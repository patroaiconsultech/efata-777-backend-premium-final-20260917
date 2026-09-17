from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import urlparse

import httpx

from ..config import Settings
from ..runtime.contracts import CanonicalTurnContext
from ..runtime.realtime import realtime_identity_from_turn
from .llm_providers import DEFAULT_OPENAI_BASE


DEFAULT_REALTIME_MODEL = "gpt-realtime"


class RealtimeSessionError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class RealtimeCallResult:
    sdp_answer: str
    call_id: str | None
    model: str
    output_modalities: tuple[str, ...]


def realtime_capability(settings: Settings) -> dict[str, object]:
    key_configured = bool((settings.openai_api_key or "").strip())
    provider_openai = (settings.voice_provider or "").strip().casefold() == "openai"
    session_configured = bool(settings.voice_enabled and provider_openai and key_configured)
    bridge_configured = bool(session_configured and settings.realtime_bridge_enabled)
    bindings_configured = (settings.voice_bindings_json or "{}").strip() not in {"", "{}"}
    tts_configured = bool(
        settings.tts_enabled
        and settings.tts_provider != "disabled"
        and bindings_configured
    )

    if not settings.voice_enabled:
        session_reason = "REALTIME_VOICE_DISABLED"
    elif not provider_openai:
        session_reason = "REALTIME_PROVIDER_NOT_OPENAI"
    elif not key_configured:
        session_reason = "REALTIME_OPENAI_KEY_NOT_CONFIGURED"
    else:
        session_reason = "REALTIME_SIGNALING_CONFIGURED_NOT_RUNTIME_PROVEN"

    if not bridge_configured:
        bridge_reason = "REALTIME_ORCHESTRATION_BRIDGE_REQUIRED"
    else:
        bridge_reason = "REALTIME_CANONICAL_BRIDGE_CONFIGURED_NOT_RUNTIME_PROVEN"

    return {
        "text_streaming": {
            "status": "CONFIGURED" if settings.realtime_streaming_enabled else "DISABLED",
            "eligible": bool(settings.realtime_streaming_enabled),
            "reason_code": (
                "CHAT_SSE_ENABLED"
                if settings.realtime_streaming_enabled
                else "REALTIME_STREAMING_DISABLED"
            ),
        },
        "realtime_session": {
            "status": "CONFIGURED" if session_configured else "UNCONFIGURED",
            "eligible": session_configured,
            "reason_code": session_reason,
            "transport": "webrtc",
            "output_modalities": ["text"],
            "runtime_proven": False,
        },
        "voice_input": {
            "status": "CONFIGURED" if bridge_configured else "NOT_BOUND",
            "eligible": bridge_configured,
            "reason_code": (
                "REALTIME_TRANSCRIPTION_BRIDGE_CONFIGURED_NOT_RUNTIME_PROVEN"
                if bridge_configured
                else "REALTIME_VOICE_INPUT_NOT_BOUND_TO_ORKIO_PIPELINE"
            ),
        },
        "voice_output": {
            "status": "CONFIGURED" if tts_configured else "NOT_BOUND",
            "eligible": tts_configured,
            "reason_code": (
                "CANONICAL_MESSAGE_TTS_CONFIGURED_NOT_RUNTIME_PROVEN"
                if tts_configured
                else "AGENT_VOICE_BINDING_NOT_VALIDATED"
            ),
        },
        "voice_segment_streaming": {
            "status": "CONFIGURED" if bridge_configured and tts_configured else "DISABLED",
            "eligible": bool(bridge_configured and tts_configured),
            "reason_code": (
                "REALTIME_VOICE_SEGMENT_STREAMING_READY"
                if bridge_configured and tts_configured
                else "REALTIME_VOICE_SEGMENT_STREAMING_NOT_READY"
            ),
            "transport": "sse",
            "audio_mode": "segment_mp3",
            "provider_streaming": False,
        },
        "interruption": {
            "status": "NOT_PROVEN",
            "eligible": False,
            "reason_code": "REALTIME_INTERRUPTION_NOT_ORKIO_PROVEN",
        },
        "turn_detection": {
            "status": "CONFIGURED" if session_configured else "NOT_PROVEN",
            "eligible": session_configured,
            "reason_code": (
                "SERVER_VAD_TRANSCRIPTION_ONLY"
                if session_configured
                else "REALTIME_TURN_DETECTION_NOT_ORKIO_PROVEN"
            ),
        },
        "orchestration_bridge": {
            "status": "CONFIGURED" if bridge_configured else "NOT_IMPLEMENTED",
            "eligible": bridge_configured,
            "reason_code": bridge_reason,
        },
        "runtime_proven": False,
    }


def _assert_realtime_configured(settings: Settings) -> str:
    if not settings.voice_enabled:
        raise RealtimeSessionError("REALTIME_VOICE_DISABLED")
    if (settings.voice_provider or "").strip().casefold() != "openai":
        raise RealtimeSessionError("REALTIME_PROVIDER_NOT_OPENAI")
    key = (settings.openai_api_key or "").strip()
    if not key:
        raise RealtimeSessionError("REALTIME_OPENAI_KEY_NOT_CONFIGURED")
    return key


def _realtime_calls_endpoint(settings: Settings) -> str:
    base = (settings.openai_api_base or DEFAULT_OPENAI_BASE).strip().rstrip("/")
    parsed = urlparse(base)
    if parsed.scheme not in {"https", "http"}:
        raise RealtimeSessionError("REALTIME_API_BASE_INVALID")
    if parsed.scheme == "http" and settings.environment not in {"development", "test"}:
        raise RealtimeSessionError("REALTIME_API_BASE_INSECURE")
    return f"{base}/realtime/calls"


def _transcription_language(locale: str) -> str:
    language = {
        "pt-BR": "pt",
        "en-US": "en",
        "es-419": "es",
    }.get(locale)
    if language is None:
        raise RealtimeSessionError("REALTIME_LOCALE_NOT_SUPPORTED")
    return language


async def create_realtime_call(
    *,
    settings: Settings,
    turn: CanonicalTurnContext,
    sdp_offer: str,
    locale: str = "pt-BR",
) -> RealtimeCallResult:
    key = _assert_realtime_configured(settings)
    identity = realtime_identity_from_turn(turn)
    if identity.turn_owner_agent_id != turn.turn_owner_agent_id:
        raise RealtimeSessionError("REALTIME_OWNER_MISMATCH")

    endpoint = _realtime_calls_endpoint(settings)
    # Provider is transport/VAD/transcription only. Canonical assistant response
    # is generated by the server-side ORKIO bridge after transcript.final.
    session = {
        "type": "realtime",
        "model": DEFAULT_REALTIME_MODEL,
        "output_modalities": ["text"],
        "audio": {
            "input": {
                "noise_reduction": {
                    "type": "far_field",
                },
                "transcription": {
                    "model": settings.realtime_transcription_model,
                    "language": _transcription_language(locale),
                },
                "turn_detection": {
                    "type": "server_vad",
                    "threshold": 0.7,
                    "prefix_padding_ms": 300,
                    "silence_duration_ms": 700,
                    "create_response": False,
                    "interrupt_response": False,
                },
            }
        },
        "tools": [],
    }

    try:
        async with httpx.AsyncClient(timeout=settings.llm_http_timeout_seconds) as client:
            response = await client.post(
                endpoint,
                headers={"Authorization": f"Bearer {key}"},
                files={
                    "sdp": (None, sdp_offer, "application/sdp"),
                    "session": (None, json.dumps(session), "application/json"),
                },
            )
            response.raise_for_status()
    except RealtimeSessionError:
        raise
    except Exception as exc:
        raise RealtimeSessionError("REALTIME_UPSTREAM_UNAVAILABLE") from exc

    location = str(response.headers.get("Location") or "").strip()
    call_id = location.rstrip("/").split("/")[-1] if location else None
    answer = str(response.text or "")
    if not answer.strip():
        raise RealtimeSessionError("REALTIME_SDP_ANSWER_EMPTY")
    # Preserve the provider SDP byte structure. Chromium/WebRTC requires the
    # terminal SDP line to be newline-terminated; stripping the response makes
    # an otherwise valid final `a=` line fail with "Invalid SDP line".
    if answer.endswith("\r"):
        answer += "\n"
    elif not answer.endswith("\n"):
        answer += "\r\n"

    return RealtimeCallResult(
        sdp_answer=answer,
        call_id=call_id or None,
        model=DEFAULT_REALTIME_MODEL,
        output_modalities=("text",),
    )
