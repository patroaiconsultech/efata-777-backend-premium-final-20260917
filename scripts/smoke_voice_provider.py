from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

import httpx

from orkio_v2.agents.registry import AgentNotFound, resolve_agent_by_id
from orkio_v2.config import Settings, get_settings


FIXED_SMOKE_TEXT = "PatroAI voice provider smoke."
_ALLOWED_MP3_CONTENT_TYPES = {
    "audio/mpeg",
    "audio/mp3",
}


_MPEG_BITRATES_KBPS = {
    ("1", "I"): (0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0),
    ("1", "II"): (0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0),
    ("1", "III"): (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0),
    ("2", "I"): (0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0),
    ("2", "II"): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0),
    ("2", "III"): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0),
}

_MPEG_SAMPLE_RATES = {
    "1": (44100, 48000, 32000),
    "2": (22050, 24000, 16000),
    "2.5": (11025, 12000, 8000),
}


def _id3v2_audio_offset(audio: bytes) -> int | None:
    """Return first byte after a structurally valid ID3v2 tag, or 0 when no tag exists."""
    if not audio.startswith(b"ID3"):
        return 0
    if len(audio) < 10:
        return None

    major = audio[3]
    revision = audio[4]
    flags = audio[5]
    size_bytes = audio[6:10]

    if major not in {2, 3, 4} or revision == 0xFF:
        return None
    if any(byte & 0x80 for byte in size_bytes):
        return None

    tag_size = (
        (size_bytes[0] << 21)
        | (size_bytes[1] << 14)
        | (size_bytes[2] << 7)
        | size_bytes[3]
    )
    footer_size = 10 if major == 4 and (flags & 0x10) else 0
    offset = 10 + tag_size + footer_size
    if offset > len(audio):
        return None
    return offset


def _parse_mpeg_frame_header(audio: bytes, offset: int) -> dict[str, int | str] | None:
    """Parse enough of a 4-byte MPEG audio frame header to calculate frame length."""
    if offset < 0 or offset + 4 > len(audio):
        return None

    b0, b1, b2, b3 = audio[offset : offset + 4]
    del b3  # channel/mode bits are not needed for structural frame-length validation.

    if b0 != 0xFF or (b1 & 0xE0) != 0xE0:
        return None

    version_bits = (b1 >> 3) & 0b11
    layer_bits = (b1 >> 1) & 0b11
    bitrate_index = (b2 >> 4) & 0x0F
    sample_rate_index = (b2 >> 2) & 0b11
    padding = (b2 >> 1) & 0b1

    version = {
        0b00: "2.5",
        0b10: "2",
        0b11: "1",
    }.get(version_bits)
    layer = {
        0b01: "III",
        0b10: "II",
        0b11: "I",
    }.get(layer_bits)

    if version is None or layer is None:
        return None
    if bitrate_index in {0, 15}:
        return None
    if sample_rate_index == 0b11:
        return None

    bitrate_version = "1" if version == "1" else "2"
    bitrate_kbps = _MPEG_BITRATES_KBPS[(bitrate_version, layer)][bitrate_index]
    if bitrate_kbps <= 0:
        return None

    sample_rate = _MPEG_SAMPLE_RATES[version][sample_rate_index]
    bitrate = bitrate_kbps * 1000

    if layer == "I":
        frame_length = ((12 * bitrate) // sample_rate + padding) * 4
    elif layer == "III" and version != "1":
        frame_length = (72 * bitrate) // sample_rate + padding
    else:
        frame_length = (144 * bitrate) // sample_rate + padding

    if frame_length < 4:
        return None

    return {
        "version": version,
        "layer": layer,
        "sample_rate": sample_rate,
        "frame_length": frame_length,
    }


def _looks_like_mp3(audio: bytes) -> bool:
    """
    Require two complete, consecutive MPEG audio frames.

    An optional ID3v2 tag is accepted only when its 10-byte header and syncsafe
    size are structurally valid. A bare `b"ID3"` prefix never passes.
    """
    first_offset = _id3v2_audio_offset(audio)
    if first_offset is None:
        return False

    first = _parse_mpeg_frame_header(audio, first_offset)
    if first is None:
        return False

    second_offset = first_offset + int(first["frame_length"])
    if second_offset > len(audio):
        return False

    second = _parse_mpeg_frame_header(audio, second_offset)
    if second is None:
        return False

    if (
        second["version"] != first["version"]
        or second["layer"] != first["layer"]
        or second["sample_rate"] != first["sample_rate"]
    ):
        return False

    second_end = second_offset + int(second["frame_length"])
    return second_end <= len(audio)


def _provider_endpoint_class(base: str) -> str:
    normalized = base.rstrip("/").lower()
    if normalized == "https://api.openai.com/v1":
        return "DEFAULT_OPENAI"
    return "CUSTOM_CONFIGURED"


class VoiceProviderSmokeError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _load_profile_for_smoke(
    settings: Settings,
    *,
    agent_id: str,
    locale: str,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    try:
        parsed = json.loads(settings.voice_bindings_json or "{}")
    except json.JSONDecodeError as exc:
        raise VoiceProviderSmokeError("VOICE_SMOKE_CONFIG_INVALID") from exc
    if not isinstance(parsed, dict):
        raise VoiceProviderSmokeError("VOICE_SMOKE_CONFIG_INVALID")

    try:
        agent = resolve_agent_by_id(agent_id)
    except AgentNotFound as exc:
        raise VoiceProviderSmokeError("VOICE_SMOKE_AGENT_NOT_FOUND") from exc

    binding_id = str(agent.voice_binding_id or "").strip()
    if not binding_id:
        raise VoiceProviderSmokeError("VOICE_SMOKE_BINDING_NOT_FOUND")

    binding = parsed.get(binding_id)
    if not isinstance(binding, dict):
        raise VoiceProviderSmokeError("VOICE_SMOKE_BINDING_NOT_FOUND")
    if str(binding.get("agent_id") or agent.slug) != agent.slug:
        raise VoiceProviderSmokeError("VOICE_SMOKE_AGENT_MISMATCH")
    if not bool(binding.get("enabled")):
        raise VoiceProviderSmokeError("VOICE_SMOKE_BINDING_DISABLED")

    delivery_modes = binding.get("delivery_modes")
    if delivery_modes is not None:
        if not isinstance(delivery_modes, list) or "REALTIME_STREAM" not in delivery_modes:
            raise VoiceProviderSmokeError("VOICE_SMOKE_REALTIME_MODE_NOT_CONFIGURED")

    profiles = binding.get("locale_profiles")
    if not isinstance(profiles, dict):
        raise VoiceProviderSmokeError("VOICE_SMOKE_PROFILE_UNBOUND")
    profile = profiles.get(locale)
    if not isinstance(profile, dict):
        raise VoiceProviderSmokeError("VOICE_SMOKE_PROFILE_UNBOUND")
    if not bool(profile.get("enabled")):
        raise VoiceProviderSmokeError("VOICE_SMOKE_PROFILE_DISABLED")

    provider = str(profile.get("provider") or "").strip()
    voice_id = str(profile.get("voice_id") or "").strip()
    model = str(profile.get("model") or "").strip()
    if not provider or not voice_id or not model:
        raise VoiceProviderSmokeError("VOICE_SMOKE_PROFILE_UNBOUND")
    if provider != "openai":
        raise VoiceProviderSmokeError("VOICE_SMOKE_PROVIDER_UNSUPPORTED")

    return binding, profile, binding_id


async def smoke_voice_provider(
    settings: Settings,
    *,
    agent_id: str,
    locale: str,
    confirmed: bool,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Perform exactly one provider call. Does not mutate ENV, DB, cache, or validation state."""
    if settings.environment != "staging":
        raise VoiceProviderSmokeError("VOICE_SMOKE_NOT_STAGING")
    if not confirmed:
        raise VoiceProviderSmokeError("VOICE_SMOKE_CONFIRMATION_REQUIRED")
    if not settings.tts_enabled or settings.tts_provider != "openai":
        raise VoiceProviderSmokeError("VOICE_SMOKE_TTS_NOT_READY")
    if not (settings.openai_api_key or "").strip():
        raise VoiceProviderSmokeError("VOICE_SMOKE_PROVIDER_UNAVAILABLE")

    binding, profile, binding_id = _load_profile_for_smoke(
        settings,
        agent_id=agent_id,
        locale=locale,
    )

    base = (settings.openai_api_base or "https://api.openai.com/v1").rstrip("/")
    payload = {
        "model": str(profile["model"]).strip(),
        "voice": str(profile["voice_id"]).strip(),
        "input": FIXED_SMOKE_TEXT,
        "response_format": "mp3",
    }

    try:
        async with httpx.AsyncClient(
            timeout=settings.tts_http_timeout_seconds,
            transport=transport,
        ) as client:
            response = await client.post(
                f"{base}/audio/speech",
                headers={
                    "Authorization": f"Bearer {settings.openai_api_key}",
                    "Content-Type": "application/json",
                },
                content=json.dumps(payload),
            )
    except httpx.TimeoutException as exc:
        raise VoiceProviderSmokeError("VOICE_SMOKE_TIMEOUT") from exc
    except httpx.HTTPError as exc:
        raise VoiceProviderSmokeError("VOICE_SMOKE_PROVIDER_UNAVAILABLE") from exc

    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    request_id_present = bool(
        (response.headers.get("x-request-id") or response.headers.get("request-id") or "").strip()
    )

    if response.status_code < 200 or response.status_code >= 300:
        raise VoiceProviderSmokeError(f"VOICE_SMOKE_HTTP_{response.status_code}")
    if content_type not in _ALLOWED_MP3_CONTENT_TYPES:
        raise VoiceProviderSmokeError("VOICE_SMOKE_CONTENT_TYPE_INVALID")

    audio = bytes(response.content)
    if not audio:
        raise VoiceProviderSmokeError("VOICE_SMOKE_EMPTY_AUDIO")
    if not _looks_like_mp3(audio):
        raise VoiceProviderSmokeError("VOICE_SMOKE_MP3_SIGNATURE_INVALID")

    return {
        "status": "PASS",
        "agent_id": agent_id,
        "binding_id": binding_id,
        "locale": locale,
        "provider": "openai",
        "provider_endpoint_class": _provider_endpoint_class(base),
        "model_configured": True,
        "voice_configured": True,
        "http_status": response.status_code,
        "audio_content_type": True,
        "audio_non_empty": True,
        "audio_bytes": len(audio),
        "provider_request_id_present": request_id_present,
        "binding_validated_before_smoke": bool(binding.get("validated")),
        "profile_validated_before_smoke": bool(profile.get("validated")),
        "mutations_performed": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Staging-only, one-call OpenAI TTS provider smoke for an unvalidated profile."
    )
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--locale", default="pt-BR")
    parser.add_argument(
        "--confirm-provider-call",
        action="store_true",
        help="Required explicit consent to make exactly one external provider call.",
    )
    return parser


async def _run() -> int:
    args = _parser().parse_args()
    settings = get_settings()
    try:
        result = await smoke_voice_provider(
            settings,
            agent_id=args.agent_id,
            locale=args.locale,
            confirmed=args.confirm_provider_call,
        )
    except VoiceProviderSmokeError as exc:
        print(json.dumps({"status": "FAIL", "error_code": exc.code}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_run()))
