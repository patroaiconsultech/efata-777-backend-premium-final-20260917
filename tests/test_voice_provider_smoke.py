from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from orkio_v2.config import Settings
from scripts.smoke_voice_provider import VoiceProviderSmokeError, smoke_voice_provider


def _settings(*, environment: str = "staging", key: str = "test-key") -> Settings:
    bindings = {
        "voice_binding::orkio": {
            "agent_id": "orkio",
            "binding_version": "1",
            "enabled": True,
            "validated": False,
            "delivery_modes": ["REALTIME_STREAM", "MESSAGE_PLAYBACK"],
            "locale_profiles": {
                "pt-BR": {
                    "provider": "openai",
                    "voice_id": "private-voice",
                    "model": "private-model",
                    "enabled": True,
                    "validated": False,
                }
            },
        }
    }
    return Settings(
        PLATFORM_ENVIRONMENT=environment,
        PLATFORM_OPENAI_API_KEY=key,
        OPENAI_API_KEY=key,
        PLATFORM_TTS_ENABLED=True,
        PLATFORM_TTS_PROVIDER="openai",
        PLATFORM_VOICE_BINDINGS_JSON=json.dumps(bindings),
    )




def _mpeg1_layer3_frame() -> bytes:
    # MPEG1 Layer III, 128 kbps, 44.1 kHz, no padding => 417-byte frame.
    header = b"\xff\xfb\x90\x64"
    return header + b"\x00" * (417 - len(header))


def _valid_mp3(*, with_id3: bool = False) -> bytes:
    frames = _mpeg1_layer3_frame() + _mpeg1_layer3_frame()
    if not with_id3:
        return frames
    # ID3v2.4 header with a valid zero-length syncsafe tag size.
    return b"ID3\x04\x00\x00\x00\x00\x00\x00" + frames

def _run(settings: Settings, *, confirmed: bool, transport=None):
    return asyncio.run(
        smoke_voice_provider(
            settings,
            agent_id="orkio",
            locale="pt-BR",
            confirmed=confirmed,
            transport=transport,
        )
    )


def test_smoke_refuses_non_staging():
    with pytest.raises(VoiceProviderSmokeError, match="VOICE_SMOKE_NOT_STAGING"):
        _run(_settings(environment="development"), confirmed=True)


def test_smoke_requires_explicit_confirmation():
    with pytest.raises(VoiceProviderSmokeError, match="VOICE_SMOKE_CONFIRMATION_REQUIRED"):
        _run(_settings(), confirmed=False)


def test_smoke_requires_provider_key(monkeypatch):
    settings = _settings(key="")
    monkeypatch.setattr(settings, "openai_api_key", "", raising=False)
    with pytest.raises(VoiceProviderSmokeError, match="VOICE_SMOKE_PROVIDER_UNAVAILABLE"):
        _run(settings, confirmed=True)


def test_smoke_http_200_audio_passes_without_mutation_or_value_disclosure():
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        assert request.url.path.endswith("/audio/speech")
        assert request.headers["authorization"].startswith("Bearer ")
        body = json.loads(request.content)
        assert body["input"] == "PatroAI voice provider smoke."
        return httpx.Response(
            200,
            headers={
                "content-type": "audio/mpeg",
                "x-request-id": "req-private",
            },
            content=_valid_mp3(with_id3=True),
        )

    result = _run(
        _settings(),
        confirmed=True,
        transport=httpx.MockTransport(handler),
    )
    assert calls["count"] == 1
    assert result["status"] == "PASS"
    assert result["http_status"] == 200
    assert result["audio_non_empty"] is True
    assert result["audio_bytes"] == len(_valid_mp3(with_id3=True))
    assert result["provider_request_id_present"] is True
    assert result["binding_validated_before_smoke"] is False
    assert result["profile_validated_before_smoke"] is False
    assert result["mutations_performed"] is False
    rendered = repr(result)
    assert "private-voice" not in rendered
    assert "private-model" not in rendered
    assert "req-private" not in rendered
    assert "test-key" not in rendered


def test_smoke_429_fails_without_retry():
    calls = {"count": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(429, json={"error": {"message": "private"}})

    with pytest.raises(VoiceProviderSmokeError, match="VOICE_SMOKE_HTTP_429"):
        _run(_settings(), confirmed=True, transport=httpx.MockTransport(handler))
    assert calls["count"] == 1


def test_smoke_rejects_non_audio_content_type():
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(200, headers={"content-type": "application/json"}, content=b"{}")
    )
    with pytest.raises(VoiceProviderSmokeError, match="VOICE_SMOKE_CONTENT_TYPE_INVALID"):
        _run(_settings(), confirmed=True, transport=transport)


def test_smoke_rejects_empty_audio():
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(200, headers={"content-type": "audio/mpeg"}, content=b"")
    )
    with pytest.raises(VoiceProviderSmokeError, match="VOICE_SMOKE_EMPTY_AUDIO"):
        _run(_settings(), confirmed=True, transport=transport)


def test_smoke_timeout_is_sanitized():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("private timeout detail", request=request)

    with pytest.raises(VoiceProviderSmokeError, match="VOICE_SMOKE_TIMEOUT"):
        _run(_settings(), confirmed=True, transport=httpx.MockTransport(handler))

def test_smoke_rejects_application_octet_stream_even_when_body_is_non_empty():
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            headers={"content-type": "application/octet-stream"},
            content=b"not-audio",
        )
    )
    with pytest.raises(VoiceProviderSmokeError, match="VOICE_SMOKE_CONTENT_TYPE_INVALID"):
        _run(_settings(), confirmed=True, transport=transport)


def test_smoke_rejects_audio_mime_when_mp3_signature_is_invalid():
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            headers={"content-type": "audio/mpeg"},
            content=b"definitely-not-mp3",
        )
    )
    with pytest.raises(VoiceProviderSmokeError, match="VOICE_SMOKE_MP3_SIGNATURE_INVALID"):
        _run(_settings(), confirmed=True, transport=transport)


def test_smoke_rejects_fake_mpeg_sync_prefix_without_complete_frames():
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            headers={"content-type": "audio/mpeg"},
            content=b"\xff\xfb\x90\x64" + b"\x00" * 16,
        )
    )
    with pytest.raises(VoiceProviderSmokeError, match="VOICE_SMOKE_MP3_SIGNATURE_INVALID"):
        _run(_settings(), confirmed=True, transport=transport)


def test_smoke_accepts_two_complete_consecutive_mpeg_frames():
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            headers={"content-type": "audio/mpeg"},
            content=_valid_mp3(),
        )
    )
    result = _run(_settings(), confirmed=True, transport=transport)
    assert result["status"] == "PASS"
    assert result["audio_non_empty"] is True


def test_smoke_rejects_bare_id3_prefix():
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            headers={"content-type": "audio/mpeg"},
            content=b"ID3-audio",
        )
    )
    with pytest.raises(VoiceProviderSmokeError, match="VOICE_SMOKE_MP3_SIGNATURE_INVALID"):
        _run(_settings(), confirmed=True, transport=transport)


def test_smoke_accepts_valid_id3_header_followed_by_two_complete_frames():
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            headers={"content-type": "audio/mpeg"},
            content=_valid_mp3(with_id3=True),
        )
    )
    result = _run(_settings(), confirmed=True, transport=transport)
    assert result["status"] == "PASS"


def test_smoke_reports_default_endpoint_class_without_exposing_url():
    result = _run(
        _settings(),
        confirmed=True,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"content-type": "audio/mpeg"},
                content=_valid_mp3(with_id3=True),
            )
        ),
    )
    assert result["provider_endpoint_class"] == "DEFAULT_OPENAI"
    assert "api.openai.com" not in repr(result)


def test_smoke_reports_custom_endpoint_class_without_exposing_custom_host(monkeypatch):
    settings = _settings()
    monkeypatch.setattr(
        settings,
        "openai_api_base",
        "https://private-gateway.example/v1",
        raising=False,
    )
    result = _run(
        settings,
        confirmed=True,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"content-type": "audio/mpeg"},
                content=_valid_mp3(with_id3=True),
            )
        ),
    )
    assert result["provider_endpoint_class"] == "CUSTOM_CONFIGURED"
    assert "private-gateway.example" not in repr(result)

