from __future__ import annotations

from pathlib import Path
import asyncio
import threading
import time

import pytest

from conftest import Testing, headers
from orkio_v2.config import get_settings
from sqlalchemy import select
from orkio_v2.models import Membership, ThreadParticipant, ThreadRole
from orkio_v2.services.speech_to_text import (
    SpeechToTextError,
    TranscriptResult,
    normalize_locale,
)


def _enable_stt(monkeypatch, *, max_bytes: int = 8_000_000):
    settings = get_settings()
    monkeypatch.setattr(settings, "stt_enabled", True, raising=False)
    monkeypatch.setattr(settings, "stt_provider", "faster_whisper", raising=False)
    monkeypatch.setattr(settings, "stt_model", "small", raising=False)
    monkeypatch.setattr(settings, "stt_device", "cpu", raising=False)
    monkeypatch.setattr(settings, "stt_compute_type", "int8", raising=False)
    monkeypatch.setattr(settings, "stt_max_upload_bytes", max_bytes, raising=False)
    monkeypatch.setattr(settings, "stt_allowed_languages", "pt,en,es", raising=False)
    monkeypatch.setattr(settings, "stt_timeout_seconds", 30.0, raising=False)
    monkeypatch.setattr(settings, "stt_concurrency_limit", 1, raising=False)


def _thread(client):
    response = client.post("/api/v2/threads", json={}, headers=headers())
    assert response.status_code == 200
    return response.json()["id"]


def _audio_bytes(container: str = "webm") -> bytes:
    if container == "webm":
        return b"\x1aE\xdf\xa3" + b"\x00" * 20
    if container == "ogg":
        return b"OggS" + b"\x00" * 20
    if container == "wav":
        return b"RIFF" + b"\x00\x00\x00\x00" + b"WAVE" + b"\x00" * 16
    if container == "mp4":
        return b"\x00\x00\x00\x18ftypM4A " + b"\x00" * 16
    if container == "mp3":
        return b"ID3" + b"\x00" * 20
    raise AssertionError(container)


def test_locale_normalization_supports_initial_three_languages():
    assert normalize_locale("pt-BR") == "pt"
    assert normalize_locale("en-US") == "en"
    assert normalize_locale("es-419") == "es"
    assert normalize_locale("auto") is None
    with pytest.raises(SpeechToTextError, match="STT_LOCALE_NOT_ALLOWED"):
        normalize_locale("fr-FR")


def test_voice_transcribe_is_fail_closed_when_stt_disabled(client, monkeypatch):
    thread_id = _thread(client)
    monkeypatch.setattr(get_settings(), "stt_enabled", False, raising=False)

    async def must_not_run(*_args, **_kwargs):
        pytest.fail("STT engine must not run while capability is disabled")

    monkeypatch.setattr("orkio_v2.voice_routes.transcribe_audio_bytes", must_not_run)
    response = client.post(
        f"/api/v2/threads/{thread_id}/voice/transcribe",
        files={"audio": ("voice.webm", _audio_bytes("webm"), "audio/webm")},
        data={"locale": "pt-BR"},
        headers=headers(),
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "STT_DISABLED"


def test_voice_transcribe_returns_reviewable_text_without_persisting_message(
    client, monkeypatch
):
    thread_id = _thread(client)
    _enable_stt(monkeypatch)
    observed: dict[str, object] = {}

    async def fake_transcribe(_settings, audio_bytes: bytes, *, suffix: str, locale: str):
        observed["locale"] = locale
        observed["suffix"] = suffix
        observed["bytes"] = audio_bytes
        return TranscriptResult(
            text="Equipe, analisem o lançamento.",
            language="pt",
            language_probability=0.99,
            engine="faster_whisper",
            model="small",
        )

    monkeypatch.setattr("orkio_v2.voice_routes.transcribe_audio_bytes", fake_transcribe)
    response = client.post(
        f"/api/v2/threads/{thread_id}/voice/transcribe",
        files={"audio": ("voice.webm", _audio_bytes("webm"), "audio/webm")},
        data={"locale": "pt-BR"},
        headers=headers(),
    )
    assert response.status_code == 200
    assert response.json() == {
        "transcript": "Equipe, analisem o lançamento.",
        "locale_requested": "pt-BR",
        "language_detected": "pt",
        "language_probability": 0.99,
        "engine": "faster_whisper",
        "model": "small",
        "persisted": False,
    }
    assert observed["locale"] == "pt-BR"
    assert observed["suffix"] == ".webm"
    assert observed["bytes"] == _audio_bytes("webm")

    messages = client.get(
        f"/api/v2/threads/{thread_id}/messages",
        headers=headers(),
    )
    assert messages.status_code == 200
    assert messages.json() == []


def test_non_member_is_rejected_before_stt_execution(client, monkeypatch):
    thread_id = _thread(client)
    _enable_stt(monkeypatch)
    with Testing() as db:
        membership = db.scalar(
            select(Membership).where(
                Membership.tenant_id == "tenant-1",
                Membership.user_id == "user-2",
            )
        )
        if membership is None:
            db.add(Membership(tenant_id="tenant-1", user_id="user-2", role="member"))
            db.commit()

    async def must_not_run(*_args, **_kwargs):
        pytest.fail("STT engine must not run before thread authorization")

    monkeypatch.setattr("orkio_v2.voice_routes.transcribe_audio_bytes", must_not_run)
    response = client.post(
        f"/api/v2/threads/{thread_id}/voice/transcribe",
        files={"audio": ("voice.webm", _audio_bytes("webm"), "audio/webm")},
        data={"locale": "pt-BR"},
        headers=headers(user="user-2"),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "THREAD_ACCESS_DENIED"


def test_voice_transcribe_rejects_unsupported_type_before_stt(client, monkeypatch):
    thread_id = _thread(client)
    _enable_stt(monkeypatch)

    async def must_not_run(*_args, **_kwargs):
        pytest.fail("STT engine must not run for unsupported media")

    monkeypatch.setattr("orkio_v2.voice_routes.transcribe_audio_bytes", must_not_run)
    response = client.post(
        f"/api/v2/threads/{thread_id}/voice/transcribe",
        files={"audio": ("voice.txt", b"voice", "text/plain")},
        data={"locale": "pt-BR"},
        headers=headers(),
    )
    assert response.status_code == 415
    assert response.json()["detail"]["code"] == "STT_AUDIO_TYPE_NOT_ALLOWED"


def test_voice_transcribe_rejects_oversized_audio_before_stt(client, monkeypatch):
    thread_id = _thread(client)
    _enable_stt(monkeypatch, max_bytes=4)

    async def must_not_run(*_args, **_kwargs):
        pytest.fail("STT engine must not run for oversized upload")

    monkeypatch.setattr("orkio_v2.voice_routes.transcribe_audio_bytes", must_not_run)
    response = client.post(
        f"/api/v2/threads/{thread_id}/voice/transcribe",
        files={"audio": ("voice.webm", b"12345", "audio/webm")},
        data={"locale": "pt-BR"},
        headers=headers(),
    )
    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "STT_FILE_TOO_LARGE"


def test_voice_transcribe_rejects_empty_audio(client, monkeypatch):
    thread_id = _thread(client)
    _enable_stt(monkeypatch)
    response = client.post(
        f"/api/v2/threads/{thread_id}/voice/transcribe",
        files={"audio": ("voice.webm", b"", "audio/webm")},
        data={"locale": "pt-BR"},
        headers=headers(),
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "STT_EMPTY_AUDIO"


@pytest.mark.parametrize(
    ("code", "expected_status"),
    [
        ("STT_EMPTY_TRANSCRIPT", 422),
        ("STT_LOCALE_NOT_ALLOWED", 422),
        ("STT_DEPENDENCY_NOT_INSTALLED", 503),
        ("STT_MODEL_UNAVAILABLE", 503),
        ("STT_TRANSCRIPTION_FAILED", 502),
        ("STT_TIMEOUT", 504),
        ("STT_CONCURRENCY_LIMIT_REACHED", 429),
    ],
)
def test_voice_transcribe_normalizes_engine_failures(
    client, monkeypatch, code, expected_status
):
    thread_id = _thread(client)
    _enable_stt(monkeypatch)

    async def fail(*_args, **_kwargs):
        raise SpeechToTextError(code)

    monkeypatch.setattr("orkio_v2.voice_routes.transcribe_audio_bytes", fail)
    response = client.post(
        f"/api/v2/threads/{thread_id}/voice/transcribe",
        files={"audio": ("voice.webm", _audio_bytes("webm"), "audio/webm")},
        data={"locale": "auto"},
        headers=headers(),
    )
    assert response.status_code == expected_status
    assert response.json()["detail"]["code"] == code

def test_viewer_is_rejected_before_stt_execution(client, monkeypatch):
    thread_id = _thread(client)
    _enable_stt(monkeypatch)
    with Testing() as db:
        participant = db.scalar(
            select(ThreadParticipant).where(
                ThreadParticipant.thread_id == thread_id,
                ThreadParticipant.user_id == "user-1",
            )
        )
        assert participant is not None
        participant.thread_role = ThreadRole.viewer.value
        db.commit()

    async def must_not_run(*_args, **_kwargs):
        pytest.fail("STT engine must not run for viewer")

    monkeypatch.setattr("orkio_v2.voice_routes.transcribe_audio_bytes", must_not_run)
    response = client.post(
        f"/api/v2/threads/{thread_id}/voice/transcribe",
        files={"audio": ("voice.webm", _audio_bytes("webm"), "audio/webm")},
        data={"locale": "pt-BR"},
        headers=headers(),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "THREAD_READ_ONLY"


@pytest.mark.parametrize(
    ("content_type", "container"),
    [
        ("audio/webm", "ogg"),
        ("audio/ogg", "webm"),
        ("audio/wav", "mp3"),
        ("audio/mp4", "wav"),
        ("audio/mpeg", "mp4"),
    ],
)
def test_voice_transcribe_rejects_content_type_signature_mismatch_before_stt(
    client, monkeypatch, content_type, container
):
    thread_id = _thread(client)
    _enable_stt(monkeypatch)

    async def must_not_run(*_args, **_kwargs):
        pytest.fail("STT engine must not run for signature mismatch")

    monkeypatch.setattr("orkio_v2.voice_routes.transcribe_audio_bytes", must_not_run)
    response = client.post(
        f"/api/v2/threads/{thread_id}/voice/transcribe",
        files={"audio": ("voice.bin", _audio_bytes(container), content_type)},
        data={"locale": "pt-BR"},
        headers=headers(),
    )
    assert response.status_code == 415
    assert response.json()["detail"]["code"] == "STT_AUDIO_SIGNATURE_MISMATCH"


def test_stt_readiness_is_authenticated_and_reports_disabled_as_not_ready(client):
    response = client.get("/api/v2/voice/stt/readiness", headers=headers())
    assert response.status_code == 503
    body = response.json()
    assert body["enabled"] is False
    assert body["ready"] is False
    assert body["reason"] == "STT_DISABLED"


def test_stt_readiness_fails_when_enabled_dependency_or_model_is_not_ready(client, monkeypatch):
    _enable_stt(monkeypatch)
    monkeypatch.setattr(
        "orkio_v2.voice_routes.inspect_stt_readiness",
        lambda _settings: {
            "enabled": True,
            "provider": "faster_whisper",
            "model": "small",
            "dependency_present": True,
            "model_cached": False,
            "local_files_only": True,
            "ready": False,
            "reason": "STT_MODEL_NOT_PREWARMED",
        },
    )
    response = client.get("/api/v2/voice/stt/readiness", headers=headers())
    assert response.status_code == 503
    assert response.json()["reason"] == "STT_MODEL_NOT_PREWARMED"


def test_production_stt_requires_prewarmed_local_model(monkeypatch):
    from orkio_v2.config import Settings
    monkeypatch.setenv("PLATFORM_ENVIRONMENT", "production")
    monkeypatch.setenv("PLATFORM_STT_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_STT_PROVIDER", "faster_whisper")
    monkeypatch.setenv("PLATFORM_STT_LOCAL_FILES_ONLY", "false")
    monkeypatch.setenv("PLATFORM_STT_TIMEOUT_SECONDS", "30")
    monkeypatch.setenv("PLATFORM_STT_CONCURRENCY_LIMIT", "1")
    monkeypatch.setenv("PLATFORM_ALLOWED_ORIGINS", "https://frontend.example.test")
    monkeypatch.setenv("DATABASE_URL", "postgresql://" + "dbuser" + ":" + "fixture" + "@example.test/db?sslmode=require")
    monkeypatch.setenv("PLATFORM_INVITATION_TOKEN_SECRET", "x" * 40)
    monkeypatch.setenv("PLATFORM_RELEASE_SHA", "a" * 40)
    with pytest.raises(ValueError, match="STT_PRODUCTION_REQUIRES_PREWARMED_LOCAL_MODEL"):
        Settings()

def test_stt_enabled_requires_explicit_timeout_and_concurrency(monkeypatch):
    from orkio_v2.config import Settings

    monkeypatch.setenv("PLATFORM_STT_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_STT_PROVIDER", "faster_whisper")
    monkeypatch.setenv("PLATFORM_STT_LOCAL_FILES_ONLY", "true")
    monkeypatch.setenv("PLATFORM_STT_TIMEOUT_SECONDS", "0")
    monkeypatch.setenv("PLATFORM_STT_CONCURRENCY_LIMIT", "1")
    with pytest.raises(ValueError, match="STT_TIMEOUT_SECONDS_REQUIRED"):
        Settings()

    monkeypatch.setenv("PLATFORM_STT_TIMEOUT_SECONDS", "30")
    monkeypatch.setenv("PLATFORM_STT_CONCURRENCY_LIMIT", "0")
    with pytest.raises(ValueError, match="STT_CONCURRENCY_LIMIT_REQUIRED"):
        Settings()


@pytest.mark.asyncio
async def test_stt_timeout_keeps_capacity_reserved_until_worker_finishes(
    monkeypatch, tmp_path
):
    import orkio_v2.services.speech_to_text as stt_service

    settings = get_settings()
    _enable_stt(monkeypatch)
    monkeypatch.setattr(settings, "stt_timeout_seconds", 0.02, raising=False)
    monkeypatch.setattr(settings, "stt_concurrency_limit", 1, raising=False)

    release_worker = threading.Event()

    def slow_transcribe(_settings, _audio_path, _requested_language):
        release_worker.wait(timeout=0.5)
        return TranscriptResult(
            text="fim",
            language="pt",
            language_probability=1.0,
            engine="faster_whisper",
            model="small",
        )

    monkeypatch.setattr(stt_service, "_transcribe_sync", slow_transcribe)
    audio_path = tmp_path / "voice.webm"
    audio_path.write_bytes(_audio_bytes("webm"))

    with pytest.raises(SpeechToTextError, match="STT_TIMEOUT"):
        await stt_service.transcribe_audio(settings, audio_path, locale="pt-BR")

    with pytest.raises(SpeechToTextError, match="STT_CONCURRENCY_LIMIT_REACHED"):
        await stt_service.transcribe_audio(settings, audio_path, locale="pt-BR")

    release_worker.set()
    await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_stt_concurrency_limit_rejects_second_active_inference(
    monkeypatch, tmp_path
):
    import orkio_v2.services.speech_to_text as stt_service

    settings = get_settings()
    _enable_stt(monkeypatch)
    monkeypatch.setattr(settings, "stt_timeout_seconds", 1.0, raising=False)
    monkeypatch.setattr(settings, "stt_concurrency_limit", 1, raising=False)

    started = threading.Event()
    release_worker = threading.Event()

    def blocking_transcribe(_settings, _audio_path, _requested_language):
        started.set()
        release_worker.wait(timeout=0.5)
        return TranscriptResult(
            text="ok",
            language="pt",
            language_probability=1.0,
            engine="faster_whisper",
            model="small",
        )

    monkeypatch.setattr(stt_service, "_transcribe_sync", blocking_transcribe)
    audio_path = tmp_path / "voice.webm"
    audio_path.write_bytes(_audio_bytes("webm"))

    first = asyncio.create_task(
        stt_service.transcribe_audio(settings, audio_path, locale="pt-BR")
    )
    await asyncio.to_thread(started.wait, 0.2)

    with pytest.raises(SpeechToTextError, match="STT_CONCURRENCY_LIMIT_REACHED"):
        await stt_service.transcribe_audio(settings, audio_path, locale="pt-BR")

    release_worker.set()
    result = await first
    assert result.text == "ok"


@pytest.mark.asyncio
async def test_stt_timeout_tempfile_lifecycle_is_owned_by_worker(monkeypatch):
    import orkio_v2.services.speech_to_text as stt_service

    settings = get_settings()
    _enable_stt(monkeypatch)
    monkeypatch.setattr(settings, "stt_timeout_seconds", 0.02, raising=False)
    monkeypatch.setattr(settings, "stt_concurrency_limit", 1, raising=False)

    started = threading.Event()
    release_worker = threading.Event()
    observed: dict[str, object] = {}

    def slow_transcribe(_settings, audio_path: Path, _requested_language):
        observed["path"] = Path(audio_path)
        observed["exists_at_start"] = Path(audio_path).exists()
        observed["bytes"] = Path(audio_path).read_bytes()
        started.set()
        release_worker.wait()
        observed["exists_before_worker_return"] = Path(audio_path).exists()
        return TranscriptResult(
            text="fim",
            language="pt",
            language_probability=1.0,
            engine="faster_whisper",
            model="small",
        )

    monkeypatch.setattr(stt_service, "_transcribe_sync", slow_transcribe)

    with pytest.raises(SpeechToTextError, match="STT_TIMEOUT"):
        await stt_service.transcribe_audio_bytes(
            settings,
            _audio_bytes("webm"),
            suffix=".webm",
            locale="pt-BR",
        )

    assert started.is_set()
    temp_path = Path(observed["path"])
    assert observed["exists_at_start"] is True
    assert observed["bytes"] == _audio_bytes("webm")
    assert temp_path.exists(), "worker-owned tempfile must survive coroutine timeout"

    release_worker.set()
    deadline = time.monotonic() + 1.0
    while temp_path.exists() and time.monotonic() < deadline:
        await asyncio.sleep(0.01)

    assert observed["exists_before_worker_return"] is True
    assert not temp_path.exists(), "worker must unlink tempfile after CPU work finishes"



def test_stt_request_observability_never_logs_transcript_or_audio_body(
    client, monkeypatch, caplog
):
    thread_id = _thread(client)
    _enable_stt(monkeypatch)

    async def fake_transcribe(_settings, _audio_bytes: bytes, *, suffix: str, locale: str):
        return TranscriptResult(
            text="SEGREDO_TRANSCRIPT_NAO_DEVE_IR_AO_LOG",
            language="pt",
            language_probability=0.99,
            engine="faster_whisper",
            model="small",
        )

    monkeypatch.setattr("orkio_v2.voice_routes.transcribe_audio_bytes", fake_transcribe)
    with caplog.at_level("INFO", logger="uvicorn.error"):
        response = client.post(
            f"/api/v2/threads/{thread_id}/voice/transcribe",
            files={"audio": ("voice.webm", _audio_bytes("webm"), "audio/webm")},
            data={"locale": "pt-BR"},
            headers=headers(),
        )
    assert response.status_code == 200
    logs = "\n".join(record.getMessage() for record in caplog.records)
    assert "STT_REQUEST_STARTED" in logs
    assert "STT_REQUEST_COMPLETED" in logs
    assert "duration_ms=" in logs
    assert "locale=pt-BR" in logs
    assert "audio_size=" in logs
    assert "model=small" in logs
    assert "SEGREDO_TRANSCRIPT_NAO_DEVE_IR_AO_LOG" not in logs
    assert _audio_bytes("webm").hex() not in logs

