from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from .auth import Principal
from .config import Settings, get_settings
from .database import get_db
from .models import ThreadRole
from .routes import thread_access
from .services.identity import require_provisioned_principal
from .services.speech_to_text import (
    SpeechToTextError,
    inspect_stt_readiness,
    transcribe_audio_bytes,
)


router = APIRouter(prefix="/api/v2")
stt_logger = logging.getLogger("uvicorn.error")

_ALLOWED_AUDIO_TYPES = {
    "audio/webm": ".webm",
    "audio/ogg": ".ogg",
    "audio/wav": ".wav",
    "audio/x-wav": ".wav",
    "audio/mp4": ".m4a",
    "audio/x-m4a": ".m4a",
    "audio/mpeg": ".mp3",
    "audio/mp3": ".mp3",
}


_EXPECTED_CONTAINERS = {
    "audio/webm": {"webm"},
    "audio/ogg": {"ogg"},
    "audio/wav": {"wav"},
    "audio/x-wav": {"wav"},
    "audio/mp4": {"mp4"},
    "audio/x-m4a": {"mp4"},
    "audio/mpeg": {"mp3"},
    "audio/mp3": {"mp3"},
}


def _detect_audio_container(raw: bytes) -> str | None:
    if raw.startswith(b"\x1aE\xdf\xa3"):
        return "webm"
    if raw.startswith(b"OggS"):
        return "ogg"
    if len(raw) >= 12 and raw[:4] == b"RIFF" and raw[8:12] == b"WAVE":
        return "wav"
    if len(raw) >= 12 and raw[4:8] == b"ftyp":
        return "mp4"
    if raw.startswith(b"ID3"):
        return "mp3"
    if len(raw) >= 2 and raw[0] == 0xFF and (raw[1] & 0xE0) == 0xE0:
        return "mp3"
    return None


def _validate_audio_signature(content_type: str, raw: bytes) -> None:
    detected = _detect_audio_container(raw)
    expected = _EXPECTED_CONTAINERS.get(content_type, set())
    if detected not in expected:
        raise HTTPException(
            415,
            detail={
                "code": "STT_AUDIO_SIGNATURE_MISMATCH",
                "detected": detected or "unknown",
            },
        )


def _raise_stt_error(exc: SpeechToTextError) -> None:
    status_by_code = {
        "STT_DISABLED": 503,
        "STT_DEPENDENCY_NOT_INSTALLED": 503,
        "STT_PROVIDER_UNAVAILABLE": 503,
        "STT_MODEL_UNAVAILABLE": 503,
        "STT_TRANSCRIPTION_FAILED": 502,
        "STT_TIMEOUT": 504,
        "STT_TIMEOUT_NOT_CONFIGURED": 503,
        "STT_CONCURRENCY_LIMIT_NOT_CONFIGURED": 503,
        "STT_CONCURRENCY_LIMIT_REACHED": 429,
        "STT_EMPTY_TRANSCRIPT": 422,
        "STT_LOCALE_NOT_ALLOWED": 422,
    }
    raise HTTPException(
        status_code=status_by_code.get(exc.code, 500),
        detail={"code": exc.code},
    ) from exc


@router.get("/voice/stt/readiness")
async def stt_readiness(
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
):
    del p
    result = await asyncio.to_thread(inspect_stt_readiness, settings)
    status = 200 if bool(result.get("ready")) else 503
    return JSONResponse(status_code=status, content=result)


@router.post("/threads/{thread_id}/voice/transcribe")
async def transcribe_voice_message(
    thread_id: str,
    audio: UploadFile = File(...),
    locale: str = Form("auto"),
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _, member = thread_access(db, thread_id, p)
    if member.thread_role == ThreadRole.viewer.value:
        raise HTTPException(403, "THREAD_READ_ONLY")
    if not settings.stt_enabled:
        raise HTTPException(503, detail={"code": "STT_DISABLED"})

    content_type = (audio.content_type or "").split(";", 1)[0].strip().lower()
    suffix = _ALLOWED_AUDIO_TYPES.get(content_type)
    if not suffix:
        raise HTTPException(415, detail={"code": "STT_AUDIO_TYPE_NOT_ALLOWED"})

    raw = await audio.read(settings.stt_max_upload_bytes + 1)
    if not raw:
        raise HTTPException(422, detail={"code": "STT_EMPTY_AUDIO"})
    if len(raw) > settings.stt_max_upload_bytes:
        raise HTTPException(413, detail={"code": "STT_FILE_TOO_LARGE"})
    _validate_audio_signature(content_type, raw)

    try:
        started_at = time.monotonic()
        stt_logger.info(
            "STT_REQUEST_STARTED locale=%s audio_size=%d model=%s",
            locale,
            len(raw),
            settings.stt_model,
        )
        try:
            result = await transcribe_audio_bytes(
                settings,
                raw,
                suffix=suffix,
                locale=locale,
            )
        except SpeechToTextError as exc:
            duration_ms = int((time.monotonic() - started_at) * 1000)
            stt_logger.warning(
                "STT_REQUEST_FAILED code=%s duration_ms=%d locale=%s audio_size=%d model=%s",
                exc.code,
                duration_ms,
                locale,
                len(raw),
                settings.stt_model,
            )
            raise
        else:
            duration_ms = int((time.monotonic() - started_at) * 1000)
            stt_logger.info(
                "STT_REQUEST_COMPLETED duration_ms=%d locale=%s audio_size=%d model=%s",
                duration_ms,
                locale,
                len(raw),
                settings.stt_model,
            )
    except SpeechToTextError as exc:
        _raise_stt_error(exc)

    return {
        "transcript": result.text,
        "locale_requested": locale,
        "language_detected": result.language,
        "language_probability": result.language_probability,
        "engine": result.engine,
        "model": result.model,
        "persisted": False,
    }
