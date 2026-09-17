from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .auth import Principal
from .config import Settings, get_settings
from .database import get_db
from .models import AuditEvent, Message, ThreadRole
from .routes import thread_access
from .services.identity import require_provisioned_principal
from .services.text_to_speech import (
    TextToSpeechError,
    complete_tts_idempotency,
    message_content_sha256,
    read_cached_speech,
    release_tts_idempotency,
    request_idempotency_identity,
    reserve_tts_idempotency,
    synthesis_identity,
    synthesize_speech,
    write_cached_speech,
)
from .services.voice_binding import VoiceBindingError, resolve_voice_profile


router = APIRouter(prefix="/api/v2", tags=["tts"])
tts_logger = logging.getLogger("uvicorn.error")


class MessageVoiceRequest(BaseModel):
    locale: str


def _detail(code: str) -> dict[str, str]:
    return {"code": code}


def _raise_voice_error(exc: VoiceBindingError) -> None:
    status = 422
    if exc.code in {
        "VOICE_BINDING_NOT_FOUND",
        "VOICE_BINDING_DISABLED",
        "VOICE_PROFILE_UNBOUND",
        "VOICE_PROFILE_NOT_VALIDATED",
        "VOICE_PROVIDER_NOT_AVAILABLE",
    }:
        status = 503
    elif exc.code == "VOICE_BINDING_AGENT_MISMATCH":
        status = 409
    raise HTTPException(status_code=status, detail=_detail(exc.code)) from exc


def _raise_tts_error(exc: TextToSpeechError) -> None:
    statuses = {
        "TTS_DISABLED": 503,
        "TTS_EMPTY_CONTENT": 422,
        "TTS_COST_GUARD_REJECTED": 429,
        "TTS_RATE_LIMITED": 429,
        "TTS_PROVIDER_UNAVAILABLE": 503,
        "TTS_TIMEOUT": 504,
        "TTS_CACHE_PATH_INVALID": 500,
        "TTS_IDEMPOTENCY_KEY_INVALID": 400,
        "TTS_IDEMPOTENCY_IN_PROGRESS": 409,
    }
    raise HTTPException(
        status_code=statuses.get(exc.code, 500),
        detail=_detail(exc.code),
    ) from exc


def _recent_count(
    db: Session,
    *,
    tenant_id: str,
    actor_id: str | None = None,
    resource_id: str | None = None,
) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=1)
    statement = select(func.count(AuditEvent.id)).where(
        AuditEvent.tenant_id == tenant_id,
        AuditEvent.action == "message_tts_request",
        AuditEvent.created_at >= cutoff,
    )
    if actor_id is not None:
        statement = statement.where(AuditEvent.actor_id == actor_id)
    if resource_id is not None:
        statement = statement.where(AuditEvent.resource_id == resource_id)
    return int(db.scalar(statement) or 0)


def _enforce_rate_limits(
    db: Session,
    *,
    settings: Settings,
    tenant_id: str,
    actor_id: str,
    message_id: str,
) -> None:
    if _recent_count(db, tenant_id=tenant_id) >= settings.tts_tenant_rate_limit_per_minute:
        raise TextToSpeechError("TTS_RATE_LIMITED")
    if (
        _recent_count(db, tenant_id=tenant_id, actor_id=actor_id)
        >= settings.tts_user_rate_limit_per_minute
    ):
        raise TextToSpeechError("TTS_RATE_LIMITED")
    if (
        _recent_count(db, tenant_id=tenant_id, resource_id=message_id)
        >= settings.tts_message_rate_limit_per_minute
    ):
        raise TextToSpeechError("TTS_RATE_LIMITED")


def _audit(
    db: Session,
    *,
    principal: Principal,
    message_id: str,
    request_id: str,
    outcome: str,
    metadata: dict[str, object],
) -> None:
    db.add(
        AuditEvent(
            tenant_id=principal.tenant_id,
            actor_id=principal.user_id,
            action="message_tts_request",
            resource_type="message",
            resource_id=message_id,
            outcome=outcome,
            metadata_json={"request_id": request_id, **metadata},
        )
    )
    db.commit()


@router.post("/threads/{thread_id}/messages/{message_id}/voice")
async def message_voice(
    thread_id: str,
    message_id: str,
    payload: MessageVoiceRequest,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    request_id = (x_request_id or "").strip()
    if not request_id:
        raise HTTPException(400, detail=_detail("REQUEST_ID_REQUIRED"))

    _, member = thread_access(db, thread_id, p)
    if member.thread_role == ThreadRole.viewer.value:
        raise HTTPException(403, detail=_detail("VIEWER_TTS_NOT_ALLOWED"))
    if not settings.tts_enabled:
        raise HTTPException(503, detail=_detail("TTS_DISABLED"))

    message = db.get(Message, message_id)
    if not message:
        raise HTTPException(404, detail=_detail("MESSAGE_NOT_FOUND"))
    if message.tenant_id != p.tenant_id:
        raise HTTPException(404, detail=_detail("MESSAGE_NOT_FOUND"))
    if message.thread_id != thread_id:
        raise HTTPException(409, detail=_detail("MESSAGE_THREAD_MISMATCH"))
    if message.author_type != "agent":
        raise HTTPException(422, detail=_detail("MESSAGE_NOT_AGENT_AUTHORED"))
    if not message.content.strip():
        raise HTTPException(422, detail=_detail("TTS_EMPTY_CONTENT"))

    reservation = None
    idempotency_replay = False
    try:
        if len(message.content) > settings.tts_max_chars:
            raise TextToSpeechError("TTS_COST_GUARD_REJECTED")
        profile = resolve_voice_profile(
            message.author_id,
            payload.locale,
            settings,
            delivery_mode="MESSAGE_PLAYBACK",
            db=db,
            tenant_id=p.tenant_id,
        )
        identity = synthesis_identity(
            tenant_id=p.tenant_id,
            thread_id=thread_id,
            message_id=message.id,
            locale=payload.locale,
            profile=profile,
            content_sha256=message_content_sha256(message.content),
        )

        # Request-level governance applies to every authorized TTS HTTP request,
        # including idempotency replays. Idempotency prevents duplicate provider
        # synthesis; it must not bypass endpoint abuse protection.
        _enforce_rate_limits(
            db,
            settings=settings,
            tenant_id=p.tenant_id,
            actor_id=p.user_id,
            message_id=message.id,
        )

        normalized_idempotency_key = (idempotency_key or "").strip()
        if normalized_idempotency_key:
            request_identity = request_idempotency_identity(
                tenant_id=p.tenant_id,
                actor_id=p.user_id,
                idempotency_key=normalized_idempotency_key,
                synthesis_identity_value=identity,
            )
            reservation = await reserve_tts_idempotency(settings, request_identity)
            if reservation.replay_audio is not None:
                audio = reservation.replay_audio
                cache_hit = False
                idempotency_replay = True
                duration_ms = 0
            else:
                cached = read_cached_speech(settings, identity)
                cache_hit = cached is not None
                if cached is None:
                    started = time.monotonic()
                    audio = await synthesize_speech(
                        settings,
                        profile,
                        message.content,
                        request_id=request_id,
                    )
                    duration_ms = int((time.monotonic() - started) * 1000)
                    write_cached_speech(settings, identity, audio)
                else:
                    audio = cached
                    duration_ms = 0
                complete_tts_idempotency(reservation, audio)
        else:
            cached = read_cached_speech(settings, identity)
            cache_hit = cached is not None
            if cached is None:
                started = time.monotonic()
                audio = await synthesize_speech(
                    settings,
                    profile,
                    message.content,
                    request_id=request_id,
                )
                duration_ms = int((time.monotonic() - started) * 1000)
                write_cached_speech(settings, identity, audio)
            else:
                audio = cached
                duration_ms = 0
    except VoiceBindingError as exc:
        _raise_voice_error(exc)
    except TextToSpeechError as exc:
        _raise_tts_error(exc)
    finally:
        release_tts_idempotency(reservation)

    _audit(
        db,
        principal=p,
        message_id=message.id,
        request_id=request_id,
        outcome="success",
        metadata={
            "thread_id": thread_id,
            "agent_id": profile.agent_id,
            "binding_id": profile.binding_id,
            "locale": profile.locale,
            "synthesis_identity": identity,
            "idempotency_key_present": bool((idempotency_key or "").strip()),
            "idempotency_replay": idempotency_replay,
            "cache_hit": cache_hit,
            "duration_ms": duration_ms,
        },
    )
    tts_logger.info(
        "MESSAGE_TTS_COMPLETED %s",
        json.dumps(
            {
                "request_id": request_id,
                "tenant_id": p.tenant_id,
                "thread_id": thread_id,
                "message_id": message.id,
                "agent_id": profile.agent_id,
                "binding_id": profile.binding_id,
                "locale": profile.locale,
                "cache_hit": cache_hit,
                "idempotency_replay": idempotency_replay,
                "duration_ms": duration_ms,
            },
            sort_keys=True,
        ),
    )
    return Response(
        content=audio,
        media_type="audio/mpeg",
        headers={
            "X-Orkio-Voice-Agent-Id": profile.agent_id,
            "X-Orkio-Voice-Binding-Id": profile.binding_id,
            "X-Orkio-Voice-Locale": profile.locale,
            "X-Orkio-TTS-Cache": "HIT" if cache_hit else "MISS",
            "X-Orkio-TTS-Idempotency": (
                "REPLAY" if idempotency_replay
                else "NEW" if (idempotency_key or "").strip()
                else "NONE"
            ),
        },
    )
