from __future__ import annotations

import asyncio
import base64
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .auth import Principal
from .config import Settings, get_settings
from .database import get_db
from .models import AuditEvent, Message, Thread, ThreadParticipant, ThreadRole
from .runtime.contracts import CanonicalTurnContext, RuntimeChannel
from .services.direct_runtime import build_turn as build_direct_turn
from .services.execution_router import resolve_direct_target_decision
from .services.identity import require_provisioned_principal
from .services.hyper_cocreator import is_allowlisted_admin
from .services.realtime_bridge import (
    RealtimeBridgeError,
    complete_receipt,
    fail_receipt,
    load_receipt,
    realtime_turn_key,
    reserve_receipt,
)
from .services.realtime_execution import (
    RealtimeExecutionError,
    execute_realtime_direct,
    execute_realtime_team,
    stream_realtime_direct,
)
from .services.realtime_session import (
    RealtimeSessionError,
    create_realtime_call,
    realtime_capability,
)
from .services.target_resolver import TargetAmbiguous, TargetNotFound
from .services.team_runtime import (
    TeamContractError,
    build_team_plan,
    build_team_turn,
)
from .services.voice_binding import VoiceBindingError, resolve_voice_profile
from .services.text_to_speech import TextToSpeechError, synthesize_speech


router = APIRouter(prefix="/api/v2", tags=["realtime"])
realtime_logger = logging.getLogger("uvicorn.error")


def _effective_direct_agent(requested_target: str, principal: Principal) -> str:
    if {"admin", "orkio_admin", "owner", "superadmin", "platform_owner"}.intersection(principal.roles):
        return requested_target
    # O resolver usa o namespace técnico explícito para IDs de agentes.
    return "id:orkio"


class RealtimeCallCreate(BaseModel):
    sdp: str = Field(min_length=16, max_length=131072)
    target_mode: Literal["direct", "team"] = "direct"
    agent: str | None = Field(default=None, max_length=160)
    team_id: str = Field("general_team", min_length=1, max_length=80)
    selection_mode: Literal["explicit", "all_eligible"] = "explicit"
    contributor_agent_ids: list[str] = Field(default_factory=list, max_length=64)
    locale: Literal["pt-BR", "en-US", "es-419"] = "pt-BR"


class RealtimeFinalTranscript(BaseModel):
    session_id: str = Field(min_length=1, max_length=128)
    provider_item_id: str = Field(min_length=1, max_length=256)
    transcript_final_id: str = Field(min_length=1, max_length=256)
    transcript: str = Field(min_length=1, max_length=100000)
    locale: Literal["pt-BR", "en-US", "es-419"] = "pt-BR"


def _thread_access(db: Session, *, thread_id: str, principal: Principal) -> ThreadParticipant:
    thread = db.get(Thread, thread_id)
    if thread is None or thread.tenant_id != principal.tenant_id:
        raise HTTPException(404, "THREAD_NOT_FOUND")
    member = db.scalar(
        select(ThreadParticipant).where(
            ThreadParticipant.thread_id == thread_id,
            ThreadParticipant.tenant_id == principal.tenant_id,
            ThreadParticipant.user_id == principal.user_id,
            ThreadParticipant.active.is_(True),
        )
    )
    if member is None:
        raise HTTPException(403, "THREAD_ACCESS_DENIED")
    if member.thread_role == ThreadRole.viewer.value:
        raise HTTPException(403, "THREAD_READ_ONLY")
    return member


def _audit(
    db: Session,
    *,
    principal: Principal,
    thread_id: str,
    action: str,
    outcome: str,
    execution_id: str | None = None,
    metadata: dict[str, object] | None = None,
):
    clean: dict[str, object] = {"thread_id": thread_id}
    for key, value in (metadata or {}).items():
        if key.casefold() in {"token", "secret", "authorization", "sdp", "content", "prompt", "transcript"}:
            continue
        if value is None or isinstance(value, (str, int, float, bool)):
            clean[str(key)[:80]] = value
        elif isinstance(value, (list, tuple)):
            clean[str(key)[:80]] = [str(x)[:80] for x in value[:32]]
    if execution_id:
        clean["execution_id"] = execution_id
    row = AuditEvent(
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action=action,
        resource_type="realtime_session",
        resource_id=execution_id,
        outcome=outcome,
        metadata_json=clean,
    )
    db.add(row)
    db.commit()


def _log_realtime_execution_failure(
    *,
    diagnostic_request_id: str,
    principal: Principal,
    thread_id: str,
    session_id: str,
    target_mode: str,
    stage: str,
    error_code: str,
    exception_type: str,
    execution_id: str | None = None,
    canonical_request_id: str | None = None,
    provider: str | None = None,
    model: str | None = None,
    upstream_status: int | None = None,
    upstream_code: str | None = None,
    upstream_type: str | None = None,
    upstream_classification: str | None = None,
    provider_request_id: str | None = None,
    retry_after: str | None = None,
    rate_limit_scope: str | None = None,
    operation: str | None = None,
    elapsed_ms: int | None = None,
) -> None:
    realtime_logger.error(
        "REALTIME_EXECUTION_FAILURE %s",
        json.dumps(
            {
                "diagnostic_request_id": diagnostic_request_id,
                "canonical_request_id": canonical_request_id,
                "execution_id": execution_id,
                "tenant_id": principal.tenant_id,
                "user_id": principal.user_id,
                "thread_id": thread_id,
                "session_id": session_id,
                "target_mode": target_mode,
                "pipeline": "realtime_canonical_execution",
                "stage": stage,
                "status": "failed",
                "error_code": error_code,
                "exception_type": exception_type,
                "provider": provider,
                "model": model,
                "upstream_status": upstream_status,
                "upstream_code": upstream_code,
                "upstream_type": upstream_type,
                "upstream_classification": upstream_classification,
                "provider_request_id": provider_request_id,
                "retry_after": retry_after,
                "rate_limit_scope": rate_limit_scope,
                "operation": operation,
                "elapsed_ms": elapsed_ms,
            },
            sort_keys=True,
        ),
    )


def _log_realtime_call_failure(
    *,
    settings: Settings,
    turn: CanonicalTurnContext,
    target_mode: str,
    locale: str,
    stage: str,
    error_code: str,
    exception_type: str,
    validation_scope: str | None = None,
) -> None:
    realtime_logger.error(
        "REALTIME_CALL_FAILURE %s",
        json.dumps(
            {
                "request_id": turn.request_id,
                "execution_id": turn.execution_id,
                "thread_id": turn.thread_id,
                "tenant_id": turn.tenant_id,
                "user_id": turn.user_id,
                "requested_target": turn.requested_target,
                "resolved_agent": turn.resolved_agent_id,
                "turn_owner": turn.turn_owner_agent_id,
                "route_family": turn.route_family.value,
                "channel": turn.channel.value,
                "target_mode": target_mode,
                "locale": locale,
                "pipeline": "realtime_call_setup",
                "stage": stage,
                "status": "failed",
                "error_code": error_code,
                "exception_type": exception_type,
                "validation_scope": validation_scope,
                "release_sha": settings.release_sha,
                "environment": settings.environment,
            },
            sort_keys=True,
        ),
    )


def _raise_team_contract(exc: TeamContractError) -> None:
    status = 400
    if exc.code in {"TEAM_NOT_FOUND", "TEAM_CONTRIBUTOR_NOT_FOUND"}:
        status = 404
    elif exc.code in {"TEAM_CONTRIBUTOR_NOT_ALLOWED", "TEAM_CHAIR_AS_CONTRIBUTOR_FORBIDDEN"}:
        status = 403
    raise HTTPException(status, detail={"code": exc.code}) from exc


@router.get("/realtime/capabilities")
def realtime_capabilities(
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
):
    del p
    return realtime_capability(settings)


@router.post("/threads/{thread_id}/realtime/calls")
async def realtime_call(
    thread_id: str,
    payload: RealtimeCallCreate,
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _thread_access(db, thread_id=thread_id, principal=p)
    _audit(
        db,
        principal=p,
        thread_id=thread_id,
        action="realtime_requested",
        outcome="requested",
        metadata={"transport": "webrtc", "target_mode": payload.target_mode},
    )

    try:
        if payload.target_mode == "direct":
            if not (payload.agent or "").strip():
                raise HTTPException(422, detail={"code": "REALTIME_TARGET_REQUIRED"})
            effective_agent = _effective_direct_agent(str(payload.agent), p)
            decision = resolve_direct_target_decision(effective_agent, settings)
            turn = build_direct_turn(
                execution=decision.execution,
                thread_id=thread_id,
                tenant_id=p.tenant_id,
                user_id=p.user_id,
                requested_target=effective_agent,
                channel=RuntimeChannel.REALTIME,
            )
            intent_metadata: dict[str, object] = {
                "target_mode": "direct",
                "agent_id": turn.turn_owner_agent_id,
                "locale": payload.locale,
                "ownership_locked": turn.ownership_locked,
            }
        else:
            plan = build_team_plan(
                team_id=payload.team_id,
                settings=settings,
                selection_mode=payload.selection_mode,
                contributor_agent_ids=payload.contributor_agent_ids,
            )
            turn = build_team_turn(
                thread_id=thread_id,
                tenant_id=p.tenant_id,
                user_id=p.user_id,
                requested_target=f"team:{payload.team_id}",
                orchestrator_agent_id=plan.orchestrator_agent_id,
                channel=RuntimeChannel.REALTIME,
            )
            intent_metadata = {
                "target_mode": "team",
                "team_id": payload.team_id,
                "selection_mode": payload.selection_mode,
                "contributor_agent_ids": list(plan.contributor_agent_ids),
                "agent_id": turn.turn_owner_agent_id,
                "locale": payload.locale,
                "ownership_locked": turn.ownership_locked,
            }
    except TargetAmbiguous as exc:
        raise HTTPException(409, detail={"code": exc.code, "candidates": list(exc.candidates)}) from exc
    except TargetNotFound as exc:
        raise HTTPException(404, detail={"code": exc.code}) from exc
    except TeamContractError as exc:
        _raise_team_contract(exc)

    _audit(
        db,
        principal=p,
        thread_id=thread_id,
        action="realtime_authorized",
        outcome="success",
        execution_id=turn.execution_id,
        metadata=intent_metadata,
    )

    capability = realtime_capability(settings)
    session_capability = capability["realtime_session"]
    if not bool(session_capability.get("eligible")):
        code = str(session_capability.get("reason_code") or "REALTIME_NOT_CONFIGURED")
        _log_realtime_call_failure(
            settings=settings,
            turn=turn,
            target_mode=payload.target_mode,
            locale=payload.locale,
            stage="realtime_session_capability",
            error_code=code,
            exception_type="CapabilityIneligible",
        )
        _audit(
            db,
            principal=p,
            thread_id=thread_id,
            action="realtime_failed",
            outcome="failed",
            execution_id=turn.execution_id,
            metadata={
                "request_id": turn.request_id,
                "stage": "realtime_session_capability",
                "error_code": code,
                "agent_id": turn.turn_owner_agent_id,
            },
        )
        raise HTTPException(403, code)

    bridge_capability = capability["orchestration_bridge"]
    if not bool(bridge_capability.get("eligible")):
        code = str(
            bridge_capability.get("reason_code")
            or "REALTIME_ORCHESTRATION_BRIDGE_REQUIRED"
        )
        _log_realtime_call_failure(
            settings=settings,
            turn=turn,
            target_mode=payload.target_mode,
            locale=payload.locale,
            stage="orchestration_bridge",
            error_code=code,
            exception_type="CapabilityIneligible",
        )
        _audit(
            db,
            principal=p,
            thread_id=thread_id,
            action="realtime_failed",
            outcome="failed",
            execution_id=turn.execution_id,
            metadata={
                "request_id": turn.request_id,
                "stage": "orchestration_bridge",
                "error_code": code,
                "agent_id": turn.turn_owner_agent_id,
            },
        )
        raise HTTPException(503, code)

    if not bool(capability["voice_output"].get("eligible")):
        code = "REALTIME_VOICE_OUTPUT_REQUIRED"
        _log_realtime_call_failure(
            settings=settings,
            turn=turn,
            target_mode=payload.target_mode,
            locale=payload.locale,
            stage="voice_output_capability",
            error_code=code,
            exception_type="CapabilityIneligible",
        )
        raise HTTPException(503, detail={"code": code})

    try:
        # Validate the exact output identity before opening microphone transport.
        resolve_voice_profile(
            turn.turn_owner_agent_id,
            payload.locale,
            settings,
            delivery_mode="REALTIME_STREAM",
            db=db,
            tenant_id=p.tenant_id,
        )
        result = await create_realtime_call(
            settings=settings,
            turn=turn,
            sdp_offer=payload.sdp,
            locale=payload.locale,
        )
    except VoiceBindingError as exc:
        _log_realtime_call_failure(
            settings=settings,
            turn=turn,
            target_mode=payload.target_mode,
            locale=payload.locale,
            stage="voice_binding",
            error_code=exc.code,
            exception_type=type(exc).__name__,
            validation_scope=exc.validation_scope,
        )
        raise HTTPException(503, detail={"code": exc.code}) from exc
    except RealtimeSessionError as exc:
        _log_realtime_call_failure(
            settings=settings,
            turn=turn,
            target_mode=payload.target_mode,
            locale=payload.locale,
            stage="provider_call",
            error_code=exc.code,
            exception_type=type(exc).__name__,
        )
        _audit(
            db,
            principal=p,
            thread_id=thread_id,
            action="realtime_failed",
            outcome="failed",
            execution_id=turn.execution_id,
            metadata={
                "request_id": turn.request_id,
                "stage": "provider_call",
                "error_code": exc.code,
                "agent_id": turn.turn_owner_agent_id,
            },
        )
        status = 403 if exc.code == "REALTIME_VOICE_DISABLED" else 503
        raise HTTPException(status, exc.code) from exc

    _audit(
        db,
        principal=p,
        thread_id=thread_id,
        action="session_created",
        outcome="success",
        execution_id=turn.execution_id,
        metadata={
            **intent_metadata,
            "model": result.model,
            "output_modalities": ",".join(result.output_modalities),
            "provider_call_id_present": bool(result.call_id),
        },
    )
    return {
        "sdp": result.sdp_answer,
        "call_id": result.call_id,
        "session_id": turn.execution_id,
        "execution_id": turn.execution_id,
        "agent_id": turn.turn_owner_agent_id,
        "agent_name": turn.display_agent_name,
        "turn_owner": turn.turn_owner_agent_id,
        "ownership_locked": turn.ownership_locked,
        "target_mode": payload.target_mode,
        "transport": "webrtc",
        "model": result.model,
        "output_modalities": list(result.output_modalities),
        "orchestration_bridge": True,
        "persistence": "canonical_on_transcript_final",
        "runtime_proven": False,
    }


def _session_intent(
    db: Session,
    *,
    principal: Principal,
    thread_id: str,
    session_id: str,
) -> dict[str, object]:
    authorized = db.scalar(
        select(AuditEvent).where(
            AuditEvent.id.is_not(None),
            AuditEvent.tenant_id == principal.tenant_id,
            AuditEvent.actor_id == principal.user_id,
            AuditEvent.action == "realtime_authorized",
            AuditEvent.resource_id == session_id,
        )
    )
    created = db.scalar(
        select(AuditEvent).where(
            AuditEvent.tenant_id == principal.tenant_id,
            AuditEvent.actor_id == principal.user_id,
            AuditEvent.action == "session_created",
            AuditEvent.resource_id == session_id,
        )
    )
    if authorized is None or created is None:
        raise HTTPException(404, detail={"code": "REALTIME_SESSION_NOT_FOUND"})
    data = dict(authorized.metadata_json or {})
    if str(data.get("thread_id") or "") != thread_id:
        raise HTTPException(409, detail={"code": "REALTIME_THREAD_CHANGED"})
    if not bool(data.get("ownership_locked")):
        raise HTTPException(409, detail={"code": "REALTIME_OWNER_MISMATCH"})
    return data


_REALTIME_STREAM_MAX_SEGMENTS = 16


def _sse_payload(payload: dict[str, object]) -> str:
    event_type = str(payload.get("type") or "message")
    return (
        f"event: {event_type}\n"
        f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
    )


def _enforce_realtime_segment_limits(
    db: Session,
    *,
    settings: Settings,
    principal: Principal,
    thread_id: str,
    turn_id: str,
    segment_id: str,
) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=1)
    statement = select(func.count(AuditEvent.id)).where(
        AuditEvent.tenant_id == principal.tenant_id,
        AuditEvent.action == "realtime_tts_segment",
        AuditEvent.created_at >= cutoff,
    )
    tenant_count = int(db.scalar(statement) or 0)
    if tenant_count >= settings.tts_tenant_rate_limit_per_minute:
        raise TextToSpeechError("TTS_RATE_LIMITED")
    user_count = int(
        db.scalar(statement.where(AuditEvent.actor_id == principal.user_id)) or 0
    )
    if user_count >= settings.tts_user_rate_limit_per_minute:
        raise TextToSpeechError("TTS_RATE_LIMITED")
    db.add(
        AuditEvent(
            tenant_id=principal.tenant_id,
            actor_id=principal.user_id,
            action="realtime_tts_segment",
            resource_type="realtime_turn",
            resource_id=turn_id,
            outcome="started",
            metadata_json={"thread_id": thread_id, "segment_id": segment_id},
        )
    )
    db.commit()


@router.post("/threads/{thread_id}/realtime/turns/stream")
async def realtime_stream_turn(
    thread_id: str,
    payload: RealtimeFinalTranscript,
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    """Stream the governed direct Co-Creator answer as text plus speech segments.

    The existing provider Realtime call remains input/VAD/transcription-only.
    This endpoint owns the canonical LLM stream and uses the configured TTS
    adapter once per safe sentence as an incremental compatibility path.
    """
    _thread_access(db, thread_id=thread_id, principal=p)
    if not settings.realtime_bridge_enabled:
        raise HTTPException(503, detail={"code": "REALTIME_ORCHESTRATION_BRIDGE_REQUIRED"})
    if not settings.tts_enabled:
        raise HTTPException(503, detail={"code": "TTS_DISABLED"})

    intent = _session_intent(
        db,
        principal=p,
        thread_id=thread_id,
        session_id=payload.session_id,
    )
    if str(intent.get("target_mode") or "direct") != "direct":
        raise HTTPException(409, detail={"code": "REALTIME_STREAM_TEAM_NOT_SUPPORTED"})
    agent_id = str(intent.get("agent_id") or "").strip()
    if not agent_id:
        raise HTTPException(409, detail={"code": "REALTIME_OWNER_MISMATCH"})

    try:
        profile = resolve_voice_profile(
            agent_id,
            payload.locale,
            settings,
            delivery_mode="REALTIME_STREAM",
            db=db,
            tenant_id=p.tenant_id,
        )
    except VoiceBindingError as exc:
        _raise_voice_error(exc)

    try:
        turn_key = realtime_turn_key(
            tenant_id=p.tenant_id,
            thread_id=thread_id,
            session_id=payload.session_id,
            provider_item_id=payload.provider_item_id,
            transcript_final_id=payload.transcript_final_id,
        )
    except RealtimeBridgeError as exc:
        raise HTTPException(422, detail={"code": exc.code}) from exc

    existing = load_receipt(db, tenant_id=p.tenant_id, turn_key=turn_key)
    if existing is not None:
        if existing.state == "completed":
            raise HTTPException(409, detail={"code": "REALTIME_TURN_ALREADY_COMPLETED"})
        if existing.state == "processing":
            raise HTTPException(409, detail={"code": "REALTIME_TURN_IN_PROGRESS"})
        raise HTTPException(409, detail={"code": "REALTIME_PREVIOUS_ATTEMPT_FAILED"})

    reserve_receipt(
        db,
        tenant_id=p.tenant_id,
        actor_id=p.user_id,
        thread_id=thread_id,
        turn_key=turn_key,
        session_id=payload.session_id,
    )

    async def events():
        emitted_done = False
        segments_count = 0
        try:
            async for item in stream_realtime_direct(
                db,
                settings=settings,
                tenant_id=p.tenant_id,
                user_id=p.user_id,
                thread_id=thread_id,
                agent_id=agent_id,
                transcript=payload.transcript,
                is_admin=is_allowlisted_admin(p, settings),
            ):
                item_type = str(item.get("type") or "")
                if item_type == "segment_ready":
                    segments_count += 1
                    if segments_count > _REALTIME_STREAM_MAX_SEGMENTS:
                        raise RealtimeExecutionError(
                            "REALTIME_TTS_SEGMENT_LIMIT",
                            stage="tts_segment_limit",
                        )
                    segment_id = str(item.get("segment_id") or f"seg-{segments_count}")
                    text_value = str(item.get("text") or "").strip()
                    if not text_value:
                        continue
                    yield _sse_payload({
                        "type": "segment_started",
                        "turn_id": item.get("turn_id"),
                        "segment_id": segment_id,
                        "segment_number": segments_count,
                        "text": text_value,
                    })
                    _enforce_realtime_segment_limits(
                        db,
                        settings=settings,
                        principal=p,
                        thread_id=thread_id,
                        turn_id=str(item.get("turn_id") or payload.session_id),
                        segment_id=segment_id,
                    )
                    try:
                        audio = await synthesize_speech(
                            settings,
                            profile,
                            text_value,
                            request_id=f"{item.get('turn_id', payload.session_id)}:{segment_id}",
                        )
                    except TextToSpeechError:
                        raise
                    yield _sse_payload({
                        "type": "audio_segment",
                        "turn_id": item.get("turn_id"),
                        "segment_id": segment_id,
                        "segment_number": segments_count,
                        "codec": "audio/mpeg",
                        "data_base64": base64.b64encode(audio).decode("ascii"),
                    })
                    yield _sse_payload({
                        "type": "segment_done",
                        "turn_id": item.get("turn_id"),
                        "segment_id": segment_id,
                        "segment_number": segments_count,
                    })
                elif item_type == "text_delta":
                    yield _sse_payload(item)
                elif item_type == "turn_started":
                    yield _sse_payload(item)
                elif item_type == "done":
                    receipt = complete_receipt(
                        db,
                        tenant_id=p.tenant_id,
                        turn_key=turn_key,
                        message_id=str(item["message_id"]),
                        execution_id=str(item["execution_id"]),
                        agent_id=str(item["agent_id"]),
                    )
                    done_payload = dict(item)
                    done_payload["execution_id"] = receipt.execution_id
                    done_payload["segments_count"] = segments_count
                    emitted_done = True
                    yield _sse_payload(done_payload)
        except asyncio.CancelledError:
            if not emitted_done:
                fail_receipt(
                    db,
                    tenant_id=p.tenant_id,
                    turn_key=turn_key,
                    error_code="CLIENT_DISCONNECTED",
                )
            raise
        except (RealtimeExecutionError, TextToSpeechError) as exc:
            if not emitted_done:
                code = getattr(exc, "code", "REALTIME_STREAM_FAILED")
                fail_receipt(
                    db,
                    tenant_id=p.tenant_id,
                    turn_key=turn_key,
                    error_code=code,
                )
                yield _sse_payload({
                    "type": "error",
                    "code": code,
                    "turn_id": payload.session_id,
                })
                yield _sse_payload({
                    "type": "done",
                    "status": "failed",
                    "code": code,
                    "turn_id": payload.session_id,
                })
        except Exception:
            if not emitted_done:
                fail_receipt(
                    db,
                    tenant_id=p.tenant_id,
                    turn_key=turn_key,
                    error_code="REALTIME_STREAM_FAILED",
                )
                yield _sse_payload({
                    "type": "error",
                    "code": "REALTIME_STREAM_FAILED",
                    "turn_id": payload.session_id,
                })
                yield _sse_payload({
                    "type": "done",
                    "status": "failed",
                    "code": "REALTIME_STREAM_FAILED",
                    "turn_id": payload.session_id,
                })

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.post("/threads/{thread_id}/realtime/turns")
async def realtime_final_turn(
    thread_id: str,
    payload: RealtimeFinalTranscript,
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _thread_access(db, thread_id=thread_id, principal=p)
    if not settings.realtime_bridge_enabled:
        raise HTTPException(503, detail={"code": "REALTIME_ORCHESTRATION_BRIDGE_REQUIRED"})

    intent = _session_intent(
        db,
        principal=p,
        thread_id=thread_id,
        session_id=payload.session_id,
    )
    transcript = payload.transcript.strip()
    if not transcript:
        raise HTTPException(422, detail={"code": "REALTIME_TRANSCRIPT_EMPTY"})

    try:
        turn_key = realtime_turn_key(
            tenant_id=p.tenant_id,
            thread_id=thread_id,
            session_id=payload.session_id,
            provider_item_id=payload.provider_item_id,
            transcript_final_id=payload.transcript_final_id,
        )
    except RealtimeBridgeError as exc:
        raise HTTPException(422, detail={"code": exc.code}) from exc

    existing = load_receipt(db, tenant_id=p.tenant_id, turn_key=turn_key)
    if existing is not None:
        if existing.state == "completed" and existing.message_id:
            message = db.get(Message, existing.message_id)
            if message is None or message.tenant_id != p.tenant_id or message.thread_id != thread_id:
                raise HTTPException(409, detail={"code": "REALTIME_RECEIPT_MESSAGE_MISMATCH"})
            return {
                "status": "completed",
                "reconciled": True,
                "terminal_event": "done",
                "message_id": message.id,
                "execution_id": existing.execution_id,
                "agent_id": existing.agent_id,
                "content": message.content,
            }
        if existing.state == "processing":
            raise HTTPException(409, detail={"code": "REALTIME_TURN_IN_PROGRESS"})
        raise HTTPException(409, detail={"code": "REALTIME_PREVIOUS_ATTEMPT_FAILED"})

    reserve_receipt(
        db,
        tenant_id=p.tenant_id,
        actor_id=p.user_id,
        thread_id=thread_id,
        turn_key=turn_key,
        session_id=payload.session_id,
    )

    diagnostic_request_id = str(uuid.uuid4())
    target_mode = str(intent.get("target_mode") or "direct")
    route_stage = "execute_team" if target_mode == "team" else "execute_direct"
    result = None

    try:
        if target_mode == "team":
            contributor_ids = tuple(
                str(x) for x in (intent.get("contributor_agent_ids") or [])
            )
            result = await execute_realtime_team(
                db,
                settings=settings,
                tenant_id=p.tenant_id,
                user_id=p.user_id,
                thread_id=thread_id,
                team_id=str(intent.get("team_id") or "general_team"),
                selection_mode=str(intent.get("selection_mode") or "explicit"),
                contributor_agent_ids=contributor_ids,
                transcript=transcript,
            )
        else:
            agent_id = str(intent.get("agent_id") or "").strip()
            if not agent_id:
                raise RealtimeExecutionError("REALTIME_OWNER_MISMATCH")
            result = await execute_realtime_direct(
                db,
                settings=settings,
                tenant_id=p.tenant_id,
                user_id=p.user_id,
                thread_id=thread_id,
                agent_id=agent_id,
                transcript=transcript,
                is_admin=is_allowlisted_admin(p, settings),
            )

        route_stage = "complete_receipt"
        receipt = complete_receipt(
            db,
            tenant_id=p.tenant_id,
            turn_key=turn_key,
            message_id=result.message_id,
            execution_id=result.execution_id,
            agent_id=result.agent_id,
        )
    except (RealtimeExecutionError, TeamContractError) as exc:
        code = getattr(exc, "code", "REALTIME_EXECUTION_FAILED")
        stage = getattr(exc, "stage", None) or route_stage
        exception_type = getattr(exc, "exception_type", None) or type(exc).__name__
        execution_id = getattr(exc, "execution_id", None)
        canonical_request_id = getattr(exc, "request_id", None)
        _log_realtime_execution_failure(
            diagnostic_request_id=diagnostic_request_id,
            principal=p,
            thread_id=thread_id,
            session_id=payload.session_id,
            target_mode=target_mode,
            stage=stage,
            error_code=code,
            exception_type=exception_type,
            execution_id=execution_id,
            canonical_request_id=canonical_request_id,
            provider=getattr(exc, "provider", None),
            model=getattr(exc, "model", None),
            upstream_status=getattr(exc, "upstream_status", None),
            upstream_code=getattr(exc, "upstream_code", None),
            upstream_type=getattr(exc, "upstream_type", None),
            upstream_classification=getattr(exc, "upstream_classification", None),
            provider_request_id=getattr(exc, "provider_request_id", None),
            retry_after=getattr(exc, "retry_after", None),
            rate_limit_scope=getattr(exc, "rate_limit_scope", None),
            operation=getattr(exc, "operation", None),
            elapsed_ms=getattr(exc, "elapsed_ms", None),
        )
        fail_receipt(db, tenant_id=p.tenant_id, turn_key=turn_key, error_code=code)
        raise HTTPException(502, detail={"code": code}) from exc
    except Exception as exc:
        execution_id = getattr(result, "execution_id", None) if result is not None else None
        _log_realtime_execution_failure(
            diagnostic_request_id=diagnostic_request_id,
            principal=p,
            thread_id=thread_id,
            session_id=payload.session_id,
            target_mode=target_mode,
            stage=route_stage,
            error_code="REALTIME_EXECUTION_FAILED",
            exception_type=type(exc).__name__,
            execution_id=execution_id,
        )
        fail_receipt(
            db,
            tenant_id=p.tenant_id,
            turn_key=turn_key,
            error_code="REALTIME_EXECUTION_FAILED",
        )
        raise HTTPException(502, detail={"code": "REALTIME_EXECUTION_FAILED"}) from exc

    return {
        "status": "completed",
        "reconciled": False,
        "terminal_event": "done",
        "message_id": result.message_id,
        "execution_id": receipt.execution_id,
        "agent_id": result.agent_id,
        "agent_name": result.agent_name,
        "target_mode": result.target_mode,
        "content": result.content,
        "tts_path": f"/api/v2/threads/{thread_id}/messages/{result.message_id}/voice",
    }
