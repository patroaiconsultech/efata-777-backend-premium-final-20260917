from __future__ import annotations

from typing import Literal

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .auth import Principal
from .config import Settings, get_settings
from .database import get_db
from .services import llm
from .services.identity import require_provisioned_principal
from .services.team_runtime import (
    TeamContractError,
    assert_team_thread_access,
    build_team_plan,
    build_team_turn,
    list_team_definitions,
    persist_team_contribution,
    persist_team_final,
    persist_user_message,
    team_audit,
    team_history,
    team_definition_payload,
)
from .runtime.events import RuntimeEvent, RuntimeEventType, validate_runtime_sequence
from .services.execution_correlation import ExecutionCorrelation


router = APIRouter(prefix="/api/v2", tags=["team"])


class TeamMessageCreate(BaseModel):
    content: str = Field(min_length=1, max_length=100000)
    team_id: str = Field("general_team", min_length=1, max_length=80)
    selection_mode: Literal["explicit", "all_eligible"] = "explicit"
    contributor_agent_ids: list[str] = Field(default_factory=list, max_length=64)
    # Rolling-deploy compatibility only. Server remains authoritative for chair.
    orchestrator_agent_id: str | None = Field(default=None, max_length=80)
    participant_agent_ids: list[str] | None = Field(default=None, max_length=64)




def _raise_team_error(exc: TeamContractError):
    status = 400
    if exc.code == "THREAD_NOT_FOUND":
        status = 404
    elif exc.code in {"THREAD_ACCESS_DENIED", "THREAD_READ_ONLY"}:
        status = 403
    elif exc.code in {"TEAM_NOT_FOUND", "TEAM_AGENT_NOT_FOUND", "TEAM_CONTRIBUTOR_NOT_FOUND"}:
        status = 404
    elif exc.code in {"TEAM_AGENT_NOT_ALLOWED", "TEAM_CONTRIBUTOR_NOT_ALLOWED", "TEAM_ORCHESTRATOR_NOT_ALLOWED", "TEAM_CHAIR_AS_CONTRIBUTOR_FORBIDDEN"}:
        status = 403
    elif exc.code.endswith("_UNCONFIGURED") or exc.code.endswith("_NOT_BOUND"):
        status = 503
    detail: dict[str, object] = {"code": exc.code}
    if exc.agent_id:
        detail["agent_id"] = exc.agent_id
    raise HTTPException(status_code=status, detail=detail) from exc


@router.get("/teams")
def teams_catalog(
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
):
    del p
    return [
        team_definition_payload(item, settings)
        for item in list_team_definitions()
    ]


@router.post("/threads/{thread_id}/team/stream")
async def stream_team_message(
    thread_id: str,
    payload: TeamMessageCreate,
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    try:
        assert_team_thread_access(db, thread_id=thread_id, principal=p)
        plan = build_team_plan(
            team_id=payload.team_id,
            selection_mode=payload.selection_mode,
            contributor_agent_ids=payload.contributor_agent_ids,
            orchestrator_agent_id=payload.orchestrator_agent_id,
            participant_agent_ids=payload.participant_agent_ids,
            settings=settings,
        )
    except TeamContractError as exc:
        _raise_team_error(exc)

    if not settings.realtime_streaming_enabled:
        raise HTTPException(403, "REALTIME_STREAMING_DISABLED")

    try:
        llm.ensure_configured(settings)
    except llm.LLMNotConfigured as exc:
        raise HTTPException(503, "LLM_NOT_CONFIGURED") from exc

    turn = build_team_turn(
        thread_id=thread_id,
        tenant_id=p.tenant_id,
        user_id=p.user_id,
        requested_target=f"team:{payload.team_id}",
        orchestrator_agent_id=plan.orchestrator_agent_id,
    )

    team_audit(
        db,
        turn=turn,
        action="team_mode_requested",
        outcome="accepted",
        metadata={"team_id": plan.definition.team_id, "participants_count": len(plan.contributor_agent_ids)},
    )
    team_audit(
        db,
        turn=turn,
        action="team_authorized",
        outcome="success",
        metadata={"team_id": plan.definition.team_id, "participants_count": len(plan.contributor_agent_ids)},
    )

    persist_user_message(db, turn=turn, content=payload.content)
    base_history = team_history(
        db,
        thread_id=thread_id,
        tenant_id=p.tenant_id,
        settings=settings,
        user_id=p.user_id,
        execution_id=turn.execution_id,
        agent_id=turn.turn_owner_agent_id,
        purpose="team",
    )

    correlation = ExecutionCorrelation(
        request_id=turn.request_id,
        execution_id=turn.execution_id,
        tenant_id=turn.tenant_id,
        thread_id=turn.thread_id,
        owner_agent_id=turn.turn_owner_agent_id,
        execution_engine="team",
    )

    def sse_event(item: RuntimeEvent) -> str:
        data = dict(item.data)
        data.setdefault("execution_id", item.execution_id)
        data.setdefault("sequence", item.sequence)
        return f"event: {item.event_type.value}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

    async def events():
        emitted: list[RuntimeEvent] = []
        sequence = 1

        def event(kind: RuntimeEventType, **data: object) -> RuntimeEvent:
            nonlocal sequence
            item = RuntimeEvent(kind, turn.execution_id, sequence, correlation.event_data(**data))
            sequence += 1
            emitted.append(item)
            return item

        def terminal(kind: RuntimeEventType, **data: object) -> RuntimeEvent:
            item = event(kind, **data)
            validate_runtime_sequence(tuple(emitted))
            return item

        try:
            team_audit(
                db,
                turn=turn,
                action="orchestration_started",
                outcome="started",
                metadata={"team_id": plan.definition.team_id, "participants_count": len(plan.contributor_agent_ids)},
            )
            yield sse_event(
                event(
                    RuntimeEventType.STATUS,
                    status="team_started",
                    team_id=plan.definition.team_id,
                    orchestrator_agent_id=plan.orchestrator_agent_id,
                    participant_agent_ids=list(plan.participant_agent_ids),
                    contributor_agent_ids=list(plan.contributor_agent_ids),
                    participants_count=len(plan.contributor_agent_ids),
                    ownership_locked=True,
                )
            )

            contributions: list[tuple[str, str]] = []
            failures: list[tuple[str, str]] = []

            for agent_id in plan.contributor_agent_ids:
                from .agents.registry import resolve_agent_by_id
                agent = resolve_agent_by_id(agent_id)
                yield sse_event(
                    event(
                        RuntimeEventType.AGENT_STARTED,
                        agent_id=agent.slug,
                        agent_name=agent.display_name,
                        status="started",
                    )
                )
                team_audit(
                    db,
                    turn=turn,
                    action="team_agent_started",
                    outcome="started",
                    metadata={"agent_id": agent.slug},
                )
                parts: list[str] = []
                try:
                    async for piece in llm.stream(settings, agent.slug, list(base_history)):
                        parts.append(piece)
                        yield sse_event(
                            event(
                                RuntimeEventType.AGENT_CHUNK,
                                agent_id=agent.slug,
                                agent_name=agent.display_name,
                                text=piece,
                            )
                        )
                    contribution = "".join(parts).strip()
                    if not contribution:
                        raise llm.LLMUpstreamError("LLM_EMPTY_RESPONSE")
                except llm.LLMNotConfigured:
                    code = "LLM_NOT_CONFIGURED"
                    failures.append((agent.slug, code))
                    team_audit(
                        db,
                        turn=turn,
                        action="team_agent_failed",
                        outcome="failed",
                        metadata={"agent_id": agent.slug, "error_code": code},
                    )
                    yield sse_event(
                        event(
                            RuntimeEventType.AGENT_DONE,
                            agent_id=agent.slug,
                            agent_name=agent.display_name,
                            status="failed",
                            error_code=code,
                        )
                    )
                    continue
                except Exception:
                    code = "LLM_UPSTREAM_ERROR"
                    failures.append((agent.slug, code))
                    team_audit(
                        db,
                        turn=turn,
                        action="team_agent_failed",
                        outcome="failed",
                        metadata={"agent_id": agent.slug, "error_code": code},
                    )
                    yield sse_event(
                        event(
                            RuntimeEventType.AGENT_DONE,
                            agent_id=agent.slug,
                            agent_name=agent.display_name,
                            status="failed",
                            error_code=code,
                        )
                    )
                    continue

                try:
                    persist_team_contribution(
                        db,
                        turn=turn,
                        agent_id=agent.slug,
                        content=contribution,
                    )
                except Exception:
                    db.rollback()
                    team_audit(
                        db,
                        turn=turn,
                        action="team_failed",
                        outcome="failed",
                        metadata={
                            "reason_code": "PERSISTENCE_FAILED",
                            "agent_id": agent.slug,
                        },
                    )
                    yield sse_event(
                        event(
                            RuntimeEventType.AGENT_DONE,
                            agent_id=agent.slug,
                            agent_name=agent.display_name,
                            status="failed",
                            error_code="PERSISTENCE_FAILED",
                        )
                    )
                    yield sse_event(event(RuntimeEventType.ERROR, code="PERSISTENCE_FAILED"))
                    yield sse_event(terminal(RuntimeEventType.DONE, status="failed"))
                    return

                contributions.append((agent.slug, contribution))
                team_audit(
                    db,
                    turn=turn,
                    action="team_agent_completed",
                    outcome="success",
                    metadata={"agent_id": agent.slug},
                )
                yield sse_event(
                    event(
                        RuntimeEventType.AGENT_DONE,
                        agent_id=agent.slug,
                        agent_name=agent.display_name,
                        status="completed",
                    )
                )

            if not contributions:
                team_audit(
                    db,
                    turn=turn,
                    action="team_failed",
                    outcome="failed",
                    metadata={"reason_code": "TEAM_ALL_CONTRIBUTORS_FAILED"},
                )
                yield sse_event(event(RuntimeEventType.ERROR, code="TEAM_ALL_CONTRIBUTORS_FAILED"))
                yield sse_event(terminal(RuntimeEventType.DONE, status="failed"))
                return

            yield sse_event(
                event(
                    RuntimeEventType.STATUS,
                    status="team_synthesizing",
                    orchestrator_agent_id=plan.orchestrator_agent_id,
                    completed_agents=len(contributions),
                    failed_agents=len(failures),
                )
            )

            synthesis_history = list(base_history)
            for agent_id, content in contributions:
                from .agents.registry import resolve_agent_by_id
                agent = resolve_agent_by_id(agent_id)
                synthesis_history.append(
                    {
                        "role": "assistant",
                        "content": f"[ContextContribution · {agent.display_name} · id:{agent.slug}] {content}",
                    }
                )
            synthesis_history.append(
                {
                    "role": "user",
                    "content": (
                        "Consolide as contribuições do Team em uma resposta única para a solicitação do usuário. "
                        "Preserve divergências relevantes, não invente consenso e não atribua a si mesmo trabalho "
                        "que pertence aos especialistas."
                    ),
                }
            )

            synthesis_parts: list[str] = []
            try:
                async for piece in llm.stream(
                    settings,
                    plan.orchestrator_agent_id,
                    synthesis_history,
                ):
                    synthesis_parts.append(piece)
                    yield sse_event(
                        event(
                            RuntimeEventType.CHUNK,
                            agent_id=turn.turn_owner_agent_id,
                            agent_name=turn.display_agent_name,
                            text=piece,
                            phase="team_synthesis",
                        )
                    )
            except llm.LLMNotConfigured:
                team_audit(
                    db,
                    turn=turn,
                    action="team_failed",
                    outcome="failed",
                    metadata={"reason_code": "LLM_NOT_CONFIGURED"},
                )
                yield sse_event(event(RuntimeEventType.ERROR, code="LLM_NOT_CONFIGURED"))
                yield sse_event(terminal(RuntimeEventType.DONE, status="failed"))
                return
            except Exception:
                team_audit(
                    db,
                    turn=turn,
                    action="team_failed",
                    outcome="failed",
                    metadata={"reason_code": "TEAM_SYNTHESIS_FAILED"},
                )
                yield sse_event(event(RuntimeEventType.ERROR, code="TEAM_SYNTHESIS_FAILED"))
                yield sse_event(terminal(RuntimeEventType.DONE, status="failed"))
                return

            answer = "".join(synthesis_parts).strip()
            if not answer:
                team_audit(
                    db,
                    turn=turn,
                    action="team_failed",
                    outcome="failed",
                    metadata={"reason_code": "TEAM_EMPTY_SYNTHESIS"},
                )
                yield sse_event(event(RuntimeEventType.ERROR, code="TEAM_EMPTY_SYNTHESIS"))
                yield sse_event(terminal(RuntimeEventType.DONE, status="failed"))
                return

            try:
                row, envelope = persist_team_final(db, turn=turn, content=answer)
            except Exception:
                db.rollback()
                team_audit(
                    db,
                    turn=turn,
                    action="team_failed",
                    outcome="failed",
                    metadata={"reason_code": "PERSISTENCE_FAILED"},
                )
                yield sse_event(event(RuntimeEventType.ERROR, code="PERSISTENCE_FAILED"))
                yield sse_event(terminal(RuntimeEventType.DONE, status="failed"))
                return

            team_audit(
                db,
                turn=turn,
                action="team_completed",
                outcome="success",
                metadata={
                    "team_id": plan.definition.team_id,
                    "participants_count": len(plan.contributor_agent_ids),
                    "completed_agents": len(contributions),
                    "failed_agents": len(failures),
                    "message_id": row.id,
                },
            )
            yield sse_event(
                terminal(
                    RuntimeEventType.DONE,
                    status="completed",
                    team_id=plan.definition.team_id,
                    participant_agent_ids=list(plan.participant_agent_ids),
                    contributor_agent_ids=list(plan.contributor_agent_ids),
                    completed_agent_ids=[agent_id for agent_id, _ in contributions],
                    failed_agent_ids=[agent_id for agent_id, _ in failures],
                    orchestrator_agent_id=plan.orchestrator_agent_id,
                    message_id=row.id,
                    agent_id=envelope["agent_id"],
                    agent_name=envelope["agent_name"],
                    turn_owner=envelope["turn_owner_agent_id"],
                    ownership_locked=True,
                    response=envelope,
                )
            )
        except asyncio.CancelledError:
            team_audit(
                db,
                turn=turn,
                action="team_failed",
                outcome="cancelled",
                metadata={"reason_code": "CLIENT_DISCONNECTED"},
            )
            raise

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
