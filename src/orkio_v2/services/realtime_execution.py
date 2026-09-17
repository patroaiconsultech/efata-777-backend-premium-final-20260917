from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

from sqlalchemy.orm import Session

from ..config import Settings
from ..runtime.contracts import RuntimeChannel
from . import llm
from .direct_runtime import (
    build_turn as build_direct_turn,
    envelope_payload,
    persist_agent_response,
)
from .execution_router import resolve_direct_target_decision
from .hyper_cocreator import hyper_cocreator_system_message, profile_for
from .github_integration import github_context_messages
from .internal_consultation import (
    build_internal_consultation_context,
    internal_contribution_messages,
)
from .team_runtime import (
    build_team_plan,
    build_team_turn,
    persist_team_contribution,
    persist_team_final,
    persist_user_message,
    team_history,
)
from .realtime_segmenter import SentenceSegmenter


class RealtimeExecutionError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        stage: str | None = None,
        exception_type: str | None = None,
        request_id: str | None = None,
        execution_id: str | None = None,
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
    ):
        super().__init__(code)
        self.code = code
        self.stage = stage
        self.exception_type = exception_type
        self.request_id = request_id
        self.execution_id = execution_id
        self.provider = provider
        self.model = model
        self.upstream_status = upstream_status
        self.upstream_code = upstream_code
        self.upstream_type = upstream_type
        self.upstream_classification = upstream_classification
        self.provider_request_id = provider_request_id
        self.retry_after = retry_after
        self.rate_limit_scope = rate_limit_scope
        self.operation = operation
        self.elapsed_ms = elapsed_ms


def _unexpected_execution_error(
    *,
    stage: str,
    exc: Exception,
    turn=None,
) -> RealtimeExecutionError:
    return RealtimeExecutionError(
        "REALTIME_EXECUTION_FAILED",
        stage=stage,
        exception_type=type(exc).__name__,
        request_id=getattr(turn, "request_id", None),
        execution_id=getattr(turn, "execution_id", None),
    )


@dataclass(frozen=True, slots=True)
class RealtimeExecutionResult:
    message_id: str
    execution_id: str
    agent_id: str
    agent_name: str
    content: str
    target_mode: str


async def execute_realtime_direct(
    db: Session,
    *,
    settings: Settings,
    tenant_id: str,
    user_id: str,
    thread_id: str,
    agent_id: str,
    transcript: str,
    is_admin: bool = False,
) -> RealtimeExecutionResult:
    try:
        decision = resolve_direct_target_decision(f"id:{agent_id}", settings)
    except Exception as exc:
        raise _unexpected_execution_error(stage="resolve_target", exc=exc) from exc

    try:
        turn = build_direct_turn(
            execution=decision.execution,
            thread_id=thread_id,
            tenant_id=tenant_id,
            user_id=user_id,
            requested_target=agent_id,
            channel=RuntimeChannel.REALTIME,
        )
    except Exception as exc:
        raise _unexpected_execution_error(stage="build_turn", exc=exc) from exc

    try:
        persist_user_message(db, turn=turn, content=transcript)
    except Exception as exc:
        raise _unexpected_execution_error(stage="persist_user", exc=exc, turn=turn) from exc

    try:
        history = team_history(
            db,
            thread_id=thread_id,
            tenant_id=tenant_id,
            settings=settings,
            user_id=user_id,
            execution_id=turn.execution_id,
            agent_id=turn.turn_owner_agent_id,
            purpose="realtime",
        )
        github_messages = (
            await github_context_messages(
                settings,
                message=transcript,
                is_admin=is_admin,
            )
            if getattr(settings, "github_enabled", False)
            else []
        )
        history = list(github_messages) + history
        if settings.internal_agent_consultation_enabled and turn.turn_owner_agent_id == "orkio":
            try:
                contributions, _ = await build_internal_consultation_context(
                    settings,
                    turn=turn,
                    message=transcript,
                )
                history = internal_contribution_messages(contributions) + history
            except Exception:
                # Internal consultation is an optional enhancement. The public
                # Realtime response must remain available if a specialist fails.
                pass
        if turn.turn_owner_agent_id == "orkio":
            profile = profile_for(
                db,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            history.insert(
                0,
                hyper_cocreator_system_message(
                    co_creator_name=profile.co_creator_name if profile else None,
                    onboarding_goal=profile.onboarding_goal if profile else None,
                ),
            )
    except Exception as exc:
        raise _unexpected_execution_error(stage="history", exc=exc, turn=turn) from exc

    try:
        answer = (await llm.generate(settings, turn.turn_owner_agent_id, history)).strip()
    except llm.LLMNotConfigured as exc:
        raise RealtimeExecutionError(
            "LLM_NOT_CONFIGURED",
            stage="llm",
            exception_type=type(exc).__name__,
            request_id=turn.request_id,
            execution_id=turn.execution_id,
        ) from exc
    except llm.LLMUpstreamError as exc:
        diagnostic = exc.diagnostic()
        raise RealtimeExecutionError(
            "LLM_UPSTREAM_ERROR",
            stage="llm",
            exception_type=exc.exception_type or type(exc).__name__,
            request_id=turn.request_id,
            execution_id=turn.execution_id,
            provider=exc.provider,
            model=exc.model,
            upstream_status=exc.upstream_status,
            upstream_code=exc.upstream_code,
            upstream_type=exc.upstream_type,
            upstream_classification=exc.upstream_classification,
            provider_request_id=exc.provider_request_id,
            retry_after=exc.retry_after,
            rate_limit_scope=exc.rate_limit_scope,
            operation=exc.operation,
            elapsed_ms=exc.elapsed_ms,
        ) from exc
    if not answer:
        raise RealtimeExecutionError(
            "LLM_EMPTY_RESPONSE",
            stage="llm",
            request_id=turn.request_id,
            execution_id=turn.execution_id,
        )
    try:
        row, _ = persist_agent_response(db, turn=turn, content=answer)
    except Exception as exc:
        raise _unexpected_execution_error(stage="persist_agent", exc=exc, turn=turn) from exc
    return RealtimeExecutionResult(
        message_id=row.id,
        execution_id=turn.execution_id,
        agent_id=turn.turn_owner_agent_id,
        agent_name=turn.display_agent_name,
        content=row.content,
        target_mode="direct",
    )


async def execute_realtime_team(
    db: Session,
    *,
    settings: Settings,
    tenant_id: str,
    user_id: str,
    thread_id: str,
    team_id: str,
    selection_mode: str,
    contributor_agent_ids: tuple[str, ...],
    transcript: str,
) -> RealtimeExecutionResult:
    plan = build_team_plan(
        team_id=team_id,
        settings=settings,
        selection_mode=selection_mode,
        contributor_agent_ids=contributor_agent_ids,
    )
    try:
        turn = build_team_turn(
            thread_id=thread_id,
            tenant_id=tenant_id,
            user_id=user_id,
            requested_target=f"team:{team_id}",
            orchestrator_agent_id=plan.orchestrator_agent_id,
            channel=RuntimeChannel.REALTIME,
        )
    except Exception as exc:
        raise _unexpected_execution_error(stage="build_turn", exc=exc) from exc

    try:
        persist_user_message(db, turn=turn, content=transcript)
    except Exception as exc:
        raise _unexpected_execution_error(stage="persist_user", exc=exc, turn=turn) from exc

    try:
        base_history = team_history(
            db,
            thread_id=thread_id,
            tenant_id=tenant_id,
            settings=settings,
            user_id=user_id,
            execution_id=turn.execution_id,
            agent_id=turn.turn_owner_agent_id,
            purpose="realtime",
        )
    except Exception as exc:
        raise _unexpected_execution_error(stage="history", exc=exc, turn=turn) from exc

    contributions: list[tuple[str, str]] = []
    for agent_id in plan.contributor_agent_ids:
        try:
            content = (await llm.generate(settings, agent_id, list(base_history))).strip()
        except Exception:
            continue
        if not content:
            continue
        try:
            persist_team_contribution(
                db,
                turn=turn,
                agent_id=agent_id,
                content=content,
            )
        except Exception as exc:
            raise _unexpected_execution_error(
                stage="persist_contribution",
                exc=exc,
                turn=turn,
            ) from exc
        contributions.append((agent_id, content))

    if not contributions:
        raise RealtimeExecutionError("TEAM_ALL_CONTRIBUTORS_FAILED")

    synthesis_history = list(base_history)
    from ..agents.registry import resolve_agent_by_id
    for agent_id, content in contributions:
        agent = resolve_agent_by_id(agent_id)
        synthesis_history.append(
            {
                "role": "assistant",
                "content": (
                    f"[ContextContribution · {agent.display_name} · id:{agent.slug}] "
                    f"{content}"
                ),
            }
        )
    synthesis_history.append(
        {
            "role": "user",
            "content": (
                "Consolide as contribuições do Team em uma resposta única para a solicitação "
                "do usuário. Preserve divergências relevantes, não invente consenso e não "
                "atribua ao chair trabalho executado pelos especialistas."
            ),
        }
    )
    try:
        answer = (
            await llm.generate(settings, plan.orchestrator_agent_id, synthesis_history)
        ).strip()
    except llm.LLMNotConfigured as exc:
        raise RealtimeExecutionError(
            "LLM_NOT_CONFIGURED",
            stage="llm_synthesis",
            exception_type=type(exc).__name__,
            request_id=turn.request_id,
            execution_id=turn.execution_id,
        ) from exc
    except llm.LLMUpstreamError as exc:
        raise RealtimeExecutionError(
            "LLM_UPSTREAM_ERROR",
            stage="llm_synthesis",
            exception_type=exc.exception_type or type(exc).__name__,
            request_id=turn.request_id,
            execution_id=turn.execution_id,
            provider=exc.provider,
            model=exc.model,
            upstream_status=exc.upstream_status,
            upstream_code=exc.upstream_code,
            upstream_type=exc.upstream_type,
            upstream_classification=exc.upstream_classification,
            provider_request_id=exc.provider_request_id,
            retry_after=exc.retry_after,
            rate_limit_scope=exc.rate_limit_scope,
            operation=exc.operation,
            elapsed_ms=exc.elapsed_ms,
        ) from exc
    if not answer:
        raise RealtimeExecutionError(
            "LLM_EMPTY_RESPONSE",
            stage="llm_synthesis",
            request_id=turn.request_id,
            execution_id=turn.execution_id,
        )

    try:
        row, _ = persist_team_final(db, turn=turn, content=answer)
    except Exception as exc:
        raise _unexpected_execution_error(stage="persist_agent", exc=exc, turn=turn) from exc
    return RealtimeExecutionResult(
        message_id=row.id,
        execution_id=turn.execution_id,
        agent_id=turn.turn_owner_agent_id,
        agent_name=turn.display_agent_name,
        content=row.content,
        target_mode="team",
    )


async def stream_realtime_direct(
    db: Session,
    *,
    settings: Settings,
    tenant_id: str,
    user_id: str,
    thread_id: str,
    agent_id: str,
    transcript: str,
    is_admin: bool = False,
) -> AsyncIterator[dict[str, object]]:
    """Stream governed text and speech segments for the direct Co-Creator turn.

    The provider Realtime session remains input/VAD/transcription-only. This
    generator owns the canonical LLM response and emits speech segments before
    the final assistant message is persisted.
    """
    try:
        requested_target = agent_id if agent_id.startswith("id:") else f"id:{agent_id}"
        decision = resolve_direct_target_decision(requested_target, settings)
        turn = build_direct_turn(
            execution=decision.execution,
            thread_id=thread_id,
            tenant_id=tenant_id,
            user_id=user_id,
            requested_target=agent_id,
            channel=RuntimeChannel.REALTIME,
        )
        persist_user_message(db, turn=turn, content=transcript)
        history = team_history(
            db,
            thread_id=thread_id,
            tenant_id=tenant_id,
            settings=settings,
            user_id=user_id,
            execution_id=turn.execution_id,
            agent_id=turn.turn_owner_agent_id,
            purpose="realtime",
        )
        github_messages = (
            await github_context_messages(
                settings,
                message=transcript,
                is_admin=is_admin,
            )
            if getattr(settings, "github_enabled", False)
            else []
        )
        history = list(github_messages) + history
        if settings.internal_agent_consultation_enabled and turn.turn_owner_agent_id == "orkio":
            try:
                contributions, _ = await build_internal_consultation_context(
                    settings,
                    turn=turn,
                    message=transcript,
                )
                history = internal_contribution_messages(contributions) + history
            except Exception:
                # Specialist consultation is optional; the canonical response
                # remains available when an internal contributor is unavailable.
                pass
        if turn.turn_owner_agent_id == "orkio":
            profile = profile_for(db, tenant_id=tenant_id, user_id=user_id)
            history.insert(
                0,
                hyper_cocreator_system_message(
                    co_creator_name=profile.co_creator_name if profile else None,
                    onboarding_goal=profile.onboarding_goal if profile else None,
                ),
            )
    except RealtimeExecutionError:
        raise
    except Exception as exc:
        raise _unexpected_execution_error(stage="prepare_stream", exc=exc) from exc

    segmenter = SentenceSegmenter()
    answer_parts: list[str] = []
    segment_number = 0
    yield {
        "type": "turn_started",
        "turn_id": turn.execution_id,
        "execution_id": turn.execution_id,
        "agent_id": turn.turn_owner_agent_id,
        "agent_name": turn.display_agent_name,
    }

    try:
        async for delta in llm.stream(settings, turn.turn_owner_agent_id, history):
            if not delta:
                continue
            answer_parts.append(delta)
            yield {
                "type": "text_delta",
                "turn_id": turn.execution_id,
                "text": delta,
            }
            for segment in segmenter.push(delta):
                segment_number += 1
                yield {
                    "type": "segment_ready",
                    "turn_id": turn.execution_id,
                    "segment_id": f"seg-{segment_number}",
                    "segment_number": segment_number,
                    "text": segment,
                }

        for segment in segmenter.flush():
            segment_number += 1
            yield {
                "type": "segment_ready",
                "turn_id": turn.execution_id,
                "segment_id": f"seg-{segment_number}",
                "segment_number": segment_number,
                "text": segment,
            }
    except llm.LLMNotConfigured as exc:
        raise RealtimeExecutionError(
            "LLM_NOT_CONFIGURED",
            stage="llm_stream",
            exception_type=type(exc).__name__,
            request_id=turn.request_id,
            execution_id=turn.execution_id,
        ) from exc
    except llm.LLMUpstreamError as exc:
        raise RealtimeExecutionError(
            "LLM_UPSTREAM_ERROR",
            stage="llm_stream",
            exception_type=exc.exception_type or type(exc).__name__,
            request_id=turn.request_id,
            execution_id=turn.execution_id,
            provider=exc.provider,
            model=exc.model,
            upstream_status=exc.upstream_status,
            upstream_code=exc.upstream_code,
            upstream_type=exc.upstream_type,
            upstream_classification=exc.upstream_classification,
            provider_request_id=exc.provider_request_id,
            retry_after=exc.retry_after,
            rate_limit_scope=exc.rate_limit_scope,
            operation=exc.operation,
            elapsed_ms=exc.elapsed_ms,
        ) from exc

    answer = "".join(answer_parts).strip()
    if not answer:
        raise RealtimeExecutionError(
            "LLM_EMPTY_RESPONSE",
            stage="llm_stream",
            request_id=turn.request_id,
            execution_id=turn.execution_id,
        )

    try:
        row, envelope = persist_agent_response(db, turn=turn, content=answer)
    except Exception as exc:
        raise _unexpected_execution_error(stage="persist_agent", exc=exc, turn=turn) from exc

    yield {
        "type": "done",
        "turn_id": turn.execution_id,
        "message_id": row.id,
        "agent_id": turn.turn_owner_agent_id,
        "agent_name": turn.display_agent_name,
        "content": row.content,
        "response": envelope_payload(envelope),
        "segments_count": segment_number,
    }
