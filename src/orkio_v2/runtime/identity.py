
from __future__ import annotations

import hashlib
import uuid
from dataclasses import replace
from datetime import datetime, timezone

from ..agents.contracts import ExecutionContext
from .contracts import (
    CanonicalMessage,
    CanonicalTurnContext,
    ResponseEnvelope,
    RuntimeChannel,
    RuntimeRouteFamily,
)


class OwnershipViolation(ValueError):
    pass


def _id(value: str | None = None) -> str:
    return value or str(uuid.uuid4())


def build_direct_turn_context(
    *,
    execution: ExecutionContext,
    thread_id: str,
    tenant_id: str,
    user_id: str,
    requested_target: str,
    channel: RuntimeChannel,
    request_id: str | None = None,
    execution_id: str | None = None,
    governance_mode: str = "normal",
    internal_persistence_allowed: bool = True,
    external_write_allowed: bool = False,
    execution_allowed: bool = True,
) -> CanonicalTurnContext:
    if not execution.ownership_locked:
        raise OwnershipViolation("DIRECT_EXECUTION_MUST_LOCK_OWNERSHIP")
    if execution.resolved_target != execution.turn_owner:
        raise OwnershipViolation("DIRECT_RESOLVED_OWNER_MISMATCH")
    return CanonicalTurnContext(
        execution_id=_id(execution_id),
        request_id=_id(request_id),
        thread_id=thread_id,
        tenant_id=tenant_id,
        user_id=user_id,
        requested_target=requested_target,
        resolved_agent_id=execution.resolved_target,
        turn_owner_agent_id=execution.turn_owner,
        display_agent_id=execution.turn_owner,
        display_agent_name=execution.display_agent,
        technical_lead_agent_id=None,
        route_family=RuntimeRouteFamily.DIRECT_AGENT,
        channel=channel,
        ownership_locked=True,
        governance_mode=governance_mode,
        internal_persistence_allowed=internal_persistence_allowed,
        external_write_allowed=external_write_allowed,
        execution_allowed=execution_allowed,
        orchestrator_agent_id=execution.orchestrator,
    )


def require_same_owner(
    context: CanonicalTurnContext,
    candidate_owner_agent_id: str,
) -> CanonicalTurnContext:
    if context.ownership_locked and candidate_owner_agent_id != context.turn_owner_agent_id:
        raise OwnershipViolation("TURN_OWNER_IMMUTABLE")
    return replace(context, turn_owner_agent_id=candidate_owner_agent_id)


def canonical_message(
    *,
    message_id: str,
    context: CanonicalTurnContext,
    content: str,
    created_at: datetime | None = None,
) -> CanonicalMessage:
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return CanonicalMessage(
        message_id=message_id,
        execution_id=context.execution_id,
        thread_id=context.thread_id,
        tenant_id=context.tenant_id,
        agent_id=context.turn_owner_agent_id,
        agent_name=context.display_agent_name,
        content=content,
        content_sha256=digest,
        created_at=created_at or datetime.now(timezone.utc),
    )


def build_response_envelope(
    *,
    context: CanonicalTurnContext,
    message: CanonicalMessage,
    status: str = "completed",
    error: str | None = None,
    token_usage: dict[str, int] | None = None,
    latency_ms: int | None = None,
) -> ResponseEnvelope:
    if message.execution_id != context.execution_id:
        raise OwnershipViolation("MESSAGE_EXECUTION_MISMATCH")
    if message.thread_id != context.thread_id or message.tenant_id != context.tenant_id:
        raise OwnershipViolation("MESSAGE_SCOPE_MISMATCH")
    if message.agent_id != context.turn_owner_agent_id:
        raise OwnershipViolation("MESSAGE_OWNER_MISMATCH")
    return ResponseEnvelope(
        message_id=message.message_id,
        execution_id=context.execution_id,
        thread_id=context.thread_id,
        tenant_id=context.tenant_id,
        agent_id=context.turn_owner_agent_id,
        agent_name=context.display_agent_name,
        display_name=context.display_agent_name,
        final_speaker_agent_id=context.turn_owner_agent_id,
        turn_owner_agent_id=context.turn_owner_agent_id,
        route_family=context.route_family,
        content=message.content,
        status=status,
        error=error,
        token_usage=token_usage,
        latency_ms=latency_ms,
        created_at=message.created_at,
    )
