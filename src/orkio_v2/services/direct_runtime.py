from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from ..agents.contracts import ExecutionContext
from ..models import Message
from ..runtime.contracts import CanonicalTurnContext, ResponseEnvelope, RuntimeChannel
from ..runtime.identity import (
    build_direct_turn_context,
    build_response_envelope,
    canonical_message,
)


def build_turn(
    *,
    execution: ExecutionContext,
    thread_id: str,
    tenant_id: str,
    user_id: str,
    requested_target: str,
    channel: RuntimeChannel,
) -> CanonicalTurnContext:
    """Build the canonical identity envelope for one direct-agent turn."""
    return build_direct_turn_context(
        execution=execution,
        thread_id=thread_id,
        tenant_id=tenant_id,
        user_id=user_id,
        requested_target=requested_target,
        channel=channel,
    )


def persist_agent_response(
    db: Session,
    *,
    turn: CanonicalTurnContext,
    content: str,
) -> tuple[Message, ResponseEnvelope]:
    """Persist once using the canonical turn owner, then verify the envelope.

    The existing Message.author_id column is the canonical agent identity for
    agent-authored messages. This avoids a schema migration in R0.4B while
    making ownership explicit at the API/runtime boundary.
    """
    row = Message(
        tenant_id=turn.tenant_id,
        thread_id=turn.thread_id,
        author_type="agent",
        author_id=turn.turn_owner_agent_id,
        agent_name=turn.display_agent_name,
        content=content,
    )
    db.add(row)
    db.commit()

    message = canonical_message(
        message_id=row.id,
        context=turn,
        content=row.content,
        created_at=row.created_at,
    )
    envelope = build_response_envelope(context=turn, message=message)
    return row, envelope


def history_item(message: Message) -> dict[str, str]:
    """Return LLM history while preserving the canonical agent speaker."""
    if message.author_type != "agent":
        return {"role": "user", "content": message.content}

    speaker = (message.agent_name or message.author_id or "Agent").strip()
    return {
        "role": "assistant",
        "content": f"[Agent: {speaker}] {message.content}",
    }


def envelope_payload(envelope: ResponseEnvelope) -> dict[str, Any]:
    """JSON-safe representation of the canonical response envelope."""
    payload = asdict(envelope)
    payload["route_family"] = envelope.route_family.value
    if isinstance(payload.get("created_at"), datetime):
        payload["created_at"] = payload["created_at"].isoformat()
    return payload
