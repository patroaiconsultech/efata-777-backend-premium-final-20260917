
from __future__ import annotations

from dataclasses import dataclass

from .contracts import CanonicalTurnContext, RuntimeChannel


class RealtimeIdentityError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RealtimeIdentity:
    execution_id: str
    tenant_id: str
    thread_id: str
    resolved_agent_id: str
    turn_owner_agent_id: str
    display_agent_id: str
    speaker_agent_id: str
    ownership_locked: bool


def realtime_identity_from_turn(context: CanonicalTurnContext) -> RealtimeIdentity:
    if context.channel is not RuntimeChannel.REALTIME:
        raise RealtimeIdentityError("REALTIME_CHANNEL_REQUIRED")
    identity = RealtimeIdentity(
        execution_id=context.execution_id,
        tenant_id=context.tenant_id,
        thread_id=context.thread_id,
        resolved_agent_id=context.resolved_agent_id,
        turn_owner_agent_id=context.turn_owner_agent_id,
        display_agent_id=context.display_agent_id,
        speaker_agent_id=context.turn_owner_agent_id,
        ownership_locked=context.ownership_locked,
    )
    validate_realtime_identity(identity)
    return identity


def validate_realtime_identity(identity: RealtimeIdentity) -> None:
    if not identity.ownership_locked:
        raise RealtimeIdentityError("REALTIME_OWNERSHIP_MUST_BE_LOCKED")
    canonical = {
        identity.resolved_agent_id,
        identity.turn_owner_agent_id,
        identity.display_agent_id,
        identity.speaker_agent_id,
    }
    if len(canonical) != 1:
        raise RealtimeIdentityError("REALTIME_SPEAKER_IDENTITY_MISMATCH")
