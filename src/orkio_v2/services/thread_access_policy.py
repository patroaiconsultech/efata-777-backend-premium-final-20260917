from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from ..models import Message, Thread, ThreadParticipant, ThreadRole


_ALLOWED_HISTORY_POLICIES = frozenset({"from_join", "full_thread"})


class ThreadAccessPolicyError(RuntimeError):
    def __init__(self, code: str, status_code: int):
        super().__init__(code)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class ThreadAccessDecision:
    thread: Thread
    participant: ThreadParticipant


def _validate_history_policy(participant: ThreadParticipant) -> str:
    policy = str(participant.history_access or "").strip()
    if policy not in _ALLOWED_HISTORY_POLICIES:
        raise ThreadAccessPolicyError("THREAD_HISTORY_POLICY_INVALID", 403)
    if policy == "from_join" and participant.joined_at is None:
        raise ThreadAccessPolicyError("THREAD_HISTORY_POLICY_INVALID", 403)
    return policy


def can_read_messages(participant: ThreadParticipant) -> bool:
    # Legacy rows must retain existing read behavior after an additive migration.
    return participant.can_read_messages is not False


def can_write_messages(participant: ThreadParticipant) -> bool:
    return (
        participant.thread_role != ThreadRole.viewer.value
        and participant.can_write_messages is not False
    )


def require_message_read(participant: ThreadParticipant) -> None:
    if not can_read_messages(participant):
        raise ThreadAccessPolicyError("THREAD_MESSAGE_READ_DENIED", 403)


def require_message_write(participant: ThreadParticipant) -> None:
    if not can_write_messages(participant):
        raise ThreadAccessPolicyError("THREAD_READ_ONLY", 403)


def require_thread_access(
    db: Session,
    *,
    thread_id: str,
    tenant_id: str,
    user_id: str,
    require_write: bool = False,
) -> ThreadAccessDecision:
    """Resolve the canonical tenant/thread participant grant.

    Tenant membership authenticates/provisions the principal elsewhere; it does
    not grant thread access. Every thread surface must converge here so REST,
    Team, Realtime and Voice fail closed on the same participant state.
    """

    thread = db.get(Thread, thread_id)
    if thread is None or thread.tenant_id != tenant_id:
        raise ThreadAccessPolicyError("THREAD_NOT_FOUND", 404)

    participant = db.scalar(
        select(ThreadParticipant).where(
            ThreadParticipant.thread_id == thread_id,
            ThreadParticipant.tenant_id == tenant_id,
            ThreadParticipant.user_id == user_id,
            ThreadParticipant.active.is_(True),
        )
    )
    if participant is None:
        raise ThreadAccessPolicyError("THREAD_ACCESS_DENIED", 403)
    # Canonical boundary shared by REST, SSE, Team, Realtime and direct
    # message retrieval. Never rely on the UI or scheduled cleanup.
    if participant.access_expires_at is not None:
        cutoff = participant.access_expires_at
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=timezone.utc)
        if cutoff <= datetime.now(timezone.utc):
            raise ThreadAccessPolicyError("THREAD_ACCESS_EXPIRED", 403)

    _validate_history_policy(participant)
    if require_write:
        require_message_write(participant)

    return ThreadAccessDecision(thread=thread, participant=participant)


def history_visible_since(participant: ThreadParticipant):
    """Canonical lower bound for resources governed by thread history grants."""
    policy = _validate_history_policy(participant)
    return participant.joined_at if policy == "from_join" else None


def _apply_history_scope(
    stmt: Select,
    *,
    participant: ThreadParticipant,
) -> Select:
    since = history_visible_since(participant)
    if since is not None:
        stmt = stmt.where(Message.created_at >= since)
    return stmt


def visible_messages(
    db: Session,
    *,
    thread_id: str,
    tenant_id: str,
    participant: ThreadParticipant,
    limit: int | None = None,
    newest_first: bool = False,
) -> list[Message]:
    """Load only messages visible under the participant's canonical history grant."""

    if not can_read_messages(participant):
        return []
    stmt = select(Message).where(
        Message.thread_id == thread_id,
        Message.tenant_id == tenant_id,
    )
    stmt = _apply_history_scope(stmt, participant=participant)
    stmt = stmt.order_by(
        Message.created_at.desc() if newest_first else Message.created_at.asc(),
        Message.id.desc() if newest_first else Message.id.asc(),
    )
    if limit is not None:
        stmt = stmt.limit(limit)
    return list(db.scalars(stmt).all())


def visible_message_by_id(
    db: Session,
    *,
    message_id: str,
    thread_id: str,
    tenant_id: str,
    participant: ThreadParticipant,
) -> Message | None:
    """Return one message only when the participant may see it.

    Returning None for pre-join messages intentionally avoids disclosing that an
    inaccessible message exists.
    """

    if not can_read_messages(participant):
        return None
    stmt = select(Message).where(
        Message.id == message_id,
        Message.thread_id == thread_id,
        Message.tenant_id == tenant_id,
    )
    stmt = _apply_history_scope(stmt, participant=participant)
    return db.scalar(stmt)
