from __future__ import annotations

from dataclasses import dataclass

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

    _validate_history_policy(participant)
    if require_write and participant.thread_role == ThreadRole.viewer.value:
        raise ThreadAccessPolicyError("THREAD_READ_ONLY", 403)

    return ThreadAccessDecision(thread=thread, participant=participant)


def _apply_history_scope(
    stmt: Select,
    *,
    participant: ThreadParticipant,
) -> Select:
    policy = _validate_history_policy(participant)
    if policy == "from_join":
        stmt = stmt.where(Message.created_at >= participant.joined_at)
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

    stmt = select(Message).where(
        Message.id == message_id,
        Message.thread_id == thread_id,
        Message.tenant_id == tenant_id,
    )
    stmt = _apply_history_scope(stmt, participant=participant)
    return db.scalar(stmt)
