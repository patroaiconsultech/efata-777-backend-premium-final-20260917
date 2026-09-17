from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sqlalchemy.orm import Session

from ..models import AuditEvent


class RealtimeBridgeError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class RealtimeReceipt:
    turn_key: str
    state: str
    message_id: str | None = None
    execution_id: str | None = None
    agent_id: str | None = None


def realtime_turn_key(
    *,
    tenant_id: str,
    thread_id: str,
    session_id: str,
    provider_item_id: str,
    transcript_final_id: str,
) -> str:
    values = [tenant_id, thread_id, session_id, provider_item_id, transcript_final_id]
    if any(not str(value or "").strip() for value in values):
        raise RealtimeBridgeError("REALTIME_IDEMPOTENCY_KEY_INCOMPLETE")
    canonical = "\n".join(str(value).strip() for value in values)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def receipt_id(turn_key: str) -> str:
    return f"rt-{turn_key[:61]}"


def load_receipt(db: Session, *, tenant_id: str, turn_key: str) -> RealtimeReceipt | None:
    row = db.get(AuditEvent, receipt_id(turn_key))
    if row is None or row.tenant_id != tenant_id or row.action != "realtime_turn_receipt":
        return None
    data = dict(row.metadata_json or {})
    return RealtimeReceipt(
        turn_key=turn_key,
        state=str(data.get("state") or row.outcome),
        message_id=str(data["message_id"]) if data.get("message_id") else None,
        execution_id=str(data["execution_id"]) if data.get("execution_id") else None,
        agent_id=str(data["agent_id"]) if data.get("agent_id") else None,
    )


def reserve_receipt(
    db: Session,
    *,
    tenant_id: str,
    actor_id: str,
    thread_id: str,
    turn_key: str,
    session_id: str,
) -> RealtimeReceipt:
    existing = load_receipt(db, tenant_id=tenant_id, turn_key=turn_key)
    if existing is not None:
        return existing
    row = AuditEvent(
        id=receipt_id(turn_key),
        tenant_id=tenant_id,
        actor_id=actor_id,
        action="realtime_turn_receipt",
        resource_type="realtime_turn",
        resource_id=thread_id,
        outcome="processing",
        metadata_json={
            "state": "processing",
            "session_id": session_id,
            "thread_id": thread_id,
        },
    )
    db.add(row)
    try:
        db.commit()
    except Exception:
        db.rollback()
        existing = load_receipt(db, tenant_id=tenant_id, turn_key=turn_key)
        if existing is not None:
            return existing
        raise
    return RealtimeReceipt(turn_key=turn_key, state="processing")


def complete_receipt(
    db: Session,
    *,
    tenant_id: str,
    turn_key: str,
    message_id: str,
    execution_id: str,
    agent_id: str,
) -> RealtimeReceipt:
    row = db.get(AuditEvent, receipt_id(turn_key))
    if row is None or row.tenant_id != tenant_id:
        raise RealtimeBridgeError("REALTIME_RECEIPT_NOT_FOUND")
    row.outcome = "success"
    data = dict(row.metadata_json or {})
    data.update(
        {
            "state": "completed",
            "message_id": message_id,
            "execution_id": execution_id,
            "agent_id": agent_id,
        }
    )
    row.metadata_json = data
    db.commit()
    return RealtimeReceipt(
        turn_key=turn_key,
        state="completed",
        message_id=message_id,
        execution_id=execution_id,
        agent_id=agent_id,
    )


def fail_receipt(
    db: Session,
    *,
    tenant_id: str,
    turn_key: str,
    error_code: str,
) -> None:
    row = db.get(AuditEvent, receipt_id(turn_key))
    if row is None or row.tenant_id != tenant_id:
        return
    row.outcome = "failed"
    data = dict(row.metadata_json or {})
    data.update({"state": "failed", "error_code": error_code})
    row.metadata_json = data
    db.commit()
