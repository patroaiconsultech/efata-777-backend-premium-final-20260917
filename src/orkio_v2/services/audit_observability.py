from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
import uuid
from typing import Mapping

from ..runtime.contracts import CanonicalTurnContext
from ..runtime.execution_record import ExecutionRecord, ExecutionStatus


class AuditEventType:
    EXECUTION_CREATED = "execution_created"
    EXECUTION_STARTED = "execution_started"
    PERSISTENCE_SUCCEEDED = "persistence_succeeded"
    EXECUTION_COMPLETED = "execution_completed"
    EXECUTION_FAILED = "execution_failed"
    INTERNAL_CONSULTATION = "internal_consultation"


_SENSITIVE_KEY = re.compile(
    r"(authorization|cookie|token|secret|password|api[_-]?key|credential|prompt|document|content|body)",
    re.IGNORECASE,
)


def sanitize_metadata(
    metadata: Mapping[str, object] | None,
    *,
    max_items: int = 32,
    max_string: int = 256,
) -> dict[str, object]:
    clean: dict[str, object] = {}
    if not metadata:
        return clean
    for index, (raw_key, value) in enumerate(metadata.items()):
        if index >= max_items:
            break
        key = str(raw_key)[:96]
        if _SENSITIVE_KEY.search(key):
            continue
        if value is None or isinstance(value, (bool, int, float)):
            clean[key] = value
        elif isinstance(value, str):
            clean[key] = value[:max_string]
        else:
            clean[key] = f"<{type(value).__name__}>"
    return clean


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_id: str
    schema_version: int
    sequence: int
    occurred_at: datetime
    event_type: str
    request_id: str
    execution_id: str
    tenant_id: str
    thread_id: str
    user_id: str
    turn_owner_agent_id: str
    execution_engine: str
    metadata: Mapping[str, object]


@dataclass(slots=True)
class ExecutionObserver:
    record: ExecutionRecord
    events: list[AuditEvent] = field(default_factory=list)
    _sequence: int = 0

    @classmethod
    def from_turn(cls, turn: CanonicalTurnContext, *, execution_engine: str) -> "ExecutionObserver":
        record = ExecutionRecord(
            request_id=turn.request_id,
            execution_id=turn.execution_id,
            tenant_id=turn.tenant_id,
            thread_id=turn.thread_id,
            user_id=turn.user_id,
            requested_target=turn.requested_target,
            resolved_agent_id=turn.resolved_agent_id,
            turn_owner_agent_id=turn.turn_owner_agent_id,
            display_agent_id=turn.display_agent_id,
            route_family=turn.route_family.value,
            channel=turn.channel.value,
            execution_engine=execution_engine,
        )
        observer = cls(record)
        observer._emit(AuditEventType.EXECUTION_CREATED)
        return observer

    def _emit(self, event_type: str, metadata: Mapping[str, object] | None = None) -> AuditEvent:
        self._sequence += 1
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            schema_version=1,
            sequence=self._sequence,
            occurred_at=datetime.now(timezone.utc),
            event_type=event_type,
            request_id=self.record.request_id,
            execution_id=self.record.execution_id,
            tenant_id=self.record.tenant_id,
            thread_id=self.record.thread_id,
            user_id=self.record.user_id,
            turn_owner_agent_id=self.record.turn_owner_agent_id,
            execution_engine=self.record.execution_engine,
            metadata=sanitize_metadata(metadata),
        )
        self.events.append(event)
        return event

    def start(self) -> None:
        self.record.transition(ExecutionStatus.STARTED)
        self._emit(AuditEventType.EXECUTION_STARTED)

    def persisted(self, *, message_id: str) -> None:
        self.record.message_id = message_id
        self.record.transition(ExecutionStatus.PERSISTED)
        self._emit(AuditEventType.PERSISTENCE_SUCCEEDED, {"message_id": message_id})

    def complete(
        self,
        *,
        provider: str | None = None,
        model: str | None = None,
        token_usage: dict[str, int] | None = None,
        latency_ms: int | None = None,
    ) -> None:
        self.record.provider = provider
        self.record.model = model
        self.record.token_usage = token_usage
        self.record.latency_ms = latency_ms
        self.record.transition(ExecutionStatus.COMPLETED)
        self._emit(
            AuditEventType.EXECUTION_COMPLETED,
            {"provider": provider, "model": model, "latency_ms": latency_ms},
        )

    def consulted(self, *, count: int, domains: list[str]) -> None:
        self._emit(
            AuditEventType.INTERNAL_CONSULTATION,
            {"count": count, "domains": domains[:8]},
        )

    def fail(self, error_code: str) -> None:
        if self.record.terminal:
            raise ValueError("EXECUTION_ALREADY_TERMINAL")
        self.record.error_code = error_code
        self.record.transition(ExecutionStatus.FAILED)
        self._emit(AuditEventType.EXECUTION_FAILED, {"error_code": error_code})
