from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum


class ExecutionStatus(StrEnum):
    CREATED = "created"
    STARTED = "started"
    PERSISTED = "persisted"
    COMPLETED = "completed"
    FAILED = "failed"


_TERMINAL = {ExecutionStatus.COMPLETED, ExecutionStatus.FAILED}
_ALLOWED = {
    ExecutionStatus.CREATED: {ExecutionStatus.STARTED, ExecutionStatus.FAILED},
    ExecutionStatus.STARTED: {ExecutionStatus.PERSISTED, ExecutionStatus.FAILED},
    ExecutionStatus.PERSISTED: {ExecutionStatus.COMPLETED, ExecutionStatus.FAILED},
    ExecutionStatus.COMPLETED: set(),
    ExecutionStatus.FAILED: set(),
}


@dataclass(slots=True)
class ExecutionRecord:
    request_id: str
    execution_id: str
    tenant_id: str
    thread_id: str
    user_id: str
    requested_target: str
    resolved_agent_id: str
    turn_owner_agent_id: str
    display_agent_id: str
    route_family: str
    channel: str
    execution_engine: str
    status: ExecutionStatus = ExecutionStatus.CREATED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    persisted_at: datetime | None = None
    completed_at: datetime | None = None
    failed_at: datetime | None = None
    message_id: str | None = None
    terminal_status: str | None = None
    provider: str | None = None
    model: str | None = None
    token_usage: dict[str, int] | None = None
    latency_ms: int | None = None
    error_code: str | None = None
    _identity_locked: bool = field(default=False, init=False, repr=False)

    _IMMUTABLE_IDENTITY_FIELDS = frozenset({
        "request_id",
        "execution_id",
        "tenant_id",
        "thread_id",
        "user_id",
        "requested_target",
        "resolved_agent_id",
        "turn_owner_agent_id",
        "display_agent_id",
        "route_family",
        "channel",
        "execution_engine",
    })

    def __post_init__(self) -> None:
        object.__setattr__(self, "_identity_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        if (
            name in self._IMMUTABLE_IDENTITY_FIELDS
            and getattr(self, "_identity_locked", False)
            and hasattr(self, name)
        ):
            raise AttributeError("EXECUTION_IDENTITY_IMMUTABLE")
        object.__setattr__(self, name, value)

    def transition(self, next_status: ExecutionStatus, *, at: datetime | None = None) -> None:
        if next_status not in _ALLOWED[self.status]:
            raise ValueError("EXECUTION_INVALID_TRANSITION")
        now = at or datetime.now(timezone.utc)
        self.status = next_status
        if next_status is ExecutionStatus.STARTED:
            self.started_at = now
        elif next_status is ExecutionStatus.PERSISTED:
            self.persisted_at = now
        elif next_status is ExecutionStatus.COMPLETED:
            self.completed_at = now
            self.terminal_status = "completed"
        elif next_status is ExecutionStatus.FAILED:
            self.failed_at = now
            self.terminal_status = "failed"

    @property
    def terminal(self) -> bool:
        return self.status in _TERMINAL
