from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping


@dataclass(frozen=True, slots=True)
class ExecutionCorrelation:
    request_id: str
    execution_id: str
    tenant_id: str
    thread_id: str
    owner_agent_id: str
    execution_engine: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def event_data(self, **extra: object) -> Mapping[str, object]:
        return {
            "request_id": self.request_id,
            "execution_id": self.execution_id,
            "thread_id": self.thread_id,
            "owner_agent_id": self.owner_agent_id,
            "execution_engine": self.execution_engine,
            **extra,
        }
