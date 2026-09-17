
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class RuntimeChannel(StrEnum):
    CHAT_JSON = "chat_json"
    CHAT_SSE = "chat_sse"
    REALTIME = "realtime"


class RuntimeRouteFamily(StrEnum):
    DIRECT_AGENT = "direct_agent"
    TEAM = "team"


@dataclass(frozen=True, slots=True)
class CanonicalTurnContext:
    execution_id: str
    request_id: str
    thread_id: str
    tenant_id: str
    user_id: str
    requested_target: str
    resolved_agent_id: str
    turn_owner_agent_id: str
    display_agent_id: str
    display_agent_name: str
    technical_lead_agent_id: str | None
    route_family: RuntimeRouteFamily
    channel: RuntimeChannel
    ownership_locked: bool
    governance_mode: str
    internal_persistence_allowed: bool
    external_write_allowed: bool
    execution_allowed: bool
    orchestrator_agent_id: str | None = None


@dataclass(frozen=True, slots=True)
class ContextContribution:
    contribution_id: str
    execution_id: str
    thread_id: str
    tenant_id: str
    source_agent_id: str
    requested_by_agent_id: str
    target_turn_owner_agent_id: str
    purpose: str
    content: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class CanonicalMessage:
    message_id: str
    execution_id: str
    thread_id: str
    tenant_id: str
    agent_id: str
    agent_name: str
    content: str
    content_sha256: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class ResponseEnvelope:
    message_id: str
    execution_id: str
    thread_id: str
    tenant_id: str
    agent_id: str
    agent_name: str
    display_name: str
    final_speaker_agent_id: str
    turn_owner_agent_id: str
    route_family: RuntimeRouteFamily
    content: str
    status: str
    error: str | None
    token_usage: dict[str, int] | None
    latency_ms: int | None
    created_at: datetime
