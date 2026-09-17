from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum

from ..agents.contracts import AgentDefinition
from ..agents.registry import resolve_agent_by_id
from ..config import Settings
from .llm_contracts import ProviderConfigurationState, ProviderHealth, ProviderHealthState
from .model_gateway import ModelGateway


class AvailabilityStatus(StrEnum):
    DISABLED = "DISABLED"
    UNCONFIGURED = "UNCONFIGURED"
    CONFIGURED = "CONFIGURED"
    READY = "READY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class CapabilityAvailability:
    status: AvailabilityStatus
    eligible: bool
    reason_code: str
    source: str


@dataclass(frozen=True, slots=True)
class AgentAvailability:
    agent_id: str
    registered: bool
    enabled: bool
    chat: CapabilityAvailability
    team: CapabilityAvailability
    realtime: CapabilityAvailability
    voice_playback: CapabilityAvailability
    voice_message: CapabilityAvailability
    tools: CapabilityAvailability

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        for key in ("chat", "team", "realtime", "voice_playback", "voice_message", "tools"):
            payload[key]["status"] = getattr(self, key).status.value
        return payload


class AgentCapabilityUnavailable(RuntimeError):
    def __init__(self, agent_id: str, capability: str, reason_code: str):
        super().__init__("AGENT_CAPABILITY_UNAVAILABLE")
        self.agent_id = agent_id
        self.capability = capability
        self.reason_code = reason_code


def _disabled(reason: str = "AGENT_DISABLED") -> CapabilityAvailability:
    return CapabilityAvailability(
        AvailabilityStatus.DISABLED,
        False,
        reason,
        "agent_registry",
    )


def _unconfigured(reason: str, source: str) -> CapabilityAvailability:
    return CapabilityAvailability(
        AvailabilityStatus.UNCONFIGURED,
        False,
        reason,
        source,
    )


def _chat(agent: AgentDefinition, settings: Settings) -> CapabilityAvailability:
    if not agent.enabled:
        return _disabled()
    descriptor = ModelGateway(settings).provider().descriptor()
    if descriptor.state is not ProviderConfigurationState.configured:
        return _unconfigured(
            "LLM_PRIMARY_PROVIDER_UNCONFIGURED",
            "model_gateway",
        )
    # Configuration proves only that a model/key/base contract is present.
    # It is intentionally not promoted to READY without a runtime healthcheck.
    return CapabilityAvailability(
        AvailabilityStatus.CONFIGURED,
        True,
        "LLM_PRIMARY_PROVIDER_CONFIGURED_NOT_HEALTHCHECKED",
        "model_gateway",
    )


def availability_for(agent: AgentDefinition, settings: Settings) -> AgentAvailability:
    if not agent.enabled:
        disabled = _disabled()
        return AgentAvailability(
            agent_id=agent.slug,
            registered=True,
            enabled=False,
            chat=disabled,
            team=disabled,
            realtime=disabled,
            voice_playback=disabled,
            voice_message=disabled,
            tools=disabled,
        )

    chat = _chat(agent, settings)
    if chat.eligible:
        team = CapabilityAvailability(
            AvailabilityStatus.CONFIGURED,
            True,
            "TEAM_ENGINE_BOUND_PROVIDER_NOT_HEALTHCHECKED",
            "team_runtime",
        )
    else:
        team = _unconfigured(
            "TEAM_ENGINE_PROVIDER_UNAVAILABLE",
            "team_runtime",
        )
    realtime = _unconfigured("REALTIME_AGENT_SESSION_NOT_BOUND", "runtime")

    # Global voice enablement/provider configuration is insufficient to prove a
    # per-agent canonical binding. Until binding validation exists, fail closed.
    if settings.voice_enabled and settings.voice_provider != "disabled":
        voice_reason = "AGENT_VOICE_BINDING_NOT_VALIDATED"
    else:
        voice_reason = "VOICE_RUNTIME_UNCONFIGURED"
    voice = _unconfigured(voice_reason, "voice_binding")

    tools = _unconfigured("AGENT_TOOL_POLICY_NOT_BOUND", "tool_gateway")

    return AgentAvailability(
        agent_id=agent.slug,
        registered=True,
        enabled=True,
        chat=chat,
        team=team,
        realtime=realtime,
        voice_playback=voice,
        voice_message=voice,
        tools=tools,
    )


def availability_for_id(agent_id: str, settings: Settings) -> AgentAvailability:
    return availability_for(resolve_agent_by_id(agent_id), settings)


def require_chat_eligible(agent_id: str, settings: Settings) -> AgentAvailability:
    snapshot = availability_for_id(agent_id, settings)
    if not snapshot.chat.eligible:
        raise AgentCapabilityUnavailable(
            agent_id,
            "chat",
            snapshot.chat.reason_code,
        )
    return snapshot


@dataclass(frozen=True, slots=True)
class AgentReadinessProbe:
    agent_id: str
    chat: CapabilityAvailability
    checked_at: str
    provider: str | None
    model: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "agent_id": self.agent_id,
            "chat": {
                "status": self.chat.status.value,
                "eligible": self.chat.eligible,
                "reason_code": self.chat.reason_code,
                "source": self.chat.source,
            },
            "checked_at": self.checked_at,
            "provider": self.provider,
            "model": self.model,
        }


def _chat_from_health(agent: AgentDefinition, health: ProviderHealth) -> CapabilityAvailability:
    if not agent.enabled:
        return _disabled()
    if health.state is ProviderHealthState.ready:
        return CapabilityAvailability(
            AvailabilityStatus.READY,
            True,
            "LLM_PRIMARY_PROVIDER_HEALTHY",
            "model_gateway.healthcheck",
        )
    if health.state is ProviderHealthState.unconfigured:
        return _unconfigured(
            health.code or "LLM_PRIMARY_PROVIDER_UNCONFIGURED",
            "model_gateway.healthcheck",
        )
    return CapabilityAvailability(
        AvailabilityStatus.UNAVAILABLE,
        False,
        health.code or "LLM_PROVIDER_UNAVAILABLE",
        "model_gateway.healthcheck",
    )


async def readiness_probe_for_id(agent_id: str, settings: Settings) -> AgentReadinessProbe:
    """Probe CHAT readiness for one technical agent id.

    The probe is intentionally explicit and runtime-scoped. It does not mutate
    catalog state, does not cache READY forever, and does not infer Team/Voice
    readiness from LLM health.
    """
    agent = resolve_agent_by_id(agent_id)
    gateway = ModelGateway(settings)
    health = await gateway.healthcheck()
    checked_at = datetime.now(timezone.utc).isoformat()
    return AgentReadinessProbe(
        agent_id=agent.slug,
        chat=_chat_from_health(agent, health),
        checked_at=checked_at,
        provider=health.provider.value,
        model=health.model or None,
    )
