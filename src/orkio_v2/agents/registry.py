from __future__ import annotations

from .catalog import AGENTS
from .contracts import AgentDefinition


class AgentNotFound(ValueError):
    def __init__(self, agent_id: str):
        super().__init__("AGENT_NOT_FOUND")
        self.agent_id = agent_id


def _technical_key(value: str) -> str:
    return value.strip().casefold()


_BY_ID = {_technical_key(agent.slug): agent for agent in AGENTS if agent.enabled}


def resolve_agent_by_id(agent_id: str) -> AgentDefinition:
    """Resolve only the technical agent_id namespace.

    This function is intentionally not a natural-language resolver. Public
    natural-language selection must go through TargetResolver.
    """
    key = _technical_key(agent_id or "")
    agent = _BY_ID.get(key)
    if agent is None:
        raise AgentNotFound(agent_id)
    return agent


def resolve_agent(requested: str) -> AgentDefinition:
    """Compatibility wrapper for callers that need natural-language resolution.

    Kept lazy to avoid an import cycle. New runtime code should import the
    TargetResolver directly.
    """
    from ..services.target_resolver import resolve_target_agent
    return resolve_target_agent(requested)


def list_agents() -> tuple[AgentDefinition, ...]:
    return tuple(agent for agent in AGENTS if agent.enabled)
