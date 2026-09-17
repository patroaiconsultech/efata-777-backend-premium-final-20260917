from __future__ import annotations

from dataclasses import dataclass

from ..agents.contracts import ExecutionContext, ExecutionEngine
from ..config import Settings
from .agent_availability import AgentAvailability, availability_for_id
from .target_resolver import resolve_target


@dataclass(frozen=True, slots=True)
class DirectTargetDecision:
    execution: ExecutionContext
    availability: AgentAvailability


def resolve_direct_execution(requested_target: str) -> ExecutionContext:
    """Resolve human/role/localized/technical target to one locked direct owner."""
    resolution = resolve_target(requested_target)
    agent = resolution.agent
    return ExecutionContext(
        room_context="direct",
        requested_target=requested_target,
        resolved_target=agent.slug,
        turn_owner=agent.slug,
        display_agent=agent.display_name,
        execution_engine=ExecutionEngine.DIRECT_AGENT,
        orchestrator=None,
        ownership_locked=True,
    )


def resolve_direct_target_decision(
    requested_target: str,
    settings: Settings,
) -> DirectTargetDecision:
    """Resolve identity first, then compute capability availability.

    Availability is intentionally separate from identity and does not silently
    rewrite the selected agent. This snapshot is configuration-scoped; READY
    requires the explicit provider health probe.
    """
    execution = resolve_direct_execution(requested_target)
    availability = availability_for_id(execution.resolved_target, settings)
    return DirectTargetDecision(execution=execution, availability=availability)
