
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from .contracts import CanonicalTurnContext, ContextContribution


MAX_DELEGATION_DEPTH = 1


class OrchestrationContractError(ValueError):
    pass


class ConsultReason(StrEnum):
    CAPABILITY_REQUIRED = "capability_required"
    CROSS_DOMAIN_REVIEW = "cross_domain_review"
    RISK_REVIEW = "risk_review"
    FOUNDER_DECISION_INPUT = "founder_decision_input"


@dataclass(frozen=True, slots=True)
class AgentConsultRequest:
    consult_id: str
    execution_id: str
    tenant_id: str
    thread_id: str
    requester_agent_id: str
    turn_owner_agent_id: str
    capability: str
    reason: ConsultReason
    target_agent_id: str | None = None
    delegation_depth: int = 1


@dataclass(frozen=True, slots=True)
class OrchestrationRun:
    turn: CanonicalTurnContext
    team_id: str | None = None
    contributions: tuple[ContextContribution, ...] = ()
    consults: tuple[AgentConsultRequest, ...] = ()


def validate_consult(run: OrchestrationRun, request: AgentConsultRequest) -> None:
    turn = run.turn
    if request.execution_id != turn.execution_id:
        raise OrchestrationContractError("CONSULT_EXECUTION_MISMATCH")
    if request.tenant_id != turn.tenant_id or request.thread_id != turn.thread_id:
        raise OrchestrationContractError("CONSULT_SCOPE_MISMATCH")
    if request.turn_owner_agent_id != turn.turn_owner_agent_id:
        raise OrchestrationContractError("CONSULT_OWNER_MISMATCH")
    if request.delegation_depth < 1 or request.delegation_depth > MAX_DELEGATION_DEPTH:
        raise OrchestrationContractError("DELEGATION_DEPTH_EXCEEDED")


def add_consult(
    run: OrchestrationRun,
    request: AgentConsultRequest,
) -> OrchestrationRun:
    validate_consult(run, request)
    return replace(run, consults=run.consults + (request,))


def add_contribution(
    run: OrchestrationRun,
    contribution: ContextContribution,
) -> OrchestrationRun:
    turn = run.turn
    if contribution.execution_id != turn.execution_id:
        raise OrchestrationContractError("CONTRIBUTION_EXECUTION_MISMATCH")
    if contribution.tenant_id != turn.tenant_id or contribution.thread_id != turn.thread_id:
        raise OrchestrationContractError("CONTRIBUTION_SCOPE_MISMATCH")
    if contribution.target_turn_owner_agent_id != turn.turn_owner_agent_id:
        raise OrchestrationContractError("CONTRIBUTION_OWNER_MISMATCH")
    return replace(run, contributions=run.contributions + (contribution,))
