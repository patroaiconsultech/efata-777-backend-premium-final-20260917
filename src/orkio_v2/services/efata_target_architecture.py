from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum


TARGET_ARCHITECTURE_ID = "EFATA_DUAL_INTELLIGENCE_V1"
TARGET_ARCHITECTURE_VERSION = "1.0.0"


class IntelligencePlane(StrEnum):
    MISSION = "MISSION"
    EVOLUTION = "EVOLUTION"
    SHARED = "SHARED"


@dataclass(frozen=True, slots=True)
class TargetRequirement:
    requirement_id: str
    plane: IntelligencePlane
    title: str
    definition_of_done: str
    priority: str

    def as_dict(self) -> dict[str, str]:
        value = asdict(self)
        value["plane"] = self.plane.value
        return value


TARGET_REQUIREMENTS: tuple[TargetRequirement, ...] = (
    TargetRequirement(
        "authorization_plane",
        IntelligencePlane.SHARED,
        "Canonical participant/context authorization",
        "REST, Direct, Team and Realtime enforce the same tenant/thread/user history and document authorization before model context.",
        "P0",
    ),
    TargetRequirement(
        "canonical_turn_context",
        IntelligencePlane.SHARED,
        "Canonical turn context",
        "One immutable server-owned turn context carries tenant, user, ownership, route, governance and execution identity.",
        "P0",
    ),
    TargetRequirement(
        "canonical_response_envelope",
        IntelligencePlane.SHARED,
        "Canonical response envelope",
        "Persistence, SSE, reconcile and frontend consume one canonical identity and terminal status contract.",
        "P0",
    ),
    TargetRequirement(
        "platform_self_model",
        IntelligencePlane.EVOLUTION,
        "Versioned platform self-model",
        "EFATA can report current baseline, structural source inventory, proven capabilities, known gaps and target architecture with evidence classes.",
        "P0",
    ),
    TargetRequirement(
        "architecture_indexer",
        IntelligencePlane.EVOLUTION,
        "Bounded architecture indexer",
        "Read-only deterministic indexing maps modules, hashes, symbols and route structure without exposing arbitrary source content.",
        "P0",
    ),
    TargetRequirement(
        "internal_auditor",
        IntelligencePlane.EVOLUTION,
        "Independent internal auditor",
        "An internal read-only auditor can inspect evidence, classify findings and produce governed proposals without silently writing code.",
        "P1",
    ),
    TargetRequirement(
        "capability_registry",
        IntelligencePlane.SHARED,
        "Central capability registry",
        "Agent capabilities are explicit, versioned, permissioned, risk-classified and runtime-bound.",
        "P1",
    ),
    TargetRequirement(
        "knowledge_plane",
        IntelligencePlane.SHARED,
        "Governed knowledge plane",
        "Knowledge is versioned, traceable, source-bound, permissioned and purpose-aware.",
        "P1",
    ),
    TargetRequirement(
        "standard_team_runtime",
        IntelligencePlane.MISSION,
        "Standard Team runtime",
        "Two to eight eligible contributors execute under one immutable chair/owner contract with bounded failure and consistent persistence.",
        "P1",
    ),
    TargetRequirement(
        "mission_model",
        IntelligencePlane.SHARED,
        "Persistent Mission model",
        "Long-running work has tenant-scoped lifecycle, chair, budget, approvals and governance policy.",
        "P1",
    ),
    TargetRequirement(
        "structured_contribution_model",
        IntelligencePlane.SHARED,
        "Persistent structured contributions",
        "Agent work is stored with source agent, task, domain, evidence, assumptions, risks, tokens, cost, latency and status.",
        "P1",
    ),
    TargetRequirement(
        "persistent_execution_graph",
        IntelligencePlane.SHARED,
        "Persistent execution graph",
        "Nodes, edges/events, status, replay, agent metrics, token usage, latency and correlation are durable and queryable.",
        "P1",
    ),
    TargetRequirement(
        "agent_studio_runtime",
        IntelligencePlane.SHARED,
        "Tenant-aware Agent Studio runtime",
        "Approved and active custom agents become executable only through canonical tenant-aware registry activation.",
        "P1",
    ),
    TargetRequirement(
        "usage_cost_ledger",
        IntelligencePlane.SHARED,
        "Real model usage/cost ledger",
        "Provider usage is recorded per execution/mission/agent with confirmed versus estimated cost provenance.",
        "P1",
    ),
    TargetRequirement(
        "hyper_team",
        IntelligencePlane.MISSION,
        "Hyper Team",
        "All eligible agents can be orchestrated with bounded parallelism, decomposition, cross-review, hierarchical synthesis and budgets.",
        "P2",
    ),
    TargetRequirement(
        "governed_autoevolution",
        IntelligencePlane.EVOLUTION,
        "Governed autoevolution",
        "Audit → proposal → diff → risk → rollback → smoke → human approval → controlled write/PR gates are machine-enforced.",
        "P2",
    ),
    TargetRequirement(
        "legacy_identity_elimination",
        IntelligencePlane.SHARED,
        "EFATA-only active product identity",
        "No active executable/distributable user-facing product identity relies on legacy platform naming; historical references remain explicitly historical.",
        "P2",
    ),
)


def target_architecture_payload() -> dict[str, object]:
    return {
        "architecture_id": TARGET_ARCHITECTURE_ID,
        "version": TARGET_ARCHITECTURE_VERSION,
        "product": "EFATA",
        "pattern": "DUAL_INTELLIGENCE",
        "planes": {
            IntelligencePlane.MISSION.value: {
                "purpose": "Understand and execute human/business missions through governed multi-agent orchestration."
            },
            IntelligencePlane.EVOLUTION.value: {
                "purpose": "Understand, audit and improve EFATA itself through governed internal intelligence."
            },
            IntelligencePlane.SHARED.value: {
                "purpose": "Identity, authorization, canonical contracts, knowledge, evidence, observability and governance shared by both planes."
            },
        },
        "requirements": [item.as_dict() for item in TARGET_REQUIREMENTS],
    }
