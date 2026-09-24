from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
import hashlib
import json
from pathlib import Path
import re

from .architecture_indexer import (
    ArchitectureIndex,
    build_architecture_index,
    contains_marker,
    find_symbol,
)
from .efata_target_architecture import TARGET_REQUIREMENTS, target_architecture_payload


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class EvidenceStatus(StrEnum):
    PROVEN_PRESENT_IN_SOURCE = "PROVEN_PRESENT_IN_SOURCE"
    PROVEN_ABSENT_IN_SOURCE = "PROVEN_ABSENT_IN_SOURCE"
    KNOWN_GAP_MARKER = "KNOWN_GAP_MARKER"
    NOT_PROVEN = "NOT_PROVEN"


@dataclass(frozen=True, slots=True)
class BaselineIdentity:
    baseline_id: str
    backend_artifact: str
    backend_sha256: str
    frontend_artifact: str
    frontend_sha256: str
    branch: str = "NOT_PROVEN"
    commit: str = "NOT_PROVEN"
    deployed_commit: str = "NOT_PROVEN"
    runtime_equivalence: str = "NOT_PROVEN"

    def validate(self) -> None:
        if not self.baseline_id.strip():
            raise ValueError("EFATA_BASELINE_ID_REQUIRED")
        for field_name, value in (
            ("backend_sha256", self.backend_sha256),
            ("frontend_sha256", self.frontend_sha256),
        ):
            if not _SHA256.fullmatch((value or "").strip().lower()):
                raise ValueError(f"EFATA_{field_name.upper()}_INVALID")


@dataclass(frozen=True, slots=True)
class ComponentEvidence:
    requirement_id: str
    status: EvidenceStatus
    evidence: tuple[str, ...]
    note: str

    def as_dict(self) -> dict[str, object]:
        return {
            "requirement_id": self.requirement_id,
            "status": self.status.value,
            "evidence": list(self.evidence),
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class PlatformSelfModel:
    schema_version: str
    product: str
    baseline: BaselineIdentity
    architecture: ArchitectureIndex
    current_state: tuple[ComponentEvidence, ...]
    target_state: dict[str, object]
    gap_requirement_ids: tuple[str, ...]
    evidence_boundary: dict[str, str]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "product": self.product,
            "baseline": asdict(self.baseline),
            "architecture": self.architecture.as_dict(),
            "current_state": [item.as_dict() for item in self.current_state],
            "target_state": self.target_state,
            "gap_requirement_ids": list(self.gap_requirement_ids),
            "evidence_boundary": dict(self.evidence_boundary),
        }

    def canonical_sha256(self) -> str:
        encoded = json.dumps(
            self.as_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def _file_present(index: ArchitectureIndex, path: str) -> bool:
    return any(item.path == path for item in index.files)


def _discover_backend_package(index: ArchitectureIndex) -> str:
    candidates: list[str] = []
    for item in index.files:
        if not item.path.startswith("src/") or not item.path.endswith("/runtime/contracts.py"):
            continue
        if item.python is None or "CanonicalTurnContext" not in item.python.classes:
            continue
        candidates.append(item.path.removesuffix("/runtime/contracts.py"))
    if len(candidates) != 1:
        raise ValueError("EFATA_BACKEND_PACKAGE_DISCOVERY_AMBIGUOUS")
    return candidates[0]


def _present(requirement_id: str, *evidence: str, note: str) -> ComponentEvidence:
    return ComponentEvidence(
        requirement_id,
        EvidenceStatus.PROVEN_PRESENT_IN_SOURCE,
        tuple(evidence),
        note,
    )


def _absent(requirement_id: str, *evidence: str, note: str) -> ComponentEvidence:
    return ComponentEvidence(
        requirement_id,
        EvidenceStatus.PROVEN_ABSENT_IN_SOURCE,
        tuple(evidence),
        note,
    )


def _known_gap(requirement_id: str, *evidence: str, note: str) -> ComponentEvidence:
    return ComponentEvidence(
        requirement_id,
        EvidenceStatus.KNOWN_GAP_MARKER,
        tuple(evidence),
        note,
    )


def _not_proven(requirement_id: str, *evidence: str, note: str) -> ComponentEvidence:
    return ComponentEvidence(
        requirement_id,
        EvidenceStatus.NOT_PROVEN,
        tuple(evidence),
        note,
    )


def _source_state(repository_root: Path, index: ArchitectureIndex) -> tuple[ComponentEvidence, ...]:
    result: list[ComponentEvidence] = []
    package = _discover_backend_package(index)

    runtime_contracts = f"{package}/runtime/contracts.py"
    models_path = f"{package}/models.py"
    services = f"{package}/services"
    agent_studio = f"{package}/agent_studio_routes.py"
    routes_path = f"{package}/routes.py"

    if find_symbol(index, path=runtime_contracts, symbol="CanonicalTurnContext"):
        result.append(_present(
            "canonical_turn_context",
            f"{runtime_contracts}::CanonicalTurnContext",
            note="Canonical turn context is defined in source; runtime parity is a separate proof.",
        ))
    else:
        result.append(_absent(
            "canonical_turn_context",
            runtime_contracts,
            note="CanonicalTurnContext class was not found in indexed source.",
        ))

    if find_symbol(index, path=runtime_contracts, symbol="ResponseEnvelope"):
        result.append(_present(
            "canonical_response_envelope",
            f"{runtime_contracts}::ResponseEnvelope",
            note="ResponseEnvelope is defined in source; complete consumer parity is not inferred.",
        ))
    else:
        result.append(_absent(
            "canonical_response_envelope",
            runtime_contracts,
            note="ResponseEnvelope class was not found in indexed source.",
        ))

    authorization_path = f"{services}/thread_context_authorization.py"
    if _file_present(index, authorization_path):
        result.append(_present(
            "authorization_plane",
            authorization_path,
            note="Canonical authorization module is present in this source snapshot.",
        ))
    else:
        result.append(_absent(
            "authorization_plane",
            authorization_path,
            note="Current source snapshot does not contain the ratified Authorization Plane module.",
        ))

    architecture_indexer_path = f"{services}/architecture_indexer.py"
    if _file_present(index, architecture_indexer_path):
        result.append(_present(
            "architecture_indexer",
            architecture_indexer_path,
            note="Bounded read-only architecture indexer is present.",
        ))
    else:
        result.append(_absent(
            "architecture_indexer",
            architecture_indexer_path,
            note="Architecture indexer module not found.",
        ))

    self_model_path = f"{services}/efata_platform_self_model.py"
    if _file_present(index, self_model_path):
        result.append(_present(
            "platform_self_model",
            self_model_path,
            note="Versioned current/target/gap self-model service is present.",
        ))
    else:
        result.append(_absent(
            "platform_self_model",
            self_model_path,
            note="Platform self-model service not found.",
        ))

    capability_path = f"{services}/capability_registry.py"
    capability_present = find_symbol(
        index,
        path=capability_path,
        symbol="CapabilityRegistry",
    )
    result.append(
        _present(
            "capability_registry",
            f"{capability_path}::CapabilityRegistry",
            note="Read-only/audit capability registry foundation is present; full product capability coverage is not inferred.",
        )
        if capability_present else
        _absent(
            "capability_registry",
            capability_path,
            note="CapabilityRegistry class not found.",
        )
    )

    knowledge_repository = f"{services}/knowledge_repository.py"
    knowledge_present = (
        _file_present(index, knowledge_repository)
        and _file_present(index, "migrations/versions/005_knowledge_plane_v1.py")
    )
    result.append(
        _present(
            "knowledge_plane",
            knowledge_repository,
            "migrations/versions/005_knowledge_plane_v1.py",
            note="Governed Knowledge Plane foundation is present in source/schema.",
        )
        if knowledge_present else
        _not_proven(
            "knowledge_plane",
            "knowledge_repository + migration 005",
            note="Knowledge Plane foundation was not fully proven by source probes.",
        )
    )

    team_path = f"{services}/team_runtime.py"
    team_present = _file_present(index, team_path)
    result.append(
        _present(
            "standard_team_runtime",
            team_path,
            note="Standard Team source runtime exists; production readiness is not inferred.",
        )
        if team_present else
        _absent(
            "standard_team_runtime",
            team_path,
            note="Team runtime module not found.",
        )
    )

    audit_invocation = f"{services}/audit_invocation_service.py"
    auditor_present = (
        _file_present(index, audit_invocation)
        and find_symbol(index, path=models_path, symbol="AuditEvidenceRecord")
    )
    result.append(
        _present(
            "internal_auditor",
            audit_invocation,
            f"{models_path}::AuditEvidenceRecord",
            note="Governed read-only audit foundation and durable evidence ledger exist; broad self-audit orchestration remains a later integration.",
        )
        if auditor_present else
        _not_proven(
            "internal_auditor",
            "audit invocation + evidence ledger",
            note="Internal auditor foundation not fully proven by source probes.",
        )
    )

    mission_present = find_symbol(index, path=models_path, symbol="Mission")
    result.append(
        _present(
            "mission_model",
            f"{models_path}::Mission",
            note="Persistent Mission model found.",
        )
        if mission_present else
        _absent(
            "mission_model",
            f"{models_path}::Mission",
            note="No persistent Mission model found in current model source.",
        )
    )

    contribution_present = any(
        find_symbol(index, path=models_path, symbol=symbol)
        for symbol in ("Contribution", "MissionContribution", "AgentContribution")
    )
    result.append(
        _present(
            "structured_contribution_model",
            f"{models_path}::Contribution",
            note="Persistent contribution model found.",
        )
        if contribution_present else
        _absent(
            "structured_contribution_model",
            models_path,
            note="ContextContribution exists in runtime contracts, but no persistent structured contribution model was found.",
        )
    )

    graph_symbols = ("ExecutionGraph", "ExecutionNode", "ExecutionEvent")
    graph_present = all(
        find_symbol(index, path=models_path, symbol=symbol)
        for symbol in graph_symbols
    )
    result.append(
        _present(
            "persistent_execution_graph",
            *(f"{models_path}::{symbol}" for symbol in graph_symbols),
            note="Persistent execution graph models found.",
        )
        if graph_present else
        _absent(
            "persistent_execution_graph",
            f"{models_path}::{{ExecutionGraph,ExecutionNode,ExecutionEvent}}",
            note="Required persistent execution graph model set was not found.",
        )
    )

    studio_gap = contains_marker(
        repository_root,
        path=agent_studio,
        marker="AGENT_STUDIO_TENANT_AWARE_RUNTIME_NOT_IMPLEMENTED",
    )
    result.append(
        _known_gap(
            "agent_studio_runtime",
            f"{agent_studio}::AGENT_STUDIO_TENANT_AWARE_RUNTIME_NOT_IMPLEMENTED",
            note="Source explicitly marks tenant-aware Agent Studio runtime activation as not implemented.",
        )
        if studio_gap else
        _not_proven(
            "agent_studio_runtime",
            agent_studio,
            note="No explicit not-implemented marker found; runtime executability still requires runtime evidence.",
        )
    )

    ledger_gap = contains_marker(
        repository_root,
        path=routes_path,
        marker="LLM_TOKEN_LEDGER_NOT_IMPLEMENTED",
    )
    result.append(
        _known_gap(
            "usage_cost_ledger",
            f"{routes_path}::LLM_TOKEN_LEDGER_NOT_IMPLEMENTED",
            note="Source explicitly marks the real LLM token ledger as not implemented.",
        )
        if ledger_gap else
        _not_proven(
            "usage_cost_ledger",
            routes_path,
            note="Usage/cost ledger readiness requires explicit schema/runtime evidence.",
        )
    )

    internal_consultation_path = f"{services}/internal_consultation.py"
    internal_consultation = _file_present(index, internal_consultation_path)
    hyper_persistent = graph_present and mission_present and contribution_present
    result.append(
        _present(
            "hyper_team",
            "persistent mission/contribution/execution graph source evidence",
            note="Hyper Team persistence prerequisites found in source.",
        )
        if hyper_persistent else
        _not_proven(
            "hyper_team",
            internal_consultation_path if internal_consultation else "internal consultation not found",
            note="Internal bounded consultation exists, but persistent Mission/Contribution/ExecutionGraph prerequisites are not all present.",
        )
    )

    result.append(_not_proven(
        "governed_autoevolution",
        "governance contract requires runtime enforcement",
        note="Source contains governance/audit foundations, but controlled write/PR automation is not proven by this read-only source snapshot.",
    ))

    source_packages = {
        item.path.split("/", 2)[1]
        for item in index.files
        if item.path.startswith("src/") and item.path.count("/") >= 2
    }
    efata_named_packages = {name for name in source_packages if name.casefold().startswith("efata")}
    legacy_active = bool(source_packages - efata_named_packages)
    result.append(
        _known_gap(
            "legacy_identity_elimination",
            "active source package namespace inventory",
            note="At least one active backend source package is not EFATA-named; final EFATA-only distributable identity remains incomplete.",
        )
        if legacy_active else
        _not_proven(
            "legacy_identity_elimination",
            "active distribution identity",
            note="No non-EFATA source package namespace detected; distributable/runtime scan still required.",
        )
    )

    return tuple(sorted(result, key=lambda item: item.requirement_id))


def build_platform_self_model(
    repository_root: str | Path,
    *,
    baseline: BaselineIdentity,
) -> PlatformSelfModel:
    """Return EFATA's deterministic read-only current→target source self-model.

    This function deliberately does not claim deployed/runtime equivalence.
    Runtime, database and production evidence must be attached by later,
    separately governed collectors.
    """
    baseline.validate()
    root = Path(repository_root).resolve()
    index = build_architecture_index(root)
    current = _source_state(root, index)
    current_by_id = {item.requirement_id: item for item in current}
    target = target_architecture_payload()

    gaps: list[str] = []
    for requirement in TARGET_REQUIREMENTS:
        evidence = current_by_id.get(requirement.requirement_id)
        if evidence is None or evidence.status is not EvidenceStatus.PROVEN_PRESENT_IN_SOURCE:
            gaps.append(requirement.requirement_id)

    return PlatformSelfModel(
        schema_version="EFATA_PLATFORM_SELF_MODEL_V1",
        product="EFATA",
        baseline=baseline,
        architecture=index,
        current_state=current,
        target_state=target,
        gap_requirement_ids=tuple(sorted(gaps)),
        evidence_boundary={
            "source_snapshot": "PROVEN_LOCAL_SOURCE",
            "database_state": "NOT_PROVEN",
            "deployed_runtime": "NOT_PROVEN",
            "production_behavior": "NOT_PROVEN",
            "external_provider_state": "NOT_PROVEN",
        },
    )
