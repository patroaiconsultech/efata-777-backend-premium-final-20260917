from __future__ import annotations

import json
from pathlib import Path

import pytest

from orkio_v2.services.architecture_indexer import (
    ArchitectureIndexError,
    build_architecture_index,
)
from orkio_v2.services.efata_platform_self_model import (
    BaselineIdentity,
    EvidenceStatus,
    build_platform_self_model,
)
from orkio_v2.services.efata_target_architecture import (
    TARGET_ARCHITECTURE_ID,
    target_architecture_payload,
)


BACKEND_SHA = "3b85c16bea13f178b20ccb39b15af53b86ad7b8398ba50b6913b13403e936f0b"
FRONTEND_SHA = "3b40be7e8c96f2b36784a5090f6e10add97fc117c7383e778ce8aeb050b017ab"


def _baseline() -> BaselineIdentity:
    return BaselineIdentity(
        baseline_id="EFATA-777-BL-20260917-MAIN-6-9",
        backend_artifact="efata-777-backend-premium-final-20260917-main (9).zip",
        backend_sha256=BACKEND_SHA,
        frontend_artifact="efata-777-frontend-premium-final-20260917-main (6).zip",
        frontend_sha256=FRONTEND_SHA,
    )


def test_architecture_index_is_deterministic_and_content_bounded(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text(
        "from fastapi import APIRouter\n"
        "router=APIRouter()\n"
        "@router.get('/x')\n"
        "def x(): return 'TOP_SECRET_VALUE'\n",
        encoding="utf-8",
    )
    first = build_architecture_index(tmp_path)
    second = build_architecture_index(tmp_path)

    assert first.tree_sha256 == second.tree_sha256
    assert first.file_count == 1
    payload = json.dumps(first.as_dict(), sort_keys=True)
    assert "TOP_SECRET_VALUE" not in payload
    assert first.files[0].python is not None
    assert "router.get:x" in first.files[0].python.route_decorators


def test_architecture_index_fails_closed_on_invalid_limits(tmp_path: Path):
    with pytest.raises(ArchitectureIndexError, match="ARCHITECTURE_LIMIT_INVALID"):
        build_architecture_index(tmp_path, max_files=0)


def test_target_architecture_is_dual_intelligence_and_efata_only():
    target = target_architecture_payload()
    assert target["architecture_id"] == TARGET_ARCHITECTURE_ID
    assert target["product"] == "EFATA"
    assert target["pattern"] == "DUAL_INTELLIGENCE"
    assert set(target["planes"]) == {"MISSION", "EVOLUTION", "SHARED"}
    requirement_ids = {item["requirement_id"] for item in target["requirements"]}
    assert {
        "platform_self_model",
        "architecture_indexer",
        "internal_auditor",
        "standard_team_runtime",
        "mission_model",
        "persistent_execution_graph",
        "hyper_team",
        "governed_autoevolution",
    }.issubset(requirement_ids)


def test_self_model_reports_current_target_gaps_without_runtime_overclaim():
    root = Path(__file__).resolve().parents[1]
    model = build_platform_self_model(root, baseline=_baseline())
    payload = model.as_dict()
    current = {item.requirement_id: item for item in model.current_state}

    assert model.product == "EFATA"
    assert model.canonical_sha256() == build_platform_self_model(
        root, baseline=_baseline()
    ).canonical_sha256()

    assert current["canonical_turn_context"].status is EvidenceStatus.PROVEN_PRESENT_IN_SOURCE
    assert current["canonical_response_envelope"].status is EvidenceStatus.PROVEN_PRESENT_IN_SOURCE
    assert current["architecture_indexer"].status is EvidenceStatus.PROVEN_PRESENT_IN_SOURCE
    assert current["platform_self_model"].status is EvidenceStatus.PROVEN_PRESENT_IN_SOURCE
    assert current["internal_auditor"].status is EvidenceStatus.PROVEN_PRESENT_IN_SOURCE
    assert current["standard_team_runtime"].status is EvidenceStatus.PROVEN_PRESENT_IN_SOURCE

    # This exact physical baseline has not materialized the already-ratified
    # Authorization Plane P0 proposal yet.
    assert current["authorization_plane"].status is EvidenceStatus.PROVEN_ABSENT_IN_SOURCE

    assert current["mission_model"].status is EvidenceStatus.PROVEN_ABSENT_IN_SOURCE
    assert current["persistent_execution_graph"].status is EvidenceStatus.PROVEN_ABSENT_IN_SOURCE
    assert current["agent_studio_runtime"].status is EvidenceStatus.KNOWN_GAP_MARKER
    assert current["usage_cost_ledger"].status is EvidenceStatus.KNOWN_GAP_MARKER
    assert current["legacy_identity_elimination"].status is EvidenceStatus.KNOWN_GAP_MARKER

    assert payload["evidence_boundary"]["deployed_runtime"] == "NOT_PROVEN"
    assert payload["evidence_boundary"]["production_behavior"] == "NOT_PROVEN"
    assert "mission_model" in model.gap_requirement_ids
    assert "persistent_execution_graph" in model.gap_requirement_ids


def test_baseline_hashes_must_be_exact_sha256():
    invalid = BaselineIdentity(
        baseline_id="x",
        backend_artifact="b.zip",
        backend_sha256="bad",
        frontend_artifact="f.zip",
        frontend_sha256=FRONTEND_SHA,
    )
    with pytest.raises(ValueError, match="EFATA_BACKEND_SHA256_INVALID"):
        build_platform_self_model(Path(__file__).resolve().parents[1], baseline=invalid)
