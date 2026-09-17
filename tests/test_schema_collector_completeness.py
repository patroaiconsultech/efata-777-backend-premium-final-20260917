import pytest
from tools.efata_schema_collector.completeness import (
    GroundTruthContractError,
    build_completeness_report,
)
from tools.efata_schema_collector.contracts import (
    CompletenessStatus,
    SecurityManifest,
    StructuralManifest,
)


def manifests():
    structural = StructuralManifest(
        included_namespaces=("public",),
        namespaces=({"schema_name": "public"},),
        relations=({"schema_name": "public", "object_name": "items", "relkind": "r"},),
        columns=({"schema_name": "public", "relation_name": "items", "column_name": "id"},),
    )
    security = SecurityManifest(
        roles=({"rolname": "collector", "rolcanlogin": True, "rolsuper": False,
                "rolinherit": False, "rolcreaterole": False, "rolcreatedb": False,
                "rolreplication": False, "rolbypassrls": False},),
    )
    return structural, security


def test_ground_truth_missing_object_is_incomplete():
    structural, security = manifests()
    gt = {
        "required_catalog_surfaces": ("catalog.namespaces",),
        "required_objects": ("namespace:public", "table:public.missing"),
        "required_security_facts": (),
    }
    report = build_completeness_report(
        structural, security, gt, observed_surfaces=("catalog.namespaces",)
    )
    assert report.status == CompletenessStatus.INCOMPLETE
    assert "CAPTURE.GROUND_TRUTH_OBJECT_MISSING" in report.reason_codes


def test_complete_requires_all_declared_surfaces_and_objects():
    structural, security = manifests()
    gt = {
        "required_catalog_surfaces": ("catalog.namespaces",),
        "required_objects": ("namespace:public", "table:public.items"),
        "required_security_facts": ("role:collector",),
    }
    report = build_completeness_report(
        structural, security, gt, observed_surfaces=("catalog.namespaces",)
    )
    assert report.status == CompletenessStatus.COMPLETE


def test_missing_catalog_surface_is_incomplete_even_when_objects_reconcile():
    structural, security = manifests()
    gt = {
        "required_catalog_surfaces": ("catalog.namespaces", "catalog.relations"),
        "required_objects": ("namespace:public", "table:public.items"),
        "required_security_facts": (),
    }
    report = build_completeness_report(
        structural, security, gt, observed_surfaces=("catalog.namespaces",)
    )
    assert report.status == CompletenessStatus.INCOMPLETE
    assert "catalog.relations" in report.failed_catalog_surfaces


import json
from pathlib import Path

import pytest

from tests.support.efata_schema_fixture_oracle import (
    OracleContractError,
    load_qualification_oracle,
)


ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "schema_collector" / "fixture_v1.sql"
ORACLE = ROOT / "tests" / "fixtures" / "schema_collector" / "fixture_ground_truth_v1.json"


def test_approved_independent_oracle_qualifies():
    data = json.loads(ORACLE.read_text())
    assert data["authorship_mode"] == "INDEPENDENT_STATIC_CONTRACT"
    assert data["review_status"] == "APPROVED"
    loaded = load_qualification_oracle(ORACLE, FIXTURE)
    assert loaded["ground_truth_sha256"] == data["ground_truth_sha256"]


def test_no_ground_truth_generator_exists_in_qualification_path():
    support = ROOT / "tests" / "support"
    tools = ROOT / "tools" / "efata_schema_collector"
    text = "\n".join(p.read_text() for p in [*support.glob("*.py"), *tools.glob("*.py")])
    assert "def generate_ground_truth" not in text

def test_unapproved_ground_truth_cannot_qualify():
    from tools.efata_schema_collector.completeness import (
        GroundTruthContractError,
        validate_ground_truth_contract,
    )
    oracle = json.loads(ORACLE.read_text())
    oracle["review_status"] = "PENDING_AO01_INDEPENDENT_REVIEW"
    with pytest.raises(GroundTruthContractError, match="NOT_APPROVED"):
        validate_ground_truth_contract(oracle)

def test_declared_object_cardinality_too_few_is_incomplete():
    structural, security = manifests()
    gt = {
        "required_catalog_surfaces": ("catalog.namespaces",),
        "required_objects": ("namespace:public", "table:public.items"),
        "required_security_facts": (),
        "required_object_count_by_class": {"table": 2},
    }
    report = build_completeness_report(
        structural, security, gt, observed_surfaces=("catalog.namespaces",)
    )
    assert report.status == CompletenessStatus.INCOMPLETE
    assert "CAPTURE.GROUND_TRUTH_OBJECT_CARDINALITY_MISMATCH" in report.reason_codes


def test_declared_object_cardinality_too_many_is_incomplete():
    structural, security = manifests()
    structural = structural.model_copy(update={
        "relations": (
            {"schema_name": "public", "object_name": "items", "relkind": "r"},
            {"schema_name": "public", "object_name": "extra", "relkind": "r"},
        )
    })
    gt = {
        "required_catalog_surfaces": ("catalog.namespaces",),
        "required_objects": ("namespace:public", "table:public.items"),
        "required_security_facts": (),
        "required_object_count_by_class": {"table": 1},
    }
    report = build_completeness_report(
        structural, security, gt, observed_surfaces=("catalog.namespaces",)
    )
    assert report.status == CompletenessStatus.INCOMPLETE
    assert "CAPTURE.GROUND_TRUTH_OBJECT_CARDINALITY_MISMATCH" in report.reason_codes


def test_declared_security_cardinality_too_few_is_incomplete():
    structural, security = manifests()
    gt = {
        "required_catalog_surfaces": ("catalog.namespaces",),
        "required_objects": ("namespace:public", "table:public.items"),
        "required_security_facts": ("role:collector",),
        "required_security_fact_count_by_class": {"role": 2},
    }
    report = build_completeness_report(
        structural, security, gt, observed_surfaces=("catalog.namespaces",)
    )
    assert report.status == CompletenessStatus.INCOMPLETE
    assert "CAPTURE.GROUND_TRUTH_SECURITY_CARDINALITY_MISMATCH" in report.reason_codes


def test_declared_security_cardinality_too_many_is_incomplete():
    structural, security = manifests()
    security = security.model_copy(update={
        "roles": (
            security.roles[0],
            {
                "rolname": "unexpected",
                "rolcanlogin": False,
                "rolsuper": False,
                "rolinherit": False,
                "rolcreaterole": False,
                "rolcreatedb": False,
                "rolreplication": False,
                "rolbypassrls": False,
            },
        )
    })
    gt = {
        "required_catalog_surfaces": ("catalog.namespaces",),
        "required_objects": ("namespace:public", "table:public.items"),
        "required_security_facts": ("role:collector",),
        "required_security_fact_count_by_class": {"role": 1},
    }
    report = build_completeness_report(
        structural, security, gt, observed_surfaces=("catalog.namespaces",)
    )
    assert report.status == CompletenessStatus.INCOMPLETE
    assert "CAPTURE.GROUND_TRUTH_SECURITY_CARDINALITY_MISMATCH" in report.reason_codes


def test_declared_cardinalities_exact_match_can_be_complete():
    structural, security = manifests()
    gt = {
        "required_catalog_surfaces": ("catalog.namespaces",),
        "required_objects": ("namespace:public", "table:public.items"),
        "required_security_facts": ("role:collector",),
        "required_object_count_by_class": {"namespace": 1, "table": 1},
        "required_security_fact_count_by_class": {"role": 1},
    }
    report = build_completeness_report(
        structural, security, gt, observed_surfaces=("catalog.namespaces",)
    )
    assert report.status == CompletenessStatus.COMPLETE


def test_invalid_cardinality_contract_fails_closed():
    structural, security = manifests()
    gt = {
        "required_catalog_surfaces": ("catalog.namespaces",),
        "required_objects": ("namespace:public", "table:public.items"),
        "required_security_facts": (),
        "required_object_count_by_class": {"table": -1},
    }
    with pytest.raises(GroundTruthContractError, match="GROUND_TRUTH_CARDINALITY_INVALID"):
        build_completeness_report(
            structural, security, gt, observed_surfaces=("catalog.namespaces",)
        )

