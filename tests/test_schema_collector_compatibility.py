from tools.efata_schema_collector.compatibility import (
    derive_overall_decision,
    evaluate_schema,
)
from tools.efata_schema_collector.contracts import (
    CaptureCompletenessReport,
    CompletenessStatus,
    DatabaseSecurityCompatibilityProfile,
    Decision,
    SchemaCompatibilityProfile,
    SecurityManifest,
    StructuralManifest,
)
from tools.efata_schema_collector.canonical import sha256_canonical


def complete_report():
    return CaptureCompletenessReport(
        completeness_proof_mode="LOCAL_FIXTURE_GROUND_TRUTH_V1",
        required_catalog_surfaces=(),
        observed_catalog_surfaces=(),
        status=CompletenessStatus.COMPLETE,
    )


def structural(extra=False):
    relations = [{"schema_name": "public", "object_name": "items", "relkind": "r"}]
    if extra:
        relations.append({"schema_name": "public", "object_name": "mystery", "relkind": "r"})
    return StructuralManifest(
        included_namespaces=("public",),
        namespaces=({"schema_name": "public"},),
        relations=tuple(relations),
    )


def profile(**updates):
    data = {
        "profile_id": "p",
        "profile_version": "1",
        "required_namespaces": ("public",),
        "required_objects": ("table:public.items",),
    }
    data.update(updates)
    return SchemaCompatibilityProfile(**data)


def test_unknown_application_object_is_deny_by_default():
    result = evaluate_schema(structural(extra=True), profile(), complete_report())
    assert result.decision == Decision.INCOMPATIBLE
    assert "SCHEMA.EXTRA_APPLICATION_OBJECT_FORBIDDEN" in result.reason_codes


def test_explicit_allowed_extra_pattern_can_remain_compatible():
    result = evaluate_schema(
        structural(extra=True),
        profile(allowed_extra_patterns=("table:public.mystery",)),
        complete_report(),
    )
    assert result.decision in {Decision.EXACT, Decision.COMPATIBLE}


def test_signature_is_bound_to_profile():
    a = evaluate_schema(structural(), profile(profile_version="1"), complete_report())
    b = evaluate_schema(structural(), profile(profile_version="2"), complete_report())
    assert a.compatibility_signature_sha256 != b.compatibility_signature_sha256


def test_incomplete_capture_forces_overall_inconclusive():
    incomplete = CaptureCompletenessReport(
        completeness_proof_mode="LOCAL_FIXTURE_GROUND_TRUTH_V1",
        required_catalog_surfaces=("x",),
        observed_catalog_surfaces=(),
        failed_catalog_surfaces=("x",),
        status=CompletenessStatus.INCOMPLETE,
        reason_codes=("CAPTURE.REQUIRED_OBJECT_CLASS_NOT_OBSERVABLE",),
    )
    decision = derive_overall_decision(
        structural(),
        SecurityManifest(),
        profile(),
        DatabaseSecurityCompatibilityProfile(profile_id="s", profile_version="1"),
        incomplete,
        session_profile_sha256="0" * 64,
    )
    assert decision.overall_decision == Decision.INCONCLUSIVE
