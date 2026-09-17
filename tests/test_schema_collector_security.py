from pathlib import Path

import pytest

from tools.efata_schema_collector.compatibility import evaluate_security
from tools.efata_schema_collector.contracts import (
    CaptureCompletenessReport,
    CompletenessStatus,
    DatabaseSecurityCompatibilityProfile,
    Decision,
    PrincipalRule,
    SecurityManifest,
)


def complete_report():
    return CaptureCompletenessReport(
        completeness_proof_mode="LOCAL_FIXTURE_GROUND_TRUTH_V1",
        required_catalog_surfaces=(),
        observed_catalog_surfaces=(),
        status=CompletenessStatus.COMPLETE,
    )


def base_role(name="runtime", **updates):
    row = {
        "rolname": name,
        "rolcanlogin": True,
        "rolsuper": False,
        "rolinherit": True,
        "rolcreaterole": False,
        "rolcreatedb": False,
        "rolreplication": False,
        "rolbypassrls": False,
    }
    row.update(updates)
    return row


def profile(**updates):
    data = {
        "profile_id": "security-p",
        "profile_version": "1",
        "principal_rules": (
            PrincipalRule(
                principal_class="APPLICATION_RUNTIME",
                physical_role_names=("runtime",),
                min_count=1,
                max_count=1,
            ),
        ),
        "forbidden_role_attributes": ("rolsuper", "rolbypassrls"),
    }
    data.update(updates)
    return DatabaseSecurityCompatibilityProfile(**data)


def test_bypassrls_role_is_incompatible():
    manifest = SecurityManifest(roles=(base_role(rolbypassrls=True),))
    result = evaluate_security(manifest, profile(), complete_report())
    assert result.decision == Decision.INCOMPATIBLE
    assert any("ROLBYPASSRLS" in code for code in result.reason_codes)


def test_public_forbidden_grant_is_incompatible():
    manifest = SecurityManifest(
        roles=(base_role(),),
        database_acl=({
            "grantee": "PUBLIC",
            "privilege_type": "TEMPORARY",
            "is_grantable": False,
        },),
    )
    result = evaluate_security(
        manifest,
        profile(forbidden_public_privileges=("TEMPORARY",)),
        complete_report(),
    )
    assert result.decision == Decision.INCOMPATIBLE
    assert "SECURITY.PUBLIC_GRANT_FORBIDDEN" in result.reason_codes


def test_principal_cardinality_is_enforced():
    manifest = SecurityManifest(roles=())
    result = evaluate_security(manifest, profile(), complete_report())
    assert result.decision == Decision.INCOMPATIBLE
    assert "SECURITY.PRINCIPAL_CARDINALITY_MISMATCH" in result.reason_codes


def test_collector_core_contains_no_connection_creation_primitive():
    root = Path(__file__).parents[1] / "tools" / "efata_schema_collector"
    text = "\n".join(
        p.read_text()
        for p in root.glob("*.py")
    )
    forbidden = (
        "psycopg.connect(",
        "create_engine(",
        "connect_url(",
        "def open_connection",
        "socket.create_connection",
    )
    for marker in forbidden:
        assert marker not in text


def test_no_cli_exists():
    root = Path(__file__).parents[1] / "tools" / "efata_schema_collector"
    assert not (root / "cli.py").exists()


def test_unclassified_privileged_role_fails_closed_inconclusive():
    manifest = SecurityManifest(
        roles=(
            base_role(),
            base_role("shadow_admin", rolsuper=True),
        )
    )
    result = evaluate_security(manifest, profile(), complete_report())
    # The unknown privileged principal prevents a positive compatibility result.
    assert result.decision in {Decision.INCOMPATIBLE, Decision.INCONCLUSIVE}
    assert "CAPTURE.PRINCIPAL_UNCLASSIFIED" in result.reason_codes
