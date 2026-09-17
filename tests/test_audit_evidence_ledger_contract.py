from pathlib import Path

from orkio_v2.models import AuditEvidenceRecord
from orkio_v2.services.capability_policy import CapabilityPolicy


ROOT = Path(__file__).resolve().parents[1]


def test_ledger_model_is_dedicated_and_not_generic_audit_event():
    assert AuditEvidenceRecord.__tablename__ == "audit_evidence_records"
    columns = set(AuditEvidenceRecord.__table__.columns.keys())
    assert {
        "audit_execution_id",
        "tenant_id",
        "execution_id",
        "capability_id",
        "envelope_json",
        "evidence_sha256",
    } <= columns


def test_repository_has_no_update_or_delete_api():
    text = (
        ROOT / "src" / "orkio_v2" / "services" / "audit_evidence_repository.py"
    ).read_text(encoding="utf-8")
    assert "def update_evidence" not in text
    assert "def delete_evidence" not in text
    assert "AUDIT_EVIDENCE_IMMUTABLE" not in text or "delete_evidence" not in text


def test_all_audit_capabilities_remain_default_disabled():
    policy = CapabilityPolicy.from_env()
    assert policy.audit_evidence_capabilities_enabled is False
    assert policy.audit_file_inspect_enabled is False
    assert policy.audit_archive_inspect_enabled is False
    assert policy.audit_runtime_inspect_enabled is False
    assert policy.audit_runtime_file_sha256_enabled is False
    assert policy.audit_runtime_search_marker_enabled is False


def test_no_new_audit_execution_route_was_added():
    routes = (ROOT / "src" / "orkio_v2" / "routes.py").read_text(encoding="utf-8")
    assert '@router.post("/audit' not in routes
    assert '@router.get("/audit' not in routes
    assert "append_evidence(" not in routes
