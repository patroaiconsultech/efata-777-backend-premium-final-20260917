from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_migration_008_matches_required_assignment_fields_and_states():
    text = (ROOT / "migrations/versions/008_admin_voice_catalog.py").read_text()
    assert '"created_at"' in text
    assert '"updated_at"' in text
    assert "ck_agent_voice_assignment_state" in text
    assert "ck_agent_voice_validation_status" in text
    assert "ck_agent_voice_active_requires_validated" in text


def test_admin_assignment_flushes_before_audit_resource_link():
    text = (ROOT / "src/orkio_v2/routes.py").read_text()
    assert "db.add(assignment)\n    db.flush()\n    db.add(AuditEvent" in text
