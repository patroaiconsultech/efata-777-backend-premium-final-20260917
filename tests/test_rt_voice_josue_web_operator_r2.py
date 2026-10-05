from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_voice_catalog_has_governed_reactivation_endpoint():
    text = (ROOT / "src/orkio_v2/routes.py").read_text()
    assert '@router.post("/admin/voice-catalog/{voice_id}/activation")' in text
    assert "require_provisioned_superadmin" in text
    assert 'action="ADMIN_VOICE_CATALOG_ACTIVATED"' in text
    assert "row.active = True" in text


def test_josue_operator_reactivates_inactive_cedar_before_preview():
    text = (ROOT / "src/orkio_v2/voice_routes.py").read_text()
    assert "if (!existing.active)" in text
    assert "/activation" in text
    assert "reactivate-web-pilot:" in text
    assert "validateCedar(existing)" in text


def test_reactivation_does_not_activate_agent_assignment():
    text = (ROOT / "src/orkio_v2/routes.py").read_text()
    block = text.split(
        '@router.post("/admin/voice-catalog/{voice_id}/activation")', 1
    )[1].split(
        '@router.post("/admin/voice-catalog/{voice_id}/preview")', 1
    )[0]
    assert "AgentVoiceAssignment" not in block
    assert "assignment_state" not in block
    assert "validation_status" not in block
