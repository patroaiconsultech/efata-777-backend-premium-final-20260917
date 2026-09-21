from __future__ import annotations

from sqlalchemy import delete, select

from conftest import Testing, headers
from orkio_v2.config import get_settings
from orkio_v2.models import (
    AgentStudioVersion,
    AgentVoiceAssignment,
    AuditEvent,
    Membership,
    VoiceCatalogEntry,
)


def _superadmin(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(
        settings,
        "admin_email_allowlist",
        "owner@example.com",
        raising=False,
    )
    with Testing() as db:
        membership = db.scalar(
            select(Membership).where(
                Membership.tenant_id == "tenant-1",
                Membership.user_id == "user-1",
            )
        )
        membership.role = "superadmin"
        db.commit()
    return settings


def _cleanup_voice():
    with Testing() as db:
        db.execute(delete(AgentVoiceAssignment))
        db.execute(delete(VoiceCatalogEntry))
        db.commit()


def _cleanup_studio():
    with Testing() as db:
        db.execute(
            delete(AuditEvent).where(
                AuditEvent.resource_type == "agent_studio_version"
            )
        )
        db.execute(delete(AgentStudioVersion))
        db.commit()


def test_voice_catalog_create_preview_approve_assignment_drives_realtime_readiness(
    client, monkeypatch
):
    _cleanup_voice()
    settings = _superadmin(monkeypatch)
    monkeypatch.setattr(settings, "tts_enabled", True, raising=False)
    monkeypatch.setattr(settings, "tts_provider", "openai", raising=False)
    monkeypatch.setattr(settings, "voice_enabled", True, raising=False)
    monkeypatch.setattr(settings, "voice_provider", "openai", raising=False)
    monkeypatch.setattr(settings, "openai_api_key", "not-real-wave-test", raising=False)
    monkeypatch.setattr(settings, "realtime_bridge_enabled", True, raising=False)
    monkeypatch.setattr(settings, "voice_bindings_json", "{}", raising=False)

    async def fake_synth(_settings, profile, text, *, request_id):
        assert profile.voice_id == "alloy"
        assert profile.model == "gpt-4o-mini-tts"
        assert "prévia" in text.lower()
        return b"ID3-wave"

    monkeypatch.setattr("orkio_v2.routes.synthesize_speech", fake_synth)

    try:
        created = client.post(
            "/api/v2/admin/voice-catalog",
            json={
                "provider_key": "openai",
                "provider_voice_id": "alloy",
                "display_name": "Alloy governada",
                "provider_model": "gpt-4o-mini-tts",
                "supported_locales": ["pt-BR"],
                "delivery_modes": ["REALTIME_STREAM", "MESSAGE_PLAYBACK"],
            },
            headers=headers(roles="superadmin"),
        )
        assert created.status_code == 200, created.text
        voice = created.json()
        assert voice["curation_status"] == "REVIEW_REQUIRED"
        assert voice["active"] is True

        preview = client.post(
            f"/api/v2/admin/voice-catalog/{voice['id']}/preview",
            json={"text": "Esta é uma prévia de voz.", "locale": "pt-BR"},
            headers=headers(roles="superadmin"),
        )
        assert preview.status_code == 200, preview.text
        assert preview.content == b"ID3-wave"

        approved = client.post(
            f"/api/v2/admin/voice-catalog/{voice['id']}/curation",
            json={
                "curation_status": "APPROVED",
                "evidence_ref": "smoke://voice-preview-reviewed",
            },
            headers=headers(roles="superadmin"),
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["curation_status"] == "APPROVED"

        draft = client.put(
            "/api/v2/admin/agents/orkio/voice-assignment",
            json={
                "voice_catalog_id": voice["id"],
                "locale": "pt-BR",
                "delivery_modes": ["REALTIME_STREAM", "MESSAGE_PLAYBACK"],
            },
            headers=headers(roles="superadmin"),
        )
        assert draft.status_code == 200, draft.text
        assignment_id = draft.json()["id"]

        validated = client.post(
            f"/api/v2/admin/agent-voice-assignments/{assignment_id}/validation",
            json={
                "validation_status": "VALIDATED",
                "evidence_ref": "smoke://voice-assignment-reviewed",
            },
            headers=headers(roles="superadmin"),
        )
        assert validated.status_code == 200, validated.text

        activated = client.post(
            f"/api/v2/admin/agent-voice-assignments/{assignment_id}/activation",
            json={"evidence_ref": "approval://voice-assignment-human"},
            headers=headers(roles="superadmin"),
        )
        assert activated.status_code == 200, activated.text

        capabilities = client.get(
            "/api/v2/realtime/capabilities",
            headers=headers(roles="superadmin"),
        )
        assert capabilities.status_code == 200, capabilities.text
        voice_output = capabilities.json()["voice_output"]
        assert voice_output["eligible"] is True
        assert voice_output["binding_source"] == "admin_assignment"
    finally:
        _cleanup_voice()


def test_agent_studio_custom_lifecycle_is_tenant_scoped_and_activation_fails_closed(
    client, monkeypatch
):
    _cleanup_studio()
    _superadmin(monkeypatch)
    try:
        created = client.post(
            "/api/v2/admin/agent-studio",
            json={
                "agent_slug": "finance-coach",
                "source_kind": "CUSTOM",
                "display_name": "Finance Coach",
                "canonical_name": "Finance Coach",
                "role_label": "Especialista Financeiro",
                "department": "Finanças",
                "description": "Agente custom de teste governado.",
                "system_instruction": "Atue somente no contexto financeiro autorizado.",
                "provider": "openai",
                "model_name": "test-model",
                "temperature": 0.2,
                "capabilities": {"chat": True},
                "knowledge_config": {},
                "daily_budget_usd": 5,
                "monthly_budget_usd": 100,
            },
            headers=headers(roles="superadmin"),
        )
        assert created.status_code == 200, created.text
        row = created.json()
        assert row["lifecycle_state"] == "DRAFT"
        assert row["runtime_enabled"] is False

        patched = client.patch(
            f"/api/v2/admin/agent-studio/versions/{row['id']}",
            json={"description": "Descrição atualizada."},
            headers=headers(roles="superadmin"),
        )
        assert patched.status_code == 200, patched.text
        assert patched.json()["description"] == "Descrição atualizada."

        reviewed = client.post(
            f"/api/v2/admin/agent-studio/versions/{row['id']}/review",
            json={"evidence_ref": "review://agent-studio-test"},
            headers=headers(roles="superadmin"),
        )
        assert reviewed.status_code == 200, reviewed.text
        assert reviewed.json()["lifecycle_state"] == "REVIEW"

        approved = client.post(
            f"/api/v2/admin/agent-studio/versions/{row['id']}/approval",
            json={"evidence_ref": "approval://agent-studio-human"},
            headers=headers(roles="superadmin"),
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["lifecycle_state"] == "APPROVED"
        assert approved.json()["runtime_enabled"] is False

        activation = client.post(
            f"/api/v2/admin/agent-studio/versions/{row['id']}/activation",
            json={"evidence_ref": "approval://runtime-attempt"},
            headers=headers(roles="superadmin"),
        )
        assert activation.status_code == 409, activation.text
        detail = activation.json()["detail"]
        assert detail["code"] == "AGENT_STUDIO_TENANT_AWARE_RUNTIME_NOT_IMPLEMENTED"
        assert detail["runtime_enabled"] is False

        with Testing() as db:
            persisted = db.get(AgentStudioVersion, row["id"])
            assert persisted is not None
            assert persisted.tenant_id == "tenant-1"
            assert persisted.lifecycle_state == "APPROVED"
            assert persisted.runtime_enabled is False
    finally:
        _cleanup_studio()


def test_agent_studio_migration_is_additive_and_single_head():
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    script = ScriptDirectory.from_config(Config(str(root / "alembic.ini")))
    assert script.get_heads() == ["013_agent_studio_control_plane"]
    revision = script.get_revision("013_agent_studio_control_plane")
    assert revision is not None
    assert revision.down_revision == "012_platform_user_invitations"

    text = (root / "migrations/versions/013_agent_studio_control_plane.py").read_text()
    assert "agent_studio_versions" in text
    assert "CUSTOM','CANONICAL_OVERRIDE" in text
    assert "runtime_enabled" in text
    assert "INSERT " not in text.upper()
    assert "UPDATE " not in text.upper()
