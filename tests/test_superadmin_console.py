import os

from fastapi.testclient import TestClient

from conftest import Testing
from orkio_v2.config import get_settings
from orkio_v2.main import app
from orkio_v2.models import AuditEvent, Membership, NativeCredential, NativeSession, Tenant, User


def _configure(monkeypatch):
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "native_session")
    monkeypatch.setenv("PLATFORM_NATIVE_AUTH_PEPPER", "p" * 40)
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_SECRET", "s" * 40)
    monkeypatch.setenv("PLATFORM_NATIVE_BOOTSTRAP_SECRET", "b" * 40)
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_COOKIE_SAMESITE", "lax")
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_COOKIE_NAME", "patroai_session")
    monkeypatch.setenv("PLATFORM_OWNER_SUBJECT", "native:daniel@patroai.com")
    monkeypatch.setenv("PLATFORM_ADMIN_EMAIL_ALLOWLIST", "daniel@patroai.com")
    get_settings.cache_clear()


def _reset_identity_tables():
    with Testing() as db:
        for model in (NativeSession, NativeCredential, Membership, User, Tenant):
            db.query(model).delete()
        db.commit()


def test_platform_owner_gets_superadmin_console_endpoints(monkeypatch):
    _configure(monkeypatch)
    _reset_identity_tables()
    client = TestClient(app)
    try:
        boot = client.post(
            "/api/v2/auth/bootstrap-owner",
            json={
                "bootstrap_secret": "b" * 40,
                "tenant_id": "patroai",
                "tenant_name": "PatroAI",
                "email": "daniel@patroai.com",
                "display_name": "Daniel",
                "password": "SenhaForte777!",
            },
        )
        assert boot.status_code == 200, boot.text
        me = client.get("/api/v2/me")
        assert me.status_code == 200, me.text
        assert {"admin", "platform_owner"}.issubset(
            set(me.json()["roles"])
        )

        for path in (
            "/api/v2/admin/overview",
            "/api/v2/admin/users",
            "/api/v2/admin/agents",
            "/api/v2/admin/teams",
            "/api/v2/admin/governance",
            "/api/v2/admin/usage-costs",
        ):
            response = client.get(path)
            assert response.status_code == 200, f"{path}: {response.text}"
    finally:
        os.environ["PLATFORM_AUTH_MODE"] = "test"
        get_settings.cache_clear()


def test_admin_without_platform_owner_subject_is_denied(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setenv("PLATFORM_OWNER_SUBJECT", "native:other@patroai.com")
    get_settings.cache_clear()
    _reset_identity_tables()
    client = TestClient(app)
    try:
        boot = client.post(
            "/api/v2/auth/bootstrap-owner",
            json={
                "bootstrap_secret": "b" * 40,
                "tenant_id": "patroai",
                "tenant_name": "PatroAI",
                "email": "daniel@patroai.com",
                "display_name": "Daniel",
                "password": "SenhaForte777!",
            },
        )
        assert boot.status_code == 200, boot.text
        denied = client.get("/api/v2/admin/overview")
        assert denied.status_code == 403
        assert denied.json()["detail"] == "SUPERADMIN_ROLE_REQUIRED"
    finally:
        os.environ["PLATFORM_AUTH_MODE"] = "test"
        get_settings.cache_clear()


def test_usage_costs_aggregates_tts_without_inventing_llm_cost(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setenv("PLATFORM_TTS_COST_PER_1M_CHARS_USD", "10")
    get_settings.cache_clear()
    _reset_identity_tables()
    client = TestClient(app)
    try:
        boot = client.post(
            "/api/v2/auth/bootstrap-owner",
            json={
                "bootstrap_secret": "b" * 40,
                "tenant_id": "patroai",
                "tenant_name": "PatroAI",
                "email": "daniel@patroai.com",
                "display_name": "Daniel",
                "password": "SenhaForte777!",
            },
        )
        assert boot.status_code == 200, boot.text

        with Testing() as db:
            db.add_all(
                [
                    AuditEvent(
                        tenant_id="patroai",
                        actor_id="native:daniel@patroai.com",
                        action="message_tts_request",
                        resource_type="message",
                        resource_id="m1",
                        outcome="success",
                        metadata_json={
                            "agent_id": "orkio",
                            "chars": 1000,
                            "cache_hit": False,
                            "idempotency_replay": False,
                        },
                    ),
                    AuditEvent(
                        tenant_id="patroai",
                        actor_id="native:daniel@patroai.com",
                        action="message_tts_request",
                        resource_type="message",
                        resource_id="m2",
                        outcome="success",
                        metadata_json={
                            "agent_id": "orkio",
                            "chars": 1000,
                            "cache_hit": True,
                            "idempotency_replay": False,
                        },
                    ),
                    AuditEvent(
                        tenant_id="patroai",
                        actor_id="native:daniel@patroai.com",
                        action="message_tts_request",
                        resource_type="message",
                        resource_id="m3",
                        outcome="success",
                        metadata_json={
                            "agent_id": "auditor",
                            "chars": 500,
                            "cache_hit": False,
                            "idempotency_replay": True,
                        },
                    ),
                    AuditEvent(
                        tenant_id="patroai",
                        actor_id="native:daniel@patroai.com",
                        action="message_tts_request",
                        resource_type="message",
                        resource_id="m4",
                        outcome="failed",
                        metadata_json={
                            "agent_id": "orkio",
                            "chars": 999999,
                            "cache_hit": False,
                            "idempotency_replay": False,
                        },
                    ),
                    AuditEvent(
                        tenant_id="other-tenant",
                        actor_id="native:other@example.com",
                        action="message_tts_request",
                        resource_type="message",
                        resource_id="foreign",
                        outcome="success",
                        metadata_json={
                            "agent_id": "orkio",
                            "chars": 999999,
                            "cache_hit": False,
                            "idempotency_replay": False,
                        },
                    ),
                ]
            )
            db.commit()

        response = client.get("/api/v2/admin/usage-costs?days=30")
        assert response.status_code == 200, response.text
        payload = response.json()

        assert payload["tenant_id"] == "patroai"
        assert payload["tts"]["requests"] == 3
        assert payload["tts"]["provider_syntheses"] == 1
        assert payload["tts"]["cache_hits"] == 1
        assert payload["tts"]["idempotency_replays"] == 1
        assert payload["tts"]["chars_requested"] == 2500
        assert payload["tts"]["chars_provider_synthesized"] == 1000
        assert payload["tts"]["cost_rate_configured"] is True
        assert payload["tts"]["estimated_provider_cost_usd"] == 0.01
        assert payload["tts"]["by_agent"]["orkio"] == {
            "requests": 2,
            "provider_syntheses": 1,
            "chars": 2000,
        }
        assert payload["llm_usage"] == {
            "status": "NOT_METERED",
            "reason_code": "LLM_TOKEN_LEDGER_NOT_IMPLEMENTED",
        }
    finally:
        os.environ["PLATFORM_AUTH_MODE"] = "test"
        get_settings.cache_clear()
