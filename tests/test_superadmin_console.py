import os

from fastapi.testclient import TestClient

from conftest import Testing
from orkio_v2.config import get_settings
from orkio_v2.main import app
from orkio_v2.models import Membership, NativeCredential, NativeSession, Tenant, User


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
