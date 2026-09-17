from http.cookies import SimpleCookie
import os

import pytest
from fastapi.testclient import TestClient

from orkio_v2.config import get_settings
from orkio_v2.main import app
from orkio_v2.models import (
    AccessGrantRedemption,
    AuditEvent,
    Membership,
    NativeCredential,
    NativePasswordReset,
    NativeSession,
    Tenant,
    User,
    UserExperienceProfile,
)
from conftest import Testing


@pytest.fixture(autouse=True)
def clear_settings_cache():
    os.environ["PLATFORM_AUTH_MODE"] = "test"
    get_settings.cache_clear()
    yield
    os.environ["PLATFORM_AUTH_MODE"] = "test"
    get_settings.cache_clear()


def native_settings(monkeypatch):
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "native_session")
    monkeypatch.setenv("PLATFORM_NATIVE_AUTH_PEPPER", "p" * 40)
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_SECRET", "s" * 40)
    monkeypatch.setenv("PLATFORM_NATIVE_BOOTSTRAP_SECRET", "b" * 40)
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_COOKIE_SAMESITE", "lax")
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_COOKIE_NAME", "patroai_session")
    monkeypatch.setenv("PLATFORM_NATIVE_PASSWORD_MIN_LENGTH", "12")
    monkeypatch.setenv("PLATFORM_NATIVE_LOGIN_MAX_FAILURES", "3")
    monkeypatch.setenv("PLATFORM_NATIVE_LOGIN_LOCK_MINUTES", "15")
    get_settings.cache_clear()
    return get_settings()


def reset_identity_tables():
    with Testing() as db:
        for model in (
            NativeSession,
            NativePasswordReset,
            NativeCredential,
            AuditEvent,
            AccessGrantRedemption,
            UserExperienceProfile,
            Membership,
            User,
            Tenant,
        ):
            db.query(model).delete()
        db.add(Tenant(id="tenant-1", name="Test"))
        db.add(
            User(
                id="user-1",
                external_subject="sub-1",
                email="owner@example.com",
                display_name="Owner",
            )
        )
        db.add(
            User(
                id="user-2",
                external_subject="sub-2",
                email="guest@example.com",
                display_name="Guest",
            )
        )
        db.add(Membership(tenant_id="tenant-1", user_id="user-1", role="admin"))
        db.commit()


def test_native_bootstrap_login_session_and_logout(monkeypatch):
    native_settings(monkeypatch)
    reset_identity_tables()
    client = TestClient(app)
    payload = {
        "bootstrap_secret": "b" * 40,
        "tenant_id": "tenant-native",
        "tenant_name": "PatroAI Native",
        "email": "Owner@PatroAI.com",
        "display_name": "Owner Native",
        "password": "SenhaForte777!",
    }

    boot = client.post("/api/v2/auth/bootstrap-owner", json=payload)
    assert boot.status_code == 200, boot.text
    assert boot.json()["authenticated"] is True
    assert boot.json()["tenant_id"] == "tenant-native"
    assert "httponly" in boot.headers["set-cookie"].lower()

    session = client.get("/api/v2/auth/session")
    assert session.status_code == 200
    assert session.json()["authenticated"] is True

    agents = client.get("/api/v2/agents")
    assert agents.status_code == 200

    logout = client.post("/api/v2/auth/logout")
    assert logout.status_code == 200
    assert logout.json()["authenticated"] is False

    denied = client.get("/api/v2/auth/session")
    assert denied.status_code == 401
    assert denied.json()["detail"] == "NATIVE_SESSION_REQUIRED"


def test_native_session_uses_configured_cookie_name(monkeypatch):
    native_settings(monkeypatch)
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_COOKIE_NAME", "patroai_session_v2")
    get_settings.cache_clear()
    reset_identity_tables()
    client = TestClient(app)

    boot = client.post(
        "/api/v2/auth/bootstrap-owner",
        json={
            "bootstrap_secret": "b" * 40,
            "tenant_id": "tenant-custom-cookie",
            "tenant_name": "PatroAI Cookie",
            "email": "cookie@patroai.com",
            "display_name": "Cookie Owner",
            "password": "SenhaForte777!",
        },
    )

    assert boot.status_code == 200, boot.text
    assert "patroai_session_v2=" in boot.headers["set-cookie"]
    assert client.get("/api/v2/auth/session").status_code == 200
    assert client.get("/api/v2/agents").status_code == 200


def test_native_password_hash_is_not_plaintext(monkeypatch):
    native_settings(monkeypatch)
    reset_identity_tables()
    client = TestClient(app)
    password = "OutraSenhaForte777!"
    response = client.post(
        "/api/v2/auth/bootstrap-owner",
        json={
            "bootstrap_secret": "b" * 40,
            "tenant_id": "tenant-native-2",
            "tenant_name": "PatroAI Native 2",
            "email": "native2@patroai.com",
            "display_name": "Native 2",
            "password": password,
        },
    )
    assert response.status_code == 200

    with Testing() as db:
        credential = db.query(NativeCredential).first()
        assert credential is not None
        assert password not in credential.password_hash
        assert credential.password_hash.startswith("scrypt$")


def test_native_login_rejects_bad_password_and_locks(monkeypatch):
    native_settings(monkeypatch)
    reset_identity_tables()
    client = TestClient(app)
    payload = {
        "bootstrap_secret": "b" * 40,
        "tenant_id": "tenant-lock",
        "tenant_name": "PatroAI Lock",
        "email": "lock@patroai.com",
        "display_name": "Lock User",
        "password": "SenhaForteLock777!",
    }

    boot = client.post("/api/v2/auth/bootstrap-owner", json=payload)
    assert boot.status_code == 200
    client.post("/api/v2/auth/logout")

    for _ in range(2):
        bad = client.post(
            "/api/v2/auth/login",
            json={"email": payload["email"], "password": "errada"},
        )
        assert bad.status_code == 401

    locked = client.post(
        "/api/v2/auth/login",
        json={"email": payload["email"], "password": "errada"},
    )
    assert locked.status_code == 401

    still_locked = client.post(
        "/api/v2/auth/login",
        json={"email": payload["email"], "password": payload["password"]},
    )
    assert still_locked.status_code == 423
    assert still_locked.json()["detail"] == "ACCOUNT_TEMPORARILY_LOCKED"


def test_native_password_reset_requires_confirmation_and_revokes_sessions(monkeypatch):
    native_settings(monkeypatch)
    reset_identity_tables()
    client = TestClient(app)
    payload = {
        "bootstrap_secret": "b" * 40,
        "tenant_id": "tenant-reset",
        "tenant_name": "PatroAI Reset",
        "email": "reset@patroai.com",
        "display_name": "Reset User",
        "password": "SenhaForteReset777!",
    }

    boot = client.post("/api/v2/auth/bootstrap-owner", json=payload)
    assert boot.status_code == 200
    old_cookie = boot.headers["set-cookie"]

    forgot = client.post("/api/v2/auth/password/forgot", json={"email": payload["email"]})
    assert forgot.status_code == 200, forgot.text
    token = forgot.json()["reset_token"]
    assert token

    mismatch = client.post(
        "/api/v2/auth/password/reset",
        json={
            "token": token,
            "password": "NovaSenhaForteReset777!",
            "password_confirm": "OutraSenhaForteReset777!",
        },
    )
    assert mismatch.status_code == 422
    assert mismatch.json()["detail"] == "PASSWORD_CONFIRMATION_MISMATCH"

    reset = client.post(
        "/api/v2/auth/password/reset",
        json={
            "token": token,
            "password": "NovaSenhaForteReset777!",
            "password_confirm": "NovaSenhaForteReset777!",
        },
    )
    assert reset.status_code == 200, reset.text
    assert reset.json()["authenticated"] is False

    parsed_cookie = SimpleCookie()
    parsed_cookie.load(old_cookie)
    old_cookie_header = "; ".join(
        f"{name}={morsel.value}" for name, morsel in parsed_cookie.items()
    )
    old_session = TestClient(app).get(
        "/api/v2/auth/session",
        headers={"Cookie": old_cookie_header},
    )
    assert old_session.status_code == 401

    login = client.post(
        "/api/v2/auth/login",
        json={"email": payload["email"], "password": "NovaSenhaForteReset777!"},
    )
    assert login.status_code == 200

    reused = client.post(
        "/api/v2/auth/password/reset",
        json={
            "token": token,
            "password": "OutraNovaSenhaReset777!",
            "password_confirm": "OutraNovaSenhaReset777!",
        },
    )
    assert reused.status_code == 400


def test_native_settings_fail_closed_in_staging(monkeypatch):
    monkeypatch.setenv("PLATFORM_ENVIRONMENT", "staging")
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "native_session")
    monkeypatch.setenv("PLATFORM_INVITATION_TOKEN_SECRET", "x" * 40)
    monkeypatch.setenv("PLATFORM_NATIVE_AUTH_PEPPER", "p" * 40)
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_SECRET", "s" * 40)
    monkeypatch.setenv("PLATFORM_NATIVE_BOOTSTRAP_SECRET", "b" * 40)
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_COOKIE_SECURE", "false")
    get_settings.cache_clear()
    try:
        try:
            get_settings()
        except ValueError as exc:
            assert "NATIVE_HOST_COOKIE_REQUIRES_SECURE" in str(exc) or "NATIVE_SESSION_COOKIE_SECURE_REQUIRED" in str(exc)
        else:
            raise AssertionError("native staging settings accepted insecure cookie")
    finally:
        get_settings.cache_clear()
