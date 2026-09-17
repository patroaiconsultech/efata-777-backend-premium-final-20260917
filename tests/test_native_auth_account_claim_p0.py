import hashlib
import hmac

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from orkio_v2.config import get_settings
from orkio_v2.main import app
from orkio_v2.models import (
    AccessGrantRedemption,
    AuditEvent,
    Membership,
    NativeAuthChallenge,
    NativeCredential,
    NativeMfaFactor,
    NativeMfaRecoveryCode,
    NativePasswordReset,
    NativeSession,
    Tenant,
    User,
    UserExperienceProfile,
)
from orkio_v2.services.hyper_cocreator import validate_access_code
from conftest import Testing


ACCESS_CODE = "p0-claim-test-code"
ACCESS_SECRET = "-".join(("p0", "claim", "test", "signing", "secret", "32chars"))


def _digest(code: str) -> str:
    return hmac.new(
        ACCESS_SECRET.encode("utf-8"),
        code.strip().lower().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


@pytest.fixture(autouse=True)
def p0_native_settings(monkeypatch):
    monkeypatch.setenv("PLATFORM_ENVIRONMENT", "test")
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "native_session")
    monkeypatch.setenv("PLATFORM_NATIVE_AUTH_PEPPER", "p" * 40)
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_SECRET", "s" * 40)
    monkeypatch.setenv("PLATFORM_NATIVE_BOOTSTRAP_SECRET", "b" * 40)
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_COOKIE_SAMESITE", "lax")
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_COOKIE_NAME", "patroai_session")
    monkeypatch.setenv("PLATFORM_NATIVE_PASSWORD_MIN_LENGTH", "12")
    monkeypatch.setenv("PLATFORM_ACCESS_GATE_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_ACCESS_GATE_CODE_HASHES", _digest(ACCESS_CODE))
    monkeypatch.setenv("PLATFORM_ACCESS_GATE_SIGNING_SECRET", ACCESS_SECRET)
    monkeypatch.setenv("PLATFORM_ACCESS_GATE_TENANT_ID", "tenant-claim")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _reset_identity_tables():
    with Testing() as db:
        for model in (
            NativeSession,
            NativeAuthChallenge,
            NativeMfaFactor,
            NativeMfaRecoveryCode,
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
        db.add(Tenant(id="tenant-claim", name="Claim Test"))
        db.commit()


def _grant() -> str:
    return validate_access_code(get_settings(), ACCESS_CODE).token


def _register_payload(email: str, *, password: str = "SenhaForteClaim777!") -> dict:
    return {
        "grant": _grant(),
        "email": email,
        "display_name": "Claim Test",
        "password": password,
        "co_creator_name": "Dani",
        "onboarding_goal": "Testar account claim",
    }


def test_existing_legacy_admin_requires_claim_and_cannot_be_taken_over():
    _reset_identity_tables()
    with Testing() as db:
        db.add(
            User(
                id="legacy-admin",
                external_subject="legacy:oidc:admin",
                email="victim@example.com",
                display_name="Legacy Admin",
            )
        )
        db.add(
            Membership(
                tenant_id="tenant-claim",
                user_id="legacy-admin",
                role="admin",
                active=True,
            )
        )
        db.commit()

    response = TestClient(app).post(
        "/api/v2/auth/register",
        json=_register_payload("victim@example.com"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is False
    assert body["status"] == "ACCOUNT_RECOVERY_REQUIRED"
    assert body["claim_token"]

    recovery = TestClient(app).post(
        "/api/v2/auth/account/recover",
        json={
            "token": body["claim_token"],
            "password": "SenhaRecuperada777!",
            "password_confirm": "SenhaRecuperada777!",
        },
    )
    assert recovery.status_code == 200
    assert recovery.json()["status"] == "ACCOUNT_RECOVERY_COMPLETE"

    with Testing() as db:
        credential = db.scalar(
            select(NativeCredential).where(NativeCredential.user_id == "legacy-admin")
        )
        assert credential is not None
        assert "SenhaRecuperada777!" not in credential.password_hash
        assert db.scalar(
            select(NativeSession).where(NativeSession.user_id == "legacy-admin")
        ) is None
        membership = db.scalar(
            select(Membership).where(
                Membership.user_id == "legacy-admin",
                Membership.tenant_id == "tenant-claim",
            )
        )
        assert membership is not None
        assert membership.role == "admin"
        assert membership.active is True
        assert db.query(AccessGrantRedemption).count() == 1


def test_claim_guard_does_not_reactivate_inactive_membership():
    _reset_identity_tables()
    with Testing() as db:
        db.add(
            User(
                id="legacy-inactive",
                external_subject="legacy:oidc:inactive",
                email="inactive@example.com",
                display_name="Inactive Legacy",
            )
        )
        db.add(
            Membership(
                tenant_id="tenant-claim",
                user_id="legacy-inactive",
                role="member",
                active=False,
            )
        )
        db.commit()

    response = TestClient(app).post(
        "/api/v2/auth/register",
        json=_register_payload("inactive@example.com"),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "ACCOUNT_RECOVERY_NOT_ALLOWED"

    with Testing() as db:
        membership = db.scalar(
            select(Membership).where(
                Membership.user_id == "legacy-inactive",
                Membership.tenant_id == "tenant-claim",
            )
        )
        assert membership is not None
        assert membership.active is False
        assert db.scalar(
            select(NativeCredential).where(NativeCredential.user_id == "legacy-inactive")
        ) is None
        assert db.query(AccessGrantRedemption).count() == 0


def test_existing_native_account_is_never_overwritten_by_register():
    _reset_identity_tables()
    # Use the public bootstrap primitive only to seed a credential through the same service.
    from orkio_v2.services.native_auth import create_or_update_credential

    settings = get_settings()
    with Testing() as db:
        user = User(
            id="native-existing",
            external_subject="native:existing@example.com",
            email="existing@example.com",
            display_name="Existing Native",
        )
        db.add(user)
        db.add(
            Membership(
                tenant_id="tenant-claim",
                user_id=user.id,
                role="member",
                active=True,
            )
        )
        db.flush()
        credential = create_or_update_credential(
            db,
            user_id=user.id,
            password="SenhaOriginal777!",
            settings=settings,
        )
        original_hash = credential.password_hash
        db.commit()

    response = TestClient(app).post(
        "/api/v2/auth/register",
        json=_register_payload(
            "existing@example.com",
            password="SenhaAtacante777!",
        ),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "NATIVE_ACCOUNT_ALREADY_EXISTS"

    with Testing() as db:
        credential = db.scalar(
            select(NativeCredential).where(
                NativeCredential.user_id == "native-existing"
            )
        )
        assert credential is not None
        assert credential.password_hash == original_hash
        assert db.query(AccessGrantRedemption).count() == 0


def test_new_identity_registration_still_works():
    _reset_identity_tables()

    response = TestClient(app).post(
        "/api/v2/auth/register",
        json=_register_payload("brand-new@example.com"),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["authenticated"] is True
    assert body["tenant_id"] == "tenant-claim"
    assert body["roles"] == ["member"]

    with Testing() as db:
        user = db.scalar(select(User).where(User.email == "brand-new@example.com"))
        assert user is not None
        assert db.scalar(
            select(NativeCredential).where(NativeCredential.user_id == user.id)
        ) is not None
        assert db.scalar(
            select(NativeSession).where(NativeSession.user_id == user.id)
        ) is not None
        membership = db.scalar(
            select(Membership).where(
                Membership.user_id == user.id,
                Membership.tenant_id == "tenant-claim",
            )
        )
        assert membership is not None
        assert membership.role == "member"
        assert membership.active is True
        assert db.query(AccessGrantRedemption).count() == 1
