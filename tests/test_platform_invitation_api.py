from __future__ import annotations

from sqlalchemy import select

from conftest import Testing, headers
from orkio_v2.config import get_settings
from orkio_v2.models import (
    AuditEvent,
    Membership,
    PlatformInvitation,
    PlatformInvitationOutbox,
    User,
)
from orkio_v2.services.email_provider import DELIVERY_ACCEPTED_BY_PROVIDER, DeliveryResult
from orkio_v2.services.platform_invitations import activation_token
import orkio_v2.services.platform_invitations as platform_service


class ApiFakeProvider:
    provider_name = "fake"

    def __init__(self):
        self.keys: list[str] = []

    def send_platform_invitation(
        self,
        *,
        to_email,
        activation_url,
        expires_hours,
        idempotency_key,
    ):
        self.keys.append(idempotency_key)
        return DeliveryResult(
            status=DELIVERY_ACCEPTED_BY_PROVIDER,
            provider_message_id="api-fake-id",
        )


def _configure(monkeypatch):
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "test")
    monkeypatch.setenv("PLATFORM_OWNER_SUBJECT", "sub-1")
    monkeypatch.setenv("PLATFORM_ADMIN_EMAIL_ALLOWLIST", "owner@example.com")
    monkeypatch.setenv("PLATFORM_USER_INVITATION_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_USER_INVITATION_SECRET", "u" * 40)
    monkeypatch.setenv("PLATFORM_USER_INVITATION_BASE_URL", "http://localhost:5173/activate")
    monkeypatch.setenv("PLATFORM_USER_INVITATION_ALLOWED_ROLES", "member,admin")
    monkeypatch.setenv("PLATFORM_NATIVE_AUTH_PEPPER", "p" * 40)
    monkeypatch.setenv("PLATFORM_NATIVE_SESSION_SECRET", "s" * 40)
    get_settings.cache_clear()


def _cleanup(email: str):
    with Testing() as db:
        invitation_ids = list(
            db.scalars(
                select(PlatformInvitation.id).where(
                    PlatformInvitation.invited_email == email
                )
            ).all()
        )
        if invitation_ids:
            db.query(PlatformInvitationOutbox).filter(
                PlatformInvitationOutbox.invitation_id.in_(invitation_ids)
            ).delete(synchronize_session=False)
            db.query(AuditEvent).filter(
                AuditEvent.resource_id.in_(invitation_ids)
            ).delete(synchronize_session=False)
            db.query(PlatformInvitation).filter(
                PlatformInvitation.id.in_(invitation_ids)
            ).delete(synchronize_session=False)
        user = db.scalar(select(User).where(User.email == email))
        if user is not None:
            db.query(Membership).filter(Membership.user_id == user.id).delete(
                synchronize_session=False
            )
            db.delete(user)
        db.commit()


def test_admin_platform_invitation_api_end_to_end_local(client, monkeypatch):
    _configure(monkeypatch)
    email = "api-invite@example.com"
    _cleanup(email)
    fake = ApiFakeProvider()
    monkeypatch.setattr(platform_service, "build_email_provider", lambda settings: fake)

    response = client.post(
        "/api/v2/admin/user-invitations",
        headers=headers(),
        json={"email": email, "role": "member"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["delivery_status"] == "ACCEPTED_BY_PROVIDER"
    assert body["provider_message_id"] == "api-fake-id"
    assert body["state"] == "PENDING"

    with Testing() as db:
        invitation = db.get(PlatformInvitation, body["invitation_id"])
        assert invitation is not None
        token = activation_token(invitation.id, get_settings())
        assert token not in str(invitation.__dict__)

    status = client.post(
        "/api/v2/platform-invitations/status",
        json={"token": token},
    )
    assert status.status_code == 200, status.text
    assert status.json()["status"] == "PENDING"

    accepted = client.post(
        "/api/v2/platform-invitations/accept",
        json={
            "token": token,
            "display_name": "API Invitee",
            "password": "SenhaPremium777!",
            "password_confirm": "SenhaPremium777!",
        },
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["status"] == "ACCEPTED_LOGIN_REQUIRED"
    assert accepted.json()["tenant_id"] == "tenant-1"

    replay = client.post(
        "/api/v2/platform-invitations/accept",
        json={
            "token": token,
            "display_name": "API Invitee",
            "password": "SenhaPremium777!",
            "password_confirm": "SenhaPremium777!",
        },
    )
    assert replay.status_code == 409
    assert replay.json()["detail"] == "PLATFORM_INVITATION_ALREADY_ACCEPTED"
    _cleanup(email)


def test_admin_invitation_schema_rejects_tenant_injection_and_invalid_role(client, monkeypatch):
    _configure(monkeypatch)

    injected = client.post(
        "/api/v2/admin/user-invitations",
        headers=headers(),
        json={
            "email": "injected@example.com",
            "role": "member",
            "tenant_id": "tenant-b",
        },
    )
    assert injected.status_code == 422

    invalid_role = client.post(
        "/api/v2/admin/user-invitations",
        headers=headers(),
        json={"email": "role@example.com", "role": "superadmin"},
    )
    assert invalid_role.status_code == 422


def test_non_admin_cannot_create_platform_invitation(client, monkeypatch):
    _configure(monkeypatch)
    with Testing() as db:
        membership = db.scalar(
            select(Membership).where(
                Membership.tenant_id == "tenant-1",
                Membership.user_id == "user-2",
            )
        )
        if membership is None:
            db.add(
                Membership(
                    tenant_id="tenant-1",
                    user_id="user-2",
                    role="member",
                    active=True,
                )
            )
        else:
            membership.role = "member"
            membership.active = True
        db.commit()

    response = client.post(
        "/api/v2/admin/user-invitations",
        headers=headers(user="user-2", roles="member"),
        json={"email": "denied@example.com", "role": "member"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "SUPERADMIN_ROLE_REQUIRED"
