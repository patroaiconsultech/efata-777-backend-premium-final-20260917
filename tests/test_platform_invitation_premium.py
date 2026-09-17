from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from orkio_v2.auth import Principal
from orkio_v2.config import Settings, get_settings
from orkio_v2.database import Base
from orkio_v2.models import (
    AuditEvent,
    Membership,
    NativeCredential,
    NativeSession,
    PlatformInvitation,
    PlatformInvitationOutbox,
    Tenant,
    User,
    now,
)
from orkio_v2.services.email_provider import (
    DELIVERY_ACCEPTED_BY_PROVIDER,
    DELIVERY_FAILED,
    DeliveryResult,
)
from orkio_v2.services.native_auth import NativeAuthError, hash_password, login
from orkio_v2.services.platform_invitations import (
    PlatformInvitationError,
    accept_platform_invitation,
    activation_token,
    dispatch_outbox,
    issue_platform_invitation,
    prepare_resend,
    public_status,
    revoke_invitation,
    revoke_user_sessions,
    update_membership,
)


class FakeProvider:
    provider_name = "fake"

    def __init__(self, *, status=DELIVERY_ACCEPTED_BY_PROVIDER, error_code=None):
        self.status = status
        self.error_code = error_code
        self.calls: list[dict] = []

    def send_platform_invitation(
        self,
        *,
        to_email,
        activation_url,
        expires_hours,
        idempotency_key,
    ):
        self.calls.append(
            {
                "to_email": to_email,
                "activation_url": activation_url,
                "expires_hours": expires_hours,
                "idempotency_key": idempotency_key,
            }
        )
        if self.status == DELIVERY_ACCEPTED_BY_PROVIDER:
            return DeliveryResult(
                status=DELIVERY_ACCEPTED_BY_PROVIDER,
                provider_message_id="fake-message-id",
            )
        return DeliveryResult(status=DELIVERY_FAILED, error_code=self.error_code or "FAKE_FAILURE")


def settings(**overrides) -> Settings:
    values = {
        "PLATFORM_ENVIRONMENT": "test",
        "PLATFORM_AUTH_MODE": "test",
        "PLATFORM_INVITATION_TOKEN_SECRET": "t" * 40,
        "PLATFORM_USER_INVITATION_ENABLED": "true",
        "PLATFORM_USER_INVITATION_SECRET": "u" * 40,
        "PLATFORM_USER_INVITATION_BASE_URL": "http://localhost:5173/activate",
        "PLATFORM_USER_INVITATION_ALLOWED_ROLES": "member,admin",
        "PLATFORM_NATIVE_AUTH_PEPPER": "p" * 40,
        "PLATFORM_NATIVE_SESSION_SECRET": "s" * 40,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as session:
        session.add(Tenant(id="tenant-a", name="Tenant A"))
        session.add(Tenant(id="tenant-b", name="Tenant B"))
        session.add(
            User(
                id="admin-a",
                external_subject="sub-admin-a",
                email="admin@example.com",
                display_name="Admin",
            )
        )
        session.add(
            Membership(
                tenant_id="tenant-a",
                user_id="admin-a",
                role="admin",
                active=True,
            )
        )
        session.commit()
        yield session


def principal() -> Principal:
    return Principal(
        user_id="admin-a",
        tenant_id="tenant-a",
        roles=("admin", "platform_owner"),
        email="admin@example.com",
        external_subject="sub-admin-a",
    )


def test_platform_invitation_token_is_not_persisted_plaintext(db):
    cfg = settings()
    invitation, outbox = issue_platform_invitation(
        db,
        principal=principal(),
        email="New.User@Example.com ",
        role="member",
        settings=cfg,
    )
    db.commit()

    token = activation_token(invitation.id, cfg)
    assert invitation.invited_email == "new.user@example.com"
    assert invitation.token_hash != token
    assert token not in invitation.token_hash
    assert token not in outbox.idempotency_key
    assert "#token=" not in str(invitation.__dict__)
    assert token not in str(outbox.__dict__)


def test_provider_acceptance_is_not_called_delivery(db):
    cfg = settings()
    invitation, outbox = issue_platform_invitation(
        db,
        principal=principal(),
        email="accepted@example.com",
        role="member",
        settings=cfg,
    )
    db.commit()
    provider = FakeProvider()

    dispatch_outbox(db, outbox_id=outbox.id, settings=cfg, provider=provider)
    db.commit()
    db.refresh(invitation)
    db.refresh(outbox)

    assert invitation.delivery_status == "ACCEPTED_BY_PROVIDER"
    assert outbox.status == "ACCEPTED_BY_PROVIDER"
    assert invitation.provider_message_id == "fake-message-id"
    assert provider.calls[0]["idempotency_key"] == outbox.idempotency_key
    assert "DELIVERED" not in invitation.delivery_status


def test_provider_failure_is_observable_without_false_success(db):
    cfg = settings()
    invitation, outbox = issue_platform_invitation(
        db,
        principal=principal(),
        email="failure@example.com",
        role="member",
        settings=cfg,
    )
    db.commit()
    provider = FakeProvider(status=DELIVERY_FAILED, error_code="PROVIDER_TIMEOUT")

    dispatch_outbox(db, outbox_id=outbox.id, settings=cfg, provider=provider)
    db.commit()
    db.refresh(invitation)

    assert invitation.delivery_status == "DELIVERY_FAILED"
    assert invitation.delivery_error_code == "PROVIDER_TIMEOUT"
    audit = db.scalar(
        select(AuditEvent)
        .where(
            AuditEvent.resource_id == invitation.id,
            AuditEvent.action == "platform_invitation.delivery_attempted",
        )
        .order_by(AuditEvent.created_at.desc())
    )
    assert audit is not None
    assert audit.outcome == "delivery_failed"
    assert "token" not in str(audit.metadata_json).lower()
    assert "password" not in str(audit.metadata_json).lower()


def test_provider_acceptance_then_db_rollback_reuses_same_idempotency_key(db):
    cfg = settings()
    invitation, outbox = issue_platform_invitation(
        db,
        principal=principal(),
        email="crash-window@example.com",
        role="member",
        settings=cfg,
    )
    db.commit()
    outbox_id = outbox.id
    key = outbox.idempotency_key
    provider = FakeProvider()

    # Simulate: provider accepted, process dies before the delivery-state commit.
    dispatch_outbox(db, outbox_id=outbox_id, settings=cfg, provider=provider)
    db.rollback()

    persisted = db.get(PlatformInvitationOutbox, outbox_id)
    assert persisted is not None
    assert persisted.status == "PENDING"

    prepared = prepare_resend(
        db,
        invitation_id=invitation.id,
        tenant_id="tenant-a",
        actor_id="admin-a",
        settings=cfg,
    )
    db.commit()
    assert prepared.id == outbox_id
    assert prepared.idempotency_key == key

    dispatch_outbox(db, outbox_id=outbox_id, settings=cfg, provider=provider)
    db.commit()

    assert [call["idempotency_key"] for call in provider.calls] == [key, key]
    assert db.get(PlatformInvitationOutbox, outbox_id).status == "ACCEPTED_BY_PROVIDER"


def test_explicit_resend_after_provider_acceptance_creates_new_generation(db):
    cfg = settings()
    invitation, outbox = issue_platform_invitation(
        db,
        principal=principal(),
        email="resend@example.com",
        role="member",
        settings=cfg,
    )
    db.commit()
    provider = FakeProvider()
    dispatch_outbox(db, outbox_id=outbox.id, settings=cfg, provider=provider)
    db.commit()

    next_outbox = prepare_resend(
        db,
        invitation_id=invitation.id,
        tenant_id="tenant-a",
        actor_id="admin-a",
        settings=cfg,
    )
    db.commit()

    assert next_outbox.id != outbox.id
    assert next_outbox.generation == 2
    assert next_outbox.idempotency_key != outbox.idempotency_key


def test_accept_once_creates_native_identity_and_tenant_membership(db):
    cfg = settings()
    invitation, _ = issue_platform_invitation(
        db,
        principal=principal(),
        email="invitee@example.com",
        role="member",
        settings=cfg,
    )
    db.commit()
    token = activation_token(invitation.id, cfg)

    status = public_status(db, token=token, settings=cfg)
    assert status["status"] == "PENDING"
    assert status["email_hint"].endswith("@example.com")

    accepted = accept_platform_invitation(
        db,
        token=token,
        display_name="Invitee",
        password="SenhaPremium777!",
        password_confirm="SenhaPremium777!",
        settings=cfg,
    )
    db.commit()

    assert accepted.tenant_id == "tenant-a"
    user = db.scalar(select(User).where(User.email == "invitee@example.com"))
    assert user is not None
    assert user.email_verified_at is not None
    credential = db.scalar(select(NativeCredential).where(NativeCredential.user_id == user.id))
    assert credential is not None
    membership = db.scalar(
        select(Membership).where(
            Membership.user_id == user.id,
            Membership.tenant_id == "tenant-a",
        )
    )
    assert membership is not None and membership.active is True and membership.role == "member"

    with pytest.raises(PlatformInvitationError, match="PLATFORM_INVITATION_ALREADY_ACCEPTED"):
        accept_platform_invitation(
            db,
            token=token,
            display_name="Invitee",
            password="SenhaPremium777!",
            password_confirm="SenhaPremium777!",
            settings=cfg,
        )


def test_existing_native_account_requires_existing_password(db):
    cfg = settings()
    user = User(
        id="existing",
        external_subject="native:existing@example.com",
        email="existing@example.com",
        display_name="Existing",
    )
    db.add(user)
    db.flush()
    db.add(
        NativeCredential(
            user_id=user.id,
            password_hash=hash_password("CurrentPassword777!", cfg),
        )
    )
    db.commit()

    invitation, _ = issue_platform_invitation(
        db,
        principal=principal(),
        email="existing@example.com",
        role="member",
        settings=cfg,
    )
    db.commit()
    token = activation_token(invitation.id, cfg)

    with pytest.raises(PlatformInvitationError, match="EXISTING_ACCOUNT_PASSWORD_INVALID"):
        accept_platform_invitation(
            db,
            token=token,
            display_name="Existing",
            password="WrongPassword777!",
            password_confirm="WrongPassword777!",
            settings=cfg,
        )
    db.rollback()

    accepted = accept_platform_invitation(
        db,
        token=token,
        display_name="Existing",
        password="CurrentPassword777!",
        password_confirm="CurrentPassword777!",
        settings=cfg,
    )
    db.commit()
    assert accepted.user_id == "existing"


def test_revoked_and_expired_tokens_fail_closed(db):
    cfg = settings()
    revoked, _ = issue_platform_invitation(
        db,
        principal=principal(),
        email="revoked@example.com",
        role="member",
        settings=cfg,
    )
    db.commit()
    revoked_token = activation_token(revoked.id, cfg)
    revoke_invitation(
        db,
        invitation_id=revoked.id,
        tenant_id="tenant-a",
        actor_id="admin-a",
    )
    db.commit()
    with pytest.raises(PlatformInvitationError, match="PLATFORM_INVITATION_REVOKED"):
        accept_platform_invitation(
            db,
            token=revoked_token,
            display_name="Revoked",
            password="SenhaPremium777!",
            password_confirm="SenhaPremium777!",
            settings=cfg,
        )

    expired, _ = issue_platform_invitation(
        db,
        principal=principal(),
        email="expired@example.com",
        role="member",
        settings=cfg,
    )
    expired.expires_at = now() - timedelta(seconds=1)
    db.commit()
    expired_token = activation_token(expired.id, cfg)
    with pytest.raises(PlatformInvitationError, match="PLATFORM_INVITATION_EXPIRED"):
        accept_platform_invitation(
            db,
            token=expired_token,
            display_name="Expired",
            password="SenhaPremium777!",
            password_confirm="SenhaPremium777!",
            settings=cfg,
        )


def test_duplicate_pending_invite_and_cross_tenant_access_are_denied(db):
    cfg = settings()
    invitation, _ = issue_platform_invitation(
        db,
        principal=principal(),
        email="duplicate@example.com",
        role="member",
        settings=cfg,
    )
    db.commit()

    with pytest.raises(PlatformInvitationError, match="PLATFORM_INVITATION_ALREADY_PENDING"):
        issue_platform_invitation(
            db,
            principal=principal(),
            email="DUPLICATE@example.com",
            role="member",
            settings=cfg,
        )
    db.rollback()

    with pytest.raises(PlatformInvitationError, match="PLATFORM_INVITATION_NOT_FOUND"):
        revoke_invitation(
            db,
            invitation_id=invitation.id,
            tenant_id="tenant-b",
            actor_id="admin-b",
        )


def test_normalized_email_unique_index_blocks_case_variant_duplicate(db):
    db.add(
        User(
            id="case-a",
            external_subject="sub-case-a",
            email="CaseSensitive@Example.com",
            display_name="Case A",
        )
    )
    db.commit()
    db.add(
        User(
            id="case-b",
            external_subject="sub-case-b",
            email="casesensitive@example.com",
            display_name="Case B",
        )
    )
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_admin_membership_suspend_and_session_revoke_are_tenant_scoped(db):
    cfg = settings()
    user = User(
        id="target",
        external_subject="native:target@example.com",
        email="target@example.com",
        display_name="Target",
    )
    db.add(user)
    db.add(Membership(tenant_id="tenant-a", user_id="target", role="member", active=True))
    db.flush()
    db.add(
        NativeSession(
            session_hash="a" * 64,
            token_prefix="prefix",
            tenant_id="tenant-a",
            user_id="target",
            expires_at=now() + timedelta(hours=1),
        )
    )
    db.commit()

    membership = update_membership(
        db,
        tenant_id="tenant-a",
        actor_id="admin-a",
        target_user_id="target",
        role=None,
        active=False,
        settings=cfg,
    )
    assert membership.active is False
    count = revoke_user_sessions(
        db,
        tenant_id="tenant-a",
        actor_id="admin-a",
        target_user_id="target",
        reason="security_review",
    )
    db.commit()
    assert count == 1
    session = db.scalar(select(NativeSession).where(NativeSession.user_id == "target"))
    assert session is not None and session.revoked_at is not None

    with pytest.raises(PlatformInvitationError, match="ADMIN_USER_MEMBERSHIP_NOT_FOUND"):
        revoke_user_sessions(
            db,
            tenant_id="tenant-b",
            actor_id="admin-a",
            target_user_id="target",
            reason="cross_tenant",
        )


def test_admin_cannot_suspend_self(db):
    cfg = settings()
    with pytest.raises(PlatformInvitationError, match="ADMIN_CANNOT_MUTATE_OWN_MEMBERSHIP"):
        update_membership(
            db,
            tenant_id="tenant-a",
            actor_id="admin-a",
            target_user_id="admin-a",
            role=None,
            active=False,
            settings=cfg,
        )


def test_concurrent_acceptance_guard_is_row_locked_contract():
    # PostgreSQL concurrency itself belongs to the later migration/runtime gate;
    # this local contract prevents accidental removal of the locking primitive.
    import inspect
    import orkio_v2.services.platform_invitations as module

    source = inspect.getsource(module.accept_platform_invitation)
    helper = inspect.getsource(module._invitation_from_token)
    assert "lock=True" in source
    assert ".with_for_update()" in helper
    assert "PLATFORM_INVITATION_ALREADY_ACCEPTED" in source


def test_provider_timeout_is_observable_and_never_promoted_to_delivery(db):
    class TimeoutProvider:
        provider_name = "timeout"

        def send_platform_invitation(self, **kwargs):
            raise TimeoutError("synthetic-provider-timeout")

    cfg = settings()
    invitation, outbox = issue_platform_invitation(
        db,
        principal=principal(),
        email="timeout@example.com",
        role="member",
        settings=cfg,
    )
    db.commit()

    dispatch_outbox(db, outbox_id=outbox.id, settings=cfg, provider=TimeoutProvider())
    db.commit()
    db.refresh(invitation)
    db.refresh(outbox)

    assert invitation.delivery_status == DELIVERY_FAILED
    assert outbox.status == DELIVERY_FAILED
    assert invitation.delivery_error_code == "EMAIL_PROVIDER_FAILURE"
    assert outbox.error_code == "EMAIL_PROVIDER_FAILURE"
    assert invitation.provider_message_id is None


def test_suspended_membership_blocks_native_login_after_admin_action(db):
    cfg = settings()
    user = User(
        id="suspended-user",
        external_subject="native:suspended@example.com",
        email="suspended@example.com",
        display_name="Suspended",
    )
    db.add(user)
    db.add(
        Membership(
            tenant_id="tenant-a",
            user_id=user.id,
            role="member",
            active=True,
        )
    )
    db.add(
        NativeCredential(
            user_id=user.id,
            password_hash=hash_password("CurrentPassword777!", cfg),
        )
    )
    db.commit()

    membership = update_membership(
        db,
        tenant_id="tenant-a",
        actor_id="admin-a",
        target_user_id=user.id,
        role=None,
        active=False,
        settings=cfg,
    )
    db.commit()
    assert membership.active is False

    with pytest.raises(NativeAuthError, match="PRINCIPAL_NOT_PROVISIONED"):
        login(
            db,
            email=user.email,
            password="CurrentPassword777!",
            settings=cfg,
        )
