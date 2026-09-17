from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta, timezone
from urllib.parse import quote

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth import Principal
from ..config import Settings
from ..models import (
    AuditEvent,
    Membership,
    NativeCredential,
    NativeSession,
    PlatformInvitation,
    PlatformInvitationDeliveryStatus,
    PlatformInvitationOutbox,
    PlatformInvitationState,
    User,
    now,
)
from .email_provider import (
    DELIVERY_ACCEPTED_BY_PROVIDER,
    DELIVERY_FAILED,
    DELIVERY_PENDING,
    DeliveryResult,
    EmailProvider,
    EmailProviderError,
    build_email_provider,
)
from .native_auth import (
    create_or_update_credential,
    normalize_email,
    verify_password,
)


class PlatformInvitationError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class InvitationAcceptance:
    user_id: str
    tenant_id: str
    role: str


def _aware(value):
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def require_platform_invitation_enabled(settings: Settings) -> None:
    if not settings.platform_invitation_enabled:
        raise PlatformInvitationError("PLATFORM_INVITATION_DISABLED")
    if len(settings.platform_invitation_secret.strip()) < 32:
        raise PlatformInvitationError("PLATFORM_INVITATION_NOT_CONFIGURED")


def allowed_roles(settings: Settings) -> frozenset[str]:
    return frozenset(
        item.strip().lower()
        for item in settings.platform_invitation_allowed_roles.split(",")
        if item.strip()
    )


def _token_proof(invitation_id: str, settings: Settings) -> str:
    digest = hmac.new(
        settings.platform_invitation_secret.encode("utf-8"),
        f"efata-platform-invite:{invitation_id}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def activation_token(invitation_id: str, settings: Settings) -> str:
    """Reconstruct the secret token without persisting plaintext in the DB."""
    require_platform_invitation_enabled(settings)
    return f"{invitation_id}.{_token_proof(invitation_id, settings)}"


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _active_dedupe_key(tenant_id: str, email: str) -> str:
    return f"{tenant_id}:{normalize_email(email)}"


def _email_hint(email: str) -> str:
    local, _, domain = normalize_email(email).partition("@")
    if not local or not domain:
        return "***"
    visible = local[:1]
    return f"{visible}{'*' * max(2, min(len(local) - 1, 6))}@{domain}"


def _audit(
    db: Session,
    *,
    tenant_id: str,
    actor_id: str | None,
    action: str,
    invitation_id: str | None,
    outcome: str,
    metadata: dict | None = None,
) -> None:
    db.add(
        AuditEvent(
            tenant_id=tenant_id,
            actor_id=actor_id,
            action=action,
            resource_type="platform_invitation",
            resource_id=invitation_id,
            outcome=outcome,
            metadata_json=metadata or {},
        )
    )


def _find_users_by_normalized_email(db: Session, email: str) -> list[User]:
    normalized = normalize_email(email)
    return list(
        db.scalars(
            select(User)
            .where(func.lower(func.trim(User.email)) == normalized)
            .order_by(User.id)
            .limit(2)
        ).all()
    )


def unique_user_by_email(db: Session, email: str) -> User | None:
    rows = _find_users_by_normalized_email(db, email)
    if len(rows) > 1:
        raise PlatformInvitationError("IDENTITY_EMAIL_AMBIGUOUS")
    return rows[0] if rows else None


def _invitation_from_token(
    db: Session,
    token: str,
    *,
    lock: bool,
    settings: Settings,
) -> PlatformInvitation:
    raw = token.strip()
    invitation_id, sep, proof = raw.partition(".")
    if not sep or not invitation_id or len(proof) < 32:
        raise PlatformInvitationError("PLATFORM_INVITATION_TOKEN_INVALID")
    statement = select(PlatformInvitation).where(PlatformInvitation.id == invitation_id)
    if lock:
        statement = statement.with_for_update()
    invitation = db.scalar(statement)
    if invitation is None:
        raise PlatformInvitationError("PLATFORM_INVITATION_TOKEN_INVALID")
    expected_token = activation_token(invitation.id, settings)
    if not secrets.compare_digest(expected_token, raw):
        raise PlatformInvitationError("PLATFORM_INVITATION_TOKEN_INVALID")
    # The persisted digest is an additional tamper-evident binding; plaintext is
    # never stored.
    if not secrets.compare_digest(invitation.token_hash, token_digest(raw)):
        raise PlatformInvitationError("PLATFORM_INVITATION_TOKEN_INVALID")
    return invitation


def _effective_state(invitation: PlatformInvitation) -> str:
    if invitation.state == PlatformInvitationState.pending.value:
        expires_at = _aware(invitation.expires_at)
        if expires_at is not None and expires_at <= now():
            return PlatformInvitationState.expired.value
    return invitation.state


def public_status(
    db: Session,
    *,
    token: str,
    settings: Settings,
) -> dict:
    require_platform_invitation_enabled(settings)
    invitation = _invitation_from_token(db, token, lock=False, settings=settings)
    return {
        "status": _effective_state(invitation),
        "delivery_status": invitation.delivery_status,
        "expires_at": invitation.expires_at,
        "email_hint": _email_hint(invitation.invited_email),
    }


def _new_outbox(invitation: PlatformInvitation, generation: int) -> PlatformInvitationOutbox:
    return PlatformInvitationOutbox(
        tenant_id=invitation.tenant_id,
        invitation_id=invitation.id,
        generation=generation,
        idempotency_key=f"platform-invite:{invitation.id}:g{generation}",
        status=DELIVERY_PENDING,
    )


def issue_platform_invitation(
    db: Session,
    *,
    principal: Principal,
    email: str,
    role: str,
    settings: Settings,
) -> tuple[PlatformInvitation, PlatformInvitationOutbox]:
    require_platform_invitation_enabled(settings)
    normalized = normalize_email(email)
    normalized_role = role.strip().lower()
    if normalized_role not in allowed_roles(settings):
        raise PlatformInvitationError("PLATFORM_INVITATION_ROLE_NOT_ALLOWED")

    existing_user = unique_user_by_email(db, normalized)
    if existing_user is not None:
        membership = db.scalar(
            select(Membership).where(
                Membership.tenant_id == principal.tenant_id,
                Membership.user_id == existing_user.id,
                Membership.active.is_(True),
            )
        )
        credential = db.scalar(
            select(NativeCredential).where(NativeCredential.user_id == existing_user.id)
        )
        if membership is not None and credential is not None:
            raise PlatformInvitationError("PLATFORM_USER_ALREADY_ACTIVE")

    active = db.scalar(
        select(PlatformInvitation)
        .where(
            PlatformInvitation.tenant_id == principal.tenant_id,
            PlatformInvitation.active_dedupe_key == _active_dedupe_key(
                principal.tenant_id, normalized
            ),
        )
        .with_for_update()
    )
    if active is not None:
        if _effective_state(active) == PlatformInvitationState.expired.value:
            active.state = PlatformInvitationState.expired.value
            active.active_dedupe_key = None
        else:
            raise PlatformInvitationError("PLATFORM_INVITATION_ALREADY_PENDING")

    invitation_id = str(uuid.uuid4())
    token = activation_token(invitation_id, settings)
    invitation = PlatformInvitation(
        id=invitation_id,
        tenant_id=principal.tenant_id,
        invited_email=normalized,
        role=normalized_role,
        token_hash=token_digest(token),
        active_dedupe_key=_active_dedupe_key(principal.tenant_id, normalized),
        state=PlatformInvitationState.pending.value,
        delivery_status=DELIVERY_PENDING,
        delivery_generation=1,
        delivery_attempts=0,
        created_by=principal.user_id,
        issued_at=now(),
        expires_at=now() + timedelta(hours=settings.platform_invitation_ttl_hours),
    )
    outbox = _new_outbox(invitation, 1)
    db.add(invitation)
    db.add(outbox)
    _audit(
        db,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="platform_invitation.created",
        invitation_id=invitation.id,
        outcome="success",
        metadata={
            "role": normalized_role,
            "delivery_status": DELIVERY_PENDING,
            "email_hash": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        },
    )
    db.flush()
    return invitation, outbox


def build_activation_url(invitation: PlatformInvitation, settings: Settings) -> str:
    token = activation_token(invitation.id, settings)
    base = settings.platform_invitation_base_url.strip().rstrip("#")
    # The token lives in the browser fragment. Browsers do not send fragments to
    # HTTP servers/reverse proxies, reducing accidental token exposure in access logs.
    return f"{base}#token={quote(token, safe='')}"


def dispatch_outbox(
    db: Session,
    *,
    outbox_id: str,
    settings: Settings,
    provider: EmailProvider | None = None,
) -> PlatformInvitationOutbox:
    require_platform_invitation_enabled(settings)
    outbox = db.scalar(
        select(PlatformInvitationOutbox)
        .where(PlatformInvitationOutbox.id == outbox_id)
        .with_for_update()
    )
    if outbox is None:
        raise PlatformInvitationError("PLATFORM_INVITATION_OUTBOX_NOT_FOUND")
    invitation = db.scalar(
        select(PlatformInvitation)
        .where(PlatformInvitation.id == outbox.invitation_id)
        .with_for_update()
    )
    if invitation is None:
        raise PlatformInvitationError("PLATFORM_INVITATION_NOT_FOUND")
    if _effective_state(invitation) != PlatformInvitationState.pending.value:
        raise PlatformInvitationError("PLATFORM_INVITATION_NOT_PENDING")

    # If the same durable outbox row was already accepted by the provider, a
    # reconciliation retry is a no-op. Explicit resend creates a new generation.
    if outbox.status == DELIVERY_ACCEPTED_BY_PROVIDER:
        return outbox

    timestamp = now()
    outbox.attempt_count += 1
    outbox.last_attempt_at = timestamp
    outbox.updated_at = timestamp
    invitation.delivery_attempts += 1
    invitation.last_delivery_attempt_at = timestamp

    try:
        selected_provider = provider or build_email_provider(settings)
        result = selected_provider.send_platform_invitation(
            to_email=invitation.invited_email,
            activation_url=build_activation_url(invitation, settings),
            expires_hours=settings.platform_invitation_ttl_hours,
            idempotency_key=outbox.idempotency_key,
        )
    except EmailProviderError as exc:
        result = DeliveryResult(status=DELIVERY_FAILED, error_code=exc.code)
    except Exception:
        # No provider exception detail is stored or returned: this keeps tokens,
        # credentials and provider internals out of logs/audit metadata.
        result = DeliveryResult(status=DELIVERY_FAILED, error_code="EMAIL_PROVIDER_FAILURE")

    if result.status == DELIVERY_ACCEPTED_BY_PROVIDER:
        outbox.status = DELIVERY_ACCEPTED_BY_PROVIDER
        outbox.provider_message_id = result.provider_message_id
        outbox.error_code = None
        invitation.delivery_status = DELIVERY_ACCEPTED_BY_PROVIDER
        invitation.provider_message_id = result.provider_message_id
        invitation.delivery_error_code = None
        outcome = "accepted_by_provider"
    else:
        outbox.status = DELIVERY_FAILED
        outbox.provider_message_id = None
        outbox.error_code = (result.error_code or "EMAIL_PROVIDER_FAILURE")[:120]
        invitation.delivery_status = DELIVERY_FAILED
        invitation.provider_message_id = None
        invitation.delivery_error_code = outbox.error_code
        outcome = "delivery_failed"

    _audit(
        db,
        tenant_id=invitation.tenant_id,
        actor_id=invitation.created_by,
        action="platform_invitation.delivery_attempted",
        invitation_id=invitation.id,
        outcome=outcome,
        metadata={
            "delivery_status": outbox.status,
            "generation": outbox.generation,
            "attempt_count": outbox.attempt_count,
            "error_code": outbox.error_code,
            "provider_message_id": outbox.provider_message_id,
        },
    )
    db.flush()
    return outbox


def prepare_resend(
    db: Session,
    *,
    invitation_id: str,
    tenant_id: str,
    actor_id: str,
    settings: Settings,
) -> PlatformInvitationOutbox:
    require_platform_invitation_enabled(settings)
    invitation = db.scalar(
        select(PlatformInvitation)
        .where(
            PlatformInvitation.id == invitation_id,
            PlatformInvitation.tenant_id == tenant_id,
        )
        .with_for_update()
    )
    if invitation is None:
        raise PlatformInvitationError("PLATFORM_INVITATION_NOT_FOUND")
    if _effective_state(invitation) != PlatformInvitationState.pending.value:
        raise PlatformInvitationError("PLATFORM_INVITATION_NOT_PENDING")

    latest = db.scalar(
        select(PlatformInvitationOutbox)
        .where(PlatformInvitationOutbox.invitation_id == invitation.id)
        .order_by(PlatformInvitationOutbox.generation.desc())
        .limit(1)
        .with_for_update()
    )
    if latest is not None and latest.status in {DELIVERY_PENDING, DELIVERY_FAILED}:
        # Recovery/reconciliation path: same durable row and same provider
        # idempotency key close the accepted-provider/persistence crash window.
        invitation.delivery_status = DELIVERY_PENDING
        invitation.delivery_error_code = None
        latest.status = DELIVERY_PENDING
        latest.error_code = None
        outbox = latest
        mode = "reconcile"
    else:
        generation = int(invitation.delivery_generation or 1) + 1
        invitation.delivery_generation = generation
        invitation.delivery_status = DELIVERY_PENDING
        invitation.delivery_error_code = None
        invitation.provider_message_id = None
        outbox = _new_outbox(invitation, generation)
        db.add(outbox)
        mode = "explicit_resend"

    _audit(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        action="platform_invitation.resend_prepared",
        invitation_id=invitation.id,
        outcome="success",
        metadata={"mode": mode, "generation": outbox.generation},
    )
    db.flush()
    return outbox


def revoke_invitation(
    db: Session,
    *,
    invitation_id: str,
    tenant_id: str,
    actor_id: str,
) -> PlatformInvitation:
    invitation = db.scalar(
        select(PlatformInvitation)
        .where(
            PlatformInvitation.id == invitation_id,
            PlatformInvitation.tenant_id == tenant_id,
        )
        .with_for_update()
    )
    if invitation is None:
        raise PlatformInvitationError("PLATFORM_INVITATION_NOT_FOUND")
    if _effective_state(invitation) != PlatformInvitationState.pending.value:
        raise PlatformInvitationError("PLATFORM_INVITATION_NOT_PENDING")
    invitation.state = PlatformInvitationState.revoked.value
    invitation.revoked_at = now()
    invitation.active_dedupe_key = None
    _audit(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        action="platform_invitation.revoked",
        invitation_id=invitation.id,
        outcome="success",
    )
    db.flush()
    return invitation


def accept_platform_invitation(
    db: Session,
    *,
    token: str,
    display_name: str,
    password: str,
    password_confirm: str,
    settings: Settings,
) -> InvitationAcceptance:
    require_platform_invitation_enabled(settings)
    if password != password_confirm:
        raise PlatformInvitationError("PASSWORD_CONFIRMATION_MISMATCH")
    if len(password) < settings.native_password_min_length:
        raise PlatformInvitationError("PASSWORD_TOO_SHORT")

    invitation = _invitation_from_token(db, token, lock=True, settings=settings)
    state = _effective_state(invitation)
    if state == PlatformInvitationState.expired.value:
        raise PlatformInvitationError("PLATFORM_INVITATION_EXPIRED")
    if state == PlatformInvitationState.revoked.value:
        raise PlatformInvitationError("PLATFORM_INVITATION_REVOKED")
    if state == PlatformInvitationState.accepted.value:
        raise PlatformInvitationError("PLATFORM_INVITATION_ALREADY_ACCEPTED")
    if state != PlatformInvitationState.pending.value:
        raise PlatformInvitationError("PLATFORM_INVITATION_NOT_PENDING")

    user = unique_user_by_email(db, invitation.invited_email)
    if user is None:
        user = User(
            id=str(uuid.uuid4()),
            external_subject=f"native:{invitation.invited_email}",
            email=invitation.invited_email,
            display_name=display_name.strip(),
            email_verified_at=now(),
        )
        db.add(user)
        db.flush()
        create_or_update_credential(
            db,
            user_id=user.id,
            password=password,
            settings=settings,
        )
    else:
        credential = db.scalar(
            select(NativeCredential).where(NativeCredential.user_id == user.id)
        )
        if credential is not None:
            if not verify_password(password, credential.password_hash, settings):
                raise PlatformInvitationError("EXISTING_ACCOUNT_PASSWORD_INVALID")
        else:
            if not user.external_subject.startswith("native:"):
                raise PlatformInvitationError("EXTERNAL_IDENTITY_LOGIN_REQUIRED")
            create_or_update_credential(
                db,
                user_id=user.id,
                password=password,
                settings=settings,
            )
        user.email = normalize_email(user.email)
        user.display_name = display_name.strip()
        if user.email_verified_at is None:
            user.email_verified_at = now()

    membership = db.scalar(
        select(Membership)
        .where(
            Membership.tenant_id == invitation.tenant_id,
            Membership.user_id == user.id,
        )
        .with_for_update()
    )
    if membership is None:
        membership = Membership(
            tenant_id=invitation.tenant_id,
            user_id=user.id,
            role=invitation.role,
            active=True,
        )
        db.add(membership)
    else:
        membership.role = invitation.role
        membership.active = True

    invitation.state = PlatformInvitationState.accepted.value
    invitation.accepted_at = now()
    invitation.accepted_by = user.id
    invitation.active_dedupe_key = None
    _audit(
        db,
        tenant_id=invitation.tenant_id,
        actor_id=user.id,
        action="platform_invitation.accepted",
        invitation_id=invitation.id,
        outcome="success",
        metadata={"role": invitation.role},
    )
    db.flush()
    return InvitationAcceptance(
        user_id=user.id,
        tenant_id=invitation.tenant_id,
        role=invitation.role,
    )


def invitation_payload(invitation: PlatformInvitation) -> dict:
    return {
        "invitation_id": invitation.id,
        "invited_email": invitation.invited_email,
        "role": invitation.role,
        "state": _effective_state(invitation),
        "delivery_status": invitation.delivery_status,
        "delivery_attempts": invitation.delivery_attempts,
        "delivery_generation": invitation.delivery_generation,
        "expires_at": invitation.expires_at,
        "accepted_at": invitation.accepted_at,
        "revoked_at": invitation.revoked_at,
        "provider_message_id": invitation.provider_message_id,
        "delivery_error_code": invitation.delivery_error_code,
    }


def list_invitations(
    db: Session,
    *,
    tenant_id: str,
) -> list[dict]:
    rows = db.scalars(
        select(PlatformInvitation)
        .where(PlatformInvitation.tenant_id == tenant_id)
        .order_by(PlatformInvitation.issued_at.desc(), PlatformInvitation.id)
    ).all()
    return [invitation_payload(row) for row in rows]


def update_membership(
    db: Session,
    *,
    tenant_id: str,
    actor_id: str,
    target_user_id: str,
    role: str | None,
    active: bool | None,
    settings: Settings,
) -> Membership:
    membership = db.scalar(
        select(Membership)
        .where(
            Membership.tenant_id == tenant_id,
            Membership.user_id == target_user_id,
        )
        .with_for_update()
    )
    if membership is None:
        raise PlatformInvitationError("ADMIN_USER_MEMBERSHIP_NOT_FOUND")
    if target_user_id == actor_id and (
        (active is False) or (role is not None and role != membership.role)
    ):
        raise PlatformInvitationError("ADMIN_CANNOT_MUTATE_OWN_MEMBERSHIP")
    if role is not None:
        normalized_role = role.strip().lower()
        if normalized_role not in allowed_roles(settings):
            raise PlatformInvitationError("PLATFORM_INVITATION_ROLE_NOT_ALLOWED")
        membership.role = normalized_role
    if active is not None:
        membership.active = active
    _audit(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        action="platform_membership.updated",
        invitation_id=None,
        outcome="success",
        metadata={
            "target_user_id": target_user_id,
            "role": membership.role,
            "active": membership.active,
        },
    )
    db.flush()
    return membership


def revoke_user_sessions(
    db: Session,
    *,
    tenant_id: str,
    actor_id: str,
    target_user_id: str,
    reason: str,
) -> int:
    membership = db.scalar(
        select(Membership).where(
            Membership.tenant_id == tenant_id,
            Membership.user_id == target_user_id,
        )
    )
    if membership is None:
        raise PlatformInvitationError("ADMIN_USER_MEMBERSHIP_NOT_FOUND")
    sessions = db.scalars(
        select(NativeSession)
        .where(
            NativeSession.tenant_id == tenant_id,
            NativeSession.user_id == target_user_id,
            NativeSession.revoked_at.is_(None),
        )
        .with_for_update()
    ).all()
    timestamp = now()
    for row in sessions:
        row.revoked_at = timestamp
    _audit(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        action="platform_sessions.revoked_by_admin",
        invitation_id=None,
        outcome="success",
        metadata={
            "target_user_id": target_user_id,
            "count": len(sessions),
            "reason": reason[:120],
        },
    )
    db.flush()
    return len(sessions)
