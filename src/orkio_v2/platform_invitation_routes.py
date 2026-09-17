from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import Principal
from .config import Settings, get_settings
from .database import get_db
from .schemas import (
    AdminMembershipUpdate,
    AdminSessionRevokeRequest,
    PlatformInvitationAcceptOut,
    PlatformInvitationAcceptRequest,
    PlatformInvitationCreate,
    PlatformInvitationOut,
    PlatformInvitationStatusOut,
    PlatformInvitationTokenRequest,
)
from .services.hyper_cocreator import require_allowlisted_admin_principal
from .services.identity import require_provisioned_superadmin
from .services.platform_invitations import (
    PlatformInvitationError,
    accept_platform_invitation,
    dispatch_outbox,
    invitation_payload,
    issue_platform_invitation,
    list_invitations,
    prepare_resend,
    public_status,
    revoke_invitation,
    revoke_user_sessions,
    update_membership,
)


router = APIRouter(prefix="/api/v2")


def _admin(
    principal: Principal,
    settings: Settings,
) -> Principal:
    return require_allowlisted_admin_principal(principal, settings)


def _raise_platform_error(exc: PlatformInvitationError) -> None:
    code = exc.code
    if code in {
        "PLATFORM_INVITATION_DISABLED",
        "PLATFORM_INVITATION_NOT_CONFIGURED",
    }:
        status = 503
    elif code in {
        "PLATFORM_INVITATION_TOKEN_INVALID",
        "PLATFORM_INVITATION_NOT_FOUND",
        "PLATFORM_INVITATION_OUTBOX_NOT_FOUND",
        "ADMIN_USER_MEMBERSHIP_NOT_FOUND",
    }:
        status = 404
    elif code in {
        "PASSWORD_CONFIRMATION_MISMATCH",
        "PASSWORD_TOO_SHORT",
        "PLATFORM_INVITATION_ROLE_NOT_ALLOWED",
    }:
        status = 422
    elif code in {"EXISTING_ACCOUNT_PASSWORD_INVALID"}:
        status = 401
    else:
        status = 409
    raise HTTPException(status, code) from exc


def _commit_or_fail(db: Session, code: str) -> None:
    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(503, code) from exc


@router.get("/admin/user-invitations", response_model=list[PlatformInvitationOut])
def admin_list_user_invitations(
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _admin(p, settings)
    return list_invitations(db, tenant_id=p.tenant_id)


@router.post("/admin/user-invitations", response_model=PlatformInvitationOut)
def admin_create_user_invitation(
    body: PlatformInvitationCreate,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _admin(p, settings)
    try:
        invitation, outbox = issue_platform_invitation(
            db,
            principal=p,
            email=str(body.email),
            role=body.role,
            settings=settings,
        )
    except PlatformInvitationError as exc:
        db.rollback()
        _raise_platform_error(exc)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "PLATFORM_INVITATION_IDENTITY_CONFLICT") from exc

    # Transaction 1 makes the invitation and outbox durable before the external
    # side effect. A crash from this point forward is recoverable.
    _commit_or_fail(db, "PLATFORM_INVITATION_PERSIST_FAILED")

    try:
        dispatch_outbox(
            db,
            outbox_id=outbox.id,
            settings=settings,
        )
    except PlatformInvitationError as exc:
        db.rollback()
        _raise_platform_error(exc)

    # If the provider accepted but this commit fails, the prior durable outbox
    # remains PENDING. Resend/reconciliation reuses the same idempotency key.
    _commit_or_fail(db, "PLATFORM_INVITATION_DELIVERY_STATE_PERSIST_FAILED")
    db.refresh(invitation)
    return invitation_payload(invitation)


@router.post(
    "/admin/user-invitations/{invitation_id}/resend",
    response_model=PlatformInvitationOut,
)
def admin_resend_user_invitation(
    invitation_id: str,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _admin(p, settings)
    try:
        outbox = prepare_resend(
            db,
            invitation_id=invitation_id,
            tenant_id=p.tenant_id,
            actor_id=p.user_id,
            settings=settings,
        )
    except PlatformInvitationError as exc:
        db.rollback()
        _raise_platform_error(exc)

    _commit_or_fail(db, "PLATFORM_INVITATION_RESEND_PREPARE_PERSIST_FAILED")
    try:
        dispatch_outbox(db, outbox_id=outbox.id, settings=settings)
    except PlatformInvitationError as exc:
        db.rollback()
        _raise_platform_error(exc)
    _commit_or_fail(db, "PLATFORM_INVITATION_DELIVERY_STATE_PERSIST_FAILED")

    from .models import PlatformInvitation

    invitation = db.get(PlatformInvitation, invitation_id)
    if invitation is None or invitation.tenant_id != p.tenant_id:
        raise HTTPException(404, "PLATFORM_INVITATION_NOT_FOUND")
    return invitation_payload(invitation)


@router.post(
    "/admin/user-invitations/{invitation_id}/revoke",
    response_model=PlatformInvitationOut,
)
def admin_revoke_user_invitation(
    invitation_id: str,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _admin(p, settings)
    try:
        invitation = revoke_invitation(
            db,
            invitation_id=invitation_id,
            tenant_id=p.tenant_id,
            actor_id=p.user_id,
        )
    except PlatformInvitationError as exc:
        db.rollback()
        _raise_platform_error(exc)
    _commit_or_fail(db, "PLATFORM_INVITATION_REVOKE_PERSIST_FAILED")
    return invitation_payload(invitation)


@router.post("/platform-invitations/status", response_model=PlatformInvitationStatusOut)
def platform_invitation_status(
    body: PlatformInvitationTokenRequest,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    try:
        return public_status(db, token=body.token, settings=settings)
    except PlatformInvitationError as exc:
        _raise_platform_error(exc)


@router.post("/platform-invitations/accept", response_model=PlatformInvitationAcceptOut)
def platform_invitation_accept(
    body: PlatformInvitationAcceptRequest,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    try:
        accepted = accept_platform_invitation(
            db,
            token=body.token,
            display_name=body.display_name,
            password=body.password,
            password_confirm=body.password_confirm,
            settings=settings,
        )
        db.commit()
    except PlatformInvitationError as exc:
        db.rollback()
        _raise_platform_error(exc)
    except IntegrityError as exc:
        db.rollback()
        # Includes the normalized-email unique invariant and membership
        # uniqueness. Never auto-merge identities.
        raise HTTPException(409, "PLATFORM_IDENTITY_CONFLICT") from exc
    return {
        "status": "ACCEPTED_LOGIN_REQUIRED",
        "tenant_id": accepted.tenant_id,
        "role": accepted.role,
    }


@router.patch("/admin/users/{user_id}/membership")
def admin_update_user_membership(
    user_id: str,
    body: AdminMembershipUpdate,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _admin(p, settings)
    try:
        membership = update_membership(
            db,
            tenant_id=p.tenant_id,
            actor_id=p.user_id,
            target_user_id=user_id,
            role=body.role,
            active=body.active,
            settings=settings,
        )
    except PlatformInvitationError as exc:
        db.rollback()
        _raise_platform_error(exc)
    _commit_or_fail(db, "ADMIN_MEMBERSHIP_UPDATE_PERSIST_FAILED")
    return {
        "user_id": user_id,
        "tenant_id": p.tenant_id,
        "role": membership.role,
        "active": membership.active,
    }


@router.post("/admin/users/{user_id}/sessions/revoke")
def admin_revoke_user_sessions(
    user_id: str,
    body: AdminSessionRevokeRequest,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _admin(p, settings)
    try:
        count = revoke_user_sessions(
            db,
            tenant_id=p.tenant_id,
            actor_id=p.user_id,
            target_user_id=user_id,
            reason=body.reason,
        )
    except PlatformInvitationError as exc:
        db.rollback()
        _raise_platform_error(exc)
    _commit_or_fail(db, "ADMIN_SESSION_REVOCATION_PERSIST_FAILED")
    return {"user_id": user_id, "revoked_sessions": count}
