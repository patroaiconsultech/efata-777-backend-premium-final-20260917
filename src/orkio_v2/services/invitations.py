from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth import Principal
from ..config import Settings
from ..models import InviteStatus, Thread, ThreadInvitation, ThreadParticipant, User
from ..schemas import InvitationCreate
from .thread_access_policy import ThreadAccessPolicyError, require_thread_access


INVITE_ALLOWED_ROLES = {"owner", "moderator"}


def _hash(token: str, secret: str) -> str:
    return hashlib.sha256((secret + token).encode()).hexdigest()


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _normalized_email(value: str) -> str:
    return value.strip().lower()


def _active_user_for_email(
    db: Session,
    *,
    tenant_id: str,
    thread_id: str,
    email: str,
) -> ThreadParticipant | None:
    user = db.scalar(
        select(User).where(func.lower(func.trim(User.email)) == email)
    )
    if user is None:
        return None
    return db.scalar(
        select(ThreadParticipant).where(
            ThreadParticipant.tenant_id == tenant_id,
            ThreadParticipant.thread_id == thread_id,
            ThreadParticipant.user_id == user.id,
            ThreadParticipant.active.is_(True),
        )
    )


def create_invitation(
    db: Session,
    thread: Thread,
    payload: InvitationCreate,
    principal: Principal,
    settings: Settings,
):
    try:
        decision = require_thread_access(
            db,
            thread_id=thread.id,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            require_write=True,
        )
    except ThreadAccessPolicyError as exc:
        raise HTTPException(exc.status_code, exc.code) from exc
    if decision.participant.thread_role not in INVITE_ALLOWED_ROLES:
        raise HTTPException(403, "THREAD_INVITE_PERMISSION_REQUIRED")

    email = _normalized_email(str(payload.email))
    now = datetime.now(timezone.utc)

    if _active_user_for_email(
        db,
        tenant_id=principal.tenant_id,
        thread_id=thread.id,
        email=email,
    ) is not None:
        raise HTTPException(409, "THREAD_PARTICIPANT_ALREADY_ACTIVE")

    pending = db.scalars(
        select(ThreadInvitation).where(
            ThreadInvitation.tenant_id == principal.tenant_id,
            ThreadInvitation.thread_id == thread.id,
            ThreadInvitation.invited_email == email,
            ThreadInvitation.status == InviteStatus.pending.value,
        )
    ).all()
    if any(_aware(item.expires_at) > now for item in pending):
        raise HTTPException(409, "INVITATION_ALREADY_PENDING")

    token = secrets.token_urlsafe(48)
    invitation = ThreadInvitation(
        tenant_id=principal.tenant_id,
        thread_id=thread.id,
        invited_email=email,
        token_hash=_hash(token, settings.invitation_secret),
        token_prefix=token[:8],
        thread_role=payload.role,
        history_access=payload.history_access,
        can_view_attachments=payload.can_view_attachments,
        can_download_artifacts=payload.can_download_artifacts,
        can_upload_files=payload.can_upload_files,
        can_generate_artifacts=payload.can_generate_artifacts,
        created_by=principal.user_id,
        expires_at=now + timedelta(hours=settings.invitation_ttl_hours),
    )
    db.add(invitation)
    db.flush()
    return invitation, token


def accept_invitation(
    db: Session,
    token: str,
    principal: Principal,
    settings: Settings,
):
    digest = _hash(token, settings.invitation_secret)
    invitation = db.scalar(
        select(ThreadInvitation)
        .where(ThreadInvitation.token_hash == digest)
        .with_for_update()
    )
    if not invitation:
        raise HTTPException(404, "INVITATION_NOT_FOUND")

    now = datetime.now(timezone.utc)
    if invitation.status != InviteStatus.pending.value:
        raise HTTPException(409, "INVITATION_NOT_AVAILABLE")
    if _aware(invitation.expires_at) <= now:
        invitation.status = InviteStatus.expired.value
        raise HTTPException(410, "INVITATION_EXPIRED")

    user = db.get(User, principal.user_id)
    stored_email = _normalized_email(user.email) if user is not None else ""
    if not stored_email or stored_email != invitation.invited_email:
        raise HTTPException(403, "INVITATION_EMAIL_MISMATCH")
    if principal.tenant_id != invitation.tenant_id:
        raise HTTPException(403, "INVITATION_TENANT_MISMATCH")

    existing = db.scalar(
        select(ThreadParticipant)
        .where(
            ThreadParticipant.tenant_id == invitation.tenant_id,
            ThreadParticipant.thread_id == invitation.thread_id,
            ThreadParticipant.user_id == principal.user_id,
        )
        .with_for_update()
    )
    if existing is not None and existing.active:
        raise HTTPException(409, "THREAD_PARTICIPANT_ALREADY_ACTIVE")

    if existing is None:
        existing = ThreadParticipant(
            tenant_id=invitation.tenant_id,
            thread_id=invitation.thread_id,
            user_id=principal.user_id,
            membership_type="external_guest",
        )
        db.add(existing)

    # A fresh invite is the only path that can reactivate a revoked participant.
    # Reset joined_at so from_join never recovers history from the previous grant.
    existing.membership_type = "external_guest"
    existing.thread_role = invitation.thread_role
    existing.history_access = invitation.history_access
    existing.can_view_attachments = invitation.can_view_attachments
    existing.can_download_artifacts = invitation.can_download_artifacts
    existing.can_upload_files = invitation.can_upload_files
    existing.can_generate_artifacts = invitation.can_generate_artifacts
    existing.active = True
    existing.joined_at = now

    invitation.status = InviteStatus.accepted.value
    invitation.accepted_at = now
    invitation.accepted_by = principal.user_id

    # Any older pending grant for the same identity/resource becomes stale.
    siblings = db.scalars(
        select(ThreadInvitation).where(
            ThreadInvitation.tenant_id == invitation.tenant_id,
            ThreadInvitation.thread_id == invitation.thread_id,
            ThreadInvitation.invited_email == invitation.invited_email,
            ThreadInvitation.status == InviteStatus.pending.value,
            ThreadInvitation.id != invitation.id,
        )
    ).all()
    for sibling in siblings:
        sibling.status = InviteStatus.revoked.value

    return invitation


def revoke_participant(
    db: Session,
    *,
    thread_id: str,
    target_user_id: str,
    principal: Principal,
) -> ThreadParticipant:
    try:
        actor = require_thread_access(
            db,
            thread_id=thread_id,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            require_write=True,
        ).participant
    except ThreadAccessPolicyError as exc:
        raise HTTPException(exc.status_code, exc.code) from exc

    if actor.thread_role not in INVITE_ALLOWED_ROLES:
        raise HTTPException(403, "THREAD_REVOKE_PERMISSION_REQUIRED")

    target = db.scalar(
        select(ThreadParticipant)
        .where(
            ThreadParticipant.tenant_id == principal.tenant_id,
            ThreadParticipant.thread_id == thread_id,
            ThreadParticipant.user_id == target_user_id,
            ThreadParticipant.active.is_(True),
        )
        .with_for_update()
    )
    if target is None:
        raise HTTPException(404, "THREAD_PARTICIPANT_NOT_FOUND")
    if target.thread_role == "owner":
        raise HTTPException(409, "THREAD_OWNER_CANNOT_BE_REVOKED")

    target.active = False

    user = db.get(User, target.user_id)
    if user is not None:
        email = _normalized_email(user.email)
        stale = db.scalars(
            select(ThreadInvitation).where(
                ThreadInvitation.tenant_id == principal.tenant_id,
                ThreadInvitation.thread_id == thread_id,
                ThreadInvitation.invited_email == email,
                ThreadInvitation.status == InviteStatus.pending.value,
            )
        ).all()
        for invitation in stale:
            invitation.status = InviteStatus.revoked.value

    return target
