import hashlib, secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from fastapi import HTTPException
from ..models import Thread, ThreadParticipant, ThreadInvitation, User, InviteStatus
from ..schemas import InvitationCreate
from ..auth import Principal
from ..config import Settings

def _hash(token: str, secret: str) -> str:
    return hashlib.sha256((secret + token).encode()).hexdigest()

def create_invitation(db: Session, thread: Thread, payload: InvitationCreate, principal: Principal, settings: Settings):
    participant = db.scalar(select(ThreadParticipant).where(
        ThreadParticipant.thread_id == thread.id,
        ThreadParticipant.user_id == principal.user_id,
        ThreadParticipant.active.is_(True),
    ))
    if not participant or participant.thread_role not in {"owner","moderator"}:
        raise HTTPException(403, "THREAD_INVITE_PERMISSION_REQUIRED")
    token = secrets.token_urlsafe(48)
    invitation = ThreadInvitation(
        tenant_id=principal.tenant_id, thread_id=thread.id,
        invited_email=str(payload.email).lower(), token_hash=_hash(token, settings.invitation_secret),
        token_prefix=token[:8], thread_role=payload.role, history_access=payload.history_access,
        can_view_attachments=payload.can_view_attachments,
        can_download_artifacts=payload.can_download_artifacts,
        can_upload_files=payload.can_upload_files,
        can_generate_artifacts=payload.can_generate_artifacts,
        created_by=principal.user_id,
        expires_at=datetime.now(timezone.utc)+timedelta(hours=settings.invitation_ttl_hours),
    )
    db.add(invitation); db.flush()
    return invitation, token

def accept_invitation(db: Session, token: str, principal: Principal, settings: Settings):
    digest = _hash(token, settings.invitation_secret)
    invitation = db.scalar(select(ThreadInvitation).where(ThreadInvitation.token_hash == digest))
    if not invitation:
        raise HTTPException(404, "INVITATION_NOT_FOUND")
    now = datetime.now(timezone.utc)
    if invitation.status != InviteStatus.pending.value:
        raise HTTPException(409, "INVITATION_NOT_AVAILABLE")
    expires = invitation.expires_at
    if expires.tzinfo is None: expires = expires.replace(tzinfo=timezone.utc)
    if expires <= now:
        invitation.status = InviteStatus.expired.value
        raise HTTPException(410, "INVITATION_EXPIRED")
    if not principal.email or principal.email.lower() != invitation.invited_email:
        raise HTTPException(403, "INVITATION_EMAIL_MISMATCH")
    if principal.tenant_id != invitation.tenant_id:
        raise HTTPException(403, "INVITATION_TENANT_MISMATCH")
    existing = db.scalar(select(ThreadParticipant).where(
        ThreadParticipant.thread_id == invitation.thread_id,
        ThreadParticipant.user_id == principal.user_id,
    ))
    if not existing:
        db.add(ThreadParticipant(
            tenant_id=invitation.tenant_id, thread_id=invitation.thread_id, user_id=principal.user_id,
            membership_type="external_guest", thread_role=invitation.thread_role,
            history_access=invitation.history_access,
            can_view_attachments=invitation.can_view_attachments,
            can_download_artifacts=invitation.can_download_artifacts,
            can_upload_files=invitation.can_upload_files,
            can_generate_artifacts=invitation.can_generate_artifacts,
        ))
    invitation.status=InviteStatus.accepted.value
    invitation.accepted_at=now
    invitation.accepted_by=principal.user_id
    return invitation
