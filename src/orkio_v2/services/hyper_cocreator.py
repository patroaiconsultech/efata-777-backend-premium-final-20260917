from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..auth import Principal
from ..config import Settings
from ..models import (
    AccessGrantRedemption,
    Membership,
    Tenant,
    User,
    UserExperienceProfile,
)


HYPER_COCREATOR_AGENT_ID = "orkio"
HYPER_COCREATOR_DEFAULT_NAME = "Co-Criador"


class AccessGateError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class AccessGrant:
    token: str
    expires_at: int


def normalize_email(value: str | None) -> str:
    return (value or "").strip().lower()


def admin_email_allowlist(settings: Settings) -> frozenset[str]:
    return frozenset(
        normalize_email(item)
        for item in settings.admin_email_allowlist.split(",")
        if normalize_email(item)
    )


def is_allowlisted_admin(principal: Principal, settings: Settings) -> bool:
    return bool(
        {"admin", "superadmin", "platform_owner"}.intersection(principal.roles)
        and normalize_email(principal.email) in admin_email_allowlist(settings)
    )


def require_allowlisted_admin_principal(
    principal: Principal,
    settings: Settings,
) -> Principal:
    if not is_allowlisted_admin(principal, settings):
        raise HTTPException(403, "ADMIN_ALLOWLIST_REQUIRED")
    return principal


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _code_hashes(settings: Settings) -> tuple[str, ...]:
    return tuple(
        item.strip().lower()
        for item in settings.access_gate_code_hashes.split(",")
        if item.strip()
    )


def validate_access_code(settings: Settings, code: str) -> AccessGrant:
    if not settings.access_gate_enabled:
        raise AccessGateError("ACCESS_GATE_DISABLED")
    if (
        len(settings.access_gate_signing_secret) < 32
        or not _code_hashes(settings)
        or not settings.access_gate_tenant_id.strip()
    ):
        raise AccessGateError("ACCESS_GATE_NOT_CONFIGURED")
    digest = hmac.new(
        settings.access_gate_signing_secret.encode("utf-8"),
        code.strip().lower().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not any(hmac.compare_digest(digest, expected) for expected in _code_hashes(settings)):
        raise AccessGateError("ACCESS_CODE_INVALID")

    now = int(time.time())
    expires_at = now + int(settings.access_gate_ttl_seconds)
    payload = {
        "v": 1,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": expires_at,
        "tenant_id": settings.access_gate_tenant_id.strip(),
        "code_fp": digest[:12],
    }
    encoded = _b64url(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signature = _b64url(
        hmac.new(
            settings.access_gate_signing_secret.encode("utf-8"),
            encoded.encode("ascii"),
            hashlib.sha256,
        ).digest()
    )
    return AccessGrant(token=f"{encoded}.{signature}", expires_at=expires_at)


def verify_access_grant(settings: Settings, token: str) -> dict[str, object]:
    if not settings.access_gate_enabled:
        raise AccessGateError("ACCESS_GATE_DISABLED")
    try:
        encoded, signature = token.split(".", 1)
    except ValueError as exc:
        raise AccessGateError("ACCESS_GRANT_INVALID") from exc

    expected = _b64url(
        hmac.new(
            settings.access_gate_signing_secret.encode("utf-8"),
            encoded.encode("ascii"),
            hashlib.sha256,
        ).digest()
    )
    if not hmac.compare_digest(signature, expected):
        raise AccessGateError("ACCESS_GRANT_INVALID")

    try:
        payload = json.loads(_unb64url(encoded))
    except Exception as exc:
        raise AccessGateError("ACCESS_GRANT_INVALID") from exc

    if payload.get("v") != 1:
        raise AccessGateError("ACCESS_GRANT_INVALID")
    if int(payload.get("exp") or 0) < int(time.time()):
        raise AccessGateError("ACCESS_GRANT_EXPIRED")
    jti = str(payload.get("jti") or "")
    if len(jti) < 16:
        raise AccessGateError("ACCESS_GRANT_INVALID")

    configured_tenant = settings.access_gate_tenant_id.strip()
    token_tenant = str(payload.get("tenant_id") or "")
    if configured_tenant and token_tenant != configured_tenant:
        raise AccessGateError("ACCESS_GRANT_TENANT_MISMATCH")
    return payload


def _safe_cocreator_name(value: str) -> str:
    cleaned = " ".join(value.strip().split())
    if len(cleaned) < 2 or len(cleaned) > 64:
        raise AccessGateError("COCREATOR_NAME_INVALID")
    return cleaned


def _safe_goal(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(value.strip().split())
    if not cleaned:
        return None
    return cleaned[:240]


def complete_onboarding(
    db: Session,
    *,
    settings: Settings,
    principal: Principal,
    grant_token: str,
    co_creator_name: str,
    onboarding_goal: str | None,
) -> UserExperienceProfile:
    payload = verify_access_grant(settings, grant_token)

    expected_tenant = settings.access_gate_tenant_id.strip()
    if expected_tenant and principal.tenant_id != expected_tenant:
        raise AccessGateError("ACCESS_TENANT_NOT_ALLOWED")

    tenant = db.get(Tenant, principal.tenant_id)
    if tenant is None:
        raise AccessGateError("ACCESS_TENANT_NOT_PROVISIONED")

    email = normalize_email(principal.email)
    subject = (principal.external_subject or "").strip()
    if not email or not subject:
        raise AccessGateError("ACCESS_IDENTITY_CLAIMS_INCOMPLETE")

    jti = str(payload["jti"])
    existing_redemption = db.scalar(
        select(AccessGrantRedemption).where(AccessGrantRedemption.grant_jti == jti)
    )
    if existing_redemption is not None and existing_redemption.user_id != principal.user_id:
        raise AccessGateError("ACCESS_GRANT_ALREADY_USED")

    user = db.get(User, principal.user_id)
    if user is None:
        existing_subject = db.scalar(
            select(User).where(User.external_subject == subject)
        )
        if existing_subject is not None and existing_subject.id != principal.user_id:
            raise AccessGateError("ACCESS_IDENTITY_CONFLICT")
        user = User(
            id=principal.user_id,
            external_subject=subject,
            email=email,
            display_name=email.split("@", 1)[0][:200],
        )
        db.add(user)
        db.flush()
    else:
        if user.external_subject != subject:
            raise AccessGateError("ACCESS_IDENTITY_CONFLICT")
        user.email = email

    membership = db.scalar(
        select(Membership).where(
            Membership.tenant_id == principal.tenant_id,
            Membership.user_id == principal.user_id,
        )
    )
    if membership is None:
        membership = Membership(
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            role="member",
            active=True,
        )
        db.add(membership)
    elif not membership.active:
        membership.active = True

    profile = db.scalar(
        select(UserExperienceProfile).where(
            UserExperienceProfile.tenant_id == principal.tenant_id,
            UserExperienceProfile.user_id == principal.user_id,
        )
    )
    if profile is None:
        profile = UserExperienceProfile(
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
        )
        db.add(profile)
    profile.co_creator_name = _safe_cocreator_name(co_creator_name)
    profile.onboarding_goal = _safe_goal(onboarding_goal)

    if existing_redemption is None:
        db.add(
            AccessGrantRedemption(
                grant_jti=jti,
                tenant_id=principal.tenant_id,
                user_id=principal.user_id,
            )
        )

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise AccessGateError("ACCESS_ONBOARDING_CONFLICT") from exc
    db.refresh(profile)
    return profile


def profile_for(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
) -> UserExperienceProfile | None:
    return db.scalar(
        select(UserExperienceProfile).where(
            UserExperienceProfile.tenant_id == tenant_id,
            UserExperienceProfile.user_id == user_id,
        )
    )



def update_profile_name(
    db: Session,
    *,
    principal: Principal,
    co_creator_name: str,
) -> UserExperienceProfile:
    """Rename the current user's visible Co-Creator without changing canonical ownership."""
    profile = profile_for(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
    )
    if profile is None:
        profile = UserExperienceProfile(
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            co_creator_name=_safe_cocreator_name(co_creator_name),
        )
        db.add(profile)
    else:
        profile.co_creator_name = _safe_cocreator_name(co_creator_name)
    db.commit()
    db.refresh(profile)
    return profile


def hyper_cocreator_system_message(
    *,
    co_creator_name: str | None,
    onboarding_goal: str | None,
) -> dict[str, str]:
    visible_name = (co_creator_name or HYPER_COCREATOR_DEFAULT_NAME).strip()
    goal = (onboarding_goal or "").strip()
    goal_line = (
        f"\nUSER ONBOARDING GOAL: {goal}" if goal else ""
    )
    return {
        "role": "system",
        "content": (
            "HYPER CO-CREATOR MODE — authoritative product behavior for the user-facing "
            "single-agent experience.\n"
            f"Visible co-creator name for this user: {visible_name}.\n"
            "The canonical runtime owner remains agent_id=orkio. The personalized name is "
            "presentation context only and must never alter ownership, tenant, authorization "
            "or persistence identity. It must not replace the resolved agent's canonical name, "
            "role, authorship or self-identification.\n"
            "Act as an exceptionally creative cross-functional CEO and business co-creator. "
            "Work across strategy, business models, finance, marketing, sales, operations, "
            "product, technology, AI, people, partnerships, innovation and execution. "
            "Generate multiple credible options, challenge assumptions, quantify when useful, "
            "turn ambiguous ideas into experiments and concrete next steps, and use authorized "
            "document/artifact/voice/realtime capabilities when the runtime actually provides them.\n"
            "PLATFORM EVOLUTION BOUNDARY: never create, edit, commit, merge, deploy, migrate, "
            "reconfigure or self-evolve the Platform from this user-facing co-creator surface. "
            "Never invoke GitHub/platform-evolution capabilities from this surface. If asked to "
            "modify the Platform, explain that platform evolution is restricted to the governed "
            "administrator/evolution plane.\n"
            "Never claim a tool was used unless a trusted runtime tool result is present."
            f"{goal_line}"
        ),
    }
