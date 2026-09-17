from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import timedelta
from datetime import timezone
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import (
    AccessGrantRedemption,
    AuditEvent,
    Membership,
    NativeAuthChallenge,
    NativeMfaFactor,
    NativeMfaRecoveryCode,
    NativeCredential,
    NativePasswordReset,
    NativeSession,
    Tenant,
    User,
    now,
)

if TYPE_CHECKING:
    from ..auth import Principal

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LENGTH = 32


@dataclass(frozen=True)
class NativeLoginResult:
    token: str
    session: NativeSession
    principal: Principal


@dataclass(frozen=True)
class NativeLoginChallenge:
    status: str
    token: str
    principal: Principal


@dataclass(frozen=True)
class NativePasswordResetIssue:
    token: str
    reset_id: str
    user_id: str
    email: str


class NativeAuthError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def normalize_email(value: str) -> str:
    return value.strip().lower()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _password_material(password: str, settings: Settings) -> bytes:
    return f"{settings.native_auth_pepper}:{password}".encode("utf-8")


def hash_password(password: str, settings: Settings) -> str:
    salt = secrets.token_bytes(16)
    kdf = Scrypt(salt=salt, length=KEY_LENGTH, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    digest = kdf.derive(_password_material(password, settings))
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, encoded: str, settings: Settings) -> bool:
    try:
        scheme, n, r, p, salt, digest = encoded.split("$", 5)
        if scheme != "scrypt":
            return False
        kdf = Scrypt(
            salt=_unb64(salt),
            length=KEY_LENGTH,
            n=int(n),
            r=int(r),
            p=int(p),
        )
        kdf.verify(_password_material(password, settings), _unb64(digest))
        return True
    except (InvalidKey, ValueError):
        return False


def session_digest(token: str, settings: Settings) -> str:
    return hmac.new(
        settings.native_session_secret.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _client_ip_prefix(ip: str | None) -> str:
    if not ip:
        return ""
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3])
    return ip[:48]


def _aware(value):
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def audit(
    db: Session,
    *,
    action: str,
    outcome: str,
    tenant_id: str | None = None,
    actor_id: str | None = None,
    resource_type: str = "native_auth",
    resource_id: str | None = None,
    metadata: dict | None = None,
) -> None:
    db.add(
        AuditEvent(
            tenant_id=tenant_id,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            metadata_json=metadata or {},
        )
    )


def create_or_update_credential(
    db: Session,
    *,
    user_id: str,
    password: str,
    settings: Settings,
) -> NativeCredential:
    credential = db.scalar(
        select(NativeCredential).where(NativeCredential.user_id == user_id)
    )
    timestamp = now()
    password_hash = hash_password(password, settings)
    if credential is None:
        credential = NativeCredential(
            user_id=user_id,
            password_hash=password_hash,
            password_updated_at=timestamp,
            created_at=timestamp,
        )
        db.add(credential)
    else:
        credential.password_hash = password_hash
        credential.failed_login_count = 0
        credential.locked_until = None
        credential.password_updated_at = timestamp
    return credential


def bootstrap_owner(
    db: Session,
    *,
    tenant_id: str,
    tenant_name: str,
    email: str,
    display_name: str,
    password: str,
    settings: Settings,
) -> Principal:
    from ..auth import Principal

    email = normalize_email(email)
    existing_credential = db.scalar(select(NativeCredential.id).limit(1))
    if existing_credential is not None:
        raise NativeAuthError("NATIVE_BOOTSTRAP_ALREADY_COMPLETED")

    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        tenant = Tenant(id=tenant_id, name=tenant_name)
        db.add(tenant)
    else:
        tenant.name = tenant_name

    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(
            external_subject=f"native:{email}",
            email=email,
            display_name=display_name,
        )
        db.add(user)
    else:
        user.display_name = display_name
    db.flush()

    membership = db.scalar(
        select(Membership).where(
            Membership.tenant_id == tenant.id,
            Membership.user_id == user.id,
        )
    )
    if membership is None:
        db.add(Membership(tenant_id=tenant.id, user_id=user.id, role="admin", active=True))
    else:
        membership.role = "admin"
        membership.active = True
    create_or_update_credential(db, user_id=user.id, password=password, settings=settings)
    audit(
        db,
        action="native_auth.bootstrap_owner",
        outcome="success",
        tenant_id=tenant.id,
        actor_id=user.id,
        resource_type="user",
        resource_id=user.id,
    )
    return Principal(
        user_id=user.id,
        tenant_id=tenant.id,
        roles=("admin",),
        email=user.email,
        external_subject=user.external_subject,
    )


def _fernet(settings: Settings) -> Fernet:
    key = base64.urlsafe_b64encode(
        hashlib.sha256(settings.native_session_secret.encode("utf-8")).digest()
    )
    return Fernet(key)


def _encrypt_mfa_secret(secret: str, settings: Settings) -> str:
    return _fernet(settings).encrypt(secret.encode("utf-8")).decode("ascii")


def _decrypt_mfa_secret(encoded: str, settings: Settings) -> str:
    try:
        return _fernet(settings).decrypt(encoded.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise NativeAuthError("MFA_FACTOR_INVALID") from exc


def _totp_code(secret: str, step: int) -> str:
    raw = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(raw, step.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def _verify_totp(secret: str, code: str, last_used_step: int | None = None) -> int | None:
    normalized = "".join(ch for ch in code.strip() if ch.isdigit())
    if len(normalized) != 6:
        return None
    current_step = int(__import__("time").time() // 30)
    for step in (current_step - 1, current_step, current_step + 1):
        if last_used_step is not None and step <= last_used_step:
            continue
        if hmac.compare_digest(_totp_code(secret, step), normalized):
            return step
    return None


def _challenge(
    db: Session,
    *,
    purpose: str,
    user_id: str,
    tenant_id: str | None,
    settings: Settings,
    payload: dict | None = None,
    ttl_minutes: int = 10,
) -> tuple[str, NativeAuthChallenge]:
    token = secrets.token_urlsafe(48)
    timestamp = now()
    item = NativeAuthChallenge(
        token_hash=session_digest(token, settings),
        token_prefix=token[:12],
        purpose=purpose,
        user_id=user_id,
        tenant_id=tenant_id,
        payload=payload or {},
        issued_at=timestamp,
        expires_at=timestamp + timedelta(minutes=ttl_minutes),
        attempts=0,
    )
    db.add(item)
    db.flush()
    return token, item


def _load_challenge(
    db: Session,
    *,
    token: str,
    purpose: str,
    settings: Settings,
) -> NativeAuthChallenge:
    item = db.scalar(
        select(NativeAuthChallenge).where(
            NativeAuthChallenge.token_hash == session_digest(token, settings),
            NativeAuthChallenge.purpose == purpose,
        ).with_for_update()
    )
    if item is None or item.used_at is not None or _aware(item.expires_at) <= now():
        raise NativeAuthError("AUTH_CHALLENGE_INVALID")
    if item.attempts >= 8:
        raise NativeAuthError("AUTH_CHALLENGE_INVALID")
    item.attempts += 1
    return item


def _principal_for_user(db: Session, *, user_id: str, tenant_id: str | None):
    from ..auth import Principal

    user = db.get(User, user_id)
    if user is None:
        raise NativeAuthError("AUTH_CHALLENGE_INVALID")
    query = select(Membership).where(
        Membership.user_id == user_id,
        Membership.active.is_(True),
    )
    if tenant_id:
        query = query.where(Membership.tenant_id == tenant_id)
    membership = db.scalar(query)
    if membership is None:
        raise NativeAuthError("PRINCIPAL_NOT_PROVISIONED")
    return Principal(
        user_id=user.id,
        tenant_id=membership.tenant_id,
        roles=(membership.role,),
        email=user.email,
        external_subject=user.external_subject,
    )


def issue_session(
    db: Session,
    *,
    principal,
    settings: Settings,
    user_agent: str = "",
    client_ip: str | None = None,
    mfa_verified: bool = False,
) -> NativeLoginResult:
    timestamp = now()
    token = secrets.token_urlsafe(48)
    session = NativeSession(
        session_hash=session_digest(token, settings),
        token_prefix=token[:12],
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        created_at=timestamp,
        expires_at=timestamp + timedelta(hours=settings.native_session_ttl_hours),
        last_seen_at=timestamp,
        user_agent=user_agent[:240],
        ip_prefix=_client_ip_prefix(client_ip),
        last_rotated_at=timestamp,
        authenticated_at=timestamp,
        mfa_verified_at=timestamp if mfa_verified else None,
    )
    db.add(session)
    audit(
        db,
        action="native_auth.login",
        outcome="success",
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        resource_type="native_session",
        resource_id=session.id,
        metadata={"mfa_verified": mfa_verified},
    )
    return NativeLoginResult(token=token, session=session, principal=principal)


def create_account_recovery_challenge(
    db: Session,
    *,
    email: str,
    grant_token: str,
    settings: Settings,
) -> str | None:
    from .hyper_cocreator import verify_access_grant, AccessGateError

    try:
        payload = verify_access_grant(settings, grant_token)
    except AccessGateError as exc:
        raise NativeAuthError(exc.code) from exc
    normalized = normalize_email(email)
    user = db.scalar(select(User).where(User.email == normalized))
    if user is None:
        return None
    credential = db.scalar(select(NativeCredential).where(NativeCredential.user_id == user.id))
    if credential is not None:
        raise NativeAuthError("NATIVE_ACCOUNT_ALREADY_EXISTS")
    configured_tenant = settings.access_gate_tenant_id.strip()
    tenant_id = str(payload.get("tenant_id") or configured_tenant or "")
    membership = db.scalar(select(Membership).where(
        Membership.user_id == user.id,
        Membership.tenant_id == tenant_id,
        Membership.active.is_(True),
    ))
    if membership is None:
        raise NativeAuthError("ACCOUNT_RECOVERY_NOT_ALLOWED")
    grant_jti = str(payload.get("jti") or "")
    if db.scalar(select(AccessGrantRedemption).where(AccessGrantRedemption.grant_jti == grant_jti)) is not None:
        raise NativeAuthError("ACCESS_GRANT_ALREADY_USED")
    db.add(AccessGrantRedemption(grant_jti=grant_jti, tenant_id=tenant_id, user_id=user.id))
    token, _ = _challenge(
        db,
        purpose="account_recovery",
        user_id=user.id,
        tenant_id=tenant_id,
        settings=settings,
        payload={"grant_jti": grant_jti},
        ttl_minutes=30,
    )
    audit(db, action="native_auth.account_recovery_requested", outcome="accepted", actor_id=user.id, tenant_id=tenant_id)
    return token


def complete_account_recovery(
    db: Session,
    *,
    token: str,
    password: str,
    settings: Settings,
) -> None:
    challenge = _load_challenge(db, token=token, purpose="account_recovery", settings=settings)
    principal = _principal_for_user(db, user_id=challenge.user_id, tenant_id=challenge.tenant_id)
    create_or_update_credential(db, user_id=principal.user_id, password=password, settings=settings)
    user = db.get(User, principal.user_id)
    if user is not None:
        user.email_verified_at = now()
    challenge.used_at = now()
    audit(db, action="native_auth.account_recovery_completed", outcome="success", actor_id=principal.user_id, tenant_id=principal.tenant_id)


def create_email_verification_challenge(
    db: Session,
    *,
    email: str,
    settings: Settings,
) -> tuple[str, str] | None:
    user = db.scalar(select(User).where(User.email == normalize_email(email)))
    if user is None:
        return None
    token, _ = _challenge(
        db,
        purpose="email_verification",
        user_id=user.id,
        tenant_id=None,
        settings=settings,
        ttl_minutes=30,
    )
    return token, user.email


def complete_email_verification(
    db: Session,
    *,
    token: str,
    settings: Settings,
) -> None:
    challenge = _load_challenge(db, token=token, purpose="email_verification", settings=settings)
    user = db.get(User, challenge.user_id)
    if user is None:
        raise NativeAuthError("AUTH_CHALLENGE_INVALID")
    user.email_verified_at = now()
    challenge.used_at = now()
    audit(db, action="native_auth.email_verified", outcome="success", actor_id=user.id)


def mfa_enrollment_start(
    db: Session,
    *,
    token: str,
    settings: Settings,
) -> tuple[str, str]:
    challenge = _load_challenge(db, token=token, purpose="mfa_enroll", settings=settings)
    factor = db.scalar(select(NativeMfaFactor).where(NativeMfaFactor.user_id == challenge.user_id))
    if factor is not None and factor.confirmed_at is not None:
        raise NativeAuthError("MFA_ALREADY_ENROLLED")
    secret = str(challenge.payload.get("secret") or "")
    if not secret:
        secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
        challenge.payload = {**challenge.payload, "secret": secret}
    user = db.get(User, challenge.user_id)
    if user is None:
        raise NativeAuthError("AUTH_CHALLENGE_INVALID")
    issuer = "PatroAI"
    label = f"{issuer}:{user.email}"
    uri = f"otpauth://totp/{__import__('urllib.parse', fromlist=['quote']).quote(label)}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    return secret, uri


def mfa_enrollment_confirm(
    db: Session,
    *,
    token: str,
    code: str,
    settings: Settings,
    user_agent: str = "",
    client_ip: str | None = None,
) -> tuple[NativeLoginResult, list[str]]:
    challenge = _load_challenge(db, token=token, purpose="mfa_enroll", settings=settings)
    secret = str(challenge.payload.get("secret") or "")
    if not secret or _verify_totp(secret, code) is None:
        raise NativeAuthError("MFA_CODE_INVALID")
    factor = db.scalar(select(NativeMfaFactor).where(NativeMfaFactor.user_id == challenge.user_id))
    if factor is None:
        factor = NativeMfaFactor(user_id=challenge.user_id, factor_type="totp", encrypted_secret=_encrypt_mfa_secret(secret, settings), confirmed_at=now())
        db.add(factor)
    else:
        factor.encrypted_secret = _encrypt_mfa_secret(secret, settings)
        factor.confirmed_at = now()
    codes: list[str] = []
    for _ in range(10):
        raw = f"{secrets.token_hex(4)}-{secrets.token_hex(4)}"
        codes.append(raw)
        db.add(NativeMfaRecoveryCode(user_id=challenge.user_id, code_hash=session_digest(raw, settings)))
    challenge.used_at = now()
    principal = _principal_for_user(db, user_id=challenge.user_id, tenant_id=challenge.tenant_id)
    return issue_session(db, principal=principal, settings=settings, user_agent=user_agent, client_ip=client_ip, mfa_verified=True), codes


def mfa_verify(
    db: Session,
    *,
    token: str,
    code: str | None,
    recovery_code: str | None,
    settings: Settings,
    user_agent: str = "",
    client_ip: str | None = None,
) -> NativeLoginResult:
    challenge = _load_challenge(db, token=token, purpose="mfa_verify", settings=settings)
    factor = db.scalar(select(NativeMfaFactor).where(NativeMfaFactor.user_id == challenge.user_id, NativeMfaFactor.confirmed_at.is_not(None)))
    verified = False
    if code and factor is not None:
        secret = _decrypt_mfa_secret(factor.encrypted_secret, settings)
        step = _verify_totp(secret, code, factor.last_used_step)
        if step is not None:
            factor.last_used_step = step
            verified = True
    elif recovery_code:
        recovery = db.scalar(select(NativeMfaRecoveryCode).where(
            NativeMfaRecoveryCode.user_id == challenge.user_id,
            NativeMfaRecoveryCode.code_hash == session_digest(recovery_code.strip(), settings),
            NativeMfaRecoveryCode.used_at.is_(None),
        ).with_for_update())
        if recovery is not None:
            recovery.used_at = now()
            verified = True
    if not verified:
        raise NativeAuthError("MFA_CODE_INVALID")
    challenge.used_at = now()
    principal = _principal_for_user(db, user_id=challenge.user_id, tenant_id=challenge.tenant_id)
    return issue_session(db, principal=principal, settings=settings, user_agent=user_agent, client_ip=client_ip, mfa_verified=True)


def login(
    db: Session,
    *,
    email: str,
    password: str,
    settings: Settings,
    user_agent: str = "",
    client_ip: str | None = None,
) -> NativeLoginResult | NativeLoginChallenge:
    from ..auth import Principal

    email = normalize_email(email)
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        audit(db, action="native_auth.login", outcome="failure", metadata={"reason": "unknown_email"})
        raise NativeAuthError("INVALID_CREDENTIALS")
    credential = db.scalar(
        select(NativeCredential).where(NativeCredential.user_id == user.id)
    )
    if credential is None:
        audit(
            db,
            action="native_auth.login",
            outcome="failure",
            actor_id=user.id,
            metadata={"reason": "missing_credential"},
        )
        raise NativeAuthError("INVALID_CREDENTIALS")

    timestamp = now()
    locked_until = _aware(credential.locked_until)
    if locked_until and locked_until > timestamp:
        audit(
            db,
            action="native_auth.login",
            outcome="failure",
            actor_id=user.id,
            metadata={"reason": "locked"},
        )
        raise NativeAuthError("ACCOUNT_TEMPORARILY_LOCKED")

    if not verify_password(password, credential.password_hash, settings):
        credential.failed_login_count += 1
        if credential.failed_login_count >= settings.native_login_max_failures:
            credential.locked_until = timestamp + timedelta(
                minutes=settings.native_login_lock_minutes
            )
        audit(
            db,
            action="native_auth.login",
            outcome="failure",
            actor_id=user.id,
            metadata={"reason": "bad_password"},
        )
        raise NativeAuthError("INVALID_CREDENTIALS")

    membership = db.scalar(
        select(Membership).where(
            Membership.user_id == user.id,
            Membership.active.is_(True),
        )
    )
    if membership is None:
        audit(
            db,
            action="native_auth.login",
            outcome="failure",
            actor_id=user.id,
            metadata={"reason": "no_active_membership"},
        )
        raise NativeAuthError("PRINCIPAL_NOT_PROVISIONED")

    credential.failed_login_count = 0
    credential.locked_until = None
    credential.last_login_at = timestamp
    principal = Principal(
        user_id=user.id,
        tenant_id=membership.tenant_id,
        roles=(membership.role,),
        email=user.email,
        external_subject=user.external_subject,
    )
    privileged = membership.role in {"admin", "owner", "orkio_admin"}
    if privileged and settings.environment in {"staging", "production"}:
        factor = db.scalar(
            select(NativeMfaFactor).where(
                NativeMfaFactor.user_id == user.id,
                NativeMfaFactor.confirmed_at.is_not(None),
            )
        )
        status = "MFA_REQUIRED" if factor is not None else "MFA_ENROLLMENT_REQUIRED"
        challenge_token, _ = _challenge(
            db,
            purpose="mfa_verify" if factor is not None else "mfa_enroll",
            user_id=user.id,
            tenant_id=membership.tenant_id,
            settings=settings,
        )
        audit(
            db,
            action="native_auth.login_challenge",
            outcome="success",
            tenant_id=membership.tenant_id,
            actor_id=user.id,
            metadata={"status": status},
        )
        return NativeLoginChallenge(status=status, token=challenge_token, principal=principal)
    return issue_session(
        db,
        principal=principal,
        settings=settings,
        user_agent=user_agent,
        client_ip=client_ip,
        mfa_verified=False,
    )


def principal_from_session(
    db: Session,
    *,
    token: str | None,
    settings: Settings,
) -> Principal | None:
    from ..auth import Principal

    if not token:
        return None
    session = db.scalar(
        select(NativeSession).where(
            NativeSession.session_hash == session_digest(token, settings)
        )
    )
    timestamp = now()
    if (
        session is None
        or session.revoked_at is not None
        or _aware(session.expires_at) <= timestamp
    ):
        return None
    user = db.get(User, session.user_id)
    membership = db.scalar(
        select(Membership).where(
            Membership.tenant_id == session.tenant_id,
            Membership.user_id == session.user_id,
            Membership.active.is_(True),
        )
    )
    if user is None or membership is None:
        return None
    session.last_seen_at = timestamp
    return Principal(
        user_id=user.id,
        tenant_id=session.tenant_id,
        roles=(membership.role,),
        email=user.email,
        external_subject=user.external_subject,
    )


def revoke_session(
    db: Session,
    *,
    token: str | None,
    settings: Settings,
) -> bool:
    if not token:
        return False
    session = db.scalar(
        select(NativeSession).where(
            NativeSession.session_hash == session_digest(token, settings)
        )
    )
    if session is None or session.revoked_at is not None:
        return False
    session.revoked_at = now()
    audit(
        db,
        action="native_auth.logout",
        outcome="success",
        tenant_id=session.tenant_id,
        actor_id=session.user_id,
        resource_type="native_session",
        resource_id=session.id,
    )
    return True


def create_password_reset(
    db: Session,
    *,
    email: str,
    settings: Settings,
) -> NativePasswordResetIssue | None:
    email = normalize_email(email)
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        audit(
            db,
            action="native_auth.password_reset_requested",
            outcome="accepted",
            metadata={"known_user": False},
        )
        return None
    credential = db.scalar(
        select(NativeCredential).where(NativeCredential.user_id == user.id)
    )
    if credential is None:
        audit(
            db,
            action="native_auth.password_reset_requested",
            outcome="accepted",
            actor_id=user.id,
            metadata={"known_user": True, "has_credential": False},
        )
        return None
    timestamp = now()
    db.query(NativePasswordReset).filter(
        NativePasswordReset.user_id == user.id,
        NativePasswordReset.used_at.is_(None),
    ).update(
        {NativePasswordReset.used_at: timestamp},
        synchronize_session=False,
    )
    token = secrets.token_urlsafe(48)
    reset = NativePasswordReset(
        token_hash=session_digest(token, settings),
        token_prefix=token[:12],
        user_id=user.id,
        issued_at=timestamp,
        expires_at=timestamp + timedelta(minutes=settings.native_password_reset_ttl_minutes),
    )
    db.add(reset)
    db.flush()
    audit(
        db,
        action="native_auth.password_reset_requested",
        outcome="accepted",
        actor_id=user.id,
        metadata={"known_user": True, "has_credential": True},
    )
    return NativePasswordResetIssue(
        token=token,
        reset_id=reset.id,
        user_id=user.id,
        email=user.email,
    )


def revoke_password_reset(
    db: Session,
    *,
    reset_id: str,
    reason: str,
) -> None:
    timestamp = now()
    reset = db.get(NativePasswordReset, reset_id)
    if reset is not None and reset.used_at is None:
        reset.used_at = timestamp
        audit(
            db,
            action="native_auth.password_reset_revoked",
            outcome="success",
            actor_id=reset.user_id,
            resource_type="native_password_reset",
            resource_id=reset.id,
            metadata={"reason": reason},
        )


def reset_password(
    db: Session,
    *,
    token: str,
    password: str,
    settings: Settings,
) -> None:
    reset = db.scalar(
        select(NativePasswordReset).where(
            NativePasswordReset.token_hash == session_digest(token, settings)
        ).with_for_update()
    )
    timestamp = now()
    if (
        reset is None
        or reset.used_at is not None
        or _aware(reset.expires_at) <= timestamp
    ):
        raise NativeAuthError("PASSWORD_RESET_TOKEN_INVALID")
    create_or_update_credential(
        db,
        user_id=reset.user_id,
        password=password,
        settings=settings,
    )
    db.query(NativeSession).filter(NativeSession.user_id == reset.user_id).update(
        {NativeSession.revoked_at: timestamp},
        synchronize_session=False,
    )
    db.query(NativePasswordReset).filter(
        NativePasswordReset.user_id == reset.user_id,
        NativePasswordReset.used_at.is_(None),
    ).update(
        {NativePasswordReset.used_at: timestamp},
        synchronize_session=False,
    )
    audit(
        db,
        action="native_auth.password_reset_completed",
        outcome="success",
        actor_id=reset.user_id,
    )
