from dataclasses import dataclass
from fastapi import Cookie, Depends, Header, HTTPException, Request
import httpx
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .database import get_db
from .services.native_auth import principal_from_session
from .services.oidc_identity import OIDCIdentityMappingError, normalize_oidc_identity


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    roles: tuple[str, ...]
    email: str | None = None
    external_subject: str | None = None


def require_principal(
    authorization: str | None = Header(None),
    native_session: str | None = Cookie(None, alias="__Host-patroai_session"),
    legacy_native_session: str | None = Cookie(None, alias="patroai_session"),
    x_test_user: str | None = Header(None, alias="X-Test-User"),
    x_test_tenant: str | None = Header(None, alias="X-Test-Tenant"),
    x_test_roles: str | None = Header(None, alias="X-Test-Roles"),
    x_test_email: str | None = Header(None, alias="X-Test-Email"),
    x_test_subject: str | None = Header(None, alias="X-Test-Subject"),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
    request: Request = None,
) -> Principal:
    if settings.auth_mode == "test":
        if settings.environment not in {"test", "development"}:
            raise HTTPException(500, "TEST_AUTH_FORBIDDEN")
        if not x_test_user or not x_test_tenant:
            raise HTTPException(401, "TEST_IDENTITY_REQUIRED")
        if not x_test_subject:
            raise HTTPException(401, "TEST_SUBJECT_REQUIRED")
        return Principal(
            user_id=x_test_user,
            tenant_id=x_test_tenant,
            roles=tuple(filter(None, (x_test_roles or "member").split(","))),
            email=x_test_email,
            external_subject=x_test_subject,
        )

    if settings.auth_mode == "external_required":
        raise HTTPException(status_code=401, detail="AUTH_PROVIDER_REQUIRED")

    if settings.auth_mode in {"native_session", "native_or_oidc"}:
        configured_native_session = (
            request.cookies.get(settings.native_session_cookie_name)
            if request is not None
            else None
        )
        token = configured_native_session or native_session or legacy_native_session
        principal = principal_from_session(db, token=token, settings=settings)
        if principal is not None:
            return principal
        if settings.auth_mode == "native_session":
            raise HTTPException(status_code=401, detail="NATIVE_SESSION_REQUIRED")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="BEARER_TOKEN_REQUIRED")

    token = authorization.removeprefix("Bearer ").strip()
    try:
        response = httpx.post(
            settings.oidc_introspection_endpoint,
            data={"token": token},
            auth=(
                settings.oidc_introspection_client_id,
                settings.oidc_introspection_client_secret,
            ),
            timeout=settings.oidc_http_timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="IDENTITY_PROVIDER_UNAVAILABLE",
        ) from exc

    if not data.get("active"):
        raise HTTPException(status_code=401, detail="TOKEN_INACTIVE")

    issuer = data.get("iss")
    if not issuer or str(issuer) != str(settings.oidc_issuer):
        raise HTTPException(status_code=401, detail="TOKEN_ISSUER_INVALID")

    audience = data.get("aud", [])
    audience = [audience] if isinstance(audience, str) else audience
    if settings.oidc_audience not in audience:
        raise HTTPException(status_code=401, detail="TOKEN_AUDIENCE_INVALID")

    try:
        identity = normalize_oidc_identity(
            data,
            user_claim=settings.oidc_user_claim,
            tenant_claim=settings.oidc_tenant_claim,
            roles_claim=settings.oidc_roles_claim,
        )
    except OIDCIdentityMappingError as exc:
        raise HTTPException(status_code=403, detail=exc.code) from exc

    return Principal(
        user_id=identity.user_id,
        tenant_id=identity.tenant_id,
        roles=identity.roles,
        email=identity.email,
        external_subject=identity.external_subject,
    )


def require_admin(
    principal: Principal = Depends(require_principal),
) -> Principal:
    """Legacy role-check helper.

    Runtime admin routes use `require_provisioned_admin`, which derives
    effective roles from the canonical Membership row. This helper remains
    for backwards compatibility only and must never be used as a substitute
    for provisioned authorization.
    """
    if not {"admin", "orkio_admin"}.intersection(principal.roles):
        raise HTTPException(403, "ADMIN_ROLE_REQUIRED")
    return principal
