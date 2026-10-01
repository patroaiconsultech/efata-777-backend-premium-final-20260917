"""Validação e autorização canônica de identidade provisionada.

Um token válido autentica uma identidade externa. Privilégios efetivos,
porém, vêm da Membership ativa no banco ORKIO. Claims de role não podem
elevar privilégio nem atravessar tenants.
"""

from __future__ import annotations

from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import Principal, require_principal
from ..config import Settings, get_settings
from ..database import get_db
from ..models import Membership, Tenant, ThreadParticipant, User
from .authorization import ProvisionedAuthorizationError, resolve_provisioned_roles


def assert_provisioned(db: Session, principal: Principal) -> None:
    """Garante tenant, usuário, subject e membership ativa."""
    tenant = db.get(Tenant, principal.tenant_id)
    user = db.get(User, principal.user_id)
    if tenant is None or user is None:
        raise HTTPException(403, "PRINCIPAL_NOT_PROVISIONED")
    if not principal.external_subject or user.external_subject != principal.external_subject:
        raise HTTPException(403, "PRINCIPAL_NOT_PROVISIONED")
    membership = db.scalar(
        select(Membership).where(
            Membership.tenant_id == principal.tenant_id,
            Membership.user_id == principal.user_id,
            Membership.active.is_(True),
        )
    )
    if membership is None:
        raise HTTPException(403, "PRINCIPAL_NOT_PROVISIONED")


def assert_identity_known(db: Session, principal: Principal) -> None:
    """Garante tenant, usuário e subject conhecido, sem exigir membership.

    Usado exclusivamente pelo aceite de convite: estabelecer o vínculo com
    a thread é justamente a finalidade do endpoint. A identidade externa,
    porém, precisa corresponder ao User existente.
    """
    tenant = db.get(Tenant, principal.tenant_id)
    user = db.get(User, principal.user_id)
    if tenant is None or user is None:
        raise HTTPException(403, "PRINCIPAL_NOT_PROVISIONED")
    if not principal.external_subject or user.external_subject != principal.external_subject:
        raise HTTPException(403, "PRINCIPAL_NOT_PROVISIONED")


def _canonicalize_provisioned_principal(
    db: Session,
    principal: Principal,
    settings: Settings,
) -> Principal:
    try:
        roles = resolve_provisioned_roles(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            external_subject=principal.external_subject,
            settings=settings,
        )
    except ProvisionedAuthorizationError as exc:
        raise HTTPException(403, exc.code) from exc

    return Principal(
        user_id=principal.user_id,
        tenant_id=principal.tenant_id,
        roles=roles,
        email=principal.email,
        external_subject=principal.external_subject,
    )


def require_provisioned_principal(
    principal: Principal = Depends(require_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Principal:
    """Autentica externamente e deriva autorização efetiva do banco."""
    return _canonicalize_provisioned_principal(db, principal, settings)



def _membership_for_principal(db: Session, principal: Principal) -> Membership | None:
    return db.scalar(
        select(Membership).where(
            Membership.tenant_id == principal.tenant_id,
            Membership.user_id == principal.user_id,
        )
    )


def _thread_guest_principal(
    db: Session,
    principal: Principal,
    *,
    thread_id: str | None = None,
) -> Principal:
    """Deriva autoridade mínima para colaborador externo thread-scoped.

    Um usuário que possui Membership no tenant, porém está inativo, nunca
    pode cair neste fallback. O fallback existe apenas para a identidade
    conhecida sem Membership que recebeu um ThreadParticipant external_guest
    ativo. Claims de role recebidos do cliente são descartados.
    """
    assert_identity_known(db, principal)

    membership = _membership_for_principal(db, principal)
    if membership is not None:
        # Membership inativa representa revogação tenant-wide e deve falhar
        # fechado, em vez de degradar silenciosamente para external_guest.
        raise HTTPException(403, "PRINCIPAL_NOT_PROVISIONED")

    statement = select(ThreadParticipant).where(
        ThreadParticipant.tenant_id == principal.tenant_id,
        ThreadParticipant.user_id == principal.user_id,
        ThreadParticipant.membership_type == "external_guest",
        ThreadParticipant.active.is_(True),
    )
    if thread_id is not None:
        statement = statement.where(ThreadParticipant.thread_id == thread_id)
    participant = db.scalar(statement)
    if participant is None:
        raise HTTPException(403, "PRINCIPAL_NOT_PROVISIONED")

    return Principal(
        user_id=principal.user_id,
        tenant_id=principal.tenant_id,
        roles=("thread_guest",),
        email=principal.email,
        external_subject=principal.external_subject,
    )


def require_collaboration_principal(
    principal: Principal = Depends(require_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Principal:
    """Autoriza tenant member provisionado ou external_guest de alguma thread.

    Esta dependência não concede acesso a recurso algum por si só. Endpoints
    globais de colaboração devem filtrar por ThreadParticipant ativo; endpoints
    thread-scoped devem preferir ``require_thread_principal``.
    """
    membership = _membership_for_principal(db, principal)
    if membership is not None and membership.active:
        return _canonicalize_provisioned_principal(db, principal, settings)
    return _thread_guest_principal(db, principal)


def require_thread_principal(
    thread_id: str,
    principal: Principal = Depends(require_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Principal:
    """Autoriza identidade provisionada ou external_guest desta thread.

    A autorização do recurso continua pertencendo à policy canônica de thread;
    esta dependência apenas permite que o principal thread-scoped chegue até
    essa decisão sem receber autoridade tenant-wide.
    """
    membership = _membership_for_principal(db, principal)
    if membership is not None and membership.active:
        return _canonicalize_provisioned_principal(db, principal, settings)
    return _thread_guest_principal(db, principal, thread_id=thread_id)

def require_provisioned_admin(
    principal: Principal = Depends(require_provisioned_principal),
) -> Principal:
    """Exige admin derivado da membership canônica, nunca de claim/header."""
    if not {"admin", "orkio_admin"}.intersection(principal.roles):
        raise HTTPException(403, "ADMIN_ROLE_REQUIRED")
    return principal


def require_provisioned_superadmin(
    principal: Principal = Depends(require_provisioned_principal),
) -> Principal:
    """Exige owner/superadmin derivado da membership e do sujeito configurado."""
    if not {"superadmin", "platform_owner"}.intersection(principal.roles):
        raise HTTPException(403, "SUPERADMIN_ROLE_REQUIRED")
    return principal


def require_known_principal(
    principal: Principal = Depends(require_principal),
    db: Session = Depends(get_db),
) -> Principal:
    """Dependência para aceite de convite: identidade conhecida e subject fiel."""
    assert_identity_known(db, principal)
    return principal
