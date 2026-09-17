from __future__ import annotations

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from orkio_v2.auth import Principal, require_principal
from orkio_v2.config import Settings
from orkio_v2.database import Base
from orkio_v2.models import Membership, Tenant, User
from orkio_v2.services.identity import (
    require_provisioned_admin,
    require_provisioned_principal,
)


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Tenant(id="tenant-1", name="Tenant 1"))
        session.add(
            User(
                id="user-1",
                external_subject="sub-1",
                email="owner@example.test",
                display_name="Owner",
            )
        )
        session.add(
            Membership(
                tenant_id="tenant-1",
                user_id="user-1",
                role="admin",
                active=True,
            )
        )
        session.commit()
        yield session


def settings(owner_subject=None):
    return Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_OWNER_SUBJECT=owner_subject,
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
    )


def test_provisioned_principal_uses_membership_role_not_claim_role(db):
    raw = Principal(
        user_id="user-1",
        tenant_id="tenant-1",
        roles=("member", "attacker_role"),
        email="owner@example.test",
        external_subject="sub-1",
    )
    canonical = require_provisioned_principal(
        principal=raw,
        db=db,
        settings=settings(),
    )
    assert canonical.roles == ("admin",)


def test_platform_owner_augmentation_requires_canonical_admin_membership(db):
    raw = Principal(
        user_id="user-1",
        tenant_id="tenant-1",
        roles=("platform_owner",),
        external_subject="sub-1",
    )
    canonical = require_provisioned_principal(
        principal=raw,
        db=db,
        settings=settings("sub-1"),
    )
    assert canonical.roles == ("admin", "platform_owner")
    assert require_provisioned_admin(principal=canonical) == canonical


def test_claimed_admin_cannot_bypass_member_membership(db):
    membership = db.query(Membership).filter_by(
        tenant_id="tenant-1",
        user_id="user-1",
    ).one()
    membership.role = "member"
    db.commit()

    raw = Principal(
        user_id="user-1",
        tenant_id="tenant-1",
        roles=("admin",),
        external_subject="sub-1",
    )
    canonical = require_provisioned_principal(
        principal=raw,
        db=db,
        settings=settings(),
    )
    assert canonical.roles == ("member",)
    with pytest.raises(HTTPException) as raised:
        require_provisioned_admin(principal=canonical)
    assert raised.value.status_code == 403
    assert raised.value.detail == "ADMIN_ROLE_REQUIRED"


def test_subject_mismatch_is_fail_closed_even_when_claims_admin(db):
    raw = Principal(
        user_id="user-1",
        tenant_id="tenant-1",
        roles=("admin",),
        external_subject="sub-attacker",
    )
    with pytest.raises(HTTPException) as raised:
        require_provisioned_principal(
            principal=raw,
            db=db,
            settings=settings(),
        )
    assert raised.value.status_code == 403
    assert raised.value.detail == "PRINCIPAL_NOT_PROVISIONED"


class FakeIntrospectionResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_oidc_runtime_rejects_cross_tenant_zitadel_role_binding(monkeypatch):
    tenant_claim = "urn:zitadel:iam:user:resourceowner:id"
    roles_claim = "urn:zitadel:iam:org:project:roles"
    monkeypatch.setattr(
        "orkio_v2.auth.httpx.post",
        lambda *_args, **_kwargs: FakeIntrospectionResponse(
            {
                "active": True,
                "iss": "https://issuer.example",
                "aud": ["orkio-api"],
                "sub": "user-1",
                tenant_claim: "tenant-1",
                roles_claim: {
                    "admin": {"other-tenant": "other.example"},
                    "member": {"tenant-1": "tenant.example"},
                },
            }
        ),
    )
    oidc_settings = Settings(
        PLATFORM_ENVIRONMENT="staging",
        PLATFORM_AUTH_MODE="oidc_introspection",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
        PLATFORM_OIDC_ISSUER="https://issuer.example",
        PLATFORM_OIDC_AUDIENCE="orkio-api",
        PLATFORM_OIDC_INTROSPECTION_ENDPOINT="https://issuer.example/introspect",
        PLATFORM_OIDC_INTROSPECTION_CLIENT_ID="backend",
        PLATFORM_OIDC_INTROSPECTION_CLIENT_SECRET="s" + "ecret",
    )

    principal = require_principal(
        authorization="Bearer token",
        x_test_user=None,
        x_test_tenant=None,
        x_test_roles=None,
        x_test_email=None,
        x_test_subject=None,
        settings=oidc_settings,
    )
    assert principal.tenant_id == "tenant-1"
    assert principal.roles == ("member",)
