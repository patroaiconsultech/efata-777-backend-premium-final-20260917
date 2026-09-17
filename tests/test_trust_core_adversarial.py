
from __future__ import annotations

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from conftest import Testing, headers
from orkio_v2.auth import Principal
from orkio_v2.config import Settings
from orkio_v2.database import Base
from orkio_v2.models import Membership, Tenant, ThreadParticipant, User
from orkio_v2.services.identity import require_provisioned_admin, require_provisioned_principal


def _settings(owner_subject: str | None = None) -> Settings:
    return Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_OWNER_SUBJECT=owner_subject,
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
    )


def test_inactive_membership_rejected_even_when_claims_admin(client):
    with Testing() as db:
        membership = db.query(Membership).filter_by(
            tenant_id="tenant-1", user_id="user-1"
        ).one()
        membership.active = False
        db.commit()
    try:
        response = client.get(
            "/api/v2/threads",
            headers=headers(roles="admin"),
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "PRINCIPAL_NOT_PROVISIONED"
    finally:
        with Testing() as db:
            membership = db.query(Membership).filter_by(
                tenant_id="tenant-1", user_id="user-1"
            ).one()
            membership.active = True
            db.commit()


def test_wrong_user_id_cannot_reuse_valid_external_subject(client):
    response = client.get(
        "/api/v2/threads",
        headers=headers(
            user="user-attacker",
            roles="admin",
            tenant="tenant-1",
            subject="sub-1",
        ),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "PRINCIPAL_NOT_PROVISIONED"


def test_admin_membership_does_not_grant_global_thread_access(client):
    owner_thread = client.post(
        "/api/v2/threads",
        json={"title": "Owner only"},
        headers=headers(),
    ).json()

    with Testing() as db:
        if not db.get(User, "user-admin-2"):
            db.add(
                User(
                    id="user-admin-2",
                    external_subject="sub-admin-2",
                    email="admin2@example.test",
                    display_name="Admin 2",
                )
            )
            db.add(
                Membership(
                    tenant_id="tenant-1",
                    user_id="user-admin-2",
                    role="admin",
                    active=True,
                )
            )
            db.commit()

    response = client.get(
        f"/api/v2/threads/{owner_thread['id']}/messages",
        headers=headers(
            user="user-admin-2",
            roles="admin",
            tenant="tenant-1",
            subject="sub-admin-2",
        ),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "THREAD_ACCESS_DENIED"


def test_foreign_tenant_thread_id_is_hidden_as_not_found(client):
    owner_thread = client.post(
        "/api/v2/threads",
        json={"title": "Tenant 1 private"},
        headers=headers(),
    ).json()

    with Testing() as db:
        if not db.get(Tenant, "tenant-2"):
            db.add(Tenant(id="tenant-2", name="Tenant 2"))
        if not db.get(User, "user-3"):
            db.add(
                User(
                    id="user-3",
                    external_subject="sub-3",
                    email="three@example.test",
                    display_name="Three",
                )
            )
        if not db.query(Membership).filter_by(
            tenant_id="tenant-2", user_id="user-3"
        ).first():
            db.add(
                Membership(
                    tenant_id="tenant-2",
                    user_id="user-3",
                    role="admin",
                    active=True,
                )
            )
        db.commit()

    response = client.get(
        f"/api/v2/threads/{owner_thread['id']}/messages",
        headers=headers(
            user="user-3",
            roles="admin",
            tenant="tenant-2",
            subject="sub-3",
        ),
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "THREAD_NOT_FOUND"


def test_inactive_thread_participation_is_rejected(client):
    thread = client.post(
        "/api/v2/threads",
        json={"title": "Inactive participant"},
        headers=headers(),
    ).json()

    with Testing() as db:
        participant = db.query(ThreadParticipant).filter_by(
            thread_id=thread["id"], user_id="user-1"
        ).one()
        participant.active = False
        db.commit()
    try:
        response = client.get(
            f"/api/v2/threads/{thread['id']}/messages",
            headers=headers(),
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "THREAD_ACCESS_DENIED"
    finally:
        with Testing() as db:
            participant = db.query(ThreadParticipant).filter_by(
                thread_id=thread["id"], user_id="user-1"
            ).one()
            participant.active = True
            db.commit()


def test_platform_owner_does_not_cross_tenant_membership_role():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all(
            [
                Tenant(id="tenant-1", name="Tenant 1"),
                Tenant(id="tenant-2", name="Tenant 2"),
                User(
                    id="user-1",
                    external_subject="sub-founder",
                    email="founder@example.test",
                    display_name="Founder",
                ),
                Membership(
                    tenant_id="tenant-1",
                    user_id="user-1",
                    role="member",
                    active=True,
                ),
                Membership(
                    tenant_id="tenant-2",
                    user_id="user-1",
                    role="admin",
                    active=True,
                ),
            ]
        )
        db.commit()

        principal_t1 = Principal(
            user_id="user-1",
            tenant_id="tenant-1",
            roles=("admin", "platform_owner"),
            external_subject="sub-founder",
        )
        with pytest.raises(HTTPException) as raised:
            require_provisioned_principal(
                principal=principal_t1,
                db=db,
                settings=_settings("sub-founder"),
            )
        assert raised.value.status_code == 403
        assert raised.value.detail == "PLATFORM_OWNER_ADMIN_MEMBERSHIP_REQUIRED"

        principal_t2 = Principal(
            user_id="user-1",
            tenant_id="tenant-2",
            roles=(),
            external_subject="sub-founder",
        )
        canonical = require_provisioned_principal(
            principal=principal_t2,
            db=db,
            settings=_settings("sub-founder"),
        )
        assert canonical.roles == ("admin", "platform_owner")


def test_claimed_platform_owner_never_works_without_configured_owner_subject(client):
    response = client.get(
        "/api/v2/admin/security/status",
        headers=headers(roles="platform_owner,admin"),
    )
    # Canonical DB admin may enter this route, but the untrusted platform_owner
    # claim must not appear as an effective role.
    assert response.status_code == 403
    assert response.json()["detail"] == "ADMIN_ALLOWLIST_REQUIRED"

    with Testing() as db:
        principal = Principal(
            user_id="user-1",
            tenant_id="tenant-1",
            roles=("platform_owner",),
            external_subject="sub-1",
        )
        canonical = require_provisioned_principal(
            principal=principal,
            db=db,
            settings=_settings(None),
        )
        assert canonical.roles == ("admin",)
        assert "platform_owner" not in canonical.roles


def test_member_claimed_admin_is_denied_from_admin_route(client):
    with Testing() as db:
        membership = db.query(Membership).filter_by(
            tenant_id="tenant-1", user_id="user-1"
        ).one()
        membership.role = "member"
        db.commit()
    try:
        response = client.get(
            "/api/v2/admin/security/status",
            headers=headers(roles="admin"),
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "ADMIN_ALLOWLIST_REQUIRED"
    finally:
        with Testing() as db:
            membership = db.query(Membership).filter_by(
                tenant_id="tenant-1", user_id="user-1"
            ).one()
            membership.role = "admin"
            db.commit()
