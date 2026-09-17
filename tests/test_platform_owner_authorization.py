import os
os.environ.setdefault("PLATFORM_ENVIRONMENT", "test")
os.environ.setdefault("PLATFORM_AUTH_MODE", "test")
os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from orkio_v2.config import Settings
from orkio_v2.database import Base
from orkio_v2.models import Membership, Tenant, User
from orkio_v2.services.authorization import (
    ProvisionedAuthorizationError,
    resolve_provisioned_roles,
)


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as session:
        session.add(Tenant(id="tenant-1", name="Patroai"))
        session.add(
            User(
                id="user-1",
                external_subject="sub-daniel",
                email="owner@example.com",
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


def test_admin_membership_is_canonical_authorization_source(db):
    roles = resolve_provisioned_roles(
        db,
        tenant_id="tenant-1",
        user_id="user-1",
        external_subject="sub-daniel",
        settings=settings(),
    )
    assert roles == ("admin",)


def test_platform_owner_requires_verified_subject_and_admin_membership(db):
    roles = resolve_provisioned_roles(
        db,
        tenant_id="tenant-1",
        user_id="user-1",
        external_subject="sub-daniel",
        settings=settings("sub-daniel"),
    )
    assert set(roles) == {"admin", "platform_owner"}


def test_platform_owner_subject_does_not_bypass_membership_role(db):
    membership = db.query(Membership).filter_by(
        tenant_id="tenant-1", user_id="user-1"
    ).one()
    membership.role = "member"
    db.commit()
    with pytest.raises(ProvisionedAuthorizationError) as raised:
        resolve_provisioned_roles(
            db,
            tenant_id="tenant-1",
            user_id="user-1",
            external_subject="sub-daniel",
            settings=settings("sub-daniel"),
        )
    assert raised.value.code == "PLATFORM_OWNER_ADMIN_MEMBERSHIP_REQUIRED"


def test_wrong_subject_cannot_inherit_platform_owner(db):
    with pytest.raises(ProvisionedAuthorizationError) as raised:
        resolve_provisioned_roles(
            db,
            tenant_id="tenant-1",
            user_id="user-1",
            external_subject="sub-other",
            settings=settings("sub-daniel"),
        )
    assert raised.value.code == "PRINCIPAL_NOT_PROVISIONED"
