from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from orkio_v2.database import Base
from orkio_v2.models import Membership, Tenant, User


def load_bootstrap_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap_identity.py"
    spec = importlib.util.spec_from_file_location("bootstrap_identity_transaction_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def plan(module, *, tenant_id="tenant-1", user_id="user-1"):
    return module.BootstrapPlan(
        tenant_id=tenant_id,
        tenant_name="Patroai",
        user_id=user_id,
        external_subject=user_id,
        email="owner@example.test",
        display_name="Owner",
        role="admin",
        create_tenant=True,
        create_user=True,
        create_membership=True,
    )


def test_apply_plan_flushes_parents_before_membership(db):
    module = load_bootstrap_module()

    module.apply_plan(db, plan(module))

    assert db.get(Tenant, "tenant-1") is not None
    assert db.get(User, "user-1") is not None
    membership = db.scalar(
        select(Membership).where(
            Membership.tenant_id == "tenant-1",
            Membership.user_id == "user-1",
        )
    )
    assert membership is not None
    assert membership.role == "admin"
    assert membership.active is True


def test_failed_child_insert_can_be_rolled_back_without_parent_residue(db):
    module = load_bootstrap_module()

    @event.listens_for(db.bind, "before_cursor_execute")
    def _fail_membership_insert(_conn, _cursor, statement, _params, _context, _executemany):
        if statement.lstrip().upper().startswith("INSERT INTO MEMBERSHIPS"):
            raise RuntimeError("forced-child-failure")

    with pytest.raises(RuntimeError, match="forced-child-failure"):
        module.apply_plan(db, plan(module))
    db.rollback()

    assert db.get(Tenant, "tenant-1") is None
    assert db.get(User, "user-1") is None
    assert db.scalar(select(Membership)) is None
