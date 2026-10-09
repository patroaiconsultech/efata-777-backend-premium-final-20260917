"""Gate D: REST and model history use the canonical thread visibility contract."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from orkio_v2.auth import Principal
from orkio_v2.models import Base, Message, Tenant, Thread, ThreadParticipant, User
from orkio_v2.routes import _history, list_messages, thread_access
from orkio_v2.services.thread_access_policy import visible_messages


@pytest.fixture
def thread_case():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(
        engine,
        tables=[
            Tenant.__table__, User.__table__, Thread.__table__,
            ThreadParticipant.__table__, Message.__table__,
        ],
    )
    with Session(engine) as db:
        joined = datetime(2026, 1, 2, tzinfo=timezone.utc)
        db.add_all([
            Tenant(id="t1", name="T1"), Tenant(id="t2", name="T2"),
            User(id="u1", external_subject="u1", email="u1@invalid.test", display_name="U1"),
            User(id="u2", external_subject="u2", email="u2@invalid.test", display_name="U2"),
            Thread(id="th1", tenant_id="t1", created_by="u1"),
            ThreadParticipant(
                id="p1", tenant_id="t1", thread_id="th1", user_id="u1",
                history_access="from_join", joined_at=joined,
                active=True, thread_role="participant",
            ),
            Message(id="old", tenant_id="t1", thread_id="th1", author_type="user",
                    author_id="u2", content="PRIVATE_PRE_JOIN", created_at=joined - timedelta(hours=1)),
            Message(id="new", tenant_id="t1", thread_id="th1", author_type="user",
                    author_id="u1", content="POST_JOIN", created_at=joined + timedelta(hours=1)),
            Message(id="foreign", tenant_id="t2", thread_id="th1", author_type="user",
                    author_id="u2", content="FOREIGN_TENANT", created_at=joined + timedelta(hours=2)),
        ])
        db.commit()
        yield db, Principal(user_id="u1", tenant_id="t1", roles=("member",))


def test_rest_list_from_join_excludes_prejoin_and_cross_tenant(thread_case):
    db, principal = thread_case
    rows = list_messages("th1", p=principal, db=db)
    assert [row["id"] for row in rows] == ["new"]


def test_rest_full_thread_includes_prejoin_not_cross_tenant(thread_case):
    db, principal = thread_case
    participant = db.get(ThreadParticipant, "p1")
    participant.history_access = "full_thread"
    db.flush()
    assert [row["id"] for row in list_messages("th1", p=principal, db=db)] == ["old", "new"]


@pytest.mark.parametrize("tenant,active,expected", [
    ("t2", True, 404),
    ("t1", False, 403),
])
def test_rest_fail_closed_for_tenant_and_inactive_participant(thread_case, tenant, active, expected):
    db, principal = thread_case
    db.get(ThreadParticipant, "p1").active = active
    db.flush()
    principal = Principal(user_id="u1", tenant_id=tenant, roles=("member",))
    with pytest.raises(HTTPException) as exc:
        list_messages("th1", p=principal, db=db)
    assert exc.value.status_code == expected


def test_model_history_scope_uses_same_visibility_grant(thread_case, monkeypatch):
    import orkio_v2.routes as routes
    monkeypatch.setattr(routes, "document_context_message", lambda *a, **k: None)
    monkeypatch.setattr(routes, "artifact_context_message", lambda *a, **k: None)
    db, principal = thread_case
    _, participant = thread_access(db, "th1", principal)
    # Use the actual history function; it may add system messages but cannot include pre-join content.
    history = _history(
        db, "th1", "t1", settings=object(), participant=participant,
        limit=40, agent_id="orkio",
    )
    serialized = str(history)
    assert "POST_JOIN" in serialized
    assert "PRIVATE_PRE_JOIN" not in serialized
    assert "FOREIGN_TENANT" not in serialized


def test_invalid_history_policy_fails_closed(thread_case):
    db, principal = thread_case
    db.get(ThreadParticipant, "p1").history_access = "invalid"
    db.flush()
    with pytest.raises(HTTPException) as exc:
        list_messages("th1", p=principal, db=db)
    assert exc.value.status_code == 403
