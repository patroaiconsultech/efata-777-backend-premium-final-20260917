"""AO-01 security regression: independent grants; no old context after read revoke."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from conftest import Testing, headers
from orkio_v2.models import AuditEvent, Message, ThreadParticipant
from orkio_v2.routes import _history
from orkio_v2.config import get_settings
from orkio_v2.services.thread_access_policy import can_read_messages, can_write_messages
from orkio_v2.schemas import ThreadParticipantGrantUpdate
import pytest


def _grant(client, **overrides):
    owner, guest = headers(), headers(user="user-2", roles="admin")
    thread_id = client.post("/api/v2/threads", json={}, headers=owner).json()["id"]
    payload = {
        "email": "guest@example.com",
        "role": "participant",
        "history_access": "full_thread",
        "allowed_agent_ids": ["orkio"],
        "can_read_messages": True,
        "can_write_messages": True,
        "can_view_attachments": False,
        "can_upload_files": False,
        "can_download_artifacts": False,
        "can_generate_artifacts": False,
    }
    payload.update(overrides)
    invitation = client.post(
        f"/api/v2/threads/{thread_id}/invitations", json=payload, headers=owner
    )
    assert invitation.status_code == 200, invitation.text
    token = invitation.json()["invitation_url"].rsplit("/", 1)[-1]
    accepted = client.post("/api/v2/invitations/accept", json={"token": token}, headers=guest)
    assert accepted.status_code == 200, accepted.text
    return thread_id, owner, guest


def test_read_only_and_explicit_agent_grant_are_independent(client):
    th, owner, guest = _grant(client, can_read_messages=True, can_write_messages=False)
    permissions = client.get(f"/api/v2/threads/{th}/my-permissions", headers=guest).json()
    assert permissions["can_read_messages"] is True
    assert permissions["can_write_messages"] is False
    assert client.get(f"/api/v2/threads/{th}/messages", headers=guest).status_code == 200
    for endpoint in ("messages", "stream", "team/stream"):
        res = client.post(
            f"/api/v2/threads/{th}/{endpoint}",
            json={"content": "escrever", "agent": "id:orkio"},
            headers=guest,
        )
        assert res.status_code == 403, (endpoint, res.text)
    assert client.get(f"/api/v2/threads/{th}/participants", headers=guest).status_code == 200


def test_disable_read_blocks_messages_but_current_prompt_stays_available(client, monkeypatch):
    th, owner, guest = _grant(client, can_read_messages=False, can_write_messages=True)
    assert client.get(f"/api/v2/threads/{th}/messages", headers=guest).status_code == 403
    with Testing() as db:
        p = db.query(ThreadParticipant).filter_by(thread_id=th, user_id="user-2").one()
        assert can_write_messages(p)
        assert not can_read_messages(p)
        now = datetime.now(timezone.utc)
        db.add(Message(
            tenant_id="tenant-1", thread_id=th, author_type="user",
            author_id="user-1", content="SEGREDO_ANTERIOR", created_at=now - timedelta(days=3)
        ))
        db.flush()
        import orkio_v2.routes as routes
        monkeypatch.setattr(routes, "document_context_message", lambda *a, **k: None)
        monkeypatch.setattr(routes, "artifact_context_message", lambda *a, **k: None)
        monkeypatch.setattr(routes, "knowledge_context_messages", lambda *a, **k: [])
        history = _history(db, th, "tenant-1", get_settings(), participant=p,
                           current_message="PERGUNTA_ATUAL", limit=40)
        contents = [item.get("content", "") for item in history]
        assert "PERGUNTA_ATUAL" in contents
        assert not any("SEGREDO_ANTERIOR" in c for c in contents)


def test_owner_can_toggle_all_grants_and_audit_revoke(client):
    th, owner, guest = _grant(client, can_read_messages=True, can_write_messages=True)
    patch = {
        "history_access": "from_join", "allowed_agent_ids": ["orkio"],
        "can_read_messages": False, "can_write_messages": False,
        "can_view_attachments": True, "can_upload_files": False,
        "can_download_artifacts": True, "can_generate_artifacts": False,
    }
    res = client.put(f"/api/v2/threads/{th}/participants/user-2/permissions", headers=owner, json=patch)
    assert res.status_code == 200, res.text
    permissions = client.get(f"/api/v2/threads/{th}/my-permissions", headers=guest).json()
    for key, value in patch.items():
        assert permissions[key] == value, (key, permissions[key])
    assert client.get(f"/api/v2/threads/{th}/messages", headers=guest).status_code == 403
    with Testing() as db:
        event = db.query(AuditEvent).filter_by(
            action="thread_permissions_updated", resource_type="thread_participant"
        ).order_by(AuditEvent.created_at.desc()).first()
        assert event.metadata_json["new"]["can_read_messages"] is False
        assert event.metadata_json["new"]["can_view_attachments"] is True
    rev = client.delete(f"/api/v2/threads/{th}/participants/user-2", headers=owner)
    assert rev.status_code == 200
    assert client.get(f"/api/v2/threads/{th}/my-permissions", headers=guest).status_code == 403
    with Testing() as db:
        assert db.query(AuditEvent).filter_by(
            action="thread_participant_revoked", resource_type="thread_participant"
        ).count() >= 1


def test_grant_schema_rejects_unknown_privileges():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ThreadParticipantGrantUpdate(
            history_access="full_thread", allowed_agent_ids=["orkio"],
            can_publish_secrets=True,
        )


def test_viewer_does_not_get_write_permission(client):
    th, owner, guest = _grant(client, role="viewer", can_write_messages=False)
    response = client.get(f"/api/v2/threads/{th}/my-permissions", headers=guest)
    assert response.status_code == 200 and response.json()["can_write_messages"] is False
    assert client.post(f"/api/v2/threads/{th}/messages", headers=guest,
                       json={"content": "proibido"}).status_code == 403


def test_cross_thread_and_cross_tenant_permissions_denied(client):
    th, owner, guest = _grant(client)
    other = client.post("/api/v2/threads", json={}, headers=owner).json()["id"]
    assert client.get(f"/api/v2/threads/{other}/messages", headers=guest).status_code == 403
    assert client.get(
        f"/api/v2/threads/{th}/messages",
        headers=headers(user="user-2", tenant="tenant-x"),
    ).status_code in (403, 404)
