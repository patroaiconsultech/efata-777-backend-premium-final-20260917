"""EFATÀ 777: human-only threads and later authorized agent context."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from conftest import Testing, headers
from orkio_v2.config import get_settings
from orkio_v2.models import AuditEvent, Message, ThreadParticipant
from orkio_v2.routes import _history


def _thread(client):
    owner = headers()
    response = client.post("/api/v2/threads", json={"title": "Projeto"}, headers=owner)
    assert response.status_code == 200, response.text
    return response.json()["id"], owner


def _invite(client, thread_id, owner, *, history_access="full_thread",
            can_read_messages=True, can_write_messages=True, role="participant"):
    invitation = client.post(
        f"/api/v2/threads/{thread_id}/invitations",
        json={
            "email": "guest@example.com",
            "role": role,
            "history_access": history_access,
            "allowed_agent_ids": ["orkio"],
            "can_read_messages": can_read_messages,
            "can_write_messages": can_write_messages,
            "can_view_attachments": False,
            "can_upload_files": False,
            "can_download_artifacts": False,
            "can_generate_artifacts": False,
        },
        headers=owner,
    )
    assert invitation.status_code == 200, invitation.text
    token = invitation.json()["invitation_url"].rsplit("/", 1)[-1]
    guest = headers(user="user-2", roles="admin")
    accepted = client.post("/api/v2/invitations/accept", json={"token": token}, headers=guest)
    assert accepted.status_code == 200, accepted.text
    return guest


def test_human_message_no_ai_tools_invoked(client, monkeypatch):
    thread_id, owner = _thread(client)

    def unexpected(*args, **kwargs):
        raise AssertionError("AI/tool invocation in human-only route")

    import orkio_v2.routes as routes
    monkeypatch.setattr(routes.llm, "ensure_configured", unexpected)
    monkeypatch.setattr(routes, "_resolve_target_or_404", unexpected)
    response = client.post(
        f"/api/v2/threads/{thread_id}/human-messages",
        json={"content": "  Mensagem humana  "},
        headers=owner,
    )
    assert response.status_code == 201, response.text
    assert response.json()["ai_invoked"] is False
    assert response.json()["content"] == "Mensagem humana"
    items = client.get(f"/api/v2/threads/{thread_id}/messages", headers=owner).json()
    assert len(items) == 1
    assert items[0]["author_type"] == "user"
    assert items[0]["author_id"] == "user-1"
    with Testing() as db:
        entry = db.query(AuditEvent).filter_by(action="thread_human_message_posted").one()
        assert entry.metadata_json == {"thread_id": thread_id, "mode": "human"}


def test_two_users_exchange_and_agent_can_read_authorized_human_history(client, monkeypatch):
    thread_id, owner = _thread(client)
    guest = _invite(client, thread_id, owner, history_access="full_thread")
    for actor, content in ((owner, "PLANO_INVESTIDOR"), (guest, "PERGUNTA_INVESTIDOR")):
        response = client.post(f"/api/v2/threads/{thread_id}/human-messages",
                               json={"content": content}, headers=actor)
        assert response.status_code == 201, response.text
    items = client.get(f"/api/v2/threads/{thread_id}/messages", headers=guest).json()
    assert [m["content"] for m in items] == ["PLANO_INVESTIDOR", "PERGUNTA_INVESTIDOR"]
    assert all(m["author_type"] == "user" for m in items)
    import orkio_v2.routes as routes
    monkeypatch.setattr(routes, "document_context_message", lambda *a, **k: None)
    monkeypatch.setattr(routes, "artifact_context_message", lambda *a, **k: None)
    monkeypatch.setattr(routes, "knowledge_context_messages", lambda *a, **k: [])
    with Testing() as db:
        member = db.query(ThreadParticipant).filter_by(thread_id=thread_id, user_id="user-2").one()
        history = _history(db, thread_id, "tenant-1", get_settings(), participant=member,
                           agent_id="orkio", current_message="Analise a conversa")
        text = "\n".join(x["content"] for x in history)
        assert "PLANO_INVESTIDOR" in text
        assert "PERGUNTA_INVESTIDOR" in text


def test_from_join_excludes_earlier_human_message_from_agent_context(client, monkeypatch):
    thread_id, owner = _thread(client)
    with Testing() as db:
        db.add(Message(
            tenant_id="tenant-1", thread_id=thread_id, author_type="user",
            author_id="user-1", content="PRE_JOIN_CONFIDENTIAL",
            created_at=datetime.now(timezone.utc) - timedelta(days=2),
        ))
        db.commit()
    guest = _invite(client, thread_id, owner, history_access="from_join")
    response = client.post(f"/api/v2/threads/{thread_id}/human-messages",
                           json={"content": "POST_JOIN_VISIBLE"}, headers=guest)
    assert response.status_code == 201
    contents = [m["content"] for m in client.get(
        f"/api/v2/threads/{thread_id}/messages", headers=guest).json()]
    assert "POST_JOIN_VISIBLE" in contents
    assert "PRE_JOIN_CONFIDENTIAL" not in contents
    import orkio_v2.routes as routes
    monkeypatch.setattr(routes, "document_context_message", lambda *a, **k: None)
    monkeypatch.setattr(routes, "artifact_context_message", lambda *a, **k: None)
    monkeypatch.setattr(routes, "knowledge_context_messages", lambda *a, **k: [])
    with Testing() as db:
        member = db.query(ThreadParticipant).filter_by(thread_id=thread_id, user_id="user-2").one()
        history = _history(db, thread_id, "tenant-1", get_settings(), participant=member,
                           agent_id="orkio", current_message="Resuma as mensagens")
        text = "\n".join(x["content"] for x in history)
        assert "POST_JOIN_VISIBLE" in text
        assert "PRE_JOIN_CONFIDENTIAL" not in text


def test_human_write_forbidden_when_read_only_or_revoked(client):
    thread_id, owner = _thread(client)
    guest = _invite(client, thread_id, owner, can_write_messages=False)
    path = f"/api/v2/threads/{thread_id}/human-messages"
    assert client.post(path, json={"content": "proibido"}, headers=guest).status_code == 403
    assert client.delete(f"/api/v2/threads/{thread_id}/participants/user-2", headers=owner).status_code == 200
    assert client.post(path, json={"content": "revogado"}, headers=guest).status_code == 403


def test_human_write_cross_thread_and_tenant_forbidden(client):
    thread_id, owner = _thread(client)
    guest = _invite(client, thread_id, owner)
    different = client.post("/api/v2/threads", json={}, headers=owner).json()["id"]
    url = f"/api/v2/threads/{different}/human-messages"
    assert client.post(url, json={"content": "cross-thread"}, headers=guest).status_code == 403
    own = f"/api/v2/threads/{thread_id}/human-messages"
    assert client.post(own, json={"content": "cross-tenant"},
                       headers=headers(user="user-2", tenant="tenant-x")).status_code in (403, 404)


def test_human_input_rejects_hidden_agent_or_blank_content(client):
    thread_id, owner = _thread(client)
    url = f"/api/v2/threads/{thread_id}/human-messages"
    for bad in (
        {"content": "msg", "agent": "id:orkio"},
        {"content": "  "},
        {"content": "msg", "tool": "execute"},
    ):
        assert client.post(url, json=bad, headers=owner).status_code == 422


def test_full_thread_to_from_join_revokes_previous_human_context(client, monkeypatch):
    thread_id, owner = _thread(client)
    with Testing() as db:
        db.add(Message(
            tenant_id="tenant-1", thread_id=thread_id,
            author_type="user", author_id="user-1",
            content="SHARED_ONCE_THEN_REVOKED",
            created_at=datetime.now(timezone.utc) - timedelta(days=10),
        ))
        db.commit()
    guest = _invite(client, thread_id, owner, history_access="full_thread")
    url = f"/api/v2/threads/{thread_id}/messages"
    assert "SHARED_ONCE_THEN_REVOKED" in [m["content"] for m in client.get(url, headers=guest).json()]
    payload = {
        "history_access": "from_join", "allowed_agent_ids": ["orkio"],
        "can_read_messages": True, "can_write_messages": True,
        "can_view_attachments": False, "can_upload_files": False,
        "can_download_artifacts": False, "can_generate_artifacts": False,
    }
    changed = client.put(
        f"/api/v2/threads/{thread_id}/participants/user-2/permissions",
        headers=owner, json=payload,
    )
    assert changed.status_code == 200, changed.text
    assert "SHARED_ONCE_THEN_REVOKED" not in [
        m["content"] for m in client.get(url, headers=guest).json()
    ]
    import orkio_v2.routes as routes
    monkeypatch.setattr(routes, "document_context_message", lambda *a, **k: None)
    monkeypatch.setattr(routes, "artifact_context_message", lambda *a, **k: None)
    monkeypatch.setattr(routes, "knowledge_context_messages", lambda *a, **k: [])
    with Testing() as db:
        member = db.query(ThreadParticipant).filter_by(thread_id=thread_id, user_id="user-2").one()
        context = _history(
            db, thread_id, "tenant-1", get_settings(), participant=member,
            agent_id="orkio", current_message="Analise o que posso ler"
        )
        assert not any("SHARED_ONCE_THEN_REVOKED" in item["content"] for item in context)
