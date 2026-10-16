"""DG-01: per-thread invitations, history scope, agents, uploads and revocation."""
from __future__ import annotations

from fastapi import HTTPException
import pytest

from conftest import headers
from orkio_v2.models import ThreadParticipant
from orkio_v2.schemas import InvitationCreate, ThreadParticipantGrantUpdate
from orkio_v2.services.thread_agent_grants import allowed_agent_ids, require_agents_allowed


def test_agent_grant_schema_is_allowlisted_and_non_empty():
    assert InvitationCreate(email="person@example.com").allowed_agent_ids == ["orkio"]
    for value in ([], ["orkio", "orkio"], ["nonexistent-agent"]):
        with pytest.raises(ValueError):
            InvitationCreate(email="person@example.com", allowed_agent_ids=value)


def test_legacy_policy_fails_closed_and_restricts_non_admin():
    p = ThreadParticipant(allowed_agent_ids=None)
    assert allowed_agent_ids(p) == ("orkio",)
    require_agents_allowed(p, ["orkio"])
    with pytest.raises(HTTPException) as exc:
        require_agents_allowed(p, ["orion"])
    assert exc.value.status_code == 403
    p.allowed_agent_ids = ["orion"]
    require_agents_allowed(p, ["orion"])
    with pytest.raises(HTTPException):
        require_agents_allowed(p, ["orkio"])
    p.allowed_agent_ids = []
    with pytest.raises(HTTPException):
        require_agents_allowed(p, ["orkio"])


def test_owner_configures_guest_and_agent_scope_enforced_at_chat_boundary(client):
    owner = headers()
    guest = headers(user="user-2", roles="admin")  # forged browser role must be discarded
    th = client.post("/api/v2/threads", json={"title": "DG grants"}, headers=owner).json()["id"]
    created = client.post(
        f"/api/v2/threads/{th}/invitations",
        json={
            "email": "guest@example.com",
            "role": "participant",
            "history_access": "from_join",
            "allowed_agent_ids": ["orion"],
            "can_upload_files": False,
        },
        headers=owner,
    )
    assert created.status_code == 200, created.text
    token = created.json()["invitation_url"].rsplit("/", 1)[-1]
    accepted = client.post("/api/v2/invitations/accept", json={"token": token}, headers=guest)
    assert accepted.status_code == 200, accepted.text

    # Guest without tenant Membership must still see their own authorized thread.
    profile = client.get("/api/v2/me", headers=guest)
    assert profile.status_code == 200, profile.text
    assert profile.json()["admin_access"] is False
    assert "thread_guest" in profile.json()["roles"]
    threads = client.get("/api/v2/threads", headers=guest)
    assert threads.status_code == 200, threads.text
    assert th in [item["id"] for item in threads.json()["items"]]

    own = client.get(f"/api/v2/threads/{th}/my-permissions", headers=guest)
    assert own.status_code == 200
    assert own.json()["allowed_agent_ids"] == ["orion"]
    assert own.json()["can_upload_files"] is False
    filtered = client.get(f"/api/v2/agents?thread_id={th}", headers=guest)
    assert filtered.status_code == 200, filtered.text
    assert [item["slug"] for item in filtered.json()] == ["orion"]

    forbidden = client.post(
        f"/api/v2/threads/{th}/stream",
        json={"content": "hi", "agent": "id:orkio"},
        headers=guest,
    )
    assert forbidden.status_code == 403
    assert "THREAD_AGENT_NOT_ALLOWED" in forbidden.text

    members = client.get(f"/api/v2/threads/{th}/participants", headers=owner)
    assert members.status_code == 200
    assert any(p["user_id"] == "user-2" for p in members.json())

    updated = client.put(
        f"/api/v2/threads/{th}/participants/user-2/permissions",
        json={
            "history_access": "full_thread",
            "allowed_agent_ids": ["orkio"],
            "can_upload_files": True,
        },
        headers=owner,
    )
    assert updated.status_code == 200, updated.text
    own2 = client.get(f"/api/v2/threads/{th}/my-permissions", headers=guest).json()
    assert own2["allowed_agent_ids"] == ["orkio"]
    assert own2["history_access"] == "full_thread"
    assert own2["can_upload_files"] is True

    unauthorized_change = client.put(
        f"/api/v2/threads/{th}/participants/user-1/permissions",
        json={"allowed_agent_ids": ["orion"]},
        headers=guest,
    )
    assert unauthorized_change.status_code == 403

    revoked = client.delete(f"/api/v2/threads/{th}/participants/user-2", headers=owner)
    assert revoked.status_code == 200, revoked.text
    assert client.get(f"/api/v2/threads/{th}/my-permissions", headers=guest).status_code == 403


def test_cross_tenant_access_does_not_reveal_participants(client):
    th = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    response = client.get(f"/api/v2/threads/{th}/participants", headers=headers(tenant="tenant-x"))
    assert response.status_code in (403, 404)
