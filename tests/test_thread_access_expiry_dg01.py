"""DG-01: finite collaboration grants and owner-managed renewal/revocation."""
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from conftest import Testing, headers
from orkio_v2.models import ThreadParticipant, ThreadInvitation, AuditEvent
from orkio_v2.schemas import InvitationCreate, ThreadParticipantAccessUpdate


def _invite_and_accept(client, *, hours=72):
    owner = headers()
    guest = headers(user="user-2", roles="admin")
    th = client.post("/api/v2/threads", json={"title": "Prazo controlado"}, headers=owner).json()["id"]
    response = client.post(
        f"/api/v2/threads/{th}/invitations",
        json={"email": "guest@example.com", "access_duration_hours": hours},
        headers=owner,
    )
    assert response.status_code == 200, response.text
    token = response.json()["invitation_url"].rsplit("/", 1)[-1]
    accepted = client.post("/api/v2/invitations/accept", json={"token": token}, headers=guest)
    assert accepted.status_code == 200, accepted.text
    return th, owner, guest


def test_access_duration_schema_bounded_and_explicit_unlimited():
    assert InvitationCreate(email="guest@example.com").access_duration_hours == 72
    assert InvitationCreate(email="guest@example.com", access_duration_hours=None).access_duration_hours is None
    for bad in [0, 8761, -8]:
        with pytest.raises(ValidationError):
            InvitationCreate(email="guest@example.com", access_duration_hours=bad)
            ThreadParticipantAccessUpdate(duration_hours=bad)


def test_default_guest_expires_and_is_rejected_even_by_human_message(client):
    th, owner, guest = _invite_and_accept(client)
    with Testing() as db:
        member = db.scalar(select(ThreadParticipant).where(ThreadParticipant.thread_id == th, ThreadParticipant.user_id == "user-2"))
        assert member.access_expires_at is not None
        member.access_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    assert client.get(f"/api/v2/threads/{th}/my-permissions", headers=guest).status_code == 403
    assert client.get(f"/api/v2/threads/{th}/messages", headers=guest).status_code == 403
    assert client.post(f"/api/v2/threads/{th}/human-messages", json={"content": "Teste"}, headers=guest).status_code == 403
    assert th not in [item["id"] for item in client.get("/api/v2/threads", headers=guest).json()["items"]]
    listed = client.get(f"/api/v2/threads/{th}/participants", headers=owner)
    assert listed.status_code == 200
    assert next(item for item in listed.json() if item["user_id"] == "user-2")["access_expired"] is True
    renewed = client.patch(f"/api/v2/threads/{th}/participants/user-2/access", json={"duration_hours": 168}, headers=owner)
    assert renewed.status_code == 200, renewed.text
    assert client.get(f"/api/v2/threads/{th}/my-permissions", headers=guest).status_code == 200
    assert client.delete(f"/api/v2/threads/{th}/participants/user-2", headers=owner).status_code == 200
    assert client.get(f"/api/v2/threads/{th}/my-permissions", headers=guest).status_code == 403


def test_only_owner_can_renew_and_legacy_guest_stays_unlimited(client):
    th, owner, guest = _invite_and_accept(client, hours=None)
    perm = client.get(f"/api/v2/threads/{th}/my-permissions", headers=guest)
    assert perm.status_code == 200
    assert perm.json()["access_expires_at"] is None
    assert client.patch(f"/api/v2/threads/{th}/participants/user-2/access", json={"duration_hours": 24}, headers=guest).status_code == 403
    assert client.patch(f"/api/v2/threads/{th}/participants/user-1/access", json={"duration_hours": 24}, headers=owner).status_code == 409
    assert client.patch(f"/api/v2/threads/{th}/participants/user-2/access", json={"duration_hours": 0}, headers=owner).status_code == 422
    response = client.patch(f"/api/v2/threads/{th}/participants/user-2/access", json={"duration_hours": 24}, headers=owner)
    assert response.status_code == 200, response.text
    with Testing() as db:
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "thread_participant_access_duration_updated", AuditEvent.resource_type == "thread_participant")) is not None
    forever = client.patch(f"/api/v2/threads/{th}/participants/user-2/access", json={"duration_hours": None}, headers=owner)
    assert forever.status_code == 200
    assert forever.json()["access_expires_at"] is None


def test_expired_grant_can_rejoin_only_using_new_admin_invitation(client):
    th, owner, guest = _invite_and_accept(client, hours=1)
    with Testing() as db:
        m = db.scalar(select(ThreadParticipant).where(ThreadParticipant.thread_id == th, ThreadParticipant.user_id == "user-2"))
        m.access_expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
    response = client.post(f"/api/v2/threads/{th}/invitations", json={"email": "guest@example.com", "access_duration_hours": 3}, headers=owner)
    assert response.status_code == 200, response.text
    token = response.json()["invitation_url"].rsplit("/", 1)[-1]
    assert client.post("/api/v2/invitations/accept", json={"token": token}, headers=guest).status_code == 200
    assert client.get(f"/api/v2/threads/{th}/my-permissions", headers=guest).status_code == 200


def test_other_tenant_cannot_renew_or_view_expired_guest(client):
    th, owner, _ = _invite_and_accept(client)
    cross = headers(tenant="tenant-x")
    r = client.patch(f"/api/v2/threads/{th}/participants/user-2/access", json={"duration_hours": 24}, headers=cross)
    assert r.status_code in (403, 404)
