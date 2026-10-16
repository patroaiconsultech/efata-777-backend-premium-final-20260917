"""AO-01 reproduction: revocation during Team SSE must stop later disclosure."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import select
from conftest import Testing, headers
from orkio_v2.auth import Principal
from orkio_v2.config import get_settings
from orkio_v2.models import ThreadParticipant
from orkio_v2.services import llm
from orkio_v2.team_routes import TeamMessageCreate, stream_team_message


@pytest.mark.asyncio
async def test_team_revocation_stops_next_sensitive_chunk(client, monkeypatch):
    owner = headers()
    th = client.post("/api/v2/threads", json={}, headers=owner).json()["id"]
    invited = client.post(f"/api/v2/threads/{th}/invitations", headers=owner, json={
        "email": "guest@example.com", "allowed_agent_ids": ["orkio", "chris", "orion"],
        "access_duration_hours": 72
    })
    assert invited.status_code == 200, invited.text
    token = invited.json()["invitation_url"].rsplit("/", 1)[-1]
    guest = headers(user="user-2", roles="admin")
    accepted = client.post("/api/v2/invitations/accept", json={"token": token}, headers=guest)
    assert accepted.status_code == 200, accepted.text

    settings = get_settings()
    monkeypatch.setattr(settings, "openai_api_key", "test-key-not-real", raising=False)
    monkeypatch.setattr(settings, "llm_primary_provider", "openai", raising=False)
    monkeypatch.setattr(settings, "realtime_streaming_enabled", True, raising=False)

    async def fake_stream(*_args):
        yield "CONTEUDO_SENSIVEL_APOS_REVOGACAO"
    monkeypatch.setattr(llm, "stream", fake_stream)
    principal = Principal(user_id="user-2", tenant_id="tenant-1", roles=("member",),
                          email="guest@example.com", external_subject="sub-2")
    with Testing() as db:
        resp = await stream_team_message(
            thread_id=th,
            payload=TeamMessageCreate(content="Analise", team_id="general_team",
                                      contributor_agent_ids=["chris", "orion"]),
            p=principal, settings=settings, db=db,
        )
        stream = resp.body_iterator
        first = await anext(stream)
        assert "team_started" in first
        second = await anext(stream)
        assert "agent_started" in second
        assert client.delete(f"/api/v2/threads/{th}/participants/user-2", headers=owner).status_code == 200
        remaining = []
        async for chunk in stream:
            remaining.append(chunk)
    rendered = "".join(remaining)
    assert "CONTEUDO_SENSIVEL_APOS_REVOGACAO" not in rendered, rendered
    assert "THREAD_ACCESS_DENIED" in rendered or "THREAD_ACCESS_REVOKED" in rendered


@pytest.mark.asyncio
async def test_expiration_interrupts_stream_before_next_piece(client):
    from orkio_v2.services.active_stream_access import guard_sse_stream, snapshot_grant
    th = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    with Testing() as db:
        original = db.scalar(select(ThreadParticipant).where(
            ThreadParticipant.thread_id == th,
            ThreadParticipant.user_id == "user-1"))
        snapshot = snapshot_grant(original)
        bind = db.get_bind()

    async def source():
        yield 'event: chunk\ndata: {"text":"VISIBLE_BEFORE_EXPIRY"}\n\n'
        yield 'event: chunk\ndata: {"text":"HIDDEN_AFTER_EXPIRY"}\n\n'

    stream = guard_sse_stream(
        source(), bind=bind, thread_id=th, tenant_id="tenant-1",
        user_id="user-1", expected_grant=snapshot,
        agent_ids=("orkio",), is_admin=True,
    )
    assert "VISIBLE_BEFORE_EXPIRY" in await anext(stream)
    with Testing() as db:
        member = db.scalar(select(ThreadParticipant).where(
            ThreadParticipant.thread_id == th, ThreadParticipant.user_id == "user-1"))
        member.access_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    remaining = [part async for part in stream]
    assert "HIDDEN_AFTER_EXPIRY" not in "".join(remaining)
    assert "THREAD_ACCESS_EXPIRED" in "".join(remaining)


@pytest.mark.asyncio
async def test_grant_change_interrupts_in_flight_stream(client):
    from orkio_v2.services.active_stream_access import guard_sse_stream, snapshot_grant
    th = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    with Testing() as db:
        original = db.scalar(select(ThreadParticipant).where(
            ThreadParticipant.thread_id == th, ThreadParticipant.user_id == "user-1"))
        snapshot = snapshot_grant(original)
        bind = db.get_bind()

    async def source():
        yield "event: chunk\\ndata: first\\n\\n"
        yield "event: chunk\\ndata: should-never-appear\\n\\n"

    stream = guard_sse_stream(
        source(), bind=bind, thread_id=th, tenant_id="tenant-1",
        user_id="user-1", expected_grant=snapshot,
        agent_ids=("orkio",), is_admin=True,
    )
    assert "first" in await anext(stream)
    with Testing() as db:
        member = db.scalar(select(ThreadParticipant).where(
            ThreadParticipant.thread_id == th, ThreadParticipant.user_id == "user-1"))
        member.can_view_attachments = not bool(member.can_view_attachments)
        db.commit()
    result = "".join([part async for part in stream])
    assert "should-never-appear" not in result
    assert "THREAD_GRANT_CHANGED" in result


@pytest.mark.asyncio
async def test_realtime_stream_revocation_stops_text_deltas(client, monkeypatch):
    import orkio_v2.realtime_routes as rt
    from orkio_v2.realtime_routes import RealtimeFinalTranscript, realtime_stream_turn
    th = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    invited = client.post(f"/api/v2/threads/{th}/invitations", headers=headers(), json={
        "email": "guest@example.com", "allowed_agent_ids": ["orkio"]
    })
    assert invited.status_code == 200
    token = invited.json()["invitation_url"].rsplit("/", 1)[-1]
    assert client.post("/api/v2/invitations/accept", headers=headers(user="user-2", roles="admin"),
                       json={"token": token}).status_code == 200
    settings = get_settings()
    monkeypatch.setattr(settings, "realtime_bridge_enabled", True, raising=False)
    monkeypatch.setattr(settings, "tts_enabled", True, raising=False)
    monkeypatch.setattr(rt, "_session_intent", lambda *a, **k: {"target_mode": "direct", "agent_id": "orkio"})
    monkeypatch.setattr(rt, "resolve_voice_profile", lambda *a, **k: object())
    monkeypatch.setattr(rt, "load_receipt", lambda *a, **k: None)
    monkeypatch.setattr(rt, "reserve_receipt", lambda *a, **k: None)

    async def fake_realtime(*_a, **_kw):
        yield {"type": "turn_started", "turn_id": "turn-1"}
        yield {"type": "text_delta", "turn_id": "turn-1", "text": "SECRET_AFTER_REVOKE"}

    monkeypatch.setattr(rt, "stream_realtime_direct", fake_realtime)
    principal = Principal(user_id="user-2", tenant_id="tenant-1", roles=("member",),
                          email="guest@example.com", external_subject="sub-2")
    with Testing() as db:
        resp = await realtime_stream_turn(
            thread_id=th,
            payload=RealtimeFinalTranscript(session_id="session-1", provider_item_id="item-1",
                                           transcript_final_id="final-1", transcript="oi"),
            p=principal, settings=settings, db=db,
        )
        stream = resp.body_iterator
        assert "turn_started" in await anext(stream)
        assert client.delete(f"/api/v2/threads/{th}/participants/user-2",
                             headers=headers()).status_code == 200
        remaining = "".join([part async for part in stream])
    assert "SECRET_AFTER_REVOKE" not in remaining
    assert "THREAD_ACCESS_DENIED" in remaining
