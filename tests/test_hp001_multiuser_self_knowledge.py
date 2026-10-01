from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from conftest import Testing
from orkio_v2.config import Settings, get_settings
from orkio_v2.models import Membership, Message, Tenant, ThreadParticipant, User
from orkio_v2.services import github_integration as gh


def _ids():
    suffix = uuid4().hex[:10]
    return {
        "tenant": f"tenant-hp-{suffix}",
        "owner": f"owner-hp-{suffix}",
        "guest": f"guest-hp-{suffix}",
        "outsider": f"outsider-hp-{suffix}",
        "other_tenant": f"tenant-other-{suffix}",
        "cross": f"cross-hp-{suffix}",
        "pending": f"pending-hp-{suffix}",
        "suffix": suffix,
    }


def _headers(*, user_id: str, tenant_id: str, subject: str, email: str, roles: str = "member"):
    return {
        "X-Test-User": user_id,
        "X-Test-Tenant": tenant_id,
        "X-Test-Roles": roles,
        "X-Test-Email": email,
        "X-Test-Subject": subject,
    }


def _bootstrap_people(ids: dict[str, str]):
    emails = {
        "owner": f"owner-{ids['suffix']}@example.com",
        "guest": f"guest-{ids['suffix']}@example.com",
        "outsider": f"outsider-{ids['suffix']}@example.com",
        "cross": f"cross-{ids['suffix']}@example.com",
        "pending": f"pending-{ids['suffix']}@example.com",
    }
    subjects = {key: f"sub-{value}" for key, value in ids.items() if key in emails}
    with Testing() as db:
        db.add(Tenant(id=ids["tenant"], name="HP tenant"))
        db.add(Tenant(id=ids["other_tenant"], name="HP other tenant"))
        for key in ("owner", "guest", "outsider", "cross", "pending"):
            tenant_id = ids["other_tenant"] if key == "cross" else ids["tenant"]
            del tenant_id  # User is global; tenant authority comes from Membership/participant.
            db.add(
                User(
                    id=ids[key],
                    external_subject=subjects[key],
                    email=emails[key],
                    display_name=key.title(),
                )
            )
        db.add(Membership(tenant_id=ids["tenant"], user_id=ids["owner"], role="admin", active=True))
        db.add(Membership(tenant_id=ids["tenant"], user_id=ids["outsider"], role="member", active=True))
        db.add(Membership(tenant_id=ids["other_tenant"], user_id=ids["cross"], role="member", active=True))
        db.commit()
    return emails, subjects


def test_hp001_external_guest_from_join_send_revoke_and_reinvite(client, monkeypatch):
    ids = _ids()
    emails, subjects = _bootstrap_people(ids)
    owner_h = _headers(
        user_id=ids["owner"],
        tenant_id=ids["tenant"],
        subject=subjects["owner"],
        email=emails["owner"],
        roles="not-trusted-admin-claim",
    )
    # The guest deliberately claims admin. Canonical collaboration identity must strip it.
    guest_h = _headers(
        user_id=ids["guest"],
        tenant_id=ids["tenant"],
        subject=subjects["guest"],
        email=emails["guest"],
        roles="admin,superadmin",
    )
    outsider_h = _headers(
        user_id=ids["outsider"],
        tenant_id=ids["tenant"],
        subject=subjects["outsider"],
        email=emails["outsider"],
    )
    cross_h = _headers(
        user_id=ids["cross"],
        tenant_id=ids["other_tenant"],
        subject=subjects["cross"],
        email=emails["cross"],
    )

    thread_r = client.post("/api/v2/threads", json={"title": "HP-001"}, headers=owner_h)
    assert thread_r.status_code == 200, thread_r.text
    thread_id = thread_r.json()["id"]

    old_text = f"before-join-{ids['suffix']}"
    after_text = f"after-join-{ids['suffix']}"
    with Testing() as db:
        db.add(
            Message(
                tenant_id=ids["tenant"],
                thread_id=thread_id,
                author_type="user",
                author_id=ids["owner"],
                content=old_text,
                created_at=datetime.now(timezone.utc) - timedelta(days=1),
            )
        )
        db.commit()

    invite = client.post(
        f"/api/v2/threads/{thread_id}/invitations",
        json={
            "email": emails["guest"],
            "role": "participant",
            "history_access": "from_join",
        },
        headers=owner_h,
    )
    assert invite.status_code == 200, invite.text
    token = invite.json()["invitation_url"].rsplit("/", 1)[-1]

    accepted = client.post("/api/v2/invitations/accept", json={"token": token}, headers=guest_h)
    assert accepted.status_code == 200, accepted.text

    # Membership is intentionally absent: access comes only from external_guest participation.
    with Testing() as db:
        assert db.scalar(
            __import__("sqlalchemy").select(Membership).where(
                Membership.tenant_id == ids["tenant"],
                Membership.user_id == ids["guest"],
            )
        ) is None
        participant = db.scalar(
            __import__("sqlalchemy").select(ThreadParticipant).where(
                ThreadParticipant.tenant_id == ids["tenant"],
                ThreadParticipant.thread_id == thread_id,
                ThreadParticipant.user_id == ids["guest"],
            )
        )
        assert participant is not None
        assert participant.membership_type == "external_guest"
        assert participant.active is True
        assert participant.history_access == "from_join"
        joined_at = participant.joined_at
        db.add(
            Message(
                tenant_id=ids["tenant"],
                thread_id=thread_id,
                author_type="user",
                author_id=ids["owner"],
                content=after_text,
                created_at=joined_at + timedelta(seconds=1),
            )
        )
        db.commit()

    listed = client.get("/api/v2/threads", headers=guest_h)
    assert listed.status_code == 200, listed.text
    assert thread_id in {item["id"] for item in listed.json()["items"]}

    history = client.get(f"/api/v2/threads/{thread_id}/messages", headers=guest_h)
    assert history.status_code == 200, history.text
    bodies = [item["content"] for item in history.json()]
    assert old_text not in bodies
    assert after_text in bodies
    owner_message = next(item for item in history.json() if item["content"] == after_text)
    assert owner_message["author_id"] == ids["owner"]
    assert owner_message["user_id"] == ids["owner"]

    # Same-tenant Membership alone is not thread authority; cross-tenant fails closed.
    assert client.get(f"/api/v2/threads/{thread_id}/messages", headers=outsider_h).status_code == 403
    assert client.get(f"/api/v2/threads/{thread_id}/messages", headers=cross_h).status_code == 404

    captured: list[list[dict[str, str]]] = []
    settings = get_settings()
    monkeypatch.setattr(settings, "openai_api_key", "hp001-not-real", raising=False)

    async def fake_generate(_settings, _agent_id, messages):
        captured.append(list(messages))
        return "ok-hp001"

    from orkio_v2 import routes as routes_module

    monkeypatch.setattr(routes_module.llm, "generate", fake_generate)
    sent = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={"content": f"guest-send-{ids['suffix']}"},
        headers=guest_h,
    )
    assert sent.status_code == 200, sent.text
    assert captured
    serialized = "\n".join(item.get("content", "") for item in captured[-1])
    assert old_text not in serialized
    assert after_text in serialized
    assert f"[HumanUser id:{ids['owner']}]" in serialized
    # The current principal remains the canonical user role; other humans are labelled.
    assert f"guest-send-{ids['suffix']}" in serialized

    # Active participants cannot accumulate a fresh pending grant.
    active_reinvite = client.post(
        f"/api/v2/threads/{thread_id}/invitations",
        json={"email": emails["guest"], "role": "participant"},
        headers=owner_h,
    )
    assert active_reinvite.status_code == 409
    assert active_reinvite.json()["detail"] == "THREAD_PARTICIPANT_ALREADY_ACTIVE"

    revoked = client.post(
        f"/api/v2/threads/{thread_id}/participants/{ids['guest']}/revoke",
        headers=owner_h,
    )
    assert revoked.status_code == 200, revoked.text
    assert client.get(f"/api/v2/threads/{thread_id}/messages", headers=guest_h).status_code == 403

    # The already-consumed token cannot reactivate a revoked user.
    stale = client.post("/api/v2/invitations/accept", json={"token": token}, headers=guest_h)
    assert stale.status_code == 409

    fresh = client.post(
        f"/api/v2/threads/{thread_id}/invitations",
        json={"email": emails["guest"], "role": "participant", "history_access": "from_join"},
        headers=owner_h,
    )
    assert fresh.status_code == 200, fresh.text
    fresh_token = fresh.json()["invitation_url"].rsplit("/", 1)[-1]
    fresh_accept = client.post(
        "/api/v2/invitations/accept",
        json={"token": fresh_token},
        headers=guest_h,
    )
    assert fresh_accept.status_code == 200, fresh_accept.text

    with Testing() as db:
        participant = db.scalar(
            __import__("sqlalchemy").select(ThreadParticipant).where(
                ThreadParticipant.tenant_id == ids["tenant"],
                ThreadParticipant.thread_id == thread_id,
                ThreadParticipant.user_id == ids["guest"],
            )
        )
        assert participant is not None and participant.active
        # Rejoin is a new grant; old history remains outside from_join.
        assert participant.joined_at >= joined_at

    # Duplicate pending invite is explicitly rejected.
    first_pending = client.post(
        f"/api/v2/threads/{thread_id}/invitations",
        json={"email": emails["pending"], "role": "viewer"},
        headers=owner_h,
    )
    assert first_pending.status_code == 200, first_pending.text
    duplicate_pending = client.post(
        f"/api/v2/threads/{thread_id}/invitations",
        json={"email": emails["pending"], "role": "viewer"},
        headers=owner_h,
    )
    assert duplicate_pending.status_code == 409
    assert duplicate_pending.json()["detail"] == "INVITATION_ALREADY_PENDING"


def test_hp001_generic_efata_analysis_selects_server_allowlist():
    settings = Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 32,
        PLATFORM_GITHUB_INTEGRATION_ENABLED="true",
        PLATFORM_GITHUB_READ_ONLY="true",
        PLATFORM_GITHUB_ALLOWED_REPOSITORIES=(
            "patroaiconsultech/efata-777-backend-premium-final-20260917,"
            "patroaiconsultech/efata-777-frontend-premium-final-20260917"
        ),
    )
    assert gh.requested_repositories_from_message(settings, "Analise a EFATÀ.") == (
        "patroaiconsultech/efata-777-backend-premium-final-20260917",
        "patroaiconsultech/efata-777-frontend-premium-final-20260917",
    )


def test_hp001_inactive_membership_cannot_fallback_to_thread_guest(client):
    ids = _ids()
    emails, subjects = _bootstrap_people(ids)
    principal_h = _headers(
        user_id=ids["outsider"],
        tenant_id=ids["tenant"],
        subject=subjects["outsider"],
        email=emails["outsider"],
    )
    owner_h = _headers(
        user_id=ids["owner"],
        tenant_id=ids["tenant"],
        subject=subjects["owner"],
        email=emails["owner"],
    )
    thread = client.post("/api/v2/threads", json={"title": "revoked-membership"}, headers=owner_h).json()
    with Testing() as db:
        membership = db.scalar(
            __import__("sqlalchemy").select(Membership).where(
                Membership.tenant_id == ids["tenant"],
                Membership.user_id == ids["outsider"],
            )
        )
        membership.active = False
        db.add(
            ThreadParticipant(
                tenant_id=ids["tenant"],
                thread_id=thread["id"],
                user_id=ids["outsider"],
                membership_type="external_guest",
                thread_role="participant",
                active=True,
            )
        )
        db.commit()

    denied = client.get(f"/api/v2/threads/{thread['id']}/messages", headers=principal_h)
    assert denied.status_code == 403
    assert denied.json()["detail"] == "PRINCIPAL_NOT_PROVISIONED"


@pytest.mark.asyncio
async def test_hp001_team_evidence_preflight_reaches_specialists_and_synthesis(client, monkeypatch):
    ids = _ids()
    emails, subjects = _bootstrap_people(ids)
    owner_h = _headers(
        user_id=ids["owner"],
        tenant_id=ids["tenant"],
        subject=subjects["owner"],
        email=emails["owner"],
        roles="bogus-client-role",
    )
    thread_r = client.post("/api/v2/threads", json={"title": "self-knowledge"}, headers=owner_h)
    assert thread_r.status_code == 200, thread_r.text
    thread_id = thread_r.json()["id"]

    settings = get_settings()
    monkeypatch.setattr(settings, "openai_api_key", "hp001-not-real", raising=False)
    monkeypatch.setattr(settings, "realtime_streaming_enabled", True, raising=False)

    from orkio_v2 import team_routes as team_routes_module

    async def fake_github(_settings, *, message, is_admin):
        assert message == "Analise a EFATÀ."
        # Effective admin must come from Membership, not the bogus client role.
        assert is_admin is True
        return [{"role": "user", "content": "EVIDENCE_GITHUB source_ref=repo@sha"}]

    async def fake_capabilities(**kwargs):
        assert kwargs["tenant_id"] == ids["tenant"]
        assert kwargs["user_id"] == ids["owner"]
        assert kwargs["thread_id"] == thread_id
        return [{"role": "system", "content": "EVIDENCE_CAPABILITY capability_id=github.read"}]

    histories: list[tuple[str, list[dict[str, str]]]] = []

    async def fake_stream(_settings, agent_id, messages):
        histories.append((agent_id, list(messages)))
        yield f"answer-{agent_id}"

    monkeypatch.setattr(team_routes_module, "github_context_messages", fake_github)
    monkeypatch.setattr(team_routes_module, "runtime_capability_messages", fake_capabilities)
    monkeypatch.setattr(team_routes_module.llm, "stream", fake_stream)

    response = client.post(
        f"/api/v2/threads/{thread_id}/team/stream",
        json={
            "content": "Analise a EFATÀ.",
            "team_id": "general_team",
            "selection_mode": "explicit",
            "contributor_agent_ids": ["chris", "orion"],
        },
        headers=owner_h,
    )
    assert response.status_code == 200, response.text
    assert len(histories) >= 3  # two specialists plus chair synthesis
    for _agent, history in histories[:2]:
        merged = "\n".join(item.get("content", "") for item in history)
        assert "EVIDENCE_GITHUB" in merged
        assert "EVIDENCE_CAPABILITY" in merged
    synthesis = "\n".join(item.get("content", "") for item in histories[-1][1])
    assert "EVIDENCE_GITHUB" in synthesis
    assert "EVIDENCE_CAPABILITY" in synthesis
