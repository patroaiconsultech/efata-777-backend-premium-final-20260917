from __future__ import annotations

import asyncio
import json

import pytest
from sqlalchemy import select

from conftest import Testing, headers
from orkio_v2.auth import Principal
from orkio_v2.config import get_settings
from orkio_v2.models import AuditEvent, Message, ThreadParticipant, ThreadRole
from orkio_v2.services import llm
from orkio_v2.team_routes import TeamMessageCreate, stream_team_message


def _events(text: str) -> list[tuple[str, dict]]:
    result: list[tuple[str, dict]] = []
    for block in text.strip().split("\n\n"):
        if not block.strip():
            continue
        event = "message"
        data_lines: list[str] = []
        for line in block.splitlines():
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].strip())
        if not data_lines:
            continue
        result.append((event, json.loads("\n".join(data_lines))))
    return result


@pytest.fixture()
def team_configured(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "openai_api_key", "test-key-not-real", raising=False)
    monkeypatch.setattr(settings, "llm_primary_provider", "openai", raising=False)
    monkeypatch.setattr(settings, "realtime_streaming_enabled", True, raising=False)
    return settings


def test_team_catalog_is_backend_driven(client):
    response = client.get("/api/v2/teams", headers=headers())
    assert response.status_code == 200
    teams = {item["team_id"]: item for item in response.json()}
    assert {"executive_team", "general_team", "founder_executive_council"} <= set(teams)
    assert teams["general_team"]["orchestrator_agent_id"] == "orkio"
    assert "chris" in teams["general_team"]["candidate_agent_ids"]
    assert teams["general_team"]["max_delegation_depth"] == 1


def test_team_stream_executes_multiple_agents_persists_provenance_and_terminates(
    client, team_configured, monkeypatch
):
    async def fake_stream(settings, agent, history):
        if agent == "chris":
            yield "Financeiro."
        elif agent == "orion":
            yield "Tecnologia."
        elif agent == "orkio":
            assert any("ContextContribution" in item["content"] for item in history)
            yield "Síntese "
            yield "final."
        else:
            pytest.fail(f"unexpected agent {agent}")

    monkeypatch.setattr(llm, "stream", fake_stream)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/team/stream",
        json={
            "content": "Analise em Team.",
            "team_id": "general_team",
            "orchestrator_agent_id": "orkio",
            "participant_agent_ids": ["orkio", "chris", "orion"],
        },
        headers=headers(),
    )
    assert response.status_code == 200
    events = _events(response.text)
    names = [kind for kind, _ in events]
    assert names[0] == "status"
    assert names[-1] == "done"
    assert names.count("done") == 1
    assert "agent_started" in names
    assert "agent_chunk" in names
    assert "agent_done" in names
    assert "chunk" in names

    first = events[0][1]
    assert first["status"] == "team_started"
    assert first["orchestrator_agent_id"] == "orkio"
    assert first["participant_agent_ids"] == ["orkio", "chris", "orion"]
    assert first["ownership_locked"] is True

    final = events[-1][1]
    assert final["status"] == "completed"
    assert final["agent_id"] == "orkio"
    assert final["turn_owner"] == "orkio"
    assert final["ownership_locked"] is True
    assert set(final["completed_agent_ids"]) == {"chris", "orion"}
    assert final["failed_agent_ids"] == []

    stored = client.get(
        f"/api/v2/threads/{thread['id']}/messages",
        headers=headers(),
    ).json()
    agent_messages = [item for item in stored if item["author_type"] == "agent"]
    assert [item["agent_id"] for item in agent_messages] == ["chris", "orion", "orkio"]
    assert agent_messages[-1]["content"] == "Síntese final."

    with Testing() as db:
        rows = db.scalars(select(AuditEvent)).all()
    actions = {
        row.action
        for row in rows
        if isinstance(row.metadata_json, dict)
        and row.metadata_json.get("thread_id") == thread["id"]
    }
    assert {
        "team_mode_requested",
        "team_authorized",
        "orchestration_started",
        "team_agent_started",
        "team_agent_completed",
        "team_completed",
    } <= actions


def test_team_rejects_duplicate_participant_before_execution(
    client, team_configured, monkeypatch
):
    async def must_not_run(*_args, **_kwargs):
        pytest.fail("LLM must not execute")

    monkeypatch.setattr(llm, "stream", must_not_run)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/team/stream",
        json={
            "content": "x",
            "team_id": "general_team",
            "orchestrator_agent_id": "orkio",
            "participant_agent_ids": ["orkio", "orkio"],
        },
        headers=headers(),
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "TEAM_DUPLICATE_PARTICIPANT"


def test_team_rejects_agent_outside_selected_team(
    client, team_configured, monkeypatch
):
    async def must_not_run(*_args, **_kwargs):
        pytest.fail("LLM must not execute")

    monkeypatch.setattr(llm, "stream", must_not_run)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/team/stream",
        json={
            "content": "x",
            "team_id": "executive_team",
            "orchestrator_agent_id": "orkio",
            "participant_agent_ids": ["orkio", "chris", "auditor"],
        },
        headers=headers(),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == {
        "code": "TEAM_AGENT_NOT_ALLOWED",
        "agent_id": "auditor",
    }


def test_team_rejects_invalid_agent(client, team_configured, monkeypatch):
    async def must_not_run(*_args, **_kwargs):
        pytest.fail("LLM must not execute")

    monkeypatch.setattr(llm, "stream", must_not_run)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/team/stream",
        json={
            "content": "x",
            "team_id": "general_team",
            "orchestrator_agent_id": "orkio",
            "participant_agent_ids": ["orkio", "chris", "not-an-agent"],
        },
        headers=headers(),
    )
    assert response.status_code in {403, 404}
    assert response.json()["detail"]["code"] in {"TEAM_AGENT_NOT_ALLOWED", "TEAM_AGENT_NOT_FOUND"}


def test_team_viewer_cannot_execute(client, team_configured, monkeypatch):
    async def must_not_run(*_args, **_kwargs):
        pytest.fail("LLM must not execute")

    monkeypatch.setattr(llm, "stream", must_not_run)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    with Testing() as db:
        member = db.scalar(
            select(ThreadParticipant).where(
                ThreadParticipant.thread_id == thread["id"],
                ThreadParticipant.user_id == "user-1",
            )
        )
        member.thread_role = ThreadRole.viewer.value
        db.commit()

    response = client.post(
        f"/api/v2/threads/{thread['id']}/team/stream",
        json={
            "content": "x",
            "team_id": "general_team",
            "orchestrator_agent_id": "orkio",
            "participant_agent_ids": ["orkio", "chris"],
        },
        headers=headers(),
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "THREAD_READ_ONLY"

    with Testing() as db:
        member = db.scalar(
            select(ThreadParticipant).where(
                ThreadParticipant.thread_id == thread["id"],
                ThreadParticipant.user_id == "user-1",
            )
        )
        member.thread_role = ThreadRole.owner.value
        db.commit()


def test_team_partial_agent_failure_still_synthesizes_and_unlocks(
    client, team_configured, monkeypatch
):
    async def fake_stream(settings, agent, history):
        if agent == "chris":
            raise llm.LLMUpstreamError("simulated")
        if agent == "orion":
            yield "Contribuição válida."
            return
        if agent == "orkio":
            yield "Consolidado."
            return
        pytest.fail(f"unexpected {agent}")

    monkeypatch.setattr(llm, "stream", fake_stream)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/team/stream",
        json={
            "content": "x",
            "team_id": "general_team",
            "orchestrator_agent_id": "orkio",
            "participant_agent_ids": ["orkio", "chris", "orion"],
        },
        headers=headers(),
    )
    assert response.status_code == 200
    events = _events(response.text)
    assert events[-1][0] == "done"
    assert events[-1][1]["status"] == "completed"
    assert events[-1][1]["completed_agent_ids"] == ["orion"]
    assert events[-1][1]["failed_agent_ids"] == ["chris"]
    failed = [
        data for kind, data in events
        if kind == "agent_done" and data.get("agent_id") == "chris"
    ]
    assert failed and failed[0]["status"] == "failed"


def test_team_complete_contributor_failure_emits_error_then_done(
    client, team_configured, monkeypatch
):
    async def fail_stream(settings, agent, history):
        if False:
            yield ""
        raise llm.LLMUpstreamError("simulated")

    monkeypatch.setattr(llm, "stream", fail_stream)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/team/stream",
        json={
            "content": "x",
            "team_id": "general_team",
            "orchestrator_agent_id": "orkio",
            "participant_agent_ids": ["orkio", "chris", "orion"],
        },
        headers=headers(),
    )
    assert response.status_code == 200
    events = _events(response.text)
    assert [kind for kind, _ in events][-2:] == ["error", "done"]
    assert events[-2][1]["code"] == "TEAM_ALL_CONTRIBUTORS_FAILED"
    assert events[-1][1]["status"] == "failed"


def test_team_tenant_isolation_precedes_execution(
    client, team_configured, monkeypatch
):
    async def must_not_run(*_args, **_kwargs):
        pytest.fail("LLM must not execute across tenant boundary")
        if False:
            yield ""

    monkeypatch.setattr(llm, "stream", must_not_run)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/team/stream",
        json={
            "content": "x",
            "team_id": "general_team",
            "orchestrator_agent_id": "orkio",
            "participant_agent_ids": ["orkio", "chris"],
        },
        headers=headers(tenant="tenant-other"),
    )
    assert response.status_code in {401, 403, 404}


@pytest.mark.asyncio
async def test_team_cancelled_generator_records_cancel_without_terminal_fabrication(
    client, team_configured, monkeypatch
):
    async def slow_stream(settings, agent, history):
        yield "primeiro"
        await asyncio.sleep(0)

    monkeypatch.setattr(llm, "stream", slow_stream)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()

    # Build an explicit provisioned principal already backed by the fixture data.
    principal = Principal(
        user_id="user-1",
        tenant_id="tenant-1",
        roles=("admin",),
        email="owner@example.com",
        external_subject="sub-1",
    )
    with Testing() as db:
        response = await stream_team_message(
            thread_id=thread["id"],
            payload=TeamMessageCreate(
                content="cancel",
                team_id="general_team",
                orchestrator_agent_id="orkio",
                participant_agent_ids=["orkio", "chris", "orion"],
            ),
            p=principal,
            settings=team_configured,
            db=db,
        )
        generator = response.body_iterator
        await anext(generator)  # team_started
        with pytest.raises(asyncio.CancelledError):
            await generator.athrow(asyncio.CancelledError())

    with Testing() as db:
        rows = db.scalars(select(AuditEvent)).all()
    cancelled = [
        row for row in rows
        if row.action == "team_failed"
        and row.outcome == "cancelled"
        and isinstance(row.metadata_json, dict)
        and row.metadata_json.get("thread_id") == thread["id"]
    ]
    assert cancelled

def test_team_rejects_client_selected_orchestrator_before_execution(
    client, team_configured, monkeypatch
):
    async def must_not_run(*_args, **_kwargs):
        pytest.fail("LLM must not execute when browser attempts to replace Team chair")
        if False:
            yield ""

    monkeypatch.setattr(llm, "stream", must_not_run)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/team/stream",
        json={
            "content": "x",
            "team_id": "general_team",
            "orchestrator_agent_id": "chris",
            "participant_agent_ids": ["orkio", "chris"],
        },
        headers=headers(),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == {
        "code": "TEAM_ORCHESTRATOR_NOT_ALLOWED",
        "agent_id": "chris",
    }

