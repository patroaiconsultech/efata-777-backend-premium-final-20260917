from __future__ import annotations

from dataclasses import replace

import pytest

from conftest import headers
from orkio_v2.config import get_settings
from orkio_v2.runtime.contracts import RuntimeChannel
from orkio_v2.runtime.identity import (
    OwnershipViolation,
    build_direct_turn_context,
    build_response_envelope,
    canonical_message,
)
from orkio_v2.services import llm
from orkio_v2.services.execution_router import resolve_direct_execution


@pytest.fixture()
def configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "openai_api_key", "test-key-not-real", raising=False)
    return get_settings()


def test_json_route_exposes_canonical_identity_and_persistence(client, configured, monkeypatch):
    async def fake_generate(settings, agent, history):
        assert agent == "chris"
        return "Resposta canônica."

    monkeypatch.setattr(llm, "generate", fake_generate)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "analise", "agent": "José"},
        headers=headers(),
    )
    assert response.status_code == 200
    body = response.json()

    assert body["agent_id"] == "chris"
    assert body["agent_name"] == "José — Chief Financial Officer"
    assert body["execution_id"]
    assert body["execution"]["execution_id"] == body["execution_id"]
    assert body["execution"]["resolved_target"] == "chris"
    assert body["execution"]["turn_owner"] == "chris"
    assert body["execution"]["display_agent_id"] == "chris"
    assert body["response"]["agent_id"] == "chris"
    assert body["response"]["final_speaker_agent_id"] == "chris"
    assert body["response"]["turn_owner_agent_id"] == "chris"

    stored = client.get(
        f"/api/v2/threads/{thread['id']}/messages",
        headers=headers(),
    ).json()
    assert stored[-1]["agent_id"] == "chris"
    assert stored[-1]["agent_name"] == "José — Chief Financial Officer"
    assert stored[-1]["content"] == body["content"]


def test_sse_route_has_same_canonical_identity_as_persistence(client, configured, monkeypatch):
    async def fake_stream(settings, agent, history):
        assert agent == "orion"
        yield "Resposta "
        yield "SSE."

    monkeypatch.setattr(llm, "stream", fake_stream)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/stream",
        json={"content": "arquitetura", "agent": "Bezalel"},
        headers=headers(),
    )
    assert response.status_code == 200
    assert '"agent_id": "orion"' in response.text
    assert '"display_agent_id": "orion"' in response.text
    assert '"turn_owner": "orion"' in response.text
    assert '"final_speaker_agent_id": "orion"' in response.text
    assert response.text.count("event: done") == 1

    stored = client.get(
        f"/api/v2/threads/{thread['id']}/messages",
        headers=headers(),
    ).json()
    assert stored[-1]["agent_id"] == "orion"
    assert stored[-1]["agent_name"] == "Bezalel — Chief Technology Officer"
    assert stored[-1]["content"] == "Resposta SSE."


def test_handoff_history_reclassifies_previous_agent_as_context(client, configured, monkeypatch):
    observed = []

    async def fake_generate(settings, agent, history):
        observed.append((agent, list(history)))
        return "Primeira." if agent == "orkio" else "Segunda."

    monkeypatch.setattr(llm, "generate", fake_generate)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    first = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "comece", "agent": "Josué"},
        headers=headers(),
    )
    assert first.status_code == 200

    second = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "José, continue", "agent": "José"},
        headers=headers(),
    )
    assert second.status_code == 200

    agent, history = observed[-1]
    assert agent == "chris"
    cross = [
        item
        for item in history
        if "CROSS_AGENT_CONTEXT_DATA" in item["content"]
    ]
    assert len(cross) == 1
    assert cross[0]["role"] == "user"
    assert '"source_agent_id":"orkio"' in cross[0]["content"]
    assert "Josué — Chief Executive Officer" in cross[0]["content"]
    assert "Primeira." in cross[0]["content"]
    assert not any(
        item["role"] == "assistant" and "Josué — Chief Executive Officer" in item["content"]
        for item in history
    )
    assert any(item["role"] == "user" and item["content"] == "José, continue" for item in history)


def test_response_envelope_rejects_poisoned_owner():
    execution = resolve_direct_execution("José")
    turn = build_direct_turn_context(
        execution=execution,
        thread_id="thread-1",
        tenant_id="tenant-1",
        user_id="user-1",
        requested_target="José",
        channel=RuntimeChannel.CHAT_JSON,
        request_id="req-1",
        execution_id="exec-1",
    )
    message = canonical_message(message_id="m1", context=turn, content="x")
    poisoned = replace(message, agent_id="orkio", agent_name="Josué — Chief Executive Officer")
    with pytest.raises(OwnershipViolation) as exc:
        build_response_envelope(context=turn, message=poisoned)
    assert str(exc.value) == "MESSAGE_OWNER_MISMATCH"


def test_list_messages_does_not_expose_user_id_as_agent_id(client):
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.get(
        f"/api/v2/threads/{thread['id']}/messages",
        headers=headers(),
    )
    assert response.status_code == 200
    assert response.json() == []


def test_auditor_to_orkio_history_never_promotes_nata_to_orkio_assistant_history(
    client, configured, monkeypatch
):
    observed = []

    async def fake_generate(settings, agent, history):
        observed.append((agent, list(history)))
        if agent == "auditor":
            return "Sou Natã, Auditor Técnico Independente."
        return "Josué — Chief Executive Officer"

    monkeypatch.setattr(llm, "generate", fake_generate)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    first = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "Faça uma auditoria.", "agent": "Natã"},
        headers=headers(),
    )
    assert first.status_code == 200
    assert first.json()["agent_id"] == "auditor"

    second = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "Responda somente com seu nome e sua função.", "agent": "Josué"},
        headers=headers(),
    )
    assert second.status_code == 200
    assert second.json()["agent_id"] == "orkio"
    assert second.json()["agent_name"] == "Josué — Chief Executive Officer"

    agent, history = observed[-1]
    assert agent == "orkio"
    nata_context = [
        item
        for item in history
        if "CROSS_AGENT_CONTEXT_DATA" in item["content"] and '"source_agent_id":"auditor"' in item["content"]
    ]
    assert len(nata_context) == 1
    assert nata_context[0]["role"] == "user"
    assert "Natã — Independent Technical Auditor" in nata_context[0]["content"]
    assert not any(
        item["role"] == "assistant" and "Natã — Independent Technical Auditor" in item["content"]
        for item in history
    )

    stored = client.get(
        f"/api/v2/threads/{thread['id']}/messages",
        headers=headers(),
    ).json()
    assert stored[-1]["agent_id"] == "orkio"
    assert stored[-1]["agent_name"] == "Josué — Chief Executive Officer"
