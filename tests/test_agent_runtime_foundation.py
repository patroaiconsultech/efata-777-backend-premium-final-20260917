import pytest

from conftest import headers
from orkio_v2.agents.registry import AgentNotFound, resolve_agent_by_id
from orkio_v2.services.execution_router import resolve_direct_execution
from orkio_v2.services.target_resolver import TargetNotFound, resolve_target
from orkio_v2.services import llm
from orkio_v2.config import get_settings


def test_registry_resolves_technical_id_only():
    assert resolve_agent_by_id("chris").canonical_name == "José"
    assert resolve_agent_by_id("ORION").slug == "orion"
    with pytest.raises(AgentNotFound):
        resolve_agent_by_id("José")


def test_target_resolver_rejects_unknown_without_fallback():
    with pytest.raises(TargetNotFound):
        resolve_target("unknown-agent")


def test_router_locks_direct_owner():
    ctx = resolve_direct_execution("José")
    assert ctx.resolved_target == "chris"
    assert ctx.turn_owner == "chris"
    assert ctx.display_agent == "José — Chief Financial Officer"
    assert ctx.execution_engine.value == "direct_agent"
    assert ctx.ownership_locked is True


def test_llm_payload_uses_resolved_agent_identity():
    payload = llm._payload(get_settings(), "auditor", [{"role": "user", "content": "audite"}], False)
    system = payload["messages"][0]["content"]
    assert "Seu nome nesta conversa é Natã." in system
    assert "Auditar de forma independente" in system


def test_agents_catalog_is_authenticated(client):
    response = client.get("/api/v2/agents", headers=headers())
    assert response.status_code == 200
    items = response.json()
    slugs = {item["slug"] for item in items}
    assert len(items) == 33
    assert {"orkio", "auditor", "chris", "orion", "security", "adao"} <= slugs
    jose = next(item for item in items if item["slug"] == "chris")
    assert jose["canonical_name"] == "José"
    assert jose["localized_names"]["en-US"] == "Joseph"


def test_json_path_persists_resolved_agent(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "openai_api_key", "test-key-not-real", raising=False)
    seen = {}

    async def fake_generate(settings, agent, history):
        seen["agent"] = agent
        return "Diagnóstico."

    monkeypatch.setattr(llm, "generate", fake_generate)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "analise", "agent": "José"}, headers=headers(),
    )
    assert response.status_code == 200
    assert seen["agent"] == "chris"
    assert response.json()["agent_name"] == "José — Chief Financial Officer"
    assert response.json()["execution"]["turn_owner"] == "chris"
    stored = client.get(f"/api/v2/threads/{thread['id']}/messages", headers=headers()).json()
    assert stored[-1]["agent_name"] == "José — Chief Financial Officer"


def test_sse_path_persists_resolved_agent(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "openai_api_key", "test-key-not-real", raising=False)
    seen = {}

    async def fake_stream(settings, agent, history):
        seen["agent"] = agent
        yield "Resposta Bezalel."

    monkeypatch.setattr(llm, "stream", fake_stream)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/stream",
        json={"content": "arquitetura", "agent": "Bezalel"}, headers=headers(),
    )
    assert response.status_code == 200
    assert seen["agent"] == "orion"
    assert '"agent_name": "Bezalel — Chief Technology Officer"' in response.text
    assert '"ownership_locked": true' in response.text
    stored = client.get(f"/api/v2/threads/{thread['id']}/messages", headers=headers()).json()
    assert stored[-1]["agent_name"] == "Bezalel — Chief Technology Officer"


def test_unknown_agent_is_typed_rejection(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "openai_api_key", "test-key-not-real", raising=False)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "oi", "agent": "not-real"}, headers=headers(),
    )
    assert response.status_code == 404
    assert response.json()["detail"] == {"code": "TARGET_NOT_FOUND"}
