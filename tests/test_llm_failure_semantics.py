"""Semântica de falha do provedor de LLM.

Estes testes fixam decisões que o smoke revelou não estarem explícitas:

1. Quando o provedor falha, a mensagem do usuário é preservada. Perder o
   que a pessoa escreveu é pior do que ter mensagem sem resposta.
2. Nenhuma mensagem de agente é gravada em caso de falha, para que o
   histórico nunca contenha resposta fabricada.
3. A URL base do provedor é configurável, permitindo gateway corporativo.
"""

import pytest
from conftest import headers

from orkio_v2.config import get_settings
from orkio_v2.services import llm


@pytest.fixture()
def configured(monkeypatch):
    """Simula chave presente sem realizar chamada de rede."""
    monkeypatch.setattr(get_settings(), "openai_api_key", "test-key-not-real", raising=False)
    return get_settings()


def test_endpoint_defaults_to_official_api(configured):
    assert llm._endpoint(configured).endswith("/chat/completions")
    assert llm._endpoint(configured).startswith("https://api.openai.com/v1")


def test_endpoint_honours_custom_base(configured, monkeypatch):
    monkeypatch.setattr(configured, "openai_api_base", "https://gateway.interno/v1/", raising=False)
    assert llm._endpoint(configured) == "https://gateway.interno/v1/chat/completions"


def test_ensure_configured_rejects_blank(monkeypatch):
    monkeypatch.setattr(get_settings(), "openai_api_key", "   ", raising=False)
    with pytest.raises(llm.LLMNotConfigured):
        llm.ensure_configured(get_settings())


def test_upstream_failure_preserves_user_message(client, configured, monkeypatch):
    """Decisão documentada: a mensagem do usuário sobrevive à falha."""

    async def boom(*args, **kwargs):
        raise llm.LLMUpstreamError("LLM_UPSTREAM_ERROR")

    monkeypatch.setattr(llm, "generate", boom)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "pergunta importante"},
        headers=headers(),
    )
    assert response.status_code == 502
    assert response.json()["detail"] == "LLM_UPSTREAM_ERROR"

    stored = client.get(f"/api/v2/threads/{thread['id']}/messages", headers=headers()).json()
    assert len(stored) == 1
    assert stored[0]["author_type"] == "user"
    assert stored[0]["content"] == "pergunta importante"


def test_upstream_failure_persists_no_agent_message(client, configured, monkeypatch):
    async def boom(*args, **kwargs):
        raise llm.LLMUpstreamError("LLM_UPSTREAM_ERROR")

    monkeypatch.setattr(llm, "generate", boom)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    client.post(f"/api/v2/threads/{thread['id']}/messages", json={"content": "oi"}, headers=headers())
    stored = client.get(f"/api/v2/threads/{thread['id']}/messages", headers=headers()).json()
    assert all(item["author_type"] != "agent" for item in stored)


def test_stream_failure_emits_error_then_done(client, configured, monkeypatch):
    async def boom(*args, **kwargs):
        raise llm.LLMUpstreamError("LLM_UPSTREAM_ERROR")
        yield ""  # pragma: no cover

    monkeypatch.setattr(llm, "stream", boom)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/stream",
        json={"content": "oi"},
        headers=headers(),
    )
    events = [
        line.removeprefix("event: ").strip()
        for line in response.text.splitlines()
        if line.startswith("event: ")
    ]
    assert "error" in events
    assert events[-1] == "done"
    assert "LLM_UPSTREAM_ERROR" in response.text


def test_stream_failure_persists_no_agent_message(client, configured, monkeypatch):
    async def boom(*args, **kwargs):
        raise llm.LLMUpstreamError("LLM_UPSTREAM_ERROR")
        yield ""  # pragma: no cover

    monkeypatch.setattr(llm, "stream", boom)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    client.post(f"/api/v2/threads/{thread['id']}/stream", json={"content": "oi"}, headers=headers())
    stored = client.get(f"/api/v2/threads/{thread['id']}/messages", headers=headers()).json()
    assert all(item["author_type"] != "agent" for item in stored)


def test_stream_success_persists_agent_message(client, configured, monkeypatch):
    """Caminho de sucesso com provedor simulado: persiste e devolve message_id."""

    async def fake_stream(*args, **kwargs):
        for piece in ["Res", "posta ", "real."]:
            yield piece

    monkeypatch.setattr(llm, "stream", fake_stream)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/stream",
        json={"content": "oi"},
        headers=headers(),
    )
    assert "event: chunk" in response.text
    assert "message_id" in response.text
    assert "event: error" not in response.text

    stored = client.get(f"/api/v2/threads/{thread['id']}/messages", headers=headers()).json()
    agent = [item for item in stored if item["author_type"] == "agent"]
    assert len(agent) == 1
    assert agent[0]["content"] == "Resposta real."


def test_message_success_persists_pair(client, configured, monkeypatch):
    async def fake_generate(*args, **kwargs):
        return "Resposta do agente."

    monkeypatch.setattr(llm, "generate", fake_generate)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "pergunta"},
        headers=headers(),
    )
    assert response.status_code == 200
    assert response.json()["content"] == "Resposta do agente."

    stored = client.get(f"/api/v2/threads/{thread['id']}/messages", headers=headers()).json()
    assert [item["author_type"] for item in stored] == ["user", "agent"]
    assert stored[1]["content"] == "Resposta do agente."


def test_empty_response_is_treated_as_failure(client, configured, monkeypatch):
    async def empty_stream(*args, **kwargs):
        yield "   "

    monkeypatch.setattr(llm, "stream", empty_stream)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/stream",
        json={"content": "oi"},
        headers=headers(),
    )
    assert "LLM_EMPTY_RESPONSE" in response.text
    stored = client.get(f"/api/v2/threads/{thread['id']}/messages", headers=headers()).json()
    assert all(item["author_type"] != "agent" for item in stored)
