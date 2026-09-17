"""Prova do caminho de sucesso da integração de LLM.

Estes testes só executam quando ORKIO_LIVE_LLM_TEST=1 e uma
OPENAI_API_KEY real estiver disponível. Não rodam em CI por padrão, para
não gerar custo nem depender de rede.

Objetivo: provar que a resposta persistida vem do provedor e não de texto
demonstrativo, e que o SSE emite chunk seguido de done com message_id.
"""

import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("ORKIO_LIVE_LLM_TEST") != "1",
    reason="Teste de integração real desabilitado. Defina ORKIO_LIVE_LLM_TEST=1.",
)


def _events(raw: str) -> list[str]:
    return [line.removeprefix("event: ").strip() for line in raw.splitlines() if line.startswith("event: ")]


def test_live_message_returns_real_answer(live_client, live_headers):
    thread = live_client.post("/api/v2/threads", json={"title": "Live"}, headers=live_headers).json()
    response = live_client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "Responda apenas com a palavra OK."},
        headers=live_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["content"].strip()
    assert "Integração LLM será usada" not in body["content"]

    stored = live_client.get(f"/api/v2/threads/{thread['id']}/messages", headers=live_headers).json()
    assert len(stored) == 2
    assert stored[0]["author_type"] == "user"
    assert stored[1]["author_type"] == "agent"
    assert stored[1]["content"] == body["content"]


def test_live_stream_emits_chunks_then_done(live_client, live_headers):
    thread = live_client.post("/api/v2/threads", json={"title": "Live SSE"}, headers=live_headers).json()
    response = live_client.post(
        f"/api/v2/threads/{thread['id']}/stream",
        json={"content": "Conte de 1 a 3, apenas os números."},
        headers=live_headers,
    )
    events = _events(response.text)
    assert events[0] == "status"
    assert "chunk" in events
    assert events[-1] == "done"
    assert "error" not in events
    assert "message_id" in response.text

    stored = live_client.get(f"/api/v2/threads/{thread['id']}/messages", headers=live_headers).json()
    assert any(message["author_type"] == "agent" for message in stored)
