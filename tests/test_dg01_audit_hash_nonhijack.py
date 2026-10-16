"""DG-01: documentary/web requests must not be misrouted as runtime hashes."""
from __future__ import annotations

import pytest

from orkio_v2.services.audit_natural_binding import resolve_natural_audit_binding


@pytest.mark.parametrize("message", [
    "Auditor, verifique se os agentes pesquisam fontes web autorizadas. "
    "Entregue depois os SHA-256 dos artefatos no handoff AO-01.",
    "Auditor, audite a pesquisa de fontes externas; anexe checksum dos relatórios.",
    "Auditor, verifique a distinção entre busca web e leitura integral de páginas. "
    "Inclua SHA256 no inventário de evidências e rollback.",
    "Auditor, investigue a integração web, documente o hash de saída.",
])
def test_web_and_documentary_hash_deliverable_does_not_hijack_audit(message):
    assert resolve_natural_audit_binding(message, resolved_agent_id="auditor") is None


@pytest.mark.parametrize("message", [
    "Audite o SHA-256 do módulo não autorizado em runtime.",
    "Verifique o hash do arquivo desconhecido em runtime.",
    "Inspecione o checksum do módulo inexistente.",
])
def test_explicit_unresolved_runtime_hash_fails_closed(message):
    result = resolve_natural_audit_binding(message, resolved_agent_id="auditor")
    assert result is not None
    assert result.error_code == "CAPABILITY_ARGUMENTS_REQUIRED"
    assert result.required_capability_id == "audit.runtime.file_sha256@1.0.0"


@pytest.mark.parametrize("message", [
    "Natã, audite o SHA-256 do módulo routes em runtime.",
    "Verifique o hash do módulo routes em runtime.",
])
def test_explicit_allowlisted_runtime_hash_remains_governed(message):
    result = resolve_natural_audit_binding(message, resolved_agent_id="auditor")
    assert result is not None and result.executable is True
    assert '"module_id":"routes"' in result.directive_message


def test_no_natural_binding_for_non_auditor():
    assert resolve_natural_audit_binding(
        "Audite o SHA-256 do módulo routes em runtime.",
        resolved_agent_id="orkio",
    ) is None


def test_auditor_explicit_web_search_is_not_preempted_by_documentary_sha(
    client, monkeypatch
):
    from conftest import headers
    from orkio_v2.config import get_settings
    from orkio_v2.services import llm, web_search as web
    from orkio_v2 import routes

    message = (
        "Pesquise na internet sobre fontes externas autorizadas. "
        "Auditor, verifique o resultado e apresente SHA-256 dos artefatos no relatório."
    )
    assert routes._resolve_audit_request(
        message, resolved_agent_id="auditor"
    ) == (False, None, None)
    assert web.explicit_search_query(message) is not None

    monkeypatch.setattr(
        get_settings(), "openai_api_key", "test-key-not-real", raising=False
    )
    invoked = []

    async def fake_search(**kwargs):
        invoked.append(kwargs)
        return web.normalize_brave(
            {"grounding": {"generic": [{
                "url": "https://example.org/research",
                "title": "Documentary source",
                "snippets": ["Example excerpt."],
            }]}}, "2026-10-16T12:00:00Z",
        )

    async def fake_generate(settings, agent, history):
        assert agent == "auditor"
        assert any("untrusted_external" in str(item) for item in history)
        return "Fonte consultada [S1]."

    async def forbidden_github(*args, **kwargs):
        raise AssertionError("a web turn cannot also fetch GitHub")

    monkeypatch.setattr(routes, "execute_explicit_web_search", fake_search)
    monkeypatch.setattr(routes, "github_context_messages", forbidden_github)
    monkeypatch.setattr(llm, "generate", fake_generate)
    thread_id = client.post(
        "/api/v2/threads", json={}, headers=headers()
    ).json()["id"]
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={"content": message, "agent": "Natã"},
        headers=headers(),
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["agent_id"] == "auditor"
    assert payload["web_search"]["status"] == "completed"
    assert len(invoked) == 1
    assert "Fontes consultadas" in payload["content"]
