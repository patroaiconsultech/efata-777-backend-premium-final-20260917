from __future__ import annotations

import pytest

from conftest import headers
from orkio_v2.agents.registry import list_agents
from orkio_v2.config import get_settings
from orkio_v2.services import llm
from orkio_v2.services.agent_availability import (
    AvailabilityStatus,
    availability_for_id,
    readiness_probe_for_id,
)
from orkio_v2.services.execution_router import resolve_direct_execution
from orkio_v2.services.llm_contracts import ProviderHealth, ProviderHealthState, ProviderName, agent_system_prompt
from orkio_v2.services.model_gateway import ModelGateway
from orkio_v2.services.target_resolver import (
    TargetAmbiguous,
    TargetNotFound,
    resolve_target,
)


def test_all_33_canonical_identities_resolve_to_exact_agent_id():
    agents = list_agents()
    assert len(agents) == 33
    assert all(agent.founder_direct_access for agent in agents)
    for agent in agents:
        assert resolve_target(agent.canonical_name).agent_id == agent.slug


def test_all_role_codes_resolve_deterministically():
    for agent in list_agents():
        assert resolve_target(agent.role_code).agent_id == agent.slug


def test_pt_en_es_localized_names_resolve_from_exact_catalog_only():
    for agent in list_agents():
        assert set(agent.localized_names) == {"pt-BR", "en-US", "es-419"}
        for localized in agent.localized_names.values():
            assert resolve_target(localized).agent_id == agent.slug


def test_localized_role_labels_resolve():
    for agent in list_agents():
        for localized_role in agent.localized_role_labels.values():
            assert resolve_target(localized_role).agent_id == agent.slug


def test_explicit_technical_namespace_is_isolated():
    assert resolve_target("id:chris").agent_id == "chris"
    assert resolve_target("ID:ORION").agent_id == "orion"
    assert resolve_target(" id:adao ").agent_id == "adao"


def test_miguel_shadowing_is_explicit_and_safe():
    natural = resolve_target("Miguel")
    technical = resolve_target("id:miguel")
    assert natural.agent_id == "archangel_michael"
    assert technical.agent_id == "miguel"
    assert natural.agent_id != technical.agent_id


def test_gabriel_shadowing_is_explicit_and_safe():
    natural = resolve_target("Gabriel")
    technical = resolve_target("id:gabriel")
    assert natural.agent_id == "archangel_gabriel"
    assert technical.agent_id == "gabriel"
    assert natural.agent_id != technical.agent_id


@pytest.mark.parametrize("raw_id", ["chris", "orkio", "orion", "aurora"])
def test_raw_legacy_technical_ids_are_not_natural_aliases(raw_id):
    with pytest.raises(TargetNotFound):
        resolve_target(raw_id)


def test_unknown_target_fails_closed_without_josue_fallback():
    with pytest.raises(TargetNotFound) as exc:
        resolve_target("totally unknown target")
    assert exc.value.code == "TARGET_NOT_FOUND"


def test_ambiguous_specialty_fails_closed():
    with pytest.raises(TargetAmbiguous) as exc:
        resolve_target("software architecture")
    assert exc.value.code == "TARGET_AMBIGUOUS"
    assert set(exc.value.candidates) == {"miguel", "orion"}


def test_case_and_accent_normalization_are_deterministic():
    assert resolve_target("jOsÉ").agent_id == "chris"
    assert resolve_target("Jose").agent_id == "chris"
    assert resolve_target("JOSUE").agent_id == "orkio"
    assert resolve_target("NATAN").agent_id == "auditor"


def test_natural_phrase_resolution_uses_catalog_terms():
    assert resolve_target("quero falar com o CFO").agent_id == "chris"
    assert resolve_target("please call Joshua").agent_id == "orkio"
    assert resolve_target("quiero hablar con María").agent_id == "maria"




def test_agent_system_prompt_uses_catalog_identity_without_global_orkio_impersonation():
    system = agent_system_prompt("chris")
    assert "Seu nome nesta conversa é José." in system
    assert "Você opera como um agente da Plataforma Efatá 777." in system
    assert "Você é ORKIO" not in system
    assert "no idioma solicitado" in system

def test_registered_is_not_ready_without_provider_configuration(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "llm_primary_provider", "openai", raising=False)
    monkeypatch.setattr(settings, "openai_api_key", None, raising=False)
    snap = availability_for_id("chris", settings)
    assert snap.registered is True
    assert snap.chat.status is AvailabilityStatus.UNCONFIGURED
    assert snap.chat.status is not AvailabilityStatus.READY
    assert snap.chat.eligible is False


@pytest.mark.asyncio
async def test_resolved_agent_can_be_runtime_unavailable_without_identity_change(monkeypatch):
    resolution = resolve_target("José")
    assert resolution.agent_id == "chris"

    async def fake_healthcheck(self, requested=None):
        return ProviderHealth(
            ProviderName.openai,
            "gpt-5",
            ProviderHealthState.unavailable,
            "LLM_PROVIDER_UNAVAILABLE",
        )

    monkeypatch.setattr(ModelGateway, "healthcheck", fake_healthcheck)
    probe = await readiness_probe_for_id(resolution.agent_id, get_settings())
    assert probe.agent_id == "chris"
    assert probe.chat.status is AvailabilityStatus.UNAVAILABLE
    assert probe.chat.eligible is False


def test_ownership_lock_preserves_resolved_agent():
    execution = resolve_direct_execution("José")
    assert execution.resolved_target == "chris"
    assert execution.turn_owner == "chris"
    assert execution.display_agent == "José — Chief Financial Officer"
    assert execution.ownership_locked is True
    assert execution.execution_engine.value == "direct_agent"


def test_direct_agent_selection_beats_team_words_in_message(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "openai_api_key", "test-key-not-real", raising=False)

    async def fake_generate(settings, agent, history):
        assert agent == "chris"
        return "Resposta direta."

    monkeypatch.setattr(llm, "generate", fake_generate)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={
            "content": "Estou numa sala Team. Mesmo assim quero José diretamente.",
            "agent": "José",
        },
        headers=headers(),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["execution"]["turn_owner"] == "chris"
    assert body["execution"]["execution_engine"] == "direct_agent"
    assert body["execution"]["ownership_locked"] is True


def test_unknown_team_text_does_not_silently_downgrade_to_josue(client):
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "oi", "agent": "Team Supremo Desconhecido"},
        headers=headers(),
    )
    assert response.status_code == 404
    assert response.json()["detail"] == {"code": "TARGET_NOT_FOUND"}


def test_tenant_isolation_precedes_agent_execution(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "openai_api_key", "test-key-not-real", raising=False)

    async def fake_generate(*_args, **_kwargs):
        pytest.fail("LLM must not execute across tenant boundary")

    monkeypatch.setattr(llm, "generate", fake_generate)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "oi", "agent": "José"},
        headers=headers(tenant="tenant-other"),
    )
    assert response.status_code in {401, 403, 404}


def test_json_persistence_identity_matches_resolver(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "openai_api_key", "test-key-not-real", raising=False)

    async def fake_generate(settings, agent, history):
        assert agent == "chris"
        return "Persistência canônica."

    monkeypatch.setattr(llm, "generate", fake_generate)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "analise", "agent": "Joseph"},
        headers=headers(),
    )
    assert response.status_code == 200
    body = response.json()
    stored = client.get(f"/api/v2/threads/{thread['id']}/messages", headers=headers()).json()[-1]
    assert body["agent_id"] == "chris"
    assert body["execution"]["resolved_target"] == "chris"
    assert body["execution"]["turn_owner"] == "chris"
    assert body["response"]["agent_id"] == "chris"
    assert body["response"]["final_speaker_agent_id"] == "chris"
    assert stored["agent_id"] == "chris"


def test_json_sse_identity_parity_for_same_agent(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "openai_api_key", "test-key-not-real", raising=False)

    async def fake_generate(settings, agent, history):
        assert agent == "chris"
        return "JSON."

    async def fake_stream(settings, agent, history):
        assert agent == "chris"
        yield "SSE."

    monkeypatch.setattr(llm, "generate", fake_generate)
    thread_json = client.post("/api/v2/threads", json={}, headers=headers()).json()
    json_response = client.post(
        f"/api/v2/threads/{thread_json['id']}/messages",
        json={"content": "um", "agent": "José"},
        headers=headers(),
    )
    assert json_response.status_code == 200

    monkeypatch.setattr(llm, "stream", fake_stream)
    thread_sse = client.post("/api/v2/threads", json={}, headers=headers()).json()
    sse_response = client.post(
        f"/api/v2/threads/{thread_sse['id']}/stream",
        json={"content": "dois", "agent": "Joseph"},
        headers=headers(),
    )
    assert sse_response.status_code == 200
    assert sse_response.text.count("event: done") == 1
    assert '"agent_id": "chris"' in sse_response.text
    assert '"turn_owner": "chris"' in sse_response.text
    assert json_response.json()["agent_id"] == "chris"


def test_regression_display_executor_divergence_is_closed():
    execution = resolve_direct_execution("José")
    assert execution.resolved_target == execution.turn_owner == "chris"
    assert execution.display_agent.startswith("José")


def test_regression_public_fastpath_precedence_is_closed():
    execution = resolve_direct_execution("quero falar com o CFO")
    assert execution.resolved_target == "chris"
    assert execution.turn_owner == "chris"
    assert execution.ownership_locked is True
