import pytest

from orkio_v2.agents.registry import resolve_agent_by_id
from orkio_v2.config import get_settings
from orkio_v2.services.agent_availability import (
    AgentCapabilityUnavailable,
    AvailabilityStatus,
    availability_for,
    availability_for_id,
    require_chat_eligible,
)


def test_registered_does_not_mean_ready(monkeypatch):
    settings=get_settings()
    monkeypatch.setattr(settings, "llm_primary_provider", "openai", raising=False)
    monkeypatch.setattr(settings, "openai_api_key", None, raising=False)
    snap=availability_for_id("chris", settings)
    assert snap.registered is True
    assert snap.enabled is True
    assert snap.chat.status is AvailabilityStatus.UNCONFIGURED
    assert snap.chat.eligible is False


def test_configured_provider_is_not_falsely_promoted_to_ready(monkeypatch):
    settings=get_settings()
    monkeypatch.setattr(settings, "llm_primary_provider", "openai", raising=False)
    monkeypatch.setattr(settings, "openai_api_key", "test-key", raising=False)
    snap=availability_for_id("chris", settings)
    assert snap.chat.status is AvailabilityStatus.CONFIGURED
    assert snap.chat.eligible is True
    assert snap.chat.status is not AvailabilityStatus.READY
    assert snap.chat.reason_code == "LLM_PRIMARY_PROVIDER_CONFIGURED_NOT_HEALTHCHECKED"


def test_team_engine_is_bound_while_realtime_voice_and_tools_remain_fail_closed(monkeypatch):
    settings=get_settings()
    monkeypatch.setattr(settings, "openai_api_key", "test-key", raising=False)
    snap=availability_for_id("chris", settings)
    assert snap.team.eligible is True
    assert snap.team.status is AvailabilityStatus.CONFIGURED
    assert snap.team.reason_code == "TEAM_ENGINE_BOUND_PROVIDER_NOT_HEALTHCHECKED"
    assert snap.team.status is not AvailabilityStatus.READY
    assert snap.realtime.eligible is False
    assert snap.realtime.reason_code == "REALTIME_AGENT_SESSION_NOT_BOUND"
    assert snap.voice_playback.eligible is False
    assert snap.voice_message.eligible is False
    assert snap.tools.eligible is False


def test_global_voice_switch_does_not_make_agent_voice_ready(monkeypatch):
    settings=get_settings()
    monkeypatch.setattr(settings, "voice_enabled", True, raising=False)
    monkeypatch.setattr(settings, "voice_provider", "provider-test", raising=False)
    snap=availability_for_id("chris", settings)
    assert snap.voice_playback.status is AvailabilityStatus.UNCONFIGURED
    assert snap.voice_playback.reason_code == "AGENT_VOICE_BINDING_NOT_VALIDATED"
    assert snap.voice_playback.eligible is False


def test_require_chat_eligible_rejects_unconfigured(monkeypatch):
    settings=get_settings()
    monkeypatch.setattr(settings, "llm_primary_provider", "openai", raising=False)
    monkeypatch.setattr(settings, "openai_api_key", None, raising=False)
    with pytest.raises(AgentCapabilityUnavailable) as exc:
        require_chat_eligible("chris", settings)
    assert exc.value.agent_id == "chris"
    assert exc.value.capability == "chat"
    assert exc.value.reason_code == "LLM_PRIMARY_PROVIDER_UNCONFIGURED"


def test_availability_is_name_independent(monkeypatch):
    settings=get_settings()
    monkeypatch.setattr(settings, "openai_api_key", "test-key", raising=False)
    agent=resolve_agent_by_id("chris")
    snap=availability_for(agent, settings)
    assert snap.agent_id == "chris"
    assert "José" not in str(snap.to_dict())


def test_agents_api_exposes_fail_closed_availability(client, monkeypatch):
    settings=get_settings()
    monkeypatch.setattr(settings, "openai_api_key", None, raising=False)
    from conftest import headers
    response=client.get("/api/v2/agents", headers=headers())
    assert response.status_code == 200
    first=response.json()[0]
    assert "availability" in first
    availability=first["availability"]
    assert availability["registered"] is True
    assert availability["chat"]["status"] == "UNCONFIGURED"
    assert availability["chat"]["eligible"] is False
    assert availability["team"]["eligible"] is False
    assert availability["realtime"]["eligible"] is False
