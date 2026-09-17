import pytest

from conftest import headers
from orkio_v2.config import get_settings
from orkio_v2.services.agent_availability import (
    AvailabilityStatus,
    readiness_probe_for_id,
)
from orkio_v2.services.llm_contracts import (
    ProviderHealth,
    ProviderHealthState,
    ProviderName,
)
from orkio_v2.services.model_gateway import ModelGateway


@pytest.mark.asyncio
async def test_healthcheck_promotes_configured_agent_to_ready(monkeypatch):
    settings=get_settings()
    async def fake_healthcheck(self, requested=None):
        return ProviderHealth(
            ProviderName.openai,
            "gpt-5",
            ProviderHealthState.ready,
        )
    monkeypatch.setattr(ModelGateway, "healthcheck", fake_healthcheck)
    probe=await readiness_probe_for_id("chris", settings)
    assert probe.agent_id == "chris"
    assert probe.chat.status is AvailabilityStatus.READY
    assert probe.chat.eligible is True
    assert probe.chat.reason_code == "LLM_PRIMARY_PROVIDER_HEALTHY"
    assert probe.provider == "openai"
    assert probe.model == "gpt-5"


@pytest.mark.asyncio
async def test_healthcheck_unavailable_fails_closed(monkeypatch):
    settings=get_settings()
    async def fake_healthcheck(self, requested=None):
        return ProviderHealth(
            ProviderName.openai,
            "gpt-5",
            ProviderHealthState.unavailable,
            "LLM_PROVIDER_UNAVAILABLE",
        )
    monkeypatch.setattr(ModelGateway, "healthcheck", fake_healthcheck)
    probe=await readiness_probe_for_id("chris", settings)
    assert probe.chat.status is AvailabilityStatus.UNAVAILABLE
    assert probe.chat.eligible is False
    assert probe.chat.reason_code == "LLM_PROVIDER_UNAVAILABLE"


@pytest.mark.asyncio
async def test_healthcheck_unconfigured_never_becomes_ready(monkeypatch):
    settings=get_settings()
    async def fake_healthcheck(self, requested=None):
        return ProviderHealth(
            ProviderName.openai,
            "gpt-5",
            ProviderHealthState.unconfigured,
            "LLM_NOT_CONFIGURED",
        )
    monkeypatch.setattr(ModelGateway, "healthcheck", fake_healthcheck)
    probe=await readiness_probe_for_id("chris", settings)
    assert probe.chat.status is AvailabilityStatus.UNCONFIGURED
    assert probe.chat.eligible is False
    assert probe.chat.reason_code == "LLM_NOT_CONFIGURED"


def test_readiness_endpoint_requires_known_technical_id(client, monkeypatch):
    async def fake_healthcheck(self, requested=None):
        return ProviderHealth(
            ProviderName.openai,
            "gpt-5",
            ProviderHealthState.ready,
        )
    monkeypatch.setattr(ModelGateway, "healthcheck", fake_healthcheck)
    response=client.get("/api/v2/agents/by-id/chris/readiness", headers=headers())
    assert response.status_code == 200
    body=response.json()
    assert body["agent_id"] == "chris"
    assert body["chat"]["status"] == "READY"
    assert body["chat"]["eligible"] is True
    assert body["provider"] == "openai"
    assert body["model"] == "gpt-5"
    assert "checked_at" in body


def test_readiness_endpoint_does_not_use_natural_name_namespace(client, monkeypatch):
    async def fake_healthcheck(self, requested=None):
        return ProviderHealth(
            ProviderName.openai,
            "gpt-5",
            ProviderHealthState.ready,
        )
    monkeypatch.setattr(ModelGateway, "healthcheck", fake_healthcheck)
    # Explicit endpoint is technical-id only. Human names must not silently map here.
    response=client.get("/api/v2/agents/by-id/Josué/readiness", headers=headers())
    assert response.status_code == 404
    assert response.json()["detail"] == "AGENT_NOT_FOUND"


def test_health_endpoint_never_returns_secrets(client, monkeypatch):
    settings=get_settings()
    monkeypatch.setattr(settings, "openai_api_key", "super-secret-test-key", raising=False)

    async def fake_healthcheck(self, requested=None):
        return ProviderHealth(
            ProviderName.openai,
            "gpt-5",
            ProviderHealthState.unavailable,
            "LLM_PROVIDER_UNAVAILABLE",
        )
    monkeypatch.setattr(ModelGateway, "healthcheck", fake_healthcheck)
    response=client.get("/api/v2/agents/by-id/chris/readiness", headers=headers())
    text=response.text
    assert response.status_code == 200
    assert "super-secret-test-key" not in text
    assert "authorization" not in text.casefold()
    assert "token" not in text.casefold()
