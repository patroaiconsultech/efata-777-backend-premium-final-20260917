from __future__ import annotations

import json

import httpx
import pytest
from pydantic import ValidationError

from orkio_v2.config import Settings, get_settings
from orkio_v2.services import llm
from orkio_v2.services.founder_council import (
    FounderCouncilState,
    configured_status,
    healthchecked_status,
)
from orkio_v2.services.llm_contracts import (
    LLMNotConfigured,
    ProviderConfigurationState,
    ProviderHealth,
    ProviderHealthState,
    ProviderName,
)
from orkio_v2.services.model_gateway import ModelGateway
from orkio_v2.services import llm_providers


def test_openai_default_model_is_gpt5():
    settings = Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
        DATABASE_URL="sqlite+pysqlite:///:memory:",
    )
    assert settings.openai_model == "gpt-5"
    assert settings.llm_primary_provider == "openai"
    assert settings.google_model == "gemini-3.6-flash"


def test_optional_providers_do_not_crash_when_keys_are_absent(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "openai_api_key", "openai-test-key", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", None, raising=False)
    monkeypatch.setattr(settings, "google_api_key", None, raising=False)

    descriptors = {item.provider: item for item in ModelGateway(settings).descriptors()}
    assert descriptors[ProviderName.openai].state is ProviderConfigurationState.configured
    assert descriptors[ProviderName.anthropic].state is ProviderConfigurationState.unconfigured
    assert descriptors[ProviderName.google].state is ProviderConfigurationState.unconfigured


def test_primary_provider_is_explicit_and_no_silent_failover(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "openai_api_key", "openai-configured", raising=False)
    monkeypatch.setattr(settings, "llm_primary_provider", "anthropic", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", None, raising=False)

    with pytest.raises(LLMNotConfigured):
        ModelGateway(settings).ensure_configured()


def test_provider_becomes_configured_when_key_is_inserted(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "llm_primary_provider", "anthropic", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", "anthropic-test-key", raising=False)

    assert ModelGateway(settings).ensure_configured() == "anthropic-test-key"


def test_unsafe_auto_failover_and_auto_route_are_rejected():
    common = {
        "PLATFORM_ENVIRONMENT": "test",
        "PLATFORM_AUTH_MODE": "test",
        "PLATFORM_INVITATION_TOKEN_SECRET": "x" * 40,
        "DATABASE_URL": "sqlite+pysqlite:///:memory:",
    }
    with pytest.raises(ValidationError, match="LLM_PROVIDER_FAILOVER_FORBIDDEN_UNTIL_GOVERNED"):
        Settings(**common, PLATFORM_LLM_PROVIDER_FAILOVER_ENABLED=True)
    with pytest.raises(ValidationError, match="LLM_AUTO_ROUTE_FORBIDDEN_UNTIL_GOVERNED"):
        Settings(**common, PLATFORM_LLM_AUTO_ROUTE_ENABLED=True)


@pytest.mark.asyncio
async def test_openai_adapter_preserves_identity_and_usage(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "llm_primary_provider", "openai", raising=False)
    monkeypatch.setattr(settings, "openai_api_key", "openai-test-key", raising=False)
    monkeypatch.setattr(settings, "openai_model", "gpt-5", raising=False)

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/chat/completions")
        assert request.headers["authorization"] == "Bearer openai-test-key"
        payload = json.loads(request.content)
        assert payload["model"] == "gpt-5"
        assert "Seu nome nesta conversa é Natã." in payload["messages"][0]["content"]
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "Resposta auditada."}}],
                "usage": {
                    "prompt_tokens": 11,
                    "completion_tokens": 7,
                    "prompt_tokens_details": {"cached_tokens": 3},
                },
            },
        )

    original = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    monkeypatch.setattr(llm_providers.httpx, "AsyncClient", client_factory)
    result = await ModelGateway(settings).generate_result(
        "auditor", [{"role": "user", "content": "audite"}]
    )
    assert result.content == "Resposta auditada."
    assert result.provider is ProviderName.openai
    assert result.model == "gpt-5"
    assert result.usage.input_tokens == 11
    assert result.usage.output_tokens == 7
    assert result.usage.cached_input_tokens == 3


@pytest.mark.asyncio
async def test_anthropic_adapter_is_functional_after_key(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "llm_primary_provider", "anthropic", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", "anthropic-test-key", raising=False)
    monkeypatch.setattr(settings, "anthropic_model", "claude-sonnet-5", raising=False)

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/messages")
        assert request.headers["x-api-key"] == "anthropic-test-key"
        payload = json.loads(request.content)
        assert payload["model"] == "claude-sonnet-5"
        assert "Seu nome nesta conversa é Josué." in payload["system"]
        assert payload["messages"] == [{"role": "user", "content": "teste"}]
        return httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "Claude OK"}],
                "usage": {"input_tokens": 9, "output_tokens": 4},
            },
        )

    original = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    monkeypatch.setattr(llm_providers.httpx, "AsyncClient", client_factory)
    result = await ModelGateway(settings).generate_result(
        "orkio", [{"role": "user", "content": "teste"}]
    )
    assert result.content == "Claude OK"
    assert result.provider is ProviderName.anthropic
    assert result.usage.input_tokens == 9


@pytest.mark.asyncio
async def test_google_adapter_is_functional_after_key(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "llm_primary_provider", "google", raising=False)
    monkeypatch.setattr(settings, "google_api_key", "google-test-key", raising=False)
    monkeypatch.setattr(settings, "google_model", "gemini-3.6-flash", raising=False)

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/models/gemini-3.6-flash:generateContent")
        assert request.headers["x-goog-api-key"] == "google-test-key"
        assert "key" not in request.url.params
        payload = json.loads(request.content)
        assert "Seu nome nesta conversa é Josué." in payload["system_instruction"]["parts"][0]["text"]
        assert payload["contents"][0]["role"] == "user"
        return httpx.Response(
            200,
            json={
                "candidates": [{"content": {"parts": [{"text": "Gemini OK"}]}}],
                "usageMetadata": {
                    "promptTokenCount": 8,
                    "candidatesTokenCount": 3,
                    "cachedContentTokenCount": 2,
                },
            },
        )

    original = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    monkeypatch.setattr(llm_providers.httpx, "AsyncClient", client_factory)
    result = await ModelGateway(settings).generate_result(
        "orkio", [{"role": "user", "content": "teste"}]
    )
    assert result.content == "Gemini OK"
    assert result.provider is ProviderName.google
    assert result.usage.cached_input_tokens == 2


def test_founder_council_never_claims_consensus_with_one_provider(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "founder_council_enabled", True, raising=False)
    monkeypatch.setattr(settings, "founder_council_min_configured_providers", 2, raising=False)
    monkeypatch.setattr(settings, "openai_api_key", "openai-test-key", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", None, raising=False)
    monkeypatch.setattr(settings, "google_api_key", None, raising=False)

    status = configured_status(settings)
    assert status.state is FounderCouncilState.insufficient_configured_providers
    assert status.configured_providers == (ProviderName.openai,)


def test_founder_council_requires_healthcheck_before_ready(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "founder_council_enabled", True, raising=False)
    monkeypatch.setattr(settings, "founder_council_min_configured_providers", 2, raising=False)
    monkeypatch.setattr(settings, "openai_api_key", "openai-test-key", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", "anthropic-test-key", raising=False)
    monkeypatch.setattr(settings, "google_api_key", None, raising=False)

    status = configured_status(settings)
    assert status.state is FounderCouncilState.configured_pending_healthcheck
    assert status.configured_providers == (ProviderName.openai, ProviderName.anthropic)


def test_legacy_llm_payload_compatibility_uses_gpt5(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "openai_model", "gpt-5", raising=False)
    payload = llm._payload(
        settings,
        "orion",
        [{"role": "user", "content": "arquitetura"}],
        False,
    )
    assert payload["model"] == "gpt-5"
    assert payload["stream"] is False
    assert "Seu nome nesta conversa é Bezalel." in payload["messages"][0]["content"]


@pytest.mark.asyncio
async def test_anthropic_stream_parser(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "llm_primary_provider", "anthropic", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", "anthropic-test-key", raising=False)

    events = (
        'data: {"type":"message_start","message":{"id":"m"}}\n\n'
        'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Olá "}}\n\n'
        'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Claude"}}\n\n'
        'data: {"type":"message_stop"}\n\n'
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=events.encode(), headers={"content-type":"text/event-stream"})

    original = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    monkeypatch.setattr(llm_providers.httpx, "AsyncClient", client_factory)
    pieces = []
    async for piece in ModelGateway(settings).stream(
        "orkio", [{"role":"user","content":"teste"}]
    ):
        pieces.append(piece)
    assert pieces == ["Olá ", "Claude"]


@pytest.mark.asyncio
async def test_google_stream_parser(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "llm_primary_provider", "google", raising=False)
    monkeypatch.setattr(settings, "google_api_key", "google-test-key", raising=False)

    events = (
        'data: {"candidates":[{"content":{"parts":[{"text":"Olá "}]}}]}\n\n'
        'data: {"candidates":[{"content":{"parts":[{"text":"Gemini"}]}}]}\n\n'
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["alt"] == "sse"
        assert request.headers["x-goog-api-key"] == "google-test-key"
        assert "key" not in request.url.params
        return httpx.Response(200, content=events.encode(), headers={"content-type":"text/event-stream"})

    original = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    monkeypatch.setattr(llm_providers.httpx, "AsyncClient", client_factory)
    pieces = []
    async for piece in ModelGateway(settings).stream(
        "orkio", [{"role":"user","content":"teste"}]
    ):
        pieces.append(piece)
    assert pieces == ["Olá ", "Gemini"]



@pytest.mark.asyncio
async def test_google_healthcheck_keeps_api_key_out_of_url(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "google_api_key", "google-test-key", raising=False)
    monkeypatch.setattr(settings, "google_model", "gemini-3.6-flash", raising=False)

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/models/gemini-3.6-flash")
        assert request.headers["x-goog-api-key"] == "google-test-key"
        assert "key" not in request.url.params
        return httpx.Response(200, json={"name": "models/gemini-3.6-flash"})

    original = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    monkeypatch.setattr(llm_providers.httpx, "AsyncClient", client_factory)
    health = await ModelGateway(settings).healthcheck("google")
    assert health.state is ProviderHealthState.ready


def test_document_context_system_message_is_preserved_for_non_openai(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "anthropic_api_key", "anthropic-test-key", raising=False)
    provider = llm_providers.AnthropicProvider(settings)
    payload = provider._payload(
        "orkio",
        [
            {"role":"system","content":"CONTEXTO DOCUMENTAL"},
            {"role":"user","content":"analise"},
        ],
        stream=False,
    )
    assert "CONTEXTO DOCUMENTAL" in payload["system"]
    assert payload["messages"] == [{"role":"user","content":"analise"}]


@pytest.mark.asyncio
async def test_founder_council_healthcheck_blocks_fake_ready(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "founder_council_enabled", True, raising=False)
    monkeypatch.setattr(settings, "founder_council_min_configured_providers", 2, raising=False)
    monkeypatch.setattr(settings, "openai_api_key", "openai-test-key", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", "anthropic-test-key", raising=False)
    monkeypatch.setattr(settings, "google_api_key", None, raising=False)

    async def fake_healthcheck(self, requested=None):
        provider = ProviderName(requested)
        if provider is ProviderName.openai:
            return ProviderHealth(provider, "gpt-5", ProviderHealthState.ready)
        return ProviderHealth(
            provider,
            "claude-sonnet-5",
            ProviderHealthState.unavailable,
            "LLM_PROVIDER_UNAVAILABLE",
        )

    monkeypatch.setattr(ModelGateway, "healthcheck", fake_healthcheck)
    status = await healthchecked_status(settings)
    assert status.state is FounderCouncilState.insufficient_ready_providers
    assert status.ready_providers == (ProviderName.openai,)


@pytest.mark.asyncio
async def test_founder_council_ready_requires_two_healthchecked_providers(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "founder_council_enabled", True, raising=False)
    monkeypatch.setattr(settings, "founder_council_min_configured_providers", 2, raising=False)
    monkeypatch.setattr(settings, "openai_api_key", "openai-test-key", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", "anthropic-test-key", raising=False)
    monkeypatch.setattr(settings, "google_api_key", None, raising=False)

    async def fake_healthcheck(self, requested=None):
        provider = ProviderName(requested)
        model = "gpt-5" if provider is ProviderName.openai else "claude-sonnet-5"
        return ProviderHealth(provider, model, ProviderHealthState.ready)

    monkeypatch.setattr(ModelGateway, "healthcheck", fake_healthcheck)
    status = await healthchecked_status(settings)
    assert status.state is FounderCouncilState.ready_for_multi_model_review
    assert status.ready_providers == (ProviderName.openai, ProviderName.anthropic)
