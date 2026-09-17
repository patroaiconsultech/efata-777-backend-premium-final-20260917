from __future__ import annotations

from collections.abc import AsyncIterator

from ..config import Settings
from .llm_contracts import (
    LLMResult,
    ProviderDescriptor,
    ProviderHealth,
    ProviderName,
)
from .llm_providers import AnthropicProvider, GoogleProvider, OpenAIProvider


class ModelGateway:
    """Gateway multi-provider sem failover silencioso.

    O provider efetivo é sempre explícito: o solicitado pela chamada ou o
    `PLATFORM_LLM_PRIMARY_PROVIDER`. Se esse provider não estiver configurado
    ou falhar, a execução falha de forma observável. Nenhum outro provider é
    acionado automaticamente.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self._providers = {
            ProviderName.openai: OpenAIProvider(settings),
            ProviderName.anthropic: AnthropicProvider(settings),
            ProviderName.google: GoogleProvider(settings),
        }

    def provider(self, requested: str | ProviderName | None = None):
        name = ProviderName(requested or self.settings.llm_primary_provider)
        return self._providers[name]

    def descriptors(self) -> tuple[ProviderDescriptor, ...]:
        return tuple(provider.descriptor() for provider in self._providers.values())

    def ensure_configured(self, requested: str | ProviderName | None = None) -> str:
        return self.provider(requested).ensure_configured()

    async def generate_result(
        self,
        agent: str,
        history: list[dict],
        *,
        provider: str | ProviderName | None = None,
    ) -> LLMResult:
        return await self.provider(provider).generate_result(agent, history)

    async def generate(
        self,
        agent: str,
        history: list[dict],
        *,
        provider: str | ProviderName | None = None,
    ) -> str:
        return (await self.generate_result(agent, history, provider=provider)).content

    async def stream(
        self,
        agent: str,
        history: list[dict],
        *,
        provider: str | ProviderName | None = None,
    ) -> AsyncIterator[str]:
        async for piece in self.provider(provider).stream(agent, history):
            yield piece

    async def healthcheck(
        self,
        requested: str | ProviderName | None = None,
    ) -> ProviderHealth:
        return await self.provider(requested).healthcheck()
