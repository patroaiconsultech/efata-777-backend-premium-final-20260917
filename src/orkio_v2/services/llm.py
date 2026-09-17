"""Facade canônica de LLM da Plataforma Efatá 777.

Compatibilidade:
- mantém `generate`, `stream`, `ensure_configured`, `_endpoint` e `_payload`;
- preserva o contrato dos caminhos JSON/SSE existentes;
- delega execução ao ModelGateway multi-provider.

Governança:
- provider primário é explícito via PLATFORM_LLM_PRIMARY_PROVIDER;
- não existe failover silencioso;
- providers sem key permanecem UNCONFIGURED sem derrubar a aplicação.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from ..config import Settings
from .llm_contracts import (
    LLMNotConfigured,
    LLMUpstreamError,
    SYSTEM_PROMPT,
)
from .llm_providers import (
    DEFAULT_OPENAI_BASE,
    OpenAIProvider,
    openai_endpoint,
    openai_payload,
)
from .model_gateway import ModelGateway


CANONICAL_AGENT_ID = "orkio"
CANONICAL_AGENT_NAME = "Josué"


def _endpoint(settings: Settings) -> str:
    """Compatibilidade: endpoint OpenAI Chat Completions atual."""
    return openai_endpoint(settings)


def _payload(settings: Settings, agent: str, history: list[dict], stream: bool) -> dict:
    """Compatibilidade: payload OpenAI atual, usado também por testes existentes."""
    return openai_payload(settings, agent, history, stream)


def ensure_configured(settings: Settings) -> str:
    """Garante que o provider primário está configurado.

    Retorna a key apenas por compatibilidade interna com o contrato anterior.
    A key nunca é registrada nem exposta em resposta.
    """
    return ModelGateway(settings).ensure_configured()


async def generate(settings: Settings, agent: str, history: list[dict]) -> str:
    """Gera resposta completa pelo provider primário explicitamente configurado."""
    return await ModelGateway(settings).generate(agent, history)


async def stream(settings: Settings, agent: str, history: list[dict]) -> AsyncIterator[str]:
    """Emite chunks pelo provider primário, sem fallback silencioso."""
    async for piece in ModelGateway(settings).stream(agent, history):
        yield piece
