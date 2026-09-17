from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..config import Settings
from .llm_contracts import ProviderConfigurationState, ProviderHealthState, ProviderName
from .model_gateway import ModelGateway


class FounderCouncilState(str, Enum):
    disabled = "DISABLED"
    insufficient_configured_providers = "INSUFFICIENT_CONFIGURED_PROVIDERS"
    configured_pending_healthcheck = "CONFIGURED_PENDING_HEALTHCHECK"
    insufficient_ready_providers = "INSUFFICIENT_READY_PROVIDERS"
    ready_for_multi_model_review = "READY_FOR_MULTI_MODEL_REVIEW"


@dataclass(frozen=True)
class FounderCouncilStatus:
    state: FounderCouncilState
    configured_providers: tuple[ProviderName, ...]
    ready_providers: tuple[ProviderName, ...] = ()


def configured_status(settings: Settings) -> FounderCouncilStatus:
    """Status sem rede. Nunca chama `CONFIGURED` de consenso/READY."""
    if not settings.founder_council_enabled:
        return FounderCouncilStatus(FounderCouncilState.disabled, ())
    gateway = ModelGateway(settings)
    configured = tuple(
        descriptor.provider
        for descriptor in gateway.descriptors()
        if descriptor.state is ProviderConfigurationState.configured
    )
    if len(configured) < settings.founder_council_min_configured_providers:
        return FounderCouncilStatus(
            FounderCouncilState.insufficient_configured_providers,
            configured,
        )
    return FounderCouncilStatus(
        FounderCouncilState.configured_pending_healthcheck,
        configured,
    )


async def healthchecked_status(settings: Settings) -> FounderCouncilStatus:
    """Prova readiness de providers antes de declarar council multi-model."""
    status = configured_status(settings)
    if status.state in {
        FounderCouncilState.disabled,
        FounderCouncilState.insufficient_configured_providers,
    }:
        return status

    gateway = ModelGateway(settings)
    ready: list[ProviderName] = []
    for provider in status.configured_providers:
        health = await gateway.healthcheck(provider)
        if health.state is ProviderHealthState.ready:
            ready.append(provider)

    if len(ready) < settings.founder_council_min_configured_providers:
        return FounderCouncilStatus(
            FounderCouncilState.insufficient_ready_providers,
            status.configured_providers,
            tuple(ready),
        )
    return FounderCouncilStatus(
        FounderCouncilState.ready_for_multi_model_review,
        status.configured_providers,
        tuple(ready),
    )
