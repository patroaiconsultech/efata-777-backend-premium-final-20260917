from datetime import datetime, timezone

import pytest

from orkio_v2.config import Settings
from orkio_v2.runtime.contracts import (
    CanonicalTurnContext,
    RuntimeChannel,
    RuntimeRouteFamily,
)
from orkio_v2.runtime.orchestration import (
    AgentConsultRequest,
    ConsultReason,
    OrchestrationContractError,
    OrchestrationRun,
    add_consult,
)
from orkio_v2.services.internal_consultation import (
    INTERNAL_SPECIALIST_ALLOWLIST,
    build_internal_consultation_context,
    select_internal_consultations,
)


def test_common_catalog_is_not_the_internal_allowlist():
    assert "orkio" not in INTERNAL_SPECIALIST_ALLOWLIST
    assert {"orion", "chris", "isadora", "helena"}.issubset(INTERNAL_SPECIALIST_ALLOWLIST)


def test_select_internal_specialists_is_bounded_and_domain_specific():
    plans = select_internal_consultations(
        "Analise a arquitetura da API, o orçamento do projeto e os riscos de segurança.",
        max_consultations=2,
    )
    assert len(plans) == 2
    assert {item.agent_id for item in plans} == {"orion", "chris"}
    assert all(item.agent_id in INTERNAL_SPECIALIST_ALLOWLIST for item in plans)


def test_empty_or_ambiguous_low_signal_does_not_consult():
    assert select_internal_consultations("Olá, tudo bem?") == ()
    assert select_internal_consultations("", max_consultations=2) == ()
    assert select_internal_consultations("Quero uma resposta geral", max_consultations=0) == ()


def _turn() -> CanonicalTurnContext:
    return CanonicalTurnContext(
        execution_id="execution-1",
        request_id="request-1",
        thread_id="thread-1",
        tenant_id="tenant-1",
        user_id="user-1",
        requested_target="id:orkio",
        resolved_agent_id="orkio",
        turn_owner_agent_id="orkio",
        display_agent_id="orkio",
        display_agent_name="Co-Criador",
        technical_lead_agent_id=None,
        route_family=RuntimeRouteFamily.DIRECT_AGENT,
        channel=RuntimeChannel.CHAT_SSE,
        ownership_locked=True,
        governance_mode="proposal_only",
        internal_persistence_allowed=True,
        external_write_allowed=False,
        execution_allowed=True,
    )


def test_consult_contract_rejects_scope_or_owner_mismatch():
    run = OrchestrationRun(turn=_turn())
    with pytest.raises(OrchestrationContractError, match="CONSULT_SCOPE_MISMATCH"):
        add_consult(
            run,
            AgentConsultRequest(
                consult_id="consult-1",
                execution_id="execution-1",
                tenant_id="other-tenant",
                thread_id="thread-1",
                requester_agent_id="orkio",
                turn_owner_agent_id="orkio",
                capability="technology_strategy",
                reason=ConsultReason.CAPABILITY_REQUIRED,
                target_agent_id="orion",
            ),
        )


@pytest.mark.asyncio
async def test_internal_consultation_returns_hidden_owner_preserving_contribution(monkeypatch):
    async def fake_generate(self, agent, history, *, provider=None):
        assert agent == "orion"
        assert history[0]["role"] == "system"
        return "Recomendação interna de arquitetura."

    monkeypatch.setattr("orkio_v2.services.internal_consultation.ModelGateway.generate", fake_generate)
    settings = Settings(
        _env_file=None,
        PLATFORM_INTERNAL_AGENT_CONSULTATION_ENABLED=True,
        PLATFORM_INTERNAL_AGENT_CONSULTATION_MAX=1,
    )
    contributions, plans = await build_internal_consultation_context(
        settings,
        turn=_turn(),
        message="Avalie a arquitetura e a API do projeto.",
    )
    assert [plan.agent_id for plan in plans] == ["orion"]
    assert len(contributions) == 1
    assert contributions[0].source_agent_id == "orion"
    assert contributions[0].target_turn_owner_agent_id == "orkio"
    assert contributions[0].tenant_id == "tenant-1"


def test_internal_consultation_is_disabled_by_default():
    settings = Settings()
    assert settings.internal_agent_consultation_enabled is False
    assert settings.internal_agent_consultation_max == 2


def test_railway_provenance_aliases_are_supported(monkeypatch):
    monkeypatch.delenv("PLATFORM_ENVIRONMENT", raising=False)
    monkeypatch.delenv("PLATFORM_RELEASE_SHA", raising=False)
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", "a" * 40)
    monkeypatch.setenv("PLATFORM_ALLOWED_ORIGINS", "https://frontend.example.test")
    monkeypatch.setenv("DATABASE_URL", "postgresql://" + "dbuser" + ":" + "fixture" + "@example.test/db?sslmode=require")
    monkeypatch.setenv("PLATFORM_INVITATION_TOKEN_SECRET", "x" * 40)
    settings = Settings()
    assert settings.environment == "production"
    assert settings.release_sha == "a" * 40
