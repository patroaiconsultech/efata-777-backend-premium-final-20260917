from __future__ import annotations

from orkio_v2.services.platform_knowledge import (
    platform_knowledge_message,
    resolve_platform_knowledge,
    system_capability_guard_message,
)


def test_platform_identity_query_no_longer_injects_mutable_legacy_facts():
    entries = resolve_platform_knowledge("O que é a PatroAI Platform?")
    assert entries == ()
    assert platform_knowledge_message("O que é a PatroAI Platform?") is None


def test_patroai_company_query_requires_governed_knowledge_document():
    entries = resolve_platform_knowledge("Quem é a PatroAI Consultech?")
    assert entries == ()


def test_unrelated_query_does_not_inject_system_capability_guard():
    assert system_capability_guard_message("Explique fluxo de caixa descontado.") is None


def test_capability_guard_never_claims_unproven_runtime_ready():
    message = system_capability_guard_message(
        "A plataforma tem realtime e está pronta em produção?"
    )
    assert message is not None
    content = message["content"]
    assert "SYSTEM / SECURITY BASELINE" in content
    assert "SYSTEM_CAPABILITY_INTEGRITY" in content
    assert "não mutable PatroAI PLATFORM knowledge" not in content  # English wording below
    assert "not mutable PatroAI PLATFORM knowledge" in content
    assert "sem evidência correspondente ao ambiente atual" in content


def test_compatibility_alias_is_system_guard_only():
    message = platform_knowledge_message("Quais capacidades estão prontas?")
    assert message is not None
    assert "SYSTEM_CAPABILITY_INTEGRITY" in message["content"]
    assert "FOUNDER_SUPPLIED_INSTITUTIONAL_CONTEXT" not in message["content"]
    assert "CANONICAL_PLATFORM_CONTEXT" not in message["content"]
