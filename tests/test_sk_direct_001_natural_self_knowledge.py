from __future__ import annotations

import pytest

from orkio_v2.config import Settings
from orkio_v2.services import github_integration as gh


BACKEND = "patroaiconsultech/efata-777-backend-premium-final-20260917"
FRONTEND = "patroaiconsultech/efata-777-frontend-premium-final-20260917"

D1_EXPLICIT = """
Analise o backend Premium atual da EFATÀ usando exclusivamente evidência
adquirida neste turno pelo GitHub autorizado.
"""

D2_NATURAL = """
Como funciona hoje a autorização de acesso às conversas da própria EFATÀ?
Responda apenas com fatos atuais que você consiga provar. Se precisar consultar
evidência interna autorizada para responder corretamente, faça isso.
"""


def settings(**overrides):
    base = dict(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 32,
        PLATFORM_GITHUB_INTEGRATION_ENABLED="true",
        PLATFORM_GITHUB_READ_ONLY="true",
        PLATFORM_GITHUB_ALLOWED_REPOSITORIES=f"{BACKEND},{FRONTEND}",
        PLATFORM_GITHUB_SNAPSHOT_MAX_FILES=8,
        PLATFORM_GITHUB_SNAPSHOT_MAX_CHARS=60000,
    )
    base.update(overrides)
    return Settings(**base)


def test_direct_ab_explicit_and_natural_platform_self_knowledge_both_select_evidence():
    s = settings()

    explicit = gh.requested_repositories_from_message(s, D1_EXPLICIT)
    natural = gh.requested_repositories_from_message(s, D2_NATURAL)

    assert explicit == (BACKEND, FRONTEND)
    assert natural == (BACKEND, FRONTEND)


def test_natural_self_knowledge_requires_platform_reference():
    assert gh.requested_repositories_from_message(
        settings(),
        "Como funciona a autorização de acesso às conversas desse outro produto?",
    ) == ()


def test_casual_efata_mention_does_not_trigger_repository_acquisition():
    assert gh.requested_repositories_from_message(
        settings(),
        "Olá EFATÀ, tudo bem?",
    ) == ()


def test_architecture_question_is_recognized_without_repo_keywords():
    assert gh.requested_repositories_from_message(
        settings(),
        "Como funciona a arquitetura da própria EFATÀ?",
    ) == (BACKEND, FRONTEND)


def test_github_disabled_still_fails_closed_for_natural_self_knowledge():
    assert gh.requested_repositories_from_message(
        settings(PLATFORM_GITHUB_INTEGRATION_ENABLED="false"),
        D2_NATURAL,
    ) == ()


@pytest.mark.asyncio
async def test_natural_direct_prompt_reaches_read_only_snapshot_with_original_query(monkeypatch):
    seen: list[tuple[str, str]] = []

    async def fake_snapshot(_settings, repository, *, requested_paths=(), query_message=""):
        assert tuple(requested_paths) == ()
        seen.append((repository, query_message))
        return gh.RepositorySnapshot(
            repository=repository,
            default_branch="main",
            commit_sha="a" * 40,
            tree_paths=("src/orkio_v2/services/thread_access_policy.py",),
            files=(),
            truncated_tree=False,
        )

    monkeypatch.setattr(gh, "repository_snapshot", fake_snapshot)

    messages = await gh.github_context_messages(
        settings(),
        message=D2_NATURAL,
        is_admin=True,
    )

    assert seen == [
        (BACKEND, D2_NATURAL),
        (FRONTEND, D2_NATURAL),
    ]
    assert len(messages) == 4
    assert all(item["role"] in {"system", "user"} for item in messages)
