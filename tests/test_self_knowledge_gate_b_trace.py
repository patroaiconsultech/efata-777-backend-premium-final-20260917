from __future__ import annotations

import logging

import pytest

from orkio_v2.config import Settings
from orkio_v2.services import github_integration as gh


REPOSITORY = "patroaiconsultech/efata-777-backend-premium-final-20260917"
QUESTION = "Analise o backend Premium atual da própria EFATÀ e identifique autorização de threads."


def _settings(enabled: bool = True) -> Settings:
    return Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 32,
        PLATFORM_GITHUB_INTEGRATION_ENABLED="true" if enabled else "false",
        PLATFORM_GITHUB_READ_ONLY="true",
        PLATFORM_GITHUB_ALLOWED_REPOSITORIES=REPOSITORY,
    )


@pytest.mark.asyncio
async def test_disabled_does_not_acquire_and_emits_safe_event(monkeypatch, caplog):
    async def forbidden(*args, **kwargs):
        raise AssertionError("must not fetch")
    monkeypatch.setattr(gh, "repository_snapshot", forbidden)
    with caplog.at_level(logging.INFO, logger="orkio.self_knowledge"):
        response = await gh.github_context_messages(
            _settings(False), message=QUESTION, is_admin=True, execution_id="gate-b-1"
        )
    assert response == []
    assert "enabled=False" in caplog.text
    assert "gate-b-1" in caplog.text
    assert QUESTION not in caplog.text


@pytest.mark.asyncio
async def test_unauthorized_never_fetches(monkeypatch, caplog):
    async def forbidden(*args, **kwargs):
        raise AssertionError("must not fetch")
    monkeypatch.setattr(gh, "repository_snapshot", forbidden)
    with caplog.at_level(logging.INFO, logger="orkio.self_knowledge"):
        response = await gh.github_context_messages(
            _settings(), message=QUESTION, is_admin=False, execution_id="gate-b-2"
        )
    assert len(response) == 1
    assert "admin_required" in caplog.text


@pytest.mark.asyncio
async def test_success_emits_commit_metadata_not_source_text(monkeypatch, caplog):
    async def snapshot(settings, repository, *, query_message):
        assert repository == REPOSITORY
        assert query_message == QUESTION
        return gh.RepositorySnapshot(
            repository=REPOSITORY,
            default_branch="main",
            commit_sha="a" * 40,
            tree_paths=(),
            files=(),
            truncated_tree=False,
        )
    monkeypatch.setattr(gh, "repository_snapshot", snapshot)
    with caplog.at_level(logging.INFO, logger="orkio.self_knowledge"):
        response = await gh.github_context_messages(
            _settings(), message=QUESTION, is_admin=True, execution_id="gate-b-3"
        )
    assert len(response) == 2
    assert "snapshot_success" in caplog.text
    assert "a" * 40 in caplog.text
    assert "context_built" in caplog.text
    assert QUESTION not in caplog.text


@pytest.mark.asyncio
async def test_upstream_failure_emits_error_code_only(monkeypatch, caplog):
    async def broken(*args, **kwargs):
        raise gh.GitHubUpstreamError("upstream details must not enter log")
    monkeypatch.setattr(gh, "repository_snapshot", broken)
    with caplog.at_level(logging.INFO, logger="orkio.self_knowledge"):
        response = await gh.github_context_messages(
            _settings(), message=QUESTION, is_admin=True, execution_id="gate-b-4"
        )
    assert len(response) == 1
    assert "snapshot_failure" in caplog.text
    assert "GITHUB_UPSTREAM_ERROR" in caplog.text
    assert "upstream details must not enter log" not in caplog.text


@pytest.mark.asyncio
async def test_upstream_error_is_sanitized_before_llm(monkeypatch):
    secret = "credential-like-upstream-body-should-never-be-shared"
    async def broken(*args, **kwargs):
        raise gh.GitHubUpstreamError(secret)
    monkeypatch.setattr(gh, "repository_snapshot", broken)
    messages = await gh.github_context_messages(
        _settings(), message=QUESTION, is_admin=True, execution_id="gate-b-sanitize"
    )
    combined = "\n".join(m["content"] for m in messages)
    assert secret not in combined
    assert "GITHUB_UPSTREAM_ERROR" in combined
    assert REPOSITORY in combined


def test_both_http_routes_bypass_github_during_governed_audit():
    """Source-level contract guard for both Direct JSON and streaming paths."""
    import ast
    from pathlib import Path
    routes_path = Path(__file__).resolve().parents[1] / "src" / "orkio_v2" / "routes.py"
    module = ast.parse(routes_path.read_text(encoding="utf-8"))
    candidates = []
    for node in ast.walk(module):
        if not isinstance(node, ast.If):
            continue
        if not isinstance(node.test, ast.Name) or node.test.id != "audit_candidate":
            continue
        body = ast.unparse(node.body)
        alternate = ast.unparse(node.orelse)
        if "github_messages = []" in body and "github_context_messages(" in alternate:
            candidates.append(node)
            assert "github_bypassed" in body
            assert "execution_id=turn.execution_id" in alternate
    assert len(candidates) == 2, "Expected governance bypass in both Direct and SSE routes"
