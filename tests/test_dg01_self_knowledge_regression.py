"""DG-01 regression: explicit self-code recognition and safe partial snapshots.

No network requests or external writes. The credentials in fixtures are fake.
"""
from __future__ import annotations

import hashlib
import logging

import pytest

from orkio_v2.config import Settings
from orkio_v2.services import github_integration as gh


BACKEND = "patroaiconsultech/efata-777-backend-premium-final-20260917"
FRONTEND = "patroaiconsultech/efata-777-frontend-premium-final-20260917"


def settings(**overrides):
    values = {
        "PLATFORM_ENVIRONMENT": "test",
        "PLATFORM_AUTH_MODE": "test",
        "PLATFORM_INVITATION_TOKEN_SECRET": "x" * 32,
        "PLATFORM_GITHUB_INTEGRATION_ENABLED": "true",
        "PLATFORM_GITHUB_READ_ONLY": "true",
        "PLATFORM_GITHUB_ALLOWED_REPOSITORIES": f"{BACKEND},{FRONTEND}",
        "PLATFORM_GITHUB_SNAPSHOT_MAX_FILES": 8,
        "PLATFORM_GITHUB_SNAPSHOT_MAX_CHARS": 60000,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.parametrize(
    "message",
    [
        "Você conhece seu código?",
        "Os agentes têm autoconhecimento do código?",
        "Investigue o seu próprio repositório.",
        "Qual o self-knowledge de vocês?",
        "Reconhece o código de vocês?",
    ],
)
def test_explicit_self_code_selects_only_configured_repositories(message):
    assert gh.requested_repositories_from_message(settings(), message) == (BACKEND, FRONTEND)


@pytest.mark.parametrize(
    "message",
    [
        "Olá, tudo bem?",
        "Como funciona a autorização de acesso nesse produto de outra empresa?",
        "Pode explicar o código genético?",
    ],
)
def test_unrelated_questions_do_not_acquire_code(message):
    assert gh.requested_repositories_from_message(settings(), message) == ()


def test_disabled_self_knowledge_never_selects_repositories():
    assert gh.requested_repositories_from_message(
        settings(PLATFORM_GITHUB_INTEGRATION_ENABLED="false"),
        "Você conhece seu código?",
    ) == ()


@pytest.mark.asyncio
async def test_non_admin_self_knowledge_never_fetches(monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("should not fetch repository")
    monkeypatch.setattr(gh, "repository_snapshot", forbidden)
    messages = await gh.github_context_messages(
        settings(), message="Você conhece seu código?", is_admin=False,
    )
    assert len(messages) == 1
    assert "requires provisioned admin" in messages[0]["content"]


@pytest.mark.asyncio
async def test_secret_rejected_file_does_not_cancel_other_safe_files(monkeypatch, caplog):
    sha = "a" * 40
    inspected = []
    fake_credential = hashlib.sha256(b"fixture-only-no-credential").hexdigest()
    fake_secret_content = f"Authorization: Bearer {fake_credential}"

    async def head(*args, **kwargs):
        return gh.RepositoryHead(FRONTEND, "main", sha, None)

    async def tree(*args, **kwargs):
        return ("README.md", "src/api.ts", "src/routes/AppConsole.tsx"), False

    async def file(_settings, repository, *, commit_sha, path):
        inspected.append(path)
        if path == "src/api.ts":
            # File-level detector remains strict; no string from this file
            # can reach source context, policy, provenance, or logs.
            gh._sanitize_repository_text(fake_secret_content)
            raise AssertionError("secret guard was bypassed")
        content = f"safe file: {path}"
        return gh.RepositoryFile(
            repository=repository,
            commit_sha=commit_sha,
            path=path,
            github_blob_sha="blob",
            sha256=hashlib.sha256(content.encode()).hexdigest(),
            size=len(content.encode()),
            text=content,
        )

    monkeypatch.setattr(gh, "repository_head", head)
    monkeypatch.setattr(gh, "repository_tree", tree)
    monkeypatch.setattr(gh, "repository_file", file)
    with caplog.at_level(logging.INFO, logger="orkio.self_knowledge"):
        messages = await gh.github_context_messages(
            settings(PLATFORM_GITHUB_ALLOWED_REPOSITORIES=FRONTEND),
            message="Analise a EFATÀ.", is_admin=True,
            execution_id="dg01-regression",
        )

    assert inspected == ["README.md", "src/api.ts", "src/routes/AppConsole.tsx"]
    assert [m["role"] for m in messages] == ["system", "user"]
    evidence = messages[1]["content"]
    assert "files_inspected=2" in evidence
    assert "files_rejected_secret=1" in evidence
    assert "safe file: README.md" in evidence
    assert "safe file: src/routes/AppConsole.tsx" in evidence
    assert fake_credential not in evidence
    assert fake_credential not in caplog.text
    assert "files_rejected_secret=1" in caplog.text


@pytest.mark.asyncio
async def test_partial_snapshot_provenance_and_non_secret_fail_closed(monkeypatch):
    sha = "b" * 40

    async def head(*args, **kwargs):
        return gh.RepositoryHead(FRONTEND, "main", sha, None)

    async def tree(*args, **kwargs):
        return ("README.md", "src/api.ts"), False

    async def file(_settings, repository, *, commit_sha, path):
        if path == "README.md":
            raise gh.GitHubSecretContentRejected("GITHUB_SECRET_CONTENT_REJECTED")
        raise gh.GitHubUpstreamError("GITHUB_UPSTREAM_UNAVAILABLE")

    monkeypatch.setattr(gh, "repository_head", head)
    monkeypatch.setattr(gh, "repository_tree", tree)
    monkeypatch.setattr(gh, "repository_file", file)

    with pytest.raises(gh.GitHubUpstreamError):
        await gh.repository_snapshot(settings(), FRONTEND)

    async def only_secret(*args, **kwargs):
        raise gh.GitHubSecretContentRejected("GITHUB_SECRET_CONTENT_REJECTED")

    monkeypatch.setattr(gh, "repository_file", only_secret)
    snapshot = await gh.repository_snapshot(settings(), FRONTEND)
    provenance = snapshot.provenance()
    assert provenance["files_inspected"] == 0
    assert provenance["files_rejected_secret"] == 2
    assert snapshot.files == ()
    assert "files_inspected=0" in gh._github_evidence_message(snapshot)["content"]
    assert "Rejected candidate files are NOT inspected" in gh._github_evidence_message(snapshot)["content"]


def test_real_source_expression_still_triggers_secret_guard():
    # Proof that an assignment to a *code expression* can be misclassified;
    # deliberately do not weaken the detector to "fix" this example.
    with pytest.raises(gh.GitHubSecretContentRejected):
        gh._sanitize_repository_text("token = secrets.token_urlsafe(48)")
