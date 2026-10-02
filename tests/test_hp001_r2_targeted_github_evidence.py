from __future__ import annotations

import pytest

from orkio_v2.config import Settings
from orkio_v2.services import github_integration as gh


BACKEND = "patroaiconsultech/efata-777-backend-premium-final-20260917"

FOCUSED_PROMPT = """
Sem usar apenas conhecimento do modelo, consulte o backend Premium autorizado da EFATÀ.
Descubra no repositório atual:
1. qual arquivo implementa a autorização canônica de acesso a threads;
2. qual arquivo executa o evidence preflight do Team antes do fan-out para especialistas;
3. qual arquivo implementa a integração GitHub read-only usada para aquisição de evidência.
"""


def settings(**overrides):
    base = dict(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 32,
        PLATFORM_GITHUB_INTEGRATION_ENABLED="true",
        PLATFORM_GITHUB_READ_ONLY="true",
        PLATFORM_GITHUB_ALLOWED_REPOSITORIES=BACKEND,
        PLATFORM_GITHUB_SNAPSHOT_MAX_FILES=8,
        PLATFORM_GITHUB_SNAPSHOT_MAX_CHARS=60000,
    )
    base.update(overrides)
    return Settings(**base)


def test_focused_self_knowledge_query_targets_causal_backend_files():
    tree = (
        "README.md",
        "pyproject.toml",
        "Dockerfile",
        "src/orkio_v2/config.py",
        "src/orkio_v2/routes.py",
        "src/orkio_v2/team_routes.py",
        "src/orkio_v2/services/team_runtime.py",
        "src/orkio_v2/services/thread_access_policy.py",
        "src/orkio_v2/services/github_integration.py",
        "src/orkio_v2/services/execution_router.py",
    )

    targeted = gh._targeted_paths_for_message(FOCUSED_PROMPT, tree, limit=4)

    assert targeted[:3] == (
        "src/orkio_v2/services/thread_access_policy.py",
        "src/orkio_v2/team_routes.py",
        "src/orkio_v2/services/github_integration.py",
    )


def test_target_selector_never_promotes_secret_or_unsupported_paths():
    tree = (
        ".env",
        "secrets/token.txt",
        "src/orkio_v2/services/github_integration.py",
        "src/orkio_v2/services/github_private_key.py",
        "assets/github-diagram.png",
    )

    targeted = gh._targeted_paths_for_message(
        "audite a integração GitHub do repositório",
        tree,
        limit=8,
    )

    assert targeted == ("src/orkio_v2/services/github_integration.py",)


@pytest.mark.asyncio
async def test_repository_snapshot_reads_query_targets_before_static_priority(monkeypatch):
    sha = "a" * 40
    tree = (
        "README.md",
        "pyproject.toml",
        "Dockerfile",
        "src/orkio_v2/config.py",
        "src/orkio_v2/routes.py",
        "src/orkio_v2/team_routes.py",
        "src/orkio_v2/services/thread_access_policy.py",
        "src/orkio_v2/services/github_integration.py",
    )
    reads: list[str] = []

    async def fake_head(*args, **kwargs):
        return gh.RepositoryHead(
            repository=BACKEND,
            default_branch="main",
            commit_sha=sha,
            html_url=None,
        )

    async def fake_tree(*args, **kwargs):
        return tree, False

    async def fake_file(_settings, repository, *, commit_sha, path):
        reads.append(path)
        text = f"CONTENT:{path}\n"
        return gh.RepositoryFile(
            repository=repository,
            commit_sha=commit_sha,
            path=path,
            github_blob_sha=f"blob-{len(reads)}",
            sha256=("f" * 63) + str(len(reads) % 10),
            size=len(text.encode()),
            text=text,
            content_truncated=False,
            provided_chars=len(text),
        )

    monkeypatch.setattr(gh, "repository_head", fake_head)
    monkeypatch.setattr(gh, "repository_tree", fake_tree)
    monkeypatch.setattr(gh, "repository_file", fake_file)

    snap = await gh.repository_snapshot(
        settings(PLATFORM_GITHUB_SNAPSHOT_MAX_FILES=3),
        BACKEND,
        query_message=FOCUSED_PROMPT,
    )

    assert reads == [
        "src/orkio_v2/services/thread_access_policy.py",
        "src/orkio_v2/team_routes.py",
        "src/orkio_v2/services/github_integration.py",
    ]
    assert [item.path for item in snap.files] == reads
    assert "README.md" not in reads
    assert "src/orkio_v2/routes.py" not in reads


@pytest.mark.asyncio
async def test_github_context_forwards_user_query_to_snapshot(monkeypatch):
    seen: list[tuple[str, str]] = []

    async def fake_snapshot(_settings, repository, *, requested_paths=(), query_message=""):
        assert tuple(requested_paths) == ()
        seen.append((repository, query_message))
        return gh.RepositorySnapshot(
            repository=repository,
            default_branch="main",
            commit_sha="b" * 40,
            tree_paths=("src/orkio_v2/services/github_integration.py",),
            files=(),
            truncated_tree=False,
        )

    monkeypatch.setattr(gh, "repository_snapshot", fake_snapshot)

    messages = await gh.github_context_messages(
        settings(),
        message=FOCUSED_PROMPT,
        is_admin=True,
    )

    assert seen == [(BACKEND, FOCUSED_PROMPT)]
    assert [item["role"] for item in messages] == ["system", "user"]
