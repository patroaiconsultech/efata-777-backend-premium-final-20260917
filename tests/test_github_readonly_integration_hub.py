
from __future__ import annotations

import base64
import json

import httpx
import pytest

from orkio_v2.config import Settings
from orkio_v2.services import github_integration as gh


def settings(**overrides):
    base = dict(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_DEMO_IDENTITY_HEADERS="true",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 32,
        PLATFORM_GITHUB_INTEGRATION_ENABLED="true",
        PLATFORM_GITHUB_READ_ONLY="true",
        PLATFORM_GITHUB_ALLOWED_REPOSITORIES=(
            "patroaiconsultech/Plataforma-Efata-777-Backend,"
            "patroaiconsultech/Plataforma-Efata-777-Frontend"
        ),
    )
    base.update(overrides)
    return Settings(**base)


def test_allowlist_is_exact_and_write_mode_remains_forbidden():
    s = settings()
    assert gh.allowed_repositories(s) == (
        "patroaiconsultech/Plataforma-Efata-777-Backend",
        "patroaiconsultech/Plataforma-Efata-777-Frontend",
    )
    assert gh.resolve_allowed_repository(
        s, "patroaiconsultech/Plataforma-Efata-777-Backend"
    ).name == "Plataforma-Efata-777-Backend"
    with pytest.raises(gh.GitHubRepositoryNotAllowed):
        gh.resolve_allowed_repository(s, "evil/other")
    with pytest.raises(ValueError, match="GITHUB_WRITE_MODE_FORBIDDEN"):
        settings(PLATFORM_GITHUB_READ_ONLY="false")


def test_sensitive_binary_and_traversal_paths_fail_closed():
    for path in ("../.env", ".env", "secrets/token.txt", "image.png", "a/../../b.py"):
        with pytest.raises(gh.GitHubPathRejected):
            gh._safe_path(path)
    assert gh._safe_path("src/orkio_v2/routes.py") == "src/orkio_v2/routes.py"
    with pytest.raises(gh.GitHubPathRejected, match="GITHUB_CONTROL_CHARACTER_REJECTED"):
        gh._sanitize_repository_text("safe\x01unsafe")
    with pytest.raises(ValueError, match="GITHUB_API_BASE_FORBIDDEN"):
        settings(PLATFORM_GITHUB_API_BASE="https://example.invalid")


@pytest.mark.asyncio
async def test_snapshot_is_pinned_to_commit_and_hashes_real_bytes(monkeypatch):
    sha = "a" * 40
    raw = b'print("ORKIO")\n'
    encoded = base64.b64encode(raw).decode()

    async def fake_get(settings, path, *, params=None):
        if path == "repos/patroaiconsultech/Plataforma-Efata-777-Backend":
            return {"default_branch": "main", "html_url": "https://example.invalid/repo"}
        if path.endswith("/commits/main"):
            return {"sha": sha}
        if path.endswith(f"/git/trees/{sha}"):
            return {
                "truncated": False,
                "tree": [
                    {"type": "blob", "path": "README.md"},
                    {"type": "blob", "path": "src/orkio_v2/routes.py"},
                    {"type": "blob", "path": ".env"},
                ],
            }
        if "/contents/README.md" in path:
            return {
                "type": "file", "size": len(raw), "encoding": "base64",
                "content": encoded, "sha": "blobreadme",
            }
        if "/contents/src/orkio_v2/routes.py" in path:
            return {
                "type": "file", "size": len(raw), "encoding": "base64",
                "content": encoded, "sha": "blobroutes",
            }
        raise AssertionError((path, params))

    monkeypatch.setattr(gh, "_get_json", fake_get)
    snap = await gh.repository_snapshot(
        settings(),
        "patroaiconsultech/Plataforma-Efata-777-Backend",
    )
    assert snap.commit_sha == sha
    assert ".env" not in snap.tree_paths
    assert {f.path for f in snap.files} == {"README.md", "src/orkio_v2/routes.py"}
    assert all(f.sha256 == __import__("hashlib").sha256(raw).hexdigest() for f in snap.files)
    assert snap.provenance()["read_only"] is True
    assert snap.provenance()["proposal_only"] is True
    assert snap.provenance()["write_executed"] is False


def test_explicit_analysis_intent_selects_only_requested_repositories():
    s = settings()
    assert gh.requested_repositories_from_message(
        s, "Natã, audite o backend atual por favor"
    ) == ("patroaiconsultech/Plataforma-Efata-777-Backend",)
    assert gh.requested_repositories_from_message(
        s, "Olá, como você está?"
    ) == ()
    assert set(gh.requested_repositories_from_message(
        s, "audite os dois repos atuais"
    )) == {
        "patroaiconsultech/Plataforma-Efata-777-Backend",
        "patroaiconsultech/Plataforma-Efata-777-Frontend",
    }


@pytest.mark.asyncio
async def test_non_admin_request_never_receives_repository_contents():
    messages = await gh.github_context_messages(
        settings(),
        message="audite o backend atual",
        is_admin=False,
    )
    assert len(messages) == 1
    assert "requires provisioned admin authorization" in messages[0]["content"]
    assert "Do not claim repository access" in messages[0]["content"]


@pytest.mark.asyncio
async def test_upstream_failure_becomes_explicit_context_not_false_success(monkeypatch):
    async def fail(*args, **kwargs):
        raise gh.GitHubUpstreamError("GITHUB_ACCESS_OR_RATE_LIMIT")
    monkeypatch.setattr(gh, "repository_snapshot", fail)
    messages = await gh.github_context_messages(
        settings(),
        message="audite o backend atual",
        is_admin=True,
    )
    assert "GITHUB INTEGRATION FAILED" in messages[0]["content"]
    assert "Do not claim that repository contents were inspected" in messages[0]["content"]


def test_github_read_token_is_not_exposed_by_governance_status_source():
    source = __import__("pathlib").Path("src/orkio_v2/routes.py").read_text()
    assert "github_read_token" not in source
