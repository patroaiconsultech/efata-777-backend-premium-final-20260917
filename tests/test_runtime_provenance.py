from __future__ import annotations

import pytest

from orkio_v2.config import Settings
from orkio_v2.provenance import (
    normalize_git_sha,
    resolve_build_provenance,
    runtime_provenance_payload,
)


SHA_A = "a" * 40
SHA_B = "b" * 40


def test_normalize_git_sha_accepts_only_full_40_hex():
    assert normalize_git_sha(SHA_A.upper()) == SHA_A
    assert normalize_git_sha("abc123") is None
    assert normalize_git_sha("85e268d4-a709-9412-42c0-8c67e9cb212c") is None
    assert normalize_git_sha("") is None
    assert normalize_git_sha(None) is None


def test_explicit_platform_release_sha_wins_when_valid():
    result = resolve_build_provenance(
        platform_release_sha=SHA_A,
        railway_git_commit_sha=SHA_B,
    )
    assert result.build_sha == SHA_A
    assert result.source == "platform_release_sha"


def test_valid_railway_sha_is_fallback_when_explicit_is_missing():
    result = resolve_build_provenance(
        platform_release_sha=None,
        railway_git_commit_sha=SHA_B,
    )
    assert result.build_sha == SHA_B
    assert result.source == "railway_git_commit_sha"


def test_valid_railway_sha_is_fallback_when_explicit_is_malformed():
    result = resolve_build_provenance(
        platform_release_sha="not-a-git-sha",
        railway_git_commit_sha=SHA_B,
    )
    assert result.build_sha == SHA_B
    assert result.source == "railway_git_commit_sha"


def test_unresolved_is_fail_visible():
    result = resolve_build_provenance(
        platform_release_sha="bad",
        railway_git_commit_sha="also-bad",
    )
    assert result.build_sha is None
    assert result.source == "unresolved"


def test_settings_uses_railway_fallback_and_preserves_source(monkeypatch):
    monkeypatch.delenv("PLATFORM_RELEASE_SHA", raising=False)
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", SHA_B)
    settings = Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
    )
    assert settings.release_sha == SHA_B
    assert settings.release_sha_source == "railway_git_commit_sha"


def test_production_rejects_unresolved_provenance(monkeypatch):
    monkeypatch.delenv("PLATFORM_RELEASE_SHA", raising=False)
    monkeypatch.delenv("RAILWAY_GIT_COMMIT_SHA", raising=False)
    with pytest.raises(ValueError, match="PRODUCTION_RELEASE_SHA_REQUIRED"):
        Settings(
            PLATFORM_ENVIRONMENT="production",
            PLATFORM_AUTH_MODE="external_required",
            PLATFORM_ALLOWED_ORIGINS="https://frontend.example.test",
            DATABASE_URL="postgresql://dbuser:fixture@example.test/db?sslmode=require",
            PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
        )


def test_runtime_payload_separates_deployment_id_from_build_sha(monkeypatch):
    monkeypatch.setenv("PLATFORM_RELEASE_SHA", SHA_A)
    settings = Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
        RAILWAY_DEPLOYMENT_ID="deployment-uuid-like-value",
        RAILWAY_SERVICE_NAME="efata-v3-api-internal",
    )
    payload = runtime_provenance_payload(settings)
    assert payload == {
        "deployment_id": "deployment-uuid-like-value",
        "build_sha": SHA_A,
        "environment": "test",
        "service_name": "efata-v3-api-internal",
        "provenance_source": "platform_release_sha",
    }
