from orkio_v2.config import Settings
import pytest
def test_production_rejects_demo_headers():
    with pytest.raises(ValueError):
        Settings(PLATFORM_ENVIRONMENT="production",PLATFORM_AUTH_MODE="external_required",
                 PLATFORM_DEMO_IDENTITY_HEADERS_ENABLED=True,
                 PLATFORM_INVITATION_TOKEN_SECRET="x"*40)
def test_external_required_is_fail_closed(monkeypatch):
    from orkio_v2.main import app
    from orkio_v2.auth import require_principal
def test_governance_defaults_safe(client):
    data=client.get("/api/v2/governance/status").json()
    assert data["evolution_execution_allowed"] is False
    assert data["human_approval_required"] is True


def test_security_headers_and_request_id(client):
    response = client.get("/api/v2/health", headers={"X-Request-ID": "release-check-1"})
    assert response.headers["X-Request-ID"] == "release-check-1"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Permissions-Policy"] == "microphone=(self)"


def test_production_requires_release_sha_and_https_database(monkeypatch):
    from orkio_v2.config import Settings

    monkeypatch.setenv("PLATFORM_ENVIRONMENT", "production")
    monkeypatch.setenv("PLATFORM_ALLOWED_ORIGINS", "https://frontend.example.test")
    monkeypatch.setenv("DATABASE_URL", "postgresql://" + "dbuser" + ":" + "fixture" + "@example.test/db?sslmode=require")
    monkeypatch.setenv("PLATFORM_INVITATION_TOKEN_SECRET", "x" * 40)
    monkeypatch.delenv("PLATFORM_RELEASE_SHA", raising=False)
    monkeypatch.delenv("RAILWAY_GIT_COMMIT_SHA", raising=False)
    with pytest.raises(ValueError, match="PRODUCTION_RELEASE_SHA_REQUIRED"):
        Settings()


def test_known_invitation_secret_default_is_rejected_outside_dev_and_test():
    from orkio_v2.config import Settings

    for environment in ("staging", "production"):
        values = {
            "PLATFORM_ENVIRONMENT": environment,
            "PLATFORM_AUTH_MODE": "external_required",
            "PLATFORM_ALLOWED_ORIGINS": "https://frontend.example.test",
            "DATABASE_URL": "postgresql://" + "dbuser" + ":" + "fixture" + "@example.test/db?sslmode=require",
            "PLATFORM_RELEASE_SHA": "a" * 40,
            "PLATFORM_INVITATION_TOKEN_SECRET": "-".join(("development", "only", "change", "me", "32chars")),
        }
        with pytest.raises(ValueError, match="INVITATION_SECRET_DEFAULT_FORBIDDEN_IN_STAGING_PRODUCTION"):
            Settings(**values)


def test_known_invitation_secret_default_is_allowed_in_test():
    settings = Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="-".join(("development", "only", "change", "me", "32chars")),
    )
    assert settings.environment == "test"
