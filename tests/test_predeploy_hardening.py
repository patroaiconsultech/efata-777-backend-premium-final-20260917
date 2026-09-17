from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import text

from conftest import Testing, engine, headers
from orkio_v2.auth import require_principal
from orkio_v2.config import Settings, get_settings
from orkio_v2.models import AuditEvent
from orkio_v2.routes import ready
from orkio_v2.services import llm


class BrokenDatabase:
    def execute(self, *_args, **_kwargs):
        raise RuntimeError("database unavailable")


def test_ready_connection_failure_is_real_http_503():
    with pytest.raises(HTTPException) as raised:
        ready(settings=get_settings(), db=BrokenDatabase())
    assert raised.value.status_code == 503
    assert raised.value.detail["checks"]["database_connect"] is False


def test_ready_rejects_migration_mismatch(client):
    with engine.begin() as connection:
        connection.execute(text("UPDATE alembic_version SET version_num='wrong'"))
    try:
        response = client.get("/api/v2/ready")
        assert response.status_code == 503
        body = response.json()["detail"]
        assert body["checks"]["migration_current"] is False
        assert body["checks"]["migration_expected"] == "012_platform_user_invitations"
    finally:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE alembic_version "
                    "SET version_num='012_platform_user_invitations'"
                )
            )


def test_ready_rejects_any_missing_model_table(client):
    AuditEvent.__table__.drop(engine)
    try:
        response = client.get("/api/v2/ready")
        assert response.status_code == 503
        missing = response.json()["detail"]["checks"]["missing_tables"]
        assert "audit_events" in missing
    finally:
        AuditEvent.__table__.create(engine)


def test_message_rejects_unregistered_client_agent(client, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "openai_api_key", "test-key", raising=False)

    async def fake_generate(*_args, **_kwargs):
        return "Resposta canônica."

    monkeypatch.setattr(llm, "generate", fake_generate)
    thread = client.post(
        "/api/v2/threads",
        json={},
        headers=headers(),
    ).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "oi", "agent": "Fake Admin"},
        headers=headers(),
    )
    assert response.status_code == 404
    assert response.json()["detail"] == {"code": "TARGET_NOT_FOUND"}


def test_stream_rejects_unregistered_client_agent(client, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "openai_api_key", "test-key", raising=False)

    async def fake_stream(*_args, **_kwargs):
        yield "Olá."

    monkeypatch.setattr(llm, "stream", fake_stream)
    thread = client.post(
        "/api/v2/threads",
        json={},
        headers=headers(),
    ).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/stream",
        json={"content": "oi", "agent": "Fake Admin"},
        headers=headers(),
    )
    assert response.status_code == 404
    assert response.json()["detail"] == {"code": "TARGET_NOT_FOUND"}


class FakeIntrospectionResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def oidc_settings() -> Settings:
    return Settings(
        PLATFORM_ENVIRONMENT="staging",
        PLATFORM_AUTH_MODE="oidc_introspection",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
        PLATFORM_OIDC_ISSUER="https://id.example/realms/orkio",
        PLATFORM_OIDC_AUDIENCE="orkio-api",
        PLATFORM_OIDC_INTROSPECTION_ENDPOINT=(
            "https://id.example/realms/orkio/protocol/"
            "openid-connect/token/introspect"
        ),
        PLATFORM_OIDC_INTROSPECTION_CLIENT_ID="backend",
        PLATFORM_OIDC_INTROSPECTION_CLIENT_SECRET="s" + "ecret",
        PLATFORM_OIDC_TENANT_CLAIM="tenant_id",
        PLATFORM_OIDC_ROLES_CLAIM="roles",
    )


def test_oidc_rejects_wrong_issuer(monkeypatch):
    monkeypatch.setattr(
        "orkio_v2.auth.httpx.post",
        lambda *_args, **_kwargs: FakeIntrospectionResponse(
            {
                "active": True,
                "iss": "https://attacker.example",
                "aud": ["orkio-api"],
                "sub": "user-1",
                "tenant_id": "tenant-1",
            }
        ),
    )
    with pytest.raises(HTTPException) as raised:
        require_principal(
            authorization="Bearer token",
            x_test_user=None,
            x_test_tenant=None,
            x_test_roles=None,
            x_test_email=None,
            settings=oidc_settings(),
        )
    assert raised.value.status_code == 401
    assert raised.value.detail == "TOKEN_ISSUER_INVALID"


def test_oidc_accepts_exact_issuer(monkeypatch):
    monkeypatch.setattr(
        "orkio_v2.auth.httpx.post",
        lambda *_args, **_kwargs: FakeIntrospectionResponse(
            {
                "active": True,
                "iss": "https://id.example/realms/orkio",
                "aud": ["orkio-api"],
                "sub": "user-1",
                "tenant_id": "tenant-1",
                "roles": ["admin"],
                "email": "owner@example.com",
            }
        ),
    )
    principal = require_principal(
        authorization="Bearer token",
        x_test_user=None,
        x_test_tenant=None,
        x_test_roles=None,
        x_test_email=None,
        settings=oidc_settings(),
    )
    assert principal.user_id == "user-1"
    assert principal.tenant_id == "tenant-1"
    assert principal.roles == ("admin",)


def test_docker_image_contains_migration_runtime_files():
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text()
    assert "COPY pyproject.toml uv.lock requirements.lock.txt alembic.ini ./" in dockerfile
    assert "COPY migrations ./migrations" in dockerfile
    assert "COPY scripts ./scripts" in dockerfile
    assert "USER orkio" in dockerfile


def test_test_auth_requires_and_preserves_external_subject():
    settings = Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
    )
    with pytest.raises(HTTPException) as raised:
        require_principal(
            authorization=None,
            x_test_user="user-1",
            x_test_tenant="tenant-1",
            x_test_roles="admin",
            x_test_email="owner@example.com",
            x_test_subject=None,
            settings=settings,
        )
    assert raised.value.status_code == 401
    assert raised.value.detail == "TEST_SUBJECT_REQUIRED"

    principal = require_principal(
        authorization=None,
        x_test_user="user-1",
        x_test_tenant="tenant-1",
        x_test_roles="admin",
        x_test_email="owner@example.com",
        x_test_subject="sub-1",
        settings=settings,
    )
    assert principal.external_subject == "sub-1"
