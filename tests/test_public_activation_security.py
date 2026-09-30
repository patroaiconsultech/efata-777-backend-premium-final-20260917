from __future__ import annotations

import asyncio
import json

import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient

from orkio_v2.config import Settings, get_settings
from orkio_v2.main import app
from orkio_v2.public_activation_security import (
    PublicActivationSecurityMiddleware,
    reset_public_activation_security_state_for_tests,
    resolve_client_ip,
)
from orkio_v2.services.activation_rate_limit import DistributedRateLimitDecision
import orkio_v2.public_activation_security as activation_security


@pytest.fixture(autouse=True)
def _reset_security_state():
    reset_public_activation_security_state_for_tests()
    get_settings.cache_clear()
    yield
    reset_public_activation_security_state_for_tests()
    get_settings.cache_clear()


def _enable_invitation(monkeypatch, **overrides):
    env = {
        "PLATFORM_ENVIRONMENT": "test",
        "PLATFORM_AUTH_MODE": "test",
        "PLATFORM_INVITATION_TOKEN_SECRET": "x" * 40,
        "PLATFORM_USER_INVITATION_ENABLED": "true",
        "PLATFORM_USER_INVITATION_SECRET": "u" * 40,
        "PLATFORM_USER_INVITATION_BASE_URL": "http://localhost:5173/activate",
        "PLATFORM_USER_INVITATION_ALLOWED_ROLES": "member,admin",
    }
    env.update({k: str(v) for k, v in overrides.items()})
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()


def test_public_activation_status_rate_limit_returns_429(monkeypatch):
    _enable_invitation(
        monkeypatch,
        PLATFORM_ACTIVATION_STATUS_RATE_LIMIT_PER_WINDOW=3,
        PLATFORM_ACTIVATION_RATE_LIMIT_WINDOW_SECONDS=60,
    )
    with TestClient(app) as client:
        statuses = [
            client.post(
                "/api/v2/platform-invitations/status",
                json={"token": "x" * 40},
            ).status_code
            for _ in range(4)
        ]

    assert statuses[:3] == [404, 404, 404]
    assert statuses[3] == 429


def test_public_activation_declared_oversize_rejected_before_endpoint(monkeypatch):
    _enable_invitation(monkeypatch, PLATFORM_ACTIVATION_MAX_BODY_BYTES=1024)
    with TestClient(app) as client:
        response = client.post(
            "/api/v2/platform-invitations/status",
            headers={"Content-Length": "10485760"},
            content=json.dumps({"token": "x" * 40}),
        )

    assert response.status_code == 413
    assert response.json()["detail"] == "PUBLIC_ACTIVATION_PAYLOAD_TOO_LARGE"


def test_public_activation_actual_bytes_rejected_without_content_length(monkeypatch):
    _enable_invitation(monkeypatch, PLATFORM_ACTIVATION_MAX_BODY_BYTES=1024)

    called = {"downstream": False}
    sent = []

    async def downstream(scope, receive, send):
        called["downstream"] = True
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = PublicActivationSecurityMiddleware(downstream)
    body = b"x" * 2048
    messages = [
        {"type": "http.request", "body": body[:900], "more_body": True},
        {"type": "http.request", "body": body[900:], "more_body": False},
    ]

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/v2/platform-invitations/status",
        "raw_path": b"/api/v2/platform-invitations/status",
        "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
        "client": ("198.51.100.8", 1234),
        "server": ("testserver", 80),
    }
    asyncio.run(middleware(scope, receive, send))

    start = next(message for message in sent if message["type"] == "http.response.start")
    assert start["status"] == 413
    assert called["downstream"] is False


def test_untrusted_peer_cannot_spoof_x_forwarded_for():
    settings = Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
        PLATFORM_ACTIVATION_TRUSTED_PROXY_CIDRS="127.0.0.1/32",
    )
    scope = {
        "client": ("198.51.100.9", 1234),
        "headers": [(b"x-forwarded-for", b"203.0.113.99")],
    }
    assert resolve_client_ip(scope, settings) == "198.51.100.9"


def test_trusted_proxy_uses_forwarded_client_and_conflict_fails_closed():
    settings = Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
        PLATFORM_ACTIVATION_TRUSTED_PROXY_CIDRS="127.0.0.1/32",
    )
    scope = {
        "client": ("127.0.0.1", 1234),
        "headers": [(b"x-forwarded-for", b"203.0.113.99")],
    }
    assert resolve_client_ip(scope, settings) == "203.0.113.99"

    conflict = {
        "client": ("127.0.0.1", 1234),
        "headers": [
            (b"x-forwarded-for", b"203.0.113.99"),
            (b"forwarded", b"for=198.51.100.17"),
        ],
    }
    assert resolve_client_ip(conflict, settings) == "unknown"


def test_malformed_forwarded_chain_fails_closed():
    settings = Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
        PLATFORM_ACTIVATION_TRUSTED_PROXY_CIDRS="127.0.0.1/32",
    )
    scope = {
        "client": ("127.0.0.1", 1234),
        "headers": [(b"x-forwarded-for", b"not-an-ip")],
    }
    assert resolve_client_ip(scope, settings) == "unknown"


def test_external_rate_limit_backend_fails_closed_until_adapter_exists(monkeypatch):
    _enable_invitation(
        monkeypatch,
        PLATFORM_ACTIVATION_RATE_LIMIT_BACKEND="external",
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v2/platform-invitations/status",
            json={"token": "x" * 40},
        )
    assert response.status_code == 503
    assert response.json()["detail"] == "PUBLIC_ACTIVATION_RATE_LIMIT_BACKEND_UNAVAILABLE"


def test_staging_invitation_rejects_process_local_rate_limiter():
    with pytest.raises(ValidationError, match="PLATFORM_ACTIVATION_DISTRIBUTED_RATE_LIMIT_REQUIRED"):
        Settings(
            PLATFORM_ENVIRONMENT="staging",
            PLATFORM_AUTH_MODE="external_required",
            PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
            PLATFORM_USER_INVITATION_ENABLED=True,
            PLATFORM_USER_INVITATION_SECRET="u" * 40,
            PLATFORM_USER_INVITATION_BASE_URL="https://example.test/activate",
            PLATFORM_USER_INVITATION_ALLOWED_ROLES="member,admin",
            PLATFORM_ACTIVATION_RATE_LIMIT_BACKEND="memory",
        )


def test_invalid_trusted_proxy_cidr_rejected():
    with pytest.raises(ValidationError, match="PLATFORM_ACTIVATION_TRUSTED_PROXY_CIDRS_INVALID"):
        Settings(
            PLATFORM_ENVIRONMENT="test",
            PLATFORM_AUTH_MODE="test",
            PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
            PLATFORM_ACTIVATION_TRUSTED_PROXY_CIDRS="not-a-cidr",
        )


def test_external_rate_limit_backend_uses_adapter_and_allows_request(monkeypatch):
    _enable_invitation(
        monkeypatch,
        PLATFORM_ACTIVATION_RATE_LIMIT_BACKEND="external",
    )
    observed = {}

    async def fake_check(**kwargs):
        observed.update(kwargs)
        return DistributedRateLimitDecision(True, 0)

    monkeypatch.setattr(
        activation_security,
        "check_external_activation_rate_limit",
        fake_check,
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v2/platform-invitations/status",
            json={"token": "x" * 40},
        )

    assert response.status_code == 404
    assert observed["endpoint_class"] == "status"
    assert observed["token"] == "x" * 40
    assert observed["secret"] == "u" * 40
    assert observed["limit"] == get_settings().platform_activation_status_rate_limit_per_window


def test_external_rate_limit_backend_returns_429_with_retry_after(monkeypatch):
    _enable_invitation(
        monkeypatch,
        PLATFORM_ACTIVATION_RATE_LIMIT_BACKEND="external",
    )

    async def fake_check(**kwargs):
        return DistributedRateLimitDecision(False, 9)

    monkeypatch.setattr(
        activation_security,
        "check_external_activation_rate_limit",
        fake_check,
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v2/platform-invitations/status",
            json={"token": "x" * 40},
        )

    assert response.status_code == 429
    assert response.json()["detail"] == "PUBLIC_ACTIVATION_RATE_LIMITED"
    assert response.headers["Retry-After"] == "9"

def test_external_rate_limit_backend_malformed_redis_url_returns_controlled_503(monkeypatch):
    _enable_invitation(
        monkeypatch,
        PLATFORM_ACTIVATION_RATE_LIMIT_BACKEND="external",
        REDIS_URL="redis://localhost:notaport/0",
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v2/platform-invitations/status",
            json={"token": "x" * 40},
        )

    assert response.status_code == 503
    assert response.json()["detail"] == "PUBLIC_ACTIVATION_RATE_LIMIT_BACKEND_UNAVAILABLE"



def test_external_rate_limit_backend_malformed_redis_ipv6_url_returns_controlled_503(monkeypatch):
    _enable_invitation(
        monkeypatch,
        PLATFORM_ACTIVATION_RATE_LIMIT_BACKEND="external",
        REDIS_URL="redis://[::1",
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v2/platform-invitations/status",
            json={"token": "x" * 40},
        )

    assert response.status_code == 503
    assert response.json()["detail"] == "PUBLIC_ACTIVATION_RATE_LIMIT_BACKEND_UNAVAILABLE"
