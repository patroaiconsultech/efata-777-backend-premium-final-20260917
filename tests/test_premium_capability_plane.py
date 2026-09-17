from __future__ import annotations

import asyncio
import json
import os

import pytest

from orkio_v2.services.capability_plane import (
    capability_manifest_message,
    privileged_roles,
    runtime_capability_messages,
)
from orkio_v2.services.capability_policy import CapabilityPolicy, CapabilityPolicyError
from orkio_v2.services.external_read_tool import (
    ExternalUrlRejected,
    extract_external_urls,
    validate_url,
)
from orkio_v2.services.python_tool import (
    PythonCodeRejected,
    PythonToolDisabled,
    execute_python,
    extract_explicit_python_request,
    validate_python,
)


def policy(**overrides):
    base = dict(
        python_enabled=True,
        python_timeout_seconds=2.0,
        python_max_code_bytes=20_000,
        python_max_output_bytes=64_000,
        external_read_enabled=True,
        external_read_allowed_domains=("example.com",),
        external_read_timeout_seconds=2.0,
        external_read_max_bytes=100_000,
        external_read_max_urls_per_turn=2,
        python_runtime_mode="legacy_local_test",
        python_runtime_adapter="unconfigured",
        python_legacy_local_test_enabled=True,
        python_runtime_environment="test",
        python_runtime_profile_id="python-analysis-lite-v1",
    )
    base.update(overrides)
    return CapabilityPolicy(**base)


def test_policy_defaults_fail_closed(monkeypatch):
    for name in [
        "PLATFORM_PYTHON_TOOL_ENABLED",
        "PLATFORM_PYTHON_RUNTIME_MODE",
        "PLATFORM_PYTHON_RUNTIME_ADAPTER",
        "PLATFORM_PYTHON_LEGACY_LOCAL_TEST_ENABLED",
        "PLATFORM_EXTERNAL_READ_ENABLED",
        "PLATFORM_EXTERNAL_READ_ALLOWED_DOMAINS",
    ]:
        monkeypatch.delenv(name, raising=False)
    p = CapabilityPolicy.from_env()
    assert p.python_enabled is False
    assert p.external_read_enabled is False
    manifest = p.manifest(privileged=True)
    assert manifest["python"]["execute"] is False
    assert manifest["python"]["availableNow"] is False
    assert manifest["python"]["runtime"] == "disabled"
    assert manifest["python"]["runtimeProved"] is False
    assert manifest["external_read"]["enabled"] is False
    assert manifest["external_write"] is False


def test_external_read_enabled_requires_allowlist(monkeypatch):
    monkeypatch.setenv("PLATFORM_EXTERNAL_READ_ENABLED", "true")
    monkeypatch.delenv("PLATFORM_EXTERNAL_READ_ALLOWED_DOMAINS", raising=False)
    with pytest.raises(CapabilityPolicyError, match="EXTERNAL_READ_ALLOWED_DOMAINS_REQUIRED"):
        CapabilityPolicy.from_env()


def test_manifest_is_role_scoped():
    p = policy()
    assert privileged_roles({"admin"}) is True
    assert privileged_roles({"member"}) is False
    assert p.manifest(privileged=False)["python"]["execute"] is False
    assert p.manifest(privileged=False)["external_read"]["enabled"] is False
    msg = capability_manifest_message(p, privileged=True)
    assert "python_execute=true" in msg["content"]
    assert "external_write=false" in msg["content"]


def test_python_requires_explicit_fenced_request():
    assert extract_explicit_python_request("use Python para calcular 2+2") is None
    code = extract_explicit_python_request("execute:\n```python\nprint(2+2)\n```")
    assert code == "print(2+2)"


@pytest.mark.asyncio
async def test_python_execution_isolated_happy_path():
    result = await execute_python("import math\nprint(math.sqrt(81))", policy())
    assert result.exit_code == 0
    assert result.stdout.strip() == "9.0"
    assert len(result.code_sha256) == 64


def test_python_tool_disabled_and_unsafe_imports_rejected():
    with pytest.raises(PythonToolDisabled, match="PYTHON_TOOL_DISABLED"):
        validate_python("print(1)", policy(python_enabled=False))
    with pytest.raises(PythonCodeRejected, match="PYTHON_IMPORT_FORBIDDEN"):
        validate_python("import os\nprint(os.getcwd())", policy())
    with pytest.raises(PythonCodeRejected):
        validate_python("print(open('/etc/passwd').read())", policy())


def test_python_dunder_escape_rejected():
    with pytest.raises(PythonCodeRejected):
        validate_python("print((1).__class__.__mro__)", policy())


def test_external_url_is_https_allowlisted_and_no_ip_literal():
    safe, host = validate_url("https://docs.example.com/page", policy())
    assert host == "docs.example.com"
    assert safe.startswith("https://")
    with pytest.raises(ExternalUrlRejected, match="EXTERNAL_DOMAIN_NOT_ALLOWED"):
        validate_url("https://evil.example.net/", policy())
    with pytest.raises(ExternalUrlRejected, match="EXTERNAL_HTTPS_REQUIRED"):
        validate_url("http://example.com/", policy())
    with pytest.raises(ExternalUrlRejected, match="EXTERNAL_IP_LITERAL_FORBIDDEN"):
        validate_url("https://127.0.0.1/", policy(external_read_allowed_domains=("127.0.0.1",)))


def test_external_url_detection_is_explicit_and_bounded():
    p = policy(external_read_max_urls_per_turn=1)
    assert extract_external_urls("https://example.com/a", p) == ()
    urls = extract_external_urls(
        "abra https://example.com/a e analise https://example.com/b", p
    )
    assert urls == ("https://example.com/a",)


@pytest.mark.asyncio
async def test_chat_python_tool_context_is_admin_only(monkeypatch):
    monkeypatch.setenv("PLATFORM_PYTHON_TOOL_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_MODE", "legacy_local_test")
    monkeypatch.setenv("PLATFORM_PYTHON_LEGACY_LOCAL_TEST_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_EXTERNAL_READ_ENABLED", "false")
    message = "execute este código:\n```python\nprint(6*7)\n```"
    denied = await runtime_capability_messages(message=message, roles=frozenset({"member"}))
    assert any("PYTHON_TOOL_REQUEST_DENIED" in item["content"] for item in denied)
    allowed = await runtime_capability_messages(
        message=message,
        roles=frozenset({"admin"}),
        tenant_id="tenant-1",
        user_id="user-1",
        thread_id="thread-test",
        agent_id="orkio",
        request_id="exec-test",
    )
    assert any("stdout:\n42" in item["content"] for item in allowed)
    assert all(
        "external_write=false" in item["content"]
        or "PYTHON RUNTIME RESULT" in item["content"]
        for item in allowed
    )


def test_capability_route_manifest_is_fail_closed(client, monkeypatch):
    from conftest import headers
    monkeypatch.delenv("PLATFORM_PYTHON_TOOL_ENABLED", raising=False)
    monkeypatch.delenv("PLATFORM_EXTERNAL_READ_ENABLED", raising=False)
    response = client.get("/api/v2/tools/capabilities", headers=headers())
    assert response.status_code == 200
    payload = response.json()
    assert payload["python"]["execute"] is False
    assert payload["external_read"]["enabled"] is False
    assert payload["external_write"] is False


def test_python_execute_route_is_admin_only_and_explicit(client, monkeypatch):
    from conftest import headers
    monkeypatch.setenv("PLATFORM_PYTHON_TOOL_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_MODE", "legacy_local_test")
    monkeypatch.setenv("PLATFORM_PYTHON_LEGACY_LOCAL_TEST_ENABLED", "true")
    response = client.post(
        "/api/v2/tools/python/execute",
        json={"code": "print(7*8)"},
        headers=headers(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["stdout"].strip() == "56"
    assert payload["runtime"] == "legacy_local_test"
    assert payload["network_policy_enforced"] is False
    assert payload["filesystem_isolation_enforced"] is False
    assert payload["execution_performed"] is True
    assert payload["proposal_only"] is False


def test_external_read_route_fails_closed_when_disabled(client, monkeypatch):
    from conftest import headers
    monkeypatch.setenv("PLATFORM_EXTERNAL_READ_ENABLED", "false")
    monkeypatch.delenv("PLATFORM_EXTERNAL_READ_ALLOWED_DOMAINS", raising=False)
    response = client.post(
        "/api/v2/tools/external/read",
        json={"url": "https://example.com"},
        headers=headers(),
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "EXTERNAL_READ_DISABLED"
