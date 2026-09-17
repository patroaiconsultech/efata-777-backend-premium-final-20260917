from __future__ import annotations

import hashlib
import json

import httpx
import pytest

from conftest import headers
from orkio_v2.services.capability_policy import CapabilityPolicy, CapabilityPolicyError
from orkio_v2.services.python_runtime.adapters.remote_http import (
    RemoteHttpPythonSandboxAdapter,
)
from orkio_v2.services.python_runtime.contracts import (
    PythonExecutionRequest,
    PythonRuntimeAttestationInvalid,
    PythonRuntimeContext,
    PythonRuntimeLimits,
    PythonRuntimeOutputInvalid,
)
from orkio_v2.services.python_runtime.gateway import execute_python_runtime
from orkio_v2.services.python_runtime.integrity import (
    canonical_json_bytes,
    sign_request,
    sign_response,
)
from orkio_v2.services.python_runtime.profiles import (
    get_runtime_profile,
    runtime_profile_manifest,
)


SIGNING_KEY = "test-signing-key-32-bytes-minimum-00000001"
EXPECTED_IMAGE_DIGEST = "sha256:" + ("a" * 64)


def signed_json_response(
    http_request: httpx.Request,
    execution_id: str,
    payload: dict,
    *,
    key: str = SIGNING_KEY,
) -> httpx.Response:
    raw = canonical_json_bytes(payload)
    request_timestamp = int(http_request.headers["X-EFATA-Request-Timestamp"])
    request_expires_at = int(http_request.headers["X-EFATA-Request-Expires-At"])
    request_nonce = http_request.headers["X-EFATA-Request-Nonce"]
    request_body_sha256 = http_request.headers["X-EFATA-Body-SHA256"]
    signature = sign_response(
        key=key,
        execution_id=execution_id,
        request_timestamp=request_timestamp,
        request_expires_at=request_expires_at,
        request_nonce=request_nonce,
        request_body_sha256=request_body_sha256,
        body=raw,
    )
    return httpx.Response(
        200,
        content=raw,
        headers={
            "X-EFATA-Integrity-Contract": "efata.hmac-sha256.v2",
            "X-EFATA-Execution-Id": execution_id,
            "X-EFATA-Response-Request-Timestamp": str(request_timestamp),
            "X-EFATA-Response-Request-Expires-At": str(request_expires_at),
            "X-EFATA-Response-Request-Nonce": request_nonce,
            "X-EFATA-Response-Request-Body-SHA256": request_body_sha256,
            "X-EFATA-Response-Signature": signature,
        },
    )


def external_policy(**overrides):
    base = dict(
        python_enabled=True,
        python_timeout_seconds=2.0,
        python_max_code_bytes=20_000,
        python_max_output_bytes=64_000,
        external_read_enabled=False,
        external_read_allowed_domains=(),
        external_read_timeout_seconds=2.0,
        external_read_max_bytes=100_000,
        external_read_max_urls_per_turn=2,
        python_runtime_mode="external",
        python_runtime_adapter="remote_http",
        python_legacy_local_test_enabled=False,
        python_runtime_environment="test",
        python_runtime_profile_id="python-analysis-lite-v1",
        python_runtime_qualified=True,
        python_runtime_base_url="https://sandbox-broker.example.invalid",
        python_runtime_api_token="test-token-never-real",
        python_runtime_signing_key=SIGNING_KEY,
        python_runtime_expected_provider="modal",
        python_runtime_expected_image_digest=EXPECTED_IMAGE_DIGEST,
        python_runtime_request_timeout_seconds=5.0,
        python_runtime_request_ttl_seconds=30,
        python_runtime_wall_clock_seconds=5.0,
        python_runtime_cpu_cores=1.0,
        python_runtime_memory_mb=512,
        python_runtime_max_processes=16,
        python_runtime_max_output_files=8,
        python_runtime_max_output_bytes=10_000_000,
    )
    base.update(overrides)
    return CapabilityPolicy(**base)


def execution_request():
    profile = get_runtime_profile("python-analysis-lite-v1")
    limits = PythonRuntimeLimits(
        wall_clock_ms=5_000,
        cpu_cores=1.0,
        memory_bytes=512 * 1024 * 1024,
        max_processes=16,
        max_stdout_stderr_bytes=64_000,
        max_output_files=8,
        max_output_bytes=10_000_000,
    )
    return PythonExecutionRequest.build(
        code="print(6*7)",
        context=PythonRuntimeContext(
            tenant_id="tenant-secret-value",
            user_id="user-secret-value",
            thread_id="thread-secret-value",
            agent_id="orkio",
            request_id="request-secret-value",
        ),
        profile=profile,
        limits=limits,
        expected_runtime_image_digest=EXPECTED_IMAGE_DIGEST,
    )


def valid_response(req: PythonExecutionRequest, **overrides):
    payload = {
        "schema": "efata.python.runtime.v1",
        "execution_id": req.execution_id,
        "sandbox_execution_id": "sbx-premium-1",
        "status": "SUCCEEDED",
        "code_sha256": req.code_sha256,
        "runtime_profile_id": req.runtime_profile_id,
        "runtime_profile_digest": req.runtime_profile_digest,
        "sandbox_provider": "modal",
        "stdout": "42\n",
        "stderr": "",
        "exit_code": 0,
        "duration_ms": 120,
        "truncated": False,
        "network_policy": "DENY",
        "enforcement": {
            "network_policy_enforced": True,
            "filesystem_isolation_enforced": True,
            "cpu_limit_enforced": True,
            "memory_limit_enforced": True,
            "process_limit_enforced": True,
            "ephemeral_filesystem_enforced": True,
            "no_operational_secrets": True,
            "applied_limits": req.limits.as_payload(),
        },
        "attestation": {
            "runtime_image_digest": req.expected_runtime_image_digest,
            "runtime_generation": "test-fixture",
        },
        "outputs": [],
    }
    payload.update(overrides)
    return payload


def test_r5b_runtime_profile_is_immutable_and_digest_is_stable():
    first = runtime_profile_manifest("python-analysis-lite-v1")
    second = runtime_profile_manifest("python-analysis-lite-v1")
    assert first == second
    assert first["python_version"] == "3.12.3"
    assert first["network_policy"] == "DENY"
    assert len(first["digest"]) == 64


def test_r5b_broker_payload_uses_opaque_identity_refs_and_no_token():
    req = execution_request()
    body = req.broker_payload()
    serialized = json.dumps(body, sort_keys=True)
    assert "tenant-secret-value" not in serialized
    assert "user-secret-value" not in serialized
    assert "thread-secret-value" not in serialized
    assert "request-secret-value" not in serialized
    assert "test-token-never-real" not in serialized
    assert body["network_policy"] == "DENY"
    assert body["limits"]["memory_bytes"] == 512 * 1024 * 1024
    assert body["runtime_profile"]["digest"] == req.runtime_profile_digest
    assert body["runtime_artifact"]["expected_image_digest"] == EXPECTED_IMAGE_DIGEST


@pytest.mark.asyncio
async def test_r5b_remote_adapter_accepts_only_fully_attested_result():
    req = execution_request()
    seen = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("authorization")
        seen["contract"] = request.headers.get("x-efata-runtime-contract")
        seen["timestamp"] = request.headers.get("x-efata-request-timestamp")
        seen["expires_at"] = request.headers.get("x-efata-request-expires-at")
        seen["nonce"] = request.headers.get("x-efata-request-nonce")
        seen["signature"] = request.headers.get("x-efata-request-signature")
        seen["integrity_contract"] = request.headers.get("x-efata-integrity-contract")
        body = json.loads(request.content.decode("utf-8"))
        seen["body"] = body
        return signed_json_response(request, req.execution_id, valid_response(req))

    adapter = RemoteHttpPythonSandboxAdapter(
        transport=httpx.MockTransport(handler)
    )
    result = await adapter.execute(req, external_policy())

    assert seen["authorization"] == "Bearer test-token-never-real"
    assert seen["contract"] == "efata.python.runtime.v1"
    assert seen["timestamp"]
    assert seen["nonce"]
    assert seen["integrity_contract"] == "efata.hmac-sha256.v2"
    assert int(seen["expires_at"]) - int(seen["timestamp"]) == 30
    expected_request_signature = sign_request(
        key=SIGNING_KEY,
        timestamp=int(seen["timestamp"]),
        expires_at=int(seen["expires_at"]),
        nonce=seen["nonce"],
        body=canonical_json_bytes(seen["body"]),
    )
    assert seen["signature"] == expected_request_signature
    assert "tenant-secret-value" not in json.dumps(seen["body"])
    assert result.status == "SUCCEEDED"
    assert result.stdout.strip() == "42"
    assert result.network_policy_enforced is True
    assert result.filesystem_isolation_enforced is True
    assert result.cpu_limit_enforced is True
    assert result.memory_limit_enforced is True
    assert result.process_limit_enforced is True
    assert result.ephemeral_filesystem_enforced is True
    assert result.no_operational_secrets is True


@pytest.mark.asyncio
async def test_r5b_remote_adapter_fails_closed_on_missing_network_enforcement():
    req = execution_request()
    payload = valid_response(req)
    payload["enforcement"]["network_policy_enforced"] = False

    async def handler(request: httpx.Request) -> httpx.Response:
        return signed_json_response(request, req.execution_id, payload)

    adapter = RemoteHttpPythonSandboxAdapter(
        transport=httpx.MockTransport(handler)
    )
    with pytest.raises(
        PythonRuntimeAttestationInvalid,
        match="NETWORK_POLICY_ENFORCED_REQUIRED",
    ):
        await adapter.execute(req, external_policy())


@pytest.mark.asyncio
async def test_r5b_remote_adapter_fails_closed_on_profile_digest_mismatch():
    req = execution_request()
    payload = valid_response(req, runtime_profile_digest="0" * 64)

    async def handler(request: httpx.Request) -> httpx.Response:
        return signed_json_response(request, req.execution_id, payload)

    adapter = RemoteHttpPythonSandboxAdapter(
        transport=httpx.MockTransport(handler)
    )
    with pytest.raises(
        PythonRuntimeAttestationInvalid,
        match="PROFILE_DIGEST_MISMATCH",
    ):
        await adapter.execute(req, external_policy())


@pytest.mark.asyncio
async def test_r5b_remote_adapter_rejects_pathlike_output_name():
    req = execution_request()
    payload = valid_response(req)
    payload["outputs"] = [
        {
            "logical_name": "../escape.txt",
            "size_bytes": 12,
            "sha256": hashlib.sha256(b"hello world\n").hexdigest(),
            "mime_type": "text/plain",
            "validation_status": "VALIDATED",
        }
    ]

    async def handler(request: httpx.Request) -> httpx.Response:
        return signed_json_response(request, req.execution_id, payload)

    adapter = RemoteHttpPythonSandboxAdapter(
        transport=httpx.MockTransport(handler)
    )
    with pytest.raises(
        PythonRuntimeOutputInvalid,
        match="OUTPUT_NAME_INVALID",
    ):
        await adapter.execute(req, external_policy())


def test_r5b_external_manifest_requires_explicit_qualification():
    unqualified = external_policy(
        python_runtime_qualified=False
    ).manifest(privileged=True)["python"]
    assert unqualified["external_configured"] is True
    assert unqualified["external_qualification_approved"] is False
    assert unqualified["availableNow"] is False
    assert unqualified["runtimeProved"] is False

    qualified = external_policy().manifest(privileged=True)["python"]
    assert qualified["availableNow"] is True
    assert qualified["external_qualification_approved"] is True
    assert qualified["runtimeProved"] is False
    assert qualified["premiumQualified"] is False
    assert qualified["network_enforcement_required"] is True
    assert qualified["filesystem_isolation_required"] is True
    assert qualified["network_enforced"] is False
    assert qualified["filesystem_isolated"] is False


def test_r5b_policy_repr_does_not_expose_sandbox_token():
    p = external_policy()
    assert "test-token-never-real" not in repr(p)
    assert SIGNING_KEY not in repr(p)


def test_r5b_from_env_rejects_non_https_remote_broker(monkeypatch):
    monkeypatch.setenv("PLATFORM_PYTHON_TOOL_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_MODE", "external")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_ADAPTER", "remote_http")
    monkeypatch.setenv("PLATFORM_PYTHON_SANDBOX_API_TOKEN", "fixture-token")
    monkeypatch.setenv("PLATFORM_PYTHON_SANDBOX_BASE_URL", "http://example.com")
    monkeypatch.setenv("PLATFORM_ENVIRONMENT", "staging")
    with pytest.raises(
        CapabilityPolicyError,
        match="BASE_URL_HTTPS_REQUIRED",
    ):
        CapabilityPolicy.from_env()


@pytest.mark.asyncio
async def test_r5b_gateway_remote_http_can_be_qualified_without_local_fallback(
    monkeypatch,
):
    req_holder = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        req_holder["body"] = body
        # Build response from the request contract without relying on local secrets.
        payload = {
            "schema": "efata.python.runtime.v1",
            "execution_id": body["execution_id"],
            "sandbox_execution_id": "sbx-gateway-1",
            "status": "SUCCEEDED",
            "code_sha256": body["code_sha256"],
            "runtime_profile_id": body["runtime_profile"]["id"],
            "runtime_profile_digest": body["runtime_profile"]["digest"],
            "sandbox_provider": "modal",
            "stdout": "100\n",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 100,
            "truncated": False,
            "network_policy": "DENY",
            "enforcement": {
                "network_policy_enforced": True,
                "filesystem_isolation_enforced": True,
                "cpu_limit_enforced": True,
                "memory_limit_enforced": True,
                "process_limit_enforced": True,
                "ephemeral_filesystem_enforced": True,
                "no_operational_secrets": True,
                "applied_limits": body["limits"],
            },
            "attestation": {
                "runtime_image_digest": body["runtime_artifact"]["expected_image_digest"],
            },
            "outputs": [],
        }
        return signed_json_response(
            request,
            body["execution_id"],
            payload,
        )

    transport = httpx.MockTransport(handler)

    from orkio_v2.services.python_runtime import gateway as gateway_module

    monkeypatch.setattr(
        gateway_module,
        "RemoteHttpPythonSandboxAdapter",
        lambda: RemoteHttpPythonSandboxAdapter(transport=transport),
    )

    result = await execute_python_runtime(
        code="print(10*10)",
        policy=external_policy(),
        context=PythonRuntimeContext(
            tenant_id="tenant-1",
            user_id="user-1",
            thread_id="thread-1",
            agent_id="orkio",
        ),
    )
    assert result.status == "SUCCEEDED"
    assert result.stdout.strip() == "100"
    assert result.sandbox_provider == "modal"
    assert result.process_limit_enforced is True
    assert req_holder["body"]["network_policy"] == "DENY"


def test_r5b_qualified_direct_route_exposes_enforcement_truth(
    client, monkeypatch
):
    monkeypatch.setenv("PLATFORM_PYTHON_TOOL_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_MODE", "external")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_ADAPTER", "remote_http")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_QUALIFIED", "true")
    monkeypatch.setenv(
        "PLATFORM_PYTHON_SANDBOX_BASE_URL",
        "https://sandbox-broker.example.invalid",
    )
    monkeypatch.setenv(
        "PLATFORM_PYTHON_SANDBOX_API_TOKEN",
        "route-test-token",
    )
    monkeypatch.setenv(
        "PLATFORM_PYTHON_SANDBOX_EXPECTED_PROVIDER",
        "modal",
    )
    monkeypatch.setenv(
        "PLATFORM_PYTHON_SANDBOX_EXPECTED_IMAGE_DIGEST",
        EXPECTED_IMAGE_DIGEST,
    )
    monkeypatch.setenv(
        "PLATFORM_PYTHON_SANDBOX_SIGNING_KEY",
        SIGNING_KEY,
    )

    from orkio_v2.services.python_runtime import gateway as gateway_module

    def adapter_factory():
        async def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode("utf-8"))
            payload = {
                "schema": "efata.python.runtime.v1",
                "execution_id": body["execution_id"],
                "sandbox_execution_id": "sbx-route-1",
                "status": "SUCCEEDED",
                "code_sha256": body["code_sha256"],
                "runtime_profile_id": body["runtime_profile"]["id"],
                "runtime_profile_digest": body["runtime_profile"]["digest"],
                "sandbox_provider": "modal",
                "stdout": "42\n",
                "stderr": "",
                "exit_code": 0,
                "duration_ms": 90,
                "truncated": False,
                "network_policy": "DENY",
                "enforcement": {
                    "network_policy_enforced": True,
                    "filesystem_isolation_enforced": True,
                    "cpu_limit_enforced": True,
                    "memory_limit_enforced": True,
                    "process_limit_enforced": True,
                    "ephemeral_filesystem_enforced": True,
                    "no_operational_secrets": True,
                    "applied_limits": body["limits"],
                },
                "attestation": {
                    "runtime_image_digest": body["runtime_artifact"]["expected_image_digest"],
                },
                "outputs": [],
            }
            return signed_json_response(
                request,
                body["execution_id"],
                payload,
            )

        return RemoteHttpPythonSandboxAdapter(
            transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(
        gateway_module,
        "RemoteHttpPythonSandboxAdapter",
        adapter_factory,
    )

    response = client.post(
        "/api/v2/tools/python/execute",
        json={"code": "print(6*7)"},
        headers=headers(),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["runtime"] == "modal"
    assert body["network_policy_enforced"] is True
    assert body["filesystem_isolation_enforced"] is True
    assert body["cpu_limit_enforced"] is True
    assert body["memory_limit_enforced"] is True
    assert body["process_limit_enforced"] is True
    assert body["ephemeral_filesystem_enforced"] is True
    assert body["no_operational_secrets"] is True
    assert body["proposal_only"] is False
