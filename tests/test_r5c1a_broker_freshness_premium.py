from __future__ import annotations

import hashlib

import httpx
import pytest

from orkio_v2.services.capability_policy import CapabilityPolicy, CapabilityPolicyError
from orkio_v2.services.python_runtime.adapters.remote_http import (
    RemoteHttpPythonSandboxAdapter,
)
from orkio_v2.services.python_runtime.contracts import (
    PythonExecutionRequest,
    PythonRuntimeAttestationInvalid,
    PythonRuntimeContext,
    PythonRuntimeLimits,
)
from orkio_v2.services.python_runtime.integrity import (
    canonical_json_bytes,
    sign_response,
)
from orkio_v2.services.python_runtime.profiles import get_runtime_profile


SIGNING_KEY = "test-signing-key-32-bytes-minimum-00000001"
EXPECTED_IMAGE_DIGEST = "sha256:" + ("a" * 64)


def policy(**overrides):
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


def request_obj():
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
        code="print(42)",
        context=PythonRuntimeContext(
            tenant_id="tenant-1",
            user_id="user-1",
            thread_id="thread-1",
            agent_id="orkio",
            request_id="request-1",
        ),
        profile=profile,
        limits=limits,
        expected_runtime_image_digest=EXPECTED_IMAGE_DIGEST,
    )


def payload(req: PythonExecutionRequest):
    return {
        "schema": "efata.python.runtime.v1",
        "execution_id": req.execution_id,
        "sandbox_execution_id": "sandbox-1",
        "status": "SUCCEEDED",
        "code_sha256": req.code_sha256,
        "runtime_profile_id": req.runtime_profile_id,
        "runtime_profile_digest": req.runtime_profile_digest,
        "sandbox_provider": "modal",
        "stdout": "42\n",
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
            "applied_limits": req.limits.as_payload(),
        },
        "attestation": {
            "runtime_image_digest": req.expected_runtime_image_digest,
        },
        "outputs": [],
    }


def response_for_request(
    http_request: httpx.Request,
    req: PythonExecutionRequest,
) -> httpx.Response:
    raw = canonical_json_bytes(payload(req))
    request_timestamp = int(http_request.headers["X-EFATA-Request-Timestamp"])
    request_expires_at = int(http_request.headers["X-EFATA-Request-Expires-At"])
    request_nonce = http_request.headers["X-EFATA-Request-Nonce"]
    request_body_sha256 = http_request.headers["X-EFATA-Body-SHA256"]
    signature = sign_response(
        key=SIGNING_KEY,
        execution_id=req.execution_id,
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
            "X-EFATA-Execution-Id": req.execution_id,
            "X-EFATA-Response-Request-Timestamp": str(request_timestamp),
            "X-EFATA-Response-Request-Expires-At": str(request_expires_at),
            "X-EFATA-Response-Request-Nonce": request_nonce,
            "X-EFATA-Response-Request-Body-SHA256": request_body_sha256,
            "X-EFATA-Response-Signature": signature,
        },
    )


@pytest.mark.asyncio
async def test_r5c1a_captured_valid_response_replay_same_execution_id_is_rejected():
    req = request_obj()
    captured: dict[str, object] = {}
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            response = response_for_request(request, req)
            captured["content"] = response.content
            captured["headers"] = dict(response.headers)
            return response

        # Replay the exact prior valid response against a fresh request attempt
        # that has the same execution_id but a new nonce.
        return httpx.Response(
            200,
            content=captured["content"],
            headers=captured["headers"],
        )

    adapter = RemoteHttpPythonSandboxAdapter(
        transport=httpx.MockTransport(handler)
    )
    first = await adapter.execute(req, policy())
    assert first.status == "SUCCEEDED"

    with pytest.raises(
        PythonRuntimeAttestationInvalid,
        match="RESPONSE_REQUEST_BINDING_MISMATCH",
    ):
        await adapter.execute(req, policy())


@pytest.mark.asyncio
async def test_r5c1a_wrong_echoed_nonce_is_rejected_even_with_valid_body():
    req = request_obj()

    async def handler(request: httpx.Request) -> httpx.Response:
        response = response_for_request(request, req)
        headers = dict(response.headers)
        headers["X-EFATA-Response-Request-Nonce"] = "0" * 32
        return httpx.Response(
            200,
            content=response.content,
            headers=headers,
        )

    adapter = RemoteHttpPythonSandboxAdapter(
        transport=httpx.MockTransport(handler)
    )
    with pytest.raises(
        PythonRuntimeAttestationInvalid,
        match="RESPONSE_REQUEST_BINDING_MISMATCH",
    ):
        await adapter.execute(req, policy())


@pytest.mark.asyncio
async def test_r5c1a_transport_attestation_contains_hashed_nonce_not_raw_nonce():
    req = request_obj()
    seen = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["nonce"] = request.headers["X-EFATA-Request-Nonce"]
        seen["body_sha256"] = request.headers["X-EFATA-Body-SHA256"]
        seen["expires_at"] = int(request.headers["X-EFATA-Request-Expires-At"])
        seen["timestamp"] = int(request.headers["X-EFATA-Request-Timestamp"])
        return response_for_request(request, req)

    adapter = RemoteHttpPythonSandboxAdapter(
        transport=httpx.MockTransport(handler)
    )
    result = await adapter.execute(req, policy())
    binding = result.attestation["transport_binding"]

    assert binding["integrity_contract"] == "efata.hmac-sha256.v2"
    assert binding["response_signature_verified"] is True
    assert binding["response_request_binding_verified"] is True
    assert binding["request_body_sha256"] == seen["body_sha256"]
    assert binding["request_expires_at"] == seen["expires_at"]
    assert binding["request_expires_at"] - seen["timestamp"] == 30
    assert binding["request_nonce_sha256"] == hashlib.sha256(
        seen["nonce"].encode("utf-8")
    ).hexdigest()
    assert seen["nonce"] not in repr(binding)


def test_r5c1a_capability_manifest_exposes_freshness_requirement_not_runtime_proof():
    manifest = policy().manifest(privileged=True)["python"]
    assert manifest["broker_request_ttl_seconds"] == 30
    assert manifest["broker_response_request_binding_required"] is True
    assert manifest["runtimeProved"] is False
    assert manifest["premiumQualified"] is False


@pytest.mark.parametrize("ttl", ["4", "121"])
def test_r5c1a_request_ttl_is_bounded_fail_closed(monkeypatch, ttl):
    monkeypatch.setenv("PLATFORM_ENVIRONMENT", "test")
    monkeypatch.setenv("PLATFORM_PYTHON_SANDBOX_REQUEST_TTL_SECONDS", ttl)
    with pytest.raises(
        CapabilityPolicyError,
        match="PLATFORM_PYTHON_SANDBOX_REQUEST_TTL_SECONDS_OUT_OF_RANGE",
    ):
        CapabilityPolicy.from_env()
