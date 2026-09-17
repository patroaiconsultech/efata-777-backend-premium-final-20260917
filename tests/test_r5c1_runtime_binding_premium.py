from __future__ import annotations

import json

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
OTHER_IMAGE_DIGEST = "sha256:" + ("b" * 64)


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


def valid_payload(req: PythonExecutionRequest, *, image_digest: str = EXPECTED_IMAGE_DIGEST):
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
            "runtime_image_digest": image_digest,
        },
        "outputs": [],
    }


def response_binding_headers(
    http_request: httpx.Request,
    execution_id: str,
) -> dict[str, str]:
    return {
        "X-EFATA-Integrity-Contract": "efata.hmac-sha256.v2",
        "X-EFATA-Execution-Id": execution_id,
        "X-EFATA-Response-Request-Timestamp": http_request.headers[
            "X-EFATA-Request-Timestamp"
        ],
        "X-EFATA-Response-Request-Expires-At": http_request.headers[
            "X-EFATA-Request-Expires-At"
        ],
        "X-EFATA-Response-Request-Nonce": http_request.headers[
            "X-EFATA-Request-Nonce"
        ],
        "X-EFATA-Response-Request-Body-SHA256": http_request.headers[
            "X-EFATA-Body-SHA256"
        ],
    }


def signed_response(
    http_request: httpx.Request,
    req: PythonExecutionRequest,
    payload: dict,
) -> httpx.Response:
    raw = canonical_json_bytes(payload)
    headers = response_binding_headers(http_request, req.execution_id)
    headers["X-EFATA-Response-Signature"] = sign_response(
        key=SIGNING_KEY,
        execution_id=req.execution_id,
        request_timestamp=int(http_request.headers["X-EFATA-Request-Timestamp"]),
        request_expires_at=int(http_request.headers["X-EFATA-Request-Expires-At"]),
        request_nonce=http_request.headers["X-EFATA-Request-Nonce"],
        request_body_sha256=http_request.headers["X-EFATA-Body-SHA256"],
        body=raw,
    )
    return httpx.Response(
        200,
        content=raw,
        headers=headers,
    )


@pytest.mark.asyncio
async def test_r5c1_attested_image_digest_must_match_approved_digest():
    req = request_obj()
    payload = valid_payload(req, image_digest=OTHER_IMAGE_DIGEST)

    async def handler(request: httpx.Request) -> httpx.Response:
        return signed_response(request, req, payload)

    adapter = RemoteHttpPythonSandboxAdapter(
        transport=httpx.MockTransport(handler)
    )
    with pytest.raises(
        PythonRuntimeAttestationInvalid,
        match="IMAGE_DIGEST_MISMATCH",
    ):
        await adapter.execute(req, policy())


@pytest.mark.asyncio
async def test_r5c1_missing_response_signature_fails_closed_before_attestation():
    req = request_obj()
    raw = canonical_json_bytes(valid_payload(req))

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=raw,
            headers=response_binding_headers(request, req.execution_id),
        )

    adapter = RemoteHttpPythonSandboxAdapter(
        transport=httpx.MockTransport(handler)
    )
    with pytest.raises(
        PythonRuntimeAttestationInvalid,
        match="RESPONSE_SIGNATURE_INVALID",
    ):
        await adapter.execute(req, policy())


@pytest.mark.asyncio
async def test_r5c1_tampered_response_body_fails_signature_check():
    req = request_obj()
    payload = valid_payload(req)
    raw = canonical_json_bytes(payload)
    tampered = raw.replace(b'"42\\n"', b'"43\\n"')

    async def handler(request: httpx.Request) -> httpx.Response:
        headers = response_binding_headers(request, req.execution_id)
        headers["X-EFATA-Response-Signature"] = sign_response(
            key=SIGNING_KEY,
            execution_id=req.execution_id,
            request_timestamp=int(request.headers["X-EFATA-Request-Timestamp"]),
            request_expires_at=int(request.headers["X-EFATA-Request-Expires-At"]),
            request_nonce=request.headers["X-EFATA-Request-Nonce"],
            request_body_sha256=request.headers["X-EFATA-Body-SHA256"],
            body=raw,
        )
        return httpx.Response(
            200,
            content=tampered,
            headers=headers,
        )

    adapter = RemoteHttpPythonSandboxAdapter(
        transport=httpx.MockTransport(handler)
    )
    with pytest.raises(
        PythonRuntimeAttestationInvalid,
        match="RESPONSE_SIGNATURE_INVALID",
    ):
        await adapter.execute(req, policy())


@pytest.mark.asyncio
async def test_r5c1_request_nonce_changes_between_executions():
    req = request_obj()
    nonces = []

    async def handler(request: httpx.Request) -> httpx.Response:
        nonces.append(request.headers["X-EFATA-Request-Nonce"])
        return signed_response(request, req, valid_payload(req))

    adapter = RemoteHttpPythonSandboxAdapter(
        transport=httpx.MockTransport(handler)
    )
    await adapter.execute(req, policy())
    await adapter.execute(req, policy())

    assert len(nonces) == 2
    assert nonces[0] != nonces[1]
    assert all(len(value) == 32 for value in nonces)


def test_r5c1_external_capability_requires_runtime_artifact_and_signing_binding():
    configured = policy().manifest(privileged=True)["python"]
    assert configured["external_configured"] is True
    assert configured["runtime_artifact_bound"] is True
    assert configured["broker_request_signing"] is True
    assert configured["runtimeProved"] is False
    assert configured["premiumQualified"] is False
    assert configured["network_enforcement_required"] is True
    assert configured["filesystem_isolation_required"] is True
    assert configured["network_enforced"] is False
    assert configured["filesystem_isolated"] is False

    no_digest = policy(
        python_runtime_expected_image_digest=""
    ).manifest(privileged=True)["python"]
    assert no_digest["external_configured"] is False
    assert no_digest["availableNow"] is False

    no_signing = policy(
        python_runtime_signing_key=""
    ).manifest(privileged=True)["python"]
    assert no_signing["external_configured"] is False
    assert no_signing["availableNow"] is False


def _set_remote_env(monkeypatch):
    monkeypatch.setenv("PLATFORM_ENVIRONMENT", "test")
    monkeypatch.setenv("PLATFORM_PYTHON_TOOL_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_MODE", "external")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_ADAPTER", "remote_http")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_QUALIFIED", "true")
    monkeypatch.setenv(
        "PLATFORM_PYTHON_SANDBOX_BASE_URL",
        "https://sandbox-broker.example.invalid",
    )
    monkeypatch.setenv("PLATFORM_PYTHON_SANDBOX_API_TOKEN", "token-fixture")
    monkeypatch.setenv("PLATFORM_PYTHON_SANDBOX_SIGNING_KEY", SIGNING_KEY)
    monkeypatch.setenv("PLATFORM_PYTHON_SANDBOX_EXPECTED_PROVIDER", "modal")
    monkeypatch.setenv(
        "PLATFORM_PYTHON_SANDBOX_EXPECTED_IMAGE_DIGEST",
        EXPECTED_IMAGE_DIGEST,
    )


def test_r5c1_from_env_rejects_missing_expected_image_digest(monkeypatch):
    _set_remote_env(monkeypatch)
    monkeypatch.delenv("PLATFORM_PYTHON_SANDBOX_EXPECTED_IMAGE_DIGEST")
    with pytest.raises(
        CapabilityPolicyError,
        match="EXPECTED_IMAGE_DIGEST_REQUIRED",
    ):
        CapabilityPolicy.from_env()


def test_r5c1_from_env_rejects_invalid_expected_image_digest(monkeypatch):
    _set_remote_env(monkeypatch)
    monkeypatch.setenv(
        "PLATFORM_PYTHON_SANDBOX_EXPECTED_IMAGE_DIGEST",
        "sha256:not-a-real-digest",
    )
    with pytest.raises(
        CapabilityPolicyError,
        match="EXPECTED_IMAGE_DIGEST_INVALID",
    ):
        CapabilityPolicy.from_env()


def test_r5c1_from_env_rejects_missing_signing_key(monkeypatch):
    _set_remote_env(monkeypatch)
    monkeypatch.delenv("PLATFORM_PYTHON_SANDBOX_SIGNING_KEY")
    with pytest.raises(
        CapabilityPolicyError,
        match="SIGNING_KEY_REQUIRED",
    ):
        CapabilityPolicy.from_env()


def test_r5c1_from_env_rejects_short_signing_key(monkeypatch):
    _set_remote_env(monkeypatch)
    monkeypatch.setenv("PLATFORM_PYTHON_SANDBOX_SIGNING_KEY", "too-short")
    with pytest.raises(
        CapabilityPolicyError,
        match="SIGNING_KEY_TOO_SHORT",
    ):
        CapabilityPolicy.from_env()


def test_r5c1_policy_repr_excludes_both_broker_secrets():
    p = policy()
    rendered = repr(p)
    assert "test-token-never-real" not in rendered
    assert SIGNING_KEY not in rendered


def test_r5c1_broker_payload_binds_expected_image_digest():
    req = request_obj()
    body = req.broker_payload()
    assert (
        body["runtime_artifact"]["expected_image_digest"]
        == EXPECTED_IMAGE_DIGEST
    )
    serialized = json.dumps(body, sort_keys=True)
    assert SIGNING_KEY not in serialized
    assert "test-token-never-real" not in serialized
