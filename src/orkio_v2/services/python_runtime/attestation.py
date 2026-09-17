from __future__ import annotations

import json
import re
from typing import Any

from .contracts import (
    PythonExecutionRequest,
    PythonOutputManifest,
    PythonRuntimeAttestationInvalid,
    PythonRuntimeOutputInvalid,
    PythonRuntimeResult,
)


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROVIDER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")
_ALLOWED_STATUSES = {
    "SUCCEEDED",
    "FAILED",
    "TIMED_OUT",
    "CANCELLED",
    "REJECTED",
}


def _require_bool(payload: dict[str, Any], key: str) -> bool:
    value = payload.get(key)
    if value is not True:
        raise PythonRuntimeAttestationInvalid(
            f"PYTHON_RUNTIME_ATTESTATION_{key.upper()}_REQUIRED"
        )
    return True


def _safe_text(value: object, *, limit_bytes: int) -> str:
    text = "" if value is None else str(value)
    if len(text.encode("utf-8")) > limit_bytes:
        raise PythonRuntimeOutputInvalid("PYTHON_RUNTIME_TEXT_OUTPUT_TOO_LARGE")
    return text


def validate_remote_runtime_response(
    payload: object,
    *,
    request: PythonExecutionRequest,
    expected_provider: str,
) -> PythonRuntimeResult:
    if not isinstance(payload, dict):
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_RESPONSE_INVALID")
    if payload.get("schema") != "efata.python.runtime.v1":
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_SCHEMA_MISMATCH")
    if payload.get("execution_id") != request.execution_id:
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_EXECUTION_ID_MISMATCH")
    if payload.get("code_sha256") != request.code_sha256:
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_CODE_SHA256_MISMATCH")
    if payload.get("runtime_profile_id") != request.runtime_profile_id:
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_PROFILE_ID_MISMATCH")
    if payload.get("runtime_profile_digest") != request.runtime_profile_digest:
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_PROFILE_DIGEST_MISMATCH")

    sandbox_execution_id = str(payload.get("sandbox_execution_id") or "").strip()
    if not sandbox_execution_id or len(sandbox_execution_id) > 200:
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_SANDBOX_ID_INVALID")

    provider = str(payload.get("sandbox_provider") or "").strip().lower()
    if not _PROVIDER.fullmatch(provider):
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_PROVIDER_INVALID")
    if expected_provider and provider != expected_provider:
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_PROVIDER_MISMATCH")

    status = str(payload.get("status") or "").strip().upper()
    if status not in _ALLOWED_STATUSES:
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_STATUS_INVALID")

    if payload.get("network_policy") != "DENY":
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_NETWORK_POLICY_MISMATCH")

    enforcement = payload.get("enforcement")
    if not isinstance(enforcement, dict):
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_ENFORCEMENT_MISSING")
    network_enforced = _require_bool(enforcement, "network_policy_enforced")
    filesystem_enforced = _require_bool(enforcement, "filesystem_isolation_enforced")
    cpu_enforced = _require_bool(enforcement, "cpu_limit_enforced")
    memory_enforced = _require_bool(enforcement, "memory_limit_enforced")
    process_enforced = _require_bool(enforcement, "process_limit_enforced")
    ephemeral_enforced = _require_bool(enforcement, "ephemeral_filesystem_enforced")
    no_operational_secrets = _require_bool(enforcement, "no_operational_secrets")

    applied_limits = enforcement.get("applied_limits")
    if not isinstance(applied_limits, dict):
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_LIMIT_ATTESTATION_MISSING")
    expected_limits = request.limits.as_payload()
    for key, expected in expected_limits.items():
        if applied_limits.get(key) != expected:
            raise PythonRuntimeAttestationInvalid(
                f"PYTHON_RUNTIME_LIMIT_MISMATCH_{key.upper()}"
            )

    attestation = payload.get("attestation")
    if not isinstance(attestation, dict):
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_ATTESTATION_MISSING")
    image_digest = str(attestation.get("runtime_image_digest") or "").strip().lower()
    if not _IMAGE_DIGEST.fullmatch(image_digest):
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_IMAGE_DIGEST_INVALID")
    expected_image_digest = (request.expected_runtime_image_digest or "").strip().lower()
    if not _IMAGE_DIGEST.fullmatch(expected_image_digest):
        raise PythonRuntimeAttestationInvalid(
            "PYTHON_RUNTIME_EXPECTED_IMAGE_DIGEST_MISSING"
        )
    if image_digest != expected_image_digest:
        raise PythonRuntimeAttestationInvalid(
            "PYTHON_RUNTIME_IMAGE_DIGEST_MISMATCH"
        )

    duration_ms = payload.get("duration_ms")
    if not isinstance(duration_ms, int) or duration_ms < 0:
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_DURATION_INVALID")
    if duration_ms > request.limits.wall_clock_ms + 2_000:
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_WALL_CLOCK_ATTESTATION_FAILED")

    max_text = request.limits.max_stdout_stderr_bytes
    stdout = _safe_text(payload.get("stdout"), limit_bytes=max_text)
    stderr = _safe_text(payload.get("stderr"), limit_bytes=max_text)
    if len((stdout + stderr).encode("utf-8")) > max_text:
        raise PythonRuntimeOutputInvalid("PYTHON_RUNTIME_TEXT_OUTPUT_TOO_LARGE")

    exit_code = payload.get("exit_code")
    if exit_code is not None and not isinstance(exit_code, int):
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_EXIT_CODE_INVALID")
    if status == "SUCCEEDED" and exit_code != 0:
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_SUCCESS_EXIT_CODE_INVALID")

    output_rows = payload.get("outputs") or []
    if not isinstance(output_rows, list):
        raise PythonRuntimeOutputInvalid("PYTHON_RUNTIME_OUTPUTS_INVALID")
    if len(output_rows) > request.limits.max_output_files:
        raise PythonRuntimeOutputInvalid("PYTHON_RUNTIME_TOO_MANY_OUTPUT_FILES")
    outputs: list[PythonOutputManifest] = []
    total_output_bytes = 0
    for row in output_rows:
        if not isinstance(row, dict):
            raise PythonRuntimeOutputInvalid("PYTHON_RUNTIME_OUTPUT_INVALID")
        try:
            size_bytes = int(row.get("size_bytes", -1))
        except (TypeError, ValueError) as exc:
            raise PythonRuntimeOutputInvalid(
                "PYTHON_RUNTIME_OUTPUT_SIZE_INVALID"
            ) from exc
        manifest = PythonOutputManifest(
            logical_name=str(row.get("logical_name") or ""),
            size_bytes=size_bytes,
            sha256=str(row.get("sha256") or "").lower(),
            mime_type=str(row.get("mime_type") or ""),
            validation_status=str(row.get("validation_status") or "REJECTED").upper(),  # type: ignore[arg-type]
        )
        manifest.validate()
        total_output_bytes += manifest.size_bytes
        if total_output_bytes > request.limits.max_output_bytes:
            raise PythonRuntimeOutputInvalid("PYTHON_RUNTIME_OUTPUT_BYTES_EXCEEDED")
        outputs.append(manifest)

    truncated = payload.get("truncated")
    if not isinstance(truncated, bool):
        raise PythonRuntimeAttestationInvalid("PYTHON_RUNTIME_TRUNCATED_INVALID")

    return PythonRuntimeResult(
        execution_id=request.execution_id,
        sandbox_execution_id=sandbox_execution_id,
        status=status,  # type: ignore[arg-type]
        code_sha256=request.code_sha256,
        runtime_profile_id=request.runtime_profile_id,
        runtime_profile_digest=request.runtime_profile_digest,
        sandbox_provider=provider,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        duration_ms=duration_ms,
        truncated=truncated,
        network_policy="DENY",
        network_policy_enforced=network_enforced,
        filesystem_isolation_enforced=filesystem_enforced,
        cpu_limit_enforced=cpu_enforced,
        memory_limit_enforced=memory_enforced,
        process_limit_enforced=process_enforced,
        ephemeral_filesystem_enforced=ephemeral_enforced,
        no_operational_secrets=no_operational_secrets,
        attestation={
            **attestation,
            "enforcement": enforcement,
        },
        outputs=tuple(outputs),
    )
