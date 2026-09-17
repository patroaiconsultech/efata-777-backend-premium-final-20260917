from __future__ import annotations

from sqlalchemy.orm import Session

from ..capability_policy import CapabilityPolicy
from ..python_tool import PythonCodeRejected, PythonExecutionFailed, PythonToolDisabled, validate_python
from .adapters.legacy_local import LegacyLocalPythonAdapter
from .adapters.remote_http import RemoteHttpPythonSandboxAdapter
from .adapters.unconfigured import UnconfiguredPythonSandboxAdapter
from .audit import record_python_runtime_audit
from .contracts import (
    PythonExecutionRequest,
    PythonRuntimeContext,
    PythonRuntimeLimits,
    PythonRuntimeError,
    PythonRuntimeForbidden,
    PythonRuntimeResult,
    PythonRuntimeUnavailable,
)
from .profiles import PythonRuntimeProfileError, get_runtime_profile


def _adapter_for(policy: CapabilityPolicy):
    if policy.python_runtime_mode == "legacy_local_test":
        return LegacyLocalPythonAdapter()
    if policy.python_runtime_mode == "external":
        if (
            policy.python_runtime_adapter == "remote_http"
            and policy.python_runtime_qualified
            and policy.python_runtime_base_url
            and policy.python_runtime_api_token
            and policy.python_runtime_signing_key
            and policy.python_runtime_expected_provider
            and policy.python_runtime_expected_image_digest
        ):
            return RemoteHttpPythonSandboxAdapter()
        if policy.python_runtime_adapter == "unconfigured":
            raise PythonRuntimeUnavailable("PYTHON_RUNTIME_UNAVAILABLE")
        raise PythonRuntimeUnavailable("PYTHON_RUNTIME_UNAVAILABLE")
    raise PythonRuntimeUnavailable("PYTHON_RUNTIME_UNAVAILABLE")


def _runtime_limits(policy: CapabilityPolicy) -> PythonRuntimeLimits:
    return PythonRuntimeLimits(
        wall_clock_ms=int(policy.python_runtime_wall_clock_seconds * 1000),
        cpu_cores=policy.python_runtime_cpu_cores,
        memory_bytes=policy.python_runtime_memory_mb * 1024 * 1024,
        max_processes=policy.python_runtime_max_processes,
        max_stdout_stderr_bytes=policy.python_max_output_bytes,
        max_output_files=policy.python_runtime_max_output_files,
        max_output_bytes=policy.python_runtime_max_output_bytes,
    )


async def execute_python_runtime(
    *,
    code: str,
    policy: CapabilityPolicy,
    context: PythonRuntimeContext,
    db: Session | None = None,
) -> PythonRuntimeResult:
    try:
        profile = get_runtime_profile(policy.python_runtime_profile_id)
    except PythonRuntimeProfileError as exc:
        raise PythonRuntimeUnavailable("PYTHON_RUNTIME_PROFILE_UNKNOWN") from exc

    request = PythonExecutionRequest.build(
        code=code,
        context=context,
        profile=profile,
        limits=_runtime_limits(policy),
        expected_runtime_image_digest=(
            policy.python_runtime_expected_image_digest
            if policy.python_runtime_mode == "external"
            else None
        ),
    )

    if not policy.python_enabled:
        record_python_runtime_audit(
            db,
            request=request,
            status="DENIED",
            error_code="PYTHON_TOOL_DISABLED",
        )
        raise PythonToolDisabled("PYTHON_TOOL_DISABLED")

    try:
        # Defense-in-depth remains useful before sending code to any adapter.
        validate_python(code, policy)
    except PythonCodeRejected as exc:
        record_python_runtime_audit(
            db,
            request=request,
            status="REJECTED",
            error_code=exc.args[0] if exc.args else exc.code,
        )
        raise

    try:
        adapter = _adapter_for(policy)
    except (PythonRuntimeUnavailable, PythonRuntimeForbidden) as exc:
        record_python_runtime_audit(
            db,
            request=request,
            status="UNAVAILABLE",
            error_code=exc.args[0] if exc.args else exc.code,
        )
        raise

    record_python_runtime_audit(db, request=request, status="STARTED")

    try:
        result = await adapter.execute(request, policy)
    except PythonExecutionFailed as exc:
        code_value = exc.args[0] if exc.args else exc.code
        terminal = "TIMED_OUT" if "TIMEOUT" in code_value else "FAILED"
        record_python_runtime_audit(
            db,
            request=request,
            status=terminal,
            error_code=code_value,
        )
        raise
    except (PythonRuntimeUnavailable, PythonRuntimeForbidden) as exc:
        record_python_runtime_audit(
            db,
            request=request,
            status="UNAVAILABLE",
            error_code=exc.args[0] if exc.args else exc.code,
        )
        raise
    except PythonRuntimeError as exc:
        record_python_runtime_audit(
            db,
            request=request,
            status="FAILED",
            error_code=exc.args[0] if exc.args else exc.code,
        )
        raise

    audit_ref = record_python_runtime_audit(
        db,
        request=request,
        status=result.status,
        result=result,
    )
    if audit_ref is None:
        return result
    return PythonRuntimeResult(
        execution_id=result.execution_id,
        sandbox_execution_id=result.sandbox_execution_id,
        status=result.status,
        code_sha256=result.code_sha256,
        runtime_profile_id=result.runtime_profile_id,
        runtime_profile_digest=result.runtime_profile_digest,
        sandbox_provider=result.sandbox_provider,
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.exit_code,
        duration_ms=result.duration_ms,
        truncated=result.truncated,
        network_policy=result.network_policy,
        network_policy_enforced=result.network_policy_enforced,
        filesystem_isolation_enforced=result.filesystem_isolation_enforced,
        cpu_limit_enforced=result.cpu_limit_enforced,
        memory_limit_enforced=result.memory_limit_enforced,
        process_limit_enforced=result.process_limit_enforced,
        ephemeral_filesystem_enforced=result.ephemeral_filesystem_enforced,
        no_operational_secrets=result.no_operational_secrets,
        attestation=result.attestation,
        outputs=result.outputs,
        audit_ref=audit_ref,
    )
