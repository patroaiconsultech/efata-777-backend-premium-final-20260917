from __future__ import annotations

import hashlib
import json
import platform

from ...capability_policy import CapabilityPolicy
from ..contracts import PythonExecutionRequest, PythonRuntimeResult, PythonRuntimeForbidden


class LegacyLocalPythonAdapter:
    adapter_id = "legacy_local_test"

    async def execute(
        self,
        request: PythonExecutionRequest,
        policy: CapabilityPolicy,
    ) -> PythonRuntimeResult:
        allowed = (
            policy.python_runtime_mode == "legacy_local_test"
            and policy.python_legacy_local_test_enabled
            and policy.python_runtime_environment in {"development", "test"}
        )
        if not allowed:
            raise PythonRuntimeForbidden("PYTHON_LEGACY_RUNTIME_FORBIDDEN")

        # Lazy import prevents the legacy executor from becoming the architectural
        # dependency of the runtime contracts.
        from ...python_tool import execute_python_legacy_local

        legacy = await execute_python_legacy_local(request.code, policy)
        profile_material = json.dumps(
            {
                "profile_id": request.runtime_profile_id,
                "python": platform.python_version(),
                "flags": ["-I", "-S"],
                "boundary": "same_host_subprocess",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        profile_digest = hashlib.sha256(profile_material).hexdigest()

        return PythonRuntimeResult(
            execution_id=request.execution_id,
            sandbox_execution_id=None,
            status="SUCCEEDED" if legacy.exit_code == 0 else "FAILED",
            code_sha256=legacy.code_sha256,
            runtime_profile_id=request.runtime_profile_id,
            runtime_profile_digest=profile_digest,
            sandbox_provider="legacy_local_test",
            stdout=legacy.stdout,
            stderr=legacy.stderr,
            exit_code=legacy.exit_code,
            duration_ms=legacy.duration_ms,
            truncated=legacy.truncated,
            network_policy="NOT_OS_ENFORCED",
            network_policy_enforced=False,
            filesystem_isolation_enforced=False,
            cpu_limit_enforced=False,
            memory_limit_enforced=False,
            process_limit_enforced=False,
            ephemeral_filesystem_enforced=False,
            no_operational_secrets=False,
            attestation={
                "security_boundary": "same_host_subprocess",
                "python_isolated_flags": ["-I", "-S"],
                "temporary_working_directory": True,
                "stdin_closed": True,
                "production_eligible": False,
            },
        )
