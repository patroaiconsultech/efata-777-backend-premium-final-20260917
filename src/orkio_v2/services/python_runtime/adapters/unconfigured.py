from __future__ import annotations

from ...capability_policy import CapabilityPolicy
from ..contracts import (
    PythonExecutionRequest,
    PythonRuntimeResult,
    PythonRuntimeUnavailable,
)


class UnconfiguredPythonSandboxAdapter:
    adapter_id = "unconfigured"

    async def execute(
        self,
        request: PythonExecutionRequest,
        policy: CapabilityPolicy,
    ) -> PythonRuntimeResult:
        del request, policy
        raise PythonRuntimeUnavailable("PYTHON_RUNTIME_UNAVAILABLE")
