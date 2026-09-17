from __future__ import annotations

from typing import Protocol

from ...capability_policy import CapabilityPolicy
from ..contracts import PythonExecutionRequest, PythonRuntimeResult


class PythonSandboxAdapter(Protocol):
    adapter_id: str

    async def execute(
        self,
        request: PythonExecutionRequest,
        policy: CapabilityPolicy,
    ) -> PythonRuntimeResult:
        ...
