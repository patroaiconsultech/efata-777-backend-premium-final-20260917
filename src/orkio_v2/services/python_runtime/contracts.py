from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Literal
import uuid

from .profiles import PythonRuntimeProfile


PythonExecutionStatus = Literal[
    "SUCCEEDED",
    "FAILED",
    "TIMED_OUT",
    "CANCELLED",
    "REJECTED",
    "UNAVAILABLE",
]


class PythonRuntimeError(RuntimeError):
    code = "PYTHON_RUNTIME_ERROR"


class PythonRuntimeUnavailable(PythonRuntimeError):
    code = "PYTHON_RUNTIME_UNAVAILABLE"


class PythonRuntimeForbidden(PythonRuntimeError):
    code = "PYTHON_RUNTIME_FORBIDDEN"


class PythonRuntimeAttestationInvalid(PythonRuntimeError):
    code = "PYTHON_RUNTIME_ATTESTATION_INVALID"


class PythonRuntimeOutputInvalid(PythonRuntimeError):
    code = "PYTHON_RUNTIME_OUTPUT_INVALID"


@dataclass(frozen=True, slots=True)
class PythonRuntimeContext:
    tenant_id: str
    user_id: str
    thread_id: str | None = None
    agent_id: str | None = None
    request_id: str | None = None


@dataclass(frozen=True, slots=True)
class PythonRuntimeLimits:
    wall_clock_ms: int
    cpu_cores: float
    memory_bytes: int
    max_processes: int
    max_stdout_stderr_bytes: int
    max_output_files: int
    max_output_bytes: int

    def as_payload(self) -> dict[str, int | float]:
        return {
            "wall_clock_ms": self.wall_clock_ms,
            "cpu_cores": self.cpu_cores,
            "memory_bytes": self.memory_bytes,
            "max_processes": self.max_processes,
            "max_stdout_stderr_bytes": self.max_stdout_stderr_bytes,
            "max_output_files": self.max_output_files,
            "max_output_bytes": self.max_output_bytes,
        }


@dataclass(frozen=True, slots=True)
class PythonExecutionRequest:
    execution_id: str
    context: PythonRuntimeContext
    code: str
    code_sha256: str
    runtime_profile_id: str
    runtime_profile_digest: str
    expected_runtime_image_digest: str | None
    limits: PythonRuntimeLimits
    network_policy: str = "DENY"
    output_policy: str = "METADATA_ONLY"

    @classmethod
    def build(
        cls,
        *,
        code: str,
        context: PythonRuntimeContext,
        profile: PythonRuntimeProfile,
        limits: PythonRuntimeLimits,
        expected_runtime_image_digest: str | None = None,
    ) -> "PythonExecutionRequest":
        raw = (code or "").encode("utf-8")
        return cls(
            execution_id=str(uuid.uuid4()),
            context=context,
            code=code,
            code_sha256=hashlib.sha256(raw).hexdigest(),
            runtime_profile_id=profile.profile_id,
            runtime_profile_digest=profile.digest,
            expected_runtime_image_digest=expected_runtime_image_digest,
            limits=limits,
        )

    @staticmethod
    def _opaque_ref(value: str | None) -> str | None:
        if not value:
            return None
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def broker_payload(self) -> dict[str, object]:
        return {
            "schema": "efata.python.runtime.v1",
            "execution_id": self.execution_id,
            "request_ref": self._opaque_ref(self.context.request_id),
            "tenant_ref": self._opaque_ref(self.context.tenant_id),
            "user_ref": self._opaque_ref(self.context.user_id),
            "thread_ref": self._opaque_ref(self.context.thread_id),
            "agent_id": self.context.agent_id,
            "code": self.code,
            "code_sha256": self.code_sha256,
            "runtime_profile": {
                "id": self.runtime_profile_id,
                "digest": self.runtime_profile_digest,
            },
            "runtime_artifact": {
                "expected_image_digest": self.expected_runtime_image_digest,
            },
            "limits": self.limits.as_payload(),
            "network_policy": self.network_policy,
            "output_policy": self.output_policy,
        }


_SAFE_LOGICAL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,159}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class PythonOutputManifest:
    logical_name: str
    size_bytes: int
    sha256: str
    mime_type: str
    validation_status: Literal["VALIDATED", "REJECTED"]

    def validate(self) -> None:
        if not _SAFE_LOGICAL_NAME.fullmatch(self.logical_name):
            raise PythonRuntimeOutputInvalid("PYTHON_RUNTIME_OUTPUT_NAME_INVALID")
        if self.size_bytes < 0:
            raise PythonRuntimeOutputInvalid("PYTHON_RUNTIME_OUTPUT_SIZE_INVALID")
        if not _SHA256.fullmatch(self.sha256):
            raise PythonRuntimeOutputInvalid("PYTHON_RUNTIME_OUTPUT_SHA256_INVALID")
        if not self.mime_type or len(self.mime_type) > 160:
            raise PythonRuntimeOutputInvalid("PYTHON_RUNTIME_OUTPUT_MIME_INVALID")
        if self.validation_status != "VALIDATED":
            raise PythonRuntimeOutputInvalid("PYTHON_RUNTIME_OUTPUT_NOT_VALIDATED")


@dataclass(frozen=True, slots=True)
class PythonRuntimeResult:
    execution_id: str
    sandbox_execution_id: str | None
    status: PythonExecutionStatus
    code_sha256: str
    runtime_profile_id: str
    runtime_profile_digest: str | None
    sandbox_provider: str
    stdout: str
    stderr: str
    exit_code: int | None
    duration_ms: int
    truncated: bool
    network_policy: str
    network_policy_enforced: bool
    filesystem_isolation_enforced: bool
    cpu_limit_enforced: bool
    memory_limit_enforced: bool
    process_limit_enforced: bool = False
    ephemeral_filesystem_enforced: bool = False
    no_operational_secrets: bool = False
    attestation: dict[str, object] = field(default_factory=dict)
    outputs: tuple[PythonOutputManifest, ...] = ()
    audit_ref: str | None = None

    @property
    def execution_performed(self) -> bool:
        return self.status in {"SUCCEEDED", "FAILED", "TIMED_OUT"}

    def as_context(self) -> dict[str, str]:
        return {
            "role": "system",
            "content": (
                "PYTHON RUNTIME RESULT — TRUSTED EXECUTION METADATA / USER CODE OUTPUT.\n"
                f"execution_id={self.execution_id}\n"
                f"status={self.status}\n"
                f"runtime={self.sandbox_provider}\n"
                f"runtime_profile_id={self.runtime_profile_id}\n"
                f"runtime_profile_digest={self.runtime_profile_digest}\n"
                f"code_sha256={self.code_sha256}\n"
                f"exit_code={self.exit_code}\n"
                f"duration_ms={self.duration_ms}\n"
                f"truncated={str(self.truncated).lower()}\n"
                f"network_policy={self.network_policy}\n"
                f"network_policy_enforced={str(self.network_policy_enforced).lower()}\n"
                f"filesystem_isolation_enforced={str(self.filesystem_isolation_enforced).lower()}\n"
                f"cpu_limit_enforced={str(self.cpu_limit_enforced).lower()}\n"
                f"memory_limit_enforced={str(self.memory_limit_enforced).lower()}\n"
                f"process_limit_enforced={str(self.process_limit_enforced).lower()}\n"
                "stdout:\n"
                f"{self.stdout or '[empty]'}\n"
                "stderr:\n"
                f"{self.stderr or '[empty]'}\n"
                "Use this result as evidence. Do not infer stronger isolation than the attested fields."
            ),
        }
