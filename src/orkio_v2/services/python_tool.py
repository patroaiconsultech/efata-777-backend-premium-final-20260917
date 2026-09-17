from __future__ import annotations

import ast
import asyncio
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass

from .capability_policy import CapabilityPolicy


_SAFE_IMPORTS = {
    "collections", "csv", "datetime", "decimal", "fractions", "functools",
    "itertools", "json", "math", "operator", "random", "re", "statistics",
}
_BANNED_CALLS = {
    "__import__", "breakpoint", "compile", "delattr", "dir", "eval", "exec",
    "getattr", "globals", "help", "input", "locals", "open", "setattr", "vars",
}
_BANNED_ATTRIBUTES = {
    "chdir", "environ", "fork", "getenv", "kill", "listdir", "mkdir", "open",
    "popen", "remove", "rename", "replace", "rmdir", "scandir", "spawn", "system",
    "unlink", "walk", "write_text", "write_bytes", "read_text", "read_bytes",
}
_EXECUTION_VERBS = re.compile(
    r"\b(execute|executar|rode|rodar|run|teste|testar)\b", re.IGNORECASE
)
_FENCED_PYTHON = re.compile(
    r"```(?:python|py)\s*\n(?P<code>.*?)```", re.IGNORECASE | re.DOTALL
)


class PythonToolError(RuntimeError):
    code = "PYTHON_TOOL_ERROR"


class PythonToolDisabled(PythonToolError):
    code = "PYTHON_TOOL_DISABLED"


class PythonCodeRejected(PythonToolError):
    code = "PYTHON_CODE_REJECTED"


class PythonExecutionFailed(PythonToolError):
    code = "PYTHON_EXECUTION_FAILED"


@dataclass(frozen=True, slots=True)
class PythonExecutionResult:
    code_sha256: str
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    truncated: bool

    def as_context(self) -> dict[str, str]:
        return {
            "role": "system",
            "content": (
                "PYTHON TOOL RESULT — TRUSTED EXECUTION METADATA / USER CODE OUTPUT.\n"
                f"code_sha256={self.code_sha256}\n"
                f"exit_code={self.exit_code}\n"
                f"duration_ms={self.duration_ms}\n"
                f"truncated={str(self.truncated).lower()}\n"
                "stdout:\n"
                f"{self.stdout or '[empty]'}\n"
                "stderr:\n"
                f"{self.stderr or '[empty]'}\n"
                "Use the result as evidence. Do not claim filesystem or network access."
            ),
        }


class _Validator(ast.NodeVisitor):
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name.split(".", 1)[0] not in _SAFE_IMPORTS:
                raise PythonCodeRejected("PYTHON_IMPORT_FORBIDDEN")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not node.module or node.module.split(".", 1)[0] not in _SAFE_IMPORTS:
            raise PythonCodeRejected("PYTHON_IMPORT_FORBIDDEN")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id.startswith("__") or node.id in _BANNED_CALLS:
            raise PythonCodeRejected("PYTHON_NAME_FORBIDDEN")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr.startswith("__") or node.attr in _BANNED_ATTRIBUTES:
            raise PythonCodeRejected("PYTHON_ATTRIBUTE_FORBIDDEN")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in _BANNED_CALLS:
            raise PythonCodeRejected("PYTHON_CALL_FORBIDDEN")
        if isinstance(node.func, ast.Attribute) and node.func.attr in _BANNED_ATTRIBUTES:
            raise PythonCodeRejected("PYTHON_CALL_FORBIDDEN")
        self.generic_visit(node)


def validate_python(code: str, policy: CapabilityPolicy) -> str:
    if not policy.python_enabled:
        raise PythonToolDisabled("PYTHON_TOOL_DISABLED")
    raw = (code or "").encode("utf-8")
    if not raw or len(raw) > policy.python_max_code_bytes:
        raise PythonCodeRejected("PYTHON_CODE_SIZE_INVALID")
    if "\x00" in code:
        raise PythonCodeRejected("PYTHON_CODE_NUL_REJECTED")
    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError as exc:
        raise PythonCodeRejected("PYTHON_SYNTAX_INVALID") from exc
    _Validator().visit(tree)
    return code


def _run_sync(code: str, policy: CapabilityPolicy) -> PythonExecutionResult:
    validated = validate_python(code, policy)
    code_hash = hashlib.sha256(validated.encode("utf-8")).hexdigest()
    env = {
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    with tempfile.TemporaryDirectory(prefix="orkio-python-") as tmp:
        import time
        start = time.monotonic()
        try:
            cp = subprocess.run(
                [sys.executable, "-I", "-S", "-c", validated],
                cwd=tmp,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=policy.python_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PythonExecutionFailed("PYTHON_EXECUTION_TIMEOUT") from exc
        duration_ms = int((time.monotonic() - start) * 1000)

    stdout_raw = cp.stdout or b""
    stderr_raw = cp.stderr or b""
    combined = len(stdout_raw) + len(stderr_raw)
    limit = policy.python_max_output_bytes
    truncated = combined > limit
    stdout = stdout_raw[:limit].decode("utf-8", errors="replace")
    remaining = max(0, limit - len(stdout_raw[:limit]))
    stderr = stderr_raw[:remaining].decode("utf-8", errors="replace")
    return PythonExecutionResult(
        code_sha256=code_hash,
        stdout=stdout,
        stderr=stderr,
        exit_code=cp.returncode,
        duration_ms=duration_ms,
        truncated=truncated,
    )


def _ensure_legacy_local_runtime_allowed(policy: CapabilityPolicy) -> None:
    if not policy.python_enabled:
        raise PythonToolDisabled("PYTHON_TOOL_DISABLED")
    if (
        policy.python_runtime_mode != "legacy_local_test"
        or not policy.python_legacy_local_test_enabled
        or policy.python_runtime_environment not in {"development", "test"}
    ):
        raise PythonToolDisabled("PYTHON_LEGACY_RUNTIME_FORBIDDEN")


async def execute_python_legacy_local(
    code: str,
    policy: CapabilityPolicy,
) -> PythonExecutionResult:
    _ensure_legacy_local_runtime_allowed(policy)
    return await asyncio.to_thread(_run_sync, code, policy)


async def execute_python(code: str, policy: CapabilityPolicy) -> PythonExecutionResult:
    """Backward-compatible name for the explicitly test-only legacy executor.

    This function is deliberately fail-closed unless the R5 legacy-local test
    mode is explicitly enabled in development/test.
    """
    return await execute_python_legacy_local(code, policy)


def extract_explicit_python_request(message: str) -> str | None:
    text = message or ""
    if not _EXECUTION_VERBS.search(text):
        return None
    match = _FENCED_PYTHON.search(text)
    if not match:
        return None
    return match.group("code").strip()


async def python_context_messages(
    policy: CapabilityPolicy,
    *,
    message: str,
    privileged: bool,
    runtime_context=None,
    db=None,
) -> list[dict[str, str]]:
    code = extract_explicit_python_request(message)
    if code is None:
        return []
    if not privileged:
        return [{
            "role": "system",
            "content": "PYTHON_TOOL_REQUEST_DENIED code=PYTHON_ADMIN_REQUIRED",
        }]
    if runtime_context is None:
        return [{
            "role": "system",
            "content": "PYTHON_TOOL_REQUEST_FAILED code=PYTHON_RUNTIME_CONTEXT_REQUIRED",
        }]

    # Lazy import preserves the legacy validator as defense-in-depth without
    # making the architecture depend on the same-host executor.
    from .python_runtime.contracts import PythonRuntimeError
    from .python_runtime.gateway import execute_python_runtime

    try:
        result = await execute_python_runtime(
            code=code,
            policy=policy,
            context=runtime_context,
            db=db,
        )
    except (PythonToolError, PythonRuntimeError) as exc:
        error_code = exc.args[0] if exc.args else getattr(exc, "code", "PYTHON_RUNTIME_ERROR")
        return [{
            "role": "system",
            "content": f"PYTHON_TOOL_REQUEST_FAILED code={error_code}",
        }]
    return [result.as_context()]

