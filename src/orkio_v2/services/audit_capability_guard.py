from __future__ import annotations

import json
import re
import unicodedata
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from .audit_secret_policy import AuditSecretPolicyError, assert_no_high_confidence_secrets
from .capability_registry import CapabilitySpec


class AuditCapabilityGuardError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
        self.terminal = True
        self.result_accepted = False


@dataclass(frozen=True, slots=True)
class GuardedAuditResult:
    data: Any
    sanitized: bool
    serialized_bytes: int


_SENSITIVE_KEY = re.compile(
    r"(authorization|cookie|token|secret|password|api[_-]?key|credential)",
    re.IGNORECASE,
)


def _sanitize_string(value: str) -> tuple[str, bool]:
    try:
        assert_no_high_confidence_secrets(value)
    except AuditSecretPolicyError as exc:
        raise AuditCapabilityGuardError("AUDIT_OUTPUT_SECRET_BLOCKED") from exc
    cleaned = "".join(
        ch
        for ch in value
        if unicodedata.category(ch) != "Cc" or ch in {"\t", "\n", "\r"}
    )
    return cleaned, cleaned != value


def _sanitize_value(value: Any, *, depth: int = 0) -> tuple[Any, bool]:
    if depth > 8:
        raise AuditCapabilityGuardError("AUDIT_OUTPUT_STRUCTURE_TOO_DEEP")
    if value is None or isinstance(value, (bool, int, float)):
        return value, False
    if isinstance(value, str):
        return _sanitize_string(value)
    if isinstance(value, Mapping):
        if len(value) > 512:
            raise AuditCapabilityGuardError("AUDIT_OUTPUT_TOO_MANY_ITEMS")
        clean: dict[str, Any] = {}
        changed = False
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            if _SENSITIVE_KEY.search(key):
                changed = True
                continue
            clean_value, child_changed = _sanitize_value(
                raw_value, depth=depth + 1
            )
            clean[key] = clean_value
            changed = changed or child_changed
        return clean, changed
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        if len(value) > 512:
            raise AuditCapabilityGuardError("AUDIT_OUTPUT_TOO_MANY_ITEMS")
        clean_items = []
        changed = False
        for item in value:
            clean_item, child_changed = _sanitize_value(item, depth=depth + 1)
            clean_items.append(clean_item)
            changed = changed or child_changed
        return clean_items, changed
    raise AuditCapabilityGuardError("AUDIT_OUTPUT_TYPE_FORBIDDEN")


class AuditCapabilityGuard:
    """Fail-closed execution seam for future governed invocation.

    Gate 033A does not wire this seam to a route/chat path. It freezes timeout,
    single-attempt, sanitization, and serialized output bounds before 033B/033C.
    """

    def execute(
        self,
        *,
        spec: CapabilitySpec,
        operation: Callable[[], Any],
    ) -> GuardedAuditResult:
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="audit-cap")
        future = executor.submit(operation)
        try:
            try:
                raw = future.result(timeout=spec.timeout_seconds)
            except FutureTimeoutError as exc:
                future.cancel()
                raise AuditCapabilityGuardError("AUDIT_REQUEST_TIMEOUT") from exc
        finally:
            # Do not wait for a timed-out read-only worker. No retry is issued and
            # any late result is discarded by this seam.
            executor.shutdown(wait=False, cancel_futures=True)

        clean, changed = _sanitize_value(raw)
        encoded = json.dumps(
            clean,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > spec.max_output_bytes:
            raise AuditCapabilityGuardError("AUDIT_OUTPUT_TOO_LARGE")
        return GuardedAuditResult(
            data=clean,
            sanitized=changed,
            serialized_bytes=len(encoded),
        )
