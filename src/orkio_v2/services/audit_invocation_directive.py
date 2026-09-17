from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from .audit_invocation_contracts import (
    AUDIT_DIRECTIVE_VERSION,
    AuditInvocationContractError,
    AuditOperationSpec,
    operation_spec,
)


class AuditDirectiveError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class AuditDirective:
    version: str
    operation: str
    spec: AuditOperationSpec
    arguments: dict[str, Any]


_FORBIDDEN_FIELDS = frozenset(
    {
        "tenant_id",
        "user_id",
        "agent_id",
        "requested_agent_id",
        "resolved_agent_id",
        "turn_owner_agent_id",
        "environment",
        "deployment_id",
        "privileged_user",
        "write_allowed",
        "execution_allowed",
        "root_id",
        "relative_path",
        "path",
        "absolute_path",
        "shell",
        "command",
        "sql",
        "query",
        "url",
        "network",
        "http",
        "https",
    }
)
_STRING_LIMITS = {
    "artifact_id": 128,
    "module_id": 120,
    "member_name": 1024,
    "marker": 512,
}
_INTEGER_FIELDS = frozenset({"offset", "max_bytes", "max_scan_bytes", "max_matches", "limit"})
_MAX_DIRECTIVE_BYTES = 20_000


def looks_like_audit_directive(message: str) -> bool:
    return str(message or "").lstrip().startswith("/audit")


def _validate_value(name: str, value: Any) -> None:
    if name in _STRING_LIMITS:
        if not isinstance(value, str) or not value.strip():
            raise AuditDirectiveError("AUDIT_DIRECTIVE_FIELD_INVALID")
        if len(value.encode("utf-8")) > _STRING_LIMITS[name]:
            raise AuditDirectiveError("AUDIT_DIRECTIVE_FIELD_TOO_LARGE")
        if "\x00" in value:
            raise AuditDirectiveError("AUDIT_DIRECTIVE_FIELD_INVALID")
        return
    if name in _INTEGER_FIELDS:
        if isinstance(value, bool) or not isinstance(value, int):
            raise AuditDirectiveError("AUDIT_DIRECTIVE_FIELD_INVALID")
        if value < 0:
            raise AuditDirectiveError("AUDIT_DIRECTIVE_FIELD_INVALID")
        return


def parse_audit_directive(message: str) -> AuditDirective | None:
    text = str(message or "")
    if not looks_like_audit_directive(text):
        return None
    if not text.startswith("/audit "):
        raise AuditDirectiveError("AUDIT_DIRECTIVE_FORMAT_INVALID")
    if len(text.encode("utf-8")) > _MAX_DIRECTIVE_BYTES:
        raise AuditDirectiveError("AUDIT_DIRECTIVE_TOO_LARGE")

    raw_json = text[len("/audit ") :]
    try:
        decoder = json.JSONDecoder()
        payload, end = decoder.raw_decode(raw_json)
    except Exception as exc:
        raise AuditDirectiveError("AUDIT_DIRECTIVE_JSON_INVALID") from exc
    if raw_json[end:].strip():
        raise AuditDirectiveError("AUDIT_DIRECTIVE_TRAILING_TEXT_FORBIDDEN")
    if not isinstance(payload, dict):
        raise AuditDirectiveError("AUDIT_DIRECTIVE_OBJECT_REQUIRED")

    forbidden = sorted(_FORBIDDEN_FIELDS.intersection(payload))
    if forbidden:
        raise AuditDirectiveError("AUDIT_DIRECTIVE_FORBIDDEN_FIELD")

    version = payload.get("version")
    operation = payload.get("operation")
    if version != AUDIT_DIRECTIVE_VERSION:
        raise AuditDirectiveError("AUDIT_DIRECTIVE_VERSION_INVALID")
    if not isinstance(operation, str) or not operation.strip():
        raise AuditDirectiveError("AUDIT_DIRECTIVE_OPERATION_REQUIRED")
    try:
        spec = operation_spec(operation)
    except AuditInvocationContractError as exc:
        raise AuditDirectiveError(exc.code) from exc

    unknown = set(payload) - set(spec.allowed_fields)
    if unknown:
        raise AuditDirectiveError("AUDIT_DIRECTIVE_UNKNOWN_FIELD")
    missing = set(spec.required_fields) - set(payload)
    if missing:
        raise AuditDirectiveError("AUDIT_DIRECTIVE_REQUIRED_FIELD_MISSING")

    arguments = {
        key: value for key, value in payload.items() if key not in {"version", "operation"}
    }
    for name, value in arguments.items():
        _validate_value(name, value)

    return AuditDirective(
        version=version,
        operation=operation,
        spec=spec,
        arguments=arguments,
    )
