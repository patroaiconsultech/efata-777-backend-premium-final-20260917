from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from .capability_registry import (
    AUDIT_ARCHIVE_INSPECT,
    AUDIT_FILE_INSPECT,
    AUDIT_RUNTIME_FILE_SHA256,
    AUDIT_RUNTIME_SEARCH_MARKER,
)


class AuditInvocationContractError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class AuditOperationSpec:
    operation: str
    capability_id: str
    required_fields: frozenset[str]
    optional_fields: frozenset[str]

    @property
    def allowed_fields(self) -> frozenset[str]:
        return frozenset({"version", "operation"}) | self.required_fields | self.optional_fields


_OPERATION_SPECS = {
    "file.metadata": AuditOperationSpec(
        "file.metadata", AUDIT_FILE_INSPECT, frozenset({"artifact_id"}), frozenset()
    ),
    "file.read_text": AuditOperationSpec(
        "file.read_text",
        AUDIT_FILE_INSPECT,
        frozenset({"artifact_id"}),
        frozenset({"offset", "max_bytes"}),
    ),
    "file.find_literal_marker": AuditOperationSpec(
        "file.find_literal_marker",
        AUDIT_FILE_INSPECT,
        frozenset({"artifact_id", "marker"}),
        frozenset({"max_scan_bytes", "max_matches"}),
    ),
    "archive.preflight": AuditOperationSpec(
        "archive.preflight", AUDIT_ARCHIVE_INSPECT, frozenset({"artifact_id"}), frozenset()
    ),
    "archive.manifest": AuditOperationSpec(
        "archive.manifest",
        AUDIT_ARCHIVE_INSPECT,
        frozenset({"artifact_id"}),
        frozenset({"offset", "limit"}),
    ),
    "archive.file_metadata": AuditOperationSpec(
        "archive.file_metadata",
        AUDIT_ARCHIVE_INSPECT,
        frozenset({"artifact_id", "member_name"}),
        frozenset(),
    ),
    "archive.read_text_member": AuditOperationSpec(
        "archive.read_text_member",
        AUDIT_ARCHIVE_INSPECT,
        frozenset({"artifact_id", "member_name"}),
        frozenset({"offset", "max_bytes"}),
    ),
    "archive.hash_member": AuditOperationSpec(
        "archive.hash_member",
        AUDIT_ARCHIVE_INSPECT,
        frozenset({"artifact_id", "member_name"}),
        frozenset(),
    ),
    "runtime.file_sha256": AuditOperationSpec(
        "runtime.file_sha256",
        AUDIT_RUNTIME_FILE_SHA256,
        frozenset({"module_id"}),
        frozenset(),
    ),
    "runtime.search_marker": AuditOperationSpec(
        "runtime.search_marker",
        AUDIT_RUNTIME_SEARCH_MARKER,
        frozenset({"module_id", "marker"}),
        frozenset({"max_scan_bytes", "max_matches"}),
    ),
}

AUDIT_OPERATION_SPECS: Mapping[str, AuditOperationSpec] = MappingProxyType(_OPERATION_SPECS)
MAX_AUDIT_INVOCATIONS_PER_TURN = 1
AUDIT_DIRECTIVE_VERSION = "1"
AUDIT_CANONICAL_AGENT_ID = "auditor"
AUDIT_GOVERNANCE_MODE = "audit_readonly"

RUNTIME_MODULE_ALLOWLIST: Mapping[str, str] = MappingProxyType(
    {
        "routes": "src/orkio_v2/routes.py",
        "capability_registry": "src/orkio_v2/services/capability_registry.py",
        "audit_evidence_repository": "src/orkio_v2/services/audit_evidence_repository.py",
        "audit_invocation_service": "src/orkio_v2/services/audit_invocation_service.py",
    }
)


def operation_spec(operation: str) -> AuditOperationSpec:
    try:
        return AUDIT_OPERATION_SPECS[operation]
    except KeyError as exc:
        raise AuditInvocationContractError("AUDIT_OPERATION_UNKNOWN") from exc
