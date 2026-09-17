from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


class AuditEvidenceError(RuntimeError):
    code = "AUDIT_EVIDENCE_ERROR"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class AuditEvidenceEnvelope:
    schema_version: str
    audit_execution_id: str
    request_id: str
    execution_id: str
    tenant_id: str
    user_id: str
    capability_id: str
    capability_version: str
    environment: str
    deployment_id: str
    requested_agent_id: str | None
    resolved_agent_id: str
    turn_owner_agent_id: str | None
    capability_decision: str
    capability_decision_reason: str
    status: str
    artifact_id: str | None
    root_id: str | None
    sanitized: bool
    read_executed: bool
    write_executed: bool
    migration_executed: bool
    deploy_executed: bool
    human_approval_required: bool
    started_at: str
    finished_at: str
    data: dict[str, Any] | None
    error_code: str | None
    created_at: str

    def to_dict(self, *, max_serialized_bytes: int = 128_000) -> dict[str, Any]:
        payload = asdict(self)
        encoded = json.dumps(
            payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        if len(encoded) > max_serialized_bytes:
            raise AuditEvidenceError("AUDIT_EVIDENCE_OUTPUT_TOO_LARGE")
        return payload


def build_evidence_envelope(
    *,
    request_id: str,
    execution_id: str,
    tenant_id: str,
    user_id: str,
    capability_id: str,
    capability_version: str,
    environment: str,
    deployment_id: str,
    requested_agent_id: str | None,
    resolved_agent_id: str,
    turn_owner_agent_id: str | None,
    capability_decision: str,
    capability_decision_reason: str,
    status: str,
    sanitized: bool,
    read_executed: bool,
    write_executed: bool = False,
    migration_executed: bool = False,
    deploy_executed: bool = False,
    human_approval_required: bool = True,
    started_at: str | None = None,
    finished_at: str | None = None,
    artifact_id: str | None = None,
    root_id: str | None = None,
    data: dict[str, Any] | None = None,
    error_code: str | None = None,
) -> AuditEvidenceEnvelope:
    if capability_decision not in {"ALLOW", "DENY"}:
        raise AuditEvidenceError("AUDIT_EVIDENCE_DECISION_INVALID")
    if status not in {"completed", "failed", "denied"}:
        raise AuditEvidenceError("AUDIT_EVIDENCE_STATUS_INVALID")
    if any((write_executed, migration_executed, deploy_executed)):
        raise AuditEvidenceError("AUDIT_EVIDENCE_READONLY_INVARIANT_VIOLATED")
    if capability_decision == "DENY" and read_executed:
        raise AuditEvidenceError("AUDIT_EVIDENCE_DENIED_READ_EXECUTED")
    if not capability_version.strip():
        raise AuditEvidenceError("AUDIT_EVIDENCE_CAPABILITY_VERSION_REQUIRED")
    if not environment.strip():
        raise AuditEvidenceError("AUDIT_EVIDENCE_ENVIRONMENT_REQUIRED")
    if not deployment_id.strip():
        raise AuditEvidenceError("AUDIT_EVIDENCE_DEPLOYMENT_ID_REQUIRED")

    now = _utc_now()
    start = started_at or now
    finish = finished_at or now

    return AuditEvidenceEnvelope(
        schema_version="1.0",
        audit_execution_id=str(uuid4()),
        request_id=request_id,
        execution_id=execution_id,
        tenant_id=tenant_id,
        user_id=user_id,
        capability_id=capability_id,
        capability_version=capability_version,
        environment=environment,
        deployment_id=deployment_id,
        requested_agent_id=requested_agent_id,
        resolved_agent_id=resolved_agent_id,
        turn_owner_agent_id=turn_owner_agent_id,
        capability_decision=capability_decision,
        capability_decision_reason=capability_decision_reason,
        status=status,
        artifact_id=artifact_id,
        root_id=root_id,
        sanitized=sanitized,
        read_executed=read_executed,
        write_executed=write_executed,
        migration_executed=migration_executed,
        deploy_executed=deploy_executed,
        human_approval_required=human_approval_required,
        started_at=start,
        finished_at=finish,
        data=data,
        error_code=error_code,
        created_at=now,
    )
