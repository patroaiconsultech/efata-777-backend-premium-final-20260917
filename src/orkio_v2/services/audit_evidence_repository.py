from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import unicodedata
import uuid
from collections.abc import Callable
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models import AuditEvidenceRecord
from .audit_evidence import AuditEvidenceEnvelope
from .audit_secret_policy import AuditSecretPolicyError, assert_no_high_confidence_secrets


_MAX_SERIALIZED_BYTES = 128_000
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_FIELDS = frozenset({"started_at", "finished_at", "created_at"})


class AuditEvidenceRepositoryError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class AppendEvidenceResult:
    record_id: str
    evidence_sha256: str
    idempotent_replay: bool


@dataclass(frozen=True, slots=True)
class AuditEvidenceSnapshot:
    id: str
    audit_execution_id: str
    tenant_id: str
    execution_id: str
    capability_id: str
    status: str
    evidence_sha256: str
    envelope_json: dict[str, Any]
    created_at: datetime


SessionFactory = Callable[[], Session]

_AUDIT_EXECUTION_UNIQUE_CONSTRAINT = "uq_audit_evidence_audit_execution_id"
_SQLITE_AUDIT_EXECUTION_UNIQUE_SIGNATURE = (
    "UNIQUE constraint failed: audit_evidence_records.audit_execution_id"
)


def _is_audit_execution_unique_violation(
    exc: IntegrityError,
    *,
    dialect_name: str | None,
) -> bool:
    """Return True only for the ledger's audit_execution_id unique constraint."""
    original = getattr(exc, "orig", None)

    if dialect_name == "postgresql":
        diagnostic = getattr(original, "diag", None)
        constraint_name = getattr(diagnostic, "constraint_name", None)
        return constraint_name == _AUDIT_EXECUTION_UNIQUE_CONSTRAINT

    if dialect_name == "sqlite":
        return str(original).strip() == _SQLITE_AUDIT_EXECUTION_UNIQUE_SIGNATURE

    return False



def _canonical_timestamp(value: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_TIMESTAMP_INVALID")
    raw = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_TIMESTAMP_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_TIMESTAMP_INVALID")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _normalize(value: Any, *, key: str | None = None) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = unicodedata.normalize("NFC", value)
        if key in _TIMESTAMP_FIELDS:
            return _canonical_timestamp(normalized)
        return normalized
    if isinstance(value, int) and not isinstance(value, bool):
        if value < _INT64_MIN or value > _INT64_MAX:
            raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_INTEGER_OUT_OF_RANGE")
        return value
    if isinstance(value, float):
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_FLOAT_FORBIDDEN")
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, tuple):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            if not isinstance(raw_key, str):
                raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_KEY_INVALID")
            normalized_key = unicodedata.normalize("NFC", raw_key)
            if normalized_key in result:
                raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_NFC_KEY_COLLISION")
            result[normalized_key] = _normalize(raw_value, key=normalized_key)
        return result
    raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_UNSUPPORTED_VALUE")


def _payload(envelope: AuditEvidenceEnvelope | dict[str, Any]) -> dict[str, Any]:
    if isinstance(envelope, AuditEvidenceEnvelope):
        try:
            raw = envelope.to_dict(max_serialized_bytes=_MAX_SERIALIZED_BYTES)
        except Exception as exc:
            message = str(exc)
            code = (
                message
                if message.startswith("AUDIT_EVIDENCE_")
                else (getattr(exc, "code", None) or message)
            )
            raise AuditEvidenceRepositoryError(str(code)) from exc
    elif isinstance(envelope, dict):
        raw = dict(envelope)
    else:
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_ENVELOPE_INVALID")

    normalized = _normalize(raw)
    if not isinstance(normalized, dict):
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_ENVELOPE_INVALID")

    required = {
        "schema_version",
        "audit_execution_id",
        "request_id",
        "execution_id",
        "tenant_id",
        "user_id",
        "capability_id",
        "capability_version",
        "environment",
        "deployment_id",
        "resolved_agent_id",
        "capability_decision",
        "status",
        "sanitized",
        "read_executed",
        "write_executed",
        "migration_executed",
        "deploy_executed",
        "started_at",
        "finished_at",
        "created_at",
    }
    missing = sorted(required - set(normalized))
    if missing:
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_REQUIRED_FIELD_MISSING")

    if normalized["capability_decision"] not in {"ALLOW", "DENY"}:
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_DECISION_INVALID")
    if normalized["status"] not in {"completed", "failed", "denied"}:
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_STATUS_INVALID")
    if normalized["sanitized"] is not True:
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_SANITIZATION_REQUIRED")
    if any(
        normalized.get(name) is True
        for name in ("write_executed", "migration_executed", "deploy_executed")
    ):
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_READONLY_INVARIANT_VIOLATED")
    if normalized["capability_decision"] == "DENY" and normalized["read_executed"] is True:
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_DENIED_READ_EXECUTED")

    for name in (
        "schema_version",
        "audit_execution_id",
        "request_id",
        "execution_id",
        "tenant_id",
        "user_id",
        "capability_id",
        "capability_version",
        "environment",
        "deployment_id",
        "resolved_agent_id",
    ):
        if not isinstance(normalized.get(name), str) or not normalized[name].strip():
            raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_REQUIRED_FIELD_INVALID")

    return normalized


def canonicalize_json_v1(value: Any) -> bytes:
    normalized = _normalize(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonicalize_evidence(envelope: AuditEvidenceEnvelope | dict[str, Any]) -> bytes:
    payload = _payload(envelope)
    encoded = canonicalize_json_v1(payload)
    if len(encoded) > _MAX_SERIALIZED_BYTES:
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_OUTPUT_TOO_LARGE")
    try:
        assert_no_high_confidence_secrets(encoded)
    except AuditSecretPolicyError as exc:
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_SECRET_CONTENT_BLOCKED") from exc
    return encoded


def evidence_sha256(envelope: AuditEvidenceEnvelope | dict[str, Any]) -> str:
    return hashlib.sha256(canonicalize_evidence(envelope)).hexdigest()


def _snapshot(row: AuditEvidenceRecord) -> AuditEvidenceSnapshot:
    return AuditEvidenceSnapshot(
        id=row.id,
        audit_execution_id=row.audit_execution_id,
        tenant_id=row.tenant_id,
        execution_id=row.execution_id,
        capability_id=row.capability_id,
        status=row.status,
        evidence_sha256=row.evidence_sha256,
        envelope_json=dict(row.envelope_json),
        created_at=row.created_at,
    )


def _compare_existing(
    row: AuditEvidenceRecord,
    *,
    tenant_id: str,
    digest: str,
) -> AppendEvidenceResult:
    if row.tenant_id == tenant_id and row.evidence_sha256 == digest:
        return AppendEvidenceResult(
            record_id=row.id,
            evidence_sha256=row.evidence_sha256,
            idempotent_replay=True,
        )
    raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_IDEMPOTENCY_CONFLICT")


def _existing_by_execution_id(
    session_factory: SessionFactory,
    audit_execution_id: str,
) -> AuditEvidenceRecord | None:
    with session_factory() as db:
        row = db.scalar(
            select(AuditEvidenceRecord).where(
                AuditEvidenceRecord.audit_execution_id == audit_execution_id
            )
        )
        if row is None:
            return None
        db.expunge(row)
        return row


def append_evidence(
    envelope: AuditEvidenceEnvelope | dict[str, Any],
    *,
    session_factory: SessionFactory = SessionLocal,
) -> AppendEvidenceResult:
    payload = _payload(envelope)
    canonical = canonicalize_evidence(payload)
    digest = hashlib.sha256(canonical).hexdigest()

    audit_execution_id = payload["audit_execution_id"]
    tenant_id = payload["tenant_id"]

    existing = _existing_by_execution_id(session_factory, audit_execution_id)
    if existing is not None:
        return _compare_existing(existing, tenant_id=tenant_id, digest=digest)

    record_id = str(uuid.uuid4())
    row = AuditEvidenceRecord(
        id=record_id,
        schema_version=payload["schema_version"],
        audit_execution_id=audit_execution_id,
        tenant_id=tenant_id,
        user_id=payload["user_id"],
        request_id=payload["request_id"],
        execution_id=payload["execution_id"],
        capability_id=payload["capability_id"],
        capability_version=payload["capability_version"],
        environment=payload["environment"],
        deployment_id=payload["deployment_id"],
        resolved_agent_id=payload["resolved_agent_id"],
        capability_decision=payload["capability_decision"],
        status=payload["status"],
        artifact_id=payload.get("artifact_id"),
        root_id=payload.get("root_id"),
        error_code=payload.get("error_code"),
        envelope_json=payload,
        evidence_sha256=digest,
        created_at=datetime.now(timezone.utc),
    )

    dialect_name: str | None = None
    try:
        with session_factory() as db:
            bind = db.get_bind()
            dialect_name = getattr(getattr(bind, "dialect", None), "name", None)
            db.add(row)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                raise
            except Exception:
                db.rollback()
                raise
    except IntegrityError as exc:
        if not _is_audit_execution_unique_violation(
            exc,
            dialect_name=dialect_name,
        ):
            raise AuditEvidenceRepositoryError(
                "AUDIT_EVIDENCE_PERSISTENCE_INTEGRITY_ERROR"
            ) from exc
        winner = _existing_by_execution_id(session_factory, audit_execution_id)
        if winner is None:
            raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_PERSISTENCE_INTEGRITY_ERROR") from exc
        return _compare_existing(winner, tenant_id=tenant_id, digest=digest)
    except Exception as exc:
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_PERSISTENCE_FAILED") from exc

    verified = verify_persisted_evidence(
        tenant_id=tenant_id,
        record_id=record_id,
        session_factory=session_factory,
    )
    if verified.evidence_sha256 != digest:
        raise AuditEvidenceRepositoryError(
            "AUDIT_EVIDENCE_PERSISTENCE_INTEGRITY_MISMATCH"
        )
    return AppendEvidenceResult(
        record_id=record_id,
        evidence_sha256=digest,
        idempotent_replay=False,
    )


def get_evidence_for_tenant(
    *,
    tenant_id: str,
    record_id: str,
    session_factory: SessionFactory = SessionLocal,
) -> AuditEvidenceSnapshot:
    with session_factory() as db:
        row = db.scalar(
            select(AuditEvidenceRecord).where(
                AuditEvidenceRecord.id == record_id,
                AuditEvidenceRecord.tenant_id == tenant_id,
            )
        )
        if row is None:
            raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_NOT_FOUND")
        return _snapshot(row)


def list_evidence_for_execution(
    *,
    tenant_id: str,
    execution_id: str,
    limit: int = 50,
    cursor: str | None = None,
    session_factory: SessionFactory = SessionLocal,
) -> list[AuditEvidenceSnapshot]:
    bounded_limit = max(1, min(int(limit), 100))
    with session_factory() as db:
        conditions = [
            AuditEvidenceRecord.tenant_id == tenant_id,
            AuditEvidenceRecord.execution_id == execution_id,
        ]
        if cursor:
            cursor_row = db.scalar(
                select(AuditEvidenceRecord).where(
                    AuditEvidenceRecord.id == cursor,
                    AuditEvidenceRecord.tenant_id == tenant_id,
                    AuditEvidenceRecord.execution_id == execution_id,
                )
            )
            if cursor_row is None:
                return []
            conditions.append(
                or_(
                    AuditEvidenceRecord.created_at < cursor_row.created_at,
                    and_(
                        AuditEvidenceRecord.created_at == cursor_row.created_at,
                        AuditEvidenceRecord.id < cursor_row.id,
                    ),
                )
            )
        rows = db.scalars(
            select(AuditEvidenceRecord)
            .where(*conditions)
            .order_by(
                AuditEvidenceRecord.created_at.desc(),
                AuditEvidenceRecord.id.desc(),
            )
            .limit(bounded_limit)
        ).all()
        return [_snapshot(row) for row in rows]


def verify_persisted_evidence(
    *,
    tenant_id: str,
    record_id: str,
    session_factory: SessionFactory = SessionLocal,
) -> AuditEvidenceSnapshot:
    with session_factory() as db:
        row = db.scalar(
            select(AuditEvidenceRecord).where(
                AuditEvidenceRecord.id == record_id,
                AuditEvidenceRecord.tenant_id == tenant_id,
            )
        )
        if row is None:
            raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_NOT_FOUND")

        payload = dict(row.envelope_json)
        digest = evidence_sha256(payload)
        if not _SHA256_RE.fullmatch(str(row.evidence_sha256 or "")):
            raise AuditEvidenceRepositoryError(
                "AUDIT_EVIDENCE_PERSISTENCE_INTEGRITY_MISMATCH"
            )
        if digest != row.evidence_sha256:
            raise AuditEvidenceRepositoryError(
                "AUDIT_EVIDENCE_PERSISTENCE_INTEGRITY_MISMATCH"
            )

        bindings = {
            "schema_version": row.schema_version,
            "audit_execution_id": row.audit_execution_id,
            "tenant_id": row.tenant_id,
            "user_id": row.user_id,
            "request_id": row.request_id,
            "execution_id": row.execution_id,
            "capability_id": row.capability_id,
            "capability_version": row.capability_version,
            "environment": row.environment,
            "deployment_id": row.deployment_id,
            "resolved_agent_id": row.resolved_agent_id,
            "capability_decision": row.capability_decision,
            "status": row.status,
            "artifact_id": row.artifact_id,
            "root_id": row.root_id,
            "error_code": row.error_code,
        }
        for key, column_value in bindings.items():
            if payload.get(key) != column_value:
                raise AuditEvidenceRepositoryError(
                    "AUDIT_EVIDENCE_COLUMN_BINDING_MISMATCH"
                )
        return _snapshot(row)
