from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import sqlite3
import threading

import pytest
from sqlalchemy import create_engine, update
from sqlalchemy.orm import sessionmaker

from orkio_v2.models import AuditEvidenceRecord
from orkio_v2.services.audit_evidence import build_evidence_envelope
import orkio_v2.services.audit_evidence_repository as audit_evidence_repository
from orkio_v2.services.audit_evidence_repository import (
    AuditEvidenceRepositoryError,
    append_evidence,
    canonicalize_json_v1,
    get_evidence_for_tenant,
    list_evidence_for_execution,
    verify_persisted_evidence,
)


def _factory(tmp_path: Path):
    db_path = tmp_path / "audit-evidence.sqlite"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_path}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    AuditEvidenceRecord.__table__.create(engine)
    Factory = sessionmaker(bind=engine, expire_on_commit=False)
    return engine, Factory


def _envelope(
    *,
    audit_execution_id: str = "audit-exec-1",
    tenant_id: str = "tenant-a",
    execution_id: str = "exec-1",
    data=None,
):
    base = build_evidence_envelope(
        request_id="req-1",
        execution_id=execution_id,
        tenant_id=tenant_id,
        user_id="user-a",
        capability_id="runtime.inspect",
        capability_version="1.0",
        environment="test",
        deployment_id="deploy-test",
        requested_agent_id="natan",
        resolved_agent_id="natan",
        turn_owner_agent_id="natan",
        capability_decision="ALLOW",
        capability_decision_reason="test",
        status="completed",
        sanitized=True,
        read_executed=True,
        started_at="2026-09-04T12:34:56.123456Z",
        finished_at="2026-09-04T12:34:57.000000Z",
        data=data,
    )
    return replace(
        base,
        audit_execution_id=audit_execution_id,
        created_at="2026-09-04T12:34:57.000000Z",
    )


def test_canonical_json_v1_golden_vectors():
    first = {
        "b": 2,
        "a": "a\u0301",
        "flag": True,
        "nested": {"z": None, "x": [3, 1]},
    }
    first_bytes = canonicalize_json_v1(first)
    assert first_bytes == (
        '{"a":"á","b":2,"flag":true,"nested":{"x":[3,1],"z":null}}'.encode("utf-8")
    )
    import hashlib
    assert hashlib.sha256(first_bytes).hexdigest() == (
        "cf5003d05ffaa5d02e55493c7b901a71e610ee3246c5253bcfaa4f022d2cffb8"
    )

    second = {
        "schema_version": "ORKIO-AUDIT-EVIDENCE-1",
        "started_at": "2026-09-04T12:34:56.123456Z",
        "finished_at": "2026-09-04T12:34:57.000000Z",
        "read_executed": True,
        "write_executed": False,
    }
    second_bytes = canonicalize_json_v1(second)
    assert second_bytes.decode("utf-8") == (
        '{"finished_at":"2026-09-04T12:34:57.000000Z",'
        '"read_executed":true,'
        '"schema_version":"ORKIO-AUDIT-EVIDENCE-1",'
        '"started_at":"2026-09-04T12:34:56.123456Z",'
        '"write_executed":false}'
    )
    assert hashlib.sha256(second_bytes).hexdigest() == (
        "50cdb56297dca7ffbde3d3d892141faa884ed25aafe436f2bd1de5fa2312828e"
    )


def test_canonical_json_v1_rejects_float_and_nfc_key_collision():
    with pytest.raises(AuditEvidenceRepositoryError) as raised:
        canonicalize_json_v1({"x": 1.5})
    assert raised.value.code == "AUDIT_EVIDENCE_FLOAT_FORBIDDEN"

    with pytest.raises(AuditEvidenceRepositoryError) as raised:
        canonicalize_json_v1({"á": 1, "a\u0301": 2})
    assert raised.value.code == "AUDIT_EVIDENCE_NFC_KEY_COLLISION"


def test_append_is_idempotent_and_reopens_for_integrity(tmp_path):
    _, Factory = _factory(tmp_path)
    envelope = _envelope()

    first = append_evidence(envelope, session_factory=Factory)
    second = append_evidence(envelope, session_factory=Factory)

    assert first.idempotent_replay is False
    assert second.idempotent_replay is True
    assert first.record_id == second.record_id
    assert first.evidence_sha256 == second.evidence_sha256

    verified = verify_persisted_evidence(
        tenant_id="tenant-a",
        record_id=first.record_id,
        session_factory=Factory,
    )
    assert verified.id == first.record_id

    with Factory() as db:
        assert db.query(AuditEvidenceRecord).count() == 1


def test_idempotency_conflict_changed_payload_and_foreign_tenant(tmp_path):
    _, Factory = _factory(tmp_path)
    first = _envelope()
    append_evidence(first, session_factory=Factory)

    with pytest.raises(AuditEvidenceRepositoryError) as raised:
        append_evidence(
            _envelope(data={"changed": "yes"}),
            session_factory=Factory,
        )
    assert raised.value.code == "AUDIT_EVIDENCE_IDEMPOTENCY_CONFLICT"

    with pytest.raises(AuditEvidenceRepositoryError) as raised:
        append_evidence(
            _envelope(tenant_id="tenant-b"),
            session_factory=Factory,
        )
    assert raised.value.code == "AUDIT_EVIDENCE_IDEMPOTENCY_CONFLICT"


def test_tenant_scoped_read_and_list_do_not_enumerate(tmp_path):
    _, Factory = _factory(tmp_path)
    result = append_evidence(_envelope(), session_factory=Factory)

    row = get_evidence_for_tenant(
        tenant_id="tenant-a",
        record_id=result.record_id,
        session_factory=Factory,
    )
    assert row.tenant_id == "tenant-a"

    with pytest.raises(AuditEvidenceRepositoryError) as raised:
        get_evidence_for_tenant(
            tenant_id="tenant-b",
            record_id=result.record_id,
            session_factory=Factory,
        )
    assert raised.value.code == "AUDIT_EVIDENCE_NOT_FOUND"

    assert list_evidence_for_execution(
        tenant_id="tenant-b",
        execution_id="exec-1",
        session_factory=Factory,
    ) == []


def test_secret_and_oversized_evidence_rejected_before_persistence(tmp_path):
    _, Factory = _factory(tmp_path)

    with pytest.raises(AuditEvidenceRepositoryError) as raised:
        append_evidence(
            _envelope(data={"secret": "sk-" + "proj-" + ("A" * 40)}),
            session_factory=Factory,
        )
    assert raised.value.code == "AUDIT_EVIDENCE_SECRET_CONTENT_BLOCKED"

    with pytest.raises(AuditEvidenceRepositoryError) as raised:
        append_evidence(
            _envelope(
                audit_execution_id="audit-large",
                data={"blob": "x" * 130_000},
            ),
            session_factory=Factory,
        )
    assert raised.value.code == "AUDIT_EVIDENCE_OUTPUT_TOO_LARGE"

    with Factory() as db:
        assert db.query(AuditEvidenceRecord).count() == 0


def test_tampered_json_and_column_binding_fail_integrity(tmp_path):
    engine, Factory = _factory(tmp_path)
    result = append_evidence(_envelope(), session_factory=Factory)

    with engine.begin() as connection:
        row = connection.execute(
            AuditEvidenceRecord.__table__.select().where(
                AuditEvidenceRecord.id == result.record_id
            )
        ).mappings().one()
        payload = dict(row["envelope_json"])
        payload["capability_decision_reason"] = "tampered"
        connection.execute(
            update(AuditEvidenceRecord)
            .where(AuditEvidenceRecord.id == result.record_id)
            .values(envelope_json=payload)
        )

    with pytest.raises(AuditEvidenceRepositoryError) as raised:
        verify_persisted_evidence(
            tenant_id="tenant-a",
            record_id=result.record_id,
            session_factory=Factory,
        )
    assert raised.value.code == "AUDIT_EVIDENCE_PERSISTENCE_INTEGRITY_MISMATCH"


def test_orm_update_and_delete_are_rejected(tmp_path):
    _, Factory = _factory(tmp_path)
    result = append_evidence(_envelope(), session_factory=Factory)

    with Factory() as db:
        row = db.get(AuditEvidenceRecord, result.record_id)
        row.status = "failed"
        with pytest.raises(RuntimeError, match="AUDIT_EVIDENCE_IMMUTABLE"):
            db.commit()
        db.rollback()

    with Factory() as db:
        row = db.get(AuditEvidenceRecord, result.record_id)
        db.delete(row)
        with pytest.raises(RuntimeError, match="AUDIT_EVIDENCE_IMMUTABLE"):
            db.commit()
        db.rollback()


def test_concurrent_same_id_same_payload_yields_one_row_and_one_replay(tmp_path):
    _, Factory = _factory(tmp_path)
    envelope = _envelope(audit_execution_id="audit-race-same")
    barrier = threading.Barrier(2)

    def worker():
        barrier.wait(timeout=5)
        return append_evidence(envelope, session_factory=Factory)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result(timeout=20) for future in [pool.submit(worker), pool.submit(worker)]]

    assert len({item.record_id for item in results}) == 1
    assert sorted(item.idempotent_replay for item in results) == [False, True]
    with Factory() as db:
        assert db.query(AuditEvidenceRecord).count() == 1


def test_concurrent_same_id_different_payload_yields_one_row_and_conflict(tmp_path):
    _, Factory = _factory(tmp_path)
    first = _envelope(
        audit_execution_id="audit-race-conflict",
        data={"winner": "a"},
    )
    second = _envelope(
        audit_execution_id="audit-race-conflict",
        data={"winner": "b"},
    )
    barrier = threading.Barrier(2)

    def worker(envelope):
        barrier.wait(timeout=5)
        try:
            return ("ok", append_evidence(envelope, session_factory=Factory))
        except AuditEvidenceRepositoryError as exc:
            return ("error", exc.code)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            future.result(timeout=20)
            for future in [pool.submit(worker, first), pool.submit(worker, second)]
        ]

    assert sorted(item[0] for item in results) == ["error", "ok"]
    assert "AUDIT_EVIDENCE_IDEMPOTENCY_CONFLICT" in [item[1] for item in results if item[0] == "error"]
    with Factory() as db:
        assert db.query(AuditEvidenceRecord).count() == 1


def test_unrelated_integrity_error_is_terminal_even_if_compatible_winner_appears(monkeypatch):
    envelope = _envelope(audit_execution_id="audit-unrelated-integrity")
    payload = audit_evidence_repository._payload(envelope)
    digest = audit_evidence_repository.evidence_sha256(payload)

    winner = AuditEvidenceRecord(
        id="winner-record",
        schema_version=payload["schema_version"],
        audit_execution_id=payload["audit_execution_id"],
        tenant_id=payload["tenant_id"],
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
    )

    calls = iter([None, winner])

    def fake_existing(_session_factory, _audit_execution_id):
        return next(calls)

    monkeypatch.setattr(
        audit_evidence_repository,
        "_existing_by_execution_id",
        fake_existing,
    )

    class _Dialect:
        name = "sqlite"

    class _Bind:
        dialect = _Dialect()

    class _FailingSession:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get_bind(self):
            return _Bind()

        def add(self, _row):
            return None

        def commit(self):
            raise audit_evidence_repository.IntegrityError(
                "INSERT INTO audit_evidence_records ...",
                {},
                sqlite3.IntegrityError(
                    "NOT NULL constraint failed: audit_evidence_records.user_id"
                ),
            )

        def rollback(self):
            return None

    def failing_factory():
        return _FailingSession()

    with pytest.raises(AuditEvidenceRepositoryError) as raised:
        append_evidence(envelope, session_factory=failing_factory)

    assert raised.value.code == "AUDIT_EVIDENCE_PERSISTENCE_INTEGRITY_ERROR"


def test_integrity_error_discriminator_uses_exact_postgres_constraint_name():
    class _Diag:
        def __init__(self, constraint_name):
            self.constraint_name = constraint_name

    class _PgOrig(Exception):
        def __init__(self, constraint_name):
            super().__init__("duplicate key value violates unique constraint")
            self.diag = _Diag(constraint_name)

    expected = audit_evidence_repository.IntegrityError(
        "INSERT INTO audit_evidence_records ...",
        {},
        _PgOrig("uq_audit_evidence_audit_execution_id"),
    )
    unrelated = audit_evidence_repository.IntegrityError(
        "INSERT INTO audit_evidence_records ...",
        {},
        _PgOrig("uq_other_constraint"),
    )

    assert audit_evidence_repository._is_audit_execution_unique_violation(
        expected,
        dialect_name="postgresql",
    )
    assert not audit_evidence_repository._is_audit_execution_unique_violation(
        unrelated,
        dialect_name="postgresql",
    )
