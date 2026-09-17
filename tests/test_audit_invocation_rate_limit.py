
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from orkio_v2.database import Base
from orkio_v2.models import AuditEvidenceRecord
from orkio_v2.services.audit_invocation_rate_limit import (
    AuditDirectiveAbuseLimiter,
    LedgerAuditRateLimitCheck,
)


def _factory():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _row(*, idx: int, now: datetime, tenant="tenant-1", user="user-1", capability="audit.runtime.file_sha256@1.0.0"):
    return AuditEvidenceRecord(
        id=f"row-{idx}",
        schema_version="1.0",
        audit_execution_id=f"audit-{idx}",
        tenant_id=tenant,
        user_id=user,
        request_id=f"request-{idx}",
        execution_id=f"execution-{idx}",
        capability_id=capability,
        capability_version="1.0.0",
        environment="test",
        deployment_id="test",
        resolved_agent_id="auditor",
        capability_decision="ALLOW",
        status="completed",
        envelope_json={"idx": idx},
        evidence_sha256="a" * 64,
        created_at=now,
    )


def test_ledger_rate_limit_uses_deterministic_60_second_server_window():
    factory = _factory()
    now = datetime(2026, 9, 4, 16, 0, 0, tzinfo=timezone.utc)
    with factory() as db:
        for idx in range(4):
            db.add(_row(idx=idx, now=now - timedelta(seconds=10)))
        db.commit()

    check = LedgerAuditRateLimitCheck(
        session_factory=factory,
        window_seconds=60,
        user_limit=4,
        tenant_limit=20,
        now_fn=lambda: now,
    )
    assert check(
        capability_id="audit.runtime.file_sha256@1.0.0",
        user_id="user-1",
        tenant_id="tenant-1",
        resolved_agent_id="auditor",
    ) is False


def test_ledger_rate_limit_counts_only_exact_capability_and_window():
    factory = _factory()
    now = datetime(2026, 9, 4, 16, 0, 0, tzinfo=timezone.utc)
    with factory() as db:
        db.add(_row(idx=1, now=now - timedelta(seconds=61)))
        db.add(_row(idx=2, now=now - timedelta(seconds=10), capability="audit.runtime.search_marker@1.0.0"))
        db.commit()

    check = LedgerAuditRateLimitCheck(
        session_factory=factory,
        now_fn=lambda: now,
    )
    assert check(
        capability_id="audit.runtime.file_sha256@1.0.0",
        user_id="user-1",
        tenant_id="tenant-1",
        resolved_agent_id="auditor",
    ) is True


def test_malformed_directive_abuse_boundary_is_independent_from_ledger():
    now = [100.0]
    limiter = AuditDirectiveAbuseLimiter(
        window_seconds=60,
        per_user_limit=2,
        time_fn=lambda: now[0],
    )
    assert limiter.consume(tenant_id="tenant-1", user_id="user-1") is True
    assert limiter.consume(tenant_id="tenant-1", user_id="user-1") is True
    assert limiter.consume(tenant_id="tenant-1", user_id="user-1") is False
    now[0] = 161.0
    assert limiter.consume(tenant_id="tenant-1", user_id="user-1") is True
