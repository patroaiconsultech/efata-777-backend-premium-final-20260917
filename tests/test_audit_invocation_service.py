
from __future__ import annotations

from types import SimpleNamespace
import hashlib
import json
import time

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from orkio_v2.database import Base
from orkio_v2.models import Artifact, AuditEvidenceRecord
from orkio_v2.runtime.contracts import CanonicalTurnContext, RuntimeChannel, RuntimeRouteFamily
from orkio_v2.services.audit_invocation_rate_limit import AuditDirectiveAbuseLimiter
from orkio_v2.services.audit_path_policy import AuditPathPolicy
from orkio_v2.services import audit_archive_source_resolver as source_resolver_module
from orkio_v2.services.audit_invocation_service import (
    AuditInvocationError,
    GovernedAuditInvocationService,
)
from orkio_v2.services.capability_policy import CapabilityPolicy


def _factory():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _policy(*, master=True, user_limit=4, tenant_limit=20, timeout=1.0):
    return CapabilityPolicy(
        python_enabled=False,
        python_timeout_seconds=3.0,
        python_max_code_bytes=20_000,
        python_max_output_bytes=64_000,
        external_read_enabled=False,
        external_read_allowed_domains=(),
        external_read_timeout_seconds=5.0,
        external_read_max_bytes=500_000,
        external_read_max_urls_per_turn=2,
        audit_evidence_capabilities_enabled=True,
        audit_file_inspect_enabled=True,
        audit_archive_inspect_enabled=True,
        audit_runtime_inspect_enabled=True,
        audit_runtime_file_sha256_enabled=True,
        audit_runtime_search_marker_enabled=True,
        audit_allowed_agent_ids=("auditor",),
        audit_allowed_tenant_ids=("tenant-1",),
        audit_allowed_environments=("test",),
        audit_timeout_seconds=timeout,
        audit_max_output_bytes=128_000,
        audit_governed_invocation_enabled=master,
        audit_rate_limit_window_seconds=60,
        audit_user_rate_limit_per_window=user_limit,
        audit_tenant_rate_limit_per_window=tenant_limit,
        audit_directive_user_rate_limit=12,
    )


def _settings(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(exist_ok=True)
    return SimpleNamespace(
        environment="test",
        release_sha="candidate-033c",
        platform_release_sha=None,
        railway_deployment_id="local-test",
        artifact_storage_backend="local",
        artifact_storage_path=str(artifacts),
    )


def _turn(*, agent="auditor", requested="Natã", channel=RuntimeChannel.CHAT_JSON):
    return CanonicalTurnContext(
        execution_id="exec-1",
        request_id="req-1",
        thread_id="thread-1",
        tenant_id="tenant-1",
        user_id="user-1",
        requested_target=requested,
        resolved_agent_id=agent,
        turn_owner_agent_id=agent,
        display_agent_id=agent,
        display_agent_name="Natã — Independent Technical Auditor",
        technical_lead_agent_id=None,
        route_family=RuntimeRouteFamily.DIRECT_AGENT,
        channel=channel,
        ownership_locked=True,
        governance_mode="normal",
        internal_persistence_allowed=True,
        external_write_allowed=False,
        execution_allowed=True,
    )


def _service(tmp_path, *, policy=None, append_fn=None):
    factory = _factory()
    kwargs = dict(
        session_factory=factory,
        settings=_settings(tmp_path),
        project_root=tmp_path,
        policy=policy or _policy(),
        directive_abuse_limiter=AuditDirectiveAbuseLimiter(),
        runtime_module_allowlist={"routes": "module.py"},
    )
    if append_fn is not None:
        kwargs["append_fn"] = append_fn
    return GovernedAuditInvocationService(**kwargs), factory


def test_plain_language_has_zero_capability_and_zero_ledger(tmp_path):
    service, factory = _service(tmp_path)
    result = service.invoke_if_directive(
        message="Natã, faça uma auditoria.",
        turn=_turn(),
        principal_roles=("admin",),
    )
    assert result is None
    with factory() as db:
        assert db.scalar(select(AuditEvidenceRecord)) is None


def test_runtime_hash_is_persisted_and_verified_before_success(tmp_path):
    (tmp_path / "module.py").write_text("hello governed audit\n", encoding="utf-8")
    service, factory = _service(tmp_path)
    result = service.invoke_if_directive(
        message='/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
        turn=_turn(),
        principal_roles=("admin",),
    )
    assert result is not None
    assert result.status == "completed"
    assert len(result.evidence_sha256) == 64
    assert result.data["governance_mode"] == "audit_readonly"
    with factory() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row is not None
        assert row.resolved_agent_id == "auditor"
        assert row.status == "completed"
        assert row.envelope_json["write_executed"] is False


def test_alias_is_resolved_server_side_to_canonical_auditor(tmp_path):
    (tmp_path / "module.py").write_text("x", encoding="utf-8")
    service, factory = _service(tmp_path)
    result = service.invoke_if_directive(
        message='/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
        turn=_turn(requested="Nathan"),
        principal_roles=("orkio_admin",),
    )
    assert result is not None
    with factory() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row.envelope_json["requested_agent_id"] == "auditor"


def test_wrong_owner_is_denied_and_no_read_occurs(tmp_path):
    (tmp_path / "module.py").write_text("must not be read", encoding="utf-8")
    service, factory = _service(tmp_path)
    with pytest.raises(AuditInvocationError) as exc:
        service.invoke_if_directive(
            message='/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            turn=_turn(agent="orion", requested="Bezalel"),
            principal_roles=("admin",),
        )
    assert exc.value.code == "AUDIT_INVOCATION_AGENT_DENIED"
    with factory() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row.status == "denied"
        assert row.envelope_json["read_executed"] is False


def test_non_admin_is_denied_and_evidenced(tmp_path):
    (tmp_path / "module.py").write_text("must not be read", encoding="utf-8")
    service, factory = _service(tmp_path)
    with pytest.raises(AuditInvocationError) as exc:
        service.invoke_if_directive(
            message='/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            turn=_turn(),
            principal_roles=("member",),
        )
    assert exc.value.code == "AUDIT_CAPABILITY_USER_DENIED"
    with factory() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row.status == "denied"
        assert row.envelope_json["read_executed"] is False


def test_master_gate_default_off_denies_without_read(tmp_path):
    (tmp_path / "module.py").write_text("must not be read", encoding="utf-8")
    service, factory = _service(tmp_path, policy=_policy(master=False))
    with pytest.raises(AuditInvocationError) as exc:
        service.invoke_if_directive(
            message='/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            turn=_turn(),
            principal_roles=("admin",),
        )
    assert exc.value.code == "AUDIT_GOVERNED_INVOCATION_DISABLED"
    with factory() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row.status == "denied"


def test_ledger_failure_after_read_discards_result_and_never_reports_success(tmp_path):
    (tmp_path / "module.py").write_text("read happened", encoding="utf-8")
    called = {"append": 0}

    def fail_append(*args, **kwargs):
        called["append"] += 1
        raise RuntimeError("AUDIT_EVIDENCE_PERSISTENCE_FAILED")

    service, _ = _service(tmp_path, append_fn=fail_append)
    with pytest.raises(AuditInvocationError) as exc:
        service.invoke_if_directive(
            message='/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            turn=_turn(),
            principal_roles=("admin",),
        )
    assert exc.value.code == "AUDIT_EVIDENCE_PERSISTENCE_FAILED"
    assert called["append"] == 1


def test_ledger_rate_limit_denies_third_attempt_and_persists_denial(tmp_path):
    (tmp_path / "module.py").write_text("rate", encoding="utf-8")
    service, factory = _service(
        tmp_path,
        policy=_policy(user_limit=2, tenant_limit=20),
    )
    message = '/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}'
    assert service.invoke_if_directive(message=message, turn=_turn(), principal_roles=("admin",))
    assert service.invoke_if_directive(message=message, turn=_turn(), principal_roles=("admin",))
    with pytest.raises(AuditInvocationError) as exc:
        service.invoke_if_directive(message=message, turn=_turn(), principal_roles=("admin",))
    assert exc.value.code == "AUDIT_REQUEST_RATE_LIMITED"
    with factory() as db:
        rows = db.scalars(select(AuditEvidenceRecord).order_by(AuditEvidenceRecord.created_at)).all()
        assert [row.status for row in rows] == ["completed", "completed", "denied"]
        assert rows[-1].envelope_json["read_executed"] is False


def test_timeout_is_terminal_and_operation_is_not_retried(tmp_path, monkeypatch):
    (tmp_path / "module.py").write_text("slow", encoding="utf-8")
    service, factory = _service(tmp_path, policy=_policy(timeout=0.01))
    calls = {"count": 0}

    def slow_hash(self, module_id):
        calls["count"] += 1
        time.sleep(0.05)
        return {"module_id": module_id, "sha256": "a" * 64, "bytes_hashed": 4}

    monkeypatch.setattr(
        "orkio_v2.services.audit_invocation_service.AuditRuntimeAdapter.file_sha256",
        slow_hash,
    )
    with pytest.raises(AuditInvocationError) as exc:
        service.invoke_if_directive(
            message='/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            turn=_turn(),
            principal_roles=("admin",),
        )
    assert exc.value.code == "AUDIT_REQUEST_TIMEOUT"
    time.sleep(0.07)
    assert calls["count"] == 1
    with factory() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row.status == "failed"
        assert row.error_code == "AUDIT_REQUEST_TIMEOUT"


def test_artifact_id_is_tenant_bound_and_physical_sha_verified(tmp_path):
    service, factory = _service(tmp_path)
    artifact_root = tmp_path / "artifacts"
    data = b"verified tenant artifact\n"
    path = artifact_root / "tenant-1" / "thread-1" / "doc.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    with factory() as db:
        db.add(
            Artifact(
                id="artifact-1",
                tenant_id="tenant-1",
                thread_id="thread-1",
                created_by="user-1",
                filename="doc.txt",
                mime_type="text/plain",
                storage_key="tenant-1/thread-1/doc.txt",
                sha256=hashlib.sha256(data).hexdigest(),
            )
        )
        db.commit()

    result = service.invoke_if_directive(
        message='/audit {"version":"1","operation":"file.read_text","artifact_id":"artifact-1","max_bytes":64}',
        turn=_turn(),
        principal_roles=("admin",),
    )
    assert result.data["result"]["content"] == "verified tenant artifact\n"
    assert result.data["result"]["relative_path"] == "artifact-1"


def test_foreign_tenant_artifact_is_private_denial_with_truthful_internal_reason(
    tmp_path, monkeypatch
):
    service, factory = _service(tmp_path)
    artifact_root = tmp_path / "artifacts"
    data = b"foreign"
    path = artifact_root / "tenant-2" / "thread-x" / "foreign.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    with factory() as db:
        db.add(
            Artifact(
                id="artifact-foreign",
                tenant_id="tenant-2",
                thread_id="thread-x",
                created_by="user-x",
                filename="foreign.txt",
                mime_type="text/plain",
                storage_key="tenant-2/thread-x/foreign.txt",
                sha256=hashlib.sha256(data).hexdigest(),
            )
        )
        db.commit()

    open_calls = {"count": 0}
    original_open = AuditPathPolicy.open_verified_file

    def counted_open(self, *args, **kwargs):
        open_calls["count"] += 1
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(AuditPathPolicy, "open_verified_file", counted_open)

    with pytest.raises(AuditInvocationError) as exc:
        service.invoke_if_directive(
            message='/audit {"version":"1","operation":"file.metadata","artifact_id":"artifact-foreign"}',
            turn=_turn(),
            principal_roles=("admin",),
        )

    assert open_calls["count"] == 0
    assert exc.value.code == "AUDIT_ARCHIVE_NOT_FOUND"
    assert exc.value.http_status == 404
    assert "tenant-2" not in str(exc.value)
    assert "thread-x" not in str(exc.value)
    with factory() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row.status == "denied"
        assert row.error_code == "AUDIT_ARCHIVE_ARTIFACT_TENANT_MISMATCH"
        assert row.envelope_json["capability_decision"] == "DENY"
        assert (
            row.envelope_json["capability_decision_reason"]
            == "AUDIT_ARCHIVE_ARTIFACT_TENANT_MISMATCH"
        )
        assert row.envelope_json["read_executed"] is False
        assert row.envelope_json["data"]["operation"] == "file.metadata"


def test_missing_artifact_matches_foreign_publicly_but_keeps_not_found_internal_reason(
    tmp_path, monkeypatch
):
    service, factory = _service(tmp_path)
    open_calls = {"count": 0}
    original_open = AuditPathPolicy.open_verified_file

    def counted_open(self, *args, **kwargs):
        open_calls["count"] += 1
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(AuditPathPolicy, "open_verified_file", counted_open)

    with pytest.raises(AuditInvocationError) as exc:
        service.invoke_if_directive(
            message='/audit {"version":"1","operation":"file.metadata","artifact_id":"artifact-missing"}',
            turn=_turn(),
            principal_roles=("admin",),
        )

    assert open_calls["count"] == 0
    assert exc.value.code == "AUDIT_ARCHIVE_NOT_FOUND"
    assert exc.value.http_status == 404
    with factory() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row.status == "denied"
        assert row.error_code == "AUDIT_ARCHIVE_NOT_FOUND"
        assert row.envelope_json["capability_decision"] == "DENY"
        assert row.envelope_json["capability_decision_reason"] == "AUDIT_ARCHIVE_NOT_FOUND"
        assert row.envelope_json["read_executed"] is False


def test_integrity_mismatch_remains_post_read_failure(tmp_path, monkeypatch):
    service, factory = _service(tmp_path)
    artifact_root = tmp_path / "artifacts"
    data = b"physical bytes"
    path = artifact_root / "tenant-1" / "thread-1" / "tampered.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    with factory() as db:
        db.add(
            Artifact(
                id="artifact-integrity",
                tenant_id="tenant-1",
                thread_id="thread-1",
                created_by="user-1",
                filename="tampered.txt",
                mime_type="text/plain",
                storage_key="tenant-1/thread-1/tampered.txt",
                sha256="0" * 64,
            )
        )
        db.commit()

    sha_calls = {"count": 0}
    original_sha = source_resolver_module._sha256_verified_file

    def counted_sha(verified):
        sha_calls["count"] += 1
        return original_sha(verified)

    monkeypatch.setattr(source_resolver_module, "_sha256_verified_file", counted_sha)

    with pytest.raises(AuditInvocationError) as exc:
        service.invoke_if_directive(
            message='/audit {"version":"1","operation":"file.metadata","artifact_id":"artifact-integrity"}',
            turn=_turn(),
            principal_roles=("admin",),
        )

    assert sha_calls["count"] == 1
    assert exc.value.code == "AUDIT_ARCHIVE_SOURCE_ERROR"
    with factory() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row.status == "failed"
        assert row.error_code == "AUDIT_ARCHIVE_SOURCE_ERROR"
        assert row.envelope_json["capability_decision"] == "ALLOW"
        assert row.envelope_json["capability_decision_reason"] == "ALLOW"
        assert row.envelope_json["read_executed"] is True


def test_runtime_marker_has_durable_request_binding_without_persisting_plaintext_marker(tmp_path):
    marker = "needle-current-directive-777"
    (tmp_path / "module.py").write_text(
        f"alpha\n{marker}\nomega\n",
        encoding="utf-8",
    )
    service, factory = _service(tmp_path)
    result = service.invoke_if_directive(
        message=(
            '/audit {"version":"1","operation":"runtime.search_marker",'
            f'"module_id":"routes","marker":"{marker}"}}'
        ),
        turn=_turn(),
        principal_roles=("admin",),
    )

    assert result is not None
    binding = result.data["request_binding"]
    assert binding["contract"] == "ORKIO-AUDIT-REQUEST-BINDING-1"
    assert binding["operation"] == "runtime.search_marker"
    assert binding["arguments"]["module_id"] == {
        "binding": "literal",
        "value": "routes",
        "source": "current_parsed_directive",
    }
    assert binding["arguments"]["marker"]["binding"] == "sha256"
    assert binding["arguments"]["marker"]["source"] == "current_parsed_directive"
    assert binding["arguments"]["marker"]["sha256"] == hashlib.sha256(
        marker.encode("utf-8")
    ).hexdigest()
    assert (
        result.data["request_result_binding"]["marker_sha256_matches_request"]
        is True
    )
    assert (
        result.data["result"]["marker_sha256"]
        == binding["arguments"]["marker"]["sha256"]
    )

    system_message = result.system_message()["content"]
    assert "fresh evidence produced by the current parsed /audit directive" in system_message
    assert "do not describe it as merely historical" in system_message
    assert marker not in system_message

    with factory() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row is not None
        persisted = json.dumps(
            row.envelope_json,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        assert marker not in persisted
        assert binding["directive_sha256"] in persisted
        assert binding["arguments"]["marker"]["sha256"] in persisted


def test_runtime_marker_request_result_binding_mismatch_fails_closed(tmp_path, monkeypatch):
    marker = "needle-binding-mismatch"
    (tmp_path / "module.py").write_text(marker, encoding="utf-8")
    service, factory = _service(tmp_path)

    def wrong_marker_hash(self, module_id, *, marker, max_scan_bytes, max_matches):
        return {
            "module_id": module_id,
            "relative_path": "module.py",
            "marker_sha256": "0" * 64,
            "marker_found": True,
            "match_count": 1,
            "line_numbers": [1],
            "truncated_matches": False,
            "max_matches": max_matches,
            "bytes_scanned": len(marker.encode("utf-8")),
            "scan_truncated": False,
            "match_count_complete": True,
        }

    monkeypatch.setattr(
        "orkio_v2.services.audit_invocation_service.AuditRuntimeAdapter.search_marker",
        wrong_marker_hash,
    )

    with pytest.raises(AuditInvocationError) as exc:
        service.invoke_if_directive(
            message=(
                '/audit {"version":"1","operation":"runtime.search_marker",'
                f'"module_id":"routes","marker":"{marker}"}}'
            ),
            turn=_turn(),
            principal_roles=("admin",),
        )

    assert exc.value.code == "AUDIT_REQUEST_RESULT_BINDING_MISMATCH"
    assert exc.value.http_status == 500
    with factory() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row is not None
        assert row.status == "failed"
        assert row.error_code == "AUDIT_REQUEST_RESULT_BINDING_MISMATCH"
        persisted = json.dumps(row.envelope_json, ensure_ascii=False, sort_keys=True)
        assert marker not in persisted
        assert hashlib.sha256(marker.encode("utf-8")).hexdigest() in persisted


def test_runtime_file_sha256_binds_persisted_evidence_to_current_turn_and_result(tmp_path):
    (tmp_path / "module.py").write_text("current binding premium\n", encoding="utf-8")
    service, factory = _service(tmp_path)
    turn = _turn(channel=RuntimeChannel.CHAT_SSE)
    result = service.invoke_if_directive(
        message='/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
        turn=turn,
        principal_roles=("admin",),
    )

    assert result is not None
    assert result.status == "completed"
    binding = result.data["request_binding"]
    assert binding["contract"] == "ORKIO-AUDIT-REQUEST-BINDING-1"
    assert binding["source"] == "current_parsed_directive_and_canonical_turn"
    assert binding["turn"] == {
        "request_id": "req-1",
        "execution_id": "exec-1",
        "thread_id": "thread-1",
        "tenant_id": "tenant-1",
        "requested_agent": "Natã",
        "resolved_agent": "auditor",
        "turn_owner": "auditor",
        "route_family": "direct_agent",
        "channel": "chat_sse",
        "ownership_locked": True,
    }
    assert binding["arguments"]["module_id"] == {
        "binding": "literal",
        "value": "routes",
        "source": "current_parsed_directive",
    }
    assert result.data["request_result_binding"]["module_id_matches_request"] is True
    assert result.data["result"]["module_id"] == "routes"

    system_message = result.system_message()["content"]
    assert '"execution_id":"exec-1"' in system_message
    assert '"request_id":"req-1"' in system_message
    assert "bind this persisted evidence to the current request" in system_message
    assert "do not classify that evidence as historical" in system_message

    with factory() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row is not None
        persisted_binding = row.envelope_json["data"]["request_binding"]
        assert persisted_binding["turn"]["execution_id"] == "exec-1"
        assert persisted_binding["turn"]["request_id"] == "req-1"
        assert row.envelope_json["execution_id"] == "exec-1"
        assert row.envelope_json["request_id"] == "req-1"


def test_runtime_file_sha256_module_binding_mismatch_fails_closed(tmp_path, monkeypatch):
    (tmp_path / "module.py").write_text("binding mismatch\n", encoding="utf-8")
    service, factory = _service(tmp_path)

    def wrong_module(self, module_id):
        return {
            "module_id": "not-the-requested-module",
            "relative_path": "module.py",
            "sha256": "0" * 64,
            "bytes_hashed": 1,
        }

    monkeypatch.setattr(
        "orkio_v2.services.audit_invocation_service.AuditRuntimeAdapter.file_sha256",
        wrong_module,
    )

    with pytest.raises(AuditInvocationError) as exc:
        service.invoke_if_directive(
            message='/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            turn=_turn(),
            principal_roles=("admin",),
        )

    assert exc.value.code == "AUDIT_REQUEST_RESULT_BINDING_MISMATCH"
    assert exc.value.http_status == 500
    with factory() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row is not None
        assert row.status == "failed"
        assert row.error_code == "AUDIT_REQUEST_RESULT_BINDING_MISMATCH"
        assert row.envelope_json["data"]["request_binding"]["turn"]["execution_id"] == "exec-1"
