from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time
import uuid

import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as SASession

from conftest import Testing, headers
from orkio_v2.config import get_settings
from orkio_v2.models import Artifact, AuditEvidenceRecord
from orkio_v2.runtime.contracts import CanonicalTurnContext, RuntimeChannel, RuntimeRouteFamily
from orkio_v2.services import llm
from orkio_v2.services import audit_evidence_repository as evidence_repo
from orkio_v2.services.audit_evidence_repository import AuditEvidenceRepositoryError
from orkio_v2.services.audit_invocation_service import (
    AuditInvocationError,
    GovernedAuditInvocationService,
)
from orkio_v2.services.audit_runtime_adapter import AuditRuntimeAdapter
from orkio_v2.services.audit_path_policy import AuditPathPolicy
from orkio_v2.services import audit_archive_source_resolver as source_resolver_module
from orkio_v2.services.capability_policy import CapabilityPolicy
import orkio_v2.routes as routes


def _enable_audit(monkeypatch) -> None:
    for name, value in {
        "PLATFORM_AUDIT_GOVERNED_INVOCATION_ENABLED": "true",
        "PLATFORM_AUDIT_EVIDENCE_CAPABILITIES_ENABLED": "true",
        "PLATFORM_AUDIT_RUNTIME_INSPECT_ENABLED": "true",
        "PLATFORM_AUDIT_RUNTIME_FILE_SHA256_ENABLED": "true",
        "PLATFORM_AUDIT_RUNTIME_SEARCH_MARKER_ENABLED": "true",
        "PLATFORM_AUDIT_FILE_INSPECT_ENABLED": "true",
        "PLATFORM_AUDIT_ARCHIVE_INSPECT_ENABLED": "true",
        "PLATFORM_AUDIT_ALLOWED_AGENT_IDS": "auditor",
        "PLATFORM_AUDIT_ALLOWED_TENANT_IDS": "tenant-1",
        "PLATFORM_AUDIT_ALLOWED_ENVIRONMENTS": "test",
        "PLATFORM_AUDIT_RATE_LIMIT_WINDOW_SECONDS": "60",
        "PLATFORM_AUDIT_USER_RATE_LIMIT_PER_WINDOW": "4",
        "PLATFORM_AUDIT_TENANT_RATE_LIMIT_PER_WINDOW": "20",
        "PLATFORM_AUDIT_DIRECTIVE_USER_RATE_LIMIT": "12",
        "PLATFORM_AUDIT_TIMEOUT_SECONDS": "3.0",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(get_settings(), "openai_api_key", "test-key-not-real", raising=False)
    for limiter in routes._audit_directive_abuse_limiters.values():
        limiter.reset()
    routes._audit_directive_abuse_limiters.clear()
    with Testing() as db:
        db.execute(delete(AuditEvidenceRecord))
        db.commit()


def _thread(client) -> str:
    response = client.post("/api/v2/threads", json={}, headers=headers())
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _sse_event_names(text: str) -> list[str]:
    return [
        line.removeprefix("event: ").strip()
        for line in text.splitlines()
        if line.startswith("event: ")
    ]


def _direct_turn(*, execution_id: str, user_id: str = "user-1", ownership_locked: bool = True):
    return CanonicalTurnContext(
        execution_id=execution_id,
        request_id=f"req-{execution_id}",
        thread_id="thread-033d-negative",
        tenant_id="tenant-1",
        user_id=user_id,
        requested_target="Natã",
        resolved_agent_id="auditor",
        turn_owner_agent_id="auditor",
        display_agent_id="auditor",
        display_agent_name="Natã — Independent Technical Auditor",
        technical_lead_agent_id=None,
        route_family=RuntimeRouteFamily.DIRECT_AGENT,
        channel=RuntimeChannel.CHAT_JSON,
        ownership_locked=ownership_locked,
        governance_mode="normal",
        internal_persistence_allowed=True,
        external_write_allowed=False,
        execution_allowed=True,
    )


def _direct_service() -> GovernedAuditInvocationService:
    return GovernedAuditInvocationService(
        session_factory=Testing,
        settings=get_settings(),
        project_root=Path(routes.__file__).resolve().parents[2],
        policy=CapabilityPolicy.from_env(),
        directive_abuse_limiter=routes._audit_directive_abuse_limiter(CapabilityPolicy.from_env()),
    )


def test_033d_n01_plain_language_does_not_execute_capability(client, monkeypatch):
    _enable_audit(monkeypatch)
    calls = {"llm": 0}

    async def fake_generate(settings, agent, history):
        calls["llm"] += 1
        return "Conversa normal."

    monkeypatch.setattr(llm, "generate", fake_generate)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={"content": "Natã, explique o status da auditoria.", "agent": "Natã"},
        headers=headers(),
    )
    assert response.status_code == 200
    assert calls["llm"] == 1
    assert "audit" not in response.json()
    with Testing() as db:
        assert db.scalar(select(AuditEvidenceRecord)) is None


def test_033d_n02_wrong_selected_agent_is_denied_before_read(client, monkeypatch):
    _enable_audit(monkeypatch)

    async def must_not_generate(*args, **kwargs):
        raise AssertionError("LLM must not run after governed denial")

    monkeypatch.setattr(llm, "generate", must_not_generate)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={
            "content": '/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            "agent": "Bezalel",
        },
        headers=headers(),
    )
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["code"] == "AUDIT_INVOCATION_AGENT_DENIED"
    with Testing() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row is not None
        assert row.status == "denied"
        assert row.envelope_json["read_executed"] is False


def test_033d_n03_foreign_tenant_artifact_denied_without_read_or_disclosure(
    client, monkeypatch, tmp_path
):
    _enable_audit(monkeypatch)
    settings = get_settings()
    storage_root = tmp_path / "artifacts"
    monkeypatch.setattr(settings, "artifact_storage_backend", "local", raising=False)
    monkeypatch.setattr(settings, "artifact_storage_path", str(storage_root), raising=False)

    thread_id = _thread(client)
    artifact_id = f"foreign-{uuid.uuid4()}"
    content = b"foreign tenant secret marker"
    storage_key = f"tenant-2/foreign-thread/foreign.txt"
    physical = storage_root / storage_key
    physical.parent.mkdir(parents=True, exist_ok=True)
    physical.write_bytes(content)

    with Testing() as db:
        db.add(
            Artifact(
                id=artifact_id,
                tenant_id="tenant-2",
                thread_id="foreign-thread",
                created_by="foreign-user",
                filename="foreign.txt",
                mime_type="text/plain",
                storage_key=storage_key,
                sha256=hashlib.sha256(content).hexdigest(),
            )
        )
        db.commit()

    open_calls = {"count": 0}
    original_open = AuditPathPolicy.open_verified_file

    def counted_open(self, *args, **kwargs):
        open_calls["count"] += 1
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(AuditPathPolicy, "open_verified_file", counted_open)

    async def must_not_generate(*args, **kwargs):
        raise AssertionError("LLM must not run for foreign tenant artifact")

    monkeypatch.setattr(llm, "generate", must_not_generate)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={
            "content": f'/audit {{"version":"1","operation":"file.metadata","artifact_id":"{artifact_id}"}}',
            "agent": "Natã",
        },
        headers=headers(),
    )
    assert open_calls["count"] == 0
    assert response.status_code == 404, response.text
    assert response.json()["detail"]["code"] == "AUDIT_ARCHIVE_NOT_FOUND"
    assert "tenant-2" not in response.text
    assert "foreign-thread" not in response.text
    assert storage_key not in response.text
    with Testing() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row is not None
        assert row.envelope_json["capability_decision"] == "DENY"
        assert (
            row.envelope_json["capability_decision_reason"]
            == "AUDIT_ARCHIVE_ARTIFACT_TENANT_MISMATCH"
        )
        assert row.error_code == "AUDIT_ARCHIVE_ARTIFACT_TENANT_MISMATCH"
        assert row.envelope_json["read_executed"] is False
        assert row.status == "denied"


def test_033d_t02_missing_artifact_is_publicly_indistinguishable_pre_read_denial(
    client, monkeypatch, tmp_path
):
    _enable_audit(monkeypatch)
    settings = get_settings()
    storage_root = tmp_path / "artifacts"
    storage_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "artifact_storage_backend", "local", raising=False)
    monkeypatch.setattr(settings, "artifact_storage_path", str(storage_root), raising=False)

    thread_id = _thread(client)
    open_calls = {"count": 0}
    original_open = AuditPathPolicy.open_verified_file

    def counted_open(self, *args, **kwargs):
        open_calls["count"] += 1
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(AuditPathPolicy, "open_verified_file", counted_open)

    async def must_not_generate(*args, **kwargs):
        raise AssertionError("LLM must not run for missing artifact")

    monkeypatch.setattr(llm, "generate", must_not_generate)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={
            "content": '/audit {"version":"1","operation":"file.metadata","artifact_id":"missing-033d"}',
            "agent": "Natã",
        },
        headers=headers(),
    )
    assert open_calls["count"] == 0
    assert response.status_code == 404, response.text
    assert response.json()["detail"]["code"] == "AUDIT_ARCHIVE_NOT_FOUND"
    with Testing() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row is not None
        assert row.envelope_json["capability_decision"] == "DENY"
        assert row.envelope_json["capability_decision_reason"] == "AUDIT_ARCHIVE_NOT_FOUND"
        assert row.error_code == "AUDIT_ARCHIVE_NOT_FOUND"
        assert row.status == "denied"
        assert row.envelope_json["read_executed"] is False


def test_033d_t03_integrity_mismatch_remains_post_read_failure(
    client, monkeypatch, tmp_path
):
    _enable_audit(monkeypatch)
    settings = get_settings()
    storage_root = tmp_path / "artifacts"
    monkeypatch.setattr(settings, "artifact_storage_backend", "local", raising=False)
    monkeypatch.setattr(settings, "artifact_storage_path", str(storage_root), raising=False)

    thread_id = _thread(client)
    artifact_id = f"integrity-{uuid.uuid4()}"
    content = b"physical bytes that do not match stored sha"
    storage_key = f"tenant-1/{thread_id}/integrity.txt"
    physical = storage_root / storage_key
    physical.parent.mkdir(parents=True, exist_ok=True)
    physical.write_bytes(content)
    with Testing() as db:
        db.add(
            Artifact(
                id=artifact_id,
                tenant_id="tenant-1",
                thread_id=thread_id,
                created_by="user-1",
                filename="integrity.txt",
                mime_type="text/plain",
                storage_key=storage_key,
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

    async def must_not_generate(*args, **kwargs):
        raise AssertionError("LLM must not run after integrity mismatch")

    monkeypatch.setattr(llm, "generate", must_not_generate)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={
            "content": f'/audit {{"version":"1","operation":"file.metadata","artifact_id":"{artifact_id}"}}',
            "agent": "Natã",
        },
        headers=headers(),
    )
    assert sha_calls["count"] == 1
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "AUDIT_ARCHIVE_SOURCE_ERROR"
    with Testing() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row is not None
        assert row.envelope_json["capability_decision"] == "ALLOW"
        assert row.envelope_json["capability_decision_reason"] == "ALLOW"
        assert row.status == "failed"
        assert row.envelope_json["read_executed"] is True

def test_033d_n04_disabled_capability_is_denied_without_execution(client, monkeypatch):
    _enable_audit(monkeypatch)
    monkeypatch.setenv("PLATFORM_AUDIT_RUNTIME_FILE_SHA256_ENABLED", "false")

    async def must_not_generate(*args, **kwargs):
        raise AssertionError("LLM must not run after capability denial")

    monkeypatch.setattr(llm, "generate", must_not_generate)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={
            "content": '/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            "agent": "Natã",
        },
        headers=headers(),
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "AUDIT_CAPABILITY_DISABLED"
    with Testing() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row.status == "denied"
        assert row.envelope_json["read_executed"] is False


def test_033d_n05_canonical_user_and_tenant_rate_limits_are_exact(monkeypatch):
    _enable_audit(monkeypatch)
    message = '/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}'
    service = _direct_service()

    # Exact user boundary: 4 durable attempts allowed, fifth denied.
    for index in range(4):
        outcome = service.invoke_if_directive(
            message=message,
            turn=_direct_turn(execution_id=f"user-boundary-{index}", user_id="user-rate"),
            principal_roles=("admin",),
        )
        assert outcome is not None
    with pytest.raises(AuditInvocationError) as exc:
        service.invoke_if_directive(
            message=message,
            turn=_direct_turn(execution_id="user-boundary-5", user_id="user-rate"),
            principal_roles=("admin",),
        )
    assert exc.value.code == "AUDIT_REQUEST_RATE_LIMITED"

    with Testing() as db:
        db.execute(delete(AuditEvidenceRecord))
        db.commit()

    # Exact tenant boundary: 5 distinct users x 4 attempts = 20; 21st denied.
    service = _direct_service()
    count = 0
    for user_number in range(5):
        for attempt in range(4):
            count += 1
            outcome = service.invoke_if_directive(
                message=message,
                turn=_direct_turn(
                    execution_id=f"tenant-{user_number}-{attempt}",
                    user_id=f"tenant-user-{user_number}",
                ),
                principal_roles=("admin",),
            )
            assert outcome is not None
    assert count == 20
    with pytest.raises(AuditInvocationError) as exc:
        service.invoke_if_directive(
            message=message,
            turn=_direct_turn(execution_id="tenant-21", user_id="tenant-user-6"),
            principal_roles=("admin",),
        )
    assert exc.value.code == "AUDIT_REQUEST_RATE_LIMITED"


def test_033d_n06_malformed_directive_has_no_fake_ledger_and_hits_parser_abuse_limit(
    client, monkeypatch
):
    _enable_audit(monkeypatch)

    async def must_not_generate(*args, **kwargs):
        raise AssertionError("LLM must not run for malformed directive")

    monkeypatch.setattr(llm, "generate", must_not_generate)
    thread_id = _thread(client)
    for _ in range(12):
        response = client.post(
            f"/api/v2/threads/{thread_id}/messages",
            json={"content": "/audit not-json", "agent": "Natã"},
            headers=headers(),
        )
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "AUDIT_DIRECTIVE_JSON_INVALID"
    limited = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={"content": "/audit still-not-json", "agent": "Natã"},
        headers=headers(),
    )
    assert limited.status_code == 429
    assert limited.json()["detail"]["code"] == "AUDIT_DIRECTIVE_RATE_LIMITED"
    with Testing() as db:
        assert db.scalar(select(AuditEvidenceRecord)) is None


def test_033d_n07_ledger_commit_failure_discards_capability_result(client, monkeypatch):
    _enable_audit(monkeypatch)
    calls = {"llm": 0}
    original_commit = SASession.commit

    def fail_audit_commit(self, *args, **kwargs):
        if any(isinstance(obj, AuditEvidenceRecord) for obj in self.new):
            raise RuntimeError("synthetic ledger commit failure")
        return original_commit(self, *args, **kwargs)

    async def must_not_generate(*args, **kwargs):
        calls["llm"] += 1
        raise AssertionError("LLM must not run when ledger commit fails")

    monkeypatch.setattr(SASession, "commit", fail_audit_commit)
    monkeypatch.setattr(llm, "generate", must_not_generate)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={
            "content": '/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            "agent": "Natã",
        },
        headers=headers(),
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "AUDIT_EVIDENCE_PERSISTENCE_FAILED"
    assert calls["llm"] == 0
    with Testing() as db:
        assert db.scalar(select(AuditEvidenceRecord)) is None


def test_033d_n08_reopen_rehash_failure_forbids_success(client, monkeypatch):
    _enable_audit(monkeypatch)
    calls = {"llm": 0}

    def fail_verify(*args, **kwargs):
        raise AuditEvidenceRepositoryError("AUDIT_EVIDENCE_PERSISTENCE_INTEGRITY_MISMATCH")

    async def must_not_generate(*args, **kwargs):
        calls["llm"] += 1
        raise AssertionError("LLM must not run when evidence rehash fails")

    monkeypatch.setattr(evidence_repo, "verify_persisted_evidence", fail_verify)
    monkeypatch.setattr(llm, "generate", must_not_generate)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={
            "content": '/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            "agent": "Natã",
        },
        headers=headers(),
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "AUDIT_EVIDENCE_PERSISTENCE_INTEGRITY_MISMATCH"
    assert calls["llm"] == 0


def test_033d_n09_timeout_is_terminal_and_never_retries(client, monkeypatch):
    _enable_audit(monkeypatch)
    monkeypatch.setenv("PLATFORM_AUDIT_TIMEOUT_SECONDS", "0.25")
    calls = {"capability": 0, "llm": 0}

    def slow_hash(self, module_id):
        calls["capability"] += 1
        time.sleep(0.40)
        return {"module_id": module_id, "sha256": "a" * 64, "bytes_hashed": 1}

    async def must_not_generate(*args, **kwargs):
        calls["llm"] += 1
        raise AssertionError("LLM must not run after timeout")

    monkeypatch.setattr(AuditRuntimeAdapter, "file_sha256", slow_hash)
    monkeypatch.setattr(llm, "generate", must_not_generate)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={
            "content": '/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            "agent": "Natã",
        },
        headers=headers(),
    )
    assert response.status_code == 504
    assert response.json()["detail"]["code"] == "AUDIT_REQUEST_TIMEOUT"
    time.sleep(0.25)
    assert calls == {"capability": 1, "llm": 0}
    with Testing() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row is not None
        assert row.status == "failed"
        assert row.error_code == "AUDIT_REQUEST_TIMEOUT"


def test_033d_n10_sse_failure_is_error_then_exactly_one_done(client, monkeypatch):
    _enable_audit(monkeypatch)
    monkeypatch.setenv("PLATFORM_AUDIT_RUNTIME_FILE_SHA256_ENABLED", "false")
    calls = {"stream": 0}

    async def must_not_stream(*args, **kwargs):
        calls["stream"] += 1
        yield "forbidden"

    monkeypatch.setattr(llm, "stream", must_not_stream)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/stream",
        json={
            "content": '/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            "agent": "Natã",
        },
        headers=headers(),
    )
    assert response.status_code == 200
    events = _sse_event_names(response.text)
    assert events == ["error", "done"]
    assert events.count("done") == 1
    assert "AUDIT_CAPABILITY_DISABLED" in response.text
    assert calls["stream"] == 0


def test_033d_n11_unlocked_ownership_is_denied_before_capability(monkeypatch):
    _enable_audit(monkeypatch)
    service = _direct_service()
    with pytest.raises(AuditInvocationError) as exc:
        service.invoke_if_directive(
            message='/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            turn=_direct_turn(execution_id="unlocked", ownership_locked=False),
            principal_roles=("admin",),
        )
    assert exc.value.code == "AUDIT_INVOCATION_OWNERSHIP_REQUIRED"
    with Testing() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row is not None
        assert row.status == "denied"
        assert row.envelope_json["read_executed"] is False


def test_033d_n12_client_identity_and_path_injection_are_rejected(client, monkeypatch):
    _enable_audit(monkeypatch)

    async def must_not_generate(*args, **kwargs):
        raise AssertionError("LLM must not run for forbidden client identity/path fields")

    monkeypatch.setattr(llm, "generate", must_not_generate)
    thread_id = _thread(client)
    payloads = [
        '/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes","tenant_id":"tenant-2"}',
        '/audit {"version":"1","operation":"file.metadata","artifact_id":"x","root_id":"runtime"}',
        '/audit {"version":"1","operation":"file.metadata","artifact_id":"x","relative_path":"../../etc/passwd"}',
    ]
    for directive in payloads:
        response = client.post(
            f"/api/v2/threads/{thread_id}/messages",
            json={"content": directive, "agent": "Natã"},
            headers=headers(),
        )
        assert response.status_code == 400
        assert response.json()["detail"]["code"] in {
            "AUDIT_DIRECTIVE_FORBIDDEN_FIELD",
            "AUDIT_DIRECTIVE_UNKNOWN_FIELD",
        }
    with Testing() as db:
        assert db.scalar(select(AuditEvidenceRecord)) is None
