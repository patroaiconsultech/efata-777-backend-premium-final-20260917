from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import time
import uuid

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as SASession

from conftest import Testing, headers
from orkio_v2.config import get_settings
from orkio_v2.models import Artifact, AuditEvidenceRecord
from orkio_v2.services import llm
from orkio_v2.services import audit_evidence_repository as evidence_repo
from orkio_v2.services.audit_evidence_repository import verify_persisted_evidence
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


def _audit_system_payload(history) -> dict:
    messages = [
        item["content"]
        for item in history
        if item["role"] == "system" and "TRUSTED GOVERNED AUDIT EVIDENCE" in item["content"]
    ]
    assert len(messages) == 1
    return json.loads(messages[0].split("\n", 1)[1])


def _sse_events(text: str) -> list[tuple[str, dict]]:
    lines = text.splitlines()
    events: list[tuple[str, dict]] = []
    current: str | None = None
    for line in lines:
        if line.startswith("event: "):
            current = line.removeprefix("event: ").strip()
        elif line.startswith("data: ") and current is not None:
            events.append((current, json.loads(line.removeprefix("data: "))))
            current = None
    return events


def _emit(name: str, payload: dict) -> None:
    target = os.environ.get("ORKIO_033D_EVIDENCE_DIR", "").strip()
    if not target:
        return
    path = Path(target)
    path.mkdir(parents=True, exist_ok=True)
    (path / f"{name}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_033d_p01_json_runtime_hash_end_to_end(client, monkeypatch):
    _enable_audit(monkeypatch)
    observed: dict[str, object] = {"llm_calls": 0}

    async def fake_generate(settings, agent, history):
        observed["llm_calls"] = int(observed["llm_calls"]) + 1
        observed["model_invoked_monotonic_ns"] = time.monotonic_ns()
        assert agent == "auditor"
        payload = _audit_system_payload(history)
        audit = payload["audit"]
        with Testing() as db:
            row = db.scalar(
                select(AuditEvidenceRecord).where(
                    AuditEvidenceRecord.audit_execution_id == audit["audit_execution_id"]
                )
            )
            assert row is not None
            assert row.status == "completed"
            assert row.resolved_agent_id == "auditor"
            assert row.evidence_sha256 == audit["evidence_sha256"]
        verified = verify_persisted_evidence(
            tenant_id="tenant-1",
            record_id=row.id,
            session_factory=Testing,
        )
        assert verified.evidence_sha256 == audit["evidence_sha256"]
        observed["verified_before_model"] = True
        return "Natã concluiu a auditoria governada."

    async def forbidden_github(*args, **kwargs):
        raise AssertionError("GitHub side path must not run for /audit")

    async def forbidden_runtime(*args, **kwargs):
        raise AssertionError("Python/external-read side path must not run for /audit")

    monkeypatch.setattr(llm, "generate", fake_generate)
    monkeypatch.setattr(routes, "github_context_messages", forbidden_github)
    monkeypatch.setattr(routes, "runtime_capability_messages", forbidden_runtime)

    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={
            "content": '/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            "agent": "Natã",
        },
        headers=headers(),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert observed == {
        "llm_calls": 1,
        "model_invoked_monotonic_ns": observed["model_invoked_monotonic_ns"],
        "verified_before_model": True,
    }
    assert body["agent_id"] == "auditor"
    assert body["execution"]["resolved_target"] == "auditor"
    assert body["execution"]["turn_owner"] == "auditor"
    assert body["execution"]["ownership_locked"] is True
    assert body["audit"]["capability_id"] == "audit.runtime.file_sha256@1.0.0"
    assert body["audit"]["status"] == "completed"
    assert len(body["audit"]["evidence_sha256"]) == 64

    with Testing() as db:
        rows = db.scalars(select(AuditEvidenceRecord)).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.tenant_id == "tenant-1"
        assert row.resolved_agent_id == "auditor"
        assert row.envelope_json["turn_owner_agent_id"] == "auditor"
        assert row.envelope_json["read_executed"] is True
        assert row.envelope_json["write_executed"] is False
        assert row.evidence_sha256 == body["audit"]["evidence_sha256"]

    _emit("P01_JSON_RUNTIME_HASH", {
        "scenario": "033D-E2E-P01",
        "request_id": body["execution"]["request_id"],
        "execution_id": body["execution_id"],
        "thread_id": thread_id,
        "tenant_id": "tenant-1",
        "requested_agent": "Natã",
        "resolved_agent_id": body["agent_id"],
        "turn_owner_agent_id": body["execution"]["turn_owner"],
        "ownership_locked": body["execution"]["ownership_locked"],
        "audit": body["audit"],
        "ledger_status": row.status,
        "ledger_read_executed": row.envelope_json["read_executed"],
        "ledger_write_executed": row.envelope_json["write_executed"],
        "verified_before_model": observed["verified_before_model"],
        "result": "PASS",
    })


def test_033d_p02_sse_runtime_marker_proves_ledger_rehash_before_first_chunk(
    client, monkeypatch
):
    _enable_audit(monkeypatch)
    trace: list[dict[str, object]] = []

    def mark(name: str) -> None:
        trace.append({"name": name, "monotonic_ns": time.monotonic_ns()})

    original_commit = SASession.commit

    def traced_commit(self, *args, **kwargs):
        ledger_pending = any(isinstance(obj, AuditEvidenceRecord) for obj in self.new)
        result = original_commit(self, *args, **kwargs)
        if ledger_pending:
            mark("ledger_committed")
        return result

    original_verify = evidence_repo.verify_persisted_evidence

    def traced_verify(*, tenant_id, record_id, session_factory):
        mark("ledger_reopen_started")
        snapshot = original_verify(
            tenant_id=tenant_id,
            record_id=record_id,
            session_factory=session_factory,
        )
        mark("evidence_verified")
        return snapshot

    async def fake_stream(settings, agent, history):
        mark("model_invoked")
        assert agent == "auditor"
        payload = _audit_system_payload(history)
        assert payload["verified"] is True
        names = [item["name"] for item in trace]
        assert "ledger_committed" in names
        assert "ledger_reopen_started" in names
        assert "evidence_verified" in names
        mark("first_model_chunk")
        yield "Auditoria "
        yield "concluída."

    async def forbidden_github(*args, **kwargs):
        raise AssertionError("GitHub side path must not run for /audit")

    async def forbidden_runtime(*args, **kwargs):
        raise AssertionError("Python/external-read side path must not run for /audit")

    monkeypatch.setattr(SASession, "commit", traced_commit)
    monkeypatch.setattr(evidence_repo, "verify_persisted_evidence", traced_verify)
    monkeypatch.setattr(llm, "stream", fake_stream)
    monkeypatch.setattr(routes, "github_context_messages", forbidden_github)
    monkeypatch.setattr(routes, "runtime_capability_messages", forbidden_runtime)

    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/stream",
        json={
            "content": '/audit {"version":"1","operation":"runtime.search_marker","module_id":"routes","marker":"send_message"}',
            "agent": "Nathan",
        },
        headers=headers(),
    )
    assert response.status_code == 200
    events = _sse_events(response.text)
    event_names = [name for name, _ in events]
    assert event_names[0] == "status"
    assert "chunk" in event_names
    assert "error" not in event_names
    assert event_names[-1] == "done"
    assert event_names.count("done") == 1
    mark("terminal_done_observed")

    names = [item["name"] for item in trace]
    required = [
        "ledger_committed",
        "ledger_reopen_started",
        "evidence_verified",
        "model_invoked",
        "first_model_chunk",
        "terminal_done_observed",
    ]
    assert all(name in names for name in required)
    positions = [names.index(name) for name in required]
    assert positions == sorted(positions), trace

    times = {
        item["name"]: int(item["monotonic_ns"])
        for item in trace
        if item["name"] in required
    }
    assert (
        times["ledger_committed"]
        <= times["ledger_reopen_started"]
        <= times["evidence_verified"]
        <= times["model_invoked"]
        <= times["first_model_chunk"]
        <= times["terminal_done_observed"]
    )

    status_payload = next(data for name, data in events if name == "status")
    done_payload = events[-1][1]
    assert status_payload["agent_id"] == "auditor"
    assert status_payload["ownership_locked"] is True
    assert status_payload["audit"]["capability_id"] == "audit.runtime.search_marker@1.0.0"
    assert done_payload["agent_id"] == "auditor"
    assert done_payload["turn_owner"] == "auditor"
    assert done_payload["ownership_locked"] is True
    assert done_payload["audit"]["evidence_sha256"] == status_payload["audit"]["evidence_sha256"]

    with Testing() as db:
        rows = db.scalars(select(AuditEvidenceRecord)).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.status == "completed"
        assert row.evidence_sha256 == done_payload["audit"]["evidence_sha256"]

    _emit("P02_SSE_RUNTIME_MARKER", {
        "scenario": "033D-E2E-P02",
        "thread_id": thread_id,
        "execution_id": done_payload["execution_id"],
        "tenant_id": "tenant-1",
        "resolved_agent_id": done_payload["agent_id"],
        "turn_owner_agent_id": done_payload["turn_owner"],
        "ownership_locked": done_payload["ownership_locked"],
        "audit": done_payload["audit"],
        "sse_events": event_names,
        "trace": trace,
        "ordering_assertion": required,
        "result": "PASS",
    })


def test_033d_p03_tenant_artifact_route_binds_stored_and_physical_sha(
    client, monkeypatch, tmp_path
):
    _enable_audit(monkeypatch)
    settings = get_settings()
    storage_root = tmp_path / "artifacts"
    monkeypatch.setattr(settings, "artifact_storage_backend", "local", raising=False)
    monkeypatch.setattr(settings, "artifact_storage_path", str(storage_root), raising=False)

    thread_id = _thread(client)
    artifact_id = f"artifact-{uuid.uuid4()}"
    content = b"verified tenant artifact for Nat\xc3\xa3\n"
    storage_key = f"tenant-1/{thread_id}/evidence.txt"
    physical = storage_root / storage_key
    physical.parent.mkdir(parents=True, exist_ok=True)
    physical.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()

    with Testing() as db:
        db.add(
            Artifact(
                id=artifact_id,
                tenant_id="tenant-1",
                thread_id=thread_id,
                created_by="user-1",
                filename="evidence.txt",
                mime_type="text/plain",
                storage_key=storage_key,
                sha256=digest,
            )
        )
        db.commit()

    seen: dict[str, object] = {}

    async def fake_generate(settings, agent, history):
        assert agent == "auditor"
        payload = _audit_system_payload(history)
        result = payload["data"]["result"]
        assert result["relative_path"] == artifact_id
        assert result["content"] == content.decode("utf-8")
        serialized = json.dumps(payload, ensure_ascii=False)
        assert storage_key not in serialized
        assert str(physical) not in serialized
        seen["verified_payload"] = payload
        return "Artefato do tenant verificado."

    monkeypatch.setattr(llm, "generate", fake_generate)

    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={
            "content": json.dumps(
                {
                    "version": "1",
                    "operation": "file.read_text",
                    "artifact_id": artifact_id,
                    "max_bytes": 256,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ).join(["/audit ", ""]),
            "agent": "Natã",
        },
        headers=headers(),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["agent_id"] == "auditor"
    assert body["audit"]["capability_id"] == "audit.file.inspect@1.0.0"

    with Testing() as db:
        row = db.scalar(
            select(AuditEvidenceRecord).where(
                AuditEvidenceRecord.audit_execution_id == body["audit"]["audit_execution_id"]
            )
        )
        assert row is not None
        assert row.tenant_id == "tenant-1"
        assert row.artifact_id == artifact_id
        assert row.root_id == "artifact"
        assert row.status == "completed"
        assert row.envelope_json["data"]["result"]["relative_path"] == artifact_id
        assert row.envelope_json["data"]["result"]["content"] == content.decode("utf-8")
        assert storage_key not in json.dumps(row.envelope_json, ensure_ascii=False)
        verified = verify_persisted_evidence(
            tenant_id="tenant-1",
            record_id=row.id,
            session_factory=Testing,
        )
        assert verified.evidence_sha256 == body["audit"]["evidence_sha256"]

    _emit("P03_TENANT_ARTIFACT", {
        "scenario": "033D-E2E-P03",
        "thread_id": thread_id,
        "tenant_id": "tenant-1",
        "artifact_id": artifact_id,
        "stored_sha256": digest,
        "physical_sha256": hashlib.sha256(physical.read_bytes()).hexdigest(),
        "logical_reference_in_evidence": artifact_id,
        "physical_storage_reference_exposed": False,
        "audit": body["audit"],
        "result": "PASS",
    })
