
from __future__ import annotations

import json

from sqlalchemy import delete, select

from conftest import Testing, headers
from orkio_v2.config import get_settings
from orkio_v2.models import AuditEvidenceRecord
from orkio_v2.services import llm
import orkio_v2.routes as routes


def _enable_audit(monkeypatch):
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


def _thread(client):
    return client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]


def test_chat_json_governed_audit_persists_before_natan_answer(client, monkeypatch):
    _enable_audit(monkeypatch)
    seen = {}

    async def fake_generate(settings, agent, history):
        seen["agent"] = agent
        seen["history"] = history
        return "Evidência auditada e registrada."

    async def forbidden_github(*args, **kwargs):
        raise AssertionError("GitHub side path must be suppressed for /audit")

    async def forbidden_runtime(*args, **kwargs):
        raise AssertionError("Python/external capability side path must be suppressed for /audit")

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
    assert body["agent_id"] == "auditor"
    assert body["execution"]["turn_owner"] == "auditor"
    assert body["execution"]["ownership_locked"] is True
    assert body["audit"]["capability_id"] == "audit.runtime.file_sha256@1.0.0"
    assert len(body["audit"]["evidence_sha256"]) == 64
    assert seen["agent"] == "auditor"
    assert any(
        item["role"] == "system" and "TRUSTED GOVERNED AUDIT EVIDENCE" in item["content"]
        for item in seen["history"]
    )

    with Testing() as db:
        row = db.scalar(
            select(AuditEvidenceRecord).where(
                AuditEvidenceRecord.audit_execution_id == body["audit"]["audit_execution_id"]
            )
        )
        assert row is not None
        assert row.status == "completed"
        assert row.evidence_sha256 == body["audit"]["evidence_sha256"]
        assert row.resolved_agent_id == "auditor"


def test_chat_json_plain_language_natan_does_not_execute_audit_capability(client, monkeypatch):
    _enable_audit(monkeypatch)

    async def fake_generate(settings, agent, history):
        return "Conversa normal."

    monkeypatch.setattr(llm, "generate", fake_generate)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={"content": "Natã, explique o status da auditoria.", "agent": "Natã"},
        headers=headers(),
    )
    assert response.status_code == 200
    assert "audit" not in response.json()
    with Testing() as db:
        assert db.scalar(select(AuditEvidenceRecord)) is None


def test_chat_json_malformed_directive_has_no_fake_capability_ledger_id(client, monkeypatch):
    _enable_audit(monkeypatch)

    async def must_not_generate(*args, **kwargs):
        raise AssertionError("LLM must not run after malformed audit directive")

    monkeypatch.setattr(llm, "generate", must_not_generate)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={"content": "/audit not-json", "agent": "Natã"},
        headers=headers(),
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "AUDIT_DIRECTIVE_JSON_INVALID"
    with Testing() as db:
        assert db.scalar(select(AuditEvidenceRecord)) is None


def test_chat_sse_governed_audit_uses_same_hook_and_terminates_done(client, monkeypatch):
    _enable_audit(monkeypatch)

    async def fake_stream(settings, agent, history):
        assert agent == "auditor"
        assert any(
            item["role"] == "system" and "TRUSTED GOVERNED AUDIT EVIDENCE" in item["content"]
            for item in history
        )
        yield "Auditoria "
        yield "concluída."

    async def forbidden_github(*args, **kwargs):
        raise AssertionError("GitHub side path must be suppressed for /audit")

    async def forbidden_runtime(*args, **kwargs):
        raise AssertionError("Python/external capability side path must be suppressed for /audit")

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
    events = [
        line.removeprefix("event: ").strip()
        for line in response.text.splitlines()
        if line.startswith("event: ")
    ]
    assert events[0] == "status"
    assert "chunk" in events
    assert events[-1] == "done"
    assert events.count("done") == 1
    assert "error" not in events
    assert '"capability_id": "audit.runtime.search_marker@1.0.0"' in response.text
    assert '"agent_id": "auditor"' in response.text


def test_chat_sse_wrong_selected_agent_fails_error_then_done_without_llm(client, monkeypatch):
    _enable_audit(monkeypatch)
    called = {"stream": 0}

    async def must_not_stream(*args, **kwargs):
        called["stream"] += 1
        yield "forbidden"

    monkeypatch.setattr(llm, "stream", must_not_stream)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/stream",
        json={
            "content": '/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}',
            "agent": "Bezalel",
        },
        headers=headers(),
    )
    assert response.status_code == 200
    events = [
        line.removeprefix("event: ").strip()
        for line in response.text.splitlines()
        if line.startswith("event: ")
    ]
    assert events == ["error", "done"]
    assert "AUDIT_INVOCATION_AGENT_DENIED" in response.text
    assert called["stream"] == 0

    with Testing() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row is not None
        assert row.status == "denied"
        assert row.envelope_json["read_executed"] is False

def test_malformed_directive_route_limiter_honors_policy_limit(monkeypatch):
    _enable_audit(monkeypatch)
    monkeypatch.setenv("PLATFORM_AUDIT_DIRECTIVE_USER_RATE_LIMIT", "2")
    from orkio_v2.services.capability_policy import CapabilityPolicy

    policy = CapabilityPolicy.from_env()
    limiter = routes._audit_directive_abuse_limiter(policy)
    assert limiter.consume(tenant_id="tenant-config", user_id="user-config") is True
    assert limiter.consume(tenant_id="tenant-config", user_id="user-config") is True
    assert limiter.consume(tenant_id="tenant-config", user_id="user-config") is False

