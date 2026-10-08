from __future__ import annotations

from sqlalchemy import delete, select

from conftest import Testing, headers
from orkio_v2.config import get_settings
from orkio_v2.models import AuditEvidenceRecord
from orkio_v2.services import llm
from orkio_v2.services.audit_natural_binding import (
    AUDIT_RUNTIME_TRACE_CAPABILITY_ID,
    resolve_natural_audit_binding,
)
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
    monkeypatch.setattr(
        get_settings(), "openai_api_key", "test-key-not-real", raising=False
    )
    for limiter in routes._audit_directive_abuse_limiters.values():
        limiter.reset()
    routes._audit_directive_abuse_limiters.clear()
    with Testing() as db:
        db.execute(delete(AuditEvidenceRecord))
        db.commit()


def _thread(client):
    return client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]


def test_natural_runtime_hash_binds_only_allowlisted_module():
    binding = resolve_natural_audit_binding(
        "Natã, audite o SHA-256 do módulo routes em runtime.",
        resolved_agent_id="auditor",
    )
    assert binding is not None
    assert binding.executable is True
    assert binding.intent == "runtime.file_sha256"
    assert binding.required_capability_id == "audit.runtime.file_sha256@1.0.0"
    assert '"module_id":"routes"' in (binding.directive_message or "")
    assert "/etc/passwd" not in (binding.directive_message or "")


def test_natural_runtime_trace_reports_capability_unavailable():
    binding = resolve_natural_audit_binding(
        "Audite a última tentativa de Realtime da EFATÀ e diga onde ocorreu a primeira divergência.",
        resolved_agent_id="auditor",
    )
    assert binding is not None
    assert binding.executable is False
    assert binding.intent == "runtime.trace.get"
    assert binding.required_capability_id == AUDIT_RUNTIME_TRACE_CAPABILITY_ID
    assert binding.error_code == "CAPABILITY_UNAVAILABLE"


def test_natural_binding_does_not_hijack_non_audit_or_other_agent():
    assert (
        resolve_natural_audit_binding(
            "Natã, explique o status da auditoria.",
            resolved_agent_id="auditor",
        )
        is None
    )
    assert (
        resolve_natural_audit_binding(
            "Audite o SHA-256 do módulo routes em runtime.",
            resolved_agent_id="orkio",
        )
        is None
    )


def test_chat_json_natural_hash_executes_governed_capability(client, monkeypatch):
    _enable_audit(monkeypatch)
    seen = {}

    async def fake_generate(settings, agent, history):
        seen["agent"] = agent
        seen["history"] = history
        return "Evidência natural adquirida de forma governada."

    async def forbidden_side_path(*args, **kwargs):
        raise AssertionError("uncontrolled side path must not run")

    monkeypatch.setattr(llm, "generate", fake_generate)
    monkeypatch.setattr(routes, "github_context_messages", forbidden_side_path)
    monkeypatch.setattr(routes, "runtime_capability_messages", forbidden_side_path)

    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={
            "content": "Natã, audite o SHA-256 do módulo routes em runtime.",
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
    assert body["audit"]["status"] == "completed"
    assert seen["agent"] == "auditor"
    assert any(
        item["role"] == "system"
        and "TRUSTED GOVERNED AUDIT EVIDENCE" in item["content"]
        for item in seen["history"]
    )
    with Testing() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row is not None
        assert row.status == "completed"
        assert row.resolved_agent_id == "auditor"
        assert row.envelope_json["write_executed"] is False


def test_chat_json_natural_realtime_fails_precisely_without_llm_or_ledger(
    client, monkeypatch
):
    _enable_audit(monkeypatch)

    async def must_not_generate(*args, **kwargs):
        raise AssertionError("LLM must not run when required capability is unavailable")

    monkeypatch.setattr(llm, "generate", must_not_generate)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={
            "content": "Audite a última tentativa de Realtime da EFATÀ e diga onde ocorreu a primeira divergência.",
            "agent": "Natã",
        },
        headers=headers(),
    )
    assert response.status_code == 501, response.text
    detail = response.json()["detail"]
    assert detail == {
        "code": "CAPABILITY_UNAVAILABLE",
        "audit_intent": "runtime.trace.get",
        "evidence_status": "NOT_PROVEN",
        "required_capability_id": AUDIT_RUNTIME_TRACE_CAPABILITY_ID,
    }
    with Testing() as db:
        assert db.scalar(select(AuditEvidenceRecord)) is None


def test_chat_sse_natural_realtime_emits_error_then_done(client, monkeypatch):
    _enable_audit(monkeypatch)

    async def must_not_stream(*args, **kwargs):
        raise AssertionError("LLM must not run when required capability is unavailable")
        yield "never"

    monkeypatch.setattr(llm, "stream", must_not_stream)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/stream",
        json={
            "content": "Natã, audite a última tentativa de Realtime e encontre a primeira divergência.",
            "agent": "Natã",
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
    assert "CAPABILITY_UNAVAILABLE" in response.text
    with Testing() as db:
        assert db.scalar(select(AuditEvidenceRecord)) is None


def test_chat_json_natural_hash_preserves_permission_fail_closed(client, monkeypatch):
    _enable_audit(monkeypatch)
    monkeypatch.setenv("PLATFORM_AUDIT_ALLOWED_TENANT_IDS", "another-tenant")

    async def must_not_generate(*args, **kwargs):
        raise AssertionError("LLM must not run after permission denial")

    monkeypatch.setattr(llm, "generate", must_not_generate)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={
            "content": "Natã, audite o SHA-256 do módulo routes em runtime.",
            "agent": "Natã",
        },
        headers=headers(),
    )
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["code"] == "AUDIT_CAPABILITY_TENANT_DENIED"
    with Testing() as db:
        row = db.scalar(select(AuditEvidenceRecord))
        assert row is not None
        assert row.status == "denied"
        assert row.envelope_json["read_executed"] is False
        assert row.envelope_json["write_executed"] is False
        assert row.error_code == "AUDIT_CAPABILITY_TENANT_DENIED"
