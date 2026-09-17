from __future__ import annotations

import json
import logging

from sqlalchemy import delete

from conftest import Testing, headers
from orkio_v2.config import get_settings
from orkio_v2.models import AuditEvidenceRecord
from orkio_v2.services import llm
import orkio_v2.routes as routes



def test_trace_runtime_sink_is_visible_under_uvicorn_default_logging(tmp_path):
    script = r"""
import logging.config
import os
from uvicorn.config import LOGGING_CONFIG
logging.config.dictConfig(LOGGING_CONFIG)
os.environ["ORKIO_AUDIT_TRACE_ENABLED"] = "true"
from orkio_v2.services.ao01_audit_trace import emit_audit_trace
emit_audit_trace("runtime_sink_probe", trace_id="trace-probe-1", status="ok")
"""
    result = __import__("subprocess").run(
        [__import__("sys").executable, "-c", script],
        cwd=str(__import__("pathlib").Path(__file__).resolve().parents[1]),
        env={**__import__("os").environ, "PYTHONPATH": str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    combined = result.stdout + result.stderr
    assert "AUDIT_TRACE" in combined
    assert "runtime_sink_probe" in combined

def _enable_audit(monkeypatch, *, trace: bool) -> None:
    for name, value in {
        "PLATFORM_AUDIT_GOVERNED_INVOCATION_ENABLED": "true",
        "PLATFORM_AUDIT_EVIDENCE_CAPABILITIES_ENABLED": "true",
        "PLATFORM_AUDIT_RUNTIME_INSPECT_ENABLED": "true",
        "PLATFORM_AUDIT_RUNTIME_FILE_SHA256_ENABLED": "true",
        "PLATFORM_AUDIT_RUNTIME_SEARCH_MARKER_ENABLED": "true",
        "PLATFORM_AUDIT_ALLOWED_AGENT_IDS": "auditor",
        "PLATFORM_AUDIT_ALLOWED_TENANT_IDS": "tenant-1",
        "PLATFORM_AUDIT_ALLOWED_ENVIRONMENTS": "test",
        "PLATFORM_AUDIT_RATE_LIMIT_WINDOW_SECONDS": "60",
        "PLATFORM_AUDIT_USER_RATE_LIMIT_PER_WINDOW": "20",
        "PLATFORM_AUDIT_TENANT_RATE_LIMIT_PER_WINDOW": "40",
        "PLATFORM_AUDIT_DIRECTIVE_USER_RATE_LIMIT": "20",
        "ORKIO_AUDIT_TRACE_ENABLED": "true" if trace else "false",
    }.items():
        monkeypatch.setenv(name, value)

    settings = get_settings()
    monkeypatch.setattr(settings, "openai_api_key", "test-key-not-real", raising=False)
    monkeypatch.setattr(settings, "release_sha", "trace-test-build-sha", raising=False)
    monkeypatch.setattr(settings, "railway_deployment_id", "trace-test-deployment", raising=False)

    for limiter in routes._audit_directive_abuse_limiters.values():
        limiter.reset()
    routes._audit_directive_abuse_limiters.clear()
    with Testing() as db:
        db.execute(delete(AuditEvidenceRecord))
        db.commit()


def _thread(client) -> str:
    return client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]


def _trace_payloads(caplog) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for record in caplog.records:
        if record.name != "uvicorn.error.orkio.audit_trace":
            continue
        message = record.getMessage()
        if message.startswith("AUDIT_TRACE "):
            payloads.append(json.loads(message.removeprefix("AUDIT_TRACE ")))
    return payloads


def test_trace_success_correlates_directive_repository_return_attach_and_sse(
    client, monkeypatch, caplog
):
    _enable_audit(monkeypatch, trace=True)
    caplog.set_level(logging.INFO, logger="uvicorn.error.orkio.audit_trace")
    marker = "TRACE_LITERAL_SHOULD_NOT_BE_LOGGED_777"

    async def fake_stream(settings, agent, history):
        assert agent == "auditor"
        yield "Auditoria rastreada."

    monkeypatch.setattr(llm, "stream", fake_stream)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/stream",
        json={
            "content": (
                '/audit {"version":"1","operation":"runtime.search_marker",'
                f'"module_id":"routes","marker":"{marker}"}}'
            ),
            "agent": "Natã",
        },
        headers=headers(),
    )

    assert response.status_code == 200
    assert "event: done" in response.text

    payloads = _trace_payloads(caplog)
    stages = [str(item["stage"]) for item in payloads]
    required = {
        "directive_received",
        "directive_parsed",
        "policy_preflight_allowed",
        "policy_allowed",
        "dispatcher_enter",
        "adapter_started",
        "adapter_completed",
        "evidence_persist_started",
        "evidence_repository_returned",
        "invocation_completed",
        "evidence_attached_to_turn",
        "sse_terminal",
    }
    assert required.issubset(set(stages)), stages

    trace_ids = {item.get("trace_id") for item in payloads if item.get("trace_id")}
    assert len(trace_ids) == 1
    assert all(item.get("contract") == "ORKIO-AUDIT-TRACE-1" for item in payloads)
    assert any(item.get("audit_execution_id") for item in payloads)
    assert any(item.get("request_id") for item in payloads)
    assert any(item.get("tenant_id") == "tenant-1" for item in payloads)
    assert any(item.get("resolved_agent") == "auditor" for item in payloads)
    assert any(item.get("turn_owner") == "auditor" for item in payloads)
    assert any(item.get("deployment_id") == "trace-test-deployment" for item in payloads)
    assert any(item.get("build_sha") == "trace-test-build-sha" for item in payloads)
    assert any(
        item.get("stage") == "evidence_repository_returned"
        and item.get("repository_verified_on_return") is True
        for item in payloads
    )

    serialized = "\n".join(record.getMessage() for record in caplog.records)
    assert marker not in serialized
    assert "/audit " not in serialized


def test_trace_invalid_module_records_first_typed_failure_and_sse_terminal(
    client, monkeypatch, caplog
):
    _enable_audit(monkeypatch, trace=True)
    caplog.set_level(logging.INFO, logger="uvicorn.error.orkio.audit_trace")

    async def must_not_stream(*args, **kwargs):
        raise AssertionError("LLM must not run for failed governed audit")
        yield ""

    monkeypatch.setattr(llm, "stream", must_not_stream)
    thread_id = _thread(client)
    response = client.post(
        f"/api/v2/threads/{thread_id}/stream",
        json={
            "content": (
                '/audit {"version":"1","operation":"runtime.file_sha256",'
                '"module_id":"MODULO_QUE_NAO_EXISTE_777XYZ"}'
            ),
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

    payloads = _trace_payloads(caplog)
    assert any(
        item.get("stage") == "adapter_failed"
        and item.get("error_code") == "AUDIT_RUNTIME_MODULE_NOT_ALLOWED"
        for item in payloads
    )
    assert any(item.get("stage") == "evidence_repository_returned" for item in payloads)
    assert any(
        item.get("stage") == "sse_terminal"
        and item.get("status") == "failed"
        and item.get("error_code") == "AUDIT_RUNTIME_MODULE_NOT_ALLOWED"
        for item in payloads
    )


def test_trace_flag_off_has_zero_audit_trace_records(client, monkeypatch, caplog):
    _enable_audit(monkeypatch, trace=False)
    caplog.set_level(logging.INFO, logger="uvicorn.error.orkio.audit_trace")

    async def fake_stream(settings, agent, history):
        yield "Sem trace."

    monkeypatch.setattr(llm, "stream", fake_stream)
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
    assert "event: done" in response.text
    assert _trace_payloads(caplog) == []
