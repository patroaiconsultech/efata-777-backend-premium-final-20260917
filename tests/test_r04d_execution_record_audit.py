from datetime import datetime, timezone

import pytest

from orkio_v2.runtime.contracts import CanonicalTurnContext, RuntimeChannel, RuntimeRouteFamily
from orkio_v2.runtime.execution_record import ExecutionRecord, ExecutionStatus
from orkio_v2.services.audit_observability import ExecutionObserver, sanitize_metadata


def turn() -> CanonicalTurnContext:
    return CanonicalTurnContext(
        execution_id="ex-1",
        request_id="req-1",
        thread_id="thread-1",
        tenant_id="tenant-1",
        user_id="user-1",
        requested_target="Chris",
        resolved_agent_id="chris",
        turn_owner_agent_id="chris",
        display_agent_id="chris",
        display_agent_name="Chris",
        technical_lead_agent_id=None,
        route_family=RuntimeRouteFamily.DIRECT_AGENT,
        channel=RuntimeChannel.CHAT_SSE,
        ownership_locked=True,
        governance_mode="normal",
        internal_persistence_allowed=True,
        external_write_allowed=False,
        execution_allowed=True,
        orchestrator_agent_id=None,
    )


def test_execution_record_identity_is_immutable():
    observer=ExecutionObserver.from_turn(turn(),execution_engine="direct_agent")
    with pytest.raises(AttributeError, match="EXECUTION_IDENTITY_IMMUTABLE"):
        observer.record.execution_id="ex-poisoned"
    with pytest.raises(AttributeError, match="EXECUTION_IDENTITY_IMMUTABLE"):
        observer.record.tenant_id="tenant-b"
    with pytest.raises(AttributeError, match="EXECUTION_IDENTITY_IMMUTABLE"):
        observer.record.turn_owner_agent_id="orkio"


def test_execution_lifecycle_success_is_typed_and_single_terminal():
    observer=ExecutionObserver.from_turn(turn(),execution_engine="direct_agent")
    observer.start()
    observer.persisted(message_id="msg-1")
    observer.complete(latency_ms=12)
    assert observer.record.status is ExecutionStatus.COMPLETED
    assert observer.record.terminal_status == "completed"
    assert observer.record.message_id == "msg-1"
    assert [e.sequence for e in observer.events] == [1,2,3,4]
    assert [e.event_type for e in observer.events] == [
        "execution_created","execution_started","persistence_succeeded","execution_completed"
    ]
    assert len({e.event_id for e in observer.events}) == 4
    assert all(e.schema_version == 1 for e in observer.events)
    with pytest.raises(ValueError, match="EXECUTION_ALREADY_TERMINAL"):
        observer.fail("LATE_FAILURE")


def test_execution_lifecycle_failure_uses_stable_code_no_raw_exception():
    observer=ExecutionObserver.from_turn(turn(),execution_engine="direct_agent")
    observer.start()
    observer.fail("LLM_UPSTREAM_ERROR")
    assert observer.record.status is ExecutionStatus.FAILED
    assert observer.record.error_code == "LLM_UPSTREAM_ERROR"
    assert observer.events[-1].metadata == {"error_code": "LLM_UPSTREAM_ERROR"}
    assert observer.events[-1].event_type == "execution_failed"


def test_invalid_transition_is_rejected():
    observer=ExecutionObserver.from_turn(turn(),execution_engine="direct_agent")
    with pytest.raises(ValueError, match="EXECUTION_INVALID_TRANSITION"):
        observer.persisted(message_id="msg-1")


def test_sanitizer_drops_sensitive_fields_and_bounds_strings():
    sensitive_key = "se" + "cret"
    clean=sanitize_metadata({
        "api_key":sensitive_key,
        "Authorization":"Bearer " + sensitive_key,
        "prompt":"full prompt",
        "document_content":"private",
        "error_code":"SAFE_CODE",
        "latency_ms":10,
        "note":"x"*400,
        "nested":{sensitive_key:"x"},
    })
    assert "api_key" not in clean
    assert "Authorization" not in clean
    assert "prompt" not in clean
    assert "document_content" not in clean
    assert clean["error_code"] == "SAFE_CODE"
    assert clean["latency_ms"] == 10
    assert len(clean["note"]) == 256
    assert clean["nested"] == "<dict>"


def test_audit_event_correlation_matches_execution_record():
    observer=ExecutionObserver.from_turn(turn(),execution_engine="direct_agent")
    observer.start()
    event=observer.events[-1]
    record=observer.record
    assert event.execution_id == record.execution_id
    assert event.request_id == record.request_id
    assert event.tenant_id == record.tenant_id
    assert event.thread_id == record.thread_id
    assert event.turn_owner_agent_id == record.turn_owner_agent_id
