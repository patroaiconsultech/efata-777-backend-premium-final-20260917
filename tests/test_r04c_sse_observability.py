from orkio_v2.runtime.events import RuntimeEvent, RuntimeEventType, validate_runtime_sequence
from orkio_v2.services.execution_correlation import ExecutionCorrelation


def test_runtime_sequence_requires_single_execution_and_contiguous_sequence():
    events=(
        RuntimeEvent(RuntimeEventType.STATUS,"ex-1",1,{}),
        RuntimeEvent(RuntimeEventType.CHUNK,"ex-1",2,{"text":"a"}),
        RuntimeEvent(RuntimeEventType.DONE,"ex-1",3,{"status":"completed"}),
    )
    validate_runtime_sequence(events)


def test_runtime_sequence_rejects_execution_mismatch():
    events=(
        RuntimeEvent(RuntimeEventType.STATUS,"ex-1",1,{}),
        RuntimeEvent(RuntimeEventType.DONE,"ex-2",2,{"status":"completed"}),
    )
    try:
        validate_runtime_sequence(events)
    except ValueError as exc:
        assert str(exc) == "SSE_EXECUTION_ID_MISMATCH"
    else:
        raise AssertionError("expected mismatch")


def test_runtime_sequence_rejects_gap():
    events=(
        RuntimeEvent(RuntimeEventType.STATUS,"ex-1",1,{}),
        RuntimeEvent(RuntimeEventType.DONE,"ex-1",3,{"status":"completed"}),
    )
    try:
        validate_runtime_sequence(events)
    except ValueError as exc:
        assert str(exc) == "SSE_SEQUENCE_MUST_BE_CONTIGUOUS"
    else:
        raise AssertionError("expected gap")


def test_correlation_never_exposes_tenant_in_sse_event_data():
    correlation=ExecutionCorrelation(
        request_id="req",execution_id="ex",tenant_id="tenant-secret",
        thread_id="thread",owner_agent_id="orkio",execution_engine="DIRECT_AGENT",
    )
    data=correlation.event_data(status="started")
    assert data["request_id"] == "req"
    assert data["execution_id"] == "ex"
    assert "tenant_id" not in data
