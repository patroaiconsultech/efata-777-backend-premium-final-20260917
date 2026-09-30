from __future__ import annotations

import logging

import pytest

from orkio_v2.sse_delivery_trace import SSEDeliveryTraceMiddleware


def _scope(path: str = "/api/v2/threads/thread-1/stream", method: str = "POST"):
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [],
        "client": ("testclient", 123),
        "server": ("testserver", 80),
        "root_path": "",
    }


async def _receive():
    return {"type": "http.request", "body": b"", "more_body": False}


@pytest.mark.asyncio
async def test_delivery_trace_logs_only_safe_metadata_after_send(monkeypatch, caplog):
    monkeypatch.setenv("PLATFORM_SSE_DELIVERY_TRACE_ENABLED", "true")
    delivered = []
    secret_text = "SECRET-USER-OR-MODEL-CONTENT"

    async def downstream(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({
            "type": "http.response.body",
            "body": (
                "event: error\n"
                'data: {"execution_id":"exec-1","sequence":1,'
                '"code":"AUDIT_RUNTIME_MODULE_NOT_ALLOWED",'
                f'"message":"{secret_text}"}}\n\n'
            ).encode(),
            "more_body": True,
        })
        await send({
            "type": "http.response.body",
            "body": b'event: done\ndata: {"execution_id":"exec-1","sequence":2,"status":"failed"}\n\n',
            "more_body": True,
        })
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    async def actual_send(message):
        delivered.append(message)

    caplog.set_level(logging.INFO, logger="uvicorn.error.orkio.sse_delivery")
    middleware = SSEDeliveryTraceMiddleware(downstream)
    await middleware(_scope(), _receive, actual_send)

    assert len(delivered) == 4
    logs = "\\n".join(record.getMessage() for record in caplog.records)
    assert "response_start_sent" in logs
    assert "body_sent" in logs
    assert "stream_closed" in logs
    assert "error" in logs
    assert "done" in logs
    assert "AUDIT_RUNTIME_MODULE_NOT_ALLOWED" in logs
    assert secret_text not in logs
    assert '"execution_id":"exec-1"' in logs
    assert '"status":"failed"' in logs


@pytest.mark.asyncio
async def test_delivery_trace_is_noop_when_flag_disabled(monkeypatch, caplog):
    monkeypatch.delenv("PLATFORM_SSE_DELIVERY_TRACE_ENABLED", raising=False)
    delivered = []

    async def downstream(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"event: done\n\ndata: {}\n\n", "more_body": False})

    async def actual_send(message):
        delivered.append(message)

    caplog.set_level(logging.INFO, logger="uvicorn.error.orkio.sse_delivery")
    middleware = SSEDeliveryTraceMiddleware(downstream)
    await middleware(_scope(), _receive, actual_send)

    assert len(delivered) == 2
    assert not caplog.records


@pytest.mark.asyncio
async def test_delivery_trace_does_not_trace_noncanonical_route(monkeypatch, caplog):
    monkeypatch.setenv("PLATFORM_SSE_DELIVERY_TRACE_ENABLED", "true")
    delivered = []

    async def downstream(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    async def actual_send(message):
        delivered.append(message)

    caplog.set_level(logging.INFO, logger="uvicorn.error.orkio.sse_delivery")
    middleware = SSEDeliveryTraceMiddleware(downstream)
    await middleware(_scope(path="/api/v2/me", method="GET"), _receive, actual_send)

    assert len(delivered) == 2
    assert not caplog.records

@pytest.mark.asyncio
async def test_delivery_trace_send_failure_logs_safe_metadata_without_false_body_sent(
    monkeypatch,
    caplog,
):
    monkeypatch.setenv("PLATFORM_SSE_DELIVERY_TRACE_ENABLED", "true")
    secret_text = "SECRET-NOT-FOR-TRACE"

    async def downstream(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({
            "type": "http.response.body",
            "body": (
                "event: done\n"
                'data: {"execution_id":"exec-fail","sequence":2,'
                '"status":"failed","code":"AUDIT_RUNTIME_MODULE_NOT_ALLOWED",'
                f'"message":"{secret_text}"}}\n\n'
            ).encode(),
            "more_body": False,
        })

    async def actual_send(message):
        if message.get("type") == "http.response.body":
            raise RuntimeError("synthetic send failure")

    caplog.set_level(logging.INFO, logger="uvicorn.error.orkio.sse_delivery")
    middleware = SSEDeliveryTraceMiddleware(downstream)

    with pytest.raises(RuntimeError, match="synthetic send failure"):
        await middleware(_scope(), _receive, actual_send)

    logs = "\n".join(record.getMessage() for record in caplog.records)
    assert "response_start_sent" in logs
    assert "body_send_failed" in logs
    assert '"event_names":["done"]' in logs
    assert '"execution_id":"exec-fail"' in logs
    assert '"sequence":2' in logs
    assert '"status":"failed"' in logs
    assert '"code":"AUDIT_RUNTIME_MODULE_NOT_ALLOWED"' in logs
    assert '"exception_type":"RuntimeError"' in logs
    assert secret_text not in logs
    assert '"event":"body_sent"' not in logs
    assert "stream_closed" not in logs

