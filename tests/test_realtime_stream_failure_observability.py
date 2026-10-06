
from __future__ import annotations

import json
import logging
from types import SimpleNamespace

from conftest import headers
from orkio_v2.config import get_settings
from orkio_v2.services.realtime_session import RealtimeCallResult


def test_unexpected_realtime_stream_failure_logs_safe_stage_metadata(
    client,
    monkeypatch,
    caplog,
):
    settings = get_settings()
    monkeypatch.setattr(settings, "realtime_bridge_enabled", True, raising=False)
    monkeypatch.setattr(settings, "tts_enabled", True, raising=False)

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.realtime_capability",
        lambda *_args, **_kwargs: {
            "realtime_session": {"eligible": True},
            "orchestration_bridge": {"eligible": True},
            "voice_output": {"eligible": True},
        },
    )
    monkeypatch.setattr(
        "orkio_v2.realtime_routes.resolve_voice_profile",
        lambda *_args, **_kwargs: SimpleNamespace(
            provider="openai",
            voice_id="cedar",
            model="gpt-4o-mini-tts",
        ),
    )

    async def fake_call(**_kwargs):
        return RealtimeCallResult(
            sdp_answer="v=0\r\nanswer\r\n",
            call_id="call-observability",
            model="gpt-realtime",
            output_modalities=("text",),
        )

    secret_marker = "DO_NOT_LOG_TRANSCRIPT_MARKER"

    async def exploding_stream(*_args, **_kwargs):
        yield {
            "type": "turn_started",
            "turn_id": "turn-observability",
            "execution_id": "exec-observability",
        }
        raise RuntimeError(secret_marker)

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.create_realtime_call",
        fake_call,
    )
    monkeypatch.setattr(
        "orkio_v2.realtime_routes.stream_realtime_direct",
        exploding_stream,
    )

    thread_id = client.post(
        "/api/v2/threads",
        json={},
        headers=headers(),
    ).json()["id"]

    session = client.post(
        f"/api/v2/threads/{thread_id}/realtime/calls",
        json={
            "sdp": "v=0\r\no=- 1 1 IN IP4 127.0.0.1",
            "agent": "Josué",
            "locale": "pt-BR",
        },
        headers=headers(),
    )
    assert session.status_code == 200, session.text
    session_id = session.json()["session_id"]

    caplog.set_level(logging.ERROR, logger="uvicorn.error")
    response = client.post(
        f"/api/v2/threads/{thread_id}/realtime/turns/stream",
        json={
            "session_id": session_id,
            "provider_item_id": "item-observability",
            "transcript_final_id": "event-observability",
            "transcript": "conteudo que nao deve aparecer no log",
            "locale": "pt-BR",
        },
        headers=headers(),
    )

    assert response.status_code == 200
    assert "event: error" in response.text
    assert '"code": "REALTIME_STREAM_FAILED"' in response.text

    matching = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("REALTIME_STREAM_FAILURE ")
    ]
    assert len(matching) == 1
    payload = json.loads(matching[0].split(" ", 1)[1])

    assert payload["pipeline"] == "realtime_segment_stream"
    assert payload["stage"] == "execution_stream"
    assert payload["exception_type"] == "RuntimeError"
    assert payload["execution_id"] == "exec-observability"
    assert payload["turn_id"] == "turn-observability"
    assert payload["segments_count"] == 0
    assert payload["error_code"] == "REALTIME_STREAM_FAILED"
    assert payload["diagnostic_request_id"]
    assert payload["trace_frames"]
    assert secret_marker not in matching[0]
    assert "conteudo que nao deve aparecer no log" not in matching[0]
