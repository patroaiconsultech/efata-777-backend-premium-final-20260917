from __future__ import annotations

from pathlib import Path

from orkio_v2.services.realtime_bridge import (
    RealtimeBridgeError,
    realtime_turn_key,
)


def test_realtime_final_transcript_key_is_boundary_scoped_and_deterministic():
    a = realtime_turn_key(
        tenant_id="tenant-a",
        thread_id="thread-1",
        session_id="sess-1",
        provider_item_id="item-1",
        transcript_final_id="event-1",
    )
    b = realtime_turn_key(
        tenant_id="tenant-a",
        thread_id="thread-1",
        session_id="sess-1",
        provider_item_id="item-1",
        transcript_final_id="event-1",
    )
    c = realtime_turn_key(
        tenant_id="tenant-b",
        thread_id="thread-1",
        session_id="sess-1",
        provider_item_id="item-1",
        transcript_final_id="event-1",
    )
    assert a == b
    assert a != c
    assert len(a) == 64


def test_realtime_final_transcript_key_fails_closed_when_identity_incomplete():
    for field in ("session_id", "provider_item_id", "transcript_final_id"):
        kwargs = dict(
            tenant_id="tenant-a",
            thread_id="thread-1",
            session_id="sess-1",
            provider_item_id="item-1",
            transcript_final_id="event-1",
        )
        kwargs[field] = ""
        try:
            realtime_turn_key(**kwargs)
        except RealtimeBridgeError as exc:
            assert exc.code == "REALTIME_IDEMPOTENCY_KEY_INCOMPLETE"
        else:
            raise AssertionError(field)


def test_realtime_duplicate_final_transcript_reconciles_without_second_execution(
    client, monkeypatch
):
    import json
    from orkio_v2.config import get_settings
    from orkio_v2.models import Message
    from orkio_v2.services.realtime_execution import RealtimeExecutionResult
    from orkio_v2.services.realtime_session import RealtimeCallResult

    settings = get_settings()
    monkeypatch.setattr(settings, "voice_enabled", True, raising=False)
    monkeypatch.setattr(settings, "voice_provider", "openai", raising=False)
    monkeypatch.setattr(settings, "openai_api_key", "not-real", raising=False)
    monkeypatch.setattr(settings, "realtime_bridge_enabled", True, raising=False)
    monkeypatch.setattr(settings, "tts_enabled", True, raising=False)
    monkeypatch.setattr(settings, "tts_provider", "openai", raising=False)
    monkeypatch.setattr(
        settings,
        "voice_bindings_json",
        json.dumps(
            {
                "voice_binding::orkio": {
                    "enabled": True,
                    "validated": True,
                    "binding_version": "1",
                    "locale_profiles": {
                        "pt-BR": {
                            "provider": "openai",
                            "voice_id": "marin",
                            "model": "gpt-4o-mini-tts",
                            "enabled": True,
                            "validated": True,
                        }
                    },
                }
            }
        ),
        raising=False,
    )

    async def fake_call(**kwargs):
        return RealtimeCallResult(
            sdp_answer="v=0\\r\\nanswer",
            call_id="call-test",
            model="gpt-realtime",
            output_modalities=("text",),
        )

    executions = {"count": 0}

    async def fake_execute(db, **kwargs):
        executions["count"] += 1
        row = Message(
            tenant_id=kwargs["tenant_id"],
            thread_id=kwargs["thread_id"],
            author_type="agent",
            author_id="orkio",
            agent_name="Josué",
            content="Resposta canônica realtime.",
        )
        db.add(row)
        db.commit()
        return RealtimeExecutionResult(
            message_id=row.id,
            execution_id="exec-realtime-1",
            agent_id="orkio",
            agent_name="Josué",
            content=row.content,
            target_mode="direct",
        )

    monkeypatch.setattr("orkio_v2.realtime_routes.create_realtime_call", fake_call)
    monkeypatch.setattr("orkio_v2.realtime_routes.execute_realtime_direct", fake_execute)

    from conftest import headers

    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    session = client.post(
        f"/api/v2/threads/{thread_id}/realtime/calls",
        json={
            "sdp": "v=0\\r\\no=- 1 1 IN IP4 127.0.0.1",
            "agent": "Josué",
            "locale": "pt-BR",
        },
        headers=headers(),
    )
    assert session.status_code == 200, session.text
    session_id = session.json()["session_id"]

    payload = {
        "session_id": session_id,
        "provider_item_id": "item-1",
        "transcript_final_id": "event-1",
        "transcript": "Pergunta realtime",
    }
    first = client.post(
        f"/api/v2/threads/{thread_id}/realtime/turns",
        json=payload,
        headers=headers(),
    )
    assert first.status_code == 200, first.text
    assert first.json()["reconciled"] is False
    assert first.json()["terminal_event"] == "done"

    second = client.post(
        f"/api/v2/threads/{thread_id}/realtime/turns",
        json=payload,
        headers=headers(),
    )
    assert second.status_code == 200, second.text
    assert second.json()["reconciled"] is True
    assert second.json()["message_id"] == first.json()["message_id"]
    assert executions["count"] == 1


def test_realtime_session_hardens_noisy_microphone_input():
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "orkio_v2"
        / "services"
        / "realtime_session.py"
    ).read_text(encoding="utf-8")
    assert '"noise_reduction": {' in source
    assert '"type": "far_field"' in source
    assert '"threshold": 0.7' in source
    assert '"prefix_padding_ms": 300' in source
    assert '"silence_duration_ms": 700' in source
