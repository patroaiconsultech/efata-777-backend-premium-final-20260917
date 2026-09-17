
from __future__ import annotations
import json
from conftest import headers
from orkio_v2.config import get_settings
from orkio_v2.services.realtime_session import RealtimeCallResult


def test_real_realtime_direct_executor_accepts_canonical_session_owner(client, monkeypatch, caplog):
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
        json.dumps({
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
        }),
        raising=False,
    )

    async def fake_call(**kwargs):
        return RealtimeCallResult(
            sdp_answer="v=0\r\nanswer\r\n",
            call_id="call-test",
            model="gpt-realtime",
            output_modalities=("text",),
        )

    async def fake_generate(settings, agent_id, history):
        assert agent_id == "orkio"
        assert any(
            item["role"] == "user"
            and item["content"] == "Pergunta realtime real executor"
            for item in history
        )
        return "Resposta canônica do executor real."

    monkeypatch.setattr("orkio_v2.realtime_routes.create_realtime_call", fake_call)
    monkeypatch.setattr("orkio_v2.services.realtime_execution.llm.generate", fake_generate)

    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
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
    payload = session.json()
    assert payload["agent_id"] == "orkio"
    sid = payload["session_id"]

    response = client.post(
        f"/api/v2/threads/{thread_id}/realtime/turns",
        json={
            "session_id": sid,
            "provider_item_id": "item-real-1",
            "transcript_final_id": "event-real-1",
            "transcript": "Pergunta realtime real executor",
        },
        headers=headers(),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "completed"
    assert body["terminal_event"] == "done"
    assert body["agent_id"] == "orkio"
    assert body["content"] == "Resposta canônica do executor real."
    assert body["tts_path"].endswith(f"/messages/{body['message_id']}/voice")

    assert not any(
        record.getMessage().startswith("REALTIME_EXECUTION_FAILURE ")
        for record in caplog.records
    )

