from __future__ import annotations

import json
import pytest
from sqlalchemy import select

from conftest import Testing, headers
from orkio_v2.config import get_settings
from orkio_v2.models import Message, ThreadParticipant, ThreadRole
from orkio_v2.services.voice_binding import (
    VoiceBindingError,
    resolve_voice_profile,
)
from orkio_v2.services.text_to_speech import (
    message_content_sha256,
    synthesis_identity,
)


def _binding_json():
    return json.dumps({
        "voice_binding::orkio": {
            "binding_version": "1",
            "enabled": True,
            "validated": True,
            "locale_profiles": {
                "pt-BR": {
                    "provider": "openai",
                    "voice_id": "marin",
                    "model": "gpt-4o-mini-tts",
                    "enabled": True,
                    "validated": True
                }
            }
        }
    })


def _enable_tts(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "tts_enabled", True, raising=False)
    monkeypatch.setattr(settings, "tts_provider", "openai", raising=False)
    monkeypatch.setattr(settings, "tts_http_timeout_seconds", 5.0, raising=False)
    monkeypatch.setattr(settings, "tts_max_chars", 4096, raising=False)
    monkeypatch.setattr(settings, "voice_bindings_json", _binding_json(), raising=False)
    monkeypatch.setattr(settings, "openai_api_key", "contract-test-not-real", raising=False)
    return settings


def test_voice_binding_exact_agent_and_locale(monkeypatch):
    settings = _enable_tts(monkeypatch)
    profile = resolve_voice_profile(
        "orkio", "pt-BR", settings, delivery_mode="MESSAGE_PLAYBACK"
    )
    assert profile.agent_id == "orkio"
    assert profile.binding_id == "voice_binding::orkio"
    assert profile.locale == "pt-BR"
    assert profile.provider == "openai"
    with pytest.raises(VoiceBindingError, match="VOICE_LOCALE_NOT_SUPPORTED"):
        resolve_voice_profile("orkio", "fr-FR", settings, delivery_mode="MESSAGE_PLAYBACK")



def test_tts_idempotency_identity_is_bound_to_message_agent_locale_and_content(monkeypatch):
    settings = _enable_tts(monkeypatch)
    profile = resolve_voice_profile(
        "orkio", "pt-BR", settings, delivery_mode="MESSAGE_PLAYBACK"
    )
    content_hash = message_content_sha256("Resposta persistida.")
    base = synthesis_identity(
        tenant_id="tenant-1",
        thread_id="thread-1",
        message_id="message-1",
        locale="pt-BR",
        profile=profile,
        content_sha256=content_hash,
    )
    replay = synthesis_identity(
        tenant_id="tenant-1",
        thread_id="thread-1",
        message_id="message-1",
        locale="pt-BR",
        profile=profile,
        content_sha256=content_hash,
    )
    cross_message = synthesis_identity(
        tenant_id="tenant-1",
        thread_id="thread-1",
        message_id="message-2",
        locale="pt-BR",
        profile=profile,
        content_sha256=content_hash,
    )
    changed_content = synthesis_identity(
        tenant_id="tenant-1",
        thread_id="thread-1",
        message_id="message-1",
        locale="pt-BR",
        profile=profile,
        content_sha256=message_content_sha256("Conteúdo alterado."),
    )
    assert base == replay
    assert base != cross_message
    assert base != changed_content
    assert len(base) == 64

def test_message_tts_resolves_persisted_author_and_denies_viewer(client, monkeypatch, tmp_path):
    settings = _enable_tts(monkeypatch)
    monkeypatch.setattr(settings, "tts_cache_path", str(tmp_path / "tts-cache"), raising=False)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    with Testing() as db:
        row = Message(
            tenant_id="tenant-1",
            thread_id=thread_id,
            author_type="agent",
            author_id="orkio",
            agent_name="Josué",
            content="Resposta persistida.",
        )
        db.add(row)
        db.commit()
        message_id = row.id

    async def fake_synth(_settings, profile, text, *, request_id):
        assert profile.agent_id == "orkio"
        assert text == "Resposta persistida."
        assert request_id == "req-tts-1"
        return b"ID3fake"

    monkeypatch.setattr("orkio_v2.tts_routes.synthesize_speech", fake_synth)
    response = client.post(
        f"/api/v2/threads/{thread_id}/messages/{message_id}/voice",
        json={"locale": "pt-BR"},
        headers={**headers(), "X-Request-Id": "req-tts-1"},
    )
    assert response.status_code == 200
    assert response.content == b"ID3fake"
    assert response.headers["x-orkio-voice-agent-id"] == "orkio"

    with Testing() as db:
        member = db.scalar(
            select(ThreadParticipant).where(
                ThreadParticipant.thread_id == thread_id,
                ThreadParticipant.user_id == "user-1",
            )
        )
        member.thread_role = ThreadRole.viewer.value
        db.commit()

    try:
        denied = client.post(
            f"/api/v2/threads/{thread_id}/messages/{message_id}/voice",
            json={"locale": "pt-BR"},
            headers={**headers(), "X-Request-Id": "req-tts-2"},
        )
        assert denied.status_code == 403
        assert denied.json()["detail"]["code"] == "VIEWER_TTS_NOT_ALLOWED"
    finally:
        # Shared test database: restore the baseline role so this contract test
        # cannot contaminate unrelated thread authorization tests.
        with Testing() as db:
            member = db.scalar(
                select(ThreadParticipant).where(
                    ThreadParticipant.thread_id == thread_id,
                    ThreadParticipant.user_id == "user-1",
                )
            )
            member.thread_role = ThreadRole.owner.value
            db.commit()

def test_tts_idempotency_replay_does_not_resynthesize_when_cache_disabled(
    client, monkeypatch, tmp_path
):
    settings = _enable_tts(monkeypatch)
    monkeypatch.setattr(settings, "tts_cache_enabled", False, raising=False)
    monkeypatch.setattr(settings, "tts_cache_path", str(tmp_path / "tts-cache"), raising=False)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    with Testing() as db:
        row = Message(
            tenant_id="tenant-1",
            thread_id=thread_id,
            author_type="agent",
            author_id="orkio",
            agent_name="Josué",
            content="Resposta idempotente.",
        )
        db.add(row)
        db.commit()
        message_id = row.id

    calls = {"count": 0}

    async def fake_synth(_settings, profile, text, *, request_id):
        calls["count"] += 1
        assert profile.agent_id == "orkio"
        assert text == "Resposta idempotente."
        return b"ID3-idempotent"

    monkeypatch.setattr("orkio_v2.tts_routes.synthesize_speech", fake_synth)
    shared_headers = {
        **headers(),
        "Idempotency-Key": "idem-message-1-ptbr",
    }

    first = client.post(
        f"/api/v2/threads/{thread_id}/messages/{message_id}/voice",
        json={"locale": "pt-BR"},
        headers={**shared_headers, "X-Request-Id": "req-idem-1"},
    )
    second = client.post(
        f"/api/v2/threads/{thread_id}/messages/{message_id}/voice",
        json={"locale": "pt-BR"},
        headers={**shared_headers, "X-Request-Id": "req-idem-2"},
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.content == second.content == b"ID3-idempotent"
    assert calls["count"] == 1
    assert first.headers["x-orkio-tts-idempotency"] == "NEW"
    assert second.headers["x-orkio-tts-idempotency"] == "REPLAY"


def test_tts_different_idempotency_key_can_create_new_synthesis_when_cache_disabled(
    client, monkeypatch, tmp_path
):
    settings = _enable_tts(monkeypatch)
    monkeypatch.setattr(settings, "tts_cache_enabled", False, raising=False)
    monkeypatch.setattr(settings, "tts_cache_path", str(tmp_path / "tts-cache"), raising=False)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    with Testing() as db:
        row = Message(
            tenant_id="tenant-1",
            thread_id=thread_id,
            author_type="agent",
            author_id="orkio",
            agent_name="Josué",
            content="Resposta idempotente por chave.",
        )
        db.add(row)
        db.commit()
        message_id = row.id

    calls = {"count": 0}

    async def fake_synth(_settings, profile, text, *, request_id):
        calls["count"] += 1
        return f"ID3-{calls['count']}".encode()

    monkeypatch.setattr("orkio_v2.tts_routes.synthesize_speech", fake_synth)
    for index in (1, 2):
        response = client.post(
            f"/api/v2/threads/{thread_id}/messages/{message_id}/voice",
            json={"locale": "pt-BR"},
            headers={
                **headers(),
                "X-Request-Id": f"req-new-{index}",
                "Idempotency-Key": f"distinct-{index}",
            },
        )
        assert response.status_code == 200
        assert response.headers["x-orkio-tts-idempotency"] == "NEW"

    assert calls["count"] == 2

def test_tts_idempotency_replay_does_not_bypass_rate_limit(
    client, monkeypatch, tmp_path
):
    settings = _enable_tts(monkeypatch)
    monkeypatch.setattr(settings, "tts_cache_enabled", False, raising=False)
    monkeypatch.setattr(settings, "tts_cache_path", str(tmp_path / "tts-cache"), raising=False)
    monkeypatch.setattr(settings, "tts_tenant_rate_limit_per_minute", 1000, raising=False)
    monkeypatch.setattr(settings, "tts_user_rate_limit_per_minute", 1000, raising=False)
    monkeypatch.setattr(settings, "tts_message_rate_limit_per_minute", 1, raising=False)

    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    with Testing() as db:
        row = Message(
            tenant_id="tenant-1",
            thread_id=thread_id,
            author_type="agent",
            author_id="orkio",
            agent_name="Josué",
            content="Resposta governada por rate limit.",
        )
        db.add(row)
        db.commit()
        message_id = row.id

    calls = {"count": 0}

    async def fake_synth(_settings, profile, text, *, request_id):
        calls["count"] += 1
        return b"ID3-rate-limited-replay"

    monkeypatch.setattr("orkio_v2.tts_routes.synthesize_speech", fake_synth)
    shared_headers = {
        **headers(),
        "Idempotency-Key": "idem-rate-limit-replay",
    }

    first = client.post(
        f"/api/v2/threads/{thread_id}/messages/{message_id}/voice",
        json={"locale": "pt-BR"},
        headers={**shared_headers, "X-Request-Id": "req-rate-idem-1"},
    )
    second = client.post(
        f"/api/v2/threads/{thread_id}/messages/{message_id}/voice",
        json={"locale": "pt-BR"},
        headers={**shared_headers, "X-Request-Id": "req-rate-idem-2"},
    )

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["detail"]["code"] == "TTS_RATE_LIMITED"
    assert calls["count"] == 1

