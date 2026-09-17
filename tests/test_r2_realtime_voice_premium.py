from __future__ import annotations

import json
from types import SimpleNamespace

from sqlalchemy import delete, select

from conftest import Testing, headers
from orkio_v2.config import get_settings
from orkio_v2.models import (
    AgentVoiceAssignment,
    AuditEvent,
    Membership,
    Message,
    VoiceCatalogEntry,
)
from orkio_v2.services.realtime_session import RealtimeCallResult
from orkio_v2.services.voice_binding import VoiceProfile, resolve_voice_profile


def _configure_voice_runtime(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "voice_enabled", True, raising=False)
    monkeypatch.setattr(settings, "voice_provider", "openai", raising=False)
    monkeypatch.setattr(settings, "openai_api_key", "r2-contract-test-not-real", raising=False)
    monkeypatch.setattr(settings, "realtime_bridge_enabled", True, raising=False)
    monkeypatch.setattr(settings, "tts_enabled", True, raising=False)
    monkeypatch.setattr(settings, "tts_provider", "openai", raising=False)
    monkeypatch.setattr(settings, "tts_cache_enabled", False, raising=False)
    monkeypatch.setattr(
        settings,
        "voice_bindings_json",
        json.dumps(
            {
                "voice_binding::orkio": {
                    "agent_id": "orkio",
                    "enabled": True,
                    "validated": True,
                    "binding_version": "env-v1",
                    "delivery_modes": ["REALTIME_STREAM", "MESSAGE_PLAYBACK"],
                    "locale_profiles": {
                        "pt-BR": {
                            "provider": "openai",
                            "voice_id": "env-voice",
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
    return settings


def _cleanup_voice_state():
    with Testing() as db:
        db.execute(
            delete(AuditEvent).where(
                AuditEvent.resource_type == "agent_voice_assignment"
            )
        )
        db.execute(delete(AgentVoiceAssignment))
        db.execute(delete(VoiceCatalogEntry))
        membership = db.scalar(
            select(Membership).where(
                Membership.tenant_id == "tenant-1",
                Membership.user_id == "user-1",
            )
        )
        if membership is not None:
            membership.role = "admin"
        db.commit()


def _seed_catalog(
    *,
    voice_id: str = "catalog-voice-r2",
    catalog_id: str = "voice-r2",
) -> str:
    with Testing() as db:
        db.add(
            VoiceCatalogEntry(
                id=catalog_id,
                provider_key="openai",
                provider_voice_id=voice_id,
                display_name="EFATÀ R2 Voice",
                provider_model="gpt-4o-mini-tts",
                source_type="BUILT_IN",
                license_label="PROVIDER_TERMS",
                cost_class="API_USAGE_BILLED",
                catalog_version="r2",
                supported_locales=["pt-BR"],
                delivery_modes=["REALTIME_STREAM", "MESSAGE_PLAYBACK"],
                curation_status="APPROVED",
                active=True,
            )
        )
        db.commit()
    return catalog_id


def _seed_active_validated_assignment(
    *,
    assignment_id: str = "assignment-r2",
    catalog_id: str = "voice-r2",
    tenant_id: str = "tenant-1",
) -> str:
    with Testing() as db:
        db.add(
            AgentVoiceAssignment(
                id=assignment_id,
                tenant_id=tenant_id,
                agent_slug="orkio",
                voice_catalog_id=catalog_id,
                locale="pt-BR",
                delivery_modes=["REALTIME_STREAM", "MESSAGE_PLAYBACK"],
                presentation_label="NEUTRA",
                assignment_state="ACTIVE",
                validation_status="VALIDATED",
                active=True,
                version=1,
                created_by="user-1",
                updated_by="user-1",
            )
        )
        db.commit()
    return assignment_id


def _catalog_profile() -> VoiceProfile:
    return VoiceProfile(
        agent_id="orkio",
        binding_id="admin:assignment-r2",
        binding_version="1",
        locale="pt-BR",
        provider="openai",
        voice_id="catalog-voice-r2",
        model="gpt-4o-mini-tts",
        source_type="CURATED_PRESET",
        delivery_mode="REALTIME_STREAM",
        provider_profile_version="catalog",
    )


def test_r2_admin_voice_lifecycle_draft_validate_activate_is_audited(
    client, monkeypatch
):
    _cleanup_voice_state()
    settings = get_settings()
    monkeypatch.setattr(
        settings,
        "admin_email_allowlist",
        "owner@example.com",
        raising=False,
    )

    with Testing() as db:
        membership = db.scalar(
            select(Membership).where(
                Membership.tenant_id == "tenant-1",
                Membership.user_id == "user-1",
            )
        )
        membership.role = "superadmin"
        db.commit()

    catalog_id = _seed_catalog()

    try:
        draft = client.put(
            "/api/v2/admin/agents/orkio/voice-assignment",
            json={
                "voice_catalog_id": catalog_id,
                "locale": "pt-BR",
                "delivery_modes": ["REALTIME_STREAM", "MESSAGE_PLAYBACK"],
                "presentation_label": "NEUTRA",
            },
            headers=headers(),
        )
        assert draft.status_code == 200, draft.text
        body = draft.json()
        assert body["assignment_state"] == "DRAFT"
        assert body["validation_status"] == "UNVALIDATED"
        assignment_id = body["id"]

        premature = client.post(
            f"/api/v2/admin/agent-voice-assignments/{assignment_id}/activation",
            json={"evidence_ref": "approval://before-validation"},
            headers=headers(),
        )
        assert premature.status_code == 409
        assert premature.json()["detail"] == "VOICE_ASSIGNMENT_NOT_VALIDATED"

        validated = client.post(
            f"/api/v2/admin/agent-voice-assignments/{assignment_id}/validation",
            json={
                "validation_status": "VALIDATED",
                "evidence_ref": "smoke://voice-r2-reviewed",
            },
            headers=headers(),
        )
        assert validated.status_code == 200, validated.text
        assert validated.json()["assignment_state"] == "DRAFT"
        assert validated.json()["validation_status"] == "VALIDATED"

        activated = client.post(
            f"/api/v2/admin/agent-voice-assignments/{assignment_id}/activation",
            json={"evidence_ref": "approval://human-reviewed-r2"},
            headers=headers(),
        )
        assert activated.status_code == 200, activated.text
        assert activated.json()["assignment_state"] == "ACTIVE"
        assert activated.json()["validation_status"] == "VALIDATED"

        with Testing() as db:
            row = db.get(AgentVoiceAssignment, assignment_id)
            assert row is not None
            assert row.assignment_state == "ACTIVE"
            assert row.validation_status == "VALIDATED"

            events = db.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.resource_type == "agent_voice_assignment",
                    AuditEvent.resource_id == assignment_id,
                )
                .order_by(AuditEvent.created_at)
            ).all()
            actions = [event.action for event in events]
            assert "ADMIN_AGENT_VOICE_ASSIGNMENT_DRAFT" in actions
            assert "ADMIN_AGENT_VOICE_ASSIGNMENT_VALIDATION" in actions
            assert "ADMIN_AGENT_VOICE_ASSIGNMENT_ACTIVATED" in actions

            validation_event = next(
                event
                for event in events
                if event.action == "ADMIN_AGENT_VOICE_ASSIGNMENT_VALIDATION"
            )
            assert (
                validation_event.metadata_json["evidence_ref"]
                == "smoke://voice-r2-reviewed"
            )
    finally:
        _cleanup_voice_state()


def test_r2_catalog_assignment_is_tenant_scoped_and_overrides_env(monkeypatch):
    _cleanup_voice_state()
    settings = _configure_voice_runtime(monkeypatch)
    catalog_id = _seed_catalog()
    _seed_active_validated_assignment(catalog_id=catalog_id)

    try:
        with Testing() as db:
            tenant_profile = resolve_voice_profile(
                "orkio",
                "pt-BR",
                settings,
                delivery_mode="MESSAGE_PLAYBACK",
                db=db,
                tenant_id="tenant-1",
            )
            other_tenant_profile = resolve_voice_profile(
                "orkio",
                "pt-BR",
                settings,
                delivery_mode="MESSAGE_PLAYBACK",
                db=db,
                tenant_id="tenant-other",
            )

        assert tenant_profile.binding_id == "admin:assignment-r2"
        assert tenant_profile.voice_id == "catalog-voice-r2"
        assert other_tenant_profile.binding_id == "voice_binding::orkio"
        assert other_tenant_profile.voice_id == "env-voice"
    finally:
        _cleanup_voice_state()


def test_r2_message_tts_uses_tenant_catalog_assignment(
    client, monkeypatch, tmp_path
):
    _cleanup_voice_state()
    settings = _configure_voice_runtime(monkeypatch)
    monkeypatch.setattr(
        settings,
        "tts_cache_path",
        str(tmp_path / "r2-tts-cache"),
        raising=False,
    )
    catalog_id = _seed_catalog()
    _seed_active_validated_assignment(catalog_id=catalog_id)

    try:
        thread_id = client.post(
            "/api/v2/threads",
            json={},
            headers=headers(),
        ).json()["id"]

        with Testing() as db:
            row = Message(
                tenant_id="tenant-1",
                thread_id=thread_id,
                author_type="agent",
                author_id="orkio",
                agent_name="Josué",
                content="Resposta usando voz curada R2.",
            )
            db.add(row)
            db.commit()
            message_id = row.id

        async def fake_synth(_settings, profile, text, *, request_id):
            assert profile.binding_id == "admin:assignment-r2"
            assert profile.voice_id == "catalog-voice-r2"
            assert text == "Resposta usando voz curada R2."
            return b"ID3-r2"

        monkeypatch.setattr(
            "orkio_v2.tts_routes.synthesize_speech",
            fake_synth,
        )

        response = client.post(
            f"/api/v2/threads/{thread_id}/messages/{message_id}/voice",
            json={"locale": "pt-BR"},
            headers={**headers(), "X-Request-Id": "r2-tts-catalog-1"},
        )
        assert response.status_code == 200, response.text
        assert response.headers["x-orkio-voice-binding-id"] == "admin:assignment-r2"
        assert response.content == b"ID3-r2"
    finally:
        _cleanup_voice_state()


def test_r2_realtime_call_passes_db_and_tenant_to_voice_resolver(
    client, monkeypatch
):
    settings = _configure_voice_runtime(monkeypatch)
    calls = []

    def fake_resolve(agent_id, locale, _settings, **kwargs):
        calls.append(
            {
                "agent_id": agent_id,
                "locale": locale,
                "db": kwargs.get("db"),
                "tenant_id": kwargs.get("tenant_id"),
                "delivery_mode": kwargs.get("delivery_mode"),
            }
        )
        return _catalog_profile()

    async def fake_call(**kwargs):
        return RealtimeCallResult(
            sdp_answer="v=0\r\nanswer\r\n",
            call_id="call-r2",
            model="gpt-realtime",
            output_modalities=("text",),
        )

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.resolve_voice_profile",
        fake_resolve,
    )
    monkeypatch.setattr(
        "orkio_v2.realtime_routes.create_realtime_call",
        fake_call,
    )

    thread_id = client.post(
        "/api/v2/threads",
        json={},
        headers=headers(),
    ).json()["id"]

    response = client.post(
        f"/api/v2/threads/{thread_id}/realtime/calls",
        json={
            "sdp": "v=0\r\no=- 1 1 IN IP4 127.0.0.1",
            "agent": "Josué",
            "locale": "pt-BR",
        },
        headers=headers(),
    )
    assert response.status_code == 200, response.text
    assert calls
    assert calls[-1]["agent_id"] == "orkio"
    assert calls[-1]["tenant_id"] == "tenant-1"
    assert calls[-1]["db"] is not None
    assert calls[-1]["delivery_mode"] == "REALTIME_STREAM"


def test_r2_realtime_stream_passes_db_tenant_and_ends_done(
    client, monkeypatch
):
    _configure_voice_runtime(monkeypatch)
    calls = []

    def fake_resolve(agent_id, locale, _settings, **kwargs):
        calls.append(
            {
                "agent_id": agent_id,
                "db": kwargs.get("db"),
                "tenant_id": kwargs.get("tenant_id"),
                "delivery_mode": kwargs.get("delivery_mode"),
            }
        )
        return _catalog_profile()

    async def fake_call(**kwargs):
        return RealtimeCallResult(
            sdp_answer="v=0\r\nanswer\r\n",
            call_id="call-r2-stream",
            model="gpt-realtime",
            output_modalities=("text",),
        )

    async def fake_stream(*args, **kwargs):
        yield {
            "type": "turn_started",
            "turn_id": "turn-r2",
            "execution_id": "exec-r2",
            "agent_id": "orkio",
        }
        yield {
            "type": "text_delta",
            "turn_id": "turn-r2",
            "execution_id": "exec-r2",
            "agent_id": "orkio",
            "delta": "Olá",
        }
        yield {
            "type": "done",
            "turn_id": "turn-r2",
            "message_id": "message-r2",
            "execution_id": "exec-r2",
            "agent_id": "orkio",
        }

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.resolve_voice_profile",
        fake_resolve,
    )
    monkeypatch.setattr(
        "orkio_v2.realtime_routes.create_realtime_call",
        fake_call,
    )
    monkeypatch.setattr(
        "orkio_v2.realtime_routes.stream_realtime_direct",
        fake_stream,
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

    response = client.post(
        f"/api/v2/threads/{thread_id}/realtime/turns/stream",
        json={
            "session_id": session_id,
            "provider_item_id": "provider-item-r2",
            "transcript_final_id": "transcript-final-r2",
            "transcript": "Pergunta por voz",
            "locale": "pt-BR",
        },
        headers=headers(),
    )
    assert response.status_code == 200, response.text
    assert "event: turn_started" in response.text
    assert "event: text_delta" in response.text
    assert "event: done" in response.text

    assert len(calls) >= 2
    stream_call = calls[-1]
    assert stream_call["tenant_id"] == "tenant-1"
    assert stream_call["db"] is not None
    assert stream_call["delivery_mode"] == "REALTIME_STREAM"
