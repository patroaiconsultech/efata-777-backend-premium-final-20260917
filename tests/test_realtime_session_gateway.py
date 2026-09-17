from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import select

from conftest import Testing, headers
from orkio_v2.config import get_settings
from orkio_v2.models import AuditEvent
from orkio_v2.runtime.contracts import RuntimeChannel
from orkio_v2.services.direct_runtime import build_turn
from orkio_v2.services.execution_router import resolve_direct_target_decision
from orkio_v2.services.realtime_session import (
    RealtimeSessionError,
    _transcription_language,
    create_realtime_call,
    realtime_capability,
)
from orkio_v2.services.voice_binding import VoiceBindingError


def _configured(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "voice_enabled", True, raising=False)
    monkeypatch.setattr(settings, "voice_provider", "openai", raising=False)
    monkeypatch.setattr(settings, "openai_api_key", "test-realtime-key-not-real", raising=False)
    return settings


def test_realtime_capability_is_fail_closed_by_default(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "voice_enabled", False, raising=False)
    monkeypatch.setattr(settings, "voice_provider", "disabled", raising=False)
    monkeypatch.setattr(settings, "openai_api_key", None, raising=False)
    cap = realtime_capability(settings)
    assert cap["text_streaming"]["eligible"] is True
    assert cap["realtime_session"]["eligible"] is False
    assert cap["realtime_session"]["reason_code"] == "REALTIME_VOICE_DISABLED"
    assert cap["voice_input"]["eligible"] is False
    assert cap["voice_output"]["eligible"] is False
    assert cap["interruption"]["eligible"] is False
    assert cap["turn_detection"]["eligible"] is False
    assert cap["orchestration_bridge"]["eligible"] is False


def test_realtime_signaling_can_be_configured_without_claiming_runtime_or_voice_ready(monkeypatch):
    settings = _configured(monkeypatch)
    cap = realtime_capability(settings)
    assert cap["realtime_session"]["status"] == "CONFIGURED"
    assert cap["realtime_session"]["eligible"] is True
    assert cap["realtime_session"]["runtime_proven"] is False
    assert cap["realtime_session"]["output_modalities"] == ["text"]
    assert cap["voice_input"]["eligible"] is False
    assert cap["voice_output"]["eligible"] is False
    assert cap["orchestration_bridge"]["status"] == "NOT_IMPLEMENTED"


def test_realtime_capabilities_endpoint_requires_authorization(client):
    response = client.get("/api/v2/realtime/capabilities")
    assert response.status_code in {401, 403}


def test_realtime_capabilities_endpoint_is_sanitized(client, monkeypatch):
    settings = _configured(monkeypatch)
    response = client.get("/api/v2/realtime/capabilities", headers=headers())
    assert response.status_code == 200
    raw = response.text
    assert "test-realtime-key-not-real" not in raw
    assert "Authorization" not in raw
    assert response.json()["orchestration_bridge"]["eligible"] is False


@pytest.mark.asyncio
async def test_realtime_session_creation_keeps_provider_key_server_side(monkeypatch):
    settings = _configured(monkeypatch)
    decision = resolve_direct_target_decision("Joseph", settings)
    turn = build_turn(
        execution=decision.execution,
        thread_id="thread-1",
        tenant_id="tenant-1",
        user_id="user-1",
        requested_target="Joseph",
        channel=RuntimeChannel.REALTIME,
    )
    captured = {}

    class FakeResponse:
        text = "v=0\\r\\nanswer"
        headers = {"Location": "https://api.openai.com/v1/realtime/calls/call_123"}

        def raise_for_status(self):
            return None

    class FakeClient:
        def __init__(self, *args, **kwargs):
            captured["timeout"] = kwargs.get("timeout")

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, endpoint, *, headers, files):
            captured["endpoint"] = endpoint
            captured["headers"] = dict(headers)
            captured["files"] = files
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    result = await create_realtime_call(
        settings=settings,
        turn=turn,
        sdp_offer="v=0\\r\\no=- 1 1 IN IP4 127.0.0.1",
    )
    assert result.call_id == "call_123"
    assert result.model == "gpt-realtime"
    assert result.output_modalities == ("text",)
    assert captured["headers"]["Authorization"] == "Bearer test-realtime-key-not-real"
    session_json = json.loads(captured["files"]["session"][1])
    assert session_json["output_modalities"] == ["text"]
    assert session_json["tools"] == []
    assert session_json["audio"]["input"]["transcription"] == {
        "model": settings.realtime_transcription_model,
        "language": "pt",
    }
    assert "test-realtime-key-not-real" not in json.dumps(session_json)
    assert result.sdp_answer == "v=0\\r\\nanswer" + "\r\n"



@pytest.mark.asyncio
async def test_realtime_sdp_terminal_line_break_is_preserved(monkeypatch):
    settings = _configured(monkeypatch)
    decision = resolve_direct_target_decision("Joseph", settings)
    turn = build_turn(
        execution=decision.execution,
        thread_id="thread-1",
        tenant_id="tenant-1",
        user_id="user-1",
        requested_target="Joseph",
        channel=RuntimeChannel.REALTIME,
    )

    class FakeResponse:
        text = "v=0\r\na=ice-pwd:synthetic\r\n"
        headers = {"Location": "https://api.openai.com/v1/realtime/calls/call_123"}

        def raise_for_status(self):
            return None

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    result = await create_realtime_call(
        settings=settings,
        turn=turn,
        sdp_offer="v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n",
    )
    assert result.sdp_answer == FakeResponse.text
    assert result.sdp_answer.endswith("\r\n")


@pytest.mark.asyncio
async def test_realtime_sdp_missing_terminal_line_break_is_normalized(monkeypatch):
    settings = _configured(monkeypatch)
    decision = resolve_direct_target_decision("Joseph", settings)
    turn = build_turn(
        execution=decision.execution,
        thread_id="thread-1",
        tenant_id="tenant-1",
        user_id="user-1",
        requested_target="Joseph",
        channel=RuntimeChannel.REALTIME,
    )

    class FakeResponse:
        text = "v=0\r\na=ice-pwd:synthetic"
        headers = {"Location": "https://api.openai.com/v1/realtime/calls/call_123"}

        def raise_for_status(self):
            return None

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    result = await create_realtime_call(
        settings=settings,
        turn=turn,
        sdp_offer="v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n",
    )
    assert result.sdp_answer == FakeResponse.text + "\r\n"
    assert result.sdp_answer.endswith("\r\n")


@pytest.mark.asyncio
async def test_realtime_sdp_whitespace_only_answer_is_rejected(monkeypatch):
    settings = _configured(monkeypatch)
    decision = resolve_direct_target_decision("Joseph", settings)
    turn = build_turn(
        execution=decision.execution,
        thread_id="thread-1",
        tenant_id="tenant-1",
        user_id="user-1",
        requested_target="Joseph",
        channel=RuntimeChannel.REALTIME,
    )

    class FakeResponse:
        text = " \r\n\t "
        headers = {}

        def raise_for_status(self):
            return None

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    with pytest.raises(RealtimeSessionError) as exc:
        await create_realtime_call(
            settings=settings,
            turn=turn,
            sdp_offer="v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n",
        )
    assert exc.value.code == "REALTIME_SDP_ANSWER_EMPTY"


def test_realtime_route_is_fail_closed_when_voice_disabled(client, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "voice_enabled", False, raising=False)
    monkeypatch.setattr(settings, "voice_provider", "disabled", raising=False)
    monkeypatch.setattr(settings, "openai_api_key", None, raising=False)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/realtime/calls",
        json={
            "sdp": "v=0\\r\\no=- 1 1 IN IP4 127.0.0.1",
            "agent": "Joseph",
        },
        headers=headers(),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "REALTIME_VOICE_DISABLED"

    with Testing() as db:
        rows = db.scalars(select(AuditEvent)).all()
    actions = [
        row.action
        for row in rows
        if isinstance(row.metadata_json, dict)
        and row.metadata_json.get("thread_id") == thread["id"]
    ]
    assert "realtime_requested" in actions
    assert "realtime_authorized" in actions
    assert "realtime_failed" in actions



def test_realtime_route_stays_fail_closed_when_signaling_is_configured_but_bridge_is_missing(
    client, monkeypatch
):
    _configured(monkeypatch)

    async def must_not_create(*args, **kwargs):
        pytest.fail("provider session must not be created before ORKIO orchestration bridge is eligible")

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.create_realtime_call",
        must_not_create,
    )
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/realtime/calls",
        json={
            "sdp": "v=0\\r\\no=- 1 1 IN IP4 127.0.0.1",
            "agent": "Joseph",
        },
        headers=headers(),
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "REALTIME_ORCHESTRATION_BRIDGE_REQUIRED"


def test_realtime_route_rejects_cross_tenant_before_provider(client, monkeypatch):
    _configured(monkeypatch)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/realtime/calls",
        json={
            "sdp": "v=0\\r\\no=- 1 1 IN IP4 127.0.0.1",
            "agent": "Joseph",
        },
        headers=headers(tenant="tenant-other"),
    )
    assert response.status_code in {401, 403, 404}


@pytest.mark.asyncio
async def test_realtime_upstream_failure_is_sanitized(monkeypatch):
    settings = _configured(monkeypatch)
    decision = resolve_direct_target_decision("Joseph", settings)
    turn = build_turn(
        execution=decision.execution,
        thread_id="thread-1",
        tenant_id="tenant-1",
        user_id="user-1",
        requested_target="Joseph",
        channel=RuntimeChannel.REALTIME,
    )

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc, tb):
            return False
        async def post(self, *args, **kwargs):
            raise RuntimeError("provider exploded with synthetic secret")

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    with pytest.raises(RealtimeSessionError) as exc:
        await create_realtime_call(
            settings=settings,
            turn=turn,
            sdp_offer="v=0\\r\\no=- 1 1 IN IP4 127.0.0.1",
        )
    assert exc.value.code == "REALTIME_UPSTREAM_UNAVAILABLE"
    assert "synthetic secret" not in str(exc.value)


def test_realtime_service_source_never_serializes_openai_key():
    source = (
        __import__("pathlib").Path(__file__).parents[1]
        / "src/orkio_v2/services/realtime_session.py"
    ).read_text(encoding="utf-8")
    assert '"openai_api_key":' not in source
    assert "'openai_api_key':" not in source
    assert "Authorization" in source  # server-side provider request is intentional



def _call_capability(
    *,
    session_eligible: bool = True,
    bridge_eligible: bool = True,
    voice_output_eligible: bool = True,
):
    return {
        "realtime_session": {
            "eligible": session_eligible,
            "reason_code": (
                "REALTIME_SIGNALING_CONFIGURED_NOT_RUNTIME_PROVEN"
                if session_eligible
                else "REALTIME_VOICE_DISABLED"
            ),
        },
        "orchestration_bridge": {
            "eligible": bridge_eligible,
            "reason_code": (
                "REALTIME_CANONICAL_BRIDGE_CONFIGURED_NOT_RUNTIME_PROVEN"
                if bridge_eligible
                else "REALTIME_ORCHESTRATION_BRIDGE_REQUIRED"
            ),
        },
        "voice_output": {
            "eligible": voice_output_eligible,
            "reason_code": (
                "CANONICAL_MESSAGE_TTS_CONFIGURED_NOT_RUNTIME_PROVEN"
                if voice_output_eligible
                else "AGENT_VOICE_BINDING_NOT_VALIDATED"
            ),
        },
    }


def _capture_call_failures(monkeypatch):
    captured = []

    def capture(**kwargs):
        captured.append(dict(kwargs))

    monkeypatch.setattr(
        "orkio_v2.realtime_routes._log_realtime_call_failure",
        capture,
    )
    return captured


def _thread_audits(thread_id):
    with Testing() as db:
        rows = db.scalars(select(AuditEvent)).all()
    return [
        row
        for row in rows
        if isinstance(row.metadata_json, dict)
        and row.metadata_json.get("thread_id") == thread_id
    ]


def test_realtime_call_failure_log_is_structured_and_sanitized(monkeypatch):
    import orkio_v2.realtime_routes as realtime_routes

    settings = _configured(monkeypatch)
    decision = resolve_direct_target_decision("Joseph", settings)
    turn = build_turn(
        execution=decision.execution,
        thread_id="thread-log-test",
        tenant_id="tenant-1",
        user_id="user-1",
        requested_target="Joseph",
        channel=RuntimeChannel.REALTIME,
    )

    rendered = []

    def capture_error(message, *args, **kwargs):
        del kwargs
        rendered.append(message % args if args else message)

    monkeypatch.setattr(
        realtime_routes.realtime_logger,
        "error",
        capture_error,
    )

    realtime_routes._log_realtime_call_failure(
        settings=settings,
        turn=turn,
        target_mode="direct",
        locale="pt-BR",
        stage="provider_call",
        error_code="REALTIME_UPSTREAM_UNAVAILABLE",
        exception_type="RealtimeSessionError",
    )

    assert len(rendered) == 1
    assert rendered[0].startswith("REALTIME_CALL_FAILURE ")

    payload = json.loads(
        rendered[0].removeprefix("REALTIME_CALL_FAILURE ")
    )

    assert payload["request_id"] == turn.request_id
    assert payload["execution_id"] == turn.execution_id
    assert payload["thread_id"] == turn.thread_id
    assert payload["tenant_id"] == turn.tenant_id
    assert payload["user_id"] == turn.user_id
    assert payload["turn_owner"] == turn.turn_owner_agent_id
    assert payload["stage"] == "provider_call"
    assert payload["error_code"] == "REALTIME_UPSTREAM_UNAVAILABLE"
    assert payload["pipeline"] == "realtime_call_setup"
    assert payload["status"] == "failed"

    raw = json.dumps(payload)
    assert "test-realtime-key-not-real" not in raw

    forbidden = {
        "sdp",
        "authorization",
        "token",
        "secret",
        "prompt",
        "transcript",
        "content",
    }
    assert forbidden.isdisjoint({key.casefold() for key in payload})


def test_realtime_session_capability_failure_is_observable(
    client, monkeypatch
):
    settings = get_settings()
    monkeypatch.setattr(settings, "voice_enabled", False, raising=False)
    monkeypatch.setattr(settings, "voice_provider", "disabled", raising=False)
    monkeypatch.setattr(settings, "openai_api_key", None, raising=False)

    failures = _capture_call_failures(monkeypatch)

    thread = client.post(
        "/api/v2/threads",
        json={},
        headers=headers(),
    ).json()

    response = client.post(
        f"/api/v2/threads/{thread['id']}/realtime/calls",
        json={
            "sdp": "v=0\\r\\no=- 1 1 IN IP4 127.0.0.1",
            "agent": "Joseph",
        },
        headers=headers(),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "REALTIME_VOICE_DISABLED"

    assert len(failures) == 1
    failure = failures[0]
    assert failure["stage"] == "realtime_session_capability"
    assert failure["error_code"] == "REALTIME_VOICE_DISABLED"
    assert failure["turn"].request_id
    assert failure["turn"].execution_id

    failed_audits = [
        row for row in _thread_audits(thread["id"])
        if row.action == "realtime_failed"
    ]
    assert len(failed_audits) == 1
    metadata = failed_audits[0].metadata_json
    assert metadata["stage"] == "realtime_session_capability"
    assert metadata["request_id"] == failure["turn"].request_id
    assert metadata["execution_id"] == failure["turn"].execution_id


def test_realtime_bridge_failure_is_observable(
    client, monkeypatch
):
    _configured(monkeypatch)
    failures = _capture_call_failures(monkeypatch)

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.realtime_capability",
        lambda settings: _call_capability(
            session_eligible=True,
            bridge_eligible=False,
            voice_output_eligible=False,
        ),
    )

    async def must_not_create(*args, **kwargs):
        pytest.fail(
            "provider session must not be created before bridge eligibility"
        )

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.create_realtime_call",
        must_not_create,
    )

    thread = client.post(
        "/api/v2/threads",
        json={},
        headers=headers(),
    ).json()

    response = client.post(
        f"/api/v2/threads/{thread['id']}/realtime/calls",
        json={
            "sdp": "v=0\\r\\no=- 1 1 IN IP4 127.0.0.1",
            "agent": "Joseph",
        },
        headers=headers(),
    )

    assert response.status_code == 503
    assert (
        response.json()["detail"]
        == "REALTIME_ORCHESTRATION_BRIDGE_REQUIRED"
    )

    assert len(failures) == 1
    failure = failures[0]
    assert failure["stage"] == "orchestration_bridge"
    assert (
        failure["error_code"]
        == "REALTIME_ORCHESTRATION_BRIDGE_REQUIRED"
    )

    failed_audits = [
        row for row in _thread_audits(thread["id"])
        if row.action == "realtime_failed"
    ]
    assert len(failed_audits) == 1
    assert (
        failed_audits[0].metadata_json["stage"]
        == "orchestration_bridge"
    )
    assert (
        failed_audits[0].metadata_json["request_id"]
        == failure["turn"].request_id
    )


def test_realtime_voice_output_failure_is_observable_without_new_failed_audit(
    client, monkeypatch
):
    _configured(monkeypatch)
    failures = _capture_call_failures(monkeypatch)

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.realtime_capability",
        lambda settings: _call_capability(
            session_eligible=True,
            bridge_eligible=True,
            voice_output_eligible=False,
        ),
    )

    def must_not_resolve(*args, **kwargs):
        pytest.fail(
            "voice binding must not be resolved before voice output eligibility"
        )

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.resolve_voice_profile",
        must_not_resolve,
    )

    thread = client.post(
        "/api/v2/threads",
        json={},
        headers=headers(),
    ).json()

    response = client.post(
        f"/api/v2/threads/{thread['id']}/realtime/calls",
        json={
            "sdp": "v=0\\r\\no=- 1 1 IN IP4 127.0.0.1",
            "agent": "Joseph",
        },
        headers=headers(),
    )

    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "REALTIME_VOICE_OUTPUT_REQUIRED"
    }

    assert len(failures) == 1
    assert failures[0]["stage"] == "voice_output_capability"
    assert (
        failures[0]["error_code"]
        == "REALTIME_VOICE_OUTPUT_REQUIRED"
    )

    failed_audits = [
        row for row in _thread_audits(thread["id"])
        if row.action == "realtime_failed"
    ]
    assert failed_audits == []


def test_realtime_voice_binding_failure_is_observable_without_new_failed_audit(
    client, monkeypatch
):
    _configured(monkeypatch)
    failures = _capture_call_failures(monkeypatch)

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.realtime_capability",
        lambda settings: _call_capability(),
    )

    def fail_binding(*args, **kwargs):
        raise VoiceBindingError("VOICE_BINDING_NOT_FOUND")

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.resolve_voice_profile",
        fail_binding,
    )

    async def must_not_create(*args, **kwargs):
        pytest.fail(
            "provider call must not occur after voice binding failure"
        )

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.create_realtime_call",
        must_not_create,
    )

    thread = client.post(
        "/api/v2/threads",
        json={},
        headers=headers(),
    ).json()

    response = client.post(
        f"/api/v2/threads/{thread['id']}/realtime/calls",
        json={
            "sdp": "v=0\\r\\no=- 1 1 IN IP4 127.0.0.1",
            "agent": "Joseph",
        },
        headers=headers(),
    )

    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "VOICE_BINDING_NOT_FOUND"
    }

    assert len(failures) == 1
    assert failures[0]["stage"] == "voice_binding"
    assert failures[0]["error_code"] == "VOICE_BINDING_NOT_FOUND"

    failed_audits = [
        row for row in _thread_audits(thread["id"])
        if row.action == "realtime_failed"
    ]
    assert failed_audits == []


def test_realtime_provider_failure_is_observable_and_preserves_contract(
    client, monkeypatch
):
    _configured(monkeypatch)
    failures = _capture_call_failures(monkeypatch)

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.realtime_capability",
        lambda settings: _call_capability(),
    )

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.resolve_voice_profile",
        lambda *args, **kwargs: object(),
    )

    provider_call = {}

    async def fail_provider(*args, **kwargs):
        provider_call.update(kwargs)
        raise RealtimeSessionError("REALTIME_UPSTREAM_UNAVAILABLE")

    monkeypatch.setattr(
        "orkio_v2.realtime_routes.create_realtime_call",
        fail_provider,
    )

    thread = client.post(
        "/api/v2/threads",
        json={},
        headers=headers(),
    ).json()

    response = client.post(
        f"/api/v2/threads/{thread['id']}/realtime/calls",
        json={
            "sdp": "v=0\\r\\no=- 1 1 IN IP4 127.0.0.1",
            "agent": "Joseph",
            "locale": "es-419",
        },
        headers=headers(),
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "REALTIME_UPSTREAM_UNAVAILABLE"
    assert provider_call["locale"] == "es-419"

    assert len(failures) == 1
    failure = failures[0]
    assert failure["stage"] == "provider_call"
    assert failure["error_code"] == "REALTIME_UPSTREAM_UNAVAILABLE"
    assert failure["exception_type"] == "RealtimeSessionError"

    failed_audits = [
        row for row in _thread_audits(thread["id"])
        if row.action == "realtime_failed"
    ]
    assert len(failed_audits) == 1

    metadata = failed_audits[0].metadata_json
    assert metadata["stage"] == "provider_call"
    assert metadata["request_id"] == failure["turn"].request_id
    assert metadata["execution_id"] == failure["turn"].execution_id


@pytest.mark.parametrize(
    ("locale", "language"),
    [
        ("pt-BR", "pt"),
        ("en-US", "en"),
        ("es-419", "es"),
    ],
)
def test_realtime_transcription_language_maps_supported_locales(locale, language):
    assert _transcription_language(locale) == language


def test_realtime_transcription_language_rejects_unknown_locale():
    with pytest.raises(RealtimeSessionError) as exc:
        _transcription_language("fr-FR")

    assert exc.value.code == "REALTIME_LOCALE_NOT_SUPPORTED"
