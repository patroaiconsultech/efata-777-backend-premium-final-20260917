
from __future__ import annotations

from dataclasses import fields, replace
from datetime import datetime, timezone

import pytest

from orkio_v2.services.execution_router import resolve_direct_execution
from orkio_v2.runtime.contracts import (
    CanonicalTurnContext,
    ContextContribution,
    RuntimeChannel,
)
from orkio_v2.runtime.events import RuntimeEventType, terminal_events, validate_terminal_sequence
from orkio_v2.runtime.identity import (
    OwnershipViolation,
    build_direct_turn_context,
    build_response_envelope,
    canonical_message,
    require_same_owner,
)
from orkio_v2.runtime.orchestration import (
    MAX_DELEGATION_DEPTH,
    AgentConsultRequest,
    ConsultReason,
    OrchestrationContractError,
    OrchestrationRun,
    add_consult,
    add_contribution,
)
from orkio_v2.runtime.realtime import (
    RealtimeIdentity,
    RealtimeIdentityError,
    realtime_identity_from_turn,
    validate_realtime_identity,
)


def direct(channel=RuntimeChannel.CHAT_JSON):
    execution = resolve_direct_execution("Bezalel")
    return build_direct_turn_context(
        execution=execution,
        thread_id="thread-1",
        tenant_id="tenant-1",
        user_id="user-1",
        requested_target="Bezalel",
        channel=channel,
        request_id="req-1",
        execution_id="exec-1",
    )


def test_direct_context_has_one_canonical_identity_and_lock():
    turn = direct()
    assert turn.requested_target == "Bezalel"
    assert turn.resolved_agent_id == "orion"
    assert turn.turn_owner_agent_id == "orion"
    assert turn.display_agent_id == "orion"
    assert turn.display_agent_name == "Bezalel — Chief Technology Officer"
    assert turn.ownership_locked is True
    assert turn.external_write_allowed is False


def test_locked_owner_cannot_be_replaced_by_context_agent():
    turn = direct()
    with pytest.raises(OwnershipViolation) as raised:
        require_same_owner(turn, "chris")
    assert str(raised.value) == "TURN_OWNER_IMMUTABLE"


def test_context_contribution_does_not_change_turn_owner():
    turn = direct()
    run = OrchestrationRun(turn=turn)
    contribution = ContextContribution(
        contribution_id="c1",
        execution_id=turn.execution_id,
        thread_id=turn.thread_id,
        tenant_id=turn.tenant_id,
        source_agent_id="chris",
        requested_by_agent_id="orion",
        target_turn_owner_agent_id="orion",
        purpose="finance_review",
        content="Contribuição auxiliar.",
        created_at=datetime.now(timezone.utc),
    )
    updated = add_contribution(run, contribution)
    assert updated.turn.turn_owner_agent_id == "orion"
    assert updated.contributions[0].source_agent_id == "chris"


def test_cross_tenant_contribution_fails_closed():
    turn = direct()
    run = OrchestrationRun(turn=turn)
    contribution = ContextContribution(
        contribution_id="c1",
        execution_id=turn.execution_id,
        thread_id=turn.thread_id,
        tenant_id="tenant-2",
        source_agent_id="chris",
        requested_by_agent_id="orion",
        target_turn_owner_agent_id="orion",
        purpose="review",
        content="x",
        created_at=datetime.now(timezone.utc),
    )
    with pytest.raises(OrchestrationContractError) as raised:
        add_contribution(run, contribution)
    assert str(raised.value) == "CONTRIBUTION_SCOPE_MISMATCH"


def test_cross_execution_contribution_fails_closed():
    turn = direct()
    run = OrchestrationRun(turn=turn)
    contribution = ContextContribution(
        contribution_id="c1",
        execution_id="other-exec",
        thread_id=turn.thread_id,
        tenant_id=turn.tenant_id,
        source_agent_id="chris",
        requested_by_agent_id="orion",
        target_turn_owner_agent_id="orion",
        purpose="review",
        content="x",
        created_at=datetime.now(timezone.utc),
    )
    with pytest.raises(OrchestrationContractError) as raised:
        add_contribution(run, contribution)
    assert str(raised.value) == "CONTRIBUTION_EXECUTION_MISMATCH"


def test_response_envelope_uses_owner_not_contributor():
    turn = direct()
    message = canonical_message(
        message_id="m1",
        context=turn,
        content="Resposta de Orion enriquecida por Chris.",
        created_at=datetime(2026, 8, 9, tzinfo=timezone.utc),
    )
    envelope = build_response_envelope(context=turn, message=message)
    assert envelope.agent_id == "orion"
    assert envelope.turn_owner_agent_id == "orion"
    assert envelope.final_speaker_agent_id == "orion"
    assert envelope.agent_name == "Bezalel — Chief Technology Officer"


def test_response_envelope_rejects_wrong_message_owner():
    turn = direct()
    message = canonical_message(message_id="m1", context=turn, content="x")
    poisoned = replace(message, agent_id="chris", agent_name="Chris")
    with pytest.raises(OwnershipViolation) as raised:
        build_response_envelope(context=turn, message=poisoned)
    assert str(raised.value) == "MESSAGE_OWNER_MISMATCH"


def test_success_terminal_sequence_is_exactly_done():
    events = terminal_events(execution_id="exec-1", start_sequence=7)
    validate_terminal_sequence(events)
    assert [event.event_type for event in events] == [RuntimeEventType.DONE]


def test_failure_terminal_sequence_is_error_then_done():
    events = terminal_events(
        execution_id="exec-1",
        start_sequence=7,
        error_code="UPSTREAM_ERROR",
    )
    validate_terminal_sequence(events)
    assert [event.event_type for event in events] == [
        RuntimeEventType.ERROR,
        RuntimeEventType.DONE,
    ]


def test_duplicate_done_is_rejected():
    good = terminal_events(execution_id="exec-1", start_sequence=1)
    with pytest.raises(ValueError) as raised:
        validate_terminal_sequence(good + good)
    assert str(raised.value) == "SSE_DONE_MUST_BE_UNIQUE_AND_LAST"


def test_consult_depth_is_limited_to_one():
    turn = direct()
    run = OrchestrationRun(turn=turn)
    request = AgentConsultRequest(
        consult_id="q1",
        execution_id=turn.execution_id,
        tenant_id=turn.tenant_id,
        thread_id=turn.thread_id,
        requester_agent_id="orion",
        turn_owner_agent_id="orion",
        capability="software_engineering",
        reason=ConsultReason.CAPABILITY_REQUIRED,
        target_agent_id="chris",
        delegation_depth=MAX_DELEGATION_DEPTH + 1,
    )
    with pytest.raises(OrchestrationContractError) as raised:
        add_consult(run, request)
    assert str(raised.value) == "DELEGATION_DEPTH_EXCEEDED"


def test_consult_is_bound_to_turn_owner():
    turn = direct()
    run = OrchestrationRun(turn=turn)
    request = AgentConsultRequest(
        consult_id="q1",
        execution_id=turn.execution_id,
        tenant_id=turn.tenant_id,
        thread_id=turn.thread_id,
        requester_agent_id="chris",
        turn_owner_agent_id="chris",
        capability="architecture",
        reason=ConsultReason.CROSS_DOMAIN_REVIEW,
        target_agent_id="orion",
    )
    with pytest.raises(OrchestrationContractError) as raised:
        add_consult(run, request)
    assert str(raised.value) == "CONSULT_OWNER_MISMATCH"


def test_realtime_identity_is_canonical_for_direct_turn():
    turn = direct(RuntimeChannel.REALTIME)
    identity = realtime_identity_from_turn(turn)
    assert identity.resolved_agent_id == "orion"
    assert identity.turn_owner_agent_id == "orion"
    assert identity.display_agent_id == "orion"
    assert identity.speaker_agent_id == "orion"


def test_realtime_wrong_speaker_fails_closed():
    identity = RealtimeIdentity(
        execution_id="exec-1",
        tenant_id="tenant-1",
        thread_id="thread-1",
        resolved_agent_id="orion",
        turn_owner_agent_id="orion",
        display_agent_id="orion",
        speaker_agent_id="chris",
        ownership_locked=True,
    )
    with pytest.raises(RealtimeIdentityError) as raised:
        validate_realtime_identity(identity)
    assert str(raised.value) == "REALTIME_SPEAKER_IDENTITY_MISMATCH"


def test_runtime_contracts_do_not_embed_auth_secrets_or_privilege_fields():
    forbidden = {
        "password",
        "token",
        "api_key",
        "secret",
        "rbac",
        "admin",
        "roles",
        "permissions",
    }
    for cls in (CanonicalTurnContext, ContextContribution):
        names = {field.name for field in fields(cls)}
        assert forbidden.isdisjoint(names)
