from types import SimpleNamespace
from unittest.mock import patch

import pytest

from orkio_v2.services import realtime_execution


@pytest.mark.asyncio
async def test_stream_realtime_direct_emits_segments_before_terminal_commit():
    turn = SimpleNamespace(
        execution_id="turn-1",
        request_id="request-1",
        turn_owner_agent_id="orkio",
        display_agent_name="Co-Criador",
    )
    decision = SimpleNamespace(execution=SimpleNamespace())
    row = SimpleNamespace(id="message-1", content="Olá, mundo. Segundo trecho.")
    settings = SimpleNamespace(internal_agent_consultation_enabled=False)
    emitted = []

    async def fake_llm_stream(*_args):
        for piece in ("Olá, ", "mundo. ", "Segundo trecho."):
            yield piece

    with (
        patch.object(realtime_execution, "resolve_direct_target_decision", return_value=decision),
        patch.object(realtime_execution, "build_direct_turn", return_value=turn),
        patch.object(realtime_execution, "persist_user_message"),
        patch.object(realtime_execution, "team_history", return_value=[]),
        patch.object(
            realtime_execution,
            "profile_for",
            return_value=SimpleNamespace(co_creator_name=None, onboarding_goal=None),
        ),
        patch.object(realtime_execution, "hyper_cocreator_system_message", return_value={"role": "system"}),
        patch.object(realtime_execution.llm, "stream", fake_llm_stream),
        patch.object(realtime_execution, "persist_agent_response", return_value=(row, object())),
        patch.object(realtime_execution, "envelope_payload", return_value={}),
    ):
        async for item in realtime_execution.stream_realtime_direct(
            object(),
            settings=settings,
            tenant_id="tenant-1",
            user_id="user-1",
            thread_id="thread-1",
            agent_id="orkio",
            transcript="Olá",
        ):
            emitted.append(item)

    types = [item["type"] for item in emitted]
    assert types[0] == "turn_started"
    assert types.count("text_delta") == 3
    assert types.count("segment_ready") == 2
    assert types[-1] == "done"
    assert emitted[-1]["message_id"] == "message-1"
