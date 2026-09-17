
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping


class RuntimeEventType(StrEnum):
    STATUS = "status"
    EXECUTION = "execution"
    AGENT_STARTED = "agent_started"
    CHUNK = "chunk"
    AGENT_CHUNK = "agent_chunk"
    AGENT_DONE = "agent_done"
    ERROR = "error"
    DONE = "done"


@dataclass(frozen=True, slots=True)
class RuntimeEvent:
    event_type: RuntimeEventType
    execution_id: str
    sequence: int
    data: Mapping[str, object]


def terminal_events(
    *,
    execution_id: str,
    start_sequence: int,
    error_code: str | None = None,
) -> tuple[RuntimeEvent, ...]:
    if error_code:
        return (
            RuntimeEvent(
                RuntimeEventType.ERROR,
                execution_id,
                start_sequence,
                {"code": error_code},
            ),
            RuntimeEvent(
                RuntimeEventType.DONE,
                execution_id,
                start_sequence + 1,
                {"status": "failed"},
            ),
        )
    return (
        RuntimeEvent(
            RuntimeEventType.DONE,
            execution_id,
            start_sequence,
            {"status": "completed"},
        ),
    )


def validate_terminal_sequence(events: tuple[RuntimeEvent, ...]) -> None:
    if not events:
        raise ValueError("SSE_TERMINAL_EVENT_REQUIRED")
    done_positions = [
        index for index, event in enumerate(events)
        if event.event_type is RuntimeEventType.DONE
    ]
    if done_positions != [len(events) - 1]:
        raise ValueError("SSE_DONE_MUST_BE_UNIQUE_AND_LAST")
    for index, event in enumerate(events):
        if event.event_type is RuntimeEventType.ERROR and index >= done_positions[0]:
            raise ValueError("SSE_ERROR_MUST_PRECEDE_DONE")


def validate_runtime_sequence(events: tuple[RuntimeEvent, ...]) -> None:
    """Validate one canonical DIRECT SSE execution sequence.

    R0.4C keeps this in-memory: it proves ordering/correlation without
    introducing a database migration or claiming durable execution storage.
    """
    validate_terminal_sequence(events)
    execution_ids = {event.execution_id for event in events}
    if len(execution_ids) != 1:
        raise ValueError("SSE_EXECUTION_ID_MISMATCH")
    sequences = [event.sequence for event in events]
    if sequences != list(range(sequences[0], sequences[0] + len(sequences))):
        raise ValueError("SSE_SEQUENCE_MUST_BE_CONTIGUOUS")
