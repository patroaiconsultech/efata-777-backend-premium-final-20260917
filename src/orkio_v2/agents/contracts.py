from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping


class TargetKind(StrEnum):
    AGENT = "agent"


class ExecutionEngine(StrEnum):
    DIRECT_AGENT = "direct_agent"


@dataclass(frozen=True, slots=True)
class AgentDefinition:
    """Runtime projection of one governed catalog agent.

    `slug` is the durable technical agent_id.
    Human/localized names are presentation/resolution metadata and never become
    authorization or ownership identifiers.
    """
    slug: str
    display_name: str
    system_instruction: str
    target_kind: TargetKind = TargetKind.AGENT
    enabled: bool = True
    canonical_name: str = ""
    role_code: str = ""
    role_label: str = ""
    organizational_level: str = ""
    department: str = ""
    reports_to: str | None = None
    specialties: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    localized_names: Mapping[str, str] = field(default_factory=dict)
    localized_role_labels: Mapping[str, str] = field(default_factory=dict)
    founder_direct_access: bool = False
    legacy_identity: str | None = None
    voice_binding_id: str | None = None
    catalog_version: str = ""


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    room_context: str
    requested_target: str
    resolved_target: str
    turn_owner: str
    display_agent: str
    execution_engine: ExecutionEngine
    orchestrator: str | None
    ownership_locked: bool
