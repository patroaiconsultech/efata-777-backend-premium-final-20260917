from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agents.catalog import RAW_CATALOG
from ..agents.registry import AgentNotFound, resolve_agent_by_id
from ..models import AuditEvent, Message, Thread, ThreadParticipant, ThreadRole
from ..runtime.contracts import CanonicalTurnContext, RuntimeChannel, RuntimeRouteFamily
from ..runtime.identity import build_response_envelope, canonical_message
from .agent_availability import availability_for_id
from .direct_runtime import envelope_payload, history_item
from .document_context import document_context_message
from .platform_knowledge import system_capability_guard_message
from .knowledge_retrieval import knowledge_context_messages



MAX_TEAM_CONTRIBUTORS = 8
MIN_TEAM_CONTRIBUTORS = 2

# Compatibility aliases for pre-v1.1 callers/tests. New code uses contributor terminology.
MAX_TEAM_PARTICIPANTS = MAX_TEAM_CONTRIBUTORS
MIN_TEAM_PARTICIPANTS = MIN_TEAM_CONTRIBUTORS

TEAM_ALLOWED_THREAD_ROLES = {
    ThreadRole.owner.value,
    ThreadRole.moderator.value,
    ThreadRole.participant.value,
}


class TeamContractError(ValueError):
    def __init__(self, code: str, *, agent_id: str | None = None):
        super().__init__(code)
        self.code = code
        self.agent_id = agent_id


@dataclass(frozen=True, slots=True)
class TeamDefinition:
    team_id: str
    display_name: str
    orchestrator_agent_id: str
    candidate_agent_ids: tuple[str, ...]
    enabled: bool
    max_delegation_depth: int

    @property
    def candidate_contributor_agent_ids(self) -> tuple[str, ...]:
        """Specialist contributors only; the canonical chair is never a contributor."""
        return tuple(
            agent_id
            for agent_id in self.candidate_agent_ids
            if agent_id != self.orchestrator_agent_id
        )


@dataclass(frozen=True, slots=True)
class TeamPlan:
    definition: TeamDefinition
    orchestrator_agent_id: str
    contributor_agent_ids: tuple[str, ...]

    @property
    def participant_agent_ids(self) -> tuple[str, ...]:
        """Legacy projection used only for compatibility/UI migration."""
        return (self.orchestrator_agent_id, *self.contributor_agent_ids)


def _team_definitions() -> tuple[TeamDefinition, ...]:
    result: list[TeamDefinition] = []
    for row in RAW_CATALOG.get("teams") or []:
        chair = str(row.get("chair_agent_id") or row.get("orchestrator_agent_id") or "").strip()
        candidates = tuple(str(x).strip() for x in row.get("candidate_agent_ids") or () if str(x).strip())
        result.append(
            TeamDefinition(
                team_id=str(row.get("team_id") or "").strip(),
                display_name=str(row.get("display_name") or "").strip(),
                orchestrator_agent_id=chair,
                candidate_agent_ids=candidates,
                enabled=bool(row.get("enabled_in_catalog", False)),
                max_delegation_depth=int(row.get("max_delegation_depth") or 1),
            )
        )
    return tuple(result)


TEAM_DEFINITIONS = _team_definitions()
_TEAM_BY_ID = {item.team_id: item for item in TEAM_DEFINITIONS}


def list_team_definitions() -> tuple[TeamDefinition, ...]:
    return tuple(item for item in TEAM_DEFINITIONS if item.enabled)


def resolve_team_definition(team_id: str) -> TeamDefinition:
    item = _TEAM_BY_ID.get((team_id or "").strip())
    if item is None or not item.enabled:
        raise TeamContractError("TEAM_NOT_FOUND")
    return item


def _dedupe_contributors(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if not normalized:
            raise TeamContractError("TEAM_CONTRIBUTOR_ID_REQUIRED")
        if normalized in seen:
            raise TeamContractError("TEAM_DUPLICATE_CONTRIBUTOR", agent_id=normalized)
        seen.add(normalized)
        result.append(normalized)
    return tuple(result)


def _eligible_contributors(definition: TeamDefinition, settings) -> tuple[str, ...]:
    result: list[str] = []
    for agent_id in definition.candidate_contributor_agent_ids:
        try:
            resolve_agent_by_id(agent_id)
        except AgentNotFound:
            continue
        availability = availability_for_id(agent_id, settings)
        if availability.team.eligible:
            result.append(agent_id)
    return tuple(result)


def team_definition_payload(
    definition_or_id: TeamDefinition | str,
    settings,
) -> dict[str, object]:
    definition = (
        resolve_team_definition(definition_or_id)
        if isinstance(definition_or_id, str)
        else definition_or_id
    )
    candidates = definition.candidate_contributor_agent_ids
    eligible = _eligible_contributors(definition, settings)
    eligible_count = len(eligible)
    return {
        "team_id": definition.team_id,
        "display_name": definition.display_name,
        "orchestrator_agent_id": definition.orchestrator_agent_id,
        "candidate_contributor_agent_ids": list(candidates),
        # legacy field kept for one rolling-deploy window; still excludes chair in v1.1
        "candidate_agent_ids": list(candidates),
        "participant_policy": {
            "min_contributors": MIN_TEAM_CONTRIBUTORS,
            "max_contributors": MAX_TEAM_CONTRIBUTORS,
            "eligible_count": eligible_count,
            "select_all_supported": (
                MIN_TEAM_CONTRIBUTORS <= eligible_count <= MAX_TEAM_CONTRIBUTORS
            ),
        },
        "max_delegation_depth": definition.max_delegation_depth,
        "enabled": definition.enabled,
    }


def build_team_plan(
    *,
    team_id: str,
    settings,
    selection_mode: str = "explicit",
    contributor_agent_ids: Iterable[str] = (),
    # Legacy rollout compatibility. Neither field is authoritative in v1.1.
    orchestrator_agent_id: str | None = None,
    participant_agent_ids: Iterable[str] | None = None,
) -> TeamPlan:
    definition = resolve_team_definition(team_id)
    chair = definition.orchestrator_agent_id

    legacy_chair = str(orchestrator_agent_id or "").strip()
    if legacy_chair and legacy_chair != chair:
        raise TeamContractError("TEAM_ORCHESTRATOR_NOT_ALLOWED", agent_id=legacy_chair)

    normalized_mode = str(selection_mode or "explicit").strip().casefold()
    if normalized_mode not in {"explicit", "all_eligible"}:
        raise TeamContractError("TEAM_SELECTION_MODE_INVALID")

    if participant_agent_ids is not None:
        # Legacy clients used participant_agent_ids=[chair, specialists].
        # The chair is stripped server-side and never enters the contributor plan.
        if tuple(contributor_agent_ids):
            raise TeamContractError("TEAM_PARTICIPANT_PAYLOAD_AMBIGUOUS")
        legacy_values = tuple(str(x or "").strip() for x in participant_agent_ids)
        seen: set[str] = set()
        for value in legacy_values:
            if not value:
                raise TeamContractError("TEAM_PARTICIPANT_ID_REQUIRED")
            if value in seen:
                raise TeamContractError("TEAM_DUPLICATE_PARTICIPANT", agent_id=value)
            seen.add(value)
        contributor_values = tuple(value for value in legacy_values if value != chair)
    else:
        contributor_values = tuple(contributor_agent_ids)

    if normalized_mode == "all_eligible":
        if contributor_values:
            raise TeamContractError("TEAM_ALL_ELIGIBLE_WITH_EXPLICIT_CONTRIBUTORS")
        eligible = _eligible_contributors(definition, settings)
        if not (
            MIN_TEAM_CONTRIBUTORS <= len(eligible) <= MAX_TEAM_CONTRIBUTORS
        ):
            raise TeamContractError("TEAM_SELECT_ALL_NOT_SUPPORTED")
        contributors = eligible
    else:
        contributors = _dedupe_contributors(contributor_values)

    if chair in contributors:
        raise TeamContractError("TEAM_CHAIR_AS_CONTRIBUTOR_FORBIDDEN", agent_id=chair)
    if len(contributors) < MIN_TEAM_CONTRIBUTORS:
        # Contract v1.1 has one canonical minimum across every accepted request
        # family. Legacy payloads may retain legacy error vocabulary, but they
        # cannot weaken the number of real specialist contributors.
        code = (
            "TEAM_MIN_PARTICIPANTS_REQUIRED"
            if participant_agent_ids is not None
            else "TEAM_MIN_CONTRIBUTORS_REQUIRED"
        )
        raise TeamContractError(code)
    if len(contributors) > MAX_TEAM_CONTRIBUTORS:
        code = (
            "TEAM_MAX_PARTICIPANTS_EXCEEDED"
            if participant_agent_ids is not None
            else "TEAM_MAX_CONTRIBUTORS_EXCEEDED"
        )
        raise TeamContractError(code)

    allowed = set(definition.candidate_contributor_agent_ids)
    legacy_payload = participant_agent_ids is not None
    for agent_id in contributors:
        if agent_id not in allowed:
            raise TeamContractError(
                "TEAM_AGENT_NOT_ALLOWED" if legacy_payload else "TEAM_CONTRIBUTOR_NOT_ALLOWED",
                agent_id=agent_id,
            )
        try:
            resolve_agent_by_id(agent_id)
        except AgentNotFound as exc:
            raise TeamContractError(
                "TEAM_AGENT_NOT_FOUND" if legacy_payload else "TEAM_CONTRIBUTOR_NOT_FOUND",
                agent_id=agent_id,
            ) from exc
        availability = availability_for_id(agent_id, settings)
        if not availability.team.eligible:
            raise TeamContractError(
                availability.team.reason_code or "TEAM_CONTRIBUTOR_UNAVAILABLE",
                agent_id=agent_id,
            )

    return TeamPlan(
        definition=definition,
        orchestrator_agent_id=chair,
        contributor_agent_ids=contributors,
    )


def assert_team_thread_access(db: Session, *, thread_id: str, principal):
    thread = db.get(Thread, thread_id)
    if thread is None or thread.tenant_id != principal.tenant_id:
        raise TeamContractError("THREAD_NOT_FOUND")
    member = db.scalar(
        select(ThreadParticipant).where(
            ThreadParticipant.thread_id == thread_id,
            ThreadParticipant.tenant_id == principal.tenant_id,
            ThreadParticipant.user_id == principal.user_id,
            ThreadParticipant.active.is_(True),
        )
    )
    if member is None:
        raise TeamContractError("THREAD_ACCESS_DENIED")
    if member.thread_role not in TEAM_ALLOWED_THREAD_ROLES:
        raise TeamContractError("THREAD_READ_ONLY")
    return thread, member


def team_history(
    db: Session,
    *,
    thread_id: str,
    tenant_id: str,
    settings,
    limit: int = 40,
    user_id: str | None = None,
    execution_id: str | None = None,
    agent_id: str | None = None,
    purpose: str = "team",
) -> list[dict]:
    rows = db.scalars(
        select(Message)
        .where(Message.thread_id == thread_id, Message.tenant_id == tenant_id)
        .order_by(Message.created_at.desc())
        .limit(limit)
    ).all()
    ordered = list(reversed(rows))
    history = [history_item(row) for row in ordered]
    latest_user_content = next(
        (str(row.content or "") for row in reversed(ordered) if row.author_type == "user"),
        "",
    )
    system_guard = system_capability_guard_message(latest_user_content)
    context = document_context_message(
        db,
        settings=settings,
        tenant_id=tenant_id,
        thread_id=thread_id,
        query_text=latest_user_content,
    )
    system_messages: list[dict] = []
    if system_guard:
        system_messages.append(system_guard)
    if user_id and execution_id:
        system_messages.extend(
            knowledge_context_messages(
                db,
                settings=settings,
                tenant_id=tenant_id,
                user_id=user_id,
                purpose=purpose,
                execution_id=execution_id,
                thread_id=thread_id,
                agent_id=agent_id,
                query_text=latest_user_content,
            )
        )
    if context:
        system_messages.append(context)
    return system_messages + history


def build_team_turn(
    *,
    thread_id: str,
    tenant_id: str,
    user_id: str,
    requested_target: str,
    orchestrator_agent_id: str,
    channel: RuntimeChannel = RuntimeChannel.CHAT_SSE,
) -> CanonicalTurnContext:
    orchestrator = resolve_agent_by_id(orchestrator_agent_id)
    return CanonicalTurnContext(
        execution_id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
        thread_id=thread_id,
        tenant_id=tenant_id,
        user_id=user_id,
        requested_target=requested_target,
        resolved_agent_id=orchestrator.slug,
        turn_owner_agent_id=orchestrator.slug,
        display_agent_id=orchestrator.slug,
        display_agent_name=orchestrator.display_name,
        technical_lead_agent_id=orchestrator.slug,
        route_family=RuntimeRouteFamily.TEAM,
        channel=channel,
        ownership_locked=True,
        governance_mode="normal",
        internal_persistence_allowed=True,
        external_write_allowed=False,
        execution_allowed=True,
        orchestrator_agent_id=orchestrator.slug,
    )


def persist_user_message(db: Session, *, turn: CanonicalTurnContext, content: str) -> Message:
    row = Message(
        tenant_id=turn.tenant_id,
        thread_id=turn.thread_id,
        author_type="user",
        author_id=turn.user_id,
        agent_name=None,
        content=content,
    )
    db.add(row)
    db.commit()
    return row


def persist_team_contribution(
    db: Session,
    *,
    turn: CanonicalTurnContext,
    agent_id: str,
    content: str,
) -> Message:
    agent = resolve_agent_by_id(agent_id)
    row = Message(
        tenant_id=turn.tenant_id,
        thread_id=turn.thread_id,
        author_type="agent",
        author_id=agent.slug,
        agent_name=agent.display_name,
        content=content,
    )
    db.add(row)
    db.commit()
    return row


def persist_team_final(
    db: Session,
    *,
    turn: CanonicalTurnContext,
    content: str,
):
    row = Message(
        tenant_id=turn.tenant_id,
        thread_id=turn.thread_id,
        author_type="agent",
        author_id=turn.turn_owner_agent_id,
        agent_name=turn.display_agent_name,
        content=content,
    )
    db.add(row)
    db.commit()
    canonical = canonical_message(
        message_id=row.id,
        context=turn,
        content=row.content,
        created_at=row.created_at,
    )
    envelope = build_response_envelope(context=turn, message=canonical)
    return row, envelope_payload(envelope)


def team_audit(
    db: Session,
    *,
    turn: CanonicalTurnContext,
    action: str,
    outcome: str,
    metadata: dict[str, object] | None = None,
) -> None:
    safe_metadata: dict[str, object] = {}
    for key, value in (metadata or {}).items():
        if key in {"content", "prompt", "token", "secret", "authorization"}:
            continue
        if value is None or isinstance(value, (str, int, float, bool)):
            safe_metadata[str(key)[:80]] = value
        elif isinstance(value, (list, tuple)):
            safe_metadata[str(key)[:80]] = [str(x)[:80] for x in value[:16]]
    safe_metadata.setdefault("execution_id", turn.execution_id)
    safe_metadata.setdefault("thread_id", turn.thread_id)
    safe_metadata.setdefault("turn_owner_agent_id", turn.turn_owner_agent_id)
    row = AuditEvent(
        tenant_id=turn.tenant_id,
        actor_id=turn.user_id,
        action=action,
        resource_type="team_execution",
        resource_id=turn.execution_id,
        outcome=outcome,
        metadata_json=safe_metadata,
    )
    db.add(row)
    db.commit()
