"""Effective per-thread agent authorization, independent of frontend visibility.

Non-admin legacy participant rows have only Josué/orkio until an explicit grant.
All decisions are made against the current active ThreadParticipant.
"""
from __future__ import annotations

from fastapi import HTTPException

from ..auth import Principal

from ..models import ThreadParticipant


def principal_can_use_all_agents(principal: Principal) -> bool:
    # Roles are derived by identity.py from active Membership, not browser claims.
    return bool(
        {"admin", "orkio_admin", "owner", "superadmin", "platform_owner"}
        .intersection(principal.roles)
    )


def allowed_agent_ids(member: ThreadParticipant) -> tuple[str, ...]:
    stored = member.allowed_agent_ids
    if stored is None:
        return ("orkio",)
    if (
        not isinstance(stored, list)
        or not stored
        or len(stored) > 64
        or any(not isinstance(value, str) or not value for value in stored)
        or len(set(stored)) != len(stored)
    ):
        raise HTTPException(403, "THREAD_AGENT_GRANT_INVALID")
    return tuple(stored)


def require_agents_allowed(
    member: ThreadParticipant,
    agent_ids: list[str] | tuple[str, ...],
    *,
    is_admin: bool = False,
) -> None:
    if is_admin:
        return
    permitted = set(allowed_agent_ids(member))
    if any(agent_id not in permitted for agent_id in agent_ids):
        raise HTTPException(403, "THREAD_AGENT_NOT_ALLOWED")
