"""Fail-closed, fresh-transaction access checks for long-lived SSE responses.

A streaming request's original ORM participant must never remain the authority
after an administrator updates or revokes a grant. Each check reloads the
canonical ACL from the database and checks the original capabilities snapshot.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.engine import Engine, Connection
from sqlalchemy.orm import Session

from ..models import ThreadParticipant
from .thread_access_policy import ThreadAccessPolicyError, require_thread_access
from .thread_agent_grants import require_agents_allowed


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class StreamGrant:
    history_access: str
    joined_at: datetime | None
    access_expires_at: datetime | None
    can_read_messages: bool | None
    can_write_messages: bool | None
    can_view_attachments: bool | None
    can_upload_files: bool | None
    can_download_artifacts: bool | None
    can_generate_artifacts: bool | None
    allowed_agent_ids: tuple[str, ...] | None


def snapshot_grant(member: ThreadParticipant) -> StreamGrant:
    values = member.allowed_agent_ids
    return StreamGrant(
        history_access=member.history_access,
        joined_at=_utc(member.joined_at),
        access_expires_at=_utc(member.access_expires_at),
        can_read_messages=member.can_read_messages,
        can_write_messages=member.can_write_messages,
        can_view_attachments=member.can_view_attachments,
        can_upload_files=member.can_upload_files,
        can_download_artifacts=member.can_download_artifacts,
        can_generate_artifacts=member.can_generate_artifacts,
        allowed_agent_ids=None if values is None else tuple(values),
    )


def require_live_stream_access(
    bind: Engine | Connection,
    *,
    thread_id: str,
    tenant_id: str,
    user_id: str,
    expected_grant: StreamGrant,
    agent_ids: tuple[str, ...],
    is_admin: bool,
) -> None:
    """Enforce revocation, expiry, scope edits and agent grants using a fresh Session.

    The request's existing Session can cache stale ACL rows inside its identity map.
    This independent short-lived Session reads the committed access state.
    """
    with Session(bind=bind) as db:
        decision = require_thread_access(
            db, thread_id=thread_id, tenant_id=tenant_id, user_id=user_id,
            require_write=True,
        )
        if snapshot_grant(decision.participant) != expected_grant:
            raise ThreadAccessPolicyError("THREAD_GRANT_CHANGED", 403)
        require_agents_allowed(decision.participant, agent_ids, is_admin=is_admin)


def _rejected(code: str, *, realtime: bool) -> tuple[str, str]:
    if realtime:
        return (
            f"event: error\ndata: {json.dumps({'type': 'error', 'code': code})}\n\n",
            f"event: done\ndata: {json.dumps({'type': 'done', 'status': 'failed', 'code': code})}\n\n",
        )
    return (
        f"event: error\ndata: {json.dumps({'code': code})}\n\n",
        f"event: done\ndata: {json.dumps({'status': 'failed', 'code': code})}\n\n",
    )


async def guard_sse_stream(
    source: AsyncIterator[str],
    *,
    bind: Engine | Connection,
    thread_id: str,
    tenant_id: str,
    user_id: str,
    expected_grant: StreamGrant,
    agent_ids: tuple[str, ...],
    is_admin: bool,
    realtime: bool = False,
) -> AsyncIterator[str]:
    """Check before resuming upstream and after each await, before exposing bytes."""
    def check() -> str | None:
        try:
            require_live_stream_access(
                bind,
                thread_id=thread_id,
                tenant_id=tenant_id,
                user_id=user_id,
                expected_grant=expected_grant,
                agent_ids=agent_ids,
                is_admin=is_admin,
            )
        except ThreadAccessPolicyError as exc:
            return exc.code
        except HTTPException as exc:
            return str(exc.detail)
        except Exception:
            # Database failures or mismatches must block further disclosure.
            return "THREAD_STREAM_AUTH_UNAVAILABLE"
        return None

    try:
        while True:
            code = check()
            if code is not None:
                error, done = _rejected(code, realtime=realtime)
                yield error
                yield done
                return
            try:
                chunk = await anext(source)
            except StopAsyncIteration:
                return
            code = check()
            if code is not None:
                error, done = _rejected(code, realtime=realtime)
                yield error
                yield done
                return
            yield chunk
    except asyncio.CancelledError:
        # Forward cancellation to the original generator for its audit/cleanup.
        try:
            await source.athrow(asyncio.CancelledError())
        except (asyncio.CancelledError, StopAsyncIteration):
            pass
        raise
    finally:
        await source.aclose()
