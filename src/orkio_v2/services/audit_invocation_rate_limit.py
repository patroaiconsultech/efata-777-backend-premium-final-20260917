from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import threading
import time
from typing import Callable

from sqlalchemy import func, select

from ..models import AuditEvidenceRecord


class AuditRateLimitError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LedgerAuditRateLimitCheck:
    """Deterministic ledger-backed limit for canonical capability invocations.

    Counted state: every durable audit_evidence_record for the exact capability
    in the trusted UTC window, irrespective of completed/failed/denied status.
    A canonical invocation attempt therefore consumes budget even when denied.
    """

    def __init__(
        self,
        *,
        session_factory,
        window_seconds: int = 60,
        user_limit: int = 4,
        tenant_limit: int = 20,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        if window_seconds != 60:
            raise AuditRateLimitError("AUDIT_RATE_LIMIT_WINDOW_INVALID")
        if user_limit < 1 or tenant_limit < user_limit:
            raise AuditRateLimitError("AUDIT_RATE_LIMIT_VALUE_INVALID")
        self._session_factory = session_factory
        self._window_seconds = int(window_seconds)
        self._user_limit = int(user_limit)
        self._tenant_limit = int(tenant_limit)
        self._now_fn = now_fn or (lambda: datetime.now(timezone.utc))

    def __call__(
        self,
        *,
        capability_id: str,
        user_id: str,
        tenant_id: str,
        resolved_agent_id: str,
    ) -> bool:
        now = self._now_fn()
        if now.tzinfo is None:
            raise AuditRateLimitError("AUDIT_RATE_LIMIT_TIME_NOT_UTC")
        now = now.astimezone(timezone.utc)
        cutoff = now - timedelta(seconds=self._window_seconds)
        try:
            with self._session_factory() as db:
                common = (
                    AuditEvidenceRecord.tenant_id == tenant_id,
                    AuditEvidenceRecord.capability_id == capability_id,
                    AuditEvidenceRecord.created_at >= cutoff,
                )
                user_count = int(
                    db.scalar(
                        select(func.count(AuditEvidenceRecord.id)).where(
                            *common,
                            AuditEvidenceRecord.user_id == user_id,
                        )
                    )
                    or 0
                )
                tenant_count = int(
                    db.scalar(select(func.count(AuditEvidenceRecord.id)).where(*common))
                    or 0
                )
        except Exception as exc:
            raise AuditRateLimitError("AUDIT_RATE_LIMITER_UNAVAILABLE") from exc
        return user_count < self._user_limit and tenant_count < self._tenant_limit


class AuditDirectiveAbuseLimiter:
    """Process-local parser abuse boundary for malformed `/audit` traffic.

    This is intentionally independent from the ledger because malformed
    directives have no canonical capability_id and must not create a fake
    capability identity. It is a secondary local guard; canonical invocations
    still use the durable ledger limiter above.
    """

    def __init__(
        self,
        *,
        window_seconds: int = 60,
        per_user_limit: int = 12,
        time_fn: Callable[[], float] | None = None,
    ) -> None:
        if window_seconds != 60 or per_user_limit < 1:
            raise AuditRateLimitError("AUDIT_DIRECTIVE_RATE_LIMIT_INVALID")
        self._window_seconds = float(window_seconds)
        self._per_user_limit = int(per_user_limit)
        self._time_fn = time_fn or time.monotonic
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def consume(self, *, tenant_id: str, user_id: str) -> bool:
        now = float(self._time_fn())
        cutoff = now - self._window_seconds
        key = (tenant_id, user_id)
        with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= self._per_user_limit:
                return False
            events.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
