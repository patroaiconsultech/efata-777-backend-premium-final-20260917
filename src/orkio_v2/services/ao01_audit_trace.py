from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
import re
from typing import Mapping


_TRACE_LOGGER = logging.getLogger("uvicorn.error.orkio.audit_trace")
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_SENSITIVE_KEY = re.compile(
    r"(authorization|cookie|token|secret|password|api[_-]?key|credential|prompt|document|content|body)",
    re.IGNORECASE,
)


def trace_enabled() -> bool:
    return os.getenv("ORKIO_AUDIT_TRACE_ENABLED", "").strip().lower() in _TRUE_VALUES


def _sanitize(metadata: Mapping[str, object], *, max_items: int = 64) -> dict[str, object]:
    clean: dict[str, object] = {}
    for index, (raw_key, value) in enumerate(metadata.items()):
        if index >= max_items:
            break
        key = str(raw_key)[:96]
        if _SENSITIVE_KEY.search(key):
            continue
        if value is None or isinstance(value, (bool, int, float)):
            clean[key] = value
        elif isinstance(value, str):
            clean[key] = value[:256]
        else:
            clean[key] = f"<{type(value).__name__}>"
    return clean


def emit_audit_trace(stage: str, **metadata: object) -> None:
    """Feature-flagged metadata-only trace that must never affect request behavior."""
    if not trace_enabled():
        return
    try:
        payload = _sanitize(
            {
                "contract": "ORKIO-AUDIT-TRACE-1",
                "event": "AUDIT_TRACE",
                "stage": str(stage)[:96],
                "occurred_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                **metadata,
            }
        )
        _TRACE_LOGGER.info(
            "AUDIT_TRACE %s",
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )
    except Exception:
        return
