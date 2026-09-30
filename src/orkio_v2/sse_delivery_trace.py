from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send


_TRUE_VALUES = {"1", "true", "yes", "on"}
_STREAM_PATH_RE = re.compile(r"^/api/v2/threads/[^/]+/stream$")
_LOGGER = logging.getLogger("uvicorn.error.orkio.sse_delivery")
_CONTRACT = "EFATA-SSE-DELIVERY-TRACE-1"
_SAFE_DATA_KEYS = ("execution_id", "sequence", "status", "code")


def _enabled() -> bool:
    return os.getenv("PLATFORM_SSE_DELIVERY_TRACE_ENABLED", "").strip().lower() in _TRUE_VALUES


def _safe_sse_metadata(body: bytes) -> tuple[list[str], dict[str, Any]]:
    """Extract only allowlisted SSE metadata; never return user/model content."""
    events: list[str] = []
    safe: dict[str, Any] = {}
    if not body:
        return events, safe

    text = body.decode("utf-8", errors="replace")
    for line in text.splitlines():
        if line.startswith("event: "):
            event_name = line[7:].strip()
            if event_name and len(event_name) <= 80:
                events.append(event_name)
        elif line.startswith("data: "):
            try:
                payload = json.loads(line[6:])
            except (TypeError, ValueError):
                continue
            if not isinstance(payload, dict):
                continue
            for key in _SAFE_DATA_KEYS:
                value = payload.get(key)
                if isinstance(value, (str, int, float, bool)) or value is None:
                    safe[key] = value
    return events, safe


def _trace(event: str, **fields: Any) -> None:
    payload = {"contract": _CONTRACT, "event": event, **fields}
    _LOGGER.info(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


class SSEDeliveryTraceMiddleware:
    """Feature-flagged wire-boundary trace for the canonical thread SSE route.

    The middleware is diagnostic only:
    - disabled by default;
    - does not modify ASGI messages;
    - emits metadata only, never SSE content;
    - logs body delivery only after the downstream ASGI send returns.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope.get("type") != "http"
            or scope.get("method", "").upper() != "POST"
            or not _STREAM_PATH_RE.fullmatch(scope.get("path", ""))
            or not _enabled()
        ):
            await self.app(scope, receive, send)
            return

        frame_index = 0

        async def traced_send(message: Message) -> None:
            nonlocal frame_index
            message_type = message.get("type")

            if message_type == "http.response.start":
                await send(message)
                try:
                    _trace(
                        "response_start_sent",
                        status=int(message.get("status", 0)),
                    )
                except Exception:
                    _LOGGER.debug("SSE delivery trace logging failed", exc_info=True)
                return

            if message_type == "http.response.body":
                frame_index += 1
                body = message.get("body", b"") or b""
                more_body = bool(message.get("more_body", False))
                event_names, safe = _safe_sse_metadata(body)
                try:
                    await send(message)
                except BaseException as exc:
                    try:
                        _trace(
                            "body_send_failed",
                            frame_index=frame_index,
                            frame_bytes=len(body),
                            more_body=more_body,
                            event_names=event_names,
                            exception_type=type(exc).__name__,
                            **safe,
                        )
                    except Exception:
                        _LOGGER.debug("SSE delivery trace logging failed", exc_info=True)
                    raise

                try:
                    _trace(
                        "body_sent",
                        frame_index=frame_index,
                        frame_bytes=len(body),
                        more_body=more_body,
                        event_names=event_names,
                        **safe,
                    )
                    if not more_body:
                        _trace("stream_closed", frame_index=frame_index)
                except Exception:
                    _LOGGER.debug("SSE delivery trace logging failed", exc_info=True)
                return

            await send(message)

        await self.app(scope, receive, traced_send)
