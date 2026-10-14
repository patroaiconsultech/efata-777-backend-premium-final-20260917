"""Fail-closed isolation for the B1.1 zero-LLM public API."""
from __future__ import annotations

import os
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import get_settings
from .public_sales_redis import shared_store_gate_ready
from .public_activation_security import (
    _buffer_bounded_body,
    _replay_receive,
    resolve_client_ip,
)

PREFIX = "/api/v2/public/sales-sessions"
MAX_BYTES = 16 * 1024

def is_public_sales_path(path: str) -> bool:
    return path == PREFIX or path.startswith(PREFIX + "/")

async def _reject(scope: Scope, send: Send, status: int, code: str):
    response = JSONResponse(
        {"detail": code}, status_code=status,
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
                 "X-Content-Type-Options": "nosniff"},
    )
    async def empty_receive():
        return {"type": "http.disconnect"}
    await response(scope, empty_receive, send)

class PublicSalesSecurityMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope.get("type") != "http" or not is_public_sales_path(scope.get("path", "")):
            await self.app(scope, receive, send)
            return

        # The only exposed actions in this gate are POST; there are no public read paths.
        method = scope.get("method", "").upper()
        if method != "POST":
            await _reject(scope, send, 405, "PUBLIC_SALES_METHOD_NOT_ALLOWED")
            return
        settings = get_settings()
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }
        origin = headers.get("origin", "")
        allowed = {x.strip() for x in settings.allowed_origins.split(",") if x.strip()}
        if (origin and origin not in allowed) or (
            settings.environment in {"staging", "production"} and not origin
        ):
            await _reject(scope, send, 403, "PUBLIC_SALES_ORIGIN_INVALID")
            return
        if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            await _reject(scope, send, 415, "PUBLIC_SALES_JSON_REQUIRED")
            return
        declared = headers.get("content-length")
        if declared is not None:
            try:
                length = int(declared)
                if length < 0:
                    raise ValueError()
            except ValueError:
                await _reject(scope, send, 400, "PUBLIC_SALES_CONTENT_LENGTH_INVALID")
                return
            if length > MAX_BYTES:
                await _reject(scope, send, 413, "PUBLIC_SALES_REQUEST_TOO_LARGE")
                return
        if os.getenv("PUBLIC_SALES_ENABLED", "false").lower() != "true":
            await _reject(scope, send, 503, "PUBLIC_SALES_DISABLED")
            return
        if settings.environment not in {"development", "test"} and not shared_store_gate_ready():
            # Flag + external Redis required before any public traffic reaches the route.
            await _reject(scope, send, 503, "PUBLIC_SALES_SHARED_STORE_NOT_CONFIGURED")
            return

        messages, _, oversized = await _buffer_bounded_body(receive, MAX_BYTES)
        if oversized:
            await _reject(scope, send, 413, "PUBLIC_SALES_REQUEST_TOO_LARGE")
            return
        scope.setdefault("state", {})["public_sales_client_ip"] = resolve_client_ip(scope, settings)
        await self.app(scope, _replay_receive(messages), send)
