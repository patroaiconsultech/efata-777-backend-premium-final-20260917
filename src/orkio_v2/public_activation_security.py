from __future__ import annotations

import ipaddress
import json
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable, Iterable

from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import Settings, get_settings
from .services.activation_rate_limit import RedisRateLimitUnavailable, check_external_activation_rate_limit


STATUS_PATH = "/api/v2/platform-invitations/status"
ACCEPT_PATH = "/api/v2/platform-invitations/accept"
PUBLIC_ACTIVATION_PATHS = {STATUS_PATH: "status", ACCEPT_PATH: "accept"}


def _parse_ip(value: str | None):
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    if raw.startswith("[") and "]" in raw:
        raw = raw[1: raw.index("]")]
    elif raw.count(":") == 1 and "." in raw:
        host, maybe_port = raw.rsplit(":", 1)
        if maybe_port.isdigit():
            raw = host
    try:
        return ipaddress.ip_address(raw)
    except ValueError:
        return None


def _trusted_networks(settings: Settings):
    networks = []
    for item in settings.platform_activation_trusted_proxy_cidrs.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            # Settings validation should prevent this; fail closed if bypassed.
            return []
    return networks


def _is_trusted(ip, networks) -> bool:
    return ip is not None and any(ip in net for net in networks)


def _parse_x_forwarded_for(value: str):
    if not value:
        return []
    parsed = []
    for item in value.split(","):
        ip = _parse_ip(item)
        if ip is None:
            return None
        parsed.append(ip)
    return parsed


def _parse_forwarded(value: str):
    if not value:
        return []
    parsed = []
    for element in value.split(","):
        found = None
        for param in element.split(";"):
            name, sep, raw = param.strip().partition("=")
            if sep and name.lower() == "for":
                raw = raw.strip().strip('"')
                found = _parse_ip(raw)
                break
        if found is None:
            return None
        parsed.append(found)
    return parsed


def _client_from_chain(chain, peer, trusted_networks):
    values = list(chain) + [peer]
    for ip in reversed(values):
        if not _is_trusted(ip, trusted_networks):
            return ip
    return values[0] if values else None


def resolve_client_ip(scope: Scope, settings: Settings) -> str:
    client = scope.get("client")
    peer = _parse_ip(client[0] if client else None)
    if peer is None:
        return "unknown"

    networks = _trusted_networks(settings)
    if not _is_trusted(peer, networks):
        return str(peer)

    headers = {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in scope.get("headers", [])
    }
    xff_raw = headers.get("x-forwarded-for", "")
    forwarded_raw = headers.get("forwarded", "")

    xff = _parse_x_forwarded_for(xff_raw) if xff_raw else []
    fwd = _parse_forwarded(forwarded_raw) if forwarded_raw else []
    if xff is None or fwd is None:
        return "unknown"

    candidates = []
    if xff:
        candidates.append(_client_from_chain(xff, peer, networks))
    if fwd:
        candidates.append(_client_from_chain(fwd, peer, networks))

    if not candidates:
        return str(peer)
    if any(candidate is None for candidate in candidates):
        return "unknown"
    first = candidates[0]
    if any(candidate != first for candidate in candidates[1:]):
        return "unknown"
    return str(first)


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int


class InMemorySlidingWindowRateLimiter:
    """Process-local only. Never permitted as staging/production assurance."""

    def __init__(self):
        self._lock = threading.Lock()
        self._buckets: dict[str, deque[float]] = defaultdict(deque)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()

    def check(self, key: str, *, limit: int, window_seconds: int) -> RateLimitDecision:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets[key]
            cutoff = now - window_seconds
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, int(window_seconds - (now - bucket[0])))
                return RateLimitDecision(False, retry_after)
            bucket.append(now)
            return RateLimitDecision(True, 0)


_memory_limiter = InMemorySlidingWindowRateLimiter()


def reset_public_activation_security_state_for_tests() -> None:
    _memory_limiter.reset()


async def _json_response(
    scope: Scope,
    send: Send,
    status: int,
    code: str,
    *,
    retry_after: int | None = None,
):
    response = JSONResponse(
        status_code=status,
        content={"detail": code},
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
        },
    )
    if retry_after is not None:
        response.headers["Retry-After"] = str(retry_after)
    await response(scope, _empty_receive, send)


async def _empty_receive() -> Message:
    return {"type": "http.disconnect"}


async def _buffer_bounded_body(receive: Receive, max_bytes: int):
    messages: list[Message] = []
    total = 0
    while True:
        message = await receive()
        messages.append(message)
        if message["type"] != "http.request":
            return messages, total, False
        body = message.get("body", b"")
        total += len(body)
        if total > max_bytes:
            return messages, total, True
        if not message.get("more_body", False):
            return messages, total, False


def _replay_receive(messages: list[Message]) -> Receive:
    queue = deque(messages)

    async def receive() -> Message:
        if queue:
            return queue.popleft()
        return {"type": "http.request", "body": b"", "more_body": False}

    return receive


def _token_from_messages(messages: list[Message]) -> str | None:
    body = b"".join(
        message.get("body", b"")
        for message in messages
        if message.get("type") == "http.request"
    )
    if not body:
        return None
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    token = payload.get("token")
    if not isinstance(token, str):
        return None
    token = token.strip()
    return token or None


class PublicActivationSecurityMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        endpoint_class = PUBLIC_ACTIVATION_PATHS.get(scope.get("path", ""))
        if endpoint_class is None or scope.get("method", "").upper() != "POST":
            await self.app(scope, receive, send)
            return

        settings = get_settings()
        max_bytes = settings.platform_activation_max_body_bytes
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }

        content_length = headers.get("content-length")
        if content_length:
            try:
                declared = int(content_length)
            except ValueError:
                await _json_response(scope, send, 400, "PUBLIC_ACTIVATION_CONTENT_LENGTH_INVALID")
                return
            if declared < 0:
                await _json_response(scope, send, 400, "PUBLIC_ACTIVATION_CONTENT_LENGTH_INVALID")
                return
            if declared > max_bytes:
                await _json_response(scope, send, 413, "PUBLIC_ACTIVATION_PAYLOAD_TOO_LARGE")
                return

        client_ip = resolve_client_ip(scope, settings)
        backend = settings.platform_activation_rate_limit_backend
        limit = (
            settings.platform_activation_status_rate_limit_per_window
            if endpoint_class == "status"
            else settings.platform_activation_accept_rate_limit_per_window
        )

        if backend == "memory":
            decision = _memory_limiter.check(
                f"{endpoint_class}|{client_ip}",
                limit=limit,
                window_seconds=settings.platform_activation_rate_limit_window_seconds,
            )
            if not decision.allowed:
                await _json_response(
                    scope,
                    send,
                    429,
                    "PUBLIC_ACTIVATION_RATE_LIMITED",
                    retry_after=decision.retry_after_seconds,
                )
                return

            messages, _, too_large = await _buffer_bounded_body(receive, max_bytes)
            if too_large:
                await _json_response(scope, send, 413, "PUBLIC_ACTIVATION_PAYLOAD_TOO_LARGE")
                return
        elif backend == "external":
            messages, _, too_large = await _buffer_bounded_body(receive, max_bytes)
            if too_large:
                await _json_response(scope, send, 413, "PUBLIC_ACTIVATION_PAYLOAD_TOO_LARGE")
                return

            token = _token_from_messages(messages)
            try:
                decision = await check_external_activation_rate_limit(
                    endpoint_class=endpoint_class,
                    client_ip=client_ip,
                    token=token,
                    secret=settings.platform_invitation_secret,
                    limit=limit,
                    window_seconds=settings.platform_activation_rate_limit_window_seconds,
                )
            except RedisRateLimitUnavailable:
                await _json_response(
                    scope,
                    send,
                    503,
                    "PUBLIC_ACTIVATION_RATE_LIMIT_BACKEND_UNAVAILABLE",
                )
                return

            if not decision.allowed:
                await _json_response(
                    scope,
                    send,
                    429,
                    "PUBLIC_ACTIVATION_RATE_LIMITED",
                    retry_after=decision.retry_after_seconds,
                )
                return
        else:
            await _json_response(
                scope,
                send,
                503,
                "PUBLIC_ACTIVATION_RATE_LIMIT_BACKEND_UNAVAILABLE",
            )
            return

        await self.app(scope, _replay_receive(messages), send)
