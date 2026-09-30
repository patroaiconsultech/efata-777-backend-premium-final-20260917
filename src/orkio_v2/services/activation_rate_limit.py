from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import ssl
import uuid
from dataclasses import dataclass
from urllib.parse import unquote, urlparse


logger = logging.getLogger("orkio_v2.activation_rate_limit")

_DEFAULT_REDIS_TIMEOUT_SECONDS = 1.0
_KEY_PREFIX = "efata:activation:rl:v1"


class RedisRateLimitUnavailable(RuntimeError):
    """External rate-limit backend could not make a safe decision."""


@dataclass(frozen=True)
class DistributedRateLimitDecision:
    allowed: bool
    retry_after_seconds: int


# Sliding-window decision/update is atomic across all KEYS in one Redis EVAL.
# Redis TIME is used so application replica clock skew cannot split the policy.
_REDIS_SLIDING_WINDOW_SCRIPT = r"""
local limit = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local member = ARGV[3]

local now_parts = redis.call("TIME")
local now_ms = (tonumber(now_parts[1]) * 1000) + math.floor(tonumber(now_parts[2]) / 1000)
local cutoff = now_ms - window_ms
local retry_after = 0

for i, key in ipairs(KEYS) do
    redis.call("ZREMRANGEBYSCORE", key, "-inf", cutoff)
    local count = redis.call("ZCARD", key)
    if count >= limit then
        local oldest = redis.call("ZRANGE", key, 0, 0, "WITHSCORES")
        local retry = 1
        if oldest[2] then
            retry = math.ceil((tonumber(oldest[2]) + window_ms - now_ms) / 1000)
            if retry < 1 then
                retry = 1
            end
        end
        if retry > retry_after then
            retry_after = retry
        end
    end
end

if retry_after > 0 then
    return {0, retry_after}
end

for i, key in ipairs(KEYS) do
    redis.call("ZADD", key, now_ms, member .. ":" .. tostring(i))
    redis.call("PEXPIRE", key, window_ms)
end

return {1, 0}
""".strip()


def _opaque_dimension(secret: str, kind: str, value: str) -> str:
    raw = f"{kind}:{value}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()


def _rate_limit_keys(
    *,
    endpoint_class: str,
    client_ip: str,
    token: str | None,
    secret: str,
) -> list[str]:
    keys = [
        f"{_KEY_PREFIX}:{endpoint_class}:client:"
        f"{_opaque_dimension(secret, 'client', client_ip)}"
    ]
    if token:
        keys.append(
            f"{_KEY_PREFIX}:{endpoint_class}:token:"
            f"{_opaque_dimension(secret, 'token', token)}"
        )
    return keys


def _encode_command(*parts: object) -> bytes:
    payload = bytearray(f"*{len(parts)}\r\n".encode("ascii"))
    for part in parts:
        raw = str(part).encode("utf-8")
        payload.extend(f"${len(raw)}\r\n".encode("ascii"))
        payload.extend(raw)
        payload.extend(b"\r\n")
    return bytes(payload)


async def _read_resp(reader: asyncio.StreamReader):
    prefix = await reader.readexactly(1)
    if prefix == b"+":
        return (await reader.readline()).rstrip(b"\r\n").decode("utf-8", errors="replace")
    if prefix == b"-":
        message = (await reader.readline()).rstrip(b"\r\n").decode("utf-8", errors="replace")
        raise RedisRateLimitUnavailable("redis_error_reply")
    if prefix == b":":
        return int((await reader.readline()).rstrip(b"\r\n"))
    if prefix == b"$":
        length = int((await reader.readline()).rstrip(b"\r\n"))
        if length < 0:
            return None
        data = await reader.readexactly(length)
        await reader.readexactly(2)
        return data
    if prefix == b"*":
        count = int((await reader.readline()).rstrip(b"\r\n"))
        if count < 0:
            return None
        return [await _read_resp(reader) for _ in range(count)]
    raise RedisRateLimitUnavailable("redis_protocol_invalid")


async def _command(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *parts: object,
):
    writer.write(_encode_command(*parts))
    await writer.drain()
    return await _read_resp(reader)


def _redis_connection_parts(redis_url: str):
    try:
        parsed = urlparse(redis_url)
        host = parsed.hostname
    except ValueError as exc:
        raise RedisRateLimitUnavailable("redis_url_invalid") from exc

    if parsed.scheme not in {"redis", "rediss"}:
        raise RedisRateLimitUnavailable("redis_scheme_invalid")
    if not host:
        raise RedisRateLimitUnavailable("redis_host_missing")

    db = 0
    if parsed.path and parsed.path != "/":
        try:
            db = int(parsed.path.lstrip("/"))
        except ValueError as exc:
            raise RedisRateLimitUnavailable("redis_database_invalid") from exc
        if db < 0:
            raise RedisRateLimitUnavailable("redis_database_invalid")

    try:
        port = parsed.port or 6379
    except ValueError as exc:
        raise RedisRateLimitUnavailable("redis_port_invalid") from exc

    return {
        "scheme": parsed.scheme,
        "host": host,
        "port": port,
        "username": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
        "db": db,
    }


class RedisActivationRateLimiter:
    def __init__(self, redis_url: str, *, timeout_seconds: float = _DEFAULT_REDIS_TIMEOUT_SECONDS):
        self._redis_url = redis_url
        self._timeout_seconds = timeout_seconds

    async def check(
        self,
        *,
        endpoint_class: str,
        client_ip: str,
        token: str | None,
        secret: str,
        limit: int,
        window_seconds: int,
    ) -> DistributedRateLimitDecision:
        if not self._redis_url.strip():
            raise RedisRateLimitUnavailable("redis_url_missing")
        if len(secret.strip()) < 32:
            raise RedisRateLimitUnavailable("rate_limit_key_secret_unavailable")
        if limit < 1 or window_seconds < 1:
            raise RedisRateLimitUnavailable("rate_limit_contract_invalid")

        parts = _redis_connection_parts(self._redis_url)
        keys = _rate_limit_keys(
            endpoint_class=endpoint_class,
            client_ip=client_ip,
            token=token,
            secret=secret,
        )
        member = uuid.uuid4().hex

        writer: asyncio.StreamWriter | None = None
        try:
            ssl_context = ssl.create_default_context() if parts["scheme"] == "rediss" else None
            connect = asyncio.open_connection(
                parts["host"],
                parts["port"],
                ssl=ssl_context,
                server_hostname=parts["host"] if ssl_context else None,
            )
            reader, writer = await asyncio.wait_for(connect, timeout=self._timeout_seconds)

            if parts["password"]:
                auth_parts = (
                    ("AUTH", parts["username"], parts["password"])
                    if parts["username"]
                    else ("AUTH", parts["password"])
                )
                auth = await asyncio.wait_for(
                    _command(reader, writer, *auth_parts),
                    timeout=self._timeout_seconds,
                )
                if auth != "OK":
                    raise RedisRateLimitUnavailable("redis_auth_failed")

            if parts["db"]:
                selected = await asyncio.wait_for(
                    _command(reader, writer, "SELECT", parts["db"]),
                    timeout=self._timeout_seconds,
                )
                if selected != "OK":
                    raise RedisRateLimitUnavailable("redis_select_failed")

            result = await asyncio.wait_for(
                _command(
                    reader,
                    writer,
                    "EVAL",
                    _REDIS_SLIDING_WINDOW_SCRIPT,
                    len(keys),
                    *keys,
                    limit,
                    window_seconds * 1000,
                    member,
                ),
                timeout=self._timeout_seconds,
            )
        except RedisRateLimitUnavailable:
            raise
        except (TimeoutError, asyncio.TimeoutError, OSError, ValueError, EOFError) as exc:
            raise RedisRateLimitUnavailable(type(exc).__name__) from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

        if (
            not isinstance(result, list)
            or len(result) != 2
            or not all(isinstance(value, int) for value in result)
        ):
            raise RedisRateLimitUnavailable("redis_decision_invalid")

        allowed_raw, retry_after = result
        if allowed_raw not in {0, 1} or retry_after < 0:
            raise RedisRateLimitUnavailable("redis_decision_invalid")

        return DistributedRateLimitDecision(
            allowed=bool(allowed_raw),
            retry_after_seconds=max(0, retry_after),
        )


async def check_external_activation_rate_limit(
    *,
    endpoint_class: str,
    client_ip: str,
    token: str | None,
    secret: str,
    limit: int,
    window_seconds: int,
) -> DistributedRateLimitDecision:
    redis_url = os.getenv("REDIS_URL", "")
    limiter = RedisActivationRateLimiter(redis_url)
    try:
        return await limiter.check(
            endpoint_class=endpoint_class,
            client_ip=client_ip,
            token=token,
            secret=secret,
            limit=limit,
            window_seconds=window_seconds,
        )
    except RedisRateLimitUnavailable as exc:
        logger.warning(
            "public_activation_external_rate_limit_unavailable endpoint_class=%s reason=%s",
            endpoint_class,
            str(exc),
        )
        raise
