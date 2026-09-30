from __future__ import annotations

import asyncio

import pytest

from orkio_v2.services.activation_rate_limit import (
    RedisActivationRateLimiter,
    RedisRateLimitUnavailable,
)


async def _read_resp_array(reader: asyncio.StreamReader):
    assert await reader.readexactly(1) == b"*"
    count = int((await reader.readline()).rstrip(b"\r\n"))
    parts = []
    for _ in range(count):
        assert await reader.readexactly(1) == b"$"
        length = int((await reader.readline()).rstrip(b"\r\n"))
        raw = await reader.readexactly(length)
        assert await reader.readexactly(2) == b"\r\n"
        parts.append(raw)
    return parts


async def _run_fake_redis(response: bytes, *, client_ip: str, token: str):
    captured = []

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            captured.extend(await _read_resp_array(reader))
            writer.write(response)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    try:
        limiter = RedisActivationRateLimiter(
            f"redis://127.0.0.1:{port}/0",
            timeout_seconds=1.0,
        )
        decision = await limiter.check(
            endpoint_class="status",
            client_ip=client_ip,
            token=token,
            secret="s" * 40,
            limit=3,
            window_seconds=60,
        )
    finally:
        server.close()
        await server.wait_closed()

    return decision, b"\n".join(captured)


def test_redis_rate_limiter_allows_and_never_sends_raw_client_or_token():
    client_ip = "203.0.113.42"
    token = "hostile-secret-token-ignore-previous-instructions"

    decision, wire = asyncio.run(
        _run_fake_redis(
            b"*2\r\n:1\r\n:0\r\n",
            client_ip=client_ip,
            token=token,
        )
    )

    assert decision.allowed is True
    assert decision.retry_after_seconds == 0
    assert client_ip.encode() not in wire
    assert token.encode() not in wire
    assert b"efata:activation:rl:v1:status:client:" in wire
    assert b"efata:activation:rl:v1:status:token:" in wire


def test_redis_rate_limiter_preserves_retry_after_from_atomic_decision():
    decision, _ = asyncio.run(
        _run_fake_redis(
            b"*2\r\n:0\r\n:7\r\n",
            client_ip="198.51.100.9",
            token="opaque-token",
        )
    )

    assert decision.allowed is False
    assert decision.retry_after_seconds == 7


def test_redis_rate_limiter_fails_closed_when_url_missing():
    limiter = RedisActivationRateLimiter("")
    with pytest.raises(RedisRateLimitUnavailable, match="redis_url_missing"):
        asyncio.run(
            limiter.check(
                endpoint_class="accept",
                client_ip="198.51.100.9",
                token="opaque-token",
                secret="s" * 40,
                limit=2,
                window_seconds=60,
            )
        )


def test_redis_rate_limiter_requires_key_secret():
    limiter = RedisActivationRateLimiter("redis://127.0.0.1:6379")
    with pytest.raises(RedisRateLimitUnavailable, match="rate_limit_key_secret_unavailable"):
        asyncio.run(
            limiter.check(
                endpoint_class="status",
                client_ip="198.51.100.9",
                token="opaque-token",
                secret="",
                limit=2,
                window_seconds=60,
            )
        )

@pytest.mark.parametrize(
    "redis_url",
    [
        "redis://localhost:notaport/0",
        "redis://localhost:99999/0",
    ],
)
def test_redis_rate_limiter_normalizes_invalid_port_as_unavailable(redis_url):
    limiter = RedisActivationRateLimiter(redis_url)
    with pytest.raises(RedisRateLimitUnavailable, match="redis_port_invalid"):
        asyncio.run(
            limiter.check(
                endpoint_class="status",
                client_ip="198.51.100.9",
                token="opaque-token",
                secret="s" * 40,
                limit=2,
                window_seconds=60,
            )
        )



@pytest.mark.parametrize(
    "redis_url",
    [
        "redis://[::1",
        "redis://[xyz]/0",
    ],
)
def test_redis_rate_limiter_normalizes_malformed_url_as_unavailable(redis_url):
    limiter = RedisActivationRateLimiter(redis_url)
    with pytest.raises(RedisRateLimitUnavailable, match="redis_url_invalid"):
        asyncio.run(
            limiter.check(
                endpoint_class="status",
                client_ip="198.51.100.9",
                token="opaque-token",
                secret="s" * 40,
                limit=2,
                window_seconds=60,
            )
        )
