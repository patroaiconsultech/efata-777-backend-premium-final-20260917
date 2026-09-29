from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx

from orkio_v2.services.llm_contracts import LLMUpstreamError, ProviderName
import orkio_v2.services.llm_providers as llm_providers_module
from orkio_v2.services.llm_providers import OpenAIProvider, _provider_error


def _status_error(
    *,
    status: int,
    payload: dict,
    headers: dict[str, str] | None = None,
) -> httpx.HTTPStatusError:
    request = httpx.Request(
        "POST",
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": "Bearer should-never-appear"},
    )
    response = httpx.Response(
        status,
        request=request,
        json=payload,
        headers=headers or {},
    )
    return httpx.HTTPStatusError("bad", request=request, response=response)


def test_llm_upstream_diagnostic_is_sanitized():
    source = _status_error(
        status=429,
        payload={
            "error": {
                "code": "rate_limit_exceeded",
                "type": "requests",
                "message": "private provider detail",
            }
        },
        headers={
            "x-request-id": "req_safe_123",
            "retry-after": "2",
            "x-ratelimit-remaining-requests": "0",
        },
    )

    error = _provider_error(
        provider=ProviderName.openai,
        model="gpt-5",
        operation="stream",
        exc=source,
    )

    assert isinstance(error, LLMUpstreamError)
    assert error.upstream_status == 429
    assert error.upstream_code == "rate_limit_exceeded"
    assert error.upstream_type == "requests"
    assert error.upstream_classification == "RATE_LIMITED"
    assert error.provider_request_id == "req_safe_123"
    assert error.retry_after == "2"
    assert error.rate_limit_scope == "requests"

    rendered = repr(error.diagnostic())
    assert "Authorization" not in rendered
    assert "should-never-appear" not in rendered
    assert "private provider detail" not in rendered


def test_429_without_code_or_type_remains_unknown_not_quota_guess():
    source = _status_error(
        status=429,
        payload={"error": {"message": "not retained"}},
        headers={
            "x-request-id": "req_429_message_only",
            "retry-after": "1.5",
            "x-ratelimit-limit-requests": "500",
            "x-ratelimit-limit-tokens": "100000",
        },
    )

    error = _provider_error(
        provider=ProviderName.openai,
        model="gpt-5",
        operation="stream",
        exc=source,
    )

    assert error.upstream_status == 429
    assert error.upstream_code is None
    assert error.upstream_type is None
    assert error.upstream_classification == "UNKNOWN_UPSTREAM_429"
    assert error.provider_request_id == "req_429_message_only"
    assert error.retry_after == "1.5"
    assert error.rate_limit_scope == "requests,tokens"
    assert "not retained" not in repr(error.diagnostic())


def test_explicit_insufficient_quota_is_classified_without_retaining_message():
    source = _status_error(
        status=429,
        payload={
            "error": {
                "code": "insufficient_quota",
                "type": "insufficient_quota",
                "message": "billing/account text must not be logged",
            }
        },
    )
    error = _provider_error(
        provider=ProviderName.openai,
        model="gpt-5",
        operation="generate",
        exc=source,
    )

    assert error.upstream_classification == "QUOTA_EXHAUSTED"
    assert "billing/account text" not in repr(error.diagnostic())


def test_type_only_preserves_backward_compatible_upstream_code():
    source = _status_error(
        status=429,
        payload={"error": {"type": "rate_limit_exceeded", "message": "private"}},
    )
    error = _provider_error(
        provider=ProviderName.openai,
        model="gpt-5",
        operation="generate",
        exc=source,
    )

    assert error.upstream_code == "rate_limit_exceeded"
    assert error.upstream_type == "rate_limit_exceeded"
    assert error.upstream_classification == "RATE_LIMITED"


def test_unsafe_provider_metadata_is_dropped():
    source = _status_error(
        status=429,
        payload={"error": {"message": "private"}},
        headers={
            "x-request-id": "unsafe\nrequest\nid",
            "retry-after": "<script>alert(1)</script>",
        },
    )
    error = _provider_error(
        provider=ProviderName.openai,
        model="gpt-5",
        operation="stream",
        exc=source,
    )

    assert error.provider_request_id is None
    assert error.retry_after is None


def test_llm_upstream_diagnostic_keeps_runtime_metadata_only():
    error = LLMUpstreamError(
        provider="openai",
        model="gpt-5",
        operation="generate",
        upstream_status=400,
        upstream_code="unsupported_parameter",
        upstream_type="invalid_request_error",
        upstream_classification=None,
        provider_request_id="req_abc",
        retry_after=None,
        rate_limit_scope=None,
        exception_type="HTTPStatusError",
    )
    assert error.diagnostic() == {
        "provider": "openai",
        "model": "gpt-5",
        "operation": "generate",
        "upstream_status": 400,
        "upstream_code": "unsupported_parameter",
        "upstream_type": "invalid_request_error",
        "upstream_classification": None,
        "provider_request_id": "req_abc",
        "retry_after": None,
        "rate_limit_scope": None,
        "exception_type": "HTTPStatusError",
        "elapsed_ms": None,
        "provider_headers_ms": None,
        "first_content_chunk_ms": None,
        "last_content_chunk_ms": None,
        "content_chunk_count": None,
        "effective_timeout_seconds": None,
    }

def test_read_timeout_is_classified_without_raw_exception_detail():
    request = httpx.Request(
        "POST",
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": "Bearer secret-never-log"},
    )
    source = httpx.ReadTimeout("private upstream timeout detail", request=request)
    error = _provider_error(
        provider=ProviderName.openai,
        model="gpt-5",
        operation="stream",
        exc=source,
        elapsed_ms=1234,
        provider_headers_ms=120,
        first_content_chunk_ms=350,
        last_content_chunk_ms=900,
        content_chunk_count=4,
        effective_timeout_seconds=30.0,
    )

    assert error.upstream_status is None
    assert error.upstream_classification == "PROVIDER_READ_TIMEOUT"
    assert error.exception_type == "ReadTimeout"
    assert error.operation == "stream"
    assert error.elapsed_ms == 1234
    assert error.provider_headers_ms == 120
    assert error.first_content_chunk_ms == 350
    assert error.last_content_chunk_ms == 900
    assert error.content_chunk_count == 4
    assert error.effective_timeout_seconds == 30.0
    rendered = repr(error.diagnostic())
    assert "private upstream timeout detail" not in rendered
    assert "secret-never-log" not in rendered


def test_non_timeout_without_explicit_provider_evidence_remains_unclassified():
    request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    source = httpx.ConnectError("private connect detail", request=request)
    error = _provider_error(
        provider=ProviderName.openai,
        model="gpt-5",
        operation="generate",
        exc=source,
        elapsed_ms=77,
    )
    assert error.upstream_classification is None
    assert error.exception_type == "ConnectError"
    assert error.elapsed_ms == 77



def test_read_timeout_phase_metadata_distinguishes_pre_headers_from_post_headers():
    request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    source = httpx.ReadTimeout("private upstream timeout detail", request=request)

    pre_headers = _provider_error(
        provider=ProviderName.openai,
        model="gpt-5",
        operation="stream",
        exc=source,
        elapsed_ms=30000,
        provider_headers_ms=None,
        first_content_chunk_ms=None,
        last_content_chunk_ms=None,
        content_chunk_count=0,
        effective_timeout_seconds=30.0,
    )
    post_headers_pre_content = _provider_error(
        provider=ProviderName.openai,
        model="gpt-5",
        operation="stream",
        exc=source,
        elapsed_ms=30000,
        provider_headers_ms=140,
        first_content_chunk_ms=None,
        last_content_chunk_ms=None,
        content_chunk_count=0,
        effective_timeout_seconds=30.0,
    )

    assert pre_headers.provider_headers_ms is None
    assert pre_headers.content_chunk_count == 0
    assert post_headers_pre_content.provider_headers_ms == 140
    assert post_headers_pre_content.first_content_chunk_ms is None
    assert post_headers_pre_content.content_chunk_count == 0


def test_read_timeout_phase_metadata_marks_post_content_stall():
    request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    source = httpx.ReadTimeout("private upstream timeout detail", request=request)
    error = _provider_error(
        provider=ProviderName.openai,
        model="gpt-5",
        operation="stream",
        exc=source,
        elapsed_ms=30000,
        provider_headers_ms=100,
        first_content_chunk_ms=500,
        last_content_chunk_ms=1200,
        content_chunk_count=9,
        effective_timeout_seconds=30.0,
    )

    assert error.provider_headers_ms == 100
    assert error.first_content_chunk_ms == 500
    assert error.last_content_chunk_ms == 1200
    assert error.content_chunk_count == 9
    assert error.effective_timeout_seconds == 30.0


class _BehavioralStreamResponse:
    def __init__(self, *, mode: str, request: httpx.Request):
        self.mode = mode
        self.request = request

    def raise_for_status(self) -> None:
        return None

    async def aiter_lines(self):
        if self.mode == "post_headers_pre_content":
            raise httpx.ReadTimeout(
                "PRIVATE_UPSTREAM_TIMEOUT_DETAIL",
                request=self.request,
            )
        if self.mode == "post_content":
            yield 'data: {"choices":[{"delta":{"content":"SECRET_CHUNK_CONTENT"}}]}'
            raise httpx.ReadTimeout(
                "PRIVATE_UPSTREAM_TIMEOUT_DETAIL",
                request=self.request,
            )
        raise AssertionError(f"unexpected response mode: {self.mode}")


class _BehavioralStreamContext:
    def __init__(self, *, mode: str, request: httpx.Request):
        self.mode = mode
        self.request = request

    async def __aenter__(self):
        if self.mode == "pre_response_context":
            raise httpx.ReadTimeout(
                "PRIVATE_UPSTREAM_TIMEOUT_DETAIL",
                request=self.request,
            )
        return _BehavioralStreamResponse(mode=self.mode, request=self.request)

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _BehavioralAsyncClient:
    def __init__(self, *, mode: str, timeout: float, counters: dict[str, object]):
        self.mode = mode
        self.timeout = timeout
        self.counters = counters
        self.counters["client_count"] = int(self.counters.get("client_count", 0)) + 1
        self.counters["timeout"] = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def stream(self, method: str, url: str, *, headers: dict, json: dict):
        self.counters["stream_calls"] = int(self.counters.get("stream_calls", 0)) + 1
        request = httpx.Request(method, url, headers=headers)
        return _BehavioralStreamContext(mode=self.mode, request=request)


def _behavioral_provider(monkeypatch, *, mode: str):
    counters: dict[str, object] = {}
    settings = SimpleNamespace(
        openai_api_key="UNIT_TEST_KEY_NEVER_LOG",
        openai_model="gpt-5",
        openai_api_base=None,
        llm_http_timeout_seconds=30.0,
    )

    def client_factory(*, timeout):
        return _BehavioralAsyncClient(mode=mode, timeout=timeout, counters=counters)

    monkeypatch.setattr(llm_providers_module.httpx, "AsyncClient", client_factory)
    return OpenAIProvider(settings), counters


async def _consume_behavioral_stream(provider: OpenAIProvider):
    pieces: list[str] = []
    try:
        async for piece in provider.stream(
            "auditor",
            [{"role": "user", "content": "SECRET_PROMPT_CONTENT"}],
        ):
            pieces.append(piece)
    except LLMUpstreamError as exc:
        return pieces, exc
    raise AssertionError("expected LLMUpstreamError")


def _assert_behavioral_safety(error: LLMUpstreamError) -> None:
    rendered = repr(error.diagnostic())
    assert "SECRET_PROMPT_CONTENT" not in rendered
    assert "SECRET_CHUNK_CONTENT" not in rendered
    assert "UNIT_TEST_KEY_NEVER_LOG" not in rendered
    assert "PRIVATE_UPSTREAM_TIMEOUT_DETAIL" not in rendered


def test_openai_stream_read_timeout_before_response_context(monkeypatch):
    provider, counters = _behavioral_provider(monkeypatch, mode="pre_response_context")
    pieces, error = asyncio.run(_consume_behavioral_stream(provider))

    assert pieces == []
    assert error.exception_type == "ReadTimeout"
    assert error.upstream_classification == "PROVIDER_READ_TIMEOUT"
    assert error.provider_headers_ms is None
    assert error.first_content_chunk_ms is None
    assert error.last_content_chunk_ms is None
    assert error.content_chunk_count == 0
    assert error.effective_timeout_seconds == 30.0
    assert counters == {"client_count": 1, "timeout": 30.0, "stream_calls": 1}
    _assert_behavioral_safety(error)


def test_openai_stream_read_timeout_after_response_context_before_content(monkeypatch):
    provider, counters = _behavioral_provider(monkeypatch, mode="post_headers_pre_content")
    pieces, error = asyncio.run(_consume_behavioral_stream(provider))

    assert pieces == []
    assert error.exception_type == "ReadTimeout"
    assert error.upstream_classification == "PROVIDER_READ_TIMEOUT"
    assert error.provider_headers_ms is not None
    assert error.first_content_chunk_ms is None
    assert error.last_content_chunk_ms is None
    assert error.content_chunk_count == 0
    assert error.effective_timeout_seconds == 30.0
    assert counters == {"client_count": 1, "timeout": 30.0, "stream_calls": 1}
    _assert_behavioral_safety(error)


def test_openai_stream_read_timeout_after_content(monkeypatch):
    provider, counters = _behavioral_provider(monkeypatch, mode="post_content")
    pieces, error = asyncio.run(_consume_behavioral_stream(provider))

    assert pieces == ["SECRET_CHUNK_CONTENT"]
    assert error.exception_type == "ReadTimeout"
    assert error.upstream_classification == "PROVIDER_READ_TIMEOUT"
    assert error.provider_headers_ms is not None
    assert error.first_content_chunk_ms is not None
    assert error.last_content_chunk_ms is not None
    assert error.last_content_chunk_ms >= error.first_content_chunk_ms
    assert error.content_chunk_count == 1
    assert error.effective_timeout_seconds == 30.0
    assert counters == {"client_count": 1, "timeout": 30.0, "stream_calls": 1}
    _assert_behavioral_safety(error)
