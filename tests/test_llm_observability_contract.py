from __future__ import annotations

import httpx

from orkio_v2.services.llm_contracts import LLMUpstreamError, ProviderName
from orkio_v2.services.llm_providers import _provider_error


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
    )

    assert error.upstream_status is None
    assert error.upstream_classification == "PROVIDER_READ_TIMEOUT"
    assert error.exception_type == "ReadTimeout"
    assert error.operation == "stream"
    assert error.elapsed_ms == 1234
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

