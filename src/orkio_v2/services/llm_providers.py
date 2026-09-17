from __future__ import annotations

from collections.abc import AsyncIterator
import json
import re
import time
from typing import Any
from urllib.parse import quote

import httpx

from ..config import Settings
from .llm_contracts import (
    LLMNotConfigured,
    LLMResult,
    LLMUpstreamError,
    LLMUsage,
    ProviderConfigurationState,
    ProviderDescriptor,
    ProviderHealth,
    ProviderHealthState,
    ProviderName,
    agent_system_prompt,
    split_system_and_history,
    system_prompt_for_history,
)


DEFAULT_OPENAI_BASE = "https://api.openai.com/v1"


def _clean(value: str | None) -> str:
    return (value or "").strip()


def _require(value: str | None) -> str:
    cleaned = _clean(value)
    if not cleaned:
        raise LLMNotConfigured("LLM_NOT_CONFIGURED")
    return cleaned


def _content_or_fail(content: str) -> str:
    if not content.strip():
        raise LLMUpstreamError("LLM_EMPTY_RESPONSE")
    return content



_SAFE_METADATA_TOKEN = re.compile(r"^[A-Za-z0-9._:/+\-, ]{1,160}$")


def _safe_metadata(value: object, *, limit: int = 160) -> str | None:
    """Keep only short provider metadata tokens; never retain free-form messages."""
    if value is None:
        return None
    text = str(value).strip()[:limit]
    if not text or not _SAFE_METADATA_TOKEN.fullmatch(text):
        return None
    return text


def _rate_limit_scope(headers: httpx.Headers) -> str | None:
    """Infer only the class of rate-limit headers, never their values."""
    scopes: list[str] = []
    lowered = {name.lower() for name in headers.keys()}
    if any(
        name in lowered
        for name in (
            "x-ratelimit-limit-requests",
            "x-ratelimit-remaining-requests",
            "x-ratelimit-reset-requests",
        )
    ):
        scopes.append("requests")
    if any(
        name in lowered
        for name in (
            "x-ratelimit-limit-tokens",
            "x-ratelimit-remaining-tokens",
            "x-ratelimit-reset-tokens",
        )
    ):
        scopes.append("tokens")
    return ",".join(scopes) or None


def _classify_upstream_error(
    *,
    status: int | None,
    upstream_code: str | None,
    upstream_type: str | None,
) -> str | None:
    """Classify only when evidence is explicit; never infer quota from HTTP 429 alone."""
    evidence = {
        token.lower()
        for token in (upstream_code, upstream_type)
        if isinstance(token, str) and token.strip()
    }
    if "insufficient_quota" in evidence:
        return "QUOTA_EXHAUSTED"
    if evidence.intersection(
        {"billing_hard_limit_reached", "billing_not_active", "billing_error"}
    ):
        return "PROVIDER_BILLING_BLOCKED"
    if "rate_limit_exceeded" in evidence:
        return "RATE_LIMITED"
    if status == 429:
        return "UNKNOWN_UPSTREAM_429"
    return None


def _provider_error(
    *,
    provider: ProviderName,
    model: str,
    operation: str,
    exc: Exception,
    elapsed_ms: int | None = None,
) -> LLMUpstreamError:
    """Normalize upstream failures without retaining secrets, prompts, or raw bodies."""
    status: int | None = None
    upstream_code: str | None = None
    upstream_type: str | None = None
    provider_request_id: str | None = None
    retry_after: str | None = None
    rate_limit_scope: str | None = None

    if isinstance(exc, httpx.HTTPStatusError):
        response = exc.response
        status = response.status_code

        provider_request_id = _safe_metadata(
            response.headers.get("x-request-id") or response.headers.get("request-id")
        )
        retry_after = _safe_metadata(response.headers.get("retry-after"), limit=80)
        rate_limit_scope = _rate_limit_scope(response.headers)

        try:
            payload = response.json()
        except Exception:
            payload = None

        if isinstance(payload, dict):
            error = payload.get("error")
            if isinstance(error, dict):
                raw_code = error.get("code")
                raw_type = error.get("type")
                upstream_code = _safe_metadata(raw_code, limit=120)
                upstream_type = _safe_metadata(raw_type, limit=120)

                # Backward compatibility: historically `upstream_code` fell back to
                # `error.type`. Preserve that field while exposing type separately.
                if upstream_code is None:
                    upstream_code = upstream_type
            elif payload.get("code") is not None:
                upstream_code = _safe_metadata(payload.get("code"), limit=120)

    upstream_classification = _classify_upstream_error(
        status=status,
        upstream_code=upstream_code,
        upstream_type=upstream_type,
    )
    if isinstance(exc, httpx.ReadTimeout):
        upstream_classification = "PROVIDER_READ_TIMEOUT"

    return LLMUpstreamError(
        "LLM_UPSTREAM_ERROR",
        provider=provider.value,
        model=model,
        operation=operation,
        upstream_status=status,
        upstream_code=upstream_code,
        upstream_type=upstream_type,
        upstream_classification=upstream_classification,
        provider_request_id=provider_request_id,
        retry_after=retry_after,
        rate_limit_scope=rate_limit_scope,
        exception_type=type(exc).__name__,
        elapsed_ms=elapsed_ms,
    )


def openai_endpoint(settings: Settings) -> str:
    base = _clean(settings.openai_api_base) or DEFAULT_OPENAI_BASE
    return f"{base.rstrip('/')}/chat/completions"


def openai_payload(settings: Settings, agent: str, history: list[dict], stream: bool) -> dict:
    messages = [{"role": "system", "content": system_prompt_for_history(agent, history)}]
    messages.extend(history)
    return {
        "model": settings.openai_model,
        "messages": messages,
        "stream": stream,
    }


class OpenAIProvider:
    name = ProviderName.openai

    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def model(self) -> str:
        return _clean(self.settings.openai_model)

    @property
    def key(self) -> str:
        return _clean(self.settings.openai_api_key)

    def descriptor(self) -> ProviderDescriptor:
        state = (
            ProviderConfigurationState.configured
            if self.key and self.model
            else ProviderConfigurationState.unconfigured
        )
        return ProviderDescriptor(self.name, self.model, state)

    def ensure_configured(self) -> str:
        if not self.model:
            raise LLMNotConfigured("LLM_NOT_CONFIGURED")
        return _require(self.settings.openai_api_key)

    async def generate_result(self, agent: str, history: list[dict]) -> LLMResult:
        key = self.ensure_configured()
        started_at = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=self.settings.llm_http_timeout_seconds) as client:
                response = await client.post(
                    openai_endpoint(self.settings),
                    headers={"Authorization": f"Bearer {key}"},
                    json=openai_payload(self.settings, agent, history, stream=False),
                )
                response.raise_for_status()
                data = response.json()
        except LLMNotConfigured:
            raise
        except Exception as exc:  # noqa: BLE001 - provider details remain private
            raise _provider_error(
                provider=self.name,
                model=self.model,
                operation="generate",
                exc=exc,
                elapsed_ms=max(0, int((time.monotonic() - started_at) * 1000)),
            ) from exc

        choices = data.get("choices") or []
        if not choices:
            raise LLMUpstreamError("LLM_EMPTY_RESPONSE")
        content = str((choices[0].get("message") or {}).get("content") or "")
        usage_raw = data.get("usage") or {}
        prompt_details = usage_raw.get("prompt_tokens_details") or {}
        return LLMResult(
            content=_content_or_fail(content),
            provider=self.name,
            model=self.model,
            usage=LLMUsage(
                input_tokens=usage_raw.get("prompt_tokens"),
                output_tokens=usage_raw.get("completion_tokens"),
                cached_input_tokens=prompt_details.get("cached_tokens"),
            ),
        )

    async def stream(self, agent: str, history: list[dict]) -> AsyncIterator[str]:
        key = self.ensure_configured()
        started_at = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=self.settings.llm_http_timeout_seconds) as client:
                async with client.stream(
                    "POST",
                    openai_endpoint(self.settings),
                    headers={"Authorization": f"Bearer {key}"},
                    json=openai_payload(self.settings, agent, history, stream=True),
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line or not line.startswith("data: "):
                            continue
                        body = line.removeprefix("data: ").strip()
                        if body == "[DONE]":
                            return
                        try:
                            chunk = json.loads(body)
                        except ValueError:
                            continue
                        for choice in chunk.get("choices") or []:
                            piece = str((choice.get("delta") or {}).get("content") or "")
                            if piece:
                                yield piece
        except LLMNotConfigured:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _provider_error(
                provider=self.name,
                model=self.model,
                operation="stream",
                exc=exc,
                elapsed_ms=max(0, int((time.monotonic() - started_at) * 1000)),
            ) from exc

    async def healthcheck(self) -> ProviderHealth:
        if self.descriptor().state is ProviderConfigurationState.unconfigured:
            return ProviderHealth(
                self.name, self.model, ProviderHealthState.unconfigured, "LLM_NOT_CONFIGURED"
            )
        key = self.ensure_configured()
        base = _clean(self.settings.openai_api_base) or DEFAULT_OPENAI_BASE
        try:
            async with httpx.AsyncClient(timeout=self.settings.llm_http_timeout_seconds) as client:
                response = await client.get(
                    f"{base.rstrip('/')}/models/{quote(self.model, safe='')}",
                    headers={"Authorization": f"Bearer {key}"},
                )
                response.raise_for_status()
        except Exception:
            return ProviderHealth(
                self.name, self.model, ProviderHealthState.unavailable, "LLM_PROVIDER_UNAVAILABLE"
            )
        return ProviderHealth(self.name, self.model, ProviderHealthState.ready)


class AnthropicProvider:
    name = ProviderName.anthropic

    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def model(self) -> str:
        return _clean(self.settings.anthropic_model)

    @property
    def key(self) -> str:
        return _clean(self.settings.anthropic_api_key)

    @property
    def base(self) -> str:
        return _clean(self.settings.anthropic_api_base).rstrip("/")

    def descriptor(self) -> ProviderDescriptor:
        state = (
            ProviderConfigurationState.configured
            if self.key and self.model and self.base
            else ProviderConfigurationState.unconfigured
        )
        return ProviderDescriptor(self.name, self.model, state)

    def ensure_configured(self) -> str:
        if not self.model or not self.base:
            raise LLMNotConfigured("LLM_NOT_CONFIGURED")
        return _require(self.settings.anthropic_api_key)

    def _headers(self, key: str) -> dict[str, str]:
        return {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

    def _payload(self, agent: str, history: list[dict], stream: bool) -> dict[str, Any]:
        system, normalized = split_system_and_history(agent, history)
        return {
            "model": self.model,
            "max_tokens": self.settings.anthropic_max_tokens,
            "system": system,
            "messages": normalized,
            "stream": stream,
        }

    async def generate_result(self, agent: str, history: list[dict]) -> LLMResult:
        key = self.ensure_configured()
        try:
            async with httpx.AsyncClient(timeout=self.settings.llm_http_timeout_seconds) as client:
                response = await client.post(
                    f"{self.base}/messages",
                    headers=self._headers(key),
                    json=self._payload(agent, history, stream=False),
                )
                response.raise_for_status()
                data = response.json()
        except LLMNotConfigured:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _provider_error(
                provider=self.name,
                model=self.model,
                operation="generate",
                exc=exc,
            ) from exc

        text = "".join(
            str(block.get("text") or "")
            for block in data.get("content") or []
            if block.get("type") == "text"
        )
        usage_raw = data.get("usage") or {}
        cached = (
            usage_raw.get("cache_read_input_tokens")
            if usage_raw.get("cache_read_input_tokens") is not None
            else usage_raw.get("cache_read_input_tokens_5m")
        )
        return LLMResult(
            content=_content_or_fail(text),
            provider=self.name,
            model=self.model,
            usage=LLMUsage(
                input_tokens=usage_raw.get("input_tokens"),
                output_tokens=usage_raw.get("output_tokens"),
                cached_input_tokens=cached,
            ),
        )

    async def stream(self, agent: str, history: list[dict]) -> AsyncIterator[str]:
        key = self.ensure_configured()
        try:
            async with httpx.AsyncClient(timeout=self.settings.llm_http_timeout_seconds) as client:
                async with client.stream(
                    "POST",
                    f"{self.base}/messages",
                    headers=self._headers(key),
                    json=self._payload(agent, history, stream=True),
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line or not line.startswith("data: "):
                            continue
                        body = line.removeprefix("data: ").strip()
                        try:
                            event = json.loads(body)
                        except ValueError:
                            continue
                        event_type = event.get("type")
                        if event_type == "error":
                            raise LLMUpstreamError("LLM_UPSTREAM_ERROR")
                        if event_type == "message_stop":
                            return
                        if event_type != "content_block_delta":
                            continue
                        delta = event.get("delta") or {}
                        if delta.get("type") != "text_delta":
                            continue
                        piece = str(delta.get("text") or "")
                        if piece:
                            yield piece
        except LLMNotConfigured:
            raise
        except LLMUpstreamError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _provider_error(
                provider=self.name,
                model=self.model,
                operation="stream",
                exc=exc,
            ) from exc

    async def healthcheck(self) -> ProviderHealth:
        if self.descriptor().state is ProviderConfigurationState.unconfigured:
            return ProviderHealth(
                self.name, self.model, ProviderHealthState.unconfigured, "LLM_NOT_CONFIGURED"
            )
        key = self.ensure_configured()
        try:
            async with httpx.AsyncClient(timeout=self.settings.llm_http_timeout_seconds) as client:
                response = await client.get(
                    f"{self.base}/models/{quote(self.model, safe='')}",
                    headers=self._headers(key),
                )
                response.raise_for_status()
        except Exception:
            return ProviderHealth(
                self.name, self.model, ProviderHealthState.unavailable, "LLM_PROVIDER_UNAVAILABLE"
            )
        return ProviderHealth(self.name, self.model, ProviderHealthState.ready)


class GoogleProvider:
    name = ProviderName.google

    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def model(self) -> str:
        return _clean(self.settings.google_model)

    @property
    def key(self) -> str:
        return _clean(self.settings.google_api_key)

    @property
    def base(self) -> str:
        return _clean(self.settings.google_api_base).rstrip("/")

    def descriptor(self) -> ProviderDescriptor:
        state = (
            ProviderConfigurationState.configured
            if self.key and self.model and self.base
            else ProviderConfigurationState.unconfigured
        )
        return ProviderDescriptor(self.name, self.model, state)

    def ensure_configured(self) -> str:
        if not self.model or not self.base:
            raise LLMNotConfigured("LLM_NOT_CONFIGURED")
        return _require(self.settings.google_api_key)

    @staticmethod
    def _headers(key: str) -> dict[str, str]:
        # Keep API credentials out of URLs/query strings so proxies and access
        # logs cannot capture them accidentally.
        return {
            "x-goog-api-key": key,
            "content-type": "application/json",
        }

    def _payload(self, agent: str, history: list[dict]) -> dict[str, Any]:
        system, normalized = split_system_and_history(agent, history)
        contents = [
            {
                "role": "model" if item["role"] == "assistant" else "user",
                "parts": [{"text": item["content"]}],
            }
            for item in normalized
        ]
        return {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": self.settings.google_max_output_tokens,
            },
        }

    @staticmethod
    def _text(data: dict[str, Any]) -> str:
        texts: list[str] = []
        for candidate in data.get("candidates") or []:
            content = candidate.get("content") or {}
            for part in content.get("parts") or []:
                value = part.get("text")
                if value:
                    texts.append(str(value))
        return "".join(texts)

    async def generate_result(self, agent: str, history: list[dict]) -> LLMResult:
        key = self.ensure_configured()
        model_path = quote(self.model, safe="")
        try:
            async with httpx.AsyncClient(timeout=self.settings.llm_http_timeout_seconds) as client:
                response = await client.post(
                    f"{self.base}/models/{model_path}:generateContent",
                    headers=self._headers(key),
                    json=self._payload(agent, history),
                )
                response.raise_for_status()
                data = response.json()
        except LLMNotConfigured:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _provider_error(
                provider=self.name,
                model=self.model,
                operation="generate",
                exc=exc,
            ) from exc

        usage_raw = data.get("usageMetadata") or {}
        return LLMResult(
            content=_content_or_fail(self._text(data)),
            provider=self.name,
            model=self.model,
            usage=LLMUsage(
                input_tokens=usage_raw.get("promptTokenCount"),
                output_tokens=usage_raw.get("candidatesTokenCount"),
                cached_input_tokens=usage_raw.get("cachedContentTokenCount"),
            ),
        )

    async def stream(self, agent: str, history: list[dict]) -> AsyncIterator[str]:
        key = self.ensure_configured()
        model_path = quote(self.model, safe="")
        try:
            async with httpx.AsyncClient(timeout=self.settings.llm_http_timeout_seconds) as client:
                async with client.stream(
                    "POST",
                    f"{self.base}/models/{model_path}:streamGenerateContent",
                    params={"alt": "sse"},
                    headers=self._headers(key),
                    json=self._payload(agent, history),
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line or not line.startswith("data: "):
                            continue
                        body = line.removeprefix("data: ").strip()
                        try:
                            event = json.loads(body)
                        except ValueError:
                            continue
                        piece = self._text(event)
                        if piece:
                            yield piece
        except LLMNotConfigured:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _provider_error(
                provider=self.name,
                model=self.model,
                operation="stream",
                exc=exc,
            ) from exc

    async def healthcheck(self) -> ProviderHealth:
        if self.descriptor().state is ProviderConfigurationState.unconfigured:
            return ProviderHealth(
                self.name, self.model, ProviderHealthState.unconfigured, "LLM_NOT_CONFIGURED"
            )
        key = self.ensure_configured()
        model_path = quote(self.model, safe="")
        try:
            async with httpx.AsyncClient(timeout=self.settings.llm_http_timeout_seconds) as client:
                response = await client.get(
                    f"{self.base}/models/{model_path}",
                    headers=self._headers(key),
                )
                response.raise_for_status()
        except Exception:
            return ProviderHealth(
                self.name, self.model, ProviderHealthState.unavailable, "LLM_PROVIDER_UNAVAILABLE"
            )
        return ProviderHealth(self.name, self.model, ProviderHealthState.ready)
