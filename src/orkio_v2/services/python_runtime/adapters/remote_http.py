from __future__ import annotations

from dataclasses import replace
import json
from typing import Any

import httpx

from ...capability_policy import CapabilityPolicy
from ..attestation import validate_remote_runtime_response
from ..integrity import (
    INTEGRITY_CONTRACT,
    body_sha256,
    canonical_json_bytes,
    current_unix_seconds,
    new_request_nonce,
    opaque_sha256,
    sign_request,
    verify_response_signature,
)
from ..contracts import (
    PythonExecutionRequest,
    PythonRuntimeAttestationInvalid,
    PythonRuntimeResult,
    PythonRuntimeUnavailable,
)


class RemoteHttpPythonSandboxAdapter:
    adapter_id = "remote_http"

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._transport = transport

    async def execute(
        self,
        request: PythonExecutionRequest,
        policy: CapabilityPolicy,
    ) -> PythonRuntimeResult:
        if (
            policy.python_runtime_mode != "external"
            or policy.python_runtime_adapter != "remote_http"
            or not policy.python_runtime_qualified
            or not policy.python_runtime_base_url
            or not policy.python_runtime_api_token
            or not policy.python_runtime_signing_key
            or not policy.python_runtime_expected_provider
            or not policy.python_runtime_expected_image_digest
            or request.expected_runtime_image_digest
               != policy.python_runtime_expected_image_digest
        ):
            raise PythonRuntimeUnavailable("PYTHON_RUNTIME_UNAVAILABLE")

        endpoint = f"{policy.python_runtime_base_url.rstrip('/')}/v1/executions"
        request_body = canonical_json_bytes(request.broker_payload())
        request_body_digest = body_sha256(request_body)
        request_timestamp = current_unix_seconds()
        request_expires_at = (
            request_timestamp + policy.python_runtime_request_ttl_seconds
        )
        request_nonce = new_request_nonce()
        request_signature = sign_request(
            key=policy.python_runtime_signing_key,
            timestamp=request_timestamp,
            expires_at=request_expires_at,
            nonce=request_nonce,
            body=request_body,
        )
        headers = {
            "Authorization": f"Bearer {policy.python_runtime_api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-EFATA-Runtime-Contract": "efata.python.runtime.v1",
            "X-EFATA-Integrity-Contract": INTEGRITY_CONTRACT,
            "X-EFATA-Execution-Id": request.execution_id,
            "X-EFATA-Request-Timestamp": str(request_timestamp),
            "X-EFATA-Request-Expires-At": str(request_expires_at),
            "X-EFATA-Request-Nonce": request_nonce,
            "X-EFATA-Body-SHA256": request_body_digest,
            "X-EFATA-Request-Signature": request_signature,
        }
        max_response_bytes = (
            request.limits.max_stdout_stderr_bytes
            + min(request.limits.max_output_files * 16_384, 262_144)
            + 262_144
        )

        try:
            timeout = httpx.Timeout(policy.python_runtime_request_timeout_seconds)
            async with httpx.AsyncClient(
                timeout=timeout,
                transport=self._transport,
                follow_redirects=False,
            ) as client:
                async with client.stream(
                    "POST",
                    endpoint,
                    headers=headers,
                    content=request_body,
                ) as response:
                    if response.status_code in {401, 403, 404, 408, 409, 429, 500, 502, 503, 504}:
                        raise PythonRuntimeUnavailable("PYTHON_RUNTIME_UNAVAILABLE")
                    if response.status_code < 200 or response.status_code >= 300:
                        raise PythonRuntimeUnavailable("PYTHON_RUNTIME_UNAVAILABLE")

                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > max_response_bytes:
                            raise PythonRuntimeAttestationInvalid(
                                "PYTHON_RUNTIME_RESPONSE_TOO_LARGE"
                            )
        except PythonRuntimeAttestationInvalid:
            raise
        except PythonRuntimeUnavailable:
            raise
        except (httpx.TimeoutException, httpx.NetworkError, httpx.ProtocolError) as exc:
            raise PythonRuntimeUnavailable("PYTHON_RUNTIME_UNAVAILABLE") from exc

        response_body = bytes(raw)
        response_contract = response.headers.get("X-EFATA-Integrity-Contract", "")
        echoed_execution_id = response.headers.get("X-EFATA-Execution-Id", "")
        echoed_timestamp = response.headers.get(
            "X-EFATA-Response-Request-Timestamp", ""
        )
        echoed_expires_at = response.headers.get(
            "X-EFATA-Response-Request-Expires-At", ""
        )
        echoed_nonce = response.headers.get("X-EFATA-Response-Request-Nonce", "")
        echoed_body_sha256 = response.headers.get(
            "X-EFATA-Response-Request-Body-SHA256", ""
        )

        if (
            response_contract != INTEGRITY_CONTRACT
            or echoed_execution_id != request.execution_id
            or echoed_timestamp != str(request_timestamp)
            or echoed_expires_at != str(request_expires_at)
            or echoed_nonce != request_nonce
            or echoed_body_sha256 != request_body_digest
        ):
            raise PythonRuntimeAttestationInvalid(
                "PYTHON_RUNTIME_RESPONSE_REQUEST_BINDING_MISMATCH"
            )

        response_signature = response.headers.get("X-EFATA-Response-Signature", "")
        if not verify_response_signature(
            key=policy.python_runtime_signing_key,
            execution_id=request.execution_id,
            request_timestamp=request_timestamp,
            request_expires_at=request_expires_at,
            request_nonce=request_nonce,
            request_body_sha256=request_body_digest,
            body=response_body,
            signature=response_signature,
        ):
            raise PythonRuntimeAttestationInvalid(
                "PYTHON_RUNTIME_RESPONSE_SIGNATURE_INVALID"
            )

        try:
            payload: Any = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PythonRuntimeAttestationInvalid(
                "PYTHON_RUNTIME_RESPONSE_INVALID"
            ) from exc

        result = validate_remote_runtime_response(
            payload,
            request=request,
            expected_provider=policy.python_runtime_expected_provider,
        )
        transport_binding = {
            "integrity_contract": INTEGRITY_CONTRACT,
            "request_timestamp": request_timestamp,
            "request_expires_at": request_expires_at,
            "request_nonce_sha256": opaque_sha256(request_nonce),
            "request_body_sha256": request_body_digest,
            "response_signature_verified": True,
            "response_request_binding_verified": True,
        }
        return replace(
            result,
            attestation={
                **result.attestation,
                "transport_binding": transport_binding,
            },
        )
