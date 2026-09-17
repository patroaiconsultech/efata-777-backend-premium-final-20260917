from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time


class PythonRuntimeIntegrityError(RuntimeError):
    code = "PYTHON_RUNTIME_INTEGRITY_ERROR"


INTEGRITY_CONTRACT = "efata.hmac-sha256.v2"


def canonical_json_bytes(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def body_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def opaque_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_request_nonce() -> str:
    return secrets.token_hex(16)


def current_unix_seconds() -> int:
    return int(time.time())


def _hmac_hex(key: str, message: bytes) -> str:
    return hmac.new(
        key.encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()


def sign_request(
    *,
    key: str,
    timestamp: int,
    expires_at: int,
    nonce: str,
    body: bytes,
) -> str:
    material = (
        b"efata.request.v2\n"
        + str(timestamp).encode("ascii")
        + b"\n"
        + str(expires_at).encode("ascii")
        + b"\n"
        + nonce.encode("ascii")
        + b"\n"
        + body_sha256(body).encode("ascii")
    )
    return _hmac_hex(key, material)


def sign_response(
    *,
    key: str,
    execution_id: str,
    request_timestamp: int,
    request_expires_at: int,
    request_nonce: str,
    request_body_sha256: str,
    body: bytes,
) -> str:
    material = (
        b"efata.response.v2\n"
        + execution_id.encode("utf-8")
        + b"\n"
        + str(request_timestamp).encode("ascii")
        + b"\n"
        + str(request_expires_at).encode("ascii")
        + b"\n"
        + request_nonce.encode("ascii")
        + b"\n"
        + request_body_sha256.encode("ascii")
        + b"\n"
        + body_sha256(body).encode("ascii")
    )
    return _hmac_hex(key, material)


def verify_response_signature(
    *,
    key: str,
    execution_id: str,
    request_timestamp: int,
    request_expires_at: int,
    request_nonce: str,
    request_body_sha256: str,
    body: bytes,
    signature: str,
) -> bool:
    expected = sign_response(
        key=key,
        execution_id=execution_id,
        request_timestamp=request_timestamp,
        request_expires_at=request_expires_at,
        request_nonce=request_nonce,
        request_body_sha256=request_body_sha256,
        body=body,
    )
    return hmac.compare_digest(expected, (signature or "").strip().lower())
