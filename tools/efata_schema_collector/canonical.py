from __future__ import annotations

import hashlib
import json
import unicodedata
from datetime import date, datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel

CANONICAL_JSON_VERSION = "EFATA-CANONICAL-JSON-1"


class CanonicalizationError(ValueError):
    pass


def _normalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="python"))
    if isinstance(value, Enum):
        return _normalize(value.value)
    if isinstance(value, UUID):
        return str(value).lower()
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise CanonicalizationError("naive datetime is not canonical")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, float):
        raise CanonicalizationError("floats are forbidden in critical canonical payloads")
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, bytes):
        return {"$bytes_sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("object keys must be strings")
            if key in out:
                raise CanonicalizationError(f"duplicate key: {key}")
            out[key] = _normalize(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    raise CanonicalizationError(f"unsupported canonical type: {type(value)!r}")


def canonical_json_bytes(value: Any) -> bytes:
    normalized = _normalize(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_canonical(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def sha256_nullable(value: str | bytes | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return sha256_text(value)
    return sha256_bytes(value)


def normalize_sensitive_definition(value: str) -> bytes:
    # Deliberately non-semantic: Unicode NFC + LF normalization only.
    normalized = unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n")
    return normalized.encode("utf-8")
