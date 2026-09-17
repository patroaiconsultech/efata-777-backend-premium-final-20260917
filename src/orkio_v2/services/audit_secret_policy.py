from __future__ import annotations

import re
from dataclasses import dataclass


class AuditSecretPolicyError(RuntimeError):
    code = "AUDIT_SECRET_CONTENT_BLOCKED"


@dataclass(frozen=True, slots=True)
class SecretMatch:
    category: str


_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("private_key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github_token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,255}\b")),
    ("openai_key", re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
)


def detect_high_confidence_secrets(data: bytes | str) -> tuple[SecretMatch, ...]:
    raw = data.encode("utf-8", "ignore") if isinstance(data, str) else data
    found: list[SecretMatch] = []
    for category, pattern in _PATTERNS:
        if pattern.search(raw):
            found.append(SecretMatch(category))
    return tuple(found)


def assert_no_high_confidence_secrets(data: bytes | str) -> None:
    matches = detect_high_confidence_secrets(data)
    if matches:
        categories = ",".join(sorted({item.category for item in matches}))
        raise AuditSecretPolicyError(f"AUDIT_SECRET_CONTENT_BLOCKED:{categories}")
