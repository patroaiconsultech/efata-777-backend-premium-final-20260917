from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import PurePosixPath
import re
import unicodedata

from .audit_invocation_contracts import (
    AUDIT_CANONICAL_AGENT_ID,
    AUDIT_DIRECTIVE_VERSION,
    RUNTIME_MODULE_ALLOWLIST,
)


AUDIT_RUNTIME_TRACE_CAPABILITY_ID = "audit.runtime.trace.get@1.0.0"


@dataclass(frozen=True, slots=True)
class NaturalAuditBinding:
    intent: str
    directive_message: str | None = None
    required_capability_id: str | None = None
    error_code: str | None = None

    @property
    def executable(self) -> bool:
        return self.directive_message is not None and self.error_code is None


def _normalize(value: str) -> str:
    folded = unicodedata.normalize("NFKD", str(value or ""))
    ascii_text = "".join(ch for ch in folded if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", ascii_text.lower()).strip()


def _contains_action(text: str) -> bool:
    return bool(
        re.search(
            r"\b(audite|auditar|audit|inspect|inspecione|investigue|verifique)\b",
            text,
        )
    )


def _module_matches(text: str) -> list[str]:
    matches: list[str] = []
    for module_id, relative_path in RUNTIME_MODULE_ALLOWLIST.items():
        filename = PurePosixPath(relative_path).name
        stem = PurePosixPath(relative_path).stem
        aliases = {
            _normalize(module_id),
            _normalize(module_id.replace("_", " ")),
            _normalize(filename),
            _normalize(stem),
        }
        if any(
            re.search(rf"(?<![a-z0-9_]){re.escape(alias)}(?![a-z0-9_])", text)
            for alias in aliases
            if alias
        ):
            matches.append(module_id)
    return matches


def _without_explicitly_denied_trace_requests(text: str) -> str:
    """Exclude a narrowly scoped, explicit denial of trace/log retrieval.

    Keep other sentences intact: an affirmative runtime audit request still
    routes through the governed capability and fails closed if unavailable.
    """
    return re.sub(
        r"\bnao\s+(?:solicito|peco|quero|requeiro|estou\s+(?:solicitando|pedindo|requerendo))\s+"
        r"(?:a\s+)?(?:consulta|acesso|leitura|busca)\s+"
        r"(?:a\s+|de\s+|aos\s+|as\s+)?"
        r"(?:traces?|logs?|registros?)[^.!?]*?"
        r"(?=(?:,\s*|\s+)(?:mas|porem|contudo|entretanto|todavia)\b|(?:,\s*|\s+)e\s+(?:audite|auditar|audit|inspect|inspecione|investigue|verifique)\b|[.!?]|$)",
        " ",
        text,
    )


def _runtime_trace_requested(text: str) -> bool:
    indicators = (
        "realtime",
        "runtime",
        "logs",
        " log ",
        "trace",
        "timeline",
        "execucao",
        "execution",
        "deployment",
        "sse",
        "request id",
        "execution id",
        "call id",
        "primeira divergencia",
        "first divergence",
    )
    padded = f" {text} "
    return any(indicator in padded for indicator in indicators)


def _runtime_hash_requested(text: str) -> bool:
    return any(token in text for token in ("sha-256", "sha256", "checksum", " hash "))


def resolve_natural_audit_binding(
    message: str,
    *,
    resolved_agent_id: str,
) -> NaturalAuditBinding | None:
    """Resolve only narrow server-owned natural audit acquisition intents.

    This function never grants authority. It only translates a bounded,
    deterministic natural request into an already governed `/audit`
    directive, or reports that the required read-only capability is absent.
    Arbitrary paths, URLs, SQL, shell commands, tenant IDs, and credentials
    are never extracted from user text.
    """

    if str(resolved_agent_id or "").strip().lower() != AUDIT_CANONICAL_AGENT_ID:
        return None

    raw = str(message or "")
    if raw.lstrip().startswith("/audit"):
        return None

    text = _normalize(raw)
    if not text or not _contains_action(text):
        return None

    if _runtime_hash_requested(f" {text} "):
        modules = _module_matches(text)
        if len(modules) == 1:
            payload = {
                "version": AUDIT_DIRECTIVE_VERSION,
                "operation": "runtime.file_sha256",
                "module_id": modules[0],
            }
            return NaturalAuditBinding(
                intent="runtime.file_sha256",
                directive_message="/audit "
                + json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                required_capability_id="audit.runtime.file_sha256@1.0.0",
            )
        return NaturalAuditBinding(
            intent="runtime.file_sha256",
            required_capability_id="audit.runtime.file_sha256@1.0.0",
            error_code="CAPABILITY_ARGUMENTS_REQUIRED",
        )

    if _runtime_trace_requested(_without_explicitly_denied_trace_requests(text)):
        return NaturalAuditBinding(
            intent="runtime.trace.get",
            required_capability_id=AUDIT_RUNTIME_TRACE_CAPABILITY_ID,
            error_code="CAPABILITY_UNAVAILABLE",
        )

    return None
