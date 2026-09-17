from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class PlatformKnowledgeEntry:
    """Backward-compatible type for immutable code-shipped system guardrails.

    Mutable PatroAI Platform directives belong exclusively in KnowledgeDocument
    scope=PLATFORM. This module no longer carries institutional/company facts.
    """

    key: str
    title: str
    content: str
    source_classification: str


_CAPABILITY_GUARD = PlatformKnowledgeEntry(
    key="capability_integrity",
    title="PatroAI Platform — capability integrity guard",
    content=(
        "Não declare uma capacidade da PatroAI Platform como pronta, ativa em produção "
        "ou validada em runtime sem evidência correspondente ao ambiente atual. "
        "Código, teste local, preview e roadmap são evidências distintas de produção. "
        "Para perguntas sobre funcionalidades, diferencie comprovado, não comprovado "
        "e planejado."
    ),
    source_classification="SYSTEM_CAPABILITY_INTEGRITY",
)

_TRIGGERS = {
    "capacidade",
    "capacidades",
    "funcao da plataforma",
    "função da plataforma",
    "o que a plataforma faz",
    "o que voces fazem",
    "o que vocês fazem",
    "realtime",
    "voz",
    "team",
    "dream team",
    "artifact",
    "artefato",
    "documento",
    "github",
    "produção",
    "producao",
    "runtime",
    "ready",
    "pronto",
    "pronta",
}


def _normalize(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value or "")
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", stripped.casefold()).strip()


def _matches(query: str, trigger: str) -> bool:
    normalized = _normalize(query)
    token = _normalize(trigger)
    if " " in token:
        return token in normalized
    return re.search(rf"(?<![\w]){re.escape(token)}(?![\w])", normalized) is not None


def resolve_platform_knowledge(query: str) -> tuple[PlatformKnowledgeEntry, ...]:
    """Return immutable system guardrails relevant to the current turn.

    Despite the legacy function name, this is not mutable PLATFORM knowledge.
    Governed PatroAI directives/institutional facts must come from
    KnowledgeDocument and therefore support publish/supersede/revoke/audit.
    """
    if any(_matches(query, trigger) for trigger in _TRIGGERS):
        return (_CAPABILITY_GUARD,)
    return ()


def system_capability_guard_message(query: str) -> dict[str, str] | None:
    entries = resolve_platform_knowledge(query)
    if not entries:
        return None
    entry = entries[0]
    return {
        "role": "system",
        "content": (
            "SYSTEM / SECURITY BASELINE — immutable capability-integrity guard. "
            "This is code-shipped system policy, not mutable PatroAI PLATFORM knowledge. "
            "Governed PLATFORM documents remain the authority for mutable directives and "
            "institutional facts.\n"
            f"--- {entry.title} [{entry.source_classification}] ---\n{entry.content}"
        ),
    }


def platform_knowledge_message(query: str) -> dict[str, str] | None:
    """Compatibility alias for callers not yet renamed.

    The returned content is now strictly a SYSTEM capability-integrity guard;
    no mutable PatroAI Platform/company knowledge is stored here.
    """
    return system_capability_guard_message(query)
