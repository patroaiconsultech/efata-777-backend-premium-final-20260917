from __future__ import annotations

from dataclasses import dataclass
import re
import unicodedata

from ..agents.contracts import AgentDefinition
from ..agents.registry import list_agents, resolve_agent_by_id, AgentNotFound


class TargetResolutionError(ValueError):
    code: str


class TargetNotFound(TargetResolutionError):
    code = "TARGET_NOT_FOUND"

    def __init__(self, requested: str):
        super().__init__(self.code)
        self.requested = requested


class TargetAmbiguous(TargetResolutionError):
    code = "TARGET_AMBIGUOUS"

    def __init__(self, requested: str, candidates: tuple[str, ...]):
        super().__init__(self.code)
        self.requested = requested
        self.candidates = tuple(sorted(set(candidates)))


@dataclass(frozen=True, slots=True)
class TargetResolution:
    requested: str
    agent: AgentDefinition
    matched_key: str
    matched_source: str
    technical_handle: bool = False

    @property
    def agent_id(self) -> str:
        return self.agent.slug


_TECHNICAL_HANDLE_RE = re.compile(r"^\s*id\s*:\s*([a-zA-Z0-9_.-]+)\s*$", re.IGNORECASE)


def normalize_target(value: str) -> str:
    """Accent/case/punctuation-insensitive normalization for human identity.

    Technical handles are parsed before this function and are never placed in
    the natural-language alias index.
    """
    text = unicodedata.normalize("NFKD", str(value or ""))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.casefold()
    text = re.sub(r"[_/—–-]+", " ", text)
    text = re.sub(r"[^\w\s]+", " ", text, flags=re.UNICODE)
    return " ".join(text.split())


def _candidate_terms(agent: AgentDefinition) -> tuple[tuple[str, str], ...]:
    terms: list[tuple[str, str]] = [
        (agent.canonical_name, "canonical_name"),
        (agent.display_name, "display_name"),
        (agent.role_code, "role_code"),
        (agent.role_label, "role_label"),
    ]
    terms.extend((value, f"localized_name:{locale}") for locale, value in agent.localized_names.items())
    terms.extend((value, f"localized_role:{locale}") for locale, value in agent.localized_role_labels.items())
    terms.extend((value, "alias") for value in agent.aliases)
    # Specialties are intentionally included as weak semantic targets. Known
    # overlaps remain ambiguous instead of silently selecting the first agent.
    terms.extend((value, "specialty") for value in agent.specialties)
    return tuple(terms)


class TargetResolver:
    def __init__(self, agents: tuple[AgentDefinition, ...] | None = None):
        self._agents = agents or list_agents()
        self._exact: dict[str, set[str]] = {}
        self._source: dict[tuple[str, str], str] = {}
        for agent in self._agents:
            for raw, source in _candidate_terms(agent):
                key = normalize_target(raw)
                if not key:
                    continue
                self._exact.setdefault(key, set()).add(agent.slug)
                self._source.setdefault((key, agent.slug), source)

    def resolve(self, requested: str) -> TargetResolution:
        raw = str(requested or "")
        technical = _TECHNICAL_HANDLE_RE.match(raw)
        if technical:
            agent_id = technical.group(1).casefold()
            try:
                agent = resolve_agent_by_id(agent_id)
            except AgentNotFound as exc:
                raise TargetNotFound(raw) from exc
            return TargetResolution(
                requested=raw,
                agent=agent,
                matched_key=f"id:{agent.slug}",
                matched_source="technical_handle",
                technical_handle=True,
            )

        key = normalize_target(raw)
        if not key:
            raise TargetNotFound(raw)

        exact = self._exact.get(key, set())
        if exact:
            if len(exact) > 1:
                raise TargetAmbiguous(raw, tuple(exact))
            agent_id = next(iter(exact))
            return TargetResolution(
                requested=raw,
                agent=resolve_agent_by_id(agent_id),
                matched_key=key,
                matched_source=self._source.get((key, agent_id), "catalog"),
            )

        # Natural request phrases such as "quero falar com o CFO" are resolved
        # by boundary-contained catalog terms. Multiple distinct agents fail
        # closed as TARGET_AMBIGUOUS.
        haystack = f" {key} "
        matches: dict[str, tuple[int, str, str]] = {}
        for term, agent_ids in self._exact.items():
            if len(term) < 2:
                continue
            if f" {term} " not in haystack:
                continue
            for agent_id in agent_ids:
                source = self._source.get((term, agent_id), "catalog")
                previous = matches.get(agent_id)
                score = len(term)
                if previous is None or score > previous[0]:
                    matches[agent_id] = (score, term, source)

        if not matches:
            raise TargetNotFound(raw)
        if len(matches) > 1:
            raise TargetAmbiguous(raw, tuple(matches))

        agent_id, (_, term, source) = next(iter(matches.items()))
        return TargetResolution(
            requested=raw,
            agent=resolve_agent_by_id(agent_id),
            matched_key=term,
            matched_source=source,
        )


_RESOLVER = TargetResolver()


def resolve_target(requested: str) -> TargetResolution:
    return _RESOLVER.resolve(requested)


def resolve_target_agent(requested: str) -> AgentDefinition:
    return resolve_target(requested).agent
