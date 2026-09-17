from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol

_GIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


@dataclass(frozen=True, slots=True)
class RuntimeProvenance:
    build_sha: str | None
    source: str


def normalize_git_sha(value: str | None) -> str | None:
    cleaned = (value or "").strip()
    if not _GIT_SHA_RE.fullmatch(cleaned):
        return None
    return cleaned.lower()


def resolve_build_provenance(
    *,
    platform_release_sha: str | None,
    railway_git_commit_sha: str | None,
) -> RuntimeProvenance:
    explicit = normalize_git_sha(platform_release_sha)
    if explicit:
        return RuntimeProvenance(explicit, "platform_release_sha")

    railway = normalize_git_sha(railway_git_commit_sha)
    if railway:
        return RuntimeProvenance(railway, "railway_git_commit_sha")

    return RuntimeProvenance(None, "unresolved")


class _SettingsLike(Protocol):
    release_sha: str
    release_sha_source: str
    environment: str
    railway_deployment_id: str | None
    railway_service_name: str | None


def runtime_provenance_payload(settings: _SettingsLike) -> dict[str, object]:
    return {
        "deployment_id": (settings.railway_deployment_id or "").strip() or None,
        "build_sha": settings.release_sha if settings.release_sha != "unknown" else None,
        "environment": settings.environment,
        "service_name": (settings.railway_service_name or "").strip() or None,
        "provenance_source": settings.release_sha_source,
    }
