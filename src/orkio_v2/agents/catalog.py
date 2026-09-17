from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .contracts import AgentDefinition, TargetKind

CATALOG_SOURCE_ARTIFACT = (
    "EFATA777_EXECUTIVE_AGENT_CATALOG_R0_3_4_"
    "ONBOARDING_LANGUAGE_LOCALIZED_IDENTITIES_PROPOSAL_ONLY.zip"
)
CATALOG_SOURCE_SHA256 = "babd5952d1fec4cb5bed15b47941433d41a749edc6321339902332452bf0c661"
CATALOG_JSON_SHA256 = "ba0be8b745e0ad049bf4f99203599273694ce3c911709e6a06366b0c3efae084"
_CATALOG_PATH = Path(__file__).with_name("catalog_r034.json")


def _load_catalog() -> dict:
    raw = _CATALOG_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != CATALOG_JSON_SHA256:
        raise RuntimeError("AGENT_CATALOG_SHA256_MISMATCH")
    data = json.loads(raw.decode("utf-8"))
    agents = data.get("agents")
    if not isinstance(agents, list) or len(agents) != 33:
        raise RuntimeError("AGENT_CATALOG_INVALID_COUNT")

    ids = [str(row.get("agent_id") or "").strip() for row in agents]
    if len(ids) != len(set(ids)) or any(not value for value in ids):
        raise RuntimeError("AGENT_CATALOG_INVALID_AGENT_IDS")

    canonical = [str(row.get("canonical_name") or "").strip().casefold() for row in agents]
    if len(canonical) != len(set(canonical)) or any(not value for value in canonical):
        raise RuntimeError("AGENT_CATALOG_INVALID_CANONICAL_NAMES")
    return data


RAW_CATALOG = _load_catalog()
CATALOG_VERSION = str(RAW_CATALOG.get("catalog_version") or "")


def _definition(row: dict) -> AgentDefinition:
    return AgentDefinition(
        slug=str(row["agent_id"]),
        canonical_name=str(row["canonical_name"]),
        display_name=str(row["display_name"]),
        role_code=str(row["role_code"]),
        role_label=str(row["role_label"]),
        organizational_level=str(row["organizational_level"]),
        department=str(row["department"]),
        reports_to=row.get("reports_to"),
        specialties=tuple(str(x) for x in row.get("specialties") or ()),
        aliases=tuple(str(x) for x in row.get("aliases") or ()),
        localized_names=dict(row.get("localized_names") or {}),
        localized_role_labels=dict(row.get("localized_role_labels") or {}),
        founder_direct_access=bool(row.get("founder_direct_access", False)),
        legacy_identity=row.get("legacy_identity"),
        voice_binding_id=row.get("voice_binding_id"),
        system_instruction=str(row["system_instruction"]),
        target_kind=TargetKind.AGENT,
        enabled=bool(row.get("enabled_in_catalog", False)),
        catalog_version=CATALOG_VERSION,
    )


AGENTS: tuple[AgentDefinition, ...] = tuple(
    _definition(row) for row in RAW_CATALOG["agents"]
)
