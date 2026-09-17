from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from ..agents.registry import AgentNotFound, resolve_agent_by_id
from ..config import Settings
from ..models import AgentVoiceAssignment, VoiceCatalogEntry


class VoiceBindingError(RuntimeError):
    def __init__(self, code: str, *, validation_scope: str | None = None):
        super().__init__(code)
        self.code = code
        self.validation_scope = validation_scope


@dataclass(frozen=True, slots=True)
class VoiceProfile:
    agent_id: str
    binding_id: str
    binding_version: str
    locale: str
    provider: str
    voice_id: str
    model: str
    source_type: str
    delivery_mode: str
    provider_profile_version: str


_ALLOWED_DELIVERY_MODES = {
    "REALTIME_STREAM",
    "MESSAGE_PLAYBACK",
    "VOICE_MESSAGE",
}


def _bindings(settings: Settings) -> dict[str, Any]:
    try:
        raw = json.loads(settings.voice_bindings_json or "{}")
    except json.JSONDecodeError as exc:
        raise VoiceBindingError("VOICE_BINDINGS_CONFIG_INVALID") from exc
    if not isinstance(raw, dict):
        raise VoiceBindingError("VOICE_BINDINGS_CONFIG_INVALID")
    return raw


def _catalog_profile(agent_id: str, locale: str, settings: Settings, *, delivery_mode: str, db: Session | None, tenant_id: str | None) -> VoiceProfile | None:
    if db is None or not tenant_id or not inspect(db.get_bind()).has_table("agent_voice_assignments"):
        return None
    assignment = db.scalar(select(AgentVoiceAssignment).where(AgentVoiceAssignment.tenant_id == tenant_id, AgentVoiceAssignment.agent_slug == agent_id, AgentVoiceAssignment.locale == locale, AgentVoiceAssignment.active.is_(True), AgentVoiceAssignment.assignment_state == "ACTIVE"))
    if assignment is None:
        return None
    if assignment.validation_status != "VALIDATED":
        raise VoiceBindingError("VOICE_PROFILE_NOT_VALIDATED", validation_scope="admin_assignment")
    entry = db.get(VoiceCatalogEntry, assignment.voice_catalog_id)
    if entry is None or not entry.active or entry.curation_status != "APPROVED" or locale not in set(entry.supported_locales or []) or delivery_mode not in set(entry.delivery_modes or []):
        raise VoiceBindingError("VOICE_PROVIDER_NOT_AVAILABLE")
    return VoiceProfile(agent_id=agent_id, binding_id=f"admin:{assignment.id}", binding_version=str(assignment.version), locale=locale, provider=entry.provider_key, voice_id=entry.provider_voice_id, model=entry.provider_model, source_type="CURATED_PRESET", delivery_mode=delivery_mode, provider_profile_version="catalog")


def resolve_voice_profile(
    agent_id: str,
    locale: str,
    settings: Settings,
    *,
    delivery_mode: str,
    db: Session | None = None,
    tenant_id: str | None = None,
) -> VoiceProfile:
    if delivery_mode not in _ALLOWED_DELIVERY_MODES:
        raise VoiceBindingError("VOICE_DELIVERY_MODE_NOT_SUPPORTED")
    try:
        agent = resolve_agent_by_id(agent_id)
    except AgentNotFound as exc:
        raise VoiceBindingError("VOICE_BINDING_NOT_FOUND") from exc

    catalog_profile = _catalog_profile(agent.slug, locale, settings, delivery_mode=delivery_mode, db=db, tenant_id=tenant_id)
    if catalog_profile is not None:
        return catalog_profile

    binding_id = (agent.voice_binding_id or "").strip()
    if not binding_id:
        raise VoiceBindingError("VOICE_BINDING_NOT_FOUND")

    raw = _bindings(settings).get(binding_id)
    if not isinstance(raw, dict):
        raise VoiceBindingError("VOICE_BINDING_NOT_FOUND")
    if str(raw.get("agent_id") or agent.slug) != agent.slug:
        raise VoiceBindingError("VOICE_BINDING_AGENT_MISMATCH")
    if not bool(raw.get("enabled")):
        raise VoiceBindingError("VOICE_BINDING_DISABLED")
    if not bool(raw.get("validated")):
        raise VoiceBindingError("VOICE_PROFILE_NOT_VALIDATED", validation_scope="binding")

    delivery_modes = raw.get("delivery_modes")
    if delivery_modes is not None:
        if not isinstance(delivery_modes, list) or delivery_mode not in delivery_modes:
            raise VoiceBindingError("VOICE_DELIVERY_MODE_NOT_SUPPORTED")

    profiles = raw.get("locale_profiles")
    if not isinstance(profiles, dict):
        raise VoiceBindingError("VOICE_PROFILE_UNBOUND")
    profile = profiles.get(locale)
    if profile is None:
        raise VoiceBindingError("VOICE_LOCALE_NOT_SUPPORTED")
    if not isinstance(profile, dict):
        raise VoiceBindingError("VOICE_PROFILE_UNBOUND")
    if not bool(profile.get("enabled")):
        raise VoiceBindingError("VOICE_PROFILE_UNBOUND")
    if not bool(profile.get("validated")):
        raise VoiceBindingError("VOICE_PROFILE_NOT_VALIDATED", validation_scope="locale_profile")

    provider = str(profile.get("provider") or "").strip()
    voice_id = str(profile.get("voice_id") or "").strip()
    model = str(profile.get("model") or "").strip()
    if not provider or not voice_id or not model:
        raise VoiceBindingError("VOICE_PROFILE_UNBOUND")
    if provider == "disabled":
        raise VoiceBindingError("VOICE_PROVIDER_NOT_AVAILABLE")
    if settings.tts_provider not in {"disabled", provider} and delivery_mode == "MESSAGE_PLAYBACK":
        raise VoiceBindingError("VOICE_PROVIDER_NOT_AVAILABLE")

    return VoiceProfile(
        agent_id=agent.slug,
        binding_id=binding_id,
        binding_version=str(raw.get("binding_version") or "1"),
        locale=locale,
        provider=provider,
        voice_id=voice_id,
        model=model,
        source_type=str(profile.get("source_type") or "CURATED_PRESET"),
        delivery_mode=delivery_mode,
        provider_profile_version=str(profile.get("profile_version") or raw.get("binding_version") or "1"),
    )
