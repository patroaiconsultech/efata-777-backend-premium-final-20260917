from __future__ import annotations

import json

import pytest

from orkio_v2.config import Settings
from orkio_v2.services.voice_binding import VoiceBindingError, resolve_voice_profile


def _settings(*, binding_validated: bool, profile_validated: bool) -> Settings:
    value = {
        "voice_binding::orkio": {
            "agent_id": "orkio",
            "enabled": True,
            "validated": binding_validated,
            "delivery_modes": ["REALTIME_STREAM"],
            "locale_profiles": {
                "pt-BR": {
                    "provider": "openai",
                    "voice_id": "private-voice",
                    "model": "private-model",
                    "enabled": True,
                    "validated": profile_validated,
                }
            },
        }
    }
    return Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
        PLATFORM_VOICE_BINDINGS_JSON=json.dumps(value),
    )


def test_binding_validation_failure_keeps_public_code_and_adds_internal_scope():
    with pytest.raises(VoiceBindingError) as captured:
        resolve_voice_profile(
            "orkio",
            "pt-BR",
            _settings(binding_validated=False, profile_validated=True),
            delivery_mode="REALTIME_STREAM",
        )
    assert captured.value.code == "VOICE_PROFILE_NOT_VALIDATED"
    assert captured.value.validation_scope == "binding"


def test_locale_profile_validation_failure_keeps_public_code_and_adds_internal_scope():
    with pytest.raises(VoiceBindingError) as captured:
        resolve_voice_profile(
            "orkio",
            "pt-BR",
            _settings(binding_validated=True, profile_validated=False),
            delivery_mode="REALTIME_STREAM",
        )
    assert captured.value.code == "VOICE_PROFILE_NOT_VALIDATED"
    assert captured.value.validation_scope == "locale_profile"
