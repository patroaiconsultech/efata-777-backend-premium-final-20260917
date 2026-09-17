from __future__ import annotations

import json

from orkio_v2.config import Settings
from scripts.check_realtime_voice import inspect_voice_bindings


def _settings(value: str) -> Settings:
    return Settings(PLATFORM_VOICE_BINDINGS_JSON=value)


def test_preflight_rejects_malformed_json_without_echoing_value():
    secretish = '{"voice_binding::orkio":{"token":"should-not-echo"'
    result = inspect_voice_bindings(_settings(secretish), agent_id="orkio")
    assert result["json_parse"] == "FAIL"
    assert result["root_object"] == "NOT_CHECKED"
    assert result["reason_code"] == "VOICE_BINDINGS_CONFIG_INVALID"
    assert "should-not-echo" not in repr(result)


def test_preflight_rejects_non_object_root():
    result = inspect_voice_bindings(_settings("[]"), agent_id="orkio")
    assert result["json_parse"] == "PASS"
    assert result["root_object"] == "FAIL"
    assert result["reason_code"] == "VOICE_BINDINGS_CONFIG_INVALID"


def test_preflight_reports_missing_orkio_binding():
    result = inspect_voice_bindings(_settings("{}"), agent_id="orkio")
    state = result["required_bindings"]["voice_binding::orkio"]
    assert result["root_object"] == "PASS"
    assert state["found"] is False
    assert result["ready"] is False


def test_preflight_distinguishes_binding_and_profile_validation_state():
    value = json.dumps({
        "voice_binding::orkio": {
            "agent_id": "orkio",
            "enabled": True,
            "validated": False,
            "locale_profiles": {
                "pt-BR": {
                    "provider": "openai",
                    "voice_id": "private-voice-value",
                    "model": "private-model-value",
                    "enabled": True,
                    "validated": True,
                }
            },
        }
    })
    result = inspect_voice_bindings(_settings(value), agent_id="orkio")
    state = result["required_bindings"]["voice_binding::orkio"]
    assert state["validated"] is False
    assert state["locale_profile"]["validated"] is True
    assert state["locale_profile"]["provider_set"] is True
    assert state["locale_profile"]["voice_id_set"] is True
    assert state["locale_profile"]["model_set"] is True
    rendered = repr(result)
    assert "private-voice-value" not in rendered
    assert "private-model-value" not in rendered


def test_preflight_can_focus_one_agent_without_hardcoded_binding_list():
    value = json.dumps({
        "voice_binding::orkio": {
            "agent_id": "orkio",
            "enabled": True,
            "validated": True,
            "locale_profiles": {
                "pt-BR": {
                    "provider": "openai",
                    "voice_id": "voice-x",
                    "model": "model-x",
                    "enabled": True,
                    "validated": True,
                }
            },
        }
    })
    result = inspect_voice_bindings(_settings(value), agent_id="orkio")
    assert list(result["required_bindings"]) == ["voice_binding::orkio"]
    assert result["reason_code"] == "VOICE_BINDINGS_CONFIG_READY"
    assert result["ready"] is True
