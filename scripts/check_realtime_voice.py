from __future__ import annotations

import argparse
import json
from typing import Any

from orkio_v2.agents.catalog import AGENTS
from orkio_v2.config import Settings, get_settings
from orkio_v2.services.realtime_session import realtime_capability
from orkio_v2.services.speech_to_text import inspect_stt_readiness


def inspect_voice_bindings(
    settings: Settings,
    *,
    agent_id: str | None = None,
    locale: str = "pt-BR",
) -> dict[str, Any]:
    """Read-only structural validation. Never emits the raw binding JSON or profile values."""
    raw_value = settings.voice_bindings_json or "{}"

    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError:
        return {
            "json_parse": "FAIL",
            "root_object": "NOT_CHECKED",
            "binding_count": 0,
            "required_bindings": {},
            "ready": False,
            "reason_code": "VOICE_BINDINGS_CONFIG_INVALID",
        }

    if not isinstance(parsed, dict):
        return {
            "json_parse": "PASS",
            "root_object": "FAIL",
            "binding_count": 0,
            "required_bindings": {},
            "ready": False,
            "reason_code": "VOICE_BINDINGS_CONFIG_INVALID",
        }

    required: dict[str, Any] = {}
    selected_agents = [
        agent for agent in AGENTS
        if not agent_id or agent.slug == agent_id
    ]

    for agent in selected_agents:
        binding_id = str(agent.voice_binding_id or "").strip()
        if not binding_id:
            continue

        binding = parsed.get(binding_id)
        found = isinstance(binding, dict)
        result: dict[str, Any] = {
            "agent_id": agent.slug,
            "found": found,
            "enabled": False,
            "validated": False,
            "locale": locale,
            "locale_profile": {
                "found": False,
                "enabled": False,
                "validated": False,
                "provider_set": False,
                "voice_id_set": False,
                "model_set": False,
            },
        }

        if found:
            result["enabled"] = bool(binding.get("enabled"))
            result["validated"] = bool(binding.get("validated"))
            profiles = binding.get("locale_profiles")
            if isinstance(profiles, dict):
                profile = profiles.get(locale)
                if isinstance(profile, dict):
                    result["locale_profile"] = {
                        "found": True,
                        "enabled": bool(profile.get("enabled")),
                        "validated": bool(profile.get("validated")),
                        "provider_set": bool(str(profile.get("provider") or "").strip()),
                        "voice_id_set": bool(str(profile.get("voice_id") or "").strip()),
                        "model_set": bool(str(profile.get("model") or "").strip()),
                    }

        required[binding_id] = result

    states = list(required.values())
    complete = bool(states) and all(
        state["found"]
        and state["enabled"]
        and state["validated"]
        and state["locale_profile"]["found"]
        and state["locale_profile"]["enabled"]
        and state["locale_profile"]["validated"]
        and state["locale_profile"]["provider_set"]
        and state["locale_profile"]["voice_id_set"]
        and state["locale_profile"]["model_set"]
        for state in states
    )

    if agent_id and not selected_agents:
        reason = "VOICE_AGENT_NOT_FOUND"
    elif not required:
        reason = "VOICE_BINDINGS_REQUIRED_BINDINGS_EMPTY"
    elif complete:
        reason = "VOICE_BINDINGS_CONFIG_READY"
    else:
        reason = "VOICE_BINDINGS_CONFIG_INCOMPLETE"

    return {
        "json_parse": "PASS",
        "root_object": "PASS",
        "binding_count": len(parsed),
        "required_bindings": required,
        "ready": complete,
        "reason_code": reason,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only Realtime/Voice readiness preflight.")
    parser.add_argument("--agent-id", default=None, help="Optional agent filter, e.g. orkio.")
    parser.add_argument("--locale", default="pt-BR", help="Locale profile to inspect.")
    return parser


def main() -> None:
    args = _parser().parse_args()
    settings = get_settings()
    payload = {
        "environment": settings.environment,
        "release_sha": settings.release_sha,
        "realtime": realtime_capability(settings),
        "stt": inspect_stt_readiness(settings),
        "voice_bindings": inspect_voice_bindings(
            settings,
            agent_id=args.agent_id,
            locale=args.locale,
        ),
        "provider_configuration_state": (
            "configured" if (settings.openai_api_key or "").strip() else "unconfigured"
        ),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
