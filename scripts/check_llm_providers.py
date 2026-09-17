from __future__ import annotations

import argparse
import asyncio
import json

from orkio_v2.config import get_settings
from orkio_v2.services.llm_contracts import ProviderConfigurationState
from orkio_v2.services.model_gateway import ModelGateway


def _descriptor_dict(item) -> dict[str, str]:
    return {
        "provider": item.provider.value,
        "model": item.model,
        "configuration_state": item.state.value,
    }


async def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safe ORKIO LLM provider status. Never prints API keys."
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="Call provider model metadata endpoints to prove READY/UNAVAILABLE.",
    )
    args = parser.parse_args()

    settings = get_settings()
    gateway = ModelGateway(settings)
    descriptors = gateway.descriptors()
    report: dict[str, object] = {
        "primary_provider": settings.llm_primary_provider,
        "providers": [],
    }

    providers: list[dict[str, str]] = []
    for item in descriptors:
        row = _descriptor_dict(item)
        if args.probe and item.state is ProviderConfigurationState.configured:
            health = await gateway.healthcheck(item.provider)
            row["health_state"] = health.state.value
            if health.code:
                row["health_code"] = health.code
        providers.append(row)

    report["providers"] = providers
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
