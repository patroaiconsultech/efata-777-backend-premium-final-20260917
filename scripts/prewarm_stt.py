from __future__ import annotations

import json

from orkio_v2.config import get_settings
from orkio_v2.services.speech_to_text import SpeechToTextError, prewarm_stt_model


def main() -> int:
    settings = get_settings()
    if settings.stt_provider != "faster_whisper":
        print(json.dumps({"ready": False, "code": "STT_PROVIDER_UNAVAILABLE"}))
        return 2
    try:
        result = prewarm_stt_model(settings)
    except SpeechToTextError as exc:
        print(json.dumps({"ready": False, "code": exc.code}))
        return 3
    print(json.dumps({"ready": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
