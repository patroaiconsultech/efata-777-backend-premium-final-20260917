# PatroAI Platform — Realtime + Voice staging enablement

Status: **candidate configuration only — audit before deploy**

This runbook is intentionally separate from auth/bootstrap. It does not create users,
tenants, roles, migrations, seeds, or production changes.

## 1. Preconditions

Before enabling Realtime/Voice in staging, prove:

- text chat returns a real LLM response;
- authenticated tenant/session are correct;
- selected agent remains the persisted/displayed owner;
- SSE always terminates with `done` or `error + done`;
- `OPENAI_API_KEY` is configured in the backend runtime;
- rollback is available by returning the feature flags below to `false/disabled`.

## 2. Canonical Realtime path already present in this baseline

The backend current source includes:

- `src/orkio_v2/realtime_routes.py`
- `src/orkio_v2/services/realtime_session.py`
- `src/orkio_v2/services/realtime_bridge.py`
- `src/orkio_v2/services/realtime_execution.py`
- `src/orkio_v2/services/realtime_segmenter.py`
- `src/orkio_v2/services/voice_binding.py`
- `src/orkio_v2/services/text_to_speech.py`
- `src/orkio_v2/services/speech_to_text.py`

The provider Realtime session is transport/VAD/transcription-only. The assistant response
must remain server-side and pass through the canonical PatroAI execution/persistence path.

## 3. Staging flags — Realtime canonical voice

Do not copy placeholder secrets into production. Keep the existing OpenAI secret in Railway.

```text
PLATFORM_REALTIME_STREAMING_ENABLED=true
PLATFORM_REALTIME_VOICE_ENABLED=true
PLATFORM_VOICE_PROVIDER=openai
PLATFORM_REALTIME_BRIDGE_ENABLED=true
PLATFORM_REALTIME_TRANSCRIPTION_MODEL=gpt-4o-mini-transcribe

PLATFORM_TTS_ENABLED=true
PLATFORM_TTS_PROVIDER=openai
PLATFORM_TTS_HTTP_TIMEOUT_SECONDS=20
PLATFORM_TTS_MAX_CHARS=4096
PLATFORM_TTS_CACHE_ENABLED=true
PLATFORM_TTS_CACHE_PATH=./data/tts-cache
```

Voice binding is mandatory for canonical speech output. Example **shape only**:

```json
{
  "voice_binding::orkio": {
    "binding_version": "1",
    "enabled": true,
    "validated": true,
    "locale_profiles": {
      "pt-BR": {
        "provider": "openai",
        "voice_id": "marin",
        "model": "gpt-4o-mini-tts",
        "enabled": true,
        "validated": true
      }
    }
  }
}
```

Store the JSON as:

```text
PLATFORM_VOICE_BINDINGS_JSON=<validated JSON>
```

Do not mark a voice profile `validated=true` until an actual provider smoke has passed.

## 4. Voice Message STT

The current non-Realtime voice-message path uses local `faster_whisper`. Enable separately:

```text
PLATFORM_STT_ENABLED=true
PLATFORM_STT_PROVIDER=faster_whisper
PLATFORM_STT_MODEL=small
PLATFORM_STT_DEVICE=cpu
PLATFORM_STT_COMPUTE_TYPE=int8
PLATFORM_STT_ALLOWED_LANGUAGES=pt,en,es
PLATFORM_STT_TIMEOUT_SECONDS=45
PLATFORM_STT_CONCURRENCY_LIMIT=1
```

For production, current settings validation requires a prewarmed local model
(`PLATFORM_STT_LOCAL_FILES_ONLY=true`). Staging must also prove model availability before demo.

## 5. Read-only preflight

Run inside the backend container:

```bash
python scripts/check_realtime_voice.py
```

Expected before activation: structured `eligible=false` reasons.
Expected after complete configuration: session, bridge, input, output and segment streaming
become eligible. `runtime_proven` remains false until a real device/runtime smoke proves it.

## 6. Mandatory device smoke

1. Login with the existing Native Auth/MFA account.
2. Select/create a thread.
3. Select the Cocriador explicitly.
4. Start Realtime.
5. Confirm WebRTC connects.
6. Speak one short sentence.
7. Confirm one final transcript only.
8. Confirm exactly one persisted user message.
9. Confirm canonical agent identity is unchanged.
10. Confirm canonical assistant message persists.
11. Confirm TTS plays the same persisted response.
12. Interrupt speech and verify playback queue cleanup/barge-in.
13. Switch threads and verify old audio/session cannot contaminate the new thread.
14. Disable Realtime and prove normal SSE chat still works.

## 7. Rollback

Set:

```text
PLATFORM_REALTIME_VOICE_ENABLED=false
PLATFORM_VOICE_PROVIDER=disabled
PLATFORM_REALTIME_BRIDGE_ENABLED=false
PLATFORM_TTS_ENABLED=false
PLATFORM_TTS_PROVIDER=disabled
PLATFORM_STT_ENABLED=false
PLATFORM_STT_PROVIDER=disabled
```

Redeploy backend. Text chat/SSE remains the primary fallback.

## 8. Premium preflight for voice bindings

Before any Realtime call, run the read-only preflight against the target agent:

```bash
python scripts/check_realtime_voice.py --agent-id orkio --locale pt-BR
```

For the current Cocriador binding, require at minimum:

```text
voice_bindings.json_parse=PASS
voice_bindings.root_object=PASS
voice_binding::orkio.found=true
voice_binding::orkio.enabled=true
locale_profile.found=true
provider_set=true
voice_id_set=true
model_set=true
```

The preflight intentionally reports validation state separately. It never prints the raw
`PLATFORM_VOICE_BINDINGS_JSON`, provider secret, `voice_id`, model value, or profile payload.

## 9. Gate 015 — staging-only provider smoke before validation promotion

`validated=true` is not a substitute for a provider smoke. When a profile is structurally
configured but still unvalidated, use the administrative CLI:

```bash
python scripts/smoke_voice_provider.py \
  --agent-id orkio \
  --locale pt-BR \
  --confirm-provider-call
```

Hard guards:

- staging only;
- exactly one provider request;
- no automatic retry;
- fixed, non-sensitive smoke text;
- no HTTP endpoint;
- no DB write;
- no ENV mutation;
- no cache write;
- no automatic change to either `validated` flag;
- no raw JSON, API key, Authorization header, `voice_id`, model value, provider response
  body, audio bytes, or provider request id printed.

A PASS requires all of:

```text
HTTP 2xx
Content-Type explicitly MP3-compatible (`audio/mpeg` or `audio/mp3`)
non-empty audio body
MP3 structural validation (optional valid ID3v2 header + two complete consecutive MPEG audio frames)
```

`application/octet-stream` is intentionally rejected because it does not prove audio.
A bare `ID3` prefix or isolated MPEG sync prefix is not accepted. The smoke requires two complete consecutive MPEG frames, optionally after a structurally valid ID3v2 header.
The evidence also reports only:

```text
provider_endpoint_class=DEFAULT_OPENAI | CUSTOM_CONFIGURED
```

It never prints the configured provider URL/hostname.

After and only after the provider smoke is independently reviewed as PASS, a human may promote:

```text
voice_binding::orkio.validated=true
voice_binding::orkio.locale_profiles.pt-BR.validated=true
```

Then redeploy staging and retry one canonical Realtime call. The disappearance of
`VOICE_PROFILE_NOT_VALIDATED` proves only that the validation gate was crossed; it does not by
itself prove WebRTC, transcription, canonical execution, TTS playback, or barge-in.

## 10. Gate 015 human authorization template

```text
GATE 015 — STAGING ORKIO VOICE PROVIDER SMOKE

Authorized:
one OpenAI TTS provider call in staging for orkio / pt-BR.

Forbidden:
ENV mutation, validated mutation, DB writes, migrations, tenant/auth changes,
WebRTC, STT, automatic retry, secret logging, raw binding JSON logging,
voice/model value logging, response-body/audio logging.

Expected evidence:
HTTP success + audio content type + non-empty audio.

Any other result:
FAIL + STOP.
```

