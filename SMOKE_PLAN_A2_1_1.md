# ORKIO A2.1.1 Voice/STT — Explicit Smoke Plan

Purpose: prove Demo Readiness after branch application and before B1.

## Preconditions

- Exact backend/frontend commits recorded.
- A2.1.1 applied on controlled branch.
- Docker image built with the pinned STT extra.
- `PLATFORM_STT_ENABLED=true`.
- `PLATFORM_STT_PROVIDER=faster_whisper`.
- `PLATFORM_STT_LOCAL_FILES_ONLY=true`.
- `PLATFORM_STT_TIMEOUT_SECONDS` explicitly configured.
- `PLATFORM_STT_CONCURRENCY_LIMIT` explicitly configured.
- model prewarm completed and `/api/v2/voice/stt/readiness` returns HTTP 200 with `ready=true`.
- Node 20.20.2 / npm 10.8.2 frontend build passes.

## Smoke A — Canonical Voice Message / real PT-BR

1. Authenticate as a writable member.
2. Select Thread A.
3. Select an explicit agent.
4. Grant mic permission.
5. Record real PT-BR speech.
6. Stop recording.
7. Confirm upload is sent to Thread A.
8. Confirm STT returns a plausible transcript.
9. Confirm transcript appears for human review and is not auto-sent.
10. Edit/review text if desired.
11. Explicitly send.
12. Confirm the message is sent to the same thread.
13. Confirm the same selected agent owns the canonical text turn.
14. Confirm persisted canonical message matches UI.
15. Confirm mic released after recording/transcription.

Success criteria:
`same thread` + `same selected agent` + human review + explicit send + persisted message + mic released.

## Smoke B — Thread-switch isolation

1. Select Thread A.
2. Start recording or transcription.
3. Before STT completes: `record Thread A` → `switch Thread B`.
4. Confirm the STT request for A is aborted or its result is invalidated.
5. Confirm zero transcript from A appears in Thread B composer.
6. Confirm microphone/timers/chunks are released.
7. Confirm B remains clean.

Success criteria:
`record Thread A` → `switch Thread B` → A cancelled/ignored → zero transcript contamination in B.

## Smoke C — Readiness semantics

- STT disabled → `/api/v2/voice/stt/readiness` returns 503 with `reason=STT_DISABLED`.
- dependency missing → 503.
- model not prewarmed → 503.
- fully ready → 200 with `ready=true`.

## Smoke D — Timeout

Force or simulate inference beyond configured timeout.

Expected:
- HTTP 504 / `STT_TIMEOUT`;
- temp audio removed;
- no transcript persisted/logged;
- capacity remains reserved until worker finishes;
- subsequent healthy request succeeds after release.

## Smoke E — Concurrency

With `PLATFORM_STT_CONCURRENCY_LIMIT=1`, hold one inference active and start a second.

Expected:
- second request fails with `STT_CONCURRENCY_LIMIT_REACHED`;
- first remains isolated and completes/cancels normally;
- no audio/transcript logged.

## Smoke F — Authorization / media validation

- viewer → 403 before STT execution;
- non-member → 403 before STT execution;
- content-type/signature mismatch → 415 before STT execution;
- oversized audio → 413;
- empty audio → 422.

## Observability

Confirm safe events exist:

- `STT_REQUEST_STARTED`
- `STT_REQUEST_COMPLETED`
- `STT_REQUEST_FAILED`
- `duration_ms`
- `locale`
- `audio_size`
- `model`

Logs MUST NOT contain raw audio or transcript text.

## Rollback

If any critical smoke fails: rollback A2.1.1 to the previously audited A2.1 candidate, then re-run:
- backend focused/full suite;
- frontend focused/full suite;
- readiness;
- typed chat smoke.

No merge/deploy approval should be issued until all mandatory smokes are green.
