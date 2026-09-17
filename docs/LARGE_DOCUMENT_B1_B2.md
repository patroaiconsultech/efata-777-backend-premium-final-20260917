# Large Document B1+B2 — Canonical Document Layer + Selective Context

## Purpose

This feature adds a bounded-memory Knowledge Plane path for large documents.
It does **not** raise the legacy thread-attachment upload limit.

Pipeline:

`source -> staged stream -> immutable blob -> canonical Markdown -> structure/chunks -> manual/automatic selection -> bounded LLM context`

The original source remains the provenance authority.

## Feature flags and limits

Recommended controlled staging values after migration:

```text
PLATFORM_LARGE_DOCUMENT_PIPELINE_ENABLED=true
PLATFORM_KNOWLEDGE_SELECTIVE_CONTEXT_ENABLED=true
PLATFORM_KNOWLEDGE_MAX_UPLOAD_BYTES=524288000
PLATFORM_KNOWLEDGE_AUTO_PROCESS_BYTES=32000000
PLATFORM_KNOWLEDGE_MAX_PDF_PAGES=5000
PLATFORM_KNOWLEDGE_CHUNK_TARGET_CHARS=6000
PLATFORM_KNOWLEDGE_CHUNK_OVERLAP_CHARS=500
PLATFORM_KNOWLEDGE_RETRIEVAL_TOP_K=12
```

`PLATFORM_MAX_UPLOAD_BYTES` remains the legacy attachment limit and should not be
raised to 500 MiB as part of this rollout.

## Processing model

Files up to `PLATFORM_KNOWLEDGE_AUTO_PROCESS_BYTES` may be canonicalized during
the upload request. Larger files remain `PENDING`.

Operators can process pending files in a controlled worker/job:

```bash
python scripts/process_pending_knowledge.py --limit 1
```

The worker logs metadata only, never document contents.

## Navigator API

```text
POST /api/v2/knowledge/{document_id}/process
GET  /api/v2/knowledge/{document_id}/structure
PUT  /api/v2/knowledge/{document_id}/selection
GET  /api/v2/knowledge/{document_id}/content
```

Manual mode persists selected section IDs per tenant/user/document.
Automatic mode ranks bounded chunks lexically against the current user query.

## Rollout

1. Apply additive migration `007_large_document_b1_b2`.
2. Keep both feature flags disabled.
3. Run baseline regression suite and DB migration smoke.
4. Enable pipeline in staging.
5. Upload small TXT/PDF and validate canonical derivative.
6. Upload a file above the auto-process threshold; verify `PENDING`.
7. Run one worker item and verify `READY`.
8. Enable selective context in staging.
9. Validate manual and automatic Navigator modes.
10. Only then exercise the 500 MiB boundary with a synthetic sparse/non-sensitive test file suitable for the parser under test.

## Rollback

Set:

```text
PLATFORM_KNOWLEDGE_SELECTIVE_CONTEXT_ENABLED=false
PLATFORM_LARGE_DOCUMENT_PIPELINE_ENABLED=false
```

The legacy Knowledge Plane remains available.
Migration 007 is additive and can be downgraded only under explicit maintenance approval.
Original blobs are never deleted as part of feature rollback.

## Known boundaries

- Scanned PDFs may return `OCR_REQUIRED`; OCR is not silently invoked.
- Canonical Markdown improves representation but token savings come from selective context.
- Large parsing is still format-dependent; upload acceptance does not guarantee extraction success.
- The source blob is retained for audit and reprocessing.
