# EFATA 777 — LLM-P0-C — GitHub upload

This package contains ONLY the three modified repository files.

Do NOT upload this ZIP itself into the repository root expecting GitHub to extract it.
GitHub does not apply the contained paths automatically from a ZIP.

After extracting locally, replace exactly:

1. `src/orkio_v2/services/llm_contracts.py`
2. `src/orkio_v2/services/llm_providers.py`
3. `tests/test_llm_observability_contract.py`

Do not change:

- `src/orkio_v2/routes.py`
- `src/orkio_v2/config.py`
- frontend
- DB/migrations
- timeout/retry/failover/provider settings

Safety note:

The canonical single-process full backend suite remains OPEN. Therefore this package is a
controlled local materialization, not a production/deploy approval.

If the GitHub `main` branch auto-deploys to Railway, upload these files to a separate branch first,
not directly to `main`.
