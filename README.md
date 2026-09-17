# ORKIO v2 Premium Backend — Functional Pre-OIDC Candidate

Secure modular monolith for the Plataforma Efatà 777 functional vertical slice.

Implemented:

- strict liveness and readiness separation;
- PostgreSQL URL normalization for Psycopg 3;
- Alembic runtime files included in the image;
- tenant-scoped thread creation, listing and history;
- provisioned-principal enforcement;
- owner/moderator invitation authorization;
- governed attachment upload;
- canonical ORKIO authorship in JSON, SSE and persistence;
- OpenAI-compatible LLM integration with configurable API base;
- terminal SSE contract: `status`, `chunk`, optional `error`, always `done`;
- OIDC introspection with active, issuer, audience, user and tenant checks;
- preview-first identity bootstrap script.

## Local validation

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
```

## Migrations

The Docker image contains `alembic.ini` and `migrations/`. Use a controlled
Railway pre-deploy command:

```bash
alembic upgrade head
```

Do not run migrations against SQLite in production.

## Identity bootstrap

Preview is the default:

```bash
python scripts/bootstrap_identity.py \
  --tenant-id '<tenant_id claim>' \
  --tenant-name 'Efatà 777' \
  --user-id '<sub claim>' \
  --external-subject '<sub claim>' \
  --email 'owner@example.com' \
  --display-name 'Owner'
```

Writing requires both `--apply` and `--confirm APPLY_BOOTSTRAP`.

Production must remain `external_required` until the OIDC provider and SPA
client are fully configured and tested.
