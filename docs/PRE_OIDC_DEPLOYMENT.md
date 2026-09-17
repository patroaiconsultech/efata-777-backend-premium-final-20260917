> **HISTORICAL / ARCHIVED — NÃO USAR COMO RUNBOOK OPERACIONAL ATUAL.**
> Este documento registra um estágio pré-OIDC. O migration head e a configuração
> operacional devem ser obtidos do release manifest gerado pelo CI e do código
> atualmente implantado. No baseline auditado em 2026-08-31, o head observado é
> `006_knowledge_plane_hardening`.

# Backend deployment order — Functional Pre-OIDC

## 1. Source and build

The Docker image includes:

```text
alembic.ini
migrations/
scripts/
src/
```

The dependency set uses Psycopg 3. Railway `postgresql://` URLs are normalized
to `postgresql+psycopg://` in application and Alembic paths.

## 2. Migration

Run as a controlled Railway pre-deploy command:

```bash
alembic upgrade head
```

Then require:

```text
GET /api/v2/ready = 200
migration_head = 001_v2_foundation
migration_current = true
schema_complete = true
```

## 3. Safe pre-OIDC mode

```text
PLATFORM_AUTH_MODE=external_required
PLATFORM_ARTIFACTS_ENABLED=false
PLATFORM_GITHUB_INTEGRATION_ENABLED=false
PLATFORM_GITHUB_READ_ONLY=true
PLATFORM_REALTIME_VOICE_ENABLED=false
PLATFORM_EVOLUTION_EXECUTION_ALLOWED=false
```

## 4. OIDC activation

Use two clients:

```text
frontend SPA client:
  public client
  Authorization Code + PKCE
  no client secret

backend introspection client:
  confidential client
  client_secret_basic
  dedicated secret
```

Fill all five backend OIDC values before changing the auth mode:

```text
PLATFORM_OIDC_ISSUER
PLATFORM_OIDC_AUDIENCE
PLATFORM_OIDC_INTROSPECTION_ENDPOINT
PLATFORM_OIDC_INTROSPECTION_CLIENT_ID
PLATFORM_OIDC_INTROSPECTION_CLIENT_SECRET
```

The introspection response must include `active`, `iss`, `aud`, `sub`,
`tenant_id` and the configured roles claim.

## 5. Identity bootstrap

Use `scripts/bootstrap_identity.py` in preview mode first. User ID must match
the configured OIDC user claim (`sub` by default), and tenant ID must match
`tenant_id`.

## 6. Attachments

Keep attachments disabled until a persistent Railway volume is mounted at
`/data` and the application path `/data/artifacts` is writable.
