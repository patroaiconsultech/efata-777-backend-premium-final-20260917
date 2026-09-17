# ORKIO OIDC + Platform Owner Premium R0.1

Status: PROPOSAL_ONLY  
Source baseline: `afe38e379c844e481ffe34f574895703cb1c8df9` (GitHub `main` observed on 2026-08-07)  
Railway deployment observed: `956daa46-bece-42a9-8339-c620b39b95de`  
Exact Git commit of that Railway deployment: **NOT_PROVEN**

## Contract

1. ZITADEL/OIDC authenticates identity (`iss`, `sub`, `aud`).
2. OIDC claim normalization is fail-closed.
3. ZITADEL role mappings are filtered by the canonical tenant.
4. Effective authorization roles come from ORKIO `memberships`, not from provider claims.
5. `PLATFORM_OWNER_SUBJECT` never bypasses OIDC or database provisioning.
6. The platform-owner subject receives the `platform_owner` marker only when:
   - the OIDC subject matches exactly;
   - tenant and user exist;
   - external subject matches the user row;
   - an active membership exists;
   - membership role is exactly `admin`.
7. Thread ownership remains the existing thread-level mechanism.

## Recommended Railway values after branch validation

```text
PLATFORM_OIDC_USER_CLAIM=sub
PLATFORM_OIDC_TENANT_CLAIM=urn:zitadel:iam:user:resourceowner:id
PLATFORM_OIDC_ROLES_CLAIM=urn:zitadel:iam:org:project:385220733510354436:roles
PLATFORM_OWNER_SUBJECT=<EXACT_VERIFIED_ZITADEL_SUB>
```

Do not infer `PLATFORM_OWNER_SUBJECT` from e-mail. Verify the immutable `sub`.

## Bootstrap

Reuse the existing governed script. Preview first:

```bash
python scripts/bootstrap_identity.py \
  --tenant-id '<verified tenant claim>' \
  --tenant-name 'Patroai' \
  --user-id '<verified sub>' \
  --external-subject '<verified sub>' \
  --email '<owner email>' \
  --display-name 'Owner' \
  --role admin
```

Writing remains a separate human gate and requires the script's existing
`--apply --confirm APPLY_BOOTSTRAP` mechanism.

## No migration

This patch does not alter schema or migrations.
