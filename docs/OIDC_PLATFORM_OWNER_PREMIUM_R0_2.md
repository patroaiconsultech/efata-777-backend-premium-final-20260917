# ORKIO OIDC + Platform Owner Premium R0.2

Status: PROPOSAL_ONLY

## Scope

This revision hardens the R0.1 OIDC identity contract without changing schema:

1. ZITADEL canonical tenant claim is the default:
   `urn:zitadel:iam:user:resourceowner:id`.
2. ZITADEL project-role mapping claim observed by runtime diagnostics is the default:
   `urn:zitadel:iam:org:project:roles`.
3. Both claims remain overridable through the existing Railway variables
   `PLATFORM_OIDC_TENANT_CLAIM` and `PLATFORM_OIDC_ROLES_CLAIM`.
4. Test authentication now carries an explicit immutable external subject through
   `X-Test-Subject`; the test subject is not inferred by production code.
5. Effective authorization remains canonical in ORKIO memberships.
6. `PLATFORM_OWNER_SUBJECT` still cannot bypass tenant/user provisioning or the
   required active `admin` membership.

## Runtime incident addressed

Observed runtime signature:

- `TENANT_CLAIM_MISSING`
- configured tenant claim absent
- ZITADEL resource-owner claim present
- generic ZITADEL project-roles claim present

R0.2 aligns the default provider mapping with that observed claim contract while
remaining fail-closed.

## Security invariants

- No global-tenant fallback.
- No e-mail-based platform-owner grant.
- No provider role grants effective ORKIO authorization by itself.
- No automatic tenant/user/membership creation.
- No token or claim value logging.
- Cross-tenant role mappings remain filtered by canonical tenant.
- Production test headers remain forbidden by the existing auth-mode/environment
  controls.

## No migration

No database schema or migration file is changed by R0.2.

## Configuration

The following are now code defaults and normally do not need to be added merely
to fix the missing-claim incident:

```text
PLATFORM_OIDC_USER_CLAIM=sub
PLATFORM_OIDC_TENANT_CLAIM=urn:zitadel:iam:user:resourceowner:id
PLATFORM_OIDC_ROLES_CLAIM=urn:zitadel:iam:org:project:roles
```

Provider-specific overrides remain available when intentionally required.

`PLATFORM_OWNER_SUBJECT` is separate and must only be set to the exact verified
immutable OIDC `sub`.

## Smoke after controlled deployment

1. `GET /api/v2/ready`
2. fresh OIDC login
3. `GET /api/v2/threads`
4. verify no `TENANT_CLAIM_MISSING`
5. verify a non-provisioned identity still fails closed
6. verify tenant-negative access
7. verify `platform_owner` only for exact subject + active admin membership
8. verify logs contain diagnostic booleans/types only, never claim values
