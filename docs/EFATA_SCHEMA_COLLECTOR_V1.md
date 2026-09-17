# EFATÁ Schema Collector v1 — DRAFT-02-R1

Proposal: `EFATA-BE-COLLECTOR-LOCAL-001`

Status: local-only qualification implementation. This tool is **not** an operational
runtime component, migration runner, or remote database inventory client.

## Scope

The collector core:

- receives an already-open restricted DB-API connection;
- does not create network/database connections;
- supports PostgreSQL 16 qualification semantics only;
- requires `REPEATABLE READ` + `READ ONLY`;
- pins the collector session profile;
- executes a closed `pg_catalog` query pack;
- captures structural and database-security manifests;
- fails closed when capture completeness is not positively proven;
- keeps schema compatibility separate from authorization/security compatibility.

The local fixture harness is test-only privileged code. It starts a disposable
PostgreSQL 16 cluster with TCP disabled and a private Unix socket. After fixture
construction, `pg_hba.conf` is tightened so the bootstrap role cannot open a new
session. Only the restricted collector role can connect to the fixture database.

## Explicit non-scope

This proposal MUST NOT:

- change `src/**`;
- change `migrations/**` or run Alembic;
- change dependencies, Dockerfile, or CI workflows;
- connect to staging/production/existing PostgreSQL;
- commit, push, open PR, merge, deploy, or touch Railway.

## Qualification gates

`PASS_LOCAL` requires all of:

1. build/import validation;
2. focused deterministic tests;
3. security negative tests;
4. disposable PostgreSQL 16 fixture tests;
5. fixture privilege transition evidence;
6. completeness oracle tests;
7. role authority/path tests;
8. function fingerprint tests;
9. lifecycle cleanup tests;
10. full collector suite;
11. zero critical skips;
12. source-boundary scan;
13. rollback proof.

A unit-test pass alone does not imply `PASS_LOCAL`.

## Independent oracle

`fixture_ground_truth_v1.json` is intentionally shipped as a developer draft.
It cannot qualify capture completeness until independently reviewed and changed
to the approved static-contract state. The qualification path rejects an
unapproved/non-independent oracle.

## Connection attestation

Trust is derived from observed connection facts plus fixture attestation, not a
Python wrapper type. The local qualification transport is Unix socket only;
non-null inet client/server address facts fail closed.

## Security-sensitive functions

Initial supported language contract: `sql` and `plpgsql`. Fingerprints detect
change; they do not claim semantic equivalence. Unsupported security-definer
languages are `INCONCLUSIVE`.

## Role authority

PostgreSQL 16 membership edges preserve `INHERIT`, `SET`, and `ADMIN` options.
Derived exercisable authority retains physical proof paths. Summary authority
never replaces provenance.

## Historical migration findings

This collector does not repair:

- `EFATA-MIG-FND-002` historical `create_all` metadata drift;
- `EFATA-MIG-FND-003` historical `drop_all` metadata drift;
- `EFATA-MIG-FND-004` unknown real `@009` schema cardinality.

It exists to generate evidence for the later A1/B/C migration decision.
