# GITHUB GATE

Status: `PREPARED / HUMAN_ACTION_REQUIRED / DEPLOY_NOT_AUTHORIZED`

Allowed:
- create a branch;
- upload these exact repository bytes;
- open a Pull Request;
- run read-only/static repository inspection;
- run local/unit CI that has no external Railway/DB/deploy side effects;
- human review.

Required before merge:
- protected branch policy;
- PR required;
- human review;
- secret scanning / push protection where supported;
- dependency scanning appropriate to repository plan;
- SAST/code scanning appropriate to repository plan;
- review of SBOM;
- exact final hash review after any PR change.

Explicitly NOT authorized:
- auto-merge;
- Railway execution;
- Fase A real;
- Fase B;
- SSH;
- database access;
- Alembic;
- migration 008;
- restart/redeploy;
- production.

Any repository modification creates a new candidate and invalidates previous artifact hashes.
