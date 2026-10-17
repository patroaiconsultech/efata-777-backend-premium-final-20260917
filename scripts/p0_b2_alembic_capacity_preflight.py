#!/usr/bin/env python3
"""DG-01 P0 B2.1 v2: explicit, fail-closed Alembic version capacity preflight.

Proposal only. Does not run Alembic migrations or modify application tables.
Defaults to a READ ONLY transaction. Apply mode requires separate AO-01/operator
approval, staging identity proof and human acknowledgement.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import sys
import hashlib
from pathlib import Path
from dataclasses import dataclass
from typing import Any

import sqlalchemy as sa
from sqlalchemy.engine import make_url

TOOL_VERSION = "DG01-P0-B2.1-20261017-v2"
SOURCE_COMMIT = "915bdc6186f36b759b21a6fe15ae6aa2bc6b330b"
EXPECTED_STAGING_SYSTEM_ID = "7696494375094112315"
KNOWN_PRODUCTION_SYSTEM_ID = "7685726733043150913"
STAGING_ENV = "staging-web01"
INITIAL_REVISIONS = ("013_agent_studio_control_plane", "014_thread_agent_grants")
TARGET_SIZE = 64
ACK_TEXT = "B2-ONLY-STAGING-NO-PRODUCTION"
# Independent copy of original migration hashes from B41 source snapshot,
# source tree reviewed against commit 915bdc6. Prevent historical drift.
ORIGINAL_MIGRATION_SHA256 = {
    "014_thread_agent_grants.py":
        "c38222ce4ef47cc06d797947acdb70aed23e884e230875fa0f4f44c37844978d",
    "015_thread_collaboration_capabilities.py":
        "bf6ec36e5a06e667ae358ff26e627b79ba18e48217e2e4fc79ed679d42b313dd",
    "016_thread_participant_access_expiry.py":
        "4065af91dd1367e872b2e303ca5df63a3267096b49e7863daa5bb6900a947eb7",
}

def _verify_unmodified_migration_files(repo_root: Path) -> None:
    for name, expected_hash in ORIGINAL_MIGRATION_SHA256.items():
        path = repo_root / "migrations" / "versions" / name
        if not path.is_file():
            raise PreflightRejected("Official migration file is missing: " + name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
            raise PreflightRejected("Official migration file drift detected: " + name)

EXPECTED_NEW_COLUMNS = {
    "thread_participants": {
        "allowed_agent_ids": "014",
        "can_read_messages": "015",
        "can_write_messages": "015",
        "access_expires_at": "016",
    },
    "thread_invitations": {
        "allowed_agent_ids": "014",
        "can_read_messages": "015",
        "can_write_messages": "015",
        "access_duration_hours": "016",
    },
}
LEGACY_COLUMNS = {
    "thread_participants": {"id", "tenant_id", "thread_id", "user_id"},
    "thread_invitations": {"id", "tenant_id", "thread_id", "status"},
}

class PreflightRejected(RuntimeError):
    """Fail-closed refusal; no DDL may have been committed."""

@dataclass(frozen=True)
class State:
    database: str
    system_identifier: str
    revision: str
    version_length: int
    column_count: int
    action: str

def _read_one(conn: Any, sql: str, params: dict | None = None) -> Any:
    rows = conn.execute(sa.text(sql), params or {}).all()
    if len(rows) != 1:
        raise PreflightRejected("Expected exactly one row from required metadata query")
    return rows[0][0]

def _validate_staging_environment(environ: dict[str, str]) -> None:
    if environ.get("PLATFORM_ENVIRONMENT") != "staging":
        raise PreflightRejected("PLATFORM_ENVIRONMENT must equal staging")
    if environ.get("RAILWAY_ENVIRONMENT_NAME") != STAGING_ENV:
        raise PreflightRejected("RAILWAY_ENVIRONMENT_NAME must equal staging-web01")
    # Guard against a mistaken manual context copied from production.
    if environ.get("RAILWAY_SERVICE_NAME") not in (None, "", "backend-web01"):
        raise PreflightRejected("Unexpected Railway service; require backend-web01")

def _validate_url(database_url: str) -> None:
    if not database_url or "${{" in database_url:
        raise PreflightRejected("DATABASE_URL missing or unresolved Railway reference")
    try:
        url = make_url(database_url)
    except Exception as exc:
        raise PreflightRejected("DATABASE_URL cannot be parsed") from exc
    if url.get_backend_name() != "postgresql":
        raise PreflightRejected("B2 requires PostgreSQL, not SQLite or another DB")

def _inspect(conn: Any, expected_db_name: str | None) -> State:
    db_name = str(_read_one(conn, "SELECT current_database()"))
    pg_id = str(_read_one(conn, "SELECT system_identifier::text FROM pg_control_system()"))
    if pg_id == KNOWN_PRODUCTION_SYSTEM_ID:
        raise PreflightRejected("Production PostgreSQL system identifier: prohibited")
    if pg_id != EXPECTED_STAGING_SYSTEM_ID:
        raise PreflightRejected("PostgreSQL system identifier does not match approved staging")
    if expected_db_name and db_name != expected_db_name:
        raise PreflightRejected("PostgreSQL database name does not match operator pin")
    if str(_read_one(conn, "SELECT current_schema()")) != "public":
        raise PreflightRejected("Current schema must be public")
    if bool(_read_one(conn, "SELECT pg_is_in_recovery()")):
        raise PreflightRejected("Target is a recovery replica")

    meta = conn.execute(sa.text("""
        SELECT data_type, character_maximum_length, is_nullable
        FROM information_schema.columns
        WHERE table_schema='public'
          AND table_name='alembic_version'
          AND column_name='version_num'
    """)).all()
    if len(meta) != 1:
        raise PreflightRejected("Missing/ambiguous public.alembic_version.version_num")
    dtype, limit, nullable = meta[0]
    if dtype != "character varying" or limit not in (32, TARGET_SIZE) or nullable != "NO":
        raise PreflightRejected("Unexpected Alembic version column definition")

    revision = str(_read_one(conn, "SELECT version_num FROM public.alembic_version"))
    if revision not in INITIAL_REVISIONS:
        raise PreflightRejected("Unexpected Alembic revision; expected single 013 or 014")

    results = conn.execute(sa.text("""
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema='public'
          AND table_name IN ('thread_participants', 'thread_invitations')
    """)).all()
    columns: dict[str, set[str]] = {t: set() for t in EXPECTED_NEW_COLUMNS}
    for table, column in results:
        columns[str(table)].add(str(column))
    for table in columns:
        if not LEGACY_COLUMNS[table].issubset(columns[table]):
            raise PreflightRejected("Missing legacy columns in " + table)
        new_actual = columns[table].intersection(EXPECTED_NEW_COLUMNS[table])
        expected = (
            {"allowed_agent_ids"} if revision == "014_thread_agent_grants" else set()
        )
        if new_actual != expected:
            raise PreflightRejected(
                "Unexpected collaboration schema for revision " + revision + " in " + table
            )

    has_constraint = conn.execute(sa.text("""
        SELECT count(*) FROM pg_constraint c
        JOIN pg_class t ON t.oid=c.conrelid
        JOIN pg_namespace n ON n.oid=t.relnamespace
        WHERE n.nspname='public' AND t.relname='thread_invitations'
          AND c.conname='ck_thread_invitation_access_duration'
    """)).scalar_one()
    if int(has_constraint) != 0:
        raise PreflightRejected("Unexpected 016 invitation constraint in 013/014 schema")

    return State(
        database=db_name,
        system_identifier=pg_id,
        revision=revision,
        version_length=int(limit),
        column_count=len(results),
        action="widen" if int(limit) == 32 else "no-op",
    )

def _record(state: State, mode: str, approval_id: str = "") -> dict:
    # Non-secret operational evidence: NO hostnames, usernames, credentials or rows.
    return {
        "tool_version": TOOL_VERSION,
        "utc": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "database": state.database,
        "system_identifier": state.system_identifier,
        "initial_revision": state.revision,
        "initial_version_length": state.version_length,
        "action": state.action,
        "approval_id": approval_id if mode == "apply" else "",
        "migrations_executed": False,
    }

def run(engine: Any, *, apply: bool, expected_database: str | None,
        approval_id: str | None = None, acknowledgement: str | None = None,
        environ: dict[str, str] | None = None) -> dict:
    env = dict(os.environ) if environ is None else environ
    _validate_staging_environment(env)
    if apply:
        if not expected_database:
            raise PreflightRejected("Apply requires --expected-database")
        if not approval_id or len(approval_id.strip()) < 8:
            raise PreflightRejected("Apply requires an independently approved gate reference")
        if acknowledgement != ACK_TEXT:
            raise PreflightRejected("Apply requires explicit staging-only acknowledgement")

    with engine.connect() as conn:
        # FIRST identify the target in a READ ONLY transaction, before
        # requesting any lock or write. A wrong/production target cannot be
        # blocked even transiently by the apply path.
        preview_tx = conn.begin()
        try:
            conn.exec_driver_sql("SET TRANSACTION READ ONLY")
            preview = _inspect(conn, expected_database)
            preview_tx.rollback()
        except Exception:
            preview_tx.rollback()
            raise
        if not apply:
            output = _record(preview, "inspect")
            output["resulting_version_length"] = preview.version_length
            output["result"] = "inspected"
            return output

        # SECOND transaction, same physical connection:
        #   1. revalidate identity AND schema before ANY explicit exclusive lock;
        #   2. acquire the version-table lock with NOWAIT;
        #   3. revalidate all state under that lock before DDL.
        # SET LOCAL only configures timeouts. The SELECTs of _inspect can take
        # PostgreSQL's normal implicit ACCESS SHARE locks, but no explicit
        # ACCESS EXCLUSIVE lock is requested until the target is verified again.
        apply_tx = conn.begin()
        try:
            conn.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
            conn.exec_driver_sql("SET LOCAL statement_timeout = '30s'")
            prelock = _inspect(conn, expected_database)
            if prelock != preview:
                raise PreflightRejected(
                    "Database destination/state changed before exclusive lock"
                )
            conn.exec_driver_sql(
                "LOCK TABLE public.alembic_version IN ACCESS EXCLUSIVE MODE NOWAIT"
            )
            state = _inspect(conn, expected_database)
            if state != prelock:
                raise PreflightRejected(
                    "Database destination/state changed after exclusive lock"
                )
            output = _record(state, "apply", approval_id or "")
            if state.action == "widen":
                conn.exec_driver_sql(
                    "ALTER TABLE public.alembic_version "
                    "ALTER COLUMN version_num TYPE VARCHAR(64)"
                )
                new_length = conn.execute(sa.text("""
                    SELECT character_maximum_length FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='alembic_version'
                      AND column_name='version_num'
                """)).scalar_one()
                if new_length != TARGET_SIZE:
                    raise PreflightRejected("Widening verification failed")
            output["resulting_version_length"] = TARGET_SIZE
            apply_tx.commit()
            output["result"] = "applied"
            return output
        except Exception:
            apply_tx.rollback()
            raise

def _cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-database", help="Pin current_database() for apply")
    parser.add_argument("--apply", action="store_true",
                        help="DANGER: allowed only after separately approved staging gate")
    parser.add_argument("--approval-id", help="AO-01/operator approved gate record")
    parser.add_argument("--acknowledge-staging-only", help="Explicit staging-only acknowledgement")
    args = parser.parse_args()
    try:
        _validate_staging_environment(dict(os.environ))
        raw_url = os.environ.get("DATABASE_URL", "")
        _validate_url(raw_url)
        _verify_unmodified_migration_files(Path(__file__).resolve().parents[1])
        # import backend's already-declared SQLAlchemy PostgreSQL driver only
        engine = sa.create_engine(raw_url, pool_pre_ping=True)
        try:
            result = run(
                engine, apply=args.apply, expected_database=args.expected_database,
                approval_id=args.approval_id,
                acknowledgement=args.acknowledge_staging_only,
            )
        finally:
            engine.dispose()
    except (PreflightRejected, sa.exc.SQLAlchemyError) as exc:
        # Never include connection strings or driver error text, which may
        # contain secret credentials or private hostnames.
        error_code = (
            "PREFLIGHT_REJECTED" if isinstance(exc, PreflightRejected)
            else "DATABASE_OPERATION_FAILED"
        )
        print(json.dumps({"result": "refused", "error_code": error_code}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(_cli())
