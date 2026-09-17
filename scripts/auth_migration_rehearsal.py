#!/usr/bin/env python3
"""Destructive PostgreSQL-only Alembic rehearsal for RC1-AUTH-D.

This script is intentionally fail-closed. It may reset the target database's
public schema and therefore refuses to run unless all CI/destructive guards are
explicitly enabled and the database name is clearly CI-scoped.

It proves:
1) fresh database -> Alembic head 004;
2) 004 -> 003 downgrade -> 004 re-upgrade;
3) simulated legacy 003 auth schema with a real persisted session -> 004;
4) legacy session preservation/backfill through downgrade/re-upgrade.

Never point this script at staging or production.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.engine import make_url


EXPECTED_HEAD = "004_rc1_auth_d"
LEGACY_REVISION = "003_native_auth"
D_TABLES = {
    "native_auth_throttles",
    "native_auth_challenges",
    "native_mfa_factors",
    "native_mfa_recovery_codes",
}
D_SESSION_COLUMNS = {
    "previous_session_hash",
    "rotation_grace_expires_at",
    "last_rotated_at",
    "authenticated_at",
    "mfa_verified_at",
    "reauthenticated_at",
}

ROOT = Path(__file__).resolve().parents[1]


class RehearsalError(RuntimeError):
    pass


def emit(stage: str, status: str, **details: object) -> None:
    # Intentionally excludes DATABASE_URL and any credential/token value.
    print(json.dumps({"stage": stage, "status": status, **details}, sort_keys=True), flush=True)


def guarded_database_url() -> str:
    if os.environ.get("CI", "").lower() != "true":
        raise RehearsalError("REFUSED_NOT_CI")
    if os.environ.get("AUTH_MIGRATION_REHEARSAL_ALLOW_DESTRUCTIVE", "").lower() != "true":
        raise RehearsalError("REFUSED_DESTRUCTIVE_GUARD_NOT_ENABLED")

    raw = os.environ.get("DATABASE_URL", "").strip()
    if not raw:
        raise RehearsalError("DATABASE_URL_REQUIRED")

    url = make_url(raw)
    if not url.drivername.startswith("postgresql"):
        raise RehearsalError("POSTGRESQL_REQUIRED")
    database = (url.database or "").lower()
    if "ci" not in database and "test" not in database:
        raise RehearsalError("REFUSED_DATABASE_NAME_NOT_CI_SCOPED")
    if (url.host or "").lower() not in {"127.0.0.1", "localhost", "postgres"}:
        raise RehearsalError("REFUSED_NONLOCAL_DATABASE_HOST")
    return raw


def engine_for(raw_url: str) -> sa.Engine:
    return sa.create_engine(raw_url, pool_pre_ping=True)


def run_alembic(*args: str) -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=ROOT,
        env=os.environ.copy(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if proc.returncode != 0:
        # Alembic output should not include DATABASE_URL; still avoid echoing env.
        tail = "\n".join(proc.stdout.splitlines()[-80:])
        raise RehearsalError(f"ALEMBIC_FAILED {' '.join(args)}\n{tail}")


def reset_public_schema(engine: sa.Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    emit("reset_public_schema", "PASS")


def current_revision(engine: sa.Engine) -> str | None:
    insp = sa.inspect(engine)
    if not insp.has_table("alembic_version"):
        return None
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()


def assert_revision(engine: sa.Engine, expected: str) -> None:
    actual = current_revision(engine)
    if actual != expected:
        raise RehearsalError(f"REVISION_MISMATCH expected={expected} actual={actual}")
    emit("revision", "PASS", revision=actual)


def columns(engine: sa.Engine, table: str) -> set[str]:
    return {item["name"] for item in sa.inspect(engine).get_columns(table)}


def tables(engine: sa.Engine) -> set[str]:
    return set(sa.inspect(engine).get_table_names())


def assert_004_shape(engine: sa.Engine) -> None:
    present_tables = tables(engine)
    missing_tables = sorted(D_TABLES - present_tables)
    missing_session_columns = sorted(D_SESSION_COLUMNS - columns(engine, "native_sessions"))
    user_has_verified = "email_verified_at" in columns(engine, "users")
    if missing_tables or missing_session_columns or not user_has_verified:
        raise RehearsalError(
            "HEAD_SCHEMA_INCOMPLETE "
            f"missing_tables={missing_tables} "
            f"missing_session_columns={missing_session_columns} "
            f"email_verified_at={user_has_verified}"
        )
    emit("schema_004", "PASS")


def assert_003_shape(engine: sa.Engine) -> None:
    present_tables = tables(engine)
    unexpected_tables = sorted(D_TABLES & present_tables)
    unexpected_session_columns = sorted(D_SESSION_COLUMNS & columns(engine, "native_sessions"))
    user_has_verified = "email_verified_at" in columns(engine, "users")
    if unexpected_tables or unexpected_session_columns or user_has_verified:
        raise RehearsalError(
            "LEGACY_SCHEMA_NOT_003 "
            f"unexpected_tables={unexpected_tables} "
            f"unexpected_session_columns={unexpected_session_columns} "
            f"email_verified_at={user_has_verified}"
        )
    emit("schema_003", "PASS")


def strip_004_to_simulated_003(engine: sa.Engine) -> None:
    # `alembic upgrade 003` traverses revision 001, whose historical implementation
    # uses current ORM metadata. We explicitly remove RC1-D objects to recreate
    # the production-relevant 003 auth shape before testing 003 -> 004.
    with engine.begin() as conn:
        for table in (
            "native_mfa_recovery_codes",
            "native_mfa_factors",
            "native_auth_challenges",
            "native_auth_throttles",
        ):
            conn.execute(text(f'DROP TABLE IF EXISTS "{table}" CASCADE'))
        for column in (
            "reauthenticated_at",
            "mfa_verified_at",
            "authenticated_at",
            "last_rotated_at",
            "rotation_grace_expires_at",
            "previous_session_hash",
        ):
            conn.execute(text(f'ALTER TABLE native_sessions DROP COLUMN IF EXISTS "{column}" CASCADE'))
        conn.execute(text('ALTER TABLE users DROP COLUMN IF EXISTS "email_verified_at" CASCADE'))
    assert_revision(engine, LEGACY_REVISION)
    assert_003_shape(engine)
    emit("simulate_legacy_003", "PASS")


def seed_legacy_session(engine: sa.Engine) -> dict[str, str]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    ids = {
        "tenant_id": "ci-migration-tenant",
        "user_id": "ci-migration-user",
        "session_id": "ci-migration-session",
        "session_hash": "a" * 64,
    }
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO tenants (id, name, created_at)
                VALUES (:id, :name, :created_at)
                """
            ),
            {"id": ids["tenant_id"], "name": "CI Migration Tenant", "created_at": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO users (id, external_subject, email, display_name, created_at)
                VALUES (:id, :external_subject, :email, :display_name, :created_at)
                """
            ),
            {
                "id": ids["user_id"],
                "external_subject": "ci-migration-subject",
                "email": "ci-migration@example.invalid",
                "display_name": "CI Migration User",
                "created_at": now,
            },
        )
        conn.execute(
            text(
                """
                INSERT INTO native_sessions (
                    id, session_hash, token_prefix, tenant_id, user_id,
                    created_at, expires_at, last_seen_at, revoked_at,
                    user_agent, ip_prefix
                )
                VALUES (
                    :id, :session_hash, :token_prefix, :tenant_id, :user_id,
                    :created_at, :expires_at, :last_seen_at, NULL,
                    :user_agent, :ip_prefix
                )
                """
            ),
            {
                "id": ids["session_id"],
                "session_hash": ids["session_hash"],
                "token_prefix": "ci-prefix",
                "tenant_id": ids["tenant_id"],
                "user_id": ids["user_id"],
                "created_at": now,
                "expires_at": now + timedelta(hours=1),
                "last_seen_at": now,
                "user_agent": "ci-rehearsal",
                "ip_prefix": "127.0.0",
            },
        )
    emit("seed_legacy_session", "PASS", session_id=ids["session_id"])
    return ids


def assert_seed_preserved(engine: sa.Engine, ids: dict[str, str], *, expect_backfill: bool) -> None:
    with engine.connect() as conn:
        if expect_backfill:
            row = conn.execute(
                text(
                    """
                    SELECT
                        session_hash,
                        last_rotated_at IS NOT NULL AS has_last_rotated,
                        authenticated_at IS NOT NULL AS has_authenticated,
                        last_rotated_at = created_at AS rotated_backfilled,
                        authenticated_at = created_at AS authenticated_backfilled
                    FROM native_sessions
                    WHERE id = :id
                    """
                ),
                {"id": ids["session_id"]},
            ).mappings().one_or_none()
            if (
                row is None
                or row["session_hash"] != ids["session_hash"]
                or not row["has_last_rotated"]
                or not row["has_authenticated"]
                or not row["rotated_backfilled"]
                or not row["authenticated_backfilled"]
            ):
                raise RehearsalError("LEGACY_SESSION_BACKFILL_OR_PRESERVATION_FAILED")
        else:
            row = conn.execute(
                text("SELECT session_hash FROM native_sessions WHERE id = :id"),
                {"id": ids["session_id"]},
            ).scalar_one_or_none()
            if row != ids["session_hash"]:
                raise RehearsalError("LEGACY_SESSION_NOT_PRESERVED")
    emit("legacy_session_preservation", "PASS", backfill=expect_backfill)


def cleanup_seed(engine: sa.Engine, ids: dict[str, str]) -> None:
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM users WHERE id = :id"), {"id": ids["user_id"]})
        conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": ids["tenant_id"]})
    emit("cleanup_seed", "PASS")


def fresh_chain_cycle(engine: sa.Engine) -> None:
    reset_public_schema(engine)
    run_alembic("upgrade", EXPECTED_HEAD)
    assert_revision(engine, EXPECTED_HEAD)
    assert_004_shape(engine)

    run_alembic("downgrade", LEGACY_REVISION)
    assert_revision(engine, LEGACY_REVISION)
    assert_003_shape(engine)

    run_alembic("upgrade", EXPECTED_HEAD)
    assert_revision(engine, EXPECTED_HEAD)
    assert_004_shape(engine)
    emit("fresh_chain_cycle", "PASS")


def legacy_upgrade_cycle(engine: sa.Engine) -> None:
    reset_public_schema(engine)
    run_alembic("upgrade", LEGACY_REVISION)
    assert_revision(engine, LEGACY_REVISION)

    strip_004_to_simulated_003(engine)
    ids = seed_legacy_session(engine)

    run_alembic("upgrade", EXPECTED_HEAD)
    assert_revision(engine, EXPECTED_HEAD)
    assert_004_shape(engine)
    assert_seed_preserved(engine, ids, expect_backfill=True)

    run_alembic("downgrade", LEGACY_REVISION)
    assert_revision(engine, LEGACY_REVISION)
    assert_003_shape(engine)
    assert_seed_preserved(engine, ids, expect_backfill=False)

    run_alembic("upgrade", EXPECTED_HEAD)
    assert_revision(engine, EXPECTED_HEAD)
    assert_004_shape(engine)
    assert_seed_preserved(engine, ids, expect_backfill=True)
    cleanup_seed(engine, ids)
    emit("legacy_upgrade_cycle", "PASS")


def main() -> int:
    try:
        raw_url = guarded_database_url()
        engine = engine_for(raw_url)
        if engine.dialect.name != "postgresql":
            raise RehearsalError("POSTGRESQL_DIALECT_REQUIRED")

        with engine.connect() as conn:
            version = conn.execute(text("SHOW server_version")).scalar_one()
        emit("postgresql_preflight", "PASS", server_version=version)

        fresh_chain_cycle(engine)
        legacy_upgrade_cycle(engine)

        assert_revision(engine, EXPECTED_HEAD)
        emit("overall", "PASS", migration_head=EXPECTED_HEAD)
        return 0
    except Exception as exc:
        emit("overall", "FAIL", error_type=type(exc).__name__, error_code=str(exc).splitlines()[0][:240])
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
