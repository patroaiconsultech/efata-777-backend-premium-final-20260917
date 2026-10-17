"""Unit-level safety tests for DG-01 P0 B2.1; not PostgreSQL integration proof."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import sqlalchemy as sa

MOD_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "p0_b2_alembic_capacity_preflight.py"
)
spec = importlib.util.spec_from_file_location("p0_b2_test_target", MOD_PATH)
mod = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

ENV = {"PLATFORM_ENVIRONMENT": "staging",
       "RAILWAY_ENVIRONMENT_NAME": "staging-web01",
       "RAILWAY_SERVICE_NAME": "backend-web01"}
ACK = mod.ACK_TEXT

class FakeResult:
    def __init__(self, rows):
        self.rows = rows
    def all(self):
        return self.rows
    def scalar_one(self):
        assert len(self.rows) == 1
        return self.rows[0][0]

class FakeTx:
    def __init__(self):
        self.committed = False
        self.rolled_back = False
    def commit(self):
        self.committed = True
    def rollback(self):
        self.rolled_back = True

class FakeConn:
    def __init__(self, *, revision="013_agent_studio_control_plane", width=32,
                 sid=mod.EXPECTED_STAGING_SYSTEM_ID, db="railway",
                 dtype="character varying", nullable="NO", schema="public",
                 replica=False, columns=None, constraint=0,
                 fail_alter=False, verify_length_wrong=False,
                 fail_lock=False, deny_control_access=False):
        self.revision = revision
        self.width = width
        self.sid = sid
        self.db = db
        self.dtype = dtype
        self.nullable = nullable
        self.schema = schema
        self.replica = replica
        self.constraint = constraint
        self.fail_alter = fail_alter
        self.fail_lock = fail_lock
        self.deny_control_access = deny_control_access
        self.mutate_on_second_begin = None
        self.verify_length_wrong = verify_length_wrong
        self.calls = []
        self.tx = FakeTx()
        self.transactions = []
        self.mutate_on_lock = False
        if columns is None:
            columns = {
                t: set(mod.LEGACY_COLUMNS[t])
                for t in mod.EXPECTED_NEW_COLUMNS
            }
            if revision == "014_thread_agent_grants":
                for t in columns:
                    columns[t].add("allowed_agent_ids")
        self.columns = columns
    def __enter__(self):
        return self
    def __exit__(self, typ, value, tb):
        return False
    def begin(self):
        self.tx = FakeTx()
        self.transactions.append(self.tx)
        if len(self.transactions) == 2 and self.mutate_on_second_begin:
            self.mutate_on_second_begin(self)
        return self.tx
    def execute(self, sql, params=None):
        statement = str(sql)
        self.calls.append(statement)
        if "SELECT current_database()" in statement:
            return FakeResult([(self.db,)])
        if "system_identifier::text" in statement:
            if self.deny_control_access:
                raise sa.exc.ProgrammingError(
                    "SELECT system_identifier", {},
                    RuntimeError("permission denied for function pg_control_system"),
                )
            return FakeResult([(self.sid,)])
        if "SELECT current_schema()" in statement:
            return FakeResult([(self.schema,)])
        if "SELECT pg_is_in_recovery()" in statement:
            return FakeResult([(self.replica,)])
        if "data_type, character_maximum_length, is_nullable" in statement:
            return FakeResult([(self.dtype, self.width, self.nullable)])
        if "SELECT version_num FROM public.alembic_version" in statement:
            if self.revision == "NONE":
                return FakeResult([])
            return FakeResult([(self.revision,)])
        if "SELECT table_name, column_name" in statement:
            return FakeResult(
                [(t, c) for t, fields in self.columns.items() for c in fields]
            )
        if "SELECT count(*) FROM pg_constraint" in statement:
            return FakeResult([(self.constraint,)])
        if "SELECT character_maximum_length FROM information_schema.columns" in statement:
            return FakeResult([(32 if self.verify_length_wrong else self.width,)])
        raise AssertionError("Unexpected query: " + statement)
    def exec_driver_sql(self, statement):
        self.calls.append(statement)
        if "LOCK TABLE" in statement and self.fail_lock:
            raise sa.exc.OperationalError(
                "LOCK TABLE public.alembic_version", {},
                RuntimeError("could not obtain lock on relation"),
            )
        if "LOCK TABLE" in statement and self.mutate_on_lock:
            self.revision = "014_thread_agent_grants"
            for table in self.columns:
                self.columns[table].add("allowed_agent_ids")
        if "ALTER TABLE" in statement:
            if self.fail_alter:
                raise ValueError("Simulated DDL failure")
            self.width = 64

class FakeEngine:
    def __init__(self, **kwargs):
        self.conn = FakeConn(**kwargs)
    def connect(self):
        return self.conn

def run(engine=None, apply=False, env=None, **kwargs):
    engine = engine or FakeEngine()
    inputs = {"approval_id": "AO01-GATE-P0-STAGE-001",
              "acknowledgement": ACK,
              "expected_database": "railway"}
    inputs.update(kwargs)
    return mod.run(engine, apply=apply, environ=ENV if env is None else env,
                   **inputs)

def test_inspect_013_is_read_only_by_default():
    engine = FakeEngine()
    r = run(engine)
    assert r["result"] == "inspected"
    assert r["action"] == "widen"
    assert r["migrations_executed"] is False
    assert "SET TRANSACTION READ ONLY" in engine.conn.calls
    assert not any("ALTER TABLE" in s for s in engine.conn.calls)
    assert engine.conn.tx.rolled_back is True

def test_inspect_014_is_read_only_and_supported():
    engine = FakeEngine(revision="014_thread_agent_grants")
    r = run(engine)
    assert r["initial_revision"] == "014_thread_agent_grants"

@pytest.mark.parametrize("width", [32, 64])
def test_inspect_widths(width):
    assert run(FakeEngine(width=width))["initial_version_length"] == width

def test_apply_widens_version_field_exactly_and_commits():
    engine = FakeEngine()
    r = run(engine, apply=True)
    assert r["resulting_version_length"] == 64
    assert r["result"] == "applied"
    assert engine.conn.tx.committed
    assert any("ACCESS EXCLUSIVE MODE NOWAIT" in s for s in engine.conn.calls)
    assert any("ALTER TABLE public.alembic_version" in s for s in engine.conn.calls)
    assert all("DROP" not in s and "INSERT" not in s for s in engine.conn.calls)

def test_apply_already_64_is_noop():
    engine = FakeEngine(width=64)
    r = run(engine, apply=True)
    assert r["action"] == "no-op"
    assert not any("ALTER TABLE" in s for s in engine.conn.calls)

def test_apply_at_014_handles_already_published_revision():
    engine = FakeEngine(revision="014_thread_agent_grants")
    assert run(engine, apply=True)["resulting_version_length"] == 64

@pytest.mark.parametrize("environment", [
    {"PLATFORM_ENVIRONMENT": "production", "RAILWAY_ENVIRONMENT_NAME": "staging-web01"},
    {"PLATFORM_ENVIRONMENT": "staging", "RAILWAY_ENVIRONMENT_NAME": "production"},
    {"PLATFORM_ENVIRONMENT": "staging"},
    {"PLATFORM_ENVIRONMENT": "staging", "RAILWAY_ENVIRONMENT_NAME": "staging-web01",
     "RAILWAY_SERVICE_NAME": "Efata-777-backend-Premium"},
])
def test_wrong_runtime_environment_rejected_before_connect(environment):
    engine = FakeEngine()
    with pytest.raises(mod.PreflightRejected):
        run(engine, env=environment, apply=True)
    assert engine.conn.calls == []

@pytest.mark.parametrize("sid", [
    mod.KNOWN_PRODUCTION_SYSTEM_ID, "123456789", "0",
])
def test_wrong_pg_cluster_rejected_and_rolled_back(sid):
    engine = FakeEngine(sid=sid)
    with pytest.raises(mod.PreflightRejected):
        run(engine, apply=True)
    assert engine.conn.tx.rolled_back
    assert not any("ALTER TABLE" in s for s in engine.conn.calls)

@pytest.mark.parametrize("extra", [
    {"expected_database": None},
    {"expected_database": "wrong-db"},
    {"approval_id": None},
    {"approval_id": "no"},
    {"acknowledgement": "wrong"},
])
def test_approval_or_identity_guard_rejected(extra):
    engine = FakeEngine()
    with pytest.raises(mod.PreflightRejected):
        run(engine, apply=True, **extra)
    assert not any("ALTER TABLE" in s for s in engine.conn.calls)

@pytest.mark.parametrize("revision", [
    "015_thread_collaboration_capabilities", "NONE", "011_billing_wallet",
])
def test_unexpected_revision_rejected(revision):
    engine = FakeEngine(revision=revision)
    with pytest.raises(mod.PreflightRejected):
        run(engine, apply=True)
    assert not any("ALTER TABLE" in s for s in engine.conn.calls)

@pytest.mark.parametrize("width, dtype, nullable", [
    (33, "character varying", "NO"),
    (37, "character varying", "NO"),
    (32, "text", "NO"),
    (32, "character varying", "YES"),
    (None, "text", "NO"),
])
def test_unexpected_alembic_column_shape_rejected(width, dtype, nullable):
    engine = FakeEngine(width=width, dtype=dtype, nullable=nullable)
    with pytest.raises(mod.PreflightRejected):
        run(engine, apply=True)
    assert not any("ALTER TABLE" in s for s in engine.conn.calls)

def test_malformed_013_schema_rejected():
    cols = {t: set(mod.LEGACY_COLUMNS[t]) for t in mod.EXPECTED_NEW_COLUMNS}
    cols["thread_participants"].add("can_read_messages")
    engine = FakeEngine(columns=cols)
    with pytest.raises(mod.PreflightRejected):
        run(engine, apply=True)

def test_missing_legacy_column_rejected():
    cols = {t: set(mod.LEGACY_COLUMNS[t]) for t in mod.EXPECTED_NEW_COLUMNS}
    cols["thread_participants"].remove("tenant_id")
    with pytest.raises(mod.PreflightRejected):
        run(FakeEngine(columns=cols), apply=True)

def test_existing_016_constraint_rejected():
    with pytest.raises(mod.PreflightRejected):
        run(FakeEngine(constraint=1), apply=True)

def test_wrong_schema_and_replica_rejected():
    for state in [{"schema": "other"}, {"replica": True}]:
        with pytest.raises(mod.PreflightRejected):
            run(FakeEngine(**state), apply=True)

def test_failure_during_ddl_causes_rollback():
    engine = FakeEngine(fail_alter=True)
    with pytest.raises(ValueError, match="Simulated"):
        run(engine, apply=True)
    assert engine.conn.tx.rolled_back
    assert not engine.conn.tx.committed

def test_failed_post_ddl_verification_causes_rollback():
    engine = FakeEngine(verify_length_wrong=True)
    with pytest.raises(mod.PreflightRejected, match="Widening verification failed"):
        run(engine, apply=True)
    assert engine.conn.tx.rolled_back

def test_invalid_urls_never_expose_credentials():
    for raw in ["", "${{postgres-web01.DATABASE_URL}}", "sqlite:///test.db", "totally bad"]:
        with pytest.raises(mod.PreflightRejected):
            mod._validate_url(raw)

def test_valid_pg_urls_accepted():
    for raw in ["postgresql://user:secret@localhost/test",
                "postgresql+psycopg://user:secret@localhost/test"]:
        mod._validate_url(raw)

def test_run_does_not_invoke_alembic():
    import inspect
    source = inspect.getsource(mod.run)
    assert "upgrade head" not in source
    assert "alembic.command" not in source
    assert "drop_column" not in source


def test_verified_original_migrations_pass_from_reference_snapshot(tmp_path):
    # Actual branch files when installed; immutable review copies in proposal ZIP.
    origin = Path(__file__).resolve().parents[1]
    source_dir = origin / "migrations" / "versions"
    if not source_dir.exists():
        source_dir = origin / "evidence" / "original_migrations_reference_only"
    for name in mod.ORIGINAL_MIGRATION_SHA256:
        f = tmp_path / "migrations" / "versions" / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes((source_dir / name).read_bytes())
    mod._verify_unmodified_migration_files(tmp_path)


def test_changed_migration_file_is_rejected(tmp_path):
    for name, expected_hash in mod.ORIGINAL_MIGRATION_SHA256.items():
        f = tmp_path / "migrations" / "versions" / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("changed")
    with pytest.raises(mod.PreflightRejected, match="drift"):
        mod._verify_unmodified_migration_files(tmp_path)


def test_missing_official_migration_is_rejected(tmp_path):
    with pytest.raises(mod.PreflightRejected, match="missing"):
        mod._verify_unmodified_migration_files(tmp_path)


def test_production_target_never_locked_even_transiently():
    engine = FakeEngine(sid=mod.KNOWN_PRODUCTION_SYSTEM_ID)
    with pytest.raises(mod.PreflightRejected):
        run(engine, apply=True)
    assert not any("LOCK TABLE" in stmt for stmt in engine.conn.calls)
    assert len(engine.conn.transactions) == 1
    assert engine.conn.transactions[0].rolled_back


def test_apply_performs_readonly_inspection_before_table_lock():
    engine = FakeEngine()
    run(engine, apply=True)
    assert engine.conn.calls.index("SET TRANSACTION READ ONLY") < next(
        i for i, q in enumerate(engine.conn.calls) if "LOCK TABLE" in q
    )
    assert len(engine.conn.transactions) == 2
    assert engine.conn.transactions[0].rolled_back
    assert engine.conn.transactions[1].committed


def test_apply_refuses_race_after_lock_and_rolls_back():
    engine = FakeEngine()
    engine.conn.mutate_on_lock = True
    with pytest.raises(mod.PreflightRejected, match="changed after exclusive lock"):
        run(engine, apply=True)
    assert len(engine.conn.transactions) == 2
    assert engine.conn.transactions[1].rolled_back
    assert not any("ALTER TABLE" in q for q in engine.conn.calls)


# B2.1 AO-01 negative tests: destination and revision MUST be inspected
# in the second transaction BEFORE any explicit exclusive table lock.

def _exclusive_lock_positions(calls):
    return [i for i, statement in enumerate(calls) if "LOCK TABLE" in statement]


def test_apply_revalidates_target_identity_before_exclusive_lock():
    engine = FakeEngine()
    result = run(engine, apply=True)
    calls = engine.conn.calls
    lock = _exclusive_lock_positions(calls)
    assert len(lock) == 1
    assert sum("system_identifier::text" in q for q in calls[:lock[0]]) == 2
    assert sum("SELECT version_num FROM public.alembic_version" in q
               for q in calls[:lock[0]]) == 2
    assert sum("system_identifier::text" in q for q in calls[lock[0]+1:]) == 1
    assert sum("SELECT version_num FROM public.alembic_version" in q
               for q in calls[lock[0]+1:]) == 1
    assert result["result"] == "applied"


def test_destination_changed_between_transactions_refuses_before_lock():
    engine = FakeEngine()
    engine.conn.mutate_on_second_begin = (
        lambda conn: setattr(conn, "sid", mod.KNOWN_PRODUCTION_SYSTEM_ID)
    )
    with pytest.raises(mod.PreflightRejected, match="Production PostgreSQL"):
        run(engine, apply=True)
    assert not _exclusive_lock_positions(engine.conn.calls)
    assert not any("ALTER TABLE" in s for s in engine.conn.calls)
    assert engine.conn.transactions[1].rolled_back
    assert not engine.conn.transactions[1].committed


def test_destination_changed_to_unknown_cluster_refuses_before_lock():
    engine = FakeEngine()
    engine.conn.mutate_on_second_begin = lambda conn: setattr(conn, "sid", "999")
    with pytest.raises(mod.PreflightRejected, match="staging"):
        run(engine, apply=True)
    assert not _exclusive_lock_positions(engine.conn.calls)
    assert not any("ALTER TABLE" in s for s in engine.conn.calls)
    assert engine.conn.transactions[1].rolled_back


def test_revision_changes_between_transactions_refuses_before_lock():
    engine = FakeEngine()
    def change_to_014(conn):
        conn.revision = "014_thread_agent_grants"
        for table in conn.columns:
            conn.columns[table].add("allowed_agent_ids")
    engine.conn.mutate_on_second_begin = change_to_014
    with pytest.raises(mod.PreflightRejected, match="before exclusive lock"):
        run(engine, apply=True)
    assert not _exclusive_lock_positions(engine.conn.calls)
    assert not any("ALTER TABLE" in s for s in engine.conn.calls)
    assert engine.conn.transactions[1].rolled_back


def test_column_length_changes_between_transactions_refuses_before_lock():
    engine = FakeEngine()
    engine.conn.mutate_on_second_begin = lambda conn: setattr(conn, "width", 64)
    with pytest.raises(mod.PreflightRejected, match="before exclusive lock"):
        run(engine, apply=True)
    assert not _exclusive_lock_positions(engine.conn.calls)
    assert not any("ALTER TABLE" in s for s in engine.conn.calls)


def test_concurrent_lock_holder_nowait_refuses_without_ddl():
    engine = FakeEngine(fail_lock=True)
    with pytest.raises(sa.exc.OperationalError):
        run(engine, apply=True)
    assert len(_exclusive_lock_positions(engine.conn.calls)) == 1
    assert not any("ALTER TABLE" in s for s in engine.conn.calls)
    assert engine.conn.transactions[1].rolled_back
    assert not engine.conn.transactions[1].committed


def test_revision_change_at_lock_refuses_after_lock():
    engine = FakeEngine()
    engine.conn.mutate_on_lock = True
    with pytest.raises(mod.PreflightRejected, match="after exclusive lock"):
        run(engine, apply=True)
    assert len(_exclusive_lock_positions(engine.conn.calls)) == 1
    assert not any("ALTER TABLE" in s for s in engine.conn.calls)
    assert engine.conn.transactions[1].rolled_back


def test_pg_control_system_permission_denied_fails_closed_without_lock():
    engine = FakeEngine(deny_control_access=True)
    with pytest.raises(sa.exc.ProgrammingError):
        run(engine, apply=True)
    assert not _exclusive_lock_positions(engine.conn.calls)
    assert not any("ALTER TABLE" in s for s in engine.conn.calls)
    assert engine.conn.transactions[0].rolled_back


def test_pg_control_system_permission_denied_in_second_tx_fails_before_lock():
    engine = FakeEngine()
    engine.conn.mutate_on_second_begin = (
        lambda conn: setattr(conn, "deny_control_access", True)
    )
    with pytest.raises(sa.exc.ProgrammingError):
        run(engine, apply=True)
    assert not _exclusive_lock_positions(engine.conn.calls)
    assert not any("ALTER TABLE" in s for s in engine.conn.calls)
    assert engine.conn.transactions[1].rolled_back


def test_apply_does_not_overwrite_legacy_migrations_or_update_revision():
    engine = FakeEngine()
    run(engine, apply=True)
    assert not any("UPDATE public.alembic_version" in q for q in engine.conn.calls)
    assert not any("INSERT INTO" in q or "DROP TABLE" in q for q in engine.conn.calls)
    assert not any("thread_participants" in q and "ALTER TABLE" in q
                   for q in engine.conn.calls)
