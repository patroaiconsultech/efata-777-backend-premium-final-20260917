from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from tools.efata_schema_collector.canonical import sha256_text
from tools.efata_schema_collector.contracts import CaptureTargetBinding

BOOTSTRAP_ROLE = "efata_fixture_bootstrap"
COLLECTOR_ROLE = "efata_schema_collector_fixture"
FIXTURE_DB = "efata_collector_fixture_test"


class FixtureUnavailable(RuntimeError):
    pass


@dataclass
class FixtureRuntime:
    fixture_runtime_id: str
    connection_binding_id: str
    fixture_nonce: str
    root: Path
    data_dir: Path
    socket_dir: Path
    log_path: Path
    port: int
    initdb: Path
    pg_ctl: Path
    psql: Path
    postgres: Path
    binding: CaptureTargetBinding
    bootstrap_reconnect_denied: bool = False


class Postgres16FixtureHarness:
    """Privileged, test-only PostgreSQL 16 fixture harness.

    The collector package never imports this module. Bootstrap authority is
    confined to child `psql` processes and becomes unavailable through pg_hba
    before a restricted collector connection is opened.
    """

    def __init__(self, fixture_sql: Path):
        self.fixture_sql = Path(fixture_sql)
        self.runtime: FixtureRuntime | None = None
        self._owned_root: Path | None = None
        self._previous_signal_handlers: dict[int, object] = {}

    @staticmethod
    def _find_bin(name: str) -> Path:
        env_dir = os.environ.get("EFATA_PG16_BIN_DIR")
        candidates: list[Path] = []
        if env_dir:
            candidates.append(Path(env_dir) / name)
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
        for path in candidates:
            if path.exists():
                return path.resolve()
        raise FixtureUnavailable(f"PostgreSQL 16 binary missing: {name}")

    @classmethod
    def available(cls) -> tuple[bool, str]:
        try:
            postgres = cls._find_bin("postgres")
            out = subprocess.run(
                [str(postgres), "--version"],
                text=True,
                capture_output=True,
                timeout=5,
                check=True,
            ).stdout.strip()
            if " 16." not in out and not out.endswith(" 16"):
                return False, f"PostgreSQL major != 16: {out}"
            for name in ("initdb", "pg_ctl", "psql"):
                cls._find_bin(name)
            try:
                import psycopg  # noqa: F401
            except Exception as exc:
                return False, f"psycopg unavailable: {exc}"
            return True, "ok"
        except Exception as exc:
            return False, str(exc)

    def _run(self, argv, *, timeout=20, check=True, env=None):
        return subprocess.run(
            [str(x) for x in argv],
            text=True,
            capture_output=True,
            timeout=timeout,
            check=check,
            env=env,
        )

    def _psql_env(self, database: str = FIXTURE_DB) -> dict[str, str]:
        if self.runtime is None:
            raise RuntimeError("fixture runtime not allocated")
        env = os.environ.copy()
        env.update({
            "PGHOST": str(self.runtime.socket_dir),
            "PGPORT": str(self.runtime.port),
            "PGDATABASE": database,
        })
        return env

    def _psql(
        self,
        role: str,
        sql: str | None = None,
        *,
        file: Path | None = None,
        variables: dict[str, str] | None = None,
        check=True,
        database: str = FIXTURE_DB,
    ):
        if self.runtime is None:
            raise RuntimeError("fixture runtime not allocated")
        args = [self.runtime.psql, "-X", "-v", "ON_ERROR_STOP=1", "-U", role]
        for key, value in sorted((variables or {}).items()):
            args.extend(["-v", f"{key}={value}"])
        if file is not None:
            args.extend(["-f", file])
        elif sql is not None:
            args.extend(["-c", sql])
        else:
            raise ValueError("sql or file required")
        return self._run(
            args,
            timeout=30,
            check=check,
            env=self._psql_env(database),
        )

    def _install_signal_handlers(self):
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                self._previous_signal_handlers[sig] = signal.getsignal(sig)
            signal.signal(signal.SIGINT, self._interrupt_handler)
            signal.signal(signal.SIGTERM, self._interrupt_handler)
        except (ValueError, RuntimeError):
            self._previous_signal_handlers.clear()

    def _restore_signal_handlers(self):
        for sig, handler in list(self._previous_signal_handlers.items()):
            try:
                signal.signal(sig, handler)
            except (ValueError, RuntimeError):
                pass
        self._previous_signal_handlers.clear()

    def _interrupt_handler(self, signum, frame):
        if signum == signal.SIGINT:
            raise KeyboardInterrupt()
        raise SystemExit(128 + signum)

    def __enter__(self):
        initdb = self._find_bin("initdb")
        pg_ctl = self._find_bin("pg_ctl")
        psql = self._find_bin("psql")
        postgres = self._find_bin("postgres")
        version = self._run([postgres, "--version"], timeout=5).stdout.strip()
        if " 16." not in version and not version.endswith(" 16"):
            raise FixtureUnavailable(f"PostgreSQL 16 required, observed: {version}")

        root = Path(tempfile.mkdtemp(prefix="efata_pg16_fixture_"))
        root.chmod(0o700)
        self._owned_root = root
        data_dir = root / "data"
        socket_dir = root / "socket"
        socket_dir.mkdir(mode=0o700)
        log_path = root / "postgres.log"
        fixture_runtime_id = str(uuid.uuid4())
        connection_binding_id = str(uuid.uuid4())
        fixture_nonce = secrets.token_hex(24)
        port = 55000 + (os.getpid() % 5000)
        binding = CaptureTargetBinding(
            fixture_runtime_id=fixture_runtime_id,
            connection_binding_id=connection_binding_id,
            expected_fixture_nonce=fixture_nonce,
            expected_database_name_sha256=sha256_text(FIXTURE_DB),
            expected_collector_principal=COLLECTOR_ROLE,
            expected_postgres_major=16,
        )
        self.runtime = FixtureRuntime(
            fixture_runtime_id=fixture_runtime_id,
            connection_binding_id=connection_binding_id,
            fixture_nonce=fixture_nonce,
            root=root,
            data_dir=data_dir,
            socket_dir=socket_dir,
            log_path=log_path,
            port=port,
            initdb=initdb,
            pg_ctl=pg_ctl,
            psql=psql,
            postgres=postgres,
            binding=binding,
        )

        marker = root / ".efata_fixture_owner.json"
        marker.write_text(json.dumps({
            "fixture_runtime_id": fixture_runtime_id,
            "pid": os.getpid(),
        }, sort_keys=True))
        marker.chmod(0o600)
        self._install_signal_handlers()

        try:
            self._run([
                initdb,
                "-D", data_dir,
                "-U", BOOTSTRAP_ROLE,
                "--auth-local=trust",
                "--auth-host=reject",
                "--no-sync",
            ], timeout=30)

            with (data_dir / "postgresql.conf").open("a") as fh:
                fh.write("\n# EFATA disposable fixture\n")
                fh.write("listen_addresses = ''\n")
                fh.write(f"unix_socket_directories = '{socket_dir}'\n")
                fh.write(f"port = {port}\n")
                fh.write("max_connections = 20\n")

            self._run(
                [pg_ctl, "-D", data_dir, "-l", log_path, "-w", "start"],
                timeout=30,
            )

            self._psql(
                BOOTSTRAP_ROLE,
                f"CREATE DATABASE {FIXTURE_DB}",
                database="postgres",
            )
            self._psql(
                BOOTSTRAP_ROLE,
                file=self.fixture_sql,
                variables={
                    "fixture_runtime_id": fixture_runtime_id,
                    "connection_binding_id": connection_binding_id,
                    "fixture_nonce": fixture_nonce,
                },
            )

            # Privileged bootstrap teardown: new DB sessions may authenticate
            # only as the restricted collector role after this point.
            hba = data_dir / "pg_hba.conf"
            hba.write_text(
                f"local {FIXTURE_DB} {COLLECTOR_ROLE} trust\n"
                "local all all reject\n"
                "host all all 0.0.0.0/0 reject\n"
                "host all all ::0/0 reject\n"
            )
            self._run([pg_ctl, "-D", data_dir, "reload"], timeout=10)
            time.sleep(0.2)

            denied = self._psql(
                BOOTSTRAP_ROLE,
                "SELECT 1",
                check=False,
            )
            self.runtime.bootstrap_reconnect_denied = denied.returncode != 0
            if not self.runtime.bootstrap_reconnect_denied:
                raise RuntimeError("fixture bootstrap privilege teardown failed")

            return self
        except BaseException:
            self._cleanup()
            raise

    def open_restricted_connection(self):
        if self.runtime is None:
            raise RuntimeError("fixture not ready")
        import psycopg
        return psycopg.connect(
            host=str(self.runtime.socket_dir),
            port=self.runtime.port,
            dbname=FIXTURE_DB,
            user=COLLECTOR_ROLE,
            autocommit=True,
        )

    def assert_restricted_privilege_boundary(self, connection) -> dict:
        """Prove bootstrap authority is unavailable before collector capture."""
        if self.runtime is None or not self.runtime.bootstrap_reconnect_denied:
            raise RuntimeError("bootstrap privilege teardown not proven")

        with connection.cursor() as cur:
            cur.execute("SELECT SESSION_USER, CURRENT_USER")
            session_user, current_user = cur.fetchone()
        if session_user != COLLECTOR_ROLE or current_user != COLLECTOR_ROLE:
            raise RuntimeError("collector principal mismatch")

        attempts = {
            "SET_ROLE_PRIVILEGED": f"SET ROLE {BOOTSTRAP_ROLE}",
            "BUSINESS_ROW_SELECT": "SELECT name FROM public.business_items LIMIT 1",
            "INSERT": "INSERT INTO public.business_items(tenant_id, name) VALUES ('x','x')",
            "UPDATE": "UPDATE public.business_items SET name='x'",
            "DELETE": "DELETE FROM public.business_items",
            "DDL": "CREATE TABLE public.collector_must_not_create(id integer)",
            "TEMP": "CREATE TEMP TABLE collector_must_not_temp(id integer)",
        }
        outcomes: dict[str, str] = {}
        for name, sql in attempts.items():
            try:
                with connection.cursor() as cur:
                    cur.execute(sql)
                outcomes[name] = "ALLOWED"
            except Exception:
                outcomes[name] = "DENIED"
                try:
                    connection.rollback()
                except Exception:
                    pass

        allowed = [name for name, outcome in outcomes.items() if outcome != "DENIED"]
        if allowed:
            raise RuntimeError(f"restricted privilege boundary failed: {allowed}")

        return {
            "bootstrap_connection_closed": True,
            "bootstrap_reconnect_denied": True,
            "collector_session_user": session_user,
            "collector_current_user": current_user,
            "outcomes": outcomes,
        }

    def _owned(self, path: Path) -> bool:
        if self._owned_root is None:
            return False
        try:
            return path.resolve().is_relative_to(self._owned_root.resolve())
        except Exception:
            return False

    def _cleanup(self):
        runtime = self.runtime
        root = self._owned_root
        cleanup_error: Exception | None = None

        if runtime is not None and runtime.data_dir.exists():
            if not self._owned(runtime.data_dir):
                cleanup_error = RuntimeError("refusing to stop/delete unowned PGDATA")
            else:
                try:
                    self._run(
                        [runtime.pg_ctl, "-D", runtime.data_dir, "-m", "fast", "-w", "stop"],
                        timeout=10,
                        check=False,
                    )
                except Exception:
                    pass
                try:
                    status = self._run(
                        [runtime.pg_ctl, "-D", runtime.data_dir, "status"],
                        timeout=5,
                        check=False,
                    )
                    if status.returncode == 0:
                        self._run(
                            [runtime.pg_ctl, "-D", runtime.data_dir, "-m", "immediate", "stop"],
                            timeout=5,
                            check=False,
                        )
                except Exception:
                    pass

        if root is not None and root.exists():
            if not self._owned(root):
                cleanup_error = cleanup_error or RuntimeError(
                    "refusing to delete unowned fixture root"
                )
            else:
                shutil.rmtree(root, ignore_errors=False)

        self.runtime = None
        self._owned_root = None
        self._restore_signal_handlers()
        if cleanup_error:
            raise cleanup_error

    def __exit__(self, exc_type, exc, tb):
        self._cleanup()
        return False
