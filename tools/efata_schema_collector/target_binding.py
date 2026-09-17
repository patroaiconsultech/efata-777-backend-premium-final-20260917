from __future__ import annotations

from .canonical import sha256_canonical, sha256_text
from .contracts import CaptureTargetBinding, ConnectionAttestation


class TargetBindingError(RuntimeError):
    pass


def _fetchone_dict(connection, sql: str, params=()) -> dict:
    with connection.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
        if row is None:
            raise TargetBindingError("CAPTURE.TARGET_ATTESTATION_MISSING")
        columns = [d.name if hasattr(d, "name") else d[0] for d in cur.description]
        return dict(zip(columns, row))


def query_actual_connection_facts(connection) -> dict:
    facts = _fetchone_dict(
        connection,
        """
        SELECT
            pg_catalog.current_database() AS database_name,
            SESSION_USER AS session_user,
            CURRENT_USER AS current_user,
            pg_catalog.current_setting('server_version_num')::integer AS server_version_num,
            pg_catalog.inet_client_addr()::text AS inet_client_addr,
            pg_catalog.inet_client_port() AS inet_client_port,
            pg_catalog.inet_server_addr()::text AS inet_server_addr,
            pg_catalog.inet_server_port() AS inet_server_port,
            pg_catalog.pg_backend_pid() AS backend_pid,
            pg_catalog.current_setting('transaction_read_only') AS transaction_read_only,
            pg_catalog.current_setting('transaction_isolation') AS transaction_isolation
        """,
    )
    fixture = _fetchone_dict(
        connection,
        """
        SELECT fixture_runtime_id, connection_binding_id, fixture_nonce
        FROM efata_fixture_meta.target_attestation
        LIMIT 1
        """,
    )
    return {**facts, **fixture}


def verify_connection_attestation(
    connection,
    expected: CaptureTargetBinding,
) -> ConnectionAttestation:
    observed = query_actual_connection_facts(connection)
    observed_major = int(observed["server_version_num"]) // 10000
    db_hash = sha256_text(str(observed["database_name"]))

    network_fields = (
        observed.get("inet_client_addr"),
        observed.get("inet_client_port"),
        observed.get("inet_server_addr"),
        observed.get("inet_server_port"),
    )
    if any(value is not None for value in network_fields):
        raise TargetBindingError("CAPTURE.CONNECTION_TRANSPORT_NOT_UNIX_SOCKET")

    checks = {
        "fixture_runtime_id": (
            expected.fixture_runtime_id,
            str(observed["fixture_runtime_id"]),
        ),
        "connection_binding_id": (
            expected.connection_binding_id,
            str(observed["connection_binding_id"]),
        ),
        "fixture_nonce": (
            expected.expected_fixture_nonce,
            str(observed["fixture_nonce"]),
        ),
        "database_name_sha256": (
            expected.expected_database_name_sha256,
            db_hash,
        ),
        "session_user": (
            expected.expected_collector_principal,
            str(observed["session_user"]),
        ),
        "current_user": (
            expected.expected_collector_principal,
            str(observed["current_user"]),
        ),
        "postgres_major": (
            expected.expected_postgres_major,
            observed_major,
        ),
        "transaction_read_only": (
            True,
            str(observed["transaction_read_only"]).lower() == "on",
        ),
        "transaction_isolation": (
            "repeatable read",
            str(observed["transaction_isolation"]).lower(),
        ),
    }
    mismatches = {
        key: pair for key, pair in checks.items() if pair[0] != pair[1]
    }
    if mismatches:
        raise TargetBindingError(
            f"CAPTURE.CONNECTION_ATTESTATION_FAILED: {mismatches}"
        )

    material = {
        "attestation_version": "1",
        "fixture_runtime_id": expected.fixture_runtime_id,
        "connection_binding_id": expected.connection_binding_id,
        "expected_fixture_nonce": expected.expected_fixture_nonce,
        "observed_fixture_nonce": str(observed["fixture_nonce"]),
        "expected_database_name_sha256": expected.expected_database_name_sha256,
        "observed_database_name_sha256": db_hash,
        "expected_principal": expected.expected_collector_principal,
        "session_user": str(observed["session_user"]),
        "current_user": str(observed["current_user"]),
        "expected_postgres_major": expected.expected_postgres_major,
        "observed_postgres_major": observed_major,
        "transport": "UNIX_SOCKET",
        "inet_client_addr": observed.get("inet_client_addr"),
        "inet_client_port": observed.get("inet_client_port"),
        "inet_server_addr": observed.get("inet_server_addr"),
        "inet_server_port": observed.get("inet_server_port"),
        "backend_pid": int(observed["backend_pid"]),
        "transaction_read_only": True,
        "transaction_isolation": "repeatable read",
    }
    return ConnectionAttestation(
        **material,
        attestation_sha256=sha256_canonical(material),
    )
