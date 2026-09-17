from types import SimpleNamespace

import pytest

from tools.efata_schema_collector.canonical import sha256_text
from tools.efata_schema_collector.contracts import CaptureTargetBinding
from tools.efata_schema_collector.target_binding import (
    TargetBindingError,
    verify_connection_attestation,
)


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.description = None
        self._row = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=()):
        if "inet_client_addr" in sql:
            data = self.connection.facts
        elif "efata_fixture_meta.target_attestation" in sql:
            data = self.connection.fixture
        else:
            raise AssertionError(sql)
        self.description = [SimpleNamespace(name=k) for k in data]
        self._row = tuple(data.values())

    def fetchone(self):
        return self._row


class FakeConnection:
    def __init__(self):
        self.facts = {
            "database_name": "fixture_db",
            "session_user": "collector",
            "current_user": "collector",
            "server_version_num": 160011,
            "inet_client_addr": None,
            "inet_client_port": None,
            "inet_server_addr": None,
            "inet_server_port": None,
            "backend_pid": 123,
            "transaction_read_only": "on",
            "transaction_isolation": "repeatable read",
        }
        self.fixture = {
            "fixture_runtime_id": "run-1",
            "connection_binding_id": "bind-1",
            "fixture_nonce": "nonce-1",
        }

    def cursor(self):
        return FakeCursor(self)


def binding():
    return CaptureTargetBinding(
        fixture_runtime_id="run-1",
        connection_binding_id="bind-1",
        expected_fixture_nonce="nonce-1",
        expected_database_name_sha256=sha256_text("fixture_db"),
        expected_collector_principal="collector",
    )


def test_attestation_uses_observed_connection_facts():
    attestation = verify_connection_attestation(FakeConnection(), binding())
    assert attestation.session_user == "collector"
    assert attestation.transport == "UNIX_SOCKET"
    assert attestation.attestation_sha256


def test_nonce_mismatch_fails_closed():
    conn = FakeConnection()
    conn.fixture["fixture_nonce"] = "wrong"
    with pytest.raises(TargetBindingError, match="ATTESTATION_FAILED"):
        verify_connection_attestation(conn, binding())


def test_tcp_connection_is_rejected_even_if_loopback():
    conn = FakeConnection()
    conn.facts["inet_server_addr"] = "127.0.0.1"
    with pytest.raises(TargetBindingError, match="TRANSPORT_NOT_UNIX_SOCKET"):
        verify_connection_attestation(conn, binding())


def test_wrong_database_identity_is_rejected():
    conn = FakeConnection()
    conn.facts["database_name"] = "other"
    with pytest.raises(TargetBindingError, match="ATTESTATION_FAILED"):
        verify_connection_attestation(conn, binding())
