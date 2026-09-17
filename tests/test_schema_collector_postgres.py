import json
from pathlib import Path

import pytest

from tests.support.efata_schema_fixture_harness import (
    Postgres16FixtureHarness,
)
from tools.efata_schema_collector.role_authority import evaluate_authority
from tools.efata_schema_collector.contracts import FixturePrivilegeTransitionEvidence
from datetime import datetime, timezone
from tools.efata_schema_collector.session import begin_readonly_transaction
from tools.efata_schema_collector.target_binding import verify_connection_attestation


ROOT = Path(__file__).parents[1]
FIXTURE_SQL = ROOT / "tests" / "fixtures" / "schema_collector" / "fixture_v1.sql"

AVAILABLE, REASON = Postgres16FixtureHarness.available()
pytestmark = pytest.mark.skipif(not AVAILABLE, reason=REASON)


def test_pg16_fixture_privilege_transition_and_connection_attestation():
    with Postgres16FixtureHarness(FIXTURE_SQL) as harness:
        conn = harness.open_restricted_connection()
        try:
            boundary = harness.assert_restricted_privilege_boundary(conn)
            assert boundary["bootstrap_connection_closed"] is True
            assert boundary["bootstrap_reconnect_denied"] is True
            assert set(boundary["outcomes"].values()) == {"DENIED"}

            begin_readonly_transaction(conn)
            attestation = verify_connection_attestation(conn, harness.runtime.binding)
            assert attestation.transport == "UNIX_SOCKET"
            assert attestation.session_user == "efata_schema_collector_fixture"
            assert attestation.current_user == "efata_schema_collector_fixture"
            assert attestation.transaction_read_only is True
            evidence = FixturePrivilegeTransitionEvidence(
                fixture_runtime_id=harness.runtime.fixture_runtime_id,
                bootstrap_principal_class="FIXTURE_BOOTSTRAP",
                bootstrap_connection_closed=boundary["bootstrap_connection_closed"],
                bootstrap_reconnect_denied=boundary["bootstrap_reconnect_denied"],
                collector_principal_class="SCHEMA_COLLECTOR",
                collector_session_user=boundary["collector_session_user"],
                collector_current_user=boundary["collector_current_user"],
                privileged_set_role_attempt=boundary["outcomes"]["SET_ROLE_PRIVILEGED"],
                business_row_select_attempt=boundary["outcomes"]["BUSINESS_ROW_SELECT"],
                write_attempts=tuple(
                    f"{name}:{boundary['outcomes'][name]}"
                    for name in ("INSERT", "UPDATE", "DELETE", "DDL", "TEMP")
                ),
                connection_attestation_sha256=attestation.attestation_sha256,
                captured_at_trusted=datetime.now(timezone.utc).isoformat(),
            )
            assert evidence.bootstrap_reconnect_denied is True
        finally:
            conn.rollback()
            conn.close()


def test_pg16_business_rows_denied_while_catalog_metadata_visible():
    with Postgres16FixtureHarness(FIXTURE_SQL) as harness:
        conn = harness.open_restricted_connection()
        try:
            boundary = harness.assert_restricted_privilege_boundary(conn)
            assert boundary["outcomes"]["BUSINESS_ROW_SELECT"] == "DENIED"
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT count(*)
                    FROM pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                    WHERE n.nspname='public' AND c.relname='business_items'
                """)
                assert cur.fetchone()[0] == 1
        finally:
            conn.close()


def test_pg16_role_graph_matches_supported_pg16_membership_semantics():
    with Postgres16FixtureHarness(FIXTURE_SQL) as harness:
        conn = harness.open_restricted_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT rolname, rolcanlogin, rolsuper, rolinherit, rolcreaterole,
                           rolcreatedb, rolreplication, rolbypassrls
                    FROM pg_catalog.pg_roles
                    WHERE rolname LIKE 'efata_%'
                    ORDER BY rolname
                """)
                names = [d.name for d in cur.description]
                roles = [dict(zip(names, row)) for row in cur.fetchall()]
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT member.rolname AS member_role,
                           granted.rolname AS granted_role,
                           grantor.rolname AS grantor_role,
                           m.admin_option, m.inherit_option, m.set_option
                    FROM pg_catalog.pg_auth_members m
                    JOIN pg_catalog.pg_roles member ON member.oid=m.member
                    JOIN pg_catalog.pg_roles granted ON granted.oid=m.roleid
                    JOIN pg_catalog.pg_roles grantor ON grantor.oid=m.grantor
                    WHERE member.rolname LIKE 'efata_%'
                    ORDER BY member.rolname, granted.rolname
                """)
                names = [d.name for d in cur.description]
                memberships = [dict(zip(names, row)) for row in cur.fetchall()]

            result = evaluate_authority("efata_runtime_fixture", roles, memberships)
            assert "BYPASSRLS" not in result.summary
            assert any(
                edge.to_role == "efata_role_a"
                for proof in result.proofs
                for edge in proof.proof_path
            ) or result.summary == ()
        finally:
            conn.close()
