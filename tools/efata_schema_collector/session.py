from __future__ import annotations

from dataclasses import dataclass

from .canonical import sha256_canonical
from .contracts import CollectorSessionProfile


class SessionProfileError(RuntimeError):
    pass


PINNED_SETTINGS = (
    ("search_path", "search_path"),
    ("TimeZone", "timezone"),
    ("DateStyle", "datestyle"),
    ("IntervalStyle", "intervalstyle"),
    ("standard_conforming_strings", "standard_conforming_strings"),
    ("extra_float_digits", "extra_float_digits"),
    ("bytea_output", "bytea_output"),
)


def _scalar(connection, sql: str, params=None):
    with connection.cursor() as cur:
        cur.execute(sql, params or ())
        row = cur.fetchone()
        return row[0] if row else None


def begin_readonly_transaction(connection) -> None:
    # Harness must provide an idle, restricted connection.
    with connection.cursor() as cur:
        cur.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")


def apply_and_verify_session_profile(
    connection,
    profile: CollectorSessionProfile,
) -> str:
    for pg_name, attr in PINNED_SETTINGS:
        expected = str(getattr(profile, attr))
        _scalar(
            connection,
            "SELECT pg_catalog.set_config(%s, %s, true)",
            (pg_name, expected),
        )

    _scalar(
        connection,
        "SELECT pg_catalog.set_config('statement_timeout', %s, true)",
        (f"{profile.statement_timeout_ms}ms",),
    )
    _scalar(
        connection,
        "SELECT pg_catalog.set_config('lock_timeout', %s, true)",
        (f"{profile.lock_timeout_ms}ms",),
    )
    _scalar(
        connection,
        "SELECT pg_catalog.set_config('idle_in_transaction_session_timeout', %s, true)",
        (f"{profile.idle_in_transaction_session_timeout_ms}ms",),
    )

    observed: dict[str, str] = {}
    for pg_name, attr in PINNED_SETTINGS:
        value = _scalar(
            connection,
            "SELECT pg_catalog.current_setting(%s)",
            (pg_name,),
        )
        observed[attr] = str(value)

    tx_read_only = str(
        _scalar(connection, "SELECT pg_catalog.current_setting('transaction_read_only')")
    ).lower()
    tx_isolation = str(
        _scalar(connection, "SELECT pg_catalog.current_setting('transaction_isolation')")
    ).lower()

    expected = {
        attr: str(getattr(profile, attr))
        for _, attr in PINNED_SETTINGS
    }

    # PostgreSQL may canonicalize case/spacing for a few GUCs. Compare
    # deliberately with small, explicit normalizers rather than ambient values.
    def norm(key: str, value: str) -> str:
        text = value.strip()
        if key in {"timezone", "datestyle", "intervalstyle", "standard_conforming_strings", "bytea_output"}:
            return text.lower().replace(" ", "")
        return text

    mismatches = {
        key: (expected[key], observed[key])
        for key in expected
        if norm(key, expected[key]) != norm(key, observed[key])
    }
    if tx_read_only != "on":
        mismatches["transaction_read_only"] = ("on", tx_read_only)
    if tx_isolation != "repeatable read":
        mismatches["transaction_isolation"] = ("repeatable read", tx_isolation)

    if mismatches:
        raise SessionProfileError(
            f"CAPTURE.SESSION_PROFILE_NOT_ENFORCED: {mismatches}"
        )

    return sha256_canonical(profile)
