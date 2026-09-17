import importlib.util
import pytest

from orkio_v2.database import make_engine, normalize_database_url


def test_postgresql_scheme_is_normalized_to_psycopg3():
    assert normalize_database_url("postgresql://u:p@h/db") == "postgresql+psycopg://u:p@h/db"


def test_legacy_postgres_scheme_is_normalized_to_psycopg3():
    assert normalize_database_url("postgres://u:p@h/db") == "postgresql+psycopg://u:p@h/db"


def test_explicit_psycopg_scheme_is_preserved():
    assert normalize_database_url("postgresql+psycopg://u:p@h/db") == "postgresql+psycopg://u:p@h/db"


def test_sqlite_scheme_is_preserved():
    assert normalize_database_url("sqlite+pysqlite:///./test.db") == "sqlite+pysqlite:///./test.db"


def test_psycopg2_scheme_is_not_rewritten():
    assert normalize_database_url("postgresql+psycopg2://u:p@h/db") == "postgresql+psycopg2://u:p@h/db"


def test_make_engine_selects_psycopg3_driver_without_connecting():
    if importlib.util.find_spec("psycopg") is None:
        pytest.skip("psycopg 3 is unavailable in this local runtime")
    engine = make_engine("postgresql://u:p@h/db")
    assert engine.url.drivername == "postgresql+psycopg"


def test_make_engine_preserves_sqlite_driver():
    engine = make_engine("sqlite+pysqlite:///:memory:")
    assert engine.url.drivername == "sqlite+pysqlite"
