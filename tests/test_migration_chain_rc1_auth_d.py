from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from orkio_v2.config import get_settings


ROOT = Path(__file__).resolve().parents[1]
HEAD = "006_knowledge_plane_hardening"
PREVIOUS = "005_knowledge_plane_v1"


def _config() -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    return cfg


def _assert_revision(database_url: str, expected: str) -> None:
    engine = sa.create_engine(database_url)
    try:
        with engine.connect() as conn:
            actual = conn.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
        assert actual == expected
    finally:
        engine.dispose()


def _assert_head_shape(database_url: str) -> None:
    engine = sa.create_engine(database_url)
    try:
        inspector = sa.inspect(engine)
        tables = set(inspector.get_table_names())
        assert {
            "native_auth_throttles",
            "native_auth_challenges",
            "native_mfa_factors",
            "native_mfa_recovery_codes",
            "knowledge_documents",
            "knowledge_storage_cleanup",
        } <= tables
        check_names = {
            item.get("name")
            for item in inspector.get_check_constraints("knowledge_documents")
        }
        assert {
            "ck_knowledge_scope_valid",
            "ck_knowledge_status_valid",
            "ck_knowledge_version_positive",
            "ck_knowledge_scope_tenant_owner",
            "ck_knowledge_allowed_purposes_valid",
        } <= check_names
        session_columns = {item["name"] for item in inspector.get_columns("native_sessions")}
        assert {
            "previous_session_hash",
            "rotation_grace_expires_at",
            "last_rotated_at",
            "authenticated_at",
            "mfa_verified_at",
            "reauthenticated_at",
        } <= session_columns
        user_columns = {item["name"] for item in inspector.get_columns("users")}
        assert "email_verified_at" in user_columns
    finally:
        engine.dispose()


def test_fresh_migration_chain_downgrade_and_reupgrade(tmp_path: Path, monkeypatch) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'fresh-migration.sqlite3'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("PLATFORM_ENVIRONMENT", "test")
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "test")
    monkeypatch.setenv("PLATFORM_INVITATION_TOKEN_SECRET", "x" * 40)
    monkeypatch.delenv("PLATFORM_NATIVE_AUTH_ENABLED", raising=False)
    get_settings.cache_clear()

    try:
        cfg = _config()
        command.upgrade(cfg, HEAD)
        _assert_revision(database_url, HEAD)
        _assert_head_shape(database_url)

        command.downgrade(cfg, PREVIOUS)
        _assert_revision(database_url, PREVIOUS)

        command.upgrade(cfg, HEAD)
        _assert_revision(database_url, HEAD)
        _assert_head_shape(database_url)
    finally:
        get_settings.cache_clear()
