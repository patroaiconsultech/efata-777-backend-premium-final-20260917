from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


ROOT = Path(__file__).resolve().parents[1]


def test_migration_graph_head_is_011_billing_wallet():
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    script = ScriptDirectory.from_config(cfg)
    assert script.get_heads() == ["012_platform_user_invitations"]


def test_migration_009_is_defensive_and_postgres_immutable():
    text = (
        ROOT / "migrations" / "versions" / "009_audit_evidence_ledger.py"
    ).read_text(encoding="utf-8")

    assert 'down_revision = "008_admin_voice_catalog"' in text
    assert 'if not _table_exists("audit_evidence_records")' in text
    assert "reject_audit_evidence_mutation" in text
    assert "BEFORE UPDATE OR DELETE" in text
    assert "trg_audit_evidence_immutable" in text


def test_migration_008_remains_defensive_for_fresh_bootstrap():
    text = (
        ROOT / "migrations" / "versions" / "008_admin_voice_catalog.py"
    ).read_text(encoding="utf-8")
    assert 'if not _table_exists("voice_catalog_entries")' in text
    assert 'if not _table_exists("agent_voice_assignments")' in text
