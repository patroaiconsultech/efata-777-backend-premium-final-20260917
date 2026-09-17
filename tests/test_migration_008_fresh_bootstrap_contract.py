from pathlib import Path


def test_migration_008_is_defensive_against_foundation_create_all():
    migration = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "versions"
        / "008_admin_voice_catalog.py"
    ).read_text(encoding="utf-8")

    assert 'if not _table_exists("voice_catalog_entries")' in migration
    assert 'if not _table_exists("agent_voice_assignments")' in migration
    assert "_ensure_index(" in migration
    assert 'if _table_exists("agent_voice_assignments")' in migration
    assert 'if _table_exists("voice_catalog_entries")' in migration
