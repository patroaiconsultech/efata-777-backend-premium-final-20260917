from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


ROOT = Path(__file__).resolve().parents[1]


def test_platform_invitation_migration_is_new_head_and_reversible_contract():
    config = Config(str(ROOT / "alembic.ini"))
    script = ScriptDirectory.from_config(config)
    assert script.get_heads() == ["016_thread_participant_access_expiry"]
    revision = script.get_revision("012_platform_user_invitations")
    assert revision is not None
    assert revision.down_revision == "011_billing_wallet"

    text = (ROOT / "migrations/versions/012_platform_user_invitations.py").read_text()
    assert "USER_NORMALIZED_EMAIL_DUPLICATES_BLOCK_MIGRATION" in text
    assert "CREATE UNIQUE INDEX CONCURRENTLY" in text
    assert "platform_invitations" in text
    assert "platform_invitation_outbox" in text
    assert "def downgrade()" in text
    assert 'op.drop_table("platform_invitation_outbox")' in text
    assert 'op.drop_table("platform_invitations")' in text
    assert 'op.drop_index("uq_users_email_normalized"' in text


def test_migration_is_proposal_only_documented_not_self_executing():
    text = (ROOT / "migrations/versions/012_platform_user_invitations.py").read_text()
    assert "MUST NOT be executed without a later" in text
    assert "op.execute" in text  # DDL exists, but there is no runtime import/call.
    assert "__main__" not in text
