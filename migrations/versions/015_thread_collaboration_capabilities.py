"""Add explicit independent message-read/write controls to collaboration grants.

Revision ID: 015_thread_collaboration_capabilities
Revises: 014_thread_agent_grants

Nullable additive fields retain legacy policy (read=True, write=non-viewer).
No data rewrite or backfill. NULL is interpreted by thread_access_policy.
Approval required prior to upgrading staging/production; do not auto-downgrade.
"""
from alembic import op
import sqlalchemy as sa

revision = "015_thread_collaboration_capabilities"
down_revision = "014_thread_agent_grants"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("thread_participants", "thread_invitations"):
        op.add_column(table, sa.Column("can_read_messages", sa.Boolean(), nullable=True))
        op.add_column(table, sa.Column("can_write_messages", sa.Boolean(), nullable=True))


def downgrade() -> None:
    # Destructive to stored grants. Requires independent explicit approval and
    # verified backup/restore rehearsal; never downgrade as a routine rollback.
    for table in ("thread_invitations", "thread_participants"):
        op.drop_column(table, "can_write_messages")
        op.drop_column(table, "can_read_messages")
