"""Additive per-invitation/per-participant allowed agent scope.

Revision ID: 014_thread_agent_grants
Revises: 013_agent_studio_control_plane

Gate: human-approved Alembic migration, only after PostgreSQL preflight.
No backfill: NULL is explicitly interpreted as legacy orkio-only in policy.
"""
from alembic import op
import sqlalchemy as sa

revision = "014_thread_agent_grants"
down_revision = "013_agent_studio_control_plane"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("thread_participants", sa.Column("allowed_agent_ids", sa.JSON(), nullable=True))
    op.add_column("thread_invitations", sa.Column("allowed_agent_ids", sa.JSON(), nullable=True))


def downgrade() -> None:
    # Downgrade removes stored grants; only with explicit human/data-loss approval.
    op.drop_column("thread_invitations", "allowed_agent_ids")
    op.drop_column("thread_participants", "allowed_agent_ids")
