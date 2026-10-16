"""Add optional per-participant access deadline and invitation grant duration.

Revision ID: 016_thread_participant_access_expiry
Revises: 015_thread_collaboration_capabilities

Zero backfill. NULL for existing accepted participants remains unlimited,
preserving historical grants. Explicitly approved migration only.
"""
from alembic import op
import sqlalchemy as sa

revision = "016_thread_participant_access_expiry"
down_revision = "015_thread_collaboration_capabilities"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "thread_invitations",
        sa.Column("access_duration_hours", sa.Integer(), nullable=True),
    )
    op.add_column(
        "thread_participants",
        sa.Column("access_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        "ck_thread_invitation_access_duration",
        "thread_invitations",
        "access_duration_hours BETWEEN 1 AND 8760",
    )


def downgrade() -> None:
    # Destructive to stored access durations. Backup and human-approved
    # restoration/reconciliation are mandatory; never auto-downgrade.
    op.drop_constraint(
        "ck_thread_invitation_access_duration",
        "thread_invitations",
        type_="check",
    )
    op.drop_column("thread_participants", "access_expires_at")
    op.drop_column("thread_invitations", "access_duration_hours")
