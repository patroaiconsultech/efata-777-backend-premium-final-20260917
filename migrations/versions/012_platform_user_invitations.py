"""Premium Platform User Invitation Plane.

Revision ID: 012_platform_user_invitations
Revises: 011_billing_wallet

Proposal-only in Wave B0. This file MUST NOT be executed without a later
migration gate and human approval.

Safety properties:
- additive invitation/outbox tables;
- no backfill or mutation of users.email;
- normalized-email uniqueness is enforced by an expression index;
- duplicate normalized emails fail closed before index creation;
- PostgreSQL uses CREATE UNIQUE INDEX CONCURRENTLY to reduce write blocking;
- downgrade removes only objects introduced here and never rewrites identity data.
"""
from alembic import op
import sqlalchemy as sa


revision = "012_platform_user_invitations"
down_revision = "011_billing_wallet"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _table_exists(name: str) -> bool:
    return _inspector().has_table(name)


def _index_names(table_name: str) -> set[str]:
    if not _table_exists(table_name):
        return set()
    return {str(row.get("name")) for row in _inspector().get_indexes(table_name) if row.get("name")}


def _preflight_normalized_email_uniqueness() -> None:
    duplicate = op.get_bind().execute(
        sa.text(
            """
            SELECT lower(trim(email)) AS normalized_email, count(*) AS row_count
            FROM users
            GROUP BY lower(trim(email))
            HAVING count(*) > 1
            LIMIT 1
            """
        )
    ).first()
    if duplicate is not None:
        raise RuntimeError("USER_NORMALIZED_EMAIL_DUPLICATES_BLOCK_MIGRATION")


def _create_normalized_email_unique_index() -> None:
    index_name = "uq_users_email_normalized"
    if index_name in _index_names("users"):
        return
    _preflight_normalized_email_uniqueness()
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        # CONCURRENTLY cannot run inside a transaction block. The preflight is
        # advisory; the unique index itself remains the final race-safe guard.
        with op.get_context().autocommit_block():
            op.execute(
                sa.text(
                    "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "
                    "uq_users_email_normalized ON users (lower(trim(email)))"
                )
            )
    else:
        op.create_index(
            index_name,
            "users",
            [sa.text("lower(trim(email))")],
            unique=True,
        )


def upgrade() -> None:
    _create_normalized_email_unique_index()

    if not _table_exists("platform_invitations"):
        op.create_table(
            "platform_invitations",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column(
                "tenant_id",
                sa.String(64),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("invited_email", sa.String(320), nullable=False),
            sa.Column("role", sa.String(40), nullable=False, server_default="member"),
            sa.Column("token_hash", sa.String(64), nullable=False),
            sa.Column("active_dedupe_key", sa.String(420), nullable=True),
            sa.Column("state", sa.String(32), nullable=False, server_default="PENDING"),
            sa.Column(
                "delivery_status",
                sa.String(40),
                nullable=False,
                server_default="PENDING",
            ),
            sa.Column("delivery_generation", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("delivery_attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_by", sa.String(64), nullable=False),
            sa.Column(
                "issued_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("accepted_by", sa.String(64), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("provider_message_id", sa.String(255), nullable=True),
            sa.Column("delivery_error_code", sa.String(120), nullable=True),
            sa.Column("last_delivery_attempt_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("token_hash", name="uq_platform_invitation_token_hash"),
            sa.UniqueConstraint(
                "active_dedupe_key", name="uq_platform_invitation_active_dedupe"
            ),
            sa.CheckConstraint(
                "state IN ('PENDING','ACCEPTED','REVOKED','EXPIRED')",
                name="ck_platform_invitation_state",
            ),
            sa.CheckConstraint(
                "delivery_status IN ('PENDING','ACCEPTED_BY_PROVIDER','DELIVERY_FAILED')",
                name="ck_platform_invitation_delivery_status",
            ),
        )
        op.create_index(
            "ix_platform_invitations_tenant_id",
            "platform_invitations",
            ["tenant_id"],
        )
        op.create_index(
            "ix_platform_invitations_invited_email",
            "platform_invitations",
            ["invited_email"],
        )
        op.create_index(
            "ix_platform_invitations_token_hash",
            "platform_invitations",
            ["token_hash"],
        )
        op.create_index(
            "ix_platform_invitations_state",
            "platform_invitations",
            ["state"],
        )
        op.create_index(
            "ix_platform_invitations_delivery_status",
            "platform_invitations",
            ["delivery_status"],
        )
        op.create_index(
            "ix_platform_invitation_tenant_state",
            "platform_invitations",
            ["tenant_id", "state"],
        )
        op.create_index(
            "ix_platform_invitation_tenant_email",
            "platform_invitations",
            ["tenant_id", "invited_email"],
        )

    if not _table_exists("platform_invitation_outbox"):
        op.create_table(
            "platform_invitation_outbox",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column(
                "tenant_id",
                sa.String(64),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "invitation_id",
                sa.String(64),
                sa.ForeignKey("platform_invitations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("generation", sa.Integer(), nullable=False),
            sa.Column("idempotency_key", sa.String(180), nullable=False),
            sa.Column("status", sa.String(40), nullable=False, server_default="PENDING"),
            sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("provider_message_id", sa.String(255), nullable=True),
            sa.Column("error_code", sa.String(120), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint(
                "idempotency_key", name="uq_platform_invitation_outbox_idempotency"
            ),
            sa.UniqueConstraint(
                "invitation_id",
                "generation",
                name="uq_platform_invitation_outbox_generation",
            ),
            sa.CheckConstraint(
                "status IN ('PENDING','ACCEPTED_BY_PROVIDER','DELIVERY_FAILED')",
                name="ck_platform_invitation_outbox_status",
            ),
        )
        op.create_index(
            "ix_platform_invitation_outbox_tenant_id",
            "platform_invitation_outbox",
            ["tenant_id"],
        )
        op.create_index(
            "ix_platform_invitation_outbox_invitation_id",
            "platform_invitation_outbox",
            ["invitation_id"],
        )
        op.create_index(
            "ix_platform_invitation_outbox_status",
            "platform_invitation_outbox",
            ["status"],
        )
        op.create_index(
            "ix_platform_invitation_outbox_status_created",
            "platform_invitation_outbox",
            ["status", "created_at"],
        )


def downgrade() -> None:
    if _table_exists("platform_invitation_outbox"):
        op.drop_table("platform_invitation_outbox")
    if _table_exists("platform_invitations"):
        op.drop_table("platform_invitations")

    if "uq_users_email_normalized" in _index_names("users"):
        op.drop_index("uq_users_email_normalized", table_name="users")
