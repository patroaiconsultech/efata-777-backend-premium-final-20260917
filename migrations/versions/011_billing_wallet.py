"""Canonical EFATA 777 transactional billing wallet.

Revision ID: 011_billing_wallet
Revises: 010_billing_core
"""
from alembic import op
import sqlalchemy as sa


revision = "011_billing_wallet"
down_revision = "010_billing_core"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _table_exists(name: str) -> bool:
    return _inspector().has_table(name)


def upgrade() -> None:
    if not _table_exists("billing_wallets"):
        op.create_table(
            "billing_wallets",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("tenant_id", sa.String(64), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("user_id", sa.String(64), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("currency", sa.String(8), nullable=False, server_default="USD"),
            sa.Column("status", sa.String(20), nullable=False, server_default="active"),
            sa.Column("balance_usd", sa.Numeric(18, 4), nullable=False, server_default="0"),
            sa.Column("lifetime_credited_usd", sa.Numeric(18, 4), nullable=False, server_default="0"),
            sa.Column("lifetime_debited_usd", sa.Numeric(18, 4), nullable=False, server_default="0"),
            sa.Column("quarantined_usd", sa.Numeric(18, 4), nullable=False, server_default="0"),
            sa.Column("auto_recharge_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("auto_recharge_pack_code", sa.String(80), nullable=True),
            sa.Column("auto_recharge_threshold_usd", sa.Numeric(18, 4), nullable=True),
            sa.Column("low_balance_threshold_usd", sa.Numeric(18, 4), nullable=True, server_default="3"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("tenant_id", "user_id", name="uq_billing_wallet_tenant_user"),
            sa.CheckConstraint("status IN ('active','quarantined')", name="ck_billing_wallet_status"),
            sa.CheckConstraint("balance_usd >= 0", name="ck_billing_wallet_nonnegative_balance"),
            sa.CheckConstraint("quarantined_usd >= 0", name="ck_billing_wallet_nonnegative_quarantine"),
        )
        op.create_index("ix_billing_wallets_tenant_id", "billing_wallets", ["tenant_id"])
        op.create_index("ix_billing_wallets_user_id", "billing_wallets", ["user_id"])
        op.create_index("ix_billing_wallet_tenant_updated", "billing_wallets", ["tenant_id", "updated_at"])

    if not _table_exists("billing_wallet_ledger"):
        op.create_table(
            "billing_wallet_ledger",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("tenant_id", sa.String(64), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("user_id", sa.String(64), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("wallet_id", sa.String(64), sa.ForeignKey("billing_wallets.id", ondelete="CASCADE"), nullable=False),
            sa.Column("direction", sa.String(16), nullable=False),
            sa.Column("source", sa.String(40), nullable=False),
            sa.Column("idempotency_key", sa.String(180), nullable=False),
            sa.Column("action_key", sa.String(120), nullable=True),
            sa.Column("quantity", sa.Numeric(18, 4), nullable=True),
            sa.Column("unit_price_usd", sa.Numeric(18, 4), nullable=True),
            sa.Column("amount_usd", sa.Numeric(18, 4), nullable=False, server_default="0"),
            sa.Column("balance_after_usd", sa.Numeric(18, 4), nullable=False, server_default="0"),
            sa.Column("currency", sa.String(8), nullable=False, server_default="USD"),
            sa.Column("provider", sa.String(32), nullable=True),
            sa.Column("external_ref", sa.String(160), nullable=True),
            sa.Column("related_checkout_id", sa.String(64), sa.ForeignKey("billing_checkouts.id", ondelete="SET NULL"), nullable=True),
            sa.Column("related_tx_id", sa.String(64), sa.ForeignKey("billing_transactions.id", ondelete="SET NULL"), nullable=True),
            sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_by", sa.String(64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_billing_wallet_ledger_tenant_idempotency"),
            sa.CheckConstraint("direction IN ('credit','debit','adjustment')", name="ck_billing_wallet_ledger_direction"),
            sa.CheckConstraint("amount_usd >= 0", name="ck_billing_wallet_ledger_nonnegative_amount"),
        )
        op.create_index("ix_billing_wallet_ledger_tenant_id", "billing_wallet_ledger", ["tenant_id"])
        op.create_index("ix_billing_wallet_ledger_user_id", "billing_wallet_ledger", ["user_id"])
        op.create_index("ix_billing_wallet_ledger_wallet_id", "billing_wallet_ledger", ["wallet_id"])
        op.create_index("ix_billing_wallet_ledger_related_checkout_id", "billing_wallet_ledger", ["related_checkout_id"])
        op.create_index("ix_billing_wallet_ledger_related_tx_id", "billing_wallet_ledger", ["related_tx_id"])
        op.create_index("ix_billing_wallet_ledger_wallet_created", "billing_wallet_ledger", ["wallet_id", "created_at"])
        op.create_index("ix_billing_wallet_ledger_tenant_created", "billing_wallet_ledger", ["tenant_id", "created_at"])


def downgrade() -> None:
    if _table_exists("billing_wallet_ledger"):
        op.drop_table("billing_wallet_ledger")
    if _table_exists("billing_wallets"):
        op.drop_table("billing_wallets")
