"""Canonical EFATA 777 Billing/Asaas core.

Revision ID: 010_billing_core
Revises: 009_audit_evidence_ledger
"""
from alembic import op
import sqlalchemy as sa


revision = "010_billing_core"
down_revision = "009_audit_evidence_ledger"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _table_exists(name: str) -> bool:
    return _inspector().has_table(name)


def upgrade() -> None:
    if not _table_exists("billing_checkouts"):
        op.create_table(
            "billing_checkouts",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("tenant_id", sa.String(64), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("user_id", sa.String(64), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("checkout_kind", sa.String(16), nullable=False),
            sa.Column("item_code", sa.String(80), nullable=False),
            sa.Column("item_name", sa.String(200), nullable=False),
            sa.Column("payer_email", sa.String(320), nullable=False),
            sa.Column("payer_name", sa.String(200), nullable=False),
            sa.Column("company", sa.String(240), nullable=True),
            sa.Column("currency", sa.String(8), nullable=False, server_default="BRL"),
            sa.Column("amount_brl", sa.Numeric(18, 2), nullable=False, server_default="0"),
            sa.Column("amount_usd", sa.Numeric(18, 4), nullable=False, server_default="0"),
            sa.Column("status", sa.String(24), nullable=False, server_default="pending"),
            sa.Column("provider", sa.String(32), nullable=False, server_default="asaas"),
            sa.Column("provider_checkout_id", sa.String(160), nullable=True),
            sa.Column("provider_payment_id", sa.String(160), nullable=True),
            sa.Column("provider_url", sa.Text(), nullable=True),
            sa.Column("callback_success_url", sa.String(500), nullable=False),
            sa.Column("idempotency_key", sa.String(128), nullable=False),
            sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("reversed_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("tenant_id", "user_id", "idempotency_key", name="uq_billing_checkout_actor_idempotency"),
            sa.UniqueConstraint("provider", "provider_checkout_id", name="uq_billing_checkout_provider_checkout"),
            sa.CheckConstraint("checkout_kind IN ('plan','topup')", name="ck_billing_checkout_kind"),
            sa.CheckConstraint(
                "status IN ('pending','paid','failed','expired','cancelled','refunded','chargeback')",
                name="ck_billing_checkout_status",
            ),
        )
        op.create_index("ix_billing_checkouts_tenant_id", "billing_checkouts", ["tenant_id"])
        op.create_index("ix_billing_checkouts_user_id", "billing_checkouts", ["user_id"])
        op.create_index("ix_billing_checkouts_status", "billing_checkouts", ["status"])
        op.create_index("ix_billing_checkouts_provider_checkout_id", "billing_checkouts", ["provider_checkout_id"])
        op.create_index("ix_billing_checkouts_provider_payment_id", "billing_checkouts", ["provider_payment_id"])
        op.create_index("ix_billing_checkout_tenant_user_created", "billing_checkouts", ["tenant_id", "user_id", "created_at"])

    if not _table_exists("billing_webhook_events"):
        op.create_table(
            "billing_webhook_events",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("tenant_id", sa.String(64), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
            sa.Column("user_id", sa.String(64), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
            sa.Column("checkout_id", sa.String(64), sa.ForeignKey("billing_checkouts.id", ondelete="SET NULL"), nullable=True),
            sa.Column("provider", sa.String(32), nullable=False, server_default="asaas"),
            sa.Column("provider_event_key", sa.String(128), nullable=False),
            sa.Column("event_type", sa.String(80), nullable=False),
            sa.Column("payload_sha256", sa.String(64), nullable=False),
            sa.Column("provider_payment_id", sa.String(160), nullable=True),
            sa.Column("provider_checkout_id", sa.String(160), nullable=True),
            sa.Column("status", sa.String(16), nullable=False, server_default="received"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("provider", "provider_event_key", name="uq_billing_webhook_provider_event"),
            sa.CheckConstraint("status IN ('received','processed','ignored')", name="ck_billing_webhook_status"),
        )
        op.create_index("ix_billing_webhook_events_tenant_id", "billing_webhook_events", ["tenant_id"])
        op.create_index("ix_billing_webhook_events_user_id", "billing_webhook_events", ["user_id"])
        op.create_index("ix_billing_webhook_events_checkout_id", "billing_webhook_events", ["checkout_id"])
        op.create_index("ix_billing_webhook_tenant_created", "billing_webhook_events", ["tenant_id", "created_at"])

    if not _table_exists("billing_entitlements"):
        op.create_table(
            "billing_entitlements",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("tenant_id", sa.String(64), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("user_id", sa.String(64), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("plan_code", sa.String(80), nullable=False),
            sa.Column("plan_name", sa.String(200), nullable=False),
            sa.Column("status", sa.String(24), nullable=False, server_default="active"),
            sa.Column("checkout_id", sa.String(64), sa.ForeignKey("billing_checkouts.id", ondelete="SET NULL"), nullable=True),
            sa.Column("starts_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_payment_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("tenant_id", "user_id", name="uq_billing_entitlement_tenant_user"),
            sa.CheckConstraint(
                "status IN ('active','expired','cancelled','refunded','chargeback')",
                name="ck_billing_entitlement_status",
            ),
        )
        op.create_index("ix_billing_entitlements_tenant_id", "billing_entitlements", ["tenant_id"])
        op.create_index("ix_billing_entitlements_user_id", "billing_entitlements", ["user_id"])
        op.create_index("ix_billing_entitlements_checkout_id", "billing_entitlements", ["checkout_id"])
        op.create_index("ix_billing_entitlement_tenant_status", "billing_entitlements", ["tenant_id", "status"])

    if not _table_exists("billing_transactions"):
        op.create_table(
            "billing_transactions",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("tenant_id", sa.String(64), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("user_id", sa.String(64), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("checkout_id", sa.String(64), sa.ForeignKey("billing_checkouts.id", ondelete="SET NULL"), nullable=True),
            sa.Column("provider", sa.String(32), nullable=False, server_default="asaas"),
            sa.Column("external_ref", sa.String(160), nullable=False),
            sa.Column("plan_code", sa.String(80), nullable=True),
            sa.Column("charge_kind", sa.String(32), nullable=False),
            sa.Column("currency", sa.String(8), nullable=False, server_default="USD"),
            sa.Column("amount_original", sa.Numeric(18, 4), nullable=False, server_default="0"),
            sa.Column("amount_usd", sa.Numeric(18, 4), nullable=False, server_default="0"),
            sa.Column("normalized_mrr_usd", sa.Numeric(18, 4), nullable=False, server_default="0"),
            sa.Column("status", sa.String(24), nullable=False),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("created_by", sa.String(64), nullable=False),
            sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("provider", "external_ref", "status", "charge_kind", name="uq_billing_transaction_provider_ref_state_kind"),
            sa.CheckConstraint("status IN ('confirmed','refunded','chargeback','void')", name="ck_billing_transaction_status"),
        )
        op.create_index("ix_billing_transactions_tenant_id", "billing_transactions", ["tenant_id"])
        op.create_index("ix_billing_transactions_user_id", "billing_transactions", ["user_id"])
        op.create_index("ix_billing_transactions_checkout_id", "billing_transactions", ["checkout_id"])
        op.create_index("ix_billing_transaction_tenant_created", "billing_transactions", ["tenant_id", "created_at"])
        op.create_index("ix_billing_transaction_tenant_status", "billing_transactions", ["tenant_id", "status"])


def downgrade() -> None:
    for table_name in (
        "billing_transactions",
        "billing_entitlements",
        "billing_webhook_events",
        "billing_checkouts",
    ):
        if _table_exists(table_name):
            op.drop_table(table_name)
