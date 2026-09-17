from __future__ import annotations

from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, Field


CheckoutKind = Literal["plan", "topup"]


class BillingCatalogItem(BaseModel):
    code: str
    name: str
    kind: str
    description: str = ""
    display_currency: str = "USD"
    price_usd: Decimal | None = None
    price_brl: Decimal | None = None
    pay_usd: Decimal | None = None
    pay_brl: Decimal | None = None
    included_credit_usd: Decimal | None = None
    credit_usd: Decimal | None = None
    entitlement_days: int | None = None
    badge: str | None = None
    features: list[str] = Field(default_factory=list)


class BillingCheckoutCreate(BaseModel):
    item_code: str = Field(min_length=1, max_length=80)
    checkout_kind: CheckoutKind = "plan"
    full_name: str | None = Field(default=None, min_length=1, max_length=200)
    company: str | None = Field(default=None, max_length=240)


class BillingCheckoutView(BaseModel):
    id: str
    checkout_kind: str
    item_code: str
    item_name: str
    status: str
    checkout_url: str | None = None
    currency: str
    amount_brl: Decimal
    amount_usd: Decimal
    created_at: str
    confirmed_at: str | None = None


class BillingWalletView(BaseModel):
    id: str | None = None
    currency: str
    status: str
    balance_usd: Decimal
    lifetime_credited_usd: Decimal
    lifetime_debited_usd: Decimal
    quarantined_usd: Decimal
    low_balance_threshold_usd: Decimal | None = None


class BillingEntitlementView(BaseModel):
    plan_code: str
    plan_name: str
    status: str
    starts_at: str | None = None
    expires_at: str | None = None
    last_payment_at: str | None = None


class BillingOverview(BaseModel):
    wallet: BillingWalletView
    entitlement: BillingEntitlementView | None = None


class BillingLedgerEntryView(BaseModel):
    id: str
    direction: str
    source: str
    action_key: str | None = None
    amount_usd: Decimal
    balance_after_usd: Decimal
    currency: str
    external_ref: str | None = None
    created_at: str


class BillingAdminSummary(BaseModel):
    confirmed_revenue_usd: Decimal
    refunded_or_chargeback_usd: Decimal
    wallet_balance_usd: Decimal
    wallet_quarantined_usd: Decimal
    transaction_count: int
    wallet_count: int
