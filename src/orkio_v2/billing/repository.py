from __future__ import annotations

from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import (
    BillingCheckout,
    BillingEntitlement,
    BillingTransaction,
    BillingWallet,
    BillingWalletLedger,
)


def checkout_for_actor(
    db: Session, *, tenant_id: str, user_id: str, checkout_id: str
) -> BillingCheckout | None:
    return db.scalar(
        select(BillingCheckout).where(
            BillingCheckout.id == checkout_id,
            BillingCheckout.tenant_id == tenant_id,
            BillingCheckout.user_id == user_id,
        )
    )


def checkout_by_idempotency(
    db: Session, *, tenant_id: str, user_id: str, idempotency_key: str
) -> BillingCheckout | None:
    return db.scalar(
        select(BillingCheckout).where(
            BillingCheckout.tenant_id == tenant_id,
            BillingCheckout.user_id == user_id,
            BillingCheckout.idempotency_key == idempotency_key,
        )
    )


def wallet_for_actor(db: Session, *, tenant_id: str, user_id: str) -> BillingWallet | None:
    return db.scalar(
        select(BillingWallet).where(
            BillingWallet.tenant_id == tenant_id,
            BillingWallet.user_id == user_id,
        )
    )


def entitlement_for_actor(
    db: Session, *, tenant_id: str, user_id: str
) -> BillingEntitlement | None:
    return db.scalar(
        select(BillingEntitlement).where(
            BillingEntitlement.tenant_id == tenant_id,
            BillingEntitlement.user_id == user_id,
        )
    )


def ledger_for_actor(
    db: Session, *, tenant_id: str, user_id: str, limit: int
) -> list[BillingWalletLedger]:
    return list(
        db.scalars(
            select(BillingWalletLedger)
            .where(
                BillingWalletLedger.tenant_id == tenant_id,
                BillingWalletLedger.user_id == user_id,
            )
            .order_by(BillingWalletLedger.created_at.desc())
            .limit(max(1, min(limit, 200)))
        ).all()
    )


def admin_transactions(db: Session, *, tenant_id: str, limit: int) -> list[BillingTransaction]:
    return list(
        db.scalars(
            select(BillingTransaction)
            .where(BillingTransaction.tenant_id == tenant_id)
            .order_by(BillingTransaction.created_at.desc())
            .limit(max(1, min(limit, 200)))
        ).all()
    )


def admin_summary(db: Session, *, tenant_id: str) -> dict[str, object]:
    confirmed = db.scalar(
        select(func.coalesce(func.sum(BillingTransaction.amount_usd), 0)).where(
            BillingTransaction.tenant_id == tenant_id,
            BillingTransaction.status == "confirmed",
        )
    ) or Decimal("0")
    reversed_amount = db.scalar(
        select(func.coalesce(func.sum(BillingTransaction.amount_usd), 0)).where(
            BillingTransaction.tenant_id == tenant_id,
            BillingTransaction.status.in_(["refunded", "chargeback"]),
        )
    ) or Decimal("0")
    wallet_balance = db.scalar(
        select(func.coalesce(func.sum(BillingWallet.balance_usd), 0)).where(
            BillingWallet.tenant_id == tenant_id
        )
    ) or Decimal("0")
    quarantined = db.scalar(
        select(func.coalesce(func.sum(BillingWallet.quarantined_usd), 0)).where(
            BillingWallet.tenant_id == tenant_id
        )
    ) or Decimal("0")
    transaction_count = db.scalar(
        select(func.count(BillingTransaction.id)).where(
            BillingTransaction.tenant_id == tenant_id
        )
    ) or 0
    wallet_count = db.scalar(
        select(func.count(BillingWallet.id)).where(
            BillingWallet.tenant_id == tenant_id
        )
    ) or 0
    return {
        "confirmed_revenue_usd": Decimal(str(confirmed)),
        "refunded_or_chargeback_usd": Decimal(str(reversed_amount)),
        "wallet_balance_usd": Decimal(str(wallet_balance)),
        "wallet_quarantined_usd": Decimal(str(quarantined)),
        "transaction_count": int(transaction_count),
        "wallet_count": int(wallet_count),
    }
