from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..auth import Principal
from ..config import Settings
from ..models import (
    AuditEvent,
    BillingCheckout,
    BillingEntitlement,
    BillingTransaction,
    BillingWallet,
    BillingWalletLedger,
    BillingWebhookEvent,
    User,
    uid,
)
from .asaas_client import AsaasClient, BillingProviderError
from .catalog import (
    BillingCatalogError,
    amount_brl,
    amount_usd,
    included_credit_usd,
    plan_catalog,
    public_item,
    resolve_item,
    topup_catalog,
)
from . import repository


class BillingDomainError(RuntimeError):
    def __init__(self, code: str, status_code: int = 400):
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _decimal(value: object) -> Decimal:
    return Decimal(str(value or "0")).quantize(Decimal("0.0001"))


def _user(db: Session, principal: Principal) -> User:
    user = db.get(User, principal.user_id)
    if user is None:
        raise BillingDomainError("BILLING_USER_NOT_PROVISIONED", 403)
    return user


def _audit(
    db: Session,
    *,
    tenant_id: str | None,
    actor_id: str | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    outcome: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    safe = dict(metadata or {})
    for forbidden in ("token", "secret", "api_key", "access_token", "payload"):
        safe.pop(forbidden, None)
    db.add(
        AuditEvent(
            tenant_id=tenant_id,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            metadata_json=safe,
        )
    )


def _checkout_return_url(settings: Settings, checkout_id: str) -> str:
    base = settings.billing_checkout_success_url.strip()
    if not base:
        raise BillingDomainError("BILLING_CHECKOUT_RETURN_URL_NOT_CONFIGURED", 503)
    parts = urlsplit(base)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["checkout_id"] = checkout_id
    query["checkout"] = "return"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def list_plans(settings: Settings) -> list[dict[str, Any]]:
    return [
        public_item(item, settings, checkout_kind="plan")
        for item in plan_catalog(settings).values()
    ]


def list_topups(settings: Settings) -> list[dict[str, Any]]:
    return [
        public_item(item, settings, checkout_kind="topup")
        for item in topup_catalog(settings).values()
    ]


def get_or_create_wallet(
    db: Session, *, tenant_id: str, user_id: str
) -> BillingWallet:
    wallet = repository.wallet_for_actor(
        db, tenant_id=tenant_id, user_id=user_id
    )
    if wallet is not None:
        return wallet
    wallet = BillingWallet(
        tenant_id=tenant_id,
        user_id=user_id,
        currency="USD",
        status="active",
        balance_usd=Decimal("0"),
        lifetime_credited_usd=Decimal("0"),
        lifetime_debited_usd=Decimal("0"),
        quarantined_usd=Decimal("0"),
        auto_recharge_enabled=False,
        low_balance_threshold_usd=Decimal("3.0000"),
    )
    db.add(wallet)
    db.flush()
    return wallet


def checkout_view(row: BillingCheckout) -> dict[str, Any]:
    return {
        "id": row.id,
        "checkout_kind": row.checkout_kind,
        "item_code": row.item_code,
        "item_name": row.item_name,
        "status": row.status,
        "checkout_url": row.provider_url,
        "currency": row.currency,
        "amount_brl": _decimal(row.amount_brl).quantize(Decimal("0.01")),
        "amount_usd": _decimal(row.amount_usd),
        "created_at": row.created_at.isoformat(),
        "confirmed_at": row.confirmed_at.isoformat() if row.confirmed_at else None,
    }


def wallet_view(row: BillingWallet | None) -> dict[str, Any]:
    if row is None:
        return {
            "id": None,
            "currency": "USD",
            "status": "active",
            "balance_usd": Decimal("0.0000"),
            "lifetime_credited_usd": Decimal("0.0000"),
            "lifetime_debited_usd": Decimal("0.0000"),
            "quarantined_usd": Decimal("0.0000"),
            "low_balance_threshold_usd": Decimal("3.0000"),
        }
    return {
        "id": row.id,
        "currency": row.currency,
        "status": row.status,
        "balance_usd": _decimal(row.balance_usd),
        "lifetime_credited_usd": _decimal(row.lifetime_credited_usd),
        "lifetime_debited_usd": _decimal(row.lifetime_debited_usd),
        "quarantined_usd": _decimal(row.quarantined_usd),
        "low_balance_threshold_usd": (
            _decimal(row.low_balance_threshold_usd)
            if row.low_balance_threshold_usd is not None
            else None
        ),
    }


def entitlement_view(row: BillingEntitlement | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "plan_code": row.plan_code,
        "plan_name": row.plan_name,
        "status": row.status,
        "starts_at": row.starts_at.isoformat() if row.starts_at else None,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "last_payment_at": row.last_payment_at.isoformat() if row.last_payment_at else None,
    }


def ledger_view(row: BillingWalletLedger) -> dict[str, Any]:
    return {
        "id": row.id,
        "direction": row.direction,
        "source": row.source,
        "action_key": row.action_key,
        "amount_usd": _decimal(row.amount_usd),
        "balance_after_usd": _decimal(row.balance_after_usd),
        "currency": row.currency,
        "external_ref": row.external_ref,
        "created_at": row.created_at.isoformat(),
    }


def _provider_operation_state(row: BillingCheckout) -> str | None:
    metadata = dict(row.metadata_json or {})
    operation = metadata.get("provider_operation")
    if not isinstance(operation, dict):
        return None
    value = str(operation.get("state") or "").strip()
    return value or None


def _set_provider_operation_state(
    row: BillingCheckout,
    *,
    state: str,
    external_reference: str,
    error_code: str | None = None,
) -> None:
    metadata = dict(row.metadata_json or {})
    operation = metadata.get("provider_operation")
    operation = dict(operation) if isinstance(operation, dict) else {}
    operation.update(
        {
            "kind": "create_payment_link",
            "state": state,
            "external_reference": external_reference,
        }
    )
    if error_code:
        operation["last_error_code"] = error_code
    else:
        operation.pop("last_error_code", None)
    metadata["provider_operation"] = operation
    row.metadata_json = metadata


def _bind_provider_checkout(
    db: Session,
    *,
    row: BillingCheckout,
    provider_response: dict[str, Any],
    actor_id: str,
    reconciled: bool,
) -> BillingCheckout:
    row.provider_checkout_id = str(provider_response["id"])
    row.provider_url = str(provider_response["url"])
    _set_provider_operation_state(
        row,
        state="completed",
        external_reference=row.id,
    )
    row.updated_at = utcnow()
    _audit(
        db,
        tenant_id=row.tenant_id,
        actor_id=actor_id,
        action=(
            "billing.checkout.reconciled"
            if reconciled
            else "billing.checkout.created"
        ),
        resource_type="billing_checkout",
        resource_id=row.id,
        outcome="success",
        metadata={
            "checkout_kind": row.checkout_kind,
            "item_code": row.item_code,
            "provider": "asaas",
            "reconciled": reconciled,
        },
    )
    db.commit()
    db.refresh(row)
    return row


def _reconcile_existing_checkout(
    db: Session,
    *,
    row: BillingCheckout,
    principal: Principal,
    provider: AsaasClient,
) -> BillingCheckout:
    if row.provider_checkout_id and row.provider_url:
        return row
    if row.status == "failed":
        return row

    match = provider.find_payment_link_by_external_reference(row.id)
    if match is None:
        # Never blind-retry POST /paymentLinks after a durable call-start
        # marker. A negative lookup still does not prove the original POST was
        # never accepted under network/provider uncertainty.
        raise BillingDomainError("BILLING_CHECKOUT_RECONCILIATION_REQUIRED", 409)
    return _bind_provider_checkout(
        db,
        row=row,
        provider_response=match,
        actor_id=principal.user_id,
        reconciled=True,
    )


def create_checkout(
    db: Session,
    *,
    principal: Principal,
    settings: Settings,
    payload: Any,
    idempotency_key: str,
    client: AsaasClient | None = None,
) -> BillingCheckout:
    if not settings.billing_enabled:
        raise BillingDomainError("BILLING_DISABLED", 503)
    if not idempotency_key or len(idempotency_key) > 128:
        raise BillingDomainError("BILLING_IDEMPOTENCY_KEY_REQUIRED", 400)

    provider = client or AsaasClient(settings)
    existing = repository.checkout_by_idempotency(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        idempotency_key=idempotency_key,
    )
    if existing is not None:
        return _reconcile_existing_checkout(
            db,
            row=existing,
            principal=principal,
            provider=provider,
        )

    try:
        item = resolve_item(
            settings,
            checkout_kind=payload.checkout_kind,
            item_code=payload.item_code,
        )
    except BillingCatalogError as exc:
        raise BillingDomainError(str(exc), 503) from exc
    if item is None:
        raise BillingDomainError("BILLING_ITEM_NOT_FOUND", 404)

    user = _user(db, principal)
    payer_name = (payload.full_name or user.display_name or "").strip()
    if not payer_name:
        raise BillingDomainError("BILLING_PAYER_NAME_REQUIRED", 400)

    checkout_id = uid()
    callback = _checkout_return_url(settings, checkout_id)
    value_brl = amount_brl(item, settings, checkout_kind=payload.checkout_kind)
    value_usd = amount_usd(item, checkout_kind=payload.checkout_kind)
    if value_brl <= 0:
        raise BillingDomainError("BILLING_ITEM_NOT_PURCHASABLE", 400)

    provider_payload = {
        "name": str(item.get("name") or payload.item_code),
        "description": str(
            item.get("description") or item.get("name") or payload.item_code
        ),
        "billingType": "UNDEFINED",
        "chargeType": "DETACHED",
        "value": float(value_brl),
        "dueDateLimitDays": max(
            1, min(int(item.get("entitlement_days") or 7), 31)
        ),
        # Asaas supports externalReference on payment links and allows
        # read-only filtering by the same field. This is our reconciliation
        # anchor across a non-transactional provider boundary.
        "externalReference": checkout_id,
        "callback": {"successUrl": callback, "autoRedirect": False},
    }

    metadata = {
        "catalog_source": "configured",
        "included_credit_usd": str(
            included_credit_usd(item, checkout_kind=payload.checkout_kind)
        ),
        "entitlement_days": int(item.get("entitlement_days") or 31),
        "provider_operation": {
            "kind": "create_payment_link",
            "state": "provider_call_started",
            "external_reference": checkout_id,
            "attempt_count": 1,
        },
    }
    row = BillingCheckout(
        id=checkout_id,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        checkout_kind=payload.checkout_kind,
        item_code=payload.item_code,
        item_name=str(item.get("name") or payload.item_code),
        payer_email=user.email.strip().lower(),
        payer_name=payer_name,
        company=(payload.company or "").strip() or None,
        currency="BRL",
        amount_brl=value_brl,
        amount_usd=value_usd,
        status="pending",
        provider="asaas",
        provider_checkout_id=None,
        provider_url=None,
        callback_success_url=callback,
        idempotency_key=idempotency_key,
        metadata_json=metadata,
    )
    db.add(row)
    _audit(
        db,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="billing.checkout.provider_intent_committed",
        resource_type="billing_checkout",
        resource_id=row.id,
        outcome="pending",
        metadata={
            "checkout_kind": payload.checkout_kind,
            "item_code": payload.item_code,
            "provider": "asaas",
        },
    )
    try:
        # Durable boundary BEFORE the external POST. A racing request can only
        # observe an already-claimed idempotency key and must reconcile/read,
        # never issue a second provider POST.
        db.commit()
        db.refresh(row)
    except IntegrityError as exc:
        db.rollback()
        existing = repository.checkout_by_idempotency(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            idempotency_key=idempotency_key,
        )
        if existing is not None:
            return _reconcile_existing_checkout(
                db,
                row=existing,
                principal=principal,
                provider=provider,
            )
        raise BillingDomainError("BILLING_CHECKOUT_CONFLICT", 409) from exc

    try:
        provider_response = provider.create_payment_link(provider_payload)
    except BillingProviderError as exc:
        if exc.outcome_unknown:
            _set_provider_operation_state(
                row,
                state="outcome_unknown",
                external_reference=row.id,
                error_code=exc.code,
            )
        else:
            row.status = "failed"
            _set_provider_operation_state(
                row,
                state="failed",
                external_reference=row.id,
                error_code=exc.code,
            )
        row.updated_at = utcnow()
        _audit(
            db,
            tenant_id=row.tenant_id,
            actor_id=principal.user_id,
            action="billing.checkout.provider_failed",
            resource_type="billing_checkout",
            resource_id=row.id,
            outcome=("unknown" if exc.outcome_unknown else "failed"),
            metadata={
                "provider": "asaas",
                "error_code": exc.code,
                "provider_outcome_unknown": exc.outcome_unknown,
            },
        )
        # Preserve the durable intent/outcome classification. The caller may
        # receive an error, but retry cannot erase the reconciliation anchor.
        db.commit()
        raise

    return _bind_provider_checkout(
        db,
        row=row,
        provider_response=provider_response,
        actor_id=principal.user_id,
        reconciled=False,
    )

def _event_key(
    *,
    provider_event_id: str | None,
    event_type: str,
    provider_payment_id: str | None,
    provider_checkout_id: str | None,
    raw_body: bytes,
) -> str:
    if provider_event_id:
        # Asaas documents webhook event IDs as stable across at-least-once
        # redelivery. Hash the provider ID rather than persisting raw payload.
        return hashlib.sha256(
            f"asaas-event|{provider_event_id}".encode("utf-8")
        ).hexdigest()
    anchor = "|".join(
        [
            event_type,
            provider_payment_id or "",
            provider_checkout_id or "",
        ]
    )
    if provider_payment_id or provider_checkout_id:
        return hashlib.sha256(anchor.encode("utf-8")).hexdigest()
    return hashlib.sha256(raw_body).hexdigest()


def _extract_provider_ids(payload: dict[str, Any]) -> tuple[str | None, str | None]:
    payment = payload.get("payment")
    payment = payment if isinstance(payment, dict) else {}
    payment_id = payment.get("id") or payload.get("paymentId")
    link = payment.get("paymentLink") or payload.get("paymentLink")
    if isinstance(link, dict):
        link = link.get("id")
    return (
        str(payment_id).strip() if payment_id else None,
        str(link).strip() if link else None,
    )


def _claim_event(
    db: Session,
    *,
    provider_event_id: str | None,
    event_type: str,
    provider_payment_id: str | None,
    provider_checkout_id: str | None,
    raw_body: bytes,
) -> BillingWebhookEvent | None:
    key = _event_key(
        provider_event_id=provider_event_id,
        event_type=event_type,
        provider_payment_id=provider_payment_id,
        provider_checkout_id=provider_checkout_id,
        raw_body=raw_body,
    )
    row = BillingWebhookEvent(
        provider="asaas",
        provider_event_key=key,
        event_type=event_type,
        payload_sha256=hashlib.sha256(raw_body).hexdigest(),
        provider_payment_id=provider_payment_id,
        provider_checkout_id=provider_checkout_id,
        status="received",
    )
    db.add(row)
    try:
        db.flush()
        return row
    except IntegrityError:
        db.rollback()
        return None

def _checkout_for_provider(
    db: Session,
    *,
    provider_payment_id: str | None,
    provider_checkout_id: str | None,
) -> BillingCheckout | None:
    row = None
    if provider_checkout_id:
        row = db.scalar(
            select(BillingCheckout).where(
                BillingCheckout.provider == "asaas",
                BillingCheckout.provider_checkout_id == provider_checkout_id,
            )
        )
    if row is None and provider_payment_id:
        row = db.scalar(
            select(BillingCheckout).where(
                BillingCheckout.provider == "asaas",
                BillingCheckout.provider_payment_id == provider_payment_id,
            )
        )
    return row


def _ledger_exists(db: Session, *, tenant_id: str, idempotency_key: str) -> bool:
    return (
        db.scalar(
            select(BillingWalletLedger.id).where(
                BillingWalletLedger.tenant_id == tenant_id,
                BillingWalletLedger.idempotency_key == idempotency_key,
            )
        )
        is not None
    )


def _credit_wallet(
    db: Session,
    *,
    checkout: BillingCheckout,
    provider_payment_id: str,
    amount: Decimal,
) -> BillingWallet:
    wallet = get_or_create_wallet(
        db, tenant_id=checkout.tenant_id, user_id=checkout.user_id
    )
    key = f"asaas:{provider_payment_id}:credit"
    if amount <= 0 or _ledger_exists(db, tenant_id=checkout.tenant_id, idempotency_key=key):
        return wallet
    new_balance = _decimal(wallet.balance_usd) + amount
    wallet.balance_usd = new_balance
    wallet.lifetime_credited_usd = _decimal(wallet.lifetime_credited_usd) + amount
    db.add(
        BillingWalletLedger(
            tenant_id=checkout.tenant_id,
            user_id=checkout.user_id,
            wallet_id=wallet.id,
            direction="credit",
            source=(
                "topup" if checkout.checkout_kind == "topup" else "plan_included"
            ),
            idempotency_key=key,
            action_key=checkout.item_code,
            amount_usd=amount,
            balance_after_usd=new_balance,
            currency="USD",
            provider="asaas",
            external_ref=provider_payment_id,
            related_checkout_id=checkout.id,
            metadata_json={"policy": "checkout_credit_exactly_once"},
            created_by="billing_webhook",
        )
    )
    return wallet


def _revoke_entitlement(
    db: Session, *, checkout: BillingCheckout, status: str, when: datetime
) -> None:
    if checkout.checkout_kind != "plan":
        return
    ent = repository.entitlement_for_actor(
        db, tenant_id=checkout.tenant_id, user_id=checkout.user_id
    )
    if ent is not None:
        ent.status = status
        ent.updated_at = when


def _activate_entitlement(
    db: Session, *, checkout: BillingCheckout, when: datetime
) -> None:
    if checkout.checkout_kind != "plan":
        return
    days = max(1, min(int(checkout.metadata_json.get("entitlement_days") or 31), 366))
    ent = repository.entitlement_for_actor(
        db, tenant_id=checkout.tenant_id, user_id=checkout.user_id
    )
    if ent is None:
        ent = BillingEntitlement(
            tenant_id=checkout.tenant_id,
            user_id=checkout.user_id,
            plan_code=checkout.item_code,
            plan_name=checkout.item_name,
            status="active",
            checkout_id=checkout.id,
            starts_at=when,
            expires_at=when + timedelta(days=days),
            last_payment_at=when,
        )
        db.add(ent)
        return
    ent.plan_code = checkout.item_code
    ent.plan_name = checkout.item_name
    ent.status = "active"
    ent.checkout_id = checkout.id
    ent.starts_at = ent.starts_at or when
    ent.expires_at = when + timedelta(days=days)
    ent.last_payment_at = when
    ent.updated_at = when


def _record_transaction(
    db: Session,
    *,
    checkout: BillingCheckout,
    provider_payment_id: str,
    status: str,
    charge_kind: str,
    when: datetime,
) -> BillingTransaction:
    existing = db.scalar(
        select(BillingTransaction).where(
            BillingTransaction.provider == "asaas",
            BillingTransaction.external_ref == provider_payment_id,
            BillingTransaction.status == status,
            BillingTransaction.charge_kind == charge_kind,
        )
    )
    if existing is not None:
        return existing
    tx = BillingTransaction(
        tenant_id=checkout.tenant_id,
        user_id=checkout.user_id,
        checkout_id=checkout.id,
        provider="asaas",
        external_ref=provider_payment_id,
        plan_code=checkout.item_code,
        charge_kind=charge_kind,
        currency="USD",
        amount_original=checkout.amount_brl,
        amount_usd=checkout.amount_usd,
        normalized_mrr_usd=(
            checkout.amount_usd if checkout.checkout_kind == "plan" else Decimal("0")
        ),
        status=status,
        notes=f"Provider event for checkout {checkout.id}",
        created_by="billing_webhook",
        occurred_at=when,
        confirmed_at=when,
    )
    db.add(tx)
    db.flush()
    return tx


def _reverse_checkout_credit(
    db: Session,
    *,
    checkout: BillingCheckout,
    provider_payment_id: str,
    source: str,
    tx: BillingTransaction,
) -> BillingWallet | None:
    """Explicit refund/chargeback policy.

    Reverse only credit that was actually materialized for this checkout. A
    reversal received before any credit must not create a synthetic wallet.
    If previously spent funds make a full reversal impossible, keep balance
    non-negative, quarantine the unrecovered amount and mark the wallet
    quarantined.
    """
    key = f"asaas:{provider_payment_id}:{source}"
    if _ledger_exists(db, tenant_id=checkout.tenant_id, idempotency_key=key):
        return repository.wallet_for_actor(
            db, tenant_id=checkout.tenant_id, user_id=checkout.user_id
        )

    original_credit = db.scalar(
        select(BillingWalletLedger).where(
            BillingWalletLedger.tenant_id == checkout.tenant_id,
            BillingWalletLedger.user_id == checkout.user_id,
            BillingWalletLedger.related_checkout_id == checkout.id,
            BillingWalletLedger.direction == "credit",
        ).order_by(BillingWalletLedger.created_at.asc())
    )
    if original_credit is None:
        return repository.wallet_for_actor(
            db, tenant_id=checkout.tenant_id, user_id=checkout.user_id
        )

    wallet = get_or_create_wallet(
        db, tenant_id=checkout.tenant_id, user_id=checkout.user_id
    )
    target = _decimal(original_credit.amount_usd)
    current = _decimal(wallet.balance_usd)
    actual = min(current, target)
    shortfall = target - actual
    new_balance = current - actual
    wallet.balance_usd = new_balance
    wallet.lifetime_debited_usd = _decimal(wallet.lifetime_debited_usd) + actual
    if shortfall > 0:
        wallet.status = "quarantined"
        wallet.quarantined_usd = _decimal(wallet.quarantined_usd) + shortfall
    db.add(
        BillingWalletLedger(
            tenant_id=checkout.tenant_id,
            user_id=checkout.user_id,
            wallet_id=wallet.id,
            direction="debit",
            source=source,
            idempotency_key=key,
            action_key=checkout.item_code,
            amount_usd=actual,
            balance_after_usd=new_balance,
            currency="USD",
            provider="asaas",
            external_ref=provider_payment_id,
            related_checkout_id=checkout.id,
            related_tx_id=tx.id,
            metadata_json={
                "policy": "reverse_available_then_quarantine_shortfall",
                "original_credit_usd": str(target),
                "unrecovered_usd": str(shortfall),
            },
            created_by="billing_webhook",
        )
    )
    return wallet


_CONFIRM_EVENTS = {"PAYMENT_CONFIRMED", "PAYMENT_RECEIVED"}
_REVERSAL_EVENTS = {
    "PAYMENT_REFUNDED": "refunded",
    "PAYMENT_CHARGEBACK_REQUESTED": "chargeback",
    "PAYMENT_CHARGEBACK_DISPUTE": "chargeback",
}
_TERMINAL_FINANCIAL_STATES = {"refunded", "chargeback"}


def _billing_transition(current_state: str, event_type: str) -> tuple[str, str]:
    """Return (decision, next_state) for provider events.

    ``ignore`` is a deliberate no-financial-mutation result. Reversal states
    dominate delayed confirmations. A second confirmation while already paid
    is also a no-op so entitlement expiry cannot be extended by duplicate
    provider events with distinct event IDs.
    """
    if current_state in _TERMINAL_FINANCIAL_STATES:
        return "ignore", current_state

    if event_type in _CONFIRM_EVENTS:
        if current_state in {"paid", "cancelled"}:
            return "ignore", current_state
        return "confirm", "paid"

    if event_type == "PAYMENT_OVERDUE":
        if current_state in {"paid", "expired", "cancelled"}:
            return "ignore", current_state
        return "expire", "expired"

    if event_type == "PAYMENT_DELETED":
        if current_state in {"paid", "cancelled"}:
            return "ignore", current_state
        return "cancel", "cancelled"

    if event_type in _REVERSAL_EVENTS:
        return "reverse", _REVERSAL_EVENTS[event_type]

    return "ignore_unsupported", current_state


def _ignore_webhook_event(
    db: Session,
    *,
    event: BillingWebhookEvent,
    checkout: BillingCheckout,
    event_type: str,
    reason: str,
) -> dict[str, Any]:
    now = utcnow()
    event.status = "ignored"
    event.processed_at = now
    _audit(
        db,
        tenant_id=checkout.tenant_id,
        actor_id=None,
        action="billing.webhook.ignored",
        resource_type="billing_webhook_event",
        resource_id=event.id,
        outcome="ignored",
        metadata={
            "event_type": event_type,
            "reason": reason,
            "checkout_state": checkout.status,
        },
    )
    db.commit()
    return {"ok": True, "ignored": True, "reason": reason}


def process_asaas_webhook(
    db: Session,
    *,
    settings: Settings,
    raw_body: bytes,
    supplied_token: str,
) -> dict[str, Any]:
    expected = settings.asaas_webhook_token.strip()
    if not expected:
        raise BillingDomainError("BILLING_WEBHOOK_NOT_CONFIGURED", 503)
    if not supplied_token or not hmac.compare_digest(supplied_token, expected):
        raise BillingDomainError("BILLING_WEBHOOK_TOKEN_INVALID", 401)
    try:
        payload = json.loads(raw_body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BillingDomainError("BILLING_WEBHOOK_INVALID_JSON", 400) from exc
    if not isinstance(payload, dict):
        raise BillingDomainError("BILLING_WEBHOOK_INVALID_JSON", 400)

    event_type = str(
        payload.get("event") or payload.get("eventType") or "UNKNOWN"
    ).strip().upper()
    provider_event_id = str(payload.get("id") or "").strip() or None
    provider_payment_id, provider_checkout_id = _extract_provider_ids(payload)
    event = _claim_event(
        db,
        provider_event_id=provider_event_id,
        event_type=event_type,
        provider_payment_id=provider_payment_id,
        provider_checkout_id=provider_checkout_id,
        raw_body=raw_body,
    )
    if event is None:
        return {"ok": True, "deduplicated": True}

    checkout = _checkout_for_provider(
        db,
        provider_payment_id=provider_payment_id,
        provider_checkout_id=provider_checkout_id,
    )
    now = utcnow()
    if checkout is None:
        event.status = "ignored"
        event.processed_at = now
        _audit(
            db,
            tenant_id=None,
            actor_id=None,
            action="billing.webhook.ignored",
            resource_type="billing_webhook_event",
            resource_id=event.id,
            outcome="ignored",
            metadata={"event_type": event_type, "reason": "checkout_not_found"},
        )
        db.commit()
        return {"ok": True, "ignored": True}

    event.tenant_id = checkout.tenant_id
    event.user_id = checkout.user_id
    event.checkout_id = checkout.id
    checkout.provider_payment_id = (
        provider_payment_id or checkout.provider_payment_id
    )

    payment_ref = (
        provider_payment_id
        or checkout.provider_payment_id
        or checkout.provider_checkout_id
    )
    if not payment_ref:
        raise BillingDomainError(
            "BILLING_WEBHOOK_PAYMENT_REFERENCE_REQUIRED", 400
        )

    decision, next_state = _billing_transition(checkout.status, event_type)
    if decision == "ignore":
        return _ignore_webhook_event(
            db,
            event=event,
            checkout=checkout,
            event_type=event_type,
            reason="state_transition_guard",
        )
    if decision == "ignore_unsupported":
        return _ignore_webhook_event(
            db,
            event=event,
            checkout=checkout,
            event_type=event_type,
            reason="unsupported_event",
        )

    if decision == "confirm":
        checkout.status = next_state
        checkout.confirmed_at = now
        _activate_entitlement(db, checkout=checkout, when=now)
        _record_transaction(
            db,
            checkout=checkout,
            provider_payment_id=payment_ref,
            status="confirmed",
            charge_kind=(
                "wallet_topup"
                if checkout.checkout_kind == "topup"
                else "recurring"
            ),
            when=now,
        )
        amount = _decimal(checkout.metadata_json.get("included_credit_usd"))
        _credit_wallet(
            db,
            checkout=checkout,
            provider_payment_id=payment_ref,
            amount=amount,
        )
        audit_action = "billing.payment.confirmed"
    elif decision == "expire":
        checkout.status = next_state
        _revoke_entitlement(
            db, checkout=checkout, status=next_state, when=now
        )
        audit_action = "billing.payment.overdue"
    elif decision == "cancel":
        checkout.status = next_state
        _revoke_entitlement(
            db, checkout=checkout, status=next_state, when=now
        )
        audit_action = "billing.payment.cancelled"
    elif decision == "reverse":
        checkout.status = next_state
        checkout.reversed_at = now
        _revoke_entitlement(
            db, checkout=checkout, status=next_state, when=now
        )
        tx = _record_transaction(
            db,
            checkout=checkout,
            provider_payment_id=payment_ref,
            status=next_state,
            charge_kind=next_state,
            when=now,
        )
        _reverse_checkout_credit(
            db,
            checkout=checkout,
            provider_payment_id=payment_ref,
            source=next_state,
            tx=tx,
        )
        audit_action = f"billing.payment.{next_state}"
    else:  # pragma: no cover - transition table is closed above.
        raise BillingDomainError("BILLING_STATE_TRANSITION_INVALID", 500)

    event.status = "processed"
    event.processed_at = now
    checkout.updated_at = now
    _audit(
        db,
        tenant_id=checkout.tenant_id,
        actor_id=None,
        action=audit_action,
        resource_type="billing_checkout",
        resource_id=checkout.id,
        outcome="success",
        metadata={
            "event_type": event_type,
            "provider": "asaas",
            "checkout_kind": checkout.checkout_kind,
            "item_code": checkout.item_code,
            "previous_state_guarded": True,
        },
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return {"ok": True, "deduplicated": True}
    return {"ok": True, "deduplicated": False}

def overview(db: Session, *, principal: Principal) -> dict[str, Any]:
    # GET/read-only contract: absence of a wallet is represented as zero state.
    # Never create or commit financial state from a read endpoint.
    wallet = repository.wallet_for_actor(
        db, tenant_id=principal.tenant_id, user_id=principal.user_id
    )
    ent = repository.entitlement_for_actor(
        db, tenant_id=principal.tenant_id, user_id=principal.user_id
    )
    return {"wallet": wallet_view(wallet), "entitlement": entitlement_view(ent)}
