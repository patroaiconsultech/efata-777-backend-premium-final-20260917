from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from ..auth import Principal
from ..config import Settings, get_settings
from ..database import get_db
from ..services.identity import require_provisioned_admin, require_provisioned_principal
from .asaas_client import BillingProviderError
from .contracts import (
    BillingAdminSummary,
    BillingCheckoutCreate,
    BillingCheckoutView,
    BillingEntitlementView,
    BillingLedgerEntryView,
    BillingOverview,
    BillingWalletView,
)
from . import repository, service


router = APIRouter(prefix="/api/v2/billing", tags=["billing"])


def _raise(exc: Exception) -> None:
    if isinstance(exc, service.BillingDomainError):
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
    if isinstance(exc, BillingProviderError):
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
    raise exc


@router.get("/plans")
def plans(
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(require_provisioned_principal),
):
    try:
        return {"items": service.list_plans(settings)}
    except Exception as exc:
        _raise(exc)


@router.get("/topups")
def topups(
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(require_provisioned_principal),
):
    try:
        return {"items": service.list_topups(settings)}
    except Exception as exc:
        _raise(exc)


@router.get("/overview", response_model=BillingOverview)
def billing_overview(
    p: Principal = Depends(require_provisioned_principal),
    db: Session = Depends(get_db),
):
    try:
        return service.overview(db, principal=p)
    except Exception as exc:
        db.rollback()
        _raise(exc)


@router.post("/checkouts", response_model=BillingCheckoutView)
def create_checkout(
    payload: BillingCheckoutCreate,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    try:
        row = service.create_checkout(
            db,
            principal=p,
            settings=settings,
            payload=payload,
            idempotency_key=(idempotency_key or "").strip(),
        )
        return service.checkout_view(row)
    except Exception as exc:
        db.rollback()
        _raise(exc)


@router.get("/checkouts/{checkout_id}", response_model=BillingCheckoutView)
def checkout_status(
    checkout_id: str,
    p: Principal = Depends(require_provisioned_principal),
    db: Session = Depends(get_db),
):
    row = repository.checkout_for_actor(
        db,
        tenant_id=p.tenant_id,
        user_id=p.user_id,
        checkout_id=checkout_id,
    )
    if row is None:
        raise HTTPException(404, "BILLING_CHECKOUT_NOT_FOUND")
    return service.checkout_view(row)


@router.get("/wallet", response_model=BillingWalletView)
def wallet(
    p: Principal = Depends(require_provisioned_principal),
    db: Session = Depends(get_db),
):
    row = repository.wallet_for_actor(
        db, tenant_id=p.tenant_id, user_id=p.user_id
    )
    return service.wallet_view(row)


@router.get("/wallet/ledger", response_model=list[BillingLedgerEntryView])
def wallet_ledger(
    limit: int = 50,
    p: Principal = Depends(require_provisioned_principal),
    db: Session = Depends(get_db),
):
    rows = repository.ledger_for_actor(
        db,
        tenant_id=p.tenant_id,
        user_id=p.user_id,
        limit=limit,
    )
    return [service.ledger_view(row) for row in rows]


@router.post("/webhooks/asaas")
async def asaas_webhook(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    raw = await request.body()
    token = (request.headers.get("asaas-access-token") or "").strip()
    try:
        return service.process_asaas_webhook(
            db,
            settings=settings,
            raw_body=raw,
            supplied_token=token,
        )
    except Exception as exc:
        db.rollback()
        _raise(exc)


@router.get("/admin/transactions")
def admin_transactions(
    limit: int = 50,
    p: Principal = Depends(require_provisioned_admin),
    db: Session = Depends(get_db),
):
    rows = repository.admin_transactions(db, tenant_id=p.tenant_id, limit=limit)
    return {
        "items": [
            {
                "id": row.id,
                "user_id": row.user_id,
                "checkout_id": row.checkout_id,
                "provider": row.provider,
                "external_ref": row.external_ref,
                "plan_code": row.plan_code,
                "charge_kind": row.charge_kind,
                "currency": row.currency,
                "amount_usd": row.amount_usd,
                "status": row.status,
                "occurred_at": row.occurred_at.isoformat(),
            }
            for row in rows
        ]
    }


@router.get("/admin/summary", response_model=BillingAdminSummary)
def admin_summary(
    p: Principal = Depends(require_provisioned_admin),
    db: Session = Depends(get_db),
):
    return repository.admin_summary(db, tenant_id=p.tenant_id)
