from __future__ import annotations

import json
from copy import deepcopy
from decimal import Decimal
from typing import Any

from ..config import Settings


class BillingCatalogError(RuntimeError):
    pass


def _load(raw: str, *, kind: str) -> dict[str, dict[str, Any]]:
    if not raw.strip():
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BillingCatalogError(f"BILLING_{kind.upper()}_CATALOG_INVALID_JSON") from exc
    if not isinstance(payload, dict):
        raise BillingCatalogError(f"BILLING_{kind.upper()}_CATALOG_MUST_BE_OBJECT")
    result: dict[str, dict[str, Any]] = {}
    for key, item in payload.items():
        if not isinstance(key, str) or not key.strip() or not isinstance(item, dict):
            raise BillingCatalogError(f"BILLING_{kind.upper()}_CATALOG_INVALID_ITEM")
        code = str(item.get("code") or key).strip()
        if code != key:
            raise BillingCatalogError(f"BILLING_{kind.upper()}_CATALOG_CODE_MISMATCH")
        copied = deepcopy(item)
        copied["code"] = code
        result[code] = copied
    return result


def plan_catalog(settings: Settings) -> dict[str, dict[str, Any]]:
    return _load(settings.billing_plan_catalog_json, kind="plan")


def topup_catalog(settings: Settings) -> dict[str, dict[str, Any]]:
    return _load(settings.billing_topup_catalog_json, kind="topup")


def resolve_item(
    settings: Settings,
    *,
    checkout_kind: str,
    item_code: str,
) -> dict[str, Any] | None:
    catalog = topup_catalog(settings) if checkout_kind == "topup" else plan_catalog(settings)
    item = catalog.get(item_code)
    return deepcopy(item) if item else None


def money_decimal(value: object, *, default: str = "0") -> Decimal:
    if value is None or value == "":
        return Decimal(default)
    return Decimal(str(value))


def amount_usd(item: dict[str, Any], *, checkout_kind: str) -> Decimal:
    field = "pay_usd" if checkout_kind == "topup" else "price_usd"
    return money_decimal(item.get(field))


def amount_brl(item: dict[str, Any], settings: Settings, *, checkout_kind: str) -> Decimal:
    direct = item.get("pay_brl" if checkout_kind == "topup" else "price_brl")
    if direct is not None:
        return money_decimal(direct).quantize(Decimal("0.01"))
    return (amount_usd(item, checkout_kind=checkout_kind) * money_decimal(settings.billing_usd_brl)).quantize(Decimal("0.01"))


def included_credit_usd(item: dict[str, Any], *, checkout_kind: str) -> Decimal:
    field = "credit_usd" if checkout_kind == "topup" else "included_credit_usd"
    return money_decimal(item.get(field)).quantize(Decimal("0.0001"))


def public_item(item: dict[str, Any], settings: Settings, *, checkout_kind: str) -> dict[str, Any]:
    result = {
        "code": str(item.get("code") or ""),
        "name": str(item.get("name") or item.get("code") or ""),
        "kind": checkout_kind,
        "description": str(item.get("description") or ""),
        "display_currency": str(item.get("display_currency") or "USD"),
        "price_usd": amount_usd(item, checkout_kind=checkout_kind),
        "price_brl": amount_brl(item, settings, checkout_kind=checkout_kind),
        "included_credit_usd": included_credit_usd(item, checkout_kind=checkout_kind),
        "badge": item.get("badge"),
        "features": list(item.get("features") or []),
    }
    if checkout_kind == "plan":
        result["entitlement_days"] = int(item.get("entitlement_days") or 31)
    return result
