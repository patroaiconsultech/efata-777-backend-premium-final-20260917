from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from ..config import Settings


@dataclass(frozen=True)
class BillingProviderError(RuntimeError):
    code: str
    status_code: int = 502
    outcome_unknown: bool = True

    def __str__(self) -> str:
        return self.code


class AsaasClient:
    """Fail-closed Asaas adapter with explicit reconciliation support.

    POST /paymentLinks is deliberately never retried automatically. The caller
    persists a durable local intent before the POST and uses ``externalReference``
    to reconcile an uncertain provider outcome through a read-only lookup.
    """

    def __init__(self, settings: Settings, *, transport: httpx.BaseTransport | None = None):
        self.settings = settings
        self._transport = transport

    def _assert_configured(self) -> None:
        if not self.settings.billing_enabled:
            raise BillingProviderError("BILLING_DISABLED", 503, False)
        if self.settings.billing_provider != "asaas":
            raise BillingProviderError("BILLING_PROVIDER_NOT_CONFIGURED", 503, False)
        if not self.settings.asaas_api_key.strip():
            raise BillingProviderError("BILLING_PROVIDER_NOT_CONFIGURED", 503, False)

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "User-Agent": "EFATA-777/1.1",
            "access_token": self.settings.asaas_api_key,
        }

    def create_payment_link(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._assert_configured()
        url = self.settings.asaas_api_base_url.rstrip("/") + "/paymentLinks"
        try:
            with httpx.Client(
                timeout=self.settings.billing_http_timeout_seconds,
                transport=self._transport,
            ) as client:
                response = client.post(url, json=payload, headers=self._headers())
        except httpx.TimeoutException as exc:
            raise BillingProviderError("BILLING_PROVIDER_TIMEOUT", 504, True) from exc
        except httpx.HTTPError as exc:
            raise BillingProviderError("BILLING_PROVIDER_UNAVAILABLE", 502, True) from exc

        if 500 <= response.status_code:
            # A 5xx response after a POST does not prove whether the provider
            # created the resource. Reconciliation is required before retry.
            raise BillingProviderError("BILLING_PROVIDER_UPSTREAM_5XX", 502, True)
        if response.status_code >= 400:
            # Provider rejection is treated as definitive for this attempt.
            raise BillingProviderError("BILLING_PROVIDER_REJECTED", 502, False)
        try:
            body = response.json()
        except ValueError as exc:
            raise BillingProviderError("BILLING_PROVIDER_INVALID_RESPONSE", 502, True) from exc
        if not isinstance(body, dict) or not body.get("id") or not body.get("url"):
            raise BillingProviderError("BILLING_PROVIDER_INVALID_RESPONSE", 502, True)
        return body

    def find_payment_link_by_external_reference(
        self, external_reference: str
    ) -> dict[str, Any] | None:
        """Read-only reconciliation lookup for a previously attempted POST."""
        self._assert_configured()
        url = self.settings.asaas_api_base_url.rstrip("/") + "/paymentLinks"
        try:
            with httpx.Client(
                timeout=self.settings.billing_http_timeout_seconds,
                transport=self._transport,
            ) as client:
                response = client.get(
                    url,
                    params={
                        "externalReference": external_reference,
                        "limit": 10,
                    },
                    headers=self._headers(),
                )
        except httpx.TimeoutException as exc:
            raise BillingProviderError(
                "BILLING_PROVIDER_RECONCILIATION_TIMEOUT", 504, True
            ) from exc
        except httpx.HTTPError as exc:
            raise BillingProviderError(
                "BILLING_PROVIDER_RECONCILIATION_UNAVAILABLE", 502, True
            ) from exc

        if response.status_code >= 400:
            raise BillingProviderError(
                "BILLING_PROVIDER_RECONCILIATION_FAILED", 502, True
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise BillingProviderError(
                "BILLING_PROVIDER_RECONCILIATION_INVALID_RESPONSE", 502, True
            ) from exc
        if not isinstance(body, dict) or not isinstance(body.get("data"), list):
            raise BillingProviderError(
                "BILLING_PROVIDER_RECONCILIATION_INVALID_RESPONSE", 502, True
            )

        exact = [
            item
            for item in body["data"]
            if isinstance(item, dict)
            and str(item.get("externalReference") or "") == external_reference
        ]
        if not exact:
            return None
        if len(exact) != 1:
            raise BillingProviderError(
                "BILLING_PROVIDER_RECONCILIATION_AMBIGUOUS", 502, True
            )
        item = exact[0]
        if not item.get("id") or not item.get("url"):
            raise BillingProviderError(
                "BILLING_PROVIDER_RECONCILIATION_INVALID_RESPONSE", 502, True
            )
        return {"id": str(item["id"]), "url": str(item["url"])}
