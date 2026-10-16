from __future__ import annotations

import json
from decimal import Decimal

import pytest
import httpx
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from orkio_v2.auth import Principal
from orkio_v2.billing.asaas_client import AsaasClient, BillingProviderError
from orkio_v2.billing.contracts import BillingCheckoutCreate
from orkio_v2.billing import repository, service
from orkio_v2.config import Settings
from orkio_v2.database import Base
from orkio_v2.main import app
from orkio_v2.models import (
    AuditEvent,
    BillingCheckout,
    BillingEntitlement,
    BillingTransaction,
    BillingWallet,
    BillingWalletLedger,
    BillingWebhookEvent,
    Membership,
    Tenant,
    User,
)


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as session:
        session.add_all(
            [
                Tenant(id="tenant-a", name="Tenant A"),
                Tenant(id="tenant-b", name="Tenant B"),
                User(
                    id="user-a",
                    external_subject="sub-user-a",
                    email="a@example.com",
                    display_name="User A",
                ),
                User(
                    id="user-b",
                    external_subject="sub-user-b",
                    email="b@example.com",
                    display_name="User B",
                ),
                Membership(tenant_id="tenant-a", user_id="user-a", role="admin"),
                Membership(tenant_id="tenant-b", user_id="user-b", role="member"),
            ]
        )
        session.commit()
        yield session


def principal(user: str, tenant: str, role: str = "member") -> Principal:
    return Principal(
        user_id=user,
        tenant_id=tenant,
        roles=(role,),
        email=f"{user}@example.com",
        external_subject=f"sub-{user}",
    )


PLAN_CATALOG = json.dumps(
    {
        "founder_access": {
            "code": "founder_access",
            "name": "Founder Access",
            "price_usd": "20.00",
            "price_brl": "100.00",
            "included_credit_usd": "20.00",
            "entitlement_days": 31,
            "description": "Test plan",
        }
    }
)
TOPUP_CATALOG = json.dumps(
    {
        "topup_10": {
            "code": "topup_10",
            "name": "Top-up 10",
            "pay_usd": "10.00",
            "pay_brl": "50.00",
            "credit_usd": "10.00",
            "description": "Test topup",
        }
    }
)


def billing_settings(**overrides) -> Settings:
    values = {
        "PLATFORM_ENVIRONMENT": "test",
        "PLATFORM_AUTH_MODE": "test",
        "PLATFORM_INVITATION_TOKEN_SECRET": "x" * 40,
        "PLATFORM_BILLING_ENABLED": True,
        "PLATFORM_BILLING_PROVIDER": "asaas",
        "PLATFORM_BILLING_PLAN_CATALOG_JSON": PLAN_CATALOG,
        "PLATFORM_BILLING_TOPUP_CATALOG_JSON": TOPUP_CATALOG,
        "PLATFORM_BILLING_CHECKOUT_SUCCESS_URL": "https://example.test/billing/return",
        "ASAAS_API_KEY": "provider-test-key",
        "ASAAS_WEBHOOK_TOKEN": "w" * 32,
        "ASAAS_API_BASE_URL": "https://api-sandbox.asaas.com/v3",
    }
    values.update(overrides)
    return Settings(**values)


class FakeProvider:
    def __init__(self):
        self.calls = 0
        self.reconcile_calls = 0
        self.links_by_external_reference = {}
        self.last_payload = None

    def create_payment_link(self, payload):
        self.calls += 1
        self.last_payload = dict(payload)
        link = {
            "id": f"plink-{self.calls}",
            "url": f"https://sandbox.example/checkout/{self.calls}",
        }
        self.links_by_external_reference[str(payload["externalReference"])] = link
        return link

    def find_payment_link_by_external_reference(self, external_reference):
        self.reconcile_calls += 1
        return self.links_by_external_reference.get(external_reference)


class FailingProvider:
    def __init__(self):
        self.calls = 0
        self.reconcile_calls = 0

    def create_payment_link(self, payload):
        self.calls += 1
        raise BillingProviderError("BILLING_PROVIDER_TIMEOUT", 504, True)

    def find_payment_link_by_external_reference(self, external_reference):
        self.reconcile_calls += 1
        return None


class TimeoutAfterProviderCreated(FakeProvider):
    def create_payment_link(self, payload):
        link = super().create_payment_link(payload)
        raise BillingProviderError("BILLING_PROVIDER_TIMEOUT", 504, True)


def create_plan_checkout(db, *, provider=None, key="idem-1"):
    provider = provider or FakeProvider()
    row = service.create_checkout(
        db,
        principal=principal("user-a", "tenant-a"),
        settings=billing_settings(),
        payload=BillingCheckoutCreate(
            item_code="founder_access",
            checkout_kind="plan",
        ),
        idempotency_key=key,
        client=provider,
    )
    return row, provider


def confirmed_payload(checkout, *, event="PAYMENT_CONFIRMED"):
    return json.dumps(
        {
            "event": event,
            "payment": {
                "id": "pay-1",
                "paymentLink": checkout.provider_checkout_id,
            },
        },
        separators=(",", ":"),
    ).encode()


def test_checkout_claims_idempotency_before_provider_side_effect(db):
    provider = FakeProvider()
    first, _ = create_plan_checkout(db, provider=provider, key="same-key")
    second, _ = create_plan_checkout(db, provider=provider, key="same-key")

    assert first.id == second.id
    assert provider.calls == 1
    assert db.scalar(select(func.count(BillingCheckout.id))) == 1


def test_provider_timeout_preserves_durable_intent_and_never_blind_reposts(db):
    provider = FailingProvider()
    with pytest.raises(BillingProviderError) as raised:
        create_plan_checkout(db, provider=provider, key="failure-key")
    assert raised.value.code == "BILLING_PROVIDER_TIMEOUT"
    assert "provider-test-key" not in str(raised.value)

    row = repository.checkout_by_idempotency(
        db,
        tenant_id="tenant-a",
        user_id="user-a",
        idempotency_key="failure-key",
    )
    assert row is not None
    assert row.status == "pending"
    assert row.provider_checkout_id is None
    assert row.metadata_json["provider_operation"]["state"] == "outcome_unknown"
    assert provider.calls == 1

    with pytest.raises(service.BillingDomainError) as retry:
        create_plan_checkout(db, provider=provider, key="failure-key")
    assert retry.value.code == "BILLING_CHECKOUT_RECONCILIATION_REQUIRED"
    assert provider.calls == 1
    assert provider.reconcile_calls == 1


def test_uncertain_provider_success_is_reconciled_without_second_post(db):
    provider = TimeoutAfterProviderCreated()
    with pytest.raises(BillingProviderError):
        create_plan_checkout(db, provider=provider, key="reconcile-key")

    row = repository.checkout_by_idempotency(
        db,
        tenant_id="tenant-a",
        user_id="user-a",
        idempotency_key="reconcile-key",
    )
    assert row is not None
    assert row.provider_checkout_id is None
    assert provider.calls == 1

    reconciled, _ = create_plan_checkout(
        db,
        provider=provider,
        key="reconcile-key",
    )
    assert provider.calls == 1
    assert provider.reconcile_calls == 1
    assert reconciled.provider_checkout_id == "plink-1"
    assert reconciled.provider_url == "https://sandbox.example/checkout/1"
    assert reconciled.metadata_json["provider_operation"]["state"] == "completed"


def test_provider_payload_uses_durable_external_reference(db):
    provider = FakeProvider()
    row, _ = create_plan_checkout(db, provider=provider, key="external-ref-key")
    assert provider.last_payload["externalReference"] == row.id
    assert (
        row.metadata_json["provider_operation"]["external_reference"]
        == row.id
    )


def test_real_asaas_adapter_reconciles_by_external_reference_without_post():
    seen = {}

    def handler(request: httpx.Request):
        seen["method"] = request.method
        seen["external_reference"] = request.url.params.get("externalReference")
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "plink-reconciled",
                        "url": "https://sandbox.example/reconciled",
                        "externalReference": "checkout-123",
                    }
                ]
            },
        )

    client = AsaasClient(
        billing_settings(),
        transport=httpx.MockTransport(handler),
    )
    result = client.find_payment_link_by_external_reference("checkout-123")
    assert seen == {
        "method": "GET",
        "external_reference": "checkout-123",
    }
    assert result == {
        "id": "plink-reconciled",
        "url": "https://sandbox.example/reconciled",
    }


def test_real_asaas_adapter_fails_closed_on_ambiguous_reconciliation():
    def handler(request: httpx.Request):
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "plink-1",
                        "url": "https://sandbox.example/1",
                        "externalReference": "checkout-ambiguous",
                    },
                    {
                        "id": "plink-2",
                        "url": "https://sandbox.example/2",
                        "externalReference": "checkout-ambiguous",
                    },
                ]
            },
        )

    client = AsaasClient(
        billing_settings(),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(BillingProviderError) as raised:
        client.find_payment_link_by_external_reference("checkout-ambiguous")
    assert raised.value.code == "BILLING_PROVIDER_RECONCILIATION_AMBIGUOUS"


def test_real_asaas_adapter_timeout_classifies_post_outcome_unknown():
    def handler(request: httpx.Request):
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    client = AsaasClient(
        billing_settings(),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(BillingProviderError) as raised:
        client.create_payment_link(
            {
                "name": "test",
                "billingType": "UNDEFINED",
                "chargeType": "DETACHED",
                "value": 10,
                "externalReference": "checkout-timeout",
            }
        )
    assert raised.value.code == "BILLING_PROVIDER_TIMEOUT"
    assert raised.value.outcome_unknown is True


def test_webhook_missing_secret_is_fail_closed(db):
    settings = Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
    )
    with pytest.raises(service.BillingDomainError) as raised:
        service.process_asaas_webhook(
            db,
            settings=settings,
            raw_body=b"{}",
            supplied_token="anything",
        )
    assert raised.value.code == "BILLING_WEBHOOK_NOT_CONFIGURED"
    assert db.scalar(select(func.count(BillingWebhookEvent.id))) == 0


def test_webhook_wrong_token_rejected_without_state(db):
    checkout, _ = create_plan_checkout(db)
    with pytest.raises(service.BillingDomainError) as raised:
        service.process_asaas_webhook(
            db,
            settings=billing_settings(),
            raw_body=confirmed_payload(checkout),
            supplied_token="wrong",
        )
    assert raised.value.status_code == 401
    assert db.scalar(select(func.count(BillingWebhookEvent.id))) == 0
    db.refresh(checkout)
    assert checkout.status == "pending"


def test_confirmed_webhook_materializes_exactly_once_financial_state(db):
    checkout, _ = create_plan_checkout(db)
    raw = confirmed_payload(checkout)
    settings = billing_settings()

    first = service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=raw,
        supplied_token="w" * 32,
    )
    second = service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=raw,
        supplied_token="w" * 32,
    )

    assert first == {"ok": True, "deduplicated": False}
    assert second == {"ok": True, "deduplicated": True}

    db.refresh(checkout)
    assert checkout.status == "paid"
    assert checkout.provider_payment_id == "pay-1"

    entitlement = repository.entitlement_for_actor(
        db, tenant_id="tenant-a", user_id="user-a"
    )
    assert entitlement is not None
    assert entitlement.status == "active"
    assert entitlement.plan_code == "founder_access"

    wallet = repository.wallet_for_actor(
        db, tenant_id="tenant-a", user_id="user-a"
    )
    assert wallet is not None
    assert Decimal(wallet.balance_usd) == Decimal("20.0000")

    assert db.scalar(select(func.count(BillingTransaction.id))) == 1
    assert db.scalar(select(func.count(BillingWalletLedger.id))) == 1
    assert db.scalar(select(func.count(BillingWebhookEvent.id))) == 1
    assert db.scalar(
        select(func.count(AuditEvent.id)).where(
            AuditEvent.action == "billing.payment.confirmed",
            AuditEvent.tenant_id == "tenant-a",
        )
    ) == 1


def test_refund_reverses_available_credit_and_quarantines_spent_shortfall(db):
    checkout, _ = create_plan_checkout(db)
    settings = billing_settings()
    service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=confirmed_payload(checkout),
        supplied_token="w" * 32,
    )

    wallet = repository.wallet_for_actor(
        db, tenant_id="tenant-a", user_id="user-a"
    )
    wallet.balance_usd = Decimal("5.0000")
    wallet.lifetime_debited_usd = Decimal("15.0000")
    db.commit()

    refund = confirmed_payload(checkout, event="PAYMENT_REFUNDED")
    service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=refund,
        supplied_token="w" * 32,
    )
    # replay must not duplicate the quarantine
    replay = service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=refund,
        supplied_token="w" * 32,
    )
    assert replay["deduplicated"] is True

    db.refresh(wallet)
    assert Decimal(wallet.balance_usd) == Decimal("0.0000")
    assert Decimal(wallet.quarantined_usd) == Decimal("15.0000")
    assert wallet.status == "quarantined"

    entitlement = repository.entitlement_for_actor(
        db, tenant_id="tenant-a", user_id="user-a"
    )
    assert entitlement.status == "refunded"
    assert db.scalar(
        select(func.count(BillingTransaction.id)).where(
            BillingTransaction.status == "refunded"
        )
    ) == 1

    reversal = db.scalar(
        select(BillingWalletLedger).where(
            BillingWalletLedger.source == "refunded"
        )
    )
    assert Decimal(reversal.amount_usd) == Decimal("5.0000")
    assert reversal.metadata_json["unrecovered_usd"] == "15.0000"


def test_unknown_payment_is_ignored_without_cross_tenant_mutation(db):
    raw = json.dumps(
        {
            "event": "PAYMENT_CONFIRMED",
            "payment": {"id": "unknown-payment", "paymentLink": "unknown-link"},
        }
    ).encode()
    result = service.process_asaas_webhook(
        db,
        settings=billing_settings(),
        raw_body=raw,
        supplied_token="w" * 32,
    )
    assert result == {"ok": True, "ignored": True}
    assert db.scalar(select(func.count(BillingTransaction.id))) == 0
    assert db.scalar(select(func.count(BillingWallet.id))) == 0
    event = db.scalar(select(BillingWebhookEvent))
    assert event.status == "ignored"
    assert event.tenant_id is None


def test_tenant_and_user_scope_hide_other_checkout_and_wallet(db):
    checkout, _ = create_plan_checkout(db)
    assert repository.checkout_for_actor(
        db,
        tenant_id="tenant-b",
        user_id="user-b",
        checkout_id=checkout.id,
    ) is None

    service.process_asaas_webhook(
        db,
        settings=billing_settings(),
        raw_body=confirmed_payload(checkout),
        supplied_token="w" * 32,
    )
    assert repository.wallet_for_actor(
        db, tenant_id="tenant-b", user_id="user-b"
    ) is None
    assert repository.entitlement_for_actor(
        db, tenant_id="tenant-b", user_id="user-b"
    ) is None


def test_readonly_overview_does_not_create_wallet(db):
    before = db.scalar(select(func.count(BillingWallet.id)))
    view = service.overview(
        db, principal=principal("user-a", "tenant-a")
    )
    after = db.scalar(select(func.count(BillingWallet.id)))
    assert before == after == 0
    assert view["wallet"]["id"] is None
    assert view["wallet"]["balance_usd"] == Decimal("0.0000")


def test_no_raw_webhook_payload_column_is_persisted(db):
    checkout, _ = create_plan_checkout(db)
    raw = confirmed_payload(checkout)
    service.process_asaas_webhook(
        db,
        settings=billing_settings(),
        raw_body=raw,
        supplied_token="w" * 32,
    )
    event = db.scalar(select(BillingWebhookEvent))
    assert len(event.payload_sha256) == 64
    assert not hasattr(event, "payload")


def test_billing_live_mode_is_forbidden_outside_production():
    with pytest.raises(ValueError, match="BILLING_LIVE_MODE_FORBIDDEN_OUTSIDE_PRODUCTION"):
        billing_settings(PLATFORM_BILLING_LIVE_MODE_ENABLED=True)


def provider_event_payload(
    checkout,
    *,
    event,
    event_id,
    payment_id="pay-1",
):
    return json.dumps(
        {
            "id": event_id,
            "event": event,
            "payment": {
                "id": payment_id,
                "paymentLink": checkout.provider_checkout_id,
            },
        },
        separators=(",", ":"),
    ).encode()


def test_provider_event_id_is_the_at_least_once_replay_key(db):
    checkout, _ = create_plan_checkout(db)
    settings = billing_settings()
    first = provider_event_payload(
        checkout,
        event="PAYMENT_CONFIRMED",
        event_id="evt-stable-replay-id",
    )
    second = provider_event_payload(
        checkout,
        event="PAYMENT_CONFIRMED",
        event_id="evt-stable-replay-id",
        payment_id="pay-different-body-but-same-event-id",
    )
    result1 = service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=first,
        supplied_token="w" * 32,
    )
    result2 = service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=second,
        supplied_token="w" * 32,
    )
    assert result1["deduplicated"] is False
    assert result2 == {"ok": True, "deduplicated": True}
    assert db.scalar(select(func.count(BillingWebhookEvent.id))) == 1


def test_refund_terminal_state_blocks_delayed_confirmation(db):
    checkout, _ = create_plan_checkout(db)
    settings = billing_settings()

    refund = provider_event_payload(
        checkout,
        event="PAYMENT_REFUNDED",
        event_id="evt-refund-first",
    )
    service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=refund,
        supplied_token="w" * 32,
    )
    db.refresh(checkout)
    assert checkout.status == "refunded"

    delayed = provider_event_payload(
        checkout,
        event="PAYMENT_CONFIRMED",
        event_id="evt-late-confirm-after-refund",
    )
    result = service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=delayed,
        supplied_token="w" * 32,
    )
    assert result == {
        "ok": True,
        "ignored": True,
        "reason": "state_transition_guard",
    }

    db.refresh(checkout)
    assert checkout.status == "refunded"
    assert (
        db.scalar(
            select(func.count(BillingTransaction.id)).where(
                BillingTransaction.status == "confirmed"
            )
        )
        == 0
    )
    wallet = repository.wallet_for_actor(
        db, tenant_id="tenant-a", user_id="user-a"
    )
    assert wallet is None
    entitlement = repository.entitlement_for_actor(
        db, tenant_id="tenant-a", user_id="user-a"
    )
    assert entitlement is None


def test_chargeback_terminal_state_blocks_late_received(db):
    checkout, _ = create_plan_checkout(db)
    settings = billing_settings()

    chargeback = provider_event_payload(
        checkout,
        event="PAYMENT_CHARGEBACK_REQUESTED",
        event_id="evt-chargeback-first",
    )
    service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=chargeback,
        supplied_token="w" * 32,
    )
    db.refresh(checkout)
    assert checkout.status == "chargeback"

    delayed = provider_event_payload(
        checkout,
        event="PAYMENT_RECEIVED",
        event_id="evt-late-received-after-chargeback",
    )
    result = service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=delayed,
        supplied_token="w" * 32,
    )
    assert result["ignored"] is True
    assert result["reason"] == "state_transition_guard"

    db.refresh(checkout)
    assert checkout.status == "chargeback"
    assert (
        db.scalar(
            select(func.count(BillingTransaction.id)).where(
                BillingTransaction.status == "confirmed"
            )
        )
        == 0
    )


def test_confirm_refund_late_distinct_confirm_does_not_reactivate(db):
    checkout, _ = create_plan_checkout(db)
    settings = billing_settings()

    service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=provider_event_payload(
            checkout,
            event="PAYMENT_CONFIRMED",
            event_id="evt-confirm-initial",
        ),
        supplied_token="w" * 32,
    )
    service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=provider_event_payload(
            checkout,
            event="PAYMENT_REFUNDED",
            event_id="evt-refund-after-confirm",
        ),
        supplied_token="w" * 32,
    )
    result = service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=provider_event_payload(
            checkout,
            event="PAYMENT_CONFIRMED",
            event_id="evt-confirm-distinct-late",
        ),
        supplied_token="w" * 32,
    )
    assert result["ignored"] is True

    db.refresh(checkout)
    assert checkout.status == "refunded"
    entitlement = repository.entitlement_for_actor(
        db, tenant_id="tenant-a", user_id="user-a"
    )
    assert entitlement.status == "refunded"
    wallet = repository.wallet_for_actor(
        db, tenant_id="tenant-a", user_id="user-a"
    )
    assert Decimal(wallet.balance_usd) == Decimal("0.0000")
    assert (
        db.scalar(
            select(func.count(BillingWalletLedger.id)).where(
                BillingWalletLedger.direction == "credit"
            )
        )
        == 1
    )


def test_paid_state_ignores_distinct_duplicate_confirmation(db):
    checkout, _ = create_plan_checkout(db)
    settings = billing_settings()

    service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=provider_event_payload(
            checkout,
            event="PAYMENT_CONFIRMED",
            event_id="evt-paid-1",
        ),
        supplied_token="w" * 32,
    )
    entitlement = repository.entitlement_for_actor(
        db, tenant_id="tenant-a", user_id="user-a"
    )
    expires_at = entitlement.expires_at

    result = service.process_asaas_webhook(
        db,
        settings=settings,
        raw_body=provider_event_payload(
            checkout,
            event="PAYMENT_RECEIVED",
            event_id="evt-paid-2-distinct",
        ),
        supplied_token="w" * 32,
    )
    assert result["ignored"] is True
    entitlement = repository.entitlement_for_actor(
        db, tenant_id="tenant-a", user_id="user-a"
    )
    assert entitlement.expires_at == expires_at
    assert (
        db.scalar(
            select(func.count(BillingWalletLedger.id)).where(
                BillingWalletLedger.direction == "credit"
            )
        )
        == 1
    )


def test_migration_graph_advances_canonically_to_011():
    root = __import__("pathlib").Path(__file__).resolve().parents[1]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    script = ScriptDirectory.from_config(cfg)
    assert script.get_heads() == ["016_thread_participant_access_expiry"]
    rev_011 = script.get_revision("011_billing_wallet")
    rev_010 = script.get_revision("010_billing_core")
    assert rev_011.down_revision == "010_billing_core"
    assert rev_010.down_revision == "009_audit_evidence_ledger"


def test_openapi_publishes_canonical_billing_contract():
    schema = app.openapi()
    paths = schema["paths"]
    assert "/api/v2/billing/plans" in paths
    assert "/api/v2/billing/checkouts" in paths
    assert "/api/v2/billing/checkouts/{checkout_id}" in paths
    assert "/api/v2/billing/overview" in paths
    assert "/api/v2/billing/wallet" in paths
    assert "/api/v2/billing/wallet/ledger" in paths
    assert "/api/v2/billing/webhooks/asaas" in paths
    assert "/api/v2/billing/admin/summary" in paths


def test_provider_webhook_is_csrf_exempt_but_still_provider_authenticated(
    client,
    monkeypatch,
):
    from orkio_v2.config import get_settings
    import orkio_v2.main as main_module

    settings = get_settings()
    monkeypatch.setattr(settings, "environment", "staging", raising=False)
    monkeypatch.setattr(settings, "asaas_webhook_token", "w" * 32, raising=False)
    monkeypatch.setattr(
        settings,
        "billing_webhook_max_body_bytes",
        1024,
        raising=False,
    )
    assert main_module.settings is settings

    # A normal state-changing browser endpoint still requires CSRF.
    protected = client.post(
        "/api/v2/billing/checkouts",
        json={"item_code": "founder_access", "checkout_kind": "plan"},
        headers={
            "X-Test-User": "user-1",
            "X-Test-Tenant": "tenant-1",
            "X-Test-Roles": "admin",
            "X-Test-Email": "owner@example.com",
            "X-Test-Subject": "sub-1",
        },
    )
    assert protected.status_code == 403
    assert protected.json()["detail"] == "CSRF_TOKEN_INVALID"

    # Provider webhooks do not carry browser CSRF cookies. The narrow exemption
    # lets the request reach provider authentication, which still fails closed.
    unauthenticated = client.post(
        "/api/v2/billing/webhooks/asaas",
        json={"id": "evt-route-missing-token", "event": "PAYMENT_CONFIRMED"},
    )
    assert unauthenticated.status_code == 401
    assert unauthenticated.json()["detail"] == "BILLING_WEBHOOK_TOKEN_INVALID"

    authenticated = client.post(
        "/api/v2/billing/webhooks/asaas",
        headers={"asaas-access-token": "w" * 32},
        json={
            "id": "evt-route-valid-token",
            "event": "PAYMENT_CONFIRMED",
            "payment": {
                "id": "pay-route-unknown",
                "paymentLink": "plink-route-unknown",
            },
        },
    )
    assert authenticated.status_code == 200
    assert authenticated.json() == {"ok": True, "ignored": True}


def test_provider_webhook_body_is_bounded_before_json_processing(client, monkeypatch):
    from orkio_v2.config import get_settings
    import orkio_v2.main as main_module

    settings = get_settings()
    monkeypatch.setattr(settings, "environment", "staging", raising=False)
    monkeypatch.setattr(settings, "asaas_webhook_token", "w" * 32, raising=False)
    monkeypatch.setattr(
        settings,
        "billing_webhook_max_body_bytes",
        64,
        raising=False,
    )
    assert main_module.settings is settings

    response = client.post(
        "/api/v2/billing/webhooks/asaas",
        headers={
            "asaas-access-token": "w" * 32,
            "content-type": "application/json",
        },
        content=b'{"payload":"' + (b"x" * 128) + b'"}',
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "BILLING_WEBHOOK_BODY_TOO_LARGE"


def test_billing_webhook_body_limit_configuration_is_bounded():
    with pytest.raises(
        ValueError,
        match="BILLING_WEBHOOK_MAX_BODY_BYTES_INVALID",
    ):
        billing_settings(PLATFORM_BILLING_WEBHOOK_MAX_BODY_BYTES=10_485_761)
