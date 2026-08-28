"""
Idempotency, Race Condition, Billing Webhook, and Fault Handling Integration Tests.
"""
import asyncio
import pytest
from contracts.entitlement import BillingEventType, HardwareFingerprint, NormalizedBillingEvent
from bridge.app.providers.keygen_provider import KeygenProvider
from bridge.app.services.event_processor import BillingEventProcessor, FOSSBillingAdapter


@pytest.mark.asyncio
async def test_billing_webhook_replay_idempotency():
    provider = KeygenProvider()
    processor = BillingEventProcessor(license_provider=provider)

    raw_event = {
        "event": "onAfterInvoicePaid",
        "id": "evt_unique_payment_1001",
        "client": {"id": "client_999", "email": "customer@example.com"},
        "invoice_id": "inv_888",
        "product_type": "pro_monthly",
        "duration_days": 30,
    }

    norm_event = FOSSBillingAdapter.normalize_event(raw_event)
    assert norm_event.event_type == BillingEventType.PAYMENT_SUCCEEDED

    # First event delivery: Creates license with 30 days
    lic1 = await processor.process_event(norm_event)
    assert lic1 is not None
    exp1 = lic1.expires_at

    # Second event delivery (Network replay / duplicate webhook): MUST NOT extend another 30 days
    lic2 = await processor.process_event(norm_event)
    assert lic2 is not None
    assert lic2.expires_at == exp1
    assert lic2.license_id == lic1.license_id


@pytest.mark.asyncio
async def test_concurrent_activation_race_condition():
    """Simulates concurrent activation requests on a single-device license."""
    provider = KeygenProvider()
    lic = await provider.create_license("cust_race", "race@example.com", "pro", 30, device_limit=1)

    dev1 = HardwareFingerprint(fingerprint="FP_CONCURRENT_1")
    dev2 = HardwareFingerprint(fingerprint="FP_CONCURRENT_2")

    # Launch both activations concurrently
    results = await asyncio.gather(
        provider.activate_device(lic.license_key, dev1),
        provider.activate_device(lic.license_key, dev2),
        return_exceptions=True,
    )

    successes = [r for r in results if not isinstance(r, Exception)]
    failures = [r for r in results if isinstance(r, Exception)]

    # Exactly one MUST succeed, and one MUST fail with device limit error
    assert len(successes) == 1
    assert len(failures) == 1
    assert "DEVICE_LIMIT_EXCEEDED" in str(failures[0])

    # Final database state verification
    devices = await provider.get_devices(lic.license_id)
    assert len(devices) == 1


@pytest.mark.asyncio
async def test_refund_and_past_due_state_transitions():
    provider = KeygenProvider()
    processor = BillingEventProcessor(license_provider=provider)

    # 1. Initial purchase
    pay_event = FOSSBillingAdapter.normalize_event({
        "event": "onAfterInvoicePaid",
        "id": "evt_pay_01",
        "client": {"id": "client_lifecycle", "email": "life@example.com"},
        "invoice_id": "inv_01",
        "duration_days": 30,
    })
    lic = await processor.process_event(pay_event)
    assert lic.status.value == "ACTIVE"

    # 2. Refund event -> Revoke
    refund_event = FOSSBillingAdapter.normalize_event({
        "event": "onAfterInvoiceRefund",
        "id": "evt_ref_01",
        "client": {"id": "client_lifecycle"},
        "invoice_id": "inv_01",
    })
    rev_lic = await processor.process_event(refund_event)
    assert rev_lic.status.value == "REVOKED"

    # Validation after revoke
    val = await provider.validate_license(lic.license_key)
    assert val.valid is False
    assert val.can_start_runner is False
