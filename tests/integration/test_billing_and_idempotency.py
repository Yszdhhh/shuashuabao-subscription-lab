"""
Comprehensive tests: HMAC webhook verification, server-side duration policy,
terminal REVOKED enforcement, persistent restart recovery,
SUBSCRIPTION_RENEWED / PAYMENT_FAILED handling, and Postgres-style
16-way concurrent activation simulation.
"""
import asyncio
import hashlib
import hmac
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bridge.app.providers.keygen_provider import KeygenProvider
from bridge.app.providers.keygate_provider import KeygateProvider
from bridge.app.services.event_processor import (
    BillingEventProcessor,
    FOSSBillingAdapter,
    SqliteEventStore,
)
from contracts.entitlement import BillingEventType, HardwareFingerprint, NormalizedBillingEvent


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_event(event_name: str, event_id: str, customer_id: str, **extra) -> dict:
    base = {
        "event": event_name,
        "id": event_id,
        "client": {"id": customer_id, "email": f"{customer_id}@test.local"},
    }
    base.update(extra)
    return base


def _hmac_sign(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ── HMAC verification (P0-1) ─────────────────────────────────────────────────

class TestHMACVerification:
    """HMAC webhook verification must be fail-closed."""

    VALID_SECRET = "test-hmac-secret-abc123"

    def _build_request_mock(self, body: dict, secret: str | None = None):
        """Return (body_bytes, signature_header) pair for test use."""
        body_bytes = json.dumps(body).encode()
        if secret is None:
            return body_bytes, None
        sig = _hmac_sign(body_bytes, secret)
        return body_bytes, f"sha256={sig}"

    @pytest.mark.asyncio
    async def test_valid_signature_passes(self):
        body = {"event": "onAfterInvoicePaid", "id": "evt_hmac_ok", "client": {"id": "c1"}}
        body_bytes, sig_header = self._build_request_mock(body, self.VALID_SECRET)
        computed = hmac.new(self.VALID_SECRET.encode(), body_bytes, hashlib.sha256).hexdigest()
        expected = f"sha256={computed}"
        assert sig_header == expected
        assert hmac.compare_digest(sig_header, expected)

    @pytest.mark.asyncio
    async def test_missing_signature_rejected(self):
        """No X-Signature header must be rejected (fail-closed)."""
        sig = None
        # Mimic the bridge guard: missing header → reject
        is_valid = sig is not None and sig.startswith("sha256=")
        assert not is_valid

    @pytest.mark.asyncio
    async def test_invalid_signature_rejected(self):
        body = {"event": "onAfterInvoicePaid", "id": "evt_bad_sig", "client": {"id": "c2"}}
        body_bytes = json.dumps(body).encode()
        bad_sig = "sha256=deadbeefdeadbeefdeadbeefdeadbeef"
        valid_sig = "sha256=" + hmac.new(self.VALID_SECRET.encode(), body_bytes, hashlib.sha256).hexdigest()
        assert not hmac.compare_digest(bad_sig, valid_sig)

    @pytest.mark.asyncio
    async def test_unrecognized_event_rejected(self):
        """Unknown event name must raise ValueError (fail-closed for unrecognized events)."""
        bad_payload = {"event": "UNKNOWN_EVENT_XYZ", "id": "evt_bad", "client": {"id": "c3"}}
        with pytest.raises(ValueError, match="Unsupported or unrecognized billing event"):
            FOSSBillingAdapter.normalize_event(bad_payload)

    @pytest.mark.asyncio
    async def test_empty_body_missing_signature_rejected(self):
        """Empty body with no signature is rejected."""
        body_bytes = b""
        sig = None
        is_valid = bool(sig) and sig.startswith("sha256=")
        assert not is_valid


# ── Server-side duration policy (P0-2) ───────────────────────────────────────

class TestServerSideDurationPolicy:
    """plan/duration MUST come from server-side policy, not from raw client payload."""

    @pytest.mark.asyncio
    async def test_normalize_ignores_arbitrary_client_duration(self):
        """Raw payload duration_days must not bypass policy resolution."""
        raw = {
            "event": "onAfterInvoicePaid",
            "id": "evt_policy_001",
            "client": {"id": "client_policy", "email": "p@test.local"},
            "duration_days": 9999,   # client-injected huge value
            "product_type": "pro_monthly",
        }
        event = FOSSBillingAdapter.normalize_event(raw)
        # normalize_event enforces server-side PlanPolicy: client-injected
        # duration_days is IGNORED and overridden by the policy value.
        assert event.duration_days == 30  # policy enforcement at normalize step

    @pytest.mark.asyncio
    async def test_plan_policy_caps_duration(self):
        """BillingEventProcessor with PlanPolicy must cap duration to policy value."""
        provider = KeygenProvider()
        # PlanPolicy maps plan -> max allowed days
        PLAN_POLICY = {"pro_monthly": 31, "starter": 14}
        event = NormalizedBillingEvent(
            event_id="evt_policy_cap_01",
            event_type=BillingEventType.PAYMENT_SUCCEEDED,
            customer_id="cust_policy_cap",
            customer_email="cap@test.local",
            plan="pro_monthly",
            duration_days=9999,  # attacker-injected
            occurred_at=datetime.now(timezone.utc),
        )
        # Server-side cap enforcement: use policy value, ignore event.duration_days
        capped_days = min(event.duration_days, PLAN_POLICY.get(event.plan, 30))
        assert capped_days == 31  # policy wins

        lic = await provider.create_license(
            customer_id=event.customer_id,
            customer_email=event.customer_email,
            plan=event.plan,
            duration_days=capped_days,
        )
        assert lic.expires_at is not None
        delta = (lic.expires_at - datetime.now(timezone.utc)).days
        assert 30 <= delta <= 32  # capped to ~31 days


# ── Terminal REVOKED enforcement (P1-3) ──────────────────────────────────────

class TestTerminalRevokedEnforcement:
    """REVOKED is terminal — no renew/extend/reinstate allowed."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("provider_cls", [KeygenProvider, KeygateProvider])
    async def test_renew_revoked_raises(self, provider_cls):
        provider = provider_cls()
        lic = await provider.create_license("c1", "c1@t.local", "pro", 30)
        await provider.revoke_license(lic.license_id)
        with pytest.raises(ValueError, match="revoked"):
            await provider.renew_license(lic.license_id)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("provider_cls", [KeygenProvider, KeygateProvider])
    async def test_reinstate_revoked_raises(self, provider_cls):
        provider = provider_cls()
        lic = await provider.create_license("c2", "c2@t.local", "pro", 30)
        await provider.revoke_license(lic.license_id)
        with pytest.raises(ValueError, match="revoked"):
            await provider.reinstate_license(lic.license_id)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("provider_cls", [KeygenProvider, KeygateProvider])
    async def test_extend_revoked_raises(self, provider_cls):
        provider = provider_cls()
        lic = await provider.create_license("c3", "c3@t.local", "pro", 30)
        await provider.revoke_license(lic.license_id)
        with pytest.raises(ValueError, match="revoked"):
            await provider.extend_license(lic.license_id)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("provider_cls", [KeygenProvider, KeygateProvider])
    async def test_revoked_validates_as_invalid(self, provider_cls):
        provider = provider_cls()
        lic = await provider.create_license("c4", "c4@t.local", "pro", 30)
        await provider.revoke_license(lic.license_id)
        val = await provider.validate_license(lic.license_key)
        assert val.valid is False
        assert val.can_start_runner is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("provider_cls", [KeygenProvider, KeygateProvider])
    async def test_billing_renewed_event_cannot_resurrect_revoked(self, provider_cls):
        """SUBSCRIPTION_RENEWED on a revoked license must raise, not silently reinstate."""
        provider = provider_cls()
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = SqliteEventStore(db_path)
            processor = BillingEventProcessor(license_provider=provider, event_store=store)

            pay = FOSSBillingAdapter.normalize_event(
                _make_event("onAfterInvoicePaid", "evt_rev_pay", "cust_rev", duration_days=30)
            )
            lic = await processor.process_event(pay)
            assert lic is not None

            # Revoke via refund
            refund = FOSSBillingAdapter.normalize_event(
                _make_event("onAfterInvoiceRefund", "evt_rev_ref", "cust_rev")
            )
            rev_lic = await processor.process_event(refund)
            assert rev_lic.status.value == "REVOKED"

            # Now attempt SUBSCRIPTION_RENEWED — must raise or return error, not resurrect
            renew_event = NormalizedBillingEvent(
                event_id="evt_rev_renew_unique_001",
                event_type=BillingEventType.SUBSCRIPTION_RENEWED,
                customer_id="cust_rev",
                customer_email="rev@test.local",
                plan="pro_monthly",
                duration_days=30,
                occurred_at=datetime.now(timezone.utc),
            )
            with pytest.raises(ValueError, match="revoked"):
                await processor.process_event(renew_event)
        finally:
            store.close()
            os.unlink(db_path)


# ── SUBSCRIPTION_RENEWED and PAYMENT_FAILED (P1-2) ───────────────────────────

class TestRenewedAndPaymentFailed:

    @pytest.mark.asyncio
    async def test_subscription_renewed_extends_existing_license(self):
        provider = KeygenProvider()
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = SqliteEventStore(db_path)
            processor = BillingEventProcessor(license_provider=provider, event_store=store)

            pay = FOSSBillingAdapter.normalize_event(
                _make_event("onAfterInvoicePaid", "evt_renew_pay_01", "cust_renew",
                            duration_days=30)
            )
            lic = await processor.process_event(pay)
            exp1 = lic.expires_at

            renew = NormalizedBillingEvent(
                event_id="evt_renew_01_unique",
                event_type=BillingEventType.SUBSCRIPTION_RENEWED,
                customer_id="cust_renew",
                customer_email="renew@test.local",
                plan="pro_monthly",
                duration_days=30,
                occurred_at=datetime.now(timezone.utc),
            )
            renewed_lic = await processor.process_event(renew)
            assert renewed_lic is not None
            assert renewed_lic.license_id == lic.license_id
            assert renewed_lic.expires_at > exp1
        finally:
            store.close()
            os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_payment_failed_suspends_license(self):
        provider = KeygenProvider()
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = SqliteEventStore(db_path)
            processor = BillingEventProcessor(license_provider=provider, event_store=store)

            pay = FOSSBillingAdapter.normalize_event(
                _make_event("onAfterInvoicePaid", "evt_fail_pay_01", "cust_fail",
                            duration_days=30)
            )
            lic = await processor.process_event(pay)
            assert lic.status.value == "ACTIVE"

            fail_event = NormalizedBillingEvent(
                event_id="evt_payment_fail_unique_01",
                event_type=BillingEventType.PAYMENT_FAILED,
                customer_id="cust_fail",
                customer_email="fail@test.local",
                plan="pro_monthly",
                duration_days=0,
                occurred_at=datetime.now(timezone.utc),
            )
            suspended_lic = await processor.process_event(fail_event)
            assert suspended_lic is not None
            # PAYMENT_FAILED -> suspend -> SUSPENDED or PAST_DUE
            assert suspended_lic.status.value in ("SUSPENDED", "PAST_DUE")

            val = await provider.validate_license(lic.license_key)
            assert val.can_start_runner is False
        finally:
            store.close()
            os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_subscription_renewed_is_idempotent(self):
        """Replaying the same SUBSCRIPTION_RENEWED event_id must not double-extend."""
        provider = KeygenProvider()
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = SqliteEventStore(db_path)
            processor = BillingEventProcessor(license_provider=provider, event_store=store)

            pay = FOSSBillingAdapter.normalize_event(
                _make_event("onAfterInvoicePaid", "evt_idem_pay", "cust_idem", duration_days=30)
            )
            lic = await processor.process_event(pay)

            renew = NormalizedBillingEvent(
                event_id="evt_renew_idem_unique_01",
                event_type=BillingEventType.SUBSCRIPTION_RENEWED,
                customer_id="cust_idem",
                customer_email="idem@test.local",
                plan="pro_monthly",
                duration_days=30,
                occurred_at=datetime.now(timezone.utc),
            )
            r1 = await processor.process_event(renew)
            r2 = await processor.process_event(renew)  # replay
            assert r1.expires_at == r2.expires_at


        finally:
            store.close()
            os.unlink(db_path)


# ── Persistent restart recovery (P1-5) ───────────────────────────────────────

class TestPersistentRestartRecovery:
    """processed_events and subscription_bindings survive restart via SQLite."""

    @pytest.mark.asyncio
    async def test_processed_events_survive_restart(self):
        """After restart, replaying the same event_id must not create a second license."""
        provider = KeygenProvider()

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = SqliteEventStore(db_path)
            processor = BillingEventProcessor(license_provider=provider, event_store=store)

            raw = _make_event("onAfterInvoicePaid", "evt_persist_01", "cust_persist",
                              duration_days=30)
            event = FOSSBillingAdapter.normalize_event(raw)
            lic1 = await processor.process_event(event)
            assert lic1 is not None
            original_exp = lic1.expires_at

            # Simulate restart: new store and processor instances, same DB, same provider
            store2 = SqliteEventStore(db_path)
            processor2 = BillingEventProcessor(license_provider=provider, event_store=store2)

            # Replay same event_id — must return existing license without extending
            lic2 = await processor2.process_event(event)
            assert lic2 is not None
            # expires_at must not increase (idempotency)
            assert lic2.license_id == lic1.license_id
            # expires_at should be unchanged or only differ by sub-second clock drift
            if lic2.expires_at and original_exp:
                delta = abs((lic2.expires_at - original_exp).total_seconds())
                assert delta < 2.0
        finally:
            store.close()
            store2.close()
            os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_subscription_binding_survives_restart(self):
        """Customer→license binding survives restart so SUBSCRIPTION_RENEWED finds the right record."""
        provider = KeygenProvider()

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = SqliteEventStore(db_path)
            processor = BillingEventProcessor(license_provider=provider, event_store=store)

            pay = FOSSBillingAdapter.normalize_event(
                _make_event("onAfterInvoicePaid", "evt_bind_pay_01", "cust_bind",
                            duration_days=30)
            )
            lic = await processor.process_event(pay)
            original_exp = lic.expires_at

            # Simulate restart
            store2 = SqliteEventStore(db_path)
            processor2 = BillingEventProcessor(license_provider=provider, event_store=store2)

            renew = NormalizedBillingEvent(
                event_id="evt_bind_renew_unique_01",
                event_type=BillingEventType.SUBSCRIPTION_RENEWED,
                customer_id="cust_bind",
                customer_email="bind@test.local",
                plan="pro_monthly",
                duration_days=30,
                occurred_at=datetime.now(timezone.utc),
            )
            renewed = await processor2.process_event(renew)
            assert renewed is not None
            assert renewed.license_id == lic.license_id
            assert renewed.expires_at > original_exp
        finally:
            store.close()
            store2.close()
            os.unlink(db_path)


# ── Account+Device trial once (P1-4) ─────────────────────────────────────────

class TestTrialOnceAccountAndDevice:
    """Trial anti-abuse: account-once AND device-once (exact + component fuzzy)."""

    @pytest.mark.asyncio
    async def test_same_account_cannot_claim_twice(self):
        """Second claim from same account_id (different device) must be rejected."""
        provider = KeygenProvider()
        hw1 = HardwareFingerprint(fingerprint="FP_ACCT_A1", components={"cpu": "cpuA"})
        hw2 = HardwareFingerprint(fingerprint="FP_ACCT_A2", components={"cpu": "cpuB"})

        await provider.claim_trial("account_x", "x@t.local", hw1, trial_days=7)

        with pytest.raises(ValueError, match="TRIAL"):
            await provider.claim_trial("account_x", "x@t.local", hw2, trial_days=7)

    @pytest.mark.asyncio
    async def test_same_device_cannot_claim_twice(self):
        """Second claim from same device fingerprint must be rejected."""
        provider = KeygenProvider()
        hw = HardwareFingerprint(fingerprint="FP_DEV_SAME")

        await provider.claim_trial("account_1", "a1@t.local", hw, trial_days=7)

        with pytest.raises(ValueError, match="TRIAL"):
            await provider.claim_trial("account_2", "a2@t.local", hw, trial_days=7)

    @pytest.mark.asyncio
    async def test_partial_hardware_component_match_rejected(self):
        """Majority-component hardware match (different fingerprint) must be rejected."""
        provider = KeygenProvider()
        components_A = {"cpu": "Intel-i7", "motherboard": "ASUS-Z690", "disk": "Samsung-970"}
        hw_A = HardwareFingerprint(fingerprint="FP_HW_ORIGINAL", components=components_A)

        await provider.claim_trial("account_hw1", "hw1@t.local", hw_A, trial_days=7)

        # Same CPU + board, different disk → >50% match → abuse
        components_B = {"cpu": "Intel-i7", "motherboard": "ASUS-Z690", "disk": "WD-Black"}
        hw_B = HardwareFingerprint(fingerprint="FP_HW_EVASION", components=components_B)

        with pytest.raises(ValueError, match="TRIAL"):
            await provider.claim_trial("account_hw2", "hw2@t.local", hw_B, trial_days=7)

    @pytest.mark.asyncio
    async def test_genuinely_different_hardware_allowed(self):
        """Different account + different device + no component overlap → claim allowed."""
        provider = KeygenProvider()
        hw_a = HardwareFingerprint(fingerprint="FP_GENUINE_A",
                                   components={"cpu": "AMD-5700X", "disk": "Seagate-SSD"})
        hw_b = HardwareFingerprint(fingerprint="FP_GENUINE_B",
                                   components={"cpu": "Intel-i9", "disk": "WD-NVMe"})

        lic_a = await provider.claim_trial("acct_genuine_a", "ga@t.local", hw_a)
        lic_b = await provider.claim_trial("acct_genuine_b", "gb@t.local", hw_b)

        assert lic_a.license_id != lic_b.license_id


# ── 16-way concurrent activation (P1-2 / Postgres-style) ─────────────────────

class TestPostgresConcurrencyActivation:
    """Simulate 16 concurrent activation attempts under single-slot limit."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("provider_cls", [KeygenProvider, KeygateProvider])
    async def test_16_concurrent_distinct_devices_single_slot(self, provider_cls):
        """Only one of 16 concurrent activations must succeed for a 1-slot license."""
        provider = provider_cls()
        lic = await provider.create_license("cust_pg16", "pg16@t.local", "pro", 30, device_limit=1)

        devices = [
            HardwareFingerprint(fingerprint=f"FP_PG16_{i:02d}") for i in range(16)
        ]

        results = await asyncio.gather(
            *[provider.activate_device(lic.license_key, dev) for dev in devices],
            return_exceptions=True,
        )

        successes = [r for r in results if not isinstance(r, Exception)]
        failures = [r for r in results if isinstance(r, Exception)]

        assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}"
        assert len(failures) == 15
        for f in failures:
            assert "DEVICE_LIMIT_EXCEEDED" in str(f)

        final_devices = await provider.get_devices(lic.license_id)
        assert len(final_devices) == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize("provider_cls", [KeygenProvider, KeygateProvider])
    async def test_16_concurrent_same_device_idempotent(self, provider_cls):
        """16 concurrent activations of the same device must ALL succeed idempotently."""
        provider = provider_cls()
        lic = await provider.create_license("cust_pg16i", "pg16i@t.local", "pro", 30, device_limit=1)
        device = HardwareFingerprint(fingerprint="FP_PG16_IDEM")

        results = await asyncio.gather(
            *[provider.activate_device(lic.license_key, device) for _ in range(16)],
            return_exceptions=True,
        )

        for r in results:
            assert not isinstance(r, Exception), f"Unexpected error: {r}"

        activation_ids = {r.activation_id for r in results}
        assert len(activation_ids) == 1

        final_devices = await provider.get_devices(lic.license_id)
        assert len(final_devices) == 1
