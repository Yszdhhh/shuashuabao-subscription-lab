"""
FOSSBilling Webhook Adapter and Normalization Service.
Translates FOSSBilling webhook/event payloads into NormalizedBillingEvent,
handles idempotency checking to prevent double billing/extension, and drives License Provider.
"""
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set
from contracts.entitlement import (
    BillingEventType,
    LicenseDTO,
    LicenseStatus,
    NormalizedBillingEvent,
)
from bridge.app.providers.base import ILicenseProvider


class FOSSBillingAdapter:
    @staticmethod
    def normalize_event(raw_payload: Dict[str, Any]) -> NormalizedBillingEvent:
        """
        Parses FOSSBilling raw event hook / webhook data into NormalizedBillingEvent.
        """
        event_name = raw_payload.get("event", raw_payload.get("type", "PAYMENT_SUCCEEDED"))
        event_id = raw_payload.get("id", raw_payload.get("event_id", f"evt_{hash(str(raw_payload))}"))
        client_data = raw_payload.get("client", {})
        customer_id = str(client_data.get("id", raw_payload.get("client_id", "guest")))
        customer_email = client_data.get("email", raw_payload.get("email"))
        invoice_id = str(raw_payload.get("invoice_id", raw_payload.get("id", "inv_unknown")))
        plan = raw_payload.get("product_type", raw_payload.get("plan", "pro_monthly"))
        duration_days = int(raw_payload.get("duration_days", 30))

        # Map FOSSBilling internal event names to canonical BillingEventType
        event_mapping = {
            "onAfterClientOrderCreate": BillingEventType.SUBSCRIPTION_STARTED,
            "onAfterInvoicePaid": BillingEventType.PAYMENT_SUCCEEDED,
            "onAfterInvoiceRefund": BillingEventType.REFUND_SUCCEEDED,
            "onAfterClientSubscriptionCancel": BillingEventType.SUBSCRIPTION_CANCELED,
            "SUBSCRIPTION_PAST_DUE": BillingEventType.SUBSCRIPTION_PAST_DUE,
            "PAYMENT_FAILED": BillingEventType.PAYMENT_FAILED,
            "PAYMENT_SUCCEEDED": BillingEventType.PAYMENT_SUCCEEDED,
        }
        canonical_type = event_mapping.get(event_name, BillingEventType.PAYMENT_SUCCEEDED)

        return NormalizedBillingEvent(
            event_id=event_id,
            event_type=canonical_type,
            customer_id=customer_id,
            customer_email=customer_email,
            subscription_id=str(raw_payload.get("subscription_id", "")),
            invoice_id=invoice_id,
            plan=plan,
            duration_days=duration_days,
            occurred_at=datetime.now(timezone.utc),
            raw_payload=raw_payload,
        )


class BillingEventProcessor:
    def __init__(self, license_provider: ILicenseProvider):
        self.provider = license_provider
        self.processed_events: Set[str] = set()
        # customer_id -> license_id mapping for subscription binding
        self.customer_licenses: Dict[str, str] = {}

    async def process_event(self, event: NormalizedBillingEvent) -> Optional[LicenseDTO]:
        """
        Process normalized event with strict idempotency protection.
        Replaying the same event_id will NEVER extend or grant duplicate license time.
        """
        if event.event_id in self.processed_events:
            # Idempotent replay protection
            lic_id = self.customer_licenses.get(event.customer_id)
            if lic_id:
                return await self.provider.get_license(lic_id)
            return None

        result_lic = None

        if event.event_type == BillingEventType.PAYMENT_SUCCEEDED:
            existing_lic_id = self.customer_licenses.get(event.customer_id)
            if existing_lic_id:
                # Renew existing subscription
                result_lic = await self.provider.renew_license(
                    existing_lic_id, extend_days=event.duration_days
                )
            else:
                # Create brand new license
                result_lic = await self.provider.create_license(
                    customer_id=event.customer_id,
                    customer_email=event.customer_email or f"{event.customer_id}@example.com",
                    plan=event.plan,
                    duration_days=event.duration_days,
                    device_limit=1,
                )
                self.customer_licenses[event.customer_id] = result_lic.license_id

        elif event.event_type == BillingEventType.REFUND_SUCCEEDED:
            existing_lic_id = self.customer_licenses.get(event.customer_id)
            if existing_lic_id:
                result_lic = await self.provider.revoke_license(
                    existing_lic_id, reason=f"Refund processed on invoice {event.invoice_id}"
                )

        elif event.event_type == BillingEventType.SUBSCRIPTION_PAST_DUE:
            existing_lic_id = self.customer_licenses.get(event.customer_id)
            if existing_lic_id:
                # Grace or suspend depending on policy
                result_lic = await self.provider.suspend_license(
                    existing_lic_id, reason="Subscription payment past due"
                )

        elif event.event_type == BillingEventType.SUBSCRIPTION_CANCELED:
            # Cancel: allow remaining time to run, but no future automatic renew
            existing_lic_id = self.customer_licenses.get(event.customer_id)
            if existing_lic_id:
                result_lic = await self.provider.get_license(existing_lic_id)

        # Mark event as successfully processed
        self.processed_events.add(event.event_id)
        return result_lic
