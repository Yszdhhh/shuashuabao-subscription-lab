"""
FOSSBilling Webhook Adapter and Normalization Service.
Translates FOSSBilling webhook/event payloads into NormalizedBillingEvent,
handles idempotency checking to prevent double billing/extension, and drives License Provider.
"""
import asyncio
import sqlite3
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from contracts.entitlement import (
    BillingEventType,
    LicenseDTO,
    LicenseStatus,
    NormalizedBillingEvent,
    SERVER_PLAN_POLICIES,
)
from bridge.app.providers.base import ILicenseProvider

_DEFAULT_DB_PATH = os.environ.get("SUBSCRIPTION_DB_PATH", ":memory:")


class SqliteEventStore:
    """Persistent idempotency, subscription, and trial state store."""

    def __init__(self, db_path: str = _DEFAULT_DB_PATH):
        self.db_path = db_path
        self._conn = sqlite3.connect(
            db_path, check_same_thread=False, timeout=30, isolation_level=None
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS processed_events (
                event_id TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'completed',
                processed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS subscription_bindings (
                binding_key TEXT PRIMARY KEY,
                license_id  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trial_accounts (
                account_id TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS trial_devices (
                fingerprint TEXT PRIMARY KEY,
                components_json TEXT NOT NULL
            );
        """)
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(processed_events)")}
        if "status" not in columns:
            self._conn.execute(
                "ALTER TABLE processed_events ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'"
            )

    def acquire_event_lock(self, event_id: str) -> bool:
        """Atomically reserve an event; False means completed or in-flight duplicate."""
        try:
            self._conn.execute(
                "INSERT INTO processed_events (event_id, status, processed_at) VALUES (?, 'processing', ?)",
                (event_id, datetime.now(timezone.utc).isoformat()),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def is_processed(self, event_id: str) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM processed_events WHERE event_id = ? AND status = 'completed'",
            (event_id,),
        )
        return cur.fetchone() is not None
    def is_processing(self, event_id: str) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM processed_events WHERE event_id = ? AND status = 'processing'",
            (event_id,),
        ).fetchone() is not None

    def mark_processed(self, event_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        cur = self._conn.execute(
            "UPDATE processed_events SET status = 'completed', processed_at = ? WHERE event_id = ?",
            (now, event_id),
        )
        if cur.rowcount == 0:
            self._conn.execute(
                "INSERT INTO processed_events (event_id, status, processed_at) VALUES (?, 'completed', ?)",
                (event_id, now),
            )

    def release_event_lock(self, event_id: str) -> None:
        self._conn.execute("DELETE FROM processed_events WHERE event_id = ?", (event_id,))

    def get_binding(self, binding_key: str) -> Optional[str]:
        cur = self._conn.execute(
            "SELECT license_id FROM subscription_bindings WHERE binding_key = ?", (binding_key,)
        )
        row = cur.fetchone()
        return row[0] if row else None

    def set_binding(self, binding_key: str, license_id: str) -> None:
        self._conn.execute(
            """INSERT INTO subscription_bindings (binding_key, license_id, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(binding_key) DO UPDATE SET license_id=excluded.license_id, updated_at=excluded.updated_at""",
            (binding_key, license_id, datetime.now(timezone.utc).isoformat()),
        )

    def has_trial_account(self, account_id: str) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM trial_accounts WHERE account_id = ?", (account_id,)
        ).fetchone() is not None

    def trial_accounts(self) -> set[str]:
        return {
            row[0] for row in self._conn.execute("SELECT account_id FROM trial_accounts")
        }

    def trial_devices(self) -> list[tuple[str, dict]]:
        import json
        return [
            (fingerprint, json.loads(components_json))
            for fingerprint, components_json in self._conn.execute(
                "SELECT fingerprint, components_json FROM trial_devices"
            )
        ]

    def record_trial_claim(self, account_id: str, fingerprint: str, components: dict) -> bool:
        import json
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute(
                "INSERT INTO trial_accounts (account_id) VALUES (?)", (account_id,)
            )
            self._conn.execute(
                "INSERT INTO trial_devices (fingerprint, components_json) VALUES (?, ?)",
                (fingerprint, json.dumps(components, sort_keys=True)),
            )
            self._conn.execute("COMMIT")
            return True
        except sqlite3.IntegrityError:
            self._conn.execute("ROLLBACK")
            return False
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self._conn.close()

class FOSSBillingAdapter:
    # Canonical FOSSBilling event name → BillingEventType mapping
    _EVENT_MAP = {
        "onAfterClientOrderCreate": BillingEventType.SUBSCRIPTION_STARTED,
        "onAfterInvoicePaid": BillingEventType.PAYMENT_SUCCEEDED,
        "onAfterInvoiceRefund": BillingEventType.REFUND_SUCCEEDED,
        "onAfterClientSubscriptionCancel": BillingEventType.SUBSCRIPTION_CANCELED,
        "SUBSCRIPTION_STARTED": BillingEventType.SUBSCRIPTION_STARTED,
        "SUBSCRIPTION_RENEWED": BillingEventType.SUBSCRIPTION_RENEWED,
        "SUBSCRIPTION_PAST_DUE": BillingEventType.SUBSCRIPTION_PAST_DUE,
        "SUBSCRIPTION_CANCELED": BillingEventType.SUBSCRIPTION_CANCELED,
        "PAYMENT_FAILED": BillingEventType.PAYMENT_FAILED,
        "PAYMENT_SUCCEEDED": BillingEventType.PAYMENT_SUCCEEDED,
        "REFUND_SUCCEEDED": BillingEventType.REFUND_SUCCEEDED,
    }

    @staticmethod
    def normalize_event(raw_payload: Dict[str, Any]) -> NormalizedBillingEvent:
        """
        Parse FOSSBilling raw event payload into NormalizedBillingEvent.
        Fail-closed: raises ValueError on missing event field or unrecognized event type.
        Duration is resolved server-side from SERVER_PLAN_POLICIES; any client-supplied
        duration_days is ignored.
        """
        event_name = raw_payload.get("event") or raw_payload.get("type")
        if not event_name:
            raise ValueError("Missing required 'event' field in webhook payload")

        if event_name not in FOSSBillingAdapter._EVENT_MAP:
            raise ValueError(f"Unsupported or unrecognized billing event: {event_name!r}")

        canonical_type = FOSSBillingAdapter._EVENT_MAP[event_name]

        event_id = raw_payload.get("id") or raw_payload.get("event_id") or f"evt_{hash(str(raw_payload))}"
        client_data = raw_payload.get("client", {})
        customer_id = str(client_data.get("id") or raw_payload.get("client_id") or "guest")
        customer_email = client_data.get("email") or raw_payload.get("email")
        invoice_id = str(raw_payload.get("invoice_id") or raw_payload.get("id") or "inv_unknown")
        plan = raw_payload.get("product_type") or raw_payload.get("plan") or "pro_monthly"

        # Server-side authoritative duration — never trust client input
        policy = SERVER_PLAN_POLICIES.get(plan, SERVER_PLAN_POLICIES.get("pro_monthly"))
        duration_days = policy["duration_days"]

        return NormalizedBillingEvent(
            event_id=str(event_id),
            event_type=canonical_type,
            customer_id=customer_id,
            customer_email=customer_email,
            subscription_id=str(raw_payload.get("subscription_id") or ""),
            invoice_id=invoice_id,
            plan=plan,
            duration_days=duration_days,
            occurred_at=datetime.now(timezone.utc),
            raw_payload=raw_payload,
        )


class BillingEventProcessor:
    def __init__(
        self,
        license_provider: ILicenseProvider,
        event_store: Optional[SqliteEventStore] = None,
    ):
        self.provider = license_provider
        # Persistent store: use provided or create default SQLite store
        self.store = event_store or SqliteEventStore()

    @staticmethod
    def resolve_binding_key(event: NormalizedBillingEvent) -> str:
        """
        Unified subscription binding key: prefer subscription_id if present,
        fall back to customer_id. Consistent across all event types.
        """
        if event.subscription_id:
            return f"sub:{event.subscription_id}"
        return f"cust:{event.customer_id}"

    async def process_event(self, event: NormalizedBillingEvent) -> Optional[LicenseDTO]:
        """
        Process normalized event with strict idempotency protection.
        Replaying the same event_id will NEVER extend or grant duplicate license time.
        """
        binding_key = self.resolve_binding_key(event)
        if not self.store.acquire_event_lock(event.event_id):
            # Wait briefly for the lock holder so concurrent callers observe its result.
            for _ in range(30000):  # bounded 30s wait for the lock holder
                if self.store.is_processed(event.event_id):
                    lic_id = self.store.get_binding(binding_key)
                    return await self.provider.get_license(lic_id) if lic_id else None
                if not self.store.is_processing(event.event_id):
                    return None
                await asyncio.sleep(0.001)
            return None

        try:
            result_lic = None
            if event.event_type == BillingEventType.PAYMENT_SUCCEEDED:
                existing_lic_id = self.store.get_binding(binding_key)
                if existing_lic_id:
                    result_lic = await self.provider.renew_license(
                        existing_lic_id, extend_days=event.duration_days
                    )
                else:
                    result_lic = await self.provider.create_license(
                        customer_id=event.customer_id,
                        customer_email=event.customer_email or f"{event.customer_id}@example.com",
                        plan=event.plan,
                        duration_days=event.duration_days,
                        device_limit=1,
                    )
                    self.store.set_binding(binding_key, result_lic.license_id)

            elif event.event_type == BillingEventType.SUBSCRIPTION_RENEWED:
                existing_lic_id = self.store.get_binding(binding_key)
                if existing_lic_id:
                    result_lic = await self.provider.renew_license(
                        existing_lic_id, extend_days=event.duration_days
                    )
                else:
                    result_lic = await self.provider.create_license(
                        customer_id=event.customer_id,
                        customer_email=event.customer_email or f"{event.customer_id}@example.com",
                        plan=event.plan,
                        duration_days=event.duration_days,
                        device_limit=1,
                    )
                    self.store.set_binding(binding_key, result_lic.license_id)

            elif event.event_type == BillingEventType.PAYMENT_FAILED:
                existing_lic_id = self.store.get_binding(binding_key)
                if existing_lic_id:
                    result_lic = await self.provider.suspend_license(
                        existing_lic_id, reason="payment_failed"
                    )

            elif event.event_type == BillingEventType.REFUND_SUCCEEDED:
                existing_lic_id = self.store.get_binding(binding_key)
                if existing_lic_id:
                    result_lic = await self.provider.revoke_license(
                        existing_lic_id, reason=f"Refund processed on invoice {event.invoice_id}"
                    )

            elif event.event_type == BillingEventType.SUBSCRIPTION_PAST_DUE:
                existing_lic_id = self.store.get_binding(binding_key)
                if existing_lic_id:
                    result_lic = await self.provider.suspend_license(
                        existing_lic_id, reason="Subscription payment past due"
                    )

            elif event.event_type == BillingEventType.SUBSCRIPTION_CANCELED:
                existing_lic_id = self.store.get_binding(binding_key)
                if existing_lic_id:
                    result_lic = await self.provider.get_license(existing_lic_id)

            self.store.mark_processed(event.event_id)
            return result_lic
        except Exception:
            self.store.release_event_lock(event.event_id)
            raise
