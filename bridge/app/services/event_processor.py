"""
FOSSBilling Webhook Adapter and Normalization Service.
Translates FOSSBilling webhook/event payloads into NormalizedBillingEvent,
handles idempotency checking to prevent double billing/extension, and drives License Provider.
"""
import asyncio
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
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
            CREATE TABLE IF NOT EXISTS trial_reservations (
                account_id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                components_json TEXT NOT NULL,
                reserved_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS local_licenses (
                id TEXT PRIMARY KEY,
                key TEXT UNIQUE NOT NULL,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS local_activations (
                activation_id TEXT PRIMARY KEY,
                license_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                data_json TEXT NOT NULL,
                activated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS license_batches (
                batch_id TEXT PRIMARY KEY,
                plan TEXT NOT NULL,
                duration_seconds INTEGER NOT NULL,
                card_count INTEGER NOT NULL,
                operator_note TEXT,
                status TEXT NOT NULL DEFAULT 'COMMITTED',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS release_policies (
                source_sha TEXT NOT NULL,
                release_manifest_sha256 TEXT NOT NULL,
                release_channel TEXT NOT NULL,
                allowed_modes_json TEXT NOT NULL,
                blocked INTEGER NOT NULL DEFAULT 0,
                advisory TEXT,
                recommended_source_sha TEXT,
                recommended_manifest_sha256 TEXT,
                recommended_channel TEXT,
                operator_note TEXT,
                updated_at TEXT NOT NULL,
                updated_by TEXT,
                PRIMARY KEY (source_sha, release_manifest_sha256, release_channel)
            );
        """)
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(processed_events)")}
        if "status" not in columns:
            self._conn.execute(
                "ALTER TABLE processed_events ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'"
            )
        batch_columns = {row[1] for row in self._conn.execute("PRAGMA table_info(license_batches)")}
        if "status" not in batch_columns:
            self._conn.execute(
                "ALTER TABLE license_batches ADD COLUMN status TEXT NOT NULL DEFAULT 'COMMITTED'"
            )

    def acquire_event_lock(self, event_id: str, lease_seconds: int = 30) -> bool:
        """Atomically reserve an event, reclaiming an expired processing lease."""
        now = datetime.now(timezone.utc)
        now_text = now.isoformat()
        try:
            self._conn.execute(
                "INSERT INTO processed_events (event_id, status, processed_at) VALUES (?, 'processing', ?)",
                (event_id, now_text),
            )
            return True
        except sqlite3.IntegrityError:
            row = self._conn.execute(
                "SELECT status, processed_at FROM processed_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if not row or row[0] != "processing":
                return False
            try:
                processed_at = datetime.fromisoformat(row[1].replace("Z", "+00:00"))
                if processed_at.tzinfo is None:
                    processed_at = processed_at.replace(tzinfo=timezone.utc)
            except (AttributeError, TypeError, ValueError):
                return False
            if (now - processed_at).total_seconds() <= lease_seconds:
                return False
            cur = self._conn.execute(
                """UPDATE processed_events
                   SET processed_at = ?
                   WHERE event_id = ? AND status = 'processing' AND processed_at = ?""",
                (now_text, event_id, row[1]),
            )
            return cur.rowcount == 1

    def is_processed(self, event_id: str) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM processed_events WHERE event_id = ? AND status = 'completed'",
            (event_id,)
        )
        return cur.fetchone() is not None

    def is_processing(self, event_id: str) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM processed_events WHERE event_id = ? AND status = 'processing'",
            (event_id,)
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
            """SELECT 1 FROM trial_accounts WHERE account_id = ?
               UNION ALL SELECT 1 FROM trial_reservations WHERE account_id = ?""",
            (account_id, account_id),
        ).fetchone() is not None

    def trial_accounts(self) -> set[str]:
        return {
            row[0]
            for row in self._conn.execute(
                """SELECT account_id FROM trial_accounts
                   UNION SELECT account_id FROM trial_reservations"""
            )
        }

    def trial_devices(self) -> list[tuple[str, dict]]:
        import json
        return [
            (fingerprint, json.loads(components_json))
            for fingerprint, components_json in self._conn.execute(
                """SELECT fingerprint, components_json FROM trial_devices
                   UNION ALL SELECT fingerprint, components_json FROM trial_reservations"""
            )
        ]

    def reserve_trial(self, account_id: str, fingerprint: str, components: dict) -> bool:
        """Atomically reserve an account and device before calling an upstream API."""
        import json
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            if self._conn.execute(
                """SELECT 1 FROM trial_accounts WHERE account_id = ?
                   UNION ALL SELECT 1 FROM trial_reservations WHERE account_id = ?""",
                (account_id, account_id),
            ).fetchone():
                self._conn.execute("ROLLBACK")
                return False
            if self._conn.execute(
                """SELECT 1 FROM trial_devices WHERE fingerprint = ?
                   UNION ALL SELECT 1 FROM trial_reservations WHERE fingerprint = ?""",
                (fingerprint, fingerprint),
            ).fetchone():
                self._conn.execute("ROLLBACK")
                return False
            self._conn.execute(
                """INSERT INTO trial_reservations
                   (account_id, fingerprint, components_json, reserved_at)
                   VALUES (?, ?, ?, ?)""",
                (account_id, fingerprint, json.dumps(components, sort_keys=True),
                 datetime.now(timezone.utc).isoformat()),
            )
            self._conn.execute("COMMIT")
            return True
        except sqlite3.IntegrityError:
            self._conn.execute("ROLLBACK")
            return False
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def release_trial_reservation(self, account_id: str, fingerprint: str) -> None:
        self._conn.execute(
            "DELETE FROM trial_reservations WHERE account_id = ? AND fingerprint = ?",
            (account_id, fingerprint),
        )

    def confirm_trial_claim(self, account_id: str, fingerprint: str, license_id: str) -> None:
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute(
                """SELECT components_json FROM trial_reservations
                   WHERE account_id = ? AND fingerprint = ?""",
                (account_id, fingerprint),
            ).fetchone()
            if row is None:
                confirmed = self._conn.execute(
                    """SELECT 1 FROM trial_accounts WHERE account_id = ?
                       AND EXISTS (SELECT 1 FROM trial_devices WHERE fingerprint = ?)""",
                    (account_id, fingerprint),
                ).fetchone()
                if confirmed:
                    self._conn.execute("COMMIT")
                    return
                raise ValueError("TRIAL_RESERVATION_NOT_FOUND")
            self._conn.execute(
                "INSERT INTO trial_accounts (account_id) VALUES (?)", (account_id,)
            )
            self._conn.execute(
                "INSERT INTO trial_devices (fingerprint, components_json) VALUES (?, ?)",
                (fingerprint, row[0]),
            )
            self._conn.execute(
                "DELETE FROM trial_reservations WHERE account_id = ? AND fingerprint = ?",
                (account_id, fingerprint),
            )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

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

    def save_local_license(self, lic_id: str, key: str, data: dict) -> None:
        import json
        now_text = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "INSERT OR REPLACE INTO local_licenses (id, key, data_json, created_at) VALUES (?, ?, ?, ?)",
            (lic_id, key, json.dumps(data, default=str), now_text),
        )

    def load_local_licenses(self) -> dict:
        import json
        from contracts.entitlement import LicenseStatus
        cur = self._conn.execute("SELECT id, data_json FROM local_licenses")
        records = {}
        for row in cur.fetchall():
            try:
                d = json.loads(row[1])
                if "created_at" in d and d["created_at"]:
                    d["created_at"] = datetime.fromisoformat(d["created_at"].replace("Z", "+00:00"))
                if "expires_at" in d and d["expires_at"]:
                    d["expires_at"] = datetime.fromisoformat(d["expires_at"].replace("Z", "+00:00"))
                if "activated_at" in d and d["activated_at"]:
                    d["activated_at"] = datetime.fromisoformat(d["activated_at"].replace("Z", "+00:00"))
                if "duration_seconds" in d and d["duration_seconds"] is not None:
                    d["duration_seconds"] = int(d["duration_seconds"])
                if "status" in d and isinstance(d["status"], str):
                    d["status"] = LicenseStatus(d["status"])
                records[row[0]] = d
            except Exception:
                pass
        return records

    def get_local_license(self, key_or_id: str) -> Optional[dict]:
        import json
        from contracts.entitlement import LicenseStatus
        row = self._conn.execute(
            "SELECT id, data_json FROM local_licenses WHERE id = ? OR key = ?",
            (key_or_id, key_or_id),
        ).fetchone()
        if not row:
            return None
        try:
            d = json.loads(row[1])
            if "created_at" in d and d["created_at"]:
                d["created_at"] = datetime.fromisoformat(d["created_at"].replace("Z", "+00:00"))
            if "expires_at" in d and d["expires_at"]:
                d["expires_at"] = datetime.fromisoformat(d["expires_at"].replace("Z", "+00:00"))
            if "activated_at" in d and d["activated_at"]:
                d["activated_at"] = datetime.fromisoformat(d["activated_at"].replace("Z", "+00:00"))
            if "duration_seconds" in d and d["duration_seconds"] is not None:
                d["duration_seconds"] = int(d["duration_seconds"])
            if "status" in d and isinstance(d["status"], str):
                d["status"] = LicenseStatus(d["status"])
            return d
        except Exception:
            return None

    def save_local_activation(self, act_id: str, lic_id: str, fp: str, data: dict) -> None:
        import json
        now_text = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "INSERT OR REPLACE INTO local_activations (activation_id, license_id, fingerprint, data_json, activated_at) VALUES (?, ?, ?, ?, ?)",
            (act_id, lic_id, fp, json.dumps(data, default=str), now_text),
        )

    def activate_license_atomic(
        self,
        license_key: str,
        hardware_fp: str,
        hardware_components: Optional[dict] = None,
        hardware_hostname: Optional[str] = None,
        server_now: Optional[datetime] = None,
    ) -> tuple[dict, dict]:
        """
        Database-authoritative compare-and-set activation within an exclusive SQLite transaction.
        Protects against cross-process and cross-connection race conditions.
        Returns: (committed_license_data_dict, committed_activation_data_dict)
        """
        import json
        now = server_now or datetime.now(timezone.utc)
        now_text = now.isoformat()

        try:
            self._conn.execute("BEGIN IMMEDIATE")

            # 1. Authoritative re-read license from DB
            row = self._conn.execute(
                "SELECT id, key, data_json, created_at FROM local_licenses WHERE key = ? OR id = ?",
                (license_key, license_key),
            ).fetchone()
            if not row:
                self._conn.execute("ROLLBACK")
                raise ValueError(f"License key {license_key} invalid")

            lic_id, lic_key, data_json, lic_created_at = row
            lic_data = json.loads(data_json)

            # 2. Check terminal / suspended states
            if lic_data.get("status") == "REVOKED":
                self._conn.execute("ROLLBACK")
                raise ValueError("Cannot activate revoked license: terminal state")
            if lic_data.get("suspended") or lic_data.get("status") == "SUSPENDED":
                self._conn.execute("ROLLBACK")
                raise ValueError("Cannot activate suspended license")

            # Check expired from DB state
            is_card = bool(lic_data.get("metadata", {}).get("is_card") or lic_data.get("is_card"))
            if lic_data.get("expires_at"):
                exp = datetime.fromisoformat(lic_data["expires_at"].replace("Z", "+00:00"))
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                cutoff = exp if is_card else (exp + timedelta(days=3))
                if now > cutoff:
                    self._conn.execute("ROLLBACK")
                    raise ValueError("Cannot activate expired license")

            # 3. Read current active devices from local_activations table directly in DB
            cur_acts = self._conn.execute(
                "SELECT activation_id, fingerprint, data_json, activated_at FROM local_activations WHERE license_id = ?",
                (lic_id,),
            ).fetchall()

            # 4. Check idempotent reactivation of same machine
            for act_row in cur_acts:
                act_id_existing, fp_existing, act_json, act_at = act_row
                if fp_existing == hardware_fp:
                    existing_act_data = json.loads(act_json)
                    existing_act_data["last_heartbeat_at"] = now_text
                    self._conn.execute(
                        "UPDATE local_activations SET data_json = ? WHERE activation_id = ?",
                        (json.dumps(existing_act_data, default=str), act_id_existing),
                    )
                    self._conn.execute("COMMIT")
                    return lic_data, existing_act_data

            # 5. Authoritative slot limit check inside transaction
            device_limit = int(lic_data.get("device_limit", 1))
            if len(cur_acts) >= device_limit:
                self._conn.execute("ROLLBACK")
                raise ValueError(f"DEVICE_LIMIT_EXCEEDED: license max devices ({device_limit}) reached")

            # 6. If UNUSED, perform authoritative state transition to ACTIVE
            if lic_data.get("status") == "UNUSED":
                duration_sec = lic_data.get("duration_seconds")
                if not duration_sec:
                    duration_sec = lic_data.get("duration_days", 30) * 86400
                lic_data["activated_at"] = now_text
                expires_at_dt = now + timedelta(seconds=duration_sec)
                lic_data["expires_at"] = expires_at_dt.isoformat()
                lic_data["status"] = "ACTIVE"

                self._conn.execute(
                    "UPDATE local_licenses SET data_json = ? WHERE id = ?",
                    (json.dumps(lic_data, default=str), lic_id),
                )

            # 7. Insert new activation record
            act_id = f"act_{uuid.uuid4().hex[:8]}"
            act_record = {
                "id": act_id,
                "fingerprint": hardware_fp,
                "name": hardware_hostname or "primary_device",
                "activated_at": now_text,
                "last_heartbeat_at": now_text,
                "components": hardware_components or {},
            }
            self._conn.execute(
                "INSERT INTO local_activations (activation_id, license_id, fingerprint, data_json, activated_at) VALUES (?, ?, ?, ?, ?)",
                (act_id, lic_id, hardware_fp, json.dumps(act_record, default=str), now_text),
            )

            self._conn.execute("COMMIT")
            return lic_data, act_record

        except Exception:
            try:
                self._conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

    def save_batch_atomic(
        self,
        batch_id: str,
        plan: str,
        duration_seconds: int,
        card_count: int,
        cards_records: list[dict],
        operator_note: Optional[str] = None,
        status: str = "COMMITTED",
        created_at: Optional[str] = None,
    ) -> None:
        """Atomically persist a batch record and all its license cards in a single SQLite transaction."""
        import json
        now_text = created_at or datetime.now(timezone.utc).isoformat()
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            batch_columns = {row[1] for row in self._conn.execute("PRAGMA table_info(license_batches)")}
            if "status" in batch_columns:
                self._conn.execute(
                    """INSERT OR REPLACE INTO license_batches
                       (batch_id, plan, duration_seconds, card_count, operator_note, status, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (batch_id, plan, duration_seconds, card_count, operator_note, status, now_text),
                )
            else:
                self._conn.execute(
                    """INSERT OR REPLACE INTO license_batches
                       (batch_id, plan, duration_seconds, card_count, operator_note, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (batch_id, plan, duration_seconds, card_count, operator_note, now_text),
                )
            for card in cards_records:
                self._conn.execute(
                    "INSERT OR REPLACE INTO local_licenses (id, key, data_json, created_at) VALUES (?, ?, ?, ?)",
                    (card["id"], card["key"], json.dumps(card, default=str), now_text),
                )
            self._conn.execute("COMMIT")
        except Exception:
            try:
                self._conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

    def save_local_activation_atomic(
        self,
        act_id: str,
        lic_id: str,
        lic_key: str,
        lic_data: dict,
        fp: str,
        act_data: dict,
    ) -> None:
        """Atomically persist updated license (status, activated_at, expires_at) and device activation."""
        import json
        now_text = datetime.now(timezone.utc).isoformat()
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute(
                "INSERT OR REPLACE INTO local_licenses (id, key, data_json, created_at) VALUES (?, ?, ?, ?)",
                (lic_id, lic_key, json.dumps(lic_data, default=str), now_text),
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO local_activations (activation_id, license_id, fingerprint, data_json, activated_at) VALUES (?, ?, ?, ?, ?)",
                (act_id, lic_id, fp, json.dumps(act_data, default=str), now_text),
            )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def delete_local_activation(self, lic_id: str, fp: str) -> None:
        self._conn.execute(
            "DELETE FROM local_activations WHERE license_id = ? AND fingerprint = ?",
            (lic_id, fp),
        )

    def load_local_activations(self) -> dict:
        import json
        cur = self._conn.execute("SELECT license_id, data_json FROM local_activations")
        acts = {}
        for row in cur.fetchall():
            lic_id, json_str = row[0], row[1]
            try:
                d = json.loads(json_str)
                if "activated_at" in d and d["activated_at"]:
                    d["activated_at"] = datetime.fromisoformat(d["activated_at"].replace("Z", "+00:00"))
                if "last_heartbeat_at" in d and d["last_heartbeat_at"]:
                    d["last_heartbeat_at"] = datetime.fromisoformat(d["last_heartbeat_at"].replace("Z", "+00:00"))
                acts.setdefault(lic_id, []).append(d)
            except Exception:
                pass
        return acts

    def get_local_activations(self, lic_id: str) -> list[dict]:
        import json
        cur = self._conn.execute("SELECT data_json FROM local_activations WHERE license_id = ?", (lic_id,))
        acts = []
        for row in cur.fetchall():
            try:
                d = json.loads(row[0])
                if "activated_at" in d and d["activated_at"]:
                    d["activated_at"] = datetime.fromisoformat(d["activated_at"].replace("Z", "+00:00"))
                if "last_heartbeat_at" in d and d["last_heartbeat_at"]:
                    d["last_heartbeat_at"] = datetime.fromisoformat(d["last_heartbeat_at"].replace("Z", "+00:00"))
                acts.append(d)
            except Exception:
                pass
        return acts

    def save_batch(
        self,
        batch_id: str,
        plan: str,
        duration_seconds: int,
        card_count: int,
        operator_note: Optional[str] = None,
        status: str = "COMMITTED",
        created_at: Optional[str] = None,
    ) -> None:
        created_at = created_at or datetime.now(timezone.utc).isoformat()
        batch_columns = {row[1] for row in self._conn.execute("PRAGMA table_info(license_batches)")}
        if "status" in batch_columns:
            self._conn.execute(
                """INSERT OR REPLACE INTO license_batches
                   (batch_id, plan, duration_seconds, card_count, operator_note, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (batch_id, plan, duration_seconds, card_count, operator_note, status, created_at),
            )
        else:
            self._conn.execute(
                """INSERT OR REPLACE INTO license_batches
                   (batch_id, plan, duration_seconds, card_count, operator_note, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (batch_id, plan, duration_seconds, card_count, operator_note, created_at),
            )

    def list_batches(self) -> list[dict]:
        batch_columns = {row[1] for row in self._conn.execute("PRAGMA table_info(license_batches)")}
        if "status" in batch_columns:
            cur = self._conn.execute(
                """SELECT batch_id, plan, duration_seconds, card_count, operator_note, status, created_at
                   FROM license_batches ORDER BY created_at DESC"""
            )
            cols = ["batch_id", "plan", "duration_seconds", "card_count", "operator_note", "status", "created_at"]
        else:
            cur = self._conn.execute(
                """SELECT batch_id, plan, duration_seconds, card_count, operator_note, created_at
                   FROM license_batches ORDER BY created_at DESC"""
            )
            cols = ["batch_id", "plan", "duration_seconds", "card_count", "operator_note", "created_at"]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def delete_batch_and_cards(self, batch_id: str) -> None:
        """Atomically delete a batch and all its associated cards and activations from SQLite."""
        import json
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            cur = self._conn.execute("SELECT id, data_json FROM local_licenses")
            card_ids = []
            for row in cur.fetchall():
                try:
                    d = json.loads(row[1])
                    if (d.get("metadata", {}).get("batch_id") == batch_id) or (d.get("batch_id") == batch_id):
                        card_ids.append(row[0])
                except Exception:
                    pass
            for cid in card_ids:
                self._conn.execute("DELETE FROM local_licenses WHERE id = ?", (cid,))
                self._conn.execute("DELETE FROM local_activations WHERE license_id = ?", (cid,))
            self._conn.execute("DELETE FROM license_batches WHERE batch_id = ?", (batch_id,))
            self._conn.execute("COMMIT")
        except Exception:
            try:
                self._conn.execute("ROLLBACK")
            except Exception:
                pass


    def upsert_release_policy(
        self,
        *,
        source_sha: str,
        release_manifest_sha256: str,
        release_channel: str,
        allowed_modes: list,
        blocked: bool = False,
        advisory: str | None = None,
        recommended_source_sha: str | None = None,
        recommended_manifest_sha256: str | None = None,
        recommended_channel: str | None = None,
        operator_note: str | None = None,
        updated_by: str | None = None,
    ) -> None:
        import json
        now_text = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._conn.execute(
            """INSERT INTO release_policies (
                source_sha, release_manifest_sha256, release_channel,
                allowed_modes_json, blocked, advisory,
                recommended_source_sha, recommended_manifest_sha256, recommended_channel,
                operator_note, updated_at, updated_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_sha, release_manifest_sha256, release_channel) DO UPDATE SET
                allowed_modes_json=excluded.allowed_modes_json,
                blocked=excluded.blocked,
                advisory=excluded.advisory,
                recommended_source_sha=excluded.recommended_source_sha,
                recommended_manifest_sha256=excluded.recommended_manifest_sha256,
                recommended_channel=excluded.recommended_channel,
                operator_note=excluded.operator_note,
                updated_at=excluded.updated_at,
                updated_by=excluded.updated_by
            """,
            (
                source_sha, release_manifest_sha256, release_channel,
                json.dumps(list(allowed_modes)),
                1 if blocked else 0,
                advisory,
                recommended_source_sha, recommended_manifest_sha256, recommended_channel,
                operator_note, now_text, updated_by,
            ),
        )

    def get_release_policy(
        self, source_sha: str, release_manifest_sha256: str, release_channel: str
    ) -> dict | None:
        import json
        row = self._conn.execute(
            """SELECT source_sha, release_manifest_sha256, release_channel,
                      allowed_modes_json, blocked, advisory,
                      recommended_source_sha, recommended_manifest_sha256, recommended_channel,
                      operator_note, updated_at, updated_by
               FROM release_policies
               WHERE source_sha=? AND release_manifest_sha256=? AND release_channel=?""",
            (source_sha, release_manifest_sha256, release_channel),
        ).fetchone()
        if not row:
            return None
        return {
            "source_sha": row[0],
            "release_manifest_sha256": row[1],
            "release_channel": row[2],
            "allowed_modes": list(json.loads(row[3] or "[]")),
            "blocked": bool(row[4]),
            "advisory": row[5],
            "recommended_source_sha": row[6],
            "recommended_manifest_sha256": row[7],
            "recommended_channel": row[8],
            "operator_note": row[9],
            "updated_at": row[10],
            "updated_by": row[11],
        }

    def list_release_policies(self) -> list:
        import json
        rows = self._conn.execute(
            """SELECT source_sha, release_manifest_sha256, release_channel,
                      allowed_modes_json, blocked, advisory,
                      recommended_source_sha, recommended_manifest_sha256, recommended_channel,
                      operator_note, updated_at, updated_by
               FROM release_policies ORDER BY updated_at DESC"""
        ).fetchall()
        out = []
        for row in rows:
            out.append({
                "source_sha": row[0],
                "release_manifest_sha256": row[1],
                "release_channel": row[2],
                "allowed_modes": list(json.loads(row[3] or "[]")),
                "blocked": bool(row[4]),
                "advisory": row[5],
                "recommended_source_sha": row[6],
                "recommended_manifest_sha256": row[7],
                "recommended_channel": row[8],
                "operator_note": row[9],
                "updated_at": row[10],
                "updated_by": row[11],
            })
        return out

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
