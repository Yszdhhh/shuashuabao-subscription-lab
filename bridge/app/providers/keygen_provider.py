"""
Keygen License Authority Provider Adapter.
Implements ILicenseProvider using Keygen API conventions (JSON:API 1.0 format,
Policy, Machine activation, Component checking, and Cryptographic Offline Signing).
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from contracts.entitlement import (
    DeviceActivationDTO,
    EntitlementValidationResult,
    HardwareFingerprint,
    LicenseDTO,
    LicenseStatus,
    SignedOfflineEntitlement,
)
from bridge.app.core.cards import generate_card_code, mask_card_code, parse_plan_duration
from bridge.app.core.crypto import CryptoEngine
from bridge.app.core.fingerprint import FingerprintMatcher
from bridge.app.services.event_processor import SqliteEventStore
from bridge.app.providers.base import ILicenseProvider


class InMemoryKeygenProvider(ILicenseProvider):
    def __init__(
        self,
        crypto_engine: Optional[CryptoEngine] = None,
        event_store: Optional[SqliteEventStore] = None,
    ):
        self.crypto = crypto_engine or CryptoEngine()
        self.event_store = event_store or SqliteEventStore()
        self._activation_lock = asyncio.Lock()
        self.licenses: Dict[str, dict] = getattr(self.event_store, "load_local_licenses", lambda: {})()
        self.activations: Dict[str, List[dict]] = getattr(self.event_store, "load_local_activations", lambda: {})()
        self.trial_claims: Dict[str, dict] = {
            fp: {"components": components} for fp, components in self.event_store.trial_devices()
        }
        self.trial_accounts: set = self.event_store.trial_accounts()
        self.batches: Dict[str, dict] = {}
        if hasattr(self.event_store, "list_batches"):
            for b in self.event_store.list_batches():
                self.batches[b["batch_id"]] = b

    async def create_license(
        self,
        customer_id: str,
        customer_email: str,
        plan: str,
        duration_days: int = 30,
        device_limit: int = 1,
        features: Optional[List[str]] = None,
        metadata: Optional[Dict] = None,
    ) -> LicenseDTO:
        lic_id = f"lic_{uuid.uuid4().hex[:12]}"
        lic_key = f"KEYGEN-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=duration_days) if duration_days > 0 else None

        record = {
            "id": lic_id,
            "key": lic_key,
            "status": LicenseStatus.ACTIVE,
            "plan": plan,
            "customer_id": customer_id,
            "customer_email": customer_email,
            "created_at": now,
            "expires_at": expires_at,
            "device_limit": device_limit,
            "features": features or ["core", "automation"],
            "metadata": metadata or {},
            "suspended": False,
        }
        self.licenses[lic_id] = record
        self.activations.setdefault(lic_id, [])
        if hasattr(self.event_store, "save_local_license"):
            self.event_store.save_local_license(lic_id, lic_key, record)
        return self._to_dto(record)

    async def create_card(
        self,
        plan: str,
        duration_seconds: Optional[int] = None,
        batch_id: Optional[str] = None,
        customer_id: str = "card_user",
        customer_email: Optional[str] = None,
        device_limit: int = 1,
        features: Optional[List[str]] = None,
        metadata: Optional[Dict] = None,
        card_code: Optional[str] = None,
        prefix: Optional[str] = None,
    ) -> LicenseDTO:
        """Create a deferred-activation license card in UNUSED state."""
        plan_name, duration_sec = parse_plan_duration(plan, duration_seconds)
        lic_id = f"lic_{uuid.uuid4().hex[:12]}"
        lic_key = card_code or generate_card_code(plan=plan_name, prefix=prefix)
        while any(r["key"] == lic_key for r in self.licenses.values()):
            lic_key = generate_card_code(plan=plan_name, prefix=prefix)
        now = datetime.now(timezone.utc)

        meta = dict(metadata or {})
        if batch_id:
            meta["batch_id"] = batch_id
        meta["is_card"] = True

        record = {
            "id": lic_id,
            "key": lic_key,
            "status": LicenseStatus.UNUSED,
            "plan": plan_name,
            "customer_id": customer_id,
            "customer_email": customer_email,
            "created_at": now,
            "expires_at": None,
            "activated_at": None,
            "duration_seconds": duration_sec,
            "device_limit": device_limit,
            "features": features or ["core", "automation"],
            "metadata": meta,
            "suspended": False,
        }
        self.licenses[lic_id] = record
        self.activations.setdefault(lic_id, [])
        if hasattr(self.event_store, "save_local_license"):
            self.event_store.save_local_license(lic_id, lic_key, record)
        return self._to_dto(record)

    def _parse_license_dict(self, d: dict) -> dict:
        res = dict(d)
        if "created_at" in res and isinstance(res["created_at"], str):
            res["created_at"] = datetime.fromisoformat(res["created_at"].replace("Z", "+00:00"))
        if "expires_at" in res and isinstance(res["expires_at"], str):
            res["expires_at"] = datetime.fromisoformat(res["expires_at"].replace("Z", "+00:00"))
        if "activated_at" in res and isinstance(res["activated_at"], str):
            res["activated_at"] = datetime.fromisoformat(res["activated_at"].replace("Z", "+00:00"))
        if "duration_seconds" in res and res["duration_seconds"] is not None:
            res["duration_seconds"] = int(res["duration_seconds"])
        if "status" in res and isinstance(res["status"], str):
            res["status"] = LicenseStatus(res["status"])
        return res

    def _parse_activation_dict(self, a: dict) -> dict:
        res = dict(a)
        if "activated_at" in res and isinstance(res["activated_at"], str):
            res["activated_at"] = datetime.fromisoformat(res["activated_at"].replace("Z", "+00:00"))
        if "last_heartbeat_at" in res and isinstance(res["last_heartbeat_at"], str):
            res["last_heartbeat_at"] = datetime.fromisoformat(res["last_heartbeat_at"].replace("Z", "+00:00"))
        return res

    def prepare_cards(
        self,
        count: int,
        plan: str,
        duration_seconds: Optional[int] = None,
        batch_id: Optional[str] = None,
        operator_note: Optional[str] = None,
        device_limit: int = 1,
        prefix: Optional[str] = None,
    ) -> tuple[str, List[dict]]:
        """Generate license card dictionaries in memory without persisting to DB."""
        import secrets
        if count <= 0:
            raise ValueError("Card count must be greater than 0")
        plan_name, duration_sec = parse_plan_duration(plan, duration_seconds)
        now = datetime.now(timezone.utc)
        if not batch_id:
            batch_id = f"batch_{now.strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"

        cards: List[dict] = []
        for _ in range(count):
            meta = {"batch_id": batch_id, "is_card": True}
            if operator_note:
                meta["operator_note"] = operator_note
            lic_id = f"lic_{uuid.uuid4().hex[:12]}"
            lic_key = generate_card_code(plan=plan_name, prefix=prefix)
            while lic_key in [c["key"] for c in cards] or any(r["key"] == lic_key for r in self.licenses.values()):
                lic_key = generate_card_code(plan=plan_name, prefix=prefix)

            rec = {
                "id": lic_id,
                "key": lic_key,
                "status": LicenseStatus.UNUSED,
                "plan": plan_name,
                "customer_id": "card_user",
                "customer_email": None,
                "created_at": now,
                "expires_at": None,
                "activated_at": None,
                "duration_seconds": duration_sec,
                "device_limit": device_limit,
                "features": ["core", "automation"],
                "metadata": meta,
                "suspended": False,
            }
            cards.append(rec)
        return batch_id, cards

    async def commit_batch(
        self,
        batch_id: str,
        plan: str,
        duration_seconds: int,
        cards: List[dict],
        operator_note: Optional[str] = None,
        status: str = "COMMITTED",
    ) -> List[LicenseDTO]:
        """Atomically persist a batch of cards into the database and update memory cache."""
        if batch_id in self.batches:
            raise ValueError(f"DUPLICATE_BATCH_ID: batch '{batch_id}' already exists")
        now = datetime.now(timezone.utc)
        if hasattr(self.event_store, "save_batch_atomic"):
            self.event_store.save_batch_atomic(
                batch_id=batch_id,
                plan=plan,
                duration_seconds=duration_seconds,
                card_count=len(cards),
                cards_records=cards,
                operator_note=operator_note,
                status=status,
                created_at=now.isoformat(),
            )
        elif hasattr(self.event_store, "save_batch"):
            self.event_store.save_batch(
                batch_id=batch_id,
                plan=plan,
                duration_seconds=duration_seconds,
                card_count=len(cards),
                operator_note=operator_note,
                status=status,
                created_at=now.isoformat(),
            )
            if hasattr(self.event_store, "save_local_license"):
                for c in cards:
                    self.event_store.save_local_license(c["id"], c["key"], c)

        self.batches[batch_id] = {
            "batch_id": batch_id,
            "plan": plan,
            "duration_seconds": duration_seconds,
            "card_count": len(cards),
            "operator_note": operator_note,
            "status": status,
            "created_at": now.isoformat(),
        }

        dtos = []
        for rec in cards:
            self.licenses[rec["id"]] = rec
            self.activations.setdefault(rec["id"], [])
            dtos.append(self._to_dto(rec))
        return dtos

    def update_batch_status(self, batch_id: str, status: str) -> bool:
        """Update status of a batch in memory and persistent event store adhering to strict CAS/FSM."""
        target = status.upper()
        if hasattr(self.event_store, "update_batch_status"):
            ok = self.event_store.update_batch_status(batch_id, target)
            if ok and batch_id in self.batches:
                self.batches[batch_id]["status"] = target
            return ok

        # In-memory only fallback with same strict FSM
        if batch_id in self.batches:
            cur = self.batches[batch_id].get("status", "COMMITTED").upper()
            if cur == target:
                return True
            if cur == "PREPARED" and target in {"COMMITTED", "FAILED"}:
                self.batches[batch_id]["status"] = target
                return True
            raise ValueError(
                f"INVALID_STATE_TRANSITION: cannot transition batch '{batch_id}' from '{cur}' to '{target}'"
            )
        return False

    async def bulk_create_cards(
        self,
        count: int,
        plan: str,
        duration_seconds: Optional[int] = None,
        batch_id: Optional[str] = None,
        operator_note: Optional[str] = None,
        device_limit: int = 1,
        prefix: Optional[str] = None,
    ) -> tuple[str, List[LicenseDTO]]:
        """Bulk generate license cards in UNUSED state with atomic batch tracking."""
        plan_name, duration_sec = parse_plan_duration(plan, duration_seconds)
        b_id, card_recs = self.prepare_cards(
            count=count,
            plan=plan_name,
            duration_seconds=duration_sec,
            batch_id=batch_id,
            operator_note=operator_note,
            device_limit=device_limit,
            prefix=prefix,
        )
        cards = await self.commit_batch(
            batch_id=b_id,
            plan=plan_name,
            duration_seconds=duration_sec,
            cards=card_recs,
            operator_note=operator_note,
            status="COMMITTED",
        )
        return b_id, cards

    async def get_license(self, license_id: str) -> Optional[LicenseDTO]:
        rec = None
        for r in self.licenses.values():
            if r["id"] == license_id or r["key"] == license_id:
                rec = r
                break

        # Re-check DB if not found in memory, or if status is UNUSED (could be activated by another process)
        if rec is None or rec.get("status") == LicenseStatus.UNUSED:
            if hasattr(self.event_store, "get_local_license"):
                db_rec = self.event_store.get_local_license(license_id)
                if db_rec:
                    self.licenses[db_rec["id"]] = db_rec
                    if hasattr(self.event_store, "get_local_activations"):
                        self.activations[db_rec["id"]] = self.event_store.get_local_activations(db_rec["id"])
                    return self._to_dto(db_rec)

        if rec:
            return self._to_dto(rec)
        return None

    async def list_licenses(self, limit: int = 100) -> List[LicenseDTO]:
        """Return the newest licenses for the local management dashboard."""
        size = max(1, min(int(limit), 100))
        ordered = sorted(self.licenses.values(), key=lambda r: r["created_at"], reverse=True)
        return [self._to_dto(r) for r in ordered[:size]]

    async def set_license_expiry(self, license_id: str, expires_at: datetime) -> LicenseDTO:
        """Set an exact, server-authoritative expiry timestamp."""
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        rec = self.licenses[dto.license_id]
        if rec["status"] == LicenseStatus.REVOKED:
            raise ValueError("Cannot modify revoked license: terminal state")
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        rec["expires_at"] = expires_at
        if hasattr(self.event_store, "save_local_license"):
            self.event_store.save_local_license(dto.license_id, rec["key"], rec)
        return self._to_dto(rec)

    async def validate_license(
        self,
        license_key: str,
        fingerprint: Optional[str] = None,
        current_time: Optional[datetime] = None,
    ) -> EntitlementValidationResult:
        rec = None
        for r in self.licenses.values():
            if r["key"] == license_key or r["id"] == license_key:
                rec = r
                break

        if rec is None or rec.get("status") == LicenseStatus.UNUSED:
            if hasattr(self.event_store, "get_local_license"):
                db_rec = self.event_store.get_local_license(license_key)
                if db_rec:
                    self.licenses[db_rec["id"]] = db_rec
                    if hasattr(self.event_store, "get_local_activations"):
                        self.activations[db_rec["id"]] = self.event_store.get_local_activations(db_rec["id"])
                    rec = db_rec

        if not rec:
            return EntitlementValidationResult(
                valid=False,
                status=LicenseStatus.EXPIRED,
                can_start_runner=False,
                code="NOT_FOUND",
                message="License key does not exist",
            )

        now = current_time or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        status = rec["status"]

        if rec.get("suspended"):
            status = LicenseStatus.SUSPENDED
        elif status == LicenseStatus.UNUSED:
            b_id = rec.get("metadata", {}).get("batch_id") or rec.get("batch_id")
            if b_id:
                b_info = None
                if hasattr(self.event_store, "get_batch"):
                    b_info = self.event_store.get_batch(b_id)
                if not b_info and b_id in self.batches:
                    b_info = self.batches[b_id]
                if not b_info:
                    return EntitlementValidationResult(
                        valid=False,
                        status=LicenseStatus.UNUSED,
                        can_start_runner=False,
                        license=self._to_dto(rec),
                        code="BATCH_UNKNOWN",
                        message=f"License card batch '{b_id}' not found",
                    )
                if b_info.get("status") != "COMMITTED":
                    return EntitlementValidationResult(
                        valid=False,
                        status=LicenseStatus.UNUSED,
                        can_start_runner=False,
                        license=self._to_dto(rec),
                        code="BATCH_NOT_COMMITTED",
                        message=f"License card batch is in '{b_info.get('status')}' state and not committed",
                    )
            return EntitlementValidationResult(
                valid=False,
                status=LicenseStatus.UNUSED,
                can_start_runner=False,
                license=self._to_dto(rec),
                code="UNUSED",
                message="License card is unused and not activated yet",
            )
        elif rec["expires_at"] and now >= rec["expires_at"]:
            is_card = bool(rec.get("metadata", {}).get("is_card") or rec.get("is_card"))
            if is_card:
                # Strict expiry: zero grace period for cards
                status = LicenseStatus.EXPIRED
            else:
                # Check grace period (3 days grace default for subscriptions)
                grace_expiry = rec["expires_at"] + timedelta(days=3)
                if now < grace_expiry:
                    status = LicenseStatus.GRACE
                else:
                    status = LicenseStatus.EXPIRED

        can_start = status in [LicenseStatus.ACTIVE, LicenseStatus.GRACE, LicenseStatus.TRIAL]

        # Verify device activation if fingerprint supplied
        if fingerprint and can_start:
            active_devs = self.activations.get(rec["id"], [])
            dev_found = any(d["fingerprint"] == fingerprint for d in active_devs)
            if not dev_found:
                return EntitlementValidationResult(
                    valid=False,
                    status=status,
                    can_start_runner=False,
                    license=self._to_dto(rec),
                    code="DEVICE_NOT_ACTIVATED",
                    message="Current machine is not activated on this license",
                )

        return EntitlementValidationResult(
            valid=can_start,
            status=status,
            can_start_runner=can_start,
            license=self._to_dto(rec),
            code="OK" if can_start else status.value,
            message=f"License status is {status.value}",
        )

    async def renew_license(
        self, license_id: str, extend_days: int = 30
    ) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        rec = self.licenses[dto.license_id]
        if rec["status"] == LicenseStatus.REVOKED:
            raise ValueError("Cannot modify/reinstate revoked license: terminal state")
        now = datetime.now(timezone.utc)
        base_date = rec["expires_at"] if rec["expires_at"] and rec["expires_at"] > now else now
        rec["expires_at"] = base_date + timedelta(days=extend_days)
        rec["status"] = LicenseStatus.ACTIVE
        rec["suspended"] = False
        if hasattr(self.event_store, "save_local_license"):
            self.event_store.save_local_license(dto.license_id, rec["key"], rec)
        return self._to_dto(rec)

    async def extend_license(
        self, license_id: str, extend_days: int = 7
    ) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        rec = self.licenses[dto.license_id]
        if rec["status"] == LicenseStatus.REVOKED:
            raise ValueError("Cannot modify/reinstate revoked license: terminal state")
        return await self.renew_license(license_id, extend_days=extend_days)

    async def suspend_license(
        self, license_id: str, reason: str = "administrative_suspension"
    ) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        rec = self.licenses[dto.license_id]
        rec["suspended"] = True
        rec["status"] = LicenseStatus.SUSPENDED
        rec["metadata"]["suspend_reason"] = reason
        if hasattr(self.event_store, "save_local_license"):
            self.event_store.save_local_license(dto.license_id, rec["key"], rec)
        return self._to_dto(rec)

    async def reinstate_license(self, license_id: str) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        rec = self.licenses[dto.license_id]
        if rec["status"] == LicenseStatus.REVOKED:
            raise ValueError("Cannot modify/reinstate revoked license: terminal state")
        rec["suspended"] = False
        rec["status"] = LicenseStatus.ACTIVE
        if hasattr(self.event_store, "save_local_license"):
            self.event_store.save_local_license(dto.license_id, rec["key"], rec)
        return self._to_dto(rec)

    async def revoke_license(
        self, license_id: str, reason: str = "refunded_or_terminated"
    ) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        rec = self.licenses[dto.license_id]
        rec["status"] = LicenseStatus.REVOKED
        rec["suspended"] = False
        rec["metadata"]["revoke_reason"] = reason
        if hasattr(self.event_store, "save_local_license"):
            self.event_store.save_local_license(dto.license_id, rec["key"], rec)
        return self._to_dto(rec)

    async def activate_device(
        self, license_key: str, hardware: HardwareFingerprint
    ) -> DeviceActivationDTO:
        async with self._activation_lock:
            if hasattr(self.event_store, "activate_license_atomic"):
                server_now = datetime.now(timezone.utc)
                lic_data, act_record = self.event_store.activate_license_atomic(
                    license_key=license_key,
                    hardware_fp=hardware.fingerprint,
                    hardware_components=hardware.components,
                    hardware_hostname=hardware.hostname,
                    server_now=server_now,
                )
                lic_id = lic_data["id"]
                parsed_lic = self._parse_license_dict(lic_data)
                self.licenses[lic_id] = parsed_lic
                dev_list = self.activations.setdefault(lic_id, [])
                existing_dev = next((d for d in dev_list if d["fingerprint"] == hardware.fingerprint), None)
                parsed_act = self._parse_activation_dict(act_record)
                if existing_dev:
                    existing_dev["last_heartbeat_at"] = parsed_act["last_heartbeat_at"]
                else:
                    dev_list.append(parsed_act)

                return DeviceActivationDTO(
                    activation_id=parsed_act["id"],
                    license_id=lic_id,
                    fingerprint=parsed_act["fingerprint"],
                    name=parsed_act.get("name") or hardware.hostname or "primary_device",
                    activated_at=parsed_act["activated_at"],
                    last_heartbeat_at=parsed_act.get("last_heartbeat_at"),
                    components=parsed_act.get("components") or hardware.components,
                )

            dto = await self.get_license(license_key)
            if not dto:
                raise ValueError(f"License key {license_key} invalid")
            rec = self.licenses[dto.license_id]

            now = datetime.now(timezone.utc)

            # Check terminal / suspended states
            if rec["status"] == LicenseStatus.REVOKED:
                raise ValueError("Cannot activate revoked license: terminal state")
            if rec.get("suspended") or rec["status"] == LicenseStatus.SUSPENDED:
                raise ValueError("Cannot activate suspended license")

            # Check if card belongs to a batch and ensure the batch is COMMITTED
            card_batch_id = rec.get("metadata", {}).get("batch_id") or rec.get("batch_id")
            if card_batch_id:
                b_info = None
                if hasattr(self.event_store, "get_batch"):
                    b_info = self.event_store.get_batch(card_batch_id)
                if not b_info and card_batch_id in self.batches:
                    b_info = self.batches[card_batch_id]
                if not b_info:
                    raise ValueError(f"BATCH_UNKNOWN: card batch '{card_batch_id}' not found")
                if b_info.get("status") != "COMMITTED":
                    raise ValueError(f"BATCH_NOT_COMMITTED: card batch '{card_batch_id}' is in '{b_info.get('status')}' state")

            # Check if expired
            if rec.get("expires_at"):
                exp = rec["expires_at"]
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                is_card = bool(rec.get("metadata", {}).get("is_card") or rec.get("is_card"))
                cutoff = exp if is_card else (exp + timedelta(days=3))
                if now >= cutoff:
                    raise ValueError("Cannot activate expired license")

            dev_list = self.activations.setdefault(dto.license_id, [])

            # Idempotent reactivation of same machine
            for dev in dev_list:
                if dev["fingerprint"] == hardware.fingerprint:
                    dev["last_heartbeat_at"] = now
                    if hasattr(self.event_store, "save_local_activation"):
                        self.event_store.save_local_activation(
                            dev["id"], dto.license_id, hardware.fingerprint, dev
                        )
                    return DeviceActivationDTO(
                        activation_id=dev["id"],
                        license_id=dto.license_id,
                        fingerprint=hardware.fingerprint,
                        name=hardware.hostname or "primary_device",
                        activated_at=dev["activated_at"],
                        last_heartbeat_at=dev["last_heartbeat_at"],
                        components=hardware.components,
                    )

            # Check slot limit
            if len(dev_list) >= rec["device_limit"]:
                raise ValueError(f"DEVICE_LIMIT_EXCEEDED: license max devices ({rec['device_limit']}) reached")

            # First successful activation of an UNUSED card: starts clock now
            is_first_activation = (rec["status"] == LicenseStatus.UNUSED)
            if is_first_activation:
                duration_sec = rec.get("duration_seconds")
                if not duration_sec:
                    duration_sec = rec.get("duration_days", 30) * 86400
                rec["activated_at"] = now
                rec["expires_at"] = now + timedelta(seconds=duration_sec)
                rec["status"] = LicenseStatus.ACTIVE

            act_id = f"act_{uuid.uuid4().hex[:8]}"
            act_record = {
                "id": act_id,
                "fingerprint": hardware.fingerprint,
                "name": hardware.hostname or "primary_device",
                "activated_at": now,
                "last_heartbeat_at": now,
                "components": hardware.components,
            }
            dev_list.append(act_record)

            if is_first_activation and hasattr(self.event_store, "save_local_activation_atomic"):
                self.event_store.save_local_activation_atomic(
                    act_id=act_id,
                    lic_id=dto.license_id,
                    lic_key=rec["key"],
                    lic_data=rec,
                    fp=hardware.fingerprint,
                    act_data=act_record,
                )
            else:
                if is_first_activation and hasattr(self.event_store, "save_local_license"):
                    self.event_store.save_local_license(dto.license_id, rec["key"], rec)
                if hasattr(self.event_store, "save_local_activation"):
                    self.event_store.save_local_activation(act_id, dto.license_id, hardware.fingerprint, act_record)

            return DeviceActivationDTO(
                activation_id=act_id,
                license_id=dto.license_id,
                fingerprint=hardware.fingerprint,
                name=hardware.hostname or "primary_device",
                activated_at=now,
                last_heartbeat_at=now,
                components=hardware.components,
            )

    async def deactivate_device(
        self, license_key: str, fingerprint: str
    ) -> bool:
        dto = await self.get_license(license_key)
        if not dto:
            return False
        dev_list = self.activations.get(dto.license_id, [])
        initial_len = len(dev_list)
        self.activations[dto.license_id] = [d for d in dev_list if d["fingerprint"] != fingerprint]
        if hasattr(self.event_store, "delete_local_activation"):
            self.event_store.delete_local_activation(dto.license_id, fingerprint)
        return len(self.activations[dto.license_id]) < initial_len

    async def get_devices(self, license_id: str) -> List[DeviceActivationDTO]:
        dto = await self.get_license(license_id)
        if not dto:
            return []
        raw_list = self.activations.get(dto.license_id, [])
        return [
            DeviceActivationDTO(
                activation_id=d["id"],
                license_id=dto.license_id,
                fingerprint=d["fingerprint"],
                name=d.get("name"),
                activated_at=d["activated_at"],
                last_heartbeat_at=d.get("last_heartbeat_at"),
                components=d.get("components", {}),
            )
            for d in raw_list
        ]

    async def claim_trial(
        self,
        account_id: str,
        email: str,
        hardware: HardwareFingerprint,
        trial_days: int = 7,
    ) -> LicenseDTO:
        # Account-once and device-once checks include in-flight reservations.
        if self.event_store.has_trial_account(account_id) or account_id in self.trial_accounts:
            raise ValueError(f"TRIAL_ALREADY_CLAIMED: Account {account_id} has already claimed a trial")

        for prior_fp, prior_data in self.event_store.trial_devices():
            if prior_fp == hardware.fingerprint:
                raise ValueError(f"TRIAL_ALREADY_CLAIMED: Device {hardware.fingerprint} has already claimed a trial")
            is_match, matched, total, _ = FingerprintMatcher.match_components(
                prior_data, hardware.components, strategy="MATCH_MOST"
            )
            if is_match and total > 0:
                raise ValueError(
                    f"TRIAL_ABUSE_DETECTED: Hardware components match existing trial ({matched}/{total} components matched)"
                )

        if not self.event_store.reserve_trial(
            account_id, hardware.fingerprint, hardware.components
        ):
            raise ValueError(f"TRIAL_ALREADY_CLAIMED: Account {account_id} or device already claimed a trial")
        try:
            lic = await self.create_license(
                customer_id=account_id,
                customer_email=email,
                plan="trial_7d",
                duration_days=trial_days,
                device_limit=1,
                features=["core", "trial_tier"],
                metadata={"is_trial": True, "trial_account": account_id},
            )
            rec = self.licenses[lic.license_id]
            rec["status"] = LicenseStatus.TRIAL
            await self.activate_device(lic.license_key, hardware)
        except Exception:
            self.event_store.release_trial_reservation(account_id, hardware.fingerprint)
            raise

        self.event_store.confirm_trial_claim(
            account_id, hardware.fingerprint, lic.license_id
        )
        self.trial_accounts.add(account_id)
        self.trial_claims[hardware.fingerprint] = {
            "account_id": account_id,
            "license_id": lic.license_id,
            "components": hardware.components,
            "claimed_at": datetime.now(timezone.utc),
        }
        return self._to_dto(rec)

    async def issue_offline_entitlement(
        self, license_key: str, hardware: HardwareFingerprint, ttl_seconds: int = 86400 * 7
    ) -> SignedOfflineEntitlement:
        dto = await self.get_license(license_key)
        if not dto or dto.status not in [LicenseStatus.ACTIVE, LicenseStatus.TRIAL]:
            raise ValueError("Cannot issue offline certificate for inactive or invalid license")
        if not any(
            activation["fingerprint"] == hardware.fingerprint
            for activation in self.activations.get(dto.license_id, [])
        ):
            raise ValueError(
                "DEVICE_NOT_ACTIVATED: Cannot issue offline entitlement for unactivated device"
            )

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=48)
        if dto.expires_at:
            expires_at = min(expires_at, dto.expires_at)

        payload = {
            "license_id": dto.license_id,
            "fingerprint": hardware.fingerprint,
            "plan": dto.plan,
            "features": dto.features,
            "issued_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "algorithm": "ED25519",
        }

        cert_b64, sig_b64 = self.crypto.sign_payload(payload)
        return SignedOfflineEntitlement(
            certificate=cert_b64,
            signature=sig_b64,
            algorithm="ED25519",
            issued_at=now,
            expires_at=expires_at,
            license_id=dto.license_id,
            fingerprint=hardware.fingerprint,
            plan=dto.plan,
            features=dto.features,
        )

    async def verify_offline_entitlement(
        self, entitlement: SignedOfflineEntitlement, current_hardware: HardwareFingerprint
    ) -> EntitlementValidationResult:
        is_sig_valid, data, reason = self.crypto.verify_payload(
            entitlement.certificate, entitlement.signature
        )
        if not is_sig_valid:
            return EntitlementValidationResult(
                valid=False,
                status=LicenseStatus.REVOKED,
                can_start_runner=False,
                code="SIGNATURE_VERIFICATION_FAILED",
                message=reason,
            )

        if data.get("fingerprint") != current_hardware.fingerprint:
            return EntitlementValidationResult(
                valid=False,
                status=LicenseStatus.REVOKED,
                can_start_runner=False,
                code="FINGERPRINT_MISMATCH",
                message="Offline entitlement was signed for a different hardware fingerprint",
            )

        now = datetime.now(timezone.utc)
        exp_dt = datetime.fromisoformat(data["expires_at"])
        if now > exp_dt:
            return EntitlementValidationResult(
                valid=False,
                status=LicenseStatus.EXPIRED,
                can_start_runner=False,
                code="OFFLINE_TTL_EXPIRED",
                message="Offline certificate TTL has expired; reconnection required",
            )

        return EntitlementValidationResult(
            valid=True,
            status=LicenseStatus.ACTIVE,
            can_start_runner=True,
            code="OK",
            message="Offline entitlement cryptographic signature and TTL verified successfully",
        )

    def _to_dto(self, rec: dict) -> LicenseDTO:
        act_count = len(self.activations.get(rec["id"], []))
        return LicenseDTO(
            license_id=rec["id"],
            license_key=rec["key"],
            status=rec["status"],
            plan=rec.get("plan", "1d"),
            customer_id=rec.get("customer_id") or "card_user",
            customer_email=rec.get("customer_email"),
            created_at=rec.get("created_at") or datetime.now(timezone.utc),
            expires_at=rec.get("expires_at"),
            activated_at=rec.get("activated_at"),
            duration_seconds=rec.get("duration_seconds"),
            device_limit=rec.get("device_limit", 1),
            devices_used=act_count,
            features=rec.get("features", ["core", "automation"]),
            metadata=rec.get("metadata", {}),
        )


# Backward-compatible alias
KeygenProvider = InMemoryKeygenProvider
