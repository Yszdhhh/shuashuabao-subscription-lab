"""
Keygate Shadow License Engine Provider Adapter.
Implements the exact same ILicenseProvider interface to enable fair side-by-side benchmarking.
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
from bridge.app.core.cards import generate_card_code, parse_plan_duration
from bridge.app.core.crypto import CryptoEngine
from bridge.app.core.fingerprint import FingerprintMatcher
from bridge.app.services.event_processor import SqliteEventStore
from bridge.app.providers.base import ILicenseProvider


class InMemoryKeygateProvider(ILicenseProvider):
    def __init__(
        self,
        crypto_engine: Optional[CryptoEngine] = None,
        event_store: Optional[SqliteEventStore] = None,
    ):
        self.crypto = crypto_engine or CryptoEngine()
        self.event_store = event_store or SqliteEventStore()
        self._activation_lock = asyncio.Lock()
        self.licenses: Dict[str, dict] = {}
        self.activations: Dict[str, List[dict]] = {}
        self.trial_claims: Dict[str, dict] = {
            fp: {"components": components} for fp, components in self.event_store.trial_devices()
        }
        self.trial_accounts: set = self.event_store.trial_accounts()

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
        lic_id = f"kg_{uuid.uuid4().hex[:12]}"
        lic_key = f"KEYGATE-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"
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
            "features": features or ["core"],
            "metadata": metadata or {},
            "suspended": False,
        }
        self.licenses[lic_id] = record
        self.activations[lic_id] = []
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
        plan_name, duration_sec = parse_plan_duration(plan, duration_seconds)
        lic_id = f"kg_{uuid.uuid4().hex[:12]}"
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
            "features": features or ["core"],
            "metadata": meta,
            "suspended": False,
        }
        self.licenses[lic_id] = record
        self.activations[lic_id] = []
        return self._to_dto(record)

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
        import secrets
        if count <= 0:
            raise ValueError("Card count must be greater than 0")
        plan_name, duration_sec = parse_plan_duration(plan, duration_seconds)
        now = datetime.now(timezone.utc)
        if not batch_id:
            batch_id = f"batch_{now.strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"

        cards: List[LicenseDTO] = []
        for _ in range(count):
            meta = {"batch_id": batch_id}
            if operator_note:
                meta["operator_note"] = operator_note
            card = await self.create_card(
                plan=plan_name,
                duration_seconds=duration_sec,
                batch_id=batch_id,
                device_limit=device_limit,
                metadata=meta,
                prefix=prefix,
            )
            cards.append(card)
        return batch_id, cards

    async def get_license(self, license_id: str) -> Optional[LicenseDTO]:
        for rec in self.licenses.values():
            if rec["id"] == license_id or rec["key"] == license_id:
                return self._to_dto(rec)
        return None

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

        if not rec:
            return EntitlementValidationResult(
                valid=False,
                status=LicenseStatus.EXPIRED,
                can_start_runner=False,
                code="NOT_FOUND",
                message="Keygate license key not found",
            )

        now = current_time or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        status = rec["status"]

        if rec["suspended"]:
            status = LicenseStatus.SUSPENDED
        elif status == LicenseStatus.UNUSED:
            return EntitlementValidationResult(
                valid=False,
                status=LicenseStatus.UNUSED,
                can_start_runner=False,
                license=self._to_dto(rec),
                code="UNUSED",
                message="Keygate license card is unused and not activated yet",
            )
        elif rec["expires_at"] and now > rec["expires_at"]:
            is_card = bool(rec.get("metadata", {}).get("is_card") or rec.get("is_card"))
            if is_card:
                # Strict expiry: zero grace period for cards
                status = LicenseStatus.EXPIRED
            else:
                # Check grace period (3 days grace default for subscriptions)
                grace_expiry = rec["expires_at"] + timedelta(days=3)
                if now <= grace_expiry:
                    status = LicenseStatus.GRACE
                else:
                    status = LicenseStatus.EXPIRED

        can_start = status in [LicenseStatus.ACTIVE, LicenseStatus.GRACE, LicenseStatus.TRIAL]

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
                    message="Device not registered in Keygate machine list",
                )

        return EntitlementValidationResult(
            valid=can_start,
            status=status,
            can_start_runner=can_start,
            license=self._to_dto(rec),
            code="OK" if can_start else status.value,
            message=f"License status: {status.value}",
        )

    async def renew_license(
        self, license_id: str, extend_days: int = 30
    ) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found in Keygate")
        rec = self.licenses[dto.license_id]
        if rec["status"] == LicenseStatus.REVOKED:
            raise ValueError("Cannot modify/reinstate revoked license: terminal state")
        now = datetime.now(timezone.utc)
        base_date = rec["expires_at"] if rec["expires_at"] and rec["expires_at"] > now else now
        rec["expires_at"] = base_date + timedelta(days=extend_days)
        rec["status"] = LicenseStatus.ACTIVE
        rec["suspended"] = False
        return self._to_dto(rec)

    async def extend_license(
        self, license_id: str, extend_days: int = 7
    ) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found in Keygate")
        rec = self.licenses[dto.license_id]
        if rec["status"] == LicenseStatus.REVOKED:
            raise ValueError("Cannot modify/reinstate revoked license: terminal state")
        return await self.renew_license(license_id, extend_days=extend_days)

    async def suspend_license(
        self, license_id: str, reason: str = "administrative_suspension"
    ) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found in Keygate")
        rec = self.licenses[dto.license_id]
        rec["suspended"] = True
        rec["status"] = LicenseStatus.SUSPENDED
        rec["metadata"]["suspend_reason"] = reason
        return self._to_dto(rec)

    async def reinstate_license(self, license_id: str) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found in Keygate")
        rec = self.licenses[dto.license_id]
        if rec["status"] == LicenseStatus.REVOKED:
            raise ValueError("Cannot modify/reinstate revoked license: terminal state")
        rec["suspended"] = False
        rec["status"] = LicenseStatus.ACTIVE
        return self._to_dto(rec)

    async def revoke_license(
        self, license_id: str, reason: str = "refunded_or_terminated"
    ) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found in Keygate")
        rec = self.licenses[dto.license_id]
        rec["status"] = LicenseStatus.REVOKED
        rec["suspended"] = False
        rec["metadata"]["revoke_reason"] = reason
        return self._to_dto(rec)

    async def activate_device(
        self, license_key: str, hardware: HardwareFingerprint
    ) -> DeviceActivationDTO:
        async with self._activation_lock:
            dto = await self.get_license(license_key)
            if not dto:
                raise ValueError(f"License key {license_key} invalid in Keygate")
            rec = self.licenses[dto.license_id]

            now = datetime.now(timezone.utc)

            # Check terminal / suspended states
            if rec["status"] == LicenseStatus.REVOKED:
                raise ValueError("Cannot activate revoked license: terminal state")
            if rec.get("suspended") or rec["status"] == LicenseStatus.SUSPENDED:
                raise ValueError("Cannot activate suspended license")
            if rec.get("expires_at"):
                exp = rec["expires_at"]
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                is_card = bool(rec.get("metadata", {}).get("is_card") or rec.get("is_card"))
                cutoff = exp if is_card else (exp + timedelta(days=3))
                if now > cutoff:
                    raise ValueError("Cannot activate expired license")

            dev_list = self.activations.setdefault(dto.license_id, [])

            for dev in dev_list:
                if dev["fingerprint"] == hardware.fingerprint:
                    dev["last_heartbeat_at"] = now
                    return DeviceActivationDTO(
                        activation_id=dev["id"],
                        license_id=dto.license_id,
                        fingerprint=hardware.fingerprint,
                        name=hardware.hostname or "keygate_node",
                        activated_at=dev["activated_at"],
                        last_heartbeat_at=dev["last_heartbeat_at"],
                    )

            if len(dev_list) >= rec["device_limit"]:
                raise ValueError(f"DEVICE_LIMIT_EXCEEDED: Keygate device limit ({rec['device_limit']}) reached")

            # First successful activation of an UNUSED card
            if rec["status"] == LicenseStatus.UNUSED:
                duration_sec = rec.get("duration_seconds")
                if not duration_sec:
                    duration_sec = rec.get("duration_days", 30) * 86400
                rec["activated_at"] = now
                rec["expires_at"] = now + timedelta(seconds=duration_sec)
                rec["status"] = LicenseStatus.ACTIVE

            act_id = f"kg_act_{uuid.uuid4().hex[:8]}"
            act_record = {
                "id": act_id,
                "fingerprint": hardware.fingerprint,
                "name": hardware.hostname or "keygate_node",
                "activated_at": now,
                "last_heartbeat_at": now,
            }
            dev_list.append(act_record)
            return DeviceActivationDTO(
                activation_id=act_id,
                license_id=dto.license_id,
                fingerprint=hardware.fingerprint,
                name=hardware.hostname or "keygate_node",
                activated_at=now,
                last_heartbeat_at=now,
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
        if self.event_store.has_trial_account(account_id) or account_id in self.trial_accounts:
            raise ValueError(f"TRIAL_ALREADY_CLAIMED: Account {account_id} has already claimed a trial")
        if hardware.fingerprint in self.trial_claims:
            raise ValueError(
                f"TRIAL_ALREADY_CLAIMED: Device {hardware.fingerprint} already claimed trial in Keygate"
            )

        for prior_data in self.trial_claims.values():
            prior_components = prior_data.get("components", {})
            if prior_components and hardware.components:
                is_match, matched, total, _ = FingerprintMatcher.match_components(
                    prior_components, hardware.components, strategy="MATCH_MOST"
                )
                if is_match and total > 0:
                    raise ValueError(
                        f"TRIAL_ABUSE_DETECTED: Hardware components match existing trial ({matched}/{total} components matched)"
                    )

        lic = await self.create_license(
            customer_id=account_id,
            customer_email=email,
            plan="trial_7d",
            duration_days=trial_days,
            device_limit=1,
            features=["core", "trial"],
            metadata={"is_trial": True},
        )
        rec = self.licenses[lic.license_id]
        rec["status"] = LicenseStatus.TRIAL
        await self.activate_device(lic.license_key, hardware)
        if not self.event_store.record_trial_claim(
            account_id, hardware.fingerprint, hardware.components
        ):
            raise ValueError(f"TRIAL_ALREADY_CLAIMED: Account {account_id} or device already claimed a trial")
        self.trial_accounts.add(account_id)
        self.trial_claims[hardware.fingerprint] = {
            "account_id": account_id,
            "components": hardware.components,
            "claimed_at": datetime.now(timezone.utc),
        }
        return self._to_dto(rec)

    async def issue_offline_entitlement(
        self, license_key: str, hardware: HardwareFingerprint, ttl_seconds: int = 86400 * 7
    ) -> SignedOfflineEntitlement:
        dto = await self.get_license(license_key)
        if not dto or dto.status not in [LicenseStatus.ACTIVE, LicenseStatus.TRIAL]:
            raise ValueError("Keygate cannot issue offline certificate for inactive license")
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
                message="Keygate offline certificate fingerprint mismatch",
            )

        now = datetime.now(timezone.utc)
        exp_dt = datetime.fromisoformat(data["expires_at"])
        if now > exp_dt:
            return EntitlementValidationResult(
                valid=False,
                status=LicenseStatus.EXPIRED,
                can_start_runner=False,
                code="OFFLINE_TTL_EXPIRED",
                message="Keygate offline token expired",
            )

        return EntitlementValidationResult(
            valid=True,
            status=LicenseStatus.ACTIVE,
            can_start_runner=True,
            code="OK",
            message="Keygate offline verification success",
        )

    def _to_dto(self, rec: dict) -> LicenseDTO:
        act_count = len(self.activations.get(rec["id"], []))
        return LicenseDTO(
            license_id=rec["id"],
            license_key=rec["key"],
            status=rec["status"],
            plan=rec["plan"],
            customer_id=rec["customer_id"],
            customer_email=rec["customer_email"],
            created_at=rec["created_at"],
            expires_at=rec["expires_at"],
            activated_at=rec.get("activated_at"),
            duration_seconds=rec.get("duration_seconds"),
            device_limit=rec["device_limit"],
            devices_used=act_count,
            features=rec["features"],
            metadata=rec["metadata"],
        )


# Backward-compatible alias
KeygateProvider = InMemoryKeygateProvider
