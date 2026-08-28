"""
Keygate Shadow License Engine Provider Adapter.
Implements the exact same ILicenseProvider interface to enable fair side-by-side benchmarking.
"""
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
from bridge.app.core.crypto import CryptoEngine
from bridge.app.providers.base import ILicenseProvider


class KeygateProvider(ILicenseProvider):
    def __init__(self, crypto_engine: Optional[CryptoEngine] = None):
        self.crypto = crypto_engine or CryptoEngine()
        self.licenses: Dict[str, dict] = {}
        self.activations: Dict[str, List[dict]] = {}
        self.trial_claims: Dict[str, dict] = {}

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

    async def get_license(self, license_id: str) -> Optional[LicenseDTO]:
        for rec in self.licenses.values():
            if rec["id"] == license_id or rec["key"] == license_id:
                return self._to_dto(rec)
        return None

    async def validate_license(
        self, license_key: str, fingerprint: Optional[str] = None
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

        now = datetime.now(timezone.utc)
        status = rec["status"]

        if rec["suspended"]:
            status = LicenseStatus.SUSPENDED
        elif rec["expires_at"] and now > rec["expires_at"]:
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
        now = datetime.now(timezone.utc)
        base_date = rec["expires_at"] if rec["expires_at"] and rec["expires_at"] > now else now
        rec["expires_at"] = base_date + timedelta(days=extend_days)
        rec["status"] = LicenseStatus.ACTIVE
        rec["suspended"] = False
        return self._to_dto(rec)

    async def extend_license(
        self, license_id: str, extend_days: int = 7
    ) -> LicenseDTO:
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
            raise ValueError(f"Cannot reinstate revoked license {license_id}: terminal state")
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
        dto = await self.get_license(license_key)
        if not dto:
            raise ValueError(f"License key {license_key} invalid in Keygate")
        rec = self.licenses[dto.license_id]
        dev_list = self.activations.setdefault(dto.license_id, [])

        for dev in dev_list:
            if dev["fingerprint"] == hardware.fingerprint:
                dev["last_heartbeat_at"] = datetime.now(timezone.utc)
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

        act_id = f"kg_act_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc)
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
        # Note: Keygate v0.1.3 has simpler exact fingerprint trial check (no fuzzy component matching)
        if hardware.fingerprint in self.trial_claims:
            raise ValueError(f"TRIAL_ALREADY_CLAIMED: Device {hardware.fingerprint} already claimed trial in Keygate")

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
        self.trial_claims[hardware.fingerprint] = {
            "account_id": account_id,
            "claimed_at": datetime.now(timezone.utc),
        }
        return self._to_dto(rec)

    async def issue_offline_entitlement(
        self, license_key: str, hardware: HardwareFingerprint, ttl_seconds: int = 86400 * 7
    ) -> SignedOfflineEntitlement:
        dto = await self.get_license(license_key)
        if not dto or dto.status not in [LicenseStatus.ACTIVE, LicenseStatus.TRIAL]:
            raise ValueError("Keygate cannot issue offline certificate for inactive license")

        now = datetime.now(timezone.utc)
        expires_at = min(now + timedelta(seconds=ttl_seconds), dto.expires_at or (now + timedelta(seconds=ttl_seconds)))

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
            device_limit=rec["device_limit"],
            devices_used=act_count,
            features=rec["features"],
            metadata=rec["metadata"],
        )
