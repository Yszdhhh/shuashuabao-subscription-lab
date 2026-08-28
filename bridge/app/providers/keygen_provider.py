"""
Keygen License Authority Provider Adapter.
Implements ILicenseProvider using Keygen API conventions (JSON:API 1.0 format,
Policy, Machine activation, Component checking, and Cryptographic Offline Signing).
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
from bridge.app.core.fingerprint import FingerprintMatcher
from bridge.app.providers.base import ILicenseProvider


class KeygenProvider(ILicenseProvider):
    def __init__(self, crypto_engine: Optional[CryptoEngine] = None):
        self.crypto = crypto_engine or CryptoEngine()
        # In-memory backing store for stateful integration harness & standalone testing
        self.licenses: Dict[str, dict] = {}
        self.activations: Dict[str, List[dict]] = {}
        self.trial_claims: Dict[str, dict] = {} # fingerprint/components -> trial metadata

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
                message="License key does not exist",
            )

        now = datetime.now(timezone.utc)
        status = rec["status"]

        if rec["suspended"]:
            status = LicenseStatus.SUSPENDED
        elif rec["expires_at"] and now > rec["expires_at"]:
            # Check grace period (3 days grace default)
            grace_expiry = rec["expires_at"] + timedelta(days=3)
            if now <= grace_expiry:
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
            raise ValueError(f"License {license_id} not found")
        rec = self.licenses[dto.license_id]
        rec["suspended"] = True
        rec["status"] = LicenseStatus.SUSPENDED
        rec["metadata"]["suspend_reason"] = reason
        return self._to_dto(rec)

    async def reinstate_license(self, license_id: str) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        rec = self.licenses[dto.license_id]
        rec["suspended"] = False
        rec["status"] = LicenseStatus.ACTIVE
        return self._to_dto(rec)

    async def revoke_license(
        self, license_id: str, reason: str = "refunded_or_terminated"
    ) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        rec = self.licenses[dto.license_id]
        rec["status"] = LicenseStatus.REVOKED
        rec["metadata"]["revoke_reason"] = reason
        return self._to_dto(rec)

    async def activate_device(
        self, license_key: str, hardware: HardwareFingerprint
    ) -> DeviceActivationDTO:
        dto = await self.get_license(license_key)
        if not dto:
            raise ValueError(f"License key {license_key} invalid")
        rec = self.licenses[dto.license_id]
        dev_list = self.activations.setdefault(dto.license_id, [])

        # Check idempotent reactivation of same machine
        for dev in dev_list:
            if dev["fingerprint"] == hardware.fingerprint:
                dev["last_heartbeat_at"] = datetime.now(timezone.utc)
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

        act_id = f"act_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc)
        act_record = {
            "id": act_id,
            "fingerprint": hardware.fingerprint,
            "name": hardware.hostname or "primary_device",
            "activated_at": now,
            "last_heartbeat_at": now,
            "components": hardware.components,
        }
        dev_list.append(act_record)
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
        # Check trial anti-abuse: Unique per device and component matching
        if hardware.fingerprint in self.trial_claims:
            raise ValueError(f"TRIAL_ALREADY_CLAIMED: Device {hardware.fingerprint} has already claimed a trial")

        # Component partial match against existing trial records
        for prior_fp, prior_data in self.trial_claims.items():
            is_match, matched, total, _ = FingerprintMatcher.match_components(
                prior_data.get("components", {}), hardware.components, strategy="MATCH_MOST"
            )
            if is_match and total > 0:
                raise ValueError(f"TRIAL_ABUSE_DETECTED: Hardware components match existing trial ({matched}/{total} components matched)")

        lic = await self.create_license(
            customer_id=account_id,
            customer_email=email,
            plan="trial_7d",
            duration_days=trial_days,
            device_limit=1,
            features=["core", "trial_tier"],
            metadata={"is_trial": True, "trial_account": account_id},
        )
        # Mark trial status
        rec = self.licenses[lic.license_id]
        rec["status"] = LicenseStatus.TRIAL

        # Automatically activate trial device
        await self.activate_device(lic.license_key, hardware)

        # Register trial claim record
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

        # Verify device fingerprint match
        if data.get("fingerprint") != current_hardware.fingerprint:
            return EntitlementValidationResult(
                valid=False,
                status=LicenseStatus.REVOKED,
                can_start_runner=False,
                code="FINGERPRINT_MISMATCH",
                message="Offline entitlement was signed for a different hardware fingerprint",
            )

        # Verify offline TTL expiration
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
