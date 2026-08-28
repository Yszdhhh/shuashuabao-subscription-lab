"""
HTTP Keygate Provider Adapter.
Communicates with a real Keygate self-hosted REST server.
Uses stdlib urllib only (no httpx dependency).
"""
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
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
from bridge.app.services.event_processor import SqliteEventStore
from bridge.app.providers.base import ILicenseProvider


class _KeygateAPIError(Exception):
    def __init__(self, status: int, body: dict):
        self.status = status
        self.body = body
        super().__init__(f"Keygate API error {status}: {body}")


def _kg_status(s: str) -> LicenseStatus:
    return {
        "active": LicenseStatus.ACTIVE,
        "trial": LicenseStatus.TRIAL,
        "grace": LicenseStatus.GRACE,
        "past_due": LicenseStatus.PAST_DUE,
        "suspended": LicenseStatus.SUSPENDED,
        "expired": LicenseStatus.EXPIRED,
        "revoked": LicenseStatus.REVOKED,
        "canceled": LicenseStatus.EXPIRED,
    }.get(s.lower(), LicenseStatus.EXPIRED)


class HttpKeygateProvider(ILicenseProvider):
    """
    Production HTTP adapter for a self-hosted Keygate REST server.

    Config env vars (read at construction time):
      KEYGATE_BASE_URL  e.g. http://localhost:8080
      KEYGATE_TOKEN     API bearer token
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        crypto_engine: Optional[CryptoEngine] = None,
        timeout: int = 10,
        event_store: Optional[SqliteEventStore] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.crypto = crypto_engine or CryptoEngine()
        self.timeout = timeout
        self.event_store = event_store or SqliteEventStore()

    # ------------------------------------------------------------------ helpers

    def _headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}",
        }

    def _url(self, path: str) -> str:
        return f"{self.base_url}/api/{path.lstrip('/')}"

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        url = self._url(path)
        data = json.dumps(body).encode() if body else None
        req = urllib_request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            with urllib_request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw.strip() else {}
        except HTTPError as e:
            raw = e.read().decode()
            try:
                body_json = json.loads(raw)
            except Exception:
                body_json = {"raw": raw}
            raise _KeygateAPIError(e.code, body_json) from e
        except URLError as e:
            raise ConnectionError(f"Keygate unreachable: {e.reason}") from e

    def _parse_license(self, data: dict) -> LicenseDTO:
        raw_exp = data.get("expires_at") or data.get("expiry")
        expires_at = None
        if raw_exp:
            expires_at = datetime.fromisoformat(raw_exp.rstrip("Z")).replace(tzinfo=timezone.utc)
        raw_created = data.get("created_at") or data.get("created")
        created_at = (
            datetime.fromisoformat(raw_created.rstrip("Z")).replace(tzinfo=timezone.utc)
            if raw_created
            else datetime.now(timezone.utc)
        )
        return LicenseDTO(
            license_id=str(data.get("id", data.get("license_id", ""))),
            license_key=data.get("key", data.get("license_key", "")),
            status=_kg_status(data.get("status", "active")),
            plan=data.get("plan", "pro_monthly"),
            customer_id=str(data.get("customer_id", data.get("user_id", "unknown"))),
            customer_email=data.get("customer_email") or data.get("email"),
            created_at=created_at,
            expires_at=expires_at,
            device_limit=data.get("device_limit", data.get("max_machines", 1)),
            devices_used=data.get("devices_used", data.get("machines_count", 0)),
            features=data.get("features", ["core"]),
            metadata=data.get("metadata") or {},
        )

    def _parse_machine(self, data: dict, license_id: str) -> DeviceActivationDTO:
        raw_created = data.get("activated_at") or data.get("created_at")
        activated_at = (
            datetime.fromisoformat(raw_created.rstrip("Z")).replace(tzinfo=timezone.utc)
            if raw_created
            else datetime.now(timezone.utc)
        )
        raw_hb = data.get("last_heartbeat_at") or data.get("last_heartbeat")
        last_hb = (
            datetime.fromisoformat(raw_hb.rstrip("Z")).replace(tzinfo=timezone.utc)
            if raw_hb
            else None
        )
        return DeviceActivationDTO(
            activation_id=str(data.get("id", data.get("activation_id", ""))),
            license_id=license_id,
            fingerprint=data.get("fingerprint", ""),
            name=data.get("name") or data.get("hostname"),
            activated_at=activated_at,
            last_heartbeat_at=last_hb,
            components=data.get("components") or {},
        )

    # ------------------------------------------------------------------ ILicenseProvider

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
        body: dict = {
            "customer_id": customer_id,
            "customer_email": customer_email,
            "plan": plan,
            "device_limit": device_limit,
            "features": features or ["core"],
            "metadata": metadata or {},
        }
        if duration_days > 0:
            body["expires_at"] = (
                datetime.now(timezone.utc) + timedelta(days=duration_days)
            ).isoformat()
        resp = self._request("POST", "licenses", body)
        return self._parse_license(resp)

    async def get_license(self, license_id: str) -> Optional[LicenseDTO]:
        try:
            resp = self._request("GET", f"licenses/{license_id}")
            return self._parse_license(resp)
        except _KeygateAPIError as e:
            if e.status == 404:
                return None
            raise

    async def validate_license(
        self, license_key: str, fingerprint: Optional[str] = None
    ) -> EntitlementValidationResult:
        body: dict = {"key": license_key}
        if fingerprint:
            body["fingerprint"] = fingerprint
        try:
            resp = self._request("POST", "licenses/validate", body)
        except _KeygateAPIError as e:
            return EntitlementValidationResult(
                valid=False,
                status=LicenseStatus.EXPIRED,
                can_start_runner=False,
                code="API_ERROR",
                message=str(e),
            )
        valid = resp.get("valid", False)
        code = resp.get("code", "UNKNOWN")
        lic_data = resp.get("license")
        status = _kg_status(lic_data.get("status", "expired")) if lic_data else LicenseStatus.EXPIRED
        can_start = valid and status in (LicenseStatus.ACTIVE, LicenseStatus.GRACE, LicenseStatus.TRIAL)
        return EntitlementValidationResult(
            valid=valid,
            status=status,
            can_start_runner=can_start,
            license=self._parse_license(lic_data) if lic_data else None,
            code=code,
            message=resp.get("message", f"Status: {status.value}"),
        )

    async def renew_license(self, license_id: str, extend_days: int = 30) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found in Keygate")
        if dto.status == LicenseStatus.REVOKED:
            raise ValueError(f"Cannot renew revoked license {license_id}: terminal state")
        now = datetime.now(timezone.utc)
        base = dto.expires_at if dto.expires_at and dto.expires_at > now else now
        new_expiry = (base + timedelta(days=extend_days)).isoformat()
        resp = self._request("PATCH", f"licenses/{license_id}", {"expires_at": new_expiry, "status": "active"})
        return self._parse_license(resp)

    async def extend_license(self, license_id: str, extend_days: int = 7) -> LicenseDTO:
        return await self.renew_license(license_id, extend_days=extend_days)

    async def suspend_license(self, license_id: str, reason: str = "administrative_suspension") -> LicenseDTO:
        resp = self._request("POST", f"licenses/{license_id}/suspend", {"reason": reason})
        lic_data = resp.get("license") or resp
        return self._parse_license(lic_data)

    async def reinstate_license(self, license_id: str) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found in Keygate")
        if dto.status == LicenseStatus.REVOKED:
            raise ValueError(f"Cannot reinstate revoked license {license_id}: terminal state")
        resp = self._request("POST", f"licenses/{license_id}/reinstate", {})
        lic_data = resp.get("license") or resp
        return self._parse_license(lic_data)

    async def revoke_license(self, license_id: str, reason: str = "refunded_or_terminated") -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found in Keygate")
        self._request("DELETE", f"licenses/{license_id}")
        return dto.model_copy(update={"status": LicenseStatus.REVOKED, "metadata": {**dto.metadata, "revoke_reason": reason}})

    async def activate_device(
        self, license_key: str, hardware: HardwareFingerprint
    ) -> DeviceActivationDTO:
        val = await self.validate_license(license_key)
        if not val.license:
            raise ValueError(f"License key {license_key} invalid or not found")
        license_id = val.license.license_id
        body = {
            "license_id": license_id,
            "fingerprint": hardware.fingerprint,
            "name": hardware.hostname or "primary_device",
            "platform": hardware.platform,
            "components": hardware.components,
        }
        try:
            resp = self._request("POST", "machines", body)
            machine_data = resp.get("machine") or resp
            return self._parse_machine(machine_data, license_id)
        except _KeygateAPIError as e:
            code = (e.body.get("code") or e.body.get("error") or "")
            if "duplicate" in str(code).lower() or "already" in str(code).lower() or e.status == 409:
                # Idempotent: find existing machine
                machines = self._request("GET", f"licenses/{license_id}/machines")
                for m in machines.get("machines", machines.get("data", [])):
                    if m.get("fingerprint") == hardware.fingerprint:
                        return self._parse_machine(m, license_id)
            if "limit" in str(code).lower() or e.status == 422:
                raise ValueError("DEVICE_LIMIT_EXCEEDED: Keygate device limit reached") from e
            raise

    async def deactivate_device(self, license_key: str, fingerprint: str) -> bool:
        val = await self.validate_license(license_key)
        if not val.license:
            return False
        license_id = val.license.license_id
        machines = self._request("GET", f"licenses/{license_id}/machines")
        removed = 0
        for m in machines.get("machines", machines.get("data", [])):
            if m.get("fingerprint") == fingerprint:
                mid = m.get("id") or m.get("activation_id")
                self._request("DELETE", f"machines/{mid}")
                removed += 1
        return removed > 0

    async def get_devices(self, license_id: str) -> List[DeviceActivationDTO]:
        resp = self._request("GET", f"licenses/{license_id}/machines")
        items = resp.get("machines", resp.get("data", []))
        return [self._parse_machine(m, license_id) for m in items]

    async def claim_trial(
        self,
        account_id: str,
        email: str,
        hardware: HardwareFingerprint,
        trial_days: int = 7,
    ) -> LicenseDTO:
        if self.event_store.has_trial_account(account_id):
            raise ValueError(f"TRIAL_ALREADY_CLAIMED: Account {account_id} has already claimed a trial")
        for fingerprint, components in self.event_store.trial_devices():
            if fingerprint == hardware.fingerprint:
                raise ValueError(f"TRIAL_ALREADY_CLAIMED: Device {hardware.fingerprint} already claimed a trial")
            if components and hardware.components:
                is_match, matched, total, _ = FingerprintMatcher.match_components(
                    components, hardware.components, strategy="MATCH_MOST"
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
        await self.activate_device(lic.license_key, hardware)
        if not self.event_store.record_trial_claim(
            account_id, hardware.fingerprint, hardware.components
        ):
            raise ValueError(f"TRIAL_ALREADY_CLAIMED: Account {account_id} or device already claimed a trial")
        return lic

    async def issue_offline_entitlement(
        self, license_key: str, hardware: HardwareFingerprint, ttl_seconds: int = 86400 * 7
    ) -> SignedOfflineEntitlement:
        val = await self.validate_license(license_key, fingerprint=hardware.fingerprint)
        if not val.can_start_runner or not val.license:
            raise ValueError("Cannot issue offline certificate for inactive or invalid license")
        lic = val.license
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=48)
        if lic.expires_at:
            expires_at = min(expires_at, lic.expires_at)
        payload = {
            "license_id": lic.license_id,
            "fingerprint": hardware.fingerprint,
            "plan": lic.plan,
            "features": lic.features,
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
            license_id=lic.license_id,
            fingerprint=hardware.fingerprint,
            plan=lic.plan,
            features=lic.features,
        )

    async def verify_offline_entitlement(
        self, entitlement: SignedOfflineEntitlement, current_hardware: HardwareFingerprint
    ) -> EntitlementValidationResult:
        is_valid, data, reason = self.crypto.verify_payload(
            entitlement.certificate, entitlement.signature
        )
        if not is_valid:
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
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
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
