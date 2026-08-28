"""
HTTP Keygen Provider Adapter.
Communicates with a real Keygen JSON:API server (keygen.sh / self-hosted keygen/api).
All I/O is via standard urllib so httpx is an optional enhancement (no new dep added).
"""
import json
import uuid
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


class _KeygenAPIError(Exception):
    def __init__(self, status: int, body: dict):
        self.status = status
        self.body = body
        super().__init__(f"Keygen API error {status}: {body}")


def _status_to_enum(s: str) -> LicenseStatus:
    mapping = {
        "ACTIVE": LicenseStatus.ACTIVE,
        "INACTIVE": LicenseStatus.EXPIRED,
        "EXPIRING_SOON": LicenseStatus.GRACE,
        "EXPIRED": LicenseStatus.EXPIRED,
        "SUSPENDED": LicenseStatus.SUSPENDED,
        "BANNED": LicenseStatus.REVOKED,
    }
    return mapping.get(s.upper(), LicenseStatus.EXPIRED)


class HttpKeygenProvider(ILicenseProvider):
    """
    Production HTTP adapter for a self-hosted Keygen JSON:API server.

    Config env vars (read at construction time):
      KEYGEN_BASE_URL   e.g. http://localhost:3000
      KEYGEN_ACCOUNT_ID Keygen account UUID
      KEYGEN_TOKEN      Admin / product token
      KEYGEN_POLICY_ID  Default policy UUID (maps to plan "pro_monthly")
    """

    def __init__(
        self,
        base_url: str,
        account_id: str,
        token: str,
        policy_map: Optional[Dict[str, str]] = None,
        crypto_engine: Optional[CryptoEngine] = None,
        timeout: int = 10,
        event_store: Optional[SqliteEventStore] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.account_id = account_id
        self.token = token
        self.policy_map: Dict[str, str] = policy_map or {}
        self.crypto = crypto_engine or CryptoEngine()
        self.timeout = timeout
        self.event_store = event_store or SqliteEventStore()

    # ------------------------------------------------------------------ helpers

    def _headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
            "Authorization": f"Bearer {self.token}",
        }

    def _url(self, path: str) -> str:
        return f"{self.base_url}/v1/accounts/{self.account_id}/{path.lstrip('/')}"

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
    ) -> dict:
        url = self._url(path)
        data = json.dumps(body).encode() if body else None
        req = urllib_request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            with urllib_request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as e:
            raw = e.read().decode()
            try:
                body_json = json.loads(raw)
            except Exception:
                body_json = {"raw": raw}
            raise _KeygenAPIError(e.code, body_json) from e
        except URLError as e:
            raise ConnectionError(f"Keygen unreachable: {e.reason}") from e

    def _license_body(self, attrs: dict) -> dict:
        return {"data": {"type": "licenses", "attributes": attrs}}

    def _license_rel_body(self, policy_id: str, attrs: dict) -> dict:
        return {
            "data": {
                "type": "licenses",
                "attributes": attrs,
                "relationships": {
                    "policy": {"data": {"type": "policies", "id": policy_id}}
                },
            }
        }

    def _parse_license(self, data: dict) -> LicenseDTO:
        attrs = data.get("attributes", {})
        meta = attrs.get("metadata") or {}
        raw_exp = attrs.get("expiry")
        expires_at = datetime.fromisoformat(raw_exp.rstrip("Z")) if raw_exp else None
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        created_raw = attrs.get("created")
        created_at = (
            datetime.fromisoformat(created_raw.rstrip("Z")).replace(tzinfo=timezone.utc)
            if created_raw
            else datetime.now(timezone.utc)
        )
        return LicenseDTO(
            license_id=data["id"],
            license_key=attrs.get("key", data["id"]),
            status=_status_to_enum(attrs.get("status", "ACTIVE")),
            plan=meta.get("plan", "pro_monthly"),
            customer_id=meta.get("customer_id", "unknown"),
            customer_email=meta.get("customer_email"),
            created_at=created_at,
            expires_at=expires_at,
            device_limit=attrs.get("maxMachines", 1),
            devices_used=attrs.get("machinesCount", 0),
            features=meta.get("features", ["core"]),
            metadata=meta,
        )

    def _parse_machine(self, data: dict, license_id: str) -> DeviceActivationDTO:
        attrs = data.get("attributes", {})
        raw_created = attrs.get("created")
        activated_at = (
            datetime.fromisoformat(raw_created.rstrip("Z")).replace(tzinfo=timezone.utc)
            if raw_created
            else datetime.now(timezone.utc)
        )
        raw_hb = attrs.get("lastHeartbeat")
        last_hb = (
            datetime.fromisoformat(raw_hb.rstrip("Z")).replace(tzinfo=timezone.utc)
            if raw_hb
            else None
        )
        return DeviceActivationDTO(
            activation_id=data["id"],
            license_id=license_id,
            fingerprint=attrs.get("fingerprint", ""),
            name=attrs.get("name"),
            activated_at=activated_at,
            last_heartbeat_at=last_hb,
            components=attrs.get("metadata", {}).get("components", {}),
        )

    def _resolve_policy(self, plan: str) -> Optional[str]:
        return self.policy_map.get(plan)

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
        policy_id = self._resolve_policy(plan)
        attrs = {
            "maxMachines": device_limit,
            "metadata": {
                "plan": plan,
                "customer_id": customer_id,
                "customer_email": customer_email,
                "features": features or ["core"],
                **(metadata or {}),
            },
        }
        if duration_days > 0:
            expires = datetime.now(timezone.utc) + timedelta(days=duration_days)
            attrs["expiry"] = expires.isoformat()

        if policy_id:
            body = self._license_rel_body(policy_id, attrs)
        else:
            body = self._license_body(attrs)

        resp = self._request("POST", "licenses", body)
        return self._parse_license(resp["data"])

    async def get_license(self, license_id: str) -> Optional[LicenseDTO]:
        try:
            resp = self._request("GET", f"licenses/{license_id}")
            return self._parse_license(resp["data"])
        except _KeygenAPIError as e:
            if e.status == 404:
                return None
            raise

    async def validate_license(
        self, license_key: str, fingerprint: Optional[str] = None
    ) -> EntitlementValidationResult:
        body: dict = {"meta": {"key": license_key}}
        if fingerprint:
            body["meta"]["fingerprint"] = fingerprint
        try:
            resp = self._request("POST", "licenses/actions/validate-key", body)
        except _KeygenAPIError as e:
            return EntitlementValidationResult(
                valid=False,
                status=LicenseStatus.EXPIRED,
                can_start_runner=False,
                code="API_ERROR",
                message=str(e),
            )

        meta = resp.get("meta", {})
        valid = meta.get("valid", False)
        code = meta.get("code", "UNKNOWN")
        status_str = meta.get("detail", "")
        data = resp.get("data") or {}
        attrs = data.get("attributes", {}) if data else {}
        raw_status = attrs.get("status", "EXPIRED")
        status = _status_to_enum(raw_status)
        can_start = valid and status in (LicenseStatus.ACTIVE, LicenseStatus.GRACE, LicenseStatus.TRIAL)
        license_dto = self._parse_license(data) if data else None
        return EntitlementValidationResult(
            valid=valid,
            status=status,
            can_start_runner=can_start,
            license=license_dto,
            code=code,
            message=status_str or f"Status: {raw_status}",
        )

    async def renew_license(self, license_id: str, extend_days: int = 30) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        if dto.status == LicenseStatus.REVOKED:
            raise ValueError(f"Cannot renew revoked license {license_id}: terminal state")
        now = datetime.now(timezone.utc)
        base = dto.expires_at if dto.expires_at and dto.expires_at > now else now
        new_expiry = base + timedelta(days=extend_days)
        body = {"data": {"type": "licenses", "attributes": {"expiry": new_expiry.isoformat()}}}
        resp = self._request("PATCH", f"licenses/{license_id}", body)
        # Also reinstate if suspended
        patched = self._parse_license(resp["data"])
        if patched.status == LicenseStatus.SUSPENDED:
            self._request("POST", f"licenses/{license_id}/actions/reinstate", {})
        return patched

    async def extend_license(self, license_id: str, extend_days: int = 7) -> LicenseDTO:
        return await self.renew_license(license_id, extend_days=extend_days)

    async def suspend_license(self, license_id: str, reason: str = "administrative_suspension") -> LicenseDTO:
        self._request("POST", f"licenses/{license_id}/actions/suspend", {})
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found after suspend")
        return dto

    async def reinstate_license(self, license_id: str) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        if dto.status == LicenseStatus.REVOKED:
            raise ValueError(f"Cannot reinstate revoked license {license_id}: terminal state")
        self._request("POST", f"licenses/{license_id}/actions/reinstate", {})
        return await self.get_license(license_id)  # type: ignore[return-value]

    async def revoke_license(self, license_id: str, reason: str = "refunded_or_terminated") -> LicenseDTO:
        # Fetch before deletion since DELETE returns 204
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        self._request("DELETE", f"licenses/{license_id}")
        # Return a DTO marked REVOKED; the record no longer exists upstream
        import dataclasses  # noqa: local import
        return dto.model_copy(update={"status": LicenseStatus.REVOKED, "metadata": {**dto.metadata, "revoke_reason": reason}})

    async def activate_device(
        self, license_key: str, hardware: HardwareFingerprint
    ) -> DeviceActivationDTO:
        # Resolve license id from key first
        dto = await self.validate_license(license_key)
        if not dto.license:
            raise ValueError(f"License key {license_key} invalid or not found")
        license_id = dto.license.license_id

        # Idempotency: check if machine already activated
        body = {
            "data": {
                "type": "machines",
                "attributes": {
                    "fingerprint": hardware.fingerprint,
                    "name": hardware.hostname or "primary_device",
                    "platform": hardware.platform,
                    "metadata": {"components": hardware.components},
                },
                "relationships": {
                    "license": {"data": {"type": "licenses", "id": license_id}}
                },
            }
        }
        try:
            resp = self._request("POST", "machines", body)
            return self._parse_machine(resp["data"], license_id)
        except _KeygenAPIError as e:
            errors = e.body.get("errors", [{}])
            code = (errors[0].get("code") or "") if errors else ""
            if code == "MACHINE_FINGERPRINT_TAKEN":
                # Already activated — fetch and return idempotently
                machines_resp = self._request(
                    "GET",
                    f"machines?filter[fingerprint]={hardware.fingerprint}&filter[license]={license_id}",
                )
                candidates = machines_resp.get("data", [])
                if candidates:
                    return self._parse_machine(candidates[0], license_id)
            if code == "MACHINE_LIMIT_EXCEEDED":
                raise ValueError(f"DEVICE_LIMIT_EXCEEDED: Keygen machine limit reached") from e
            raise

    async def deactivate_device(self, license_key: str, fingerprint: str) -> bool:
        dto = await self.validate_license(license_key)
        if not dto.license:
            return False
        license_id = dto.license.license_id
        machines_resp = self._request(
            "GET",
            f"machines?filter[fingerprint]={fingerprint}&filter[license]={license_id}",
        )
        candidates = machines_resp.get("data", [])
        for machine in candidates:
            self._request("DELETE", f"machines/{machine['id']}")
        return len(candidates) > 0

    async def get_devices(self, license_id: str) -> List[DeviceActivationDTO]:
        resp = self._request("GET", f"licenses/{license_id}/machines")
        return [self._parse_machine(m, license_id) for m in resp.get("data", [])]

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
                raise ValueError(f"TRIAL_ALREADY_CLAIMED: Device {hardware.fingerprint} has already claimed a trial")
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
            features=["core", "trial_tier"],
            metadata={"is_trial": True, "trial_account": account_id},
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
        dto = await self.validate_license(license_key, fingerprint=hardware.fingerprint)
        if not dto.can_start_runner or not dto.license:
            raise ValueError("Cannot issue offline certificate for inactive or invalid license")
        lic = dto.license
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
        is_valid, data, reason = self.crypto.verify_payload(entitlement.certificate, entitlement.signature)
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
                message="Offline entitlement fingerprint mismatch",
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
                message="Offline certificate TTL expired; reconnect required",
            )
        return EntitlementValidationResult(
            valid=True,
            status=LicenseStatus.ACTIVE,
            can_start_runner=True,
            code="OK",
            message="Offline entitlement verified",
        )
