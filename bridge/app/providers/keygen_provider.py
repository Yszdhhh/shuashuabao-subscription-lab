"""
Keygen License Authority Provider Adapter.
Implements ILicenseProvider using Keygen API conventions (JSON:API 1.0 format,
Policy, Machine activation, Component checking, and Cryptographic Offline Signing).
"""
import uuid
import threading
from copy import deepcopy
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
from bridge.app.services.event_processor import SqliteEventStore
from bridge.app.providers.base import ILicenseProvider
from bridge.app.services import tiers as _tiers
from bridge.app.services.current_license import select_current
import logging as _logging
logger = _logging.getLogger("shuabao.keygen_provider")

# ---------------------------------------------------------------------------------------------
# BATCH A (entitlement_fix_20261018 r3): minimal legacy-compatible persistence fix on 694e3c2.
# No schema change, no pepper, no new protocol; plaintext card keys stay as they are (scrub = B).
#   A1 renew / extend / suspend / reinstate / revoke are PERSISTED, persist-then-apply: the new
#      record is written to SQLite first and only then copied into memory, so a failed write
#      never leaves memory ahead of the DB (single asyncio loop, no await inside the section).
#   A2 revoked / suspended / expired-beyond-grace licenses cannot bind a device (checked BEFORE
#      any binding is created).
#   A3 REVOKED is terminal in validate (never reported as GRACE).
#   A4 errors never echo the submitted card key.
# ---------------------------------------------------------------------------------------------


# WEEKEND EVENT (2026-10-17~10-18): allow an expired self-service device trial
# to be renewed once by re-claiming (+24h). Window closes automatically at
# 2026-10-18 23:59 CST (= 2026-10-18 15:59 UTC). REVERT for the official
# release: delete this constant + the event block in claim_device_trial.
TRIAL_RECLAIM_EVENT_END_UTC = datetime(2026, 10, 18, 15, 59, tzinfo=timezone.utc)

# Clients select the execution target; only server-held entitlements authorize it.
RUN_SCOPE_FEATURES = {"core": ["core"], "pip_background": ["core", "pip_background"]}


def _operation_id(value: Optional[str]) -> str:
    if value is not None and not isinstance(value, str):
        raise ValueError("INVALID_OPERATION_ID")
    return (value or "").strip() or uuid.uuid4().hex


def _utc_datetime(value: datetime | str) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


DEFAULT_GRACE_DAYS = 0


def _grace_days(rec: dict) -> int:
    """Grace after expiry. Missing/garbled metadata fails closed (0 = hard expiry)."""
    raw = (rec.get("metadata") or {}).get("grace_days")
    if raw is None:
        return DEFAULT_GRACE_DAYS
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return DEFAULT_GRACE_DAYS


class InMemoryKeygenProvider(ILicenseProvider):
    def __init__(
        self,
        crypto_engine: Optional[CryptoEngine] = None,
        event_store: Optional[SqliteEventStore] = None,
    ):
        self.crypto = crypto_engine or CryptoEngine()
        self.event_store = event_store or SqliteEventStore()
        self.licenses: Dict[str, dict] = getattr(self.event_store, "load_local_licenses", lambda: {})()
        self.activations: Dict[str, List[dict]] = getattr(self.event_store, "load_local_activations", lambda: {})()
        self.trial_claims: Dict[str, dict] = {
            fp: {"components": components} for fp, components in self.event_store.trial_devices()
        }
        self.trial_accounts: set = self.event_store.trial_accounts()
        self._claim_sync_lock = threading.Lock()
        self._claim_sync_pending: dict = {}
        self._claim_sync_worker = None

    async def create_license(
        self,
        customer_id: str,
        customer_email: str,
        plan: str,
        duration_days: int = 30,
        device_limit: int = 1,
        features: Optional[List[str]] = None,
        metadata: Optional[Dict] = None,
        tier: Optional[str] = None,
        expires_at_override: Optional[datetime] = None,
        operation_id: Optional[str] = None,
        audit: Optional[dict] = None,
    ) -> LicenseDTO:
        if tier is not None and not _tiers.is_tier(tier):
            raise ValueError(f"INVALID_TIER: unknown tier {tier!r}")
        operation_id = _operation_id(operation_id)
        request = {"action": "create_license", "customer_id": customer_id,
                   "customer_email": customer_email, "plan": plan, "duration_days": duration_days,
                   "device_limit": device_limit, "features": features, "metadata": metadata,
                   "tier": tier, "expires_at_override": expires_at_override.isoformat() if expires_at_override else None}
        prior = self.event_store.get_entitlement_operation(operation_id, request)
        if prior is not None:
            return LicenseDTO.model_validate(prior)
        lic_id = f"lic_{uuid.uuid4().hex[:12]}"
        lic_key = f"SSB-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"
        now = datetime.now(timezone.utc)
        meta = dict(metadata or {})
        meta.setdefault("grace_days", DEFAULT_GRACE_DAYS)
        starts_on_first = bool(meta.get("starts_on_first_activation"))
        if tier == "ultra":
            # BATCH C lifetime policy: fixed expiry, never first-activation based.
            starts_on_first = False
            meta.pop("starts_on_first_activation", None)
            meta.pop("activation_ttl_days", None)
            expires_at = _tiers.LIFETIME_EXPIRES_AT
        elif expires_at_override is not None:
            # r7 ruling 3: explicit expires_at wins over first-activation start.
            starts_on_first = False
            meta.pop("starts_on_first_activation", None)
            meta.pop("activation_ttl_days", None)
            meta["expires_at_override"] = True
            expires_at = expires_at_override.astimezone(timezone.utc)
        elif starts_on_first:
            expires_at = None
            if meta.get("activation_ttl_days") in (None, ""):
                meta["activation_ttl_days"] = duration_days
            else:
                meta["activation_ttl_days"] = int(meta["activation_ttl_days"])
        else:
            expires_at = now + timedelta(days=duration_days) if duration_days > 0 else None

        feature_list = _tiers.license_features({"plan": plan, "tier": tier, "metadata": meta,
                                               "features": features or ["core", "automation"]})
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
            "features": feature_list,
            "metadata": meta,
            "suspended": False,
        }
        if tier is not None:
            record["tier"] = tier
            record["tier_name"] = _tiers.tier_name(tier)
        result = self._to_dto(record).model_dump(mode="json")
        event = {**(audit or {}), "action": "issue_ultra" if tier == "ultra" else (
                     "issue_pip_background" if "pip_background" in feature_list else "create_license"),
                 "license_id": lic_id, "plan": plan, "tier": tier, "features": feature_list,
                 "license_key_masked": f"{lic_key[:4]}…{lic_key[-4:]}",
                 "pip_background": "pip_background" in feature_list,
                 "expires_at": expires_at, "issued_by": meta.get("issued_by"), "customer_id": customer_id}
        result, applied = self.event_store.commit_entitlement_operation(
            operation_id, request, record, result, event,
        )
        if applied:
            self.licenses[lic_id] = record
            self.activations.setdefault(lic_id, [])
        return LicenseDTO.model_validate(result)

    async def get_license(self, license_id: str) -> Optional[LicenseDTO]:
        for rec in self.licenses.values():
            if rec["id"] == license_id or rec["key"] == license_id:
                return self._to_dto(rec)
        return None

    async def list_licenses(self, limit: int = 100) -> List[LicenseDTO]:
        """Return the newest licenses for the local management dashboard."""
        size = max(1, min(int(limit), 100))
        ordered = sorted(self.licenses.values(), key=lambda r: r["created_at"], reverse=True)
        return [self._to_dto(r) for r in ordered[:size]]

    async def set_device_limit(self, license_id: str, device_limit: int) -> LicenseDTO:
        """Admin: change bindable device count. Does not touch run leases or running scripts."""
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        rec = self.licenses[dto.license_id]
        if rec["status"] == LicenseStatus.REVOKED:
            raise ValueError("Cannot modify revoked license: terminal state")
        limit = max(1, min(int(device_limit), 10))
        rec["device_limit"] = limit
        if hasattr(self.event_store, "save_local_license"):
            self.event_store.save_local_license(rec["id"], rec["key"], rec)
        return self._to_dto(rec)

    async def set_license_features(self, license_id: str, features: List[str], *,
                                   operation_id: Optional[str] = None,
                                   audit: Optional[dict] = None) -> LicenseDTO:
        """Admin: persist an explicitly approved feature change."""
        operation_id = _operation_id(operation_id)
        request = {"action": "set_license_features", "license_id": license_id,
                   "features": sorted(set(features))}
        if audit and audit.get("action") == "update_pip_background":
            request = {"action": "update_pip_background", "license_id": license_id,
                       "enabled": audit["enabled"]}
        prior = self.event_store.get_entitlement_operation(operation_id, request)
        if prior is not None:
            return LicenseDTO.model_validate(prior)
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        rec = deepcopy(self.licenses[dto.license_id])
        if rec["status"] == LicenseStatus.REVOKED:
            raise ValueError("Cannot modify revoked license: terminal state")
        if _tiers.has_default_pip_background(rec) and "pip_background" not in features:
            raise ValueError("Internal test and beta licenses must retain pip_background")
        if _tiers.is_regular_trial_record(rec) and "pip_background" in features:
            raise ValueError("Regular trial licenses cannot receive pip_background")
        rec["features"] = list(dict.fromkeys(features))
        result = self._to_dto(rec).model_dump(mode="json")
        event = {**(audit or {}), "action": "update_license_features", "license_id": rec["id"],
                 "before_features": dto.features, "features": rec["features"]}
        if audit:
            event["action"] = audit.get("action", event["action"])
        result, applied = self.event_store.commit_entitlement_operation(
            operation_id, request, rec, result, event,
        )
        if applied:
            self.licenses[rec["id"]] = rec
        return LicenseDTO.model_validate(result)

    # ---- run lease: one active run per license; kick only on acquire ----

    def _check_run_entitlement(self, dto: LicenseDTO, fingerprint: str,
                               required_features: List[str], now: datetime) -> Optional[datetime]:
        rec = self.licenses[dto.license_id]
        if dto.status not in (LicenseStatus.ACTIVE, LicenseStatus.TRIAL, LicenseStatus.GRACE) or rec.get("suspended"):
            raise ValueError("LICENSE_NOT_ACTIVE")
        expiry = _utc_datetime(dto.expires_at) if dto.expires_at is not None else None
        if expiry is not None and expiry <= now:
            raise ValueError("LICENSE_EXPIRED")
        if not any(d["fingerprint"] == fingerprint for d in self.activations.get(dto.license_id, [])):
            raise ValueError("DEVICE_NOT_ACTIVATED")
        if not set(required_features).issubset(dto.features):
            raise ValueError("FEATURE_NOT_ENTITLED")
        return expiry

    async def acquire_run_lease(
        self, license_key: str, fingerprint: str, ttl_seconds: int = 300, *, scope: str = "core"
    ) -> dict:
        """Start-run exclusive lease. Binding/activating devices never calls this."""
        dto = await self.get_license(license_key)
        if not dto:
            raise ValueError("LICENSE_NOT_FOUND: license key not recognised")
        if scope not in RUN_SCOPE_FEATURES:
            raise ValueError("INVALID_RUN_SCOPE")
        required_features = list(RUN_SCOPE_FEATURES[scope])
        store = self.event_store
        if not hasattr(store, "save_run_lease"):
            raise ValueError("RUN_LEASE_UNSUPPORTED")
        now = datetime.now(timezone.utc)
        license_expiry = self._check_run_entitlement(dto, fingerprint, required_features, now)
        now_s = now.isoformat()
        expires = now + timedelta(seconds=min(600, max(60, int(ttl_seconds))))
        if license_expiry is not None:
            expires = min(expires, license_expiry)
        prior = store.get_run_lease(dto.license_id)
        kicked_fp = None
        prev_id = None
        if prior and prior.get("lease_id"):
            prev_id = prior["lease_id"]
            if prior.get("fingerprint") and prior["fingerprint"] != fingerprint:
                kicked_fp = prior["fingerprint"]
        lease_id = f"lease_{uuid.uuid4().hex[:12]}"
        store.save_run_lease(
            license_id=dto.license_id,
            fingerprint=fingerprint,
            lease_id=lease_id,
            obtained_at=now_s,
            heartbeat_at=now_s,
            expires_at=expires.isoformat(),
            previous_lease_id=prev_id,
            kicked_fingerprint=kicked_fp,
            required_features=required_features,
            scope=scope,
        )
        return {
            "lease_id": lease_id,
            "license_id": dto.license_id,
            "fingerprint": fingerprint,
            "obtained_at": now_s,
            "expires_at": expires.isoformat(),
            "required_features": required_features,
            "scope": scope,
            "kicked": (
                {"fingerprint": kicked_fp, "kicked_at": now_s} if kicked_fp else None
            ),
        }

    async def heartbeat_run_lease(self, lease_id: str, fingerprint: str, ttl_seconds: int = 300) -> dict:
        store = self.event_store
        if not hasattr(store, "get_run_lease_by_id"):
            raise ValueError("RUN_LEASE_UNSUPPORTED")
        row = store.get_run_lease_by_id(lease_id)
        if not row or row.get("fingerprint") != fingerprint:
            raise PermissionError("LEASE_REVOKED")
        now = datetime.now(timezone.utc)
        dto = await self.get_license(row["license_id"])
        if (dto is None or row["scope"] not in RUN_SCOPE_FEATURES
                or row["required_features"] != RUN_SCOPE_FEATURES[row["scope"]]):
            raise PermissionError("LEASE_REVOKED")
        try:
            if _utc_datetime(row["expires_at"]) <= now:
                raise ValueError("LEASE_EXPIRED")
            license_expiry = self._check_run_entitlement(dto, fingerprint, row["required_features"], now)
        except ValueError as exc:
            raise PermissionError("LEASE_REVOKED") from exc
        expires = now + timedelta(seconds=min(600, max(60, int(ttl_seconds))))
        if license_expiry is not None:
            expires = min(expires, license_expiry)
        store.save_run_lease(
            license_id=row["license_id"],
            fingerprint=fingerprint,
            lease_id=lease_id,
            obtained_at=row["obtained_at"],
            heartbeat_at=now.isoformat(),
            expires_at=expires.isoformat(),
            previous_lease_id=row.get("previous_lease_id"),
            kicked_fingerprint=row.get("kicked_fingerprint"),
            required_features=row["required_features"],
            scope=row["scope"],
        )
        return {
            "lease_id": lease_id,
            "license_id": row["license_id"],
            "fingerprint": fingerprint,
            "expires_at": expires.isoformat(),
            "required_features": row["required_features"],
            "scope": row["scope"],
        }

    async def release_run_lease(self, lease_id: str, fingerprint: str) -> bool:
        store = self.event_store
        row = store.get_run_lease_by_id(lease_id) if hasattr(store, "get_run_lease_by_id") else None
        if not row:
            return False
        if row.get("fingerprint") != fingerprint:
            return False
        return bool(store.delete_run_lease(row["license_id"], lease_id))

    def run_lease_active_for(self, license_id: str, fingerprint: str | None = None) -> dict | None:
        store = self.event_store
        if not hasattr(store, "get_run_lease"):
            return None
        row = store.get_run_lease(license_id)
        if not row:
            return None
        try:
            exp = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return None
        if exp <= datetime.now(timezone.utc):
            return None
        if fingerprint is not None and row.get("fingerprint") != fingerprint:
            return None
        return row

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
            self.event_store.save_local_license(rec["id"], rec["key"], rec)
        self._sync_current_claims(rec)
        return self._to_dto(rec)

    def current_device_license(self, fingerprint: str) -> Optional[dict]:
        from bridge.app.services import referral as _ref
        records = [rec for ident, rec in list(self.licenses.items())
                   if any(d.get("fingerprint") == fingerprint for d in list(self.activations.get(ident, [])))]
        beta = _ref.is_beta_fp(self.event_store._conn, fingerprint)
        return select_current(records, beta=beta)

    def _sync_current_claims(self, rec: dict) -> None:
        """Refresh existing claim pointers and publish their projection after a write."""
        import json
        import os
        import urllib.request
        url = os.environ.get("TRIAL_CLAIM_SYNC_URL")
        for dev in list(self.activations.get(rec["id"], [])):
            fp = dev["fingerprint"]
            current = self.current_device_license(fp)
            if current is None:
                continue
            try:
                self.event_store.update_device_trial_current(fp, current)
                if url:
                    payload = json.dumps({"fingerprint": fp, "current": current}).encode("utf-8")
                    req = urllib.request.Request(url, data=payload, method="POST", headers={
                        "Content-Type": "application/json",
                        "X-Referral-Internal-Key": os.environ.get("REFERRAL_INTERNAL_KEY", "")})
                    # One worker preserves send order; pending updates coalesce per device.
                    with self._claim_sync_lock:
                        self._claim_sync_pending[fp] = req
                        if self._claim_sync_worker is None:
                            self._claim_sync_worker = threading.Thread(target=self._publish_current_claims, daemon=True)
                            self._claim_sync_worker.start()
            except Exception as exc:
                logger.error("current_claim_sync_failed: %s", type(exc).__name__)

    def _publish_current_claims(self) -> None:
        """Network callbacks never run on the request/startup thread."""
        import urllib.request
        while True:
            with self._claim_sync_lock:
                if not self._claim_sync_pending:
                    self._claim_sync_worker = None
                    return
                fp = next(iter(self._claim_sync_pending))
                req = self._claim_sync_pending.pop(fp)
            try:
                with urllib.request.urlopen(req, timeout=1) as response:
                    if response.status != 200:
                        raise OSError("claim sync failed")
            except Exception as exc:
                logger.error("current_claim_sync_failed: %s", type(exc).__name__)

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
        identity_rec = rec
        if fingerprint and any(d.get("fingerprint") == fingerprint for d in self.activations.get(rec["id"], [])):
            from bridge.app.services import referral as _ref
            if _ref.is_beta_fp(self.event_store._conn, fingerprint):
                identity_rec = {**rec, "is_beta_user": True}

        if status == LicenseStatus.REVOKED:
            pass  # BATCH A (A3): terminal, never GRACE
        elif rec["suspended"]:
            status = LicenseStatus.SUSPENDED
        elif rec["expires_at"] and now > rec["expires_at"]:
            # Hard expiry by default (DEFAULT_GRACE_DAYS = 0); a per-license
            # metadata.grace_days > 0 is an explicit operator opt-in only.
            grace_days = _grace_days(rec)
            grace_expiry = rec["expires_at"] + timedelta(days=grace_days)
            if grace_days > 0 and now <= grace_expiry:
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
                    license=self._to_dto(rec, identity_rec=identity_rec),
                    code="DEVICE_NOT_ACTIVATED",
                    message="Current machine is not activated on this license",
                )

        return EntitlementValidationResult(
            valid=can_start,
            status=status,
            can_start_runner=can_start,
            license=self._to_dto(rec, identity_rec=identity_rec),
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
        self._persist_then_apply(rec, expires_at=base_date + timedelta(days=extend_days),
                                 status=LicenseStatus.ACTIVE, suspended=False)
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
        meta = dict(rec.get("metadata") or {})
        meta["suspend_reason"] = reason
        self._persist_then_apply(rec, suspended=True, status=LicenseStatus.SUSPENDED, metadata=meta)
        return self._to_dto(rec)

    async def reinstate_license(self, license_id: str) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        rec = self.licenses[dto.license_id]
        if rec["status"] == LicenseStatus.REVOKED:
            raise ValueError("Cannot modify/reinstate revoked license: terminal state")
        self._persist_then_apply(rec, suspended=False, status=LicenseStatus.ACTIVE)
        return self._to_dto(rec)

    async def revoke_license(
        self, license_id: str, reason: str = "refunded_or_terminated"
    ) -> LicenseDTO:
        dto = await self.get_license(license_id)
        if not dto:
            raise ValueError(f"License {license_id} not found")
        rec = self.licenses[dto.license_id]
        meta = dict(rec.get("metadata") or {})
        meta["revoke_reason"] = reason
        meta.setdefault("revoked_at", datetime.now(timezone.utc).isoformat())
        self._persist_then_apply(rec, status=LicenseStatus.REVOKED, suspended=False, metadata=meta)
        return self._to_dto(rec)

    def _persist_then_apply(self, rec: dict, **changes) -> None:
        """BATCH A (A1): write the changed record first, then mutate memory (all-or-nothing)."""
        new = dict(rec)
        new.update(changes)
        if hasattr(self.event_store, "save_local_license"):
            self.event_store.save_local_license(new["id"], new["key"], new)
        rec.update(changes)
        # r7.1: a renewal / extension / reinstatement can make a non-beta inviter eligible
        # ("需开通/续订正式订阅后再叠加") -> apply that inviter's pending referral rewards.
        if "expires_at" in changes or changes.get("status") == LicenseStatus.ACTIVE:
            for d in list(self.activations.get(rec.get("id"), []) or []):
                fp = d.get("fingerprint")
                if fp:
                    self._referral_apply_pending(fp)
        self._sync_current_claims(rec)

    async def activate_device(
        self, license_key: str, hardware: HardwareFingerprint
    ) -> DeviceActivationDTO:
        dto = await self.get_license(license_key)
        if not dto:
            raise ValueError("LICENSE_NOT_FOUND: license key not recognised")
        rec = self.licenses[dto.license_id]
        # BATCH A (A2): state is checked BEFORE binding (694e3c2 bound revoked licenses).
        _st = rec.get("status")
        _exp = rec.get("expires_at")
        if _st == LicenseStatus.REVOKED:
            raise ValueError("LICENSE_REVOKED: license is revoked")
        if rec.get("suspended") or _st == LicenseStatus.SUSPENDED:
            raise ValueError("LICENSE_SUSPENDED: license is suspended")
        if _exp is not None:
            if datetime.now(timezone.utc) > _exp + timedelta(days=_grace_days(rec)):
                raise ValueError("LICENSE_EXPIRED: license is expired")
        dev_list = self.activations.setdefault(dto.license_id, [])

        # Idempotent reactivation of same machine
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

        was_first_device = len(dev_list) == 0
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
        if hasattr(self.event_store, "save_local_activation"):
            self.event_store.save_local_activation(act_id, dto.license_id, hardware.fingerprint, act_record)

        # Start license clock on first activation when configured
        if (
            was_first_device
            and rec.get("expires_at") is None
            and bool((rec.get("metadata") or {}).get("starts_on_first_activation"))
        ):
            meta = rec.setdefault("metadata", {})
            ttl_days = int(meta.get("activation_ttl_days") or 0)
            if ttl_days > 0:
                rec["expires_at"] = now + timedelta(days=ttl_days)
                meta["activated_clock_started_at"] = now.isoformat()
                if hasattr(self.event_store, "save_local_license"):
                    self.event_store.save_local_license(rec["id"], rec["key"], rec)

        # r7 ruling 6: an inviter whose rewards were kept pending (NO_ELIGIBLE_LICENSE) gets them
        # applied as soon as one of its cards is activated (bound) on this fingerprint.
        self._referral_note_beta(rec, hardware.fingerprint)
        self._referral_apply_pending(hardware.fingerprint)
        self._sync_current_claims(rec)

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

    async def claim_device_trial(
        self,
        hardware: HardwareFingerprint,
        *,
        client_ip: Optional[str] = None,
        duration: timedelta = timedelta(hours=24),
        now: Optional[datetime] = None,
    ) -> LicenseDTO:
        """Self-service, one-per-machine trial bound to ``hardware.fingerprint``.

        Idempotent: the same machine always gets the same license key/expiry while the
        trial is valid; expiry is fixed at claim time and never extended here.
        Raises TrialClaimError(TRIAL_ALREADY_USED | TRIAL_NOT_ELIGIBLE).
        """
        from bridge.app.services.trial_claim import (
            CODE_ALREADY_USED,
            CODE_NOT_ELIGIBLE,
            TRIAL_CUSTOMER_PREFIX,
            TRIAL_FEATURES,
            TRIAL_PLAN,
            TrialClaimError,
            normalize_fingerprint,
        )

        fp = normalize_fingerprint(hardware.fingerprint)
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
        store = self.event_store
        if not hasattr(store, "create_device_trial"):
            raise TrialClaimError("TRIAL_UNSUPPORTED", "event store cannot persist trials")

        existing = store.get_device_trial(fp)
        if existing is None:
            # In-memory bindings mirror local_activations; checked as well so a store
            # without history can never hand a trial to an already-bound machine.
            for lic_id, devs in self.activations.items():
                if any(str(d.get("fingerprint", "")).strip().lower() == fp for d in devs):
                    raise TrialClaimError(CODE_NOT_ELIGIBLE, "machine has existing license history")

            lic_id = f"lic_{uuid.uuid4().hex[:12]}"
            lic_key = f"SSB-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"
            expires_at = now + duration
            record = {
                "id": lic_id,
                "key": lic_key,
                "status": LicenseStatus.ACTIVE,
                "plan": TRIAL_PLAN,
                "tier": "trial",                       # r7.1: post-cutover self-service trial is never beta
                "tier_name": _tiers.tier_name("trial"),
                "customer_id": f"{TRIAL_CUSTOMER_PREFIX}{now:%Y%m%d}",
                "customer_email": None,
                "created_at": now,
                "expires_at": expires_at,
                "device_limit": 1,
                "features": list(TRIAL_FEATURES),
                "metadata": {
                    "issued_by": "trial_claim",
                    "is_trial": True,
                    "trial_kind": "self_service_device",
                    "trial_claimed_at": now.isoformat(),
                    "grace_days": 0,
                },
                "suspended": False,
            }
            act_record = {
                "id": f"act_{uuid.uuid4().hex[:8]}",
                "fingerprint": fp,
                "name": hardware.hostname or "primary_device",
                "activated_at": now,
                "last_heartbeat_at": now,
                "components": dict(hardware.components or {}),
            }
            outcome, row = store.create_device_trial(
                fingerprint=fp,
                license_record=record,
                activation_record=act_record,
                claimed_at=now.isoformat(),
                expires_at=expires_at.isoformat(),
                client_ip=client_ip,
            )
            if outcome == "created":
                self.licenses[lic_id] = record
                self.activations.setdefault(lic_id, []).append(act_record)
                self._sync_current_claims(record)
                return self._to_dto(record)
            if outcome == "used":
                raise TrialClaimError(CODE_ALREADY_USED, "trial already used on this machine")
            if outcome == "history":
                raise TrialClaimError(CODE_NOT_ELIGIBLE, "machine has existing license history")
            existing = row

        # Repeat / concurrent / retry: return the SAME license while it is still valid.
        rec = self.licenses.get(existing["license_id"])
        if rec is None and hasattr(store, "load_local_license"):
            rec = store.load_local_license(existing["license_id"])
            if rec is not None:
                self.licenses[rec["id"]] = rec
        if rec is None:
            raise TrialClaimError(CODE_ALREADY_USED, "trial already used on this machine")
        exp = rec.get("expires_at")
        if exp is not None and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if (
            rec.get("status") == LicenseStatus.REVOKED
            or rec.get("suspended")
            or exp is None
            or exp <= now
        ):
            # WEEKEND EVENT: expired self-service trial -> renew +24h (same key).
            # Revert for official release: delete this if-block.
            if (
                rec.get("status") != LicenseStatus.REVOKED
                and not rec.get("suspended")
                and exp is not None
                and rec.get("plan") == TRIAL_PLAN
                and now < TRIAL_RECLAIM_EVENT_END_UTC
            ):
                new_exp = now + duration
                rec["expires_at"] = new_exp
                self.event_store.save_local_license(rec["id"], rec["key"], rec)
                return self._to_dto(rec)
            raise TrialClaimError(CODE_ALREADY_USED, "trial already used on this machine")
        return self._to_dto(rec)

    # ---- BATCH C: referral reward (extend inviter's bound subscription in place) ----

    def _referral_conn(self):
        conn = getattr(self, "_ref_conn", None)
        if conn is None:
            from bridge.app.services import referral as _ref
            conn = _ref.open_conn(self.event_store.db_path)
            self._ref_conn = conn
        return conn

    def _referral_note_beta(self, rec: dict, fingerprint: str) -> None:
        """r7.1: activating a card flagged at cutover as beta makes that fingerprint a beta user;
        a beta fingerprint activating a card does NOT relabel the card (label stays per card)."""
        from bridge.app.services import referral as _ref
        if not _tiers.is_beta_record(rec) or not getattr(self.event_store, "db_path", None):
            return
        try:
            _ref.mark_beta(self._referral_conn(), fingerprint, rec.get("id"), "activation_of_beta_card")
        except Exception as exc:
            logger.warning("referral_note_beta_failed: %s", type(exc).__name__)

    def _referral_apply_pending(self, fingerprint: str) -> None:
        from bridge.app.services import referral as _ref
        lock = getattr(self.event_store, "_trial_lock", None)
        if lock is None or not getattr(self.event_store, "db_path", None):
            return
        try:
            with lock:
                out = _ref.apply_pending(self._referral_conn(), fingerprint, cap=_ref.bonus_cap())
                lic = out.get("license")
                if lic:
                    fresh = self.event_store.load_local_license(lic["id"])
                    if fresh is not None:
                        if lic["id"] in self.licenses:
                            self.licenses[lic["id"]].update(fresh)
                        else:
                            self.licenses[lic["id"]] = fresh
        except Exception as exc:  # never fail an activation because of the referral ledger
            logger.warning("referral_apply_pending_failed: %s", type(exc).__name__)

    async def referral_reward_extend(self, inviter_fingerprint: str, invitee_fingerprint: str,
                                     review_id: str, *, cap: int, now: Optional[datetime] = None) -> dict:
        from bridge.app.services import referral as _ref
        lock = getattr(self.event_store, "_trial_lock", None)
        if lock is None:
            raise _ref.ReferralError("REFERRAL_DISABLED", "event store does not support referrals")
        with lock:  # in-process serialisation; BEGIN IMMEDIATE covers other connections
            out = _ref.reward_extend(self._referral_conn(), inviter_fingerprint, invitee_fingerprint,
                                     review_id, cap=cap, now=now)
            touched = out.pop("_touched", None)
            if touched:
                lic_id = touched["license"]["id"]
                fresh = self.event_store.load_local_license(lic_id)
                if fresh is not None:
                    if lic_id in self.licenses:
                        self.licenses[lic_id].update(fresh)   # keep object identity
                    else:
                        self.licenses[lic_id] = fresh
                act = touched.get("activation")
                if act:
                    act_id, a_lic, fp, data = act
                    rec = dict(data)
                    for k in ("activated_at", "last_heartbeat_at"):
                        rec[k] = datetime.fromisoformat(str(rec[k]).replace("Z", "+00:00"))
                    self.activations.setdefault(a_lic, []).append(rec)
        if touched:
            self._sync_current_claims(self.licenses[lic_id])
        return out

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

    def _to_dto(self, rec: dict, *, identity_rec: Optional[dict] = None) -> LicenseDTO:
        act_count = len(self.activations.get(rec["id"], []))
        features = _tiers.license_features(rec)
        metadata = dict(rec.get("metadata") or {})
        if _tiers.is_tier(rec.get("tier")):
            metadata["tier"] = rec["tier"]  # retain stored identity independently of the display tier
        if rec.get("is_beta_user") is True:
            metadata["is_beta_user"] = True
        identity = _tiers.resolve(identity_rec if identity_rec is not None else rec)
        return LicenseDTO(
            license_id=rec["id"],
            license_key=rec["key"],
            status=rec["status"],
            plan=rec.get("plan") or "",
            customer_id=rec["customer_id"],
            customer_email=rec["customer_email"],
            created_at=rec["created_at"],
            expires_at=rec["expires_at"],
            device_limit=rec["device_limit"],
            devices_used=act_count,
            features=features,
            pip_background="pip_background" in features,
            metadata=metadata,
            tier=identity["tier"],
            tier_name=identity["tier_name"],
            is_beta_user=identity["is_beta_user"],
        )


# Backward-compatible alias
KeygenProvider = InMemoryKeygenProvider
