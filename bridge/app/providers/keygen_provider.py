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
from bridge.app.services.event_processor import SqliteEventStore
from bridge.app.providers.base import ILicenseProvider

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
        lic_key = f"SSB-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"
        now = datetime.now(timezone.utc)
        meta = dict(metadata or {})
        starts_on_first = bool(meta.get("starts_on_first_activation"))
        if starts_on_first:
            expires_at = None
            if meta.get("activation_ttl_days") in (None, ""):
                meta["activation_ttl_days"] = duration_days
            else:
                meta["activation_ttl_days"] = int(meta["activation_ttl_days"])
        else:
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
            "metadata": meta,
            "suspended": False,
        }
        self.licenses[lic_id] = record
        self.activations.setdefault(lic_id, [])
        if hasattr(self.event_store, "save_local_license"):
            self.event_store.save_local_license(lic_id, lic_key, record)
        return self._to_dto(record)

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

    # ---- run lease: one active run per license; kick only on acquire ----

    async def acquire_run_lease(
        self, license_key: str, fingerprint: str, ttl_seconds: int = 300
    ) -> dict:
        """Start-run exclusive lease. Binding/activating devices never calls this."""
        dto = await self.get_license(license_key)
        if not dto:
            raise ValueError("LICENSE_NOT_FOUND: license key not recognised")
        rec = self.licenses[dto.license_id]
        if rec["status"] == LicenseStatus.REVOKED or rec.get("suspended"):
            raise ValueError("LICENSE_NOT_ACTIVE")
        store = self.event_store
        if not hasattr(store, "save_run_lease"):
            raise ValueError("RUN_LEASE_UNSUPPORTED")
        now = datetime.now(timezone.utc)
        now_s = now.isoformat()
        expires = now + timedelta(seconds=max(60, int(ttl_seconds)))
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
        )
        return {
            "lease_id": lease_id,
            "license_id": dto.license_id,
            "fingerprint": fingerprint,
            "obtained_at": now_s,
            "expires_at": expires.isoformat(),
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
        expires = now + timedelta(seconds=max(60, int(ttl_seconds)))
        store.save_run_lease(
            license_id=row["license_id"],
            fingerprint=fingerprint,
            lease_id=lease_id,
            obtained_at=row["obtained_at"],
            heartbeat_at=now.isoformat(),
            expires_at=expires.isoformat(),
            previous_lease_id=row.get("previous_lease_id"),
            kicked_fingerprint=row.get("kicked_fingerprint"),
        )
        return {
            "lease_id": lease_id,
            "license_id": row["license_id"],
            "fingerprint": fingerprint,
            "expires_at": expires.isoformat(),
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
        return self._to_dto(rec)

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

        if status == LicenseStatus.REVOKED:
            pass  # BATCH A (A3): terminal, never GRACE
        elif rec["suspended"]:
            status = LicenseStatus.SUSPENDED
        elif rec["expires_at"] and now > rec["expires_at"]:
            # Check grace period (3 days grace default; per-license metadata.grace_days
            # overrides it, e.g. self-service trials use 0 = hard expiry)
            grace_days = 3
            meta_grace = (rec.get("metadata") or {}).get("grace_days")
            if meta_grace is not None:
                try:
                    grace_days = max(0, int(meta_grace))
                except (TypeError, ValueError):
                    grace_days = 3
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
            _g = (rec.get("metadata") or {}).get("grace_days")
            try:
                _g = 3 if _g is None else max(0, int(_g))
            except (TypeError, ValueError):
                _g = 3
            if datetime.now(timezone.utc) > _exp + timedelta(days=_g):
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


# Backward-compatible alias
KeygenProvider = InMemoryKeygenProvider
