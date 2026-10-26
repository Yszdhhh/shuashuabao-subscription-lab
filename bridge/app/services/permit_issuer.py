"""Issue short-lived ShuaBao LIVE permits bound to approved release identities."""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Optional, Protocol

from bridge.app.core.crypto import CryptoEngine
from contracts.entitlement import HardwareFingerprint, LicenseDTO


PERMIT_SCHEMA_VERSION = 1
# schema_version=2 is a distinct reusable offline-permit type with its own 24h ceiling;
# the v1 constants above (schema 1, 15-minute one-shot) are left byte-for-byte unchanged.
OFFLINE_PERMIT_SCHEMA_VERSION = 2
PERMIT_PRODUCT_ID = "shuabao"
PERMIT_AUDIENCE = "live-runner"
PERMIT_ISSUER = "shuabao-subscription"
PERMIT_SIGNATURE_ALGORITHM = "Ed25519"
MAX_PERMIT_LIFETIME = timedelta(minutes=15)
MAX_OFFLINE_PERMIT_LIFETIME = timedelta(hours=24)
RELEASE_CHANNELS = frozenset({"dev", "internal-pilot", "external-beta", "release"})
_ADVISORIES = frozenset({"recommended", "outdated"})
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

LOGGER = logging.getLogger("shuabao.permit_issuer")


class PermitIssueError(Exception):
    """Stable fail-closed permit issuance error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ApprovedRelease:
    """Exact release approval identity (unchanged trust key)."""

    source_sha: str
    release_manifest_sha256: str
    release_channel: str
    allowed_modes: frozenset[str]
    blocked: bool = False
    advisory: Optional[str] = None
    recommended_source_sha: Optional[str] = None
    recommended_manifest_sha256: Optional[str] = None
    recommended_channel: Optional[str] = None
    operator_note: Optional[str] = None
    updated_at: Optional[str] = None
    updated_by: Optional[str] = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ApprovedRelease":
        source_sha = str(value.get("source_sha") or "").strip().lower()
        manifest_sha = str(value.get("release_manifest_sha256") or "").strip().lower()
        channel = str(value.get("release_channel") or "").strip()
        modes = value.get("allowed_modes")
        blocked = bool(value.get("blocked") or False)
        advisory_raw = value.get("advisory")
        advisory = str(advisory_raw).strip().lower() if advisory_raw else None
        if advisory == "":
            advisory = None
        if (
            not _HEX40.fullmatch(source_sha)
            or not _HEX64.fullmatch(manifest_sha)
            or channel not in RELEASE_CHANNELS
            or not isinstance(modes, list)
            or not modes
            or not all(isinstance(item, str) and item.strip() for item in modes)
        ):
            raise PermitIssueError(
                "PERMIT_RELEASE_REGISTRY_INVALID",
                "approved release entry has invalid source/manifest/channel/modes",
            )
        if advisory is not None and advisory not in _ADVISORIES:
            raise PermitIssueError(
                "PERMIT_RELEASE_REGISTRY_INVALID",
                "advisory must be recommended|outdated|null",
            )
        return cls(
            source_sha=source_sha,
            release_manifest_sha256=manifest_sha,
            release_channel=channel,
            allowed_modes=frozenset(item.strip() for item in modes),
            blocked=blocked,
            advisory=advisory,
            recommended_source_sha=_optional_hex40(value.get("recommended_source_sha")),
            recommended_manifest_sha256=_optional_hex64(value.get("recommended_manifest_sha256")),
            recommended_channel=_optional_channel(value.get("recommended_channel")),
            operator_note=str(value.get("operator_note") or "").strip() or None,
            updated_at=str(value.get("updated_at") or "").strip() or None,
            updated_by=str(value.get("updated_by") or "").strip() or None,
        )

    def identity_key(self) -> tuple[str, str, str]:
        return (self.source_sha, self.release_manifest_sha256, self.release_channel)

    def _state(self) -> str:
        if self.blocked:
            return "blocked"
        if self.allowed_modes:
            return "approved"
        return "not_approved"

    def _recommended_release(self) -> dict[str, str] | None:
        if (
            self.recommended_source_sha
            and self.recommended_manifest_sha256
            and self.recommended_channel
        ):
            return {
                "source_sha": self.recommended_source_sha,
                "release_manifest_sha256": self.recommended_manifest_sha256,
                "release_channel": self.recommended_channel,
            }
        return None

    @staticmethod
    def _generic_status_message(state: str, advisory: Optional[str]) -> str:
        if state == "blocked":
            return "release is blocked for new LIVE permits"
        if advisory == "recommended":
            return "a newer recommended release is available"
        if advisory == "outdated":
            return "this release is marked outdated; still approved unless blocked"
        if state == "approved":
            return "release is approved for LIVE permits"
        return "release is not approved"

    def status_payload(self) -> dict[str, Any]:
        """Full admin/ops payload (may include operator_note via message + updated_by)."""
        state = self._state()
        message = self.operator_note or self._generic_status_message(state, self.advisory)
        return {
            "approved": state == "approved",
            "blocked": self.blocked,
            "recommended": self.advisory == "recommended",
            "outdated": self.advisory == "outdated",
            "status": state,
            "advisory": self.advisory,
            "message": message,
            "allowed_modes": sorted(self.allowed_modes),
            "source_sha": self.source_sha,
            "release_manifest_sha256": self.release_manifest_sha256,
            "release_channel": self.release_channel,
            "recommended_release": self._recommended_release(),
            "operator_note": self.operator_note,
            "updated_at": self.updated_at,
            "updated_by": self.updated_by,
        }

    def public_status_payload(self) -> dict[str, Any]:
        """Client-facing status: no operator_note / updated_by / other internal ops fields."""
        state = self._state()
        return {
            "approved": state == "approved",
            "blocked": self.blocked,
            "recommended": self.advisory == "recommended",
            "outdated": self.advisory == "outdated",
            "status": state,
            "advisory": self.advisory,
            "message": self._generic_status_message(state, self.advisory),
            "allowed_modes": sorted(self.allowed_modes),
            "source_sha": self.source_sha,
            "release_manifest_sha256": self.release_manifest_sha256,
            "release_channel": self.release_channel,
            "recommended_release": self._recommended_release(),
        }


class ReleasePolicyStore(Protocol):
    def get_release_policy(
        self, source_sha: str, release_manifest_sha256: str, release_channel: str
    ) -> dict | None: ...

    def upsert_release_policy(self, **kwargs: Any) -> None: ...


def _optional_hex40(value: object) -> Optional[str]:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if not _HEX40.fullmatch(text):
        raise PermitIssueError("PERMIT_RELEASE_REGISTRY_INVALID", "recommended_source_sha invalid")
    return text


def _optional_hex64(value: object) -> Optional[str]:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if not _HEX64.fullmatch(text):
        raise PermitIssueError(
            "PERMIT_RELEASE_REGISTRY_INVALID", "recommended_manifest_sha256 invalid"
        )
    return text


def _optional_channel(value: object) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None
    if text not in RELEASE_CHANNELS:
        raise PermitIssueError("PERMIT_RELEASE_REGISTRY_INVALID", "recommended_channel invalid")
    return text


def policy_from_row(row: Mapping[str, object]) -> ApprovedRelease:
    return ApprovedRelease.from_mapping(
        {
            "source_sha": row.get("source_sha"),
            "release_manifest_sha256": row.get("release_manifest_sha256"),
            "release_channel": row.get("release_channel"),
            "allowed_modes": row.get("allowed_modes") or [],
            "blocked": row.get("blocked"),
            "advisory": row.get("advisory"),
            "recommended_source_sha": row.get("recommended_source_sha"),
            "recommended_manifest_sha256": row.get("recommended_manifest_sha256"),
            "recommended_channel": row.get("recommended_channel"),
            "operator_note": row.get("operator_note"),
            "updated_at": row.get("updated_at"),
            "updated_by": row.get("updated_by"),
        }
    )



def not_approved_status_payload(
    source_sha: str,
    release_manifest_sha256: str,
    release_channel: str,
    *,
    public: bool = False,
) -> dict[str, Any]:
    payload = {
        "approved": False,
        "blocked": False,
        "recommended": False,
        "outdated": False,
        "status": "not_approved",
        "advisory": None,
        "message": "release is not approved",
        "allowed_modes": [],
        "source_sha": str(source_sha or "").strip().lower(),
        "release_manifest_sha256": str(release_manifest_sha256 or "").strip().lower(),
        "release_channel": str(release_channel or "").strip(),
        "recommended_release": None,
    }
    if not public:
        payload["operator_note"] = None
        payload["updated_at"] = None
        payload["updated_by"] = None
    return payload


def public_status_payload_from_policy(policy: "ApprovedRelease") -> dict[str, Any]:
    return policy.public_status_payload()


def validate_release_identity(
    source_sha: str,
    release_manifest_sha256: str,
    release_channel: str,
) -> tuple[str, str, str]:
    source_sha = str(source_sha or "").strip().lower()
    manifest = str(release_manifest_sha256 or "").strip().lower()
    channel = str(release_channel or "").strip()
    if not _HEX40.fullmatch(source_sha) or not _HEX64.fullmatch(manifest) or channel not in RELEASE_CHANNELS:
        raise ValueError("invalid source_sha, release_manifest_sha256, or release_channel")
    return source_sha, manifest, channel


def parse_allowed_modes(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = [p.strip() for p in value.replace(";", ",").split(",")]
        return [p for p in parts if p]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    raise ValueError("allowed_modes must be a list or comma-separated string")


def parse_offline_v2_releases(raw: str | None) -> frozenset[tuple[str, str, str]]:
    """Parse SHUABAO_OFFLINE_V2_RELEASES_JSON into an exact v2 opt-in allowlist.

    Returns a frozenset of ``(source_sha, release_manifest_sha256, release_channel)``
    tuples, each a strict 40-hex / 64-hex / known-channel triple. Default is EMPTY.

    Compatibility-sensitive handling: a malformed/invalid config must never enable v2
    or widen matching. It is logged as a bounded, non-secret operator warning and the
    whole v2 allowlist is disabled (returned empty), so existing v1 clients keep working
    instead of failing or crashing startup. Only exact triples survive; anything else is
    dropped by disabling the set.
    """
    text = str(raw or "").strip()
    if not text:
        return frozenset()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        LOGGER.warning(
            "SHUABAO_OFFLINE_V2_RELEASES_JSON is not valid JSON; v2 offline permits disabled"
        )
        return frozenset()
    if not isinstance(parsed, list):
        LOGGER.warning(
            "SHUABAO_OFFLINE_V2_RELEASES_JSON must be a JSON list; v2 offline permits disabled"
        )
        return frozenset()
    allowlist: set[tuple[str, str, str]] = set()
    for item in parsed:
        if not isinstance(item, Mapping):
            LOGGER.warning(
                "SHUABAO_OFFLINE_V2_RELEASES_JSON entry is not an object; v2 offline permits disabled"
            )
            return frozenset()
        source_sha = str(item.get("source_sha") or "").strip().lower()
        manifest_sha = str(item.get("release_manifest_sha256") or "").strip().lower()
        channel = str(item.get("release_channel") or "").strip()
        if (
            not _HEX40.fullmatch(source_sha)
            or not _HEX64.fullmatch(manifest_sha)
            or channel not in RELEASE_CHANNELS
        ):
            LOGGER.warning(
                "SHUABAO_OFFLINE_V2_RELEASES_JSON has an invalid source/manifest/channel triple; "
                "v2 offline permits disabled"
            )
            return frozenset()
        allowlist.add((source_sha, manifest_sha, channel))
    return frozenset(allowlist)


class PermitIssuer:
    """Server-only signer; client-supplied release identities must be pre-approved."""

    def __init__(
        self,
        crypto: CryptoEngine,
        *,
        key_id: str,
        approved_releases: Iterable[ApprovedRelease] = (),
        policy_store: Optional[ReleasePolicyStore] = None,
        offline_v2_releases: Iterable[tuple[str, str, str]] = (),
    ) -> None:
        self.crypto = crypto
        self.key_id = str(key_id or "").strip()
        self._policy_store = policy_store
        self._memory = {
            item.identity_key(): item
            for item in approved_releases
        }
        # Exact (source_sha, manifest, channel) triples explicitly opted into schema-2
        # offline permits. Empty default => every release keeps the legacy v1 path.
        self._offline_v2_releases = frozenset(offline_v2_releases)

    @classmethod
    def from_environment(
        cls,
        crypto: CryptoEngine,
        env: Mapping[str, str] | None = None,
        *,
        policy_store: Optional[ReleasePolicyStore] = None,
    ) -> "PermitIssuer":
        source = os.environ if env is None else env
        key_id = str(source.get("SHUABAO_PERMIT_SIGNING_KEY_ID") or "").strip()
        raw = str(source.get("SHUABAO_APPROVED_RELEASES_JSON") or "").strip()
        offline_v2_releases = parse_offline_v2_releases(
            source.get("SHUABAO_OFFLINE_V2_RELEASES_JSON")
        )
        approvals: list[ApprovedRelease] = []
        if raw:
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "SHUABAO_APPROVED_RELEASES_JSON is not valid JSON"
                ) from exc
            if not isinstance(parsed, list):
                raise RuntimeError("SHUABAO_APPROVED_RELEASES_JSON must be a JSON list")
            try:
                approvals = [ApprovedRelease.from_mapping(item) for item in parsed]
            except (AttributeError, PermitIssueError, TypeError) as exc:
                raise RuntimeError(f"approved release registry is invalid: {exc}") from exc
            if policy_store is not None:
                for raw_item, item in zip(parsed, approvals):
                    existing = policy_store.get_release_policy(
                        item.source_sha,
                        item.release_manifest_sha256,
                        item.release_channel,
                    )
                    blocked = item.blocked
                    advisory = item.advisory
                    operator_note = item.operator_note
                    rec_src = item.recommended_source_sha
                    rec_man = item.recommended_manifest_sha256
                    rec_ch = item.recommended_channel
                    # Env seed must not wipe ops flags or recommended_* pointers:
                    # preserve blocked/advisory/note/recommended_* unless JSON sets them.
                    if existing is not None and isinstance(raw_item, dict):
                        if "blocked" not in raw_item:
                            blocked = bool(existing.get("blocked"))
                        if "advisory" not in raw_item:
                            advisory = existing.get("advisory")
                        if "operator_note" not in raw_item:
                            operator_note = existing.get("operator_note")
                        if "recommended_source_sha" not in raw_item:
                            rec_src = existing.get("recommended_source_sha")
                        if "recommended_manifest_sha256" not in raw_item:
                            rec_man = existing.get("recommended_manifest_sha256")
                        if "recommended_channel" not in raw_item:
                            rec_ch = existing.get("recommended_channel")
                    policy_store.upsert_release_policy(
                        source_sha=item.source_sha,
                        release_manifest_sha256=item.release_manifest_sha256,
                        release_channel=item.release_channel,
                        allowed_modes=sorted(item.allowed_modes),
                        blocked=blocked,
                        advisory=advisory,
                        recommended_source_sha=rec_src,
                        recommended_manifest_sha256=rec_man,
                        recommended_channel=rec_ch,
                        operator_note=operator_note,
                        updated_by="env:SHUABAO_APPROVED_RELEASES_JSON",
                    )
        return cls(
            crypto,
            key_id=key_id,
            approved_releases=approvals,
            policy_store=policy_store,
            offline_v2_releases=offline_v2_releases,
        )

    @property
    def configured(self) -> bool:
        has_policies = bool(self._memory) or self._policy_store is not None
        return bool(self.key_id and has_policies and self.crypto.private_key is not None)

    def resolve_policy(
        self,
        source_sha: str,
        release_manifest_sha256: str,
        release_channel: str,
    ) -> Optional[ApprovedRelease]:
        source_sha = str(source_sha or "").strip().lower()
        manifest_sha = str(release_manifest_sha256 or "").strip().lower()
        channel = str(release_channel or "").strip()
        if self._policy_store is not None:
            row = self._policy_store.get_release_policy(source_sha, manifest_sha, channel)
            if row is not None:
                # empty modes allowed for blocked-only rows created by ops
                modes = row.get("allowed_modes") or []
                if not modes and not row.get("blocked"):
                    return None
                payload = dict(row)
                if not modes:
                    # from_mapping requires non-empty modes; synthesize placeholder denied set
                    payload["allowed_modes"] = ["__none__"]
                    policy = ApprovedRelease.from_mapping(payload)
                    return ApprovedRelease(
                        source_sha=policy.source_sha,
                        release_manifest_sha256=policy.release_manifest_sha256,
                        release_channel=policy.release_channel,
                        allowed_modes=frozenset(),
                        blocked=policy.blocked,
                        advisory=policy.advisory,
                        recommended_source_sha=policy.recommended_source_sha,
                        recommended_manifest_sha256=policy.recommended_manifest_sha256,
                        recommended_channel=policy.recommended_channel,
                        operator_note=policy.operator_note,
                        updated_at=policy.updated_at,
                        updated_by=policy.updated_by,
                    )
                return ApprovedRelease.from_mapping(payload)
        return self._memory.get((source_sha, manifest_sha, channel))


    def status_payload_for(
        self,
        source_sha: str,
        release_manifest_sha256: str,
        release_channel: str,
        *,
        public: bool = False,
    ) -> dict[str, Any]:
        source_sha = str(source_sha or "").strip().lower()
        manifest = str(release_manifest_sha256 or "").strip().lower()
        channel = str(release_channel or "").strip()
        policy = self.resolve_policy(source_sha, manifest, channel)
        if policy is None:
            return not_approved_status_payload(source_sha, manifest, channel, public=public)
        if public:
            return policy.public_status_payload()
        return policy.status_payload()

    def issue(
        self,
        *,
        license: LicenseDTO,
        hardware: HardwareFingerprint,
        source_sha: str,
        release_manifest_sha256: str,
        release_channel: str,
        mode_id: str,
        now: datetime | None = None,
    ) -> dict[str, object]:
        if not self.key_id or self.crypto.private_key is None:
            raise PermitIssueError(
                "PERMIT_SIGNER_NOT_CONFIGURED",
                "permit signing key id/private key is not configured",
            )
        source_sha = str(source_sha or "").strip().lower()
        manifest_sha = str(release_manifest_sha256 or "").strip().lower()
        channel = str(release_channel or "").strip()
        requested_mode = str(mode_id or "").strip()
        if (
            not _HEX40.fullmatch(source_sha)
            or not _HEX64.fullmatch(manifest_sha)
            or channel not in RELEASE_CHANNELS
            or not requested_mode
        ):
            raise PermitIssueError(
                "PERMIT_REQUEST_MALFORMED",
                "release identity or mode is malformed",
            )
        policy = self.resolve_policy(source_sha, manifest_sha, channel)
        # Precedence: BLOCKED > NOT_APPROVED > mode/entitlement handled by caller
        if policy is not None and policy.blocked:
            raise PermitIssueError(
                "RELEASE_BLOCKED",
                policy.operator_note or "requested release is blocked for new LIVE permits",
            )
        if policy is None:
            raise PermitIssueError(
                "RELEASE_NOT_APPROVED",
                "requested source/manifest/channel is not approved",
            )
        if requested_mode not in policy.allowed_modes:
            raise PermitIssueError(
                "MODE_NOT_ALLOWED",
                "requested mode is not approved for this release",
            )

        issued_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        # Schema-2 is selected ONLY when this exact release triple was explicitly opted in
        # AND the license has a finite expiry. Everything else keeps the legacy v1 path:
        # no expiry is never fabricated into an offline/permanent entitlement.
        license_expiry: datetime | None = None
        if license.expires_at is not None:
            license_expiry = license.expires_at
            if license_expiry.tzinfo is None:
                license_expiry = license_expiry.replace(tzinfo=timezone.utc)
            license_expiry = license_expiry.astimezone(timezone.utc)
        offline_v2 = (
            (source_sha, manifest_sha, channel) in self._offline_v2_releases
            and license_expiry is not None
        )

        max_lifetime = MAX_OFFLINE_PERMIT_LIFETIME if offline_v2 else MAX_PERMIT_LIFETIME
        expires_at = issued_at + max_lifetime
        if license_expiry is not None:
            expires_at = min(expires_at, license_expiry)
        if expires_at <= issued_at:
            raise PermitIssueError("LICENSE_EXPIRED", "license has no remaining permit lifetime")

        permit_id = uuid.uuid4().hex
        payload: dict[str, object] = {
            "schema_version": OFFLINE_PERMIT_SCHEMA_VERSION if offline_v2 else PERMIT_SCHEMA_VERSION,
            "product_id": PERMIT_PRODUCT_ID,
            "audience": PERMIT_AUDIENCE,
            "issuer": PERMIT_ISSUER,
            "permit_id": permit_id,
            "jti": permit_id,
            "license_id": license.license_id,
            "device_id": hardware.fingerprint,
            "device_fingerprint": hardware.fingerprint,
            "release_channel": channel,
            "source_sha": source_sha,
            "release_manifest_sha256": manifest_sha,
            "allowed_modes": [requested_mode],
            "features": list(license.features),
            "issued_at": _timestamp(issued_at),
            "expires_at": _timestamp(expires_at),
            "nonce": secrets.token_urlsafe(24),
            "signature_algorithm": PERMIT_SIGNATURE_ALGORITHM,
            "key_id": self.key_id,
        }
        # v2 adds the signature-protected subscription_expires_at; v1 payload is unchanged.
        if offline_v2:
            assert license_expiry is not None  # guaranteed by offline_v2 condition
            payload["subscription_expires_at"] = _timestamp(license_expiry)
        payload["signature"] = self.crypto.sign_canonical_json(payload)
        return payload


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
