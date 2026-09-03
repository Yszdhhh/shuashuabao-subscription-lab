"""Issue short-lived ShuaBao LIVE permits bound to approved release identities."""
from __future__ import annotations

import json
import os
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Mapping

from bridge.app.core.crypto import CryptoEngine
from contracts.entitlement import HardwareFingerprint, LicenseDTO


PERMIT_SCHEMA_VERSION = 1
PERMIT_PRODUCT_ID = "shuabao"
PERMIT_AUDIENCE = "live-runner"
PERMIT_ISSUER = "shuabao-subscription"
PERMIT_SIGNATURE_ALGORITHM = "Ed25519"
MAX_PERMIT_LIFETIME = timedelta(minutes=15)
RELEASE_CHANNELS = frozenset({"dev", "internal-pilot", "external-beta", "release"})
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class PermitIssueError(Exception):
    """Stable fail-closed permit issuance error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ApprovedRelease:
    source_sha: str
    release_manifest_sha256: str
    release_channel: str
    allowed_modes: frozenset[str]

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ApprovedRelease":
        source_sha = str(value.get("source_sha") or "").strip().lower()
        manifest_sha = str(value.get("release_manifest_sha256") or "").strip().lower()
        channel = str(value.get("release_channel") or "").strip()
        modes = value.get("allowed_modes")
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
        return cls(
            source_sha=source_sha,
            release_manifest_sha256=manifest_sha,
            release_channel=channel,
            allowed_modes=frozenset(item.strip() for item in modes),
        )


class PermitIssuer:
    """Server-only signer; client-supplied release identities must be pre-approved."""

    def __init__(
        self,
        crypto: CryptoEngine,
        *,
        key_id: str,
        approved_releases: Iterable[ApprovedRelease],
    ) -> None:
        self.crypto = crypto
        self.key_id = str(key_id or "").strip()
        self._approved = {
            (
                item.source_sha,
                item.release_manifest_sha256,
                item.release_channel,
            ): item
            for item in approved_releases
        }

    @classmethod
    def from_environment(
        cls,
        crypto: CryptoEngine,
        env: Mapping[str, str] | None = None,
    ) -> "PermitIssuer":
        source = os.environ if env is None else env
        key_id = str(source.get("SHUABAO_PERMIT_SIGNING_KEY_ID") or "").strip()
        raw = str(source.get("SHUABAO_APPROVED_RELEASES_JSON") or "").strip()
        if not raw:
            return cls(crypto, key_id=key_id, approved_releases=())
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
        except (AttributeError, PermitIssueError) as exc:
            raise RuntimeError(f"approved release registry is invalid: {exc}") from exc
        return cls(crypto, key_id=key_id, approved_releases=approvals)

    @property
    def configured(self) -> bool:
        return bool(self.key_id and self._approved and self.crypto.private_key is not None)

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
        approval = self._approved.get((source_sha, manifest_sha, channel))
        if approval is None:
            raise PermitIssueError(
                "RELEASE_NOT_APPROVED",
                "requested source/manifest/channel is not approved",
            )
        if requested_mode not in approval.allowed_modes:
            raise PermitIssueError(
                "MODE_NOT_ALLOWED",
                "requested mode is not approved for this release",
            )
        issued_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        expires_at = issued_at + MAX_PERMIT_LIFETIME
        if license.expires_at is not None:
            license_expiry = license.expires_at
            if license_expiry.tzinfo is None:
                license_expiry = license_expiry.replace(tzinfo=timezone.utc)
            expires_at = min(expires_at, license_expiry.astimezone(timezone.utc))
        if expires_at <= issued_at:
            raise PermitIssueError("LICENSE_EXPIRED", "license has no remaining permit lifetime")

        permit_id = uuid.uuid4().hex
        payload: dict[str, object] = {
            "schema_version": PERMIT_SCHEMA_VERSION,
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
        payload["signature"] = self.crypto.sign_canonical_json(payload)
        return payload


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
