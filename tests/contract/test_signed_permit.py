from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from bridge.app.core.crypto import CryptoEngine
from bridge.app.services.permit_issuer import (
    ApprovedRelease,
    PermitIssueError,
    PermitIssuer,
)
from contracts.entitlement import HardwareFingerprint, LicenseDTO, LicenseStatus


SOURCE_SHA = "a" * 40
MANIFEST_SHA = "b" * 64


def _engine() -> CryptoEngine:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return CryptoEngine(private_key_pem=pem)


def _license(expires_at: datetime | None = None) -> LicenseDTO:
    now = datetime.now(timezone.utc)
    return LicenseDTO(
        license_id="lic-test",
        license_key="redacted-test-key",
        status=LicenseStatus.ACTIVE,
        plan="pro_monthly",
        customer_id="customer-test",
        created_at=now,
        expires_at=expires_at or now + timedelta(days=1),
        device_limit=1,
        devices_used=1,
        features=["core", "automation"],
    )


def _issuer(engine: CryptoEngine) -> PermitIssuer:
    approval = ApprovedRelease.from_mapping({
        "source_sha": SOURCE_SHA,
        "release_manifest_sha256": MANIFEST_SHA,
        "release_channel": "dev",
        "allowed_modes": ["normal_farm", "lobby_hitch"],
    })
    return PermitIssuer(
        engine,
        key_id="shuabao-test-1",
        approved_releases=[approval],
    )


def _canonical_payload(permit: dict[str, object]) -> bytes:
    payload = dict(permit)
    payload.pop("signature")
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_permit_matches_desktop_schema_and_signature() -> None:
    engine = _engine()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    permit = _issuer(engine).issue(
        license=_license(),
        hardware=HardwareFingerprint(fingerprint="device-test"),
        source_sha=SOURCE_SHA,
        release_manifest_sha256=MANIFEST_SHA,
        release_channel="dev",
        mode_id="lobby_hitch",
        now=now,
    )

    assert set(permit) == {
        "schema_version", "product_id", "audience", "issuer",
        "permit_id", "jti", "license_id", "device_id",
        "device_fingerprint", "release_channel", "source_sha",
        "release_manifest_sha256", "allowed_modes", "features",
        "issued_at", "expires_at", "nonce", "signature_algorithm",
        "key_id", "signature",
    }
    assert permit["permit_id"] == permit["jti"]
    assert permit["device_id"] == permit["device_fingerprint"] == "device-test"
    assert permit["release_channel"] == "dev"
    assert permit["source_sha"] == SOURCE_SHA
    assert permit["release_manifest_sha256"] == MANIFEST_SHA
    assert permit["allowed_modes"] == ["lobby_hitch"]
    assert permit["issued_at"] == "2026-09-03T12:00:00Z"
    assert permit["expires_at"] == "2026-09-03T12:15:00Z"
    signature = base64.urlsafe_b64decode(
        str(permit["signature"]) + "=" * (-len(str(permit["signature"])) % 4)
    )
    engine.public_key.verify(signature, _canonical_payload(permit))


def test_permit_rejects_static_stable_or_unapproved_identity() -> None:
    engine = _engine()
    with pytest.raises(PermitIssueError) as exc:
        _issuer(engine).issue(
            license=_license(),
            hardware=HardwareFingerprint(fingerprint="device-test"),
            source_sha=SOURCE_SHA,
            release_manifest_sha256=MANIFEST_SHA,
            release_channel="stable",
            mode_id="lobby_hitch",
        )
    assert exc.value.code == "PERMIT_REQUEST_MALFORMED"

    with pytest.raises(PermitIssueError) as exc:
        _issuer(engine).issue(
            license=_license(),
            hardware=HardwareFingerprint(fingerprint="device-test"),
            source_sha="c" * 40,
            release_manifest_sha256=MANIFEST_SHA,
            release_channel="dev",
            mode_id="lobby_hitch",
        )
    assert exc.value.code == "RELEASE_NOT_APPROVED"


def test_permit_is_clamped_to_license_expiry_and_mode_approval() -> None:
    engine = _engine()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    permit = _issuer(engine).issue(
        license=_license(now + timedelta(minutes=4)),
        hardware=HardwareFingerprint(fingerprint="device-test"),
        source_sha=SOURCE_SHA,
        release_manifest_sha256=MANIFEST_SHA,
        release_channel="dev",
        mode_id="normal_farm",
        now=now,
    )
    assert permit["expires_at"] == "2026-09-03T12:04:00Z"

    with pytest.raises(PermitIssueError) as exc:
        _issuer(engine).issue(
            license=_license(),
            hardware=HardwareFingerprint(fingerprint="device-test"),
            source_sha=SOURCE_SHA,
            release_manifest_sha256=MANIFEST_SHA,
            release_channel="dev",
            mode_id="lead_team",
            now=now,
        )
    assert exc.value.code == "MODE_NOT_ALLOWED"


def test_environment_registry_is_fail_closed() -> None:
    engine = _engine()
    issuer = PermitIssuer.from_environment(engine, {})
    assert issuer.configured is False
    with pytest.raises(PermitIssueError) as exc:
        issuer.issue(
            license=_license(),
            hardware=HardwareFingerprint(fingerprint="device-test"),
            source_sha=SOURCE_SHA,
            release_manifest_sha256=MANIFEST_SHA,
            release_channel="dev",
            mode_id="lobby_hitch",
        )
    assert exc.value.code == "PERMIT_SIGNER_NOT_CONFIGURED"
