"""schema_version=2 offline-permit issuance gating (LOCAL-ONLY compatibility).

These tests only cover the server issuer. They use process-ephemeral Ed25519 keys and
in-memory LicenseDTO objects; no real keys, credentials, or database.

Invariants under test (mirrors SUBSCRIPTION_V2_CHANGE_ORDER_20261022.md):
- The v2 allowlist defaults EMPTY: nothing opts into schema 2 unless an exact
  (source_sha, release_manifest_sha256, release_channel) triple is listed.
- Empty / non-matching / malformed allowlist => v1 permit, byte-for-byte unchanged.
- An exact-listed triple with a finite license expiry => schema 2, <=24h, with a
  signed subscription_expires_at and expires_at=min(now+24h, license.expires_at).
- A listed triple with NO license expiry stays v1 (no fabricated offline entitlement).
- All existing gates (blocked / not-approved / mode mismatch / expired / malformed)
  still fail before any v2 decision; they never yield a v2 permit.
"""
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
    MAX_OFFLINE_PERMIT_LIFETIME,
    MAX_PERMIT_LIFETIME,
    PermitIssueError,
    PermitIssuer,
    parse_offline_v2_releases,
)
from contracts.entitlement import HardwareFingerprint, LicenseDTO, LicenseStatus


SOURCE_SHA = "a" * 40
MANIFEST_SHA = "b" * 64
CHANNEL = "dev"
V2_TRIPLE = (SOURCE_SHA, MANIFEST_SHA, CHANNEL)


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
        expires_at=expires_at,
        device_limit=1,
        devices_used=1,
        features=["core", "automation"],
    )


def _issuer(engine: CryptoEngine, *, v2_releases=()) -> PermitIssuer:
    approval = ApprovedRelease.from_mapping({
        "source_sha": SOURCE_SHA,
        "release_manifest_sha256": MANIFEST_SHA,
        "release_channel": CHANNEL,
        "allowed_modes": ["normal_farm", "lobby_hitch"],
    })
    return PermitIssuer(
        engine,
        key_id="shuabao-test-1",
        approved_releases=[approval],
        offline_v2_releases=v2_releases,
    )


def _canonical_payload(permit: dict[str, object]) -> bytes:
    payload = dict(permit)
    payload.pop("signature")
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def _issue(issuer: PermitIssuer, license: LicenseDTO, now: datetime, mode="lobby_hitch"):
    return issuer.issue(
        license=license,
        hardware=HardwareFingerprint(fingerprint="device-test"),
        source_sha=SOURCE_SHA,
        release_manifest_sha256=MANIFEST_SHA,
        release_channel=CHANNEL,
        mode_id=mode,
        now=now,
    )


# ---- allowlist parser: default-empty, strict, malformed never widens -------------------

def test_v2_allowlist_defaults_empty():
    assert parse_offline_v2_releases(None) == frozenset()
    assert parse_offline_v2_releases("") == frozenset()
    assert parse_offline_v2_releases("   ") == frozenset()


def test_v2_allowlist_exact_triple_parses():
    raw = json.dumps([{
        "source_sha": SOURCE_SHA,
        "release_manifest_sha256": MANIFEST_SHA,
        "release_channel": CHANNEL,
    }])
    assert parse_offline_v2_releases(raw) == frozenset({V2_TRIPLE})


@pytest.mark.parametrize("raw", [
    "{not json",                                   # not JSON
    json.dumps({"source_sha": SOURCE_SHA}),        # not a list
    json.dumps(["not-an-object"]),                 # entry not an object
    json.dumps([{"source_sha": "z" * 40,
                 "release_manifest_sha256": MANIFEST_SHA,
                 "release_channel": CHANNEL}]),     # bad source hex
    json.dumps([{"source_sha": SOURCE_SHA,
                 "release_manifest_sha256": "b" * 63,
                 "release_channel": CHANNEL}]),     # bad manifest hex
    json.dumps([{"source_sha": SOURCE_SHA,
                 "release_manifest_sha256": MANIFEST_SHA,
                 "release_channel": "stable"}]),    # unknown channel
])
def test_v2_allowlist_malformed_disables_without_widening(raw):
    # Malformed config yields an EMPTY set: it never enables v2, never widens matching.
    assert parse_offline_v2_releases(raw) == frozenset()


# ---- issuance gating -------------------------------------------------------------------

def test_empty_allowlist_issues_v1():
    engine = _engine()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    permit = _issue(_issuer(engine), _license(now + timedelta(days=1)), now)
    assert permit["schema_version"] == 1
    assert "subscription_expires_at" not in permit
    assert permit["expires_at"] == "2026-09-03T12:15:00Z"  # 15-minute v1 ceiling


def test_nonmatching_allowlist_issues_v1():
    engine = _engine()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    other = ("c" * 40, MANIFEST_SHA, CHANNEL)
    permit = _issue(_issuer(engine, v2_releases=[other]), _license(now + timedelta(days=1)), now)
    assert permit["schema_version"] == 1
    assert "subscription_expires_at" not in permit


def test_malformed_allowlist_env_issues_v1():
    # from_environment with malformed v2 JSON must still issue v1, never crash.
    engine = _engine()
    env = {
        "SHUABAO_PERMIT_SIGNING_KEY_ID": "shuabao-test-1",
        "SHUABAO_APPROVED_RELEASES_JSON": json.dumps([{
            "source_sha": SOURCE_SHA,
            "release_manifest_sha256": MANIFEST_SHA,
            "release_channel": CHANNEL,
            "allowed_modes": ["lobby_hitch"],
        }]),
        "SHUABAO_OFFLINE_V2_RELEASES_JSON": "{not json",
    }
    issuer = PermitIssuer.from_environment(engine, env)
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    permit = _issue(issuer, _license(now + timedelta(days=1)), now)
    assert permit["schema_version"] == 1
    assert "subscription_expires_at" not in permit


def test_exact_approved_issues_v2_with_24h_cap():
    engine = _engine()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    # License far in the future so the 24h ceiling binds, not the subscription.
    license = _license(now + timedelta(days=30))
    permit = _issue(_issuer(engine, v2_releases=[V2_TRIPLE]), license, now)
    assert permit["schema_version"] == 2
    assert permit["issued_at"] == "2026-09-03T12:00:00Z"
    assert permit["expires_at"] == "2026-09-04T12:00:00Z"  # now + 24h
    assert permit["subscription_expires_at"] == "2026-10-03T12:00:00Z"
    issued = datetime.fromisoformat(permit["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(permit["expires_at"].replace("Z", "+00:00"))
    assert expires - issued == MAX_OFFLINE_PERMIT_LIFETIME
    # subscription_expires_at is signature-protected (round-trips through canonical payload).
    signature = base64.urlsafe_b64decode(
        str(permit["signature"]) + "=" * (-len(str(permit["signature"])) % 4)
    )
    engine.public_key.verify(signature, _canonical_payload(permit))


def test_v2_permit_preserves_server_license_features():
    engine = _engine()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    license = _license(now + timedelta(days=30))
    license.features.append("pip_background")
    permit = _issue(_issuer(engine, v2_releases=[V2_TRIPLE]), license, now)
    assert permit["schema_version"] == 2
    assert "pip_background" in permit["features"]


def test_short_subscription_caps_v2_below_24h():
    engine = _engine()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    # 6 hours of subscription left: expires_at must clamp to the subscription, not +24h.
    license = _license(now + timedelta(hours=6))
    permit = _issue(_issuer(engine, v2_releases=[V2_TRIPLE]), license, now)
    assert permit["schema_version"] == 2
    assert permit["expires_at"] == "2026-09-03T18:00:00Z"
    assert permit["subscription_expires_at"] == "2026-09-03T18:00:00Z"
    issued = datetime.fromisoformat(permit["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(permit["expires_at"].replace("Z", "+00:00"))
    assert expires - issued < MAX_OFFLINE_PERMIT_LIFETIME


def test_no_expiry_license_stays_v1_even_when_listed():
    engine = _engine()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    # Listed triple, but license has no expiry: never fabricate an offline entitlement.
    permit = _issue(_issuer(engine, v2_releases=[V2_TRIPLE]), _license(None), now)
    assert permit["schema_version"] == 1
    assert "subscription_expires_at" not in permit
    issued = datetime.fromisoformat(permit["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(permit["expires_at"].replace("Z", "+00:00"))
    assert expires - issued == MAX_PERMIT_LIFETIME


def test_listed_but_unapproved_release_never_issues_v2():
    # In the v2 allowlist but NOT in the approved-release registry => RELEASE_NOT_APPROVED.
    engine = _engine()
    issuer = PermitIssuer(
        engine,
        key_id="shuabao-test-1",
        approved_releases=[],  # no approvals at all
        offline_v2_releases=[V2_TRIPLE],
    )
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    with pytest.raises(PermitIssueError) as exc:
        _issue(issuer, _license(now + timedelta(days=1)), now)
    assert exc.value.code == "RELEASE_NOT_APPROVED"


def test_listed_but_blocked_release_never_issues_v2():
    engine = _engine()
    blocked = ApprovedRelease.from_mapping({
        "source_sha": SOURCE_SHA,
        "release_manifest_sha256": MANIFEST_SHA,
        "release_channel": CHANNEL,
        "allowed_modes": ["lobby_hitch"],
        "blocked": True,
    })
    issuer = PermitIssuer(
        engine, key_id="shuabao-test-1",
        approved_releases=[blocked], offline_v2_releases=[V2_TRIPLE],
    )
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    with pytest.raises(PermitIssueError) as exc:
        _issue(issuer, _license(now + timedelta(days=1)), now)
    assert exc.value.code == "RELEASE_BLOCKED"


def test_listed_but_mode_mismatch_never_issues_v2():
    engine = _engine()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    with pytest.raises(PermitIssueError) as exc:
        _issue(_issuer(engine, v2_releases=[V2_TRIPLE]), _license(now + timedelta(days=1)),
               now, mode="lead_team")
    assert exc.value.code == "MODE_NOT_ALLOWED"


def test_listed_but_expired_license_never_issues_v2():
    engine = _engine()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    with pytest.raises(PermitIssueError) as exc:
        _issue(_issuer(engine, v2_releases=[V2_TRIPLE]),
               _license(now - timedelta(minutes=1)), now)
    assert exc.value.code == "LICENSE_EXPIRED"


def test_listed_but_malformed_channel_request_never_issues_v2():
    # A request with a non-dev channel is malformed before any v2 decision.
    engine = _engine()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    with pytest.raises(PermitIssueError) as exc:
        _issuer(engine, v2_releases=[V2_TRIPLE]).issue(
            license=_license(now + timedelta(days=1)),
            hardware=HardwareFingerprint(fingerprint="device-test"),
            source_sha=SOURCE_SHA,
            release_manifest_sha256=MANIFEST_SHA,
            release_channel="stable",
            mode_id="lobby_hitch",
            now=now,
        )
    assert exc.value.code == "PERMIT_REQUEST_MALFORMED"
