"""Cross-repo SOURCE interop: server-issued permits verified by the REAL client verifier.

The client verifier (GameScript-Local/src/shuabao/subscription_permit.py) is loaded
read-only, by file path, as a standalone module (it imports only stdlib + cryptography,
no business modules). We never import the ``shuabao`` package or modify the client tree.

Resolution order for the client module path:
  1. env SHUABAO_CLIENT_PERMIT_MODULE (explicit override)
  2. the live client at ../GameScript-Local/src/shuabao/subscription_permit.py
  3. the read-only Root snapshot copy
The test is skipped (not failed) if none is present, so the server suite stays runnable
in isolation.

Positive: v2 (24h) and short-expiry v2 verify. Negatives: signature tamper, lifted
subscription_expires_at, wrong device/source/manifest/channel/mode. schema-1 still verifies.
"""
from __future__ import annotations

import importlib.util
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bridge.app.core.crypto import CryptoEngine
from bridge.app.services.permit_issuer import ApprovedRelease, PermitIssuer
from contracts.entitlement import HardwareFingerprint, LicenseDTO, LicenseStatus


SOURCE_SHA = "a" * 40
MANIFEST_SHA = "b" * 64
CHANNEL = "dev"
MODE = "lobby_hitch"
DEVICE = "interop-device"
V2_TRIPLE = (SOURCE_SHA, MANIFEST_SHA, CHANNEL)
KEY_ID = "shuabao-interop-key-1"


def _candidate_module_paths() -> list[Path]:
    paths: list[Path] = []
    override = os.environ.get("SHUABAO_CLIENT_PERMIT_MODULE")
    if override:
        paths.append(Path(override))
    repo_root = Path(__file__).resolve().parents[2]  # .../Subscription-Lab
    workspace = repo_root.parent  # .../刷刷宝
    paths.append(workspace / "GameScript-Local" / "src" / "shuabao" / "subscription_permit.py")
    paths.append(
        Path("D:/Temp/root-policy-acceptance-20261022-9a2f")
        / "src" / "shuabao" / "subscription_permit.py"
    )
    return paths


def _load_client_module():
    import sys

    for path in _candidate_module_paths():
        if path.is_file():
            name = "shuabao_client_permit_interop"
            spec = importlib.util.spec_from_file_location(name, path)
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            # dataclasses resolves cls.__module__ via sys.modules during class creation.
            sys.modules[name] = module
            spec.loader.exec_module(module)
            return module, path
    return None, None


_CLIENT, _CLIENT_PATH = _load_client_module()
pytestmark = pytest.mark.skipif(
    _CLIENT is None, reason="client subscription_permit.py not found (set SHUABAO_CLIENT_PERMIT_MODULE)"
)


@pytest.fixture
def engine() -> CryptoEngine:
    key = Ed25519PrivateKey.generate()
    return CryptoEngine(private_key_pem=key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))


def _issuer(engine: CryptoEngine, *, v2_releases=()) -> PermitIssuer:
    approval = ApprovedRelease.from_mapping({
        "source_sha": SOURCE_SHA,
        "release_manifest_sha256": MANIFEST_SHA,
        "release_channel": CHANNEL,
        "allowed_modes": [MODE, "normal_farm"],
    })
    return PermitIssuer(
        engine, key_id=KEY_ID, approved_releases=[approval], offline_v2_releases=v2_releases,
    )


def _license(expires_at):
    now = datetime.now(timezone.utc)
    return LicenseDTO(
        license_id="lic-interop", license_key="redacted", status=LicenseStatus.ACTIVE,
        plan="pro_monthly", customer_id="cust", created_at=now, expires_at=expires_at,
        device_limit=1, devices_used=1, features=["core", "automation"],
    )


def _public_keys(engine: CryptoEngine) -> dict:
    spki = engine.public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub = __import__("cryptography.hazmat.primitives.serialization",
                     fromlist=["load_der_public_key"]).load_der_public_key(spki)
    return {KEY_ID: pub}


def _issue_v2(engine, *, expires_at, now):
    return _issuer(engine, v2_releases=[V2_TRIPLE]).issue(
        license=_license(expires_at),
        hardware=HardwareFingerprint(fingerprint=DEVICE),
        source_sha=SOURCE_SHA, release_manifest_sha256=MANIFEST_SHA,
        release_channel=CHANNEL, mode_id=MODE, now=now,
    )


def _issue_v1(engine, *, expires_at, now):
    return _issuer(engine).issue(
        license=_license(expires_at),
        hardware=HardwareFingerprint(fingerprint=DEVICE),
        source_sha=SOURCE_SHA, release_manifest_sha256=MANIFEST_SHA,
        release_channel=CHANNEL, mode_id=MODE, now=now,
    )


def _context(now, **overrides):
    base = dict(device_id=DEVICE, source_sha=SOURCE_SHA,
                release_manifest_sha256=MANIFEST_SHA, release_channel=CHANNEL,
                mode_id=MODE, now=now)
    base.update(overrides)
    return _CLIENT.PermitVerificationContext(**base)


def _verify(engine, permit, context):
    verifier = _CLIENT.PermitVerifier(_public_keys(engine))
    parsed = _CLIENT.EntitlementPermit.from_mapping(permit)
    return verifier.verify(parsed, context)


# ---- positive ---------------------------------------------------------------------------

def test_client_accepts_server_v2_24h(engine):
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    permit = _issue_v2(engine, expires_at=now + timedelta(days=30), now=now)
    assert permit["schema_version"] == 2
    verified = _verify(engine, permit, _context(now + timedelta(hours=1)))
    assert verified.schema_version == 2
    assert verified.device_id == DEVICE


def test_client_accepts_server_v2_short_subscription(engine):
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    permit = _issue_v2(engine, expires_at=now + timedelta(hours=6), now=now)
    assert permit["schema_version"] == 2
    verified = _verify(engine, permit, _context(now + timedelta(hours=1)))
    assert verified.schema_version == 2


def test_client_accepts_server_v1(engine):
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    permit = _issue_v1(engine, expires_at=now + timedelta(days=30), now=now)
    assert permit["schema_version"] == 1
    verified = _verify(engine, permit, _context(now + timedelta(minutes=1)))
    assert verified.schema_version == 1


# ---- negatives --------------------------------------------------------------------------

def test_client_rejects_tampered_signature(engine):
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    permit = _issue_v2(engine, expires_at=now + timedelta(days=30), now=now)
    permit["features"] = list(permit["features"]) + ["smuggled"]  # break the signed payload
    with pytest.raises(_CLIENT.PermitVerificationError) as exc:
        _verify(engine, permit, _context(now + timedelta(hours=1)))
    assert exc.value.code == "PERMIT_SIGNATURE_INVALID"


def test_client_rejects_lifted_subscription_expiry(engine):
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    # 6h subscription -> expires_at is clamped to +6h. Forging subscription_expires_at
    # (without re-signing) cannot extend it: the signed field no longer matches.
    permit = _issue_v2(engine, expires_at=now + timedelta(hours=6), now=now)
    permit["subscription_expires_at"] = "2027-01-01T00:00:00Z"
    with pytest.raises(_CLIENT.PermitVerificationError) as exc:
        _verify(engine, permit, _context(now + timedelta(hours=1)))
    assert exc.value.code == "PERMIT_SIGNATURE_INVALID"


@pytest.mark.parametrize(("override", "code"), [
    ({"device_id": "other-device"}, "PERMIT_DEVICE_MISMATCH"),
    ({"source_sha": "c" * 40}, "PERMIT_SOURCE_MISMATCH"),
    ({"release_manifest_sha256": "c" * 64}, "PERMIT_MANIFEST_MISMATCH"),
    ({"release_channel": "release"}, "PERMIT_CHANNEL_MISMATCH"),
    ({"mode_id": "normal_farm"}, "PERMIT_MODE_NOT_ALLOWED"),
])
def test_client_rejects_binding_mismatch(engine, override, code):
    now = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    permit = _issue_v2(engine, expires_at=now + timedelta(days=30), now=now)
    with pytest.raises(_CLIENT.PermitVerificationError) as exc:
        _verify(engine, permit, _context(now + timedelta(hours=1), **override))
    assert exc.value.code == code
