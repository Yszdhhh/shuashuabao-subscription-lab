"""Endpoint-level check that /v1/entitlements/validate naturally issues schema 2
through the issuer decision, while unlisted releases keep the legacy v1 path.

Ephemeral Ed25519 keys + in-memory provider + in-memory DB only. No real keys/DB.
"""
import asyncio
import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from bridge.app import main
from bridge.app.core.crypto import CryptoEngine
from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
from bridge.app.services.event_processor import SqliteEventStore
from bridge.app.services.permit_issuer import ApprovedRelease, PermitIssuer
from contracts.entitlement import HardwareFingerprint


RELEASE = {
    "source_sha": "a" * 40,
    "release_manifest_sha256": "b" * 64,
    "release_channel": "dev",
    "mode_id": "lobby_hitch",
}
V2_TRIPLE = (RELEASE["source_sha"], RELEASE["release_manifest_sha256"], RELEASE["release_channel"])


def _make_context(monkeypatch, *, v2_releases, expires_at):
    private_key = Ed25519PrivateKey.generate()
    engine = CryptoEngine(private_key_pem=private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    provider = InMemoryKeygenProvider(engine, SqliteEventStore(":memory:"))
    hardware = HardwareFingerprint(fingerprint="permit-endpoint-v2-device")

    async def activate_license():
        license = await provider.create_license(
            "permit-v2-test", "permit-v2@example.invalid", "pro_monthly", 1,
        )
        if expires_at is not None:
            await provider.set_license_expiry(license.license_id, expires_at)
        await provider.activate_device(license.license_key, hardware)
        return await provider.get_license(license.license_id)

    license = asyncio.run(activate_license())
    approval = ApprovedRelease.from_mapping({
        "source_sha": RELEASE["source_sha"],
        "release_manifest_sha256": RELEASE["release_manifest_sha256"],
        "release_channel": RELEASE["release_channel"],
        "allowed_modes": ["normal_farm", "lobby_hitch"],
    })
    monkeypatch.setattr(main, "keygen_provider", provider)
    monkeypatch.setattr(main, "permit_issuer", PermitIssuer(
        engine, key_id="permit-endpoint-v2-test",
        approved_releases=[approval], offline_v2_releases=v2_releases,
    ))
    request = {"license_key": license.license_key, "hardware": hardware.model_dump()}
    return engine, request


def _verify_signature(engine, permit):
    signature = permit.pop("signature")
    payload = json.dumps(
        permit, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    engine.public_key.verify(
        base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), payload,
    )


def test_endpoint_unlisted_release_still_issues_v1(monkeypatch):
    # Empty v2 allowlist: the existing client request path is unchanged (schema 1).
    engine, request = _make_context(
        monkeypatch, v2_releases=(),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    with TestClient(main.app, client=("127.0.0.1", 50000)) as client:
        response = client.post("/v1/entitlements/validate", json={
            **request, "permit_request": RELEASE,
        })
    assert response.status_code == 200
    result = response.json()
    assert result["can_start_runner"] is True
    permit = result["permit"]
    assert permit["schema_version"] == 1
    assert "subscription_expires_at" not in permit
    _verify_signature(engine, permit)


def test_endpoint_listed_eligible_release_issues_verified_v2(monkeypatch):
    engine, request = _make_context(
        monkeypatch, v2_releases=[V2_TRIPLE],
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    with TestClient(main.app, client=("127.0.0.1", 50000)) as client:
        response = client.post("/v1/entitlements/validate", json={
            **request, "permit_request": RELEASE,
        })
    assert response.status_code == 200
    result = response.json()
    assert result["can_start_runner"] is True
    permit = result["permit"]
    assert permit["schema_version"] == 2
    assert permit["subscription_expires_at"]
    issued = datetime.fromisoformat(permit["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(permit["expires_at"].replace("Z", "+00:00"))
    assert timedelta(0) < expires - issued <= timedelta(hours=24)
    _verify_signature(engine, permit)
