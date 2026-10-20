"""Exercise the HTTP permit boundary with ephemeral keys and in-memory licenses."""
import asyncio
import base64
import json
from datetime import datetime, timedelta

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


@pytest.fixture
def permit_context(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    engine = CryptoEngine(private_key_pem=private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    provider = InMemoryKeygenProvider(engine, SqliteEventStore(":memory:"))
    hardware = HardwareFingerprint(fingerprint="permit-endpoint-test-device")

    async def activate_license():
        license = await provider.create_license(
            "permit-endpoint-test", "permit@example.invalid", "pro_monthly", 1,
        )
        await provider.activate_device(license.license_key, hardware)
        return license

    license = asyncio.run(activate_license())
    approval = ApprovedRelease.from_mapping({
        **RELEASE,
        "allowed_modes": ["normal_farm", "lobby_hitch"],
    })
    monkeypatch.setattr(main, "keygen_provider", provider)
    monkeypatch.setattr(main, "permit_issuer", PermitIssuer(
        engine, key_id="permit-endpoint-test", approved_releases=[approval],
    ))
    request = {
        "license_key": license.license_key,
        "hardware": hardware.model_dump(),
    }
    with TestClient(main.app, client=("127.0.0.1", 50000)) as client:
        yield client, request, engine


def test_entitlement_query_does_not_issue_permit(permit_context):
    client, request, _ = permit_context
    response = client.post("/v1/entitlements/validate", json=request)
    assert response.status_code == 200
    result = response.json()
    assert result["valid"] is True
    assert result["can_start_runner"] is True
    assert result["permit"] is None


@pytest.mark.parametrize(("override", "code"), [
    ({"source_sha": "c" * 40}, "RELEASE_NOT_APPROVED"),
    ({"release_manifest_sha256": "c" * 64}, "RELEASE_NOT_APPROVED"),
    ({"release_channel": "internal-pilot"}, "RELEASE_NOT_APPROVED"),
    ({"release_channel": "stable"}, "PERMIT_REQUEST_MALFORMED"),
    ({"mode_id": "lead_team"}, "MODE_NOT_ALLOWED"),
])
def test_rejected_permit_request_returns_no_permit(permit_context, override, code):
    client, request, _ = permit_context
    response = client.post("/v1/entitlements/validate", json={
        **request, "permit_request": {**RELEASE, **override},
    })
    assert response.status_code == 200
    result = response.json()
    assert result["can_start_runner"] is False
    assert result["code"] == code
    assert result["permit"] is None


def test_approved_permit_request_returns_verified_release_signature(permit_context):
    client, request, engine = permit_context
    response = client.post("/v1/entitlements/validate", json={
        **request, "permit_request": RELEASE,
    })
    assert response.status_code == 200
    result = response.json()
    assert result["can_start_runner"] is True
    permit = result["permit"]
    for field in ("source_sha", "release_manifest_sha256", "release_channel"):
        assert permit[field] == RELEASE[field]
    assert permit["allowed_modes"] == [RELEASE["mode_id"]]
    assert permit["device_fingerprint"] == request["hardware"]["fingerprint"]
    issued_at = datetime.fromisoformat(permit["issued_at"].replace("Z", "+00:00"))
    expires_at = datetime.fromisoformat(permit["expires_at"].replace("Z", "+00:00"))
    assert timedelta(0) < expires_at - issued_at <= timedelta(minutes=15)
    signature = permit.pop("signature")
    payload = json.dumps(
        permit, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    engine.public_key.verify(
        base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), payload,
    )


def test_missing_permit_signer_returns_no_permit(permit_context, monkeypatch):
    client, request, engine = permit_context
    monkeypatch.setattr(main, "permit_issuer", PermitIssuer(
        engine, key_id="", approved_releases=[],
    ))
    response = client.post("/v1/entitlements/validate", json={
        **request, "permit_request": RELEASE,
    })
    assert response.status_code == 200
    result = response.json()
    assert result["can_start_runner"] is False
    assert result["code"] == "PERMIT_SIGNER_NOT_CONFIGURED"
    assert result["permit"] is None


def test_missing_permit_hardware_returns_no_permit(permit_context):
    client, request, _ = permit_context
    response = client.post("/v1/entitlements/validate", json={
        "license_key": request["license_key"], "permit_request": RELEASE,
    })
    assert response.status_code == 200
    result = response.json()
    assert result["can_start_runner"] is False
    assert result["code"] == "PERMIT_CONTEXT_MISSING"
    assert result["permit"] is None


@pytest.mark.parametrize("fingerprint", ["", " \t\r\n "])
def test_blank_activated_device_cannot_receive_permit(permit_context, fingerprint):
    client, request, _ = permit_context

    async def replace_activation():
        await main.keygen_provider.deactivate_device(
            request["license_key"], request["hardware"]["fingerprint"],
        )
        await main.keygen_provider.activate_device(
            request["license_key"], HardwareFingerprint(fingerprint=fingerprint),
        )

    asyncio.run(replace_activation())
    response = client.post("/v1/entitlements/validate", json={
        **request,
        "hardware": {**request["hardware"], "fingerprint": fingerprint},
        "permit_request": RELEASE,
    })
    assert response.status_code == 200
    result = response.json()
    assert result["can_start_runner"] is False
    assert result["code"] == "PERMIT_CONTEXT_MISSING"
    assert result["permit"] is None
