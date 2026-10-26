"""Local-only tests for the manually reviewed PiP entitlement."""
from __future__ import annotations

import asyncio
import base64
import json
from urllib.parse import unquote

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

SOURCE = "a" * 40
MANIFEST = "b" * 64
CHANNEL = "dev"


@pytest.fixture
def pip_ctx(monkeypatch, tmp_path):
    monkeypatch.setenv("SUBSCRIPTION_ADMIN_PASSWORD", "test-admin-pass-pip-strong")
    audit_path = tmp_path / "admin_audit.jsonl"
    monkeypatch.setenv("SUBSCRIPTION_ADMIN_AUDIT_LOG", str(audit_path))
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    engine = CryptoEngine(private_key_pem=pem)
    store = SqliteEventStore(":memory:")
    provider = InMemoryKeygenProvider(engine, store)
    release = ApprovedRelease.from_mapping({
        "source_sha": SOURCE,
        "release_manifest_sha256": MANIFEST,
        "release_channel": CHANNEL,
        "allowed_modes": ["lobby_hitch"],
    })
    issuer = PermitIssuer(
        engine,
        key_id="pip-test",
        approved_releases=[release],
        offline_v2_releases=[(SOURCE, MANIFEST, CHANNEL)],
    )
    monkeypatch.setattr(main, "keygen_provider", provider)
    monkeypatch.setattr(main, "permit_issuer", issuer)
    monkeypatch.setattr(main, "_STORE", store)
    auth = {"Authorization": "Basic " + base64.b64encode(
        b"admin:test-admin-pass-pip-strong"
    ).decode()}
    with TestClient(main.app, client=("127.0.0.1", 50000)) as client:
        yield client, provider, auth, audit_path


def _issue(client, auth, **values):
    response = client.post("/admin/licenses", data=values, headers=auth, follow_redirects=False)
    assert response.status_code == 303
    return asyncio.run(main.keygen_provider.list_licenses())[0]


def test_admin_pip_issue_and_unselected_v2_permits(pip_ctx):
    client, provider, auth, audit_path = pip_ctx
    unauthorized = client.post("/admin/licenses", data={
        "tier": "pro", "pip_background": "1",
    }, headers=auth, follow_redirects=False)
    assert "需要勾选确认" in unquote(unauthorized.headers["location"])
    assert asyncio.run(provider.list_licenses()) == []

    licensed = _issue(client, auth, tier="pro", pip_background="1", confirm_pip="1")
    plain = _issue(client, auth, tier="pro")
    assert licensed.pip_background is True
    assert "pip_background" in licensed.features
    extended = client.post(
        f"/admin/licenses/{licensed.license_id}/extend", data={"days": "1"},
        headers=auth, follow_redirects=False,
    )
    assert extended.status_code == 303
    assert "pip_background" in asyncio.run(provider.get_license(licensed.license_id)).features
    issue_events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert any(event["action"] == "issue_pip_background" and event["license_id"] == licensed.license_id
               for event in issue_events)
    assert plain.pip_background is False
    assert "pip_background" not in plain.features

    hardware = HardwareFingerprint(fingerprint="pip-entitlement-device")
    asyncio.run(provider.activate_device(licensed.license_key, hardware))
    result = client.post("/v1/entitlements/validate", json={
        "license_key": licensed.license_key,
        "hardware": hardware.model_dump(),
        "features": ["pip_background"],  # ignored; features come from the license record
        "permit_request": {
            "source_sha": SOURCE,
            "release_manifest_sha256": MANIFEST,
            "release_channel": CHANNEL,
            "mode_id": "lobby_hitch",
        },
    }).json()
    assert result["permit"]["schema_version"] == 2
    assert "pip_background" in result["permit"]["features"]
    assert "pip_background" in result["license"]["features"]
    offline = asyncio.run(provider.issue_offline_entitlement(licensed.license_key, hardware))
    assert "pip_background" in offline.features

    plain_hw = HardwareFingerprint(fingerprint="pip-entitlement-plain")
    asyncio.run(provider.activate_device(plain.license_key, plain_hw))
    result = client.post("/v1/entitlements/validate", json={
        "license_key": plain.license_key,
        "hardware": plain_hw.model_dump(),
        "features": ["pip_background"],
        "permit_request": {
            "source_sha": SOURCE,
            "release_manifest_sha256": MANIFEST,
            "release_channel": CHANNEL,
            "mode_id": "lobby_hitch",
        },
    }).json()
    assert result["permit"]["schema_version"] == 2
    assert "pip_background" not in result["permit"]["features"]


def test_existing_card_pip_switch_requires_confirm_and_audits(pip_ctx):
    client, provider, auth, audit_path = pip_ctx
    dto = _issue(client, auth, tier="pro")
    path = f"/admin/licenses/{dto.license_id}/pip-background"
    response = client.post(path, data={"pip_background": "1"}, headers=auth, follow_redirects=False)
    assert "确认" in unquote(response.headers["location"])
    assert "pip_background" not in asyncio.run(provider.get_license(dto.license_id)).features

    response = client.post(path, data={"pip_background": "1", "confirm_pip": "1"}, headers=auth)
    assert "pip_background" in asyncio.run(provider.get_license(dto.license_id)).features
    response = client.post(path, data={"pip_background": "0", "confirm_pip": "1"}, headers=auth)
    assert "pip_background" not in asyncio.run(provider.get_license(dto.license_id)).features

    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    changes = [event for event in events if event["action"] == "update_pip_background"]
    assert [(event["enabled"], event["license_id"]) for event in changes] == [
        (True, dto.license_id), (False, dto.license_id),
    ]


def test_trial_never_receives_pip_background(pip_ctx):
    client, provider, auth, _ = pip_ctx
    denied = client.post("/admin/licenses", data={
        "tier": "test", "pip_background": "1", "confirm_pip": "1",
    }, headers=auth, follow_redirects=False)
    assert "不能授权画中画" in unquote(denied.headers["location"])

    claimed = client.post("/v1/trials/claim", json={
        "hardware": {"fingerprint": "a" * 64, "components": {}, "platform": "windows"},
    })
    assert claimed.status_code == 200, claimed.text
    dto = asyncio.run(provider.get_license(claimed.json()["license_key"]))
    assert "pip_background" not in dto.features
    offline = asyncio.run(provider.issue_offline_entitlement(
        dto.license_key, HardwareFingerprint(fingerprint="a" * 64),
    ))
    assert "pip_background" not in offline.features
