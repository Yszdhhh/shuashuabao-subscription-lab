"""G2 thin release lifecycle matrix: blocked / advisory / status / admin."""
from __future__ import annotations

import asyncio
import base64
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

os.environ["SUBSCRIPTION_ADMIN_PASSWORD"] = "test-admin-pass-g2-strong"
os.environ["SUBSCRIPTION_ADMIN_USER"] = "admin"
os.environ.setdefault("PROVIDER_MODE", "inmemory")

from bridge.app import main
from bridge.app.core.crypto import CryptoEngine
from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
from bridge.app.services.event_processor import SqliteEventStore
from bridge.app.services.permit_issuer import ApprovedRelease, PermitIssuer
from contracts.entitlement import HardwareFingerprint


SOURCE = "a" * 40
MANIFEST = "b" * 64
CHANNEL = "dev"
MODE = "lobby_hitch"
REC_SOURCE = "c" * 40
REC_MANIFEST = "d" * 64


def _auth() -> dict:
    user = os.environ.get("SUBSCRIPTION_ADMIN_USER") or "admin"
    password = os.environ.get("SUBSCRIPTION_ADMIN_PASSWORD") or ""
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _engine() -> CryptoEngine:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return CryptoEngine(private_key_pem=pem)


@pytest.fixture
def lifecycle_ctx(monkeypatch):
    store = SqliteEventStore(":memory:")
    engine = _engine()
    provider = InMemoryKeygenProvider(engine, store)
    hardware = HardwareFingerprint(fingerprint="g2-lifecycle-device")

    async def activate():
        lic = await provider.create_license(
            "g2-lifecycle", "g2@example.invalid", "pro_monthly", 1
        )
        await provider.activate_device(lic.license_key, hardware)
        return lic

    license = asyncio.run(activate())
    issuer = PermitIssuer(engine, key_id="g2-lifecycle-test", policy_store=store)
    monkeypatch.setattr(main, "keygen_provider", provider)
    monkeypatch.setattr(main, "permit_issuer", issuer)
    monkeypatch.setattr(main, "_STORE", store)
    request = {
        "license_key": license.license_key,
        "hardware": hardware.model_dump(),
    }
    with TestClient(main.app) as client:
        yield client, request, store, issuer


def _upsert(store: SqliteEventStore, **kwargs):
    base = {
        "source_sha": SOURCE,
        "release_manifest_sha256": MANIFEST,
        "release_channel": CHANNEL,
        "allowed_modes": [MODE, "normal_farm"],
        "blocked": False,
        "advisory": None,
        "updated_by": "test",
    }
    base.update(kwargs)
    store.upsert_release_policy(**base)


def test_blocked_identity_denies_even_with_allowed_modes(lifecycle_ctx):
    client, request, store, _ = lifecycle_ctx
    _upsert(store, blocked=True, allowed_modes=[MODE, "normal_farm"])
    response = client.post(
        "/v1/entitlements/validate",
        json={
            **request,
            "permit_request": {
                "source_sha": SOURCE,
                "release_manifest_sha256": MANIFEST,
                "release_channel": CHANNEL,
                "mode_id": MODE,
            },
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["can_start_runner"] is False
    assert body["code"] == "RELEASE_BLOCKED"
    assert body["permit"] is None
    assert body["release_status"]["blocked"] is True
    assert body["release_status"]["status"] == "blocked"


@pytest.mark.parametrize("advisory", ["recommended", "outdated"])
def test_approved_advisory_issues_permit_outside_signature(lifecycle_ctx, advisory):
    client, request, store, engine_holder = lifecycle_ctx
    _upsert(
        store,
        advisory=advisory,
        recommended_source_sha=REC_SOURCE,
        recommended_manifest_sha256=REC_MANIFEST,
        recommended_channel="external-beta",
        operator_note="please upgrade when convenient",
    )
    response = client.post(
        "/v1/entitlements/validate",
        json={
            **request,
            "permit_request": {
                "source_sha": SOURCE,
                "release_manifest_sha256": MANIFEST,
                "release_channel": CHANNEL,
                "mode_id": MODE,
            },
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["can_start_runner"] is True
    permit = body["permit"]
    assert permit is not None
    assert "advisory" not in permit
    assert "recommended" not in permit
    assert "blocked" not in permit
    assert "operator_note" not in permit
    assert "release_status" not in permit
    assert set(permit.keys()) >= {
        "schema_version",
        "source_sha",
        "release_manifest_sha256",
        "release_channel",
        "allowed_modes",
        "signature",
        "key_id",
    }
    status = body["release_status"]
    assert status["approved"] is True
    assert status["advisory"] == advisory
    assert status[advisory] is True
    assert status["recommended_release"]["source_sha"] == REC_SOURCE
    assert "operator_note" not in status
    assert "updated_by" not in status
    assert "updated_at" not in status
    # public message must be generic, not the ops note
    assert status["message"] != "please upgrade when convenient"


def test_not_approved_returns_release_not_approved(lifecycle_ctx):
    client, request, store, _ = lifecycle_ctx
    response = client.post(
        "/v1/entitlements/validate",
        json={
            **request,
            "permit_request": {
                "source_sha": SOURCE,
                "release_manifest_sha256": MANIFEST,
                "release_channel": CHANNEL,
                "mode_id": MODE,
            },
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["code"] == "RELEASE_NOT_APPROVED"
    assert body["permit"] is None
    assert body["release_status"]["status"] == "not_approved"
    assert body["release_status"]["approved"] is False


def test_wrong_mode_returns_mode_not_allowed(lifecycle_ctx):
    client, request, store, _ = lifecycle_ctx
    _upsert(store)
    response = client.post(
        "/v1/entitlements/validate",
        json={
            **request,
            "permit_request": {
                "source_sha": SOURCE,
                "release_manifest_sha256": MANIFEST,
                "release_channel": CHANNEL,
                "mode_id": "lead_team",
            },
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["code"] == "MODE_NOT_ALLOWED"
    assert body["permit"] is None
    assert body["release_status"]["approved"] is True
    assert "lead_team" not in body["release_status"]["allowed_modes"]


def test_status_api_shape(lifecycle_ctx):
    client, _, store, _ = lifecycle_ctx
    empty = client.get(
        "/v1/releases/status",
        params={
            "source_sha": SOURCE,
            "release_manifest_sha256": MANIFEST,
            "release_channel": CHANNEL,
        },
    )
    assert empty.status_code == 200
    assert empty.json()["status"] == "not_approved"
    assert empty.json()["approved"] is False

    _upsert(store, advisory="recommended", recommended_source_sha=REC_SOURCE,
            recommended_manifest_sha256=REC_MANIFEST, recommended_channel="release")
    ok = client.get(
        "/v1/releases/status",
        params={
            "source_sha": SOURCE,
            "release_manifest_sha256": MANIFEST,
            "release_channel": CHANNEL,
        },
    )
    body = ok.json()
    assert body["status"] == "approved"
    assert body["advisory"] == "recommended"
    assert "hot_update" not in body
    assert "remote_control" not in body
    assert "payload" not in body
    assert "operator_note" not in body
    assert "updated_by" not in body
    assert "updated_at" not in body


def test_admin_json_upsert_requires_auth_and_blocks(lifecycle_ctx):
    client, request, store, _ = lifecycle_ctx
    denied = client.put(
        "/v1/admin/releases",
        json={
            "source_sha": SOURCE,
            "release_manifest_sha256": MANIFEST,
            "release_channel": CHANNEL,
            "allowed_modes": [MODE],
            "blocked": True,
        },
    )
    assert denied.status_code == 401

    upsert = client.put(
        "/v1/admin/releases",
        headers=_auth(),
        json={
            "source_sha": SOURCE,
            "release_manifest_sha256": MANIFEST,
            "release_channel": CHANNEL,
            "allowed_modes": [MODE, "normal_farm"],
            "blocked": True,
            "advisory": "outdated",
            "operator_note": "ops block",
        },
    )
    assert upsert.status_code == 200
    assert upsert.json()["release_status"]["blocked"] is True

    listed = client.get("/v1/admin/releases", headers=_auth())
    assert listed.status_code == 200
    assert any(p["blocked"] for p in listed.json()["policies"])

    page = client.get("/admin/releases", headers=_auth())
    assert page.status_code == 200
    assert SOURCE in page.text

    validate = client.post(
        "/v1/entitlements/validate",
        json={
            **request,
            "permit_request": {
                "source_sha": SOURCE,
                "release_manifest_sha256": MANIFEST,
                "release_channel": CHANNEL,
                "mode_id": MODE,
            },
        },
    )
    assert validate.json()["code"] == "RELEASE_BLOCKED"


def test_env_seed_preserves_ops_blocked_flag():
    store = SqliteEventStore(":memory:")
    store.upsert_release_policy(
        source_sha=SOURCE,
        release_manifest_sha256=MANIFEST,
        release_channel=CHANNEL,
        allowed_modes=[MODE],
        blocked=True,
        advisory="outdated",
        operator_note="do not clear",
        updated_by="ops",
    )
    engine = _engine()
    env = {
        "SHUABAO_PERMIT_SIGNING_KEY_ID": "seed-test",
        "SHUABAO_APPROVED_RELEASES_JSON": json.dumps(
            [
                {
                    "source_sha": SOURCE,
                    "release_manifest_sha256": MANIFEST,
                    "release_channel": CHANNEL,
                    "allowed_modes": [MODE, "normal_farm"],
                }
            ]
        ),
    }
    issuer = PermitIssuer.from_environment(engine, env, policy_store=store)
    row = store.get_release_policy(SOURCE, MANIFEST, CHANNEL)
    assert row["blocked"] is True
    assert row["advisory"] == "outdated"
    assert row["operator_note"] == "do not clear"
    assert set(row["allowed_modes"]) == {MODE, "normal_farm"}
    with pytest.raises(Exception) as exc:
        issuer.issue(
            license=__import__("contracts.entitlement", fromlist=["LicenseDTO"]).LicenseDTO(
                license_id="x",
                license_key="y",
                status=__import__("contracts.entitlement", fromlist=["LicenseStatus"]).LicenseStatus.ACTIVE,
                plan="pro_monthly",
                customer_id="c",
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
                features=["core"],
            ),
            hardware=HardwareFingerprint(fingerprint="seed-device"),
            source_sha=SOURCE,
            release_manifest_sha256=MANIFEST,
            release_channel=CHANNEL,
            mode_id=MODE,
        )
    assert exc.value.code == "RELEASE_BLOCKED"



def test_env_seed_preserves_recommended_fields():
    """Restart/re-seed without recommended_* in JSON must not wipe DB pointers."""
    store = SqliteEventStore(":memory:")
    store.upsert_release_policy(
        source_sha=SOURCE,
        release_manifest_sha256=MANIFEST,
        release_channel=CHANNEL,
        allowed_modes=[MODE],
        blocked=False,
        advisory="recommended",
        recommended_source_sha=REC_SOURCE,
        recommended_manifest_sha256=REC_MANIFEST,
        recommended_channel="external-beta",
        operator_note="keep me",
        updated_by="ops",
    )
    engine = _engine()
    env = {
        "SHUABAO_PERMIT_SIGNING_KEY_ID": "seed-rec-test",
        "SHUABAO_APPROVED_RELEASES_JSON": json.dumps(
            [
                {
                    "source_sha": SOURCE,
                    "release_manifest_sha256": MANIFEST,
                    "release_channel": CHANNEL,
                    "allowed_modes": [MODE, "normal_farm"],
                }
            ]
        ),
    }
    PermitIssuer.from_environment(engine, env, policy_store=store)
    row = store.get_release_policy(SOURCE, MANIFEST, CHANNEL)
    assert row["recommended_source_sha"] == REC_SOURCE
    assert row["recommended_manifest_sha256"] == REC_MANIFEST
    assert row["recommended_channel"] == "external-beta"
    assert row["advisory"] == "recommended"
    assert row["operator_note"] == "keep me"
    assert set(row["allowed_modes"]) == {MODE, "normal_farm"}


def test_admin_status_keeps_ops_fields_while_public_redacts(lifecycle_ctx):
    client, _, store, _ = lifecycle_ctx
    _upsert(
        store,
        advisory="outdated",
        operator_note="internal-only-note",
        recommended_source_sha=REC_SOURCE,
        recommended_manifest_sha256=REC_MANIFEST,
        recommended_channel="release",
    )
    public = client.get(
        "/v1/releases/status",
        params={
            "source_sha": SOURCE,
            "release_manifest_sha256": MANIFEST,
            "release_channel": CHANNEL,
        },
    ).json()
    assert "operator_note" not in public
    assert "updated_by" not in public
    assert public["message"] != "internal-only-note"

    admin = client.put(
        "/v1/admin/releases",
        headers=_auth(),
        json={
            "source_sha": SOURCE,
            "release_manifest_sha256": MANIFEST,
            "release_channel": CHANNEL,
            "allowed_modes": [MODE],
            "blocked": False,
            "advisory": "outdated",
            "operator_note": "internal-only-note",
            "recommended_source_sha": REC_SOURCE,
            "recommended_manifest_sha256": REC_MANIFEST,
            "recommended_channel": "release",
        },
    )
    assert admin.status_code == 200
    admin_status = admin.json()["release_status"]
    assert admin_status.get("operator_note") == "internal-only-note" or admin_status.get("message") == "internal-only-note"
    assert "updated_by" in admin_status


def test_health_exposes_safe_service_revision(lifecycle_ctx, monkeypatch):
    client, _, _, _ = lifecycle_ctx
    monkeypatch.delenv("SHUABAO_SERVICE_REVISION", raising=False)
    monkeypatch.delenv("SHUABAO_DEPLOYMENT_ID", raising=False)
    body = client.get("/health").json()
    assert body["status"] == "healthy"
    assert "service_revision" not in body

    monkeypatch.setenv("SHUABAO_SERVICE_REVISION", "g2-sha-deadbeef")
    body = client.get("/health").json()
    assert body["service_revision"] == "g2-sha-deadbeef"

    monkeypatch.setenv("SHUABAO_SERVICE_REVISION", "/etc/passwd")
    assert "service_revision" not in client.get("/health").json()
