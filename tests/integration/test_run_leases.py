"""v1 leases bind the requested run scope to server-held entitlements."""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from bridge.app import main
from bridge.app.core.crypto import CryptoEngine
from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
from bridge.app.services.event_processor import SqliteEventStore
from contracts.entitlement import HardwareFingerprint


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def lease_ctx(tmp_path, monkeypatch):
    store = SqliteEventStore(str(tmp_path / "leases.db"))
    provider = InMemoryKeygenProvider(CryptoEngine(), store)
    dto = run(provider.create_license("lease-test", "lease@example.invalid", "pro_monthly",
                                      features=["core", "pip_background"]))
    run(provider.activate_device(dto.license_key, HardwareFingerprint(fingerprint="device-a")))
    monkeypatch.setattr(main, "keygen_provider", provider)
    with TestClient(main.app) as client:
        yield provider, dto, client


@pytest.mark.parametrize("scope", ["core", "pip_background"])
def test_scope_survives_restart_and_pip_revocation_is_scoped(lease_ctx, scope):
    provider, dto, client = lease_ctx
    acquired = client.post("/v1/run/acquire", json={
        "license_key": dto.license_key, "fingerprint": "device-a", "scope": scope,
    })
    assert acquired.status_code == 200
    lease = acquired.json()
    required = ["core"] if scope == "core" else ["core", "pip_background"]
    assert lease["scope"] == scope and lease["required_features"] == required
    restarted = InMemoryKeygenProvider(provider.crypto, SqliteEventStore(provider.event_store.db_path))
    assert restarted.event_store.get_run_lease_by_id(lease["lease_id"])["required_features"] == required
    run(restarted.set_license_features(dto.license_id, ["core"], operation_id="remove-pip"))
    before = restarted.event_store.get_run_lease_by_id(lease["lease_id"])
    if scope == "pip_background":
        with pytest.raises(PermissionError, match="LEASE_REVOKED"):
            run(restarted.heartbeat_run_lease(lease["lease_id"], "device-a"))
        assert restarted.event_store.get_run_lease_by_id(lease["lease_id"]) == before
        core = run(restarted.acquire_run_lease(dto.license_key, "device-a"))
        assert run(restarted.heartbeat_run_lease(core["lease_id"], "device-a"))["scope"] == "core"
    else:
        assert run(restarted.heartbeat_run_lease(lease["lease_id"], "device-a"))["scope"] == "core"
    restarted.event_store._conn.close()


@pytest.mark.parametrize("scope", ["core", "pip_background"])
@pytest.mark.parametrize("change", ["revoke", "suspend", "expire", "unbind", "remove_core"])
def test_acquire_and_heartbeat_recheck_entitlement(lease_ctx, scope, change):
    provider, dto, client = lease_ctx
    lease = run(provider.acquire_run_lease(dto.license_key, "device-a", scope=scope))
    if change == "revoke":
        run(provider.revoke_license(dto.license_id))
    elif change == "suspend":
        run(provider.suspend_license(dto.license_id))
    elif change == "expire":
        run(provider.set_license_expiry(dto.license_id, datetime.now(timezone.utc) - timedelta(seconds=1)))
    elif change == "unbind":
        run(provider.deactivate_device(dto.license_key, "device-a"))
    else:
        run(provider.set_license_features(dto.license_id, ["pip_background"]))
    before = provider.event_store.get_run_lease_by_id(lease["lease_id"])
    response = client.post("/v1/run/heartbeat", json={
        "lease_id": lease["lease_id"], "fingerprint": "device-a",
        "scope": "core", "required_features": [],  # cannot downgrade a persisted PiP scope
    })
    assert response.status_code == 409 and response.json()["detail"] == "LEASE_REVOKED"
    response = client.post("/v1/run/acquire", json={
        "license_key": dto.license_key, "fingerprint": "device-a", "scope": scope,
    })
    assert response.status_code == 400
    assert provider.event_store.get_run_lease_by_id(lease["lease_id"]) == before


def test_default_core_and_forged_client_features(lease_ctx):
    provider, dto, client = lease_ctx
    run(provider.set_license_features(dto.license_id, ["core"]))
    body = {"license_key": dto.license_key, "fingerprint": "device-a"}
    old_client = client.post("/v1/run/acquire", json=body)
    assert old_client.status_code == 200
    assert old_client.json()["scope"] == "core" and old_client.json()["required_features"] == ["core"]
    forged = client.post("/v1/run/acquire", json={
        **body, "scope": "pip_background", "required_features": [], "features": ["pip_background"],
    })
    assert forged.status_code == 400 and forged.json()["detail"] == "FEATURE_NOT_ENTITLED"
    assert client.post("/v1/run/acquire", json={**body, "scope": "unknown"}).status_code == 400
    assert client.post("/v1/run/acquire", json={**body, "fingerprint": "device-b"}).status_code == 400


def test_kick_release_expired_lease_and_subscription_ttl_clamp(lease_ctx):
    provider, dto, client = lease_ctx
    run(provider.activate_device(dto.license_key, HardwareFingerprint(fingerprint="device-a")))
    first = run(provider.acquire_run_lease(dto.license_key, "device-a"))
    second = run(provider.acquire_run_lease(dto.license_key, "device-a", scope="pip_background"))
    with pytest.raises(PermissionError):
        run(provider.heartbeat_run_lease(first["lease_id"], "device-a"))
    with pytest.raises(PermissionError):
        run(provider.heartbeat_run_lease(second["lease_id"], "device-b"))
    assert not run(provider.release_run_lease(second["lease_id"], "device-b"))
    provider.event_store._conn.execute("UPDATE run_leases SET expires_at = ?",
                                      ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),))
    with pytest.raises(PermissionError):
        run(provider.heartbeat_run_lease(second["lease_id"], "device-a"))
    assert run(provider.release_run_lease(second["lease_id"], "device-a"))
    expiry = datetime.now(timezone.utc) + timedelta(seconds=90)
    run(provider.set_license_expiry(dto.license_id, expiry))
    lease = run(provider.acquire_run_lease(dto.license_key, "device-a", ttl_seconds=9999))
    assert datetime.fromisoformat(lease["expires_at"]) == expiry
    beat = run(provider.heartbeat_run_lease(lease["lease_id"], "device-a", ttl_seconds=9999))
    assert datetime.fromisoformat(beat["expires_at"]) == expiry


def test_old_database_scope_migration_is_repeatable(lease_ctx):
    provider, dto, _ = lease_ctx
    db = provider.event_store.db_path
    lease = run(provider.acquire_run_lease(dto.license_key, "device-a"))
    # Recreate the exact pre-scope schema, retaining its row.
    provider.event_store._conn.executescript("""
        ALTER TABLE run_leases RENAME TO run_leases_new;
        CREATE TABLE run_leases (
            license_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, lease_id TEXT UNIQUE NOT NULL,
            obtained_at TEXT NOT NULL, heartbeat_at TEXT NOT NULL, expires_at TEXT NOT NULL,
            previous_lease_id TEXT, kicked_fingerprint TEXT);
        INSERT INTO run_leases SELECT license_id, fingerprint, lease_id, obtained_at, heartbeat_at,
            expires_at, previous_lease_id, kicked_fingerprint FROM run_leases_new;
        DROP TABLE run_leases_new;
    """)
    for _ in range(2):
        upgraded = InMemoryKeygenProvider(provider.crypto, SqliteEventStore(db))
        row = upgraded.event_store.get_run_lease_by_id(lease["lease_id"])
        assert row["scope"] == "core" and row["required_features"] == ["core"]
        assert row["obtained_at"] == lease["obtained_at"]
        assert run(upgraded.heartbeat_run_lease(lease["lease_id"], "device-a"))["scope"] == "core"
        upgraded.event_store._conn.close()


@pytest.mark.parametrize("ttl", [-100, 0, 60, 300, 600, 601, 10**15])
def test_server_bounds_ttl_on_acquire_and_heartbeat(lease_ctx, ttl):
    provider, dto, client = lease_ctx
    body = {"license_key": dto.license_key, "fingerprint": "device-a", "ttl_seconds": ttl}
    acquired = client.post("/v1/run/acquire", json=body)
    assert acquired.status_code == 200
    lease = acquired.json()
    for endpoint in (None, "heartbeat"):
        before = datetime.now(timezone.utc)
        if endpoint:
            response = client.post("/v1/run/heartbeat", json={
                "lease_id": lease["lease_id"], "fingerprint": "device-a", "ttl_seconds": ttl})
            assert response.status_code == 200
            lease = response.json()
        expiry = datetime.fromisoformat(lease["expires_at"])
        expected = min(600, max(60, ttl))
        assert abs((expiry - before).total_seconds() - expected) < 2


def test_naive_legacy_license_and_lease_expiry_are_utc(lease_ctx):
    provider, dto, _ = lease_ctx
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=90)).replace(tzinfo=None)
    rec = provider.licenses[dto.license_id]
    rec["expires_at"] = expiry
    provider.event_store.save_local_license(rec["id"], rec["key"], rec)
    restarted = InMemoryKeygenProvider(provider.crypto, SqliteEventStore(provider.event_store.db_path))
    lease = run(restarted.acquire_run_lease(dto.license_key, "device-a"))
    assert datetime.fromisoformat(lease["expires_at"]) == expiry.replace(tzinfo=timezone.utc)
    restarted.event_store._conn.execute("UPDATE run_leases SET expires_at = ?", (expiry.isoformat(),))
    assert run(restarted.heartbeat_run_lease(lease["lease_id"], "device-a"))["expires_at"] == lease["expires_at"]
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).replace(tzinfo=None)
    restarted.event_store._conn.execute("UPDATE run_leases SET expires_at = ?", (expired.isoformat(),))
    with pytest.raises(PermissionError, match="^LEASE_REVOKED$"):
        run(restarted.heartbeat_run_lease(lease["lease_id"], "device-a"))
    restarted.licenses[dto.license_id]["expires_at"] = expired
    with pytest.raises(ValueError, match="^LICENSE_EXPIRED$"):
        run(restarted.acquire_run_lease(dto.license_key, "device-a"))
    restarted.event_store._conn.close()
