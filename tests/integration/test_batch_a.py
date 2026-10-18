"""BATCH A targeted tests (r3): persist-then-apply atomicity, bind checks before binding, REVOKED
terminal in validate, lic_/h: never a secret, no key echo. Legacy (old Windows client / prod
trial-claim) contract diffs are covered by batch_a_diff.py + tc_proxy_bind_check.py."""
import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from contracts.entitlement import HardwareFingerprint, LicenseStatus
from bridge.app.core.crypto import CryptoEngine
from bridge.app.main import app
from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
from bridge.app.services.event_processor import SqliteEventStore


def run(c):
    return asyncio.run(c)


def prov(db):
    return InMemoryKeygenProvider(CryptoEngine(), SqliteEventStore(db))


def hw(fp="a" * 64):
    return HardwareFingerprint(fingerprint=fp, components={}, platform="windows")


@pytest.fixture()
def db(tmp_path):
    return str(tmp_path / "a.db")


def mk(p, days=30, meta=None):
    return run(p.create_license(customer_id="ba", customer_email="ba@example.invalid", plan="pro",
                                duration_days=days, device_limit=2, metadata=meta or {}))


def rows(db, lid):
    c = sqlite3.connect(db)
    try:
        return c.execute("SELECT COUNT(*) FROM local_activations WHERE license_id=?", (lid,)).fetchone()[0]
    finally:
        c.close()


@pytest.mark.parametrize("op", ["revoke", "suspend", "renew", "reinstate"])
def test_failed_write_leaves_memory_unchanged(db, op):
    p = prov(db)
    lic = mk(p)
    if op == "reinstate":
        run(p.suspend_license(lic.license_id))
    before = dict(p.licenses[lic.license_id])

    def boom(*a, **k):
        raise sqlite3.OperationalError("disk I/O error (simulated)")

    p.event_store.save_local_license = boom
    with pytest.raises(sqlite3.OperationalError):
        if op == "revoke":
            run(p.revoke_license(lic.license_id))
        elif op == "suspend":
            run(p.suspend_license(lic.license_id))
        elif op == "renew":
            run(p.renew_license(lic.license_id, extend_days=30))
        else:
            run(p.reinstate_license(lic.license_id))
    after = p.licenses[lic.license_id]
    assert after["status"] == before["status"] and after["expires_at"] == before["expires_at"]
    assert after["suspended"] == before["suspended"]


def test_revoke_persists_and_records_time(db):
    p = prov(db)
    lic = mk(p)
    run(p.revoke_license(lic.license_id, reason="refund"))
    rec = prov(db).licenses[lic.license_id]
    assert rec["status"] == LicenseStatus.REVOKED
    assert rec["metadata"]["revoke_reason"] == "refund" and rec["metadata"].get("revoked_at")


@pytest.mark.parametrize("state", ["revoked", "suspended", "expired_beyond_grace"])
def test_bind_rejected_before_binding(db, state):
    p = prov(db)
    lic = mk(p, meta={"grace_days": 0} if state == "expired_beyond_grace" else None)
    if state == "revoked":
        run(p.revoke_license(lic.license_id)); code = "LICENSE_REVOKED"
    elif state == "suspended":
        run(p.suspend_license(lic.license_id)); code = "LICENSE_SUSPENDED"
    else:
        p.licenses[lic.license_id]["expires_at"] = datetime.now(timezone.utc) - timedelta(minutes=1); code = "LICENSE_EXPIRED"
    with pytest.raises(ValueError) as e:
        run(p.activate_device(lic.license_key, hw()))
    assert str(e.value).startswith(code)
    assert lic.license_key not in str(e.value)
    assert rows(db, lic.license_id) == 0 and not p.activations.get(lic.license_id)


def test_bind_allowed_inside_grace(db):
    p = prov(db)
    lic = mk(p)  # default grace 3 days
    p.licenses[lic.license_id]["expires_at"] = datetime.now(timezone.utc) - timedelta(days=1)
    run(p.activate_device(lic.license_key, hw()))
    assert rows(db, lic.license_id) == 1


def test_revoked_is_terminal_in_validate_even_when_expired(db):
    p = prov(db)
    lic = mk(p)
    run(p.activate_device(lic.license_key, hw()))
    run(p.revoke_license(lic.license_id))
    p.licenses[lic.license_id]["expires_at"] = datetime.now(timezone.utc) - timedelta(hours=1)
    r = run(p.validate_license(lic.license_key, fingerprint="a" * 64))
    assert r.valid is False and r.status == LicenseStatus.REVOKED


def test_unknown_key_error_does_not_echo_key(db):
    p = prov(db)
    with pytest.raises(ValueError) as e:
        run(p.activate_device("SSB-AAAA-BBBB-CCCC", hw()))
    assert "SSB-AAAA" not in str(e.value) and str(e.value).startswith("LICENSE_NOT_FOUND")
    with pytest.raises(ValueError) as e:
        run(p.acquire_run_lease("SSB-AAAA-BBBB-CCCC", "a" * 64))
    assert "SSB-AAAA" not in str(e.value)


client = TestClient(app)


@pytest.mark.parametrize("path,body", [
    ("/v1/entitlements/validate", {"license_key": "lic_0123456789abcdef", "hardware": {"fingerprint": "b" * 64}}),
    ("/v1/devices/activate", {"license_key": "lic_0123456789abcdef", "hardware": {"fingerprint": "b" * 64}}),
    ("/v1/run/acquire", {"license_key": "lic_0123456789abcdef", "fingerprint": "b" * 64}),
    ("/v1/devices/deactivate", {"license_key": "h:00", "fingerprint": "b" * 64}),
])
def test_public_id_or_hash_marker_is_never_a_secret(path, body):
    r = client.post(path, json=body)
    j = r.json()
    if path.endswith("validate"):
        assert r.status_code == 200 and j["valid"] is False and j["code"] == "NOT_FOUND"
    elif path.endswith("deactivate"):
        assert r.status_code == 200 and j == {"success": False}
    else:
        assert r.status_code == 400 and j["detail"].startswith("LICENSE_NOT_FOUND")
