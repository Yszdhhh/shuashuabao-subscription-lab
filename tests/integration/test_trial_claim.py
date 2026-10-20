"""Self-service 1-day device trial: POST /v1/trials/claim."""
import asyncio
import os
import secrets
import threading
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
from bridge.app.services.trial_claim import (
    SlidingWindowLimiter,
    TrialClaimError,
    TrialRateLimits,
    client_ip_key,
    normalize_fingerprint,
    trials_enabled,
)
from contracts.entitlement import HardwareFingerprint, LicenseStatus

RELEASE = {
    "source_sha": "e3ca3f0c7a00df8187b7b4db1177f58a392754bc",
    "release_manifest_sha256": "a25615c39ae8adbdb9521ab55b5de02c13fb0d83f579f188f3f40b43ef8ad2cb",
    "release_channel": "internal-pilot",
    "mode_id": "normal_farm",
}


def _fp() -> str:
    return secrets.token_hex(32)


def _hw(fp: str, host: str = "trial-pc") -> dict:
    return {"fingerprint": fp, "components": {}, "platform": "windows", "hostname": host}


def _engine() -> CryptoEngine:
    key = Ed25519PrivateKey.generate()
    return CryptoEngine(private_key_pem=key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))


@pytest.fixture
def ctx(monkeypatch):
    engine = _engine()
    provider = InMemoryKeygenProvider(engine, SqliteEventStore(":memory:"))
    monkeypatch.setattr(main, "keygen_provider", provider)
    monkeypatch.setattr(main, "_TRIAL_RATE_LIMITS", TrialRateLimits({}))
    monkeypatch.setattr(main, "permit_issuer", PermitIssuer(
        engine,
        key_id="trial-test",
        approved_releases=[ApprovedRelease.from_mapping({
            **RELEASE, "allowed_modes": ["normal_farm", "lobby_hitch"],
        })],
    ))
    monkeypatch.delenv("SHUABAO_TRIALS_ENABLED", raising=False)
    with TestClient(main.app) as client:
        yield client, provider


def _claim(client, fp, ip="198.51.100.7"):
    return client.post(
        "/v1/trials/claim", json={"hardware": _hw(fp)}, headers={"CF-Connecting-IP": ip}
    )


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def test_first_claim_creates_bound_one_day_trial(ctx):
    client, provider = ctx
    fp = _fp()
    before = datetime.now(timezone.utc).replace(microsecond=0)
    resp = _claim(client, fp)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True and set(body) == {"ok", "license_key", "expires_at", "plan", "tier", "tier_name"}  # BATCH C additive
    assert body["license_key"].startswith("SSB-")
    assert body["expires_at"].endswith("Z")
    exp = _parse(body["expires_at"])
    assert timedelta(hours=24) <= exp - before <= timedelta(hours=24, seconds=5)
    dto = asyncio.run(provider.get_license(body["license_key"]))
    assert dto.plan == "trial_1d_auto"
    assert dto.customer_id.startswith("trial-auto-")
    assert dto.device_limit == 1 and dto.devices_used == 1
    assert dto.metadata["is_trial"] is True
    devices = asyncio.run(provider.get_devices(dto.license_id))
    assert [d.fingerprint for d in devices] == [fp]


def test_repeat_claim_returns_same_key_and_expiry(ctx):
    client, _ = ctx
    fp = _fp()
    first = _claim(client, fp).json()
    for _ in range(3):
        again = _claim(client, fp)
        assert again.status_code == 200
        assert again.json() == first


def test_fingerprint_is_trimmed_and_lowercased(ctx):
    client, _ = ctx
    fp = _fp()
    first = _claim(client, fp).json()
    again = _claim(client, f"  {fp.upper()}  ")
    assert again.status_code == 200 and again.json() == first


@pytest.mark.parametrize("bad", ["", "abc", "g" * 64, "a" * 63, "a" * 65, "0x" + "a" * 62])
def test_invalid_fingerprint_rejected(ctx, bad):
    client, _ = ctx
    resp = _claim(client, bad)
    assert resp.status_code == 400
    assert resp.json() == {"ok": False, "code": "INVALID_FINGERPRINT"}


@pytest.mark.parametrize("payload", [{}, {"hardware": None}, {"hardware": {"components": {}}}, [1, 2]])
def test_malformed_body_rejected(ctx, payload):
    client, _ = ctx
    resp = client.post("/v1/trials/claim", json=payload)
    assert resp.status_code == 400
    assert resp.json() == {"ok": False, "code": "INVALID_REQUEST"}


def test_kill_switch_returns_403(ctx, monkeypatch):
    client, _ = ctx
    monkeypatch.setenv("SHUABAO_TRIALS_ENABLED", "false")
    resp = _claim(client, _fp())
    assert resp.status_code == 403
    assert resp.json() == {"ok": False, "code": "TRIAL_DISABLED"}
    assert trials_enabled({}) is True
    assert trials_enabled({"SHUABAO_TRIALS_ENABLED": "0"}) is False
    assert trials_enabled({"SHUABAO_TRIALS_ENABLED": "true"}) is True


def test_activate_and_validate_with_trial_key(ctx):
    client, _ = ctx
    fp = _fp()
    claim = _claim(client, fp).json()
    for _ in range(2):
        act = client.post("/v1/devices/activate",
                          json={"license_key": claim["license_key"], "hardware": _hw(fp)})
        assert act.status_code == 200, act.text
        assert act.json()["fingerprint"] == fp
    val = client.post("/v1/entitlements/validate", json={
        "license_key": claim["license_key"], "hardware": _hw(fp), "permit_request": RELEASE,
    }).json()
    assert val["valid"] is True and val["can_start_runner"] is True
    assert val["permit"] is not None
    assert _parse(val["license"]["expires_at"]) == _parse(claim["expires_at"])
    # permit can never outlive the trial
    assert _parse(val["permit"]["expires_at"]) <= _parse(claim["expires_at"])
    # repeat claim after activation: unchanged
    assert _claim(client, fp).json() == claim


@pytest.mark.parametrize(("override", "code"), [
    ({"source_sha": "c" * 40}, "RELEASE_NOT_APPROVED"),
    ({"mode_id": "lead_team"}, "MODE_NOT_ALLOWED"),
])
def test_trial_key_still_subject_to_release_approval(ctx, override, code):
    client, _ = ctx
    fp = _fp()
    claim = _claim(client, fp).json()
    val = client.post("/v1/entitlements/validate", json={
        "license_key": claim["license_key"], "hardware": _hw(fp),
        "permit_request": {**RELEASE, **override},
    }).json()
    assert val["can_start_runner"] is False
    assert val["code"] == code
    assert val["permit"] is None


def test_trial_key_on_other_machine_hits_device_limit(ctx):
    client, _ = ctx
    claim = _claim(client, _fp()).json()
    resp = client.post("/v1/devices/activate",
                       json={"license_key": claim["license_key"], "hardware": _hw(_fp())})
    assert resp.status_code == 400
    assert "DEVICE_LIMIT_EXCEEDED" in resp.json()["detail"]


def test_expired_trial_cannot_be_reclaimed_and_has_no_grace(ctx):
    client, provider = ctx
    fp = _fp()
    claim = _claim(client, fp).json()
    rec = provider.licenses[asyncio.run(provider.get_license(claim["license_key"])).license_id]
    rec["expires_at"] = datetime.now(timezone.utc) - timedelta(minutes=1)
    resp = _claim(client, fp)
    assert resp.status_code == 409
    assert resp.json() == {"ok": False, "code": "TRIAL_ALREADY_USED"}
    val = client.post("/v1/entitlements/validate", json={
        "license_key": claim["license_key"], "hardware": _hw(fp), "permit_request": RELEASE,
    }).json()
    assert val["valid"] is False and val["status"] == "EXPIRED" and val["permit"] is None


def test_revoked_trial_is_already_used(ctx):
    client, provider = ctx
    fp = _fp()
    claim = _claim(client, fp).json()
    asyncio.run(provider.revoke_license(claim["license_key"]))
    assert _claim(client, fp).json()["code"] == "TRIAL_ALREADY_USED"


def test_machine_bound_to_paid_card_not_eligible(ctx):
    client, provider = ctx
    fp = _fp()

    async def bind():
        lic = await provider.create_license("paid", "p@example.invalid", "pro_monthly", 30)
        await provider.activate_device(lic.license_key, HardwareFingerprint(fingerprint=fp))

    asyncio.run(bind())
    resp = _claim(client, fp)
    assert resp.status_code == 409
    assert resp.json() == {"ok": False, "code": "TRIAL_NOT_ELIGIBLE"}


def test_legacy_account_trial_device_already_used(ctx):
    client, provider = ctx
    fp = _fp()
    provider.event_store.record_trial_claim("legacy-acct", fp, {})
    assert _claim(client, fp).json() == {"ok": False, "code": "TRIAL_ALREADY_USED"}


def test_per_ip_rate_limit_only_counts_new_issuance(ctx):
    client, _ = ctx
    claimed = _fp()
    assert _claim(client, claimed, ip="203.0.113.9").status_code == 200
    for _ in range(9):
        assert _claim(client, _fp(), ip="203.0.113.9").status_code == 200
    limited = _claim(client, _fp(), ip="203.0.113.9")
    assert limited.status_code == 429
    assert limited.json() == {"ok": False, "code": "TRIAL_RATE_LIMITED"}
    assert int(limited.headers["Retry-After"]) > 0
    # a retry for an already-claimed machine is not blocked by the IP budget
    assert _claim(client, claimed, ip="203.0.113.9").status_code == 200
    # other IPs unaffected
    assert _claim(client, _fp(), ip="203.0.113.10").status_code == 200


def test_per_fingerprint_rate_limit(ctx):
    client, _ = ctx
    fp = _fp()
    for i in range(30):
        assert _claim(client, fp, ip=f"192.0.2.{i + 1}").status_code == 200
    assert _claim(client, fp, ip="192.0.2.200").status_code == 429


def test_concurrent_http_claims_identical(ctx):
    client, _ = ctx
    fp = _fp()
    results = []

    def worker():
        results.append(_claim(client, fp).json())

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 10
    assert all(r["ok"] for r in results)
    assert len({(r["license_key"], r["expires_at"]) for r in results}) == 1


def test_cross_connection_race_creates_exactly_one(tmp_path):
    """Two processes/connections racing on the same fingerprint: one row, one key."""
    db = str(tmp_path / "race.db")
    SqliteEventStore(db).close()  # schema
    fp = _fp()
    providers = [InMemoryKeygenProvider(_engine(), SqliteEventStore(db)) for _ in range(6)]
    barrier = threading.Barrier(len(providers))
    out = []

    def worker(p):
        barrier.wait()
        dto = asyncio.run(p.claim_device_trial(HardwareFingerprint(fingerprint=fp)))
        out.append((dto.license_key, dto.expires_at))

    threads = [threading.Thread(target=worker, args=(p,)) for p in providers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(out) == len(providers) and len(set(out)) == 1
    check = SqliteEventStore(db)
    assert check._conn.execute("SELECT count(*) FROM device_trial_claims").fetchone()[0] == 1
    assert check._conn.execute(
        "SELECT count(*) FROM local_licenses WHERE json_extract(data_json,'$.plan')='trial_1d_auto'"
    ).fetchone()[0] == 1
    assert check._conn.execute(
        "SELECT count(*) FROM local_activations WHERE fingerprint=?", (fp,)
    ).fetchone()[0] == 1


def test_trial_survives_restart(tmp_path):
    db = str(tmp_path / "persist.db")
    fp = _fp()
    hw = HardwareFingerprint(fingerprint=fp)
    p1 = InMemoryKeygenProvider(_engine(), SqliteEventStore(db))
    first = asyncio.run(p1.claim_device_trial(hw))
    p1.event_store.close()
    # schema init is idempotent on an existing DB
    p2 = InMemoryKeygenProvider(_engine(), SqliteEventStore(db))
    again = asyncio.run(p2.claim_device_trial(hw))
    assert (again.license_key, again.expires_at) == (first.license_key, first.expires_at)
    act = asyncio.run(p2.activate_device(first.license_key, hw))
    assert act.fingerprint == fp
    val = asyncio.run(p2.validate_license(first.license_key, fingerprint=fp))
    assert val.valid and val.license.expires_at == first.expires_at
    with pytest.raises(ValueError, match="DEVICE_LIMIT_EXCEEDED"):
        asyncio.run(p2.activate_device(first.license_key, HardwareFingerprint(fingerprint=_fp())))


def test_expiry_fixed_at_claim_time():
    provider = InMemoryKeygenProvider(_engine(), SqliteEventStore(":memory:"))
    t0 = datetime(2026, 10, 9, 6, 0, 0, tzinfo=timezone.utc)
    hw = HardwareFingerprint(fingerprint=_fp())
    dto = asyncio.run(provider.claim_device_trial(hw, now=t0))
    assert dto.expires_at == t0 + timedelta(hours=24)
    later = asyncio.run(provider.claim_device_trial(hw, now=t0 + timedelta(hours=23)))
    assert later.expires_at == dto.expires_at and later.license_key == dto.license_key
    with pytest.raises(TrialClaimError, match="TRIAL_ALREADY_USED"):
        asyncio.run(provider.claim_device_trial(hw, now=t0 + timedelta(hours=24)))


def test_normalize_fingerprint_and_client_ip():
    assert normalize_fingerprint(" " + "AB" * 32 + "\n") == "ab" * 32
    with pytest.raises(TrialClaimError):
        normalize_fingerprint("zz" * 32)
    assert client_ip_key({"cf-connecting-ip": "203.0.113.5", "x-forwarded-for": "127.0.0.1"}, "127.0.0.1") == "203.0.113.5"
    assert client_ip_key({"x-forwarded-for": "198.51.100.1, 127.0.0.1"}, "127.0.0.1") == "198.51.100.1"
    assert client_ip_key({"cf-connecting-ip": "not-an-ip"}, "127.0.0.1") == "127.0.0.1"
    assert client_ip_key({"cf-connecting-ip": "2001:db8::1"}, None) == client_ip_key(
        {"cf-connecting-ip": "2001:db8::ffff"}, None
    ) == "2001:db8::/64"


def test_sliding_window_limiter():
    lim = SlidingWindowLimiter(2, 10)
    assert lim.hit("k", now=0)[0] and lim.hit("k", now=1)[0]
    allowed, retry = lim.hit("k", now=2)
    assert not allowed and retry >= 1
    assert lim.hit("k", now=10.5)[0]
