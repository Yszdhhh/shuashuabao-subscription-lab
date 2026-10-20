"""BATCH C: four-tier identity + referral reward-extend. Synthetic fingerprints only."""
import asyncio
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import bridge.app.main as main_mod
from contracts.entitlement import HardwareFingerprint, LicenseStatus
from bridge.app.core.crypto import CryptoEngine
from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
from bridge.app.services import referral, tiers
from bridge.app.services.event_processor import SqliteEventStore

KEY = "k" * 40
FP_INV = "1" * 64          # synthetic inviter
FP_NEW = "2" * 64          # synthetic invitee


def fp(n):
    return f"{n:064x}"


def run(c):
    return asyncio.run(c)


def hw(f):
    return HardwareFingerprint(fingerprint=f, components={}, platform="windows")


@pytest.fixture()
def env(tmp_path, monkeypatch):
    db = str(tmp_path / "subscription_state.db")
    p = InMemoryKeygenProvider(CryptoEngine(), SqliteEventStore(db))
    monkeypatch.setattr(main_mod, "keygen_provider", p)
    monkeypatch.setenv("REFERRAL_INTERNAL_KEY", KEY)
    monkeypatch.delenv("REF_BONUS_CAP", raising=False)
    loop = TestClient(main_mod.app, client=("127.0.0.1", 40001))
    remote = TestClient(main_mod.app, client=("203.0.113.9", 40002))
    return {"db": db, "p": p, "loop": loop, "remote": remote}


AUTH = ("admin", "test-admin-pass-g2-strong")


def issue(env, tier, **kw):
    r = env["loop"].post("/admin/licenses/create-test", json={"tier": tier, **kw}, auth=AUTH)
    assert r.status_code == 200, r.text
    return r.json()


def reward(env, inviter, invitee, rid, client="loop", key=KEY, headers=None):
    h = {"X-Referral-Internal-Key": key, **(headers or {})}
    return env[client].post("/internal/referrals/reward-extend", headers=h,
                            json={"inviter_fingerprint": inviter, "invitee_fingerprint": invitee, "review_id": rid})


def activate(env, key, f):
    r = env["loop"].post("/v1/devices/activate", json={"license_key": key, "hardware": {
        "fingerprint": f, "components": {}, "platform": "windows"}})
    assert r.status_code == 200, r.text
    return r.json()


def validate(env, key, f=None):
    body = {"license_key": key}
    if f:
        body["hardware"] = {"fingerprint": f, "components": {}, "platform": "windows"}
    return env["loop"].post("/v1/entitlements/validate", json=body).json()


# ---------------- Feature 1 ----------------
EXPECT = {"go": ("go_1d", "Go 订阅", 1), "plus": ("plus_7d", "Plus 订阅", 7),
          "pro": ("pro_30d", "Pro 订阅", 30), "ultra": ("ultra_lifetime", "Ultra 永久用户", None),
          "test": ("trial_1d", "内测用户", 1)}


@pytest.mark.parametrize("tier", list(EXPECT))
def test_issue_activate_validate_each_tier(env, tier):
    plan, name, days = EXPECT[tier]
    d = issue(env, tier)
    assert (d["plan"], d["tier"], d["tier_name"]) == (plan, tier, name)
    assert d["license_key"].startswith("SSB-")
    exp = datetime.fromisoformat(d["expires_at"].replace("Z", "+00:00"))
    if days is None:
        assert exp == tiers.LIFETIME_EXPIRES_AT
    else:
        assert abs((exp - datetime.now(timezone.utc)) - timedelta(days=days)) < timedelta(minutes=1)
    a = activate(env, d["license_key"], fp(100))
    assert (a["plan"], a["tier"], a["tier_name"]) == (plan, tier, name)
    v = validate(env, d["license_key"], fp(100))
    assert v["valid"] and (v["plan"], v["tier"], v["tier_name"]) == (plan, tier, name)
    assert (v["license"]["plan"], v["license"]["tier"], v["license"]["tier_name"]) == (plan, tier, name)
    # persisted in data_json and survives restart
    row = sqlite3.connect(env["db"]).execute("SELECT data_json FROM local_licenses WHERE id=?", (d["license_id"],)).fetchone()
    assert json.loads(row[0])["tier"] == tier
    p2 = InMemoryKeygenProvider(CryptoEngine(), SqliteEventStore(env["db"]))
    assert run(p2.get_license(d["license_id"])).tier == tier


def test_invalid_tier_rejected(env):
    r = env["loop"].post("/admin/licenses/create-test", json={"tier": "gold"}, auth=AUTH)
    assert r.status_code == 400 and r.json()["detail"].startswith("INVALID_TIER:")
    assert env["loop"].post("/admin/licenses/create-test", json={"tier": "go"}).status_code in (401, 403)


def test_test_tier_first_activation_clock_preserved(env):
    d = issue(env, "test", days=7, starts_on_first_activation=True)
    assert d["plan"] == "test_7d_first_act" and d["tier"] == "test" and d["expires_at"] is None
    a = activate(env, d["license_key"], fp(101))
    exp = datetime.fromisoformat(a["expires_at"].replace("Z", "+00:00"))
    assert abs(exp - datetime.now(timezone.utc) - timedelta(days=7)) < timedelta(minutes=1)


def test_ultra_ignores_first_activation(env):
    d = issue(env, "ultra", starts_on_first_activation=True)
    assert d["expires_at"].startswith("2099-12-31T23:59:59")


def test_admin_form_tier(env):
    r = env["loop"].post("/admin/licenses", data={"tier": "plus", "device_limit": "1"}, auth=AUTH, follow_redirects=False)
    assert r.status_code == 303
    lic = run(env["p"].list_licenses())[0]
    assert (lic.plan, lic.tier) == ("plus_7d", "plus")


@pytest.mark.parametrize("plan,tier", [("test_1d", "test"), ("test_7d_first_act", "test"), ("test_30d", "test"),
                                       ("pro_monthly", "pro"), ("pro_annual", "pro"), ("trial_1d_auto", "test"),
                                       ("trial_7d", "test"), ("pro", "test"), ("something_else", "test")])
def test_legacy_plan_mapping_validates(env, plan, tier):
    dto = run(env["p"].create_license("legacy", "l@example.invalid", plan, duration_days=3, device_limit=1))
    rec = env["p"].licenses[dto.license_id]
    assert "tier" not in rec  # legacy record: no stored tier
    v = validate(env, dto.license_key)
    assert v["valid"] and v["plan"] == plan and v["tier"] == tier and v["tier_name"] == tiers.tier_name(tier)


def test_trial_claim_returns_tier(env, monkeypatch):
    r = env["loop"].post("/v1/trials/claim", json={"hardware": {"fingerprint": fp(102), "components": {}, "platform": "windows"}})
    assert r.status_code == 200, r.text
    assert r.json()["tier"] == "test" and r.json()["tier_name"] == "内测用户"


# ---------------- Feature 2 ----------------
def bound(env, tier, f=FP_INV, **kw):
    d = issue(env, tier, **kw)
    activate(env, d["license_key"], f)
    return d


def exp_of(env, lid):
    return env["p"].licenses[lid]["expires_at"]


def test_extend_active(env):
    d = bound(env, "plus")
    before = exp_of(env, d["license_id"])
    r = reward(env, FP_INV, FP_NEW, "rv1")
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["action"] == "extended" and j["tier"] == "plus" and j["invite_count"] == 1
    assert exp_of(env, d["license_id"]) == before.replace(microsecond=0) + timedelta(hours=24) or \
        abs(exp_of(env, d["license_id"]) - before - timedelta(hours=24)) < timedelta(seconds=1)
    row = sqlite3.connect(env["db"]).execute("SELECT inviter_fingerprint, inviter_license_id, review_id FROM referral_rewards WHERE invitee_fingerprint=?", (FP_NEW,)).fetchone()
    assert row == (FP_INV, d["license_id"], "rv1")
    # validate reflects the new expiry (memory mirrored after commit) and after restart
    v = validate(env, d["license_key"], FP_INV)
    assert v["license"]["expires_at"].startswith(j["expires_at"][:19].replace("Z", ""))
    p2 = InMemoryKeygenProvider(CryptoEngine(), SqliteEventStore(env["db"]))
    assert abs(p2.licenses[d["license_id"]]["expires_at"] - exp_of(env, d["license_id"])) < timedelta(seconds=1)


def test_extend_expired_from_now(env):
    d = bound(env, "go")
    rec = env["p"].licenses[d["license_id"]]
    run(env["p"].set_license_expiry(d["license_id"], datetime.now(timezone.utc) - timedelta(days=10)))
    j = reward(env, FP_INV, FP_NEW, "rv1").json()
    assert j["action"] == "extended_from_now"
    assert abs(rec["expires_at"] - datetime.now(timezone.utc) - timedelta(hours=24)) < timedelta(seconds=5)
    assert validate(env, d["license_key"], FP_INV)["valid"] is True


def test_ultra_count_only(env):
    d = bound(env, "ultra")
    j = reward(env, FP_INV, FP_NEW, "rv1").json()
    assert j["action"] == "count_only_lifetime" and j["invite_count"] == 1
    assert exp_of(env, d["license_id"]) == tiers.LIFETIME_EXPIRES_AT


@pytest.mark.parametrize("how", ["revoke", "suspend"])
def test_revoked_or_suspended_not_extended(env, how):
    d = bound(env, "pro")
    before = exp_of(env, d["license_id"])
    getattr(env["p"], f"{how}_license")
    run(getattr(env["p"], f"{how}_license")(d["license_id"]))
    r = reward(env, FP_INV, FP_NEW, "rv1")
    assert r.status_code == 409 and r.json()["detail"].startswith("REFERRAL_INVITER_INELIGIBLE:")
    assert exp_of(env, d["license_id"]) == before
    assert sqlite3.connect(env["db"]).execute("SELECT COUNT(*) FROM referral_rewards").fetchone()[0] == 0


def test_multiple_bound_picks_most_recent_non_revoked(env):
    a = bound(env, "go")
    b = bound(env, "plus")
    c = bound(env, "pro")
    run(env["p"].revoke_license(c["license_id"]))
    j = reward(env, FP_INV, FP_NEW, "rv1").json()
    assert j["inviter_license_id"] == b["license_id"] and j["tier"] == "plus"


def test_fallback_never_activated(env):
    j = reward(env, FP_INV, FP_NEW, "rv1").json()
    assert j["action"] == "fallback_trial_issued" and j["plan"] == "trial_1d" and j["tier"] == "test"
    lid = j["inviter_license_id"]
    rec = env["p"].licenses[lid]
    assert rec["key"].startswith("SSB-")
    assert any(a["fingerprint"] == FP_INV for a in env["p"].activations[lid])
    assert validate(env, rec["key"], FP_INV)["valid"] is True
    # second reward now extends the fallback card (no second fallback)
    j2 = reward(env, FP_INV, fp(3), "rv2").json()
    assert j2["action"] == "extended" and j2["inviter_license_id"] == lid


def test_history_but_unbound_is_not_found(env):
    env["loop"].post("/v1/trials/claim", json={"hardware": {"fingerprint": FP_INV, "components": {}, "platform": "windows"}})
    lid = next(iter(env["p"].activations))
    run(env["p"].deactivate_device(env["p"].licenses[lid]["key"], FP_INV))
    r = reward(env, FP_INV, FP_NEW, "rv1")
    assert r.status_code == 404 and r.json()["detail"].startswith("REFERRAL_INVITER_NOT_FOUND:")


def test_idempotent_repeat_and_duplicate_invitee(env):
    d = bound(env, "pro")
    j1 = reward(env, FP_INV, FP_NEW, "rv1").json()
    e1 = exp_of(env, d["license_id"])
    r2 = reward(env, FP_INV, FP_NEW, "rv1")
    assert r2.status_code == 200 and r2.json()["idempotent"] is True and r2.json()["expires_at"] == j1["expires_at"]
    assert exp_of(env, d["license_id"]) == e1
    r3 = reward(env, FP_INV, FP_NEW, "rv-other")
    assert r3.status_code == 409 and r3.json()["detail"].startswith("REFERRAL_ALREADY_REWARDED:")
    other = fp(77)
    bound(env, "go", f=other)
    r4 = reward(env, other, FP_NEW, "rv1")   # same invitee, other inviter
    assert r4.status_code == 409 and r4.json()["detail"].startswith("REFERRAL_ALREADY_REWARDED:")
    assert exp_of(env, d["license_id"]) == e1


def test_self_invite(env):
    bound(env, "go")
    r = reward(env, FP_INV, FP_INV.upper(), "rv1")
    assert r.status_code == 409 and r.json()["detail"].startswith("REFERRAL_SELF_INVITE:")


def test_cap(env, monkeypatch):
    monkeypatch.setenv("REF_BONUS_CAP", "3")
    bound(env, "pro")
    for i in range(3):
        assert reward(env, FP_INV, fp(1000 + i), f"rv{i}").status_code == 200
    r = reward(env, FP_INV, fp(2000), "rvX")
    assert r.status_code == 409 and r.json()["detail"].startswith("REFERRAL_CAP_REACHED:")


def test_cap_default_10(env):
    bound(env, "ultra")
    for i in range(10):
        assert reward(env, FP_INV, fp(3000 + i), f"rv{i}").status_code == 200
    assert reward(env, FP_INV, fp(4000), "rvX").json()["detail"].startswith("REFERRAL_CAP_REACHED:")


def test_bad_request(env):
    r = reward(env, "zz", FP_NEW, "rv1")
    assert r.status_code == 400 and r.json()["detail"].startswith("REFERRAL_BAD_REQUEST:")
    r = reward(env, FP_INV, FP_NEW, "")
    assert r.status_code == 400


def test_non_loopback_and_forwarded_rejected(env):
    bound(env, "go")
    r = reward(env, FP_INV, FP_NEW, "rv1", client="remote")
    assert r.status_code == 403 and r.json()["detail"].startswith("REFERRAL_UNAUTHORIZED:")
    r = reward(env, FP_INV, FP_NEW, "rv1", headers={"X-Forwarded-For": "198.51.100.7"})
    assert r.status_code == 403 and r.json()["detail"].startswith("REFERRAL_UNAUTHORIZED:")
    assert sqlite3.connect(env["db"]).execute("SELECT COUNT(*) FROM referral_rewards").fetchone()[0] == 0


def test_bad_or_missing_key(env, monkeypatch):
    bound(env, "go")
    assert reward(env, FP_INV, FP_NEW, "rv1", key="k" * 39 + "x").status_code == 403
    assert reward(env, FP_INV, FP_NEW, "rv1", key="").json()["detail"].startswith("REFERRAL_UNAUTHORIZED:")
    monkeypatch.setenv("REFERRAL_INTERNAL_KEY", "short")
    r = reward(env, FP_INV, FP_NEW, "rv1", key="short")
    assert r.status_code == 503 and r.json()["detail"].startswith("REFERRAL_DISABLED:")
    assert sqlite3.connect(env["db"]).execute("SELECT COUNT(*) FROM referral_rewards").fetchone()[0] == 0


def test_concurrency_race_two_connections(env):
    """Two approvals racing for the SAME invitee on separate SQLite connections (as two
    processes would): exactly one extension, the other is idempotent/rejected."""
    d = bound(env, "pro")
    before = exp_of(env, d["license_id"])
    barrier = threading.Barrier(8)
    results = []

    def worker(i):
        conn = referral.open_conn(env["db"])
        barrier.wait()
        try:
            results.append(("ok", referral.reward_extend(conn, FP_INV, FP_NEW, f"rv{i % 2}")))
        except referral.ReferralError as exc:
            results.append(("err", exc.code))

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    fresh = [r for k, r in results if k == "ok" and not r["idempotent"]]
    assert len(fresh) == 1
    assert all(k == "ok" or r == "REFERRAL_ALREADY_REWARDED" for k, r in results)
    data = json.loads(sqlite3.connect(env["db"]).execute("SELECT data_json FROM local_licenses WHERE id=?", (d["license_id"],)).fetchone()[0])
    new = datetime.fromisoformat(data["expires_at"])
    assert abs(new - before - timedelta(hours=24)) < timedelta(seconds=1)
    assert sqlite3.connect(env["db"]).execute("SELECT COUNT(*) FROM referral_rewards").fetchone()[0] == 1


def test_concurrency_cap_race(env):
    """Many distinct invitees racing at cap boundary never exceed REF_BONUS_CAP."""
    bound(env, "go")
    barrier = threading.Barrier(15)
    out = []

    def worker(i):
        conn = referral.open_conn(env["db"])
        barrier.wait()
        try:
            referral.reward_extend(conn, FP_INV, fp(5000 + i), f"rv{i}", cap=10); out.append(1)
        except referral.ReferralError as exc:
            out.append(exc.code)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(15)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert out.count(1) == 10 and out.count("REFERRAL_CAP_REACHED") == 5


def test_migration_up_down(env, tmp_path):
    import subprocess, sys, os
    db = str(tmp_path / "m.db")
    SqliteEventStore(db)
    script = os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "migrate_batchc.py")
    assert subprocess.run([sys.executable, script, "down", "--db", db]).returncode == 0
    assert sqlite3.connect(db).execute("SELECT 1 FROM sqlite_master WHERE name='referral_rewards'").fetchone() is None
    assert subprocess.run([sys.executable, script, "up", "--db", db]).returncode == 0
    assert sqlite3.connect(db).execute("SELECT 1 FROM sqlite_master WHERE name='referral_rewards'").fetchone()
    assert subprocess.run([sys.executable, script, "status", "--db", "/home/shuabao/x.db"]).returncode == 2
