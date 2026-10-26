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
    body = ({"tier": tier} if tier else {})
    r = env["loop"].post("/admin/licenses/create-test", json={**body, **kw}, auth=AUTH)
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
EXPECT = {"go": ("go_daily", "Go 订阅", 1), "plus": ("plus_weekly", "Plus 订阅", 7),
          "pro": ("pro_monthly", "Pro 订阅", 30), "ultra": ("ultra_permanent", "Ultra 永久用户", None),
          "test": ("trial_1d", "试用", 1)}   # r7.1: post-cutover internal card, not beta


@pytest.mark.parametrize("tier", list(EXPECT))
def test_issue_activate_validate_each_tier(env, tier):
    plan, name, days = EXPECT[tier]
    d = issue(env, tier, **({"confirm_ultra": True} if tier == "ultra" else {}))
    tier = "trial" if tier == "test" else tier
    assert (d["plan"], d["tier"], d["tier_name"]) == (plan, tier, name) and d["is_beta_user"] is False
    assert d["license_key"].startswith("SSB-")
    if tier in ("go", "plus", "pro"):
        # r7 ruling 3: formal tiers default to first-activation start
        assert d["expires_at"] is None and d["starts_on_first_activation"] is True
    else:
        exp = datetime.fromisoformat(d["expires_at"].replace("Z", "+00:00"))
        if days is None:
            assert exp == tiers.LIFETIME_EXPIRES_AT
        else:
            assert abs((exp - datetime.now(timezone.utc)) - timedelta(days=days)) < timedelta(minutes=1)
    a = activate(env, d["license_key"], fp(100))
    if days is not None:
        exp = datetime.fromisoformat(a["expires_at"].replace("Z", "+00:00"))
        assert abs((exp - datetime.now(timezone.utc)) - timedelta(days=days)) < timedelta(minutes=1)
    assert (a["plan"], a["tier"], a["tier_name"]) == (plan, tier, name)
    v = validate(env, d["license_key"], fp(100))
    assert v["valid"] and (v["plan"], v["tier"], v["tier_name"]) == (plan, tier, name)
    assert (v["license"]["plan"], v["license"]["tier"], v["license"]["tier_name"]) == (plan, tier, name)
    # persisted in data_json and survives restart
    row = sqlite3.connect(env["db"]).execute("SELECT data_json FROM local_licenses WHERE id=?", (d["license_id"],)).fetchone()
    assert json.loads(row[0])["tier"] == ("test" if tier == "trial" else tier)
    p2 = InMemoryKeygenProvider(CryptoEngine(), SqliteEventStore(env["db"]))
    assert run(p2.get_license(d["license_id"])).tier == tier


def test_invalid_tier_rejected(env):
    r = env["loop"].post("/admin/licenses/create-test", json={"tier": "gold"}, auth=AUTH)
    assert r.status_code == 400 and r.json()["detail"].startswith("INVALID_TIER:")
    assert env["loop"].post("/admin/licenses/create-test", json={"tier": "go"}).status_code in (401, 403)


def test_test_tier_first_activation_clock_preserved(env):
    d = issue(env, "test", days=7, starts_on_first_activation=True)
    assert d["plan"] == "test_7d_first_act" and d["tier"] == "trial" and d["expires_at"] is None
    a = activate(env, d["license_key"], fp(101))
    exp = datetime.fromisoformat(a["expires_at"].replace("Z", "+00:00"))
    assert abs(exp - datetime.now(timezone.utc) - timedelta(days=7)) < timedelta(minutes=1)


def test_ultra_ignores_first_activation(env):
    d = issue(env, "ultra", starts_on_first_activation=True, confirm_ultra=True)
    assert d["expires_at"].startswith("2099-12-31T23:59:59")


def test_admin_form_tier(env):
    r = env["loop"].post("/admin/licenses", data={"tier": "plus", "device_limit": "1"}, auth=AUTH, follow_redirects=False)
    assert r.status_code == 303
    lic = run(env["p"].list_licenses())[0]
    assert (lic.plan, lic.tier) == ("plus_weekly", "plus")


@pytest.mark.parametrize("plan,tier", [("test_1d", "trial"), ("test_7d_first_act", "trial"), ("test_30d", "trial"),
                                       ("pro_monthly", "pro"), ("pro_annual", "pro"), ("trial_1d_auto", "trial"),
                                       ("trial_7d", "trial"), ("pro", "trial"), ("something_else", "trial")])
def test_legacy_plan_mapping_validates(env, plan, tier):
    dto = run(env["p"].create_license("legacy", "l@example.invalid", plan, duration_days=3, device_limit=1))
    rec = env["p"].licenses[dto.license_id]
    assert "tier" not in rec  # legacy record: no stored tier
    v = validate(env, dto.license_key)
    assert v["valid"] and v["plan"] == plan and v["tier"] == tier and v["tier_name"] == tiers.tier_name(tier)


def test_trial_claim_returns_tier(env, monkeypatch):
    r = env["loop"].post("/v1/trials/claim", json={"hardware": {"fingerprint": fp(102), "components": {}, "platform": "windows"}})
    assert r.status_code == 200, r.text
    assert r.json()["tier"] == "trial" and r.json()["tier_name"] == "试用" and r.json()["is_beta_user"] is False


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




def test_ultra_immutable_not_counted(env):
    d = bound(env, "ultra", confirm_ultra=True)
    j = reward(env, FP_INV, FP_NEW, "rv1").json()
    assert j["status"] == "ultra_immutable" and j["action"] == "ultra_immutable" and j["invite_count"] == 0
    assert exp_of(env, d["license_id"]) == tiers.LIFETIME_EXPIRES_AT


@pytest.mark.parametrize("how", ["revoke", "suspend"])
def test_revoked_or_suspended_not_extended(env, how):
    """r7.1: a non-beta inviter whose only paid card is revoked/suspended -> pending SUBSCRIPTION_REQUIRED."""
    d = bound(env, "pro")
    before = exp_of(env, d["license_id"])
    getattr(env["p"], f"{how}_license")
    run(getattr(env["p"], f"{how}_license")(d["license_id"]))
    r = reward(env, FP_INV, FP_NEW, "rv1")
    assert r.status_code == 202 and r.json()["code"] == "SUBSCRIPTION_REQUIRED_FOR_REFERRAL"
    assert exp_of(env, d["license_id"]) == before
    assert sqlite3.connect(env["db"]).execute("SELECT status FROM referral_rewards").fetchone()[0] == "pending"


def test_multiple_bound_picks_most_recent_non_revoked(env):
    a = bound(env, "go")
    b = bound(env, "plus")
    c = bound(env, "pro")
    run(env["p"].revoke_license(c["license_id"]))
    j = reward(env, FP_INV, FP_NEW, "rv1").json()
    assert j["inviter_license_id"] == b["license_id"] and j["tier"] == "plus"














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
    bound(env, "pro")
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


# ---------------- r7 Owner rulings ----------------


@pytest.mark.parametrize("plan,tier", [("go_daily", "go"), ("plus_weekly", "plus"), ("pro_monthly", "pro"),
                                       ("ultra_permanent", "ultra"), ("go_1d", "go"), ("pro_30d", "pro"),
                                       ("plus_7d", "plus"), ("ultra_lifetime", "ultra")])
def test_plan_aliases_issue_and_derive(env, plan, tier):
    """r7.1 Q5: aliases accepted and REWRITTEN; the DB stores the canonical name."""
    canon = {"go": "go_daily", "plus": "plus_weekly", "pro": "pro_monthly", "ultra": "ultra_permanent"}[tier]
    d = issue(env, None, plan=plan, **({"confirm_ultra": True} if tier == "ultra" else {}))
    assert d["tier"] == tier and d["plan"] == canon
    stored = json.loads(sqlite3.connect(env["db"]).execute("SELECT data_json FROM local_licenses WHERE id=?", (d["license_id"],)).fetchone()[0])
    assert stored["plan"] == canon
    assert tiers.derive_tier(plan) == tier
    dto = run(env["p"].create_license("legacy", "l@example.invalid", plan, duration_days=3, device_limit=1))
    assert validate(env, dto.license_key)["tier"] == tier


def test_bad_plan_rejected(env):
    r = env["loop"].post("/admin/licenses/create-test", json={"plan": "gold_forever"}, auth=AUTH)
    assert r.status_code == 400 and r.json()["detail"].startswith("INVALID_PLAN:")
    r = env["loop"].post("/admin/licenses/create-test", json={"tier": "go", "plan": "pro_monthly"}, auth=AUTH)
    assert r.status_code == 400 and r.json()["detail"].startswith("INVALID_PLAN:")


def test_explicit_expires_at_override(env):
    when = (datetime.now(timezone.utc) + timedelta(days=90)).replace(microsecond=0)
    d = issue(env, "plus", expires_at=when.isoformat())
    assert d["starts_on_first_activation"] is False
    assert datetime.fromisoformat(d["expires_at"].replace("Z", "+00:00")) == when
    r = env["loop"].post("/admin/licenses/create-test", json={"tier": "go", "expires_at": "2020-01-01T00:00:00+00:00"}, auth=AUTH)
    assert r.status_code == 400 and r.json()["detail"].startswith("INVALID_EXPIRES_AT:")
    r = env["loop"].post("/admin/licenses/create-test", json={"tier": "go", "expires_at": "2030-01-01T00:00:00"}, auth=AUTH)
    assert r.status_code == 400
    d2 = issue(env, "go", starts_on_first_activation=False)
    assert d2["expires_at"] is not None and d2["starts_on_first_activation"] is False


def test_ultra_requires_confirm_and_audits(env, tmp_path, monkeypatch):
    log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("SUBSCRIPTION_ADMIN_AUDIT_LOG", str(log))
    r = env["loop"].post("/admin/licenses/create-test", json={"tier": "ultra"}, auth=AUTH)
    assert r.status_code == 400 and r.json()["detail"].startswith("ULTRA_CONFIRM_REQUIRED:")
    assert env["p"].event_store._conn.execute("SELECT COUNT(*) FROM entitlement_operations").fetchone()[0] == 0
    assert env["p"].event_store.load_local_licenses() == {}
    d = issue(env, "ultra", confirm_ultra=True)
    assert d["expires_at"].startswith("2099-12-31T23:59:59")
    lines = [json.loads(row[0]) for row in env["p"].event_store._conn.execute(
        "SELECT audit_json FROM entitlement_operations")]
    assert len(lines) == 1 and lines[0]["action"] == "issue_ultra" and lines[0]["license_id"] == d["license_id"]
    assert d["license_key"] not in json.dumps(lines)
    assert lines[0]["license_key_masked"] == d["license_key"][:4] + "…" + d["license_key"][-4:]
    # admin form: ultra without confirm checkbox is refused
    r = env["loop"].post("/admin/licenses", data={"tier": "ultra"}, auth=AUTH, follow_redirects=False)
    from urllib.parse import unquote
    assert r.status_code == 303 and "确认签发 Ultra" in unquote(r.headers["location"])
    assert env["p"].event_store._conn.execute("SELECT COUNT(*) FROM entitlement_operations").fetchone()[0] == 1
    assert len(env["p"].event_store.load_local_licenses()) == 1


def test_admin_loopback_and_token(env, monkeypatch):
    tok = "t" * 40
    monkeypatch.setenv("SUBSCRIPTION_ADMIN_TOKEN", tok)
    ok = env["loop"].post("/admin/licenses/create-test", json={"tier": "go"}, headers={"X-Admin-Token": tok})
    assert ok.status_code == 200
    bad = env["loop"].post("/admin/licenses/create-test", json={"tier": "go"}, headers={"X-Admin-Token": "x" * 40})
    assert bad.status_code == 401
    # r7.1 Q4: with a token configured, HTTP Basic (even correct) is refused
    assert env["loop"].get("/admin", auth=AUTH).status_code == 401
    assert env["loop"].post("/admin/licenses/create-test", json={"tier": "go"}, auth=AUTH).status_code == 401
    # non-loopback peer or proxied request: 404 even with valid credentials
    assert env["remote"].post("/admin/licenses/create-test", json={"tier": "go"}, headers={"X-Admin-Token": tok}).status_code == 404
    assert env["remote"].get("/admin", auth=AUTH).status_code == 404
    assert env["loop"].get("/admin", headers={"X-Admin-Token": tok, "X-Forwarded-For": "198.51.100.7"}).status_code == 404


def _mk(env, plan, *, activate_fp=None, bind=False, status=None):
    dto = run(env["p"].create_license("c", "c@example.invalid", plan, duration_days=30, device_limit=1))
    if activate_fp:
        activate(env, dto.license_key, activate_fp)
    if bind:
        env["p"].event_store._conn.execute("INSERT INTO subscription_bindings VALUES (?,?,?)",
                                           (f"order:{dto.license_id}", dto.license_id, "2026-10-20T00:00:00Z"))
    if status == "revoke":
        run(env["p"].revoke_license(dto.license_id))
    return dto


def test_migration_test30d_to_pro_monthly(env, tmp_path):
    import subprocess, sys, os
    a = _mk(env, "test_30d", activate_fp=fp(901))          # activated -> migrate
    b = _mk(env, "test_30d", bind=True)                    # sold (billing binding) -> migrate
    c = _mk(env, "test_30d")                               # unsold pure test -> unchanged
    dl = _mk(env, "test_30d")                              # sold via Owner list -> migrate
    r_ = _mk(env, "test_30d", activate_fp=fp(902), status="revoke")   # revoked -> unchanged
    o = _mk(env, "test_7d_first_act")                      # other plan -> unchanged
    sold = tmp_path / "sold.txt"; sold.write_text(dl.license_id + "\n")
    script = os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "migrate_r7_test30d_to_pro.py")
    def mig(*args):
        out = subprocess.run([sys.executable, script, "--db", env["db"], *args], capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        return json.loads(out.stdout)
    snap = lambda: {r[0]: json.loads(r[1]) for r in sqlite3.connect(env["db"]).execute("SELECT id, data_json FROM local_licenses")}
    before = snap()
    dry = mig("--sold-list", str(sold))
    assert dry["mode"] == "dry-run" and dry["to_migrate"] == 3 and dry["unchanged_unsold_unactivated"] == 1
    assert dry["unchanged_revoked"] == 1 and dry["to_migrate_by_reason"] == {"activated": 1, "sold_only": 2}
    assert snap() == before                                  # dry-run wrote nothing
    assert all(k.startswith("SSB-") is False for k in dry["sample_ids_masked"])
    assert a.license_key not in json.dumps(dry)
    ap = mig("--apply", "--sold-list", str(sold))
    assert ap["migrated"] == 3 and os.stat(ap["undo_file"]).st_mode & 0o077 == 0
    assert a.license_key not in open(ap["undo_file"]).read()
    after = snap()
    for x in (a, b, dl):
        assert (after[x.license_id]["plan"], after[x.license_id]["tier"], after[x.license_id]["tier_name"]) == \
            ("pro_monthly", "pro", "Pro 订阅")
    for x in (c, r_, o):
        assert after[x.license_id] == before[x.license_id]
    again = mig("--apply", "--sold-list", str(sold))           # idempotent
    assert again["to_migrate"] == 0 and again["already_migrated_r7"] == 3 and "migrated" not in again
    p2 = InMemoryKeygenProvider(CryptoEngine(), SqliteEventStore(env["db"]))
    assert run(p2.get_license(a.license_id)).tier == "pro"


def test_issue_cards_cli_requires_confirm_ultra(tmp_path):
    import subprocess, sys, os
    script = os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "issue_cards.py")
    out = subprocess.run([sys.executable, script, "--base", "http://127.0.0.1:9", "--tier", "ultra",
                          "--out", str(tmp_path / "o.tsv")], capture_output=True, text=True,
                         env={**os.environ, "SUBSCRIPTION_ADMIN_TOKEN": "t" * 40})
    assert out.returncode == 2 and "ULTRA_CONFIRM_REQUIRED" in out.stderr and not (tmp_path / "o.tsv").exists()
    out = subprocess.run([sys.executable, script, "--base", "http://example.com", "--tier", "go",
                          "--out", str(tmp_path / "o2.tsv")], capture_output=True, text=True,
                         env={**os.environ, "SUBSCRIPTION_ADMIN_TOKEN": "t" * 40})
    assert out.returncode == 2 and "non-loopback" in out.stderr


# ---------------- r7.1: beta identity + referral split ----------------
def make_beta(env, f, plan="test_7d", bind=True, expired=False):
    """Simulate a pre-cutover beta card, then run the cutover snapshot (box test DB)."""
    import subprocess, sys, os
    dto = run(env["p"].create_license("legacy-beta", "b@example.invalid", plan, duration_days=7, device_limit=1))
    if bind:
        activate(env, dto.license_key, f)
    if expired:
        rec = env["p"].licenses[dto.license_id]
        rec["expires_at"] = datetime.now(timezone.utc) - timedelta(days=5)
        env["p"].event_store.save_local_license(dto.license_id, dto.license_key, rec)
    snap(env, "--apply")
    return dto


def snap(env, *args):
    import subprocess, sys, os
    script = os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "snapshot_beta_r71.py")
    out = subprocess.run([sys.executable, script, "--db", env["db"], *args], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    # the running provider caches licenses: reload (prod runs the snapshot while 8010 is stopped)
    p2 = InMemoryKeygenProvider(CryptoEngine(), SqliteEventStore(env["db"]))
    main_mod.keygen_provider = p2; env["p"] = p2
    return json.loads(out.stdout)


def test_beta_label_only_for_snapshot(env):
    old = run(env["p"].create_license("legacy", "l@example.invalid", "test_30d", duration_days=30, device_limit=1))
    activate(env, old.license_key, fp(11))
    unbound = run(env["p"].create_license("legacy", "l@example.invalid", "trial_1d_auto", duration_days=1, device_limit=1))
    pro = run(env["p"].create_license("legacy", "l@example.invalid", "pro_monthly", duration_days=30, device_limit=1))
    activate(env, pro.license_key, fp(11))
    dry = snap(env)
    assert dry["mode"] == "dry-run" and dry["beta_licenses_internal"] == 2 and dry["beta_fingerprints"] == 1
    assert validate(env, old.license_key)["tier"] == "trial"            # dry-run wrote nothing
    ap = snap(env, "--apply")
    assert ap["licenses_to_flag"] == 3 and ap["formal_licenses_of_beta_users"] == 1
    v = validate(env, old.license_key)
    assert (v["tier"], v["tier_name"], v["is_beta_user"]) == ("beta", "内测用户", True)
    vp = validate(env, pro.license_key)
    assert (vp["tier"], vp["is_beta_user"]) == ("pro", True)            # beta user's paid card keeps tier pro
    again = snap(env, "--apply")
    assert again["licenses_to_flag"] == 0 and again["beta_fingerprints_new"] == 0      # idempotent
    # an unbound beta card activated after cutover makes its holder beta
    activate(env, unbound.license_key, fp(12))
    assert referral.is_beta_fp(env["p"]._referral_conn(), fp(12))
    # cards issued after cutover never carry the beta label; issuing tier=beta is refused
    d = issue(env, "test")
    assert (d["tier"], d["tier_name"], d["is_beta_user"]) == ("trial", "试用", False)
    r = env["loop"].post("/admin/licenses/create-test", json={"tier": "beta"}, auth=AUTH)
    assert r.status_code == 400 and r.json()["detail"].startswith("INVALID_TIER:")
    # self-service trial after cutover: 试用, not beta
    t = env["loop"].post("/v1/trials/claim", json={"hardware": {"fingerprint": fp(13), "components": {}, "platform": "windows"}}).json()
    assert (t["tier"], t["is_beta_user"]) == ("trial", False)


def test_no_card_is_weikaitong(env):
    v = env["loop"].post("/v1/entitlements/validate", json={"license_key": "SSB-0000-0000-0000"}).json()
    assert v["valid"] is False and (v["tier"], v["tier_name"], v["is_beta_user"]) == ("none", "未开通", False)


def test_migrated_only_holder_not_beta(env, tmp_path):
    import subprocess, sys, os
    t30 = run(env["p"].create_license("c", "c@example.invalid", "test_30d", duration_days=30, device_limit=1))
    activate(env, t30.license_key, fp(21))
    t30b = run(env["p"].create_license("c", "c@example.invalid", "test_30d", duration_days=30, device_limit=1))
    activate(env, t30b.license_key, fp(22))
    other = run(env["p"].create_license("c", "c@example.invalid", "test_7d", duration_days=7, device_limit=1))
    activate(env, other.license_key, fp(22))                         # fp22 also holds another test_* card
    script = os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "migrate_r7_test30d_to_pro.py")
    assert subprocess.run([sys.executable, script, "--db", env["db"], "--apply"], capture_output=True).returncode == 0
    rep = snap(env, "--apply")                          # r7.1 Q-B1 (Owner 13:27): migrated holders ARE beta (default)
    assert rep["include_migrated"] is True and rep["migrated_pro_monthly_holders_not_beta"] == 0
    v1, v2 = validate(env, t30.license_key), validate(env, t30b.license_key)
    assert (v1["plan"], v1["tier"], v1["is_beta_user"]) == ("pro_monthly", "pro", True)
    assert (v2["tier"], v2["is_beta_user"]) == ("pro", True)


def test_beta_inviter_expired_card_extended_from_now(env):
    d = make_beta(env, FP_INV, expired=True)
    j = reward(env, FP_INV, FP_NEW, "rv1").json()
    assert j["status"] == "applied" and j["action"] == "extended_from_now" and j["tier"] == "beta"
    assert abs(exp_of(env, d.license_id) - datetime.now(timezone.utc) - timedelta(hours=24)) < timedelta(minutes=1)


def test_beta_inviter_without_card_gets_1day_trial(env):
    run(env["p"].create_license("c", "c@example.invalid", "test_7d", duration_days=7, device_limit=1))
    referral.mark_beta(env["p"]._referral_conn(), FP_INV, None, "test")   # beta user whose card was unbound
    j = reward(env, FP_INV, FP_NEW, "rv1").json()
    assert j["status"] == "applied" and j["action"] == "beta_trial_issued" and j["tier"] == "beta" and j["plan"] == "trial_1d"
    lid = j["inviter_license_id"]
    rec = env["p"].licenses[lid]
    assert validate(env, rec["key"], FP_INV)["valid"] is True and validate(env, rec["key"], FP_INV)["is_beta_user"] is True
    j2 = reward(env, FP_INV, fp(3), "rv2").json()          # second reward extends the trial
    assert j2["action"] == "extended" and j2["inviter_license_id"] == lid


def test_nonbeta_valid_paid_stacks(env):
    d = issue(env, "plus", starts_on_first_activation=False)
    activate(env, d["license_key"], FP_INV)
    before = exp_of(env, d["license_id"])
    j = reward(env, FP_INV, FP_NEW, "rv1").json()
    assert j["status"] == "applied" and exp_of(env, d["license_id"]) == before + timedelta(hours=24)


@pytest.mark.parametrize("case", ["no_card", "expired_paid", "trial_only", "never_activated"])
def test_nonbeta_requires_subscription_then_applies_on_purchase(env, case):
    if case == "expired_paid":
        d = bound(env, "go", starts_on_first_activation=False)
        rec = env["p"].licenses[d["license_id"]]; rec["expires_at"] = datetime.now(timezone.utc) - timedelta(hours=1)
        env["p"].event_store.save_local_license(d["license_id"], d["license_key"], rec)
    elif case == "trial_only":
        env["loop"].post("/v1/trials/claim", json={"hardware": {"fingerprint": FP_INV, "components": {}, "platform": "windows"}})
    elif case == "never_activated":
        issue(env, "pro")
    n_before = len(env["p"].licenses)
    r = reward(env, FP_INV, FP_NEW, "rv1")
    assert r.status_code == 202 and r.json()["status"] == "pending" and r.json()["code"] == "SUBSCRIPTION_REQUIRED_FOR_REFERRAL"
    assert r.json()["invite_count"] == 0 and len(env["p"].licenses) == n_before          # no trial card created
    # later purchase: valid paid pro activated -> +24h stacked on its expiry
    p = issue(env, "pro")
    activate(env, p["license_key"], FP_INV)
    exp = exp_of(env, p["license_id"])
    assert abs(exp - datetime.now(timezone.utc) - timedelta(days=30, hours=24)) < timedelta(minutes=1)
    assert sqlite3.connect(env["db"]).execute("SELECT status FROM referral_rewards").fetchone()[0] == "applied"


def test_nonbeta_pending_applies_on_renewal(env):
    d = bound(env, "plus", starts_on_first_activation=False)
    rec = env["p"].licenses[d["license_id"]]; rec["expires_at"] = datetime.now(timezone.utc) - timedelta(hours=1)
    env["p"].event_store.save_local_license(d["license_id"], d["license_key"], rec)
    assert reward(env, FP_INV, FP_NEW, "rv1").status_code == 202
    run(env["p"].renew_license(d["license_id"], extend_days=7))            # 续订
    exp = exp_of(env, d["license_id"])
    assert abs(exp - datetime.now(timezone.utc) - timedelta(days=7, hours=24)) < timedelta(minutes=1)
    assert sqlite3.connect(env["db"]).execute("SELECT status FROM referral_rewards").fetchone()[0] == "applied"


def test_pending_respects_cap_at_activation(env, monkeypatch):
    monkeypatch.setenv("REF_BONUS_CAP", "2")
    for i in range(3):
        assert reward(env, FP_INV, fp(6000 + i), f"rv{i}").status_code == 202
    d = bound(env, "plus")
    c = sqlite3.connect(env["db"])
    assert c.execute("SELECT status, COUNT(*) FROM referral_rewards GROUP BY status ORDER BY status").fetchall() == \
        [("applied", 2), ("rejected", 1)]
    assert abs(exp_of(env, d["license_id"]) - datetime.now(timezone.utc) - timedelta(days=7, hours=48)) < timedelta(minutes=1)


def test_cap_counts_only_applied(env):
    c = sqlite3.connect(env["db"])
    for i in range(5):   # 5 pending (non-beta, no subscription)
        assert reward(env, fp(8000), fp(8100 + i), f"p{i}").status_code == 202
    bound(env, "ultra", f=fp(8001), confirm_ultra=True)
    for i in range(12):
        assert reward(env, fp(8001), fp(8200 + i), f"u{i}").json()["status"] == "ultra_immutable"
    assert c.execute("SELECT COUNT(*) FROM referral_rewards WHERE status='applied'").fetchone()[0] == 0
    # ultra pending never upgrades: a non-beta ultra holder stays count-only
    assert c.execute("SELECT COUNT(*) FROM referral_rewards WHERE status='pending'").fetchone()[0] == 5


def test_beta_revoked_only_is_ineligible(env):
    d = make_beta(env, FP_INV)
    run(env["p"].revoke_license(d.license_id))
    r = reward(env, FP_INV, FP_NEW, "rv1")
    assert r.status_code == 409 and r.json()["detail"].startswith("REFERRAL_INVITER_INELIGIBLE:")


def test_r71_approved_release_v1_0(env, monkeypatch):
    """r7.1 item 4: the v1.0 identity is accepted by /v1/admin/releases and reported approved."""
    import os
    from bridge.app.services.permit_issuer import PermitIssuer
    store = env["p"].event_store
    monkeypatch.setattr(main_mod, "_STORE", store)
    monkeypatch.setattr(main_mod, "permit_issuer", PermitIssuer(CryptoEngine(), key_id="t", policy_store=store))
    body = json.load(open(os.path.join(os.path.dirname(__file__), "..", "..", "ops", "approved_release_v1.0.json")))
    q = {k: body[k] for k in ("source_sha", "release_manifest_sha256", "release_channel")}
    assert env["loop"].get("/v1/releases/status", params=q).json()["approved"] is False
    r = env["loop"].post("/v1/admin/releases", json={**body, "version": "1.0", "build_id": "v1.0"}, auth=AUTH)
    assert r.status_code == 200, r.text
    s = env["loop"].get("/v1/releases/status", params=q).json()
    assert s["approved"] is True and s["status"] == "approved"
    assert sorted(s["allowed_modes"]) == ["follow_team", "lead_team", "lobby_hitch", "normal_farm"]
    for mode in ("normal_farm", "lobby_hitch", "follow_team", "lead_team"):
        assert env["loop"].get("/v1/releases/status", params={**q, "mode_id": mode}).json()["approved"] is True
    assert "operator_note" not in s          # internal fields are not public
    pol = env["loop"].get("/v1/admin/releases", auth=AUTH).json()["policies"]
    assert any("exe_sha256=6d195881" in (p.get("operator_note") or "") for p in pol)
    assert env["remote"].get("/v1/admin/releases", auth=AUTH).status_code == 404
