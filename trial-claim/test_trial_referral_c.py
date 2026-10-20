"""BATCH C trial-claim: approval -> 8010 in-place extension; retry when 8010 is down;
least-privilege review gate. Real batch C bridge (uvicorn) on a free loopback port,
fresh temp DB, synthetic fingerprints only.
  BRIDGE_TREE=/workspace/batchc BRIDGE_PY=/workspace/r2venv/bin/python pytest -q test_trial_referral_c.py"""
import asyncio, importlib.util, json, os, shutil, socket, subprocess, sys, tempfile, threading, time, urllib.request
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.environ.get("BRIDGE_TREE", "/workspace/batchc")
PY = os.environ.get("BRIDGE_PY", sys.executable)
KEY = "rk_" + "s" * 40
INVITER, INVITEE, INVITEE2 = "a1" * 32, "b2" * 32, "c3" * 32
SHOT = ("s.png", "image/png", b"\x89PNG-synthetic")


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def bridge_cmd(db, code):
    return [PY, "-c", f"""
import asyncio, json, sys
sys.path[:0] = [{TREE!r}, {os.path.join(TREE, 'bridge')!r}]
from bridge.app.core.crypto import CryptoEngine
from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
from bridge.app.services.event_processor import SqliteEventStore
from contracts.entitlement import HardwareFingerprint
p = InMemoryKeygenProvider(CryptoEngine(), SqliteEventStore({db!r}))
{code}
"""]


class Bridge:
    def __init__(self, db, port):
        self.db, self.port, self.proc = db, port, None
        self.base = f"http://127.0.0.1:{port}"

    def start(self):
        env = dict(os.environ, SUBSCRIPTION_DB_PATH=self.db, PROVIDER_MODE="inmemory",
                   SUBSCRIPTION_ADMIN_PASSWORD="x" * 20, REFERRAL_INTERNAL_KEY=KEY,
                   PYTHONPATH=TREE + os.pathsep + os.path.join(TREE, "bridge"))
        self.proc = subprocess.Popen([PY, "-m", "uvicorn", "bridge.app.main:app", "--host", "127.0.0.1",
                                      "--port", str(self.port), "--log-level", "warning"], cwd=TREE, env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                urllib.request.urlopen(self.base + "/health", timeout=1); return self
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("bridge did not start")

    def stop(self):
        if self.proc:
            self.proc.terminate(); self.proc.wait(10); self.proc = None

    def post(self, path, body):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")


@pytest.fixture()
def world(tmp_path):
    db = str(tmp_path / "subscription_state.db")
    made = json.loads(subprocess.check_output(bridge_cmd(db, f"""
mk = lambda t, n: asyncio.run(p.create_license('c', 'c@example.invalid', {{'plus':'plus_7d','test':'trial_1d'}}[t], duration_days={{'plus':7,'test':1}}[t], device_limit=1, tier=t))
pool = [mk('test', i).license_key for i in range(4)]
inv = mk('plus', 0)
asyncio.run(p.activate_device(inv.license_key, HardwareFingerprint(fingerprint={INVITER!r}, components={{}}, platform='windows')))
print(json.dumps({{'pool': pool, 'inv_id': inv.license_id, 'inv_key': inv.license_key, 'inv_exp': inv.expires_at.isoformat()}}))
"""), cwd=TREE))
    br = Bridge(db, free_port())
    tc = str(tmp_path / "tc"); os.makedirs(tc)
    for f in ("server.py", "trial_store_v2.py", "migrate_pool.py", "review_gate.py"):
        shutil.copy(os.path.join(HERE, f), tc)
    os.environ["SHUABAO_SUBSCRIPTION_BASE"] = br.base
    os.environ["REFERRAL_INTERNAL_KEY"] = KEY
    sys.modules.pop("trial_store_v2", None)
    spec = importlib.util.spec_from_file_location(f"tcc_{tmp_path.name}", os.path.join(tc, "server.py"))
    srv = importlib.util.module_from_spec(spec); spec.loader.exec_module(srv)
    with open(os.path.join(tc, "pool.json"), "w") as fh:
        json.dump({"pool": made["pool"], "bonus_pool": ["SSB-BONU-SNOT-USED"], "claims": {}}, fh)
    yield {"br": br, "srv": srv, "tc": tc, **made}
    br.stop()


def inviter_exp(w):
    st, v = w["br"].post("/v1/entitlements/validate", {"license_key": w["inv_key"],
                         "hardware": {"fingerprint": INVITER, "components": {}, "platform": "windows"}})
    return v["license"]["expires_at"], v


def invite(w, invitee):
    srv = w["srv"]
    tok = srv.decide(INVITER)["token"]
    assert srv.decide(invitee, ref=tok, shot=SHOT).get("pending") is True


def test_approve_extends_inviter_in_place(world):
    w = world; w["br"].start()
    before, _ = inviter_exp(w)
    invite(w, INVITEE)
    res = w["srv"].approve_pending(INVITEE)
    assert res["ok"] and res["activated"] is True and res["referral"]["state"] == "rewarded"
    after, v = inviter_exp(w)
    from datetime import datetime
    d = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
    assert (d(after) - d(before)).total_seconds() == pytest.approx(86400, abs=2)
    assert v["tier"] == "plus" and v["tier_name"] == "Plus 订阅"
    st = json.load(open(os.path.join(w["tc"], "pool.json")))
    assert st["bonus_pool"] == ["SSB-BONU-SNOT-USED"]                # no card drawn
    assert st["referral_outbox"][INVITEE]["state"] == "rewarded"
    assert st["ref_counts"][INVITER] == 1
    # invitee query shows its own trial identity (#brandSubBadge)
    q = w["srv"].decide(INVITEE)
    assert q["activated"] is True and q["tier"] == "trial" and q["tier_name"] == "试用" and q["plan"] == "trial_1d"
    # duplicate delivery of the same review is idempotent on 8010
    rid = st["referral_outbox"][INVITEE]["review_id"]
    s2, _c2, b2 = w["srv"]._referral_post(INVITER, INVITEE, rid)
    assert s2 == 200 and b2["idempotent"] is True
    assert inviter_exp(w)[0] == after


def test_8010_down_keeps_review_retryable(world):
    w = world
    invite(w, INVITEE)
    res = w["srv"].approve_pending(INVITEE)                         # 8010 not running
    assert res["ok"] and res["referral"]["state"] == "pending"
    st = json.load(open(os.path.join(w["tc"], "pool.json")))
    e = st["referral_outbox"][INVITEE]
    assert e["state"] == "pending" and e["attempts"] == 1 and e["last_error"]
    assert st.get("ref_counts", {}).get(INVITER, 0) == 0             # NOT marked rewarded
    rid = e["review_id"]
    w["br"].start()
    before, _ = inviter_exp(w)
    out = w["srv"].flush_referrals()
    assert out[INVITEE]["state"] == "rewarded"
    st = json.load(open(os.path.join(w["tc"], "pool.json")))
    assert st["referral_outbox"][INVITEE]["review_id"] == rid and st["referral_outbox"][INVITEE]["attempts"] == 2
    assert w["srv"].flush_referrals() == {INVITEE: {"state": "rewarded", "code": None}}   # nothing re-sent
    after, _ = inviter_exp(w)
    assert after > before


def test_bad_key_stays_pending(world, monkeypatch):
    w = world; w["br"].start()
    monkeypatch.setenv("REFERRAL_INTERNAL_KEY", "wrong" * 8)
    invite(w, INVITEE)
    assert w["srv"].approve_pending(INVITEE)["referral"] == {"state": "pending", "code": "REFERRAL_UNAUTHORIZED"}
    monkeypatch.setenv("REFERRAL_INTERNAL_KEY", KEY)
    assert w["srv"].flush_referrals()[INVITEE]["state"] == "rewarded"


def test_review_gate_peer_cred_and_token(world, tmp_path):
    import hashlib
    w = world; w["br"].start()
    gate = sys.modules.get("review_gate") or importlib.import_module("review_gate")
    token = "tok_" + "z" * 40
    sock = str(tmp_path / "review.sock")
    stop = threading.Event()
    t = threading.Thread(target=gate.serve, args=(vars(w["srv"]), sock, os.getuid(),
                                                  hashlib.sha256(token.encode()).hexdigest(), stop), daemon=True)
    t.start()
    for _ in range(50):
        if os.path.exists(sock): break
        time.sleep(0.05)

    def call(req):
        s = socket.socket(socket.AF_UNIX); s.connect(sock); s.sendall(json.dumps(req).encode() + b"\n")
        buf = b""
        while True:
            c = s.recv(65536)
            if not c: break
            buf += c
        return json.loads(buf)

    invite(w, INVITEE); invite(w, INVITEE2)
    assert call({"op": "list", "token": "bad"}) == {"ok": False, "code": "REVIEW_UNAUTHORIZED"}
    lst = call({"op": "list", "token": token})
    assert lst["ok"] and len(lst["pending"]) == 2
    blob = json.dumps(lst)
    assert INVITEE not in blob and INVITER not in blob and "…" in lst["pending"][0]["fingerprint_masked"]
    refs = {p["fingerprint_masked"]: p["review_ref"] for p in lst["pending"]}
    r1 = refs[INVITEE[:4] + "…" + INVITEE[-4:]]; r2 = refs[INVITEE2[:4] + "…" + INVITEE2[-4:]]
    shot = call({"op": "shot", "token": token, "review_ref": r1})
    assert shot["ok"] and shot["b64"]
    ap = call({"op": "approve", "token": token, "review_ref": r1})
    assert ap["ok"] and ap["referral_state"] == "rewarded" and "license_key" not in json.dumps(ap)
    rj = call({"op": "reject", "token": token, "review_ref": r2, "reason": "截图不清晰"})
    assert rj["ok"]
    assert call({"op": "approve", "token": token, "review_ref": r2})["code"] == "REVIEW_NOT_PENDING"
    # wrong peer uid
    assert gate.handle(vars(w["srv"]), {"op": "list", "token": token}, peer_uid=os.getuid() + 1,
                       allowed_uid=os.getuid(), token_sha=hashlib.sha256(token.encode()).hexdigest())["code"] == "REVIEW_FORBIDDEN"
    stop.set(); t.join(3)


# ---------------- r7 Owner rulings 5 / 6 / 8 ----------------
OTHER_INVITER = "d4" * 32


def test_r7_attribution_locked_by_first_claim(world):
    """ruling 5: first claim via r=<token> fixes the inviter; a resubmission after rejection with another
    inviter's token does not re-attribute; approval rewards the first inviter once."""
    w = world; w["br"].start(); srv = w["srv"]
    tok1 = srv.decide(INVITER)["token"]
    tok2 = srv.decide(OTHER_INVITER)["token"]
    assert srv.decide(INVITEE, ref=tok1, shot=SHOT).get("pending") is True
    assert srv.reject_pending(INVITEE, "blurry")["ok"]
    assert srv.decide(INVITEE, ref=tok2, shot=SHOT).get("pending") is True    # resubmit with another token
    st = json.load(open(os.path.join(w["tc"], "pool.json")))
    assert st["pending"][INVITEE]["inviter"] == INVITER and st["attribution"][INVITEE] == INVITER
    assert [e["code"] for e in st["invite_log"][INVITER]] == [INVITEE]           # no duplicate log entry
    assert INVITEE not in [e["code"] for e in st.get("invite_log", {}).get(OTHER_INVITER, [])]
    res = srv.approve_pending(INVITEE)
    assert res["ok"] and res["inviter"] == INVITER and res["referral"]["state"] == "rewarded"
    # once per device_code lifetime on 8010: a second review id for the same invitee is refused
    s2, c2, _b = srv._referral_post(OTHER_INVITER, INVITEE, "rv_other")
    assert s2 == 409 and c2 == "REFERRAL_ALREADY_REWARDED"


def test_r71_subscription_required_deferred_then_applied(world):
    """r7.1: non-beta inviter without a valid paid subscription -> 8010 202 SUBSCRIPTION_REQUIRED_FOR_REFERRAL; outbox 'deferred', no cap
    count; reward applied by 8010 when the inviter activates a card."""
    w = world; w["br"].start(); srv = w["srv"]
    tok = srv.decide(OTHER_INVITER)["token"]                        # OTHER_INVITER has no card on 8010
    assert srv.decide(INVITEE2, ref=tok, shot=SHOT).get("pending") is True
    res = srv.approve_pending(INVITEE2)
    assert res["ok"] and res["referral"]["state"] == "deferred" and res["referral"]["code"] == "SUBSCRIPTION_REQUIRED_FOR_REFERRAL"
    st = json.load(open(os.path.join(w["tc"], "pool.json")))
    assert st["referral_outbox"][INVITEE2]["state"] == "deferred"
    assert st.get("ref_counts", {}).get(OTHER_INVITER, 0) == 0
    assert srv.flush_referrals() .get(INVITEE2, {}).get("state") in ("deferred", None)   # not retried
    # inviter now activates a plus card -> pending reward applied (+24h)
    w["br"].stop()
    out = json.loads(subprocess.check_output(bridge_cmd(w["br"].db, f"""
d = asyncio.run(p.create_license('c', 'c@example.invalid', 'plus_7d', duration_days=7, device_limit=1, tier='plus'))
asyncio.run(p.activate_device(d.license_key, HardwareFingerprint(fingerprint={OTHER_INVITER!r}, components={{}}, platform='windows')))
import sqlite3
row = sqlite3.connect({w['br'].db!r}).execute("SELECT status, inviter_license_id FROM referral_rewards WHERE invitee_fingerprint=?", ({INVITEE2!r},)).fetchone()
print(json.dumps({{'row': row, 'id': d.license_id, 'exp': p.licenses[d.license_id]['expires_at'].isoformat(), 'created': d.created_at.isoformat() if getattr(d, 'created_at', None) else None}}))
"""), cwd=TREE))
    assert out["row"] == ["applied", out["id"]]
    from datetime import datetime, timezone, timedelta
    exp = datetime.fromisoformat(out["exp"])
    assert abs(exp - datetime.now(timezone.utc) - timedelta(days=8)) < timedelta(minutes=2)


def test_r7_file_drop_disabled(world):
    """ruling 8: a JSON file in review-queue/ is never consumed; the claim stays pending."""
    w = world; srv = w["srv"]
    assert srv.decide(INVITEE, shot=SHOT).get("pending") is True
    qd = os.path.join(w["tc"], "review-queue"); os.makedirs(qd, exist_ok=True)
    with open(os.path.join(qd, "x.json"), "w") as fh:
        json.dump({"action": "approve", "code": INVITEE}, fh)
    srv.decide("e5" * 32)
    st = json.load(open(os.path.join(w["tc"], "pool.json")))
    assert INVITEE not in st.get("claims", {}) and st["pending"][INVITEE]["status"] == "pending"
    assert os.path.exists(os.path.join(qd, "x.json"))
