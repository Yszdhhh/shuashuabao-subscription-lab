"""r3 trial-claim storage v2 tests. Real bridge (BATCH A tree, uvicorn, temp DB) behind the real legacy
interface (/v1/devices/activate + /v1/entitlements/validate). Run:
  BRIDGE_TREE=/workspace/efix_batcha pytest -q test_trial_r3.py"""
import asyncio, importlib.util, io, json, os, re, shutil, socket, subprocess, sys, tempfile, threading, time, urllib.request
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.environ.get("BRIDGE_TREE", "/workspace/efix_batcha")
PY = os.environ.get("BRIDGE_PY", sys.executable)
CARD = re.compile(r"SSB-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}")
HEX64 = re.compile(r"\b[0-9a-f]{64}\b")


@pytest.fixture(scope="module")
def bridge():
    tmp = tempfile.mkdtemp(prefix="tr3-br-")
    db = os.path.join(tmp, "s.db")
    code = f"""
import asyncio, json, sys
sys.path[:0] = [{TREE!r}, {os.path.join(TREE, 'bridge')!r}]
from bridge.app.core.crypto import CryptoEngine
from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
from bridge.app.services.event_processor import SqliteEventStore
p = InMemoryKeygenProvider(CryptoEngine(), SqliteEventStore({db!r}))
mk = lambda: asyncio.run(p.create_license(customer_id="tr3", customer_email="t@example.invalid", plan="trial", duration_days=1, device_limit=1))
cards = [mk().license_key for _ in range(8)]
r = mk(); asyncio.run(p.revoke_license(r.license_id))
print(json.dumps({{"cards": cards, "revoked": r.license_key}}))
"""
    made = json.loads(subprocess.check_output([PY, "-c", code], cwd=TREE))
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    env = dict(os.environ, SUBSCRIPTION_DB_PATH=db, PROVIDER_MODE="inmemory", SUBSCRIPTION_ADMIN_PASSWORD="x" * 20,
               PYTHONPATH=TREE + os.pathsep + os.path.join(TREE, "bridge"))
    proc = subprocess.Popen([PY, "-m", "uvicorn", "bridge.app.main:app", "--host", "127.0.0.1", "--port", str(port),
                             "--log-level", "warning"], cwd=TREE, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1); break
        except OSError:
            time.sleep(0.1)
    yield {"base": f"http://127.0.0.1:{port}", **made}
    proc.terminate(); proc.wait(10); shutil.rmtree(tmp, ignore_errors=True)


def load_server(tmp, base, legacy_card="0"):
    for f in ("server.py", "trial_store_v2.py", "migrate_pool.py"):
        shutil.copy(os.path.join(HERE, f), tmp)
    os.environ["SHUABAO_SUBSCRIPTION_BASE"] = base
    os.environ["TRIAL_POOL_KEY_FILE"] = os.path.join(tmp, "k.key")
    os.environ["TRIAL_LEGACY_CARD"] = legacy_card
    sys.modules.pop("trial_store_v2", None)
    spec = importlib.util.spec_from_file_location(f"srv_{os.path.basename(tmp)}", os.path.join(tmp, "server.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def write_v1(tmp, cards, claims=None, pending=None, ref_tokens=None):
    d = {"batch": "t", "pool": cards[:3], "bonus_pool": cards[3:4], "claims": claims or {}, "closed": False,
         "pending": pending or {}, "ref_tokens": ref_tokens or {}, "ref_counts": {}, "ref_cards": {}, "invite_log": {}}
    fd = os.open(os.path.join(tmp, "pool.json"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, json.dumps(d).encode()); os.close(fd)
    return d


def migrate(tmp):
    r = subprocess.run([sys.executable, os.path.join(tmp, "migrate_pool.py"), "--src", os.path.join(tmp, "pool.json"),
                        "--dst", os.path.join(tmp, "pool.v2.json"), "--key-file", os.path.join(tmp, "k.key"), "--gen-key"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    rep = json.loads(r.stdout)
    assert not CARD.search(r.stdout) and not HEX64.search(r.stdout)
    os.replace(os.path.join(tmp, "pool.v2.json"), os.path.join(tmp, "pool.json"))
    return rep


SHOT = ("s.jpg", "image/jpeg", b"fake-jpeg")


def approve_via_queue(tmp, code):
    os.makedirs(os.path.join(tmp, "review-queue"), exist_ok=True)
    json.dump({"action": "approve", "code": code}, open(os.path.join(tmp, "review-queue", f"{time.time_ns()}.json"), "w"))


def test_legacy_self_check_unchanged():
    """No schema:2 -> every legacy code path (prod self-check) behaves exactly as before."""
    r = subprocess.run([sys.executable, os.path.join(HERE, "server.py"), "--self-check"], capture_output=True, text=True, cwd=HERE)
    assert r.returncode == 0 and "self_check_ok" in (r.stdout + r.stderr)


def test_migration_roundtrip_and_no_plaintext(tmp_path, bridge):
    tmp = str(tmp_path); load_server(tmp, bridge["base"])
    mc = "a" * 64; inviter = "b" * 64
    write_v1(tmp, bridge["cards"], claims={mc: bridge["cards"][5]}, pending={"c" * 64: {"ref": "t1", "inviter": inviter, "shot": "uploads/x.jpg",
             "at": "2026-10-18T00:00:00+00:00", "status": "rejected", "reason": "r"}}, ref_tokens={"t1": inviter})
    rep = migrate(tmp)
    assert rep["dst_leak"] == {"card_pattern_hits": 0, "machine_code_hits": 0}
    assert rep["cards_roundtrip_equal"] and rep["claims_roundtrip_ok"] and rep["pool_order_kept"] and rep["ref_tokens_ok"]
    raw = open(os.path.join(tmp, "pool.json")).read()
    assert not CARD.search(raw) and not HEX64.search(raw)
    assert oct(os.stat(os.path.join(tmp, "pool.json")).st_mode & 0o777) == "0o600"


def test_v2_claim_activate_reveal_once_idempotent(tmp_path, bridge):
    tmp = str(tmp_path); srv = load_server(tmp, bridge["base"])
    write_v1(tmp, bridge["cards"]); migrate(tmp)
    mc = "d" * 64
    err = io.StringIO()
    with redirect_stderr(err):
        assert srv.decide(mc, shot=SHOT)["pending"] is True
        approve_via_queue(tmp, mc)
        r = srv.decide(mc)                       # drains queue: approve + activate on the bridge
        assert "card" not in r and r.get("card_last4")
        r2 = srv.decide(mc)                      # repeat query
        assert r2["activation_state"] == "ok" and r2["activated"] is True and "card" not in r2
        tok = r2["reveal_token"]
        a = srv.redeem_reveal(mc, tok, "idem-1")
        assert a["ok"] is True and CARD.fullmatch(a["card"]) and a["replayed"] is False
        b = srv.redeem_reveal(mc, tok, "idem-1")  # caller timed out -> retries with same key -> same result
        assert b["ok"] is True and b["card"] == a["card"] and b["replayed"] is True
        c = srv.redeem_reveal(mc, tok, "idem-2")
        assert c == {"ok": False, "code": "TOKEN_USED", "l4": a["card"][-4:]}
        assert srv.redeem_reveal("e" * 64, tok, "idem-3")["code"] == "TOKEN_INVALID"
        assert srv.redeem_reveal(mc, tok, "")["code"] == "IDEMPOTENCY_KEY_REQUIRED"
        assert "reveal_token" not in srv.decide(mc)   # revealed once -> no new token
    raw = open(os.path.join(tmp, "pool.json")).read()
    assert not CARD.search(raw) and not HEX64.search(raw)   # still no plaintext at rest after claims/tokens
    logs = err.getvalue()
    assert "trial_activate" in logs and not CARD.search(logs) and not HEX64.search(logs)


def test_token_expiry_and_single_live_token(tmp_path, bridge):
    tmp = str(tmp_path); srv = load_server(tmp, bridge["base"])
    write_v1(tmp, bridge["cards"]); migrate(tmp)
    mc = "f" * 64
    srv.decide(mc, shot=SHOT); approve_via_queue(tmp, mc); srv.decide(mc)
    t1 = srv.decide(mc)["reveal_token"]; t2 = srv.decide(mc)["reveal_token"]
    assert srv.redeem_reveal(mc, t1, "k")["code"] == "TOKEN_INVALID"     # superseded
    d = json.load(open(os.path.join(tmp, "pool.json")))
    for t in d["tokens"].values():
        t["exp"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    json.dump(d, open(os.path.join(tmp, "pool.json"), "w"))
    assert srv.redeem_reveal(mc, t2, "k")["code"] == "TOKEN_EXPIRED"


def test_concurrent_redeem_exactly_one_winner(tmp_path, bridge):
    tmp = str(tmp_path); srv = load_server(tmp, bridge["base"])
    write_v1(tmp, bridge["cards"]); migrate(tmp)
    mc = "1" * 64
    srv.decide(mc, shot=SHOT); approve_via_queue(tmp, mc); srv.decide(mc)
    tok = srv.decide(mc)["reveal_token"]
    res = []
    th = [threading.Thread(target=lambda i=i: res.append(srv.redeem_reveal(mc, tok, f"k{i}"))) for i in range(12)]
    [t.start() for t in th]; [t.join() for t in th]
    assert sum(1 for r in res if r.get("ok")) == 1 and sum(1 for r in res if r.get("code") == "TOKEN_USED") == 11


def test_timeout_after_server_success_recovers_by_query(tmp_path, bridge):
    tmp = str(tmp_path); srv = load_server(tmp, bridge["base"])
    real = srv._post_json; calls = []
    def flaky(path, payload, timeout):
        calls.append(path)
        if path == "/v1/devices/activate" and calls.count(path) == 1:
            real(path, payload, timeout)          # the bridge DID bind ...
            raise TimeoutError("caller timeout")  # ... but the caller never saw the answer
        return real(path, payload, timeout)
    res = srv._v2.activate_with_recovery(bridge["cards"][6], "2" * 64, flaky, 5)
    assert res["state"] == "ok" and res["why"].startswith("recovered:validate_bound")
    assert calls == ["/v1/devices/activate", "/v1/entitlements/validate"]


def test_bridge_down_is_unknown_not_failed(tmp_path, bridge):
    tmp = str(tmp_path); srv = load_server(tmp, "http://127.0.0.1:9")   # nothing listens
    write_v1(tmp, bridge["cards"]); migrate(tmp)
    mc = "3" * 64
    srv.decide(mc, shot=SHOT); approve_via_queue(tmp, mc); srv.decide(mc)
    r = srv.decide(mc)
    assert r["activation_state"] == "unknown" and r["activated"] is None and "未确认" in r["message"]


def test_revoked_pool_card_reports_failed(tmp_path, bridge):
    tmp = str(tmp_path); srv = load_server(tmp, bridge["base"])
    res = srv._v2.activate_with_recovery(bridge["revoked"], "4" * 64, srv._post_json, 5)
    assert res == {"state": "failed", "why": "LICENSE_REVOKED"}


def test_missing_key_fails_closed(tmp_path, bridge):
    tmp = str(tmp_path); srv = load_server(tmp, bridge["base"])
    write_v1(tmp, bridge["cards"]); migrate(tmp)
    os.remove(os.path.join(tmp, "k.key")); srv._KEYS = None
    assert srv.decide("5" * 64) == {"message": srv.MSG_UNAVAILABLE}


def test_legacy_card_flag_compat_period(tmp_path, bridge):
    tmp = str(tmp_path); srv = load_server(tmp, bridge["base"], legacy_card="1")
    write_v1(tmp, bridge["cards"]); migrate(tmp)
    mc = "6" * 64
    srv.decide(mc, shot=SHOT); approve_via_queue(tmp, mc); srv.decide(mc)
    assert CARD.fullmatch(srv.decide(mc)["card"])     # cached legacy page still gets the card
