"""Current-card recovery uses bound records, never historical activation success."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
import time
import types
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import bridge.app.main as main
from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
from bridge.app.services import referral
from bridge.app.services.current_license import select_current
from bridge.app.services.event_processor import SqliteEventStore
from contracts.entitlement import HardwareFingerprint

FP = "a" * 64
KEY = "current-test-" + "k" * 40


def run(coro):
    return asyncio.run(coro)


def drain_sync(provider):
    worker = provider._claim_sync_worker
    if worker is not None:
        worker.join(timeout=5)
        assert not worker.is_alive()


@pytest.fixture
def env(tmp_path, monkeypatch):
    store = SqliteEventStore(str(tmp_path / "state.db"))
    provider = InMemoryKeygenProvider(event_store=store)
    monkeypatch.setattr(main, "keygen_provider", provider)
    monkeypatch.setenv("REFERRAL_INTERNAL_KEY", KEY)
    monkeypatch.delenv("TRIAL_CLAIM_SYNC_URL", raising=False)
    monkeypatch.setenv("TRIAL_LEGACY_CARD", "1")
    client = TestClient(main.app, client=("127.0.0.1", 40100))
    if os.name == "nt":
        # Import only: current status must not acquire a write lock on Windows either.
        monkeypatch.setitem(sys.modules, "fcntl", types.ModuleType("fcntl"))
    path = Path(__file__).resolve().parents[2] / "trial-claim" / "server.py"
    spec = importlib.util.spec_from_file_location("trial_current_server", path)
    server = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server)
    server.DATA = str(tmp_path / "pool.json")
    server.LOCK = str(tmp_path / "pool.lock")
    server.ROOT = str(tmp_path)
    Path(server.DATA).write_text(json.dumps({"pool": ["unused"], "claims": {FP: "old"},
                                           "ref_tokens": {"existing-token": FP}}))

    def current(fp):
        result = client.post("/internal/trials/current", json={"fingerprint": fp},
                             headers={"X-Referral-Internal-Key": KEY})
        assert result.status_code == 200
        return result.json()["current"]
    monkeypatch.setattr(server, "_current_claim", current)
    return provider, store, server, client


def issue(provider, *, fp=FP, days=1, beta=False):
    dto = run(provider.create_license("current-test", "test@example.invalid", "go_daily",
                                     duration_days=1, tier="go", metadata={"is_beta_user": beta,
                                                                         "grace_days": 0}))
    run(provider.activate_device(dto.license_key, HardwareFingerprint(fingerprint=fp)))
    run(provider.set_license_expiry(dto.license_id, datetime.now(timezone.utc) + timedelta(days=days)))
    return dto


@pytest.mark.parametrize("schema", [1, 2])
def test_old_expired_new_current_and_read_only(env, schema):
    provider, store, server, _ = env
    old = issue(provider, days=-4)
    new = issue(provider, days=2)
    issue(provider, fp="b" * 64, days=100)
    if schema == 2:
        server._KEYS = server._v2.Keys(b"x" * 32)
        data = {"schema": 2, "pool": [], "claims": {server._keys().mref(FP): {
            **server._keys().card(old.license_key), "act": {"state": "ok"}}}}
        Path(server.DATA).write_text(json.dumps(data))
    before = Path(server.DATA).read_bytes()
    changes = store._conn.total_changes
    result = server.decide(FP)
    assert result["card"] == new.license_key and result["activated"] is True
    assert result["expires_at"] == provider.licenses[new.license_id]["expires_at"].isoformat()
    assert Path(server.DATA).read_bytes() == before and store._conn.total_changes == changes
    assert run(provider.validate_license(result["card"], FP)).valid


def test_expired_history_ok_and_renewal_immediate(env):
    provider, _, server, _ = env
    old = issue(provider, days=-4)
    expired = server.decide(FP)
    assert expired["card"] == old.license_key
    assert expired["activated"] is False and expired["status"] == "EXPIRED"
    assert expired["code"] == "LICENSE_EXPIRED" and expired["expires_at"]
    run(provider.renew_license(old.license_id, 3))
    assert server.decide(FP)["activated"] is True


def test_two_valid_choose_latest_expiry(env):
    provider, _, server, _ = env
    first = issue(provider, days=5)
    second = issue(provider, days=2)
    assert server.decide(FP)["card"] == first.license_key
    run(provider.renew_license(second.license_id, 10))
    assert server.decide(FP)["card"] == second.license_key
    run(provider.suspend_license(second.license_id))
    assert server.decide(FP)["card"] == first.license_key
    run(provider.revoke_license(first.license_id))
    assert server.decide(FP)["activated"] is False


def test_direct_claim_pointer_updated_on_new_card(env):
    provider, store, server, _ = env
    old = run(provider.claim_device_trial(HardwareFingerprint(fingerprint=FP)))
    run(provider.set_license_expiry(old.license_id, datetime.now(timezone.utc) - timedelta(days=4)))
    new = issue(provider, days=2)
    assert store.get_device_trial(FP)["license_id"] == new.license_id
    assert server.decide(FP)["card"] == new.license_key


def test_never_claimed_and_missing_binding(env, monkeypatch):
    _, _, server, _ = env
    monkeypatch.setitem(server._LEGACY, "decide", lambda code, **kw: {"message": "unchanged"})
    assert server.decide("c" * 64) == {"message": "unchanged"}
    assert server.decide(FP)["code"] == "LICENSE_NOT_FOUND"


@pytest.mark.parametrize("listed,flagged", [(True, False), (False, True), (False, False)])
def test_beta_union_in_trial_and_validate(env, listed, flagged):
    provider, store, server, client = env
    dto = issue(provider, beta=flagged)
    if listed:
        referral.mark_beta(store._conn, FP, dto.license_id, "test")
    result = client.post("/v1/entitlements/validate", json={"license_key": dto.license_key,
                         "hardware": {"fingerprint": FP}}).json()
    assert result["is_beta_user"] is (listed or flagged)
    assert result["license"]["is_beta_user"] is (listed or flagged)
    assert server.decide(FP)["is_beta_user"] is (listed or flagged)
    assert provider.licenses[dto.license_id].get("is_beta_user") is None


def test_internal_current_auth_and_no_forwarding(env):
    _, _, _, client = env
    assert client.post("/internal/trials/current", json={"fingerprint": FP}).status_code == 403
    assert client.post("/internal/trials/current", json={"fingerprint": FP}, headers={
        "X-Referral-Internal-Key": KEY, "X-Forwarded-For": "127.0.0.1"}).status_code == 403
    remote = TestClient(main.app, client=("203.0.113.1", 40000))
    assert remote.post("/internal/trials/current", json={"fingerprint": FP}, headers={
        "X-Referral-Internal-Key": KEY}).status_code == 403


def test_missing_expiry_does_not_claim_permanent_validity():
    rec = {"id": "missing-expiry", "key": "card", "status": "ACTIVE", "expires_at": None}
    assert select_current([rec])["activated"] is False


def test_expiry_boundary_and_naive_legacy_timestamp():
    now = datetime(2026, 10, 24, 6, tzinfo=timezone.utc)
    rec = {"id": "boundary", "key": "card", "status": "ACTIVE",
           "expires_at": now.replace(tzinfo=None)}
    assert select_current([rec], now=now)["activated"] is True
    assert select_current([rec], now=now + timedelta(microseconds=1))["status"] == "EXPIRED"


@pytest.mark.skipif(os.name == "nt", reason="requires production POSIX file locking")
@pytest.mark.parametrize("schema", [1, 2])
def test_write_callback_mirror_cron_and_reveal(env, monkeypatch, schema):
    import threading
    provider, store, server, _ = env
    old = run(provider.claim_device_trial(HardwareFingerprint(fingerprint=FP)))
    if schema == 2:
        server._KEYS = server._v2.Keys(b"x" * 32)
        Path(server.DATA).write_text(json.dumps({"schema": 2, "pool": [], "claims": {
            server._keys().mref(FP): {**server._keys().card(old.license_key),
                                    "revealed": True, "act": {"state": "ok"}}}}))
    httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    worker = threading.Thread(target=httpd.serve_forever, daemon=True)
    worker.start()
    monkeypatch.setenv("TRIAL_CLAIM_SYNC_URL", f"http://127.0.0.1:{httpd.server_port}/internal/trials/sync")
    try:
        run(provider.set_license_expiry(old.license_id, datetime.now(timezone.utc) - timedelta(days=4)))
        new = issue(provider, days=5)
        drain_sync(provider)
        assert store.get_device_trial(FP)["license_key"] == new.license_key
        data = json.loads(Path(server.DATA).read_text())
        if schema == 1:
            assert data["claims"][FP] == new.license_key
        else:
            assert server._keys().card_plain(data["claims"][server._keys().mref(FP)]) == new.license_key
            monkeypatch.setenv("TRIAL_LEGACY_CARD", "0")
            status = server.decide(FP)
            assert "card" not in status and status["reveal_token"]
            revealed = server.redeem_reveal(FP, status["reveal_token"], "current-test-redeem")
            assert revealed["ok"] and revealed["card"] == new.license_key
        mirror = Path(server.ROOT) / "dashboard_claims.json"
        assert json.loads(mirror.read_text())[FP]["key"] == new.license_key
        path = Path(__file__).resolve().parents[2] / "ops" / "shuabao-dashboard-claims-sync.py"
        spec = importlib.util.spec_from_file_location("current_mirror", path)
        cron = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cron)
        monkeypatch.setattr(cron, "DB", store.db_path)
        monkeypatch.setattr(cron, "OUT", str(mirror))
        monkeypatch.setattr(cron.os, "chown", lambda *args: None)
        assert cron.main() == 0
        assert json.loads(mirror.read_text())[FP]["key"] == new.license_key
    finally:
        httpd.shutdown()
        httpd.server_close()
        worker.join(timeout=5)


@pytest.mark.parametrize("operation", ["activate", "expiry", "claim", "renew", "sync"])
@pytest.mark.parametrize("failure", ["timeout", "down"])
def test_callback_failure_does_not_block_requests(env, monkeypatch, caplog, operation, failure):
    provider, _, _, client = env
    dto = issue(provider)
    run(provider.set_device_limit(dto.license_id, 3))
    started, release = threading.Event(), threading.Event()
    timeouts = []

    def unavailable(req, timeout):
        timeouts.append(timeout)
        started.set()
        if failure == "timeout":
            release.wait(2)
            raise TimeoutError("synthetic callback timeout")
        raise ConnectionRefusedError("synthetic callback outage")

    monkeypatch.setattr("urllib.request.urlopen", unavailable)
    monkeypatch.setenv("TRIAL_CLAIM_SYNC_URL", "http://127.0.0.1:1/internal/trials/sync")
    monkeypatch.setattr(main, "_TRIAL_RATE_LIMITS", main.TrialRateLimits({}))
    monkeypatch.setenv("SHUABAO_TRIALS_ENABLED", "1")
    try:
        begin = time.monotonic()
        if operation == "activate":
            result = client.post("/v1/devices/activate", json={"license_key": dto.license_key,
                                 "hardware": {"fingerprint": "b" * 64}})
            assert result.status_code == 200
        elif operation == "claim":
            result = client.post("/v1/trials/claim", json={"hardware": {"fingerprint": "c" * 64}})
            assert result.status_code == 200
        elif operation == "expiry":
            run(provider.set_license_expiry(dto.license_id, datetime.now(timezone.utc) + timedelta(days=3)))
        elif operation == "renew":
            run(provider.renew_license(dto.license_id, 2))
        else:
            # Synchronous callers (including loading/reconciliation) must return promptly too.
            provider._sync_current_claims(provider.licenses[dto.license_id])
        assert time.monotonic() - begin < 1.5
        assert started.wait(1)
        assert client.get("/health").status_code == 200
    finally:
        release.set()
        drain_sync(provider)
    assert timeouts and set(timeouts) == {1}
    assert "current_claim_sync_failed" in caplog.text


@pytest.mark.skipif(os.name == "nt", reason="requires production POSIX file locking")
def test_shared_license_conflict_still_syncs_pool_and_mirror(env, monkeypatch, caplog):
    provider, store, server, _ = env
    old = run(provider.claim_device_trial(HardwareFingerprint(fingerprint=FP)))
    other_fp = "b" * 64
    shared = run(provider.claim_device_trial(HardwareFingerprint(fingerprint=other_fp)))
    run(provider.set_device_limit(shared.license_id, 2))
    run(provider.set_license_expiry(shared.license_id, datetime.now(timezone.utc) + timedelta(days=5)))
    calls = []

    @contextmanager
    def callback(req, timeout):
        payload = json.loads(req.data)
        calls.append(payload)
        server._sync_current_claim(payload["fingerprint"], payload["current"])
        yield types.SimpleNamespace(status=200)

    monkeypatch.setattr("urllib.request.urlopen", callback)
    monkeypatch.setenv("TRIAL_CLAIM_SYNC_URL", "http://127.0.0.1:1/internal/trials/sync")
    run(provider.activate_device(shared.license_key, HardwareFingerprint(fingerprint=FP)))
    drain_sync(provider)
    assert store.get_device_trial(FP)["license_id"] == old.license_id
    assert store.get_device_trial(other_fp)["license_id"] == shared.license_id
    assert any(p["fingerprint"] == FP and p["current"]["card"] == shared.license_key for p in calls)
    assert json.loads(Path(server.DATA).read_text())["claims"][FP] == shared.license_key
    assert json.loads((Path(server.ROOT) / "dashboard_claims.json").read_text())[FP]["key"] == shared.license_key
    assert "device_trial_current_conflict" in caplog.text


def test_current_lookup_snapshots_licenses_during_concurrent_creation(env):
    provider, _, _, client = env
    dto = issue(provider)
    entered, resume = threading.Event(), threading.Event()

    class PausedDevice(dict):
        def get(self, key, default=None):
            entered.set()
            assert resume.wait(3)
            return super().get(key, default)

    provider.activations[dto.license_id][0] = PausedDevice(provider.activations[dto.license_id][0])
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(client.post, "/internal/trials/current", json={"fingerprint": FP},
                                 headers={"X-Referral-Internal-Key": KEY})
        try:
            assert entered.wait(2)
            for _ in range(10):
                run(provider.create_license("concurrent", "test@example.invalid", "go_daily"))
        finally:
            resume.set()
        result = future.result(timeout=3)
    assert result.status_code == 200
    assert result.json()["current"]["card"] == dto.license_key


def test_pending_callbacks_coalesce_to_latest_state(env, monkeypatch):
    provider, _, _, _ = env
    dto = issue(provider)
    entered, release = threading.Event(), threading.Event()
    sent = []

    @contextmanager
    def callback(req, timeout):
        sent.append(json.loads(req.data)["current"])
        entered.set()
        assert release.wait(3)
        yield types.SimpleNamespace(status=200)

    monkeypatch.setattr("urllib.request.urlopen", callback)
    monkeypatch.setenv("TRIAL_CLAIM_SYNC_URL", "http://127.0.0.1:1/internal/trials/sync")
    try:
        run(provider.renew_license(dto.license_id, 1))
        assert entered.wait(1)
        worker = provider._claim_sync_worker
        for _ in range(5):
            run(provider.renew_license(dto.license_id, 1))
        assert provider._claim_sync_worker is worker
        assert len(provider._claim_sync_pending) == 1
    finally:
        release.set()
        drain_sync(provider)
    assert len(sent) == 2
    assert sent[-1] == provider.current_device_license(FP)
