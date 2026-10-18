"""Restart persistence of admin/billing state changes. API common to ORIGINAL (694e3c2), FIXED and
COMPAT builds. On the ORIGINAL code these are expected to FAIL (renew/extend/suspend/reinstate/
revoke were memory-only and reverted on every process restart) -> documents a pre-existing bug."""
import asyncio
import os
import tempfile

import pytest

os.environ.setdefault("SHUABAO_KEY_HASH_PEPPER", "r2-test-pepper-not-a-real-secret-000000")

from bridge.app.core.crypto import CryptoEngine
from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
from bridge.app.services.event_processor import SqliteEventStore


def _p(db):
    return InMemoryKeygenProvider(CryptoEngine(), SqliteEventStore(db))


def _run(c):
    return asyncio.get_event_loop().run_until_complete(c) if False else asyncio.run(c)


@pytest.fixture()
def db(tmp_path):
    return str(tmp_path / "s.db")


def _status(db, lid):
    d = _run(_p(db).get_license(lid))
    return d.status.value if hasattr(d.status, "value") else str(d.status), d.expires_at


@pytest.mark.parametrize("op", ["revoke", "suspend", "renew", "extend", "reinstate"])
def test_state_change_survives_restart(db, op):
    p = _p(db)
    lic = _run(p.create_license(customer_id="c1", customer_email="c1@example.invalid", plan="pro", duration_days=30, device_limit=1))
    lid = lic.license_id
    before = _status(db, lid)
    if op == "revoke":
        _run(p.revoke_license(lid)); want = ("REVOKED", None)
    elif op == "suspend":
        _run(p.suspend_license(lid)); want = ("SUSPENDED", None)
    elif op == "renew":
        d = _run(p.renew_license(lid, extend_days=30)); want = ("ACTIVE", d.expires_at)
    elif op == "extend":
        d = _run(p.extend_license(lid, extend_days=7)); want = ("ACTIVE", d.expires_at)
    else:
        _run(p.suspend_license(lid)); p2 = _p(db); _run(p2.suspend_license(lid))
        _run(p2.reinstate_license(lid)); want = ("ACTIVE", None)
    after = _status(db, lid)  # fresh process-equivalent provider on the same DB file
    assert after[0].upper() == want[0], f"{op}: after restart status={after[0]} (before={before[0]})"
    if want[1] is not None:
        assert after[1] == want[1], f"{op}: after restart expires_at={after[1]} expected {want[1]}"
