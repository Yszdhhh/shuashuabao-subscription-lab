"""Run-lease single-active semantics (kick only on acquire)."""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.app.providers.keygen_provider import InMemoryKeygenProvider  # noqa: E402
from bridge.app.services.event_processor import SqliteEventStore  # noqa: E402
from contracts.entitlement import HardwareFingerprint  # noqa: E402


def _fp(name: str) -> HardwareFingerprint:
    return HardwareFingerprint(fingerprint=name, components={"disk": name}, hostname=name)


class RunLeaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "t.db")
        self.store = SqliteEventStore(self.db)
        self.provider = InMemoryKeygenProvider(event_store=self.store)
        self.lic = asyncio.run(
            self.provider.create_license(
                "u1", "u1@x.invalid", "test_7d", duration_days=7, device_limit=3
            )
        )

    def tearDown(self) -> None:
        try:
            self.store._conn.close()
        except Exception:
            pass
        try:
            self.tmp.cleanup()
        except Exception:
            pass

    def test_acquire_kicks_previous_but_bind_does_not(self) -> None:
        a = asyncio.run(self.provider.acquire_run_lease(self.lic.license_key, "fpA"))
        self.assertIsNone(a["kicked"])
        # bind second device must NOT kick
        asyncio.run(self.provider.activate_device(self.lic.license_key, _fp("fpB")))
        still = self.provider.run_lease_active_for(self.lic.license_id, "fpA")
        self.assertIsNotNone(still)
        # start on B kicks A
        b = asyncio.run(self.provider.acquire_run_lease(self.lic.license_key, "fpB"))
        self.assertEqual(b["kicked"]["fingerprint"], "fpA")
        with self.assertRaises(PermissionError):
            asyncio.run(self.provider.heartbeat_run_lease(a["lease_id"], "fpA"))
        hb = asyncio.run(self.provider.heartbeat_run_lease(b["lease_id"], "fpB"))
        self.assertEqual(hb["lease_id"], b["lease_id"])

    def test_release(self) -> None:
        a = asyncio.run(self.provider.acquire_run_lease(self.lic.license_key, "fpA"))
        ok = asyncio.run(self.provider.release_run_lease(a["lease_id"], "fpA"))
        self.assertTrue(ok)
        self.assertIsNone(self.provider.run_lease_active_for(self.lic.license_id, "fpA"))


if __name__ == "__main__":
    unittest.main()
