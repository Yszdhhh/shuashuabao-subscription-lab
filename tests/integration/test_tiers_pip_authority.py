"""Stored identity and grants, independently of tier display fallbacks."""
import asyncio
from copy import deepcopy
import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from bridge.app.core.crypto import CryptoEngine
from bridge.app.providers.http_keygen_provider import HttpKeygenProvider
from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
from bridge.app.services.event_processor import SqliteEventStore
from bridge.app.services import tiers
from scripts.inventory_pip_entitlements import inventory


CASES = [
    ({"tier": "test"}, True),
    ({"tier": "beta"}, True),
    ({"tier": "test", "metadata": {"is_trial": True}}, True),
    ({"tier": "trial"}, False),
    ({"tier": "trial", "features": ["core", "pip_background"]}, False),
    ({"tier": "trial", "is_beta_user": True}, True),
    ({"metadata": {"tier": "test"}}, True),
    ({"metadata": {"tier": "beta"}}, True),
    ({"metadata": {"is_beta_user": True, "beta_snapshot_at": "2026-10-18T00:00:00Z"}}, True),
    ({"metadata": None}, False),
    ({"plan": None}, False),
    ({"plan": ""}, False),
    ({"plan": "unknown"}, False),
    ({"plan": "unknown", "features": ["core", "pip_background"]}, True),
    ({"plan": "test_30d"}, False),
    ({"plan": "trial_1d"}, False),
    ({"plan": "trial_7d", "features": ["core", "pip_background"]}, False),
    ({"plan": "trial_1d_auto", "features": ["core", "pip_background"]}, False),
    ({"plan": "unknown", "metadata": {"is_trial": True}, "features": ["core", "pip_background"]}, False),
    ({"plan": "pro_monthly", "metadata": {"is_beta_user": True}}, False),
] + [({"tier": tier, "plan": tiers.TIERS[tier]["plan"], "features": features,
       "metadata": {"is_beta_user": True}}, expected)
     for tier in tiers.FORMAL_TIERS
     for features, expected in ((["core"], False), (["core", "pip_background"], True))]


@pytest.mark.parametrize("values,expected", CASES)
def test_pip_truth_table_across_local_and_http_providers(values, expected):
    engine = CryptoEngine()
    provider = InMemoryKeygenProvider(engine, SqliteEventStore(":memory:"))
    dto = asyncio.run(provider.create_license("truth-table", "test@example.invalid", "unknown", features=["core"]))
    rec = {**provider.licenses[dto.license_id], **deepcopy(values)}
    before = deepcopy(rec)
    local = provider._to_dto(rec)
    meta = dict(rec.get("metadata") or {})
    for field in ("plan", "tier", "is_beta_user"):
        if field in rec:
            meta[field] = rec[field]
    http = HttpKeygenProvider("http://unused.invalid", "test-account", "test-token", crypto_engine=engine)
    remote = http._parse_license({"id": "lic_http", "attributes": {"status": "ACTIVE", "metadata": {
        **meta, "features": rec["features"],
    }}})
    for result in (local, remote):
        assert result.pip_background is expected
        assert ("pip_background" in result.features) is expected
    assert rec == before  # read projections never grant by mutating stored records


def test_active_http_object_without_metadata_never_grants_pip():
    provider = HttpKeygenProvider("http://unused.invalid", "test-account", "test-token")
    dto = provider._parse_license({"id": "lic_missing_meta", "attributes": {"status": "ACTIVE"}})
    assert dto.features == ["core"] and dto.pip_background is False and dto.plan == ""
    assert tiers.derive_tier(None) == tiers.DEFAULT_TIER  # existing presentation fallback is preserved


def test_regular_trial_cannot_be_granted_pip_but_unknown_explicit_grant_can_be_revoked():
    provider = InMemoryKeygenProvider(CryptoEngine(), SqliteEventStore(":memory:"))
    dto = asyncio.run(provider.create_license("trial", "test@example.invalid", "trial_7d",
                                              features=["core", "pip_background"]))
    assert not dto.pip_background
    with pytest.raises(ValueError, match="Regular trial"):
        asyncio.run(provider.set_license_features(dto.license_id, ["core", "pip_background"]))
    unknown = asyncio.run(provider.create_license("unknown", "test@example.invalid", "unknown",
                                                  features=["core", "pip_background"]))
    assert unknown.pip_background
    updated = asyncio.run(provider.set_license_features(unknown.license_id, ["core"]))
    assert not updated.pip_background


def test_inventory_is_read_only_and_counts_losses_and_gains(tmp_path):
    db = tmp_path / "inventory.db"
    records = [
        {"plan": "", "features": ["core"], "status": "ACTIVE"},
        {"plan": "unknown", "features": ["core"], "status": "REVOKED"},
        {"tier": "trial", "features": ["core", "pip_background"]},
        {"tier": "trial", "is_beta_user": True, "features": ["core"]},
        {"tier": "test", "features": ["core"]},
        {"tier": "pro", "features": ["core", "pip_background"]},
    ]
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE local_licenses (id TEXT PRIMARY KEY, data_json TEXT NOT NULL)")
        conn.executemany("INSERT INTO local_licenses VALUES (?, ?)",
                         [(str(i), json.dumps(rec)) for i, rec in enumerate(records)])
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    result = inventory(db)
    assert result["cards_total"] == 6 and result["pip_before"] == 5 and result["pip_after"] == 3
    assert result["pip_lost"] == 3 and result["pip_gained"] == 1 and result["unchanged"] == 2
    assert result["by_status"]["ACTIVE"]["pip_lost"] == 1
    script = Path(__file__).resolve().parents[2] / "scripts" / "inventory_pip_entitlements.py"
    command = subprocess.run([sys.executable, str(script), "--db", str(db)],
                             capture_output=True, text=True, check=True)
    assert json.loads(command.stdout) == result
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
    assert {p.name for p in tmp_path.iterdir()} == {"inventory.db"}
    with pytest.raises(sqlite3.OperationalError):
        inventory(tmp_path / "missing.db")
    assert not (tmp_path / "missing.db").exists()
