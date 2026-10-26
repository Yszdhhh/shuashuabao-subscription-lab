"""Local-only tests for the manually reviewed PiP entitlement."""
from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
from datetime import datetime, timezone
from urllib.parse import unquote

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from bridge.app import main
from bridge.app.core.crypto import CryptoEngine
from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
from bridge.app.providers.http_keygen_provider import HttpKeygenProvider
from bridge.app.services.event_processor import SqliteEventStore
from bridge.app.services.permit_issuer import ApprovedRelease, PermitIssuer
from bridge.app.services import tiers
from tests.integration.test_tiers_pip_authority import CASES
from contracts.entitlement import HardwareFingerprint

SOURCE = "a" * 40
MANIFEST = "b" * 64
CHANNEL = "dev"


@pytest.fixture
def pip_ctx(monkeypatch, tmp_path):
    monkeypatch.setenv("SUBSCRIPTION_ADMIN_PASSWORD", "test-admin-pass-pip-strong")
    audit_path = tmp_path / "admin_audit.jsonl"
    monkeypatch.setenv("SUBSCRIPTION_ADMIN_AUDIT_LOG", str(audit_path))
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    engine = CryptoEngine(private_key_pem=pem)
    store = SqliteEventStore(str(tmp_path / "subscription.db"))
    provider = InMemoryKeygenProvider(engine, store)
    release = ApprovedRelease.from_mapping({
        "source_sha": SOURCE,
        "release_manifest_sha256": MANIFEST,
        "release_channel": CHANNEL,
        "allowed_modes": ["lobby_hitch"],
    })
    issuer = PermitIssuer(
        engine,
        key_id="pip-test",
        approved_releases=[release],
        offline_v2_releases=[(SOURCE, MANIFEST, CHANNEL)],
    )
    monkeypatch.setattr(main, "keygen_provider", provider)
    monkeypatch.setattr(main, "permit_issuer", issuer)
    monkeypatch.setattr(main, "_STORE", store)
    auth = {"Authorization": "Basic " + base64.b64encode(
        b"admin:test-admin-pass-pip-strong"
    ).decode()}
    with TestClient(main.app, client=("127.0.0.1", 50000)) as client:
        yield client, provider, auth, audit_path


def _issue(client, auth, **values):
    response = client.post("/admin/licenses", data=values, headers=auth, follow_redirects=False)
    assert response.status_code == 303
    return asyncio.run(main.keygen_provider.list_licenses())[0]


def _audit_events(provider):
    return [json.loads(row[0]) for row in provider.event_store._conn.execute(
        "SELECT audit_json FROM entitlement_operations ORDER BY rowid")]


@pytest.mark.parametrize("values,expected", CASES + [
    ({"plan": plan, "is_beta_user": True}, False)
    for plan in ("plus_1d", "pro_7d", "max_30d", " PRO_MONTHLY ")
])
@pytest.mark.parametrize("device_beta", [False, True])
def test_authority_truth_table_through_validate_lease_and_admin(pip_ctx, values, expected, device_beta):
    client, provider, auth, _ = pip_ctx
    dto = asyncio.run(provider.create_license("truth-table", "test@example.invalid", "unknown", features=["core"]))
    rec = {**provider.licenses[dto.license_id], **values}
    provider.licenses[dto.license_id] = rec
    provider.event_store.save_local_license(rec["id"], rec["key"], rec)
    hw = HardwareFingerprint(fingerprint="f" * 64)
    asyncio.run(provider.activate_device(dto.license_key, hw))
    provider.event_store._conn.execute("DELETE FROM beta_users")
    if device_beta:
        provider.event_store._conn.execute("INSERT INTO beta_users VALUES (?, ?, ?, ?)",
            (hw.fingerprint, dto.license_id, "test_snapshot", "2026-10-26T00:00:00Z"))
    stored = provider.event_store.load_local_license(dto.license_id)
    validated = asyncio.run(provider.validate_license(dto.license_key, hw.fingerprint))
    assert validated.valid and validated.license.pip_background is expected
    assert validated.license.is_beta_user is (device_beta or tiers.is_beta_record(rec))
    assert validated.license.metadata.get("is_beta_user", False) is tiers.is_beta_record(rec)
    assert asyncio.run(provider.get_license(dto.license_id)).pip_background is expected
    for v2 in (False, True):
        main.permit_issuer = PermitIssuer(provider.crypto, key_id="truth-table", approved_releases=[
            ApprovedRelease.from_mapping({"source_sha": SOURCE, "release_manifest_sha256": MANIFEST,
                                          "release_channel": CHANNEL, "allowed_modes": ["lobby_hitch"]})],
            offline_v2_releases=[(SOURCE, MANIFEST, CHANNEL)] if v2 else [])
        result = client.post("/v1/entitlements/validate", json={
            "license_key": dto.license_key, "hardware": hw.model_dump(),
            "permit_request": {"source_sha": SOURCE, "release_manifest_sha256": MANIFEST,
                               "release_channel": CHANNEL, "mode_id": "lobby_hitch"},
        }).json()
        assert result["permit"]["schema_version"] == (2 if v2 else 1)
        assert ("pip_background" in result["permit"]["features"]) is expected
    lease = client.post("/v1/run/acquire", json={
        "license_key": dto.license_key, "fingerprint": hw.fingerprint, "scope": "pip_background",
    })
    if expected:
        assert lease.status_code == 200
    else:
        assert lease.status_code == 400 and lease.json()["detail"] == "FEATURE_NOT_ENTITLED"
    assert asyncio.run(provider.acquire_run_lease(dto.license_key, hw.fingerprint))["scope"] == "core"
    offline = asyncio.run(provider.issue_offline_entitlement(dto.license_key, hw))
    assert ("pip_background" in offline.features) is expected
    page = client.get("/admin", headers=auth).text
    start = page.index(f"/admin/licenses/{dto.license_id}/pip-background")
    form = page[start:page.index("</form>", start)]
    assert (" checked" in form) is expected
    locked = tiers.has_default_pip_background(rec)
    assert (" disabled" in form) is locked
    assert provider.event_store.load_local_license(dto.license_id) == stored
    path = f"/admin/licenses/{dto.license_id}/pip-background"
    for enabled in (False, True):
        response = client.post(path, headers=auth, follow_redirects=False, data={
            "pip_background": "1" if enabled else "0", "confirm_pip": "1",
        })
        message = unquote(response.headers["location"])
        if locked and not enabled:
            assert "内测卡默认包含画中画，不能取消" in message
        elif tiers.is_regular_trial_record(rec) and enabled:
            assert "普通试用卡不能授权画中画" in message
        else:
            assert ("画中画授权已开启" if enabled else "画中画授权已关闭") in message


def test_admin_pip_issue_and_unselected_v2_permits(pip_ctx):
    client, provider, auth, audit_path = pip_ctx
    unauthorized = client.post("/admin/licenses", data={
        "tier": "pro", "pip_background": "1",
    }, headers=auth, follow_redirects=False)
    assert "需要勾选确认" in unquote(unauthorized.headers["location"])
    assert asyncio.run(provider.list_licenses()) == []

    licensed = _issue(client, auth, tier="pro", pip_background="1", confirm_pip="1")
    plain = _issue(client, auth, tier="pro")
    assert licensed.pip_background is True
    assert "pip_background" in licensed.features
    extended = client.post(
        f"/admin/licenses/{licensed.license_id}/extend", data={"days": "1"},
        headers=auth, follow_redirects=False,
    )
    assert extended.status_code == 303
    assert "pip_background" in asyncio.run(provider.get_license(licensed.license_id)).features
    issue_events = _audit_events(provider)
    assert any(event["action"] == "issue_pip_background" and event["license_id"] == licensed.license_id
               for event in issue_events)
    assert plain.pip_background is False
    assert "pip_background" not in plain.features

    hardware = HardwareFingerprint(fingerprint="pip-entitlement-device")
    asyncio.run(provider.activate_device(licensed.license_key, hardware))
    result = client.post("/v1/entitlements/validate", json={
        "license_key": licensed.license_key,
        "hardware": hardware.model_dump(),
        "features": ["pip_background"],  # ignored; features come from the license record
        "permit_request": {
            "source_sha": SOURCE,
            "release_manifest_sha256": MANIFEST,
            "release_channel": CHANNEL,
            "mode_id": "lobby_hitch",
        },
    }).json()
    assert result["permit"]["schema_version"] == 2
    assert "pip_background" in result["permit"]["features"]
    assert "pip_background" in result["license"]["features"]
    offline = asyncio.run(provider.issue_offline_entitlement(licensed.license_key, hardware))
    assert "pip_background" in offline.features

    plain_hw = HardwareFingerprint(fingerprint="pip-entitlement-plain")
    asyncio.run(provider.activate_device(plain.license_key, plain_hw))
    result = client.post("/v1/entitlements/validate", json={
        "license_key": plain.license_key,
        "hardware": plain_hw.model_dump(),
        "features": ["pip_background"],
        "permit_request": {
            "source_sha": SOURCE,
            "release_manifest_sha256": MANIFEST,
            "release_channel": CHANNEL,
            "mode_id": "lobby_hitch",
        },
    }).json()
    assert result["permit"]["schema_version"] == 2
    assert "pip_background" not in result["permit"]["features"]


def test_existing_card_pip_switch_requires_confirm_and_audits(pip_ctx):
    client, provider, auth, audit_path = pip_ctx
    dto = _issue(client, auth, tier="pro")
    path = f"/admin/licenses/{dto.license_id}/pip-background"
    response = client.post(path, data={"pip_background": "1"}, headers=auth, follow_redirects=False)
    assert "确认" in unquote(response.headers["location"])
    assert "pip_background" not in asyncio.run(provider.get_license(dto.license_id)).features

    response = client.post(path, data={"pip_background": "1", "confirm_pip": "1"}, headers=auth)
    assert "pip_background" in asyncio.run(provider.get_license(dto.license_id)).features
    response = client.post(path, data={"pip_background": "0", "confirm_pip": "1"}, headers=auth)
    assert "pip_background" not in asyncio.run(provider.get_license(dto.license_id)).features

    events = _audit_events(provider)
    changes = [event for event in events if event["action"] == "update_pip_background"]
    assert [(event["enabled"], event["license_id"]) for event in changes] == [
        (True, dto.license_id), (False, dto.license_id),
    ]


def test_legacy_test_and_beta_cards_infer_pip_for_v1_v2_and_offline(pip_ctx, monkeypatch):
    client, provider, auth, _ = pip_ctx
    v2_issuer = main.permit_issuer
    for tier in ("test", "beta"):
        monkeypatch.setattr(main, "permit_issuer", v2_issuer)
        dto = asyncio.run(provider.create_license(
            customer_id=f"legacy-{tier}", customer_email="legacy@example.invalid",
            plan="trial_1d", duration_days=30, tier=tier,
        ))
        record = provider.licenses[dto.license_id]
        record["features"] = ["core", "automation"]
        provider.event_store.save_local_license(record["id"], record["key"], record)
        assert "pip_background" not in record["features"]  # inference does not rewrite storage
        assert "pip_background" in asyncio.run(provider.get_license(dto.license_id)).features

        hardware = HardwareFingerprint(fingerprint=f"legacy-{tier}-device")
        asyncio.run(provider.activate_device(dto.license_key, hardware))
        page = client.get("/admin", headers=auth).text
        row_start = page.find(dto.license_id)
        assert row_start >= 0
        assert "name='pip_background' value='1' checked disabled" in page[row_start:page.index("</tr>", row_start)]
        response = client.post(
            f"/admin/licenses/{dto.license_id}/pip-background",
            data={"pip_background": "0", "confirm_pip": "1"}, headers=auth,
            follow_redirects=False,
        )
        assert "不能取消" in unquote(response.headers["location"])

        request_data = {
            "license_key": dto.license_key,
            "hardware": hardware.model_dump(),
            "permit_request": {
                "source_sha": SOURCE,
                "release_manifest_sha256": MANIFEST,
                "release_channel": CHANNEL,
                "mode_id": "lobby_hitch",
            },
        }
        v2 = client.post("/v1/entitlements/validate", json=request_data).json()["permit"]
        assert v2["schema_version"] == 2 and "pip_background" in v2["features"]
        offline = asyncio.run(provider.issue_offline_entitlement(dto.license_key, hardware))
        assert "pip_background" in offline.features

        monkeypatch.setattr(main, "permit_issuer", PermitIssuer(
            provider.crypto, key_id="pip-test-v1", approved_releases=[ApprovedRelease.from_mapping({
                "source_sha": SOURCE,
                "release_manifest_sha256": MANIFEST,
                "release_channel": CHANNEL,
                "allowed_modes": ["lobby_hitch"],
            })],
        ))
        v1 = client.post("/v1/entitlements/validate", json=request_data).json()["permit"]
        assert v1["schema_version"] == 1 and "pip_background" in v1["features"]


def test_test_tier_issues_pip_without_confirmation_but_trial_does_not(pip_ctx):
    client, provider, auth, audit_path = pip_ctx
    internal = _issue(client, auth, tier="test")
    assert "pip_background" in internal.features
    assert any(event["action"] == "issue_pip_background" for event in _audit_events(provider))

    claimed = client.post("/v1/trials/claim", json={
        "hardware": {"fingerprint": "a" * 64, "components": {}, "platform": "windows"},
    })
    assert claimed.status_code == 200, claimed.text
    dto = asyncio.run(provider.get_license(claimed.json()["license_key"]))
    assert "pip_background" not in dto.features
    offline = asyncio.run(provider.issue_offline_entitlement(
        dto.license_key, HardwareFingerprint(fingerprint="a" * 64),
    ))
    assert "pip_background" not in offline.features


@pytest.mark.parametrize("failure", ["license_write", "audit_write", "commit"])
@pytest.mark.parametrize("create", [False, True])
def test_entitlement_transaction_failure_and_retry(pip_ctx, failure, create):
    client, provider, auth, _ = pip_ctx
    store = provider.event_store
    dto = None if create else _issue(client, auth, tier="pro")
    before = store.load_local_licenses()
    before_events = _audit_events(provider)
    if failure == "commit":
        store._conn.set_authorizer(lambda action, arg, *_: (
            sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_TRANSACTION and arg == "COMMIT"
            else sqlite3.SQLITE_OK))
    else:
        table = "local_licenses" if failure == "license_write" else "entitlement_operations"
        store._conn.execute(f"CREATE TRIGGER fail_write BEFORE INSERT ON {table} "
                            "BEGIN SELECT RAISE(ABORT, 'injected write failure'); END")
    path = "/admin/licenses" if create else f"/admin/licenses/{dto.license_id}/pip-background"
    values = {"tier": "pro", "pip_background": "1", "confirm_pip": "1", "operation_id": "fault-op"}
    response = client.post(path, data=values, headers=auth, follow_redirects=False)
    assert "失败" in unquote(response.headers["location"])
    assert provider.licenses == before
    assert store.load_local_licenses() == before
    assert _audit_events(provider) == before_events
    restarted = InMemoryKeygenProvider(provider.crypto, SqliteEventStore(store.db_path))
    assert restarted.licenses == before
    restarted.event_store._conn.close()
    if failure == "commit":
        store._conn.set_authorizer(None)
    else:
        store._conn.execute("DROP TRIGGER fail_write")
    response = client.post(path, data=values, headers=auth, follow_redirects=False)
    assert "失败" not in unquote(response.headers["location"])
    assert len(_audit_events(provider)) == len(before_events) + 1
    result = store._conn.execute(
        "SELECT result_json FROM entitlement_operations WHERE operation_id = 'fault-op'").fetchone()[0]
    assert "pip_background" in json.loads(result)["features"]
    # Replaying after a restart returns the original result without writing another audit.
    restarted = InMemoryKeygenProvider(provider.crypto, SqliteEventStore(store.db_path))
    main.keygen_provider = restarted
    response = client.post(path, data=values, headers=auth, follow_redirects=False)
    assert "失败" not in unquote(response.headers["location"])
    assert len(_audit_events(restarted)) == len(before_events) + 1
    assert len(restarted.licenses) == len(before) + int(create)
    assert len(restarted.event_store.load_local_licenses()) == len(before) + int(create)
    assert restarted.event_store._conn.execute(
        "SELECT result_json FROM entitlement_operations WHERE operation_id = 'fault-op'").fetchone()[0] == result
    restarted.event_store._conn.close()


@pytest.mark.parametrize("value", [["x"], {"a": 1}, 1, False])
def test_invalid_operation_id_returns_400_without_writes(pip_ctx, value):
    client, provider, auth, _ = pip_ctx
    response = client.post("/admin/licenses/create-test", headers=auth,
                           json={"tier": "pro", "operation_id": value})
    assert response.status_code == 400 and response.json()["detail"] == "INVALID_OPERATION_ID"
    assert provider.event_store.load_local_licenses() == {} and _audit_events(provider) == []
    dto = _issue(client, auth, tier="pro")
    with pytest.raises(ValueError, match="^INVALID_OPERATION_ID$"):
        asyncio.run(provider.set_license_features(dto.license_id, ["core"], operation_id=value))
    assert len(_audit_events(provider)) == 1


def test_create_json_replay_conflict_and_blank_ids(pip_ctx, monkeypatch):
    client, provider, auth, _ = pip_ctx
    values = {"tier": "pro", "operation_id": " create-json "}
    first = client.post("/admin/licenses/create-test", headers=auth, json=values)
    assert first.status_code == 200
    restarted = InMemoryKeygenProvider(provider.crypto, SqliteEventStore(provider.event_store.db_path))
    monkeypatch.setattr(main, "keygen_provider", restarted)
    replay = client.post("/admin/licenses/create-test", headers=auth, json=values)
    assert replay.status_code == 200 and replay.json() == first.json()
    conflict = client.post("/admin/licenses/create-test", headers=auth, json={**values, "tier": "plus"})
    assert conflict.status_code == 400 and conflict.json()["detail"] == "OPERATION_ID_CONFLICT"
    assert len(restarted.licenses) == len(restarted.event_store.load_local_licenses()) == 1
    assert len(_audit_events(restarted)) == 1
    assert _audit_events(restarted)[0]["operation_id"] == "create-json"
    for _ in range(2):
        response = client.post("/admin/licenses/create-test", headers=auth,
                               json={"tier": "pro", "operation_id": "   "})
        assert response.status_code == 200
    assert len(restarted.licenses) == 3 and len(_audit_events(restarted)) == 3
    restarted.event_store._conn.close()


def test_request_normalization_and_replay_snapshots_do_not_duplicate_keys(pip_ctx):
    _, provider, _, _ = pip_ctx
    kwargs = {"customer_id": "normalize", "customer_email": "test@example.invalid", "plan": "pro_monthly",
              "features": ("core", "automation"), "metadata": {"at": datetime(2026, 10, 26, tzinfo=timezone.utc)},
              "operation_id": "normalize-op"}
    first = asyncio.run(provider.create_license(**kwargs))
    replay = asyncio.run(provider.create_license(**kwargs))
    assert first == replay
    asyncio.run(provider.set_license_features(first.license_id, ["core"], operation_id="features-op"))
    rows = provider.event_store._conn.execute(
        "SELECT result_json, audit_json FROM entitlement_operations").fetchall()
    assert len(rows) == 2
    assert all("license_key" not in json.loads(result) for result, _ in rows)
    assert all(first.license_key not in result + audit for result, audit in rows)
    # Upgrade a previous-version snapshot; reopening twice is safe and replay still resolves the key.
    old_result = first.model_dump(mode="json")
    provider.event_store._conn.execute(
        "UPDATE entitlement_operations SET result_json = ? WHERE operation_id = ?",
        (json.dumps(old_result), "normalize-op"))
    for _ in range(2):
        restarted = InMemoryKeygenProvider(provider.crypto, SqliteEventStore(provider.event_store.db_path))
        assert asyncio.run(restarted.create_license(**kwargs)) == first
        snapshots = restarted.event_store._conn.execute("SELECT result_json FROM entitlement_operations").fetchall()
        assert all(first.license_key not in row[0] for row in snapshots)
        restarted.event_store._conn.close()


def test_ultra_pip_audit_retains_pip_identity(pip_ctx):
    client, provider, auth, _ = pip_ctx
    dto = _issue(client, auth, tier="ultra", confirm_ultra="1", pip_background="1", confirm_pip="1")
    events = _audit_events(provider)
    assert len(events) == 1
    assert events[0]["action"] == "issue_ultra" and events[0]["pip_background"] is True
    assert events[0]["license_id"] == dto.license_id


def test_pip_form_replay_after_unrelated_feature_change(pip_ctx):
    client, provider, auth, _ = pip_ctx
    dto = _issue(client, auth, tier="pro")
    path = f"/admin/licenses/{dto.license_id}/pip-background"
    values = {"pip_background": "1", "confirm_pip": "1", "operation_id": "pip-replay"}
    first = client.post(path, headers=auth, data=values, follow_redirects=False)
    assert "画中画授权已开启" in unquote(first.headers["location"])
    asyncio.run(provider.set_license_features(dto.license_id, ["core", "new_feature"], operation_id="later-change"))
    replay = client.post(path, headers=auth, data=values, follow_redirects=False)
    assert replay.headers["location"] == first.headers["location"]
    assert asyncio.run(provider.get_license(dto.license_id)).features == ["core", "new_feature"]
    assert len(_audit_events(provider)) == 3
    assert _audit_events(provider)[1]["action"] == "update_pip_background"


def test_feature_operation_replays_original_result_after_later_changes(pip_ctx):
    client, provider, auth, _ = pip_ctx
    dto = _issue(client, auth, tier="pro")
    granted = asyncio.run(provider.set_license_features(
        dto.license_id, ["core", "pip_background"], operation_id="grant-1"))
    asyncio.run(provider.set_license_features(dto.license_id, ["core"], operation_id="revoke-1"))
    asyncio.run(provider.revoke_license(dto.license_id))
    replay = asyncio.run(provider.set_license_features(
        dto.license_id, ["core", "pip_background"], operation_id="grant-1"))
    assert replay == granted
    assert "pip_background" not in asyncio.run(provider.get_license(dto.license_id)).features
    with pytest.raises(ValueError, match="OPERATION_ID_CONFLICT"):
        asyncio.run(provider.set_license_features(dto.license_id, ["core"], operation_id="grant-1"))
    assert len(_audit_events(provider)) == 3


def test_no_change_is_audited_and_file_path_does_not_affect_commit(pip_ctx, monkeypatch, tmp_path):
    client, provider, auth, _ = pip_ctx
    dto = _issue(client, auth, tier="pro")
    monkeypatch.setenv("SUBSCRIPTION_ADMIN_AUDIT_LOG", str(tmp_path / "absent" / "audit.jsonl"))
    values = {"pip_background": "0", "confirm_pip": "1", "operation_id": "no-change"}
    path = f"/admin/licenses/{dto.license_id}/pip-background"
    for _ in range(2):
        response = client.post(path, data=values, headers=auth, follow_redirects=False)
        assert "已关闭" in unquote(response.headers["location"])
    assert len([event for event in _audit_events(provider) if event["operation_id"] == "no-change"]) == 1


def test_admin_remote_authority_rejects_before_any_nontransactional_write(pip_ctx, monkeypatch):
    client, provider, auth, _ = pip_ctx
    remote = HttpKeygenProvider("http://unused.invalid", "test", "test", crypto_engine=provider.crypto)
    def unexpected_request(*args, **kwargs):
        pytest.fail("SQLite admin transactions must not perform remote mutations")
    monkeypatch.setattr(remote, "_request", unexpected_request)
    monkeypatch.setattr(main, "keygen_provider", remote)
    response = client.post("/admin/licenses/create-test", json={"tier": "pro"}, headers=auth)
    assert response.status_code == 400 and "ENTITLEMENT_TRANSACTION_UNSUPPORTED" in response.json()["detail"]
    response = client.post("/admin/licenses/remote/pip-background", data={
        "pip_background": "1", "confirm_pip": "1", "operation_id": "remote-op",
    }, headers=auth, follow_redirects=False)
    assert "失败" in unquote(response.headers["location"])
