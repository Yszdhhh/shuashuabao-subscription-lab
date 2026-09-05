"""
Card密（License Card）Lifecycle and Bulk Generation Integration & Regression Tests.
Covers all 14 requirements specified in Section VII of the product specification.
"""
import asyncio
import csv
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bridge.app.core.cards import (
    CARD_ALPHABET,
    CARD_PLAN_DURATIONS,
    generate_card_code,
    mask_card_code,
    parse_plan_duration,
)
from bridge.app.main import app
from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
from bridge.app.providers.keygate_provider import InMemoryKeygateProvider
from bridge.app.services.event_processor import SqliteEventStore
from contracts.entitlement import HardwareFingerprint, LicenseStatus


def _hw(fp: str = "FP_TEST_001") -> HardwareFingerprint:
    return HardwareFingerprint(
        fingerprint=fp,
        hostname=f"HOST_{fp}",
        components={"mb": f"MB_{fp}", "disk": f"DISK_{fp}"},
    )


# ----------------------------------------------------------------------
# Requirement 1: generate 1-day UNUSED card
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_generate_1day_unused_card():
    store = SqliteEventStore(":memory:")
    provider = InMemoryKeygenProvider(event_store=store)

    card = await provider.create_card(plan="1d")

    assert card.license_id.startswith("lic_")
    assert card.license_key.startswith("SSB-D1-")
    assert card.status == LicenseStatus.UNUSED
    assert card.plan == "1d"
    assert card.duration_seconds == 86400
    assert card.activated_at is None
    assert card.expires_at is None
    assert card.devices_used == 0

    # UNUSED card cannot start runner before activation
    val_res = await provider.validate_license(card.license_key, fingerprint="FP_TEST_001")
    assert val_res.valid is False
    assert val_res.can_start_runner is False
    assert val_res.status == LicenseStatus.UNUSED
    assert val_res.code == "UNUSED"


# ----------------------------------------------------------------------
# Requirement 2: created_at 后等待不会改变 validity
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_wait_after_created_at_does_not_change_validity():
    store = SqliteEventStore(":memory:")
    provider = InMemoryKeygenProvider(event_store=store)

    card = await provider.create_card(plan="1d")
    # Simulate that card was created 180 days ago
    long_ago = datetime.now(timezone.utc) - timedelta(days=180)
    provider.licenses[card.license_id]["created_at"] = long_ago

    # Validation still returns UNUSED, NOT EXPIRED
    val_res = await provider.validate_license(card.license_key)
    assert val_res.valid is False
    assert val_res.status == LicenseStatus.UNUSED

    # After 180 days, first activation still succeeds and starts timer from NOW
    before_act = datetime.now(timezone.utc)
    act_dto = await provider.activate_device(card.license_key, _hw("FP_WAIT_180D"))
    after_act = datetime.now(timezone.utc)

    updated_card = await provider.get_license(card.license_id)
    assert updated_card.status == LicenseStatus.ACTIVE
    assert updated_card.activated_at is not None
    assert before_act <= updated_card.activated_at <= after_act
    # Expires at exactly activated_at + 86400s (full 1-day remaining)
    assert updated_card.expires_at == updated_card.activated_at + timedelta(seconds=86400)


# ----------------------------------------------------------------------
# Requirement 3: first successful activation sets activated_at
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_first_successful_activation_sets_activated_at():
    store = SqliteEventStore(":memory:")
    provider = InMemoryKeygenProvider(event_store=store)
    card = await provider.create_card(plan="3d")

    t_before = datetime.now(timezone.utc)
    act = await provider.activate_device(card.license_key, _hw("FP_FIRST_ACT"))
    t_after = datetime.now(timezone.utc)

    assert act.fingerprint == "FP_FIRST_ACT"
    updated = await provider.get_license(card.license_id)
    assert updated.status == LicenseStatus.ACTIVE
    assert updated.activated_at is not None
    assert t_before <= updated.activated_at <= t_after


# ----------------------------------------------------------------------
# Requirement 4: first activation sets expires_at = activated_at + duration
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_first_activation_sets_expires_at_authoritative():
    store = SqliteEventStore(":memory:")
    provider = InMemoryKeygenProvider(event_store=store)
    card = await provider.create_card(plan="7d")
    expected_duration = CARD_PLAN_DURATIONS["7d"]  # 604800s

    await provider.activate_device(card.license_key, _hw("FP_DUR_7D"))

    updated = await provider.get_license(card.license_id)
    assert updated.duration_seconds == expected_duration
    assert updated.expires_at == updated.activated_at + timedelta(seconds=expected_duration)

    val_res = await provider.validate_license(card.license_key, fingerprint="FP_DUR_7D")
    assert val_res.valid is True
    assert val_res.can_start_runner is True
    assert val_res.status == LicenseStatus.ACTIVE


# ----------------------------------------------------------------------
# Requirement 5: repeated validation does not extend expiry
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_repeated_validation_and_idempotent_activation_does_not_extend_expiry():
    store = SqliteEventStore(":memory:")
    provider = InMemoryKeygenProvider(event_store=store)
    card = await provider.create_card(plan="1d")

    await provider.activate_device(card.license_key, _hw("FP_REPEAT"))
    first_dto = await provider.get_license(card.license_id)
    fixed_expires_at = first_dto.expires_at
    fixed_activated_at = first_dto.activated_at

    # Repeated validations
    for _ in range(5):
        val = await provider.validate_license(card.license_key, fingerprint="FP_REPEAT")
        assert val.valid is True
        assert val.license.expires_at == fixed_expires_at
        assert val.license.activated_at == fixed_activated_at

    # Idempotent reactivation with same device
    react_dto = await provider.activate_device(card.license_key, _hw("FP_REPEAT"))
    assert react_dto.fingerprint == "FP_REPEAT"

    after_dto = await provider.get_license(card.license_id)
    assert after_dto.expires_at == fixed_expires_at
    assert after_dto.activated_at == fixed_activated_at


# ----------------------------------------------------------------------
# Requirement 6: failed activation does not start timer
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_failed_activation_does_not_start_timer():
    store = SqliteEventStore(":memory:")
    provider = InMemoryKeygenProvider(event_store=store)
    card = await provider.create_card(plan="1d")

    # Corrupt key attempt
    with pytest.raises(ValueError, match="invalid"):
        await provider.activate_device(card.license_key + "_CORRUPT", _hw("FP_FAIL"))

    # Card must remain UNUSED with no timer started
    raw = await provider.get_license(card.license_id)
    assert raw.status == LicenseStatus.UNUSED
    assert raw.activated_at is None
    assert raw.expires_at is None

    val = await provider.validate_license(card.license_key)
    assert val.valid is False
    assert val.status == LicenseStatus.UNUSED


# ----------------------------------------------------------------------
# Requirement 7: concurrent first activation cannot double-activate incorrectly
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_concurrent_first_activation_cannot_double_activate():
    store = SqliteEventStore(":memory:")
    provider = InMemoryKeygenProvider(event_store=store)
    card = await provider.create_card(plan="1d", device_limit=1)

    hw1 = _hw("FP_CONCURRENT_1")
    hw2 = _hw("FP_CONCURRENT_2")

    # Concurrently attempt first activation with two different devices
    results = await asyncio.gather(
        provider.activate_device(card.license_key, hw1),
        provider.activate_device(card.license_key, hw2),
        return_exceptions=True,
    )

    successes = [r for r in results if isinstance(r, type(results[0])) and not isinstance(r, Exception)]
    failures = [r for r in results if isinstance(r, Exception)]

    # Exactly one device must succeed, the other must fail with slot limit
    assert len(successes) == 1
    assert len(failures) == 1
    assert "DEVICE_LIMIT_EXCEEDED" in str(failures[0])

    devices = await provider.get_devices(card.license_id)
    assert len(devices) == 1
    winning_fp = successes[0].fingerprint
    assert devices[0].fingerprint == winning_fp

    # License is ACTIVE with only one winning device
    lic = await provider.get_license(card.license_id)
    assert lic.status == LicenseStatus.ACTIVE
    assert lic.devices_used == 1


# ----------------------------------------------------------------------
# Requirement 8: expired card rejected
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_expired_card_rejected():
    store = SqliteEventStore(":memory:")
    provider = InMemoryKeygenProvider(event_store=store)
    card = await provider.create_card(plan="1d")
    await provider.activate_device(card.license_key, _hw("FP_EXP"))

    # Force expiration beyond grace period (e.g. 5 days ago)
    expired_time = datetime.now(timezone.utc) - timedelta(days=5)
    await provider.set_license_expiry(card.license_id, expired_time)

    val = await provider.validate_license(card.license_key, fingerprint="FP_EXP")
    assert val.valid is False
    assert val.can_start_runner is False
    assert val.status == LicenseStatus.EXPIRED

    # Cannot activate an expired card
    with pytest.raises(ValueError, match="expired"):
        await provider.activate_device(card.license_key, _hw("FP_EXP_NEW"))


# ----------------------------------------------------------------------
# Requirement 9: revoked card rejected
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_revoked_card_rejected():
    store = SqliteEventStore(":memory:")
    provider = InMemoryKeygenProvider(event_store=store)
    card = await provider.create_card(plan="1d")

    # Revoke while UNUSED
    await provider.revoke_license(card.license_id, reason="chargeback")

    val = await provider.validate_license(card.license_key)
    assert val.valid is False
    assert val.can_start_runner is False
    assert val.status == LicenseStatus.REVOKED

    # Cannot activate a revoked card
    with pytest.raises(ValueError, match="revoked"):
        await provider.activate_device(card.license_key, _hw("FP_REV"))


# ----------------------------------------------------------------------
# Requirement 10: bulk generation count correct
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_bulk_generation_count_correct():
    store = SqliteEventStore(":memory:")
    provider = InMemoryKeygenProvider(event_store=store)

    batch_id, cards = await provider.bulk_create_cards(
        count=100,
        plan="1d",
        operator_note="testing count 100",
    )

    assert len(cards) == 100
    assert batch_id.startswith("batch_")

    batches = store.list_batches()
    assert len(batches) == 1
    assert batches[0]["batch_id"] == batch_id
    assert batches[0]["card_count"] == 100
    assert batches[0]["plan"] == "1d"
    assert batches[0]["duration_seconds"] == 86400
    assert batches[0]["operator_note"] == "testing count 100"

    # All cards saved in store
    loaded = store.load_local_licenses()
    for c in cards:
        assert c.license_id in loaded
        assert loaded[c.license_id]["status"] == LicenseStatus.UNUSED


# ----------------------------------------------------------------------
# Requirement 11: generated codes unique and entropy
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_generated_codes_unique_and_no_ambiguous_chars():
    codes = [generate_card_code(plan="1d") for _ in range(250)]
    # Unambiguous alphabet has exactly 31 characters (8 digits + 23 uppercase letters)
    assert len(CARD_ALPHABET) == 31
    # Uniqueness
    assert len(set(codes)) == 250

    # Ensure no confusing characters (0, O, 1, I, L)
    for code in codes:
        assert code.startswith("SSB-D1-")
        body = code.removeprefix("SSB-D1-").replace("-", "")
        assert len(body) == 16
        for ch in body:
            assert ch in CARD_ALPHABET
            assert ch not in {"0", "O", "1", "I", "L"}


# ----------------------------------------------------------------------
# Requirement 12: CSV export count correct and CLI execution
# ----------------------------------------------------------------------
def test_csv_export_and_cli_workflow(tmp_path):
    import subprocess
    import sys

    db_path = str(tmp_path / "test_cards.db")
    csv_path = str(tmp_path / "output_1d.csv")

    cmd = [
        sys.executable,
        "tools/card_admin.py",
        "generate",
        "--plan",
        "1d",
        "--count",
        "30",
        "--output",
        csv_path,
        "--note",
        "CLI batch test",
        "--db",
        db_path,
    ]

    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0
    assert "ShuaBao License Card Batch Generation Completed" in res.stdout
    assert "Card Count:       30" in res.stdout
    assert "Sample Masked:    SSB-D1-" in res.stdout

    # Verify CSV file contents
    assert os.path.exists(csv_path)
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = list(csv.reader(f))
        assert reader[0] == ["code", "plan", "duration_seconds", "batch_id", "created_at"]
        data_rows = reader[1:]
        assert len(data_rows) == 30
        for row in data_rows:
            code, plan, dur, b_id, created = row
            assert code.startswith("SSB-D1-")
            assert plan == "1d"
            assert dur == "86400"
            assert b_id.startswith("batch_")
            # Verify no secrets or sensitive fields
            assert "admin" not in row
            assert "password" not in row
            assert "key.pem" not in row

    # Verify list-batches CLI
    cmd_lb = [sys.executable, "tools/card_admin.py", "list-batches", "--db", db_path]
    res_lb = subprocess.run(cmd_lb, capture_output=True, text=True)
    assert res_lb.returncode == 0
    assert "CLI batch test" in res_lb.stdout

    # Verify list-cards CLI masks codes
    cmd_lc = [sys.executable, "tools/card_admin.py", "list-cards", "--db", db_path]
    res_lc = subprocess.run(cmd_lc, capture_output=True, text=True)
    assert res_lc.returncode == 0
    assert "****" in res_lc.stdout
    # Confirm full plaintext codes from CSV are NOT leaked in list-cards
    first_plaintext_code = data_rows[0][0]
    assert first_plaintext_code not in res_lc.stdout


# ----------------------------------------------------------------------
# Requirement 13: existing entitlement / permit behavior without regression
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_full_rest_api_activation_and_validation_flow():
    client = TestClient(app)

    # 1. Create a 1d card using in-memory provider
    from bridge.app.main import keygen_provider
    card = await keygen_provider.create_card("1d")

    # 2. Before activation: validate returns UNUSED
    val_resp = client.post(
        "/v1/entitlements/validate",
        json={"license_key": card.license_key, "hardware": {"fingerprint": "FP_REST_01"}},
    )
    assert val_resp.status_code == 200
    val_data = val_resp.json()
    assert val_data["valid"] is False
    assert val_data["can_start_runner"] is False
    assert val_data["status"] == "UNUSED"

    # 3. First activation via /v1/devices/activate
    act_resp = client.post(
        "/v1/devices/activate",
        json={"license_key": card.license_key, "hardware": {"fingerprint": "FP_REST_01"}},
    )
    assert act_resp.status_code == 200
    act_data = act_resp.json()
    assert act_data["fingerprint"] == "FP_REST_01"

    # 4. After activation: validate returns ACTIVE and can_start_runner
    val_resp2 = client.post(
        "/v1/entitlements/validate",
        json={"license_key": card.license_key, "hardware": {"fingerprint": "FP_REST_01"}},
    )
    assert val_resp2.status_code == 200
    val_data2 = val_resp2.json()
    assert val_data2["valid"] is True
    assert val_data2["can_start_runner"] is True
    assert val_data2["status"] == "ACTIVE"


# ----------------------------------------------------------------------
# Parity with Keygate Provider
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_keygate_provider_parity_with_cards():
    provider = InMemoryKeygateProvider()
    card = await provider.create_card("3d")

    assert card.status == LicenseStatus.UNUSED
    assert card.duration_seconds == 259200
    assert card.activated_at is None
    assert card.expires_at is None

    # Unused validation
    val = await provider.validate_license(card.license_key)
    assert val.valid is False
    assert val.status == LicenseStatus.UNUSED

    # Activation
    await provider.activate_device(card.license_key, _hw("FP_KEYGATE"))
    act_card = await provider.get_license(card.license_id)
    assert act_card.status == LicenseStatus.ACTIVE
    assert act_card.activated_at is not None
    assert act_card.expires_at == act_card.activated_at + timedelta(seconds=259200)


# ----------------------------------------------------------------------
# P1-1 Regression: Cross-connection concurrency protection and atomic CAS
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cross_connection_concurrent_activation_atomic(tmp_path):
    db_file = str(tmp_path / "concurrent_test.db")
    store1 = SqliteEventStore(db_file)
    store2 = SqliteEventStore(db_file)

    p1 = InMemoryKeygenProvider(event_store=store1)
    p2 = InMemoryKeygenProvider(event_store=store2)

    # Generate 1-day UNUSED card on connection 1
    card = await p1.create_card(plan="1d", device_limit=1)
    assert card.status == LicenseStatus.UNUSED

    # Both connections attempt to activate the card simultaneously with DIFFERENT hardware
    task1 = p1.activate_device(card.license_key, _hw("FP_WINNER_OR_RUNNER_1"))
    task2 = p2.activate_device(card.license_key, _hw("FP_WINNER_OR_RUNNER_2"))

    results = await asyncio.gather(task1, task2, return_exceptions=True)

    # Exactly one must succeed, and exactly one must fail with DEVICE_LIMIT_EXCEEDED
    successes = [r for r in results if not isinstance(r, Exception)]
    errors = [r for r in results if isinstance(r, Exception)]

    assert len(successes) == 1, f"Expected 1 success, got {len(successes)}: {results}"
    assert len(errors) == 1, f"Expected 1 error, got {len(errors)}: {results}"
    assert "DEVICE_LIMIT_EXCEEDED" in str(errors[0])

    winning_act = successes[0]
    winning_fp = winning_act.fingerprint

    # Verify both providers observe the EXACT same DB state
    c1 = await p1.get_license(card.license_id)
    c2 = await p2.get_license(card.license_id)
    assert c1.status == LicenseStatus.ACTIVE
    assert c2.status == LicenseStatus.ACTIVE
    assert c1.activated_at is not None
    assert c1.activated_at == c2.activated_at
    assert c1.expires_at == c2.expires_at

    # Check that idempotent re-activation by the WINNING device succeeds without changing activated_at
    orig_act_time = c1.activated_at
    orig_exp_time = c1.expires_at

    re_act = await p2.activate_device(card.license_key, _hw(winning_fp))
    assert re_act.fingerprint == winning_fp

    c2_re = await p2.get_license(card.license_id)
    assert c2_re.activated_at == orig_act_time
    assert c2_re.expires_at == orig_exp_time

    # Attempt by a 3rd distinct device must be rejected
    with pytest.raises(ValueError, match="DEVICE_LIMIT_EXCEEDED"):
        await p1.activate_device(card.license_key, _hw("FP_DEVICE_003"))


# ----------------------------------------------------------------------
# P1-2 Regression: Strict hard expiry boundary (zero grace) for cards vs subscription grace
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_strict_card_hard_expiry_boundary_vs_subscription_grace():
    # Test BOTH Keygen and Keygate providers for symmetry
    for prov_cls in [InMemoryKeygenProvider, InMemoryKeygateProvider]:
        provider = prov_cls()

        # 1. License Card (is_card = True)
        card = await provider.create_card("1d")
        act = await provider.activate_device(card.license_key, _hw("FP_HARD_EXP"))

        card_dto = await provider.get_license(card.license_id)
        exp = card_dto.expires_at
        assert exp is not None

        # Expiry - 1 second: MUST be valid (ACTIVE)
        val_before = await provider.validate_license(
            card.license_key, fingerprint="FP_HARD_EXP", current_time=exp - timedelta(seconds=1)
        )
        assert val_before.valid is True
        assert val_before.status == LicenseStatus.ACTIVE
        assert val_before.can_start_runner is True

        # Expiry + 1 second: MUST immediately be invalid (EXPIRED), zero grace!
        val_after = await provider.validate_license(
            card.license_key, fingerprint="FP_HARD_EXP", current_time=exp + timedelta(seconds=1)
        )
        assert val_after.valid is False
        assert val_after.status == LicenseStatus.EXPIRED
        assert val_after.can_start_runner is False

        # 2. Regular Subscription (is_card = False)
        sub = await provider.create_license(
            customer_id="cust_sub_001",
            customer_email="sub@example.com",
            plan="monthly",
            duration_days=30,
        )
        await provider.activate_device(sub.license_key, _hw("FP_SUB_001"))
        sub_dto = await provider.get_license(sub.license_id)
        sub_exp = sub_dto.expires_at
        assert sub_exp is not None

        # Expiry + 1 second: Regular subscription gets 3-day grace (GRACE, valid)
        val_sub_grace = await provider.validate_license(
            sub.license_key, fingerprint="FP_SUB_001", current_time=sub_exp + timedelta(seconds=1)
        )
        assert val_sub_grace.valid is True
        assert val_sub_grace.status == LicenseStatus.GRACE
        assert val_sub_grace.can_start_runner is True

        # Expiry + 3 days + 1 second: Exceeds grace period -> EXPIRED
        val_sub_expired = await provider.validate_license(
            sub.license_key,
            fingerprint="FP_SUB_001",
            current_time=sub_exp + timedelta(days=3, seconds=1),
        )
        assert val_sub_expired.valid is False
        assert val_sub_expired.status == LicenseStatus.EXPIRED
        assert val_sub_expired.can_start_runner is False


# ----------------------------------------------------------------------
# P1-3 Regression: Bulk generation failure safety (no orphan cards/batches on CSV failure)
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_csv_write_failure_leaves_no_orphan_cards_or_batches(tmp_path):
    from tools.card_admin import _generate_cards
    db_file = str(tmp_path / "atomic_bulk.db")
    store = SqliteEventStore(db_file)

    # Initial state: 0 batches, 0 cards
    assert len(store.list_batches()) == 0
    assert len(store.load_local_licenses()) == 0

    # Simulate an impossible CSV output path (parent is an existing file, preventing dir/file creation)
    blocker_file = tmp_path / "not_a_dir"
    blocker_file.write_text("i am a file")
    impossible_csv_path = str(blocker_file / "sub_dir" / "out.csv")

    with pytest.raises(Exception):
        await _generate_cards(
            plan="1d",
            count=15,
            output_path=impossible_csv_path,
            db_path=db_file,
        )

    # Verify atomic rollback: 0 orphan cards and 0 batches in DB
    assert len(store.list_batches()) == 0
    assert len(store.load_local_licenses()) == 0

    # Also verify no stray .tmp files were left behind
    tmp_files = list(tmp_path.glob("*.tmp*"))
    assert len(tmp_files) == 0


# ----------------------------------------------------------------------
# Exact Boundary Expiry (now == expires_at)
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_exact_boundary_expiry_at_now_equals_expires_at():
    for prov_cls in [InMemoryKeygenProvider, InMemoryKeygateProvider]:
        provider = prov_cls()
        card = await provider.create_card("1d")
        act = await provider.activate_device(card.license_key, _hw("FP_BOUNDARY"))
        card_dto = await provider.get_license(card.license_id)
        exp = card_dto.expires_at
        assert exp is not None

        # 1. 1 microsecond before expiry: valid
        val_before = await provider.validate_license(
            card.license_key, fingerprint="FP_BOUNDARY", current_time=exp - timedelta(microseconds=1)
        )
        assert val_before.valid is True
        assert val_before.status == LicenseStatus.ACTIVE

        # 2. EXACT boundary (now == expires_at): MUST be EXPIRED (>= rule)
        val_exact = await provider.validate_license(
            card.license_key, fingerprint="FP_BOUNDARY", current_time=exp
        )
        assert val_exact.valid is False
        assert val_exact.status == LicenseStatus.EXPIRED
        assert val_exact.can_start_runner is False

        # 3. 1 microsecond after expiry: EXPIRED
        val_after = await provider.validate_license(
            card.license_key, fingerprint="FP_BOUNDARY", current_time=exp + timedelta(microseconds=1)
        )
        assert val_after.valid is False
        assert val_after.status == LicenseStatus.EXPIRED


# ----------------------------------------------------------------------
# Fail-Closed Duplicate batch_id
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_duplicate_batch_id_fails_closed(tmp_path):
    db_file = str(tmp_path / "dup_batch.db")
    store = SqliteEventStore(db_file)
    provider = InMemoryKeygenProvider(event_store=store)

    # 1. First batch succeeds
    b_id, cards = provider.prepare_cards(count=2, plan="1d", batch_id="BATCH_DUP_001")
    await provider.commit_batch(
        batch_id=b_id,
        plan="1d",
        duration_seconds=86400,
        cards=cards,
        status="COMMITTED",
    )
    assert len(store.list_batches()) == 1

    # 2. Second batch with same batch_id must raise DUPLICATE_BATCH_ID
    _, cards2 = provider.prepare_cards(count=2, plan="1d", batch_id="BATCH_DUP_001")
    with pytest.raises(ValueError, match="DUPLICATE_BATCH_ID"):
        await provider.commit_batch(
            batch_id="BATCH_DUP_001",
            plan="1d",
            duration_seconds=86400,
            cards=cards2,
            status="COMMITTED",
        )

    # Store still has only 1 batch
    assert len(store.list_batches()) == 1


# ----------------------------------------------------------------------
# P1-3 Regression: os.replace failure in DB commit marks batch FAILED & rejects activation
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_os_replace_failure_marks_batch_failed_and_rejects_activation(tmp_path, monkeypatch):
    from tools.card_admin import _generate_cards

    db_file = str(tmp_path / "replace_fail.db")
    csv_out = str(tmp_path / "replace_fail.csv")
    store = SqliteEventStore(db_file)

    def mock_replace_failure(src, dst):
        raise OSError("Simulated disk replacement failure after DB preparation")

    monkeypatch.setattr(os, "replace", mock_replace_failure)

    # Run _generate_cards, expect OSError
    with pytest.raises(OSError, match="Simulated disk replacement failure"):
        await _generate_cards(
            plan="1d",
            count=5,
            output_path=csv_out,
            batch_id="BATCH_REPLACE_FAIL",
            db_path=db_file,
        )

    # Verify CSV output file does not exist
    assert not os.path.exists(csv_out)

    # Verify the batch was marked FAILED in the DB
    batches = store.list_batches()
    assert len(batches) == 1
    assert batches[0]["batch_id"] == "BATCH_REPLACE_FAIL"
    assert batches[0]["status"] == "FAILED"

    # Verify that cards from this FAILED batch CANNOT be activated
    licenses = store.load_local_licenses()
    assert len(licenses) == 5
    card_key = list(licenses.values())[0]["key"]

    with pytest.raises(ValueError, match="BATCH_NOT_COMMITTED"):
        store.activate_license_atomic(
            license_key=card_key,
            hardware_fp="FP_REPLACE_FAIL",
            hardware_components={},
            hardware_hostname="test-host",
            server_now=datetime.now(timezone.utc),
        )

    # Also check provider validate
    provider = InMemoryKeygenProvider(event_store=store)
    val_res = await provider.validate_license(card_key)
    assert val_res.valid is False
    assert val_res.code == "BATCH_NOT_COMMITTED"


# ----------------------------------------------------------------------
# /admin Web Console Card Masking (No plaintext key, no copy button for cards)
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_admin_console_masks_card_codes():
    import base64
    os.environ["SUBSCRIPTION_ADMIN_PASSWORD"] = "test-admin-pass-strong"
    auth_header = {"Authorization": "Basic " + base64.b64encode(b"admin:test-admin-pass-strong").decode()}
    client = TestClient(app)

    # 1. Create regular license
    reg_resp = client.post(
        "/admin/licenses",
        data={"customer_id": "reg_user", "email": "reg@example.com", "days": "30", "device_limit": "2"},
        headers=auth_header,
        follow_redirects=True,
    )
    assert reg_resp.status_code == 200

    # 2. Create card batch via Admin API
    card_resp = client.post(
        "/admin/cards/batches",
        json={"plan": "1d", "count": 1, "batch_id": "BATCH_ADMIN_MASK_01", "initial_status": "COMMITTED"},
        headers={"X-Admin-Key": "test-admin-pass-strong"},
    )
    assert card_resp.status_code == 200
    card_data = card_resp.json()
    card_plaintext = card_data["cards"][0]["code"]
    card_masked = mask_card_code(card_plaintext)

    # 3. View /admin web console page
    page = client.get("/admin", headers=auth_header)
    assert page.status_code == 200

    # Regular license has copy button and data-key attribute
    assert "复制" in page.text

    # Card license: masked code MUST be in page, plaintext MUST NOT be anywhere in page!
    assert card_masked in page.text
    assert card_plaintext not in page.text
    assert f"data-key='{card_plaintext}'" not in page.text


# ----------------------------------------------------------------------
# HTTPS Admin API & Remote Workflow
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_https_admin_api_lifecycle(tmp_path):
    import json
    os.environ["SUBSCRIPTION_ADMIN_PASSWORD"] = "test-admin-pass-strong"
    client = TestClient(app)

    # 1. Unauthorized without key
    unauth = client.post("/admin/cards/batches", json={"plan": "1d", "count": 2})
    assert unauth.status_code == 401

    # 2. Create batch in PREPARED state
    create_resp = client.post(
        "/admin/cards/batches",
        json={"plan": "1d", "count": 2, "batch_id": "BATCH_API_TEST_01", "initial_status": "PREPARED"},
        headers={"X-Admin-Key": "test-admin-pass-strong"},
    )
    assert create_resp.status_code == 200
    res = create_resp.json()
    assert res["batch_id"] == "BATCH_API_TEST_01"
    assert res["status"] == "PREPARED"
    assert len(res["cards"]) == 2
    c0 = res["cards"][0]
    card_code = c0["code"]

    # 3. Duplicate batch creation fail-closed with 409
    dup_resp = client.post(
        "/admin/cards/batches",
        json={"plan": "1d", "count": 1, "batch_id": "BATCH_API_TEST_01"},
        headers={"X-Admin-Key": "test-admin-pass-strong"},
    )
    assert dup_resp.status_code == 409

    # 4. In PREPARED state, activating the card must fail
    act_fail = client.post(
        "/v1/devices/activate",
        json={"license_key": card_code, "hardware": _hw("FP_API_TEST").model_dump()},
    )
    assert act_fail.status_code == 400
    assert "BATCH_NOT_COMMITTED" in act_fail.text

    # 5. List batches
    lb_resp = client.get("/admin/cards/batches", headers={"X-Admin-Key": "test-admin-pass-strong"})
    assert lb_resp.status_code == 200
    batches = lb_resp.json()["batches"]
    assert any(b["batch_id"] == "BATCH_API_TEST_01" for b in batches)

    # 6. List cards: masked only, NO plaintext
    lc_resp = client.get(
        "/admin/cards?batch_id=BATCH_API_TEST_01",
        headers={"X-Admin-Key": "test-admin-pass-strong"},
    )
    assert lc_resp.status_code == 200
    cards_list = lc_resp.json()["cards"]
    assert len(cards_list) == 2
    expected_masked = {mask_card_code(c["code"]) for c in res["cards"]}
    actual_masked = {c["masked_code"] for c in cards_list}
    assert actual_masked == expected_masked
    assert "key" not in cards_list[0]
    assert card_code not in json.dumps(lc_resp.json())

    # 7. Inspect card: masked only
    insp_resp = client.get(
        f"/admin/cards/{c0['id']}",
        headers={"X-Admin-Key": "test-admin-pass-strong"},
    )
    assert insp_resp.status_code == 200
    assert insp_resp.json()["masked_code"] == mask_card_code(card_code)
    assert card_code not in json.dumps(insp_resp.json())

    # 8. Commit batch
    commit_resp = client.post(
        "/admin/cards/batches/BATCH_API_TEST_01/commit",
        headers={"X-Admin-Key": "test-admin-pass-strong"},
    )
    assert commit_resp.status_code == 200
    assert commit_resp.json()["status"] == "COMMITTED"

    # 9. Now card activation succeeds
    act_ok = client.post(
        "/v1/devices/activate",
        json={"license_key": card_code, "hardware": _hw("FP_API_TEST").model_dump()},
    )
    assert act_ok.status_code == 200
