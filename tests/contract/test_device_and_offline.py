"""
Device limit, Trial anti-abuse, and Signed Offline License Contract Tests.
"""
import pytest
from contracts.entitlement import HardwareFingerprint, LicenseStatus
from bridge.app.providers.keygen_provider import KeygenProvider
from bridge.app.providers.keygate_provider import KeygateProvider


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_cls", [KeygenProvider, KeygateProvider])
async def test_device_activation_and_limits(provider_cls):
    provider = provider_cls()
    lic = await provider.create_license(
        customer_id="cust_dev",
        customer_email="bob@example.com",
        plan="standard",
        duration_days=30,
        device_limit=1,
    )

    dev_a = HardwareFingerprint(
        fingerprint="FP_DEVICE_AAA",
        hostname="WORKSTATION_A",
        components={"mb": "MB_123", "disk": "DISK_456"},
    )
    dev_b = HardwareFingerprint(
        fingerprint="FP_DEVICE_BBB",
        hostname="WORKSTATION_B",
        components={"mb": "MB_999", "disk": "DISK_888"},
    )

    # 1. Activate Device A
    act_a = await provider.activate_device(lic.license_key, dev_a)
    assert act_a.fingerprint == "FP_DEVICE_AAA"

    # 2. Duplicate activation of Device A (Idempotent success)
    act_a_dup = await provider.activate_device(lic.license_key, dev_a)
    assert act_a_dup.fingerprint == "FP_DEVICE_AAA"

    # 3. Activate Device B with device_limit = 1 (MUST reject)
    with pytest.raises(ValueError, match="DEVICE_LIMIT_EXCEEDED"):
        await provider.activate_device(lic.license_key, dev_b)

    # 4. Deactivate Device A
    deact_res = await provider.deactivate_device(lic.license_key, dev_a.fingerprint)
    assert deact_res is True

    # 5. Reactivate Device B now succeeds
    act_b = await provider.activate_device(lic.license_key, dev_b)
    assert act_b.fingerprint == "FP_DEVICE_BBB"


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_cls", [KeygenProvider, KeygateProvider])
async def test_trial_anti_abuse_contract(provider_cls):
    provider = provider_cls()

    dev_x = HardwareFingerprint(
        fingerprint="FP_HARDWARE_X",
        hostname="DEV_BOX_1",
        components={"mb": "ASUS_Z790", "disk": "SAMSUNG_990_PRO", "mac": "00:11:22:33:44:55"},
    )

    # Test A: Account A on Device X -> Trial OK
    lic_a = await provider.claim_trial("account_A", "userA@example.com", dev_x)
    assert lic_a.status == LicenseStatus.TRIAL

    # Test B: Account B on same Device X -> Trial DENY
    with pytest.raises(ValueError, match="TRIAL_ALREADY_CLAIMED"):
        await provider.claim_trial("account_B", "userB@example.com", dev_x)


@pytest.mark.asyncio
async def test_keygen_component_fuzzy_matching_trial_abuse():
    """Keygen specific verification of component MATCH_MOST anti-abuse strategy."""
    provider = KeygenProvider()

    orig_dev = HardwareFingerprint(
        fingerprint="FP_RIG_01",
        components={
            "mb": "GIGABYTE_B760",
            "disk": "WD_BLACK_SN850X",
            "cpu": "INTEL_13600K",
            "mac": "AA:BB:CC:DD:EE:01",
        },
    )
    await provider.claim_trial("acc_1", "acc1@example.com", orig_dev)

    # Partial spoof: same MB, same CPU, same Disk, but changed MAC (3/4 matched = majority matched)
    spoofed_dev = HardwareFingerprint(
        fingerprint="FP_SPOOFED_FP_99",
        components={
            "mb": "GIGABYTE_B760",
            "disk": "WD_BLACK_SN850X",
            "cpu": "INTEL_13600K",
            "mac": "AA:BB:CC:DD:EE:99",  # Changed
        },
    )

    # MUST detect trial abuse via MATCH_MOST
    with pytest.raises(ValueError, match="TRIAL_ABUSE_DETECTED"):
        await provider.claim_trial("acc_2", "acc2@example.com", spoofed_dev)


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_cls", [KeygenProvider, KeygateProvider])
async def test_offline_signed_entitlement_validation_and_tampering(provider_cls):
    provider = provider_cls()
    lic = await provider.create_license("cust_off", "off@example.com", "enterprise", 30)

    hw = HardwareFingerprint(
        fingerprint="FP_OFFLINE_NODE_01",
        components={"mb": "DELL_SERVER_MB", "disk": "SAMSUNG_PM9A3"},
    )
    await provider.activate_device(lic.license_key, hw)

    # 1. Issue signed offline certificate (7 days TTL)
    offline_cert = await provider.issue_offline_entitlement(
        lic.license_key, hw, ttl_seconds=86400 * 7
    )
    assert offline_cert.certificate is not None
    assert offline_cert.signature is not None

    # 2. Local offline validation with valid signature & matching device -> PASS
    res = await provider.verify_offline_entitlement(offline_cert, hw)
    assert res.valid is True
    assert res.can_start_runner is True
    assert res.status == LicenseStatus.ACTIVE

    # 3. Tampering test: Modify certificate base64 payload (tamper with plan/expiry) -> FAIL
    tampered_cert = offline_cert.model_copy()
    tampered_cert.certificate = tampered_cert.certificate[:-4] + "AAAA"
    tamper_res = await provider.verify_offline_entitlement(tampered_cert, hw)
    assert tamper_res.valid is False
    assert tamper_res.can_start_runner is False
    assert "SIGNATURE" in tamper_res.code

    # 4. Fingerprint mismatch test -> FAIL
    different_hw = HardwareFingerprint(fingerprint="FP_OTHER_DEVICE_99")
    mismatch_res = await provider.verify_offline_entitlement(offline_cert, different_hw)
    assert mismatch_res.valid is False
    assert mismatch_res.code == "FINGERPRINT_MISMATCH"
