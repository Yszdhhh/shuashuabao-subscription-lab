"""
Fault Injection and Security Boundary Contract Tests.
Verifies service resilience under network timeouts, malformed payloads, and tamper attempts.
"""
from datetime import datetime, timezone, timedelta
import pytest
from contracts.entitlement import HardwareFingerprint, LicenseStatus, SignedOfflineEntitlement
from bridge.app.core.crypto import CryptoEngine
from bridge.app.providers.keygen_provider import KeygenProvider


@pytest.mark.asyncio
async def test_security_boundary_client_cannot_forge_signature():
    """Verifies that an attacker with a different public key cannot forge entitlement."""
    server_crypto = CryptoEngine()
    attacker_crypto = CryptoEngine()  # Generates different keypair

    provider = KeygenProvider(crypto_engine=server_crypto)
    lic = await provider.create_license("cust_sec", "sec@example.com", "enterprise", 30)
    hw = HardwareFingerprint(fingerprint="FP_ATTACKER_DEVICE")

    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=365)

    # Attacker crafts fake certificate signed by attacker's own private key
    fake_payload = {
        "license_id": lic.license_id,
        "fingerprint": hw.fingerprint,
        "plan": "unlimited_vip",
        "features": ["all"],
        "expires_at": exp.isoformat(),
    }
    fake_cert, fake_sig = attacker_crypto.sign_payload(fake_payload)

    forged_entitlement = SignedOfflineEntitlement(
        certificate=fake_cert,
        signature=fake_sig,
        algorithm="ED25519",
        license_id=lic.license_id,
        fingerprint=hw.fingerprint,
        plan="unlimited_vip",
        issued_at=now,
        expires_at=exp,
    )

    # Server / Official Client verification MUST reject forged entitlement
    res = await provider.verify_offline_entitlement(forged_entitlement, hw)
    assert res.valid is False
    assert res.can_start_runner is False
    assert res.code == "SIGNATURE_VERIFICATION_FAILED"


@pytest.mark.asyncio
async def test_malformed_payload_and_corrupt_data_handling():
    provider = KeygenProvider()
    hw = HardwareFingerprint(fingerprint="FP_NORMAL")
    now = datetime.now(timezone.utc)

    corrupt_entitlement = SignedOfflineEntitlement(
        certificate="NOT_VALID_BASE64_OR_JSON!@#$",
        signature="INVALID_SIG",
        algorithm="ED25519",
        license_id="lic_fake",
        fingerprint="FP_NORMAL",
        plan="standard",
        issued_at=now,
        expires_at=now + timedelta(days=7),
    )

    res = await provider.verify_offline_entitlement(corrupt_entitlement, hw)
    assert res.valid is False
    assert res.can_start_runner is False
    assert "FAILED" in res.code
