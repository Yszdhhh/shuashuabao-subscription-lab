"""
Fault Injection and Security Boundary Contract Tests.
Verifies service resilience under network timeouts, malformed payloads, and tamper attempts.
"""
import base64
from datetime import datetime, timezone, timedelta
import pytest
from contracts.entitlement import HardwareFingerprint, LicenseStatus, SignedOfflineEntitlement
from bridge.app.core.crypto import CryptoEngine
from bridge.app.providers.keygen_provider import KeygenProvider
from bridge.app.providers.keygate_provider import KeygateProvider


@pytest.mark.asyncio
async def test_security_boundary_client_cannot_forge_signature():
    """Verifies that an attacker with a different public key cannot forge entitlement."""
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
    from cryptography.hazmat.primitives import serialization as _ser

    def _fresh_pem():
        k = _ed25519.Ed25519PrivateKey.generate()
        return k.private_bytes(
            encoding=_ser.Encoding.PEM,
            format=_ser.PrivateFormat.PKCS8,
            encryption_algorithm=_ser.NoEncryption(),
        )

    server_pem = _fresh_pem()
    attacker_pem = _fresh_pem()
    # Guarantee distinct keypairs (vanishingly unlikely but explicit)
    assert server_pem != attacker_pem

    server_crypto = CryptoEngine(private_key_pem=server_pem)
    attacker_crypto = CryptoEngine(private_key_pem=attacker_pem)

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


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_cls", [KeygenProvider, KeygateProvider])
@pytest.mark.parametrize("bad_signature", [
    "not-base64",
    base64.b64encode(b"too-short").decode("ascii"),
])
async def test_valid_certificate_with_malformed_signature_is_rejected(provider_cls, bad_signature):
    """A valid certificate must not pass when its signature is malformed."""
    provider = provider_cls()
    hardware = HardwareFingerprint(fingerprint="FP_BAD_SIGNATURE")
    license_dto = await provider.create_license("cust_bad_sig", "bad-sig@example.com", "pro", 30)
    entitlement = await provider.issue_offline_entitlement(license_dto.license_key, hardware)
    entitlement.signature = bad_signature

    result = await provider.verify_offline_entitlement(entitlement, hardware)

    assert result.valid is False
    assert result.can_start_runner is False
    assert result.code == "SIGNATURE_VERIFICATION_FAILED"


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_cls", [KeygenProvider, KeygateProvider])
async def test_expired_offline_entitlement_denies_runner(provider_cls):
    """A correctly signed token whose TTL has elapsed must be rejected."""
    provider = provider_cls()
    hardware = HardwareFingerprint(fingerprint="FP_EXPIRED_TOKEN")
    license_dto = await provider.create_license("cust_expired", "expired@example.com", "pro", 30)
    entitlement = await provider.issue_offline_entitlement(
        license_dto.license_key,
        hardware,
        ttl_seconds=-1,
    )

    result = await provider.verify_offline_entitlement(entitlement, hardware)

    assert result.valid is False
    assert result.can_start_runner is False
    assert result.status == LicenseStatus.EXPIRED
    assert result.code == "OFFLINE_TTL_EXPIRED"
