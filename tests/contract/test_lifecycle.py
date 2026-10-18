"""
Core License Lifecycle Contract Tests.
Runs the exact same test matrix against both KeygenProvider and KeygateProvider.
"""
import pytest
from datetime import datetime, timezone
from contracts.entitlement import LicenseStatus
from bridge.app.providers.keygen_provider import KeygenProvider
from bridge.app.providers.keygate_provider import KeygateProvider


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_cls", [KeygenProvider, KeygateProvider])
async def test_license_lifecycle_crud(provider_cls):
    provider = provider_cls()

    # 1. Create License
    lic = await provider.create_license(
        customer_id="cust_001",
        customer_email="alice@example.com",
        plan="pro_monthly",
        duration_days=30,
        device_limit=1,
    )
    assert lic.license_id is not None
    assert lic.status == LicenseStatus.ACTIVE
    assert lic.device_limit == 1
    assert lic.devices_used == 0

    # 2. Validate License
    val_res = await provider.validate_license(lic.license_key)
    assert val_res.valid is True
    assert val_res.can_start_runner is True
    assert val_res.status == LicenseStatus.ACTIVE

    # 3. Renew License (+30 days)
    old_exp = lic.expires_at
    renewed = await provider.renew_license(lic.license_id, extend_days=30)
    assert renewed.status == LicenseStatus.ACTIVE
    assert renewed.expires_at > old_exp

    # 4. Manual Extend (+7 days)
    mid_exp = renewed.expires_at
    extended = await provider.extend_license(lic.license_id, extend_days=7)
    assert extended.expires_at > mid_exp

    # 5. Suspend License
    suspended = await provider.suspend_license(lic.license_id, reason="billing_dispute")
    assert suspended.status == LicenseStatus.SUSPENDED

    val_sus = await provider.validate_license(lic.license_key)
    assert val_sus.valid is False
    assert val_sus.can_start_runner is False
    assert val_sus.status == LicenseStatus.SUSPENDED

    # 6. Reinstate License
    reinstated = await provider.reinstate_license(lic.license_id)
    assert reinstated.status == LicenseStatus.ACTIVE

    val_rein = await provider.validate_license(lic.license_key)
    assert val_rein.valid is True
    assert val_rein.can_start_runner is True

    # 7. Revoke License
    revoked = await provider.revoke_license(lic.license_id, reason="customer_refund")
    assert revoked.status == LicenseStatus.REVOKED

    val_rev = await provider.validate_license(lic.license_key)
    assert val_rev.valid is False
    assert val_rev.can_start_runner is False
    assert val_rev.status == LicenseStatus.REVOKED
