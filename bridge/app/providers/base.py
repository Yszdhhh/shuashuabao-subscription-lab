"""
Abstract Provider Interface for License Authorities.
Both KeygenProvider and KeygateProvider MUST implement this interface.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from contracts.entitlement import (
    DeviceActivationDTO,
    EntitlementValidationResult,
    HardwareFingerprint,
    LicenseDTO,
    LicenseStatus,
    SignedOfflineEntitlement,
)


class ILicenseProvider(ABC):
    @abstractmethod
    async def create_license(
        self,
        customer_id: str,
        customer_email: str,
        plan: str,
        duration_days: int = 30,
        device_limit: int = 1,
        features: Optional[List[str]] = None,
        metadata: Optional[Dict] = None,
    ) -> LicenseDTO:
        """Create a new commercial or trial license."""
        pass

    @abstractmethod
    async def get_license(self, license_id: str) -> Optional[LicenseDTO]:
        """Fetch license details by ID or key."""
        pass

    @abstractmethod
    async def validate_license(
        self, license_key: str, fingerprint: Optional[str] = None
    ) -> EntitlementValidationResult:
        """Validate license status and verify device authorization."""
        pass

    @abstractmethod
    async def renew_license(
        self, license_id: str, extend_days: int = 30
    ) -> LicenseDTO:
        """Renew / extend existing license expiration."""
        pass

    @abstractmethod
    async def extend_license(
        self, license_id: str, extend_days: int = 7
    ) -> LicenseDTO:
        """Manually grant extra grace or trial days."""
        pass

    @abstractmethod
    async def suspend_license(
        self, license_id: str, reason: str = "administrative_suspension"
    ) -> LicenseDTO:
        """Suspend license (e.g. past due, chargeback, or fraud)."""
        pass

    @abstractmethod
    async def reinstate_license(self, license_id: str) -> LicenseDTO:
        """Reinstate a previously suspended license back to active."""
        pass

    @abstractmethod
    async def revoke_license(
        self, license_id: str, reason: str = "refunded_or_terminated"
    ) -> LicenseDTO:
        """Permanently revoke / cancel license."""
        pass

    @abstractmethod
    async def activate_device(
        self, license_key: str, hardware: HardwareFingerprint
    ) -> DeviceActivationDTO:
        """Activate a device on a license, enforcing max device limit and uniqueness."""
        pass

    @abstractmethod
    async def deactivate_device(
        self, license_key: str, fingerprint: str
    ) -> bool:
        """Deactivate / unbind a device slot."""
        pass

    @abstractmethod
    async def get_devices(self, license_id: str) -> List[DeviceActivationDTO]:
        """List all active machine activations under a license."""
        pass

    @abstractmethod
    async def claim_trial(
        self,
        account_id: str,
        email: str,
        hardware: HardwareFingerprint,
        trial_days: int = 7,
    ) -> LicenseDTO:
        """Claim a trial license with device anti-abuse and component matching."""
        pass

    @abstractmethod
    async def issue_offline_entitlement(
        self, license_key: str, hardware: HardwareFingerprint, ttl_seconds: int = 86400 * 7
    ) -> SignedOfflineEntitlement:
        """Issue cryptographically signed offline entitlement certificate."""
        pass

    @abstractmethod
    async def verify_offline_entitlement(
        self, entitlement: SignedOfflineEntitlement, current_hardware: HardwareFingerprint
    ) -> EntitlementValidationResult:
        """Client-side offline verification of cryptographic signature and validity."""
        pass
