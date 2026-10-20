"""
ShuaBao Unified Entitlement Contract Definitions.
Defines canonical state, DTOs, interfaces, and events.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class LicenseStatus(str, Enum):
    TRIAL = "TRIAL"
    ACTIVE = "ACTIVE"
    GRACE = "GRACE"
    PAST_DUE = "PAST_DUE"
    SUSPENDED = "SUSPENDED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class BillingEventType(str, Enum):
    CUSTOMER_CREATED = "CUSTOMER_CREATED"
    SUBSCRIPTION_STARTED = "SUBSCRIPTION_STARTED"
    SUBSCRIPTION_RENEWED = "SUBSCRIPTION_RENEWED"
    SUBSCRIPTION_PAST_DUE = "SUBSCRIPTION_PAST_DUE"
    SUBSCRIPTION_CANCELED = "SUBSCRIPTION_CANCELED"
    PAYMENT_SUCCEEDED = "PAYMENT_SUCCEEDED"
    PAYMENT_FAILED = "PAYMENT_FAILED"
    REFUND_SUCCEEDED = "REFUND_SUCCEEDED"


class HardwareFingerprint(BaseModel):
    fingerprint: str = Field(..., description="Primary combined SHA256 hardware identifier")
    components: Dict[str, str] = Field(default_factory=dict, description="Component level hash map, e.g. motherboard, disk, cpu")
    platform: str = Field(default="windows", description="OS platform, e.g. windows, linux")
    hostname: Optional[str] = None


class LicenseDTO(BaseModel):
    license_id: str
    license_key: str
    status: LicenseStatus
    plan: str
    customer_id: str
    customer_email: Optional[str] = None
    created_at: datetime
    expires_at: Optional[datetime] = None
    device_limit: int = 1
    devices_used: int = 0
    offline_until: Optional[datetime] = None
    features: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # BATCH C: unified tier identity (go|plus|pro|ultra|test); derived for legacy plans.
    tier: Optional[str] = None
    tier_name: Optional[str] = None
    is_beta_user: Optional[bool] = None  # r7.1


class DeviceActivationDTO(BaseModel):
    activation_id: str
    license_id: str
    fingerprint: str
    name: Optional[str] = None
    activated_at: datetime
    last_heartbeat_at: Optional[datetime] = None
    components: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # BATCH C: identity of the bound license (for #brandSubBadge right after activation).
    plan: Optional[str] = None
    tier: Optional[str] = None
    tier_name: Optional[str] = None
    is_beta_user: Optional[bool] = None  # r7.1
    expires_at: Optional[datetime] = None


class SignedOfflineEntitlement(BaseModel):
    certificate: str = Field(..., description="Base64 encoded signed entitlement payload")
    signature: str = Field(..., description="Cryptographic signature (Ed25519/RSA/ECDSA)")
    algorithm: str = Field(default="ED25519", description="Signature algorithm")
    issued_at: datetime
    expires_at: datetime
    license_id: str
    fingerprint: str
    plan: str
    features: List[str] = Field(default_factory=list)


class NormalizedBillingEvent(BaseModel):
    event_id: str = Field(..., description="Unique event identifier for idempotency check")
    event_type: BillingEventType
    customer_id: str
    customer_email: Optional[str] = None
    subscription_id: Optional[str] = None
    invoice_id: Optional[str] = None
    plan: str = "pro_monthly"
    duration_days: int = 30
    occurred_at: datetime
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


class EntitlementValidationResult(BaseModel):
    valid: bool
    status: LicenseStatus
    can_start_runner: bool
    license: Optional[LicenseDTO] = None
    code: str = "OK"
    message: str = "License is valid"
    grace_remaining_seconds: int = 0
    permit: Optional[Dict[str, Any]] = None
    release_status: Optional[Dict[str, Any]] = None
    # BATCH C: top-level mirror of license.plan/tier/tier_name (null when license unknown).
    plan: Optional[str] = None
    tier: Optional[str] = None
    tier_name: Optional[str] = None
    is_beta_user: Optional[bool] = None  # r7.1


# Server-side authoritative plan policy — clients/webhooks CANNOT override duration.
# Keys match the plan field in NormalizedBillingEvent / LicenseDTO.
SERVER_PLAN_POLICIES: dict = {
    "pro_monthly":  {"duration_days": 30,  "features": ["core", "automation"]},
    "pro_annual":   {"duration_days": 365, "features": ["core", "automation", "priority_support"]},
    "trial_7d":     {"duration_days": 7,   "features": ["core", "trial_tier"]},
    "enterprise":   {"duration_days": 365, "features": ["core", "automation", "priority_support", "enterprise"]},
}
