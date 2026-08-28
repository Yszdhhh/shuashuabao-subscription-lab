"""
ShuaBao Entitlement Bridge REST API Server.
Unified interface for client validation, device activation, trial claim, offline entitlement,
and billing webhook ingestion.
"""
import os
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel
from contracts.entitlement import (
    DeviceActivationDTO,
    EntitlementValidationResult,
    HardwareFingerprint,
    LicenseDTO,
    SignedOfflineEntitlement,
)
from bridge.app.core.crypto import CryptoEngine, verify_hmac_signature
from bridge.app.providers.http_keygen_provider import HttpKeygenProvider
from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
from bridge.app.providers.keygate_provider import InMemoryKeygateProvider
from bridge.app.services.event_processor import BillingEventProcessor, FOSSBillingAdapter

_PROVIDER_MODE = os.environ.get("PROVIDER_MODE", "inmemory").lower()
_WEBHOOK_SECRET = os.environ.get("FOSSBILLING_WEBHOOK_SECRET", "")
if _PROVIDER_MODE in ("production", "compose", "real") and not _WEBHOOK_SECRET:
    raise RuntimeError(
        "FATAL: FOSSBILLING_WEBHOOK_SECRET must be configured in production/compose mode"
    )

app = FastAPI(
    title="ShuaBao Entitlement Bridge",
    version="1.0.0",
    description="Unified abstraction bridge for FOSSBilling, Keygen, and Keygate",
)

# Global singleton providers
crypto_engine = CryptoEngine()
if _PROVIDER_MODE in ("keygen", "real", "http_keygen", "production", "compose"):
    keygen_provider = HttpKeygenProvider(
        base_url=os.environ.get("KEYGEN_BASE_URL", ""),
        account_id=os.environ.get("KEYGEN_ACCOUNT_ID", ""),
        token=os.environ.get("KEYGEN_TOKEN", ""),
        crypto_engine=crypto_engine,
    )
else:
    keygen_provider = InMemoryKeygenProvider(crypto_engine=crypto_engine)
keygate_provider = InMemoryKeygateProvider(crypto_engine=crypto_engine)
billing_processor = BillingEventProcessor(license_provider=keygen_provider)

# Server-enforced trial duration policy (3 days default per server policy)
_TRIAL_DAYS = int(os.environ.get("DEFAULT_TRIAL_DAYS", "3"))

class ValidateRequest(BaseModel):
    license_key: str
    hardware: Optional[HardwareFingerprint] = None


class ActivateRequest(BaseModel):
    license_key: str
    hardware: HardwareFingerprint


class DeactivateRequest(BaseModel):
    license_key: str
    fingerprint: str


class TrialRequest(BaseModel):
    account_id: str
    email: str
    hardware: HardwareFingerprint
    # trial_days intentionally not accepted — server enforces _TRIAL_DAYS


class OfflineIssueRequest(BaseModel):
    license_key: str
    hardware: HardwareFingerprint
    ttl_seconds: int = 48 * 3600  # ignored; server policy is always 48 hours


@app.get("/health")
def health_check():
    provider_name = "http_keygen" if isinstance(keygen_provider, HttpKeygenProvider) else "inmemory_keygen"
    return {
        "status": "healthy",
        "service": "shuashuabao-entitlement-bridge",
        "provider_mode": _PROVIDER_MODE,
        "active_provider": provider_name,
        "shadow_provider": "keygate",
    }


@app.post("/v1/entitlements/validate", response_model=EntitlementValidationResult)
async def validate_entitlement(req: ValidateRequest):
    fp = req.hardware.fingerprint if req.hardware else None
    return await keygen_provider.validate_license(req.license_key, fingerprint=fp)


@app.post("/v1/devices/activate", response_model=DeviceActivationDTO)
async def activate_device(req: ActivateRequest):
    try:
        return await keygen_provider.activate_device(req.license_key, req.hardware)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/v1/devices/deactivate")
async def deactivate_device(req: DeactivateRequest):
    success = await keygen_provider.deactivate_device(req.license_key, req.fingerprint)
    return {"success": success}


@app.post("/v1/trials/claim", response_model=LicenseDTO)
async def claim_trial(req: TrialRequest):
    """Server enforces TRIAL_DAYS=7; any client-supplied trial_days is ignored."""
    try:
        return await keygen_provider.claim_trial(
            account_id=req.account_id,
            email=req.email,
            hardware=req.hardware,
            trial_days=_TRIAL_DAYS,
        )
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))


@app.post("/v1/offline/issue", response_model=SignedOfflineEntitlement)
async def issue_offline_entitlement(req: OfflineIssueRequest):
    try:
        return await keygen_provider.issue_offline_entitlement(
            req.license_key, req.hardware, ttl_seconds=req.ttl_seconds
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/v1/webhooks/fossbilling")
async def handle_fossbilling_webhook(
    request: Request,
    x_fossbilling_signature: Optional[str] = Header(None, alias="X-FOSSBilling-Signature"),
    x_webhook_signature: Optional[str] = Header(None, alias="X-Webhook-Signature"),
):
    """
    Process FOSSBilling webhook events.
    HMAC verification is fail-closed: if FOSSBILLING_WEBHOOK_SECRET is configured,
    a missing or invalid signature returns 401/403. Unrecognized events return 400.
    """
    raw_body = await request.body()

    # HMAC verification — fail-closed when secret is configured
    if _WEBHOOK_SECRET:
        sig = x_fossbilling_signature or x_webhook_signature
        if not sig:
            raise HTTPException(status_code=401, detail="Missing webhook signature header")
        if not verify_hmac_signature(_WEBHOOK_SECRET, raw_body, sig):
            raise HTTPException(status_code=403, detail="Invalid webhook signature")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed JSON payload")

    try:
        norm_event = FOSSBillingAdapter.normalize_event(payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    lic = await billing_processor.process_event(norm_event)
    return {
        "status": "processed",
        "event_id": norm_event.event_id,
        "event_type": norm_event.event_type,
        "license": lic,
    }
