"""
ShuaBao Entitlement Bridge REST API Server.
Unified interface for client validation, device activation, trial claim, offline entitlement,
and billing webhook ingestion.
"""
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from contracts.entitlement import (
    DeviceActivationDTO,
    EntitlementValidationResult,
    HardwareFingerprint,
    LicenseDTO,
    NormalizedBillingEvent,
    SignedOfflineEntitlement,
)
from bridge.app.core.crypto import CryptoEngine
from bridge.app.providers.keygen_provider import KeygenProvider
from bridge.app.providers.keygate_provider import KeygateProvider
from bridge.app.services.event_processor import BillingEventProcessor, FOSSBillingAdapter

app = FastAPI(
    title="ShuaBao Entitlement Bridge",
    version="1.0.0",
    description="Unified abstraction bridge for FOSSBilling, Keygen, and Keygate",
)

# Global singleton providers
crypto_engine = CryptoEngine()
keygen_provider = KeygenProvider(crypto_engine=crypto_engine)
keygate_provider = KeygateProvider(crypto_engine=crypto_engine)
billing_processor = BillingEventProcessor(license_provider=keygen_provider)


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
    trial_days: int = 7


class OfflineIssueRequest(BaseModel):
    license_key: str
    hardware: HardwareFingerprint
    ttl_seconds: int = 86400 * 7


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "shuashuabao-entitlement-bridge",
        "active_provider": "keygen",
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
    try:
        return await keygen_provider.claim_trial(
            account_id=req.account_id,
            email=req.email,
            hardware=req.hardware,
            trial_days=req.trial_days,
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
async def handle_fossbilling_webhook(payload: dict):
    norm_event = FOSSBillingAdapter.normalize_event(payload)
    lic = await billing_processor.process_event(norm_event)
    return {
        "status": "processed",
        "event_id": norm_event.event_id,
        "event_type": norm_event.event_type,
        "license": lic,
    }
