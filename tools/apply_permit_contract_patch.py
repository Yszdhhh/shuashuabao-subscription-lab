#!/usr/bin/env python3
"""One-shot deterministic wiring for the signed LIVE permit contract.

The script fails unless every expected pre-patch block occurs exactly once.
It is removed from the final review commit after CI succeeds.
"""
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def replace_once(relative: str, old: str, new: str, label: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one exact match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


def main() -> int:
    replace_once(
        "bridge/app/core/crypto.py",
        "    def verify_payload(self, cert_b64: str, sig_b64: str) -> Tuple[bool, dict, str]:\n",
        '''    def sign_canonical_json(self, payload_dict: dict) -> str:
        """Sign canonical UTF-8 JSON and return base64url without padding."""
        if not self.private_key:
            raise ValueError("Server private key required for signing")
        json_bytes = json.dumps(
            payload_dict,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        raw_sig = self.private_key.sign(json_bytes)
        return base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode("ascii")

    def verify_payload(self, cert_b64: str, sig_b64: str) -> Tuple[bool, dict, str]:
''',
        "CryptoEngine.sign_canonical_json",
    )

    replace_once(
        "contracts/entitlement.py",
        "    grace_remaining_seconds: int = 0\n",
        "    grace_remaining_seconds: int = 0\n    permit: Optional[Dict[str, Any]] = None\n",
        "EntitlementValidationResult.permit",
    )

    replace_once(
        "bridge/app/main.py",
        '''from bridge.app.services.event_processor import (
    BillingEventProcessor,
    FOSSBillingAdapter,
    SqliteEventStore,
)
''',
        '''from bridge.app.services.event_processor import (
    BillingEventProcessor,
    FOSSBillingAdapter,
    SqliteEventStore,
)
from bridge.app.services.permit_issuer import PermitIssueError, PermitIssuer
''',
        "main permit issuer import",
    )

    replace_once(
        "bridge/app/main.py",
        "crypto_engine = CryptoEngine()\n",
        "crypto_engine = CryptoEngine()\npermit_issuer = PermitIssuer.from_environment(crypto_engine)\n",
        "main permit issuer initialization",
    )

    replace_once(
        "bridge/app/main.py",
        '''class ValidateRequest(BaseModel):
    license_key: str
    hardware: Optional[HardwareFingerprint] = None
''',
        '''class PermitRequest(BaseModel):
    source_sha: str
    release_manifest_sha256: str
    release_channel: str
    mode_id: str


class ValidateRequest(BaseModel):
    license_key: str
    hardware: Optional[HardwareFingerprint] = None
    permit_request: Optional[PermitRequest] = None
''',
        "ValidateRequest permit context",
    )

    replace_once(
        "bridge/app/main.py",
        '''@app.post("/v1/entitlements/validate", response_model=EntitlementValidationResult)
async def validate_entitlement(req: ValidateRequest):
    fp = req.hardware.fingerprint if req.hardware else None
    return await keygen_provider.validate_license(req.license_key, fingerprint=fp)
''',
        '''@app.post("/v1/entitlements/validate", response_model=EntitlementValidationResult)
async def validate_entitlement(req: ValidateRequest):
    fp = req.hardware.fingerprint if req.hardware else None
    result = await keygen_provider.validate_license(req.license_key, fingerprint=fp)
    if req.permit_request is None or not result.valid or not result.can_start_runner:
        return result
    if req.hardware is None or result.license is None:
        result.can_start_runner = False
        result.code = "PERMIT_CONTEXT_MISSING"
        result.message = "LIVE permit requires an activated device and license context"
        return result
    try:
        context = req.permit_request
        result.permit = permit_issuer.issue(
            license=result.license,
            hardware=req.hardware,
            source_sha=context.source_sha,
            release_manifest_sha256=context.release_manifest_sha256,
            release_channel=context.release_channel,
            mode_id=context.mode_id,
        )
    except PermitIssueError as exc:
        result.can_start_runner = False
        result.code = exc.code
        result.message = exc.message
    return result
''',
        "validate endpoint permit issuance",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
