"""
ShuaBao Entitlement Bridge REST API Server.
Unified interface for client validation, device activation, trial claim, offline entitlement,
and billing webhook ingestion.
"""
import base64
import html
import os
import secrets
from datetime import datetime, timezone
from urllib.parse import parse_qs, quote
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import HTMLResponse, RedirectResponse
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
from bridge.app.services.event_processor import (
    BillingEventProcessor,
    FOSSBillingAdapter,
    SqliteEventStore,
)
from bridge.app.services.permit_issuer import PermitIssueError, PermitIssuer

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
_STORE = SqliteEventStore()
crypto_engine = CryptoEngine()
permit_issuer = PermitIssuer.from_environment(crypto_engine)
if _PROVIDER_MODE in ("keygen", "real", "http_keygen", "production", "compose"):
    keygen_provider = HttpKeygenProvider(
        base_url=os.environ.get("KEYGEN_BASE_URL", ""),
        account_id=os.environ.get("KEYGEN_ACCOUNT_ID", ""),
        token=os.environ.get("KEYGEN_TOKEN", ""),
        crypto_engine=crypto_engine,
        event_store=_STORE,
    )
else:
    keygen_provider = InMemoryKeygenProvider(crypto_engine=crypto_engine, event_store=_STORE)
keygate_provider = InMemoryKeygateProvider(crypto_engine=crypto_engine)
billing_processor = BillingEventProcessor(license_provider=keygen_provider, event_store=_STORE)

# Server-enforced trial duration policy (3 days default per server policy)
_TRIAL_DAYS = int(os.environ.get("DEFAULT_TRIAL_DAYS", "3"))
_ADMIN_USER = os.environ.get("SUBSCRIPTION_ADMIN_USER", "admin")
_ADMIN_PASSWORD = os.environ.get("SUBSCRIPTION_ADMIN_PASSWORD", "")

class PermitRequest(BaseModel):
    source_sha: str
    release_manifest_sha256: str
    release_channel: str
    mode_id: str


class ValidateRequest(BaseModel):
    license_key: str
    hardware: Optional[HardwareFingerprint] = None
    permit_request: Optional[PermitRequest] = None


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


def _admin_authorized(request: Request) -> bool:
    """Local operator page only; the subscription client never receives this secret."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic ") or not _ADMIN_PASSWORD:
        return False
    try:
        user, password = base64.b64decode(auth[6:]).decode("utf-8").split(":", 1)
    except Exception:
        return False
    return secrets.compare_digest(user, _ADMIN_USER) and secrets.compare_digest(password, _ADMIN_PASSWORD)


def _require_admin(request: Request) -> None:
    if not _admin_authorized(request):
        raise HTTPException(
            status_code=401,
            detail="Subscription admin login required",
            headers={"WWW-Authenticate": 'Basic realm="ShuaBao Subscription"'},
        )


def _license_row(dto: LicenseDTO) -> str:
    expiry = dto.expires_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if dto.expires_at else "无到期日"
    key = html.escape(dto.license_key)
    ident = html.escape(dto.license_id)
    owner = html.escape(dto.customer_email or dto.customer_id)
    return f"""<tr><td>{key}</td><td>{html.escape(dto.status.value)}</td><td>{expiry}</td><td>{owner}</td><td>
<form method='post' action='/admin/licenses/{ident}/extend'><input name='days' type='number' value='1' min='1' max='365'><button>延期</button></form>
<form method='post' action='/admin/licenses/{ident}/expiry'><input name='expires_at' value='{dto.expires_at.isoformat() if dto.expires_at else ''}' placeholder='2026-09-01T00:00:00+00:00'><button>设到期日</button></form>
<form method='post' action='/admin/licenses/{ident}/revoke'><button class='danger'>吊销</button></form></td></tr>"""


async def _form_values(request: Request) -> dict[str, str]:
    body = (await request.body()).decode("utf-8")
    return {key: values[-1].strip() for key, values in parse_qs(body).items() if values}


def _admin_error(message: str) -> RedirectResponse:
    return RedirectResponse(f"/admin?message={quote(message)}", status_code=303)


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


@app.get("/admin", response_class=HTMLResponse)
async def subscription_admin(request: Request, message: str = ""):
    """Small local-only operator page for manual test licenses."""
    _require_admin(request)
    list_licenses = getattr(keygen_provider, "list_licenses", None)
    if not callable(list_licenses):
        raise HTTPException(status_code=503, detail="Admin page requires the HTTP Keygen provider")
    try:
        licenses = await list_licenses()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"License provider unavailable: {type(exc).__name__}") from exc
    rows = "".join(_license_row(dto) for dto in licenses)
    notice = f"<p class='notice'>{html.escape(message)}</p>" if message else ""
    return f"""<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'><title>刷刷宝订阅管理</title>
<style>body{{font:15px system-ui;margin:32px;color:#1f2937}}main{{max-width:1180px;margin:auto}}form{{display:inline-block;margin:3px}}input{{padding:6px;margin:2px}}button{{padding:6px 10px;cursor:pointer}}.danger{{color:#a00}}table{{width:100%;border-collapse:collapse;margin-top:20px}}td,th{{border-bottom:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}}.notice{{padding:8px;background:#ecfdf5}}</style></head><body><main>
<h1>刷刷宝订阅管理</h1><p>本页只绑定 <code>127.0.0.1</code>。创建后复制密钥，在刷刷宝看板点击“激活密钥”填入。</p>{notice}
<h2>创建测试密钥</h2><form method='post' action='/admin/licenses'><label>测试标识 <input name='customer_id' value='manual-test'></label><label>邮箱 <input name='email' value='test@example.invalid'></label><label>有效天数 <input name='days' type='number' value='1' min='1' max='365'></label><button>生成密钥</button></form>
<h2>已有密钥</h2><table><thead><tr><th>密钥</th><th>状态</th><th>到期时间</th><th>归属</th><th>管理</th></tr></thead><tbody>{rows or '<tr><td colspan=5>暂无密钥</td></tr>'}</tbody></table>
</main></body></html>"""


@app.post("/admin/licenses")
async def admin_create_license(request: Request):
    _require_admin(request)
    values = await _form_values(request)
    try:
        days = max(1, min(int(values.get("days") or "1"), 365))
    except ValueError:
        return _admin_error("有效天数必须是 1 到 365 的整数")
    try:
        dto = await keygen_provider.create_license(
            values.get("customer_id") or "manual-test",
            values.get("email") or "test@example.invalid",
            "pro_monthly",
            duration_days=days,
            device_limit=1,
            features=["core", "automation"],
            metadata={"issued_by": "local_admin"},
        )
    except Exception as exc:
        return _admin_error(f"创建失败：{type(exc).__name__}")
    return _admin_error(f"已创建测试密钥，到期日：{dto.expires_at.isoformat() if dto.expires_at else '未返回'}；请到刷刷宝看板激活设备")


@app.post("/admin/licenses/{license_id}/extend")
async def admin_extend_license(license_id: str, request: Request):
    _require_admin(request)
    values = await _form_values(request)
    try:
        days = max(1, min(int(values.get("days") or "1"), 365))
        dto = await keygen_provider.extend_license(license_id, extend_days=days)
    except Exception as exc:
        return _admin_error(f"延期失败：{type(exc).__name__}")
    return _admin_error(f"已延期，到期日：{dto.expires_at.isoformat() if dto.expires_at else '未返回'}")


@app.post("/admin/licenses/{license_id}/expiry")
async def admin_set_license_expiry(license_id: str, request: Request):
    _require_admin(request)
    values = await _form_values(request)
    try:
        expires_at = datetime.fromisoformat(values.get("expires_at", "").replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            raise ValueError("past expiry")
        dto = await keygen_provider.set_license_expiry(license_id, expires_at)
    except Exception:
        return _admin_error("到期日必须是未来的 ISO 时间，例如 2026-09-01T00:00:00+00:00")
    return _admin_error(f"已设置到期日：{dto.expires_at.isoformat() if dto.expires_at else '未返回'}")


@app.post("/admin/licenses/{license_id}/revoke")
async def admin_revoke_license(license_id: str, request: Request):
    _require_admin(request)
    try:
        await keygen_provider.revoke_license(license_id, reason="local_admin")
    except Exception as exc:
        return _admin_error(f"吊销失败：{type(exc).__name__}")
    return _admin_error("密钥已吊销")


@app.post("/v1/entitlements/validate", response_model=EntitlementValidationResult)
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
