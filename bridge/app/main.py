"""
ShuaBao Entitlement Bridge REST API Server.
Unified interface for client validation, device activation, trial claim, offline entitlement,
and billing webhook ingestion.
"""
import base64
import json
import html
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, quote
from typing import Any, Optional
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ValidationError
from contracts.entitlement import (
    DeviceActivationDTO,
    EntitlementValidationResult,
    HardwareFingerprint,
    LicenseDTO,
    LicenseStatus,
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
from bridge.app.services.permit_issuer import (
    PermitIssueError,
    PermitIssuer,
    RELEASE_CHANNELS,
    not_approved_status_payload,
    parse_allowed_modes,
    validate_release_identity,
)
from bridge.app.services.trial_claim import (
    CODE_DISABLED,
    CODE_INVALID_REQUEST,
    CODE_RATE_LIMITED,
    TrialClaimError,
    TrialRateLimits,
    client_ip_key,
    normalize_fingerprint,
    trial_duration_hours,
    trials_enabled,
    validate_hardware_extras,
)
from bridge.app.services import tiers as _tiers
from bridge.app.services import referral as _referral
from bridge.app.services.release_distribution import (
    ReleaseDistributionError,
    ReleaseStore,
    public_base_from_env,
    releases_root_from_env,
)

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


def _check_provider_capabilities(provider) -> None:
    if isinstance(provider, HttpKeygenProvider):
        logging.getLogger("shuabao.main").warning(
            "HTTP_KEYGEN_CAPABILITY_LIMIT: online run leases (/v1/run/*), admin license issuance "
            "and PiP grants are unsupported; use the local SQLite authority for these operations"
        )

# Global singleton providers
_STORE = SqliteEventStore()
crypto_engine = CryptoEngine()
permit_issuer = PermitIssuer.from_environment(crypto_engine, policy_store=_STORE)
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
_check_provider_capabilities(keygen_provider)
keygate_provider = InMemoryKeygateProvider(crypto_engine=crypto_engine)
billing_processor = BillingEventProcessor(license_provider=keygen_provider, event_store=_STORE)

# Self-service device trial rate limits (in-process; single uvicorn worker).
_TRIAL_RATE_LIMITS = TrialRateLimits()
_ADMIN_USER = os.environ.get("SUBSCRIPTION_ADMIN_USER") or "admin"
# Fail-closed: no default password. Missing/empty disables admin endpoints.
_ADMIN_PASSWORD = (os.environ.get("SUBSCRIPTION_ADMIN_PASSWORD") or "").strip()
# Conservative provider-status → admin-filter mapping (GRACE/TRIAL count as active).
_ADMIN_STATUS_FILTERS = ("UNACTIVATED", "ACTIVE", "EXPIRED", "REVOKED")
_ACTIVE_LIKE_STATUSES = {LicenseStatus.ACTIVE, LicenseStatus.TRIAL, LicenseStatus.GRACE}
_ADMIN_OPERATION_ERRORS = {
    "ENTITLEMENT_TRANSACTION_UNSUPPORTED": "当前 Provider 不支持管理发卡或 PiP 授权，请使用本地 SQLite 授权服务",
    "OPERATION_ID_CONFLICT": "操作编号已用于其他请求，请核对原请求或使用新的操作编号",
    "INVALID_OPERATION_ID": "操作编号必须是字符串，留空时由服务端生成",
    "OPERATION_RESULT_UNAVAILABLE": "原操作对应的密钥记录不存在，无法重放结果",
}


def _admin_operation_message(code: str) -> str:
    return f"{code}：{_ADMIN_OPERATION_ERRORS[code]}"

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


class RunAcquireRequest(BaseModel):
    license_key: str
    fingerprint: str
    ttl_seconds: int = 300
    scope: str = "core"


class RunHeartbeatRequest(BaseModel):
    lease_id: str
    fingerprint: str
    ttl_seconds: int = 300


class RunReleaseRequest(BaseModel):
    lease_id: str
    fingerprint: str


class TrialClaimRequest(BaseModel):
    # Same hardware shape as /v1/devices/activate; duration/plan are never client-supplied.
    hardware: HardwareFingerprint


class OfflineIssueRequest(BaseModel):
    license_key: str
    hardware: HardwareFingerprint
    ttl_seconds: int = 48 * 3600  # ignored; server policy is always 48 hours


def _configured_admin_password() -> str:
    """Live read so tests can monkeypatch env; empty means admin is disabled."""
    return (os.environ.get("SUBSCRIPTION_ADMIN_PASSWORD") or "").strip()


def _configured_admin_user() -> str:
    return (os.environ.get("SUBSCRIPTION_ADMIN_USER") or _ADMIN_USER or "admin").strip() or "admin"


_ADMIN_FORWARD_HEADERS = ("x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded",
                          "x-real-ip", "cf-connecting-ip", "true-client-ip", "via")


def _admin_local(request: Request) -> bool:
    """r7 ruling 9: /admin/* only from a direct loopback peer (Caddy keeps /admin/* 404 publicly;
    anything that arrived through a proxy carries forwarding headers and is refused)."""
    host = request.client.host if request.client else ""
    return host in ("127.0.0.1", "::1") and not any(h in request.headers for h in _ADMIN_FORWARD_HEADERS)


def _configured_admin_token() -> str:
    tok = (os.environ.get("SUBSCRIPTION_ADMIN_TOKEN") or "").strip()
    return tok if len(tok) >= 32 else ""


def _admin_authorized(request: Request) -> bool:
    """Local operator page only; the subscription client never receives this secret.
    r7: loopback required; X-Admin-Token (SUBSCRIPTION_ADMIN_TOKEN, >=32 chars) is the primary
    credential; HTTP Basic is still accepted for the HTML console over the SSH tunnel."""
    if not _admin_local(request):
        return False
    token = _configured_admin_token()
    supplied = request.headers.get("X-Admin-Token") or ""
    if token:
        # r7.1 Owner Q4 (13:27): once SUBSCRIPTION_ADMIN_TOKEN is configured, admin is local + token ONLY
        # (HTTP Basic no longer accepted). Basic remains only as the pre-token legacy path.
        return bool(supplied) and secrets.compare_digest(supplied.encode("utf-8"), token.encode("utf-8"))
    password = _configured_admin_password()
    if not password:
        return False
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return False
    try:
        user, provided = base64.b64decode(auth[6:]).decode("utf-8").split(":", 1)
    except Exception:
        return False
    return secrets.compare_digest(user, _configured_admin_user()) and secrets.compare_digest(
        provided, password
    )


def _require_admin(request: Request) -> None:
    if not _admin_local(request):
        raise HTTPException(status_code=404, detail="Not Found")
    if not _configured_admin_password() and not _configured_admin_token():
        raise HTTPException(
            status_code=503,
            detail="Subscription admin disabled: SUBSCRIPTION_ADMIN_PASSWORD is not configured",
        )
    if not _admin_authorized(request):
        raise HTTPException(
            status_code=401,
            detail="Subscription admin login required",
            headers={"WWW-Authenticate": 'Basic realm="ShuaBao Subscription"'},
        )


def _effective_license_status(dto: LicenseDTO) -> LicenseStatus:
    """Use the expiry timestamp to avoid displaying stale provider status."""
    status = dto.status
    expires_at = dto.expires_at
    if status != LicenseStatus.REVOKED and expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            return LicenseStatus.EXPIRED
    return status


def _license_matches_filter(
    dto: LicenseDTO, devices: list, status_filter: str, devices_error: str = ""
) -> bool:
    """Conservative admin status filtering; unknown values show everything."""
    effective_status = _effective_license_status(dto)
    if not status_filter:
        return True
    if status_filter == "UNACTIVATED":
        return not devices_error and not devices and effective_status != LicenseStatus.REVOKED
    if status_filter == "ACTIVE":
        return effective_status in _ACTIVE_LIKE_STATUSES
    if status_filter == "EXPIRED":
        return effective_status == LicenseStatus.EXPIRED
    if status_filter == "REVOKED":
        return effective_status == LicenseStatus.REVOKED
    return True


async def _license_row(dto: LicenseDTO, devices: list, devices_error: str = "") -> str:
    expiry = html.escape(dto.expires_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")) if dto.expires_at else "无到期日"
    key = html.escape(dto.license_key)
    ident = html.escape(dto.license_id)
    owner = html.escape(dto.customer_email or dto.customer_id)
    status = html.escape(_effective_license_status(dto).value)
    limit = html.escape(str(dto.device_limit))
    if devices_error:
        device_cell = f"<span class='warn'>{html.escape(devices_error)}</span>"
    elif devices:
        dev_rows = "".join(
            f"<li>{html.escape(d.name or d.fingerprint)} "
            f"<form method='post' action='/admin/licenses/{ident}/unbind'><input type='hidden' name='fingerprint' value='{html.escape(d.fingerprint)}'><button class='danger'>解绑</button></form></li>"
            for d in devices
        )
        device_cell = f"{len(devices)} / {limit}<ul class='devices'>{dev_rows}</ul>"
    else:
        device_cell = f"0 / {limit}"
    expiry_input = html.escape(dto.expires_at.isoformat()) if dto.expires_at else ""
    pip_checked = " checked" if "pip_background" in dto.features else ""
    entitlement_record = {"plan": dto.plan, "metadata": dto.metadata}
    pip_locked = _tiers.has_default_pip_background(entitlement_record)
    pip_disabled = " disabled" if pip_locked else ""
    pip_confirmation = "" if pip_locked else "<label><input type='checkbox' name='confirm_pip' value='1'>确认权限变更</label>"
    return f"""<tr><td><code class='key' data-key='{key}'>{key}</code> <button type='button' class='copy' data-key='{key}' onclick='copyKey(this)'>复制</button></td><td>{status}</td><td>{expiry}</td><td>{owner}</td><td>{device_cell}</td><td>
<form method='post' action='/admin/licenses/{ident}/extend'><input name='days' type='number' value='1' min='1' max='365'><button>延期</button></form>
<form method='post' action='/admin/licenses/{ident}/expiry'><input name='expires_at' value='{expiry_input}' placeholder='2026-09-01T00:00:00+00:00'><button>设到期日</button></form>
<form method='post' action='/admin/licenses/{ident}/device-limit'><input name='device_limit' type='number' value='{limit}' min='1' max='10' title='device_limit'><button>set-limit</button></form>
<form method='post' action='/admin/licenses/{ident}/pip-background'><input type='hidden' name='operation_id' value='{secrets.token_hex(16)}'><input type='hidden' name='pip_background' value='0'><label><input type='checkbox' name='pip_background' value='1'{pip_checked}{pip_disabled}>含画中画</label>{pip_confirmation}<button>更新</button></form>
<form method='post' action='/admin/licenses/{ident}/revoke'><button class='danger'>吊销</button></form></td></tr>"""


async def _form_values(request: Request) -> dict[str, str]:
    body = (await request.body()).decode("utf-8")
    return {key: values[-1].strip() for key, values in parse_qs(body).items() if values}


def _admin_error(message: str) -> RedirectResponse:
    return RedirectResponse(f"/admin?message={quote(message)}", status_code=303)

def _safe_service_revision() -> str | None:
    """Optional public deploy marker from env; never paths/secrets."""
    raw = (
        os.environ.get("SHUABAO_SERVICE_REVISION")
        or os.environ.get("SHUABAO_DEPLOYMENT_ID")
        or ""
    ).strip()
    if not raw or len(raw) > 128:
        return None
    # Allow digest-like tokens (hex, semver, git-describe); reject paths/whitespace.
    if raw.startswith("/") or ".." in raw or "\\" in raw or any(ch.isspace() for ch in raw):
        return None
    if not all(ch.isalnum() or ch in "._-+" for ch in raw):
        return None
    return raw


@app.get("/health")
def health_check():
    provider_name = "http_keygen" if isinstance(keygen_provider, HttpKeygenProvider) else "inmemory_keygen"
    payload = {
        "status": "healthy",
        "service": "shuashuabao-entitlement-bridge",
        "provider_mode": _PROVIDER_MODE,
        "active_provider": provider_name,
        "shadow_provider": "keygate",
    }
    revision = _safe_service_revision()
    if revision:
        payload["service_revision"] = revision
    return payload


@app.get("/admin", response_class=HTMLResponse)
async def subscription_admin(request: Request, message: str = "", status: str = ""):
    """Small local-only operator page for manual test licenses."""
    _require_admin(request)
    status_filter = status.upper() if status else ""
    if status_filter not in _ADMIN_STATUS_FILTERS:
        status_filter = ""

    list_licenses = getattr(keygen_provider, "list_licenses", None)
    list_error = ""
    licenses = []
    if not callable(list_licenses):
        list_error = "当前 Provider 不支持密钥列表查询"
    else:
        try:
            licenses = await list_licenses()
        except Exception as exc:
            list_error = f"密钥列表查询失败：{html.escape(type(exc).__name__)}"

    get_devices = getattr(keygen_provider, "get_devices", None)
    rows = ""
    for dto in licenses:
        devices, devices_error = [], ""
        if callable(get_devices):
            try:
                devices = await get_devices(dto.license_id)
            except Exception as exc:
                devices_error = f"设备查询失败：{html.escape(type(exc).__name__)}"
        else:
            devices_error = "当前 Provider 不支持设备查询"
        if not _license_matches_filter(dto, devices, status_filter, devices_error):
            continue
        rows += await _license_row(dto, devices, devices_error)

    notice = f"<p class='notice'>{html.escape(message)}</p>" if message else ""
    list_error_html = f"<p class='error'>{list_error}</p>" if list_error else ""
    if isinstance(keygen_provider, HttpKeygenProvider):
        list_error_html += "<p class='error'>HTTP Keygen 模式不支持在线租约、管理发卡和 PiP 授权。</p>"
    filter_options = "".join(
        f"<option value='{f}'{ ' selected' if status_filter == f else ''}>{f}</option>"
        for f in _ADMIN_STATUS_FILTERS
    )

    pip_defaults = json.dumps({tier: bool(config.get("pip_background", False)) for tier, config in _tiers.TIERS.items()})
    return f"""<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'><title>刷刷宝订阅管理</title>
<style>body{{font:15px system-ui;margin:32px;color:#1f2937}}main{{max-width:1180px;margin:auto}}form{{display:inline-block;margin:3px}}input{{padding:6px;margin:2px}}button{{padding:6px 10px;cursor:pointer}}.danger{{color:#a00}}table{{width:100%;border-collapse:collapse;margin-top:20px}}td,th{{border-bottom:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}}.notice,.error{{padding:8px;background:#ecfdf5}}.error{{background:#fef2f2}}.warn{{color:#92400e}}.key{{font-family:monospace;font-size:13px}}ul.devices{{margin:2px 0;padding-left:16px;font-size:13px}}ul.devices li{{margin:2px 0}}.copy{{padding:2px 6px;font-size:12px}}</style>
<script>var pipDefaults={pip_defaults};function setPipDefault(){{var tier=document.querySelector("select[name='tier']").value;var included=!!pipDefaults[tier];var option=document.getElementById('pip-background-option');option.checked=included;option.disabled=included;document.getElementById('confirm-pip-label').hidden=included;}}function copyKey(btn){{var v=btn.dataset.key;navigator.clipboard.writeText(v).then(function(){{btn.textContent='已复制';setTimeout(function(){{btn.textContent='复制'}},1500);}}).catch(function(){{}});}}</script></head><body><main>
<h1>刷刷宝订阅管理</h1><p>本页只绑定 <code>127.0.0.1</code>。创建后复制密钥，在刷刷宝看板点击“激活密钥”填入。 <a href='/admin/releases'>发布策略</a></p>{notice}{list_error_html}
<h2>创建测试密钥</h2><form method='post' action='/admin/licenses'><input type='hidden' name='operation_id' value='{secrets.token_hex(16)}'><label>测试标识 <input name='customer_id' value='manual-test'></label><label>邮箱 <input name='email' value='test@example.invalid'></label><label>档位 <select name='tier' onchange='setPipDefault()'><option value='test'>内测用户 (test)</option><option value='go'>Go 订阅 (1 天)</option><option value='plus'>Plus 订阅 · 天卡 (1 天)</option><option value='pro'>Pro 订阅 · 周卡 (7 天)</option><option value='max'>Max 订阅 · 月卡 (30 天)</option><option value='ultra'>Ultra 永久用户</option></select></label><label>有效天数(仅内测) <input name='days' type='number' value='1' min='1' max='365'></label><label>设备上限 <input name='device_limit' type='number' value='3' min='1' max='10'></label><label><input name='starts_on_first_activation' type='checkbox' value='1' checked> 首次激活起算</label><input type='hidden' name='pip_background' value='0'><label><input id='pip-background-option' name='pip_background' type='checkbox' value='1'> 含画中画</label><label id='confirm-pip-label'><input name='confirm_pip' type='checkbox' value='1'> 确认画中画授权（写审计日志）</label><label><input name='confirm_ultra' type='checkbox' value='1'> 确认签发 Ultra（写审计日志）</label><button>生成密钥</button></form>
<script>setPipDefault();</script><h2>已有密钥</h2><form method='get' action='/admin' style='display:inline-block;margin-bottom:8px'><label>状态 <select name='status'><option value=''>全部</option>{filter_options}</select></label><button>筛选</button></form>
<table><thead><tr><th>密钥</th><th>状态</th><th>到期时间</th><th>归属</th><th>设备</th><th>管理</th></tr></thead><tbody>{rows or '<tr><td colspan=6>暂无密钥</td></tr>'}</tbody></table>
</main></body></html>"""


def _truthy(v) -> bool:
    return v is True or str(v if v is not None else "").strip().lower() in ("1", "true", "on", "yes")


def _batch_c_card_spec(values: dict, *, form: bool = False) -> dict:
    """BATCH C + r7: caller chooses the tier (or a canonical/alias ``plan``). Formal tiers have a
    fixed duration; only tier=test takes ``days``. Raises ValueError with a CODE: prefix.
    r7 ruling 3: go/plus/pro default starts_on_first_activation=True (JSON: when the field is
    absent; form: checkbox pre-checked); explicit ``expires_at`` overrides.
    r7 ruling 4: ultra requires confirm_ultra=true."""
    req_plan = str(values.get("plan") or "").strip().lower()
    plan_tier = _tiers.tier_from_plan_input(req_plan) if req_plan else None
    if req_plan and plan_tier is None:
        raise ValueError(f"INVALID_PLAN: plan must be one of {', '.join(sorted(set(_tiers.CANONICAL_PLANS.values()) | set(_tiers.PLAN_ALIASES)))}")
    tier = str(values.get("tier") or plan_tier or "test").strip().lower()
    if tier == "trial":
        tier = "test"
    if tier == "beta":   # r7.1: the 内测用户 label is historical only (cutover snapshot), never issued
        raise ValueError("INVALID_TIER: beta is assigned only by the cutover snapshot; issue tier=test (shown as 试用)")
    if not _tiers.is_tier(tier):
        raise ValueError(f"INVALID_TIER: tier must be one of {', '.join(_tiers.TIER_ORDER)}")
    if plan_tier and plan_tier != tier:
        raise ValueError("INVALID_PLAN: plan does not match tier")
    try:
        device_limit = max(1, min(int(values.get("device_limit") or "1"), 10))
    except (TypeError, ValueError):
        raise ValueError("INVALID_DEVICE_LIMIT: device_limit must be an integer 1-10")
    raw_first = values.get("starts_on_first_activation")
    if raw_first is None and not form and tier in ("go", "plus", "pro", "max"):
        starts_on_first = True
    else:
        starts_on_first = _truthy(raw_first)
    starts_on_first = starts_on_first and tier != "ultra"
    expires_override = None
    raw_exp = str(values.get("expires_at") or "").strip()
    if raw_exp:
        if tier == "ultra":
            raise ValueError("INVALID_EXPIRES_AT: ultra expiry is fixed at 2099-12-31T23:59:59+00:00")
        try:
            expires_override = datetime.fromisoformat(raw_exp.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("INVALID_EXPIRES_AT: expires_at must be ISO-8601 with timezone")
        if expires_override.tzinfo is None:
            raise ValueError("INVALID_EXPIRES_AT: expires_at must include a timezone offset")
        if expires_override <= datetime.now(timezone.utc):
            raise ValueError("INVALID_EXPIRES_AT: expires_at must be in the future")
        starts_on_first = False
    pip_background = bool(_tiers.TIERS[tier].get("pip_background", False)) or _truthy(values.get("pip_background"))
    if pip_background and not _tiers.TIERS[tier].get("pip_background", False) and not _truthy(values.get("confirm_pip")):
        raise ValueError("PIP_CONFIRM_REQUIRED: granting pip_background requires confirm_pip=true")
    if tier == "ultra" and not _truthy(values.get("confirm_ultra")):
        raise ValueError("ULTRA_CONFIRM_REQUIRED: issuing an Ultra (lifetime) card requires confirm_ultra=true")
    if tier == "test":
        try:
            days = max(1, min(int(values.get("days") or "1"), 365))
        except (TypeError, ValueError):
            raise ValueError("INVALID_DAYS: days must be an integer 1-365")
    elif tier == "ultra":
        days = 0
    else:
        days = int(_tiers.TIERS[tier]["duration_days"])
    plan = _tiers.canonical_plan(req_plan) if (req_plan and tier != "test") else _tiers.plan_for(tier, days, starts_on_first)
    metadata: dict = {"issued_by": "local_admin", "tier": tier}
    if starts_on_first:
        metadata["starts_on_first_activation"] = True
        metadata["activation_ttl_days"] = days
    return {"tier": tier, "plan": plan, "days": days, "device_limit": device_limit,
            "pip_background": pip_background,
            "starts_on_first": starts_on_first, "metadata": metadata, "expires_override": expires_override}


def _mask_key(v: str) -> str:
    v = str(v or "")
    return v if len(v) <= 8 else f"{v[:4]}…{v[-4:]}"


async def _batch_c_issue(values: dict, issued_by: str, *, form: bool = False, request: Optional[Request] = None) -> LicenseDTO:
    if not isinstance(keygen_provider, InMemoryKeygenProvider):
        raise ValueError("ENTITLEMENT_TRANSACTION_UNSUPPORTED: admin issuance requires the local SQLite authority")
    spec = _batch_c_card_spec(values, form=form)
    spec["metadata"]["issued_by"] = issued_by
    if spec["tier"] == "ultra":
        spec["metadata"]["ultra_confirmed"] = True
    dto = await keygen_provider.create_license(
        values.get("customer_id") or "manual-test",
        values.get("email") or "test@example.invalid",
        spec["plan"],
        duration_days=spec["days"],
        device_limit=spec["device_limit"],
        features=["core", "automation"] + (["pip_background"] if spec["pip_background"] else []),
        metadata=spec["metadata"],
        tier=spec["tier"],
        operation_id=values.get("operation_id"),
        audit={"client": (request.client.host if request is not None and request.client else None)},
        **({"expires_at_override": spec["expires_override"]} if spec["expires_override"] else {}),
    )
    return dto


@app.post("/admin/licenses")
async def admin_create_license(request: Request):
    _require_admin(request)
    values = await _form_values(request)
    try:
        dto = await _batch_c_issue(values, "local_admin", form=True, request=request)
    except ValueError as exc:
        code = str(exc).split(":", 1)[0]
        if code in _ADMIN_OPERATION_ERRORS:
            return _admin_error(_admin_operation_message(code))
        return _admin_error({"PIP_CONFIRM_REQUIRED": "授权画中画需要勾选确认并写入审计日志",
                             "INVALID_DAYS": "有效天数必须是 1 到 365 的整数",
                             "INVALID_DEVICE_LIMIT": "设备上限必须是 1 到 10 的整数",
                             "INVALID_TIER": "档位必须是 go/plus/pro/ultra/test 之一",
                             "INVALID_PLAN": "plan 不在允许列表",
                             "INVALID_EXPIRES_AT": "到期时间格式错误或已过期",
                             "ULTRA_CONFIRM_REQUIRED": "签发 Ultra 永久卡需要勾选“确认签发 Ultra”"}.get(code, "创建失败"))
    except Exception as exc:
        return _admin_error(f"创建失败：{type(exc).__name__}")
    if dto.expires_at is None:
        ttl = (dto.metadata or {}).get("activation_ttl_days")
        return _admin_error(f"已创建{dto.tier_name}密钥，首次激活起算 {ttl} 天；请到刷刷宝看板激活设备")
    return _admin_error(f"已创建{dto.tier_name}密钥，到期日：{dto.expires_at.isoformat()}；请到刷刷宝看板激活设备")


@app.post("/admin/licenses/create-test")
async def admin_create_test_license_json(request: Request):
    """BATCH C JSON issuance: {tier, days?, device_limit?, starts_on_first_activation?,
    customer_id?, email?}. Admin auth required (same as /admin)."""
    _require_admin(request)
    try:
        values = await request.json()
        if not isinstance(values, dict):
            raise ValueError
    except Exception:
        raise HTTPException(status_code=400, detail="INVALID_REQUEST: JSON object body required")
    try:
        dto = await _batch_c_issue(values, str(values.get("issued_by") or "admin_api")[:64], request=request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, "license_id": dto.license_id, "license_key": dto.license_key,
            "plan": dto.plan, "tier": dto.tier, "tier_name": dto.tier_name, "is_beta_user": dto.is_beta_user,
            "expires_at": dto.expires_at, "device_limit": dto.device_limit,
            "starts_on_first_activation": bool((dto.metadata or {}).get("starts_on_first_activation")),
            "pip_background": dto.pip_background}


@app.post("/admin/licenses/{license_id}/pip-background")
async def admin_set_pip_background(license_id: str, request: Request):
    _require_admin(request)
    values = await _form_values(request)
    try:
        if not isinstance(keygen_provider, InMemoryKeygenProvider):
            raise ValueError("ENTITLEMENT_TRANSACTION_UNSUPPORTED")
        dto = await keygen_provider.get_license(license_id)
        if not dto:
            return _admin_error("密钥不存在")
        enabled = _truthy(values.get("pip_background"))
        entitlement_record = {"plan": dto.plan, "metadata": dto.metadata}
        pip_locked = _tiers.has_default_pip_background(entitlement_record)
        if pip_locked and not enabled:
            return _admin_error("内测卡默认包含画中画，不能取消")
        if _tiers.is_regular_trial_record(entitlement_record) and enabled:
            return _admin_error("普通试用卡不能授权画中画")
        if not _truthy(values.get("confirm_pip")):
            return _admin_error("画中画授权变更需要勾选确认并写入审计日志")
        features = [feature for feature in dto.features if feature != "pip_background"]
        if enabled:
            features.append("pip_background")
        await keygen_provider.set_license_features(
            license_id, features, operation_id=values.get("operation_id"),
            audit={"action": "update_pip_background", "license_key_masked": _mask_key(dto.license_key),
                   "enabled": enabled, "plan": dto.plan, "tier": dto.tier,
                   "client": (request.client.host if request.client else None)},
        )
    except ValueError as exc:
        code = str(exc).split(":", 1)[0]
        return _admin_error(_admin_operation_message(code) if code in _ADMIN_OPERATION_ERRORS
                            else f"画中画授权更新失败：{type(exc).__name__}")
    except Exception as exc:
        return _admin_error(f"画中画授权更新失败：{type(exc).__name__}")
    return _admin_error(f"画中画授权已{'开启' if enabled else '关闭'}")


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
    except (TypeError, ValueError):
        return _admin_error("到期日必须是未来的 ISO 时间，例如 2026-09-01T00:00:00+00:00")
    try:
        dto = await keygen_provider.set_license_expiry(license_id, expires_at)
    except Exception as exc:
        return _admin_error(f"设置到期日失败：{type(exc).__name__}")
    return _admin_error(f"已设置到期日：{dto.expires_at.isoformat() if dto.expires_at else '未返回'}")


@app.post("/admin/licenses/{license_id}/revoke")
async def admin_revoke_license(license_id: str, request: Request):
    _require_admin(request)
    try:
        await keygen_provider.revoke_license(license_id, reason="local_admin")
    except Exception as exc:
        return _admin_error(f"吊销失败：{type(exc).__name__}")
    return _admin_error("密钥已吊销")


@app.post("/admin/licenses/{license_id}/unbind")
async def admin_unbind_device(license_id: str, request: Request):
    _require_admin(request)
    values = await _form_values(request)
    fingerprint = values.get("fingerprint", "")
    if not fingerprint:
        return _admin_error("缺少设备指纹")
    try:
        dto = await keygen_provider.get_license(license_id)
        if not dto:
            return _admin_error("密钥不存在")
        ok = await keygen_provider.deactivate_device(dto.license_key, fingerprint)
    except Exception as exc:
        return _admin_error(f"解绑失败：{type(exc).__name__}")


@app.post("/admin/licenses/{license_id}/device-limit")
async def admin_set_device_limit(license_id: str, request: Request):
    _require_admin(request)
    values = await _form_values(request)
    try:
        device_limit = max(1, min(int(values.get("device_limit") or "1"), 10))
    except ValueError:
        return _admin_error("device_limit must be int 1..10")
    try:
        dto = await keygen_provider.set_device_limit(license_id, device_limit=device_limit)
    except Exception as exc:
        return _admin_error(f"set device_limit failed: {type(exc).__name__}")
    return _admin_error(f"device_limit updated to {dto.device_limit} (running scripts not affected)")

    return _admin_error("设备已解绑" if ok else "未找到该设备")


def _attach_release_status(result: EntitlementValidationResult, context: PermitRequest) -> None:
    """Advisory/status belong on the validation envelope, never inside the signed permit."""
    result.release_status = permit_issuer.status_payload_for(
        context.source_sha,
        context.release_manifest_sha256,
        context.release_channel,
        public=True,
    )


def _parse_blocked(value: object) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "true", "on", "yes", "blocked"}


def _normalize_advisory(value: object) -> str | None:
    text = str(value or "").strip().lower()
    if text in {"", "none", "null", "empty"}:
        return None
    if text not in {"recommended", "outdated"}:
        raise ValueError("advisory must be recommended, outdated, or empty")
    return text


def _upsert_release_policy_from_values(values: dict, updated_by: str) -> dict:
    try:
        source_sha, manifest, channel = validate_release_identity(
            values.get("source_sha", ""),
            values.get("release_manifest_sha256", ""),
            values.get("release_channel", ""),
        )
        allowed_modes = parse_allowed_modes(values.get("allowed_modes"))
        blocked = _parse_blocked(values.get("blocked"))
        advisory = _normalize_advisory(values.get("advisory"))
        if not allowed_modes and not blocked:
            raise ValueError("allowed_modes required unless blocked")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    rec_src = str(values.get("recommended_source_sha") or "").strip().lower() or None
    rec_man = str(values.get("recommended_manifest_sha256") or "").strip().lower() or None
    rec_ch = str(values.get("recommended_channel") or "").strip() or None
    if rec_src or rec_man or rec_ch:
        try:
            rec_src, rec_man, rec_ch = validate_release_identity(
                rec_src or "", rec_man or "", rec_ch or ""
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"recommended identity invalid: {exc}") from exc
    operator_note = str(values.get("operator_note") or "").strip() or None
    _STORE.upsert_release_policy(
        source_sha=source_sha,
        release_manifest_sha256=manifest,
        release_channel=channel,
        allowed_modes=allowed_modes,
        blocked=blocked,
        advisory=advisory,
        recommended_source_sha=rec_src,
        recommended_manifest_sha256=rec_man,
        recommended_channel=rec_ch,
        operator_note=operator_note,
        updated_by=updated_by,
    )
    policy = permit_issuer.resolve_policy(source_sha, manifest, channel)
    if policy is not None:
        return policy.status_payload()
    return not_approved_status_payload(source_sha, manifest, channel)


class ReleasePolicyUpsert(BaseModel):
    source_sha: str
    release_manifest_sha256: str
    release_channel: str
    allowed_modes: Any = None
    blocked: bool = False
    advisory: Optional[str] = None
    recommended_source_sha: Optional[str] = None
    recommended_manifest_sha256: Optional[str] = None
    recommended_channel: Optional[str] = None
    operator_note: Optional[str] = None


def _batch_a_secret_ok(value) -> bool:
    """BATCH A (A5): a public license id (or a hash marker) is never accepted as the card secret."""
    v = str(value or "").strip()
    return bool(v) and not v.startswith(("lic_", "h:"))


_BATCH_A_NOT_FOUND = "LICENSE_NOT_FOUND: license key not recognised"


def _batch_c_mirror(result: EntitlementValidationResult) -> None:
    """BATCH C: top-level plan/tier/tier_name for the client badge (#brandSubBadge)."""
    lic = result.license
    if lic is not None:
        result.plan = lic.plan
        result.tier = lic.tier
        result.tier_name = lic.tier_name
        result.is_beta_user = lic.is_beta_user
    else:  # r7.1: no card -> 未开通
        result.tier, result.tier_name, result.is_beta_user = "none", "未开通", False


@app.post("/v1/entitlements/validate", response_model=EntitlementValidationResult)
async def validate_entitlement(req: ValidateRequest):
    if not _batch_a_secret_ok(req.license_key):
        return EntitlementValidationResult(valid=False, status=LicenseStatus.EXPIRED, can_start_runner=False,
                                           code="NOT_FOUND", message="License key does not exist",
                                           tier="none", tier_name="未开通", is_beta_user=False)
    fp = req.hardware.fingerprint if req.hardware else None
    result = await keygen_provider.validate_license(req.license_key, fingerprint=fp)
    _batch_c_mirror(result)
    if req.permit_request is None or not result.valid or not result.can_start_runner:
        return result
    if (
        req.hardware is None
        or not req.hardware.fingerprint.strip()
        or result.license is None
    ):
        result.can_start_runner = False
        result.code = "PERMIT_CONTEXT_MISSING"
        result.message = "LIVE permit requires an activated device and license context"
        return result
    context = req.permit_request
    try:
        result.permit = permit_issuer.issue(
            license=result.license,
            hardware=req.hardware,
            source_sha=context.source_sha,
            release_manifest_sha256=context.release_manifest_sha256,
            release_channel=context.release_channel,
            mode_id=context.mode_id,
        )
        _attach_release_status(result, context)
    except PermitIssueError as exc:
        result.can_start_runner = False
        result.code = exc.code
        result.message = exc.message
        if exc.code in {"RELEASE_BLOCKED", "RELEASE_NOT_APPROVED", "MODE_NOT_ALLOWED"}:
            _attach_release_status(result, context)
    return result



def _release_store() -> ReleaseStore:
    """Distribution catalog. Separate from permit policy and not used to stream bundles."""
    root = releases_root_from_env()
    max_bytes = int(os.environ.get("SHUABAO_RELEASE_MAX_BUNDLE_BYTES") or "1073741824")
    return ReleaseStore(root=root, public_base=public_base_from_env(), max_bundle_bytes=max_bytes)


@app.get("/v1/releases/latest")
def get_latest_release(channel: str = "release"):
    """Public distribution metadata for the current channel bundle. Not a policy decision.

    FastAPI returns JSON only. Large zip bytes are served by the download edge (nginx),
    never streamed from this process.
    """
    requested = str(channel or "").strip()
    if requested not in RELEASE_CHANNELS:
        raise HTTPException(status_code=400, detail="invalid release channel")
    store = _release_store()
    try:
        payload = store.latest_public(requested)
    except ReleaseDistributionError as exc:
        if exc.code == "PUBLIC_BASE_MISSING":
            raise HTTPException(status_code=503, detail="release public base is not configured") from exc
        raise HTTPException(status_code=503, detail="release metadata is unavailable") from exc
    if payload is None:
        raise HTTPException(status_code=404, detail="no published release for channel")
    return payload


@app.get("/v1/releases/status")
def get_release_status(
    source_sha: str = "",
    release_manifest_sha256: str = "",
    release_channel: str = "",
):
    """Read-only release approval/blocked/advisory status. No remote-control payload."""
    try:
        source_sha, manifest, channel = validate_release_identity(
            source_sha, release_manifest_sha256, release_channel
        )
    except ValueError:
        return not_approved_status_payload(
            source_sha, release_manifest_sha256, release_channel, public=True
        )
    return permit_issuer.status_payload_for(source_sha, manifest, channel, public=True)


@app.get("/admin/releases", response_class=HTMLResponse)
async def admin_releases_page(request: Request, message: str = ""):
    _require_admin(request)
    rows_html = ""
    for row in _STORE.list_release_policies():
        modes = html.escape(", ".join(row.get("allowed_modes") or []))
        ident = (
            f"{html.escape(row['source_sha'])}<br>"
            f"{html.escape(row['release_manifest_sha256'])}<br>"
            f"{html.escape(row['release_channel'])}"
        )
        blocked = "yes" if row.get("blocked") else "no"
        advisory = html.escape(str(row.get("advisory") or ""))
        note = html.escape(str(row.get("operator_note") or ""))
        updated = html.escape(f"{row.get('updated_at') or ''} {row.get('updated_by') or ''}".strip())
        rec = ""
        if row.get("recommended_source_sha"):
            rec = (
                f"{html.escape(row.get('recommended_source_sha') or '')} / "
                f"{html.escape(row.get('recommended_channel') or '')}"
            )
        rows_html += (
            f"<tr><td><code>{ident}</code></td><td>{modes}</td><td>{blocked}</td>"
            f"<td>{advisory}</td><td>{rec}</td><td>{note}</td><td>{updated}</td></tr>"
        )
    notice = f"<p class='notice'>{html.escape(message)}</p>" if message else ""
    channels = "".join(f"<option value='{c}'>{c}</option>" for c in sorted(RELEASE_CHANNELS))
    return f"""<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'><title>刷刷宝发布策略</title>
<style>body{{font:15px system-ui;margin:32px;color:#1f2937}}main{{max-width:1180px;margin:auto}}form label{{display:block;margin:6px 0}}input,select,textarea{{padding:6px;min-width:280px}}button{{padding:6px 10px;cursor:pointer}}table{{width:100%;border-collapse:collapse;margin-top:20px}}td,th{{border-bottom:1px solid #ddd;padding:8px;text-align:left;vertical-align:top;font-size:13px}}code{{font-size:12px}}.notice{{padding:8px;background:#ecfdf5}}</style>
</head><body><main>
<h1>刷刷宝发布策略</h1>
<p><a href='/admin'>返回订阅管理</a>。本页只配置 exact release 批准 / 阻断 / advisory，不含热更新或远程控制载荷。</p>
{notice}
<h2>新增或更新策略</h2>
<form method='post' action='/admin/releases'>
<label>source_sha (40 hex) <input name='source_sha' required pattern='[0-9a-fA-F]{{40}}'></label>
<label>release_manifest_sha256 (64 hex) <input name='release_manifest_sha256' required pattern='[0-9a-fA-F]{{64}}'></label>
<label>release_channel <select name='release_channel'>{channels}</select></label>
<label>allowed_modes (comma) <input name='allowed_modes' placeholder='normal_farm,lobby_hitch'></label>
<label><input type='checkbox' name='blocked' value='true'> blocked（即使已批准也不签发新 permit）</label>
<label>advisory <select name='advisory'><option value=''>empty</option><option value='recommended'>recommended</option><option value='outdated'>outdated</option></select></label>
<label>recommended_source_sha <input name='recommended_source_sha'></label>
<label>recommended_manifest_sha256 <input name='recommended_manifest_sha256'></label>
<label>recommended_channel <select name='recommended_channel'><option value=''></option>{channels}</select></label>
<label>operator_note <input name='operator_note'></label>
<button>保存</button>
</form>
<h2>当前策略</h2>
<table><thead><tr><th>identity</th><th>modes</th><th>blocked</th><th>advisory</th><th>recommended</th><th>note</th><th>updated</th></tr></thead>
<tbody>{rows_html or '<tr><td colspan=7>暂无策略</td></tr>'}</tbody></table>
</main></body></html>"""


@app.post("/admin/releases")
async def admin_upsert_release(request: Request):
    _require_admin(request)
    values = await _form_values(request)
    try:
        payload = _upsert_release_policy_from_values(values, updated_by=_configured_admin_user())
    except HTTPException as exc:
        return _admin_releases_error(str(exc.detail))
    state = payload.get("status") or "updated"
    return RedirectResponse(f"/admin/releases?message={quote('已保存: ' + str(state))}", status_code=303)


def _admin_releases_error(message: str) -> RedirectResponse:
    return RedirectResponse(f"/admin/releases?message={quote(message)}", status_code=303)


@app.get("/v1/admin/releases")
async def admin_list_releases_json(request: Request):
    _require_admin(request)
    return {"policies": _STORE.list_release_policies()}


@app.put("/v1/admin/releases")
@app.post("/v1/admin/releases")
async def admin_upsert_release_json(req: ReleasePolicyUpsert, request: Request):
    _require_admin(request)
    values = req.model_dump()
    payload = _upsert_release_policy_from_values(values, updated_by=_configured_admin_user())
    return {"ok": True, "release_status": payload}

@app.get("/admin/backup/db")
async def download_backup_db(request: Request):
    _require_admin(request)
    import os
    from fastapi.responses import FileResponse
    # BATCH A (A4): raw DB download (plaintext card keys) disabled; 0 uses in prod access log.
    raise HTTPException(status_code=410, detail="Raw database download disabled (use an offline sanitized export)")


@app.post("/v1/devices/activate", response_model=DeviceActivationDTO)
async def activate_device(req: ActivateRequest):
    if not _batch_a_secret_ok(req.license_key):
        raise HTTPException(status_code=400, detail=_BATCH_A_NOT_FOUND)
    try:
        act = await keygen_provider.activate_device(req.license_key, req.hardware)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # BATCH C: identity of the bound license (read AFTER binding so a first-activation
    # clock start is reflected in expires_at).
    try:
        lic = await keygen_provider.get_license(act.license_id)
    except Exception:
        lic = None
    if lic is not None:
        act.plan, act.tier, act.tier_name, act.expires_at = lic.plan, lic.tier, lic.tier_name, lic.expires_at
        act.is_beta_user = lic.is_beta_user
    return act


@app.post("/v1/devices/deactivate")
async def deactivate_device(req: DeactivateRequest):
    if not _batch_a_secret_ok(req.license_key):
        return {"success": False}
    success = await keygen_provider.deactivate_device(req.license_key, req.fingerprint)
    return {"success": success}


@app.post("/v1/run/acquire")
async def run_acquire(req: RunAcquireRequest):
    """Exclusive run lease. Only called when the user starts the script (not on bind)."""
    _require_run_lease_support()
    if not _batch_a_secret_ok(req.license_key):
        raise HTTPException(status_code=400, detail=_BATCH_A_NOT_FOUND)
    try:
        return await keygen_provider.acquire_run_lease(
            req.license_key, req.fingerprint, ttl_seconds=req.ttl_seconds, scope=req.scope
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/v1/run/heartbeat")
async def run_heartbeat(req: RunHeartbeatRequest):
    _require_run_lease_support()
    try:
        return await keygen_provider.heartbeat_run_lease(
            req.lease_id, req.fingerprint, ttl_seconds=req.ttl_seconds
        )
    except PermissionError:
        raise HTTPException(status_code=409, detail="LEASE_REVOKED")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/v1/run/release")
async def run_release(req: RunReleaseRequest):
    _require_run_lease_support()
    ok = await keygen_provider.release_run_lease(req.lease_id, req.fingerprint)
    return {"success": ok}


def _require_run_lease_support() -> None:
    if not isinstance(keygen_provider, InMemoryKeygenProvider):
        raise HTTPException(status_code=503, detail="RUN_LEASE_UNSUPPORTED")


def _trial_error(status_code: int, code: str, headers: Optional[dict] = None) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"ok": False, "code": code}, headers=headers)


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


@app.post("/v1/trials/claim")
async def claim_trial(request: Request):
    """Self-service 1-day trial, at most one per machine fingerprint.

    200 {"ok": true, "license_key", "expires_at"} (same key/expiry on every repeat while valid)
    400 INVALID_FINGERPRINT / INVALID_REQUEST, 403 TRIAL_DISABLED,
    409 TRIAL_ALREADY_USED / TRIAL_NOT_ELIGIBLE, 429 TRIAL_RATE_LIMITED.
    The returned key is a normal license: activation, validation, runtime permits and
    release approval apply unchanged.
    """
    if not trials_enabled():
        return _trial_error(403, CODE_DISABLED)
    try:
        raw = await request.json()
        req = TrialClaimRequest.model_validate(raw)
        fingerprint = normalize_fingerprint(req.hardware.fingerprint)
        validate_hardware_extras(req.hardware.components, req.hardware.hostname, req.hardware.platform)
    except TrialClaimError as exc:
        return _trial_error(400, exc.code)
    except (ValidationError, ValueError, TypeError):
        return _trial_error(400, CODE_INVALID_REQUEST)
    hardware = req.hardware.model_copy(update={"fingerprint": fingerprint})

    allowed, retry_after = _TRIAL_RATE_LIMITS.per_fp.hit(fingerprint)
    if not allowed:
        return _trial_error(429, CODE_RATE_LIMITED, {"Retry-After": str(retry_after)})
    ip_key = client_ip_key(request.headers, request.client.host if request.client else None)
    get_trial = getattr(getattr(keygen_provider, "event_store", None), "get_device_trial", None)
    claim = getattr(keygen_provider, "claim_device_trial", None)
    if not callable(get_trial) or not callable(claim):
        return _trial_error(403, CODE_DISABLED)
    if get_trial(fingerprint) is None:
        # Per-IP budget is only spent on attempts that could mint a NEW trial,
        # so retries/repeats for an already-claimed machine never get 429 from it.
        allowed, retry_after = _TRIAL_RATE_LIMITS.per_ip.hit(ip_key)
        if not allowed:
            return _trial_error(429, CODE_RATE_LIMITED, {"Retry-After": str(retry_after)})
    try:
        dto = await claim(
            hardware,
            client_ip=ip_key,
            duration=timedelta(hours=trial_duration_hours()),
        )
    except TrialClaimError as exc:
        return _trial_error(409, exc.code)
    return {"ok": True, "license_key": dto.license_key, "expires_at": _utc_iso(dto.expires_at),
            "plan": dto.plan, "tier": dto.tier, "tier_name": dto.tier_name, "is_beta_user": dto.is_beta_user}


# ---- BATCH C: internal referral reward (loopback + shared secret; blocked at Caddy) ----
_FORWARD_HEADERS = ("x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded",
                    "x-real-ip", "cf-connecting-ip", "true-client-ip", "via")


def _referral_error(code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=_referral.ERRORS.get(code, 400), content={"detail": f"{code}: {message}"})


@app.post("/internal/trials/current")
async def internal_trial_current(request: Request):
    """Read-only device lookup; direct loopback and the existing shared secret only."""
    host = request.client.host if request.client else ""
    expected = (os.environ.get("REFERRAL_INTERNAL_KEY") or "").strip()
    supplied = request.headers.get("x-referral-internal-key") or ""
    if (host != "127.0.0.1" or any(h in request.headers for h in _FORWARD_HEADERS)
            or len(expected) < 32 or not secrets.compare_digest(supplied.encode(), expected.encode())):
        raise HTTPException(status_code=403, detail="internal endpoint")
    try:
        body = await request.json()
        fp = str(body.get("fingerprint") or "").strip().lower()
        if len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp):
            raise ValueError
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="invalid fingerprint")
    lookup = getattr(keygen_provider, "current_device_license", None)
    if lookup is None:
        raise HTTPException(status_code=503, detail="current lookup unavailable")
    return {"current": lookup(fp)}


@app.post("/internal/referrals/reward-extend")
async def internal_referral_reward_extend(request: Request):
    """Body {inviter_fingerprint, invitee_fingerprint, review_id}; header X-Referral-Internal-Key.
    Only a direct loopback client (127.0.0.1, no proxy/forwarding headers) is accepted."""
    host = request.client.host if request.client else ""
    if host != "127.0.0.1" or any(h in request.headers for h in _FORWARD_HEADERS):
        return _referral_error("REFERRAL_UNAUTHORIZED", "internal endpoint")
    expected = (os.environ.get("REFERRAL_INTERNAL_KEY") or "").strip()
    if len(expected) < 32:
        return _referral_error("REFERRAL_DISABLED", "REFERRAL_INTERNAL_KEY is not configured")
    supplied = request.headers.get("x-referral-internal-key") or ""
    if not secrets.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
        return _referral_error("REFERRAL_UNAUTHORIZED", "bad internal key")
    try:
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError
    except Exception:
        return _referral_error("REFERRAL_BAD_REQUEST", "JSON object body required")
    fn = getattr(keygen_provider, "referral_reward_extend", None)
    if not callable(fn):
        return _referral_error("REFERRAL_DISABLED", "provider does not support referrals")
    try:
        out = await fn(body.get("inviter_fingerprint"), body.get("invitee_fingerprint"),
                       body.get("review_id"), cap=_referral.bonus_cap())
    except _referral.ReferralError as exc:
        return JSONResponse(status_code=exc.status, content={"detail": exc.detail})
    if out.get("status") == _referral.STATUS_PENDING:
        return JSONResponse(status_code=202, content=jsonable_encoder(out))   # r7: NO_ELIGIBLE_LICENSE
    return out


@app.post("/v1/offline/issue", response_model=SignedOfflineEntitlement)
async def issue_offline_entitlement(req: OfflineIssueRequest):
    if not _batch_a_secret_ok(req.license_key):
        raise HTTPException(status_code=400, detail=_BATCH_A_NOT_FOUND)
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
    Process incoming FOSSBilling webhook event.
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
