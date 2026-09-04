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
from typing import Any, Optional
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
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
keygate_provider = InMemoryKeygateProvider(crypto_engine=crypto_engine)
billing_processor = BillingEventProcessor(license_provider=keygen_provider, event_store=_STORE)

# Server-enforced trial duration policy (3 days default per server policy)
_TRIAL_DAYS = int(os.environ.get("DEFAULT_TRIAL_DAYS", "3"))
_ADMIN_USER = os.environ.get("SUBSCRIPTION_ADMIN_USER") or "admin"
_ADMIN_PASSWORD = os.environ.get("SUBSCRIPTION_ADMIN_PASSWORD") or "admin"
# Conservative provider-status → admin-filter mapping (GRACE/TRIAL count as active).
_ADMIN_STATUS_FILTERS = ("UNACTIVATED", "ACTIVE", "EXPIRED", "REVOKED")
_ACTIVE_LIKE_STATUSES = {LicenseStatus.ACTIVE, LicenseStatus.TRIAL, LicenseStatus.GRACE}

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
    return f"""<tr><td><code class='key' data-key='{key}'>{key}</code> <button type='button' class='copy' data-key='{key}' onclick='copyKey(this)'>复制</button></td><td>{status}</td><td>{expiry}</td><td>{owner}</td><td>{device_cell}</td><td>
<form method='post' action='/admin/licenses/{ident}/extend'><input name='days' type='number' value='1' min='1' max='365'><button>延期</button></form>
<form method='post' action='/admin/licenses/{ident}/expiry'><input name='expires_at' value='{expiry_input}' placeholder='2026-09-01T00:00:00+00:00'><button>设到期日</button></form>
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
        list_error = "当前 Provider 不支持密钥列表查询，仍可创建测试密钥"
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
    filter_options = "".join(
        f"<option value='{f}'{ ' selected' if status_filter == f else ''}>{f}</option>"
        for f in _ADMIN_STATUS_FILTERS
    )

    return f"""<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'><title>刷刷宝订阅管理</title>
<style>body{{font:15px system-ui;margin:32px;color:#1f2937}}main{{max-width:1180px;margin:auto}}form{{display:inline-block;margin:3px}}input{{padding:6px;margin:2px}}button{{padding:6px 10px;cursor:pointer}}.danger{{color:#a00}}table{{width:100%;border-collapse:collapse;margin-top:20px}}td,th{{border-bottom:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}}.notice,.error{{padding:8px;background:#ecfdf5}}.error{{background:#fef2f2}}.warn{{color:#92400e}}.key{{font-family:monospace;font-size:13px}}ul.devices{{margin:2px 0;padding-left:16px;font-size:13px}}ul.devices li{{margin:2px 0}}.copy{{padding:2px 6px;font-size:12px}}</style>
<script>function copyKey(btn){{var v=btn.dataset.key;navigator.clipboard.writeText(v).then(function(){{btn.textContent='已复制';setTimeout(function(){{btn.textContent='复制'}},1500);}}).catch(function(){{}});}}</script></head><body><main>
<h1>刷刷宝订阅管理</h1><p>本页只绑定 <code>127.0.0.1</code>。创建后复制密钥，在刷刷宝看板点击“激活密钥”填入。 <a href='/admin/releases'>发布策略</a></p>{notice}{list_error_html}
<h2>创建测试密钥</h2><form method='post' action='/admin/licenses'><label>测试标识 <input name='customer_id' value='manual-test'></label><label>邮箱 <input name='email' value='test@example.invalid'></label><label>有效天数 <input name='days' type='number' value='1' min='1' max='365'></label><label>设备上限 <input name='device_limit' type='number' value='1' min='1' max='10'></label><button>生成密钥</button></form>
<h2>已有密钥</h2><form method='get' action='/admin' style='display:inline-block;margin-bottom:8px'><label>状态 <select name='status'><option value=''>全部</option>{filter_options}</select></label><button>筛选</button></form>
<table><thead><tr><th>密钥</th><th>状态</th><th>到期时间</th><th>归属</th><th>设备</th><th>管理</th></tr></thead><tbody>{rows or '<tr><td colspan=6>暂无密钥</td></tr>'}</tbody></table>
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
        device_limit = max(1, min(int(values.get("device_limit") or "1"), 10))
    except ValueError:
        return _admin_error("设备上限必须是 1 到 10 的整数")
    try:
        dto = await keygen_provider.create_license(
            values.get("customer_id") or "manual-test",
            values.get("email") or "test@example.invalid",
            "pro_monthly",
            duration_days=days,
            device_limit=device_limit,
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
    return _admin_error("设备已解绑" if ok else "未找到该设备")


def _attach_release_status(result: EntitlementValidationResult, context: PermitRequest) -> None:
    """Advisory/status belong on the validation envelope, never inside the signed permit."""
    result.release_status = permit_issuer.status_payload_for(
        context.source_sha,
        context.release_manifest_sha256,
        context.release_channel,
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


@app.post("/v1/entitlements/validate", response_model=EntitlementValidationResult)
async def validate_entitlement(req: ValidateRequest):
    fp = req.hardware.fingerprint if req.hardware else None
    result = await keygen_provider.validate_license(req.license_key, fingerprint=fp)
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
        return not_approved_status_payload(source_sha, release_manifest_sha256, release_channel)
    return permit_issuer.status_payload_for(source_sha, manifest, channel)


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
        payload = _upsert_release_policy_from_values(values, updated_by=_ADMIN_USER)
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
    payload = _upsert_release_policy_from_values(values, updated_by=_ADMIN_USER)
    return {"ok": True, "release_status": payload}

@app.get("/admin/backup/db")
async def download_backup_db(request: Request):
    _require_admin(request)
    import os
    from fastapi.responses import FileResponse
    db_path = os.environ.get("SUBSCRIPTION_DB_PATH", "./data/subscription_state.db")
    if not os.path.exists(db_path):
        raise HTTPException(status_code=404, detail="Database file not found")
    return FileResponse(db_path, media_type="application/x-sqlite3", filename="subscription_state.db")


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
