"""
Local /admin console E2E tests.
Runs against the FastAPI app with the default in-memory provider.
"""
import base64
import os
from datetime import datetime, timedelta, timezone

os.environ["SUBSCRIPTION_ADMIN_PASSWORD"] = "test-admin-pass-g2-strong"
os.environ["SUBSCRIPTION_ADMIN_USER"] = "admin"
os.environ.setdefault("PROVIDER_MODE", "inmemory")

from urllib.parse import unquote

from contracts.entitlement import HardwareFingerprint, LicenseStatus
from bridge.app.main import app, keygen_provider
from fastapi.testclient import TestClient

client = TestClient(app, client=("127.0.0.1", 50000))


def _auth() -> dict:
    token = base64.b64encode(b"admin:test-admin-pass-g2-strong").decode()
    return {"Authorization": f"Basic {token}"}


async def _create(limit=2, email="tester@test.local") -> "object":
    return await keygen_provider.create_license(
        customer_id=f"admin_test_{datetime.now().timestamp()}",
        customer_email=email,
        plan="pro_monthly",
        duration_days=30,
        device_limit=limit,
        features=["core", "automation"],
        metadata={},
    )


def test_admin_requires_basic_auth():
    assert client.get("/admin").status_code == 401
    assert client.post("/admin/licenses", data={}).status_code == 401


def test_admin_page_lists_licenses_and_copy_button():
    import asyncio
    dto = asyncio.run(_create())
    page = client.get("/admin", headers=_auth())
    assert page.status_code == 200
    # full key appears in HTML (admin-only surface) with a copy button
    assert dto.license_key in page.text
    assert "复制" in page.text
    assert f"data-key='{dto.license_key}'" in page.text


def test_admin_create_respects_device_limit():
    import asyncio
    dto = asyncio.run(_create(limit=3))
    assert dto.device_limit == 3
    page = client.get("/admin", headers=_auth())
    assert "0 / 3" in page.text


def test_admin_create_device_limit_bounded():
    """Out-of-range values are clamped, non-integer values are rejected."""
    # clamp to max
    resp = client.post(
        "/admin/licenses",
        data={"customer_id": "c1", "email": "c1@t.local", "days": "30", "device_limit": "999"},
        headers=_auth(),
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert unquote(resp.headers.get("location", "")).startswith("/admin?message=已创建")
    # non-integer rejected
    resp2 = client.post(
        "/admin/licenses",
        data={"customer_id": "c2", "email": "c2@t.local", "days": "30", "device_limit": "abc"},
        headers=_auth(),
        follow_redirects=False,
    )
    assert resp2.status_code == 303
    assert "设备上限必须是 1 到 10 的整数" in unquote(resp2.headers.get("location", ""))


def test_admin_status_filter_revoked():
    import asyncio
    good = asyncio.run(_create())
    bad = asyncio.run(_create())
    asyncio.run(keygen_provider.revoke_license(bad.license_id, reason="test"))
    page = client.get("/admin?status=REVOKED", headers=_auth())
    assert bad.license_key in page.text
    assert good.license_key not in page.text


def test_admin_status_filter_unactivated():
    import asyncio
    plain = asyncio.run(_create())
    bound = asyncio.run(_create())
    asyncio.run(
        keygen_provider.activate_device(
            bound.license_key, HardwareFingerprint(fingerprint="fp-a", hostname="dev-a")
        )
    )
    page = client.get("/admin?status=UNACTIVATED", headers=_auth())
    assert plain.license_key in page.text
    assert bound.license_key not in page.text


def test_admin_devices_shown_with_unbind_form():
    import asyncio
    dto = asyncio.run(_create(limit=2))
    asyncio.run(
        keygen_provider.activate_device(
            dto.license_key, HardwareFingerprint(fingerprint="fp-b", hostname="dev-b")
        )
    )
    page = client.get("/admin", headers=_auth())
    assert "1 / 2" in page.text
    assert "dev-b" in page.text
    assert f"/admin/licenses/{dto.license_id}/unbind" in page.text


def test_admin_unbind_device():
    import asyncio
    dto = asyncio.run(_create(limit=2))
    asyncio.run(
        keygen_provider.activate_device(
            dto.license_key, HardwareFingerprint(fingerprint="fp-c", hostname="dev-c")
        )
    )
    assert asyncio.run(keygen_provider.get_devices(dto.license_id))
    resp = client.post(
        f"/admin/licenses/{dto.license_id}/unbind",
        data={"fingerprint": "fp-c"},
        headers=_auth(),
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert asyncio.run(keygen_provider.get_devices(dto.license_id)) == []
    # unknown fingerprint does not crash
    resp2 = client.post(
        f"/admin/licenses/{dto.license_id}/unbind",
        data={"fingerprint": "missing"},
        headers=_auth(),
        follow_redirects=False,
    )
    assert resp2.status_code == 303
    assert "未找到该设备" in unquote(resp2.headers.get("location", ""))


def test_admin_survives_list_failure(monkeypatch):
    async def boom():
        raise RuntimeError("provider down")

    monkeypatch.setattr(keygen_provider, "list_licenses", boom)
    page = client.get("/admin", headers=_auth())
    assert page.status_code == 200
    assert "密钥列表查询失败" in page.text
    assert "创建测试密钥" in page.text  # create form still usable


def test_admin_survives_missing_list_method(monkeypatch):
    monkeypatch.setattr(keygen_provider, "list_licenses", None)
    page = client.get("/admin", headers=_auth())
    assert page.status_code == 200
    assert "不支持密钥列表" in page.text
    assert "创建测试密钥" in page.text


def test_admin_survives_device_failure(monkeypatch):
    import asyncio
    asyncio.run(_create())

    async def boom(license_id):
        raise RuntimeError("machines down")

    monkeypatch.setattr(keygen_provider, "get_devices", boom)
    page = client.get("/admin", headers=_auth())
    assert page.status_code == 200
    assert "设备查询失败" in page.text


def test_admin_escapes_html_in_owner():
    import asyncio
    asyncio.run(_create(email='<script>alert("x")</script>@test.local'))
    page = client.get("/admin", headers=_auth())
    assert "<script>alert" not in page.text
    assert "&lt;script&gt;" in page.text


def test_admin_expiry_route_works_with_inmemory():
    """set_license_expiry must exist on the default in-memory provider."""
    import asyncio
    dto = asyncio.run(_create())
    future = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    resp = client.post(
        f"/admin/licenses/{dto.license_id}/expiry",
        data={"expires_at": future},
        headers=_auth(),
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "已设置到期日" in unquote(resp.headers.get("location", ""))


def test_admin_effective_status_uses_expiry_timestamp():
    import asyncio

    dto = asyncio.run(_create())
    keygen_provider.licenses[dto.license_id]["expires_at"] = datetime.now(timezone.utc) - timedelta(days=1)
    expired = client.get("/admin?status=EXPIRED", headers=_auth())
    active = client.get("/admin?status=ACTIVE", headers=_auth())
    assert dto.license_key in expired.text
    assert "<td>EXPIRED</td>" in expired.text
    assert dto.license_key not in active.text

def test_admin_unactivated_filter_excludes_device_lookup_failure(monkeypatch):
    import asyncio

    dto = asyncio.run(_create())

    async def boom(license_id):
        raise RuntimeError("machines down")

    monkeypatch.setattr(keygen_provider, "get_devices", boom)
    page = client.get("/admin?status=UNACTIVATED", headers=_auth())
    assert dto.license_key not in page.text
    assert "暂无密钥" in page.text


def test_admin_expiry_errors_distinguish_parse_and_provider_failures():
    invalid = client.post(
        "/admin/licenses/missing/expiry",
        data={"expires_at": "not-a-date"},
        headers=_auth(),
        follow_redirects=False,
    )
    assert "到期日必须是未来的 ISO 时间" in unquote(invalid.headers.get("location", ""))

    future = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    provider_error = client.post(
        "/admin/licenses/missing/expiry",
        data={"expires_at": future},
        headers=_auth(),
        follow_redirects=False,
    )
    message = unquote(provider_error.headers.get("location", ""))
    assert "设置到期日失败" in message
    assert "到期日必须是未来的 ISO 时间" not in message


def test_admin_backup_requires_basic_auth():
    assert client.get("/admin/backup/db").status_code == 401
    assert client.get("/admin/backup/db", auth=("admin", "wrong-password")).status_code == 401


def test_admin_raw_backup_download_disabled_in_batch_a(tmp_path, monkeypatch):
    """BATCH A: raw DB download (plaintext secrets) is disabled."""
    db_path = tmp_path / "subscription.db"
    db_path.write_bytes(b"")
    monkeypatch.setenv("SUBSCRIPTION_DB_PATH", str(db_path))
    assert client.get("/admin/backup/db", headers=_auth()).status_code == 410


def test_local_license_and_device_state_survives_restart(tmp_path):
    import asyncio

    from bridge.app.providers.keygen_provider import InMemoryKeygenProvider
    from bridge.app.services.event_processor import SqliteEventStore

    db_path = str(tmp_path / "local-state.db")
    hardware = HardwareFingerprint(fingerprint="persisted-local-device")

    async def exercise_restart():
        store = SqliteEventStore(db_path)
        provider = InMemoryKeygenProvider(keygen_provider.crypto, store)
        try:
            license = await provider.create_license("local-restart", "local@example.invalid", "pro_monthly", 1)
            await provider.activate_device(license.license_key, hardware)
        finally:
            store.close()

        store = SqliteEventStore(db_path)
        provider = InMemoryKeygenProvider(keygen_provider.crypto, store)
        try:
            licenses = await provider.list_licenses()
            assert [item.license_id for item in licenses] == [license.license_id]
            devices = await provider.get_devices(license.license_id)
            assert [item.fingerprint for item in devices] == [hardware.fingerprint]
            result = await provider.validate_license(license.license_key, hardware.fingerprint)
            assert result.valid is True
            assert result.permit is None
            assert await provider.deactivate_device(license.license_key, hardware.fingerprint)
        finally:
            store.close()

        store = SqliteEventStore(db_path)
        provider = InMemoryKeygenProvider(keygen_provider.crypto, store)
        try:
            assert await provider.get_devices(license.license_id) == []
        finally:
            store.close()

    asyncio.run(exercise_restart())


def test_admin_fails_closed_without_password(monkeypatch):
    """Missing/empty SUBSCRIPTION_ADMIN_PASSWORD must refuse admin (503), not default admin/admin."""
    monkeypatch.delenv("SUBSCRIPTION_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("SUBSCRIPTION_ADMIN_PASSWORD", "")
    # Even with classic default credentials, access must be refused.
    denied = client.get("/admin", auth=("admin", "admin"))
    assert denied.status_code == 503
    assert "not configured" in denied.json()["detail"].lower() or "disabled" in denied.text.lower()
    # Restore for subsequent tests in this module (live env read).
    monkeypatch.setenv("SUBSCRIPTION_ADMIN_PASSWORD", "test-admin-pass-g2-strong")
    ok = client.get("/admin", headers=_auth())
    assert ok.status_code == 200
