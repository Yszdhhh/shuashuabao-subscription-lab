"""
HTTP Provider Adapter E2E Tests — mocked HTTP server.
Tests HttpKeygenProvider and HttpKeygateProvider without a live server.
"""
import json
import pytest
from datetime import datetime, timedelta, timezone
from io import BytesIO
from unittest.mock import MagicMock, patch
from contracts.entitlement import HardwareFingerprint, LicenseStatus
from bridge.app.providers.http_keygen_provider import HttpKeygenProvider, _status_to_enum
from bridge.app.providers.http_keygate_provider import HttpKeygateProvider


def _keygen_license(
    lic_id="lic_test001",
    key="KEYGEN-AAAA-BBBB-CCCC",
    status="ACTIVE",
    plan="pro_monthly",
    customer_id="cust_01",
    expires_days=30,
):
    exp = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()
    return {
        "data": {
            "id": lic_id,
            "type": "licenses",
            "attributes": {
                "key": key,
                "status": status,
                "expiry": exp,
                "created": datetime.now(timezone.utc).isoformat(),
                "maxMachines": 1,
                "machinesCount": 0,
                "metadata": {
                    "plan": plan,
                    "customer_id": customer_id,
                    "customer_email": f"{customer_id}@test.local",
                    "features": ["core"],
                },
            },
        }
    }


def _keygate_license(
    lic_id="kg_test001",
    key="KEYGATE-AAAA-BBBB-CCCC",
    status="active",
    plan="pro_monthly",
    customer_id="cust_01",
    expires_days=30,
):
    exp = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()
    return {
        "id": lic_id,
        "key": key,
        "status": status,
        "plan": plan,
        "customer_id": customer_id,
        "customer_email": f"{customer_id}@test.local",
        "expires_at": exp,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "device_limit": 1,
        "devices_used": 0,
        "features": ["core"],
        "metadata": {},
    }


def _mock_keygen_urlopen(responses: list, captured_requests=None):
    """Return a context manager factory for JSON or (status, body) responses."""
    idx = {"i": 0}

    class MockResp:
        def __init__(self, status, body):
            self.status = status
            self._body = body if isinstance(body, bytes) else json.dumps(body).encode()

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    def urlopen(req, timeout=None):
        i = idx["i"]
        if i < len(responses):
            response = responses[i]
            idx["i"] += 1
        else:
            response = responses[-1]
        status, body = response if isinstance(response, tuple) else (200, response)
        if captured_requests is not None:
            captured_requests.append(req)
        return MockResp(status, body)

    return urlopen


# ── HttpKeygenProvider ─────────────────────────────────────────────────────────

class TestHttpKeygenProvider:

    def _provider(self):
        return HttpKeygenProvider(
            base_url="http://localhost:3000",
            account_id="test-account-uuid",
            token="test-admin-token",
            policy_map={"pro_monthly": "policy-uuid-001"},
        )

    @pytest.mark.asyncio
    async def test_create_license_posts_to_keygen(self):
        provider = self._provider()
        lic_resp = _keygen_license()

        with patch("bridge.app.providers.http_keygen_provider.urllib_request.urlopen",
                   side_effect=_mock_keygen_urlopen([lic_resp])):
            lic = await provider.create_license(
                "cust_kg_01", "kg@test.local", "pro_monthly", duration_days=30
            )

        assert lic.license_id == "lic_test001"
        assert lic.status == LicenseStatus.ACTIVE
        assert lic.plan == "pro_monthly"

    @pytest.mark.asyncio
    async def test_get_license_returns_parsed_dto(self):
        provider = self._provider()
        lic_resp = _keygen_license(lic_id="lic_get_01", key="KEYGEN-GET1-TEST-0001")

        with patch("bridge.app.providers.http_keygen_provider.urllib_request.urlopen",
                   side_effect=_mock_keygen_urlopen([lic_resp])):
            lic = await provider.get_license("lic_get_01")

        assert lic is not None
        assert lic.license_id == "lic_get_01"
        assert lic.license_key == "KEYGEN-GET1-TEST-0001"

    @pytest.mark.asyncio
    async def test_get_license_not_found_returns_none(self):
        from urllib.error import HTTPError
        provider = self._provider()

        def raise_404(req, timeout=None):
            raise HTTPError(url="", code=404, msg="Not Found", hdrs={}, fp=BytesIO(b'{"errors":[]}'))

        with patch("bridge.app.providers.http_keygen_provider.urllib_request.urlopen",
                   side_effect=raise_404):
            lic = await provider.get_license("nonexistent")
        assert lic is None

    @pytest.mark.asyncio
    async def test_list_licenses_and_set_exact_expiry(self):
        provider = self._provider()
        listed = {"data": [_keygen_license(lic_id="lic_list_01")["data"]]}
        updated = _keygen_license(lic_id="lic_list_01")
        captured_requests = []
        expires_at = datetime(2026, 9, 1, tzinfo=timezone.utc)

        with patch(
            "bridge.app.providers.http_keygen_provider.urllib_request.urlopen",
            side_effect=_mock_keygen_urlopen([listed, updated], captured_requests),
        ):
            licenses = await provider.list_licenses()
            changed = await provider.set_license_expiry("lic_list_01", expires_at)

        assert licenses[0].license_id == "lic_list_01"
        assert changed.license_id == "lic_list_01"
        assert "licenses?page[number]=1&page[size]=100&sort=-created" in captured_requests[0].full_url
        assert json.loads(captured_requests[1].data)["data"]["attributes"]["expiry"] == expires_at.isoformat()

    @pytest.mark.asyncio
    async def test_validate_license_valid(self):
        provider = self._provider()
        validate_resp = {
            "meta": {"valid": True, "code": "VALID", "detail": "License is valid"},
            "data": _keygen_license()["data"],
        }

        with patch("bridge.app.providers.http_keygen_provider.urllib_request.urlopen",
                   side_effect=_mock_keygen_urlopen([validate_resp])):
            result = await provider.validate_license("KEYGEN-AAAA-BBBB-CCCC")

        assert result.valid is True
        assert result.can_start_runner is True
        assert result.code == "VALID"

    @pytest.mark.asyncio
    async def test_validate_license_uses_scoped_fingerprint(self):
        provider = self._provider()
        validate_resp = {
            "meta": {"valid": True, "code": "VALID", "detail": ""},
            "data": _keygen_license()["data"],
        }
        captured_requests = []

        with patch(
            "bridge.app.providers.http_keygen_provider.urllib_request.urlopen",
            side_effect=_mock_keygen_urlopen([validate_resp], captured_requests),
        ):
            result = await provider.validate_license(
                "KEYGEN-AAAA-BBBB-CCCC", fingerprint="FP-SCOPED"
            )

        payload = json.loads(captured_requests[0].data)
        assert result.valid is True
        assert payload["meta"]["scope"]["fingerprint"] == "FP-SCOPED"
        assert "fingerprint" not in payload["meta"]

    def test_headers_include_keygen_proxy_environment(self, monkeypatch):
        monkeypatch.setenv("KEYGEN_HOST_HEADER", "keygen.internal")
        monkeypatch.setenv("KEYGEN_FORWARD_PROTO", "https")

        headers = self._provider()._headers()

        assert headers["Host"] == "keygen.internal"
        assert headers["X-Forwarded-Proto"] == "https"

    def test_policy_env_is_default_only_when_policy_map_is_none(self, monkeypatch):
        monkeypatch.setenv("KEYGEN_POLICY_ID", "policy-from-env")
        kwargs = {
            "base_url": "http://localhost:3000",
            "account_id": "test-account-uuid",
            "token": "test-admin-token",
        }

        defaulted = HttpKeygenProvider(**kwargs, policy_map=None)
        explicit = HttpKeygenProvider(**kwargs, policy_map={})

        assert defaulted.policy_map == {"pro_monthly": "policy-from-env"}
        assert explicit.policy_map == {}

    @pytest.mark.asyncio
    async def test_validate_license_expired(self):
        provider = self._provider()
        lic_data = _keygen_license(status="EXPIRED", expires_days=-5)["data"]
        validate_resp = {
            "meta": {"valid": False, "code": "LICENSE_EXPIRED", "detail": ""},
            "data": lic_data,
        }

        with patch("bridge.app.providers.http_keygen_provider.urllib_request.urlopen",
                   side_effect=_mock_keygen_urlopen([validate_resp])):
            result = await provider.validate_license("KEYGEN-AAAA-BBBB-CCCC")

        assert result.valid is False
        assert result.can_start_runner is False

    def test_expiring_keygen_status_maps_to_allowed_grace(self):
        assert _status_to_enum("EXPIRING") == LicenseStatus.GRACE

    @pytest.mark.asyncio
    async def test_activate_device_reports_conflict_with_another_license(self):
        from urllib.error import HTTPError

        provider = self._provider()
        validation = {
            "meta": {"valid": True, "code": "VALID"},
            "data": _keygen_license(lic_id="lic_conflict")["data"],
        }
        conflict = {"errors": [{"code": "FINGERPRINT_TAKEN"}]}
        calls = {"count": 0}

        def urlopen(request, timeout=None):
            calls["count"] += 1
            if calls["count"] == 1:
                return _mock_keygen_urlopen([validation])(request, timeout)
            if calls["count"] == 2:
                raise HTTPError("http://keygen/machines", 422, "Unprocessable", {}, BytesIO(json.dumps(conflict).encode()))
            return _mock_keygen_urlopen([{"data": []}])(request, timeout)

        with patch("bridge.app.providers.http_keygen_provider.urllib_request.urlopen", side_effect=urlopen):
            with pytest.raises(ValueError, match="DEVICE_ALREADY_BOUND_TO_ANOTHER_LICENSE"):
                await provider.activate_device("KEYGEN-CONFLICT", HardwareFingerprint(fingerprint="fingerprint-in-use"))

    @pytest.mark.asyncio
    async def test_revoke_license_marks_revoked(self):
        provider = self._provider()
        lic_resp = _keygen_license(lic_id="lic_rev_kg")
        # GET then DELETE (204 → empty) → parse from original DTO
        delete_resp = (204, b"")

        with patch("bridge.app.providers.http_keygen_provider.urllib_request.urlopen",
                   side_effect=_mock_keygen_urlopen([lic_resp, delete_resp])):
            dto = await provider.revoke_license("lic_rev_kg")

        assert dto.status == LicenseStatus.REVOKED
        assert "revoke_reason" in dto.metadata

    @pytest.mark.asyncio
    async def test_renew_revoked_license_raises(self):
        """renew_license must raise ValueError for REVOKED status without calling PATCH."""
        provider = self._provider()
        revoked_lic = _keygen_license(status="BANNED")  # Keygen uses BANNED for revoked

        with patch("bridge.app.providers.http_keygen_provider.urllib_request.urlopen",
                   side_effect=_mock_keygen_urlopen([revoked_lic])):
            with pytest.raises(ValueError, match="revoked|terminal"):
                await provider.renew_license("lic_test001")

    @pytest.mark.asyncio
    async def test_offline_entitlement_roundtrip(self):
        """Issue and verify offline entitlement via HttpKeygenProvider (local crypto)."""
        from bridge.app.core.crypto import CryptoEngine
        provider = self._provider()
        crypto = CryptoEngine()
        provider.crypto = crypto

        # validate_license must return valid=True with a license
        lic_data = _keygen_license()["data"]
        validate_resp = {
            "meta": {"valid": True, "code": "VALID", "detail": ""},
            "data": lic_data,
        }

        hw = HardwareFingerprint(fingerprint="FP_HTTP_KG_OFFLINE")
        with patch("bridge.app.providers.http_keygen_provider.urllib_request.urlopen",
                   side_effect=_mock_keygen_urlopen([validate_resp])):
            entitlement = await provider.issue_offline_entitlement("KEYGEN-AAAA-BBBB-CCCC", hw)

        result = await provider.verify_offline_entitlement(entitlement, hw)
        assert result.valid is True
        assert result.can_start_runner is True


# ── HttpKeygateProvider ────────────────────────────────────────────────────────

class TestHttpKeygateProvider:

    def _provider(self):
        return HttpKeygateProvider(
            base_url="http://localhost:8080",
            token="test-keygate-token",
        )

    def _mock_urlopen(self, responses: list):
        return _mock_keygen_urlopen(responses)  # Same generic mock

    @pytest.mark.asyncio
    async def test_create_license_posts_to_keygate(self):
        provider = self._provider()
        lic_resp = _keygate_license()

        with patch("bridge.app.providers.http_keygate_provider.urllib_request.urlopen",
                   side_effect=_mock_keygen_urlopen([lic_resp])):
            lic = await provider.create_license(
                "cust_kg_01", "kg@test.local", "pro_monthly", duration_days=30
            )

        assert lic.license_id == "kg_test001"
        assert lic.status == LicenseStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_get_license_not_found(self):
        from urllib.error import HTTPError
        provider = self._provider()

        def raise_404(req, timeout=None):
            raise HTTPError(url="", code=404, msg="Not Found", hdrs={}, fp=BytesIO(b'{"error":"not_found"}'))

        with patch("bridge.app.providers.http_keygate_provider.urllib_request.urlopen",
                   side_effect=raise_404):
            lic = await provider.get_license("missing")
        assert lic is None

    @pytest.mark.asyncio
    async def test_validate_license_returns_valid(self):
        provider = self._provider()
        lic_data = _keygate_license()
        validate_resp = {
            "valid": True,
            "code": "VALID",
            "message": "OK",
            "license": lic_data,
        }

        with patch("bridge.app.providers.http_keygate_provider.urllib_request.urlopen",
                   side_effect=_mock_keygen_urlopen([validate_resp])):
            result = await provider.validate_license("KEYGATE-AAAA-BBBB-CCCC")

        assert result.valid is True
        assert result.can_start_runner is True

    @pytest.mark.asyncio
    async def test_revoke_marks_dto_revoked(self):
        provider = self._provider()
        lic_resp = _keygate_license(lic_id="kg_rev_test")
        delete_resp = {}

        with patch("bridge.app.providers.http_keygate_provider.urllib_request.urlopen",
                   side_effect=_mock_keygen_urlopen([lic_resp, delete_resp])):
            dto = await provider.revoke_license("kg_rev_test")

        assert dto.status == LicenseStatus.REVOKED

    @pytest.mark.asyncio
    async def test_reinstate_revoked_raises(self):
        """reinstate_license on REVOKED must raise ValueError."""
        provider = self._provider()
        revoked_lic = _keygate_license(status="revoked")

        with patch("bridge.app.providers.http_keygate_provider.urllib_request.urlopen",
                   side_effect=_mock_keygen_urlopen([revoked_lic])):
            with pytest.raises(ValueError, match="revoked|terminal"):
                await provider.reinstate_license("kg_rev_test")

    @pytest.mark.asyncio
    async def test_offline_entitlement_roundtrip(self):
        from bridge.app.core.crypto import CryptoEngine
        provider = self._provider()
        provider.crypto = CryptoEngine()

        lic_data = _keygate_license()
        validate_resp = {
            "valid": True,
            "code": "VALID",
            "message": "OK",
            "license": lic_data,
        }
        hw = HardwareFingerprint(fingerprint="FP_HTTP_KGT_OFFLINE")

        with patch("bridge.app.providers.http_keygate_provider.urllib_request.urlopen",
                   side_effect=_mock_keygen_urlopen([validate_resp])):
            entitlement = await provider.issue_offline_entitlement("KEYGATE-AAAA-BBBB-CCCC", hw)

        result = await provider.verify_offline_entitlement(entitlement, hw)
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_activate_device_idempotent_on_conflict(self):
        """409 conflict on machine creation → fetch existing machine idempotently."""
        from urllib.error import HTTPError
        provider = self._provider()

        lic_data = _keygate_license(lic_id="kg_idem_01", key="KG-IDEM-KEY-001")
        validate_resp = {"valid": True, "code": "VALID", "message": "OK", "license": lic_data}

        existing_machine = {
            "id": "mach_existing_01",
            "fingerprint": "FP_IDEM_KEYGATE",
            "name": "test_node",
            "activated_at": "2026-01-01T00:00:00Z",
        }
        machines_resp = {"machines": [existing_machine]}

        call_count = {"n": 0}

        def urlopen(req, timeout=None):
            call_count["n"] += 1
            class R:
                def read(self):
                    if call_count["n"] == 1:
                        return json.dumps(validate_resp).encode()
                    if call_count["n"] == 2:
                        raise HTTPError(url="", code=409, msg="Conflict",
                                        hdrs={}, fp=BytesIO(b'{"code":"duplicate"}'))
                    return json.dumps(machines_resp).encode()
                def __enter__(self): return self
                def __exit__(self, *a): pass
            return R()

        hw = HardwareFingerprint(fingerprint="FP_IDEM_KEYGATE")
        with patch("bridge.app.providers.http_keygate_provider.urllib_request.urlopen",
                   side_effect=urlopen):
            act = await provider.activate_device("KG-IDEM-KEY-001", hw)

        assert act.activation_id == "mach_existing_01"
        assert act.fingerprint == "FP_IDEM_KEYGATE"
