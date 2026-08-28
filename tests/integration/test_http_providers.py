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
from bridge.app.providers.http_keygen_provider import HttpKeygenProvider
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


def _mock_keygen_urlopen(responses: list):
    """Return a context manager factory that feeds from a list of (status, body) pairs."""
    idx = {"i": 0}

    class MockResp:
        def __init__(self, body):
            self._body = json.dumps(body).encode()

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    def urlopen(req, timeout=None):
        i = idx["i"]
        if i < len(responses):
            body = responses[i]
            idx["i"] += 1
        else:
            body = responses[-1]
        return MockResp(body)

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

    @pytest.mark.asyncio
    async def test_revoke_license_marks_revoked(self):
        provider = self._provider()
        lic_resp = _keygen_license(lic_id="lic_rev_kg")
        # GET then DELETE (204 → empty) → parse from original DTO
        delete_resp = {}

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
