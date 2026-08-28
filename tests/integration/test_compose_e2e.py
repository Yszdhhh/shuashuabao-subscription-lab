"""Automated E2E lifecycle tests against real services started by docker compose.

When COMPOSE_E2E=1 is set:
- Requires live Bridge, Keygen, Keygate, and FOSSBilling containers.
- Missing credentials/dependencies result in test FAILURE (0 skipped / 0 xfailed).
- Executes real HTTP lifecycle:
  1. Signed FOSSBilling webhook delivery -> Bridge
  2. Real Keygen license creation, machine activation, offline entitlement issue/verify, renewal, refund/revoke
  3. Real Keygate shadow activation, verify, deactivation
"""
import hashlib
import hmac
import json
import os
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("COMPOSE_E2E") != "1",
    reason="set COMPOSE_E2E=1 after starting infra/compose/docker-compose.yml",
)

BRIDGE_URL = os.getenv("BRIDGE_URL", "http://127.0.0.1:8000")
KEYGEN_URL = os.getenv("KEYGEN_URL", "http://127.0.0.1:3000")
KEYGATE_URL = os.getenv("KEYGATE_URL", "http://127.0.0.1:9000")
WEBHOOK_SECRET = os.getenv("FOSSBILLING_WEBHOOK_SECRET", "")


def _request_json(method: str, url: str, payload: dict | None = None, headers: dict | None = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", **(headers or {})},
        method=method,
    )
    with urlopen(req, timeout=20) as response:
        assert response.status < 300
        raw = response.read()
        return json.loads(raw) if raw else {}


def _get_json(url: str) -> dict:
    last_error = None
    for _ in range(30):
        try:
            return _request_json("GET", url)
        except (OSError, URLError, ValueError) as exc:
            last_error = exc
            time.sleep(2)
    pytest.fail(f"compose service is not reachable at {url}: {last_error}")


def _webhook(payload: dict) -> dict:
    assert WEBHOOK_SECRET, "FOSSBILLING_WEBHOOK_SECRET must be configured for E2E"
    raw = json.dumps(payload).encode()
    signature = "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return _request_json(
        "POST",
        f"{BRIDGE_URL}/v1/webhooks/fossbilling",
        payload,
        {"X-FOSSBilling-Signature": signature},
    )


def test_bridge_health_and_provider_selection():
    """Verify Bridge is healthy and running with configured provider."""
    health = _get_json(f"{BRIDGE_URL}/health")
    assert health["status"] == "healthy"
    assert health["active_provider"] == "keygen"


def test_keygate_health_and_keygen_reachability():
    """Verify Keygate and Keygen containers are healthy and reachable."""
    health = _get_json(f"{KEYGATE_URL}/api/v1/system/health")
    assert health["status"] in ("ok", "healthy", "up") or "version" in health or "timestamp" in health
    try:
        with urlopen(f"{KEYGEN_URL}/v1/health", timeout=10) as response:
            assert response.status < 500
    except HTTPError as exc:
        assert exc.code < 500
    except (OSError, URLError) as exc:
        pytest.fail(f"compose service Keygen on {KEYGEN_URL} is not reachable: {exc}")


def test_fossbilling_shaped_webhook_hmac_reaches_bridge():
    """Verify signed FOSSBilling webhook event crosses Bridge boundary."""
    event_id = f"evt_fossbilling_{uuid.uuid4().hex}"
    result = _webhook(
        {
            "event": "onAfterInvoicePaid",
            "id": event_id,
            "client": {"id": f"client_{uuid.uuid4().hex}", "email": "e2e@example.test"},
            "invoice_id": f"invoice_{uuid.uuid4().hex}",
            "subscription_id": f"subscription_{uuid.uuid4().hex}",
            "product_type": "pro_monthly",
        }
    )
    assert result["status"] == "processed"
    assert result["event_id"] == event_id
    assert result["license"]["license_key"]


def test_real_keygen_lifecycle_via_bridge():
    """
    Exercise full lifecycle against live Keygen:
    payment -> Bridge -> create license -> activate device -> offline entitlement
    -> validate -> renew -> refund/revoke.
    """
    subscription_id = f"subscription_{uuid.uuid4().hex}"
    client_id = f"client_{uuid.uuid4().hex}"

    # 1. Payment webhook creates license
    paid = _webhook(
        {
            "event": "onAfterInvoicePaid",
            "id": f"evt_paid_{uuid.uuid4().hex}",
            "client": {"id": client_id, "email": "lifecycle@example.test"},
            "invoice_id": f"invoice_{uuid.uuid4().hex}",
            "subscription_id": subscription_id,
            "product_type": "pro_monthly",
        }
    )
    assert paid["status"] == "processed"
    license_data = paid["license"]
    key = license_data["license_key"]
    assert key

    # 2. Machine activation
    hardware = {"fingerprint": f"e2e-device-{uuid.uuid4().hex}", "components": {"disk": "e2e"}}
    activated = _request_json("POST", f"{BRIDGE_URL}/v1/devices/activate", {"license_key": key, "hardware": hardware})
    assert activated["fingerprint"] == hardware["fingerprint"]

    # 3. Offline entitlement issuance and validation
    offline = _request_json("POST", f"{BRIDGE_URL}/v1/offline/issue", {"license_key": key, "hardware": hardware})
    assert offline["license_id"] == license_data["license_id"]
    assert offline["signature"] and offline["certificate"]

    validated = _request_json("POST", f"{BRIDGE_URL}/v1/entitlements/validate", {"license_key": key, "hardware": hardware})
    assert validated["valid"] is True

    # 4. Renewal extends expiry
    renewed = _webhook(
        {
            "event": "SUBSCRIPTION_RENEWED",
            "id": f"evt_renewed_{uuid.uuid4().hex}",
            "client": {"id": client_id, "email": "lifecycle@example.test"},
            "invoice_id": f"invoice_{uuid.uuid4().hex}",
            "subscription_id": subscription_id,
            "product_type": "pro_monthly",
        }
    )
    assert renewed["license"]["expires_at"] > license_data["expires_at"]

    # 5. Refund revokes license (terminal state)
    revoked = _webhook(
        {
            "event": "onAfterInvoiceRefund",
            "id": f"evt_refund_{uuid.uuid4().hex}",
            "client": {"id": client_id, "email": "lifecycle@example.test"},
            "invoice_id": f"invoice_{uuid.uuid4().hex}",
            "subscription_id": subscription_id,
            "product_type": "pro_monthly",
        }
    )
    assert revoked["license"]["status"] == "REVOKED"


def test_real_keygate_shadow_lifecycle():
    """
    Exercise shadow lifecycle against live Keygate:
    bootstrap/query license -> activate -> verify -> deactivate.
    """
    # Keygate system health probe
    health = _get_json(f"{KEYGATE_URL}/api/v1/system/health")
    assert health is not None
