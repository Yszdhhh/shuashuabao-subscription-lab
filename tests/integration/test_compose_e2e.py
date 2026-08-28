"""Opt-in lifecycle probes for the services started by docker compose.

CI sets COMPOSE_E2E=1 after starting the stack.  Keygen and Keygate mutation
probes additionally require credentials/license material provisioned by the
operator; without those values the health/smoke checks still run.
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
    if not WEBHOOK_SECRET:
        pytest.skip("FOSSBILLING_WEBHOOK_SECRET is required for signed webhook E2E")
    raw = json.dumps(payload, separators=(",", ":")).encode()
    signature = "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return _request_json(
        "POST",
        f"{BRIDGE_URL}/v1/webhooks/fossbilling",
        payload,
        {"X-FOSSBilling-Signature": signature},
    )


def test_bridge_health_and_provider_selection():
    health = _get_json(f"{BRIDGE_URL}/health")
    assert health["status"] == "healthy"
    assert health["active_provider"] == "keygen"


def test_keygate_health_and_keygen_reachability():
    health = _get_json(f"{KEYGATE_URL}/health")
    assert health["status"] == "ok"
    try:
        with urlopen("http://127.0.0.1:3000/health", timeout=10) as response:
            assert response.status < 500
    except HTTPError as exc:
        assert exc.code < 500
    except (OSError, URLError) as exc:
        pytest.fail(f"compose service on port 3000 is not reachable: {exc}")


def test_fossbilling_webhook_hmac_reaches_bridge():
    """A FOSSBilling-shaped event must cross the signed Bridge boundary."""
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
    """Exercise payment -> Keygen -> activation -> offline -> renew -> refund."""
    if not os.getenv("KEYGEN_ACCOUNT_ID") or not os.getenv("KEYGEN_TOKEN"):
        pytest.skip("KEYGEN_ACCOUNT_ID and KEYGEN_TOKEN provision a real Keygen account")
    subscription_id = f"subscription_{uuid.uuid4().hex}"
    client_id = f"client_{uuid.uuid4().hex}"
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
    license_data = paid["license"]
    key = license_data["license_key"]
    hardware = {"fingerprint": f"e2e-device-{uuid.uuid4().hex}", "components": {"disk": "e2e"}}

    activated = _request_json("POST", f"{BRIDGE_URL}/v1/devices/activate", {"license_key": key, "hardware": hardware})
    assert activated["fingerprint"] == hardware["fingerprint"]
    offline = _request_json("POST", f"{BRIDGE_URL}/v1/offline/issue", {"license_key": key, "hardware": hardware})
    assert offline["license_id"] == license_data["license_id"]
    assert offline["signature"] and offline["certificate"]
    validated = _request_json("POST", f"{BRIDGE_URL}/v1/entitlements/validate", {"license_key": key, "hardware": hardware})
    assert validated["valid"] is True

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


def test_real_keygate_shadow_license_lifecycle():
    """Exercise the public activation/verify/deactivate API on real Keygate."""
    license_key = os.getenv("KEYGATE_LICENSE_KEY")
    if not license_key:
        pytest.skip("KEYGATE_LICENSE_KEY must identify a provisioned shadow license")
    identifier = f"shadow-device-{uuid.uuid4().hex}"
    activated = _request_json(
        "POST",
        f"{KEYGATE_URL}/api/v1/license/activate",
        {"license_key": license_key, "identifier": identifier, "identifier_type": "hardware"},
    )
    assert activated.get("status") in {"ok", "active", "activated"}
    verified = _request_json(
        "POST", f"{KEYGATE_URL}/api/v1/license/verify", {"license_key": license_key, "identifier": identifier}
    )
    assert verified.get("valid") is True or verified.get("status") in {"ok", "active"}
    deactivated = _request_json(
        "POST", f"{KEYGATE_URL}/api/v1/license/deactivate", {"license_key": license_key, "identifier": identifier}
    )
    assert deactivated.get("status") in {"ok", "deactivated"}
