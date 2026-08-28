"""Smoke tests for the running subscription-lab compose stack.

The suite is opt-in because the local unit-test command does not start Docker.
CI sets COMPOSE_E2E=1 after bringing the stack up.
"""
import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

import pytest


pytestmark = pytest.mark.skipif(
    os.getenv("COMPOSE_E2E") != "1",
    reason="set COMPOSE_E2E=1 after starting infra/compose/docker-compose.yml",
)


def _get_json(url: str) -> dict:
    try:
        with urlopen(url, timeout=10) as response:
            assert response.status == 200
            return json.load(response)
    except (OSError, URLError) as exc:
        pytest.fail(f"compose service is not reachable at {url}: {exc}")


def test_bridge_health_and_provider_selection():
    health = _get_json("http://127.0.0.1:8000/health")
    assert health["status"] == "healthy"
    assert health["active_provider"] == "keygen"


def test_keygate_and_keygen_ports_are_reachable():
    # Keygate exposes a DB-backed health endpoint; this proves the shadow
    # service is live rather than merely having a bound TCP port.
    keygate_health = _get_json("http://127.0.0.1:8080/health")
    assert keygate_health["status"] == "ok"

    # Keygen's endpoint shape varies by image version; an HTTP response proves
    # the container is reachable without coupling this smoke test to its API.
    try:
        with urlopen("http://127.0.0.1:3000/health", timeout=10) as response:
            assert response.status < 500
    except OSError as exc:
        pytest.fail(f"compose service on port 3000 is not reachable: {exc}")
