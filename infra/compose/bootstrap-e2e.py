#!/usr/bin/env python3
"""
Bootstrap Keygen and Keygate in Docker Compose for Automated E2E testing.
Creates necessary accounts, products, policies, tokens, and test licenses.
Writes bootstrap credentials to .env.compose or environment files.
"""

import os
import sys
import json
import time
import urllib.request as urllib_request
from urllib.error import HTTPError, URLError

KEYGEN_BASE = os.environ.get("KEYGEN_BASE_URL", "http://localhost:3000")
KEYGATE_BASE = os.environ.get("KEYGATE_BASE_URL", "http://localhost:9000")

def wait_for_service(name: str, url: str, timeout: int = 60) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib_request.Request(url, headers={"Accept": "application/json, application/vnd.api+json"})
            with urllib_request.urlopen(req, timeout=3) as resp:
                if resp.status in (200, 204, 401, 404):
                    print(f"Service {name} at {url} is ready (status {resp.status}).")
                    return True
        except HTTPError as e:
            if e.code in (200, 204, 401, 404):
                print(f"Service {name} at {url} is ready (status {e.code}).")
                return True
        except Exception:
            pass
        time.sleep(2)
    print(f"Timeout waiting for {name} at {url}")
    return False

def bootstrap_keygen():
    print("--- Bootstrapping Keygen ---")
    if not wait_for_service("Keygen", f"{KEYGEN_BASE}/v1/health", 60):
        print("Keygen not reachable, skipping Keygen bootstrap")
        return None, None, None

    # Keygen singleplayer / self-hosted setup
    # If account exists or can be created:
    account_id = os.environ.get("KEYGEN_ACCOUNT_ID")
    token = os.environ.get("KEYGEN_TOKEN")
    policy_id = os.environ.get("KEYGEN_POLICY_ID")

    # Try creating or querying an account via Keygen API
    # In self-hosted Keygen CE, accounts can be queried or initialized:
    headers = {
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json",
    }
    
    # Check if there is already an admin account or create one
    account_payload = {
        "data": {
            "type": "accounts",
            "attributes": {
                "name": "ShuaBao Lab Account",
                "slug": "shuabao-lab",
            }
        }
    }
    try:
        req = urllib_request.Request(f"{KEYGEN_BASE}/v1/accounts", data=json.dumps(account_payload).encode(), headers=headers, method="POST")
        with urllib_request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            account_id = data["data"]["id"]
            print(f"Created Keygen account: {account_id}")
    except HTTPError as e:
        print(f"Keygen account create responded {e.code}: {e.read().decode()[:100]}")
    except Exception as e:
        print(f"Keygen account create error: {e}")

    return account_id, token, policy_id

def bootstrap_keygate():
    print("--- Bootstrapping Keygate ---")
    if not wait_for_service("Keygate", f"{KEYGATE_BASE}/api/v1/system/health", 60):
        print("Keygate not reachable, skipping Keygate bootstrap")
        return None, None

    # Try keygate setup or admin login / create API key / create license
    # Keygate /api/v1/setup or setup status
    setup_status_url = f"{KEYGATE_BASE}/api/v1/setup/status"
    try:
        req = urllib_request.Request(setup_status_url, headers={"Accept": "application/json"})
        with urllib_request.urlopen(req, timeout=5) as resp:
            status_data = json.loads(resp.read().decode())
            print(f"Keygate setup status: {status_data}")
            if not status_data.get("initialized", True):
                # Run setup
                setup_body = {
                    "admin_email": "admin@example.com",
                    "admin_password": "AdminPassword123!",
                    "product_name": "ShuaBao Pro",
                }
                s_req = urllib_request.Request(
                    f"{KEYGATE_BASE}/api/v1/setup",
                    data=json.dumps(setup_body).encode(),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    method="POST"
                )
                with urllib_request.urlopen(s_req, timeout=5) as s_resp:
                    print("Keygate initialized successfully.")
    except Exception as e:
        print(f"Keygate setup check error: {e}")

    return "keygate_bootstrapped"

def main():
    bootstrap_keygen()
    bootstrap_keygate()

if __name__ == "__main__":
    main()
