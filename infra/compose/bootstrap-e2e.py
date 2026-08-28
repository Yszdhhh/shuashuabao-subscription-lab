import json
import os
import sys
import time
from urllib import request as urllib_request, error as urllib_error

KEYGEN_BASE = os.getenv("KEYGEN_BASE_URL", "http://localhost:3000")
KEYGATE_BASE = os.getenv("KEYGATE_BASE_URL", "http://localhost:9000")

def wait_for_service(name: str, url: str, timeout: int = 60) -> bool:
    start = time.time()
    print(f"Waiting for {name} at {url}...")
    while time.time() - start < timeout:
        try:
            req = urllib_request.Request(url, headers={"Accept": "application/json"})
            with urllib_request.urlopen(req, timeout=3) as resp:
                if resp.status in (200, 204, 404):
                    print(f"{name} is reachable (HTTP {resp.status})")
                    return True
        except Exception:
            time.sleep(2)
    print(f"{name} was not reachable within {timeout}s")
    return False

def main():
    wait_for_service("Keygen", f"{KEYGEN_BASE}/v1/health", 60)
    wait_for_service("Keygate", f"{KEYGATE_BASE}/api/v1/system/health", 60)
    print("Bootstrap check completed.")

if __name__ == "__main__":
    main()
