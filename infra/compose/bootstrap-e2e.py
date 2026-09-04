import json
import os
import sys
import time
import urllib.error
import urllib.request

KEYGEN_URL = os.getenv("KEYGEN_URL", "http://localhost:3000")
KEYGATE_URL = os.getenv("KEYGATE_URL", "http://localhost:9000")

def req(url: str, method: str = "GET", body: dict = None, headers: dict = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/vnd.api+json", "Accept": "application/vnd.api+json", **(headers or {})}
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw.decode(errors="ignore")}
    except Exception as e:
        return 500, {"error": str(e)}

def wait_for(name: str, url: str, timeout: int = 60) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        status, _ = req(url)
        if status in (200, 204, 404):
            print(f"{name} is UP ({status})")
            return True
        time.sleep(2)
    print(f"{name} FAILED to respond within {timeout}s")
    return False

def bootstrap_keygen():
    print("Waiting for Keygen...")
    if not wait_for("Keygen", f"{KEYGEN_URL}/v1/health", 90):
        print("Keygen unreachable, skipping direct bootstrap")
        return

    # In Keygen singleplayer, the setup command creates account + admin + token,
    # or we can create them via CLI / API.
    print("Keygen container is ready.")

def bootstrap_keygate():
    print("Waiting for Keygate...")
    if not wait_for("Keygate", f"{KEYGATE_URL}/api/v1/version", 60):
        print("Keygate unreachable, skipping bootstrap")
        return
    print("Keygate container is ready.")

def main():
    bootstrap_keygen()
    bootstrap_keygate()

if __name__ == "__main__":
    main()
