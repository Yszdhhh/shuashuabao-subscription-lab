#!/usr/bin/env python3
"""BATCH C formal/test card issuance via POST /admin/licenses/create-test.

  SUBSCRIPTION_ADMIN_PASSWORD=... python scripts/issue_cards.py --base http://127.0.0.1:8010 \
      --tier plus --count 5 --out /secure/dir/plus_batch.tsv [--starts-on-first-activation]

* tier is chosen directly (go|plus|pro|ultra|test); --days only applies to tier=test.
* Only loopback base URLs are accepted. Full keys go ONLY to --out (mode 0600, must not
  exist); stdout shows license ids and masked keys (first 4 + last 4).
"""
import argparse, base64, json, os, sys, urllib.parse, urllib.request

TIERS = ("go", "plus", "pro", "ultra", "test")


def mask(v: str) -> str:
    return v if len(v) <= 8 else f"{v[:4]}…{v[-4:]}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--tier", required=True, choices=TIERS)
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--days", type=int, default=1, help="tier=test only")
    ap.add_argument("--device-limit", type=int, default=1)
    ap.add_argument("--starts-on-first-activation", action="store_true")
    ap.add_argument("--customer-id", default="formal-batch")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    host = urllib.parse.urlparse(a.base).hostname
    if host not in ("127.0.0.1", "localhost"):
        print("refusing non-loopback base URL", file=sys.stderr); return 2
    if not 1 <= a.count <= 500:
        print("count must be 1..500", file=sys.stderr); return 2
    pw = os.environ.get("SUBSCRIPTION_ADMIN_PASSWORD") or ""
    user = os.environ.get("SUBSCRIPTION_ADMIN_USER") or "admin"
    if not pw:
        print("SUBSCRIPTION_ADMIN_PASSWORD not set", file=sys.stderr); return 2
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write("license_id\tlicense_key\tplan\ttier\ttier_name\texpires_at\n")
        for _ in range(a.count):
            body = json.dumps({"tier": a.tier, "days": a.days, "device_limit": a.device_limit,
                               "starts_on_first_activation": a.starts_on_first_activation,
                               "customer_id": a.customer_id, "issued_by": "issue_cards.py"}).encode()
            req = urllib.request.Request(a.base.rstrip("/") + "/admin/licenses/create-test", data=body,
                                         method="POST", headers={"Content-Type": "application/json",
                                                                 "Authorization": auth})
            with urllib.request.urlopen(req, timeout=10) as r:
                d = json.loads(r.read())
            out.write("\t".join(str(d.get(k) or "") for k in
                                ("license_id", "license_key", "plan", "tier", "tier_name", "expires_at")) + "\n")
            print(d["license_id"], mask(d["license_key"]), d["plan"], d["tier"], d["tier_name"], d.get("expires_at"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
