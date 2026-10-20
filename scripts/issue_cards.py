#!/usr/bin/env python3
"""BATCH C / r7 formal/test card issuance via POST /admin/licenses/create-test (loopback only).

  SUBSCRIPTION_ADMIN_TOKEN=... python scripts/issue_cards.py --base http://127.0.0.1:8010 \
      --tier plus --count 5 --out /secure/dir/plus_batch.tsv

r7 Owner rulings:
* go/plus/pro default to starts_on_first_activation=True (clock starts on first activation);
  --no-starts-on-first-activation or --expires-at <ISO8601+tz> overrides.
* ultra requires --confirm-ultra (server also requires confirm_ultra:true and writes an audit entry);
  expiry is fixed at 2099-12-31T23:59:59+00:00.
* --plan accepts canonical plans and aliases (go_daily, plus_weekly, pro_monthly, ultra_permanent).
* Auth: X-Admin-Token from $SUBSCRIPTION_ADMIN_TOKEN (preferred) or Basic from
  $SUBSCRIPTION_ADMIN_USER/$SUBSCRIPTION_ADMIN_PASSWORD. Only loopback base URLs are accepted.
* Full keys go ONLY to --out (mode 0600, must not exist); stdout shows ids + masked keys (first4…last4).
"""
import argparse, base64, json, os, sys, urllib.error, urllib.parse, urllib.request

TIERS = ("go", "plus", "pro", "ultra", "test")
PLAN_TIER = {"go_1d": "go", "go_daily": "go", "plus_7d": "plus", "plus_weekly": "plus", "pro_30d": "pro",
             "pro_monthly": "pro", "ultra_lifetime": "ultra", "ultra_permanent": "ultra", "trial_1d": "test"}


def mask(v: str) -> str:
    return v if len(v) <= 8 else f"{v[:4]}…{v[-4:]}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--tier", choices=TIERS)
    ap.add_argument("--plan", choices=sorted(PLAN_TIER))
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--days", type=int, default=1, help="tier=test only")
    ap.add_argument("--device-limit", type=int, default=1)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--starts-on-first-activation", dest="sofa", action="store_true", default=None)
    g.add_argument("--no-starts-on-first-activation", dest="sofa", action="store_false")
    ap.add_argument("--expires-at", default=None, help="explicit ISO-8601 expiry with tz (overrides first-activation)")
    ap.add_argument("--confirm-ultra", action="store_true")
    ap.add_argument("--customer-id", default="formal-batch")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    tier = a.tier or (PLAN_TIER.get(a.plan) if a.plan else None)
    if not tier:
        print("--tier or --plan required", file=sys.stderr); return 2
    if a.plan and PLAN_TIER[a.plan] != tier:
        print("--plan does not match --tier", file=sys.stderr); return 2
    if tier == "ultra" and not a.confirm_ultra:
        print("ULTRA_CONFIRM_REQUIRED: pass --confirm-ultra to issue lifetime cards", file=sys.stderr); return 2
    host = urllib.parse.urlparse(a.base).hostname
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("refusing non-loopback base URL", file=sys.stderr); return 2
    if not 1 <= a.count <= 500:
        print("count must be 1..500", file=sys.stderr); return 2
    headers = {"Content-Type": "application/json"}
    tok = (os.environ.get("SUBSCRIPTION_ADMIN_TOKEN") or "").strip()
    pw = os.environ.get("SUBSCRIPTION_ADMIN_PASSWORD") or ""
    if tok:
        headers["X-Admin-Token"] = tok
    elif pw:
        user = os.environ.get("SUBSCRIPTION_ADMIN_USER") or "admin"
        headers["Authorization"] = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    else:
        print("SUBSCRIPTION_ADMIN_TOKEN (or SUBSCRIPTION_ADMIN_PASSWORD) not set", file=sys.stderr); return 2
    body = {"tier": tier, "days": a.days, "device_limit": a.device_limit,
            "customer_id": a.customer_id, "issued_by": "issue_cards.py"}
    if a.plan:
        body["plan"] = a.plan
    if a.sofa is not None:
        body["starts_on_first_activation"] = a.sofa
    if a.expires_at:
        body["expires_at"] = a.expires_at
    if tier == "ultra":
        body["confirm_ultra"] = True
    fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    n_ok = 0
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write("license_id\tlicense_key\tplan\ttier\ttier_name\texpires_at\tstarts_on_first_activation\n")
        for _ in range(a.count):
            req = urllib.request.Request(a.base.rstrip("/") + "/admin/licenses/create-test",
                                         data=json.dumps(body).encode(), method="POST", headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    d = json.loads(r.read())
            except urllib.error.HTTPError as e:
                print(f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:200]}", file=sys.stderr)
                return 1
            out.write("\t".join(str(d.get(k) if d.get(k) is not None else "") for k in
                                ("license_id", "license_key", "plan", "tier", "tier_name", "expires_at",
                                 "starts_on_first_activation")) + "\n")
            out.flush()
            n_ok += 1
            print(d["license_id"], mask(d["license_key"]), d["plan"], d["tier"], d["tier_name"],
                  d.get("expires_at"), "first_act=" + str(d.get("starts_on_first_activation")))
    print(f"issued={n_ok} out={a.out} (0600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
