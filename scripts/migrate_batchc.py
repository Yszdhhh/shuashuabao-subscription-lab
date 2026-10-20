#!/usr/bin/env python3
"""BATCH C DB migration for subscription_state.db (additive only).

  up      CREATE TABLE IF NOT EXISTS referral_rewards (+ index). Idempotent. The service
          also runs this at start-up (SqliteEventStore._init_schema).
  down    export referral_rewards to <db>.referral_rewards.<ts>.jsonl (0600), then DROP it.
          Does NOT revert expiries already extended by rewards (they are real entitlement
          changes; the export lists prev/new expiry per row for manual review).
  status  print table presence and row count.
No change to local_licenses columns: plan/tier/tier_name live in data_json; legacy rows
derive tier from plan at read time (no backfill). Old code ignores the extra JSON keys.
"""
import argparse, json, os, sqlite3, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bridge"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from bridge.app.services.referral import ROLLBACK_SQL, SCHEMA_SQL  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=("up", "down", "status"))
    ap.add_argument("--db", required=True)
    ap.add_argument("--allow-production-path", action="store_true",
                    help="required for paths under /home/shuabao (needs Owner approval)")
    a = ap.parse_args(argv)
    if os.path.realpath(a.db).startswith("/home/shuabao") and not a.allow_production_path:
        print("refusing production path without --allow-production-path", file=sys.stderr); return 2
    conn = sqlite3.connect(a.db, isolation_level=None, timeout=30)
    has = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='referral_rewards'").fetchone()
    if a.action == "status":
        n = conn.execute("SELECT COUNT(*) FROM referral_rewards").fetchone()[0] if has else 0
        print(json.dumps({"referral_rewards": bool(has), "rows": n})); return 0
    if a.action == "up":
        conn.executescript(SCHEMA_SQL); print("up: ok"); return 0
    if has:
        path = f"{a.db}.referral_rewards.{time.strftime('%Y%m%dT%H%M%S')}.jsonl"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        cur = conn.execute("SELECT * FROM referral_rewards")
        cols = [c[0] for c in cur.description]
        with os.fdopen(fd, "w") as fh:
            for r in cur:
                fh.write(json.dumps(dict(zip(cols, r))) + "\n")
        print("exported", path)
    conn.executescript("BEGIN IMMEDIATE;" + ROLLBACK_SQL + "COMMIT;")
    print("down: ok"); return 0


if __name__ == "__main__":
    sys.exit(main())
