#!/usr/bin/env python3
"""r7 Owner ruling 2: one-time migration test_30d -> pro_monthly (Pro 订阅).

Targets: local_licenses rows with plan == 'test_30d' that are ACTIVATED or SOLD.
  activated := a local_activations row exists for the license, OR metadata.activated_clock_started_at is set
  sold      := a subscription_bindings row maps to the license (FOSSBilling order binding), OR
               metadata.sold is true / metadata.sold_at is set, OR the id is listed in --sold-list
               (one license_id per line, supplied by Owner).
  The schema has NO dedicated "sold" column; customer_id/customer_email are NOT used as a sale signal
  (reported only, as `unsold_with_customer_hint`) -> Owner decides (待Owner决定).
Unsold, never-activated test_30d cards are left unchanged. REVOKED rows are left unchanged (reported).

Default is --dry-run (no writes). --apply writes in ONE BEGIN IMMEDIATE transaction:
  plan='pro_monthly', tier='pro', tier_name='Pro 订阅', metadata.migrated_r7={from_plan, at, reason}
and writes an undo file <db>.r7_test30d_undo.<ts>.jsonl (0600; id + previous plan/tier only, no keys).
Idempotent: only rows still on plan 'test_30d' are selected; a second run reports 0 to migrate.
MUST run while shuabao-subscription is STOPPED (the service caches licenses in memory and would
overwrite data_json on its next save). Output: counts and masked ids (lic_…last4) only.
"""
import argparse, json, os, sqlite3, sys, time
from datetime import datetime, timezone

SRC_PLAN, DST_PLAN, DST_TIER, DST_NAME = "test_30d", "pro_monthly", "pro", "Pro 订阅"
DEFAULT_CUST = {"", "manual-test", "formal-batch", "none", "null"}


def mid(v):
    v = str(v or "")
    return v if len(v) <= 8 else f"{v[:4]}…{v[-4:]}"


def has_table(c, n):
    return c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (n,)).fetchone() is not None


def classify(conn, sold_list):
    act = {r[0] for r in conn.execute("SELECT DISTINCT license_id FROM local_activations")} \
        if has_table(conn, "local_activations") else set()
    bound = {r[0] for r in conn.execute("SELECT DISTINCT license_id FROM subscription_bindings")} \
        if has_table(conn, "subscription_bindings") else set()
    out = {"migrate": [], "skip_unsold_unactivated": [], "skip_revoked": [], "unsold_with_customer_hint": [],
           "variant_plans_not_migrated": {}, "already_pro_monthly_r7": 0}
    for lid, dj in conn.execute("SELECT id, data_json FROM local_licenses"):
        d = json.loads(dj)
        plan = str(d.get("plan") or "")
        meta = d.get("metadata") or {}
        if plan == DST_PLAN and meta.get("migrated_r7"):
            out["already_pro_monthly_r7"] += 1
        if plan != SRC_PLAN:
            if plan.startswith("test_30d"):
                out["variant_plans_not_migrated"][plan] = out["variant_plans_not_migrated"].get(plan, 0) + 1
            continue
        activated = lid in act or bool(meta.get("activated_clock_started_at"))
        sold = lid in bound or meta.get("sold") is True or bool(meta.get("sold_at")) or lid in sold_list
        if str(getattr(d.get("status"), "value", d.get("status")) or "").lower() == "revoked":
            out["skip_revoked"].append(lid); continue
        if activated or sold:
            out["migrate"].append((lid, d, "activated" if activated else "sold", activated, sold))
        else:
            out["skip_unsold_unactivated"].append(lid)
            if str(d.get("customer_id") or "").strip().lower() not in DEFAULT_CUST or \
               not str(d.get("customer_email") or "").endswith("example.invalid"):
                out["unsold_with_customer_hint"].append(lid)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    m = ap.add_mutually_exclusive_group()
    m.add_argument("--dry-run", action="store_true", default=True)
    m.add_argument("--apply", action="store_true")
    ap.add_argument("--sold-list", help="file with one license_id per line (Owner-supplied)")
    ap.add_argument("--allow-production-path", action="store_true")
    a = ap.parse_args(argv)
    if os.path.realpath(a.db).startswith("/home/shuabao") and not a.allow_production_path:
        print("refusing production path without --allow-production-path", file=sys.stderr); return 2
    if not os.path.exists(a.db):
        print("db not found", file=sys.stderr); return 2
    sold_list = set()
    if a.sold_list:
        sold_list = {ln.strip() for ln in open(a.sold_list, encoding="utf-8") if ln.strip() and not ln.startswith("#")}
    conn = sqlite3.connect(a.db, isolation_level=None, timeout=30)
    conn.execute("BEGIN IMMEDIATE" if a.apply else "BEGIN")
    try:
        c = classify(conn, sold_list)
        by_reason = {"activated": 0, "sold_only": 0}
        for (_l, _d, _r, act, sold) in c["migrate"]:
            by_reason["activated" if act else "sold_only"] += 1
        report = {"mode": "apply" if a.apply else "dry-run", "source_plan": SRC_PLAN, "target_plan": DST_PLAN,
                  "to_migrate": len(c["migrate"]), "to_migrate_by_reason": by_reason,
                  "unchanged_unsold_unactivated": len(c["skip_unsold_unactivated"]),
                  "unchanged_revoked": len(c["skip_revoked"]),
                  "unsold_with_customer_hint": len(c["unsold_with_customer_hint"]),
                  "variant_plans_not_migrated": c["variant_plans_not_migrated"],
                  "already_migrated_r7": c["already_pro_monthly_r7"],
                  "sold_list_entries": len(sold_list),
                  "sample_ids_masked": [mid(x[0]) for x in c["migrate"][:10]]}
        if a.apply and c["migrate"]:
            ts = time.strftime("%Y%m%dT%H%M%S")
            undo = f"{a.db}.r7_test30d_undo.{ts}.jsonl"
            fd = os.open(undo, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            now = datetime.now(timezone.utc).isoformat()
            with os.fdopen(fd, "w") as fh:
                for (lid, d, reason, _a, _s) in c["migrate"]:
                    fh.write(json.dumps({"id": lid, "prev_plan": d.get("plan"), "prev_tier": d.get("tier"),
                                         "prev_tier_name": d.get("tier_name")}) + "\n")
                    d["plan"], d["tier"], d["tier_name"] = DST_PLAN, DST_TIER, DST_NAME
                    meta = dict(d.get("metadata") or {})
                    meta["tier"] = DST_TIER
                    meta["migrated_r7"] = {"from_plan": SRC_PLAN, "at": now, "reason": reason}
                    d["metadata"] = meta
                    conn.execute("UPDATE local_licenses SET data_json=? WHERE id=?", (json.dumps(d, default=str), lid))
                fh.flush(); os.fsync(fh.fileno())
            report["undo_file"] = undo
            report["migrated"] = len(c["migrate"])
        conn.execute("COMMIT" if a.apply else "ROLLBACK")
    except BaseException:
        conn.execute("ROLLBACK"); raise
    print(json.dumps(report, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
