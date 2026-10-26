#!/usr/bin/env python3
"""Read-only comparison of local PiP grants against baseline 8064f4b.

Run on an operator-provided SQLite backup. No provider, key loading, schema
migration or beta backfill is invoked; only aggregate counts are printed.
"""
import argparse
import json
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bridge.app.services import tiers  # noqa: E402


def baseline_has_pip(rec):
    """Freeze the pre-F07 local DTO rule so future tier edits cannot alter the comparison."""
    if "pip_background" in (rec.get("features") or []):
        return True
    meta = rec.get("metadata") or {}
    tier = rec.get("tier") or meta.get("tier")
    beta = rec.get("is_beta_user") is True or meta.get("is_beta_user") is True
    plan = str(rec.get("plan") or "")
    regular_trial = (tier not in ("test", "beta") and not beta and (
        tier == "trial" or meta.get("is_trial") is True or plan == "trial_1d_auto"))
    if regular_trial:
        return False
    if tier in ("go", "plus", "pro", "max", "ultra", "test", "beta", "trial"):
        return tier in ("test", "beta")
    if beta:
        return True
    # In 8064f4b, every unmapped plan fell back to test, including empty plans.
    formal_plans = {"go_1d", "plus_7d", "pro_30d", "ultra_lifetime", "pro_monthly",
                    "pro_annual", "enterprise", "go_daily", "plus_daily", "pro_weekly",
                    "max_monthly", "plus_weekly", "ultra_permanent"}
    return plan != "trial_1d_auto" and plan.strip() not in formal_plans


def inventory(db):
    counts = {"cards_total": 0, "pip_before": 0, "pip_after": 0,
              "pip_lost": 0, "pip_gained": 0, "unchanged": 0}
    by_status = {}
    # mode=ro refuses missing files and writes; query_only also forbids accidental SQL writes.
    conn = sqlite3.connect(Path(db).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        for (raw,) in conn.execute("SELECT data_json FROM local_licenses"):
            rec = json.loads(raw)
            before = baseline_has_pip(rec)
            after = "pip_background" in tiers.license_features(rec)
            change = "pip_lost" if before and not after else "pip_gained" if after and not before else "unchanged"
            counts["cards_total"] += 1
            counts["pip_before"] += int(before)
            counts["pip_after"] += int(after)
            counts[change] += 1
            bucket = by_status.setdefault(str(rec.get("status") or "UNKNOWN"),
                                          {"pip_lost": 0, "pip_gained": 0, "unchanged": 0})
            bucket[change] += 1
    finally:
        conn.close()
    return {"baseline": "8064f4b", "read_only": True, **counts, "by_status": by_status}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, help="Path to an existing SQLite backup (read-only)")
    args = parser.parse_args(argv)
    print(json.dumps(inventory(args.db), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
