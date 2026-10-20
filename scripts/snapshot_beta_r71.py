#!/usr/bin/env python3
"""r7.1 cutover snapshot of HISTORICAL BETA USERS (内测用户). One-time, run while shuabao-subscription
is STOPPED, AFTER migrate_r7_test30d_to_pro.py --apply.

Definition (persisted, never re-derived from plan afterwards):
  beta license  := a local_licenses row that exists at snapshot time whose identity is internal
                   (plan test_* / trial_* / other non-formal plan, or stored tier test) and that was NOT
                   converted by the r7 test_30d -> pro_monthly migration (metadata.migrated_r7).
                   Revoked/suspended internal cards count too (the holder was a beta user).
  beta user     := every fingerprint bound (local_activations) to a beta license at snapshot time,
                   plus - later - whoever activates a still-unbound beta license (done by 8010 on
                   activation, see keygen_provider._referral_note_beta).
Writes: data_json.is_beta_user=true + metadata.is_beta_user=true + metadata.beta_snapshot_at on beta
licenses AND on every other license bound to a beta fingerprint (a beta user's Pro card keeps tier
pro but reports is_beta_user=true); INSERT OR IGNORE into beta_users(source='cutover_snapshot').
Users whose ONLY internal card was migrated to pro_monthly are NOT beta (default; Owner may override
with --include-migrated). Default is dry-run; --apply in one BEGIN IMMEDIATE; idempotent; writes an
undo file <db>.r71_beta_undo.<ts>.jsonl (0600: license ids + fingerprints masked? no - full ids/fps
are needed to undo; it contains NO card keys). Output: counts + masked ids only.
"""
import argparse, json, os, sqlite3, sys, time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bridge"))
from bridge.app.services import tiers as T  # noqa: E402
from bridge.app.services.referral import ensure_schema  # noqa: E402


def mid(v):
    v = str(v or "")
    return v if len(v) <= 8 else f"{v[:4]}…{v[-4:]}"


def is_internal(d):
    tier = d.get("tier") if T.is_tier(d.get("tier")) else T.derive_tier(d.get("plan"))
    return tier in T.INTERNAL_TIERS


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    m = ap.add_mutually_exclusive_group()
    m.add_argument("--dry-run", action="store_true", default=True)
    m.add_argument("--apply", action="store_true")
    # r7.1 Owner Q-B1 (13:27): migrated pro_monthly holders ARE beta -> default on; --exclude-migrated to opt out
    ap.add_argument("--exclude-migrated", dest="include_migrated", action="store_false")
    ap.add_argument("--include-migrated", dest="include_migrated", action="store_true", default=True,
                    help="also treat holders of r7-migrated test_30d->pro_monthly cards as beta")
    ap.add_argument("--allow-production-path", action="store_true")
    a = ap.parse_args(argv)
    if os.path.realpath(a.db).startswith("/home/shuabao") and not a.allow_production_path:
        print("refusing production path without --allow-production-path", file=sys.stderr); return 2
    conn = sqlite3.connect(a.db, isolation_level=None, timeout=30)
    if a.apply:
        ensure_schema(conn)
    conn.execute("BEGIN IMMEDIATE" if a.apply else "BEGIN")
    try:
        lic = {r[0]: json.loads(r[1]) for r in conn.execute("SELECT id, data_json FROM local_licenses")}
        acts = conn.execute("SELECT license_id, lower(fingerprint) FROM local_activations").fetchall()
        bound = {}
        for lid, fp in acts:
            bound.setdefault(lid, set()).add(fp)
        migrated = {i for i, d in lic.items() if (d.get("metadata") or {}).get("migrated_r7")}
        beta_lic = {i for i, d in lic.items() if is_internal(d) or (a.include_migrated and i in migrated)}
        beta_fp = set()
        for i in beta_lic:
            beta_fp |= bound.get(i, set())
        flag = set(beta_lic) | {i for i, fps in bound.items() if fps & beta_fp}
        has_tbl = conn.execute("SELECT 1 FROM sqlite_master WHERE name='beta_users'").fetchone()
        known = {r[0] for r in conn.execute("SELECT fingerprint FROM beta_users")} if has_tbl else set()
        new_fp = beta_fp - known
        to_flag = {i for i in flag if not T.is_beta_record(lic[i])}
        migrated_only = {fp for i in migrated for fp in bound.get(i, set())} - beta_fp
        rep = {"mode": "apply" if a.apply else "dry-run", "licenses_total": len(lic),
               "beta_licenses_internal": len(beta_lic), "beta_licenses_unbound": sum(1 for i in beta_lic if i not in bound),
               "beta_fingerprints": len(beta_fp), "beta_fingerprints_new": len(new_fp),
               "licenses_to_flag": len(to_flag), "licenses_already_flagged": len(flag) - len(to_flag),
               "formal_licenses_of_beta_users": len(flag - beta_lic),
               "migrated_pro_monthly_holders_not_beta": len(migrated_only),
               "include_migrated": a.include_migrated, "sample_license_ids_masked": [mid(x) for x in sorted(to_flag)[:10]]}
        if a.apply and (to_flag or new_fp):
            now = datetime.now(timezone.utc).isoformat()
            undo = f"{a.db}.r71_beta_undo.{time.strftime('%Y%m%dT%H%M%S')}.jsonl"
            fd = os.open(undo, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                for i in sorted(to_flag):
                    d = lic[i]; d["is_beta_user"] = True
                    meta = dict(d.get("metadata") or {}); meta["is_beta_user"] = True; meta["beta_snapshot_at"] = now
                    d["metadata"] = meta
                    conn.execute("UPDATE local_licenses SET data_json=? WHERE id=?", (json.dumps(d, default=str), i))
                    fh.write(json.dumps({"license_id": i}) + "\n")
                for fp in sorted(new_fp):
                    first = sorted(x for x in beta_lic if fp in bound.get(x, set()))[0]
                    conn.execute("INSERT OR IGNORE INTO beta_users VALUES (?,?,?,?)", (fp, first, "cutover_snapshot", now))
                    fh.write(json.dumps({"beta_fingerprint": fp}) + "\n")
                fh.flush(); os.fsync(fh.fileno())
            rep["undo_file"] = undo
        conn.execute("COMMIT" if a.apply else "ROLLBACK")
    except BaseException:
        conn.execute("ROLLBACK"); raise
    print(json.dumps(rep, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
