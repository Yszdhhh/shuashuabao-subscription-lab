#!/usr/bin/env python3
"""Mirror client-dashboard trial claims into the trial-claim service dir.

The trial-claim service is sandboxed (NoNewPrivileges, read-only home) and
runs as ubuntu, so it cannot query the subscription DB itself. This root
cron job publishes a minimal read-only mirror every minute:
{fingerprint: {key, status, plan, expires_at, is_beta_user}}.
"""
import fcntl
import grp
import json
import os
import sqlite3
import sys
import tempfile

DB = "/home/shuabao/services/data/subscription_state.db"
sys.path.insert(0, "/home/shuabao/services/subscription-lab")
from bridge.app.services.current_license import select_current

OUT = "/home/shuabao/services/trial-claim/dashboard_claims.json"


def main():
    with open(os.path.join(os.path.dirname(OUT), "pool.lock"), "a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        return sync()


def sync():
    con = sqlite3.connect("file:%s?mode=ro" % DB, uri=True, timeout=5)
    try:
        rows = con.execute(
            "SELECT a.fingerprint, l.data_json FROM local_activations a "
            "JOIN local_licenses l ON l.id = a.license_id").fetchall()
        beta = {r[0] for r in con.execute("SELECT fingerprint FROM beta_users")}
    finally:
        con.close()
    candidates = {}
    for fp, dj in rows:
        candidates.setdefault(fp, []).append(json.loads(dj))
    out = {}
    for fp, records in candidates.items():
        current = select_current(records, beta=fp in beta)
        out[fp] = {**current, "key": current["card"]}
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(OUT), prefix=".dash-",
                               suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, separators=(",", ":"))
    # The directory carries default ACLs; a bare chmod would only change the
    # ACL mask and leave the owning-group entry empty, denying ubuntu reads.
    try:
        import subprocess
        subprocess.run(["setfacl", "-b", tmp], check=False,
                       capture_output=True, timeout=5)
    except Exception:
        pass
    os.chown(tmp, 0, grp.getgrnam("ubuntu").gr_gid)
    os.chmod(tmp, 0o640)
    os.rename(tmp, OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
