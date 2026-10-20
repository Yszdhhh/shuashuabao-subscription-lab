"""BATCH C: referral reward = extend the inviter's existing subscription in place.

Called only by POST /internal/referrals/reward-extend (loopback + shared secret).
All reads and writes for one reward happen in ONE SQLite ``BEGIN IMMEDIATE``
transaction on subscription_state.db, so two approvals racing for the same invitee
(even from different connections/processes) can never both extend: the second one
waits for the write lock, then sees the ledger row (PRIMARY KEY invitee_fingerprint).

Selection rule (inviter with several bound licenses): among licenses currently bound
to the inviter fingerprint (local_activations) that are NOT revoked and NOT suspended,
pick the most recently activated binding (activation.activated_at DESC, then
license_id DESC as a deterministic tie-break).
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from bridge.app.services import tiers as _tiers

REWARD = timedelta(hours=24)
REF_BONUS_CAP_DEFAULT = 10
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REVIEW_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS referral_rewards (
    invitee_fingerprint TEXT PRIMARY KEY,
    inviter_fingerprint TEXT NOT NULL,
    inviter_license_id  TEXT NOT NULL,
    review_id           TEXT NOT NULL,
    rewarded_at         TEXT NOT NULL,
    action              TEXT NOT NULL,
    prev_expires_at     TEXT,
    new_expires_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_referral_rewards_inviter ON referral_rewards(inviter_fingerprint);
"""
# r7 (Owner rulings 6/7): ledger row status. Only 'applied' counts toward REF_BONUS_CAP.
#   applied          inviter license extended by +24h
#   pending          NO_ELIGIBLE_LICENSE (inviter has no bound card / only never-activated cards);
#                    applied automatically when the inviter activates a card (apply_pending)
#   ultra_immutable  inviter's card is Ultra (lifetime) - recorded, NOT counted, expiry unchanged
#   rejected         pending row that could not be applied (cap reached at activation time)
R7_COLUMNS = (("status", "TEXT NOT NULL DEFAULT 'applied'"), ("reason", "TEXT"), ("applied_at", "TEXT"))
STATUS_APPLIED, STATUS_PENDING, STATUS_ULTRA, STATUS_REJECTED = "applied", "pending", "ultra_immutable", "rejected"
ROLLBACK_SQL = """
DROP INDEX IF EXISTS idx_referral_rewards_inviter;
DROP TABLE IF EXISTS referral_rewards;
"""

# code -> HTTP status. Body is always {"detail": "CODE: message"}.
ERRORS = {
    "REFERRAL_UNAUTHORIZED": 403,
    "REFERRAL_DISABLED": 503,
    "REFERRAL_BAD_REQUEST": 400,
    "REFERRAL_SELF_INVITE": 409,
    "REFERRAL_ALREADY_REWARDED": 409,
    "REFERRAL_CAP_REACHED": 409,
    "REFERRAL_INVITER_NOT_FOUND": 404,
    "REFERRAL_INVITER_INELIGIBLE": 409,
    "REFERRAL_STORE_BUSY": 503,
}
CODE_NO_ELIGIBLE = "NO_ELIGIBLE_LICENSE"   # r7: HTTP 202, reward kept pending


class ReferralError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.status = ERRORS.get(code, 400)
        self.detail = f"{code}: {message}"


def bonus_cap(env=None) -> int:
    src = os.environ if env is None else env
    try:
        return max(0, int(str(src.get("REF_BONUS_CAP") or REF_BONUS_CAP_DEFAULT)))
    except ValueError:
        return REF_BONUS_CAP_DEFAULT


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    have = {r[1] for r in conn.execute("PRAGMA table_info(referral_rewards)")}
    for col, decl in R7_COLUMNS:          # r7 additive columns (idempotent)
        if col not in have:
            conn.execute(f"ALTER TABLE referral_rewards ADD COLUMN {col} {decl}")


def applied_count(conn, inviter: str) -> int:
    return conn.execute("SELECT COUNT(*) FROM referral_rewards WHERE inviter_fingerprint = ? AND status = ?",
                        (inviter, STATUS_APPLIED)).fetchone()[0]


def open_conn(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def _norm_fp(v: Any, field: str) -> str:
    s = str(v or "").strip().lower()
    if not _HEX64.fullmatch(s):
        raise ReferralError("REFERRAL_BAD_REQUEST", f"{field} must be a 64-char hex fingerprint")
    return s


def _dt(v) -> Optional[datetime]:
    if not v:
        return None
    if isinstance(v, datetime):
        d = v
    else:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _iso(d: Optional[datetime]) -> Optional[str]:
    return None if d is None else d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _status(v) -> str:
    s = getattr(v, "value", v)
    return str(s or "").lower()


def _row_result(row, idempotent: bool, count: int, lic: Optional[dict]) -> dict:
    ident = _tiers.resolve(lic) if lic else {"plan": None, "tier": None, "tier_name": None}
    st = row["status"] if "status" in row.keys() else STATUS_APPLIED
    return {
        "ok": True,
        "status": st,
        **({"code": CODE_NO_ELIGIBLE} if st == STATUS_PENDING else {}),
        "idempotent": idempotent,
        "action": row["action"],
        "inviter_license_id": row["inviter_license_id"],
        "review_id": row["review_id"],
        "rewarded_at": row["rewarded_at"],
        "prev_expires_at": row["prev_expires_at"],
        "expires_at": row["new_expires_at"],
        "invite_count": count,
        **ident,
    }


def _load_lic(conn, lic_id) -> Optional[dict]:
    r = conn.execute("SELECT data_json FROM local_licenses WHERE id = ?", (lic_id,)).fetchone()
    return json.loads(r[0]) if r else None


def _bound_candidates(conn, inviter: str):
    """(candidates, had_rows). Candidates = bound, not revoked/suspended, newest binding first."""
    rows = conn.execute(
        "SELECT a.activation_id, a.license_id, a.data_json AS adata, a.activated_at AS acol, "
        "l.key AS lkey, l.data_json AS ldata FROM local_activations a "
        "JOIN local_licenses l ON l.id = a.license_id WHERE lower(a.fingerprint) = ?",
        (inviter,)).fetchall()
    cands = []
    for r in rows:
        ld = json.loads(r["ldata"])
        if _status(ld.get("status")) in ("revoked", "suspended") or ld.get("suspended"):
            continue
        ad = json.loads(r["adata"] or "{}")
        at = _dt(ad.get("activated_at")) or _dt(r["acol"]) or datetime.min.replace(tzinfo=timezone.utc)
        cands.append((at, r["license_id"], ld))
    cands.sort(key=lambda c: (c[0], c[1]), reverse=True)
    return cands, bool(rows)


def _apply_to(conn, lic: dict, now: datetime):
    """Extend lic in place (+24h from max(expires_at, now)). Returns (status, action, prev, new)."""
    tier = _tiers.resolve(lic)["tier"]
    prev = _dt(lic.get("expires_at"))
    if tier == "ultra":
        return STATUS_ULTRA, "ultra_immutable", prev, prev
    if prev is not None and prev > now:
        action, new = "extended", prev + REWARD
    else:
        action, new = "extended_from_now", now + REWARD
    lic["expires_at"] = new
    if _status(lic.get("status")) == "expired":
        lic["status"] = "ACTIVE"
    meta = dict(lic.get("metadata") or {})
    meta["referral_bonus_hours"] = int(meta.get("referral_bonus_hours") or 0) + 24
    lic["metadata"] = meta
    conn.execute("UPDATE local_licenses SET data_json = ? WHERE id = ?", (json.dumps(lic, default=str), lic["id"]))
    return STATUS_APPLIED, action, prev, new


def _begin(conn):
    try:
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError as exc:
        raise ReferralError("REFERRAL_STORE_BUSY", "subscription store is busy, retry") from exc


def reward_extend(conn: sqlite3.Connection, inviter_fp, invitee_fp, review_id, *,
                  cap: int = REF_BONUS_CAP_DEFAULT, now: Optional[datetime] = None) -> dict:
    """Apply one referral reward atomically (r7 rulings 5/6/7). Returns a result dict plus
    ``_touched`` = {"license": record-dict, "activation": None} for the caller's cache mirror."""
    inviter = _norm_fp(inviter_fp, "inviter_fingerprint")
    invitee = _norm_fp(invitee_fp, "invitee_fingerprint")
    rid = str(review_id or "").strip()
    if not _REVIEW_ID.fullmatch(rid):
        raise ReferralError("REFERRAL_BAD_REQUEST", "review_id must be 1-64 chars [A-Za-z0-9_.:-]")
    if inviter == invitee:
        raise ReferralError("REFERRAL_SELF_INVITE", "inviter and invitee are the same machine")
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    _begin(conn)
    try:
        prior = conn.execute("SELECT * FROM referral_rewards WHERE invitee_fingerprint = ?",
                             (invitee,)).fetchone()
        if prior is not None:
            # ruling 5: one reward per invitee device_code lifetime; attribution is locked.
            if prior["review_id"] == rid and prior["inviter_fingerprint"] == inviter:
                count = applied_count(conn, inviter)
                lic = _load_lic(conn, prior["inviter_license_id"]) if prior["inviter_license_id"] else None
                conn.execute("COMMIT")
                out = _row_result(prior, True, count, lic)
                out["_touched"] = None
                return out
            raise ReferralError("REFERRAL_ALREADY_REWARDED",
                                "this invitee machine has already produced a referral reward")
        count = applied_count(conn, inviter)          # ruling 7: only status='applied'
        if count >= cap:
            raise ReferralError("REFERRAL_CAP_REACHED", f"inviter reached the referral cap ({cap})")
        cands, had_rows = _bound_candidates(conn, inviter)
        lic = None
        if not had_rows:
            # ruling 6: no card / only never-activated cards -> NO_ELIGIBLE_LICENSE, keep pending.
            status, action, prev, new = STATUS_PENDING, "pending_no_eligible_license", None, None
        elif not cands:
            raise ReferralError("REFERRAL_INVITER_INELIGIBLE",
                                "inviter's bound licenses are all revoked or suspended")
        else:
            lic = cands[0][2]
            status, action, prev, new = _apply_to(conn, lic, now)
        conn.execute(
            "INSERT INTO referral_rewards (invitee_fingerprint, inviter_fingerprint, inviter_license_id, "
            "review_id, rewarded_at, action, prev_expires_at, new_expires_at, status, reason, applied_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (invitee, inviter, lic["id"] if lic else "", rid, _iso(now), action, _iso(prev), _iso(new), status,
             CODE_NO_ELIGIBLE if status == STATUS_PENDING else None,
             _iso(now) if status == STATUS_APPLIED else None))
        conn.execute("COMMIT")
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    row = {"action": action, "inviter_license_id": lic["id"] if lic else "", "review_id": rid, "status": status,
           "rewarded_at": _iso(now), "prev_expires_at": _iso(prev), "new_expires_at": _iso(new)}
    out = _row_result(row, False, count + (1 if status == STATUS_APPLIED else 0), lic)
    out["_touched"] = {"license": lic, "activation": None} if status == STATUS_APPLIED else None
    return out


def apply_pending(conn: sqlite3.Connection, inviter_fp, *, cap: int = REF_BONUS_CAP_DEFAULT,
                  now: Optional[datetime] = None) -> dict:
    """r7 ruling 6: called after a device activation; applies this fingerprint's pending rewards
    (oldest first) to its newest eligible bound license. Returns {"applied": n, "license": lic|None, ...}."""
    try:
        inviter = _norm_fp(inviter_fp, "inviter_fingerprint")
    except ReferralError:
        return {"applied": 0, "license": None}
    if not _has_table(conn, "referral_rewards"):
        return {"applied": 0, "license": None}
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    _begin(conn)
    result = {"applied": 0, "ultra_immutable": 0, "rejected": 0, "license": None}
    try:
        pend = conn.execute("SELECT invitee_fingerprint FROM referral_rewards WHERE inviter_fingerprint = ? "
                            "AND status = ? ORDER BY rewarded_at, invitee_fingerprint",
                            (inviter, STATUS_PENDING)).fetchall()
        cands, _had = _bound_candidates(conn, inviter) if pend else ([], False)
        if pend and cands:
            lic = cands[0][2]
            for (inv,) in pend:
                if applied_count(conn, inviter) >= cap:
                    conn.execute("UPDATE referral_rewards SET status=?, reason=?, applied_at=? WHERE invitee_fingerprint=?",
                                 (STATUS_REJECTED, "REFERRAL_CAP_REACHED", _iso(now), inv))
                    result["rejected"] += 1
                    continue
                status, action, prev, new = _apply_to(conn, lic, now)
                conn.execute("UPDATE referral_rewards SET status=?, action=?, inviter_license_id=?, prev_expires_at=?, "
                             "new_expires_at=?, reason=NULL, applied_at=? WHERE invitee_fingerprint=?",
                             (status, action, lic["id"], _iso(prev), _iso(new), _iso(now), inv))
                result["applied" if status == STATUS_APPLIED else "ultra_immutable"] += 1
            if result["applied"]:
                result["license"] = lic
        conn.execute("COMMIT")
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    return result


def _has_table(conn, name) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None
