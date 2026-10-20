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
    return {
        "ok": True,
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


def reward_extend(conn: sqlite3.Connection, inviter_fp, invitee_fp, review_id, *,
                  cap: int = REF_BONUS_CAP_DEFAULT, now: Optional[datetime] = None) -> dict:
    """Apply one referral reward atomically. Returns a result dict (see _row_result)
    plus ``_touched`` = {"license": record-dict, "activation": (act_id, lic_id, fp, data)|None}
    for the caller to mirror into its in-memory cache AFTER commit."""
    inviter = _norm_fp(inviter_fp, "inviter_fingerprint")
    invitee = _norm_fp(invitee_fp, "invitee_fingerprint")
    rid = str(review_id or "").strip()
    if not _REVIEW_ID.fullmatch(rid):
        raise ReferralError("REFERRAL_BAD_REQUEST", "review_id must be 1-64 chars [A-Za-z0-9_.:-]")
    if inviter == invitee:
        raise ReferralError("REFERRAL_SELF_INVITE", "inviter and invitee are the same machine")
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    # ``conn`` must be a DEDICATED connection (isolation_level=None, row_factory=sqlite3.Row).
    try:
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError as exc:
        raise ReferralError("REFERRAL_STORE_BUSY", "subscription store is busy, retry") from exc
    try:
        prior = conn.execute("SELECT * FROM referral_rewards WHERE invitee_fingerprint = ?",
                             (invitee,)).fetchone()
        if prior is not None:
            if prior["review_id"] == rid and prior["inviter_fingerprint"] == inviter:
                count = conn.execute("SELECT COUNT(*) FROM referral_rewards WHERE inviter_fingerprint = ?",
                                     (inviter,)).fetchone()[0]
                lic = _load_lic(conn, prior["inviter_license_id"])
                conn.execute("COMMIT")
                out = _row_result(prior, True, count, lic)
                out["_touched"] = None
                return out
            raise ReferralError("REFERRAL_ALREADY_REWARDED",
                                "this invitee machine has already produced a referral reward")
        count = conn.execute("SELECT COUNT(*) FROM referral_rewards WHERE inviter_fingerprint = ?",
                             (inviter,)).fetchone()[0]
        if count >= cap:
            raise ReferralError("REFERRAL_CAP_REACHED", f"inviter reached the referral cap ({cap})")

        rows = conn.execute(
            "SELECT a.activation_id, a.license_id, a.data_json AS adata, a.activated_at AS acol, "
            "l.key AS lkey, l.data_json AS ldata FROM local_activations a "
            "JOIN local_licenses l ON l.id = a.license_id WHERE lower(a.fingerprint) = ?",
            (inviter,)).fetchall()
        activation = None
        if not rows:
            history = conn.execute("SELECT 1 FROM device_trial_claims WHERE lower(fingerprint) = ?",
                                   (inviter,)).fetchone() if _has_table(conn, "device_trial_claims") else None
            if history:
                raise ReferralError("REFERRAL_INVITER_NOT_FOUND",
                                    "inviter has license history but no currently bound license")
            lic, activation = _fallback_trial(inviter, now)
            conn.execute("INSERT INTO local_licenses (id, key, data_json, created_at) VALUES (?, ?, ?, ?)",
                         (lic["id"], lic["key"], json.dumps(lic, default=str), now.isoformat()))
            act_id, _lid, _fp, adata = activation
            conn.execute("INSERT INTO local_activations (activation_id, license_id, fingerprint, data_json, activated_at) "
                         "VALUES (?, ?, ?, ?, ?)", (act_id, lic["id"], inviter, json.dumps(adata, default=str), now.isoformat()))
            action, prev, new = "fallback_trial_issued", None, _dt(lic["expires_at"])
        else:
            cands = []
            for r in rows:
                ld = json.loads(r["ldata"])
                if _status(ld.get("status")) in ("revoked", "suspended") or ld.get("suspended"):
                    continue
                ad = json.loads(r["adata"] or "{}")
                at = _dt(ad.get("activated_at")) or _dt(r["acol"]) or datetime.min.replace(tzinfo=timezone.utc)
                cands.append((at, r["license_id"], ld))
            if not cands:
                raise ReferralError("REFERRAL_INVITER_INELIGIBLE",
                                    "inviter's bound licenses are all revoked or suspended")
            cands.sort(key=lambda c: (c[0], c[1]), reverse=True)
            _at, _lid, lic = cands[0]
            tier = _tiers.resolve(lic)["tier"]
            prev = _dt(lic.get("expires_at"))
            if tier == "ultra" or prev is None:
                action, new = "count_only_lifetime", prev
            else:
                if prev > now:
                    action, new = "extended", prev + REWARD
                else:
                    action, new = "extended_from_now", now + REWARD
                lic["expires_at"] = new
                if _status(lic.get("status")) == "expired":
                    lic["status"] = "ACTIVE"
                meta = dict(lic.get("metadata") or {})
                meta["referral_bonus_hours"] = int(meta.get("referral_bonus_hours") or 0) + 24
                lic["metadata"] = meta
                conn.execute("UPDATE local_licenses SET data_json = ? WHERE id = ?",
                             (json.dumps(lic, default=str), lic["id"]))
        conn.execute(
            "INSERT INTO referral_rewards (invitee_fingerprint, inviter_fingerprint, inviter_license_id, "
            "review_id, rewarded_at, action, prev_expires_at, new_expires_at) VALUES (?,?,?,?,?,?,?,?)",
            (invitee, inviter, lic["id"], rid, _iso(now), action, _iso(prev), _iso(new)))
        conn.execute("COMMIT")
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    row = {"action": action, "inviter_license_id": lic["id"], "review_id": rid,
           "rewarded_at": _iso(now), "prev_expires_at": _iso(prev), "new_expires_at": _iso(new)}
    out = _row_result(row, False, count + 1, lic)
    out["_touched"] = {"license": lic, "activation": activation}
    return out


def _has_table(conn, name) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _fallback_trial(fp: str, now: datetime):
    lic_id = f"lic_{uuid.uuid4().hex[:12]}"
    key = f"SSB-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"
    lic = {
        "id": lic_id, "key": key, "status": "ACTIVE", "plan": "trial_1d",
        "tier": "test", "tier_name": _tiers.tier_name("test"),
        "customer_id": f"referral-fallback-{now:%Y%m%d}", "customer_email": None,
        "created_at": now.isoformat(), "expires_at": (now + REWARD).isoformat(),
        "device_limit": 1, "features": ["core", "automation", "trial_tier"],
        "metadata": {"issued_by": "referral_fallback", "is_trial": True, "grace_days": 0},
        "suspended": False,
    }
    act_id = f"act_{uuid.uuid4().hex[:8]}"
    adata = {"id": act_id, "fingerprint": fp, "name": "referral_fallback",
             "activated_at": now.isoformat(), "last_heartbeat_at": now.isoformat(), "components": {}}
    return lic, (act_id, lic_id, fp, adata)
