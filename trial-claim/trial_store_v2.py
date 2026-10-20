"""trial-claim pool storage v2 (r3, Batch B, NOT deployed).

Same service, same pool, same bridge interface (/v1/devices/activate + /v1/entitlements/validate of
the subscription service). Changes only HOW pool.json stores secrets:
  * card keys   -> {"h": HMAC(card), "l4": last4, "ct": AES-256-GCM(card)}   (no plaintext at rest)
  * machine code-> mref = HMAC(machine code)[:32] as the dict key; the code itself only as "mct"
                   (AES-GCM) where the service must call the bridge later (bonus card for inviter)
  * keys live in TRIAL_POOL_KEY_FILE (0600, outside pool.json, outside backups of pool.json)
  * single-use reveal token ("rdt_", sha256 stored, TTL 10 min, bound to mref) + Idempotency-Key
    replay window so a caller that timed out after a successful redeem gets the SAME result back
  * per-claim activation state: ok / failed / unknown (timeout). unknown is resolved by a validate
    QUERY, then an idempotent re-activate (same machine) -- never treated as "not activated".
Stdlib + `cryptography` (present on the VPS system python3: 41.0.7)."""
import base64, hashlib, hmac, json, os, re, secrets
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCHEMA = 2
TOKEN_TTL = timedelta(minutes=10)
REPLAY_WINDOW = timedelta(minutes=10)
CARD_RE = re.compile(r"^SSB-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Keys:
    def __init__(self, master: bytes):
        if len(master) != 32:
            raise ValueError("TRIAL_POOL_KEY must be 32 bytes")
        self.enc = hmac.new(master, b"trial-pool-v2:enc", hashlib.sha256).digest()
        self.mac = hmac.new(master, b"trial-pool-v2:mac", hashlib.sha256).digest()

    @classmethod
    def load(cls, path: str) -> "Keys":
        st = os.stat(path)
        if st.st_mode & 0o077:
            raise PermissionError("TRIAL_POOL_KEY_FILE must be 0600")
        raw = open(path, "rb").read().strip()
        return cls(base64.b64decode(raw))

    @staticmethod
    def generate(path: str) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(base64.b64encode(secrets.token_bytes(32)) + b"\n")

    def h(self, kind: str, value: str) -> str:
        return hmac.new(self.mac, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()

    def mref(self, machine_code: str) -> str:
        return self.h("machine", machine_code.strip().lower())[:32]

    def seal(self, plaintext: str, aad: str) -> str:
        n = secrets.token_bytes(12)
        return base64.b64encode(n + AESGCM(self.enc).encrypt(n, plaintext.encode(), aad.encode())).decode()

    def open(self, blob: str, aad: str) -> str:
        raw = base64.b64decode(blob)
        return AESGCM(self.enc).decrypt(raw[:12], raw[12:], aad.encode()).decode()

    def card(self, key: str) -> dict:
        h = self.h("card", key)[:40]   # 160-bit ref; 64-hex is reserved for machine codes in leak scans
        return {"h": h, "l4": key[-4:], "ct": self.seal(key, "card:" + h)}

    def card_plain(self, c: dict) -> str:
        return self.open(c["ct"], "card:" + c["h"])

    def machine_ct(self, code: str, mref: str) -> str:
        return self.seal(code, "machine:" + mref)

    def machine_plain(self, ct: str, mref: str) -> str:
        return self.open(ct, "machine:" + mref)


def now_utc():
    return datetime.now(timezone.utc)


def migrate(data: dict, keys: Keys) -> dict:
    """pool.json v1 (plaintext cards, machine-code keys) -> v2. Pure function; caller writes a NEW file."""
    if data.get("schema") == SCHEMA:
        return data
    out = {k: v for k, v in data.items() if k not in ("pool", "bonus_pool", "claims", "pending", "invite_log",
                                                      "ref_tokens", "ref_counts", "ref_cards")}
    out["schema"] = SCHEMA
    out["pool"] = [keys.card(c) for c in data.get("pool") or []]
    out["bonus_pool"] = [keys.card(c) for c in data.get("bonus_pool") or []]
    mr = lambda code: keys.mref(code)
    out["claims"] = {}
    for code, card in (data.get("claims") or {}).items():
        m = mr(code)
        out["claims"][m] = {**keys.card(card), "mct": keys.machine_ct(code, m), "at": None,
                            "revealed": True,   # v1 returned the card in every response: treat as already shown
                            "act": {"state": "legacy_unknown"}}
    out["pending"] = {}
    for code, rec in (data.get("pending") or {}).items():
        m = mr(code)
        r = dict(rec)
        if r.get("inviter"):
            im = mr(r["inviter"]); r["inviter_mct"] = keys.machine_ct(r["inviter"], im); r["inviter"] = im
        r["mct"] = keys.machine_ct(code, m)
        if code in str(r.get("shot") or ""):
            r["shot"] = str(r["shot"]).replace(code, m)   # upload file is renamed at cutover (upload_renames)
        out["pending"][m] = r
    out["ref_tokens"] = {}
    inviter_mct = {}
    for tok, code in (data.get("ref_tokens") or {}).items():
        m = mr(code); out["ref_tokens"][tok] = m; inviter_mct[m] = keys.machine_ct(code, m)
    out["inviter_mct"] = inviter_mct
    out["ref_counts"] = {mr(k): v for k, v in (data.get("ref_counts") or {}).items()}
    out["ref_cards"] = {mr(k): [keys.card(c) for c in v] for k, v in (data.get("ref_cards") or {}).items()}
    out["invite_log"] = {mr(k): [{**e, "code": mr(e["code"]) if HEX64.match(str(e.get("code", ""))) else e.get("code")} for e in v]
                         for k, v in (data.get("invite_log") or {}).items()}
    out["tokens"] = {}
    out["migrated_at"] = now_utc().isoformat()
    return out


def upload_renames(data_v1: dict, keys: Keys) -> list:
    """(old_relpath, new_relpath) for screenshots named after the machine code; applied at cutover only."""
    out = []
    for code, rec in (data_v1.get("pending") or {}).items():
        shot = str(rec.get("shot") or "")
        if code in shot:
            out.append((shot, shot.replace(code, keys.mref(code))))
    return out


def leak_scan(data) -> dict:
    raw = json.dumps(data)
    return {"card_pattern_hits": len(re.findall(r"SSB-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}", raw)),
            "machine_code_hits": len(re.findall(r"\b[0-9a-f]{64}\b", raw))}


# ------------------------------------------------------------------ single-use reveal token
def issue_token(data: dict, mref: str) -> tuple:
    """Call INSIDE the pool lock. One live token per claim; older unredeemed ones die."""
    tok = "rdt_" + secrets.token_urlsafe(24)
    th = hashlib.sha256(tok.encode()).hexdigest()[:48]
    exp = now_utc() + TOKEN_TTL
    toks = data.setdefault("tokens", {})
    for k, t in list(toks.items()):
        if t["mref"] == mref and not t.get("used_at"):
            del toks[k]
        elif t.get("used_at") and datetime.fromisoformat(t["used_at"]) + REPLAY_WINDOW < now_utc():
            del toks[k]   # GC
    toks[th] = {"mref": mref, "exp": exp.isoformat(), "used_at": None, "idem": None}
    return tok, exp


def redeem(data: dict, keys: Keys, machine_code: str, token: str, idem_key: str) -> dict:
    """Call INSIDE the pool lock (atomic: check + mark used + read in one locked read-modify-write).
    Returns {"ok":True,"card":...} or {"ok":False,"code":...}. Same token + same Idempotency-Key inside the
    replay window returns the same card again (caller timed out after server success)."""
    if not idem_key or len(idem_key) > 128:
        return {"ok": False, "code": "IDEMPOTENCY_KEY_REQUIRED"}
    m = keys.mref(machine_code)
    th = hashlib.sha256(str(token or "").encode()).hexdigest()[:48]
    t = (data.get("tokens") or {}).get(th)
    ih = hashlib.sha256(idem_key.encode()).hexdigest()[:48]
    if t is None or t["mref"] != m:
        return {"ok": False, "code": "TOKEN_INVALID"}
    claim = (data.get("claims") or {}).get(m)
    if claim is None:
        return {"ok": False, "code": "TOKEN_INVALID"}
    if t.get("used_at"):
        if t.get("idem") == ih and datetime.fromisoformat(t["used_at"]) + REPLAY_WINDOW >= now_utc():
            return {"ok": True, "card": keys.card_plain(claim), "replayed": True, "l4": claim["l4"]}
        return {"ok": False, "code": "TOKEN_USED", "l4": claim["l4"]}
    if datetime.fromisoformat(t["exp"]) <= now_utc():
        return {"ok": False, "code": "TOKEN_EXPIRED"}
    t["used_at"] = now_utc().isoformat(); t["idem"] = ih
    claim["revealed"] = True
    return {"ok": True, "card": keys.card_plain(claim), "replayed": False, "l4": claim["l4"]}


# ------------------------------------------------------------------ activation with recovery
class Outcome:
    OK, FAILED, UNKNOWN = "ok", "failed", "unknown"


def activate_with_recovery(card_key: str, machine_code: str, post_json, timeout: float) -> dict:
    """post_json(path, payload, timeout) -> (http_status, body_dict) or raises TimeoutError/OSError.
    activate -> on timeout/transport error: QUERY validate(key, fp); bound -> ok; DEVICE_NOT_ACTIVATED ->
    one idempotent re-activate (bridge re-activation of the same machine is idempotent); still unknown ->
    state=unknown (caller retries later). A timeout is never reported as 'not activated'."""
    body = {"license_key": card_key, "hardware": {"fingerprint": machine_code, "components": {}, "platform": "windows"}}
    def classify_validate():
        try:
            st, j = post_json("/v1/entitlements/validate", body, timeout)
        except (TimeoutError, OSError):
            return Outcome.UNKNOWN, None, "validate_timeout"
        if st == 200 and isinstance(j, dict):
            if j.get("valid"):
                return Outcome.OK, (j.get("license") or {}).get("expires_at"), "validate_bound"
            if j.get("code") == "DEVICE_NOT_ACTIVATED":
                return None, None, "not_bound"
            return Outcome.FAILED, None, str(j.get("code") or "INVALID")[:40]
        return Outcome.UNKNOWN, None, f"validate_http_{st}"
    try:
        st, j = post_json("/v1/devices/activate", body, timeout)
    except (TimeoutError, OSError):
        out, exp, why = classify_validate()
        if out is None:
            try:
                st, j = post_json("/v1/devices/activate", body, timeout)
            except (TimeoutError, OSError):
                return {"state": Outcome.UNKNOWN, "why": "activate_timeout_twice"}
            if st == 200:
                out, exp, why = classify_validate()
                return {"state": out or Outcome.UNKNOWN, "expires_at": exp, "why": "reactivated:" + why}
            return {"state": Outcome.FAILED, "why": _code(j)}
        return {"state": out, "expires_at": exp, "why": "recovered:" + why}
    if st == 200:
        out, exp, why = classify_validate()
        return {"state": Outcome.OK, "expires_at": exp, "why": "activated"}
    if 400 <= st < 500:
        return {"state": Outcome.FAILED, "why": _code(j)}
    out, exp, why = classify_validate()      # 5xx: server may or may not have bound -> query
    return {"state": out or Outcome.UNKNOWN, "expires_at": exp, "why": f"http_{st}:" + why}


def _code(j):
    if isinstance(j, dict):
        d = j.get("detail") or j.get("code") or ""
        d = str(d).split(":", 1)[0]
        return re.sub(r"SSB-[0-9A-Z-]+", "SSB-****", d)[:40]
    return "ERROR"
