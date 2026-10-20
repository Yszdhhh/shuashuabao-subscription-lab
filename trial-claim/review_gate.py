"""BATCH C least-privilege review gate for the trial-claim service.

A unix stream socket (REVIEW_SOCKET, e.g. /run/shuabao-review/review.sock) served by the
trial-claim process. Access requires BOTH:
  * SO_PEERCRED uid == REVIEW_AGENT_UID (the dedicated `shuabao-review` unix user), and
  * a token whose sha256 equals REVIEW_TOKEN_SHA256 (token file 0400 owned by that user;
    the service only knows the hash), compared in constant time.
Protocol: one JSON object per connection (<= 8 KiB), one JSON reply.
  {"op":"list","token":T}                       -> pending reviews, fingerprints masked
  {"op":"shot","token":T,"review_ref":R}        -> screenshot bytes (base64), <= 3 MiB
  {"op":"approve","token":T,"review_ref":R}     -> service issues+activates the invitee card
                                                   and extends the inviter on 8010 itself
  {"op":"reject","token":T,"review_ref":R,"reason":"..."}
The agent never sees full fingerprints, card keys, subscription.env or SQLite.
"""
import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import threading

MAX_REQ = 8192


def mask(v):
    v = str(v or "")
    return v if len(v) <= 8 else f"{v[:4]}…{v[-4:]}"


def review_ref(key):
    return "r_" + hashlib.sha256(("review-ref:" + key).encode()).hexdigest()[:20]


def _peer_uid(conn):
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


def _token_ok(token, expected_sha):
    if not expected_sha or not isinstance(token, str) or not token:
        return False
    got = hashlib.sha256(token.encode()).hexdigest()
    return hmac.compare_digest(got, expected_sha.strip().lower())


def handle(srv, req, *, peer_uid, allowed_uid, token_sha):
    if allowed_uid is None or peer_uid != allowed_uid:
        return {"ok": False, "code": "REVIEW_FORBIDDEN"}
    if not _token_ok(req.get("token"), token_sha):
        return {"ok": False, "code": "REVIEW_UNAUTHORIZED"}
    op = req.get("op")
    pending = (srv["_read_data"]().get("pending") or {})
    keymap = {review_ref(k): k for k, r in pending.items() if r.get("status") == "pending"}
    if op == "list":
        items = []
        for ref, k in keymap.items():
            r = pending[k]
            items.append({"review_ref": ref, "fingerprint_masked": mask(k), "at": r.get("at"),
                          "inviter_masked": mask(r.get("inviter")) if r.get("inviter") else "",
                          "shot_id": os.path.basename(str(r.get("shot") or ""))[-12:]})
        items.sort(key=lambda e: e["at"] or "")
        return {"ok": True, "pending": items}
    key = keymap.get(str(req.get("review_ref") or ""))
    if key is None:
        return {"ok": False, "code": "REVIEW_NOT_PENDING"}
    if op == "shot":
        rel = str(pending[key].get("shot") or "")
        path = os.path.realpath(os.path.join(srv["ROOT"], rel))
        if not path.startswith(os.path.realpath(srv["UPLOAD_DIR"]) + os.sep):
            return {"ok": False, "code": "REVIEW_SHOT_UNAVAILABLE"}
        try:
            blob = open(path, "rb").read(3 * 1024 * 1024 + 1)
        except OSError:
            return {"ok": False, "code": "REVIEW_SHOT_UNAVAILABLE"}
        return {"ok": True, "name": os.path.basename(path)[-12:], "b64": base64.b64encode(blob).decode()}
    if op == "approve":
        res = srv["approve_pending"](key)
        ref = (res or {}).get("referral") or {}
        return {"ok": bool(res and res.get("ok")), "error": (res or {}).get("error"),
                "invitee_activated": res.get("activated", res.get("activation_state")) if res else None,
                "referral_state": ref.get("state"), "referral_code": ref.get("code")}
    if op == "reject":
        res = srv["reject_pending"](key, str(req.get("reason") or "截图不符合要求")[:200])
        return {"ok": bool(res and res.get("ok")), "error": (res or {}).get("error")}
    return {"ok": False, "code": "REVIEW_BAD_OP"}


def serve(srv, path, allowed_uid, token_sha, stop=None):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o117)          # socket 0660: service user + group shuabao-review only
    try:
        s.bind(path)
    finally:
        os.umask(old)
    s.listen(8)
    s.settimeout(0.5)
    while not (stop and stop.is_set()):
        try:
            conn, _ = s.accept()
        except socket.timeout:
            continue
        with conn:
            conn.settimeout(10)
            try:
                buf = b""
                while len(buf) <= MAX_REQ:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if b"\n" in chunk:
                        break
                req = json.loads(buf[:MAX_REQ].decode("utf-8")) if len(buf) <= MAX_REQ else {}
                out = handle(srv, req if isinstance(req, dict) else {}, peer_uid=_peer_uid(conn),
                             allowed_uid=allowed_uid, token_sha=token_sha)
            except Exception as exc:
                out = {"ok": False, "code": "REVIEW_ERROR", "error": type(exc).__name__}
            try:
                conn.sendall(json.dumps(out, ensure_ascii=False).encode() + b"\n")
            except OSError:
                pass
    s.close()


def start(srv, stop=None):
    path = os.environ["REVIEW_SOCKET"]
    uid = os.environ.get("REVIEW_AGENT_UID")
    t = threading.Thread(target=serve, args=(srv, path, int(uid) if uid else None,
                                             os.environ.get("REVIEW_TOKEN_SHA256", ""), stop), daemon=True)
    t.start()
    return t
