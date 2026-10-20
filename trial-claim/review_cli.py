#!/usr/bin/env python3
"""Restricted review CLI for the `shuabao-review` user (no sudo, no env/DB access).

  review_cli.py list
  review_cli.py shot <review_ref> <out_file>
  review_cli.py approve <review_ref>
  review_cli.py reject <review_ref> <reason>
Token: $REVIEW_TOKEN_FILE (default ~/.config/shuabao-review/token, must be 0400/0600).
Socket: $REVIEW_SOCKET (default /run/shuabao-review/review.sock).
"""
import base64, json, os, socket, stat, sys


def call(req):
    tf = os.environ.get("REVIEW_TOKEN_FILE", os.path.expanduser("~/.config/shuabao-review/token"))
    st = os.stat(tf)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SystemExit("token file must not be group/other readable")
    req["token"] = open(tf, encoding="utf-8").read().strip()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(os.environ.get("REVIEW_SOCKET", "/run/shuabao-review/review.sock"))
    s.sendall(json.dumps(req).encode() + b"\n")
    buf = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        buf += c
    return json.loads(buf.decode())


def main(argv):
    if not argv:
        print(__doc__); return 2
    op = argv[0]
    if op == "list":
        out = call({"op": "list"})
    elif op == "shot" and len(argv) == 3:
        out = call({"op": "shot", "review_ref": argv[1]})
        if out.get("ok"):
            fd = os.open(argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, base64.b64decode(out.pop("b64"))); os.close(fd)
            out["saved"] = argv[2]
    elif op == "approve" and len(argv) == 2:
        out = call({"op": "approve", "review_ref": argv[1]})
    elif op == "reject" and len(argv) >= 3:
        out = call({"op": "reject", "review_ref": argv[1], "reason": " ".join(argv[2:])})
    else:
        print(__doc__); return 2
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
