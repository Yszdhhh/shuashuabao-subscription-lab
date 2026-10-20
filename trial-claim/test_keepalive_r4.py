"""r4 keep-alive / chunked-POST regression tests (raw sockets, one TCP connection per test).
Run against any server file:  TRIAL_SERVER_FILE=/path/server.py pytest -q test_keepalive_r4.py
Expected: r4 work/server.py -> all pass; production 0987e3ad -> the chunked/unknown-path tests FAIL (= bug reproduced)."""
import importlib.util, json, os, shutil, socket, sys, threading, urllib.parse
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get("TRIAL_SERVER_FILE", os.path.join(HERE, "server.py"))
CODE = "ab" * 32  # synthetic 64-hex machine code (isolated test only)


@pytest.fixture()
def srv(tmp_path):
    shutil.copy(SRC, tmp_path / "server.py")
    for f in ("trial_store_v2.py",):
        if os.path.exists(os.path.join(HERE, f)): shutil.copy(os.path.join(HERE, f), tmp_path)
    d = {"batch": "t", "pool": [], "bonus_pool": [], "claims": {}, "closed": False, "pending": {}, "ref_tokens": {},
         "ref_counts": {}, "ref_cards": {}, "invite_log": {}}
    (tmp_path / "pool.json").write_text(json.dumps(d)); os.chmod(tmp_path / "pool.json", 0o600)
    os.environ["SHUABAO_SUBSCRIPTION_BASE"] = "http://127.0.0.1:9"  # nothing listens; never production
    sys.modules.pop("trial_store_v2", None)
    spec = importlib.util.spec_from_file_location(f"tc_{tmp_path.name}", str(tmp_path / "server.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    httpd = m.ThreadingHTTPServer(("127.0.0.1", 0), m.Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()
    yield m, httpd.server_address[1]
    httpd.shutdown(); httpd.server_close()


def read_resp(f):
    line = f.readline()
    if not line:
        return None
    if not line.startswith(b"HTTP/"):  # stray bytes, e.g. an HTTP/0.9-style error page written for leftover body bytes
        return {"status": "NON_HTTP", "headers": {}, "body": line + f.read1(300)}
    status = int(line.split(b" ", 2)[1])
    hdrs = {}
    while True:
        h = f.readline()
        if h in (b"\r\n", b"\n", b""):
            break
        if b":" not in h:
            return {"status": status, "headers": hdrs, "body": b"MALFORMED_HEADER:" + h}
        k, v = h.decode("latin-1").split(":", 1); hdrs[k.strip().lower()] = v.strip()
    body = f.read(int(hdrs.get("content-length", "0")))
    return {"status": status, "headers": hdrs, "body": body}


def conn(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5); return s, s.makefile("rb")


def chunked(body: bytes, n=7):
    out = b""
    for i in range(0, len(body), n):
        c = body[i:i + n]; out += b"%x\r\n" % len(c) + c + b"\r\n"
    return out + b"0\r\n\r\n"


GET_STATUS = b"GET /trial/status HTTP/1.1\r\nHost: t\r\n\r\n"


def expected_message(m, form):
    return m.decide(form.get("code", ""), ref=form.get("ref", ""), shot=None)["message"]


def test_chunked_post_parsed_and_connection_not_desynced(srv):
    m, port = srv
    form = {"code": "not-a-machine-code", "ref": ""}
    body = urllib.parse.urlencode(form).encode()
    s, f = conn(port)
    s.sendall(b"POST /trial HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n"
              + chunked(body) + GET_STATUS)
    r1 = read_resp(f); r2 = read_resp(f); s.close()
    assert r1["status"] == 200
    assert json.loads(r1["body"])["message"] == expected_message(m, form)  # body was actually read, not MSG_UNAVAILABLE
    assert r2 is not None and r2["status"] == 200 and "remaining" in json.loads(r2["body"])  # next request on same conn OK


def test_unknown_path_post_closes_connection_instead_of_desync(srv):
    m, port = srv
    s, f = conn(port)
    s.sendall(b"POST /nope HTTP/1.1\r\nHost: t\r\nContent-Length: 11\r\n\r\nhello=world" + GET_STATUS)
    r1 = read_resp(f); r2 = read_resp(f); s.close()
    assert r1["status"] == 404
    # either the body is consumed and the GET is served normally, or the server closes the connection. Never a stray 400.
    assert r2 is None or r2["status"] == 200, r2
    if r2 is None:
        assert r1["headers"].get("connection", "").lower() == "close"


def test_content_length_post_keepalive_still_works(srv):
    m, port = srv
    form = {"code": "not-a-machine-code", "ref": ""}
    body = urllib.parse.urlencode(form).encode()
    s, f = conn(port)
    s.sendall(b"POST /trial HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n" % len(body) + body + GET_STATUS)
    r1 = read_resp(f); r2 = read_resp(f); s.close()
    assert json.loads(r1["body"])["message"] == expected_message(m, form)
    assert r1["headers"].get("connection", "").lower() != "close"
    assert r2["status"] == 200


def test_oversized_body_rejected_and_connection_closed(srv):
    m, port = srv
    s, f = conn(port)
    s.sendall(b"POST /trial HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 99999999\r\n\r\ncode=x")
    r1 = read_resp(f); s.close()
    assert json.loads(r1["body"])["message"] == m.MSG_UNAVAILABLE
    assert r1["headers"].get("connection", "").lower() == "close"


def test_chunked_multipart_post(srv):
    pytest.importorskip("cgi")
    m, port = srv
    b = b"----x1"
    body = (b"--" + b + b"\r\nContent-Disposition: form-data; name=\"code\"\r\n\r\nnot-a-machine-code\r\n--" + b + b"--\r\n")
    s, f = conn(port)
    s.sendall(b"POST /trial HTTP/1.1\r\nHost: t\r\nContent-Type: multipart/form-data; boundary=" + b + b"\r\nTransfer-Encoding: chunked\r\n\r\n"
              + chunked(body, 13) + GET_STATUS)
    r1 = read_resp(f); r2 = read_resp(f); s.close()
    assert json.loads(r1["body"])["message"] == expected_message(m, {"code": "not-a-machine-code"})
    assert r2 is not None and r2["status"] == 200
