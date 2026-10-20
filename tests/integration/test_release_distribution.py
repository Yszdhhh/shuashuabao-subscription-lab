"""Distribution security and integrity: publish, rollback, public latest, download path."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from bridge.app import main
from bridge.app.services.release_distribution import (
    PUBLIC_LATEST_FIELDS,
    SIGNING_PURPOSE,
    ReleaseDistributionError,
    ReleaseStore,
    resolve_published_artifact,
    sign_descriptor,
)
from infra.nginx.render_downloads_conf import render_downloads_config

ROOT = Path(__file__).resolve().parents[2]
PUBLIC_BASE = "https://downloads.shuabao.test"
SOURCE_V1 = "a" * 40
MANIFEST_V1 = "b" * 64
SOURCE_V2 = "c" * 40
MANIFEST_V2 = "d" * 64


def _keypair():
    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, public_pem


def _write_signed(tmp: Path, private, *, version: str, sequence: int, source: str, manifest: str,
                  channel: str = "release", bundle_bytes: bytes | None = None, changelog: str = "public notes"):
    bundle_bytes = bundle_bytes or f"PK\x03\x04shuabao-{version}\n".encode()
    bundle = tmp / f"in-{version}.zip"
    bundle.write_bytes(bundle_bytes)
    digest = hashlib.sha256(bundle_bytes).hexdigest()
    descriptor = {
        "schema_version": 1,
        "product_id": "shuabao",
        "version": version,
        "release_channel": channel,
        "source_sha": source,
        "release_manifest_sha256": manifest,
        "bundle_sha256": digest,
        "bundle_size": len(bundle_bytes),
        "bundle_name": f"shuabao-{version}.zip",
        "published_at": "2026-09-09T06:00:00Z",
        "minimum_supported_version": "1.0.0",
        "mandatory": False,
        "release_sequence": sequence,
        "changelog_summary": changelog,
        "key_id": "release-test-key",
        "purpose": SIGNING_PURPOSE,
    }
    signature = sign_descriptor(private, descriptor)
    desc_path = tmp / f"{version}.descriptor.json"
    sig_path = tmp / f"{version}.sig"
    desc_path.write_text(json.dumps(descriptor), encoding="utf-8")
    sig_path.write_bytes(base64.b64encode(signature) + b"\n")
    return bundle, desc_path, sig_path, descriptor


def _store(tmp: Path) -> ReleaseStore:
    return ReleaseStore(root=tmp / "releases", public_base=PUBLIC_BASE)


def test_valid_signed_release_publishes_and_latest_returns_it(tmp_path, monkeypatch):
    private, public_pem = _keypair()
    store = _store(tmp_path)
    bundle, desc, sig, descriptor = _write_signed(
        tmp_path, private, version="1.0.0", sequence=1, source=SOURCE_V1, manifest=MANIFEST_V1
    )
    assert not (store.root / "release" / "1.0.0").exists()
    result = store.publish(
        bundle_path=bundle,
        descriptor_path=desc,
        signature_path=sig,
        public_key_pem=public_pem,
        expected_key_id="release-test-key",
    )
    assert result["version"] == "1.0.0"
    published = store.root / "release" / "1.0.0" / "shuabao-1.0.0.zip"
    assert published.is_file()
    assert published.read_bytes() == bundle.read_bytes()
    # staging publish dir is not left as the public current pointer source
    assert not list((store.root / "staging").glob("pub-*"))

    monkeypatch.setenv("SHUABAO_RELEASES_ROOT", str(store.root))
    monkeypatch.setenv("SHUABAO_RELEASE_PUBLIC_BASE", PUBLIC_BASE)
    with TestClient(main.app, client=("127.0.0.1", 50000)) as client:
        missing = client.get("/v1/releases/latest", params={"channel": "dev"})
        assert missing.status_code == 404
        response = client.get("/v1/releases/latest", params={"channel": "release"})
        assert response.status_code == 200
        body = response.json()
        assert body["version"] == "1.0.0"
        assert body["release_channel"] == "release"
        assert body["source_sha"] == SOURCE_V1
        assert body["release_manifest_sha256"] == MANIFEST_V1
        assert body["bundle_sha256"] == descriptor["bundle_sha256"]
        assert body["bundle_size"] == descriptor["bundle_size"]
        assert body["download_url"] == f"{PUBLIC_BASE}/downloads/shuabao/release/1.0.0/shuabao-1.0.0.zip"
        assert body["descriptor_url"] == f"{PUBLIC_BASE}/downloads/shuabao/release/1.0.0/release-descriptor.json"
        assert body["signature"]["algorithm"] == "Ed25519"
        assert body["signature"]["key_id"] == "release-test-key"
        assert body["signature"]["purpose"] == SIGNING_PURPOSE
        assert body["release_sequence"] == 1
        # distribution does not approve the LIVE policy
        status = client.get(
            "/v1/releases/status",
            params={
                "source_sha": SOURCE_V1,
                "release_manifest_sha256": MANIFEST_V1,
                "release_channel": "release",
            },
        )
        assert status.status_code == 200
        assert status.json()["status"] == "not_approved"
        assert status.json()["approved"] is False


def test_tampered_bundle_cannot_publish(tmp_path):
    private, public_pem = _keypair()
    store = _store(tmp_path)
    bundle, desc, sig, _ = _write_signed(
        tmp_path, private, version="1.0.0", sequence=1, source=SOURCE_V1, manifest=MANIFEST_V1
    )
    raw = bytearray(bundle.read_bytes())
    raw[-1] ^= 0x01
    bundle.write_bytes(bytes(raw))
    with pytest.raises(ReleaseDistributionError) as exc:
        store.publish(bundle_path=bundle, descriptor_path=desc, signature_path=sig, public_key_pem=public_pem)
    assert exc.value.code == "BUNDLE_HASH_MISMATCH"
    assert store.latest_public("release") is None
    assert not (store.root / "release" / "1.0.0").exists()


def test_invalid_descriptor_signature_cannot_publish(tmp_path):
    private, public_pem = _keypair()
    other, _ = _keypair()
    store = _store(tmp_path)
    bundle, desc, sig, descriptor = _write_signed(
        tmp_path, private, version="1.0.0", sequence=1, source=SOURCE_V1, manifest=MANIFEST_V1
    )
    sig.write_bytes(base64.b64encode(other.sign(b"not-the-descriptor")) + b"\n")
    with pytest.raises(ReleaseDistributionError) as exc:
        store.publish(bundle_path=bundle, descriptor_path=desc, signature_path=sig, public_key_pem=public_pem)
    assert exc.value.code == "INVALID_SIGNATURE"
    assert store.latest_public("release") is None
    assert descriptor["version"] == "1.0.0"


def test_mid_publish_failure_does_not_pollute_latest(tmp_path):
    private, public_pem = _keypair()
    store = _store(tmp_path)
    bundle, desc, sig, _ = _write_signed(
        tmp_path, private, version="1.0.0", sequence=1, source=SOURCE_V1, manifest=MANIFEST_V1
    )
    store.publish(bundle_path=bundle, descriptor_path=desc, signature_path=sig, public_key_pem=public_pem)
    assert store.latest_public("release")["version"] == "1.0.0"

    bundle2, desc2, sig2, _ = _write_signed(
        tmp_path, private, version="1.1.0", sequence=2, source=SOURCE_V2, manifest=MANIFEST_V2
    )
    with pytest.raises(ReleaseDistributionError) as exc:
        store.publish(
            bundle_path=bundle2,
            descriptor_path=desc2,
            signature_path=sig2,
            public_key_pem=public_pem,
            failpoint="after_verify",
        )
    assert exc.value.code == "PUBLISH_FAILED"
    assert store.latest_public("release")["version"] == "1.0.0"
    assert not (store.root / "release" / "1.1.0").exists()

    with pytest.raises(ReleaseDistributionError) as placed:
        store.publish(
            bundle_path=bundle2,
            descriptor_path=desc2,
            signature_path=sig2,
            public_key_pem=public_pem,
            failpoint="after_place",
        )
    assert placed.value.code == "PUBLISH_FAILED"
    latest = store.latest_public("release")
    assert latest["version"] == "1.0.0"
    assert latest["source_sha"] == SOURCE_V1
    # file may exist, but latest must not flip before the pointer commit
    assert (store.root / "release" / "1.1.0" / "shuabao-1.1.0.zip").is_file()


def test_rollback_points_latest_at_previous_and_keeps_artifact(tmp_path, monkeypatch):
    private, public_pem = _keypair()
    store = _store(tmp_path)
    b1, d1, s1, desc1 = _write_signed(
        tmp_path, private, version="1.0.0", sequence=1, source=SOURCE_V1, manifest=MANIFEST_V1
    )
    b2, d2, s2, _ = _write_signed(
        tmp_path, private, version="1.1.0", sequence=2, source=SOURCE_V2, manifest=MANIFEST_V2
    )
    store.publish(bundle_path=b1, descriptor_path=d1, signature_path=s1, public_key_pem=public_pem)
    store.publish(bundle_path=b2, descriptor_path=d2, signature_path=s2, public_key_pem=public_pem)
    v2_path = store.root / "release" / "1.1.0" / "shuabao-1.1.0.zip"
    v2_bytes = v2_path.read_bytes()
    rolled = store.rollback(channel="release", version="1.0.0")
    assert rolled["version"] == "1.0.0"
    assert rolled["previous_version"] == "1.1.0"
    assert v2_path.is_file()
    assert v2_path.read_bytes() == v2_bytes
    assert (store.root / "release" / "1.0.0" / "shuabao-1.0.0.zip").read_bytes() == b1.read_bytes()

    monkeypatch.setenv("SHUABAO_RELEASES_ROOT", str(store.root))
    monkeypatch.setenv("SHUABAO_RELEASE_PUBLIC_BASE", PUBLIC_BASE)
    with TestClient(main.app, client=("127.0.0.1", 50000)) as client:
        body = client.get("/v1/releases/latest").json()
    assert body["version"] == "1.0.0"
    assert body["bundle_sha256"] == desc1["bundle_sha256"]
    assert body["release_sequence"] == 1
    withdrawn = store.withdraw(channel="release", version="1.1.0")
    assert withdrawn["version"] == "1.1.0"
    assert store.latest_public("release")["version"] == "1.0.0"
    assert not (store.root / "release" / "1.1.0").exists()
    kept = store.withdrawn / "release" / "1.1.0" / "shuabao-1.1.0.zip"
    assert kept.is_file()
    assert kept.read_bytes() == v2_bytes


def test_published_bundle_cannot_be_silently_overwritten(tmp_path):
    private, public_pem = _keypair()
    store = _store(tmp_path)
    bundle, desc, sig, descriptor = _write_signed(
        tmp_path, private, version="1.0.0", sequence=1, source=SOURCE_V1, manifest=MANIFEST_V1
    )
    store.publish(bundle_path=bundle, descriptor_path=desc, signature_path=sig, public_key_pem=public_pem)
    original = (store.root / "release" / "1.0.0" / "shuabao-1.0.0.zip").read_bytes()
    replacement = tmp_path / "other.zip"
    bundle_bytes = b"PK\x03\x04different-bytes"
    replacement.write_bytes(bundle_bytes)
    digest = hashlib.sha256(bundle_bytes).hexdigest()
    rewritten = {
        **descriptor,
        "bundle_sha256": digest,
        "bundle_size": len(bundle_bytes),
        "published_at": "2026-09-09T07:00:00Z",
    }
    desc2 = tmp_path / "overwrite.descriptor.json"
    desc2.write_text(json.dumps(rewritten), encoding="utf-8")
    sig2 = tmp_path / "overwrite.sig"
    sig2.write_bytes(base64.b64encode(sign_descriptor(private, rewritten)))
    with pytest.raises(ReleaseDistributionError) as exc:
        store.publish(
            bundle_path=replacement,
            descriptor_path=desc2,
            signature_path=sig2,
            public_key_pem=public_pem,
        )
    assert exc.value.code == "CONFLICT"
    assert (store.root / "release" / "1.0.0" / "shuabao-1.0.0.zip").read_bytes() == original
    assert store.latest_public("release")["bundle_sha256"] == descriptor["bundle_sha256"]


def test_public_latest_json_has_no_server_path_or_internal_metadata(tmp_path, monkeypatch):
    private, public_pem = _keypair()
    store = _store(tmp_path)
    bundle, desc, sig, _ = _write_signed(
        tmp_path, private, version="1.2.3", sequence=1, source=SOURCE_V1, manifest=MANIFEST_V1,
        changelog="ready for external clients",
    )
    store.publish(bundle_path=bundle, descriptor_path=desc, signature_path=sig, public_key_pem=public_pem)
    monkeypatch.setenv("SHUABAO_RELEASES_ROOT", str(store.root))
    monkeypatch.setenv("SHUABAO_RELEASE_PUBLIC_BASE", PUBLIC_BASE)
    with TestClient(main.app, client=("127.0.0.1", 50000)) as client:
        response = client.get("/v1/releases/latest", params={"channel": "release"})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == set(PUBLIC_LATEST_FIELDS)
    public_copy = dict(body)
    public_copy["signature"] = {k: v for k, v in body["signature"].items() if k != "signature"}
    blob = json.dumps(public_copy)
    root_text = str(store.root)
    assert root_text not in blob
    assert str(tmp_path) not in blob
    assert "/home/" not in blob
    assert "/opt/" not in blob
    assert "operator_note" not in blob
    assert "updated_by" not in blob
    assert "admin" not in blob.lower()
    assert "github" not in blob.lower()
    assert "signing_key" not in blob
    assert "BEGIN " not in blob
    assert "password" not in blob.lower()
    assert "token" not in blob.lower()
    assert body["download_url"].startswith(PUBLIC_BASE + "/downloads/shuabao/")
    assert "://" not in body["download_url"].removeprefix("https://")


def test_path_traversal_rejected_by_resolver_and_nginx_config(tmp_path):
    root = tmp_path / "releases"
    store = ReleaseStore(root=root, public_base=PUBLIC_BASE)
    store.ensure_layout()
    outside = tmp_path / "secret.zip"
    outside.write_bytes(b"nope")
    version_dir = root / "release" / "1.0.0"
    version_dir.mkdir(parents=True)
    (version_dir / "shuabao-1.0.0.zip").write_bytes(b"ok")
    link = version_dir / "shuabao-link.zip"
    link.symlink_to(outside)

    with pytest.raises(ReleaseDistributionError) as parent:
        resolve_published_artifact(root, "../staging", "1.0.0", "shuabao-1.0.0.zip")
    assert parent.value.code == "PATH_REJECTED"
    with pytest.raises(ReleaseDistributionError):
        resolve_published_artifact(root, "release", "..", "shuabao-1.0.0.zip")
    with pytest.raises(ReleaseDistributionError):
        resolve_published_artifact(root, "release", "1.0.0", "../secret.zip")
    with pytest.raises(ReleaseDistributionError):
        resolve_published_artifact(root, "release", "1.0.0", "..%2Fsecret.zip")
    with pytest.raises(ReleaseDistributionError):
        resolve_published_artifact(root, "staging", "1.0.0", "shuabao-1.0.0.zip")
    with pytest.raises(ReleaseDistributionError):
        resolve_published_artifact(root, "release", "1.0.0", "shuabao-link.zip")

    safe = resolve_published_artifact(root, "release", "1.0.0", "shuabao-1.0.0.zip")
    assert safe == (root / "release" / "1.0.0" / "shuabao-1.0.0.zip").resolve()
    assert "staging" not in safe.parts[-3:]

    conf = (ROOT / "infra/nginx/shuabao-downloads.conf").read_text()
    assert "autoindex off;" in conf
    assert "disable_symlinks on;" in conf
    assert "location ^~ /downloads/shuabao/staging/" in conf
    assert "location ^~ /downloads/shuabao/withdrawn/" in conf
    assert "location ^~ /downloads/shuabao/index/" in conf
    assert "location ^~ /downloads/shuabao/audit/" in conf
    assert "listen 8010" not in conf
    assert "listen 8088;" in conf
    assert "application/zip zip;" in conf
    assert "alias /srv/shuabao/releases/$1/$2/$3;" in conf
    assert "max_ranges 0;" not in conf
    with pytest.raises(SystemExit):
        render_downloads_config(releases_root="/srv/shuabao/releases", listen_port=8010)


def test_cli_publish_and_rollback(tmp_path):
    private, public_pem = _keypair()
    key_path = tmp_path / "release_public_key.pem"
    key_path.write_bytes(public_pem)
    root = tmp_path / "releases"
    b1, d1, s1, _ = _write_signed(
        tmp_path, private, version="1.0.0", sequence=1, source=SOURCE_V1, manifest=MANIFEST_V1
    )
    b2, d2, s2, _ = _write_signed(
        tmp_path, private, version="1.1.0", sequence=2, source=SOURCE_V2, manifest=MANIFEST_V2
    )
    script = ROOT / "scripts" / "publish_release.py"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)

    def run(args):
        return subprocess.run(
            [sys.executable, str(script), "--root", str(root), *args],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    first = run(["publish", "--bundle", str(b1), "--descriptor", str(d1), "--signature", str(s1), "--public-key", str(key_path)])
    assert first.returncode == 0, first.stderr
    second = run(["publish", "--bundle", str(b2), "--descriptor", str(d2), "--signature", str(s2), "--public-key", str(key_path)])
    assert second.returncode == 0, second.stderr
    rolled = run(["rollback", "--channel", "release", "--version", "1.0.0"])
    assert rolled.returncode == 0, rolled.stderr
    payload = json.loads(rolled.stdout)
    assert payload["version"] == "1.0.0"
    assert (root / "release" / "1.1.0" / "shuabao-1.1.0.zip").is_file()
    store = ReleaseStore(root=root, public_base=PUBLIC_BASE)
    assert store.latest_public("release")["version"] == "1.0.0"


def test_private_key_not_in_commit_tree_and_permit_signer_untracked():
    # Split so this assertion is not itself a private-key blob in the commit tree.
    needle = "BEGIN PRIVATE " + "KEY"
    grep = subprocess.run(
        ["git", "grep", "-n", needle, "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert grep.returncode == 1, grep.stdout
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "signing_key.pem"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert tracked.returncode != 0
    on_disk = ROOT / "signing_key.pem"
    assert on_disk.exists()
    check = subprocess.run(
        ["git", "check-ignore", "-q", "signing_key.pem"],
        cwd=ROOT,
        check=False,
    )
    assert check.returncode == 0


def _nginx_binary() -> tuple[str | None, str]:
    found = shutil.which("nginx")
    if not found:
        for candidate in ("/usr/sbin/nginx", "/usr/bin/nginx"):
            if Path(candidate).is_file() and os.access(candidate, os.X_OK):
                found = candidate
                break
    if found:
        return found, ""
    if os.environ.get("SHUABAO_SKIP_NGINX_INSTALL") == "1":
        return None, "nginx binary not present and install skipped"
    install = subprocess.run(
        ["apt-get", "update", "-qq"],
        text=True,
        capture_output=True,
        check=False,
    )
    if install.returncode != 0:
        return None, f"apt-get update failed: {install.stderr.strip()[:200]}"
    installed = subprocess.run(
        ["apt-get", "install", "-y", "-qq", "nginx"],
        text=True,
        capture_output=True,
        check=False,
    )
    if installed.returncode != 0:
        return None, f"nginx install failed: {installed.stderr.strip()[:200]}"
    found = shutil.which("nginx")
    if not found:
        return None, "nginx package installed but binary not on PATH"
    return found, ""


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_nginx_download_smoke_or_config_level(tmp_path, capsys):
    conf_text = (ROOT / "infra/nginx/shuabao-downloads.conf").read_text()
    # config-level smoke always executes, even if the binary cannot be installed
    assert "autoindex off;" in conf_text
    assert "location ^~ /downloads/shuabao/staging/" in conf_text
    assert "alias /srv/shuabao/releases/$1/$2/$3;" in conf_text
    assert "/downloads/shuabao/staging/" not in conf_text.split("location ~ ^/downloads")[1]

    nginx, reason = _nginx_binary()
    if not nginx:
        print(f"NGINX_BINARY_SMOKE=SKIPPED reason={reason}")
        return

    port = _free_port()
    if port == 8010:
        port = 18088
    releases = tmp_path / "releases"
    version_dir = releases / "release" / "1.0.0"
    version_dir.mkdir(parents=True)
    (releases / "staging").mkdir(parents=True)
    (releases / "staging" / "hidden.zip").write_bytes(b"hidden")
    payload = b"PK\x03\x04official-bundle"
    (version_dir / "shuabao-1.0.0.zip").write_bytes(payload)
    (version_dir / "release-descriptor.json").write_text("{}", encoding="utf-8")
    rendered = render_downloads_config(releases_root=str(releases), listen_port=port)
    rendered = rendered.replace(
        "http {\n",
        "http {\n    client_body_temp_path /tmp/shuabao-nginx-client;\n"
        "    proxy_temp_path /tmp/shuabao-nginx-proxy;\n"
        "    fastcgi_temp_path /tmp/shuabao-nginx-fastcgi;\n"
        "    uwsgi_temp_path /tmp/shuabao-nginx-uwsgi;\n"
        "    scgi_temp_path /tmp/shuabao-nginx-scgi;\n",
        1,
    )
    for folder in (
        "/tmp/shuabao-nginx-client",
        "/tmp/shuabao-nginx-proxy",
        "/tmp/shuabao-nginx-fastcgi",
        "/tmp/shuabao-nginx-uwsgi",
        "/tmp/shuabao-nginx-scgi",
    ):
        Path(folder).mkdir(exist_ok=True)
    conf_path = tmp_path / "nginx.conf"
    conf_path.write_text(rendered, encoding="utf-8")
    prefix = tmp_path / "nginx-prefix"
    prefix.mkdir()
    proc = subprocess.Popen(
        [nginx, "-p", str(prefix), "-c", str(conf_path), "-g", "daemon off;"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        import time
        import urllib.error
        import urllib.request

        url = f"http://127.0.0.1:{port}/downloads/shuabao/release/1.0.0/shuabao-1.0.0.zip"
        last_error = ""
        body = b""
        headers = {}
        for _ in range(40):
            if proc.poll() is not None:
                err = proc.stderr.read() if proc.stderr else ""
                raise AssertionError(f"nginx exited early: {err}")
            try:
                with urllib.request.urlopen(url, timeout=1) as response:
                    body = response.read()
                    headers = dict(response.headers.items())
                break
            except Exception as exc:  # noqa: BLE001 - wait for bind
                last_error = str(exc)
                time.sleep(0.1)
        else:
            raise AssertionError(f"nginx did not serve bundle: {last_error}")
        assert body == payload
        assert headers.get("Content-Length") == str(len(payload))
        assert headers.get("Content-Type", "").startswith("application/zip")
        range_req = urllib.request.Request(url, headers={"Range": "bytes=0-3"})
        with urllib.request.urlopen(range_req, timeout=2) as response:
            ranged = response.read()
            range_headers = dict(response.headers.items())
        assert ranged == payload[:4]
        assert range_headers.get("Content-Range", "").startswith("bytes 0-3/")
        listing = urllib.request.Request(f"http://127.0.0.1:{port}/downloads/shuabao/release/")
        with pytest.raises(urllib.error.HTTPError) as listed:
            urllib.request.urlopen(listing, timeout=2)
        assert listed.value.code in {403, 404}
        staging = urllib.request.Request(f"http://127.0.0.1:{port}/downloads/shuabao/staging/hidden.zip")
        with pytest.raises(urllib.error.HTTPError) as staged:
            urllib.request.urlopen(staging, timeout=2)
        assert staged.value.code in {403, 404}
        traversal = urllib.request.Request(
            f"http://127.0.0.1:{port}/downloads/shuabao/release/1.0.0/../../staging/hidden.zip"
        )
        with pytest.raises(urllib.error.HTTPError) as escaped:
            urllib.request.urlopen(traversal, timeout=2)
        assert escaped.value.code in {400, 403, 404}
        print("NGINX_BINARY_SMOKE=PASS")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
