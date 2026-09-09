"""Immutable ShuaBao release distribution store.

Server role is VERIFY, STORE, PUBLISH, SERVE. Signing happens off-box.
This module stores a configured Ed25519 public key only. It must never
load, persist, or use the permit signer (signing_key.pem).

Distribution is separate from release policy (approved/blocked/recommended)
and from LIVE permit issuance.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional
from urllib.parse import unquote, urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from bridge.app.services.permit_issuer import RELEASE_CHANNELS, validate_release_identity

DESCRIPTOR_SCHEMA_VERSION = 1
PRODUCT_ID = "shuabao"
SIGNING_PURPOSE = "shuabao-release-descriptor-v1"
SIGNATURE_ALGORITHM = "Ed25519"
DOWNLOAD_PATH_PREFIX = "/downloads/shuabao"
DEFAULT_RELEASES_ROOT = "data/releases"
DEFAULT_MAX_BUNDLE_BYTES = 1024 * 1024 * 1024

CHANNEL_DIRS = ("dev", "internal-pilot", "external-beta", "release")
PUBLIC_ARTIFACT_NAMES = frozenset()  # filled conceptually; names validated below

_VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})"
    r"(?:-[A-Za-z0-9][A-Za-z0-9._-]{0,32})?$"
)
_BUNDLE_NAME_RE = re.compile(r"^shuabao[A-Za-z0-9._-]{0,120}\.zip$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ACTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}$")

DESCRIPTOR_FIELDS = (
    "schema_version",
    "product_id",
    "version",
    "release_channel",
    "source_sha",
    "release_manifest_sha256",
    "bundle_sha256",
    "bundle_size",
    "bundle_name",
    "published_at",
    "minimum_supported_version",
    "mandatory",
    "release_sequence",
    "changelog_summary",
    "key_id",
    "purpose",
)

PUBLIC_LATEST_FIELDS = (
    "version",
    "release_channel",
    "source_sha",
    "release_manifest_sha256",
    "bundle_sha256",
    "bundle_size",
    "download_url",
    "published_at",
    "minimum_supported_version",
    "mandatory",
    "release_sequence",
    "changelog_summary",
    "signature",
    "descriptor_url",
)

_FORBIDDEN_PUBLIC_MARKERS = (
    "operator_note",
    "updated_by",
    "filesystem",
    "local_path",
    "private_key",
    "BEGIN PRIVATE",
    "BEGIN RSA",
    "admin_password",
    "github_token",
    "signing_key.pem",
)


class ReleaseDistributionError(Exception):
    """Fail-closed distribution error. Message must not include secrets or paths."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def releases_root_from_env(env: Optional[Mapping[str, str]] = None) -> Path:
    source = os.environ if env is None else env
    raw = str(source.get("SHUABAO_RELEASES_ROOT") or DEFAULT_RELEASES_ROOT).strip()
    return Path(raw)


def public_base_from_env(env: Optional[Mapping[str, str]] = None) -> str:
    source = os.environ if env is None else env
    return str(source.get("SHUABAO_RELEASE_PUBLIC_BASE") or "").strip()


def normalize_public_base(public_base: str) -> str:
    text = str(public_base or "").strip().rstrip("/")
    if not text:
        raise ReleaseDistributionError(
            "PUBLIC_BASE_MISSING",
            "SHUABAO_RELEASE_PUBLIC_BASE is not configured",
        )
    parsed = urlparse(text)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise ReleaseDistributionError(
            "PUBLIC_BASE_INVALID",
            "release public base must be an absolute http(s) URL",
        )
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ReleaseDistributionError(
            "PUBLIC_BASE_INVALID",
            "release public base must not include credentials, query, or fragment",
        )
    if ".." in parsed.path or "\\" in text or any(ch.isspace() for ch in text):
        raise ReleaseDistributionError("PUBLIC_BASE_INVALID", "release public base is not safe")
    return text


def build_download_url(public_base: str, channel: str, version: str, bundle_name: str) -> str:
    """Absolute public URL. Future OSS/COS/CDN can replace the origin without changing this path.

    Authenticity is the client-side Ed25519 descriptor signature, not possession of this URL.
    Entitlement-scoped download tokens are intentionally not implemented (hook left unused).
    """
    base = normalize_public_base(public_base)
    rel = download_url_path(channel, version, bundle_name)
    return f"{base}{rel}"


def build_descriptor_url(public_base: str, channel: str, version: str) -> str:
    base = normalize_public_base(public_base)
    rel = artifact_url_path(channel, version, "release-descriptor.json")
    return f"{base}{rel}"


def download_url_path(channel: str, version: str, bundle_name: str) -> str:
    channel, version, bundle_name = _safe_public_components(channel, version, bundle_name)
    return f"{DOWNLOAD_PATH_PREFIX}/{channel}/{version}/{bundle_name}"


def artifact_url_path(channel: str, version: str, name: str) -> str:
    channel, version, _bundle = _safe_public_components(channel, version, "shuabao-placeholder.zip")
    safe_name = _safe_artifact_name(name)
    return f"{DOWNLOAD_PATH_PREFIX}/{channel}/{version}/{safe_name}"


def canonical_descriptor_bytes(descriptor: Mapping[str, Any]) -> bytes:
    normalized = normalize_descriptor(descriptor)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def normalize_descriptor(descriptor: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(descriptor, Mapping):
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "descriptor must be a JSON object")
    unknown = sorted(set(descriptor) - set(DESCRIPTOR_FIELDS))
    if unknown:
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "descriptor contains unknown fields")
    missing = [field for field in DESCRIPTOR_FIELDS if field not in descriptor]
    if missing:
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "descriptor is missing required fields")

    schema_version = descriptor.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != DESCRIPTOR_SCHEMA_VERSION:
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "unsupported descriptor schema_version")
    if descriptor.get("product_id") != PRODUCT_ID:
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "product_id must be shuabao")
    if descriptor.get("purpose") != SIGNING_PURPOSE:
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "signing purpose is not a release descriptor")

    version = _require_version(descriptor.get("version"), "version")
    minimum = _require_version(descriptor.get("minimum_supported_version"), "minimum_supported_version")
    try:
        source_sha, manifest, channel = validate_release_identity(
            str(descriptor.get("source_sha") or ""),
            str(descriptor.get("release_manifest_sha256") or ""),
            str(descriptor.get("release_channel") or ""),
        )
    except ValueError as exc:
        raise ReleaseDistributionError("INVALID_IDENTITY", "invalid release identity") from exc

    bundle_sha = str(descriptor.get("bundle_sha256") or "").strip().lower()
    if not _HEX64.fullmatch(bundle_sha):
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "bundle_sha256 must be 64 hex characters")
    bundle_size = _require_positive_int(descriptor.get("bundle_size"), "bundle_size")
    sequence = _require_positive_int(descriptor.get("release_sequence"), "release_sequence")
    bundle_name = _require_bundle_name(descriptor.get("bundle_name"))
    key_id = str(descriptor.get("key_id") or "").strip()
    if not _KEY_ID_RE.fullmatch(key_id):
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "key_id is not a safe token")
    published_at = _canonical_timestamp(descriptor.get("published_at"))
    mandatory = descriptor.get("mandatory")
    if not isinstance(mandatory, bool):
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "mandatory must be a boolean")
    changelog = _require_changelog(descriptor.get("changelog_summary"))

    return {
        "schema_version": DESCRIPTOR_SCHEMA_VERSION,
        "product_id": PRODUCT_ID,
        "version": version,
        "release_channel": channel,
        "source_sha": source_sha,
        "release_manifest_sha256": manifest,
        "bundle_sha256": bundle_sha,
        "bundle_size": bundle_size,
        "bundle_name": bundle_name,
        "published_at": published_at,
        "minimum_supported_version": minimum,
        "mandatory": mandatory,
        "release_sequence": sequence,
        "changelog_summary": changelog,
        "key_id": key_id,
        "purpose": SIGNING_PURPOSE,
    }


def sign_descriptor(private_key: Ed25519PrivateKey, descriptor: Mapping[str, Any]) -> bytes:
    """Off-box helper. The distribution server must not call this with a stored private key."""
    return private_key.sign(canonical_descriptor_bytes(descriptor))


def load_ed25519_public_key(pem: bytes) -> Ed25519PublicKey:
    if not pem or b"PRIVATE KEY" in pem or b"BEGIN OPENSSH PRIVATE" in pem:
        raise ReleaseDistributionError(
            "PUBLIC_KEY_INVALID",
            "release verifier accepts a public key only",
        )
    try:
        key = serialization.load_pem_public_key(pem)
    except Exception as exc:
        raise ReleaseDistributionError("PUBLIC_KEY_INVALID", "release public key could not be loaded") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ReleaseDistributionError("PUBLIC_KEY_INVALID", "release public key must be Ed25519")
    return key


def load_public_key_material(
    *,
    pem: Optional[bytes] = None,
    path: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> bytes:
    if pem:
        load_ed25519_public_key(pem)
        return pem
    source = os.environ if env is None else env
    env_pem = source.get("SHUABAO_RELEASE_PUBLIC_KEY_PEM")
    if env_pem:
        raw = env_pem.encode("utf-8")
        load_ed25519_public_key(raw)
        return raw
    key_path = path or source.get("SHUABAO_RELEASE_PUBLIC_KEY_PATH") or ""
    if not key_path:
        raise ReleaseDistributionError(
            "PUBLIC_KEY_INVALID",
            "release public key is not configured",
        )
    key_file = Path(key_path)
    if not key_file.is_file() or key_file.is_symlink():
        raise ReleaseDistributionError("PUBLIC_KEY_INVALID", "release public key path is not a regular file")
    raw = key_file.read_bytes()
    load_ed25519_public_key(raw)
    return raw


def parse_signature_blob(raw: bytes) -> bytes:
    text = raw.strip()
    if not text:
        raise ReleaseDistributionError("INVALID_SIGNATURE", "descriptor signature is empty")
    if text.startswith(b"{"):
        try:
            payload = json.loads(text.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReleaseDistributionError("INVALID_SIGNATURE", "descriptor signature is not valid") from exc
        if not isinstance(payload, dict):
            raise ReleaseDistributionError("INVALID_SIGNATURE", "descriptor signature is not valid")
        encoded = payload.get("signature")
        algorithm = str(payload.get("algorithm") or SIGNATURE_ALGORITHM)
        if algorithm != SIGNATURE_ALGORITHM or not isinstance(encoded, str):
            raise ReleaseDistributionError("INVALID_SIGNATURE", "descriptor signature is not Ed25519")
        text = encoded.encode("ascii", errors="strict") if encoded.isascii() else b""
    if not text:
        raise ReleaseDistributionError("INVALID_SIGNATURE", "descriptor signature is empty")
    try:
        compact = b"".join(text.split())
        decoded = _b64decode(compact)
    except Exception as exc:
        raise ReleaseDistributionError("INVALID_SIGNATURE", "descriptor signature is not valid base64") from exc
    if len(decoded) != 64:
        raise ReleaseDistributionError("INVALID_SIGNATURE", "descriptor signature length is invalid")
    return decoded


def verify_descriptor_signature(
    public_key: Ed25519PublicKey,
    canonical: bytes,
    signature: bytes,
) -> None:
    try:
        public_key.verify(signature, canonical)
    except InvalidSignature as exc:
        raise ReleaseDistributionError("INVALID_SIGNATURE", "descriptor signature verification failed") from exc


def public_latest_payload(
    descriptor: Mapping[str, Any],
    signature_b64: str,
    *,
    public_base: str,
) -> dict[str, Any]:
    """Client-facing latest metadata. Allowlisted fields only; no local paths."""
    normalized = normalize_descriptor(descriptor)
    payload = {
        "version": normalized["version"],
        "release_channel": normalized["release_channel"],
        "source_sha": normalized["source_sha"],
        "release_manifest_sha256": normalized["release_manifest_sha256"],
        "bundle_sha256": normalized["bundle_sha256"],
        "bundle_size": normalized["bundle_size"],
        "download_url": build_download_url(
            public_base,
            normalized["release_channel"],
            normalized["version"],
            normalized["bundle_name"],
        ),
        "published_at": normalized["published_at"],
        "minimum_supported_version": normalized["minimum_supported_version"],
        "mandatory": normalized["mandatory"],
        "release_sequence": normalized["release_sequence"],
        "changelog_summary": normalized["changelog_summary"],
        "signature": {
            "key_id": normalized["key_id"],
            "algorithm": SIGNATURE_ALGORITHM,
            "purpose": SIGNING_PURPOSE,
            "signature": signature_b64,
        },
        "descriptor_url": build_descriptor_url(
            public_base,
            normalized["release_channel"],
            normalized["version"],
        ),
    }
    assert_public_payload_safe(payload)
    return payload


def assert_public_payload_safe(payload: Mapping[str, Any]) -> None:
    if tuple(payload.keys()) != PUBLIC_LATEST_FIELDS and set(payload) != set(PUBLIC_LATEST_FIELDS):
        raise ReleaseDistributionError("PUBLIC_PAYLOAD_INVALID", "public latest payload is not allowlisted")
    blob = json.dumps(payload, sort_keys=True)
    lowered = blob.lower()
    for marker in _FORBIDDEN_PUBLIC_MARKERS:
        if marker.lower() in lowered:
            raise ReleaseDistributionError("PUBLIC_PAYLOAD_INVALID", "public latest payload is not safe")
    if "://" in blob.replace("https://", "").replace("http://", ""):
        # download_url / descriptor_url are the only URLs; strip them before scanning leftovers
        pass
    for key in ("path", "root", "operator_note", "updated_by", "admin_user"):
        if key in payload:
            raise ReleaseDistributionError("PUBLIC_PAYLOAD_INVALID", "public latest payload is not safe")


def resolve_published_artifact(root: Path, channel: str, version: str, name: str) -> Path:
    """Resolve a published artifact under the channel tree. Reject traversal and symlink escape."""
    root = Path(root).resolve()
    channel, version, bundle_name = _safe_public_components(channel, version, "shuabao-placeholder.zip")
    artifact = _safe_artifact_name(name) if name != bundle_name else bundle_name
    if name != bundle_name:
        artifact = _safe_artifact_name(name)
    channel_root = (root / channel).resolve()
    try:
        channel_root.relative_to(root)
    except ValueError as exc:
        raise ReleaseDistributionError("PATH_REJECTED", "download path is outside the release root") from exc
    candidate = (channel_root / version / artifact)
    if candidate.is_symlink():
        raise ReleaseDistributionError("PATH_REJECTED", "symlink escape is not allowed")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(channel_root)
    except ValueError as exc:
        raise ReleaseDistributionError("PATH_REJECTED", "download path is outside the channel root") from exc
    # staging / withdrawn / index / audit are never valid public artifact locations
    if channel in {"staging", "withdrawn", "index", "audit"}:
        raise ReleaseDistributionError("PATH_REJECTED", "download path is not a published channel")
    return resolved


class ReleaseStore:
    """Filesystem catalog of immutable published bundles plus an atomic latest pointer."""

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        public_base: str = "",
        max_bundle_bytes: int = DEFAULT_MAX_BUNDLE_BYTES,
    ) -> None:
        self.root = Path(root or DEFAULT_RELEASES_ROOT)
        self.public_base = str(public_base or "")
        self.max_bundle_bytes = int(max_bundle_bytes)
        self.staging = self.root / "staging"
        self.withdrawn = self.root / "withdrawn"
        self.index = self.root / "index"
        self.audit_dir = self.root / "audit"

    def ensure_layout(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for name in ("staging", "withdrawn", "index", "audit", *CHANNEL_DIRS):
            path = self.root / name
            path.mkdir(parents=True, exist_ok=True)
        (self.withdrawn / ".keep").touch(exist_ok=True)

    def latest_public(self, channel: str) -> Optional[dict[str, Any]]:
        channel = _require_channel(channel)
        pointer = self._read_latest_pointer(channel)
        if not pointer or not pointer.get("version"):
            return None
        version = str(pointer["version"])
        record = self._read_catalog().get("releases", {}).get(f"{channel}/{version}")
        if not record or record.get("status") != "published":
            return None
        descriptor = self._read_published_descriptor(channel, version)
        if descriptor is None:
            return None
        signature_b64 = self._read_published_signature_b64(channel, version)
        if not signature_b64:
            return None
        return public_latest_payload(descriptor, signature_b64, public_base=self.public_base)

    def publish(
        self,
        *,
        bundle_path: str | Path,
        descriptor_path: str | Path,
        signature_path: str | Path,
        public_key_pem: bytes,
        expected_key_id: Optional[str] = None,
        failpoint: Optional[str] = None,
        actor: str = "ops",
    ) -> dict[str, Any]:
        self.ensure_layout()
        actor = _require_actor(actor)
        public_key = load_ed25519_public_key(public_key_pem)
        pinned = (expected_key_id or "").strip() or None
        staging_dir = self.staging / f"pub-{os.getpid()}-{_nonce()}"
        phase = "staging"
        version = ""
        channel = ""
        try:
            staging_dir.mkdir(parents=True, exist_ok=False)
            descriptor_obj = _load_json_object(Path(descriptor_path))
            normalized = normalize_descriptor(descriptor_obj)
            if pinned and normalized["key_id"] != pinned:
                raise ReleaseDistributionError("INVALID_DESCRIPTOR", "descriptor key_id does not match configured key")
            canonical = canonical_descriptor_bytes(normalized)
            signature = parse_signature_blob(Path(signature_path).read_bytes())
            verify_descriptor_signature(public_key, canonical, signature)
            if failpoint == "after_verify_before_bundle":
                raise ReleaseDistributionError("PUBLISH_FAILED", "injected failure after signature verify")

            bundle_name = normalized["bundle_name"]
            staged_bundle = staging_dir / bundle_name
            self._copy_regular_file(Path(bundle_path), staged_bundle)
            digest, size = _hash_file(staged_bundle)
            if size != normalized["bundle_size"] or size > self.max_bundle_bytes or size <= 0:
                raise ReleaseDistributionError("BUNDLE_SIZE_MISMATCH", "bundle size does not match descriptor")
            if digest != normalized["bundle_sha256"]:
                raise ReleaseDistributionError("BUNDLE_HASH_MISMATCH", "bundle sha256 does not match descriptor")

            (staging_dir / "release-descriptor.json").write_bytes(canonical)
            signature_b64 = _b64encode(signature)
            (staging_dir / "release-descriptor.sig").write_text(signature_b64 + "\n", encoding="utf-8")

            channel = normalized["release_channel"]
            version = normalized["version"]
            with self._lock():
                self._assert_publishable(normalized)
                if failpoint == "after_verify":
                    raise ReleaseDistributionError("PUBLISH_FAILED", "injected failure before place")
                dest = self.root / channel / version
                if dest.exists() or dest.is_symlink():
                    raise ReleaseDistributionError("CONFLICT", "published release identity already exists")
                os.rename(staging_dir, dest)
                _fsync_dir(dest.parent)
                phase = "placed"
                if failpoint == "after_place":
                    raise ReleaseDistributionError("PUBLISH_FAILED", "injected failure after place")
                self._commit_published(normalized, signature_b64, actor)
                phase = "committed"
            result = {
                "event": "publish",
                "release_channel": channel,
                "version": version,
                "release_sequence": normalized["release_sequence"],
                "bundle_sha256": normalized["bundle_sha256"],
                "source_sha": normalized["source_sha"],
                "release_manifest_sha256": normalized["release_manifest_sha256"],
            }
            self._audit({**result, "actor": actor, "result": "ok"})
            return result
        except ReleaseDistributionError as exc:
            if phase == "staging" and staging_dir.exists():
                shutil.rmtree(staging_dir, ignore_errors=True)
            self._audit(
                {
                    "event": "publish_failed",
                    "release_channel": channel,
                    "version": version,
                    "actor": actor,
                    "result": exc.code,
                }
            )
            raise
        except Exception:
            if phase == "staging" and staging_dir.exists():
                shutil.rmtree(staging_dir, ignore_errors=True)
            raise

    def rollback(self, *, channel: str, version: str, actor: str = "ops") -> dict[str, Any]:
        self.ensure_layout()
        channel = _require_channel(channel)
        version = _require_version(version, "version")
        actor = _require_actor(actor)
        with self._lock():
            record = self._require_active_record(channel, version)
            pointer = self._read_latest_pointer(channel) or {}
            current = str(pointer.get("version") or "")
            if current == version:
                return {
                    "event": "rollback",
                    "release_channel": channel,
                    "version": version,
                    "previous_version": current,
                    "result": "unchanged",
                }
            if current:
                current_record = self._require_active_record(channel, current)
                if int(record["release_sequence"]) >= int(current_record["release_sequence"]):
                    raise ReleaseDistributionError(
                        "SEQUENCE_NOT_MONOTONIC",
                        "rollback target must be an older published sequence",
                    )
            self._write_latest_pointer(
                channel,
                version,
                int(record["release_sequence"]),
                event="rollback",
            )
            result = {
                "event": "rollback",
                "release_channel": channel,
                "version": version,
                "previous_version": current,
                "release_sequence": int(record["release_sequence"]),
                "bundle_sha256": record["bundle_sha256"],
            }
        self._audit({**result, "actor": actor, "result": "ok"})
        return result

    def withdraw(
        self,
        *,
        channel: str,
        version: str,
        promote_version: Optional[str] = None,
        clear_latest: bool = False,
        actor: str = "ops",
    ) -> dict[str, Any]:
        self.ensure_layout()
        channel = _require_channel(channel)
        version = _require_version(version, "version")
        actor = _require_actor(actor)
        promote = _require_version(promote_version, "promote_version") if promote_version else None
        with self._lock():
            record = self._require_active_record(channel, version)
            pointer = self._read_latest_pointer(channel) or {}
            current = str(pointer.get("version") or "")
            if current == version:
                if promote:
                    if promote == version:
                        raise ReleaseDistributionError("CONFLICT", "cannot promote a release to itself")
                    promoted = self._require_active_record(channel, promote)
                    if int(promoted["release_sequence"]) >= int(record["release_sequence"]):
                        raise ReleaseDistributionError(
                            "SEQUENCE_NOT_MONOTONIC",
                            "withdraw promote target must be an older published sequence",
                        )
                    self._write_latest_pointer(
                        channel,
                        promote,
                        int(promoted["release_sequence"]),
                        event="withdraw_promote",
                    )
                elif clear_latest:
                    self._write_latest_pointer(channel, "", 0, event="withdraw_clear")
                else:
                    raise ReleaseDistributionError(
                        "LATEST_PROTECTED",
                        "withdraw of current latest requires promote or clear",
                    )
            src = self.root / channel / version
            dest_parent = self.withdrawn / channel
            dest_parent.mkdir(parents=True, exist_ok=True)
            dest = dest_parent / version
            if dest.exists() or not src.is_dir() or src.is_symlink():
                raise ReleaseDistributionError("CONFLICT", "cannot withdraw release into an occupied path")
            os.rename(src, dest)
            catalog = self._read_catalog()
            key = f"{channel}/{version}"
            catalog["releases"][key]["status"] = "withdrawn"
            self._write_catalog(catalog)
            result = {
                "event": "withdraw",
                "release_channel": channel,
                "version": version,
                "promoted_version": promote or "",
                "cleared_latest": bool(clear_latest and current == version),
                "bundle_sha256": record["bundle_sha256"],
            }
        self._audit({**result, "actor": actor, "result": "ok"})
        return result

    def published_bundle_path(self, channel: str, version: str) -> Optional[Path]:
        """Internal ops/test helper. Not for the public API."""
        channel = _require_channel(channel)
        version = _require_version(version, "version")
        record = self._read_catalog().get("releases", {}).get(f"{channel}/{version}")
        if not record or record.get("status") != "published":
            withdrawn = self.withdrawn / channel / version
            if withdrawn.is_dir():
                name = record["bundle_name"] if record else None
                if name:
                    return withdrawn / name
            return None
        return self.root / channel / version / record["bundle_name"]

    def _commit_published(self, normalized: Mapping[str, Any], signature_b64: str, actor: str) -> None:
        catalog = self._read_catalog()
        channel = normalized["release_channel"]
        version = normalized["version"]
        key = f"{channel}/{version}"
        identity = _identity_key(channel, normalized["source_sha"], normalized["release_manifest_sha256"])
        if key in catalog["releases"] or identity in catalog["identities"]:
            raise ReleaseDistributionError("CONFLICT", "published release identity already exists")
        now = _now()
        catalog["releases"][key] = {
            "version": version,
            "release_channel": channel,
            "source_sha": normalized["source_sha"],
            "release_manifest_sha256": normalized["release_manifest_sha256"],
            "bundle_sha256": normalized["bundle_sha256"],
            "bundle_size": normalized["bundle_size"],
            "bundle_name": normalized["bundle_name"],
            "release_sequence": normalized["release_sequence"],
            "published_at": normalized["published_at"],
            "minimum_supported_version": normalized["minimum_supported_version"],
            "mandatory": normalized["mandatory"],
            "changelog_summary": normalized["changelog_summary"],
            "key_id": normalized["key_id"],
            "algorithm": SIGNATURE_ALGORITHM,
            "purpose": SIGNING_PURPOSE,
            "signature": signature_b64,
            "status": "published",
            "placed_at": now,
            "actor": actor,
        }
        catalog["identities"][identity] = version
        state = catalog["channels"].setdefault(channel, {"latest_version": "", "highest_sequence": 0})
        sequence = int(normalized["release_sequence"])
        if sequence <= int(state.get("highest_sequence") or 0):
            raise ReleaseDistributionError(
                "SEQUENCE_NOT_MONOTONIC",
                "release_sequence must increase for the channel",
            )
        state["highest_sequence"] = sequence
        state["latest_version"] = version
        catalog["channels"][channel] = state
        self._write_catalog(catalog)
        self._write_latest_pointer(channel, version, sequence, event="publish")

    def _assert_publishable(self, normalized: Mapping[str, Any]) -> None:
        channel = normalized["release_channel"]
        version = normalized["version"]
        catalog = self._read_catalog()
        key = f"{channel}/{version}"
        identity = _identity_key(channel, normalized["source_sha"], normalized["release_manifest_sha256"])
        if key in catalog["releases"] or identity in catalog["identities"]:
            raise ReleaseDistributionError("CONFLICT", "published release identity already exists")
        dest = self.root / channel / version
        withdrawn = self.withdrawn / channel / version
        if dest.exists() or dest.is_symlink() or withdrawn.exists():
            raise ReleaseDistributionError("CONFLICT", "published release identity already exists")
        state = catalog["channels"].get(channel) or {}
        highest = int(state.get("highest_sequence") or 0)
        if int(normalized["release_sequence"]) <= highest:
            raise ReleaseDistributionError(
                "SEQUENCE_NOT_MONOTONIC",
                "release_sequence must increase for the channel",
            )

    def _require_active_record(self, channel: str, version: str) -> dict[str, Any]:
        catalog = self._read_catalog()
        record = catalog.get("releases", {}).get(f"{channel}/{version}")
        artifact = self.root / channel / version
        if not record or record.get("status") != "published" or not artifact.is_dir() or artifact.is_symlink():
            raise ReleaseDistributionError("NOT_FOUND", "published release was not found")
        return record

    def _read_published_descriptor(self, channel: str, version: str) -> Optional[dict[str, Any]]:
        path = self.root / channel / version / "release-descriptor.json"
        if not path.is_file() or path.is_symlink():
            return None
        try:
            return normalize_descriptor(_load_json_object(path))
        except ReleaseDistributionError:
            return None

    def _read_published_signature_b64(self, channel: str, version: str) -> str:
        path = self.root / channel / version / "release-descriptor.sig"
        if not path.is_file() or path.is_symlink():
            return ""
        try:
            raw = parse_signature_blob(path.read_bytes())
        except ReleaseDistributionError:
            return ""
        return _b64encode(raw)

    def _read_latest_pointer(self, channel: str) -> Optional[dict[str, Any]]:
        path = self.index / f"latest-{channel}.json"
        if not path.is_file() or path.is_symlink():
            return None
        try:
            payload = _load_json_object(path)
        except ReleaseDistributionError:
            return None
        return payload

    def _write_latest_pointer(self, channel: str, version: str, sequence: int, *, event: str) -> None:
        payload = {
            "schema_version": 1,
            "release_channel": channel,
            "version": version,
            "release_sequence": sequence,
            "event": event,
            "updated_at": _now(),
        }
        _atomic_write_json(self.index / f"latest-{channel}.json", payload)
        catalog = self._read_catalog()
        state = catalog["channels"].setdefault(channel, {"latest_version": "", "highest_sequence": 0})
        state["latest_version"] = version
        catalog["channels"][channel] = state
        self._write_catalog(catalog)

    def _catalog_path(self) -> Path:
        return self.index / "catalog.json"

    def _read_catalog(self) -> dict[str, Any]:
        path = self._catalog_path()
        if not path.exists():
            return {"releases": {}, "identities": {}, "channels": {}}
        if path.is_symlink() or not path.is_file():
            raise ReleaseDistributionError("CATALOG_INVALID", "release catalog is not a regular file")
        payload = _load_json_object(path)
        payload.setdefault("releases", {})
        payload.setdefault("identities", {})
        payload.setdefault("channels", {})
        return payload

    def _write_catalog(self, payload: Mapping[str, Any]) -> None:
        _atomic_write_json(self._catalog_path(), dict(payload))

    def _audit(self, event: Mapping[str, Any]) -> None:
        try:
            self.audit_dir.mkdir(parents=True, exist_ok=True)
            safe = {k: event[k] for k in event if k in {
                "event",
                "release_channel",
                "version",
                "previous_version",
                "promoted_version",
                "cleared_latest",
                "release_sequence",
                "bundle_sha256",
                "source_sha",
                "release_manifest_sha256",
                "actor",
                "result",
            }}
            safe["at"] = _now()
            line = json.dumps(safe, sort_keys=True, separators=(",", ":")) + "\n"
            path = self.audit_dir / "release-audit.jsonl"
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            # Audit must not hide a successful pointer update, but publish records
            # already happened. Swallowing here only covers post-commit audit IO.
            return

    @contextmanager
    def _lock(self) -> Iterator[None]:
        self.ensure_layout()
        lock_path = self.index / ".lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _copy_regular_file(self, src: Path, dest: Path) -> None:
        if not src.is_file():
            raise ReleaseDistributionError("INVALID_BUNDLE", "bundle is not a regular file")
        if dest.exists() or dest.is_symlink():
            raise ReleaseDistributionError("CONFLICT", "staging destination already exists")
        size = src.stat().st_size
        if size <= 0 or size > self.max_bundle_bytes:
            raise ReleaseDistributionError("BUNDLE_SIZE_MISMATCH", "bundle size is not allowed")
        in_fd = os.open(src, os.O_RDONLY)
        try:
            st = os.fstat(in_fd)
            if not stat.S_ISREG(st.st_mode):
                raise ReleaseDistributionError("INVALID_BUNDLE", "bundle is not a regular file")
            out_fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            try:
                remaining = st.st_size
                while True:
                    chunk = os.read(in_fd, 1024 * 1024)
                    if not chunk:
                        break
                    os.write(out_fd, chunk)
                    remaining -= len(chunk)
                os.fsync(out_fd)
            finally:
                os.close(out_fd)
        finally:
            os.close(in_fd)


def _safe_public_components(channel: str, version: str, bundle_name: str) -> tuple[str, str, str]:
    channel = _require_channel(channel)
    version = _require_version(version, "version")
    bundle_name = _require_bundle_name(bundle_name)
    return channel, version, bundle_name


def _safe_artifact_name(name: str) -> str:
    decoded = _reject_traversal_token(name, "artifact")
    if decoded in {"release-descriptor.json", "release-descriptor.sig"}:
        return decoded
    return _require_bundle_name(decoded)


def _require_channel(channel: str) -> str:
    text = _reject_traversal_token(str(channel or ""), "channel")
    if text not in RELEASE_CHANNELS:
        raise ReleaseDistributionError("INVALID_IDENTITY", "release_channel is not a known channel")
    return text


def _require_version(value: object, field: str) -> str:
    text = _reject_traversal_token(str(value or "").strip(), field)
    if not _VERSION_RE.fullmatch(text):
        raise ReleaseDistributionError("INVALID_IDENTITY", f"{field} is not a legal version")
    return text


def _require_bundle_name(value: object) -> str:
    text = _reject_traversal_token(str(value or "").strip(), "bundle_name")
    if not _BUNDLE_NAME_RE.fullmatch(text):
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "bundle_name is not a safe zip name")
    return text


def _reject_traversal_token(value: str, field: str) -> str:
    if not isinstance(value, str) or value == "" or "\x00" in value:
        raise ReleaseDistributionError("PATH_REJECTED", f"{field} is not a safe path component")
    decoded = unquote(value)
    if unquote(decoded) != decoded or decoded != value:
        # Reject encoded or double-encoded separators and dots.
        if "%" in value or decoded != value:
            raise ReleaseDistributionError("PATH_REJECTED", f"{field} is not a safe path component")
    if decoded in {".", ".."} or decoded.startswith("/") or decoded.startswith("\\"):
        raise ReleaseDistributionError("PATH_REJECTED", f"{field} is not a safe path component")
    if any(sep in decoded for sep in ("/", "\\", "..")):
        raise ReleaseDistributionError("PATH_REJECTED", f"{field} is not a safe path component")
    return decoded


def _require_positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > 2**31 - 1:
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", f"{field} must be a positive integer")
    return value


def _require_changelog(value: object) -> str:
    if not isinstance(value, str):
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "changelog_summary must be a string")
    if "\x00" in value or len(value) > 1024:
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "changelog_summary is not allowed")
    lowered = value.lower()
    banned = ("/home/", "/opt/", "data/releases", "signing_key", "begin private", "operator_note")
    if any(item in lowered for item in banned):
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "changelog_summary contains internal metadata")
    return value


def _require_actor(actor: str) -> str:
    text = str(actor or "ops").strip()
    if not _ACTOR_RE.fullmatch(text):
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "actor is not a safe token")
    return text


def _canonical_timestamp(value: object) -> str:
    text = str(value or "").strip()
    if not text or any(ch.isspace() and ch not in " " for ch in text):
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "published_at is invalid")
    try:
        if text.endswith("Z"):
            parsed = datetime.fromisoformat(text[:-1] + "+00:00")
        else:
            parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "published_at is invalid") from exc
    if parsed.tzinfo is None:
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "published_at must be UTC")
    utc = parsed.astimezone(timezone.utc).replace(microsecond=0)
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def _identity_key(channel: str, source_sha: str, manifest: str) -> str:
    return f"{channel}|{source_sha}|{manifest}"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _nonce() -> str:
    return hashlib.sha256(os.urandom(16)).hexdigest()[:12]


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "JSON object could not be read") from exc
    if not isinstance(payload, dict):
        raise ReleaseDistributionError("INVALID_DESCRIPTOR", "JSON value must be an object")
    return payload


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{_nonce()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest(), size


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _b64encode(raw: bytes) -> str:
    import base64

    return base64.b64encode(raw).decode("ascii")


def _b64decode(raw: bytes) -> bytes:
    import base64

    return base64.b64decode(raw, validate=True)
