#!/usr/bin/env python3
"""Off-box signed publish / rollback / withdraw for ShuaBao release bundles.

Signing happens before this tool runs. The server (and this CLI) verify a
configured Ed25519 public key, then store and publish. Never pass a private
key. Do not point --public-key at the permit signing_key.pem.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from bridge.app.services.release_distribution import (
    ReleaseDistributionError,
    ReleaseStore,
    load_public_key_material,
    public_base_from_env,
    releases_root_from_env,
)


def _print_result(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")


def _fail(exc: ReleaseDistributionError) -> int:
    sys.stderr.write(json.dumps({"ok": False, "code": exc.code, "message": exc.message}) + "\n")
    if exc.code in {"CONFLICT", "SEQUENCE_NOT_MONOTONIC", "LATEST_PROTECTED"}:
        return 3
    if exc.code in {"INVALID_DESCRIPTOR", "INVALID_SIGNATURE", "INVALID_IDENTITY", "BUNDLE_HASH_MISMATCH", "BUNDLE_SIZE_MISMATCH", "PUBLIC_KEY_INVALID", "INVALID_BUNDLE", "PATH_REJECTED"}:
        return 2
    return 1


def _store(args: argparse.Namespace) -> ReleaseStore:
    root = Path(args.root) if args.root else releases_root_from_env()
    return ReleaseStore(root=root, public_base=public_base_from_env())


def cmd_publish(args: argparse.Namespace) -> int:
    try:
        pem = load_public_key_material(path=args.public_key)
        store = _store(args)
        result = store.publish(
            bundle_path=args.bundle,
            descriptor_path=args.descriptor,
            signature_path=args.signature,
            public_key_pem=pem,
            expected_key_id=args.key_id or None,
            actor=args.actor,
        )
    except ReleaseDistributionError as exc:
        return _fail(exc)
    _print_result({"ok": True, **result})
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    try:
        result = _store(args).rollback(channel=args.channel, version=args.version, actor=args.actor)
    except ReleaseDistributionError as exc:
        return _fail(exc)
    _print_result({"ok": True, **result})
    return 0


def cmd_withdraw(args: argparse.Namespace) -> int:
    try:
        result = _store(args).withdraw(
            channel=args.channel,
            version=args.version,
            promote_version=args.promote,
            clear_latest=args.clear_latest,
            actor=args.actor,
        )
    except ReleaseDistributionError as exc:
        return _fail(exc)
    _print_result({"ok": True, **result})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Publish or roll back a signed ShuaBao release bundle")
    parser.add_argument("--root", default="", help="release artifact root (default: SHUABAO_RELEASES_ROOT or data/releases)")
    parser.add_argument("--actor", default="ops", help="audit actor token")
    sub = parser.add_subparsers(dest="command", required=True)

    publish = sub.add_parser("publish", help="verify a signed descriptor and publish a bundle")
    publish.add_argument("--bundle", required=True, help="path to the zip bundle to store")
    publish.add_argument("--descriptor", required=True, help="path to the versioned descriptor JSON")
    publish.add_argument("--signature", required=True, help="detached Ed25519 signature (base64 or JSON)")
    publish.add_argument("--public-key", default="", help="Ed25519 public key PEM (not a private key)")
    publish.add_argument("--key-id", default="", help="optional expected descriptor key_id")
    publish.set_defaults(func=cmd_publish)

    rollback = sub.add_parser("rollback", help="point channel latest at a previously published version")
    rollback.add_argument("--channel", required=True)
    rollback.add_argument("--version", required=True)
    rollback.set_defaults(func=cmd_rollback)

    withdraw = sub.add_parser("withdraw", help="move a published release out of the active index without deleting bytes")
    withdraw.add_argument("--channel", required=True)
    withdraw.add_argument("--version", required=True)
    withdraw.add_argument("--promote", default="", help="older published version to make latest if withdrawing current latest")
    withdraw.add_argument("--clear-latest", action="store_true", help="clear latest if withdrawing the current latest")
    withdraw.set_defaults(func=cmd_withdraw)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "withdraw":
        args.promote = args.promote or None
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
