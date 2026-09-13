"""Fail-fast validation for the 0.4 production subscription bridge.

This guard is intentionally separate from the E2E compose fixture. Production
entrypoints should run ``python -m bridge.app.production_guard`` immediately
before starting uvicorn.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Mapping

PRODUCTION_MODES = frozenset({"production", "real"})
_WEAK_PASSWORDS = frozenset({
    "admin",
    "admin123",
    "changeme",
    "password",
    "root",
    "test",
    "123456",
    "supersecretadminpassword123!",
})
_E2E_ACCOUNT_ID = "e2e00000-0000-0000-0000-000000000000"


def _value(source: Mapping[str, str], key: str) -> str:
    return str(source.get(key) or "").strip()


def validate_production_env(env: Mapping[str, str] | None = None) -> list[str]:
    """Return human-readable configuration errors for production modes.

    Non-production provider modes are deliberately ignored here. In particular,
    ``compose`` remains the repository's integration-test fixture and must not be
    promoted into a production deployment by this guard.
    """
    source = os.environ if env is None else env
    mode = _value(source, "PROVIDER_MODE").lower() or "inmemory"
    if mode not in PRODUCTION_MODES:
        return []

    errors: list[str] = []

    admin_user = _value(source, "SUBSCRIPTION_ADMIN_USER")
    admin_password = _value(source, "SUBSCRIPTION_ADMIN_PASSWORD")
    if not admin_user:
        errors.append("SUBSCRIPTION_ADMIN_USER is required in production")
    if not admin_password:
        errors.append("SUBSCRIPTION_ADMIN_PASSWORD is required in production")
    elif len(admin_password) < 16 or admin_password.lower() in _WEAK_PASSWORDS:
        errors.append("SUBSCRIPTION_ADMIN_PASSWORD is weak or a known fixture/default value")

    webhook_secret = _value(source, "FOSSBILLING_WEBHOOK_SECRET")
    if len(webhook_secret) < 32 or "changeme" in webhook_secret.lower():
        errors.append("FOSSBILLING_WEBHOOK_SECRET must be a non-default secret of at least 32 characters")

    keygen_url = _value(source, "KEYGEN_BASE_URL")
    if not keygen_url.startswith(("http://", "https://")):
        errors.append("KEYGEN_BASE_URL must be configured for the private Keygen endpoint")

    account_id = _value(source, "KEYGEN_ACCOUNT_ID")
    if not account_id or account_id == _E2E_ACCOUNT_ID:
        errors.append("KEYGEN_ACCOUNT_ID must not be empty or the E2E fixture account")

    token = _value(source, "KEYGEN_TOKEN")
    if not token or token.lower() == "changeme" or "bridge-e2e" in token.lower():
        errors.append("KEYGEN_TOKEN must be a production token, not an E2E/default value")

    if not _value(source, "KEYGEN_POLICY_ID"):
        errors.append("KEYGEN_POLICY_ID is required for production license creation")

    db_path = _value(source, "SUBSCRIPTION_DB_PATH")
    if not db_path or db_path == ":memory:":
        errors.append("SUBSCRIPTION_DB_PATH must point to persistent storage in production")

    key_pem = _value(source, "SIGNING_KEY_PEM")
    key_path = _value(source, "SIGNING_KEY_PATH")
    if not key_pem and not key_path:
        errors.append("SIGNING_KEY_PEM or SIGNING_KEY_PATH is required in production")
    elif key_path and not key_pem and not Path(key_path).is_file():
        errors.append(f"SIGNING_KEY_PATH does not exist or is not a regular file: {key_path}")

    if not _value(source, "SHUABAO_PERMIT_SIGNING_KEY_ID"):
        errors.append("SHUABAO_PERMIT_SIGNING_KEY_ID is required in production")

    return errors


def main() -> int:
    errors = validate_production_env()
    if errors:
        print("FATAL: invalid ShuaBao subscription production environment", file=sys.stderr)
        for item in errors:
            print(f" - {item}", file=sys.stderr)
        return 2
    print("ShuaBao subscription production environment guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
