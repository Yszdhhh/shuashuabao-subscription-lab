from bridge.app.production_guard import validate_production_env


def _valid_env() -> dict[str, str]:
    return {
        "PROVIDER_MODE": "production",
        "SUBSCRIPTION_ADMIN_USER": "ops",
        "SUBSCRIPTION_ADMIN_PASSWORD": "a-strong-production-password-2026",
        "FOSSBILLING_WEBHOOK_SECRET": "webhook-secret-value-that-is-over-32-characters",
        "KEYGEN_BASE_URL": "http://keygen.internal:3000",
        "KEYGEN_ACCOUNT_ID": "11111111-2222-3333-4444-555555555555",
        "KEYGEN_TOKEN": "prod_keygen_token_value_abcdef",
        "KEYGEN_POLICY_ID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "SUBSCRIPTION_DB_PATH": "/data/subscription_state.db",
        "SIGNING_KEY_PEM": "-----BEGIN PRIVATE KEY-----\nplaceholder-for-validation-only\n-----END PRIVATE KEY-----",
        "SHUABAO_PERMIT_SIGNING_KEY_ID": "prod-2026-09",
    }


def _valid_persistent_local_env() -> dict[str, str]:
    env = _valid_env()
    env["PROVIDER_MODE"] = "inmemory"
    for key in ("KEYGEN_BASE_URL", "KEYGEN_ACCOUNT_ID", "KEYGEN_TOKEN", "KEYGEN_POLICY_ID"):
        env.pop(key)
    return env


def test_development_modes_are_not_promoted_by_guard():
    for mode in ("compose", "keygen", "http_keygen"):
        assert validate_production_env({"PROVIDER_MODE": mode}) == []


def test_production_requires_admin_credentials():
    env = _valid_env()
    env.pop("SUBSCRIPTION_ADMIN_USER")
    env.pop("SUBSCRIPTION_ADMIN_PASSWORD")
    errors = validate_production_env(env)
    assert any("SUBSCRIPTION_ADMIN_USER" in item for item in errors)
    assert any("SUBSCRIPTION_ADMIN_PASSWORD" in item for item in errors)


def test_production_rejects_known_fixture_defaults():
    env = _valid_env()
    env.update({
        "SUBSCRIPTION_ADMIN_PASSWORD": "admin",
        "KEYGEN_ACCOUNT_ID": "e2e00000-0000-0000-0000-000000000000",
        "KEYGEN_TOKEN": "changeme",
        "SUBSCRIPTION_DB_PATH": ":memory:",
    })
    errors = validate_production_env(env)
    assert any("SUBSCRIPTION_ADMIN_PASSWORD" in item for item in errors)
    assert any("KEYGEN_ACCOUNT_ID" in item for item in errors)
    assert any("KEYGEN_TOKEN" in item for item in errors)
    assert any("SUBSCRIPTION_DB_PATH" in item for item in errors)


def test_production_requires_release_signing_identity():
    env = _valid_env()
    env.pop("SHUABAO_PERMIT_SIGNING_KEY_ID")
    errors = validate_production_env(env)
    assert any("SHUABAO_PERMIT_SIGNING_KEY_ID" in item for item in errors)


def test_valid_production_environment_passes():
    assert validate_production_env(_valid_env()) == []


def test_valid_persistent_local_provider_environment_passes_without_keygen():
    assert validate_production_env(_valid_persistent_local_env()) == []


def test_persistent_local_provider_requires_persistent_sqlite():
    env = _valid_persistent_local_env()
    env["SUBSCRIPTION_DB_PATH"] = ":memory:"
    errors = validate_production_env(env)
    assert any("SUBSCRIPTION_DB_PATH" in item for item in errors)


import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("change", "expected_key"),
    [
        ({"SUBSCRIPTION_ADMIN_USER": None}, "SUBSCRIPTION_ADMIN_USER"),
        ({"SUBSCRIPTION_ADMIN_PASSWORD": None}, "SUBSCRIPTION_ADMIN_PASSWORD"),
        ({"SUBSCRIPTION_ADMIN_PASSWORD": "admin"}, "SUBSCRIPTION_ADMIN_PASSWORD"),
        ({"SUBSCRIPTION_ADMIN_PASSWORD": "SuperSecretAdminPassword123!"}, "SUBSCRIPTION_ADMIN_PASSWORD"),
        ({"SUBSCRIPTION_ADMIN_PASSWORD": "test-admin-pass-g2-strong"}, "SUBSCRIPTION_ADMIN_PASSWORD"),
        ({"SUBSCRIPTION_ADMIN_PASSWORD": "shuabao-local-admin"}, "SUBSCRIPTION_ADMIN_PASSWORD"),
        ({"SUBSCRIPTION_ADMIN_PASSWORD": "short-pw"}, "SUBSCRIPTION_ADMIN_PASSWORD"),
        ({"FOSSBILLING_WEBHOOK_SECRET": None}, "FOSSBILLING_WEBHOOK_SECRET"),
        ({"FOSSBILLING_WEBHOOK_SECRET": "too-short-secret"}, "FOSSBILLING_WEBHOOK_SECRET"),
        ({"KEYGEN_ACCOUNT_ID": "e2e00000-0000-0000-0000-000000000000"}, "KEYGEN_ACCOUNT_ID"),
        ({"KEYGEN_TOKEN": "changeme"}, "KEYGEN_TOKEN"),
        ({"KEYGEN_POLICY_ID": None}, "KEYGEN_POLICY_ID"),
        ({"SUBSCRIPTION_DB_PATH": ":memory:"}, "SUBSCRIPTION_DB_PATH"),
        ({"SIGNING_KEY_PEM": None}, "SIGNING_KEY_PEM or SIGNING_KEY_PATH"),
        ({"SIGNING_KEY_PEM": None, "SIGNING_KEY_PATH": "/nonexistent/signing_key.pem"}, "SIGNING_KEY_PATH"),
        ({"SHUABAO_PERMIT_SIGNING_KEY_ID": None}, "SHUABAO_PERMIT_SIGNING_KEY_ID"),
    ],
)
def test_each_required_production_check_fails_on_its_own(change, expected_key):
    env = _valid_env()
    for key, value in change.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    errors = validate_production_env(env)
    assert errors, f"guard accepted {change}"
    assert any(expected_key in item for item in errors), errors


def _example_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for line in (_ROOT / "infra/production/.env.example").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key] = value
    return env


def test_unedited_env_example_is_rejected():
    env = _example_env()
    env["SIGNING_KEY_PEM"] = _valid_env()["SIGNING_KEY_PEM"]  # compose mounts a key file
    errors = validate_production_env(env)
    for key in (
        "SUBSCRIPTION_ADMIN_PASSWORD",
        "FOSSBILLING_WEBHOOK_SECRET",
        "KEYGEN_ACCOUNT_ID",
        "KEYGEN_TOKEN",
        "KEYGEN_POLICY_ID",
    ):
        assert any(key in item and "placeholder" in item for item in errors), (key, errors)


def test_env_example_revision_key_is_the_one_health_reports():
    env = _example_env()
    main_src = (_ROOT / "bridge/app/main.py").read_text(encoding="utf-8")
    assert "SHUABAO_SERVICE_REVISION" in env
    assert 'os.environ.get("SHUABAO_SERVICE_REVISION")' in main_src
    assert "SERVICE_REVISION" not in {k for k in env if k != "SHUABAO_SERVICE_REVISION"}


def test_public_nginx_example_denies_every_admin_prefix():
    conf = (_ROOT / "infra/production/nginx-shuabao-subscription.conf.example").read_text(encoding="utf-8")
    main_src = (_ROOT / "bridge/app/main.py").read_text(encoding="utf-8")
    routes = set(re.findall(r'@app\.(?:get|post|put|delete)\("([^"]+)"', main_src))
    admin_routes = {r for r in routes if "/admin" in r}
    assert admin_routes, "expected admin routes in bridge"
    denied = re.findall(r"location \^~ (\S+) \{\s*return 404;", conf)
    for route in admin_routes:
        assert any(route.startswith(prefix) for prefix in denied), (route, denied)
