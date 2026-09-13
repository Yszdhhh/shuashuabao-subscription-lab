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


def test_non_production_modes_are_not_promoted_by_guard():
    for mode in ("inmemory", "compose", "keygen", "http_keygen"):
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
