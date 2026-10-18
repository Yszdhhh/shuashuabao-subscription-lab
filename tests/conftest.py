"""Shared fixtures: force admin credentials before bridge.app.main import."""
import os

# Fail-closed admin requires a configured secret. Force test values so leftover
# staging/prod shell env cannot desync Basic-auth helpers from live env reads.
os.environ["SUBSCRIPTION_ADMIN_PASSWORD"] = "test-admin-pass-g2-strong"
os.environ["SUBSCRIPTION_ADMIN_USER"] = "admin"
os.environ.setdefault("PROVIDER_MODE", "inmemory")
# Keep approved-releases JSON out of unit/integration imports unless a test sets it.
os.environ.pop("SHUABAO_APPROVED_RELEASES_JSON", None)
os.environ.pop("SUBSCRIPTION_DB_PATH", None)
os.environ.pop("SHUABAO_PERMIT_SIGNING_KEY_ID", None)
os.environ.pop("SHUABAO_PERMIT_PRIVATE_KEY_PEM", None)
