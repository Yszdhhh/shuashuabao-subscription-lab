# Test Evidence

## Scope

This file records the contract, integration, and compose checks for the subscription
bridge. The compose checks are opt-in locally (`COMPOSE_E2E=1`) and are run by the
`compose-e2e` CI job after the Docker stack is started.

## P0 fixes

- **Provider selection:** `PROVIDER_MODE=keygen`, `real`, and `http_keygen` select
  `HttpKeygenProvider`; `InMemoryKeygenProvider` remains test-only.
- **Webhook secret:** `FOSSBILLING_WEBHOOK_SECRET` is the only compose/application
  secret name. Production startup fails when it is absent instead of accepting an
  empty or legacy webhook-secret value.
- **Offline binding:** issuing an offline entitlement first verifies that the
  requested fingerprint is already activated on the license. An unactivated
  Device B therefore cannot obtain an entitlement from a one-device license
  activated by Device A. Offline lifetime is server policy (48 hours by default,
  capped by license expiry), not a client-controlled TTL.

Covered by:

- `TestOfflineDeviceBinding::test_unactivated_device_cannot_obtain_offline_entitlement`
- contract and fault offline-signature tests
- application startup/configuration tests in the contract suite

## P1 fixes

- **SQLite trial ledger:** account and device trial claims are stored in SQLite and
  survive closing and reopening `SqliteEventStore`.
- **Atomic webhook idempotency:** event claiming is protected by a SQLite unique
  transaction/lock. Repeated delivery of one event ID can extend a subscription
  only once.
- **Signing/database paths:** compose uses `SIGNING_KEY_PATH=/run/secrets/signing_key.pem`
  and `SUBSCRIPTION_DB_PATH=/data/subscription_state.db`; the key and database are
  excluded from version control.

Covered by:

- `TestPersistentTrialLedger::test_trial_claims_survive_sqlite_store_restart`
- `TestConcurrentDuplicateDelivery::test_16_same_event_id_extends_once`
- existing restart and duplicate-delivery tests in
  `tests/integration/test_billing_and_idempotency.py`


## Verification executed for this change

- `python -m pytest tests/integration/test_billing_and_idempotency.py -q`:
  **35 passed**.
- Focused P0/P1 additions (duplicate delivery, offline binding, and trial
  persistence): **5 passed**.
- `python -m py_compile` for both integration test modules: **passed**.
- `docker compose ... config -q` and `bash -n infra/compose/init-db.sh`:
  **passed**.
- Compose E2E collection without a running stack: **2 skipped** as intended;
  CI sets `COMPOSE_E2E=1` after starting the stack.

## Compose E2E

`infra/compose/docker-compose.yml` starts Bridge, Keygen, Keygate, FOSSBilling,
Postgres, MariaDB, and Redis on the shared `subscription` network. Postgres runs
`infra/compose/init-db.sh`, which creates `keygen` and `keygate` databases when
missing. `tests/integration/test_compose_e2e.py` verifies Bridge health/provider
selection and reachability of the Keygen and Keygate service ports against the
running stack. CI runs the contract/unit command and compose smoke command in
separate jobs; the compose job generates an ephemeral ignored signing key before
mounting it, and Docker teardown runs even when the E2E test fails. The
authoritative pass/fail result is the workflow log for the commit under review.

Run locally:

```text
docker compose -f infra/compose/docker-compose.yml up -d --build
COMPOSE_E2E=1 python -m pytest tests/integration/test_compose_e2e.py -q
docker compose -f infra/compose/docker-compose.yml down -v
```
