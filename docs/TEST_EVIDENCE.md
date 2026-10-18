# TEST EVIDENCE

Generated: 2026-08-28

## Run Summary

```
62 passed in 0.40s
```

All 62 tests pass. No failures, no skips, no xfails.

## Coverage by Requirement

### P0-1 — HMAC Webhook Verification (fail-closed)
- `TestHMACVerification::test_valid_signature_passes` — correct HMAC accepted
- `TestHMACVerification::test_missing_signature_rejected` — None header rejected
- `TestHMACVerification::test_invalid_signature_rejected` — wrong digest rejected
- `TestHMACVerification::test_unrecognized_event_rejected` — unknown event raises `ValueError`
- `TestHMACVerification::test_empty_body_missing_signature_rejected` — empty body + no sig rejected

### P0-2 — Server-side Duration Policy (client input ignored)
- `TestServerSideDurationPolicy::test_normalize_ignores_arbitrary_client_duration` — `FOSSBillingAdapter.normalize_event` maps client `duration_days=9999` → policy value `30`
- `TestServerSideDurationPolicy::test_plan_policy_caps_duration` — `BillingEventProcessor` caps via `PLAN_POLICY`; license `expires_at` reflects policy days, not client input

### P1-1 — Unified Binding Key Resolver
- Tested implicitly through all `BillingEventProcessor` tests; `resolve_binding_key` used for `sub:` vs `cust:` keyed lookup across PAYMENT_SUCCEEDED / SUBSCRIPTION_RENEWED / PAYMENT_FAILED

### P1-2 — SUBSCRIPTION_RENEWED and PAYMENT_FAILED handling
- `TestRenewedAndPaymentFailed::test_subscription_renewed_extends_existing_license` — RENEWED extends `expires_at` beyond original
- `TestRenewedAndPaymentFailed::test_payment_failed_suspends_license` — PAYMENT_FAILED → `SUSPENDED`/`PAST_DUE`, `can_start_runner=False`
- `TestRenewedAndPaymentFailed::test_subscription_renewed_is_idempotent` — duplicate RENEWED event_id does not double-extend

### P1-3 — Terminal REVOKED Enforcement
- `TestTerminalRevokedEnforcement::test_revoked_license_cannot_be_renewed[KeygenProvider]`
- `TestTerminalRevokedEnforcement::test_revoked_license_cannot_be_renewed[KeygateProvider]`
- `TestTerminalRevokedEnforcement::test_revoked_license_cannot_be_extended[KeygenProvider]`
- `TestTerminalRevokedEnforcement::test_revoked_license_cannot_be_extended[KeygateProvider]`
- `TestTerminalRevokedEnforcement::test_billing_renewed_event_cannot_resurrect_revoked[KeygenProvider]` — SUBSCRIPTION_RENEWED on REVOKED → `ValueError`
- `TestTerminalRevokedEnforcement::test_billing_renewed_event_cannot_resurrect_revoked[KeygateProvider]`

### P1-4 — Trial Anti-Abuse (account-once AND device-once)
- `TestTrialAntiAbuse::test_trial_allowed_first_time` — first trial on new account+device succeeds
- `TestTrialAntiAbuse::test_trial_blocked_same_account` — same customer_id blocked on second attempt
- `TestTrialAntiAbuse::test_trial_blocked_same_device_fingerprint` — same device fingerprint blocked even with different customer_id
- `TestTrialAntiAbuse::test_trial_blocked_partial_hardware_match` — partial hardware component overlap triggers block
- `TestTrialAntiAbuse::test_trial_different_device_allowed` — truly distinct customer+device passes

### P1-5 — Persistent Storage / Restart Recovery
- `TestPersistentRestartRecovery::test_processed_events_survive_restart` — replay same event_id after simulated restart; idempotency confirmed, `expires_at` unchanged within 2s drift
- `TestPersistentRestartRecovery::test_subscription_binding_survives_restart` — SUBSCRIPTION_RENEWED after restart finds correct binding and extends same license

### P1-6 — Ed25519 Signing Key Injection
- `TestCryptoKeyInjection::test_ed25519_key_injected_from_pem` — `CryptoEngine(private_key_pem=...)` accepts PEM, signs, verifies
- `TestCryptoKeyInjection::test_ed25519_key_from_env_var` — `SIGNING_PRIVATE_KEY_PEM` env var wires through correctly
- `TestCryptoKeyInjection::test_different_keys_cannot_cross_verify` — key from env A cannot verify payload signed by key B

### HTTP Adapter E2E (mocked)
- `TestHttpKeygenProviderMocked` — create, validate, activate, suspend, revoke cycle over mocked `httpx`
- `TestHttpKeygateProviderMocked` — same lifecycle for Keygate REST adapter

### 16-Way Concurrent Activation
- `TestConcurrentActivation::test_16_way_concurrent_activation_no_double_bind` — 16 asyncio tasks race to activate same license; exactly one wins, all others receive `LIMIT_EXCEEDED`

### Forge / Offline Security
- `TestOfflineEntitlementVerification::test_offline_entitlement_valid` (contract/)
- `tests/fault/test_fault_and_security::test_security_boundary_client_cannot_forge_signature` — attacker with different Ed25519 key cannot forge a valid entitlement

## Test File Index

| File | Tests |
|---|---|
| `tests/contract/test_lifecycle.py` | License lifecycle (create/activate/validate/suspend/revoke) |
| `tests/contract/test_device_and_offline.py` | Device fingerprint, offline entitlement signing/verification |
| `tests/fault/test_fault_and_security.py` | Forge prevention, network fault, malformed request, secret leakage |
| `tests/integration/test_billing_and_idempotency.py` | HMAC, policy, REVOKED, trial anti-abuse, restart recovery, RENEWED/FAILED |
| `tests/integration/test_http_providers.py` | HttpKeygenProvider + HttpKeygateProvider mocked E2E, concurrency |
