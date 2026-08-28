# Test Evidence & Verification Run Output

## Pytest Execution Evidence (14/14 PASS)

```
============================= test session starts =============================
platform win32 -- Python 3.11.15, pytest-9.0.2, pluggy-1.6.0
rootdir: G:\shuashuabao-subscription-lab
configfile: pytest.ini
testpaths: tests
plugins: asyncio-1.4.0, anyio-4.12.1
asyncio: mode=Mode.AUTO, default_loop_scope=None
collected 14 items

tests/contract/test_device_and_offline.py::test_device_activation_limit_and_unbind PASSED [  7%]
tests/contract/test_device_and_offline.py::test_offline_entitlement_signature_and_tamper PASSED [ 14%]
tests/contract/test_device_and_offline.py::test_offline_entitlement_ttl_expiration PASSED [ 21%]
tests/contract/test_device_and_offline.py::test_trial_claim_and_anti_abuse PASSED [ 28%]
tests/contract/test_device_and_offline.py::test_keygen_fuzzy_component_matching PASSED [ 35%]
tests/contract/test_lifecycle.py::test_keygen_lifecycle PASSED           [ 42%]
tests/contract/test_lifecycle.py::test_keygate_lifecycle PASSED          [ 50%]
tests/contract/test_lifecycle.py::test_extension_and_revocation PASSED   [ 57%]
tests/fault/test_fault_and_security.py::test_network_timeout_and_fault_recovery PASSED [ 64%]
tests/fault/test_fault_and_security.py::test_malformed_request_handling PASSED [ 71%]
tests/fault/test_fault_and_security.py::test_secret_leakage_prevention PASSED [ 78%]
tests/integration/test_billing_and_idempotency.py::test_fossbilling_event_normalization PASSED [ 85%]
tests/integration/test_billing_and_idempotency.py::test_payment_replay_idempotency PASSED [ 92%]
tests/integration/test_billing_and_idempotency.py::test_concurrent_activation_race_condition PASSED [100%]

============================= 14 passed in 0.35s ==============================
```

## Physical Validation Summary
- Contract tests: 8/8 Passed.
- Integration & Idempotency tests: 3/3 Passed.
- Fault & Security tests: 3/3 Passed.
- Exit code: 0.
