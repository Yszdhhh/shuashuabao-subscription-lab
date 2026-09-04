# Test Plan & Verification Strategy

## 1. Test Categories

1. **Contract Tests (`tests/contract/`)**:
   - `test_lifecycle.py`: License creation, validation, renewal (+30d), manual extension (+7d), suspension, reinstatement, and revocation.
   - `test_device_and_offline.py`: Single-device enforcement (`device_limit = 1`), second device rejection, unbinding & re-binding, offline signed token issuance, signature verification, tampering detection, and TTL expiration.
2. **Integration Tests (`tests/integration/`)**:
   - `test_billing_and_idempotency.py`: FOSSBilling webhook event normalization, event idempotency deduplication (replayed payment events do not cause double extensions), and concurrent activation handling.
3. **Fault & Security Tests (`tests/fault/`)**:
   - `test_fault_and_security.py`: Service timeout recovery, malformed payload rejections, downstream database crash simulations, and secret leakage prevention.
