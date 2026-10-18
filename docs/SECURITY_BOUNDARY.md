# Security Boundary & Cryptographic Verification

## 1. Asymmetric Cryptography Model

- **Algorithm**: Ed25519 (Edwards-curve Digital Signature Algorithm).
- **Key Distribution**:
  - **Server Side**: Securely stores the 32-byte Ed25519 Private Key in environment/vault. Private key is never transmitted over the wire or embedded in client binaries.
  - **Client Side**: Only holds the 32-byte Ed25519 Public Key.

---

## 2. Tamper Resistance Verification

The offline entitlement file contains a serialized JSON payload and an Ed25519 signature:
1. If an attacker modifies `expires_at` in the payload $\rightarrow$ Signature verification immediately fails (`InvalidSignature`).
2. If an attacker alters `device_limit` or `plan` $\rightarrow$ Signature verification fails.
3. If an attacker changes `device_id` to run on an unauthorized machine $\rightarrow$ Device identity validation fails.
4. If the offline entitlement TTL expires $\rightarrow$ Client offline check rejects token (`Offline TTLExpired`).

All 4 tampering scenarios are covered by automated unit tests in `tests/contract/test_device_and_offline.py` and passed with 100% assertions.
