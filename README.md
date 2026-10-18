# ShuaBao Subscription Lab (SUBSCRIPTION-LAB-001)

An independent, reproducible, and auditable Subscription / License Integration Lab evaluating three upstream projects:
1. **FOSSBilling** (`upstreams/fossbilling`) - Billing, Order, Customer, and Invoice Management.
2. **Keygen CE** (`upstreams/keygen`) - Primary License Authority Candidate (Machine activation, component fuzzy matching, cryptographic offline entitlement).
3. **Keygate** (`upstreams/keygate`) - Shadow License Engine Candidate (Clean Go-based architecture, JWT/Ed25519 token issuance).

---

## Key Architecture Principles

1. **Role Boundary Isolation**:
   - FOSSBilling handles Customer / Invoicing / Payment events. Never turned into an HWID authority.
   - Keygen handles Policy / License / Machine / Component validation / Signed Offline Entitlements.
   - Keygate serves as Shadow License engine for contract comparison.
   - ShuaBao Bridge unifies DTOs and lifecycle states (`ACTIVE`, `GRACE`, `PAST_DUE`, `SUSPENDED`, `EXPIRED`, `REVOKED`, `TRIAL`).
2. **Strict Cryptographic Security Boundary**:
   - Ed25519 asymmetric signatures. Client holds only the public verification key.
   - Server private keys, payment tokens, and admin secrets never leave the backend.
3. **Zero Production Changes**:
   - ShuaBao core runtime is completely untouched.

---

## Quick Start & Test Harness

### Run Automated Contract & Verification Tests
```bash
# Linux / macOS
./scripts/run_tests.sh

# Windows (PowerShell)
.\scripts\run_tests.ps1
```

### Docker Compose
```bash
docker compose -f infra/compose/docker-compose.yml up -d
```

---

## Documentation Index
- `docs/ARCHITECTURE.md`: Detailed architecture design and contract flows.
- `docs/UPSTREAM_LOCK.md`: Exact pinned commit SHAs, licenses, and repositories.
- `docs/ROLE_BOUNDARIES.md`: Separation of concerns and boundary matrices.
- `docs/PROVIDER_COMPARISON.md`: Side-by-side feature comparison table across 13 dimensions.
- `docs/LICENSE_COMPLIANCE.md`: Legal review of FCL, AGPL, and Apache-2.0.
- `docs/SECURITY_BOUNDARY.md`: Cryptographic boundary and tamper resistance verification.
- `docs/TEST_PLAN.md`: Test strategies and contract definitions.
- `docs/TEST_EVIDENCE.md`: Complete test execution outputs and evidence.
- `docs/KNOWN_GAPS.md`: Identified gaps and missing upstream features.
- `docs/RUNBOOK.md`: Operational guides for deployment and recovery.
- `docs/DECISION_LOG.md`: Architectural decision records (ADRs).
