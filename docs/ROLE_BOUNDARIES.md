# Role Boundaries & Isolation Matrix

## Strict Role Segregation

| Component | Permitted Responsibilities | Prohibited Responsibilities |
| :--- | :--- | :--- |
| **FOSSBilling** | Customer management, Invoice generation, Product catalog, Payment gateway integration, Subscription billing cycles. | Hardware fingerprinting, Machine slot management, Offline cryptographic license issuance, Device binding. |
| **Keygen CE** | License policy management, Machine activation / unbinding, Component-level fuzzy matching, Cryptographic offline entitlement issuance. | Direct payment gateway handling, Invoicing, Customer CRM, Pricing catalogs. |
| **Keygate** | Shadow license validation, Machine limit check, JWT/Ed25519 token issuance (for parity comparison). | Production authority, Billing orchestration. |
| **ShuaBao Bridge** | DTO normalization, Webhook event ingestion, Idempotency tracking, Entitlement FSM lifecycle routing. | Heavy custom license database, Direct client tampering logic. |
| **ShuaBao Runtime** | Public-key signature verification, Offline TTL enforcement, Grace-period worker continuation. | Server-side secret management, Direct DB queries to billing/license backends. |

## Runtime Non-Interruption Invariant

- **Active Running Workers**: When an entitlement enters `PAST_DUE`, `EXPIRED`, or `SUSPENDED`, currently executing background tasks MUST NOT be abruptly killed mid-transaction.
- **New Task Gate**: New task executions (`RunnerService.start()`) check current cached entitlement state and reject launch if invalid.
