# Architecture Design & Integration Contract

## 1. System Topology

```
+-------------------------------------------------------------+
|                        Client Layer                         |
|  - ShuaBao Client Runtime (Untouched, Contract Consumer)    |
|  - Verification with Ed25519 Public Key Only                |
+------------------------------+------------------------------+
                               | HTTPS (ShuaBao Contract DTO)
                               v
+-------------------------------------------------------------+
|                  ShuaBao Entitlement Bridge                 |
|  - Normalization & Lifecycle FSM Management                 |
|  - Event Ingestion & Idempotency Store                      |
|  - Provider Adapter Factory (Keygen / Keygate)              |
+------------------+-----------------------+------------------+
                   |                       |
        Webhook / API Events       License API Calls
                   |                       |
                   v                       v
+----------------------+     +--------------------------------+
|     FOSSBilling      |     | License Authority Candidate    |
| - Customer CRM       |     | - Primary: Keygen CE           |
| - Orders & Invoicing |     | - Shadow: Keygate              |
| - Payment Gateways   |     | - Policy & Machine Activation  |
+----------------------+     +--------------------------------+
```

---

## 2. Standardized Entitlement Lifecycle FSM

```
  +---------------------------------------------------------+
  |                          TRIAL                          |
  +----------------------------+----------------------------+
                               | PAYMENT_SUCCEEDED
                               v
  +---------------------------------------------------------+
  |                         ACTIVE                          | <------+
  +----------------------------+----------------------------+        |
                               | PAST_DUE / EXPIRED                  | RENEWED
                               v                                     |
  +---------------------------------------------------------+        |
  |                      GRACE / PAST_DUE                   | -------+
  +----------------------------+----------------------------+
                               | GRACE EXPIRED / REFUNDED
                               v
  +---------------------------------------------------------+
  |                   SUSPENDED / REVOKED                   |
  +---------------------------------------------------------+
```

---

## 3. Data Transfer Objects (DTO)

### Standard License DTO
```json
{
  "license_id": "lic_9921a8f",
  "status": "ACTIVE",
  "plan": "pro_monthly",
  "expires_at": "2026-09-28T00:00:00Z",
  "device_limit": 1,
  "devices_used": 1,
  "offline_until": "2026-09-04T00:00:00Z",
  "features": ["automation", "advanced_routing"]
}
```

### Offline Signed Token Format
Base64-encoded JSON payload accompanied by Ed25519 asymmetric signature. Verified purely locally by the client.
