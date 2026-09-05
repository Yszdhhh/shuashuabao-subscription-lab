# ShuaBao License Card Operations & Lifecycle Runbook

## 1. Overview & Architecture

This runbook documents the minimal, offline-capable operator tool and lifecycle engine for ShuaBao subscription license cards (卡密).
The solution builds directly upon existing authorities without duplicating subscription systems, databases, activation services, or permit issuers.

Key design principles:
- **Deferred activation**: Card validity duration does NOT begin upon generation. Clock starts strictly upon the first successful client activation on the server.
- **Inventory safety**: Inventory cards can be generated in bulk and distributed one by one over arbitrary timeframes without premature expiration.
- **AI-independent**: Pure Python stdlib cryptographic randomness (`secrets`), zero dependency on LLM / Grok / cloud AI.
- **Single authority reuse**: Cards exist as first-class entries in `local_licenses`, activated via `/v1/devices/activate`, validated via `/v1/entitlements/validate`, and bound to existing release policies and permit issuance.

---

## 2. Card Lifecycle Semantics

```
              generate
                 │
                 ▼
          ┌─────────────┐
          │   UNUSED    │ ◄── created_at set, duration set, activated_at=NULL, expires_at=NULL
          └──────┬──────┘     (Remains valid indefinitely regardless of created_at age)
                 │
                 │ 1st successful /v1/devices/activate
                 │ (Atomic server-time assignment: activated_at = server_now,
                 │  expires_at = activated_at + duration_seconds)
                 ▼
          ┌─────────────┐
          │   ACTIVE    │ ◄── Valid for runner, heartbeat/validate idempotent (never extends timer)
          └──────┬──────┘
                 │
        ┌────────┴────────┐
        │ server_now >=   │ Operator revocation
        │ expires_at      │
        ▼                 ▼
 ┌─────────────┐   ┌─────────────┐
 │   EXPIRED   │   │   REVOKED   │
 └─────────────┘   └─────────────┘
```

### Lifecycle Rules:
1. **UNUSED**:
   - `created_at`: recorded at generation.
   - `duration_seconds`: authoritative duration (e.g. 86400s for 1d, 259200s for 3d, 604800s for 7d, 2592000s for 30d).
   - `activated_at`: `NULL`.
   - `expires_at`: `NULL`.
   - `validate_license`: returns `valid=False, status=UNUSED, can_start_runner=False, code=UNUSED`.
   - Time passage after generation does not reduce validity.

2. **First Successful Activation**:
   - Must be triggered by `/v1/devices/activate`.
   - Server authoritative timestamp `server_now = datetime.now(timezone.utc)`.
   - Atomically records `activated_at = server_now`, `expires_at = server_now + timedelta(seconds=duration_seconds)`, and `status = ACTIVE`.
   - Atomically binds device hardware fingerprint and components.
   - Concurrency protection: `asyncio.Lock` inside the server process and SQLite `BEGIN IMMEDIATE` transaction across processes ensure two devices cannot concurrently double-activate an UNUSED card.

3. **Subsequent Activations & Validations**:
   - Same device: idempotent success, updates heartbeat, strictly preserves `activated_at` and `expires_at`.
   - Different device (when device_limit=1): rejects with `DEVICE_LIMIT_EXCEEDED`, strictly preserves `activated_at` and `expires_at`.
   - Repeated validation: never extends or restarts expiry clock.

4. **Failed Activation**:
   - Bad key, device limit rejection, uncommitted batch, or database rollback leaves the card in `UNUSED` state with `activated_at=NULL` and `expires_at=NULL`. Timer never starts.

5. **Terminal / Inactive States**:
   - `EXPIRED`: when `server_now >= expires_at` (zero grace period for cards; exact boundary `>=` is expired), validation and activation are rejected.
   - `REVOKED`: terminal state, validation and activation are rejected.

---

## 3. Database Schema & Migration

### Schema Modification Details
1. **`local_licenses`** (existing):
   - Unchanged column schema: `(id TEXT PRIMARY KEY, key TEXT UNIQUE NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL)`.
   - `data_json` carries additive fields:
     - `status`: `"UNUSED"` (added to `LicenseStatus` enum)
     - `duration_seconds`: integer seconds
     - `activated_at`: ISO timestamp or null
     - `expires_at`: ISO timestamp or null
     - `metadata.batch_id`: batch identifier
     - `metadata.is_card`: boolean true
2. **`license_batches`** (additive table):
   ```sql
   CREATE TABLE IF NOT EXISTS license_batches (
       batch_id TEXT PRIMARY KEY,
       plan TEXT NOT NULL,
       duration_seconds INTEGER NOT NULL,
       card_count INTEGER NOT NULL,
       operator_note TEXT,
       status TEXT NOT NULL DEFAULT 'COMMITTED',
       created_at TEXT NOT NULL
   );
   ```
   - `status`: Minimal recoverable batch state machine:
     - `PREPARED`: batch records inserted before local CSV rename is confirmed.
     - `COMMITTED`: CSV rename (`os.replace`) succeeded; cards are eligible for activation.
     - `FAILED`: CSV rename failed; cards cannot be activated (`BATCH_NOT_COMMITTED`).
3. **Migration nature**:
   - 100% additive, backward-compatible, and non-destructive.
   - Existing licenses, trial reservations, bindings, and release policies are completely unaffected.

---

## 4. Operator CLI Usage (`tools/card_admin.py`)

The CLI supports two operating modes:
- **Authoritative Remote Mode (Production)**: The Windows operator CLI connects to the production authoritative backend via HTTPS Admin API (`--api-url https://api.shuashuabao.com --admin-key <secret>`). No local SQLite DB is created on the operator's machine; the production database remains the single source of truth.
- **Local SQLite Mode (Development/Offline)**: Uses `--db ./data/subscription_state.db`.

### 4.1 Bulk Generation
Remote authoritative generation (Recommended):
```bash
python tools/card_admin.py generate --plan 1d --count 100 --output cards_1d.csv --api-url https://api.shuashuabao.com --admin-key $SUBSCRIPTION_ADMIN_PASSWORD
```

Local development generation:
```bash
python tools/card_admin.py generate --plan 1d --count 100 --output cards_1d.csv
```

Options:
- `--plan`: required plan identifier (`1d`, `3d`, `7d`, `30d` or custom like `14d`).
- `--count`: number of cards to generate (default: `1`).
- `--output`: path to export plaintext CSV.
- `--api-url`: backend URL (or env `SHUABAO_ADMIN_URL`).
- `--admin-key`: admin key/password (or env `SUBSCRIPTION_ADMIN_PASSWORD`).
- `--note`: optional operator note (e.g. `--note "Discord promo 2026-09"`).
- `--duration-seconds`: optional manual override for duration in seconds.
- `--batch-id`: optional manual batch ID override (fail-closed: duplicate `batch_id` will be rejected).
- `--device-limit`: device limit per card (default: `1`).
- `--prefix`: optional custom card prefix (e.g. `SSB-D1-`).
- `--db`: path to SQLite database (local mode fallback).

### 4.2 List Batches
```bash
python tools/card_admin.py list-batches --api-url https://api.shuashuabao.com
```

### 4.3 List Cards (Masked)
```bash
python tools/card_admin.py list-cards --batch-id batch_20260905_153000_a1b2 --status UNUSED --limit 50 --api-url https://api.shuashuabao.com
```

### 4.4 Inspect Card (Masked)
```bash
python tools/card_admin.py inspect SSB-D1-2345-6789-ABCD-EFGH --api-url https://api.shuashuabao.com
```

---

## 5. Security, Masking & HTTPS Admin API

1. **Card Code Randomness**:
   - Uses `secrets.choice` from unambiguous alphabet `23456789ABCDEFGHJKMNPQRSTUVWXYZ` (31 characters: 8 digits + 23 uppercase letters).
   - Excludes confusing characters: `0`, `O`, `1`, `I`, `L`.
   - Format: `SSB-D{days}-{4chars}-{4chars}-{4chars}-{4chars}` (~79.3 bits entropy).
   - No sequential numbers as secrets.

2. **Plaintext Leak Prevention & Single Normal Export Point**:
   - Initial batch generation response and CSV export are the **ONLY** normal export point for plaintext card codes.
   - Plaintext card codes are **never** dumped in stdout logs during normal operations.
   - All management surfaces (`list-cards`, `inspect`, `/admin` web console, Admin API) display strictly masked codes: e.g. `SSB-D1-ABCD-****-****-PQRT`.
   - In `/admin`, card licenses (`is_card=True`) omit the copy button and plaintext `data-key` attributes.
   - CSV export contains strictly: `code,plan,duration_seconds,batch_id,created_at`. No admin passwords or server secrets.

3. **HTTPS Admin API Endpoints**:
   - `POST /admin/cards/batches`: Protected by `X-Admin-Key` / Basic Auth. Prepares cards in `PREPARED` state, returns batch metadata and initial plaintext cards for operator CSV save.
   - `POST /admin/cards/batches/{batch_id}/commit`: Transitions batch state to `COMMITTED` after local CSV write succeeds.
   - `POST /admin/cards/batches/{batch_id}/fail`: Transitions batch state to `FAILED` if local CSV rename fails.
   - `GET /admin/cards/batches`: Returns list of batches with their status.
   - `GET /admin/cards`: Returns masked cards list with filters (`batch_id`, `status`, `limit`).
   - `GET /admin/cards/{card_or_id}`: Returns masked card details and device activations.

4. **P1 Security Debt Disclosure**:
   > [!WARNING]
   > **P1 Security Debt**: The underlying system currently persists license keys as plaintext in `local_licenses.key` and `data_json["key"]`. To maintain full backward compatibility with the existing authority without performing an invasive cryptographic overhaul, cards are stored in accordance with existing authority.
   > A future milestone should migrate license keys to salted cryptographic hashes (e.g. SHA-256 with server salt or Argon2) for lookup, storing only masked codes for operational display.

---

## 6. Verification Summary

All specification requirements and regression checks are covered:
- Strict exact boundary expiry (`now >= expires_at`).
- Duplicate `batch_id` fail-closed rejection.
- Recoverable batch state machine (`PREPARED -> COMMITTED` or `FAILED`).
- Remote HTTPS Admin API & operator CLI verification.
