# Offline Permit v2 — LOCAL-ONLY Server Implementation Report (2026-10-22)

Status: **local server-side preparation only.** Not an authorization to deploy or enable v2.
This change implements the reviewed, minimal server compatibility direction in
`GameScript-Local/docs/SUBSCRIPTION_V2_CHANGE_ORDER_20261022.md`. It is uncommitted and
left for line-by-line review. Online validation was not called; no real DB / licenses /
keys / production config were touched; no commit / push / deploy was performed.

- Repo: `G:/刷刷宝/Subscription-Lab`
- Branch: `feature/offline-permit-v2-20261022`
- Baseline HEAD at time of work: `9bee75ce6137e6f2a05a4537a05bf355f782dc85`
  (`rehearsal/r7.1b-merge`, the verified online-package source baseline)

---

## 1. Files changed

| File | Status | Reason |
| --- | --- | --- |
| `bridge/app/services/permit_issuer.py` | modified (+85 / −3) | Add schema-2 constants, the strict default-empty v2 release allowlist parser, issuer wiring, and the v2 issuance branch in `issue()`. |
| `tests/contract/test_signed_permit_v2.py` | new (19 tests) | Contract tests for v2 gating and v1 preservation. |
| `tests/integration/test_signed_permit_v2_endpoint.py` | new (2 tests) | Endpoint tests: unlisted release stays v1; listed+eligible release issues verified v2 via the existing `/v1/entitlements/validate`. |
| `tests/integration/test_client_verifier_interop.py` | new (10 tests) | Cross-repo interop against the REAL client `PermitVerifier`. |

`git status --porcelain`:
```
 M bridge/app/services/permit_issuer.py
?? tests/contract/test_signed_permit_v2.py
?? tests/integration/test_client_verifier_interop.py
?? tests/integration/test_signed_permit_v2_endpoint.py
```

### SHA256 of changed/added files
```
4C8207571B430545AE713FBDC2431275344A9A1240BC72EF8521D42AB62454EB  bridge/app/services/permit_issuer.py
7A0208D09BA38EFC810689DE0CF26BED3B95DEF3C0C24F67C6E9BDCB8ABD5418  tests/contract/test_signed_permit_v2.py
BA24176A1D6E59F75CBB3376B4E306377A4DFFB22FE0C801004ECA8904382FF8  tests/integration/test_signed_permit_v2_endpoint.py
9B4B9112012338C196242A414534739642D7DD6492EA68E130ACDD65085E524C  tests/integration/test_client_verifier_interop.py
```

---

## 2. What the server change does (and does not do)

### Added (schema-2 issuance path)
- Independent constants `OFFLINE_PERMIT_SCHEMA_VERSION = 2` and
  `MAX_OFFLINE_PERMIT_LIFETIME = timedelta(hours=24)`. The v1 constants
  (`PERMIT_SCHEMA_VERSION = 1`, `MAX_PERMIT_LIFETIME = 15min`) are untouched.
- `parse_offline_v2_releases(raw)` — strict parser for `SHUABAO_OFFLINE_V2_RELEASES_JSON`.
  Returns a `frozenset` of exact `(source_sha40, release_manifest_sha256_64, release_channel)`
  triples. **Default is EMPTY.**
- `PermitIssuer(..., offline_v2_releases=...)` and
  `PermitIssuer.from_environment(...)` read the allowlist.
- In `PermitIssuer.issue()`, **after all existing gates pass**, the issuer selects schema 2
  only when BOTH hold:
  1. the exact `(source_sha, manifest, channel)` triple is in the v2 allowlist, AND
  2. the license has a **finite** `expires_at`.
  For v2: `expires_at = min(issued_at + 24h, license.expires_at)` and a signed
  `subscription_expires_at = license.expires_at` is added to the canonical payload.
  Everything else keeps the legacy v1 path.

### Preserved (hard invariants, verified)
- `PermitRequest` wire shape is unchanged (`source_sha`, `release_manifest_sha256`,
  `release_channel`, `mode_id`). No new request/response fields.
- v1 permits are **byte-identical** to baseline (20-key payload, no
  `subscription_expires_at`, schema 1, 15-minute ceiling). See §4.
- The release approval / blocked / mode / license-expiry / device gates run **before** the
  v2 decision and are the only way to reach issuance. Nothing is enabled by channel, source,
  request version, wildcard, or "all releases."
- No change to `/v1/run/*` lease/heartbeat/release.
- A license with no expiry (`expires_at is None`) stays v1 even if its triple is listed —
  no fabricated offline/permanent entitlement.

### Compatibility-sensitive malformed-config behavior (documented + tested)
A malformed / invalid `SHUABAO_OFFLINE_V2_RELEASES_JSON` (not JSON, not a list, non-object
entry, or any bad source/manifest/channel triple) **never enables v2 and never widens a
match**. The whole v2 allowlist is disabled (returned empty) and a bounded, non-secret
`LOGGER.warning` is emitted. Existing v1 clients keep working; the server does not crash on
startup and does not fail old requests. This is a deliberate fail-safe-to-v1 choice (not
fail-closed-to-startup-crash) because empty allowlist is the safe state.

---

## 3. Test commands and counts

All tests were run with an **ephemeral Python 3.11 venv** built from the project's existing
`requirements.txt` (no new runtime deps; interpreter seeded from the project 3.11 at
`G:/刷刷宝/GameScript-Local/.venv/Scripts/python.exe`). `pytest.ini` provides
`pythonpath = . bridge`.

Owner can reproduce (from repo root) with any 3.11 env that has `requirements.txt` installed:
```powershell
python -m pytest tests/contract/test_signed_permit.py tests/contract/test_signed_permit_v2.py -q
python -m pytest tests/integration/test_signed_permit_endpoint.py tests/integration/test_signed_permit_v2_endpoint.py -q
python -m pytest tests/integration/test_client_verifier_interop.py -q
# broader no-regression sweep (no Docker needed):
python -m pytest tests/contract tests/integration/test_signed_permit_endpoint.py tests/integration/test_signed_permit_v2_endpoint.py tests/integration/test_client_verifier_interop.py tests/integration/test_release_lifecycle_g2.py -q
```

Results observed in this session:
- `tests/contract/test_signed_permit_v2.py` → **19 passed**
- `tests/integration/test_signed_permit_v2_endpoint.py` → **2 passed**
- `tests/integration/test_client_verifier_interop.py` → **10 passed**
- Baseline permit tests (`test_signed_permit.py` + `test_signed_permit_endpoint.py`) →
  **15 passed** (unchanged before and after the edit)
- Broader no-regression sweep (contract + permit endpoints + interop + release lifecycle G2)
  → **92 passed, 0 failures**

The compose-based E2E suite (`tests/integration/test_compose_e2e.py`) was **not** run: it
requires Docker and is out of scope for this local server-only change.

---

## 4. v1 compatibility evidence (byte identity)

With an empty v2 allowlist, for fixed inputs, the issued permit was reduced to its
deterministic portion (dropping the inherently-random `permit_id`/`jti`/`nonce`/`signature`)
and compared to the expected baseline v1 canonical payload:

```
v1 keys: ['allowed_modes','audience','device_fingerprint','device_id','expires_at',
          'features','issued_at','issuer','jti','key_id','license_id','nonce','permit_id',
          'product_id','release_channel','release_manifest_sha256','schema_version',
          'signature','signature_algorithm','source_sha']   (20 keys)
subscription_expires_at present: False
BYTE-IDENTICAL v1 (minus random): True
```

- `schema_version == 1`, `expires_at == issued_at + 15min`, no `subscription_expires_at`.
- The pre-existing `tests/contract/test_signed_permit.py` (exact field-set / timestamps /
  Ed25519 signature) still passes **unchanged**.

---

## 5. Client interoperability evidence

`tests/integration/test_client_verifier_interop.py` loads the REAL client verifier
read-only, by file path, as a standalone module (it imports only stdlib + `cryptography`).
Resolution order:
1. env `SHUABAO_CLIENT_PERMIT_MODULE` (override),
2. live client `../GameScript-Local/src/shuabao/subscription_permit.py` (used in this run),
3. the read-only Root snapshot `D:/Temp/root-policy-acceptance-20261022-9a2f/src/shuabao/subscription_permit.py`.

The client tree was **not** modified; the snapshot was **not** modified or restored. The
module is loaded via `importlib` (registered in `sys.modules` under a throwaway name so
`@dataclass` resolves), so the `shuabao` package `__init__` and business modules are not
imported.

Covered against the live `PermitVerifier`:
- **Positive**: server v2 (24h, future subscription) verifies as `schema_version == 2`;
  server v2 with a short (6h) subscription verifies (expiry clamped to subscription);
  server v1 still verifies as `schema_version == 1`.
- **Negative**: signature tamper → `PERMIT_SIGNATURE_INVALID`; forged (lifted)
  `subscription_expires_at` without re-signing → `PERMIT_SIGNATURE_INVALID`; device / source
  / manifest / channel / mode binding mismatch → `PERMIT_DEVICE_MISMATCH`,
  `PERMIT_SOURCE_MISMATCH`, `PERMIT_MANIFEST_MISMATCH`, `PERMIT_CHANNEL_MISMATCH`,
  `PERMIT_MODE_NOT_ALLOWED` respectively.

This proves the client accepts the server's v2 wire shape AND that none of the new fields is
unsigned or tamperable. It does **not** stand in for frozen-EXE / live-window acceptance
(see §8).

---

## 6. Config format example (PUBLIC DUMMY hashes only — do not deploy as-is)

`SHUABAO_OFFLINE_V2_RELEASES_JSON` is a JSON list of exact release triples. It is an
operational opt-in list; it does NOT replace the approval registry
(`SHUABAO_APPROVED_RELEASES_JSON` / the release-policy store). A triple must additionally be
approved, non-blocked, mode-matching, with a finite-expiry license, to ever produce v2.

```jsonc
// Example value for SHUABAO_OFFLINE_V2_RELEASES_JSON (dummy hashes):
[
  {
    "source_sha": "1111111111111111111111111111111111111111",
    "release_manifest_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
    "release_channel": "release"
  }
]
```
- `source_sha`: 40 lowercase hex. `release_manifest_sha256`: 64 lowercase hex.
  `release_channel`: one of `dev | internal-pilot | external-beta | release`.
- Default / unset / empty → v2 disabled (all releases stay v1).
- Anything malformed → v2 disabled + one bounded operator warning (no startup crash).

---

## 7. Deploy / rollback changes needed (NOT authorized here)

This section describes what a future, Owner-approved change order would do. Nothing below was
executed.

Deploy (server side only, in an approved maintenance window, by the authorized operator):
1. Deploy this server code on top of the approved baseline.
2. Keep `SHUABAO_OFFLINE_V2_RELEASES_JSON` **empty/unset** first; confirm old v1 clients still
   validate and start (`/v1/entitlements/validate` returns schema-1 permits).
3. Only then, for a single approved+accepted new build, set the exact triple in
   `SHUABAO_OFFLINE_V2_RELEASES_JSON` and confirm the real issued version, lifetime, and
   background request cadence. Logs keep only redacted error codes / counts.

Rollback:
1. First remove the build's triple from `SHUABAO_OFFLINE_V2_RELEASES_JSON` (disables new v2
   issuance immediately).
2. Then roll back code + this config. Do **not** roll back or modify the database.
3. Already-issued offline v2 permits cannot be recalled instantly; they persist up to their
   signed lifetime (≤ 24h). This is the Owner-accepted maximum revocation delay — do not claim
   instant revocation.

No new DB tables, migrations, or changed production defaults are introduced by this change.

---

## 8. Outstanding evidence (NOT satisfied by this change)

- **Frozen EXE / live-window**: source-level interop here does not substitute for the frozen
  client's TLS, subscription, and runtime checks, nor for the 6-hour background re-verification,
  temporary-offline expiry gating, explicit-reject immediate stop, stop/pause not being woken by
  background, and expired-response isolation from new workers. Those are client B2 runtime /
  Root serial-task responsibilities and remain to be demonstrated on the frozen build in a live
  window before v2 can be opened.
- Owner identified this maintenance repository and the actual deployed-package baseline
  `rehearsal/r7.1b-merge` / `9bee75ce6137e6f2a05a4537a05bf355f782dc85`. This local v2
  change has not been deployed; the recorded production protocol remains v1.
- The only real cleanup PASS on record is the SOURCE_QUICK_TEST backpack transaction, which is
  unrelated to subscription v2.

---

## 9. Final handoff text

Implemented LOCAL-ONLY server-side schema-2 (offline reusable) permit issuance in
`bridge/app/services/permit_issuer.py` on branch `feature/offline-permit-v2-20261022`
(baseline `9bee75c`), per the reviewed change order — minimal diff (+85/−3), uncommitted.
v2 is gated behind a **default-empty** exact `SHUABAO_OFFLINE_V2_RELEASES_JSON` allowlist of
`(source_sha, release_manifest_sha256, release_channel)` triples AND still requires every
existing gate (approved / non-blocked / mode / finite-expiry license / device). v2 sets
`expires_at = min(issued_at+24h, license.expires_at)` and adds a signed
`subscription_expires_at`; malformed config fails safe to v1 with a bounded operator warning,
never a crash. v1 permits are byte-identical to baseline (proven). Added 31 proportionate tests
(19 contract + 2 endpoint + 10 cross-repo interop against the real client `PermitVerifier`);
92 passed in the no-regression sweep, 0 failures, via an ephemeral 3.11 venv from the existing
`requirements.txt`. No commit/push/deploy, no online validation, no real DB/keys/config touched;
the client tree and the Root snapshot were read-only. This is preparation for a future concrete
change order, not deployment authorization; frozen-EXE / live-window acceptance remains
outstanding (§8). Root performs independent diff/test acceptance.

## 10. Root independent acceptance

- Inspected the full issuer diff, new contract/endpoint/interop tests and unchanged endpoint
  caller gates. Issuer SHA256 independently matches
  `4C8207571B430545AE713FBDC2431275344A9A1240BC72EF8521D42AB62454EB`.
- Project Python 3.11.15: independently ran baseline permit contract + new v2 contract +
  baseline permit endpoint + new v2 endpoint + real client verifier interop: **46 passed in
  0.69s**, no skips. Only existing Starlette/httpx deprecation warnings.
- Additional in-memory HTTP boundary checks with an exact v2-listed release: unbound device
  returns `DEVICE_NOT_ACTIVATED`; expired subscription returns `LICENSE_EXPIRED`. Both return
  no permit and deny runner start. No real subscription requests or database were used.
- Executed the issuer from the exact Git baseline in memory and compared complete signed v1
  responses with the new default-empty-allowlist issuer using the same ephemeral key and
  fixed test nonce/id. Full response equality, including signature, passed for no-expiry,
  1-hour-remaining and 30-day-remaining licenses.
- Accepted for local source compatibility preparation only. Deployment, frozen EXE and live
  renewal/offline behavior remain outstanding as described above. No commit, push or deployment.
