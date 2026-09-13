# 0.4 production hardening — local evidence and VPS status (2026-09-13)

Branch: `ops/production-hardening-0.4-20260913`. Cloud baseline `dd1f4ac5`
(Production Hardening CI run `34749892450`). Every value below is a throwaway
local test value or a redacted observation; no real secret, card key, token or
private key appears in this document.

## 1. Result summary

| Item | Result |
|---|---|
| Cloud CI baseline reproduced locally (`dd1f4ac`) | yes: guard tests 5 passed, `compileall` OK |
| Production guard tests (this branch) | 24 passed |
| Full repo test suite on Windows | 146 passed, 5 skipped, 9 failed. The same 9 fail on untouched `dd1f4ac` (`os.O_NOFOLLOW` is POSIX-only in `release_distribution.py`), so they are a platform gap, not a regression. |
| `docker compose --env-file infra/production/.env -f infra/production/bridge-compose.yml config` | exit 0; bridge publishes `host_ip: 127.0.0.1`, `target: 8000` |
| Startup-level fail-fast (real `guard && exec uvicorn` chain) | 14/14 bad configs exit 2 before uvicorn starts |
| Valid production config starts | yes (details in section 3) |
| Real VPS-A verification | **BLOCKED**: no operator access from this workstation (section 4) |
| Production traffic switched | **no** |

## 2. Defects found locally and fixed on this branch

1. **An unedited copy of `.env.example` passed the guard.** The
   `REPLACE_WITH_...` placeholders for the admin password, webhook secret,
   Keygen account/token/policy are long enough and are not in the weak list, so
   `cp .env.example .env` plus a key file started production with a publicly
   known admin password. This is exactly the "operator forgot to set admin
   credentials" case the hardening exists for. Fix: the guard now rejects any
   guarded value containing `REPLACE_WITH`.
2. **Two in-repo fixture admin passwords passed the guard**:
   `test-admin-pass-g2-strong` (tests) and `shuabao-local-admin`
   (`infra/compose/docker-compose.local.yml`). Both are now in the weak list.
3. **`.env.example` set `SERVICE_REVISION`, but the bridge reads
   `SHUABAO_SERVICE_REVISION`** (fallback `SHUABAO_DEPLOYMENT_ID`). Deployed as
   documented, `/health` would never show the revision required by acceptance
   item "revision matches the expected SHA". The example now uses
   `SHUABAO_SERVICE_REVISION`.
4. **The public nginx example only denied `/admin`.** The JSON admin API
   `/v1/admin/releases` (release-policy read and write, Basic auth) was proxied
   to the Internet. The example now also returns 404 for `^~ /v1/admin`, and a
   contract test asserts that every `/admin` route in `bridge/app/main.py` is
   covered by a public deny prefix. `tools/approve_dev_release.py` already
   accepts loopback HTTP, so operators keep using it through an SSH tunnel.

New tests: one parametrized case per required fail-fast condition (16 cases),
the unedited-`.env.example` case, the revision-key contract, and the nginx
admin-prefix contract.

## 3. Local startup-level acceptance

Harness: the exact compose entry chain
`python -m bridge.app.production_guard && exec python -m uvicorn bridge.app.main:app`
run through Git Bash on Windows with isolated throwaway values (random admin
password, 37 characters; local Ed25519 test key; SQLite in a scratch directory).

| Bad configuration | exit | uvicorn started |
|---|---|---|
| no `SUBSCRIPTION_ADMIN_USER` | 2 | no |
| no `SUBSCRIPTION_ADMIN_PASSWORD` | 2 | no |
| password `admin` | 2 | no |
| fixture password (e2e Keygen admin) | 2 | no |
| fixture password (repo tests) | 2 | no |
| no `FOSSBILLING_WEBHOOK_SECRET` | 2 | no |
| short webhook secret | 2 | no |
| E2E `KEYGEN_ACCOUNT_ID` | 2 | no |
| `KEYGEN_TOKEN=changeme` | 2 | no |
| no `KEYGEN_POLICY_ID` | 2 | no |
| `SUBSCRIPTION_DB_PATH=:memory:` | 2 | no |
| signing key file missing | 2 | no |
| no `SHUABAO_PERMIT_SIGNING_KEY_ID` | 2 | no |
| unedited `.env.example` | 2 | no (5 placeholder errors) |

Valid configuration, bound to `127.0.0.1`:

| Check | Observed |
|---|---|
| `/health` | `healthy`, `provider_mode=production`, `service_revision` reported |
| `/admin` without credentials | 401 |
| `/admin` wrong credentials | 401 |
| `/admin` correct credentials (loopback) | 200 |
| `/v1/admin/releases` with `admin:admin` | 401 |
| Seed an approved release policy via `/v1/admin/releases` | 200 |
| `/v1/releases/status` approved identity | `approved` |
| `/v1/releases/status` non-approved identity | `not_approved` |
| Restart the bridge on the same SQLite file | approved policy still present, status still `approved` |

Not verified locally: LIVE permit issuance through `/v1/entitlements/validate`
in production mode, because it needs a real Keygen. The permit issuer logic is
covered by the in-memory suite (`tests/contract/test_signed_permit.py`, passing),
but that is not production evidence.

## 4. VPS-A status: BLOCKED

- This workstation has no SSH access to VPS-A. The only SSH host configured
  here has no `/home/box/services`, so it is not the documented live host (`/home/box/services/shuashuabao-subscription-lab`,
  uvicorn `0.0.0.0:8010`, Cloudflare Quick Tunnel, no docker, no nginx; see
  `docs/G2_FIXED_HTTPS_HOSTNAME_RUNBOOK.md` and `docs/ops/release-distribution.md`).
  Earlier project records show VPS-A is operated through a separate operator
  agent.
- Public-edge probe, 2026-09-13T10:12Z: the client default subscription URL
  `quebec-luis-flooring-kenneth.trycloudflare.com` (main repo
  `src/shuabao/settings.py:121`, `src/shuabao/subscription_client.py:47`)
  returns **NXDOMAIN** from Cloudflare's authoritative DNS (DoH `Status: 3`) and
  from 1.1.1.1 and 8.8.8.8. The Quick Tunnel has rotated or is down, so the
  shipped default endpoint is currently unreachable. This supports B1
  (a fixed HTTPS hostname) as a hard 0.4 blocker.
- Not executed, all pending VPS access: the read-only inventory
  (revision, supervisor/unit, `PROVIDER_MODE`, bind addresses, Keygen/PostgreSQL/Redis
  binds, SQLite path, key permissions, credential presence), backups, public/private
  `/admin` checks, restart persistence, permit approved/rejected checks, and the
  external port scan.

## 5. Conditional upgrade plan (only if VPS-A is verified to run `306c66a`)

`306c66a..dd1f4ac` (plus this branch's fixes) is purely additive: 17 files,
+2553/-0, no SQLite DDL change. `main.py` gains only an import and the public
`GET /v1/releases/latest` (file-backed, returns 503/404 until a release root is
configured). No change to permit v1, signing, or existing routes.

1. **Read-only inventory first** (section 4 list). Record the running PID/cmdline,
   `git rev-parse HEAD`, and `/health` on `127.0.0.1:8010`.
2. **Back up**: the supervisor/start scripts, the environment/credential files,
   the tunnel config, the bridge SQLite file (`sqlite3 .backup`), the Keygen
   PostgreSQL database (`pg_dump -Fc`), and the current commit identity. Restore
   into a staging copy once before relying on it.
3. **Environment delta for `PROVIDER_MODE=production`**: the guard requires strong
   admin credentials, a webhook secret of 32+ characters, the Keygen account/token/policy,
   a persistent `SUBSCRIPTION_DB_PATH`, the signing key, and
   `SHUABAO_PERMIT_SIGNING_KEY_ID`. **Keep both the key id and the signing key itself
   unchanged.** The client maps `key_id` to a pinned Ed25519 public key and rejects
   unknown ids with `PERMIT_KEY_UNKNOWN` (main repo
   `src/shuabao/subscription_permit.py:311-329`). Add `SHUABAO_SERVICE_REVISION`.
   The release-distribution variables stay unset for 0.4.
4. **Topology gap**: the live host runs uvicorn on `0.0.0.0:8010` behind a Quick
   Tunnel with no nginx. The minimum hardened step without new infrastructure:
   rebind uvicorn to `127.0.0.1:8010`; point a **Named** Tunnel (per the G2 runbook)
   at it with ingress rules that return 404 for `/admin*` and `/v1/admin*`; run the
   guard in the supervisor before `exec uvicorn`. nginx/docker are optional, not required.
5. **Staging first**: a second uvicorn on another loopback port from the new
   revision with a copy of the SQLite file, then check health, admin and permit
   behaviour.
6. **Cutover** (restart required, a few seconds of downtime): stop the old
   uvicorn, start the new one with the guard, verify `/health`, then move tunnel
   ingress. A client pinned to the rotating Quick Tunnel URL needs the fixed
   hostname (B1) anyway.
7. **Rollback to `306c66a`**: stop the new process, `git checkout 306c66a`,
   restore the backed-up start script and environment file, start uvicorn, and
   verify `/health`. There is no schema change, so the SQLite file is compatible
   in both directions. Only restore the SQLite backup if data was corrupted.

This plan is not authorization to switch production. It needs the VPS
inventory and explicit owner approval first.

## 6. VPS-A operator report audit and local edge probe (2026-09-13)

Source: the operator's one-time, redacted Phase 1--2 report. This section
contains no credential, card key, token, private-key material, or database
content. It is an audit record, not an authorization to change VPS-A.

| Check | Expected | Actual | Result |
|---|---|---|---|
| A--I report format and secret redaction | Complete sections; no secret plaintext | All sections A--I supplied. Values reported for credentials are presence, length, permissions, or public-key fingerprint; no secret plaintext was observed. | PASS |
| Phase-0 stop rule | Stop after Phase 2 if live revision diverges materially or Keygen is absent | Live tree is `46d9aafa4dc2` on `master`, does not contain `306c66a`, and Keygen/PostgreSQL/Redis are absent. Operator stopped before staging. | PASS |
| Production untouched | No production process, configuration, data, DNS, or traffic change | Operator attests no restart/kill, no production configuration or data write, no checkout/pull/reset in the live tree, and no traffic switch. | PASS (attested) |
| Local backup | New protected backup; SQLite integrity and row counts verified | Protected Phase-2 backup was created; live and backup SQLite integrity were `ok` and reported table counts matched. PostgreSQL restore is N/A because PostgreSQL is absent. | PASS (local backup only) |
| Required staging acceptance | Guard, loopback staging, admin, policy, permit, and persistence checks against `8a02593` | Not run because the stop rule applied. No staging result may be inferred from local tests. | BLOCKED |
| Production provider prerequisites | Deployed provider is persistent and covered by the startup guard | Live `inmemory` is a historical name for the SQLite-backed local provider, so Keygen is not required. Before this audit, however, the guard skipped this mode entirely; the branch now covers its persistent-storage, credential, webhook, and signing prerequisites without requiring Keygen. Approved-release policy still needs a real candidate identity before release. | FIXED LOCALLY; VPS STAGING REQUIRED |
| Production network posture | Bridge not publicly bound; public admin routes denied through a working fixed endpoint | Live uvicorn is reported on `0.0.0.0:8010`; Quick Tunnel is down, `cloudflared` is absent, and no Named Tunnel/fixed hostname is active. | FAIL |
| Git provenance for upgrade | Target revision available through an isolated clone/worktree | Live directory has no usable target/history objects or remote. A separate clone/worktree is required before staging. | FAIL |
| Cutover | Owner-approved fixed hostname, staging PASS, and a validated provider/release policy | None of these prerequisites is present. | BLOCKED |

### Local external TCP probe

The operator reported the container's public egress IPv4 as `104.30.180.111`
and only one listening service (`0.0.0.0:8010`). From this workstation, TCP
connection attempts to ports `22, 80, 443, 3000, 3306, 5432, 6379, 8000, 8010,
8088, 9000` did not establish within five seconds.

This is **not** proof that VPS-A is closed: the reported address is observed
from an overlay-container egress lookup and has not been established as a
dedicated, routable VPS-A address. Therefore the external-exposure conclusion
is **BLOCKED/INCONCLUSIVE**. The live `0.0.0.0:8010` bind remains a FAIL until
the Owner supplies a verified instance address or cloud-edge/security-group
evidence and a repeat probe can be correlated to that instance.

### Required next actions (ownership preserved)

1. **Deployment decision:** retain the SQLite-backed local provider on VPS-A;
   do not introduce Keygen/PostgreSQL for 0.4. It is the single subscription
   writer, while the development machine keeps recoverable backups and VPS-B
   remains a cold standby/other-24x7-task node rather than a concurrent writer.
2. **Owner:** supply a fixed domain in the same Cloudflare account/zone as the
   intended Named Tunnel, and decide the approved-release policy contents.
3. **Grok/operator:** obtain GitHub access in an isolated clone/worktree,
   validate `8a025930deb6`, and run the skipped staging suite against a copied
   SQLite database. LIVE permit validation remains blocked until the Owner
   supplies an already-bound test card.
4. **Grok/operator:** provide verifiable VPS-A ingress evidence (provider
   security-group/firewall view or a stable instance address) before treating
   the local TCP probe as an exposure result. Repairing the absent tunnel,
   rebinding uvicorn to loopback, and changing production configuration all
   require a separately approved cutover window.
5. **Development machine:** continue to pull VPS-A's SQLite snapshot, runtime
   configuration, signing-key backup, and supervisor scripts into the existing
   local backup archive; verify one restore into an isolated copy. The failed
   VPS-side `age` job is not a release blocker while this pull-based backup is
   working. The non-production lab signing-key permissions remain a separate
   approved-maintenance item and were not modified during this audit.

## 7. VPS-A staging acceptance: `0bb40964` (2026-09-13)

Source: the operator's redacted staging report. This supersedes the earlier
``VPS STAGING REQUIRED`` and isolated-worktree prerequisites in section 6; it
does not authorize a production cutover.

| Check | Expected | Actual | Result |
|---|---|---|---|
| Report redaction | No secret plaintext | Credential values remained redacted; only presence, permissions, sizes, and non-secret hashes were reported. | PASS |
| Production untouched | No process/configuration/data/DNS/traffic change | Production PID stayed unchanged; operator attests no live Git, data, network, or process mutation. | PASS (attested) |
| Isolated target | Exact branch head in separate worktree with a SQLite copy | Staging worktree ran exact `0bb409649ecc8ad2c82e84c89299dfd9830e73c9`; its database and environment were separate from production. | PASS |
| Persistent-local guard | Reject bad local configuration; accept persistent SQLite without Keygen | Missing/weak admin credentials and `:memory:` each exited 2; correct `inmemory` plus persistent SQLite and no `KEYGEN_*` exited 0. | PASS |
| Staging network | Uvicorn bound only to loopback | Staging used `127.0.0.1:18010`; production continued on its original port/PID. | PASS |
| HTTP administration | Admin remains authenticated and release policy survives restart | Anonymous/wrong credentials returned 401, correct staging credentials returned 200, and API/SQLite release-policy counts remained 9 after restart. | PASS |
| LIVE permit | A real already-bound test card validates approved/rejected identities | No Owner test card was available; no license/device was created or modified. | BLOCKED |
| Current production network posture | No public bridge bind, working fixed endpoint, public admin denial | Production still reports `0.0.0.0:8010`; Tunnel binary and fixed hostname are absent. | FAIL |
| Cloud ingress evidence | Security-group/firewall or verified stable instance address | Overlay host exposes neither cloud metadata nor firewall tooling. | BLOCKED |
| Backup recovery source | Development-machine pull has all source inputs | SQLite/WAL/SHM, protected runtime/credential/key files, supervisor/start scripts, and an earlier verified backup are present. The development-machine pull and restore receipt still require separate verification. | SOURCE READY |
| SQLite local permissions | Entitlement data is restricted to the service account | Reported database mode is `644`. Parent-directory access was not reported, so local exposure cannot be assessed; tighten to owner-only access in an approved maintenance window before cutover. | PENDING |

The current production service remains unavailable through the former Quick
Tunnel and must not be rebound to loopback until a working Tunnel is staged.
The existing nine release-policy rows prove persistence only; a release-bound
policy for the final signed 0.4 candidate still has to be approved after that
candidate exists.

### Remaining cutover gates

1. Inventory an Owner-authorized Cloudflare account/zone and propose the stable
   `entitlement.<zone>` hostname; stage the Named Tunnel and its public
   `/admin*` and `/v1/admin*` deny rules before changing the bridge bind.
2. Obtain cloud-edge ingress evidence or a verified stable VPS-A address;
   repeat the external probe against that attributable target.
3. Verify the development machine's pull receipt and an isolated restore; use
   that procedure for VPS-B cold recovery, never as a concurrent writer.
4. In a separately approved maintenance window, restrict the SQLite file and
   parent directory to the service account, then install/verify the Tunnel,
   rebind production to `127.0.0.1:8010`, and re-run the staging smoke checks.
5. Once a signed 0.4 desktop candidate and an already-bound test card exist,
   create/verify its release-policy identity and run the final LIVE permit
   acceptance.

## 8. VPS-A G1 fixed-HTTPS and recovery preparation (2026-09-13)

Source: the operator's redacted, read-only G1 report. Production bridge PID
was unchanged and no binary, DNS, Tunnel, firewall, cloud-rule, process, Git,
or production-data mutation was made.

| Check | Expected | Actual | Result |
|---|---|---|---|
| Cloudflare account/zone | An authorized zone from which to select `entitlement.<zone>` | No Cloudflare login, token, cookies, configuration, or zone authorization was available. | BLOCKED |
| Current public endpoint | A working fixed HTTPS hostname through a Tunnel | `cloudflared` and its configuration directory are absent; the old Quick Tunnel is down; only an unused protected token file remains. | BLOCKED |
| Production bridge | No production change during G1 | Existing PID remained on `0.0.0.0:8010`; health stayed normal. | PASS (attested) |
| Backup source inventory | Pull sources present without exposing their contents | SQLite/WAL/SHM, protected runtime/credential/key files, supervisor/start scripts, and the earlier protected hardening backup are present. SQLite integrity and reported rows are consistent. | SOURCE READY |
| Least-privilege files | Entitlement data and unused local signing material restricted to the service account | SQLite/WAL/SHM and lab `signing_key.pem` are reported as `644`; data directory is `755`. No mutation was made. | PENDING MAINTENANCE |
| Ingress attribution | Stable instance address or cloud-edge/security-group evidence | Host is an overlay container with no IMDS, firewall tooling, or cloud console access. Its observed outbound IP changed between reports, so neither address is attributable inbound evidence. | BLOCKED |
| Listener inventory | Every listener has its bind address and owner classified | Bridge `0.0.0.0:8010` is identified, but the report also names websockify, X11/VNC, node/agent, and `2375` listeners without a complete bind/process classification. | INCOMPLETE: G1.1 REQUIRED |

The operator must not proceed to Tunnel installation, DNS changes, loopback
rebinding, or production restart. First complete G1.1: classify every listener
and determine whether port `2375` and the other overlay services are confined
to an internal network. This is a read-only exposure audit, not an instruction
to interact with any Docker, agent, VNC, or platform control API.

## 9. VPS-A G1.1 listener-boundary audit (2026-09-13)

Source: the operator's redacted, read-only listener classification report.
Production bridge PID remained unchanged and no platform/control API was
called. G1.1 resolves the requested process classification but cannot establish
host-level ingress control from inside the overlay container.

| Check | Actual | Result |
|---|---|---|
| Bridge ownership | `uvicorn` on `0.0.0.0:8010` is owned by `box` and traces through its supervisor to the overlay runtime. | IDENTIFIED |
| Overlay runtime listeners | websockify, VNC/X11 loopback servers, node exec-daemons, and sand runtime services own numerous wildcard or loopback ports. | PLATFORM-OWNED |
| Unknown root listeners | `2375`, `26500`, and `50052` are wildcard listeners whose PID/executable cannot be read from the container. `2375` must not be assumed to be Docker without probing. | UNATTRIBUTED |
| Public-exposure proof | No host IMDS, provider console, firewall tooling, stable inbound address, or security-group view exists in this environment. | BLOCKED |
| Named-Tunnel effect | Binding bridge to loopback would affect only bridge, not the overlay listeners; a Tunnel would not establish ownership or exposure evidence for the underlying host. | FACTUAL LIMIT |
| Production-host acceptance | A production endpoint requires an operator-controlled host/network boundary, attributable ingress, and the ability to verify exposed ports. The current Cursor/overlay container supplies none of these. | FAIL: NOT A HARDENABLE PRODUCTION HOST |

### Hosting decision

Do not install a public Named Tunnel or publish a final subscription hostname
from this Cursor/overlay container. It may retain its current role for isolated
staging or temporary operator work, but it cannot be accepted as the 0.4
production subscription host.

Before the production cutover, place the bridge on a user-controlled VPS (A or
B) that has all of the following: operator sudo or an equivalent host control
plane, a provider security-group/firewall view, attributable ingress, an
Owner-authorized Cloudflare zone, and a verified backup/restore path. Keep one
active SQLite writer only; the other VPS remains cold standby. The already
passed `0bb40964` staging procedure can be rerun unchanged on that host.
