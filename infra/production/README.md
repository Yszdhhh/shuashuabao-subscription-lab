# ShuaBao 0.4 production subscription deployment

This directory is the production-only deployment path for the 0.4 release line.
`infra/compose/docker-compose.yml` remains an integration/E2E fixture and must not
be deployed to the Internet.

## 1. Production topology

```text
Internet
  -> TLS reverse proxy :443
       - deny /admin publicly
       - proxy other API routes to 127.0.0.1:8000
  -> ShuaBao Entitlement Bridge (loopback bind only)
       -> persistent SQLite state: /data/subscription_state.db
       -> production Ed25519 signing key mounted read-only
       -> private Keygen endpoint
            -> PostgreSQL (private only)
            -> Redis (private only)
```

For 0.4, **Keygate is not part of the production serving path**. FOSSBilling is
optional if card issuance/renewal is still operated manually; if enabled later,
FOSSBilling and MariaDB stay private and only the signed webhook endpoint reaches
the bridge through the public reverse proxy.

## 2. Provider-mode contract

- `production`: the supported 0.4 production mode.
- `real`: accepted only as a legacy production alias by the guard.
- `compose`: E2E fixture only; never production.
- `keygen` / `http_keygen`: provider-selection/development modes; they do not by
  themselves assert production hardening.
- `inmemory`: supported for the deployed local-provider topology when
  `SUBSCRIPTION_DB_PATH` names persistent SQLite storage. Despite its historical
  name, it reloads licenses and activations from SQLite at startup and writes
  them back there; it does not require Keygen/PostgreSQL. The production guard
  still requires strong local credentials, webhook authentication, a persistent
  SQLite path, and the permit signing identity.

The production compose runs `python -m bridge.app.production_guard` before
uvicorn. Missing admin credentials, known default/fixture credentials, in-memory
state, missing Keygen identity/token/policy, missing signing identity, or missing
webhook secret fail before the service starts. A copied but unedited
`.env.example` also fails: any guarded value still containing `REPLACE_WITH`
is rejected.

## 3. Network exposure

Only the TLS reverse proxy should listen on a public interface. The production
compose publishes the bridge as `127.0.0.1:8000` by default. Keygen, PostgreSQL,
Redis, and any billing database must not publish public host ports.

The sample nginx config returns 404 for `/admin` and for the JSON admin API
`/v1/admin` (release policy read/write). Operators reach both through an SSH
tunnel or VPN directly to the bridge loopback listener, then use its Basic-auth
credentials; `tools/approve_dev_release.py` accepts loopback HTTP for exactly
this path (e.g. `ssh -L 18000:127.0.0.1:8000 <vps>` then
`--endpoint http://127.0.0.1:18000`). Do not punch an Internet-facing exception
for either admin path.

## 4. Secret injection

1. Copy `.env.example` to `.env` on the VPS and set mode 0600.
2. Create `infra/production/secrets/signing_key.pem` outside Git history and set
   mode 0600. The container mounts it read-only.
3. Use unique production values for Keygen account/token/policy, webhook secret,
   and admin password. Never reuse values from the E2E compose fixture.
4. Prefer the VPS secret manager or a systemd `EnvironmentFile` if available;
   this compose file is only the minimum reproducible serving shape.

No real secret belongs in this repository or in CI logs.

## 5. Persistence and backup

Back up both the bridge SQLite volume and the Keygen PostgreSQL database. Redis
is cache/coordination state and is not the source of truth. Verify restore into a
separate staging instance before relying on the backup procedure for release.

## 6. Pre-deploy acceptance

From the repository root on the target revision:

```bash
pytest -q tests/contract/test_production_guard.py
cp infra/production/.env.example infra/production/.env
# fill real values and install signing_key.pem, then:
docker compose -f infra/production/bridge-compose.yml config
docker compose -f infra/production/bridge-compose.yml up -d --build
docker compose -f infra/production/bridge-compose.yml ps
```

Acceptance requires:

- the environment guard exits 0 with the real VPS configuration;
- bridge is reachable from the reverse proxy but not on a public host port;
- `/admin` returns 404 through the public hostname;
- `/admin` is reachable only through the private operator path and rejects bad credentials;
- `/health` reports the expected deployed revision/provider (set
  `SHUABAO_SERVICE_REVISION` to the deployed commit);
- `/v1/admin/releases` returns 404 through the public hostname;
- a known-good 0.4 entitlement can validate and receive a release-bound LIVE permit;
- a non-approved source/manifest/channel identity is rejected;
- the bridge state survives a container restart.

Do not switch production traffic to this branch until the VPS checks above are
captured as evidence.
