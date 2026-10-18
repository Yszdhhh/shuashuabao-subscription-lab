# G2 Fixed HTTPS Hostname Runbook (Named Tunnel)

Status: **documentation only**. This runbook does **not** cut DNS, rotate
certificates, replace the live Quick Tunnel, or restart production `:8010`.

Live production today still uses a Cloudflare **Quick Tunnel**:

- public URL (rotates): `https://quebec-luis-flooring-kenneth.trycloudflare.com`
- origin: `http://127.0.0.1:8010` (host `0.0.0.0:8010` uvicorn)
- supervisor: `/home/box/services/shuabao-supervisor/ensure-up.sh`
- start script: `/home/box/services/shuashuabao-subscription-lab/bin/start-tunnel.sh`
  (`cloudflared tunnel --url http://127.0.0.1:8010`)

Named Tunnel credentials already exist on this host and **must not be
regenerated** as part of G2:

| Item | Value / location |
|---|---|
| `TUNNEL_ID` | `d85ab05b-8b82-42ea-a97b-72eeb82f34f9` |
| token file | `/home/box/services/shuashuabao-subscription-lab/.cloudflared_tunnel_token` (mode 600) |
| recorded mode | `TUNNEL_MODE=quick` in lab `.admin_credentials` (Named Tunnel unused live) |

## Goal

Give the ShuaBao client a **stable HTTPS hostname** (no `*.trycloudflare.com`
rotation) before any `external-beta` permit enforcement cutover.

## Prerequisites (operator, not this deploy)

1. **Domain** — a hostname the client will pin, e.g. `subscription.example.com`
   (exact name is an operator choice; do not invent and ship a domain here).
2. **Cloudflare zone** — the domain's DNS zone must be on the same Cloudflare
   account that owns tunnel `d85ab05b-8b82-42ea-a97b-72eeb82f34f9`.
3. **DNS record** — a CNAME (or Cloudflare route) from the chosen hostname
   to `<TUNNEL_ID>.cfargotunnel.com`. **Do not create or change this record
   from automation.** Human operator only, after staging verification.
4. **TLS certificate** — Cloudflare edge certificate for the hostname
   (Universal SSL / Advanced Certificate). Origin can stay HTTP on localhost.
5. **Token** — already present (`TUNNEL_ID` above). Do **not** rotate the
   tunnel token, do **not** `cloudflared tunnel create`, do **not**
   `cloudflared tunnel route dns` from this G2 change.

## Proposed cutover sequence (manual, after G2 production review)

These steps are **intentionally not executed** by G2 code or scripts.

1. Confirm production `:8010` health and that G2 permit lifecycle is reviewed.
2. Configure the Named Tunnel ingress (local `config.yml` **or** dashboard):
   - hostname → `http://127.0.0.1:8010`
   - catch-all `http_status:404`
3. Start a **second** cloudflared using the existing token / tunnel id,
   bound to the Named Tunnel, **without** stopping the Quick Tunnel yet.
4. Probe the **new** hostname: `GET https://<fixed-host>/health`.
5. Only after health matches production, a human updates DNS / Cloudflare
   route and client `PUBLIC_BASE_URL`.
6. Keep the Quick Tunnel running until clients have moved; then stop it.

## Explicit non-goals / bans

- **NO automatic DNS cut** (no `cloudflared tunnel route dns`, no Cloudflare
  API DNS writes, no registrar changes).
- **NO** live tunnel process replacement from this worktree.
- **NO** signing-key rotation.
- **NO** production `:8010` restart as part of hostname work.
- **NO** session-grace or min-supported policy in this G2 slice.

## Rollback

Leave the Quick Tunnel and `:8010` supervisor as they are. If a Named Tunnel
sidecar was started, stop **only** that sidecar. DNS remains unchanged unless
an operator already published a record — in that case the operator reverts
the CNAME.

## Evidence to collect before any DNS publish

- `curl -fsS http://127.0.0.1:8010/health`
- `curl -fsS https://<fixed-host>/health` (Named Tunnel path)
- PID/cmdline of production uvicorn unchanged
- client configured with the fixed host, not a trycloudflare URL
