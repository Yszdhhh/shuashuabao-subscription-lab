# ShuaBao release distribution

This is the GitHub-free version distribution foundation. A future Windows client can HTTPS to this host, read latest metadata, download the official bundle, and verify the descriptor locally with Ed25519.

It does not change entitlement validate semantics, LIVE permit issuance, or the existing release approval policy. Production cutover is a separate authorized step. **This branch is not deployed.**

## Current live topology

The live host runs `uvicorn bridge.app.main:app` on `:8010` via a shell supervisor.

- There is **no Docker** on the live host today.
- There is **no Nginx** on the live host today.
- Do not dockerize or rewrite the subscription service to turn this on.
- Do not bind the download edge to `:8010`.
- FastAPI must not stream large bundles. `GET /v1/releases/latest` returns JSON only.

`infra/compose/docker-compose.downloads.yml` is an isolated harness for the download edge only. It is not the live topology and is not attached to the subscription process.

## Responsibilities stay separate

| Concern | What it answers | Where it lives |
| :--- | :--- | :--- |
| Distribution | which bundle to download and where the file is | this document, `data/releases` (or `SHUABAO_RELEASES_ROOT`), nginx static |
| Policy | approved / blocked / recommended / outdated and allowed modes | `GET /v1/releases/status` and `/admin/releases` |
| Permit | whether a subscriber may start LIVE | permit issuer; still fail-closed on approval |

Publishing a bundle does **not** approve it for LIVE. A hard block stays a policy flag. Do not implement a block by deleting a ZIP or replacing bytes in place.

Ordinary users do not need GitHub, git, `raw.githubusercontent.com`, or a GitHub token.

## What the client will use

`GET /v1/releases/latest?channel=release`

Public fields only:

- `version`, `release_channel`, `source_sha`, `release_manifest_sha256`
- `bundle_sha256`, `bundle_size`, `download_url`
- `published_at`, `minimum_supported_version`, `mandatory`, `release_sequence`
- `changelog_summary`
- descriptor signature information: `signature.key_id`, `signature.algorithm`, `signature.purpose`, `signature.signature`, and `descriptor_url`

The public payload never includes a local filesystem path, operator note, VPS internals, admin user, secrets, or private keys.

`download_url` is an absolute URL built from `SHUABAO_RELEASE_PUBLIC_BASE` plus:

```text
/downloads/shuabao/<channel>/<version>/<bundle>
```

Future OSS/COS/CDN can replace the origin without changing that path. Authenticity is the client-side Ed25519 signature, not "the server gave this URL". Entitlement-scoped download tokens are not implemented.

Channels already used by policy are the only legal channels: `dev`, `internal-pilot`, `external-beta`, `release`.

`GET /v1/releases/status` is unchanged. It remains the policy API. Do not collapse status and latest.

## Signing and the public key

Signing happens **off-box**. The server role is verify, store, publish, serve. It stores a configured **public** key only.

Do not reuse `signing_key.pem`. That file is the permit signer. It is gitignored, must stay untracked, and must not be used for release distribution. Never commit a release private key.

Configure one of:

- `SHUABAO_RELEASE_PUBLIC_KEY_PATH` — PEM file containing an Ed25519 **public** key
- `SHUABAO_RELEASE_PUBLIC_KEY_PEM` — the same PEM text
- optional `SHUABAO_RELEASE_KEY_ID` — if set, the descriptor `key_id` must match

Suggested on-box location when nginx is placed later: `/etc/shuabao/release_public_key.pem` (mode `0644`, public material only). The artifact root may also hold a copy under the configured root, but that directory is runtime state and must not be committed.

The signed object is a versioned descriptor JSON. The signer canonicalizes it (`schema_version=1`, `product_id=shuabao`, `purpose=shuabao-release-descriptor-v1`, sorted keys, no extra whitespace) and writes a detached Ed25519 signature (standard base64, 64 raw bytes). `published_at` must be UTC, for example `2026-09-09T06:00:00Z`.

`download_url` is **not** part of the signed descriptor. The server computes it.

## Storage layout

Root is `SHUABAO_RELEASES_ROOT`. Default in this repo is `data/releases` so `/opt` is not required. Suggested production root when the download edge is added later: `/opt/shuabao/releases`.

```text
<root>/
  staging/                 # not publicly served; unpublished packages never appear in latest
  dev/
  internal-pilot/
  external-beta/
  release/
  withdrawn/               # moved out of the active index; bytes kept
  index/                   # atomic latest pointers and catalog; not publicly served
  audit/release-audit.jsonl
```

A published version directory contains the zip named in the descriptor (`shuabao-....zip`), `release-descriptor.json`, and `release-descriptor.sig`. Same release identity is immutable. New bytes require a new version / `source_sha` / manifest identity. Silent overwrite is refused.

`release_sequence` must increase per channel. Rollback does not reuse or delete the higher sequence.

## Publish

1. Place the bundle, descriptor, and signature into a staging temp dir.
2. Verify the descriptor signature with the configured public key.
3. Verify bundle sha256.
4. Verify bundle size.
5. Verify release identity formats (40 hex `source_sha`, 64 hex manifest, known channel, legal version, monotonic `release_sequence` unless this is a rollback).
6. Reject duplicate or conflicting identity.
7. Move the files to the immutable published path.
8. Atomically update the channel latest pointer.
9. Append an audit event (no secrets).
10. Only then does `GET /v1/releases/latest` return it.

Never flip latest before the file is in place. A failed publish must not change current latest.

```bash
python scripts/publish_release.py \
  --root /opt/shuabao/releases \
  publish \
  --bundle ./shuabao-1.2.3.zip \
  --descriptor ./release-descriptor.json \
  --signature ./release-descriptor.sig \
  --public-key /etc/shuabao/release_public_key.pem \
  --key-id release-2026
```

Required environment for the public API to emit absolute URLs:

```bash
SHUABAO_RELEASES_ROOT=/opt/shuabao/releases
SHUABAO_RELEASE_PUBLIC_BASE=https://downloads.example
```

If the public base is missing, latest metadata for a published channel fails closed rather than emitting a host path.

## Rollback

Rollback switches latest from V2 to a previously published V1. It keeps V2 bytes and writes an audit event. It does not delete the previous artifact and does not change policy blocked/approved.

```bash
python scripts/publish_release.py \
  --root /opt/shuabao/releases \
  rollback \
  --channel release \
  --version 1.0.0
```

The target must still be in the active published tree (not withdrawn) and must be an older `release_sequence` than current latest.

## Withdraw

Withdraw moves a published release out of the active index into `withdrawn/<channel>/<version>/`. It does not delete bytes. It must not leave latest pointing at a withdrawn release.

- If the target is not current latest, it is moved and latest stays put.
- If it is current latest, pass `--promote <older-version>` or `--clear-latest`.
- Withdrawn identity is reserved. Republish requires a new version and release identity.

```bash
python scripts/publish_release.py \
  --root /opt/shuabao/releases \
  withdraw \
  --channel release \
  --version 1.1.0
```

## Nginx beside uvicorn :8010 later

Do this only as a separately authorized cutover. The live host has no nginx today.

Suggested later placement:

1. Keep uvicorn on `:8010` for the subscription API, including `GET /v1/releases/latest` and `GET /v1/releases/status`.
2. Add a download edge from `infra/nginx/shuabao-downloads.conf` (render with `infra/nginx/render_downloads_conf.py` if the root or listen port differs).
3. Mount or point the alias root at `SHUABAO_RELEASES_ROOT`. The committed example uses `/srv/shuabao/releases` and listens on `8088`, never `8010`.
4. TLS terminates at the outer edge (cloudflared or an existing TLS proxy). The checked-in server block is HTTP on purpose so an isolated test can exercise static serving. Do not terminate release TLS by changing the subscription process.
5. Public download path shape stays `/downloads/shuabao/<channel>/<version>/<bundle>`.
6. `autoindex` is off. Staging, withdrawn, index, and audit are denied. Symlinks are disabled. Published files are versioned and must not be overwritten in place.
7. Range requests stay at nginx default. Zip responses use `Content-Type: application/zip` and `Content-Length`.

Renderer refuses `--listen-port 8010`.

The isolated compose file `infra/compose/docker-compose.downloads.yml` publishes `127.0.0.1:18088` only. Do not start it on the live host as a substitute for the subscription service, and do not assume Docker exists there.

## Backup of the release index

Back up the whole artifact root, not only the pointer file. A pointer without the version directory is not a restorable release.

Minimum set:

- `index/catalog.json`
- `index/latest-*.json`
- each active `<channel>/<version>/` directory (bundle, descriptor, signature)
- `withdrawn/` if withdrawn bytes must remain recoverable
- `audit/release-audit.jsonl`

Do not back up or copy `signing_key.pem` into this tree. Do not put admin passwords, GitHub tokens, or release private keys in the archive.

Restore by copying the root into place, then confirming `GET /v1/releases/latest` before pointing DNS or the public base at it. A restore must not be followed by an in-place ZIP replace.

## Production cutover

**SAFE_TO_DEPLOY = NO.** Shipping this branch does not authorize enabling the download edge on the live host.

Cutover later, separately, only when explicitly authorized:

1. Choose `SHUABAO_RELEASES_ROOT` and install the release **public** key.
2. Set `SHUABAO_RELEASE_PUBLIC_BASE` to the public HTTPS origin clients will use.
3. Publish a signed bundle with the CLI. Confirm latest JSON has no server path.
4. Place nginx beside `:8010` as a new process. Do not restart or rewrite the existing uvicorn supervisor as part of this foundation.
5. Confirm a client can download the zip and verify the detached descriptor without GitHub.

## Known gaps

- No Windows client updater, dashboard download button, or installer.
- No entitlement download-token system. A short hook exists in the URL builder only.
- A crash after the version directory is placed and before the latest pointer commit leaves an unpublished artifact occupying that version identity. Latest does not change. Do not overwrite it; withdraw it if it is not latest, then publish a new identity.
- One configured release public key. Rotation is an off-box key change plus new publishes. Existing stored signatures are not rewritten.
- The live host still has no docker and no nginx. Config here is not active.
