# UPSTREAM LOCK & VERIFICATION REPORT

## 1. Overview & Pinned Facts

All upstream repositories are cloned and pinned as Git submodules at exact commit SHAs. No unpinned branches (`master`, `main`, `latest`) or untracked Docker tags are permitted as acceptance baselines.

| Upstream Project | Pinned Commit SHA | Commit Date | Release/Tag | License | Defined Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FOSSBilling** | `94a40e2af6854cf32064a6ff7e1d4d6836268613` | 2026-08-27 23:24:45 +0000 | `0.8.5-238-g94a40e2af` (Release `0.8.5`) | **Apache-2.0** | Billing / Customer / Order / Invoice / Subscription Management |
| **Keygen CE** (`keygen-api`) | `af351aed20101032348a3c146b6fdca7ece3b814` | 2026-07-31 11:20:27 -0500 | `v1.7.2-7-gaf351aed2` (Release `v1.7.2`) | **FCL-1.0-ALv2** (Fair Core License 1.0) | Primary License Authority / Machine Activation / Cryptographic Offline File |
| **Keygate** | `0adfc139ef41ac8d637a12c29591c1b457b537ba` | 2026-08-25 21:13:12 +0800 | `v0.1.3` (Release `v0.1.3`) | **AGPL-3.0** | Shadow License Engine / Comparison Benchmark |

---

## 2. Technical Stack & Deployment Constraints

### FOSSBilling
- **Upstream Repository**: https://github.com/FOSSBilling/FOSSBilling
- **Architecture**: PHP 8.2+ / Symfony components / Twig / MySQL (MariaDB).
- **Deployment**: `upstreams/fossbilling/Dockerfile` (Apache/PHP-FPM container).
- **Admin UI**: Native built-in Admin panel (`/admin`).
- **Customer Portal**: Native built-in Client portal (`/client`).
- **API Spec**: JSON-RPC / REST endpoints located under `src/modules/api` and `src/library/Box/API`.
- **Event/Hook Subsystem**: Event manager (`Box_EventManager`) fires internal events like `onAfterClientOrderCreate`, `onAfterInvoicePaid`, `onAfterInvoiceRefund`.

### Keygen CE
- **Upstream Repository**: https://github.com/keygen-sh/keygen-api
- **Architecture**: Ruby on Rails (API only), PostgreSQL 13+, Redis / Sidekiq (for async webhooks, metrics, cleanup).
- **Deployment**: `upstreams/keygen/Dockerfile` + Multi-stage build.
- **Admin UI**: None (API only; requires external dashboard or direct API/CLI).
- **Customer Portal**: None (API only; customer management handled via token/account permissions).
- **API Spec**: JSON:API 1.0 standard (`application/vnd.api+json`). Endpoints documented in OpenAPI schemas and official Keygen API documentation.
- **Security & Crypto**: Native support for Ed25519, RSA, and ECDSA offline license signing and machine file verification.

### Keygate
- **Upstream Repository**: https://github.com/tabloy/keygate
- **Architecture**: Go 1.22+, Gin framework, GORM, PostgreSQL / SQLite.
- **Deployment**: `upstreams/keygate/Dockerfile` + `docker-compose.yml`.
- **Admin UI**: Built-in Vue/Web UI embedded into Go binary (`web/dist`).
- **Customer Portal**: None.
- **API Spec**: REST API (`/api/v1/...`).
- **Security & Crypto**: Built-in Ed25519 signature generation and license verification.

---

## 3. Upstream Modification Policy
1. **Submodules are strictly pinned.**
2. **Zero In-Tree Modification**: No upstream source code is altered inside `upstreams/`.
3. **Pluggable Integration**: All custom business rules, webhook routing, event normalization, and hardware fingerprint mapping are strictly implemented inside `bridge/` and `adapters/`.
