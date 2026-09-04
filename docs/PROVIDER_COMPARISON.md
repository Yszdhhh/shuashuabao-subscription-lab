# Provider Comparison: FOSSBilling vs Keygen vs Keygate

| Dimension | FOSSBilling | Keygen CE | Keygate |
| :--- | :--- | :--- | :--- |
| **Billing** | Native (Full support for invoicing, gateways, orders) | None (Requires external billing) | None (Requires external billing) |
| **License** | Basic metadata only (Not designed for software licensing) | Native (Comprehensive policies, expiration, pools) | Supported (Standard license CRUD) |
| **Machines** | None | Native (Hardware ID, multi-component tracking) | Supported (1-level machine ID binding) |
| **Trial** | Order trial period | Policy-based (`REQUIRE_COMPONENTS`, fingerprint uniqueness) | Basic (Relies on client account or manual check) |
| **Offline** | None | Native (Cryptographic license files, TTL checkout) | Supported (Signed JWT tokens) |
| **Portal** | Native client web portal | None (API only, Cloud has paid portal) | None (Admin API only) |
| **Admin UI** | Native Admin Dashboard | None in CE (Rails Admin available via API) | Minimal Web Admin UI |
| **Suspend** | Order suspension | Native license status suspension | Supported (`is_active` toggle) |
| **Renew** | Recurring invoice payment | API-based expiration extension | API-based expiration extension |
| **Audit** | Activity logs & Invoice histories | Comprehensive event audit logs | Basic DB timestamps |
| **Deployment**| PHP / MariaDB | Ruby on Rails / PostgreSQL / Redis | Single Go binary / PostgreSQL |
| **License Risk**| Low (Apache-2.0) | High Commercial Restrictions (Fair Core FCL-1.0-MIT) | High Derivative Restrictions (AGPL-3.0) |
| **Missing Features**| HWID matching, cryptographic licensing | Built-in billing, open web admin | Fuzzy component matching, advanced policy rules |
