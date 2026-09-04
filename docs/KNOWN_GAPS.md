# Known Gaps & Missing Upstream Features

## 1. Upstream Missing Capabilities

1. **FOSSBilling**:
   - Lacks native software licensing / machine fingerprint authority.
   - Outgoing webhooks require a customized plugin or bridge poller.
2. **Keygen CE**:
   - No native web admin UI in Community Edition (API-first architecture).
   - Requires external Redis & PostgreSQL infrastructure.
   - Strict commercial licensing (FCL).
3. **Keygate**:
   - Lacks component-level fuzzy matching (`MATCH_TWO`, `MATCH_MOST`).
   - Lacks sophisticated multi-tier policy engines.
   - AGPL-3.0 network copyleft requires careful architectural separation.

## 2. Future Production Work (Post-Lab)
- Integration of hardware fingerprint collector into ShuaBao client.
- Dynamic billing webhook verification via HMAC signatures.
- Enterprise Redis cluster for distributed rate limiting.
