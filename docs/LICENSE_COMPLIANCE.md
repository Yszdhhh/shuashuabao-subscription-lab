# License Compliance & Legal Risk Analysis

## 1. Upstream License Analysis

### FOSSBilling
- **License**: Apache-2.0 (Permissive Open Source)
- **Implications**: Fully commercial-friendly. Allows self-hosting, distribution, modification without requiring source code disclosure of custom bridge or plugins. Attribution notice required.

### Keygen CE
- **License**: Fair Core License (FCL-1.0-MIT) - **Source-Available, NOT Open Source**
- **Implications**: Grants right to use and modify for internal business operations. Converts to MIT after a fixed date. **Commercial SaaS/distribution of licensing services to third parties may trigger licensing violations**. Internal self-hosting for ShuaBao's own user base is permitted under FCL.

### Keygate
- **License**: AGPL-3.0 (Strong Copyleft)
- **Implications**: If Keygate source code is modified and hosted over a network, the modified source code of Keygate must be made available to network users. Integrating Keygate strictly as an external service via REST API preserves bridge proprietary status.

---

## 2. Redistribution & Commercial Self-Host Matrix

| Upstream | Commercial Self-Host | Network Copyleft Trigger | Source Disclosure Requirement |
| :--- | :--- | :--- | :--- |
| **FOSSBilling** | Yes | No | None for proprietary plugins |
| **Keygen CE** | Yes (internal use) | No | None, but subject to FCL restrictions |
| **Keygate** | Yes | Yes (if Keygate itself is modified) | Required only if Keygate binary is modified |
