# Architecture Decision Log (ADR)

## ADR-001: Pinned Upstream Submodules over Forks
- **Status**: Accepted
- **Context**: Modifying upstream repositories directly creates heavy merge maintenance debt and pollutes audit boundaries.
- **Decision**: Pin exact commit hashes for FOSSBilling, Keygen CE, and Keygate as Git submodules without modifying upstream source files.

## ADR-002: Loose Coupling with Normalized Event Ingestion
- **Status**: Accepted
- **Context**: Direct coupling between FOSSBilling database triggers and Keygen API tightly couples billing and licensing concerns.
- **Decision**: Introduce ShuaBao Bridge as a standalone translation layer normalizing webhook events (`PAYMENT_SUCCEEDED`, `SUBSCRIPTION_CANCELED`, etc.).

## ADR-003: Ed25519 Asymmetric Signatures for Offline Entitlement
- **Status**: Accepted
- **Context**: Symmetric secrets (e.g. HMAC secret keys) would expose the entire verification system if extracted from client binaries.
- **Decision**: Use Ed25519 asymmetric signatures. The client runtime holds only the 32-byte public key.
