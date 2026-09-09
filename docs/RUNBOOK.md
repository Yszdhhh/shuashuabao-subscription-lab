# Operations & Deployment Runbook

## 1. Local Environment Setup

### Prerequisites
- Python 3.11+
- Docker & Docker Compose
- Git

### Initializing Environment
```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/Yszdhhh/shuashuabao-subscription-lab.git
cd shuashuabao-subscription-lab

# Install test dependencies
pip install -r requirements.txt (or use scripts/run_tests.sh)
```

---

## 2. Running Verification Suite

```bash
# Windows
.\scripts\run_tests.ps1

# Linux / Mac
./scripts/run_tests.sh
```

---

## 3. Disaster Recovery & Fault Handling
- **Database Restart**: Postgres/MariaDB restart causes temporary connection drops; Bridge retries with exponential backoff.
- **Idempotency Recovery**: Re-sent webhook payloads from billing providers are matched against idempotency table and skipped if already processed.

---

## 4. Release distribution (not deployed)

Client bundle distribution is separate from LIVE permit policy. See `docs/ops/release-distribution.md`.

The live host currently has no Docker and no Nginx. Do not treat the download-edge compose file as a production cutover.
