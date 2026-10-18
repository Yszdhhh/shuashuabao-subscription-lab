# G2 Baseline Provenance

- When: 2026-09-05 10:05:07 CST
- Production tree: `/home/box/services/shuashuabao-subscription-lab`
- Production DEPLOYED_REF.txt: `c9e1aa44e1f0c195560604e9767dffc7d3a3e67e`
- Git baseline compared: worktree commit `24c14b1737298dea54fb840872a5f92e828c3dd4` (message: import c9e1aa44 baseline)
- Documented c9 cutover claim: `c9e1aa44e1f0c195560604e9767dffc7d3a3e67e` (object not present in prod lab git; compared via import commit tree)
- Scope: `bridge/` + `contracts/` business source (exclude venv, data, secrets, logs, __pycache__)
- Verdict: **BASELINE_MATCH**

## Summary
- Core business files compared: 12
- Exact content matches: 12
- Content drifts: 0
- Prod-only empty package markers (`__init__.py`): 6 (not in git archive; each is `# package\n` only)

## File SHA256 (core business source)

| path | baseline sha256 | prod sha256 | match |
|---|---|---|---|
| `bridge/Dockerfile` | `704f4a842fc95662784105a75693fc08b67d56effa20862123fcddcc737757fb` | `704f4a842fc95662784105a75693fc08b67d56effa20862123fcddcc737757fb` | yes |
| `bridge/app/core/crypto.py` | `be7ef9f2d14a3150c48068e9ee39b6aea9e14605525d6a86651e65c50667ffd1` | `be7ef9f2d14a3150c48068e9ee39b6aea9e14605525d6a86651e65c50667ffd1` | yes |
| `bridge/app/core/fingerprint.py` | `308327f555fb32d79bfb7fbd7a00b7332866dabf5cc34a4bde4a75a1ebeeb07c` | `308327f555fb32d79bfb7fbd7a00b7332866dabf5cc34a4bde4a75a1ebeeb07c` | yes |
| `bridge/app/main.py` | `f3ffe5c7c8d25e4fb3f927e2b4b1281d2400c59fd1af8e8f1f5c724a7eeb23ad` | `f3ffe5c7c8d25e4fb3f927e2b4b1281d2400c59fd1af8e8f1f5c724a7eeb23ad` | yes |
| `bridge/app/providers/base.py` | `171a0bd8680f1e7fd56d8162e1d08e5885cd3dacb07d3cfadd024aacbf2f48b9` | `171a0bd8680f1e7fd56d8162e1d08e5885cd3dacb07d3cfadd024aacbf2f48b9` | yes |
| `bridge/app/providers/http_keygate_provider.py` | `8011da97c7143b2e08b636bec73ac0075f1b771f0f6289255deb2d01766d892c` | `8011da97c7143b2e08b636bec73ac0075f1b771f0f6289255deb2d01766d892c` | yes |
| `bridge/app/providers/http_keygen_provider.py` | `58dd2d024b5668b4c4bbd722277eb9cbb285bb02d74a211213debc991adc81b4` | `58dd2d024b5668b4c4bbd722277eb9cbb285bb02d74a211213debc991adc81b4` | yes |
| `bridge/app/providers/keygate_provider.py` | `6348bd12b8272c89ead7400d1dcc66acabc9d1fb0b46fa33b8fb642dfcd6ea6a` | `6348bd12b8272c89ead7400d1dcc66acabc9d1fb0b46fa33b8fb642dfcd6ea6a` | yes |
| `bridge/app/providers/keygen_provider.py` | `91964468e5fa12d0c66096715b42a3ef926d1310ddf2836c8efd007f81066803` | `91964468e5fa12d0c66096715b42a3ef926d1310ddf2836c8efd007f81066803` | yes |
| `bridge/app/services/event_processor.py` | `207a919f1291391cc6b4e7a8b5a70013cd127f6dca1a906783c730d1dbd9b872` | `207a919f1291391cc6b4e7a8b5a70013cd127f6dca1a906783c730d1dbd9b872` | yes |
| `bridge/app/services/permit_issuer.py` | `c8d730b005437b4a18f9586f1c6c8f052706fe4af51ee28c9b00327179841b68` | `c8d730b005437b4a18f9586f1c6c8f052706fe4af51ee28c9b00327179841b68` | yes |
| `contracts/entitlement.py` | `89349b09f958b091252389168e17829affc3c7dec03c49a72d681b3148e85e85` | `89349b09f958b091252389168e17829affc3c7dec03c49a72d681b3148e85e85` | yes |

## Prod-only `__init__.py` markers

- `bridge/__init__.py` sha256=`527c668d5ae4f9e3` content=b'# package\n'
- `bridge/app/__init__.py` sha256=`527c668d5ae4f9e3` content=b'# package\n'
- `bridge/app/core/__init__.py` sha256=`527c668d5ae4f9e3` content=b'# package\n'
- `bridge/app/providers/__init__.py` sha256=`527c668d5ae4f9e3` content=b'# package\n'
- `bridge/app/services/__init__.py` sha256=`527c668d5ae4f9e3` content=b'# package\n'
- `contracts/__init__.py` sha256=`527c668d5ae4f9e3` content=b'# package\n'

## Drift details
- none (core business source identical to git baseline `24c14b1` / claimed c9 import)

## Notes
- Production runtime extras (venv, data, secrets, signing_key.pem, DEPLOY_NOTES) intentionally excluded from business-source provenance.
- Empty `# package` `__init__.py` files on disk do not change imported module bytecode relative to namespace packages and are treated as non-drift for this verdict.

