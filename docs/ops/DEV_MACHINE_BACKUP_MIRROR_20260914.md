# Development-machine encrypted backup mirror

`scripts/mirror_vps_b_backup_to_dev.ps1` mirrors the encrypted subscription archives already held by VPS-B to `%LOCALAPPDATA%\ShuaBao\subscription-backup-mirror\vps-b` and writes a redacted `receipt.json`.

It deliberately does not retrieve the B-side age private key or decrypt a user-data archive on the development machine. Each archive must match the corresponding remote SHA-256 sidecar before it is accepted locally.

The script requires the existing SSH alias `racknerd` to reach VPS-B and uses its existing privileged read path only for the encrypted archive directory. It does not alter either VPS.

Run it manually:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\mirror_vps_b_backup_to_dev.ps1
```

The default freshness limit is eight hours, covering the intended six-hour source cadence plus two hours of slack. A stale but hash-valid archive is still mirrored and a receipt is written; the command exits with code `2` so the problem is visible.

After a successful manual check, install the user-session task:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_vps_b_backup_mirror_task.ps1
```

The scheduled task runs every six hours while the development-machine user session is available. The receipt is the local evidence of delivery; VPS-B's restore-validation timer remains the separate evidence that an archive can be restored without touching production.
