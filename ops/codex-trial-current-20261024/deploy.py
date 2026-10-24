import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parent
FILES = json.loads((ROOT / 'manifest.json').read_text())
SUFFIX = '.bak-20261024-codex'
DB = Path('/home/shuabao/services/data/subscription_state.db')
DB_BACKUP = Path('/home/shuabao/services/backups/subscription_state.db' + SUFFIX)


def check(item):
    p = Path(item['target'])
    if item['sha256'] is None:
        if p.exists():
            raise RuntimeError('CONCURRENT_FILE_EXISTS: ' + str(p))
    elif (not p.exists() or int(p.stat().st_mtime) != item['mtime']
          or hashlib.sha256(p.read_bytes()).hexdigest() != item['sha256']):
        raise RuntimeError('CONCURRENT_FILE_CHANGED: ' + str(p))


def restart(unit, health=None):
    start = time.monotonic()
    subprocess.run(['systemctl', 'restart', unit], check=True)
    for _ in range(60):
        try:
            if health:
                with urllib.request.urlopen(health, timeout=1) as response:
                    assert response.status == 200
            else:
                subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=True)
            print('RESTART', unit, round(time.monotonic() - start, 3), 'seconds', flush=True)
            return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError('service did not recover: ' + unit)


def rollback():
    state_path = ROOT / 'installed.json'
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    for item in reversed(FILES):
        p = Path(item['target'])
        if str(p) not in state:
            continue
        if hashlib.sha256(p.read_bytes()).hexdigest() != state[str(p)]:
            raise RuntimeError('CONCURRENT_CHANGE_DURING_ROLLBACK: ' + str(p))
        backup = Path(str(p) + SUFFIX)
        if item['sha256'] is not None and backup.exists():
            subprocess.run(['cp', '-a', str(backup), str(p)], check=True)
        elif item['sha256'] is None and p.exists():
            p.rename(str(p) + '.disabled-20261024-codex')
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    restart('shuabao-trial-claim.service', 'http://127.0.0.1:18012/trial/status')
    restart('shuabao-subscription.service', 'http://127.0.0.1:8010/health')
    print('ROLLED_BACK; DB backup retained, no card data was changed', flush=True)


def deploy():
    for item in FILES:
        check(item)
        if Path(item['target'] + SUFFIX).exists():
            raise RuntimeError('backup already exists: ' + item['target'])
    if DB_BACKUP.exists():
        raise RuntimeError('DB backup already exists')
    with sqlite3.connect(str(DB)) as source, sqlite3.connect(str(DB_BACKUP)) as backup:
        source.backup(backup)
    os.chmod(DB_BACKUP, 0o600)
    print('DB_BACKUP', DB_BACKUP, flush=True)
    for p in [Path('/home/shuabao/services/trial-claim/pool.json'),
              Path('/home/shuabao/services/trial-claim/dashboard_claims.json')]:
        if Path(str(p) + SUFFIX).exists():
            raise RuntimeError('runtime backup exists: ' + str(p))
        subprocess.run(['cp', '-a', str(p), str(p) + SUFFIX], check=True)
    for item in FILES:
        check(item)
        if item['sha256'] is not None:
            subprocess.run(['cp', '-a', item['target'], item['target'] + SUFFIX], check=True)
    installed = False
    state = {}
    try:
        for item in FILES:
            check(item)  # Recheck immediately before every replacement.
            p = Path(item['target'])
            tmp = Path(str(p) + '.codex-next')
            if tmp.exists():
                raise RuntimeError('unexpected staging file: ' + str(tmp))
            if p.exists():
                subprocess.run(['cp', '-a', str(p), str(tmp)], check=True)
            else:
                tmp.touch(mode=0o644)
                parent = p.parent.stat()
                os.chown(tmp, parent.st_uid, parent.st_gid)
            tmp.write_bytes((ROOT / item['source']).read_bytes())
            check(item)
            os.replace(tmp, p)
            installed = True
            state[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
            (ROOT / 'installed.json').write_text(json.dumps(state))
            print('INSTALLED', p, hashlib.sha256(p.read_bytes()).hexdigest(), flush=True)
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        restart('shuabao-trial-claim.service', 'http://127.0.0.1:18012/trial/status')
        restart('shuabao-subscription.service', 'http://127.0.0.1:8010/health')
        subprocess.run([sys.executable, str(ROOT / 'verify.py')], check=True)
    except Exception:
        if installed:
            rollback()
        raise


if __name__ == '__main__':
    if sys.argv[1:] == ['rollback']:
        rollback()
    else:
        deploy()
