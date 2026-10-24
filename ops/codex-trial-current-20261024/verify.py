import hashlib
import json
from pathlib import Path
import sqlite3
import urllib.parse
import urllib.request

BASE = 'http://127.0.0.1:8010'
POOL = Path('/home/shuabao/services/trial-claim/pool.json')
DB = '/home/shuabao/services/data/subscription_state.db'
EXPECTED_POLICIES = 'f53aaa33e4d1d7b5fb66c519b436c7e7e766cd9a9a792778f362e47918e6a62e'


def request(url, body=None, form=False, key=None):
    headers = {'User-Agent': 'ShuaBaoClient/1.0'}
    if body is not None:
        body = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
    if key:
        headers['X-Referral-Internal-Key'] = key
    with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers), timeout=10) as response:
        assert response.status == 200
        return json.load(response)


def main():
    baseline = json.loads(Path('/tmp/sb-codex-baseline-20261024.json').read_text())
    con = sqlite3.connect('file:' + DB + '?mode=ro', uri=True)
    policies = con.execute('SELECT * FROM release_policies ORDER BY source_sha,release_manifest_sha256,release_channel').fetchall()
    assert hashlib.sha256(json.dumps(policies, sort_keys=True).encode()).hexdigest() == EXPECTED_POLICIES
    counts_before = [con.execute('SELECT count(*) FROM ' + t).fetchone()[0] for t in
                     ('local_licenses', 'local_activations', 'device_trial_claims', 'run_leases')]
    pool_before = hashlib.sha256(POOL.read_bytes()).hexdigest()
    health = request(BASE + '/health')
    assert health['status'] == 'healthy'
    print('HEALTH_200', health['service_revision'], flush=True)
    results = []
    for index, before in enumerate(baseline):
        fp = before['fingerprint']
        trial = request('http://127.0.0.1:18012/trial', {'code': fp}, form=True)
        assert trial['activated'] is True and trial['status'] == 'ACTIVE'
        if index == 0:
            assert trial['card'][-4:] == 'C74C'
        validation = request(BASE + '/v1/entitlements/validate', {'license_key': trial['card'],
                             'hardware': {'fingerprint': fp, 'components': {}, 'platform': 'windows'}})
        previous = request(BASE + '/v1/entitlements/validate', {'license_key': before['card'],
                           'hardware': {'fingerprint': fp}})
        assert validation['valid'] and validation['can_start_runner']
        assert previous['valid'] == before['valid'] and previous['status'] == before['status']
        assert previous['license']['expires_at'] == before['expires_at']
        masked = fp[:8] + '...' + fp[-4:]
        result = {'device': masked, 'card_last4': trial['card'][-4:], 'status': trial['status'],
                  'expires_at': trial['expires_at'], 'is_beta_user': trial['is_beta_user'],
                  'validate': validation['valid'], 'previous_card_unchanged': True}
        print('VERIFIED', json.dumps(result), flush=True)
        results.append(result)
    counts_after = [con.execute('SELECT count(*) FROM ' + t).fetchone()[0] for t in
                    ('local_licenses', 'local_activations', 'device_trial_claims', 'run_leases')]
    assert counts_before == counts_after
    assert pool_before == hashlib.sha256(POOL.read_bytes()).hexdigest()
    print('READ_ONLY_COUNTS_AND_POOL_UNCHANGED', counts_after, flush=True)
    Path('/tmp/sb-codex-verified-20261024.json').write_text(json.dumps(results))


if __name__ == '__main__':
    main()
