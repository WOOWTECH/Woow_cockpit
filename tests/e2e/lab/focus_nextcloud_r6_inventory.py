#!/usr/bin/env python3
"""R6 read-only inventory. Fixed fields only; no service/image/package/recovery mutation or credential values."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[3]
LAB = Path.home() / '.woowbk-lab'
LP = LAB / 'bin/labpodman'
DEVICE = 'woowbk-dev-e'
BASELINE = '20261123T132013Z-34811d90'
FIXTURE = LAB / 'ha-fixtures/20261123-batch2/x86/woow-b2-nextcloud-x86-enc-share/woow-b2-nextcloud-x86-enc-share-20261123.tar'
FIXTURE_SHA = '2dcfc6769d6fed7dd5c375fc379aac43da606931c8378e3970c33f78a4bded9d'
ORIGINALS = {
    'localhost/woow-nextcloud:35.0.1-office2': 'e80170f48ac2534abd0960be4838dbe9fcdc498da924a62f2436cd470dab4165',
    'docker.io/collabora/code:26.04.4.2.1': 'a35ff1de149aeae0b1c9ecc83ab9406bd14a788cd61284e95b88b602df4a6ba3',
    'docker.io/pgvector/pgvector:0.8.6-pg16': '9b05db12a35460fff0587e009f9326e414a53e9484555547f96d214a2ba98ef7',
    'docker.io/library/redis:8.10.1-alpine': 'd1e21a26915a35a6eb5d820018cd55adfcda02e02f7d629e1f42df397d5494ad',
    'docker.io/nginxinc/nginx-unprivileged:1.29.3-alpine': '696695300a3c18a324c07ecb41f220e8c470302148b0378770cf5c70e6458ea0',
}
OWNER_BODY = r'''
import hashlib,json,pathlib,subprocess,sys
refs=json.loads(sys.stdin.read())
fmt='{"id":"{{.Id}}","architecture":"{{.Architecture}}","os":"{{.Os}}","size":{{.Size}},"repo_tags":{{json .RepoTags}},"repo_digests":{{json .RepoDigests}}}'
images=[]
for ref in refs:
 r=subprocess.run(['podman','image','inspect','--format',fmt,ref],capture_output=True,timeout=60)
 images.append({'ref':ref,'present':r.returncode==0,'identity':json.loads(r.stdout) if r.returncode==0 else None})
units={}
for name in ('nextcloud.target','nextcloud-app.service','nextcloud-db.service','nextcloud-redis.service',
             'nextcloud-office.service','nextcloud-gateway.service','nextcloud-cron.timer','woowtech-backup-schedule.timer'):
 r=subprocess.run(['systemctl','--user','show',name,'--property=ActiveState,SubState,UnitFileState'],capture_output=True,timeout=30)
 units[name]=dict(line.split('=',1) for line in r.stdout.decode().splitlines() if '=' in line)
quadlets={}
for p in sorted((pathlib.Path.home()/'.config/containers/systemd').glob('nextcloud*')):
 if p.is_file() and not p.is_symlink():
  raw=p.read_bytes()
  quadlets[p.name]={'sha256':hashlib.sha256(raw).hexdigest(),
   'images':[line.split('=',1)[1] for line in raw.decode().splitlines() if line.startswith('Image=')]}
print(json.dumps({'images':images,'units':units,'quadlets':quadlets},sort_keys=True))
'''
ROOT_BODY = r'''
import hashlib,json,pathlib,shutil
base=pathlib.Path('/usr/local/lib/woowtech-cockpit-backup/woowbackup');hashes={}
for name in ('ha_nextcloud.py','haadapters.py','haapps.py','hacommands.py','flows.py','hatarget.py','habackup.py'):
 p=base/name
 hashes[name]=hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
cat=pathlib.Path('/etc/woowtech-cockpit/backup/apps/nextcloud.json')
archive_root=pathlib.Path('/var/lib/woowtech-backup/archives')
found=[]
for p in archive_root.iterdir():
 if p.name.startswith('20261123T132013Z-34811d90') and not p.is_symlink():
  found.append({'directory':p.is_dir(),'bytes':p.stat().st_size if p.is_file() else None})
print(json.dumps({'memory_current':int(pathlib.Path('/sys/fs/cgroup/memory.current').read_text()),
 'memory_max':pathlib.Path('/sys/fs/cgroup/memory.max').read_text().strip(),
 'varlib_free_bytes':shutil.disk_usage('/var/lib').free,'installed_hashes':hashes,
 'catalog_exists':cat.is_file(),'catalog_sha256':hashlib.sha256(cat.read_bytes()).hexdigest() if cat.is_file() else None,
 'original_baseline_entries':found},sort_keys=True))
'''


def call(argv, data=None):
    result = subprocess.run([str(x) for x in argv], input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=400)
    if result.returncode or len(result.stdout) > 256 * 1024:
        raise RuntimeError('fixed-read-only-inventory-failed')
    return json.loads(result.stdout)


def collect():
    isolation = call([LP, 'inspect', DEVICE, '--format',
                      '{"running":{{.State.Running}},"network":"{{.HostConfig.NetworkMode}}",'
                      '"ports":{{json .HostConfig.PortBindings}},"memory_limit":{{.HostConfig.Memory}}}'])
    if isolation['running'] is not True or isolation['network'] != 'none' or isolation['ports'] != {}:
        raise RuntimeError('fixed-device-isolation-refused')
    owner = call([LP, 'exec', '-i', DEVICE, '/usr/local/bin/woowbk-owner', 'python3', '-I', '-c', OWNER_BODY],
                 json.dumps(list(ORIGINALS)).encode())
    root = call([LP, 'exec', '-i', DEVICE, 'python3', '-I', '-c', ROOT_BODY])
    historical = json.loads((LAB / 'evidence/test-env-cleanup-20261126/images-after.json').read_text())
    originals = []
    for ref, expected in ORIGINALS.items():
        row = next(x for x in historical if x['Id'] == expected)
        originals.append({'ref': ref, 'config_id': 'sha256:' + expected, 'size': row['Size'],
                          'repo_digests': row['RepoDigests'], 'historical_source_only': True})
    mem = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    return {'status': 'read-only-inventoried', 'device': DEVICE,
            'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO).decode().strip(),
            'isolation': isolation, 'owner': owner, 'root': root,
            'host_free_bytes': shutil.disk_usage(REPO).free,
            'host_memory_available_mib': int(mem['MemAvailable'].split()[0]) // 1024,
            'historical_original_images': originals, 'live_host_source_store_inspected': False,
            'fixture': {'exists': FIXTURE.is_file(), 'size': FIXTURE.stat().st_size if FIXTURE.is_file() else None,
                        'expected_size': 4467947520, 'expected_sha256': FIXTURE_SHA,
                        'fresh_full_sha256_verified': False},
            'completed_noshare_run': {'source': 'a3f49012', 'checks': '36/36', 'repeat_planned': False},
            'historical_original_share_run': {'source': '6a67eefa', 'checks': '113/113'},
            'original_baseline_id': BASELINE, 'live_baseline_validation': 'requires-reviewed-wake',
            's5_fixture_verified': False, 'device_mutations': 0, 'pulls': 0, 'image_recovery': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit('choose-new-inventory-output')
    record = collect()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as output:
        output.write(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'status': record['status'], 'images_present': sum(x['present'] for x in record['owner']['images']),
                      'memory_current': record['root']['memory_current'],
                      'free_bytes': record['root']['varlib_free_bytes'], 'device_mutations': 0, 'pulls': 0}))


if __name__ == '__main__':
    main()
