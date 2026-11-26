#!/usr/bin/env python3
"""Reviewed, leased R6 image-only recovery; default is an offline plan.

The host source route is deploy-batch2.sh (inspect/save only); its original
save/load/tag algorithm is retained. Its floor is raised to 13GiB (admission
keeps its additional 1GiB), and transfer size/time are explicitly bounded.
No packages, services, host image changes, network access or pulls.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shlex
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from focus_nextcloud_r6_inventory import collect, call, ORIGINALS, LP
from focus_nextcloud_r6_sources import collect as sources_collect
from focus_nextcloud_r6_plan import DEVICE_CAP, GIB, MIB, RESERVE, image_budget, lease_check

REPO = HERE.parents[2]
CONTROLLER = HERE / 'deploy-batch2.sh'
CONTROLLER_SHA = 'e172fd5927ccf065ce088e426bc240ee8f0d60b4088a308388a5452a2546087b'

# The load is supervised INSIDE dev-e. Killing only the host `labpodman exec`
# client can leave a nested load running after the device mutex is released.
LOAD_SUPERVISOR = r'''
import os,signal,shutil,subprocess,sys,time
path,flag,expires=sys.argv[1:]
assert flag in ('','ignore-chown')
argv=['/usr/local/bin/woowbk-owner','podman']
if flag: argv+=['--storage-opt','ignore_chown_errors=true']
argv+=['load','-q','-i',path]
p=subprocess.Popen(argv,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
rc=2
try:
 while p.poll() is None:
  if min(shutil.disk_usage('/home').free,shutil.disk_usage('/var/lib').free)<13*1024**3+512*1024**2 or time.time()>=int(expires):
   break
  time.sleep(0.5)
 else: rc=p.returncode
finally:
 if p.poll() is None:
  os.killpg(p.pid,signal.SIGTERM)
  try:p.wait(timeout=60)
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGKILL);p.wait()
sys.exit(rc)
'''


def bounded_controller(original, expires_epoch):
    if hashlib.sha256(original.encode()).hexdigest() != CONTROLLER_SHA:
        raise ValueError('fixed-controller-source-changed')
    # Shell $0 remains the original absolute script, so its lib.sh and helpers
    # resolve exactly as before. No copy, edit or source of a mutating script.
    text = original.replace('FLOOR_GIB=12\n', 'FLOOR_GIB=13\n', 1)
    text = text.replace('guarded() {\n',
                        'guarded() {\n'
                        f'    [ "$(date +%s)" -lt {int(expires_epoch)} ] || die "R6 lease expired"\n', 1)
    text = text.replace('if [ "$SECONDS" -ge "$deadline" ]; then',
                        f'if [ "$SECONDS" -ge "$deadline" ] || [ "$(date +%s)" -ge {int(expires_epoch)} ]; then', 1)
    line = '    compressed=$(du -sb "$XFER_HOST" | cut -f1)\n'
    if text.count(line) != 1:
        raise ValueError('fixed-controller-boundary-changed')
    text = text.replace(line, line +
                        '    [ "$compressed" -le "$((size + 16 * 1024 * 1024))" ] || die "R6 compressed cap exceeded"\n', 1)
    load = ('    guarded 3600 nice -n 10 "$LP" exec -i "$NAME" /usr/local/bin/woowbk-owner podman '
            '"${load_opts[@]}" load -q -i "$xfer_dev" \\\n')
    if text.count(load) != 1:
        raise ValueError('fixed-controller-load-boundary-changed')
    return text.replace(load, '    nice -n 10 "$LP" exec -i "$NAME" python3 -I -c ' +
                        shlex.quote(LOAD_SUPERVISOR) + f' "$xfer_dev" "$flag" {int(expires_epoch)} \\\n', 1)


def run(lease_path):
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO, text=True).strip():
        raise ValueError('fixed-committed-source-required')
    lease = json.loads(lease_path.read_text())
    lease_check(lease, commit, 'image-recovery')
    if lease.get('host_source_operations') != ['inspect', 'save']:
        raise ValueError('fixed-host-export-lease-required')
    with open('/tmp/woowbk-dev-e-mutation.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lease_check(lease, commit, 'image-recovery')
        before = collect()
        if (before['isolation']['memory_limit'] != DEVICE_CAP
                or before['root']['memory_max'] != str(DEVICE_CAP)
                or before['host_memory_available_mib'] < 2200
                or DEVICE_CAP - before['root']['memory_current'] < 1536 * MIB
                or any(x['present'] for x in before['owner']['images'])
                or any(x.get('ActiveState') != 'inactive' for x in before['owner']['units'].values())):
            raise ValueError('fixed-cold-three-gib-baseline-required')
        sources = sources_collect()
        if not sources['all_originals_present_and_matching'] or not all(x['canonical_ref_matches'] for x in sources['images']):
            raise ValueError('fixed-original-source-identity-refused')
        bound = image_budget([x['identity']['size'] for x in sources['images']])
        # Controller admission additionally retains 1GiB beyond its raised floor.
        if min(before['host_free_bytes'], before['root']['varlib_free_bytes']) < bound['minimum_start_free_bytes'] + GIB:
            raise ValueError('fixed-recovery-disk-preflight-refused')
        home = subprocess.check_output([str(LP), 'volume', 'inspect', 'woowbk-dev-e-home',
                                        '--format', '{{.Mountpoint}}'], text=True).strip()
        transfer_parent = Path(home) / '.woowbk-xfer'
        if transfer_parent.is_symlink() or any((transfer_parent / x[:12]).exists() or
                                               (transfer_parent / x[:12]).is_symlink() for x in ORIGINALS.values()):
            raise ValueError('fixed-existing-transfer-refused')
        expires = int(datetime.datetime.fromisoformat(lease['expires_utc'].replace('Z', '+00:00')).timestamp())
        body = bounded_controller(CONTROLLER.read_text(), expires)
        evidence = Path.home() / '.woowbk-lab/evidence/focus-nextcloud-r6-recovery' / time.strftime('%Y%m%dT%H%M%S')
        evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chmod(evidence.parent, 0o700)
        fd = os.open(evidence / 'controller.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as log:
            proc = subprocess.run(['bash', '-c', body, str(CONTROLLER), 'e', 'images:nextcloud'],
                                  stdout=log, stderr=log)
        # Even on failure, hold the device mutex until this read-only snapshot is
        # captured. No automatic image/store deletion or retry is attempted.
        after = collect()
        source_after = sources_collect()
        unchanged = [{k: x[k] for k in ('ref', 'expected_config_id', 'identity', 'canonical_ref_config_id')}
                     for x in sources['images']] == [
                     {k: x[k] for k in ('ref', 'expected_config_id', 'identity', 'canonical_ref_config_id')}
                     for x in source_after['images']]
        loaded = all(x['present'] and x['identity']['id'].removeprefix('sha256:') == ORIGINALS[x['ref']]
                     and x['identity']['architecture'] == 'amd64' and x['identity']['os'] == 'linux'
                     for x in after['owner']['images'])
        preserved = (after['owner']['units'] == before['owner']['units']
                     and after['owner']['quadlets'] == before['owner']['quadlets']
                     and after['root']['catalog_sha256'] == before['root']['catalog_sha256']
                     and after['root']['original_baseline_entries'] == before['root']['original_baseline_entries'])
        record = {'status': 'passed' if proc.returncode == 0 and unchanged and loaded and preserved else 'failed',
                  'source_commit': commit, 'phase': 'image-recovery-only', 'source_unchanged': unchanged,
                  'original_five_loaded': loaded, 'inactive_units_quadlets_catalog_baseline_metadata_preserved': preserved,
                  'images': after['owner']['images'], 'free_bytes': after['root']['varlib_free_bytes'],
                  'reserve_bytes': RESERVE, 'memory_cap_bytes': DEVICE_CAP, 'pulls': 0,
                  'host_source_operations': ['inspect', 'save'], 'live_baseline_validation': 'requires-reviewed-wake'}
        (evidence / 'fixed-result.json').write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps({'status': record['status'], 'phase': record['phase'], 'pulls': 0,
                          'source_unchanged': unchanged, 'original_five_loaded': loaded}))
        return 0 if record['status'] == 'passed' else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', action='store_true')
    p.add_argument('--lease', type=Path)
    args = p.parse_args()
    if not args.run:
        print('offline image-recovery preparation; no device/host image access or bytes copied')
        return 0
    if args.lease is None:
        p.error('--run requires a reviewed --lease including host inspect/save')
    return run(args.lease)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, BlockingIOError):
        print('fixed-r6-recovery-preflight-refused', file=sys.stderr)
        sys.exit(2)
