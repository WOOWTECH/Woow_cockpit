#!/usr/bin/env python3
"""Plan by default. One synthetic case per future coordinator lease; no existing app or package commands."""
import argparse
import datetime
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
import focus_emqx_r4_fixtures as fixtures

PLAN = {'device': 'woowbk-dev-d', 'case': 'EMQX-R4-generated', 'image': fixtures.IMAGE,
        'brokers_running_max': 2, 'each_memory_mib': 768, 'each_cpus': 0.5, 'each_pids': 256,
        'wall_seconds_per_case': 900, 'staging_mib': 256, 'disk_floor_gib': 13,
        'host_available_mib': 1200, 'device_headroom_mib': 1900,
        'network': 'none', 'ports': 0, 'image_volume': 'ignore', 'pull': 'never',
        'lock': '/tmp/woowbk-dev-d-mutation.lock', 'native_executed': False,
        'cases': fixtures.matrix(), 'package_smoke': 'separate proposal; no installer/upgrader invocation',
        'addon_env_vars': 'current policy: not moved; device environment wins (H1); no source addon feature added'}
BOOTSTRAP = '''import io,pathlib,shutil,subprocess,sys,tarfile,tempfile
raw=sys.stdin.buffer.read(16777217); assert len(raw)<=16777216
root=pathlib.Path(tempfile.mkdtemp(prefix='woowbk-r4-',dir=pathlib.Path.home()))
with tarfile.open(fileobj=io.BytesIO(raw)) as src:
 for m in src:
  p=pathlib.PurePosixPath(m.name)
  assert m.isfile() and not p.is_absolute() and '..' not in p.parts and 0<=m.size<=4194304
  dest=root.joinpath(*p.parts);dest.parent.mkdir(parents=True,exist_ok=True)
  with dest.open('xb') as out:out.write(src.extractfile(m).read())
r=subprocess.run([sys.executable,'-B','-I',str(root/'focus_emqx_r4_runtime.py'),sys.argv[1]],capture_output=True,timeout=870)
sys.stdout.buffer.write(r.stdout)
if r.returncode==0:shutil.rmtree(root)
sys.exit(r.returncode)
'''


def bundle():
    buf = io.BytesIO()
    members = [(p, 'woowbackup/' + p.name) for p in sorted((ROOT / 'backup-engine/woowbackup').glob('*.py'))]
    members += [(HERE / ('focus_emqx_r4_' + name + '.py'), 'focus_emqx_r4_' + name + '.py')
                for name in ('fixtures', 'runtime')]
    with tarfile.open(fileobj=buf, mode='w') as archive:
        for path, name in members:
            if path.is_symlink() or not path.is_file():
                raise ValueError('regular_reviewed_sources_only')
            data = path.read_bytes()
            if len(data) > 4 * 1024**2:
                raise ValueError('source_file_budget')
            info = tarfile.TarInfo(name); info.size = len(data); info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))
    data = buf.getvalue()
    if len(data) > 16 * 1024**2:
        raise ValueError('source_payload_budget')
    return data


def validate_lease(path, case_id, commit, now=None):
    """Require a fresh exact-case lease. No existing E44 or NC authorization can start an R4 fixture."""
    if not path or Path(path).is_symlink():
        raise ValueError('new_coordinator_lease_required')
    lease = json.loads(Path(path).read_text())
    now = now or datetime.datetime.now(datetime.timezone.utc)
    expires = datetime.datetime.fromisoformat(lease['expires'])
    if (expires.tzinfo is None or (expires - now).total_seconds() < 900 or lease.get('device') != PLAN['device']
            or lease.get('case') != 'EMQX-R4-generated:' + case_id
            or lease.get('source_commit') != commit or lease.get('image_config') != fixtures.IMAGE
            or lease.get('command') != 'python3 -B -I tests/e2e/lab/focus_emqx_r4.py --run --case ' + case_id
            or lease.get('package_commands') is not False):
        raise ValueError('lease_does_not_match_reviewed_case')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--case', choices=sorted(fixtures.BY_ID))
    parser.add_argument('--lease', type=Path)
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps(PLAN, sort_keys=True)); return 0
    if not args.case:
        raise ValueError('select_exactly_one_reviewed_case')
    import dev_d_guard
    commit = dev_d_guard.head(ROOT)
    if not dev_d_guard.clean_tree(ROOT)[0]:
        raise ValueError('commit_driver_and_product_first')
    lease = args.lease or Path('/tmp/parity-focus-20261127/lease-emqx-r4-' + args.case + '.json')
    validate_lease(lease, args.case, commit)
    available = next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines()
                     if x.startswith('MemAvailable:'))
    if available < 1200 * 1024 or shutil.disk_usage(ROOT).free < 13 * 1024**3 + 256 * 1024**2:
        raise ValueError('host_resource_floor')
    owner = HERE / 'owner.sh'
    dev_d_guard.verify_isolation(owner)
    # Yield quickly to queued device work. No automatic retry/multi-case loop inside a heavy slot.
    fd, _ = dev_d_guard.acquire(timeout=15)
    try:
        validate_lease(lease, args.case, commit)
        dev_d_guard.verify_isolation(owner)
        result = subprocess.run(['bash', str(owner), 'd', 'python3', '-B', '-I', '-c', BOOTSTRAP, args.case],
                                input=bundle(), capture_output=True, timeout=900)
        rows = result.stdout.strip().splitlines()
        doc = json.loads(rows[-1]) if rows else {'ok': False, 'reason': 'no_fixed_result'}
        doc['source_commit'] = commit
        print(json.dumps(doc, sort_keys=True))
        return 0 if result.returncode == 0 and doc.get('ok') else 1
    finally:
        try: dev_d_guard.verify_isolation(owner)
        finally: os.close(fd)


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'ok': False, 'reason': type(error).__name__})); raise SystemExit(1)
