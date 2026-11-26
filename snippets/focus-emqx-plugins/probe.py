#!/usr/bin/env python3
"""Plan by default; --run is for the coordinator's bounded dev-d fixture lease only.

Uses the existing isolated lab owner wrapper and mutation lock. Never calls host Podman, installs sources, pulls images,
loads an original HA fixture, or selects an installed application's container/volume for mutation.
"""
import argparse
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
IMAGE = 'sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b'
PLAN = {'device': 'woowbk-dev-d', 'case': 'E-44-disposable-plugins', 'image': IMAGE,
        'image_manifest': 'sha256:d4ec63c4065c745507e7652d9c0213134697dc1317d8a431b167ae7651c4e937',
        'lock': '/tmp/woowbk-dev-d-mutation.lock', 'wall_seconds': 900,
        'brokers_max': 2, 'each_memory_mib': 768, 'each_cpus': 0.5, 'each_pids': 256,
        'staging_max_mib': 256, 'host_disk_reserve_gib': 13, 'host_memory_min_mib': 1200,
        'device_headroom_min_mib': 1900, 'network': 'none', 'published_ports': 0,
        'states_persisted_before_boot': ['woow_e44_fixture-1.0.0', 'woow_e44_missing-1.0.0']}
# The payload is THIS clean checkout's ordinary Python package and the reviewed fixture sources only, not an installer.
BOOTSTRAP = '''import io, pathlib, subprocess, sys, tarfile, tempfile
payload=sys.stdin.buffer.read(16777217)
assert len(payload)<=16777216
root=pathlib.Path(tempfile.mkdtemp(prefix="woowbk-e44-"))
with tarfile.open(fileobj=io.BytesIO(payload)) as src:
    for m in src:
        p=pathlib.PurePosixPath(m.name)
        assert m.isfile() and not p.is_absolute() and ".." not in p.parts and 0<=m.size<=4194304
        dst=root.joinpath(*p.parts); dst.parent.mkdir(parents=True,exist_ok=True)
        with dst.open("xb") as out: out.write(src.extractfile(m).read())
r=subprocess.run([sys.executable,"-I",str(root/"runtime_probe.py")],timeout=870,capture_output=True)
sys.stdout.buffer.write(r.stdout)
# Child owns cleanup. Retain its private payload if cleanup was uncertain; no host-side sweeping.
if r.returncode==0:
    import shutil; shutil.rmtree(root)
sys.exit(r.returncode)
'''


def bundle():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as out:
        files = [(p, str(p.relative_to(ROOT / 'backup-engine'))) for p in sorted((ROOT / 'backup-engine/woowbackup').glob('*.py'))]
        files += [(HERE / name, name) for name in ('runtime_probe.py', 'woow_e44_fixture.erl')]
        for path, name in files:
            data = path.read_bytes()
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(data), 0o600
            out.addfile(entry, io.BytesIO(data))
    data = buf.getvalue()
    if len(data) > 16 * 1024 * 1024:
        raise RuntimeError('source_payload_budget')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    if not args.run:
        print(json.dumps(PLAN, sort_keys=True))
        return 0
    sys.path.insert(0, str(ROOT / 'tests/e2e/lab'))
    import dev_d_guard
    clean, _ = dev_d_guard.clean_tree(ROOT)
    if not clean:
        raise RuntimeError('commit_probe_and_source_first')
    available = next(int(row.split()[1]) for row in Path('/proc/meminfo').read_text().splitlines()
                     if row.startswith('MemAvailable:'))
    if available < 1200 * 1024 or shutil.disk_usage(ROOT).free < 13 * 1024**3 + 256 * 1024**2:
        raise RuntimeError('host_resource_floor')
    owner = ROOT / 'tests/e2e/lab/owner.sh'
    dev_d_guard.verify_isolation(owner)
    # Existing shared lock; never create a second scheduling/lease mechanism. NC may hold this lock first.
    fd, _ = dev_d_guard.acquire(timeout=180)
    try:
        dev_d_guard.verify_isolation(owner)
        result = subprocess.run(['bash', str(owner), 'd', 'python3', '-I', '-c', BOOTSTRAP],
                                input=bundle(), capture_output=True, timeout=900)
        # Child emits fixed check names and booleans only; stderr/raw broker logs never become public evidence.
        body = result.stdout.strip().splitlines()
        doc = json.loads(body[-1]) if body else {'ok': False, 'reason': 'no_fixed_result'}
        doc['source_commit'] = dev_d_guard.head(ROOT)
        print(json.dumps(doc, sort_keys=True))
        return 0 if result.returncode == 0 and doc.get('ok') is True else 1
    finally:
        dev_d_guard.verify_isolation(owner)
        os.close(fd)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'ok': False, 'reason': type(error).__name__}))
        raise SystemExit(1)
