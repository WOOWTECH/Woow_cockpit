#!/usr/bin/env python3
"""Exact unchanged package smoke on a separately provisioned SYNTHETIC device only.

Default is a plan. This does not provision a device, install/upgrade packages, read current app secrets or use dev-d's
package names. The prerequisite fixture device/commands in package-review.md need their own coordinator review/lease.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
import focus_emqx_r4_fixtures as fx

PACKAGE_COMMIT = 'ea5886c'
PACKAGE_DIR = '/home/appowner/r4-package'
# Source bound to the unchanged package reviewed for this preparation. Full hashes are in package-source.json.
PACKAGE_FILES = ('tests/smoke.sh', 'scripts/common.sh', 'scripts/lib/quadlet-lib.sh')
CLIENT_IMAGE = 'docker.io/library/eclipse-mosquitto:2.0.22@sha256:212f89e1eaeb2c322d6441b64396e3346026674db8fa9c27beac293405c32b3c'
PLAN = {'phase': 'exact-package-smoke', 'provisioning': 'separate owned synthetic device required; not automated here',
        'device_pattern': 'woowbk-r4-package-<12 lowercase hex>', 'outer_network': 'none', 'outer_ports': 0,
        'outer_memory_mib': 2304, 'outer_cpus': 2, 'outer_pids': 2048, 'host_available_mib': 3000,
        'disk_floor_gib': 16, 'smoke_wall_seconds': 600, 'package_commit': PACKAGE_COMMIT,
        'package_modified': False, 'installer_or_upgrader': False,
        'client_image': CLIENT_IMAGE, 'cases': [c.id for c in fx.CASES if c.expected == 'candidate-and-restart'],
        'scope': 'exact package smoke only; upgrade decision inferred, upgrader never invoked'}


def validate_lease(doc, case, commit, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    until = datetime.datetime.fromisoformat(doc['expires'])
    if (until.tzinfo is None or until <= now or doc.get('case') != 'EMQX-R4-package:' + case
            or doc.get('source_commit') != commit or doc.get('fixture_inputs') != 'synthetic-owned-only'
            or doc.get('installer_or_upgrader') is not False
            or not re.fullmatch(r'woowbk-r4-package-[0-9a-f]{12}', doc.get('device', ''))):
        raise ValueError('separate_exact_package_fixture_lease_required')
    return doc['device']


def smoke_status(raw):
    """Retain check IDs/statuses only; never echo arbitrary package diagnostics or values."""
    if len(raw) > 8 * 1024**2: raise ValueError('smoke_output_budget')
    rows = []
    for line in raw.decode('utf-8', 'replace').splitlines():
        match = re.match(r'^(PASS|FAIL|WARN) (A[0-9]+(?:/A[0-9]+)*)\b', line)
        if match: rows.append({'status': match[1], 'check': match[2]})
    if not rows: raise ValueError('no_smoke_status')
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true'); parser.add_argument('--case', choices=PLAN['cases'])
    parser.add_argument('--lease', type=Path)
    args = parser.parse_args(argv)
    if not args.run: print(json.dumps(PLAN, sort_keys=True)); return 0
    if not args.case or not args.lease or args.lease.is_symlink(): raise ValueError('reviewed_fixture_lease_required')
    import dev_d_guard
    if not dev_d_guard.clean_tree(ROOT)[0]: raise ValueError('commit_sources_first')
    doc = json.loads(args.lease.read_text()); commit = dev_d_guard.head(ROOT)
    device = validate_lease(doc, args.case, commit)
    if (next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
            < 3000 * 1024): raise ValueError('host_memory_floor')
    if __import__('shutil').disk_usage(ROOT).free < 16 * 1024**3: raise ValueError('host_disk_floor')
    lp = Path.home() / '.woowbk-lab/bin/labpodman'
    manifest = json.loads((ROOT / 'snippets/focus-emqx-r4/package-source.json').read_text())
    fd, _ = dev_d_guard.acquire(timeout=15)
    def call(*parts, timeout=60):
        result = subprocess.run([str(lp), *parts], capture_output=True, timeout=timeout)
        if result.returncode or len(result.stdout) > 8 * 1024**2: raise ValueError('owned_package_command_failed')
        return result.stdout
    try:
        validate_lease(doc, args.case, commit)
        # Exact fixed fields only; no full inspect/env/command lines or external device actions.
        state = call('inspect', device, '--format', '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}} {{index .Config.Labels "io.woowtech.r4.fixture"}}').decode().strip()
        if state != 'true none {} ' + device: raise ValueError('not_owned_isolated_fixture_device')
        mounts = call('inspect', device, '--format', '{{range .Mounts}}{{.Name}}:{{.Destination}};{{end}}').decode().strip()
        if set(mounts.rstrip(';').split(';')) != {device + '-home:/home', device + '-varlib:/var/lib/woowtech-backup',
                                                 device + '-containers:/var/lib/containers'}:
            raise ValueError('fixture_mounts_not_all_owned')
        owner = ['exec', '-i', device, '/usr/local/bin/woowbk-owner']
        uid = call(*owner, 'id', '-u').strip()
        if uid != b'1031': raise ValueError('dedicated_fixture_uid_required')
        marker = call(*owner, 'cat', '/home/appowner/r4-owned-inputs.json')
        if json.loads(marker) != {'device': device, 'case': args.case, 'inputs': 'synthetic-owned-only',
                                  'source_commit': commit}:
            raise ValueError('synthetic_fixture_marker_mismatch')
        for relative in PACKAGE_FILES:
            data = call(*owner, 'cat', PACKAGE_DIR + '/' + relative)
            if hashlib.sha256(data).hexdigest() != manifest['head_files'][relative]:
                raise ValueError('unmodified_package_source_required')
        call(*owner, 'podman', 'image', 'exists', CLIENT_IMAGE)
        raw = subprocess.run([str(lp), *owner, 'bash', PACKAGE_DIR + '/tests/smoke.sh'], capture_output=True, timeout=600)
        rows = smoke_status(raw.stdout)
        check_ids = {x['check'] for x in rows}
        if not {'A1', 'A2', 'A3', 'A4', 'A5', 'A6', 'A7', 'A8', 'A9'} <= check_ids:
            raise ValueError('package_smoke_missing_checks')
        result = {'case': args.case, 'source_commit': commit, 'package_commit': manifest['head_commit'],
                  'smoke_exit_code': raw.returncode, 'checks': rows, 'installer_or_upgrader_executed': False,
                  'capture_completed': True, 'smoke_ok': raw.returncode == 0,
                  'scope': 'exact smoke on independent synthetic fixture; no current app selected',
                  'fixture_cleanup': 'coordinator-owned provisioning driver must remove the whole device and its three owned volumes'}
        print(json.dumps(result, sort_keys=True)); return 0
    finally: os.close(fd)


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'ok': False, 'reason': type(error).__name__})); raise SystemExit(1)
