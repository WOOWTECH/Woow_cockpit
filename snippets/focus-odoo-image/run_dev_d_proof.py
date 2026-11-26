#!/usr/bin/env python3
"""LEASE ONLY: stage this committed code into a NEW dev-d proof directory and run the offline image proof.

Uses only labpodman (isolated lab outer storage), existing dev-d mutation lock, and root-protected /var/lib staging.
No packages, host images, pulls, source retags, account/auth changes, or source-tree deployment.
"""
import argparse
import base64
import datetime
import fcntl
import json
from pathlib import Path
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
LAB = Path.home() / '.woowbk-lab/bin/labpodman'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proof-root', required=True, help='NEW /var/lib/woowbk-odoo-pg16-proof-<lease-id> inside dev-d.')
    args = parser.parse_args()
    root = Path(args.proof_root)
    assert root.parent == Path('/var/lib') and root.name.startswith('woowbk-odoo-pg16-proof-')
    assert shutil.disk_usage(REPO).free >= 17 * 1024**3
    assert not Path('/tmp/woowbk-dev-d-emqx-main-waiting').exists(), 'emqx-priority-waiter'
    lease = json.loads(Path('/tmp/parity-focus-20261127/lease-odoo-dev-d.json').read_text())
    assert datetime.datetime.now(datetime.timezone.utc) < datetime.datetime.fromisoformat(lease['expires'])
    assert str(REPO) == lease['worktree']
    leased_root = Path(lease['proof_root'])
    suffix = root.name.removeprefix(leased_root.name + '-r')
    assert root == leased_root or (root.name.startswith(leased_root.name + '-r') and suffix.isdigit())
    assert subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--'], cwd=REPO).returncode == 0
    with open('/tmp/woowbk-dev-d-mutation.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        assert int(memory['MemAvailable'].split()[0]) >= 1200 * 1024
        isolated = subprocess.run([str(LAB), 'inspect', 'woowbk-dev-d', '--format',
                                   '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}'],
                                  capture_output=True, timeout=30)
        assert isolated.returncode == 0 and isolated.stdout.strip() == b'true none {}'
        paths = sorted(p for p in (REPO / 'backup-engine/woowbackup').rglob('*.py') if '__pycache__' not in p.parts)
        paths += [REPO / 'scripts/package_odoo_pg16.py']
        paths += [REPO / 'snippets/focus-odoo-image' / name for name in
                  ('dev_d_offline_proof.py', 'upstream-pg16-index.json', 'upstream-pg16-amd64-manifest.json')]
        files = {str(p.relative_to(REPO)): base64.b64encode(p.read_bytes()).decode() for p in paths}
        # Only small trusted code/registry metadata goes through this JSON. All image bytes remain streamed on device.
        payload = r'''
import base64, json, os, pathlib, shutil, sys
root = pathlib.Path(PROOF_ROOT)
assert os.geteuid() == 0 and root.parent == pathlib.Path('/var/lib')
assert root.name.startswith('woowbk-odoo-pg16-proof-') and not root.exists() and not root.is_symlink()
assert shutil.disk_usage('/var/lib').free >= 17 * 1024**3
current = int(pathlib.Path('/sys/fs/cgroup/memory.current').read_text())
limit = pathlib.Path('/sys/fs/cgroup/memory.max').read_text().strip()
assert limit != 'max' and int(limit) - current >= 512 * 1024**2
os.umask(0o022)
root.mkdir(mode=0o755)
code = root / 'code'
for relative, value in FILES.items():
    path = code / relative
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    path.write_bytes(base64.b64decode(value))
    path.chmod(0o644)
script = code / 'snippets/focus-odoo-image/dev_d_offline_proof.py'
sys.argv = [str(script), '--proof-root', str(root), '--code-root', str(code)]
exec(compile(script.read_text(), str(script), 'exec'), {'__name__': '__main__', '__file__': str(script)})
'''.replace('PROOF_ROOT', repr(str(root))).replace('FILES', repr(files))
        result = subprocess.run([str(LAB), 'exec', '-i', 'woowbk-dev-d', 'python3', '-I', '-'],
                                input=payload.encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3600)
        try:
            report = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            report = {'status': 'failed', 'exit': result.returncode, 'reason': 'no-fixed-result'}
        report['proof_root'] = str(root)
        report['host_ram_available_mib_start'] = int(memory['MemAvailable'].split()[0]) // 1024
        report['source_commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO).decode().strip()
        destination = REPO / 'snippets/focus-odoo-image' / (root.name + '-result.json')
        with destination.open('x') as output:
            output.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, sort_keys=True))
        return 0 if result.returncode == 0 and report.get('status') == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
