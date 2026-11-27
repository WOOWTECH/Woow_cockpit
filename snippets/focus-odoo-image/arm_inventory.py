#!/usr/bin/env python3
"""Read-only OD-23 lease preflight through the existing private ARM controller. No authentication overrides.

The controller supplies its existing remote()/HOST54/workspace() context. Only fixed image-inspect fields leave
the device; no export, load, pull, staging, package install, account change, or default-store command is executed.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

PIN = ('docker.io/library/postgres:16.15-alpine'
       '@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139')
CONFIG = 'sha256:35726244c51a57338a5a5a5ad8a7e2b18f4ecb8dccd51224cab33ac2ea6a5df0'
CODE = r'''
import json, os, pathlib, platform, shutil, subprocess
root = pathlib.Path(WORKSPACE)
assert root.parent == pathlib.Path('/var/tmp') and root.name.startswith('woow-arm54-final-20261123-')
out = {'device': '192.168.2.54', 'workspace': str(root), 'workspace_exists': root.is_dir(),
       'machine': platform.machine(), 'free_bytes': shutil.disk_usage('/var/tmp').free,
       'reserve_bytes': 12 * 1024**3 + 128 * 1024**2, 'extra_budget_bytes': 2 * 1024**3,
       'read_only': True, 'pulls': 0, 'image_inspect': 'not-run'}
if root.is_dir() and not root.is_symlink() and root.stat().st_mode & 0o777 == 0o700:
    driver = (root / 'store-driver').read_text().strip() if (root / 'store-driver').is_file() else 'vfs'
    assert driver in ('overlay', 'vfs')
    out['store_driver'] = driver
    if (root / 'store').is_dir() and (root / 'run').is_dir():
        base = ['podman', '--root', str(root / 'store'), '--runroot', str(root / 'run'), '--storage-driver', driver]
        if driver == 'overlay':
            base += ['--storage-opt', 'overlay.skip_mount_home=true']
        base += ['--events-backend', 'file', '--tmpdir', str(root / 'tmp'), '--cgroup-manager', 'cgroupfs']
        env = dict(os.environ, HOME=str(root), XDG_CONFIG_HOME=str(root / 'config'),
                   REGISTRY_AUTH_FILE=str(root / 'empty-auth.json'), TMPDIR=str(root / 'tmp'),
                   CONTAINERS_CONF_OVERRIDE=str(root / 'containers-override.conf'))
        fmt = ('{"id":"{{.Id}}","architecture":"{{.Architecture}}","os":"{{.Os}}",'
               '"size":{{.Size}},"repo_digests":{{json .RepoDigests}},"repo_tags":{{json .RepoTags}}}')
        result = subprocess.run(base + ['image', 'inspect', '--format', fmt, REF],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, env=env)
        out['image_inspect'] = 'passed' if result.returncode == 0 else 'missing-or-unavailable'
        out['inspect_exit'] = result.returncode
        if result.returncode == 0:
            assert len(result.stdout) <= 65536
            fields = json.loads(result.stdout)
            if not fields['id'].startswith('sha256:'):
                fields['id'] = 'sha256:' + fields['id']
            out['source_image'] = fields
            out['exact_source_match'] = (fields['id'] == CONFIG_ID and fields['architecture'] == 'arm64'
                and fields['os'] == 'linux' and REF.split('@')[0] in (fields['repo_tags'] or [])
                and 'docker.io/library/postgres@' + REF.split('@')[1] in (fields['repo_digests'] or []))
out['budget_fits'] = out['free_bytes'] >= out['reserve_bytes'] + out['extra_budget_bytes']
print(json.dumps(out, sort_keys=True))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--controller', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('od23_existing_arm_controller', args.controller)
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    workspace = controller.workspace()
    code = CODE.replace('WORKSPACE', repr(workspace)).replace('CONFIG_ID', repr(CONFIG)).replace('REF', repr(PIN))
    try:
        result = controller.remote(controller.HOST54, code, timeout=90)
    except SystemExit:
        report = {'status': 'blocked-existing-auth-context-unavailable', 'workspace': workspace,
                  'read_only': True, 'remote_invoked': False, 'pulls': 0}
    else:
        if result.returncode != 0:
            report = {'status': 'remote-inventory-failed', 'workspace': workspace, 'exit': result.returncode,
                      'diagnostics': controller.fixed_diagnostics(result.stderr), 'pulls': 0}
        else:
            report = json.loads(result.stdout)
            report['status'] = 'lease-preflight-ready' if report.get('exact_source_match') and report['budget_fits'] else 'lease-preflight-incomplete'
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'lease-preflight-ready' else 1


if __name__ == '__main__':
    sys.exit(main())
