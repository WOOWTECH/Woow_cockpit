"""Remove only this run's isolated objects/workspace; compare original inventory."""
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(sys.argv[1])
assert root.parent == Path('/var/tmp') and root.name.startswith('woow-arm54-ha-20261122-')
assert not root.is_symlink() and root.stat().st_uid == 0 and root.stat().st_mode & 0o777 == 0o700
baseline = json.loads((root / 'baseline.json').read_text())
started = (root / 'baseline.json').stat().st_mtime


def read(args):
    return subprocess.check_output(args, timeout=45).decode().splitlines()


def inventory():
    return {'containers': read(['podman', 'ps', '-a', '--no-trunc', '--format', '{{.ID}} {{.Names}} {{.Image}} {{.State}} {{.Ports}}']),
            'images': read(['podman', 'images', '--no-trunc', '--format', '{{.ID}} {{.Repository}}:{{.Tag}}']),
            'volumes': read(['podman', 'volume', 'ls', '--format', '{{.Name}}']),
            'networks': read(['podman', 'network', 'ls', '--format', '{{.Name}}']),
            'store': read(['podman', 'info', '--format', '{{.Store.GraphRoot}} {{.Store.RunRoot}}'])}


def equal(a, b):
    return all(sorted(a[key]) == sorted(b[key]) for key in a)


env = dict(os.environ, HOME=str(root), XDG_CONFIG_HOME=str(root / 'config'),
           REGISTRY_AUTH_FILE=str(root / 'empty-auth.json'), TMPDIR=str(root / 'tmp'))
base = ['podman', '--root', str(root / 'store'), '--runroot', str(root / 'run'),
        '--storage-driver', 'vfs', '--events-backend', 'file', '--tmpdir', str(root / 'tmp')]
report = {'workspace': str(root), 'commands': [], 'free_bytes_before_cleanup': shutil.disk_usage(root).free}


def own(args):
    report['commands'].append(args)
    result = subprocess.run(base + args, env=env, capture_output=True, timeout=60)
    assert result.returncode == 0, 'isolated-cleanup-command-failed'
    return result.stdout.decode().splitlines()


before = inventory()
report['default_inventory_equal_before_cleanup'] = equal(before, baseline)
# IDs belong only to this run's private store; never invoke default mutation.
containers = own(['ps', '-aq', '--no-trunc'])
if containers:
    own(['rm', '-f', *containers])
volumes = own(['volume', 'ls', '--format', '{{.Name}}'])
if volumes:
    own(['volume', 'rm', *volumes])
images = own(['images', '-q', '--no-trunc'])
if images:
    own(['rmi', '-f', *sorted(set(images))])
report['isolated_containers_after'] = own(['ps', '-aq'])
report['isolated_volumes_after'] = own(['volume', 'ls', '--format', '{{.Name}}'])
report['isolated_images_after'] = own(['images', '-q'])
assert not report['isolated_containers_after'] and not report['isolated_volumes_after'] and not report['isolated_images_after']
mounts = [line.split()[4] for line in Path('/proc/self/mountinfo').read_text().splitlines()]
assert not any(path == str(root) or path.startswith(str(root) + '/') for path in mounts), 'workspace-still-mounted'
report['workspace_mounts_remaining'] = False
shutil.rmtree(root)
after = inventory()
report['default_inventory_after'] = after
report['default_inventory_equal_after_cleanup'] = equal(after, baseline)
report['workspace_removed'] = not root.exists()
report['free_bytes_after_cleanup'] = shutil.disk_usage('/var/tmp').free
ids = [line.split()[0] for line in baseline['containers']]
started_rows = [json.loads(line) for line in read(['podman', 'inspect', '--format',
    '{"id":"{{.Id}}","started":{{json .State.StartedAt}},"running":{{json .State.Running}}}', *ids])]
report['original_started_at_after'] = started_rows
report['probe_started_epoch'] = started
report['originals_started_before_probe_and_still_running'] = all(
    row['running'] and datetime.datetime.fromisoformat(row['started'].replace('Z', '+00:00')).timestamp() < started
    for row in started_rows)
report['status'] = 'passed' if all((report['default_inventory_equal_before_cleanup'],
    report['default_inventory_equal_after_cleanup'], report['workspace_removed'],
    report['originals_started_before_probe_and_still_running'],
    report['free_bytes_after_cleanup'] >= 12 * 1024 ** 3)) else 'failed'
print(json.dumps(report, sort_keys=True))
sys.exit(0 if report['status'] == 'passed' else 1)
