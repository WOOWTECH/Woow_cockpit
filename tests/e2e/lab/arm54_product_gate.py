"""Product target-version gate and inspect-only container isolation evidence.

Runs only in the uniquely allocated ARM54 workspace. Does not restore or start
an application service; refuses unknown product image versions unchanged.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

root = Path(sys.argv[1])
assert root.parent == Path('/var/tmp') and root.name.startswith('woow-arm54-ha-20261122-')
os.umask(0o077)
sys.path.insert(0, str(root / 'source/backup-engine'))
from woowbackup import hacommon, ha_headscale

env = dict(os.environ, HOME=str(root), XDG_CONFIG_HOME=str(root / 'config'),
           REGISTRY_AUTH_FILE=str(root / 'empty-auth.json'), TMPDIR=str(root / 'tmp'))
base = ['podman', '--root', str(root / 'store'), '--runroot', str(root / 'run'),
        '--storage-driver', 'vfs', '--events-backend', 'file', '--tmpdir', str(root / 'tmp')]
reference = 'docker.io/headscale/headscale@sha256:2df4cb333db8496801780b8b15ac13026dbe5c0b5207fca4abdde33e1cffaa31'
commands = []


def podman(*args, **kwargs):
    commands.append(list(args))
    result = subprocess.run(base + list(args), env=env, capture_output=True,
                            timeout=min(kwargs.get('timeout', 45), 45))
    if kwargs.get('check', True) and result.returncode:
        raise RuntimeError('isolated-product-gate-command-failed')
    assert len(result.stdout) <= kwargs.get('max_output', 1024 * 1024)
    return result


work = SimpleNamespace(runner=lambda app: SimpleNamespace(podman=podman))
app = SimpleNamespace(id='headscale')
labels = hacommon.image_labels(work, app, reference)
version = hacommon.semver(labels.get('org.opencontainers.image.version'))
blocker = ha_headscale.VERSIONS.blocker('0.1.3', version)
name = root.name + '-isolation-inspect'
try:
    podman('create', '--name', name, '--pull=never', '--network=none', '--memory=256m',
           '--memory-swap=256m', '--pids-limit=128', '--cpus=0.5', '--read-only', '--cap-drop=ALL',
           '--security-opt=no-new-privileges', '--log-driver=none', reference, 'version')
    info = json.loads(podman('inspect', name).stdout)[0]
    host = info['HostConfig']
    isolation = {'network_mode': host['NetworkMode'], 'port_bindings': host.get('PortBindings'),
                 'privileged': host['Privileged'], 'memory_bytes': host['Memory'],
                 'read_only_root': host['ReadonlyRootfs'], 'security_opt': host['SecurityOpt'],
                 'mounts': info.get('Mounts'), 'running': info['State']['Running']}
    assert isolation['network_mode'] == 'none' and not isolation['port_bindings']
    assert not isolation['privileged'] and not isolation['running'] and not isolation['mounts']
    assert isolation['memory_bytes'] == 256 * 1024 ** 2 and isolation['read_only_root']
    assert 'no-new-privileges' in isolation['security_opt']
finally:
    podman('rm', '-f', name, check=False)
print(json.dumps({'target_version': version, 'version_label_present': 'org.opencontainers.image.version' in labels,
                  'product_blocker': blocker, 'service_restore_acceptance': False,
                  'isolation': isolation, 'commands': commands}, sort_keys=True))
