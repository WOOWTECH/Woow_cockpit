"""Run on the authorized ARM target in the already allocated private workspace.

Official public Headscale ARM image only; separate storage, no published ports.
This prepares a native service baseline, not HA conversion/restore acceptance.
"""
import json
import hashlib
import urllib.request
import os
from pathlib import Path
import shutil
import subprocess
import sys

RESERVE = 12 * 1024 ** 3
REFERENCE = 'docker.io/headscale/headscale@sha256:2df4cb333db8496801780b8b15ac13026dbe5c0b5207fca4abdde33e1cffaa31'


def main():
    root = Path(sys.argv[1])
    assert root.parent == Path('/var/tmp') and root.name.startswith('woow-arm54-ha-20261122-')
    assert root.stat().st_mode & 0o777 == 0o700
    os.umask(0o077)
    env = dict(os.environ, HOME=str(root), XDG_CONFIG_HOME=str(root / 'config'),
               REGISTRY_AUTH_FILE=str(root / 'empty-auth.json'), TMPDIR=str(root / 'tmp'))
    base = ['podman', '--root', str(root / 'store'), '--runroot', str(root / 'run'),
            '--storage-driver', 'vfs', '--events-backend', 'file', '--tmpdir', str(root / 'tmp')]
    report = {'image_reference': REFERENCE, 'network': 'none', 'published_ports': [],
              'service_restore_acceptance': False, 'commands': []}

    def call(args, *, timeout=60, check=True):
        report['commands'].append(args)
        result = subprocess.run(base + args, capture_output=True, timeout=timeout, env=env)
        if check and result.returncode:
            report['failure_command'] = args[:2]
            report['failure_exit'] = result.returncode
            raise RuntimeError('isolated-podman-operation-failed')
        return result

    def reserve(extra=0):
        free = shutil.disk_usage(root).free
        report.setdefault('free_bytes_samples', []).append(free)
        assert free >= RESERVE + extra, 'reserve-refused'

    try:
        reserve(512 * 1024 ** 2)
        # Podman 6.1.1 cannot inspect a single OCI manifest via `manifest inspect`.
        # Fetch this public manifest directly, keeping its anonymous pull token
        # in memory and verifying the exact ARM descriptor digest before use.
        with urllib.request.urlopen('https://auth.docker.io/token?service=registry.docker.io&scope=repository:headscale/headscale:pull', timeout=20) as response:
            token = json.loads(response.read(64 * 1024))['token']
        request = urllib.request.Request(
            'https://registry-1.docker.io/v2/headscale/headscale/manifests/' + REFERENCE.split('@')[1],
            headers={'Authorization': 'Bearer ' + token,
                     'Accept': 'application/vnd.oci.image.manifest.v1+json'})
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(1024 * 1024 + 1)
        assert len(raw) <= 1024 * 1024, 'manifest-size-refused'
        assert 'sha256:' + hashlib.sha256(raw).hexdigest() == REFERENCE.split('@')[1], 'manifest-digest-refused'
        manifest = json.loads(raw)
        report['manifest_sha256_verified'] = True
        compressed = sum(layer['size'] for layer in manifest['layers']) + manifest['config']['size']
        report['compressed_image_bytes'] = compressed
        # Deliberately refuse large images instead of consuming a 4 GiB device's margin.
        assert compressed <= 128 * 1024 ** 2, 'image-size-refused'
        reserve(8 * compressed + 512 * 1024 ** 2)
        mem = next(int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()
                   if line.startswith('MemAvailable:'))
        report['mem_available_before'] = mem
        assert mem >= 1024 ** 3, 'memory-headroom-refused'
        if call(['image', 'exists', REFERENCE], check=False).returncode != 0:
            call(['pull', '--arch', 'arm64', '--authfile', str(root / 'empty-auth.json'), REFERENCE], timeout=180)
        reserve(256 * 1024 ** 2)
        info = json.loads(call(['image', 'inspect', REFERENCE]).stdout)[0]
        report['image'] = {key: info.get(key) for key in ('Id', 'Digest', 'Architecture', 'Os', 'Size', 'RepoDigests')}
        assert info['Architecture'] == 'arm64', 'image-architecture-refused'
        report['image_labels'] = {k: v for k, v in (info.get('Config', {}).get('Labels') or {}).items()
                                  if k in ('org.opencontainers.image.version', 'org.opencontainers.image.revision',
                                           'org.opencontainers.image.source')}
        assert info['Size'] <= 512 * 1024 ** 2, 'expanded-image-size-refused'
        name = root.name + '-version'
        run = ['run', '--name', name, '--pull=never', '--network=none', '--memory=256m',
               '--memory-swap=256m', '--pids-limit=128', '--cpus=0.5', '--read-only', '--cap-drop=ALL',
               '--security-opt=no-new-privileges', '--log-driver=none', info['Id'], 'version']
        output = call(run, timeout=45).stdout.decode().strip()
        assert output.splitlines()[0] == 'headscale version v0.29.4', 'unexpected-version-output'
        report['native_version'] = '0.29.4'
        report['binary_revision'] = '8106636c7f8d0cf8c9d4fb0beae94415069b768b' if 'commit: 8106636c7f8d0cf8c9d4fb0beae94415069b768b' in output else 'unknown'
        report['status'] = 'native-image-prepared'
    except Exception as exc:
        report['status'] = 'blocked'
        report['error_code'] = str(exc) if isinstance(exc, (AssertionError, RuntimeError)) else 'operation-failed'
    finally:
        # Only our container in our store; never use default storage for mutations.
        call(['rm', '-f', root.name + '-version'], check=False)
        remaining = json.loads(call(['ps', '-a', '--format', 'json']).stdout)
        report['isolated_containers_remaining'] = len(remaining)
        reserve()
        print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
