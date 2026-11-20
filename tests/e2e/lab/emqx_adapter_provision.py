"""Scoped dev-d synthetic resources. This file is intended to run inside dev-d only."""
import json
import os
import socket
import secrets

from emqx_adapter_fixture import Fixture
from woowbackup.podman import OwnerRunner


class Provision:
    def __init__(self, image_id):
        if os.geteuid() != 0 or socket.gethostname() != 'woowbk-dev-d':
            raise RuntimeError('must run as root inside dev-d')
        self.fixture = Fixture('woowbk-emqxlab-' + secrets.token_hex(4), 'appowner', image_id)
        self.runner = OwnerRunner('appowner')
        self.created = []

    def create(self, base, acl, bootstrap):
        """Create unique resources; record each immediately for fail-closed cleanup."""
        f, r = self.fixture, self.runner
        image = json.loads(r.podman('image', 'inspect', 'sha256:' + f.image_id).stdout)[0]
        if image.get('Id', '').removeprefix('sha256:') != f.image_id:
            raise RuntimeError('image id mismatch')
        labels = (image.get('Config') or {}).get('Labels') or {}
        if labels.get('org.opencontainers.image.version') != '5.8.9':
            raise RuntimeError('image version mismatch')
        config = '.config/' + f.prefix
        r.run(['/usr/bin/mkdir', '--', r.home + '/' + config])
        self.created.append(('config', config))
        for name, value in (('base.hocon', base), ('acl.conf', acl)):
            r.write_file(config + '/' + name, value, 0o644)
        for name in f.volumes:
            if r.podman('volume', 'exists', name, check=False).returncode != 1:
                raise RuntimeError('volume namespace collision or inspection failure')
            r.podman('volume', 'create', name)
            self.created.append(('volume', name))
        existing = r.podman('secret', 'ls', '--format', '{{.Name}}').stdout.decode().splitlines()
        if f.secret in existing:
            raise RuntimeError('secret namespace collision')
        r.podman('secret', 'create', f.secret, '-', input=bootstrap)
        self.created.append(('secret', f.secret))
        unit = '.config/containers/systemd/' + f.prefix + '.container'
        if r.stat_files([unit])[unit]['type'] != 'missing':
            raise RuntimeError('unit namespace collision')
        r.write_file(unit, f.container_unit().encode(), 0o600)
        self.created.append(('unit', unit))
        r.systemctl('daemon-reload')
        return f

    def cleanup(self):
        """Remove only tracked names from this fixture; any unconfirmed removal fails."""
        f, r = self.fixture, self.runner
        failures = []
        if any(kind == 'unit' for kind, _ in self.created):
            try:
                r.systemctl('stop', '--', f.unit)
                r.systemctl('unmask', '--', f.unit)
                status = r.podman('container', 'exists', f.prefix, check=False)
                if status.returncode == 0:
                    r.podman('rm', '--force', f.prefix)
                    status = r.podman('container', 'exists', f.prefix, check=False)
                if status.returncode != 1:
                    raise RuntimeError('container cleanup unconfirmed')
            except Exception:
                failures.append('container')
        for kind, name in reversed(self.created):
            try:
                if kind == 'unit':
                    r.remove_file(name)
                elif kind == 'volume':
                    r.podman('volume', 'rm', name)
                    if r.podman('volume', 'exists', name, check=False).returncode != 1:
                        raise RuntimeError('volume still exists')
                elif kind == 'secret':
                    r.podman('secret', 'rm', name)
                    remaining = r.podman('secret', 'ls', '--format', '{{.Name}}').stdout.decode().splitlines()
                    if name in remaining:
                        raise RuntimeError('secret still exists')
                elif kind == 'config':
                    for leaf in ('base.hocon', 'acl.conf'):
                        r.remove_file(name + '/' + leaf)
                    r.run(['/usr/bin/rmdir', '--', r.home + '/' + name])
            except Exception:
                failures.append(kind)
        try:
            if any(kind == 'unit' for kind, _ in self.created):
                r.systemctl('reset-failed', f.unit, check=False)
            r.systemctl('daemon-reload')
        except Exception:
            failures.append('daemon-reload-or-reset')
        if failures:
            raise RuntimeError('synthetic cleanup incomplete: ' + ','.join(failures))
