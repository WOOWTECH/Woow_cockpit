"""Offline fixture specification for an isolated EMQX adapter rollback test.

This module does not create users, units, volumes or containers. The eventual lab
driver must verify the actual runtime objects before invoking any product flow.
"""
from dataclasses import dataclass
import re

IMAGE_ID_PREFIX = '3f60addfad2b'
EMQX_VERSION = '5.8.9'
NAMESPACE = re.compile(r'woowbk-emqxlab-[0-9a-f]{8}\Z')


@dataclass(frozen=True)
class Fixture:
    prefix: str
    owner: str
    image_id: str

    def __post_init__(self):
        if not NAMESPACE.fullmatch(self.prefix):
            raise ValueError('invalid synthetic namespace')
        if self.owner != self.prefix:
            raise ValueError('the synthetic owner must match the namespace')
        if not re.fullmatch(r'3f60addfad2b[0-9a-f]{52}', self.image_id):
            raise ValueError('a full pinned EMQX image id is required')

    @property
    def unit(self):
        return self.prefix + '.service'

    @property
    def volumes(self):
        return (self.prefix + '-data', self.prefix + '-log')

    @property
    def secret(self):
        return self.prefix + '-bootstrap'

    def catalog(self):
        return {'schema': 1, 'id': self.prefix, 'name': 'Synthetic EMQX adapter test',
                'owner': self.owner, 'adapter': 'quadlet-postgres',
                'quadlet': {'files': [self.prefix + '.container']},
                'units': [self.unit], 'writer_units': [self.unit],
                'volumes': [{'name': name, 'label': 'synthetic'} for name in self.volumes],
                'secrets': [{'name': self.secret}],
                'config_files': [{'path': '.config/' + self.prefix + '/base.hocon', 'mode': '0600'},
                                 {'path': '.config/' + self.prefix + '/acl.conf', 'mode': '0600'}]}

    def container_unit(self):
        data, log = self.volumes
        config = '%h/.config/' + self.prefix
        return ('[Unit]\nDescription=Synthetic EMQX adapter rollback test\n'
                '[Container]\nImage=sha256:' + self.image_id + '\nContainerName=' + self.prefix + '\n'
                'Network=none\nPull=never\n'
                'Environment=EMQX_NODE__NAME=emqx@127.0.0.1\n'
                'Secret=' + self.secret + ',type=mount,target=/opt/emqx/etc/lab-bootstrap.csv,uid=1000,gid=1000,mode=0400\n'
                'Volume=' + data + ':/opt/emqx/data\nVolume=' + log + ':/opt/emqx/log\n'
                'Volume=' + config + '/base.hocon:/opt/emqx/etc/base.hocon:ro\n'
                'Volume=' + config + '/acl.conf:/opt/emqx/etc/lab-acl.conf:ro\n'
                'PodmanArgs=--memory=768m --cpus=1 --pids-limit=512\n'
                '[Service]\nRestart=no\n')

    def validate_inspection(self, inspection):
        """Fail closed on unexpected namespace, network, ports, volumes or resource limits."""
        if not isinstance(inspection, dict) or inspection.get('Name', '').lstrip('/') != self.prefix:
            raise ValueError('unexpected container')
        if inspection.get('Image', '').removeprefix('sha256:') != self.image_id:
            raise ValueError('unexpected image')
        host = inspection.get('HostConfig') or {}
        if host.get('NetworkMode') != 'none' or host.get('PortBindings'):
            raise ValueError('container is not isolated')
        if host.get('Memory') != 768 * 1024 * 1024 or host.get('NanoCpus') != 1_000_000_000:
            raise ValueError('container resource limits differ')
        mounts = inspection.get('Mounts') or []
        volumes = {m.get('Name') for m in mounts if m.get('Type') == 'volume'}
        if volumes != set(self.volumes):
            raise ValueError('unexpected mounted volumes')

