"""Run as root inside dev-d against synthetic volumes only; invoke the unmodified product converter."""
import gzip
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace

sys.path.insert(0, sys.argv[1])
from woowbackup import habackup, ha_headscale, nested, tempctr  # noqa: E402

root = Path(sys.argv[2])
source_volume, target_volume, plane_volume = sys.argv[3:6]
image = 'localhost/woow-headscale:0.29.4-r1'
slug = '1b7b4ce7_woow-headscale'
prefix = ['runuser', '-u', 'appowner', '--', 'env', 'XDG_RUNTIME_DIR=/run/user/1019',
          'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1019/bus', 'podman']

class Runner:
    home = str(root)
    uid = 1019

    def podman(self, *args, **kwargs):
        incoming = kwargs.get('input')
        stream = hasattr(incoming, 'read')
        with tempfile.TemporaryFile() as capture:
            os.fchown(capture.fileno(), 1019, 1019)
            result = subprocess.run(prefix + list(args), stdin=incoming if stream else None,
                                    input=None if stream else incoming, stdout=capture,
                                    stderr=subprocess.PIPE, timeout=kwargs.get('timeout', 120))
            capture.seek(0)
            if kwargs.get('stdout') is not None:
                import shutil
                shutil.copyfileobj(capture, kwargs['stdout'])
                result.stdout = None
            else:
                result.stdout = capture.read()
        if result.returncode and kwargs.get('check', True):
            raise RuntimeError('podman failed: ' + ' '.join(args[:3]) + ': ' + result.stderr.decode(errors='replace')[-500:])
        return result

    def relay(self, args, **kwargs):
        return self.podman(*args, **kwargs)

    def read_file(self, path, max_bytes):
        data = (root / path).read_bytes()
        assert len(data) <= max_bytes
        return data

class Guard:
    def budget(self): return 256 * 1024 * 1024
    def wrote(self, size): pass

runner = Runner()
tmp = tempctr.TempObjects(runner, 'j20261120T100000Z-' + os.urandom(4).hex(), memory='768m', pids=512, cpus='1')
raw = runner.podman('volume', 'export', source_volume).stdout

def add(archive, name, data):
    info = tarfile.TarInfo(name)
    info.mode, info.size = 0o600, len(data)
    archive.addfile(info, io.BytesIO(data))

inner = io.BytesIO()
with tarfile.open(fileobj=inner, mode='w') as out, tarfile.open(fileobj=io.BytesIO(raw)) as source:
    add(out, 'addon.json', json.dumps({'user': {'version': '0.1.3'}, 'system': {'slug': 'woow-headscale'},
                                       'version': '0.1.3', 'state': 'stopped'}).encode())
    for member in source:
        name = member.name.removeprefix('./')
        if name in ('db.sqlite', 'db.sqlite-wal', 'noise.key') and member.isfile():
            add(out, 'data/' + ('noise_private.key' if name == 'noise.key' else name), source.extractfile(member).read())
    add(out, 'config/config.yaml', (root / 'config/config.yaml').read_bytes())
    add(out, 'config/dns_records.json', b'[]')
doc = {'slug': 'c0ffee00', 'version': 2, 'name': 'synthetic-headscale', 'date': '2026-11-20T10:00:00+00:00',
       'type': 'partial', 'supervisor_version': '2026.11.0', 'compressed': True, 'protected': False,
       'homeassistant': None, 'folders': [], 'repositories': [],
       'addons': [{'slug': slug, 'name': 'Synthetic Headscale', 'version': '0.1.3', 'size': 0.0}]}
backup = root / 'synthetic-ha.tar'
with tarfile.open(backup, 'w') as archive:
    add(archive, slug + '.tar.gz', gzip.compress(inner.getvalue()))
    add(archive, 'backup.json', json.dumps(doc).encode())

quadlets = {
    'headscale.container': (f'[Container]\nContainerName=headscale\nImage={image}\n'
        f'Volume={target_volume}.volume:/var/lib/headscale\nVolume=%h/config:/etc/headscale:ro\n').encode(),
    'headplane.container': (f'[Container]\nContainerName=headplane\nVolume={plane_volume}.volume:/var/lib/headplane\n').encode(),
    target_volume + '.volume': f'[Volume]\nVolumeName={target_volume}\n'.encode(),
    plane_volume + '.volume': f'[Volume]\nVolumeName={plane_volume}\n'.encode(),
}
app = SimpleNamespace(id='headscale', name='Synthetic Headscale', volumes=[{'name': target_volume}, {'name': plane_volume}],
                      postgres=[], data_dirs=[])
uid_map = nested.IdMap(runner.podman('unshare', 'cat', '/proc/self/uid_map').stdout.decode())
gid_map = nested.IdMap(runner.podman('unshare', 'cat', '/proc/self/gid_map').stdout.decode())
staging = root / 'engine-staging'
staging.mkdir(mode=0o700)
out = root / 'converted-output'
out.mkdir(mode=0o700)

with habackup.open_backup(backup) as opened:
    work = SimpleNamespace(quadlets=lambda _app: quadlets, runner=lambda _app: runner,
        adapter=lambda _app: SimpleNamespace(owner_ids=lambda: (uid_map, gid_map)), temp=lambda _app: tmp,
        addon_member=lambda _slug: slug, open=lambda member: opened.open_addon(member),
        addon_info=lambda _slug: SimpleNamespace(version='0.1.3'), staging=staging, guard=Guard(), abort=None,
        checkpoint=lambda: None, phase=lambda p: print('product phase:', p, flush=True),
        log=lambda message: print('product:', message, flush=True))
    try:
        result = ha_headscale.convert(work, app, False, out)
        assert result['nodes'] == 2 and result['api_keys_kept'] == 1 and result['api_keys_removed'] == 1, result
        with tarfile.open(fileobj=io.BytesIO(raw)) as source, tarfile.open(result['volumes'][target_volume]) as converted:
            source_key = next(source.extractfile(m).read().strip() for m in source
                              if m.name.removeprefix('./') == 'noise.key' and m.isfile())
            target_key = next(converted.extractfile(m).read().strip() for m in converted
                              if m.name.removeprefix('./') == 'noise.key' and m.isfile())
            assert source_key == target_key, 'Noise identity differs'
        print('source Noise key matches converted volume: PASS', flush=True)
        print('product convert: PASS nodes=2 source_keys_removed=1 target_keys_kept=1', flush=True)
        print('converted tar:', result['volumes'][target_volume], flush=True)
    finally:
        remaining = tmp.cleanup()
        if remaining:
            raise RuntimeError('product temporary resources not cleaned')
