"""The restore applies a volume tar's top-directory entry itself (Podman 6.1.1 ignores it on `volume import` and no
longer chowns the imported volume at the first mount; probe n8n-volume-probe on an ARM64 test machine, 2026-11-23)."""
import io
import tarfile
import tempfile
import time
import types
import unittest
from pathlib import Path

from woowbackup import nested, podman
from woowbackup.adapters import quadlet_postgres as qp
from woowbackup.errors import BackupError

IDS = '         0       1013          1\n         1     100000      65536\n'
MOUNT = '/home/appowner/.local/share/containers/storage/volumes/n8n_n8n_data/_data'


def volume_tar(path, *, root=(1000, 1000, 0o755), first_file=False):
    with tarfile.open(path, 'w', format=tarfile.PAX_FORMAT) as tar:
        def add_file():
            data = b'{"encryptionKey": "test-only"}'
            info = tarfile.TarInfo('config')
            info.size, info.mode, info.uid, info.gid, info.mtime = len(data), 0o600, 1000, 1000, int(time.time())
            tar.addfile(info, io.BytesIO(data))
        if first_file:
            add_file()
        if root is not None:
            info = tarfile.TarInfo('.')
            info.type, info.uid, info.gid, info.mode, info.mtime = tarfile.DIRTYPE, root[0], root[1], root[2], 1
            tar.addfile(info)
        if not first_file:
            add_file()


class Runner:
    def __init__(self, mount=MOUNT, existing=None):
        self.argvs = []
        self.mount = mount
        self.existing = existing   # (uid, gid, mode) of the volume being replaced; None = no such volume

    def podman(self, *args, input=None, stdout=None, timeout=None, max_output=None, check=True, abort=None):
        args = [str(a) for a in args]
        self.argvs.append(args)
        if args[:2] == ['unshare', 'cat']:
            return podman.Result(0, IDS.encode(), b'')
        if args[:2] == ['volume', 'import']:
            if hasattr(input, 'read'):
                input.read()
            return podman.Result(0, b'', b'')
        if args[:2] == ['volume', 'inspect']:
            return podman.Result(0, (self.mount + '\n').encode(), b'')
        if args[:2] == ['volume', 'exists']:
            return podman.Result(0 if self.existing else 1, b'', b'')
        if args[:2] == ['unshare', 'stat']:
            uid, gid, mode = self.existing
            return podman.Result(0, f'{uid} {gid} {mode:o}\n'.encode(), b'')
        if args[:2] == ['volume', 'create']:
            self.existing = None
        return podman.Result(0, b'', b'')


def adapter(runner):
    app = types.SimpleNamespace(id='n8n', name='n8n', volumes=[{'name': 'n8n_n8n_data'}], postgres=[], data_dirs=[],
                                secrets=[], config_files=[], units=[], health=[])
    return qp.QuadletPostgresAdapter(app, runner, lambda line: None)


class VolumeRootTest(unittest.TestCase):
    def test_root_entry_is_read_and_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'v.tar'
            volume_tar(path)
            ids = nested.IdMap(IDS), nested.IdMap(IDS)
            self.assertEqual(nested.volume_root(path, ids), (1000, 1000, 0o755))
            volume_tar(path, root=None)
            self.assertIsNone(nested.volume_root(path, ids))
            volume_tar(path, first_file=True)   # only a leading root entry counts
            self.assertIsNone(nested.volume_root(path, ids))
            volume_tar(path, root=(70000, 1000, 0o755))   # owner outside the owner's user namespace
            with self.assertRaises(BackupError):
                nested.volume_root(path, ids)

    def test_recreate_applies_the_root_entry_after_the_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'v.tar'
            volume_tar(path, root=(1000, 1000, 0o750))
            runner = Runner()
            adapter(runner)._recreate_volume('n8n_n8n_data', path)
        tail = [a for a in runner.argvs if a[:2] != ['unshare', 'cat']]
        self.assertEqual(tail, [
            ['volume', 'exists', 'n8n_n8n_data'],
            ['volume', 'rm', '-f', 'n8n_n8n_data'], ['volume', 'create', 'n8n_n8n_data'],
            ['volume', 'import', 'n8n_n8n_data', '-'],
            ['volume', 'inspect', '--format', '{{.Mountpoint}}', 'n8n_n8n_data'],
            ['unshare', 'chown', '--no-dereference', '1000:1000', '--', MOUNT],
            ['unshare', 'chmod', '0750', '--', MOUNT]])

    def test_tar_without_root_entry_and_no_volume_leaves_the_directory_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'v.tar'
            volume_tar(path, root=None)
            runner = Runner()
            adapter(runner)._recreate_volume('n8n_n8n_data', path)
        self.assertFalse([a for a in runner.argvs if a[:2] in (['unshare', 'chown'], ['unshare', 'chmod'])])

    def test_export_without_root_entry_keeps_the_replaced_volumes_top_directory(self):
        """`podman volume export` (6.1.1) writes no '.' entry: a rollback or ordinary restore keeps the owner and mode
        the replaced volume had (n8n's node-owned folder), read before the volume is removed."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'v.tar'
            volume_tar(path, root=None)
            runner = Runner(existing=(1000, 1000, 0o700))
            adapter(runner)._recreate_volume('n8n_n8n_data', path)
        tail = [a for a in runner.argvs if a[:2] != ['unshare', 'cat']]
        self.assertEqual(tail, [
            ['volume', 'exists', 'n8n_n8n_data'], ['volume', 'inspect', '--format', '{{.Mountpoint}}', 'n8n_n8n_data'],
            ['unshare', 'stat', '-c', '%u %g %a', '--', MOUNT],
            ['volume', 'rm', '-f', 'n8n_n8n_data'], ['volume', 'create', 'n8n_n8n_data'],
            ['volume', 'import', 'n8n_n8n_data', '-'],
            ['volume', 'inspect', '--format', '{{.Mountpoint}}', 'n8n_n8n_data'],
            ['unshare', 'chown', '--no-dereference', '1000:1000', '--', MOUNT],
            ['unshare', 'chmod', '0700', '--', MOUNT]])

    def test_archive_entry_wins_over_the_replaced_volume(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'v.tar'
            volume_tar(path, root=(1000, 1000, 0o755))
            runner = Runner(existing=(0, 0, 0o755))
            adapter(runner)._recreate_volume('n8n_n8n_data', path)
        self.assertIn(['unshare', 'chown', '--no-dereference', '1000:1000', '--', MOUNT], runner.argvs)

    def test_unusable_mountpoint_stops_the_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'v.tar'
            volume_tar(path)
            runner = Runner(mount='relative/path')
            with self.assertRaises(BackupError):
                adapter(runner)._recreate_volume('n8n_n8n_data', path)
        self.assertFalse([a for a in runner.argvs if a[:2] == ['unshare', 'chown']])


if __name__ == '__main__':
    unittest.main()
