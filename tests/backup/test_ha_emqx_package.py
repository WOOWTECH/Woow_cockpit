"""Output packaging boundary with fixture volume transport, not broker acceptance."""
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from woowbackup import ha_emqx, nested
from woowbackup.errors import BackupError


class PackageTests(unittest.TestCase):
    def run_package(self, stop_code=0, uid=1000):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        export = self.root / 'export.tar'
        export.write_bytes(b'fixture')
        self.events = []
        events = self.events
        class Transport:
            def stop(self, role, **kwargs):
                events.append('stop')
                return stop_code
            def remove(self, role):
                events.append('remove')
            def volume_export(self, role, handle, **kwargs):
                events.append('export')
                with tarfile.open(fileobj=handle, mode='w') as archive:
                    for name, body in (('.', None), ('configs', None),
                                       ('configs/cluster.hocon', b'custom-target'),
                                       ('configs/app.1.config', b'generated')):
                        info = tarfile.TarInfo(name)
                        info.uid = info.gid = uid
                        info.mode = 0o700 if body is None else 0o600
                        if body is None:
                            info.type = tarfile.DIRTYPE
                        else:
                            info.size = len(body)
                        archive.addfile(info, None if body is None else io.BytesIO(body))
            def remove_volume(self, role):
                events.append('clean:' + role)
        guard = SimpleNamespace(budget=lambda: 1024*1024, wrote=lambda size: None)
        return ha_emqx._package_candidate(SimpleNamespace(guard=guard), Transport(),
            SimpleNamespace(data_volume='fixture-data', log_volume='fixture-log'),
            self.root, self.root / 'out', export,
            ids=(nested.IdMap('0 100000 65536'), nested.IdMap('0 100000 65536')),
            log_root=(1000, 1000, 0o700))

    def test_packages_private_validated_volumes_and_filters_generated_files(self):
        paths = self.run_package()
        self.assertEqual(set(paths), {'fixture-data', 'fixture-log'})
        for path in paths.values():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with tarfile.open(paths['fixture-data']) as archive:
            self.assertEqual(archive.extractfile('configs/cluster.hocon').read(), b'custom-target')
            self.assertNotIn('configs/app.1.config', archive.getnames())
        with tarfile.open(paths['fixture-log']) as archive:
            self.assertEqual(len(archive.getmembers()), 1)
            root = archive.getmembers()[0]
            self.assertEqual((root.uid, root.gid, root.mode), (1000, 1000, 0o700))
        self.assertIn('clean:emqx-new', self.events)

    def test_failed_stop_does_not_export_or_remove_candidate(self):
        with self.assertRaises(BackupError):
            self.run_package(stop_code=137)
        self.assertEqual(self.events, ['stop'])

    def test_unmappable_owner_is_rejected_before_volume_cleanup(self):
        with self.assertRaises(BackupError):
            self.run_package(uid=999999)
        self.assertIn('export', self.events)
        self.assertFalse(any(e.startswith('clean:') for e in self.events))
