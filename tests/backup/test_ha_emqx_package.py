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


class CountReadTests(unittest.TestCase):
    def test_unstable_retainer_observation_refused(self):
        with self.assertRaises(BackupError):
            ha_emqx.parse_counts('{emqx_retainer_message,-2}')

    def test_absent_optional_table_not_confused_with_unstable(self):
        self.assertEqual(ha_emqx.parse_counts('{emqx_psk,-1}'), {'emqx_psk': -1})

    def test_ticker_pause_refuses_non_job_role(self):
        with self.assertRaises(BackupError):
            ha_emqx.quiesce_system_ticker(None, 'production')

    def test_ticker_pause_missing_ack_is_no_reason_to_stop(self):
        """E-13: a ticker that cannot be paused is told apart (None): the import goes on and says it."""
        tmp = SimpleNamespace(exec=lambda *args, **kwargs: SimpleNamespace(stdout=b'ok'))
        self.assertIsNone(ha_emqx.quiesce_system_ticker(tmp, 'emqx-new'))

        def broken(*args, **kwargs):
            raise BackupError('job-failed', 'x')
        self.assertIsNone(ha_emqx.quiesce_system_ticker(SimpleNamespace(exec=broken), 'emqx-new'))
        cancelled = BackupError('busy', 'x')

        def busy(*args, **kwargs):
            raise cancelled
        with self.assertRaises(BackupError):   # the job's own end is never swallowed
            ha_emqx.quiesce_system_ticker(SimpleNamespace(exec=busy), 'emqx-new')

    def test_a_paused_ticker_is_checked_again_and_a_changed_one_is_only_said(self):
        good = SimpleNamespace(exec=lambda *a, **k: SimpleNamespace(stdout=b'ticker_unchanged'))
        changed = SimpleNamespace(exec=lambda *a, **k: SimpleNamespace(stdout=b'{badmatch,x}'))
        self.assertTrue(ha_emqx.assert_system_ticker(good, 'emqx-ha', '<0.1.0>'))
        self.assertFalse(ha_emqx.assert_system_ticker(changed, 'emqx-ha', '<0.1.0>'))
        self.assertFalse(ha_emqx.assert_system_ticker(good, 'emqx-ha', None), 'nothing was paused')
        for role, pid in (('production', '<0.1.0>'), ('emqx-ha', 'not a pid')):
            with self.assertRaises(BackupError):
                ha_emqx.assert_system_ticker(good, role, pid)

    def test_the_retained_messages_may_differ_by_a_few_rows_only_when_the_ticker_ran(self):
        ha, seeded = {'emqx_retainer_message': 5, 'emqx_acl': 2}, {'emqx_retainer_message': 0, 'emqx_acl': 0}
        counts = {'emqx_retainer_message': 5 + ha_emqx.SYS_SLACK, 'emqx_acl': 2}
        self.assertTrue(ha_emqx.check_counts(ha, seeded, counts), 'exact when both tickers were paused')
        self.assertEqual(ha_emqx.check_counts(ha, seeded, counts, loose=('emqx_retainer_message',)), [])
        too_many = dict(counts, emqx_retainer_message=5 + ha_emqx.SYS_SLACK + 1)
        self.assertTrue(ha_emqx.check_counts(ha, seeded, too_many, loose=('emqx_retainer_message',)))
        lost_rows = dict(counts, emqx_acl=1)   # the slack is for retained messages only, never for an account or a rule
        self.assertTrue(ha_emqx.check_counts(ha, seeded, lost_rows, loose=('emqx_retainer_message', 'emqx_acl')))
        fewer = dict(counts, emqx_retainer_message=4)
        self.assertTrue(ha_emqx.check_counts(ha, seeded, fewer, loose=('emqx_retainer_message',)))
