"""Local storage, index sidecars, staging, uploads and download containment (team E1).

Uploads are validated by their outer header only (no key needed), so these tests run without age.
"""
import datetime
import hashlib
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ENGINE = Path(__file__).resolve().parents[2] / 'backup-engine'
if str(ENGINE) not in sys.path:
    sys.path.insert(0, str(ENGINE))

from woowbackup.errors import BackupError  # noqa: E402
from woowbackup.paths import Paths  # noqa: E402
from woowbackup.storage import Storage  # noqa: E402

try:
    from .test_archive import fake_archive_bytes
except ImportError:  # executed as a top-level module
    from test_archive import fake_archive_bytes

GIB = 1024 ** 3


def mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def meta(**fields):
    base = {'type': 'manual', 'created': '2026-11-13T02:00:00Z', 'note': '', 'apps': [{'id': 'woowbk-demo',
            'name': '示範筆記應用'}], 'sha256': 'a' * 64, 'key_id': 'ABCD-EF01-2345-6789',
            'include_images': True, 'source': {'hostname': 'dev-a'}, 'verified': None, 'inspected': False}
    base.update(fields)
    return base


class StorageTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='woowbk-e1-storage-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.paths = Paths(base=self.base)
        self.free = 100 * GIB
        self.storage = Storage(self.paths, free_space=lambda path: self.free)
        self.storage.ensure_layout()

    def put_archive(self, backup_id, data=b'archive-bytes', **fields):
        path = self.storage.archive_path(backup_id)
        path.write_bytes(data)
        return self.storage.register(backup_id, meta(**fields))


class LayoutTests(StorageTestCase):
    def test_layout_modes(self):
        for path in (self.paths.data, self.paths.archives, self.paths.uploads, self.paths.staging, self.paths.jobs,
                     self.paths.run):
            self.assertTrue(path.is_dir(), path)
            self.assertEqual(mode(path), 0o700, path)
        os.chmod(self.paths.archives, 0o755)
        self.storage.ensure_layout()
        self.assertEqual(mode(self.paths.archives), 0o700, 'loose mode tightened')

    def test_layout_refuses_symlinked_dirs(self):
        elsewhere = self.base / 'elsewhere'
        elsewhere.mkdir()
        os.chmod(elsewhere, 0o755)
        os.rmdir(self.paths.uploads)
        os.symlink(elsewhere, self.paths.uploads)
        with self.assertRaises(BackupError) as ctx:
            self.storage.ensure_layout()
        self.assertEqual(ctx.exception.code, 'internal-error')
        self.assertEqual(mode(elsewhere), 0o755, 'symlink target never chmod-ed')
        with self.assertRaises(BackupError):
            self.storage.begin_upload('x.woowbackup', 100)
        self.assertEqual(os.listdir(elsewhere), [], 'nothing written through the symlink')

    def test_ids(self):
        fixed = datetime.datetime(2026, 11, 13, 10, 0, 0, tzinfo=datetime.timezone(datetime.timedelta(hours=8)))
        backup_id = self.storage.new_backup_id(fixed)
        self.assertRegex(backup_id, r'^20261113T020000Z-[0-9a-f]{8}$')
        self.assertRegex(self.storage.new_backup_id(), r'^\d{8}T\d{6}Z-[0-9a-f]{8}$')
        self.assertNotEqual(self.storage.new_backup_id(fixed), self.storage.new_backup_id(fixed))
        self.assertEqual(self.storage.archive_path(backup_id), self.paths.archives / f'{backup_id}.woowbackup')
        for bad in ('../../etc/passwd', '20261113T020000Z-a1b2c3d4/../x', '20261113T020000Z-A1B2C3D4', '', None,
                    'j20261113T020000Z-a1b2c3d4', '20261113T020000Z-a1b2c3d4\n', '２０２６１１１３T020000Z-a1b2c3d4'):
            with self.subTest(bad=bad):
                with self.assertRaises(BackupError) as ctx:
                    self.storage.archive_path(bad)
                self.assertEqual(ctx.exception.code, 'invalid-request')

    def test_free_space(self):
        self.assertEqual(self.storage.free_bytes(), 100 * GIB)
        real = Storage(self.paths)
        self.assertGreater(real.free_bytes(), 0)
        self.assertGreater(real.total_bytes(), 0)
        usage = self.storage.usage()
        self.assertEqual(set(usage), {'path', 'free_bytes', 'total_bytes', 'backups_bytes', 'backup_count'})
        self.assertEqual(usage['backup_count'], 0)


class IndexTests(StorageTestCase):
    def test_register_get_list_update_delete(self):
        older = self.put_archive('20261112T010000Z-00000001', created='2026-11-12T01:00:00Z', type='safety')
        newer = self.put_archive('20261113T020000Z-00000002', data=b'x' * 1000, key_available=True)
        uploaded = self.put_archive('20261110T000000Z-00000003', created=None, type='uploaded',
                                    uploaded_at='2026-11-13T05:00:00Z', source=None)
        self.assertNotIn('key_available', newer)
        self.assertEqual(newer['size'], 1000)
        self.assertEqual(newer['filename'], 'woowtech-backup-dev-a-20261113-020000.woowbackup')
        self.assertEqual(mode(self.storage.index_path(newer['id'])), 0o600)
        self.assertEqual([r['id'] for r in self.storage.list_backups()],
                         [newer['id'], older['id'], uploaded['id']], 'newest first')
        self.assertEqual(self.storage.get(newer['id']), newer)
        updated = self.storage.update(newer['id'], verified={'at': '2026-11-13T03:00:00Z', 'ok': True},
                                      inspected=True, source={'hostname': 'dev-b', 'arch': 'x86_64'})
        self.assertEqual(updated['verified'], {'at': '2026-11-13T03:00:00Z', 'ok': True})
        self.assertEqual(updated['source'], {'hostname': 'dev-b'})
        self.assertEqual(self.storage.get(newer['id']), updated)
        for bad in ({'id': 'x'}, {'key_available': True}, {'bogus': 1}, {'type': 'weekly'}, {'size': -1}):
            with self.subTest(bad=bad):
                with self.assertRaises(BackupError):
                    self.storage.update(newer['id'], **bad)
        usage = self.storage.usage()
        self.assertEqual((usage['backup_count'], usage['backups_bytes']), (3, 1000 + 2 * len(b'archive-bytes')))
        self.storage.delete(older['id'])
        self.assertFalse(self.storage.archive_path(older['id']).exists())
        self.assertFalse(self.storage.index_path(older['id']).exists())
        with self.assertRaises(BackupError) as ctx:
            self.storage.delete(older['id'])
        self.assertEqual(ctx.exception.code, 'not-found')
        with self.assertRaises(BackupError) as ctx:
            self.storage.get(older['id'])
        self.assertEqual(ctx.exception.code, 'not-found')

    def test_register_validation(self):
        with self.assertRaises(BackupError) as ctx:
            self.storage.register('20261113T020000Z-0000000a', meta())
        self.assertEqual(ctx.exception.code, 'not-found', 'archive must already be in place')
        self.storage.archive_path('20261113T020000Z-0000000a').write_bytes(b'data')
        for bad in (meta(unknown=1), meta(type='weekly'), meta(key_id='abc'), meta(apps=[{'id': 'a'}]),
                    meta(id='20261113T020000Z-0000000b'), meta(created='yesterday'), meta(filename='../x')):
            with self.subTest(bad=bad):
                with self.assertRaises(BackupError):
                    self.storage.register('20261113T020000Z-0000000a', bad)
        rec = self.storage.register('20261113T020000Z-0000000a', {'type': 'manual', 'key_id': 'ABCD-EF01-2345-6789',
                                                                  'created': '2026-11-13T02:00:00Z'})
        self.assertEqual(rec['sha256'], hashlib.sha256(b'data').hexdigest(), 'computed when not supplied')
        self.assertEqual((rec['note'], rec['apps'], rec['verified'], rec['inspected']), ('', [], None, False))

    def test_malformed_sidecars_are_ignored(self):
        good = self.put_archive('20261113T020000Z-00000001')
        archives = self.paths.archives
        cases = {
            '20261113T020000Z-00000002': b'{not json',
            '20261113T020000Z-00000003': json.dumps(dict(good, id='20261113T020000Z-00000003', extra=1)).encode(),
            '20261113T020000Z-00000004': json.dumps(dict(good, id='20261113T020000Z-00000004', size='1')).encode(),
            '20261113T020000Z-00000005': json.dumps(dict(good, id='20261113T020000Z-99999999')).encode(),
            '20261113T020000Z-00000006': json.dumps(dict(good, id='20261113T020000Z-00000006',
                                                         note='x' * 300_000)).encode(),
            '20261113T020000Z-00000007': b'{"id": "20261113T020000Z-00000007", "id": "dup"}',
        }
        for backup_id, data in cases.items():
            (archives / f'{backup_id}.woowbackup').write_bytes(b'a')
            (archives / f'{backup_id}.json').write_bytes(data)
        # Sidecar symlinked to a valid record elsewhere, and a sidecar whose archive is missing.
        (archives / '20261113T020000Z-00000008.woowbackup').write_bytes(b'a')
        outside = self.base / 'outside.json'
        outside.write_text(json.dumps(dict(good, id='20261113T020000Z-00000008')))
        (archives / '20261113T020000Z-00000008.json').symlink_to(outside)
        (archives / '20261113T020000Z-00000009.json').write_text(json.dumps(dict(good, id='20261113T020000Z-00000009')))
        # Archive replaced by a symlink.
        (archives / '20261113T020000Z-0000000a.json').write_text(json.dumps(dict(good, id='20261113T020000Z-0000000a')))
        (archives / '20261113T020000Z-0000000a.woowbackup').symlink_to(outside)
        (archives / 'notes.json').write_text('{}')
        self.assertEqual([r['id'] for r in self.storage.list_backups()], [good['id']])
        for backup_id in list(cases) + ['20261113T020000Z-00000008', '20261113T020000Z-00000009',
                                        '20261113T020000Z-0000000a']:
            with self.assertRaises(BackupError):
                self.storage.get(backup_id)


class IndexRaceTests(StorageTestCase):
    """Sidecar read-modify-writes from two processes (job-record race audit, release regression 16)."""

    def race_after_read(self, other_step):
        """self.storage reads the sidecar; `other_step` (another process) runs right then, in a thread."""
        original_get = Storage.get
        seen = {}

        def get(storage, backup_id):
            rec = original_get(storage, backup_id)
            if storage is self.storage and 'thread' not in seen:
                seen['thread'] = threading.Thread(target=other_step)
                seen['thread'].start()
                seen['thread'].join(0.5)  # blocked by the index lock (fixed) or already done (lost update)
            return rec

        return mock.patch.object(Storage, 'get', get), seen

    def test_inspect_does_not_revert_the_result_a_verify_job_just_recorded(self):
        backup_id = self.put_archive('20261113T020000Z-00000001', verified={'at': '2026-11-12T00:00:00Z', 'ok': True})['id']
        job = Storage(self.paths, free_space=lambda path: self.free)  # the verify job's process
        failed = {'at': '2026-11-13T03:00:00Z', 'ok': False}
        patch, seen = self.race_after_read(lambda: job.update(backup_id, verified=failed))
        with patch:
            self.storage.update(backup_id, inspected=True, note='已檢查')  # what inspect records
        seen['thread'].join(10)
        final = self.storage.get(backup_id)
        self.assertEqual(final['verified'], failed, 'a failed verification must never be masked')
        self.assertEqual((final['inspected'], final['note']), (True, '已檢查'))

    def test_update_never_brings_back_a_deleted_backups_sidecar(self):
        backup_id = self.put_archive('20261113T020000Z-00000001')['id']
        other = Storage(self.paths, free_space=lambda path: self.free)
        patch, seen = self.race_after_read(lambda: other.delete(backup_id))
        with patch:
            self.storage.update(backup_id, inspected=True)
        seen['thread'].join(10)
        self.assertFalse(self.storage.index_path(backup_id).exists())
        self.assertFalse(self.storage.archive_path(backup_id).exists())
        self.assertEqual(sorted(p.name for p in Path(self.paths.archives).iterdir()), [],
                         'archives/ holds archives and sidecars only (the lock lives in the run directory)')


class StagingTests(StorageTestCase):
    def test_staging_dir(self):
        path = self.storage.staging_dir('j20261113T020000Z-a1b2c3d4')
        self.assertEqual(path, self.paths.staging / 'j20261113T020000Z-a1b2c3d4')
        self.assertEqual(mode(path), 0o700)
        self.assertEqual(os.listdir(path), [])
        (path / 'plain.dump').write_bytes(b'secret')
        (path / 'sub').mkdir()
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'keep').write_text('keep')
        (path / 'sub' / 'link').symlink_to(outside)
        again = self.storage.staging_dir('j20261113T020000Z-a1b2c3d4')
        self.assertEqual(os.listdir(again), [], 'recreated empty')
        self.assertEqual((outside / 'keep').read_text(), 'keep', 'symlink inside staging not followed')
        (again / 'x').write_text('x')
        self.storage.remove_staging('j20261113T020000Z-a1b2c3d4')
        self.assertFalse(again.exists())
        self.storage.remove_staging('j20261113T020000Z-a1b2c3d4')  # idempotent
        for bad in ('../escape', 'a/b', '.hidden', '', 'x' * 120, None, '..'):
            with self.subTest(bad=bad):
                with self.assertRaises(BackupError) as ctx:
                    self.storage.staging_dir(bad)
                self.assertEqual(ctx.exception.code, 'invalid-request')


class UploadTests(StorageTestCase):
    def simulate_fsreplace(self, path, data):
        """What cockpit's fsreplace1 does: write a temp file next to `path`, then rename over it."""
        temp = Path(path).parent / f'.{Path(path).name}-x1y2z3'
        temp.write_bytes(data)
        os.chmod(temp, 0o644)
        os.rename(temp, path)

    def test_upload_round_trip(self):
        data = fake_archive_bytes(backup_id='20261101T080000Z-0123abcd', created='2026-11-01T08:00:00Z',
                                  key_id='1234-5678-9ABC-DEF0')
        begun = self.storage.begin_upload('woowtech-backup-dev-a-20261101-0800.woowbackup', len(data))
        self.assertRegex(begun['upload_id'], r'^u[0-9a-f]{16}$')
        part = Path(begun['path'])
        self.assertEqual(part, self.paths.uploads / f'{begun["upload_id"]}.part')
        self.assertEqual((part.stat().st_size, mode(part)), (0, 0o600))
        self.assertEqual(begun['max_size'], 100 * GIB - self.paths.reserve_bytes)
        self.simulate_fsreplace(part, data)
        rec = self.storage.finish_upload(begun['upload_id'])
        self.assertEqual(rec['id'], '20261101T080000Z-0123abcd')
        self.assertEqual((rec['type'], rec['key_id'], rec['created']),
                         ('uploaded', '1234-5678-9ABC-DEF0', '2026-11-01T08:00:00Z'))
        self.assertEqual((rec['size'], rec['sha256']), (len(data), hashlib.sha256(data).hexdigest()))
        self.assertEqual(rec['filename'], 'woowtech-backup-dev-a-20261101-0800.woowbackup')
        self.assertFalse(rec['inspected'])
        self.assertRegex(rec['uploaded_at'], r'Z$')
        archive_file = self.storage.archive_path(rec['id'])
        self.assertEqual(archive_file.read_bytes(), data)
        self.assertEqual(mode(archive_file), 0o600)
        self.assertEqual(os.listdir(self.paths.uploads), [f'{begun["upload_id"]}.done'],
                         'upload files cleaned up; only the small completion marker stays (24 h)')
        self.assertEqual([r['id'] for r in self.storage.list_backups()], [rec['id']])
        # Review F6: a retry after the page timed out returns the same backup instead of "not found".
        self.assertEqual(self.storage.finish_upload(begun['upload_id']), rec)
        # Same file again: deduplicated to the existing record.
        again = self.storage.begin_upload('copy.woowbackup', len(data))
        self.simulate_fsreplace(again['path'], data)
        self.assertEqual(self.storage.finish_upload(again['upload_id']), rec)
        self.assertEqual(sorted(os.listdir(self.paths.uploads)),
                         sorted([f'{begun["upload_id"]}.done', f'{again["upload_id"]}.done']))
        # Same backup id, different bytes: refused, the original stays intact.
        evil = fake_archive_bytes(backup_id='20261101T080000Z-0123abcd', created='2026-11-01T08:00:00Z',
                                  payload=b'\x01' * 64)
        third = self.storage.begin_upload('x.woowbackup', len(evil))
        self.simulate_fsreplace(third['path'], evil)
        with self.assertRaises(BackupError) as ctx:
            self.storage.finish_upload(third['upload_id'])
        self.assertEqual(ctx.exception.code, 'invalid-request')
        self.assertEqual(archive_file.read_bytes(), data)

    def test_uploaded_filename_is_generated_when_untrusted(self):
        data = fake_archive_bytes(backup_id='20261101T080000Z-0123abce')
        begun = self.storage.begin_upload('../../My Backup (1).woowbackup', len(data))
        self.simulate_fsreplace(begun['path'], data)
        rec = self.storage.finish_upload(begun['upload_id'])
        self.assertEqual(rec['filename'], 'woowtech-backup-uploaded-20261113-020000.woowbackup')

    def test_uploaded_names_with_and_without_seconds_are_kept(self):
        # Coordinator decision: download names carry seconds; names from older engines (HHMM) stay accepted.
        for name, backup_id in (('woowtech-backup-dev-b-20261101-080005.woowbackup', '20261101T080005Z-0123abc1'),
                                ('woowtech-backup-dev-b-20261101-0800.woowbackup', '20261101T080000Z-0123abc2')):
            data = fake_archive_bytes(backup_id=backup_id, created=f'2026-11-01T08:00:{backup_id[13:15]}Z')
            begun = self.storage.begin_upload(name, len(data))
            self.simulate_fsreplace(begun['path'], data)
            self.assertEqual(self.storage.finish_upload(begun['upload_id'])['filename'], name)

    def test_a_failure_after_the_move_puts_the_file_back(self):
        # Review SEC-4 (upload window): nothing may stay in archives/ unlisted, and a retry can still finish.
        data = fake_archive_bytes(backup_id='20261101T080000Z-0123abcf')
        begun = self.storage.begin_upload('u.woowbackup', len(data))
        self.simulate_fsreplace(begun['path'], data)
        register = self.storage.register

        def interrupted(*args, **kwargs):
            raise KeyboardInterrupt
        self.storage.register = interrupted
        with self.assertRaises(KeyboardInterrupt):
            self.storage.finish_upload(begun['upload_id'])
        self.assertEqual(os.listdir(self.paths.archives), [])
        self.assertEqual(Path(begun['path']).read_bytes(), data)
        self.storage.register = register
        self.assertEqual(self.storage.finish_upload(begun['upload_id'])['id'], '20261101T080000Z-0123abcf')

    def test_unindexed_archives_are_adopted(self):
        # Lab open issue: a hard kill between publishing and indexing left a never-listed archive.
        data = fake_archive_bytes(backup_id='20261101T080000Z-0123abd0', key_id='1234-5678-9ABC-DEF0')
        orphan = self.storage.archive_path('20261101T080000Z-0123abd0')
        self.storage.ensure_layout()
        orphan.write_bytes(data)
        self.assertEqual(self.storage.adopt_orphans(), [], 'too recent: it may be being published right now')
        self.assertEqual(self.storage.adopt_orphans(now=time.time() + 7200), ['20261101T080000Z-0123abd0'])
        rec = self.storage.get('20261101T080000Z-0123abd0')
        self.assertEqual((rec['type'], rec['key_id'], rec['sha256']),
                         ('uploaded', '1234-5678-9ABC-DEF0', hashlib.sha256(data).hexdigest()))
        (self.paths.archives / '20261101T080000Z-0123abd1.woowbackup').write_bytes(b'not a backup' * 20)
        self.assertEqual(self.storage.adopt_orphans(now=time.time() + 7200), [])

    def test_reupload_of_an_unindexed_archive_indexes_it(self):
        data = fake_archive_bytes(backup_id='20261101T080000Z-0123abd2')
        self.storage.ensure_layout()
        self.storage.archive_path('20261101T080000Z-0123abd2').write_bytes(data)
        begun = self.storage.begin_upload('again.woowbackup', len(data))
        self.simulate_fsreplace(begun['path'], data)
        self.assertEqual(self.storage.finish_upload(begun['upload_id'])['id'], '20261101T080000Z-0123abd2')

    def test_hd10_an_unreadable_sidecar_is_never_replaced_by_an_uploaded_one(self):
        # A safety backup's sidecar a newer engine wrote (one extra field): unlisted here, but never rewritten.
        backup_id = '20261101T080000Z-0123abd3'
        data = fake_archive_bytes(backup_id=backup_id, key_id='1234-5678-9ABC-DEF0')
        self.storage.archive_path(backup_id).write_bytes(data)
        self.storage.register(backup_id, meta(type='safety', note='還原前自動備份', key_id='1234-5678-9ABC-DEF0',
                                              sha256=hashlib.sha256(data).hexdigest()))
        index = self.storage.index_path(backup_id)
        record = json.loads(index.read_text())
        record['restore_job'] = 'j20261101T080000Z-0123abcd'
        index.write_text(json.dumps(record))
        before = index.read_bytes()
        self.assertEqual(self.storage.list_backups(), [])
        self.assertEqual(self.storage.adopt_orphans(now=time.time() + 7200), [])
        self.assertEqual(index.read_bytes(), before)
        begun = self.storage.begin_upload('again.woowbackup', len(data))
        self.simulate_fsreplace(begun['path'], data)
        with self.assertRaises(BackupError) as caught:
            self.storage.finish_upload(begun['upload_id'])
        self.assertEqual(caught.exception.code, 'invalid-request')
        self.assertIn('索引無法讀取', caught.exception.message)
        self.assertEqual(index.read_bytes(), before)
        self.assertEqual(self.storage.archive_path(backup_id).read_bytes(), data)
        with self.assertRaises(BackupError):  # the guard itself
            self.storage.register(backup_id, meta(sha256=hashlib.sha256(data).hexdigest()), exclusive=True)

    def test_hd08_a_page_timeout_no_longer_stops_the_check(self):
        # cockpit-bridge sends SIGTERM when the page closes the channel on a timeout; the check now runs to its
        # end, so the page's "重新確認" finds the backup instead of hashing from byte 0 again (review HD-08).
        import signal
        from woowbackup import jobs, util
        data = fake_archive_bytes(backup_id='20261101T080000Z-0123abd4')
        begun = self.storage.begin_upload('slow.woowbackup', len(data))
        self.simulate_fsreplace(begun['path'], data)
        real = util.sha256_fd
        hashed = []

        def hashing(fd, *args, **kwargs):
            os.kill(os.getpid(), signal.SIGTERM)
            hashed.append(1)
            return real(fd, *args, **kwargs)
        with mock.patch.object(util, 'sha256_fd', hashing), jobs.signals_as_exceptions():
            rec = self.storage.finish_upload(begun['upload_id'])
            self.assertIs(signal.getsignal(signal.SIGTERM) not in (signal.SIG_IGN, signal.SIG_DFL), True,
                          'the termination handler is back after the check')
        self.assertEqual((rec['id'], len(hashed)), ('20261101T080000Z-0123abd4', 1))
        self.assertTrue((self.paths.uploads / f'{begun["upload_id"]}.done').exists())
        self.assertEqual(self.storage.finish_upload(begun['upload_id']), rec, 'the retry returns the same backup')
        self.assertEqual(len(hashed), 1)

    def test_hd08_a_retry_waits_for_the_running_check_and_returns_its_backup(self):
        from woowbackup import util
        data = fake_archive_bytes(backup_id='20261101T080000Z-0123abd5')
        begun = self.storage.begin_upload('slow.woowbackup', len(data))
        self.simulate_fsreplace(begun['path'], data)
        started, release, hashed, results = threading.Event(), threading.Event(), [], {}
        real = util.sha256_fd

        def slow(fd, *args, **kwargs):
            hashed.append(1)
            started.set()
            release.wait(10)
            return real(fd, *args, **kwargs)

        def finish(name):
            results[name] = self.storage.finish_upload(begun['upload_id'])
        with mock.patch.object(util, 'sha256_fd', slow):
            first = threading.Thread(target=finish, args=('first',))
            first.start()
            self.assertTrue(started.wait(10))
            second = threading.Thread(target=finish, args=('second',))
            second.start()
            time.sleep(0.3)
            self.assertTrue(second.is_alive(), 'the retry waits for the running check')
            release.set()
            first.join(10)
            second.join(10)
        self.assertEqual(results['first'], results['second'])
        self.assertEqual(len(hashed), 1, 'hashed once')

    def test_begin_validation_space_and_limits(self):
        for filename, size in (('', 100), ('a\nb', 100), ('x' * 300, 100), ('ok', 10), ('ok', True), ('ok', '100'),
                               (None, 100), ('ok', 10 ** 15)):
            with self.subTest(filename=filename, size=size):
                with self.assertRaises(BackupError) as ctx:
                    self.storage.begin_upload(filename, size)
                self.assertEqual(ctx.exception.code, 'invalid-request')
        self.free = self.paths.reserve_bytes + 1000
        with self.assertRaises(BackupError) as ctx:
            self.storage.begin_upload('big.woowbackup', 1001)
        self.assertEqual(ctx.exception.code, 'insufficient-space')
        self.assertEqual(self.storage.begin_upload('fits.woowbackup', 1000)['max_size'], 1000)
        self.free = 100 * GIB
        for _ in range(3):
            self.storage.begin_upload('more.woowbackup', 100)
        with self.assertRaises(BackupError) as ctx:
            self.storage.begin_upload('one-too-many.woowbackup', 100)
        self.assertEqual(ctx.exception.code, 'busy')

    def test_finish_rejects_unsafe_or_wrong_files(self):
        data = fake_archive_bytes()

        def begin(size=len(data)):
            return self.storage.begin_upload('u.woowbackup', size)

        cases = []
        up = begin()  # size mismatch (upload incomplete)
        self.simulate_fsreplace(up['path'], data[:-1])
        cases.append((up, 'invalid-request'))
        up = begin()  # symlink to a valid file
        target = self.base / 'target.woowbackup'
        target.write_bytes(data)
        os.unlink(up['path'])
        os.symlink(target, up['path'])
        cases.append((up, 'invalid-request'))
        up = begin()  # hard link to a file elsewhere
        hard = self.base / 'hard.woowbackup'
        hard.write_bytes(data)
        os.unlink(up['path'])
        os.link(hard, up['path'])
        cases.append((up, 'invalid-request'))
        for up, code in cases:
            with self.subTest(upload=up['upload_id']):
                with self.assertRaises(BackupError) as ctx:
                    self.storage.finish_upload(up['upload_id'])
                self.assertEqual(ctx.exception.code, code)
            self.storage.abort_upload(up['upload_id'])
        for kind in ('dir', 'fifo'):
            up = begin()
            os.unlink(up['path'])
            os.mkdir(up['path']) if kind == 'dir' else os.mkfifo(up['path'])
            with self.subTest(kind=kind):
                with self.assertRaises(BackupError) as ctx:
                    self.storage.finish_upload(up['upload_id'])
                self.assertEqual(ctx.exception.code, 'invalid-request')
            os.rmdir(up['path']) if kind == 'dir' else os.unlink(up['path'])
            self.storage.abort_upload(up['upload_id'])
        for content, code in ((os.urandom(len(data)), 'not-a-backup'),
                              (b'WOOWTECH-BACKUP/9\n' + data[len(b'WOOWTECH-BACKUP/1\n'):], 'unsupported-format'),
                              (data[:120] + b'\x00' * (len(data) - 120), 'corrupt-archive')):
            up = begin()
            self.simulate_fsreplace(up['path'], content)
            with self.subTest(code=code):
                with self.assertRaises(BackupError) as ctx:
                    self.storage.finish_upload(up['upload_id'])
                self.assertEqual(ctx.exception.code, code)
            self.storage.abort_upload(up['upload_id'])
        self.assertEqual(self.storage.list_backups(), [])
        self.assertEqual(sorted(os.listdir(self.paths.archives)), [])
        for bad in ('../x', 'u123', 'U' + '0' * 16, None):
            with self.assertRaises(BackupError) as ctx:
                self.storage.finish_upload(bad)
            self.assertEqual(ctx.exception.code, 'invalid-request')
        with self.assertRaises(BackupError) as ctx:
            self.storage.finish_upload('u' + '0' * 16)
        self.assertEqual(ctx.exception.code, 'not-found')

    def test_abort_and_cleanup(self):
        up = self.storage.begin_upload('a.woowbackup', 100)
        temp = self.paths.uploads / f'.{up["upload_id"]}.part-abc123'
        temp.write_bytes(b'partial')
        self.assertTrue(self.storage.abort_upload(up['upload_id']))
        self.assertEqual(os.listdir(self.paths.uploads), [])
        self.assertFalse(self.storage.abort_upload(up['upload_id']), 'idempotent')
        old = self.storage.begin_upload('old.woowbackup', 100)
        fresh = self.storage.begin_upload('fresh.woowbackup', 100)
        stale_temp = self.paths.uploads / f'.{old["upload_id"]}.part-zz'
        stale_temp.write_bytes(b'x')
        unrelated = self.paths.uploads / 'README'
        unrelated.write_text('not ours')
        past = time.time() - 2 * 86400
        for name in (f'{old["upload_id"]}.part', f'{old["upload_id"]}.json', stale_temp.name, 'README'):
            os.utime(self.paths.uploads / name, (past, past))
        self.assertEqual(self.storage.cleanup_uploads(), 3)
        self.assertEqual(sorted(os.listdir(self.paths.uploads)),
                         sorted(['README', f'{fresh["upload_id"]}.part', f'{fresh["upload_id"]}.json']))
        with self.assertRaises(BackupError) as ctx:
            self.storage.finish_upload(old['upload_id'])
        self.assertEqual(ctx.exception.code, 'not-found')


class DownloadTests(StorageTestCase):
    def test_download_info(self):
        rec = self.put_archive('20261113T020000Z-00000001', data=b'z' * 4096)
        info = self.storage.download_info(rec['id'])
        self.assertEqual(info, {'path': os.path.realpath(self.storage.archive_path(rec['id'])),
                                'filename': rec['filename'], 'size': 4096})
        self.assertTrue(info['path'].startswith(os.path.realpath(self.paths.archives) + os.sep))
        for bad in ('../../../etc/passwd', '/etc/passwd', '20261113T020000Z-0000000z'):
            with self.subTest(bad=bad):
                with self.assertRaises(BackupError) as ctx:
                    self.storage.download_info(bad)
                self.assertEqual(ctx.exception.code, 'invalid-request')
        with self.assertRaises(BackupError) as ctx:
            self.storage.download_info('20261113T020000Z-00000002')
        self.assertEqual(ctx.exception.code, 'not-found')
        secret = self.base / 'shadow'
        secret.write_text('root:x')
        path = self.storage.archive_path(rec['id'])
        path.unlink()
        path.symlink_to(secret)
        with self.assertRaises(BackupError) as ctx:
            self.storage.download_info(rec['id'])
        self.assertIn(ctx.exception.code, ('not-found', 'permission-denied'))


if __name__ == '__main__':
    unittest.main()
