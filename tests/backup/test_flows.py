"""Backup / restore / verify orchestration with fakes for storage, keys, archive and adapters.

Covers: phases and cancellable windows, space check before stopping writers (F6), dump failure
(F7), safety backup + automatic rollback (F8), fresh-mode cleanup, rollback failure guidance,
verification comparison, keep-3 safety pruning, key-required, and staging cleanup.
"""
import base64
import contextlib
import copy
import hashlib
import json
import os
import shutil
import tempfile
import types
import unittest
from pathlib import Path

from woowbackup import catalog, flows
from woowbackup.archive import Entry
from woowbackup.errors import BackupError
from woowbackup.keys import KeyInfo
from woowbackup.paths import Paths

from .test_catalog import demo_entry, lookup as user_lookup

HOST = {'hostname': 'dev-a', 'machine_id_sha256': 'f' * 64, 'arch': 'x86_64', 'os': 'Ubuntu 24.04.3 LTS',
        'podman': '4.9.3'}
TEST_SECRET = 'AGE-SECRET-KEY-1' + 'Q' * 58
TEST_SECRET_ID = 'EEEE-FFFF-0000-1111'


def noop(*_args, **_kwargs):
    return None


# ---------------------------------------------------------------- fakes

class FakeReporter:
    def __init__(self):
        self.events, self.logs, self.partial = [], [], {}
        self.partials = []  # every set_partial call, in order
        self.cancellable = True
        self.cancel = False

    def phase(self, phase_id):
        self.events.append(('phase', phase_id))

    def skip(self, phase_id):
        self.events.append(('skip', phase_id))

    def complete(self, phase_id):
        self.events.append(('complete', phase_id))

    def add_phase(self, phase_id, label):
        self.events.append(('add_phase', phase_id))

    def progress(self, percent=None, message=None, *, fraction=None, force=False):
        self.events.append(('progress', fraction))

    def log(self, message):
        self.logs.append(message)

    def set_cancellable(self, flag):
        self.cancellable = flag
        self.events.append(('cancellable', flag))

    def cancel_requested(self):
        return self.cancel

    def set_partial(self, **fields):
        self.partials.append(copy.deepcopy(fields))
        self.partial.update(fields)

    def phases(self):
        return [e[1] for e in self.events if e[0] == 'phase']


class FakeKeys:
    def __init__(self, root, device=True):
        self.root = Path(root)
        self.device = KeyInfo('AAAA-BBBB-CCCC-DDDD', 'age1' + 'q' * 58, self.root / 'device.key', 'device',
                              '2026-11-01T00:00:00Z', False) if device else None
        self.imported = []
        self.temp_paths = []
        self.confirmed = []

    def device_key(self):
        return self.device

    def identities(self):
        return ([self.device] if self.device else []) + list(self.imported)

    def ensure_device_key(self):
        if self.device:
            return self.device, False
        self.device = KeyInfo('AAAA-BBBB-CCCC-DDDD', 'age1' + 'q' * 58, self.root / 'device.key', 'device',
                              '2026-11-13T00:00:00Z', False)
        return self.device, True

    def import_key(self, text):
        if text.strip().upper() != TEST_SECRET:
            raise BackupError('invalid-request', '金鑰格式不正確。')
        info = KeyInfo(TEST_SECRET_ID, 'age1' + 'p' * 58, self.root / 'imported.key', 'imported',
                       '2026-11-13T00:00:00Z', False)
        if all(k.key_id != info.key_id for k in self.imported):
            self.imported.append(info)
        return info

    def kit_text(self):
        if not self.device:
            raise BackupError('no-device-key', '本設備尚未建立備份金鑰。')
        return f'緊急金鑰 {self.device.key_id}\n{TEST_SECRET}\n'

    def kit_filename(self):
        return f'woowtech-backup-key-dev-a-{self.device.key_id}.txt'

    def confirm_kit(self, key_id):
        if not self.device or key_id != self.device.key_id:
            raise BackupError('invalid-request', '金鑰 ID 與本設備目前的備份金鑰不符。')
        self.confirmed.append(key_id)

    @contextlib.contextmanager
    def temp_identity(self, text, name):
        if text.strip().upper() != TEST_SECRET:
            raise BackupError('invalid-request', '金鑰格式不正確。')
        path = self.root / name
        path.write_text(TEST_SECRET + '\n')
        self.temp_paths.append(path)
        try:
            yield path
        finally:
            path.unlink()


class FakeStorage:
    def __init__(self, root, free=10 ** 12):
        self.root = Path(root)
        self.archives = self.root / 'archives'
        self.staging = self.root / 'staging'
        self.index, self.free, self.counter = {}, free, 0
        self.deleted, self.updates, self.removed_staging = [], [], []
        self.uploads = {}

    def ensure_layout(self):
        for path in (self.archives, self.staging):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)

    def new_backup_id(self, now=None):
        self.counter += 1
        return f'20261113T0200{self.counter:02d}Z-{self.counter:08x}'

    def archive_path(self, backup_id):
        return self.archives / f'{backup_id}.woowbackup'

    def list_backups(self):
        records = [copy.deepcopy(m) for m in self.index.values() if self.archive_path(m['id']).exists()]
        return sorted(records, key=lambda m: (m.get('created') or '', m['id']), reverse=True)

    def get(self, backup_id):
        if backup_id not in self.index or not self.archive_path(backup_id).exists():
            raise BackupError('not-found', '找不到指定的備份。', backup_id=backup_id)
        return copy.deepcopy(self.index[backup_id])

    def register(self, backup_id, meta):
        assert self.archive_path(backup_id).exists()
        self.index[backup_id] = copy.deepcopy(meta)
        return copy.deepcopy(meta)

    def update(self, backup_id, **fields):
        self.get(backup_id)
        self.index[backup_id].update(copy.deepcopy(fields))
        self.updates.append((backup_id, fields))
        return copy.deepcopy(self.index[backup_id])

    def delete(self, backup_id):
        self.get(backup_id)
        del self.index[backup_id]
        self.archive_path(backup_id).unlink()
        self.deleted.append(backup_id)

    def free_bytes(self):
        return self.free

    def usage(self):
        backups = self.list_backups()
        return {'path': str(self.root), 'free_bytes': self.free, 'total_bytes': 2 * self.free,
                'backups_bytes': sum(b['size'] for b in backups), 'backup_count': len(backups)}

    def staging_dir(self, job_id):
        path = self.staging / job_id
        if path.exists():
            shutil.rmtree(path)
        self.ensure_layout()
        path.mkdir(mode=0o700)
        return path

    def remove_staging(self, job_id):
        shutil.rmtree(self.staging / job_id, ignore_errors=True)
        self.removed_staging.append(job_id)

    def begin_upload(self, filename, size):
        upload_id = 'u' + '0' * 15 + str(len(self.uploads))
        self.uploads[upload_id] = (filename, size)
        return {'upload_id': upload_id, 'path': str(self.root / f'{upload_id}.part'), 'max_size': self.free}

    def finish_upload(self, upload_id):
        if upload_id not in self.uploads:
            raise BackupError('not-found', '找不到上傳工作。')
        return {'id': '20261101T000000Z-0000abcd', 'type': 'uploaded', 'created': '2026-11-01T00:00:00Z', 'note': '',
                'apps': [], 'size': 10, 'sha256': '0' * 64, 'key_id': TEST_SECRET_ID, 'include_images': False,
                'filename': 'x.woowbackup', 'source': None, 'verified': None, 'inspected': False,
                'uploaded_at': '2026-11-13T00:00:00Z'}

    def abort_upload(self, upload_id):
        self.uploads.pop(upload_id, None)
        return True

    def download_info(self, backup_id):
        meta = self.get(backup_id)
        return {'path': str(self.archive_path(backup_id)), 'filename': meta['filename'],
                'size': self.archive_path(backup_id).stat().st_size}


class FakeArchive:
    """JSON container standing in for the age/zstd/tar format; enforces the identity rules."""

    def __init__(self):
        self.writes, self.extracts, self.verifies = [], [], []
        self.corrupt = set()
        self.on_write = None

    @staticmethod
    def _load(path):
        return json.loads(Path(path).read_text())

    @staticmethod
    def _key_ids(identities):
        ids = set()
        for item in identities:
            if getattr(item, 'key_id', None):
                ids.add(item.key_id)
            elif Path(item).read_text().strip() == TEST_SECRET:
                ids.add(TEST_SECRET_ID)
        return ids

    def write_archive(self, dest, header, manifest, entries, recipient, *, tmp_dir, progress=None):
        dest = Path(dest)
        assert not dest.exists() and Path(tmp_dir).is_dir()
        assert header['key_id'] == manifest['key_id']
        manifest = dict(manifest, entries=[{'path': e.path, 'size': e.size, 'sha256': e.sha256} for e in entries])
        files = {}
        for done, entry in enumerate(entries, 1):
            data = Path(entry.source).read_bytes()
            assert hashlib.sha256(data).hexdigest() == entry.sha256 and len(data) == entry.size
            files[entry.path] = base64.b64encode(data).decode()
            if progress:
                progress(done, len(entries))
        if self.on_write:
            self.on_write()
        payload = json.dumps({'header': header, 'manifest': manifest, 'files': files}).encode()
        tmp = Path(tmp_dir) / '.write.tmp'
        tmp.write_bytes(payload)
        os.rename(tmp, dest)
        self.writes.append({'dest': dest, 'recipient': recipient, 'manifest': manifest})
        return {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}

    def read_header(self, path):
        return self._load(path)['header']

    def _open(self, path, identities):
        data = self._load(path)
        if not identities:
            raise BackupError('key-required', '需要備份金鑰。')
        if data['header']['key_id'] not in self._key_ids(identities):
            raise BackupError('wrong-key', '金鑰不正確。')
        if str(path) in self.corrupt or Path(path).name in self.corrupt:
            raise BackupError('corrupt-archive', '備份檔已損毀或遭到修改，無法使用。')
        return data

    def read_manifest(self, path, identities, *, limits=None):
        return self._open(path, identities)['manifest']

    def verify_archive(self, path, identities, *, progress=None, limits=None):
        data = self._open(path, identities)
        self.verifies.append(Path(path))
        if progress:
            progress(1, 1)
        return {'manifest': data['manifest'], 'entries': len(data['files']),
                'bytes': sum(e['size'] for e in data['manifest']['entries'])}

    def extract_archive(self, path, identities, dest_dir, *, progress=None, limits=None):
        dest_dir = Path(dest_dir)
        assert dest_dir.is_dir() and not any(dest_dir.iterdir()) and dest_dir.stat().st_mode & 0o077 == 0
        data = self._open(path, identities)
        for rel, blob in data['files'].items():
            target = dest_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(base64.b64decode(blob))
        self.extracts.append((Path(path), dest_dir))
        if progress:
            progress(1, 1)
        return data['manifest']


class World:
    """Shared state for FakeAdapter instances: app data, modes and injected failures."""

    def __init__(self):
        self.data = {'woowbk-demo': b'notes-v1', 'woowbk-two': b'two-v1'}
        self.mode = {'woowbk-demo': 'inplace', 'woowbk-two': 'inplace'}
        self.deployed = {'woowbk-demo': True, 'woowbk-two': True}
        self.estimate = 1000
        self.events = []
        self.fail_backup = set()
        self.fail_restore_after = {}
        self.fail_restore_before = set()
        self.fail_remove = set()
        self.fail_rollback_restore = set()
        self.unhealthy = {}
        self.corrupt_restore = set()
        self.preflight_fail = set()
        self.db_down = set()
        self.unstartable = set()
        self.hook_probe = None
        self.after_backup = None
        self.health_hints = {}
        self.extract_seen = None
        self.raise_after_destructive = None  # e.g. jobs.Terminated: a signal after the first destructive step
        self.raise_in = {}  # app id -> exception raised after that app's first destructive step
        self.adapters = []
        self.preflight_dirs = []
        self.unchecked = []
        self.restore_warnings = {}
        self.fresh_live = {}  # app id -> units adapter.fresh_in_use() reports
        self.fresh_live_error = set()

    def factory(self, app, *, log, phase=None, checkpoint=None, writers_hook=None, imported_hook=None):
        adapter = FakeAdapter(app, self, log, phase, checkpoint, writers_hook, imported_hook)
        self.adapters.append(adapter)
        return adapter


def snapshot_of(data):
    return {'summary': {'notes': len(data), 'files': 1, 'digest': hashlib.sha256(data).hexdigest()[:12],
                        'title': 'Demo', 'signatures_valid': True}}


class FakeAdapter:
    def __init__(self, app, world, log, phase, checkpoint, writers_hook=None, imported_hook=None):
        self.app, self.world, self.log = app, world, log
        self.phase = phase or noop
        self.checkpoint = checkpoint or noop
        self.writers_hook = writers_hook or noop
        self.imported_hook = imported_hook or noop
        self.destructive_started = False
        self.last_downtime = 0.0
        self.warnings = []

    def probe(self):
        deployed = self.world.deployed[self.app.id]
        return {'deployed': deployed, 'state': 'running' if deployed else 'not-deployed',
                'units': [{'name': u, 'active': deployed} for u in self.app.units], 'problems': []}

    def detect_mode(self):
        return self.world.mode[self.app.id]

    def ensure_databases_running(self):
        self.world.events.append(('ensure-db', self.app.id))
        if self.app.id in self.world.db_down:
            raise BackupError('job-failed', 'systemctl start 執行失敗（結束碼 1）。')
        return []

    def estimate_bytes(self, *, include_images=False):
        return self.world.estimate

    def backup(self, staging_dir, *, include_images):
        self.world.events.append(('backup', self.app.id))
        self.phase('stop')
        self.writers_hook(list(self.app.writer_units))
        if self.world.hook_probe:
            self.world.hook_probe()
        self.phase('dump')
        if self.app.id in self.world.fail_backup:
            self.phase('start')
            self.writers_hook([])
            raise BackupError('job-failed', 'pg_dump 執行失敗（結束碼 1）。')
        self.phase('export')
        data = self.world.data[self.app.id]
        source = Path(staging_dir) / 'data'
        source.write_bytes(data)
        self.phase('start')
        self.writers_hook([])
        self.last_downtime = 2.4
        if self.world.after_backup:
            self.world.after_backup()
        entry = Entry(f'apps/{self.app.id}/volumes/data.tar', source, len(data), hashlib.sha256(data).hexdigest())
        manifest = {'id': self.app.id, 'name': self.app.name, 'adapter': 'quadlet-postgres', 'adapter_version': 1,
                    'catalog_sha256': self.app.sha256, 'owner': {'name': 'appowner', 'uid': 1001},
                    'images': [{'ref': 'localhost/x:1', 'id': 'sha256:' + 'a' * 64, 'digest': '', 'arch': 'amd64'}],
                    'postgres': [], 'volumes': [{'name': 'data', 'entry': entry.path}], 'secrets': [],
                    'config_files': [], 'quadlet_files': [], 'verify_snapshot': snapshot_of(data)}
        return manifest, [entry]

    def preflight(self, app_manifest, *, mode, entry_sizes=None, extracted_dir=None):
        self.world.preflight_dirs.append(extracted_dir)
        if self.app.id in self.world.preflight_fail:
            return [{'id': f'{self.app.id}/image', 'status': 'fail', 'message': '缺少映像 localhost/x:1。'}]
        return [{'id': f'{self.app.id}/items', 'status': 'ok', 'message': '項目齊全。'},
                {'id': f'{self.app.id}/catalog', 'status': 'warn', 'message': '設定與備份時不同。'}]

    def restore(self, app_manifest, extracted_dir, *, mode, rollback=False, unchecked_databases_ok=False):
        assert rollback == (self.phase is noop), 'rollbacks (and only they) use rollback=True and no phases'
        self.world.events.append(('restore', self.app.id, mode, 'rollback' if rollback else 'restore'))
        if not rollback:
            self.world.unchecked.append((self.app.id, unchecked_databases_ok))
        if self.app.id in self.world.fail_restore_before:
            raise BackupError('incompatible', '映像載入失敗。')
        self.phase('stop')
        self.destructive_started = True
        self.phase('restore')
        if self.world.raise_after_destructive is not None and not rollback:
            raise self.world.raise_after_destructive
        if self.app.id in self.world.raise_in and not rollback:
            raise self.world.raise_in[self.app.id]
        if rollback and self.app.id in self.world.fail_rollback_restore:
            raise BackupError('job-failed', '回復時資料卷匯入失敗。')
        data = (Path(extracted_dir) / app_manifest['volumes'][0]['entry']).read_bytes()
        self.world.data[self.app.id] = data + (b'-corrupted' if self.app.id in self.world.corrupt_restore and
                                                  not rollback else b'')
        left = self.world.fail_restore_after.get(self.app.id, 0)
        if left and not rollback:
            self.world.fail_restore_after[self.app.id] = left - 1
            raise BackupError('job-failed', '資料卷匯入失敗。')
        self.warnings.extend(self.world.restore_warnings.get(self.app.id, []))
        self.world.events.append(('imported', self.app.id))
        self.imported_hook()  # like the real adapter: the import finished, the units start next (HD-04)
        self.phase('start')

    def start_units(self, units):
        self.world.events.append(('start_units', self.app.id, tuple(units)))
        return [u for u in units if u in self.world.unstartable]

    def fresh_in_use(self):
        if self.app.id in self.world.fresh_live_error:
            raise BackupError('job-failed', 'systemctl --user show 執行失敗。')
        return list(self.world.fresh_live.get(self.app.id, []))

    def remove_fresh(self):
        self.world.events.append(('remove_fresh', self.app.id))
        if self.app.id in self.world.fail_remove:
            raise BackupError('job-failed', '無法完整移除新部署的項目；需人工處理。')

    def health(self):
        status = self.world.unhealthy.get(self.app.id, 'ok')
        return [{'id': f'{self.app.id}/health-1', 'status': status, 'message': f'健康檢查 {status}'}]

    def health_hint(self):
        return self.world.health_hints.get(self.app.id)

    def verify_snapshot(self):
        return snapshot_of(self.world.data[self.app.id])


def make_catalog(paths):
    apps = catalog.Catalog()
    entry = demo_entry(paths)
    apps['woowbk-demo'] = catalog.validate_entry(entry, paths=paths, user_lookup=user_lookup)
    second = copy.deepcopy(entry)
    second.update(id='woowbk-two', name='第二個應用',
                  config_files=[{'path': '.config/woowbk-two/app.env', 'mode': '0600'}])
    apps['woowbk-two'] = catalog.validate_entry(second, paths=paths, user_lookup=user_lookup)
    return apps


class FlowCase(unittest.TestCase):
    job_id = 'j20261113T020000Z-0123abcd'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.paths = Paths(base=self.root / 'sys')
        self.storage = FakeStorage(self.root / 'data')
        self.keys = FakeKeys(self.root)
        self.archive = FakeArchive()
        self.world = World()
        self.catalog = make_catalog(self.paths)
        self.deps = flows.Deps(storage=self.storage, keys=self.keys, archive=self.archive,
                               load_catalog=lambda: self.catalog, adapter_factory=self.world.factory,
                               host_info=lambda: dict(HOST))
        self.reporter = FakeReporter()

    def tearDown(self):
        self.tmp.cleanup()

    def ctx(self, key_file=None, job_id=None):
        self.reporter = FakeReporter()
        return flows.FlowContext(self.paths, job_id or self.job_id, self.deps, self.reporter, key_file=key_file)

    def backup(self, apps=('woowbk-demo',), **params):
        params = {'apps': list(apps), 'include_images': False, 'note': '手動', **params}
        return flows.run_backup(self.ctx(), params)

    def assert_staging_clean(self):
        self.assertFalse((self.storage.staging / self.job_id).exists())


class BackupFlowTests(FlowCase):
    def test_success_phases_windows_and_registration(self):
        result = self.backup()
        self.assertEqual(result['apps'], ['woowbk-demo'])
        self.assertEqual(result['downtime_seconds'], 2)
        self.assertEqual(self.reporter.phases(), ['prepare', 'check', 'stop', 'dump', 'export', 'start', 'package',
                                                  'verify'])
        flags = [e[1] for e in self.reporter.events if e[0] == 'cancellable']
        self.assertEqual(flags, [True, False, True])
        stop_at = self.reporter.events.index(('phase', 'stop'))
        self.assertEqual(self.reporter.events[stop_at - 1], ('cancellable', False))
        meta = self.storage.index[result['backup_id']]
        self.assertEqual(meta['type'], 'manual')
        self.assertEqual(meta['verified']['ok'], True)
        self.assertEqual(meta['apps'], [{'id': 'woowbk-demo', 'name': '示範筆記應用'}])
        self.assertEqual(meta['filename'], 'woowtech-backup-dev-a-20261113-020001.woowbackup')
        manifest = self.archive.writes[0]['manifest']
        self.assertEqual(manifest['created'], '2026-11-13T02:00:01Z')
        self.assertEqual(manifest['consistency'], {'method': 'writers-stopped', 'downtime_seconds': 2})
        self.assertEqual(manifest['source'], HOST)
        self.assertEqual(self.archive.writes[0]['recipient'], self.keys.device.recipient)
        # written and verified inside the job's staging, then published into archives/
        final = self.storage.archive_path(result['backup_id'])
        self.assertEqual(self.archive.verifies, [self.storage.staging / self.job_id / final.name])
        self.assertTrue(final.is_file())
        self.assert_staging_clean()

    def test_archive_appears_in_archives_only_after_verification(self):
        # Lab H4: SIGKILL during 'verify' left an unlisted 142 MB archive in archives/ that nothing removed.
        seen = []
        verify = self.archive.verify_archive

        def spy(path, identities, **kwargs):
            seen.append((Path(path), sorted(p.name for p in self.storage.archives.iterdir())))
            return verify(path, identities, **kwargs)
        self.archive.verify_archive = spy
        result = self.backup()
        path, listing = seen[0]
        self.assertEqual(path.parent, self.storage.staging / self.job_id)
        self.assertEqual(listing, [])
        self.assertEqual(sorted(p.name for p in self.storage.archives.iterdir()),
                         [f'{result["backup_id"]}.woowbackup'])

    def test_insufficient_space_fails_before_any_writer_stops(self):
        self.storage.free = 1000
        with self.assertRaises(BackupError) as caught:
            self.backup()
        self.assertEqual(caught.exception.code, 'insufficient-space')
        self.assertEqual(self.world.events, [])
        self.assertNotIn('stop', self.reporter.phases())
        self.assertEqual(self.storage.index, {})
        self.assert_staging_clean()

    def test_dump_failure_lists_nothing(self):
        self.world.fail_backup.add('woowbk-demo')
        with self.assertRaises(BackupError) as caught:
            self.backup()
        self.assertIn('pg_dump', caught.exception.message)
        self.assertEqual(self.storage.index, {})
        self.assertEqual(list(self.storage.archives.iterdir()), [])
        self.assert_staging_clean()

    def test_cancel_before_stop(self):
        ctx = self.ctx()
        self.reporter.cancel = True
        with self.assertRaises(flows.Cancelled):
            flows.run_backup(ctx, {'apps': ['woowbk-demo']})
        self.assertEqual(self.world.events, [])
        self.assert_staging_clean()

    def test_cancel_request_during_stop_window_is_ignored_until_package(self):
        self.world.after_backup = lambda: setattr(self.reporter, 'cancel', True)
        with self.assertRaises(flows.Cancelled):
            self.backup()
        self.assertEqual(self.world.events, [('backup', 'woowbk-demo')])
        self.assertEqual(self.storage.index, {})
        self.assertEqual(list(self.storage.archives.iterdir()), [])

    def test_cancel_during_verify_discards_archive(self):
        self.archive.on_write = lambda: setattr(self.reporter, 'cancel', True)
        with self.assertRaises(flows.Cancelled):
            self.backup()
        self.assertEqual(self.storage.index, {})
        self.assertEqual(list(self.storage.archives.iterdir()), [])

    def test_verify_failure_discards_archive(self):
        self.archive.on_write = lambda: self.archive.corrupt.add('20261113T020001Z-00000001.woowbackup')
        with self.assertRaises(BackupError) as caught:
            self.backup()
        self.assertEqual(caught.exception.code, 'corrupt-archive')
        self.assertEqual(list(self.storage.archives.iterdir()), [])

    def test_requires_device_key_and_catalog_apps(self):
        self.keys.device = None
        with self.assertRaises(BackupError) as caught:
            self.backup()
        self.assertEqual(caught.exception.code, 'no-device-key')
        self.keys = FakeKeys(self.root)
        self.deps.keys = self.keys
        with self.assertRaises(BackupError) as caught:
            self.backup(apps=['unknown-app'])
        self.assertEqual(caught.exception.code, 'app-not-in-catalog')
        self.world.deployed['woowbk-demo'] = False
        with self.assertRaises(BackupError) as caught:
            self.backup()
        self.assertEqual(caught.exception.code, 'not-deployed')

    def test_owner_missing_is_reported_as_such(self):
        self.catalog.pop('woowbk-two')
        self.catalog.problems.append({'file': 'woowbk-two.json', 'id': 'woowbk-two', 'code': 'owner-missing',
                                      'message': '擁有者帳號不存在。'})
        with self.assertRaises(BackupError) as caught:
            self.backup(apps=['woowbk-two'])
        self.assertEqual(caught.exception.code, 'owner-missing')

    def test_stopped_writers_are_recorded_while_stopped(self):
        seen = []
        self.world.hook_probe = lambda: seen.append(dict(self.reporter.partial))
        self.backup()
        self.assertEqual(seen, [{'stopped_writers': {'woowbk-demo': ['woowbk-demo-app.service']}}])
        self.assertEqual(self.reporter.partial, {'stopped_writers': {}})

    def test_multi_app_backup_sums_downtime(self):
        result = self.backup(apps=['woowbk-demo', 'woowbk-two'])
        self.assertEqual(result['downtime_seconds'], 5)
        self.assertEqual([a['id'] for a in self.archive.writes[0]['manifest']['apps']], ['woowbk-demo', 'woowbk-two'])


class VerifyFlowTests(FlowCase):
    def setUp(self):
        super().setUp()
        self.backup_id = self.backup()['backup_id']

    def test_verify_ok_updates_index(self):
        result = flows.run_verify(self.ctx(), {'backup_id': self.backup_id})
        self.assertEqual(result, {'ok': True, 'entries': 1, 'bytes': len(b'notes-v1')})
        self.assertEqual(self.reporter.phases(), ['prepare', 'decrypt', 'check'])
        self.assertTrue(self.storage.index[self.backup_id]['verified']['ok'])

    def test_corrupt_marks_index_failed(self):
        self.archive.corrupt.add(str(self.storage.archive_path(self.backup_id)))
        with self.assertRaises(BackupError):
            flows.run_verify(self.ctx(), {'backup_id': self.backup_id})
        self.assertFalse(self.storage.index[self.backup_id]['verified']['ok'])

    def test_key_required_and_wrong_key_do_not_mark_failed(self):
        self.keys.device = None
        with self.assertRaises(BackupError) as caught:
            flows.run_verify(self.ctx(), {'backup_id': self.backup_id})
        self.assertEqual(caught.exception.code, 'key-required')
        key_file = self.root / 'key-file'
        key_file.write_text(TEST_SECRET + '\n')
        with self.assertRaises(BackupError) as caught:
            flows.run_verify(self.ctx(key_file=key_file), {'backup_id': self.backup_id})
        self.assertEqual(caught.exception.code, 'wrong-key')
        self.assertTrue(self.storage.index[self.backup_id]['verified']['ok'])

    def test_unknown_backup(self):
        with self.assertRaises(BackupError) as caught:
            flows.run_verify(self.ctx(), {'backup_id': '20200101T000000Z-00000000'})
        self.assertEqual(caught.exception.code, 'not-found')


class RestoreFlowTests(FlowCase):
    def setUp(self):
        super().setUp()
        self.backup_id = self.backup(apps=['woowbk-demo', 'woowbk-two'])['backup_id']
        self.world.data.update({'woowbk-demo': b'notes-v2-changed', 'woowbk-two': b'two-v2-changed'})
        self.world.events.clear()

    def restore(self, apps=('woowbk-demo',), key_file=None):
        return flows.run_restore(self.ctx(key_file=key_file), {'backup_id': self.backup_id, 'apps': list(apps)})

    def safety_ids(self):
        return [m['id'] for m in self.storage.list_backups() if m['type'] == 'safety']

    def test_inplace_success(self):
        result = self.restore()
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v1')
        self.assertEqual(self.reporter.phases(), ['prepare', 'decrypt', 'preflight', 'safety', 'stop', 'restore',
                                                  'start', 'check'])
        safety = self.safety_ids()
        self.assertEqual(len(safety), 1)
        self.assertEqual(result['safety_backup_id'], safety[0])
        self.assertEqual(self.reporter.partial, {'safety_backup_id': safety[0], 'stopped_writers': {}})
        self.assertEqual(self.storage.index[safety[0]]['apps'], [{'id': 'woowbk-demo', 'name': '示範筆記應用'}])
        self.assertFalse(self.storage.index[safety[0]]['include_images'])
        self.assertEqual(result['health'][0]['status'], 'ok')
        self.assertEqual(result['verification'][0]['app'], 'woowbk-demo')
        self.assertIs(result['verification'][0]['match'], True)
        self.assertEqual(result['rolled_back'], False)
        cancel_flags = [e[1] for e in self.reporter.events if e[0] == 'cancellable']
        self.assertEqual(cancel_flags, [True, False])
        self.assertLess(self.reporter.events.index(('cancellable', False)), self.reporter.events.index(('phase', 'safety')))
        self.assertEqual(self.world.events[:2], [('ensure-db', 'woowbk-demo'), ('backup', 'woowbk-demo')])
        self.assert_staging_clean()

    def test_failure_after_destructive_step_rolls_back_to_safety(self):
        self.world.fail_restore_after['woowbk-demo'] = 1
        with self.assertRaises(flows.RolledBack) as caught:
            self.restore()
        rolled = caught.exception
        self.assertEqual(rolled.error.code, 'job-failed')
        self.assertTrue(rolled.result['rolled_back'])
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v2-changed')  # pre-restore state is back
        self.assertIn(('add_phase', 'rollback'), self.reporter.events)
        self.assertEqual(self.reporter.phases()[-1], 'rollback')
        restores = [e for e in self.world.events if e[0] == 'restore']
        self.assertEqual(restores, [('restore', 'woowbk-demo', 'inplace', 'restore'),
                                    ('restore', 'woowbk-demo', 'inplace', 'rollback')])
        safety_path = self.storage.archive_path(rolled.result['safety_backup_id'])
        self.assertEqual(self.archive.extracts[-1][0], safety_path)
        self.assert_staging_clean()

    def test_verification_mismatch_rolls_back(self):
        self.world.corrupt_restore.add('woowbk-demo')
        with self.assertRaises(flows.RolledBack) as caught:
            self.restore()
        self.assertIs(caught.exception.result['verification'][0]['match'], False)
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v2-changed')

    def test_health_failure_rolls_back(self):
        self.world.unhealthy['woowbk-demo'] = 'fail'
        with self.assertRaises(BackupError) as caught:
            self.restore()
        # health stays failing in the fake, so the rollback itself is reported as needing manual work
        self.assertIn('需人工處理', caught.exception.message)
        self.assertIn(caught.exception.result['safety_backup_id'], caught.exception.message)

    def test_failure_before_destructive_step_does_not_roll_back(self):
        self.world.fail_restore_before.add('woowbk-demo')
        with self.assertRaises(BackupError) as caught:
            self.restore()
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertNotIn(('add_phase', 'rollback'), self.reporter.events)
        result = caught.exception.result
        self.assertEqual(result['safety_backup_id'], self.safety_ids()[0])
        # Review CR-09/F2: the page must be able to say "nothing changed" instead of "rollback incomplete".
        self.assertIs(result['changed'], False)
        self.assertIs(result['rolled_back'], False)
        self.assertIn(('complete', 'safety'), self.reporter.events, 'the safety phase is done, not failed')
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v2-changed')

    def test_fresh_failure_removes_what_was_created(self):
        self.world.mode['woowbk-demo'] = 'fresh'
        self.world.fail_restore_after['woowbk-demo'] = 1
        seen = []
        self.world.hook_probe = None
        restore = FakeAdapter.restore

        def spy(adapter, *args, **kwargs):
            seen.append(dict(self.reporter.partial))
            return restore(adapter, *args, **kwargs)
        FakeAdapter.restore = spy
        try:
            with self.assertRaises(flows.RolledBack) as caught:
                self.restore()
        finally:
            FakeAdapter.restore = restore
        self.assertIn(('remove_fresh', 'woowbk-demo'), self.world.events)
        self.assertIsNone(caught.exception.result['safety_backup_id'])
        self.assertEqual(caught.exception.result['fresh_apps'], ['woowbk-demo'])
        self.assertEqual(self.safety_ids(), [])
        self.assertIn(('skip', 'safety'), self.reporter.events)
        # Review CR-05: recorded before the first fresh step, cleared once the job removed the deployment itself.
        self.assertEqual(seen[0].get('fresh_apps'), ['woowbk-demo'])
        self.assertEqual(self.reporter.partial['fresh_apps'], [])

    def test_rollback_failure_needs_manual_work(self):
        self.world.fail_restore_after['woowbk-demo'] = 1
        self.world.fail_rollback_restore.add('woowbk-demo')
        with self.assertRaises(BackupError) as caught:
            self.restore()
        error = caught.exception
        self.assertEqual(error.code, 'job-failed')
        self.assertIn('需人工處理', error.message)
        self.assertNotIn('。。', error.message)  # lab H5 showed "…（結束碼 125）。。可使用…"
        self.assertTrue(error.message.endswith(f'可使用還原前備份 {error.result["safety_backup_id"]} 再次還原。'))
        self.assertFalse(error.result['rolled_back'])
        self.assertTrue(error.result['safety_backup_id'])
        self.assert_staging_clean()

    def test_termination_during_a_fresh_restore_at_shutdown_keeps_the_cleanup_marker(self):
        # Review CR-05: the recovery after boot removes the partial fresh deployment.
        from woowbackup.jobs import Terminated
        self.deps.system_stopping = lambda: True
        self.world.mode['woowbk-demo'] = 'fresh'
        self.world.raise_after_destructive = Terminated(15)
        with self.assertRaises(Terminated):
            self.restore()
        self.assertNotIn(('remove_fresh', 'woowbk-demo'), self.world.events)
        self.assertEqual(self.reporter.partial['fresh_apps'], ['woowbk-demo'])

    def test_termination_during_shutdown_does_not_start_a_rollback(self):
        # Lab H5: a reboot during the restore sent SIGTERM; the rollback started while the owner's services were
        # going away and failed with a misleading "podman pull" error. Now the signal propagates (-> interrupted).
        from woowbackup.jobs import Terminated
        self.deps.system_stopping = lambda: True
        self.world.raise_after_destructive = Terminated(15)
        with self.assertRaises(Terminated):
            self.restore()
        self.assertNotIn(('add_phase', 'rollback'), self.reporter.events)
        self.assertEqual([e for e in self.world.events if e[0] == 'restore'],
                         [('restore', 'woowbk-demo', 'inplace', 'restore')])
        self.assertTrue(self.reporter.partial['safety_backup_id'])
        self.assertTrue(any('系統正在關機或重新開機' in line for line in self.reporter.logs))
        self.assert_staging_clean()

    def test_termination_while_the_system_runs_still_rolls_back(self):
        from woowbackup.jobs import Terminated
        self.deps.system_stopping = lambda: False
        self.world.raise_after_destructive = Terminated(15)
        with self.assertRaises(flows.RolledBack) as caught:
            self.restore()
        self.assertTrue(caught.exception.result['rolled_back'])
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v2-changed')

    def test_failures_roll_back_even_while_shutting_down(self):
        # Only termination signals skip the rollback; an ordinary failure is still rolled back.
        self.deps.system_stopping = lambda: True
        self.world.fail_restore_after['woowbk-demo'] = 1
        with self.assertRaises(flows.RolledBack):
            self.restore()

    def test_one_failing_rollback_does_not_stop_the_others(self):
        # Review CR-03: woowbk-demo's rollback fails; woowbk-two must still get its pre-restore data back.
        self.world.fail_restore_after['woowbk-two'] = 1
        self.world.fail_rollback_restore.add('woowbk-demo')
        with self.assertRaises(BackupError) as caught:
            self.restore(apps=['woowbk-demo', 'woowbk-two'])
        rollbacks = [e[1] for e in self.world.events if e[0] == 'restore' and e[3] == 'rollback']
        self.assertEqual(rollbacks, ['woowbk-demo', 'woowbk-two'])
        self.assertEqual(self.world.data['woowbk-two'], b'two-v2-changed')
        self.assertIn('需人工處理', caught.exception.message)
        self.assertIn('示範筆記應用', caught.exception.message)
        self.assertNotIn('第二個應用', caught.exception.message)

    def test_rollback_frees_the_extracted_archive_first(self):
        # Review CR-01: the failed archive's plaintext (and the safety plaintext) is gone before the rollback
        # extracts the safety backup, so the rollback has the space a successful safety backup needed.
        staging = self.storage.staging / self.job_id
        extract = self.archive.extract_archive
        present = []

        def spy(path, identities, dest_dir, **kwargs):
            present.append(sorted(p.name for p in staging.iterdir()))
            return extract(path, identities, dest_dir, **kwargs)
        self.archive.extract_archive = spy
        self.world.fail_restore_after['woowbk-demo'] = 1
        with self.assertRaises(flows.RolledBack):
            self.restore()
        self.assertEqual(present, [['extract'], ['rollback']])

    def test_no_restore_when_a_rollback_would_lack_space(self):
        # Review CR-01: with the safety backup taken, the rollback must fit; otherwise stop before any change.
        reserve = self.paths.reserve_bytes
        self.storage.free = reserve + 1000  # enough for the safety backup estimate check below
        self.world.estimate = 1
        free = iter([reserve + 10 ** 6, 10])

        def free_bytes():
            try:
                return next(free)
            except StopIteration:
                return 10
        self.storage.free_bytes = free_bytes
        with self.assertRaises(BackupError) as caught:
            self.restore()
        self.assertEqual(caught.exception.code, 'insufficient-space')
        self.assertIn('未做任何變更', caught.exception.message)
        self.assertNotIn('restore', [e[0] for e in self.world.events])
        self.assertEqual(len(self.safety_ids()), 1)
        self.assertIs(caught.exception.result['changed'], False)

    def test_safety_plaintext_is_removed_as_soon_as_it_is_published(self):
        staging = self.storage.staging / self.job_id
        names = []
        restore = FakeAdapter.restore

        def spy(adapter, *args, **kwargs):
            names.append(sorted(p.name for p in staging.iterdir()))
            return restore(adapter, *args, **kwargs)
        FakeAdapter.restore = spy
        try:
            self.restore()
        finally:
            FakeAdapter.restore = restore
        self.assertEqual(names, [['extract']])

    def test_multi_app_failure_rolls_back_every_touched_app(self):
        self.world.fail_restore_after['woowbk-two'] = 1
        with self.assertRaises(flows.RolledBack):
            self.restore(apps=['woowbk-demo', 'woowbk-two'])
        rollbacks = [e[1] for e in self.world.events if e[0] == 'restore' and e[3] == 'rollback']
        self.assertEqual(rollbacks, ['woowbk-demo', 'woowbk-two'])
        self.assertEqual(self.world.data, {'woowbk-demo': b'notes-v2-changed', 'woowbk-two': b'two-v2-changed'})

    def test_safety_backup_failure_aborts_without_changes(self):
        self.world.db_down.add('woowbk-demo')
        with self.assertRaises(BackupError) as caught:
            self.restore()
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertIn('無法建立還原前備份', caught.exception.message)
        self.assertNotIn('restore', [e[0] for e in self.world.events])
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v2-changed')

    def test_restoring_a_safety_backup_proceeds_when_no_new_safety_backup_is_possible(self):
        safety_id = self.restore()['safety_backup_id']  # creates a real safety backup of the current state
        self.world.data['woowbk-demo'] = b'broken-half-restored'
        self.world.db_down.add('woowbk-demo')
        self.world.events.clear()
        result = flows.run_restore(self.ctx(), {'backup_id': safety_id, 'apps': ['woowbk-demo']})
        self.assertIsNone(result['safety_backup_id'])
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v2-changed')
        self.assertIn(('ensure-db', 'woowbk-demo'), self.world.events)
        self.assertTrue(any('將直接還原' in line for line in self.reporter.logs))
        self.assertIn(safety_id, self.storage.index)
        # Review F1: the page must not claim a safety backup was made; the phase is skipped, not done.
        self.assertIs(result['safety_skipped'], True)
        self.assertIn(('skip', 'safety'), self.reporter.events)
        self.assertNotIn(('complete', 'safety'), self.reporter.events)

    def test_safety_failure_result_tells_the_page_why(self):
        self.world.db_down.add('woowbk-demo')
        with self.assertRaises(BackupError) as caught:
            self.restore()
        self.assertIs(caught.exception.result['safety_failed'], True)
        self.assertIs(caught.exception.result['changed'], False)
        self.assertIn('不建立還原前備份', caught.exception.message)

    def test_explicit_restore_without_a_safety_backup(self):
        # Review CR-16: an app whose database cannot start can still be restored from a manual or uploaded
        # backup once the user explicitly accepts that no rollback is possible.
        self.world.db_down.add('woowbk-demo')
        result = flows.run_restore(self.ctx(), {'backup_id': self.backup_id, 'apps': ['woowbk-demo'],
                                                'allow_no_safety': True})
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v1')
        self.assertIsNone(result['safety_backup_id'])
        self.assertIs(result['safety_skipped'], True)
        self.assertIn(('skip', 'safety'), self.reporter.events)
        self.assertTrue(any('你已選擇不建立還原前備份' in line for line in self.reporter.logs))
        self.assertEqual(self.safety_ids(), [])

    def test_verification_keeps_only_bounded_compared_values(self):
        # Review SEC-5: the archive's snapshot is untrusted; only compared keys, each bounded, reach the record.
        data = json.loads(self.storage.archive_path(self.backup_id).read_text())
        app = data['manifest']['apps'][0]
        app['verify_snapshot']['summary']['title'] = 'x' * 10000
        app['verify_snapshot']['summary']['extra'] = 'y' * 10000
        app['verify_snapshot']['other'] = {'big': 'z' * 10000}
        self.storage.archive_path(self.backup_id).write_text(json.dumps(data))
        with self.assertRaises(flows.RolledBack) as caught:  # title differs, so the data check fails
            self.restore()
        before = caught.exception.result['verification'][0]['before']
        self.assertEqual(set(before), {'summary'})
        self.assertEqual(set(before['summary']), {'notes', 'files', 'digest', 'title', 'signatures_valid'})
        self.assertEqual(before['summary']['title'], flows.OMITTED)
        self.assertLess(len(json.dumps(caught.exception.result, ensure_ascii=False)), 4000)

    def test_preflight_failure_changes_nothing(self):
        self.world.preflight_fail.add('woowbk-demo')
        with self.assertRaises(BackupError) as caught:
            self.restore()
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('localhost/x:1', caught.exception.message)
        self.assertEqual(self.world.events, [])
        self.assertEqual(self.safety_ids(), [])

    def test_cancel_honoured_until_preflight_only(self):
        ctx = self.ctx()
        self.reporter.cancel = True
        with self.assertRaises(flows.Cancelled):
            flows.run_restore(ctx, {'backup_id': self.backup_id, 'apps': ['woowbk-demo']})
        self.assertEqual(self.world.events, [])
        self.assert_staging_clean()

    def test_key_required_and_temporary_key(self):
        self.keys.device = None
        with self.assertRaises(BackupError) as caught:
            self.restore()
        self.assertEqual(caught.exception.code, 'key-required')
        self.assertEqual(self.archive.extracts, [])

    def test_inplace_needs_device_key_for_safety(self):
        # Archive encrypted for an imported key; the device has no key of its own.
        self.keys.import_key(TEST_SECRET)
        data = json.loads(self.storage.archive_path(self.backup_id).read_text())
        data['header']['key_id'] = TEST_SECRET_ID
        self.storage.archive_path(self.backup_id).write_text(json.dumps(data))
        self.keys.device = None
        with self.assertRaises(BackupError) as caught:
            self.restore()
        self.assertEqual(caught.exception.code, 'no-device-key')
        self.world.mode['woowbk-demo'] = 'fresh'
        result = self.restore()
        self.assertIsNone(result['safety_backup_id'])

    def test_app_missing_from_archive_or_catalog(self):
        with self.assertRaises(BackupError) as caught:
            self.restore(apps=['not-here'])
        self.assertEqual(caught.exception.code, 'app-not-in-catalog')
        manifest_path = self.storage.archive_path(self.backup_id)
        data = json.loads(manifest_path.read_text())
        data['manifest']['apps'] = data['manifest']['apps'][:1]
        manifest_path.write_text(json.dumps(data))
        with self.assertRaises(BackupError) as caught:
            self.restore(apps=['woowbk-two'])
        self.assertEqual(caught.exception.code, 'incompatible')


class DeltaReviewFlowTests(RestoreFlowTests):
    """Delta review findings HD-01, HD-04, HD-06 and HD-09 at the flow level."""

    def fresh_markers(self):
        return [item['fresh_apps'] for item in self.reporter.partials if 'fresh_apps' in item]

    def test_hd04_an_app_leaves_the_fresh_marker_once_its_import_finished(self):
        # The finding's probe: fresh restore of woowbk-demo, then woowbk-two; a shutdown signal arrives in
        # woowbk-two after its destructive step. woowbk-demo was complete (and starts at boot): never removed.
        from woowbackup.jobs import Terminated
        self.deps.system_stopping = lambda: True
        self.world.mode.update({'woowbk-demo': 'fresh', 'woowbk-two': 'fresh'})
        self.world.raise_in['woowbk-two'] = Terminated(15)
        with self.assertRaises(Terminated):
            self.restore(apps=['woowbk-demo', 'woowbk-two'])
        self.assertIn(('imported', 'woowbk-demo'), self.world.events)
        self.assertEqual(self.fresh_markers(), [['woowbk-demo', 'woowbk-two'], ['woowbk-two']])
        self.assertEqual(self.reporter.partial['fresh_apps'], ['woowbk-two'], 'kept for the recovery after boot')
        # What the recovery then does with an older record that still lists both apps: the complete one runs.
        self.world.fresh_live = {'woowbk-demo': ['woowbk-demo-app.service']}
        self.world.events.clear()
        problems = flows.remove_fresh_apps(self.deps, ['woowbk-demo', 'woowbk-two'])
        self.assertEqual([e for e in self.world.events if e[0] == 'remove_fresh'], [('remove_fresh', 'woowbk-two')])
        self.assertEqual(len(problems), 1)
        self.assertIn('示範筆記應用', problems[0])
        self.assertIn('需人工確認', problems[0])
        self.world.fresh_live_error = {'woowbk-two'}
        self.world.events.clear()
        problems = flows.remove_fresh_apps(self.deps, ['woowbk-two'])
        self.assertEqual(self.world.events, [], 'a state that cannot be read is never "unfinished"')
        self.assertIn('需人工確認', problems[0])

    def test_hd04_a_rollback_lists_the_fresh_app_again_before_removing_it(self):
        self.world.mode['woowbk-demo'] = 'fresh'
        self.world.unhealthy['woowbk-demo'] = 'fail'
        with self.assertRaises(flows.RolledBack):
            self.restore()
        self.assertIn(('remove_fresh', 'woowbk-demo'), self.world.events)
        self.assertEqual(self.fresh_markers(), [['woowbk-demo'], [], ['woowbk-demo'], []])

    def test_hd01_the_job_preflight_checks_the_extracted_archive_before_the_safety_backup(self):
        self.world.preflight_fail.add('woowbk-demo')
        with self.assertRaises(BackupError):
            self.restore()
        self.assertEqual(self.world.preflight_dirs, [self.storage.staging / self.job_id / 'extract'])
        self.assertEqual(self.safety_ids(), [], 'refused before the safety backup')

    def test_hd06_an_unqueryable_database_may_be_rebuilt_only_without_a_safety_backup(self):
        self.restore()
        self.assertEqual(self.world.unchecked, [('woowbk-demo', False)])
        self.world.unchecked.clear()
        self.world.db_down.add('woowbk-demo')  # no safety backup possible; the user accepted restoring anyway
        flows.run_restore(self.ctx(), {'backup_id': self.backup_id, 'apps': ['woowbk-demo'], 'allow_no_safety': True})
        self.assertEqual(self.world.unchecked, [('woowbk-demo', True)])

    def test_hd09_what_an_adapter_could_not_keep_reaches_the_result(self):
        note = '資料卷 data 有 1 個檔案的 setuid／setgid 權限在還原時會被移除（例如 bin/helper）。'
        self.world.restore_warnings['woowbk-demo'] = [note]
        result = self.restore()
        self.assertEqual(result['warnings'], [note])
        self.world.fail_restore_after['woowbk-two'] = 1
        self.world.restore_warnings['woowbk-two'] = [note]
        with self.assertRaises(flows.RolledBack) as caught:
            self.restore(apps=['woowbk-demo', 'woowbk-two'])
        self.assertEqual(caught.exception.result['warnings'], [note])


class SafetyPruneTests(FlowCase):
    def add(self, backup_id, created, apps, kind='safety'):
        self.storage.ensure_layout()
        self.storage.archive_path(backup_id).write_text('{}')
        self.storage.index[backup_id] = {'id': backup_id, 'type': kind, 'created': created,
                                         'apps': [{'id': a, 'name': a} for a in apps], 'size': 2}

    def test_keep_three_newest_per_app(self):
        for i in range(1, 6):
            self.add(f'2026110{i}T000000Z-0000000{i}', f'2026-11-0{i}T00:00:00Z', ['woowbk-demo'])
        self.add('20261020T000000Z-000000aa', '2026-10-20T00:00:00Z', ['woowbk-two'])
        self.add('20261021T000000Z-000000bb', '2026-10-21T00:00:00Z', ['woowbk-demo'], kind='manual')
        self.add('20261022T000000Z-000000cc', '2026-10-22T00:00:00Z', ['woowbk-demo', 'woowbk-two'])
        flows.prune_safety(self.ctx(), ['woowbk-demo'])
        remaining = sorted(self.storage.index)
        self.assertEqual(remaining, ['20261020T000000Z-000000aa', '20261021T000000Z-000000bb',
                                     '20261022T000000Z-000000cc', '20261103T000000Z-00000003',
                                     '20261104T000000Z-00000004', '20261105T000000Z-00000005'])

    def test_prune_after_success_keeps_this_restores_safety_backup_despite_clock_skew(self):
        # Review SEC-2/CR-02: three safety backups dated in the future (clock went backwards). The new safety
        # backup sorts oldest; it must survive, and a failing restore must still be able to roll back with it.
        backup_id = self.backup()['backup_id']
        for day in (1, 2, 3):
            self.add(f'2026120{day}T000000Z-0000000{day}', f'2026-12-0{day}T00:00:00Z', ['woowbk-demo'])
        self.world.data['woowbk-demo'] = b'notes-v2-changed'
        result = flows.run_restore(self.ctx(), {'backup_id': backup_id, 'apps': ['woowbk-demo']})
        self.assertIn(result['safety_backup_id'], self.storage.index)
        self.world.data['woowbk-demo'] = b'notes-v3-newest'
        self.world.fail_restore_after['woowbk-demo'] = 1
        with self.assertRaises(flows.RolledBack) as caught:
            flows.run_restore(self.ctx(), {'backup_id': backup_id, 'apps': ['woowbk-demo']})
        self.assertIn(caught.exception.result['safety_backup_id'], self.storage.index)
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v3-newest')

    def test_failed_restores_never_prune(self):
        backup_id = self.backup()['backup_id']
        for _ in range(4):
            flows.run_restore(self.ctx(), {'backup_id': backup_id, 'apps': ['woowbk-demo']})
        deleted = list(self.storage.deleted)
        self.world.fail_restore_after['woowbk-demo'] = 1
        with self.assertRaises(flows.RolledBack):
            flows.run_restore(self.ctx(), {'backup_id': backup_id, 'apps': ['woowbk-demo']})
        self.assertEqual(self.storage.deleted, deleted)

    def test_safety_backup_of_a_failed_restore_is_pinned(self):
        # Review CR-02b: retries after a failed restore must not prune the only good pre-restore backup S1.
        from woowbackup import jobs
        for i in range(1, 6):
            self.add(f'2026110{i}T000000Z-0000000{i}', f'2026-11-0{i}T00:00:00Z', ['woowbk-demo'])
        store = jobs.JobStore(self.paths)
        record = store.create('restore', {'backup_id': '20261101T000000Z-00000001', 'apps': ['woowbk-demo']})
        record.update(state='failed', result={'apps': ['woowbk-demo'], 'safety_backup_id': '20261101T000000Z-00000001',
                                             'rolled_back': False})
        store.save(record)
        flows.prune_safety(self.ctx(), ['woowbk-demo'])
        self.assertIn('20261101T000000Z-00000001', self.storage.index)
        self.assertNotIn('20261102T000000Z-00000002', self.storage.index)
        # A later successful restore of the app settles it: the old safety backup may be pruned again.
        later = store.create('restore', {'backup_id': 'x', 'apps': ['woowbk-demo']}, now=__import__('time').time() + 60)
        later.update(state='succeeded')
        store.save(later)
        flows.prune_safety(self.ctx(), ['woowbk-demo'])
        self.assertNotIn('20261101T000000Z-00000001', self.storage.index)

    def test_prune_never_deletes_the_backup_being_restored(self):
        for i in range(1, 5):
            self.add(f'2026110{i}T000000Z-0000000{i}', f'2026-11-0{i}T00:00:00Z', ['woowbk-demo'])
        flows.prune_safety(self.ctx(), ['woowbk-demo'], exclude={'20261101T000000Z-00000001'})
        self.assertIn('20261101T000000Z-00000001', self.storage.index)
        self.assertEqual(len(self.storage.index), 4)

    def test_restore_prunes_to_three(self):
        backup_id = self.backup()['backup_id']
        for _ in range(4):
            flows.run_restore(self.ctx(), {'backup_id': backup_id, 'apps': ['woowbk-demo']})
        safety = [m for m in self.storage.list_backups() if m['type'] == 'safety']
        self.assertEqual(len(safety), 3)
        self.assertEqual(len(self.storage.deleted), 1)


class CompareTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        paths = Paths(base=Path(tmp.name))
        self.app = catalog.validate_entry(demo_entry(paths), paths=paths, user_lookup=user_lookup)

    def test_compare_semantics(self):
        before = {'summary': {'notes': 1, 'files': 2, 'digest': 'x', 'title': 't', 'signatures_valid': True}}
        self.assertIs(flows.compare_snapshots(self.app, before, copy.deepcopy(before)), True)
        changed = copy.deepcopy(before)
        changed['summary']['digest'] = 'y'
        self.assertIs(flows.compare_snapshots(self.app, before, changed), False)
        self.assertIs(flows.compare_snapshots(self.app, before, {}), False)
        self.assertIsNone(flows.compare_snapshots(self.app, {}, before))
        self.assertIsNone(flows.compare_snapshots(self.app, {'other': {'notes': 1}}, before))
        extra = copy.deepcopy(before)
        extra['summary']['uptime'] = 5
        self.assertIs(flows.compare_snapshots(self.app, before, extra), True)

    def test_created_from_id(self):
        self.assertEqual(flows.created_from_id('20261113T020000Z-a1b2c3d4'), '2026-11-13T02:00:00Z')


if __name__ == '__main__':
    unittest.main()
