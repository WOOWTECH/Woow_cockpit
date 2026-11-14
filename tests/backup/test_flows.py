"""Backup / restore / verify orchestration with fakes for storage, keys, archive and adapters.

Covers: phases and cancellable windows, space check before stopping writers (F6), dump failure
(F7), safety backup + automatic rollback (F8), fresh-mode cleanup, rollback failure guidance,
verification comparison, keep-3 safety pruning, key-required, and staging cleanup.
"""
import base64
import contextlib
import copy
import errno
import hashlib
import json
import os
import shutil
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

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

    def fail(self, phase_id):
        self.events.append(('fail', phase_id))

    def mark(self, phase_id, state):
        self.events.append(('mark', phase_id, state))

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
        self.pending = self.root / 'pending'
        self.index, self.free, self.counter = {}, free, 0
        self.deleted, self.updates, self.removed_staging, self.removed_pending = [], [], [], []
        self.uploads = {}

    def ensure_layout(self):
        for path in (self.archives, self.staging, self.pending):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)

    def new_backup_id(self, now=None):
        self.counter += 1
        return f'20261113T0200{self.counter:02d}Z-{self.counter:08x}'

    def archive_path(self, backup_id, fmt=None):
        return self.archives / f'{backup_id}{".woowbackup" if fmt == 1 else ".tar"}'

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

    def pending_path(self, job_id):
        return self.pending / job_id

    def pending_dir(self, job_id):
        path = self.pending_path(job_id)
        assert not os.path.lexists(path), 'a pending copy is never replaced'
        self.ensure_layout()
        path.mkdir(mode=0o700)
        return path

    def remove_pending(self, job_id):
        shutil.rmtree(self.pending / job_id, ignore_errors=True)
        self.removed_pending.append(job_id)

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
        self.deep_corrupt = set()  # archive names whose deep check (nested tars) fails
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
            if hashlib.sha256(data).hexdigest() != entry.sha256 or len(data) != entry.size:  # like archive._add_entries
                raise BackupError('internal-error', '封裝時來源檔案的校驗值與記錄不符。', entry=entry.path)
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
        if data['header'].get('encryption') != 'none':
            if not identities:
                raise BackupError('key-required', '需要備份金鑰。')
            if data['header']['key_id'] not in self._key_ids(identities):
                raise BackupError('wrong-key', '金鑰不正確。')
        if str(path) in self.corrupt or Path(path).name in self.corrupt:
            raise BackupError('corrupt-archive', '備份檔已損毀或遭到修改，無法使用。')
        return data

    @staticmethod
    def _select(manifest, apps):
        """Like the real readers: only the selected apps (incompatible when one is missing)."""
        if apps is None:
            return manifest
        for app_id in apps:
            if app_id not in {app['id'] for app in manifest['apps']}:
                raise BackupError('incompatible', f'此備份不包含應用「{app_id}」。', app=app_id)
        return dict(manifest, apps=[a for a in manifest['apps'] if a['id'] in apps],
                    entries=[e for e in manifest['entries'] if e['path'].split('/')[1] in apps])

    def read_manifest(self, path, identities, *, limits=None, apps=None):
        return self._select(self._open(path, identities)['manifest'], apps)

    def verify_archive(self, path, identities, *, progress=None, limits=None, apps=None, deep=None, scratch_dir=None):
        data = self._open(path, identities)
        self.verifies.append(Path(path))
        self.verify_limits = limits
        if deep is not None:
            assert scratch_dir is not None and Path(scratch_dir).is_dir()
            deep.start(data['manifest']['apps'])
            if str(path) in self.deep_corrupt or Path(path).name in self.deep_corrupt:
                raise BackupError('corrupt-archive', '應用「示範」的資料卷 data 未通過還原前的內容檢查（指向資料卷外的符號連結）；'
                                                     '這份備份無法還原。', check='volumes')
        if progress:
            progress(1, 1)
        return {'manifest': data['manifest'], 'entries': len(data['files']),
                'bytes': sum(e['size'] for e in data['manifest']['entries']),
                'format': data['manifest'].get('format', 1),
                'encryption': data['header'].get('encryption', 'age-x25519')}

    def extract_archive(self, path, identities, dest_dir, *, progress=None, limits=None, apps=None):
        dest_dir = Path(dest_dir)
        assert dest_dir.is_dir() and not any(dest_dir.iterdir()) and dest_dir.stat().st_mode & 0o077 == 0
        data = self._open(path, identities)
        manifest = self._select(data['manifest'], apps)
        wanted = {e['path'] for e in manifest['entries']}
        for rel, blob in data['files'].items():
            if rel not in wanted:
                continue
            target = dest_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(base64.b64decode(blob))
        self.extracts.append((Path(path), dest_dir, None if apps is None else list(apps)))
        if progress:
            progress(1, 1)
        return manifest


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
        self.keep_stopped_drops_snapshot = False  # like the real adapter: a kept-stopped safety backup has no snapshot
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
        self.finish_notes = {}    # (app id, 'restore'|'rollback') -> notes finish_dirs() returns
        self.finish_raises = {}   # (app id, 'restore'|'rollback') -> exception finish_dirs() raises
        self.discard_problems = {}  # app id -> problems discard_dirs() returns
        self.leftover_notes = {}  # app id -> notes dir_leftovers() returns
        self.recover_notes = {}   # app id -> notes recover_dirs() returns
        self.digest_results = {}  # app id -> digest checks its restore() compared (adapter.digest_results)
        self.fail_stage = set()   # app ids whose stage_dirs() fails

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
        self.job_id = None
        self.run = None
        self.kept_stopped = []
        self.taken_over = None
        self.staged = False
        self.timing = {}
        self.digest_results = []

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

    def backup(self, staging_dir, *, include_images, keep_stopped=False):
        self.world.events.append(('backup', self.app.id))
        self.phase('stop')
        self.writers_hook(list(self.app.writer_units))
        self.timing = {'first_stop': 100.0}
        if self.world.hook_probe:
            self.world.hook_probe()
        self.phase('dump')
        if self.app.id in self.world.fail_backup:
            self.phase('start')
            self.writers_hook([])
            raise BackupError('job-failed', 'pg_dump 執行失敗（結束碼 1）。')
        self.phase('export')
        data = self.world.data[self.app.id]
        # Like the real adapter: a staged file lies at <staging root>/<entry path> (staging_dir is <root>/apps/<id>).
        (Path(staging_dir) / 'volumes').mkdir(mode=0o700, exist_ok=True)
        source = Path(staging_dir) / 'volumes' / 'data.tar'
        source.write_bytes(data)
        if keep_stopped:  # like the real adapter: the restore that follows takes the stopped writers over
            self.kept_stopped = list(self.app.writer_units)
            self.world.events.append(('kept-stopped', self.app.id))
        else:
            self.phase('start')
            self.writers_hook([])
            self.timing.update(started=102.4, healthy=105.0)
        self.last_downtime = 0.0 if keep_stopped else 2.4
        if self.world.after_backup:
            self.world.after_backup()
        entry = Entry(f'apps/{self.app.id}/volumes/data.tar', source, len(data), hashlib.sha256(data).hexdigest())
        manifest = {'id': self.app.id, 'name': self.app.name, 'adapter': 'quadlet-postgres', 'adapter_version': 1,
                    'catalog_sha256': self.app.sha256, 'owner': {'name': 'appowner', 'uid': 1001},
                    'images': [{'ref': 'localhost/x:1', 'id': 'sha256:' + 'a' * 64, 'digest': '', 'arch': 'amd64'}],
                    'postgres': [], 'volumes': [{'name': 'data', 'entry': entry.path}], 'secrets': [],
                    'config_files': [], 'quadlet_files': [], 'verify_snapshot': snapshot_of(data)}
        if keep_stopped and self.world.keep_stopped_drops_snapshot:
            manifest['verify_snapshot'] = {}
        return manifest, [entry]

    def preflight(self, app_manifest, *, mode, entry_sizes=None, extracted_dir=None):
        self.world.preflight_dirs.append(extracted_dir)
        if self.app.id in self.world.preflight_fail:
            return [{'id': f'{self.app.id}/image', 'status': 'fail', 'message': '缺少映像 localhost/x:1。'}]
        return [{'id': f'{self.app.id}/items', 'status': 'ok', 'message': '項目齊全。'},
                {'id': f'{self.app.id}/catalog', 'status': 'warn', 'message': '設定與備份時不同。'}]

    def restore(self, app_manifest, extracted_dir, *, mode, rollback=False, unchecked_databases_ok=False,
                replaced_dirs=()):
        assert rollback == (self.phase is noop), 'rollbacks (and only they) use rollback=True and no phases'
        self.world.events.append(('restore', self.app.id, mode, 'rollback' if rollback else 'restore'))
        if rollback:
            self.world.events.append(('replaced_dirs', self.app.id, tuple(sorted(replaced_dirs))))
        self.run = 'rollback' if rollback else 'restore'
        if not rollback:
            self.world.unchecked.append((self.app.id, unchecked_databases_ok))
        if self.app.id in self.world.fail_restore_before:
            raise BackupError('incompatible', '映像載入失敗。')
        self.phase('stop')
        self.destructive_started = True
        if mode == 'inplace' and not rollback:
            self.writers_hook(list(self.app.units))
            self.writers_hook([])  # stopped and masked: the restore owns the stopped state (like the real adapter)
        self.phase('restore')
        self.digest_results = list(self.world.digest_results.get(self.app.id, [])) if not rollback else []
        if not rollback and any(item.get('match') is False for item in self.digest_results):
            raise BackupError('job-failed', f'應用「{self.app.name}」還原後的資料與備份時不一致：資料摘要不同。')
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

    def take_over(self, units, first_stop):
        self.world.events.append(('take_over', self.app.id, tuple(units)))
        self.taken_over = (list(units), first_stop)
        self.timing['first_stop'] = first_stop

    def stage_dirs(self, app_manifest, extracted_dir, *, mode):
        self.world.events.append(('stage_dirs', self.app.id, mode))
        if self.app.id in self.world.fail_stage:
            raise BackupError('job-failed', '無法寫入主機資料夾。')
        self.staged = True

    def timing_report(self):
        first, started, healthy = (self.timing.get(key) for key in ('first_stop', 'started', 'healthy'))
        return {'writer_pause_seconds': None if None in (first, started) else round(started - first, 1),
                'unavailable_seconds': None if None in (first, healthy) else round(healthy - first, 1)}

    def swapped_dirs(self):
        # Like the real adapter: what its restore swapped (all of the app's directories once it got that far).
        return {item['path'] for item in self.app.data_dirs} if self.destructive_started else set()

    def start_units(self, units):
        self.world.events.append(('start_units', self.app.id, tuple(units)))
        return [u for u in units if u in self.world.unstartable]

    def finish_dirs(self):
        self.world.events.append(('finish_dirs', self.app.id, self.run, self.job_id))
        error = self.world.finish_raises.get((self.app.id, self.run))
        if error is not None:
            raise error
        return list(self.world.finish_notes.get((self.app.id, self.run), []))

    def discard_dirs(self):
        self.world.events.append(('discard_dirs', self.app.id, self.run))
        problems = self.world.discard_problems.get(self.app.id, [])
        if isinstance(problems, BaseException):
            raise problems
        return list(problems)

    def dir_leftovers(self):
        notes = self.world.leftover_notes.get(self.app.id, [])
        if isinstance(notes, BaseException):
            raise notes
        return list(notes)

    def recover_dirs(self):
        self.world.events.append(('recover_dirs', self.app.id, self.job_id))
        notes = self.world.recover_notes.get(self.app.id, [])
        if isinstance(notes, BaseException):
            raise notes
        return list(notes)

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
        if status == 'ok' and self.run == 'restore':
            self.timing.update(started=110.0, healthy=112.5)
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
        self.assertEqual(meta['filename'], 'woowtech-backup-dev-a-20261113-020001.tar')
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
                         [f'{result["backup_id"]}.tar'])

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
        self.archive.on_write = lambda: self.archive.corrupt.add('20261113T020001Z-00000001.tar')
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
        self.assertEqual({k: result[k] for k in ('ok', 'entries', 'bytes', 'deep', 'format', 'encrypted')},
                         {'ok': True, 'entries': 1, 'bytes': len(b'notes-v1'), 'deep': True, 'format': 2,
                          'encrypted': True})
        self.assertEqual([app['id'] for app in result['apps']], ['woowbk-demo'])
        self.assertEqual(self.reporter.phases(), ['prepare', 'decrypt', 'check'])
        self.assertEqual({k: v for k, v in self.storage.index[self.backup_id]['verified'].items() if k != 'at'},
                         {'ok': True, 'deep': True})
        self.assertIn(self.job_id, self.storage.removed_staging, 'the scratch directory goes with the staging')

    def test_the_scratch_copies_leave_the_larger_reserve_free(self):
        # review M4: the verify job copies entries while every app runs: at least 2 GiB stay free, not 512 MiB
        flows.run_verify(self.ctx(), {'backup_id': self.backup_id})
        self.assertGreaterEqual(self.archive.verify_limits.reserve_bytes, 2 * 1024 ** 3)
        self.assertLessEqual(self.archive.verify_limits.reserve_bytes, 10 * 1024 ** 3)

    def test_deep_check_failure_marks_index_failed(self):
        # Feature 4: a nested tar a restore would refuse makes the verify job fail (未通過), not 已驗證.
        self.archive.deep_corrupt.add(self.storage.archive_path(self.backup_id).name)
        with self.assertRaises(BackupError) as caught:
            flows.run_verify(self.ctx(), {'backup_id': self.backup_id})
        self.assertEqual(caught.exception.code, 'corrupt-archive')
        self.assertEqual({k: v for k, v in self.storage.index[self.backup_id]['verified'].items() if k != 'at'},
                         {'ok': False, 'deep': True})

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


class RestoreCase(FlowCase):
    """A backup of both apps whose data changed afterwards: what an in-place restore brings back."""

    def setUp(self):
        super().setUp()
        self.backup_id = self.backup(apps=['woowbk-demo', 'woowbk-two'])['backup_id']
        self.world.data.update({'woowbk-demo': b'notes-v2-changed', 'woowbk-two': b'two-v2-changed'})
        self.world.events.clear()

    def restore(self, apps=('woowbk-demo',), key_file=None):
        return flows.run_restore(self.ctx(key_file=key_file), {'backup_id': self.backup_id, 'apps': list(apps)})

    def safety_ids(self):
        return [m['id'] for m in self.storage.list_backups() if m['type'] == 'safety']

    def pending(self):
        return self.storage.pending / self.job_id

    def safety_files(self, backup_id):
        """{entry path: bytes} of a backup written by the fake archive."""
        data = json.loads(self.storage.archive_path(backup_id).read_text())
        return {path: base64.b64decode(blob) for path, blob in data['files'].items()}


class RestoreFlowTests(RestoreCase):
    def test_inplace_success(self):
        result = self.restore()
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v1')
        # 2026.11.14.2: the pre-restore copy is packaged into the safety backup after the check, outside the outage.
        self.assertEqual(self.reporter.phases(), ['prepare', 'decrypt', 'preflight', 'safety', 'stop', 'restore',
                                                  'start', 'check', 'safety-package'])
        safety = self.safety_ids()
        self.assertEqual(len(safety), 1)
        self.assertEqual(result['safety_backup_id'], safety[0])
        self.assertIs(result['safety_pending'], False)
        self.assertEqual(self.reporter.partial, {'safety_backup_id': safety[0], 'safety_pending': False,
                                                 'stopped_writers': {}, 'finishing': True})
        self.assertEqual(self.safety_files(safety[0]), {'apps/woowbk-demo/volumes/data.tar': b'notes-v2-changed'})
        self.assertFalse(self.pending().exists(), 'the copy goes once its safety backup is registered')
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
        # 2026.11.14.2: the rollback reads the pre-restore copy as it is (nothing is extracted but the source backup),
        # and the copy becomes the safety backup afterwards.
        self.assertEqual([item[0] for item in self.archive.extracts], [self.storage.archive_path(self.backup_id)])
        self.assertEqual(self.safety_files(rolled.result['safety_backup_id']),
                         {'apps/woowbk-demo/volumes/data.tar': b'notes-v2-changed'})
        self.assertFalse(self.pending().exists())
        self.assert_staging_clean()

    def test_a_rollback_without_comparable_values_says_it_compared_no_data(self):
        # review F16: the kept-stopped safety backup of an http-json-only app stores no snapshot; its rollback passes
        # on the health checks alone and the result says so instead of implying a data check
        self.world.keep_stopped_drops_snapshot = True
        self.world.fail_restore_after['woowbk-demo'] = 1
        with self.assertRaises(flows.RolledBack) as caught:
            self.restore()
        self.assertTrue(caught.exception.result['rolled_back'])
        self.assertTrue(any('未比對資料' in note for note in caught.exception.result['warnings']),
                        caught.exception.result['warnings'])
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v2-changed')

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
        # 2026.11.14.2: nothing changed, so the pre-restore copy is deleted instead of becoming a safety backup.
        self.assertIsNone(result['safety_backup_id'])
        self.assertEqual(self.safety_ids(), [])
        self.assertFalse(self.pending().exists())
        self.assertEqual((result['safety_pending'], self.reporter.partial['safety_pending']), (False, False))
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
        # 2026.11.14.2: no packaging either; the copy and its flag stay for the recovery after boot.
        self.assertIs(self.reporter.partial['safety_pending'], True)
        self.assertNotIn('safety_backup_id', self.reporter.partial)
        self.assertEqual(self.safety_ids(), [])
        self.assertTrue((self.pending() / 'pending.json').is_file())
        self.assertTrue(any('系統正在關機或重新開機' in line and '封裝成還原前備份' in line for line in self.reporter.logs))
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
        # Review CR-01: the failed archive's plaintext is gone before the rollback packages the pre-restore copy, so
        # the packaging has the space the space check counted on. 2026.11.14.2: nothing else is extracted.
        staging = self.storage.staging / self.job_id
        write = self.archive.write_archive
        present = []

        def spy(dest, *args, **kwargs):
            present.append(sorted(p.name for p in staging.iterdir()))
            return write(dest, *args, **kwargs)
        self.archive.write_archive = spy
        self.world.fail_restore_after['woowbk-demo'] = 1
        with self.assertRaises(flows.RolledBack):
            self.restore()
        self.assertEqual(present, [[]])
        self.assertEqual(len(self.archive.extracts), 1, 'only the source backup was extracted')

    def test_no_restore_when_the_copy_could_not_be_packaged_afterwards(self):
        # Review CR-01, 2026.11.14.2: with the pre-restore copy taken, its packaging after the restore must fit;
        # otherwise stop before any change: the writers start again and the copy (not the only one) is deleted.
        reserve = self.paths.reserve_bytes
        self.storage.free = reserve + 1000  # enough for the safety copy's estimate check below
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
        self.assertIn('空間不足以在還原後封裝還原前備份', caught.exception.message)
        self.assertIn('未做任何變更', caught.exception.message)
        self.assertNotIn('restore', [e[0] for e in self.world.events])
        self.assertIn(('start_units', 'woowbk-demo', ('woowbk-demo-app.service',)), self.world.events)
        self.assertEqual(self.safety_ids(), [])
        self.assertFalse(self.pending().exists())
        self.assertEqual([item.get('safety_pending') for item in self.reporter.partials if 'safety_pending' in item],
                         [True, False])
        self.assertIs(caught.exception.result['changed'], False)

    def test_the_pre_restore_copy_lies_outside_staging_while_the_restore_runs(self):
        # 2026.11.14.2: the copy is in pending/<job>/ (durable, flushed, with its record), not in the job's staging.
        staging = self.storage.staging / self.job_id
        names = []
        restore = FakeAdapter.restore

        def spy(adapter, *args, **kwargs):
            names.append((sorted(p.name for p in staging.iterdir()), sorted(p.name for p in self.pending().iterdir())))
            return restore(adapter, *args, **kwargs)
        FakeAdapter.restore = spy
        try:
            self.restore()
        finally:
            FakeAdapter.restore = restore
        self.assertEqual(names, [(['extract'], ['data', 'pending.json'])])

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


class HostDirFlowTests(RestoreFlowTests):
    """flows around the adapters' host-directory steps: the record marker, finishing only after success, the
    rollback's own siblings, reporting what stays, and the recovery entry point."""

    def setUp(self):
        super().setUp()
        entry = demo_entry(self.paths)
        entry['data_dirs'] = [{'path': 'woowbk-demo-data', 'label': '資料'}]
        self.catalog['woowbk-demo'] = catalog.validate_entry(entry, paths=self.paths, user_lookup=user_lookup)

    def events(self, *kinds):
        return [e for e in self.world.events if e[0] in kinds]

    def test_inplace_success(self):  # the inherited restore cases all run with a host directory declared too
        result = self.restore()
        self.assertEqual(self.reporter.partial, {'safety_backup_id': result['safety_backup_id'], 'safety_pending': False,
                                                 'stopped_writers': {}, 'dir_apps': [], 'finishing': True})
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v1')

    def test_marker_before_the_first_copy_and_finish_after_success_only(self):
        seen = []
        restore = FakeAdapter.restore

        def spy(adapter, *args, **kwargs):
            seen.append(dict(self.reporter.partial))
            return restore(adapter, *args, **kwargs)
        FakeAdapter.restore = spy
        self.world.finish_notes[('woowbk-demo', 'restore')] = []
        try:
            result = self.restore(apps=('woowbk-demo', 'woowbk-two'))
        finally:
            FakeAdapter.restore = restore
        self.assertEqual(seen[0].get('dir_apps'), ['woowbk-demo'], 'only apps with host directories, before any copy')
        self.assertEqual(self.reporter.partial['dir_apps'], [], 'settled in-process')
        finishes = self.events('finish_dirs')
        self.assertEqual(finishes, [('finish_dirs', 'woowbk-demo', 'restore', self.job_id),
                                    ('finish_dirs', 'woowbk-two', 'restore', self.job_id)])
        last_check = max(i for i, e in enumerate(self.world.events) if e[0] == 'restore')
        self.assertGreater(self.world.events.index(finishes[0]), last_check, 'after every app was restored and checked')
        self.assertEqual(result['warnings'], [])
        self.assertTrue(all(adapter.job_id == self.job_id for adapter in self.world.adapters))

    def test_failure_discards_rolls_back_and_finishes_only_the_verified_rollback(self):
        self.world.fail_restore_after['woowbk-demo'] = 1
        kept = '主機資料夾 ~/woowbk-demo-data 在還原前的原內容保留在 ~/woowbk-demo-data.woowbk-old-x'
        self.world.finish_notes[('woowbk-demo', 'rollback')] = [kept]
        with self.assertRaises(flows.RolledBack) as caught:
            self.restore()
        self.assertEqual(self.events('discard_dirs', 'finish_dirs'), [
            ('discard_dirs', 'woowbk-demo', 'restore'),
            ('finish_dirs', 'woowbk-demo', 'rollback', self.job_id)], 'the failed restore is never finished')
        self.assertIn(kept, caught.exception.result['warnings'])
        self.assertTrue(any(kept in line for line in self.reporter.logs))
        self.assertEqual(self.reporter.partial['dir_apps'], [])

    def test_a_failed_rollback_names_where_the_copies_are(self):
        self.world.fail_restore_after['woowbk-demo'] = 1
        self.world.fail_rollback_restore.add('woowbk-demo')
        note = '主機資料夾 ~/woowbk-demo-data 旁留有這次還原的資料夾：~/woowbk-demo-data.woowbk-old-x'
        self.world.leftover_notes['woowbk-demo'] = [note]
        with self.assertRaises(BackupError) as caught:
            self.restore()
        self.assertIn('需人工處理', caught.exception.message)
        self.assertIn(note, caught.exception.result['warnings'])
        self.assertEqual([e[2] for e in self.events('discard_dirs')], ['restore', 'rollback'])
        self.assertEqual(self.events('finish_dirs'), [])

    def test_a_discard_problem_makes_the_rollback_incomplete(self):
        self.world.fail_restore_after['woowbk-demo'] = 1
        self.world.discard_problems['woowbk-demo'] = ['主機資料夾 ~/woowbk-demo-data：無法移回']
        with self.assertRaises(BackupError) as caught:
            self.restore()
        self.assertIn('無法移回', caught.exception.message)
        self.assertFalse(caught.exception.result['rolled_back'])
        self.assertEqual(self.reporter.partial['dir_apps'], ['woowbk-demo'],
                         'kept: the next recovery pass settles the directories again')

    def test_the_rollback_knows_which_directories_the_failed_restore_swapped(self):
        self.world.fail_restore_after['woowbk-demo'] = 1
        with self.assertRaises(flows.RolledBack):
            self.restore()
        self.assertEqual(self.events('replaced_dirs'), [('replaced_dirs', 'woowbk-demo', ('woowbk-demo-data',))])

    def test_unexpected_directory_errors_never_stop_another_apps_rollback(self):
        # Review M1: a TypeError from an owner's answer used to escape _rollback: the other app stayed half-restored.
        self.world.fail_restore_after['woowbk-two'] = 1
        self.world.discard_problems['woowbk-demo'] = TypeError('string indices must be integers')
        self.world.leftover_notes['woowbk-demo'] = RecursionError('maximum recursion depth exceeded')
        with self.assertRaises(BackupError) as caught:
            self.restore(apps=('woowbk-demo', 'woowbk-two'))
        self.assertEqual([e[1] for e in self.world.events if e[0] == 'restore' and e[3] == 'rollback'],
                         ['woowbk-demo', 'woowbk-two'])
        self.assertEqual(self.world.data['woowbk-two'], b'two-v2-changed', 'woowbk-two got its pre-restore data back')
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertIn('需人工處理', caught.exception.message)
        self.assertIn('無法整理「示範筆記應用」的主機資料夾', caught.exception.message)
        self.assertIn('無法列出「示範筆記應用」主機資料夾旁留下的資料夾', caught.exception.result['warnings'][0])

    def test_a_failed_rollback_without_directory_problems_clears_the_marker(self):
        self.world.fail_restore_after['woowbk-demo'] = 1
        self.world.fail_rollback_restore.add('woowbk-demo')
        with self.assertRaises(BackupError):
            self.restore()
        self.assertEqual(self.reporter.partial['dir_apps'], [], 'the copies are settled and reported (dir_leftovers)')

    def test_a_signal_while_finishing_does_not_undo_a_finished_restore(self):
        from woowbackup.jobs import Terminated
        self.world.finish_raises[('woowbk-demo', 'restore')] = Terminated(15)
        result = self.restore(apps=('woowbk-demo', 'woowbk-two'))
        self.assertEqual(self.events('finish_dirs'), [('finish_dirs', 'woowbk-demo', 'restore', self.job_id)],
                         'the remaining apps are left (reported), the job ends quickly')
        self.assertTrue(any('.woowbk-old-' in note for note in result['warnings']))

    def test_shutdown_keeps_the_marker_for_the_recovery_after_boot(self):
        from woowbackup.jobs import Terminated
        self.deps.system_stopping = lambda: True
        self.world.raise_after_destructive = Terminated(15)
        with self.assertRaises(Terminated):
            self.restore()
        self.assertEqual(self.reporter.partial['dir_apps'], ['woowbk-demo'])
        self.assertEqual(self.events('discard_dirs', 'finish_dirs'), [])

    def test_recovery_entry_point(self):
        self.world.recover_notes = {'woowbk-demo': ['已把 ~/woowbk-demo-data 的原內容移回'],
                                    'woowbk-two': RuntimeError('boom')}
        notes = flows.settle_dirs(self.deps, 'j20261101T000000Z-deadbeef', ['woowbk-demo', 'woowbk-two', 'gone-app'])
        self.assertEqual(self.events('recover_dirs'), [('recover_dirs', 'woowbk-demo', 'j20261101T000000Z-deadbeef'),
                                                       ('recover_dirs', 'woowbk-two', 'j20261101T000000Z-deadbeef')])
        self.assertEqual(notes[0], '已把 ~/woowbk-demo-data 的原內容移回')
        self.assertIn('需人工確認', notes[1])
        self.assertIn('gone-app', notes[2])


class StrengthenFlowTests(RestoreFlowTests):
    """2026-11-13: host directories written before anything stops, the safety backup's hand-over of its stopped writers,
    digest checks in the result, unavailability per app (CONTRACT sections 7, 9)."""

    def with_dirs(self, *app_ids):
        for app_id in app_ids:
            entry = demo_entry(self.paths)
            entry['data_dirs'] = [{'path': f'{app_id}-data'}]
            if app_id != 'woowbk-demo':
                entry.update(id=app_id, name='第二個應用', config_files=[{'path': f'.config/{app_id}/app.env',
                                                                          'mode': '0600'}])
            self.catalog[app_id] = catalog.validate_entry(entry, paths=self.paths, user_lookup=user_lookup)

    def events(self, *kinds):
        return [e for e in self.world.events if e[0] in kinds]

    def test_directories_are_staged_before_the_safety_backup_and_writers_are_handed_over(self):
        self.with_dirs('woowbk-demo')
        result = self.restore()
        order = [e[:2] for e in self.world.events if e[0] in ('stage_dirs', 'backup', 'kept-stopped', 'take_over',
                                                                'restore')]
        self.assertEqual(order, [('stage_dirs', 'woowbk-demo'), ('backup', 'woowbk-demo'), ('kept-stopped', 'woowbk-demo'),
                                 ('take_over', 'woowbk-demo'), ('restore', 'woowbk-demo')])
        self.assertEqual(self.events('take_over'), [('take_over', 'woowbk-demo', ('woowbk-demo-app.service',))])
        phases = self.reporter.phases()
        self.assertLess(phases.index('stage'), phases.index('safety'))
        self.assertEqual(self.reporter.partial.get('stopped_writers'), {}, 'the restore took the stopped units over')
        self.assertEqual(result['timing'], [{'app': 'woowbk-demo', 'writer_pause_seconds': 10.0,
                                             'unavailable_seconds': 12.5}])
        self.assertEqual(self.reporter.partial['dir_apps'], [])

    def test_without_directories_the_stage_phase_is_skipped(self):
        self.restore()
        self.assertIn(('skip', 'stage'), self.reporter.events)
        self.assertFalse(self.events('stage_dirs'))

    def test_a_failure_before_the_first_destructive_step_discards_copies_and_restarts_writers(self):
        self.with_dirs('woowbk-demo')
        self.world.fail_restore_before.add('woowbk-demo')
        with self.assertRaises(BackupError):
            self.restore()
        self.assertEqual(self.events('discard_dirs'), [('discard_dirs', 'woowbk-demo', 'restore')])
        self.assertEqual(self.events('start_units'), [('start_units', 'woowbk-demo', ('woowbk-demo-app.service',))])
        self.assertEqual(self.reporter.partial['stopped_writers'], {})
        self.assertEqual(self.reporter.partial['dir_apps'], [], 'every copy was removed: nothing for the recovery')

    def test_a_signal_while_the_copies_are_removed_leaves_them_to_the_recovery(self):
        # review F14: a termination signal inside discard_dirs must not clear `dir_apps` (the recovery settles them)
        self.with_dirs('woowbk-demo')
        self.world.fail_restore_before.add('woowbk-demo')
        self.world.discard_problems['woowbk-demo'] = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.restore()
        self.assertEqual(self.reporter.partial['dir_apps'], ['woowbk-demo'])

    def test_a_staging_failure_changes_nothing(self):
        self.with_dirs('woowbk-demo')
        self.world.fail_stage.add('woowbk-demo')
        with self.assertRaises(BackupError):
            self.restore()
        self.assertFalse(self.events('backup'), 'no safety backup, nothing stopped')
        self.assertEqual(self.events('discard_dirs'), [('discard_dirs', 'woowbk-demo', None)])

    def test_a_pre_restore_copy_that_cannot_be_saved_restarts_the_writers_it_kept(self):
        # 2026.11.14.2: nothing is packaged before the restore any more; what can fail there is saving the copy.
        full = OSError(errno.ENOSPC, 'No space left on device')
        with mock.patch.object(flows.util, 'atomic_write_json', side_effect=full):
            with self.assertRaises(BackupError) as caught:
                self.restore()
        # Like a safety backup that could not be made (review): job-failed with the safety_failed guidance.
        self.assertEqual((caught.exception.code, caught.exception.details.get('original')),
                         ('job-failed', 'insufficient-space'))
        self.assertIn('無法建立還原前備份，未做任何變更：無法保存還原前資料', caught.exception.message)
        self.assertIs(caught.exception.result['safety_failed'], True)
        self.assertEqual(self.events('start_units'), [('start_units', 'woowbk-demo', ('woowbk-demo-app.service',))])
        self.assertFalse(self.events('restore'))
        self.assertFalse((self.storage.pending / self.job_id).exists())
        self.assertNotIn('safety_pending', self.reporter.partial, 'never flagged: the copy was not complete')

    def test_an_unstartable_writer_stays_recorded_for_the_recovery(self):
        self.world.fail_restore_before.add('woowbk-demo')
        self.world.unstartable.add('woowbk-demo-app.service')
        with self.assertRaises(BackupError):
            self.restore()
        self.assertEqual(self.reporter.partial['stopped_writers'], {'woowbk-demo': ['woowbk-demo-app.service']})

    def test_digest_differences_roll_back_and_reach_the_result(self):
        check = {'id': 'db', 'type': 'postgres-digest', 'target': 'postgres:main', 'label': '', 'match': False,
                 'before': {'databases': 1, 'tables': 2, 'sequences': 0, 'rows': 10, 'roles': 0},
                 'after': {'databases': 1, 'tables': 2, 'sequences': 0, 'rows': 9, 'roles': 0},
                 'differences': {'missing': 0, 'extra': 0, 'changed': 1, 'samples': [
                     {'item': '資料表 notes:public.notes', 'change': 'changed', 'detail': '資料列 10 → 9'}]}, 'note': None}
        self.world.digest_results['woowbk-demo'] = [check]
        with self.assertRaises(flows.RolledBack) as caught:
            self.restore()
        result = caught.exception.result
        self.assertTrue(result['rolled_back'])
        entry = result['verification'][0]
        self.assertEqual((entry['app'], entry['match']), ('woowbk-demo', False))
        self.assertEqual(entry['checks'][0]['differences']['samples'][0]['detail'], '資料列 10 → 9')
        self.assertEqual(entry['before']['db']['rows'], 10)
        self.assertEqual(entry['after']['db']['rows'], 9)

    def test_matching_digests_join_the_http_json_entry(self):
        check = {'id': 'files', 'type': 'files-digest', 'target': 'volume:x', 'label': '', 'match': True,
                 'before': {'entries': 3, 'files': 2, 'dirs': 1, 'symlinks': 0, 'other': 0, 'bytes': 9},
                 'after': {'entries': 3, 'files': 2, 'dirs': 1, 'symlinks': 0, 'other': 0, 'bytes': 9},
                 'differences': None, 'note': None}
        self.world.digest_results['woowbk-demo'] = [check]
        result = self.restore()
        entry = result['verification'][0]
        self.assertIs(entry['match'], True)
        self.assertEqual(set(entry['before']), {'summary', 'files'})
        self.assertEqual(entry['checks'], [check])

    def test_a_multi_app_failure_releases_the_app_it_never_reached(self):
        self.with_dirs('woowbk-demo', 'woowbk-two')
        self.world.fail_restore_after['woowbk-demo'] = 1
        with self.assertRaises(flows.RolledBack):
            self.restore(apps=('woowbk-demo', 'woowbk-two'))
        self.assertIn(('discard_dirs', 'woowbk-two', None), self.events('discard_dirs'))
        self.assertIn(('start_units', 'woowbk-two', ('woowbk-demo-app.service',)), self.events('start_units'))
        self.assertFalse([e for e in self.events('restore') if e[1] == 'woowbk-two'])

    def test_an_app_refused_before_its_first_step_is_released_not_rolled_back(self):
        self.world.fail_restore_before.add('woowbk-two')
        with self.assertRaises(flows.RolledBack):
            self.restore(apps=('woowbk-demo', 'woowbk-two'))
        rollbacks = [e[1] for e in self.events('restore') if e[3] == 'rollback']
        self.assertEqual(rollbacks, ['woowbk-demo'], 'woowbk-two never changed: nothing to roll back')
        self.assertIn(('start_units', 'woowbk-two', ('woowbk-demo-app.service',)), self.events('start_units'))
        self.assertEqual(self.reporter.partial['stopped_writers'], {}, 'no stale hand-over entry is left')

    def test_recovery_starts_any_unit_of_the_app_but_nothing_else(self):
        # An in-place restore lists every unit it stops until it masked them (CONTRACT section 8): the database too.
        failed = flows.restart_writers(self.deps, {'woowbk-demo': ['woowbk-demo-db.service', 'woowbk-demo-app.service',
                                                                   'unrelated.service']})
        self.assertEqual(self.events('start_units'),
                         [('start_units', 'woowbk-demo', ('woowbk-demo-db.service', 'woowbk-demo-app.service'))])
        self.assertEqual(failed, ['unrelated.service'])

    def test_backup_result_reports_the_unavailability(self):
        result = self.backup(apps=['woowbk-demo', 'woowbk-two'])
        self.assertEqual(result['timing'], [
            {'app': 'woowbk-demo', 'writer_pause_seconds': 2.4, 'unavailable_seconds': 5.0},
            {'app': 'woowbk-two', 'writer_pause_seconds': 2.4, 'unavailable_seconds': 5.0}])
        self.assertEqual(result['unavailable_seconds'], 10.0)
        self.assertEqual(result['downtime_seconds'], 5)


class PendingCopyFlowTests(RestoreCase):
    """2026.11.14.2: the pre-restore copy is kept in pending/<job>/ while the writers stay stopped, the restore runs,
    and the copy becomes the verified safety backup only once the apps run again (one outage, the packaging outside
    it); a rollback reads the copy directly; a dead job's copy is packaged by the recovery (CONTRACT sections 8, 9)."""

    def fresh_world(self):
        """A new device for the next subtest (the test's own tearDown cleans up the last one)."""
        self.tearDown()
        self.setUp()

    def spy_restores(self):
        """[(run, extracted_dir)] of every FakeAdapter.restore call while the test runs."""
        calls = []
        restore = FakeAdapter.restore

        def spy(adapter, app_manifest, extracted_dir, **kwargs):
            calls.append(('rollback' if kwargs.get('rollback') else 'restore', Path(extracted_dir)))
            return restore(adapter, app_manifest, extracted_dir, **kwargs)
        patcher = mock.patch.object(FakeAdapter, 'restore', spy)
        patcher.start()
        self.addCleanup(patcher.stop)
        return calls

    def spy_writes(self):
        """For each archive written: (reporter events so far, world events so far)."""
        seen = []
        write = self.archive.write_archive

        def spy(dest, *args, **kwargs):
            seen.append((list(self.reporter.events), list(self.world.events)))
            return write(dest, *args, **kwargs)
        self.archive.write_archive = spy
        return seen

    def test_the_copy_is_flushed_and_recorded_before_the_first_destructive_step(self):
        flushed, seen = [], []
        fsync_tree = flows._fsync_tree

        def flush(root):
            flushed.append((Path(root), (Path(root) / 'pending.json').exists()))
            return fsync_tree(root)
        restore = FakeAdapter.restore

        def spy(adapter, *args, **kwargs):
            record = json.loads((self.pending() / 'pending.json').read_text())
            seen.append((record, dict(self.reporter.partial), oct((self.pending() / 'pending.json').stat().st_mode & 0o777),
                         oct(self.pending().stat().st_mode & 0o777)))
            return restore(adapter, *args, **kwargs)
        with mock.patch.object(flows, '_fsync_tree', flush), mock.patch.object(FakeAdapter, 'restore', spy):
            self.restore()
        self.assertEqual(flushed, [(self.pending(), False)], 'every file is on disk before the record names it')
        record, partial, record_mode, dir_mode = seen[0]
        self.assertTrue(partial['safety_pending'])
        self.assertEqual((record_mode, dir_mode), ('0o600', '0o700'))
        data = b'notes-v2-changed'
        chosen = record['safety_backup_id']
        self.assertRegex(chosen, r'^\d{8}T\d{6}Z-[0-9a-f]{8}$', 'the safety backup id is chosen with the copy')
        self.assertEqual({key: record[key] for key in record
                          if key not in ('created', 'manifest_apps', 'safety_backup_id')}, {
            'format': flows.PENDING_FORMAT, 'job_id': self.job_id, 'source_backup_id': self.backup_id,
            'note': f'還原前自動備份（還原來源 {self.backup_id}）', 'backup_type': 'safety', 'encrypt': True,
            'key_id': self.keys.device.key_id, 'apps': [{'id': 'woowbk-demo', 'name': '示範筆記應用'}],
            'entries': [{'path': 'apps/woowbk-demo/volumes/data.tar', 'size': len(data),
                         'sha256': hashlib.sha256(data).hexdigest()}],
            'downtime_seconds': 0.0})
        self.assertRegex(record['created'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')
        self.assertEqual([app['id'] for app in record['manifest_apps']], ['woowbk-demo'])
        self.assertEqual(self.safety_ids(), [chosen], 'the packaging used the id the copy recorded')
        self.assertTrue(any(line.startswith('還原前資料已保存（') and '還原前備份會在應用恢復後封裝' in line
                            for line in self.reporter.logs))

    def test_the_safety_backup_is_packaged_once_the_apps_run_again(self):
        writes = self.spy_writes()
        result = self.restore(apps=('woowbk-demo', 'woowbk-two'))
        reporter_events, world_events = writes[0]
        phases = [event[1] for event in reporter_events if event[0] == 'phase']
        self.assertEqual(phases[-2:], ['check', 'safety-package'], 'after the last app passed its checks')
        self.assertEqual([event for event in world_events if event[0] == 'imported'],
                         [('imported', 'woowbk-demo'), ('imported', 'woowbk-two')], 'both apps run again first')
        self.assertIn(('progress', 1.0), reporter_events, 'the packaging reports its progress')
        self.assertEqual(result['timing'], [
            {'app': 'woowbk-demo', 'writer_pause_seconds': 10.0, 'unavailable_seconds': 12.5},
            {'app': 'woowbk-two', 'writer_pause_seconds': 10.0, 'unavailable_seconds': 12.5}],
            'measured before the packaging: it is not part of the outage any more')
        meta = self.storage.index[result['safety_backup_id']]
        self.assertEqual((meta['type'], meta['note'], meta['encrypted'], [app['id'] for app in meta['apps']]),
                         ('safety', f'還原前自動備份（還原來源 {self.backup_id}）', True, ['woowbk-demo', 'woowbk-two']))
        self.assertEqual(self.safety_files(result['safety_backup_id']),
                         {'apps/woowbk-demo/volumes/data.tar': b'notes-v2-changed',
                          'apps/woowbk-two/volumes/data.tar': b'two-v2-changed'})
        self.assertEqual(self.archive.verifies[-1].parent, self.storage.staging / self.job_id,
                         'written and verified in the job staging')
        self.assertEqual(self.storage.removed_pending, [self.job_id])
        self.assert_staging_clean()

    def test_a_packaging_failure_after_a_successful_restore_keeps_the_copy(self):
        self.archive.on_write = lambda: (_ for _ in ()).throw(BackupError('insufficient-space', '空間不足。'))
        result = self.restore()
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v1', 'the restore itself succeeded')
        self.assertEqual((result['safety_backup_id'], result['safety_pending']), (None, True))
        self.assertIs(self.reporter.partial['safety_pending'], True, 'flagged: a recovery pass tries once more')
        self.assertNotIn('safety_backup_id', self.reporter.partial)
        note = (f'還原已完成，但還原前備份尚未封裝：空間不足。還原前資料保留在 {self.pending()}，系統會再試一次；'
                '若仍失敗需人工處理。')
        self.assertEqual(result['warnings'], [note])
        self.assertIn(note, self.reporter.logs)
        self.assertIn(('fail', 'safety-package'), self.reporter.events)
        self.assertTrue((self.pending() / 'pending.json').is_file())
        self.assertTrue((self.pending() / 'data/apps/woowbk-demo/volumes/data.tar').is_file())
        self.assertEqual((self.safety_ids(), self.storage.removed_pending), ([], []))
        self.assert_staging_clean()

    def test_a_termination_signal_while_packaging_leaves_the_copy_to_the_recovery(self):
        # The restore is complete and passed its checks: the job ends succeeded with its result (review); only the
        # packaging is left to the recovery.
        from woowbackup.jobs import Terminated
        self.archive.on_write = lambda: (_ for _ in ()).throw(Terminated(15))
        result = self.restore()
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v1')
        self.assertEqual((result['safety_backup_id'], result['safety_pending']), (None, True))
        self.assertTrue(result['health'] and result['timing'], 'the result of the finished restore is kept')
        self.assertTrue(any('還原前備份尚未封裝：作業被要求停止' in note for note in result['warnings']))
        self.assertIn(('fail', 'safety-package'), self.reporter.events)
        self.assertEqual((self.reporter.partial['safety_pending'], self.reporter.partial['finishing']), (True, True))
        self.assertTrue((self.pending() / 'pending.json').is_file())
        self.assertEqual(self.safety_ids(), [])
        self.assert_staging_clean()

    def test_a_signal_while_finishing_skips_the_packaging(self):
        from woowbackup.jobs import Terminated
        self.world.finish_raises[('woowbk-demo', 'restore')] = Terminated(15)
        writes = self.spy_writes()
        result = self.restore()
        self.assertEqual(writes, [], 'the job ends quickly; a recovery pass packages the copy')
        self.assertIs(result['safety_pending'], True)
        self.assertTrue(any('還原前備份尚未封裝：作業被要求停止' in note for note in result['warnings']))
        self.assertTrue((self.pending() / 'pending.json').is_file())

    def test_the_rollback_reads_the_copy_and_packages_it_afterwards(self):
        restores = self.spy_restores()
        writes = self.spy_writes()
        self.world.fail_restore_after['woowbk-demo'] = 1
        with self.assertRaises(flows.RolledBack) as caught:
            self.restore()
        result = caught.exception.result
        self.assertEqual(restores, [('restore', self.storage.staging / self.job_id / 'extract'),
                                    ('rollback', self.pending() / 'data')])
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v2-changed')
        self.assertIn(('restore', 'woowbk-demo', 'inplace', 'rollback'), writes[0][1], 'packaged after the rollback')
        self.assertEqual(self.reporter.phases()[-1], 'rollback', 'inside the rollback phase')
        self.assertIn('封裝還原前備份…', self.reporter.logs)
        self.assertEqual(self.safety_ids(), [result['safety_backup_id']])
        self.assertEqual((result['safety_pending'], self.reporter.partial['safety_pending']), (False, False))
        self.assertEqual(self.reporter.partial['safety_backup_id'], result['safety_backup_id'])
        self.assertFalse(self.pending().exists())

    def damaged_copy(self, how):
        """A patch (context manager) that changes the copy while the restore runs (before it fails)."""
        restore = FakeAdapter.restore

        def spy(adapter, *args, **kwargs):
            if not kwargs.get('rollback'):
                target = self.pending() / 'data/apps/woowbk-demo/volumes/data.tar'
                if how == 'content':
                    target.write_bytes(b'notes-v2-chanGed')
                else:
                    other = self.pending() / 'other.tar'
                    other.write_bytes(target.read_bytes())
                    target.unlink()
                    target.symlink_to(other)
            return restore(adapter, *args, **kwargs)
        return mock.patch.object(FakeAdapter, 'restore', spy)

    def test_a_damaged_copy_is_never_rolled_back_from(self):
        for how in ('content', 'symlink'):
            with self.subTest(how=how):
                self.fresh_world()
                self.world.fail_restore_after['woowbk-demo'] = 1
                writes = len(self.archive.writes)
                with self.damaged_copy(how), self.assertRaises(BackupError) as caught:
                    self.restore()
                error = caught.exception
                self.assertIn('需人工處理', error.message)
                self.assertIn('還原前資料已損毀，無法自動回復', error.message)
                self.assertTrue(error.message.endswith(f'還原前資料保留在 {self.pending()}。'))
                self.assertNotIn(('restore', 'woowbk-demo', 'inplace', 'rollback'), self.world.events)
                self.assertEqual(len(self.archive.writes), writes, 'a damaged copy is not packaged either')
                self.assertTrue((self.pending() / 'pending.json').is_file())
                self.assertIs(self.reporter.partial['safety_pending'], True)
                self.assertIsNone(error.result['safety_backup_id'])

    def test_a_packaging_failure_after_a_rollback_keeps_the_copy_and_names_it(self):
        self.world.fail_restore_after['woowbk-demo'] = 1
        self.archive.on_write = lambda: (_ for _ in ()).throw(BackupError('insufficient-space', '空間不足。'))
        with self.assertRaises(flows.RolledBack) as caught:
            self.restore()
        result = caught.exception.result
        self.assertTrue(result['rolled_back'], 'the apps are back; only the safety backup is missing')
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v2-changed')
        self.assertIn(f'還原前備份尚未封裝：空間不足。還原前資料保留在 {self.pending()}，系統會再試一次；若仍失敗需人工處理。',
                      result['warnings'])
        self.assertEqual((result['safety_backup_id'], result['safety_pending']), (None, True))
        self.assertIs(self.reporter.partial['safety_pending'], True)
        self.assertTrue((self.pending() / 'pending.json').is_file())

    def test_a_failed_rollback_names_the_copy_when_it_could_not_be_packaged(self):
        self.world.fail_restore_after['woowbk-demo'] = 1
        self.world.fail_rollback_restore.add('woowbk-demo')
        self.archive.on_write = lambda: (_ for _ in ()).throw(BackupError('insufficient-space', '空間不足。'))
        with self.assertRaises(BackupError) as caught:
            self.restore()
        self.assertIn('需人工處理', caught.exception.message)
        self.assertTrue(caught.exception.message.endswith(f'還原前資料保留在 {self.pending()}。'))
        self.assertNotIn('可使用還原前備份', caught.exception.message)
        self.assertTrue((self.pending() / 'pending.json').is_file())

    def test_staged_files_outside_the_copy_are_refused_before_any_change(self):
        backup = FakeAdapter.backup

        def misplaced(adapter, staging_dir, **kwargs):
            manifest, entries = backup(adapter, staging_dir, **kwargs)
            other = Path(staging_dir) / 'elsewhere.tar'
            shutil.copyfile(entries[0].source, other)
            return manifest, [Entry(entries[0].path, other, entries[0].size, entries[0].sha256)]
        with mock.patch.object(FakeAdapter, 'backup', misplaced):
            with self.assertRaises(BackupError) as caught:
                self.restore()
        self.assertEqual((caught.exception.code, caught.exception.details.get('original')), ('job-failed', 'internal-error'))
        self.assertIn('未做任何變更', caught.exception.message)
        self.assertIs(caught.exception.result['safety_failed'], True)
        self.assertNotIn('restore', [event[0] for event in self.world.events])
        self.assertIn(('start_units', 'woowbk-demo', ('woowbk-demo-app.service',)), self.world.events)
        self.assertFalse(self.pending().exists())

    def test_without_a_copy_the_package_phase_is_skipped(self):
        self.world.mode['woowbk-demo'] = 'fresh'
        self.restore()
        self.assertIn(('skip', 'safety-package'), self.reporter.events)
        self.assertNotIn('safety-package', self.reporter.phases())
        self.world.mode['woowbk-demo'] = 'inplace'
        self.world.db_down.add('woowbk-demo')
        result = flows.run_restore(self.ctx(), {'backup_id': self.backup_id, 'apps': ['woowbk-demo'],
                                                'allow_no_safety': True})
        self.assertIs(result['safety_skipped'], True)
        self.assertIn(('skip', 'safety-package'), self.reporter.events)
        self.assertFalse(self.pending().exists())

    def interrupted_copy(self):
        """A restore cut by a shutdown after its first destructive step: the copy stays, flagged."""
        from woowbackup.jobs import Terminated
        self.deps.system_stopping = lambda: True
        self.world.raise_after_destructive = Terminated(15)
        with self.assertRaises(Terminated):
            self.restore()
        self.assertTrue((self.pending() / 'pending.json').is_file())

    def test_the_recovery_packages_a_kept_copy(self):
        self.interrupted_copy()
        logs = []
        chosen = json.loads((self.pending() / 'pending.json').read_text())['safety_backup_id']
        backup_id, problem, deferred = flows.package_pending_safety(self.paths, self.deps, self.job_id, log=logs.append)
        self.assertEqual((backup_id, problem, deferred), (chosen, None, False))
        meta = self.storage.index[backup_id]
        self.assertEqual((meta['type'], meta['note'], meta['apps'], meta['encrypted']),
                         ('safety', f'還原前自動備份（還原來源 {self.backup_id}）',
                          [{'id': 'woowbk-demo', 'name': '示範筆記應用'}], True))
        self.assertEqual(self.archive.writes[-1]['recipient'], self.keys.device.recipient)
        self.assertEqual(self.safety_files(backup_id), {'apps/woowbk-demo/volumes/data.tar': b'notes-v2-changed'})
        self.assertTrue(self.pending().is_dir(), 'never deleted here: the job record names the backup first')
        self.assertFalse((self.storage.staging / self.job_id).exists(), 'the archive was written in the staging')
        self.assertTrue(any(backup_id in line for line in logs))

    def test_the_recovery_packages_an_unencrypted_copy_without_a_key(self):
        self.deps.encrypt_by_default = lambda: False
        self.interrupted_copy()
        self.keys.device = None
        backup_id, problem, _deferred = flows.package_pending_safety(self.paths, self.deps, self.job_id)
        self.assertIsNone(problem)
        self.assertIs(self.storage.index[backup_id]['encrypted'], False)

    def test_the_recovery_adopts_a_backup_registered_before_the_record_said_so(self):
        self.interrupted_copy()
        first, _problem, _deferred = flows.package_pending_safety(self.paths, self.deps, self.job_id)
        writes = len(self.archive.writes)
        again = flows.package_pending_safety(self.paths, self.deps, self.job_id)
        self.assertEqual(again, (first, None, False))
        self.assertEqual(len(self.archive.writes), writes, 'not packaged a second time')

    def test_the_recovery_packages_again_over_its_own_unregistered_archive(self):
        self.interrupted_copy()
        chosen = json.loads((self.pending() / 'pending.json').read_text())['safety_backup_id']
        self.storage.archive_path(chosen).write_text('published, never registered')
        backup_id, problem, _deferred = flows.package_pending_safety(self.paths, self.deps, self.job_id)
        self.assertEqual((backup_id, problem), (chosen, None))
        self.assertEqual(self.storage.index[chosen]['type'], 'safety')

    def test_the_recovery_waits_for_space_without_writing(self):
        self.interrupted_copy()
        self.storage.free = 1024
        writes = len(self.archive.writes)
        backup_id, problem, deferred = flows.package_pending_safety(self.paths, self.deps, self.job_id)
        self.assertEqual((backup_id, deferred), (None, True))
        self.assertIn('空間不足，暫不封裝還原前備份', problem)
        self.assertEqual(len(self.archive.writes), writes)
        self.assertTrue((self.pending() / 'pending.json').is_file())

    def test_too_little_space_after_the_restore_keeps_the_copy(self):
        refuse = BackupError('insufficient-space', '空間不足，暫不封裝還原前備份：需要約 3.0 GiB，可用約 1.0 GiB')
        with mock.patch.object(flows, '_check_package_space', side_effect=refuse):
            result = self.restore()
        self.assertEqual((result['safety_backup_id'], result['safety_pending']), (None, True))
        self.assertTrue(any('空間不足，暫不封裝還原前備份' in note for note in result['warnings']))
        self.assertTrue((self.pending() / 'pending.json').is_file())

    def test_a_copy_that_cannot_be_recorded_counts_as_none_when_restoring_without_one_is_allowed(self):
        full = OSError(errno.ENOSPC, 'No space left on device')
        with mock.patch.object(flows.util, 'atomic_write_json', side_effect=full):
            result = flows.run_restore(self.ctx(), {'backup_id': self.backup_id, 'apps': ['woowbk-demo'],
                                                    'allow_no_safety': True})
        self.assertEqual((result['safety_skipped'], result['safety_pending']), (True, False))
        self.assertFalse(self.pending().exists())

    def test_dropping_a_copy_clears_its_flag_first(self):
        seen = []
        remove = self.storage.remove_pending

        def spy(job_id):
            seen.append(self.reporter.partial.get('safety_pending'))
            return remove(job_id)
        self.world.fail_restore_before.add('woowbk-demo')
        with mock.patch.object(self.storage, 'remove_pending', spy):
            with self.assertRaises(BackupError):
                self.restore()
        self.assertEqual(seen, [False], 'a kill during the deletion leaves an unflagged copy for the sweep')

    def test_a_termination_signal_while_the_rollback_packages_still_reports_the_rollback(self):
        from woowbackup.jobs import Terminated
        self.world.raise_after_destructive = BackupError('job-failed', '資料卷匯入失敗。')
        self.archive.on_write = lambda: (_ for _ in ()).throw(Terminated(15))
        with self.assertRaises(flows.RolledBack) as caught:
            self.restore()
        self.assertIs(caught.exception.result['rolled_back'], True)
        self.assertIs(caught.exception.result['safety_pending'], True)
        self.assertIn(('mark', 'safety-package', 'failed'), self.reporter.events)
        self.assertTrue((self.pending() / 'pending.json').is_file())

    def test_the_recovery_never_packages_a_copy_it_cannot_trust(self):
        def record_path():
            return self.pending() / 'pending.json'

        def target():
            return self.pending() / 'data/apps/woowbk-demo/volumes/data.tar'

        def no_key():
            self.keys.device = None

        def edit_record(**fields):
            record = json.loads(record_path().read_text())
            record.update(fields)
            record_path().write_text(json.dumps(record))

        def escape():
            entries = json.loads(record_path().read_text())['entries']
            entries[0]['path'] = 'apps/woowbk-demo/volumes/../../../../outside'
            edit_record(entries=entries)

        def symlink():
            other = self.pending() / 'other.tar'
            other.write_bytes(target().read_bytes())
            target().unlink()
            target().symlink_to(other)

        cases = {'missing record': lambda: record_path().unlink(), 'no device key': no_key, 'path outside': escape,
                 'symlink': symlink, 'shorter file': lambda: target().write_bytes(b'short'),
                 'changed content': lambda: target().write_bytes(b'notes-v2-chanGed'),
                 'other job': lambda: edit_record(job_id='j20261113T020000Z-ffffffff')}
        for name, damage in cases.items():
            with self.subTest(name):
                self.fresh_world()
                self.interrupted_copy()
                damage()
                registered = dict(self.storage.index)
                backup_id, problem, deferred = flows.package_pending_safety(self.paths, self.deps, self.job_id)
                self.assertEqual((backup_id, deferred), (None, False))
                self.assertTrue(isinstance(problem, str) and problem and not problem.endswith('。'), problem)
                self.assertEqual(self.storage.index, registered, 'nothing registered')
                self.assertTrue(self.pending().is_dir(), 'the copy is never deleted by a failed packaging')


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

    def test_a_damaged_job_record_stops_pruning(self):
        # review F11: a record that cannot be read may be a failed restore that pins a safety backup
        from woowbackup import jobs
        for i in range(1, 6):
            self.add(f'2026110{i}T000000Z-0000000{i}', f'2026-11-0{i}T00:00:00Z', ['woowbk-demo'])
        jobs.JobStore(self.paths).ensure()
        Path(self.paths.jobs, 'j20261110T000000Z-0000abcd.json').write_bytes(b'{damaged')
        flows.prune_safety(self.ctx(), ['woowbk-demo'])
        self.assertEqual(len(self.storage.index), 5, 'nothing is pruned while a record cannot be read')
        self.assertIn('無法讀取部分作業紀錄', '\n'.join(self.reporter.logs))
        self.assertIsNone(flows.pinned_safety(self.paths))

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
