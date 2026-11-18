"""Uploaded Home Assistant backups: their own store `<data>/ha-backups/` (CONTRACT sections 3 and 7). Owner: E1
engine-core (format).

Layout (root 0700): `<id>.tar` -- the uploaded file exactly as it was (root 0600) -- and `<id>.json`, the sidecar (root
0600, exactly SIDECAR_KEYS, checked strictly on every read; unknown keys make a sidecar unreadable). The id is `ha-` +
the first 20 hex digits of the file's sha256, so the same file uploaded twice is the same record. The sidecar is the
validated summary of habackup.describe (display data from backup.json plus each add-on member's encryption as its
first bytes say) and the upload facts (size, sha256, uploaded_at, filename).

HA backups are not Cockpit backups: they never enter `archives/` or the index, so retention, `adopt_orphans`, the
schedule and `delete` never see them, and an older engine simply does not list them. A record stays until
`ha-delete`.

Every write (publish, delete) happens under the index lock (`<run>/index.lock`, the lock storage.py uses for its
sidecars). Publishing writes the sidecar first and then renames the upload into place, re-checking (dev, ino), so a
listed record always has its file; a kill in between leaves a sidecar without a file (never listed, removed an hour
later by the next publish) and the upload in uploads/ (swept after 24 h). A failure after the rename puts the file
back into uploads/, like a Cockpit upload. An existing sidecar that cannot be read (e.g. a newer engine's) is never
replaced (review finding HD-10).
"""
import contextlib
import fcntl
import os
import re
import stat
import time
from pathlib import Path

from . import util
from .errors import BackupError

DIRNAME = 'ha-backups'
ID_RE = re.compile(r'ha-[0-9a-f]{20}\Z')
FILE_RE = re.compile(r'(ha-[0-9a-f]{20})\.(tar|json)\Z')
SHA256_RE = re.compile(r'[0-9a-f]{64}\Z')
SLUG_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')
ADDON_SLUG_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z')
VERSION_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9.+_~-]{0,63}\Z')
FOLDER_RE = re.compile(r'[a-z0-9_]{1,40}(?:/[a-z0-9_]{1,40})?\Z')
CONTROL_RE = re.compile(r'[\x00-\x1f\x7f]')
SIDECAR_KEYS = ('id', 'ha_slug', 'name', 'date', 'type', 'supervisor_version', 'protected', 'compressed', 'addons',
                'folders', 'size', 'sha256', 'uploaded_at', 'filename')
ADDON_KEYS = ('slug', 'name', 'version', 'encrypted')
MAX_SIDECAR = 256 * 1024
STALE_SIDECAR_AGE = 3600

# WOOWTECH add-ons Cockpit can import (owner decision Q1): the add-on slug after the first `_` (any repository prefix)
# -> this device's catalog id and the name shown when that app is not installed here.
IMPORTABLE = {'odoo18ce': ('odoo', 'Odoo 18'), 'woow-n8n': ('n8n', 'n8n 工作流程')}

MSG_BAD_ID = 'HA 備份 ID 格式不正確。'
MSG_NOT_FOUND = '找不到指定的 HA 備份。'


def valid_id(value):
    return isinstance(value, str) and ID_RE.fullmatch(value) is not None


def is_record(meta):
    """True for an HA backup record (what Storage.finish_upload returns for an HA file), False for BackupMeta."""
    return isinstance(meta, dict) and valid_id(meta.get('id'))


def addon_suffix(slug):
    """The add-on slug without its repository prefix: `5e12b5f3_odoo18ce` -> `odoo18ce` (no `_`: the slug itself)."""
    return slug.split('_', 1)[1] if '_' in slug else slug


def importable_app(slug):
    """(catalog id, default name) of the app an add-on slug maps to, or None."""
    return IMPORTABLE.get(addon_suffix(slug))


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _text(value, max_len, *, min_len=0):
    if not isinstance(value, str) or not min_len <= len(value) <= max_len or CONTROL_RE.search(value):
        return False
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True


def safe_filename(filename, date):
    """The uploaded file's name when it is a plain file name (<= 200 printable characters, no path separators), else
    `ha-backup-<YYYYMMDD-HHMMSS>.tar` from the backup's date. Display only: the stored file is `<id>.tar`."""
    name = (filename or '').strip() if isinstance(filename, str) else ''
    if _text(name, 200, min_len=1) and name.isprintable() and '/' not in name and '\\' not in name \
            and name not in ('.', '..'):
        return name
    try:
        stamp = util.parse_iso_utc(date).strftime('%Y%m%d-%H%M%S')
    except ValueError:
        stamp = util.utc_now().strftime('%Y%m%d-%H%M%S')
    return f'ha-backup-{stamp}.tar'


def record_from(summary, sha256, size, filename, uploaded_at):
    """The sidecar of an uploaded HA backup from habackup's Layout.summary() and the upload facts."""
    return {
        'id': 'ha-' + sha256[:20], 'ha_slug': summary['ha_slug'], 'name': summary['name'], 'date': summary['date'],
        'type': summary['type'], 'supervisor_version': summary['supervisor_version'],
        'protected': summary['protected'], 'compressed': summary['compressed'],
        'addons': [{'slug': a['slug'], 'name': a['name'], 'version': a['version'],
                    'encrypted': a['encryption'] != 'none'} for a in summary['addons']],
        'folders': list(summary['folders']), 'size': size, 'sha256': sha256, 'uploaded_at': uploaded_at,
        'filename': safe_filename(filename, summary['date']),
    }


def valid_record(rec, ha_id=None):
    """True when `rec` is a complete, well-typed sidecar (exactly SIDECAR_KEYS) of `ha_id` (when given)."""
    if not isinstance(rec, dict) or set(rec) != set(SIDECAR_KEYS):
        return False
    if not valid_id(rec['id']) or (ha_id is not None and rec['id'] != ha_id):
        return False
    if not isinstance(rec['sha256'], str) or not SHA256_RE.fullmatch(rec['sha256']) \
            or rec['id'] != 'ha-' + rec['sha256'][:20]:
        return False
    if not isinstance(rec['ha_slug'], str) or not SLUG_RE.fullmatch(rec['ha_slug']):
        return False
    if not _text(rec['name'], 200) or not util.is_iso_utc(rec['date']) or rec['type'] not in ('full', 'partial'):
        return False
    if not isinstance(rec['supervisor_version'], str) or not VERSION_RE.fullmatch(rec['supervisor_version']):
        return False
    if not isinstance(rec['protected'], bool) or not isinstance(rec['compressed'], bool):
        return False
    addons = rec['addons']
    if not isinstance(addons, list) or len(addons) > 100:
        return False
    slugs = set()
    for addon in addons:
        if (not isinstance(addon, dict) or set(addon) != set(ADDON_KEYS) or not isinstance(addon['slug'], str)
                or not ADDON_SLUG_RE.fullmatch(addon['slug']) or addon['slug'] in slugs
                or not _text(addon['name'], 200) or not isinstance(addon['version'], str)
                or not VERSION_RE.fullmatch(addon['version']) or not isinstance(addon['encrypted'], bool)):
            return False
        slugs.add(addon['slug'])
    folders = rec['folders']
    if (not isinstance(folders, list) or len(folders) > 32 or len(set(map(str, folders))) != len(folders)
            or not all(isinstance(f, str) and FOLDER_RE.fullmatch(f) for f in folders)):
        return False
    if not _is_int(rec['size']) or rec['size'] < 0 or not util.is_iso_utc(rec['uploaded_at']):
        return False
    return (_text(rec['filename'], 255, min_len=1) and '/' not in rec['filename'] and '\\' not in rec['filename'])


def view(rec, catalog=None):
    """HaBackupMeta (CONTRACT section 7): the sidecar plus `importable_apps` [{slug, app_id, app_name, installed}] (a
    WOOWTECH add-on this engine can import; `installed`: this device's catalog has that app) and `other_addons`
    [{slug, name, version}] (「這台沒有對應的應用」)."""
    result = dict(rec)
    importable, other = [], []
    for addon in rec['addons']:
        target = importable_app(addon['slug'])
        if target is None:
            other.append({'slug': addon['slug'], 'name': addon['name'], 'version': addon['version']})
            continue
        app_id, default_name = target
        app = None
        if catalog is not None:
            with contextlib.suppress(Exception):  # an unreadable catalog never breaks a listing
                app = catalog.get(app_id)
        importable.append({'slug': addon['slug'], 'app_id': app_id,
                           'app_name': getattr(app, 'name', None) or default_name, 'installed': app is not None})
    result['importable_apps'] = importable
    result['other_addons'] = other
    return result


@contextlib.contextmanager
def _index_lock(paths):
    """The same exclusive flock storage.py takes around its sidecar writes (`<run>/index.lock`)."""
    run = util.ensure_dir(paths.run, 0o700)
    fd = os.open(Path(run) / 'index.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


class HaStore:
    def __init__(self, paths):
        self.paths = paths

    @property
    def root(self):
        return Path(self.paths.data) / DIRNAME

    def ensure(self):
        """Create the store (and the data dir) root 0700; refuses a symlinked or non-directory store."""
        for path in (self.paths.data, self.root):
            try:
                util.ensure_dir(path, 0o700)
            except NotADirectoryError as exc:
                raise BackupError('internal-error', 'HA 備份資料夾被替換為非目錄或符號連結，已停止。',
                                  path=str(path)) from exc

    def _check(self, ha_id):
        if not valid_id(ha_id):
            raise BackupError('invalid-request', MSG_BAD_ID)
        return ha_id

    def file_path(self, ha_id):
        """`<data>/ha-backups/<id>.tar` (what habackup.open_backup reads)."""
        return self.root / f'{self._check(ha_id)}.tar'

    def sidecar_path(self, ha_id):
        return self.root / f'{self._check(ha_id)}.json'

    def _root_ok(self):
        try:
            st = os.lstat(self.root)
        except FileNotFoundError:
            return False
        if not stat.S_ISDIR(st.st_mode):
            raise BackupError('internal-error', 'HA 備份資料夾被替換為非目錄或符號連結，已停止。', path=str(self.root))
        return True

    def _file_stat(self, ha_id):
        try:
            st = os.lstat(self.file_path(ha_id))
        except FileNotFoundError:
            return None
        return st if stat.S_ISREG(st.st_mode) else None

    def _load(self, ha_id):
        try:
            rec = util.load_json_file(self.sidecar_path(ha_id), max_bytes=MAX_SIDECAR)
        except (OSError, ValueError):
            return None
        return rec if valid_record(rec, ha_id) else None

    def _listed(self, ha_id):
        rec = self._load(ha_id)
        st = self._file_stat(ha_id) if rec is not None else None
        return rec if st is not None and st.st_size == rec['size'] else None

    def list(self):
        """Records with a valid sidecar and their file, newest HA backup first (date, upload time, id)."""
        if not self._root_ok():
            return []
        records = []
        for name in os.listdir(self.root):
            match = FILE_RE.fullmatch(name)
            if not match or match.group(2) != 'json':
                continue
            rec = self._listed(match.group(1))
            if rec is not None:
                records.append(rec)
        records.sort(key=lambda r: (r['date'], r['uploaded_at'], r['id']), reverse=True)
        return records

    def get(self, ha_id):
        """The record of `ha_id`; not-found when it has no valid sidecar or no file."""
        self._check(ha_id)
        rec = self._listed(ha_id) if self._root_ok() else None
        if rec is None:
            raise BackupError('not-found', MSG_NOT_FOUND, ha_backup_id=ha_id)
        return rec

    def exists(self, ha_id):
        try:
            self.get(ha_id)
        except BackupError:
            return False
        return True

    def delete(self, ha_id):
        """Remove a record: the sidecar first (a listed record always has its file), then the file."""
        self._check(ha_id)
        with _index_lock(self.paths):
            if not self._root_ok():
                raise BackupError('not-found', MSG_NOT_FOUND, ha_backup_id=ha_id)
            side, path = self.sidecar_path(ha_id), self.file_path(ha_id)
            if not os.path.lexists(side) and not os.path.lexists(path):
                raise BackupError('not-found', MSG_NOT_FOUND, ha_backup_id=ha_id)
            for target in (side, path):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(target)
            util.fsync_dir(self.root)

    def publish(self, fd, st, part, summary, sha256, filename, *, now=None):
        """Store the validated upload `part` (open as `fd`, fstat `st`) whose habackup summary is `summary` and whose
        sha256 is `sha256`. Returns (record, created): created False when the same file is already stored (the caller
        then drops the upload). Refuses (invalid-request) an id that exists with different content, an unreadable
        existing sidecar (kept as it is) and a file swapped during the check."""
        if not isinstance(sha256, str) or not SHA256_RE.fullmatch(sha256):
            raise BackupError('internal-error', 'HA 備份的檢查碼格式不正確。')
        rec = record_from(summary, sha256, st.st_size, filename, util.iso_utc())
        if not valid_record(rec):
            raise BackupError('internal-error', 'HA 備份的記錄格式不正確。')
        ha_id = rec['id']
        side, dest = self.sidecar_path(ha_id), self.file_path(ha_id)
        with _index_lock(self.paths):
            self.ensure()
            self._cleanup_locked(time.time() if now is None else now, keep=ha_id)
            if os.path.lexists(side):
                current = self._load(ha_id)
                if current is None:
                    raise BackupError('invalid-request', '這台設備已有這份 HA 備份，但它的記錄無法讀取（可能由較新版本的備份元件'
                                                         '建立），已保留原狀，未重複上傳。', ha_backup_id=ha_id)
                if current['sha256'] != sha256:
                    raise BackupError('invalid-request', '這台設備已有相同 ID 但內容不同的 HA 備份，已拒絕上傳。',
                                      ha_backup_id=ha_id)
                existing = self._file_stat(ha_id)
                if existing is not None and existing.st_size == current['size']:
                    return current, False
            # A file without a valid record is a leftover (a deletion cut between its two steps): replaced below.
            os.fchmod(fd, 0o600)
            moved = False
            try:
                util.atomic_write_json(side, rec, 0o600)
                os.rename(part, dest)
                moved = True
                current = os.lstat(dest)
                if (current.st_dev, current.st_ino) != (st.st_dev, st.st_ino):
                    moved = False
                    os.unlink(dest)
                    raise BackupError('invalid-request', '上傳的檔案在驗證期間被更換，已拒絕。')
                util.fsync_dir(self.root)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(side)
                if moved:  # back to the upload area: a retry can finish it, nothing stays half-listed
                    with contextlib.suppress(OSError):
                        os.rename(dest, part)
                raise
        return rec, True

    def _cleanup_locked(self, now, keep=None):
        """Remove sidecars whose file is missing and stale temp files (written more than an hour ago); under the index
        lock, which every publish holds from its sidecar to its rename, so nothing here can be a publish in progress."""
        try:
            names = os.listdir(self.root)
        except FileNotFoundError:
            return
        for name in names:
            path = self.root / name
            match = FILE_RE.fullmatch(name)
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                continue
            if now - st.st_mtime < STALE_SIDECAR_AGE or stat.S_ISDIR(st.st_mode):
                continue
            if match and match.group(2) == 'json' and match.group(1) != keep:
                if not os.path.lexists(self.root / f'{match.group(1)}.tar'):
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(path)
            elif name.startswith('.ha-') and name.endswith('.tmp'):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(path)
