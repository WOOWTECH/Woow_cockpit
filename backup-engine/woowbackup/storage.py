"""Local backup storage, index sidecars, uploads, staging and unencrypted download copies (CONTRACT section 3). Owner: E1.

Layout below `paths.data` (all 0700): `archives/<id>.tar` (format 2, every new backup) or `archives/<id>.woowbackup`
(format 1, read forever) + `archives/<id>.json` (index sidecar, 0600), `uploads/<upload_id>.part` +
`uploads/<upload_id>.json`, `staging/<job>/`, `pending/<job>/` (an in-place restore's pre-restore copy until it is
packaged into its safety backup; never replaced, only its packaging removes it), `jobs/`, `exports/<export_id>.tar` +
`.json` (unencrypted copies made for one download: root 0600, deleted after EXPORT_TTL seconds by the next
status/list/export command or the transient timer the export job schedules; CONTRACT section 8).
Sidecars are written atomically; unreadable or invalid sidecars are ignored by listings. Every sidecar
write (register, update, delete) happens under one index lock in the run directory, and `update` reads the
sidecar under it: a helper command (`inspect`) and a job (a verify result) never overwrite each other's fields,
and an update never brings back the sidecar of a backup deleted meanwhile. A sidecar that exists but cannot be
read (e.g. written by a newer engine) is never replaced by an `uploaded` one (review finding HD-10).

`upload-finish` hashes the whole file before it answers. Once it started it runs to its end even when the page
times out and cockpit-bridge terminates it (SIGTERM is ignored meanwhile), and a second `upload-finish` of the
same upload waits for the first and then returns its result (review finding HD-08).
"""
import contextlib
import datetime
import errno
import fcntl
import hashlib
import os
import re
import shutil
import stat
import time
from pathlib import Path

from . import archive, util
from .errors import BackupError

BACKUP_ID_RE = re.compile(r'^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
UPLOAD_ID_RE = re.compile(r'^u[0-9a-f]{16}\Z')
STAGING_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,100}\Z')
KEY_ID_RE = re.compile(r'^[0-9A-F]{4}(?:-[0-9A-F]{4}){3}\Z')
SHA256_RE = re.compile(r'^[0-9a-f]{64}\Z')
FILENAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,200}\.(woowbackup|tar)\Z')
# Download names carry seconds since 2026-11 (`…-YYYYMMDD-HHMMSS`); older engines wrote `…-YYYYMMDD-HHMM`. Format 2 files
# end in `.tar`, an unencrypted download copy in `-unencrypted.tar`.
UPLOADED_NAME_RE = re.compile(r'^woowtech-backup-[a-z0-9-]{1,63}-[0-9]{8}-[0-9]{4}(?:[0-9]{2})?(?:-unencrypted)?'
                              r'\.(woowbackup|tar)\Z')
EXTENSIONS = {1: '.woowbackup', 2: '.tar'}
EXPORT_ID_RE = re.compile(r'^x[0-9a-f]{16}\Z')
EXPORT_FILE_RE = re.compile(r'^(x[0-9a-f]{16})\.(tar|json)\Z')
EXPORT_TEMP_RE = re.compile(r'^\.x[0-9a-f]{16}\..+\.tmp\Z')
EXPORT_TTL = 15 * 60          # seconds an unencrypted copy stays downloadable
EXPORT_ORPHAN_AGE = 3600      # a copy without its sidecar (or a temp file) is removed after this
MAX_EXPORTS = 2               # unencrypted copies kept at the same time (the oldest goes first)
BRIDGE_TEMP_RE = re.compile(r'^\.(u[0-9a-f]{16})\.part-.+\Z')  # cockpit fsreplace1 temp files
UPLOAD_FILE_RE = re.compile(r'^(u[0-9a-f]{16})\.(part|json|done)\Z')
ORPHAN_MIN_AGE = 3600

TYPES = ('manual', 'safety', 'uploaded')
META_REQUIRED = ('id', 'type', 'created', 'note', 'apps', 'size', 'sha256', 'key_id', 'include_images',
                 'filename', 'source', 'verified', 'inspected')
META_OPTIONAL = ('uploaded_at', 'format', 'encrypted')
MAX_SIDECAR = 256 * 1024
MAX_PENDING_UPLOADS = 4
MIN_UPLOAD = 64
MAX_UPLOAD = 2 * 1024 ** 4

MSG_BAD_ID = '備份 ID 格式不正確。'
MSG_NOT_FOUND = '找不到指定的備份。'


def valid_backup_id(value):
    return isinstance(value, str) and BACKUP_ID_RE.match(value) is not None


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_meta(rec, backup_id=None):
    """True when `rec` is a complete, well-typed index record (BackupMeta without the derived fields).

    `format` (1|2) and `encrypted` are optional: sidecars written before format 2 have neither (format 1, encrypted).
    An unencrypted backup has `key_id` null; `apps[]` may carry `size` (bytes of its application archive in a format
    2 file) and `verified` may carry `deep` (the verify job checked the content like a restore, CONTRACT section 5)."""
    if not isinstance(rec, dict) or set(rec) - set(META_REQUIRED) - set(META_OPTIONAL):
        return False
    if any(key not in rec for key in META_REQUIRED):
        return False
    if not valid_backup_id(rec['id']) or (backup_id is not None and rec['id'] != backup_id):
        return False
    if rec['type'] not in TYPES:
        return False
    if rec['created'] is not None and not util.is_iso_utc(rec['created']):
        return False
    if not isinstance(rec['note'], str) or len(rec['note']) > 1000:
        return False
    apps = rec['apps']
    if not isinstance(apps, list) or len(apps) > 100:
        return False
    for app in apps:
        if (not isinstance(app, dict) or set(app) - {'size'} != {'id', 'name'} or not isinstance(app['id'], str)
                or not isinstance(app['name'], str) or len(app['id']) > 64 or len(app['name']) > 200):
            return False
        if 'size' in app and (not _is_int(app['size']) or app['size'] < 0):
            return False
    size = rec['size']
    if not _is_int(size) or size < 0:
        return False
    if not isinstance(rec['sha256'], str) or not SHA256_RE.match(rec['sha256']):
        return False
    fmt = rec.get('format', 1)
    encrypted = rec.get('encrypted', True)
    if fmt not in (1, 2) or not _is_int(fmt) or not isinstance(encrypted, bool) or (fmt == 1 and not encrypted):
        return False
    if encrypted:
        if not isinstance(rec['key_id'], str) or not KEY_ID_RE.match(rec['key_id']):
            return False
    elif rec['key_id'] is not None:
        return False
    if not isinstance(rec['include_images'], bool) or not isinstance(rec['inspected'], bool):
        return False
    if not isinstance(rec['filename'], str) or not FILENAME_RE.match(rec['filename']):
        return False
    source = rec['source']
    if source is not None and (not isinstance(source, dict) or set(source) != {'hostname'}
                               or not isinstance(source['hostname'], str) or len(source['hostname']) > 255):
        return False
    verified = rec['verified']
    if verified is not None and (not isinstance(verified, dict) or set(verified) - {'deep'} != {'at', 'ok'}
                                 or not util.is_iso_utc(verified['at']) or not isinstance(verified['ok'], bool)
                                 or not isinstance(verified.get('deep', False), bool)):
        return False
    if 'uploaded_at' in rec and not util.is_iso_utc(rec['uploaded_at']):
        return False
    return True


def unauthenticated(rec):
    """True for an unencrypted backup that did not come from this device's own jobs (an upload or an adopted file):
    nothing in it is authenticated, so a restore needs an extra acknowledgement (CONTRACT section 7)."""
    return rec.get('encrypted', True) is False and rec.get('type') not in ('manual', 'safety')


class Storage:
    def __init__(self, paths, *, free_space=None):
        """`free_space(path) -> int` replaces statvfs (tests only)."""
        self.paths = paths
        self._free_space = free_space

    # ------------------------------------------------------------ layout and ids

    @property
    def exports(self):
        return Path(self.paths.data) / 'exports'

    def ensure_layout(self):
        """Create data/run dirs with mode 0700 (root-owned in production)."""
        for path in (self.paths.data, self.paths.archives, self.paths.uploads, self.paths.staging,
                     self.paths.pending, self.paths.jobs, self.paths.run, self.exports):
            try:
                util.ensure_dir(path, 0o700)
            except NotADirectoryError as exc:
                raise BackupError('internal-error', '備份資料目錄被替換為非目錄或符號連結，已停止。',
                                  path=str(path)) from exc

    def new_backup_id(self, now=None):
        return f'{util.compact_utc(now)}-{util.random_hex(4)}'

    def _check_id(self, backup_id):
        if not valid_backup_id(backup_id):
            raise BackupError('invalid-request', MSG_BAD_ID)
        return backup_id

    def archive_path(self, backup_id, fmt=None):
        """`archives/<id>.tar` or `archives/<id>.woowbackup`: the file that exists (format 2 first), else the name a
        new backup of format `fmt` gets (format 2 by default)."""
        self._check_id(backup_id)
        base = Path(self.paths.archives)
        if fmt is not None:
            return base / f'{backup_id}{EXTENSIONS[fmt]}'
        for ext in (EXTENSIONS[2], EXTENSIONS[1]):
            path = base / f'{backup_id}{ext}'
            if os.path.lexists(path):
                return path
        return base / f'{backup_id}{EXTENSIONS[2]}'

    def index_path(self, backup_id):
        return Path(self.paths.archives) / f'{self._check_id(backup_id)}.json'

    # ------------------------------------------------------------ index sidecars

    def _archive_stat(self, backup_id):
        try:
            st = os.lstat(self.archive_path(backup_id))
        except FileNotFoundError:
            return None
        return st if stat.S_ISREG(st.st_mode) else None

    def _archive_files(self, backup_id):
        """Every archive file of this id that exists (normally one)."""
        return [path for path in (self.archive_path(backup_id, 2), self.archive_path(backup_id, 1))
                if os.path.lexists(path)]

    def _load(self, backup_id):
        try:
            rec = util.load_json_file(self.index_path(backup_id), max_bytes=MAX_SIDECAR)
        except (OSError, ValueError):
            return None
        return rec if _valid_meta(rec, backup_id) else None

    def list_backups(self):
        """Index dicts (BackupMeta without key_available), newest first; ignores invalid sidecars."""
        try:
            names = os.listdir(self.paths.archives)
        except (FileNotFoundError, NotADirectoryError):
            return []
        records = []
        for name in names:
            if not name.endswith('.json') or not valid_backup_id(name[:-5]):
                continue
            rec = self._load(name[:-5])
            if rec is not None and self._archive_stat(rec['id']) is not None:
                records.append(rec)
        records.sort(key=lambda rec: (rec['created'] or '', rec['id']), reverse=True)
        return records

    def get(self, backup_id):
        """Index record for `backup_id`; raises BackupError('not-found') when absent or invalid."""
        self._check_id(backup_id)
        rec = self._load(backup_id)
        if rec is None or self._archive_stat(backup_id) is None:
            raise BackupError('not-found', MSG_NOT_FOUND, backup_id=backup_id)
        return rec

    def exists(self, backup_id):
        try:
            self.get(backup_id)
        except BackupError:
            return False
        return True

    def _normalize(self, backup_id, meta, st):
        rec = dict(meta)
        rec.pop('key_available', None)
        unknown = set(rec) - set(META_REQUIRED) - set(META_OPTIONAL)
        if unknown:
            raise BackupError('internal-error', '備份索引含有未定義的欄位。', fields=sorted(unknown)[:10])
        if rec.setdefault('id', backup_id) != backup_id:
            raise BackupError('internal-error', '備份索引的 ID 不一致。')
        source = rec.get('source')
        if isinstance(source, dict) and 'hostname' in source:
            rec['source'] = {'hostname': source['hostname']}
        rec.setdefault('created', None)
        rec.setdefault('note', '')
        rec.setdefault('apps', [])
        rec.setdefault('include_images', False)
        rec.setdefault('source', None)
        rec.setdefault('verified', None)
        rec.setdefault('inspected', False)
        path = self.archive_path(backup_id)
        rec.setdefault('format', 1 if path.name.endswith(EXTENSIONS[1]) else 2)
        rec.setdefault('encrypted', rec['format'] == 1 or rec.get('key_id') is not None)
        rec['size'] = st.st_size
        if 'sha256' not in rec:
            rec['sha256'] = util.sha256_file(path)
        if 'filename' not in rec:
            host = (rec['source'] or {}).get('hostname') or util.hostname()
            rec['filename'] = util.download_filename(host, rec['created'] or util.iso_utc(), rec['format'])
        rec = {key: rec[key] for key in (*META_REQUIRED, *META_OPTIONAL) if key in rec}
        if not _valid_meta(rec, backup_id):
            raise BackupError('internal-error', '備份索引資料格式不正確。', backup_id=backup_id)
        return rec

    @contextlib.contextmanager
    def _index_lock(self):
        """Exclusive flock on `<run>/index.lock` around one sidecar read-modify-write (held briefly, not nested).

        In the run directory (tmpfs) rather than in archives/, which holds archives and sidecars only.
        """
        run = util.ensure_dir(self.paths.run, 0o700)
        fd = os.open(Path(run) / 'index.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def register(self, backup_id, meta, *, exclusive=False):
        """Atomically write the index sidecar for an archive already in place; `exclusive=True` never replaces an
        existing sidecar, readable or not (raises invalid-request)."""
        self._check_id(backup_id)
        with self._index_lock():
            if exclusive and os.path.lexists(self.index_path(backup_id)):
                raise BackupError('invalid-request', '這份備份已有索引，未覆寫。', backup_id=backup_id)
            st = self._archive_stat(backup_id)
            if st is None:
                raise BackupError('not-found', MSG_NOT_FOUND, backup_id=backup_id)
            rec = self._normalize(backup_id, meta, st)
            util.atomic_write_json(self.index_path(backup_id), rec, 0o600)
        return rec

    def update(self, backup_id, **fields):
        """Change some fields of a sidecar, read and written under the index lock."""
        with self._index_lock():
            rec = self.get(backup_id)
            for key in fields:
                if key == 'id' or key not in (*META_REQUIRED, *META_OPTIONAL):
                    raise BackupError('internal-error', '不可更新此備份索引欄位。', field=str(key)[:64])
            rec.update(fields)
            source = rec.get('source')
            if isinstance(source, dict) and 'hostname' in source:
                rec['source'] = {'hostname': source['hostname']}
            if not _valid_meta(rec, backup_id):
                raise BackupError('internal-error', '備份索引資料格式不正確。', backup_id=backup_id)
            util.atomic_write_json(self.index_path(backup_id), rec, 0o600)
        return rec

    def delete(self, backup_id):
        index = self.index_path(backup_id)
        with self._index_lock():
            files = self._archive_files(backup_id)
            if not os.path.lexists(index) and not files:
                raise BackupError('not-found', MSG_NOT_FOUND, backup_id=backup_id)
            for target in (index, *files):  # sidecar first: a listed backup always has its file
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(target)
        util.fsync_dir(self.paths.archives)

    # ------------------------------------------------------------ space

    def _existing(self, path):
        path = Path(path)
        while not path.exists() and path != path.parent:
            path = path.parent
        return path

    def free_bytes(self):
        path = self._existing(self.paths.data)
        if self._free_space is not None:
            return int(self._free_space(path))
        st = os.statvfs(path)
        return st.f_bavail * st.f_frsize

    def total_bytes(self):
        st = os.statvfs(self._existing(self.paths.data))
        return st.f_blocks * st.f_frsize

    def usage(self):
        """`status.storage` shape: path, free_bytes, total_bytes, backups_bytes, backup_count."""
        backups = self.list_backups()
        return {'path': str(self.paths.data), 'free_bytes': self.free_bytes(), 'total_bytes': self.total_bytes(),
                'backups_bytes': sum(rec['size'] for rec in backups), 'backup_count': len(backups)}

    # ------------------------------------------------------------ staging

    def _staging_path(self, job_id):
        if not isinstance(job_id, str) or not STAGING_RE.match(job_id):
            raise BackupError('invalid-request', '工作 ID 格式不正確。')
        return Path(self.paths.staging) / job_id

    @staticmethod
    def _remove_tree(path):
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(path)  # fd-based on Linux: never follows symlinks inside the tree
        else:
            os.unlink(path)

    def staging_dir(self, job_id):
        """Create and return an empty 0700 staging directory for a job."""
        path = self._staging_path(job_id)
        self.ensure_layout()
        self._remove_tree(path)
        os.mkdir(path, 0o700)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
        return path

    def remove_staging(self, job_id):
        self._remove_tree(self._staging_path(job_id))

    # ------------------------------------------------------------ pre-restore copies

    def pending_path(self, job_id):
        """`pending/<job>/`: the pre-restore copy of an in-place restore until it is packaged (CONTRACT section 3)."""
        if not isinstance(job_id, str) or not STAGING_RE.match(job_id):
            raise BackupError('invalid-request', '工作 ID 格式不正確。')
        return Path(self.paths.pending) / job_id

    def pending_dir(self, job_id):
        """Create and return the job's empty 0700 pending directory. One that exists is never replaced: it may hold
        the only copy of the data an earlier restore changed."""
        path = self.pending_path(job_id)
        self.ensure_layout()
        if os.path.lexists(path):
            raise BackupError('internal-error', '這個作業的還原前資料資料夾已存在，已停止。', path=str(path))
        os.mkdir(path, 0o700)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
        return path

    def remove_pending(self, job_id):
        """Delete a pre-restore copy (after it was packaged, or before the restore changed anything)."""
        self._remove_tree(self.pending_path(job_id))

    # ------------------------------------------------------------ uploads

    def _upload_paths(self, upload_id):
        if not isinstance(upload_id, str) or not UPLOAD_ID_RE.match(upload_id):
            raise BackupError('invalid-request', '上傳 ID 格式不正確。')
        base = Path(self.paths.uploads)
        return base / f'{upload_id}.part', base / f'{upload_id}.json'

    def _pending_uploads(self):
        try:
            return sorted(m.group(1) for m in map(UPLOAD_FILE_RE.match, os.listdir(self.paths.uploads))
                          if m and m.group(2) == 'json')
        except FileNotFoundError:
            return []

    def begin_upload(self, filename, size):
        """Space check and placeholder; returns {'upload_id', 'path', 'max_size'}."""
        if (not isinstance(filename, str) or not 1 <= len(filename) <= 255
                or any(ord(c) < 32 or ord(c) == 127 for c in filename)):
            raise BackupError('invalid-request', '檔案名稱不正確。')
        if not isinstance(size, int) or isinstance(size, bool) or not MIN_UPLOAD <= size <= MAX_UPLOAD:
            raise BackupError('invalid-request', '檔案大小不正確或不是有效的備份檔。')
        self.ensure_layout()
        self.cleanup_uploads()
        if len(self._pending_uploads()) >= MAX_PENDING_UPLOADS:
            raise BackupError('busy', '同時進行中的上傳過多，請稍後再試。')
        free = self.free_bytes()
        max_size = max(0, free - self.paths.reserve_bytes)
        if size > max_size:
            raise BackupError('insufficient-space', '磁碟空間不足，無法上傳此備份檔。',
                              required=size + self.paths.reserve_bytes, free=free)
        upload_id = 'u' + util.random_hex(8)
        part, info = self._upload_paths(upload_id)
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        os.close(fd)
        util.atomic_write_json(info, {'upload_id': upload_id, 'filename': filename, 'size': size,
                                      'created': util.iso_utc()}, 0o600)
        return {'upload_id': upload_id, 'path': str(part), 'max_size': max_size}

    def _upload_info(self, upload_id, info_path):
        try:
            info = util.load_json_file(info_path, max_bytes=16 * 1024)
        except FileNotFoundError:
            raise BackupError('not-found', '找不到上傳工作，可能已逾時或取消。', upload_id=upload_id) from None
        except (OSError, ValueError):
            info = None
        if (not isinstance(info, dict) or info.get('upload_id') != upload_id
                or not isinstance(info.get('size'), int) or not isinstance(info.get('filename'), str)):
            raise BackupError('internal-error', '上傳工作的記錄已損毀。', upload_id=upload_id)
        return info

    def _done_path(self, upload_id):
        self._upload_paths(upload_id)
        return Path(self.paths.uploads) / f'{upload_id}.done'

    def _finished(self, upload_id):
        """BackupMeta of an upload that already finished (a retry after the page timed out), else None."""
        try:
            done = util.load_json_file(self._done_path(upload_id), max_bytes=4096)
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            return None
        backup_id = done.get('backup_id') if isinstance(done, dict) else None
        return self.get(backup_id) if valid_backup_id(backup_id) else None

    def _mark_done(self, upload_id, backup_id):
        with contextlib.suppress(OSError):
            util.atomic_write_json(self._done_path(upload_id), {'backup_id': backup_id, 'at': util.iso_utc()}, 0o600)

    def _register_uploaded(self, backup_id, header, sha256, filename, *, exclusive=False):
        """Index an uploaded (or adopted) file as type `uploaded`. Its apps stay empty until `inspect` read the
        authenticated manifests; backup.json of a format 2 file is not trusted for that (CONTRACT section 5)."""
        fmt = header.get('format', 1)
        original = (filename or '').strip().lower()
        keep = UPLOADED_NAME_RE.match(original) and original.endswith(EXTENSIONS[fmt])
        name = original if keep else util.download_filename('uploaded', header['created'], fmt)
        return self.register(backup_id, exclusive=exclusive, meta={
            'type': 'uploaded', 'created': header['created'], 'note': '', 'apps': [], 'sha256': sha256,
            'key_id': header['key_id'], 'include_images': False, 'filename': name, 'source': None,
            'verified': None, 'inspected': False, 'uploaded_at': util.iso_utc(), 'format': fmt,
            'encrypted': header.get('encryption', 'age-x25519') != 'none'})

    @contextlib.contextmanager
    def _upload_lock(self, upload_id, info_path):
        """Exclusive flock on the upload's `.json` (it exists from upload-begin until a successful finish removes it):
        a second upload-finish of the same upload waits here for the first one, then finds its `.done`."""
        try:
            fd = os.open(info_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        except FileNotFoundError:
            raise BackupError('not-found', '找不到上傳工作，可能已逾時或取消。', upload_id=upload_id) from None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)  # waiting stays interruptible: nothing is lost if this one is stopped
            yield
        finally:
            os.close(fd)

    def finish_upload(self, upload_id):
        """Validate the written file and register it as type 'uploaded'; returns BackupMeta.

        Idempotent: a retry after success returns the same backup (the page may time out while a large
        file is hashed). A failure after the file was moved puts it back, so nothing is left unlisted.
        Once the check started it runs to its end although the page timed out (review finding HD-08), and a
        concurrent retry waits for it.
        """
        part, info_path = self._upload_paths(upload_id)
        finished = self._finished(upload_id)
        if finished is not None:
            return finished
        with self._upload_lock(upload_id, info_path):
            finished = self._finished(upload_id)
            if finished is not None:
                return finished
            with util.termination_ignored():
                return self._finish_upload_locked(upload_id, part, info_path)

    def _finish_upload_locked(self, upload_id, part, info_path):
        info = self._upload_info(upload_id, info_path)
        try:
            fd = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        except FileNotFoundError:
            raise BackupError('not-found', '找不到上傳的檔案。', upload_id=upload_id) from None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise BackupError('invalid-request', '上傳的檔案不是一般檔案。') from None
            raise
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise BackupError('invalid-request', '上傳的檔案不是一般檔案。')
            if st.st_size != info['size']:
                raise BackupError('invalid-request', '上傳的檔案大小與宣告不符，上傳可能未完成。',
                                  expected=info['size'], actual=st.st_size)
            # Format 1: the outer header, then the file's sha256. Format 2: one pass over every byte checks the outer
            # tar strictly (backup.json, README.txt, each application archive against backup.json's sha256, the end
            # of the archive) and hashes the file. Neither needs a key; the content is checked by inspect/restore.
            hasher = hashlib.sha256()
            described = archive.describe_fd(fd, check_members=True, hasher=hasher)
            header = described['header']
            if described['format'] == 1:
                os.lseek(fd, 0, os.SEEK_SET)
                sha256 = util.sha256_fd(fd)[0]
            else:
                sha256 = hasher.hexdigest()
            backup_id = header['backup_id']
            dest = self.archive_path(backup_id, described['format'])
            present = self._archive_files(backup_id)
            if present or os.path.lexists(self.index_path(backup_id)):
                existing = self._load(backup_id)
                if existing is not None and existing['sha256'] == sha256 and self._archive_stat(backup_id):
                    self.abort_upload(upload_id)
                    self._mark_done(upload_id, backup_id)
                    return existing
                same_file = (existing is None and len(present) == 1 and present[0] == dest
                             and self._archive_stat(backup_id) is not None and util.sha256_file(dest) == sha256)
                if same_file and not os.path.lexists(self.index_path(backup_id)):
                    # The same file without an index (a kill between publishing and indexing): index it.
                    rec = self._register_uploaded(backup_id, header, sha256, info['filename'], exclusive=True)
                    self.abort_upload(upload_id)
                    self._mark_done(upload_id, backup_id)
                    return rec
                if same_file:
                    # Its index exists but cannot be read (e.g. a newer engine wrote it): kept as it is (HD-10).
                    raise BackupError('invalid-request', '這台設備已有這份備份，但它的索引無法讀取（可能由較新版本的備份元件建立），'
                                                         '已保留原狀，未重複上傳。', backup_id=backup_id)
                raise BackupError('invalid-request', '這台設備已有相同 ID 但內容不同的備份，已拒絕上傳。',
                                  backup_id=backup_id)
            os.fchmod(fd, 0o600)
            moved = False
            try:
                os.rename(part, dest)
                moved = True
                current = os.lstat(dest)
                if (current.st_dev, current.st_ino) != (st.st_dev, st.st_ino):
                    moved = False
                    os.unlink(dest)
                    raise BackupError('invalid-request', '上傳的檔案在驗證期間被更換，已拒絕。')
                util.fsync_dir(self.paths.archives)
                rec = self._register_uploaded(backup_id, header, sha256, info['filename'])
            except BaseException:
                if moved:  # back to the upload area: a retry can finish it, nothing stays unlisted
                    with contextlib.suppress(OSError):
                        os.rename(dest, part)
                raise
        finally:
            os.close(fd)
        self._mark_done(upload_id, backup_id)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(info_path)
        return rec

    def adopt_orphans(self, min_age=ORPHAN_MIN_AGE, now=None):
        """Index archives without a sidecar as 'uploaded' (a hard kill between publishing and indexing).

        Only files unchanged for `min_age` seconds are considered (ctime counts: a rename updates it), so an
        archive being published right now is never touched. A sidecar that exists but cannot be read or validated
        (a transient read error, a newer engine's extra field) is never replaced: adopting it turned a safety
        backup into an 'uploaded' one and dropped its apps and note (review finding HD-10). Returns the adopted ids.
        """
        now = time.time() if now is None else now
        try:
            names = os.listdir(self.paths.archives)
        except (FileNotFoundError, NotADirectoryError):
            return []
        adopted = []
        for name in sorted(names):
            backup_id, ext = '', None
            for fmt, suffix in EXTENSIONS.items():
                if name.endswith(suffix):
                    backup_id, ext = name[:-len(suffix)], fmt
            if not valid_backup_id(backup_id) or os.path.lexists(self.index_path(backup_id)):
                continue
            if len(self._archive_files(backup_id)) != 1:
                continue  # both names exist: never guess which one the index should describe
            path = self.archive_path(backup_id, ext)
            try:
                st = os.lstat(path)
                if not stat.S_ISREG(st.st_mode) or now - max(st.st_mtime, st.st_ctime) < min_age:
                    continue
                header = archive.read_header(path)
                if header['backup_id'] != backup_id or header.get('format', 1) != ext:
                    continue
                self._register_uploaded(backup_id, header, util.sha256_file(path), '', exclusive=True)
            except (BackupError, OSError, ValueError):
                continue
            adopted.append(backup_id)
        return adopted

    def abort_upload(self, upload_id):
        part, info = self._upload_paths(upload_id)
        removed = False
        for target in (part, info):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(target)
                removed = True
        with contextlib.suppress(FileNotFoundError):
            for name in os.listdir(self.paths.uploads):
                match = BRIDGE_TEMP_RE.match(name)
                if match and match.group(1) == upload_id:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(Path(self.paths.uploads) / name)
                        removed = True
        return removed

    def cleanup_uploads(self, max_age_seconds=86400):
        """Remove upload files (and cockpit temp files) older than `max_age_seconds`; returns the count."""
        try:
            names = os.listdir(self.paths.uploads)
        except FileNotFoundError:
            return 0
        cutoff = time.time() - max_age_seconds
        removed = 0
        for name in names:
            if not (UPLOAD_FILE_RE.match(name) or BRIDGE_TEMP_RE.match(name)):
                continue
            path = Path(self.paths.uploads) / name
            try:
                st = os.lstat(path)
                if st.st_mtime < cutoff and not stat.S_ISDIR(st.st_mode):
                    os.unlink(path)
                    removed += 1
            except FileNotFoundError:
                continue
        return removed

    # ------------------------------------------------------------ download

    def download_info(self, backup_id):
        rec = self.get(backup_id)
        path = self.archive_path(backup_id)
        st = os.lstat(path)
        real = os.path.realpath(path)
        base = os.path.realpath(self.paths.archives)
        if (not stat.S_ISREG(st.st_mode) or os.path.dirname(real) != base
                or os.path.basename(real) not in (f'{backup_id}{ext}' for ext in EXTENSIONS.values())):
            raise BackupError('permission-denied', '備份檔位置不安全，已拒絕下載。', backup_id=backup_id)
        return {'path': real, 'filename': rec['filename'], 'size': st.st_size}

    # ------------------------------------------------------------ unencrypted download copies (exports)

    def new_export_id(self):
        return 'x' + util.random_hex(8)

    def _export_paths(self, export_id):
        if not isinstance(export_id, str) or not EXPORT_ID_RE.match(export_id):
            raise BackupError('invalid-request', '下載副本 ID 格式不正確。')
        return self.exports / f'{export_id}.tar', self.exports / f'{export_id}.json'

    def _load_export(self, export_id):
        path, side = self._export_paths(export_id)
        try:
            rec = util.load_json_file(side, max_bytes=16 * 1024)
        except (OSError, ValueError):
            return None
        keys = {'export_id', 'backup_id', 'filename', 'size', 'sha256', 'created', 'expires'}
        if (not isinstance(rec, dict) or set(rec) != keys or rec['export_id'] != export_id
                or not valid_backup_id(rec['backup_id']) or not isinstance(rec['filename'], str)
                or not UPLOADED_NAME_RE.match(rec['filename']) or not rec['filename'].endswith('-unencrypted.tar')
                or not _is_int(rec['size']) or rec['size'] < 0 or not isinstance(rec['sha256'], str)
                or not SHA256_RE.match(rec['sha256']) or not util.is_iso_utc(rec['created'])
                or not _is_int(rec['expires'])):
            return None
        return rec

    def publish_export(self, export_id, staged, *, backup_id, filename, sha256, ttl=EXPORT_TTL, now=None,
                       evicted=None):
        """Move a verified unencrypted copy from staging into exports/ (rename, never overwrites; root 0600) and record
        when it expires. Older copies beyond MAX_EXPORTS - 1 are removed first (their ids are appended to `evicted`, for
        the journal; review F17). Returns the export record."""
        self.ensure_layout()
        now = time.time() if now is None else now
        path, side = self._export_paths(export_id)
        def age(rec):  # `created` has whole seconds: the copy's own mtime (ns) orders copies made in one second
            st = self._export_file(rec['export_id'])
            return (rec['created'], st.st_mtime_ns if st is not None else 0)

        current = sorted(self.list_exports(now=now), key=age)
        for rec in current[:max(0, len(current) - (MAX_EXPORTS - 1))]:
            if self.delete_export(rec['export_id']) and evicted is not None:
                evicted.append(rec['export_id'])
        if os.path.lexists(path) or os.path.lexists(side):
            raise BackupError('internal-error', '下載副本已存在。')
        fd = os.open(staged, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise BackupError('internal-error', '下載副本不是一般檔案。')
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        os.rename(staged, path)
        util.fsync_dir(self.exports)
        rec = {'export_id': export_id, 'backup_id': backup_id, 'filename': filename, 'size': st.st_size,
               'sha256': sha256, 'created': util.iso_utc(datetime.datetime.fromtimestamp(now, datetime.timezone.utc)),
               'expires': int(now) + int(ttl)}
        try:
            util.atomic_write_json(side, rec, 0o600)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)
            raise
        return rec

    def list_exports(self, *, now=None):
        """Records of the copies that exist and have not expired (expired ones are left to cleanup_exports)."""
        now = time.time() if now is None else now
        try:
            names = os.listdir(self.exports)
        except (FileNotFoundError, NotADirectoryError):
            return []
        found = []
        for name in sorted(names):
            match = EXPORT_FILE_RE.match(name)
            if not match or match.group(2) != 'json':
                continue
            rec = self._load_export(match.group(1))
            if rec is not None and rec['expires'] > now and self._export_file(match.group(1)) is not None:
                found.append(rec)
        return found

    def _export_file(self, export_id):
        path, _side = self._export_paths(export_id)
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        return st if stat.S_ISREG(st.st_mode) else None

    def export_info(self, export_id, *, now=None, removed=None):
        """{path, filename, size, expires, backup_id} of a copy that has not expired; not-found otherwise. Expired copies
        are deleted first (their ids are appended to `removed`, for the journal; review F17)."""
        now = time.time() if now is None else now
        gone = self.cleanup_exports(now=now)
        if removed is not None:
            removed.extend(gone)
        path, _side = self._export_paths(export_id)
        rec = self._load_export(export_id)
        st = self._export_file(export_id)
        if rec is None or st is None or rec['expires'] <= now:
            raise BackupError('not-found', '找不到這份未加密的下載副本（可能已過期並被刪除），請重新建立。',
                              export_id=export_id)
        real = os.path.realpath(path)
        if os.path.dirname(real) != os.path.realpath(self.exports) or os.path.basename(real) != f'{export_id}.tar':
            raise BackupError('permission-denied', '下載副本位置不安全，已拒絕下載。', export_id=export_id)
        if st.st_size != rec['size']:
            raise BackupError('not-found', '下載副本已損毀，請重新建立。', export_id=export_id)
        return {'path': real, 'filename': rec['filename'], 'size': st.st_size, 'expires': rec['expires'],
                'backup_id': rec['backup_id']}

    def delete_export(self, export_id):
        """Remove a copy (file first, then its record); True when something was removed."""
        path, side = self._export_paths(export_id)
        removed = False
        for target in (path, side):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(target)
                removed = True
        return removed

    def cleanup_exports(self, *, now=None):
        """Delete expired copies, copies without a valid record and leftover temp files (older than an hour).
        Returns the ids of the copies removed."""
        now = time.time() if now is None else now
        try:
            names = os.listdir(self.exports)
        except (FileNotFoundError, NotADirectoryError):
            return []
        removed = []
        for name in names:
            target = self.exports / name
            match = EXPORT_FILE_RE.match(name)
            if match:
                export_id = match.group(1)
                rec = self._load_export(export_id)
                if rec is not None and rec['expires'] > now:
                    continue
                if rec is None:
                    try:
                        st = os.lstat(target)
                    except FileNotFoundError:
                        continue
                    if now - max(st.st_mtime, st.st_ctime) < EXPORT_ORPHAN_AGE and match.group(2) == 'tar':
                        continue  # being published right now (the record follows the rename)
                if self.delete_export(export_id) and export_id not in removed:
                    removed.append(export_id)
            elif EXPORT_TEMP_RE.match(name):
                with contextlib.suppress(FileNotFoundError):
                    st = os.lstat(target)
                    if now - max(st.st_mtime, st.st_ctime) >= EXPORT_ORPHAN_AGE and not stat.S_ISDIR(st.st_mode):
                        os.unlink(target)
        return removed
