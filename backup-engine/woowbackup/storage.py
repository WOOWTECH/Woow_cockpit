"""Local backup storage, index sidecars, uploads and staging (CONTRACT section 3). Owner: E1.

Layout below `paths.data` (all 0700): `archives/<id>.woowbackup` + `archives/<id>.json` (index
sidecar, 0600), `uploads/<upload_id>.part` + `uploads/<upload_id>.json`, `staging/<job>/`, `jobs/`.
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
import errno
import fcntl
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
FILENAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,200}\.woowbackup\Z')
# Download names carry seconds since 2026-11 (`…-YYYYMMDD-HHMMSS`); older engines wrote `…-YYYYMMDD-HHMM`.
UPLOADED_NAME_RE = re.compile(r'^woowtech-backup-[a-z0-9-]{1,63}-[0-9]{8}-[0-9]{4}(?:[0-9]{2})?\.woowbackup\Z')
BRIDGE_TEMP_RE = re.compile(r'^\.(u[0-9a-f]{16})\.part-.+\Z')  # cockpit fsreplace1 temp files
UPLOAD_FILE_RE = re.compile(r'^(u[0-9a-f]{16})\.(part|json|done)\Z')
ORPHAN_MIN_AGE = 3600

TYPES = ('manual', 'safety', 'uploaded')
META_REQUIRED = ('id', 'type', 'created', 'note', 'apps', 'size', 'sha256', 'key_id', 'include_images',
                 'filename', 'source', 'verified', 'inspected')
META_OPTIONAL = ('uploaded_at',)
MAX_SIDECAR = 256 * 1024
MAX_PENDING_UPLOADS = 4
MIN_UPLOAD = 64
MAX_UPLOAD = 2 * 1024 ** 4

MSG_BAD_ID = '備份 ID 格式不正確。'
MSG_NOT_FOUND = '找不到指定的備份。'


def valid_backup_id(value):
    return isinstance(value, str) and BACKUP_ID_RE.match(value) is not None


def _valid_meta(rec, backup_id=None):
    """True when `rec` is a complete, well-typed index record (BackupMeta without key_available)."""
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
        if (not isinstance(app, dict) or set(app) != {'id', 'name'} or not isinstance(app['id'], str)
                or not isinstance(app['name'], str) or len(app['id']) > 64 or len(app['name']) > 200):
            return False
    size = rec['size']
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        return False
    if not isinstance(rec['sha256'], str) or not SHA256_RE.match(rec['sha256']):
        return False
    if not isinstance(rec['key_id'], str) or not KEY_ID_RE.match(rec['key_id']):
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
    if verified is not None and (not isinstance(verified, dict) or set(verified) != {'at', 'ok'}
                                 or not util.is_iso_utc(verified['at']) or not isinstance(verified['ok'], bool)):
        return False
    if 'uploaded_at' in rec and not util.is_iso_utc(rec['uploaded_at']):
        return False
    return True


class Storage:
    def __init__(self, paths, *, free_space=None):
        """`free_space(path) -> int` replaces statvfs (tests only)."""
        self.paths = paths
        self._free_space = free_space

    # ------------------------------------------------------------ layout and ids

    def ensure_layout(self):
        """Create data/run dirs with mode 0700 (root-owned in production)."""
        for path in (self.paths.data, self.paths.archives, self.paths.uploads, self.paths.staging,
                     self.paths.jobs, self.paths.run):
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

    def archive_path(self, backup_id):
        return Path(self.paths.archives) / f'{self._check_id(backup_id)}.woowbackup'

    def index_path(self, backup_id):
        return Path(self.paths.archives) / f'{self._check_id(backup_id)}.json'

    # ------------------------------------------------------------ index sidecars

    def _archive_stat(self, backup_id):
        try:
            st = os.lstat(self.archive_path(backup_id))
        except FileNotFoundError:
            return None
        return st if stat.S_ISREG(st.st_mode) else None

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
        rec['size'] = st.st_size
        if 'sha256' not in rec:
            rec['sha256'] = util.sha256_file(self.archive_path(backup_id))
        if 'filename' not in rec:
            host = (rec['source'] or {}).get('hostname') or util.hostname()
            rec['filename'] = util.download_filename(host, rec['created'] or util.iso_utc())
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
        index, path = self.index_path(backup_id), self.archive_path(backup_id)
        with self._index_lock():
            if not os.path.lexists(index) and not os.path.lexists(path):
                raise BackupError('not-found', MSG_NOT_FOUND, backup_id=backup_id)
            for target in (index, path):  # sidecar first: a listed backup always has its file
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
        original = (filename or '').strip().lower()
        name = original if UPLOADED_NAME_RE.match(original) else util.download_filename('uploaded', header['created'])
        return self.register(backup_id, exclusive=exclusive, meta={
            'type': 'uploaded', 'created': header['created'], 'note': '', 'apps': [], 'sha256': sha256,
            'key_id': header['key_id'], 'include_images': False, 'filename': name, 'source': None,
            'verified': None, 'inspected': False, 'uploaded_at': util.iso_utc()})

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
            header = archive._read_header_fd(fd)[0]
            os.lseek(fd, 0, os.SEEK_SET)
            sha256 = util.sha256_fd(fd)[0]
            backup_id = header['backup_id']
            dest = self.archive_path(backup_id)
            if os.path.lexists(dest) or os.path.lexists(self.index_path(backup_id)):
                existing = self._load(backup_id)
                if existing is not None and existing['sha256'] == sha256 and self._archive_stat(backup_id):
                    self.abort_upload(upload_id)
                    self._mark_done(upload_id, backup_id)
                    return existing
                same_file = (existing is None and self._archive_stat(backup_id) is not None
                             and util.sha256_file(dest) == sha256)
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
            backup_id = name[:-len('.woowbackup')] if name.endswith('.woowbackup') else ''
            if not valid_backup_id(backup_id) or os.path.lexists(self.index_path(backup_id)):
                continue
            path = self.archive_path(backup_id)
            try:
                st = os.lstat(path)
                if not stat.S_ISREG(st.st_mode) or now - max(st.st_mtime, st.st_ctime) < min_age:
                    continue
                header = archive.read_header(path)
                if header['backup_id'] != backup_id:
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
                or os.path.basename(real) != f'{backup_id}.woowbackup'):
            raise BackupError('permission-denied', '備份檔位置不安全，已拒絕下載。', backup_id=backup_id)
        return {'path': real, 'filename': rec['filename'], 'size': st.st_size}
