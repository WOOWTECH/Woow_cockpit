"""`.woowbackup` v1 format (CONTRACT section 5). Owner: E1 engine-core.

Outer header + age(X25519) ciphertext of zstd(PAX tar). `manifest.json` is the first member.
All readers treat the input as hostile until age and zstd exit 0 and every entry is verified.

Write path: tarfile 'w|' (PAX) -> `zstd -q -c -3 -T2` -> `age -e -r <recipient>` -> a pump thread
that hashes and appends to a temp file after the outer header -> fsync -> atomic rename.

Read path: outer header (+ age header sanity limits) -> `age -d -i …` reading the file after the
header -> `zstd -d -c` -> a strict, minimal tar parser written for exactly what tarfile emits
(ustar blocks with optional PAX 'x' records for `path`/`size`). Every member must be a regular file
whose name, size and sha256 equal the next manifest entry; anything else (links, devices, dirs,
GNU/global/sparse headers, extra or missing members, trailing data) is rejected. Subprocess stderr
goes to temp files, so nothing can deadlock, and every exit path kills and reaps the children.
"""
import contextlib
import errno
import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from . import util
from .errors import BackupError
from .keys import KEY_ID_RE, RECIPIENT_RE, key_id_for

MAGIC = b'WOOWTECH-BACKUP/1\n'
FORMAT = 1
MAX_HEADER = 4096
MAX_MANIFEST = 1024 * 1024
MAX_MEMBERS = 4000

FAMILY = b'WOOWTECH-BACKUP/'
AGE_MAGIC = b'age-encryption.org/v1\n'
MAX_AGE_HEADER = 16 * 1024
MAX_AGE_STANZAS = 32
MIN_AGE_PAYLOAD = 32  # 16-byte nonce + at least one 16-byte chunk tag
HEADER_KEYS = ('format', 'backup_id', 'created', 'key_id', 'encryption', 'compression')
ENCRYPTION = 'age-x25519'
COMPRESSION = 'zstd'

BLOCK = 512
ZERO_BLOCK = bytes(BLOCK)
USTAR_MAGIC = b'ustar\x0000'
MAX_PAX = 16 * 1024
MAX_TRAILER = 1024 * 1024
CHUNK = 1024 * 1024
PROGRESS_STEP = 8 * 1024 * 1024
TOOL_WAIT = 60

BACKUP_ID_RE = re.compile(r'^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
SHA256_RE = re.compile(r'^[0-9a-f]{64}\Z')
ENTRY_RE = re.compile(r'^apps/[a-z0-9][a-z0-9-]{1,40}/(images|postgres|volumes|secrets|config|quadlet)/'
                      r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,200}\Z')
APP_ID_RE = re.compile(r'^[a-z0-9][a-z0-9-]{1,40}\Z')
ADAPTER_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,40}\Z')
OWNER_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}\Z')
VOLUME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
SECRET_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,200}\Z')
QUADLET_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.@-]*\.(container|network|volume|pod)\Z')
PG_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')
PG_DB_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.$-]{0,62}\Z')
IMAGE_REF_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,511}\Z')
IMAGE_ID_RE = re.compile(r'^(sha256:)?[0-9a-f]{64}\Z')
IMAGE_DIGEST_RE = re.compile(r'^(sha256:[0-9a-f]{64})?\Z')
ARCH_RE = re.compile(r'^[A-Za-z0-9_.-]{0,32}\Z')
MACHINE_ID_RE = re.compile(r'^([0-9a-f]{64})?\Z')
METHOD_RE = re.compile(r'^[a-z][a-z0-9-]{0,40}\Z')
MODE_RE = re.compile(r'^0[0-7]{3}\Z')
VERIFY_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')
CONFIG_SEGMENT_RE = re.compile(r'^[^\x00-\x1f\x7f/\\]{1,255}\Z')
SECTIONS = {  # manifest app section -> entry category directory
    'images': 'images', 'postgres': 'postgres', 'volumes': 'volumes',
    'secrets': 'secrets', 'config_files': 'config', 'quadlet_files': 'quadlet',
}
MAX_SIZE = 2 ** 53


@dataclass(frozen=True)
class Entry:
    """A file to add. `path` is the archive member name, `source` a local regular file."""
    path: str
    source: Path
    size: int
    sha256: str


@dataclass(frozen=True)
class Limits:
    """Reader limits. `free_bytes(path) -> int` overrides statvfs (tests inject it)."""
    max_members: int = MAX_MEMBERS
    max_manifest: int = MAX_MANIFEST
    max_total_bytes: int = 2 * 1024 ** 4
    reserve_bytes: int = 512 * 1024 * 1024
    free_bytes: object = None


def entry_from_file(path, source):
    """Entry for a staged regular file (size and sha256 computed now)."""
    st = os.lstat(source)
    if not stat.S_ISREG(st.st_mode):
        raise BackupError('internal-error', '備份暫存檔不是一般檔案。', entry=path)
    return Entry(path, Path(source), st.st_size, util.sha256_file(source))


# ====================================================================== errors

def _corrupt(reason, **details):
    return BackupError('corrupt-archive', '備份檔已損毀或遭到修改，無法使用。', reason=reason, **details)


def _invalid(reason, **details):
    return BackupError('invalid-manifest', '備份內容清單（manifest）格式不正確。', reason=reason, **details)


def _limit(reason, **details):
    return BackupError('limit-exceeded', '備份檔超出安全限制（檔案數量或大小），已拒絕處理。', reason=reason, **details)


class _Truncated(Exception):
    """The decrypted/decompressed stream ended early; the tool exit status decides the error."""


# ====================================================================== outer header

def _valid_backup_id(value):
    if not isinstance(value, str) or not BACKUP_ID_RE.match(value):
        return False
    try:
        util.parse_iso_utc(f'{value[0:4]}-{value[4:6]}-{value[6:8]}T{value[9:11]}:{value[11:13]}:{value[13:15]}Z')
    except ValueError:
        return False
    return True


def _check_header_dict(header):
    """Validate the parsed JSON header line (format and algorithms first, then strict keys)."""
    if not isinstance(header, dict):
        raise _corrupt('header is not an object')
    fmt = header.get('format')
    if not isinstance(fmt, int) or isinstance(fmt, bool):
        raise _corrupt('header format missing')
    if fmt != FORMAT:
        raise BackupError('unsupported-format', '不支援此備份檔版本，請更新這台設備的備份元件。', version=fmt)
    if header.get('encryption') != ENCRYPTION or header.get('compression') != COMPRESSION:
        if isinstance(header.get('encryption'), str) and isinstance(header.get('compression'), str):
            raise BackupError('unsupported-format', '不支援此備份檔的加密或壓縮方式。')
        raise _corrupt('header algorithms missing')
    if set(header) != set(HEADER_KEYS):
        raise _corrupt('header keys mismatch')
    if not _valid_backup_id(header['backup_id']):
        raise _corrupt('header backup_id invalid')
    if not util.is_iso_utc(header['created']):
        raise _corrupt('header created invalid')
    if not isinstance(header['key_id'], str) or not KEY_ID_RE.match(header['key_id']):
        raise _corrupt('header key_id invalid')
    return header


def _parse_prefix(buf, file_size):
    """Parse header from the first bytes of a file. Returns (header, age_offset)."""
    eof = len(buf) >= file_size
    if not buf.startswith(MAGIC):
        newline = buf.find(b'\n', 0, 64)
        if newline >= 0:
            match = re.fullmatch(rb'WOOWTECH-BACKUP/([1-9][0-9]{0,8})', buf[:newline])
            if match and int(match.group(1)) != FORMAT:
                raise BackupError('unsupported-format', '不支援此備份檔版本，請更新這台設備的備份元件。',
                                  version=int(match.group(1)))
            raise BackupError('not-a-backup', '這不是 woowtech 備份檔（.woowbackup）。')
        if eof and len(buf) >= 8 and (MAGIC.startswith(buf) or buf.startswith(FAMILY)):
            raise _corrupt('truncated in format line')
        raise BackupError('not-a-backup', '這不是 woowtech 備份檔（.woowbackup）。')
    pos = len(MAGIC)
    end = buf.find(b'\n', pos, pos + MAX_HEADER)
    if end < 0:
        raise _corrupt('truncated header' if eof and len(buf) < pos + MAX_HEADER else 'header line too long')
    try:
        header = util.loads_strict(buf[pos:end], max_bytes=MAX_HEADER)
    except ValueError:
        raise _corrupt('header is not valid JSON') from None
    _check_header_dict(header)
    age_start = end + 1
    age = buf[age_start:age_start + MAX_AGE_HEADER]
    if not age.startswith(AGE_MAGIC):
        raise _corrupt('truncated before encrypted data' if eof and AGE_MAGIC.startswith(age)
                       else 'encrypted data is not age v1')
    mac = age.find(b'\n--- ', len(AGE_MAGIC) - 1)
    mac_end = age.find(b'\n', mac + 1) if mac >= 0 else -1
    if mac < 0 or mac_end < 0:
        raise _corrupt('truncated age header' if eof and len(age) < MAX_AGE_HEADER
                       else 'age header has no MAC line within the size limit')
    stanzas = age[:mac + 1].count(b'\n-> ')
    if stanzas < 1 or stanzas > MAX_AGE_STANZAS:
        raise _corrupt('age header stanza count', stanzas=stanzas)
    if file_size - (age_start + mac_end + 1) < MIN_AGE_PAYLOAD:
        raise _corrupt('truncated encrypted payload')
    return header, age_start


def _read_header_fd(fd):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise BackupError('not-a-backup', '這不是 woowtech 備份檔（.woowbackup）。')
    want = len(MAGIC) + MAX_HEADER + MAX_AGE_HEADER + 1
    buf = os.pread(fd, want, 0)
    while len(buf) < min(want, st.st_size):
        more = os.pread(fd, want - len(buf), len(buf))
        if not more:
            break
        buf += more
    return _parse_prefix(buf, st.st_size)


def _open_archive(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        raise BackupError('not-found', '找不到備份檔。') from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise BackupError('not-a-backup', '這不是 woowtech 備份檔（.woowbackup）。') from None
        raise
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
    return fd


def read_header(path):
    """Return the validated outer header dict; raise BackupError(not-a-backup|unsupported-format|corrupt-archive)."""
    fd = _open_archive(path)
    try:
        return _read_header_fd(fd)[0]
    finally:
        os.close(fd)


def header_bytes(header):
    return MAGIC + json.dumps({k: header[k] for k in HEADER_KEYS}, separators=(',', ':')).encode('ascii') + b'\n'


# ====================================================================== manifest schema

def _need(cond, reason, **details):
    if not cond:
        raise _invalid(reason, **details)


def _obj(value, where, required, optional=()):
    _need(isinstance(value, dict), f'{where} must be an object')
    keys = set(value)
    missing = sorted(set(required) - keys)
    unknown = sorted(keys - set(required) - set(optional))
    _need(not missing, f'{where} missing keys', keys=missing[:10])
    _need(not unknown, f'{where} has unknown keys', keys=[str(k)[:64] for k in unknown[:10]])


def _utf8(value):
    """False for text that is not valid Unicode (a lone surrogate from a JSON \\ud800 escape)."""
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True


def _str(value, where, pattern=None, min_len=0, max_len=200):
    _need(isinstance(value, str) and min_len <= len(value) <= max_len, f'{where} must be a string')
    _need('\x00' not in value, f'{where} contains NUL')
    # A lone surrogate passed every other check and later crashed `inspect` output and job records
    # (review finding SEC-5).
    _need(_utf8(value), f'{where} is not valid Unicode text')
    if pattern is not None:
        _need(pattern.match(value) is not None, f'{where} has an invalid format')


def _int(value, where, lo, hi):
    _need(isinstance(value, int) and not isinstance(value, bool) and lo <= value <= hi, f'{where} out of range')


def _list(value, where, max_items, min_items=0):
    _need(isinstance(value, list) and min_items <= len(value) <= max_items, f'{where} must be a list')


def _json_value(value, where, depth=0):
    _need(depth <= 4, f'{where} nested too deeply')
    if isinstance(value, dict):
        _need(len(value) <= 100, f'{where} too many keys')
        for key, item in value.items():
            _str(key, f'{where} key', max_len=100)
            _json_value(item, where, depth + 1)
    elif isinstance(value, list):
        _need(len(value) <= 1000, f'{where} too many items')
        for item in value:
            _json_value(item, where, depth + 1)
    elif isinstance(value, str):
        _need(len(value) <= 16384, f'{where} string too long')
        _need(_utf8(value), f'{where} is not valid Unicode text')
    elif isinstance(value, float):
        _need(value == value and abs(value) != float('inf'), f'{where} not finite')
    else:
        _need(value is None or isinstance(value, (bool, int)), f'{where} has an invalid type')


def _config_path(value, where):
    _str(value, where, min_len=1, max_len=1024)
    _need(not value.startswith('/'), f'{where} must be relative')
    segments = value.split('/')
    _need(all(s not in ('', '.', '..') and CONFIG_SEGMENT_RE.match(s) for s in segments),
          f'{where} has invalid segments')
    _need(value.startswith('.config/') or value.startswith('.local/share/'),
          f'{where} must be under .config/ or .local/share/')


def validate_manifest(manifest):
    """Strict schema validation; returns the manifest or raises BackupError('invalid-manifest')."""
    _obj(manifest, 'manifest', ('format', 'backup_id', 'created', 'type', 'note', 'key_id', 'tool',
                                'source', 'consistency', 'apps', 'entries'))
    _int(manifest['format'], 'format', FORMAT, FORMAT)
    _need(_valid_backup_id(manifest['backup_id']), 'backup_id has an invalid format')
    _need(util.is_iso_utc(manifest['created']), 'created has an invalid format')
    _need(manifest['type'] in ('manual', 'safety'), 'type must be manual or safety')
    _str(manifest['note'], 'note', max_len=1000)
    _str(manifest['key_id'], 'key_id', KEY_ID_RE)

    tool = manifest['tool']
    _obj(tool, 'tool', ('name', 'version'))
    _str(tool['name'], 'tool.name', min_len=1, max_len=100)
    _str(tool['version'], 'tool.version', min_len=1, max_len=100)

    source = manifest['source']
    _obj(source, 'source', ('hostname', 'machine_id_sha256', 'arch', 'os', 'podman'))
    _str(source['hostname'], 'source.hostname', min_len=1, max_len=255)
    _str(source['machine_id_sha256'], 'source.machine_id_sha256', MACHINE_ID_RE, max_len=64)
    _str(source['arch'], 'source.arch', ARCH_RE, max_len=32)
    _str(source['os'], 'source.os', max_len=200)
    _str(source['podman'], 'source.podman', max_len=64)

    consistency = manifest['consistency']
    _obj(consistency, 'consistency', ('method', 'downtime_seconds'))
    _str(consistency['method'], 'consistency.method', METHOD_RE, max_len=41)
    downtime = consistency['downtime_seconds']
    _need(isinstance(downtime, (int, float)) and not isinstance(downtime, bool)
          and downtime == downtime and 0 <= downtime <= 10 ** 7, 'consistency.downtime_seconds out of range')

    entries = manifest['entries']
    _list(entries, 'entries', MAX_MEMBERS - 1)
    by_path = {}
    for index, entry in enumerate(entries):
        where = f'entries[{index}]'
        _obj(entry, where, ('path', 'size', 'sha256'))
        _str(entry['path'], f'{where}.path', ENTRY_RE, max_len=300)
        _int(entry['size'], f'{where}.size', 0, MAX_SIZE)
        _str(entry['sha256'], f'{where}.sha256', SHA256_RE, max_len=64)
        _need(entry['path'] not in by_path, 'duplicate entry path', path=entry['path'])
        by_path[entry['path']] = entry

    referenced = set()

    def ref(app_id, section, value, where):
        _str(value, where, ENTRY_RE, max_len=300)
        _need(value.startswith(f'apps/{app_id}/{SECTIONS[section]}/'), f'{where} outside its app section',
              path=value)
        _need(value in by_path, f'{where} not listed in entries', path=value)
        _need(value not in referenced, f'{where} referenced twice', path=value)
        referenced.add(value)

    apps = manifest['apps']
    _list(apps, 'apps', 100, min_items=1)
    app_ids = set()
    for index, app in enumerate(apps):
        where = f'apps[{index}]'
        _obj(app, where, ('id', 'name', 'adapter', 'adapter_version', 'catalog_sha256', 'owner', 'images',
                          'postgres', 'volumes', 'secrets', 'config_files', 'quadlet_files', 'verify_snapshot'))
        _str(app['id'], f'{where}.id', APP_ID_RE, max_len=41)
        app_id = app['id']
        _need(app_id not in app_ids, 'duplicate app id', app=app_id)
        app_ids.add(app_id)
        _str(app['name'], f'{where}.name', min_len=1, max_len=200)
        _str(app['adapter'], f'{where}.adapter', ADAPTER_RE, max_len=41)
        _int(app['adapter_version'], f'{where}.adapter_version', 1, 1000)
        _str(app['catalog_sha256'], f'{where}.catalog_sha256', SHA256_RE, max_len=64)
        owner = app['owner']
        _obj(owner, f'{where}.owner', ('name', 'uid'))
        _str(owner['name'], f'{where}.owner.name', OWNER_RE, max_len=32)
        _need(owner['name'] != 'root', 'owner root is not allowed')
        _int(owner['uid'], f'{where}.owner.uid', 1, 2 ** 32 - 2)

        _list(app['images'], f'{where}.images', 50)
        for i, item in enumerate(app['images']):
            w = f'{where}.images[{i}]'
            _obj(item, w, ('ref', 'id', 'digest', 'arch'), ('entry',))
            _str(item['ref'], f'{w}.ref', IMAGE_REF_RE, max_len=512)
            _str(item['id'], f'{w}.id', IMAGE_ID_RE, max_len=71)
            _str(item['digest'], f'{w}.digest', IMAGE_DIGEST_RE, max_len=71)
            _str(item['arch'], f'{w}.arch', ARCH_RE, max_len=32)
            if 'entry' in item:
                ref(app_id, 'images', item['entry'], f'{w}.entry')

        _list(app['postgres'], f'{where}.postgres', 20)
        seen = set()
        for i, item in enumerate(app['postgres']):
            w = f'{where}.postgres[{i}]'
            _obj(item, w, ('id', 'database', 'server_version', 'major', 'entry'))
            _str(item['id'], f'{w}.id', PG_ID_RE, max_len=64)
            _need(item['id'] not in seen, f'{w}.id duplicate')
            seen.add(item['id'])
            _str(item['database'], f'{w}.database', PG_DB_RE, max_len=63)
            _str(item['server_version'], f'{w}.server_version', min_len=1, max_len=100)
            _int(item['major'], f'{w}.major', 1, 999)
            ref(app_id, 'postgres', item['entry'], f'{w}.entry')

        for section, key, pattern, max_len, limit in (('volumes', 'name', VOLUME_RE, 128, 50),
                                                       ('secrets', 'name', SECRET_NAME_RE, 201, 100),
                                                       ('quadlet_files', 'name', QUADLET_RE, 255, 50)):
            _list(app[section], f'{where}.{section}', limit)
            seen = set()
            for i, item in enumerate(app[section]):
                w = f'{where}.{section}[{i}]'
                _obj(item, w, (key, 'entry'))
                _str(item[key], f'{w}.{key}', pattern, min_len=1, max_len=max_len)
                _need(item[key] not in seen, f'{w}.{key} duplicate')
                seen.add(item[key])
                ref(app_id, section, item['entry'], f'{w}.entry')

        _list(app['config_files'], f'{where}.config_files', 100)
        seen = set()
        for i, item in enumerate(app['config_files']):
            w = f'{where}.config_files[{i}]'
            _obj(item, w, ('path', 'mode', 'entry'))
            _config_path(item['path'], f'{w}.path')
            _need(item['path'] not in seen, f'{w}.path duplicate')
            seen.add(item['path'])
            _str(item['mode'], f'{w}.mode', MODE_RE, max_len=4)
            _need(int(item['mode'], 8) & ~0o644 == 0, f'{w}.mode exceeds 0644')
            ref(app_id, 'config_files', item['entry'], f'{w}.entry')

        snapshot = app['verify_snapshot']
        _need(isinstance(snapshot, dict) and len(snapshot) <= 20, f'{where}.verify_snapshot must be an object')
        for key, value in snapshot.items():
            _str(key, f'{where}.verify_snapshot key', VERIFY_ID_RE, max_len=64)
            _need(isinstance(value, dict), f'{where}.verify_snapshot.{key} must be an object')
            _json_value(value, f'{where}.verify_snapshot.{key}')

    orphans = sorted(set(by_path) - referenced)
    _need(not orphans, 'entries not referenced by any app', paths=orphans[:10])
    return manifest


# ====================================================================== tools

def _tools():
    age, zstd = util.find_tool('age'), util.find_tool('zstd')
    if age is None or zstd is None:
        raise BackupError('internal-error', '系統缺少 age 或 zstd 工具，無法處理加密備份。')
    return age, zstd


def _grow_pipe(fileobj):
    with contextlib.suppress(OSError, AttributeError, ValueError):
        fcntl.fcntl(fileobj.fileno(), fcntl.F_SETPIPE_SZ, CHUNK)


def _stderr_text(handle):
    try:
        handle.seek(0)
        return handle.read(8192).decode('utf-8', 'replace')
    except (OSError, ValueError):
        return ''


def _identity_file_key_ids(path):
    """Key ids of an age identity file via `age-keygen -y` (file on stdin); empty set when invalid."""
    tool = util.find_tool('age-keygen')
    if tool is None:
        return set()
    try:
        with open(path, 'rb') as handle:
            proc = subprocess.run([tool, '-y'], stdin=handle, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  env=util.clean_env(), timeout=30, close_fds=True, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return set()
    lines = proc.stdout.decode('ascii', 'replace').split()
    if proc.returncode != 0 or not lines or not all(RECIPIENT_RE.match(line) for line in lines):
        return set()
    return {key_id_for(line) for line in lines}


def _reap(procs):
    """Kill (if still running) and wait for every process; never leaves zombies."""
    for proc in procs:
        if proc.poll() is None:
            with contextlib.suppress(OSError):
                proc.kill()
    for proc in procs:
        with contextlib.suppress(Exception):
            proc.wait()


class _Progress:
    def __init__(self, callback, total):
        self.callback, self.total, self.done, self.last = callback, total, 0, 0

    def add(self, count):
        self.done += count
        if self.callback and self.done - self.last >= PROGRESS_STEP:
            self.last = self.done
            self.callback(self.done, self.total)

    def finish(self):
        if self.callback:
            self.callback(self.done, self.total)


# ====================================================================== writer

class _Pump(threading.Thread):
    """Copy age's stdout into the archive temp file while hashing it."""

    def __init__(self, source, out_fd, digest):
        super().__init__(name='woowbackup-pump', daemon=True)
        self.source, self.out_fd, self.digest = source, out_fd, digest
        self.total, self.error = 0, None

    def run(self):
        try:
            fd = self.source.fileno()
            while True:
                buf = os.read(fd, CHUNK)
                if not buf:
                    return
                self.digest.update(buf)
                view = memoryview(buf)
                while view:
                    view = view[os.write(self.out_fd, view):]
                self.total += len(buf)
        except BaseException as exc:  # noqa: BLE001 - reported by the writer thread
            self.error = exc
            # Closing the read end makes age (and then zstd) fail instead of blocking forever.
            with contextlib.suppress(OSError):
                self.source.close()


class _HashingReader:
    def __init__(self, fd, progress):
        self.fd, self.progress = fd, progress
        self.digest, self.count = hashlib.sha256(), 0

    def read(self, size=-1):
        if size is None or size < 0:
            size = CHUNK
        parts, need = [], size
        while need:
            buf = os.read(self.fd, min(need, CHUNK))
            if not buf:
                break
            parts.append(buf)
            need -= len(buf)
        data = b''.join(parts)
        self.digest.update(data)
        self.count += len(data)
        self.progress.add(len(data))
        return data


def _tarinfo(name, size, mtime):
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o600
    info.uid = info.gid = 0
    info.uname = info.gname = 'root'
    info.mtime = mtime
    info.type = tarfile.REGTYPE
    return info


def _map_os_error(exc, what):
    if isinstance(exc, OSError) and exc.errno in (errno.ENOSPC, errno.EDQUOT):
        return BackupError('insufficient-space', '磁碟空間不足，無法完成備份封裝。')
    return BackupError('internal-error', f'{what}失敗。', reason=type(exc).__name__)


def write_archive(dest, header, manifest, entries, recipient, *, tmp_dir, progress=None):
    """Write atomically (temp in `tmp_dir` on the same filesystem, fsync, rename to `dest`).

    `manifest['entries']` is (re)built from `entries` in order. Returns {'size', 'sha256'} of the file.
    `progress(done_bytes, total_bytes)` is optional.
    """
    dest, tmp_dir = Path(dest), Path(tmp_dir)
    entries = list(entries)
    if not isinstance(recipient, str) or not RECIPIENT_RE.match(recipient):
        raise BackupError('internal-error', '加密金鑰的公開金鑰格式不正確。')
    key_id = key_id_for(recipient)
    manifest = dict(manifest)
    manifest['entries'] = [{'path': e.path, 'size': e.size, 'sha256': e.sha256} for e in entries]
    hdr = {'format': FORMAT, 'backup_id': manifest.get('backup_id'), 'created': manifest.get('created'),
           'key_id': key_id, 'encryption': ENCRYPTION, 'compression': COMPRESSION}
    for key, value in (header or {}).items():
        if key not in hdr or hdr[key] != value:
            raise BackupError('internal-error', '備份標頭與內容清單不一致。', field=str(key)[:64])
    if manifest.get('key_id') != key_id:
        raise BackupError('internal-error', '內容清單的金鑰 ID 與加密金鑰不符。')
    validate_manifest(manifest)
    try:
        _check_header_dict(dict(hdr))
    except BackupError as exc:
        raise BackupError('internal-error', '備份標頭格式不正確。', reason=exc.details.get('reason')) from None
    manifest_data = json.dumps(manifest, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(manifest_data) > MAX_MANIFEST:
        raise _limit('manifest too large', size=len(manifest_data))
    if len(entries) + 1 > MAX_MEMBERS:
        raise _limit('too many members', members=len(entries) + 1)
    for entry in entries:
        try:
            st = os.lstat(entry.source)
        except OSError:
            st = None
        if st is None or not stat.S_ISREG(st.st_mode) or st.st_size != entry.size:
            raise BackupError('internal-error', '備份暫存檔不存在或大小與記錄不符。', entry=entry.path)
    if os.path.lexists(dest):
        raise BackupError('internal-error', '目標備份檔已存在。')

    age_bin, zstd_bin = _tools()
    mtime = int(util.parse_iso_utc(manifest['created']).timestamp())
    head = header_bytes(hdr)
    tmp_path = tmp_dir / f'.{manifest["backup_id"]}.{util.random_hex(6)}.woowbackup.tmp'
    digest = hashlib.sha256()
    procs, pump, renamed = [], None, False
    meter = _Progress(progress, sum(e.size for e in entries))
    age_err, zstd_err = tempfile.TemporaryFile(), tempfile.TemporaryFile()
    try:
        out_fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as exc:
        age_err.close()
        zstd_err.close()
        raise _map_os_error(exc, '建立備份暫存檔') from exc
    # The recipient goes to age in a private file, not in argv where every local account could read it
    # from /proc (review finding SEC-7: it lets anyone encrypt a hostile archive to this device's key).
    recipients_path = tmp_dir / f'.recipient-{util.random_hex(6)}'
    try:
        view = memoryview(head)
        while view:
            view = view[os.write(out_fd, view):]
        digest.update(head)
        rfd = os.open(recipients_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(rfd, (recipient + '\n').encode('ascii'))
        finally:
            os.close(rfd)
        env = util.clean_env()
        age = subprocess.Popen([age_bin, '-e', '-R', str(recipients_path)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=age_err, env=env, close_fds=True)
        procs.append(age)
        zstd = subprocess.Popen([zstd_bin, '-q', '-c', '-3', '-T2'], stdin=subprocess.PIPE, stdout=age.stdin,
                                stderr=zstd_err, env=env, close_fds=True, bufsize=CHUNK)
        procs.append(zstd)
        age.stdin.close()  # zstd holds the only write end now: EOF reaches age when zstd exits
        _grow_pipe(age.stdout)
        _grow_pipe(zstd.stdin)
        pump = _Pump(age.stdout, out_fd, digest)
        pump.start()
        try:
            with tarfile.open(fileobj=zstd.stdin, mode='w|', format=tarfile.PAX_FORMAT, bufsize=CHUNK,
                              copybufsize=CHUNK) as tar:
                tar.addfile(_tarinfo('manifest.json', len(manifest_data), mtime), io.BytesIO(manifest_data))
                for entry in entries:
                    src = os.open(entry.source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        if not stat.S_ISREG(os.fstat(src).st_mode):
                            raise BackupError('internal-error', '備份暫存檔不是一般檔案。', entry=entry.path)
                        reader = _HashingReader(src, meter)
                        try:
                            tar.addfile(_tarinfo(entry.path, entry.size, mtime), reader)
                        except OSError as exc:
                            if reader.count < entry.size and not isinstance(exc, BrokenPipeError):
                                raise BackupError('internal-error', '備份暫存檔在封裝時變短。',
                                                  entry=entry.path) from None
                            raise
                        if reader.digest.hexdigest() != entry.sha256:
                            raise BackupError('internal-error', '封裝時來源檔案的校驗值與記錄不符。', entry=entry.path)
                    finally:
                        os.close(src)
            zstd.stdin.close()
        except (BrokenPipeError, ConnectionResetError):
            # A tool died; its exit status and stderr explain why (checked below).
            with contextlib.suppress(OSError):
                zstd.stdin.close()
        zstd_rc = zstd.wait()
        pump.join()
        age_rc = age.wait()
        if pump.error is not None:
            raise _map_os_error(pump.error, '寫入備份檔')
        if zstd_rc != 0 or age_rc != 0:
            raise BackupError('internal-error', '壓縮或加密程序失敗。', age_exit=age_rc, zstd_exit=zstd_rc,
                              stderr=(_stderr_text(age_err) + _stderr_text(zstd_err))[-500:])
        # Last progress report before publishing: a cancel raised by the callback discards the temp file.
        meter.finish()
        os.fsync(out_fd)
        os.close(out_fd)
        out_fd = -1
        if os.path.lexists(dest):
            raise BackupError('internal-error', '目標備份檔已存在。')
        os.rename(tmp_path, dest)
        renamed = True
        util.fsync_dir(dest.parent)
        return {'size': len(head) + pump.total, 'sha256': digest.hexdigest()}
    except BackupError:
        raise
    except OSError as exc:
        raise _map_os_error(exc, '建立備份檔') from exc
    finally:
        # Order matters: kill/reap first (EOF reaches the pump), join the pump, and only then close
        # the pipe objects, so no fd number is closed while another thread may still read it.
        _reap(procs)
        if pump is not None:
            pump.join()
        for proc in procs:
            for handle in (proc.stdin, proc.stdout):
                if handle is not None:
                    with contextlib.suppress(OSError):
                        handle.close()
        if out_fd >= 0:
            os.close(out_fd)
        if not renamed:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_path)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(recipients_path)
        age_err.close()
        zstd_err.close()


# ====================================================================== reader

class _Decryptor:
    """`age -d` | `zstd -d` over an archive file; plaintext is read from zstd's stdout."""

    def __init__(self, path, identity_files):
        self.procs = []
        self.out = None
        self.age_err = self.zstd_err = None
        fd = _open_archive(path)
        try:
            self.header, offset = _read_header_fd(fd)
            # age aborts completely if ANY identity file is missing or malformed (e.g. a user key with a
            # typo, or a damaged key file), which would hide the valid keys and look like a corrupt
            # archive. So only existing regular files that age-keygen can parse are used.
            self.identities, self.key_ids, invalid = [], set(), 0
            for item in identity_files or []:
                path = getattr(item, 'path', item)
                try:
                    if not stat.S_ISREG(os.lstat(path).st_mode):
                        continue
                except (OSError, TypeError, ValueError):
                    continue
                ids = _identity_file_key_ids(path)
                if not ids:
                    invalid += 1
                    continue
                self.identities.append(path)
                self.key_ids |= ids
            if not self.identities:
                if invalid:
                    raise BackupError('wrong-key', '提供的金鑰無效或已損毀，無法用來解密此備份。',
                                      key_id=self.header['key_id'])
                raise BackupError('key-required', '需要緊急金鑰或這台設備的加密金鑰才能讀取此備份。', key_id=self.header['key_id'])
            argv = []
            for path in self.identities:
                argv += ['-i', str(path)]
            age_bin, zstd_bin = _tools()
            os.lseek(fd, offset, os.SEEK_SET)
            self.age_err, self.zstd_err = tempfile.TemporaryFile(), tempfile.TemporaryFile()
            env = util.clean_env()
            self.age = subprocess.Popen([age_bin, '-d', *argv], stdin=fd, stdout=subprocess.PIPE,
                                        stderr=self.age_err, env=env, close_fds=True)
            self.procs.append(self.age)
            self.zstd = subprocess.Popen([zstd_bin, '-d', '-c', '-q'], stdin=self.age.stdout,
                                         stdout=subprocess.PIPE, stderr=self.zstd_err, env=env, close_fds=True)
            self.procs.append(self.zstd)
            self.age.stdout.close()
            self.out = self.zstd.stdout
            _grow_pipe(self.out)
        except BaseException:
            self.close()
            raise
        finally:
            os.close(fd)
        self._fd = self.out.fileno()

    def read(self, size):
        return os.read(self._fd, size)

    def read_exact(self, size):
        parts, need = [], size
        while need:
            buf = os.read(self._fd, min(need, CHUNK))
            if not buf:
                raise _Truncated()
            parts.append(buf)
            need -= len(buf)
        return b''.join(parts)

    def chunks(self, size):
        need = size
        while need:
            buf = os.read(self._fd, min(need, CHUNK))
            if not buf:
                raise _Truncated()
            need -= len(buf)
            yield buf

    def tool_error(self, wait):
        """BackupError explaining a failed age/zstd run, or None if both exited 0.

        With wait=False only already-exited processes are considered (the stream may still flow).
        """
        codes = []
        for proc in (self.age, self.zstd):
            if wait:
                try:
                    codes.append(proc.wait(timeout=TOOL_WAIT))
                except subprocess.TimeoutExpired:
                    proc.kill()
                    codes.append(proc.wait())
            else:
                codes.append(proc.poll())
        age_rc, zstd_rc = codes
        if age_rc not in (None, 0):
            text = _stderr_text(self.age_err)
            if 'no identity matched' in text:
                if self.header['key_id'] in self.key_ids:
                    # We hold the key named in the header, so the recipient block itself is damaged.
                    return _corrupt('key matches but the encrypted key block is damaged')
                return BackupError('wrong-key', '金鑰不正確：此備份不是用提供的金鑰加密的。',
                                   key_id=self.header['key_id'])
            if 'error: reading "' in text:
                # An identity file could not be loaded (vanished or damaged after the pre-check).
                return BackupError('wrong-key', '提供的金鑰無效或已損毀，無法用來解密此備份。',
                                   key_id=self.header['key_id'])
            return _corrupt('decryption failed', stage='decrypt')
        if zstd_rc not in (None, 0):
            return _corrupt('decompression failed', stage='decompress')
        return None

    def close(self):
        if self.out is not None:
            with contextlib.suppress(OSError):
                self.out.close()
        _reap(self.procs)
        for handle in (self.age_err, self.zstd_err):
            if handle is not None:
                handle.close()
        self.procs, self.out = [], None


# ---------------------------------------------------------------- strict tar parsing

def _cstr(field, what):
    head, _, rest = field.partition(b'\0')
    if rest.strip(b'\0'):
        raise _corrupt(f'tar {what} field has trailing data')
    try:
        return head.decode('ascii')
    except UnicodeDecodeError:
        raise _corrupt(f'tar {what} is not ASCII') from None


def _octal(field, what):
    if field[:1] and field[0] & 0x80:
        raise _corrupt(f'tar {what} uses base-256')
    text = field.rstrip(b'\0 ').lstrip(b' ')
    if not text or not all(48 <= c <= 55 for c in text):
        raise _corrupt(f'tar {what} is not octal')
    return int(text, 8)


def _parse_block(block):
    stored = _octal(block[148:156], 'checksum')
    if stored != sum(block[:148]) + 8 * 32 + sum(block[156:]):
        raise _corrupt('tar header checksum mismatch')
    if block[257:265] != USTAR_MAGIC:
        raise _corrupt('tar header is not POSIX ustar')
    typeflag = block[156:157]
    if typeflag not in (b'0', b'x'):
        raise _corrupt('member is not a regular file (link, device, directory or special)',
                       type=typeflag.decode('latin-1'))
    if _cstr(block[157:257], 'linkname') or _cstr(block[345:500], 'prefix'):
        raise _corrupt('tar link or prefix fields are not allowed')
    return _cstr(block[0:100], 'name'), _octal(block[124:136], 'size'), typeflag


def _parse_pax(data):
    records, pos = {}, 0
    while pos < len(data):
        space = data.find(b' ', pos, pos + 12)
        if space <= pos or not data[pos:space].isdigit():
            raise _corrupt('malformed pax record')
        length = int(data[pos:space])
        end = pos + length
        if length < 5 or end > len(data) or data[end - 1:end] != b'\n':
            raise _corrupt('malformed pax record')
        key, eq, value = data[space + 1:end - 1].partition(b'=')
        try:
            key, value = key.decode('ascii'), value.decode('utf-8')
        except UnicodeDecodeError:
            raise _corrupt('pax record is not text') from None
        if not eq or key not in ('path', 'size') or key in records or '\x00' in value:
            raise _corrupt('pax record not allowed', key=key[:40])
        if key == 'size':
            if not re.fullmatch(r'[0-9]{1,20}', value):
                raise _corrupt('pax size invalid')
            value = int(value)
        records[key] = value
        pos = end
    return records


def _skip_padding(dec, size):
    pad = (-size) % BLOCK
    if pad and dec.read_exact(pad).strip(b'\0'):
        raise _corrupt('tar padding is not zero')


def _next_member(dec):
    """(name, size) of the next regular-file member, or None at the end-of-archive marker."""
    pax = None
    while True:
        block = dec.read_exact(BLOCK)
        if block == ZERO_BLOCK:
            if pax is not None:
                raise _corrupt('pax header without a member')
            return None
        name, size, typeflag = _parse_block(block)
        if typeflag == b'x':
            if pax is not None:
                raise _corrupt('consecutive pax headers')
            if size > MAX_PAX:
                raise _corrupt('pax header too large')
            data = dec.read_exact(size)
            _skip_padding(dec, size)
            pax = _parse_pax(data)
            continue
        if typeflag != b'0':
            raise _corrupt('member is not a regular file (link, device, directory or special)',
                           type=typeflag.decode('latin-1'))
        if pax:
            name = pax.get('path', name)
            size = pax.get('size', size)
        if not name or any(ord(c) < 32 or ord(c) == 127 for c in name):
            raise _corrupt('member name invalid')
        return name, size


def _finish_tar(dec):
    """After the first zero block: the second one, then only zero padding until EOF."""
    if dec.read_exact(BLOCK) != ZERO_BLOCK:
        raise _corrupt('data after the end-of-archive marker')
    trailing = 0
    while True:
        buf = dec.read(CHUNK)
        if not buf:
            return
        trailing += len(buf)
        if buf.strip(b'\0') or trailing > MAX_TRAILER:
            raise _corrupt('data after the end-of-archive marker')


# ---------------------------------------------------------------- extraction target

class _Extractor:
    """Writes members below an empty, private directory using dir fds and O_NOFOLLOW|O_EXCL."""

    def __init__(self, dest_dir):
        self.root = Path(dest_dir)
        self.dirs = {}
        try:
            st = os.lstat(self.root)
        except FileNotFoundError:
            raise BackupError('internal-error', '還原暫存目錄不存在。') from None
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077):
            raise BackupError('internal-error', '還原暫存目錄不安全（必須是僅限管理員存取的目錄）。')
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.dirs[''] = fd
        st2 = os.fstat(fd)
        if (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino):
            self.close()
            raise BackupError('internal-error', '還原暫存目錄在檢查時被更換。')
        if os.listdir(fd):
            self.close()
            raise BackupError('internal-error', '還原暫存目錄不是空的。')

    def _dir(self, rel):
        if rel in self.dirs:
            return self.dirs[rel]
        parent, _, name = rel.rpartition('/')
        parent_fd = self._dir(parent)
        with contextlib.suppress(FileExistsError):
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        os.fchmod(fd, 0o700)
        self.dirs[rel] = fd
        return fd

    def create(self, path):
        parent, _, name = path.rpartition('/')
        parent_fd = self._dir(parent)
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                         dir_fd=parent_fd)
        except FileExistsError:
            raise _corrupt('member written twice', path=path) from None
        os.fchmod(fd, 0o600)
        return fd

    def remove_all(self):
        root = self.dirs.get('')
        if root is None:
            return
        for name in os.listdir(root):
            with contextlib.suppress(OSError):
                st = os.lstat(name, dir_fd=root)
                if stat.S_ISDIR(st.st_mode):
                    shutil.rmtree(name, dir_fd=root)
                else:
                    os.unlink(name, dir_fd=root)

    def close(self):
        for fd in self.dirs.values():
            with contextlib.suppress(OSError):
                os.close(fd)
        self.dirs = {}


def _write_all(fd, buf):
    view = memoryview(buf)
    while view:
        view = view[os.write(fd, view):]


# ---------------------------------------------------------------- the read pass

def _free_bytes(limits, path):
    if limits.free_bytes is not None:
        return int(limits.free_bytes(path))
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def _read_stream(dec, mode, limits, progress, extractor):
    member = _next_member(dec)
    if member is None:
        raise _corrupt('archive is empty')
    name, size = member
    if name != 'manifest.json':
        raise _corrupt('manifest.json is not the first member', member=name[:200])
    if size > limits.max_manifest:
        raise _limit('manifest too large', size=size)
    data = dec.read_exact(size)
    _skip_padding(dec, size)
    try:
        manifest = util.loads_strict(data, max_bytes=limits.max_manifest)
    except ValueError as exc:
        raise _invalid(f'manifest is not strict JSON: {str(exc)[:120]}') from None
    if isinstance(manifest, dict) and isinstance(manifest.get('entries'), list):
        if len(manifest['entries']) + 1 > limits.max_members:
            raise _limit('too many members', members=len(manifest['entries']) + 1)
    validate_manifest(manifest)
    for key in ('backup_id', 'created', 'key_id'):
        if manifest[key] != dec.header[key]:
            raise _corrupt('outer header does not match the manifest', field=key)
    entries = manifest['entries']
    total = sum(e['size'] for e in entries)
    if total > limits.max_total_bytes:
        raise _limit('declared total size too large', total=total)
    if mode == 'manifest':
        return manifest, total
    if extractor is not None:
        free = _free_bytes(limits, extractor.root)
        if total > free - limits.reserve_bytes:
            raise BackupError('insufficient-space', '磁碟空間不足，無法解開此備份。',
                              required=total + limits.reserve_bytes, free=free)
    meter = _Progress(progress, total)
    for entry in entries:
        member = _next_member(dec)
        if member is None:
            raise _corrupt('member missing', path=entry['path'])
        name, size = member
        if name != entry['path']:
            raise _corrupt('unexpected member (wrong name, order or duplicate)', member=name[:200],
                           expected=entry['path'])
        if size != entry['size']:
            raise _corrupt('member size differs from the manifest', path=entry['path'])
        digest = hashlib.sha256()
        out = extractor.create(entry['path']) if extractor is not None else -1
        try:
            for chunk in dec.chunks(size):
                digest.update(chunk)
                if out >= 0:
                    _write_all(out, chunk)
                meter.add(len(chunk))
        finally:
            if out >= 0:
                os.close(out)
        _skip_padding(dec, size)
        if digest.hexdigest() != entry['sha256']:
            raise _corrupt('member checksum mismatch', path=entry['path'])
    if _next_member(dec) is not None:
        raise _corrupt('extra member after the manifest entries')
    _finish_tar(dec)
    meter.finish()
    return manifest, total


def _run(path, identity_files, mode, *, limits=None, progress=None, dest_dir=None):
    limits = limits or Limits()
    extractor = _Extractor(dest_dir) if mode == 'extract' else None
    ok = False
    try:
        dec = _Decryptor(path, identity_files)
        try:
            try:
                manifest, total = _read_stream(dec, mode, limits, progress, extractor)
            except _Truncated:
                raise dec.tool_error(wait=True) or _corrupt('archive content is truncated') from None
            except BackupError as exc:
                # Prefer the tools' diagnosis when they already failed (e.g. wrong key, bad MAC).
                tool = dec.tool_error(wait=False)
                raise (tool or exc) from None
            if mode != 'manifest':
                error = dec.tool_error(wait=True)
                if error is not None:
                    raise error
            ok = True
            return manifest, total
        finally:
            dec.close()
    except OSError as exc:
        raise _map_os_error(exc, '讀取備份檔') from exc
    finally:
        if extractor is not None:
            if not ok:
                extractor.remove_all()
            extractor.close()


def read_manifest(path, identity_files, *, limits=None):
    """Decrypt only as far as needed to return the validated manifest dict (no extraction).

    Stops after the manifest member, then kills and reaps age/zstd. This authenticates only the
    age chunks read so far; use verify_archive() before trusting the rest of the archive.
    """
    return _run(path, identity_files, 'manifest', limits=limits)[0]


def verify_archive(path, identity_files, *, progress=None, limits=None):
    """Full streaming pass. Returns {'manifest', 'entries', 'bytes'}; raises BackupError on any defect."""
    manifest, total = _run(path, identity_files, 'verify', limits=limits, progress=progress)
    return {'manifest': manifest, 'entries': len(manifest['entries']), 'bytes': total}


def extract_archive(path, identity_files, dest_dir, *, progress=None, limits=None):
    """Safely extract into empty root-only `dest_dir`; returns the manifest. Partial output is the caller's to delete."""
    return _run(path, identity_files, 'extract', limits=limits, progress=progress, dest_dir=dest_dir)[0]
