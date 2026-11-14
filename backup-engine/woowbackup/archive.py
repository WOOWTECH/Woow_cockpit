"""Backup file formats (CONTRACT section 5). Owner: E1 engine-core (format).

**v2** (`<id>.tar`, every new backup since 2026-11-13): a plain, uncompressed POSIX tar that any archive tool opens,
laid out like a Home Assistant backup:

    backup.json             readable metadata without secrets. NOT authenticated: shown before a key is entered and
                            otherwise only compared with the per-app manifests (any difference is corrupt-archive)
    README.txt              what the file is, how to restore it in Cockpit, how to unpack it by hand (zh-TW, English)
    apps/<id>.tar.zst.age   one per app: age X25519 ciphertext of zstd(tar)  (encryption "age-x25519"), or
    apps/<id>.tar.gz        gzip(tar)                                        (encryption "none")

Each inner tar holds `manifest.json` first -- the authenticated per-app manifest (backup id, created, key id, type,
note, tool, source, consistency, the ids of every app of the backup, the app's section and its entries with size and
sha256) -- then exactly those entries in that order, named `apps/<id>/<category>/<name>` like v1, so an extraction has
the v1 layout. An app is restored, verified or exported without reading any other app's inner archive.

**v1** (`<id>.woowbackup`, read forever, written only by compatibility tests): `WOOWTECH-BACKUP/1` + a JSON header line +
age(X25519) ciphertext of zstd(PAX tar) with `manifest.json` first.

Everything read is hostile until proven otherwise. The outer tar and every inner tar go through one strict parser
written for exactly what Python's tarfile emits (ustar blocks, PAX `path`/`size` records only, regular files only, no
links, devices, directories, GNU or global headers, extra, missing or duplicate members, trailing data). age and zstd
(or zlib for gzip) must finish cleanly before anything counts as valid; subprocess stderr goes to temp files, and every
exit path kills and reaps the children and joins the threads.

Writing v2: the outer file is written in place in a temp file -- backup.json's bytes are reserved up front (its size is
fixed by the largest values its fields can take, the rest is padded with spaces), each inner archive streams through
`zstd | age` (or a parallel deflate, pigz style) straight into the outer file behind a reserved header slot that is
filled once its size is known -- then fsync, a full read for the file's sha256, and an atomic rename.
"""
import collections
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
import struct
import subprocess
import tarfile
import tempfile
import threading
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from . import util
from .errors import BackupError
from .keys import KEY_ID_RE, RECIPIENT_RE, key_id_for

MAGIC = b'WOOWTECH-BACKUP/1\n'
FORMAT = 1            # the v1 format number (`.woowbackup`)
FORMAT_V2 = 2         # the native format (`.tar`)
FORMATS = (FORMAT, FORMAT_V2)
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
PLAIN = 'none'
COMPRESSION = 'zstd'
GZIP = 'gzip'
ENCRYPTIONS = (ENCRYPTION, PLAIN)
COMPRESSION_OF = {ENCRYPTION: COMPRESSION, PLAIN: GZIP}
INNER_SUFFIX = {ENCRYPTION: '.tar.zst.age', PLAIN: '.tar.gz'}
BACKUP_JSON = 'backup.json'
README = 'README.txt'
INNER_MANIFEST = 'manifest.json'
MAX_BACKUP_JSON = 1024 * 1024
MAX_README = 64 * 1024
MAX_APPS = 100
TYPES = ('manual', 'safety')

BLOCK = 512
ZERO_BLOCK = bytes(BLOCK)
RECORD = 20 * BLOCK   # outer tar padded to a whole record like tar(1) and tarfile write it
USTAR_MAGIC = b'ustar\x0000'
USTAR_SIZE_MAX = 8 ** 11 - 1  # larger members need a PAX `size` record
PAX_SLOT = 3 * BLOCK          # PAX header + its records + the ustar header
MAX_PAX = 16 * 1024
MAX_TRAILER = 1024 * 1024
CHUNK = 1024 * 1024
HEAD_BYTES = 64               # first bytes of each entry handed to a deep check
PROGRESS_STEP = 8 * 1024 * 1024
TOOL_WAIT = 60
GZIP_LEVEL = 1                # deflate level of plain inner archives (speed: they are written while apps wait)
GZIP_BLOCK = 1024 * 1024
GZIP_WINDOW = 32 * 1024
GZIP_HEADER = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03'  # deflate, no flags, no mtime, Unix

BACKUP_ID_RE = re.compile(r'^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
SHA256_RE = re.compile(r'^[0-9a-f]{64}\Z')
ENTRY_RE = re.compile(r'^apps/[a-z0-9][a-z0-9-]{1,40}/(images|postgres|volumes|dirs|secrets|config|quadlet|verify)/'
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
DIGEST_ID_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{0,31}\Z')
CONFIG_SEGMENT_RE = re.compile(r'^[^\x00-\x1f\x7f/\\]{1,255}\Z')
DIR_SEGMENT_RE = re.compile(r'^[A-Za-z0-9._@+-]{1,255}\Z')
ENCODING_RE = re.compile(r'^[A-Za-z0-9_]{1,32}\Z')
LOCALE_RE = re.compile(r'^[A-Za-z0-9_.@-]{0,100}\Z')
MAX_DATA_DIRS = 16
MAX_DIGESTS = 16
DIGEST_TYPES = ('files-digest', 'postgres-digest')
DIGEST_SUMMARY = {'files-digest': ('entries', 'files', 'dirs', 'symlinks', 'other', 'bytes'),
                  'postgres-digest': ('databases', 'tables', 'sequences', 'rows', 'roles')}
SECTIONS = {  # manifest app section -> entry category directory
    'images': 'images', 'postgres': 'postgres', 'volumes': 'volumes', 'data_dirs': 'dirs',
    'secrets': 'secrets', 'config_files': 'config', 'quadlet_files': 'quadlet', 'verify_digests': 'verify',
}
MAX_SIZE = 2 ** 53
HEAD_FIELDS = ('backup_id', 'created', 'type', 'note', 'key_id', 'encryption', 'tool', 'source', 'consistency')


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


def inner_name(app_id, encryption):
    """Outer member name of an app's inner archive (`apps/<id>.tar.zst.age` or `apps/<id>.tar.gz`)."""
    return f'apps/{app_id}{INNER_SUFFIX[encryption]}'


# ====================================================================== errors

def _corrupt(reason, **details):
    return BackupError('corrupt-archive', '備份檔已損毀或遭到修改，無法使用。', reason=reason, **details)


def _invalid(reason, **details):
    return BackupError('invalid-manifest', '備份內容清單（manifest）格式不正確。', reason=reason, **details)


def _limit(reason, **details):
    return BackupError('limit-exceeded', '備份檔超出安全限制（檔案數量或大小），已拒絕處理。', reason=reason, **details)


def _not_a_backup():
    return BackupError('not-a-backup', '這不是 woowtech 備份檔（.tar 或 .woowbackup）。')


def _unsupported(version):
    return BackupError('unsupported-format', '不支援此備份檔版本，請更新這台設備的備份元件。', version=version)


class _Truncated(Exception):
    """The decrypted/decompressed stream (or the file) ended early; the tool exit status decides the error."""


# ====================================================================== v1 outer header

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
        raise _unsupported(fmt)
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
                raise _unsupported(int(match.group(1)))
            raise _not_a_backup()
        if eof and len(buf) >= 8 and (MAGIC.startswith(buf) or buf.startswith(FAMILY)):
            raise _corrupt('truncated in format line')
        raise _not_a_backup()
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
    """v1 only: (header, age offset) of an open `.woowbackup`."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise _not_a_backup()
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
            raise _not_a_backup() from None
        raise
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
    return fd


def header_bytes(header):
    return MAGIC + json.dumps({k: header[k] for k in HEADER_KEYS}, separators=(',', ':')).encode('ascii') + b'\n'


# ====================================================================== format detection

def _looks_like_tar(block):
    if len(block) < BLOCK or block[257:265] != USTAR_MAGIC:
        return False
    try:
        stored = int(block[148:156].rstrip(b'\0 ').lstrip(b' ') or b'x', 8)
    except ValueError:
        return False
    return stored == sum(block[:148]) + 8 * 32 + sum(block[156:BLOCK])


def _format_of_fd(fd):
    """1 or 2 by the first bytes; raises not-a-backup / unsupported-format / corrupt-archive like the readers."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise _not_a_backup()
    head = os.pread(fd, BLOCK, 0)
    if head[:len(FAMILY)] == FAMILY[:len(head)] and head:
        return FORMAT  # also a short or damaged v1 prefix: the v1 parser names the defect
    if _looks_like_tar(head):
        if head[:len(BACKUP_JSON) + 1] != BACKUP_JSON.encode() + b'\0':
            raise _not_a_backup()
        return FORMAT_V2
    if head.startswith(BACKUP_JSON.encode() + b'\0') and len(head) < BLOCK:
        raise _corrupt('truncated in the first header')
    return FORMAT  # not a tar: the v1 parser reports not-a-backup


def format_of(path):
    """1 (`.woowbackup`) or 2 (`.tar`) of an archive file."""
    fd = _open_archive(path)
    try:
        return _format_of_fd(fd)
    finally:
        os.close(fd)


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


def _printable(value, where, min_len=1, max_len=63):
    _str(value, where, min_len=min_len, max_len=max_len)
    _need(value.isprintable(), f'{where} has control characters')


def _int(value, where, lo, hi):
    _need(isinstance(value, int) and not isinstance(value, bool) and lo <= value <= hi, f'{where} out of range')


def _bool(value, where):
    _need(isinstance(value, bool), f'{where} must be true or false')


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


def _dir_path(value, where):
    """A host directory relative to the owner's home. Only compared with the local catalog's paths, which alone
    decide what is written (CONTRACT section 4), but held to the catalog's segment rules all the same."""
    _str(value, where, min_len=1, max_len=1024)
    _need(not value.startswith('/') and not value.endswith('/'), f'{where} must be a relative directory path')
    _need(all(s not in ('.', '..') and DIR_SEGMENT_RE.match(s) for s in value.split('/')),
          f'{where} has invalid segments')


def _validate_head(manifest, fmt):
    """The fields every manifest shares (v1 manifest, v2 per-app manifest)."""
    _int(manifest['format'], 'format', fmt, fmt)
    _need(_valid_backup_id(manifest['backup_id']), 'backup_id has an invalid format')
    _need(util.is_iso_utc(manifest['created']), 'created has an invalid format')
    _need(manifest['type'] in TYPES, 'type must be manual or safety')
    _str(manifest['note'], 'note', max_len=1000)
    encryption = manifest.get('encryption', ENCRYPTION)
    _need(encryption in ENCRYPTIONS, 'encryption must be age-x25519 or none')
    if encryption == ENCRYPTION:
        _str(manifest['key_id'], 'key_id', KEY_ID_RE)
    else:
        _need(manifest['key_id'] is None, 'key_id must be null without encryption')

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


def _validate_entries(entries, max_items=MAX_MEMBERS - 1):
    _list(entries, 'entries', max_items)
    by_path = {}
    for index, entry in enumerate(entries):
        where = f'entries[{index}]'
        _obj(entry, where, ('path', 'size', 'sha256'))
        _str(entry['path'], f'{where}.path', ENTRY_RE, max_len=300)
        _int(entry['size'], f'{where}.size', 0, MAX_SIZE)
        _str(entry['sha256'], f'{where}.sha256', SHA256_RE, max_len=64)
        _need(entry['path'] not in by_path, 'duplicate entry path', path=entry['path'])
        by_path[entry['path']] = entry
    return by_path


def _postgres_instance(item, w, app_id, ref):
    """An instance-mode `postgres[]` item (CONTRACT section 5, [format])."""
    # `bootstrap_user` (2026-11-14, review F5): the instance's bootstrap superuser at backup time; optional (archives
    # written before it have none).
    _obj(item, w, ('id', 'scope', 'database', 'server_version', 'major', 'entry', 'databases', 'roles'),
         ('bootstrap_user',))
    if 'bootstrap_user' in item:
        _printable(item['bootstrap_user'], f'{w}.bootstrap_user', max_len=63)
    _str(item['database'], f'{w}.database', PG_DB_RE, max_len=63)
    _str(item['server_version'], f'{w}.server_version', min_len=1, max_len=100)
    _int(item['major'], f'{w}.major', 1, 999)
    ref(app_id, 'postgres', item['entry'], f'{w}.entry')
    _list(item['databases'], f'{w}.databases', 64, min_items=1)
    names = set()
    for i, db in enumerate(item['databases']):
        d = f'{w}.databases[{i}]'
        # `template` (2026-11-14, review F1): a template database, restored as a template again; optional.
        _obj(db, d, ('name', 'owner', 'encoding', 'collate', 'ctype', 'locale_provider', 'icu_locale', 'extensions',
                     'entry'), ('template',))
        if 'template' in db:
            _bool(db['template'], f'{d}.template')
        _str(db['name'], f'{d}.name', PG_DB_RE, max_len=63)
        _need(db['name'] not in ('template0', 'template1'), f'{d}.name invalid')
        _need(db['name'] not in names, f'{d}.name duplicate')
        names.add(db['name'])
        _printable(db['owner'], f'{d}.owner')
        _str(db['encoding'], f'{d}.encoding', ENCODING_RE, max_len=32)
        _str(db['collate'], f'{d}.collate', LOCALE_RE, max_len=100)
        _str(db['ctype'], f'{d}.ctype', LOCALE_RE, max_len=100)
        _need(db['locale_provider'] in ('libc', 'icu', 'builtin'), f'{d}.locale_provider invalid')
        if db['icu_locale'] is not None:
            _str(db['icu_locale'], f'{d}.icu_locale', LOCALE_RE, max_len=100)
        _list(db['extensions'], f'{d}.extensions', 100)
        for j, ext in enumerate(db['extensions']):
            e = f'{d}.extensions[{j}]'
            _obj(ext, e, ('name', 'version'))
            _printable(ext['name'], f'{e}.name')
            _printable(ext['version'], f'{e}.version')
        ref(app_id, 'postgres', db['entry'], f'{d}.entry')
    _list(item['roles'], f'{w}.roles', 1000)
    for i, role in enumerate(item['roles']):
        r = f'{w}.roles[{i}]'
        _obj(role, r, ('name', 'superuser', 'login'))
        _printable(role['name'], f'{r}.name')
        _bool(role['superuser'], f'{r}.superuser')
        _bool(role['login'], f'{r}.login')


def _verify_digests(items, where, app_id, ref, by_path):
    """`verify_digests` of an app (CONTRACT section 5, [format])."""
    _list(items, where, MAX_DIGESTS)
    ids = set()
    for i, item in enumerate(items):
        w = f'{where}[{i}]'
        _need(isinstance(item, dict), f'{w} must be an object')
        kind = item.get('type')
        _need(kind in DIGEST_TYPES, f'{w}.type invalid')
        extra = ('databases', 'roles') if kind == 'postgres-digest' else ()
        # `server_major` (2026-11-14, review L4/F7): the PostgreSQL major the digest was read on; optional.
        _obj(item, w, ('id', 'type', 'target', 'exclude', 'summary', 'digest', 'entry', *extra),
             ('server_major',) if kind == 'postgres-digest' else ())
        if 'server_major' in item:
            _int(item['server_major'], f'{w}.server_major', 1, 999)
        _str(item['id'], f'{w}.id', DIGEST_ID_RE, max_len=32)
        _need(item['id'] not in ids, f'{w}.id duplicate')
        ids.add(item['id'])
        _printable(item['target'], f'{w}.target', max_len=1100)
        _list(item['exclude'], f'{w}.exclude', 64)
        for j, glob in enumerate(item['exclude']):
            _printable(glob, f'{w}.exclude[{j}]', max_len=200)
        summary = item['summary']
        _obj(summary, f'{w}.summary', DIGEST_SUMMARY[kind])
        for key in DIGEST_SUMMARY[kind]:
            _int(summary[key], f'{w}.summary.{key}', 0, MAX_SIZE)
        _str(item['digest'], f'{w}.digest', SHA256_RE, max_len=64)
        ref(app_id, 'verify_digests', item['entry'], f'{w}.entry')
        _need(by_path[item['entry']]['sha256'] == item['digest'], f'{w}.digest differs from its entry')
        if kind == 'postgres-digest':
            _list(item['databases'], f'{w}.databases', 64, min_items=1)
            for j, name in enumerate(item['databases']):
                _str(name, f'{w}.databases[{j}]', PG_DB_RE, max_len=63)
            _bool(item['roles'], f'{w}.roles')


def _validate_app(app, where, ref, by_path):
    """One app section (v1 manifest `apps[]`, v2 per-app manifest `app`). `ref(app_id, section, entry, where)` checks
    an entry reference."""
    # `data_dirs` (host directories) and `verify_digests` are optional: archives written before them have none.
    _obj(app, where, ('id', 'name', 'adapter', 'adapter_version', 'catalog_sha256', 'owner', 'images',
                      'postgres', 'volumes', 'secrets', 'config_files', 'quadlet_files', 'verify_snapshot'),
         ('data_dirs', 'verify_digests'))
    _str(app['id'], f'{where}.id', APP_ID_RE, max_len=41)
    app_id = app['id']
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
        _need(isinstance(item, dict), f'{w} must be an object')
        _str(item.get('id'), f'{w}.id', PG_ID_RE, max_len=64)
        _need(item['id'] not in seen, f'{w}.id duplicate')
        seen.add(item['id'])
        if item.get('scope') == 'instance':
            _postgres_instance(item, w, app_id, ref)
            continue
        _obj(item, w, ('id', 'database', 'server_version', 'major', 'entry'), ('scope',))
        _need(item.get('scope', 'database') == 'database', f'{w}.scope invalid')
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

    if 'data_dirs' in app:
        _list(app['data_dirs'], f'{where}.data_dirs', MAX_DATA_DIRS)
        seen = []
        for i, item in enumerate(app['data_dirs']):
            w = f'{where}.data_dirs[{i}]'
            _obj(item, w, ('path', 'entry'))
            _dir_path(item['path'], f'{w}.path')
            _need(all(item['path'] != other and not item['path'].startswith(other + '/')
                      and not other.startswith(item['path'] + '/') for other in seen), f'{w}.path overlaps')
            seen.append(item['path'])
            ref(app_id, 'data_dirs', item['entry'], f'{w}.entry')

    if 'verify_digests' in app:
        _verify_digests(app['verify_digests'], f'{where}.verify_digests', app_id, ref, by_path)

    snapshot = app['verify_snapshot']
    _need(isinstance(snapshot, dict) and len(snapshot) <= 20, f'{where}.verify_snapshot must be an object')
    for key, value in snapshot.items():
        _str(key, f'{where}.verify_snapshot key', VERIFY_ID_RE, max_len=64)
        _need(isinstance(value, dict), f'{where}.verify_snapshot.{key} must be an object')
        _json_value(value, f'{where}.verify_snapshot.{key}')


def _referencer(by_path):
    referenced = set()

    def ref(app_id, section, value, where):
        _str(value, where, ENTRY_RE, max_len=300)
        _need(value.startswith(f'apps/{app_id}/{SECTIONS[section]}/'), f'{where} outside its app section',
              path=value)
        _need(value in by_path, f'{where} not listed in entries', path=value)
        _need(value not in referenced, f'{where} referenced twice', path=value)
        referenced.add(value)

    return ref, referenced


def validate_manifest(manifest):
    """Strict schema validation of a v1 manifest; returns it or raises BackupError('invalid-manifest')."""
    _obj(manifest, 'manifest', ('format', 'backup_id', 'created', 'type', 'note', 'key_id', 'tool',
                                'source', 'consistency', 'apps', 'entries'))
    _validate_head(manifest, FORMAT)
    by_path = _validate_entries(manifest['entries'])
    ref, referenced = _referencer(by_path)
    apps = manifest['apps']
    _list(apps, 'apps', MAX_APPS, min_items=1)
    app_ids = set()
    for index, app in enumerate(apps):
        _need(isinstance(app, dict) and app.get('id') not in app_ids, 'duplicate app id',
              app=str(app.get('id') if isinstance(app, dict) else '')[:64])
        _validate_app(app, f'apps[{index}]', ref, by_path)
        app_ids.add(app['id'])
    orphans = sorted(set(by_path) - referenced)
    _need(not orphans, 'entries not referenced by any app', paths=orphans[:10])
    return manifest


INNER_KEYS = ('format', 'backup_id', 'created', 'type', 'note', 'key_id', 'encryption', 'tool', 'source',
              'consistency', 'backup_apps', 'app', 'entries')


def validate_app_manifest(manifest):
    """Strict schema validation of a v2 per-app manifest (the authenticated `manifest.json` of an inner archive)."""
    _obj(manifest, 'manifest', INNER_KEYS)
    _validate_head(manifest, FORMAT_V2)
    apps = manifest['backup_apps']
    _list(apps, 'backup_apps', MAX_APPS, min_items=1)
    for index, app_id in enumerate(apps):
        _str(app_id, f'backup_apps[{index}]', APP_ID_RE, max_len=41)
    _need(len(set(apps)) == len(apps), 'backup_apps has duplicates')
    app = manifest['app']
    _need(isinstance(app, dict) and app.get('id') in apps, 'app is not one of backup_apps')
    by_path = _validate_entries(manifest['entries'])
    _need(all(path.startswith(f'apps/{app["id"]}/') for path in by_path), 'entries outside the app')
    ref, referenced = _referencer(by_path)
    _validate_app(app, 'app', ref, by_path)
    orphans = sorted(set(by_path) - referenced)
    _need(not orphans, 'entries not referenced by the app', paths=orphans[:10])
    return manifest


# ---------------------------------------------------------------- backup.json (untrusted display metadata)

DOC_KEYS = ('format', 'backup_id', 'created', 'type', 'note', 'tool', 'source', 'encryption', 'compression', 'key_id',
            'apps')
DOC_SOURCE_KEYS = ('hostname', 'arch', 'os', 'podman')
DOC_APP_KEYS = ('id', 'name', 'adapter', 'owner', 'images', 'databases', 'volumes', 'data_dirs', 'secrets',
                'config_files', 'file', 'size', 'sha256')


def _doc_need(cond, reason, **details):
    if not cond:
        raise _corrupt(f'backup.json: {reason}', **details)


def _doc_str(value, where, pattern=None, min_len=0, max_len=200):
    _doc_need(isinstance(value, str) and min_len <= len(value) <= max_len and '\x00' not in value
              and _utf8(value), f'{where} must be a string')
    if pattern is not None:
        _doc_need(pattern.match(value) is not None, f'{where} has an invalid format')


def _doc_list(value, where, max_items, check):
    _doc_need(isinstance(value, list) and len(value) <= max_items, f'{where} must be a list')
    for index, item in enumerate(value):
        check(item, f'{where}[{index}]')


def validate_doc(doc):
    """Strict schema of `backup.json` (format 2). Returns the doc; raises unsupported-format or corrupt-archive."""
    _doc_need(isinstance(doc, dict), 'not an object')
    fmt = doc.get('format')
    _doc_need(isinstance(fmt, int) and not isinstance(fmt, bool), 'format missing')
    if fmt != FORMAT_V2:
        raise _unsupported(fmt)
    _doc_need(set(doc) == set(DOC_KEYS), 'keys mismatch', keys=sorted(str(k)[:40] for k in set(doc) ^ set(DOC_KEYS))[:10])
    _doc_need(_valid_backup_id(doc['backup_id']), 'backup_id invalid')
    _doc_need(util.is_iso_utc(doc['created']), 'created invalid')
    _doc_need(doc['type'] in TYPES, 'type invalid')
    _doc_str(doc['note'], 'note', max_len=1000)
    tool = doc['tool']
    _doc_need(isinstance(tool, dict) and set(tool) == {'name', 'version'}, 'tool invalid')
    _doc_str(tool['name'], 'tool.name', min_len=1, max_len=100)
    _doc_str(tool['version'], 'tool.version', min_len=1, max_len=100)
    source = doc['source']
    _doc_need(isinstance(source, dict) and set(source) == set(DOC_SOURCE_KEYS), 'source invalid')
    _doc_str(source['hostname'], 'source.hostname', min_len=1, max_len=255)
    _doc_str(source['arch'], 'source.arch', ARCH_RE, max_len=32)
    _doc_str(source['os'], 'source.os', max_len=200)
    _doc_str(source['podman'], 'source.podman', max_len=64)
    if doc['encryption'] not in ENCRYPTIONS:
        if isinstance(doc['encryption'], str):
            raise BackupError('unsupported-format', '不支援此備份檔的加密或壓縮方式。')
        _doc_need(False, 'encryption invalid')
    if doc['compression'] != COMPRESSION_OF[doc['encryption']]:
        if isinstance(doc['compression'], str):
            raise BackupError('unsupported-format', '不支援此備份檔的加密或壓縮方式。')
        _doc_need(False, 'compression invalid')
    if doc['encryption'] == ENCRYPTION:
        _doc_str(doc['key_id'], 'key_id', KEY_ID_RE)
    else:
        _doc_need(doc['key_id'] is None, 'key_id must be null without encryption')
    apps = doc['apps']
    _doc_need(isinstance(apps, list) and 1 <= len(apps) <= MAX_APPS, 'apps must be a list of 1 to 100')
    seen = set()
    for index, app in enumerate(apps):
        w = f'apps[{index}]'
        _doc_need(isinstance(app, dict) and set(app) == set(DOC_APP_KEYS), f'{w} keys mismatch')
        _doc_str(app['id'], f'{w}.id', APP_ID_RE, max_len=41)
        _doc_need(app['id'] not in seen, f'{w}.id duplicate')
        seen.add(app['id'])
        _doc_str(app['name'], f'{w}.name', min_len=1, max_len=200)
        _doc_str(app['adapter'], f'{w}.adapter', ADAPTER_RE, max_len=41)
        _doc_str(app['owner'], f'{w}.owner', OWNER_RE, max_len=32)

        def image(item, where):
            _doc_need(isinstance(item, dict) and set(item) == {'ref', 'included'}, f'{where} invalid')
            _doc_str(item['ref'], f'{where}.ref', IMAGE_REF_RE, max_len=512)
            _doc_need(isinstance(item['included'], bool), f'{where}.included invalid')

        _doc_list(app['images'], f'{w}.images', 50, image)
        _doc_list(app['databases'], f'{w}.databases', 20 * 64,
                  lambda item, where: _doc_str(item, where, PG_DB_RE, max_len=63))
        _doc_list(app['volumes'], f'{w}.volumes', 50, lambda item, where: _doc_str(item, where, VOLUME_RE, 1, 128))
        _doc_list(app['secrets'], f'{w}.secrets', 100,
                  lambda item, where: _doc_str(item, where, SECRET_NAME_RE, 1, 201))

        def under(check):
            def run(item, where):
                try:
                    check(item, where)
                except BackupError:
                    raise _corrupt(f'backup.json: {where} invalid') from None
            return run

        _doc_list(app['data_dirs'], f'{w}.data_dirs', MAX_DATA_DIRS, under(_dir_path))
        _doc_list(app['config_files'], f'{w}.config_files', 100, under(_config_path))
        _doc_need(app['file'] == inner_name(app['id'], doc['encryption']), f'{w}.file invalid')
        _doc_need(isinstance(app['size'], int) and not isinstance(app['size'], bool)
                  and 0 < app['size'] <= MAX_SIZE, f'{w}.size invalid')
        _doc_str(app['sha256'], f'{w}.sha256', SHA256_RE, max_len=64)
    return doc


def display_app(app):
    """backup.json's view of an app section: names only (CONTRACT section 5), without file, size and sha256."""
    databases = []
    for item in app.get('postgres') or []:
        if item.get('scope') == 'instance':
            databases.extend(db['name'] for db in item.get('databases') or [])
        else:
            databases.append(item['database'])
    return {'id': app['id'], 'name': app['name'], 'adapter': app['adapter'], 'owner': app['owner']['name'],
            'images': [{'ref': img['ref'], 'included': 'entry' in img} for img in app.get('images') or []],
            'databases': databases, 'volumes': [v['name'] for v in app.get('volumes') or []],
            'data_dirs': [d['path'] for d in app.get('data_dirs') or []],
            'secrets': [s['name'] for s in app.get('secrets') or []],
            'config_files': [c['path'] for c in app.get('config_files') or []]}


def _head_view(head):
    """backup.json's top-level fields derived from a manifest head (machine id and consistency are not shown)."""
    return {'format': FORMAT_V2, 'backup_id': head['backup_id'], 'created': head['created'], 'type': head['type'],
            'note': head['note'], 'tool': dict(head['tool']),
            'source': {key: head['source'][key] for key in DOC_SOURCE_KEYS}, 'encryption': head['encryption'],
            'compression': COMPRESSION_OF[head['encryption']], 'key_id': head['key_id']}


def _check_against_doc(doc, doc_app, inner):
    """An authenticated per-app manifest must say what the untrusted backup.json says (mismatch = corrupt)."""
    view = _head_view(inner)
    for key, value in view.items():
        if doc.get(key) != value:
            raise _corrupt('backup.json differs from the authenticated manifest', field=key)
    if inner['backup_apps'] != [app['id'] for app in doc['apps']]:
        raise _corrupt('backup.json differs from the authenticated manifest', field='apps')
    if inner['app']['id'] != doc_app['id']:
        raise _corrupt('an inner archive holds another app', member=doc_app['file'])
    shown = display_app(inner['app'])
    for key, value in shown.items():
        if doc_app.get(key) != value:
            raise _corrupt('backup.json differs from the authenticated manifest', field=f'apps.{key}',
                           app=doc_app['id'])


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


def _usable_identities(identity_files, key_id):
    """(identity paths, their key ids) of the identity files age can load.

    age aborts completely if ANY identity file is missing or malformed (e.g. a user key with a typo, or a damaged key
    file), which would hide the valid keys and look like a corrupt archive. So only existing regular files that
    age-keygen can parse are used; none at all is key-required (or wrong-key when only unusable ones were given)."""
    identities, key_ids, invalid = [], set(), 0
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
        identities.append(path)
        key_ids |= ids
    if not identities:
        if invalid:
            raise BackupError('wrong-key', '提供的金鑰無效或已損毀，無法用來解密此備份。', key_id=key_id)
        raise BackupError('key-required', '需要緊急金鑰或這台設備的加密金鑰才能讀取此備份。', key_id=key_id)
    return identities, key_ids


def _age_error(text, key_id, key_ids):
    if 'no identity matched' in text:
        if key_id in key_ids:
            # We hold the key named in the header, so the recipient block itself is damaged.
            return _corrupt('key matches but the encrypted key block is damaged')
        return BackupError('wrong-key', '金鑰不正確：此備份不是用提供的金鑰加密的。', key_id=key_id)
    if 'error: reading "' in text:
        # An identity file could not be loaded (vanished or damaged after the pre-check).
        return BackupError('wrong-key', '提供的金鑰無效或已損毀，無法用來解密此備份。', key_id=key_id)
    return _corrupt('decryption failed', stage='decrypt')


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


def _map_os_error(exc, what):
    if isinstance(exc, OSError) and exc.errno in (errno.ENOSPC, errno.EDQUOT):
        return BackupError('insufficient-space', '磁碟空間不足，無法完成備份封裝。')
    return BackupError('internal-error', f'{what}失敗。', reason=type(exc).__name__)


def _write_all(fd, buf):
    view = memoryview(buf)
    while view:
        view = view[os.write(fd, view):]


# ====================================================================== writing (shared pieces)

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
                _write_all(self.out_fd, buf)
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


def _check_sources(entries):
    for entry in entries:
        try:
            st = os.lstat(entry.source)
        except OSError:
            st = None
        if st is None or not stat.S_ISREG(st.st_mode) or st.st_size != entry.size:
            raise BackupError('internal-error', '備份暫存檔不存在或大小與記錄不符。', entry=entry.path)


def _add_entries(tar, entries, mtime, meter):
    """Append staged files to an open tarfile, checking each against its recorded size and sha256."""
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
                    raise BackupError('internal-error', '備份暫存檔在封裝時變短。', entry=entry.path) from None
                raise
            if reader.digest.hexdigest() != entry.sha256:
                raise BackupError('internal-error', '封裝時來源檔案的校驗值與記錄不符。', entry=entry.path)
        finally:
            os.close(src)


def _write_recipient(tmp_dir, recipient):
    # The recipient goes to age in a private file, not in argv where every local account could read it
    # from /proc (review finding SEC-7: it lets anyone encrypt a hostile archive to this device's key).
    path = Path(tmp_dir) / f'.recipient-{util.random_hex(6)}'
    rfd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(rfd, (recipient + '\n').encode('ascii'))
    finally:
        os.close(rfd)
    return path


def _encrypted_stream(out_fd, recipients_path, digest, produce):
    """`produce(binary file)` writes a tar into `zstd | age -R <recipients>`, whose output is appended to `out_fd`
    (hashed into `digest`). Returns the number of bytes appended. Children are always reaped."""
    age_bin, zstd_bin = _tools()
    procs, pump = [], None
    age_err, zstd_err = tempfile.TemporaryFile(), tempfile.TemporaryFile()
    try:
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
            produce(zstd.stdin)
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
        return pump.total
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
        age_err.close()
        zstd_err.close()


def _deflate_block(block, dictionary, last, level):
    compressor = (zlib.compressobj(level, zlib.DEFLATED, -15, 8, zlib.Z_DEFAULT_STRATEGY, dictionary) if dictionary
                  else zlib.compressobj(level, zlib.DEFLATED, -15))
    return compressor.compress(block) + compressor.flush(zlib.Z_FINISH if last else zlib.Z_SYNC_FLUSH)


class _GzipWriter:
    """File-like sink for tarfile that appends gzip (one RFC 1952 member) of everything written to `out_fd`.

    Blocks of GZIP_BLOCK bytes are deflated in parallel the way pigz does it: each block as raw deflate primed with
    the 32 KiB before it and ended by a sync flush (byte aligned, not final), the last one finished. The output is a
    single ordinary gzip stream any gzip reader accepts. zlib releases the GIL while it compresses, so plain backups
    are not bound to one core."""

    def __init__(self, out_fd, digest, *, level=GZIP_LEVEL, workers=None):
        self.out_fd, self.digest, self.level = out_fd, digest, level
        self.workers = workers or max(1, min(4, os.cpu_count() or 1))
        self.pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix='woowbackup-deflate')
        self.pending = collections.deque()
        self.buffer = bytearray()
        self.previous = b''
        self.crc, self.length, self.total = 0, 0, 0
        self.closed = False
        self._emit(GZIP_HEADER)

    def _emit(self, data):
        _write_all(self.out_fd, data)
        self.digest.update(data)
        self.total += len(data)

    def _submit(self, block, last):
        dictionary, self.previous = self.previous, block[-GZIP_WINDOW:] if block else self.previous
        self.pending.append(self.pool.submit(_deflate_block, block, dictionary, last, self.level))
        while len(self.pending) > 2 * self.workers:
            self._emit(self.pending.popleft().result())

    def write(self, data):
        if self.closed:
            raise ValueError('write to a closed gzip writer')
        data = bytes(data)
        self.crc = zlib.crc32(data, self.crc)
        self.length += len(data)
        self.buffer += data
        while len(self.buffer) >= GZIP_BLOCK:
            block = bytes(self.buffer[:GZIP_BLOCK])
            del self.buffer[:GZIP_BLOCK]
            self._submit(block, last=False)
        return len(data)

    def flush(self):
        return None

    def close(self):
        """Finish the stream (last block, trailer). Idempotent; abort() instead after a failure."""
        if self.closed:
            return
        self.closed = True
        try:
            self._submit(bytes(self.buffer), last=True)
            self.buffer = bytearray()
            while self.pending:
                self._emit(self.pending.popleft().result())
            self._emit(struct.pack('<II', self.crc & 0xFFFFFFFF, self.length & 0xFFFFFFFF))
        finally:
            self.pool.shutdown(wait=True, cancel_futures=True)

    def abort(self):
        self.closed = True
        for future in self.pending:
            future.cancel()
        self.pending.clear()
        self.pool.shutdown(wait=True, cancel_futures=True)


# ====================================================================== v1 writer (compatibility tests only)

def _write_v1(dest, header, manifest, entries, recipient, *, tmp_dir, progress=None):
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
    _check_sources(entries)
    if os.path.lexists(dest):
        raise BackupError('internal-error', '目標備份檔已存在。')

    _tools()
    mtime = int(util.parse_iso_utc(manifest['created']).timestamp())
    head = header_bytes(hdr)
    tmp_path = tmp_dir / f'.{manifest["backup_id"]}.{util.random_hex(6)}.woowbackup.tmp'
    digest = hashlib.sha256()
    renamed = False
    meter = _Progress(progress, sum(e.size for e in entries))
    try:
        out_fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as exc:
        raise _map_os_error(exc, '建立備份暫存檔') from exc
    recipients_path = None
    try:
        _write_all(out_fd, head)
        digest.update(head)
        recipients_path = _write_recipient(tmp_dir, recipient)

        def produce(sink):
            with tarfile.open(fileobj=sink, mode='w|', format=tarfile.PAX_FORMAT, bufsize=CHUNK,
                              copybufsize=CHUNK) as tar:
                tar.addfile(_tarinfo('manifest.json', len(manifest_data), mtime), io.BytesIO(manifest_data))
                _add_entries(tar, entries, mtime, meter)

        total = _encrypted_stream(out_fd, recipients_path, digest, produce)
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
        return {'size': len(head) + total, 'sha256': digest.hexdigest()}
    except BackupError:
        raise
    except OSError as exc:
        raise _map_os_error(exc, '建立備份檔') from exc
    finally:
        if out_fd >= 0:
            os.close(out_fd)
        if not renamed:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_path)
        if recipients_path is not None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(recipients_path)


# ====================================================================== v2 writer

README_TEXT = """woowtech Cockpit 備份檔（格式 2）
====================================

這個檔案是 woowtech Cockpit「備份與還原」建立的應用備份，可直接上傳到任何安裝了「備份與還原」的設備還原。

備份 ID：{backup_id}
建立時間：{created}（UTC）
來源設備：{hostname}
類型：{type_zh}
加密：{encryption_zh}

包含的應用：
{apps_zh}

在 Cockpit 還原
1. 登入目標設備的 Cockpit，以管理員身分開啟「備份與還原」。
2. 在「從檔案還原」上傳這個 .tar 檔案（不需要先解開）。
{key_step_zh}
4. 檢查相容性檢查的結果與受影響的應用，確認後開始還原。

手動解開（進階）
backup.json 只是方便閱讀的說明，沒有經過驗證；還原時以各應用封存檔內的 manifest.json 為準。
{manual_zh}
解開後 manifest.json 列出每個項目的大小與 SHA-256。資料庫匯出（*.dump）是 pg_dump 的自訂格式，可用 pg_restore
讀取；資料卷與主機資料夾是 tar 檔。{secrets_zh}

----------------------------------------------------------------------

woowtech Cockpit backup (format 2)
==================================

This file is an application backup made by "Backup & Restore" (備份與還原) in woowtech Cockpit. Upload it on any
device that runs it to restore.

Backup ID:  {backup_id}
Created:    {created} (UTC)
Source:     {hostname}
Type:       {type}
Encryption: {encryption_en}

Applications:
{apps_en}

Restore in Cockpit
1. Log in to Cockpit on the target device with administrative access and open "備份與還原".
2. Under "從檔案還原" (restore from a file), upload this .tar file as it is.
{key_step_en}
4. Review the compatibility check and the affected applications, then confirm.

Unpack by hand (advanced)
backup.json is informational and NOT authenticated; a restore trusts only the manifest.json inside each
application archive.
{manual_en}
manifest.json lists every item with its size and SHA-256. Database dumps (*.dump) are pg_dump custom-format files
(read them with pg_restore); volumes and host directories are tar files. {secrets_en}
"""


def readme_text(doc):
    """README.txt of a v2 backup (zh-TW and English): what it is, how to restore it, how to unpack it by hand."""
    encrypted = doc['encryption'] == ENCRYPTION
    apps_zh = '\n'.join(f'  - {app["name"]}（{app["id"]}）：{app["file"]}' for app in doc['apps'])
    apps_en = '\n'.join(f'  - {app["name"]} ({app["id"]}): {app["file"]}' for app in doc['apps'])
    if encrypted:
        lines = ['  tar -xf <backup-file>.tar']
        for app in doc['apps']:
            lines += [f'  mkdir {app["id"]}',
                      f'  age -d -i <emergency-kit>.txt {app["file"]} | zstd -d -c | tar -x -C {app["id"]}']
        commands = '\n'.join(lines)
        manual_zh = ('需要 age 與 zstd（Ubuntu／Debian：sudo apt install age zstd）以及這份備份的緊急金鑰檔'
                     f'（金鑰 ID {doc["key_id"]}，woowtech-backup-key-….txt）：\n\n{commands}\n')
        manual_en = ('You need age and zstd (Ubuntu/Debian: sudo apt install age zstd) and the emergency kit of this '
                     f'backup (key ID {doc["key_id"]}, woowtech-backup-key-….txt):\n\n{commands}\n')
        key_step_zh = f'3. 頁面要求金鑰時，讀取或貼上這份備份的緊急金鑰（金鑰 ID {doc["key_id"]}）。'
        key_step_en = f'3. When the page asks for a key, load or paste the emergency kit of this backup (key ID {doc["key_id"]}).'
        secrets_zh = '內容包含資料庫密碼、API 金鑰與存取權杖等應用機密，解開後請妥善保管並在用完後刪除。'
        secrets_en = ('The content includes application secrets such as database passwords, API keys and tokens: '
                      'keep what you unpack safe and delete it when you are done.')
        encryption_zh = f'age X25519（金鑰 ID {doc["key_id"]}）'
        encryption_en = f'age X25519 (key ID {doc["key_id"]})'
    else:
        lines = ['  tar -xf <backup-file>.tar']
        for app in doc['apps']:
            lines += [f'  mkdir {app["id"]}', f'  tar -xzf {app["file"]} -C {app["id"]}']
        commands = '\n'.join(lines)
        manual_zh = f'任何支援 tar 與 gzip 的工具都能解開：\n\n{commands}\n'
        manual_en = f'Any tool that reads tar and gzip can unpack it:\n\n{commands}\n'
        key_step_zh = '3. 這份備份沒有加密，不需要金鑰；上傳的未加密備份在還原前需要另外確認其來源可信。'
        key_step_en = ('3. This backup is not encrypted and needs no key; an uploaded unencrypted backup asks you to '
                       'confirm that you trust where it came from.')
        secrets_zh = ('注意：這份備份沒有加密，資料庫密碼、API 金鑰與存取權杖等應用機密以明文存放，'
                      '任何取得這個檔案的人都能讀取，請妥善保管。')
        secrets_en = ('Warning: this backup is NOT encrypted. Application secrets such as database passwords, API keys '
                      'and tokens are stored in plain text: anyone who gets this file can read them.')
        encryption_zh = '未加密'
        encryption_en = 'none'
    return README_TEXT.format(
        backup_id=doc['backup_id'], created=doc['created'], hostname=doc['source']['hostname'],
        type=doc['type'], type_zh={'manual': '手動備份', 'safety': '還原前自動備份'}[doc['type']],
        encryption_zh=encryption_zh, encryption_en=encryption_en, apps_zh=apps_zh, apps_en=apps_en,
        key_step_zh=key_step_zh, key_step_en=key_step_en, manual_zh=manual_zh, manual_en=manual_en,
        secrets_zh=secrets_zh, secrets_en=secrets_en)


def _outer_header(name, size, mtime, *, pax=False):
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o600
    info.uid = info.gid = 0
    info.uname = info.gname = ''
    info.mtime = mtime
    info.type = tarfile.REGTYPE
    if pax:
        info.pax_headers = {'size': str(size)}
    return info.tobuf(tarfile.PAX_FORMAT, 'utf-8', 'surrogateescape')


def _padding(size):
    return bytes((-size) % BLOCK)


def _tar_bound(manifest_size, entries):
    """Upper bound of a tar stream tarfile writes for manifest.json plus `entries` (headers, PAX records, padding)."""
    total = 3 * BLOCK + manifest_size + BLOCK
    for entry in entries:
        total += 3 * BLOCK + entry.size + BLOCK
    return total + 2 * BLOCK + RECORD


class ArchiveWriter:
    """Incremental v2 writer: `add_app()` once per app in the order of `apps`, then `finish()` (or `abort()`; used as
    a context manager, an exception aborts). `head`: backup_id, created, type, note, key_id, encryption, tool,
    source, consistency. `recipient`: the age recipient (encryption age-x25519) or None (encryption none)."""

    def __init__(self, dest, head, apps, recipient, *, tmp_dir):
        self.dest, self.tmp_dir = Path(dest), Path(tmp_dir)
        head = {key: head[key] for key in HEAD_FIELDS}
        self.head = head
        self.encryption = head['encryption']
        if self.encryption == ENCRYPTION:
            if not isinstance(recipient, str) or not RECIPIENT_RE.match(recipient):
                raise BackupError('internal-error', '加密金鑰的公開金鑰格式不正確。')
            if head['key_id'] != key_id_for(recipient):
                raise BackupError('internal-error', '內容清單的金鑰 ID 與加密金鑰不符。')
        elif recipient is not None or self.encryption != PLAIN:
            raise BackupError('internal-error', '未加密的備份不能指定加密金鑰。')
        _validate_head(dict(head, format=FORMAT_V2), FORMAT_V2)
        self.apps = [dict(app) for app in apps]
        _list(self.apps, 'apps', MAX_APPS, min_items=1)
        ids = [app.get('id') for app in self.apps]
        _need(len(set(ids)) == len(ids), 'duplicate app id')
        self.ids = ids
        self.mtime = int(util.parse_iso_utc(head['created']).timestamp())
        self.done = []
        self.fd = -1
        self.renamed = False
        self.recipients_path = None
        if os.path.lexists(self.dest):
            raise BackupError('internal-error', '目標備份檔已存在。')
        if self.encryption == ENCRYPTION:
            _tools()
        try:
            doc = self._doc([{'file': inner_name(app['id'], self.encryption), 'size': MAX_SIZE, 'sha256': 'f' * 64}
                             for app in self.apps])
        except (KeyError, TypeError, AttributeError):
            raise _invalid('an app section is incomplete') from None
        try:
            validate_doc(json.loads(json.dumps(doc)))
        except BackupError as exc:
            raise _invalid('the backup metadata would be invalid', detail=exc.details.get('reason')) from None
        self.json_size = len(self._doc_bytes(doc)) + 1
        readme = readme_text(doc).encode('utf-8')
        self.tmp_path = self.tmp_dir / f'.{head["backup_id"]}.{util.random_hex(6)}.tar.tmp'
        try:
            self.fd = os.open(self.tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o600)
            _write_all(self.fd, _outer_header(BACKUP_JSON, self.json_size, self.mtime))
            self.json_offset = BLOCK
            _write_all(self.fd, bytes(self.json_size) + _padding(self.json_size))
            _write_all(self.fd, _outer_header(README, len(readme), self.mtime) + readme + _padding(len(readme)))
            if self.encryption == ENCRYPTION:
                self.recipients_path = _write_recipient(self.tmp_dir, recipient)
        except BaseException as exc:
            self.abort()
            if isinstance(exc, OSError):
                raise _map_os_error(exc, '建立備份暫存檔') from exc
            raise

    def _doc(self, files):
        doc = _head_view(self.head)
        doc['apps'] = [dict(display_app(app), **files[index]) for index, app in enumerate(self.apps)]
        return doc

    @staticmethod
    def _doc_bytes(doc):
        return json.dumps(doc, ensure_ascii=False, indent=2).encode('utf-8')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, _exc, _tb):
        if exc_type is not None:
            self.abort()
        return False

    def add_app(self, app, entries, *, meter=None, progress=None):
        """Write one app's inner archive (manifest.json + `entries`, Entry objects in reference order)."""
        index = len(self.done)
        if index >= len(self.apps) or app.get('id') != self.ids[index]:
            raise BackupError('internal-error', '封裝應用的順序與備份內容不符。')
        entries = list(entries)
        manifest = dict(self.head, format=FORMAT_V2, backup_apps=list(self.ids), app=app,
                        entries=[{'path': e.path, 'size': e.size, 'sha256': e.sha256} for e in entries])
        manifest = {key: manifest[key] for key in INNER_KEYS}
        validate_app_manifest(manifest)
        if display_app(app) != display_app(self.apps[index]):
            raise BackupError('internal-error', '封裝應用的內容與備份清單不符。')
        data = json.dumps(manifest, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        if len(data) > MAX_MANIFEST:
            raise _limit('manifest too large', size=len(data))
        if len(entries) + 1 > MAX_MEMBERS:
            raise _limit('too many members', members=len(entries) + 1)
        _check_sources(entries)
        meter = meter or _Progress(progress, sum(e.size for e in entries))
        name = inner_name(app['id'], self.encryption)
        bound = _tar_bound(len(data), entries)
        bound += bound // 500 + CHUNK  # zstd/age or deflate never grow incompressible data by that much
        slot = BLOCK if bound <= USTAR_SIZE_MAX else PAX_SLOT
        try:
            slot_offset = os.lseek(self.fd, 0, os.SEEK_CUR)
            _write_all(self.fd, bytes(slot))
            digest = hashlib.sha256()

            def produce(sink):
                with tarfile.open(fileobj=sink, mode='w|', format=tarfile.PAX_FORMAT, bufsize=CHUNK,
                                  copybufsize=CHUNK) as tar:
                    tar.addfile(_tarinfo(INNER_MANIFEST, len(data), self.mtime), io.BytesIO(data))
                    _add_entries(tar, entries, self.mtime, meter)

            if self.encryption == ENCRYPTION:
                size = _encrypted_stream(self.fd, self.recipients_path, digest, produce)
            else:
                sink = _GzipWriter(self.fd, digest)
                try:
                    produce(sink)
                    sink.close()
                except BaseException:
                    sink.abort()
                    raise
                size = sink.total
            _write_all(self.fd, _padding(size))
            header = _outer_header(name, size, self.mtime, pax=slot == PAX_SLOT)
            if len(header) != slot:
                raise BackupError('internal-error', '備份檔的項目標頭大小與預留空間不符。', member=name)
            os.pwrite(self.fd, header, slot_offset)
        except OSError as exc:
            raise _map_os_error(exc, '寫入備份檔') from exc
        self.done.append({'id': app['id'], 'file': name, 'size': size, 'sha256': digest.hexdigest()})
        return dict(self.done[-1])

    def finish(self):
        """backup.json, end of archive, fsync, the file's sha256, atomic rename. Returns {size, sha256, apps}."""
        if len(self.done) != len(self.apps):
            raise BackupError('internal-error', '備份檔缺少部分應用的內容。')
        doc = self._doc([{key: item[key] for key in ('file', 'size', 'sha256')} for item in self.done])
        data = self._doc_bytes(doc)
        if len(data) + 1 > self.json_size:
            raise BackupError('internal-error', '備份說明檔超出預留空間。')
        data += b' ' * (self.json_size - len(data) - 1) + b'\n'
        try:
            os.pwrite(self.fd, data, self.json_offset)
            end = os.lseek(self.fd, 0, os.SEEK_CUR) + 2 * BLOCK
            _write_all(self.fd, bytes(2 * BLOCK + (-end) % RECORD))
            os.fsync(self.fd)
            size = os.lseek(self.fd, 0, os.SEEK_CUR)
            os.close(self.fd)
            self.fd = -1
            sha256 = util.sha256_file(self.tmp_path)
            if os.path.lexists(self.dest):
                raise BackupError('internal-error', '目標備份檔已存在。')
            os.rename(self.tmp_path, self.dest)
            self.renamed = True
            util.fsync_dir(self.dest.parent)
        except OSError as exc:
            self.abort()
            raise _map_os_error(exc, '建立備份檔') from exc
        except BaseException:
            self.abort()
            raise
        self._drop_recipient()
        return {'size': size, 'sha256': sha256, 'apps': [dict(item) for item in self.done]}

    def _drop_recipient(self):
        if self.recipients_path is not None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(self.recipients_path)
            self.recipients_path = None

    def abort(self):
        if self.fd >= 0:
            with contextlib.suppress(OSError):
                os.close(self.fd)
            self.fd = -1
        if not self.renamed:
            with contextlib.suppress(FileNotFoundError, AttributeError):
                os.unlink(self.tmp_path)
        self._drop_recipient()


def head_of(manifest):
    """The head fields of a combined manifest (v2 writer input)."""
    head = {key: manifest[key] for key in HEAD_FIELDS if key in manifest}
    head.setdefault('encryption', ENCRYPTION if manifest.get('key_id') else PLAIN)
    missing = [key for key in HEAD_FIELDS if key not in head]
    if missing:
        raise _invalid('manifest missing keys', keys=missing)
    return head


def group_entries(apps, entries):
    """{app id: [Entry]} in the given order; every entry must belong to one of `apps`."""
    groups = {app['id']: [] for app in apps}
    for entry in entries:
        match = re.match(r'apps/([a-z0-9][a-z0-9-]{1,40})/', entry.path)
        if not match or match.group(1) not in groups:
            raise _invalid('entry outside the apps of the backup', path=str(entry.path)[:300])
        groups[match.group(1)].append(entry)
    return groups


def write_archive(dest, header, manifest, entries, recipient, *, tmp_dir, progress=None):
    """Write a backup atomically (temp in `tmp_dir` on the same filesystem, fsync, rename to `dest`).

    The format follows `manifest['format']`: 2 (native, `.tar`; `recipient` None writes an unencrypted backup) or 1
    (`.woowbackup`, compatibility tests). `manifest['entries']` is (re)built from `entries`. Returns {'size',
    'sha256'} of the file, plus `apps` [{id, file, size, sha256}] for v2. `progress(done, total)` is optional.
    """
    fmt = (manifest or {}).get('format', FORMAT)
    if fmt == FORMAT:
        return _write_v1(dest, header, manifest, entries, recipient, tmp_dir=tmp_dir, progress=progress)
    if fmt != FORMAT_V2:
        raise BackupError('internal-error', '不支援的備份格式。', version=str(fmt)[:20])
    entries = list(entries)
    head = head_of(manifest)
    view = {'format': FORMAT_V2, 'backup_id': head['backup_id'], 'created': head['created'],
            'key_id': head['key_id'], 'encryption': head['encryption'], 'compression': COMPRESSION_OF.get(
                head['encryption'])}
    for key, value in (header or {}).items():
        if key not in view or view[key] != value:
            raise BackupError('internal-error', '備份標頭與內容清單不一致。', field=str(key)[:64])
    apps = list(manifest.get('apps') or [])
    groups = group_entries(apps, entries)
    meter = _Progress(progress, sum(e.size for e in entries))
    with ArchiveWriter(dest, head, apps, recipient, tmp_dir=tmp_dir) as writer:
        for app in apps:
            writer.add_app(app, groups[app['id']], meter=meter)
        # Last progress report before publishing: a cancel raised by the callback discards the temp file.
        meter.finish()
        return writer.finish()


# ====================================================================== reading: sources

class _Decryptor:
    """v1: `age -d` | `zstd -d` over an archive file; plaintext is read from zstd's stdout."""

    def __init__(self, path, identity_files):
        self.procs = []
        self.out = None
        self.age_err = self.zstd_err = None
        fd = _open_archive(path)
        try:
            self.header, offset = _read_header_fd(fd)
            self.identities, self.key_ids = _usable_identities(identity_files, self.header['key_id'])
            argv = []
            for path_ in self.identities:
                argv += ['-i', str(path_)]
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
            return _age_error(_stderr_text(self.age_err), self.header['key_id'], self.key_ids)
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


class _Feeder(threading.Thread):
    """Copies one member of the outer tar (pread from the archive fd) into a tool's stdin, hashing it."""

    def __init__(self, fd, offset, size, sink):
        super().__init__(name='woowbackup-feed', daemon=True)
        self.fd, self.offset, self.size, self.sink = fd, offset, size, sink
        self.digest = hashlib.sha256()
        self.done = 0
        self.error = None

    def run(self):
        try:
            out = self.sink.fileno()
            pos, end = self.offset, self.offset + self.size
            while pos < end:
                buf = os.pread(self.fd, min(CHUNK, end - pos), pos)
                if not buf:
                    self.error = 'short read'
                    return
                self.digest.update(buf)
                _write_all(out, buf)
                pos += len(buf)
                self.done += len(buf)
        except (BrokenPipeError, ConnectionResetError):
            return  # the tool stopped reading (wrong key, early stop): its exit status says why
        except BaseException as exc:  # noqa: BLE001 - reported through tool_error()
            self.error = type(exc).__name__
        finally:
            with contextlib.suppress(OSError):
                self.sink.close()


class _InnerAge:
    """v2 encrypted: `age -d` | `zstd -d` over one member of the outer tar, fed by a thread."""

    def __init__(self, fd, member, identities, key_ids, key_id):
        self.procs, self.out, self.feeder = [], None, None
        self.member, self.key_ids, self.key_id = member, key_ids, key_id
        self.age_err = self.zstd_err = None
        try:
            age_bin, zstd_bin = _tools()
            argv = []
            for path in identities:
                argv += ['-i', str(path)]
            self.age_err, self.zstd_err = tempfile.TemporaryFile(), tempfile.TemporaryFile()
            env = util.clean_env()
            self.age = subprocess.Popen([age_bin, '-d', *argv], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.age_err, env=env, close_fds=True)
            self.procs.append(self.age)
            self.zstd = subprocess.Popen([zstd_bin, '-d', '-c', '-q'], stdin=self.age.stdout, stdout=subprocess.PIPE,
                                         stderr=self.zstd_err, env=env, close_fds=True)
            self.procs.append(self.zstd)
            self.age.stdout.close()
            self.out = self.zstd.stdout
            _grow_pipe(self.out)
            _grow_pipe(self.age.stdin)
            self.feeder = _Feeder(fd, member.offset, member.size, self.age.stdin)
            self.feeder.start()
        except BaseException:
            self.close()
            raise
        self._fd = self.out.fileno()

    read = _Decryptor.read
    read_exact = _Decryptor.read_exact
    chunks = _Decryptor.chunks

    def tool_error(self, wait):
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
            return _age_error(_stderr_text(self.age_err), self.key_id, self.key_ids)
        if zstd_rc not in (None, 0):
            return _corrupt('decompression failed', stage='decompress')
        if wait:
            self.feeder.join()
            if self.feeder.error is not None or self.feeder.done != self.member.size:
                return _corrupt('the archive file changed or ended while it was read', member=self.member.name)
        return None

    def member_sha256(self):
        """sha256 of the member bytes (only after tool_error(wait=True) returned None)."""
        return self.feeder.digest.hexdigest()

    def close(self):
        if self.out is not None:
            with contextlib.suppress(OSError):
                self.out.close()
        _reap(self.procs)
        if self.feeder is not None:
            self.feeder.join()
        for proc in self.procs:
            if proc.stdin is not None:
                with contextlib.suppress(OSError):
                    proc.stdin.close()
        for handle in (self.age_err, self.zstd_err):
            if handle is not None:
                handle.close()
        self.procs, self.out = [], None


class _InnerGzip:
    """v2 unencrypted: zlib (one gzip member, nothing after it) over one member of the outer tar, in-process."""

    def __init__(self, fd, member):
        self.fd, self.member = fd, member
        self.pos, self.end = member.offset, member.offset + member.size
        self.inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self.digest = hashlib.sha256()
        self.buffer = bytearray()
        self.pending = b''

    def _fill(self):
        """Decompress more; False at the end of the gzip stream."""
        while not self.buffer:
            if self.inflater.eof:
                if self.inflater.unused_data or self.pending or self.pos < self.end:
                    raise _corrupt('data after the gzip stream', member=self.member.name)
                return False
            if not self.pending:
                if self.pos >= self.end:
                    raise _Truncated()
                data = os.pread(self.fd, min(CHUNK, self.end - self.pos), self.pos)
                if not data:
                    raise _Truncated()
                self.pos += len(data)
                self.digest.update(data)
                self.pending = data
            try:
                out = self.inflater.decompress(self.pending, CHUNK)
            except zlib.error:
                raise _corrupt('decompression failed', stage='decompress', member=self.member.name) from None
            self.pending = self.inflater.unconsumed_tail
            self.buffer += out
        return True

    def read(self, size):
        if not self.buffer and not self._fill():
            return b''
        data = bytes(self.buffer[:size])
        del self.buffer[:size]
        return data

    def read_exact(self, size):
        parts, need = [], size
        while need:
            buf = self.read(min(need, CHUNK))
            if not buf:
                raise _Truncated()
            parts.append(buf)
            need -= len(buf)
        return b''.join(parts)

    def chunks(self, size):
        need = size
        while need:
            buf = self.read(min(need, CHUNK))
            if not buf:
                raise _Truncated()
            need -= len(buf)
            yield buf

    def tool_error(self, wait):
        if not wait:
            return None
        if not self.inflater.eof:
            return _corrupt('the gzip stream is incomplete', stage='decompress', member=self.member.name)
        if self.inflater.unused_data or self.pending or self.buffer or self.pos != self.end:
            return _corrupt('data after the gzip stream', member=self.member.name)
        return None

    def member_sha256(self):
        return self.digest.hexdigest()

    def close(self):
        self.buffer = bytearray()
        self.pending = b''


class _FileReader:
    """Sequential strict reads of the outer tar with pread (position kept here), optionally hashing what it reads."""

    def __init__(self, fd, size, hasher=None):
        self.fd, self.size, self.pos, self.hasher = fd, size, 0, hasher

    def read(self, size):
        size = min(size, self.size - self.pos)
        if size <= 0:
            return b''
        data = os.pread(self.fd, size, self.pos)
        self.pos += len(data)
        if self.hasher is not None:
            self.hasher.update(data)
        return data

    def read_exact(self, size):
        parts, need = [], size
        while need:
            buf = self.read(min(need, CHUNK))
            if not buf:
                raise _Truncated()
            parts.append(buf)
            need -= len(buf)
        return b''.join(parts)

    def chunks(self, size):
        need = size
        while need:
            buf = self.read(min(need, CHUNK))
            if not buf:
                raise _Truncated()
            need -= len(buf)
            yield buf

    def skip(self, size):
        if self.pos + size > self.size:
            raise _Truncated()
        self.pos += size


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


# ---------------------------------------------------------------- extraction target and scratch files

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


class _Scratch:
    """One entry at a time in a private directory, for the deep checks of a verify pass (CONTRACT section 5)."""

    def __init__(self, folder, limits):
        self.folder, self.limits, self.count = Path(folder), limits, 0
        st = os.lstat(self.folder)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise BackupError('internal-error', '驗證暫存目錄不安全（必須是僅限管理員存取的目錄）。')

    def create(self, size):
        free = _free_bytes(self.limits, self.folder)
        if size > free - self.limits.reserve_bytes:
            raise BackupError('insufficient-space', '磁碟空間不足，無法深入檢查備份內容。',
                              required=size + self.limits.reserve_bytes, free=free)
        self.count += 1
        path = self.folder / f'entry-{self.count}'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        return fd, path


# ---------------------------------------------------------------- the entry pass (v1 and v2)

def _free_bytes(limits, path):
    if limits.free_bytes is not None:
        return int(limits.free_bytes(path))
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def _read_entries(src, entries, *, meter, extractor=None, keep=None, deep=None, scratch=None):
    """Read `entries` (manifest order) from a strict tar stream: name, size and sha256 of each member; extract the
    ones `keep(path)` accepts; hand each to `deep` (a verify job's nested checks)."""
    for entry in entries:
        member = _next_member(src)
        if member is None:
            raise _corrupt('member missing', path=entry['path'])
        name, size = member
        if name != entry['path']:
            raise _corrupt('unexpected member (wrong name, order or duplicate)', member=name[:200],
                           expected=entry['path'])
        if size != entry['size']:
            raise _corrupt('member size differs from the manifest', path=entry['path'])
        digest = hashlib.sha256()
        out = extractor.create(entry['path']) if extractor is not None and (keep is None or keep(name)) else -1
        check, check_path = -1, None
        if deep is not None and scratch is not None and deep.wants(name):
            check, check_path = scratch.create(size)
        head = b''
        try:
            for chunk in src.chunks(size):
                digest.update(chunk)
                if len(head) < HEAD_BYTES:
                    head += chunk[:HEAD_BYTES - len(head)]
                if out >= 0:
                    _write_all(out, chunk)
                if check >= 0:
                    _write_all(check, chunk)
                meter.add(len(chunk))
        finally:
            if out >= 0:
                os.close(out)
            if check >= 0:
                os.close(check)
        try:
            _skip_padding(src, size)
            if digest.hexdigest() != entry['sha256']:
                raise _corrupt('member checksum mismatch', path=entry['path'])
            if deep is not None:
                deep.entry(name, head, check_path, size)
        finally:
            if check_path is not None:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(check_path)


def _app_of(path):
    match = re.match(r'apps/([a-z0-9][a-z0-9-]{1,40})/', path)
    return match.group(1) if match else None


def _missing_apps(available, wanted):
    for app_id in wanted or ():
        if app_id not in available:
            raise BackupError('incompatible', f'此備份不包含應用「{app_id}」。', app=app_id)


def _select(manifest, apps):
    """A v1 manifest restricted to `apps` (all when None), with only their entries."""
    if apps is None:
        return manifest
    _missing_apps({app['id'] for app in manifest['apps']}, apps)
    wanted = set(apps)
    return dict(manifest, apps=[app for app in manifest['apps'] if app['id'] in wanted],
                entries=[entry for entry in manifest['entries'] if _app_of(entry['path']) in wanted])


# ---------------------------------------------------------------- v1 read pass

def _read_stream(dec, mode, limits, progress, extractor, apps=None, deep=None, scratch=None):
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
    selected = _select(manifest, apps)
    wanted = None if apps is None else set(apps)
    entries = manifest['entries']
    total = sum(e['size'] for e in entries)
    if total > limits.max_total_bytes:
        raise _limit('declared total size too large', total=total)
    if mode == 'manifest':
        return selected, sum(e['size'] for e in selected['entries'])
    keep = None if wanted is None else (lambda path: _app_of(path) in wanted)
    if extractor is not None:
        need = sum(e['size'] for e in selected['entries'])
        free = _free_bytes(limits, extractor.root)
        if need > free - limits.reserve_bytes:
            raise BackupError('insufficient-space', '磁碟空間不足，無法解開此備份。',
                              required=need + limits.reserve_bytes, free=free)
    if deep is not None:
        deep.start(manifest['apps'])
    meter = _Progress(progress, total)
    _read_entries(dec, entries, meter=meter, extractor=extractor, keep=keep, deep=deep, scratch=scratch)
    if _next_member(dec) is not None:
        raise _corrupt('extra member after the manifest entries')
    _finish_tar(dec)
    meter.finish()
    return (selected if mode == 'extract' else manifest), total


def _run_v1(path, identity_files, mode, *, limits, progress, dest_dir, apps, deep, scratch_dir):
    extractor = _Extractor(dest_dir) if mode == 'extract' else None
    ok = False
    try:
        scratch = _Scratch(scratch_dir, limits) if deep is not None and scratch_dir is not None else None
        dec = _Decryptor(path, identity_files)
        try:
            try:
                manifest, total = _read_stream(dec, mode, limits, progress, extractor, apps, deep, scratch)
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


# ---------------------------------------------------------------- v2 outer layout

@dataclass(frozen=True)
class _Member:
    name: str
    offset: int
    size: int
    app: dict


@dataclass(frozen=True)
class _Layout:
    doc: dict
    readme: str
    members: tuple
    size: int

    @property
    def encrypted(self):
        return self.doc['encryption'] == ENCRYPTION

    def header(self):
        doc = self.doc
        return {'format': FORMAT_V2, 'backup_id': doc['backup_id'], 'created': doc['created'],
                'key_id': doc['key_id'], 'encryption': doc['encryption'], 'compression': doc['compression']}

    def select(self, apps):
        if apps is None:
            return list(self.members)
        _missing_apps({member.app['id'] for member in self.members}, apps)
        wanted = set(apps)
        return [member for member in self.members if member.app['id'] in wanted]


def _scan_layout(fd, *, read_data=False, hasher=None):
    """Strict parse of the outer tar of a v2 backup: backup.json, README.txt, one member per app of backup.json in its
    order (names, sizes), zero padding, the end-of-archive marker and nothing but zeros after it. Member data is
    skipped unless `read_data` (then every member's sha256 is checked against backup.json and `hasher` sees every
    byte of the file in order)."""
    st = os.fstat(fd)
    reader = _FileReader(fd, st.st_size, hasher)
    try:
        first = _next_member(reader)
        if first is None or first[0] != BACKUP_JSON:
            raise _not_a_backup()
        if first[1] > MAX_BACKUP_JSON:
            raise _limit('backup.json too large', size=first[1])
        raw = reader.read_exact(first[1])
        _skip_padding(reader, first[1])
        try:
            doc = util.loads_strict(raw, max_bytes=MAX_BACKUP_JSON)
        except ValueError:
            raise _corrupt('backup.json is not strict JSON') from None
        validate_doc(doc)
        second = _next_member(reader)
        if second is None or second[0] != README:
            raise _corrupt('README.txt is not the second member')
        if second[1] > MAX_README:
            raise _limit('README.txt too large', size=second[1])
        try:
            readme = reader.read_exact(second[1]).decode('utf-8')
        except UnicodeDecodeError:
            raise _corrupt('README.txt is not UTF-8 text') from None
        _skip_padding(reader, second[1])
        members = []
        for app in doc['apps']:
            member = _next_member(reader)
            if member is None:
                raise _corrupt('member missing', member=app['file'])
            if member[0] != app['file']:
                raise _corrupt('unexpected member (wrong name, order or duplicate)', member=member[0][:200],
                               expected=app['file'])
            if member[1] != app['size']:
                raise _corrupt('member size differs from backup.json', member=app['file'])
            offset = reader.pos
            if read_data:
                digest = hashlib.sha256()
                for chunk in reader.chunks(member[1]):
                    digest.update(chunk)
                if digest.hexdigest() != app['sha256']:
                    raise _corrupt('member checksum differs from backup.json', member=app['file'])
            else:
                reader.skip(member[1])
            _skip_padding(reader, member[1])
            members.append(_Member(app['file'], offset, member[1], app))
        if _next_member(reader) is not None:
            raise _corrupt('extra member after the application archives')
        _finish_tar(reader)
    except _Truncated:
        raise _corrupt('archive is truncated') from None
    return _Layout(doc, readme, tuple(members), st.st_size)


def _open_inner(fd, layout, member, identities):
    if layout.encrypted:
        return _InnerAge(fd, member, identities[0], identities[1], layout.doc['key_id'])
    return _InnerGzip(fd, member)


def _inner_manifest(src, layout, member, limits):
    """Read and check the first member of an inner archive: the authenticated per-app manifest."""
    first = _next_member(src)
    if first is None:
        raise _corrupt('application archive is empty', member=member.name)
    name, size = first
    if name != INNER_MANIFEST:
        raise _corrupt('manifest.json is not the first member', member=name[:200])
    if size > limits.max_manifest:
        raise _limit('manifest too large', size=size)
    data = src.read_exact(size)
    _skip_padding(src, size)
    try:
        inner = util.loads_strict(data, max_bytes=limits.max_manifest)
    except ValueError as exc:
        raise _invalid(f'manifest is not strict JSON: {str(exc)[:120]}') from None
    if isinstance(inner, dict) and isinstance(inner.get('entries'), list):
        if len(inner['entries']) + 1 > limits.max_members:
            raise _limit('too many members', members=len(inner['entries']) + 1)
    validate_app_manifest(inner)
    _check_against_doc(layout.doc, member.app, inner)
    return inner


def _with_source(fd, layout, member, identities, body, *, complete):
    """Run `body(src)` on an inner archive; tool failures (wrong key, bad MAC, broken gzip) win over parse errors.
    `complete`: the whole member was read, so the tools must have exited 0 and its sha256 equal backup.json's."""
    src = _open_inner(fd, layout, member, identities)
    try:
        try:
            result = body(src)
        except _Truncated:
            raise src.tool_error(wait=True) or _corrupt('archive content is truncated') from None
        except BackupError as exc:
            tool = src.tool_error(wait=False)
            raise (tool or exc) from None
        if complete:
            error = src.tool_error(wait=True)
            if error is not None:
                raise error
            if src.member_sha256() != member.app['sha256']:
                raise _corrupt('member checksum differs from backup.json', member=member.name)
        return result
    finally:
        src.close()


def _combine(layout, inners):
    """The v1-shaped manifest the flows use: head fields from the authenticated manifests (all equal), apps and
    entries of the apps that were read, plus `encryption`."""
    first = inners[0]
    for inner in inners[1:]:
        for key in (*HEAD_FIELDS, 'backup_apps'):
            if inner[key] != first[key]:
                raise _corrupt('the application archives belong to different backups', field=key)
    manifest = {'format': FORMAT_V2}
    manifest.update({key: first[key] for key in HEAD_FIELDS})
    manifest['apps'] = [inner['app'] for inner in inners]
    manifest['entries'] = [entry for inner in inners for entry in inner['entries']]
    manifest['backup_apps'] = list(first['backup_apps'])
    return manifest


def _run_v2(fd, identity_files, mode, *, limits, progress, dest_dir, apps, deep, scratch_dir):
    layout = _scan_layout(fd)
    selected = layout.select(apps)
    identities = _usable_identities(identity_files, layout.doc['key_id']) if layout.encrypted else None
    # Every selected app's authenticated manifest first: the totals and limits are known before anything is written,
    # and a manifest that differs from backup.json fails before any data is read.
    inners = [_with_source(fd, layout, member, identities,
                           lambda src, member=member: _inner_manifest(src, layout, member, limits), complete=False)
              for member in selected]
    manifest = _combine(layout, inners)
    count = len(manifest['entries'])
    if count + 1 > limits.max_members:
        raise _limit('too many members', members=count + 1)
    total = sum(e['size'] for e in manifest['entries'])
    if total > limits.max_total_bytes:
        raise _limit('declared total size too large', total=total)
    if mode == 'manifest':
        return manifest, total, layout
    extractor = _Extractor(dest_dir) if mode == 'extract' else None
    ok = False
    try:
        if extractor is not None:
            free = _free_bytes(limits, extractor.root)
            if total > free - limits.reserve_bytes:
                raise BackupError('insufficient-space', '磁碟空間不足，無法解開此備份。',
                                  required=total + limits.reserve_bytes, free=free)
        scratch = _Scratch(scratch_dir, limits) if deep is not None and scratch_dir is not None else None
        if deep is not None:
            deep.start(manifest['apps'])
        meter = _Progress(progress, total)
        for member, inner in zip(selected, inners):
            def body(src, inner=inner, member=member):
                again = _inner_manifest(src, layout, member, limits)
                if again != inner:
                    raise _corrupt('the archive changed while it was read', member=member.name)
                _read_entries(src, inner['entries'], meter=meter, extractor=extractor, deep=deep, scratch=scratch)
                if _next_member(src) is not None:
                    raise _corrupt('extra member after the manifest entries', member=member.name)
                _finish_tar(src)

            _with_source(fd, layout, member, identities, body, complete=True)
        meter.finish()
        ok = True
        return manifest, total, layout
    finally:
        if extractor is not None:
            if not ok:
                extractor.remove_all()
            extractor.close()


# ====================================================================== public reading API

def _run(path, identity_files, mode, *, limits=None, progress=None, dest_dir=None, apps=None, deep=None,
         scratch_dir=None):
    """(manifest, declared bytes, v2 layout or None)."""
    limits = limits or Limits()
    if apps is not None:
        apps = list(dict.fromkeys(apps))
    fd = _open_archive(path)
    try:
        fmt = _format_of_fd(fd)
        if fmt == FORMAT_V2:
            try:
                return _run_v2(fd, identity_files, mode, limits=limits, progress=progress, dest_dir=dest_dir,
                               apps=apps, deep=deep, scratch_dir=scratch_dir)
            except OSError as exc:
                raise _map_os_error(exc, '讀取備份檔') from exc
    finally:
        os.close(fd)
    manifest, total = _run_v1(path, identity_files, mode, limits=limits, progress=progress, dest_dir=dest_dir,
                              apps=apps, deep=deep, scratch_dir=scratch_dir)
    return manifest, total, None


def read_header(path):
    """The outer header: v1 `{format: 1, backup_id, created, key_id, encryption, compression}`; v2 the same fields
    from backup.json (`key_id` null and encryption "none" when unencrypted) after a strict parse of the outer tar.
    Raises BackupError(not-a-backup|unsupported-format|corrupt-archive|limit-exceeded)."""
    fd = _open_archive(path)
    try:
        if _format_of_fd(fd) == FORMAT_V2:
            return _scan_layout(fd).header()
        return _read_header_fd(fd)[0]
    finally:
        os.close(fd)


def describe(path, *, check_members=False):
    """{'format', 'header', 'doc' (v2 backup.json, untrusted: display only) | None, 'readme' | None}.
    `check_members` reads every byte of a v2 file and compares each application archive with backup.json's sha256."""
    fd = _open_archive(path)
    try:
        return describe_fd(fd, check_members=check_members)
    finally:
        os.close(fd)


def describe_fd(fd, *, check_members=False, hasher=None):
    """describe() of an open file (uploads). With `hasher` (and `check_members`) every byte of a v2 file is hashed in
    order; a v1 file is not read beyond its header."""
    if _format_of_fd(fd) == FORMAT_V2:
        layout = _scan_layout(fd, read_data=check_members, hasher=hasher if check_members else None)
        return {'format': FORMAT_V2, 'header': layout.header(), 'doc': layout.doc, 'readme': layout.readme}
    return {'format': FORMAT, 'header': _read_header_fd(fd)[0], 'doc': None, 'readme': None}


def read_manifest(path, identity_files, *, limits=None, apps=None):
    """Decrypt only as far as needed to return the validated manifest (no extraction).

    v1: stops after the manifest member (authenticates only the age chunks read so far). v2: reads each selected app's
    authenticated manifest (all apps when `apps` is None) and returns the combined, v1-shaped manifest (plus
    `encryption` and `backup_apps`). Use verify_archive() before trusting the rest of the archive.
    """
    return _run(path, identity_files, 'manifest', limits=limits, apps=apps)[0]


def verify_archive(path, identity_files, *, progress=None, limits=None, apps=None, deep=None, scratch_dir=None):
    """Full streaming pass (of the selected apps of a v2 backup). Returns {'manifest', 'entries', 'bytes', 'format',
    'encryption'}; raises BackupError on any defect. `deep` (with `scratch_dir`, a private empty directory) gets
    `start(apps)`, then `wants(path)` / `entry(path, head, file or None, size)` for every entry (CONTRACT section 5)."""
    manifest, total, layout = _run(path, identity_files, 'verify', limits=limits, progress=progress, apps=apps,
                                   deep=deep, scratch_dir=scratch_dir)
    return {'manifest': manifest, 'entries': len(manifest['entries']), 'bytes': total,
            'format': FORMAT_V2 if layout is not None else FORMAT,
            'encryption': manifest.get('encryption', ENCRYPTION)}


def extract_archive(path, identity_files, dest_dir, *, progress=None, limits=None, apps=None):
    """Safely extract into empty root-only `dest_dir`; returns the manifest of the extracted apps (all when `apps` is
    None; a v2 backup reads only their application archives). Partial output is the caller's to delete."""
    return _run(path, identity_files, 'extract', limits=limits, progress=progress, dest_dir=dest_dir, apps=apps)[0]
