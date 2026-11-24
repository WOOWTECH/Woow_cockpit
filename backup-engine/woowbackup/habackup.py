"""Home Assistant (Supervisor) backup files: recognise, describe, open members, read inner tars (CONTRACT section 5
"Home Assistant backups"). Owner: E1 engine-core (format).

An HA backup is a plain, uncompressed POSIX tar written by Python's tarfile (PAX headers carry float mtimes):
one inner tar per component -- `homeassistant.tar[.gz]`, `<add-on slug>.tar[.gz]`, `<folder>.tar[.gz]` (`share`,
`ssl`, `media`, `apps_local`/legacy `addons_local`), optionally `supervisor.tar[.gz]` -- and `./backup.json`, written
LAST (facts: haimport/HA-FACTS.md section 2; very old ones: `./snapshot.json`). `.tar.gz` members are gzip streams,
`.tar` members plain tars when `compressed` is false; with a password every member is encrypted on its own
(hasecuretar.py). Member names carry no `./` except backup.json's; names are compared after normalisation, like
Supervisor does.

Everything is hostile until checked, and what cannot be read stops no more than it must (HAOS parity 2026-11-25, DESIGN
section D): an entry, else that member (an add-on), else the file. Data that is not complete and intact is never used,
limits are wide but there are limits, and text from a backup is cleaned before anybody sees it (`clean_text`).

* `looks_like_ha(fd)`: cheap recognition for the upload path -- a member named `backup.json` (any `./` prefix; else
  `snapshot.json`) whose strict JSON is an HA description (`_is_ha_doc`). A Cockpit format 2 file (whose first member
  `backup.json` is not one) or a format 1 file answers False at once.
* `describe(fd)` -> Layout: the outer tar with valid header checksums, in any tar dialect (POSIX ustar, GNU, v7; PAX
  records, GNU long names): only regular files with flat names are members, everything else (folders, links, devices,
  names with a path, whatever backup.json does not list) is skipped and never followed, and nothing after the
  end-of-archive marker is read. Names are only compared, members only read in place by their offset: nothing of the
  outer tar is ever written anywhere. backup.json (<= 16 MiB, strict JSON, once; the schema subset below) is display
  data only and never trusted for a security decision. Each member's first bytes decide its encryption (SecureTar v2/v3
  header, gzip or tar, else legacy v1 when the backup is `protected`) and it must hold what that header announces;
  `protected` is never trusted for encryption either (an HA UI download is a decrypted copy that says
  `protected: false` while `supervisor.tar.gz` stays encrypted). A member that is there twice, cut off, of an unknown
  kind or encryption keeps a `problem` (PROBLEMS): it is listed and never opened; a listed add-on without a member has
  the problem `missing`, one whose slug cannot name a member `bad-slug`.
* `HaBackup` / `open_backup(path)` / `open_member(...)`: the plaintext of one member as a stream: its bytes, decrypted
  when encrypted (key-required without a key, wrong-key before any plaintext), gunzipped when compressed. The gzip
  reader inflates raw deflate after its own header parse and checks CRC32 and ISIZE of every gzip member (a stream may
  be several, then zero padding); a v1 member's trailer may have the legacy shape `pad | CRC | 0x0c * 12 | ISIZE`
  (securetar <= 2024.11 padded every write; GNU tar and gzip refuse it). `finish()` reads to the end and runs every
  final check (gzip trailer, v3 final tag, v2 padding and size).
* `iter_entries(stream, select, report)`: streaming walk of an inner tar (POSIX, GNU or v7) -- never an absolute name or
  one with `..`, no duplicates, nothing below a non-directory, no sparse files, global headers or unknown types: those
  stop the walk; symlinks and hard links per the caller's `Select`; byte, member and inflate budgets. Single entries
  that cannot be moved are skipped and counted in `report.skips` for the customer's confirmation: names that are blank,
  too long or have control characters, device nodes, FIFOs, anything but a file in a secret's place, links that cannot
  be handed out. The first end-of-archive block ends the tar; the rest of the stream is only read (and dropped) for the
  stream's `finish()`, or, when no checksum covers the stream (a plain, unencrypted tar), for another tar header: then
  the marker was not the end. Two kinds of files are never handed out: `addon.json` (it holds the add-on's options with
  passwords and tokens) is parsed into `report.addon` (AddonInfo: slug, version, image, arch, name -- never options or
  tokens), and NEVER_READ (`data/options.json`, `data/odoo.conf` with HA passwords, `data/n8n-runners-auth-token`, the
  HA-side secrets of the batch 1 add-ons) with everything below such a name is skipped unread; a hard link that names
  one is not followed either.

Symlinks are only ever handed out as link entries (names and targets), never followed: a later entry may not lie
below one. A relative target must stay inside the caller's area; an absolute one is handed out only when the caller
names allowed target prefixes (`Select.absolute_symlinks`, e.g. a Python venv's `/opt/data/...` interpreter link)
and it is clean (no empty, `.` or `..` component), so joined below the link's own folder -- the way the restore and
podman's import resolve it (nested.py) -- it can never leave the volume either.

Hard links: one that names an earlier selected file is handed out as a link when the caller takes links
(`Select.hardlinks`); every other selected one comes as a regular file with the content of the file it names, read from
the same member in a second pass after the walk (`_copy_links`); only when that file is not in the member, is a secret
or lies in an area the caller excludes, the link is skipped and listed.

backup.json schema subset (Supervisor SCHEMA_BACKUP, backups/validate.py; unknown keys tolerated and ignored): `version`
1 or 2 (absent: 1), `type` full|partial, `addons[{slug, name, version}]` (unique slugs), `folders[]` (known names,
unique), `repositories[]`, `extra` object; display only, cleaned and cut, never a reason to refuse: `slug`, `name`,
`date` (ISO 8601, normalised to UTC `...Z`, else null), `supervisor_version`, `homeassistant`, an add-on's name and
version. `protected` absent: false, not a boolean: true; `compressed` absent or not a boolean: what the member names
say, else true.

Errors (errors.CODES): corrupt-archive (hasecuretar.CORRUPT_MESSAGE for the file, MEMBER_MESSAGE with the detail `scope`
"member" for one member; English `reason` in the details), unsupported-format, limit-exceeded, not-found, key-required,
wrong-key, internal-error (missing crypto package).
"""
import array
import dataclasses
import datetime
import errno
import fcntl
import hashlib
import io
import os
import posixpath
import re
import secrets
import stat
import typing
import unicodedata
import zlib

from . import hasecuretar, util
from .errors import BackupError

BLOCK = 512
ZERO_BLOCK = bytes(BLOCK)
TAR_MAGIC_AT = hasecuretar.TAR_MAGIC_AT
POSIX_MAGIC = b'ustar\x00'       # any version ("00" by the standard)
GNU_MAGIC = b'ustar  \x00'
V7_MAGIC = bytes(8)              # a tar from before POSIX has no magic: these bytes are zero
CHUNK = 1024 * 1024
# Limits (HAOS parity 2026-11-25: far above any real backup, low enough that a crafted one stays harmless).
MAX_OUTER_MEMBERS = 4096         # an HA backup has one member per component (dozens at most); every header counts
MAX_BACKUP_JSON = 16 * 1024 * 1024
MAX_ADDONS = 1000
MAX_FOLDERS = 256
MAX_PAX = 1024 * 1024
MAX_LONG_NAME = 64 * 1024
MAX_NAME = 4096
MAX_ADDON_JSON = 32 * 1024 * 1024
DEFAULT_MAX_MEMBERS = 4_000_000  # _Names keeps about 18 bytes per entry
DEFAULT_MAX_BYTES = 16 * 1024 ** 4
# A member's tar may inflate to at most INFLATE_RATIO times its stored size (at least INFLATE_FLOOR): deflate's
# ~1000:1 would turn 1 GB into 1 TB of work (review HA-SEC-05); the job's space guard stops earlier when the disk gets
# low. Every CHECK_BYTES read and CHECK_ENTRIES headers the walk calls its `checkpoint` (a cancel stops it also while it
# skips what is not selected).
INFLATE_RATIO = 100
INFLATE_FLOOR = 256 * 1024 ** 3
CHECK_BYTES = 64 * 1024 * 1024
CHECK_ENTRIES = 1024
MAX_GZIP_FIELD = 1024 * 1024
MAX_GZIP_TRAILER = 64
MAX_GZIP_MEMBERS = 1_000_000
GZIP_FEED = 64 * 1024            # inflated at a time (what is left over of a piece is copied)
SAMPLES = 20                     # names listed per area or kind
MAX_KEPT_NAMES = 1000            # names of skipped entries kept per kind (above that their digest stands for them)
MAX_SHOWN_NAME = 120
# Hard links handed out as files: links that may wait for the second pass, passes over the member, and the size up to
# which a file with several waiting links is kept in memory for them.
MAX_LINK_COPIES = 100_000
MAX_LINK_PASSES = 4
LINK_MEMORY = 1024 * 1024
ENCODING, ERRORS = 'utf-8', 'surrogateescape'

BACKUP_JSON = 'backup.json'
SNAPSHOT_JSON = 'snapshot.json'  # what Supervisor called it until 2021 (its backups/backup.py load() still reads it)
ADDON_JSON = 'addon.json'
# Files of an add-on's data that hold Home Assistant passwords or tokens: never read, extracted or kept (batch 1:
# Hermes's generated secrets and the hashes of its applied provider keys, EMQX's Erlang cookie, Headscale's
# Headplane API key and cookie secret; facts hermes.md, emqx.md, headscale.md section 1; batch 2: code-server's
# agent logins).
NEVER_READ = frozenset({'data/options.json', 'data/odoo.conf', 'data/n8n-runners-auth-token',
                        'data/secrets/dashboard_password', 'data/secrets/api_server_key', 'data/secrets/webhook_secret',
                        'data/secrets/basic_auth_secret', 'data/applied/minimax_api_key',
                        'data/applied/openrouter_api_key', 'data/applied/github_token', 'data/emqx/node.cookie',
                        'data/.headplane_api_key', 'data/.headplane_cookie_secret',
                        # batch 2, code-server: the agents' logins (facts code-server.md section 1.4, decision D2 a)
                        'data/pi-agent/auth.json', 'data/pi-agent/mcp-auth.json',
                        'data/pi-agent/claude/.credentials.json', 'data/pi-agent/codex/auth.json'})
NEVER_READ_DEPTH = max(name.count('/') for name in NEVER_READ)
# Records of a global PAX header that would change how the members after it are found.
GLOBAL_UNSAFE = frozenset({'path', 'linkpath', 'size'})
LEGACY_APPS_FOLDERS = ('apps/local', 'addons/local')
V1_FOLDER = 'homeassistant'      # a folder of version 1 backups that Supervisor drops (validate.py v1_folderlist)

ADDON_SLUG_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z')
SYSTEM_SLUG_RE = re.compile(r'[a-z0-9][a-z0-9_-]{0,63}\Z')
VERSION_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9.+_~-]{0,63}\Z')
FOLDER_RE = re.compile(r'[a-z0-9_]{1,40}(?:/[a-z0-9_]{1,40})?\Z')
IMAGE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,511}\Z')
PAX_INT_RE = re.compile(r'[0-9]{1,20}\Z')
PAX_TIME_RE = re.compile(r'-?[0-9]{1,20}(?:\.[0-9]{1,20})?\Z')
CONTROL_RE = re.compile(r'[\x00-\x1f\x7f]')

LIMIT_MESSAGE = 'HA 備份檔超出安全限制（檔案數量或大小），已拒絕處理。'
# Why a member of a backup is listed but never opened (the sidecar's `addons[].problem`): code -> (error code, text).
PROBLEMS = {
    'missing': ('not-found', 'HA 備份的說明檔有列出這一項，但檔案裡沒有它的資料（可能是 HA 備份時失敗，或檔案被刪減過），'
                             '所以不能匯入它。請在 HA 重新備份後再匯入。'),
    'duplicate': ('corrupt-archive', 'HA 備份檔裡有兩份同名的資料，分不出哪一份是真的，所以不會使用它。請在 HA 重新備份後再匯入。'),
    'bad-slug': ('not-found', 'HA 備份的說明檔裡這個附加元件的代號無法辨識，找不到它的資料，所以不能匯入它。'
                              '請在 HA 重新備份後再匯入。'),
    'encryption-unsupported': ('unsupported-format', 'HA 備份裡這一項使用這台還不支援的加密格式，所以不能匯入它。'
                                                     '請更新這台設備的備份元件後再試。'),
    'size-mismatch': ('corrupt-archive', hasecuretar.MEMBER_MESSAGE),
    'partial-ciphertext': ('corrupt-archive', hasecuretar.MEMBER_MESSAGE),
    'not-an-archive': ('corrupt-archive', hasecuretar.MEMBER_MESSAGE),
}


def _corrupt(reason, **details):
    """The whole file cannot be used (the outer tar, backup.json)."""
    return hasecuretar.corrupt(reason, **details)


def _broken(reason, **details):
    """One member (an add-on, a folder) cannot be read; the rest of the file can."""
    return hasecuretar.broken(reason, **details)


def _limit(reason, **details):
    return BackupError('limit-exceeded', LIMIT_MESSAGE, reason=reason, **details)


def problem_text(code):
    """zh-TW: what a member's problem (PROBLEMS) means and what to do."""
    return PROBLEMS.get(code, ('', hasecuretar.MEMBER_MESSAGE))[1]


def problem_error(member_name, code):
    """The BackupError of a member that is never opened."""
    error_code, message = PROBLEMS.get(code, ('corrupt-archive', hasecuretar.MEMBER_MESSAGE))
    return BackupError(error_code, message, reason='member is not usable', scope='member', problem=code,
                       member=clean_text(member_name, 200))


# ====================================================================== text from a backup

# Never shown as they are: control characters, format characters (bidirectional overrides, zero-width ones), lone
# surrogates, unassigned code points, line and paragraph separators.
HIDDEN_CATEGORIES = frozenset({'Cc', 'Cf', 'Cs', 'Cn', 'Zl', 'Zp'})


def clean_text(value, max_len):
    """`value` as text that may be shown and logged: each character of HIDDEN_CATEGORIES becomes a space, no spaces
    around it, at most `max_len` characters; '' when it is not text."""
    if not isinstance(value, str):
        return ''
    return ''.join(' ' if unicodedata.category(c) in HIDDEN_CATEGORIES else c for c in value[:4 * max_len])\
        .strip()[:max_len].rstrip()


def shown_name(name):
    """An entry name of a tar for a message: cleaned, at most MAX_SHOWN_NAME characters (bytes that are not UTF-8 as
    spaces)."""
    return clean_text(name, MAX_SHOWN_NAME) or '（空白檔名）'


class _Truncated(Exception):
    """A read reached the end of the data early."""


# ====================================================================== tar header pieces (shared)

def _checksum_ok(block):
    """The header checksum: the unsigned byte sum (what tarfile writes) or, like tarfile accepts, the signed one."""
    try:
        stored = _number(block[148:156])
    except BackupError:
        return False
    if stored == sum(block[:148]) + 8 * 32 + sum(block[156:]):
        return True
    return stored == (sum(b - 256 if b > 127 else b for b in block[:148]) + 8 * 32
                      + sum(b - 256 if b > 127 else b for b in block[156:]))


def _number(field, bad=_corrupt):
    """An octal (NUL/space padded) or GNU base-256 number field (positive only)."""
    if field[:1] == b'\x80':
        return int.from_bytes(field[1:], 'big')
    if field[:1] and field[0] & 0x80:
        raise bad('tar number field is negative or invalid')
    text = field.split(b'\0', 1)[0].strip(b' ')
    if not text:
        return 0
    if text.strip(b'01234567'):
        raise bad('tar number field is not octal')
    return int(text, 8)


def _cbytes(field):
    return field.split(b'\0', 1)[0]


def _text(raw):
    return raw.decode(ENCODING, ERRORS)


def _parse_pax(data, bad=_corrupt):
    """{key: raw value bytes} of one PAX extended header; strict record syntax, no duplicate keys (keys nobody here
    knows are kept and ignored; sparse files are refused)."""
    records, pos = {}, 0
    while pos < len(data):
        if data[pos] == 0:  # NUL padding after the last record is tolerated like tarfile does, only zeros
            if data[pos:].strip(b'\0'):
                raise bad('malformed pax header')
            break
        space = data.find(b' ', pos, pos + 22)
        if space <= pos or not data[pos:space].isdigit():
            raise bad('malformed pax record')
        length = int(data[pos:space])
        end = pos + length
        if length < 5 or end > len(data) or data[end - 1:end] != b'\n':
            raise bad('malformed pax record')
        key, eq, value = data[space + 1:end - 1].partition(b'=')
        try:
            key = key.decode('ascii')
        except UnicodeDecodeError:
            raise bad('pax record key is not ASCII') from None
        if not eq or not key or key in records:
            raise bad('malformed or repeated pax record', key=key[:40])
        if key.startswith('GNU.sparse.'):
            raise bad('sparse files are not supported')
        records[key] = value
        pos = end
    return records


def _pax_int(records, key, default, bad=_corrupt):
    raw = records.get(key)
    if raw is None:
        return default
    text = raw.decode('ascii', 'replace')
    if not PAX_INT_RE.fullmatch(text):
        raise bad(f'pax {key} is not a number')
    return int(text)


def _pax_time(records, key, default, bad=_corrupt):
    raw = records.get(key)
    if raw is None:
        return default
    text = raw.decode('ascii', 'replace')
    if not PAX_TIME_RE.fullmatch(text):
        raise bad(f'pax {key} is not a time')
    return float(text)


class _Head(typing.NamedTuple):
    """One member's header block with the extended headers before it applied."""
    block: bytes
    pax: dict
    name: bytes
    link: bytes
    typeflag: bytes
    size: int


def _read_head(src, *, outer=False):
    """The next member's _Head from `src` (read_exact, skip), with its PAX and GNU long name records applied, or None at
    the end-of-archive marker: the first zero block, as tar(1) and tarfile stop (nothing after it is looked at here). A
    global PAX header is refused, except in the outer tar when it says nothing about names and sizes (None of its
    records is used)."""
    bad = _corrupt if outer else _broken
    pax = long_name = long_link = None
    while True:
        block = src.read_exact(BLOCK)
        if block == ZERO_BLOCK:
            if pax is not None or long_name is not None or long_link is not None:
                raise bad('extended header without a member')
            return None
        if not _checksum_ok(block):
            raise bad('tar header checksum mismatch')
        magic = block[TAR_MAGIC_AT:TAR_MAGIC_AT + 8]
        posix = magic.startswith(POSIX_MAGIC)
        if not posix and magic not in (GNU_MAGIC, V7_MAGIC):
            raise bad('tar header is neither POSIX, GNU nor v7')
        typeflag = block[156:157]
        size = _number(block[124:136], bad)
        if typeflag in (b'x', b'L', b'K', b'g') or outer and typeflag == b'X':  # X: Solaris' name for x
            if typeflag == b'g' and (not outer or pax is not None or long_name is not None or long_link is not None):
                raise bad('global pax headers are not supported')
            if size > (MAX_LONG_NAME if typeflag in (b'L', b'K') else MAX_PAX):
                raise _limit('extended header too large', size=size)
            data = src.read_exact(size)
            src.skip((-size) % BLOCK)
            if typeflag == b'g':
                if not GLOBAL_UNSAFE.isdisjoint(_parse_pax(data, bad)):
                    raise bad('a global pax header changes the members after it')
                return _Head(block, {}, b'', b'', typeflag, 0)
            if typeflag == b'L':
                if long_name is not None:
                    raise bad('consecutive long name records')
                long_name = _cbytes(data)
            elif typeflag == b'K':
                if long_link is not None:
                    raise bad('consecutive long link records')
                long_link = _cbytes(data)
            else:
                if pax is not None:
                    raise bad('consecutive pax headers')
                pax = _parse_pax(data, bad)
            continue
        name = _cbytes(block[0:100])
        prefix = _cbytes(block[345:500]) if posix else b''
        if prefix:
            name = prefix + b'/' + name
        link = _cbytes(block[157:257])
        if long_name is not None:
            name = long_name
        if long_link is not None:
            link = long_link
        pax = pax or {}
        name = pax.get('path', name)
        link = pax.get('linkpath', link)
        if typeflag == b'\0' and name.endswith(b'/'):
            typeflag = b'5'  # an old-style directory, as tarfile reads it
        return _Head(block, pax, name, link, typeflag, _pax_int(pax, 'size', size, bad))


# ====================================================================== outer tar

class _Outer:
    """Sequential reads of the outer tar with pread (position kept here)."""

    def __init__(self, fd, size):
        self.fd, self.size, self.pos = fd, size, 0

    def read_exact(self, n):
        if self.pos + n > self.size:
            raise _Truncated()
        data = _pread_exact(self.fd, self.pos, n)
        self.pos += n
        return data

    def skip(self, n):
        if self.pos + n > self.size:
            raise _Truncated()
        self.pos += n


def _pread_exact(fd, offset, n):
    parts, got = [], 0
    while got < n:
        buf = os.pread(fd, min(n - got, CHUNK), offset + got)
        if not buf:
            raise _Truncated()
        parts.append(buf)
        got += len(buf)
    return b''.join(parts)


def _outer_name(raw):
    """A flat member name without `./` prefixes, or None for a name that no member has (a path, blank, too long, with
    control characters): names are only compared, never written."""
    name = _text(raw)
    while name.startswith('./'):
        name = name[2:]
    if not name or name in ('.', '..') or '/' in name or len(name) > 255 or CONTROL_RE.search(name):
        return None
    return name


@dataclasses.dataclass(frozen=True)
class _Raw:
    name: str
    offset: int
    size: int


# What has data behind its header, like tarfile reads it: regular files (0, NUL, 7 "contiguous") and types it does not
# know; hard and symbolic links, devices, folders and FIFOs have none whatever their size field says.
OUTER_FILES = (b'0', b'\0', b'7')
OUTER_NO_DATA = (b'1', b'2', b'3', b'4', b'5', b'6', b'g')


def _walk_outer(fd, size, *, limit=MAX_OUTER_MEMBERS, ignored=None):
    """Yield every regular member with a flat name (_Raw) of the outer tar until its end-of-archive marker; everything
    else is stepped over (counted in `ignored`, an _Ignored)."""
    outer = _Outer(fd, size)
    count = 0
    try:
        while True:
            head = _read_head(outer, outer=True)
            if head is None:
                return
            count += 1
            if count > limit:
                raise _limit('too many members in the outer tar', limit=limit)
            if head.typeflag == b'S':
                raise _corrupt('sparse files are not supported')
            name = _outer_name(head.name) if head.typeflag in OUTER_FILES else None
            offset = outer.pos
            if head.typeflag not in OUTER_NO_DATA:
                outer.skip(head.size + (-head.size) % BLOCK)
            if name is not None:
                yield _Raw(name, offset, head.size)
            elif ignored is not None and head.typeflag != b'g':
                ignored.add('name' if head.typeflag in OUTER_FILES else 'not-a-file', _text(head.name))
    except _Truncated:
        raise _corrupt('the backup file is truncated') from None


def _fd_size(fd):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise _corrupt('not a regular file')
    return st.st_size


def _is_ha_doc(doc):
    """True for the JSON of an HA backup: it has `supervisor_version`, or (backups older than 2022.08 have none) what
    Supervisor requires of every one -- `slug`, `name`, `date`, `type` -- and not a Cockpit backup's `backup_id`."""
    if not isinstance(doc, dict):
        return False
    return 'supervisor_version' in doc or ('backup_id' not in doc and {'slug', 'name', 'date', 'type'} <= set(doc))


def _load_doc(fd, raw):
    """The strict JSON of a member; ValueError when it is not one."""
    return util.loads_strict(_pread_exact(fd, raw.offset, raw.size), max_bytes=MAX_BACKUP_JSON)


def looks_like_ha(fd):
    """True when the file is meant to be a Home Assistant backup: a member named backup.json (any `./` prefix) -- or, of
    a very old one, snapshot.json -- whose strict JSON is an HA backup's (_is_ha_doc). Never raises for other files
    (they go to the normal checks)."""
    try:
        size = _fd_size(fd)
        if size < 3 * BLOCK or os.pread(fd, 2, 0) == b'\x1f\x8b':
            return False
        old = None
        for raw in _walk_outer(fd, size):
            if raw.name == BACKUP_JSON:
                return raw.size <= MAX_BACKUP_JSON and _is_ha_doc(_load_doc(fd, raw))
            if raw.name == SNAPSHOT_JSON and old is None and raw.size <= MAX_BACKUP_JSON:
                old = raw
        return old is not None and _is_ha_doc(_load_doc(fd, old))
    except (BackupError, OSError, ValueError, _Truncated):
        return False


# ====================================================================== backup.json

def _need(cond, reason, **details):
    if not cond:
        raise _corrupt(reason, **details)


def _backup_version(value):
    """1 or 2, read like Supervisor's `vol.All(vol.Coerce(int), vol.In((1, 2)))`."""
    try:
        version = int(value) if isinstance(value, (int, float, str)) else None
    except (ValueError, OverflowError):
        version = None
    _need(version in (1, 2), 'backup.json version is not supported', version=clean_text(str(value)[:100], 20))
    return version


def _date(value):
    """The backup's date as UTC `...Z`, None when it cannot be read (display and sorting only)."""
    if not isinstance(value, str) or not 10 <= len(value) <= 64:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        text = util.iso_utc(parsed)
    except (ValueError, OverflowError):
        return None
    return text if util.is_iso_utc(text) else None


def _version_text(value):
    """A version as it may be shown: text cleaned and cut, a number as Supervisor's AwesomeVersion writes it."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    return clean_text(value, 64)


def _stems(addons, folders):
    """Member names (without `.tar[.gz]`) that a backup.json lists, and the two every backup may have."""
    stems = {'homeassistant', 'supervisor', *(addon['slug'] for addon in addons)}
    for folder in folders:
        stems.update(('apps_local', 'addons_local') if folder == 'apps/local' else (folder.replace('/', '_'),))
    return stems


def _compressed(value, stems, names):
    """Whether the members are `.tar.gz`: what backup.json says, else (absent or not a boolean) what the member names
    say, else Supervisor's default (true)."""
    if isinstance(value, bool):
        return value
    packed = sum(stem + '.tar.gz' in names for stem in stems)
    return packed > 0 or not any(stem + '.tar' in names for stem in stems)


def validate_doc(doc, names=frozenset()):
    """The schema subset of an HA backup.json (module notes) -> normalised dict; unknown keys are ignored. `names`: the
    member names of the file (only for a `compressed` that is missing)."""
    _need(isinstance(doc, dict), 'backup.json is not an object')
    version = _backup_version(doc.get('version', 1))
    _need(doc.get('type') in ('full', 'partial'), 'backup.json type is invalid')
    protected = doc.get('protected', False)
    addons = doc.get('addons', [])
    _need(isinstance(addons, list), 'backup.json addons must be a list')
    if len(addons) > MAX_ADDONS:
        raise _limit('too many add-ons in backup.json', limit=MAX_ADDONS)
    normal_addons, slugs = [], set()
    for item in addons:
        _need(isinstance(item, dict), 'backup.json addon is not an object')
        slug = item.get('slug')
        addon = {'slug': slug, 'name': clean_text(item.get('name'), 200), 'version': _version_text(item.get('version'))}
        if isinstance(slug, str) and ADDON_SLUG_RE.fullmatch(slug):
            _need(slug not in slugs, 'backup.json lists an add-on twice', slug=slug)
            slugs.add(slug)
            addon['name'] = addon['name'] or slug
        else:  # it cannot name a member: listed by its name, and only it is left out
            addon.update(slug=None, name=addon['name'] or clean_text(slug, 100) or '（沒有名稱的附加元件）',
                         problem='bad-slug')
        normal_addons.append(addon)
    number = 0
    for addon in normal_addons:
        while addon['slug'] is None:
            number += 1
            if f'invalid-{number}' not in slugs:
                addon['slug'] = f'invalid-{number}'
    folders = doc.get('folders', [])
    _need(isinstance(folders, list), 'backup.json folders must be a list')
    if len(folders) > MAX_FOLDERS:
        raise _limit('too many folders in backup.json', limit=MAX_FOLDERS)
    normal_folders = []
    for folder in folders:
        _need(isinstance(folder, str) and FOLDER_RE.fullmatch(folder), 'backup.json folder is invalid')
        if folder == V1_FOLDER:
            continue
        if folder in LEGACY_APPS_FOLDERS:
            folder = 'apps/local'
        _need(folder not in normal_folders, 'backup.json lists a folder twice', folder=folder)
        normal_folders.append(folder)
    homeassistant = doc.get('homeassistant')
    core = None
    if isinstance(homeassistant, dict) and homeassistant.get('version') is not None:
        core = {'version': _version_text(homeassistant['version'])}
    repositories = doc.get('repositories', [])
    _need(isinstance(repositories, list) and len(repositories) <= 500
          and all(isinstance(url, str) and len(url) <= 2048 for url in repositories),
          'backup.json repositories must be a list of text')
    _need(isinstance(doc.get('extra', {}), dict), 'backup.json extra must be an object')
    compressed = _compressed(doc.get('compressed'), _stems(normal_addons, normal_folders), names)
    return {'slug': clean_text(doc.get('slug'), 64), 'name': clean_text(doc.get('name'), 200),
            'date': _date(doc.get('date')), 'type': doc['type'], 'version': version,
            'supervisor_version': _version_text(doc.get('supervisor_version')),
            'protected': protected if isinstance(protected, bool) else True, 'compressed': compressed,
            'homeassistant': core, 'addons': normal_addons, 'folders': normal_folders}


# ====================================================================== describe

@dataclasses.dataclass(frozen=True)
class Member:
    """One inner tar of the outer file. `role`: addon | homeassistant | folder | supervisor; `slug`: the add-on slug
    (addon) or folder name (folder); `encryption`: none | v1 | v2 | v3 (from the member's first bytes); `problem`: why
    it is never opened (PROBLEMS), None when it can be."""
    name: str
    offset: int
    size: int
    role: str
    slug: str | None
    encryption: str
    compressed: bool
    problem: str | None = None

    @property
    def encrypted(self):
        return self.encryption != 'none'


class _Ignored:
    """What of the outer file is not a member: the count and the first SAMPLES of them as (kind, shown name) -- kinds:
    `name` (no flat name), `not-a-file`, `unlisted`, `second-folder` (the same folder under its old and new name)."""

    def __init__(self):
        self.count = 0
        self.samples = []

    def add(self, kind, name):
        self.count += 1
        if len(self.samples) < SAMPLES:
            self.samples.append((kind, shown_name(name)))


@dataclasses.dataclass(frozen=True)
class Layout:
    """A described HA backup: `doc` (validate_doc of backup.json: untrusted display data), `members` (inner tars in file
    order, also the ones with a problem), the file `size` and what was stepped over (`ignored_count`, `ignored`)."""
    doc: dict
    members: tuple
    size: int
    ignored_count: int = 0
    ignored: tuple = ()

    def member(self, name):
        for member in self.members:
            if member.name == name:
                return member
        raise BackupError('not-found', '這份 HA 備份沒有這個項目。', member=str(name)[:200])

    def addon(self, slug):
        for member in self.members:
            if member.role == 'addon' and member.slug == slug:
                return member
        listed = next((addon for addon in self.doc['addons'] if addon['slug'] == slug), None)
        if listed is not None:
            raise problem_error(slug, listed.get('problem', 'missing'))
        raise BackupError('not-found', '這份 HA 備份沒有這個附加元件。', slug=str(slug)[:100])

    def summary(self):
        """JSON-ready description: backup.json's fields plus, per add-on, its member, size, encryption and -- only when
        it cannot be read -- its `problem`."""
        doc = self.doc
        by_slug = {m.slug: m for m in self.members if m.role == 'addon'}
        addons = []
        for addon in doc['addons']:
            member = by_slug.get(addon['slug'])
            item = dict(addon, member=member.name if member else None, size=member.size if member else 0,
                        encryption=member.encryption if member else 'none')
            problem = addon.get('problem') or (member.problem if member else 'missing')
            if problem:
                item['problem'] = problem
            addons.append(item)
        return {
            'ha_slug': doc['slug'], 'name': doc['name'], 'date': doc['date'], 'type': doc['type'],
            'supervisor_version': doc['supervisor_version'], 'protected': doc['protected'],
            'compressed': doc['compressed'], 'homeassistant': dict(doc['homeassistant']) if doc['homeassistant'] else None,
            'addons': addons, 'folders': list(doc['folders']),
            'supervisor': any(m.role == 'supervisor' for m in self.members),
            'size': self.size,
        }


def _listed_members(doc):
    """{member name: (role, slug)} that backup.json lists (a folder may go by two names); supervisor's is optional. A
    name of Home Assistant's own parts is never an add-on's."""
    ext = '.tar.gz' if doc['compressed'] else '.tar'
    listed = {'supervisor' + ext: ('supervisor', None)}
    if doc['homeassistant'] is not None:
        listed['homeassistant' + ext] = ('homeassistant', None)
    for folder in doc['folders']:
        for stem in ('apps_local', 'addons_local') if folder == 'apps/local' else (folder.replace('/', '_'),):
            listed[stem + ext] = ('folder', folder)
    for addon in doc['addons']:
        if 'problem' not in addon:
            listed.setdefault(addon['slug'] + ext, ('addon', addon['slug']))
    return listed


def _member_state(fd, raw, protected, compressed):
    """(encryption, problem) of a member from its first bytes: it must be a whole encrypted file of a known kind or an
    inner tar of the declared kind."""
    head = os.pread(fd, min(raw.size, BLOCK), raw.offset)
    kind = hasecuretar.sniff(head)
    if kind == 'unsupported':
        return 'none', 'encryption-unsupported'
    if kind in ('v2', 'v3'):
        return (kind, None) if hasecuretar.ciphertext_ok(kind, raw.size, head) else ('none', 'size-mismatch')
    if kind == ('gzip' if compressed else 'tar'):
        return 'none', None
    if kind == 'unknown' and protected:
        return ('v1', None) if hasecuretar.ciphertext_ok('v1', raw.size, head) else ('none', 'partial-ciphertext')
    return 'none', 'not-an-archive'


def describe(fd):
    """The description (Layout) of the HA backup open at `fd`; raises corrupt-archive or limit-exceeded when the outer
    tar or backup.json cannot be used. Reads the headers, backup.json and each member's first 512 bytes only."""
    try:
        size = _fd_size(fd)
        if os.pread(fd, 2, 0) == b'\x1f\x8b':
            raise _corrupt('the outer file is compressed (HA backups are plain tar files)')
        ignored, raws = _Ignored(), {}
        for raw in _walk_outer(fd, size, ignored=ignored):
            raws.setdefault(raw.name, []).append(raw)  # in file order; a name may be there twice
        doc_name = BACKUP_JSON if BACKUP_JSON in raws else SNAPSHOT_JSON
        if doc_name not in raws:
            raise _corrupt('backup.json is missing')
        docs = raws.pop(doc_name)
        if len(docs) > 1:
            raise _corrupt('backup.json is in the file twice')
        if docs[0].size > MAX_BACKUP_JSON:
            raise _limit('backup.json too large', size=docs[0].size)
        try:
            doc = _load_doc(fd, docs[0])
        except ValueError:
            raise _corrupt('backup.json is not strict JSON') from None
        doc = validate_doc(doc, raws)
        listed = _listed_members(doc)
        members, folders = [], set()
        for name, found in raws.items():
            role, slug = listed.get(name, (None, None))
            if role is None:
                ignored.add('unlisted', name)
                continue
            if role == 'folder':
                if slug in folders:  # apps_local and addons_local both there: the first one
                    ignored.add('second-folder', name)
                    continue
                folders.add(slug)
            encryption, problem = 'none', 'duplicate'
            if len(found) == 1:
                encryption, problem = _member_state(fd, found[0], doc['protected'], doc['compressed'])
            members.append(Member(name, found[0].offset, found[0].size, role, slug, encryption, doc['compressed'],
                                  problem))
    except _Truncated:
        raise _corrupt('the backup file is truncated') from None
    return Layout(doc, tuple(members), size, ignored.count, tuple(ignored.samples))


# ====================================================================== member streams

class _Slice:
    """read(n) of bytes [offset, offset + size) of `fd` with pread."""

    def __init__(self, fd, offset, size):
        self.fd, self.pos, self.end = fd, offset, offset + size

    def read(self, n=CHUNK):
        n = min(n if n is not None and n >= 0 else CHUNK, self.end - self.pos, CHUNK)
        if n <= 0:
            return b''
        data = os.pread(self.fd, n, self.pos)
        if not data:  # the file was cut off after it was described: no member of it can be trusted any more
            error = _corrupt('the backup file is truncated')
            error.job_wide = True
            raise error
        self.pos += len(data)
        return data


class _Gunzip:
    """Streaming gzip (RFC 1952) reader with bounded output per read: own header parse, raw inflate, CRC32 and ISIZE
    checked at the end of every gzip member. A stream may hold several members one after the other and end in zero
    padding, as gzip(1) reads it; anything else behind a member is refused. `legacy` (a v1 member) is one gzip member
    and also accepts the trailer `pad | CRC | 0x0c * 12 | ISIZE` that securetar <= 2024.11 wrote (module notes)."""

    def __init__(self, src, *, legacy=False):
        self.src, self.legacy = src, legacy
        self._buf, self._off = b'', 0
        self._members = 0
        self._eof = False
        self._begin()

    def _begin(self):
        self._members += 1
        if self._members > MAX_GZIP_MEMBERS:
            raise _limit('too many gzip members', limit=MAX_GZIP_MEMBERS)
        self._inflate = zlib.decompressobj(-zlib.MAX_WBITS)
        self._crc = 0
        self._size = 0
        self._header()

    def _fill(self):
        """More input behind what is left of the buffer; False at the end of the source."""
        data = self.src.read(CHUNK)
        if data:
            self._buf, self._off = self._buf[self._off:] + data, 0
        return bool(data)

    def _take(self, n, reason='gzip stream is truncated'):
        while len(self._buf) - self._off < n:
            if not self._fill():
                raise _broken(reason)
        data = self._buf[self._off:self._off + n]
        self._off += n
        return data

    def _take_zero_terminated(self):
        parts, total = [], 0
        while True:
            end = self._buf.find(b'\0', self._off)
            part = self._buf[self._off:] if end < 0 else self._buf[self._off:end + 1]
            total += len(part)
            if total > MAX_GZIP_FIELD:
                raise _broken('gzip header field too long')
            parts.append(part)
            self._off += len(part)
            if end >= 0:
                return b''.join(parts)
            if not self._fill():
                raise _broken('gzip stream is truncated')

    def _header(self):
        fixed = self._take(10)
        if fixed[:3] != hasecuretar.GZIP_MAGIC:
            raise _broken('member data is not gzip')
        flags = fixed[3]
        if flags & 0xe0:
            raise _broken('gzip header has reserved flags')
        header = fixed
        if flags & 0x04:
            length = self._take(2)
            header += length + self._take(int.from_bytes(length, 'little'))
        if flags & 0x08:
            header += self._take_zero_terminated()
        if flags & 0x10:
            header += self._take_zero_terminated()
        if flags & 0x02:
            check = self._take(2)
            if int.from_bytes(check, 'little') != zlib.crc32(header) & 0xffff:
                raise _broken('gzip header checksum mismatch')

    def read(self, n=CHUNK):
        n = CHUNK if n is None or n < 0 else max(1, min(n, CHUNK))
        while not self._eof:
            if self._off >= len(self._buf) and not self._fill():
                raise _broken('gzip stream is truncated')
            piece = self._buf[self._off:self._off + GZIP_FEED]
            try:
                out = self._inflate.decompress(piece, n)
            except zlib.error:
                raise _broken('gzip data is invalid') from None
            left = self._inflate.unused_data if self._inflate.eof else self._inflate.unconsumed_tail
            self._off += len(piece) - len(left)
            if out:
                self._crc = zlib.crc32(out, self._crc)
                self._size += len(out)
            if self._inflate.eof:
                self._member_end()
            if out:
                return out
        return b''

    def _member_end(self):
        """After a member's deflate data: its trailer, then the end of the stream, zero padding or the next member."""
        if self.legacy:
            self._legacy_trailer()
            self._eof = True
            return
        trailer = self._take(8, 'gzip trailer is invalid')
        self._verify(trailer[:4], trailer[4:])
        while True:
            rest = self._buf[self._off:self._off + GZIP_FEED]
            zeros = len(rest) - len(rest.lstrip(b'\0'))
            self._off += zeros
            if zeros < len(rest):
                break
            if not rest and not self._fill():
                self._eof = True
                return
        while len(self._buf) - self._off < len(hasecuretar.GZIP_MAGIC) and self._fill():
            pass
        if not self._buf.startswith(hasecuretar.GZIP_MAGIC, self._off):
            raise _broken('data after the gzip stream')
        self._begin()

    def _legacy_trailer(self):
        while len(self._buf) - self._off <= MAX_GZIP_TRAILER and self._fill():
            pass
        rest = self._buf[self._off:]
        if len(rest) > MAX_GZIP_TRAILER:
            raise _broken('data after the gzip stream')
        pad = len(rest) - 20
        if len(rest) == 8:
            self._verify(rest[:4], rest[4:])
        elif 0 <= pad <= 15 and rest[:pad] == bytes([pad]) * pad and rest[pad + 4:pad + 16] == b'\x0c' * 12:
            self._verify(rest[pad:pad + 4], rest[pad + 16:])
        else:
            raise _broken('gzip trailer is invalid')

    def _verify(self, crc, size):
        if int.from_bytes(crc, 'little') != self._crc or int.from_bytes(size, 'little') != self._size & 0xffffffff:
            raise _broken('gzip checksum mismatch')

    def finish(self):
        while self.read(CHUNK):
            pass


class MemberStream(io.RawIOBase):
    """Plaintext (a tar stream) of one inner tar: decrypted when the member is encrypted, gunzipped when compressed.
    `finish()` reads the rest and runs every final check (a member that is neither has none: nothing after its tar's end
    is read); `close()` releases it (and the file when it owns it). `reopen()` is another stream of the same member from
    its start (on the same descriptor, so it must be closed first)."""

    def __init__(self, fd, member, keys=None, *, owns_fd=False):
        super().__init__()
        self.member = member
        self._fd = fd if owns_fd else None
        self._source_fd, self._keys = fd, keys
        self._decrypt = None
        try:
            if member.problem is not None:
                raise problem_error(member.name, member.problem)
            source = _Slice(fd, member.offset, member.size)
            if member.encrypted:
                if keys is None:
                    raise hasecuretar.key_required(member=member.name)
                self._decrypt = hasecuretar.DecryptReader(source, member.size, keys, name=member.name)
                source = self._decrypt
            self._gunzip = _Gunzip(source, legacy=member.encryption == 'v1') if member.compressed else None
            self._top = self._gunzip or source
        except BaseException:
            self.close()
            raise

    def reopen(self):
        return MemberStream(self._source_fd, self.member, self._keys)

    @property
    def checked_to_the_end(self):
        """True when `finish()` has something to check (a gzip trailer, the encryption's final tag or padding)."""
        return self._gunzip is not None or self._decrypt is not None

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self._top.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def finish(self):
        if self._gunzip is not None:
            self._gunzip.finish()
        if self._decrypt is not None:
            self._decrypt.finish()

    def close(self):
        if not self.closed:
            decrypt = getattr(self, '_decrypt', None)
            if decrypt is not None:
                decrypt.close()
            fd = getattr(self, '_fd', None)
            if fd is not None:
                self._fd = None
                os.close(fd)
        super().close()


def _open_ro(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        raise BackupError('not-found', '找不到 HA 備份檔。') from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise _corrupt('the backup file is a symbolic link') from None
        raise
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
        _fd_size(fd)
    except BaseException:
        os.close(fd)
        raise
    return fd


class HaBackup:
    """An HA backup file open for reading: `layout` (described at open) and its members' plaintext streams (a member
    with a problem never opens: problem_error). Use as a context manager; streams opened from it must be closed before
    it."""

    def __init__(self, path):
        self.fd = _open_ro(path)
        try:
            self.layout = describe(self.fd)
        except BaseException:
            os.close(self.fd)
            raise

    def open_member(self, name, keys=None):
        """MemberStream of the member called `name` (key-required without `keys` when it is encrypted)."""
        return MemberStream(self.fd, self.layout.member(name), keys)

    def open_addon(self, slug, keys=None):
        return MemberStream(self.fd, self.layout.addon(slug), keys)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def open_backup(path):
    """HaBackup of the file at `path` (O_NOFOLLOW; described at open)."""
    return HaBackup(path)


def open_member(path, name, *, keys=None, password=None):
    """MemberStream of one member that owns its file descriptor (closing the stream closes the file). `password` is a
    shortcut for `keys=hasecuretar.Keys(password)`; share one Keys per backup when reading several members (v3 runs
    Argon2id once per Keys)."""
    if keys is None and password is not None:
        keys = hasecuretar.Keys(password)
    fd = _open_ro(path)
    try:
        member = describe(fd).member(name)
    except BaseException:
        os.close(fd)
        raise
    return MemberStream(fd, member, keys, owns_fd=True)  # closes the descriptor itself when it fails


# ====================================================================== add-on metadata

@dataclasses.dataclass(frozen=True)
class AddonInfo:
    """What Cockpit uses of an add-on's addon.json: `slug` = system.slug (e.g. odoo18ce, woow-n8n; identifies the app
    whatever repository prefix the backup slug has), `version` (installed add-on version), `image` (user.image, e.g.
    ghcr.io/woowtech/woow-ha-odoo-amd64; None when the add-on was built locally), `arch` (amd64 | aarch64 | unknown,
    from the image name), `name` (system.name) and `state` (the add-on's state when the backup began, e.g. `started`:
    with a hot backup mode its files were copied while it ran; '' when absent). Options, passwords and tokens are never
    kept."""
    slug: str
    version: str
    image: str | None
    arch: str
    name: str
    state: str = ''

    def as_dict(self):
        return dataclasses.asdict(self)


def image_arch(image):
    """amd64 | aarch64 | unknown from an image reference's last path component (`...-amd64`, `amd64-...`, any tag)."""
    if not isinstance(image, str) or not image:
        return 'unknown'
    last = image.split('@', 1)[0].rsplit('/', 1)[-1].split(':', 1)[0].lower()
    for arch in ('amd64', 'aarch64'):
        if last.endswith('-' + arch) or last.startswith(arch + '-'):
            return arch
    return 'unknown'


def parse_addon_json(data):
    """AddonInfo of addon.json bytes (strict JSON <= 32 MiB); corrupt-archive when it is not an add-on's metadata. A
    version that is not one is '' (the importers then read it from the data, CM-01), an image name that is not one None
    (an unknown processor), a name that cannot be shown ''."""
    if len(data) > MAX_ADDON_JSON:
        raise _limit('addon.json too large', size=len(data))
    try:
        doc = util.loads_strict(data, max_bytes=MAX_ADDON_JSON)
    except ValueError:
        raise _broken('addon.json is not strict JSON') from None
    if not isinstance(doc, dict) or not isinstance(doc.get('system'), dict):
        raise _broken('addon.json has no system section')
    system = doc['system']
    user = doc.get('user') if isinstance(doc.get('user'), dict) else {}
    slug = system.get('slug')
    if not isinstance(slug, str) or not SYSTEM_SLUG_RE.fullmatch(slug):
        raise _broken('addon.json system.slug is invalid')
    version = doc.get('version', user.get('version'))
    version = version if isinstance(version, str) and VERSION_RE.fullmatch(version) else ''
    image = user.get('image')
    image = image if isinstance(image, str) and IMAGE_RE.fullmatch(image) else None
    state = doc.get('state')
    state = state if isinstance(state, str) and re.fullmatch(r'[a-z]{1,20}', state) else ''
    return AddonInfo(slug=slug, version=version, image=image, arch=image_arch(image),
                     name=clean_text(system.get('name'), 200), state=state)


# ====================================================================== inner tar entries

@dataclasses.dataclass(frozen=True)
class Select:
    """Which entries of an inner tar a caller wants (normalised names, e.g. `data/postgres`; a prefix selects itself
    and everything below it). `include` None = everything, () = nothing; `exclude` wins over `include` (what lies there
    is not handed out for a hard link elsewhere either). `symlinks`: prefixes below which a selected symlink is handed
    out when its target is relative and, resolved from the link's directory, stays inside that prefix (other symlinks
    are skipped and counted). `absolute_symlinks`: absolute target prefixes (e.g. `/opt/data`) for which a symlink below
    a `symlinks` area is handed out too, when its target is clean (`_absolute_ok`); () = never. `hardlinks`: the caller
    takes hard links: a selected one that names an earlier selected regular file is handed out as `hardlink`; every
    other selected one (all of them when False) as a regular `file` with that file's content, after the walk
    (`_copy_links`). Budgets: `max_members` entries in the whole tar, `max_bytes` bytes of selected regular files (the
    copies count)."""
    include: tuple | None = None
    exclude: tuple = ()
    symlinks: tuple = ()
    hardlinks: bool = False
    max_members: int = DEFAULT_MAX_MEMBERS
    max_bytes: int = DEFAULT_MAX_BYTES
    absolute_symlinks: tuple = ()

    def excludes(self, name):
        return any(_under(name, prefix) for prefix in self.exclude)

    def wants(self, name):
        if self.excludes(name):
            return False
        return self.include is None or any(_under(name, prefix) for prefix in self.include)

    def area(self, name):
        """The `include` prefix a selected name lies in ('' when everything is selected)."""
        return next((prefix for prefix in self.include or () if _under(name, prefix)), '')

    def symlink_root(self, name):
        return next((prefix for prefix in self.symlinks if _under(name, prefix) and name != prefix), None)


def _under(name, prefix):
    return name == prefix or name.startswith(prefix + '/') or prefix == '.'


# Why a selected entry was not handed out (Report.skips), as the customer reads it (with the number in front).
SKIP_KINDS = {
    'name': '檔名空白、太長或含控制字元的項目',
    'device': '裝置檔',
    'fifo': '特殊檔案（FIFO）',
    'secret': '佔用機密檔位置的連結或資料夾',
    'symlink': '指到資料以外的符號連結',
    'hardlink': '找不到內容的硬連結',
    'large': '大小超出上限的設定檔',
}


class SkipList:
    """The skipped entries of one kind, without keeping them all: how many (`count`), the first SAMPLES names as they may
    be shown (`first`) and, for a confirmation's key, what stands for every one of them (`key_items`: the names up to
    MAX_KEPT_NAMES, above that their number and an order-independent digest). The interface of haissues.Names."""

    def __init__(self):
        self.count = 0
        self.first = []
        self._names = []
        self._sum = 0

    def add(self, name):
        self.count += 1
        if len(self.first) < SAMPLES:
            self.first.append(name)
        if self.count <= MAX_KEPT_NAMES:
            self._names.append(name)
        digest = hashlib.sha256(name.encode('utf-8', 'surrogatepass')).digest()
        self._sum = (self._sum + int.from_bytes(digest, 'big')) % (1 << 256)

    def __len__(self):
        return self.count

    def key_items(self):
        if self.count <= MAX_KEPT_NAMES:
            return tuple(self._names)
        return (f'count={self.count}', f'sum={self._sum:064x}')


class Report:
    """What a walk saw: counts of entries handed out, bytes, what was skipped (`skips`; symlinks outside the allowed
    areas, FIFOs and NEVER_READ files also in the older counters) and the add-on's AddonInfo (`addon`, from
    addon.json). `names`: what keeps the names of one kind in `skips` (SkipList; an importer passes haissues.Names and
    hands `skips[kind]` to its confirmation as it is)."""

    def __init__(self, names=SkipList):
        self.entries = 0            # every entry of the tar
        self.files = self.dirs = self.symlinks = self.hardlinks = 0   # handed out
        self.bytes = 0              # bytes of the regular files handed out
        self.copied_links = 0       # of the files: hard links handed out with the content of the file they name
        self.skipped_symlinks = 0
        self.skipped_symlink_samples = []   # the first SAMPLES of every selected area (Select.area)
        self.absolute_symlinks = 0  # handed out with an absolute target (Select.absolute_symlinks)
        self.skipped_other = 0      # FIFOs (no data)
        self.secret_files = 0       # NEVER_READ entries skipped unread
        self.skips = {}             # {kind of SKIP_KINDS: the names}
        self.addon = None           # AddonInfo
        self.complete = False       # the end of the tar and every final check of the stream passed
        self._areas = {}
        self._new_names = names

    def skip(self, kind, name):
        if kind not in self.skips:
            self.skips[kind] = self._new_names()
        self.skips[kind].add(shown_name(name))

    def _skip_symlink(self, name, area):
        self.skip('symlink', name)
        self.skipped_symlinks += 1
        if self._areas.setdefault(area, 0) < SAMPLES:
            self._areas[area] += 1
            self.skipped_symlink_samples.append(name[:200])

    def _kinds(self, kinds):
        return [kind for kind in SKIP_KINDS if kind in self.skips and (not kinds or kind in kinds)]

    def skip_count(self, *kinds):
        """How many selected entries were not handed out (of these kinds; all when none is named)."""
        return sum(self.skips[kind].count for kind in self._kinds(kinds))

    def skip_names(self, *kinds):
        """Their names as they may be shown: the first SAMPLES of every kind, in the tar's order."""
        return [name for kind in self._kinds(kinds) for name in self.skips[kind].first]

    def skip_text(self, *kinds):
        """「裝置檔 2 個、…」 ('' when nothing was skipped)."""
        return '、'.join(f'{SKIP_KINDS[kind]} {self.skips[kind].count} 個' for kind in self._kinds(kinds))

    def warnings(self):
        """zh-TW notes for a job log."""
        notes = []
        if self.skipped_symlinks:
            notes.append(f'HA 備份中有 {self.skipped_symlinks} 個符號連結沒有搬過來（例如 '
                         f'{"、".join(shown_name(name) for name in self.skipped_symlink_samples[:5])}）。')
        if self.skipped_other:
            notes.append(f'HA 備份中有 {self.skipped_other} 個特殊檔案（FIFO）沒有搬過來。')
        for kind in self._kinds(set(SKIP_KINDS) - {'symlink', 'fifo'}):
            skipped = self.skips[kind]
            notes.append(f'HA 備份中有 {skipped.count} 個{SKIP_KINDS[kind]}沒有搬過來（例如 '
                         f'{"、".join(skipped.first[:5])}）。')
        return notes


class Entry:
    """One entry of an inner tar handed out by iter_entries: `name` (normalised), `kind` (file | dir | symlink |
    hardlink), `mode` (permission bits), `uid`, `gid`, `size` (regular files), `mtime`, `linkname` (symlink target as
    stored / hard link target normalised) and `fileobj` (itself for a regular file, else None). A file's data can be
    read only until the walk moves on (`peek`, `read`, `readinto`, `read_all`, `read_or_skip`, `copy_to`)."""

    __slots__ = ('name', 'kind', 'mode', 'uid', 'gid', 'size', 'mtime', 'linkname', '_reader', '_left', '_head',
                 '_report', '_copy')

    def __init__(self, name, kind, mode, uid, gid, size, mtime, linkname, reader, report=None):
        self.name, self.kind, self.mode, self.uid, self.gid = name, kind, mode, uid, gid
        self.size, self.mtime, self.linkname = size, mtime, linkname
        self._reader = reader if kind == 'file' else None
        self._left = size if kind == 'file' else 0
        self._head = b''
        self._report = report
        self._copy = False

    @property
    def fileobj(self):
        return self if self.kind == 'file' else None

    def read(self, n=CHUNK):
        if self._reader is None:
            if self.kind == 'file':
                raise ValueError('the entry data is no longer available (the walk moved on)')
            return b''
        n = CHUNK if n is None or n < 0 else n
        if self._head:
            data, self._head = self._head[:n], self._head[n:]
            return data
        return self._next(n)

    def _next(self, n):
        n = min(n, self._left, CHUNK)
        if n <= 0:
            return b''
        try:
            data = self._reader.read_some(n)
        except _Truncated:
            raise _broken('the inner tar is truncated', member=shown_name(self.name)) from None
        self._left -= len(data)
        return data

    def peek(self, n):
        """The first `n` bytes of a regular file (fewer when it is shorter); `read` still starts at the beginning."""
        if self._reader is None:
            return b''
        while len(self._head) < n:
            data = self._next(n - len(self._head))
            if not data:
                break
            self._head += data
        return self._head[:n]

    def readinto(self, buffer):
        data = self.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def read_all(self, max_bytes):
        """The whole file (limit-exceeded when it is larger than `max_bytes`)."""
        if self.size > max_bytes:
            raise _limit('file too large to read', member=shown_name(self.name), size=self.size)
        parts = []
        while True:
            data = self.read(CHUNK)
            if not data:
                return b''.join(parts)
            parts.append(data)

    def read_or_skip(self, max_bytes):
        """The whole file, or None when it is larger than `max_bytes`: such a file counts as not there and is listed
        (Report.skips `large`), instead of stopping the whole app."""
        if self.size > max_bytes:
            if self._report is not None:
                self._report.skip('large', self.name)
            return None
        return self.read_all(max_bytes)

    def copy_later(self):
        """For a `hardlink`: the caller does not keep the file it names. The same name is handed out again after the
        walk as a regular `file` with that file's content (Select.hardlinks)."""
        self._copy = self.kind == 'hardlink'

    def copy_to(self, out, chunk=CHUNK):
        """Write the rest of the file to `out` (write(bytes)); returns the bytes copied."""
        total = 0
        while True:
            data = self.read(chunk)
            if not data:
                return total
            out.write(data)
            total += len(data)

    def _release(self):
        reader, left = self._reader, self._left
        self._reader, self._left = None, 0
        if reader is not None and left:
            reader.skip(left)


class _Reader:
    """Buffered sequential reads of a plaintext tar stream (any object with read(n)); an offset into the current
    buffer instead of deleting from its front keeps every read proportional to its own size."""

    def __init__(self, stream, *, checkpoint=None, max_bytes=None):
        self.stream = stream
        self.buf = b''
        self.off = 0
        self.eof = False
        self.checkpoint = checkpoint
        self.max_bytes = max_bytes
        self.consumed = 0
        self._next_check = CHECK_BYTES

    def _avail(self):
        return len(self.buf) - self.off

    def _fill(self, n):
        if self._avail() >= n:
            return
        parts = [self.buf[self.off:]]
        have = len(parts[0])
        while have < n and not self.eof:
            data = self.stream.read(CHUNK)
            if not data:
                self.eof = True
                break
            parts.append(data)
            have += len(data)
            self.consumed += len(data)
            if self.max_bytes is not None and self.consumed > self.max_bytes:
                raise _limit('the add-on archive inflates too much', limit=self.max_bytes)
            if self.consumed >= self._next_check:
                self._next_check = self.consumed + CHECK_BYTES
                if self.checkpoint is not None:
                    self.checkpoint()
        self.buf, self.off = b''.join(parts), 0

    def read_exact(self, n):
        self._fill(n)
        if self._avail() < n:
            raise _Truncated()
        data = self.buf[self.off:self.off + n]
        self.off += n
        return data

    def read_some(self, n):
        if not self._avail():
            self._fill(1)
            if not self._avail():
                raise _Truncated()
        n = min(n, self._avail())
        data = self.buf[self.off:self.off + n]
        self.off += n
        return data

    def skip(self, n):
        while n:
            if not self._avail():
                self._fill(1)
                if not self._avail():
                    raise _Truncated()
            step = min(n, self._avail())
            self.off += step
            n -= step

    def drain(self):
        """Read and drop the rest of the stream (within the budget, cancellable)."""
        while not self.eof:
            self.buf, self.off = b'', 0
            self._fill(1)
        self.buf, self.off = b'', 0

    def another_header(self):
        """True when a tar header stands at one of the next blocks (read and dropped, within the budget)."""
        while True:
            self._fill(BLOCK)
            end = self.off + self._avail() // BLOCK * BLOCK
            if end == self.off:
                return False
            at = self.buf.find(b'ustar', self.off, end)
            while at >= 0:
                head = at - TAR_MAGIC_AT
                if head >= self.off and (head - self.off) % BLOCK == 0 and _checksum_ok(self.buf[head:head + BLOCK]):
                    return True
                at = self.buf.find(b'ustar', at + 1, end)
            self.off = end


class _Held:
    """A file's data in memory, read like from a _Reader (a hard link's copy)."""

    def __init__(self, data):
        self.data, self.off = data, 0

    def read_some(self, n):
        data = self.data[self.off:self.off + n]
        self.off += len(data)
        return data

    def skip(self, n):
        self.off += n


@dataclasses.dataclass
class _Header:
    name: str
    typeflag: bytes
    mode: int
    uid: int
    gid: int
    size: int
    mtime: float
    linkname: str


def _inner_header(reader):
    """The next entry's header (PAX / GNU long name records applied) or None at the end-of-archive marker."""
    head = _read_head(reader)
    if head is None:
        return None
    block, pax = head.block, head.pax
    return _Header(name=_text(head.name), typeflag=head.typeflag, mode=_number(block[100:108], _broken) & 0o7777,
                   uid=_pax_int(pax, 'uid', _number(block[108:116], _broken), _broken),
                   gid=_pax_int(pax, 'gid', _number(block[116:124], _broken), _broken), size=head.size,
                   mtime=_pax_time(pax, 'mtime', _number(block[136:148], _broken), _broken), linkname=_text(head.link))


KINDS = {b'0': 'file', b'\0': 'file', b'5': 'dir', b'2': 'symlink', b'1': 'hardlink', b'6': 'fifo', b'3': 'device',
         b'4': 'device'}


def _entry_name(name):
    """(normalised name, flaw) of an entry. Refuses (corrupt-archive) a name that could lead outside: absolute, or with
    an empty, `.` or `..` component (leading `./` and one trailing slash are dropped, "." is the root). `flaw`: None, or
    why no file can have this name -- `blank`, `long` (over 4096 bytes), `control` (control characters); such an entry
    is skipped and listed."""
    if not name:
        return '', 'blank'
    if name.startswith('/'):
        raise _broken('absolute entry name', member=shown_name(name))
    parts = name.split('/')
    first = 0
    while first < len(parts) and parts[first] == '.':
        first += 1
    last = len(parts) - (parts[-1] == '' and len(parts) > first)
    parts = parts[first:last]
    if not parts:
        return '.', None
    if any(part in ('', '.', '..') for part in parts):
        raise _broken('entry name with an empty, "." or ".." component', member=shown_name(name))
    joined = '/'.join(parts)
    if len(joined.encode(ENCODING, ERRORS)) > MAX_NAME:
        return joined, 'long'
    return joined, 'control' if CONTROL_RE.search(joined) else None


def normalize(name):
    """Relative entry name without `./` prefixes or a trailing slash ("." for the root); corrupt-archive for empty,
    absolute, `..`, `.` or empty components, control characters or names longer than 4096 bytes."""
    joined, flaw = _entry_name(name) if isinstance(name, str) else ('', 'blank')
    if flaw is not None:
        raise _broken('entry name has control characters' if flaw == 'control' else 'invalid entry name',
                      member=shown_name(joined))
    return joined


def _link_target(name):
    """The normalised name a hard link gives, None when it cannot be an entry's."""
    try:
        return _entry_name(name)[0] or None
    except BackupError:
        return None


def never_read(name):
    """True for a NEVER_READ name and for everything below one."""
    if name in NEVER_READ:
        return True
    at = name.find('/')
    for _ in range(NEVER_READ_DEPTH + 1):
        if at < 0:
            return False
        if name[:at] in NEVER_READ:
            return True
        at = name.find('/', at + 1)
    return False


def _symlink_ok(name, target, root):
    """A relative target that, resolved from the link's directory, stays inside `root` ('.': the whole tar), and whose
    `..` components all come before its names (review HA-SEC-03). A `..` after a name could climb through another link
    of the archive (`a -> .`, then `b -> a/..` is lexically inside but really one folder up, and so on, in any order
    of the entries). The link's own folders are real directories (nothing may lie below a link), so leading `..`
    resolve exactly, and the names after them only go down: a chain of such links never leaves `root`."""
    if not target or '\x00' in target or target.startswith('/') or len(target) > MAX_NAME:
        return False
    named = False
    for part in target.split('/'):
        if part in ('', '.'):
            continue
        if part != '..':
            named = True
        elif named:
            return False
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name) or '.', target))
    if root == '.':
        return not (resolved == '..' or resolved.startswith('../'))
    return resolved == root or resolved.startswith(root + '/')


def _absolute_ok(target, prefixes):
    """An absolute target below one of `prefixes` without an empty, `.` or `..` component and without control
    characters (at most MAX_NAME bytes). Joined below any folder of the volume it stays inside (nested._escapes), and
    nothing on this device ever follows it: inside the app's container it names the container's own path."""
    if not prefixes or not isinstance(target, str) or not target.startswith('/') or CONTROL_RE.search(target):
        return False
    if len(target.encode(ENCODING, ERRORS)) > MAX_NAME:
        return False
    parts = target.split('/')[1:]
    if not parts or any(part in ('', '.', '..') for part in parts):
        return False
    return any(target == prefix or target.startswith(prefix.rstrip('/') + '/') for prefix in prefixes)


class _Names:
    """Order-aware structure rules for every entry: no duplicates, nothing below a non-directory, no non-directory
    where a directory was implied. Names are kept as keyed 64-bit digests in an open-addressing table, 9 bytes per slot
    and at most half full (about 18 bytes per name): four million entries take some 75 MB. A collision -- at that size
    less than one in 100000, and not steerable because the key is random -- can only refuse an archive, never accept a
    wrong one."""

    DIR, FILE, SYMLINK, HARDLINK, FIFO, DEVICE, IMPLIED = range(1, 8)
    KIND = {'dir': DIR, 'file': FILE, 'symlink': SYMLINK, 'hardlink': HARDLINK, 'fifo': FIFO, 'device': DEVICE}
    HANDED_OUT = 0x10               # a regular file the caller got

    def __init__(self, limit):
        self.key = secrets.token_bytes(16)
        self.limit = limit          # names it may hold: entries and the folders they imply
        self.used = 0
        self.parent = None          # the folder whose chain was checked last (its members usually follow each other)
        self._table(1 << 10)

    def _table(self, slots):
        self.mask = slots - 1
        self.keys = array.array('Q', (0,)) * slots
        self.states = bytearray(slots)

    def digest(self, name):
        return int.from_bytes(hashlib.blake2b(name.encode(ENCODING, ERRORS), digest_size=8, key=self.key).digest(),
                              'little')

    def _find(self, key):
        """The slot of `key`, or the empty one where it belongs."""
        at, mask, keys, states = key & self.mask, self.mask, self.keys, self.states
        while states[at] and keys[at] != key:
            at = (at + 1) & mask
        return at

    def _put(self, key, state):
        if self.used >= self.limit:
            raise _limit('too many names in an inner tar', limit=self.limit)
        if 2 * (self.used + 1) > self.mask + 1:
            keys, states = self.keys, self.states
            self._table(2 * (self.mask + 1))
            for at, old in enumerate(states):
                if old:
                    slot = self._find(keys[at])
                    self.keys[slot], self.states[slot] = keys[at], old
        at = self._find(key)
        self.keys[at], self.states[at] = key, state
        self.used += 1

    def _folders(self, parent):
        """`parent` and every folder above it must be folders (implied when they have no entry yet)."""
        parts = parent.split('/')
        for depth in range(1, len(parts) + 1):
            key = self.digest('/'.join(parts[:depth]))
            state = self.states[self._find(key)]
            if not state:
                self._put(key, self.IMPLIED)
            elif state not in (self.DIR, self.IMPLIED):
                raise _broken('entry below a file or link', member=shown_name(parent))

    def admit(self, name, kind):
        key = self.digest(name)
        state = self.states[self._find(key)]
        if state and state != self.IMPLIED:
            raise _broken('duplicate entry', member=shown_name(name))
        if state and kind != 'dir':
            raise _broken('a non-directory replaces a directory', member=shown_name(name))
        parent = name.rpartition('/')[0]
        if parent and parent != self.parent:
            self._folders(parent)
            self.parent = parent
        if state:
            self.states[self._find(key)] = self.DIR
        else:
            self._put(key, self.KIND[kind])
        return key

    def hand_out(self, key):
        self.states[self._find(key)] |= self.HANDED_OUT

    def handed_out(self, key):
        return self.states[self._find(key)] == self.FILE | self.HANDED_OUT


@dataclasses.dataclass
class _Link:
    """A hard link that waits for the end of the walk (its name is admitted; `key`: its target's digest; `copy`: the
    caller wants the content, not the link)."""
    name: str
    target: str
    key: int
    mode: int
    uid: int
    gid: int
    mtime: float
    copy: bool = False


class _Links:
    """The hard links of a walk: the ones that wait, and what every one names (a link may name another link)."""

    def __init__(self):
        self.waiting = []
        self.targets = {}

    def note(self, key, target):
        if len(self.targets) < MAX_LINK_COPIES:
            self.targets[key] = target

    def wait(self, link, report):
        if len(self.waiting) < MAX_LINK_COPIES:
            self.waiting.append(link)
        else:
            report.skip('hardlink', link.name)

    def resolve(self, key):
        for _ in range(8):
            if key not in self.targets:
                break
            key = self.targets[key]
        return key


def inflate_budget(stream):
    """Bytes the tar of a MemberStream may inflate to (None for other streams)."""
    member = getattr(stream, 'member', None)
    size = getattr(member, 'size', None)
    if not isinstance(size, int) or isinstance(size, bool):
        return None
    return max(INFLATE_FLOOR, INFLATE_RATIO * size)


def _start(stream):
    """Where a stream that cannot be reopened, but is seekable, starts (None: there is no second pass)."""
    try:
        return stream.tell() if not hasattr(stream, 'reopen') and stream.seekable() else None
    except (AttributeError, OSError, ValueError):
        return None


def _reopen(stream, start):
    """The same plaintext from its start, or None."""
    if hasattr(stream, 'reopen'):
        return stream.reopen()
    if start is None:
        return None
    stream.seek(start)
    return stream


def iter_entries(stream, select=None, report=None, *, addon=None, until_addon=False, checkpoint=None):
    """Walk the plaintext tar `stream` (a MemberStream or any object with read(n)) and yield the selected entries
    (Entry) in order, then the hard links that come as files (`_copy_links`); see Select for symlinks, hard links and
    budgets and the module notes for what is skipped, what stops the walk and what is never handed out. The first
    end-of-archive block ends the tar; what follows is only read (within the budget) for the checks of
    `stream.finish()` or, without any, to see that the tar does not go on. `report.complete` is True only after the last
    entry. A caller that stops early skips those checks. `addon`: the tar is an add-on's (its top-level addon.json is
    metadata, parsed into `report.addon`, never handed out); None = a MemberStream's member role, True for other
    streams. `until_addon`: stop as soon as addon.json was read (read_addon_info). `checkpoint`: called every
    CHECK_ENTRIES headers and CHECK_BYTES read (a cancel stops the walk also where nothing is selected); a MemberStream
    may inflate to inflate_budget() bytes (HA-SEC-05)."""
    select = select or Select()
    report = report if report is not None else Report()
    if addon is None:
        member = getattr(stream, 'member', None)
        addon = getattr(member, 'role', 'addon') == 'addon'
    start = _start(stream)
    reader = _Reader(stream, checkpoint=checkpoint, max_bytes=inflate_budget(stream))
    names = _Names(2 * select.max_members)
    links = _Links()
    try:
        while True:
            header = _inner_header(reader)
            if header is None:
                break
            report.entries += 1
            if report.entries > select.max_members:
                raise _limit('too many entries in an inner tar', limit=select.max_members)
            if checkpoint is not None and report.entries % CHECK_ENTRIES == 0:
                checkpoint()
            name, flaw = _entry_name(header.name)
            kind = KINDS.get(header.typeflag)
            if kind is None:
                code = header.typeflag.decode('latin-1')
                raise _broken('entry type not allowed (sparse, contiguous or unknown)', member=shown_name(name),
                              type=code)
            if kind != 'file' and header.size:
                raise _broken('a non-file entry carries data', member=shown_name(name))
            if name == '.' and kind != 'dir':
                raise _broken('the root entry is not a directory')
            padded = header.size + (-header.size) % BLOCK
            key = names.admit(name, kind) if flaw in (None, 'control') else None
            if never_read(name):
                if kind == 'file':
                    report.secret_files += 1
                elif name in NEVER_READ and select.wants(name):
                    report.skip('secret', name)
                reader.skip(padded)
                continue
            if addon and name == ADDON_JSON:
                if kind != 'file':
                    raise _broken('unexpected entry type for a metadata file', member=name)
                if header.size > MAX_ADDON_JSON:
                    raise _limit('addon.json too large', size=header.size)
                report.addon = parse_addon_json(reader.read_exact(header.size))
                reader.skip((-header.size) % BLOCK)
                if until_addon:
                    return
                continue
            target = target_key = None
            if kind == 'hardlink':
                target = _link_target(header.linkname)
                target_key = names.digest(target) if target is not None else None
                if key is not None and target is not None:
                    links.note(key, target_key)
            wanted = select.wants(name) if flaw != 'blank' else select.include != ()
            if flaw is not None or not wanted:
                if wanted:
                    report.skip('name', name)
                reader.skip(padded)
                continue
            if kind in ('fifo', 'device'):
                report.skipped_other += kind == 'fifo'
                report.skip(kind, name)
                continue
            linkname = None
            if kind == 'symlink':
                root = select.symlink_root(name)
                absolute = root is not None and _absolute_ok(header.linkname, select.absolute_symlinks)
                if root is None or not (absolute or _symlink_ok(name, header.linkname, root)):
                    report._skip_symlink(name, select.area(name))
                    continue
                if absolute:
                    report.absolute_symlinks += 1
                linkname = header.linkname
            elif kind == 'hardlink':
                if target is None:
                    report.skip('hardlink', name)
                    continue
                link = _Link(name, target, target_key, header.mode, header.uid, header.gid, header.mtime)
                if not select.hardlinks or not names.handed_out(target_key):
                    links.wait(link, report)
                    continue
                linkname = target
            elif kind == 'file':
                if report.bytes + header.size > select.max_bytes:
                    raise _limit('the selected files are too large', limit=select.max_bytes)
                report.bytes += header.size
                names.hand_out(key)
            setattr(report, f'{kind}s', getattr(report, f'{kind}s') + 1)
            entry = Entry(name, kind, header.mode, header.uid, header.gid, header.size if kind == 'file' else 0,
                          header.mtime, linkname, reader, report)
            try:
                yield entry
            except BaseException:  # the caller stopped (or threw): the data is not skipped, the entry is dead
                entry._reader = None
                raise
            entry._release()
            if kind == 'file':
                reader.skip((-header.size) % BLOCK)
            elif entry._copy:
                report.hardlinks -= 1
                link.copy = True
                links.wait(link, report)
    except _Truncated:
        raise _broken('the inner tar is truncated') from None
    if getattr(stream, 'checked_to_the_end', hasattr(stream, 'finish')):
        reader.drain()
        stream.finish()
    elif reader.another_header():  # no checksum covers this stream: zeros in its middle must not pass for its end
        raise _broken('the inner tar goes on after its end-of-archive marker')
    if links.waiting:
        yield from _copy_links(stream, start, links, names, select, report, addon, checkpoint)
    report.complete = True


def _copy_links(stream, start, links, names, select, report, addon, checkpoint):
    """The hard links that wait, after a complete first pass (every check of the stream passed): one whose file was
    handed out only later in the tar is still a link for a caller that takes links; every other one is a regular file
    with the content of the file it names (through other links too), read in further passes over the same member. A
    file with several waiting links is handed out once and the others as links to it, or -- a caller that takes no links
    -- from memory when it is small, else in the next pass. Never copied: a secret (never_read, addon.json), what the
    caller excludes, and what is not a regular file of this member; such links are skipped and listed."""
    wanted = {}
    for link in links.waiting:
        if select.hardlinks and not link.copy and names.handed_out(link.key):
            report.hardlinks += 1
            entry = _link_entry(link, link.target, report)
            yield entry
            if not entry._copy:
                continue
            report.hardlinks -= 1
        wanted.setdefault(links.resolve(link.key), []).append(link)
    for _ in range(MAX_LINK_PASSES):
        again = _reopen(stream, start) if wanted else None
        if again is None:
            break
        later = {}
        try:
            yield from _copy_pass(again, inflate_budget(stream), wanted, later, names, select, report, addon,
                                  checkpoint)
        except _Truncated:
            raise _broken('the inner tar is truncated') from None
        finally:
            if again is not stream:
                again.close()
        _skip_links(wanted, report)
        wanted = later
    _skip_links(wanted, report)


def _skip_links(links, report):
    for waiting in links.values():
        for link in waiting:
            report.skip('hardlink', link.name)


def _copy_pass(stream, budget, wanted, later, names, select, report, addon, checkpoint):
    """One pass for `_copy_links`: takes out of `wanted` ({digest of a file's name: [_Link]}) what it finds; `later`
    gets what needs another pass. It stops once nothing is wanted any more: the first pass has checked the whole
    stream."""
    reader = _Reader(stream, checkpoint=checkpoint, max_bytes=budget)
    count = 0
    while wanted:
        header = _inner_header(reader)
        if header is None:
            return
        count += 1
        if checkpoint is not None and count % CHECK_ENTRIES == 0:
            checkpoint()
        name = _entry_name(header.name)[0]
        key = names.digest(name)
        waiting = wanted.pop(key, None) if KINDS.get(header.typeflag) == 'file' else None
        pad = (-header.size) % BLOCK
        if waiting is None or never_read(name) or addon and name == ADDON_JSON or select.excludes(name):
            _skip_links({key: waiting or ()}, report)
            reader.skip(header.size + pad)
            continue
        held = None
        if len(waiting) > 1 and not select.hardlinks and header.size <= LINK_MEMORY:
            held = reader.read_exact(header.size)
        for index, link in enumerate(waiting):
            if index and held is None:
                if not select.hardlinks:
                    later.setdefault(key, []).append(link)
                    continue
                report.hardlinks += 1
                entry = _link_entry(link, waiting[0].name, report)
                yield entry
                if entry._copy:
                    report.hardlinks -= 1
                    later.setdefault(key, []).append(link)
                continue
            if report.bytes + header.size > select.max_bytes:
                raise _limit('the selected files are too large', limit=select.max_bytes)
            report.bytes += header.size
            report.files += 1
            report.copied_links += 1
            entry = Entry(link.name, 'file', link.mode, link.uid, link.gid, header.size, link.mtime, None,
                          reader if held is None else _Held(held), report)
            try:
                yield entry
            except BaseException:
                entry._reader = None
                raise
            entry._release()
        reader.skip(pad)


def _link_entry(link, target, report):
    return Entry(link.name, 'hardlink', link.mode, link.uid, link.gid, 0, link.mtime, target, None, report)


def read_addon_info(stream):
    """AddonInfo from addon.json of an add-on's inner tar (Supervisor writes it near the start), or None when the tar
    has none. Stops right after it: nothing else is checked."""
    report = Report()
    for _entry in iter_entries(stream, Select(include=()), report, until_addon=True):
        pass
    return report.addon
