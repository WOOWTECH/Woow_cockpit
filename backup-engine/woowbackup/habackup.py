"""Home Assistant (Supervisor) backup files: recognise, describe strictly, open members, read inner tars (CONTRACT
section 5 "Home Assistant backups"). Owner: E1 engine-core (format).

An HA backup is a plain, uncompressed POSIX tar written by Python's tarfile (PAX headers carry float mtimes):
one inner tar per component -- `homeassistant.tar[.gz]`, `<add-on slug>.tar[.gz]`, `<folder>.tar[.gz]` (`share`,
`ssl`, `media`, `apps_local`/legacy `addons_local`), optionally `supervisor.tar[.gz]` -- and `./backup.json`, written
LAST (facts: haimport/HA-FACTS.md section 2). `.tar.gz` members are gzip streams, `.tar` members plain tars when
`compressed` is false; with a password every member is encrypted on its own (hasecuretar.py). Member names carry no
`./` except backup.json's; names are compared after normalisation, like Supervisor does.

Everything is hostile until checked, and parsed by readers written for exactly what Python's tarfile emits:

* `looks_like_ha(fd)`: cheap recognition for the upload path -- a member named `backup.json` (any `./` prefix) whose
  strict JSON has `supervisor_version`. A Cockpit format 2 file (whose first member `backup.json` has none) or a
  format 1 file answers False at once.
* `describe(fd)` -> Layout: strict outer parse -- ustar POSIX headers with valid checksums, PAX records of the kinds
  tarfile writes, regular files only, flat names without duplicates, zero padding, the end-of-archive marker and only
  zeros after it; backup.json (<= 1 MiB, strict JSON, the schema subset below); exactly the members backup.json
  implies (`supervisor` optional); each member's first bytes decide its encryption (SecureTar v2/v3 header, gzip or
  tar, else legacy v1 when the backup is `protected`) and its size must fit that header. backup.json is display data
  only and never trusted for a security decision; `protected` is never trusted for encryption either (an HA UI download
  is a decrypted copy that says `protected: false` while `supervisor.tar.gz` stays encrypted).
* `HaBackup` / `open_backup(path)` / `open_member(...)`: the plaintext of one member as a stream: its bytes, decrypted
  when encrypted (key-required without a key, wrong-key before any plaintext), gunzipped when compressed. The gzip
  reader inflates raw deflate after its own header parse and checks CRC32 and ISIZE; a v1 member's trailer may have the
  legacy shape `pad | CRC | 0x0c * 12 | ISIZE` (securetar <= 2024.11 padded every write; GNU tar and gzip refuse it).
  `finish()` reads to the end and runs every final check (gzip trailer, v3 final tag, v2 padding and size).
* `iter_entries(stream, select, report)`: strict streaming walk of an inner tar -- names without `./`, never absolute
  or `..`, no control characters, no duplicates, nothing below a non-directory, no devices, sparse files, global
  headers or unknown types; symlinks and hard links per the caller's `Select`; byte and member budgets; the
  end-of-archive marker and only zeros after it, then the stream's `finish()`. Two kinds of files are never handed
  out: `addon.json` (it holds the add-on's options with passwords and tokens) is parsed into `report.addon`
  (AddonInfo: slug, version, image, arch, name -- never options or tokens), and NEVER_READ (`data/options.json`,
  `data/odoo.conf` with HA passwords, `data/n8n-runners-auth-token`, the HA-side secrets of the batch 1 add-ons) is
  skipped unread.

Symlinks are only ever handed out as link entries (names and targets), never followed: a later entry may not lie
below one. A relative target must stay inside the caller's area; an absolute one is handed out only when the caller
names allowed target prefixes (`Select.absolute_symlinks`, e.g. a Python venv's `/opt/data/...` interpreter link)
and it is clean (no empty, `.` or `..` component), so joined below the link's own folder -- the way the restore and
podman's import resolve it (nested.py) -- it can never leave the volume either.

backup.json schema subset (Supervisor SCHEMA_BACKUP; unknown keys tolerated and ignored): `version` 2 (1: too old,
unsupported-format), `slug`, `name` (<= 200), `date` (ISO 8601, normalised to UTC `...Z`), `type` full|partial,
`supervisor_version`, `protected` and `compressed` booleans, `addons[{slug, name, version, size?}]` (unique slugs),
`folders[]`, `homeassistant` object|null, `repositories[]`, `extra` object.

Errors (errors.CODES): corrupt-archive (hasecuretar.CORRUPT_MESSAGE, English `reason` in the details),
unsupported-format, limit-exceeded, key-required, wrong-key, internal-error (missing crypto package).
"""
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
import zlib

from . import hasecuretar, util
from .errors import BackupError

BLOCK = 512
ZERO_BLOCK = bytes(BLOCK)
POSIX_MAGIC = b'ustar\x0000'
GNU_MAGIC = b'ustar  \x00'
CHUNK = 1024 * 1024
MAX_OUTER_MEMBERS = 512          # an HA backup has one member per component (dozens at most)
MAX_BACKUP_JSON = 1024 * 1024
MAX_PAX = 64 * 1024
MAX_LONG_NAME = 8 * 1024
MAX_TRAILER = 1024 * 1024        # zeros allowed after the end-of-archive marker (tarfile pads to 10 KiB)
MAX_NAME = 4096
MAX_ADDON_JSON = 4 * 1024 * 1024
DEFAULT_MAX_MEMBERS = 2_000_000
DEFAULT_MAX_BYTES = 2 * 1024 ** 4
# A member's tar may inflate to at most INFLATE_RATIO times its stored size (at least INFLATE_FLOOR): deflate's
# ~1000:1 would turn 1 GB into 1 TB of work (review HA-SEC-05). Every CHECK_BYTES read and CHECK_ENTRIES headers the
# walk calls its `checkpoint` (a cancel stops it also while it skips what is not selected).
INFLATE_RATIO = 100
INFLATE_FLOOR = 32 * 1024 ** 3
CHECK_BYTES = 64 * 1024 * 1024
CHECK_ENTRIES = 1024
MAX_GZIP_FIELD = 64 * 1024
MAX_GZIP_TRAILER = 64
SAMPLES = 5
ENCODING, ERRORS = 'utf-8', 'surrogateescape'

BACKUP_JSON = 'backup.json'
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
OUTER_PAX_KEYS = frozenset({'path', 'size', 'mtime', 'atime', 'ctime', 'uid', 'gid', 'uname', 'gname', 'hdrcharset'})
LEGACY_APPS_FOLDERS = ('apps/local', 'addons/local')

SLUG_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')
ADDON_SLUG_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z')
SYSTEM_SLUG_RE = re.compile(r'[a-z0-9][a-z0-9_-]{0,63}\Z')
VERSION_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9.+_~-]{0,63}\Z')
FOLDER_RE = re.compile(r'[a-z0-9_]{1,40}(?:/[a-z0-9_]{1,40})?\Z')
IMAGE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,511}\Z')
PAX_INT_RE = re.compile(r'[0-9]{1,20}\Z')
PAX_TIME_RE = re.compile(r'-?[0-9]{1,20}(?:\.[0-9]{1,20})?\Z')
CONTROL_RE = re.compile(r'[\x00-\x1f\x7f]')

UNSUPPORTED_VERSION = '這份 HA 備份的格式太舊，目前不支援；請用較新版本的 Home Assistant 重新建立備份。'
LIMIT_MESSAGE = 'HA 備份檔超出安全限制（檔案數量或大小），已拒絕處理。'


def _corrupt(reason, **details):
    return hasecuretar.corrupt(reason, **details)


def _limit(reason, **details):
    return BackupError('limit-exceeded', LIMIT_MESSAGE, reason=reason, **details)


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


def _number(field):
    """An octal (NUL/space padded) or GNU base-256 number field (positive only)."""
    if field[:1] == b'\x80':
        return int.from_bytes(field[1:], 'big')
    if field[:1] and field[0] & 0x80:
        raise _corrupt('tar number field is negative or invalid')
    text = field.split(b'\0', 1)[0].strip(b' ')
    if not text:
        return 0
    if not all(48 <= c <= 55 for c in text):
        raise _corrupt('tar number field is not octal')
    return int(text, 8)


def _cbytes(field):
    return field.split(b'\0', 1)[0]


def _text(raw):
    return raw.decode(ENCODING, ERRORS)


def _parse_pax(data, allowed=None):
    """{key: raw value bytes} of one PAX extended header; strict record syntax, no duplicate keys."""
    records, pos = {}, 0
    while pos < len(data):
        if data[pos] == 0:  # NUL padding after the last record is tolerated like tarfile does, only zeros
            if data[pos:].strip(b'\0'):
                raise _corrupt('malformed pax header')
            break
        space = data.find(b' ', pos, pos + 22)
        if space <= pos or not data[pos:space].isdigit():
            raise _corrupt('malformed pax record')
        length = int(data[pos:space])
        end = pos + length
        if length < 5 or end > len(data) or data[end - 1:end] != b'\n':
            raise _corrupt('malformed pax record')
        key, eq, value = data[space + 1:end - 1].partition(b'=')
        try:
            key = key.decode('ascii')
        except UnicodeDecodeError:
            raise _corrupt('pax record key is not ASCII') from None
        if not eq or not key or key in records:
            raise _corrupt('malformed or repeated pax record', key=key[:40])
        if key.startswith('GNU.sparse.'):
            raise _corrupt('sparse files are not supported')
        if allowed is not None and key not in allowed:
            raise _corrupt('pax record not allowed here', key=key[:40])
        records[key] = value
        pos = end
    return records


def _pax_int(records, key, default):
    raw = records.get(key)
    if raw is None:
        return default
    text = raw.decode('ascii', 'replace')
    if not PAX_INT_RE.fullmatch(text):
        raise _corrupt(f'pax {key} is not a number')
    return int(text)


def _pax_time(records, key, default):
    raw = records.get(key)
    if raw is None:
        return default
    text = raw.decode('ascii', 'replace')
    if not PAX_TIME_RE.fullmatch(text):
        raise _corrupt(f'pax {key} is not a time')
    return float(text)


# ====================================================================== outer tar

class _Outer:
    """Sequential strict reads of the outer tar with pread (position kept here)."""

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
    """A flat member name without `./` prefixes."""
    name = _text(raw)
    while name.startswith('./'):
        name = name[2:]
    if not name or name in ('.', '..') or '/' in name or len(name) > 255 or CONTROL_RE.search(name):
        raise _corrupt('unexpected member name in the outer tar', member=name[:200])
    return name


@dataclasses.dataclass(frozen=True)
class _Raw:
    name: str
    offset: int
    size: int


def _walk_outer(fd, size, *, limit=MAX_OUTER_MEMBERS):
    """Yield every regular member (_Raw) of a strictly parsed outer tar; after the last one the end-of-archive marker
    and the trailing zeros are checked."""
    outer = _Outer(fd, size)
    count = 0
    try:
        while True:
            pax = None
            while True:
                block = outer.read_exact(BLOCK)
                if block == ZERO_BLOCK:
                    if pax is not None:
                        raise _corrupt('pax header without a member')
                    _finish_outer(outer)
                    return
                if not _checksum_ok(block):
                    raise _corrupt('tar header checksum mismatch')
                if block[257:265] != POSIX_MAGIC:
                    raise _corrupt('outer tar header is not POSIX ustar')
                typeflag = block[156:157]
                member_size = _number(block[124:136])
                if typeflag == b'x':
                    if pax is not None:
                        raise _corrupt('consecutive pax headers')
                    if member_size > MAX_PAX:
                        raise _limit('pax header too large', size=member_size)
                    data = outer.read_exact(member_size)
                    _skip_padding(outer, member_size)
                    pax = _parse_pax(data, OUTER_PAX_KEYS)
                    continue
                if typeflag != b'0':
                    raise _corrupt('outer member is not a regular file', type=typeflag.decode('latin-1'))
                break
            if _cbytes(block[157:257]):
                raise _corrupt('outer member has a link name')
            raw = _cbytes(block[0:100])
            prefix = _cbytes(block[345:500])
            if prefix:
                raw = prefix + b'/' + raw
            if pax and 'path' in pax:
                raw = pax['path']
            member_size = _pax_int(pax or {}, 'size', member_size)
            name = _outer_name(raw)
            count += 1
            if count > limit:
                raise _limit('too many members in the outer tar', limit=limit)
            offset = outer.pos
            outer.skip(member_size)
            _skip_padding(outer, member_size)
            yield _Raw(name, offset, member_size)
    except _Truncated:
        raise _corrupt('the backup file is truncated') from None


def _skip_padding(outer, size):
    pad = (-size) % BLOCK
    if pad and outer.read_exact(pad).strip(b'\0'):
        raise _corrupt('tar padding is not zero')


def _finish_outer(outer):
    if outer.read_exact(BLOCK) != ZERO_BLOCK:
        raise _corrupt('data after the end-of-archive marker')
    left = outer.size - outer.pos
    if left > MAX_TRAILER:
        raise _corrupt('data after the end-of-archive marker')
    if left and outer.read_exact(left).strip(b'\0'):
        raise _corrupt('data after the end-of-archive marker')


def _fd_size(fd):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise _corrupt('not a regular file')
    return st.st_size


def looks_like_ha(fd):
    """True when the file is meant to be a Home Assistant backup: a member named backup.json (any `./` prefix) whose
    strict JSON object has `supervisor_version`. Never raises for other files (they go to the normal checks)."""
    try:
        size = _fd_size(fd)
        if size < 3 * BLOCK or os.pread(fd, 2, 0) == b'\x1f\x8b':
            return False
        for member in _walk_outer(fd, size):
            if member.name == BACKUP_JSON:
                if member.size > MAX_BACKUP_JSON:
                    return False
                doc = util.loads_strict(_pread_exact(fd, member.offset, member.size), max_bytes=MAX_BACKUP_JSON)
                return isinstance(doc, dict) and 'supervisor_version' in doc
        return False
    except (BackupError, OSError, ValueError, _Truncated):
        return False


# ====================================================================== backup.json

def _need(cond, reason, **details):
    if not cond:
        raise _corrupt(reason, **details)


def _plain_text(value, where, max_len, *, min_len=0):
    _need(isinstance(value, str) and min_len <= len(value) <= max_len, f'backup.json {where} must be text')
    _need(not CONTROL_RE.search(value), f'backup.json {where} has control characters')
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise _corrupt(f'backup.json {where} is not valid Unicode text') from None
    return value


def _date(value):
    _need(isinstance(value, str) and 10 <= len(value) <= 64, 'backup.json date must be text')
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError:
        raise _corrupt('backup.json date is not an ISO 8601 time') from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    try:
        text = util.iso_utc(parsed)
    except (OverflowError, ValueError):
        raise _corrupt('backup.json date is out of range') from None
    _need(util.is_iso_utc(text), 'backup.json date is out of range')
    return text


def validate_doc(doc):
    """The schema subset of an HA backup.json (module notes) -> normalised dict; unknown keys are ignored."""
    _need(isinstance(doc, dict), 'backup.json is not an object')
    version = doc.get('version', 1)
    if version == 1 and not isinstance(version, bool):
        raise BackupError('unsupported-format', UNSUPPORTED_VERSION, reason='backup.json version 1', version=1)
    _need(version == 2 and isinstance(version, int) and not isinstance(version, bool),
          'backup.json version is not supported', version=str(version)[:20])
    slug = doc.get('slug')
    _need(isinstance(slug, str) and SLUG_RE.fullmatch(slug), 'backup.json slug is invalid')
    name = _plain_text(doc.get('name'), 'name', 200)
    date = _date(doc.get('date'))
    _need(doc.get('type') in ('full', 'partial'), 'backup.json type is invalid')
    supervisor = doc.get('supervisor_version')
    _need(isinstance(supervisor, str) and VERSION_RE.fullmatch(supervisor), 'backup.json supervisor_version is invalid')
    for key in ('protected', 'compressed'):
        _need(isinstance(doc.get(key), bool), f'backup.json {key} must be true or false')
    addons = doc.get('addons', [])
    _need(isinstance(addons, list) and len(addons) <= 100, 'backup.json addons must be a list')
    normal_addons, slugs = [], set()
    for item in addons:
        _need(isinstance(item, dict), 'backup.json addon is not an object')
        addon_slug = item.get('slug')
        _need(isinstance(addon_slug, str) and ADDON_SLUG_RE.fullmatch(addon_slug), 'backup.json addon slug is invalid')
        _need(addon_slug not in slugs, 'backup.json lists an add-on twice', slug=addon_slug)
        slugs.add(addon_slug)
        addon_version = item.get('version')
        _need(isinstance(addon_version, str) and VERSION_RE.fullmatch(addon_version),
              'backup.json addon version is invalid', slug=addon_slug)
        size = item.get('size', 0)
        _need(isinstance(size, (int, float)) and not isinstance(size, bool) and size == size and 0 <= size < 2 ** 63,
              'backup.json addon size is invalid', slug=addon_slug)
        normal_addons.append({'slug': addon_slug, 'name': _plain_text(item.get('name'), 'addon name', 200),
                              'version': addon_version})
    folders = doc.get('folders', [])
    _need(isinstance(folders, list) and len(folders) <= 32, 'backup.json folders must be a list')
    normal_folders = []
    for folder in folders:
        _need(isinstance(folder, str) and FOLDER_RE.fullmatch(folder), 'backup.json folder is invalid')
        if folder == 'homeassistant':  # a v1 artefact Supervisor drops (validate.py v1_folderlist)
            continue
        if folder in LEGACY_APPS_FOLDERS:
            folder = 'apps/local'
        _need(folder not in normal_folders, 'backup.json lists a folder twice', folder=folder)
        normal_folders.append(folder)
    homeassistant = doc.get('homeassistant')
    _need(homeassistant is None or isinstance(homeassistant, dict), 'backup.json homeassistant is invalid')
    core = None
    if isinstance(homeassistant, dict) and homeassistant.get('version') is not None:
        core_version = homeassistant.get('version')
        _need(isinstance(core_version, str) and VERSION_RE.fullmatch(core_version),
              'backup.json homeassistant version is invalid')
        core = {'version': core_version}
    repositories = doc.get('repositories', [])
    _need(isinstance(repositories, list) and len(repositories) <= 500
          and all(isinstance(url, str) and len(url) <= 2048 for url in repositories),
          'backup.json repositories must be a list of text')
    _need(isinstance(doc.get('extra', {}), dict), 'backup.json extra must be an object')
    return {'slug': slug, 'name': name, 'date': date, 'type': doc['type'], 'version': 2,
            'supervisor_version': supervisor, 'protected': doc['protected'], 'compressed': doc['compressed'],
            'homeassistant': core, 'addons': normal_addons, 'folders': normal_folders}


# ====================================================================== describe

@dataclasses.dataclass(frozen=True)
class Member:
    """One inner tar of the outer file. `role`: addon | homeassistant | folder | supervisor; `slug`: the add-on slug
    (addon) or folder name (folder); `encryption`: none | v1 | v2 | v3 (from the member's first bytes)."""
    name: str
    offset: int
    size: int
    role: str
    slug: str | None
    encryption: str
    compressed: bool

    @property
    def encrypted(self):
        return self.encryption != 'none'


@dataclasses.dataclass(frozen=True)
class Layout:
    """A strictly described HA backup: `doc` (validate_doc of backup.json: untrusted display data), `members` (inner
    tars in file order) and the file `size`."""
    doc: dict
    members: tuple
    size: int

    def member(self, name):
        for member in self.members:
            if member.name == name:
                return member
        raise BackupError('not-found', '這份 HA 備份沒有這個項目。', member=str(name)[:200])

    def addon(self, slug):
        for member in self.members:
            if member.role == 'addon' and member.slug == slug:
                return member
        raise BackupError('not-found', '這份 HA 備份沒有這個附加元件。', slug=str(slug)[:100])

    def summary(self):
        """JSON-ready description: backup.json's fields plus, per add-on, its member, size and encryption."""
        doc = self.doc
        by_slug = {m.slug: m for m in self.members if m.role == 'addon'}
        return {
            'ha_slug': doc['slug'], 'name': doc['name'], 'date': doc['date'], 'type': doc['type'],
            'supervisor_version': doc['supervisor_version'], 'protected': doc['protected'],
            'compressed': doc['compressed'], 'homeassistant': dict(doc['homeassistant']) if doc['homeassistant'] else None,
            'addons': [dict(addon, member=by_slug[addon['slug']].name, size=by_slug[addon['slug']].size,
                            encryption=by_slug[addon['slug']].encryption) for addon in doc['addons']],
            'folders': list(doc['folders']),
            'supervisor': any(m.role == 'supervisor' for m in self.members),
            'size': self.size,
        }


def _expected_members(doc):
    """{member name: (role, slug)} backup.json implies; supervisor's member is optional (listed separately)."""
    ext = '.tar.gz' if doc['compressed'] else '.tar'
    expected = {}
    for addon in doc['addons']:
        expected[addon['slug'] + ext] = ('addon', addon['slug'])
    if doc['homeassistant'] is not None:
        expected['homeassistant' + ext] = ('homeassistant', None)
    for folder in doc['folders']:
        stems = ('apps_local', 'addons_local') if folder == 'apps/local' else (folder.replace('/', '_'),)
        expected[tuple(stem + ext for stem in stems)] = ('folder', folder)
    return expected, 'supervisor' + ext


def _member_encryption(fd, raw, protected, compressed):
    head = os.pread(fd, min(raw.size, BLOCK), raw.offset)
    kind = hasecuretar.sniff(head)
    if kind == 'unsupported':
        raise BackupError('unsupported-format', hasecuretar.UNSUPPORTED_MESSAGE, reason='unsupported SecureTar header',
                          member=raw.name)
    if kind in ('v2', 'v3'):
        if not hasecuretar.ciphertext_ok(kind, raw.size, head):
            raise _corrupt('member size does not match its SecureTar header', member=raw.name)
        return kind
    if kind == ('gzip' if compressed else 'tar'):
        return 'none'
    if kind == 'unknown' and protected:
        if not hasecuretar.ciphertext_ok('v1', raw.size, head):
            raise _corrupt('member is not a whole number of cipher blocks', member=raw.name)
        return 'v1'
    raise _corrupt('member is neither an encrypted nor a plain inner tar of the declared kind', member=raw.name)


def describe(fd):
    """Strict description (Layout) of the HA backup open at `fd`; raises corrupt-archive, unsupported-format or
    limit-exceeded. Reads the headers, backup.json and each member's first 512 bytes only."""
    try:
        size = _fd_size(fd)
        if os.pread(fd, 2, 0) == b'\x1f\x8b':
            raise _corrupt('the outer file is compressed (HA backups are plain tar files)')
        raws, names = [], set()
        for raw in _walk_outer(fd, size):
            if raw.name in names:
                raise _corrupt('duplicate member in the outer tar', member=raw.name)
            names.add(raw.name)
            raws.append(raw)
        docs = [raw for raw in raws if raw.name == BACKUP_JSON]
        if not docs:
            raise _corrupt('backup.json is missing')
        if docs[0].size > MAX_BACKUP_JSON:
            raise _limit('backup.json too large', size=docs[0].size)
        try:
            doc = util.loads_strict(_pread_exact(fd, docs[0].offset, docs[0].size), max_bytes=MAX_BACKUP_JSON)
        except ValueError:
            raise _corrupt('backup.json is not strict JSON') from None
        doc = validate_doc(doc)
        expected, supervisor = _expected_members(doc)
        wanted = {}
        for key, value in expected.items():
            for name in (key if isinstance(key, tuple) else (key,)):
                wanted[name] = (key, value)
        found = set()
        members = []
        for raw in raws:
            if raw.name == BACKUP_JSON:
                continue
            if raw.name == supervisor:
                role, slug = 'supervisor', None
            elif raw.name in wanted:
                key, (role, slug) = wanted[raw.name]
                if key in found:  # apps_local and addons_local both present
                    raise _corrupt('a folder has two members', member=raw.name)
                found.add(key)
            else:
                raise _corrupt('member that backup.json does not list', member=raw.name)
            members.append(Member(raw.name, raw.offset, raw.size, role, slug,
                                  _member_encryption(fd, raw, doc['protected'], doc['compressed']),
                                  doc['compressed']))
        missing = [key if isinstance(key, str) else key[0] for key in expected if key not in found]
        if missing:
            raise _corrupt('member that backup.json lists is missing', member=missing[0])
    except _Truncated:
        raise _corrupt('the backup file is truncated') from None
    return Layout(doc, tuple(members), size)


# ====================================================================== member streams

class _Slice:
    """read(n) of bytes [offset, offset + size) of `fd` with pread."""

    def __init__(self, fd, offset, size):
        self.fd, self.pos, self.end = fd, offset, offset + size

    @property
    def left(self):
        return self.end - self.pos

    def read(self, n=CHUNK):
        n = min(n if n is not None and n >= 0 else CHUNK, self.end - self.pos, CHUNK)
        if n <= 0:
            return b''
        data = os.pread(self.fd, n, self.pos)
        if not data:
            raise _corrupt('the backup file is truncated')
        self.pos += len(data)
        return data


class _Gunzip:
    """Streaming gzip (RFC 1952, one member) reader with bounded output per read: own header parse, raw inflate,
    CRC32 and ISIZE checked at the end; `legacy` (a v1 member) also accepts the trailer `pad | CRC | 0x0c * 12 | ISIZE`
    that securetar <= 2024.11 wrote (module notes)."""

    def __init__(self, src, *, legacy=False):
        self.src, self.legacy = src, legacy
        self._input = b''
        self._inflate = zlib.decompressobj(-zlib.MAX_WBITS)
        self._crc = 0
        self._size = 0
        self._eof = False
        self._header()

    def _more(self):
        data = self.src.read(CHUNK)
        if not data:
            raise _corrupt('gzip stream is truncated')
        return data

    def _take(self, n):
        while len(self._input) < n:
            self._input += self._more()
        data, self._input = self._input[:n], self._input[n:]
        return data

    def _take_zero_terminated(self):
        parts, total = [], 0
        while True:
            if not self._input:
                self._input = self._more()
            end = self._input.find(b'\0')
            if end >= 0:
                parts.append(self._input[:end + 1])
                self._input = self._input[end + 1:]
                return b''.join(parts)
            parts.append(self._input)
            total += len(self._input)
            self._input = b''
            if total > MAX_GZIP_FIELD:
                raise _corrupt('gzip header field too long')

    def _header(self):
        fixed = self._take(10)
        if fixed[:3] != b'\x1f\x8b\x08':
            raise _corrupt('member data is not gzip')
        flags = fixed[3]
        if flags & 0xe0:
            raise _corrupt('gzip header has reserved flags')
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
                raise _corrupt('gzip header checksum mismatch')

    def read(self, n=CHUNK):
        n = CHUNK if n is None or n < 0 else max(1, min(n, CHUNK))
        while not self._eof:
            data = self._inflate.unconsumed_tail or self._input or self._more()
            self._input = b''
            try:
                out = self._inflate.decompress(data, n)
            except zlib.error:
                raise _corrupt('gzip data is invalid') from None
            if self._inflate.eof:
                self._eof = True
            if out:
                self._crc = zlib.crc32(out, self._crc)
                self._size += len(out)
            if self._eof:
                self._trailer()
            if out:
                return out
        return b''

    def _trailer(self):
        rest = self._inflate.unused_data
        while len(rest) <= MAX_GZIP_TRAILER:
            more = self.src.read(MAX_GZIP_TRAILER + 1)
            if not more:
                break
            rest += more
        if len(rest) > MAX_GZIP_TRAILER:
            raise _corrupt('data after the gzip stream')
        crc = size = None
        if len(rest) == 8:
            crc, size = rest[:4], rest[4:]
        elif self.legacy and 20 <= len(rest) <= 35:
            pad = len(rest) - 20
            if rest[:pad] == bytes([pad]) * pad and rest[pad + 4:pad + 16] == b'\x0c' * 12:
                crc, size = rest[pad:pad + 4], rest[pad + 16:]
        if crc is None:
            raise _corrupt('gzip trailer is invalid')
        if int.from_bytes(crc, 'little') != self._crc or int.from_bytes(size, 'little') != self._size & 0xffffffff:
            raise _corrupt('gzip checksum mismatch')

    def finish(self):
        while self.read(CHUNK):
            pass


class MemberStream(io.RawIOBase):
    """Plaintext (a tar stream) of one inner tar: decrypted when the member is encrypted, gunzipped when compressed.
    `finish()` reads the rest and runs every final check; `close()` releases it (and the file when it owns it)."""

    def __init__(self, fd, member, keys=None, *, owns_fd=False):
        super().__init__()
        self.member = member
        self._fd = fd if owns_fd else None
        self._decrypt = None
        try:
            source = _Slice(fd, member.offset, member.size)
            self._slice = source
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

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self._top.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def finish(self):
        if self._gunzip is not None:
            self._gunzip.finish()
        elif self._decrypt is None:
            while self._slice.read(CHUNK):
                pass
        if self._decrypt is not None:
            self._decrypt.finish()
        elif self._slice.left:
            raise _corrupt('data after the end of the inner tar', member=self.member.name)

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
    """An HA backup file open for reading: `layout` (strict describe at open) and its members' plaintext streams.
    Use as a context manager; streams opened from it must be closed before it."""

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
    """HaBackup of the file at `path` (O_NOFOLLOW; described strictly)."""
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
    """AddonInfo of addon.json bytes (strict JSON <= 4 MiB); corrupt-archive when it is not an add-on's metadata."""
    if len(data) > MAX_ADDON_JSON:
        raise _limit('addon.json too large', size=len(data))
    try:
        doc = util.loads_strict(data, max_bytes=MAX_ADDON_JSON)
    except ValueError:
        raise _corrupt('addon.json is not strict JSON') from None
    _need(isinstance(doc, dict) and isinstance(doc.get('system'), dict), 'addon.json has no system section')
    system = doc['system']
    user = doc.get('user') if isinstance(doc.get('user'), dict) else {}
    slug = system.get('slug')
    _need(isinstance(slug, str) and SYSTEM_SLUG_RE.fullmatch(slug), 'addon.json system.slug is invalid')
    version = doc.get('version', user.get('version'))
    _need(isinstance(version, str) and VERSION_RE.fullmatch(version), 'addon.json version is invalid')
    image = user.get('image')
    if image is not None:
        _need(isinstance(image, str) and IMAGE_RE.fullmatch(image), 'addon.json user.image is invalid')
    name = system.get('name', '')
    name = name if isinstance(name, str) and len(name) <= 200 and not CONTROL_RE.search(name) else ''
    state = doc.get('state')
    state = state if isinstance(state, str) and re.fullmatch(r'[a-z]{1,20}', state) else ''
    return AddonInfo(slug=slug, version=version, image=image, arch=image_arch(image), name=name, state=state)


# ====================================================================== inner tar entries

@dataclasses.dataclass(frozen=True)
class Select:
    """Which entries of an inner tar a caller wants (normalised names, e.g. `data/postgres`; a prefix selects itself
    and everything below it). `include` None = everything, () = nothing; `exclude` wins over `include`. `symlinks`:
    prefixes below which a selected symlink is handed out when its target is relative and, resolved from the link's
    directory, stays inside that prefix (other symlinks are skipped and counted). `absolute_symlinks`: absolute
    target prefixes (e.g. `/opt/data`) for which a symlink below a `symlinks` area is handed out too, when its target
    is clean (`_absolute_ok`); () = never. `hardlinks`: a selected hard link is handed out when it names an earlier
    selected regular file; otherwise (or when False) it is refused (corrupt-archive), so a second name of a file is
    never lost silently. Budgets: `max_members` entries in the whole tar, `max_bytes` bytes of selected regular
    files."""
    include: tuple | None = None
    exclude: tuple = ()
    symlinks: tuple = ()
    hardlinks: bool = False
    max_members: int = DEFAULT_MAX_MEMBERS
    max_bytes: int = DEFAULT_MAX_BYTES
    absolute_symlinks: tuple = ()

    def wants(self, name):
        if any(_under(name, prefix) for prefix in self.exclude):
            return False
        return self.include is None or any(_under(name, prefix) for prefix in self.include)

    def symlink_root(self, name):
        return next((prefix for prefix in self.symlinks if _under(name, prefix) and name != prefix), None)


def _under(name, prefix):
    return name == prefix or name.startswith(prefix + '/') or prefix == '.'


class Report:
    """What a walk saw: counts of entries handed out, bytes, what was skipped (symlinks outside the allowed areas,
    FIFOs, NEVER_READ files) and the add-on's AddonInfo (`addon`, from addon.json)."""

    def __init__(self):
        self.entries = 0            # every entry of the tar
        self.files = self.dirs = self.symlinks = self.hardlinks = 0   # handed out
        self.bytes = 0              # bytes of the regular files handed out
        self.skipped_symlinks = 0
        self.skipped_symlink_samples = []
        self.absolute_symlinks = 0  # handed out with an absolute target (Select.absolute_symlinks)
        self.skipped_other = 0      # FIFOs (no data)
        self.secret_files = 0       # NEVER_READ entries skipped unread
        self.addon = None           # AddonInfo
        self.complete = False       # the end of the tar and every final check of the stream passed

    def warnings(self):
        """zh-TW notes for a job log."""
        notes = []
        if self.skipped_symlinks:
            notes.append(f'HA 備份中有 {self.skipped_symlinks} 個符號連結沒有搬過來（例如 '
                         f'{"、".join(self.skipped_symlink_samples)}）。')
        if self.skipped_other:
            notes.append(f'HA 備份中有 {self.skipped_other} 個特殊檔案（FIFO）沒有搬過來。')
        return notes


class Entry:
    """One entry of an inner tar handed out by iter_entries: `name` (normalised), `kind` (file | dir | symlink |
    hardlink), `mode` (permission bits), `uid`, `gid`, `size` (regular files), `mtime`, `linkname` (symlink target as
    stored / hard link target normalised) and `fileobj` (itself for a regular file, else None). A file's data can be
    read only until the walk moves on (`peek`, `read`, `readinto`, `read_all`, `copy_to`)."""

    __slots__ = ('name', 'kind', 'mode', 'uid', 'gid', 'size', 'mtime', 'linkname', '_reader', '_left', '_head')

    def __init__(self, name, kind, mode, uid, gid, size, mtime, linkname, reader):
        self.name, self.kind, self.mode, self.uid, self.gid = name, kind, mode, uid, gid
        self.size, self.mtime, self.linkname = size, mtime, linkname
        self._reader = reader if kind == 'file' else None
        self._left = size if kind == 'file' else 0
        self._head = b''

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
            raise _corrupt('the inner tar is truncated', member=self.name[:200]) from None
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
            raise _limit('file too large to read', member=self.name[:200], size=self.size)
        parts = []
        while True:
            data = self.read(CHUNK)
            if not data:
                return b''.join(parts)
            parts.append(data)

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

    def rest_is_zero(self, limit):
        """True when the stream holds only zeros (at most `limit` bytes) until its end."""
        total = 0
        while True:
            rest = self.buf[self.off:]
            total += len(rest)
            if total > limit or rest.strip(b'\0'):
                return False
            self.buf, self.off = b'', 0
            if self.eof:
                return True
            self._fill(1)


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
    """The next member header (PAX / GNU long name records applied) or None at the end-of-archive marker."""
    pax = long_name = long_link = None
    while True:
        block = reader.read_exact(BLOCK)
        if block == ZERO_BLOCK:
            if pax is not None or long_name is not None or long_link is not None:
                raise _corrupt('extended header without a member')
            return None
        if not _checksum_ok(block):
            raise _corrupt('tar header checksum mismatch')
        magic = block[257:265]
        if magic not in (POSIX_MAGIC, GNU_MAGIC):
            raise _corrupt('inner tar header is neither POSIX nor GNU ustar')
        typeflag = block[156:157]
        size = _number(block[124:136])
        if typeflag in (b'x', b'L', b'K'):
            if size > (MAX_PAX if typeflag == b'x' else MAX_LONG_NAME):
                raise _limit('extended header too large', size=size)
            data = reader.read_exact(size)
            reader.skip((-size) % BLOCK)
            if typeflag == b'x':
                if pax is not None:
                    raise _corrupt('consecutive pax headers')
                pax = _parse_pax(data)
            elif typeflag == b'L':
                if long_name is not None:
                    raise _corrupt('consecutive long name records')
                long_name = _cbytes(data)
            else:
                if long_link is not None:
                    raise _corrupt('consecutive long link records')
                long_link = _cbytes(data)
            continue
        if typeflag == b'g':
            raise _corrupt('global pax headers are not supported')
        raw = _cbytes(block[0:100])
        prefix = _cbytes(block[345:500]) if magic == POSIX_MAGIC else b''
        if prefix:
            raw = prefix + b'/' + raw
        link = _cbytes(block[157:257])
        if long_name is not None:
            raw = long_name
        if long_link is not None:
            link = long_link
        pax = pax or {}
        if 'path' in pax:
            raw = pax['path']
        if 'linkpath' in pax:
            link = pax['linkpath']
        if typeflag == b'\0' and raw.endswith(b'/'):
            typeflag = b'5'  # an old-style directory, as tarfile reads it
        return _Header(name=_text(raw), typeflag=typeflag, mode=_number(block[100:108]) & 0o7777,
                       uid=_pax_int(pax, 'uid', _number(block[108:116])),
                       gid=_pax_int(pax, 'gid', _number(block[116:124])),
                       size=_pax_int(pax, 'size', size),
                       mtime=_pax_time(pax, 'mtime', _number(block[136:148])),
                       linkname=_text(link))


KINDS = {b'0': 'file', b'\0': 'file', b'5': 'dir', b'2': 'symlink', b'1': 'hardlink', b'6': 'fifo'}
KIND_CODE = {'dir': 0, 'file': 1, 'symlink': 2, 'hardlink': 3, 'fifo': 4}


def normalize(name):
    """Relative entry name without `./` prefixes or a trailing slash ("." for the root); corrupt-archive for empty,
    absolute, `..`, `.` or empty components, control characters or names longer than 4096 bytes."""
    if not isinstance(name, str) or not name or len(name.encode(ENCODING, ERRORS)) > MAX_NAME:
        raise _corrupt('invalid entry name')
    if CONTROL_RE.search(name):
        raise _corrupt('entry name has control characters', member=name[:200].encode('ascii', 'backslashreplace')
                       .decode('ascii'))
    if name.startswith('/'):
        raise _corrupt('absolute entry name', member=name[:200])
    parts = name.split('/')
    while parts and parts[0] == '.':
        parts = parts[1:]
    if parts and parts[-1] == '':
        parts = parts[:-1]
    if not parts:
        return '.'
    if any(part in ('', '.', '..') for part in parts):
        raise _corrupt('entry name with an empty, "." or ".." component', member=name[:200])
    return '/'.join(parts)


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
    where a directory was implied. Names are kept as keyed 128-bit digests (bounded memory, like nested.py)."""

    def __init__(self):
        self.kinds = {}
        self.implicit = set()
        self.key = secrets.token_bytes(16)

    def digest(self, name):
        return int.from_bytes(hashlib.blake2b(name.encode(ENCODING, ERRORS), digest_size=16, key=self.key).digest(),
                              'little')

    def admit(self, name, kind):
        key = self.digest(name)
        if key in self.kinds:
            raise _corrupt('duplicate entry', member=name[:200])
        if kind != 'dir' and key in self.implicit:
            raise _corrupt('a non-directory replaces a directory', member=name[:200])
        parts = [] if name == '.' else name.split('/')
        for depth in range(1, len(parts)):
            prefix = self.digest('/'.join(parts[:depth]))
            if self.kinds.get(prefix, KIND_CODE['dir']) != KIND_CODE['dir']:
                raise _corrupt('entry below a file or link', member=name[:200])
            self.implicit.add(prefix)
        self.kinds[key] = KIND_CODE[kind]
        return key


def inflate_budget(stream):
    """Bytes the tar of a MemberStream may inflate to (None for other streams)."""
    member = getattr(stream, 'member', None)
    size = getattr(member, 'size', None)
    if not isinstance(size, int) or isinstance(size, bool):
        return None
    return max(INFLATE_FLOOR, INFLATE_RATIO * size)


def iter_entries(stream, select=None, report=None, *, addon=None, until_addon=False, checkpoint=None):
    """Walk the plaintext tar `stream` (a MemberStream or any object with read(n)) strictly and yield the selected
    entries (Entry) in order; see Select for symlinks, hard links and budgets and the module notes for what is never
    handed out. After the last entry the end-of-archive marker, the zero trailer and `stream.finish()` (when it has
    one) are checked; `report.complete` is True only then. A caller that stops early skips those checks.
    `addon`: the tar is an add-on's (its top-level addon.json is metadata, parsed into `report.addon`, never handed
    out); None = a MemberStream's member role, True for other streams. `until_addon`: stop as soon as addon.json was
    read (read_addon_info). `checkpoint`: called every CHECK_ENTRIES headers and CHECK_BYTES read (a cancel stops the
    walk also where nothing is selected); a MemberStream may inflate to inflate_budget() bytes (HA-SEC-05)."""
    select = select or Select()
    report = report if report is not None else Report()
    if addon is None:
        member = getattr(stream, 'member', None)
        addon = getattr(member, 'role', 'addon') == 'addon'
    reader = _Reader(stream, checkpoint=checkpoint, max_bytes=inflate_budget(stream))
    names = _Names()
    selected_files = set()
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
            name = normalize(header.name)
            kind = KINDS.get(header.typeflag)
            if kind is None:
                code = header.typeflag.decode('latin-1')
                raise _corrupt('entry type not allowed (device, sparse, contiguous or unknown)', member=name[:200],
                               type=code)
            if kind != 'file' and header.size:
                raise _corrupt('a non-file entry carries data', member=name[:200])
            if name == '.' and kind != 'dir':
                raise _corrupt('the root entry is not a directory')
            key = names.admit(name, kind)
            if name in NEVER_READ or (addon and name == ADDON_JSON):
                if kind != 'file':
                    raise _corrupt('unexpected entry type for a metadata file', member=name)
                if name == ADDON_JSON:
                    if header.size > MAX_ADDON_JSON:
                        raise _limit('addon.json too large', size=header.size)
                    report.addon = parse_addon_json(reader.read_exact(header.size))
                    reader.skip((-header.size) % BLOCK)
                    if until_addon:
                        return
                else:
                    reader.skip(header.size + (-header.size) % BLOCK)
                    report.secret_files += 1
                continue
            if kind == 'fifo' or not select.wants(name):
                if kind == 'fifo' and select.wants(name):
                    report.skipped_other += 1
                reader.skip(header.size + (-header.size) % BLOCK)
                continue
            linkname = None
            if kind == 'symlink':
                root = select.symlink_root(name)
                absolute = root is not None and _absolute_ok(header.linkname, select.absolute_symlinks)
                if root is None or not (absolute or _symlink_ok(name, header.linkname, root)):
                    report.skipped_symlinks += 1
                    if len(report.skipped_symlink_samples) < SAMPLES:
                        report.skipped_symlink_samples.append(name[:200])
                    continue
                if absolute:
                    report.absolute_symlinks += 1
                linkname = header.linkname
            elif kind == 'hardlink':
                target = normalize(header.linkname)
                if not select.hardlinks or names.digest(target) not in selected_files:
                    raise _corrupt('hard link to an entry outside the selection', member=name[:200],
                                   target=target[:200])
                linkname = target
            if kind == 'file':
                if report.bytes + header.size > select.max_bytes:
                    raise _limit('the selected files are too large', limit=select.max_bytes)
                report.bytes += header.size
                selected_files.add(key)
            setattr(report, f'{kind}s', getattr(report, f'{kind}s') + 1)
            entry = Entry(name, kind, header.mode, header.uid, header.gid, header.size if kind == 'file' else 0,
                          header.mtime, linkname, reader)
            try:
                yield entry
            except BaseException:  # the caller stopped (or threw): the data is not skipped, the entry is dead
                entry._reader = None
                raise
            entry._release()
            if kind == 'file':
                reader.skip((-header.size) % BLOCK)
        if reader.read_exact(BLOCK) != ZERO_BLOCK:
            raise _corrupt('data after the end-of-archive marker')
        if not reader.rest_is_zero(MAX_TRAILER):
            raise _corrupt('data after the end-of-archive marker')
    except _Truncated:
        raise _corrupt('the inner tar is truncated') from None
    finish = getattr(stream, 'finish', None)
    if finish is not None:
        finish()
    report.complete = True


def read_addon_info(stream):
    """AddonInfo from addon.json of an add-on's inner tar (Supervisor writes it near the start), or None when the tar
    has none. Stops right after it: nothing else is checked."""
    report = Report()
    for _entry in iter_entries(stream, Select(include=()), report, until_addon=True):
        pass
    return report.addon
