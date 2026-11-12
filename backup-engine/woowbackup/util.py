"""Small shared helpers (owner: E1 engine-core).

Everything here is dependency free (stdlib only) and safe to call as root:
* atomic file writes with fsync of the file and its directory,
* sha256 of files, UTC timestamps in the contract's `…Z` form,
* strict JSON parsing with a size limit (duplicate keys, NaN/Infinity rejected),
* hostname sanitising for download file names,
* a sanitised environment and tool lookup for subprocesses (CONTRACT section 10.2).
"""
import datetime
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import stat
import tempfile
from pathlib import Path

SAFE_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
CHUNK = 1024 * 1024

ISO_RE = re.compile(r'^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\Z')
SHA256_RE = re.compile(r'^[0-9a-f]{64}\Z')


# ---------------------------------------------------------------- environment

def clean_env(extra=None):
    """Minimal environment for helper subprocesses: fixed PATH and a UTF-8 C locale."""
    env = {'PATH': SAFE_PATH, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
    if extra:
        env.update(extra)
    return env


def find_tool(name):
    """Absolute path of a system tool looked up only in SAFE_PATH, or None."""
    return shutil.which(name, path=SAFE_PATH)


# ---------------------------------------------------------------- time

def utc_now():
    """Current UTC time without microseconds (timezone aware)."""
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def _as_utc(dt):
    if dt is None:
        return utc_now()
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def iso_utc(dt=None):
    """`YYYY-MM-DDTHH:MM:SSZ` for `dt` (naive values are taken as UTC) or now."""
    return _as_utc(dt).strftime('%Y-%m-%dT%H:%M:%SZ')


def compact_utc(dt=None):
    """`YYYYMMDDTHHMMSSZ` (backup and job id prefix)."""
    return _as_utc(dt).strftime('%Y%m%dT%H%M%SZ')


def parse_iso_utc(text):
    """Parse the strict `…Z` form; raise ValueError on anything else (including impossible dates)."""
    if not isinstance(text, str) or not ISO_RE.match(text):
        raise ValueError('not an ISO-8601 UTC timestamp')
    return datetime.datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)


def is_iso_utc(text):
    try:
        parse_iso_utc(text)
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------- ids and names

def random_hex(nbytes):
    return secrets.token_hex(nbytes)


def sanitize_hostname(name, fallback='device'):
    """Lower-case `[a-z0-9-]` only, runs of other characters collapse to '-', max 63 chars."""
    text = (name or '').strip().lower()
    text = re.sub(r'[^a-z0-9]+', '-', text).strip('-')
    text = text[:63].strip('-')
    return text or fallback


def hostname():
    try:
        return socket.gethostname() or 'device'
    except OSError:
        return 'device'


def download_filename(host, created):
    """`woowtech-backup-<hostname>-<YYYYMMDD-HHMM>.woowbackup` (CONTRACT section 5)."""
    try:
        stamp = parse_iso_utc(created).strftime('%Y%m%d-%H%M')
    except ValueError:
        stamp = utc_now().strftime('%Y%m%d-%H%M')
    return f'woowtech-backup-{sanitize_hostname(host)}-{stamp}.woowbackup'


# ---------------------------------------------------------------- files

def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def ensure_dir(path, mode=0o700):
    """Create `path` (and missing parents with the same mode) and enforce `mode`.

    Refuses symlinks and non-directories at `path` so a planted link can never redirect writes.
    """
    path = Path(path)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if not path.parent.exists():
            ensure_dir(path.parent, mode)
        try:
            os.mkdir(path, mode)
        except FileExistsError:
            pass
        st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise NotADirectoryError(f'not a real directory: {path}')
    if stat.S_IMODE(st.st_mode) != mode:
        # Open without following links and chmod the fd, so a racing symlink swap cannot redirect it.
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
    return path


def atomic_write(path, data, mode=0o600):
    """Write bytes/str to `path` via a temp file in the same directory, fsync file + directory.

    The temp file is created with O_EXCL (mkstemp) and renamed over `path`; a symlink at `path`
    is replaced, never followed.
    """
    path = Path(path)
    if isinstance(data, str):
        data = data.encode('utf-8')
    fd, tmp = tempfile.mkstemp(prefix=f'.{path.name}.', suffix='.tmp', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(tmp, path)
        tmp = None
        fsync_dir(path.parent)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
    return path


def atomic_write_json(path, obj, mode=0o600):
    data = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False) + '\n'
    return atomic_write(path, data.encode('utf-8'), mode)


def sha256_fd(fd, chunk=CHUNK):
    """sha256 hex digest and byte count of an open fd from its current offset."""
    digest = hashlib.sha256()
    total = 0
    while True:
        buf = os.read(fd, chunk)
        if not buf:
            return digest.hexdigest(), total
        digest.update(buf)
        total += len(buf)


def sha256_file(path, chunk=CHUNK):
    """sha256 hex digest of a regular file (symlinks are refused)."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f'not a regular file: {path}')
        return sha256_fd(fd, chunk)[0]
    finally:
        os.close(fd)


# ---------------------------------------------------------------- strict JSON

class StrictJSONError(ValueError):
    """Raised for oversize, non UTF-8, malformed or ambiguous JSON."""


def _no_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise StrictJSONError(f'duplicate key: {key[:64]!r}')
        obj[key] = value
    return obj


def _no_constants(name):
    raise StrictJSONError(f'non-standard JSON constant: {name}')


def loads_strict(data, *, max_bytes=1024 * 1024):
    """Parse JSON from bytes/str: <= max_bytes UTF-8, no duplicate keys, no NaN/Infinity."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise StrictJSONError('JSON input must be bytes or text')
    data = bytes(data)
    if len(data) > max_bytes:
        raise StrictJSONError(f'JSON larger than {max_bytes} bytes')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise StrictJSONError('JSON is not valid UTF-8') from exc
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except StrictJSONError:
        raise
    except RecursionError as exc:
        raise StrictJSONError('JSON nested too deeply') from exc
    except ValueError as exc:
        raise StrictJSONError(f'invalid JSON: {exc}') from exc


def read_file_limited(path, max_bytes):
    """Read a regular, non-symlink file of at most max_bytes; raise StrictJSONError when larger."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f'not a regular file: {path}')
        if st.st_size > max_bytes:
            raise StrictJSONError(f'file larger than {max_bytes} bytes')
        chunks, total = [], 0
        while True:
            buf = os.read(fd, min(CHUNK, max_bytes + 1 - total))
            if not buf:
                break
            chunks.append(buf)
            total += len(buf)
            if total > max_bytes:
                raise StrictJSONError(f'file larger than {max_bytes} bytes')
        return b''.join(chunks)
    finally:
        os.close(fd)


def load_json_file(path, *, max_bytes=1024 * 1024):
    """Strictly parse a JSON file (regular file, no symlink, size limited)."""
    return loads_strict(read_file_limited(path, max_bytes), max_bytes=max_bytes)
