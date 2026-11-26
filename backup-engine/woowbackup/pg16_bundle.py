"""Opt-in release sidecar for OD-23. Stdlib only; never invokes a container engine.

The authenticated release supplies the SHA256 of manifest.json. A Docker save archive does not prove registry
provenance: the release builder must obtain its expected config ID from the pinned registry manifest independently.
Large files stay outside the Cockpit payload/state/rollback journal and are copied/hashed in bounded chunks.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import tarfile
import tempfile

PINNED_REF = ('docker.io/library/postgres:16.15-alpine'
              '@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139')
TAG = PINNED_REF.split('@')[0]
INSTALL_REL = 'usr/local/share/woowtech-cockpit-backup/images/odoo-pg16'
INSTALLED_ROOT = Path('/') / INSTALL_REL
ARCHIVE = 'postgres16.docker.tar'
CHUNK = 1024 * 1024
MAX_JSON = 1024 * 1024
MAX_ARCHIVE = 2 * 1024**3
HEX = re.compile(r'[0-9a-f]{64}\Z')
ROOT_UID = 0
TRUST_ANCHOR = Path('/')


class BundleError(ValueError):
    """A bundle is malformed, untrusted, or inconsistent (messages contain no artifact contents)."""


def architecture(machine=None):
    value = machine or platform.machine()
    result = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(value)
    if result is None:
        raise BundleError('Unsupported PG16 bundle architecture.')
    return result


def _hex(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def _json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BundleError('Duplicate bundle JSON key.')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise BundleError('Invalid bundle JSON.') from None


def _root_owned(st):
    if st.st_uid != ROOT_UID or st.st_mode & 0o022:
        raise BundleError('PG16 bundle must be root-owned and not writable by the app owner/group/others.')


@contextlib.contextmanager
def _directory(path, *, trusted=False, create=False, anchor=None):
    """Walk with directory descriptors and O_NOFOLLOW, including every trusted parent up to /."""
    path = Path(os.path.abspath(path))
    anchor = Path(anchor or TRUST_ANCHOR) if trusted else Path('/')
    try:
        parts = path.relative_to(anchor).parts
    except ValueError:
        raise BundleError('Bundle path outside trust anchor.') from None
    fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if trusted:
            _root_owned(os.fstat(fd))
        for part in parts:
            if create:
                try:
                    os.mkdir(part, 0o755, dir_fd=fd)
                except FileExistsError:
                    pass
            nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nfd
            if trusted:
                _root_owned(os.fstat(fd))
        yield fd
    finally:
        os.close(fd)


def _file(dfd, name, *, trusted=False):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise BundleError('Bundle files must be regular files with no links.')
        if trusted:
            _root_owned(st)
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def _small(stream):
    data = stream.read(MAX_JSON + 1)
    if len(data) > MAX_JSON:
        raise BundleError('Bundle metadata exceeds limit.')
    return data


def _tick(abort):
    if abort is not None:
        error = abort()
        if error is not None:
            raise error


def copy_hash(source, output=None, *, abort=None):
    digest, total = hashlib.sha256(), 0
    while True:
        _tick(abort)
        data = source.read(CHUNK)
        if not data:
            break
        total += len(data)
        if total > MAX_ARCHIVE:
            raise BundleError('PG16 archive exceeds limit.')
        digest.update(data)
        if output is not None:
            output.write(data)
    return digest.hexdigest(), total


def validate_archive(stream, arch, image_id, *, abort=None):
    """Inspect bounded Docker-save metadata without extraction, layer buffering, or tar extension allocations.

    USTAR/GNU regular headers only; PAX, sparse files, links, devices, duplicate/absolute/traversing paths are refused.
    Full artifact SHA256 binds layer contents; layer bytes are never interpreted here.
    """
    if arch not in ('amd64', 'arm64') or not isinstance(image_id, str) or not image_id.startswith('sha256:') or not _hex(image_id[7:]):
        raise BundleError('Invalid PG16 architecture/config ID.')
    stream.seek(0, os.SEEK_END)
    end = stream.tell()
    stream.seek(0)
    config_name = image_id[7:] + '.json'
    names, metadata, sizes = set(), {}, {}
    while stream.tell() < end:
        _tick(abort)
        header = stream.read(512)
        if header == bytes(512):
            # Reject concatenated archives and nonzero trailing data as well.
            while True:
                _tick(abort)
                tail = stream.read(CHUNK)
                if not tail:
                    break
                if any(tail):
                    raise BundleError('Unexpected data after Docker archive.')
            break
        try:
            info = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
        except (tarfile.TarError, ValueError, UnicodeError):
            raise BundleError('Invalid Docker archive header.') from None
        name = info.name.rstrip('/') if info.isdir() else info.name
        if (not name or name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/'))
                or '\\' in name or len(name) > 255 or name in names or len(names) >= 4096
                or info.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                or info.size < 0 or (info.isdir() and info.size)):
            raise BundleError('Unsafe Docker archive member.')
        names.add(name)
        if info.isfile():
            sizes[name] = info.size
        start = stream.tell()
        next_header = start + ((info.size + 511) // 512) * 512
        if next_header > end:
            raise BundleError('Truncated Docker archive.')
        if name in ('manifest.json', config_name, 'repositories'):
            if info.size > MAX_JSON or not info.isfile():
                raise BundleError('Docker image metadata exceeds limit or is not a file.')
            metadata[name] = stream.read(info.size)
        stream.seek(next_header)
    manifest = _json(metadata.get('manifest.json', b''))
    config = metadata.get(config_name, b'')
    if (not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict)
            or manifest[0].get('Config') != config_name or manifest[0].get('RepoTags') != [TAG]
            or hashlib.sha256(config).hexdigest() != image_id[7:]):
        raise BundleError('Docker image ref/config ID differs from the release pin.')
    config = _json(config)
    layers = manifest[0].get('Layers')
    if (not isinstance(config, dict) or config.get('architecture') != arch or config.get('os') != 'linux'
            or not isinstance(layers, list) or not layers
            or not all(isinstance(n, str) and n.endswith('.tar') and n in sizes for n in layers)
            or len(set(layers)) != len(layers)):
        raise BundleError('Docker image architecture/OS/layers differ from the release manifest.')
    allowed = {'manifest.json', config_name, 'repositories', *layers}
    for layer in layers:
        if layer.endswith('/layer.tar'):
            allowed.update({layer[:-9] + 'json', layer[:-9] + 'VERSION'})
    if set(sizes) - allowed:
        raise BundleError('Unrelated image files in Docker archive.')
    if 'repositories' in metadata:
        repositories = _json(metadata['repositories'])
        repo, tag = TAG.rsplit(':', 1)
        if (not isinstance(repositories, dict) or set(repositories) != {repo}
                or not isinstance(repositories[repo], dict) or set(repositories[repo]) != {tag}
                or repositories[repo][tag] != layers[-1].removesuffix('/layer.tar').removesuffix('.tar')):
            raise BundleError('Docker archive repositories differ from the release ref.')
    stream.seek(0)


def manifest_bytes(arch, image_id, sha256, size):
    return (json.dumps({'schema': 1, 'kind': 'odoo-pg16', 'architecture': arch, 'ref': PINNED_REF,
                        'image_id': image_id, 'archive': ARCHIVE, 'archive_sha256': sha256, 'archive_size': size},
                       sort_keys=True, indent=2) + '\n').encode()


@contextlib.contextmanager
def open_bundle(path, expected_sha256, *, arch=None, trusted=False, abort=None, trust_anchor=None):
    if not _hex(expected_sha256):
        raise BundleError('A trusted release manifest SHA256 is required.')
    with _directory(path, trusted=trusted, anchor=trust_anchor) as dfd, _file(dfd, 'manifest.json', trusted=trusted) as source:
        raw = _small(source)
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise BundleError('PG16 release manifest SHA256 mismatch.')
        record = _json(raw)
        keys = {'schema', 'kind', 'architecture', 'ref', 'image_id', 'archive', 'archive_sha256', 'archive_size'}
        if (not isinstance(record, dict) or set(record) != keys or type(record['schema']) is not int
                or record['schema'] != 1 or record['kind'] != 'odoo-pg16' or record['ref'] != PINNED_REF
                or record['architecture'] not in ('amd64', 'arm64') or (arch and record['architecture'] != arch)
                or record['archive'] != ARCHIVE or not _hex(record['archive_sha256'])
                or type(record['archive_size']) is not int or not 0 < record['archive_size'] <= MAX_ARCHIVE):
            raise BundleError('Invalid PG16 release manifest contract.')
        with _file(dfd, ARCHIVE, trusted=trusted) as archive:
            if os.fstat(archive.fileno()).st_size != record['archive_size']:
                raise BundleError('PG16 archive size mismatch.')
            actual, size = copy_hash(archive, abort=abort)
            if (actual, size) != (record['archive_sha256'], record['archive_size']):
                raise BundleError('PG16 archive SHA256 mismatch.')
            validate_archive(archive, record['architecture'], record['image_id'], abort=abort)
            yield record, raw, archive


def _write(path, data):
    with open(path, 'xb') as target:
        os.fchmod(target.fileno(), 0o644)
        target.write(data)
        target.flush()
        os.fsync(target.fileno())


def install_bundle(source, expected_sha256, root=Path('/')):
    """Stage a verified immutable generation, then atomically select it. Never reads old archives into memory."""
    with open_bundle(source, expected_sha256) as (record, raw, archive):
        target = Path(root) / INSTALL_REL / record['architecture']
        with _directory(target, trusted=True, create=True, anchor=Path(root)) as dfd:
            generation = target / expected_sha256
            if generation.exists():
                with open_bundle(generation, expected_sha256, trusted=True, trust_anchor=Path(root)) as _verified:
                    pass
            else:
                stage = Path(tempfile.mkdtemp(prefix='.stage-', dir=target))
                try:
                    with open(stage / ARCHIVE, 'xb') as output:
                        os.fchmod(output.fileno(), 0o644)
                        actual = copy_hash(archive, output)
                        output.flush()
                        os.fsync(output.fileno())
                    if actual != (record['archive_sha256'], record['archive_size']):
                        raise BundleError('PG16 archive changed during installation.')
                    _write(stage / 'manifest.json', raw)
                    os.chmod(stage, 0o755)
                    with _directory(stage) as stage_fd:
                        os.fsync(stage_fd)
                    os.rename(stage, generation)
                finally:
                    if stage.exists():
                        shutil.rmtree(stage)
            fd, name = tempfile.mkstemp(prefix='.active-', dir=target)
            try:
                with os.fdopen(fd, 'wb') as output:
                    os.fchmod(output.fileno(), 0o644)
                    output.write((expected_sha256 + '\n').encode())
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(name, target / 'active.sha256')
                os.fsync(dfd)
            finally:
                if os.path.exists(name):
                    os.unlink(name)
    return {'architecture': record['architecture'], 'manifest_sha256': expected_sha256, 'image_id': record['image_id'],
            'status': 'staged', 'path': str(generation)}


@contextlib.contextmanager
def installed_bundle(*, abort=None):
    arch = architecture()
    target = INSTALLED_ROOT / arch
    # A device that never opted in need not have a trusted sidecar parent tree at all.
    try:
        os.lstat(target / 'active.sha256')
    except FileNotFoundError:
        yield None
        return
    try:
        with _directory(target, trusted=True) as dfd, _file(dfd, 'active.sha256', trusted=True) as source:
            pin = _small(source).decode('ascii').strip()
    except FileNotFoundError:
        yield None
        return
    except UnicodeError:
        raise BundleError('Invalid installed PG16 manifest pin.') from None
    if not _hex(pin):
        raise BundleError('Invalid installed PG16 manifest pin.')
    with open_bundle(target / pin, pin, arch=arch, trusted=True, abort=abort) as bundle:
        yield bundle
