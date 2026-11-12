"""Untrusted tar files nested inside a backup: strict checks and canonical re-emission. Owner: E2.

An archive's image entries (OCI archives) and volume entries are tar files whose bytes come from an
untrusted `.woowbackup` (CONTRACT sections 5 and 10.5). Podman unpacks them without a chroot, as the
app owner: `podman load` untars an OCI archive into a temp directory and `podman volume import`
untars into the volume, and both follow a symlink that an earlier member planted (an absolute target
escapes into the owner's home; review finding SEC-1, verified with podman 4.9.3). So podman never
sees those bytes directly:

* each file is first checked here completely, before anything on the system is changed, and
* podman is then fed a *new* tar written by this module from the parsed, validated members only
  (`stream_volume`, `stream_oci` through `pipe_from`), so no parser difference between Python's
  tarfile and Go's archive/tar can matter.

Volume tars may hold regular files, directories, symlinks (any target: a symlink is never traversed
while unpacking, because no later member may lie below a symlink or other non-directory) and hard
links to an earlier regular file. Rejected: devices, FIFOs, sparse/contiguous/unknown types, global
PAX headers, absolute or `..` names, duplicates, a non-directory replacing a directory, members
below a non-directory, and hard links to anything else. Re-emitted members keep their mode (without
setuid/setgid on non-directories), numeric owner, mtime and `SCHILY.xattr.user.*` records only.

OCI archives (`podman save --format oci-archive`) may only contain `oci-layout`, `index.json`,
`blobs/`, `blobs/sha256/` and `blobs/sha256/<64 hex>` (regular files and directories). The index
must hold exactly one OCI image manifest whose `org.opencontainers.image.ref.name` equals the ref
the trusted local templates need (podman names the loaded image after it, so a foreign name would
retag another image of the owner), the manifest blob must match its digest and its config digest
must equal the image id recorded in the backup manifest.
"""
import contextlib
import hashlib
import json
import os
import re
import tarfile
import threading

from .errors import BackupError

MAX_VOLUME_MEMBERS = 2_000_000
MAX_OCI_MEMBERS = 10_000
MAX_OCI_JSON = 4 * 1024 * 1024
MAX_NAME = 4096
OCI_LAYOUT = b'{"imageLayoutVersion":"1.0.0"}'
OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
REF_NAME = 'org.opencontainers.image.ref.name'
DIGEST_RE = re.compile(r'sha256:([0-9a-f]{64})\Z')
BLOB_RE = re.compile(r'blobs/sha256/([0-9a-f]{64})\Z')
IMAGE_ID_RE = re.compile(r'(?:sha256:)?([0-9a-f]{64})\Z')
KEEP_PAX = 'SCHILY.xattr.user.'
COPY_CHUNK = 1024 * 1024
ENCODING, ERRORS = 'utf-8', 'surrogateescape'
REGULAR = (tarfile.REGTYPE, tarfile.AREGTYPE)
KIND_TYPES = {'dir': tarfile.DIRTYPE, 'file': tarfile.REGTYPE, 'symlink': tarfile.SYMTYPE, 'link': tarfile.LNKTYPE}
VOLUME, IMAGE = '資料卷', '容器映像'


def _bad(what, reason, **details):
    return BackupError('corrupt-archive', f'備份中的{what}含有不安全或不支援的內容，已拒絕還原；這台設備沒有任何變更。',
                       reason=reason, **details)


def _normalize(name, what):
    """Relative member name without "./" prefixes or a trailing slash; "." for the root itself."""
    if not isinstance(name, str) or not name or '\x00' in name or len(name) > MAX_NAME:
        raise _bad(what, 'invalid member name')
    if name.startswith('/'):
        raise _bad(what, 'absolute member name', member=name[:200])
    parts = name.split('/')
    while parts and parts[0] == '.':
        parts = parts[1:]
    if parts and parts[-1] == '':
        parts = parts[:-1]
    if not parts:
        return '.'
    if any(part in ('', '.', '..') for part in parts):
        raise _bad(what, 'member name with an empty, "." or ".." component', member=name[:200])
    return '/'.join(parts)


def _members(tar, what, limit):
    """Iterate a tarfile's members without letting tarfile cache them all (bounded memory)."""
    count = 0
    while True:
        try:
            member = tar.next()
        except tarfile.TarError as exc:
            raise _bad(what, f'unreadable tar: {str(exc)[:120]}') from None
        if member is None:
            break
        count += 1
        if count > limit:
            raise _bad(what, 'too many members', limit=limit)
        yield member
        tar.members.clear()
    if tar.pax_headers:
        raise _bad(what, 'global PAX header')


def _open(path, what, mode):
    try:
        return tarfile.open(path, mode, encoding=ENCODING, errors=ERRORS)
    except (tarfile.TarError, OSError) as exc:
        raise _bad(what, f'not a tar file: {str(exc)[:120]}') from None


# ---------------------------------------------------------------- volumes

class _VolumePolicy:
    """Order-aware member rules; one instance per pass over a volume tar."""

    def __init__(self):
        self.kinds = {}        # explicit member -> 'dir' | 'file' | 'symlink' | 'link'
        self.implicit = set()  # parents created implicitly by the unpacker

    def admit(self, member):
        name = _normalize(member.name, VOLUME)
        if member.type == tarfile.DIRTYPE:
            kind = 'dir'
        elif member.type in REGULAR:
            kind = 'file'
        elif member.type == tarfile.SYMTYPE:
            kind = 'symlink'
        elif member.type == tarfile.LNKTYPE:
            kind = 'link'
        else:
            raise _bad(VOLUME, 'member type not allowed (device, FIFO, sparse or unknown)',
                       member=name[:200], type=member.type.decode('latin-1'))
        if name == '.' and kind != 'dir':
            raise _bad(VOLUME, 'the volume root is not a directory')
        if name in self.kinds:
            raise _bad(VOLUME, 'duplicate member', member=name[:200])
        if kind != 'dir' and name in self.implicit:
            raise _bad(VOLUME, 'a non-directory replaces a directory', member=name[:200])
        parts = [] if name == '.' else name.split('/')
        for depth in range(1, len(parts)):
            prefix = '/'.join(parts[:depth])
            if self.kinds.get(prefix, 'dir') != 'dir':
                raise _bad(VOLUME, 'member below a symlink, hard link or file', member=name[:200])
            self.implicit.add(prefix)
        link = None
        if kind == 'link':
            link = _normalize(member.linkname, VOLUME)
            if self.kinds.get(link) != 'file':
                raise _bad(VOLUME, 'hard link to something other than an earlier regular file', member=name[:200])
        elif kind == 'symlink':
            link = member.linkname
            if not isinstance(link, str) or not link or '\x00' in link or len(link) > MAX_NAME:
                raise _bad(VOLUME, 'invalid symlink target', member=name[:200])
        self.kinds[name] = kind
        return name, kind, link


def _volume_info(member, name, kind, link):
    info = tarfile.TarInfo(name)
    info.type = KIND_TYPES[kind]
    mode = member.mode & 0o7777
    info.mode = mode if kind == 'dir' else mode & ~0o6000
    info.uid, info.gid = int(member.uid), int(member.gid)
    info.uname = info.gname = ''
    info.mtime = member.mtime
    info.size = member.size if kind == 'file' else 0
    if link is not None:
        info.linkname = link
    info.pax_headers = {key: value for key, value in member.pax_headers.items() if key.startswith(KEEP_PAX)}
    return info


def check_volume(path):
    """Validate a volume tar completely (no output); returns the member count."""
    count = 0
    policy = _VolumePolicy()
    with _open(path, VOLUME, 'r|') as tar:
        for member in _members(tar, VOLUME, MAX_VOLUME_MEMBERS):
            policy.admit(member)
            count += 1
    return count


def stream_volume(path, out):
    """Write a canonical tar of the validated members of `path` to the binary file `out`."""
    policy = _VolumePolicy()
    with _open(path, VOLUME, 'r|') as tar, \
            tarfile.open(fileobj=out, mode='w|', format=tarfile.PAX_FORMAT, encoding=ENCODING, errors=ERRORS,
                         bufsize=COPY_CHUNK) as dest:
        for member in _members(tar, VOLUME, MAX_VOLUME_MEMBERS):
            name, kind, link = policy.admit(member)
            info = _volume_info(member, name, kind, link)
            if kind == 'file':
                source = tar.extractfile(member)
                try:
                    dest.addfile(info, source)
                except OSError:
                    raise _bad(VOLUME, 'member data truncated', member=name[:200]) from None
            else:
                dest.addfile(info)


# ---------------------------------------------------------------- OCI archives

def _read_member(tar, member, limit, what, label):
    if member.size > limit:
        raise _bad(what, f'{label} too large', size=member.size)
    handle = tar.extractfile(member)
    data = handle.read(limit + 1) if handle else b''
    if len(data) != member.size:
        raise _bad(what, f'{label} truncated')
    return data


def _json(data, what, label):
    try:
        value = json.loads(data.decode('utf-8'))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _bad(what, f'{label} is not JSON') from None
    if not isinstance(value, dict):
        raise _bad(what, f'{label} is not a JSON object')
    return value


def _digest(value, what, label):
    match = DIGEST_RE.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise _bad(what, f'{label} digest invalid')
    return match.group(1)


def _oci_members(tar):
    found = {}
    for member in _members(tar, IMAGE, MAX_OCI_MEMBERS):
        name = _normalize(member.name, IMAGE)
        if name in found:
            raise _bad(IMAGE, 'duplicate member', member=name[:200])
        if member.type == tarfile.DIRTYPE:
            if name not in ('.', 'blobs', 'blobs/sha256'):
                raise _bad(IMAGE, 'unexpected directory', member=name[:200])
        elif member.type in REGULAR:
            if name not in ('oci-layout', 'index.json') and not BLOB_RE.fullmatch(name):
                raise _bad(IMAGE, 'unexpected file', member=name[:200])
        else:
            raise _bad(IMAGE, 'member is not a regular file or directory', member=name[:200],
                       type=member.type.decode('latin-1'))
        found[name] = member
    return found


def check_oci(path, *, ref, image_id):
    """Validate an OCI archive for `ref`; returns the plan `stream_oci` needs."""
    match = IMAGE_ID_RE.fullmatch(image_id) if isinstance(image_id, str) else None
    if not match:
        raise _bad(IMAGE, 'the backup manifest has no valid image id', ref=str(ref)[:200])
    config_hex = match.group(1)
    with _open(path, IMAGE, 'r:') as tar:
        found = _oci_members(tar)
        for name in ('oci-layout', 'index.json'):
            if name not in found or found[name].type not in REGULAR:
                raise _bad(IMAGE, f'{name} missing')
        layout = _json(_read_member(tar, found['oci-layout'], 4096, IMAGE, 'oci-layout'), IMAGE, 'oci-layout')
        if layout.get('imageLayoutVersion') != '1.0.0':
            raise _bad(IMAGE, 'unsupported OCI layout version')
        index = _json(_read_member(tar, found['index.json'], MAX_OCI_JSON, IMAGE, 'index.json'), IMAGE, 'index.json')
        manifests = index.get('manifests')
        if not isinstance(manifests, list) or len(manifests) != 1 or not isinstance(manifests[0], dict):
            raise _bad(IMAGE, 'the index must hold exactly one manifest')
        descriptor = manifests[0]
        annotations = descriptor.get('annotations')
        if descriptor.get('mediaType') != OCI_MANIFEST:
            raise _bad(IMAGE, 'the index entry is not an OCI image manifest')
        if not isinstance(annotations, dict) or annotations.get(REF_NAME) != ref:
            raise _bad(IMAGE, 'the image name in the archive differs from the name the app needs', ref=str(ref)[:200])
        manifest_hex = _digest(descriptor.get('digest'), IMAGE, 'manifest')

        def blob(hex_digest, label):
            member = found.get(f'blobs/sha256/{hex_digest}')
            if member is None or member.type not in REGULAR:
                raise _bad(IMAGE, f'{label} blob missing')
            return member

        manifest_data = _read_member(tar, blob(manifest_hex, 'manifest'), MAX_OCI_JSON, IMAGE, 'manifest')
        if hashlib.sha256(manifest_data).hexdigest() != manifest_hex:
            raise _bad(IMAGE, 'manifest digest mismatch')
        manifest = _json(manifest_data, IMAGE, 'manifest')
        if manifest.get('schemaVersion') != 2 or manifest.get('mediaType', OCI_MANIFEST) != OCI_MANIFEST:
            raise _bad(IMAGE, 'not an OCI image manifest')
        config = manifest.get('config')
        layers = manifest.get('layers')
        if not isinstance(config, dict) or not isinstance(layers, list) or len(layers) > 1000:
            raise _bad(IMAGE, 'manifest config or layers invalid')
        if _digest(config.get('digest'), IMAGE, 'config') != config_hex:
            raise _bad(IMAGE, 'the image id differs from the backup manifest', ref=str(ref)[:200])
        config_data = _read_member(tar, blob(config_hex, 'config'), MAX_OCI_JSON, IMAGE, 'config')
        if hashlib.sha256(config_data).hexdigest() != config_hex:
            raise _bad(IMAGE, 'config digest mismatch')
        blobs = [manifest_hex, config_hex]
        for layer in layers:
            if not isinstance(layer, dict):
                raise _bad(IMAGE, 'layer descriptor invalid')
            layer_hex = _digest(layer.get('digest'), IMAGE, 'layer')
            blob(layer_hex, 'layer')
            if layer_hex not in blobs:
                blobs.append(layer_hex)
    index_data = json.dumps({'schemaVersion': 2, 'manifests': [{
        'mediaType': OCI_MANIFEST, 'digest': f'sha256:{manifest_hex}', 'size': len(manifest_data),
        'annotations': {REF_NAME: ref}}]}, separators=(',', ':')).encode()
    return {'ref': ref, 'image_id': f'sha256:{config_hex}', 'index': index_data, 'blobs': blobs}


def stream_oci(path, plan, out):
    """Write a canonical OCI archive (layout, index, referenced blobs only) to the binary file `out`."""

    def entry(name, kind, size=0):
        info = tarfile.TarInfo(name)
        info.type = KIND_TYPES[kind]
        info.mode = 0o755 if kind == 'dir' else 0o644
        info.size = size
        return info

    with _open(path, IMAGE, 'r:') as tar, \
            tarfile.open(fileobj=out, mode='w|', format=tarfile.PAX_FORMAT, bufsize=COPY_CHUNK) as dest:
        found = _oci_members(tar)
        dest.addfile(entry('oci-layout', 'file', len(OCI_LAYOUT)), _Bytes(OCI_LAYOUT))
        dest.addfile(entry('index.json', 'file', len(plan['index'])), _Bytes(plan['index']))
        dest.addfile(entry('blobs', 'dir'))
        dest.addfile(entry('blobs/sha256', 'dir'))
        for hex_digest in plan['blobs']:
            member = found.get(f'blobs/sha256/{hex_digest}')
            if member is None or member.type not in REGULAR:
                raise _bad(IMAGE, 'blob missing while streaming')
            try:
                dest.addfile(entry(f'blobs/sha256/{hex_digest}', 'file', member.size), tar.extractfile(member))
            except OSError:
                raise _bad(IMAGE, 'blob truncated') from None


class _Bytes:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def read(self, size=-1):
        end = len(self.data) if size is None or size < 0 else self.pos + size
        chunk = self.data[self.pos:end]
        self.pos += len(chunk)
        return chunk


# ---------------------------------------------------------------- feeding a subprocess

@contextlib.contextmanager
def pipe_from(writer):
    """Yield the read end of a pipe that a thread fills with `writer(binary_file)` (a subprocess stdin).

    On exit the read end is closed first (a writer blocked on a full pipe then fails with EPIPE
    instead of hanging), the thread is joined, and a writer error is raised: a BackupError from the
    writer (an unsafe member found while streaming) wins over the command's own failure.
    """
    rfd, wfd = os.pipe()
    reader = os.fdopen(rfd, 'rb', buffering=0)
    state = {}

    def run():
        out = os.fdopen(wfd, 'wb', buffering=COPY_CHUNK)
        try:
            writer(out)
            out.flush()
        except BrokenPipeError:
            state['broken'] = True
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller's thread
            state['error'] = exc
        finally:
            with contextlib.suppress(OSError):
                out.close()

    thread = threading.Thread(target=run, name='woowbackup-tar-feed', daemon=True)
    thread.start()
    try:
        yield reader
    finally:
        reader.close()
        thread.join()
        error = state.get('error')
        if isinstance(error, BackupError):
            raise error
    if error is not None:
        raise BackupError('internal-error', '準備還原資料時發生錯誤。', reason=type(error).__name__)
