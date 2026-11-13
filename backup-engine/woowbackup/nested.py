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

Volume tars may hold regular files, directories, FIFOs, symlinks and hard links to an earlier
non-directory member (Go's os.Link does not follow a symlink; `podman volume export` writes a second name
of a symlink or FIFO as such a hard link, review finding HD-03). A symlink is never traversed while
unpacking, because no later member may lie below a symlink or other non-directory; its target is only
checked the way podman's import checks it: resolved from the link's own directory it must stay inside the
volume (podman aborts the import half-way otherwise, after the volume was emptied; finding HD-02).
Rejected: devices, sparse/contiguous/unknown types, global PAX headers, absolute or `..` names,
duplicates, a non-directory replacing a directory, members below a non-directory, and, when the owner's
ID map is given, a member owner the owner's user namespace cannot represent (podman's lchown fails
half-way otherwise; HD-02). Re-emitted members keep their mode (without setuid/setgid on
non-directories), numeric owner, mtime and `SCHILY.xattr.user.*` records only; what was dropped is
counted in the check report, so the restore can say so (HD-09). Member names are remembered as keyed
128-bit digests, not strings, which keeps a pass at the 2,000,000-member cap well below the job's memory
limit (HD-03).

Host directory tars (`apps/<id>/dirs/<n>.tar`, written by GNU tar as the owner inside his user namespace) follow
the volume rules with two differences: the root entry `./` is expected (it carries the directory's own owner,
mode and mtime), and a symlink may point anywhere (it is restored verbatim and never followed: no member may lie
below it, and GNU tar extracts into a new, empty directory). Such links are counted for the backup log.

OCI archives (`podman save --format oci-archive`) may only contain `oci-layout`, `index.json`,
`blobs/`, `blobs/sha256/` and `blobs/sha256/<64 hex>` (regular files and directories). The index
must hold exactly one OCI image manifest, the manifest blob must match its digest and its config digest
must equal the image id recorded in the backup manifest. Its `org.opencontainers.image.ref.name` must name
the same image as the ref the trusted local templates need: podman writes the name it resolved the ref to
(`postgres:16` is saved as `docker.io/library/postgres:16`, a locally built `app:1` as `localhost/app:1`;
review finding HD-01), so a short ref accepts the same repository path and tag under any registry. The
rebuilt index never carries the archive's name: it names the image `local_name(ref)`, the name
`podman tag <id> <ref>` would give it, so a crafted archive can never choose which image name of the owner
the load moves.
"""
import contextlib
import hashlib
import json
import os
import posixpath
import re
import secrets
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
KIND_TYPES = {'dir': tarfile.DIRTYPE, 'file': tarfile.REGTYPE, 'symlink': tarfile.SYMTYPE, 'link': tarfile.LNKTYPE,
              'fifo': tarfile.FIFOTYPE}
LINKABLE = frozenset({'file', 'symlink', 'link', 'fifo'})  # hard links may name any earlier non-directory
KIND_CODES = {'dir': 0, 'file': 1, 'symlink': 2, 'link': 3, 'fifo': 4}
CODE_KINDS = {code: kind for kind, code in KIND_CODES.items()}
VOLUME, IMAGE, DIRECTORY = '資料卷', '容器映像', '主機資料夾'
SAMPLES = 5
REGISTRY_RE = re.compile(r'[A-Za-z0-9.-]+(?::[0-9]+)?\Z')
MTIME_RE = re.compile(r'[0-9]{1,12}(?:\.[0-9]{1,9})?\Z')


def _bad(what, reason, label=None, **details):
    """corrupt-archive for an unsafe or unsupported nested tar; `reason` (English) and the zh-TW `label` go to
    the details, so a backup-time check can explain the same rule in its own words."""
    detail = f'（{label}）' if label else ''
    if label:
        details['label'] = label
    return BackupError('corrupt-archive', f'備份中的{what}含有不安全或不支援的內容{detail}，已拒絕還原；這台設備沒有任何變更。',
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
            raise _bad(what, 'too many members', f'超過 {limit:,} 個項目的上限', limit=limit)
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

class IdMap:
    """IDs a user namespace can represent, from `/proc/self/uid_map` (or gid_map) text read inside it
    (`podman unshare cat /proc/self/uid_map`): lines of "inside outside count"."""

    def __init__(self, text):
        self.ranges = []
        for line in str(text).splitlines():
            fields = line.split()
            if len(fields) != 3 or not all(field.isdigit() for field in fields):
                continue
            inside, _outside, count = (int(field) for field in fields)
            if count > 0:
                self.ranges.append((inside, inside + count))
        self.ranges.sort()

    def __contains__(self, value):
        return any(start <= value < end for start, end in self.ranges)

    def describe(self):
        return '、'.join(f'{start}–{end - 1}' for start, end in self.ranges) or '（無）'


def _escapes(name, target):
    """True when a symlink `name` -> `target` leaves the volume, resolved the way podman's import checks it:
    the target joined to the link's directory (also an absolute target: Go's filepath.Join keeps it below)."""
    folder = posixpath.dirname(name)
    base = '/R' if not folder else f'/R/{folder}'
    resolved = posixpath.normpath(f'{base}/{target}')
    return not (resolved == '/R' or resolved.startswith('/R/'))


class VolumeReport:
    """What a volume (or host directory) check found: member count, the largest member owner ids, symlinks that
    point outside, and what the canonical copy drops (CONTRACT section 5)."""

    def __init__(self, subject=VOLUME):
        self.subject = subject          # 資料卷 or 主機資料夾, for the notes
        self.members = 0
        self.max_uid = 0                # largest member owner (uid / gid): what the target namespace must map
        self.max_gid = 0
        self.special_modes = 0          # setuid/setgid bits dropped from non-directories
        self.special_mode_samples = []
        self.dropped_xattrs = 0         # members with extended attributes other than user.* (dropped)
        self.dropped_xattr_names = []   # e.g. security.capability (bounded)
        self.dropped_xattr_samples = []
        self.outside_links = 0          # host directories only: symlinks whose target is outside the directory
        self.outside_link_samples = []

    def note(self, member, name, kind):
        self.max_uid = max(self.max_uid, int(member.uid))
        self.max_gid = max(self.max_gid, int(member.gid))
        if kind != 'dir' and member.mode & 0o6000:
            self.special_modes += 1
            if len(self.special_mode_samples) < SAMPLES:
                self.special_mode_samples.append(name)
        dropped = [key[len('SCHILY.xattr.'):] for key in member.pax_headers
                   if key.startswith('SCHILY.xattr.') and not key.startswith(KEEP_PAX)]
        if dropped:
            self.dropped_xattrs += 1
            if len(self.dropped_xattr_samples) < SAMPLES:
                self.dropped_xattr_samples.append(name)
            for key in dropped:
                if key not in self.dropped_xattr_names and len(self.dropped_xattr_names) < 10:
                    self.dropped_xattr_names.append(key[:100])

    def note_outside_link(self, name):
        self.outside_links += 1
        if len(self.outside_link_samples) < SAMPLES:
            self.outside_link_samples.append(name)

    def warnings(self, volume):
        """zh-TW notes for the job log and the restore result (review finding HD-09)."""
        notes = []
        if self.special_modes:
            notes.append(f'{self.subject} {volume} 有 {self.special_modes} 個檔案的 setuid／setgid 權限在還原時會被移除'
                         f'（例如 {"、".join(self.special_mode_samples)}）；需要這些權限的程式可能無法正常運作。')
        if self.dropped_xattrs:
            notes.append(f'{self.subject} {volume} 有 {self.dropped_xattrs} 個檔案的延伸屬性（{"、".join(self.dropped_xattr_names)}）'
                         f'在還原時會被移除，例如 file capabilities（例如 {"、".join(self.dropped_xattr_samples)}）；'
                         '只有 user.* 屬性會保留。')
        return notes

    def link_note(self, name):
        """Backup-log note about symlinks that leave a host directory (kept as links; their targets are not in it)."""
        if not self.outside_links:
            return None
        return (f'{self.subject} {name} 有 {self.outside_links} 個符號連結指向資料夾以外（例如 '
                f'{"、".join(self.outside_link_samples)}）；連結本身會備份與還原，但它指向的內容不在這份備份中。')


class _VolumePolicy:
    """Order-aware member rules; one instance per pass over a volume (or host directory) tar.

    Names are remembered as keyed 128-bit digests (a random key per pass, so a crafted archive cannot aim at
    a collision; a collision could only refuse a valid archive): a str per member cost about twice the memory.
    `what` is VOLUME or DIRECTORY; a host directory keeps symlinks that point outside it (see the module notes).
    """

    def __init__(self, ids=None, what=VOLUME):
        self.kinds = {}        # digest of an explicit member -> kind code
        self.implicit = set()  # digests of parents created implicitly by the unpacker
        self.ids = ids         # (uid IdMap, gid IdMap) of the owner's user namespace, or None
        self.what = what
        self.report = VolumeReport(what)
        self._key = secrets.token_bytes(16)

    def _digest(self, name):
        return int.from_bytes(hashlib.blake2b(name.encode(ENCODING, ERRORS), digest_size=16, key=self._key).digest(),
                              'little')

    def admit(self, member):
        what = self.what
        name = _normalize(member.name, what)
        if member.type == tarfile.DIRTYPE:
            kind = 'dir'
        elif member.type in REGULAR:
            kind = 'file'
        elif member.type == tarfile.SYMTYPE:
            kind = 'symlink'
        elif member.type == tarfile.LNKTYPE:
            kind = 'link'
        elif member.type == tarfile.FIFOTYPE:
            kind = 'fifo'
        else:
            raise _bad(what, 'member type not allowed (device, sparse or unknown)', '裝置檔或不支援的檔案類型',
                       member=name[:200], type=member.type.decode('latin-1'))
        if name == '.' and kind != 'dir':
            raise _bad(what, 'the volume root is not a directory')
        key = self._digest(name)
        if key in self.kinds:
            raise _bad(what, 'duplicate member', member=name[:200])
        if kind != 'dir' and key in self.implicit:
            raise _bad(what, 'a non-directory replaces a directory', member=name[:200])
        parts = [] if name == '.' else name.split('/')
        for depth in range(1, len(parts)):
            prefix = self._digest('/'.join(parts[:depth]))
            if self.kinds.get(prefix, 0) != 0:
                raise _bad(what, 'member below a symlink, hard link or file', member=name[:200])
            self.implicit.add(prefix)
        link = None
        outside = False
        if kind == 'link':
            link = _normalize(member.linkname, what)
            target = self.kinds.get(self._digest(link))
            if target is None or CODE_KINDS[target] not in LINKABLE:
                raise _bad(what, 'hard link to something other than an earlier non-directory member', member=name[:200])
        elif kind == 'symlink':
            link = member.linkname
            if not isinstance(link, str) or not link or '\x00' in link or len(link) > MAX_NAME:
                raise _bad(what, 'invalid symlink target', member=name[:200])
            if what == DIRECTORY:
                outside = link.startswith('/') or _escapes(name, link)
            elif _escapes(name, link):
                raise _bad(what, 'symlink pointing outside the volume', '指向資料卷外的符號連結',
                           member=name[:200], target=link[:200])
        if self.ids is not None:
            uid, gid = int(member.uid), int(member.gid)
            if uid not in self.ids[0] or gid not in self.ids[1]:
                tool = 'Podman 無法匯入' if what == VOLUME else '無法以應用帳號還原'
                raise BackupError('incompatible', f'{what}中的 {name[:200]} 屬於 UID {uid}／GID {gid}，超出這台設備應用帳號'
                                                  f'可用的 ID 範圍（UID {self.ids[0].describe()}；GID {self.ids[1].describe()}），'
                                                  f'{tool}；這台設備沒有任何變更。',
                                  reason='owner id outside the user namespace', label=f'擁有者 UID {uid}／GID {gid} 超出帳號可用的範圍',
                                  member=name[:200], uid=uid, gid=gid)
        self.kinds[key] = KIND_CODES[kind]
        self.report.members += 1
        self.report.note(member, name, kind)
        if outside:
            self.report.note_outside_link(name)
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
    # GNU tar writes nanosecond mtimes ("1700000000.123456789"); tarfile keeps a float (about 100 ns here). A
    # plain decimal string is passed on as is, so a host directory keeps its exact modification times.
    exact = member.pax_headers.get('mtime')
    if isinstance(exact, str) and MTIME_RE.fullmatch(exact):
        info.pax_headers['mtime'] = exact
    return info


def _check(path, ids, what):
    policy = _VolumePolicy(ids, what)
    with _open(path, what, 'r|') as tar:
        for member in _members(tar, what, MAX_VOLUME_MEMBERS):
            policy.admit(member)
    return policy.report


def _stream(path, out, ids, what):
    policy = _VolumePolicy(ids, what)
    with _open(path, what, 'r|') as tar, \
            tarfile.open(fileobj=out, mode='w|', format=tarfile.PAX_FORMAT, encoding=ENCODING, errors=ERRORS,
                         bufsize=COPY_CHUNK) as dest:
        for member in _members(tar, what, MAX_VOLUME_MEMBERS):
            name, kind, link = policy.admit(member)
            info = _volume_info(member, name, kind, link)
            if kind == 'file':
                source = tar.extractfile(member)
                try:
                    dest.addfile(info, source)
                except OSError:
                    raise _bad(what, 'member data truncated', member=name[:200]) from None
            else:
                dest.addfile(info)
    return policy.report


def check_volume(path, ids=None):
    """Validate a volume tar completely (no output); returns a VolumeReport.

    `ids`: (uid IdMap, gid IdMap) of the owner's user namespace; every member owner must be in it.
    """
    return _check(path, ids, VOLUME)


def stream_volume(path, out, ids=None):
    """Write a canonical tar of the validated members of `path` to the binary file `out`."""
    return _stream(path, out, ids, VOLUME)


def check_dir(path, ids=None):
    """Validate a host directory tar completely (no output); returns a VolumeReport (volume rules, see above)."""
    return _check(path, ids, DIRECTORY)


def stream_dir(path, out, ids=None):
    """Write a canonical tar of the validated members of a host directory tar to the binary file `out`."""
    return _stream(path, out, ids, DIRECTORY)


# ---------------------------------------------------------------- OCI archives

def _split_ref(ref):
    """(registry or None, path, tag or None, digest or None) of an image reference, without normalizing."""
    name, _, digest = ref.partition('@')
    slash, colon = name.rfind('/'), name.rfind(':')
    tag = None
    if colon > slash:
        name, tag = name[:colon], name[colon + 1:]
    first, _, rest = name.partition('/')
    if rest and ('.' in first or ':' in first or first == 'localhost'):
        return first, rest, tag, digest or None
    return None, name, tag, digest or None


def _join_ref(registry, path, tag, digest):
    if registry in ('docker.io', 'index.docker.io'):
        registry = 'docker.io'
        if '/' not in path:
            path = f'library/{path}'
    name = f'{registry}/{path}' if registry else path
    if digest:
        return f'{name}@{digest}'  # a tagged and digested name keeps only the digest (like podman)
    return f'{name}:{tag or "latest"}'


def local_name(ref):
    """The name podman gives `ref` locally (libimage NormalizeName, which `podman tag <id> <ref>` and
    `podman load` use): a short name gets `localhost/`, Docker Hub names `library/`, no tag `:latest`.
    `podman image inspect <ref>` and a Quadlet `Image=<ref>` resolve to it (localhost/ is tried first), except a
    short name with an alias (`registries.conf.d/shortnames.conf`, e.g. ubuntu, python, node): an existing image
    under the alias target wins (podman 4.9.3), which the adapter handles (`_resolve_to`)."""
    registry, path, tag, digest = _split_ref(ref)
    return _join_ref(registry or 'localhost', path, tag, digest)


def is_short_ref(ref):
    """True for a reference without a registry (`postgres:16`, `team/app:1`), which podman resolves through
    aliases, `localhost/` and search registries."""
    return isinstance(ref, str) and bool(ref) and _split_ref(ref)[0] is None


def same_image_name(saved, ref):
    """True when `saved` (the name `podman save` wrote for `ref` on the backup device) names the image the
    trusted `ref` means: the same name after normalization; for a short ref the same repository path and tag
    under any registry (the device resolved it through its own search registries), Docker Hub's `library/`
    included."""
    if not isinstance(saved, str) or not saved or len(saved) > 512 or not isinstance(ref, str) or not ref:
        return False
    if saved == ref:
        return True
    registry, path, tag, digest = _split_ref(saved)
    want_registry, want_path, want_tag, want_digest = _split_ref(ref)
    if (digest or None) != (want_digest or None):
        return False
    if not digest and (tag or 'latest') != (want_tag or 'latest'):
        return False
    if registry is not None and not REGISTRY_RE.fullmatch(registry):
        return False
    if want_registry is not None:
        return _join_ref(registry, path, tag, digest) == _join_ref(want_registry, want_path, want_tag, want_digest)
    if registry in ('docker.io', 'index.docker.io') and '/' not in want_path:
        return path in (want_path, f'library/{want_path}')
    return path == want_path


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
    """Validate an OCI archive for `ref`; returns the plan `stream_oci` needs (the image is named `local_name(ref)`)."""
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
        if not isinstance(annotations, dict) or not same_image_name(annotations.get(REF_NAME), ref):
            raise _bad(IMAGE, 'the image name in the archive differs from the name the app needs',
                       '映像名稱與應用需要的不同', ref=str(ref)[:200],
                       saved=str((annotations or {}).get(REF_NAME) if isinstance(annotations, dict) else '')[:200])
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
    name = local_name(ref)  # from the trusted ref, never the archive's annotation
    index_data = json.dumps({'schemaVersion': 2, 'manifests': [{
        'mediaType': OCI_MANIFEST, 'digest': f'sha256:{manifest_hex}', 'size': len(manifest_data),
        'annotations': {REF_NAME: name}}]}, separators=(',', ':')).encode()
    return {'ref': ref, 'name': name, 'image_id': f'sha256:{config_hex}', 'index': index_data, 'blobs': blobs}


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
