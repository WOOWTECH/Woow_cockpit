"""Home Assistant import: what the batch 1 importers (ha_omnigent, ha_hermes, ha_emqx, ha_headscale) share --
reading the live target as its Quadlet files describe it, writing a volume tar from an HA tree, copying a live
volume export, small text scans and version tables (CONTRACT section 9 "Home Assistant import"). Owner: E2.

Writing a volume tar (`TreeTar`): every member gets the owner the caller names, permission bits without setuid/setgid,
the HA entry's mtime; a symlink is written as a link entry with its target as stored (habackup already admitted it),
a hard link only when it names a regular file this tar already holds -- a file the caller skipped or deferred can
never be the target of a later link, and a subtree is never cut in half silently (HAOS parity, 2026-11-25, CM-11): the
file is copied instead (`hardlink(..., entry=entry)`: the reader hands it out again as a regular file), and what cannot
be copied is left out and listed in the walk's `report` (kind `hardlink`), never silently. The same list takes the
symlinks that would leave the volume (kind `symlink`; X-NS-08): the restore refuses such a link (nested.py), so a
conversion that is given a `report` leaves it out and says so; without a `report` nothing changes.
"""
import ipaddress
import json
import os
import re
import tarfile
import time
import unicodedata

from . import habackup, nested, podman, tempctr, util
from .errors import BackupError
from .ha_n8n import URL_HOST_RE
from .ha_odoo import (ELF_MACHINES, FileTar, _copy_info, _live_tar, _norm, _under, host_elf_machine,  # noqa: F401
                      quadlet_container_name, quadlet_mounts)

LABELS_OUTPUT = 256 * 1024
LIVE_JSON_OUTPUT = 64 * 1024 * 1024        # one JSON cell of this device's own database (was 4 MiB: a catalog can be bigger)
LIVE_JSON_CEILING = 256 * 1024 * 1024
MAX_TEXT_SCAN = 16 * 1024 * 1024
VERSION_RE = re.compile(r'v?([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,4})\Z')


# C0/C1 controls, U+2028/U+2029 and the Unicode bidirectional controls (PropList Bidi_Control: U+061C, U+200E,
# U+200F, U+202A-U+202E, U+2066-U+2069, which reorder how the text after them reads).
CONTROL_RE = re.compile(r'[\x00-\x1f\x7f-\x9f\u2028\u2029\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]')


# What a shown name never carries as it is (EMQX security re-review 2026-11-24, iteration 8, O-2): every character of
# the Unicode general categories Cc (controls), Cf (format: the bidirectional controls above, and also the zero-width
# space / joiners U+200B-U+200D, the word joiner U+2060, the byte order mark U+FEFF, the soft hyphen U+00AD and the tag
# characters, which make two names look alike or hide text), Cs (lone surrogates of an undecodable name), Cn
# (unassigned) and Zl / Zp (line and paragraph separators). A superset of CONTROL_RE.
HIDDEN_CATEGORIES = frozenset(('Cc', 'Cf', 'Cs', 'Cn', 'Zl', 'Zp'))


def clean(text, limit=60):
    """`text` cut at `limit` characters, every HIDDEN_CATEGORIES character shown as `?`."""
    return ''.join('?' if unicodedata.category(ch) in HIDDEN_CATEGORIES else ch for ch in str(text)[:limit])


def names(items, limit=10):
    """`a、b、c 等 N 個` (each item cut at 60 characters; control and format characters shown as `?` (clean): a name
    from HA's backup -- a table, schema or extension name -- can hold a line break, a terminal escape, a bidirectional
    control or a zero-width character, and these messages reach the job log and the page; secreview SR-4, the
    verifier's bidi gap and the EMQX re-review's O-2)."""
    items = list(items)
    return '、'.join(clean(item) for item in items[:limit]) + (f' 等 {len(items)} 個' if len(items) > limit else '')


# ====================================================================== versions

def semver(text):
    """'0.29.4' of 'v0.29.4' / '0.29.4' (x.y.z only), else None."""
    match = VERSION_RE.fullmatch(text.strip()) if isinstance(text, str) else None
    return '.'.join(str(int(part)) for part in match.groups()) if match else None


class VersionTable:
    """The upstream product version each released add-on version ships (kept here, from the add-ons' CHANGELOG and
    Dockerfile). `issues` only informs about a version the table does not know or that cannot be read here (CM-01,
    CM-02: the data's own structure decides); `blocker` is the gate the importers are still changing over from."""

    def __init__(self, product, table):
        self.product = product
        self.table = dict(table)

    def upstream(self, addon_version):
        return self.table.get(addon_version)

    def issues(self, addon_version, target):
        """[haissues.Issue] (haissues.version_issues) of HA's add-on version and this device's version `target`."""
        from .haissues import version_issues
        return version_issues(self.product, addon_version, self.upstream(addon_version), target)

    def blocker(self, addon_version, target):
        """A zh-TW blocker unless the add-on's product version is known and equals `target` (x.y.z)."""
        mine = self.upstream(addon_version)
        if mine is None:
            return (f'無法確認 HA 附加元件版本 {addon_version} 搭配的 {self.product} 版本（這台的資料表還不認得它），'
                    '為避免版本不同而無法匯入；請先更新這台的 Cockpit。')
        if target is None:
            return f'無法讀取這台 {self.product} 的版本。'
        if semver(mine) != semver(target):
            return (f'版本不同：HA 的 {self.product} 是 {mine}（附加元件 {addon_version}），這台是 {target}。'
                    f'請先讓兩邊的 {self.product} 版本一致後再匯入。')
        return None


def image_labels(work, app, ref, *, pull=True):
    """{label: value} of a local image (strings only; {} when it has none). Read as the owner. An image this device does
    not have is downloaded first, as the owner (`hatarget.ensure_image`, CM-05; `pull=False`: never); when that fails only
    this app stops, with the reason."""
    if not isinstance(ref, str) or not tempctr.IMAGE_RE.fullmatch(ref):
        raise BackupError('incompatible', '映像名稱格式不正確。', app=app.id)
    runner = work.runner(app)

    def read():
        return runner.podman('image', 'inspect', '--format', '{{json .Config.Labels}}', ref, timeout=120,
                             max_output=LABELS_OUTPUT, check=False)

    result = read()
    if result.returncode != 0 and pull:
        from . import hatarget
        if hatarget.ensure_image(work, app, ref):    # not here: downloaded (or this app stops, with the reason)
            result = read()
    if result.returncode != 0:
        raise BackupError('incompatible', f'找不到這台使用的映像 {ref[:120]}。', app=app.id)
    try:
        doc = util.loads_strict((result.stdout or b'null').strip() or b'null', max_bytes=LABELS_OUTPUT)
    except ValueError:
        raise BackupError('job-failed', f'無法讀取映像 {ref[:120]} 的標籤。', app=app.id) from None
    if not isinstance(doc, dict):
        return {}
    return {str(k)[:200]: v[:1000] for k, v in list(doc.items())[:200] if isinstance(k, str) and isinstance(v, str)}


# ====================================================================== the live target

def container_file(quadlets, container_name):
    """The `.container` file whose ContainerName= is `container_name`, else None."""
    for name in sorted(quadlets):
        if name.endswith('.container') and quadlet_container_name(quadlets, name) == container_name:
            return name
    return None


def mounted(quadlets, home, target, *, files=None):
    """(container file, volume or path) of the first Volume= whose container target is `target`."""
    for name in sorted(files or quadlets):
        if not name.endswith('.container'):
            continue
        for source, mount_target, _o in quadlet_mounts(quadlets, name, home):
            if mount_target.rstrip('/') == target.rstrip('/'):
                return name, source
    return None, None


def environment(quadlets, name, keys):
    return tempctr.quadlet_environment(quadlets[name], set(keys))


def live_json(work, app, container, user, database, sql, *, size=None):
    """One JSON cell read from a LIVE database container as its user over the socket (`podman exec ... psql`; read
    only; never a statement that writes). A database that is not running (or still starting up) is started first and put
    back when the app's throwaway objects are cleaned (`hatarget.ensure_running`, CM-07); only when that fails, or the
    account or database name does not fit this device's settings, this app stops, and the message says which. `size`:
    the bytes of data the cell is about (a bigger one gets more time and room: X-PD-05, X-PD-04); without it the wait
    follows the size of the open HA backup (`hatarget.size_hint`), the room stays what it is."""
    runner = work.runner(app)
    limit = podman.scaled_limit(LIVE_JSON_OUTPUT, size, ratio=2, ceiling=LIVE_JSON_CEILING)
    from . import hatarget
    data = size if size is not None else hatarget.size_hint(getattr(work, 'ha', None))   # the waits follow the HA backup
    wait = podman.scaled_timeout(120, data)
    started = False
    while True:
        try:
            out = runner.podman('exec', container, 'psql', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-U', user,
                                '-d', database, '-c', sql, timeout=wait,
                                max_output=limit).stdout or b''
            break
        except BackupError as error:
            if error.code != 'job-failed':
                raise
            reason = podman.reason_code(error)
            if not started and reason in ('no-container', 'db-not-ready'):
                from . import hatarget
                hatarget.ensure_running(work, app, container, ready='postgres', size=data)
                started = True
                continue
            sentence = podman.SENTENCES.get(reason)
            if reason in LIVE_REASONS and sentence:
                raise BackupError('job-failed', f'無法讀取這台「{app.name}」的資料庫：{sentence}', app=app.id,
                                  reason=reason) from None
            raise BackupError('job-failed', f'無法讀取這台「{app.name}」的資料庫，請確認它正在執行。', app=app.id) from None
    try:
        return util.loads_strict(out.strip() or b'null', max_bytes=limit)
    except ValueError:
        raise BackupError('job-failed', f'無法讀取這台「{app.name}」的資料庫。', app=app.id) from None


# What the customer is told when the database of this device cannot be read for a reason the account or the name tells
# (the other reasons keep the old sentence: "make sure it is running").
LIVE_REASONS = frozenset({'db-auth', 'db-missing', 'role-missing', 'no-user-manager', 'no-space', 'permission'})


def live_export(work, app, volume, path, *, size=None):
    """`podman volume export` of a live volume into the staging file `path` (0600), read while the app runs. `size`: the
    volume's bytes when known (the wait grows with it: X-PD-05; the 3 hours of before are the floor)."""
    with open(path, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        work.runner(app).relay(['volume', 'export', volume], stdout=handle, timeout=podman.scaled_timeout(3 * 3600, size),
                               max_output=work.guard.budget(), abort=work.abort)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def link_escapes(name, target):
    """True when the symlink `name` -> `target` leaves the volume, by the restore's own rule (nested._escapes: the target
    joined to the link's folder, an absolute one too)."""
    return nested._escapes(name, target)


def copy_live(src_path, out, *, drop=lambda _name: False, what='這台的資料卷', report=None, label=''):
    """Copy a live volume export into the FileTar `out` without the members `drop(name)` says (names normalised,
    '.' for the root); returns {name: (uid, gid, mode)} of the directories it read (also dropped ones).

    `report` (a habackup.Report; X-NS-08, CM-11): the restore refuses a symlink that leaves the volume and a hard link
    to a member that is not in the archive. A customer's own link of that kind is left out of the copy instead, and
    listed in the report with its full count (`symlink`, `hardlink`; `label` goes in front of the name, e.g. the volume's
    name): the importer asks the customer once (`Sink.skipped(report)`), the rest of the volume is copied as it is. Without
    a `report` everything is copied as before."""
    dirs = {}
    kept = set()
    try:
        with _live_tar(src_path, what) as tar:
            for member in tar:
                name = _norm(member.name)
                if name is None:
                    raise BackupError('job-failed', f'{what}的匯出內容格式不正確。')
                if member.isdir():
                    dirs[name] = (member.uid, member.gid, member.mode & 0o7777)
                if not drop(name):
                    if report is not None and member.issym() and link_escapes(name, member.linkname):
                        report.skip('symlink', f'{label}{name}')
                    elif report is not None and member.islnk() and _norm(member.linkname) not in kept:
                        report.skip('hardlink', f'{label}{name}')
                    else:
                        out.add_member(_copy_info(member, name), tar.extractfile(member) if member.isfile() else None)
                        kept.add(name)
                tar.members.clear()
    except tarfile.TarError:
        raise BackupError('job-failed', f'{what}的匯出內容無法讀取。') from None
    return dirs


def top_only(out, root):
    """A volume tar with only its top directory, owned like the live one (`root` = (uid, gid, mode))."""
    uid, gid, mode = root
    out.add_member(info('.', 'dir', mode=mode, uid=uid, gid=gid, mtime=time.time()))


# ====================================================================== writing an HA tree

def info(name, kind, *, mode, uid, gid, mtime, size=0, linkname=None):
    item = tarfile.TarInfo(name)
    item.type = {'file': tarfile.REGTYPE, 'dir': tarfile.DIRTYPE, 'symlink': tarfile.SYMTYPE,
                 'hardlink': tarfile.LNKTYPE}[kind]
    item.mode, item.uid, item.gid = mode, uid, gid
    item.uname = item.gname = ''
    item.mtime = int(mtime) if isinstance(mtime, (int, float)) and mtime >= 0 else int(time.time())
    item.size = size if kind == 'file' else 0
    if linkname is not None:
        item.linkname = linkname
    return item


class _Exact:
    """read(n) of an habackup Entry that returns n bytes until its end (tarfile's copy needs whole reads)."""

    def __init__(self, entry, guard=None):
        self.entry, self.guard = entry, guard

    def read(self, n=-1):
        parts, have = [], 0
        while n < 0 or have < n:
            data = self.entry.read(habackup.CHUNK if n < 0 else min(n - have, habackup.CHUNK))
            if not data:
                break
            parts.append(data)
            have += len(data)
        if self.guard is not None:
            self.guard.wrote(have)
        return b''.join(parts)


class TreeTar:
    """A volume tar written from an HA tree (see the module notes). `uid`/`gid`: every member's owner. `report`: the walk's
    habackup.Report; what cannot be written is left out and listed in it (a link that leaves the volume: `symlink`; a
    hard link whose file is not in the tar and cannot be copied: `hardlink`), for the one confirmation line
    (`Sink.skipped`). Without one the tar is written as before and a hard link without its file stops the import."""

    def __init__(self, path, uid, gid, guard=None, report=None):
        self.tar = FileTar(path, guard)
        self.uid, self.gid = uid, gid
        self.guard = guard
        self.report = report
        self.files = set()      # names of the regular files written (hard link targets)
        self.copied = 0         # hard links the reader hands out again as regular files (hardlink(entry=...))
        self.counts = {'files': 0, 'dirs': 0, 'symlinks': 0, 'hardlinks': 0, 'bytes': 0}

    @property
    def path(self):
        return self.tar.path

    def root(self, mode, uid=None, gid=None):
        self.tar.add_member(info('.', 'dir', mode=mode & 0o1777, uid=self.uid if uid is None else uid,
                                 gid=self.gid if gid is None else gid, mtime=time.time()))

    def dir(self, name, mode, mtime):
        self.tar.add_member(info(name, 'dir', mode=mode & 0o1777, uid=self.uid, gid=self.gid, mtime=mtime))
        self.counts['dirs'] += 1

    def file(self, name, entry, mode):
        self.tar.add_member(info(name, 'file', mode=mode & 0o777, uid=self.uid, gid=self.gid, mtime=entry.mtime,
                                 size=entry.size), _Exact(entry, None))
        self.files.add(name)
        self.counts['files'] += 1
        self.counts['bytes'] += entry.size

    def data(self, name, data, mode, mtime):
        import io
        self.tar.add_member(info(name, 'file', mode=mode & 0o777, uid=self.uid, gid=self.gid, mtime=mtime,
                                 size=len(data)), io.BytesIO(data))
        self.files.add(name)
        self.counts['files'] += 1
        self.counts['bytes'] += len(data)

    def symlink(self, name, target, mtime):
        """Write a link entry. One that leaves the volume (the restore refuses it) is left out and listed when the tar has
        a report (X-NS-08); returns whether it was written."""
        if self.report is not None and link_escapes(name, target):
            self.report.skip('symlink', name)
            return False
        self.tar.add_member(info(name, 'symlink', mode=0o777, uid=self.uid, gid=self.gid, mtime=mtime,
                                 linkname=target))
        self.counts['symlinks'] += 1
        return True

    def hardlink(self, name, target, mtime, *, entry=None):
        """Write a hard link to a regular file this tar already holds ('link'). Any other: the file is copied instead when
        the walk's `entry` can say so (`entry.copy_later()`: the reader hands the same name out again, after the walk, as a
        regular file with the content: 'copy'; CM-11), else left out and listed in the report ('skip'), else the import
        stops as it always did."""
        if target in self.files:
            self.tar.add_member(info(name, 'hardlink', mode=0o644, uid=self.uid, gid=self.gid, mtime=mtime,
                                     linkname=target))
            self.counts['hardlinks'] += 1
            return 'link'
        copy_later = getattr(entry, 'copy_later', None)
        if copy_later is not None:
            copy_later()
            self.copied += 1
            return 'copy'
        if self.report is not None:
            self.report.skip('hardlink', name)
            return 'skip'
        raise BackupError('incompatible', f'HA 備份中的 {name[:200]} 是另一個沒有搬過來的檔案的硬連結，無法只搬一半；'
                                          '已停止。', member=name[:200], target=target[:200])

    def close(self):
        self.tar.close()


# ====================================================================== text scans

# Hosts that exist only inside Home Assistant OS: the Supervisor and Core names, the hassio network 172.30.32.0/23,
# `*.local` (mDNS names of the HA box) and add-on host names `<8 hex>-<slug>` / `core-<slug>` / `a0d7b954-<slug>`.
# localhost and 127.0.0.1 are left out: inside a container they mean the container on both sides.
HA_ONLY_HOST_RE = re.compile(r'(?:supervisor|homeassistant|hassio|core-[a-z0-9_-]+|[0-9a-f]{8}-[a-z0-9][a-z0-9_-]{0,62}'
                             r'|172\.30\.3[23]\.[0-9]{1,3}|[a-z0-9-]{1,63}\.local)\Z', re.I)


def ha_hosts(text, limit=50):
    """Sorted HA-only hosts (HA_ONLY_HOST_RE) that URLs in `text` name (bounded)."""
    found = set()
    for match in URL_HOST_RE.finditer(text[:MAX_TEXT_SCAN]):
        host = match.group(1).strip('[]').lower()
        if HA_ONLY_HOST_RE.fullmatch(host):
            found.add(host[:100])
            if len(found) >= limit:
                break
    return sorted(found)


def scalars(text, max_bytes=1024 * 1024):
    """{dotted.key: value} of the plain `key: value` mappings of a simple YAML text (block mappings by indentation,
    scalar values with optional quotes; lists, flow values and anchors are skipped). Enough for the few settings the
    importers compare; never used to decide anything a wrong parse could make unsafe."""
    if not isinstance(text, str) or len(text) > max_bytes:
        return {}
    result, stack = {}, []
    for raw in text.splitlines():
        line = raw.split(' #', 1)[0].rstrip() if not raw.lstrip().startswith('#') else ''
        if not line.strip() or line.lstrip().startswith('-'):
            continue
        indent = len(line) - len(line.lstrip(' '))
        match = re.fullmatch(r'\s*([A-Za-z0-9_.-]{1,100}):(?:\s+(.*))?', line)
        if not match:
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        key = '.'.join([k for _i, k in stack] + [match.group(1)])
        value = (match.group(2) or '').strip()
        if not value:
            stack.append((indent, match.group(1)))
            continue
        if value[:1] in ('"', "'") and value[-1:] == value[:1] and len(value) >= 2:
            value = value[1:-1]
        elif value[:1] in ('[', '{', '&', '*', '|', '>'):
            continue
        result[key[:300]] = value[:2000]
    return result


def network(text):
    """ipaddress network of a prefix text (strict=False), else None."""
    try:
        return ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        return None


def foreign_elf(head, machine):
    """True when `head` (a file's first 20 bytes) starts a 64/32-bit Linux program or library for another
    processor than `machine`."""
    if machine is None or len(head) < 20 or head[:4] != b'\x7fELF':
        return False
    order = 'little' if head[5] == 1 else 'big'
    return int.from_bytes(head[18:20], order) != machine


def strict_json(data, max_bytes):
    try:
        return util.loads_strict(data, max_bytes=max_bytes)
    except ValueError:
        return None


def json_text(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))

