"""Home Assistant import, OpenDesign part: the WOOWTECH add-on `woow_ha_opendesign` -> this device's app `open-design`
(CONTRACT section 9 "Home Assistant import"; facts phase3/facts/opendesign.md). Owner: E2.

The add-on persists only /data: the OpenDesign daemon's data folder is `data/opendesign` (OD_DATA_DIR), the built-in
MCP server's token and tool grants are `data/mcp`, HA's options `data/options.json` (never read). The target is the
Podman package: the volume `open-design_open_design_data` at /app/.od (the daemon and the terminal, `keep-id`, so the
owner's namespace root is the daemon's user) and `open-design_mcp_data` at /data/mcp (the MCP server's state). There is
no database server: the daemon keeps everything in the SQLite file `app.sqlite` (WAL) and plain files.

Versions (HAOS parity, 2026-11-25, OP-01, OP-02): the data has no version stamp (the daemon migrates `app.sqlite`
forward silently), so the add-on version maps to the WoowTech fork revision of the OpenDesign core it ships (VERSIONS,
from the add-on's CHANGELOG and its image label). The table only informs: an add-on version it does not know, and a
live image that carries no revision label, are notices (the import goes on; the restore's own health check and its
automatic roll-back are the net). Only when both revisions are known and differ the app stops (OP-03: installing HA's
core on this device is a later phase).

What moves (owner decisions 2026-11-23 「決定2 A」 = the facts' recommended answers O1-O5): the database `app.sqlite`
with its WAL (never the `-shm` wal-index), projects, runs, artifacts, design systems and templates, brands, library,
memory, skills, plugins, the user's own third-party settings stored as data (O4: `mcp-config.json`,
`mcp-tokens.json`, `mcp-oauth-clients.json`, `connectors/`, `media-config.json`) and HA's preferences
(`app-config.json` without this device's `installationId`, `agentCliEnv` and `agentCliEnvIntent`; project locations
and recent folders below /data/opendesign are rewritten to /app/.od, others dropped); HA's `shared/workspaces` and
`shared/skills` are copied inert (O5). What stays this device's: the agents' logins and caches `home/` (O1), the
Omnigent host identity `integrations/` and the Paseo pairing `paseo/` (O2), `installation.json`, the MCP volume (O3:
token and tool grants), secrets, `open-design.env`, nginx configuration and units. Left out of HA's tree: `home/`,
`paseo/`, `integrations/`, `installation.json`, `diagnostics/`, `od-next-*-inputs/`, `agent-runtime/`, `export-*`,
the withdrawn `credentials`, `.backup/` (retired Omnigent archives), `shared/mcp`, `shared/plugins`. A top-level entry
this table does not know (with something in it) is not moved and not dropped silently: it is one line of the ONE
confirmation (`opendesign.unknown-entries`, OP-10), and so is everything the reader had to leave out (`files.skipped`).

Hard links (OP-11, OP-16): a moved file that is a hard link to a file that does not move is written as a file with
the content (the reader hands it out again: Entry.copy_later), unless that file is a login or an identity of HA (the
agents' logins, the Paseo pairing, the Omnigent identity, the preferences that are rewritten): then the link is left
out and listed. A kept file of this device that is a hard link to a file that is replaced is written as a file with its
live content (the first one of a file; the others link to it). Every moved entry is owned like the live volume's top
folder (0:0 in the owner's namespace = the daemon's user), permission bits without setuid/setgid; relative symlinks
that stay in the tree are link entries, others are skipped and counted. The kept parts are copied from a live export of
the volume (read while the app runs, like Odoo's web data; tried again and, when that does not help, read once with the
app's own containers paused). `app.sqlite` is opened only by the sandboxed child (hasqlite): quick_check and the counts
of projects, conversations, messages and routines.
"""
import contextlib
import io
import json
import os
import re
import tarfile
import time

from . import habackup, haissues, hacommon, hasqlite, hatarget, ha_n8n, ha_odoo, tempctr
from .errors import BackupError
from .haissues import Issue

SLUG = 'woow_ha_opendesign'
APP_ID = 'open-design'
TREE = 'data/opendesign'
HA_MCP = 'data/mcp'             # HA's built-in MCP server's token and tool grants: this device's stay, never read, never copied
DAEMON = 'open-design'          # the daemon's ContainerName (Quadlet open-design.container)
DATA_TARGET = '/app/.od'
MCP_TARGET = '/data/mcp'
HA_DATA = '/data/opendesign'
SOURCE_LABEL = 'io.woow.opendesign.source-revision'
# Add-on version -> (OpenDesign, WoowTech fork revision of the core): Woow_ha_opendesign_add_on CHANGELOG.md 0.2.15
# ("w2.11 core 20261101.2319, WoowTech fork revision 05b23f5a") and the label of ghcr.io/woowtech/woow-ha-opendesign-
# amd64:0.2.15 (facts opendesign.md section 1.1, section 3). Extend per release.
VERSIONS = {'0.2.15': ('0.24.1', '05b23f5a5259d4f2c22e5c6e3eb92ce9103ed34a')}
REVISION_RE = re.compile(r'[0-9a-f]{7,64}\Z')
MOVE_DIRS = frozenset({'projects', 'runs', 'artifacts', 'chat-artifact-blobs', 'critique-artifacts', 'design-systems',
                       'design-templates', 'brands', 'library', 'memory', 'skills', 'plugins', 'connectors'})
DATABASE = 'app.sqlite'
SIDECARS = ('-wal', '-journal')
CONFIGS = ('app-config.json', 'mcp-config.json')           # rewritten JSON (paths), never moved unread
MOVE_FILES = frozenset({DATABASE, *(DATABASE + s for s in SIDECARS), *CONFIGS, 'mcp-tokens.json',
                        'mcp-oauth-clients.json', 'media-config.json'})
SHARED = 'shared'
SHARED_MOVE = frozenset({'workspaces', 'skills'})
# Left out of HA's tree: this device's logins, identities and transient folders, HA-only and retired state.
LEFT_OUT = frozenset({'home', 'paseo', 'integrations', 'installation.json', 'diagnostics', 'od-next-run-inputs',
                      'od-next-task-inputs', 'agent-runtime', 'export-render', 'export-pdf', 'credentials', '.backup',
                      DATABASE + '-shm'})
# Kept from this device's live volume (everything else of it is replaced).
KEEP_LIVE = frozenset({'home', 'paseo', 'integrations', 'installation.json', 'export-render', 'export-pdf'})
TARGET_PREFS = ('installationId', 'agentCliEnv', 'agentCliEnvIntent')
# mcp-config.json entries that this device's integrations write themselves (the Paseo runtime registers `woow-paseo`
# through PUT /api/mcp/servers/woow-paseo, Woow_podman_opendesign paseo/runtime/host/native-mcp.mjs:5-24; the HA
# add-on's points at HA's paths): never moved from HA, this device's own entry stays (decision O2).
OWNED_MCP_SERVERS = frozenset({'woow-paseo'})
MAX_CONFIG = 16 * 1024 * 1024    # was 4 MiB (OP-13): a larger file is left out and listed, this device's own stays
MAX_SCAN = 1024 * 1024
MAX_UNKNOWN = 2000               # names of unknown top-level entries that are tracked (a crafted backup cannot grow it)
COUNTS = ('projects', 'conversations', 'messages', 'routines')
# What `files.skipped` is made of here: the kinds that are lost for sure. Symlinks that leave the data are a reminder of
# their own (most lie in the agents' home, which is left out anyway).
SKIPS = ('name', 'device', 'fifo', 'secret', 'hardlink', 'large')
# Below HA's `home/`: the package managers' caches. A project file that is a hard link into one of them (bun, pnpm) gets the
# content as a file; a hard link into any other place that does not move (a login, an identity) never does.
CACHE_ROOTS = ('home/.bun', 'home/.npm', 'home/.cache', 'home/.pnpm-store', 'home/.yarn', 'home/.local/share/pnpm')
READ_TRIES = 3                   # a read of this device's live data that fails for a moment (OP-15) is tried this often

# Every issue id of this module, with its level (haissues; tests/backup/test_ha_issues.py keeps it exact).
ISSUES = {
    'opendesign.no-folder': 'stop',               # OP-06: HA's backup has no OpenDesign folder (this app only)
    'opendesign.no-database': 'stop',             # OP-07: ... or no app.sqlite (this device would be made empty)
    'opendesign.database-unreadable': 'stop',     # OP-14: the sandboxed reader of app.sqlite did not finish, twice
    'opendesign.database-damaged': 'stop',        # OP-08 (as it was)
    'opendesign.database-not-opendesign': 'stop',  # OP-09 (as it was)
    'opendesign.core-different': 'stop',          # OP-03 (as it was; the later phase that installs HA's core lifts it)
    'opendesign.core-unknown': 'notice',          # OP-01: the table does not know HA's add-on version
    'opendesign.target-core-unknown': 'notice',   # OP-02, OP-05: this device's image carries no (readable) core revision
    'opendesign.unknown-entries': 'confirm',      # OP-10: top-level entries of HA's folder this importer does not know
    'opendesign.links-copied': 'auto',            # OP-11: hard links to files that do not move got the content
    'opendesign.kept-links-copied': 'auto',       # OP-16: this device's kept hard links to replaced files got the content
    'opendesign.service-paused': 'auto',          # OP-15: the app's own containers were paused for one read
    'opendesign.config-kept': 'notice',           # OP-13: a settings file of HA is too large, this device's stays
    'opendesign.foreign-programs': 'notice',
    'opendesign.symlinks-skipped': 'notice',
    'opendesign.project-folders': 'notice',
    'opendesign.ha-addresses': 'notice',
    'opendesign.prefs-unreadable': 'notice',
    'opendesign.prefs-dropped': 'notice',
    'opendesign.mcp-unreadable': 'notice',
    'opendesign.shared-left': 'notice',
    'opendesign.routines-active': 'notice',
}


def _rev(text):
    return text[:8] if isinstance(text, str) else ''


def remap(path):
    """`/data/opendesign[/...]` -> `/app/.od[/...]`, None for any other path."""
    if not isinstance(path, str):
        return None
    if path == HA_DATA:
        return DATA_TARGET
    if path.startswith(HA_DATA + '/') and '/../' not in path + '/' and '/./' not in path + '/':
        return DATA_TARGET + path[len(HA_DATA):]
    return None


def rewrite_strings(value, counter):
    """A copy of a JSON value with every string `/data/opendesign...` remapped (counter[0] counts them)."""
    if isinstance(value, str):
        new = remap(value) if value.startswith(HA_DATA) else None
        if new is not None:
            counter[0] += 1
            return new
        if HA_DATA + '/' in value:
            counter[0] += 1
            return value.replace(HA_DATA + '/', DATA_TARGET + '/')
        return value
    if isinstance(value, list):
        return [rewrite_strings(item, counter) for item in value]
    if isinstance(value, dict):
        return {key: rewrite_strings(item, counter) for key, item in value.items()}
    return value


def merge_prefs(ha_doc, live_doc):
    """(HA's preferences with this device's TARGET_PREFS, number of folders dropped): project locations and recent
    folders below /data/opendesign are remapped, other absolute paths dropped (they do not exist here)."""
    doc = {key: value for key, value in ha_doc.items() if key not in TARGET_PREFS}
    for key in TARGET_PREFS:
        if isinstance(live_doc, dict) and key in live_doc:
            doc[key] = live_doc[key]
    dropped = 0
    locations = doc.get('projectLocations')
    if isinstance(locations, list):
        kept, gone = [], set()
        for item in locations:
            path = remap(item.get('path')) if isinstance(item, dict) else None
            if path is None:
                dropped += 1
                if isinstance(item, dict) and isinstance(item.get('id'), str):
                    gone.add(item['id'])
                continue
            kept.append(dict(item, path=path))
        doc['projectLocations'] = kept
        if doc.get('defaultProjectLocationId') in gone:
            doc['defaultProjectLocationId'] = None
    recent = doc.get('recentLinkedDirs')
    if isinstance(recent, list):
        mapped = [remap(item) for item in recent]
        dropped += sum(1 for item in mapped if item is None)
        doc['recentLinkedDirs'] = [item for item in mapped if item is not None]
    return doc, dropped


def merge_mcp(ha_doc, live_doc):
    """(HA's MCP settings with its paths remapped and this device's own integration entries, number of path strings
    remapped, number of HA's integration entries left out)."""
    counter = [0]
    doc = rewrite_strings({key: value for key, value in ha_doc.items() if key != 'servers'}, counter)
    servers = ha_doc.get('servers') if isinstance(ha_doc.get('servers'), list) else []
    kept = [rewrite_strings(item, counter) for item in servers
            if not (isinstance(item, dict) and item.get('id') in OWNED_MCP_SERVERS)]
    dropped = len(servers) - len(kept)
    live = live_doc.get('servers') if isinstance(live_doc, dict) and isinstance(live_doc.get('servers'), list) else []
    kept += [item for item in live if isinstance(item, dict) and item.get('id') in OWNED_MCP_SERVERS]
    doc['servers'] = kept
    return doc, counter[0], dropped


def json_bytes(doc):
    return (json.dumps(doc, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


class Source:
    def __init__(self):
        self.addon = None
        self.dbs = {}             # staged name -> path (app.sqlite and its sidecars)
        self.configs = {}         # name -> (bytes, mode, mtime) of CONFIGS, written at the end
        self.configs_skipped = set()   # CONFIGS of HA that are too large to read (OP-13): this device's stay
        self.left_out = {}        # top-level name -> entries
        self.unknown = {}         # top-level name -> [entries, entries that are not directories] (at most MAX_UNKNOWN names)
        self.unknown_more = 0     # entries of names beyond that cap (a crafted backup)
        self.shared_left = 0      # files and links of shared/ other than workspaces and skills
        self.shared_moved = 0
        self.foreign = []         # programs for another processor in the moved trees
        self.ha_urls = set()
        self.path_refs = 0        # /data/opendesign strings rewritten in the moved JSON settings
        self.prefs_dropped = 0
        self.prefs_unreadable = False
        self.mcp_unreadable = False
        self.mcp_owned = 0           # HA's integration entries (woow-paseo) in mcp-config.json: left out
        self.mcp_servers = 0         # HA's external MCP servers that move
        self.links_copied = 0        # hard links of HA that got the content of the file they name (OP-11)
        self.tree = False
        self.counts = {}

    def note_unknown(self, top, is_file):
        seen = self.unknown.get(top)
        if seen is None:
            if len(self.unknown) >= MAX_UNKNOWN:
                self.unknown_more += 1
                return
            seen = self.unknown[top] = [0, 0]
        seen[0] += 1
        seen[1] += is_file

    def unknown_names(self):
        """Top-level names HA has that this importer does not know, with something but folders in them."""
        return sorted(name for name, (_entries, files) in self.unknown.items() if files)


class _Count:
    """TreeTar's bookkeeping without an output (the check job); it decides about links exactly like TreeTar does, so the
    check and the conversion list the same names (the key of a confirmation)."""

    def __init__(self, report=None):
        self.files = set()
        self.report = report
        self.counts = {'files': 0, 'dirs': 0, 'symlinks': 0, 'hardlinks': 0, 'bytes': 0}

    def dir(self, name, mode, mtime):
        self.counts['dirs'] += 1

    def file(self, name, entry, mode):
        self.files.add(name)
        self.counts['files'] += 1
        self.counts['bytes'] += entry.size

    def data(self, name, data, mode, mtime):
        self.files.add(name)
        self.counts['files'] += 1
        self.counts['bytes'] += len(data)

    def symlink(self, name, target, mtime):
        if self.report is not None and hacommon.link_escapes(name, target):
            self.report.skip('symlink', name)
            return False
        self.counts['symlinks'] += 1
        return True

    def hardlink(self, name, target, mtime, *, entry=None):
        if target in self.files:
            self.counts['hardlinks'] += 1
            return 'link'
        copy_later = getattr(entry, 'copy_later', None)
        if copy_later is not None:
            copy_later()
            return 'copy'
        if self.report is not None:
            self.report.skip('hardlink', name)
            return 'skip'
        raise BackupError('incompatible', f'HA 備份中的 {name[:200]} 是另一個沒有搬過來的檔案的硬連結，無法只搬一半；'
                                          '已停止。', member=name[:200], target=target[:200])


class _Tee:
    """An Entry read by tarfile while a copy goes to `handle` (the database staged for the SQLite child)."""

    def __init__(self, entry, handle, guard=None):
        self.entry, self.handle, self.guard = entry, handle, guard

    def read(self, n=-1):
        parts, have = [], 0
        while n < 0 or have < n:
            data = self.entry.read(habackup.CHUNK if n < 0 else min(n - have, habackup.CHUNK))
            if not data:
                break
            parts.append(data)
            have += len(data)
        data = b''.join(parts)
        self.handle.write(data)
        if self.guard is not None:
            self.guard.wrote(len(data))
        return data


def _stage_db(entry, rel, staging, out):
    """Write a database file (or sidecar) to `out` and to staging for the SQLite child; returns its staged path."""
    path = staging / rel
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        if isinstance(out, hacommon.TreeTar):
            out.tar.add_member(hacommon.info(rel, 'file', mode=entry.mode & 0o777, uid=out.uid, gid=out.gid,
                                             mtime=entry.mtime, size=entry.size), _Tee(entry, handle))
            out.files.add(rel)
            out.counts['files'] += 1
            out.counts['bytes'] += entry.size
        else:
            entry.copy_to(handle)
            out.data(rel, b'', entry.mode, entry.mtime)
            out.counts['bytes'] += entry.size
        handle.flush()
        os.fsync(handle.fileno())
    return path


def _area(rel):
    """'move' | 'left' | 'shared-move' | 'shared-left' | 'unknown' | 'shared' (the shared/ folder itself)."""
    top, _, rest = rel.partition('/')
    if top == SHARED:
        if not rest:
            return 'shared'
        return 'shared-move' if rest.split('/', 1)[0] in SHARED_MOVE else 'shared-left'
    if top in LEFT_OUT:
        return 'left'
    if top in MOVE_DIRS or (not rest and top in MOVE_FILES):
        return 'move'
    return 'unknown'


def _copy_ok(target):
    """True when the content of `target` (a name below the tree) may be written where a hard link to it is, although the
    file itself does not move (OP-11). Default-deny: a file that moves (its content is moved anyway) or lies in a package
    manager's cache; never the preferences and MCP settings (they are rewritten on the way: their text holds what is not
    moved) and never anything of the agents' logins, the Paseo pairing, the Omnigent identity or a folder this importer
    does not know."""
    if target in CONFIGS:
        return False
    area = _area(target)
    if area in ('move', 'shared-move'):
        return True
    return area == 'left' and any(target == root or target.startswith(root + '/') for root in CACHE_ROOTS)


def _hardlink(src, out, rel, entry):
    """A hard link of HA's tree: written as a link to a file this tar holds; else, when `_copy_ok`, the reader hands the
    same name out again as a file with the content; else it is left out and listed (the one `files.skipped` line)."""
    prefix = TREE + '/'
    target = entry.linkname[len(prefix):] if entry.linkname.startswith(prefix) else ''
    how = out.hardlink(rel, target, entry.mtime, entry=entry if target and _copy_ok(target) else None)
    if how == 'copy':
        src.links_copied += 1


def _config(src, rel, data):
    """Look at a JSON setting HA's daemon wrote (bytes as read): HA-only hosts, /data/opendesign paths, MCP servers."""
    text = data.decode('utf-8', 'replace')
    src.ha_urls.update(f'{rel}：{host}' for host in hacommon.ha_hosts(text))
    if rel == 'mcp-config.json':
        doc = hacommon.strict_json(data, MAX_CONFIG)
        servers = doc.get('servers') if isinstance(doc, dict) else None
        servers = servers if isinstance(servers, list) else []
        owned = sum(1 for item in servers if isinstance(item, dict) and item.get('id') in OWNED_MCP_SERVERS)
        src.mcp_servers, src.mcp_owned = len(servers) - owned, owned


def scan_member(stream, report, staging, out, *, machine=None, checkpoint=None):
    """One strict pass over `data/opendesign/**` into `out` (a TreeTar or _Count; names relative to the tree). The
    database and its sidecars are also staged in `staging` for the SQLite child; the JSON settings are kept in
    `src.configs` for the end of the conversion. Returns a Source. Anything the reader leaves out is in `report`
    (`report.skips`; make it with `habackup.Report(names=haissues.Names)`)."""
    select = habackup.Select(include=(TREE,), exclude=(HA_MCP,), symlinks=(TREE,), hardlinks=True)
    src = Source()
    count = 0
    for entry in habackup.iter_entries(stream, select, report, checkpoint=checkpoint):
        count += 1
        if checkpoint is not None and count % 256 == 0:
            checkpoint()
        if entry.name == TREE:
            if entry.kind != 'dir':
                raise BackupError('incompatible', 'HA 的 OpenDesign 資料夾不是一般目錄，無法安全匯入。', member=TREE)
            src.tree = True
            continue  # the volume's top folder is the live one
        rel = entry.name[len(TREE) + 1:]
        area = _area(rel)
        top = rel.split('/', 1)[0]
        if area == 'left':
            src.left_out[top] = src.left_out.get(top, 0) + 1
            continue
        if area == 'shared-left':
            src.shared_left += entry.kind != 'dir'   # empty folders lose nothing
            continue
        if area == 'unknown':
            src.note_unknown(top[:100], entry.kind != 'dir')
            continue
        if area == 'shared-move':
            src.shared_moved += 1
        special = '/' not in rel and rel in MOVE_FILES
        if (special and entry.kind != 'file') or ((rel in MOVE_DIRS or area == 'shared') and entry.kind != 'dir'):
            raise BackupError('incompatible', f'HA 的 OpenDesign 資料 {rel} 不是一般檔案或目錄，無法安全匯入。', member=rel)
        if entry.kind == 'dir':
            out.dir(rel, entry.mode, entry.mtime)
            continue
        if entry.kind == 'symlink':
            out.symlink(rel, entry.linkname, entry.mtime)
            continue
        if entry.kind == 'hardlink':
            _hardlink(src, out, rel, entry)
            continue
        if rel == DATABASE or rel in (DATABASE + s for s in SIDECARS):
            src.dbs[rel] = _stage_db(entry, rel, staging, out)
            continue
        if rel in CONFIGS:
            data = entry.read_or_skip(MAX_CONFIG)   # OP-13: a file above the limit is left out and listed, not a stop
            if data is None:
                src.configs_skipped.add(rel)
                continue
            _config(src, rel, data)
            src.configs[rel] = (data, entry.mode, entry.mtime)
            continue
        if machine is not None and len(src.foreign) < 1000 and hacommon.foreign_elf(entry.peek(20), machine):
            src.foreign.append(rel)
        if '/' not in rel or rel.startswith('connectors/'):
            if entry.size <= MAX_SCAN:  # the other JSON settings: HA-only hosts (their keys move as they are)
                data = entry.read_all(MAX_SCAN)
                src.ha_urls.update(f'{rel}：{host}' for host in hacommon.ha_hosts(data.decode('utf-8', 'replace')))
                out.data(rel, data, entry.mode, entry.mtime)
                continue
        out.file(rel, entry, entry.mode)
    src.addon = report.addon
    src.counts = dict(out.counts, skipped_symlinks=report.skipped_symlinks)
    return src


def ha_prefs(src):
    """HA's app-config.json document, or None (absent, too large, or not a JSON object)."""
    if 'app-config.json' not in src.configs:
        return None
    doc = hacommon.strict_json(src.configs['app-config.json'][0], MAX_CONFIG)
    return doc if isinstance(doc, dict) else None


def finish_configs(src, out, live_prefs, live_mcp=None, *, keep_mcp=False):
    """Write HA's JSON settings into `out` (TreeTar or _Count): app-config.json merged with this device's
    preferences (`live_prefs`: the live file's document or None), mcp-config.json with its paths remapped, without
    HA's integration entries and with this device's (`live_mcp`). A setting that is not a JSON object is left out:
    this device's app-config.json stays (copy_kept), an unreadable mcp-config.json leaves only this device's
    integration entries (the daemon starts without HA's external MCP servers). A file of HA that was too large to read
    (`src.configs_skipped`, OP-13) is not taken: this device's own app-config.json stays and, with `keep_mcp`, so does its
    whole mcp-config.json (copy_kept took it over as it is)."""
    for rel in CONFIGS:
        if rel not in src.configs:
            if rel == 'mcp-config.json' and live_mcp is not None and not keep_mcp:
                doc, _refs, _dropped = merge_mcp({}, live_mcp)
                if doc['servers']:
                    out.data(rel, json_bytes(doc), 0o600, int(time.time()))
            continue
        data, mode, mtime = src.configs[rel]
        if rel == 'app-config.json':
            doc = ha_prefs(src)
            if doc is None:
                src.prefs_unreadable = True
                continue
            doc, src.prefs_dropped = merge_prefs(doc, live_prefs)
        else:
            doc = hacommon.strict_json(data, MAX_CONFIG)
            if not isinstance(doc, dict):
                src.mcp_unreadable = True
                doc = {}
            doc, refs, _owned = merge_mcp(doc, live_mcp)
            src.path_refs += refs
            if src.mcp_unreadable and not doc['servers']:
                continue
        out.data(rel, json_bytes(doc), mode, mtime)
    src.counts.update(out.counts)


# ====================================================================== the live target

class Target:
    """The open-design app's catalog items the import fills, resolved against the live Quadlet files."""

    def __init__(self, work, app):
        quadlets = work.quadlets(app)
        home = work.runner(app).home
        declared = [v['name'] for v in app.volumes]
        daemon_file = hacommon.container_file(quadlets, DAEMON)
        data_volume = mcp_volume = None
        if daemon_file is not None:
            data_volume = next((source for source, target, _o in ha_odoo.quadlet_mounts(quadlets, daemon_file, home)
                                if target.rstrip('/') == DATA_TARGET), None)
        _mcp_file, mcp_volume = hacommon.mounted(quadlets, home, MCP_TARGET)
        if (daemon_file is None or data_volume not in declared or mcp_volume not in declared or data_volume == mcp_volume
                or len(declared) != 2 or app.postgres or app.data_dirs):
            raise BackupError('incompatible', '這台的 OpenDesign 應用設定和 Quadlet 檔不一致，無法匯入。', app=app.id)
        self.data_volume, self.mcp_volume = data_volume, mcp_volume
        self.image = tempctr.quadlet_image(quadlets[daemon_file])
        if not self.image:
            # nothing to download: a service whose Quadlet file names no image cannot start (OP-05 keeps this stop)
            raise BackupError('incompatible', '這台 OpenDesign 的 Quadlet 設定缺少映像。', app=app.id)


def target_core(work, app, target):
    """(fork revision, OpenDesign version) of the live image (label and OD_APP_VERSION; None when unknown). An image that
    is not on this device is downloaded first (hacommon.image_labels, OP-05: this app stops only when that cannot be
    done); a label that cannot be read is an unknown revision, not a stop."""
    try:
        labels = hacommon.image_labels(work, app, target.image)
    except BackupError as error:
        if error.code != 'job-failed' or haissues.is_job_wide(error):
            raise
        labels = {}
    revision = labels.get(SOURCE_LABEL, '').strip().lower()
    image = work.adapter(app).image_inspect(target.image) or {}
    version = next((item.split('=', 1)[1] for item in image.get('env') or []
                    if isinstance(item, str) and item.startswith('OD_APP_VERSION=')), None)
    return (revision if REVISION_RE.fullmatch(revision) else None), hacommon.semver(version or '')


CORE_UNKNOWN = ('這台的版本對照表還不認得 HA 的 OpenDesign 附加元件版本 {version}，不用版本判斷能不能匯入；'
                '如果 HA 的資料庫比這台的 OpenDesign 新，這台可能看不懂它。匯入後會自動檢查，OpenDesign 啟動不了會自動退回。')
TARGET_CORE_UNKNOWN = ('讀不到這台 OpenDesign 的核心版本（映像沒有 io.woow.opendesign.source-revision 標籤，或讀不出來），'
                       '這次不比對版本；匯入後請確認 OpenDesign 能正常使用。')
CORE_DIFFERENT = ('版本不同：HA 的 OpenDesign 核心是 {ha}（OpenDesign {ha_version}，附加元件 {addon}），'
                  '這台是 {mine}（OpenDesign {mine_version}）。')
CORE_DIFFERENT_ACTION = '請先把這台的 OpenDesign 換成同一個核心版本，再匯入。'


def version_issues(addon_version, revision, version):
    """The notices and the one stop about versions (OP-01, OP-02, OP-03): the table that maps HA's add-on version to a core
    revision only informs; both revisions known and different stops this app."""
    mine = VERSIONS.get(addon_version)
    found = []
    if mine is None:
        found.append(Issue('opendesign.core-unknown', 'notice',
                           CORE_UNKNOWN.format(version=haissues.clean(addon_version, 40) or '（讀不到）')))
    if revision is None:
        found.append(Issue('opendesign.target-core-unknown', 'notice', TARGET_CORE_UNKNOWN))
    if mine is not None and revision is not None and revision != mine[1] \
            and not (len(revision) < len(mine[1]) and mine[1].startswith(revision)):
        found.append(Issue('opendesign.core-different', 'stop',
                           CORE_DIFFERENT.format(ha=_rev(mine[1]), ha_version=mine[0],
                                                 addon=haissues.clean(addon_version, 40), mine=_rev(revision),
                                                 mine_version=version or '版本不明'),
                           action=CORE_DIFFERENT_ACTION))
    return found


NO_FOLDER = 'HA 備份裡沒有 OpenDesign 的資料夾（data/opendesign），沒有可搬的資料。'
NO_FOLDER_ACTION = '請確認 HA 的 OpenDesign 有資料後重新備份，再匯入；這台的 OpenDesign 不會有任何變更。'
NO_DATABASE = 'HA 備份裡沒有 OpenDesign 的資料庫（app.sqlite），可能從來沒有啟動過；沒有專案與對話可搬。'
NO_DATABASE_ACTION = '請先在 HA 啟動一次 OpenDesign、確認專案都在後重新備份，再匯入；這台的 OpenDesign 不會被換成空的。'
DATABASE_UNREADABLE = ('無法確認 HA 的 OpenDesign 資料庫是否完好：讀取它的獨立程式沒有在時限內完成，或中途結束（已自動再試一次）。'
                       '這次不匯入 OpenDesign，這台的 OpenDesign 沒有任何變更。')
DATABASE_UNREADABLE_ACTION = '請等這台比較不忙的時候再匯入一次；仍然不行時，請把作業紀錄交給工程人員。'
UNKNOWN_ENTRIES = ('HA 的 OpenDesign 資料夾裡有 {count} 個這台的匯入程式還不認得的項目{more}；它們不會搬過來，會留在 HA，'
                   '其他資料照常搬。需要它們時，請在匯入後自行從 HA 複製。')


def collect(sink, src, answers, report):
    """What HA's OpenDesign says about itself, as issues (the check and the conversion call it the same way: in a
    conversion a stop raises and a line that was not confirmed raises `confirmation-required`). Returns the counts of
    the database. The versions (`version_issues`) are the caller's, the skipped files `skip_line`'s."""
    if not src.tree:
        sink.stop('opendesign.no-folder', NO_FOLDER, action=NO_FOLDER_ACTION)
    elif DATABASE not in src.dbs:
        sink.stop('opendesign.no-database', NO_DATABASE, action=NO_DATABASE_ACTION)
    details = {name: 0 for name in COUNTS}
    details.update(project_folders=0, project_folders_ha=0)
    answer = answers.get(DATABASE)
    if answer is not None:
        why = hasqlite.problem(answer)
        if why:
            sink.stop('opendesign.database-damaged', f'HA 的 OpenDesign 資料庫 app.sqlite 已損毀或無法讀取（{why}）。',
                      action='請在 HA 重新備份後再匯入；這台的 OpenDesign 不會有任何變更。')
        else:
            counts = answer.get('counts') or {}
            for name in COUNTS:
                details[name] = ha_odoo._int(counts.get(name))
            if 'projects' not in counts:
                sink.stop('opendesign.database-not-opendesign',
                          'HA 的 OpenDesign 資料庫沒有專案資料表，不像是 OpenDesign 的資料，無法匯入。',
                          action='請確認備份的是 HA 的 OpenDesign 附加元件，再重新備份後匯入。')
            values = answer.get('values') or {}
            rows = values.get('opendesign.project_folders')
            if isinstance(rows, list) and rows and isinstance(rows[0], list) and len(rows[0]) == 2:
                details['project_folders'] = ha_odoo._int(rows[0][0])
                details['project_folders_ha'] = ha_odoo._int(rows[0][1])
            details['routines_active'] = ha_odoo._int(values.get('opendesign.routines_active'))
    unknown = src.unknown_names()
    if unknown:
        sink.confirm('opendesign.unknown-entries',
                     UNKNOWN_ENTRIES.format(count=len(unknown), more='（還有更多沒有列出）' if src.unknown_more else ''), unknown)
    if report.copied_links:
        sink.auto('opendesign.links-copied',
                  f'HA 的 OpenDesign 有 {report.copied_links} 個硬連結的檔案，這台不能把它們連在一起，已改成各自複製檔案內容'
                  '（磁碟用量會比 HA 大一些）。')
    if src.foreign:
        sink.notice('opendesign.foreign-programs',
                    f'HA 的 OpenDesign 專案中有其他處理器的程式（{len(src.foreign)} 個，例如 '
                    f'{hacommon.names(src.foreign, 3)}），搬過來後無法執行，需要時請在這台重新安裝。')
    if src.counts.get('skipped_symlinks'):
        sink.notice('opendesign.symlinks-skipped',
                    f'HA 的 OpenDesign 資料中有 {src.counts["skipped_symlinks"]} 個指向資料以外的符號連結沒有搬過來'
                    '（多半在代理程式的登入資料夾裡，這台保留自己的）。')
    if details['project_folders']:
        sink.notice('opendesign.project-folders',
                    f'HA 有 {details["project_folders"]} 個從資料夾匯入的專案；'
                    + (f'其中 {details["project_folders_ha"]} 個的資料夾在 HA 的 /data/opendesign 裡，'
                       if details['project_folders_ha'] else '')
                    + '這台沒有那些資料夾，搬過來後會打不開，請在這台重新匯入它們。')
    if src.ha_urls:
        sink.notice('opendesign.ha-addresses',
                    f'HA 的 OpenDesign 設定連到 HA 內部的位址（{hacommon.names(sorted(src.ha_urls), 8)}），'
                    '這台連不到，搬過來後請改成實際位址。')
    if src.prefs_unreadable:
        sink.notice('opendesign.prefs-unreadable',
                    'HA 的 OpenDesign 偏好設定（app-config.json）不是有效的設定檔，不會搬過來，這台維持自己的設定。')
    if src.prefs_dropped:
        sink.notice('opendesign.prefs-dropped',
                    f'HA 的 OpenDesign 偏好設定中有 {src.prefs_dropped} 個專案位置或最近使用的資料夾不在 HA 的 OpenDesign 資料夾裡，'
                    '這台沒有它們，不會搬過來。')
    if src.mcp_unreadable:
        sink.notice('opendesign.mcp-unreadable', 'HA 的 OpenDesign 外部 MCP 伺服器設定（mcp-config.json）不是有效的設定檔，不會搬過來。')
    if src.configs_skipped:
        sink.notice('opendesign.config-kept',
                    'HA 的 OpenDesign 設定檔太大，這次沒有搬過來：' + hacommon.names(sorted(src.configs_skipped), 4)
                    + '；這台原有的同名設定維持不變。')
    if src.shared_left:
        sink.notice('opendesign.shared-left', 'HA 專用的共用 MCP 伺服器與共用外掛（shared/mcp、shared/plugins）不會搬過來。')
    if details.get('routines_active'):
        sink.notice('opendesign.routines-active',
                    f'HA 有 {details["routines_active"]} 個啟用中的 OpenDesign 例行工作（routines），匯入後會在這台執行。')
    return details


def skip_line(sink, report, seen=None):
    """The one line `files.skipped` about what could not be moved (SKIPS): once the HA walk is done and, in a conversion,
    again when this device's own links added something (`seen`: the count of the first call). Returns the count."""
    count = report.skip_count(*SKIPS)
    if count and count != seen:
        sink.skipped(report, *SKIPS)
    return count


def section(src, details, report, *, revision, version):
    mine = VERSIONS.get(src.addon.version) if src.addon else None
    # `<app id>_version`: the product version the page shows next to the add-on's (backup.js haVersionText)
    return {'open-design_version': mine[0] if mine else '', 'source_revision': _rev(mine[1]) if mine else '',
            'target_version': version or '', 'target_revision': _rev(revision),
            'files': src.counts.get('files', 0), 'bytes': src.counts.get('bytes', 0), 'dirs': src.counts.get('dirs', 0),
            'symlinks': src.counts.get('symlinks', 0), 'hardlinks': src.counts.get('hardlinks', 0),
            'skipped_symlinks': src.counts.get('skipped_symlinks', 0),
            'links_copied': report.copied_links, 'skipped': report.skip_count(*SKIPS),
            'config_skipped': sorted(src.configs_skipped),
            **{name: details.get(name, 0) for name in COUNTS},
            'routines_active': details.get('routines_active', 0), 'project_folders': details['project_folders'],
            'mcp_servers': src.mcp_servers, 'mcp_integration_entries': src.mcp_owned, 'shared': src.shared_moved,
            'ha_urls': sorted(src.ha_urls)[:20],
            'left_out': {name: count for name, count in sorted(src.left_out.items())}}


# ====================================================================== reading this device's own data (OP-15, OP-16)
# Shared with ha_codeserver (CS-14, CS-15, CS-16): a read of this device's live volume or folder that fails is tried again; what
# still fails is read once with the app's own containers paused (they are started again at once); what still fails stops this app.

PAUSE_ID = 'opendesign.service-paused'


def is_running(runner, container):
    result = runner.podman('container', 'inspect', '--format', '{{.State.Running}}', container, timeout=60,
                           max_output=64 * 1024, check=False)
    return result.returncode == 0 and (result.stdout or b'').strip() == b'true'


def mounting_units(work, app, sources):
    """[(unit, container)] of this app's own containers (the Quadlet files of its catalog entry) that run now and mount one of
    `sources` (volume names, or absolute host folders): the ones that write into what is being read."""
    from .adapters.quadlet_postgres import quadlet_unit
    runner = work.runner(app)
    quadlets = work.quadlets(app)
    home = runner.home.rstrip('/')
    wanted = {source for source in sources if source}
    found = []
    for name in sorted(quadlets):
        if not name.endswith('.container'):
            continue
        container = ha_odoo.quadlet_container_name(quadlets, name)
        if not container or not hatarget.CONTAINER_RE.fullmatch(container):
            continue
        try:
            mounts = [source for source, _target, _options in ha_odoo.quadlet_mounts(quadlets, name, home)]
        except BackupError:
            continue   # a file this importer does not read (another container's): not a reason to stop the read
        if wanted.intersection(mounts) and is_running(runner, container):
            found.append((quadlet_unit(name), container))
    return found


@contextlib.contextmanager
def paused(work, app, sink, units, *, issue_id=PAUSE_ID):
    """The containers `units` ([(unit, container)]) of this app stopped for the block and started again after it, whatever
    happens in it; a unit that cannot be started again is tried again by the app's clean-up (put_back_later)."""
    runner = work.runner(app)
    temp = work.temp(app)
    stopped, started = [], set()

    def start(unit):
        if unit not in started:       # the clean-up's put-back finds it started already
            runner.systemctl('start', '--', unit, timeout=hatarget.START_TIMEOUT, max_output=64 * 1024)
            started.add(unit)

    try:
        for unit, _container in units:
            runner.systemctl('stop', '--', unit, timeout=hatarget.STOP_TIMEOUT, max_output=64 * 1024)
            stopped.append(unit)
            temp.put_back_later(f'服務 {unit}', lambda unit=unit: start(unit))
        sink.auto(issue_id, f'讀取這台「{app.name}」的資料多次沒有成功，已暫時停下它的服務再讀一次，讀完會自動啟動。',
                  [container for _unit, container in units])
        yield
    finally:
        for unit in reversed(stopped):
            try:
                start(unit)
            except Exception:  # noqa: BLE001 - the clean-up tries again and says so in the log
                work.log(f'警告：服務 {unit} 沒有立刻啟動回來，作業結束時會再試一次。')


def read_live(work, app, sink, attempt, *, sources, what, issue_id=PAUSE_ID):
    """`attempt()` -> its value: a read of this device's live data that makes sure what it read is whole (OP-15, CS-14, CS-16).
    A failure that may pass (a command that failed, a tar that is not whole because files changed under it) is tried again
    (hatarget.retry: READ_TRIES times); when that does not help and the app's own containers that mount `sources` run, they are
    paused for one more read and started again. What still fails comes up as it was: this app stops, this device is unchanged."""
    try:
        return hatarget.retry(attempt, attempts=READ_TRIES, pause_first=2, retry_if=hatarget.transient, abort=work.abort,
                              log=work.log, what=f'讀取{what}')
    except BackupError as error:
        if not hatarget.transient(error):
            raise
        units = mounting_units(work, app, sources)
        if not units:
            raise
    with paused(work, app, sink, units, issue_id=issue_id):
        return attempt()


def validate_live_tar(path, what):
    """A live export is read to its end before it is used: a tar that is cut or torn (files changed while it was made) is a
    read that failed, not a conversion that stops half way."""
    try:
        with ha_odoo._live_tar(path, what) as tar:
            for member in tar:
                if ha_odoo._norm(member.name) is None:
                    raise BackupError('job-failed', f'{what}的匯出內容格式不正確。')
                tar.members.clear()
    except tarfile.TarError:
        raise BackupError('job-failed', f'{what}的匯出內容無法讀取。') from None


def live_volume(work, app, sink, volume, path, *, what, issue_id=PAUSE_ID):
    """`podman volume export` of a live volume into `path`, read to its end (OP-15, CS-14): tried again, then once more with
    the app's own containers paused."""
    def attempt():
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        hacommon.live_export(work, app, volume, path)
        validate_live_tar(path, what)
        return path

    return read_live(work, app, sink, attempt, sources=(volume,), what=what, issue_id=issue_id)


def links_as_files(live_path, out, pending, what, *, report=None, label=''):
    """Hard links of this device's own volume whose file is not kept (it is replaced by HA's, or it is not kept at all) get the
    content of that file (OP-16, CS-15): `pending` = {name of the file: [(link name, its TarInfo)]}; the export is read once more,
    the first link of a file is written into the FileTar `out` as a regular file with the content, the others as hard links to
    it. A link whose file is no regular file of the export is left out and listed in `report` (without one: the conversion
    stops, as it did). Returns how many links got a file."""
    left = {target: list(links) for target, links in pending.items()}
    done = 0
    try:
        with ha_odoo._live_tar(live_path, what) as tar:
            for member in tar:
                name = ha_odoo._norm(member.name)
                links = left.pop(name, None) if (name is not None and member.isfile()) else None
                if links:
                    first_name, first = links[0]
                    info = ha_odoo._copy_info(first, first_name)
                    info.type, info.size, info.linkname = tarfile.REGTYPE, member.size, ''
                    out.add_member(info, tar.extractfile(member))
                    for other_name, other in links[1:]:
                        info = ha_odoo._copy_info(other, other_name)
                        info.linkname = first_name
                        out.add_member(info)
                    done += len(links)
                tar.members.clear()
    except tarfile.TarError:
        raise BackupError('job-failed', f'{what}的匯出內容無法讀取。') from None
    for links in left.values():
        for link_name, _member in links:
            if report is None:
                raise BackupError('job-failed', f'{what}中的 {link_name[:200]} 是另一個不會保留的檔案的硬連結，無法只保留一半；'
                                                '已停止。', member=link_name[:200])
            report.skip('hardlink', f'{label}{link_name}')
    return done


# ====================================================================== the job steps

def _child_failed(error):
    """The sandboxed SQLite reader did not finish (it timed out, could not be cut off the network or ended half way)."""
    return isinstance(error, BackupError) and error.code in ('job-failed', 'corrupt-archive') \
        and not haissues.is_job_wide(error)


def _inspect(work, sink, src, staging):
    """The SQLite child over the staged database: quick_check, counts, folder projects and active routines. When the child
    does not finish it is started once more (OP-14); then only this app stops (`opendesign.database-unreadable`)."""
    if DATABASE not in src.dbs:
        return {}
    spec = {'db': DATABASE, 'check': 'quick', 'counts': list(COUNTS),
            'queries': ['opendesign.project_folders', 'opendesign.routines_active']}

    def read():
        return hasqlite.run([spec], {name: path for name, path in src.dbs.items()}, staging / 'sqlite',
                            checkpoint=work.checkpoint, what='OpenDesign 資料庫')

    try:
        answers = hatarget.retry(read, attempts=2, pause_first=3, retry_if=_child_failed, abort=work.abort, log=work.log,
                                 what='讀取 OpenDesign 資料庫')
    except BackupError as error:
        if not _child_failed(error):
            raise
        sink.stop('opendesign.database-unreadable', DATABASE_UNREADABLE, action=DATABASE_UNREADABLE_ACTION)
        return {}
    return {name: answer for name, answer in answers.items() if name is not None}


def _pass(work, app, staging, out, report):
    member = work.addon_member(SLUG)
    with work.open(member) as stream:
        src = scan_member(stream, report, staging, out, machine=hacommon.host_elf_machine(), checkpoint=work.checkpoint)
    for note in report.warnings():
        work.log(note)
    left = sum(src.left_out.values())
    work.log(f'HA 的 OpenDesign：{src.counts.get("files", 0)} 個檔案（{src.counts.get("bytes", 0) / 1048576:.1f} MiB）要搬，'
             f'{left} 個項目（代理程式登入、Omnigent、Paseo、暫存）留在 HA')
    return src


def check(work, app):
    sink = work.sink(app)
    target = Target(work, app)
    revision, version = target_core(work, app, target)
    addon = work.addon_info(SLUG)
    sink.extend(version_issues(addon.version, revision, version))
    staging = work.staging / 'opendesign-work'
    staging.mkdir(mode=0o700)
    report = habackup.Report(names=haissues.Names)
    out = _Count(report)
    src = _pass(work, app, staging, out, report)
    finish_configs(src, out, None)
    work.phase('check')
    answers = _inspect(work, sink, src, staging)
    details = collect(sink, src, answers, report)
    skip_line(sink, report)
    return {'target_version': version or '', 'open-design': section(src, details, report, revision=revision, version=version)}


def copy_kept(live_path, out, *, keep_prefs, keep_mcp=False, what='這台 OpenDesign 的資料卷', report=None, stats=None):
    """Copy KEEP_LIVE of a live export (and its app-config.json when `keep_prefs`: HA has none that can be used, and its
    mcp-config.json when `keep_mcp`: HA's is too large) into the TreeTar `out` with the live owners; returns the live
    app-config.json and mcp-config.json documents (None when absent or unreadable). A kept hard link to a file that is not
    kept (OP-16) is written with that file's content (`links_as_files`; `stats['links_copied']` counts them)."""
    keep = KEEP_LIVE | ({'app-config.json'} if keep_prefs else set()) | ({'mcp-config.json'} if keep_mcp else set())
    live_prefs, live_mcp, written, pending = None, None, set(), {}
    try:
        with ha_odoo._live_tar(live_path, what) as tar:
            for member in tar:
                name = ha_odoo._norm(member.name)
                if name is None:
                    raise BackupError('job-failed', f'{what}的匯出內容格式不正確。')
                top = name.split('/', 1)[0]
                body = tar.extractfile(member) if member.isfile() else None
                if name in CONFIGS and member.isfile() and member.size <= MAX_CONFIG:
                    data = body.read()
                    if name == 'app-config.json':
                        live_prefs = hacommon.strict_json(data, MAX_CONFIG)
                    else:
                        live_mcp = hacommon.strict_json(data, MAX_CONFIG)
                    body = io.BytesIO(data)
                if name == '.' or top not in keep:
                    tar.members.clear()
                    continue
                if member.islnk() and ha_odoo._norm(member.linkname) not in written:
                    pending.setdefault(ha_odoo._norm(member.linkname), []).append((name, member))
                    tar.members.clear()
                    continue
                out.tar.add_member(ha_odoo._copy_info(member, name), body)
                if member.isfile():
                    written.add(name)
                tar.members.clear()
    except tarfile.TarError:
        raise BackupError('job-failed', f'{what}的匯出內容無法讀取。') from None
    if pending:
        done = links_as_files(live_path, out.tar, pending, what, report=report, label='這台：')
        if stats is not None:
            stats['links_copied'] = done
    return (live_prefs if isinstance(live_prefs, dict) else None), (live_mcp if isinstance(live_mcp, dict) else None)


def convert(work, app, test_mode, out_dir):
    """Build `out_dir/volumes/<data volume>.tar` (HA's data + this device's kept parts) and the MCP volume (the live
    export, unchanged)."""
    del test_mode
    adapter = work.adapter(app)
    sink = work.sink(app)
    target = Target(work, app)
    revision, version = target_core(work, app, target)
    addon = work.addon_info(SLUG)
    sink.extend(version_issues(addon.version, revision, version))   # a stop raises before anything of this device is read
    ids = adapter.owner_ids()
    staging = work.staging / 'opendesign-work'
    staging.mkdir(mode=0o700)
    (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
    work.log('讀取這台 OpenDesign 的資料卷（代理程式登入、Omnigent、Paseo 與安裝識別會保留）')
    what = '這台 OpenDesign 的資料卷'
    live = live_volume(work, app, sink, target.data_volume, staging / 'live-data.tar', what=what)
    data_path = out_dir / 'volumes' / f'{target.data_volume}.tar'
    root = ha_n8n.volume_root(work, app, target.data_volume)
    report = habackup.Report(names=haissues.Names)
    out = hacommon.TreeTar(data_path, root[0], root[1], work.guard, report=report)
    stats = {}
    try:
        out.root(root[2], root[0], root[1])
        src = _pass(work, app, staging, out, report)
        work.phase('convert')
        answers = _inspect(work, sink, src, staging)
        details = collect(sink, src, answers, report)
        seen = skip_line(sink, report)      # a stop or a line that was not confirmed ends this app here, before this device's data is copied
        keep_mcp = 'mcp-config.json' in src.configs_skipped
        live_prefs, live_mcp = copy_kept(live, out, keep_prefs=ha_prefs(src) is None, keep_mcp=keep_mcp, what=what,
                                         report=report, stats=stats)
        finish_configs(src, out, live_prefs, live_mcp, keep_mcp=keep_mcp)
        if stats.get('links_copied'):
            sink.auto('opendesign.kept-links-copied',
                      f'這台 OpenDesign 有 {stats["links_copied"]} 個保留下來的硬連結，它指到的檔案會被 HA 的資料取代，'
                      '已改成各自保留原本的檔案內容。')
        skip_line(sink, report, seen)       # this device's own links that could not be copied (rare): a line of its own
    finally:
        out.close()
    os.unlink(live)
    mcp_path = out_dir / 'volumes' / f'{target.mcp_volume}.tar'
    work.log('OpenDesign 的 MCP 權杖與工具設定維持這台現有的內容')
    live_volume(work, app, sink, target.mcp_volume, mcp_path, what='這台 OpenDesign 的 MCP 資料卷')
    for path in (data_path, mcp_path):
        ha_odoo.check_volume_tar(path, ids)
    work.log(f'OpenDesign 資料整理完成：{details["projects"]} 個專案、{details["conversations"]} 個對話、'
             f'{details["messages"]} 則訊息')
    return {'volumes': {target.data_volume: data_path, target.mcp_volume: mcp_path},
            'projects': details['projects'], 'conversations': details['conversations'],
            'messages': details['messages'], 'routines_active': details.get('routines_active', 0),
            'project_folders': details['project_folders'], 'mcp_servers': src.mcp_servers,
            'shared': src.shared_moved, 'ha_urls': sorted(src.ha_urls), 'links_copied': report.copied_links,
            'config_skipped': sorted(src.configs_skipped)}


# ====================================================================== texts

def import_texts(data):
    notes = ['OpenDesign 的專案、對話、執行紀錄、設計系統、品牌、技能、外掛、記憶與偏好設定，以及在 OpenDesign 裡設定的外部 MCP '
             '伺服器、連接器與媒體服務金鑰會換成 HA 的；這台的登入密碼（API 權杖）、MCP 權杖與工具設定、代理程式的登入、'
             'Omnigent 連線、Paseo 配對與 open-design.env 保持不變。']
    if data.get('shared'):
        notes.append('HA 專用的共用工作區與共用技能（shared）會原樣放進這台 OpenDesign 的資料夾，這台不會自動使用它們。')
    if data.get('links_copied'):
        notes.append(f'HA 有 {data["links_copied"]} 個硬連結的檔案（例如 bun、pnpm 安裝過的套件），已改成各自複製檔案內容。')
    reminders = ['匯入後請用這台的 OpenDesign 帳號 open-design 和這台的 API 權杖登入（不是 HA 的登入）。',
                 '代理程式（Claude Code、Codex、Pi、OpenCode）沿用這台原本的登入，HA 上登入的帳號不會搬過來，需要時請在這台的終端機重新登入。',
                 'Omnigent 與 Paseo 沿用這台原本的連線與配對；HA 的 OpenDesign 連過的 Omnigent 伺服器上，請移除 HA 那台主機。',
                 'HA 的 OpenDesign 附加元件內建的 MCP 伺服器不會搬過來：指向它的 MCP 連接器（例如 claude.ai）請刪掉，'
                 '改用這台的 MCP 網址與權杖重新建立。',
                 '在瀏覽器裡輸入的模型金鑰（BYOK）不在備份裡，請在這台重新輸入。']
    if data.get('ha_urls'):
        reminders.append(f'HA 的 OpenDesign 設定連到 HA 內部的位址（{hacommon.names(data["ha_urls"], 8)}），請改成這台連得到的位址。')
    if data.get('project_folders'):
        reminders.append(f'{data["project_folders"]} 個從資料夾匯入的專案在這台打不開，請在這台重新匯入那些資料夾。')
    if data.get('routines_active'):
        reminders.append(f'HA 的 {data["routines_active"]} 個 OpenDesign 例行工作會在這台執行，請先停掉 HA 的 OpenDesign，避免重複執行。')
    if data.get('config_skipped'):
        reminders.append(f'HA 的 OpenDesign 設定檔 {hacommon.names(data["config_skipped"], 4)} 太大，沒有搬過來；'
                         '這台原有的同名設定維持不變，需要 HA 的內容時請自行處理。')
    return notes, reminders
