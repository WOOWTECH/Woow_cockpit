"""Home Assistant import, OpenDesign part: the WOOWTECH add-on `woow_ha_opendesign` -> this device's app `open-design`
(CONTRACT section 9 "Home Assistant import"; facts phase3/facts/opendesign.md). Owner: E2.

The add-on persists only /data: the OpenDesign daemon's data folder is `data/opendesign` (OD_DATA_DIR), the built-in
MCP server's token and tool grants are `data/mcp`, HA's options `data/options.json` (never read). The target is the
Podman package: the volume `open-design_open_design_data` at /app/.od (the daemon and the terminal, `keep-id`, so the
owner's namespace root is the daemon's user) and `open-design_mcp_data` at /data/mcp (the MCP server's state). There is
no database server: the daemon keeps everything in the SQLite file `app.sqlite` (WAL) and plain files.

Versions: the data has no version stamp (the daemon migrates `app.sqlite` forward silently), so the add-on version maps
to the WoowTech fork revision of the OpenDesign core it ships (VERSIONS, from the add-on's CHANGELOG and its image
label) and that revision must equal the live image's label `io.woow.opendesign.source-revision`; an add-on version the
table does not know is refused.

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
this table does not know (with something in it) is a blocker: it is neither moved blindly nor dropped silently.

Every moved entry is owned like the live volume's top folder (0:0 in the owner's namespace = the daemon's user),
permission bits without setuid/setgid; relative symlinks that stay in the tree are link entries, others are skipped and
counted; a hard link must name an earlier moved file (one to a file that does not move stops the import). The kept
parts are copied from a live export of the volume (read while the app runs, like Odoo's web data) with their live
owners; a kept hard link to a dropped file stops the import too. `app.sqlite` is opened only by the sandboxed child
(hasqlite): quick_check and the counts of projects, conversations, messages and routines.
"""
import io
import json
import os
import re
import tarfile
import time

from . import habackup, hacommon, hasqlite, ha_n8n, ha_odoo, tempctr
from .errors import BackupError

SLUG = 'woow_ha_opendesign'
APP_ID = 'open-design'
TREE = 'data/opendesign'
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
MAX_CONFIG = 4 * 1024 * 1024
MAX_SCAN = 1024 * 1024
COUNTS = ('projects', 'conversations', 'messages', 'routines')


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
        self.left_out = {}        # top-level name -> entries
        self.unknown = {}         # top-level name -> [entries, entries that are not directories]
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
        self.tree = False
        self.counts = {}


class _Count:
    """TreeTar's bookkeeping without an output (the check job)."""

    def __init__(self):
        self.files = set()
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
        self.counts['symlinks'] += 1

    def hardlink(self, name, target, mtime):
        if target not in self.files:
            raise BackupError('incompatible', f'HA 備份中的 {name[:200]} 是另一個沒有搬過來的檔案的硬連結，無法只搬一半；'
                                              '已停止。', member=name[:200], target=target[:200])
        self.counts['hardlinks'] += 1


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
    `src.configs` for the end of the conversion. Returns a Source."""
    select = habackup.Select(include=(TREE,), symlinks=(TREE,), hardlinks=True)
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
            seen = src.unknown.setdefault(top[:100], [0, 0])
            seen[0] += 1
            seen[1] += entry.kind != 'dir'
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
            out.hardlink(rel, entry.linkname[len(TREE) + 1:], entry.mtime)
            continue
        if rel == DATABASE or rel in (DATABASE + s for s in SIDECARS):
            src.dbs[rel] = _stage_db(entry, rel, staging, out)
            continue
        if rel in CONFIGS:
            data = entry.read_all(MAX_CONFIG)
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
    """HA's app-config.json document, or None (absent, or not a JSON object)."""
    if 'app-config.json' not in src.configs:
        return None
    doc = hacommon.strict_json(src.configs['app-config.json'][0], MAX_CONFIG)
    return doc if isinstance(doc, dict) else None


def finish_configs(src, out, live_prefs, live_mcp=None):
    """Write HA's JSON settings into `out` (TreeTar or _Count): app-config.json merged with this device's
    preferences (`live_prefs`: the live file's document or None), mcp-config.json with its paths remapped, without
    HA's integration entries and with this device's (`live_mcp`). A setting that is not a JSON object is left out:
    this device's app-config.json stays (copy_kept), an unreadable mcp-config.json leaves only this device's
    integration entries (the daemon starts without HA's external MCP servers)."""
    for rel in CONFIGS:
        if rel not in src.configs:
            if rel == 'mcp-config.json' and live_mcp is not None:
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
            raise BackupError('incompatible', '這台 OpenDesign 的 Quadlet 設定缺少映像。', app=app.id)


def target_core(work, app, target):
    """(fork revision, OpenDesign version) of the live image (label and OD_APP_VERSION; None when unknown)."""
    revision = hacommon.image_labels(work, app, target.image).get(SOURCE_LABEL, '').strip().lower()
    image = work.adapter(app).image_inspect(target.image) or {}
    version = next((item.split('=', 1)[1] for item in image.get('env') or []
                    if isinstance(item, str) and item.startswith('OD_APP_VERSION=')), None)
    return (revision if REVISION_RE.fullmatch(revision) else None), hacommon.semver(version or '')


def version_blocker(addon_version, revision, version):
    mine = VERSIONS.get(addon_version)
    if mine is None:
        return (f'無法確認 HA 附加元件版本 {addon_version} 搭配的 OpenDesign 核心版本（這台的資料表還不認得它），'
                '為避免版本不同而無法匯入；請先更新這台的 Cockpit。')
    if revision is None:
        return '無法讀取這台 OpenDesign 的核心版本（映像沒有 io.woow.opendesign.source-revision 標籤）。'
    if revision != mine[1] and not (len(revision) < len(mine[1]) and mine[1].startswith(revision)):
        return (f'版本不同：HA 的 OpenDesign 核心是 {_rev(mine[1])}（OpenDesign {mine[0]}，附加元件 {addon_version}），'
                f'這台是 {_rev(revision)}（OpenDesign {version or "版本不明"}）。請先把這台的 OpenDesign 換成同一個核心版本後再匯入。')
    return None


def analyse(src, answers, *, addon_version, revision, version):
    """(blockers, warnings, details) of HA's OpenDesign against this device."""
    blockers, warnings = [], []
    blocker = version_blocker(addon_version, revision, version)
    if blocker:
        blockers.append(blocker)
    if not src.tree:
        blockers.append('HA 備份裡沒有 OpenDesign 的資料夾（data/opendesign），沒有可搬的資料。')
    elif DATABASE not in src.dbs:
        blockers.append('HA 備份裡沒有 OpenDesign 的資料庫（app.sqlite），可能從來沒有啟動過；沒有可搬的資料。')
    details = {name: 0 for name in COUNTS}
    details.update(project_folders=0, project_folders_ha=0)
    answer = answers.get(DATABASE)
    if answer is not None:
        why = hasqlite.problem(answer)
        if why:
            blockers.append(f'HA 的 OpenDesign 資料庫 app.sqlite 已損毀或無法讀取（{why}）。')
        else:
            counts = answer.get('counts') or {}
            for name in COUNTS:
                details[name] = ha_odoo._int(counts.get(name))
            if 'projects' not in counts:
                blockers.append('HA 的 OpenDesign 資料庫沒有專案資料表，不像是 OpenDesign 的資料，無法匯入。')
            values = answer.get('values') or {}
            rows = values.get('opendesign.project_folders')
            if isinstance(rows, list) and rows and isinstance(rows[0], list) and len(rows[0]) == 2:
                details['project_folders'] = ha_odoo._int(rows[0][0])
                details['project_folders_ha'] = ha_odoo._int(rows[0][1])
            details['routines_active'] = ha_odoo._int(values.get('opendesign.routines_active'))
    unknown = sorted(name for name, (_entries, files) in src.unknown.items() if files)
    if unknown:
        blockers.append(f'HA 的 OpenDesign 資料有這台的匯入程式還不認得的項目（{hacommon.names(unknown, 5)}），'
                        '為避免漏搬或搬錯，已停止；請先更新這台的 Cockpit。')
    if src.foreign:
        warnings.append(f'HA 的 OpenDesign 專案中有其他處理器的程式（{len(src.foreign)} 個，例如 '
                        f'{hacommon.names(src.foreign, 3)}），搬過來後無法執行，需要時請在這台重新安裝。')
    if src.counts.get('skipped_symlinks'):
        warnings.append(f'HA 的 OpenDesign 資料中有 {src.counts["skipped_symlinks"]} 個指向資料以外的符號連結沒有搬過來'
                        '（多半在代理程式的登入資料夾裡，這台保留自己的）。')
    if details['project_folders']:
        warnings.append(f'HA 有 {details["project_folders"]} 個從資料夾匯入的專案；'
                        + (f'其中 {details["project_folders_ha"]} 個的資料夾在 HA 的 /data/opendesign 裡，'
                           if details['project_folders_ha'] else '')
                        + '這台沒有那些資料夾，搬過來後會打不開，請在這台重新匯入它們。')
    if src.ha_urls:
        warnings.append(f'HA 的 OpenDesign 設定連到 HA 內部的位址（{hacommon.names(sorted(src.ha_urls), 8)}），'
                        '這台連不到，搬過來後請改成實際位址。')
    if src.prefs_unreadable:
        warnings.append('HA 的 OpenDesign 偏好設定（app-config.json）不是有效的設定檔，不會搬過來，這台維持自己的設定。')
    if src.prefs_dropped:
        warnings.append(f'HA 的 OpenDesign 偏好設定中有 {src.prefs_dropped} 個專案位置或最近使用的資料夾不在 HA 的 OpenDesign 資料夾裡，'
                        '這台沒有它們，不會搬過來。')
    if src.mcp_unreadable:
        warnings.append('HA 的 OpenDesign 外部 MCP 伺服器設定（mcp-config.json）不是有效的設定檔，不會搬過來。')
    if src.shared_left:
        warnings.append('HA 專用的共用 MCP 伺服器與共用外掛（shared/mcp、shared/plugins）不會搬過來。')
    if details.get('routines_active'):
        warnings.append(f'HA 有 {details["routines_active"]} 個啟用中的 OpenDesign 例行工作（routines），匯入後會在這台執行。')
    return blockers, warnings, details


def section(src, details, *, revision, version):
    mine = VERSIONS.get(src.addon.version) if src.addon else None
    # `<app id>_version`: the product version the page shows next to the add-on's (backup.js haVersionText)
    return {'open-design_version': mine[0] if mine else '', 'source_revision': _rev(mine[1]) if mine else '',
            'target_version': version or '', 'target_revision': _rev(revision),
            'files': src.counts.get('files', 0), 'bytes': src.counts.get('bytes', 0), 'dirs': src.counts.get('dirs', 0),
            'symlinks': src.counts.get('symlinks', 0), 'hardlinks': src.counts.get('hardlinks', 0),
            'skipped_symlinks': src.counts.get('skipped_symlinks', 0),
            **{name: details.get(name, 0) for name in COUNTS},
            'routines_active': details.get('routines_active', 0), 'project_folders': details['project_folders'],
            'mcp_servers': src.mcp_servers, 'mcp_integration_entries': src.mcp_owned, 'shared': src.shared_moved,
            'ha_urls': sorted(src.ha_urls)[:20],
            'left_out': {name: count for name, count in sorted(src.left_out.items())}}


# ====================================================================== the job steps

def _inspect(work, src, staging):
    """The SQLite child over the staged database: quick_check, counts, folder projects and active routines."""
    if DATABASE not in src.dbs:
        return {}
    spec = {'db': DATABASE, 'check': 'quick', 'counts': list(COUNTS),
            'queries': ['opendesign.project_folders', 'opendesign.routines_active']}
    answers = hasqlite.run([spec], {name: path for name, path in src.dbs.items()}, staging / 'sqlite',
                           checkpoint=work.checkpoint, what='OpenDesign 資料庫')
    return {name: answer for name, answer in answers.items() if name is not None}


def _pass(work, app, staging, out):
    member = work.addon_member(SLUG)
    report = habackup.Report()
    with work.open(member) as stream:
        src = scan_member(stream, report, staging, out, machine=hacommon.host_elf_machine(), checkpoint=work.checkpoint)
    for note in report.warnings():
        work.log(note)
    left = sum(src.left_out.values())
    work.log(f'HA 的 OpenDesign：{src.counts.get("files", 0)} 個檔案（{src.counts.get("bytes", 0) / 1048576:.1f} MiB）要搬，'
             f'{left} 個項目（代理程式登入、Omnigent、Paseo、暫存）留在 HA')
    return src


def check(work, app):
    target = Target(work, app)
    revision, version = target_core(work, app, target)
    staging = work.staging / 'opendesign-work'
    staging.mkdir(mode=0o700)
    out = _Count()
    src = _pass(work, app, staging, out)
    finish_configs(src, out, None)
    work.phase('check')
    answers = _inspect(work, src, staging)
    addon = work.addon_info(SLUG)
    blockers, warnings, details = analyse(src, answers, addon_version=addon.version, revision=revision,
                                          version=version)
    return {'target_version': version or '', 'blockers': blockers, 'warnings': warnings,
            'open-design': section(src, details, revision=revision, version=version)}


def copy_kept(live_path, out, *, keep_prefs, what='這台 OpenDesign 的資料卷'):
    """Copy KEEP_LIVE of a live export (and its app-config.json when `keep_prefs`: HA has none that can be used) into
    the TreeTar `out` with the live owners; returns the live app-config.json and mcp-config.json documents (None when
    absent or unreadable)."""
    keep = KEEP_LIVE | ({'app-config.json'} if keep_prefs else set())
    live_prefs, live_mcp, written = None, None, set()
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
                if member.islnk():
                    target = ha_odoo._norm(member.linkname)
                    if target not in written:
                        raise BackupError('job-failed', f'{what}中的 {name[:200]} 是另一個不會保留的檔案的硬連結，'
                                                        '無法只保留一半；已停止。', member=name[:200])
                out.tar.add_member(ha_odoo._copy_info(member, name), body)
                if member.isfile():
                    written.add(name)
                tar.members.clear()
    except tarfile.TarError:
        raise BackupError('job-failed', f'{what}的匯出內容無法讀取。') from None
    return (live_prefs if isinstance(live_prefs, dict) else None), (live_mcp if isinstance(live_mcp, dict) else None)


def convert(work, app, test_mode, out_dir):
    """Build `out_dir/volumes/<data volume>.tar` (HA's data + this device's kept parts) and the MCP volume (the live
    export, unchanged)."""
    adapter = work.adapter(app)
    target = Target(work, app)
    revision, version = target_core(work, app, target)
    ids = adapter.owner_ids()
    staging = work.staging / 'opendesign-work'
    staging.mkdir(mode=0o700)
    (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
    work.log('讀取這台 OpenDesign 的資料卷（代理程式登入、Omnigent、Paseo 與安裝識別會保留）')
    live = hacommon.live_export(work, app, target.data_volume, staging / 'live-data.tar')
    data_path = out_dir / 'volumes' / f'{target.data_volume}.tar'
    root = ha_n8n.volume_root(work, app, target.data_volume)
    out = hacommon.TreeTar(data_path, root[0], root[1], work.guard)
    try:
        out.root(root[2], root[0], root[1])
        src = _pass(work, app, staging, out)
        live_prefs, live_mcp = copy_kept(live, out, keep_prefs=ha_prefs(src) is None)
        finish_configs(src, out, live_prefs, live_mcp)
    finally:
        out.close()
    os.unlink(live)
    work.phase('convert')
    answers = _inspect(work, src, staging)
    addon = work.addon_info(SLUG)
    blockers, _warnings, details = analyse(src, answers, addon_version=addon.version, revision=revision,
                                           version=version)
    if blockers:
        raise BackupError('incompatible', f'OpenDesign 不能搬過來：{blockers[0]}', app=app.id)
    mcp_path = out_dir / 'volumes' / f'{target.mcp_volume}.tar'
    work.log('OpenDesign 的 MCP 權杖與工具設定維持這台現有的內容')
    hacommon.live_export(work, app, target.mcp_volume, mcp_path)
    for path in (data_path, mcp_path):
        ha_odoo.check_volume_tar(path, ids)
    work.log(f'OpenDesign 資料整理完成：{details["projects"]} 個專案、{details["conversations"]} 個對話、'
             f'{details["messages"]} 則訊息')
    return {'volumes': {target.data_volume: data_path, target.mcp_volume: mcp_path},
            'projects': details['projects'], 'conversations': details['conversations'],
            'messages': details['messages'], 'routines_active': details.get('routines_active', 0),
            'project_folders': details['project_folders'], 'mcp_servers': src.mcp_servers,
            'shared': src.shared_moved, 'ha_urls': sorted(src.ha_urls)}


# ====================================================================== texts

def import_texts(data):
    notes = ['OpenDesign 的專案、對話、執行紀錄、設計系統、品牌、技能、外掛、記憶與偏好設定，以及在 OpenDesign 裡設定的外部 MCP '
             '伺服器、連接器與媒體服務金鑰會換成 HA 的；這台的登入密碼（API 權杖）、MCP 權杖與工具設定、代理程式的登入、'
             'Omnigent 連線、Paseo 配對與 open-design.env 保持不變。']
    if data.get('shared'):
        notes.append('HA 專用的共用工作區與共用技能（shared）會原樣放進這台 OpenDesign 的資料夾，這台不會自動使用它們。')
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
    return notes, reminders
