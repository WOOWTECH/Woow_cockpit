"""Home Assistant import, Hermes part: the WOOWTECH add-on `woow-hermes` -> this device's app `hermes` (CONTRACT section
9 "Home Assistant import"; facts phase3/facts/hermes.md). Owner: E2.

The add-on maps its `addon_config` folder at /opt/data, Hermes's HERMES_HOME: every piece of state is SQLite files and
plain files there (`config/**` in the backup member; HA already leaves out `logs`, `lazy-packages`, `.cache`, `.npm`).
`data/**` holds only HA's options, HA's generated dashboard/API/webhook/session secrets and the hashes of applied
provider keys: never read (habackup.NEVER_READ). The target is the Podman package: the volume `hermes-data` at
/opt/data owned by the Quadlet's HERMES_UID/HERMES_GID (or, when those do not say a number, by the owner of the live
folder), an unused PostgreSQL 15 (`main`) and Redis.

HAOS parity (2026-11-25, DESIGN B, E1): what HA's data holds never keeps the import from happening. The add-on version
and this device's Hermes version only inform (`VERSIONS.issues`); what decides is the data: `state.db`'s `schema_version`
and `config.yaml`'s `_config_version` (a newer settings file is moved and noted: this release ignores what it does not
know). No size limit refuses an app: `.woow-image-version` is only read at its start, a `.env` up to MAX_ENV is filtered
(a larger one is left out and listed), `config.yaml`, `cron/jobs.json` and `SKILL.md` are copied as they are and only read
for what they say up to SCAN_MAX. An entry that is a link or a folder where a file must be is left out and listed (one
line of the one confirmation); a secondary database that is damaged or stands where a link is is left out with its WAL and
listed, a damaged `state.db` stops only Hermes; an index structure the sandbox does not know does not stop anything (the
database moves unchanged, unchecked). A hard link follows the file it names, never more: to a runtime file that does not move
it is copied as a file (CM-11); to a database it moves with the database or stays out with it; to a file that stays out for
what it holds (an `.env` too large to filter, a damaged database, what lies below a folder where a file must be) it stays out
too and is listed -- no name carries what its file may not.

The tree moves as it is -- data, the data's own keys (vault, OAuth tokens, per-route webhook secrets, plugin logins)
and HA's `config.yaml` -- with every owner set to this device's hermes uid/gid and no setuid/setgid bit; symlinks stay
link entries (relative ones that stay in the tree, absolute ones only into /opt/data, /opt/hermes or /usr: a venv's
interpreter), hard links stay hard links to an earlier file of the same tree (uv's ~14,000 links), nothing is ever
followed. Left out: the gateway's runtime files, `.woow-image-version` (the first start then resets the caches),
`.woow-dotenv` (Podman's record of applied keys: without it the first start applies this device's hermes.env, whose keys
win over HA's), every `-shm` wal-index, the browser login profiles (a credential store, never archived upstream either).
HA's `.env` keeps HA's provider keys but loses the lines this device's secrets and URLs own (API_SERVER_KEY,
WEBHOOK_SECRET, HERMES_DASHBOARD_BASIC_AUTH_*, HERMES_DASHBOARD_PUBLIC_URL, HERMES_BASE_URL, HERMES_PASEO_*). The SQLite
files move unchanged with their WAL, after the sandboxed child (hasqlite) checked each known database (`quick_check`)
and read `state.db`'s counts and schema version; they are written into the tree only then, and so are the hard links to them
(so one that stays out leaves nothing behind, not even under the name of a link); known Hermes FTS5 layouts are allowed,
their index structure is checked by quick_check in the sandbox, but an index is not compared with its messages.
`hermes-redis-data` is only its top folder (owned like the live one),
every other volume or folder of this device's entry (a cold database, a workspace) is carried as it is, and the database
`main` is a dump of the live, unused database (this device's own, unchanged). HA's /media is never moved.
"""
import os
import re

from . import habackup, hacommon, haissues, hasqlite, hatarget, ha_n8n, ha_odoo, tempctr
from .errors import BackupError
from .haissues import Issue

SLUG = 'woow-hermes'
APP_ID = 'hermes'
TREE = 'config'
BASE_LABEL = 'io.woowtech.hermes.base'
# Add-on version -> Hermes Agent release (Woow_ha_hermes_add_on CHANGELOG.md; every release tag's ARG HERMES_BASE).
VERSIONS = hacommon.VersionTable('Hermes', {**{f'0.1.{n}': '2026.8.31' for n in range(0, 10)},
                                            **{f'0.1.{n}': '0.22.5' for n in range(10, 15)}})
BASE_DIGESTS = {'0.22.5': 'sha256:9c5561579f3ffdf333401797094ac3a743738d6c25d40f4331c7bf77b694238d'}
SCHEMA_VERSION = 32     # state.db schema of Hermes v0.22.5 (hermes_state_common.py)
CONFIG_VERSION = 51     # config.yaml _config_version of v0.22.5 (hermes_cli/config_defaults.py)
RUNTIME_FILES = frozenset({'gateway.pid', 'gateway.lock', 'gateway_state.json', 'processes.json', 'cron.pid',
                           '.backup.lock', '.woow-image-version'})
EXCLUDED_DIRS = ('browser-profile', 'browser-profiles', 'browser_profiles', '.woow-dotenv')
ABSOLUTE_LINKS = ('/opt/data', '/opt/hermes', '/usr')
KNOWN_DBS = ('state.db', 'kanban.db', 'response_store.db', 'runs_idempotency.db', 'shared-state.db', 'projects.db',
             'cron/executions.db', 'cron/notepad.db')
SIDECARS = ('-wal', '-journal')
SPECIAL_FILES = ('.env', 'config.yaml', 'cron/jobs.json', '.woow-image-version')   # a file, never a link or a folder
MANAGED_ENV_RE = re.compile(rb'\s*(?:export\s+)?(?:\x27)?(?:API_SERVER_KEY|WEBHOOK_SECRET|HERMES_DASHBOARD_BASIC_AUTH_[A-Z_]*'
                            rb'|HERMES_DASHBOARD_PUBLIC_URL|HERMES_BASE_URL|HERMES_PASEO_[A-Z_]*)(?:\x27)?\s*=')
ENV_KEY_RE = re.compile(rb'\s*(?:export\s+)?(?:\x27)?([A-Za-z_][A-Za-z0-9_]{0,100})(?:\x27)?\s*=')
CONFIG_VERSION_RE = re.compile(r'^_config_version:\s*([0-9]{1,6})\s*$', re.M)
MAX_ENV = 8 * 1024 * 1024          # H-19: the largest `.env` that is filtered in memory; a larger one is left out and listed
SCAN_MAX = 32 * 1024 * 1024        # H-20, H-21: the largest config.yaml / jobs.json / SKILL.md read for what it says
VERSION_BYTES = 1024               # H-18: of `.woow-image-version` (a file that does not move) only its start is read
MASK_MIN = 12
MAX_MASKED = 500                   # values of a `.env` registered as secrets: jobs.mask_secret sorts them all on every call
UID_RE = re.compile(r'[0-9]{1,9}\Z')
VIRTUAL_ERROR = 'ValueError: virtual tables are not supported'   # hasqlite's child: an index structure it does not know

ISSUES = {
    'hermes.layout-unsupported': 'stop',        # H-03: this device's settings have no folder at /opt/data, or dump a whole instance
    'hermes.extras-carried': 'auto',            # H-03: this device's other volumes and folders go along as they are
    'hermes.owner-from-folder': 'auto',         # H-05: HERMES_UID / HERMES_GID say no number: the live folder's owner is used
    'hermes.links-copied': 'auto',              # H-01: a hard link to a file that does not move is copied as a file
    'hermes.entries-skipped': 'confirm',        # H-02: a link or a folder where a file must be, left out
    'hermes.databases-skipped': 'confirm',      # H-02, H-11: a secondary database that is damaged or a link, left out
    'hermes.no-state-db': 'stop',               # H-10: HA's Hermes never started: nothing to move
    'hermes.state-db-unusable': 'stop',         # H-02, H-11: the main database is damaged or a link
    'hermes.schema-unreadable': 'stop',         # H-12 (kept)
    'hermes.schema-newer': 'stop',              # H-13 (kept)
    'hermes.config-newer': 'notice',            # H-14: a settings file of a newer Hermes is moved as it is
    'hermes.foreign-programs': 'notice',        # H-16: programs for another processor are moved, they will not run here
    'hermes.image-version-differs': 'notice',   # H-09: HA updated the add-on before it ran once
    'hermes.image-version-missing': 'notice',
    'hermes.digest-differs': 'notice',
    'hermes.db-unchecked': 'notice',            # H-11: an index structure the sandbox does not know: moved, not checked
    'hermes.text-unread': 'notice',             # H-20, H-21: a very large text file is copied without being read
    'hermes.ha-addresses': 'notice',
    'hermes.media-refs': 'notice',
    'hermes.plugins-replaced': 'notice',
}


def flat(rel):
    """The staged name of a known database (or its sidecar): `cron/executions.db-wal` -> `cron.executions.db-wal`."""
    return rel.replace('/', '.')


class Source:
    def __init__(self):
        self.addon = None
        self.report = None        # the walk's habackup.Report: what the reader left out (Sink.skipped)
        self.image_version = None
        self.env_keys = []
        self.ha_urls = set()
        self.media_refs = 0
        self.config_version = None
        self.cron_jobs = 0
        self.skills = 0
        self.plugins = set()
        self.dbs = {}             # staged name -> path
        self.db_meta = {}         # staged name -> (name in the tree, mode, mtime)
        self.db_skip = set()      # staged names that stay out of the tree (a group left out, with its sidecars)
        self.skipped = []         # runtime files, -shm, ...
        self.runtime = set()      # H-01: the names in `skipped`: a hard link to one of them may be copied
        self.copying = set()      # H-01: the hard links whose copy was asked for (the reader hands their names out again, after the walk)
        self.db_links = []        # H-01: hard links to a known database (name, the database's name in the tree, mtime), settled by judge
        self.kept_links = []      # of those, the links whose database stays: add_databases writes them after the databases
        self.links_settled = False
        self.foreign = []         # programs for another processor
        self.specials = haissues.Names()    # H-02: a link or a folder where a file must be
        self.unread = haissues.Names()      # H-20, H-21: copied without being read
        self.bad_groups = set()   # known databases (names of KNOWN_DBS) one member of which is not a regular file
        self.skip_trees = []      # a folder where a file must be: what lies below it is left out
        self.copied = 0           # hard links copied as files
        self.counts = {}


class _Count:
    """TreeTar's bookkeeping without an output (the check job); a link is judged the way TreeTar judges it, so the check lists
    exactly what the conversion will leave out."""

    def __init__(self, report=None):
        self.files = set()
        self.report = report
        self.copied = 0
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
            self.copied += 1
            return 'copy'
        if self.report is not None:
            self.report.skip('hardlink', name)
            return 'skip'
        raise BackupError('incompatible', f'HA 備份中的 {name[:200]} 是另一個沒有搬過來的檔案的硬連結，無法只搬一半；'
                                          '已停止。', member=name[:200], target=target[:200])


class _Staged:
    """The writer of a staged copy of a database: every byte is counted by the job's space guard."""

    def __init__(self, handle, guard=None):
        self.handle, self.guard = handle, guard

    def write(self, data):
        self.handle.write(data)
        if self.guard is not None:
            self.guard.wrote(len(data))


def strip_env(data):
    """(HA's .env without the lines this device's secrets and URLs own, the key names it holds, the values of the
    kept keys -- the caller masks them)."""
    kept, keys, values = [], [], []
    for line in data.splitlines(keepends=True):
        if MANAGED_ENV_RE.match(line):
            continue
        match = ENV_KEY_RE.match(line)
        if match:
            keys.append(match.group(1).decode('ascii'))
            value = line[match.end():].strip().strip(b'"\'').decode('utf-8', 'replace')
            if value:
                values.append(value)
        kept.append(line)
    return b''.join(kept), sorted(set(keys)), values


def _known_db(rel):
    """The known database a name is (or is the sidecar of), else None."""
    for db in KNOWN_DBS:
        if rel == db or any(rel == db + suffix for suffix in SIDECARS):
            return db
    return None


def _leave_out(src, rel, db, kind):
    """H-02: `rel` is a link or a folder where a regular file must be. It stays out and is listed; a database takes its
    whole group (the file and its sidecars) with it; a folder takes what lies below it."""
    src.specials.add(rel[:200])
    if db is not None:
        src.bad_groups.add(db)
    if kind == 'dir':
        src.skip_trees.append(rel + '/')


def _mask_values(values):
    from . import jobs
    masked = 0
    for value in values:
        if len(value) >= MASK_MIN:  # provider keys and tokens: masked in every log line of this job
            jobs.mask_secret(value)
            masked += 1
            if masked >= MAX_MASKED:
                break


def _hard_link(src, out, rel, entry):
    """H-01: a hard link follows what the importer did with the file it names -- never more. The file is in the tree: a hard
    link. The file did not move because it is only runtime state (a pid file, a wal-index): the link is copied as a file (the
    reader hands the name out again after the walk). A known database: the link follows the database, which is only decided
    once the checks are in (`settle_links`, called by `judge`, so the check and the conversion list the same names). Every
    other file that is not in the tree stays out for what it holds -- an `.env` too large to filter, what lies below a folder
    where a file must be -- and the link stays out with it and is listed: `entry` is never handed to the tar for those
    (TreeTar.hardlink would copy exactly the content that stays out, under another name)."""
    linkname = entry.linkname
    target = linkname[len(TREE) + 1:] if linkname.startswith(TREE + '/') else None
    if target is not None and _known_db(target) is not None:
        src.db_links.append((rel, target, entry.mtime))
        return
    copy = entry if target in src.runtime else None
    if out.hardlink(rel, target if target is not None else linkname, entry.mtime, entry=copy) == 'copy':
        src.copying.add(rel)


def settle_links(src):
    """H-01, H-02, H-11: a hard link to a known database (or to its WAL) moves when that database moves and stays out, listed
    in the reader's own line, when the database stays out (damaged, or in a group with a member that is no file): what stays
    out leaves nothing behind, not even under another name. Called by `judge` after the checks; once only."""
    if src.links_settled:
        return
    src.links_settled = True
    for name, target, mtime in src.db_links:
        staged = flat(target)
        if staged in src.dbs and staged not in src.db_skip:
            src.kept_links.append((name, target, mtime))
        elif src.report is not None:
            src.report.skip('hardlink', name)
    src.counts['hardlinks'] = src.counts.get('hardlinks', 0) + len(src.kept_links)


def scan_member(stream, report, staging, out, *, machine=None, guard=None, checkpoint=None):
    """One strict pass over `config/**` into `out` (a TreeTar or _Count; names relative to the tree); the known
    databases and their sidecars are staged in `staging` for the SQLite child and only added to `out` afterwards
    (`add_databases`). Returns a Source. What is not a regular file where one must be is left out and listed (H-02), a
    hard link to a file that does not move becomes a copy (H-01)."""
    select = habackup.Select(include=(TREE,), exclude=tuple(f'{TREE}/{name}' for name in EXCLUDED_DIRS),
                             symlinks=(TREE,), absolute_symlinks=ABSOLUTE_LINKS, hardlinks=True)
    src = Source()
    src.report = report
    count = 0
    handed = 0   # report.copied_links before this entry: when it grows, the reader hands this regular file out for a hard link
    for entry in habackup.iter_entries(stream, select, report, checkpoint=checkpoint):
        count += 1
        if checkpoint is not None and count % 256 == 0:
            checkpoint()
        linked, handed = report.copied_links - handed, report.copied_links
        if entry.name == TREE:
            continue  # the volume's top folder is the live one
        rel = entry.name[len(TREE) + 1:]
        if any(rel.startswith(prefix) for prefix in src.skip_trees):
            continue  # below a folder that stands where a file must be: left out with it
        top, _, rest = rel.partition('/')
        if top == 'plugins' and rest and '/' not in rest and entry.kind == 'dir':
            src.plugins.add(rest[:100])
        db = _known_db(rel)
        if linked and rel not in src.copying:
            # H-01: a regular file the reader hands out for a hard link this walk never saw as one and never asked to copy -- a chain
            # of links, which the reader follows to the file at its end without naming it. Nothing says what it holds (an `.env` too
            # large to filter, a database that stays out), so it is judged like a link to such a file: left out and listed
            if rel in SPECIAL_FILES or db is not None or rel == 'cron':
                _leave_out(src, rel, db, 'hardlink')
            else:
                report.skip('hardlink', rel)
            continue
        if ((rel in SPECIAL_FILES or db is not None) and entry.kind != 'file') or (rel == 'cron' and entry.kind != 'dir'):
            _leave_out(src, rel, db, entry.kind)
            continue
        if entry.kind == 'dir':
            out.dir(rel, entry.mode, entry.mtime)
            continue
        if entry.kind == 'symlink':
            out.symlink(rel, entry.linkname, entry.mtime)
            continue
        if entry.kind == 'hardlink':
            _hard_link(src, out, rel, entry)
            continue
        # a regular file
        if '/' not in rel and rel in RUNTIME_FILES:
            if rel == '.woow-image-version':
                src.image_version = entry.peek(VERSION_BYTES).decode('ascii', 'replace').strip()[:64]
            src.skipped.append(rel)
            src.runtime.add(rel)
            continue
        if rel.endswith('-shm'):
            src.skipped.append(rel)
            src.runtime.add(rel)
            continue
        if machine is not None and hacommon.foreign_elf(entry.peek(20), machine) and len(src.foreign) < 1000:
            src.foreign.append(rel)
        mode = entry.mode
        if rel == '.env':
            data = entry.read_or_skip(MAX_ENV)   # a larger one cannot be filtered in memory: the report lists it
            if data is None:
                continue
            data, src.env_keys, values = strip_env(data)
            _mask_values(values)
            src.ha_urls.update(f'.env：{host}' for host in hacommon.ha_hosts(data.decode('utf-8', 'replace')))
            out.data(rel, data, mode, entry.mtime)
            continue
        skill = rel.startswith('skills/') and rel.endswith('/SKILL.md')
        if rel in ('config.yaml', 'cron/jobs.json') or skill:
            if entry.size > SCAN_MAX:   # H-20, H-21: no size refuses it; it is copied without being read for what it says
                src.unread.add(rel[:200])
                src.skills += skill
                out.file(rel, entry, mode)
                continue
            data = entry.read_all(SCAN_MAX)
            text = data.decode('utf-8', 'replace')
            src.media_refs += text.count('/media/')
            if rel == 'config.yaml':
                match = CONFIG_VERSION_RE.search(text)
                src.config_version = int(match.group(1)) if match else None
                src.ha_urls.update(f'config.yaml：{host}' for host in hacommon.ha_hosts(text))
            elif rel == 'cron/jobs.json':
                doc = hacommon.strict_json(data, SCAN_MAX)
                jobs = doc.get('jobs') if isinstance(doc, dict) else doc
                src.cron_jobs = len(jobs) if isinstance(jobs, (list, dict)) else 0
            else:
                src.skills += 1
            out.data(rel, data, mode, entry.mtime)
            continue
        if db is not None:
            staged = flat(rel)
            path = staging / staged
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                entry.copy_to(_Staged(handle, guard))
                handle.flush()
                os.fsync(handle.fileno())
            src.dbs[staged] = path
            src.db_meta[staged] = (rel, mode & 0o777, entry.mtime)
            if isinstance(out, _Count):
                out.data(rel, b'', mode, entry.mtime)
                out.counts['bytes'] += entry.size
            continue
        out.file(rel, entry, mode)
    src.addon = report.addon
    src.copied = getattr(out, 'copied', 0)
    for staged in [name for name, (rel, _m, _t) in src.db_meta.items() if _known_db(rel) in src.bad_groups]:
        src.dbs.pop(staged, None)   # a group with a member that is no file stays out as a whole
        src.db_skip.add(staged)
    src.counts = dict(out.counts, absolute_symlinks=report.absolute_symlinks, skipped_symlinks=report.skipped_symlinks)
    return src


def add_databases(out, src):
    """Put the databases that stay into the tree: their staged copies, after the checks (a database that is left out leaves
    nothing behind, also no hard link to it: `settle_links`), then the hard links to them. `out`: a TreeTar."""
    for staged, path in sorted(src.dbs.items()):
        if staged in src.db_skip:
            continue
        rel, mode, mtime = src.db_meta[staged]
        with open(path, 'rb') as handle:
            size = os.fstat(handle.fileno()).st_size
            out.tar.add_member(hacommon.info(rel, 'file', mode=mode, uid=out.uid, gid=out.gid, mtime=mtime, size=size), handle)
        out.files.add(rel)
        out.counts['files'] += 1
        out.counts['bytes'] += size
    for name, target, mtime in src.kept_links:   # H-01: a hard link to a database follows its database
        out.hardlink(name, target, mtime)


# ====================================================================== the live target

class Target:
    """The hermes app's catalog items the import fills, resolved against the live Quadlet files. Whatever else this device's
    entry holds (a cold database's volume, a workspace folder) is carried as it is (H-03); only what the import cannot take
    at all stops the app (`hermes.layout-unsupported`, with what to do)."""

    def __init__(self, work, app, sink=None):
        quadlets = work.quadlets(app)
        home = work.runner(app).home
        declared = [v['name'] for v in app.volumes]
        agent_file, data_volume = hacommon.mounted(quadlets, home, '/opt/data')
        if agent_file is None or data_volume not in declared:
            raise haissues.stopped(Issue('hermes.layout-unsupported', 'stop',
                                         '這台 Hermes 的應用設定裡找不到掛在 /opt/data 的資料卷，不知道 HA 的資料要放在哪裡。',
                                         action='請到「應用軟體」確認這個應用的資料卷設定有包含 Hermes 存放資料的那個資料卷（掛在 /opt/data），再匯入。'),
                                   'incompatible', app=app.id)
        self.pgs = list(app.postgres)
        if any(pg.get('scope', 'database') != 'database' for pg in self.pgs):
            raise haissues.stopped(Issue('hermes.layout-unsupported', 'stop',
                                         '這台 Hermes 的資料庫備份模式是「整個執行個體」，Hermes 匯入還不支援這個模式。',
                                         action='請到「應用軟體」把這個應用的資料庫備份模式改成「單一資料庫」或「冷備份」，再匯入。'),
                                   'incompatible', app=app.id)
        self.data_volume = data_volume
        _file, redis = hacommon.mounted(quadlets, home, '/data')
        self.redis_volume = redis if redis in declared and redis != data_volume else None
        self.extra_volumes, self.extra_dirs = hatarget.extras(app, handled_volumes=(data_volume, self.redis_volume))
        self.image = tempctr.quadlet_image(quadlets[agent_file])
        if not self.image:
            raise BackupError('incompatible', '這台 Hermes 的 Quadlet 設定缺少映像。', app=app.id)
        env = hacommon.environment(quadlets, agent_file, {'HERMES_UID', 'HERMES_GID'})
        uid, gid = env.get('HERMES_UID', '10000'), env.get('HERMES_GID', env.get('HERMES_UID', '10000'))
        self.uid = self.gid = None
        if UID_RE.fullmatch(uid) and UID_RE.fullmatch(gid):
            self.uid, self.gid = int(uid), int(gid)
        if sink is not None:
            if self.uid is None:
                sink.auto('hermes.owner-from-folder', '這台 Hermes 的 HERMES_UID／HERMES_GID 設定不是數字，改用這台現有資料夾的擁有者，'
                                                     '搬過來的檔案會歸它所有。')
            if self.extra_volumes or self.extra_dirs:
                sink.auto('hermes.extras-carried', '這台 Hermes 的應用設定還有 Hermes 匯入不處理的資料卷或資料夾，'
                                                  '匯入時會照這台現在的內容原樣帶過去，不會變。',
                          [*self.extra_volumes, *self.extra_dirs])

    def owner(self, root):
        """(uid, gid) every moved file gets: this device's HERMES_UID/GID, else the live folder's owner `root` (H-05)."""
        return (self.uid, self.gid) if self.uid is not None else (root[0], root[1])


def target_release(work, app, target):
    """(x.y.z, digest) of the live image's Hermes base (label io.woowtech.hermes.base), (None, None) when unknown (H-07: the
    version is then only not compared)."""
    try:
        base = hacommon.image_labels(work, app, target.image).get(BASE_LABEL, '')
    except BackupError as error:
        if error.code != 'job-failed':   # an image that is not here is the app's stop; labels that cannot be read are not
            raise
        base = ''
    match = re.fullmatch(r'[A-Za-z0-9./_-]+:(v?[0-9.]+)(?:@(sha256:[0-9a-f]{64}))?', base)
    if match and hacommon.semver(match.group(1)):
        return hacommon.semver(match.group(1)), match.group(2)
    reader = getattr(work, 'image_version', None)
    if reader is None:
        return None, None
    return reader(app, target.image, env=('HERMES_VERSION',),
                  command=('/opt/hermes/bin/hermes', '--version')), None


def judge(sink, src, answers, *, addon_version, release, digest):
    """What the check and the conversion say about HA's Hermes: every finding goes to `sink` (the check collects, the conversion
    stops at a `stop` and wants a `confirm` confirmed); returns the details (counts). `answers`: the SQLite child's, by staged
    name of the main databases. Decides what stays out of the tree (`src.db_skip`)."""
    sink.extend(VERSIONS.issues(addon_version, release))   # H-06, H-07: the table and this device's version only inform
    mine = VERSIONS.upstream(addon_version)
    if (mine is not None and release is not None and hacommon.semver(mine) == hacommon.semver(release) and digest
            and BASE_DIGESTS.get(mine) and digest != BASE_DIGESTS[mine]):
        sink.notice('hermes.digest-differs', f'兩邊都是 Hermes {mine}，但這台映像的上游版本摘要和 HA 的不同，請確認兩邊用的是同一個版本。')
    if src.image_version is None:
        sink.notice('hermes.image-version-missing', 'HA 的 Hermes 資料沒有記錄附加元件版本（.woow-image-version），以 HA 備份中的'
                                                   '附加元件版本為準。')
    elif src.image_version != addon_version:   # H-09
        sink.notice('hermes.image-version-differs', f'HA 的 Hermes 資料是附加元件 {haissues.clean(src.image_version, 40)} 留下的，'
                                                   f'和備份中的附加元件版本 {haissues.clean(addon_version, 40)} 不同（HA 更新後'
                                                   '還沒啟動過就備份）；資料照樣搬，Hermes 啟動時會自己整理。')
    details = {'sessions': 0, 'messages': 0, 'schema_version': None, 'databases': 0}
    skipped = haissues.Names()
    unchecked = haissues.Names()
    if 'state.db' in src.bad_groups:
        sink.stop('hermes.state-db-unusable', 'HA 的 Hermes 主資料庫（state.db）或它的 WAL 不是一般檔案（是連結或資料夾），'
                                              '沒有可以安全搬過來的對話。', action='請在 HA 重新備份後再匯入 Hermes；這台的 Hermes 不會變。')
    elif 'state.db' not in src.dbs:   # H-10: HA's Hermes never started: only Hermes is left out, this device's chats stay
        sink.stop('hermes.no-state-db', 'HA 備份裡沒有 Hermes 的資料（state.db），可能從來沒有啟動過；沒有可搬的資料，這台的 Hermes 不會變。',
                  action='請先在 HA 啟動 Hermes 並使用一次，再重新備份後匯入；不需要搬 Hermes 時，取消勾選它即可。')
    for db in sorted(src.bad_groups - {'state.db'}):
        skipped.add(db)
    mains = sorted(name for name in src.dbs if not name.endswith(SIDECARS))
    for staged in mains:
        rel = src.db_meta[staged][0]
        answer = answers.get(staged) or {'error': 'no answer'}
        why = hasqlite.problem(answer)
        if why and answer.get('error') == VIRTUAL_ERROR:   # H-11: an index structure the sandbox does not know
            unchecked.add(rel)
            details['databases'] += 1
            continue
        if why:
            if staged == 'state.db':
                sink.stop('hermes.state-db-unusable', f'HA 的 Hermes 主資料庫（state.db）已損毀或無法讀取（{haissues.clean(why, 120)}）。',
                          action='請在 HA 重新備份後再匯入 Hermes；這台的 Hermes 不會變。')
            else:
                skipped.add(rel)
                src.db_skip.update(name for name in src.dbs if name in (staged, *(staged + s for s in SIDECARS)))
            continue
        details['databases'] += 1
        if staged == 'state.db':
            counts = answer.get('counts') or {}
            details['sessions'] = ha_odoo._int(counts.get('sessions'))
            details['messages'] = ha_odoo._int(counts.get('messages'))
            details['schema_version'] = (answer.get('values') or {}).get('hermes.schema_version')
    settle_links(src)   # H-01: the databases are decided: a hard link to one follows it
    schema = details['schema_version']
    state = answers.get('state.db')
    if state is not None and not hasqlite.problem(state) and (type(schema) is not int or schema < 0):   # H-12 (kept)
        sink.stop('hermes.schema-unreadable', 'HA 的 Hermes 資料庫結構版本無法判讀，無法安全匯入。',
                  action='請先在 HA 更新並啟動一次 Hermes，再重新備份後匯入。')
    if type(schema) is int and schema > SCHEMA_VERSION:   # H-13 (kept)
        sink.stop('hermes.schema-newer', f'HA 的 Hermes 資料庫結構（{schema}）比這台的 Hermes 新（{SCHEMA_VERSION}），無法搬過來。',
                  action='請先更新這台的 Hermes，再匯入。')
    if src.config_version is not None and src.config_version > CONFIG_VERSION:   # H-14
        sink.notice('hermes.config-newer', f'HA 的 Hermes 設定檔版本（{src.config_version}）比這台的 Hermes 新（{CONFIG_VERSION}），'
                                           '照樣搬過來；這台的 Hermes 看不懂的新設定項目會被忽略。')
    if src.foreign:   # H-16
        sink.notice('hermes.foreign-programs', f'HA 的 Hermes 資料含有其他處理器的程式（{len(src.foreign)} 個），照樣搬過來；'
                                               '對話、記憶和技能都能用，但這些外掛或虛擬環境在這台跑不起來，請在這台重新安裝。',
                    src.foreign[:200])
    if src.copied:   # H-01
        sink.auto('hermes.links-copied', f'HA 的 Hermes 資料中有 {src.copied} 個硬連結指到沒有搬過來的執行期檔案，已改成複製檔案內容。')
    if src.unread.count:   # H-20, H-21
        sink.notice('hermes.text-unread', '有很大的文字檔（設定檔、排程或技能說明）照原樣搬過來，沒有讀它的內容，所以版本與位址的提醒不含它們。',
                    src.unread)
    if unchecked.count:   # H-11
        sink.notice('hermes.db-unchecked', 'HA 的 Hermes 資料庫含有這台的檢查程式不認得的索引結構，無法先檢查內容；它們照原樣搬過來，'
                                           '由 Hermes 自己開啟。', unchecked)
    if src.specials.count:   # H-02
        sink.confirm('hermes.entries-skipped', f'HA 的 Hermes 資料中有 {src.specials.count} 個項目應該是一般檔案，但在備份裡是連結或資料夾，'
                                               '不會搬過來（這台的 Hermes 啟動時會重新建立它們）。', src.specials)
    if skipped.count:   # H-02, H-11
        sink.confirm('hermes.databases-skipped', f'HA 的 Hermes 有 {skipped.count} 個次要資料庫損毀或不是一般檔案，不會搬過來；'
                                                 '這台的 Hermes 啟動時會建立新的空資料庫，那一部分的紀錄會從頭開始。', skipped)
    if src.report is not None:   # a Source that was made by hand (a test) has no walk
        sink.skipped(src.report)   # H-01, X-NS-08, IN-27, IN-28, IN-35, IN-38, UP: the reader's own list, one line
    if src.ha_urls:
        sink.notice('hermes.ha-addresses', f'HA 的 Hermes 設定連到 HA 內部的位址（{hacommon.names(sorted(src.ha_urls), 8)}），這台連不到，'
                                           '搬過來後請改成實際位址。')
    if src.media_refs:
        sink.notice('hermes.media-refs', f'HA 的 Hermes 設定或技能提到 /media 共 {src.media_refs} 處；HA 的 /media 不會搬過來。')
    if src.plugins:
        sink.notice('hermes.plugins-replaced', f'HA 的 Hermes 外掛（{hacommon.names(sorted(src.plugins))}）會一起搬過來並取代這台的外掛；'
                                               'Omnigent、Paseo 等配對需要重新設定。')
    return details


def analyse(src, answers, *, addon_version, release, digest):
    """(blockers, warnings, details) of HA's Hermes against this device, the sentences the older pages read: the lines that
    stop or must be confirmed, and the others. `judge` with a sink that only collects."""
    sink = haissues.Sink(APP_ID)
    details = judge(sink, src, answers, addon_version=addon_version, release=release, digest=digest)
    return ([i.message for i in sink.found if i.level in ('stop', 'confirm')],
            [i.message for i in sink.found if i.level in ('auto', 'notice')], details)


def section(src, details, *, release):
    return {'hermes_version': VERSIONS.upstream(src.addon.version) if src.addon else '',
            'target_release': release or '',
            'files': src.counts.get('files', 0), 'bytes': src.counts.get('bytes', 0), 'dirs': src.counts.get('dirs', 0),
            'symlinks': src.counts.get('symlinks', 0), 'absolute_symlinks': src.counts.get('absolute_symlinks', 0),
            'hardlinks': src.counts.get('hardlinks', 0), 'databases': details['databases'],
            'sessions': details['sessions'], 'messages': details['messages'],
            'schema_version': details['schema_version'], 'config_version': src.config_version,
            'skills': src.skills, 'cron_jobs': src.cron_jobs, 'plugins': sorted(src.plugins),
            'env_keys': len(src.env_keys), 'ha_urls': sorted(src.ha_urls)[:20], 'media_refs': src.media_refs,
            'skipped': src.skipped[:20]}


# ====================================================================== the job steps

def _inspect(work, src, staging):
    """The SQLite child over the staged known databases: quick_check each; state.db's counts and schema."""
    mains = sorted(name for name in src.dbs if not name.endswith(SIDECARS))
    if not mains:
        return {}
    specs = [{'db': name, 'check': 'quick'} for name in mains]
    for spec in specs:
        if spec['db'] == 'state.db':
            spec.update(counts=['sessions', 'messages'], queries=['hermes.schema_version'], hermes_fts=True)
    answers = hasqlite.run(specs, dict(src.dbs), staging / 'sqlite', checkpoint=work.checkpoint, what='Hermes 資料庫')
    return {name: answer for name, answer in answers.items() if name is not None}


def _pass(work, app, staging, out, report):
    member = work.addon_member(SLUG)
    with work.open(member) as stream:
        src = scan_member(stream, report, staging, out, machine=hacommon.host_elf_machine(), guard=work.guard,
                          checkpoint=work.checkpoint)
    for note in report.warnings():
        work.log(note)
    work.log(f'HA 的 Hermes：{src.counts.get("files", 0)} 個檔案（{src.counts.get("bytes", 0) / 1048576:.1f} MiB），'
             f'{src.counts.get("symlinks", 0)} 個符號連結，{src.counts.get("hardlinks", 0)} 個硬連結')
    return src


def check(work, app):
    sink = work.sink(app)
    target = Target(work, app, sink)
    release, digest = target_release(work, app, target)
    staging = work.staging / 'hermes-work'
    staging.mkdir(mode=0o700)
    report = habackup.Report(names=haissues.Names)
    src = _pass(work, app, staging, _Count(report), report)
    work.phase('check')
    answers = _inspect(work, src, staging)
    addon = work.addon_info(SLUG)
    details = judge(sink, src, answers, addon_version=addon.version, release=release, digest=digest)
    return {'target_version': release or '', 'hermes': section(src, details, release=release)}


def convert(work, app, test_mode, out_dir):
    """Build `out_dir/volumes/<hermes-data>.tar`, the Redis volume's top folder, the live database dump(s) and what else this
    device's entry holds (carried as it is)."""
    sink = work.sink(app)
    adapter = work.adapter(app)
    target = Target(work, app, sink)
    release, digest = target_release(work, app, target)
    ids = adapter.owner_ids()
    staging = work.staging / 'hermes-work'
    staging.mkdir(mode=0o700)
    for sub in ('volumes', 'postgres'):
        (out_dir / sub).mkdir(mode=0o700, parents=True, exist_ok=True)
    data_path = out_dir / 'volumes' / f'{target.data_volume}.tar'
    root = ha_n8n.volume_root(work, app, target.data_volume)
    uid, gid = target.owner(root)
    report = habackup.Report(names=haissues.Names)
    out = hacommon.TreeTar(data_path, uid, gid, work.guard, report=report)
    try:
        out.root(root[2], root[0], root[1])
        src = _pass(work, app, staging, out, report)
        work.phase('convert')
        answers = _inspect(work, src, staging)
        addon = work.addon_info(SLUG)
        details = judge(sink, src, answers, addon_version=addon.version, release=release, digest=digest)
        add_databases(out, src)
    finally:
        out.close()
    volumes = {target.data_volume: data_path}
    if target.redis_volume is not None:
        redis_path = out_dir / 'volumes' / f'{target.redis_volume}.tar'
        tar = hacommon.FileTar(redis_path, work.guard)
        try:
            hacommon.top_only(tar, ha_n8n.volume_root(work, app, target.redis_volume))
        finally:
            tar.close()
        volumes[target.redis_volume] = redis_path
    postgres = {}
    if target.pgs:
        work.log('Hermes 未使用的 PostgreSQL 資料庫維持這台現有的內容')
    for pg in target.pgs:
        dump = adapter._dump_database(pg, out_dir)
        postgres[pg['id']] = {k: dump[k] for k in ('database', 'server_version', 'major', 'file')}
    for path in volumes.values():
        ha_odoo.check_volume_tar(path, ids)
    dirs = {}
    if target.extra_volumes or target.extra_dirs:   # H-03: this device's own other data goes along as it is
        carried = hatarget.carry(work, app, out_dir, ids, volumes=target.extra_volumes, dirs=target.extra_dirs,
                                 report=report, size=hatarget.size_hint(work.ha))
        volumes.update(carried['volumes'])
        dirs = carried['dirs']
        sink.skipped(report)   # X-NS-08: a link of this device's own data the restore would refuse is left out and listed
    if details['databases']:
        work.log(f'Hermes 資料整理完成：{details["sessions"]} 個對話、{details["messages"]} 則訊息')
    else:
        work.log('Hermes 資料整理完成')
    result = {'volumes': volumes, 'postgres': postgres,
              'sessions': details['sessions'], 'messages': details['messages'], 'plugins': sorted(src.plugins),
              'ha_urls': sorted(src.ha_urls), 'media_refs': src.media_refs, 'cron_jobs': src.cron_jobs}
    if dirs:
        result['dirs'] = dirs
    return result


# ====================================================================== texts

def import_texts(data):
    notes = ['Hermes 的對話、記憶、技能、排程、外掛與 HA 的設定檔（config.yaml）會換成 HA 的；這台的 Dashboard 密碼、'
             'API 金鑰、Webhook 與工作階段金鑰以及 hermes.env 保持不變，hermes.env 中的金鑰會蓋過 HA 的同名金鑰。']
    if data.get('plugins'):
        notes.append(f'HA 的 Hermes 外掛（{hacommon.names(data["plugins"])}）會取代這台的外掛與配對（例如 Omnigent、Paseo）。')
    reminders = ['匯入後請用這台的 Hermes Dashboard 密碼登入（不是 HA 的）。',
                 '呼叫 Hermes API 或 Webhook 的地方請改用這台的網址與 API 金鑰；沒有自己金鑰的 Webhook 路由要改用這台的全域金鑰。',
                 '請重新配對 Hermes 的 Omnigent 與 Paseo 外掛，HA 上的配對不會沿用。']
    if data.get('ha_urls'):
        reminders.append(f'HA 的 Hermes 設定連到 HA 內部的位址（{hacommon.names(data["ha_urls"], 8)}），請改成這台連得到的位址'
                         '（例如這台的 LiteLLM：http://litellm:4000/v1）。')
    if data.get('media_refs'):
        reminders.append('HA 的 /media 資料夾沒有搬過來，用到它的設定、排程或技能請改用這台的資料夾。')
    if data.get('cron_jobs'):
        reminders.append(f'HA 的 {data["cron_jobs"]} 個 Hermes 排程會在這台執行，請先停掉 HA 的 Hermes，避免重複執行。')
    return notes, reminders
