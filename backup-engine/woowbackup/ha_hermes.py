"""Home Assistant import, Hermes part: the WOOWTECH add-on `woow-hermes` -> this device's app `hermes` (CONTRACT section
9 "Home Assistant import"; facts phase3/facts/hermes.md). Owner: E2.

The add-on maps its `addon_config` folder at /opt/data, Hermes's HERMES_HOME: every piece of state is SQLite files and
plain files there (`config/**` in the backup member; HA already leaves out `logs`, `lazy-packages`, `.cache`, `.npm`).
`data/**` holds only HA's options, HA's generated dashboard/API/webhook/session secrets and the hashes of applied
provider keys: never read (habackup.NEVER_READ). The target is the Podman package: the volume `hermes-data` at
/opt/data owned by the Quadlet's HERMES_UID/HERMES_GID, an unused PostgreSQL 15 (`main`) and Redis.

Versions: the add-on version maps to a Hermes release (VERSIONS) that must equal the tag of the live image's base
(label `io.woowtech.hermes.base`); `config/.woow-image-version` must name the add-on version; HA's `state.db`
`schema_version` and `config.yaml` `_config_version` must not be newer than this release's.

The tree moves as it is -- data, the data's own keys (vault, OAuth tokens, per-route webhook secrets, plugin logins)
and HA's `config.yaml` -- with every owner set to this device's hermes uid/gid and no setuid/setgid bit; symlinks stay
link entries (relative ones that stay in the tree, absolute ones only into /opt/data, /opt/hermes or /usr: a venv's
interpreter), hard links stay hard links to an earlier file of the same tree (uv's ~14,000 links; a link to a file
that does not move stops the import instead of cutting the subtree), nothing is ever followed. Left out: the
gateway's runtime files, `.woow-image-version` (the first start then resets the caches), `.woow-dotenv` (Podman's
record of applied keys: without it the first start applies this device's hermes.env, whose keys win over HA's), every
`-shm` wal-index, the browser login profiles (a credential store, never archived upstream either). HA's `.env` keeps
HA's provider keys but loses the lines this device's secrets and URLs own (API_SERVER_KEY, WEBHOOK_SECRET,
HERMES_DASHBOARD_BASIC_AUTH_*, HERMES_DASHBOARD_PUBLIC_URL, HERMES_BASE_URL, HERMES_PASEO_*). The SQLite files move
unchanged with their WAL; the sandboxed child (hasqlite) checks each known database (`quick_check`) and reads
`state.db`'s counts and schema version; known Hermes FTS5 layouts are allowed, their index structure is checked
by quick_check in the sandbox, but an index is not compared with its messages. `hermes-redis-data` is only its top folder (owned like the live one) and the
database `main` is a dump of the live, unused database (this device's own, unchanged). HA's /media is never moved.
"""
import re

from . import habackup, hacommon, hasqlite, ha_n8n, ha_odoo, tempctr
from .errors import BackupError

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
MANAGED_ENV_RE = re.compile(rb'\s*(?:export\s+)?(?:\x27)?(?:API_SERVER_KEY|WEBHOOK_SECRET|HERMES_DASHBOARD_BASIC_AUTH_[A-Z_]*'
                            rb'|HERMES_DASHBOARD_PUBLIC_URL|HERMES_BASE_URL|HERMES_PASEO_[A-Z_]*)(?:\x27)?\s*=')
ENV_KEY_RE = re.compile(rb'\s*(?:export\s+)?(?:\x27)?([A-Za-z_][A-Za-z0-9_]{0,100})(?:\x27)?\s*=')
CONFIG_VERSION_RE = re.compile(r'^_config_version:\s*([0-9]{1,6})\s*$', re.M)
MAX_ENV = 1024 * 1024
MASK_MIN = 12
MAX_TEXT = 8 * 1024 * 1024
MAX_SKILL = 4 * 1024 * 1024
UID_RE = re.compile(r'[0-9]{1,9}\Z')


def flat(rel):
    """The staged name of a known database (or its sidecar): `cron/executions.db-wal` -> `cron.executions.db-wal`."""
    return rel.replace('/', '.')


class Source:
    def __init__(self):
        self.addon = None
        self.image_version = None
        self.env_keys = []
        self.env_symlink = False
        self.ha_urls = set()
        self.media_refs = 0
        self.config_version = None
        self.cron_jobs = 0
        self.skills = 0
        self.plugins = set()
        self.dbs = {}             # staged name -> path
        self.skipped = []         # runtime files, -shm, ...
        self.foreign = []         # programs for another processor
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
    """An Entry read by tarfile while a copy goes to `handle` (a known database staged for the SQLite child)."""

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


def scan_member(stream, report, staging, out, *, machine=None, guard=None, checkpoint=None):
    """One strict pass over `config/**` into `out` (a TreeTar or _Count; names relative to the tree); the known
    databases and their sidecars are also staged in `staging` for the SQLite child. Returns a Source."""
    import os
    select = habackup.Select(include=(TREE,), exclude=tuple(f'{TREE}/{name}' for name in EXCLUDED_DIRS),
                             symlinks=(TREE,), absolute_symlinks=ABSOLUTE_LINKS, hardlinks=True)
    src = Source()
    count = 0
    for entry in habackup.iter_entries(stream, select, report, checkpoint=checkpoint):
        count += 1
        if checkpoint is not None and count % 256 == 0:
            checkpoint()
        if entry.name == TREE:
            continue  # the volume's top folder is the live one
        rel = entry.name[len(TREE) + 1:]
        top, _, rest = rel.partition('/')
        if top == 'plugins' and rest and '/' not in rest and entry.kind == 'dir':
            src.plugins.add(rest[:100])
        special = rel in ('.env', 'config.yaml', 'cron/jobs.json', '.woow-image-version') or _known_db(rel) is not None
        if (special and entry.kind != 'file') or (rel == 'cron' and entry.kind != 'dir'):
            raise BackupError('incompatible', f'HA 的 Hermes 資料 {rel} 不是一般檔案或目錄，無法安全匯入。', member=rel)
        if entry.kind == 'dir':
            out.dir(rel, entry.mode, entry.mtime)
            continue
        if entry.kind == 'symlink':
            if rel == '.env':
                src.env_symlink = True
            out.symlink(rel, entry.linkname, entry.mtime)
            continue
        if entry.kind == 'hardlink':
            out.hardlink(rel, entry.linkname[len(TREE) + 1:], entry.mtime)
            continue
        # a regular file
        if '/' not in rel and rel in RUNTIME_FILES:
            if rel == '.woow-image-version':
                src.image_version = entry.read_all(1024).decode('ascii', 'replace').strip()[:64]
            src.skipped.append(rel)
            continue
        if rel.endswith('-shm'):
            src.skipped.append(rel)
            continue
        if machine is not None and hacommon.foreign_elf(entry.peek(20), machine) and len(src.foreign) < 1000:
            src.foreign.append(rel)
        mode = entry.mode
        if rel == '.env':
            data, src.env_keys, values = strip_env(entry.read_all(MAX_ENV))
            from . import jobs
            for value in values:
                if len(value) >= MASK_MIN:  # provider keys and tokens: masked in every log line of this job
                    jobs.mask_secret(value)
            src.ha_urls.update(f'.env：{host}' for host in hacommon.ha_hosts(data.decode('utf-8', 'replace')))
            out.data(rel, data, mode, entry.mtime)
            continue
        if rel in ('config.yaml', 'cron/jobs.json') or (rel.startswith('skills/') and rel.endswith('/SKILL.md')):
            data = entry.read_all(MAX_SKILL if rel.endswith('SKILL.md') else MAX_TEXT)
            text = data.decode('utf-8', 'replace')
            src.media_refs += text.count('/media/')
            if rel == 'config.yaml':
                match = CONFIG_VERSION_RE.search(text)
                src.config_version = int(match.group(1)) if match else None
                src.ha_urls.update(f'config.yaml：{host}' for host in hacommon.ha_hosts(text))
            elif rel == 'cron/jobs.json':
                doc = hacommon.strict_json(data, MAX_TEXT)
                jobs = doc.get('jobs') if isinstance(doc, dict) else doc
                src.cron_jobs = len(jobs) if isinstance(jobs, (list, dict)) else 0
            else:
                src.skills += 1
            out.data(rel, data, mode, entry.mtime)
            continue
        db = _known_db(rel)
        if db is not None:
            path = staging / flat(rel)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                if isinstance(out, hacommon.TreeTar):
                    out.tar.add_member(hacommon.info(rel, 'file', mode=mode & 0o777, uid=out.uid, gid=out.gid,
                                                     mtime=entry.mtime, size=entry.size), _Tee(entry, handle))
                    out.files.add(rel)
                    out.counts['files'] += 1
                    out.counts['bytes'] += entry.size
                else:
                    entry.copy_to(handle)
                    out.data(rel, b'', mode, entry.mtime)
                    out.counts['bytes'] += entry.size
                handle.flush()
                os.fsync(handle.fileno())
            src.dbs[flat(rel)] = path
            continue
        out.file(rel, entry, mode)
    src.addon = report.addon
    src.counts = dict(out.counts, absolute_symlinks=report.absolute_symlinks, skipped_symlinks=report.skipped_symlinks)
    return src


# ====================================================================== the live target

class Target:
    """The hermes app's catalog items the import fills, resolved against the live Quadlet files."""

    def __init__(self, work, app):
        quadlets = work.quadlets(app)
        home = work.runner(app).home
        declared = [v['name'] for v in app.volumes]
        agent_file, data_volume = hacommon.mounted(quadlets, home, '/opt/data')
        redis_volumes = [v for v in declared if v != data_volume]
        if (agent_file is None or data_volume not in declared or len(declared) != 2 or len(redis_volumes) != 1
                or len(app.postgres) != 1 or app.postgres[0].get('scope', 'database') != 'database' or app.data_dirs):
            raise BackupError('incompatible', '這台的 Hermes 應用設定和 Quadlet 檔不一致，無法匯入。', app=app.id)
        self.data_volume, self.redis_volume = data_volume, redis_volumes[0]
        self.pg = app.postgres[0]
        self.image = tempctr.quadlet_image(quadlets[agent_file])
        if not self.image:
            raise BackupError('incompatible', '這台 Hermes 的 Quadlet 設定缺少映像。', app=app.id)
        env = hacommon.environment(quadlets, agent_file, {'HERMES_UID', 'HERMES_GID'})
        uid, gid = env.get('HERMES_UID', '10000'), env.get('HERMES_GID', env.get('HERMES_UID', '10000'))
        if not UID_RE.fullmatch(uid) or not UID_RE.fullmatch(gid):
            raise BackupError('incompatible', '這台 Hermes 的 HERMES_UID／HERMES_GID 設定格式不正確。', app=app.id)
        self.uid, self.gid = int(uid), int(gid)


def target_release(work, app, target):
    """(x.y.z, digest) of the live image's Hermes base (label io.woowtech.hermes.base), (None, None) when unknown."""
    base = hacommon.image_labels(work, app, target.image).get(BASE_LABEL, '')
    match = re.fullmatch(r'[A-Za-z0-9./_-]+:(v?[0-9.]+)(?:@(sha256:[0-9a-f]{64}))?', base)
    if not match:
        return None, None
    return hacommon.semver(match.group(1)), match.group(2)


def analyse(src, answers, *, addon_version, release, digest):
    """(blockers, warnings, details) of HA's Hermes against this device."""
    blockers, warnings = [], []
    blocker = VERSIONS.blocker(addon_version, release)
    if blocker:
        blockers.append(blocker)
    mine = VERSIONS.upstream(addon_version)
    if not blocker and digest and BASE_DIGESTS.get(mine) and digest != BASE_DIGESTS[mine]:
        warnings.append(f'兩邊都是 Hermes {mine}，但這台映像的上游版本摘要和 HA 的不同，請確認兩邊用的是同一個版本。')
    if src.image_version is None:
        warnings.append('HA 的 Hermes 資料沒有記錄附加元件版本（.woow-image-version），以 HA 備份中的附加元件版本為準。')
    elif src.image_version != addon_version:
        blockers.append(f'HA 的 Hermes 資料是附加元件 {src.image_version} 留下的，和備份中的附加元件版本 {addon_version} 不同；'
                        '請先啟動一次 HA 的 Hermes 再重新備份。')
    if 'state.db' not in src.dbs:
        blockers.append('HA 備份裡沒有 Hermes 的資料（state.db），可能從來沒有啟動過；沒有可搬的資料。')
    details = {'sessions': 0, 'messages': 0, 'schema_version': None, 'databases': len(
        [n for n in src.dbs if not n.endswith(SIDECARS)])}
    for name, answer in sorted(answers.items()):
        why = hasqlite.problem(answer)
        if why:
            blockers.append(f'HA 的 Hermes 資料庫 {name} 已損毀或無法讀取（{why}）。')
            continue
        if name == 'state.db':
            counts = answer.get('counts') or {}
            details['sessions'] = ha_odoo._int(counts.get('sessions'))
            details['messages'] = ha_odoo._int(counts.get('messages'))
            details['schema_version'] = (answer.get('values') or {}).get('hermes.schema_version')
    schema = details['schema_version']
    if 'state.db' in answers and not hasqlite.problem(answers['state.db']) and (type(schema) is not int or schema < 0):
        blockers.append('HA 的 Hermes 資料庫結構版本無法判讀，無法安全匯入。')
    if type(schema) is int and schema > SCHEMA_VERSION:
        blockers.append(f'HA 的 Hermes 資料庫結構（{schema}）比這台的 Hermes 新（{SCHEMA_VERSION}），無法搬過來。')
    if src.config_version is not None and src.config_version > CONFIG_VERSION:
        blockers.append(f'HA 的 Hermes 設定檔版本（{src.config_version}）比這台的 Hermes 新（{CONFIG_VERSION}），無法搬過來。')
    if src.env_symlink:
        blockers.append('HA 的 Hermes 金鑰檔（.env）是符號連結，這台的 Hermes 會拒絕啟動；請先在 HA 改成一般檔案再備份。')
    if src.foreign:
        blockers.append(f'HA 的 Hermes 資料含有其他處理器的程式（{len(src.foreign)} 個，例如 {hacommon.names(src.foreign, 3)}），'
                        '搬過來後無法執行。')
    if src.counts.get('skipped_symlinks'):
        warnings.append(f'HA 的 Hermes 資料中有 {src.counts["skipped_symlinks"]} 個指向資料以外的符號連結沒有搬過來。')
    if src.ha_urls:
        warnings.append(f'HA 的 Hermes 設定連到 HA 內部的位址（{hacommon.names(sorted(src.ha_urls), 8)}），這台連不到，'
                        '搬過來後請改成實際位址。')
    if src.media_refs:
        warnings.append(f'HA 的 Hermes 設定或技能提到 /media 共 {src.media_refs} 處；HA 的 /media 不會搬過來。')
    if src.plugins:
        warnings.append(f'HA 的 Hermes 外掛（{hacommon.names(sorted(src.plugins))}）會一起搬過來並取代這台的外掛；'
                        'Omnigent、Paseo 等配對需要重新設定。')
    return blockers, warnings, details


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


def _pass(work, app, staging, out):
    member = work.addon_member(SLUG)
    report = habackup.Report()
    with work.open(member) as stream:
        src = scan_member(stream, report, staging, out, machine=hacommon.host_elf_machine(), guard=work.guard,
                          checkpoint=work.checkpoint)
    for note in report.warnings():
        work.log(note)
    work.log(f'HA 的 Hermes：{src.counts.get("files", 0)} 個檔案（{src.counts.get("bytes", 0) / 1048576:.1f} MiB），'
             f'{src.counts.get("symlinks", 0)} 個符號連結，{src.counts.get("hardlinks", 0)} 個硬連結')
    return src


def check(work, app):
    target = Target(work, app)
    release, digest = target_release(work, app, target)
    staging = work.staging / 'hermes-work'
    staging.mkdir(mode=0o700)
    src = _pass(work, app, staging, _Count())
    work.phase('check')
    answers = _inspect(work, src, staging)
    addon = work.addon_info(SLUG)
    blockers, warnings, details = analyse(src, answers, addon_version=addon.version, release=release, digest=digest)
    return {'target_version': release or '', 'blockers': blockers, 'warnings': warnings,
            'hermes': section(src, details, release=release)}


def convert(work, app, test_mode, out_dir):
    """Build `out_dir/volumes/<hermes-data>.tar`, the Redis volume's top folder and the live database dump."""
    adapter = work.adapter(app)
    target = Target(work, app)
    release, digest = target_release(work, app, target)
    ids = adapter.owner_ids()
    staging = work.staging / 'hermes-work'
    staging.mkdir(mode=0o700)
    for sub in ('volumes', 'postgres'):
        (out_dir / sub).mkdir(mode=0o700, parents=True, exist_ok=True)
    data_path = out_dir / 'volumes' / f'{target.data_volume}.tar'
    root = ha_n8n.volume_root(work, app, target.data_volume)
    out = hacommon.TreeTar(data_path, target.uid, target.gid, work.guard)
    try:
        out.root(root[2], root[0], root[1])
        src = _pass(work, app, staging, out)
    finally:
        out.close()
    work.phase('convert')
    answers = _inspect(work, src, staging)
    addon = work.addon_info(SLUG)
    blockers, _warnings, details = analyse(src, answers, addon_version=addon.version, release=release, digest=digest)
    if blockers:
        raise BackupError('incompatible', f'Hermes 不能搬過來：{blockers[0]}', app=app.id)
    redis_path = out_dir / 'volumes' / f'{target.redis_volume}.tar'
    tar = hacommon.FileTar(redis_path, work.guard)
    try:
        hacommon.top_only(tar, ha_n8n.volume_root(work, app, target.redis_volume))
    finally:
        tar.close()
    work.log('Hermes 未使用的 PostgreSQL 資料庫維持這台現有的內容')
    dump = adapter._dump_database(target.pg, out_dir)
    for path in (data_path, redis_path):
        ha_odoo.check_volume_tar(path, ids)
    work.log(f'Hermes 資料整理完成：{details["sessions"]} 個對話、{details["messages"]} 則訊息')
    return {'volumes': {target.data_volume: data_path, target.redis_volume: redis_path},
            'postgres': {target.pg['id']: {k: dump[k] for k in ('database', 'server_version', 'major', 'file')}},
            'sessions': details['sessions'], 'messages': details['messages'], 'plugins': sorted(src.plugins),
            'ha_urls': sorted(src.ha_urls), 'media_refs': src.media_refs, 'cron_jobs': src.cron_jobs}


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
