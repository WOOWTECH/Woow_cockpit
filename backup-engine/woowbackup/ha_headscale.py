"""Home Assistant import, Headscale part: the WOOWTECH add-on `woow-headscale` -> this device's app `headscale`
(CONTRACT section 9 "Home Assistant import"; facts phase3/facts/headscale.md). Owner: E2.

The add-on keeps its whole VPN state in /var/lib/headscale (`data/`): the SQLite database `db.sqlite` (+ WAL; the
backup is cold), the control server's Noise identity `noise_private.key`, and in /etc/headscale (`config/`) the
MagicDNS extra records `dns_records.json` next to the `config.yaml` rendered from its options. HA's Headplane data,
its API key and cookie secret (`data/.headplane_*`, never read) and `data/options.json` do not move.

Versions: the add-on version maps to a Headscale version (VERSIONS) that must equal the live image's
`org.opencontainers.image.version`; the database's `database_versions` row must name it too and every applied
migration must be one that release knows. HA's IP prefixes must be this device's (an address outside them would never
be renumbered) and every node's addresses must lie inside them.

The database is read -- and changed -- only by the sandboxed SQLite child (hasqlite): integrity, schema (only
Headscale's tables, no trigger, no view), counts, version, migrations, node addresses; for the conversion HA's API keys
are replaced by this device's own rows, read from a copy of the live database (taken from the live volume's export,
integrity-checked), so the live Headplane and MCP admin keys keep working and HA's keys never administer this server;
the WAL is checkpointed into the file. `headscale-data` is built from scratch with the live volume's owner: the
converted `db.sqlite` (0644), HA's noise key (0600, masked in every log) and HA's DNS records at the live config's
`extra_records_path` (0644; `[]` when HA has none). Before it is packaged the live image runs `headscale configtest`
(network none, the live configuration read-only) on a throwaway copy of that volume: it opens the database, checks
the version path, applies migrations and validates the schema exactly as the server will. `headplane-data` is the live
export as it is (this device's Headplane logins and roles stay). The target keeps its `server_url`, prefixes, DNS and
policy configuration, every config file and secret. Database policies are replaced by HA policies; a live database policy blocks the import.
An app entry that names the package's read-only configuration folder as its one host folder -- the form catalog-suggest
drafts -- gets this device's own folder, packed as it is while Headscale runs.
"""
import os
import re
import tarfile
import time

from . import habackup, hacommon, hasqlite, ha_n8n, ha_odoo, nested, tempctr
from .errors import BackupError

SLUG = 'woow-headscale'
APP_ID = 'headscale'
DB = 'data/db.sqlite'
WAL = 'data/db.sqlite-wal'
NOISE = 'data/noise_private.key'
DNS = 'config/dns_records.json'
CONFIG = 'config/config.yaml'
DATA_TARGET = '/var/lib/headscale'
# Add-on version -> Headscale version (Woow_ha_vpn_headscale_package CHANGELOG.md, Dockerfile).
VERSIONS = hacommon.VersionTable('Headscale', {'0.1.0': '0.29.3', '0.1.1': '0.29.4', '0.1.2': '0.29.4',
                                               '0.1.3': '0.29.4'})
# The migrations Headscale 0.29.4 knows (hscontrol/db/db.go; `SCHEMA_INIT` is gormigrate's mark of a database its
# InitSchema created -- every fresh 0.29.x database has it, seen in the real backups); any other one is not this
# release's.
MIGRATIONS = {'0.29.4': frozenset({'SCHEMA_INIT',
    '202501221827', '202501311657', '202502070949', '202502131714', '202502171819', '202505091439', '202505141324',
    '202507021200', '202510311551', '202511101554-drop-old-idx', '202511011637-preauthkey-bcrypt',
    '202511122344-remove-newline-index', '202511131445-node-forced-tags-to-tags',
    '202601121700-migrate-hostinfo-request-tags', '202602201200-clear-tagged-node-user-id',
    '202605221435-clear-zero-time-node-expiry', '202606181200-recover-null-tags-node-user-id',
    '202607241200-clear-tagged-node-expiry'})}
TABLES = frozenset({'migrations', 'users', 'pre_auth_keys', 'api_keys', 'nodes', 'policies', 'database_versions',
                    'sqlite_sequence'})
COUNTED = ('users', 'nodes', 'pre_auth_keys', 'api_keys', 'policies')
NOISE_RE = re.compile(r'privkey:[0-9a-f]{64}\Z')
RECORD_KEYS = frozenset({'name', 'type', 'value'})
MAX_RECORDS = 10000
MAX_SMALL = 1024 * 1024
MAX_DB = 4 * 1024 ** 3


class Source:
    def __init__(self):
        self.addon = None
        self.db = None           # staged path
        self.wal = None
        self.noise = None        # the key text (masked)
        self.records = None      # bytes of a valid DNS records file, or None
        self.records_count = 0
        self.records_bad = False
        self.config = {}


def valid_records(data):
    """The number of records of a valid extra-records JSON array ({name, type, value} strings), else None."""
    doc = hacommon.strict_json(data, MAX_SMALL)
    if not isinstance(doc, list) or len(doc) > MAX_RECORDS:
        return None
    for item in doc:
        if not isinstance(item, dict) or not item or {k.lower() for k in item} - RECORD_KEYS \
                or len(item) != len({k.lower() for k in item}):
            return None
        if not all(isinstance(v, str) and 0 < len(v) <= 255 for v in item.values()):
            return None
    return len(doc)


def scan_member(stream, report, staging, *, checkpoint=None):
    """One strict pass: the database (+ WAL) staged root 0600, the noise key read and masked, the DNS records and
    HA's config.yaml read (bounded). Never: `-shm`, Headplane's data and secrets, options."""
    from . import jobs
    select = habackup.Select(include=(DB, WAL, NOISE, DNS, CONFIG), symlinks=(), hardlinks=False)
    src = Source()
    for entry in habackup.iter_entries(stream, select, report, checkpoint=checkpoint):
        if entry.kind != 'file':
            raise BackupError('incompatible', f'HA 備份中 Headscale 的 {entry.name[:100]} 不是一般檔案。', member=entry.name)
        if entry.name in (DB, WAL):
            if entry.size > MAX_DB:
                raise BackupError('limit-exceeded', 'HA 的 Headscale 資料庫過大。')
            path = staging / ('ha.sqlite' if entry.name == DB else 'ha.sqlite-wal')
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                entry.copy_to(handle)
                handle.flush()
                os.fsync(handle.fileno())
            if entry.name == DB:
                src.db = path
            else:
                src.wal = path
        elif entry.name == NOISE:
            text = entry.read_all(4096).decode('ascii', 'replace').strip()
            if text:
                jobs.mask_secret(text)
            src.noise = text if NOISE_RE.fullmatch(text) else ''
        elif entry.name == DNS:
            data = entry.read_all(MAX_SMALL)
            count = valid_records(data)
            src.records_bad = count is None
            src.records, src.records_count = (data, count) if count is not None else (None, 0)
        elif entry.name == CONFIG:
            src.config = hacommon.scalars(entry.read_all(MAX_SMALL).decode('utf-8', 'replace'))
    src.addon = report.addon
    return src


# ====================================================================== the live target

class Target:
    """The headscale app's catalog items the import fills, resolved against the live Quadlet files."""

    def __init__(self, work, app):
        quadlets = work.quadlets(app)
        home = work.runner(app).home.rstrip('/')
        declared = [v['name'] for v in app.volumes]
        server_file = hacommon.container_file(quadlets, 'headscale')
        if server_file is None:
            raise BackupError('incompatible', '這台的 Headscale 不是 WOOWTECH 的 Podman 版本（找不到 headscale 容器）。', app=app.id)
        mounts = ha_odoo.quadlet_mounts(quadlets, server_file, home)
        self.data_volume = next((s for s, t, _o in mounts if t == DATA_TARGET), None)
        config = next((s for s, t, _o in mounts if t == '/etc/headscale'), None)
        _file, self.headplane_volume = hacommon.mounted(quadlets, home, '/var/lib/headplane')
        dirs = [d['path'] for d in app.data_dirs]
        if (self.data_volume not in declared or self.headplane_volume not in declared or len(declared) != 2
                or app.postgres or config is None or not config.startswith(home + '/')
                or dirs not in ([], [config[len(home) + 1:]])):
            raise BackupError('incompatible', '這台的 Headscale 應用設定和 Quadlet 檔不一致，無法匯入。', app=app.id)
        self.config_dir = dirs[0] if dirs else None  # the configuration folder as the entry's host folder (docstring)
        self.config_mount = (config, '/etc/headscale', 'ro')
        self.config_rel = config[len(home) + 1:] + '/config.yaml'
        self.image = tempctr.quadlet_image(quadlets[server_file])
        if not self.image:
            raise BackupError('incompatible', '這台 Headscale 的 Quadlet 設定缺少映像。', app=app.id)


def live_config(work, app, target):
    try:
        data = work.runner(app).read_file(target.config_rel, max_bytes=MAX_SMALL)
    except BackupError:
        raise BackupError('incompatible', '無法讀取這台 Headscale 的設定檔。', app=app.id) from None
    return hacommon.scalars(data.decode('utf-8', 'replace'))


def data_paths(config):
    """Resolve configured identity files strictly inside the data volume."""
    paths = []
    for key, default in (('database.sqlite.path', '/var/lib/headscale/db.sqlite'),
                         ('noise.private_key_path', '/var/lib/headscale/noise_private.key')):
        path = config.get(key, default)
        if not isinstance(path, str) or not path.startswith(DATA_TARGET + '/'):
            raise BackupError('incompatible', f'Headscale 設定 {key} 必須位於 {DATA_TARGET}/ 內。')
        rel = path[len(DATA_TARGET) + 1:]
        if not rel or any(not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', part) or part in ('.', '..')
                          for part in rel.split('/')):
            raise BackupError('incompatible', f'Headscale 設定 {key} 的路徑不安全。')
        paths.append(rel)
    if (paths[1] in (paths[0], paths[0] + '-wal', paths[0] + '-shm')
            or paths[0].startswith(paths[1] + '/') or paths[1].startswith(paths[0] + '/')):
        raise BackupError('incompatible', 'Headscale 資料庫與身分金鑰的路徑衝突。')
    return tuple(paths)


def records_rel(config):
    """The extra-records file's path inside the data volume (None when the live config keeps it elsewhere)."""
    path = config.get('dns.extra_records_path') or ''
    if not path.startswith(DATA_TARGET + '/'):
        return None
    rel = path[len(DATA_TARGET) + 1:]
    return rel if re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', rel) and rel not in ('.', '..', 'db.sqlite',
                                                                            'noise_private.key') else None


# ====================================================================== analysis

def _specs(*, replace):
    ha = {'db': 'ha.sqlite', 'check': 'integrity', 'schema': True, 'counts': sorted(TABLES),
          'queries': ['headscale.version', 'headscale.migrations', 'headscale.node_ips', 'headscale.api_key_prefixes']}
    if replace:
        ha['replace_api_keys_from'] = 'live.sqlite'
        return [{'db': 'live.sqlite', 'check': 'integrity', 'queries': ['headscale.api_key_prefixes'], 'counts': ['policies']}, ha]
    return [ha]


def analyse(src, answer, *, addon_version, version, ha_config, config):
    """(blockers, warnings, details) of HA's Headscale against this device (`answer`: the child's on ha.sqlite)."""
    blockers, warnings = [], []
    blocker = VERSIONS.blocker(addon_version, version)
    if blocker:
        blockers.append(blocker)
    details = {'users': 0, 'nodes': 0, 'pre_auth_keys': 0, 'api_keys': 0, 'policies': 0, 'db_version': None}
    if src.db is None:
        blockers.append('HA 備份裡沒有 Headscale 的資料庫（db.sqlite），可能從來沒有啟動過；沒有可搬的資料。')
    elif answer is not None:
        why = hasqlite.problem(answer)
        if why:
            blockers.append(f'HA 的 Headscale 資料庫已損毀或無法讀取（{why}）。')
        else:
            schema = answer.get('schema') or {}
            odd = sorted(set(schema.get('tables') or []) - TABLES) + sorted(schema.get('virtual') or [])
            if odd or schema.get('triggers') or schema.get('views'):
                blockers.append('HA 的 Headscale 資料庫含有 Headscale 不會建立的資料表、觸發程序或檢視表'
                                f'{"（" + hacommon.names(odd, 5) + "）" if odd else ""}，無法安全地搬過來。')
            counts = answer.get('counts') or {}
            details.update({k: ha_odoo._int(counts.get(k)) for k in COUNTED})
            values = answer.get('values') or {}
            stored = values.get('headscale.version')
            details['db_version'] = stored if isinstance(stored, str) else None
            if version and hacommon.semver(details['db_version']) != hacommon.semver(version):
                blockers.append(f'HA 的 Headscale 資料庫記錄的版本是 {details["db_version"] or "未知"}，這台是 {version}；'
                                '請先讓兩邊的 Headscale 版本一致後再匯入。')
            known = MIGRATIONS.get(hacommon.semver(version) or '')
            applied = [m for m in values.get('headscale.migrations') or [] if isinstance(m, str)]
            unknown = [m for m in applied if known is not None and m not in known]
            if version and not blocker and known is None:
                blockers.append(f'這台的 Headscale {version} 的升級紀錄清單還沒有建立，無法確認 HA 的資料庫；請先更新這台的 Cockpit。')
            elif unknown:
                blockers.append(f'HA 的 Headscale 資料庫有這台的 Headscale 不認得的升級紀錄（{hacommon.names(unknown, 3)}），無法搬過來。')
            outside = nodes_outside(values.get('headscale.node_ips') or [], config)
            if outside:
                blockers.append(f'HA 的 {len(outside)} 台裝置的 VPN 位址不在這台的 IP 位址範圍內（例如 '
                                f'{hacommon.names(outside, 3)}），Headscale 不會自動重新配置，無法搬過來。')
    if not src.noise:
        blockers.append('HA 備份裡沒有可用的 Headscale 伺服器身分金鑰（noise_private.key）；沒有它，所有裝置都得重新註冊。')
    for key in ('prefixes.v4', 'prefixes.v6'):
        mine, theirs = hacommon.network(ha_config.get(key)), hacommon.network(config.get(key))
        if mine is None or theirs is None:
            blockers.append(f'無法讀取 {"HA" if mine is None else "這台"} Headscale 的 IP 位址範圍設定（{key}）。')
        elif mine != theirs:
            blockers.append(f'IP 位址範圍不同（{key}）：HA 是 {mine}，這台是 {theirs}。請先讓兩邊的設定一致後再匯入。')
    if src.records_bad:
        blockers.append('HA 的 Headscale DNS 額外記錄（dns_records.json）格式不正確，無法搬過來。')
    if src.records_count and records_rel(config) is None:
        warnings.append(f'這台的 Headscale 把 DNS 額外記錄放在資料卷以外，HA 的 {src.records_count} 筆記錄不會搬過來，'
                        '請手動加入。')
    if ha_config.get('policy.path'):
        warnings.append('HA 的 Headscale 使用了 ACL 檔案，它不會搬過來；這台使用自己的存取政策設定。')
    if details['api_keys']:
        warnings.append(f'HA 的 {details["api_keys"]} 把 Headscale API 金鑰不會搬過來，這台的 API 金鑰（Headplane、MCP 管理）保持有效。')
    return blockers, warnings, details


def nodes_outside(rows, config):
    """Addresses of nodes outside this device's prefixes."""
    nets = [hacommon.network(config.get(key)) for key in ('prefixes.v4', 'prefixes.v6')]
    nets = [n for n in nets if n is not None]
    if not nets:
        return []
    import ipaddress
    outside = []
    for row in rows:
        for value in row if isinstance(row, list) else []:
            if not isinstance(value, str) or not value:
                continue
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                outside.append(value[:60])
                continue
            if not any(address.version == n.version and address in n for n in nets):
                outside.append(value[:60])
    return outside


def section(src, details, *, version, ha_config, config):
    return {'headscale_version': VERSIONS.upstream(src.addon.version) if src.addon else '',
            'db_version': details['db_version'] or '', 'users': details['users'], 'nodes': details['nodes'],
            'pre_auth_keys': details['pre_auth_keys'], 'api_keys': details['api_keys'], 'policies': details['policies'],
            'prefixes': {'v4': ha_config.get('prefixes.v4', ''), 'v6': ha_config.get('prefixes.v6', '')},
            'server_url': ha_config.get('server_url', ''), 'target_server_url': config.get('server_url', ''),
            'dns_records': src.records_count, 'target_version': version or ''}


# ====================================================================== the job steps

def _pass(work, staging):
    member = work.addon_member(SLUG)
    report = habackup.Report()
    with work.open(member) as stream:
        src = scan_member(stream, report, staging, checkpoint=work.checkpoint)
    for note in report.warnings():
        work.log(note)
    return src


def _prepare(work, app):
    target = Target(work, app)
    version = hacommon.semver(hacommon.image_labels(work, app, target.image).get('org.opencontainers.image.version'))
    config = live_config(work, app, target)
    data_paths(config)
    return target, version, config


def check(work, app):
    target, version, config = _prepare(work, app)
    staging = work.staging / 'headscale-work'
    staging.mkdir(mode=0o700)
    src = _pass(work, staging)
    work.phase('check')
    answer = None
    if src.db is not None:
        files = {'ha.sqlite': src.db, **({'ha.sqlite-wal': src.wal} if src.wal else {})}
        answer = hasqlite.run(_specs(replace=False), files, staging / 'sqlite', checkpoint=work.checkpoint,
                              what='Headscale 資料庫')['ha.sqlite']
    live = _live_db(work, app, target, staging, config)
    live_answer = hasqlite.run([{'db': 'live.sqlite', 'check': 'integrity', 'counts': ['policies']}], live,
                               staging / 'sqlite-live', checkpoint=work.checkpoint, what='這台 Headscale 資料庫')['live.sqlite']
    addon = work.addon_info(SLUG)
    blockers, warnings, details = analyse(src, answer, addon_version=addon.version, version=version,
                                          ha_config=src.config, config=config)
    policy_blocker = live_policy_blocker(live_answer, config)
    if policy_blocker:
        blockers.append(policy_blocker)
    return {'target_version': version or '', 'blockers': blockers, 'warnings': warnings,
            'headscale': section(src, details, version=version, ha_config=src.config, config=config)}


def live_policy_blocker(answer, config):
    if hasqlite.problem(answer) or 'policies' not in (answer.get('counts') or {}):
        return '無法確認這台 Headscale 的資料庫存取政策，已停止匯入。'
    if config.get('policy.mode', 'file') == 'database' and answer['counts']['policies']:
        return '這台 Headscale 有資料庫存取政策；匯入會以 HA 的政策取代，為避免放寬存取權限已停止。'
    return None


def _live_db(work, app, target, staging, config):
    """The live database (+ WAL) copied out of the live volume's export (read while Headscale runs; the child checks
    its integrity before it uses a row of it)."""
    db_rel, _key_rel = data_paths(config)
    export = hacommon.live_export(work, app, target.data_volume, staging / 'live-data.tar')
    found = {}
    try:
        with ha_odoo._live_tar(export, '這台 Headscale 的資料卷') as tar:
            for member in tar:
                name = ha_odoo._norm(member.name)
                if name in (db_rel, db_rel + '-wal') and member.isfile() and member.size <= MAX_DB:
                    dest = staging / ('live.sqlite' if name == db_rel else 'live.sqlite-wal')
                    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                    with os.fdopen(fd, 'wb') as handle:
                        source = tar.extractfile(member)
                        while True:
                            data = source.read(habackup.CHUNK)
                            if not data:
                                break
                            handle.write(data)
                    found[dest.name] = dest
                tar.members.clear()
    except tarfile.TarError:
        raise BackupError('job-failed', '這台 Headscale 資料卷的匯出內容無法讀取。', app=app.id) from None
    os.unlink(export)
    if 'live.sqlite' not in found:
        raise BackupError('incompatible', '這台的 Headscale 資料卷裡沒有資料庫，無法保留這台的 API 金鑰。', app=app.id)
    return found


def convert(work, app, test_mode, out_dir):
    """Build `out_dir/volumes/<headscale-data>.tar` and `<headplane-data>.tar`."""
    adapter = work.adapter(app)
    tmp = work.temp(app)
    target, version, config = _prepare(work, app)
    ids = adapter.owner_ids()
    staging = work.staging / 'headscale-work'
    staging.mkdir(mode=0o700)
    (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
    src = _pass(work, staging)
    work.phase('convert')
    if src.db is None:
        raise BackupError('incompatible', 'Headscale 不能搬過來：HA 備份裡沒有 Headscale 的資料庫。', app=app.id)
    files = {'ha.sqlite': src.db, **({'ha.sqlite-wal': src.wal} if src.wal else {}),
             **_live_db(work, app, target, staging, config)}
    converted = staging / 'converted'
    converted.mkdir(mode=0o700)
    answers = hasqlite.run(_specs(replace=True), files, staging / 'sqlite', outputs=('ha.sqlite',),
                           out_dir=converted, checkpoint=work.checkpoint, what='Headscale 資料庫')
    live_problem = hasqlite.problem(answers['live.sqlite'])
    if live_problem:
        raise BackupError('job-failed', f'這台 Headscale 資料庫的複本無法讀取（{live_problem}），請稍後再試一次。', app=app.id)
    policy_blocker = live_policy_blocker(answers['live.sqlite'], config)
    if policy_blocker:
        raise BackupError('incompatible', policy_blocker, app=app.id)
    addon = work.addon_info(SLUG)
    blockers, _warnings, details = analyse(src, answers['ha.sqlite'], addon_version=addon.version, version=version,
                                           ha_config=src.config, config=config)
    if blockers:
        raise BackupError('incompatible', f'Headscale 不能搬過來：{blockers[0]}', app=app.id)
    replaced = answers['ha.sqlite'].get('replaced') or {}
    live_keys = (answers['live.sqlite'].get('values') or {}).get('headscale.api_key_prefixes') or []
    if replaced.get('prefixes') != live_keys:
        raise BackupError('job-failed', 'Headscale 的 API 金鑰沒有換成這台的，已停止。', app=app.id)
    db_file = answers[None]['ha.sqlite']
    verify_specs = _specs(replace=False)
    verify_specs += [{'db': 'original.sqlite', 'check': 'integrity', 'counts': sorted(TABLES)},
                     {'db': 'live.sqlite', 'check': 'integrity', 'counts': ['policies'],
                      'queries': ['headscale.api_key_prefixes']}]
    verify_files = {'ha.sqlite': db_file, 'original.sqlite': src.db,
                    **({'original.sqlite-wal': src.wal} if src.wal else {}),
                    **{name: path for name, path in files.items() if name.startswith('live.sqlite')}}
    verified = hasqlite.run(verify_specs, verify_files, staging / 'sqlite-verify',
                            checkpoint=work.checkpoint, what='轉換後 Headscale 資料庫')
    expected_counts = dict(verified['original.sqlite'].get('counts') or {})
    fresh_keys = (verified['live.sqlite'].get('values') or {}).get('headscale.api_key_prefixes')
    expected_counts['api_keys'] = len(live_keys)
    if (any(hasqlite.problem(verified[name]) for name in ('ha.sqlite', 'original.sqlite', 'live.sqlite'))
            or live_policy_blocker(verified['live.sqlite'], config)
            or fresh_keys != live_keys or verified['ha.sqlite'].get('counts') != expected_counts
            or (verified['ha.sqlite'].get('values') or {}).get('headscale.api_key_prefixes') != fresh_keys):
        raise BackupError('job-failed', '轉換後的 Headscale 資料庫驗證失敗，已停止。', app=app.id)
    work.log(f'Headscale：HA 的 {details["api_keys"]} 把 API 金鑰換成這台的 {len(live_keys)} 把')

    root = ha_n8n.volume_root(work, app, target.data_volume)
    uid, gid, _mode = root
    data_path = out_dir / 'volumes' / f'{target.data_volume}.tar'
    out = hacommon.FileTar(data_path, work.guard)
    try:
        hacommon.top_only(out, root)
        db_rel, key_rel = data_paths(config)
        rel = records_rel(config)
        if rel and any(rel == x or x.startswith(rel + '/') or rel.startswith(x + '/')
                       for x in (db_rel, key_rel, db_rel + '-wal', db_rel + '-shm')):
            raise BackupError('incompatible', 'Headscale DNS 記錄與資料庫或身分金鑰路徑衝突。', app=app.id)
        dirs = set()
        for name in (db_rel, key_rel):
            parts = name.split('/')[:-1]
            for i in range(1, len(parts) + 1):
                directory = '/'.join(parts[:i])
                if directory not in dirs:
                    out.add_member(hacommon.info(directory, 'dir', mode=0o755, uid=uid, gid=gid, mtime=time.time()))
                    dirs.add(directory)
        with open(db_file, 'rb') as handle:
            out.add_member(hacommon.info(db_rel, 'file', mode=0o644, uid=uid, gid=gid, mtime=time.time(),
                                         size=os.fstat(handle.fileno()).st_size), handle)
        key = (src.noise + '\n').encode('ascii')
        out.add_member(hacommon.info(key_rel, 'file', mode=0o600, uid=uid, gid=gid, mtime=time.time(),
                                     size=len(key)), _Bytes(key))
        rel = records_rel(config)
        if rel is not None:
            records = src.records if src.records is not None else b'[]'
            out.add_member(hacommon.info(rel, 'file', mode=0o644, uid=uid, gid=gid, mtime=time.time(),
                                         size=len(records)), _Bytes(records))
    finally:
        out.close()
    os.unlink(db_file)
    configtest(work, tmp, target, data_path)
    headplane_path = out_dir / 'volumes' / f'{target.headplane_volume}.tar'
    hacommon.live_export(work, app, target.headplane_volume, headplane_path)
    for path in (data_path, headplane_path):
        ha_odoo.check_volume_tar(path, ids)
    dirs = {} if target.config_dir is None else {
        'dirs': {target.config_dir: live_config_dir(work, app, target, out_dir, ids, config)}}
    return {'volumes': {target.data_volume: data_path, target.headplane_volume: headplane_path}, **dirs,
            'users': details['users'], 'nodes': details['nodes'], 'api_keys_removed': details['api_keys'],
            'api_keys_kept': len(live_keys), 'server_url': config.get('server_url', ''),
            'ha_server_url': src.config.get('server_url', ''), 'dns_records': src.records_count}


def live_config_dir(work, app, target, out_dir, ids, config):
    """This device's configuration folder as it is (nothing of HA's goes into it), packed while Headscale runs and checked
    like every host folder; its config.yaml must still say what the conversion was made with."""
    (out_dir / 'dirs').mkdir(mode=0o700, parents=True, exist_ok=True)
    path = out_dir / 'dirs' / '0.tar'
    with open(path, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        work.runner(app).dir_pack(target.config_dir, stdout=handle, timeout=3600, max_output=work.guard.budget(),
                                  abort=work.abort)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        nested.check_dir(path, ids=ids)
    except BackupError as error:
        raise BackupError('job-failed', f'這台的 Headscale 設定資料夾無法還原（{error.message}）。', app=app.id,
                          reason=(error.details or {}).get('reason')) from None
    text = None
    with ha_odoo._live_tar(path, '這台的 Headscale 設定資料夾') as tar:
        for member in tar:
            if ha_odoo._norm(member.name) == 'config.yaml' and member.isfile() and member.size <= MAX_SMALL:
                text = tar.extractfile(member).read().decode('utf-8', 'replace')
            tar.members.clear()
    if text is None or hacommon.scalars(text) != config:
        raise BackupError('job-failed', '這台 Headscale 的設定檔在轉換期間改變了，已停止；請再試一次。', app=app.id)
    return path


class _Bytes:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def read(self, n=-1):
        end = len(self.data) if n is None or n < 0 else self.pos + n
        chunk = self.data[self.pos:end]
        self.pos += len(chunk)
        return chunk


def configtest(work, tmp, target, data_path):
    """`headscale configtest` of the live image on a throwaway copy of the converted volume (network none, the live
    configuration read-only): the database opens, its version path, migrations and schema are what this release
    accepts."""
    tmp.volume('hs-check')

    def produce(out):
        with open(data_path, 'rb') as handle:
            while True:
                data = handle.read(habackup.CHUNK)
                if not data:
                    break
                out.write(data)

    tmp.volume_import('hs-check', produce)
    try:
        tmp.run('hs-configtest', target.image, ['configtest'], volumes=[(tmp.name('hs-check'), DATA_TARGET, None),
                                                                       target.config_mount],
                read_only_root=True, timeout=300, max_output=1024 * 1024)
    except BackupError as error:
        if error.code != 'job-failed':
            raise
        raise BackupError('job-failed', '這台的 Headscale 無法開啟轉換後的資料庫（headscale configtest 沒有通過），已停止；'
                                        '這台沒有任何變更。') from None
    tmp.remove_volume('hs-check')
    work.log('這台的 Headscale 已確認可以開啟轉換後的資料庫（configtest）')


# ====================================================================== texts

def import_texts(data):
    notes = ['Headscale 的使用者、裝置、預先授權金鑰與 DNS 額外記錄會換成 HA 的，HA 的伺服器身分金鑰（noise）也一起搬過來；'
             '這台的伺服器網址、IP 位址範圍與 API 金鑰保持不變；資料庫存取政策會換成 HA 的政策。']
    if data.get('api_keys_removed'):
        notes.append(f'HA 的 {data["api_keys_removed"]} 把 Headscale API 金鑰不會搬過來，這台的 {data.get("api_keys_kept", 0)} 把'
                     '（Headplane、MCP 管理）保持有效。')
    url = data.get('server_url') or '這台的 Headscale 網址'
    old = data.get('ha_server_url')
    reminders = [f'請把每一台裝置的登入伺服器改成 {url}（例如 tailscale up --login-server={url}）'
                 + (f'，不再使用 HA 的 {old}' if old else '') + '。',
                 '請把 HA 的 Headscale 附加元件永久停用（關掉開機自動啟動）：兩台伺服器使用同一個身分金鑰卻有不同的資料，會讓裝置連線錯亂。']
    return notes, reminders
