"""Home Assistant import, Omnigent part: the WOOWTECH add-on `woow-omnigent` -> this device's app `omnigent` (CONTRACT
section 9 "Home Assistant import"; facts phase3/facts/omnigent.md). Owner: E2.

The add-on keeps an embedded PostgreSQL 16 cluster (`data/postgres`, initdb --locale=C, database `omnigent`) and the
server's artifact store with the session-cookie key of its accounts (`data/omnigent-home/.omnigent/artifacts/`: the
add-on's ARTIFACT_DIR is never read by omnigent 0.21.0; `omnigent server` keeps `<HOME>/.omnigent/artifacts`, HOME
being /data/omnigent-home -- cli.py `_default_artifact_location`, host/local_server.py `_local_data_dir`). The target
is the Podman package in cold mode: volumes `omnigent-postgres-data` (a whole PostgreSQL 16 cluster whose bootstrap
superuser is the app role), `omnigent-server-data` (/data: artifacts and the admin's runtime setting files) and
`omnigent-pi-data` (the runner's own pi state).

Versions: the add-on version maps to an Omnigent version (VERSIONS) that must equal the live server's `/v1/info`
`server_version`, and HA's `alembic_version` must equal the live database's; HA's PostgreSQL major must not be newer.

check: HA's cluster is streamed into a throwaway volume (its configuration and recovery files replaced or dropped,
ha_odoo.PgSink) and opened by a throwaway PostgreSQL 16 of the live image exactly as hardened as Odoo's
(ha_odoo.start_ha_cluster: socket only, network none, read-only root, noexec data volume, every library/command
setting overridden); the database must hold only Omnigent's own tables, no function, trigger, view, rule, policy,
other schema or object only a superuser can create, extensions within plpgsql and pg_trgm, UTF8; every agent bundle and
file blob the database names must be in the backup's artifact store, whose `accounts-cookie-secret` must be there.

convert: `pg_dump -Fc omnigent`; a NEW cluster from the live image, environment and secret mount (its superuser is the
live app role with the live password); pg_trgm created first; the dump's list must hold only the kinds of objects
Omnigent creates (TOC_ALLOWED) and is restored by a separate role without any privilege
(`pg_restore --no-owner --no-acl --exit-on-error --single-transaction`, then REASSIGN OWNED to the app role and the
role dropped). This does not prevent stored expressions from running with superuser rights; conversion is disabled (B1-01). This device's own admin and runner accounts
(the Quadlet's OMNIGENT_ACCOUNTS_INIT_ADMIN_USERNAME / OMNIGENT_RUNNER_USERNAME) are read from the live database as
the app owner and added back unless HA has a user of the same name (HA's wins, with a warning): without them the
runner could not log in while every health check stays green. Test mode pauses every active scheduled task. Counts
and alembic are verified, the cluster is stopped cleanly (`pg_controldata` "shut down") and exported.
`omnigent-server-data` is the live export without `artifacts/**` plus HA's artifacts (owner of the live artifacts
folder, dirs 0755, files 0644, the cookie key 0600; `.cache/` never moves); `omnigent-pi-data` is the live export as
it is (the runner's identity, logins and pairings never move). HA's runtime setting files in /data (sharing, admins,
allowed domains, config.yaml) are settings: this device keeps its own and the check lists HA's.
"""
import json
import os
import re
import time
import urllib.parse

from . import habackup, hacommon, ha_odoo, tempctr
from .errors import BackupError

SLUG = 'woow-omnigent'
APP_ID = 'omnigent'
PG_PREFIX = 'data/postgres'
ARTIFACTS = 'data/omnigent-home/.omnigent/artifacts'
ADDON_ARTIFACT_DIR = 'data/artifacts'  # the add-on's ARTIFACT_DIR: expected empty (never read by omnigent 0.21.0)
COOKIE = 'accounts-cookie-secret'
OVERRIDES = ('sharing_mode', 'public_sharing', 'public_sharing_max_level', 'default_public_sessions', 'admins',
             'allowed_domains', 'config.yaml')
DATABASE = 'omnigent'
RESTORE_ROLE = 'woowbk_restore'
# Add-on version -> Omnigent version (Woow_ha_omnigent_addon CHANGELOG.md; Dockerfile OMNIGENT_VERSION).
VERSIONS = hacommon.VersionTable('Omnigent', {**{f'0.1.{n}': '0.12.0' for n in range(0, 19)}, '0.1.19': '0.20.0',
                                              '0.1.20': '0.21.0', '0.1.21': '0.21.0', '0.1.22': '0.21.0',
                                              '0.1.23': '0.21.0'})
TABLES = ('agents', 'files', 'users', 'preferences', 'account_tokens', 'connections', 'device_grants',
          'session_permissions', 'omnigent_conversation_metadata', 'projects', 'conversations', 'conversation_items',
          'conversation_labels', 'comments', 'policies', 'hosts', 'user_daily_cost', 'scheduled_tasks',
          'scheduled_task_runs')
KNOWN_TABLES = frozenset(TABLES) | {'alembic_version'}
EXTENSIONS_OK = ('plpgsql', 'pg_trgm')
# pg_restore list entry kinds Omnigent's schema consists of (anything else is refused before the restore).
TOC_ALLOWED = frozenset({'TABLE', 'TABLE DATA', 'INDEX', 'CONSTRAINT', 'FK CONSTRAINT', 'CHECK CONSTRAINT', 'SEQUENCE',
                         'SEQUENCE SET', 'SEQUENCE OWNED BY', 'DEFAULT', 'COMMENT', 'TYPE', 'DOMAIN', 'EXTENSION',
                         'SCHEMA', 'ACL'})
TOC_KINDS = sorted(TOC_ALLOWED | set(ha_odoo.SUPERUSER_KINDS) | {
    'FUNCTION', 'PROCEDURE', 'AGGREGATE', 'TRIGGER', 'VIEW', 'MATERIALIZED VIEW', 'MATERIALIZED VIEW DATA', 'RULE',
    'POLICY', 'ROW SECURITY', 'OPERATOR', 'CONVERSION', 'COLLATION', 'DEFAULT ACL', 'LARGE OBJECT', 'BLOB', 'BLOBS',
    'BLOB METADATA', 'STATISTICS', 'STATISTICS DATA', 'TEXT SEARCH CONFIGURATION', 'TEXT SEARCH DICTIONARY',
    'PUBLICATION TABLE', 'PUBLICATION TABLES IN SCHEMA', 'SUBSCRIPTION TABLE', 'SECURITY LABEL', 'SHELL TYPE',
    'INDEX ATTACH', 'TABLE ATTACH', 'DATABASE', 'DATABASE PROPERTIES', 'ENCODING', 'STDSTRINGS', 'SEARCHPATH',
    'FOREIGN SERVER'}, key=len, reverse=True)
USER_RE = re.compile(r'[a-z0-9][a-z0-9_.@+-]{0,127}\Z')
KEY_RE = re.compile(r'[A-Za-z0-9_.-]{1,128}(?:/[A-Za-z0-9_.-]{1,128}){0,3}\Z')
ALEMBIC_RE = re.compile(r'[0-9a-z_]{1,64}\Z')
SERVER_VERSION_RE = re.compile(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\Z')
MAX_KEYS = 1_000_000
DUMP_TIMEOUT = ha_odoo.DUMP_TIMEOUT

# Fail closed until HA data is loaded into a trusted live-derived schema (B1-01).
SECURITY_BLOCKER = 'Omnigent HA 匯入暫時停用：資料庫結構的安全驗證尚未完成。'


# ====================================================================== the add-on member

class Source:
    """What one pass over the add-on's inner tar learned."""

    def __init__(self):
        self.addon = None
        self.pg_version = None
        self.pg_files = self.pg_bytes = 0
        self.keys = set()           # artifact keys (paths relative to the artifact store)
        self.artifact_files = 0
        self.artifact_bytes = 0
        self.cookie = False
        self.addon_artifacts = 0    # files in the add-on's own ARTIFACT_DIR (expected none)
        self.overrides = []         # HA's runtime setting files in /data (not imported)
        self.problems = []


def scan_member(stream, report, *, pg=None, artifacts=None, checkpoint=None):
    """One strict pass: `data/postgres/**` into `pg` (a PgSink), the artifact store into `artifacts` (a TreeTar,
    names `artifacts/...`, owner and modes fixed later); HA's runtime setting files are only named. Returns a
    Source."""
    select = habackup.Select(include=(PG_PREFIX, ARTIFACTS, ADDON_ARTIFACT_DIR) + tuple(f'data/{n}' for n in OVERRIDES),
                             exclude=(f'{ARTIFACTS}/.cache',), symlinks=(), hardlinks=True)
    src = Source()
    count = 0
    for entry in habackup.iter_entries(stream, select, report, checkpoint=checkpoint):
        count += 1
        if checkpoint is not None and count % 256 == 0:
            checkpoint()
        name = entry.name
        if ha_odoo._under(name, PG_PREFIX):
            if entry.kind == 'hardlink':
                raise BackupError('incompatible', 'HA 的 Omnigent 資料庫檔案含有硬連結，無法安全地搬過來。', member=name[:200])
            rel = name[len(PG_PREFIX) + 1:] if name != PG_PREFIX else '.'
            data = None
            if entry.kind == 'file':
                src.pg_files += 1
                src.pg_bytes += entry.size
                if rel == 'PG_VERSION':
                    data = entry.read_all(ha_odoo.MAX_SMALL_FILE)
                    src.pg_version = data.decode('ascii', 'replace').strip()[:16]
            if pg is not None:
                pg.add(rel, entry, data)
            continue
        if ha_odoo._under(name, ARTIFACTS):
            rel = name[len(ARTIFACTS) + 1:] if name != ARTIFACTS else ''
            target = 'artifacts' + (f'/{rel}' if rel else '')
            if entry.kind == 'dir':
                if artifacts is not None:
                    artifacts.dir(target, 0o755, entry.mtime)
            elif entry.kind == 'file':
                src.artifact_files += 1
                src.artifact_bytes += entry.size
                if len(src.keys) < MAX_KEYS:
                    src.keys.add(rel)
                if rel == COOKIE:
                    src.cookie = 0 < entry.size <= 4096
                if artifacts is not None:
                    artifacts.file(target, entry, 0o600 if rel == COOKIE else 0o644)
            elif entry.kind == 'hardlink':
                if not ha_odoo._under(entry.linkname, ARTIFACTS) or entry.linkname == ARTIFACTS:
                    raise BackupError('incompatible', 'HA 的 Omnigent 檔案區有指向其他資料的硬連結，無法安全地搬過來。',
                                      member=name[:200])
                linked = entry.linkname[len(ARTIFACTS) + 1:]
                if len(src.keys) < MAX_KEYS:
                    src.keys.add(rel)
                if artifacts is not None:
                    artifacts.hardlink(target, f'artifacts/{linked}', entry.mtime)
            continue
        if ha_odoo._under(name, ADDON_ARTIFACT_DIR):
            if entry.kind == 'file':
                src.addon_artifacts += 1
            continue
        if entry.kind == 'file' and name.startswith('data/') and name[5:] in OVERRIDES:
            src.overrides.append(name[5:])
    tablespaces = [s for s in report.skipped_symlink_samples if ha_odoo._under(s, PG_PREFIX)]
    if tablespaces:
        raise BackupError('incompatible', 'HA 的 Omnigent 資料庫使用了另外的表空間（tablespace）或符號連結，目前無法搬過來。',
                          member=tablespaces[0])
    src.addon = report.addon
    return src


# ====================================================================== the live target

class Target:
    """The omnigent app's catalog items the import fills, resolved against the live Quadlet files."""

    def __init__(self, work, app):
        quadlets = work.quadlets(app)
        home = work.runner(app).home
        declared = [v['name'] for v in app.volumes]
        db_file = next((f for f in sorted(quadlets) if f.endswith('.container') and ha_odoo._is_db(quadlets[f])), None)
        server_file, server_volume = hacommon.mounted(quadlets, home, '/data')
        runner_file, pi_volume = hacommon.mounted(quadlets, home, '/data/pi-agent')
        problems = []
        if app.postgres or app.data_dirs:
            problems.append('應用設定含有資料庫匯出項目或主機資料夾（不是冷備份的 Omnigent）')
        if db_file is None or server_file is None or runner_file is None:
            problems.append('找不到 PostgreSQL、伺服器或 runner 的 Quadlet 檔')
        if problems:
            raise BackupError('incompatible', f'這台的 Omnigent 應用設定不是 HA 匯入支援的樣子：{"；".join(problems)}。',
                              app=app.id)
        text = quadlets[db_file]
        self.db_image = tempctr_image(text, app)
        self.db_env = hacommon.environment(quadlets, db_file, ha_odoo.DB_ENV_KEYS)
        self.db_secrets = tempctr.quadlet_secrets(text)
        self.db_container = ha_odoo.quadlet_container_name(quadlets, db_file)
        mounts = ha_odoo.quadlet_mounts(quadlets, db_file, home)
        self.db_volume, self.db_target = (mounts[0][0], mounts[0][1]) if mounts else (None, None)
        self.db_user = self.db_env.get('POSTGRES_USER', 'postgres')
        self.database = self.db_env.get('POSTGRES_DB', self.db_user)
        self.pgdata = self.db_env.get('PGDATA') or self.db_target
        self.server_volume, self.pi_volume = server_volume, pi_volume
        server_env = hacommon.environment(quadlets, server_file, {'OMNIGENT_ACCOUNTS_INIT_ADMIN_USERNAME'})
        runner_env = hacommon.environment(quadlets, runner_file, {'OMNIGENT_RUNNER_USERNAME'})
        users = [server_env.get('OMNIGENT_ACCOUNTS_INIT_ADMIN_USERNAME') or 'admin',
                 runner_env.get('OMNIGENT_RUNNER_USERNAME') or 'operator']
        self.own_users = [u.lower() for u in dict.fromkeys(users) if USER_RE.fullmatch(u.lower())]
        if (sorted(declared) != sorted({self.db_volume, server_volume, pi_volume} - {None}) or len(declared) != 3
                or self.database != DATABASE or not self.pgdata or not tempctr.TARGET_RE.fullmatch(self.pgdata)
                or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', self.db_user)):
            raise BackupError('incompatible', '這台的 Omnigent 資料卷、資料庫設定和 Quadlet 檔不一致，無法匯入。', app=app.id)
        self.info_url = info_url(app)


def tempctr_image(text, app):
    image = tempctr.quadlet_image(text)
    if not image:
        raise BackupError('incompatible', '這台 Omnigent 的 Quadlet 設定缺少映像。', app=app.id)
    return image


def info_url(app):
    """`http://127.0.0.1:<port>/v1/info` from the catalog's health URL of the server."""
    for item in app.health:
        parts = urllib.parse.urlsplit(item.get('url') or '')
        if parts.scheme == 'http' and parts.hostname in ('127.0.0.1', 'localhost'):
            return f'http://{parts.hostname}:{parts.port or 80}/v1/info'
    return None


def target_version(work, app, url):
    """The live server's version (`GET /v1/info` -> server_version; unauthenticated, loopback only)."""
    from .adapters.quadlet_postgres import loopback_get
    if url is None:
        return None
    try:
        status, body = loopback_get(url, 15)
    except (OSError, ValueError):
        return None
    if status != 200:
        return None
    doc = hacommon.strict_json(body, 1024 * 1024)
    version = doc.get('server_version') if isinstance(doc, dict) else None
    return version if isinstance(version, str) and SERVER_VERSION_RE.fullmatch(version) else None


def live_alembic(work, app, target):
    value = hacommon.live_json(work, app, target.db_container, target.db_user, target.database,
                               "SELECT coalesce(json_agg(version_num), '[]'::json) FROM alembic_version")
    return value if isinstance(value, list) and all(isinstance(v, str) for v in value) else None


LIVE_USERS_SQL = "SELECT coalesce(json_agg(u ORDER BY u.id), '[]'::json) FROM users u WHERE u.id IN ({names})"


def live_users(work, app, target):
    """This device's own admin and runner rows (argon2id hashes masked in every log line from now on)."""
    from . import jobs
    if not target.own_users:
        return []
    sql = LIVE_USERS_SQL.format(names=', '.join(ha_odoo.sql_literal(u) for u in target.own_users))
    rows = hacommon.live_json(work, app, target.db_container, target.db_user, target.database, sql)
    if not isinstance(rows, list):
        raise BackupError('job-failed', '無法讀取這台 Omnigent 的帳號。', app=app.id)
    kept = []
    for row in rows[:10]:
        if not isinstance(row, dict) or row.get('id') not in target.own_users:
            continue
        secret = row.get('password_hash')
        if isinstance(secret, str) and secret:
            jobs.mask_secret(secret)
        kept.append(row)
    return kept


# ====================================================================== HA's database

OBJECTS_SQL = """SELECT json_build_object(
 'tables', (SELECT coalesce(json_agg(c.relname ORDER BY c.relname), '[]'::json) FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r', 'p', 'f') AND n.nspname = 'public'),
 'schemas', (SELECT coalesce(json_agg(nspname ORDER BY nspname), '[]'::json) FROM pg_namespace
             WHERE nspname NOT IN ('public', 'information_schema') AND nspname NOT LIKE 'pg\\_%'),
 'functions', (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
               WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND NOT EXISTS (SELECT 1 FROM pg_depend d
               WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')),
 'triggers', (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal),
 'views', (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE c.relkind IN ('v', 'm') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
           AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid
           AND d.deptype = 'e')),
 'rules', (SELECT count(*) FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class JOIN pg_namespace n
           ON n.oid = c.relnamespace WHERE r.rulename <> '_RETURN' AND n.nspname NOT IN ('pg_catalog',
           'information_schema')),
 'policies', (SELECT count(*) FROM pg_policy),
 'extensions', (SELECT coalesce(json_agg(extname ORDER BY extname), '[]'::json) FROM pg_extension),
 'encoding', pg_encoding_to_char((SELECT encoding FROM pg_database WHERE datname = current_database())),
 'collate', (SELECT datcollate FROM pg_database WHERE datname = current_database()))"""
HAS_ALEMBIC_SQL = "SELECT to_json(to_regclass('public.alembic_version') IS NOT NULL)"
ALEMBIC_SQL = "SELECT coalesce(json_agg(version_num), '[]'::json) FROM alembic_version"
DETAIL_SQL = """SELECT json_build_object(
 'users', (SELECT count(*) FROM users WHERE deleted_at IS NULL AND id NOT IN ('local', '__public__')),
 'admins', (SELECT count(*) FROM users WHERE deleted_at IS NULL AND is_admin AND id NOT IN ('local', '__public__')),
 'user_ids', (SELECT coalesce(json_agg(id ORDER BY id), '[]'::json) FROM users),
 'conversations', (SELECT count(*) FROM conversations),
 'scheduled_tasks', (SELECT count(*) FROM scheduled_tasks WHERE state IN (1, 2)),
 'scheduled_tasks_active', (SELECT count(*) FROM scheduled_tasks WHERE state = 1),
 'hosts', (SELECT count(*) FROM hosts),
 'agents', (SELECT count(*) FROM agents),
 'files', (SELECT count(*) FROM files),
 'public_sessions', (SELECT count(DISTINCT conversation_id) FROM session_permissions WHERE user_id = '__public__'),
 'connections_with_secrets', (SELECT count(*) FROM connections WHERE coalesce(secret_enc, '') <> ''))"""
KEYS_SQL = """SELECT json_build_object(
 'bundles', (SELECT coalesce(json_agg(DISTINCT bundle_location), '[]'::json) FROM agents
             WHERE coalesce(bundle_location, '') <> ''),
 'blobs', (SELECT coalesce(json_agg(DISTINCT encode(coalesce(blob_key, id), 'hex')), '[]'::json) FROM files))"""


def _count_sql(tables):
    parts = ', '.join(f"'{t}', (SELECT count(*) FROM {ha_odoo.pg_ident(t)})" for t in tables)
    return f'SELECT json_build_object({parts})'


def table_counts(cluster, tables, database=DATABASE):
    found = {}
    tables = [t for t in tables if t in KNOWN_TABLES]
    for start in range(0, len(tables), 40):  # 2 arguments each, PostgreSQL allows 100 (review C-11)
        doc = cluster.query_json(_count_sql(tables[start:start + 40]), database)
        if isinstance(doc, dict):
            found.update({k: ha_odoo._int(v) for k, v in doc.items() if k in KNOWN_TABLES})
    return found


def analyse(cluster):
    """What HA's database holds (from the hardened throwaway cluster)."""
    databases = {db['name']: db for db in ha_odoo.ha_databases(cluster)}
    if DATABASE not in databases:
        raise BackupError('incompatible', 'HA 的 Omnigent 沒有 omnigent 資料庫。')
    objects = cluster.query_json(OBJECTS_SQL, DATABASE)
    if not isinstance(objects, dict):
        raise BackupError('job-failed', '無法讀取 HA 的 Omnigent 資料庫。')
    tables = [t for t in objects.get('tables') or [] if isinstance(t, str)]
    alembic = cluster.query_json(ALEMBIC_SQL, DATABASE) if cluster.query_json(HAS_ALEMBIC_SQL, DATABASE) is True else []
    detail = cluster.query_json(DETAIL_SQL, DATABASE) if set(TABLES) <= set(tables) else None
    keys = cluster.query_json(KEYS_SQL, DATABASE) if {'agents', 'files'} <= set(tables) else None
    superuser = cluster.query_json(ha_odoo.SUPERUSER_SQL, DATABASE)
    return {'objects': objects, 'tables': tables, 'alembic': [a for a in alembic or [] if isinstance(a, str)][:5],
            'detail': detail if isinstance(detail, dict) else {}, 'keys': keys if isinstance(keys, dict) else {},
            'superuser': [str(k)[:40] for k in superuser[:20]] if isinstance(superuser, list) else [],
            'counts': table_counts(cluster, tables)}


def verdict(src, found, *, live_alembic_value, ha_major, target_major):
    """(blockers, warnings) of HA's Omnigent against this device."""
    blockers, warnings = [], []
    objects = found['objects']
    unknown = sorted(set(found['tables']) - KNOWN_TABLES)
    missing = sorted(set(TABLES) - set(found['tables']))
    if unknown:
        blockers.append(f'HA 的 Omnigent 資料庫有 Omnigent 不會建立的資料表（{hacommon.names(unknown)}），無法安全地搬過來。')
    if missing:
        blockers.append(f'HA 的 Omnigent 資料庫缺少資料表（{hacommon.names(missing)}），版本或資料可能不完整。')
    odd = [label for key, label in (('functions', '函式'), ('triggers', '觸發程序'), ('views', '檢視表'), ('rules', '規則'),
                                    ('policies', '資料列政策')) if ha_odoo._int(objects.get(key))]
    if objects.get('schemas'):
        odd.append(f'其他結構描述（{hacommon.names([str(s) for s in objects["schemas"]], 5)}）')
    if odd:
        blockers.append(f'HA 的 Omnigent 資料庫含有 Omnigent 不會建立的物件（{"、".join(odd)}），無法安全地搬過來。')
    if found['superuser']:
        blockers.append(f'HA 的 Omnigent 資料庫含有只有資料庫超級使用者才能建立的物件（{hacommon.names(found["superuser"])}），'
                        '無法安全地搬過來。')
    extensions = [str(e) for e in objects.get('extensions') or []]
    if any(e not in EXTENSIONS_OK for e in extensions):
        odd_extensions = [e for e in extensions if e not in EXTENSIONS_OK]
        blockers.append(f'HA 的 Omnigent 資料庫使用了這台不支援的擴充功能：{hacommon.names(odd_extensions)}。')
    if objects.get('encoding') != 'UTF8':
        blockers.append('HA 的 Omnigent 資料庫不是 UTF8 編碼。')
    if ha_major is None or target_major is None or ha_major > target_major:
        blockers.append(f'HA 的 PostgreSQL 是 {ha_major or "未知"} 版，這台是 {target_major or "未知"} 版；只能從相同或較舊的版本搬過來。')
    ha_alembic = found['alembic']
    if not ha_alembic or live_alembic_value is None or sorted(ha_alembic) != sorted(live_alembic_value):
        blockers.append(f'資料庫結構版本不同：HA 是 {"、".join(ha_alembic) or "未知"}，這台是 '
                        f'{"、".join(live_alembic_value or []) or "未知"}。請先讓兩邊的 Omnigent 版本一致後再匯入。')
    if not src.cookie:
        blockers.append('HA 備份裡找不到 Omnigent 的登入金鑰（accounts-cookie-secret），它應在 /data/omnigent-home/.omnigent/'
                        'artifacts；可能用了其他資料位置（OMNIGENT_DATA_DIR），無法完整搬過來。')
    keys = found['keys']
    wanted = [k for k in (keys.get('bundles') or []) + (keys.get('blobs') or []) if isinstance(k, str)]
    bad = [k for k in wanted if not key_ok(k)]
    lost = [k for k in wanted if key_ok(k) and k not in src.keys]
    if bad:
        blockers.append(f'HA 的 Omnigent 資料庫有格式不明的檔案位置（{hacommon.names(bad, 3)}），無法安全地搬過來。')
    if lost:
        blockers.append(f'HA 的 Omnigent 有 {len(lost)} 個代理程式包或檔案不在備份的檔案區裡（例如 {hacommon.names(lost, 3)}）；'
                        '可能用了其他資料位置，無法完整搬過來。')
    if src.addon_artifacts:
        warnings.append(f'HA 的 /data/artifacts 有 {src.addon_artifacts} 個檔案，Omnigent 不會使用它們，不會搬過來。')
    detail = found['detail']
    if ha_odoo._int(detail.get('connections_with_secrets')):
        warnings.append(f'HA 的 Omnigent 有 {detail["connections_with_secrets"]} 個加密保存的外部連線憑證，這台沒有相同的'
                        '加密設定，搬過來後需要重新連線。')
    if src.overrides:
        warnings.append(f'HA 的 Omnigent 執行期設定檔（{hacommon.names(src.overrides)}）不會搬過來，這台維持自己的分享與管理者設定。')
    if ha_odoo._int(detail.get('scheduled_tasks_active')):
        warnings.append(f'HA 的 Omnigent 有 {detail["scheduled_tasks_active"]} 個啟用中的排程，搬過來後會在這台執行'
                        '（測試匯入會先全部暫停）。')
    if ha_odoo._int(detail.get('public_sessions')):
        warnings.append(f'HA 的 Omnigent 有 {detail["public_sessions"]} 個公開分享的工作階段，搬過來後仍然公開。')
    return blockers, warnings


def key_ok(key):
    """An artifact key as Omnigent writes them (`<agent id>/<sha256>`, a blob's hex id): plain names, no `.`/`..`."""
    return bool(KEY_RE.fullmatch(key)) and not any(part in ('.', '..') for part in key.split('/'))


def account_conflicts(found, target):
    """This device's own accounts that HA also has (HA's wins)."""
    ids = {str(u) for u in found['detail'].get('user_ids') or [] if isinstance(u, str)}
    return [user for user in target.own_users if user in ids]


def section(src, found, *, version, conflicts):
    detail = found['detail']
    return {'omnigent_version': version or '', 'alembic': '、'.join(found['alembic']),
            'users': ha_odoo._int(detail.get('users')), 'admins': ha_odoo._int(detail.get('admins')),
            'conversations': ha_odoo._int(detail.get('conversations')),
            'scheduled_tasks': ha_odoo._int(detail.get('scheduled_tasks')),
            'scheduled_tasks_active': ha_odoo._int(detail.get('scheduled_tasks_active')),
            'hosts': ha_odoo._int(detail.get('hosts')), 'agents': ha_odoo._int(detail.get('agents')),
            'files': ha_odoo._int(detail.get('files')), 'public_sessions': ha_odoo._int(detail.get('public_sessions')),
            'artifact_files': src.artifact_files, 'artifact_bytes': src.artifact_bytes,
            'override_files': list(src.overrides), 'account_conflicts': list(conflicts)}


# ====================================================================== the job steps

def member_pass(work, app, tmp, pg_ids, *, artifacts=None):
    member = work.addon_member(SLUG)
    report = habackup.Report()
    holder = {}

    def produce(out):
        sink = ha_odoo.PgSink(out, *pg_ids, guard=work.guard)
        with work.open(member) as stream:
            holder['src'] = scan_member(stream, report, pg=sink, artifacts=artifacts, checkpoint=work.checkpoint)
        sink.close()

    tmp.volume('hapg')
    tmp.volume_import('hapg', produce)
    for note in report.warnings():
        work.log(note)
    src = holder['src']
    work.log(f'HA 的 Omnigent：PostgreSQL {src.pg_version or "?"}，{src.pg_files} 個資料庫檔案，'
             f'{src.artifact_files} 個檔案區檔案')
    return src


def _ha_major(src):
    try:
        return int((src.pg_version or '').split('.')[0])
    except ValueError:
        return None


def _prepare(work, app):
    """(Target, live server version, live alembic, add-on, version blocker or None)."""
    target = Target(work, app)
    addon = work.addon_info(SLUG)
    version = target_version(work, app, target.info_url)
    blocker = VERSIONS.blocker(addon.version if addon else '', version)
    return target, version, live_alembic(work, app, target), addon, blocker


def check(work, app):
    tmp = work.temp(app)
    target, version, alembic, _addon, blocker = _prepare(work, app)
    pg_ids = tmp.user_ids('ids-pg', target.db_image, 'postgres')
    src = member_pass(work, app, tmp, pg_ids)
    work.phase('check')
    cluster = ha_odoo.start_ha_cluster(work, tmp, target.db_image)
    found = analyse(cluster)
    tmp.remove('hapg')
    tmp.remove_volume('hapg')
    blockers, warnings = verdict(src, found, live_alembic_value=alembic, ha_major=_ha_major(src),
                                 target_major=ha_odoo.target_pg_major(work, app, target.db_image))
    if blocker:
        blockers.insert(0, blocker)
    blockers.insert(0, SECURITY_BLOCKER)
    conflicts = account_conflicts(found, target)
    if conflicts:
        warnings.append(f'HA 也有和這台相同名稱的帳號（{hacommon.names(conflicts)}），匯入後以 HA 的帳號為準，這台的'
                        '管理者或 runner 密碼對它不再適用。')
    return {'target_version': version or '', 'blockers': blockers, 'warnings': warnings,
            'omnigent': section(src, found, version=VERSIONS.upstream(work.addon_info(SLUG).version),
                                conflicts=conflicts)}


def toc_kinds(text):
    """The entry kinds of a `pg_restore -l` list (the longest known kind that starts the entry; else UNKNOWN)."""
    found = []
    for line in text.splitlines():
        match = re.match(r'\s*\d+;\s+\d+\s+\d+\s+(.*)\Z', line)
        if not match:
            continue
        rest = match.group(1)
        kind = next((k for k in TOC_KINDS if rest == k or rest.startswith(k + ' ')), None)
        kind = kind or 'UNKNOWN ' + rest.split(' ', 1)[0][:30]
        if kind not in found:
            found.append(kind)
    return found


def restore_dump(work, tmp, dump, superuser, role='omni-db'):
    """Restore HA's dump into the new cluster's database AS A ROLE WITHOUT ANY PRIVILEGE (RESTORE_ROLE), then hand
    every object to the app role and drop the restore role; refused before anything when the list holds a kind of
    object Omnigent never creates."""
    cluster = ha_odoo.Cluster(tmp, role, superuser=superuser, log=work.log)
    with open(dump, 'rb') as handle:
        toc = tmp.exec(role, ['pg_restore', '-l'], user='postgres', input=handle, timeout=DUMP_TIMEOUT,
                       max_output=ha_odoo.TOC_OUTPUT).stdout or b''
    text = toc.decode('utf-8', 'surrogateescape')
    odd = [kind for kind in toc_kinds(text) if kind not in TOC_ALLOWED]
    if odd:
        raise BackupError('incompatible', f'HA 的 Omnigent 資料庫含有 Omnigent 不會建立的物件（{hacommon.names(odd)}），'
                                          '無法安全地搬過來。')
    cluster.write_file('/tmp/woowbk-omnigent.toc', ha_odoo.filter_toc(text).encode('utf-8', 'surrogateescape'))
    cluster.script(f'CREATE ROLE {RESTORE_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n'
                   f'GRANT CREATE, USAGE ON SCHEMA public TO {RESTORE_ROLE};\n', DATABASE)
    work.log('把 HA 的 Omnigent 資料庫還原到新的叢集（以沒有任何權限的暫用角色還原）')
    with open(dump, 'rb') as handle:
        try:
            tmp.exec(role, ['pg_restore', '-U', RESTORE_ROLE, '--no-owner', '--no-acl', '--exit-on-error',
                            '--single-transaction', '-L', '/tmp/woowbk-omnigent.toc', '-d', DATABASE],
                     user='postgres', input=handle, timeout=DUMP_TIMEOUT, max_output=1024 * 1024)
        except BackupError as error:
            if error.code != 'job-failed':
                raise
            raise BackupError('job-failed', '無法把 HA 的 Omnigent 資料庫還原到新的叢集（可能含有這台不支援的內容）。') from None
    cluster.script(f'REASSIGN OWNED BY {RESTORE_ROLE} TO {ha_odoo.pg_ident(superuser)};\n'
                   f'DROP OWNED BY {RESTORE_ROLE};\nDROP ROLE {RESTORE_ROLE};\n', DATABASE)
    tmp.exec(role, ['rm', '-f', '/tmp/woowbk-omnigent.toc'], user='postgres', timeout=120)
    return cluster


def carry_accounts(work, cluster, rows):
    """Add this device's own accounts back (HA's same-named users win): the rows travel in a file inside the
    throwaway container (never in a statement, an argv or a log); returns the names added."""
    if not rows:
        return []
    names = [row['id'] for row in rows]
    present = cluster.query_json('SELECT coalesce(json_agg(id), \'[]\'::json) FROM users WHERE id IN ('
                                 + ', '.join(ha_odoo.sql_literal(n) for n in names) + ')', DATABASE)
    present = {p for p in present if isinstance(p, str)} if isinstance(present, list) else set()
    carried = [row for row in rows if row['id'] not in present]
    if not carried:
        return []
    cluster.write_file('/tmp/woowbk-omnigent-users.json', json.dumps(carried).encode('utf-8'))
    cluster.script("INSERT INTO users SELECT * FROM json_populate_recordset(NULL::users, "
                   "pg_read_file('/tmp/woowbk-omnigent-users.json')::json) ON CONFLICT DO NOTHING;\n", DATABASE)
    cluster.tmp.exec(cluster.role, ['rm', '-f', '/tmp/woowbk-omnigent-users.json'], user='postgres', timeout=120)
    return [row['id'] for row in carried]


PAUSE_SQL = 'UPDATE scheduled_tasks SET state = 2 WHERE state = 1;\n'
ACTIVE_SQL = 'SELECT to_json(count(*)) FROM scheduled_tasks WHERE state = 1'


def convert(work, app, test_mode, out_dir):
    """Build the app's volumes in `out_dir/volumes`; returns {volumes {name: path}, counts, kept_accounts,
    conflicts, ...}."""
    raise BackupError('incompatible', SECURITY_BLOCKER, app=app.id)

    adapter = work.adapter(app)
    tmp = work.temp(app)
    target, version, alembic, addon, blocker = _prepare(work, app)
    if blocker:
        raise BackupError('incompatible', f'Omnigent 不能搬過來：{blocker}', app=app.id)
    ids = adapter.owner_ids()
    staging = work.staging / 'omnigent-work'
    staging.mkdir(mode=0o700)
    (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
    pg_ids = tmp.user_ids('ids-pg', target.db_image, 'postgres')
    artifacts = hacommon.TreeTar(staging / 'ha-artifacts.tar', 0, 0, work.guard)
    try:
        src = member_pass(work, app, tmp, pg_ids, artifacts=artifacts)
    finally:
        artifacts.close()
    work.phase('convert')
    work.guard.check(2 * src.pg_bytes + ha_odoo.WAL_ALLOWANCE)
    cluster = ha_odoo.start_ha_cluster(work, tmp, target.db_image)
    found = analyse(cluster)
    blockers, _warnings = verdict(src, found, live_alembic_value=alembic, ha_major=_ha_major(src),
                                  target_major=ha_odoo.target_pg_major(work, app, target.db_image))
    if blockers:
        raise BackupError('incompatible', f'Omnigent 不能搬過來：{blockers[0]}', app=app.id)
    dump = staging / 'omnigent.dump'
    work.log('匯出 HA 的 Omnigent 資料庫')
    with open(dump, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        tmp.exec('hapg', ['pg_dump', '-U', 'postgres', '-Fc', '-d', DATABASE], user='postgres', stdout=handle,
                 timeout=DUMP_TIMEOUT, max_output=work.guard.budget())
        handle.flush()
        os.fsync(handle.fileno())
    tmp.remove('hapg')
    tmp.remove_volume('hapg')
    work.checkpoint()

    work.log('建立新的 PostgreSQL 資料庫叢集（與這台相同的映像與設定）')
    tmp.volume('omni-db')
    tmp.run('omni-db', target.db_image, [], detach=True, volumes=[(tmp.name('omni-db'), target.db_target, None)],
            env=target.db_env, secrets=target.db_secrets)
    pg = ha_odoo.Cluster(tmp, 'omni-db', superuser=target.db_user, log=work.log)
    pg.wait_ready(tcp=True, checkpoint=work.checkpoint)
    extensions = [e for e in found['objects'].get('extensions') or [] if e != 'plpgsql']
    if extensions:
        pg.script(''.join(f'CREATE EXTENSION IF NOT EXISTS {ha_odoo.pg_ident(e)};\n' for e in extensions), DATABASE)
    restore_dump(work, tmp, dump, target.db_user)
    os.unlink(dump)
    kept = carry_accounts(work, pg, live_users(work, app, target))
    conflicts = account_conflicts(found, target)
    paused = 0
    if test_mode:
        paused = ha_odoo._int(pg.query_json(ACTIVE_SQL, DATABASE))
        work.log(f'測試匯入：暫停 {paused} 個啟用中的 Omnigent 排程')
        pg.script(PAUSE_SQL, DATABASE)
        if ha_odoo._int(pg.query_json(ACTIVE_SQL, DATABASE)):
            raise BackupError('job-failed', '測試匯入沒有暫停全部 Omnigent 排程。')
    counts = table_counts(pg, found['tables'])
    expected = dict(found['counts'], users=found['counts'].get('users', 0) + len(kept))
    differ = [f'{t}（HA {n}，匯入後 {counts.get(t)}）' for t, n in sorted(expected.items()) if counts.get(t) != n]
    now_alembic = pg.query_json(ALEMBIC_SQL, DATABASE)
    if differ or sorted(now_alembic or []) != sorted(found['alembic']):
        raise BackupError('job-failed', f'Omnigent 匯入後的資料和 HA 不同，已停止：{"、".join(differ[:10]) or "結構版本"}。')
    work.log(f'Omnigent 資料匯入完成：{len(expected)} 個資料表的筆數都和 HA 相同'
             + (f'，保留這台的帳號 {"、".join(kept)}' if kept else ''))
    pg.statement('CHECKPOINT;')
    code = tmp.stop('omni-db', timeout=300)
    if code != 0:
        raise BackupError('job-failed', f'新的 PostgreSQL 叢集沒有正常關閉（結束碼 {code}）。')
    state = tmp.run('controldata', target.db_image, ['pg_controldata', target.pgdata], user='postgres',
                    volumes=[(tmp.name('omni-db'), target.db_target, 'ro')], timeout=300, read_only_root=True,
                    max_output=1024 * 1024).stdout or b''
    if not re.search(rb'Database cluster state:\s+shut down\s*$', state, re.M):
        raise BackupError('job-failed', '新的 PostgreSQL 叢集沒有正常關閉。')
    tmp.remove('omni-db')
    db_path = out_dir / 'volumes' / f'{target.db_volume}.tar'
    with open(db_path, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        tmp.volume_export('omni-db', handle, max_output=work.guard.budget())
        handle.flush()
        os.fsync(handle.fileno())
    tmp.remove_volume('omni-db')

    server_path = server_volume(work, app, target, staging, out_dir)
    pi_path = out_dir / 'volumes' / f'{target.pi_volume}.tar'
    hacommon.live_export(work, app, target.pi_volume, pi_path)
    for path in (db_path, server_path, pi_path):
        ha_odoo.check_volume_tar(path, ids)
    return {'volumes': {target.db_volume: db_path, target.server_volume: server_path, target.pi_volume: pi_path},
            'counts': {k: found['detail'].get(k, 0) for k in ('users', 'conversations', 'scheduled_tasks', 'hosts')},
            'kept_accounts': kept, 'conflicts': conflicts, 'paused_tasks': paused,
            'scheduled_tasks_active': ha_odoo._int(found['detail'].get('scheduled_tasks_active')),
            'public_sessions': ha_odoo._int(found['detail'].get('public_sessions')),
            'overrides': list(src.overrides), 'hosts': ha_odoo._int(found['detail'].get('hosts'))}


def server_volume(work, app, target, staging, out_dir):
    """omnigent-server-data: the live export without `artifacts/**`, plus HA's artifacts owned like the live
    artifacts folder (or the volume's top folder)."""
    import tarfile
    live = hacommon.live_export(work, app, target.server_volume, staging / 'live-server.tar')
    path = out_dir / 'volumes' / f'{target.server_volume}.tar'
    out = hacommon.FileTar(path, work.guard)
    try:
        dirs = hacommon.copy_live(live, out, drop=lambda name: ha_odoo._under(name, 'artifacts'),
                                  what='這台 Omnigent 的伺服器資料卷')
        uid, gid, _mode = dirs.get('artifacts') or dirs.get('.') or (0, 0, 0o755)
        if '.' not in dirs:
            raise BackupError('job-failed', '這台 Omnigent 伺服器資料卷的匯出內容不完整。', app=app.id)
        with tarfile.open(staging / 'ha-artifacts.tar', 'r|', encoding=habackup.ENCODING,
                          errors=habackup.ERRORS) as tar:
            seen_root = False
            for member in tar:
                item = tarfile.TarInfo(member.name)
                item.type, item.mode, item.mtime = member.type, member.mode, member.mtime
                item.uid, item.gid, item.size, item.linkname = uid, gid, member.size, member.linkname
                item.uname = item.gname = ''
                seen_root = seen_root or member.name == 'artifacts'
                out.add_member(item, tar.extractfile(member) if member.isfile() else None)
                tar.members.clear()
        if not seen_root:
            out.add_member(hacommon.info('artifacts', 'dir', mode=0o755, uid=uid, gid=gid, mtime=time.time()))
    finally:
        out.close()
    os.unlink(live)
    os.unlink(staging / 'ha-artifacts.tar')
    return path


# ====================================================================== texts

def import_texts(data):
    notes = ['Omnigent 的使用者帳號、工作階段、代理程式與排程會換成 HA 的；HA 的登入金鑰（accounts-cookie-secret）一起搬過來，'
             '這台目前登入的瀏覽器與裝置需要重新登入。']
    kept = data.get('kept_accounts') or []
    if kept:
        notes.append(f'這台 Omnigent 的管理者與 runner 帳號（{hacommon.names(kept)}）會保留，密碼不變。')
    conflicts = data.get('conflicts') or []
    if conflicts:
        notes.append(f'HA 也有帳號 {hacommon.names(conflicts)}：匯入後以 HA 的為準，這台設定的密碼對它不再適用，'
                     '請用 HA 的密碼登入，必要時更新這台的應用機密。')
    if data.get('overrides'):
        notes.append('HA 的 Omnigent 分享與管理者執行期設定不會搬過來，這台維持自己的設定。')
    reminders = ['匯入後請用 HA 那邊的 Omnigent 帳號和密碼登入。',
                 '請把每一台 runner（例如 HA 的 Pi Agent、其他電腦上的 omnigent host）改連到這台的 Omnigent 網址並重新登入；'
                 '在那之前 HA 的 runner 會顯示離線。']
    if data.get('paused_tasks'):
        reminders.append(f'測試匯入已暫停 {data["paused_tasks"]} 個排程，確認無誤後再到 Omnigent 重新啟用。')
    elif data.get('scheduled_tasks_active'):
        reminders.append(f'HA 的 {data["scheduled_tasks_active"]} 個啟用中的排程會在這台執行，請確認它們有可用的 runner。')
    if data.get('public_sessions'):
        reminders.append(f'HA 有 {data["public_sessions"]} 個公開分享的工作階段，搬過來後仍然公開，請確認是否需要。')
    return notes, reminders
