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

The check also compares HA's tables and columns with this device's live database (the trusted schema, below); a
difference is a blocker naming the tables.

convert (B1-01: HA's backup never provides DDL, defaults, checks or domains): `pg_dump -Fc omnigent` of HA's cluster
is the source of DATA only. A NEW cluster from the live image, environment and secret mount (its superuser is the live
app role with the live password) gets THIS device's schema: `pg_dump --schema-only` of the live database inside one
exported snapshot (capture_consistent_target_schema), its pre-data and post-data sections restored by the app role.
The product enforces what the lab proved instead of trusting a caller (trusted_schema): the live database's whole
schema signature (SCHEMA_SIGNATURE_SQL: tables, columns with types and defaults, constraints, indexes, sequences,
types, functions, triggers, rules, views, policies, extensions, schemas, other user objects) and alembic revision are
read before and after the capture and must be equal, and so must the snapshot's columns (no DDL ran while it was
taken; else the job stops and nothing changed); HA's columns, sequences and types must equal it (else `incompatible`,
naming the tables); from HA's dump only TABLE DATA and SEQUENCE SET entries are restored (`-L`, data_only_toc), by a
role without any privilege beyond INSERT and sequence values (`woowbk_restore`); the new cluster's schema signature
must equal the live one after the post-data section and again after the last write, and the new cluster may hold no
other role, no role or database setting, no ALTER SYSTEM setting and no large object (audit_new_cluster). This
device's own admin and runner accounts (the Quadlet's OMNIGENT_ACCOUNTS_INIT_ADMIN_USERNAME /
OMNIGENT_RUNNER_USERNAME) are read from the live database as the app owner and added back by that restricted role
unless HA has a user of the same name (HA's wins, with a warning): without them the runner could not log in while
every health check stays green. Test mode pauses every active scheduled task (the restricted role). Counts and alembic
are verified, the restricted role is dropped, the cluster is stopped cleanly (`pg_controldata` "shut down") and
exported. HA's cluster can lie and run code inside its container (security review 2026-11-23): its answers are given
again by the new cluster before anything is exported (require_answers, SR-1) and the SEQUENCE SET statements pg_dump
wrote from its values must be bare setval calls (require_sequence_sets, SR-3).
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

from . import habackup, hacommon, ha_n8n, ha_odoo, tempctr
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
SCHEMA_CHANGED = ('這台 Omnigent 的資料庫結構在轉換期間改變了（可能正在升級或重新啟動），沒有匯入任何資料；'
                  '請等它正常執行後再轉換一次。')


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
        blockers.append(f'資料庫結構版本不同：HA 是 {hacommon.names(ha_alembic, 5) or "未知"}，這台是 '
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
    return {'omnigent_version': version or '', 'alembic': hacommon.names(found['alembic'], 5),
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
    ha_schema = read_schema(cluster, found['alembic']) if set(TABLES) <= set(found['tables']) else None
    tmp.remove('hapg')
    tmp.remove_volume('hapg')
    blockers, warnings = verdict(src, found, live_alembic_value=alembic, ha_major=_ha_major(src),
                                 target_major=ha_odoo.target_pg_major(work, app, target.db_image))
    if blocker:
        blockers.insert(0, blocker)
    if ha_schema is not None:
        differ = schema_differences(ha_schema, live_schema(work, app, target))
        if differ:
            blockers.append(schema_blocker(differ))
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


def data_only_toc(text, *, tables=None, sequences=None):
    """Only the table data and sequence values of a locally generated custom archive (its `pg_restore -l` list), as
    the `-L` list of the data restore. pg_restore reads nothing of a selected line but the dump id at its start, so a
    name in HA's database that carries a line break could add an entry of its own choice: with `tables`/`sequences`
    (the trusted schema's names) every selected entry must name one of them, each at most once."""
    selected, seen, named = [], set(), set()
    strict = tables is not None or sequences is not None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(';'):
            continue
        match = re.fullmatch(r'\s*(\d+);\s+\d+\s+\d+\s+(.+)', line)
        if not match or match.group(1) in seen:
            raise BackupError('incompatible', 'HA 的資料庫匯出清單格式不正確。')
        seen.add(match.group(1))
        if match.group(2).startswith(('TABLE DATA ', 'SEQUENCE SET ')):
            if strict:
                entry = re.fullmatch(r'(TABLE DATA|SEQUENCE SET) public (\S+) \S+', match.group(2))
                allowed = (tables if entry and entry.group(1) == 'TABLE DATA' else sequences) or ()
                if not entry or entry.group(2) not in allowed or entry.groups()[:2] in named:
                    raise BackupError('incompatible', 'HA 的資料庫匯出清單有不屬於這台 Omnigent 資料庫結構的資料項目，'
                                                      '無法安全地搬過來。')
                named.add(entry.groups()[:2])
            selected.append(line)
    if not selected:
        raise BackupError('incompatible', 'HA 的資料庫匯出清單沒有資料。')
    return '\n'.join(selected) + '\n'


# Compare physical data columns, including order: a matching revision alone does not
# establish that HA and the trusted target schema actually match.
SCHEMA_COLUMNS_SQL = """SELECT coalesce(json_agg(json_build_array(c.relname, a.attname,
 pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnotnull, a.attidentity, a.attgenerated)
 ORDER BY c.relname, a.attnum), '[]'::json)
 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped"""


def schema_columns(cluster):
    value = cluster.query_json(SCHEMA_COLUMNS_SQL, DATABASE)
    if not isinstance(value, list) or not value or any(not isinstance(row, list) or len(row) != 6 for row in value):
        raise BackupError('incompatible', '無法確認 Omnigent 的資料表結構。')
    return value


# This script runs in the trusted target's PostgreSQL container. psql owns the
# exported snapshot until pg_dump finishes; stdout contains one JSON line and
# then the custom archive. All temporary paths are private and cleaned on exit.
SNAPSHOT_SCRIPT = r'''set -eu
umask 077
snapdir=$(mktemp -d /tmp/woowbk-schema.XXXXXXXX)
pid=
cleanup() {
    exec 3>&- || :
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
    rm -rf -- "$snapdir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mkfifo "$snapdir/in"
psql -X -q -A -t -v ON_ERROR_STOP=1 -U "$1" -d "$2" < "$snapdir/in" > "$snapdir/out" 2> "$snapdir/err" &
pid=$!
exec 3> "$snapdir/in"
cat >&3 <<SQL
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL application_name = 'woowbk-schema-snapshot';
SET LOCAL lock_timeout = '15s';
SET LOCAL idle_in_transaction_session_timeout = '10920s';
LOCK TABLE public.alembic_version IN ACCESS SHARE MODE;
\\o $snapdir/snapshot
SELECT pg_export_snapshot();
\\o $snapdir/revision
SELECT CASE WHEN (SELECT coalesce(json_agg(version_num ORDER BY version_num), '[]'::json)::text FROM public.alembic_version) = '__REVISION__' THEN 'ok' ELSE 'mismatch' END;
\\o $snapdir/columns
__COLUMNS__;
\\o
SQL
for n in $(seq 1 60); do
    [ -s "$snapdir/columns" ] && break
    kill -0 "$pid" 2>/dev/null || exit 21
    sleep 1
done
[ -s "$snapdir/columns" ] && [ "$(cat "$snapdir/revision")" = ok ] || exit 22
snapshot=$(cat "$snapdir/snapshot")
printf '%s' "$snapshot" | grep -Eq '^[0-9A-Fa-f-]+$' || exit 23
cat "$snapdir/columns"
pg_dump -U "$1" -d "$2" -Fc --schema-only --no-owner --no-acl --lock-wait-timeout=15s --snapshot="$snapshot"
printf '%s\n' 'COMMIT;' '\q' >&3
exec 3>&-
wait "$pid"
pid=
'''


def capture_consistent_target_schema(work, app, target, path, expected_alembic):
    """Capture schema, revision and column signature from one exported snapshot.

    Contract: the caller must prevent concurrent target schema DDL for the
    duration of capture; PostgreSQL table locks do not cover every DDL object.
    The public import remains guarded until that precondition is established.
    """
    if not expected_alembic or any(not isinstance(v, str) or not ALEMBIC_RE.fullmatch(v) for v in expected_alembic):
        raise BackupError('incompatible', '目標 Omnigent 的結構版本不明。', app=app.id)
    revision = json.dumps(sorted(expected_alembic), ensure_ascii=True)
    script = SNAPSHOT_SCRIPT.replace('__REVISION__', revision.replace("'", "''"))
    script = script.replace('__COLUMNS__', ' '.join(SCHEMA_COLUMNS_SQL.split()))
    capture = path.with_name(path.name + '.capture')
    capture_created = output_created = False
    try:
        with open(capture, 'xb') as handle:
            capture_created = True
            os.fchmod(handle.fileno(), 0o600)
            work.runner(app).podman('exec', '-i', target.db_container, 'sh', '-s', '--', target.db_user, DATABASE,
                                    input=script.encode('utf-8'), stdout=handle, timeout=DUMP_TIMEOUT,
                                    max_output=work.guard.budget(), abort=work.abort)
            handle.flush()
            os.fsync(handle.fileno())
        work.guard.check(os.path.getsize(capture))
        with open(capture, 'rb') as source:
            from . import util
            try:
                columns = util.loads_strict(source.readline(4 * 1024 * 1024 + 1), max_bytes=4 * 1024 * 1024)
            except ValueError:
                raise BackupError('incompatible', '目標 Omnigent 的結構快照格式不正確。', app=app.id) from None
            if not isinstance(columns, list) or not columns or any(not isinstance(v, list) or len(v) != 6 for v in columns):
                raise BackupError('incompatible', '目標 Omnigent 的結構快照格式不正確。', app=app.id)
            with open(path, 'xb') as dest:
                output_created = True
                os.fchmod(dest.fileno(), 0o600)
                import shutil
                shutil.copyfileobj(source, dest, 1024 * 1024)
                dest.flush()
                os.fsync(dest.fileno())
        return columns
    except BaseException:
        if output_created:
            path.unlink(missing_ok=True)
        raise
    finally:
        if capture_created:
            capture.unlink(missing_ok=True)


# secreview SR-3: a SEQUENCE SET entry is SQL that pg_dump WROTE FROM WHAT HA'S SERVER SENT: `SELECT
# pg_catalog.setval('<name>', <last_value as sent>, <called>);` (pg_dump.c dumpSequenceData puts last_value into the
# statement unquoted). HA's server is untrusted (a crafted catalog makes last_value any text: proven in the lab, the
# archive then held a whole DO block). Before anything is loaded, the selected SEQUENCE SET entries are printed by
# pg_restore itself (`-f -`, the very text `-d` would run) and must be exactly one setval of a trusted sequence with an
# integer each; pg_restore's own header lines may precede them, nothing else may appear.
SETVAL_RE = re.compile(r"SELECT pg_catalog\.setval\('public\.([A-Za-z_][A-Za-z0-9_]{0,62})', (-?[0-9]{1,19}), "
                       r"(true|false)\);")
SCRIPT_HEADER = frozenset({'SET statement_timeout = 0;', 'SET lock_timeout = 0;',
                           'SET idle_in_transaction_session_timeout = 0;', 'SET transaction_timeout = 0;',
                           'SET standard_conforming_strings = on;', 'SET check_function_bodies = false;',
                           'SET xmloption = content;', 'SET client_min_messages = warning;', 'SET row_security = off;'})
SCRIPT_HEADER_RE = re.compile(r"SET client_encoding = '[A-Z0-9_]{1,30}';"
                              r"|SELECT pg_catalog\.set_config\('search_path', '(?:[^'\n]|''){0,500}', false\);")
SCRIPT_SKIP_RE = re.compile(r'|--.*|\\(?:un)?restrict [A-Za-z0-9]{1,128}')
SEQUENCE_SET_ODD = 'HA 的資料庫匯出清單裡的序號（SEQUENCE SET）項目含有序號值以外的內容，無法安全地搬過來。'
SEQUENCE_SCRIPT_OUTPUT = 4 * 1024 * 1024


def sequence_set_lines(selection):
    return [line for line in selection.splitlines() if re.match(r'\s*\d+;\s+\d+\s+\d+\s+SEQUENCE SET ', line)]


def require_sequence_sets(script, count, sequences):
    """`script`: pg_restore's plain text of the `count` selected SEQUENCE SET entries (see SETVAL_RE above)."""
    names, body = [], False
    for line in script.splitlines():
        if SCRIPT_SKIP_RE.fullmatch(line):
            continue
        match = SETVAL_RE.fullmatch(line)
        if match:
            body = True
            names.append(match.group(1))
        elif body or not (line in SCRIPT_HEADER or SCRIPT_HEADER_RE.fullmatch(line)):
            raise BackupError('incompatible', SEQUENCE_SET_ODD)
    if len(names) != count or len(set(names)) != count or not set(names) <= set(sequences or ()):
        raise BackupError('incompatible', SEQUENCE_SET_ODD)


def restore_trusted_data(work, tmp, schema_dump, data_dump, superuser, *, source_columns, role='omni-db',
                         tables=None, sequences=None):
    """Load the trusted target schema and only data from HA (`tables`/`sequences`: data_only_toc's names).

    Both archives must be generated by our own pg_dump; schema_dump must come from
    the trusted target. The caller must compare Alembic revisions before calling.
    The role and its limited grants remain until finish_trusted_data is called.
    """
    cluster = ha_odoo.Cluster(tmp, role, superuser=superuser, log=work.log)
    with open(data_dump, 'rb') as handle:
        listing = tmp.exec(role, ['pg_restore', '-l'], user='postgres', input=handle,
                           timeout=DUMP_TIMEOUT, max_output=ha_odoo.TOC_OUTPUT).stdout or b''
    text = listing.decode('utf-8', 'surrogateescape')
    selection = data_only_toc(text, tables=tables, sequences=sequences)
    sets = sequence_set_lines(selection)
    if sets:
        cluster.write_file('/tmp/woowbk-omnigent-seq.toc', ('\n'.join(sets) + '\n').encode('utf-8', 'surrogateescape'))
        with open(data_dump, 'rb') as handle:
            script = tmp.exec(role, ['pg_restore', '-f', '-', '-L', '/tmp/woowbk-omnigent-seq.toc'], user='postgres',
                              input=handle, timeout=DUMP_TIMEOUT, max_output=SEQUENCE_SCRIPT_OUTPUT).stdout or b''
        require_sequence_sets(script.decode('utf-8', 'surrogateescape'), len(sets), sequences)
    skipped = [kind for kind in toc_kinds(text) if kind not in ('TABLE DATA', 'SEQUENCE SET')]
    work.log(f'HA 的資料庫匯出清單：只載入資料（TABLE DATA、SEQUENCE SET），略過 {len(skipped)} 種結構項目'
             + (f'（{hacommon.names(skipped, 8)}）' if skipped else ''))
    cluster.write_file('/tmp/woowbk-omnigent.toc', selection.encode('utf-8', 'surrogateescape'))
    with open(schema_dump, 'rb') as handle:
        tmp.exec(role, ['pg_restore', '-U', superuser, '--no-owner', '--no-acl', '--exit-on-error',
                        '--single-transaction', '--section=pre-data', '-d', DATABASE], user='postgres',
                 input=handle, timeout=DUMP_TIMEOUT, max_output=1024 * 1024)
    if schema_columns(cluster) != source_columns:
        raise BackupError('incompatible', 'HA 與目標 Omnigent 的資料表欄位結構不同。')
    cluster.script(f'CREATE ROLE {RESTORE_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n'
                   f'GRANT USAGE ON SCHEMA public TO {RESTORE_ROLE};\n'
                   f'GRANT INSERT ON ALL TABLES IN SCHEMA public TO {RESTORE_ROLE};\n'
                   f'GRANT SELECT ON public.users, public.scheduled_tasks TO {RESTORE_ROLE};\n'
                   f'GRANT UPDATE ON public.scheduled_tasks TO {RESTORE_ROLE};\n'
                   f'GRANT USAGE, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {RESTORE_ROLE};\n', DATABASE)
    with open(data_dump, 'rb') as handle:
        tmp.exec(role, ['pg_restore', '-U', RESTORE_ROLE, '--no-owner', '--no-acl', '--exit-on-error',
                        '--single-transaction', '-L', '/tmp/woowbk-omnigent.toc', '-d', DATABASE],
                 user='postgres', input=handle, timeout=DUMP_TIMEOUT, max_output=1024 * 1024)
    with open(schema_dump, 'rb') as handle:
        tmp.exec(role, ['pg_restore', '-U', superuser, '--no-owner', '--no-acl', '--exit-on-error',
                        '--single-transaction', '--section=post-data', '-d', DATABASE], user='postgres',
                 input=handle, timeout=DUMP_TIMEOUT, max_output=1024 * 1024)
    tmp.exec(role, ['rm', '-f', '/tmp/woowbk-omnigent.toc'], user='postgres', timeout=120)
    return cluster


def finish_trusted_data(cluster):
    """Revoke all temporary loader grants and remove its login before export."""
    cluster.script(f'DROP OWNED BY {RESTORE_ROLE};\nDROP ROLE {RESTORE_ROLE};\n', DATABASE)


def carry_accounts_restricted(cluster, rows):
    """Carry target accounts as the limited loader; values are sent only on stdin."""
    if not rows:
        return []
    names = [row['id'] for row in rows]
    present = cluster.query_json("SELECT coalesce(json_agg(id), '[]'::json) FROM users WHERE id IN ("
                                 + ', '.join(ha_odoo.sql_literal(n) for n in names) + ')', DATABASE)
    if not isinstance(present, list):
        raise BackupError('job-failed', '無法確認 Omnigent 帳號。')
    carried = [row for row in rows if row['id'] not in set(present)]
    if carried:
        payload = ha_odoo.sql_literal(json.dumps(carried, ensure_ascii=True))
        loader = ha_odoo.Cluster(cluster.tmp, cluster.role, superuser=RESTORE_ROLE, log=cluster.log)
        loader.script('INSERT INTO users SELECT * FROM json_populate_recordset(NULL::users, '
                      + payload + '::json) ON CONFLICT DO NOTHING;\n', DATABASE)
    return [row['id'] for row in carried]


PAUSE_SQL = 'UPDATE scheduled_tasks SET state = 2 WHERE state = 1;\n'
ACTIVE_SQL = 'SELECT to_json(count(*)) FROM scheduled_tasks WHERE state = 1'


# ====================================================================== the trusted schema (B1-01)
#
# HA's archive provides DATA only. The schema is this device's own; the product itself proves (never a caller's
# promise) that what the new cluster gets is exactly that schema and that no DDL ran while it was captured.

def _own(catalog, column='oid'):
    """`<alias>.<column>` is not a member of an extension (pg_trgm puts its type and functions into public)."""
    return (f"NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend x WHERE x.classid = 'pg_catalog.{catalog}'::regclass "
            f"AND x.objid = o.{column} AND x.deptype = 'e')")


# User objects outside the parts below (FirstNormalObjectId 16384: what initdb made is older); Omnigent has none.
OTHER_CATALOGS = ('pg_cast', 'pg_operator', 'pg_opclass', 'pg_opfamily', 'pg_collation', 'pg_conversion',
                  'pg_ts_config', 'pg_ts_dict', 'pg_ts_parser', 'pg_ts_template', 'pg_foreign_data_wrapper',
                  'pg_foreign_server', 'pg_publication', 'pg_statistic_ext', 'pg_transform', 'pg_language', 'pg_am',
                  'pg_event_trigger')
SIGNATURE_PARTS = (
    ('relations', "SELECT coalesce(json_agg(json_build_array(o.relname, o.relkind::text, o.relpersistence::text, "
                  "o.relrowsecurity, o.relforcerowsecurity, coalesce(array_to_string(o.reloptions, ','), ''), "
                  "o.relispartition) ORDER BY o.relname), '[]'::json) FROM pg_catalog.pg_class o "
                  "JOIN pg_catalog.pg_namespace n ON n.oid = o.relnamespace WHERE n.nspname = 'public' "
                  "AND o.relkind IN ('r', 'p', 'v', 'm', 'S', 'f', 'c') AND " + _own('pg_class')),
    ('columns', "SELECT coalesce(json_agg(json_build_array(o.relname, a.attname, "
                "pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnotnull, a.attidentity::text, "
                "a.attgenerated::text, coalesce(pg_catalog.pg_get_expr(d.adbin, d.adrelid), ''), "
                "CASE WHEN a.attcollation <> t.typcollation THEN coalesce(l.collname, '?') ELSE '' END) "
                "ORDER BY o.relname, a.attnum), '[]'::json) FROM pg_catalog.pg_attribute a "
                "JOIN pg_catalog.pg_class o ON o.oid = a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid = o.relnamespace "
                "JOIN pg_catalog.pg_type t ON t.oid = a.atttypid "
                "LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum "
                "LEFT JOIN pg_catalog.pg_collation l ON l.oid = a.attcollation "
                "WHERE n.nspname = 'public' AND o.relkind IN ('r', 'p', 'v', 'm', 'f', 'c') AND a.attnum > 0 "
                "AND NOT a.attisdropped AND " + _own('pg_class')),
    ('constraints', "SELECT coalesce(json_agg(json_build_array(coalesce(c.relname, t.typname, ''), o.conname, "
                    "o.contype::text, pg_catalog.pg_get_constraintdef(o.oid), o.condeferrable, o.condeferred, "
                    "o.convalidated, o.connoinherit) ORDER BY coalesce(c.relname, t.typname, ''), o.conname), "
                    "'[]'::json) FROM pg_catalog.pg_constraint o JOIN pg_catalog.pg_namespace n ON n.oid = o.connamespace "
                    "LEFT JOIN pg_catalog.pg_class c ON c.oid = o.conrelid LEFT JOIN pg_catalog.pg_type t "
                    "ON t.oid = o.contypid WHERE n.nspname = 'public'"),
    ('indexes', "SELECT coalesce(json_agg(json_build_array(c.relname, i.relname, "
                "pg_catalog.pg_get_indexdef(o.indexrelid)) ORDER BY c.relname, i.relname), '[]'::json) "
                "FROM pg_catalog.pg_index o JOIN pg_catalog.pg_class i ON i.oid = o.indexrelid "
                "JOIN pg_catalog.pg_class c ON c.oid = o.indrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public'"),
    ('sequences', "SELECT coalesce(json_agg(json_build_array(o.relname, pg_catalog.format_type(s.seqtypid, NULL), "
                  "s.seqstart, s.seqincrement, s.seqmax, s.seqmin, s.seqcache, s.seqcycle, "
                  "coalesce((SELECT r.relname || '.' || a.attname FROM pg_catalog.pg_depend d "
                  "JOIN pg_catalog.pg_class r ON r.oid = d.refobjid JOIN pg_catalog.pg_attribute a "
                  "ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid "
                  "WHERE d.classid = 'pg_catalog.pg_class'::regclass AND d.objid = o.oid "
                  "AND d.refclassid = 'pg_catalog.pg_class'::regclass AND d.deptype IN ('a', 'i') "
                  "ORDER BY 1 LIMIT 1), '')) ORDER BY o.relname), '[]'::json) FROM pg_catalog.pg_sequence s "
                  "JOIN pg_catalog.pg_class o ON o.oid = s.seqrelid JOIN pg_catalog.pg_namespace n ON n.oid = o.relnamespace "
                  "WHERE n.nspname = 'public'"),
    ('types', "SELECT coalesce(json_agg(json_build_array(o.typname, o.typtype::text, "
              "CASE WHEN o.typbasetype <> 0 THEN pg_catalog.format_type(o.typbasetype, o.typtypmod) ELSE '' END, "
              "o.typnotnull, coalesce(pg_catalog.pg_get_expr(o.typdefaultbin, 0), ''), "
              "(SELECT coalesce(json_agg(e.enumlabel ORDER BY e.enumsortorder), '[]'::json) FROM pg_catalog.pg_enum e "
              "WHERE e.enumtypid = o.oid)) ORDER BY o.typname), '[]'::json) FROM pg_catalog.pg_type o "
              "JOIN pg_catalog.pg_namespace n ON n.oid = o.typnamespace LEFT JOIN pg_catalog.pg_class r ON r.oid = o.typrelid "
              "WHERE n.nspname = 'public' AND o.typcategory <> 'A' AND (o.typrelid = 0 OR r.relkind = 'c') AND "
              + _own('pg_type')),
    ('functions', "SELECT coalesce(json_agg(n.nspname || '.' || o.proname || '(' "
                  "|| pg_catalog.pg_get_function_identity_arguments(o.oid) || ')' || o.prokind::text "
                  "ORDER BY n.nspname, o.proname, pg_catalog.pg_get_function_identity_arguments(o.oid)), '[]'::json) "
                  "FROM pg_catalog.pg_proc o JOIN pg_catalog.pg_namespace n ON n.oid = o.pronamespace "
                  "WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND " + _own('pg_proc')),
    ('triggers', "SELECT coalesce(json_agg(json_build_array(c.relname, o.tgname, pg_catalog.pg_get_triggerdef(o.oid)) "
                 "ORDER BY c.relname, o.tgname), '[]'::json) FROM pg_catalog.pg_trigger o "
                 "JOIN pg_catalog.pg_class c ON c.oid = o.tgrelid WHERE NOT o.tgisinternal"),
    ('rules', "SELECT coalesce(json_agg(json_build_array(c.relname, o.rulename, pg_catalog.pg_get_ruledef(o.oid)) "
              "ORDER BY c.relname, o.rulename), '[]'::json) FROM pg_catalog.pg_rewrite o "
              "JOIN pg_catalog.pg_class c ON c.oid = o.ev_class JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
              "WHERE o.rulename <> '_RETURN' AND n.nspname NOT IN ('pg_catalog', 'information_schema')"),
    ('views', "SELECT coalesce(json_agg(json_build_array(n.nspname, o.relname, pg_catalog.pg_get_viewdef(o.oid)) "
              "ORDER BY n.nspname, o.relname), '[]'::json) FROM pg_catalog.pg_class o "
              "JOIN pg_catalog.pg_namespace n ON n.oid = o.relnamespace WHERE o.relkind IN ('v', 'm') "
              "AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND " + _own('pg_class')),
    ('policies', "SELECT coalesce(json_agg(json_build_array(c.relname, o.polname, o.polcmd::text, o.polpermissive, "
                 "coalesce(pg_catalog.pg_get_expr(o.polqual, o.polrelid), ''), "
                 "coalesce(pg_catalog.pg_get_expr(o.polwithcheck, o.polrelid), '')) ORDER BY c.relname, o.polname), "
                 "'[]'::json) FROM pg_catalog.pg_policy o JOIN pg_catalog.pg_class c ON c.oid = o.polrelid"),
    ('extensions', "SELECT coalesce(json_agg(json_build_array(o.extname, o.extversion, n.nspname) ORDER BY o.extname), "
                   "'[]'::json) FROM pg_catalog.pg_extension o JOIN pg_catalog.pg_namespace n ON n.oid = o.extnamespace"),
    ('schemas', "SELECT coalesce(json_agg(o.nspname ORDER BY o.nspname), '[]'::json) FROM pg_catalog.pg_namespace o "
                "WHERE o.nspname NOT IN ('public', 'information_schema') AND o.nspname !~ '^pg_'"),
    ('other', 'SELECT json_build_object(' + ', '.join(
        f"'{name}', (SELECT count(*) FROM pg_catalog.{name} o WHERE o.oid >= 16384 AND {_own(name)})"
        for name in OTHER_CATALOGS) + ')'),
)
SCHEMA_SIGNATURE_SQL = ('SELECT json_build_object('
                        + ', '.join(f"'{key}', ({sql})" for key, sql in SIGNATURE_PARTS) + ')')
SIGNATURE_KEYS = tuple(key for key, _sql in SIGNATURE_PARTS)
# What the new cluster may hold besides the schema: only its bootstrap superuser, no role or database setting, no
# ALTER SYSTEM setting, no large object (lo_export/lo_import are what B1-01's expressions would have used).
AUDIT_SQL = ("SELECT json_build_object("
             "'roles', (SELECT coalesce(json_agg(rolname ORDER BY rolname), '[]'::json) FROM pg_catalog.pg_roles "
             "WHERE rolname !~ '^pg_'), "
             "'role_settings', (SELECT count(*) FROM pg_catalog.pg_db_role_setting), "
             "'auto_conf', (SELECT count(*) FROM pg_catalog.pg_file_settings WHERE sourcefile ~ '/postgresql[.]auto[.]conf$'), "
             "'large_objects', (SELECT count(*) FROM pg_catalog.pg_largeobject_metadata))")


class Schema:
    """A database's columns (SCHEMA_COLUMNS_SQL), whole signature (SCHEMA_SIGNATURE_SQL) and alembic revision."""

    def __init__(self, columns, signature, alembic):
        self.columns, self.signature, self.alembic = columns, signature, sorted(alembic or [])

    def __eq__(self, other):
        return isinstance(other, Schema) and (self.columns, self.signature, self.alembic) == (
            other.columns, other.signature, other.alembic)

    def tables(self):
        return sorted({row[0] for row in self.signature.get('relations') or [] if row[1] in ('r', 'p')})

    def sequences(self):
        return sorted({row[0] for row in self.signature.get('sequences') or []})


def _signature(value):
    if not isinstance(value, dict) or set(value) != set(SIGNATURE_KEYS):
        raise BackupError('incompatible', '無法確認 Omnigent 的資料庫結構。')
    return value


def schema_signature(cluster):
    return _signature(cluster.query_json(SCHEMA_SIGNATURE_SQL, DATABASE))


def read_schema(cluster, alembic):
    """HA's (or the new cluster's) schema, from a throwaway cluster."""
    return Schema(schema_columns(cluster), schema_signature(cluster), alembic)


def live_schema(work, app, target):
    """This device's schema, read from the LIVE database as the app owner (read only)."""
    columns = hacommon.live_json(work, app, target.db_container, target.db_user, target.database, SCHEMA_COLUMNS_SQL)
    if not isinstance(columns, list) or not columns or any(not isinstance(r, list) or len(r) != 6 for r in columns):
        raise BackupError('incompatible', '無法確認這台 Omnigent 的資料表結構。', app=app.id)
    signature = _signature(hacommon.live_json(work, app, target.db_container, target.db_user, target.database,
                                              SCHEMA_SIGNATURE_SQL))
    alembic = live_alembic(work, app, target)
    if alembic is None:
        raise BackupError('incompatible', '無法讀取這台 Omnigent 的資料庫結構版本。', app=app.id)
    return Schema(columns, signature, alembic)


def _by(rows, width):
    groups = {}
    for row in rows or []:
        if isinstance(row, list) and row:
            groups.setdefault(str(row[0]), []).append(tuple(row[1:width]))
    return groups


def schema_differences(ha, trusted):
    """The names (tables, sequences, types) whose DATA shape differs between HA and the trusted schema: the columns
    (name, type, not null, identity, generated; in order), the sequences (type, owning column) and the types.
    Defaults, constraints and indexes are never compared: HA's are never used, the trusted ones apply."""
    differ = set()
    ha_cols, trusted_cols = _by(ha.columns, 6), _by(trusted.columns, 6)
    differ |= {t for t in set(ha_cols) | set(trusted_cols) if ha_cols.get(t) != trusted_cols.get(t)}
    pick = lambda rows: {str(r[0]): (r[1], r[8]) for r in rows or [] if isinstance(r, list) and len(r) == 9}  # noqa: E731
    ha_seq, trusted_seq = pick(ha.signature.get('sequences')), pick(trusted.signature.get('sequences'))
    differ |= {s for s in set(ha_seq) | set(trusted_seq) if ha_seq.get(s) != trusted_seq.get(s)}
    ha_types, trusted_types = _by(ha.signature.get('types'), 6), _by(trusted.signature.get('types'), 6)
    differ |= {t for t in set(ha_types) | set(trusted_types) if ha_types.get(t) != trusted_types.get(t)}
    return sorted(differ)


def schema_blocker(differ):
    return (f'HA 與這台 Omnigent 的資料庫結構不同（{hacommon.names(differ)}）：只能搬到資料表與欄位完全相同的 Omnigent，'
            '請先讓兩邊的 Omnigent 版本一致後再匯入。')


def trusted_schema(work, app, target, path, alembic):
    """This device's schema as the new cluster gets it: `path` is its `pg_dump --schema-only` taken in one exported
    snapshot; the live schema (signature, columns, alembic) before and after the capture and the snapshot's columns
    must all be equal -- no DDL ran meanwhile (enforced here, not promised by a caller)."""
    before = live_schema(work, app, target)
    if before.alembic != sorted(alembic or []):
        raise BackupError('incompatible', SCHEMA_CHANGED, app=app.id)
    columns = capture_consistent_target_schema(work, app, target, path, alembic)
    after = live_schema(work, app, target)
    if columns != before.columns or after != before:
        path.unlink(missing_ok=True)
        raise BackupError('incompatible', SCHEMA_CHANGED, app=app.id)
    return before


def require_schema(cluster, trusted, stage):
    """The new cluster's schema signature equals the trusted one (after the post-data section, after the last write)."""
    found = schema_signature(cluster)
    differ = [key for key in SIGNATURE_KEYS if found.get(key) != trusted.signature.get(key)]
    if differ:
        raise BackupError('job-failed', f'新的 PostgreSQL 叢集的資料庫結構和這台 Omnigent 的不同（{"、".join(differ)}），'
                                        '已停止，這台的應用沒有任何變更。', stage=stage)


HA_ANSWERS_DIFFER = ('這份 HA 備份的 Omnigent 資料庫回報的內容和它實際的資料不一致（備份可能被竄改過），已停止，'
                     '這台的應用沒有任何變更。')


def _answers(detail, keys, counts):
    """HA's (or the new cluster's) answers in a comparable form: lists as sorted sets (json_agg order follows the
    collation, which differs between HA's cluster and this device's), numbers as numbers."""
    def norm(value):
        if isinstance(value, list):
            return sorted(json.dumps(v, sort_keys=True) for v in value)
        return value
    detail = detail if isinstance(detail, dict) else {}
    keys = keys if isinstance(keys, dict) else {}
    return ({k: norm(v) for k, v in detail.items()}, {k: norm(v) for k, v in keys.items()},
            {k: ha_odoo._int(v) for k, v in (counts or {}).items()})


def require_answers(cluster, found):
    """secreview SR-1: what the check and this conversion SHOW and VALIDATE (accounts and their conflicts, active
    schedules, public shares, external credentials, the artifact keys, the counts) was answered by HA's cluster,
    which a crafted backup controls (its catalog, its own per-role search_path). The new cluster holds exactly HA's
    data on THIS device's schema and server (nothing of this device's added yet): it must answer the same, else the
    job stops before anything is exported."""
    tables = sorted(KNOWN_TABLES | set(found['counts']))
    now = _answers(cluster.query_json(DETAIL_SQL, DATABASE), cluster.query_json(KEYS_SQL, DATABASE),
                   table_counts(cluster, tables))
    ha = _answers(found['detail'], found['keys'], {t: found['counts'].get(t) for t in tables})
    differ = []
    for part, a, b in zip(('detail', 'keys', 'counts'), ha, now):
        for name in sorted(set(a) | set(b)):
            if a.get(name) != b.get(name):
                # counts name the table and both numbers; the other answers only their name (never a value)
                differ.append(f'{name}（HA {a.get(name)}，實際 {b.get(name)}）' if part == 'counts' else name)
    if differ:
        raise BackupError('incompatible', f'{HA_ANSWERS_DIFFER}不一致的項目：{"、".join(differ[:10])}。',
                          stage='answers')


def audit_new_cluster(cluster, superuser):
    """Nothing but the schema and the data: one role (the app's), no setting, no large object."""
    found = cluster.query_json(AUDIT_SQL, DATABASE)
    if not isinstance(found, dict):
        raise BackupError('job-failed', '無法檢查新的 PostgreSQL 叢集。')
    problems = []
    if found.get('roles') != [superuser]:
        problems.append('多出的資料庫角色')
    for key, label in (('role_settings', '角色或資料庫設定'), ('auto_conf', 'ALTER SYSTEM 設定'),
                       ('large_objects', '大型物件')):
        if found.get(key) != 0:
            problems.append(label)
    if problems:
        raise BackupError('job-failed', f'新的 PostgreSQL 叢集含有不應存在的內容（{"、".join(problems)}），已停止，'
                                        '這台的應用沒有任何變更。')


def require_registered_secrets(work, app):
    """Every target Quadlet secret must be carried by the real import adapter.

    This registers names, not values; cookie/artifact and pi credentials are carried
    inside their volumes. Never read credentials merely to enumerate dependencies.
    """
    declared = [item['name'] for item in app.secrets]
    referenced = {spec.split(',', 1)[0] for text in work.quadlets(app).values()
                  for spec in tempctr.quadlet_secrets(text)}
    if len(declared) != len(set(declared)) or not referenced <= set(declared):
        raise BackupError('incompatible', 'Omnigent 的 Quadlet 機密未完整登記於應用設定，無法建立可回復候選。',
                          app=app.id)


def convert(work, app, test_mode, out_dir):
    """Build the app's volumes in `out_dir/volumes` (module docstring: the trusted schema, HA's data only); returns
    {volumes {name: path}, counts, kept_accounts, conflicts, paused_tasks, ...}."""
    require_registered_secrets(work, app)
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
    ha_schema = read_schema(cluster, found['alembic'])
    dump = staging / 'omnigent.dump'
    work.log('匯出 HA 的 Omnigent 資料（只當作資料來源，HA 的資料庫結構不會使用）')
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
    tmp.run('omni-db', target.db_image, [], detach=True,
            volumes=[(tmp.name('omni-db'), target.db_target, 'rw,noexec,nosuid,nodev')],
            env=target.db_env, secrets=target.db_secrets, read_only_root=True)
    pg = ha_odoo.Cluster(tmp, 'omni-db', superuser=target.db_user, log=work.log)
    pg.wait_ready(tcp=True, checkpoint=work.checkpoint)
    schema_dump = staging / 'target-schema.dump'
    work.log('讀取這台 Omnigent 自己的資料庫結構（同一個快照；前後比對確認期間沒有結構變更）')
    trusted = trusted_schema(work, app, target, schema_dump, alembic)
    differ = schema_differences(ha_schema, trusted)
    if differ:
        raise BackupError('incompatible', f'Omnigent 不能搬過來：{schema_blocker(differ)}', app=app.id)
    work.log('用這台的資料庫結構建立資料表，只把 HA 的資料（資料列與序號）以沒有任何管理權限的暫用角色載入')
    restore_trusted_data(work, tmp, schema_dump, dump, target.db_user, source_columns=ha_schema.columns,
                         tables=trusted.tables(), sequences=trusted.sequences())
    os.unlink(dump)
    os.unlink(schema_dump)
    require_schema(pg, trusted, 'restored')
    require_answers(pg, found)
    kept = carry_accounts_restricted(pg, live_users(work, app, target))
    conflicts = account_conflicts(found, target)
    paused = 0
    if test_mode:
        paused = ha_odoo._int(pg.query_json(ACTIVE_SQL, DATABASE))
        work.log(f'測試匯入：暫停 {paused} 個啟用中的 Omnigent 排程')
        ha_odoo.Cluster(tmp, 'omni-db', superuser=RESTORE_ROLE, log=work.log).script(PAUSE_SQL, DATABASE)
        if ha_odoo._int(pg.query_json(ACTIVE_SQL, DATABASE)):
            raise BackupError('job-failed', '測試匯入沒有暫停全部 Omnigent 排程。')
    finish_trusted_data(pg)
    require_schema(pg, trusted, 'loaded')
    audit_new_cluster(pg, target.db_user)
    counts = table_counts(pg, found['tables'])
    expected = dict(found['counts'], users=found['counts'].get('users', 0) + len(kept))
    differ = [f'{t}（HA {n}，匯入後 {counts.get(t)}）' for t, n in sorted(expected.items()) if counts.get(t) != n]
    now_alembic = pg.query_json(ALEMBIC_SQL, DATABASE)
    if differ or sorted(now_alembic or []) != sorted(found['alembic']):
        raise BackupError('job-failed', f'Omnigent 匯入後的資料和 HA 不同，已停止：{"、".join(differ[:10]) or "結構版本"}。')
    work.log(f'Omnigent 資料匯入完成：{len(expected)} 個資料表的筆數都和 HA 相同，資料庫結構和這台的相同'
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


def _convert_candidate(work, app, test_mode, out_dir, *, schema_ddl_quiesced):
    """Lab compatibility entry of the 2026-11-20..23 internal-candidate harnesses: the product conversion (`convert`
    enforces the capture's stability itself; the flag is still required so those callers keep their contract)."""
    if schema_ddl_quiesced is not True:
        raise BackupError('incompatible', '目標資料庫結構變更未暫停，無法擷取安全快照。', app=app.id)
    return convert(work, app, test_mode, out_dir)


def server_volume(work, app, target, staging, out_dir):
    """omnigent-server-data: the live export without `artifacts/**`, plus HA's artifacts owned like the live
    artifacts folder (or the volume's top folder)."""
    import tarfile
    live = hacommon.live_export(work, app, target.server_volume, staging / 'live-server.tar')
    path = out_dir / 'volumes' / f'{target.server_volume}.tar'
    root = ha_n8n.volume_root(work, app, target.server_volume)
    out = hacommon.FileTar(path, work.guard)
    try:
        hacommon.top_only(out, root)
        dirs = hacommon.copy_live(live, out, drop=lambda name: name == '.' or ha_odoo._under(name, 'artifacts'),
                                  what='這台 Omnigent 的伺服器資料卷')
        # Podman exports may omit the root directory. Preserve its actual
        # namespace metadata through the existing bounded owner interface.
        if '.' in dirs and dirs['.'] != root:
            raise BackupError('job-failed', '這台 Omnigent 伺服器資料卷的根目錄權限已改變。', app=app.id)
        uid, gid, _mode = dirs.get('artifacts') or root
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
             '這台目前登入的瀏覽器與裝置需要重新登入。',
             'Omnigent 只搬 HA 的資料：資料庫結構（資料表、欄位、預設值、檢查與索引）用這台 Omnigent 自己的，'
             'HA 備份裡的資料庫結構不會執行。']
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
