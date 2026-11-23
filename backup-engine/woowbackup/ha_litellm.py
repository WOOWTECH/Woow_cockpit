"""Home Assistant import, LiteLLM part: the WOOWTECH add-on `woow-litellm` -> this device's app `litellm` (CONTRACT
section 9 "Home Assistant import"; facts phase3/facts/litellm.md; lab proof tests/e2e/lab/litellm_real_ha.py, 24/24 on
the owner-made real backup 2026-11-23). Owner: E2.

The add-on keeps an embedded PostgreSQL 18 cluster (`data/postgres`, database `litellm`: LiteLLM's Prisma tables in
`public`, the WOOWTECH platform tables in `woow_platform`, HA's own bookkeeping in `woow`) and the key that encrypts
every stored provider credential, `data/secrets/salt_key` (also stored in `woow_platform.settings` and as a
fingerprint in `woow.meta`). The target is the Podman package: `litellm-postgres` (PostgreSQL 17, one database
`litellm` whose owner is the image's bootstrap superuser `litellm`, a logical dump in every backup: catalog item
`postgres` main) and `litellm` (the proxy), with five Podman secrets.

Versions: the add-on version maps to a LiteLLM version (VERSIONS) that must equal the live proxy's (read in the
running container: `importlib.metadata`), HA's `data/woow/state.json` must say the same, and HA's finished Prisma
migrations must be exactly the live database's. HA's PostgreSQL is 18, this device's 17: only this importer moves
data DOWN a major, and only as plain rows (below), never as HA's dump or HA's DDL.

check: HA's cluster is streamed into a throwaway volume (its configuration and recovery files replaced or dropped,
ha_odoo.PgSink; a symlink in it -- a tablespace -- refuses, and so do backup_label and tablespace_map, which a cold
backup never has: tablespace_map would make the server create tablespace links itself, review SR-4) and opened by a
throwaway PostgreSQL 18 of the official image pinned by content (PG18_IDS; pulled by digest when the device has none)
as hardened as Odoo's (socket only, network none, read-only root, noexec data volume, every library/command setting
of the configuration files overridden, event triggers off). Per-database and per-role settings stored in HA's catalog
beat the command line, so every session the engine opens there also sends its own settings as client options, which
beat them (HA_SESSION_OPTIONS: names resolve in pg_catalog only -- a function or aggregate HA's database owner put in
`public` never runs as the superuser, review SR-1 --, the rows are exported in fixed formats like pg_dump's -- an
`ALTER DATABASE ... SET DateStyle` cannot turn 5 November into 11 May, SR-2 --, and the superuser's sessions fire no
event trigger, SR-3). A crafted data directory can still run its own SQL as the superuser inside that sandbox (it can
redirect built-in operators and types); what it answers is only ever HA's data. The salt file must be
HA's format and must be the salt the database is bound to (woow_platform.settings and the woow.meta fingerprint, read
by a role without privileges; ha_litellm_candidate.read_source_salt_binding): else nothing can decrypt the stored
credentials and the import refuses. HA's database may hold only `public`, `woow_platform` and `woow` (with `meta`
only), nothing only a superuser creates, UTF8; HA's data shape (tables, columns, sequences, types of both moved
schemas) must equal this device's live database (else a blocker naming the tables).

convert (the trust rules of the Omnigent import, B1-01: HA's backup never provides DDL): a NEW cluster from the live
`litellm-postgres` image, environment and secret mount (bootstrap superuser `litellm` with this device's password)
gets THIS device's schema: `pg_dump --schema-only` of the live database inside one exported snapshot, its pre-data
section restored, then only HA's ROWS: every table of the trusted schema copied table by table (`COPY <trusted
schema.table> (<trusted columns>) TO STDOUT` in HA's cluster, `COPY ... FROM STDIN` in the new one: the statements are
built from this device's names only, the text format is the same in both majors) by a role that may only INSERT and
set sequence values (`woowbk_restore`), every sequence value set by it, then the post-data section (constraints,
indexes, triggers: HA's rows must satisfy this device's constraints). The product proves what the lab proved instead
of trusting a caller: the live schema signature and migrations before == after the capture == the snapshot's columns
(no DDL meanwhile, else the job stops); the new cluster's signature equals the live one after the post-data section
and after the last write; it holds no other role, setting or large object; every table's row count and the
migrations equal HA's; the salt row it got from HA equals the salt that moves. HA's `woow` schema, its two hand-built
spend-log indexes, its comments, its configuration and its other secret files never move. Its dump (`pg_dump -Fc`,
PostgreSQL 17) is the backup's `postgres/main.dump`, read in full once.

Keys: HA's salt replaces this device's secret `litellm-salt-key` in the converted backup (adapter.import_manifest
`secrets`): without it the proxy refuses to start (db_prepare) and nothing stored decrypts. This device keeps its
master key, UI password, database password and URL, config.yaml, litellm.env and Quadlet files (read live like every
backup). The restore's safety backup holds the old salt and database, so a failed or undone import puts both back.
This device's virtual keys are replaced by HA's: the check and the conversion name this device's other apps whose
configuration uses LiteLLM today (key_users: catalog config files and Quadlet files, LiteLLM's own network drop-ins,
the Pi agent provider list models.json of pi-web / Omnigent's runner),
whose keys stop working after the import (owner decision 2026-11-23, option A: a reminder, nothing else changes).
"""
import hashlib
import json
import os
import re
import shutil

from . import habackup, hacommon, ha_litellm_candidate as candidate, ha_odoo, tempctr
from .errors import BackupError

SLUG = 'woow-litellm'
APP_ID = 'litellm'
DATABASE = 'litellm'
PG_PREFIX = 'data/postgres'
SALT_FILE = 'data/secrets/salt_key'
STATE_FILE = 'data/woow/state.json'
SALT_SECRET = 'litellm-salt-key'
SALT_ENV = 'LITELLM_SALT_KEY'
APP_CONTAINER = 'litellm'
# The add-on versions whose LiteLLM and PostgreSQL were verified (HA build-info.json / CHANGELOG; facts section 3).
VERSIONS = hacommon.VersionTable('LiteLLM', {'0.1.15': '1.104.0'})
HA_PG_MAJOR = 18
SCHEMAS = ('public', 'woow_platform')           # moved: data only
HA_ONLY = {'woow': ('meta',)}                   # HA's bookkeeping (salt fingerprint): never moved
RESTORE_ROLE = 'woowbk_restore'
READER_ROLE = 'woowbk_litellm_reader'
DASHBOARD_TEAM = 'litellm-dashboard'            # the UI's session keys: deleted by the proxy at the first start
IDENT_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,62}\Z')
# Prisma migration folder names; one of LiteLLM 1.104.0's has spaces (litellm-proxy-extras 0.4.102.post1:
# litellm_proxy_extras/migrations/20251122125322_Add organization_id to spend logs/migration.sql).
MIGRATION_RE = re.compile(r'[0-9A-Za-z_. -]{1,200}\Z')
VERSION_RE = re.compile(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\Z')
SALT_RE = re.compile(rb'[A-Za-z0-9_-]{16,256}\Z')   # HA woow_init.py SECRET_VALUE_RE (read_secret strips)
MAX_SALT_FILE = 1024
MAX_TABLES = 400
DUMP_TIMEOUT = ha_odoo.DUMP_TIMEOUT
# The official PostgreSQL 18.7 alpine image by content: Docker Hub index sha256:ff64c9e3... (registry-1.docker.io,
# checked 2026-11-23) has these linux/amd64 and linux/arm64 config digests = the image IDs Podman shows. A device
# copy of exactly one of them is used; else the index is pulled by digest and the result must be one of them.
PG18_PINNED = 'docker.io/library/postgres@sha256:ff64c9e3bdf8e2120107d3559de8db314e8305f7e38c5105903c6295876738ff'
PG18_IDS = ('sha256:4ea77c7055dec6a632156aa2cd9f1abaaedeba5f812f104f4e9e1ac37363469b',
            'sha256:d4e55489302f9c75af116f3b3147f613e712f07e5eb8dabec82d9147dd0a00e5')
HA_PGDATA = '/var/lib/postgresql'               # the PG 18 image's VOLUME: mounted there, no anonymous volume
# Files of an online (hot) backup: a cold HA backup never has them; tablespace_map makes the server create tablespace
# links at its start (review SR-4). Never streamed into the volume; their presence refuses the import.
RECOVERY_FILES = ('backup_label', 'tablespace_map')
# Client options of every session the engine opens in HA's cluster (libpq PGOPTIONS): they beat HA's per-database and
# per-role settings (PostgreSQL GucSource: PGC_S_CLIENT > PGC_S_DATABASE_USER > PGC_S_ARGV). Names resolve in
# pg_catalog only (SR-1); the text COPY and json write is fixed like pg_dump's setup_connection (SR-2). Only
# settings any role may set: the salt reader (no privileges) gets them too.
HA_SESSION_OPTIONS = ('-c search_path=pg_catalog -c DateStyle=ISO,MDY -c IntervalStyle=postgres '
                      '-c extra_float_digits=3 -c client_encoding=UTF8 -c bytea_output=hex -c TimeZone=UTC '
                      '-c standard_conforming_strings=on -c local_preload_libraries=')
# The superuser's sessions also load no library HA's catalog names for them and fire no event trigger (PostgreSQL 17+
# `event_triggers`; SR-3: a login trigger would run at the engine's first connection, a ddl_command_end one at the
# salt reader's GRANT). Superuser-only settings: a role without privileges could not log in with them.
HA_SUPERUSER_OPTIONS = HA_SESSION_OPTIONS + ' -c session_preload_libraries= -c event_triggers=off'
SCHEMA_CHANGED = ('這台 LiteLLM 的資料庫結構在轉換期間改變了（可能正在升級或重新啟動），沒有匯入任何資料；'
                  '請等 LiteLLM 正常執行後再匯入一次。')
SALT_MISMATCH = ('HA 備份裡的加密金鑰（salt_key）和 HA 資料庫裡記錄的金鑰不一致，搬過來後儲存的供應商憑證都無法解密，'
                 '所以不能匯入；請在 HA 重新做一份 LiteLLM 的備份。')


# ====================================================================== HA's member

class Source:
    """What one pass over the add-on's member learned: the cluster (`pg_version`, files, bytes), the salt (private:
    no repr, never logged; `salt_valid`), state.json's `litellm_version`, symlinks the cluster had (refused)."""

    __slots__ = ('addon', 'pg_version', 'pg_files', 'pg_bytes', '_salt', 'salt_valid', 'state_version', 'symlinks',
                 'recovery_files')

    def __init__(self):
        self.addon = None
        self.pg_version = None
        self.pg_files = self.pg_bytes = 0
        self._salt = None
        self.salt_valid = False
        self.state_version = None
        self.symlinks = 0
        self.recovery_files = 0

    def __repr__(self):
        return f'<Source pg={self.pg_version} files={self.pg_files} salt_valid={self.salt_valid}>'

    def salt(self):
        return self._salt


def scan_member(stream, report, *, pg=None, checkpoint=None):
    """One strict pass over the add-on member (habackup.iter_entries: no hard link, no symlink handed out): every
    `data/postgres` entry to `pg` (a PgSink; None = only counted), the salt file (one small regular file, HA's
    format), state.json's version. Nothing else of the member is read (options.json, the master key, the UI and
    database passwords, HA's pre-upgrade dumps never are)."""
    select = habackup.Select(include=(PG_PREFIX, SALT_FILE, STATE_FILE), symlinks=(), hardlinks=False)
    src = Source()
    salts = 0
    for entry in habackup.iter_entries(stream, select, report, addon=True, checkpoint=checkpoint):
        name = entry.name
        if ha_odoo._under(name, PG_PREFIX):
            rel = name[len(PG_PREFIX) + 1:] if name != PG_PREFIX else '.'
            if rel.split('/', 1)[0] in RECOVERY_FILES:
                src.recovery_files += 1  # never reaches the volume (SR-4); the verdict refuses
                continue
            data = None
            if entry.kind == 'file':
                src.pg_files += 1
                src.pg_bytes += entry.size
                if rel == 'PG_VERSION':
                    data = entry.read_all(64)
                    text = data.decode('ascii', 'replace').strip()
                    src.pg_version = text if re.fullmatch(r'[1-9][0-9]?', text) else None
            if pg is not None:
                pg.add(rel, entry, data)
            continue
        if name == SALT_FILE:
            salts += 1
            if entry.kind != 'file' or entry.size > MAX_SALT_FILE or salts > 1:
                raise BackupError('incompatible', 'LiteLLM 附加元件的加密金鑰檔格式不正確，無法匯入。')
            value = entry.read_all(MAX_SALT_FILE).strip()
            src.salt_valid = bool(SALT_RE.fullmatch(value))
            src._salt = value if src.salt_valid else None
        elif name == STATE_FILE and entry.kind == 'file' and entry.size <= 65536:
            state = hacommon.strict_json(entry.read_all(65536), 65536)
            value = state.get('litellm_version') if isinstance(state, dict) else None
            src.state_version = value if isinstance(value, str) and VERSION_RE.fullmatch(value) else None
    src.addon = report.addon
    src.symlinks = report.skipped_symlinks
    if src.addon is None or src.addon.slug != SLUG:
        raise BackupError('incompatible', '備份不是可辨識的 LiteLLM 附加元件。')
    return src


# ====================================================================== this device's app

class Target:
    """The litellm app's catalog items the import fills, resolved against the live Quadlet files: the catalog's one
    database item (the container, database and user of litellm-postgres), the proxy's container and the salt secret
    it reads as LITELLM_SALT_KEY."""

    def __init__(self, work, app):
        quadlets = work.quadlets(app)
        home = work.runner(app).home
        problems = []
        if len(app.postgres) != 1 or app.volumes or app.data_dirs:
            problems.append('應用設定不是一個資料庫匯出項目（沒有資料卷或主機資料夾）')
        pg = app.postgres[0] if len(app.postgres) == 1 else {}
        self.pg_id = pg.get('id')
        self.db_container = pg.get('container')
        self.database = pg.get('database')
        self.db_user = pg.get('user')
        db_file = hacommon.container_file(quadlets, self.db_container) if self.db_container else None
        app_file = hacommon.container_file(quadlets, APP_CONTAINER)
        if db_file is None or app_file is None:
            problems.append('找不到 litellm-postgres 或 litellm 的 Quadlet 檔')
        if problems:
            raise BackupError('incompatible', f'這台的 LiteLLM 應用設定不是 HA 匯入支援的樣子：{"；".join(problems)}。',
                              app=app.id)
        text = quadlets[db_file]
        self.db_image = tempctr.quadlet_image(text)
        self.db_env = hacommon.environment(quadlets, db_file, ha_odoo.DB_ENV_KEYS)
        self.db_secrets = tempctr.quadlet_secrets(text)
        mounts = ha_odoo.quadlet_mounts(quadlets, db_file, home)
        self.db_volume, self.db_target = (mounts[0][0], mounts[0][1]) if mounts else (None, None)
        self.pgdata = self.db_env.get('PGDATA') or self.db_target
        self.app_image = tempctr.quadlet_image(quadlets[app_file])
        salt_specs = [spec for spec in tempctr.quadlet_secrets(quadlets[app_file])
                      if spec.split(',', 1)[0] == SALT_SECRET]
        declared = [item['name'] for item in app.secrets]
        if (self.database != DATABASE or self.db_env.get('POSTGRES_DB', self.db_user) != DATABASE
                or self.db_env.get('POSTGRES_USER', 'postgres') != self.db_user
                or not isinstance(self.db_user, str) or not IDENT_RE.fullmatch(self.db_user)
                or not self.db_image or not self.app_image or self.db_volume != pg.get('data_volume')
                or not self.pgdata or not tempctr.TARGET_RE.fullmatch(self.pgdata)
                or len(salt_specs) != 1 or f'target={SALT_ENV}' not in salt_specs[0].split(',')[1:]
                or SALT_SECRET not in declared or len(declared) != len(set(declared))):
            raise BackupError('incompatible', '這台的 LiteLLM 資料庫、加密金鑰（litellm-salt-key）和 Quadlet 檔的設定不一致，'
                                              '無法匯入。', app=app.id)


VERSION_PROBE = ('import importlib.metadata as m, sys; '
                 'sys.stdout.write(m.version("litellm"))')


def target_version(work, app):
    """The running proxy's LiteLLM version (`podman exec litellm python -I -c ...`: read only), else None."""
    result = work.runner(app).podman('exec', APP_CONTAINER, 'python', '-I', '-c', VERSION_PROBE, timeout=120,
                                     max_output=4096, check=False)
    text = (result.stdout or b'').decode('ascii', 'replace').strip()
    return text if result.returncode == 0 and VERSION_RE.fullmatch(text) else None


MIGRATIONS_SQL = ('SELECT coalesce(json_agg(migration_name ORDER BY migration_name COLLATE "C"), \'[]\'::json) '
                  'FROM public."_prisma_migrations" WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL')


# HA's migrations are read only from an ordinary table: a view (or anything else) there could run HA's code as the
# superuser at the read (review SR-1).
MIGRATIONS_TABLE_SQL = ("SELECT to_json(coalesce((SELECT c.relkind = 'r' FROM pg_catalog.pg_class c "
                        "WHERE c.oid = pg_catalog.to_regclass('public._prisma_migrations')), false))")


def _migrations(value):
    if not isinstance(value, list) or not value or len(value) > 2000 \
            or any(not isinstance(v, str) or not MIGRATION_RE.fullmatch(v) for v in value):
        return None
    return sorted(value)


def live_migrations(work, app, target):
    return _migrations(hacommon.live_json(work, app, target.db_container, target.db_user, target.database,
                                          MIGRATIONS_SQL))


# ====================================================================== the schema of the moved schemas

def _own(catalog, alias='o', column='oid'):
    return (f"NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend x WHERE x.classid = 'pg_catalog.{catalog}'::regclass "
            f"AND x.objid = {alias}.{column} AND x.deptype = 'e')")


IN_SCHEMAS = "n.nspname IN ('public', 'woow_platform')"
# Physical data columns, in order (schema, table, column, type, not null, identity, generated).
COLUMNS_SQL = ("SELECT coalesce(json_agg(json_build_array(n.nspname, c.relname, a.attname, "
               "pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnotnull, a.attidentity::text, a.attgenerated::text) "
               "ORDER BY n.nspname, c.relname, a.attnum), '[]'::json) FROM pg_catalog.pg_attribute a "
               "JOIN pg_catalog.pg_class c ON c.oid = a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
               f"WHERE {IN_SCHEMAS} AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped")
OTHER_CATALOGS = ('pg_cast', 'pg_operator', 'pg_opclass', 'pg_opfamily', 'pg_collation', 'pg_conversion',
                  'pg_ts_config', 'pg_ts_dict', 'pg_ts_parser', 'pg_ts_template', 'pg_foreign_data_wrapper',
                  'pg_foreign_server', 'pg_publication', 'pg_statistic_ext', 'pg_transform', 'pg_language', 'pg_am',
                  'pg_event_trigger')
SIGNATURE_PARTS = (
    ('relations', "SELECT coalesce(json_agg(json_build_array(n.nspname, o.relname, o.relkind::text, "
                  "o.relpersistence::text, o.relrowsecurity, o.relforcerowsecurity, "
                  "coalesce(array_to_string(o.reloptions, ','), ''), o.relispartition) ORDER BY n.nspname, o.relname), "
                  "'[]'::json) FROM pg_catalog.pg_class o JOIN pg_catalog.pg_namespace n ON n.oid = o.relnamespace "
                  f"WHERE {IN_SCHEMAS} AND o.relkind IN ('r', 'p', 'v', 'm', 'S', 'f', 'c') AND " + _own('pg_class')),
    ('columns', "SELECT coalesce(json_agg(json_build_array(n.nspname, o.relname, a.attname, "
                "pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnotnull, a.attidentity::text, "
                "a.attgenerated::text, coalesce(pg_catalog.pg_get_expr(d.adbin, d.adrelid), ''), "
                "CASE WHEN a.attcollation <> t.typcollation THEN coalesce(l.collname, '?') ELSE '' END) "
                "ORDER BY n.nspname, o.relname, a.attnum), '[]'::json) FROM pg_catalog.pg_attribute a "
                "JOIN pg_catalog.pg_class o ON o.oid = a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid = o.relnamespace "
                "JOIN pg_catalog.pg_type t ON t.oid = a.atttypid "
                "LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum "
                "LEFT JOIN pg_catalog.pg_collation l ON l.oid = a.attcollation "
                f"WHERE {IN_SCHEMAS} AND o.relkind IN ('r', 'p', 'v', 'm', 'f', 'c') AND a.attnum > 0 "
                "AND NOT a.attisdropped AND " + _own('pg_class')),
    ('constraints', "SELECT coalesce(json_agg(json_build_array(n.nspname, coalesce(c.relname, t.typname, ''), o.conname, "
                    "o.contype::text, pg_catalog.pg_get_constraintdef(o.oid), o.condeferrable, o.condeferred, "
                    "o.convalidated, o.connoinherit) ORDER BY n.nspname, coalesce(c.relname, t.typname, ''), o.conname), "
                    "'[]'::json) FROM pg_catalog.pg_constraint o JOIN pg_catalog.pg_namespace n ON n.oid = o.connamespace "
                    "LEFT JOIN pg_catalog.pg_class c ON c.oid = o.conrelid LEFT JOIN pg_catalog.pg_type t "
                    f"ON t.oid = o.contypid WHERE {IN_SCHEMAS}"),
    ('indexes', "SELECT coalesce(json_agg(json_build_array(n.nspname, c.relname, i.relname, "
                "pg_catalog.pg_get_indexdef(o.indexrelid)) ORDER BY n.nspname, c.relname, i.relname), '[]'::json) "
                "FROM pg_catalog.pg_index o JOIN pg_catalog.pg_class i ON i.oid = o.indexrelid "
                "JOIN pg_catalog.pg_class c ON c.oid = o.indrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                f"WHERE {IN_SCHEMAS}"),
    ('sequences', "SELECT coalesce(json_agg(json_build_array(n.nspname, o.relname, pg_catalog.format_type(s.seqtypid, NULL), "
                  "s.seqstart, s.seqincrement, s.seqmax, s.seqmin, s.seqcache, s.seqcycle, "
                  "coalesce((SELECT r.relname || '.' || a.attname FROM pg_catalog.pg_depend d "
                  "JOIN pg_catalog.pg_class r ON r.oid = d.refobjid JOIN pg_catalog.pg_attribute a "
                  "ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid "
                  "WHERE d.classid = 'pg_catalog.pg_class'::regclass AND d.objid = o.oid "
                  "AND d.refclassid = 'pg_catalog.pg_class'::regclass AND d.deptype IN ('a', 'i') "
                  "ORDER BY 1 LIMIT 1), '')) ORDER BY n.nspname, o.relname), '[]'::json) FROM pg_catalog.pg_sequence s "
                  "JOIN pg_catalog.pg_class o ON o.oid = s.seqrelid JOIN pg_catalog.pg_namespace n ON n.oid = o.relnamespace "
                  f"WHERE {IN_SCHEMAS}"),
    ('types', "SELECT coalesce(json_agg(json_build_array(n.nspname, o.typname, o.typtype::text, "
              "CASE WHEN o.typbasetype <> 0 THEN pg_catalog.format_type(o.typbasetype, o.typtypmod) ELSE '' END, "
              "o.typnotnull, coalesce(pg_catalog.pg_get_expr(o.typdefaultbin, 0), ''), "
              "(SELECT coalesce(json_agg(e.enumlabel ORDER BY e.enumsortorder), '[]'::json) FROM pg_catalog.pg_enum e "
              "WHERE e.enumtypid = o.oid)) ORDER BY n.nspname, o.typname), '[]'::json) FROM pg_catalog.pg_type o "
              "JOIN pg_catalog.pg_namespace n ON n.oid = o.typnamespace LEFT JOIN pg_catalog.pg_class r ON r.oid = o.typrelid "
              f"WHERE {IN_SCHEMAS} AND o.typcategory <> 'A' AND (o.typrelid = 0 OR r.relkind = 'c') AND "
              + _own('pg_type')),
    ('functions', "SELECT coalesce(json_agg(n.nspname || '.' || o.proname || '(' "
                  "|| pg_catalog.pg_get_function_identity_arguments(o.oid) || ')' || o.prokind::text "
                  "ORDER BY n.nspname, o.proname, pg_catalog.pg_get_function_identity_arguments(o.oid)), '[]'::json) "
                  "FROM pg_catalog.pg_proc o JOIN pg_catalog.pg_namespace n ON n.oid = o.pronamespace "
                  "WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND " + _own('pg_proc')),
    ('triggers', "SELECT coalesce(json_agg(json_build_array(n.nspname, c.relname, o.tgname, pg_catalog.pg_get_triggerdef(o.oid)) "
                 "ORDER BY n.nspname, c.relname, o.tgname), '[]'::json) FROM pg_catalog.pg_trigger o "
                 "JOIN pg_catalog.pg_class c ON c.oid = o.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                 "WHERE NOT o.tgisinternal"),
    ('rules', "SELECT coalesce(json_agg(json_build_array(n.nspname, c.relname, o.rulename, pg_catalog.pg_get_ruledef(o.oid)) "
              "ORDER BY n.nspname, c.relname, o.rulename), '[]'::json) FROM pg_catalog.pg_rewrite o "
              "JOIN pg_catalog.pg_class c ON c.oid = o.ev_class JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
              "WHERE o.rulename <> '_RETURN' AND n.nspname NOT IN ('pg_catalog', 'information_schema')"),
    ('views', "SELECT coalesce(json_agg(json_build_array(n.nspname, o.relname, pg_catalog.pg_get_viewdef(o.oid)) "
              "ORDER BY n.nspname, o.relname), '[]'::json) FROM pg_catalog.pg_class o "
              "JOIN pg_catalog.pg_namespace n ON n.oid = o.relnamespace WHERE o.relkind IN ('v', 'm') "
              "AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND " + _own('pg_class')),
    ('policies', "SELECT coalesce(json_agg(json_build_array(n.nspname, c.relname, o.polname, o.polcmd::text, "
                 "o.polpermissive, coalesce(pg_catalog.pg_get_expr(o.polqual, o.polrelid), ''), "
                 "coalesce(pg_catalog.pg_get_expr(o.polwithcheck, o.polrelid), '')) ORDER BY n.nspname, c.relname, "
                 "o.polname), '[]'::json) FROM pg_catalog.pg_policy o JOIN pg_catalog.pg_class c ON c.oid = o.polrelid "
                 "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"),
    ('extensions', "SELECT coalesce(json_agg(json_build_array(o.extname, o.extversion, n.nspname) ORDER BY o.extname), "
                   "'[]'::json) FROM pg_catalog.pg_extension o JOIN pg_catalog.pg_namespace n ON n.oid = o.extnamespace"),
    ('schemas', "SELECT coalesce(json_agg(o.nspname ORDER BY o.nspname), '[]'::json) FROM pg_catalog.pg_namespace o "
                "WHERE o.nspname NOT IN ('public', 'information_schema') AND o.nspname !~ '^pg_'"),
    ('other', 'SELECT json_build_object(' + ', '.join(
        f"'{name}', (SELECT count(*) FROM pg_catalog.{name} o WHERE o.oid >= 16384 AND {_own(name)})"
        for name in OTHER_CATALOGS) + ')'),
)
SIGNATURE_SQL = 'SELECT json_build_object(' + ', '.join(f"'{key}', ({sql})" for key, sql in SIGNATURE_PARTS) + ')'
SIGNATURE_KEYS = tuple(key for key, _sql in SIGNATURE_PARTS)
# What the new cluster may hold besides the schema and HA's rows: only its bootstrap superuser, no role or database
# setting, no ALTER SYSTEM setting, no large object.
AUDIT_SQL = ("SELECT json_build_object("
             "'roles', (SELECT coalesce(json_agg(rolname ORDER BY rolname), '[]'::json) FROM pg_catalog.pg_roles "
             "WHERE rolname !~ '^pg_'), "
             "'role_settings', (SELECT count(*) FROM pg_catalog.pg_db_role_setting), "
             "'auto_conf', (SELECT count(*) FROM pg_catalog.pg_file_settings WHERE sourcefile ~ '/postgresql[.]auto[.]conf$'), "
             "'large_objects', (SELECT count(*) FROM pg_catalog.pg_largeobject_metadata))")


class Schema:
    """A database's data columns (COLUMNS_SQL), whole signature (SIGNATURE_SQL) and finished Prisma migrations."""

    def __init__(self, columns, signature, migrations):
        self.columns, self.signature, self.migrations = columns, signature, sorted(migrations or [])

    def __eq__(self, other):
        return isinstance(other, Schema) and (self.columns, self.signature, self.migrations) == (
            other.columns, other.signature, other.migrations)

    def tables(self):
        """[(schema, table)] of the ordinary tables, in order."""
        return sorted({(row[0], row[1]) for row in self.signature.get('relations') or [] if row[2] in ('r', 'p')})

    def sequences(self):
        return sorted({(row[0], row[1]) for row in self.signature.get('sequences') or []})

    def copy_columns(self, schema, table):
        """The columns a row copy names (not generated ones), in order."""
        return [row[2] for row in self.columns if row[0] == schema and row[1] == table and not row[6]]


def _columns(value, what):
    if (not isinstance(value, list) or not value or len(value) > 20000
            or any(not isinstance(row, list) or len(row) != 7 for row in value)):
        raise BackupError('incompatible', f'無法確認{what}的資料表結構。')
    return value


def _signature(value, what):
    if not isinstance(value, dict) or set(value) != set(SIGNATURE_KEYS):
        raise BackupError('incompatible', f'無法確認{what}的資料庫結構。')
    return value


def read_schema(cluster, migrations, what='HA 的 LiteLLM'):
    return Schema(_columns(cluster.query_json(COLUMNS_SQL, DATABASE), what),
                  _signature(cluster.query_json(SIGNATURE_SQL, DATABASE), what), migrations)


def live_schema(work, app, target):
    """This device's schema, read from the LIVE database as its owner (read only)."""
    what = '這台 LiteLLM'
    columns = _columns(hacommon.live_json(work, app, target.db_container, target.db_user, target.database,
                                          COLUMNS_SQL), what)
    signature = _signature(hacommon.live_json(work, app, target.db_container, target.db_user, target.database,
                                              SIGNATURE_SQL), what)
    migrations = live_migrations(work, app, target)
    if migrations is None:
        raise BackupError('incompatible', '無法讀取這台 LiteLLM 的資料庫結構版本（Prisma 遷移紀錄）。', app=app.id)
    return Schema(columns, signature, migrations)


def _by(rows, key_width, width):
    groups = {}
    for row in rows or []:
        if isinstance(row, list) and len(row) >= width:
            groups.setdefault('.'.join(str(v) for v in row[:key_width]), []).append(tuple(row[key_width:width]))
    return groups


def schema_differences(ha, trusted):
    """The names (schema.table, sequences, types) whose DATA shape differs between HA and the trusted schema: the
    columns (name, type, not null, identity, generated; in order), the sequences (type, owning column) and the types
    (kind, base, enum labels). Defaults, constraints and indexes are never compared: HA's are never used."""
    differ = set()
    ha_cols, trusted_cols = _by(ha.columns, 2, 7), _by(trusted.columns, 2, 7)
    differ |= {t for t in set(ha_cols) | set(trusted_cols) if ha_cols.get(t) != trusted_cols.get(t)}

    def seqs(schema):
        return {f'{r[0]}.{r[1]}': (r[2], r[9]) for r in schema.signature.get('sequences') or []
                if isinstance(r, list) and len(r) == 10}

    ha_seq, trusted_seq = seqs(ha), seqs(trusted)
    differ |= {s for s in set(ha_seq) | set(trusted_seq) if ha_seq.get(s) != trusted_seq.get(s)}

    def types(schema):
        return {f'{r[0]}.{r[1]}': (r[2], r[3], r[6]) for r in schema.signature.get('types') or []
                if isinstance(r, list) and len(r) == 7}

    ha_types, trusted_types = types(ha), types(trusted)
    differ |= {t for t in set(ha_types) | set(trusted_types) if ha_types.get(t) != trusted_types.get(t)}
    return sorted(differ)


def schema_blocker(differ):
    return (f'HA 與這台 LiteLLM 的資料庫結構不同（{hacommon.names(differ)}）：只能搬到資料表與欄位完全相同的 LiteLLM，'
            '請先讓兩邊的 LiteLLM 版本一致後再匯入。')


def require_names(schema, app=None):
    """Every moved table, column and sequence name is a plain identifier (the copy statements quote them)."""
    names = [n for pair in schema.tables() + schema.sequences() for n in pair]
    names += [row[2] for row in schema.columns]
    bad = [n for n in names if not isinstance(n, str) or not IDENT_RE.fullmatch(n)]
    if bad or len(schema.tables()) > MAX_TABLES or not schema.tables():
        raise BackupError('incompatible', f'LiteLLM 有 {len(bad)} 個資料表、欄位或序號的名稱不是這個匯入支援的格式'
                                          f'（{len(schema.tables())} 個資料表），沒有讀取任何資料就停止了。',
                          **({'app': app.id} if app is not None else {}))


def _q(schema, name):
    if not IDENT_RE.fullmatch(schema) or not IDENT_RE.fullmatch(name):
        raise BackupError('incompatible', 'LiteLLM 的資料表名稱不是這個匯入支援的格式，無法匯入。')
    return f'"{schema}"."{name}"'


def _cols(columns):
    if not columns or any(not IDENT_RE.fullmatch(c) for c in columns):
        raise BackupError('incompatible', 'LiteLLM 的資料表欄位名稱不是這個匯入支援的格式，無法匯入。')
    return ', '.join(f'"{c}"' for c in columns)


def copy_out_sql(schema, table, columns):
    return f'COPY {_q(schema, table)} ({_cols(columns)}) TO STDOUT'


def copy_in_sql(schema, table, columns):
    return f'COPY {_q(schema, table)} ({_cols(columns)}) FROM STDIN'


def counts_sql(tables):
    parts = ', '.join(f"'{s}.{t}', (SELECT count(*) FROM {_q(s, t)})" for s, t in tables)
    return f'SELECT json_build_object({parts})'


def table_counts(cluster, tables):
    found = {}
    for start in range(0, len(tables), 40):  # 2 arguments each; PostgreSQL allows 100
        doc = cluster.query_json(counts_sql(tables[start:start + 40]), DATABASE)
        if isinstance(doc, dict):
            found.update({k: ha_odoo._int(v) for k, v in doc.items()})
    return found


# ====================================================================== HA's database

OBJECTS_SQL = """SELECT json_build_object(
 'schemas', (SELECT coalesce(json_agg(nspname ORDER BY nspname), '[]'::json) FROM pg_catalog.pg_namespace
             WHERE nspname NOT IN ('public', 'information_schema') AND nspname !~ '^pg_'),
 'ha_only', (SELECT coalesce(json_agg(c.relname ORDER BY c.relname), '[]'::json) FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'woow' AND c.relkind NOT IN ('i', 'S')),
 'extensions', (SELECT coalesce(json_agg(extname ORDER BY extname), '[]'::json) FROM pg_catalog.pg_extension),
 'encoding', pg_catalog.pg_encoding_to_char((SELECT encoding FROM pg_catalog.pg_database WHERE datname = current_database())),
 'large_objects', (SELECT count(*) FROM pg_catalog.pg_largeobject_metadata))"""
DETAIL = (('users', 'public', 'LiteLLM_UserTable', ''), ('teams', 'public', 'LiteLLM_TeamTable', ''),
          ('keys', 'public', 'LiteLLM_VerificationToken',
           f" WHERE coalesce(\"team_id\", '') <> '{DASHBOARD_TEAM}'"),
          ('models', 'public', 'LiteLLM_ProxyModelTable', ''), ('credentials', 'public', 'LiteLLM_CredentialsTable', ''),
          ('organizations', 'public', 'LiteLLM_OrganizationTable', ''), ('spend_logs', 'public', 'LiteLLM_SpendLogs', ''),
          ('chatgpt_accounts', 'woow_platform', 'chatgpt_accounts', ''))


# HA's LiteLLM settings stored in its database (LiteLLM_Config): with `store_model_in_db: true` (the package's
# config.yaml) the proxy applies them at every start: `environment_variables` decrypted with the salt and put into its
# environment, `litellm_settings` callbacks loaded (litellm 1.104.0 litellm/proxy/proxy_server.py
# _update_config_from_db :7741-7793; only s3:// and gcs:// module URLs are refused, :4486-4513). So an import moves
# HA's proxy behaviour too (an HTTPS_PROXY or a logging callback would send this device's requests where HA's settings
# say). The check and the import name them (review SR-5): names only, never a value.
CONFIG_TABLE = ('public', 'LiteLLM_Config')
CALLBACK_KEYS = ('callbacks', 'success_callback', 'failure_callback', 'audit_log_callbacks')
_OBJECT = "CASE WHEN jsonb_typeof({v}) = 'object' THEN {v} ELSE '{{}}'::jsonb END"
STORED_SETTINGS_SQL = (
    "SELECT json_build_object("
    "'sections', (SELECT coalesce(json_agg(c.param_name ORDER BY c.param_name), '[]'::json) "
    "FROM public.\"LiteLLM_Config\" c), "
    "'env', (SELECT coalesce(json_agg(k.key ORDER BY k.key), '[]'::json) FROM public.\"LiteLLM_Config\" c "
    f"CROSS JOIN LATERAL jsonb_each({_OBJECT.format(v='c.param_value')}) k "
    "WHERE c.param_name = 'environment_variables'), "
    "'callbacks', (SELECT coalesce(json_agg(DISTINCT v.value ORDER BY v.value), '[]'::json) "
    "FROM public.\"LiteLLM_Config\" c "
    f"CROSS JOIN LATERAL jsonb_each({_OBJECT.format(v='c.param_value')}) e "
    "CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(e.value) = 'array' THEN e.value "
    "ELSE '[]'::jsonb END) v WHERE c.param_name = 'litellm_settings' AND e.key IN ("
    + ', '.join(f"'{key}'" for key in CALLBACK_KEYS) + ")))")


def stored_settings(cluster, schema):
    """{sections, env, callbacks}: the NAMES of HA's stored LiteLLM settings (STORED_SETTINGS_SQL), or None when HA has
    no such table or it cannot be read (the check goes on without the line)."""
    columns = {row[2]: row[3] for row in schema.columns if (row[0], row[1]) == CONFIG_TABLE}
    if columns.get('param_value') != 'jsonb' or 'param_name' not in columns:
        return None
    try:
        found = cluster.query_json(STORED_SETTINGS_SQL, DATABASE)
    except BackupError:
        return None
    if not isinstance(found, dict):
        return None

    def names(value):
        return [str(v)[:60] for v in value[:50] if isinstance(v, str)] if isinstance(value, list) else []

    return {'sections': names(found.get('sections')), 'env': names(found.get('env')),
            'callbacks': names(found.get('callbacks'))}


def stored_settings_line(found):
    if not found or not (found.get('env') or found.get('callbacks')):
        return None
    parts = []
    if found.get('env'):
        parts.append(f'環境變數 {hacommon.names(found["env"])}')
    if found.get('callbacks'):
        parts.append(f'記錄或通知的回呼 {hacommon.names(found["callbacks"])}')
    return (f'HA 的 LiteLLM 有存在資料庫裡的代理設定（{"；".join(parts)}），匯入後會在這台的 LiteLLM 生效'
            '（這台的 LiteLLM 以資料庫裡的設定為準），請求可能會被轉送或記錄到這些設定指定的地方；請確認都是你自己設定的再正式匯入。')


def detail_sql(tables):
    present = set(tables)
    parts = ', '.join(f"'{key}', (SELECT count(*) FROM {_q(s, t)}{where})" for key, s, t, where in DETAIL
                      if (s, t) in present)
    return f'SELECT json_build_object({parts})' if parts else None


READER_SQL = (f'CREATE ROLE {READER_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n'
              f'GRANT USAGE ON SCHEMA woow, woow_platform TO {READER_ROLE};\n'
              f'GRANT SELECT ON woow.meta, woow_platform.settings TO {READER_ROLE};\n')


def salt_binding(cluster, src):
    """'match' when HA's salt file is the salt HA's database is bound to (ha_litellm_candidate.read_source_salt_binding:
    a role without privileges reads the two fixed rows; the salt is compared in this process, never logged)."""
    if not src.salt_valid or src.salt() is None:
        return 'invalid_source'
    try:
        cluster.script(READER_SQL, DATABASE)
    except BackupError:
        return 'unknown'
    return candidate.read_source_salt_binding(cluster, src.salt())


def analyse(cluster):
    """What HA's database holds (from the hardened throwaway cluster)."""
    databases = {db['name']: db for db in ha_odoo.ha_databases(cluster)}
    if DATABASE not in databases:
        raise BackupError('incompatible', 'HA 的 LiteLLM 沒有 litellm 資料庫。')
    objects = cluster.query_json(OBJECTS_SQL, DATABASE)
    if not isinstance(objects, dict):
        raise BackupError('job-failed', '無法讀取 HA 的 LiteLLM 資料庫。')
    has_migrations = cluster.query_json(MIGRATIONS_TABLE_SQL, DATABASE)
    migrations = _migrations(cluster.query_json(MIGRATIONS_SQL, DATABASE)) if has_migrations is True else None
    superuser = cluster.query_json(ha_odoo.SUPERUSER_SQL, DATABASE)
    return {'objects': objects, 'databases': sorted(databases), 'migrations': migrations,
            'superuser': [str(k)[:40] for k in superuser[:20]] if isinstance(superuser, list) else []}


def verdict(src, found, *, ha_major, target_major, live_migrations_value, binding):
    """(blockers, warnings) of HA's LiteLLM against this device."""
    blockers, warnings = [], []
    objects = found['objects']
    if src.symlinks:
        blockers.append('HA 的 LiteLLM 資料庫使用了表格空間或符號連結，無法安全地搬過來。')
    if src.recovery_files:
        blockers.append('HA 的 LiteLLM 資料庫不是在停止狀態下備份的（含有 backup_label 或 tablespace_map），無法安全地搬過來；'
                        '請在 HA 重新做一份 LiteLLM 的備份。')
    if ha_major != HA_PG_MAJOR or src.pg_version is None:
        blockers.append(f'HA 的 LiteLLM 資料庫不是預期的 PostgreSQL {HA_PG_MAJOR}（是 {ha_major or "未知"} 版）。')
    if target_major is None or not 13 <= target_major < HA_PG_MAJOR + 1:
        blockers.append(f'無法確認這台 LiteLLM 的 PostgreSQL 版本（{target_major or "未知"}）。')
    extra_dbs = [d for d in found['databases'] if d != DATABASE]
    if extra_dbs:
        warnings.append(f'HA 的 LiteLLM 資料庫叢集還有其他資料庫（{hacommon.names(extra_dbs, 5)}），不會搬過來。')
    schemas = [str(s) for s in objects.get('schemas') or []]
    odd = [s for s in schemas if s not in ('woow_platform', 'woow')]
    if odd or 'woow_platform' not in schemas:
        blockers.append(f'HA 的 LiteLLM 資料庫的結構描述不是 LiteLLM 會建立的（{hacommon.names(odd or ["缺少 woow_platform"], 5)}），'
                        '無法安全地搬過來。')
    ha_only = [str(t) for t in objects.get('ha_only') or []]
    if any(t not in HA_ONLY['woow'] for t in ha_only):
        blockers.append(f'HA 的 LiteLLM 資料庫的 woow 結構描述有不認得的物件（{hacommon.names(ha_only, 5)}），無法安全地搬過來。')
    if found['superuser']:
        blockers.append(f'HA 的 LiteLLM 資料庫含有只有資料庫超級使用者才能建立的物件（{hacommon.names(found["superuser"])}），'
                        '無法安全地搬過來。')
    if ha_odoo._int(objects.get('large_objects')):
        blockers.append('HA 的 LiteLLM 資料庫含有大型物件（LiteLLM 不會建立），無法安全地搬過來。')
    if objects.get('encoding') != 'UTF8':
        blockers.append('HA 的 LiteLLM 資料庫不是 UTF8 編碼。')
    ha_migrations = found['migrations']
    if ha_migrations is None or live_migrations_value is None or ha_migrations != live_migrations_value:
        only_ha = sorted(set(ha_migrations or []) - set(live_migrations_value or []))
        only_here = sorted(set(live_migrations_value or []) - set(ha_migrations or []))
        blockers.append('資料庫結構版本不同（Prisma 遷移紀錄：只在 HA 的 '
                        f'{len(only_ha) if ha_migrations is not None else "未知"} 筆，只在這台的 '
                        f'{len(only_here) if live_migrations_value is not None else "未知"} 筆）。'
                        '請先讓兩邊的 LiteLLM 版本一致後再匯入。')
    if binding != 'match':
        blockers.append(SALT_MISMATCH if binding in ('mismatch', 'invalid_rows')
                        else 'HA 備份裡找不到格式正確的 LiteLLM 加密金鑰（salt_key），搬過來後儲存的供應商憑證都無法解密，所以不能匯入。')
    return blockers, warnings


def section(src, detail, *, version, migrations, target_major, key_users_value):
    detail = detail or {}
    return {'litellm_version': version or '', 'migrations': len(migrations or []),
            'pg_major': _ha_major(src), 'target_pg_major': target_major,
            'users': ha_odoo._int(detail.get('users')), 'teams': ha_odoo._int(detail.get('teams')),
            'keys': ha_odoo._int(detail.get('keys')), 'models': ha_odoo._int(detail.get('models')),
            'credentials': ha_odoo._int(detail.get('credentials')),
            'organizations': ha_odoo._int(detail.get('organizations')),
            'spend_logs': ha_odoo._int(detail.get('spend_logs')),
            'chatgpt_accounts': ha_odoo._int(detail.get('chatgpt_accounts')),
            'salt_moves': True, 'key_users': list(key_users_value)}


# ====================================================================== this device's apps that use LiteLLM keys

# A LiteLLM address another app is configured with: the container/network alias `litellm` (port 4000), this device's
# published loopback port, or Podman's host alias with that port.
LITELLM_URL_RE = re.compile(r'(?:^|[/@=\s"\'])(?:litellm|litellm-net)(?::4000)?(?:[/\s"\']|$)'
                            r'|(?:127\.0\.0\.1|localhost|host\.containers\.internal|host\.docker\.internal):4000\b', re.I)
ENV_LINE_RE = re.compile(r'\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*\Z')
NETWORK_RE = re.compile(r'(?:network\s+connect\s+(?:--[a-z-]+(?:=\S+)?\s+)*|--network[= ])([A-Za-z0-9][A-Za-z0-9_.-]{0,62})')
DROPIN_DIR = '.config/systemd/user/litellm.service.d'
# LiteLLM's network drop-ins as the package's hosts have them (production: local-agent-networks.conf joins the Hermes
# and OpenDesign networks). Read as the owner; a missing file is simply not there.
DROPINS = ('local-agent-networks.conf',)
LITELLM_NETWORKS = ('litellm-net', 'litellm', 'litellm.network', 'systemd-litellm')
MAX_SCAN = 1024 * 1024


def _uses_litellm_text(text):
    """True when a config/Quadlet text sets a LiteLLM key or address: a non-empty `*LITELLM*` setting, or a value that
    points at this device's LiteLLM. Only the verdict leaves this function (no value is kept or logged)."""
    for raw in text.splitlines()[:5000]:
        line = raw.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('Environment='):
            line = line[len('Environment='):].strip().strip('"')
        match = ENV_LINE_RE.match(line)
        if match:
            key, value = match.group(1), match.group(2).strip().strip('"\'')
            if 'LITELLM' in key.upper() and value:
                return True
            if value and LITELLM_URL_RE.search(value):
                return True
        elif LITELLM_URL_RE.search(line) and not line.startswith('['):
            return True
    return False


def _network_names(quadlets):
    """{network name: True} of an app's Quadlet `.network` files (NetworkName=, else systemd-<file>)."""
    found = set()
    for name, data in quadlets.items():
        if not name.endswith('.network'):
            continue
        text = data.decode('utf-8', 'replace') if isinstance(data, bytes) else str(data)
        names = [value for key, value in tempctr.parse_unit(text).get('Network', []) if key == 'NetworkName']
        found.add(names[-1] if names else f'systemd-{name[:-len(".network")]}')
        found.add(name[:-len('.network')])
    return found


def litellm_networks(work, app):
    """The networks LiteLLM's own unit drop-ins (DROPINS) connect it to, read as the owner; [] when there is none."""
    runner = work.runner(app)
    names = set()
    for entry in DROPINS:
        try:
            text = runner.read_file(f'{DROPIN_DIR}/{entry}', max_bytes=MAX_SCAN).decode('utf-8', 'replace')
        except (BackupError, OSError, TypeError, ValueError):
            continue
        names |= set(NETWORK_RE.findall(text))
    return sorted(names)


def _joins_litellm_network(text):
    """A `.container` file that puts the app on LiteLLM's own network."""
    for key, value in tempctr.parse_unit(text).get('Container', []):
        if key == 'Network' and value.split(':', 1)[0] in LITELLM_NETWORKS:
            return True
    return False


# The Pi coding agent (the Pi agent package's pi-web and Omnigent's runner) keeps its model providers, keys included,
# in <PI_CODING_AGENT_DIR>/models.json on a volume: both packages set PI_CODING_AGENT_DIR=/data/pi-agent (pi-web's
# image ENV, omnigent-runner.container Environment=) and mount their pi volume there. A provider whose base URL is this
# device's LiteLLM uses one of its keys.
PI_DIR_ENV = 'PI_CODING_AGENT_DIR'
PI_DIR_DEFAULT = '/data/pi-agent'
PI_MODELS = 'models.json'
PI_URL_KEYS = ('baseUrl', 'baseURL', 'base_url')
VOLUME_NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}')


def pi_agent_sources(quadlets, home):
    """[('volume', name) | ('path', path relative to the owner's home)] of the mounts that hold a Pi agent directory:
    a `.container` file's `Volume=` whose container target is its PI_CODING_AGENT_DIR (the Quadlet's Environment=, else
    /data/pi-agent). Sources outside the owner's home are never read."""
    home = home.rstrip('/')
    found = []
    for name in sorted(quadlets):
        if not name.endswith('.container'):
            continue
        data = quadlets[name]
        text = data.decode('utf-8', 'replace') if isinstance(data, bytes) else str(data)
        try:
            target = (tempctr.quadlet_environment(text, {PI_DIR_ENV}).get(PI_DIR_ENV) or PI_DIR_DEFAULT).rstrip('/')
        except BackupError:
            continue
        for key, value in tempctr.parse_unit(text).get('Container', []):
            parts = value.split(':')
            if key != 'Volume' or len(parts) < 2 or not target or parts[1].rstrip('/') != target:
                continue
            source = parts[0]
            if source.endswith('.volume'):
                try:
                    found.append(('volume', ha_odoo.quadlet_volume_name(quadlets, source)))
                except BackupError:
                    continue
            elif source.startswith(('%h/', home + '/')):
                rel = source[3:] if source.startswith('%h/') else source[len(home) + 1:]
                if rel and '..' not in rel.split('/'):
                    found.append(('path', rel.rstrip('/')))
            elif VOLUME_NAME_RE.fullmatch(source):
                found.append(('volume', source))
    return found


def models_use_litellm(data):
    """True when a Pi agent models.json names a provider whose base URL is this device's LiteLLM. The file holds API
    keys: only the verdict leaves this function (no value is kept or logged)."""
    try:
        doc = json.loads(data.decode('utf-8') if isinstance(data, bytes) else data)
    except (UnicodeDecodeError, ValueError, TypeError):
        return False
    providers = doc.get('providers') if isinstance(doc, dict) else None
    if not isinstance(providers, dict):
        return False
    for provider in list(providers.values())[:500]:
        if not isinstance(provider, dict):
            continue
        for key in PI_URL_KEYS:
            value = provider.get(key)
            if isinstance(value, str) and value.strip() and LITELLM_URL_RE.search(value.strip()[:2048]):
                return True
    return False


def pi_agent_uses_litellm(work, other, quadlets):
    """An app whose Pi agent provider list (models.json in a mount found by pi_agent_sources) points at this
    device's LiteLLM. A volume outside the owner's home, a missing or unreadable file: not counted."""
    runner = work.runner(other)
    home = str(runner.home).rstrip('/')
    for kind, source in pi_agent_sources(quadlets, home):
        try:
            if kind == 'volume':
                mount = (runner.podman('volume', 'inspect', '--format', '{{.Mountpoint}}', source, timeout=60,
                                       max_output=64 * 1024).stdout or b'').decode('utf-8', 'replace').strip()
                if '\n' in mount or not mount.startswith(home + '/') or len(mount) > 1024:
                    continue
                rel = mount[len(home) + 1:].rstrip('/')
            else:
                rel = source
            data = runner.read_file(f'{rel}/{PI_MODELS}', max_bytes=MAX_SCAN)
        except (BackupError, OSError, TypeError, ValueError):
            continue
        if models_use_litellm(data):
            return True
    return False


def key_users(work, app):
    """The names of this device's OTHER catalog apps whose configuration uses LiteLLM today (their virtual keys stop
    working once HA's keys replace this device's): a declared config file or a Quadlet file sets a LiteLLM key or
    address, LiteLLM's own drop-ins join one of the app's networks, or the app's Pi agent provider list (models.json)
    points at this device's LiteLLM. Derived from the catalog and the files as they are; nothing is written and no
    value leaves this function. A file that cannot be read is skipped."""
    try:
        catalog = work.ctx.catalog()
    except Exception:  # noqa: BLE001 - no catalog: no reminder line
        return []
    joined = set(litellm_networks(work, app))
    found = []
    for other_id, other in sorted(catalog.items()):
        if other_id == app.id or other_id.startswith(f'{app.id}-mcp'):
            continue  # LiteLLM's own MCP admin uses the master key, which this device keeps
        try:
            uses = False
            runner = work.runner(other)
            for item in getattr(other, 'config_files', ()) or ():
                try:
                    text = runner.read_file(item['path'], max_bytes=MAX_SCAN).decode('utf-8', 'replace')
                except (BackupError, OSError, TypeError):
                    continue
                if _uses_litellm_text(text):
                    uses = True
                    break
            if not uses:
                quadlets = work.quadlets(other)
                texts = [data.decode('utf-8', 'replace') if isinstance(data, bytes) else str(data)
                         for name, data in quadlets.items() if name.endswith('.container')]
                uses = (any(_uses_litellm_text(text) or _joins_litellm_network(text) for text in texts)
                        or bool(joined & _network_names(quadlets)) or pi_agent_uses_litellm(work, other, quadlets))
        except Exception:  # noqa: BLE001 - an app whose files cannot be read is not named
            continue
        if uses:
            found.append(str(getattr(other, 'name', '') or other_id)[:60])
    return found[:20]


def key_users_line(names):
    if not names:
        return None
    return (f'這台的 {hacommon.names(names)} 目前使用這台 LiteLLM 的金鑰；匯入後這台 LiteLLM 的虛擬金鑰會換成 HA 的，'
            '這些應用的 LiteLLM 金鑰會失效，請在匯入後為它們重新設定金鑰。')


# ====================================================================== the job steps

def pick_pg18(work, app):
    """The PostgreSQL 18 image that opens HA's cluster: a device copy of the pinned official image (by its content
    ID), else the pinned index is pulled by digest and must give one of those IDs."""
    runner = work.runner(app)
    for image_id in PG18_IDS:
        if runner.podman('image', 'exists', image_id, timeout=60, check=False).returncode == 0:
            return image_id
    work.log('這台沒有 PostgreSQL 18 映像，下載固定版本的官方 postgres 18.7 映像（以內容摘要固定）')
    runner.podman('pull', '--quiet', PG18_PINNED, timeout=1800, max_output=64 * 1024, abort=work.abort)
    for image_id in PG18_IDS:
        if runner.podman('image', 'exists', image_id, timeout=60, check=False).returncode == 0:
            return image_id
    raise BackupError('job-failed', '下載的 PostgreSQL 18 映像不是預期的版本，已停止，這台的應用沒有任何變更。', app=app.id)


def ha_server_args():
    """ha_odoo.HA_SERVER_SETTINGS (every library/command setting off, socket only) with the PG 18 image's paths, and
    no event trigger (SR-3; HA's per-database settings could turn it on again: the sessions' own options win)."""
    args = ['postgres']
    for setting in ha_odoo.HA_SERVER_SETTINGS:
        if setting.startswith('hba_file='):
            setting = f'hba_file={HA_PGDATA}/pg_hba.conf'
        elif setting.startswith('ident_file='):
            setting = f'ident_file={HA_PGDATA}/pg_ident.conf'
        args += ['-c', setting]
    return args + ['-c', 'event_triggers=off']


class HaSessions:
    """The job's throwaway objects as HA's cluster sees them: every `podman exec` in the HA container carries
    PGOPTIONS (HA_SUPERUSER_OPTIONS; the salt reader, a role without privileges, HA_SESSION_OPTIONS), so no session
    the engine opens there -- ha_odoo.Cluster's, export_rows' COPY, the salt reader's -- runs with HA's settings."""

    def __init__(self, tmp, role):
        self._tmp, self._role = tmp, role

    def __getattr__(self, name):
        return getattr(self._tmp, name)

    def exec(self, role, argv, *, env=None, **kwargs):
        if role == self._role:
            user = argv[argv.index('-U') + 1] if '-U' in argv[:-1] else None
            env = {**(env or {}), 'PGOPTIONS': HA_SESSION_OPTIONS if user == READER_ROLE else HA_SUPERUSER_OPTIONS}
        return self._tmp.exec(role, argv, env=env, **kwargs)


def start_ha_cluster(work, tmp, image):
    """PostgreSQL 18 on HA's (untrusted) cluster, as hardened as ha_odoo.start_ha_cluster: read-only root, no network,
    the data volume noexec/nosuid/nodev at the image's VOLUME path, every library/command setting overridden."""
    tmp.run('hapg', image, ha_server_args(), detach=True, read_only_root=True, env={'PGDATA': HA_PGDATA},
            volumes=[(tmp.name('hapg'), HA_PGDATA, 'rw,noexec,nosuid,nodev')])
    cluster = ha_odoo.Cluster(HaSessions(tmp, 'hapg'), 'hapg', log=work.log)
    cluster.wait_ready(checkpoint=work.checkpoint)
    major = cluster.query_json("SELECT to_json(current_setting('server_version_num')::int / 10000)", DATABASE)
    if major != HA_PG_MAJOR:
        raise BackupError('job-failed', '暫用的 PostgreSQL 18 版本不符，已停止，這台的應用沒有任何變更。')
    return cluster


def member_pass(work, app, tmp, pg_ids):
    member = work.addon_member(SLUG)
    report = habackup.Report()
    holder = {}

    def produce(out):
        sink = ha_odoo.PgSink(out, *pg_ids, guard=work.guard)
        with work.open(member) as stream:
            holder['src'] = scan_member(stream, report, pg=sink, checkpoint=work.checkpoint)
        sink.close()

    tmp.volume('hapg')
    tmp.volume_import('hapg', produce)
    for note in report.warnings():
        work.log(note)
    src = holder['src']
    if src.salt() is not None:
        from . import jobs
        jobs.mask_secret(src.salt().decode('ascii'))  # every log line, progress message and error of this job
    work.log(f'HA 的 LiteLLM：PostgreSQL {src.pg_version or "?"}，{src.pg_files} 個資料庫檔案'
             f'（{src.pg_bytes / 1048576:.1f} MiB），加密金鑰{"格式正確" if src.salt_valid else "缺少或格式不正確"}')
    return src


def _ha_major(src):
    try:
        return int((src.pg_version or '').split('.')[0])
    except ValueError:
        return None


def _prepare(work, app):
    """(Target, live LiteLLM version, live migrations, target PG major, version blocker or None)."""
    target = Target(work, app)
    addon = work.addon_info(SLUG)
    version = target_version(work, app)
    blocker = VERSIONS.blocker(addon.version if addon else '', version)
    return (target, version, live_migrations(work, app, target),
            ha_odoo.target_pg_major(work, app, target.db_image), blocker)


def _state_blocker(src, addon):
    expected = VERSIONS.upstream(addon.version if addon else '')
    if src.state_version is not None and expected is not None and src.state_version != expected:
        return (f'HA 的 LiteLLM 資料庫最後由 LiteLLM {src.state_version} 遷移，和附加元件 {addon.version} '
                f'搭配的 {expected} 不同，無法確認資料庫結構。')
    return None


def check(work, app):
    tmp = work.temp(app)
    target, version, migrations, target_major, blocker = _prepare(work, app)
    image18 = pick_pg18(work, app)
    pg_ids = tmp.user_ids('ids-pg', image18, 'postgres')
    src = member_pass(work, app, tmp, pg_ids)
    work.phase('check')
    cluster = start_ha_cluster(work, tmp, image18)
    found = analyse(cluster)
    binding = salt_binding(cluster, src)
    ha_schema = read_schema(cluster, found['migrations']) if found['migrations'] else None
    tables = ha_schema.tables() if ha_schema else []
    sql = detail_sql(tables)
    detail = cluster.query_json(sql, DATABASE) if sql else {}
    settings = stored_settings(cluster, ha_schema) if ha_schema else None
    tmp.remove('hapg')
    tmp.remove_volume('hapg')
    blockers, warnings = verdict(src, found, ha_major=_ha_major(src), target_major=target_major,
                                 live_migrations_value=migrations, binding=binding)
    stored_line = stored_settings_line(settings)
    if stored_line:
        warnings.append(stored_line)
    for item in (_state_blocker(src, work.addon_info(SLUG)), blocker):
        if item:
            blockers.insert(0, item)
    if ha_schema is not None:
        differ = schema_differences(ha_schema, live_schema(work, app, target))
        if differ:
            blockers.append(schema_blocker(differ))
    users = key_users(work, app)
    line = key_users_line(users)
    if line:
        warnings.append(line)
    if ha_odoo._int((detail or {}).get('chatgpt_accounts')):
        warnings.append(f'HA 的 LiteLLM 有 {detail["chatgpt_accounts"]} 個 ChatGPT 訂閱登入會一起搬過來；請先停掉 HA 那邊的 '
                        'LiteLLM（它的登入權杖會輪替，兩邊同時使用會讓其中一邊失效）。')
    return {'target_version': version or '', 'blockers': blockers, 'warnings': warnings,
            'litellm': section(src, detail, version=VERSIONS.upstream(work.addon_info(SLUG).version),
                               migrations=found['migrations'], target_major=target_major, key_users_value=users)}


# ---------------------------------------------------------------------- the trusted schema

# Runs in this device's litellm-postgres container: one exported snapshot holds the migrations check, the columns
# line and the schema-only archive; every temporary path is private and removed on exit.
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
LOCK TABLE public."_prisma_migrations" IN ACCESS SHARE MODE;
\\o $snapdir/snapshot
SELECT pg_export_snapshot();
\\o $snapdir/revision
SELECT CASE WHEN (__MIGRATIONS__)::text = '__EXPECTED__' THEN 'ok' ELSE 'mismatch' END;
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


def snapshot_script(expected):
    """SNAPSHOT_SCRIPT with the migrations the snapshot must hold (json_agg's text: `["a", "b"]`) and the columns
    query; no value of the database is in it."""
    text = json.dumps(sorted(expected), ensure_ascii=True)
    return (SNAPSHOT_SCRIPT.replace('__MIGRATIONS__', MIGRATIONS_SQL).replace('__EXPECTED__', text.replace("'", "''"))
            .replace('__COLUMNS__', ' '.join(COLUMNS_SQL.split())))


def capture_schema(work, app, target, path, expected):
    """The live database's columns and schema-only archive from ONE exported snapshot (the snapshot's migrations must
    be `expected`). Returns the snapshot's columns; the archive is written to `path` (0600)."""
    if not expected or any(not isinstance(v, str) or not MIGRATION_RE.fullmatch(v) for v in expected):
        raise BackupError('incompatible', '目標 LiteLLM 的資料庫結構版本不明。', app=app.id)
    capture = path.with_name(path.name + '.capture')
    created = output = False
    try:
        with open(capture, 'xb') as handle:
            created = True
            os.fchmod(handle.fileno(), 0o600)
            work.runner(app).podman('exec', '-i', target.db_container, 'sh', '-s', '--', target.db_user, target.database,
                                    input=snapshot_script(expected).encode('utf-8'), stdout=handle,
                                    timeout=DUMP_TIMEOUT, max_output=work.guard.budget(), abort=work.abort)
            handle.flush()
            os.fsync(handle.fileno())
        work.guard.check(os.path.getsize(capture))
        from . import util
        with open(capture, 'rb') as source:
            try:
                columns = util.loads_strict(source.readline(4 * 1024 * 1024 + 1), max_bytes=4 * 1024 * 1024)
            except ValueError:
                raise BackupError('incompatible', '目標 LiteLLM 的結構快照格式不正確。', app=app.id) from None
            _columns(columns, '這台 LiteLLM 的結構快照')
            with open(path, 'xb') as dest:
                output = True
                os.fchmod(dest.fileno(), 0o600)
                shutil.copyfileobj(source, dest, 1024 * 1024)
                dest.flush()
                os.fsync(dest.fileno())
        return columns
    except BaseException:
        if output:
            path.unlink(missing_ok=True)
        raise
    finally:
        if created:
            capture.unlink(missing_ok=True)


def trusted_schema(work, app, target, path, migrations):
    """This device's schema as the new cluster gets it: the live schema (signature, columns, migrations) before and
    after the capture and the snapshot's columns must all be equal -- no DDL ran meanwhile (enforced here)."""
    before = live_schema(work, app, target)
    if before.migrations != sorted(migrations or []):
        raise BackupError('incompatible', SCHEMA_CHANGED, app=app.id)
    if [s for s in before.signature.get('schemas') or [] if s != 'woow_platform']:
        raise BackupError('incompatible', '這台 LiteLLM 的資料庫有 LiteLLM 不會建立的結構描述，無法匯入。', app=app.id)
    columns = capture_schema(work, app, target, path, migrations)
    after = live_schema(work, app, target)
    if columns != before.columns or after != before:
        path.unlink(missing_ok=True)
        raise BackupError('incompatible', SCHEMA_CHANGED, app=app.id)
    return before


def require_schema(cluster, trusted, stage):
    found = _signature(cluster.query_json(SIGNATURE_SQL, DATABASE), '新的 PostgreSQL 叢集')
    differ = [key for key in SIGNATURE_KEYS if found.get(key) != trusted.signature.get(key)]
    if differ:
        raise BackupError('job-failed', f'新的 PostgreSQL 叢集的資料庫結構和這台 LiteLLM 的不同（{"、".join(differ)}），'
                                        '已停止，這台的應用沒有任何變更。', stage=stage)


def audit_new_cluster(cluster, superuser):
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


SEQUENCE_SQL = 'SELECT json_build_array(last_value, is_called) FROM {name}'
SALT_DIGEST_SQL = ("SELECT coalesce(json_agg(encode(pg_catalog.sha256(convert_to(value, 'UTF8')), 'hex')), '[]'::json) "
                   "FROM woow_platform.settings WHERE key OPERATOR(pg_catalog.=) 'litellm_salt_key'")


def export_rows(work, cluster, trusted, staging):
    """HA's rows of every trusted table into staging files (COPY text, the trusted columns) and every trusted
    sequence's value: {(schema, table): path}, {(schema, sequence): (value, called)}."""
    files, sequences = {}, {}
    for index, (schema, table) in enumerate(trusted.tables()):
        path = staging / f'rows-{index:03d}.copy'
        with open(path, 'xb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            cluster.tmp.exec(cluster.role, ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', DATABASE,
                                            '-c', copy_out_sql(schema, table, trusted.copy_columns(schema, table))],
                             user='postgres', stdout=handle, timeout=DUMP_TIMEOUT, max_output=work.guard.budget())
            handle.flush()
            os.fsync(handle.fileno())
        work.guard.wrote(os.path.getsize(path))
        files[(schema, table)] = path
        work.checkpoint()
    for schema, name in trusted.sequences():
        value = cluster.query_json(SEQUENCE_SQL.format(name=_q(schema, name)), DATABASE)
        if (not isinstance(value, list) or len(value) != 2 or type(value[0]) is not int
                or not isinstance(value[1], bool)):
            raise BackupError('incompatible', f'無法讀取 HA 的 LiteLLM 序號 {schema}.{name}。')
        sequences[(schema, name)] = (value[0], value[1])
    return files, sequences


def grants_sql(trusted):
    lines = [f'CREATE ROLE {RESTORE_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;']
    for schema in SCHEMAS:
        lines += [f'GRANT USAGE ON SCHEMA "{schema}" TO {RESTORE_ROLE};',
                  f'GRANT INSERT ON ALL TABLES IN SCHEMA "{schema}" TO {RESTORE_ROLE};',
                  f'GRANT USAGE, UPDATE ON ALL SEQUENCES IN SCHEMA "{schema}" TO {RESTORE_ROLE};']
    return '\n'.join(lines) + '\n'


def load_rows(work, tmp, role, superuser, schema_dump, files, sequences, trusted, ha_columns):
    """Into the new cluster: the trusted pre-data, HA's rows (the restricted role, table by table) and sequence
    values, then the trusted post-data (HA's rows must satisfy this device's constraints)."""
    cluster = ha_odoo.Cluster(tmp, role, superuser=superuser, log=work.log)
    with open(schema_dump, 'rb') as handle:
        tmp.exec(role, ['pg_restore', '-U', superuser, '--no-owner', '--no-acl', '--exit-on-error',
                        '--single-transaction', '--section=pre-data', '-d', DATABASE], user='postgres',
                 input=handle, timeout=DUMP_TIMEOUT, max_output=1024 * 1024)
    if _columns(cluster.query_json(COLUMNS_SQL, DATABASE), '新的 PostgreSQL 叢集') != ha_columns:
        raise BackupError('incompatible', 'HA 與目標 LiteLLM 的資料表欄位結構不同。')
    cluster.script(grants_sql(trusted), DATABASE)
    for (schema, table), path in files.items():
        with open(path, 'rb') as handle:
            tmp.exec(role, ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-1', '-U', RESTORE_ROLE, '-d', DATABASE,
                            '-c', copy_in_sql(schema, table, trusted.copy_columns(schema, table))],
                     user='postgres', input=handle, timeout=DUMP_TIMEOUT, max_output=1024 * 1024)
        os.unlink(path)
        work.checkpoint()
    if sequences:
        script = ''.join(f"SELECT pg_catalog.setval('{_q(s, n)}', {int(v)}, {'true' if called else 'false'});\n"
                         for (s, n), (v, called) in sorted(sequences.items()))
        ha_odoo.Cluster(tmp, role, superuser=RESTORE_ROLE, log=work.log).script(script, DATABASE)
    with open(schema_dump, 'rb') as handle:
        tmp.exec(role, ['pg_restore', '-U', superuser, '--no-owner', '--no-acl', '--exit-on-error',
                        '--single-transaction', '--section=post-data', '-d', DATABASE], user='postgres',
                 input=handle, timeout=DUMP_TIMEOUT, max_output=1024 * 1024)
    require_schema(cluster, trusted, 'restored')
    cluster.script(f'DROP OWNED BY {RESTORE_ROLE};\nDROP ROLE {RESTORE_ROLE};\n', DATABASE)
    return cluster


def write_secret(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def convert(work, app, test_mode, out_dir):
    """The converted database `out_dir/postgres/main.dump` and HA's salt as `litellm-salt-key` (module docstring: the
    trusted schema, HA's rows only); returns {postgres, secrets, counts, key_users, ...}. `test_mode` changes nothing
    for LiteLLM (it has no scheduled work of its own to pause)."""
    tmp = work.temp(app)
    target, version, migrations, target_major, blocker = _prepare(work, app)
    if blocker:
        raise BackupError('incompatible', f'LiteLLM 不能搬過來：{blocker}', app=app.id)
    staging = work.staging / 'litellm-work'
    staging.mkdir(mode=0o700)
    (out_dir / 'postgres').mkdir(mode=0o700, parents=True, exist_ok=True)
    (out_dir / 'ha-secrets').mkdir(mode=0o700, parents=True, exist_ok=True)
    image18 = pick_pg18(work, app)
    pg_ids = tmp.user_ids('ids-pg', image18, 'postgres')
    src = member_pass(work, app, tmp, pg_ids)
    work.phase('convert')
    work.guard.check(3 * src.pg_bytes + ha_odoo.WAL_ALLOWANCE)
    cluster = start_ha_cluster(work, tmp, image18)
    found = analyse(cluster)
    binding = salt_binding(cluster, src)
    blockers, _warnings = verdict(src, found, ha_major=_ha_major(src), target_major=target_major,
                                  live_migrations_value=migrations, binding=binding)
    state = _state_blocker(src, work.addon_info(SLUG))
    if state:
        blockers.insert(0, state)
    if blockers:
        raise BackupError('incompatible', f'LiteLLM 不能搬過來：{blockers[0]}', app=app.id)
    ha_schema = read_schema(cluster, found['migrations'])
    schema_dump = staging / 'target-schema.dump'
    work.log('讀取這台 LiteLLM 自己的資料庫結構（同一個快照；前後比對確認期間沒有結構變更）')
    trusted = trusted_schema(work, app, target, schema_dump, migrations)
    differ = schema_differences(ha_schema, trusted)
    if differ:
        raise BackupError('incompatible', f'LiteLLM 不能搬過來：{schema_blocker(differ)}', app=app.id)
    require_names(trusted, app)
    tables = trusted.tables()
    expected = table_counts(cluster, tables)
    detail = cluster.query_json(detail_sql(tables), DATABASE) if detail_sql(tables) else {}
    work.log(f'匯出 HA 的 LiteLLM 資料：{len(tables)} 個資料表的資料列（只當作資料來源，HA 的資料庫結構不會使用）')
    files, sequences = export_rows(work, cluster, trusted, staging)
    settings = stored_settings(cluster, ha_schema)
    tmp.remove('hapg')
    tmp.remove_volume('hapg')
    work.checkpoint()

    work.log('建立新的 PostgreSQL 資料庫叢集（與這台相同的映像與設定）')
    tmp.volume('ll-db')
    tmp.run('ll-db', target.db_image, [], detach=True,
            volumes=[(tmp.name('ll-db'), target.db_target, 'rw,noexec,nosuid,nodev')],
            env=target.db_env, secrets=target.db_secrets, read_only_root=True)
    pg = ha_odoo.Cluster(tmp, 'll-db', superuser=target.db_user, log=work.log)
    pg.wait_ready(tcp=True, checkpoint=work.checkpoint)
    work.log('用這台的資料庫結構建立資料表，只把 HA 的資料列與序號以沒有任何管理權限的暫用角色載入')
    load_rows(work, tmp, 'll-db', target.db_user, schema_dump, files, sequences, trusted, ha_schema.columns)
    os.unlink(schema_dump)
    require_schema(pg, trusted, 'loaded')
    audit_new_cluster(pg, target.db_user)
    counts = table_counts(pg, tables)
    differ = [f'{t}（HA {n}，匯入後 {counts.get(t)}）' for t, n in sorted(expected.items()) if counts.get(t) != n]
    now = _migrations(pg.query_json(MIGRATIONS_SQL, DATABASE))
    if differ or now != found['migrations'] or len(expected) != len(tables):
        raise BackupError('job-failed', f'LiteLLM 匯入後的資料和 HA 不同，已停止：{"、".join(differ[:10]) or "結構版本"}。')
    salt_rows = pg.query_json(SALT_DIGEST_SQL, DATABASE)
    if salt_rows != [hashlib.sha256(src.salt()).hexdigest()]:
        raise BackupError('job-failed', '匯入後資料庫裡的加密金鑰和要搬過來的不同，已停止，這台的應用沒有任何變更。')
    work.log(f'LiteLLM 資料匯入完成：{len(tables)} 個資料表的筆數都和 HA 相同，資料庫結構和這台的相同')
    dump = out_dir / 'postgres' / f'{target.pg_id}.dump'
    with open(dump, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        tmp.exec('ll-db', ['pg_dump', '-U', target.db_user, '-d', DATABASE, '-Fc'], user='postgres', stdout=handle,
                 timeout=DUMP_TIMEOUT, max_output=work.guard.budget())
        handle.flush()
        os.fsync(handle.fileno())
    if dump.stat().st_size == 0:
        raise BackupError('job-failed', 'LiteLLM 轉換後的資料庫匯出結果為空。', app=app.id)
    with open(dump, 'rb') as handle:  # a full read: every data block decompresses (adapter._pg_dump, lab H3)
        tmp.exec('ll-db', ['pg_restore', '-f', '/dev/null'], user='postgres', input=handle, timeout=DUMP_TIMEOUT,
                 max_output=1024 * 1024)
    server_version = str(pg.query_json("SELECT to_json(current_setting('server_version'))", DATABASE) or '')
    server_version = server_version.split(' ')[0][:32]
    major = pg.query_json("SELECT to_json(current_setting('server_version_num')::int / 10000)", DATABASE)
    if type(major) is not int or major != target_major:
        raise BackupError('job-failed', '新的 PostgreSQL 叢集版本和這台的不同，已停止。', app=app.id)
    tmp.stop('ll-db', timeout=120)
    tmp.remove('ll-db')
    tmp.remove_volume('ll-db')
    salt_path = write_secret(out_dir / 'ha-secrets' / SALT_SECRET, src.salt())
    users = key_users(work, app)
    return {'postgres': {target.pg_id: {'database': DATABASE, 'server_version': server_version, 'major': major,
                                        'file': dump}},
            'secrets': {SALT_SECRET: salt_path},
            'counts': section(src, detail, version=version, migrations=found['migrations'],
                              target_major=target_major, key_users_value=users),
            'tables': len(tables), 'key_users': users, 'stored_settings': settings}


# ====================================================================== texts

def import_texts(data):
    counts = data.get('counts') or {}
    notes = ['LiteLLM 的虛擬金鑰、使用者、團隊、模型、儲存的供應商憑證與用量紀錄會換成 HA 的；HA 的加密金鑰（salt）一起搬過來，'
             '取代這台的 litellm-salt-key，這台的主金鑰（master key）、管理介面密碼、資料庫密碼與網址不變。',
             'LiteLLM 只搬 HA 的資料：資料庫結構（資料表、欄位、預設值、檢查與索引）用這台 LiteLLM 自己的，'
             'HA 備份裡的資料庫結構不會執行；HA 的 PostgreSQL 18 資料以資料列搬到這台的 PostgreSQL 17。']
    line = key_users_line(data.get('key_users') or [])
    if line:
        notes.append(line)
    stored_line = stored_settings_line(data.get('stored_settings'))
    if stored_line:
        notes.append(stored_line)
    reminders = ['請用這台 LiteLLM 的主金鑰與管理介面密碼登入（HA 的主金鑰在這台不能用）；HA 的虛擬金鑰在這台繼續有效，'
                 '請把原本連到 HA 的用戶端改連到這台的 LiteLLM 網址。']
    if data.get('key_users'):
        reminders.append(f'請為 {hacommon.names(data["key_users"])} 重新設定 LiteLLM 金鑰（這台原本發出的虛擬金鑰已失效）。')
    if ha_odoo._int(counts.get('chatgpt_accounts')):
        reminders.append('請停掉 HA 那邊的 LiteLLM；如果 HA 在備份之後還在執行，請到這台 LiteLLM 的 ChatGPT 頁面重新連結訂閱帳號。')
    reminders.append('如果 HA 的模型設定連到 HA 內部的位址（例如 homeassistant、*.local），請改成這台連得到的位址。')
    return notes, reminders
