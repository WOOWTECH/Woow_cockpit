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
by a role without privileges; read_source_salt_binding below): else nothing can decrypt the stored
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

HAOS parity (2026-11-25, DESIGN F-a LITELLM; owner decision "what HAOS does not have is taken away"): every finding is an
issue of the issue model (haissues; ISSUES below), found by the check and found again by the conversion. A line to confirm
(`confirm`) stops only this app unless the customer confirmed exactly its names. What used to stop the import only
because of a version, a shape or a limit does not any more:
* the version numbers inform and decide nothing (L-31..L-34, L-45): HA's and this device's finished Prisma migrations and
  the data shape (L-26, L-09) decide; this device's PostgreSQL major is no gate (L-20, L-53: read from the new cluster);
* a stored setting that makes LiteLLM load code (L-13, L-14, L-47, L-49) is never moved: the conversion names it in one
  line to confirm, loads the rest, takes the setting out of the NEW cluster by key (the whole setting, never a part of it),
  and looks again in that cluster, whose catalog is this device's own, before anything is packed; a stored-settings table
  that cannot be read completely is not moved at all (and says so);
* schemas, superuser-only objects (L-21, L-23) and large objects (L-24) of HA's database beyond LiteLLM's own are never
  moved (only this device's tables' rows are), they are named; other schemas in THIS device's database (L-38) are named
  too, and the pre-restore backup that holds them is kept (`keep_safety`, RESTORE lane: kept.py) instead of deleted;
* a device whose app settings use the cold mode, or have other volumes and folders, is filled too (L-03): the new cluster
  is exported as the data volume, the rest is carried as it is; only the whole-instance dump stays a stop;
* the proxy's Quadlet is found by what it mounts (L-04), a database without finished migrations is given the first start of
  the proxy (L-08), a snapshot that came out wrong is taken again (L-36, L-37, L-39, L-54, L-55), extension versions that
  differ from this device's are aligned or named (L-40), the PostgreSQL 18 image is fetched with the reason for a failure
  (L-58), names of tables, columns and sequences are quoted instead of refused (L-10..L-12).
The COPY data of every table goes to the new cluster inside a script that ends with an end mark (pg-stdin follow-up F2): a
tail that did not arrive, a cut last field included, never commits and is noticed.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil

from . import habackup, haissues, hacommon, hatarget, ha_odoo, podman, tempctr
from .errors import BackupError
from .haissues import Issue

SLUG = 'woow-litellm'
APP_ID = 'litellm'
DATABASE = 'litellm'
PG_PREFIX = 'data/postgres'
SALT_FILE = 'data/secrets/salt_key'
STATE_FILE = 'data/woow/state.json'
SALT_SECRET = 'litellm-salt-key'
SALT_ENV = 'LITELLM_SALT_KEY'
# The add-on versions whose LiteLLM and PostgreSQL were verified (HA build-info.json / CHANGELOG; facts section 3).
VERSIONS = hacommon.VersionTable('LiteLLM', {'0.1.15': '1.104.0'})
HA_PG_MAJOR = 18
SCHEMAS = ('public', 'woow_platform')           # moved: data only (HA's `woow` bookkeeping and anything else never moves: L-22)
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
# The catalog entry the import fills (L-03): one single-database `postgres` item (suggest.PREFERRED_MODES makes it the default
# of a new draft) or, when the entry declares none, the data volume of the database among its volumes (cold mode); every
# other volume or folder of the entry is carried as it is. What it cannot fill is an entry that dumps the whole database
# instance (adapter.import_manifest has no instance form) or names no database at all.
LAYOUT_INSTANCE = '這台的 LiteLLM 應用設定用「整個資料庫執行個體」的方式備份資料庫，這個匯入還不支援這種方式。'
LAYOUT_NONE = '這台的 LiteLLM 應用設定裡沒有資料庫的匯出項目，也沒有資料庫的資料卷，匯入不知道要把資料放在哪裡。'
LAYOUT_MANY = '這台的 LiteLLM 應用設定有不只一個資料庫匯出項目，這個匯入只支援一個。'
LAYOUT_ACTION = ('請到「應用設定」掃描，在 LiteLLM 的草稿選「單一資料庫」（預設）或「冷備份」並安裝，再重新檢查。'
                 '改變方式後，這個應用之前的備份無法以新設定還原。')
TARGET_MISSING = '這台找不到 LiteLLM 的資料庫或代理服務的 Quadlet 檔（沒有掛載 litellm-salt-key 的容器，或資料庫容器），當作還沒安裝。'
TARGET_MISSING_ACTION = '請先用它的安裝套件在這台安裝並啟動 LiteLLM，再到「應用設定」加入它，然後重新檢查。'
TARGET_MISMATCH = '這台的 LiteLLM 資料庫、加密金鑰（litellm-salt-key）和 Quadlet 檔的設定不一致，無法匯入。'
TARGET_MISMATCH_ACTION = '請到「應用設定」修正這台 LiteLLM 的設定，使它和 Quadlet 檔一致，再重新檢查。'
MIGRATIONS_UNREADABLE = '無法讀取這台 LiteLLM 的資料庫結構版本（Prisma 遷移紀錄）。'
SALT_MISMATCH = ('HA 備份裡的加密金鑰（salt_key）和 HA 資料庫裡記錄的金鑰不一致，搬過來後儲存的供應商憑證都無法解密，'
                 '所以不能匯入；請在 HA 重新做一份 LiteLLM 的備份。')
SALT_MISSING = 'HA 備份裡找不到格式正確的 LiteLLM 加密金鑰（salt_key），搬過來後儲存的供應商憑證都無法解密，所以不能匯入。'
SALT_ACTION = '請在 HA 重新做一份 LiteLLM 的備份，再匯入。'

ISSUES = {
    'litellm.layout-unsupported': 'stop',     # L-03: an entry that dumps the whole instance, or names no database
    'litellm.extras-carried': 'auto',         # L-03: this device's other volumes and folders go along as they are
    'litellm.target-missing': 'stop',         # L-04: no Quadlet file of the database or of the proxy: not installed
    'litellm.target-mismatch': 'stop',        # L-05 (kept)
    'litellm.target-migrations': 'stop',      # L-08: this device's migrations stay unreadable, also after the proxy ran once
    'litellm.salt-file-invalid': 'stop',      # L-01 (kept)
    'litellm.no-database': 'stop',            # L-15: HA's PostgreSQL has no litellm database: nothing to move
    'litellm.tablespaces': 'stop',            # L-17 (kept)
    'litellm.not-cold-backup': 'stop',        # L-18 (kept)
    'litellm.pg-major': 'stop',               # L-19 (kept)
    'litellm.encoding': 'stop',               # L-25 (kept)
    'litellm.migrations-differ': 'stop',      # L-26 (kept)
    'litellm.schema-differs': 'stop',         # L-09 (kept)
    'litellm.salt-mismatch': 'stop',          # L-27 (kept)
    'litellm.salt-missing': 'stop',           # L-28 (kept)
    'litellm.schemas-skipped': 'confirm',     # L-21: HA's other schemas are not moved
    'litellm.superuser-objects': 'confirm',   # L-23: objects only a superuser can make are not moved
    'litellm.large-objects': 'notice',        # L-24: large objects are not moved
    'litellm.hooks-removed': 'confirm',       # L-13, L-14, L-47, L-49: stored settings that load code are not moved
    'litellm.config-unreadable': 'confirm',   # L-13: the stored-settings table cannot be read completely: not moved
    'litellm.other-schemas': 'confirm',       # L-38 (S4): other schemas in this device's database; the pre-restore backup is kept
    'litellm.keep-unsupported': 'stop',       # L-38: this engine cannot keep that backup (haimport.ITEM_KEYS lacks keep_safety)
    'litellm.version-differs': 'notice',      # L-34, L-45: both versions are known and differ; the data decides
    'litellm.extension-versions': 'auto',     # L-40: an extension's version in the new cluster is not this device's
    'litellm.databases-left': 'notice',       # HA's cluster has other databases: not moved
    'litellm.stored-settings': 'notice',      # HA's environment variables and callbacks in its database take effect here
    'litellm.key-users': 'notice',            # other apps use this device's virtual keys: they stop working
    'litellm.chatgpt-accounts': 'notice',     # ChatGPT sign-ins move along; stop HA's LiteLLM
}


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
            if entry.kind == 'file':
                src.pg_files += 1
                src.pg_bytes += entry.size
                if rel == 'PG_VERSION':
                    # L-57: its first bytes say the version; a file that is longer is no PostgreSQL's and the cluster does
                    # not open (nothing is refused here). The whole file still goes to the volume.
                    text = entry.peek(64).decode('ascii', 'replace').strip()
                    src.pg_version = text if re.fullmatch(r'[1-9][0-9]?', text) else None
            if pg is not None:
                pg.add(rel, entry, None)
            continue
        if name == SALT_FILE:
            salts += 1
            if entry.kind != 'file' or entry.size > MAX_SALT_FILE or salts > 1:
                raise haissues.stopped(Issue('litellm.salt-file-invalid', 'stop',
                                             'LiteLLM 附加元件的加密金鑰檔格式不正確，無法匯入。',
                                             action='請在 HA 重新備份 LiteLLM 後再匯入。'))
            value = entry.read_all(MAX_SALT_FILE).strip()
            src.salt_valid = bool(SALT_RE.fullmatch(value))
            src._salt = value if src.salt_valid else None
        elif name == STATE_FILE and entry.kind == 'file' and entry.size <= 65536:
            state = hacommon.strict_json(entry.read_all(65536), 65536)
            value = state.get('litellm_version') if isinstance(state, dict) else None
            src.state_version = value if isinstance(value, str) and VERSION_RE.fullmatch(value) else None
    src.addon = report.addon
    src.symlinks = report.skipped_symlinks
    return src   # L-02: whose add-on this is was settled before (Work.addon_info: ha.addon-other); not asked again here


# ====================================================================== this device's app

def _sink(work, app):
    """The issues of this app (a work without sinks -- a harness, a lab driver -- collects nowhere)."""
    maker = getattr(work, 'sink', None)
    app_id = getattr(app, 'id', None) or APP_ID
    return maker(app_id) if callable(maker) else haissues.Sink(app_id)


def _text_of(data):
    return data.decode('utf-8', 'replace') if isinstance(data, bytes) else str(data)


def _is_proxy(text):
    """The proxy's Quadlet file is the one that mounts the salt secret (L-04: not found by the container's name)."""
    return any(spec.split(',', 1)[0] == SALT_SECRET for spec in tempctr.quadlet_secrets(_text_of(text)))


def _is_database(text):
    text = _text_of(text)
    return 'POSTGRES_' in text and '/var/lib/postgresql' in text


def _stop(app, issue_id, message, action, code='incompatible'):
    return haissues.stopped(Issue(issue_id, 'stop', message, action=action), code, app=app.id)


def _layout_stop(app, message):
    return _stop(app, 'litellm.layout-unsupported', message, LAYOUT_ACTION)


class Target:
    """The litellm app's catalog items the import fills, resolved against the live Quadlet files: the database (the
    catalog's one database item and its container -- `mode` 'database' -- or, when the entry declares none, the container
    that holds the cluster in one of the entry's volumes -- `mode` 'cold'), the proxy (the container that mounts the salt
    secret as LITELLM_SALT_KEY, whatever it is called: L-04) and the salt secret. What else the entry declares -- other
    volumes, other folders -- is `extra_volumes` and `extra_dirs`, carried as it is (L-03)."""

    def __init__(self, work, app, sink=None):
        sink = sink if sink is not None else _sink(work, app)
        quadlets = work.quadlets(app)
        home = work.runner(app).home
        self.app = app
        pgs = list(app.postgres)
        if any(isinstance(pg, dict) and pg.get('scope', 'database') == 'instance' for pg in pgs):
            raise _layout_stop(app, LAYOUT_INSTANCE)
        if len(pgs) > 1:
            raise _layout_stop(app, LAYOUT_MANY)
        declared_volumes = [item['name'] for item in app.volumes]
        if not pgs and not declared_volumes:
            raise _layout_stop(app, LAYOUT_NONE)
        files = sorted(name for name in quadlets if name.endswith('.container'))
        self.mode = 'database' if pgs else 'cold'
        pg = pgs[0] if pgs else {}
        self.pg_id = pg.get('id')
        self.db_container = pg.get('container')
        db_file = hacommon.container_file(quadlets, self.db_container) if self.db_container else None
        if db_file is None and pgs:     # no file of that container's name: the one that mounts the data volume (L-04)
            db_file = next((name for name in files if self._mounts(quadlets, name, home, pg.get('data_volume'))), None)
        if db_file is None and not pgs:
            db_file = next((name for name in files if _is_database(quadlets[name])), None)
        proxies = [name for name in files if _is_proxy(quadlets[name])]
        if db_file is None or not proxies:
            raise _stop(app, 'litellm.target-missing', TARGET_MISSING, TARGET_MISSING_ACTION)
        if len(proxies) != 1:
            raise _stop(app, 'litellm.target-mismatch', TARGET_MISMATCH, TARGET_MISMATCH_ACTION)
        app_file = proxies[0]
        text = quadlets[db_file]
        self.db_image = tempctr.quadlet_image(text)
        self.db_env = hacommon.environment(quadlets, db_file, ha_odoo.DB_ENV_KEYS)
        self.db_secrets = tempctr.quadlet_secrets(text)
        if self.db_container is None:
            self.db_container = ha_odoo.quadlet_container_name(quadlets, db_file)
        self.db_user = pg.get('user') if pgs else self.db_env.get('POSTGRES_USER', 'postgres')
        self.database = pg.get('database') if pgs else self.db_env.get('POSTGRES_DB', self.db_user)
        mounts = ha_odoo.quadlet_mounts(quadlets, db_file, home)
        wanted = self.db_env.get('PGDATA') or '/var/lib/postgresql/data'
        holder = next((m for m in mounts if wanted == m[1] or wanted.startswith(m[1].rstrip('/') + '/')), None)
        holder = holder or (mounts[0] if mounts else None)
        self.db_volume, self.db_target = (holder[0], holder[1]) if holder else (None, None)
        self.pgdata = self.db_env.get('PGDATA') or self.db_target
        self.app_container = ha_odoo.quadlet_container_name(quadlets, app_file)
        self.app_image = tempctr.quadlet_image(quadlets[app_file])
        salt_specs = [spec for spec in tempctr.quadlet_secrets(quadlets[app_file])
                      if spec.split(',', 1)[0] == SALT_SECRET]
        declared = [item['name'] for item in app.secrets]
        wanted_volume = pg.get('data_volume') if pgs else (self.db_volume if self.db_volume in declared_volumes else None)
        if (self.database != DATABASE or self.db_env.get('POSTGRES_DB', self.db_user) != DATABASE
                or self.db_env.get('POSTGRES_USER', 'postgres') != self.db_user
                or not isinstance(self.db_user, str) or not IDENT_RE.fullmatch(self.db_user)
                or not self.db_image or not self.app_image or self.db_volume is None or self.db_volume != wanted_volume
                or not self.pgdata or not tempctr.TARGET_RE.fullmatch(self.pgdata)
                or len(salt_specs) != 1 or f'target={SALT_ENV}' not in salt_specs[0].split(',')[1:]
                or SALT_SECRET not in declared or len(declared) != len(set(declared))):
            raise _stop(app, 'litellm.target-mismatch', TARGET_MISMATCH, TARGET_MISMATCH_ACTION)
        # L-03: what the entry declares besides the database is this device's own data; it goes along as it is.
        self.extra_volumes, self.extra_dirs = hatarget.extras(
            app, handled_volumes=(self.db_volume,) if self.mode == 'cold' else ())
        if self.extra_volumes or self.extra_dirs:
            sink.auto('litellm.extras-carried', '這台 LiteLLM 的應用設定還有其他資料卷或資料夾，匯入時會照這台現在的內容原樣帶過去，'
                      '不會被 HA 的資料取代。', [*self.extra_volumes, *self.extra_dirs])

    @staticmethod
    def _mounts(quadlets, name, home, volume):
        try:
            return volume is not None and any(source == volume for source, _t, _o in ha_odoo.quadlet_mounts(quadlets, name, home))
        except BackupError:
            return False


VERSION_PROBE = ('import importlib.metadata as m, sys; '
                 'sys.stdout.write(m.version("litellm"))')


def target_version(work, app, target):
    """The proxy's LiteLLM version, read in the running container (`podman exec <proxy> python -I -c ...`: read only), else
    from its image (`Work.image_version`: the same program in a throwaway container without a network); None when neither
    says it (L-33: that only goes unsaid, it stops nothing)."""
    result = work.runner(app).podman('exec', target.app_container, 'python', '-I', '-c', VERSION_PROBE, timeout=120,
                                     max_output=4096, check=False)
    text = (result.stdout or b'').decode('ascii', 'replace').strip()
    if result.returncode == 0 and VERSION_RE.fullmatch(text):
        return text
    reader = getattr(work, 'image_version', None)
    if reader is None or not target.app_image:
        return None
    try:
        return reader(app, target.app_image, label=None, command=('python', '-I', '-c', VERSION_PROBE))
    except BackupError as error:
        if haissues.is_job_wide(error) or error.code in ('insufficient-space', 'busy'):
            raise
        return None


MIGRATIONS_SQL = ('SELECT coalesce(json_agg(migration_name ORDER BY migration_name COLLATE "C"), \'[]\'::json) '
                  'FROM public."_prisma_migrations" WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL')
MIGRATIONS_PRESENT_SQL = "SELECT to_json(pg_catalog.to_regclass('public._prisma_migrations') IS NOT NULL)"


# HA's migrations are read only from an ordinary table: a view (or anything else) there could run HA's code as the
# superuser at the read (review SR-1).
MIGRATIONS_TABLE_SQL = ("SELECT to_json(coalesce((SELECT c.relkind = 'r' FROM pg_catalog.pg_class c "
                        "WHERE c.oid = pg_catalog.to_regclass('public._prisma_migrations')), false))")
FIRST_START_WAIT = 900     # seconds the proxy gets to build its schema at its first start (L-08)


def _migrations(value):
    if not isinstance(value, list) or not value or len(value) > 2000 \
            or any(not isinstance(v, str) or not MIGRATION_RE.fullmatch(v) for v in value):
        return None
    return sorted(value)


def _read_live_migrations(work, app, target):
    """(table is there, the answer) of this device's database: a database whose proxy never ran has no table yet."""
    present = hacommon.live_json(work, app, target.db_container, target.db_user, target.database, MIGRATIONS_PRESENT_SQL)
    if present is not True:
        return False, None
    return True, hacommon.live_json(work, app, target.db_container, target.db_user, target.database, MIGRATIONS_SQL)


def _migrations_ready(target):
    """`ensure_running`'s test: the database answers with at least one finished migration."""
    def ready(runner, _container):
        result = runner.podman('exec', target.db_container, 'psql', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-U',
                               target.db_user, '-d', target.database, '-c', MIGRATIONS_SQL, timeout=60,
                               max_output=1024 * 1024, check=False)
        try:
            return result.returncode == 0 and bool(json.loads((result.stdout or b'null').strip() or b'null'))
        except ValueError:
            return False
    return ready


def live_migrations(work, app, target):
    """This device's finished Prisma migrations (sorted), None when they cannot be read. LiteLLM builds its schema at its
    first start: a database with no table or no finished migration yet gets that one start (the proxy is started, waited
    for and put back with the app's other throwaway objects), then it is read again (L-08); what is there but not usable
    (more than 2000, a name that is no migration's) is not helped by a start."""
    present, value = _read_live_migrations(work, app, target)
    if present and value:
        return _migrations(value)
    work.log('這台 LiteLLM 的資料庫還沒有完成的結構遷移紀錄，先啟動它的代理服務讓它建立資料庫結構，讀完會恢復原狀。')
    hatarget.ensure_running(work, app, target.app_container, ready=_migrations_ready(target), timeout=FIRST_START_WAIT)
    present, value = _read_live_migrations(work, app, target)
    return _migrations(value) if present else None


# ====================================================================== the schema of the moved schemas

def _own(catalog, alias='o', column='oid'):
    return (f"NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend x WHERE x.classid = 'pg_catalog.{catalog}'::regclass "
            f"AND x.objid = {alias}.{column} AND x.deptype = 'e')")


IN_SCHEMAS = "n.nspname IN ('public', 'woow_platform')"
# Every session that reads COLUMNS_SQL or SIGNATURE_SQL -- HA's cluster, this device's live database, the schema
# snapshot, the new cluster -- renders names with the same search_path, pg_catalog only: format_type, pg_get_expr and
# the pg_get_*def functions then qualify every name outside pg_catalog (public."JobStatus"), whatever the role or
# database settings say. HA's sessions have it anyway (HA_SESSION_OPTIONS, SR-1); without the pin this device's sides
# rendered the same enum column as "JobStatus" and the real backup's LiteLLM_CronJob "differed" (real attempt 7).
PIN_SEARCH_PATH = 'SET search_path = pg_catalog; '
# Physical data columns, in order (schema, table, column, type, not null, identity, generated).
COLUMNS_SQL = (PIN_SEARCH_PATH + "SELECT coalesce(json_agg(json_build_array(n.nspname, c.relname, a.attname, "
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
SIGNATURE_SQL = (PIN_SEARCH_PATH + 'SELECT json_build_object('
                 + ', '.join(f"'{key}', ({sql})" for key, sql in SIGNATURE_PARTS) + ')')
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
    """{(schema, name): [the rest of every row]}: keyed by the names themselves (a name may hold a dot: L-10..L-12)."""
    groups = {}
    for row in rows or []:
        if isinstance(row, list) and len(row) >= width:
            groups.setdefault(tuple(str(v) for v in row[:key_width]), []).append(tuple(row[key_width:width]))
    return groups


def schema_differences(ha, trusted):
    """The names (schema.table, sequences, types) whose DATA shape differs between HA and the trusted schema: the
    columns (name, type, not null, identity, generated; in order), the sequences (type, owning column) and the types
    (kind, base, enum labels). Defaults, constraints and indexes are never compared: HA's are never used."""
    differ = set()
    ha_cols, trusted_cols = _by(ha.columns, 2, 7), _by(trusted.columns, 2, 7)
    differ |= {t for t in set(ha_cols) | set(trusted_cols) if ha_cols.get(t) != trusted_cols.get(t)}

    def seqs(schema):
        return {(str(r[0]), str(r[1])): (r[2], r[9]) for r in schema.signature.get('sequences') or []
                if isinstance(r, list) and len(r) == 10}

    ha_seq, trusted_seq = seqs(ha), seqs(trusted)
    differ |= {s for s in set(ha_seq) | set(trusted_seq) if ha_seq.get(s) != trusted_seq.get(s)}

    def types(schema):
        return {(str(r[0]), str(r[1])): (r[2], r[3], r[6]) for r in schema.signature.get('types') or []
                if isinstance(r, list) and len(r) == 7}

    ha_types, trusted_types = types(ha), types(trusted)
    differ |= {t for t in set(ha_types) | set(trusted_types) if ha_types.get(t) != trusted_types.get(t)}
    return sorted('.'.join(key) for key in differ)


def schema_blocker(differ):
    return (f'HA 與這台 LiteLLM 的資料庫結構不同（{hacommon.names(differ)}）：只能搬到資料表與欄位完全相同的 LiteLLM，'
            '請先讓兩邊的 LiteLLM 版本一致後再匯入。')


def require_names(schema, app=None):
    """The moved tables, columns and sequences all have names the copy statements can quote (`_ident`): every name is
    quoted, none is refused for its characters and there is no limit on how many tables (L-10, L-11, L-12); a database
    without a table stops."""
    names = [n for pair in schema.tables() + schema.sequences() for n in pair]
    names += [row[2] for row in schema.columns]
    for name in names:
        _ident(name, TABLE_NAME_BAD)
    if not schema.tables():
        raise BackupError('incompatible', 'LiteLLM 的資料庫沒有任何資料表，沒有讀取任何資料就停止了。',
                          **({'app': app.id} if app is not None else {}))


TABLE_NAME_BAD = 'LiteLLM 的資料表名稱不是這個匯入支援的格式，無法匯入。'
COLUMN_NAME_BAD = 'LiteLLM 的資料表欄位名稱不是這個匯入支援的格式，無法匯入。'


def _ident(name, message):
    """`name` as an SQL identifier: in double quotes, a double quote inside doubled. What PostgreSQL cannot hold in a name
    (nothing, a NUL, more than 63 bytes) or that is no text cannot come from a catalog and is refused."""
    if (not isinstance(name, str) or not name or '\x00' in name
            or len(name.encode('utf-8', 'surrogatepass')) > 63):
        raise BackupError('incompatible', message)
    return '"' + name.replace('"', '""') + '"'


def _literal(text):
    """`text` as an SQL string literal (standard_conforming_strings is on in every session the engine opens)."""
    return "'" + text.replace("'", "''") + "'"


def _q(schema, name):
    return f'{_ident(schema, TABLE_NAME_BAD)}.{_ident(name, TABLE_NAME_BAD)}'


def _cols(columns):
    if not columns:
        raise BackupError('incompatible', COLUMN_NAME_BAD)
    return ', '.join(_ident(c, COLUMN_NAME_BAD) for c in columns)


def copy_out_sql(schema, table, columns):
    return f'COPY {_q(schema, table)} ({_cols(columns)}) TO STDOUT'


def copy_in_sql(schema, table, columns):
    return f'COPY {_q(schema, table)} ({_cols(columns)}) FROM STDIN'


def counts_sql(tables):
    """One count per table, in the order of `tables` (a position, not a name: names may hold any character)."""
    parts = ', '.join(f'(SELECT count(*) FROM {_q(s, t)})' for s, t in tables)
    return f'SELECT json_build_array({parts})'


def table_counts(cluster, tables):
    """{(schema, table): rows}; a table whose count did not come back is left out."""
    found = {}
    for start in range(0, len(tables), 40):  # one argument each; PostgreSQL allows 100
        batch = tables[start:start + 40]
        doc = cluster.query_json(counts_sql(batch), DATABASE)
        if isinstance(doc, list) and len(doc) == len(batch):
            found.update({table: ha_odoo._int(value) for table, value in zip(batch, doc)})
    return found


# ====================================================================== HA's database

OBJECTS_SQL = """SELECT json_build_object(
 'schemas', (SELECT coalesce(json_agg(nspname ORDER BY nspname), '[]'::json) FROM pg_catalog.pg_namespace
             WHERE nspname NOT IN ('public', 'information_schema') AND nspname !~ '^pg_'),
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
# Stored settings whose value LiteLLM turns into Python code to call: get_instance_fn imports any dotted path
# (litellm/proxy/types_utils/utils.py:9-52, importlib.import_module), e.g. post_call_rules "builtins.exec" is then
# called with every model response text (litellm/litellm_core_utils/rules.py:41-46; proxy_server.py:6193-6194); the
# DB overlay refuses only s3:// and gcs:// for them (proxy_server.py:4494-4505). A callback with a dot in its name is
# such a module path too (4506-4513); a plain name (`langfuse`) is a built-in integration. Any of them refuses
# (review SR-6): this device's LiteLLM would run HA's code.
MODULE_HOOKS = (('litellm_settings', 'post_call_rules'), ('general_settings', 'custom_auth'),
                ('general_settings', 'custom_key_generate'), ('general_settings', 'custom_key_update'),
                ('general_settings', 'custom_key_policy'), ('general_settings', 'custom_team_metadata_validate'),
                ('general_settings', 'custom_sso'), ('general_settings', 'custom_ui_sso_sign_in_handler'))
# The nested places of the same kind (review iteration 2): the rest of the vendor's own DB-overlay list of values that
# reach get_instance_fn (proxy_server.py:4486-4640) plus router_settings.plugins, which that list misses
# (:6722-6737 -> resolve_routing_plugins :4767-4800; router_settings is a DB-overlay section, :5186-5193). Each is a
# SQL/JSON path over the section's stored object; only the label leaves the database, never a value.
#   custom_provider_map[].custom_handler: get_instance_fn for every item (:6215-6231);
#   guardrails v1 {name: {callbacks, guardrail}} and v2 {litellm_params: {callbacks, guardrail}}: a dotted callback
#     or guardrail type is a module (guardrails/init_guardrails.py:101-160 -> callback_utils; guardrail_registry.py
#     :580-618), a plain name is a built-in one;
#   pass_through_endpoints[].target: get_instance_fn for EVERY target (pass_through_endpoints.py:1993-2001); a URL only
#     falls back because its import fails, so a dotted target that is not scheme://... is a module;
#   litellm_jwtauth.custom_validate (_types.py:5374-5378); router_settings.plugins.
_TEXT = '@.type() == "string" && @ != ""'
NESTED_HOOKS = (
    ('litellm_settings', 'custom_provider_map', f'lax $.custom_provider_map[*].custom_handler ? ({_TEXT})'),
    ('litellm_settings', 'guardrails', f'lax $.guardrails[*].*.callbacks[*] ? ({_TEXT} && @ like_regex "[.]")'),
    ('litellm_settings', 'guardrails', f'lax $.guardrails[*].*.guardrail ? ({_TEXT} && @ like_regex "[.]")'),
    ('general_settings', 'pass_through_endpoints',
     f'lax $.pass_through_endpoints[*].target ? ({_TEXT} && @ like_regex "[.]" && '
     '!(@ like_regex "^[a-z][a-z0-9+-]*://" flag "i"))'),
    ('general_settings', 'litellm_jwtauth.custom_validate', f'lax $.litellm_jwtauth.custom_validate ? ({_TEXT})'),
    # key_management_system "custom" loads <config dir>/<file>.py (or an absolute path) with exec_module at every start
    # (secret_managers/custom_secret_manager_loader.py:30-75 via proxy_server.py:6981-6987, called on the DB-merged
    # configuration, :5815-5831 -> :5550-5590)
    ('general_settings', 'custom_secret_manager',
     f'lax $.key_management_settings.custom_secret_manager ? ({_TEXT})'),
    ('router_settings', 'plugins', f'lax $.plugins[*] ? ({_TEXT})'),
)
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
    + ', '.join(f"'{key}'" for key in CALLBACK_KEYS) + ")), "
    "'hooks', (SELECT coalesce(json_agg(DISTINCT c.param_name || '.' || h.key ORDER BY c.param_name || '.' || h.key), "
    "'[]'::json) FROM public.\"LiteLLM_Config\" c "
    f"CROSS JOIN LATERAL jsonb_each({_OBJECT.format(v='c.param_value')}) h "
    "WHERE (c.param_name, h.key) IN (" + ', '.join(f"('{a}', '{b}')" for a, b in MODULE_HOOKS) + ") "
    "AND h.value NOT IN ('null'::jsonb, '\"\"'::jsonb, '[]'::jsonb)), "
    # a STRING litellm_settings.callbacks is one module path (common_utils/callback_utils.py:403-415)
    "'nested', (SELECT coalesce(json_agg(DISTINCT n.label ORDER BY n.label), '[]'::json) FROM ("
    "SELECT 'litellm_settings.callbacks' AS label FROM public.\"LiteLLM_Config\" c "
    "WHERE c.param_name = 'litellm_settings' AND jsonb_typeof(c.param_value -> 'callbacks') = 'string' "
    "AND (c.param_value ->> 'callbacks') <> ''"
    # a dotted entry in ANY of the callback lists, however many plain names come first (the Python side used to look
    # only at the first 50 names; review iteration 2)
    " UNION ALL SELECT 'litellm_settings.' || e.key FROM public.\"LiteLLM_Config\" c "
    f"CROSS JOIN LATERAL jsonb_each({_OBJECT.format(v='c.param_value')}) e "
    "CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(e.value) = 'array' THEN e.value "
    "ELSE '[]'::jsonb END) v WHERE c.param_name = 'litellm_settings' AND e.key IN ("
    + ', '.join(f"'{key}'" for key in CALLBACK_KEYS) + ") AND strpos(v.value, '.') > 0"
    + ''.join(f" UNION ALL SELECT '{section}.{label}' FROM public.\"LiteLLM_Config\" c WHERE c.param_name = "
              f"'{section}' AND jsonb_path_exists({_OBJECT.format(v='c.param_value')}, '{path}')"
              for section, label, path in NESTED_HOOKS)
    + ") n))")


UNREADABLE = {'sections': [], 'env': [], 'callbacks': [], 'hooks': [], 'unreadable': True}


def stored_settings(cluster, schema):
    """{sections, env, callbacks, hooks}: the NAMES of the stored LiteLLM settings in `cluster` (STORED_SETTINGS_SQL),
    or None when the schema has no such table. An answer that cannot be read (over the output limit, a timeout, not a
    JSON object) is UNREADABLE, which refuses (review iteration 2: it failed open, so ~1M stored names hid a hook)."""
    columns = {row[2]: row[3] for row in schema.columns if (row[0], row[1]) == CONFIG_TABLE}
    if columns.get('param_value') != 'jsonb' or 'param_name' not in columns:
        return None
    try:   # L-13: a read that failed for a moment is tried once more; only what stays unreadable is not moved
        found = hatarget.retry(lambda: cluster.query_json(STORED_SETTINGS_SQL, DATABASE), attempts=2, pause_first=2.0,
                               log=getattr(cluster, 'log', None), what='讀取 HA 的 LiteLLM 存在資料庫裡的設定')
    except BackupError as error:
        if haissues.is_job_wide(error):
            raise
        return dict(UNREADABLE)
    if not isinstance(found, dict):
        return dict(UNREADABLE)

    def names(value):
        return [str(v)[:60] for v in value[:50] if isinstance(v, str)] if isinstance(value, list) else []

    callbacks = names(found.get('callbacks'))
    hooks = (names(found.get('hooks')) + names(found.get('nested'))
             + [f'litellm_settings 回呼 {c}'[:60] for c in callbacks if '.' in c])
    return {'sections': names(found.get('sections')), 'env': names(found.get('env')),
            'callbacks': [c for c in callbacks if '.' not in c], 'hooks': hooks,
            'labels': sorted(set(names(found.get('hooks')) + names(found.get('nested'))))}


def stored_hooks_blocker(found):
    """The sentence of the refusal this import made until 2026-11-25 (L-13, L-14: the stored settings make LiteLLM load and
    run code, or cannot be read completely). The import does not stop for them any more (`settings_issues`: the settings are
    left out and named); the sentence stays for the lab drivers (tests/e2e/lab) that quote it."""
    if found and found.get('unreadable'):
        return ('無法完整讀取 HA 的 LiteLLM 存在資料庫裡的設定（內容過大或讀取逾時），無法確認其中沒有會載入並執行程式的設定，'
                '無法安全地搬過來。')
    if not found or not found.get('hooks'):
        return None
    return (f'HA 的 LiteLLM 在資料庫裡存了會載入並執行程式的設定（{hacommon.names(found["hooks"])}），匯入後這台的 LiteLLM '
            '會照著執行，無法安全地搬過來；請先在 HA 的 LiteLLM 移除這些設定，再重新備份。')


HOOKS_REMOVED = ('HA 的 LiteLLM 在資料庫裡存了會載入並執行程式的設定，匯入後這台的 LiteLLM 會照著執行，所以這些設定不會搬過來'
                 '（其他設定照搬）。需要它們的話，請匯入後自己在這台的 LiteLLM 重新設定。')
CONFIG_UNREADABLE = ('HA 的 LiteLLM 存在資料庫裡的代理設定（資料表 LiteLLM_Config）讀不完整（內容過大或讀取逾時），無法確認其中沒有會載入並'
                     '執行程式的設定，所以這個資料表這次不搬；匯入後請在這台的 LiteLLM 重新設定代理設定。')
HOOKS_STAYED = '匯入後的資料庫裡還留有會載入並執行程式的設定，沒有完全拿掉，已停止，這台的應用沒有任何變更。'
# What is taken out of a stored section for every label STORED_SETTINGS_SQL gives (MODULE_HOOKS pairs, NESTED_HOOKS labels, the
# callback lists): the whole setting, by its key or its path -- never a part of its value, so what is taken out can be told
# from what stays by the key alone. tests/backup/test_ha_litellm.py proves that no label the detection can give is without one.
NESTED_REMOVAL = {
    'custom_provider_map': ('key', 'custom_provider_map'), 'guardrails': ('key', 'guardrails'),
    'pass_through_endpoints': ('key', 'pass_through_endpoints'),
    'litellm_jwtauth.custom_validate': ('path', ('litellm_jwtauth', 'custom_validate')),
    'custom_secret_manager': ('path', ('key_management_settings', 'custom_secret_manager')),
    'plugins': ('key', 'plugins'),
}


def hook_removals():
    """{label: (section, ('key', name) | ('path', (a, b)))} of every label STORED_SETTINGS_SQL can give for a setting that
    loads code."""
    table = {f'{section}.{key}': (section, ('key', key)) for section, key in MODULE_HOOKS}
    for section, label, _path in NESTED_HOOKS:
        table[f'{section}.{label}'] = (section, NESTED_REMOVAL[label])
    for key in CALLBACK_KEYS:
        table[f'litellm_settings.{key}'] = ('litellm_settings', ('key', key))
    return table


def removal_sql(labels):
    """The UPDATEs that take the named settings out of the stored sections of the NEW cluster (one per label, in a script)."""
    table = hook_removals()
    statements = []
    for label in sorted(set(labels)):
        section, (kind, arg) = table[label]
        if kind == 'key':
            expr = f'param_value - {_literal(arg)}::text'
        else:
            expr = f"param_value #- {_literal('{' + ','.join(arg) + '}')}::text[]"
        statements.append(f'UPDATE public."LiteLLM_Config" SET param_value = {expr} WHERE param_name = {_literal(section)} '
                          "AND jsonb_typeof(param_value) = 'object';")
    return '\n'.join(statements) + '\n'


def settings_issues(sink, found):
    """What HA's stored settings say, as lines: the settings that load code are named in one line to confirm (they are not
    moved), a table that cannot be read completely is named in another (it is not moved), the rest that takes effect here is
    a reminder. Returns whether the table's rows are moved (False: the table stays empty)."""
    if found and found.get('unreadable'):
        sink.confirm('litellm.config-unreadable', CONFIG_UNREADABLE, [CONFIG_TABLE[1]])
        return False
    if found and found.get('hooks'):
        sink.confirm('litellm.hooks-removed', HOOKS_REMOVED, found['hooks'])
    line = stored_settings_line(found)
    if line:
        sink.notice('litellm.stored-settings', line)
    return True


def again(sink, issue_id, message, items):
    """The same line to confirm, found a second time in the NEW cluster: it must have exactly the names the customer
    confirmed (the same key), else this app stops (`confirmation-required`). A line already said is not said twice."""
    issue = Issue(issue_id, 'confirm', message, items)
    key = issue.key(sink.app_id)
    if not any(known.id == issue.id and known.level == 'confirm' and known.key(sink.app_id) == key for known in sink.found):
        sink.add(issue)


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

# The reader runs only against the hardened, isolated HA cluster. The role above can
# read the two ordinary salt tables but has no superuser or BYPASSRLS privilege.
_SALT_FINGERPRINT_RE = re.compile(rb'[0-9a-f]{16}\Z')
_SALT_QUERY = r'''SET LOCAL search_path = pg_catalog;
SET LOCAL transaction_read_only = on;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '2s';
SET LOCAL enable_indexscan = off;
SET LOCAL enable_indexonlyscan = off;
SET LOCAL enable_bitmapscan = off;
SET LOCAL max_parallel_workers_per_gather = 0;
SELECT CASE WHEN
  NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolsuper AND pg_has_role(current_user, r.oid, 'MEMBER'))
  AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = current_user AND (r.rolsuper OR r.rolbypassrls))
  AND (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE (n.nspname, c.relname) IN (('woow_platform', 'settings'), ('woow', 'meta'))
       AND c.relkind = 'r' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
       AND NOT EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhrelid = c.oid OR i.inhparent = c.oid)
       AND (SELECT count(*) FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname IN ('key','value')
            AND a.atttypid = 'pg_catalog.text'::regtype AND a.attnum > 0 AND NOT a.attisdropped) = 2) = 2
  THEN 'true' ELSE 'false' END AS schema_safe \gset
\if :schema_safe
SELECT json_build_object(
 'platform', (SELECT coalesce(json_agg(v), '[]'::json) FROM
   (SELECT CASE WHEN octet_length(value) <= 256 THEN value ELSE NULL END AS v
    FROM woow_platform.settings WHERE key OPERATOR(pg_catalog.=) 'litellm_salt_key'::text LIMIT 2) s),
 'fingerprint', (SELECT coalesce(json_agg(v), '[]'::json) FROM
   (SELECT CASE WHEN octet_length(value) <= 16 THEN value ELSE NULL END AS v
    FROM woow.meta WHERE key OPERATOR(pg_catalog.=) 'salt_fingerprint_v1'::text LIMIT 2) s));
\else
SELECT 1 / 0;
\endif
'''


def read_source_salt_binding(cluster, source_salt):
    """Compare the HA file salt with fixed DB rows; return only a safe status.

    The caller provisions the restricted role in an isolated cluster and prevents
    concurrent DDL. Neither SQL nor argv contains the salt. Captured output is bounded
    and DB values never leave this function.
    """
    if not isinstance(source_salt, bytes) or len(source_salt) > MAX_SALT_FILE:
        return 'invalid_source'
    source = source_salt.strip()
    if not SALT_RE.fullmatch(source):
        return 'invalid_source'
    try:
        response = cluster.tmp.exec(cluster.role,
            ['psql', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-1',
             '-U', READER_ROLE, '-d', DATABASE, '-f', '-'],
            user='postgres', input=_SALT_QUERY.encode('ascii'), timeout=15, max_output=4096, check=False)
        if response.returncode != 0 or not isinstance(response.stdout, bytes) or len(response.stdout) > 4096:
            return 'unknown'
        value = hacommon.strict_json(response.stdout.strip(), 4096)
        if not isinstance(value, dict) or set(value) != {'platform', 'fingerprint'}:
            return 'invalid_rows'
        platform, fingerprint = value['platform'], value['fingerprint']
        if (not isinstance(platform, list) or len(platform) != 1 or not isinstance(platform[0], str)
                or not isinstance(fingerprint, list) or len(fingerprint) != 1 or not isinstance(fingerprint[0], str)):
            return 'invalid_rows'
        db_salt, db_fp = platform[0].encode('ascii'), fingerprint[0].encode('ascii')
        if (len(db_salt) > 256 or not SALT_RE.fullmatch(db_salt) or len(db_fp) != 16
                or not _SALT_FINGERPRINT_RE.fullmatch(db_fp)):
            return 'invalid_rows'
        expected = hashlib.sha256(b'woow-litellm-salt-v1:' + source).hexdigest()[:16].encode('ascii')
        if hmac.compare_digest(source, db_salt) and hmac.compare_digest(expected, db_fp):
            return 'match'
        return 'mismatch'
    except (BackupError, UnicodeError, ValueError, TypeError):
        return 'unknown'


def salt_binding(cluster, src):
    """'match' when HA's salt file matches the two fixed database rows."""
    if not src.salt_valid or src.salt() is None:
        return 'invalid_source'
    try:
        cluster.script(READER_SQL, DATABASE)
    except BackupError:
        return 'unknown'
    return read_source_salt_binding(cluster, src.salt())


def analyse(cluster):
    """What HA's database holds (from the hardened throwaway cluster)."""
    databases = {db['name']: db for db in ha_odoo.ha_databases(cluster)}
    if DATABASE not in databases:   # L-15: nothing to move; only this app stops, this device's data is not touched
        raise haissues.stopped(Issue('litellm.no-database', 'stop', 'HA 的 LiteLLM 沒有 litellm 資料庫。',
                                     action='請先確認 HA 的 LiteLLM 有資料並重新備份，再匯入；這台的 LiteLLM 不會有任何變更。'))
    objects = cluster.query_json(OBJECTS_SQL, DATABASE)
    if not isinstance(objects, dict):
        raise BackupError('job-failed', '無法讀取 HA 的 LiteLLM 資料庫。')
    has_migrations = cluster.query_json(MIGRATIONS_TABLE_SQL, DATABASE)
    migrations = _migrations(cluster.query_json(MIGRATIONS_SQL, DATABASE)) if has_migrations is True else None
    superuser = cluster.query_json(ha_odoo.SUPERUSER_SQL, DATABASE)
    return {'objects': objects, 'databases': sorted(databases), 'migrations': migrations,
            'superuser': [str(k)[:40] for k in superuser[:20]] if isinstance(superuser, list) else []}


REBACKUP = '請在 HA 重新做一份 LiteLLM 的備份後再匯入。'


def judge(sink, src, found, *, ha_major, live_migrations_value, binding):
    """HA's LiteLLM against this device, as the issues of `sink` (the check collects them all; a conversion stops at the
    first stop and asks for every line to confirm). What this device's PostgreSQL major is, and which version either side's
    LiteLLM has, decide nothing here (L-20, L-31..L-34): the migrations (L-26) and the data shape (L-09) do."""
    objects = found['objects']
    if src.symlinks:
        sink.stop('litellm.tablespaces', 'HA 的 LiteLLM 資料庫使用了表格空間或符號連結，無法安全地搬過來。', action=REBACKUP)
    if src.recovery_files:
        sink.stop('litellm.not-cold-backup', 'HA 的 LiteLLM 資料庫不是在停止狀態下備份的（含有 backup_label 或 tablespace_map），'
                  '無法安全地搬過來；請在 HA 重新做一份 LiteLLM 的備份。', action=REBACKUP)
    if ha_major != HA_PG_MAJOR or src.pg_version is None:
        sink.stop('litellm.pg-major', f'HA 的 LiteLLM 資料庫不是預期的 PostgreSQL {HA_PG_MAJOR}（是 {ha_major or "未知"} 版）。',
                  action='請把 HA 的 LiteLLM 更新到使用 PostgreSQL 18 的版本，重新備份後再匯入。')
    extra_dbs = [d for d in found['databases'] if d != DATABASE]
    if extra_dbs:
        sink.notice('litellm.databases-left', f'HA 的 LiteLLM 資料庫叢集還有其他資料庫（{hacommon.names(extra_dbs, 5)}），不會搬過來。')
    schemas = [str(s) for s in objects.get('schemas') or []]
    odd = [s for s in schemas if s not in ('woow_platform', 'woow')]
    if odd:   # L-21: what LiteLLM does not make is not moved; a missing woow_platform is told by the shape comparison (L-09)
        sink.confirm('litellm.schemas-skipped', 'HA 的 LiteLLM 資料庫還有 LiteLLM 不會建立的結構描述，它們不會搬過來'
                     '（只搬 LiteLLM 自己的資料表的資料列）。', haissues.Names(odd))
    if found['superuser']:   # L-23: never moved; they only ever exist inside HA's sandboxed cluster
        sink.confirm('litellm.superuser-objects', 'HA 的 LiteLLM 資料庫含有只有資料庫超級使用者才能建立的物件，它們不會搬過來'
                     '（LiteLLM 不會建立這類物件；只搬資料表的資料列，由這台自己的資料庫結構接收）。', found['superuser'])
    large = ha_odoo._int(objects.get('large_objects'))
    if large:   # L-24
        sink.notice('litellm.large-objects', f'HA 的 LiteLLM 資料庫含有 {large} 個大型物件（LiteLLM 不會建立），它們不會搬過來。')
    if objects.get('encoding') != 'UTF8':
        sink.stop('litellm.encoding', 'HA 的 LiteLLM 資料庫不是 UTF8 編碼。', action=REBACKUP)
    ha_migrations = found['migrations']
    if ha_migrations is None or live_migrations_value is None or ha_migrations != live_migrations_value:
        only_ha = sorted(set(ha_migrations or []) - set(live_migrations_value or []))
        only_here = sorted(set(live_migrations_value or []) - set(ha_migrations or []))
        sink.stop('litellm.migrations-differ', '資料庫結構版本不同（Prisma 遷移紀錄：只在 HA 的 '
                  f'{len(only_ha) if ha_migrations is not None else "未知"} 筆，只在這台的 '
                  f'{len(only_here) if live_migrations_value is not None else "未知"} 筆）。'
                  '請先讓兩邊的 LiteLLM 版本一致後再匯入。',
                  action='請把 HA 和這台的 LiteLLM 更新到同一版，在 HA 重新備份後再匯入。')
    if binding != 'match':
        if binding in ('mismatch', 'invalid_rows'):
            sink.stop('litellm.salt-mismatch', SALT_MISMATCH, action=SALT_ACTION)
        else:
            sink.stop('litellm.salt-missing', SALT_MISSING, action=SALT_ACTION)


def verdict(src, found, *, ha_major, live_migrations_value, binding, target_major=None):
    """(blockers, warnings) as sentences: `judge` on a sink that only collects. Kept for the lab drivers of tests/e2e/lab;
    `target_major` is no gate any more (L-20)."""
    sink = haissues.Sink(APP_ID)
    judge(sink, src, found, ha_major=ha_major, live_migrations_value=live_migrations_value, binding=binding)
    return ([i.message for i in sink.found if i.level in ('stop', 'confirm')],
            [i.message for i in sink.found if i.level in ('auto', 'notice')])


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
    hatarget.ensure_image(work, app, PG18_PINNED)   # L-58: a second try, then only this app stops, with the reason
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


def start_ha_cluster(work, tmp, image, size=None):
    """PostgreSQL 18 on HA's (untrusted) cluster, as hardened as ha_odoo.start_ha_cluster: read-only root, no network,
    the data volume noexec/nosuid/nodev at the image's VOLUME path, every library/command setting overridden. `size`: the
    cluster's bytes (the wait for it to open grows with them)."""
    tmp.run('hapg', image, ha_server_args(), detach=True, read_only_root=True, env={'PGDATA': HA_PGDATA},
            volumes=[(tmp.name('hapg'), HA_PGDATA, 'rw,noexec,nosuid,nodev')])
    cluster = ha_odoo.Cluster(HaSessions(tmp, 'hapg'), 'hapg', log=work.log)
    cluster.wait_ready(checkpoint=work.checkpoint, timeout=podman.scaled_timeout(ha_odoo.PG_READY_TIMEOUT, size))
    return cluster   # L-30: the image is the pinned one by content (pick_pg18); which version it says is not asked again


def member_pass(work, app, tmp, pg_ids, sink=None):
    """HA's cluster streamed into the throwaway volume `hapg`, the salt file and state.json read. What the reader left out of
    the member (a device file, a fifo, a name it cannot show ...) is one line to confirm (`Sink.skipped`; symlinks are not
    among them: they stop the import, L-17)."""
    member = work.addon_member(SLUG)
    report = habackup.Report(names=haissues.Names)
    holder = {}

    def produce(out):
        pgsink = ha_odoo.PgSink(out, *pg_ids, guard=work.guard)
        with work.open(member) as stream:
            holder['src'] = scan_member(stream, report, pg=pgsink, checkpoint=work.checkpoint)
        pgsink.close()

    tmp.volume('hapg')
    tmp.volume_import('hapg', produce)
    for note in report.warnings():
        work.log(note)
    src = holder['src']
    if sink is not None:
        sink.skipped(report, *[kind for kind in habackup.SKIP_KINDS if kind != 'symlink'])
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


def target_major(work, app, target):
    """The PostgreSQL major this device's image says (shown only: the new cluster's own answer is what counts, L-20, L-53)."""
    try:
        return ha_odoo.target_pg_major(work, app, target.db_image)
    except BackupError as error:
        if haissues.is_job_wide(error) or error.code in ('insufficient-space', 'busy'):
            raise
        return None


def version_issues(addon_version, target):
    """The lines about versions: the table that maps HA's add-on version to LiteLLM's does not know it, this device's
    version cannot be read (both only inform), or both are known and differ (a reminder, never a gate: HA's and this
    device's migrations and data shape decide; L-31..L-34, L-45)."""
    upstream = VERSIONS.upstream(addon_version)
    result = []
    for issue in haissues.version_issues(VERSIONS.product, addon_version, upstream, target):
        if issue.id == 'version.different':
            issue = Issue('litellm.version-differs', 'notice',
                          f'HA 的 LiteLLM 是 {haissues.clean(upstream, 40)}（附加元件 {haissues.clean(addon_version, 40)}），'
                          f'這台的是 {haissues.clean(target, 40)}；版本不同不會擋下匯入：只要兩邊的資料庫結構相同'
                          '（遷移紀錄與資料表結構一致）就照常匯入，匯入後這台的 LiteLLM 用 HA 的資料執行。')
        result.append(issue)
    return result


def schema_stops(sink, ha_schema, live):
    """The shape of HA's tables against this device's live ones (L-09) and what else this device's database holds (L-38).
    The conversion asks it twice (before the capture, and of the captured schema): a line already said is not said twice."""
    differ = schema_differences(ha_schema, live)
    if differ:
        sink.stop('litellm.schema-differs', schema_blocker(differ),
                  action='請把 HA 和這台的 LiteLLM 更新到同一版，在 HA 重新備份後再匯入。')
    others = other_schemas(live)
    if others:
        again(sink, 'litellm.other-schemas', OTHER_SCHEMAS, others)
        if not keep_supported():
            sink.stop('litellm.keep-unsupported', KEEP_UNSUPPORTED,
                      action='請先更新這台的備份元件（需要能保留匯入前備份的版本），再匯入。')


OTHER_SCHEMAS = ('這台 LiteLLM 的資料庫裡還有 LiteLLM 不會建立的結構描述（資料）。匯入會用 HA 的資料取代整個資料庫，它們不會留在資料庫裡；'
                 '匯入前會先把整個資料庫存成「保留的複本」，不會自動刪除，需要時可以從備份清單取回。')
KEEP_UNSUPPORTED = ('這台的備份元件還不能保留匯入前的備份，所以不能在會失去這台資料庫裡其他資料的情況下匯入（匯入沒有開始，'
                    '這台沒有任何變更）。')


def other_schemas(live):
    """The schemas of this device's database besides `public` and `woow_platform` (L-38)."""
    return [str(name) for name in live.signature.get('schemas') or [] if name != 'woow_platform']


def keep_supported():
    """Whether this engine hands `keep_safety` to the adapter (haimport.ITEM_KEYS): without it the converted backup would not
    make the restore keep its pre-restore backup, and the schemas the confirmation promises to keep would go (L-38)."""
    from . import haimport
    return 'keep_safety' in haimport.ITEM_KEYS


def _prepare(work, app, sink):
    """(Target, live LiteLLM version or None, live migrations or None) of this device, ready to be read."""
    target = Target(work, app, sink)
    hatarget.ensure_image(work, app, target.db_image)
    version = target_version(work, app, target)
    migrations = live_migrations(work, app, target)
    if migrations is None:   # L-08: also after the proxy's first start the migrations cannot be read: nothing to compare with
        raise _stop(app, 'litellm.target-migrations', MIGRATIONS_UNREADABLE,
                    '請先在這台啟動 LiteLLM，等它建好資料庫（約一兩分鐘）後再重新檢查；仍然不行時請把作業紀錄交給工程人員。')
    return target, version, migrations


def check(work, app):
    sink = _sink(work, app)
    tmp = work.temp(app)
    target, version, migrations = _prepare(work, app, sink)
    addon = work.addon_info(SLUG)
    major = target_major(work, app, target)
    image18 = pick_pg18(work, app)
    pg_ids = tmp.user_ids('ids-pg', image18, 'postgres')
    src = member_pass(work, app, tmp, pg_ids, sink)
    work.phase('check')
    cluster = start_ha_cluster(work, tmp, image18, size=src.pg_bytes)
    found = analyse(cluster)
    binding = salt_binding(cluster, src)
    ha_schema = read_schema(cluster, found['migrations']) if found['migrations'] else None
    tables = ha_schema.tables() if ha_schema else []
    sql = detail_sql(tables)
    detail = cluster.query_json(sql, DATABASE) if sql else {}
    settings = stored_settings(cluster, ha_schema) if ha_schema else None
    tmp.remove('hapg')
    tmp.remove_volume('hapg')
    judge(sink, src, found, ha_major=_ha_major(src), live_migrations_value=migrations, binding=binding)
    settings_issues(sink, settings)
    sink.extend(version_issues(addon.version, version))
    if ha_schema is not None:
        schema_stops(sink, ha_schema, live_schema(work, app, target))
    users = key_users(work, app)
    line = key_users_line(users)
    if line:
        sink.notice('litellm.key-users', line)
    if ha_odoo._int((detail or {}).get('chatgpt_accounts')):
        sink.notice('litellm.chatgpt-accounts', f'HA 的 LiteLLM 有 {detail["chatgpt_accounts"]} 個 ChatGPT 訂閱登入會一起搬過來；請先停掉 HA 那邊的 '
                    'LiteLLM（它的登入權杖會輪替，兩邊同時使用會讓其中一邊失效）。')
    return {'target_version': version or '',
            'litellm': section(src, detail, version=VERSIONS.upstream(addon.version) or src.state_version,
                               migrations=found['migrations'], target_major=major, key_users_value=users)}


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
    values = list(expected or [])
    if any(not isinstance(v, str) or not MIGRATION_RE.fullmatch(v) for v in values):
        # Not a customer's case (L-35: `live_migrations` only gives names that are migrations'): the names are put into a shell
        # here-document, so one that is no migration's is a programming error and never reaches it.
        raise BackupError('internal-error', '結構快照腳本的遷移名稱格式不正確。')
    text = json.dumps(sorted(values), ensure_ascii=True)
    return (SNAPSHOT_SCRIPT.replace('__MIGRATIONS__', MIGRATIONS_SQL).replace('__EXPECTED__', text.replace("'", "''"))
            .replace('__COLUMNS__', ' '.join(COLUMNS_SQL.split())))


def capture_schema(work, app, target, path, expected):
    """The live database's columns and schema-only archive from ONE exported snapshot (the snapshot's migrations must
    be `expected`). Returns the snapshot's columns; the archive is written to `path` (0600)."""
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
                raise unsteady('目標 LiteLLM 的結構快照格式不正確。', app) from None
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


def unsteady(message, app):
    """A capture that came out wrong although nothing is wrong with the data (the device was busy, its schema moved for a
    moment): it is made again (`trusted_schema`); only what stays that way stops the app."""
    return BackupError('incompatible', message, app=app.id, unsteady=True)


def _unsteady(error):
    """Whether a failed capture may be made again (L-36, L-37, L-39, L-54, L-55): the schema moved, the snapshot came back
    garbled, or the script ended early (its exit codes 21 and 22: psql was gone / the snapshot is of other migrations)."""
    if haissues.is_job_wide(error):
        return False
    if (getattr(error, 'details', None) or {}).get('unsteady') is True:
        return True
    return isinstance(error, BackupError) and error.code == 'job-failed' and getattr(error, 'returncode', None) in (21, 22)


def trusted_schema(work, app, target, path, migrations):
    """This device's schema as the new cluster gets it: the live schema (signature, columns, migrations) before and
    after the capture and the snapshot's columns must all be equal -- no DDL ran meanwhile (enforced here). A capture that
    came out wrong because the device was busy or its schema was moving is made again after a pause (L-36, L-37, L-39,
    L-54, L-55); only a schema that does not hold still stops this app, and nothing was changed."""
    def once():
        before = live_schema(work, app, target)
        if before.migrations != sorted(migrations or []):
            raise unsteady(SCHEMA_CHANGED, app)
        columns = capture_schema(work, app, target, path, migrations)
        after = live_schema(work, app, target)
        if columns != before.columns or after != before:
            path.unlink(missing_ok=True)
            raise unsteady(SCHEMA_CHANGED, app)
        return before

    return hatarget.retry(once, attempts=3, pause_first=5.0, longest=30.0, retry_if=_unsteady, abort=work.abort,
                          log=work.log, what='讀取這台 LiteLLM 的資料庫結構')


def comparable(signature):
    """A signature without the versions of the extensions (L-40): the new cluster has the version its image makes of an
    extension, this device's database the one it was created with; a different version is told (`extension_notes`), a
    different extension is a different schema."""
    value = dict(signature)
    value['extensions'] = [[row[0], row[2]] for row in signature.get('extensions') or []
                           if isinstance(row, list) and len(row) == 3]
    return value


def extension_versions(signature):
    return {row[0]: row[1] for row in signature.get('extensions') or [] if isinstance(row, list) and len(row) == 3}


def require_schema(cluster, trusted, stage, notes=None):
    found = _signature(cluster.query_json(SIGNATURE_SQL, DATABASE), '新的 PostgreSQL 叢集')
    wanted = comparable(trusted.signature)
    seen = comparable(found)
    differ = [key for key in SIGNATURE_KEYS if seen.get(key) != wanted.get(key)]
    if differ:
        raise BackupError('job-failed', f'新的 PostgreSQL 叢集的資料庫結構和這台 LiteLLM 的不同（{"、".join(differ)}），'
                                        '已停止，這台的應用沒有任何變更。', stage=stage)
    if notes is not None:
        live, new = extension_versions(trusted.signature), extension_versions(found)
        notes.update({name for name in live if name in new and new[name] != live[name]})


def align_extensions(cluster, trusted):
    """L-40: the new cluster gets the extensions this device's database has at the versions it has them, when its image still
    ships those (CREATE EXTENSION ... VERSION from the live catalog's own names, before the schema is restored); what it
    cannot make that way is left to the image's version, which `require_schema` then only names."""
    for row in trusted.signature.get('extensions') or []:
        if not isinstance(row, list) or len(row) != 3 or row[0] == 'plpgsql':
            continue
        name, version, schema = row
        if not all(isinstance(v, str) and v for v in row):
            continue
        try:
            cluster.script(f'CREATE EXTENSION IF NOT EXISTS {_ident(name, TABLE_NAME_BAD)} WITH SCHEMA '
                           f'{_ident(schema, TABLE_NAME_BAD)} VERSION {_literal(version)};\n', DATABASE)
        except BackupError as error:
            if haissues.is_job_wide(error):
                raise


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


def copy_script(schema, table, columns, mark):
    """(head, tail) of the script one table's rows travel in (pg-stdin follow-up F2): one transaction that the script itself
    opens and closes around the COPY, then an end mark psql prints only after it has read and run everything before it. A
    tail that did not arrive -- on a row boundary or inside the last field -- never reaches COMMIT and never the mark: nothing
    is committed and the load notices (`load_table`)."""
    return (f'BEGIN;\nCOPY {_q(schema, table)} ({_cols(columns)}) FROM STDIN;\n', f'\\.\nCOMMIT;\n\\echo {mark}\n')


def export_rows(work, cluster, trusted, staging, skip=()):
    """HA's rows of every trusted table into staging files -- each one the whole script of its load (`copy_script`: the COPY
    text of the trusted columns between its head and its tail) -- and every trusted sequence's value:
    {(schema, table): (path, end mark)}, {(schema, sequence): (value, called)}. A table in `skip` is not read."""
    files, sequences = {}, {}
    for index, (schema, table) in enumerate(trusted.tables()):
        if (schema, table) in skip:
            continue
        path = staging / f'rows-{index:03d}.copy'
        columns = trusted.copy_columns(schema, table)
        mark = ha_odoo.SQL_END_MARK + secrets.token_hex(8)
        head, tail = copy_script(schema, table, columns, mark)
        with open(path, 'xb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(head.encode('utf-8'))
            handle.flush()
            cluster.tmp.exec(cluster.role, ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', DATABASE,
                                            '-c', copy_out_sql(schema, table, columns)],
                             user='postgres', stdout=handle, timeout=DUMP_TIMEOUT, max_output=work.guard.budget())
            handle.write(tail.encode('utf-8'))
            handle.flush()
            os.fsync(handle.fileno())
        work.guard.wrote(os.path.getsize(path))
        files[(schema, table)] = (path, mark)
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


def load_table(tmp, role, path, mark):
    """One table's script into the new cluster as the restricted role; its stdout must end with the end mark."""
    with open(path, 'rb') as handle:
        out = tmp.exec(role, ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', RESTORE_ROLE, '-d', DATABASE, '-f', '-'],
                       user='postgres', input=handle, timeout=DUMP_TIMEOUT, max_output=1024 * 1024).stdout or b''
    if out.rstrip(b'\n').rsplit(b'\n', 1)[-1] != mark.encode('ascii'):
        raise BackupError('job-failed', ha_odoo.INCOMPLETE_SQL)


def load_rows(work, tmp, role, superuser, schema_dump, files, sequences, trusted, ha_columns, notes=None):
    """Into the new cluster: the trusted pre-data, HA's rows (the restricted role, table by table) and sequence
    values, then the trusted post-data (HA's rows must satisfy this device's constraints). `notes`: gets the names of the
    extensions whose version the image could not make like this device's (L-40)."""
    cluster = ha_odoo.Cluster(tmp, role, superuser=superuser, log=work.log)
    align_extensions(cluster, trusted)
    with open(schema_dump, 'rb') as handle:
        tmp.exec(role, ['pg_restore', '-U', superuser, '--no-owner', '--no-acl', '--exit-on-error',
                        '--single-transaction', '--section=pre-data', '-d', DATABASE], user='postgres',
                 input=handle, timeout=DUMP_TIMEOUT, max_output=1024 * 1024)
    if _columns(cluster.query_json(COLUMNS_SQL, DATABASE), '新的 PostgreSQL 叢集') != ha_columns:
        raise BackupError('incompatible', 'HA 與目標 LiteLLM 的資料表欄位結構不同。')
    cluster.script(grants_sql(trusted), DATABASE)
    for (schema, table), (path, mark) in files.items():
        load_table(tmp, role, path, mark)
        os.unlink(path)
        work.checkpoint()
    if sequences:
        script = ''.join(f"SELECT pg_catalog.setval({_literal(_q(s, n))}, {int(v)}, {'true' if called else 'false'});\n"
                         for (s, n), (v, called) in sorted(sequences.items()))
        ha_odoo.Cluster(tmp, role, superuser=RESTORE_ROLE, log=work.log).script(script, DATABASE)
    with open(schema_dump, 'rb') as handle:
        tmp.exec(role, ['pg_restore', '-U', superuser, '--no-owner', '--no-acl', '--exit-on-error',
                        '--single-transaction', '--section=post-data', '-d', DATABASE], user='postgres',
                 input=handle, timeout=DUMP_TIMEOUT, max_output=1024 * 1024)
    require_schema(cluster, trusted, 'restored', notes)
    cluster.script(f'DROP OWNED BY {RESTORE_ROLE};\nDROP ROLE {RESTORE_ROLE};\n', DATABASE)
    return cluster


def write_secret(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def take_out_hooks(sink, pg, trusted):
    """L-14, L-47, L-49 (and review SR-8): decide again on what actually moved, in the NEW cluster -- this device's image and
    schema, HA's data only as rows, so its catalog is this device's own. The settings that make LiteLLM load code are named
    (the same line to confirm as the check's: the same names, else this app stops with `confirmation-required`), taken out
    by their keys (the whole setting, never a part of it) and looked for again: one that is still there stops the app and
    nothing is packed. Returns the stored settings that stay (None: the table is not there)."""
    found = stored_settings(pg, trusted)
    if found is None:
        return None
    if found.get('unreadable'):
        raise BackupError('job-failed', '無法完整讀取匯入後資料庫裡的 LiteLLM 設定，無法確認其中沒有會載入並執行程式的設定，'
                                        '已停止，這台的應用沒有任何變更。')
    if found.get('hooks'):
        again(sink, 'litellm.hooks-removed', HOOKS_REMOVED, found['hooks'])
        pg.script(removal_sql(found['labels']), DATABASE)
        found = stored_settings(pg, trusted)
        if found is None or found.get('unreadable') or found.get('hooks'):
            raise BackupError('job-failed', HOOKS_STAYED)
    return found


def convert(work, app, test_mode, out_dir):
    """The converted database (module docstring: the trusted schema, HA's rows only) as `out_dir/postgres/<id>.dump` -- or,
    for an app whose settings use the cold mode, the new cluster itself as the data volume (L-03) --, HA's salt as
    `litellm-salt-key`, and this device's other volumes and folders as they are; returns {postgres, volumes, dirs, secrets,
    counts, key_users, ...}. The same lines as the check (`work.sink`): a stop raises at once, a line to confirm raises unless
    the customer confirmed it with these names. `test_mode` changes nothing for LiteLLM (it has no scheduled work of its own
    to pause)."""
    sink = _sink(work, app)
    tmp = work.temp(app)
    target, version, migrations = _prepare(work, app, sink)
    addon = work.addon_info(SLUG)
    sink.extend(version_issues(addon.version, version))
    ids = work.adapter(app).owner_ids()
    size = hatarget.size_hint(getattr(work, 'ha', None))
    staging = work.staging / 'litellm-work'
    staging.mkdir(mode=0o700)
    (out_dir / 'postgres').mkdir(mode=0o700, parents=True, exist_ok=True)
    (out_dir / 'ha-secrets').mkdir(mode=0o700, parents=True, exist_ok=True)
    carried = {'volumes': {}, 'dirs': {}}
    if target.extra_volumes or target.extra_dirs:   # L-03: this device's own other data goes along as it is (cheap, first)
        report = habackup.Report(names=haissues.Names)
        carried = hatarget.carry(work, app, out_dir, ids, volumes=target.extra_volumes, dirs=target.extra_dirs,
                                 report=report, size=size)
        sink.skipped(report)
    image18 = pick_pg18(work, app)
    pg_ids = tmp.user_ids('ids-pg', image18, 'postgres')
    src = member_pass(work, app, tmp, pg_ids, sink)
    work.phase('convert')
    work.guard.check(3 * src.pg_bytes + ha_odoo.WAL_ALLOWANCE)
    cluster = start_ha_cluster(work, tmp, image18, size=src.pg_bytes)
    found = analyse(cluster)
    binding = salt_binding(cluster, src)
    judge(sink, src, found, ha_major=_ha_major(src), live_migrations_value=migrations, binding=binding)
    ha_schema = read_schema(cluster, found['migrations'])
    settings = stored_settings(cluster, ha_schema)
    moves_config = settings_issues(sink, settings)   # L-13, L-14, L-47: before anything else is read
    schema_dump = staging / 'target-schema.dump'
    work.log('讀取這台 LiteLLM 自己的資料庫結構（同一個快照；前後比對確認期間沒有結構變更）')
    schema_stops(sink, ha_schema, live_schema(work, app, target))   # before anything is captured: the shape, what else is there
    trusted = trusted_schema(work, app, target, schema_dump, migrations)
    schema_stops(sink, ha_schema, trusted)
    require_names(trusted, app)
    tables = trusted.tables()
    skipped = set() if moves_config else {CONFIG_TABLE}   # L-13: this table's rows are not read, the new one stays empty
    expected = {table: (0 if table in skipped else count) for table, count in table_counts(cluster, tables).items()}
    detail = cluster.query_json(detail_sql(tables), DATABASE) if detail_sql(tables) else {}
    work.log(f'匯出 HA 的 LiteLLM 資料：{len(tables) - len(skipped)} 個資料表的資料列（只當作資料來源，HA 的資料庫結構不會使用）')
    files, sequences = export_rows(work, cluster, trusted, staging, skip=skipped)
    tmp.remove('hapg')
    tmp.remove_volume('hapg')
    work.checkpoint()

    work.log('建立新的 PostgreSQL 資料庫叢集（與這台相同的映像與設定）')
    tmp.volume('ll-db')
    tmp.run('ll-db', target.db_image, [], detach=True,
            volumes=[(tmp.name('ll-db'), target.db_target, 'rw,noexec,nosuid,nodev')],
            env=target.db_env, secrets=target.db_secrets, read_only_root=True)
    pg = ha_odoo.Cluster(tmp, 'll-db', superuser=target.db_user, log=work.log)
    pg.wait_ready(tcp=True, checkpoint=work.checkpoint, timeout=podman.scaled_timeout(ha_odoo.PG_READY_TIMEOUT, src.pg_bytes))
    work.log('用這台的資料庫結構建立資料表，只把 HA 的資料列與序號以沒有任何管理權限的暫用角色載入')
    versions = set()
    load_rows(work, tmp, 'll-db', target.db_user, schema_dump, files, sequences, trusted, ha_schema.columns, versions)
    os.unlink(schema_dump)
    require_schema(pg, trusted, 'loaded', versions)
    audit_new_cluster(pg, target.db_user)
    if versions:   # L-40
        sink.auto('litellm.extension-versions', '這台資料庫的擴充功能版本和新資料庫的不同，匯入以這台映像附的版本為準，資料不受影響。',
                  sorted(versions))
    settings = take_out_hooks(sink, pg, trusted) if moves_config else None
    counts = table_counts(pg, tables)
    differ = [f'{s}.{t}（HA {n}，匯入後 {counts.get((s, t))}）' for (s, t), n in sorted(expected.items())
              if counts.get((s, t)) != n]
    now = _migrations(pg.query_json(MIGRATIONS_SQL, DATABASE))
    if differ or now != found['migrations'] or len(expected) != len(tables):
        raise BackupError('job-failed', f'LiteLLM 匯入後的資料和 HA 不同，已停止：{"、".join(differ[:10]) or "結構版本"}。')
    salt_rows = pg.query_json(SALT_DIGEST_SQL, DATABASE)
    if salt_rows != [hashlib.sha256(src.salt()).hexdigest()]:
        raise BackupError('job-failed', '匯入後資料庫裡的加密金鑰和要搬過來的不同，已停止，這台的應用沒有任何變更。')
    work.log(f'LiteLLM 資料匯入完成：{len(tables)} 個資料表的筆數都和 HA 相同，資料庫結構和這台的相同')
    server_version = str(pg.query_json("SELECT to_json(current_setting('server_version'))", DATABASE) or '')
    server_version = server_version.split(' ')[0][:32]
    major = pg.query_json("SELECT to_json(current_setting('server_version_num')::int / 10000)", DATABASE)
    if type(major) is not int:   # L-53: this cluster's own answer is the version; what the image says is not asked
        raise BackupError('job-failed', '無法讀取新的 PostgreSQL 叢集的版本，已停止。', app=app.id)
    postgres, volumes = {}, dict(carried['volumes'])
    if target.mode == 'cold':
        pg.statement('CHECKPOINT;')
        code = tmp.stop('ll-db', timeout=300)
        if code != 0:
            raise BackupError('job-failed', f'新的 PostgreSQL 叢集沒有正常關閉（結束碼 {code}）。')
        state = tmp.run('controldata', target.db_image, ['pg_controldata', target.pgdata], user='postgres',
                        volumes=[(tmp.name('ll-db'), target.db_target, 'ro')], timeout=300, read_only_root=True,
                        max_output=1024 * 1024).stdout or b''
        if not re.search(rb'Database cluster state:\s+shut down\s*$', state, re.M):
            raise BackupError('job-failed', '新的 PostgreSQL 叢集沒有正常關閉。')
        tmp.remove('ll-db')
        (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
        db_path = out_dir / 'volumes' / f'{target.db_volume}.tar'
        with open(db_path, 'xb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            tmp.volume_export('ll-db', handle, max_output=work.guard.budget())
            handle.flush()
            os.fsync(handle.fileno())
        tmp.remove_volume('ll-db')
        ha_odoo.check_volume_tar(db_path, ids)
        volumes[target.db_volume] = db_path
    else:
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
        tmp.stop('ll-db', timeout=120)
        tmp.remove('ll-db')
        tmp.remove_volume('ll-db')
        postgres = {target.pg_id: {'database': DATABASE, 'server_version': server_version, 'major': major, 'file': dump}}
    salt_path = write_secret(out_dir / 'ha-secrets' / SALT_SECRET, src.salt())
    users = key_users(work, app)
    others = other_schemas(trusted)
    converted = {'postgres': postgres, 'volumes': volumes, 'dirs': carried['dirs'], 'secrets': {SALT_SECRET: salt_path},
                 'counts': section(src, detail, version=version, migrations=found['migrations'],
                                   target_major=target_major(work, app, target), key_users_value=users),
                 'tables': len(tables), 'key_users': users, 'stored_settings': settings,
                 'hooks_removed': [issue for found_issue in sink.found if found_issue.id == 'litellm.hooks-removed'
                                   for issue in found_issue.names][:20],
                 'config_skipped': not moves_config, 'other_schemas': others[:20]}
    if others:   # L-38 (S4): the restore of this backup keeps its pre-restore backup, which holds every schema (kept.py)
        converted['keep_safety'] = True
    return converted


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
    if data.get('other_schemas'):
        notes.append(f'這台 LiteLLM 資料庫原本的其他結構描述（{hacommon.names(data["other_schemas"], 5)}）的資料沒有搬過來；'
                     '匯入前的整個資料庫已存成「保留的複本」，需要時可以從備份清單取回。')
    reminders = ['請用這台 LiteLLM 的主金鑰與管理介面密碼登入（HA 的主金鑰在這台不能用）；HA 的虛擬金鑰在這台繼續有效，'
                 '請把原本連到 HA 的用戶端改連到這台的 LiteLLM 網址。']
    if data.get('key_users'):
        reminders.append(f'請為 {hacommon.names(data["key_users"])} 重新設定 LiteLLM 金鑰（這台原本發出的虛擬金鑰已失效）。')
    if data.get('hooks_removed'):
        reminders.append(f'HA 的 LiteLLM 有會載入並執行程式的設定（{hacommon.names(data["hooks_removed"], 5)}）沒有搬過來；'
                         '需要的話，請自己在這台的 LiteLLM 重新設定。')
    if data.get('config_skipped'):
        reminders.append('HA 的 LiteLLM 存在資料庫裡的代理設定（資料表 LiteLLM_Config）沒有搬過來，請在這台的 LiteLLM 重新設定代理設定。')
    if ha_odoo._int(counts.get('chatgpt_accounts')):
        reminders.append('請停掉 HA 那邊的 LiteLLM；如果 HA 在備份之後還在執行，請到這台 LiteLLM 的 ChatGPT 頁面重新連結訂閱帳號。')
    reminders.append('如果 HA 的模型設定連到 HA 內部的位址（例如 homeassistant、*.local），請改成這台連得到的位址。')
    return notes, reminders
