"""Home Assistant import, Omnigent part: the WOOWTECH add-on `woow-omnigent` -> this device's app `omnigent` (CONTRACT
section 9 "Home Assistant import"; facts phase3/facts/omnigent.md). Owner: E2.

The add-on keeps an embedded PostgreSQL 16 cluster (`data/postgres`, initdb --locale=C, database `omnigent`) and the
server's artifact store with the session-cookie key of its accounts (`data/omnigent-home/.omnigent/artifacts/`: the
add-on's ARTIFACT_DIR is never read by omnigent 0.21.0; `omnigent server` keeps `<HOME>/.omnigent/artifacts`, HOME
being /data/omnigent-home -- cli.py `_default_artifact_location`, host/local_server.py `_local_data_dir`). The target
is the Podman package in cold mode: volumes `omnigent-postgres-data` (a whole PostgreSQL 16 cluster whose bootstrap
superuser is the app role), `omnigent-server-data` (/data: artifacts and the admin's runtime setting files) and
`omnigent-pi-data` (the runner's own pi state).

Versions (HAOS parity, 2026-11-25): the add-on version maps to an Omnigent version (VERSIONS); that table and the live
server's `/v1/info` `server_version` only inform (O-23, O-24, O-25: an unknown or unreadable version is a notice, two
different versions are a notice too). What decides is the data itself: HA's `alembic_version` must equal the live
database's and HA's tables and columns must equal this device's (O-19, O-26: stops of this app only); HA's PostgreSQL
major must not be newer than the image that opens it (O-18).

Findings go to `work.sink(app)` (haissues; ISSUES below): the check collects them, the conversion asks for the same ones
again (`judge`) and stops this app only (`stop`, or a `confirm` the customer did not confirm with exactly these names).
What HAOS would simply restore is no longer a refusal here: what this device cannot take over is left out and listed in
ONE line to confirm (`omnigent.skipped`: tables, objects, extensions and links that are not Omnigent's, locations that
point out of the artifact store; `omnigent.files-missing`), the rest is moved. Nothing of it weakens a protection: only
TABLE DATA and SEQUENCE SET entries that name this device's own tables and sequences, once each, are ever restored, as the
role without privileges; HA's cluster stays isolated (no network, read-only root, no executable data volume).

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
import unicodedata
import urllib.parse

from . import habackup, hacommon, ha_n8n, ha_odoo, haissues, hatarget, podman, tempctr
from .errors import BackupError
from .podman import CommandError

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
# HA's pg_dump runs as an OS user that is not the HA server's (the image's postgres, uid 70) and owns nothing in the
# container: code HA's catalog runs inside its server (security review 2026-11-23 SR-2) can then neither open
# pg_dump's stdout through /proc/<pid>/fd (a same-uid check that Yama does not restrict) nor signal it, so it cannot
# write the archive the conversion restores. pg_dump connects over the socket directory (mode 3777) as the database
# user postgres (trust). The id must be one the owner's rootless user namespace can represent (dev-d's maps only
# 1-54999: `podman exec --user 65534` failed there with 255), so the first of DUMP_IDS the owner's uid AND gid maps
# hold is taken, never root and never the image's postgres ids.
DUMP_IDS = (65534, 32767, 9999, 999)
SCHEMA_CHANGED = ('這台 Omnigent 的資料庫結構在轉換期間改變了（可能正在升級或重新啟動），沒有匯入任何資料；'
                  '請等它正常執行後再轉換一次。')

# What this module says about HA's Omnigent against this device (haissues; DESIGN B2). Numbers only in a message, names in
# `items`; a name from the backup is shown cleaned (haissues.Issue.shown).
ISSUES = {
    'omnigent.no-database': 'stop',          # O-10: HA's PostgreSQL has no omnigent database: nothing to move
    'omnigent.encoding': 'stop',             # O-17 (wave 2): HA's database is not UTF8
    'omnigent.pg-newer': 'stop',             # O-18: HA's PostgreSQL major is newer than the image that must open it
    'omnigent.alembic-different': 'stop',    # O-19 (wave 2): the structure version of the two databases differs
    'omnigent.schema-different': 'stop',     # O-26 (wave 2): tables or columns differ
    'omnigent.target-unreadable': 'stop',    # O-41: this device's structure version cannot be read (also after trying again)
    'omnigent.version-different': 'notice',  # O-25, O-49: the two versions differ; the data decides
    'omnigent.skipped': 'confirm',           # O-03, O-12, O-14, O-15, O-16, O-21, O-28: what is left out, in ONE line
    'omnigent.files-missing': 'confirm',     # O-22: agent bundles or files the database names that the backup does not hold
    'omnigent.cookie-missing': 'notice',     # O-20: no usable login key: everyone signs in again
    'omnigent.extras-carried': 'auto',       # O-07: this device's other volumes go along as they are
    'omnigent.hardlinks-copied': 'auto',     # O-02: hard links in HA's database folder are copied as ordinary files
    'omnigent.extension-version': 'auto',    # O-44: an extension of the new cluster has another version than this device's
    'omnigent.secrets-unregistered': 'notice',  # O-48: a Quadlet secret is not in the app settings
    'omnigent.accounts-unreadable': 'notice',   # O-09: this device's own accounts could not be read, not kept
    'omnigent.entries-skipped': 'notice',    # O-28: entries of HA's dump list that are not this device's tables or sequences
    'omnigent.addon-artifacts-unused': 'notice',
    'omnigent.credentials-reconnect': 'notice',
    'omnigent.settings-not-moved': 'notice',
    'omnigent.tasks-active': 'notice',
    'omnigent.public-sessions': 'notice',
    'omnigent.account-conflict': 'notice',
}
ACTION_REBACKUP = '請在 HA 重新備份後再匯入 Omnigent；這台的 Omnigent 不會有任何變更。'
ACTION_SAME_VERSION = '請先讓兩邊的 Omnigent 版本一致後再匯入；這台的 Omnigent 不會有任何變更。'
ACTION_UNCHANGED = '這台的 Omnigent 不會有任何變更。'
SNAPSHOT_ATTEMPTS = 3      # O-32, O-33, O-58, O-59: this device's structure snapshot, tried this many times
STEADY_ATTEMPTS = 3        # O-42, O-43: waits for this device's database structure to stop changing, this many times
READ_ATTEMPTS = 3          # O-09, O-40, O-41: a read of this device's own database
MAX_KEY_PARTS = 16         # O-21: levels of an artifact key (Omnigent's own have 2)
MAX_KEY_CHARS = 512        # agents.bundle_location is a String(512)
MAX_PART_CHARS = 255


def _spare_id(uids, gids, avoid):
    """The highest id both the owner's uid and gid maps hold that is not in `avoid` (None when there is none)."""
    spans = sorted(((max(a, c), min(b, d)) for a, b in uids.ranges for c, d in gids.ranges if max(a, c) < min(b, d)),
                   reverse=True)
    for start, end in spans:
        for candidate in range(end - 1, max(start, end - 1 - len(avoid)) - 1, -1):
            if candidate not in avoid:
                return candidate
    return None


def dump_user(ids, pg_ids):
    """`uid:gid` of HA's pg_dump (see DUMP_IDS): `ids` = the owner's (uid IdMap, gid IdMap), `pg_ids` = the image's
    postgres (uid, gid). One of DUMP_IDS when the owner's maps hold it; else any other id both maps hold (O-01): never
    root and never the image's postgres ids. None at all: this device cannot run the dump safely (job-failed)."""
    uids, gids = ids if ids else (None, None)
    for candidate in DUMP_IDS:
        if candidate in (0, *pg_ids):
            continue
        if uids is not None and (candidate not in uids or candidate not in gids):
            continue
        return f'{candidate}:{candidate}'
    spare = _spare_id(uids, gids, {0, *pg_ids}) if uids is not None else None
    if spare is not None:
        return f'{spare}:{spare}'
    raise BackupError('job-failed', '這台的使用者命名空間沒有可用來匯出 HA 資料庫的帳號 ID，無法安全地轉換。')


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
        self.cookie = False         # a usable accounts-cookie-secret is there (and carried)
        self.cookie_unusable = False  # O-20: one is there but empty or too large: not carried, a new one is made
        self.addon_artifacts = 0    # files in the add-on's own ARTIFACT_DIR (expected none)
        self.overrides = []         # HA's runtime setting files in /data (not imported)
        self.pg_links = haissues.Names()       # O-02: hard links in HA's database folder, copied as ordinary files
        self.outside_links = haissues.Names()  # O-03: hard links of the artifact store to files outside it: left out
        self.problems = []


def scan_member(stream, report, *, pg=None, artifacts=None, checkpoint=None):
    """One strict pass: `data/postgres/**` into `pg` (a PgSink), the artifact store into `artifacts` (a TreeTar,
    names `artifacts/...`, owner and modes fixed later); HA's runtime setting files are only named. Returns a
    Source.

    Hard links (HAOS parity; the reader hands a link to an earlier selected file out as a `hardlink` and every other one as
    a regular `file` after the walk): in HA's database folder a link is copied as an ordinary file (O-02: a normal database
    has none; the content stays in the isolated throwaway); in the artifact store a link that names a file outside the store
    is never carried, nor copied (O-03: the store is downloadable): it is left out and listed in `Source.outside_links`.
    The login key (accounts-cookie-secret) that is empty or larger than 4096 bytes is not carried either (O-20: Omnigent
    makes a new one; an empty key would sign with nothing). PG_VERSION is read only at its start (O-61: the database that
    opens the folder is what refuses a damaged one)."""
    select = habackup.Select(include=(PG_PREFIX, ARTIFACTS, ADDON_ARTIFACT_DIR) + tuple(f'data/{n}' for n in OVERRIDES),
                             exclude=(f'{ARTIFACTS}/.cache',), symlinks=(), hardlinks=True)
    src = Source()
    count = 0
    copies = getattr(report, 'copied_links', 0)
    for entry in habackup.iter_entries(stream, select, report, checkpoint=checkpoint):
        count += 1
        if checkpoint is not None and count % 256 == 0:
            checkpoint()
        copied = getattr(report, 'copied_links', 0) != copies   # a hard link whose file the reader copied (set just before)
        copies = getattr(report, 'copied_links', 0)
        name = entry.name
        if ha_odoo._under(name, PG_PREFIX):
            rel = name[len(PG_PREFIX) + 1:] if name != PG_PREFIX else '.'
            if entry.kind == 'hardlink':
                entry.copy_later()      # the same name comes again after the walk as a file with the content
                continue
            if copied:
                src.pg_links.add(rel)   # counted once: here, where the copy arrives
            if entry.kind == 'file':
                src.pg_files += 1
                src.pg_bytes += entry.size
                if rel == 'PG_VERSION':
                    head = entry.peek(64).split(b'\n', 1)[0]
                    src.pg_version = head.decode('ascii', 'replace').strip()[:16]
            if pg is not None:
                pg.add(rel, entry, None)
            continue
        if ha_odoo._under(name, ARTIFACTS):
            rel = name[len(ARTIFACTS) + 1:] if name != ARTIFACTS else ''
            target = 'artifacts' + (f'/{rel}' if rel else '')
            if copied or (entry.kind == 'hardlink' and (not ha_odoo._under(entry.linkname, ARTIFACTS)
                                                        or entry.linkname == ARTIFACTS)):
                src.outside_links.add(f'檔案區裡指到區外的硬連結 {rel}')   # O-03: never carried, never copied
                continue
            if entry.kind == 'dir':
                if artifacts is not None:
                    artifacts.dir(target, 0o755, entry.mtime)
            elif entry.kind == 'file':
                if rel == COOKIE:
                    src.cookie = 0 < entry.size <= 4096
                    src.cookie_unusable = not src.cookie
                    if not src.cookie:
                        continue
                src.artifact_files += 1
                src.artifact_bytes += entry.size
                if len(src.keys) < MAX_KEYS:
                    src.keys.add(rel)
                if artifacts is not None:
                    artifacts.file(target, entry, 0o600 if rel == COOKIE else 0o644)
            elif entry.kind == 'hardlink':
                linked = entry.linkname[len(ARTIFACTS) + 1:]
                if linked == COOKIE and src.cookie_unusable:
                    src.outside_links.add(f'檔案區裡指到區外的硬連結 {rel}')   # the key it names is not carried
                    continue
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

def _sink(work, app):
    """The issues of this app (a work without sinks -- a harness -- collects nowhere)."""
    maker = getattr(work, 'sink', None)
    app_id = getattr(app, 'id', None) or APP_ID
    return maker(app_id) if callable(maker) else haissues.Sink(app_id)


def _abort(work):
    abort = getattr(work, 'abort', None)
    return abort if callable(abort) else None


def _log(work):
    log = getattr(work, 'log', None)
    return log if callable(log) else None


def _again(work, action, what, **kwargs):
    """`action()` tried READ_ATTEMPTS times when a read of this device fails for a moment (hatarget.retry)."""
    return hatarget.retry(action, attempts=READ_ATTEMPTS, abort=_abort(work), log=_log(work), what=what, **kwargs)


class _Odd(BackupError):
    """An answer of this device's own database that is not the shape asked for: worth another try (O-09, O-41)."""

    def __init__(self, message, app):
        super().__init__('job-failed', message, app=app.id)


class Target:
    """The omnigent app's catalog items the import fills, resolved against the live Quadlet files. A volume of the app
    settings beyond the three (database, server, runner) is this device's own and goes along as it is (O-07: `extra_volumes`,
    carried by `convert`); the three must be there, all different, and the database settings must fit."""

    def __init__(self, work, app, sink=None):
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
        needed = {self.db_volume, server_volume, pi_volume} - {None}
        if (len(needed) != 3 or not needed <= set(declared) or len(declared) != len(set(declared))
                or self.database != DATABASE or not self.pgdata or not tempctr.TARGET_RE.fullmatch(self.pgdata)
                or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', self.db_user)):
            raise BackupError('incompatible', '這台的 Omnigent 資料卷、資料庫設定和 Quadlet 檔不一致，無法匯入。', app=app.id)
        self.extra_volumes, _dirs = hatarget.extras(app, needed)
        if self.extra_volumes and sink is not None:
            sink.auto('omnigent.extras-carried', '這台 Omnigent 的應用設定還有其他資料卷，匯入時會照這台現在的內容原樣帶過去，不會被 HA 的資料取代。',
                      self.extra_volumes)
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
    """The live server's version (`GET /v1/info` -> server_version; unauthenticated, loopback only); None when it cannot be
    read (O-24: that is no reason to refuse, the data decides)."""
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
    """This device's structure version; None when the answer is no list of texts, also after trying again (O-41; a read that
    fails stops this app as it did)."""
    def read():
        value = hacommon.live_json(work, app, target.db_container, target.db_user, target.database,
                                   "SELECT coalesce(json_agg(version_num), '[]'::json) FROM alembic_version")
        if not (isinstance(value, list) and all(isinstance(v, str) for v in value)):
            raise _Odd('這台 Omnigent 的資料庫結構版本讀到的不是清單。', app)
        return value
    try:
        return _again(work, read, '讀取這台 Omnigent 的資料庫結構版本')
    except _Odd:
        return None


LIVE_USERS_SQL = "SELECT coalesce(json_agg(u ORDER BY u.id), '[]'::json) FROM users u WHERE u.id IN ({names})"


def live_users(work, app, target, sink=None):
    """This device's own admin and runner rows (argon2id hashes masked in every log line from now on). When they cannot be
    read, also after trying again, they are not kept (O-09): the import goes on and the customer is told to make the runner's
    account again."""
    from . import jobs
    if not target.own_users:
        return []
    sql = LIVE_USERS_SQL.format(names=', '.join(ha_odoo.sql_literal(u) for u in target.own_users))

    def read():
        rows = hacommon.live_json(work, app, target.db_container, target.db_user, target.database, sql)
        if not isinstance(rows, list):
            raise _Odd('無法讀取這台 Omnigent 的帳號。', app)
        return rows
    try:
        rows = _again(work, read, '讀取這台 Omnigent 的帳號')
    except BackupError as error:
        if not (isinstance(error, _Odd) or hatarget.transient(error)):
            raise
        if sink is not None:
            sink.notice('omnigent.accounts-unreadable',
                        '讀不到這台 Omnigent 自己的管理者與 runner 帳號，匯入後它們不會保留；請用 HA 的帳號登入，並重新建立 runner 的帳號。',
                        target.own_users)
        return []
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


def analyse(cluster, sink=None):
    """What HA's database holds (from the hardened throwaway cluster). Without an `omnigent` database there is nothing to
    move: this app only stops (O-10)."""
    databases = {db['name']: db for db in ha_odoo.ha_databases(cluster)}
    if DATABASE not in databases:
        (sink if sink is not None else haissues.Sink(APP_ID)).refuse(
            'omnigent.no-database', 'HA 的 Omnigent 沒有 omnigent 資料庫，沒有資料可以搬。',
            action='請先在 HA 的 Omnigent 建立資料並重新備份，再匯入；這台的 Omnigent 不會有任何變更。')
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


def unknown_tables(found):
    """HA's tables that are none of Omnigent's (O-12): left out, listed."""
    return sorted(set(found['tables']) - KNOWN_TABLES)


def odd_extensions(found):
    """HA's extensions beyond plpgsql and pg_trgm (O-16): left out, listed."""
    return [e for e in (str(e) for e in found['objects'].get('extensions') or []) if e not in EXTENSIONS_OK]


def bundle_locations(found):
    """(the agent bundle locations and file blob keys HA's database names, the bundle locations that are not safe)."""
    keys = found['keys']
    wanted = [k for k in (keys.get('bundles') or []) + (keys.get('blobs') or []) if isinstance(k, str)]
    return wanted, [k for k in wanted if not key_ok(k)]


ODD_OBJECTS = (('functions', '函式'), ('triggers', '觸發程序'), ('views', '檢視表'), ('rules', '規則'),
               ('policies', '資料列政策'))
MSG_SKIPPED = ('HA 的 Omnigent 備份裡有這台搬不過來、Omnigent 也用不到的項目（資料表、物件、擴充功能、連結或不安全的檔案位置），'
               '只會略過它們，其餘的資料照常搬：{what}。')
MSG_FILES_MISSING = ('HA 的資料庫記著 {count} 個代理程式包或檔案，不在這份備份的檔案區裡{all}；它們在這台打不開，其他資料都正常。'
                     '請確認 HA 那邊本來就缺這些檔案，或把它們放在別的資料位置。')


def skipped_names(src, found):
    """(the names of everything that is left out, as ONE list for the line to confirm, and how many of each kind): HA's tables
    that are not Omnigent's, objects and extensions that are not Omnigent's or only a database superuser can make (O-12,
    O-14, O-15, O-16), the artifact store's links to files outside it (O-03), the agent locations that could leave the store
    (O-21). Every name of every kind is in the key (haissues.MergedNames)."""
    kinds = {'資料表': haissues.Names(f'資料表 {t}' for t in unknown_tables(found))}
    objects = found['objects']
    odd = haissues.Names(label for key, label in ODD_OBJECTS if ha_odoo._int(objects.get(key)))
    for schema in objects.get('schemas') or []:
        odd.add(f'其他結構描述 {schema}')
    for kind in found['superuser']:
        odd.add(f'只有資料庫超級使用者能建立的物件 {kind}')
    kinds['物件'] = odd
    kinds['擴充功能'] = haissues.Names(f'擴充功能 {e}' for e in odd_extensions(found))
    kinds['檔案位置'] = haissues.Names(f'會跑出檔案區的代理程式位置（會被清空） {k}' for k in bundle_locations(found)[1])
    kinds['連結'] = src.outside_links
    kinds = {kind: names for kind, names in kinds.items() if names.count}
    return haissues.MergedNames(list(kinds.items())), {kind: names.count for kind, names in kinds.items()}


def judge(sink, src, found, *, live_alembic_value, ha_major, target_major, differ=None):
    """Everything the check says about HA's Omnigent against this device, in the sink (the conversion asks again: a stop
    raises there, a line to confirm raises unless the customer confirmed these names). Stops first, so a conversion that
    stops, stops with the reason and not with a question. `differ`: the tables, sequences and types whose shape differs
    (O-26), known to the caller (the check reads this device's live schema, the conversion has the captured one)."""
    objects = found['objects']
    if ha_major is not None and target_major is not None and ha_major > target_major:
        sink.stop('omnigent.pg-newer', f'HA 的 PostgreSQL 是 {ha_major} 版，這台的資料庫是 {target_major} 版，打不開比自己新的資料。',
                  action='請先把這台的 Omnigent 更新到使用同版或更新的 PostgreSQL，再匯入；這台的 Omnigent 不會有任何變更。')
    if objects.get('encoding') != 'UTF8':
        sink.stop('omnigent.encoding', 'HA 的 Omnigent 資料庫不是 UTF8 編碼。', action=ACTION_REBACKUP)
    ha_alembic = found['alembic']
    if live_alembic_value is None:
        sink.stop('omnigent.target-unreadable', '無法讀取這台 Omnigent 的資料庫結構版本。',
                  action='請先確認這台的 Omnigent 資料庫正常執行（啟動過一次），再匯入。')
    elif not ha_alembic or sorted(ha_alembic) != sorted(live_alembic_value):
        sink.stop('omnigent.alembic-different',
                  f'資料庫結構版本不同：HA 是 {hacommon.names(ha_alembic, 5) or "未知"}，這台是 '
                  f'{hacommon.names(live_alembic_value, 5) or "未知"}。', action=ACTION_SAME_VERSION)
    if differ:
        sink.stop('omnigent.schema-different', schema_blocker(differ), action=ACTION_UNCHANGED)
    names, counts = skipped_names(src, found)
    if names.count:
        what = '、'.join(f'{kind} {n} 個' for kind, n in counts.items())
        sink.confirm('omnigent.skipped', MSG_SKIPPED.format(what=what), names)
    wanted, _bad = bundle_locations(found)
    lost = [k for k in wanted if key_ok(k) and k not in src.keys]
    if lost:
        sink.confirm('omnigent.files-missing', MSG_FILES_MISSING.format(
            count=len(lost), all='（備份的檔案區裡完全沒有它們要的檔案）' if len(lost) == len(set(wanted)) else ''),
            haissues.Names(lost))
    if not src.cookie:
        sink.notice('omnigent.cookie-missing', 'HA 備份裡沒有可用的 Omnigent 登入金鑰（accounts-cookie-secret：沒有、是空的或太大）；'
                    '匯入後 Omnigent 會自己產生新的，所有瀏覽器、裝置授權和權杖都要重新登入，外部連線可能要重連；帳號和對話都還在。')
    detail = found['detail']
    if src.addon_artifacts:
        sink.notice('omnigent.addon-artifacts-unused', f'HA 的 /data/artifacts 有 {src.addon_artifacts} 個檔案，Omnigent 不會使用它們，不會搬過來。')
    if ha_odoo._int(detail.get('connections_with_secrets')):
        sink.notice('omnigent.credentials-reconnect', f'HA 的 Omnigent 有 {detail["connections_with_secrets"]} 個加密保存的外部連線憑證，'
                    '這台沒有相同的加密設定，搬過來後需要重新連線。')
    if src.overrides:
        sink.notice('omnigent.settings-not-moved', 'HA 的 Omnigent 執行期設定檔不會搬過來，這台維持自己的分享與管理者設定。',
                    src.overrides)
    if ha_odoo._int(detail.get('scheduled_tasks_active')):
        sink.notice('omnigent.tasks-active', f'HA 的 Omnigent 有 {detail["scheduled_tasks_active"]} 個啟用中的排程，搬過來後會在這台執行'
                    '（測試匯入會先全部暫停）。')
    if ha_odoo._int(detail.get('public_sessions')):
        sink.notice('omnigent.public-sessions', f'HA 的 Omnigent 有 {detail["public_sessions"]} 個公開分享的工作階段，搬過來後仍然公開。')


def key_ok(key):
    """An artifact key (`<agent id>/<sha256>`, a blob's hex id, or whatever a later Omnigent writes) that stays inside the
    artifact store (O-21): not empty, no empty, `.` or `..` part, no absolute path, no backslash, no control or invisible
    character, within the size of agents.bundle_location. Anything else could make Omnigent read outside the store."""
    if not isinstance(key, str) or not 0 < len(key) <= MAX_KEY_CHARS:
        return False
    parts = key.split('/')
    return (len(parts) <= MAX_KEY_PARTS and all(
        part and part not in ('.', '..') and len(part) <= MAX_PART_CHARS and '\\' not in part
        and not any(unicodedata.category(ch) in haissues.HIDDEN_CATEGORIES for ch in part) for part in parts))


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

def member_pass(work, app, tmp, pg_ids, *, artifacts=None, report=None):
    member = work.addon_member(SLUG)
    report = report if report is not None else habackup.Report(names=haissues.Names)
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
    """(Target, live server version, live alembic, add-on, None). The fifth value was the version gate; no version is a gate
    any more (`note_versions` tells), it stays for the callers that unpack five."""
    target = Target(work, app)
    addon = work.addon_info(SLUG)
    version = target_version(work, app, target.info_url)
    return target, version, live_alembic(work, app, target), addon, None


def note_versions(sink, addon, version):
    """O-23, O-24, O-25, O-49: the add-on's version that the table does not know, this device's version that cannot be read
    and two different versions are notices; the structure version and the tables decide (judge)."""
    addon_version = addon.version if addon else ''
    for issue in VERSIONS.issues(addon_version, version):
        if issue.id != 'version.different':
            sink.add(issue)
            continue
        sink.notice('omnigent.version-different',
                    f'HA 的 Omnigent 是 {haissues.clean(VERSIONS.upstream(addon_version), 40)}（附加元件 {haissues.clean(addon_version, 40)}），'
                    f'這台是 {haissues.clean(version, 40)}；版本不同本身不擋，資料庫結構版本和資料表欄位相同才會匯入。')


def pg_major(work, app, target):
    """The PostgreSQL major of the image that opens HA's data: its PG_MAJOR; an image without one is asked through the
    database it runs here (O-18); None when neither says (then PostgreSQL itself refuses a cluster it cannot open)."""
    major = ha_odoo.target_pg_major(work, app, target.db_image)
    if major is not None:
        return major
    try:
        value = hacommon.live_json(work, app, target.db_container, target.db_user, target.database,
                                   "SELECT to_json(current_setting('server_version_num')::int / 10000)")
    except BackupError as error:
        if error.code != 'job-failed':
            raise
        return None
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def unregistered_secrets(work, app):
    """The secrets this device's Quadlet files use that the app settings do not list, and those listed twice (O-48): only
    names, read from the Quadlet files, never a value."""
    declared = [item['name'] for item in app.secrets]
    referenced = {spec.split(',', 1)[0] for text in work.quadlets(app).values() for spec in tempctr.quadlet_secrets(text)}
    return sorted(referenced - set(declared)) + sorted({n for n in declared if declared.count(n) > 1})


def note_secrets(sink, names):
    if names:
        sink.notice('omnigent.secrets-unregistered', '這台 Omnigent 用到的機密沒有全部登記在應用設定裡（或登記了兩次）；原地匯入不受影響，'
                    '但之後把備份還原到全新的設備時會少這些機密，服務起不來。請補登它們。', names)


def check(work, app):
    sink = _sink(work, app)
    tmp = work.temp(app)
    target = Target(work, app, sink)
    hatarget.ensure_image(work, app, target.db_image)
    addon = work.addon_info(SLUG)
    version = target_version(work, app, target.info_url)
    alembic = live_alembic(work, app, target)
    note_versions(sink, addon, version)
    note_secrets(sink, unregistered_secrets(work, app))
    pg_ids = tmp.user_ids('ids-pg', target.db_image, 'postgres')
    report = habackup.Report(names=haissues.Names)
    src = member_pass(work, app, tmp, pg_ids, report=report)
    sink.skipped(report)
    if src.pg_links.count:
        sink.auto('omnigent.hardlinks-copied', f'HA 的資料庫資料夾裡有 {src.pg_links.count} 個硬連結（正常的資料庫不會有），'
                  '匯入時會把它們當成一般檔案複製。', src.pg_links)
    work.phase('check')
    cluster = ha_odoo.start_ha_cluster(work, tmp, target.db_image)
    found = analyse(cluster, sink)
    ha_schema = read_schema(cluster, found['alembic'])
    tmp.remove('hapg')
    tmp.remove_volume('hapg')
    differ = (schema_differences(ha_schema, live_schema(work, app, target), ignore=unknown_tables(found))
              if alembic is not None else None)   # no structure version of this device: judge says so
    conflicts = account_conflicts(found, target)
    judge(sink, src, found, live_alembic_value=alembic, ha_major=_ha_major(src),
          target_major=pg_major(work, app, target), differ=differ)
    if conflicts:
        sink.notice('omnigent.account-conflict', 'HA 也有和這台相同名稱的帳號，匯入後以 HA 的帳號為準，這台的管理者或 runner 密碼對它不再適用。',
                    conflicts)
    return {'target_version': version or '',
            'omnigent': section(src, found, version=VERSIONS.upstream(addon.version if addon else ''),
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


def data_only_toc(text, *, tables=None, sequences=None, skipped=None):
    """Only the table data and sequence values of a locally generated custom archive (its `pg_restore -l` list), as
    the `-L` list of the data restore. pg_restore reads nothing of a selected line but the dump id at its start, so a
    name in HA's database that carries a line break could add an entry of its own choice: with `tables`/`sequences`
    (the trusted schema's names) an entry is selected only when it names exactly one of them, each at most once; an entry
    that names anything else is not selected and is counted in `skipped` (a haissues.Names: O-28, HA's tables and
    sequences that are not Omnigent's); one trusted name twice, a line that is no entry and an empty selection stop."""
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
                if not entry or entry.group(2) not in allowed:
                    if skipped is not None:
                        skipped.add(match.group(2)[:200])
                    continue
                if entry.groups()[:2] in named:
                    raise BackupError('incompatible', 'HA 的資料庫匯出清單有同一個資料項目出現兩次，無法安全地搬過來。')
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
for n in $(seq 1 __WAIT__); do
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


class _BadSnapshot(BackupError):
    """The snapshot's first line is no list of columns (O-32, O-33): a read of the live database that went wrong, tried again."""

    def __init__(self, app):
        super().__init__('incompatible', '目標 Omnigent 的結構快照格式不正確。', app=app.id)


def _snapshot_worth_another_try(error):
    """O-32, O-33, O-58, O-59: a snapshot that was not taken (psql ended by itself: no connection, no lock within 15 s, an SQL
    failure: exit 21; no columns within the wait or another revision: exit 22) or came back damaged; not a snapshot id that
    is no id (exit 23), and nothing that stays (a missing image, a refused login)."""
    if isinstance(error, _BadSnapshot):
        return True
    return hatarget.transient(error) and getattr(error, 'returncode', None) != 23


def capture_consistent_target_schema(work, app, target, path, expected_alembic):
    """Capture schema, revision and column signature from one exported snapshot.

    PostgreSQL table locks do not cover every DDL object, so this capture alone does
    not prove that no schema change ran meanwhile. Nobody has to promise it either:
    the import's only caller, trusted_schema, compares the live schema (signature,
    columns, revision) before and after the capture, and the columns returned here,
    and stops the job when anything differs.

    A snapshot that was not taken is tried again, SNAPSHOT_ATTEMPTS times in all, each time with a longer wait for the
    columns (60, 120, 180 seconds): this device may be busy (O-58, O-59), answer badly for a moment (O-32, O-33). What is
    left of a failed try is removed before the next one.
    """
    if not expected_alembic or any(not isinstance(v, str) or not ALEMBIC_RE.fullmatch(v) for v in expected_alembic):
        raise BackupError('incompatible', '目標 Omnigent 的結構版本不明。', app=app.id)
    revision = json.dumps(sorted(expected_alembic), ensure_ascii=True)
    tries = []

    def attempt():
        tries.append(1)
        script = SNAPSHOT_SCRIPT.replace('__REVISION__', revision.replace("'", "''"))
        script = script.replace('__COLUMNS__', ' '.join(SCHEMA_COLUMNS_SQL.split()))
        script = script.replace('__WAIT__', str(60 * len(tries)))
        return _capture_once(work, app, target, path, script)

    return hatarget.retry(attempt, attempts=SNAPSHOT_ATTEMPTS, retry_if=_snapshot_worth_another_try, abort=_abort(work),
                          log=_log(work), what='擷取這台 Omnigent 的資料庫結構快照')


def _capture_once(work, app, target, path, script):
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
                raise _BadSnapshot(app) from None
            if not isinstance(columns, list) or not columns or any(not isinstance(v, list) or len(v) != 6 for v in columns):
                raise _BadSnapshot(app)
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


# HA's rows that this device's schema refuses (a CHECK or NOT NULL constraint, a duplicate key, a reference to a row that
# is not there, a value its column type rejects; the schema comparison covers columns, sequences and types, not
# constraints): pg_restore stops (--exit-on-error, one transaction, nothing of it stays) and the job says why in plain
# words (security review 2026-11-23 v5: the message only said that a command failed). pg_restore's stderr is kept for
# diagnostics only and never shown or logged (it can hold HA's row values); it only tells these failures from others.
DATA_REFUSED = ('HA 的 Omnigent 資料不符合這台 Omnigent 的資料庫結構（例如違反欄位的檢查條件、必填的欄位是空的、'
                '資料重複或參照的資料不存在），無法匯入；這台的應用沒有任何變更。')
DATA_REFUSED_RE = re.compile(rb'violates (?:check|not-null|foreign key|unique|exclusion) constraint'
                             rb'|could not create unique index|invalid input (?:syntax|value) for'
                             rb'|value too long for type|out of range for type|invalid byte sequence for encoding'
                             rb'|missing data for column|extra data after last expected column')


def load_into_new_cluster(tmp, role, argv, path):
    """One pg_restore of the archive `path` into the new cluster; HA's rows refused by this device's schema end the job
    with DATA_REFUSED ('incompatible'), every other failure as it was."""
    with open(path, 'rb') as handle:
        try:
            tmp.exec(role, argv, user='postgres', input=handle, timeout=DUMP_TIMEOUT, max_output=1024 * 1024)
        except CommandError as error:
            if DATA_REFUSED_RE.search(error.stderr or b''):
                raise BackupError('incompatible', DATA_REFUSED, stage='data') from None
            raise


def restore_trusted_data(work, tmp, schema_dump, data_dump, superuser, *, source_columns, role='omni-db',
                         tables=None, sequences=None, skipped=None):
    """Load the trusted target schema and only data from HA (`tables`/`sequences`: data_only_toc's names; `skipped`: what
    names HA's entries of other tables and sequences are counted in).

    Both archives must be generated by our own pg_dump; schema_dump must come from
    the trusted target. The caller must compare Alembic revisions before calling.
    The role and its limited grants remain until finish_trusted_data is called.
    """
    cluster = ha_odoo.Cluster(tmp, role, superuser=superuser, log=work.log)
    with open(data_dump, 'rb') as handle:
        listing = tmp.exec(role, ['pg_restore', '-l'], user='postgres', input=handle,
                           timeout=DUMP_TIMEOUT, max_output=ha_odoo.TOC_OUTPUT).stdout or b''
    text = listing.decode('utf-8', 'surrogateescape')
    selection = data_only_toc(text, tables=tables, sequences=sequences, skipped=skipped)
    sets = sequence_set_lines(selection)
    if sets:
        cluster.write_file('/tmp/woowbk-omnigent-seq.toc', ('\n'.join(sets) + '\n').encode('utf-8', 'surrogateescape'))
        with open(data_dump, 'rb') as handle:
            script = tmp.exec(role, ['pg_restore', '-f', '-', '-L', '/tmp/woowbk-omnigent-seq.toc'], user='postgres',
                              input=handle, timeout=DUMP_TIMEOUT, max_output=SEQUENCE_SCRIPT_OUTPUT).stdout or b''
        require_sequence_sets(script.decode('utf-8', 'surrogateescape'), len(sets), sequences)
    kinds = [kind for kind in toc_kinds(text) if kind not in ('TABLE DATA', 'SEQUENCE SET')]
    work.log(f'HA 的資料庫匯出清單：只載入資料（TABLE DATA、SEQUENCE SET），略過 {len(kinds)} 種結構項目'
             + (f'（{hacommon.names(kinds, 8)}）' if kinds else ''))
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
    load_into_new_cluster(tmp, role, ['pg_restore', '-U', RESTORE_ROLE, '--no-owner', '--no-acl', '--exit-on-error',
                                      '--single-transaction', '-L', '/tmp/woowbk-omnigent.toc', '-d', DATABASE],
                          data_dump)
    # post-data (primary keys, unique indexes, foreign keys) is this device's; it fails on HA's duplicate or dangling rows
    load_into_new_cluster(tmp, role, ['pg_restore', '-U', superuser, '--no-owner', '--no-acl', '--exit-on-error',
                                      '--single-transaction', '--section=post-data', '-d', DATABASE], schema_dump)
    tmp.exec(role, ['rm', '-f', '/tmp/woowbk-omnigent.toc'], user='postgres', timeout=120)
    return cluster


def blank_locations(cluster, locations):
    """O-21: the agent bundle locations of HA's database that could make Omnigent read outside the artifact store are cleared
    in the new cluster, by the role without privileges, which gets the right to read and change this ONE column for it. The
    names travel as one JSON text on the statement's stdin and are compared as they are: nothing of HA's text is ever part
    of a command line or of the statement itself."""
    if not locations:
        return
    payload = ha_odoo.sql_literal(json.dumps(sorted(locations), ensure_ascii=True))
    cluster.script(f'GRANT SELECT (bundle_location), UPDATE (bundle_location) ON public.agents TO {RESTORE_ROLE};\n', DATABASE)
    loader = ha_odoo.Cluster(cluster.tmp, cluster.role, superuser=RESTORE_ROLE, log=cluster.log)
    loader.script("UPDATE public.agents SET bundle_location = '' WHERE bundle_location IN "
                  f"(SELECT json_array_elements_text({payload}::json));\n", DATABASE)


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
    """This device's schema, read from the LIVE database as the app owner (read only). An answer that is not what was asked
    for is read again (O-40, O-41: hatarget.retry, READ_ATTEMPTS in all); a database that is not running is started by
    `live_json` first (CM-07); only a structure that cannot be read at the end stops this app."""
    def read_columns():
        columns = hacommon.live_json(work, app, target.db_container, target.db_user, target.database, SCHEMA_COLUMNS_SQL)
        if not isinstance(columns, list) or not columns or any(not isinstance(r, list) or len(r) != 6 for r in columns):
            raise _Odd('這台 Omnigent 的資料表結構讀到的不是欄位清單。', app)
        return columns

    def read_signature():
        value = hacommon.live_json(work, app, target.db_container, target.db_user, target.database, SCHEMA_SIGNATURE_SQL)
        if not isinstance(value, dict) or set(value) != set(SIGNATURE_KEYS):
            raise _Odd('這台 Omnigent 的資料庫結構讀到的不完整。', app)
        return value
    try:
        columns = _again(work, read_columns, '讀取這台 Omnigent 的資料表結構')
    except _Odd:
        raise BackupError('incompatible', '無法確認這台 Omnigent 的資料表結構。', app=app.id) from None
    try:
        signature = _again(work, read_signature, '讀取這台 Omnigent 的資料庫結構')
    except _Odd:
        raise BackupError('incompatible', '無法確認 Omnigent 的資料庫結構。') from None
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


def schema_differences(ha, trusted, *, ignore=()):
    """The names (tables, sequences, types) whose DATA shape differs between HA and the trusted schema: the columns
    (name, type, not null, identity, generated; in order), the sequences (type, owning column) and the types.
    Defaults, constraints and indexes are never compared: HA's are never used, the trusted ones apply. `ignore`: HA's tables
    that are not Omnigent's and are not moved (O-12): they and the sequences that belong to their columns are not compared
    (a table that this device has too would then stop the conversion where the new cluster's columns are compared with HA's:
    the columns of the tables that are moved)."""
    ignored = set(ignore)
    differ = set()
    ha_cols, trusted_cols = _by(ha.columns, 6), _by(trusted.columns, 6)
    differ |= {t for t in set(ha_cols) | set(trusted_cols) if t not in ignored and ha_cols.get(t) != trusted_cols.get(t)}
    pick = lambda rows: {str(r[0]): (r[1], r[8]) for r in rows or [] if isinstance(r, list) and len(r) == 9}  # noqa: E731
    ha_seq, trusted_seq = pick(ha.signature.get('sequences')), pick(trusted.signature.get('sequences'))
    own = lambda owner: str(owner).split('.', 1)[0] in ignored  # noqa: E731 - a sequence of a column of an ignored table
    differ |= {s for s in set(ha_seq) | set(trusted_seq)
               if ha_seq.get(s) != trusted_seq.get(s) and not (s not in trusted_seq and own(ha_seq[s][1]))}
    ha_types, trusted_types = _by(ha.signature.get('types'), 6), _by(trusted.signature.get('types'), 6)
    differ |= {t for t in set(ha_types) | set(trusted_types) if ha_types.get(t) != trusted_types.get(t)}
    return sorted(differ)


def moved_columns(columns, ignore):
    """HA's columns of the tables that are moved (the new cluster has only this device's tables, O-12)."""
    return [row for row in columns if row[0] not in set(ignore)]


def schema_blocker(differ):
    return (f'HA 與這台 Omnigent 的資料庫結構不同（{hacommon.names(differ)}）：只能搬到資料表與欄位完全相同的 Omnigent，'
            '請先讓兩邊的 Omnigent 版本一致後再匯入。')


class _Unsteady(BackupError):
    """This device's structure moved while it was read (a server that upgrades or restarts): waited for, then read again."""

    def __init__(self, app):
        super().__init__('incompatible', SCHEMA_CHANGED, app=app.id)


def trusted_schema(work, app, target, path, alembic):
    """This device's schema as the new cluster gets it: `path` is its `pg_dump --schema-only` taken in one exported
    snapshot; the live schema (signature, columns, alembic) before and after the capture and the snapshot's columns
    must all be equal -- no DDL ran meanwhile (enforced here, not promised by a caller). When this device is not steady --
    its structure version is not the one the import started with, or anything changed while the snapshot was taken (an
    upgrade, a restart: O-42, O-43) -- it is waited for and read again, STEADY_ATTEMPTS times in all (hatarget.retry); only
    one that keeps changing stops the job, and nothing of this device was touched."""
    def attempt():
        before = live_schema(work, app, target)
        if before.alembic != sorted(alembic or []):
            raise _Unsteady(app)
        columns = capture_consistent_target_schema(work, app, target, path, alembic)
        after = live_schema(work, app, target)
        if columns != before.columns or after != before:
            path.unlink(missing_ok=True)
            raise _Unsteady(app)
        return before

    return hatarget.retry(attempt, attempts=STEADY_ATTEMPTS, pause_first=5.0, factor=3.0, longest=60.0,
                          retry_if=lambda error: isinstance(error, _Unsteady), abort=_abort(work), log=_log(work),
                          what='這台 Omnigent 的資料庫結構還在變動，等它穩定後再讀取')


def extension_drift(found, trusted):
    """['pg_trgm 1.5 -> 1.6', ...] when the only difference between the two `extensions` parts of a schema signature is the
    version of an extension both have (O-44: the new cluster takes the extension version of the image, this device's may be
    older; a newer extension is what an update would make, nothing of Omnigent depends on it), else None."""
    now = {(row[0], row[2]): row[1] for row in found if isinstance(row, list) and len(row) == 3}
    live = {(row[0], row[2]): row[1] for row in trusted if isinstance(row, list) and len(row) == 3}
    if len(now) != len(found) or len(live) != len(trusted) or set(now) != set(live):
        return None
    return [f'{name[0]} {live[name]} -> {now[name]}' for name in sorted(now) if now[name] != live[name]]


def require_schema(cluster, trusted, stage):
    """The new cluster's schema signature equals the trusted one (after the post-data section, after the last write). Only the
    version of an extension may differ (O-44); those are returned (['pg_trgm 1.5 -> 1.6']) for the line that says so."""
    found = schema_signature(cluster)
    differ = [key for key in SIGNATURE_KEYS if found.get(key) != trusted.signature.get(key)]
    drift = []
    if 'extensions' in differ:
        versions = extension_drift(found.get('extensions') or [], trusted.signature.get('extensions') or [])
        if versions is not None:
            differ.remove('extensions')
            drift = versions
    if differ:
        raise BackupError('job-failed', f'新的 PostgreSQL 叢集的資料庫結構和這台 Omnigent 的不同（{"、".join(differ)}），'
                                        '已停止，這台的應用沒有任何變更。', stage=stage)
    return drift


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
                # counts name the table and both numbers; the other answers only their name (never a value). The
                # names are HA's (a crafted cluster chooses its answers' keys): cut, no control characters (SR-4 class)
                shown = hacommon.names([name])
                differ.append(f'{shown}（HA {a.get(name)}，實際 {b.get(name)}）' if part == 'counts' else shown)
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


def convert(work, app, test_mode, out_dir):
    """Build the app's volumes in `out_dir/volumes` (module docstring: the trusted schema, HA's data only); returns
    {volumes {name: path}, counts, kept_accounts, conflicts, paused_tasks, ...}. The same findings as the check come again
    from the sink (a stop raises, a line the customer did not confirm raises `confirmation-required`) before anything of HA
    is dumped."""
    sink = _sink(work, app)
    unregistered = unregistered_secrets(work, app)      # O-48: names only, from the Quadlet files
    adapter = work.adapter(app)
    tmp = work.temp(app)
    target = Target(work, app, sink)
    hatarget.ensure_image(work, app, target.db_image)
    addon = work.addon_info(SLUG)
    version = target_version(work, app, target.info_url)
    alembic = live_alembic(work, app, target)
    note_versions(sink, addon, version)
    note_secrets(sink, unregistered)
    ids = adapter.owner_ids()
    staging = work.staging / 'omnigent-work'
    staging.mkdir(mode=0o700)
    (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
    pg_ids = tmp.user_ids('ids-pg', target.db_image, 'postgres')
    report = habackup.Report(names=haissues.Names)
    artifacts = hacommon.TreeTar(staging / 'ha-artifacts.tar', 0, 0, work.guard)
    try:
        src = member_pass(work, app, tmp, pg_ids, artifacts=artifacts, report=report)
    finally:
        artifacts.close()
    sink.skipped(report)
    if src.pg_links.count:
        sink.auto('omnigent.hardlinks-copied', f'HA 的資料庫資料夾裡有 {src.pg_links.count} 個硬連結（正常的資料庫不會有），'
                  '匯入時會把它們當成一般檔案複製。', src.pg_links)
    work.phase('convert')
    work.guard.check(2 * src.pg_bytes + ha_odoo.WAL_ALLOWANCE)
    cluster = ha_odoo.start_ha_cluster(work, tmp, target.db_image)
    found = analyse(cluster, sink)
    judge(sink, src, found, live_alembic_value=alembic, ha_major=_ha_major(src), target_major=pg_major(work, app, target))
    ha_schema = read_schema(cluster, found['alembic'])
    ignored = unknown_tables(found)
    dump = staging / 'omnigent.dump'
    work.log('匯出 HA 的 Omnigent 資料（只當作資料來源，HA 的資料庫結構不會使用）')
    with open(dump, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        tmp.exec('hapg', ['pg_dump', '-U', 'postgres', '-Fc', '-d', DATABASE], user=dump_user(ids, pg_ids),
                 stdout=handle, timeout=DUMP_TIMEOUT, max_output=work.guard.budget())
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
    differ = schema_differences(ha_schema, trusted, ignore=ignored)
    if differ:
        sink.stop('omnigent.schema-different', schema_blocker(differ), action=ACTION_UNCHANGED)
    work.log('用這台的資料庫結構建立資料表，只把 HA 的資料（資料列與序號）以沒有任何管理權限的暫用角色載入')
    entries = haissues.Names()
    restore_trusted_data(work, tmp, schema_dump, dump, target.db_user, source_columns=moved_columns(ha_schema.columns, ignored),
                         tables=trusted.tables(), sequences=trusted.sequences(), skipped=entries)
    if entries.count:
        sink.notice('omnigent.entries-skipped', f'HA 的資料庫匯出清單有 {entries.count} 個不屬於這台 Omnigent 的資料項目，沒有載入。',
                    entries)
    os.unlink(dump)
    os.unlink(schema_dump)
    drift = list(require_schema(pg, trusted, 'restored'))
    require_answers(pg, found)
    unsafe = bundle_locations(found)[1]
    if unsafe:     # O-21: the locations that could leave the artifact store are cleared, as the role without privileges
        blank_locations(pg, unsafe)
        if bundle_locations({'keys': pg.query_json(KEYS_SQL, DATABASE) or {}})[1]:
            raise BackupError('job-failed', '新資料庫裡仍有會跑出檔案區的代理程式位置，已停止；這台的應用沒有任何變更。')
        work.log(f'清空了 {len(unsafe)} 個會跑出檔案區的代理程式位置')
    kept = carry_accounts_restricted(pg, live_users(work, app, target, sink))
    conflicts = account_conflicts(found, target)
    paused = 0
    if test_mode:
        paused = ha_odoo._int(pg.query_json(ACTIVE_SQL, DATABASE))
        work.log(f'測試匯入：暫停 {paused} 個啟用中的 Omnigent 排程')
        ha_odoo.Cluster(tmp, 'omni-db', superuser=RESTORE_ROLE, log=work.log).script(PAUSE_SQL, DATABASE)
        if ha_odoo._int(pg.query_json(ACTIVE_SQL, DATABASE)):
            raise BackupError('job-failed', '測試匯入沒有暫停全部 Omnigent 排程。')
    finish_trusted_data(pg)
    drift += require_schema(pg, trusted, 'loaded')
    if drift:
        sink.auto('omnigent.extension-version', '新資料庫的擴充功能版本和這台原本的不同（新的是這台映像附的版本，Omnigent 不受影響）。',
                  sorted(set(drift)))
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
    if code != 0:    # O-54: the control file below is the proof of a clean stop (a PostgreSQL that was killed says so there)
        work.log(f'新的 PostgreSQL 叢集關閉時結束碼是 {code}；以 pg_controldata 的狀態判斷它有沒有正常關閉。')
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

    live_report = habackup.Report(names=haissues.Names)
    server_path = server_volume(work, app, target, staging, out_dir, report=live_report)
    pi_path = out_dir / 'volumes' / f'{target.pi_volume}.tar'
    hacommon.live_export(work, app, target.pi_volume, pi_path)
    carried = {'volumes': {}}
    if target.extra_volumes:   # O-07: this device's other volumes of the app, as they are
        carried = hatarget.carry(work, app, out_dir, ids, volumes=target.extra_volumes, report=live_report)
    sink.skipped(live_report)
    for path in (db_path, server_path, pi_path):
        ha_odoo.check_volume_tar(path, ids)
    volumes = {target.db_volume: db_path, target.server_volume: server_path, target.pi_volume: pi_path,
               **carried['volumes']}
    return {'volumes': volumes,
            'counts': {k: found['detail'].get(k, 0) for k in ('users', 'conversations', 'scheduled_tasks', 'hosts')},
            'kept_accounts': kept, 'conflicts': conflicts, 'paused_tasks': paused,
            'accounts_unreadable': any(issue.id == 'omnigent.accounts-unreadable' for issue in sink.found),
            'scheduled_tasks_active': ha_odoo._int(found['detail'].get('scheduled_tasks_active')),
            'public_sessions': ha_odoo._int(found['detail'].get('public_sessions')),
            'overrides': list(src.overrides), 'hosts': ha_odoo._int(found['detail'].get('hosts')),
            'extra_volumes': list(target.extra_volumes), 'cookie_missing': not src.cookie,
            'skipped': skipped_names(src, found)[0].count, 'cleared_locations': len(unsafe)}


def _convert_candidate(work, app, test_mode, out_dir, *, schema_ddl_quiesced=None):
    """Lab compatibility entry of the 2026-11-20..23 internal-candidate harnesses: the product conversion. `convert` enforces
    the capture's stability itself (trusted_schema), so the caller's promise that this device's DDL is quiet is no
    condition any more (O-56: only these harnesses ever called it); the argument is still accepted for them."""
    return convert(work, app, test_mode, out_dir)


def server_volume(work, app, target, staging, out_dir, report=None):
    """omnigent-server-data: the live export without `artifacts/**`, plus HA's artifacts owned like the live
    artifacts folder (or the volume's top folder). A link of this device's own data that leaves the volume is left out
    and listed in `report` (X-NS-08). The top folder's owner and mode are those read last (O-57: a change between the two
    readings is no reason to stop)."""
    import tarfile
    live = hacommon.live_export(work, app, target.server_volume, staging / 'live-server.tar')
    path = out_dir / 'volumes' / f'{target.server_volume}.tar'
    root = ha_n8n.volume_root(work, app, target.server_volume)
    out = hacommon.FileTar(path, work.guard)
    try:
        hacommon.top_only(out, root)
        dirs = hacommon.copy_live(live, out, drop=lambda name: name == '.' or ha_odoo._under(name, 'artifacts'),
                                  what='這台 Omnigent 的伺服器資料卷', report=report, label=f'{target.server_volume}：')
        # Podman exports may omit the root directory. Preserve its actual
        # namespace metadata through the existing bounded owner interface.
        if '.' in dirs and dirs['.'] != root and callable(getattr(work, 'log', None)):
            work.log('這台 Omnigent 伺服器資料卷的根目錄權限在匯出前後不同，以最後讀到的為準。')
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
    if data.get('cookie_missing'):
        notes.append('HA 備份裡沒有可用的登入金鑰，匯入後 Omnigent 會自己產生新的；所有瀏覽器、裝置授權和權杖都要重新登入，外部連線可能要重連。')
    kept = data.get('kept_accounts') or []
    if kept:
        notes.append(f'這台 Omnigent 的管理者與 runner 帳號（{hacommon.names(kept)}）會保留，密碼不變。')
    conflicts = data.get('conflicts') or []
    if conflicts:
        notes.append(f'HA 也有帳號 {hacommon.names(conflicts)}：匯入後以 HA 的為準，這台設定的密碼對它不再適用，'
                     '請用 HA 的密碼登入，必要時更新這台的應用機密。')
    if data.get('overrides'):
        notes.append('HA 的 Omnigent 分享與管理者執行期設定不會搬過來，這台維持自己的設定。')
    if data.get('skipped'):
        notes.append(f'HA 的 Omnigent 備份裡有 {data["skipped"]} 個這台搬不過來的項目（資料表、物件、擴充功能、連結或不安全的檔案位置），'
                     '已依匯入前的確認略過，其餘資料照常搬過來。')
    if data.get('cleared_locations'):
        notes.append(f'{data["cleared_locations"]} 個代理程式的檔案位置可能跑出檔案區，已清空；那些代理程式要在 Omnigent 裡重新設定。')
    if data.get('extra_volumes'):
        notes.append(f'這台 Omnigent 的其他資料卷（{hacommon.names(data["extra_volumes"])}）照現在的內容原樣帶過去。')
    reminders = ['匯入後請用 HA 那邊的 Omnigent 帳號和密碼登入。',
                 '請把每一台 runner（例如 HA 的 Pi Agent、其他電腦上的 omnigent host）改連到這台的 Omnigent 網址並重新登入；'
                 '在那之前 HA 的 runner 會顯示離線。']
    if data.get('accounts_unreadable'):
        reminders.append('這台原有的管理者與 runner 帳號沒有讀到，沒有保留；請用 HA 的帳號登入，並重新建立 runner 的帳號。')
    if data.get('paused_tasks'):
        reminders.append(f'測試匯入已暫停 {data["paused_tasks"]} 個排程，確認無誤後再到 Omnigent 重新啟用。')
    elif data.get('scheduled_tasks_active'):
        reminders.append(f'HA 的 {data["scheduled_tasks_active"]} 個啟用中的排程會在這台執行，請確認它們有可用的 runner。')
    if data.get('public_sessions'):
        reminders.append(f'HA 有 {data["public_sessions"]} 個公開分享的工作階段，搬過來後仍然公開，請確認是否需要。')
    return notes, reminders
