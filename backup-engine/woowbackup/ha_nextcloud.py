"""Home Assistant import, Nextcloud part: the WOOWTECH add-on `woow-nextcloud-office` -> this device's app `nextcloud`
(CONTRACT section 9 "Home Assistant import", "Batch 2: Nextcloud"; facts phase3/facts/nextcloud.md). Owner: E2.

The add-on is all in one container: a PostgreSQL 16 cluster (`data/postgres`, socket only, trust), Nextcloud's
`config.php` and the app-store apps (`data/nextcloud/config`, `data/nextcloud/custom_apps`), Redis (cache and file
locks only) and Collabora (stateless). The users' files live OUTSIDE the add-on, in Nextcloud's data directory
(`datadirectory` of config.php, by default /share/nextcloud): they are in the HA backup only when its `share` folder
was included (`share.tar[.gz]`, entries `nextcloud/**`); a data directory under /data or /config is read from the
add-on's own member. Without the data directory the import is refused (a database without its files would lose them).

The target is the Podman package (Woow_podman_nextcloud): five units, four host data dirs (catalog `data_dirs`: the
PostgreSQL cluster, Redis, the html dir with code, config.php and custom_apps, and the data dir), no volume and no
database dump (cold). Versions: HA's config.php `version` (4 parts, written by Nextcloud) must equal the live
config.php's, and its first three parts the live image's NEXTCLOUD_VERSION, so the image's entrypoint neither upgrades
nor refuses; HA's PostgreSQL major must not be newer than the target's.

check: the cluster is streamed into a throwaway volume and opened by a throwaway PostgreSQL 16 (socket only, network
none, HA's settings never used: ha_odoo.start_ha_cluster; every session pinned to pg_catalog names: Pinned); its
catalogs are read first and a database holding anything beyond Nextcloud's own tables, sequences and indexes
(functions, triggers, rules, views, operators, types, policies, CHECK constraints, generated columns, non-constant
defaults...: SHAPE_SQL) is refused without reading its tables; config.php is parsed strictly (never executed: only
arrays, single-quoted strings, numbers, booleans and null); the data directory is walked (it must exist with its
`.ncdata`; symlinks, server-side encryption and object storage are refused); counts, apps and storages are read.

convert: pg_dump of HA's database; a NEW cluster from the live database image, environment and secret (its superuser
password is the live one), the live Nextcloud database role (`dbuser` of the live config.php, e.g. oc_admin) with the
LIVE role's attributes and password verifier (read from the live cluster, passed on stdin, masked), the grants
Nextcloud's installer gives it (lib/private/Setup/PostgreSQL.php: CONNECT, REVOKE ALL FROM PUBLIC, CREATE on public),
the live extensions, then the dump restored AS THAT ROLE (`--no-owner --no-acl --exit-on-error --single-transaction`;
refused before the restore when its list holds a kind of object Nextcloud never creates: TOC_ALLOWED); then, every
session pinned, the superuser reads the catalogs only (the same SHAPE_SQL refusal, the role's attributes, no per-role
or per-database setting) and the fix-ups and table reads run as that role, never as the superuser; fix-ups: the root
storage id `local::<HA datadirectory>/` -> `local::<target datadirectory>/` and every local storage below it (Team
folders keep one each: storage_moves), Office (richdocuments wopi_url, public_wopi_url, wopi_callback_url,
wopi_allowlist, disable_certificate_verification) and core.backgroundjobs_mode exactly as the live database has them,
HA's cached Collabora discovery (`appdata_<id>/richdocuments/remoteData`, files and rows) replaced by this device's own
(the app never fetches it on demand) and the hourly job that refreshes it made due at once, so Office uses this device's
Collabora from the first minute; every count, owner, grant, extension and value is verified; PostgreSQL settings of the
live cluster are carried; clean stop, `pg_controldata` "shut down". config.php = the LIVE config.php (URLs, trusted domains, database
credentials, mail, caches, data directory) plus HA's `instanceid`, `passwordsalt`, `secret` (app data folder, ICrypto:
app passwords, TOTP, encrypted app values) and HA's two-factor enforcement and app_install_overwrite (owner decision
D1; never weaker than the target's enforcement) and a new `data-fingerprint` (what the package's own restore sets with
`occ maintenance:data-fingerprint`, so sync clients treat the server as restored); the live image's PHP parses it and
returns exactly the merged values.
The html dir is the live dir without config.php and without the custom apps HA brings, plus the merged config.php and
HA's custom apps (decision D2); the data dir is HA's data directory (owner www-data of the live image, top dir like
the live one; the web updater's own folder `updater-<instanceid>` skipped, previews kept: decision D5) with Nextcloud's
own `.htaccess` written on top: here the data dir is inside the web root and that file is what keeps the users' files
private (HA's data directory is outside its web root; any other `.htaccess` in it is refused); the Redis dir is empty;
the PostgreSQL dir is the new cluster (top dir like the live one).
"""
import base64
import hashlib
import hmac
import io
import json
import os
import re
import tarfile
import time
import xml.etree.ElementTree as ElementTree

from . import habackup, hacommon, haissues, ha_odoo, hatarget, nested, tempctr
from .errors import BackupError

SLUG = 'woow-nextcloud-office'
APP_ID = 'nextcloud'
PG_PREFIX = 'data/postgres'
CONFIG_PHP = 'data/nextcloud/config/config.php'
CUSTOM_APPS = 'data/nextcloud/custom_apps'
# What the add-on member holds besides a data directory (a data directory under /data must not overlap them).
ADDON_ITEMS = (PG_PREFIX, 'data/nextcloud/config', CUSTOM_APPS, 'data/redis', 'data/coolwsd-jail', 'data/coolwsd-cache',
               'data/options.json')
# Add-on version -> Nextcloud version (Woow_ha_nextcloud CHANGELOG.md, Dockerfile:60); display only: config.php's
# `version` is what is compared.
VERSIONS = hacommon.VersionTable('Nextcloud', {'0.2.1': '33.0.9', '0.2.2': '34.0.4', '0.2.3': '35.0.1',
                                               '0.2.4': '35.0.1'})
# Every issue of this module (haissues): id -> level. Rows of DESIGN K, lane NEXTCLOUD, are named in the comments.
ISSUES = {
    'nextcloud.config-unreadable': 'stop',        # NC-12: HA's config.php is more than a file of values (a variable, a function)
    'nextcloud.config-missing': 'stop',           # NC-12: HA's backup has no config.php
    'nextcloud.not-installed': 'stop',            # NC-13 (skip this app only)
    'nextcloud.maintenance-mode': 'notice',       # NC-14: in maintenance mode when HA made the backup, same version
    'nextcloud.maintenance-upgrading': 'stop',    # NC-14: ... and not the same version: an upgrade may have been half done
    'nextcloud.not-postgres': 'stop',             # NC-15
    'nextcloud.table-prefix': 'stop',             # NC-16
    'nextcloud.object-storage': 'stop',           # NC-17
    'nextcloud.no-identity': 'stop',              # NC-18
    'nextcloud.no-dbname': 'stop',                # NC-19
    'nextcloud.live-not-installed': 'stop',       # NC-10
    'nextcloud.version-unreadable': 'notice',     # NC-20: HA's version comes from the add-on's version
    'nextcloud.version-different': 'stop',        # NC-21
    'nextcloud.image-version': 'stop',            # NC-11
    'nextcloud.no-datadir-setting': 'stop',       # NC-24
    'nextcloud.no-share': 'confirm',              # NC-22: no share folder in the backup: the users' files stay behind
    'nextcloud.no-datadir': 'confirm',            # NC-23: ... no data folder (or no .ncdata) in it
    'nextcloud.datadir-elsewhere': 'confirm',     # NC-25: ... the data folder is somewhere a backup never holds
    'nextcloud.symlinks-skipped': 'confirm',      # NC-26
    'nextcloud.htaccess-skipped': 'confirm',      # NC-27
    'nextcloud.server-side-encryption': 'confirm',  # NC-28 (owner decision D8/S5)
    'nextcloud.hardlinks-copied': 'auto',         # NC-29
    'nextcloud.no-database': 'stop',              # NC-30 (skip this app only)
    'nextcloud.database-version': 'stop',         # NC-31
    'nextcloud.online-backup': 'stop',            # NC-33
    'nextcloud.no-database-name': 'stop',         # NC-35
    'nextcloud.not-nextcloud-db': 'stop',         # NC-36
    'nextcloud.shape-unreadable': 'stop',         # NC-37
    'nextcloud.db-objects': 'stop',               # NC-38: objects that cannot be left out
    'nextcloud.db-objects-skipped': 'confirm',    # NC-38, NC-45: functions and triggers of other apps are left out
    'nextcloud.db-objects-known': 'notice',       # NC-38, NC-45: ... and they are only those a known app (Memories) makes again by itself
    'nextcloud.extension-enabled': 'auto',        # NC-39: an extension this device's database image has is enabled
    'nextcloud.extension-missing': 'stop',        # NC-39: ... and one it has not
    'nextcloud.schemas-skipped': 'confirm',       # NC-40: only the schema public is moved
    'nextcloud.live-config-php': 'auto',          # NC-05: this device's config.php is read by its own PHP
    'nextcloud.live-config-unreadable': 'stop',   # NC-05: ... and could not be
    'nextcloud.db-role-created': 'auto',          # NC-07: the database role of config.php is made from config.php
    'nextcloud.db-role-unusable': 'stop',         # NC-07: ... and config.php has no password to make it from
    'nextcloud.db-role-hand-over': 'auto',        # NC-08: a superuser role: loaded by a plain one, handed over
    'nextcloud.office-settings-unread': 'notice',  # NC-09
    'nextcloud.settings-not-carried': 'notice',   # NC-49
    'nextcloud.storage-missing': 'stop',          # NC-41
    'nextcloud.storage-taken': 'stop',            # NC-42
}
NC_VERSION_RE = re.compile(r'[0-9]{1,4}(?:\.[0-9]{1,6}){2,3}\Z')
APP_ID_RE = re.compile(r'[a-z0-9_]{1,64}\Z')
INSTANCE_RE = re.compile(r'[a-z0-9]{6,40}\Z')
SECRET_VALUE_RE = re.compile(r'[A-Za-z0-9+/=._-]{8,512}\Z')
# A folder of the data directory's path as HA's config.php writes it: any name a person can type (spaces, Chinese ...), no
# control character (habackup leaves such a name out of what it hands out) and no slash (NC-25).
DATADIR_SEG_RE = re.compile(r'[^\x00-\x1f\x7f/]{1,255}\Z')
ROLE_RE = re.compile(r'[a-z_][a-z0-9_]{0,62}\Z')
# NC-05: this device's own PHP evaluates a config.php that is more than a file of values; the strict parser reads what it prints.
PHP_DUMP = ('ob_start(); include "/var/www/html/config/config.php"; ob_end_clean(); '
            'if (!isset($CONFIG) || !is_array($CONFIG)) { exit(3); } '
            'echo "<?php\\n\\$CONFIG = "; var_export($CONFIG); echo ";\\n";')
PLAIN_PASSWORD_RE = re.compile(r'[\x20-\x7e]{1,512}\Z')   # a password that SCRAM-SHA-256 takes as it is (no SASLprep change)
# What Nextcloud's installer makes of its database role (lib/private/Setup/PostgreSQL.php), for a role that is not there.
INSTALLER_ROLE = {'super': False, 'login': True, 'createdb': True, 'createrole': False, 'replication': False,
                  'bypassrls': False, 'connlimit': -1}
LOADER = 'woowbk_load'    # NC-08: the plain role that loads HA's data when the database role of Nextcloud is a superuser
EXT_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_-]{0,62}\Z')
DB_RE = re.compile(r'[a-z_][a-z0-9_]{0,62}\Z')
STAT_RE = re.compile(rb'\s*([0-9]{1,10}) ([0-9]{1,10}) ([0-7]{1,4})\s*\Z')
MAX_CONFIG = 1024 * 1024
MAX_INFO_XML = 256 * 1024
MAX_DEPTH = 16
MAX_ITEMS = 20000
PREFIX = 'oc_'
# Files of an online (hot) backup: a cold HA backup (the add-on is `backup: cold`) has neither, and tablespace_map makes
# the server create tablespace links itself (the class of LiteLLM review SR-4): never streamed, refused.
RECOVERY_FILES = ('backup_label', 'tablespace_map')
# config.php keys taken from HA: the instance identity (appdata_<instanceid>, ICrypto `secret`, legacy hashes).
FROM_HA = ('instanceid', 'passwordsalt', 'secret')
# Owner decision D1 (facts nextcloud.md section 5): HA's two-factor enforcement and app_install_overwrite (the apps
# copied from HA) are carried; a live enforcement HA lacks stays (never weaker).
TWOFACTOR = ('twofactor_enforced', 'twofactor_enforced_groups', 'twofactor_enforced_excluded_groups')
FROM_HA_POLICY = TWOFACTOR + ('app_install_overwrite',)
# HA keys that describe HA's own installation (the target keeps its values); never listed as "not carried".
HA_OWN = frozenset({'version', 'installed', 'dbtype', 'dbhost', 'dbname', 'dbuser', 'dbpassword', 'dbport',
                    'dbtableprefix', 'datadirectory', 'trusted_domains', 'overwrite.cli.url', 'overwritehost',
                    'overwriteprotocol', 'overwritewebroot', 'trusted_proxies', 'memcache.local', 'memcache.locking',
                    'memcache.distributed', 'redis', 'maintenance', 'maintenance_window_start', 'default_phone_region',
                    'apps_paths', 'logfile', 'loglevel', 'log_type', 'logtimezone', 'allow_local_remote_servers',
                    'htaccess.RewriteBase', 'upgrade.disable-web', 'check_data_directory_permissions',
                    'data-fingerprint'})
SECRET_KEYS = ('secret', 'passwordsalt', 'dbpassword', 'mail_smtppassword')
# The Office (richdocuments) settings and the core setting the target keeps exactly as its live database has them.
LIVE_APPCONFIG = (('richdocuments', 'wopi_url'), ('richdocuments', 'public_wopi_url'),
                  ('richdocuments', 'wopi_callback_url'), ('richdocuments', 'wopi_allowlist'),
                  ('richdocuments', 'disable_certificate_verification'), ('core', 'backgroundjobs_mode'))
# richdocuments reads Collabora's discovery and capabilities only from its cache: Redis (empty after the import), else
# these files of `appdata_<instanceid>/richdocuments/remoteData` (12.0.1 lib/Service/CachedRequestService.php get(): it
# never fetches on demand; without them opening a document is an HTTP 500, share attempt 5 of 2026-11-24). An hourly
# background job refreshes them (lib/Backgroundjobs/ObtainCapabilities.php:30,40-50).
OFFICE_CACHE = ('capabilities', 'discovery')
MAX_OFFICE_CACHE = 4 * 1024 * 1024
OFFICE_JOB = 'OCA\\Richdocuments\\Backgroundjobs\\ObtainCapabilities'
OFFICE_COMMAND = 'podman exec -u www-data {container} php occ richdocuments:activate-config'
# Counted in HA's database and again after the restore (table -> key); optional tables only when they exist.
COUNTED = (('oc_users', 'users'), ('oc_filecache', 'files'), ('oc_share', 'shares'), ('oc_authtoken', 'tokens'),
           ('oc_calendarobjects', 'calendar_objects'), ('oc_cards', 'contacts'), ('oc_storages', 'storages'),
           ('oc_mounts', 'mounts'), ('oc_external_mounts', 'external_mounts'))
EXTENSIONS_OK = frozenset({'plpgsql'})
# Client options of every session the engine opens in a cluster that holds HA's (untrusted) objects: HA's own
# throwaway cluster, and the new cluster once HA's dump is restored into it. libpq's PGOPTIONS is a client setting
# (PGC_S_CLIENT, above per-database and per-role settings), so every name resolves in pg_catalog only and no function,
# operator or table of HA's database can stand in for a built-in (the class of LiteLLM review SR-1).
PINNED_OPTIONS = '-c search_path=pg_catalog'
# pg_restore list entry kinds a Nextcloud database consists of (dev-e's Nextcloud 35.0.1 on PostgreSQL 16, read
# 2026-11-24: TABLE, TABLE DATA, SEQUENCE, SEQUENCE SET, SEQUENCE OWNED BY, DEFAULT, CONSTRAINT, FK CONSTRAINT, INDEX,
# COMMENT, ACL, EXTENSION). Any other kind (functions, triggers, rules, views, operators, types, policies...) is refused
# before the restore: nothing of HA's may run as code in the new cluster, nor later on this device.
TOC_ALLOWED = frozenset({'TABLE', 'TABLE DATA', 'SEQUENCE', 'SEQUENCE SET', 'SEQUENCE OWNED BY', 'DEFAULT',
                         'CONSTRAINT', 'FK CONSTRAINT', 'INDEX', 'COMMENT', 'ACL', 'EXTENSION'})
TOC_KINDS = tuple(sorted(TOC_ALLOWED | set(ha_odoo.SUPERUSER_KINDS) | {
    'FUNCTION', 'PROCEDURE', 'AGGREGATE', 'TRIGGER', 'VIEW', 'MATERIALIZED VIEW', 'MATERIALIZED VIEW DATA', 'RULE',
    'POLICY', 'ROW SECURITY', 'OPERATOR', 'TYPE', 'DOMAIN', 'SHELL TYPE', 'CHECK CONSTRAINT', 'CONVERSION',
    'COLLATION', 'DEFAULT ACL', 'LARGE OBJECT', 'BLOB', 'BLOBS', 'BLOB METADATA', 'STATISTICS', 'STATISTICS DATA',
    'TEXT SEARCH CONFIGURATION', 'TEXT SEARCH DICTIONARY', 'PUBLICATION TABLE', 'PUBLICATION TABLES IN SCHEMA',
    'SUBSCRIPTION TABLE', 'SECURITY LABEL', 'INDEX ATTACH', 'TABLE ATTACH', 'SCHEMA', 'DATABASE',
    'DATABASE PROPERTIES', 'ENCODING', 'STDSTRINGS', 'SEARCHPATH', 'FOREIGN SERVER'}, key=len, reverse=True))
# What a database may hold beyond Nextcloud's tables, sequences and indexes, read from the catalogs only (no table of
# HA's is read; this device's extension members such as pgvector's are not counted). dev-e's Nextcloud 35.0.1 has 0 of
# each, relation kinds r/S/i only and column defaults that are literals or nextval() of a sequence. Run pinned.
SHAPE_SQL = """WITH ns AS (SELECT oid FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'),
 ext AS (SELECT classid, objid FROM pg_depend WHERE deptype = 'e'),
 rel AS (SELECT oid FROM pg_class WHERE relnamespace IN (SELECT oid FROM ns))
SELECT json_build_object(
 'functions', (SELECT count(*) FROM pg_proc WHERE pronamespace IN (SELECT oid FROM ns)
               AND oid NOT IN (SELECT objid FROM ext WHERE classid = 'pg_proc'::regclass)),
 'operators', (SELECT count(*) FROM pg_operator WHERE oprnamespace IN (SELECT oid FROM ns)
               AND oid NOT IN (SELECT objid FROM ext WHERE classid = 'pg_operator'::regclass)),
 'types', (SELECT count(*) FROM pg_type t WHERE t.typnamespace IN (SELECT oid FROM ns) AND t.typrelid = 0
           AND t.oid NOT IN (SELECT objid FROM ext WHERE classid = 'pg_type'::regclass)
           AND NOT (t.typelem <> 0 AND t.typelem IN (SELECT e.oid FROM pg_type e WHERE e.typrelid <> 0
                    OR e.oid IN (SELECT objid FROM ext WHERE classid = 'pg_type'::regclass)))),
 'triggers', (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal),
 'rules', (SELECT count(*) FROM pg_rewrite WHERE ev_class IN (SELECT oid FROM rel)),
 'policies', (SELECT count(*) FROM pg_policy) + (SELECT count(*) FROM pg_class WHERE relrowsecurity OR relforcerowsecurity),
 'event_triggers', (SELECT count(*) FROM pg_event_trigger),
 'relations', (SELECT count(*) FROM pg_class WHERE oid IN (SELECT oid FROM rel) AND relkind NOT IN ('r', 'S', 'i')
               AND oid NOT IN (SELECT objid FROM ext WHERE classid = 'pg_class'::regclass)),
 'checks', (SELECT count(*) FROM pg_constraint WHERE connamespace IN (SELECT oid FROM ns)
            AND contype NOT IN ('p', 'u', 'f', 'n')),
 'generated', (SELECT count(*) FROM pg_attribute WHERE attrelid IN (SELECT oid FROM rel) AND attgenerated <> ''),
 'inherits', (SELECT count(*) FROM pg_inherits),
 'others', (SELECT count(*) FROM pg_collation WHERE collnamespace IN (SELECT oid FROM ns)
              AND oid NOT IN (SELECT objid FROM ext WHERE classid = 'pg_collation'::regclass))
           + (SELECT count(*) FROM pg_conversion WHERE connamespace IN (SELECT oid FROM ns)
              AND oid NOT IN (SELECT objid FROM ext WHERE classid = 'pg_conversion'::regclass))
           + (SELECT count(*) FROM pg_ts_config WHERE cfgnamespace IN (SELECT oid FROM ns)
              AND oid NOT IN (SELECT objid FROM ext WHERE classid = 'pg_ts_config'::regclass))
           + (SELECT count(*) FROM pg_ts_dict WHERE dictnamespace IN (SELECT oid FROM ns)
              AND oid NOT IN (SELECT objid FROM ext WHERE classid = 'pg_ts_dict'::regclass))
           + (SELECT count(*) FROM pg_opclass WHERE opcnamespace IN (SELECT oid FROM ns)
              AND oid NOT IN (SELECT objid FROM ext WHERE classid = 'pg_opclass'::regclass))
           + (SELECT count(*) FROM pg_opfamily WHERE opfnamespace IN (SELECT oid FROM ns)
              AND oid NOT IN (SELECT objid FROM ext WHERE classid = 'pg_opfamily'::regclass))
           + (SELECT count(*) FROM pg_cast WHERE oid >= 16384
              AND oid NOT IN (SELECT objid FROM ext WHERE classid = 'pg_cast'::regclass))
           + (SELECT count(*) FROM pg_foreign_server) + (SELECT count(*) FROM pg_user_mapping)
           + (SELECT count(*) FROM pg_publication) + (SELECT count(*) FROM pg_largeobject_metadata)
           + (SELECT count(*) FROM pg_default_acl) + (SELECT count(*) FROM pg_transform)
           + (SELECT count(*) FROM pg_statistic_ext),
 'tablespaces', (SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default', 'pg_global')),
 'role_settings', (SELECT count(*) FROM pg_db_role_setting),
 'defaults', (SELECT coalesce(json_agg(DISTINCT pg_get_expr(adbin, adrelid)), '[]'::json) FROM pg_attrdef
              WHERE adrelid IN (SELECT oid FROM rel)))"""
# NC-38, NC-45: what another app (Memories makes a function and a trigger) creates in the database. Programs of that kind are
# left out of the restore and listed, the tables and their data are moved; nothing else of the shape list may be left out
# (a type, a view, a rule, a CHECK or a default that calls a function would break the tables that use it).
SKIPPABLE = ('functions', 'triggers')
# pg_proc holds functions, procedures and aggregates (SHAPE_SQL counts all of them as `functions`); pg_dump lists them as three kinds
SKIPPED_TOC = ('FUNCTION', 'PROCEDURE', 'AGGREGATE', 'TRIGGER')
# The objects of an app this module knows, by the names OBJECTS_SQL gives. Memories (pulsejet/memories lib/Db/FilecacheTriggers.php,
# read on 2026-11-25) makes one function and one trigger on oc_filecache. Without them it runs in its compatibility mode:
# lib/Db/TimelineQueryDays.php joins the file cache when `memories.db.triggers.fcu` is false, which is its default, and HA's
# value of that setting is not carried (merge_config). Its repair step (appinfo/info.xml: post-migration and install; the
# `maintenance:repair` command runs the post-migration steps of the enabled apps) makes them again. Leaving exactly these
# out loses nothing, so they alone are no line to confirm. They are NOT carried over as HA had them: code that comes out of
# a backup is never restored, a known name or not (the vendor's own repair step is the way back).
KNOWN_OBJECTS = {'Memories': frozenset({'public.memories_fcu_fun', 'oc_filecache.memories_fcu_trg'})}
REPAIR_COMMAND = 'podman exec -u www-data {container} php occ maintenance:repair'
OBJECTS_SQL = """WITH ns AS (SELECT oid FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'),
 ext AS (SELECT classid, objid FROM pg_depend WHERE deptype = 'e')
SELECT json_build_object(
 'functions', (SELECT coalesce(json_agg(q.name ORDER BY q.name), '[]'::json) FROM (
    SELECT n.nspname || '.' || p.proname AS name FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE p.pronamespace IN (SELECT oid FROM ns) AND p.oid NOT IN (SELECT objid FROM ext WHERE classid = 'pg_proc'::regclass)
    ORDER BY 1 LIMIT 100) q),
 'triggers', (SELECT coalesce(json_agg(q.name ORDER BY q.name), '[]'::json) FROM (
    SELECT c.relname || '.' || t.tgname AS name FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
    WHERE NOT t.tgisinternal ORDER BY 1 LIMIT 100) q))"""
SHAPE_LABELS = (('functions', '函式'), ('operators', '運算子'), ('types', '自訂資料型別'), ('triggers', '觸發程序'),
                ('rules', '規則'), ('policies', '資料列安全原則'), ('event_triggers', '事件觸發程序'),
                ('relations', '檢視表或其他特殊資料表'), ('checks', 'CHECK 等限制'), ('generated', '產生欄位'),
                ('inherits', '繼承的資料表'), ('others', '其他自訂資料庫物件'),
                ('tablespaces', '另外的表空間（tablespace）'))
# A column default Nextcloud writes: nextval() of a sequence or a constant (dev-e's 35.0.1: '', 0, '-1'::integer,
# 'x'::character varying, NULL::timestamp without time zone, false...); anything else (a function call) is refused.
_PG_TYPE = r'[a-z][a-z ]{0,40}(?:\([0-9]{1,4}(?:,[0-9]{1,4})?\))?(?: with(?:out)? time zone)?(?:\[\])?'
DEFAULT_RE = re.compile(rf"(?:nextval\('(?:public\.)?[a-z0-9_]{{1,63}}'::regclass\)|'(?:[^']|''){{0,1024}}'::{_PG_TYPE}"
                        rf"|-?[0-9]{{1,20}}(?:\.[0-9]{{1,20}})?|true|false|NULL::{_PG_TYPE})")
MSG_SHAPE = 'HA 的 Nextcloud 資料庫含有 Nextcloud 不會建立、這台也無法略過的資料庫物件（{kinds}），無法安全地搬過來。'
MSG_SKIPPED = ('HA 的 Nextcloud 資料庫含有 Nextcloud 不會建立的程式（{kinds}）。它們不會搬過來，資料表和資料照搬；'
               '用到它們的應用匯入後如果不正常，請在這台更新或重新安裝那個應用，讓它自己把程式建回來。')
# What a known app's objects need (NC-38, NC-45): nothing to confirm, a reminder after the import with the command.
MSG_KNOWN_LEFT = ('HA 的 Nextcloud 資料庫有 {apps} 建立的函式與觸發程序。它們不會搬過來；沒有它們時 {apps} 會自動改用相容模式（查詢較慢），'
                  '資料不受影響。匯入後執行一次 maintenance:repair，{apps} 就會把它們建回來。')
MSG_REPAIR = ('HA 的 Nextcloud 資料庫裡 {apps} 建立的函式與觸發程序沒有搬過來；{apps} 目前改用相容模式（查詢較慢）。'
              '要讓它建回來，請在匯入後執行一次：' + REPAIR_COMMAND)
MSG_LEFT_OUT = ('HA 的 Nextcloud 資料庫裡其他應用建立的程式（函式、觸發程序）沒有搬過來；如果有應用匯入後不正常，'
                '請在這台更新或重新安裝那個應用，讓它自己把程式建回來。')
MSG_SCHEMAS = ('HA 的 Nextcloud 資料庫除了 Nextcloud 用的 public 之外還有其他 schema（資料庫裡的分組）。'
               '只搬 public，其他 schema 不會搬過來，Nextcloud 本身不受影響。')
MSG_SHAPE_UNREAD = '無法讀取 HA 的 Nextcloud 資料庫結構，無法確認可以安全地搬過來。'
MSG_TOC = 'HA 的 Nextcloud 資料庫匯出檔含有 Nextcloud 不會建立、這台也無法略過的物件（{kinds}），無法安全地搬過來。'
MSG_ONLINE = ('HA 的 Nextcloud 資料庫不是在停止狀態下備份的（含有 backup_label 或 tablespace_map），無法安全地搬過來；'
              '請在 HA 重新做一份 Nextcloud 的備份。')
# The users' files that are not in the backup (NC-22, NC-23, NC-25): the import goes on once the customer confirmed it (DESIGN
# H-b 1, owner rule 3). The accounts, calendars, shares and settings move; the data directory stays empty (with its
# .ncdata marker and Nextcloud's own .htaccess) and this device's own user files are in the safety backup of the restore.
MSG_FILES_LEFT = ('帳號、設定、行事曆、聯絡人與分享會照常搬，使用者檔案不會搬：Nextcloud 的檔案列表看得到名稱但打不開；'
                  '這台原本的使用者檔案會先存進匯入前的備份。把檔案補回這台後，請執行一次檔案掃描。')
MSG_NO_SHARE = '這份 HA 備份沒有包含 share 資料夾，Nextcloud 的使用者檔案放在那裡。' + MSG_FILES_LEFT
MSG_NO_DATADIR = ('HA 備份的 share 裡找不到 Nextcloud 的使用者檔案資料夾（或資料夾裡缺少 .ncdata 標記，可能當時沒有掛上），'
                  '為避免搬錯資料夾，不會搬它。' + MSG_FILES_LEFT)
MSG_ELSEWHERE = 'HA 的 Nextcloud 使用者檔案放在 HA 備份不會包含的位置（網路磁碟或其他路徑，不在 /share、/data 或 /config）。' + MSG_FILES_LEFT
# The official image serves the data dir from inside Apache's web root (/var/www/html/data; docker-php.conf:
# `AllowOverride All` for /var/www/), so the .htaccess at its top is what keeps the users' files from being fetched
# without a login, and one further down could open its folder again or run files as programs. HA's data directory is
# outside its web root (nginx reads no .htaccess): its own one may be missing or say anything. So the conversion always
# writes Nextcloud's own rules (35.0.1 lib/private/Setup.php:649-678 protectDataDirectory, also rewritten by every
# update: lib/private/Updater.php:225) and refuses any other .htaccess below (Nextcloud never creates nor accepts one:
# `forbidden_filenames`).
HTACCESS = '.htaccess'
TEAM_FOLDERS = '__groupfolders'  # the Team folders app's folder in the data directory
DATA_HTACCESS = b'''# Written by the WOOWTECH backup when it imported this data from Home Assistant: Nextcloud's own rules
# Section for Apache 2.4 to 2.6
<IfModule mod_authz_core.c>
  Require all denied
</IfModule>
<IfModule mod_access_compat.c>
  Order Allow,Deny
  Deny from all
  Satisfy All
</IfModule>

# Section for Apache 2.2
<IfModule !mod_authz_core.c>
  <IfModule !mod_access_compat.c>
    <IfModule mod_authz_host.c>
      Order Allow,Deny
      Deny from all
    </IfModule>
    Satisfy All
  </IfModule>
</IfModule>

# Section for Apache 2.2 to 2.6
<IfModule mod_autoindex.c>
  IndexIgnore *
</IfModule>
'''
NCDATA = b'# Nextcloud data directory\n# Do not change this file\n'   # the marker Nextcloud's installer writes (only its existence counts)
MSG_HTACCESS = ('HA 的 Nextcloud 使用者檔案裡有 {count} 個網站伺服器設定檔 .htaccess。這台的使用者檔案在網站資料夾裡，'
                '這種檔案可能讓檔案被公開或被當成程式執行，所以不會搬它們（這台會寫入 Nextcloud 自己的 .htaccess），其他檔案照常搬。'
                '匯入後請執行一次檔案掃描。')
MSG_SYMLINKS = ('HA 的 Nextcloud 使用者檔案裡有 {count} 個符號連結（捷徑）。連結可能指到這台資料夾外的檔案，所以不會搬它們'
                '（Nextcloud 預設本來就不跟連結），其他檔案照常搬。匯入後請執行一次檔案掃描。')
MSG_ENCRYPTION = ('HA 的 Nextcloud 開啟了伺服器端加密。金鑰和檔案會一起搬，但這種備份這台還沒有實測過；'
                  '匯入後如果檔案打不開，請用匯入前自動做的備份退回。')
SCAN_COMMAND = 'podman exec -u www-data {container} php occ files:scan --all'
MSG_STORAGE_TAKEN = ('HA 的 Nextcloud 資料庫裡已經有這台使用者檔案資料夾（{dir}）的儲存空間記錄，和 HA 自己的資料夾記錄衝突，'
                     '無法安全地搬過來。')
MSG_LISTS = ('HA 備份裡有 {count} 位 Nextcloud 使用者（例如 {names}）的檔案清單（資料庫）和實際檔案不一致：HA 先備份資料庫、'
             'Nextcloud 重新啟動後才備份使用者檔案，備份時可能有人在使用。')


def _under(name, prefix):
    return name == prefix or name.startswith(prefix + '/')


def shown(text, limit=120):
    """A text HA's backup chose (a path, a version, a URL), as a message or the check result shows it: cut, control
    characters and bidirectional controls as `?` (hacommon.names does the same for lists of names)."""
    return hacommon.CONTROL_RE.sub('?', str(text)[:limit])


# ====================================================================== config.php (strict; never executed)

class Float:
    """A PHP float literal kept exactly as written (re-emitted unchanged)."""
    __slots__ = ('text',)

    def __init__(self, text):
        self.text = text

    def __eq__(self, other):
        return isinstance(other, Float) and other.text == self.text

    def __hash__(self):
        return hash(self.text)

    def __repr__(self):
        return f'Float({self.text})'


_TOKEN_RE = re.compile(r"""
 (?P<ws>\s+)
|(?P<comment>//[^\n]*|\#[^\n]*|/\*.*?\*/)
|(?P<open><\?php(?![A-Za-z0-9_]))
|(?P<close>\?>)
|(?P<var>\$CONFIG(?![A-Za-z0-9_]))
|(?P<string>'(?:[^'\\]|\\.)*')
|(?P<dstring>"(?:[^"\\$]|\\.)*")
|(?P<number>-?(?:[0-9]+\.[0-9]+(?:[eE][-+]?[0-9]+)?|[0-9]+[eE][-+]?[0-9]+|[0-9]+))
|(?P<word>[A-Za-z_][A-Za-z0-9_]*)
|(?P<arrow>=>)
|(?P<punct>[=,;()\[\]])
|(?P<dot>\.)
""", re.S | re.X)


# NC-12: a hand-edited config.php may write a text in double quotes, join texts with a dot or name a constant. Those are
# still only values: a double-quoted text without a variable (a `$` is never accepted unescaped, so nothing is
# interpolated), the escapes that mean one fixed character, a dot between two texts and the constants below. A variable, a
# function call, another constant or another escape still stops the import of Nextcloud (the file is never run).
_DQ_ESCAPES = {'n': '\n', 'r': '\r', 't': '\t', '\\': '\\', '"': '"', '$': '$'}
CONSTANTS = {'PHP_EOL': '\n', 'DIRECTORY_SEPARATOR': '/', 'PATH_SEPARATOR': ':', 'PHP_INT_SIZE': 8,
             'PHP_INT_MAX': 2 ** 63 - 1, 'PHP_INT_MIN': -2 ** 63, 'E_ERROR': 1, 'E_WARNING': 2, 'E_NOTICE': 8,
             'E_DEPRECATED': 8192, 'E_STRICT': 2048, 'E_ALL': 32767}


def _php_dstring(token):
    body, out, i = token[1:-1], [], 0
    if '{\\$' in body:
        raise ValueError('ambiguous interpolation')
    while i < len(body):
        if body[i] == '\\':
            if body[i + 1] not in _DQ_ESCAPES:
                raise ValueError('unsupported escape')
            out.append(_DQ_ESCAPES[body[i + 1]])
            i += 2
        else:
            out.append(body[i])
            i += 1
    return ''.join(out)


def _php_string(token):
    body, out, i = token[1:-1], [], 0
    while i < len(body):
        if body[i] == '\\' and i + 1 < len(body) and body[i + 1] in "\\'":
            out.append(body[i + 1])
            i += 2
        else:
            out.append(body[i])
            i += 1
    return ''.join(out)


class _Parser:
    def __init__(self, tokens):
        self.tokens, self.i, self.items = tokens, 0, 0

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else (None, None)

    def take(self, kind=None, text=None):
        token = self.peek()
        if token[0] is None or (kind is not None and token[0] != kind) or (text is not None and token[1] != text):
            raise ValueError(f'unexpected token at {self.i}')
        self.i += 1
        return token

    def value(self, depth=0):
        first = self.term(depth)
        while self.peek()[0] == 'dot':
            self.i += 1
            other = self.term(depth)
            if not isinstance(first, str) or not isinstance(other, str):
                raise ValueError('only texts are joined')
            first += other
            if len(first) > MAX_CONFIG:
                raise ValueError('text too long')
        return first

    def term(self, depth=0):
        if depth > MAX_DEPTH:
            raise ValueError('too deep')
        kind, text = self.take()
        if kind == 'string':
            return _php_string(text)
        if kind == 'dstring':
            return _php_dstring(text)
        if kind == 'number':
            if re.fullmatch(r'-?[0-9]+', text):
                number = int(text)
                if abs(number) >= 2 ** 63:
                    raise ValueError('integer out of range')
                return number
            return Float(text)
        if kind == 'word':
            lower = text.lower()
            if lower in ('true', 'false'):
                return lower == 'true'
            if lower == 'null':
                return None
            if lower == 'array':
                self.take('punct', '(')
                return self.array(')', depth)
            if text in CONSTANTS:
                return CONSTANTS[text]
            raise ValueError('unsupported word')
        if kind == 'punct' and text == '[':
            return self.array(']', depth)
        raise ValueError('unsupported value')

    def array(self, close, depth):
        result, index = {}, 0
        while True:
            if self.peek() == ('punct', close):
                self.i += 1
                return result
            first = self.value(depth + 1)
            if self.peek()[0] == 'arrow':
                self.i += 1
                if isinstance(first, bool) or not isinstance(first, (str, int)):
                    raise ValueError('unsupported key')
                key, item = first, self.value(depth + 1)
            else:
                key, item = index, first
            if key in result:
                raise ValueError('duplicate key')
            result[key] = item
            if isinstance(key, int) and key >= index:
                index = key + 1
            self.items += 1
            if self.items > MAX_ITEMS:
                raise ValueError('too many items')
            if self.peek() == ('punct', ','):
                self.i += 1
            elif self.peek() != ('punct', close):
                raise ValueError('expected a comma')


def parse_config(data):
    """{key: value} of a config.php as Nextcloud writes it (`<?php $CONFIG = array (...);`, var_export): arrays as
    dicts (int or str keys, in order), single-quoted strings, ints, Float, bools and None; comments are skipped.
    Anything else (double quotes, constants, calls, concatenation, a second statement) raises ValueError: the file is
    PHP code and is never run (facts R5)."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_CONFIG:
        raise ValueError('size')
    text = bytes(data).decode('utf-8')
    if text.startswith('﻿'):
        text = text[1:]
    tokens, pos = [], 0
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if match is None:
            raise ValueError(f'unexpected input at {pos}')
        if match.lastgroup not in ('ws', 'comment'):
            tokens.append((match.lastgroup, match.group()))
        pos = match.end()
    if tokens and tokens[-1][0] == 'close':
        tokens.pop()
    parser = _Parser(tokens)
    parser.take('open')
    parser.take('var')
    parser.take('punct', '=')
    config = parser.value()
    parser.take('punct', ';')
    if parser.i != len(tokens) or not isinstance(config, dict):
        raise ValueError('not one $CONFIG array')
    return config


def _php_str(value):
    return "'" + value.replace('\\', '\\\\').replace("'", "\\'") + "'"


def _emit(value, indent):
    if isinstance(value, dict):
        pad = '  ' * (indent + 1)
        lines = ['array (']
        for key, item in value.items():
            name = str(key) if isinstance(key, int) else _php_str(key)
            if isinstance(item, dict):
                lines.append(f'{pad}{name} => ')
                lines.append(f'{pad}{_emit(item, indent + 1)},')
            else:
                lines.append(f'{pad}{name} => {_emit(item, indent + 1)},')
        lines.append('  ' * indent + ')')
        return '\n'.join(lines)
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if value is None:
        return 'NULL'
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Float):
        return value.text
    if isinstance(value, str):
        if '\x00' in value:
            raise ValueError('NUL in a value')
        return _php_str(value)
    raise ValueError('unsupported value')


def render_config(config):
    """config.php bytes in Nextcloud's own format (`<?php` + `$CONFIG = ` + var_export + `;`)."""
    return ('<?php\n$CONFIG = ' + _emit(config, 0) + ';\n').encode('utf-8')


def jsonable(value):
    """What PHP's json_encode gives for a parsed value (arrays with keys 0..n-1 are lists)."""
    if isinstance(value, dict):
        if list(value) == list(range(len(value))):
            return [jsonable(item) for item in value.values()]
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, Float):
        return float(value.text)
    return value


def mask_config(config):
    """Mask every secret value of a config.php in this process's logs (jobs.mask_secret)."""
    from . import jobs
    for key in SECRET_KEYS:
        value = config.get(key) if isinstance(config, dict) else None
        if isinstance(value, str) and len(value) >= 4:
            jobs.mask_secret(value)


def nc_version(value):
    return value if isinstance(value, str) and NC_VERSION_RE.fullmatch(value) else None


def _enforced(config):
    """Nextcloud enforces two-factor only for the string 'true' (lib/private/Authentication/TwoFactorAuth/
    MandatoryTwoFactor.php getState)."""
    return config.get('twofactor_enforced') == 'true'


def _enforced_for_all(config):
    """Enforced for every user: no list of enforced groups, no excluded group (MandatoryTwoFactor.php
    isEnforcedFor)."""
    return _enforced(config) and not any(config.get(key) for key in TWOFACTOR[1:])


def _version3(version):
    return '.'.join(version.split('.')[:3]) if version else None


def config_issues(sink, ha, live, image_version, *, found=True, addon_version=None):
    """What HA's and the live config.php say against an import, into `sink` (versions, installation state, database,
    identity). `found`: HA's backup has a config.php at all. `addon_version`: HA's add-on version (HA's own Nextcloud version
    is inferred from it when config.php does not say: NC-20)."""
    if not isinstance(ha, dict):
        if found:
            sink.stop('nextcloud.config-unreadable',
                      '無法解讀 HA 的 Nextcloud 設定檔 config.php（它不只是一份設定值：含有變數、函式或這台不認得的寫法），'
                      '為了安全不會執行它，無法匯入 Nextcloud。',
                      action='請在 HA 把 config.php 裡的變數、函式換成固定的值後重新備份，再匯入 Nextcloud；這台的 Nextcloud 不會變。')
        else:
            sink.stop('nextcloud.config-missing',
                      'HA 備份裡找不到 Nextcloud 的設定檔 config.php，沒有它就不知道 Nextcloud 的身分金鑰與使用者檔案位置，無法匯入。',
                      action='請先在 HA 讓 Nextcloud 附加元件正常啟動過（會產生 config.php），再重新備份並匯入 Nextcloud。')
        return
    ha_version, live_version = nc_version(ha.get('version')), nc_version(live.get('version'))
    if ha.get('installed') is not True:
        sink.stop('nextcloud.not-installed', 'HA 的 Nextcloud 還沒有安裝完成（config.php 沒有 installed），沒有資料可以匯入。',
                  action='請先在 HA 完成 Nextcloud 的安裝並使用過，再重新備份；這次只有 Nextcloud 不會匯入，其他應用照常。')
    if ha.get('dbtype') != 'pgsql':
        sink.stop('nextcloud.not-postgres', 'HA 的 Nextcloud 不是使用 PostgreSQL 資料庫，無法匯入。')
    if ha.get('dbtableprefix', PREFIX) != PREFIX or live.get('dbtableprefix', PREFIX) != PREFIX:
        sink.stop('nextcloud.table-prefix', 'Nextcloud 的資料表前綴不是 oc_，目前無法匯入。')
    if any(key in ha for key in ('objectstore', 'objectstore_multibucket')):
        sink.stop('nextcloud.object-storage', 'HA 的 Nextcloud 把檔案放在物件儲存（例如 S3），無法搬到這台。')
    if not (isinstance(ha.get('instanceid'), str) and INSTANCE_RE.fullmatch(ha['instanceid'])
            and all(isinstance(ha.get(key), str) and SECRET_VALUE_RE.fullmatch(ha[key])
                    for key in ('passwordsalt', 'secret'))):
        sink.stop('nextcloud.no-identity', 'HA 的 Nextcloud 設定缺少它的身分資料（instanceid、secret），無法匯入。')
    if not (isinstance(ha.get('dbname'), str) and DB_RE.fullmatch(ha['dbname'])):
        sink.stop('nextcloud.no-dbname', 'HA 的 Nextcloud 設定沒有可用的資料庫名稱。')
    consistent = None
    if live.get('installed') is not True or live_version is None:
        sink.stop('nextcloud.live-not-installed', '這台的 Nextcloud 還沒有安裝完成，請先到「應用軟體」完成安裝。')
    elif ha_version is None:
        # NC-20: the add-on's version says which Nextcloud it ships (VERSIONS); the two sides are only compared by what
        # is known, and what is not known is said.
        sink.notice('nextcloud.version-unreadable',
                    '讀不到 HA 的 Nextcloud 版本（config.php 沒有可用的 version），改用附加元件版本推算；'
                    '兩邊的 Nextcloud 版本可能不同，匯入後請確認 Nextcloud 能正常使用。')
        addon_version = addon_version or ''
        sink.extend(VERSIONS.issues(addon_version, hacommon.semver(_version3(live_version))))
        inferred = VERSIONS.upstream(addon_version)
        consistent = inferred is not None and hacommon.semver(inferred) == hacommon.semver(_version3(live_version))
    elif ha_version != live_version:
        sink.stop('nextcloud.version-different', f'版本不同：HA 的 Nextcloud 是 {shown(ha_version, 40)}，這台是 {live_version}。',
                  action='請先讓兩邊的 Nextcloud 版本一致後再匯入。')
        consistent = False
    elif _version3(live_version) != image_version:
        sink.stop('nextcloud.image-version',
                  f'這台 Nextcloud 的映像版本（{shown(image_version or "未知", 40)}）和已安裝的版本 {live_version} 不同，'
                  '請先讓這台的 Nextcloud 正常完成升級。')
    else:
        consistent = True
    if ha.get('maintenance') is True:
        if consistent:
            sink.notice('nextcloud.maintenance-mode',
                        'HA 的 Nextcloud 做備份時處於維護模式（多半是忘了關），兩邊版本相同，所以照常匯入；'
                        '這台的 Nextcloud 匯入後不會在維護模式。')
        else:
            sink.stop('nextcloud.maintenance-upgrading',
                      'HA 的 Nextcloud 做備份時處於維護模式，而且兩邊版本不同或無法確認，可能正在升級；'
                      '資料庫可能升級到一半，搬過來會壞。',
                      action='請在 HA 讓 Nextcloud 正常啟動並完成升級後，重新備份再匯入。')


def config_blockers(ha, live, image_version, *, found=True, addon_version=None):
    """The sentences of the stops `config_issues` finds, as the list the lab scripts of earlier runs read."""
    sink = haissues.Sink('nextcloud')
    config_issues(sink, ha, live, image_version, found=found, addon_version=addon_version)
    return [issue.message for issue in sink.found if issue.level == 'stop']


def merge_config(ha, live):
    """(merged config, carried policy keys, HA keys not carried): the live config.php is the base (facts section
    4.2); HA's identity keys replace the live ones; HA's policy keys (D1) are carried. The two-factor keys are one
    policy (the groups are HA's users' groups): all of HA's or, when the live enforcement is stricter (HA enforces
    nothing, or leaves someone out where the live one is for everybody), all of the live ones."""
    merged = dict(live)
    for key in FROM_HA:
        merged[key] = ha[key]
    carried = []
    stricter = _enforced(live) and (not _enforced(ha) or (_enforced_for_all(live) and not _enforced_for_all(ha)))
    if any(key in ha for key in TWOFACTOR) and not stricter:
        for key in TWOFACTOR:
            merged.pop(key, None)
            if key in ha:
                merged[key] = ha[key]
                carried.append(key)
    for key in FROM_HA_POLICY:
        if key not in TWOFACTOR and key in ha:
            merged[key] = ha[key]
            carried.append(key)
    skipped = [key for key in ha if isinstance(key, str) and key not in HA_OWN and key not in FROM_HA
               and key not in FROM_HA_POLICY and not key.startswith('mail_') and live.get(key) != ha[key]]
    return merged, carried, skipped


def data_fingerprint():
    """A new `data-fingerprint` system value, written the way `occ maintenance:data-fingerprint` writes it (md5 of the
    time). The Podman package's own restore runs that command (Woow_podman_nextcloud scripts/restore.sh:76): sync
    clients that see a new fingerprint treat the server as restored from a backup and do not delete their local files
    that the restored server lacks."""
    return hashlib.md5(str(int(time.time())).encode('ascii'), usedforsecurity=False).hexdigest()


def _stored_id(value):
    """A storage id as Nextcloud stores it: ids longer than 64 bytes as their md5 (lib/private/Files/Cache/Storage.php
    adjustStorageId)."""
    data = value.encode('utf-8', 'surrogateescape')
    return hashlib.md5(data, usedforsecurity=False).hexdigest() if len(data) > 64 else value


def _local_id(path):
    """'local::' + the path with '//' collapsed and one trailing '/' (lib/private/Files/Storage/Local.php:53-62,84-85)."""
    path = path.replace('//', '/')
    return 'local::' + (path if path.endswith('/') else path + '/')


def storage_id(datadir):
    """Nextcloud's id of the local storage of `datadir`, as stored."""
    return _stored_id(_local_id(datadir))


def storage_moves(ha_datadir, target_datadir, storages, folders=()):
    """[(HA's stored id, this device's stored id)] of the storage rows whose folder moves with the data directory: the
    root storage and every local storage below it. Team folders keep one each, and their folder rows name it by its
    number (groupfolders 23.0.2, for Nextcloud 35: lib/Mount/FolderStorageManager.php
    getBaseStorageForFolderSeparateStorageLocal, `local::<datadirectory>/__groupfolders/<id>/`; lib/Folder/FolderManager.php
    createFolder): a row left on HA's path would be another storage here, with new file numbers (shares, tags and
    versions lost). `storages`: the stored ids of HA's database; `folders`: the folder names below `__groupfolders` in the
    backup (an id stored as its md5 cannot be recognised by its text)."""
    old, new = _local_id(ha_datadir), _local_id(target_datadir)
    moves = {_stored_id(old): _stored_id(new)}
    for item in storages:
        if item.startswith(old) and item != old:
            moves[item] = _stored_id(new + item[len(old):])
    for name in folders:
        rest = f'{TEAM_FOLDERS}/{name}/'
        if _stored_id(old + rest) in storages:
            moves[_stored_id(old + rest)] = _stored_id(new + rest)
    return [(a, b) for a, b in moves.items() if a != b]


def datadir_source(datadir):
    """Where HA's data directory is in the backup: ('share', prefix) for /share/<prefix>, ('addon', prefix) for
    /data/<rest> or /config/<rest> (the add-on member), None for anything else (a network mount, /media, ...)."""
    if not isinstance(datadir, str) or not datadir.startswith('/'):
        return None
    parts = [part for part in datadir.split('/') if part]
    if len(parts) < 2 or not all(DATADIR_SEG_RE.fullmatch(p) and p not in ('.', '..') for p in parts):
        return None
    root, rest = parts[0], '/'.join(parts[1:])
    if root == 'share':
        return 'share', rest
    if root in ('data', 'config'):
        prefix = f'{root}/{rest}'
        if any(_under(prefix, item) or _under(item, prefix) for item in ADDON_ITEMS):
            return None
        return 'addon', prefix
    return None


# ====================================================================== custom apps (appinfo/info.xml)

def _version_tuple(text):
    if not isinstance(text, str) or not re.fullmatch(r'[0-9]{1,6}(?:\.[0-9]{1,6}){0,3}', text.strip()):
        return None
    return tuple(int(part) for part in text.strip().split('.'))


def parse_info_xml(data):
    """{id, version, nextcloud: (min, max), php: (min, max)} of an app's appinfo/info.xml (no DTD, no entities)."""
    if len(data) > MAX_INFO_XML or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        return {'info_ok': False}
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError:
        return {'info_ok': False}
    found = {'info_ok': root.tag == 'info', 'id': (root.findtext('id') or '').strip()[:64],
             'version': (root.findtext('version') or '').strip()[:32]}
    deps = root.find('dependencies')
    for name in ('nextcloud', 'php'):
        node = deps.find(name) if deps is not None else None
        found[name] = ((node.get('min-version') or '').strip()[:16], (node.get('max-version') or '').strip()[:16]) \
            if node is not None else ('', '')
    return found


def _fits(version, low, high):
    """Nextcloud's dependency rule: compare only as many parts as the limit names (DependencyAnalyzer)."""
    target = _version_tuple(version)
    if target is None:
        return True
    for limit, sign in ((low, 1), (high, -1)):
        bound = _version_tuple(limit) if limit else None
        if bound is None:
            continue
        cut = target[:len(bound)] + (0,) * max(0, len(bound) - len(target))
        if (cut < bound) if sign == 1 else (cut > bound):
            return False
    return True


def app_warnings(apps, *, nc_version_text, php_version):
    """zh-TW warnings about HA's custom apps on this device (Nextcloud and PHP versions, programs for another
    processor)."""
    warnings = []
    for app_id, info in sorted(apps.items()):
        if not info.get('info_ok'):
            warnings.append(f'HA 的 Nextcloud 應用 {app_id} 沒有可讀的 appinfo/info.xml，匯入後可能無法使用。')
            continue
        low, high = info.get('nextcloud') or ('', '')
        if not _fits(nc_version_text, low, high):
            warnings.append(f'HA 的 Nextcloud 應用 {app_id}（{shown(info.get("version") or "?", 32)}）不支援這台的 Nextcloud '
                            f'{nc_version_text}，匯入後 Nextcloud 可能停用它。')
        low, high = info.get('php') or ('', '')
        if php_version and not _fits(php_version, low, high):
            warnings.append(f'HA 的 Nextcloud 應用 {app_id}（{shown(info.get("version") or "?", 32)}）不支援這台的 PHP '
                            f'{php_version}，匯入後可能無法使用。')
        if info.get('foreign'):
            warnings.append(f'HA 的 Nextcloud 應用 {app_id} 含有給其他處理器的程式（例如 {shown(info["foreign"][0], 80)}），'
                            '在這台可能無法執行。')
    return warnings


# ====================================================================== the HA backup

class Source:
    """One pass over the add-on's inner tar: `addon`, `pg_version`, `pg_files`/`pg_bytes`, `recovery_files` (files of an
    online backup, not streamed), `config` (parsed
    config.php or None; `config_found`), `apps` {id: {version, files, bytes, nextcloud, php, info_ok, foreign}},
    `app_bytes`, `bad_apps` (folders that are no app id)."""

    def __init__(self):
        self.addon = None
        self.pg_version = None
        self.pg_files = self.pg_bytes = 0
        self.recovery_files = 0
        self.config = None
        self.config_found = False
        self.apps = {}
        self.app_bytes = 0
        self.bad_apps = []
        self.report = None          # the walk's habackup.Report: the entries it left out (haissues.Sink.skipped)


def scan_member(stream, report, *, pg=None, apps=None, machine=None, checkpoint=None):
    """One strict pass over the add-on's inner tar: the cluster into `pg` (ha_odoo.PgSink), config.php parsed,
    every custom app into the FileTar `apps` as `<id>/**` (HA's modes, owner 0 for now). Symlinks are skipped
    (counted), hard links refused (habackup)."""
    select = habackup.Select(include=(PG_PREFIX, CONFIG_PHP, CUSTOM_APPS), symlinks=(), hardlinks=False)
    src = Source()
    for count, entry in enumerate(habackup.iter_entries(stream, select, report, checkpoint=checkpoint), 1):
        if checkpoint is not None and count % 256 == 0:
            checkpoint()
        name = entry.name
        if _under(name, PG_PREFIX):
            rel = name[len(PG_PREFIX) + 1:] if name != PG_PREFIX else '.'
            if rel.split('/', 1)[0] in RECOVERY_FILES:
                src.recovery_files += 1  # never reaches the volume; the check refuses
                continue
            data = None
            if entry.kind == 'file':
                src.pg_files += 1
                src.pg_bytes += entry.size
                if rel == 'PG_VERSION':
                    data = entry.read_all(ha_odoo.MAX_SMALL_FILE)
                    src.pg_version = shown(data.decode('ascii', 'replace').strip(), 16)
            if pg is not None:
                pg.add(rel, entry, data)
            continue
        if name == CONFIG_PHP:
            if entry.kind == 'file':
                src.config_found = True
                try:
                    src.config = parse_config(entry.read_all(MAX_CONFIG))
                except (ValueError, BackupError):
                    src.config = None
                mask_config(src.config)
            continue
        if name == CUSTOM_APPS:
            continue
        app_id, _, tail = name[len(CUSTOM_APPS) + 1:].partition('/')
        if not APP_ID_RE.fullmatch(app_id):
            if app_id not in src.bad_apps:
                src.bad_apps.append(shown(app_id, 60))
            continue
        info = src.apps.setdefault(app_id, {'version': '', 'files': 0, 'bytes': 0, 'info_ok': False, 'foreign': []})
        target = app_id + (f'/{tail}' if tail else '')
        if entry.kind == 'file':
            info['files'] += 1
            info['bytes'] += entry.size
            src.app_bytes += entry.size
            if hacommon.foreign_elf(entry.peek(20), machine):
                info['foreign'] = (info['foreign'] + [tail])[:5]
            if tail == 'appinfo/info.xml':
                data = entry.read_all(MAX_INFO_XML)
                info.update(parse_info_xml(data))
                if apps is not None:
                    apps.add_member(hacommon.info(target, 'file', mode=entry.mode & 0o777, uid=0, gid=0,
                                                  mtime=entry.mtime, size=len(data)), io.BytesIO(data))
                continue
        if apps is not None:
            apps.add_entry(target, entry, mode=entry.mode & 0o777, uid=0, gid=0)
    if report.skipped_symlinks:
        samples = [s for s in report.skipped_symlink_samples if _under(s, PG_PREFIX)]
        if samples:
            raise BackupError('incompatible', 'HA 的 Nextcloud 資料庫使用了另外的表空間（tablespace），目前無法搬過來。',
                              reason='tablespace symlink', member=samples[0])
    src.addon = report.addon
    return src


class DataDir:
    """What a walk of HA's data directory saw (and, for a conversion, wrote)."""

    def __init__(self):
        self.present = False
        self.ncdata = False
        self.encryption = False
        self.files = self.dirs = self.hardlinks = self.bytes = 0
        self.skipped_files = self.skipped_bytes = 0
        self.symlinks = 0
        self.symlink_samples = []
        self.htaccess = 0
        self.htaccess_samples = []
        self.htaccess_names = haissues.Names()   # every .htaccess left out (NC-27): its key covers all of them
        self.hardlinks_copied = 0   # hard links to a file that is left out: handed out again as files (NC-29)
        self.report = None          # the walk's habackup.Report: what the reader left out (haissues.Sink.skipped)
        self.users = set()
        self.team_folders = set()  # the folder names below `__groupfolders`
        self.lists = {}     # user -> [files, bytes, digest] of `<user>/files/**` (FILES_SQL's values)

    def listed(self, user, path, size):
        """Count a user's file `path` (`files/...`) the way FILES_SQL does: an order-free digest of sizes and paths."""
        row = self.lists.setdefault(user, [0, 0, 0])
        row[0] += 1
        row[1] += size
        row[2] ^= int(hashlib.md5(f'{size}:{path}'.encode('utf-8', 'surrogateescape'),
                                  usedforsecurity=False).hexdigest()[:16], 16)


class DirTar:
    """A host directory tar in the folder pack's naming (`./`, `./<name>`), written into staging with the space
    guard counting; hard links only to a regular file written before."""

    def __init__(self, path, guard=None):
        self.tar = ha_odoo.FileTar(path, guard)
        self.files = set()

    @property
    def path(self):
        return self.tar.path

    @property
    def names(self):
        return self.tar.names

    @staticmethod
    def name(rel):
        return './' if rel == '.' else f'./{rel}'

    def add(self, rel, kind, *, mode, uid, gid, mtime, size=0, fileobj=None, linkname=None):
        if kind == 'hardlink' and linkname not in self.files:
            raise BackupError('incompatible', f'HA 備份中的 {shown(rel, 200)} 是另一個沒有搬過來的檔案的硬連結，無法只搬一半；'
                                              '已停止。', member=shown(rel, 200))
        mode = mode & (0o1777 if kind == 'dir' else 0o777)
        self.tar.add_member(hacommon.info(self.name(rel), kind, mode=mode, uid=uid, gid=gid, mtime=mtime, size=size,
                                          linkname=self.name(linkname) if kind == 'hardlink' else linkname), fileobj)
        if kind == 'file':
            self.files.add(rel)

    def close(self):
        self.tar.close()


def _left_out(parts, updater, remote):
    """Why the walk of the data directory does not take the entry `parts` (its names below the directory): 'updater' (the web
    updater's folder, HA's cached Collabora discovery) or 'htaccess' (any `.htaccess`), else None."""
    rel = '/'.join(parts)
    if parts[0] == updater or (remote is not None and _under(rel, remote)):
        return 'updater'
    return 'htaccess' if HTACCESS in parts else None


def scan_datadir(stream, report, prefix, *, addon, instanceid=None, out=None, ids=None, checkpoint=None):
    """Walk HA's data directory (`prefix` and below) in a member; with `out` (DirTar) write it as the data dir,
    every entry owned by `ids` (www-data of the live image), modes as in HA, the top written by the caller. Skipped:
    the web updater's own folder (decision D5; core/BackgroundJobs/BackgroundCleanupUpdaterBackupsJob.php:44
    `updater-<instanceid>`: a user may be called `updater-...`, lib/private/User/Manager.php:835-849 refuses other names
    only), HA's cached Collabora discovery
    (`appdata_<instanceid>/richdocuments/remoteData`) and HA's own `.htaccess` at the top (the caller writes this
    device's: DATA_HTACCESS). Symlinks and every other `.htaccess` are counted (the caller refuses them)."""
    select = habackup.Select(include=(prefix,), symlinks=(), hardlinks=True)
    data = DataDir()
    remote = f'appdata_{instanceid}/richdocuments/remoteData' if instanceid else None
    updater = f'updater-{instanceid}' if instanceid else None
    uid, gid = ids if ids is not None else (0, 0)
    entries = habackup.iter_entries(stream, select, report, addon=addon, checkpoint=checkpoint)
    for count, entry in enumerate(entries, 1):
        if checkpoint is not None and count % 256 == 0:
            checkpoint()
        data.present = True
        if entry.name == prefix:
            continue
        rel = entry.name[len(prefix) + 1:]
        parts = rel.split('/')
        left = _left_out(parts, updater, remote)
        if left == 'updater':
            if entry.kind == 'file':
                data.skipped_files += 1
                data.skipped_bytes += entry.size
            continue
        if left == 'htaccess':
            if len(parts) > 1 or entry.kind != 'file':
                data.htaccess += 1
                data.htaccess_names.add(rel)
                if len(data.htaccess_samples) < 3:
                    data.htaccess_samples.append(rel[:200])
            continue
        if parts[0] == 'files_encryption' or (len(parts) > 1 and parts[1] == 'files_encryption'):
            data.encryption = True
        if rel == '.ncdata' and entry.kind == 'file':
            data.ncdata = True
        own = not parts[0].startswith(('appdata_', '__'))  # a user's folder (not app data, not group folders)
        if len(parts) >= 2 and parts[1] == 'files' and own:
            data.users.add(parts[0])
        if parts[0] == TEAM_FOLDERS and len(parts) >= 2 and len(data.team_folders) < MAX_ITEMS:
            data.team_folders.add(parts[1])
        if entry.kind == 'dir':
            data.dirs += 1
            if out is not None:
                out.add(rel, 'dir', mode=entry.mode, uid=uid, gid=gid, mtime=entry.mtime)
        elif entry.kind == 'file':
            data.files += 1
            data.bytes += entry.size
            if len(parts) >= 3 and parts[1] == 'files' and own:
                data.listed(parts[0], '/'.join(parts[1:]), entry.size)
            if out is not None:
                out.add(rel, 'file', mode=entry.mode, uid=uid, gid=gid, mtime=entry.mtime, size=entry.size,
                        fileobj=hacommon._Exact(entry, None))
        elif entry.kind == 'hardlink':
            inside = _under(entry.linkname, prefix) and entry.linkname != prefix
            if inside and _left_out(entry.linkname[len(prefix) + 1:].split('/'), updater, remote):
                # NC-29: the file it names is not moved (an updater backup, the Office cache, an .htaccess): the same name
                # comes again after the walk as a regular file with that content
                entry.copy_later()
                data.hardlinks_copied += 1
                continue
            data.hardlinks += 1
            if out is not None:
                if not inside:
                    raise BackupError('incompatible', f'HA 備份中的 {shown(rel, 200)} 是資料夾外檔案的硬連結，無法搬過來。',
                                      member=shown(rel, 200))
                out.add(rel, 'hardlink', mode=0o644, uid=uid, gid=gid, mtime=entry.mtime,
                        linkname=entry.linkname[len(prefix) + 1:])
    if report.skipped_symlinks:  # every one is below `prefix` (Select.include)
        data.symlinks = report.skipped_symlinks
        data.symlink_samples = list(report.skipped_symlink_samples)
    data.report = report
    return data


def add_office_cache(out, instanceid, files, www):
    """This device's cached Collabora answers as the Office app's cache of the converted data dir (HA's was left out;
    Nextcloud finds files it has no row for and adds them: lib/private/Files/View.php getCacheEntry)."""
    rel = ''
    for part in (f'appdata_{instanceid}', 'richdocuments', 'remoteData') if files else ():
        rel = f'{rel}/{part}' if rel else part
        if out.name(rel) not in out.names:
            out.add(rel, 'dir', mode=0o755, uid=www[0], gid=www[1], mtime=time.time())
    for name, data in sorted(files.items()):
        out.add(f'{rel}/{name}', 'file', mode=0o644, uid=www[0], gid=www[1], mtime=time.time(), size=len(data),
                fileobj=io.BytesIO(data))


# ====================================================================== the live target

APP_ENV_KEYS = frozenset()  # nothing of the app container's environment is passed to a throwaway copy


class Live:
    """The live Nextcloud as its Quadlet files describe it: the database container (image, allowed environment,
    secret mounts, PGDATA, name), the app and Redis containers, and which catalog data dir each mount is."""

    def __init__(self, quadlets, home, app):
        containers = {}
        for name, text in quadlets.items():
            if name.endswith('.container'):
                containers[name] = (text, ha_odoo.quadlet_mounts(quadlets, name, home))
        home = home.rstrip('/') + '/'

        def rel(source):
            return source[len(home):] if source.startswith(home) else None

        def find(test):
            found = [name for name, (text, mounts) in containers.items() if test(text, mounts)]
            return found[0] if len(found) == 1 else None

        self.db_file = find(lambda text, mounts: 'POSTGRES_' in ha_odoo._text_of(text)
                            and any(t == '/var/lib/postgresql/data' for _s, t, _o in mounts))
        self.app_file = find(lambda _text, mounts: {'/var/www/html', '/var/www/html/data'}
                             <= {t for _s, t, _o in mounts})
        self.redis_file = find(lambda text, mounts: 'redis' in (tempctr.quadlet_image(text) or '')
                               and any(t == '/data' for _s, t, _o in mounts))
        if None in (self.db_file, self.app_file, self.redis_file):
            raise BackupError('incompatible', '這台的 Nextcloud 不是 WOOWTECH 的 Podman 版本（找不到資料庫、Nextcloud 或 '
                                              'Redis 的 Quadlet 檔）。', app=app.id)
        for name in (self.db_file, self.app_file, self.redis_file):
            text = ha_odoo._text_of(containers[name][0])
            if any(key in ('UserNS', 'User') for key, _v in tempctr.parse_unit(text).get('Container', [])):
                raise BackupError('incompatible', f'{name} 設定了 UserNS= 或 User=，目前的 Nextcloud 匯入不支援。',
                                  app=app.id)
        db_text = containers[self.db_file][0]
        self.db_image = tempctr.quadlet_image(db_text)
        self.db_env = tempctr.quadlet_environment(db_text, ha_odoo.DB_ENV_KEYS)
        self.db_secrets = tempctr.quadlet_secrets(db_text)
        self.db_container = ha_odoo.quadlet_container_name(quadlets, self.db_file)
        self.db_user = self.db_env.get('POSTGRES_USER', 'postgres')
        self.db_name = self.db_env.get('POSTGRES_DB', self.db_user)
        mounts = {t: s for s, t, _o in containers[self.db_file][1]}
        self.db_target = '/var/lib/postgresql/data'
        self.pgdata = self.db_env.get('PGDATA') or self.db_target
        self.app_image = tempctr.quadlet_image(containers[self.app_file][0])
        self.app_container = ha_odoo.quadlet_container_name(quadlets, self.app_file)
        self.redis_image = tempctr.quadlet_image(containers[self.redis_file][0])
        self.redis_container = ha_odoo.quadlet_container_name(quadlets, self.redis_file)
        app_mounts = {t: s for s, t, _o in containers[self.app_file][1]}
        redis_mounts = {t: s for s, t, _o in containers[self.redis_file][1]}
        self.rels = {'postgres': rel(mounts[self.db_target]), 'redis': rel(redis_mounts['/data']),
                     'html': rel(app_mounts['/var/www/html']), 'data': rel(app_mounts['/var/www/html/data'])}
        problems = []
        if not self.db_image or not self.app_image or not self.redis_image:
            problems.append('Quadlet 設定缺少映像')
        if not (ROLE_RE.fullmatch(self.db_user) and DB_RE.fullmatch(self.db_name)):
            problems.append('資料庫使用者或名稱的格式不受支援')
        if self.pgdata != self.db_target:
            problems.append('PGDATA 不在資料夾的最上層')
        if app.postgres or app.volumes:
            problems.append('應用設定含有資料庫匯出或資料卷項目')
        if sorted(d['path'] for d in app.data_dirs) != sorted(r for r in self.rels.values() if r) \
                or len(set(self.rels.values())) != 4 or None in self.rels.values():
            problems.append('主機資料夾和 Nextcloud 的 Quadlet 設定不一致')
        if problems:
            raise BackupError('incompatible', f'這台的 Nextcloud 應用設定不是 HA 匯入支援的樣子：{"；".join(problems)}。',
                              app=app.id)


def _exec(work, app, container, argv, what, *, max_output=MAX_CONFIG):
    """A read-only command in a LIVE container (`podman exec`), as the owner; job-failed when it cannot run."""
    try:
        return work.runner(app).podman('exec', container, *argv, timeout=120, max_output=max_output).stdout or b''
    except BackupError as error:
        if error.code != 'job-failed':
            raise
        raise BackupError('job-failed', f'無法讀取這台 Nextcloud 的{what}，請確認它正在執行。', app=app.id) from None


def php_config(work, app, live):
    """The live config.php as its own PHP evaluates it (NC-05), in the shape Nextcloud writes it: read only, the file
    is this device's own and runs in this device's own container (never HA's). None when it cannot be."""
    try:
        out = _exec(work, app, live.app_container, ['php', '-d', 'display_errors=0', '-r', PHP_DUMP], '設定檔 config.php')
        return parse_config(out)
    except ValueError:
        return None
    except BackupError as error:
        if error.code != 'job-failed' or haissues.is_job_wide(error):
            raise
        return None


def live_config(work, app, live):
    """The live config.php (parsed strictly, secrets masked). One that is not what Nextcloud writes (a function, a double-quoted
    text with a variable ...) is read by this device's own PHP instead (NC-05); only when that fails Nextcloud stops."""
    data = _exec(work, app, live.app_container, ['cat', '/var/www/html/config/config.php'], '設定檔 config.php')
    try:
        config = parse_config(data)
    except ValueError:
        config = php_config(work, app, live)
        if config is None:
            raise haissues.stopped(haissues.Issue(
                'nextcloud.live-config-unreadable', 'stop', '無法解讀這台 Nextcloud 的 config.php（格式不是 Nextcloud 自己寫的樣子），'
                '也無法請這台 Nextcloud 自己讀出它的設定值。',
                action='請先在這台確認 Nextcloud 能正常運作、config.php 是 Nextcloud 自己寫的樣子，再匯入。'),
                'incompatible', app=app.id) from None
        _sink(work, app).auto('nextcloud.live-config-php',
                            '這台 Nextcloud 的 config.php 不是 Nextcloud 自己寫的樣子（含有函式或變數），'
                            '已改由這台 Nextcloud 自己的 PHP 讀出設定值。')
    mask_config(config)
    role, dbname = config.get('dbuser'), config.get('dbname')
    if config.get('dbtype') != 'pgsql' or not (isinstance(role, str) and ROLE_RE.fullmatch(role)) \
            or dbname != live.db_name or not isinstance(config.get('datadirectory'), str):
        raise BackupError('incompatible', '這台 Nextcloud 的 config.php 資料庫或資料夾設定不是 HA 匯入支援的樣子。',
                          app=app.id)
    return config


def live_stat(work, app, container, path):
    """(uid, gid, mode) of a live mount point, in the container's view (= the owner's namespace: no UserNS)."""
    out = _exec(work, app, container, ['stat', '-c', '%u %g %a', path], '資料夾權限', max_output=4096)
    match = STAT_RE.fullmatch(out)
    if match is None:
        raise BackupError('job-failed', '無法讀取這台 Nextcloud 資料夾的權限。', app=app.id)
    return int(match.group(1)), int(match.group(2)), int(match.group(3), 8)


def live_apps(work, app, live):
    """The app folders of the live html dir: (shipped apps, custom apps)."""
    found = []
    for folder in ('apps', 'custom_apps'):
        out = _exec(work, app, live.app_container, ['ls', '-1A', f'/var/www/html/{folder}'], '應用程式清單',
                    max_output=256 * 1024)
        found.append({name for name in out.decode('utf-8', 'replace').split('\n') if APP_ID_RE.fullmatch(name)})
    return found[0], found[1]


def live_office_cache(work, app, live, config):
    """{name: bytes}: what this device's Office app has cached of its Collabora (OFFICE_CACHE); {} when it has none."""
    instance = config.get('instanceid')
    if not (isinstance(instance, str) and INSTANCE_RE.fullmatch(instance)):
        return {}
    folder = f'/var/www/html/data/appdata_{instance}/richdocuments/remoteData'
    files = {}
    for name in OFFICE_CACHE:
        data = _exec(work, app, live.app_container, ['sh', '-c', 'if [ -f "$1" ]; then cat "$1"; fi', 'sh',
                                                     f'{folder}/{name}'], 'Office 設定', max_output=MAX_OFFICE_CACHE)
        if data:
            files[name] = data
    return files


def image_env(work, app, image, key):
    info = work.adapter(app).image_inspect(image) or {}
    for item in info.get('env', []):
        if isinstance(item, str) and item.startswith(key + '='):
            return item.split('=', 1)[1].strip()[:32]
    return None


def live_db_sql(role, *, appconfig=True):
    """What the import reads of the LIVE database, as its superuser: names resolve in pg_catalog only, so nothing the
    Nextcloud role could have created in `public` can stand in for a built-in. `appconfig` False: without the Office settings
    (NC-09: the part that can fail on its own)."""
    lit = ha_odoo.sql_literal
    keys = ' OR '.join(f'(appid = {lit(a)} AND configkey = {lit(k)})' for a, k in LIVE_APPCONFIG)
    parts = [f""" 'role', (SELECT json_build_object('password', rolpassword, 'super', rolsuper, 'login', rolcanlogin,
          'createdb', rolcreatedb, 'createrole', rolcreaterole, 'replication', rolreplication,
          'bypassrls', rolbypassrls, 'connlimit', rolconnlimit) FROM pg_authid WHERE rolname = {lit(role)})""",
             """ 'roles', (SELECT coalesce(json_agg(rolname ORDER BY rolname), '[]'::json) FROM pg_roles WHERE rolname !~ '^pg_')""",
             """ 'extensions', (SELECT coalesce(json_agg(extname ORDER BY extname), '[]'::json) FROM pg_extension)""",
             """ 'available', (SELECT coalesce(json_agg(name ORDER BY name), '[]'::json) FROM pg_available_extensions)""",
             """ 'datacl', (SELECT datacl::text FROM pg_database WHERE datname = current_database())""",
             """ 'nspacl', (SELECT nspacl::text FROM pg_namespace WHERE nspname = 'public')"""]
    if appconfig:
        parts.append(f""" 'appconfig', (SELECT coalesce(json_agg(row_to_json(a) ORDER BY appid, configkey), '[]'::json)
               FROM public.oc_appconfig a WHERE {keys})""")
    return 'SET search_path = pg_catalog; SELECT json_build_object(\n' + ',\n'.join(parts) + ')'


def scram_verifier(password, *, iterations=4096, salt=None):
    """The SCRAM-SHA-256 verifier PostgreSQL keeps of `password` (RFC 5802 and 7677: the salted password, the keys of the client
    and the server; `SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>`). The role gets it as it is, so the password
    itself is never in a statement."""
    salt = os.urandom(16) if salt is None else salt
    salted = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    stored = hashlib.sha256(hmac.new(salted, b'Client Key', hashlib.sha256).digest()).digest()
    server = hmac.new(salted, b'Server Key', hashlib.sha256).digest()

    def b64(raw):
        return base64.b64encode(raw).decode('ascii')
    return f'SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored)}:{b64(server)}'


def database_role(work, app, doc, role, config, sink):
    """The Nextcloud database role the new cluster gets, from the live read `doc` (NC-07, NC-08): the live role as it is; or,
    when the live database has no such role or no usable password for it, the role config.php names with the password
    config.php holds (the verifier is made here); a superuser role stays one (it is loaded by a plain role: build_cluster)."""
    from . import jobs
    row = doc.get('role') if isinstance(doc.get('role'), dict) else None
    made = row is None      # not even the role is there (a role without a usable password is): the live lists have nothing of it
    password = row.get('password') if row else None
    if not (isinstance(password, str) and ha_odoo.VERIFIER_RE.fullmatch(password)):
        plain = config.get('dbpassword')
        if not (isinstance(plain, str) and PLAIN_PASSWORD_RE.fullmatch(plain)) or role.startswith('pg_'):
            raise haissues.stopped(haissues.Issue(
                'nextcloud.db-role-unusable', 'stop',
                '這台 Nextcloud 的資料庫裡沒有 config.php 寫的資料庫帳號，或它沒有可用的密碼，config.php 裡也沒有可用的密碼可以重建它，'
                '沒辦法讓 Nextcloud 在匯入後登入資料庫。', [role],
                action='請先在這台讓 Nextcloud 正常運作（它能連上自己的資料庫），再匯入。'), 'incompatible', app=app.id)
        password = scram_verifier(plain)
        row = dict(INSTALLER_ROLE, **{key: value for key, value in (row or {}).items() if key != 'password'})
        row['password'] = password
        sink.auto('nextcloud.db-role-created',
                  '這台 Nextcloud 的資料庫裡沒有 config.php 寫的資料庫帳號，或它沒有可用的密碼；'
                  '已用 config.php 裡的帳號與密碼在新的資料庫建立它。', [role])
    jobs.mask_secret(password)
    if row.get('super') is True:
        sink.auto('nextcloud.db-role-hand-over',
                  '這台 Nextcloud 用的資料庫帳號是超級使用者，不是 Nextcloud 安裝程式建立的樣子。放入 HA 的資料時改用權限低的暫時帳號，'
                  '放完再把資料交回這個帳號；匯入後它仍是超級使用者，和這台原本一樣。', [role])
    doc['role'] = row
    doc['role_made'] = made
    return doc


def _sink(work, app):
    """The app's sink of the job; a `work` that has none (the stand-in of the lab scripts) gets one that only collects."""
    sink = getattr(work, 'sink', None)
    return sink(app) if callable(sink) else haissues.Sink(app.id)


def office_unread(sink):
    """NC-09: this device's Office settings (or its cached Collabora answers) could not be read: the converted Nextcloud keeps
    HA's, a reminder says so (once)."""
    if not any(issue.id == 'nextcloud.office-settings-unread' for issue in sink.found):
        sink.notice('nextcloud.office-settings-unread',
                    '讀不到這台 Nextcloud 的 Office（Collabora）設定，匯入後 Office 設定會是 HA 的，可能開不了線上文件；'
                    '請在匯入後重新設定 Office。')


def live_database(work, app, live, role, config, sink):
    """The live database's role `role` (verifier masked), roles, extensions, grants and kept app settings. A role that is not
    there, one without a usable password and a superuser one are no refusal (database_role, NC-07, NC-08); Office settings that
    cannot be read are a reminder, `appconfig` is then None (NC-09)."""
    try:
        doc = hacommon.live_json(work, app, live.db_container, live.db_user, live.db_name, live_db_sql(role))
    except BackupError as error:
        if error.code != 'job-failed' or haissues.is_job_wide(error):
            raise
        doc = hacommon.live_json(work, app, live.db_container, live.db_user, live.db_name, live_db_sql(role, appconfig=False))
        doc = dict(doc, appconfig=None) if isinstance(doc, dict) else doc
    if not isinstance(doc, dict):
        raise BackupError('job-failed', '無法讀取這台 Nextcloud 的資料庫設定。', app=app.id)
    rows = doc.get('appconfig')
    if rows is not None and not (isinstance(rows, list) and all(isinstance(r, dict) and isinstance(r.get('appid'), str)
                                                                 and isinstance(r.get('configkey'), str) for r in rows)):
        doc['appconfig'] = rows = None
    if rows is None:
        office_unread(sink)
    if not all(isinstance(doc.get(key), list) for key in ('roles', 'extensions')):
        raise BackupError('job-failed', '無法讀取這台 Nextcloud 的資料庫設定。', app=app.id)
    available = doc.get('available')
    doc['available'] = [name for name in available if isinstance(name, str)] if isinstance(available, list) else []
    return database_role(work, app, doc, role, config, sink)


class Target:
    """Everything the import reads of the live app before it starts (nothing is stopped or written)."""

    def __init__(self, work, app):
        runner = work.runner(app)
        self.live = Live(work.quadlets(app), runner.home, app)
        # NC-04: a stopped Nextcloud or database is started to be read, and put back when the app's throwaway objects go; the waits
        # follow the size of the open HA backup, as those of hacommon.live_json do (a database that was stopped needs its recovery)
        size = hatarget.size_hint(getattr(work, 'ha', None))
        hatarget.ensure_running(work, app, self.live.app_container, size=size)
        hatarget.ensure_running(work, app, self.live.db_container, ready='postgres', size=size)
        self.config = live_config(work, app, self.live)
        self.image_version = image_env(work, app, self.live.app_image, 'NEXTCLOUD_VERSION')
        self.php_version = image_env(work, app, self.live.app_image, 'PHP_VERSION')
        self.role = self.config['dbuser']
        self.db = live_database(work, app, self.live, self.role, self.config, _sink(work, app))
        self.shipped, self.custom = live_apps(work, app, self.live)
        self.index = {d['path']: i for i, d in enumerate(app.data_dirs)}


# ====================================================================== HA's database

class Pinned:
    """`tmp` whose `podman exec`s into the container `role` carry PGOPTIONS=PINNED_OPTIONS: every psql, pg_dump and
    pg_restore session there resolves names in pg_catalog only, whatever HA's database or roles set."""

    def __init__(self, tmp, role):
        self._tmp, self._role = tmp, role

    def __getattr__(self, name):
        return getattr(self._tmp, name)

    def exec(self, role, argv, *, env=None, **kwargs):
        if role == self._role:
            env = {**(env or {}), 'PGOPTIONS': PINNED_OPTIONS}
        return self._tmp.exec(role, argv, env=env, **kwargs)


def toc_kinds(text):
    """The entry kinds of a `pg_restore -l` list (the longest known kind that starts an entry; else UNKNOWN ...)."""
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


def shape_problems(doc, *, converted=False):
    """zh-TW names of what a database holds beyond Nextcloud's own objects (SHAPE_SQL's document); None when it is
    unreadable. `converted`: the new cluster, which must not hold a per-role or per-database setting either."""
    if not isinstance(doc, dict) or not isinstance(doc.get('defaults'), list):
        return None
    counts = {key: doc.get(key) for key, _label in SHAPE_LABELS + (('role_settings', ''),)}
    if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in counts.values()):
        return None
    found = [label for key, label in SHAPE_LABELS if counts[key]]
    if any(not isinstance(d, str) or not DEFAULT_RE.fullmatch(d) for d in doc['defaults']):
        found.append('不是固定值的欄位預設值')
    if converted and counts['role_settings']:
        found.append('角色或資料庫層級的設定')
    return found


def shape_objects(doc):
    """(left out, stopping): the labels of what HA's database holds beyond Nextcloud's own objects, split into what is left
    out of the conversion (SKIPPABLE: the functions and triggers of other apps) and what stops it; None when the document
    cannot be read (shape_problems)."""
    problems = shape_problems(doc)
    if problems is None:
        return None
    left_out = [label for key, label in SHAPE_LABELS if key in SKIPPABLE and doc.get(key)]
    return left_out, [label for label in problems if label not in left_out]


def object_names(doc):
    """The names OBJECTS_SQL gives, as a list of texts ('函式 public.f', ...); [] when the answer is not what it should be."""
    if not isinstance(doc, dict):
        return []
    names = []
    for key, label in (('functions', '函式'), ('triggers', '觸發程序')):
        value = doc.get(key)
        if isinstance(value, list):
            names += [f'{label} {name}' for name in value if isinstance(name, str)]
    return names


def known_objects(names, shape):
    """(apps, others): the known apps (KNOWN_OBJECTS) whose objects are among `names` (object_names), and whether any other
    object is left out as well (`others`). A list that is not whole (OBJECTS_SQL cuts it at 100 names; `shape` counts them all)
    cannot say that nothing else is there: `others` is then True. Nothing a backup names can make something be restored."""
    count = sum(shape.get(key) for key in SKIPPABLE if isinstance(shape.get(key), int)) if isinstance(shape, dict) else None
    apps, others = set(), count is None or count != len(names)
    for name in names:
        owner = next((app for app, objects in KNOWN_OBJECTS.items() if name.split(' ', 1)[-1] in objects), None)
        if owner is None:
            others = True
        else:
            apps.add(owner)
    return sorted(apps), others


def _counts_sql(tables):
    parts = [f"'{key}', (SELECT count(*) FROM public.{table})" for table, key in COUNTED if table in tables]
    return 'SELECT json_build_object(' + ', '.join(parts) + ')'


TABLES_SQL = ("SELECT coalesce(json_agg(tablename ORDER BY tablename), '[]'::json) FROM pg_tables "
              "WHERE schemaname = 'public'")
HA_SQL = """SELECT json_build_object(
 'extensions', (SELECT coalesce(json_agg(extname ORDER BY extname), '[]'::json) FROM pg_extension),
 'schemas', (SELECT coalesce(json_agg(nspname ORDER BY nspname), '[]'::json) FROM pg_namespace
             WHERE nspname !~ '^pg_' AND nspname NOT IN ('information_schema', 'public')),
 'local_storages', (SELECT coalesce(json_agg(id ORDER BY numeric_id), '[]'::json) FROM public.oc_storages
                    WHERE id LIKE 'local::%' OR id ~ '^[0-9a-f]{32}$'),
 'enabled', (SELECT coalesce(json_agg(appid ORDER BY appid), '[]'::json) FROM public.oc_appconfig
             WHERE configkey = 'enabled' AND configvalue <> 'no'),
 'encryption', (SELECT configvalue FROM public.oc_appconfig WHERE appid = 'core' AND configkey = 'encryption_enabled'))"""


# Nextcloud's list of every user's files (home storages, `files/**` without the folders) as counts, bytes and an
# order-free digest, compared with the files in the backup (DataDir.listed; lists_differ).
FILES_SQL = """SELECT coalesce(json_agg(json_build_array(owner, files, bytes, digest) ORDER BY owner), '[]'::json) FROM (
 SELECT substr(s.id, 7) AS owner, count(*) AS files, sum(f.size)::bigint AS bytes,
        bit_xor(('x' || substr(md5(f.size::text || ':' || f.path), 1, 16))::bit(64)::bigint) AS digest
 FROM public.oc_filecache f JOIN public.oc_storages s ON s.numeric_id = f.storage
 WHERE s.id LIKE 'home::%' AND f.path LIKE 'files/%'
   AND f.mimetype <> (SELECT m.id FROM public.oc_mimetypes m WHERE m.mimetype = 'httpd/unix-directory')
 GROUP BY s.id) q"""


def lists_differ(data, details):
    """The users whose files in the backup are not the ones Nextcloud's database lists (names), or [] when they are
    the same or cannot be compared (no list in the database, hard links)."""
    rows = details.get('lists') if isinstance(details, dict) else None
    if not isinstance(rows, list) or not isinstance(data, DataDir) or data.hardlinks:
        return []
    listed = {}
    for row in rows:
        if not (isinstance(row, list) and len(row) == 4 and isinstance(row[0], str)
                and all(isinstance(v, int) and not isinstance(v, bool) for v in row[1:])):
            return []
        listed[row[0]] = [row[1], row[2], row[3] % 2 ** 64]
    return sorted(user for user in set(listed) | set(data.lists) if listed.get(user) != data.lists.get(user))


def ha_database(cluster, dbname):
    """HA's database: {tables, shape, skipped, counts, extensions, schemas, local_storages, enabled, encryption, lists}.
    `cluster` runs pinned (Pinned). Its catalogs are read first: a database that holds anything beyond Nextcloud's own
    objects that cannot be left out (shape_objects) is not read any further, so no view or rule of HA's runs even in the
    throwaway cluster; the functions and triggers of other apps (which are left out) are only named (`skipped`)."""
    names = [d['name'] for d in ha_odoo.ha_databases(cluster)]
    if dbname not in names:
        return None
    tables = cluster.query_json(TABLES_SQL, dbname)
    if not isinstance(tables, list):
        raise BackupError('job-failed', '無法讀取 HA 的 Nextcloud 資料表。')
    tables = {t for t in tables if isinstance(t, str)}
    if not {'oc_appconfig', 'oc_storages', 'oc_users', 'oc_filecache'} <= tables:
        return {'tables': tables, 'nextcloud': False}
    shape = cluster.query_json(SHAPE_SQL, dbname)
    split = shape_objects(shape)
    if split is None or split[1]:      # unreadable, or something that cannot be left out: nothing more is read
        return {'tables': tables, 'nextcloud': True, 'shape': shape}
    skipped = object_names(cluster.query_json(OBJECTS_SQL, dbname)) if split[0] else []
    doc = cluster.query_json(HA_SQL, dbname)
    counts = cluster.query_json(_counts_sql(tables), dbname)
    if not isinstance(doc, dict) or not isinstance(counts, dict):
        raise BackupError('job-failed', '無法讀取 HA 的 Nextcloud 資料庫內容。')
    doc.update(tables=tables, shape=shape, skipped=skipped, counts={k: int(v) for k, v in counts.items() if isinstance(v, int)},
               nextcloud=True, lists=cluster.query_json(FILES_SQL, dbname) if 'oc_mimetypes' in tables else None)
    return doc


def userfiles_moved(data):
    """Whether HA's users' files are in the backup and move: a data folder that is there, with its .ncdata marker."""
    return isinstance(data, DataDir) and data.present and data.ncdata


def datadir_issues(sink, config, data, ha_source):
    """What HA's data directory (where it is, whether the backup holds it, what it holds) asks of the customer. The users'
    files that are not in the backup are one line to confirm (NC-22, NC-23, NC-25); what the walk leaves out of the data that
    is there is listed (NC-26, NC-27, and the reader's own list)."""
    if not isinstance(config, dict):
        return
    datadir = config.get('datadirectory')
    if not isinstance(datadir, str):
        sink.stop('nextcloud.no-datadir-setting', 'HA 的 Nextcloud 設定檔沒有使用者檔案資料夾（datadirectory）。')
    elif ha_source is None:
        sink.confirm('nextcloud.datadir-elsewhere', MSG_ELSEWHERE, [shown(datadir, 200)])
    elif data == 'no-share':
        sink.confirm('nextcloud.no-share', MSG_NO_SHARE, [shown(datadir, 200)])
    elif not userfiles_moved(data):
        sink.confirm('nextcloud.no-datadir', MSG_NO_DATADIR, [shown(datadir, 200)])
    else:
        if data.symlinks:
            names = data.report.skips.get('symlink') if data.report is not None else None
            sink.confirm('nextcloud.symlinks-skipped', MSG_SYMLINKS.format(count=data.symlinks), names or data.symlink_samples)
        if data.htaccess:
            sink.confirm('nextcloud.htaccess-skipped', MSG_HTACCESS.format(count=data.htaccess), data.htaccess_names)
        if data.hardlinks_copied:
            sink.auto('nextcloud.hardlinks-copied',
                      f'HA 的 Nextcloud 使用者檔案裡有 {data.hardlinks_copied} 個硬連結指到沒有搬過來的檔案（暫存檔），'
                      '已改成複製檔案內容。')
        if data.report is not None:
            sink.skipped(data.report, *[kind for kind in habackup.SKIP_KINDS if kind != 'symlink'])


def moves_of(config, live, storages, data):
    """storage_moves of HA's config.php, the live one, HA's stored ids and the walk of HA's data directory."""
    folders = sorted(data.team_folders) if isinstance(data, DataDir) else ()
    return storage_moves(config['datadirectory'], live['datadirectory'], storages, folders)


def ha_datadir_source(src):
    config = src.config if isinstance(src.config, dict) else {}
    return datadir_source(config.get('datadirectory'))


def raise_stops(sink):
    """A conversion never goes on past a stop, whatever kind of sink it was given (a conversion's own sink raises at the stop;
    this is what keeps it so for one that only collects)."""
    stop = next((issue for issue in sink.found if issue.level == 'stop'), None)
    if stop is not None:
        raise haissues.stopped(stop)


def member_issues(sink, src, target):
    """What the add-on's own files say (check and conversion, right after the add-on member was read): config.php, the
    PostgreSQL data, the files of an online backup, what the reader left out. Returns the reminders (notice texts)."""
    config, live = src.config, target.config
    warnings = []
    config_issues(sink, config, live, target.image_version, found=src.config_found,
                  addon_version=src.addon.version if src.addon else None)
    ha_major = ha_odoo._ha_major(src)
    if src.pg_version is None or ha_major is None:
        sink.stop('nextcloud.no-database', 'HA 備份裡沒有 Nextcloud 的 PostgreSQL 資料庫。',
                  action='請在 HA 確認 Nextcloud 附加元件有它的資料（資料庫）後重新備份；這次只有 Nextcloud 不會匯入，其他應用照常。')
    elif ha_major != 16:
        sink.stop('nextcloud.database-version', f'HA 的 PostgreSQL 是 {src.pg_version} 版，目前只支援 16 版。')
    # NC-32: HA's PostgreSQL against this device's is not asked here: the restore itself says (restore_dump).
    if src.recovery_files:
        sink.stop('nextcloud.online-backup', MSG_ONLINE)
    if src.report is not None:
        sink.skipped(src.report)
    if src.bad_apps:
        warnings.append(f'HA 的 custom_apps 裡有名稱不符合 Nextcloud 規則的資料夾（{hacommon.names(src.bad_apps)}），不會搬過來。')
    return warnings


def database_issues(sink, src, data, details, target):
    """What HA's database says (check and conversion, once its catalogs and counts are read); returns the reminders."""
    config, live = src.config, target.config
    warnings = []
    ha_major = ha_odoo._ha_major(src)
    if details is None and ha_major == 16 and not src.recovery_files:
        sink.stop('nextcloud.no-database-name', 'HA 的 PostgreSQL 裡沒有 Nextcloud 的資料庫。')
    elif isinstance(details, dict):
        split = shape_objects(details.get('shape')) if details.get('nextcloud') else None
        reasons = ['files_encryption'] if isinstance(data, DataDir) and data.encryption else []
        if not details.get('nextcloud'):
            sink.stop('nextcloud.not-nextcloud-db', 'HA 的資料庫不是 Nextcloud 的資料庫（找不到 Nextcloud 的資料表）。')
        elif split is None:
            sink.stop('nextcloud.shape-unreadable', MSG_SHAPE_UNREAD)
        elif split[1]:
            sink.stop('nextcloud.db-objects', MSG_SHAPE.format(kinds=hacommon.names(split[1])))
        else:
            if split[0]:
                names = details.get('skipped') or []
                apps, others = known_objects(names, details.get('shape'))
                if apps and not others:       # only what a known app makes again by itself: nothing is lost, nothing to confirm
                    sink.notice('nextcloud.db-objects-known', MSG_KNOWN_LEFT.format(apps=hacommon.names(apps)), names)
                else:
                    sink.confirm('nextcloud.db-objects-skipped', MSG_SKIPPED.format(kinds=hacommon.names(split[0])),
                                 names or split[0])
            extra = [e for e in details.get('extensions') or [] if e not in EXTENSIONS_OK]
            enable = [e for e in extra if e in target.db.get('available', ())]
            if enable:
                sink.auto('nextcloud.extension-enabled',
                          'HA 的 Nextcloud 資料庫使用了擴充功能，這台的資料庫映像也有，已自動啟用後再放資料。', enable)
            if len(enable) < len(extra):
                sink.stop('nextcloud.extension-missing',
                          'HA 的 Nextcloud 資料庫使用了這台的資料庫映像沒有的擴充功能，相依的欄位放不進去，無法匯入。',
                          items=[e for e in extra if e not in enable],
                          action='請先在這台安裝帶有這個擴充功能的 PostgreSQL 映像，或在 HA 移除它之後重新備份。')
            if details.get('schemas'):
                sink.confirm('nextcloud.schemas-skipped', MSG_SCHEMAS, details['schemas'])
            if details.get('encryption') == 'yes':
                reasons.append('encryption_enabled')
            storages = [s for s in details.get('local_storages') or [] if isinstance(s, str)]
            if isinstance(config, dict) and isinstance(config.get('datadirectory'), str):
                root = storage_id(config['datadirectory'])
                moves = moves_of(config, live, storages, data)
                if root not in storages:
                    sink.stop('nextcloud.storage-missing',
                              'HA 的 Nextcloud 資料庫和它的資料夾設定不一致（找不到使用者檔案資料夾的儲存空間記錄），無法匯入。')
                if any(new in storages for _old, new in moves):
                    sink.stop('nextcloud.storage-taken', MSG_STORAGE_TAKEN.format(dir=shown(live.get('datadirectory') or '', 200)))
                moved = {old for old, _new in moves} | {root}
                other = [s for s in storages if s.startswith('local::') and s not in moved]
                if other:
                    warnings.append(f'HA 的 Nextcloud 有 {len(other)} 個本機外部儲存空間（例如 {shown(other[0][7:])}），'
                                    '那些路徑在這台不存在，匯入後需要重新設定。')
            differ = lists_differ(data, details)
            if differ:
                warnings.append(MSG_LISTS.format(count=len(differ), names=hacommon.names(differ))
                                + '匯入後請在這台執行一次檔案掃描（' + SCAN_COMMAND.format(container=target.live.app_container) + '）。')
            if details.get('counts', {}).get('external_mounts'):
                warnings.append('HA 的 Nextcloud 設定了外部儲存空間，那些位置（HA 的資料夾或網路磁碟）在這台不一定存在，匯入後請檢查。')
            enabled = [a for a in details.get('enabled') or [] if isinstance(a, str)]
            missing = [a for a in enabled if a not in target.shipped and a not in src.apps and a not in target.custom]
            if missing:
                warnings.append(f'HA 啟用的 Nextcloud 應用 {hacommon.names(missing)} 在這台沒有程式，匯入後不會載入。')
        if reasons:
            sink.confirm('nextcloud.server-side-encryption', MSG_ENCRYPTION, reasons)
    if isinstance(config, dict) and isinstance(live, dict):
        warnings += app_warnings(src.apps, nc_version_text=nc_version(live.get('version')) or '',
                                 php_version=target.php_version)
        if not any(issue.level == 'stop' for issue in sink.found):
            _merged, _carried, skipped = merge_config(config, live)
            if skipped:
                warnings.append(f'HA 的 Nextcloud 設定 {hacommon.names(skipped)} 不會搬過來（以這台的設定為準）。')
    return warnings


def section(src, data, details, target):
    config = src.config if isinstance(src.config, dict) else {}
    counts = (details or {}).get('counts', {}) if isinstance(details, dict) else {}
    present = isinstance(data, DataDir) and data.present
    return {'nextcloud_version': nc_version(config.get('version')) or '',
            'addon_nextcloud_version': VERSIONS.upstream(src.addon.version) if src.addon else None,
            'users': counts.get('users', 0), 'files': counts.get('files', 0), 'shares': counts.get('shares', 0),
            'tokens': counts.get('tokens', 0), 'calendar_objects': counts.get('calendar_objects', 0),
            'contacts': counts.get('contacts', 0),
            'datadir': shown(config.get('datadirectory') or '', 200),
            'datadir_in_backup': present and data.ncdata,
            'datadir_files': data.files if present else 0, 'datadir_bytes': data.bytes if present else 0,
            'custom_apps': sorted(src.apps), 'pg_version': src.pg_version or '',
            'office': 'richdocuments' in ((details or {}).get('enabled') or []) if isinstance(details, dict) else False,
            'ha_url': shown(config.get('overwrite.cli.url') or '', 200),
            'target_url': str(target.config.get('overwrite.cli.url') or '')[:200]}


# ====================================================================== the job steps

def member_pass(work, app, tmp, image, *, apps=None):
    """The add-on member streamed once: the cluster into the throwaway volume `hapg`, config.php, custom apps."""
    member = work.addon_member(SLUG)
    report = habackup.Report(names=haissues.Names)
    holder = {}
    pg_ids = tmp.user_ids('ids-pg', image, 'postgres')

    def produce(out):
        sink = ha_odoo.PgSink(out, *pg_ids, guard=work.guard)
        with work.open(member) as stream:
            holder['src'] = scan_member(stream, report, pg=sink, apps=apps, machine=hacommon.host_elf_machine(),
                                        checkpoint=work.checkpoint)
        sink.close()

    tmp.volume('hapg')
    tmp.volume_import('hapg', produce)
    for note in report.warnings():
        work.log(note)
    src = holder['src']
    src.report = report
    work.log(f'HA 的 Nextcloud：PostgreSQL {src.pg_version or "?"}，{src.pg_files} 個資料庫檔案'
             f'（{ha_odoo._mib(src.pg_bytes)}），{len(src.apps)} 個自訂應用')
    return src


def datadir_pass(work, src, *, out=None, ids=None):
    """HA's data directory (the share folder member, or the add-on member): DataDir, 'no-share' when the share
    folder is not in the backup, None when config.php has no usable data directory."""
    config = src.config if isinstance(src.config, dict) else {}
    located = datadir_source(config.get('datadirectory'))
    if located is None:
        return None
    kind, prefix = located
    member = work.share_member() if kind == 'share' else work.addon_member(SLUG)
    if member is None:
        return 'no-share'
    report = habackup.Report(names=haissues.Names)
    with work.open(member) as stream:
        data = scan_datadir(stream, report, prefix, addon=kind == 'addon', instanceid=config.get('instanceid'),
                            out=out, ids=ids, checkpoint=work.checkpoint)
    if report.skipped_other:
        work.log(f'HA 的 Nextcloud 使用者檔案裡有 {report.skipped_other} 個特殊檔案（FIFO）沒有搬過來。')
    work.log(f'HA 的 Nextcloud 使用者檔案：{data.files} 個檔案（{ha_odoo._mib(data.bytes)}），'
             f'{len(data.users)} 位使用者的資料夾' + (f'，略過 {data.skipped_files} 個暫存檔' if data.skipped_files else ''))
    return data


def _source(work, app, tmp, *, apps=None):
    """(PostgreSQL 16 image, Source): HA's add-on ships PostgreSQL 16 (Dockerfile:21-37); another major is a blocker
    found after the pass (member_issues), the cluster is then never started."""
    image = ha_odoo.pick_pg16(work, app)
    return image, member_pass(work, app, tmp, image, apps=apps)


def check(work, app):
    sink = work.sink(app)
    target = Target(work, app)
    tmp = work.temp(app)
    try:
        image, src = _source(work, app, tmp)
        data = datadir_pass(work, src)
        work.phase('check')
        details = None
        if isinstance(src.config, dict) and isinstance(src.config.get('dbname'), str) \
                and DB_RE.fullmatch(src.config['dbname']) and ha_odoo._ha_major(src) == 16 and not src.recovery_files:
            cluster = ha_odoo.start_ha_cluster(work, Pinned(tmp, 'hapg'), image)
            details = ha_database(cluster, src.config['dbname'])
    finally:
        tmp.remove('hapg')
        tmp.remove_volume('hapg')
    warnings = member_issues(sink, src, target)
    datadir_issues(sink, src.config, data, ha_datadir_source(src))
    warnings += database_issues(sink, src, data, details, target)
    return {'target_version': nc_version(target.config.get('version')) or '', 'warnings': warnings,
            'nextcloud': section(src, data, details, target)}


def import_texts(data):
    """(notes, reminders) of a conversion (haimport.import_texts; CONTRACT section 7 HaImport)."""
    notes = ['Nextcloud 的使用者、檔案、分享、行事曆、聯絡人與應用程式密碼會換成 HA 的；這台原本的 Nextcloud 帳號與檔案'
             '不會保留（匯入前的自動備份裡還有）。',
             'Nextcloud 的網址、資料庫密碼、郵件與快取設定保持這台的；Office 會改用這台的 Collabora。',
             'Nextcloud 會標示資料是從備份還原的（新的資料指紋），同步用戶端連上後不會因為這次匯入刪掉電腦上的檔案。']
    apps = data.get('custom_apps') or []
    if apps:
        notes.append(f'HA 的 Nextcloud 應用 {hacommon.names(apps)} 會一起放進這台的 custom_apps。')
    if data.get('policy'):
        notes.append(f'HA 的 Nextcloud 安全設定 {hacommon.names(data["policy"])} 會一起搬過來。')
    url = data.get('target_url') or '這台的 Nextcloud 網址'
    reminders = ['請把 HA 的 Nextcloud 附加元件永久停用（關掉開機自動啟動）：兩邊是同一個 Nextcloud 身分，同時使用會讓同步用戶端錯亂。',
                 f'請用 HA 那邊 Nextcloud 的帳號和密碼登入；桌面與手機的同步用戶端、行事曆與聯絡人（CalDAV/CardDAV）'
                 f'請改連到 {url}（應用程式密碼可以繼續使用）。',
                 '公開分享連結與聯邦雲端 ID 仍是 HA 的網址，請重新分享或通知對方。']
    if data.get('mail'):
        reminders.append('HA 的 Nextcloud 寄信（SMTP）設定沒有搬過來，請在這台 Nextcloud 的管理設定確認寄信設定。')
    if data.get('userfiles') is False:
        reminders.append('HA 的使用者檔案沒有搬過來：這台 Nextcloud 的使用者檔案資料夾目前是空的。請把 HA 的使用者檔案複製到這台的使用者檔案資料夾'
                         '（擁有者 www-data）後，執行一次檔案掃描：' + SCAN_COMMAND.format(container=data.get('app_container') or 'nextcloud-app'))
    if data.get('lists_differ'):
        reminders.append('HA 備份時有人在使用 Nextcloud，有些使用者的檔案清單和實際檔案不一致；匯入後請執行一次檔案掃描：'
                         + SCAN_COMMAND.format(container=data.get('app_container') or 'nextcloud-app'))
    apps = [a for a in data.get('left_out_apps') or [] if a in KNOWN_OBJECTS]       # NC-38, NC-45: the programs left out
    if apps:
        reminders.append(MSG_REPAIR.format(apps=hacommon.names(apps), container=data.get('app_container') or 'nextcloud-app'))
    if data.get('left_out_others'):
        reminders.append(MSG_LEFT_OUT)
    if not data.get('office'):
        reminders.append('HA 的 Nextcloud 沒有啟用 Office（richdocuments），需要的話請在這台 Nextcloud 的應用程式頁面啟用。')
    elif len(data.get('office_cache') or []) < len(OFFICE_CACHE):
        reminders.append('這台的 Office 還沒有取得 Collabora 的設定，匯入後第一次開文件前請先執行一次：'
                         + OFFICE_COMMAND.format(container=data.get('app_container') or 'nextcloud-app'))
    return notes, reminders


# -------------------------------------------------------------------- convert: the database

def role_sql(name, role, dbname):
    """The live Nextcloud role with its attributes and verifier, and the grants Nextcloud's installer gives it
    (lib/private/Setup/PostgreSQL.php:86,95,186-193,108)."""
    flags = ['LOGIN' if role.get('login') else 'NOLOGIN', 'SUPERUSER' if role.get('super') is True else 'NOSUPERUSER',
             'CREATEDB' if role.get('createdb') else 'NOCREATEDB',
             'CREATEROLE' if role.get('createrole') else 'NOCREATEROLE',
             'REPLICATION' if role.get('replication') else 'NOREPLICATION',
             'BYPASSRLS' if role.get('bypassrls') else 'NOBYPASSRLS']
    limit = role.get('connlimit')
    if isinstance(limit, int) and not isinstance(limit, bool) and limit >= 0:
        flags.append(f'CONNECTION LIMIT {limit}')
    ident, db = ha_odoo.pg_ident(name), ha_odoo.pg_ident(dbname)
    return (f"CREATE ROLE {ident} {' '.join(flags)} PASSWORD {ha_odoo.sql_literal(role['password'])};\n"
            f'GRANT CONNECT ON DATABASE {db} TO {ident};\n'
            f'REVOKE ALL PRIVILEGES ON DATABASE {db} FROM PUBLIC;\n')


ARCHIVE_SETTINGS = ('ENCODING', 'STDSTRINGS', 'SEARCHPATH')   # the three entries every pg_dump archive of 11 and later begins with
LISTING_SLACK = 9      # entries beyond the three settings a plain listing may keep back (a real PostgreSQL 16.15 listing: 2)
INCOMPLETE_LIST = '資料庫匯出檔的項目清單沒有完整送達（主機可能太忙），已停止，沒有做任何變更，請稍後再試。'


def toc_entries(text):
    """(entries, declared, shown) of a `pg_restore -l` listing: how many lines are entries (`<id>; <oid> <oid> <kind> ...`),
    the `TOC Entries:` its header says the archive has (None when the header is not there) and how many of the archive
    settings ENCODING, STDSTRINGS and SEARCHPATH the lines show."""
    declared, entries, shown_settings = None, 0, set()
    for line in text.splitlines():
        header = re.match(r';\s+TOC Entries:\s+([0-9]{1,9})\s*\Z', line)
        if header:
            declared = int(header.group(1))
        elif re.match(r'\s*\d+;\s+\d+\s+\d+\s', line):
            entries += 1
            kind = re.match(r'\s*\d+;\s+\d+\s+\d+\s+([A-Z]+)\s', line)
            if kind and kind.group(1) in ARCHIVE_SETTINGS:
                shown_settings.add(kind.group(1))
    return entries, declared, len(shown_settings)


def check_listing(text):
    """The `pg_restore -l` listing is whole when its entries are the ones its own header says the archive has, less the
    few a plain listing keeps back (pg-stdin follow-up F4: a listing that came back short would restore only the part it
    names, and nothing would notice). What a plain listing keeps back is no exact number: a REAL listing (PostgreSQL
    16.15, a Nextcloud database, this lane's shape probe of 2026-11-24) has 1131 entry lines under `TOC Entries: 1136`, so
    it keeps back five: the three archive settings ENCODING, STDSTRINGS and SEARCHPATH (none of them is listed) and two
    more of a kind nobody looked at. The lines may be short of the header by the settings not shown, plus LISTING_SLACK;
    a listing without the header, with more lines than the header or with a larger gap is refused (the same rule as
    Odoo's). A gap inside the slack goes unnoticed (a listing that was cut short loses a stretch of its end). Returns
    the number of entries."""
    entries, declared, shown_settings = toc_entries(text)
    held_back = None if declared is None else declared - entries
    lowest = len(ARCHIVE_SETTINGS) - shown_settings
    if held_back is None or not lowest <= held_back <= lowest + LISTING_SLACK:
        # the numbers (no content) go with the error: what a real run shows decides how tight the check can be
        raise BackupError('job-failed', INCOMPLETE_LIST, listed=entries, shown=shown_settings,
                          **({} if declared is None else {'declared': declared}))
    return entries


def restore_failed(majors):
    """The sentence of a restore that PostgreSQL refused (NC-32, NC-46): HA's PostgreSQL being newer than this device's is
    the likely reason when it is, and what to do about it."""
    ha_major, pg_major = majors if majors else (None, None)
    if ha_major is not None and pg_major is not None and ha_major > pg_major:
        return (f'無法把 HA 的 Nextcloud 資料庫還原到新的叢集：HA 的 PostgreSQL（{ha_major}）比這台的（{pg_major}）新，'
                '這台的資料庫放不進去。請先把這台 Nextcloud 的資料庫更新到同一版（或更新這台的 Nextcloud 套件）後再匯入；'
                '這台的 Nextcloud 沒有任何變更。')
    return ('無法把 HA 的 Nextcloud 資料庫還原到新的叢集（可能含有這台不支援、或需要資料庫超級使用者權限的內容）；'
            '這台的 Nextcloud 沒有任何變更。')


def skip_toc(text, kinds):
    """A `pg_restore -l` listing without the entries of these kinds (`FUNCTION`, `TRIGGER`) and the comments on them: what
    is left out of the restore and listed to the customer (NC-38, NC-45)."""
    if not kinds:
        return text
    names = '|'.join(re.escape(kind) for kind in kinds)
    entry = re.compile(rf'\s*\d+;\s+\d+\s+\d+\s+(?:{names})\s')
    comment = re.compile(rf'\s*\d+;\s+\d+\s+\d+\s+COMMENT\s+\S+\s+(?:{names})\s')
    return ''.join(line for line in text.splitlines(True) if not entry.match(line) and not comment.match(line))


def loader_sql(dbname, *, connect=True):
    """The plain role that loads HA's data when Nextcloud's own database role is a superuser (NC-08): no right but to
    connect and to create in `public`; it is handed over and dropped when the data is in (hand_over_sql). `connect` False:
    nothing revoked the right of every role to connect (the cluster's own superuser is the Nextcloud role, role_sql did not
    run), so none is granted: a grant and its revoke would leave an explicit list of rights in the database's ACL where this
    device's own database has none, and the check of the grants would see a difference."""
    ident = ha_odoo.pg_ident(LOADER)
    return (f'CREATE ROLE {ident} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n'
            + (f'GRANT CONNECT ON DATABASE {ha_odoo.pg_ident(dbname)} TO {ident};\n' if connect else ''))


def hand_over_sql(role):
    """Everything the loader made goes to Nextcloud's role, what the loader was given is taken back, the loader is dropped."""
    ident, loader = ha_odoo.pg_ident(role), ha_odoo.pg_ident(LOADER)
    return f'REASSIGN OWNED BY {loader} TO {ident};\nDROP OWNED BY {loader};\nDROP ROLE {loader};\n'


def restore_dump(work, tmp, dump, role, dbname, *, majors=None, skip=()):
    """HA's dump into the new database AS THE NEXTCLOUD ROLE (HA's server is untrusted: review HA-SEC-01), without
    its EXTENSION entries, refused when it holds superuser-only objects; streamed on stdin. The listing is cross-checked
    against its own header first and the retry note of its write reaches the job log (pg-stdin follow-ups F4, F3).
    `majors`: (HA's, this device's) PostgreSQL major, to say why a refused restore was refused (NC-32). `skip`: the kinds
    of entries the customer confirmed to leave out (SKIPPED_TOC); any other kind Nextcloud never creates stops it."""
    with open(dump, 'rb') as handle:
        toc = tmp.exec('nc-db', ['pg_restore', '-l'], user='postgres', input=handle, timeout=ha_odoo.DUMP_TIMEOUT,
                       max_output=ha_odoo.TOC_OUTPUT).stdout or b''
    text = toc.decode('utf-8', 'surrogateescape')
    check_listing(text)
    kinds = ha_odoo.superuser_kinds(text)
    if kinds:
        raise BackupError('incompatible', f'HA 的 Nextcloud 資料庫含有只有資料庫超級使用者才能建立的物件'
                                          f'（{hacommon.names(kinds)}），無法安全地搬過來。')
    odd = [kind for kind in toc_kinds(text) if kind not in TOC_ALLOWED and kind not in skip]
    if odd:
        raise BackupError('incompatible', MSG_TOC.format(kinds=hacommon.names(odd)))
    left = ha_odoo.filter_toc(skip_toc(text, skip))
    ha_odoo.Cluster(tmp, 'nc-db', log=work.log).write_file('/tmp/woowbk-nc.toc', left.encode('utf-8', 'surrogateescape'))
    work.log(f'把 HA 的 Nextcloud 資料庫還原到新的叢集（以 {role} 角色還原）')
    with open(dump, 'rb') as handle:
        try:
            tmp.exec('nc-db', ['pg_restore', '-U', role, '--no-owner', '--no-acl', '--exit-on-error',
                               '--single-transaction', '-L', '/tmp/woowbk-nc.toc', '-d', dbname],
                     user='postgres', input=handle, timeout=ha_odoo.DUMP_TIMEOUT, max_output=1024 * 1024)
        except BackupError as error:
            if error.code != 'job-failed':
                raise
            raise BackupError('job-failed', restore_failed(majors)) from None
    tmp.exec('nc-db', ['rm', '-f', '/tmp/woowbk-nc.toc'], user='postgres', timeout=120)


def _ext_ident(name):
    """An extension's name as an SQL identifier (the names are this device's own list, checked against EXT_RE)."""
    if not isinstance(name, str) or not EXT_RE.fullmatch(name):
        raise BackupError('internal-error', '擴充功能名稱格式不正確。')
    return f'"{name}"'


def removed_sql(old_root, remote):
    """How many file cache rows of HA's cached Collabora discovery the fix-ups delete (read as the table owner)."""
    lit = ha_odoo.sql_literal
    return (f'SELECT count(*) FROM public.oc_filecache WHERE storage = (SELECT numeric_id FROM public.oc_storages '
            f'WHERE id = {lit(old_root)}) AND (path = {lit(remote)} OR left(path, {len(remote) + 1}) = {lit(remote + "/")})')


def fixup_sql(moves, new_root, remote, live_rows, *, jobs=False):
    """The conversion's changes inside the restored database (one transaction, as the tables' owner, pinned): the
    storage rows of `moves` (storage_moves), this device's kept settings, HA's cached Collabora answers. `jobs`: the
    database has oc_jobs; the job that refreshes the Office app's cache is made due at once (the converted backup may be
    restored later than the cache it carries was read)."""
    lit = ha_odoo.sql_literal
    keys = ', '.join(f'({lit(a)}, {lit(k)})' for a, k in LIVE_APPCONFIG)
    sql = [f'UPDATE public.oc_storages SET id = {lit(new)} WHERE id = {lit(old)};\n' for old, new in moves]
    if live_rows is not None:      # None: this device's Office settings could not be read (NC-09): HA's stay as they are
        sql.append(f'DELETE FROM public.oc_appconfig WHERE (appid, configkey) IN ({keys});\n')
    if live_rows:
        sql.append('INSERT INTO public.oc_appconfig SELECT * FROM json_populate_recordset(NULL::public.oc_appconfig, '
                   f'{lit(json.dumps(live_rows, ensure_ascii=False, sort_keys=True))});\n')
    if remote:
        sql.append(f'DELETE FROM public.oc_filecache WHERE storage = (SELECT numeric_id FROM public.oc_storages WHERE '
                   f'id = {lit(new_root)}) AND (path = {lit(remote)} OR left(path, {len(remote) + 1}) = '
                   f'{lit(remote + "/")});\n')
    if jobs:
        sql.append('UPDATE public.oc_jobs SET last_run = 0, last_checked = 0, reserved_at = 0 WHERE class = '
                   f'{lit(OFFICE_JOB)};\n')
    return ''.join(sql)


def data_verify_sql(new_root, moves, tables):
    """The converted database's contents, read as the tables' owner (pinned): `root` = the root storage row, `moved` and
    `old` = how many of the moved storage rows have this device's and still have HA's id."""
    lit = ha_odoo.sql_literal
    counts = [f"'{key}', (SELECT count(*) FROM public.{table})" for table, key in COUNTED if table in tables]
    keys = ' OR '.join(f'(appid = {lit(a)} AND configkey = {lit(k)})' for a, k in LIVE_APPCONFIG)
    new_ids = ', '.join(lit(new) for _old, new in moves) or 'NULL'
    old_ids = ', '.join(lit(old) for old, _new in moves) or 'NULL'
    return f"""SELECT json_build_object(
 'counts', json_build_object({', '.join(counts)}),
 'root', (SELECT count(*) FROM public.oc_storages WHERE id = {lit(new_root)}),
 'moved', (SELECT count(*) FROM public.oc_storages WHERE id IN ({new_ids})),
 'old', (SELECT count(*) FROM public.oc_storages WHERE id IN ({old_ids})),
 'appconfig', (SELECT coalesce(json_agg(row_to_json(a) ORDER BY appid, configkey), '[]'::json)
               FROM public.oc_appconfig a WHERE {keys}))"""


def catalog_verify_sql(role):
    """The converted cluster's databases, roles, grants and extensions, read by its superuser from the catalogs only
    (pinned)."""
    lit = ha_odoo.sql_literal
    return f"""SELECT json_build_object(
 'owners', (SELECT coalesce(json_agg(DISTINCT tableowner), '[]'::json) FROM pg_tables WHERE schemaname = 'public'),
 'databases', (SELECT coalesce(json_agg(datname ORDER BY datname), '[]'::json) FROM pg_database),
 'verifier_md5', (SELECT md5(rolpassword) FROM pg_authid WHERE rolname = {lit(role)}),
 'role', (SELECT json_build_object('super', rolsuper, 'login', rolcanlogin, 'createdb', rolcreatedb,
          'createrole', rolcreaterole, 'replication', rolreplication, 'bypassrls', rolbypassrls,
          'connlimit', rolconnlimit) FROM pg_authid WHERE rolname = {lit(role)}),
 'roles', (SELECT coalesce(json_agg(rolname ORDER BY rolname), '[]'::json) FROM pg_roles WHERE rolname !~ '^pg_'),
 'extensions', (SELECT coalesce(json_agg(extname ORDER BY extname), '[]'::json) FROM pg_extension),
 'datacl', (SELECT datacl::text FROM pg_database WHERE datname = current_database()),
 'nspacl', (SELECT nspacl::text FROM pg_namespace WHERE nspname = 'public'),
 'grants', (SELECT count(*) FROM pg_class WHERE relacl IS NOT NULL AND relnamespace IN (SELECT oid FROM pg_namespace
            WHERE nspname !~ '^pg_' AND nspname <> 'information_schema')
            AND oid NOT IN (SELECT objid FROM pg_depend WHERE deptype = 'e' AND classid = 'pg_class'::regclass))
           + (SELECT count(*) FROM pg_attribute WHERE attacl IS NOT NULL AND attrelid IN (SELECT oid FROM pg_class
              WHERE relnamespace IN (SELECT oid FROM pg_namespace WHERE nspname !~ '^pg_'
                                     AND nspname <> 'information_schema'))),
 'role_settings', (SELECT count(*) FROM pg_db_role_setting))"""


ROLE_ATTRS = ('super', 'login', 'createdb', 'createrole', 'replication', 'bypassrls', 'connlimit')
BASELINE_KEYS = ('roles', 'datacl', 'nspacl')     # what a made role changes in the lists of this device's own database (NC-07)


def _rows(rows):
    return sorted(json.dumps(r, sort_keys=True, ensure_ascii=False) for r in rows or [])


def _same(found, expected):
    """Two lists of names are the same names whatever their order (the database sorts them by its own collation, `_` and `-`
    do not count there: Python's order is another one); anything else is compared as it is."""
    if isinstance(found, list) and isinstance(expected, list):
        return sorted(found) == sorted(expected)
    return found == expected


def verify_converted(doc, *, expected, db, role, dbname, moves):
    """zh-TW problems of the converted database against what it must be."""
    if not isinstance(doc, dict):
        return ['無法讀取轉換後的資料庫']
    problems = []
    attrs = doc.get('role') if isinstance(doc.get('role'), dict) else {}
    if any(attrs.get(key) != db['role'].get(key) for key in ROLE_ATTRS):
        problems.append(f'{role} 角色的權限和這台的不同')
    if doc.get('role_settings') != 0:
        problems.append('出現了角色或資料庫層級的設定')
    # The role may create databases (CREATEDB, as on the live cluster): SQL hidden in HA's dump could leave one behind.
    if not _same(doc.get('databases'), sorted({'postgres', 'template0', 'template1', dbname})):
        problems.append('資料庫叢集裡有其他資料庫')
    # The dump is restored with --no-acl: a grant on a table or column can only come from SQL hidden in HA's dump.
    if doc.get('grants') != 0:
        problems.append('資料表或欄位多了權限設定')
    if doc.get('counts') != expected:
        problems.append('資料筆數和 HA 的不同')
    if doc.get('owners') != [role]:
        problems.append(f'資料表的擁有者不是 {role}')
    # PostgreSQL keeps a verifier only when it parses as one (else it hashes the text as a password): the role must
    # hold exactly the live verifier, or Nextcloud's config.php password would not log in after the restore.
    if doc.get('verifier_md5') != hashlib.md5(db['role']['password'].encode('utf-8')).hexdigest():
        problems.append(f'{role} 角色的密碼設定和這台的不同')
    if doc.get('root') != 1 or doc.get('moved') != len(moves) or doc.get('old') != 0:
        problems.append('使用者檔案資料夾的儲存空間記錄沒有改成這台的路徑')
    for key, label in (('roles', '資料庫角色'), ('extensions', '擴充功能'), ('datacl', '資料庫權限'),
                       ('nspacl', 'public schema 權限')):
        if not _same(doc.get(key), db.get(key)):
            problems.append(f'{label}和這台的不同')
    if db.get('appconfig') is not None and _rows(doc.get('appconfig')) != _rows(db.get('appconfig')):
        problems.append('Office 或背景工作設定和這台的不同')
    return problems


def carry_settings(work, app, live, cluster, sink):
    """PostgreSQL settings the live cluster sets (ha_odoo.settings_to_carry), written with ALTER SYSTEM. What cannot be carried
    (the live cluster's settings cannot be read, one is refused by the new cluster) is taken out again and the new
    cluster uses its defaults for it: a reminder (NC-49), the data is not touched."""
    try:
        live_rows = hacommon.live_json(work, app, live.db_container, live.db_user, 'postgres', ha_odoo.SETTINGS_SQL)
    except BackupError as error:
        if error.code != 'job-failed' or haissues.is_job_wide(error):
            raise
        sink.notice('nextcloud.settings-not-carried', '讀不到這台 PostgreSQL 自己的設定，新的資料庫改用預設值；資料沒有影響。')
        return []
    carried = []
    for name, value in ha_odoo.settings_to_carry(live_rows, cluster.query_json(ha_odoo.SETTINGS_SQL)):
        sql = ha_odoo.alter_system_sql(name, value)
        if sql is not None:
            cluster.statement(sql)
            carried.append(name)

    def refused():
        cluster.statement('SELECT pg_reload_conf();')
        rows = cluster.query_json(ha_odoo.FILE_SETTINGS_SQL)
        written = {r[0].lower(): r[2] for r in rows or [] if isinstance(r, list) and len(r) == 3}
        return [name for name in carried if name not in written or written[name]]

    if carried:
        bad = refused()
        if bad:
            for name in bad:
                cluster.statement(f'ALTER SYSTEM RESET {name};')
            carried = [name for name in carried if name not in bad]
            if refused():     # one that is still refused: none of them is kept
                cluster.statement('ALTER SYSTEM RESET ALL;')
                bad, carried = bad + [name for name in carried if name not in bad], []
                cluster.statement('SELECT pg_reload_conf();')
            sink.notice('nextcloud.settings-not-carried', '沿用這台 PostgreSQL 設定失敗，新的資料庫對它們改用預設值；資料沒有影響。',
                        bad)
        if carried:
            work.log(f'沿用這台 PostgreSQL 的設定：{"、".join(carried)}')
    return carried


def build_cluster(work, app, tmp, target, dump, *, details, old_root, new_root, moves, remote, majors=None):
    """The new cluster in the throwaway volume `nc-db` (stopped cleanly); returns the verified document."""
    live, db, role = target.live, target.db, target.role
    sink = _sink(work, app)
    # NC-08: a superuser role never loads HA's data: a plain role does and owns it until the fix-ups and the reads of the
    # tables are done, then everything goes to the role and the plain one is dropped
    plain = db['role'].get('super') is not True
    loader = role if plain else LOADER
    work.log('建立新的 PostgreSQL 資料庫叢集（與這台相同的映像與設定）')
    tmp.volume('nc-db')
    tmp.run('nc-db', live.db_image, [], detach=True, volumes=[(tmp.name('nc-db'), live.db_target, None)],
            env=live.db_env, secrets=live.db_secrets)
    pg = ha_odoo.Cluster(tmp, 'nc-db', superuser=live.db_user, log=work.log)
    pg.wait_ready(tcp=True, checkpoint=work.checkpoint)
    own = role == live.db_user and not plain
    if own:      # the cluster's own superuser exists already: it only gets this device's verifier
        pg.script(f'ALTER ROLE {ha_odoo.pg_ident(role)} PASSWORD {ha_odoo.sql_literal(db["role"]["password"])};\n')
    else:
        pg.script(role_sql(role, db['role'], live.db_name))
    if not plain:
        pg.script(loader_sql(live.db_name, connect=not own))
    extensions = [e for e in db['extensions'] if e != 'plpgsql' and ROLE_RE.fullmatch(e)]
    # NC-39: what HA's database uses and this device's database image has is enabled too (before HA's data is put in)
    extras = [e for e in details.get('extensions') or [] if e not in EXTENSIONS_OK and e not in extensions
              and e in db.get('available', ()) and EXT_RE.fullmatch(e)]
    pg.script(f'GRANT CREATE ON SCHEMA public TO {ha_odoo.pg_ident(loader)};\n'
              + ''.join(f'CREATE EXTENSION IF NOT EXISTS {_ext_ident(e)};\n' for e in extensions + extras), live.db_name)
    baseline = None
    if db.get('role_made'):
        # NC-07: this device's database has no such role, so its list of roles and its rights (database, schema public) have nothing
        # of the role to be compared with. What the new cluster is before HA's data goes in (the role, its rights, the extensions)
        # is the baseline the converted one must still be after it: HA's dump may add no role and no right.
        baseline = pg.query_json(catalog_verify_sql(role), live.db_name)
        if not (isinstance(baseline, dict) and isinstance(baseline.get('roles'), list) and all(key in baseline for key in BASELINE_KEYS)):
            raise BackupError('job-failed', '無法讀取新資料庫的角色與權限。')
    left_out = shape_objects(details.get('shape'))
    restore_dump(work, tmp, dump, loader, live.db_name, majors=majors, skip=SKIPPED_TOC if left_out and left_out[0] else ())
    # From here on the cluster holds HA's objects: every session is pinned (Pinned); the superuser reads catalogs only
    # and never touches a table of HA's, the fix-ups and table reads run as the tables' owner (the live Nextcloud role, or
    # the plain loader of a superuser role), so a default, constraint or index expression of HA's never runs with more
    # rights than Nextcloud itself has.
    pinned = Pinned(tmp, 'nc-db')
    admin = ha_odoo.Cluster(pinned, 'nc-db', superuser=live.db_user, log=work.log)
    owner = ha_odoo.Cluster(pinned, 'nc-db', superuser=loader, log=work.log)
    shape = shape_problems(admin.query_json(SHAPE_SQL, live.db_name), converted=True)
    if shape is None:
        raise BackupError('job-failed', '無法讀取轉換後的 Nextcloud 資料庫結構。')
    if shape:
        raise BackupError('incompatible', MSG_SHAPE.format(kinds=hacommon.names(shape)))
    removed = owner.query_json(removed_sql(old_root, remote), live.db_name) if remote else 0
    owner.script(fixup_sql(moves, new_root, remote, db['appconfig'], jobs='oc_jobs' in details['tables']), live.db_name)
    expected = dict(details['counts'])
    expected['files'] = expected.get('files', 0) - int(removed or 0)
    doc = owner.query_json(data_verify_sql(new_root, moves, details['tables']), live.db_name)
    if not plain:
        admin.script(hand_over_sql(role), live.db_name)
    catalog = admin.query_json(catalog_verify_sql(role), live.db_name)
    if isinstance(doc, dict) and isinstance(catalog, dict):
        doc = {**doc, **catalog}
    else:
        doc = None
    problems = verify_converted(doc, expected=expected, role=role, dbname=live.db_name, moves=moves,
                                db=dict(db, extensions=sorted(set(db['extensions']) | set(extras)),
                                        **({key: baseline[key] for key in BASELINE_KEYS} if baseline else {})))
    if problems:
        raise BackupError('job-failed', f'轉換後的 Nextcloud 資料庫檢查沒有通過：{"；".join(problems)}。')
    carry_settings(work, app, live, admin, sink)
    admin.statement('CHECKPOINT;')
    code = tmp.stop('nc-db', timeout=300)
    if code != 0:
        raise BackupError('job-failed', f'新的 PostgreSQL 叢集沒有正常關閉（結束碼 {code}）。')
    state = tmp.run('controldata', live.db_image, ['pg_controldata', live.pgdata], user='postgres',
                    volumes=[(tmp.name('nc-db'), live.db_target, 'ro')], timeout=300, read_only_root=True,
                    max_output=1024 * 1024).stdout or b''
    if not re.search(rb'Database cluster state:\s+shut down\s*$', state, re.M):
        raise BackupError('job-failed', '新的 PostgreSQL 叢集沒有正常關閉。')
    tmp.remove('nc-db')
    return {'counts': doc['counts'], 'removed_cache_rows': int(removed or 0)}


# -------------------------------------------------------------------- convert: the folders

def php_check(tmp, image, data, merged):
    """The live image's PHP parses the merged config.php and returns exactly the merged values (stdin in, JSON out;
    network none, read-only root; nothing is logged)."""
    script = ('cat > /tmp/woowbk-config.php && php -l /tmp/woowbk-config.php >/dev/null && '
              'php -r \'include "/tmp/woowbk-config.php"; echo json_encode($CONFIG);\'')
    out = tmp.run('nc-php', image, ['-c', script], entrypoint='sh', input=data, read_only_root=True, timeout=300,
                  max_output=4 * MAX_CONFIG).stdout or b''
    try:
        parsed = json.loads(out.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        parsed = None
    if parsed != jsonable(merged):
        raise BackupError('job-failed', '合併後的 Nextcloud 設定檔 config.php 沒有通過這台 PHP 的檢查。')


def html_tar(live_tar, apps_tar, out, *, config_data, www, ha_apps):
    """The html dir as it will be (`./`-names): the live pack without config/config.php and without the custom apps
    HA brings, the merged config.php (owner and mode of the live one) and HA's custom apps (owner www-data)."""
    config_info = None
    try:
        with ha_odoo._live_tar(live_tar, '這台的 Nextcloud 程式資料夾') as tar:
            for member in tar:
                name = ha_odoo._norm(member.name)
                if name is None:
                    raise BackupError('job-failed', '這台 Nextcloud 程式資料夾的匯出內容格式不正確。')
                parts = name.split('/')
                if name == 'config/config.php':
                    config_info = (member.uid, member.gid, member.mode & 0o777)
                elif not (parts[0] == 'custom_apps' and len(parts) >= 2 and parts[1] in ha_apps):
                    if member.islnk():
                        link = ha_odoo._norm(member.linkname)
                        if link is None or out.name(link) not in out.names:
                            raise BackupError('job-failed', '這台 Nextcloud 程式資料夾有指向被取代檔案的硬連結，無法轉換。')
                        member.linkname = out.name(link)
                    out.tar.add_member(ha_odoo._copy_info(member, out.name(name)),
                                       tar.extractfile(member) if member.isfile() else None)
                tar.members.clear()
    except tarfile.TarError:
        raise BackupError('job-failed', '這台 Nextcloud 程式資料夾的匯出內容無法讀取。') from None
    if config_info is None:
        raise BackupError('job-failed', '這台 Nextcloud 的程式資料夾裡沒有 config/config.php。')
    uid, gid, mode = config_info
    out.add('config/config.php', 'file', mode=mode, uid=uid, gid=gid, mtime=time.time(), size=len(config_data),
            fileobj=io.BytesIO(config_data))
    if ha_apps and out.name('custom_apps') not in out.names:
        out.add('custom_apps', 'dir', mode=0o750, uid=www[0], gid=www[1], mtime=time.time())
    if apps_tar is None:
        return
    with tarfile.open(apps_tar, 'r|', encoding=habackup.ENCODING, errors=habackup.ERRORS) as tar:
        for member in tar:
            rel = f'custom_apps/{member.name}'
            if member.isdir():
                out.add(rel, 'dir', mode=member.mode, uid=www[0], gid=www[1], mtime=member.mtime)
            elif member.isfile():
                out.add(rel, 'file', mode=member.mode, uid=www[0], gid=www[1], mtime=member.mtime, size=member.size,
                        fileobj=tar.extractfile(member))
            tar.members.clear()
    for app_id in ha_apps:  # an app whose tar has no directory entry for its root still gets one
        if out.name(f'custom_apps/{app_id}') not in out.names:
            out.add(f'custom_apps/{app_id}', 'dir', mode=0o755, uid=www[0], gid=www[1], mtime=time.time())


def pg_dir_tar(export, out, top):
    """The PostgreSQL dir: the new cluster's volume export with its top dir owned like the live one."""
    uid, gid, mode = top
    out.add('.', 'dir', mode=mode, uid=uid, gid=gid, mtime=time.time())
    try:
        with ha_odoo._live_tar(export, '新的 PostgreSQL 叢集') as tar:
            for member in tar:
                name = ha_odoo._norm(member.name)
                if name is None:
                    raise BackupError('job-failed', '新的 PostgreSQL 叢集的匯出內容格式不正確。')
                if name != '.':
                    if member.islnk():
                        member.linkname = out.name(ha_odoo._norm(member.linkname) or '.')
                    out.tar.add_member(ha_odoo._copy_info(member, out.name(name)),
                                       tar.extractfile(member) if member.isfile() else None)
                tar.members.clear()
    except tarfile.TarError:
        raise BackupError('job-failed', '新的 PostgreSQL 叢集的匯出內容無法讀取。') from None


class _private:
    """A new staging file (0600), flushed and synced when the block ends without an error."""

    def __init__(self, path):
        self.path = path

    def __enter__(self):
        self.handle = open(self.path, 'xb')  # noqa: SIM115 - closed in __exit__
        os.fchmod(self.handle.fileno(), 0o600)
        return self.handle

    def __exit__(self, kind, _value, _tb):
        try:
            if kind is None:
                self.handle.flush()
                os.fsync(self.handle.fileno())
        finally:
            self.handle.close()


def check_dir_tar(path, ids, label):
    try:
        return nested.check_dir(path, ids=ids)
    except BackupError as error:
        raise BackupError('job-failed', f'轉換後的{label}無法還原（{error.message}）。',
                          reason=(error.details or {}).get('reason')) from None


def convert(work, app, test_mode, out_dir):
    """Build the four data dirs in `out_dir/dirs/<index>.tar`; returns {dirs, custom_apps, counts, ...}."""
    del test_mode  # a test import changes nothing else for Nextcloud (CONTRACT section 7 HaImport)
    runner = work.runner(app)
    adapter = work.adapter(app)
    target = Target(work, app)
    live = target.live
    tmp = work.temp(app)
    ids = adapter.owner_ids()
    staging = work.staging / 'nextcloud-work'
    staging.mkdir(mode=0o700)
    (out_dir / 'dirs').mkdir(mode=0o700, parents=True, exist_ok=True)
    hatarget.ensure_running(work, app, live.redis_container)      # NC-04 (the app and the database were started by Target)
    tops = {'postgres': live_stat(work, app, live.db_container, live.db_target),
            'redis': live_stat(work, app, live.redis_container, '/data'),
            'data': live_stat(work, app, live.app_container, '/var/www/html/data')}
    www = tmp.user_ids('ids-www', live.app_image, 'www-data')
    paths = {role: out_dir / 'dirs' / f'{target.index[rel]}.tar' for role, rel in live.rels.items()}

    # HA's add-on member: the cluster into a throwaway volume, config.php, the custom apps into staging.
    sink = work.sink(app)
    apps = ha_odoo.FileTar(staging / 'ha-apps.tar', work.guard)
    try:
        image, src = _source(work, app, tmp, apps=apps)
    finally:
        apps.close()
    member_issues(sink, src, target)      # a stop stops this app, a line to confirm needs its key (haissues.Sink)
    raise_stops(sink)

    # HA's data directory, written as the data dir while it is read (owner www-data, top like the live one). When its files are
    # not in the backup (or the folder is not the data directory: no .ncdata) the data dir stays empty with its marker.
    def new_data_dir():
        out = DirTar(paths['data'], work.guard)
        uid, gid, mode = tops['data']
        out.add('.', 'dir', mode=mode, uid=uid, gid=gid, mtime=time.time())
        out.add(HTACCESS, 'file', mode=0o644, uid=www[0], gid=www[1], mtime=time.time(), size=len(DATA_HTACCESS),
                fileobj=io.BytesIO(DATA_HTACCESS))
        return out

    data_out = new_data_dir()
    try:
        data = datadir_pass(work, src, out=data_out, ids=www)
        if isinstance(data, DataDir) and data.present and not data.ncdata:
            data_out.close()           # NC-23: a folder without the marker is not moved: start the folder again, empty
            paths['data'].unlink()
            data_out = new_data_dir()
        if not userfiles_moved(data):
            data_out.add('.ncdata', 'file', mode=0o644, uid=www[0], gid=www[1], mtime=time.time(), size=len(NCDATA),
                         fileobj=io.BytesIO(NCDATA))
        try:
            office_cache = live_office_cache(work, app, live, target.config)
        except BackupError as error:
            if error.code != 'job-failed' or haissues.is_job_wide(error):
                raise
            office_unread(sink)
            office_cache = {}
        add_office_cache(data_out, src.config['instanceid'], office_cache, www)
    finally:
        data_out.close()
    datadir_issues(sink, src.config, data, ha_datadir_source(src))
    raise_stops(sink)
    work.phase('convert')
    hapg = Pinned(tmp, 'hapg')
    cluster = ha_odoo.start_ha_cluster(work, hapg, image)
    dbname = src.config['dbname']
    details = ha_database(cluster, dbname)
    database_issues(sink, src, data, details, target)
    raise_stops(sink)
    # What is still to be written: the dump, the new cluster with its WAL and its export, the html dir twice.
    html_bytes = runner.dir_measure(live.rels['html'])['bytes']
    work.guard.check(2 * src.pg_bytes + ha_odoo.WAL_ALLOWANCE + 2 * html_bytes)
    dump = staging / 'nextcloud.dump'
    work.log('匯出 HA 的 Nextcloud 資料庫')
    with _private(dump) as handle:
        hapg.exec('hapg', ['pg_dump', '-U', 'postgres', '-Fc', '-d', dbname] + (['-n', 'public'] if details.get('schemas') else []),
                  user='postgres', stdout=handle, timeout=ha_odoo.DUMP_TIMEOUT, max_output=work.guard.budget())
    tmp.remove('hapg')
    tmp.remove_volume('hapg')
    work.checkpoint()
    old_root, new_root = storage_id(src.config['datadirectory']), storage_id(target.config['datadirectory'])
    remote = f'appdata_{src.config["instanceid"]}/richdocuments/remoteData'
    moves = moves_of(src.config, target.config, details.get('local_storages') or [], data)
    if len(moves) > 1:
        work.log(f'Nextcloud 的儲存空間記錄：使用者檔案資料夾，和它裡面的 {len(moves) - 1} 個資料夾（團隊資料夾）一起改成這台的路徑')
    built = build_cluster(work, app, tmp, target, dump, details=details, old_root=old_root, new_root=new_root,
                          moves=moves, remote=remote,
                          majors=(ha_odoo._ha_major(src), ha_odoo.target_pg_major(work, app, live.db_image)))
    dump.unlink()
    export = staging / 'nc-db.tar'
    with _private(export) as handle:
        tmp.volume_export('nc-db', handle, max_output=work.guard.budget())
    tmp.remove_volume('nc-db')
    pg_out = DirTar(paths['postgres'], work.guard)
    try:
        pg_dir_tar(export, pg_out, tops['postgres'])
    finally:
        pg_out.close()
    export.unlink()

    # config.php: the live one plus HA's identity and policy keys, parsed back by the live image's PHP.
    merged, carried, _skipped = merge_config(src.config, target.config)
    merged['data-fingerprint'] = data_fingerprint()  # what the package's restore does after a restore
    config_data = render_config(merged)
    php_check(tmp, live.app_image, config_data, merged)
    live_html = staging / 'live-html.tar'
    with _private(live_html) as handle:
        runner.dir_pack(live.rels['html'], stdout=handle, timeout=3 * 3600, max_output=work.guard.budget(),
                        abort=work.abort)
    html_out = DirTar(paths['html'], work.guard)
    try:
        html_tar(live_html, staging / 'ha-apps.tar', html_out, config_data=config_data, www=www,
                 ha_apps=set(src.apps))
    finally:
        html_out.close()
    live_html.unlink()
    (staging / 'ha-apps.tar').unlink()
    redis_out = DirTar(paths['redis'], work.guard)
    try:
        uid, gid, mode = tops['redis']
        redis_out.add('.', 'dir', mode=mode, uid=uid, gid=gid, mtime=time.time())
    finally:
        redis_out.close()
    for role, label in (('postgres', 'PostgreSQL 資料夾'), ('redis', 'Redis 資料夾'), ('html', 'Nextcloud 程式資料夾'),
                        ('data', '使用者檔案資料夾')):
        check_dir_tar(paths[role], ids, label)
    moved = userfiles_moved(data)
    left_apps, left_others = known_objects(details.get('skipped') or [], details.get('shape'))
    left_any = bool((shape_objects(details.get('shape')) or ([], []))[0])      # programs were left out at all
    return {'dirs': {live.rels[role]: paths[role] for role in paths}, 'custom_apps': sorted(src.apps),
            'policy': carried, 'counts': built['counts'], 'datadir_files': data.files if moved else 0,
            'datadir_bytes': data.bytes if moved else 0, 'userfiles': moved,
            'left_out_apps': left_apps if left_any else [], 'left_out_others': left_any and left_others,
            'mail': any(isinstance(k, str) and k.startswith('mail_') for k in src.config),
            'office': 'richdocuments' in (details.get('enabled') or []),
            'office_cache': sorted(office_cache),
            'lists_differ': len(lists_differ(data, details)), 'app_container': live.app_container,
            'target_url': str(target.config.get('overwrite.cli.url') or '')[:200]}
