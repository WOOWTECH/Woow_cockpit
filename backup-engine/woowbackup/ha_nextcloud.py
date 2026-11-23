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
none, HA's settings never used: ha_odoo.start_ha_cluster); config.php is parsed strictly (never executed: only
arrays, single-quoted strings, numbers, booleans and null); the data directory is walked (it must exist with its
`.ncdata`; symlinks, server-side encryption and object storage are refused); counts, apps and storages are read.

convert: pg_dump of HA's database; a NEW cluster from the live database image, environment and secret (its superuser
password is the live one), the live Nextcloud database role (`dbuser` of the live config.php, e.g. oc_admin) with the
LIVE role's attributes and password verifier (read from the live cluster, passed on stdin, masked), the grants
Nextcloud's installer gives it (lib/private/Setup/PostgreSQL.php: CONNECT, REVOKE ALL FROM PUBLIC, CREATE on public),
the live extensions, then the dump restored AS THAT ROLE (`--no-owner --no-acl --exit-on-error --single-transaction`,
superuser-only objects refused); fix-ups: the root storage id `local::<HA datadirectory>/` -> `local::<target
datadirectory>/`, Office (richdocuments wopi_url, public_wopi_url, wopi_callback_url, wopi_allowlist,
disable_certificate_verification) and core.backgroundjobs_mode exactly as the live database has them, HA's cached
Collabora discovery (`appdata_<id>/richdocuments/remoteData`, files and rows) dropped so Office uses this device's
Collabora; every count, owner, grant, extension and value is verified; PostgreSQL settings of the live cluster are
carried; clean stop, `pg_controldata` "shut down". config.php = the LIVE config.php (URLs, trusted domains, database
credentials, mail, caches, data directory) plus HA's `instanceid`, `passwordsalt`, `secret` (app data folder, ICrypto:
app passwords, TOTP, encrypted app values) and HA's two-factor enforcement and app_install_overwrite (owner decision
D1; never weaker than the target's enforcement); the live image's PHP parses it and returns exactly the merged values.
The html dir is the live dir without config.php and without the custom apps HA brings, plus the merged config.php and
HA's custom apps (decision D2); the data dir is HA's data directory (owner www-data of the live image, top dir like
the live one; web-updater backups `updater-*` skipped, previews kept: decision D5); the Redis dir is empty; the
PostgreSQL dir is the new cluster (top dir like the live one).
"""
import hashlib
import io
import json
import os
import re
import tarfile
import time
import xml.etree.ElementTree as ElementTree

from . import habackup, hacommon, ha_odoo, nested, tempctr
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
NC_VERSION_RE = re.compile(r'[0-9]{1,4}(?:\.[0-9]{1,6}){2,3}\Z')
APP_ID_RE = re.compile(r'[a-z0-9_]{1,64}\Z')
INSTANCE_RE = re.compile(r'[a-z0-9]{6,40}\Z')
SECRET_VALUE_RE = re.compile(r'[A-Za-z0-9+/=._-]{8,512}\Z')
DATADIR_SEG_RE = re.compile(r'[A-Za-z0-9._@+-]{1,255}\Z')
ROLE_RE = re.compile(r'[a-z_][a-z0-9_]{0,62}\Z')
DB_RE = re.compile(r'[a-z_][a-z0-9_]{0,62}\Z')
STAT_RE = re.compile(rb'\s*([0-9]{1,10}) ([0-9]{1,10}) ([0-7]{1,4})\s*\Z')
MAX_CONFIG = 1024 * 1024
MAX_INFO_XML = 256 * 1024
MAX_DEPTH = 16
MAX_ITEMS = 20000
PREFIX = 'oc_'
# config.php keys taken from HA: the instance identity (appdata_<instanceid>, ICrypto `secret`, legacy hashes).
FROM_HA = ('instanceid', 'passwordsalt', 'secret')
# Owner decision D1 (facts nextcloud.md section 5): HA's two-factor enforcement and app_install_overwrite (the apps
# copied from HA) are carried; a live enforcement HA lacks stays (never weaker).
FROM_HA_POLICY = ('twofactor_enforced', 'twofactor_enforced_groups', 'twofactor_enforced_excluded_groups',
                  'app_install_overwrite')
# HA keys that describe HA's own installation (the target keeps its values); never listed as "not carried".
HA_OWN = frozenset({'version', 'installed', 'dbtype', 'dbhost', 'dbname', 'dbuser', 'dbpassword', 'dbport',
                    'dbtableprefix', 'datadirectory', 'trusted_domains', 'overwrite.cli.url', 'overwritehost',
                    'overwriteprotocol', 'overwritewebroot', 'trusted_proxies', 'memcache.local', 'memcache.locking',
                    'memcache.distributed', 'redis', 'maintenance', 'maintenance_window_start', 'default_phone_region',
                    'apps_paths', 'logfile', 'loglevel', 'log_type', 'logtimezone', 'allow_local_remote_servers',
                    'htaccess.RewriteBase', 'upgrade.disable-web', 'check_data_directory_permissions'})
SECRET_KEYS = ('secret', 'passwordsalt', 'dbpassword', 'mail_smtppassword')
# The Office (richdocuments) settings and the core setting the target keeps exactly as its live database has them.
LIVE_APPCONFIG = (('richdocuments', 'wopi_url'), ('richdocuments', 'public_wopi_url'),
                  ('richdocuments', 'wopi_callback_url'), ('richdocuments', 'wopi_allowlist'),
                  ('richdocuments', 'disable_certificate_verification'), ('core', 'backgroundjobs_mode'))
# Counted in HA's database and again after the restore (table -> key); optional tables only when they exist.
COUNTED = (('oc_users', 'users'), ('oc_filecache', 'files'), ('oc_share', 'shares'), ('oc_authtoken', 'tokens'),
           ('oc_calendarobjects', 'calendar_objects'), ('oc_cards', 'contacts'), ('oc_storages', 'storages'),
           ('oc_mounts', 'mounts'), ('oc_external_mounts', 'external_mounts'))
EXTENSIONS_OK = frozenset({'plpgsql'})
MSG_NO_SHARE = ('這份 HA 備份沒有包含 share 資料夾，Nextcloud 的使用者檔案（{dir}）不在備份裡，無法匯入'
                '（只搬資料庫會讓檔案遺失）。請在 HA 重新做一份備份，並勾選 share 資料夾。')
MSG_NO_DATADIR = ('HA 備份裡找不到 Nextcloud 的使用者檔案資料夾 {dir}（或缺少 Nextcloud 的 .ncdata 標記），'
                  '無法匯入。請確認 HA 的 Nextcloud 資料夾設定，並重新做一份包含它的備份。')


def _under(name, prefix):
    return name == prefix or name.startswith(prefix + '/')


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
|(?P<number>-?(?:[0-9]+\.[0-9]+(?:[eE][-+]?[0-9]+)?|[0-9]+[eE][-+]?[0-9]+|[0-9]+))
|(?P<word>[A-Za-z_][A-Za-z0-9_]*)
|(?P<arrow>=>)
|(?P<punct>[=,;()\[\]])
""", re.S | re.X)


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
        if depth > MAX_DEPTH:
            raise ValueError('too deep')
        kind, text = self.take()
        if kind == 'string':
            return _php_string(text)
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


def _enforced(value):
    return value is True or value == 'true'


def config_blockers(ha, live, image_version):
    """zh-TW blockers of HA's and the live config.php (versions, installation state, database, identity)."""
    if not isinstance(ha, dict):
        return ['無法解讀 HA 的 Nextcloud 設定檔 config.php（格式不是 Nextcloud 自己寫的樣子），為了安全不會執行它，無法匯入。']
    blockers = []
    if ha.get('installed') is not True:
        blockers.append('HA 的 Nextcloud 還沒有安裝完成（config.php 沒有 installed），無法匯入。')
    if ha.get('maintenance') is True:
        blockers.append('HA 的 Nextcloud 做備份時處於維護模式（可能正在升級），請在 HA 讓它正常啟動後重新備份。')
    if ha.get('dbtype') != 'pgsql':
        blockers.append('HA 的 Nextcloud 不是使用 PostgreSQL 資料庫，無法匯入。')
    if ha.get('dbtableprefix', PREFIX) != PREFIX or live.get('dbtableprefix', PREFIX) != PREFIX:
        blockers.append('Nextcloud 的資料表前綴不是 oc_，目前無法匯入。')
    if any(key in ha for key in ('objectstore', 'objectstore_multibucket')):
        blockers.append('HA 的 Nextcloud 把檔案放在物件儲存（例如 S3），無法搬到這台。')
    if not (isinstance(ha.get('instanceid'), str) and INSTANCE_RE.fullmatch(ha['instanceid'])
            and all(isinstance(ha.get(key), str) and SECRET_VALUE_RE.fullmatch(ha[key])
                    for key in ('passwordsalt', 'secret'))):
        blockers.append('HA 的 Nextcloud 設定缺少它的身分資料（instanceid、secret），無法匯入。')
    if not (isinstance(ha.get('dbname'), str) and DB_RE.fullmatch(ha['dbname'])):
        blockers.append('HA 的 Nextcloud 設定沒有可用的資料庫名稱。')
    ha_version, live_version = nc_version(ha.get('version')), nc_version(live.get('version'))
    if live.get('installed') is not True or live_version is None:
        blockers.append('這台的 Nextcloud 還沒有安裝完成，請先到「應用軟體」完成安裝。')
    elif ha_version is None:
        blockers.append('無法讀取 HA 的 Nextcloud 版本。')
    elif ha_version != live_version:
        blockers.append(f'版本不同：HA 的 Nextcloud 是 {ha_version}，這台是 {live_version}。'
                        '請先讓兩邊的 Nextcloud 版本一致後再匯入。')
    elif '.'.join(live_version.split('.')[:3]) != image_version:
        blockers.append(f'這台 Nextcloud 的映像版本（{image_version or "未知"}）和已安裝的版本 {live_version} 不同，'
                        '請先讓這台的 Nextcloud 正常完成升級。')
    return blockers


def merge_config(ha, live):
    """(merged config, carried policy keys, HA keys not carried): the live config.php is the base (facts section
    4.2); HA's identity keys replace the live ones; HA's policy keys (D1) are carried, a live two-factor enforcement
    stays when HA's is weaker."""
    merged = dict(live)
    for key in FROM_HA:
        merged[key] = ha[key]
    carried = []
    for key in FROM_HA_POLICY:
        if key not in ha:
            continue
        if key.startswith('twofactor_enforced') and _enforced(live.get('twofactor_enforced')) \
                and not _enforced(ha.get('twofactor_enforced')):
            continue
        merged[key] = ha[key]
        carried.append(key)
    skipped = [key for key in ha if isinstance(key, str) and key not in HA_OWN and key not in FROM_HA
               and key not in FROM_HA_POLICY and not key.startswith('mail_') and live.get(key) != ha[key]]
    return merged, carried, skipped


def storage_id(datadir):
    """Nextcloud's id of the local storage of `datadir`: 'local::' + the path with '//' collapsed and one trailing
    '/' (lib/private/Files/Storage/Local.php:53-62,84-85); ids longer than 64 bytes are stored as their md5
    (lib/private/Files/Cache/Storage.php adjustStorageId)."""
    path = datadir.replace('//', '/')
    if not path.endswith('/'):
        path += '/'
    value = 'local::' + path
    return hashlib.md5(value.encode('utf-8')).hexdigest() if len(value.encode('utf-8')) > 64 else value


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
            warnings.append(f'HA 的 Nextcloud 應用 {app_id}（{info.get("version") or "?"}）不支援這台的 Nextcloud '
                            f'{nc_version_text}，匯入後 Nextcloud 可能停用它。')
        low, high = info.get('php') or ('', '')
        if php_version and not _fits(php_version, low, high):
            warnings.append(f'HA 的 Nextcloud 應用 {app_id}（{info.get("version") or "?"}）不支援這台的 PHP '
                            f'{php_version}，匯入後可能無法使用。')
        if info.get('foreign'):
            warnings.append(f'HA 的 Nextcloud 應用 {app_id} 含有給其他處理器的程式（例如 {info["foreign"][0][:80]}），'
                            '在這台可能無法執行。')
    return warnings


# ====================================================================== the HA backup

class Source:
    """One pass over the add-on's inner tar: `addon`, `pg_version`, `pg_files`/`pg_bytes`, `config` (parsed
    config.php or None; `config_found`), `apps` {id: {version, files, bytes, nextcloud, php, info_ok, foreign}},
    `app_bytes`, `bad_apps` (folders that are no app id)."""

    def __init__(self):
        self.addon = None
        self.pg_version = None
        self.pg_files = self.pg_bytes = 0
        self.config = None
        self.config_found = False
        self.apps = {}
        self.app_bytes = 0
        self.bad_apps = []


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
                src.bad_apps.append(app_id[:60])
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
        self.users = set()


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
            raise BackupError('incompatible', f'HA 備份中的 {rel[:200]} 是另一個沒有搬過來的檔案的硬連結，無法只搬一半；'
                                              '已停止。', member=rel[:200])
        mode = mode & (0o1777 if kind == 'dir' else 0o777)
        self.tar.add_member(hacommon.info(self.name(rel), kind, mode=mode, uid=uid, gid=gid, mtime=mtime, size=size,
                                          linkname=self.name(linkname) if kind == 'hardlink' else linkname), fileobj)
        if kind == 'file':
            self.files.add(rel)

    def close(self):
        self.tar.close()


def scan_datadir(stream, report, prefix, *, addon, instanceid=None, out=None, ids=None, checkpoint=None):
    """Walk HA's data directory (`prefix` and below) in a member; with `out` (DirTar) write it as the data dir,
    every entry owned by `ids` (www-data of the live image), modes as in HA, the top written by the caller. Skipped:
    web-updater backups (`updater-*`, decision D5) and HA's cached Collabora discovery
    (`appdata_<instanceid>/richdocuments/remoteData`). Symlinks are counted (the caller refuses them)."""
    select = habackup.Select(include=(prefix,), symlinks=(), hardlinks=True)
    data = DataDir()
    remote = f'appdata_{instanceid}/richdocuments/remoteData' if instanceid else None
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
        if parts[0].startswith('updater-') or (remote is not None and _under(rel, remote)):
            if entry.kind == 'file':
                data.skipped_files += 1
                data.skipped_bytes += entry.size
            continue
        if parts[0] == 'files_encryption' or (len(parts) > 1 and parts[1] == 'files_encryption'):
            data.encryption = True
        if rel == '.ncdata' and entry.kind == 'file':
            data.ncdata = True
        if len(parts) >= 2 and parts[1] == 'files' and not parts[0].startswith(('appdata_', '__')):
            data.users.add(parts[0])
        if entry.kind == 'dir':
            data.dirs += 1
            if out is not None:
                out.add(rel, 'dir', mode=entry.mode, uid=uid, gid=gid, mtime=entry.mtime)
        elif entry.kind == 'file':
            data.files += 1
            data.bytes += entry.size
            if out is not None:
                out.add(rel, 'file', mode=entry.mode, uid=uid, gid=gid, mtime=entry.mtime, size=entry.size,
                        fileobj=hacommon._Exact(entry, None))
        elif entry.kind == 'hardlink':
            data.hardlinks += 1
            if out is not None:
                if not _under(entry.linkname, prefix) or entry.linkname == prefix:
                    raise BackupError('incompatible', f'HA 備份中的 {rel[:200]} 是資料夾外檔案的硬連結，無法搬過來。',
                                      member=rel[:200])
                out.add(rel, 'hardlink', mode=0o644, uid=uid, gid=gid, mtime=entry.mtime,
                        linkname=entry.linkname[len(prefix) + 1:])
    samples = [s for s in report.skipped_symlink_samples if _under(s, prefix)]
    if report.skipped_symlinks and samples:
        data.symlinks = report.skipped_symlinks
        data.symlink_samples = samples
    return data


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


def live_config(work, app, live):
    """The live config.php (parsed strictly, secrets masked)."""
    data = _exec(work, app, live.app_container, ['cat', '/var/www/html/config/config.php'], '設定檔 config.php')
    try:
        config = parse_config(data)
    except ValueError:
        raise BackupError('incompatible', '無法解讀這台 Nextcloud 的 config.php（格式不是 Nextcloud 自己寫的樣子）。',
                          app=app.id) from None
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


def image_env(work, app, image, key):
    info = work.adapter(app).image_inspect(image) or {}
    for item in info.get('env', []):
        if isinstance(item, str) and item.startswith(key + '='):
            return item.split('=', 1)[1].strip()[:32]
    return None


def live_db_sql(role):
    lit = ha_odoo.sql_literal
    keys = ' OR '.join(f'(appid = {lit(a)} AND configkey = {lit(k)})' for a, k in LIVE_APPCONFIG)
    return f"""SELECT json_build_object(
 'role', (SELECT json_build_object('password', rolpassword, 'super', rolsuper, 'login', rolcanlogin,
          'createdb', rolcreatedb, 'createrole', rolcreaterole, 'replication', rolreplication,
          'bypassrls', rolbypassrls, 'connlimit', rolconnlimit) FROM pg_authid WHERE rolname = {lit(role)}),
 'roles', (SELECT coalesce(json_agg(rolname ORDER BY rolname), '[]'::json) FROM pg_roles WHERE rolname !~ '^pg_'),
 'extensions', (SELECT coalesce(json_agg(extname ORDER BY extname), '[]'::json) FROM pg_extension),
 'datacl', (SELECT datacl::text FROM pg_database WHERE datname = current_database()),
 'nspacl', (SELECT nspacl::text FROM pg_namespace WHERE nspname = 'public'),
 'appconfig', (SELECT coalesce(json_agg(row_to_json(a) ORDER BY appid, configkey), '[]'::json)
               FROM oc_appconfig a WHERE {keys}))"""


def live_database(work, app, live, role):
    """The live database's role `role` (verifier masked), roles, extensions, grants and kept app settings."""
    from . import jobs
    doc = hacommon.live_json(work, app, live.db_container, live.db_user, live.db_name, live_db_sql(role))
    if not isinstance(doc, dict) or not isinstance(doc.get('role'), dict):
        raise BackupError('incompatible', f'這台的 Nextcloud 資料庫沒有 {role} 角色。', app=app.id)
    password = doc['role'].get('password')
    if not isinstance(password, str) or not ha_odoo.VERIFIER_RE.fullmatch(password):
        raise BackupError('incompatible', f'這台 Nextcloud 資料庫的 {role} 角色沒有可用的密碼設定。', app=app.id)
    jobs.mask_secret(password)
    if doc['role'].get('super') is not False:
        raise BackupError('incompatible', f'這台 Nextcloud 資料庫的 {role} 角色是超級使用者，不是 Nextcloud 安裝程式建立的樣子。',
                          app=app.id)
    rows = doc.get('appconfig')
    if not isinstance(rows, list) or not all(isinstance(r, dict) and isinstance(r.get('appid'), str)
                                             and isinstance(r.get('configkey'), str) for r in rows):
        raise BackupError('job-failed', '無法讀取這台 Nextcloud 的 Office 設定。', app=app.id)
    if not all(isinstance(doc.get(key), list) for key in ('roles', 'extensions')):
        raise BackupError('job-failed', '無法讀取這台 Nextcloud 的資料庫設定。', app=app.id)
    return doc


class Target:
    """Everything the import reads of the live app before it starts (nothing is stopped or written)."""

    def __init__(self, work, app):
        runner = work.runner(app)
        self.live = Live(work.quadlets(app), runner.home, app)
        self.config = live_config(work, app, self.live)
        self.image_version = image_env(work, app, self.live.app_image, 'NEXTCLOUD_VERSION')
        self.php_version = image_env(work, app, self.live.app_image, 'PHP_VERSION')
        self.role = self.config['dbuser']
        self.db = live_database(work, app, self.live, self.role)
        self.shipped, self.custom = live_apps(work, app, self.live)
        self.index = {d['path']: i for i, d in enumerate(app.data_dirs)}


# ====================================================================== HA's database

def _counts_sql(tables):
    parts = [f"'{key}', (SELECT count(*) FROM {table})" for table, key in COUNTED if table in tables]
    return 'SELECT json_build_object(' + ', '.join(parts) + ')'


TABLES_SQL = ("SELECT coalesce(json_agg(tablename ORDER BY tablename), '[]'::json) FROM pg_tables "
              "WHERE schemaname = 'public'")
HA_SQL = """SELECT json_build_object(
 'extensions', (SELECT coalesce(json_agg(extname ORDER BY extname), '[]'::json) FROM pg_extension),
 'schemas', (SELECT coalesce(json_agg(nspname ORDER BY nspname), '[]'::json) FROM pg_namespace
             WHERE nspname !~ '^pg_' AND nspname NOT IN ('information_schema', 'public')),
 'local_storages', (SELECT coalesce(json_agg(id ORDER BY numeric_id), '[]'::json) FROM oc_storages
                    WHERE id LIKE 'local::%'),
 'enabled', (SELECT coalesce(json_agg(appid ORDER BY appid), '[]'::json) FROM oc_appconfig
             WHERE configkey = 'enabled' AND configvalue <> 'no'),
 'encryption', (SELECT configvalue FROM oc_appconfig WHERE appid = 'core' AND configkey = 'encryption_enabled'))"""


def ha_database(cluster, dbname):
    """HA's database: {tables, counts, extensions, schemas, local_storages, enabled, encryption}."""
    names = [d['name'] for d in ha_odoo.ha_databases(cluster)]
    if dbname not in names:
        return None
    tables = cluster.query_json(TABLES_SQL, dbname)
    if not isinstance(tables, list):
        raise BackupError('job-failed', '無法讀取 HA 的 Nextcloud 資料表。')
    tables = {t for t in tables if isinstance(t, str)}
    if not {'oc_appconfig', 'oc_storages', 'oc_users', 'oc_filecache'} <= tables:
        return {'tables': tables, 'nextcloud': False}
    doc = cluster.query_json(HA_SQL, dbname)
    counts = cluster.query_json(_counts_sql(tables), dbname)
    if not isinstance(doc, dict) or not isinstance(counts, dict):
        raise BackupError('job-failed', '無法讀取 HA 的 Nextcloud 資料庫內容。')
    doc.update(tables=tables, counts={k: int(v) for k, v in counts.items() if isinstance(v, int)}, nextcloud=True)
    return doc


def datadir_blockers(config, data, ha_source):
    """zh-TW blockers about HA's data directory (where it is, whether the backup holds it, what it holds)."""
    blockers = []
    datadir = config.get('datadirectory') if isinstance(config, dict) else None
    if isinstance(config, dict):
        if not isinstance(datadir, str):
            blockers.append('HA 的 Nextcloud 設定檔沒有使用者檔案資料夾（datadirectory）。')
        elif ha_source is None:
            blockers.append(f'HA 的 Nextcloud 使用者檔案放在 {datadir[:200]}，不在 HA 備份會包含的位置'
                            '（/share、/data 或 /config），無法匯入。')
        elif data == 'no-share':
            blockers.append(MSG_NO_SHARE.format(dir=datadir[:200]))
        elif not isinstance(data, DataDir) or not data.present or not data.ncdata:
            blockers.append(MSG_NO_DATADIR.format(dir=datadir[:200]))
        else:
            if data.symlinks:
                blockers.append(f'HA 的 Nextcloud 使用者檔案裡有 {data.symlinks} 個符號連結（例如 '
                                f'{data.symlink_samples[0][:120]}），無法安全地搬過來。')
            if data.encryption:
                blockers.append('HA 的 Nextcloud 開啟了伺服器端加密（files_encryption），目前不支援匯入。')
    return blockers


def analyse(src, data, details, target, *, ha_source, pg_major):
    """(blockers, warnings) of everything a check found."""
    config, live = src.config, target.config
    blockers = config_blockers(config if src.config_found else None, live, target.image_version)
    warnings = []
    ha_major = ha_odoo._ha_major(src)
    if src.pg_version is None or ha_major is None:
        blockers.append('HA 備份裡沒有 Nextcloud 的 PostgreSQL 資料庫。')
    elif ha_major != 16:
        blockers.append(f'HA 的 PostgreSQL 是 {src.pg_version} 版，目前只支援 16 版。')
    elif pg_major is None or ha_major > pg_major:
        blockers.append(f'HA 的 PostgreSQL（{src.pg_version}）比這台的（{pg_major or "未知"}）新，無法匯入。')
    blockers += datadir_blockers(config, data, ha_source)
    if details is None and ha_major == 16:
        blockers.append('HA 的 PostgreSQL 裡沒有 Nextcloud 的資料庫。')
    elif isinstance(details, dict):
        if not details.get('nextcloud'):
            blockers.append('HA 的資料庫不是 Nextcloud 的資料庫（找不到 Nextcloud 的資料表）。')
        else:
            extra = [e for e in details.get('extensions') or [] if e not in EXTENSIONS_OK]
            if extra:
                blockers.append(f'HA 的 Nextcloud 資料庫使用了擴充功能 {hacommon.names(extra)}，目前無法搬過來。')
            if details.get('schemas'):
                blockers.append(f'HA 的 Nextcloud 資料庫有額外的 schema（{hacommon.names(details["schemas"])}），'
                                '目前無法搬過來。')
            if details.get('encryption') == 'yes':
                blockers.append('HA 的 Nextcloud 開啟了伺服器端加密，目前不支援匯入。')
            storages = [s for s in details.get('local_storages') or [] if isinstance(s, str)]
            if isinstance(config, dict) and isinstance(config.get('datadirectory'), str):
                root = storage_id(config['datadirectory'])
                if root not in storages:
                    blockers.append('HA 的 Nextcloud 資料庫和它的資料夾設定不一致（找不到使用者檔案資料夾的儲存空間記錄），無法匯入。')
                other = [s for s in storages if s != root]
                if other:
                    warnings.append(f'HA 的 Nextcloud 有 {len(other)} 個本機外部儲存空間（例如 {other[0][7:120]}），'
                                    '那些路徑在這台不存在，匯入後需要重新設定。')
            if details.get('counts', {}).get('external_mounts'):
                warnings.append('HA 的 Nextcloud 設定了外部儲存空間，那些位置（HA 的資料夾或網路磁碟）在這台不一定存在，匯入後請檢查。')
            enabled = [a for a in details.get('enabled') or [] if isinstance(a, str)]
            missing = [a for a in enabled if a not in target.shipped and a not in src.apps and a not in target.custom]
            if missing:
                warnings.append(f'HA 啟用的 Nextcloud 應用 {hacommon.names(missing)} 在這台沒有程式，匯入後不會載入。')
    if src.bad_apps:
        warnings.append(f'HA 的 custom_apps 裡有名稱不符合 Nextcloud 規則的資料夾（{hacommon.names(src.bad_apps)}），不會搬過來。')
    if isinstance(config, dict) and isinstance(live, dict):
        warnings += app_warnings(src.apps, nc_version_text=nc_version(live.get('version')) or '',
                                 php_version=target.php_version)
        _merged, _carried, skipped = merge_config(config, live) if not blockers else (None, [], [])
        if skipped:
            warnings.append(f'HA 的 Nextcloud 設定 {hacommon.names(skipped)} 不會搬過來（以這台的設定為準）。')
    return blockers, warnings


def section(src, data, details, target):
    config = src.config if isinstance(src.config, dict) else {}
    counts = (details or {}).get('counts', {}) if isinstance(details, dict) else {}
    present = isinstance(data, DataDir) and data.present
    return {'nextcloud_version': nc_version(config.get('version')) or '',
            'addon_nextcloud_version': VERSIONS.upstream(src.addon.version) if src.addon else None,
            'users': counts.get('users', 0), 'files': counts.get('files', 0), 'shares': counts.get('shares', 0),
            'tokens': counts.get('tokens', 0), 'calendar_objects': counts.get('calendar_objects', 0),
            'contacts': counts.get('contacts', 0),
            'datadir': str(config.get('datadirectory') or '')[:200],
            'datadir_in_backup': present and data.ncdata,
            'datadir_files': data.files if present else 0, 'datadir_bytes': data.bytes if present else 0,
            'custom_apps': sorted(src.apps), 'pg_version': src.pg_version or '',
            'office': 'richdocuments' in ((details or {}).get('enabled') or []) if isinstance(details, dict) else False,
            'ha_url': str(config.get('overwrite.cli.url') or '')[:200],
            'target_url': str(target.config.get('overwrite.cli.url') or '')[:200]}


# ====================================================================== the job steps

def member_pass(work, app, tmp, image, *, apps=None):
    """The add-on member streamed once: the cluster into the throwaway volume `hapg`, config.php, custom apps."""
    member = work.addon_member(SLUG)
    report = habackup.Report()
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
    report = habackup.Report()
    with work.open(member) as stream:
        data = scan_datadir(stream, report, prefix, addon=kind == 'addon', instanceid=config.get('instanceid'),
                            out=out, ids=ids, checkpoint=work.checkpoint)
    work.log(f'HA 的 Nextcloud 使用者檔案：{data.files} 個檔案（{ha_odoo._mib(data.bytes)}），'
             f'{len(data.users)} 位使用者的資料夾' + (f'，略過 {data.skipped_files} 個暫存檔' if data.skipped_files else ''))
    return data


def _source(work, app, tmp, *, apps=None):
    """(PostgreSQL 16 image, Source): HA's add-on ships PostgreSQL 16 (Dockerfile:21-37); another major is a blocker
    found after the pass (analyse), the cluster is then never started."""
    image = ha_odoo.pick_pg16(work, app)
    return image, member_pass(work, app, tmp, image, apps=apps)


def check(work, app):
    target = Target(work, app)
    tmp = work.temp(app)
    try:
        image, src = _source(work, app, tmp)
        data = datadir_pass(work, src)
        work.phase('check')
        details = None
        if isinstance(src.config, dict) and isinstance(src.config.get('dbname'), str) \
                and DB_RE.fullmatch(src.config['dbname']) and ha_odoo._ha_major(src) == 16:
            cluster = ha_odoo.start_ha_cluster(work, tmp, image)
            details = ha_database(cluster, src.config['dbname'])
    finally:
        tmp.remove('hapg')
        tmp.remove_volume('hapg')
    pg_major = ha_odoo.target_pg_major(work, app, target.live.db_image)
    blockers, warnings = analyse(src, data, details, target, ha_source=datadir_source(
        (src.config or {}).get('datadirectory') if isinstance(src.config, dict) else None), pg_major=pg_major)
    return {'target_version': nc_version(target.config.get('version')) or '', 'blockers': blockers,
            'warnings': warnings,
            'nextcloud': section(src, data, details, target)}


def import_texts(data):
    """(notes, reminders) of a conversion (haimport.import_texts; CONTRACT section 7 HaImport)."""
    notes = ['Nextcloud 的使用者、檔案、分享、行事曆、聯絡人與應用程式密碼會換成 HA 的；這台原本的 Nextcloud 帳號與檔案'
             '不會保留（匯入前的自動備份裡還有）。',
             'Nextcloud 的網址、資料庫密碼、郵件與快取設定保持這台的；Office 會改用這台的 Collabora。']
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
    if not data.get('office'):
        reminders.append('HA 的 Nextcloud 沒有啟用 Office（richdocuments），需要的話請在這台 Nextcloud 的應用程式頁面啟用。')
    return notes, reminders


# -------------------------------------------------------------------- convert: the database

def role_sql(name, role, dbname):
    """The live Nextcloud role with its attributes and verifier, and the grants Nextcloud's installer gives it
    (lib/private/Setup/PostgreSQL.php:86,95,186-193,108)."""
    flags = ['LOGIN' if role.get('login') else 'NOLOGIN', 'NOSUPERUSER',
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


def restore_dump(work, tmp, dump, role, dbname):
    """HA's dump into the new database AS THE NEXTCLOUD ROLE (HA's server is untrusted: review HA-SEC-01), without
    its EXTENSION entries, refused when it holds superuser-only objects; streamed on stdin."""
    with open(dump, 'rb') as handle:
        toc = tmp.exec('nc-db', ['pg_restore', '-l'], user='postgres', input=handle, timeout=ha_odoo.DUMP_TIMEOUT,
                       max_output=ha_odoo.TOC_OUTPUT).stdout or b''
    text = toc.decode('utf-8', 'surrogateescape')
    kinds = ha_odoo.superuser_kinds(text)
    if kinds:
        raise BackupError('incompatible', f'HA 的 Nextcloud 資料庫含有只有資料庫超級使用者才能建立的物件'
                                          f'（{hacommon.names(kinds)}），無法安全地搬過來。')
    ha_odoo.Cluster(tmp, 'nc-db').write_file('/tmp/woowbk-nc.toc',
                                             ha_odoo.filter_toc(text).encode('utf-8', 'surrogateescape'))
    work.log(f'把 HA 的 Nextcloud 資料庫還原到新的叢集（以 {role} 角色還原）')
    with open(dump, 'rb') as handle:
        try:
            tmp.exec('nc-db', ['pg_restore', '-U', role, '--no-owner', '--no-acl', '--exit-on-error',
                               '--single-transaction', '-L', '/tmp/woowbk-nc.toc', '-d', dbname],
                     user='postgres', input=handle, timeout=ha_odoo.DUMP_TIMEOUT, max_output=1024 * 1024)
        except BackupError as error:
            if error.code != 'job-failed':
                raise
            raise BackupError('job-failed', '無法把 HA 的 Nextcloud 資料庫還原到新的叢集（可能含有這台不支援、'
                                            '或需要資料庫超級使用者權限的內容）。') from None
    tmp.exec('nc-db', ['rm', '-f', '/tmp/woowbk-nc.toc'], user='postgres', timeout=120)


def fixup_sql(old_root, new_root, remote, live_rows):
    """The conversion's changes inside the restored database (one transaction)."""
    lit = ha_odoo.sql_literal
    keys = ', '.join(f'({lit(a)}, {lit(k)})' for a, k in LIVE_APPCONFIG)
    sql = [f'UPDATE oc_storages SET id = {lit(new_root)} WHERE id = {lit(old_root)};\n' if old_root != new_root else '',
           f'DELETE FROM oc_appconfig WHERE (appid, configkey) IN ({keys});\n']
    if live_rows:
        sql.append('INSERT INTO oc_appconfig SELECT * FROM json_populate_recordset(NULL::oc_appconfig, '
                   f'{lit(json.dumps(live_rows, ensure_ascii=False, sort_keys=True))});\n')
    if remote:
        sql.append(f'DELETE FROM oc_filecache WHERE storage = (SELECT numeric_id FROM oc_storages WHERE id = '
                   f'{lit(new_root)}) AND (path = {lit(remote)} OR left(path, {len(remote) + 1}) = {lit(remote + "/")});\n')
    return ''.join(sql)


def verify_sql(new_root, old_root, tables, role):
    lit = ha_odoo.sql_literal
    counts = [f"'{key}', (SELECT count(*) FROM {table})" for table, key in COUNTED if table in tables]
    keys = ' OR '.join(f'(appid = {lit(a)} AND configkey = {lit(k)})' for a, k in LIVE_APPCONFIG)
    return f"""SELECT json_build_object(
 'counts', json_build_object({', '.join(counts)}),
 'owners', (SELECT coalesce(json_agg(DISTINCT tableowner), '[]'::json) FROM pg_tables WHERE schemaname = 'public'),
 'root', (SELECT count(*) FROM oc_storages WHERE id = {lit(new_root)}),
 'old', (SELECT count(*) FROM oc_storages WHERE id = {lit(old_root)}),
 'verifier_md5', (SELECT md5(rolpassword) FROM pg_authid WHERE rolname = {lit(role)}),
 'roles', (SELECT coalesce(json_agg(rolname ORDER BY rolname), '[]'::json) FROM pg_roles WHERE rolname !~ '^pg_'),
 'extensions', (SELECT coalesce(json_agg(extname ORDER BY extname), '[]'::json) FROM pg_extension),
 'datacl', (SELECT datacl::text FROM pg_database WHERE datname = current_database()),
 'nspacl', (SELECT nspacl::text FROM pg_namespace WHERE nspname = 'public'),
 'appconfig', (SELECT coalesce(json_agg(row_to_json(a) ORDER BY appid, configkey), '[]'::json)
               FROM oc_appconfig a WHERE {keys}))"""


def _rows(rows):
    return sorted(json.dumps(r, sort_keys=True, ensure_ascii=False) for r in rows or [])


def verify_converted(doc, *, expected, db, role, old_root, new_root):
    """zh-TW problems of the converted database against what it must be."""
    if not isinstance(doc, dict):
        return ['無法讀取轉換後的資料庫']
    problems = []
    if doc.get('counts') != expected:
        problems.append('資料筆數和 HA 的不同')
    if doc.get('owners') != [role]:
        problems.append(f'資料表的擁有者不是 {role}')
    # PostgreSQL keeps a verifier only when it parses as one (else it hashes the text as a password): the role must
    # hold exactly the live verifier, or Nextcloud's config.php password would not log in after the restore.
    if doc.get('verifier_md5') != hashlib.md5(db['role']['password'].encode('utf-8')).hexdigest():
        problems.append(f'{role} 角色的密碼設定和這台的不同')
    if doc.get('root') != 1 or (old_root != new_root and doc.get('old') != 0):
        problems.append('使用者檔案資料夾的儲存空間記錄沒有改成這台的路徑')
    for key, label in (('roles', '資料庫角色'), ('extensions', '擴充功能'), ('datacl', '資料庫權限'),
                       ('nspacl', 'public schema 權限')):
        if doc.get(key) != db.get(key):
            problems.append(f'{label}和這台的不同')
    if _rows(doc.get('appconfig')) != _rows(db.get('appconfig')):
        problems.append('Office 或背景工作設定和這台的不同')
    return problems


def carry_settings(work, app, live, cluster):
    """PostgreSQL settings the live cluster sets (ha_odoo.settings_to_carry), written with ALTER SYSTEM."""
    live_rows = hacommon.live_json(work, app, live.db_container, live.db_user, 'postgres', ha_odoo.SETTINGS_SQL)
    carried = []
    for name, value in ha_odoo.settings_to_carry(live_rows, cluster.query_json(ha_odoo.SETTINGS_SQL)):
        sql = ha_odoo.alter_system_sql(name, value)
        if sql is not None:
            cluster.statement(sql)
            carried.append(name)
    if carried:
        cluster.statement('SELECT pg_reload_conf();')
        rows = cluster.query_json(ha_odoo.FILE_SETTINGS_SQL)
        written = {r[0].lower(): r[2] for r in rows or [] if isinstance(r, list) and len(r) == 3}
        bad = [name for name in carried if name not in written or written[name]]
        if bad:
            raise BackupError('job-failed', f'沿用這台 PostgreSQL 的設定失敗：{"、".join(bad[:10])}。')
        work.log(f'沿用這台 PostgreSQL 的設定：{"、".join(carried)}')
    return carried


def build_cluster(work, app, tmp, target, dump, *, details, old_root, new_root, remote):
    """The new cluster in the throwaway volume `nc-db` (stopped cleanly); returns the verified document."""
    live, db, role = target.live, target.db, target.role
    work.log('建立新的 PostgreSQL 資料庫叢集（與這台相同的映像與設定）')
    tmp.volume('nc-db')
    tmp.run('nc-db', live.db_image, [], detach=True, volumes=[(tmp.name('nc-db'), live.db_target, None)],
            env=live.db_env, secrets=live.db_secrets)
    pg = ha_odoo.Cluster(tmp, 'nc-db', superuser=live.db_user, log=work.log)
    pg.wait_ready(tcp=True, checkpoint=work.checkpoint)
    pg.script(role_sql(role, db['role'], live.db_name))
    extensions = [e for e in db['extensions'] if e != 'plpgsql' and ROLE_RE.fullmatch(e)]
    pg.script(f'GRANT CREATE ON SCHEMA public TO {ha_odoo.pg_ident(role)};\n'
              + ''.join(f'CREATE EXTENSION IF NOT EXISTS {ha_odoo.pg_ident(e)};\n' for e in extensions), live.db_name)
    restore_dump(work, tmp, dump, role, live.db_name)
    removed = 0
    if remote:
        removed = pg.query_json(f"SELECT count(*) FROM oc_filecache WHERE storage = (SELECT numeric_id FROM oc_storages "
                                f"WHERE id = {ha_odoo.sql_literal(old_root)}) AND (path = {ha_odoo.sql_literal(remote)} "
                                f"OR left(path, {len(remote) + 1}) = {ha_odoo.sql_literal(remote + '/')})",
                                live.db_name)
    pg.script(fixup_sql(old_root, new_root, remote, db['appconfig']), live.db_name)
    expected = dict(details['counts'])
    expected['files'] = expected.get('files', 0) - int(removed or 0)
    doc = pg.query_json(verify_sql(new_root, old_root, details['tables'], role), live.db_name)
    problems = verify_converted(doc, expected=expected, db=db, role=role, old_root=old_root, new_root=new_root)
    if problems:
        raise BackupError('job-failed', f'轉換後的 Nextcloud 資料庫檢查沒有通過：{"；".join(problems)}。')
    carry_settings(work, app, live, pg)
    pg.statement('CHECKPOINT;')
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
    tops = {'postgres': live_stat(work, app, live.db_container, live.db_target),
            'redis': live_stat(work, app, live.redis_container, '/data'),
            'data': live_stat(work, app, live.app_container, '/var/www/html/data')}
    www = tmp.user_ids('ids-www', live.app_image, 'www-data')
    paths = {role: out_dir / 'dirs' / f'{target.index[rel]}.tar' for role, rel in live.rels.items()}

    # HA's add-on member: the cluster into a throwaway volume, config.php, the custom apps into staging.
    apps = ha_odoo.FileTar(staging / 'ha-apps.tar', work.guard)
    try:
        image, src = _source(work, app, tmp, apps=apps)
    finally:
        apps.close()
    if not isinstance(src.config, dict) or config_blockers(src.config, target.config, target.image_version):
        blockers = config_blockers(src.config if src.config_found else None, target.config, target.image_version)
        raise BackupError('incompatible', blockers[0] if blockers else '無法解讀 HA 的 Nextcloud 設定檔。', app=app.id)

    # HA's data directory, written as the data dir while it is read (owner www-data, top like the live one).
    data_out = DirTar(paths['data'], work.guard)
    try:
        uid, gid, mode = tops['data']
        data_out.add('.', 'dir', mode=mode, uid=uid, gid=gid, mtime=time.time())
        data = datadir_pass(work, src, out=data_out, ids=www)
    finally:
        data_out.close()
    early = datadir_blockers(src.config, data, datadir_source(src.config.get('datadirectory')))
    if ha_odoo._ha_major(src) != 16:
        early.append(f'HA 的 PostgreSQL 是 {src.pg_version or "未知"} 版，目前只支援 16 版。')
    if early:  # refused before any cluster is started or anything else is built
        raise BackupError('incompatible', early[0], app=app.id)
    work.phase('convert')
    cluster = ha_odoo.start_ha_cluster(work, tmp, image)
    dbname = src.config['dbname']
    details = ha_database(cluster, dbname)
    blockers, _warnings = analyse(src, data, details, target, ha_source=datadir_source(src.config.get('datadirectory')),
                                  pg_major=ha_odoo.target_pg_major(work, app, live.db_image))
    if blockers:
        raise BackupError('incompatible', blockers[0], app=app.id)
    # What is still to be written: the dump, the new cluster with its WAL and its export, the html dir twice.
    html_bytes = runner.dir_measure(live.rels['html'])['bytes']
    work.guard.check(2 * src.pg_bytes + ha_odoo.WAL_ALLOWANCE + 2 * html_bytes)
    dump = staging / 'nextcloud.dump'
    work.log('匯出 HA 的 Nextcloud 資料庫')
    with _private(dump) as handle:
        tmp.exec('hapg', ['pg_dump', '-U', 'postgres', '-Fc', '-d', dbname], user='postgres', stdout=handle,
                 timeout=ha_odoo.DUMP_TIMEOUT, max_output=work.guard.budget())
    tmp.remove('hapg')
    tmp.remove_volume('hapg')
    work.checkpoint()
    old_root, new_root = storage_id(src.config['datadirectory']), storage_id(target.config['datadirectory'])
    remote = f'appdata_{src.config["instanceid"]}/richdocuments/remoteData'
    built = build_cluster(work, app, tmp, target, dump, details=details, old_root=old_root, new_root=new_root,
                          remote=remote)
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
    return {'dirs': {live.rels[role]: paths[role] for role in paths}, 'custom_apps': sorted(src.apps),
            'policy': carried, 'counts': built['counts'], 'datadir_files': data.files, 'datadir_bytes': data.bytes,
            'mail': any(isinstance(k, str) and k.startswith('mail_') for k in src.config),
            'office': 'richdocuments' in (details.get('enabled') or []),
            'target_url': str(target.config.get('overwrite.cli.url') or '')[:200]}
