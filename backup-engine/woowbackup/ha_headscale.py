"""Home Assistant import, Headscale part: the WOOWTECH add-on `woow-headscale` -> this device's app `headscale`
(CONTRACT section 9 "Home Assistant import"; facts phase3/facts/headscale.md). Owner: E2.

The add-on keeps its whole VPN state in /var/lib/headscale (`data/`): the SQLite database `db.sqlite` (+ WAL; the
backup is cold), the control server's Noise identity `noise_private.key`, and in /etc/headscale (`config/`) the
MagicDNS extra records `dns_records.json` next to the `config.yaml` rendered from its options. HA's Headplane data,
its API key and cookie secret (`data/.headplane_*`, never read) and `data/options.json` do not move.

HAOS parity (2026-11-25, DESIGN B, E1; lane HERMES-HEADSCALE): HA's data and this device's own setup are no reason to refuse.
The add-on version, this device's version and the version the database records only inform (`VERSIONS.issues`, a notice):
what decides is the database itself, opened by this device's own `headscale configtest` before anything is packaged (HS-37).
No size limit refuses the app (the database and its WAL are only counted against the free space; a DNS file or a settings
file beyond what a valid one can be is no valid file, and a key longer than a key is no key). HA's IP prefixes replace this
device's in the converted configuration folder (HS-22; without that folder the range stays this device's and the devices
outside it are listed: HS-19), HA's identity key moves, and when HA has none that can be used this device's is kept and every
device has to log in again (HS-20, HS-38). A DNS file that is not valid, or whose path on this device would overwrite the
database or the key, is not moved and listed (HS-23, HS-34).

The access policy (owner decision D6, S3): HA's policy replaces this device's; when HA has none, this device's stays -- a
policy of this device that lives in its database is copied into the converted database by the SQLite child
(`hasqlite.COPY_POLICIES`, `replace_policies_from`); a device that keeps its policy in a file is not touched (the folder is
packed as it is). Where the child cannot do that yet, an import that would empty this device's database policy is refused
for Headscale only (`headscale.policy-keep-unsupported`): never silently open every device to every device.

The database is read -- and changed -- only by the sandboxed SQLite child (hasqlite): integrity, schema (only Headscale's
tables, no trigger, no view; the tables this device's own database has count as Headscale's), counts, version, migrations,
node addresses; for the conversion HA's API keys are replaced by this device's own rows, read from a copy of the live
database (taken from the live volume's export, integrity-checked, read again when it was being written), so the live
Headplane and MCP admin keys keep working and HA's keys never administer this server; the WAL is checkpointed into the file.
`headscale-data` is built from scratch with the live volume's owner: the converted `db.sqlite` (0644), HA's noise key (0600,
masked in every log; this device's own when HA's cannot be used) and HA's DNS records at the live config's
`extra_records_path` (0644; `[]` when HA has none). Before it is packaged the live image runs `headscale configtest`
(network none, the configuration read-only -- the converted one when the prefixes change) on a throwaway copy of that volume:
it opens the database, checks the version path, applies migrations and validates the schema exactly as the server will.
`headplane-data` is the live export as it is (this device's Headplane logins and roles stay; an entry without Headplane moves
only Headscale); every other volume or folder of this device's entry is carried as it is. The target keeps its `server_url`,
DNS and policy configuration, every config file and secret. An app entry that names the package's read-only configuration
folder as one of its host folders -- the form catalog-suggest drafts -- gets this device's own folder, packed as it is while
Headscale runs (with HA's prefixes written into its config.yaml when they differ).
"""
import contextlib
import copy
import io
import os
import posixpath
import re
import shutil
import tarfile
import time

from . import habackup, hacommon, haissues, hasqlite, hatarget, ha_n8n, ha_odoo, nested, tempctr
from .errors import BackupError
from .haissues import Issue

SLUG = 'woow-headscale'
APP_ID = 'headscale'
DB = 'data/db.sqlite'
WAL = 'data/db.sqlite-wal'
NOISE = 'data/noise_private.key'
DNS = 'config/dns_records.json'
CONFIG = 'config/config.yaml'
DATA_TARGET = '/var/lib/headscale'
CONFIG_TARGET = '/etc/headscale'
# Add-on version -> Headscale version (Woow_ha_vpn_headscale_package CHANGELOG.md, Dockerfile).
VERSIONS = hacommon.VersionTable('Headscale', {'0.1.0': '0.29.3', '0.1.1': '0.29.4', '0.1.2': '0.29.4',
                                               '0.1.3': '0.29.4'})
# The migrations Headscale 0.29.4 knows (hscontrol/db/db.go; `SCHEMA_INIT` is gormigrate's mark of a database its
# InitSchema created -- every fresh 0.29.x database has it, seen in the real backups). They only inform now: a database with
# another one is opened by this device's configtest, which decides (HS-17, HS-18).
MIGRATIONS = {'0.29.4': frozenset({'SCHEMA_INIT',
    '202501221827', '202501311657', '202502070949', '202502131714', '202502171819', '202505091439', '202505141324',
    '202507021200', '202510311551', '202511101554-drop-old-idx', '202511011637-preauthkey-bcrypt',
    '202511122344-remove-newline-index', '202511131445-node-forced-tags-to-tags',
    '202601121700-migrate-hostinfo-request-tags', '202602201200-clear-tagged-node-user-id',
    '202605221435-clear-zero-time-node-expiry', '202606181200-recover-null-tags-node-user-id',
    '202607241200-clear-tagged-node-expiry'})}
TABLES = frozenset({'migrations', 'users', 'pre_auth_keys', 'api_keys', 'nodes', 'policies', 'database_versions',
                    'sqlite_sequence'})
SQLITE_STATS = frozenset({'sqlite_stat1', 'sqlite_stat3', 'sqlite_stat4'})   # ANALYZE's own tables, not Headscale data
COUNTED = ('users', 'nodes', 'pre_auth_keys', 'api_keys', 'policies')
CORE_TABLES = frozenset({'users', 'nodes', 'api_keys'})   # without these it is no Headscale database (and no API key can be put in)
NOISE_RE = re.compile(r'privkey:[0-9a-f]{64}\Z')
RECORD_KEYS = frozenset({'name', 'type', 'value'})
PART_RE = re.compile(r'[^/\x00-\x1f\x7f]{1,255}\Z')
MAX_RECORDS = 10000
MAX_SMALL = 16 * 1024 * 1024    # HS-39, HS-40, HS-06: the largest dns_records.json / config.yaml that is read (a larger one is no valid file)
NOISE_BYTES = 4096              # HS-38: a longer noise_private.key is no key
LIVE_TRIES = 3                  # HS-24, HS-26, HS-29: reading this device's database copy again when it was being written
START_WAIT = 90                 # HS-27: seconds a Headscale that never ran gets to make its database
PREFIX_KEYS = ('prefixes.v4', 'prefixes.v6')

ISSUES = {
    'headscale.layout-unsupported': 'stop',     # HS-03, HS-04: this device's setup is none the import knows
    'headscale.extras-carried': 'auto',         # HS-04: this device's other volumes and folders go along as they are
    'headscale.headplane-absent': 'auto',       # HS-04: no Headplane here: only Headscale moves
    'headscale.config-unreadable': 'stop',      # HS-06: this device's config.yaml cannot be read
    'headscale.config-link-followed': 'auto',   # HS-06: it is a link to a file in the home folder: read there
    'headscale.data-path': 'stop',              # HS-07, HS-08, HS-09: where the database or the key lie
    'headscale.no-database': 'stop',            # HS-13, HS-28: HA's Headscale never started
    'headscale.db-unusable': 'stop',            # HS-14 (kept)
    'headscale.db-extra-objects': 'confirm',    # HS-15: remove only the extra schema objects in a sandboxed copy
    'headscale.db-version-differs': 'notice',   # HS-16, HS-18: the database is of another version: configtest decides
    'headscale.noise-key-kept': 'confirm',      # HS-20, HS-38: HA's identity key cannot be used: this device's stays
    'headscale.devices-outside-range': 'confirm',   # HS-19
    'headscale.prefixes-replaced': 'confirm',   # HS-22: this device's IP ranges become HA's
    'headscale.prefixes-kept': 'notice',        # HS-22: ... cannot be written here: this device's stay
    'headscale.prefixes-unknown': 'notice',     # HS-21: HA's settings cannot be read: this device's ranges are used
    'headscale.dns-records-invalid': 'confirm',     # HS-23: HA's extra DNS records stay out
    'headscale.dns-path-conflict': 'confirm',   # HS-34: ... where this device's setting would overwrite its database or key
    'headscale.dns-outside-volume': 'notice',
    'headscale.api-keys-not-moved': 'notice',
    'headscale.policy-replaced': 'confirm',     # HS-25 (S3): HA's policy replaces the one stored here
    'headscale.policy-kept': 'notice',          # HS-25 (S3): HA has none: this device's stays
    'headscale.policy-not-applied': 'confirm',  # HS-25 (S3): HA has a policy that cannot be applied here
    'headscale.policy-stale': 'confirm',        # HS-25 (S3): HA's database holds a policy HA did not use: it would apply here
    'headscale.policy-keep-unsupported': 'stop',    # HS-25 (S3): this device's stored policy cannot be kept yet
    'headscale.policy-unreadable': 'stop',      # HS-24, HS-30: this device's policy cannot be read
    'headscale.live-db-missing': 'stop',        # HS-27: this device's Headscale has no database, also after starting it
    'headscale.live-copy-unreadable': 'stop',   # HS-26, HS-29: this device's database copy cannot be read, also after trying again
    'headscale.config-changed': 'stop',         # HS-36: this device's configuration kept changing
    'headscale.config-edit-failed': 'stop',     # HS-22: the prefixes cannot be written into this device's config.yaml
    'headscale.config-folder-unusable': 'stop',     # HS-35
    'headscale.keys-not-replaced': 'stop',      # HS-32
    'headscale.verify-failed': 'stop',          # HS-33: the converted database is not what was made
    'headscale.configtest-failed': 'stop',      # HS-37
}


class Source:
    def __init__(self):
        self.addon = None
        self.report = None
        self.db = None           # staged path
        self.wal = None
        self.noise = None        # the key text (masked); '' when there is none that can be used
        self.records = None      # bytes of a valid DNS records file, or None
        self.records_count = 0
        self.records_bad = False
        self.config = {}
        self.config_unread = False


class Plan:
    """What the conversion does beyond moving HA's database (decided by `judge`)."""

    def __init__(self):
        self.edits = {}              # {'prefixes.v4': text}: written into this device's config.yaml (HS-22)
        self.copy_policies = False   # this device's stored policy goes into the converted database (S3)
        self.keep_noise = False      # HA's identity key cannot be used: this device's stays (HS-20, HS-38)
        self.skip_records = False    # no DNS records file is written: this device's path for it lies on its database or key (HS-34)
        self.policy = None           # 'kept' | 'replaced' | None
        self.strip_extra = False     # HA has schema objects Headscale on this device does not use (HS-15)


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
    HA's config.yaml read (bounded). Never: `-shm`, Headplane's data and secrets, options. No size refuses the app: the
    database goes to disk whatever its size (the job's watchdog watches the free space), a key longer than a key is no key
    (HS-38), a DNS file or a settings file larger than any valid one is not read (HS-39, HS-40)."""
    from . import jobs
    select = habackup.Select(include=(DB, WAL, NOISE, DNS, CONFIG), symlinks=(), hardlinks=False)
    src = Source()
    for entry in habackup.iter_entries(stream, select, report, checkpoint=checkpoint):
        if entry.kind != 'file':
            raise BackupError('incompatible', f'HA 備份中 Headscale 的 {entry.name[:100]} 不是一般檔案。', member=entry.name)
        if entry.name in (DB, WAL):
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
            if entry.size > NOISE_BYTES:   # HS-38: no key is that long
                src.noise = ''
                continue
            text = entry.read_all(NOISE_BYTES).decode('ascii', 'replace').strip()
            if text:
                jobs.mask_secret(text)
            src.noise = text if NOISE_RE.fullmatch(text) else ''
        elif entry.name == DNS:
            if entry.size > MAX_SMALL:   # HS-39: larger than any valid file
                src.records_bad, src.records, src.records_count = True, None, 0
                continue
            data = entry.read_all(MAX_SMALL)
            count = valid_records(data)
            src.records_bad = count is None
            src.records, src.records_count = (data, count) if count is not None else (None, 0)
        elif entry.name == CONFIG:
            if entry.size > MAX_SMALL:   # HS-40
                src.config_unread = True
                continue
            src.config = hacommon.scalars(entry.read_all(MAX_SMALL).decode('utf-8', 'replace'), max_bytes=MAX_SMALL)
    src.addon = report.addon
    src.report = report
    return src


# ====================================================================== the live target

def _mounts(quadlets, name, home):
    return ha_odoo.quadlet_mounts(quadlets, name, home)


def _server_file(quadlets, home):
    """The Quadlet file of the Headscale server (HS-03): the container named `headscale`, else the only one that mounts the
    data and the configuration folder and is no Headplane."""
    named = hacommon.container_file(quadlets, 'headscale')
    if named is not None:
        return named
    found = []
    for name in sorted(quadlets):
        if not name.endswith('.container'):
            continue
        try:
            targets = {t.rstrip('/') for _s, t, _o in _mounts(quadlets, name, home)}
        except BackupError:
            continue
        if {DATA_TARGET, CONFIG_TARGET} <= targets and '/var/lib/headplane' not in targets:
            found.append(name)
    return found[0] if len(found) == 1 else None


class Target:
    """The headscale app's catalog items the import fills, resolved against the live Quadlet files: the server is found by what
    it mounts, Headplane may be absent, whatever else the entry holds is carried as it is (HS-03, HS-04); only what the import
    cannot take at all stops the app (`headscale.layout-unsupported`, with what to do)."""

    def __init__(self, work, app, sink=None):
        quadlets = work.quadlets(app)
        home = work.runner(app).home.rstrip('/')
        declared = [v['name'] for v in app.volumes]
        server_file = _server_file(quadlets, home)
        if server_file is None:
            raise haissues.stopped(Issue('headscale.layout-unsupported', 'stop',
                                         '這台的 Headscale 設定裡找不到 Headscale 伺服器的容器（沒有叫 headscale 的容器，也沒有一個同時掛著 '
                                         '/var/lib/headscale 和 /etc/headscale 的容器）。',
                                         action='請確認這台的 Headscale 是照 WOOWTECH 的 Podman 套件安裝的，再匯入。'),
                                   'incompatible', app=app.id)
        mounts = _mounts(quadlets, server_file, home)
        self.data_volume = next((s for s, t, _o in mounts if t.rstrip('/') == DATA_TARGET), None)
        config = next((s for s, t, _o in mounts if t.rstrip('/') == CONFIG_TARGET), None)
        _file, headplane = hacommon.mounted(quadlets, home, '/var/lib/headplane')
        self.headplane_volume = headplane if headplane in declared else None
        if self.data_volume not in declared or config is None or not config.startswith(home + '/') or app.postgres:
            raise haissues.stopped(Issue('headscale.layout-unsupported', 'stop',
                                         '這台 Headscale 的應用設定和它的 Quadlet 檔不一致：資料卷不在應用設定裡、設定資料夾不在擁有者的家目錄裡，'
                                         '或設定了資料庫匯出項目。', action='請到「應用軟體」修正這個應用的設定，再匯入。'),
                                   'incompatible', app=app.id)
        config_rel = config[len(home) + 1:]
        dirs = [d['path'] for d in app.data_dirs]
        self.config_dir = config_rel if config_rel in dirs else None   # the configuration folder as the entry's host folder
        self.config_mount = (config, CONFIG_TARGET, 'ro')
        self.config_rel = config_rel + '/config.yaml'
        self.server_container = ha_odoo.quadlet_container_name(quadlets, server_file)
        self.extra_volumes, self.extra_dirs = hatarget.extras(app, handled_volumes=(self.data_volume, self.headplane_volume),
                                                              handled_dirs=(self.config_dir,))
        self.image = tempctr.quadlet_image(quadlets[server_file])
        if not self.image:
            raise BackupError('incompatible', '這台 Headscale 的 Quadlet 設定缺少映像。', app=app.id)
        if sink is not None:
            if self.headplane_volume is None:
                sink.auto('headscale.headplane-absent', '這台沒有安裝 Headplane，匯入只搬 Headscale 的資料。')
            if self.extra_volumes or self.extra_dirs:
                sink.auto('headscale.extras-carried', '這台 Headscale 的應用設定還有 Headscale 匯入不處理的資料卷或資料夾，'
                                                     '匯入時會照這台現在的內容原樣帶過去，不會變。',
                          [*self.extra_volumes, *self.extra_dirs])


def _config_through_link(work, app, runner, rel):
    """This device's config.yaml when it is a link to a file inside the owner's home folder (HS-06), else None. The link's text
    is read once, the file it names is read with the runner's usual rules (no further link is ever followed); a link that leaves
    the home folder is no link to follow (X-PD-08)."""
    stat = getattr(runner, 'stat_files', None)
    if stat is None or (stat([rel]).get(rel) or {}).get('type') != 'link':
        return None
    home = runner.home.rstrip('/')
    path = f'{home}/{rel}'
    try:
        result = runner.podman('unshare', 'readlink', '--', path, timeout=60, max_output=64 * 1024, check=False)
    except BackupError:
        return None
    text = (result.stdout or b'').decode('utf-8', 'replace').strip() if result.returncode == 0 else ''
    if not text or len(text) > 1024 or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return None
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), text))
    if not resolved.startswith(home + '/'):
        return None
    try:
        data = runner.read_file(resolved[len(home) + 1:], max_bytes=MAX_SMALL)
    except BackupError:
        return None
    sink = getattr(work, 'sink', None)
    if sink is not None:
        sink(app).auto('headscale.config-link-followed', '這台 Headscale 的 config.yaml 是連結，已改讀它指到的檔案（在擁有者的家目錄裡）。')
    return data


def live_config(work, app, target):
    runner = work.runner(app)
    try:
        data = runner.read_file(target.config_rel, max_bytes=MAX_SMALL)
    except BackupError:
        data = _config_through_link(work, app, runner, target.config_rel)
        if data is None:
            raise haissues.stopped(Issue('headscale.config-unreadable', 'stop', '無法讀取這台 Headscale 的設定檔（config.yaml）。',
                                         action='請確認這台 Headscale 已安裝並啟動過一次，設定檔是一般檔案（或指到家目錄裡的檔案），再匯入。'),
                                   'incompatible', app=app.id) from None
    return hacommon.scalars(data.decode('utf-8', 'replace'), max_bytes=MAX_SMALL)


def _part_ok(part):
    return PART_RE.fullmatch(part) is not None and part not in ('.', '..')


def data_paths(config):
    """Resolve configured identity files strictly inside the data volume: any characters but the ones that would leave it
    (HS-08); a place outside the volume (HS-07) or one file on top of the other (HS-09) is no setup that can be imported."""
    paths = []
    for key, default in (('database.sqlite.path', '/var/lib/headscale/db.sqlite'),
                         ('noise.private_key_path', '/var/lib/headscale/noise_private.key')):
        path = config.get(key, default)
        if not isinstance(path, str) or not path.startswith(DATA_TARGET + '/'):
            raise haissues.stopped(Issue('headscale.data-path', 'stop',
                                         f'這台 Headscale 的設定 {key} 必須放在 {DATA_TARGET}/ 底下，否則匯入的資料伺服器看不到。',
                                         action='請把這台 Headscale 設定檔裡的這個路徑改到資料卷 /var/lib/headscale 裡，再匯入。'))
        rel = path[len(DATA_TARGET) + 1:]
        if not rel or not all(_part_ok(part) for part in rel.split('/')):
            raise haissues.stopped(Issue('headscale.data-path', 'stop', f'這台 Headscale 的設定 {key} 的路徑含有會跑出資料卷的部分（..）或不能用的字元。',
                                         action='請修正這台 Headscale 設定檔裡的這個路徑，再匯入。'))
        paths.append(rel)
    if (paths[1] in (paths[0], paths[0] + '-wal', paths[0] + '-shm')
            or paths[0].startswith(paths[1] + '/') or paths[1].startswith(paths[0] + '/')):
        raise haissues.stopped(Issue('headscale.data-path', 'stop', '這台 Headscale 的資料庫與身分金鑰的路徑互相衝突（一個蓋在另一個上面）。',
                                     action='請修正這台 Headscale 設定檔裡的這兩個路徑，再匯入。'))
    return tuple(paths)


def records_rel(config):
    """The extra-records file's path inside the data volume (None when the live config keeps it elsewhere)."""
    path = config.get('dns.extra_records_path') or ''
    if not path.startswith(DATA_TARGET + '/'):
        return None
    rel = path[len(DATA_TARGET) + 1:]
    return rel if all(_part_ok(part) for part in rel.split('/')) and rel not in ('db.sqlite', 'noise_private.key') else None


def records_conflict(config):
    """True when this device's extra-records file lies where its database or key does (HS-34)."""
    rel = records_rel(config)
    if rel is None:
        return False
    db_rel, key_rel = data_paths(config)
    return any(rel == x or x.startswith(rel + '/') or rel.startswith(x + '/') for x in (db_rel, key_rel, db_rel + '-wal', db_rel + '-shm'))


# ====================================================================== analysis

def _specs(*, replace, copy_policies=False, strip_extra=False):
    ha = {'db': 'ha.sqlite', 'check': 'integrity', 'schema': True, 'counts': sorted(TABLES),
          'queries': ['headscale.version', 'headscale.migrations', 'headscale.node_ips', 'headscale.api_key_prefixes']}
    if replace:
        ha['replace_api_keys_from'] = 'live.sqlite'
        if strip_extra:
            ha['strip_extra_from'] = 'live.sqlite'
            ha['keep_tables'] = sorted(TABLES | SQLITE_STATS)
        if copy_policies:
            ha['replace_policies_from'] = 'live.sqlite'
        return [{'db': 'live.sqlite', 'check': 'integrity', 'schema': True, 'queries': ['headscale.api_key_prefixes'],
                 'counts': ['policies']}, ha]
    return [ha]


def can_copy_policies():
    """Whether the SQLite child can put this device's stored policy into the converted database (the operation of the patch
    snippets/parity-hh/hasqlite.py.patch)."""
    return bool(getattr(hasqlite, 'COPY_POLICIES', False))


def _prefix_changes(ha_config, config):
    return {key: (hacommon.network(ha_config.get(key)), hacommon.network(config.get(key))) for key in PREFIX_KEYS
            if hacommon.network(ha_config.get(key)) is not None and hacommon.network(config.get(key)) is not None
            and hacommon.network(ha_config.get(key)) != hacommon.network(config.get(key))}


def judge(sink, src, answer, *, addon_version, version, ha_config, config, live=None, edit_config=False):
    """What the check and the conversion say about HA's Headscale and this device's side of it: every finding goes to `sink` (the
    check collects, the conversion stops at a `stop` and wants a `confirm` confirmed). `answer`: the SQLite child's on HA's
    database (None when HA has none); `live`: its answer on this device's copy (None: this device's side is not judged);
    `edit_config`: this device's configuration folder is part of the backup, so HA's prefixes can be written into it. Returns
    (details, plan)."""
    plan = Plan()
    sink.extend(VERSIONS.issues(addon_version, version))   # HS-10, HS-11: the table and this device's version only inform
    details = {'users': 0, 'nodes': 0, 'pre_auth_keys': 0, 'api_keys': 0, 'policies': 0, 'db_version': None}
    known = TABLES | SQLITE_STATS | frozenset(((live or {}).get('schema') or {}).get('tables') or ())   # HS-15: this device's own tables count
    node_ips = []
    if src.db is None:   # HS-13, HS-28: HA's Headscale never started: only Headscale is left out, this device's stays
        sink.stop('headscale.no-database', 'HA 備份裡沒有 Headscale 的資料庫（db.sqlite），可能從來沒有啟動過；沒有可搬的資料，這台的 Headscale 不會變。',
                  action='請先在 HA 啟動 Headscale 並使用一次，再重新備份後匯入；不需要搬 Headscale 時，取消勾選它即可。')
    elif answer is not None:
        why = hasqlite.problem(answer)
        if why:
            sink.stop('headscale.db-unusable', f'HA 的 Headscale 資料庫已損毀或無法讀取（{haissues.clean(why, 120)}）。',
                      action='請在 HA 重新備份後再匯入 Headscale；這台的 Headscale 不會變。')
        else:
            schema = answer.get('schema') or {}
            tables = set(schema.get('tables') or [])
            if not tables - {'sqlite_sequence'}:   # a database file with nothing in it: HA's Headscale never made its tables
                sink.stop('headscale.no-database', 'HA 備份裡 Headscale 的資料庫是空的（沒有任何資料表），可能從來沒有啟動過；沒有可搬的資料，'
                                                   '這台的 Headscale 不會變。',
                          action='請先在 HA 啟動 Headscale 並使用一次，再重新備份後匯入；不需要搬 Headscale 時，取消勾選它即可。')
            elif CORE_TABLES - tables:   # not the database of a Headscale: the API keys of this device could not be put into it
                sink.stop('headscale.db-unusable', 'HA 備份裡 Headscale 的資料庫缺少 Headscale 的基本資料表（'
                                                   f'{hacommon.names(sorted(CORE_TABLES - tables), 5)}），不是可以搬過來的 Headscale 資料庫。',
                          action='請在 HA 重新備份後再匯入 Headscale；這台的 Headscale 不會變。')
            extra_tables = sorted(tables - known)
            triggers, views = list(schema.get('trigger_names') or []), list(schema.get('view_names') or [])
            odd = ([f'資料表：{name}' for name in extra_tables]
                   + [f'觸發程序：{name}' for name in triggers]
                   + [f'檢視表：{name}' for name in views])
            if odd:   # HS-15: none of these objects belongs to the imported Headscale data
                if (len(odd) > 1000 or schema.get('triggers') != len(triggers) or schema.get('views') != len(views)
                        or any(not isinstance(name, str) or not name or len(name) > 512 or '\x00' in name
                               for name in [*extra_tables, *triggers, *views])):
                    sink.stop('headscale.db-unusable', 'HA 的 Headscale 資料庫多出的結構太多或名稱不完整，無法安全地移除。',
                              action='請先在 HA 檢查資料庫，再重新備份後匯入；這台的 Headscale 不會變。')
                elif ((live or {}).get('schema') or {}).get('triggers') or ((live or {}).get('schema') or {}).get('views'):
                    sink.stop('headscale.db-unusable', '這台 Headscale 的資料庫有觸發程序或檢視表，無法確認哪些是應保留的結構。',
                              action='請先確認這台 Headscale 的資料庫結構，再匯入；這台的 Headscale 不會變。')
                else:
                    plan.strip_extra = True
                    sink.confirm('headscale.db-extra-objects',
                                 f'HA 的 Headscale 資料庫有這台不使用的內容（{hacommon.names(odd, 5)}）；'
                                 '匯入時只在轉換用的複本移除這些資料表、觸發程序或檢視表，其餘資料照搬。', odd)
            counts = answer.get('counts') or {}
            details.update({k: ha_odoo._int(counts.get(k)) for k in COUNTED})
            values = answer.get('values') or {}
            stored = values.get('headscale.version')
            details['db_version'] = stored if isinstance(stored, str) else None
            known_migrations = MIGRATIONS.get(hacommon.semver(version) or '')
            applied = [m for m in values.get('headscale.migrations') or [] if isinstance(m, str)]
            unknown = [m for m in applied if known_migrations is not None and m not in known_migrations]
            if (version and hacommon.semver(details['db_version']) != hacommon.semver(version)) or unknown:   # HS-16, HS-18
                sink.notice('headscale.db-version-differs',
                            f'HA 的 Headscale 資料庫記錄的版本是 {haissues.clean(details["db_version"] or "未知", 40)}，這台是 '
                            f'{haissues.clean(version or "未知", 40)}{"，而且有這台不認得的升級紀錄" if unknown else ""}；'
                            '匯入前這台的 Headscale 會先試著開啟轉換後的資料庫（configtest），打不開時只停 Headscale，這台不會變。',
                            unknown[:20])
            node_ips = values.get('headscale.node_ips') or []
    # HA's identity key (HS-20, HS-38)
    if not src.noise:
        plan.keep_noise = True
        sink.confirm('headscale.noise-key-kept', 'HA 備份裡沒有可用的 Headscale 伺服器身分金鑰（noise_private.key）；會沿用這台現有的金鑰，'
                                                 '所有裝置都要重新登入這台伺服器（使用者與設定都在）。', ['noise_private.key'])
    # the IP ranges (HS-21, HS-22, HS-19)
    effective = dict(config)
    if not src.config:
        sink.notice('headscale.prefixes-unknown', '讀不到 HA 的 Headscale 設定檔裡的 IP 位址範圍（prefixes），這台的範圍保持不變；'
                                                  '有裝置的位址在這台的範圍外時會列出來。')
    changes = _prefix_changes(ha_config, config)
    if changes:
        text = '、'.join(f'{key}：HA 是 {ha}，這台原本是 {mine}' for key, (ha, mine) in changes.items())
        if edit_config:
            plan.edits = {key: ha_config[key].strip() for key in changes}
            effective.update(plan.edits)
            sink.confirm('headscale.prefixes-replaced', f'匯入後這台 Headscale 的 IP 位址範圍會改成 HA 的（{text}）；這台設定檔（config.yaml）裡的 '
                                                        'prefixes 會被改寫，裝置才能照常連線。', sorted(changes))
        else:
            sink.notice('headscale.prefixes-kept', f'HA 與這台的 IP 位址範圍不同（{text}）；這台的設定檔不在這份備份裡，沒有改成 HA 的，'
                                                   '範圍保持這台的。')
    outside = haissues.Names(nodes_outside(node_ips, effective))
    if outside.count:   # HS-19
        sink.confirm('headscale.devices-outside-range', f'HA 有 {outside.count} 個裝置位址不在匯入後這台的 IP 位址範圍內，這些裝置的位址不會重新配置，'
                                                        '可能連不上，需要重新註冊（其他裝置不受影響）。', outside)
    # the DNS extra records (HS-23, HS-34)
    if src.records_bad:   # no record of HA's is moved: an empty list is written where this device keeps them
        sink.confirm('headscale.dns-records-invalid', 'HA 的 Headscale DNS 額外記錄（dns_records.json）格式不正確或太大，這次不搬它；'
                                                      '匯入後沒有額外的 DNS 記錄（其他資料照搬）。', ['dns_records.json'])
    if records_conflict(config):
        plan.skip_records = True
        sink.confirm('headscale.dns-path-conflict', '這台 Headscale 的 DNS 額外記錄檔的路徑會蓋到它的資料庫或身分金鑰，這次不搬 HA 的 DNS 額外記錄'
                                                    '（其他資料照搬）。', ['dns.extra_records_path'])
    elif src.records_count and records_rel(config) is None:
        sink.notice('headscale.dns-outside-volume', f'這台的 Headscale 把 DNS 額外記錄放在資料卷以外，HA 的 {src.records_count} 筆記錄不會搬過來，'
                                                    '請手動加入。')
    if details['api_keys']:
        sink.notice('headscale.api-keys-not-moved', f'HA 的 {details["api_keys"]} 把 Headscale API 金鑰不會搬過來，這台的 API 金鑰'
                                                    '（Headplane、MCP 管理）保持有效。')
    if live is not None:
        _policy(sink, plan, details, ha_config, config, live)
    return details, plan


def _policy(sink, plan, details, ha_config, config, live):
    """The access policy (S3): HA's replaces this device's; when HA has none this device's stays."""
    counts = live.get('counts') or {}
    if hasqlite.problem(live) or 'policies' not in counts:   # HS-24, HS-30
        sink.stop('headscale.policy-unreadable', '無法確認這台 Headscale 的資料庫存取政策，已停止匯入。',
                  action='請稍後再試一次；仍然不行時，請確認這台的 Headscale 正常運作。')
        return
    rows = ha_odoo._int(counts['policies'])
    here_database = config.get('policy.mode', 'file') == 'database'
    mine = rows > 0 if here_database else bool(config.get('policy.path'))   # this device has a policy of its own
    ha_database = ha_config.get('policy.mode', 'file') == 'database'
    ha_rows = details['policies']
    if ha_config.get('policy.path'):
        sink.confirm('headscale.policy-not-applied', 'HA 的 Headscale 使用了存取政策檔（policy.path），那個檔案這次不會套用到這台；'
                                                     f'{"這台現有的存取政策會保留。" if mine else "匯入後這台沒有存取政策，所有裝置可以互相連線。"}'
                                                     '請匯入後到 Headplane 檢查存取政策。', ['policy.path'])
    if ha_database and ha_rows > 0:
        if here_database:   # HA's database comes with its policy: it replaces this device's
            plan.policy = 'replaced'
            if rows > 0:
                sink.confirm('headscale.policy-replaced', '這台現有的存取政策會換成 HA 的。', ['policies'])
            return
        sink.confirm('headscale.policy-not-applied', 'HA 的存取政策放在資料庫裡，但這台用政策檔，HA 的政策不會套用；這台的政策檔保持不變。'
                                                     '請匯入後檢查存取政策。', ['policies'])
    # HA brings no policy that applies here
    if here_database and (rows > 0 or ha_rows > 0):   # this device's stored policy, or HA's unused one that must not apply
        if can_copy_policies():
            plan.copy_policies = True
        elif rows > 0:
            sink.stop('headscale.policy-keep-unsupported', 'HA 沒有存取政策，而這台的存取政策存在資料庫裡；匯入會把它清掉，所有裝置就會互通，'
                                                           '所以這次沒有匯入 Headscale。',
                      action='請先在 Headplane 把這台的存取政策另存一份，並請工程人員更新備份元件後再匯入；也可以先不匯入 Headscale。')
            return
        else:
            sink.confirm('headscale.policy-stale', 'HA 的資料庫裡留有一份 HA 沒有在使用的存取政策，匯入後它會在這台生效。', ['policies'])
            return
    if mine:
        plan.policy = 'kept'
        sink.notice('headscale.policy-kept', 'HA 沒有存取政策，這台現有的存取政策會保留；它寫的使用者和群組如果 HA 沒有，規則不會生效，'
                                             '請匯入後檢查。')


def analyse(src, answer, *, addon_version, version, ha_config, config, live=None, edit_config=False):
    """(blockers, warnings, details) of HA's Headscale against this device, the sentences the older pages read: the lines that
    stop or must be confirmed, and the others. `judge` with a sink that only collects."""
    sink = haissues.Sink(APP_ID)
    details, _plan = judge(sink, src, answer, addon_version=addon_version, version=version, ha_config=ha_config, config=config,
                           live=live, edit_config=edit_config)
    return ([i.message for i in sink.found if i.level in ('stop', 'confirm')],
            [i.message for i in sink.found if i.level in ('auto', 'notice')], details)


def nodes_outside(rows, config):
    """Addresses of nodes outside this device's prefixes."""
    nets = [hacommon.network(config.get(key)) for key in PREFIX_KEYS]
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


def section(src, details, *, version, ha_config, config, plan=None):
    return {'headscale_version': VERSIONS.upstream(src.addon.version) if src.addon else '',
            'db_version': details['db_version'] or '', 'users': details['users'], 'nodes': details['nodes'],
            'pre_auth_keys': details['pre_auth_keys'], 'api_keys': details['api_keys'], 'policies': details['policies'],
            'prefixes': {'v4': ha_config.get('prefixes.v4', ''), 'v6': ha_config.get('prefixes.v6', '')},
            'server_url': ha_config.get('server_url', ''), 'target_server_url': config.get('server_url', ''),
            'dns_records': src.records_count, 'target_version': version or '',
            'policy': plan.policy if plan is not None else None,
            'prefixes_replaced': sorted(plan.edits) if plan is not None else []}


# ====================================================================== this device's own database (HS-24, HS-26, HS-27, HS-29)

def _clean_live(staging):
    """What an earlier try of reading this device's database copy left."""
    for name in ('live-data.tar', 'live.sqlite', 'live.sqlite-wal'):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(staging / name)
    shutil.rmtree(staging / 'sqlite-live', ignore_errors=True)


def _export_live(work, app, target, staging, db_rel, key_rel):
    """({name: path} of this device's database (+ WAL) copied out of the live volume's export, this device's identity key text or
    None). Read while Headscale runs; the child checks the copy before a row of it is used."""
    from . import jobs
    export = hacommon.live_export(work, app, target.data_volume, staging / 'live-data.tar')
    found, noise = {}, None
    try:
        with ha_odoo._live_tar(export, '這台 Headscale 的資料卷') as tar:
            for member in tar:
                name = ha_odoo._norm(member.name)
                if name in (db_rel, db_rel + '-wal') and member.isfile():
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
                elif key_rel is not None and name == key_rel and member.isfile() and member.size <= NOISE_BYTES:
                    text = tar.extractfile(member).read().decode('ascii', 'replace').strip()
                    if text:
                        jobs.mask_secret(text)
                    noise = text if NOISE_RE.fullmatch(text) else None
                tar.members.clear()
    except tarfile.TarError:
        raise BackupError('job-failed', '這台 Headscale 資料卷的匯出內容無法讀取。', app=app.id) from None
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(export)
    return found, noise


def _read_live(work, app, target, staging, config, *, key=False):
    """(files, answer, noise): this device's database (+ WAL) and what the child says about it (integrity, tables, how many
    policies, API key prefixes), `noise` this device's identity key when `key`. A copy that cannot be read -- Headscale was writing
    while it was copied -- is read again (HS-24, HS-26, HS-29); a Headscale that never ran has no database: it is started once so
    that it makes one, and put back afterwards (HS-27). When this device's database cannot be had, only Headscale stops."""
    db_rel, key_rel = data_paths(config)

    def attempt():
        _clean_live(staging)
        found, noise = _export_live(work, app, target, staging, db_rel, key_rel if key else None)
        if 'live.sqlite' not in found:
            return None
        answer = hasqlite.run([{'db': 'live.sqlite', 'check': 'integrity', 'schema': True, 'counts': ['policies'],
                                'queries': ['headscale.api_key_prefixes']}], found, staging / 'sqlite-live',
                              checkpoint=work.checkpoint, what='這台 Headscale 資料庫')['live.sqlite']
        why = hasqlite.problem(answer)
        if why:
            raise BackupError('job-failed', f'這台 Headscale 資料庫的複本無法讀取（{haissues.clean(why, 80)}）。', app=app.id)
        return found, answer, noise

    def settle(action):
        try:
            return hatarget.retry(action, attempts=LIVE_TRIES, abort=work.abort, log=work.log, what='讀取這台 Headscale 的資料庫複本')
        except BackupError as error:
            if error.code != 'job-failed' or haissues.is_job_wide(error):
                raise
            raise haissues.stopped(Issue('headscale.live-copy-unreadable', 'stop',
                                         '這台 Headscale 資料庫的複本一直讀不出來（可能正在寫入），已試了多次；這台沒有任何變更。',
                                         action='請稍後再試一次；仍然不行時，請確認這台的 Headscale 正常運作。'),
                                   'job-failed', app=app.id) from None

    got = settle(attempt)
    if got is not None:
        return got
    # HS-27: no database in this device's volume
    service = hatarget.ensure_running(work, app, target.server_container)
    found = []

    def database_there():
        try:
            result = attempt()
        except BackupError as error:
            if error.code != 'job-failed' or haissues.is_job_wide(error):
                raise
            return False
        if result is None:
            return False
        found.append(result)
        return True

    if not hatarget.wait_until(database_there, timeout=START_WAIT if service.started else 0, interval=3.0, abort=work.abort) and not found:
        raise haissues.stopped(Issue('headscale.live-db-missing', 'stop', '這台的 Headscale 資料卷裡沒有資料庫，啟動它之後也沒有出現。',
                                     action='請先在這台確認 Headscale 能正常啟動（資料庫路徑在設定檔裡），再匯入。'),
                               'incompatible', app=app.id)
    work.log('這台的 Headscale 還沒有資料庫，已暫時啟動它建立一個；匯入完成後會恢復原狀。')
    return found[0]


# ====================================================================== the job steps

def _pass(work, staging):
    member = work.addon_member(SLUG)
    report = habackup.Report(names=haissues.Names)
    with work.open(member) as stream:
        src = scan_member(stream, report, staging, checkpoint=work.checkpoint)
    for note in report.warnings():
        work.log(note)
    return src


def _prepare(work, app, sink=None):
    target = Target(work, app, sink)
    try:
        labels = hacommon.image_labels(work, app, target.image)
    except BackupError as error:
        if error.code != 'job-failed':   # an image that is not here is the app's stop; labels that cannot be read only mean "no version"
            raise
        labels = {}
    version = hacommon.semver(labels.get('org.opencontainers.image.version'))
    config = live_config(work, app, target)
    data_paths(config)
    return target, version, config


def _ha_files(src):
    return {'ha.sqlite': src.db, **({'ha.sqlite-wal': src.wal} if src.wal else {})}


def check(work, app):
    sink = work.sink(app)
    target, version, config = _prepare(work, app, sink)
    staging = work.staging / 'headscale-work'
    staging.mkdir(mode=0o700)
    src = _pass(work, staging)
    sink.skipped(src.report)   # the selected HA entries the reader left out are shown before import
    work.phase('check')
    answer = None
    if src.db is not None:
        answer = hasqlite.run(_specs(replace=False), _ha_files(src), staging / 'sqlite', checkpoint=work.checkpoint,
                              what='Headscale 資料庫')['ha.sqlite']
    _files, live, _noise = _read_live(work, app, target, staging, config)
    addon = work.addon_info(SLUG)
    details, plan = judge(sink, src, answer, addon_version=addon.version, version=version, ha_config=src.config, config=config,
                          live=live, edit_config=target.config_dir is not None)
    return {'target_version': version or '',
            'headscale': section(src, details, version=version, ha_config=src.config, config=config, plan=plan)}


def convert(work, app, test_mode, out_dir):
    """Build `out_dir/volumes/<headscale-data>.tar` and `<headplane-data>.tar` (and what else this device's entry holds)."""
    sink = work.sink(app)
    adapter = work.adapter(app)
    tmp = work.temp(app)
    target, version, config = _prepare(work, app, sink)
    ids = adapter.owner_ids()
    staging = work.staging / 'headscale-work'
    staging.mkdir(mode=0o700)
    (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
    src = _pass(work, staging)
    sink.skipped(src.report)   # a changed skip list needs confirmation before the converted data is written
    work.phase('convert')
    addon = work.addon_info(SLUG)
    ha_answer = None
    if src.db is not None:
        ha_answer = hasqlite.run(_specs(replace=False), _ha_files(src), staging / 'sqlite-ha', checkpoint=work.checkpoint,
                                 what='Headscale 資料庫')['ha.sqlite']
    live_files, live_answer, live_noise = _read_live(work, app, target, staging, config, key=True)
    details, plan = judge(sink, src, ha_answer, addon_version=addon.version, version=version, ha_config=src.config, config=config,
                          live=live_answer, edit_config=target.config_dir is not None)
    files = {**_ha_files(src), **live_files}
    converted = staging / 'converted'
    converted.mkdir(mode=0o700)
    answers = hasqlite.run(_specs(replace=True, copy_policies=plan.copy_policies, strip_extra=plan.strip_extra), files, staging / 'sqlite', outputs=('ha.sqlite',),
                           out_dir=converted, checkpoint=work.checkpoint, what='Headscale 資料庫')
    replaced = answers['ha.sqlite'].get('replaced') or {}
    live_keys = (answers['live.sqlite'].get('values') or {}).get('headscale.api_key_prefixes') or []
    if replaced.get('prefixes') != live_keys:   # HS-32
        raise haissues.stopped(Issue('headscale.keys-not-replaced', 'stop', 'Headscale 的 API 金鑰沒有換成這台的，已停止；這台沒有任何變更。',
                                     action='請再試一次；仍然不行時，請把作業紀錄交給工程人員。'), 'job-failed', app=app.id)
    db_file = answers[None]['ha.sqlite']
    verify_specs = _specs(replace=False)
    verify_specs += [{'db': 'original.sqlite', 'check': 'integrity', 'counts': sorted(TABLES)},
                     {'db': 'live.sqlite', 'check': 'integrity', 'counts': ['policies'],
                      'queries': ['headscale.api_key_prefixes']}]
    verify_files = {'ha.sqlite': db_file, 'original.sqlite': src.db,
                    **({'original.sqlite-wal': src.wal} if src.wal else {}),
                    **{name: path for name, path in files.items() if name.startswith('live.sqlite')}}
    verified = hasqlite.run(verify_specs, verify_files, staging / 'sqlite-verify', checkpoint=work.checkpoint,
                            what='轉換後 Headscale 資料庫')
    # SQLite's own bookkeeping table (`sqlite_sequence`) gets a row when the first API key of a table is written: it is no data
    expected_counts = dict(verified['original.sqlite'].get('counts') or {})
    fresh_keys = (verified['live.sqlite'].get('values') or {}).get('headscale.api_key_prefixes')
    expected_counts['api_keys'] = len(live_keys)
    if plan.copy_policies:
        expected_counts['policies'] = ha_odoo._int(((verified['live.sqlite'].get('counts')) or {}).get('policies'))
    sqlite_bookkeeping = {'sqlite_sequence'} | SQLITE_STATS
    data_counts = lambda counts: {k: v for k, v in (counts or {}).items() if k not in sqlite_bookkeeping}   # noqa: E731
    schema = verified['ha.sqlite'].get('schema') or {}
    known_tables = TABLES | SQLITE_STATS | frozenset((((live_answer or {}).get('schema') or {}).get('tables') or ()))
    if (any(hasqlite.problem(verified[name]) for name in ('ha.sqlite', 'original.sqlite', 'live.sqlite'))
            or fresh_keys != live_keys or data_counts(verified['ha.sqlite'].get('counts')) != data_counts(expected_counts)
            or set(schema.get('tables') or []) - known_tables or schema.get('virtual') or schema.get('triggers') or schema.get('views')
            or (verified['ha.sqlite'].get('values') or {}).get('headscale.api_key_prefixes') != fresh_keys):
        raise haissues.stopped(Issue('headscale.verify-failed', 'stop', '轉換後的 Headscale 資料庫驗證沒有通過，已停止；這台沒有任何變更。',
                                     action='請再試一次；仍然不行時，請把作業紀錄交給工程人員。'), 'job-failed', app=app.id)
    work.log(f'Headscale：HA 的 {details["api_keys"]} 把 API 金鑰換成這台的 {len(live_keys)} 把')

    root = ha_n8n.volume_root(work, app, target.data_volume)
    uid, gid, _mode = root
    data_path = out_dir / 'volumes' / f'{target.data_volume}.tar'
    out = hacommon.FileTar(data_path, work.guard)
    try:
        hacommon.top_only(out, root)
        db_rel, key_rel = data_paths(config)
        rel = records_rel(config)
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
        key = ((src.noise or live_noise or '') + '\n').encode('ascii') if (src.noise or live_noise) else None
        if key is not None:   # no key at all (HA's cannot be used, this device has none): Headscale makes a new one
            out.add_member(hacommon.info(key_rel, 'file', mode=0o600, uid=uid, gid=gid, mtime=time.time(),
                                         size=len(key)), _Bytes(key))
        if rel is not None and not plan.skip_records:
            records = src.records if src.records is not None else b'[]'
            out.add_member(hacommon.info(rel, 'file', mode=0o644, uid=uid, gid=gid, mtime=time.time(),
                                         size=len(records)), _Bytes(records))
    finally:
        out.close()
    os.unlink(db_file)
    config_dirs, config_pack = {}, None
    if target.config_dir is not None:
        config_pack = live_config_dir(work, app, target, out_dir, ids, config, plan.edits)
        config_dirs = {target.config_dir: config_pack}
    configtest(work, tmp, target, data_path, config_pack if plan.edits else None)
    volumes = {target.data_volume: data_path}
    paths = [data_path]
    if target.headplane_volume is not None:
        headplane_path = out_dir / 'volumes' / f'{target.headplane_volume}.tar'
        hacommon.live_export(work, app, target.headplane_volume, headplane_path)
        volumes[target.headplane_volume] = headplane_path
        paths.append(headplane_path)
    for path in paths:
        ha_odoo.check_volume_tar(path, ids)
    dirs_out = dict(config_dirs)
    if target.extra_volumes or target.extra_dirs:   # HS-04: this device's own other data goes along as it is
        report = habackup.Report(names=haissues.Names)
        carried = hatarget.carry(work, app, out_dir, ids, volumes=target.extra_volumes, dirs=target.extra_dirs, report=report,
                                 size=hatarget.size_hint(work.ha))
        volumes.update(carried['volumes'])
        dirs_out.update(carried['dirs'])
        sink.skipped(report)   # X-NS-08: a link of this device's own data the restore would refuse is left out and listed
    result = {'volumes': volumes, 'users': details['users'], 'nodes': details['nodes'], 'api_keys_removed': details['api_keys'],
              'api_keys_kept': len(live_keys), 'server_url': config.get('server_url', ''),
              'ha_server_url': src.config.get('server_url', ''), 'dns_records': 0 if plan.skip_records else src.records_count,
              'prefixes_replaced': {key: text for key, text in plan.edits.items()}, 'policy': plan.policy,
              'noise_kept': plan.keep_noise}
    if dirs_out:
        result['dirs'] = dirs_out
    return result


def edit_prefixes(text, edits):
    """`text` (a config.yaml) with the values of `prefixes.v4` / `prefixes.v6` set to `edits` ({key: text}): only the value is
    changed, quoting and a trailing comment stay. ValueError unless every key is found exactly once under a top-level
    `prefixes:` and the result reads back (hacommon.scalars) as the old text with those values and nothing else changed."""
    out, done, inside = [], set(), False
    for raw in text.splitlines(keepends=True):
        body = raw.rstrip('\r\n')
        if body.strip() and not body.lstrip().startswith('#'):
            indent = len(body) - len(body.lstrip(' '))
            if indent == 0:
                inside = re.fullmatch(r'prefixes:[ \t]*(?:#.*)?', body) is not None
                out.append(raw)
                continue
            match = re.fullmatch(r'([ \t]+)(v4|v6)(:[ \t]*)(["\']?)([^"\'#\s]*)\4([ \t]*(?:#.*)?)', body) if inside else None
            if match and f'prefixes.{match.group(2)}' in edits:
                key = f'prefixes.{match.group(2)}'
                if key in done:
                    raise ValueError('a prefix is set twice')
                done.add(key)
                out.append(f'{match.group(1)}{match.group(2)}{match.group(3)}{match.group(4)}{edits[key]}{match.group(4)}'
                           f'{match.group(6)}{raw[len(body):]}')
                continue
        out.append(raw)
    result = ''.join(out)
    if done != set(edits) or hacommon.scalars(result, max_bytes=MAX_SMALL) != {**hacommon.scalars(text, max_bytes=MAX_SMALL), **edits}:
        raise ValueError('the prefixes cannot be written')
    return result


def _replace_member(path, name, data):
    """The folder pack at `path` with its regular member `name` replaced by `data` (the same owner, mode and time)."""
    new = path.with_name(path.name + '.new')
    found = False
    with open(new, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        with ha_odoo._live_tar(path, '這台的 Headscale 設定資料夾') as old, tarfile.open(fileobj=handle, mode='w', format=tarfile.PAX_FORMAT) as dst:
            for member in old:
                if ha_odoo._norm(member.name) == name and member.isfile():
                    info = copy.copy(member)
                    info.size = len(data)
                    dst.addfile(info, io.BytesIO(data))
                    found = True
                else:
                    dst.addfile(member, old.extractfile(member) if member.isfile() else None)
                old.members.clear()
        handle.flush()
        os.fsync(handle.fileno())
    if not found:
        os.unlink(new)
        raise ValueError(f'{name} is not in the pack')
    os.replace(new, path)


def live_config_dir(work, app, target, out_dir, ids, config, edits=None):
    """This device's configuration folder as it is (nothing of HA's goes into it but HA's IP ranges, HS-22), packed while
    Headscale runs and checked like every host folder; its config.yaml must still say what the conversion was made with
    (read again, up to three times, when it changed meanwhile: HS-36)."""
    (out_dir / 'dirs').mkdir(mode=0o700, parents=True, exist_ok=True)
    path = out_dir / 'dirs' / '0.tar'
    for attempt in range(1, LIVE_TRIES + 1):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        with open(path, 'xb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            work.runner(app).dir_pack(target.config_dir, stdout=handle, timeout=3600, max_output=work.guard.budget(),
                                      abort=work.abort)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            nested.check_dir(path, ids=ids)
        except BackupError as error:
            raise haissues.stopped(Issue('headscale.config-folder-unusable', 'stop',
                                         f'這台的 Headscale 設定資料夾無法還原（{haissues.clean(error.message, 120)}）。',
                                         action='請先清理這台 Headscale 設定資料夾裡的特殊檔案或擁有者設定，再匯入。'),
                                   'job-failed', app=app.id, reason=(error.details or {}).get('reason')) from None
        text = None
        with ha_odoo._live_tar(path, '這台的 Headscale 設定資料夾') as tar:
            for member in tar:
                if ha_odoo._norm(member.name) == 'config.yaml' and member.isfile() and member.size <= MAX_SMALL:
                    text = tar.extractfile(member).read().decode('utf-8', 'replace')
                tar.members.clear()
        if text is not None and hacommon.scalars(text, max_bytes=MAX_SMALL) == config:
            break
        if attempt == LIVE_TRIES:
            raise haissues.stopped(Issue('headscale.config-changed', 'stop',
                                         '這台 Headscale 的設定檔在轉換期間一直在變，已試了多次，停止；這台沒有任何變更。',
                                         action='請等設定穩定後再試一次。'), 'job-failed', app=app.id)
        work.log('這台 Headscale 的設定檔在轉換期間改變了，改用最新的設定重做一次。')
        config = _reread_config(work, app, target, config)
    if edits:
        try:
            _replace_member(path, 'config.yaml', edit_prefixes(text, edits).encode('utf-8'))
            nested.check_dir(path, ids=ids)
        except (ValueError, BackupError) as error:
            os.unlink(path)
            raise haissues.stopped(Issue('headscale.config-edit-failed', 'stop',
                                         '無法把 HA 的 IP 位址範圍寫進這台 Headscale 的設定檔（config.yaml 的 prefixes 寫法不是這個備份元件看得懂的形式）。',
                                         action='請手動把這台設定檔裡的 prefixes 改成和 HA 相同後，再匯入；或請工程人員協助。'),
                                   'incompatible', app=app.id) from None
        work.log('已把 HA 的 IP 位址範圍寫進這台 Headscale 設定檔的副本（匯入時才會放回去）。')
    return path


def _reread_config(work, app, target, old):
    """This device's configuration again (HS-36): what the conversion goes on with when it changed meanwhile; its database, key and
    DNS records paths must still be the ones the volume was built for."""
    config = live_config(work, app, target)
    if (data_paths(config), records_rel(config)) != (data_paths(old), records_rel(old)):
        raise haissues.stopped(Issue('headscale.config-changed', 'stop',
                                     '這台 Headscale 設定檔裡的資料庫、身分金鑰或 DNS 記錄的路徑在轉換期間改變了，已停止；這台沒有任何變更。',
                                     action='請等設定穩定後再試一次。'), 'job-failed', app=app.id)
    return config


class _Bytes:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def read(self, n=-1):
        end = len(self.data) if n is None or n < 0 else self.pos + n
        chunk = self.data[self.pos:end]
        self.pos += len(chunk)
        return chunk


def configtest(work, tmp, target, data_path, config_pack=None):
    """`headscale configtest` of the live image on a throwaway copy of the converted volume (network none, the live
    configuration read-only -- or, when HA's prefixes were written into it, the converted copy of the configuration folder, in
    a throwaway volume): the database opens, its version path, migrations and schema are what this release accepts."""
    tmp.volume('hs-check')

    def produce_from(path):
        def produce(out):
            with open(path, 'rb') as handle:
                while True:
                    data = handle.read(habackup.CHUNK)
                    if not data:
                        break
                    out.write(data)
        return produce

    tmp.volume_import('hs-check', produce_from(data_path))
    config_mount = target.config_mount
    if config_pack is not None:
        tmp.volume('hs-config')
        tmp.volume_import('hs-config', produce_from(config_pack))
        config_mount = (tmp.name('hs-config'), CONFIG_TARGET, 'ro')
    try:
        tmp.run('hs-configtest', target.image, ['configtest'], volumes=[(tmp.name('hs-check'), DATA_TARGET, None), config_mount],
                read_only_root=True, timeout=300, max_output=1024 * 1024)
    except BackupError as error:
        if error.code != 'job-failed':
            raise
        raise haissues.stopped(Issue('headscale.configtest-failed', 'stop',
                                     '這台的 Headscale 無法開啟轉換後的資料庫（headscale configtest 沒有通過），已停止；這台沒有任何變更。',
                                     action='請確認 HA 與這台的 Headscale 版本相近（較新的資料庫舊版打不開）；仍然不行時，請把作業紀錄交給工程人員。'),
                               'job-failed') from None
    tmp.remove_volume('hs-check')
    if config_pack is not None:
        tmp.remove_volume('hs-config')
    work.log('這台的 Headscale 已確認可以開啟轉換後的資料庫（configtest）')


# ====================================================================== texts

def import_texts(data):
    notes = ['Headscale 的使用者、裝置、預先授權金鑰與 DNS 額外記錄會換成 HA 的，HA 的伺服器身分金鑰（noise）也一起搬過來；'
             '這台的伺服器網址與 API 金鑰保持不變。']
    if data.get('prefixes_replaced'):
        notes.append('這台 Headscale 的 IP 位址範圍會改成 HA 的（設定檔 config.yaml 的 prefixes 一起換）。')
    else:
        notes.append('這台的 IP 位址範圍保持不變。')
    if data.get('policy') == 'replaced':
        notes.append('資料庫存取政策會換成 HA 的政策。')
    elif data.get('policy') == 'kept':
        notes.append('HA 沒有存取政策，這台現有的存取政策保留；它寫的使用者和群組如果 HA 沒有，規則不會生效，請匯入後檢查。')
    if data.get('noise_kept'):
        notes.append('HA 的伺服器身分金鑰不能用，沿用這台的身分金鑰，所有裝置都要重新登入。')
    if data.get('api_keys_removed'):
        notes.append(f'HA 的 {data["api_keys_removed"]} 把 Headscale API 金鑰不會搬過來，這台的 {data.get("api_keys_kept", 0)} 把'
                     '（Headplane、MCP 管理）保持有效。')
    url = data.get('server_url') or '這台的 Headscale 網址'
    old = data.get('ha_server_url')
    reminders = [f'請把每一台裝置的登入伺服器改成 {url}（例如 tailscale up --login-server={url}）'
                 + (f'，不再使用 HA 的 {old}' if old else '') + '。',
                 '請把 HA 的 Headscale 附加元件永久停用（關掉開機自動啟動）：兩台伺服器使用同一個身分金鑰卻有不同的資料，會讓裝置連線錯亂。']
    return notes, reminders
