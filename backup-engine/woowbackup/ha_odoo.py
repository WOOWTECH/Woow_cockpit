"""Home Assistant import, Odoo part: the WOOWTECH add-on `odoo18ce` -> this device's app `odoo` (CONTRACT section 9
"Home Assistant import"; design notes of branch feat/ha-import, section 3). Owner: E2.

The add-on keeps a whole PostgreSQL 16 cluster (`data/postgres`, initdb --locale=C), the filestore of every database
(`data/odoo/filestore/<db>`) and runtime/custom modules (`data/addons/<module>`, `data/odoo/addons/18.0/<module>`;
custom modules may also be in HA's share folder, `share.tar[.gz]` -> `odoo_addons/<module>`, when the backup holds it).
The target is a tenant Odoo 18 on PostgreSQL 17 in cold mode: the catalog backs up the whole cluster volume
(`odoo18-db-data-isolated`), the data dir volume (`odoo18-web-data`) and the custom modules folder
(`.local/share/odoo18/addons`).

check: the cluster is streamed into a throwaway volume and opened by a throwaway PostgreSQL 16 (socket only, network
none, `local all all trust`); per database (connectable, not a template, not `postgres`) the installed modules and
counts are read; the target's modules come from Odoo itself, run in a throwaway container of the live Odoo image with
the live configuration secret and the live module folders mounted read-only. A database can move when every installed
module exists on the target -- or as a custom module in the backup -- with the identical version, nothing is pending,
the extensions are among plpgsql, pg_trgm, unaccent and vector, the custom modules' Python packages and programs exist
in the target image and HA's PostgreSQL is not newer.

convert (one chosen database): pg_dump in the PostgreSQL 16 container; a NEW PostgreSQL 17 cluster from the live
odoo-db image, environment and secret mount (so its superuser password is the live one), role odoo with the LIVE
role's password verifier (read from the live cluster, passed on stdin, never in argv or logs), database `odoo`
(template0, UTF8, collation C), pg_trgm + vector (+ unaccent), the dump restored without its EXTENSION entries exactly
like Woow_podman_odoo's restore-online.sh (`--role=odoo --no-owner --no-acl --exit-on-error --single-transaction`);
then `web.base.url` (and its freeze flag) as the target has it, the target's upgrade-gate marker copied and the
attempt marker deleted (never HA's core date); test mode neutralises the database with `odoo neutralize` (throwaway
Odoo on an internal network with the database) and gives it a new database.uuid; the modules are verified again
(installed, versions equal); PostgreSQL settings set on the live cluster that differ are carried over; the cluster is
stopped cleanly and exported. The data dir volume is the live export without `filestore/odoo/**` and `sessions/**`,
plus HA's filestore of that database as `filestore/odoo/**` (the container's odoo uid/gid, dirs 0700, files 0600) and
an empty `sessions/`. The custom modules folder is the live folder plus the custom modules the target lacks (or holds
in another version only there), owned by the app owner, o+rX.
"""
import ast
import hashlib
import io
import json
import os
import re
import secrets
import tarfile
import time

from . import habackup, haissues, hatarget, nested, podman, tempctr, util
from .errors import BackupError
from .haissues import Issue

SLUG = 'odoo18ce'
APP_ID = 'odoo'
PG_PREFIX = 'data/postgres'
FILESTORE_PREFIX = 'data/odoo/filestore'
MODULE_SOURCES = ('data/addons', 'data/odoo/addons/18.0')
SHARE_MODULES = 'odoo_addons'
EXTENSIONS_OK = ('plpgsql', 'pg_trgm', 'unaccent', 'vector')
EXTENSIONS_CREATED = ('pg_trgm', 'vector')  # what the tenant install creates (odoo-helpers.sh)
# pgvector first: it opens every PostgreSQL 16 cluster and also reads vector columns (review C-13).
PG16_IMAGES = ('docker.io/pgvector/pgvector:0.8.6-pg16', 'docker.io/library/postgres:16.15-alpine')
SERIES = '18.0'
DB_NAME_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}\Z')
PG_ROLE_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,62}\Z')   # a role name pg_ident quotes without a doubt
EXT_NAME_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_$-]{0,62}\Z')   # an extension name (uuid-ossp has a dash)
MODULE_RE = re.compile(r'[A-Za-z0-9_]{1,128}\Z')
PY_DEP_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}(?:\[[A-Za-z0-9,._-]{1,100}\])?'
                       r'(?:\s*(?:===|==|!=|~=|>=|<=|>|<)\s*[A-Za-z0-9.*+!_-]{1,40}'
                       r'(?:\s*,\s*(?:===|==|!=|~=|>=|<=|>|<)\s*[A-Za-z0-9.*+!_-]{1,40}){0,4})?\Z')
BIN_DEP_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,99}\Z')
VERIFIER_RE = re.compile(r'(?:SCRAM-SHA-256\$[0-9]{1,7}:[A-Za-z0-9+/=]{1,200}\$[A-Za-z0-9+/=]{1,200}:'
                         r'[A-Za-z0-9+/=]{1,200}|md5[0-9a-f]{32})\Z')
DIGEST_RE = re.compile(r'sha256:[0-9a-f]{64}\Z')
MAX_MANIFEST = 256 * 1024
MAX_MODULE_ROWS = 20000
ELF_HEAD = 20         # bytes of an ELF header up to and including e_machine
EM_X86_64, EM_AARCH64 = 0x3E, 0xB7
ELF_MACHINES = {'x86_64': EM_X86_64, 'amd64': EM_X86_64, 'aarch64': EM_AARCH64, 'arm64': EM_AARCH64}
MAX_SMALL_FILE = 64 * 1024
PG_READY_TIMEOUT = 300
DUMP_TIMEOUT = 3 * 3600
SQL_OUTPUT = 16 * 1024 * 1024
SCAN_OUTPUT = 8 * 1024 * 1024    # the module listing of this device's Odoo
TOC_OUTPUT = 128 * 1024 * 1024
WAL_ALLOWANCE = 1024 * 1024 * 1024  # the new cluster's WAL while the dump is restored (max_wal_size)
PG_HBA = b'# woowbk: throwaway copy, unix socket only\nlocal all all trust\n'
# HA's cluster is untrusted (review HA-SEC-01): its configuration and recovery files never reach the throwaway server.
# The configuration files are replaced by known ones, the recovery/standby files and the old server's pid files are
# dropped, and start_ha_cluster overrides every setting that loads a library or runs a command.
PG_CONF = (b"# woowbk: throwaway copy of a Home Assistant cluster; HA's own settings are not used\n"
           b"listen_addresses = ''\nmax_connections = 20\nshared_buffers = 128MB\ndynamic_shared_memory_type = posix\n"
           b"unix_socket_directories = '/var/run/postgresql'\ntimezone = 'UTC'\nlog_timezone = 'UTC'\n"
           b"datestyle = 'iso, mdy'\nlc_messages = 'C'\ndefault_text_search_config = 'pg_catalog.english'\n")
REPLACED_PG_FILES = {'pg_hba.conf': PG_HBA, 'postgresql.conf': PG_CONF,
                     'postgresql.auto.conf': b'# woowbk: HA settings are not used\n', 'pg_ident.conf': b''}
SKIPPED_PG_FILES = ('postmaster.pid', 'postmaster.opts', 'recovery.signal', 'standby.signal', 'recovery.conf',
                    'recovery.done')
HA_DATA = '/var/lib/postgresql/data'
# Command-line settings win over every configuration FILE of HA's cluster (they do not win over its own per-role and
# per-database settings in pg_db_role_setting, and its catalog can make the server run code as the superuser: security
# review 2026-11-23 SR-2). The boundary is the container: no network, read-only root, noexec data volume, limits.
HA_SERVER_SETTINGS = ('listen_addresses=', 'max_connections=20', 'shared_preload_libraries=',
                      'session_preload_libraries=', 'local_preload_libraries=', 'dynamic_library_path=$libdir',
                      'archive_mode=off', 'archive_command=', 'archive_library=', 'restore_command=',
                      'archive_cleanup_command=', 'recovery_end_command=', 'primary_conninfo=', 'primary_slot_name=',
                      'ssl=off', 'jit=off', 'logging_collector=off', f'hba_file={HA_DATA}/pg_hba.conf',
                      f'ident_file={HA_DATA}/pg_ident.conf', 'unix_socket_directories=/var/run/postgresql')
# Objects only a database superuser can create: an HA dump holding one is refused (it is restored as the role odoo).
SUPERUSER_KINDS = ('EVENT TRIGGER', 'FOREIGN DATA WRAPPER', 'SERVER', 'USER MAPPING', 'SUBSCRIPTION', 'PUBLICATION',
                   'ACCESS METHOD', 'TEXT SEARCH PARSER', 'TEXT SEARCH TEMPLATE', 'PROCEDURAL LANGUAGE', 'CAST',
                   'TRANSFORM', 'OPERATOR CLASS', 'OPERATOR FAMILY', 'FOREIGN TABLE')
SETTINGS_SKIPPED = frozenset({'config_file', 'data_directory', 'hba_file', 'ident_file', 'external_pid_file',
                              'unix_socket_directories', 'listen_addresses', 'port', 'ssl_cert_file', 'ssl_key_file',
                              'ssl_ca_file', 'ssl_crl_file', 'ssl_crl_dir', 'ssl_passphrase_command',
                              'archive_command', 'restore_command', 'archive_cleanup_command', 'recovery_end_command',
                              'primary_conninfo', 'lc_messages', 'lc_monetary', 'lc_numeric', 'lc_time',
                              'shared_preload_libraries', 'data_checksums', 'server_encoding', 'block_size',
                              'wal_block_size', 'segment_size', 'wal_segment_size', 'max_function_args',
                              'max_identifier_length', 'max_index_keys', 'integer_datetimes', 'server_version',
                              'server_version_num', 'debug_assertions', 'ssl_library', 'in_hot_standby'})
SETTING_NAME_RE = re.compile(r'[a-z_][a-z0-9_.]{0,62}\Z')
SETTING_VALUE_RE = re.compile(r'[^\x00-\x1f\x7f\']{0,1024}\Z')
# Settings whose value is a list of quoted names (GUC_LIST_QUOTE): ALTER SYSTEM takes them as one literal per element,
# a single literal of the whole text would become ONE quoted name (review C-06).
LIST_SETTINGS = frozenset({'search_path', 'temp_tablespaces', 'session_preload_libraries', 'local_preload_libraries'})

MSG_NOT_ODOO = '這不是 Odoo 資料庫。'
MSG_HINT_SHARE = '如果模組放在 HA 的 /share/odoo_addons，做 HA 備份時要把 share 資料夾也勾進去。'
MSG_MODULES_UNREADABLE = '無法讀取 HA 資料庫的模組清單。'
MSG_CONTENT_UNREADABLE = '無法讀取 HA 資料庫的內容。'
CONF_PATH = '/etc/odoo/odoo.conf'
DEFAULT_DB_NAME = 'odoo'     # the tenant's database and role when its configuration names none
DEFAULT_DB_ROLE = 'odoo'
MAX_NAME_BYTES = 63          # PostgreSQL's NAMEDATALEN - 1
BAD_NAME_RE = re.compile(r'[\x00-\x1f\x7f-\x9f]')
# The role of the tenant install (package smoke: `CREATE ROLE odoo LOGIN NOSUPERUSER CREATEDB NOCREATEROLE`); what a role
# that has to be made again (OD-20, OD-21) or normalised (OD-22) gets.
STANDARD_ROLE = {'login': True, 'createdb': True, 'createrole': False, 'replication': False, 'bypassrls': False,
                 'connlimit': -1}
# What the customer is told (zh-TW, plain; names go into the issue's items, never a value).
MSG_MISSING_MODULES = ('這台的 Odoo 缺少 HA 資料庫已安裝的模組，用到它們的畫面、排程和報表會出錯，資料還在資料庫裡；'
                       '匯入後這台之後更新 Odoo 時，套件的升級檢查（upgrade-gate.sh）也會因此被擋下來（結束碼 4），要先補上這些模組。')
MSG_LEFT_DATABASES = ('這次只搬資料庫「{database}」；HA 的其他資料庫不會搬，會留在 HA（HA 停用後就看不到了）。'
                      '這台 Odoo 一次只放一個資料庫，以後再匯入另一個會取代這次的。')

ISSUES = {
    'odoo.layout-unsupported': 'stop',       # OD-12, OD-13: the layout of this device's Odoo is not one the import knows
    'odoo.extras-carried': 'auto',           # OD-12, OD-13: this device's own other volumes and folders go along as they are
    'odoo.addons-folder-undeclared': 'notice',  # OD-72: the modules folder is mounted but not in the app settings
    'odoo.mount-skipped': 'notice',          # OD-08, OD-09: a mount that is no data (a time zone file, another path) is left out
    'odoo.marker-written': 'auto',           # OD-18: the upgrade marker of this device's Odoo was missing or not its image's
    'odoo.marker-unwritable': 'stop',        # OD-18: ... and the image says no release date to write it with
    'odoo.settings-unreadable': 'notice',    # OD-16, OD-17: this device's address and marker could not be read
    'odoo.base-url-invalid': 'notice',       # OD-19
    'odoo.role-created': 'auto',             # OD-20: the database role of this device's Odoo was made from its configuration
    'odoo.role-password-reset': 'auto',      # OD-21: its password was set again from its configuration
    'odoo.role-normalised': 'auto',          # OD-22: the role was a superuser; the new one is an ordinary role
    'odoo.role-unusable': 'stop',            # OD-20, OD-21: ... and the configuration has no password to make it with
    'odoo.no-database': 'stop',              # OD-47
    'odoo.no-movable-database': 'stop',      # OD-48
    'odoo.not-odoo': 'stop',                 # OD-32 (database)
    'odoo.db-unreadable': 'stop',            # OD-33, OD-34 (database)
    'odoo.database-name': 'stop',            # a name that cannot be handed to the database tools (database)
    'odoo.target-modules-partial': 'notice',  # OD-35
    'odoo.modules-pending': 'notice',        # OD-36, OD-61 (database)
    'odoo.modules-missing': 'confirm',       # OD-37 (database)
    'odoo.module-version-different': 'stop',  # (database)
    'odoo.modules-skipped-deps': 'confirm',  # OD-44 (database)
    'odoo.dependency-unreadable': 'notice',  # OD-44 (database)
    'odoo.module-not-installable': 'notice',  # OD-43 (database)
    'odoo.program-missing': 'notice',        # OD-45 (database)
    'odoo.module-foreign-native': 'notice',  # OD-46 (database)
    'odoo.extension-unsupported': 'stop',    # OD-39 (database)
    'odoo.vector-image-missing': 'stop',     # OD-40 (database)
    'odoo.superuser-objects': 'confirm',     # OD-41, OD-58 (database)
    'odoo.superuser-skipped': 'notice',      # OD-58: what the dump's list had of them, left out of the restore
    'odoo.restore-failed': 'stop',           # OD-58: the rest did not fit into the new cluster either
    'odoo.pg-newer': 'stop',                 # (database)
    'odoo.mail-servers-active': 'notice',    # (database)
    'odoo.crons-active': 'notice',           # (database)
    'odoo.website-domains': 'notice',        # (database)
    'odoo.filestore-missing': 'notice',      # (database)
    'odoo.databases-left': 'confirm',        # UI-20, S6 (database)
    'odoo.url-differs': 'notice',            # OD-66
    'odoo.website-domain-kept': 'notice',    # OD-67
    'odoo.settings-not-carried': 'notice',   # OD-69
}


# ====================================================================== versions and manifests

def adapt_version(version):
    """Odoo's adapt_version: a module version without the series gets it ("1.3" -> "18.0.1.3")."""
    version = str(version)
    if version == SERIES or not version.startswith(SERIES + '.'):
        version = f'{SERIES}.{version}'
    return version


def version_key(value):
    """verify-modules.py's comparison key: 2-5 numeric parts padded to 5, None when it is not such a version."""
    parts = str(value or '').split('.')
    if not 2 <= len(parts) <= 5 or not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts + ['0'] * (5 - len(parts)))


def same_version(a, b):
    ka, kb = version_key(a), version_key(b)
    return ka is not None and ka == kb


def parse_manifest(data):
    """{version (adapted), installable, python[], bin[]} of a `__manifest__.py` (a dict literal, read with
    ast.literal_eval, never executed); None when it is not one."""
    if len(data) > MAX_MANIFEST:
        return None
    try:
        doc = ast.literal_eval(data.decode('utf-8'))
    except (ValueError, SyntaxError, UnicodeDecodeError, MemoryError, RecursionError, TypeError):
        return None
    if not isinstance(doc, dict):
        return None
    version = doc.get('version', '1.0')
    if not isinstance(version, (str, int, float)):
        return None
    external = doc.get('external_dependencies') if isinstance(doc.get('external_dependencies'), dict) else {}
    python = [d for d in external.get('python', []) or [] if isinstance(d, str)][:50]
    binaries = [d for d in external.get('bin', []) or [] if isinstance(d, str)][:50]
    return {'version': adapt_version(version), 'installable': doc.get('installable', True) is not False,
            'python': python, 'bin': binaries}


# ====================================================================== the add-on member

class _Exact:
    """read(n) that returns exactly n bytes until the end (tarfile's copy needs whole reads)."""

    def __init__(self, entry, guard=None):
        self.entry, self.guard = entry, guard

    def read(self, n=-1):
        parts, have = [], 0
        while n < 0 or have < n:
            data = self.entry.read(habackup.CHUNK if n < 0 else min(n - have, habackup.CHUNK))
            if not data:
                break
            parts.append(data)
            have += len(data)
        if self.guard is not None:
            self.guard.wrote(have)
        return b''.join(parts)


def _info(name, kind, *, mode, uid, gid, mtime, size=0, linkname=None):
    info = tarfile.TarInfo(name)
    info.type = {'file': tarfile.REGTYPE, 'dir': tarfile.DIRTYPE, 'symlink': tarfile.SYMTYPE}[kind]
    info.mode, info.uid, info.gid = mode, uid, gid
    info.uname = info.gname = ''
    info.mtime = int(mtime) if isinstance(mtime, (int, float)) and mtime >= 0 else int(time.time())
    info.size = size if kind == 'file' else 0
    if linkname is not None:
        info.linkname = linkname
    return info


def _under(name, prefix):
    return name == prefix or name.startswith(prefix + '/')


class Source:
    """What one pass over the Odoo add-on's inner tar learned: `addon` (AddonInfo), `pg_version` (PG_VERSION, e.g.
    "16"), `pg_files`/`pg_bytes`, `filestore` {db: [files, bytes]}, `modules` {name: {version, installable, python,
    bin, from, files, bytes}} (custom module candidates: data/addons first, then the data dir's, then share's),
    `tablespaces` (symlinks below pg_tblspc: refused)."""

    def __init__(self):
        self.addon = None
        self.pg_version = None
        self.pg_files = self.pg_bytes = 0
        self.filestore = {}
        self.modules = {}
        self.module_bytes = 0
        self.warnings = []


class PgSink:
    """The HA cluster as a tar for `podman volume import` (names relative to the data dir, the helper image's
    postgres uid/gid, dirs 0700, files 0600). HA's configuration files are replaced by known ones (REPLACED_PG_FILES:
    socket-only trust, no library, no command), its recovery/standby and pid files dropped (review HA-SEC-01)."""

    def __init__(self, out, uid, gid, guard=None):
        self.tar = tarfile.open(fileobj=out, mode='w|', format=tarfile.PAX_FORMAT, encoding=habackup.ENCODING,
                                errors=habackup.ERRORS)
        self.uid, self.gid, self.guard = uid, gid, guard
        self.root_written = False
        self.replaced = set()

    def _file(self, rel, data, mtime):
        self.tar.addfile(_info(rel, 'file', mode=0o600, uid=self.uid, gid=self.gid, mtime=mtime, size=len(data)),
                         io.BytesIO(data))

    def add(self, rel, entry, data=None):
        top = rel.split('/', 1)[0]
        if top in SKIPPED_PG_FILES:
            return
        if top in REPLACED_PG_FILES:  # whatever HA has there (a file, a folder): the known file, once
            if top not in self.replaced:
                self.replaced.add(top)
                self._file(top, REPLACED_PG_FILES[top], entry.mtime)
            return
        if rel == '.':
            self.root_written = True
        if entry.kind == 'dir':
            self.tar.addfile(_info(rel, 'dir', mode=0o700, uid=self.uid, gid=self.gid, mtime=entry.mtime))
        elif entry.kind == 'file':
            if data is not None:
                self._file(rel, data, entry.mtime)
            else:
                self.tar.addfile(_info(rel, 'file', mode=0o600, uid=self.uid, gid=self.gid, mtime=entry.mtime,
                                       size=entry.size), _Exact(entry, self.guard))

    def close(self):
        if not self.root_written:
            self.tar.addfile(_info('.', 'dir', mode=0o700, uid=self.uid, gid=self.gid, mtime=time.time()))
        for name in sorted(set(REPLACED_PG_FILES) - self.replaced):
            self._file(name, REPLACED_PG_FILES[name], time.time())
        self.tar.close()


class FileTar:
    """A tar written into a staging file (PAX), with the space guard counting what it writes."""

    def __init__(self, path, guard=None):
        self.path = path
        self.handle = open(path, 'xb')  # noqa: SIM115 - closed in close()
        os.fchmod(self.handle.fileno(), 0o600)
        self.tar = tarfile.open(fileobj=self.handle, mode='w|', format=tarfile.PAX_FORMAT,
                                encoding=habackup.ENCODING, errors=habackup.ERRORS)
        self.guard = guard
        self.names = set()

    def add_entry(self, name, entry, *, mode, uid, gid):
        if name in self.names:
            raise BackupError('corrupt-archive', 'HA 備份中有重複的項目。', member=name[:200])
        self.names.add(name)
        if entry.kind == 'dir':
            self.tar.addfile(_info(name, 'dir', mode=mode, uid=uid, gid=gid, mtime=entry.mtime))
        else:
            self.tar.addfile(_info(name, 'file', mode=mode, uid=uid, gid=gid, mtime=entry.mtime, size=entry.size),
                             _Exact(entry, self.guard))

    def add_member(self, info, fileobj=None):
        if info.name in self.names:
            raise BackupError('internal-error', '暫存的資料夾封存有重複的項目。')
        self.names.add(info.name)
        self.tar.addfile(info, fileobj)
        if self.guard is not None and info.isfile():
            self.guard.wrote(info.size)

    def close(self):
        try:
            self.tar.close()
            self.handle.flush()
            os.fsync(self.handle.fileno())
        finally:
            self.handle.close()


def host_elf_machine():
    """ELF e_machine of this device's processor (x86-64 0x3E, aarch64 0xB7), None when unknown."""
    return ELF_MACHINES.get(os.uname().machine.lower())


def foreign_native(head):
    """True when `head` (a file's first bytes) starts a Linux program or library for a processor other than this
    device's (a device of an unknown processor counts as x86-64)."""
    if len(head) < ELF_HEAD or head[:4] != b'\x7fELF':
        return False
    machine = host_elf_machine() or EM_X86_64
    return head[4:6] != b'\x02\x01' or int.from_bytes(head[18:20], 'little') != machine


def _note_native(info, tail, entry):
    if foreign_native(entry.peek(ELF_HEAD)):
        info['foreign'] = [*info.get('foreign', []), tail][:5]


def _module_of(name):
    """(source label, module name, rest) of a custom module candidate entry, else None."""
    for prefix in MODULE_SOURCES:
        if name.startswith(prefix + '/'):
            rest = name[len(prefix) + 1:]
            module, _, tail = rest.partition('/')
            return prefix, module, tail
    return None


def scan_member(stream, report, *, pg=None, filestore_db=None, filestore=None, modules=None, guard=None,
                checkpoint=None):
    """One strict pass over the add-on's inner tar (habackup.iter_entries). `pg`: a PgSink fed with the cluster;
    `filestore`: a FileTar receiving `filestore_db`'s filestore as `filestore/odoo/**` (owner ids and modes from the
    caller via `filestore.ids`); `modules`: a FileTar receiving every custom module candidate as
    `<source>/<module>/**` (original modes). Returns a Source."""
    select = habackup.Select(include=(PG_PREFIX, FILESTORE_PREFIX) + MODULE_SOURCES,
                             exclude=tuple(f'{prefix}/{name}' for prefix in MODULE_SOURCES
                                           for name in ('__pycache__',)), symlinks=(), hardlinks=False)
    src = Source()
    count = 0
    for entry in habackup.iter_entries(stream, select, report, checkpoint=checkpoint):
        count += 1
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
                    data = entry.read_all(MAX_SMALL_FILE)
                    src.pg_version = data.decode('ascii', 'replace').strip()[:16]
            if pg is not None:
                pg.add(rel, entry, data)
            continue
        if _under(name, FILESTORE_PREFIX):
            if name == FILESTORE_PREFIX:
                continue
            rest = name[len(FILESTORE_PREFIX) + 1:]
            db, _, tail = rest.partition('/')
            counts = src.filestore.setdefault(db, [0, 0])
            if entry.kind == 'file':
                counts[0] += 1
                counts[1] += entry.size
            if filestore is not None and db == filestore_db:
                target = 'filestore/odoo' + (f'/{tail}' if tail else '')
                uid, gid = filestore.ids
                filestore.add_entry(target, entry, mode=0o700 if entry.kind == 'dir' else 0o600, uid=uid, gid=gid)
            continue
        found = _module_of(name)
        if found is None:
            continue
        prefix, module, tail = found
        if not MODULE_RE.fullmatch(module) or '__pycache__' in tail.split('/'):
            continue
        info = src.modules.get(module)
        if info is not None and info['from'] != prefix:
            continue  # data/addons wins (first on HA's addons_path after core); the data dir copy is shadowed
        if info is None:
            info = src.modules[module] = {'from': prefix, 'manifest': None, 'files': 0, 'bytes': 0}
        if entry.kind == 'file':
            info['files'] += 1
            info['bytes'] += entry.size
            src.module_bytes += entry.size
            _note_native(info, tail, entry)
            if tail == '__manifest__.py':
                data = entry.read_all(MAX_MANIFEST)
                info['manifest'] = parse_manifest(data)
                if modules is not None:
                    modules.add_member(_info(f'{prefix}/{module}/{tail}', 'file', mode=entry.mode & 0o777, uid=0,
                                             gid=0, mtime=entry.mtime, size=len(data)), io.BytesIO(data))
                continue
        if modules is not None:
            modules.add_entry(f'{prefix}/{module}' + (f'/{tail}' if tail else ''), entry,
                              mode=entry.mode & 0o777, uid=0, gid=0)
    if report.skipped_symlinks:
        samples = [s for s in report.skipped_symlink_samples if _under(s, PG_PREFIX)]
        if samples:
            raise BackupError('incompatible', 'HA 的 Odoo 資料庫使用了另外的表空間（tablespace），目前無法搬過來。',
                              reason='tablespace symlink', member=samples[0])
    src.addon = report.addon
    return src


def scan_share(stream, report, *, modules=None, checkpoint=None):
    """Custom modules in HA's share folder (`odoo_addons/<module>/**` of share.tar[.gz]): {name: info} like
    Source.modules (`from` = share/odoo_addons); written to `modules` as `share/odoo_addons/<module>/**`."""
    select = habackup.Select(include=(SHARE_MODULES,), symlinks=(), hardlinks=False)
    found = {}
    count = 0
    for entry in habackup.iter_entries(stream, select, report, addon=False, checkpoint=checkpoint):
        count += 1
        if checkpoint is not None and count % 256 == 0:
            checkpoint()
        if entry.name == SHARE_MODULES:
            continue
        module, _, tail = entry.name[len(SHARE_MODULES) + 1:].partition('/')
        if not MODULE_RE.fullmatch(module) or '__pycache__' in tail.split('/'):
            continue
        info = found.setdefault(module, {'from': 'share/odoo_addons', 'manifest': None, 'files': 0, 'bytes': 0})
        target = f'share/odoo_addons/{module}' + (f'/{tail}' if tail else '')
        if entry.kind == 'file':
            info['files'] += 1
            info['bytes'] += entry.size
            _note_native(info, tail, entry)
            if tail == '__manifest__.py':
                data = entry.read_all(MAX_MANIFEST)
                info['manifest'] = parse_manifest(data)
                if modules is not None:
                    modules.add_member(_info(target, 'file', mode=entry.mode & 0o777, uid=0, gid=0,
                                             mtime=entry.mtime, size=len(data)), io.BytesIO(data))
                continue
        if modules is not None:
            modules.add_entry(target, entry, mode=entry.mode & 0o777, uid=0, gid=0)
    return found


# ====================================================================== the live target

def quadlet_volume_name(quadlets, ref):
    """A Quadlet `Volume=` source that names a `.volume` unit -> that volume's name (VolumeName=, else systemd-<stem>)."""
    text = quadlets.get(ref)
    if text is None:
        raise BackupError('incompatible', f'找不到 Quadlet 檔 {ref}。')
    if isinstance(text, bytes):
        text = text.decode('utf-8', 'replace')
    values = [v for k, v in tempctr.parse_unit(text).get('Volume', []) if k == 'VolumeName']
    name = values[-1] if values else f'systemd-{ref[:-len(".volume")]}'
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name):
        raise BackupError('incompatible', f'{ref} 的 VolumeName= 設定不受支援。')
    return name


def quadlet_mounts(quadlets, container_file, home, *, read_only=True, skipped=None):
    """The `Volume=` mounts of a `.container` file as (source, target, options): `.volume` units resolved to their
    volume names, `%h/` expanded to the owner's home; relabel options dropped and `ro` forced (a throwaway copy only
    reads them). A source that is a path outside the owner's home, a `%h/` path with `..` or another `%` specifier
    refuses the file (`incompatible`) -- the other importers rely on that -- unless `skipped` (a list) is given: the
    mount is then left out (it is never mounted into a throwaway container) and `(container file, target)` is added to
    `skipped` (OD-08, OD-09: a time zone file, a path of its own)."""
    text = quadlets[container_file]
    if isinstance(text, bytes):
        text = text.decode('utf-8', 'replace')
    mounts = []
    for key, value in tempctr.parse_unit(text).get('Container', []):
        if key != 'Volume':
            continue
        parts = value.split(':')
        if len(parts) < 2:
            continue
        source, target = parts[0], parts[1]
        if source.endswith('.volume'):
            source = quadlet_volume_name(quadlets, source)
        elif source.startswith('%h/'):
            source = home.rstrip('/') + '/' + source[3:]
            if '..' in source.split('/'):
                if skipped is None:
                    raise BackupError('incompatible', f'{container_file} 的 Volume= 設定不受支援。')
                skipped.append((container_file, target))
                continue
        elif source.startswith('/') or '%' in source:
            if skipped is None:
                raise BackupError('incompatible', f'{container_file} 的 Volume= 設定不受支援：{value[:80]}')
            skipped.append((container_file, target))
            continue
        mounts.append((source, target, 'ro' if read_only else None))
    return mounts


def quadlet_container_name(quadlets, container_file):
    text = quadlets[container_file]
    if isinstance(text, bytes):
        text = text.decode('utf-8', 'replace')
    values = [v for k, v in tempctr.parse_unit(text).get('Container', []) if k == 'ContainerName']
    name = values[-1] if values else f'systemd-{container_file[:-len(".container")]}'
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name):
        raise BackupError('incompatible', f'{container_file} 的 ContainerName= 設定不受支援。')
    return name


DB_ENV_KEYS = frozenset({'POSTGRES_USER', 'POSTGRES_DB', 'POSTGRES_INITDB_ARGS', 'POSTGRES_PASSWORD_FILE',
                         'POSTGRES_INITDB_WALDIR', 'POSTGRES_HOST_AUTH_METHOD', 'PGDATA', 'LANG', 'LC_ALL', 'TZ'})


class Live:
    """The live Odoo target as its Quadlet files describe it: the database container (image, allowed environment,
    secret mounts, data dir target, container name), the web container (image, configuration secret, mounts).
    `skipped_mounts`: [(container file, target)] of the mounts that are no data of Odoo and were left out (OD-08, OD-09).
    `db_name` and `db_role`: what the configuration of this device's Odoo names (`apply_conf`; the tenant's own `odoo`
    until then)."""

    def __init__(self, quadlets, home):
        files = list(quadlets)
        self.db_file = next((f for f in files if f.endswith('.container') and _is_db(quadlets[f])), None)
        self.web_file = next((f for f in files if f.endswith('.container') and _is_web(quadlets[f])), None)
        if self.db_file is None or self.web_file is None:
            raise BackupError('incompatible', '這台的 Odoo 不是 WOOWTECH 的 Podman 版本（找不到資料庫或 Odoo 主程式的 Quadlet 檔）。')
        self.skipped_mounts = []
        self.db_name, self.db_role = DEFAULT_DB_NAME, DEFAULT_DB_ROLE
        db_text = quadlets[self.db_file]
        self.db_image = tempctr.quadlet_image(db_text)
        self.db_env = tempctr.quadlet_environment(db_text, DB_ENV_KEYS)
        self.db_secrets = tempctr.quadlet_secrets(db_text)
        self.db_container = quadlet_container_name(quadlets, self.db_file)
        db_skipped = []
        db_mounts = quadlet_mounts(quadlets, self.db_file, home, skipped=db_skipped)
        self.skipped_mounts += db_skipped
        if not db_mounts:
            raise BackupError('incompatible', f'{self.db_file} 沒有資料卷設定。')
        # The data volume is the mount that holds the cluster (PGDATA, else the image's own folder); the first mount when
        # nothing says so -- but never another one when the mount that held the cluster was left out.
        wanted = self.db_env.get('PGDATA') or '/var/lib/postgresql/data'
        holder = next((m for m in db_mounts if wanted == m[1] or wanted.startswith(m[1].rstrip('/') + '/')), None)
        if holder is None:
            if db_skipped:
                raise BackupError('incompatible', f'{self.db_file} 的資料庫資料夾掛在這個匯入不支援的位置。')
            holder = db_mounts[0]
        self.db_volume, self.db_target = holder[0], holder[1]
        self.db_user = self.db_env.get('POSTGRES_USER', 'postgres')
        # The cluster lives in PGDATA when the Quadlet sets it (a folder of the volume), else at the mount point.
        self.pgdata = self.db_env.get('PGDATA') or self.db_target
        if not (tempctr.TARGET_RE.fullmatch(self.pgdata) and '..' not in self.pgdata.split('/')
                and (self.pgdata == self.db_target or self.pgdata.startswith(self.db_target.rstrip('/') + '/'))):
            raise BackupError('incompatible', f'{self.db_file} 的 PGDATA 設定不在資料卷裡，不受支援。')
        web_text = quadlets[self.web_file]
        self.web_image = tempctr.quadlet_image(web_text)
        self.web_secrets = tempctr.quadlet_secrets(web_text)
        self.conf_secret = next((s for s in self.web_secrets if 'target=/etc/odoo/odoo.conf' in s.split(',')), None)
        web_skipped = []
        self.web_mounts = quadlet_mounts(quadlets, self.web_file, home, skipped=web_skipped)
        self.skipped_mounts += web_skipped
        if not self.db_image or not self.web_image or self.conf_secret is None:
            raise BackupError('incompatible', '這台 Odoo 的 Quadlet 設定缺少映像或設定檔機密。')
        # OD-05: the superuser's name is only ever handed over as one argument (`-U <name>`) or an environment value, never
        # put into a command line of a shell or into SQL, so no character but a control one or a length can hurt.
        if (not self.db_user or len(self.db_user.encode('utf-8', 'surrogatepass')) > MAX_NAME_BYTES
                or BAD_NAME_RE.search(self.db_user)):
            raise BackupError('incompatible', f'{self.db_file} 的 POSTGRES_USER 設定不受支援。')

    def web_volume_mount(self, name):
        return next((target for source, target, _opts in self.web_mounts if source == name), None)

    def apply_conf(self, conf):
        """The database and role this device's Odoo is configured with (`read_conf`); a name that does not fit what the
        tools take stops this app."""
        for key, value, pattern in (('db_name', conf.get('db_name'), DB_NAME_RE), ('db_user', conf.get('db_user'),
                                                                                    PG_ROLE_RE)):
            if value is not None and not pattern.fullmatch(value):
                raise haissues.stopped(Issue('odoo.layout-unsupported', 'stop',
                                             f'這台 Odoo 設定檔裡的 {key} 設定不是這個匯入支援的名稱，無法匯入。',
                                             action='請把這台 Odoo 設定檔的資料庫名稱和帳號改成英文字母、數字、底線組成的名稱，再重新檢查。'))
        self.db_name = conf.get('db_name') or DEFAULT_DB_NAME
        self.db_role = conf.get('db_user') or DEFAULT_DB_ROLE


def _text_of(data):
    return data.decode('utf-8', 'replace') if isinstance(data, bytes) else str(data)


def _is_db(data):
    text = _text_of(data)
    return 'POSTGRES_' in text and '/var/lib/postgresql' in text


def _is_web(data):
    return 'target=/etc/odoo/odoo.conf' in _text_of(data)


# ====================================================================== PostgreSQL in a throwaway container

def sql_literal(value):
    """A standard-conforming SQL string literal (checked text: no NUL or control characters)."""
    if not isinstance(value, str) or re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', value):
        raise BackupError('internal-error', '資料庫設定值格式不正確。')
    return "'" + value.replace("'", "''") + "'"


def pg_ident(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_$]{0,62}', value):
        raise BackupError('internal-error', '資料庫名稱格式不正確。')
    return '"' + value + '"'


# What the engine sends into a throwaway container on a `podman exec` stdin is checked to have arrived whole (final
# verification 2026-11-24: an Odoo conversion on a host with load ~21 restored only part of its pg_restore list and
# failed only at a later step).
WRITE_ATTEMPTS = 3        # Cluster.write_file: the first write and at most 2 more
WRITE_RETRY_PAUSE = 2     # seconds between them
SQL_END_MARK = 'woowbk-sql-end-'
INCOMPLETE_FILE = '暫用容器裡的暫存檔沒有完整寫入（主機可能太忙），已停止，沒有做任何變更，請稍後再試。'
INCOMPLETE_SQL = '送進暫用 PostgreSQL 的資料庫指令沒有完整送達（主機可能太忙），已停止，沒有做任何變更，請稍後再試。'
# The size, then the digest's kind and line: sha256sum where the image has one (busybox in the Alpine images and
# coreutils in the Debian ones do), else POSIX cksum. `path` is a fixed name (Cluster.write_file checks it).
READBACK = ('wc -c < {path} && if command -v sha256sum >/dev/null 2>&1; then echo sha256 && sha256sum < {path}; '
            'else echo cksum && cksum < {path}; fi')


def _cksum_table():
    table = []
    for i in range(256):
        crc = i << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) if crc & 0x80000000 else crc << 1
        table.append(crc & 0xFFFFFFFF)
    return tuple(table)


CKSUM_TABLE = _cksum_table()


def _cksum_update(crc, data):
    for byte in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ CKSUM_TABLE[(crc >> 24) ^ byte]
    return crc


def source_digest(source, start, kind):
    """(size, digest text) of what Cluster.write_file sends: `source` is bytes (`start` None) or a file read from
    `start` to its end; `kind` 'sha256' (hex, as sha256sum prints it) or 'cksum' (POSIX cksum's CRC in decimal)."""
    chunks = [source] if start is None else iter(lambda: source.read(1024 * 1024), b'')
    if start is not None:
        source.seek(start)
    size, sha, crc = 0, hashlib.sha256(), 0
    for chunk in chunks:
        size += len(chunk)
        if kind == 'sha256':
            sha.update(chunk)
        else:
            crc = _cksum_update(crc, chunk)
    if kind == 'sha256':
        return size, sha.hexdigest()
    length = size
    while length:
        crc = _cksum_update(crc, bytes([length & 0xFF]))
        length >>= 8
    return size, str(~crc & 0xFFFFFFFF)


def database_arguments(database, by_env=False):
    """(`psql`/`pg_dump` arguments, environment) that name the database `database`: `['-d', name]` for a name that is
    plainly a name (letters, digits, `_ . -`) -- what every other caller always did -- and, for `by_env` or any other name,
    no argument and `PGDATABASE=<name>`: libpq takes that value as the name and never as a connection string (OD-31: a
    name of an HA database may hold spaces, `=`, `$`, any text). Only a name PostgreSQL cannot have (empty, over 63 bytes,
    a control character) is refused."""
    if not isinstance(database, str) or not database or len(database.encode('utf-8', 'surrogatepass')) > MAX_NAME_BYTES \
            or BAD_NAME_RE.search(database):
        raise BackupError('internal-error', '資料庫名稱格式不正確。')
    if not by_env and DB_NAME_RE.fullmatch(database):
        return ['-d', database], None
    return [], {'PGDATABASE': database}


class Cluster:
    """A PostgreSQL server in a throwaway container (`role` of `tmp`), used as its OS user postgres through the unix
    socket (trust): psql/pg_dump/pg_restore by `podman exec`."""

    def __init__(self, tmp, role, *, superuser='postgres', log=None, sleep=time.sleep, clock=time.monotonic):
        self.tmp, self.role, self.superuser = tmp, role, superuser
        self.log = log or (lambda _text: None)
        self.sleep, self.clock = sleep, clock

    def wait_ready(self, *, tcp=False, timeout=PG_READY_TIMEOUT, checkpoint=None):
        """Until the server accepts connections (`tcp`: on 127.0.0.1, i.e. the final server of the image's entrypoint
        and not its temporary initdb one)."""
        args = ['pg_isready', '-q', '-U', self.superuser] + (['-h', '127.0.0.1', '-p', '5432'] if tcp else [])
        deadline = self.clock() + timeout
        while True:
            if checkpoint is not None:
                checkpoint()
            result = self.tmp.exec(self.role, args, user='postgres', check=False, timeout=60, max_output=64 * 1024)
            if result.returncode == 0:
                return
            if not self.tmp.running(self.role):
                raise BackupError('job-failed', '暫用的 PostgreSQL 沒有啟動（資料可能不完整或版本不符）。')
            if self.clock() > deadline:
                raise BackupError('job-failed', f'暫用的 PostgreSQL 在 {timeout} 秒內沒有就緒。')
            self.sleep(1)

    def query_json(self, sql, database='postgres', *, max_output=SQL_OUTPUT, timeout=600, by_env=False):
        """One JSON value from `psql -At` (the statement must return exactly one json cell). `by_env`: the database's
        name comes from a backup (or is any name at all): it goes through PGDATABASE and not through `-d`, which psql
        reads as a connection string when it holds an `=` or starts like a URI (OD-31)."""
        where, env = database_arguments(database, by_env)
        out = self.tmp.exec(self.role, ['psql', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-U',
                                        self.superuser, *where, '-c', sql], user='postgres', env=env, timeout=timeout,
                            max_output=max_output).stdout or b''
        try:
            return util.loads_strict(out.strip() or b'null', max_bytes=max_output)
        except ValueError:
            raise BackupError('job-failed', '暫用 PostgreSQL 的回應格式不正確。') from None

    def script(self, sql, database='postgres', *, timeout=600, by_env=False):
        """Run SQL from stdin in ONE transaction that the input itself opens and closes (`BEGIN;` sql `COMMIT;`, then
        an end mark: `_run`); ON_ERROR_STOP, values never appear in argv. Not `psql -1`: it commits at the end of its
        input, so an input that arrived short committed the part that arrived, a cut last statement included (psql
        sends what is left at EOF; real psql 17.11, evidence pg-stdin-fix-20261124). Never for a statement PostgreSQL
        refuses inside a transaction block (ALTER SYSTEM, VACUUM...): `statement`."""
        if not isinstance(sql, str):
            raise BackupError('internal-error', '資料庫指令格式不正確。')
        self._run(f'BEGIN;\n{sql}\nCOMMIT;\n', database, timeout, by_env)

    def statement(self, sql, database='postgres', *, timeout=600, by_env=False):
        """Run exactly one SQL statement from stdin outside any transaction block (review C-19: ALTER SYSTEM cannot
        run inside one), then the end mark (`_run`): values never appear in argv."""
        if not isinstance(sql, str) or not sql.strip() or ';' in re.sub(r"'(?:[^']|'')*'", '', sql.strip().rstrip(';')):
            raise BackupError('internal-error', '一次只能執行一個資料庫指令。')
        self._run(sql.strip().rstrip(';') + ';\n', database, timeout, by_env)

    def _run(self, text, database, timeout, by_env=False):
        """`text` on psql's stdin, followed by `\\echo <a new end mark>`: psql prints the mark only after it has read
        and run everything before it, so stdout must end with it. A `podman exec` stdin transfer can arrive short
        under host load (final verification 2026-11-24): without COMMIT PostgreSQL rolls the transaction back when
        psql disconnects (psql still exits 0), and the missing mark stops the job (INCOMPLETE_SQL)."""
        mark = SQL_END_MARK + secrets.token_hex(8)
        where, env = database_arguments(database, by_env)
        out = self.tmp.exec(self.role, ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', self.superuser, *where,
                                        '-f', '-'], user='postgres', env=env,
                            input=(text + f'\\echo {mark}\n').encode('utf-8'), timeout=timeout,
                            max_output=1024 * 1024).stdout or b''
        if out.rstrip(b'\n').rsplit(b'\n', 1)[-1] != mark.encode('ascii'):
            raise BackupError('job-failed', INCOMPLETE_SQL)

    def write_file(self, path, source, *, timeout=DUMP_TIMEOUT):
        """Copy `source` (bytes, or a seekable binary file from its current position) into the container at `path`
        (fixed paths under /tmp only) and check that it arrived whole: the file's size and digest, read back inside
        the container (READBACK), must be the source's. A `podman exec` stdin transfer can arrive short under host
        load (final verification 2026-11-24: pg_restore then restored only part of its list), so a copy that does not
        match is written again, WRITE_ATTEMPTS times in all, then the job stops (INCOMPLETE_FILE). Neither the
        content nor a digest is logged."""
        if not re.fullmatch(r'/tmp/woowbk-[a-z0-9.-]{1,40}', path):
            raise BackupError('internal-error', '暫存檔路徑不正確。')
        if isinstance(source, (bytes, bytearray, memoryview)):
            source, start = bytes(source), None
        else:
            try:
                start = source.tell()
                source.seek(start)
            except (AttributeError, OSError, ValueError):
                raise BackupError('internal-error', '暫存檔的來源無法重新讀取。') from None
        expected = {}
        for attempt in range(1, WRITE_ATTEMPTS + 1):
            if start is not None:
                source.seek(start)
            self.tmp.exec(self.role, ['sh', '-c', f'umask 077 && cat > {path}'], user='postgres', input=source,
                          timeout=timeout, max_output=64 * 1024)
            found = self._read_back(path, timeout)
            if found is not None:
                kind, size, value = found
                if kind not in expected:
                    expected[kind] = source_digest(source, start, kind)
                if expected[kind] == (size, value):
                    return
            if attempt < WRITE_ATTEMPTS:
                self.log(f'暫用容器裡的暫存檔沒有完整寫入，重新寫入（第 {attempt + 1} 次，共 {WRITE_ATTEMPTS} 次）。')
                self.sleep(WRITE_RETRY_PAUSE)
        raise BackupError('job-failed', INCOMPLETE_FILE)

    def _read_back(self, path, timeout):
        """(digest kind, size, digest text) of the file at `path` in the container, None when it cannot be read."""
        result = self.tmp.exec(self.role, ['sh', '-c', READBACK.format(path=path)], user='postgres', check=False,
                               timeout=timeout, max_output=64 * 1024)
        lines = (result.stdout or b'').decode('ascii', 'replace').split('\n')
        if result.returncode != 0 or len(lines) < 3 or not re.fullmatch(r'\s*[0-9]{1,15}\s*', lines[0]):
            return None
        size, kind, fields = int(lines[0]), lines[1].strip(), lines[2].split()
        if kind == 'sha256' and fields and re.fullmatch(r'[0-9a-f]{64}', fields[0]):
            return kind, size, fields[0]
        if (kind == 'cksum' and len(fields) >= 2 and all(re.fullmatch(r'[0-9]{1,15}', f) for f in fields[:2])
                and int(fields[1]) == size):
            return kind, size, str(int(fields[0]))
        return None


DATABASES_SQL = ("SELECT coalesce(json_agg(json_build_array(datname, pg_database_size(oid), datcollate, datctype) "
                 "ORDER BY datname), '[]'::json) FROM pg_database WHERE datallowconn AND NOT datistemplate "
                 "AND datname <> 'postgres'")
IS_ODOO_SQL = ("SELECT json_build_array(to_regclass('public.ir_module_module') IS NOT NULL, "
               "to_regclass('public.res_partner') IS NOT NULL, to_regclass('public.ir_config_parameter') IS NOT NULL, "
               "to_regclass('public.res_users') IS NOT NULL, to_regclass('public.ir_attachment') IS NOT NULL, "
               "to_regclass('public.ir_cron') IS NOT NULL, to_regclass('public.ir_mail_server') IS NOT NULL)")
DETAIL_SQL = """SELECT json_build_object(
 'modules', (SELECT coalesce(json_agg(json_build_array(name, coalesce(latest_version, ''), state) ORDER BY name),
             '[]'::json) FROM ir_module_module WHERE state IN ('installed', 'to upgrade', 'to install', 'to remove')),
 'partners', (SELECT count(*) FROM res_partner),
 'users', (SELECT count(*) FROM res_users WHERE active AND NOT share),
 'attachments', (SELECT count(*) FROM ir_attachment),
 'attachment_bytes', (SELECT coalesce(sum(file_size), 0) FROM ir_attachment WHERE store_fname IS NOT NULL),
 'crons_active', (SELECT count(*) FROM ir_cron WHERE active),
 'mail_servers_active', (SELECT count(*) FROM ir_mail_server WHERE active),
 'size', pg_database_size(current_database()),
 'extensions', (SELECT coalesce(json_agg(json_build_array(extname, extversion) ORDER BY extname), '[]'::json)
                FROM pg_extension),
 'base_url', (SELECT value FROM ir_config_parameter WHERE key = 'web.base.url'))"""
def _not_extension(catalog, alias):
    return (f"NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = '{catalog}'::regclass "
            f"AND d.objid = {alias}.oid AND d.deptype = 'e')")


# Objects of HA's database that only a superuser can create (the restore runs as the role odoo and would refuse them;
# the check says so first). Extension members (pg_trgm, unaccent, vector) are created by the extensions here.
SUPERUSER_SQL = ("SELECT coalesce(json_agg(kind), '[]'::json) FROM ("
                 "SELECT 'EVENT TRIGGER' AS kind WHERE EXISTS (SELECT 1 FROM pg_event_trigger e WHERE "
                 + _not_extension('pg_event_trigger', 'e') + ") "
                 "UNION ALL SELECT 'FOREIGN DATA WRAPPER' WHERE EXISTS (SELECT 1 FROM pg_foreign_data_wrapper w WHERE "
                 + _not_extension('pg_foreign_data_wrapper', 'w') + ") "
                 "UNION ALL SELECT 'SERVER' WHERE EXISTS (SELECT 1 FROM pg_foreign_server) "
                 "UNION ALL SELECT 'SUBSCRIPTION' WHERE EXISTS (SELECT 1 FROM pg_subscription WHERE subdbid = "
                 "(SELECT oid FROM pg_database WHERE datname = current_database())) "
                 "UNION ALL SELECT 'PROCEDURAL LANGUAGE' WHERE EXISTS (SELECT 1 FROM pg_language l WHERE l.oid >= 16384 "
                 "AND " + _not_extension('pg_language', 'l') + ") "
                 "UNION ALL SELECT 'FUNCTION (LANGUAGE C)' WHERE EXISTS (SELECT 1 FROM pg_proc p WHERE p.oid >= 16384 "
                 "AND p.prolang IN (SELECT oid FROM pg_language WHERE lanname IN ('c', 'internal')) AND "
                 + _not_extension('pg_proc', 'p') + ") "
                 "UNION ALL SELECT 'ACCESS METHOD' WHERE EXISTS (SELECT 1 FROM pg_am a WHERE a.oid >= 16384 AND "
                 + _not_extension('pg_am', 'a') + ") "
                 "UNION ALL SELECT 'CAST' WHERE EXISTS (SELECT 1 FROM pg_cast c WHERE c.oid >= 16384 AND "
                 + _not_extension('pg_cast', 'c') + ") "
                 "UNION ALL SELECT 'OPERATOR CLASS' WHERE EXISTS (SELECT 1 FROM pg_opclass o WHERE o.oid >= 16384 AND "
                 + _not_extension('pg_opclass', 'o') + ") "
                 "UNION ALL SELECT 'TEXT SEARCH PARSER' WHERE EXISTS (SELECT 1 FROM pg_ts_parser t WHERE t.oid >= 16384 "
                 "AND " + _not_extension('pg_ts_parser', 't') + ") "
                 "UNION ALL SELECT 'TEXT SEARCH TEMPLATE' WHERE EXISTS (SELECT 1 FROM pg_ts_template t WHERE "
                 "t.oid >= 16384 AND " + _not_extension('pg_ts_template', 't') + ")) k")
HAS_WEBSITE_SQL = "SELECT to_json(to_regclass('public.website') IS NOT NULL)"
WEBSITE_DOMAINS_SQL = ("SELECT coalesce(json_agg(DISTINCT domain ORDER BY domain), '[]'::json) FROM website "
                       "WHERE coalesce(domain, '') <> ''")
# The converted database keeps no website address of HA: the target's own address (web.base.url) is used (review C-02).
CLEAR_WEBSITE_DOMAINS_SQL = ("DO $$ BEGIN IF to_regclass('public.website') IS NOT NULL THEN "
                             "UPDATE website SET domain = NULL WHERE domain IS NOT NULL; END IF; END $$;\n")
VERIFY_SQL = """SELECT json_build_object(
 'modules', (SELECT coalesce(json_agg(json_build_array(name, coalesce(latest_version, ''), state) ORDER BY name),
             '[]'::json) FROM ir_module_module WHERE state IN ('installed', 'to upgrade', 'to install', 'to remove')),
 'partners', (SELECT count(*) FROM res_partner),
 'attachments', (SELECT count(*) FROM ir_attachment),
 'marker', (SELECT value FROM ir_config_parameter WHERE key = 'woow_paas_platform.upgrade_done'),
 'attempt', (SELECT count(*) FROM ir_config_parameter WHERE key = 'woow_paas_platform.upgrade_attempt'),
 'base_url', (SELECT value FROM ir_config_parameter WHERE key = 'web.base.url'),
 'uuid', (SELECT value FROM ir_config_parameter WHERE key = 'database.uuid'))"""
LIVE_SQL = """SELECT json_build_object(
 'base_url', (SELECT value FROM ir_config_parameter WHERE key = 'web.base.url'),
 'freeze', (SELECT value FROM ir_config_parameter WHERE key = 'web.base.url.freeze'),
 'marker', (SELECT value FROM ir_config_parameter WHERE key = 'woow_paas_platform.upgrade_done'))"""
# Whether the live database has Odoo's settings table at all: asked first, so that a database that was never initialised
# gives the defaults of OD-16/OD-17 and not an error.
LIVE_TABLE_SQL = "SELECT to_json(to_regclass('public.ir_config_parameter') IS NOT NULL)"
# The extensions the live PostgreSQL image has and whether PostgreSQL itself calls them trusted (a non-superuser may
# create them: no code of their own that a superuser alone should load): OD-39, OD-40, OD-57.
AVAILABLE_EXTENSIONS_SQL = ("SELECT coalesce(jsonb_agg(DISTINCT jsonb_build_array(name, trusted)), '[]'::jsonb) "
                            "FROM pg_available_extension_versions")


def live_role_sql(name):
    """What the live cluster says about the role `name` (null when there is none)."""
    return ("SELECT json_build_object('password', rolpassword, 'super', rolsuper, 'login', rolcanlogin, "
            "'createdb', rolcreatedb, 'createrole', rolcreaterole, 'replication', rolreplication, "
            "'bypassrls', rolbypassrls, 'connlimit', rolconnlimit) FROM pg_authid WHERE rolname = "
            + sql_literal(name))


LIVE_ROLE_SQL = live_role_sql(DEFAULT_DB_ROLE)
SETTINGS_SQL = ("SELECT coalesce(json_agg(json_build_array(name, setting, source, context) ORDER BY name), '[]'::json) "
                "FROM pg_settings WHERE source NOT IN ('default', 'override', 'client', 'session')")
# What the new cluster's postgresql.auto.conf holds after ALTER SYSTEM (every carried setting must be there, valid).
FILE_SETTINGS_SQL = ("SELECT coalesce(json_agg(json_build_array(name, setting, coalesce(error, '')) ORDER BY seqno), "
                     "'[]'::json) FROM pg_file_settings WHERE sourcefile LIKE '%/postgresql.auto.conf'")


def _int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def parse_modules(rows):
    """[(name, version, state)] of ir_module_module rows (checked)."""
    if not isinstance(rows, list) or len(rows) > MAX_MODULE_ROWS:
        raise BackupError('job-failed', MSG_MODULES_UNREADABLE)
    modules = []
    for row in rows:
        if (not isinstance(row, list) or len(row) != 3 or not all(isinstance(x, str) for x in row)
                or not MODULE_RE.fullmatch(row[0]) or len(row[1]) > 64):
            raise BackupError('job-failed', MSG_MODULES_UNREADABLE)
        modules.append(tuple(row))
    return modules


def database_details(cluster, name):
    """Counts, modules and extensions of one HA database, or None when it is not an Odoo database. The name is HA's: it
    goes to PostgreSQL through PGDATABASE (OD-31)."""
    def ask(sql):
        return cluster.query_json(sql, name, by_env=True)

    flags = ask(IS_ODOO_SQL)
    if not isinstance(flags, list) or not all(flag is True for flag in flags):
        return None
    doc = ask(DETAIL_SQL)
    if not isinstance(doc, dict):
        raise BackupError('job-failed', MSG_CONTENT_UNREADABLE)
    extensions = doc.get('extensions') if isinstance(doc.get('extensions'), list) else []
    base_url = doc.get('base_url') if isinstance(doc.get('base_url'), str) else None
    kinds = ask(SUPERUSER_SQL)
    domains = ask(WEBSITE_DOMAINS_SQL) if ask(HAS_WEBSITE_SQL) is True else []
    return {
        'superuser_objects': [str(k)[:40] for k in kinds[:20] if isinstance(k, str)] if isinstance(kinds, list) else [],
        'website_domains': ([str(d)[:200] for d in domains[:20] if isinstance(d, str)] if isinstance(domains, list)
                            else []),
        'modules': parse_modules(doc.get('modules')),
        'partners': _int(doc.get('partners')), 'users': _int(doc.get('users')),
        'attachments': _int(doc.get('attachments')), 'attachment_bytes': _int(doc.get('attachment_bytes')),
        'crons_active': _int(doc.get('crons_active')), 'mail_servers_active': _int(doc.get('mail_servers_active')),
        'size': _int(doc.get('size')),
        'extensions': [str(e[0])[:64] for e in extensions if isinstance(e, list) and e and isinstance(e[0], str)],
        'base_url': base_url[:2048] if base_url else None,
    }


# ====================================================================== the target's modules (Odoo itself)

SCANNER = r'''
import json, os, sys
request = json.loads(sys.argv[1])
out = {"python": {}, "bin": {}}
try:
    import odoo
    from odoo import release, tools
    from odoo.tools import config
    from odoo.modules import module
    config.parse_config(["-c", request["conf"]] if os.path.isfile(request["conf"]) else [])
    module.initialize_sys_path()
    out["version"] = release.version
    out["paths"] = [str(p) for p in odoo.addons.__path__]
    rows = []
    broken = []
    for name in sorted(module.get_modules()):
        try:
            manifest = module.get_manifest(name) or {}
            path = module.get_module_path(name, display_warning=False) or ""
            rows.append([name, str(manifest.get("version", "")), bool(manifest.get("installable", True)),
                         os.path.dirname(path)])
        except Exception:
            broken.append(name)
    out["modules"] = rows
    out["broken"] = broken
    for dep in request.get("python", []):
        try:
            module.check_python_external_dependency(dep)
            out["python"][dep] = True
        except Exception:
            out["python"][dep] = False
    for dep in request.get("bin", []):
        try:
            tools.find_in_path(dep)
            out["bin"][dep] = True
        except Exception:
            out["bin"][dep] = False
except Exception as exc:
    out["error"] = type(exc).__name__
sys.stdout.write(json.dumps(out))
'''


def target_inventory(tmp, live, *, python=(), binaries=(), role='scan', size=None):
    """{version, paths, modules {name: (version, installable, root)}, broken [names], python {dep: bool}, bin {dep: bool}}
    from the live Odoo image (network none, the live configuration secret and module folders mounted read-only). A module
    whose manifest cannot be read is left out and named in `broken` (OD-35); only a list that has none at all stops.
    `size`: the bytes of data the answer is about (the wait and the room for the listing grow with it: OD-73)."""
    request = {'conf': CONF_PATH, 'python': sorted(set(python)), 'bin': sorted(set(binaries))}
    for dep in request['python']:
        if not PY_DEP_RE.fullmatch(dep):
            raise BackupError('internal-error', 'Python 套件名稱格式不正確。')
    for dep in request['bin']:
        if not BIN_DEP_RE.fullmatch(dep):
            raise BackupError('internal-error', '程式名稱格式不正確。')
    room = podman.scaled_limit(SCAN_OUTPUT, size, ratio=1)
    result = tmp.run(role, live.web_image, ['-I', '-', json.dumps(request)], entrypoint='python3',
                     input=SCANNER.encode('utf-8'), volumes=live.web_mounts, secrets=[live.conf_secret],
                     timeout=podman.scaled_timeout(600, size), max_output=room, read_only_root=True)
    try:
        doc = util.loads_strict((result.stdout or b'').strip(), max_bytes=room)
    except ValueError:
        raise BackupError('job-failed', '無法讀取這台 Odoo 的模組清單。') from None
    if (not isinstance(doc, dict) or doc.get('error') or not isinstance(doc.get('modules'), list)
            or not doc['modules']):
        raise BackupError('job-failed', '無法讀取這台 Odoo 的模組清單。', reason=str((doc or {}).get('error'))[:80])
    modules = {}
    for row in doc['modules'][:MAX_MODULE_ROWS]:
        if (isinstance(row, list) and len(row) == 4 and isinstance(row[0], str) and MODULE_RE.fullmatch(row[0])
                and isinstance(row[1], str) and isinstance(row[2], bool) and isinstance(row[3], str)):
            modules[row[0]] = (row[1][:64], row[2], row[3][:512])
    if not modules:
        raise BackupError('job-failed', '無法讀取這台 Odoo 的模組清單。')
    python_ok = {k: v is True for k, v in (doc.get('python') or {}).items() if isinstance(k, str)}
    bin_ok = {k: v is True for k, v in (doc.get('bin') or {}).items() if isinstance(k, str)}
    version = doc.get('version') if isinstance(doc.get('version'), str) else ''
    broken = sorted({n for n in doc.get('broken') or [] if isinstance(n, str) and MODULE_RE.fullmatch(n)})
    return {'version': version[:64], 'paths': [str(p)[:512] for p in doc.get('paths') or []][:32],
            'modules': modules, 'broken': broken[:MAX_MODULE_ROWS], 'python': python_ok, 'bin': bin_ok}


# What this device's Odoo says it is configured with: only the three settings the import needs, never the rest of the file
# (it holds the master password): the database, the account and the account's password.
CONF_SCRIPT = r'''
import configparser, json, sys
out = {}
try:
    parser = configparser.RawConfigParser(strict=False)
    with open(sys.argv[1], encoding="utf-8") as handle:
        parser.read_file(handle)
    options = parser["options"] if parser.has_section("options") else {}
    for key in ("db_name", "db_user", "db_password"):
        value = options.get(key) if options else None
        if isinstance(value, str) and value.strip() and value.strip() != "False":
            out[key] = value.strip().split(",")[0].strip() if key == "db_name" else value.strip()
except Exception as exc:
    out["error"] = type(exc).__name__
sys.stdout.write(json.dumps(out))
'''


def read_conf(work, app, live):
    """{db_name?, db_user?, db_password?} of this device's odoo.conf, read in a throwaway container of the live Odoo
    image (network none, the configuration secret mounted, read-only root; only these three settings are printed). The
    password is masked in every log at once and never put into a message. A file that cannot be read gives {} (the
    tenant's own names, no password to make an account with)."""
    from . import jobs
    tmp = work.temp(app)
    result = tmp.run('conf', live.web_image, ['-I', '-', CONF_PATH], entrypoint='python3',
                     input=CONF_SCRIPT.encode('utf-8'), secrets=[live.conf_secret], timeout=120,
                     max_output=64 * 1024, read_only_root=True)
    try:
        doc = util.loads_strict((result.stdout or b'').strip(), max_bytes=64 * 1024)
    except ValueError:
        doc = None
    conf = {}
    if isinstance(doc, dict) and not doc.get('error'):
        for key in ('db_name', 'db_user', 'db_password'):
            value = doc.get(key)
            if isinstance(value, str) and 0 < len(value) <= 1024 and not re.search(r'[\x00-\x1f\x7f]', value):
                conf[key] = value
    if 'db_password' in conf:
        jobs.mask_secret(conf['db_password'])
    return conf


# ====================================================================== the verdict

def database_issues(name, details, target, candidates, *, ha_major, target_major, extra_target='/mnt/extra-addons',
                    vector_ok=True, others=()):
    """(issues, copy, unavailable) of one HA database against the target: what to say about it (every issue belongs to
    the database `name`), the custom modules of the backup that go into the target's folder, and the modules that will not
    work on this device and that the customer confirms.

    A module installed in the HA database must be on the target with the identical version -- Odoo's own copy (the
    first on its addons path) -- or be a custom module of the backup with that version; a backup copy goes into the
    custom modules folder when the target has none, or has another version only there (a copy elsewhere would win).
    What HAOS would do -- take the data as it is -- is done where the data stays whole: a module the target lacks, a
    custom module that needs a package the target lacks, objects only a superuser can create and the databases that stay on
    HA are lines to confirm; modules still waiting for an installation or upgrade, a module that cannot be installed or
    needs a program, mail servers and crons are reminders; only what the data itself makes impossible stops this database
    (another version of a module, a PostgreSQL that is newer, an extension this device's PostgreSQL does not have)."""
    issues, copy, unavailable = [], {}, set()

    def add(issue_id, level, message, items=(), action=''):
        issues.append(Issue(issue_id, level, message, items, action=action, database=name))

    missing, mismatch, pending = [], [], []
    for module, version, state in details['modules']:
        if state != 'installed':
            pending.append(f'{module}（{state}）')
            continue
        effective = target['modules'].get(module)
        candidate = candidates.get(module)
        manifest = (candidate or {}).get('manifest') or {}
        has_copy = candidate is not None and manifest and same_version(manifest.get('version'), version)
        if effective is not None and same_version(effective[0], version):
            continue
        if has_copy and (effective is None or effective[2].rstrip('/') == extra_target):
            copy[module] = candidate
            continue
        if effective is None:
            missing.append(module)
        else:
            mismatch.append(f'{module}（HA {version}，這台 {effective[0]}）')
    skipped_deps, unreadable, not_installable, no_program, foreign = [], [], [], [], []
    for module, candidate in sorted(copy.items()):
        manifest = candidate.get('manifest') or {}
        lacking = []
        for dep in manifest.get('python') or []:
            if not PY_DEP_RE.fullmatch(dep):       # a spelling that was never asked of Odoo: only said
                unreadable.append(f'{dep[:80]}（模組 {module}）')
            elif target['python'].get(dep) is not True:
                lacking.append(dep)
        if lacking:                                  # the module stays out: its files could not even be loaded
            skipped_deps.append(f'{module}（缺 {"、".join(lacking)}）')
            unavailable.add(module)
            del copy[module]
            continue
        if not manifest.get('installable', True):
            not_installable.append(module)
        no_program += [f'{dep}（模組 {module}）' for dep in manifest.get('bin') or [] if target['bin'].get(dep) is not True]
        if candidate.get('foreign'):
            foreign.append(module)
    unavailable.update(missing)
    if pending:
        add('odoo.modules-pending', 'notice', '這個資料庫有尚未完成的模組安裝、升級或移除，會照 HA 的狀態搬過來；'
            '匯入後請到 Odoo 的「應用程式」套用或取消它們。', pending)
    if mismatch:
        add('odoo.module-version-different', 'stop', '這些模組的版本和這台的不同，資料結構可能對不上，不能直接搬。', mismatch,
            action='請先讓 HA 和這台的 Odoo 版本一致，再匯入這個資料庫。')
    if missing:
        add('odoo.modules-missing', 'confirm', MSG_MISSING_MODULES + MSG_HINT_SHARE, sorted(missing))
    if skipped_deps:
        add('odoo.modules-skipped-deps', 'confirm', '這些自訂模組需要這台沒有的 Python 套件，不會搬過來，它們的功能先不能用；'
            '資料還在資料庫裡，之後裝好套件、放好模組就能用。', skipped_deps)
    if unreadable:
        add('odoo.dependency-unreadable', 'notice', '這些模組的套件需求寫法這台看不懂，沒有檢查它們；模組照搬，請匯入後確認能用。',
            unreadable)
    if not_installable:
        add('odoo.module-not-installable', 'notice', '這些自訂模組標示為不可安裝：照搬，但 Odoo 不會載入它們，用到它們的畫面會出錯。',
            not_installable)
    if no_program:
        add('odoo.program-missing', 'notice', '這些自訂模組需要這台沒有的程式：照搬，只有用到那個程式的功能（例如產生檔案）不能用。',
            no_program)
    if foreign:
        other = 'x86' if host_elf_machine() == EM_AARCH64 else 'ARM'
        add('odoo.module-foreign-native', 'notice', f'這些自訂模組含有只能在其他處理器（例如 {other}）上執行的程式：'
            '照搬，但那個模組可能不能用；Odoo 起不來時匯入會自動退回。', foreign)
    extensions = [ext for ext in details['extensions'] if ext != 'plpgsql']
    offered = target.get('extensions')
    if offered is None:                              # this device's PostgreSQL could not be asked: the fixed list
        unsupported = [ext for ext in extensions if ext not in EXTENSIONS_OK]
    else:                                            # what its image has, of what PostgreSQL itself calls safe (OD-39)
        unsupported = [ext for ext in extensions
                       if ext not in offered or not (ext in EXTENSIONS_OK or offered[ext] is True)]
    if unsupported:
        add('odoo.extension-unsupported', 'stop', '這個資料庫使用了這台的 PostgreSQL 沒有（或不能安全建立）的擴充功能。', unsupported,
            action='請在 HA 移除這些擴充功能的用途後重新備份，或改用這台有這些擴充功能的 PostgreSQL。')
    if 'vector' in extensions and not vector_ok and 'vector' not in unsupported:
        add('odoo.vector-image-missing', 'stop', '這個資料庫使用了 vector 擴充功能，而這台沒有含 pgvector 的 PostgreSQL 16 映像'
            f'（{PG16_IMAGES[0]}），而且下載不到，無法讀出它的資料。',
            action='請讓這台連上網路後重新檢查（會自動下載映像），或先把含 pgvector 的映像放進這台。')
    if details.get('superuser_objects'):
        add('odoo.superuser-objects', 'confirm', '這個資料庫含有只有資料庫超級使用者才能建立的物件；這台不會建立它們，只略過它們，其他資料照搬。'
            '如果其他資料要靠它們才放得進去，匯入會停下，這台不會有變更。', sorted(details['superuser_objects']))
    if ha_major is None or target_major is None or ha_major > target_major:
        add('odoo.pg-newer', 'stop', f'HA 的 PostgreSQL 是 {ha_major or "未知"} 版，這台是 {target_major or "未知"} 版；'
            '只能從相同或較舊的版本搬過來。', action='請讓這台的 PostgreSQL 版本不低於 HA 的，再匯入這個資料庫。')
    if details['mail_servers_active']:
        add('odoo.mail-servers-active', 'notice', f'這個資料庫有 {details["mail_servers_active"]} 個啟用中的外寄郵件伺服器，'
            '搬過來後會開始寄信（包括 HA 上還沒寄出的信和每天的提醒信）；正式搬家前請先停掉 HA 那邊的 Odoo，避免兩邊各寄一次。')
    if details['crons_active']:
        add('odoo.crons-active', 'notice', f'這個資料庫有 {details["crons_active"]} 個啟用中的排程動作，搬過來後會在這台執行。')
    if details.get('website_domains'):
        add('odoo.website-domains', 'notice', '網站原本使用的網域會改成這台的網址。', details['website_domains'][:5])
    if others:
        add('odoo.databases-left', 'confirm', MSG_LEFT_DATABASES.format(database=name), sorted(others))
    return issues, copy, unavailable


def _names(items, limit=20):
    items = list(items)
    shown = '、'.join(items[:limit])
    return shown + (f' 等 {len(items)} 個' if len(items) > limit else '')


def custom_module_view(name, candidate):
    manifest = candidate.get('manifest') or {}
    return {'name': name, 'version': manifest.get('version') or '', 'from': candidate['from']}


def python_and_bins(candidates):
    python, binaries = set(), set()
    for candidate in candidates.values():
        manifest = candidate.get('manifest') or {}
        python.update(d for d in manifest.get('python') or [] if PY_DEP_RE.fullmatch(d))
        binaries.update(d for d in manifest.get('bin') or [] if BIN_DEP_RE.fullmatch(d))
    return python, binaries


# ====================================================================== converted data

def filter_toc(text, skip=()):
    """A pg_restore list without the EXTENSION entries and their comments (the extensions are created first, as
    postgres; restore-online.sh's awk filter, matched on the entry type field only). `skip`: object kinds (SUPERUSER_KINDS)
    that are left out as well, with their comments and security labels: the entry is commented out (`;`), as pg_restore's
    list syntax allows (OD-41, OD-58)."""
    kinds = '|'.join(re.escape(kind) for kind in skip)
    left_out = re.compile(r'\s*\d+;\s+\d+\s+\d+\s+(?:(?:' + kinds + r')\s|(?:COMMENT|SECURITY LABEL)\s+-\s+(?:' + kinds
                          + r')\s)') if kinds else None
    kept = []
    for line in text.splitlines():
        if re.match(r'\s*\d+;\s+\d+\s+\d+\s+EXTENSION\s', line) or \
                re.match(r'\s*\d+;\s+\d+\s+\d+\s+COMMENT\s+-\s+EXTENSION\s', line):
            continue
        if left_out is not None and left_out.match(line):
            line = ';' + line
        kept.append(line)
    return '\n'.join(kept) + '\n'


def settings_to_carry(live_rows, new_rows):
    """[(name, value)] of PostgreSQL settings the live cluster sets in its configuration (postgresql.conf, ALTER
    SYSTEM) that the new cluster has otherwise; locations, ports, commands and build constants are never carried."""
    def rows(value):
        result = {}
        for row in value if isinstance(value, list) else []:
            if (isinstance(row, list) and len(row) == 4 and all(isinstance(x, str) for x in row)
                    and SETTING_NAME_RE.fullmatch(row[0])):
                result[row[0]] = (row[1], row[2], row[3])
        return result
    live, new = rows(live_rows), rows(new_rows)
    carry = []
    for name, (value, source, context) in sorted(live.items()):
        if source != 'configuration file' or name in SETTINGS_SKIPPED or context == 'internal':
            continue
        if 'command' in name or 'password' in name or 'passphrase' in name:
            continue
        if new.get(name, (None,))[0] == value or not SETTING_VALUE_RE.fullmatch(value):
            continue
        carry.append((name, value))
    return carry[:100]


def split_list_setting(text):
    """The elements of a list setting as PostgreSQL prints it (`"$user", public`: comma separated, double quotes around
    an element, `""` inside them); None when the text is not such a list."""
    items, current, quoted, was_quoted, i = [], [], False, False, 0
    while i < len(text):
        char = text[i]
        if quoted:
            if char == '"' and text[i + 1:i + 2] == '"':
                current.append('"')
                i += 1
            elif char == '"':
                quoted = False
            else:
                current.append(char)
        elif char == '"':
            if ''.join(current).strip():
                return None
            current, quoted, was_quoted = [], True, True
        elif char == ',':
            item = ''.join(current) if was_quoted else ''.join(current).strip()
            if not item:
                return None
            items.append(item)
            current, was_quoted = [], False
        elif was_quoted and not char.isspace():
            return None
        else:
            current.append(char)
        i += 1
    if quoted:
        return None
    item = ''.join(current) if was_quoted else ''.join(current).strip()
    if item or was_quoted:
        items.append(item)
    return items if items and all(items) else None


def alter_system_sql(name, value):
    """`ALTER SYSTEM SET <name> TO <value>;` for one carried setting (list settings: one literal per element); None
    when a list setting's text cannot be split."""
    if not SETTING_NAME_RE.fullmatch(name):
        raise BackupError('internal-error', '資料庫設定名稱格式不正確。')
    if name in LIST_SETTINGS:
        items = split_list_setting(value)
        if items is None:
            return None
        return f'ALTER SYSTEM SET {name} TO {", ".join(sql_literal(item) for item in items)};'
    return f'ALTER SYSTEM SET {name} TO {sql_literal(value)};'


def carry_settings(work, app, live, cluster):
    """Write the PostgreSQL settings the live cluster sets in its configuration (settings_to_carry) into the new
    cluster's postgresql.auto.conf: one ALTER SYSTEM per psql call, outside any transaction block (review C-19), then
    a reload and a read-back of pg_file_settings (every carried setting there, without an error). A setting that cannot be
    written, or that the new cluster refuses, is taken out again (`ALTER SYSTEM RESET`) and stays at the default of the new
    cluster, which never harms the data; they are listed in one reminder (OD-69). Returns the names that were carried."""
    live_rows = _read_live_json(work, app, live, SETTINGS_SQL, 'postgres')
    carried, skipped = [], []
    for name, value in settings_to_carry(live_rows, cluster.query_json(SETTINGS_SQL)):
        sql = alter_system_sql(name, value)
        if sql is None:
            skipped.append(name)
            continue
        cluster.statement(sql)
        carried.append(name)
    if carried:
        cluster.statement('SELECT pg_reload_conf();')
        bad = _unaccepted(cluster, carried)
        if bad:
            for name in bad:
                cluster.statement(f'ALTER SYSTEM RESET {name};')
            cluster.statement('SELECT pg_reload_conf();')
            still = _unaccepted(cluster, [], only_errors=True)
            if still:
                raise BackupError('job-failed', f'沿用這台 PostgreSQL 的設定失敗：{"、".join(still[:10])}。')
            carried = [name for name in carried if name not in bad]
            skipped += bad
    if skipped:
        work.log(f'這些 PostgreSQL 設定的格式無法沿用，維持新叢集的預設值：{"、".join(skipped)}')
        _sink(work, app).notice('odoo.settings-not-carried', '這台 PostgreSQL 調整過的這些設定沒有沿用，新叢集用預設值，'
                                '資料不受影響；需要時請匯入後再調整。', skipped)
    if carried:
        work.log(f'沿用這台 PostgreSQL 的設定：{"、".join(carried)}')
    return carried


def _unaccepted(cluster, wanted, *, only_errors=False):
    """The names of `wanted` that the new cluster's postgresql.auto.conf does not hold or holds with an error (pg_file_settings);
    `only_errors`: every setting of that file that has an error."""
    rows = cluster.query_json(FILE_SETTINGS_SQL)
    written = {}
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, list) and len(row) == 3 and all(isinstance(x, str) for x in row):
            written[row[0].lower()] = row[2]
    if only_errors:
        return [name for name, error in written.items() if error]
    return [name for name in wanted if name not in written or written[name]]


def marker_ok(value, image_id):
    """The live upgrade-gate marker JSON when it names the live Odoo image (`{"digest": <image ID>, ...}`)."""
    try:
        doc = util.loads_strict(value.encode('utf-8'), max_bytes=4096) if isinstance(value, str) else None
    except ValueError:
        doc = None
    return isinstance(doc, dict) and doc.get('digest') == image_id and isinstance(doc.get('core_date'), str)


def _live_tar(path, what):
    """A tar the owner's side wrote (a volume export, a folder pack): read in stream mode; a parse error is the job's
    failure, never an internal error (nested.check_volume / check_dir then check every member of the result)."""
    try:
        return tarfile.open(path, 'r|', encoding=habackup.ENCODING, errors=habackup.ERRORS)
    except tarfile.TarError:
        raise BackupError('job-failed', f'{what}的匯出內容無法讀取。') from None


def web_data_tar(live_tar, out, *, sessions_ids, sessions_mode=0o700):
    """Copy the live data dir export (`podman volume export`) into the FileTar `out` without `filestore/odoo/**` and
    `sessions/**`; adds an empty `sessions/` owned like the live one (or `sessions_ids`). Returns the owner of the live
    root entry."""
    try:
        return _web_data_tar(live_tar, out, sessions_ids=sessions_ids, sessions_mode=sessions_mode)
    except tarfile.TarError:
        raise BackupError('job-failed', '這台 Odoo 資料卷的匯出內容無法讀取。') from None


def _web_data_tar(live_tar, out, *, sessions_ids, sessions_mode):
    root_ids = None
    with _live_tar(live_tar, '這台 Odoo 資料卷') as tar:
        for member in tar:
            name = _norm(member.name)
            if name is None:
                raise BackupError('job-failed', '這台 Odoo 資料卷的匯出內容格式不正確。')
            if _under(name, 'filestore/odoo') or _under(name, 'sessions'):
                if name == 'sessions' and member.isdir():
                    sessions_ids = (member.uid, member.gid)
                    sessions_mode = member.mode & 0o7777
                continue
            if name == '.':
                root_ids = (member.uid, member.gid)
            info = _copy_info(member, name)
            out.add_member(info, tar.extractfile(member) if member.isfile() else None)
            tar.members.clear()
    uid, gid = sessions_ids
    out.add_member(_info('sessions', 'dir', mode=sessions_mode, uid=uid, gid=gid, mtime=time.time()))
    return root_ids


def _norm(name):
    try:
        return habackup.normalize(name)
    except BackupError:
        return None


def _copy_info(member, name):
    info = tarfile.TarInfo(name)
    info.type = member.type
    info.mode, info.uid, info.gid = member.mode & 0o7777, member.uid, member.gid
    info.uname = info.gname = ''
    info.mtime = member.mtime
    info.size = member.size if member.isfile() else 0
    info.linkname = member.linkname
    info.pax_headers = {k: v for k, v in member.pax_headers.items() if k.startswith('SCHILY.xattr.user.')}
    return info


def addons_dir_tar(live_tar, modules_tar, out, *, copy, mtime=None):
    """The custom modules folder: the live folder (DIR_HELPER pack, names `./…`) without the modules `copy` replaces,
    plus those modules from `modules_tar` (`<source>/<module>/**`) as `./<module>/**`, owned by the app owner (0:0 in
    his namespace), dirs 0755, files 0644 (0755 when executable). `copy`: {module: source label}."""
    try:
        _addons_dir_tar(live_tar, modules_tar, out, copy=copy, mtime=mtime)
    except tarfile.TarError:
        raise BackupError('job-failed', '自訂模組資料夾的匯出內容無法讀取。') from None


def _addons_dir_tar(live_tar, modules_tar, out, *, copy, mtime):
    sources = {module: source for module, source in copy.items()}
    with _live_tar(live_tar, '自訂模組資料夾') as tar:
        for member in tar:
            name = _norm(member.name)
            if name is None:
                raise BackupError('job-failed', '自訂模組資料夾的匯出內容格式不正確。')
            top = name.split('/', 1)[0]
            if name != '.' and top in sources:
                tar.members.clear()
                continue
            info = _copy_info(member, './' if name == '.' else f'./{name}')
            out.add_member(info, tar.extractfile(member) if member.isfile() else None)
            tar.members.clear()
    if not sources:
        return
    with tarfile.open(modules_tar, 'r|', encoding=habackup.ENCODING, errors=habackup.ERRORS) as tar:
        for member in tar:
            name = member.name
            for module, source in sources.items():
                prefix = f'{source}/{module}'
                if _under(name, prefix):
                    rest = name[len(prefix):].lstrip('/')
                    target = f'./{module}' + (f'/{rest}' if rest else '')
                    if member.isdir():
                        info = _info(target, 'dir', mode=0o755, uid=0, gid=0, mtime=member.mtime)
                        out.add_member(info)
                    elif member.isfile():
                        mode = 0o755 if member.mode & 0o111 else 0o644
                        info = _info(target, 'file', mode=mode, uid=0, gid=0, mtime=member.mtime, size=member.size)
                        out.add_member(info, tar.extractfile(member))
                    break
            tar.members.clear()
    for module in sources:  # a module whose tar has no directory entry for its root still gets one
        if f'./{module}' not in out.names:
            out.add_member(_info(f'./{module}', 'dir', mode=0o755, uid=0, gid=0, mtime=mtime or time.time()))


def check_volume_tar(path, ids):
    """nested.check_volume with the owner's ids; job-failed with the reason when podman could not import it."""
    try:
        return nested.check_volume(path, ids=ids)
    except BackupError as error:
        raise BackupError('job-failed', f'轉換後的資料卷內容無法匯入（{error.message}）。',
                          reason=(error.details or {}).get('reason')) from None


def check_dir_tar(path, ids):
    try:
        return nested.check_dir(path, ids=ids)
    except BackupError as error:
        raise BackupError('job-failed', f'轉換後的自訂模組資料夾無法還原（{error.message}）。',
                          reason=(error.details or {}).get('reason')) from None


# ====================================================================== the job steps (haimport.Work drives them)

PG16_PINNED = ('docker.io/library/postgres:16.15-alpine'
               '@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139')


def pick_pg16(work, app):
    """The PostgreSQL 16 image that opens HA's cluster: the first one on the device of PG16_IMAGES, else the pinned
    official image, downloaded as the app's owner (`hatarget.ensure_image`: a second try, then only this app stops, with
    the reason: OD-23)."""
    for ref in PG16_IMAGES:
        if hatarget.image_present(work, app, ref):
            return ref
    work.log('這台沒有 PostgreSQL 16 映像，下載固定版本的 postgres:16.15-alpine')
    hatarget.ensure_image(work, app, PG16_PINNED)
    return PG16_PINNED


def _sink(work, app):
    """The issues of this app (a work without sinks -- a harness -- collects nowhere)."""
    maker = getattr(work, 'sink', None)
    app_id = getattr(app, 'id', None) or APP_ID
    return maker(app_id) if callable(maker) else haissues.Sink(app_id)


class Target:
    """The app's catalog items the import fills, resolved against the live Quadlet files. What the app settings hold beyond
    the two volumes and the custom modules folder of the tenant Odoo -- other volumes, other folders -- is `extra_volumes`
    and `extra_dirs`: carried as they are (OD-12, OD-13). The custom modules folder counts only when the settings declare
    it too (`addons_rel` None otherwise: OD-72)."""

    def __init__(self, work, app, sink=None):
        self.app = app
        runner = work.runner(app)
        sink = sink if sink is not None else _sink(work, app)
        self.live = Live(work.quadlets(app), runner.home)
        if self.live.skipped_mounts:
            sink.notice('odoo.mount-skipped', '這台 Odoo 的容器有掛載不是 Odoo 資料的路徑（例如時區檔），匯入不會用到它們，已略過；'
                        '它們在這台維持原樣。', [f'{file}：{target}' for file, target in self.live.skipped_mounts])
        declared = [v['name'] for v in app.volumes]
        self.db_volume = self.live.db_volume
        web = next((source for source, target, _o in self.live.web_mounts if target == '/var/lib/odoo'), None)
        self.web_volume = web
        extra = next(((source, target) for source, target, _o in self.live.web_mounts
                      if source.startswith(runner.home.rstrip('/') + '/')), None)
        self.addons_rel = extra[0][len(runner.home.rstrip('/')) + 1:] if extra else None
        self.addons_target = extra[1] if extra else '/mnt/extra-addons'
        dirs = [d['path'] for d in app.data_dirs]
        problems = []
        if app.postgres:
            problems.append('應用設定含有資料庫匯出項目（不是冷備份的 tenant Odoo）')
        if web is None:
            problems.append('Odoo 的資料沒有掛在 /var/lib/odoo')
        elif not {self.db_volume, web} <= set(declared):
            problems.append('資料卷和 Odoo 的 Quadlet 設定不一致')
        if problems:
            raise haissues.stopped(Issue('odoo.layout-unsupported', 'stop',
                                         f'這台的 Odoo 應用設定不是 HA 匯入支援的樣子：{"；".join(problems)}。',
                                         action='請到「應用設定」修正這台 Odoo 的設定，再重新檢查。'),
                                   'incompatible', app=app.id)
        if self.addons_rel is not None and self.addons_rel not in dirs:
            sink.notice('odoo.addons-folder-undeclared', '這台 Odoo 掛了自訂模組資料夾，但應用設定沒有列它，所以 HA 的自訂模組不會放進去；'
                        '需要它們時，請把這個資料夾加進應用設定後重新檢查。', [self.addons_rel])
            self.addons_rel = None
        self.addons_index = dirs.index(self.addons_rel) if self.addons_rel is not None else None
        self.extra_volumes, self.extra_dirs = hatarget.extras(
            app, handled_volumes=(self.db_volume, web),
            handled_dirs=(self.addons_rel,) if self.addons_rel is not None else ())
        if self.extra_volumes or self.extra_dirs:
            sink.auto('odoo.extras-carried', '這台 Odoo 的應用設定還有其他資料卷或資料夾，匯入時會照這台現在的內容原樣帶過去，'
                      '不會被 HA 的資料取代。', [*self.extra_volumes, *self.extra_dirs])


def target_pg_major(work, app, image):
    info = work.adapter(app).image_inspect(image)
    for item in (info or {}).get('env', []):
        if isinstance(item, str) and item.startswith('PG_MAJOR='):
            try:
                return int(item.split('=', 1)[1].split('.')[0])
            except ValueError:
                return None
    return None


def _ha_major(src):
    try:
        return int((src.pg_version or '').split('.')[0])
    except ValueError:
        return None


def member_pass(work, app, tmp, pg_ids, *, filestore_db=None, filestore=None, modules=None):
    """Stream the add-on's cluster into the throwaway volume `hapg` (and, for a conversion, the filestore and the
    custom module candidates into staging); then HA's share folder modules. Returns (Source, candidates)."""
    member = work.addon_member(SLUG)
    report = habackup.Report()
    holder = {}

    def produce(out):
        sink = PgSink(out, *pg_ids, guard=work.guard)
        with work.open(member) as stream:
            holder['src'] = scan_member(stream, report, pg=sink, filestore_db=filestore_db, filestore=filestore,
                                        modules=modules, guard=work.guard, checkpoint=work.checkpoint)
        sink.close()

    tmp.volume('hapg')
    tmp.volume_import('hapg', produce)
    src = holder['src']
    for note in report.warnings():
        work.log(note)
    candidates = dict(src.modules)
    share = work.share_member()
    if share is not None:
        share_report = habackup.Report()
        with work.open(share) as stream:
            for name, info in scan_share(stream, share_report, modules=modules, checkpoint=work.checkpoint).items():
                candidates.setdefault(name, info)  # data/addons comes before /share/odoo_addons on HA's path
    work.log(f'HA 的 Odoo：PostgreSQL {src.pg_version or "?"}，{src.pg_files} 個資料庫檔案'
             f'（{_mib(src.pg_bytes)}），{len(src.filestore)} 個附件資料夾，{len(candidates)} 個自訂模組')
    return src, candidates


def _mib(n):
    return f'{n / 1048576:.1f} MiB'


def ha_server_args():
    args = ['postgres']
    for setting in HA_SERVER_SETTINGS:
        args += ['-c', setting]
    return args


def start_ha_cluster(work, tmp, image, *, size=None):
    """PostgreSQL 16 on HA's (untrusted) cluster: every library/command setting overridden on the command line, the
    data volume mounted noexec/nosuid/nodev (no library of HA's can be loaded from it), a read-only root file system,
    no network (review HA-SEC-01). HA's catalog and its per-role/per-database settings can still make this server lie
    and run commands inside the container (security review 2026-11-23 SR-2): every answer is HA's, untrusted. `size`:
    the bytes of HA's cluster when known: a big one needs its crash recovery first, and the wait for the server to accept
    connections grows with it (OD-28); the container going away still ends it at once."""
    tmp.run('hapg', image, ha_server_args(), detach=True, read_only_root=True,
            volumes=[(tmp.name('hapg'), HA_DATA, 'rw,noexec,nosuid,nodev')])
    cluster = Cluster(tmp, 'hapg', log=work.log)
    cluster.wait_ready(checkpoint=work.checkpoint, timeout=podman.scaled_timeout(PG_READY_TIMEOUT, size))
    return cluster


def superuser_kinds(toc):
    """The object kinds of a pg_restore list that only a database superuser can create (SUPERUSER_KINDS)."""
    found = []
    pattern = re.compile(r'\s*\d+;\s+\d+\s+\d+\s+(' + '|'.join(re.escape(k) for k in SUPERUSER_KINDS) + r')\s')
    for line in toc.splitlines():
        match = pattern.match(line)
        if match and match.group(1) not in found:
            found.append(match.group(1))
    return found


def ha_databases(cluster):
    rows = cluster.query_json(DATABASES_SQL)
    if not isinstance(rows, list):
        raise BackupError('job-failed', '無法讀取 HA 的資料庫清單。')
    found = []
    for row in rows[:200]:
        if isinstance(row, list) and len(row) == 4 and isinstance(row[0], str):
            found.append({'name': row[0], 'size': _int(row[1]), 'collate': str(row[2])[:64],
                          'ctype': str(row[3])[:64]})
    return found


def _valid_name(name):
    """A database name the tools can be given: 1..63 bytes of text without control characters (haimport.valid_database)."""
    return (isinstance(name, str) and bool(name) and len(name.encode('utf-8', 'surrogatepass')) <= MAX_NAME_BYTES
            and BAD_NAME_RE.search(name) is None)


def live_extensions(work, app, live):
    """{extension: trusted} of what this device's PostgreSQL image has (PostgreSQL's own word: a non-superuser may create a
    trusted one), None when it cannot be asked: the fixed list EXTENSIONS_OK then (OD-39, OD-57)."""
    try:
        rows = _read_live_json(work, app, live, AVAILABLE_EXTENSIONS_SQL, 'postgres')
    except BackupError as error:
        if haissues.is_job_wide(error) or error.code != 'job-failed':
            raise
        return None
    if not isinstance(rows, list):
        return None
    found = {}
    for row in rows[:5000]:
        if isinstance(row, list) and len(row) == 2 and isinstance(row[0], str) and EXT_NAME_RE.fullmatch(row[0]):
            found[row[0]] = row[1] is True
    return found or None


def analyse(work, app, tmp, src, candidates, cluster, live, *, image16, size=None):
    """Per HA database: {name, ok, blockers, warnings, counts…, custom_modules, _details, _copy, _issues, _unavailable}
    (`_issues`: [haissues.Issue] of that database; `ok`: none of them stops it; `blockers` and `warnings` are the same
    sentences for the pages that do not read issues); plus the target inventory and the two PostgreSQL major versions.
    A database whose own reading fails is that database's stop (OD-32, OD-33, OD-34); the others go on."""
    python, binaries = python_and_bins(candidates)
    target = target_inventory(tmp, live, python=python, binaries=binaries, size=size)
    target['extensions'] = live_extensions(work, app, live)
    target_major = target_pg_major(work, app, live.db_image)
    ha_major = _ha_major(src)
    databases = []
    extra_target = None
    for source, mount_target, _o in live.web_mounts:
        if mount_target not in ('/var/lib/odoo',) and source.startswith('/'):
            extra_target = mount_target
    listed = ha_databases(cluster)
    names = sorted(db['name'] for db in listed)
    for db in listed:
        name = db['name']
        entry = {'name': name, 'ok': False, 'blockers': [], 'warnings': [], 'partners': 0, 'users': 0,
                 'attachments': 0, 'attachment_bytes': 0, 'modules': 0, 'custom_modules': [], 'crons_active': 0,
                 'mail_servers_active': 0, 'size': db['size'], '_issues': [], '_unavailable': set()}
        databases.append(entry)

        def stop(issue_id, message, action='', entry=entry, name=name):
            entry['_issues'].append(Issue(issue_id, 'stop', message, action=action, database=name))

        if not _valid_name(name):
            stop('odoo.database-name', '這個資料庫的名稱含有控制字元，無法交給資料庫工具處理。',
                 '請在 HA 把這個資料庫改成一般的名稱後重新備份；其他資料庫不受影響。')
        else:
            try:
                details = database_details(cluster, name)
            except BackupError as error:
                if error.code != 'job-failed' or haissues.is_job_wide(error):
                    raise
                message = error.message if error.message in (MSG_MODULES_UNREADABLE, MSG_CONTENT_UNREADABLE) \
                    else MSG_CONTENT_UNREADABLE
                stop('odoo.db-unreadable', message, '其他資料庫不受影響；請在 HA 確認這個資料庫能正常使用後重新備份。')
                details = False
            if details is None:
                stop('odoo.not-odoo', MSG_NOT_ODOO, '其他資料庫不受影響。')
            elif details:
                issues, copy, unavailable = database_issues(
                    name, details, target, candidates, ha_major=ha_major, target_major=target_major,
                    extra_target=extra_target or '/mnt/extra-addons', vector_ok='pgvector' in image16,
                    others=[other for other in names if other != name])
                files, size_bytes = src.filestore.get(name, [0, 0])
                if details['attachments'] and not files:
                    issues.append(Issue('odoo.filestore-missing', 'notice', '這個資料庫在 HA 備份裡沒有附件檔案（filestore）；'
                                        '搬過來後附件會打不開。', database=name))
                entry.update({'partners': details['partners'], 'users': details['users'],
                              'attachments': details['attachments'], 'attachment_bytes': details['attachment_bytes'],
                              'modules': sum(1 for _n, _v, state in details['modules'] if state == 'installed'),
                              'custom_modules': [custom_module_view(module, cand) for module, cand in sorted(copy.items())],
                              'crons_active': details['crons_active'], 'mail_servers_active': details['mail_servers_active'],
                              'size': details['size'], 'filestore_files': files, 'filestore_bytes': size_bytes,
                              '_details': details, '_copy': copy, '_unavailable': unavailable})
                entry['_issues'].extend(issues)
        entry['ok'] = not any(issue.level == 'stop' for issue in entry['_issues'])
        entry['blockers'] = [issue.message for issue in entry['_issues'] if issue.level in ('stop', 'confirm')]
        entry['warnings'] = [issue.message for issue in entry['_issues'] if issue.level in ('auto', 'notice')]
    return databases, target, target_major, ha_major


def public_database(entry):
    return {key: value for key, value in entry.items() if not key.startswith('_')}


def live_image_id(work, app, live):
    """The ID of this device's Odoo image; an image this device does not have is downloaded first (OD-14: when that fails
    only this app stops, with the reason, and nothing has changed)."""
    hatarget.ensure_image(work, app, live.web_image)
    info = work.adapter(app).image_inspect(live.web_image)
    if not info or not DIGEST_RE.fullmatch(info.get('id') or ''):
        raise BackupError('incompatible', '找不到這台 Odoo 使用的映像。', app=app.id)
    return info['id']


def image_release(work, app, live):
    """The release of this device's Odoo image (`ODOO_RELEASE`, e.g. 18.0.20260926: the `core_date` of the upgrade
    marker), None when the image does not say."""
    info = work.adapter(app).image_inspect(live.web_image) or {}
    for item in info.get('env') or []:
        if isinstance(item, str) and item.startswith('ODOO_RELEASE='):
            value = item.split('=', 1)[1]
            return value if re.fullmatch(r'[0-9A-Za-z._-]{1,64}', value) else None
    return None


def _read(work, app, tmp, live, image16, *, size=None):
    """Stream HA's cluster into a throwaway volume, open it with the PostgreSQL 16 image `image16` and read every database;
    the server and its volume are removed again whatever happens. Returns (Source, databases, target)."""
    pg_ids = tmp.user_ids('ids-pg', image16, 'postgres')
    try:
        src, candidates = member_pass(work, app, tmp, pg_ids)
        work.phase('check')
        cluster = start_ha_cluster(work, tmp, image16, size=src.pg_bytes)
        databases, target, _target_major, _ha_major_ = analyse(work, app, tmp, src, candidates, cluster, live,
                                                               image16=image16, size=size)
    finally:
        tmp.remove('hapg')
        tmp.remove_volume('hapg')
    return src, databases, target


def check(work, app):
    """The check job's Odoo part: (app result fields, internal notes). This device's side is read first and made ready,
    as the conversion does it (review C-05): the image (downloaded when it is not here), the configuration, the database
    (started when it is stopped), the upgrade marker, the account. Everything found goes to the app's issues
    (`work.sink`); each HA database has its own, so one that cannot move never keeps the others from it (OD-32..OD-35).
    `choices.database`: what can be picked; `odoo.databases[]` keeps the sentences for the older pages."""
    sink = work.sink(app)
    tmp = work.temp(app)
    target_items = Target(work, app, sink)
    live = target_items.live
    conf = read_conf(work, app, live)
    live.apply_conf(conf)
    image_id = live_image_id(work, app, live)
    hatarget.ensure_image(work, app, live.db_image)
    live_settings(work, app, live, image_id, sink)
    live_role(work, app, live, conf, sink)
    image16 = pick_pg16(work, app)
    size = hatarget.size_hint(getattr(work, 'ha', None))
    src, databases, target = _read(work, app, tmp, live, image16, size=size)
    if 'pgvector' not in image16 and any('vector' in (entry.get('_details') or {}).get('extensions', ())
                                         for entry in databases):
        try:   # OD-40: a database uses vector, the image that read it cannot: the one that can is downloaded, and it reads again
            hatarget.ensure_image(work, app, PG16_IMAGES[0])
        except BackupError as error:
            if haissues.is_job_wide(error) or error.code in ('insufficient-space', 'busy'):
                raise
        else:
            image16 = PG16_IMAGES[0]
            src, databases, target = _read(work, app, tmp, live, image16, size=size)
    if target.get('broken'):
        sink.notice('odoo.target-modules-partial', '這台 Odoo 有些模組讀不出來（可能壞了或設定錯了），比對時略過了它們；'
                    '資料庫要用到它們的話會被當成缺模組。', target['broken'])
    for entry in databases:
        sink.extend(entry['_issues'])
    if not databases:
        sink.stop('odoo.no-database', 'HA 的 Odoo 沒有任何資料庫，沒有資料可以搬。', action='請先在 HA 的 Odoo 建立資料庫並備份，再重新檢查。')
    elif not any(entry['ok'] for entry in databases):
        sink.stop('odoo.no-movable-database', 'HA 的 Odoo 資料庫都不能搬過來（原因見各資料庫）。',
                  action='請依各資料庫的說明處理後重新檢查；這台的 Odoo 不會有任何變更。')
    return {'target_version': target['version'], 'pg_bytes': src.pg_bytes,
            'filestore_bytes': sum(size_bytes for _files, size_bytes in src.filestore.values()),
            'module_bytes': src.module_bytes,
            'odoo': {'databases': [public_database(entry) for entry in databases]},
            'choices': {'database': [{'value': entry['name'], 'label': entry['name'],
                                      'ok': entry['ok'] and _valid_name(entry['name'])} for entry in databases]}}


def check_blockers(found):
    """Blockers of a check result that does not carry its own `choices` (an older module, a harness): none at all, or none
    that can move. `check` says both through its issues and has nothing left to add here."""
    if 'choices' in found:
        return []
    databases = found['odoo']['databases']
    if not databases:
        return ['HA 的 Odoo 沒有任何資料庫。']
    if not any(db['ok'] for db in databases):
        return ['HA 的 Odoo 資料庫都不能搬過來（原因見各資料庫）。']
    return []


def _text_names(items, limit=10):
    items = [str(item)[:60] for item in items]
    return '、'.join(items[:limit]) + (f' 等 {len(items)} 個' if len(items) > limit else '')


def import_texts(data):
    """(notes, reminders) of a conversion (haimport.import_texts; CONTRACT section 7 HaImport)."""
    notes = ['Odoo 的使用者帳號和密碼會換成 HA 那邊的，這台原本的 Odoo 管理者密碼不再適用。']
    copied = [m['name'] for m in data.get('custom_modules') or []]
    if copied:
        notes.append(f'HA 的 Odoo 自訂模組 {_text_names(copied)} 會一起放進這台 Odoo 的自訂模組資料夾。')
    domains = data.get('website_domains') or []
    if domains:
        notes.append(f'Odoo 網站原本使用的網域 {_text_names(domains, 5)} 會改成這台的網址。')
    left = data.get('left_databases') or []
    if left:
        notes.append(f'HA 的其他 Odoo 資料庫（{_text_names(left, 5)}）沒有搬過來，會留在 HA；這台 Odoo 一次只放一個資料庫。')
    return notes, ['匯入後請用 HA 那邊的 Odoo 帳號和密碼登入。']


# -------------------------------------------------------------------- convert

def _read_live_json(work, app, live, sql, database, *, size=None):
    """One JSON cell from the LIVE database container (read only; as its superuser over its socket). A database that is
    stopped is started first and put back afterwards (hacommon.live_json, OD-15); only a database that still cannot be read
    stops this app, and the message says why."""
    from . import hacommon
    return hacommon.live_json(work, app, live.db_container, live.db_user, database, sql, size=size)


def live_role(work, app, live, conf=None, sink=None):
    """The role of this device's Odoo in the new cluster: its password verifier (masked in every log of this process) and
    attributes as the live cluster has them. A role that does not exist (OD-20) or has no usable password (OD-21) is made
    from this device's own configuration (`conf`: the account and password its Odoo logs in with); a superuser (OD-22) is
    made an ordinary role, as the tenant install has it. Only when the configuration has no password to make one with
    does this app stop. A password in the configuration is never in a message, argv or log."""
    from . import jobs
    sink = sink if sink is not None else _sink(work, app)
    conf = conf or {}
    doc = _read_live_json(work, app, live, live_role_sql(live.db_role), 'postgres')
    role = dict(STANDARD_ROLE)

    def from_conf():
        password = conf.get('db_password')
        if password is None:
            sink.refuse('odoo.role-unusable', '這台 Odoo 的資料庫帳號沒有可用的密碼，設定檔裡也沒有密碼可以重新設定，無法匯入。',
                        action='請先在這台確認 Odoo 能正常登入資料庫（設定檔要有 db_user 和 db_password），再重新檢查。',
                        items=[live.db_role])
        return password

    if not isinstance(doc, dict):
        role['password'] = from_conf()
        sink.auto('odoo.role-created', '這台的資料庫沒有 Odoo 的資料庫帳號，匯入時會照這台 Odoo 設定檔裡的帳號和密碼建立它。',
                  [live.db_role])
    else:
        verifier = doc.get('password')
        if isinstance(verifier, str) and VERIFIER_RE.fullmatch(verifier):
            role['password'] = verifier
        else:
            role['password'] = from_conf()
            sink.auto('odoo.role-password-reset', '這台 Odoo 的資料庫帳號沒有可用的密碼設定，匯入時會用這台 Odoo 設定檔裡的密碼重新設定它。',
                      [live.db_role])
        if doc.get('super') is not False:
            sink.auto('odoo.role-normalised', '這台 Odoo 的資料庫帳號是超級使用者；匯入後新資料庫裡它會是一般帳號'
                      '（HA 來的內容不能以超級使用者權限執行）。', [live.db_role])
        else:
            for key in ('login', 'createdb', 'createrole', 'replication', 'bypassrls', 'connlimit'):
                if key in doc:
                    role[key] = doc[key]
    jobs.mask_secret(role['password'])
    return role


def role_sql(role, name=DEFAULT_DB_ROLE):
    flags = ['LOGIN' if role.get('login') else 'NOLOGIN', 'NOSUPERUSER',
             'CREATEDB' if role.get('createdb') else 'NOCREATEDB',
             'CREATEROLE' if role.get('createrole') else 'NOCREATEROLE',
             'REPLICATION' if role.get('replication') else 'NOREPLICATION',
             'BYPASSRLS' if role.get('bypassrls') else 'NOBYPASSRLS']
    limit = role.get('connlimit')
    if isinstance(limit, int) and not isinstance(limit, bool) and limit >= 0:
        flags.append(f'CONNECTION LIMIT {limit}')
    ident = name if name == DEFAULT_DB_ROLE else pg_ident(name)
    return f"CREATE ROLE {ident} {' '.join(flags)} PASSWORD {sql_literal(role['password'])};\n"


def engine_marker(work, app, live, image_id, sink):
    """The upgrade-gate marker of this device's Odoo image, made by the engine when the live database has none or one of
    another image (OD-18): `{"digest": <image ID>, "core_date": <the image's ODOO_RELEASE>}`, the shape the tenant install
    writes. Without a release the image does not say, there is no honest marker to write: this app stops."""
    release = image_release(work, app, live)
    if release is None:
        sink.refuse('odoo.marker-unwritable', '這台 Odoo 的升級標記不存在或不是目前映像的，而且讀不到這個映像的發行日期，沒辦法寫上正確的標記。',
                    action='請先讓這台 Odoo 啟動並完成升級（它會自己寫上升級標記），再重新檢查。')
    sink.auto('odoo.marker-written', '這台 Odoo 的升級標記不存在或不是目前映像的，匯入時由程式寫上目前映像的標記'
              '（HA 的資料庫和這台的模組版本相同，不需要再升級）。')
    return json.dumps({'digest': image_id, 'core_date': release}, separators=(',', ':'))


def live_settings(work, app, live, image_id, sink=None):
    """What the converted database takes from this device's Odoo: its address, whether it is frozen and the upgrade
    marker. What cannot be read gets the default and a reminder (OD-16, OD-17, OD-19: no address means Odoo makes its own at
    the first login); a marker that is missing or of another image is written by the engine (OD-18)."""
    sink = sink if sink is not None else _sink(work, app)
    table = _read_live_json(work, app, live, LIVE_TABLE_SQL, live.db_name)
    doc = _read_live_json(work, app, live, LIVE_SQL, live.db_name) if table is True else None
    if not isinstance(doc, dict):
        sink.notice('odoo.settings-unreadable', '讀不到這台 Odoo 的網址設定，改用預設網址（Odoo 會在第一次登入時依連線的網址自己設定）；'
                    '匯入後請確認 Odoo 的網址是否正確。')
        doc = {}
    base_url = doc.get('base_url')
    if base_url is not None and (not isinstance(base_url, str) or len(base_url) > 2048):
        sink.notice('odoo.base-url-invalid', '這台 Odoo 的網址設定格式不正確，改用預設網址；匯入後請確認 Odoo 的網址是否正確。')
        base_url = None
    freeze = doc.get('freeze')
    if freeze is not None and (not isinstance(freeze, str) or len(freeze) > 64):
        freeze = None
    marker = doc.get('marker')
    if not marker_ok(marker, image_id):
        marker = engine_marker(work, app, live, image_id, sink)
    return {'base_url': base_url, 'freeze': freeze, 'marker': marker}


def settings_sql(live_values):
    """Target address, upgrade-gate marker (copied from the live database) and no attempt marker."""
    lines = []

    def upsert(key, value):
        lines.append(f'INSERT INTO ir_config_parameter (key, value, create_uid, create_date, write_uid, write_date) '
                     f"VALUES ({sql_literal(key)}, {sql_literal(value)}, 1, now() AT TIME ZONE 'UTC', 1, "
                     f"now() AT TIME ZONE 'UTC') ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, "
                     f"write_date = EXCLUDED.write_date;")

    if live_values['base_url'] is not None:
        upsert('web.base.url', live_values['base_url'])
    else:
        lines.append("DELETE FROM ir_config_parameter WHERE key = 'web.base.url';")
    if live_values['freeze'] is not None:
        upsert('web.base.url.freeze', live_values['freeze'])
    else:
        lines.append("DELETE FROM ir_config_parameter WHERE key = 'web.base.url.freeze';")
    upsert('woow_paas_platform.upgrade_done', live_values['marker'])
    lines.append("DELETE FROM ir_config_parameter WHERE key = 'woow_paas_platform.upgrade_attempt';")
    return '\n'.join(lines) + '\n'


NEW_UUID_SQL = ("INSERT INTO ir_config_parameter (key, value, create_uid, create_date, write_uid, write_date) "
                "VALUES ('database.uuid', gen_random_uuid()::text, 1, now() AT TIME ZONE 'UTC', 1, "
                "now() AT TIME ZONE 'UTC') ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, "
                "write_date = EXCLUDED.write_date;\n")


def verify_converted(doc, details, target, copy, live_values, *, test_mode, old_uuid, unavailable=()):
    """Problems (zh-TW) of the converted database against what the check promised; any of them stops this conversion.
    Every module is as HA's database had it: installed ones with the version of the target (or of the custom copy), the
    ones still waiting for an installation or upgrade in the very state HA had (OD-61); `unavailable` (modules the customer
    confirmed will not work here) are only compared with HA's own version. What is only a reminder (the address, the
    website domains, OD-66, OD-67) is `converted_notes`."""
    problems = []
    if not isinstance(doc, dict):
        return ['無法讀取轉換後的資料庫。']
    modules = parse_modules(doc.get('modules'))
    ha_rows = {name: (version, state) for name, version, state in details['modules']}
    seen = {}
    for name, version, state in modules:
        seen[name] = version
        expected = ha_rows.get(name)
        if expected is not None and state != expected[1]:
            problems.append(f'模組 {name} 的狀態是 {state}，和 HA 的 {expected[1]} 不同')
            continue
        if state != 'installed':
            continue
        effective = target['modules'].get(name)
        wanted = ((copy[name].get('manifest') or {}).get('version') if name in copy
                  else expected[0] if name in unavailable and expected is not None
                  else effective[0] if effective else None)
        if wanted is None or not same_version(version, wanted):
            problems.append(f'模組 {name} 的版本 {version} 和這台的 {wanted or "（沒有）"} 不同')
    if set(seen) != set(ha_rows):
        problems.append('轉換後的模組和 HA 的不同')
    if _int(doc.get('partners')) != details['partners'] or _int(doc.get('attachments')) != details['attachments']:
        problems.append('轉換後的聯絡人或附件數量和 HA 的不同')
    if doc.get('marker') != live_values['marker'] or _int(doc.get('attempt')):
        problems.append('升級標記沒有設定好')
    if test_mode and (not isinstance(doc.get('uuid'), str) or doc.get('uuid') == old_uuid):
        problems.append('測試匯入沒有換上新的資料庫識別碼')
    return problems[:20]


def converted_notes(doc, details, live_values):
    """[(issue id, message, items)] reminders about the converted database that are no reason to stop (DESIGN: what the
    conversion finds can only be a notice or a stop): modules left in the state HA had them in (OD-61), an address that is
    not this device's (OD-66), website domains that are still HA's (OD-67)."""
    notes = []
    ha_rows = {name: state for name, _version, state in details['modules']}
    pending = [f'{name}（{state}）' for name, _version, state in parse_modules(doc.get('modules'))
               if state != 'installed' and ha_rows.get(name) == state]
    if pending:
        notes.append(('odoo.modules-pending', '這些模組還停在 HA 的狀態（尚未完成安裝、升級或移除）；匯入後請到 Odoo 的「應用程式」套用或取消它們。',
                      pending))
    if doc.get('base_url') != live_values['base_url']:
        notes.append(('odoo.url-differs', '資料庫裡的網址沒有設定成這台的網址；照樣匯入，匯入後請把 Odoo 的網址改成這台的'
                      '（信件連結和登入跳轉才不會連到 HA）。', []))
    if doc.get('website_domains'):
        notes.append(('odoo.website-domain-kept', '網站的網域沒有清除（仍是 HA 的網址）；照樣匯入，匯入後請到 Odoo 的網站設定清掉舊網域。',
                      [str(d)[:200] for d in doc['website_domains'][:5]]))
    return notes


def convert(work, app, database, test_mode, out_dir):
    """Build the app's data items in `out_dir` (`volumes/<name>.tar`, `dirs/<index>.tar`); returns
    {volumes {name: path}, dirs {rel: path}, database, custom_modules[], left_databases[], counts}.
    The chosen database is looked at again exactly as the check did and by the same rules (OD-50): what stops it stops this
    app, a line to confirm that was not confirmed -- or confirmed with other names -- is `confirmation-required`."""
    sink = work.sink(app)
    runner = work.runner(app)
    adapter = work.adapter(app)
    tmp = work.temp(app)
    items = Target(work, app, sink)
    live = items.live
    ids = adapter.owner_ids()
    size = hatarget.size_hint(getattr(work, 'ha', None))
    staging = work.staging / 'odoo-work'
    staging.mkdir(mode=0o700)
    (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
    (out_dir / 'dirs').mkdir(mode=0o700, parents=True, exist_ok=True)
    conf = read_conf(work, app, live)
    live.apply_conf(conf)
    image_id = live_image_id(work, app, live)
    hatarget.ensure_image(work, app, live.db_image)
    live_values = live_settings(work, app, live, image_id, sink)
    role = live_role(work, app, live, conf, sink)
    image16 = pick_pg16(work, app)
    pg_ids = tmp.user_ids('ids-pg', image16, 'postgres')
    odoo_ids = tmp.user_ids('ids-odoo', live.web_image, 'odoo')

    # The live data dir and custom modules folder, read while Odoo runs (only what the import keeps of them).
    live_web = staging / 'live-web.tar'
    with open(live_web, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        runner.relay(['volume', 'export', items.web_volume], stdout=handle, timeout=podman.scaled_timeout(3 * 3600, size),
                     max_output=work.guard.budget(), abort=work.abort)
    web_path = out_dir / 'volumes' / f'{items.web_volume}.tar'
    web = FileTar(web_path, work.guard)
    web.ids = odoo_ids
    web_data_tar(live_web, web, sessions_ids=odoo_ids)
    os.unlink(live_web)
    live_dir = None
    if items.addons_rel is not None:
        live_dir = staging / 'live-addons.tar'
        with open(live_dir, 'xb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            runner.dir_pack(items.addons_rel, stdout=handle, timeout=podman.scaled_timeout(3600, size),
                            max_output=work.guard.budget(), abort=work.abort)
    modules_tar = FileTar(staging / 'ha-modules.tar', work.guard)
    try:
        src, candidates = member_pass(work, app, tmp, pg_ids, filestore_db=database, filestore=web,
                                      modules=modules_tar)
    finally:
        modules_tar.close()
    web.close()
    work.phase('convert')
    cluster = start_ha_cluster(work, tmp, image16, size=src.pg_bytes)
    databases, target, _major, _ha = analyse(work, app, tmp, src, candidates, cluster, live, image16=image16, size=size)
    entry = next((db for db in databases if db['name'] == database), None)
    if entry is None:
        raise BackupError('not-found', f'HA 備份裡沒有資料庫 {database}。', database=database)
    if 'vector' in (entry.get('_details') or {}).get('extensions', ()) and 'pgvector' not in image16:
        try:   # the image that can read it is fetched now, so that the next try has it (the check does this itself)
            hatarget.ensure_image(work, app, PG16_IMAGES[0])
        except BackupError as error:
            if haissues.is_job_wide(error) or error.code in ('insufficient-space', 'busy'):
                raise
    sink.extend(entry['_issues'])
    details, copy, unavailable = entry['_details'], entry['_copy'], entry['_unavailable']
    if copy and items.addons_rel is None:
        sink.refuse('odoo.layout-unsupported', '這台的 Odoo 沒有（或沒有登記）自訂模組資料夾，無法放進 HA 的自訂模組。',
                    action='請把這台 Odoo 的自訂模組資料夾加進應用設定後重新檢查。')
    # What is still to be written (review C-01): the dump, the new cluster (about the size of HA's) with its WAL and
    # its export; HA's cluster and the filestore are already on disk.
    work.guard.check(2 * src.pg_bytes + WAL_ALLOWANCE)
    old_uuid = cluster.query_json("SELECT to_json((SELECT value FROM ir_config_parameter WHERE key = 'database.uuid'))",
                                  database, by_env=True)
    dump = staging / 'odoo.dump'
    work.log(f'匯出 HA 的資料庫 {haissues.clean(database, MAX_NAME_BYTES)}')
    where, env = database_arguments(database, True)
    with open(dump, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        tmp.exec('hapg', ['pg_dump', '-U', 'postgres', '-Fc', *where], user='postgres', env=env, stdout=handle,
                 timeout=podman.scaled_timeout(DUMP_TIMEOUT, src.pg_bytes), max_output=work.guard.budget())
        handle.flush()
        os.fsync(handle.fileno())
    tmp.remove('hapg')
    tmp.remove_volume('hapg')
    work.checkpoint()

    # The custom modules folder as it will be after the import (the live folder plus HA's custom modules).
    dirs = {}
    dir_path = None
    if items.addons_rel is not None:
        dir_path = out_dir / 'dirs' / f'{items.addons_index}.tar'
        out = FileTar(dir_path, work.guard)
        try:
            addons_dir_tar(live_dir, staging / 'ha-modules.tar', out,
                           copy={name: cand['from'] for name, cand in copy.items()})
        finally:
            out.close()
        os.unlink(live_dir)
        os.unlink(staging / 'ha-modules.tar')
        check_dir_tar(dir_path, ids)
        dirs[items.addons_rel] = dir_path

    # A new PostgreSQL 17 cluster exactly like the live one.
    work.log('建立新的 PostgreSQL 資料庫叢集（與這台相同的映像與設定）')
    network = tmp.network('odoo-net') if test_mode else None
    tmp.volume('odoo-db')
    tmp.run('odoo-db', live.db_image, [], detach=True, network=network,
            volumes=[(tmp.name('odoo-db'), live.db_target, None)], env=live.db_env, secrets=live.db_secrets)
    pg17 = Cluster(tmp, 'odoo-db', superuser=live.db_user, log=work.log)
    pg17.wait_ready(tcp=True, checkpoint=work.checkpoint, timeout=podman.scaled_timeout(PG_READY_TIMEOUT, src.pg_bytes))
    pg17.script(role_sql(role, live.db_role))
    tmp.exec('odoo-db', ['createdb', '-U', live.db_user, '-O', live.db_role, '--template=template0', '--encoding=UTF8',
                         '--lc-collate=C', live.db_name], user='postgres', timeout=600, max_output=64 * 1024)
    offered = target.get('extensions')
    wanted = [ext for ext in EXTENSIONS_CREATED if offered is None or ext in offered or ext in details['extensions']]
    extensions = wanted + [ext for ext in details['extensions'] if ext not in wanted and ext != 'plpgsql']
    pg17.script(''.join(f'CREATE EXTENSION IF NOT EXISTS {ext_ident(ext)};\n' for ext in extensions)
                + ('ALTER EXTENSION vector UPDATE;\n' if 'vector' in extensions else ''), live.db_name)
    restore_dump(work, tmp, dump, database, new_db=live.db_name, role=live.db_role, sink=sink)
    os.unlink(dump)
    pg17.script(settings_sql(live_values) + CLEAR_WEBSITE_DOMAINS_SQL, live.db_name)
    if test_mode:
        work.log('測試匯入：停用寄信與排程（odoo neutralize），並換上新的資料庫識別碼')
        neutralize(work, tmp, live, items, network, dir_path, size=src.pg_bytes)
        pg17.script(NEW_UUID_SQL, live.db_name)
    doc = pg17.query_json(VERIFY_SQL, live.db_name)
    if isinstance(doc, dict):
        doc['website_domains'] = (pg17.query_json(WEBSITE_DOMAINS_SQL, live.db_name)
                                  if pg17.query_json(HAS_WEBSITE_SQL, live.db_name) is True else [])
    problems = verify_converted(doc, details, target, copy, live_values, test_mode=test_mode, old_uuid=old_uuid,
                                unavailable=unavailable)
    if problems:
        raise BackupError('job-failed', f'轉換後的 Odoo 資料庫檢查沒有通過：{"；".join(problems)}。')
    for issue_id, message, names in converted_notes(doc, details, live_values):
        sink.notice(issue_id, message, names, database=database)
    carry_settings(work, app, live, pg17)
    pg17.statement('CHECKPOINT;')
    code = tmp.stop('odoo-db', timeout=300)
    if code != 0:
        raise BackupError('job-failed', f'新的 PostgreSQL 叢集沒有正常關閉（結束碼 {code}）。')
    state = tmp.run('controldata', live.db_image, ['pg_controldata', live.pgdata], user='postgres',
                    volumes=[(tmp.name('odoo-db'), live.db_target, 'ro')], timeout=300, read_only_root=True,
                    max_output=1024 * 1024).stdout or b''
    if not re.search(rb'Database cluster state:\s+shut down\s*$', state, re.M):
        raise BackupError('job-failed', '新的 PostgreSQL 叢集沒有正常關閉。')
    tmp.remove('odoo-db')
    db_path = out_dir / 'volumes' / f'{items.db_volume}.tar'
    with open(db_path, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        tmp.volume_export('odoo-db', handle, max_output=work.guard.budget())
        handle.flush()
        os.fsync(handle.fileno())
    tmp.remove_volume('odoo-db')
    check_volume_tar(web_path, ids)
    check_volume_tar(db_path, ids)
    volumes = {items.db_volume: db_path, items.web_volume: web_path}
    if items.extra_volumes or items.extra_dirs:   # OD-12, OD-13: this device's own other data goes along as it is
        report = habackup.Report(names=haissues.Names)
        carried = hatarget.carry(work, app, out_dir, ids, volumes=items.extra_volumes, dirs=items.extra_dirs,
                                 report=report, size=size)
        sink.skipped(report)
        volumes.update(carried['volumes'])
        dirs.update(carried['dirs'])
    return {'volumes': volumes, 'dirs': dirs, 'database': database,
            'custom_modules': entry['custom_modules'], 'website_domains': list(details.get('website_domains') or []),
            'left_databases': [db['name'] for db in databases if db['name'] != database][:100],
            'counts': {key: entry[key] for key in ('partners', 'users', 'attachments', 'modules')}}


def ext_ident(name):
    """An extension's name as an SQL identifier (the names were checked against what this device's PostgreSQL has)."""
    if not isinstance(name, str) or not EXT_NAME_RE.fullmatch(name):
        raise BackupError('internal-error', '擴充功能名稱格式不正確。')
    return '"' + name + '"'


ARCHIVE_SETTINGS = ('ENCODING', 'STDSTRINGS', 'SEARCHPATH')   # the three entries every pg_dump 16 archive begins with


def toc_entries(text):
    """(entries, declared, shown) of a `pg_restore -l` listing: how many lines are entries (`<id>; <oid> <oid> <kind> ...`),
    the `TOC Entries:` its header says the archive has (None when the header is not there) and how many of the archive
    settings ENCODING, STDSTRINGS and SEARCHPATH the lines show."""
    declared, entries, shown = None, 0, set()
    for line in text.splitlines():
        header = re.match(r';\s+TOC Entries:\s+([0-9]{1,9})\s*\Z', line)
        if header:
            declared = int(header.group(1))
        elif re.match(r'\s*\d+;\s+\d+\s+\d+\s', line):
            entries += 1
            kind = re.match(r'\s*\d+;\s+\d+\s+\d+\s+([A-Z]+)\s', line)
            if kind and kind.group(1) in ARCHIVE_SETTINGS:
                shown.add(kind.group(1))
    return entries, declared, len(shown)


INCOMPLETE_LIST = '資料庫匯出檔的項目清單沒有完整送達（主機可能太忙），已停止，沒有做任何變更，請稍後再試。'


def check_listing(text):
    """The `pg_restore -l` listing is whole when the number of its entries is what its own header says the archive has
    (pg-stdin follow-up F4: a listing that came back short would restore only the part it names, and nothing would notice).
    The header counts the three archive settings of a pg_dump 16 archive (ENCODING, STDSTRINGS, SEARCHPATH), which pg_restore
    keeps out of a plain listing: the lines are short by exactly the ones they do not show. A listing without the header
    cannot be checked and is refused. Returns the number of entries."""
    entries, declared, shown = toc_entries(text)
    if declared is None or declared != entries + len(ARCHIVE_SETTINGS) - shown:
        raise BackupError('job-failed', INCOMPLETE_LIST)
    return entries


def restore_dump(work, tmp, dump, database, *, new_db=DEFAULT_DB_NAME, role=DEFAULT_DB_ROLE, sink=None):
    """Restore HA's dump into the new cluster's database `new_db` AS THE ROLE `role` (review HA-SEC-01: HA's server is
    untrusted, so what its dump says runs without superuser rights): the list without the EXTENSION entries (created
    by postgres before) and without the objects only a superuser can create (OD-41, OD-58: left out and named in one
    reminder; what cannot be restored without them stops this app, nothing has changed); the dump is streamed on stdin
    (no copy of it inside the container). The list is cross-checked against its own header before anything is restored
    (pg-stdin F4), and the retry note of the list's write reaches the job log (pg-stdin F3)."""
    size = os.path.getsize(dump)
    with open(dump, 'rb') as handle:
        toc = tmp.exec('odoo-db', ['pg_restore', '-l'], user='postgres', input=handle,
                       timeout=podman.scaled_timeout(DUMP_TIMEOUT, size),
                       max_output=podman.scaled_limit(TOC_OUTPUT, size)).stdout or b''
    text = toc.decode('utf-8', 'surrogateescape')
    check_listing(text)
    kinds = superuser_kinds(text)
    if kinds:
        if sink is None:
            raise BackupError('incompatible', f'HA 的資料庫 {haissues.clean(database, MAX_NAME_BYTES)} 含有只有資料庫超級使用者才能建立的物件'
                                              f'（{_names(kinds)}），無法安全地搬過來。', database=database)
        sink.notice('odoo.superuser-skipped', '匯出檔的清單裡有只有資料庫超級使用者才能建立的物件，已略過它們，其他資料照搬。', kinds,
                    database=database)
    Cluster(tmp, 'odoo-db', log=work.log).write_file('/tmp/woowbk-odoo.toc',
                                                     filter_toc(text, skip=kinds).encode('utf-8', 'surrogateescape'))
    work.log(f'把資料庫 {haissues.clean(database, MAX_NAME_BYTES)} 還原到新的叢集（資料庫名稱 {new_db}，以 {role} 角色還原）')
    with open(dump, 'rb') as handle:
        try:
            tmp.exec('odoo-db', ['pg_restore', '-U', role, '--no-owner', '--no-acl', '--exit-on-error',
                                 '--single-transaction', '-L', '/tmp/woowbk-odoo.toc', '-d', new_db],
                     user='postgres', input=handle, timeout=podman.scaled_timeout(DUMP_TIMEOUT, size),
                     max_output=1024 * 1024)
        except BackupError as error:
            if error.code != 'job-failed' or haissues.is_job_wide(error):
                raise
            message = (f'無法把 HA 的資料庫 {haissues.clean(database, MAX_NAME_BYTES)} 還原到新的叢集（可能含有這台不支援、'
                       '或需要資料庫超級使用者權限的內容）。')
            if sink is None:
                raise BackupError('job-failed', message, database=database) from None
            sink.refuse('odoo.restore-failed', message, action='請在 HA 處理這個資料庫裡需要超級使用者的物件後重新備份；這台沒有任何變更。',
                        code='job-failed')
    tmp.exec('odoo-db', ['rm', '-f', '/tmp/woowbk-odoo.toc'], user='postgres', timeout=120)


def neutralize(work, tmp, live, items, network, dir_path, *, size=None):
    """`odoo neutralize` of the converted database with the custom modules folder AS IT WILL BE after the import
    (review C-12: a module copied from HA only there has its own neutralize.sql), in a throwaway volume."""
    mounts = [(source, target, opts) for source, target, opts in live.web_mounts
              if target not in ('/var/lib/odoo', items.addons_target)]
    if dir_path is not None:
        tmp.volume('odoo-addons')

        def produce(out):
            with open(dir_path, 'rb') as handle:
                while True:
                    data = handle.read(habackup.CHUNK)
                    if not data:
                        break
                    out.write(data)

        tmp.volume_import('odoo-addons', produce)
        mounts.append((tmp.name('odoo-addons'), items.addons_target, 'ro'))
    tmp.run('neutralize', live.web_image, ['neutralize', '-c', CONF_PATH, '-d', live.db_name, '--db_host',
                                           tmp.name('odoo-db'), '--db_port', '5432'],
            entrypoint='odoo', network=network, secrets=[live.conf_secret], volumes=mounts,
            timeout=podman.scaled_timeout(1800, size), max_output=4 * 1024 * 1024)
    if dir_path is not None:
        tmp.remove_volume('odoo-addons')
