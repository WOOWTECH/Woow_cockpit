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
import io
import json
import os
import re
import tarfile
import time

from . import habackup, nested, tempctr, util
from .errors import BackupError

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
MAX_SMALL_FILE = 64 * 1024
PG_READY_TIMEOUT = 300
DUMP_TIMEOUT = 3 * 3600
SQL_OUTPUT = 16 * 1024 * 1024
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
# Command-line settings win over every configuration file: nothing of HA's cluster can load a library, run a command
# or listen anywhere.
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
    for entry in habackup.iter_entries(stream, select, report):
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
    for entry in habackup.iter_entries(stream, select, report, addon=False):
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


def quadlet_mounts(quadlets, container_file, home, *, read_only=True):
    """The `Volume=` mounts of a `.container` file as (source, target, options): `.volume` units resolved to their
    volume names, `%h/` expanded to the owner's home; relabel options dropped and `ro` forced (a throwaway copy only
    reads them)."""
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
                raise BackupError('incompatible', f'{container_file} 的 Volume= 設定不受支援。')
        elif source.startswith('/') or '%' in source:
            raise BackupError('incompatible', f'{container_file} 的 Volume= 設定不受支援：{value[:80]}')
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
    secret mounts, data dir target, container name), the web container (image, configuration secret, mounts)."""

    def __init__(self, quadlets, home):
        files = list(quadlets)
        self.db_file = next((f for f in files if f.endswith('.container') and _is_db(quadlets[f])), None)
        self.web_file = next((f for f in files if f.endswith('.container') and _is_web(quadlets[f])), None)
        if self.db_file is None or self.web_file is None:
            raise BackupError('incompatible', '這台的 Odoo 不是 WOOWTECH 的 Podman 版本（找不到資料庫或 Odoo 主程式的 Quadlet 檔）。')
        db_text = quadlets[self.db_file]
        self.db_image = tempctr.quadlet_image(db_text)
        self.db_env = tempctr.quadlet_environment(db_text, DB_ENV_KEYS)
        self.db_secrets = tempctr.quadlet_secrets(db_text)
        self.db_container = quadlet_container_name(quadlets, self.db_file)
        db_mounts = quadlet_mounts(quadlets, self.db_file, home)
        if not db_mounts:
            raise BackupError('incompatible', f'{self.db_file} 沒有資料卷設定。')
        self.db_volume, self.db_target = db_mounts[0][0], db_mounts[0][1]
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
        self.web_mounts = quadlet_mounts(quadlets, self.web_file, home)
        if not self.db_image or not self.web_image or self.conf_secret is None:
            raise BackupError('incompatible', '這台 Odoo 的 Quadlet 設定缺少映像或設定檔機密。')
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}', self.db_user):
            raise BackupError('incompatible', f'{self.db_file} 的 POSTGRES_USER 設定不受支援。')

    def web_volume_mount(self, name):
        return next((target for source, target, _opts in self.web_mounts if source == name), None)


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

    def query_json(self, sql, database='postgres', *, max_output=SQL_OUTPUT, timeout=600):
        """One JSON value from `psql -At` (the statement must return exactly one json cell)."""
        out = self.tmp.exec(self.role, ['psql', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-U',
                                        self.superuser, '-d', database, '-c', sql], user='postgres', timeout=timeout,
                            max_output=max_output).stdout or b''
        try:
            return util.loads_strict(out.strip() or b'null', max_bytes=max_output)
        except ValueError:
            raise BackupError('job-failed', '暫用 PostgreSQL 的回應格式不正確。') from None

    def script(self, sql, database='postgres', *, timeout=600):
        """Run SQL from stdin in ONE transaction (`psql -v ON_ERROR_STOP=1 -1`): values never appear in argv. Never
        for a statement PostgreSQL refuses inside a transaction block (ALTER SYSTEM, VACUUM...): `statement`."""
        self.tmp.exec(self.role, ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-1', '-U', self.superuser, '-d',
                                  database, '-f', '-'], user='postgres', input=sql.encode('utf-8'), timeout=timeout,
                      max_output=1024 * 1024)

    def statement(self, sql, database='postgres', *, timeout=600):
        """Run exactly one SQL statement from stdin outside any transaction block (no `-1`; review C-19: ALTER SYSTEM
        cannot run inside one): values never appear in argv."""
        if not isinstance(sql, str) or not sql.strip() or ';' in re.sub(r"'(?:[^']|'')*'", '', sql.strip().rstrip(';')):
            raise BackupError('internal-error', '一次只能執行一個資料庫指令。')
        self.tmp.exec(self.role, ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', self.superuser, '-d', database,
                                  '-f', '-'], user='postgres', input=sql.encode('utf-8'), timeout=timeout,
                      max_output=1024 * 1024)

    def write_file(self, path, source, *, timeout=DUMP_TIMEOUT):
        """Copy `source` (an open file or bytes) into the container at `path` (fixed paths under /tmp only)."""
        if not re.fullmatch(r'/tmp/woowbk-[a-z0-9.-]{1,40}', path):
            raise BackupError('internal-error', '暫存檔路徑不正確。')
        self.tmp.exec(self.role, ['sh', '-c', f'umask 077 && cat > {path}'], user='postgres', input=source,
                      timeout=timeout, max_output=64 * 1024)


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
LIVE_ROLE_SQL = ("SELECT json_build_object('password', rolpassword, 'super', rolsuper, 'login', rolcanlogin, "
                 "'createdb', rolcreatedb, 'createrole', rolcreaterole, 'replication', rolreplication, "
                 "'bypassrls', rolbypassrls, 'connlimit', rolconnlimit) FROM pg_authid WHERE rolname = 'odoo'")
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
        raise BackupError('job-failed', '無法讀取 HA 資料庫的模組清單。')
    modules = []
    for row in rows:
        if (not isinstance(row, list) or len(row) != 3 or not all(isinstance(x, str) for x in row)
                or not MODULE_RE.fullmatch(row[0]) or len(row[1]) > 64):
            raise BackupError('job-failed', '無法讀取 HA 資料庫的模組清單。')
        modules.append(tuple(row))
    return modules


def database_details(cluster, name):
    """Counts, modules and extensions of one HA database, or None when it is not an Odoo database."""
    flags = cluster.query_json(IS_ODOO_SQL, name)
    if not isinstance(flags, list) or not all(flag is True for flag in flags):
        return None
    doc = cluster.query_json(DETAIL_SQL, name)
    if not isinstance(doc, dict):
        raise BackupError('job-failed', '無法讀取 HA 資料庫的內容。')
    extensions = doc.get('extensions') if isinstance(doc.get('extensions'), list) else []
    base_url = doc.get('base_url') if isinstance(doc.get('base_url'), str) else None
    kinds = cluster.query_json(SUPERUSER_SQL, name)
    domains = cluster.query_json(WEBSITE_DOMAINS_SQL, name) if cluster.query_json(HAS_WEBSITE_SQL, name) is True else []
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
    for name in sorted(module.get_modules()):
        manifest = module.get_manifest(name) or {}
        path = module.get_module_path(name, display_warning=False) or ""
        rows.append([name, str(manifest.get("version", "")), bool(manifest.get("installable", True)),
                     os.path.dirname(path)])
    out["modules"] = rows
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


def target_inventory(tmp, live, *, python=(), binaries=(), role='scan'):
    """{version, paths, modules {name: (version, installable, root)}, python {dep: bool}, bin {dep: bool}} from the
    live Odoo image (network none, the live configuration secret and module folders mounted read-only)."""
    request = {'conf': '/etc/odoo/odoo.conf', 'python': sorted(set(python)), 'bin': sorted(set(binaries))}
    for dep in request['python']:
        if not PY_DEP_RE.fullmatch(dep):
            raise BackupError('internal-error', 'Python 套件名稱格式不正確。')
    for dep in request['bin']:
        if not BIN_DEP_RE.fullmatch(dep):
            raise BackupError('internal-error', '程式名稱格式不正確。')
    result = tmp.run(role, live.web_image, ['-I', '-', json.dumps(request)], entrypoint='python3',
                     input=SCANNER.encode('utf-8'), volumes=live.web_mounts, secrets=[live.conf_secret],
                     timeout=600, max_output=8 * 1024 * 1024)
    try:
        doc = util.loads_strict((result.stdout or b'').strip(), max_bytes=8 * 1024 * 1024)
    except ValueError:
        raise BackupError('job-failed', '無法讀取這台 Odoo 的模組清單。') from None
    if not isinstance(doc, dict) or doc.get('error') or not isinstance(doc.get('modules'), list):
        raise BackupError('job-failed', '無法讀取這台 Odoo 的模組清單。', reason=str((doc or {}).get('error'))[:80])
    modules = {}
    for row in doc['modules'][:MAX_MODULE_ROWS]:
        if (isinstance(row, list) and len(row) == 4 and isinstance(row[0], str) and MODULE_RE.fullmatch(row[0])
                and isinstance(row[1], str) and isinstance(row[2], bool) and isinstance(row[3], str)):
            modules[row[0]] = (row[1][:64], row[2], row[3][:512])
    python_ok = {k: v is True for k, v in (doc.get('python') or {}).items() if isinstance(k, str)}
    bin_ok = {k: v is True for k, v in (doc.get('bin') or {}).items() if isinstance(k, str)}
    version = doc.get('version') if isinstance(doc.get('version'), str) else ''
    return {'version': version[:64], 'paths': [str(p)[:512] for p in doc.get('paths') or []][:32],
            'modules': modules, 'python': python_ok, 'bin': bin_ok}


# ====================================================================== the verdict

def database_verdict(details, target, candidates, *, ha_major, target_major, extra_target='/mnt/extra-addons',
                     vector_ok=True):
    """(ok, blockers[], warnings[], copy {module: candidate}) of one HA database against the target.

    A module installed in the HA database must be on the target with the identical version -- Odoo's own copy (the
    first on its addons path) -- or be a custom module of the backup with that version; a backup copy goes into the
    custom modules folder when the target has none, or has another version only there (a copy elsewhere would win)."""
    blockers, warnings, copy = [], [], {}
    missing, mismatch, pending, newer_hint = [], [], [], []
    for name, version, state in details['modules']:
        if state != 'installed':
            pending.append(name)
            continue
        effective = target['modules'].get(name)
        candidate = candidates.get(name)
        manifest = (candidate or {}).get('manifest') or {}
        has_copy = candidate is not None and manifest and same_version(manifest.get('version'), version)
        if effective is not None and same_version(effective[0], version):
            continue
        if has_copy and (effective is None or effective[2].rstrip('/') == extra_target):
            copy[name] = candidate
            continue
        if effective is None:
            missing.append(name)
        else:
            mismatch.append(f'{name}（HA {version}，這台 {effective[0]}）')
            ha_key, target_key = version_key(version), version_key(effective[0])
            if ha_key is not None and target_key is not None and ha_key > target_key:
                newer_hint.append(name)
    if pending:
        blockers.append(f'HA 的資料庫有尚未完成的模組安裝、升級或移除（{_names(pending)}），請先在 HA 完成後再做一次備份。')
    if missing:
        blockers.append(f'這台的 Odoo 缺少 HA 資料庫已安裝的模組：{_names(missing)}。{MSG_HINT_SHARE}')
    if mismatch:
        blockers.append(f'這些模組的版本和這台不同：{_names(mismatch)}。請先讓兩邊的 Odoo 版本一致後再匯入。')
    unknown = [ext for ext in details['extensions'] if ext not in EXTENSIONS_OK]
    if unknown:
        blockers.append(f'HA 的資料庫使用了這台不支援的 PostgreSQL 擴充功能：{_names(unknown)}。')
    if 'vector' in details['extensions'] and not vector_ok:
        blockers.append('HA 的資料庫使用了 vector 擴充功能，這台沒有含 pgvector 的 PostgreSQL 16 映像'
                        f'（{PG16_IMAGES[0]}），無法讀出它的資料。')
    if details.get('superuser_objects'):
        blockers.append('HA 的資料庫含有只有資料庫超級使用者才能建立的物件'
                        f'（{_names(details["superuser_objects"])}），無法安全地搬過來。')
    if ha_major is None or target_major is None or ha_major > target_major:
        blockers.append(f'HA 的 PostgreSQL 是 {ha_major or "未知"} 版，這台是 {target_major or "未知"} 版；'
                        '只能從相同或較舊的版本搬過來。')
    lacking = []
    for name, candidate in sorted(copy.items()):
        manifest = candidate.get('manifest') or {}
        if not manifest.get('installable', True):
            lacking.append(f'{name} 標示為不可安裝')
        for dep in manifest.get('python') or []:
            if target['python'].get(dep) is not True:
                lacking.append(f'Python 套件 {dep}（模組 {name}）')
        for dep in manifest.get('bin') or []:
            if target['bin'].get(dep) is not True:
                lacking.append(f'程式 {dep}（模組 {name}）')
    if lacking:
        blockers.append(f'要一起搬過來的自訂模組需要這台沒有的東西：{_names(lacking)}。')
    if details['mail_servers_active']:
        warnings.append(f'HA 的資料庫有 {details["mail_servers_active"]} 個啟用中的外寄郵件伺服器，搬過來後會開始寄信。')
    if details['crons_active']:
        warnings.append(f'HA 的資料庫有 {details["crons_active"]} 個啟用中的排程工作，搬過來後會在這台執行。')
    if details.get('website_domains'):
        warnings.append(f'網站原本使用的網域 {_names(details["website_domains"], 5)} 會改成這台的網址。')
    return not blockers, blockers, warnings, copy


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

def filter_toc(text):
    """A pg_restore list without the EXTENSION entries and their comments (the extensions are created first, as
    postgres; restore-online.sh's awk filter, matched on the entry type field only)."""
    kept = []
    for line in text.splitlines():
        if re.match(r'\s*\d+;\s+\d+\s+\d+\s+EXTENSION\s', line) or \
                re.match(r'\s*\d+;\s+\d+\s+\d+\s+COMMENT\s+-\s+EXTENSION\s', line):
            continue
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
    a reload and a read-back of pg_file_settings (every carried setting there, without an error). Returns the names."""
    live_rows = _read_live_json(work, app, live, SETTINGS_SQL, 'postgres')
    carried, skipped = [], []
    for name, value in settings_to_carry(live_rows, cluster.query_json(SETTINGS_SQL)):
        sql = alter_system_sql(name, value)
        if sql is None:
            skipped.append(name)
            continue
        cluster.statement(sql)
        carried.append(name)
    if skipped:
        work.log(f'這些 PostgreSQL 設定的格式無法沿用，維持新叢集的預設值：{"、".join(skipped)}')
    if not carried:
        return []
    cluster.statement('SELECT pg_reload_conf();')
    rows = cluster.query_json(FILE_SETTINGS_SQL)
    written = {}
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, list) and len(row) == 3 and all(isinstance(x, str) for x in row):
            written[row[0].lower()] = row[2]
    bad = [name for name in carried if name not in written or written[name]]
    if bad:
        raise BackupError('job-failed', f'沿用這台 PostgreSQL 的設定失敗：{"、".join(bad[:10])}。')
    work.log(f'沿用這台 PostgreSQL 的設定：{"、".join(carried)}')
    return carried


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
    official image is pulled (Docker Hub index digest of postgres:16.15-alpine)."""
    runner = work.runner(app)
    for ref in PG16_IMAGES:
        if runner.podman('image', 'exists', ref, timeout=60, check=False).returncode == 0:
            return ref
    work.log('這台沒有 PostgreSQL 16 映像，下載固定版本的 postgres:16.15-alpine')
    runner.podman('pull', '--quiet', PG16_PINNED, timeout=1800, max_output=64 * 1024, abort=work.abort)
    return PG16_PINNED


class Target:
    """The app's catalog items the import fills, resolved against the live Quadlet files."""

    def __init__(self, work, app):
        self.app = app
        runner = work.runner(app)
        self.live = Live(work.quadlets(app), runner.home)
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
        if sorted(declared) != sorted({self.db_volume, web} - {None}) or web is None:
            problems.append('資料卷和 Odoo 的 Quadlet 設定不一致')
        if dirs and dirs != [self.addons_rel]:
            problems.append('主機資料夾不是 Odoo 的自訂模組資料夾')
        if problems:
            raise BackupError('incompatible', f'這台的 Odoo 應用設定不是 HA 匯入支援的樣子：{"；".join(problems)}。',
                              app=app.id)
        self.addons_index = 0 if dirs else None


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


def start_ha_cluster(work, tmp, image):
    """PostgreSQL 16 on HA's (untrusted) cluster: every library/command setting overridden on the command line, the
    data volume mounted noexec/nosuid/nodev (no library of HA's can be loaded from it), a read-only root file system,
    no network (review HA-SEC-01). What it answers is still HA's data only: the dump is restored as the role odoo."""
    tmp.run('hapg', image, ha_server_args(), detach=True, read_only_root=True,
            volumes=[(tmp.name('hapg'), HA_DATA, 'rw,noexec,nosuid,nodev')])
    cluster = Cluster(tmp, 'hapg', log=work.log)
    cluster.wait_ready(checkpoint=work.checkpoint)
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


def analyse(work, app, tmp, src, candidates, cluster, live, *, image16):
    """Per HA database: {name, ok, blockers, warnings, counts…, custom_modules, _details, _copy}; plus the target
    inventory."""
    python, binaries = python_and_bins(candidates)
    target = target_inventory(tmp, live, python=python, binaries=binaries)
    target_major = target_pg_major(work, app, live.db_image)
    ha_major = _ha_major(src)
    databases = []
    extra_target = None
    for source, mount_target, _o in live.web_mounts:
        if mount_target not in ('/var/lib/odoo',) and source.startswith('/'):
            extra_target = mount_target
    for db in ha_databases(cluster):
        entry = {'name': db['name'], 'ok': False, 'blockers': [], 'warnings': [], 'partners': 0, 'users': 0,
                 'attachments': 0, 'attachment_bytes': 0, 'modules': 0, 'custom_modules': [], 'crons_active': 0,
                 'mail_servers_active': 0, 'size': db['size']}
        if not DB_NAME_RE.fullmatch(db['name']):
            entry['blockers'].append('資料庫名稱含有不支援的字元。')
            databases.append(entry)
            continue
        details = database_details(cluster, db['name'])
        if details is None:
            entry['blockers'].append(MSG_NOT_ODOO)
            databases.append(entry)
            continue
        ok, blockers, warnings, copy = database_verdict(details, target, candidates, ha_major=ha_major,
                                                        target_major=target_major,
                                                        extra_target=extra_target or '/mnt/extra-addons',
                                                        vector_ok='pgvector' in image16)
        files, size = src.filestore.get(db['name'], [0, 0])
        if details['attachments'] and not files:
            warnings.append('HA 備份裡沒有這個資料庫的附件檔案（filestore）；搬過來後附件會打不開。')
        entry.update({'ok': ok, 'blockers': blockers, 'warnings': warnings, 'partners': details['partners'],
                      'users': details['users'], 'attachments': details['attachments'],
                      'attachment_bytes': details['attachment_bytes'],
                      'modules': sum(1 for _n, _v, state in details['modules'] if state == 'installed'),
                      'custom_modules': [custom_module_view(name, cand) for name, cand in sorted(copy.items())],
                      'crons_active': details['crons_active'], 'mail_servers_active': details['mail_servers_active'],
                      'size': details['size'], 'filestore_files': files, 'filestore_bytes': size,
                      '_details': details, '_copy': copy})
        databases.append(entry)
    return databases, target, target_major, ha_major


def public_database(entry):
    return {key: value for key, value in entry.items() if not key.startswith('_')}


def live_image_id(work, app, live):
    info = work.adapter(app).image_inspect(live.web_image)
    if not info or not DIGEST_RE.fullmatch(info.get('id') or ''):
        raise BackupError('incompatible', '找不到這台 Odoo 使用的映像。', app=app.id)
    return info['id']


def check(work, app):
    """The check job's Odoo part: (app result fields, internal notes). The live upgrade-gate marker and the role odoo
    are checked first, exactly as the conversion checks them (review C-05)."""
    tmp = work.temp(app)
    target_items = Target(work, app)
    live = target_items.live
    live_settings(work, app, live, live_image_id(work, app, live))
    live_role(work, app, live)
    image16 = pick_pg16(work, app)
    pg_ids = tmp.user_ids('ids-pg', image16, 'postgres')
    src, candidates = member_pass(work, app, tmp, pg_ids)
    work.phase('check')
    cluster = start_ha_cluster(work, tmp, image16)
    databases, target, _target_major, _ha_major_ = analyse(work, app, tmp, src, candidates, cluster, live,
                                                           image16=image16)
    tmp.remove('hapg')
    tmp.remove_volume('hapg')
    return {'target_version': target['version'], 'pg_bytes': src.pg_bytes,
            'filestore_bytes': sum(size for _files, size in src.filestore.values()),
            'module_bytes': src.module_bytes,
            'odoo': {'databases': [public_database(entry) for entry in databases]}}


# -------------------------------------------------------------------- convert

def _read_live_json(work, app, live, sql, database):
    """One JSON cell from the LIVE database container (read only; as its superuser over its socket)."""
    runner = work.runner(app)
    try:
        out = runner.podman('exec', live.db_container, 'psql', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-U',
                            live.db_user, '-d', database, '-c', sql, timeout=120,
                            max_output=1024 * 1024).stdout or b''
    except BackupError as error:
        if error.code != 'job-failed':
            raise
        raise BackupError('job-failed', '無法讀取這台 Odoo 資料庫的設定，請確認這台的 Odoo 正在執行。') from None
    try:
        return util.loads_strict(out.strip() or b'null', max_bytes=1024 * 1024)
    except ValueError:
        raise BackupError('job-failed', '無法讀取這台 Odoo 資料庫的設定。') from None


def live_role(work, app, live):
    """The live role odoo: password verifier (masked in every log of this process) and attributes."""
    from . import jobs
    doc = _read_live_json(work, app, live, LIVE_ROLE_SQL, 'postgres')
    if not isinstance(doc, dict):
        raise BackupError('incompatible', '這台的 Odoo 資料庫沒有 odoo 角色。')
    password = doc.get('password')
    if not isinstance(password, str) or not VERIFIER_RE.fullmatch(password):
        raise BackupError('incompatible', '這台 Odoo 資料庫的 odoo 角色沒有可用的密碼設定。')
    jobs.mask_secret(password)
    if doc.get('super') is not False:
        raise BackupError('incompatible', '這台 Odoo 資料庫的 odoo 角色是超級使用者，不是 tenant 的設定。')
    return doc


def role_sql(role):
    flags = ['LOGIN' if role.get('login') else 'NOLOGIN', 'NOSUPERUSER',
             'CREATEDB' if role.get('createdb') else 'NOCREATEDB',
             'CREATEROLE' if role.get('createrole') else 'NOCREATEROLE',
             'REPLICATION' if role.get('replication') else 'NOREPLICATION',
             'BYPASSRLS' if role.get('bypassrls') else 'NOBYPASSRLS']
    limit = role.get('connlimit')
    if isinstance(limit, int) and not isinstance(limit, bool) and limit >= 0:
        flags.append(f'CONNECTION LIMIT {limit}')
    return f"CREATE ROLE odoo {' '.join(flags)} PASSWORD {sql_literal(role['password'])};\n"


def live_settings(work, app, live, image_id):
    doc = _read_live_json(work, app, live, LIVE_SQL, 'odoo')
    if not isinstance(doc, dict):
        raise BackupError('incompatible', '無法讀取這台 Odoo 的網址與升級標記。')
    marker = doc.get('marker')
    if not marker_ok(marker, image_id):
        raise BackupError('incompatible', '這台 Odoo 的升級標記和目前的映像不一致（或沒有），請先確認 Odoo 正常運作後再匯入。')
    base_url = doc.get('base_url')
    if base_url is not None and (not isinstance(base_url, str) or len(base_url) > 2048):
        raise BackupError('incompatible', '這台 Odoo 的網址設定格式不正確。')
    freeze = doc.get('freeze')
    if freeze is not None and (not isinstance(freeze, str) or len(freeze) > 64):
        freeze = None
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


def verify_converted(doc, details, target, copy, live_values, *, test_mode, old_uuid):
    """Problems (zh-TW) of the converted database against what the check promised."""
    problems = []
    if not isinstance(doc, dict):
        return ['無法讀取轉換後的資料庫。']
    modules = parse_modules(doc.get('modules'))
    expected = {name: version for name, version, state in details['modules'] if state == 'installed'}
    seen = {}
    for name, version, state in modules:
        seen[name] = version
        if state != 'installed':
            problems.append(f'模組 {name} 的狀態是 {state}')
            continue
        effective = target['modules'].get(name)
        wanted = ((copy[name].get('manifest') or {}).get('version') if name in copy
                  else effective[0] if effective else None)
        if wanted is None or not same_version(version, wanted):
            problems.append(f'模組 {name} 的版本 {version} 和這台的 {wanted or "（沒有）"} 不同')
    if set(seen) != set(expected):
        problems.append('轉換後的已安裝模組和 HA 的不同')
    if _int(doc.get('partners')) != details['partners'] or _int(doc.get('attachments')) != details['attachments']:
        problems.append('轉換後的聯絡人或附件數量和 HA 的不同')
    if doc.get('marker') != live_values['marker'] or _int(doc.get('attempt')):
        problems.append('升級標記沒有設定好')
    if doc.get('base_url') != live_values['base_url']:
        problems.append('網址沒有設定成這台的網址')
    if doc.get('website_domains'):
        problems.append('網站的網域沒有清除（仍是 HA 的網址）')
    if test_mode and (not isinstance(doc.get('uuid'), str) or doc.get('uuid') == old_uuid):
        problems.append('測試匯入沒有換上新的資料庫識別碼')
    return problems[:20]


def convert(work, app, database, test_mode, out_dir):
    """Build the app's data items in `out_dir` (`volumes/<name>.tar`, `dirs/<index>.tar`); returns
    {volumes {name: path}, dirs {rel: path}, database, custom_modules[], counts}."""
    runner = work.runner(app)
    adapter = work.adapter(app)
    tmp = work.temp(app)
    items = Target(work, app)
    live = items.live
    ids = adapter.owner_ids()
    staging = work.staging / 'odoo-work'
    staging.mkdir(mode=0o700)
    (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
    (out_dir / 'dirs').mkdir(mode=0o700, parents=True, exist_ok=True)
    live_values = live_settings(work, app, live, live_image_id(work, app, live))
    image16 = pick_pg16(work, app)
    pg_ids = tmp.user_ids('ids-pg', image16, 'postgres')
    odoo_ids = tmp.user_ids('ids-odoo', live.web_image, 'odoo')

    # The live data dir and custom modules folder, read while Odoo runs (only what the import keeps of them).
    live_web = staging / 'live-web.tar'
    with open(live_web, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        runner.relay(['volume', 'export', items.web_volume], stdout=handle, timeout=3 * 3600,
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
            runner.dir_pack(items.addons_rel, stdout=handle, timeout=3600, max_output=work.guard.budget(),
                            abort=work.abort)
    modules_tar = FileTar(staging / 'ha-modules.tar', work.guard)
    try:
        src, candidates = member_pass(work, app, tmp, pg_ids, filestore_db=database, filestore=web,
                                      modules=modules_tar)
    finally:
        modules_tar.close()
    web.close()
    work.phase('convert')
    cluster = start_ha_cluster(work, tmp, image16)
    databases, target, _major, _ha = analyse(work, app, tmp, src, candidates, cluster, live, image16=image16)
    entry = next((db for db in databases if db['name'] == database), None)
    if entry is None:
        raise BackupError('not-found', f'HA 備份裡沒有資料庫 {database}。', database=database)
    if not entry['ok']:
        raise BackupError('incompatible', f'資料庫 {database} 不能搬過來：{entry["blockers"][0]}', database=database)
    details, copy = entry['_details'], entry['_copy']
    if copy and items.addons_rel is None:
        raise BackupError('incompatible', '這台的 Odoo 沒有自訂模組資料夾，無法放進 HA 的自訂模組。', app=app.id)
    # What is still to be written (review C-01): the dump, the new cluster (about the size of HA's) with its WAL and
    # its export; HA's cluster and the filestore are already on disk.
    work.guard.check(2 * src.pg_bytes + WAL_ALLOWANCE)
    old_uuid = cluster.query_json("SELECT to_json((SELECT value FROM ir_config_parameter WHERE key = 'database.uuid'))",
                                  database)
    dump = staging / 'odoo.dump'
    work.log(f'匯出 HA 的資料庫 {database}')
    with open(dump, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        tmp.exec('hapg', ['pg_dump', '-U', 'postgres', '-Fc', '-d', database], user='postgres', stdout=handle,
                 timeout=DUMP_TIMEOUT, max_output=work.guard.budget())
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
    pg17.wait_ready(tcp=True, checkpoint=work.checkpoint)
    role = live_role(work, app, live)
    pg17.script(role_sql(role))
    tmp.exec('odoo-db', ['createdb', '-U', live.db_user, '-O', 'odoo', '--template=template0', '--encoding=UTF8',
                         '--lc-collate=C', 'odoo'], user='postgres', timeout=600, max_output=64 * 1024)
    extensions = list(EXTENSIONS_CREATED) + [ext for ext in details['extensions']
                                             if ext not in EXTENSIONS_CREATED and ext != 'plpgsql']
    pg17.script(''.join(f'CREATE EXTENSION IF NOT EXISTS {pg_ident(ext)};\n' for ext in extensions)
                + 'ALTER EXTENSION vector UPDATE;\n', 'odoo')
    restore_dump(work, tmp, dump, database)
    os.unlink(dump)
    pg17.script(settings_sql(live_values) + CLEAR_WEBSITE_DOMAINS_SQL, 'odoo')
    if test_mode:
        work.log('測試匯入：停用寄信與排程（odoo neutralize），並換上新的資料庫識別碼')
        neutralize(work, tmp, live, items, network, dir_path)
        pg17.script(NEW_UUID_SQL, 'odoo')
    doc = pg17.query_json(VERIFY_SQL, 'odoo')
    if isinstance(doc, dict):
        doc['website_domains'] = (pg17.query_json(WEBSITE_DOMAINS_SQL, 'odoo')
                                  if pg17.query_json(HAS_WEBSITE_SQL, 'odoo') is True else [])
    problems = verify_converted(doc, details, target, copy, live_values, test_mode=test_mode, old_uuid=old_uuid)
    if problems:
        raise BackupError('job-failed', f'轉換後的 Odoo 資料庫檢查沒有通過：{"；".join(problems)}。')
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
    return {'volumes': {items.db_volume: db_path, items.web_volume: web_path}, 'dirs': dirs, 'database': database,
            'custom_modules': entry['custom_modules'], 'website_domains': list(details.get('website_domains') or []),
            'counts': {key: entry[key] for key in ('partners', 'users', 'attachments', 'modules')}}


def restore_dump(work, tmp, dump, database):
    """Restore HA's dump into the new cluster's database odoo AS THE ROLE odoo (review HA-SEC-01: HA's server is
    untrusted, so what its dump says runs without superuser rights): the list without the EXTENSION entries (created
    by postgres before), refused when it holds objects only a superuser can create; the dump is streamed on stdin
    (no copy of it inside the container)."""
    with open(dump, 'rb') as handle:
        toc = tmp.exec('odoo-db', ['pg_restore', '-l'], user='postgres', input=handle, timeout=DUMP_TIMEOUT,
                       max_output=TOC_OUTPUT).stdout or b''
    text = toc.decode('utf-8', 'surrogateescape')
    kinds = superuser_kinds(text)
    if kinds:
        raise BackupError('incompatible', f'HA 的資料庫 {database} 含有只有資料庫超級使用者才能建立的物件'
                                          f'（{_names(kinds)}），無法安全地搬過來。', database=database)
    Cluster(tmp, 'odoo-db').write_file('/tmp/woowbk-odoo.toc', filter_toc(text).encode('utf-8', 'surrogateescape'))
    work.log(f'把資料庫 {database} 還原到新的叢集（資料庫名稱 odoo，以 odoo 角色還原）')
    with open(dump, 'rb') as handle:
        try:
            tmp.exec('odoo-db', ['pg_restore', '-U', 'odoo', '--no-owner', '--no-acl', '--exit-on-error',
                                 '--single-transaction', '-L', '/tmp/woowbk-odoo.toc', '-d', 'odoo'],
                     user='postgres', input=handle, timeout=DUMP_TIMEOUT, max_output=1024 * 1024)
        except BackupError as error:
            if error.code != 'job-failed':
                raise
            raise BackupError('job-failed', f'無法把 HA 的資料庫 {database} 還原到新的叢集（可能含有這台不支援、'
                                            '或需要資料庫超級使用者權限的內容）。', database=database) from None
    tmp.exec('odoo-db', ['rm', '-f', '/tmp/woowbk-odoo.toc'], user='postgres', timeout=120)


def neutralize(work, tmp, live, items, network, dir_path):
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
    tmp.run('neutralize', live.web_image, ['neutralize', '-c', '/etc/odoo/odoo.conf', '-d', 'odoo', '--db_host',
                                           tmp.name('odoo-db'), '--db_port', '5432'],
            entrypoint='odoo', network=network, secrets=[live.conf_secret], volumes=mounts, timeout=1800,
            max_output=4 * 1024 * 1024)
    if dir_path is not None:
        tmp.remove_volume('odoo-addons')
