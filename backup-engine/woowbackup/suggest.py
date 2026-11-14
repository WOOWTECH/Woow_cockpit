"""Catalog drafts from an owner's Quadlet directory (`catalog-suggest`). Owner: catalog + retention engineer.

Read-only. The owner's `~/.config/containers/systemd/` is listed and read *as the owner* (SCAN_HELPER through
OwnerRunner; root never opens a path in the home), bind-mount sources are stat'ed with the owner-side FILE_HELPER,
and `podman secret ls`, `podman volume ls` and `systemctl --user show` run as the owner. Nothing is written,
started or stopped.

Everything read from the owner's files is untrusted: a name only reaches a draft entry after it matched the
catalog's own regular expressions, every draft is checked with `catalog.validate_entry`, and the values of
`Environment=` assignments are never returned (only POSTGRES_USER / POSTGRES_DB, and only when they are plain
identifiers). Environment files are never read: they usually hold passwords.

How a directory becomes apps (each step is reported in the draft's `notes`/`warnings`):
* `.container` files are linked by systemd dependencies on each other's services (Requires/BindsTo/PartOf/
  Requisite/Wants/After/Before), a shared network namespace (`Network=container:<name>` / `<x>.container`), a
  shared pod, a shared volume or host directory, the label `app=<id>`, and a Quadlet network whose name is a
  prefix of the container's file name (`n8n.network` links `n8n-worker`, but `proxy.network` does not link
  every app on it). The label `io.woowtech.app=<id>` is authoritative: containers with different values are
  never merged.
* The app id is that label, else the longest common `-`-prefix of the container file names, else the stem of
  the one linked network file, else the first container's stem.
* Writers (`writer_units`): a container that mounts a backed-up volume, host directory or config file read-write,
  every client of a database (it depends on the database unit), every database in cold mode, and (closure) every
  container that systemd stops with a writer (Requires/BindsTo/PartOf/Requisite on it) or that lives in a
  writer's network namespace -- the engine only restarts the writers it stopped, so anything stopped with them
  must be one.
* PostgreSQL (image name or POSTGRES_* environment): cold mode by default (database unit is a writer, its data
  volume or directory is backed up whole); `instance` (pg_dumpall + every database) and `database` (one
  pg_dump) are offered as variants when the data lives in a named volume.
* Volumes mounted only at runtime paths (`/run`, `/var/run`, `/tmp`, `/dev/shm`) are skipped; bind mounts of
  directories become `data_dirs` unless they are forbidden (`.ssh`, `.config/systemd`, ...) or personal
  (`Desktop`, `Documents`, ...); bound files and `EnvironmentFile=` files become `config_files` when they lie in
  `.config/<id>/` or `.local/share/<id>/`.
* Health URLs come from URLs in `HealthCmd=` mapped through a loopback `PublishPort=` (or `Network=host`).
"""
import heapq
import json
import os
import posixpath
import pwd
import re
import shlex
from dataclasses import dataclass, field

from . import catalog as catalog_mod
from . import podman
from .catalog_admin import diff_entries
from .errors import BackupError

QUADLET_DIR = '.config/containers/systemd'
LINGER_DIR = '/var/lib/systemd/linger'
SUPPORTED_KINDS = ('container', 'network', 'volume', 'pod')
UNSUPPORTED_KINDS = ('kube', 'image', 'build')
FILE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,190}\.(container|network|volume|pod|kube|image|build)\Z')
SCAN_MAX_ENTRIES = 512
SCAN_MAX_FILE = 1024 * 1024
SCAN_MAX_TOTAL = 8 * 1024 * 1024
SCAN_OUTPUT = 2 * SCAN_MAX_TOTAL + 1024 * 1024  # JSON escapes (newlines, quotes) at most double the text
SMALL_OUTPUT = 1024 * 1024
MAX_STAT_PATHS = 400
MAX_HEALTH = 8
# Per container: an owner's file could repeat a key thousands of times; the analysis stays bounded.
MAX_ITEMS = 128
MAX_VERIFY = 16
TEXT_LIMIT = 120

# Executed as the owner with `python3 -I -c SCAN_HELPER <rel dir>`: every component from $HOME down is opened with
# O_NOFOLLOW, the directory is listed (not recursively), and the Quadlet files in it are returned as UTF-8 text.
# Output: {"state": "ok"|"missing"|"blocked", "entries": [{name, type, size, mode, text?, skipped?}], "more": n}.
SCAN_HELPER = r'''
import json, os, stat, sys
EXTS = ('.container', '.network', '.volume', '.pod', '.kube', '.image', '.build')
MAX_ENTRIES = 512
MAX_FILE = 1048576
MAX_TOTAL = 8388608
def emit(out):
    sys.stdout.buffer.write(json.dumps(out, ensure_ascii=False).encode('utf-8'))
def read_file(fd, name):
    ffd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    try:
        if not stat.S_ISREG(os.fstat(ffd).st_mode):
            return None
        chunks, size = [], 0
        while size <= MAX_FILE:
            chunk = os.read(ffd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b''.join(chunks)
    finally:
        os.close(ffd)
def main():
    out = {'state': 'ok', 'entries': [], 'more': 0}
    try:
        fd = os.open(os.environ['HOME'], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        out['state'] = 'blocked'
        return emit(out)
    for part in sys.argv[1].split('/'):
        try:
            nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        except FileNotFoundError:
            out['state'] = 'missing'
            return emit(out)
        except OSError:
            out['state'] = 'blocked'
            return emit(out)
        os.close(fd)
        fd = nfd
    total = 0
    for name in sorted(os.listdir(fd)):
        try:
            name.encode('utf-8')
        except UnicodeEncodeError:
            out['more'] += 1
            continue
        if len(out['entries']) >= MAX_ENTRIES:
            out['more'] += 1
            continue
        try:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except OSError:
            continue
        kind = ('file' if stat.S_ISREG(st.st_mode) else 'dir' if stat.S_ISDIR(st.st_mode)
                else 'link' if stat.S_ISLNK(st.st_mode) else 'other')
        row = {'name': name, 'type': kind, 'size': st.st_size if kind == 'file' else 0,
               'mode': stat.S_IMODE(st.st_mode)}
        if kind == 'file' and name.endswith(EXTS) and not name.startswith('.'):
            if st.st_size > MAX_FILE or total + st.st_size > MAX_TOTAL:
                row['skipped'] = 'too-large'
            else:
                try:
                    data = read_file(fd, name)
                except OSError:
                    data = None
                if data is None:
                    row['skipped'] = 'unreadable'
                elif len(data) > MAX_FILE or total + len(data) > MAX_TOTAL:
                    row['skipped'] = 'too-large'
                else:
                    try:
                        row['text'] = data.decode('utf-8')
                        total += len(data)
                    except UnicodeDecodeError:
                        row['skipped'] = 'binary'
        out['entries'].append(row)
    emit(out)
main()
'''

ENTRY_TYPES = ('file', 'dir', 'link', 'other')
ENTRY_SKIPS = ('too-large', 'unreadable', 'binary')

# Stop propagation: systemd stops a unit when a unit it Requires/BindsTo/PartOf/Requisite is stopped.
STOP_DEPS = ('Requires', 'BindsTo', 'PartOf', 'Requisite')
ORDER_DEPS = ('Requires', 'BindsTo', 'PartOf', 'Requisite', 'Wants', 'After', 'Upholds')
# A container that depends on a database unit is taken for one of its clients: it writes into the database.
DB_CLIENT_DEPS = ('Requires', 'BindsTo', 'PartOf', 'Requisite', 'Wants', 'After')
RUNTIME_DESTS = ('/run', '/var/run', '/tmp', '/var/tmp', '/dev/shm')
PG_NAMES = frozenset({'postgres', 'postgresql', 'postgis', 'pgvector', 'timescaledb', 'timescaledb-ha',
                      'postgresql-repmgr', 'supabase-postgres'})
CACHE_NAMES = frozenset({'redis', 'valkey', 'keydb', 'dragonfly', 'redis-stack', 'redis-stack-server'})
COLD_DB_NAMES = frozenset({'mariadb', 'mysql', 'mongo', 'mongodb', 'mongodb-community-server', 'percona-server',
                           'clickhouse-server', 'influxdb', 'couchdb', 'elasticsearch', 'opensearch', 'neo4j',
                           'cassandra', 'etcd', 'memgraph', 'questdb'})
PG_DATA_DESTS = ('/var/lib/postgresql/data', '/var/lib/postgresql', '/bitnami/postgresql', '/home/postgres/pgdata')
PG_IDENT_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,62}\Z')
SECRETISH_RE = re.compile(r'(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|_KEY\Z|CREDENTIAL)', re.I)
URL_IN_CMD_RE = re.compile(r'(https?)://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|\[::\])(?::([0-9]{1,5}))?'
                           r'(/[A-Za-z0-9._~!$*+,=:@%/?-]*)?')
TAG_MAJOR_RE = re.compile(r'\A(?:pg)?([0-9]{1,3})(?:[._-]|\Z)')
# Personal folders and whole configuration trees: never proposed as host directories (the administrator can add
# them by hand after deciding the scope). Compared without regard to case on the first segment(s).
SENSITIVE_TOP = frozenset({'desktop', 'documents', 'downloads', 'pictures', 'music', 'videos', 'public', 'templates',
                           'snap', '.aws', '.azure', '.kube', '.docker', '.password-store', '.mozilla',
                           '.thunderbird', '.pki', '.cache', '.npm', '.cargo', '.rustup', '.vscode',
                           '.vscode-server', '.git-credentials', '.netrc', '.gitconfig', '.bash_history',
                           '.ssh', '.gnupg'})
SENSITIVE_EXACT = frozenset({'.config', '.local', '.local/share', '.local/state'})
VARIANT_LABELS = {
    'cold': '冷備份（預設）：資料庫與應用一起停止，資料檔整份備份；保留整個執行個體（所有資料庫、角色與密碼），'
            '還原時 PostgreSQL 主版本必須相同。',
    'instance': '整個執行個體：備份時資料庫保持執行，以 pg_dumpall 保存角色並逐一匯出每個資料庫；'
                '還原到相同或更新的主版本。',
    'database': '單一資料庫：備份時資料庫保持執行，只以 pg_dump 匯出一個資料庫，不保留角色與權限；'
                '執行個體有其他資料庫時無法原位還原。',
}


class Unresolvable(ValueError):
    """A systemd specifier this module does not expand (e.g. %i)."""


# ---------------------------------------------------------------- small helpers

def _printable(text, limit=TEXT_LIMIT):
    """Owner-controlled text for a message: printable characters only, bounded."""
    text = ''.join(ch if ch.isprintable() else '?' for ch in str(text))
    return text if len(text) <= limit else text[:limit - 1] + '…'


def _warn(code, message, **extra):
    item = {'code': code, 'level': extra.pop('level', 'warn'), 'message': message}
    item.update({key: value for key, value in extra.items() if value is not None})
    return item


def parse_unit(text):
    """systemd unit syntax: {section: [(key, value), ...]}; `#`/`;` comments, backslash continuation lines."""
    sections, current, pending = {}, None, None
    for raw in text.splitlines():
        line = raw.strip()
        if pending is not None:
            if line.startswith(('#', ';')):
                continue
            line = pending + ' ' + line
            pending = None
        elif not line or line.startswith(('#', ';')):
            continue
        if line.endswith('\\'):
            pending = line[:-1].rstrip()
            continue
        if line.startswith('[') and line.endswith(']'):
            current = line[1:-1].strip()
            sections.setdefault(current, [])
            continue
        if current is not None and '=' in line:
            key, value = line.split('=', 1)
            sections[current].append((key.strip(), value.strip()))
    if pending is not None and current is not None and '=' in pending:
        key, value = pending.split('=', 1)
        sections[current].append((key.strip(), value.strip()))
    return sections


def values(sections, section, key):
    return [value for name, value in sections.get(section, []) if name == key]


def last(sections, section, key):
    found = values(sections, section, key)
    return found[-1] if found else None


def split_words(value):
    """systemd-style word list (quotes respected); falls back to whitespace on unbalanced quotes."""
    try:
        return shlex.split(value, comments=False, posix=True)
    except ValueError:
        return value.split()


def quadlet_unit(file_name):
    stem, kind = file_name.rsplit('.', 1)
    return f'{stem}.service' if kind == 'container' else f'{stem}-{kind}.service'


def dash_prefix(prefix, name):
    return name == prefix or name.startswith(prefix + '-')


def common_dash_prefix(names):
    split = [name.split('-') for name in names]
    if not split:
        return ''
    common = []
    for parts in zip(*split):
        if all(part == parts[0] for part in parts):
            common.append(parts[0])
        else:
            break
    return '-'.join(common)


def sanitize_id(text):
    text = re.sub(r'[^a-z0-9-]+', '-', str(text).lower()).strip('-')
    text = re.sub(r'-{2,}', '-', text)[:41].strip('-')
    if len(text) < 2:
        text = (text + '-app') if text else 'app'
    return text


def repository_name(ref):
    """`docker.io/library/postgres:16-alpine` -> ('postgres', '16-alpine'); digests drop the tag."""
    ref = ref.split('@', 1)[0]
    last_part = ref.rsplit('/', 1)[-1]
    if ':' in last_part:
        name, tag = last_part.split(':', 1)
    else:
        name, tag = last_part, ''
    return name.lower(), tag


def image_major(ref, low=9, high=99):
    """Major version pinned by the tag (`16-alpine`, `pg17`, `17.2`), else None. PostgreSQL by default (9..99)."""
    _name, tag = repository_name(ref or '')
    match = TAG_MAJOR_RE.match(tag)
    if not match:
        return None
    major = int(match.group(1))
    return major if low <= major <= high else None


def parse_publish(value):
    """`[[ip:][hostPort]:]containerPort[/proto]` -> [(ip, host_port|None, container_port, proto)] (ranges expanded)."""
    value = value.strip()
    proto = 'tcp'
    if '/' in value:
        value, proto = value.rsplit('/', 1)
        proto = proto.lower()
    ip = ''
    if value.startswith('['):
        end = value.find(']')
        if end < 0:
            return []
        ip, value = value[1:end], value[end + 1:].lstrip(':')
        parts = value.split(':')
        if len(parts) == 1:
            host, cport = '', parts[0]
        elif len(parts) == 2:
            host, cport = parts
        else:
            return []
    else:
        parts = value.split(':')
        if len(parts) == 1:
            host, cport = '', parts[0]
        elif len(parts) == 2:
            host, cport = parts
        elif len(parts) == 3:
            ip, host, cport = parts
        else:
            return []

    def span(text):
        if not text:
            return None
        if '-' in text:
            low, high = text.split('-', 1)
            if not (low.isdigit() and high.isdigit()) or int(high) < int(low) or int(high) - int(low) > 256:
                raise ValueError(text)
            return list(range(int(low), int(high) + 1))
        if not text.isdigit():
            raise ValueError(text)
        return [int(text)]

    try:
        hosts, cports = span(host), span(cport)
    except ValueError:
        return []
    if not cports:
        return []
    if hosts is None:
        return [(ip, None, port, proto) for port in cports]
    if len(hosts) != len(cports):
        return []
    return [(ip, hp, cp, proto) for hp, cp in zip(hosts, cports)]


def loopback_usable(ip):
    return ip in ('', '0.0.0.0', '127.0.0.1', '::', '*')


# ---------------------------------------------------------------- model

@dataclass
class Mount:
    kind: str            # 'volume' (named), 'qvolume' (Quadlet .volume), 'bind', 'anonymous', 'other'
    source: str          # volume name, volume file name or absolute host path
    dest: str
    read_only: bool
    rel: str | None = None   # bind source relative to the owner's home (None: outside the home)
    problem: str | None = None


@dataclass
class Container:
    file: str
    stem: str
    unit: str
    name: str
    image: str | None
    sections: dict
    networks: list = field(default_factory=list)       # raw Network= values (Quadlet refs resolved later)
    netns_target: str | None = None                   # container file whose network namespace this joins
    netns_name: str | None = None                     # raw container name from Network=container:<name>
    host_network: bool = False
    pod: str | None = None
    mounts: list = field(default_factory=list)
    env_files: list = field(default_factory=list)      # (absolute path, rel|None)
    secrets: list = field(default_factory=list)
    publish: list = field(default_factory=list)
    health_cmd: str | None = None
    labels: dict = field(default_factory=dict)
    env: dict = field(default_factory=dict)            # only the keys in ENV_KEEP
    secret_env: list = field(default_factory=list)     # names of secret-looking variables with literal values
    deps: dict = field(default_factory=dict)           # {Requires: set(units), ...}
    before: set = field(default_factory=set)
    stop_timeout: int | None = None
    notes: list = field(default_factory=list)


ENV_KEEP = ('POSTGRES_USER', 'POSTGRES_DB', 'PGDATA', 'POSTGRESQL_USERNAME', 'POSTGRESQL_DATABASE')


class _Context:
    def __init__(self, owner, uid, home):
        self.owner, self.uid, self.home = owner, uid, home.rstrip('/') or '/'
        self.specifiers = {'h': self.home, 'U': str(uid), 'u': owner, 't': f'/run/user/{uid}', 'T': '/tmp',
                           'V': '/var/tmp', 'E': f'{self.home}/.config', 'S': f'{self.home}/.local/state',
                           'C': f'{self.home}/.cache', 'L': f'{self.home}/.local/state/log', '%': '%'}

    def expand(self, value):
        out, i = [], 0
        while i < len(value):
            ch = value[i]
            if ch == '%' and i + 1 < len(value):
                key = value[i + 1]
                if key not in self.specifiers:
                    raise Unresolvable(key)
                out.append(self.specifiers[key])
                i += 2
                continue
            out.append(ch)
            i += 1
        return ''.join(out)

    def host_path(self, raw):
        """Absolute normalized path of a bind source or file (relative paths are relative to the Quadlet dir)."""
        path = self.expand(raw)
        if path.startswith('./') or path.startswith('../') or path in ('.', '..'):
            path = posixpath.join(self.home, QUADLET_DIR, path)
        if not path.startswith('/'):
            return None
        return posixpath.normpath(path)

    def rel(self, path):
        """Path relative to the home, '' for the home itself, None outside."""
        if path == self.home:
            return ''
        if path.startswith(self.home + '/'):
            return path[len(self.home) + 1:]
        return None


def _volume_source_kind(source):
    if source.startswith(('/', '.', '%')):
        return 'bind'
    if source.endswith('.volume'):
        return 'qvolume'
    return 'volume'


def _parse_volume(ctx, value):
    parts = value.split(':')
    if len(parts) == 1:
        return Mount('anonymous', '', parts[0], False)
    source, dest = parts[0], parts[1]
    options = [opt.strip().lower() for opt in ':'.join(parts[2:]).split(',') if opt.strip()]
    read_only = 'ro' in options or 'readonly' in options
    kind = _volume_source_kind(source)
    if kind != 'bind':
        return Mount(kind, source, dest, read_only)
    try:
        path = ctx.host_path(source)
    except Unresolvable as error:
        return Mount('bind', source, dest, read_only, problem=f'含有無法解析的 systemd 代換符號 %{error}')
    if path is None:
        return Mount('bind', source, dest, read_only, problem='不是絕對路徑')
    return Mount('bind', path, dest, read_only, rel=ctx.rel(path))


def _parse_mount(ctx, value):
    fields = {}
    flags = set()
    for item in value.split(','):
        item = item.strip()
        if not item:
            continue
        if '=' in item:
            key, val = item.split('=', 1)
            fields[key.strip().lower()] = val.strip()
        else:
            flags.add(item.lower())
    kind = fields.get('type', 'volume').lower()
    source = fields.get('source') or fields.get('src') or ''
    dest = fields.get('destination') or fields.get('dst') or fields.get('target') or ''
    read_only = ('ro' in flags or 'readonly' in flags or fields.get('ro', '').lower() in ('true', '1', 'yes')
                 or fields.get('readonly', '').lower() in ('true', '1', 'yes'))
    if kind == 'bind':
        try:
            path = ctx.host_path(source)
        except Unresolvable as error:
            return Mount('bind', source, dest, read_only, problem=f'含有無法解析的 systemd 代換符號 %{error}')
        if path is None:
            return Mount('bind', source, dest, read_only, problem='不是絕對路徑')
        return Mount('bind', path, dest, read_only, rel=ctx.rel(path))
    if kind == 'volume':
        if not source:
            return Mount('anonymous', '', dest, read_only)
        return Mount(_volume_source_kind(source) if source.endswith('.volume') else 'volume', source, dest, read_only)
    return Mount('other', source, dest, read_only)


def _unit_list(value):
    return {word for word in split_words(value) if word.endswith('.service')}


def _parse_container(ctx, name, text):
    sections = parse_unit(text)
    stem = name[:-len('.container')]
    container = Container(file=name, stem=stem, unit=quadlet_unit(name),
                          name=last(sections, 'Container', 'ContainerName') or f'systemd-{stem}',
                          image=last(sections, 'Container', 'Image'), sections=sections)
    for key in ORDER_DEPS:
        container.deps[key] = set()
        for value in values(sections, 'Unit', key):
            container.deps[key] |= _unit_list(value)
    for value in values(sections, 'Unit', 'Before'):
        container.before |= _unit_list(value)
    for value in values(sections, 'Container', 'Network'):
        _add_network(container, value)
    pod = last(sections, 'Container', 'Pod')
    if pod:
        container.pod = pod
    for value in values(sections, 'Container', 'Volume'):
        container.mounts.append(_parse_volume(ctx, value))
    for value in values(sections, 'Container', 'Mount'):
        container.mounts.append(_parse_mount(ctx, value))
    for value in values(sections, 'Container', 'Secret'):
        secret = value.split(',', 1)[0].strip()
        if secret:
            container.secrets.append(secret)
    for value in values(sections, 'Container', 'PublishPort'):
        container.publish.extend(parse_publish(value))
    for value in values(sections, 'Container', 'EnvironmentFile') + values(sections, 'Service', 'EnvironmentFile'):
        _add_env_file(ctx, container, value)
    for value in values(sections, 'Container', 'Environment'):
        _add_environment(container, value)
    for value in values(sections, 'Container', 'Label'):
        for word in split_words(value):
            if '=' in word:
                key, val = word.split('=', 1)
                container.labels[key.strip()] = val.strip()
    health = last(sections, 'Container', 'HealthCmd')
    container.health_cmd = health if health and health.lower() != 'none' else None
    for value in values(sections, 'Container', 'PodmanArgs'):
        _parse_podman_args(ctx, container, value)
    timeout = last(sections, 'Container', 'StopTimeout')
    if timeout and timeout.isdigit():
        container.stop_timeout = int(timeout)
    for attribute in ('mounts', 'secrets', 'publish', 'env_files'):
        items = getattr(container, attribute)
        if len(items) > MAX_ITEMS:
            del items[MAX_ITEMS:]
            container.notes.append(_warn('too-many', f'{name} 的 {attribute} 項目過多，只分析前 {MAX_ITEMS} 個。', file=name))
    if last(sections, 'Container', 'ServiceName') or last(sections, 'Service', 'ServiceName'):
        container.notes.append(_warn('service-name', f'{name} 以 ServiceName= 改了服務名稱；備份元件假設服務名稱是 '
                                                     f'{container.unit}，請確認。', file=name))
    return container


def _add_network(container, value):
    value = value.strip()
    mode = value.split(':', 1)[0].split(',', 1)[0]
    if mode == 'host':
        container.host_network = True
    elif mode == 'container' and ':' in value:
        container.netns_name = value.split(':', 1)[1].split(',', 1)[0]
    elif value.endswith('.container'):
        container.netns_target = value
    elif mode in ('none', 'private', 'slirp4netns', 'pasta', 'bridge', 'ns', ''):
        return
    else:
        container.networks.append(value.split(':', 1)[0])


def _add_env_file(ctx, container, value):
    raw = value.strip()
    if raw.startswith('-'):
        raw = raw[1:]
    try:
        path = ctx.host_path(raw)
    except Unresolvable as error:
        container.notes.append(_warn('env-file-unresolved', f'{container.file} 的 EnvironmentFile= 含有無法解析的代換符號 '
                                                            f'%{_printable(error)}，未列入設定檔。', file=container.file))
        return
    if path is None:
        return
    container.env_files.append((path, ctx.rel(path)))


def _add_environment(container, value):
    for word in split_words(value):
        if '=' not in word:
            continue
        key, val = word.split('=', 1)
        if key in ENV_KEEP:
            container.env[key] = val
        if SECRETISH_RE.search(key) and val and not key.endswith('_FILE') and key not in container.secret_env:
            container.secret_env.append(key)


def _parse_podman_args(ctx, container, value):
    words = split_words(value)
    i = 0
    while i < len(words):
        word = words[i]
        option, inline = (word.split('=', 1) + [None])[:2] if word.startswith('--') else (word, None)

        def take():
            nonlocal i
            if inline is not None:
                return inline
            i += 1
            return words[i] if i < len(words) else None

        if option in ('-v', '--volume'):
            arg = take()
            if arg:
                container.mounts.append(_parse_volume(ctx, arg))
        elif option == '--mount':
            arg = take()
            if arg:
                container.mounts.append(_parse_mount(ctx, arg))
        elif option in ('--network', '--net'):
            arg = take()
            if arg:
                _add_network(container, arg)
        elif option in ('-p', '--publish'):
            arg = take()
            if arg:
                container.publish.extend(parse_publish(arg))
        elif option == '--secret':
            arg = take()
            if arg:
                container.secrets.append(arg.split(',', 1)[0].strip())
        elif option == '--env-file':
            arg = take()
            if arg:
                _add_env_file(ctx, container, arg)
        elif option in ('-l', '--label'):
            arg = take()
            if arg and '=' in arg:
                key, val = arg.split('=', 1)
                container.labels[key.strip()] = val.strip()
        elif option == '--pod':
            arg = take()
            if arg:
                container.pod = arg
        elif option in ('-e', '--env'):
            arg = take()
            if arg:
                _add_environment(container, shlex.quote(arg))
        elif option == '--stop-timeout':
            arg = take()
            if arg and arg.isdigit():
                container.stop_timeout = int(arg)
        i += 1


@dataclass
class AuxFile:
    file: str
    kind: str
    stem: str
    name: str                 # NetworkName / VolumeName / PodName (Quadlet default systemd-<stem>)
    sections: dict


def _parse_aux(name, text):
    stem, kind = name.rsplit('.', 1)
    sections = parse_unit(text)
    key = {'network': 'NetworkName', 'volume': 'VolumeName', 'pod': 'PodName'}[kind]
    return AuxFile(file=name, kind=kind, stem=stem, sections=sections,
                   name=last(sections, kind.capitalize(), key) or f'systemd-{stem}')


# ---------------------------------------------------------------- scanning (owner side)

def _scan_ok(data):
    if not isinstance(data, dict) or set(data) != {'state', 'entries', 'more'}:
        return False
    if data['state'] not in ('ok', 'missing', 'blocked') or type(data['more']) is not int or data['more'] < 0:
        return False
    entries = data['entries']
    if not isinstance(entries, list) or len(entries) > SCAN_MAX_ENTRIES:
        return False
    total = 0
    for row in entries:
        if not isinstance(row, dict) or not {'name', 'type', 'size', 'mode'} <= set(row) <= {
                'name', 'type', 'size', 'mode', 'text', 'skipped'}:
            return False
        name = row['name']
        if not isinstance(name, str) or not 0 < len(name) <= 255 or '/' in name or '\x00' in name:
            return False
        if row['type'] not in ENTRY_TYPES or type(row['size']) is not int or row['size'] < 0:
            return False
        if type(row['mode']) is not int or not 0 <= row['mode'] <= 0o7777:
            return False
        if 'skipped' in row and row['skipped'] not in ENTRY_SKIPS:
            return False
        if 'text' in row:
            if not isinstance(row['text'], str) or row['type'] != 'file':
                return False
            total += len(row['text'])
            if len(row['text']) > SCAN_MAX_FILE or total > SCAN_MAX_TOTAL:
                return False
    return True


def scan_quadlet_dir(runner):
    """The owner's Quadlet directory as the owner sees it (validated answer of SCAN_HELPER)."""
    result = runner.run([podman.PYTHON, '-I', '-c', SCAN_HELPER, QUADLET_DIR], timeout=120, check=False,
                        max_output=SCAN_OUTPUT)
    if result.returncode != 0:
        raise BackupError('job-failed', f'無法以擁有者 {runner.owner} 的身分讀取 ~/{QUADLET_DIR}（結束碼 {result.returncode}）。',
                          owner=runner.owner)
    try:
        data = json.loads((result.stdout or b'').decode('utf-8'))
        ok = _scan_ok(data)
    except (ValueError, UnicodeDecodeError, RecursionError):
        ok = False
    if not ok:
        raise BackupError('job-failed', 'Quadlet 資料夾的讀取結果格式不正確，已停止。', owner=runner.owner)
    return data


def _owner_names(runner, *args):
    """Names printed one per line by a read-only owner podman command; None when it failed."""
    try:
        result = runner.podman(*args, timeout=60, check=False, max_output=SMALL_OUTPUT)
    except BackupError:
        return None
    if result.returncode != 0:
        return None
    names = set()
    for line in (result.stdout or b'').decode('utf-8', 'replace').splitlines():
        line = line.strip()
        if line:
            names.add(line)
    return names


def _unit_states(runner, units):
    """{unit: ActiveState} read with one `systemctl --user show`; {} when it failed."""
    units = [unit for unit in units if catalog_mod.UNIT_RE.fullmatch(unit)]
    if not units:
        return {}
    try:
        result = runner.systemctl('show', '--property=Id,LoadState,ActiveState', '--', *units, timeout=60,
                                  check=False, max_output=SMALL_OUTPUT)
    except BackupError:
        return {}
    if result.returncode != 0:
        return {}
    states = {}
    for block in (result.stdout or b'').decode('utf-8', 'replace').split('\n\n'):
        fields = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        unit = fields.get('Id')
        if unit in units:
            state = fields.get('ActiveState') or 'unknown'
            states[unit] = 'not-found' if fields.get('LoadState') == 'not-found' else state
    return states


# ---------------------------------------------------------------- analysis

class _Groups:
    """Union-find over container files; `io.woowtech.app` labels are hard partitions."""

    def __init__(self, items, labels):
        self.parent = {item: item for item in items}
        self.label = {item: labels.get(item) for item in items}
        self.refused = []

    def find(self, item):
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a, b, why):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        la, lb = self.label[ra], self.label[rb]
        if la and lb and la != lb:
            self.refused.append((a, b, why))
            return
        self.parent[rb] = ra
        self.label[ra] = la or lb


@dataclass
class Database:
    container: Container
    kind: str                   # 'postgres', 'cache', 'other'
    data: Mount | None = None   # the mount that holds the data
    database: str | None = None
    user: str | None = None
    guessed: bool = False       # database/user not found in the Quadlet file
    major: int | None = None


class Analyzer:
    def __init__(self, owner, uid, home, entries, *, stat=None, secrets=None, volumes=None, unit_states=None,
                 installed=(), other_ids=(), paths=None, user_lookup=None):
        self.ctx = _Context(owner, uid, home)
        self.entries = entries
        self.stat_fn = stat or (lambda rels: {})
        self.secret_names = secrets
        self.volume_names = volumes
        self.unit_states_fn = unit_states or (lambda units: {})
        self.installed = list(installed)
        self.other_ids = set(other_ids)
        self.paths = paths
        self.user_lookup = user_lookup
        self.warnings = []
        self.unsupported = []
        self.unassigned = []
        self.containers = {}
        self.aux = {}

    # ------------------------------------------------------------ parsing
    def _load(self):
        for row in self.entries:
            name = row['name']
            if name.startswith('.'):
                continue
            if row['type'] == 'dir':
                if name.endswith('.d'):
                    self.warnings.append(_warn('dropin', f'Quadlet 附加設定資料夾 {_printable(name)} 沒有分析；'
                                                         '請確認它沒有改變掛載、密鑰或相依關係。'))
                else:
                    self.warnings.append(_warn('subdir', f'子資料夾 {_printable(name)} 中的 Quadlet 檔沒有分析'
                                                         '（備份元件只支援直接放在 Quadlet 資料夾的檔案）。'))
                continue
            match = FILE_RE.fullmatch(name)
            if not match:
                if name.rsplit('.', 1)[-1] in SUPPORTED_KINDS + UNSUPPORTED_KINDS:
                    self.warnings.append(_warn('file-name', f'Quadlet 檔名 {_printable(name)} 含有不支援的字元，已略過。'))
                continue
            kind = match.group(1)
            if row['type'] == 'link':
                self.warnings.append(_warn('symlink', f'{name} 是符號連結；備份元件只接受一般檔案，已略過。', file=name))
                continue
            if row['type'] != 'file':
                continue
            if kind in UNSUPPORTED_KINDS:
                self.unsupported.append({'file': name, 'reason': f'.{kind} 類型的 Quadlet 檔不受支援，這個應用需要人工評估。'})
                continue
            if '@' in name:
                self.unsupported.append({'file': name, 'reason': '範本單元（檔名含 @）不受支援。'})
                continue
            if 'text' not in row:
                reason = {'too-large': '檔案過大', 'binary': '不是 UTF-8 文字', 'unreadable': '無法讀取'}.get(
                    row.get('skipped'), '無法讀取')
                self.warnings.append(_warn('file-unread', f'{name}：{reason}，已略過。', file=name))
                continue
            if kind == 'container':
                self.containers[name] = _parse_container(self.ctx, name, row['text'])
            else:
                self.aux[name] = _parse_aux(name, row['text'])

    # ------------------------------------------------------------ resolution helpers
    def _resolve_netns(self):
        by_name = {c.name: c.file for c in self.containers.values()}
        for container in self.containers.values():
            if container.netns_name:
                target = by_name.get(container.netns_name)
                if target is None and f'{container.netns_name}.container' in self.containers:
                    target = f'{container.netns_name}.container'
                if target is None:
                    container.notes.append(_warn('netns-unknown', f'{container.file} 使用容器 '
                                                                  f'{_printable(container.netns_name)} 的網路，但找不到它的 '
                                                                  'Quadlet 檔。', file=container.file))
                container.netns_target = target
            elif container.netns_target and container.netns_target not in self.containers:
                container.notes.append(_warn('netns-unknown', f'{container.file} 參照 '
                                                              f'{_printable(container.netns_target)}，但找不到這個 Quadlet 檔。',
                                             file=container.file))
                container.netns_target = None

    def _volume_key(self, mount):
        """(volume name, its `.volume` file or None) of a named-volume mount; None for other mounts."""
        if mount.kind == 'qvolume':
            aux = self.aux.get(mount.source)
            return (aux.name if aux else mount.source[:-len('.volume')], mount.source if aux else None)
        if mount.kind == 'volume':
            return (mount.source, None)
        return None

    def _unit_owner(self):
        return {c.unit: c.file for c in self.containers.values()}

    # ------------------------------------------------------------ grouping
    def _group(self):
        files = sorted(self.containers)
        hard = {f: self.containers[f].labels.get('io.woowtech.app') or None for f in files}
        groups = _Groups(files + [f'net:{name}' for name in self._network_keys()], hard)
        units = self._unit_owner()
        for container in self.containers.values():
            for key, targets in container.deps.items():
                for unit in targets:
                    if unit in units and units[unit] != container.file:
                        groups.union(container.file, units[unit], f'{key}={unit}')
            for unit in container.before:
                if unit in units and units[unit] != container.file:
                    groups.union(container.file, units[unit], f'Before={unit}')
            if container.netns_target:
                groups.union(container.file, container.netns_target, 'network namespace')
        by_pod, by_volume, by_app, binds = {}, {}, {}, []
        for container in self.containers.values():
            if container.pod:
                by_pod.setdefault(container.pod, []).append(container.file)
            for mount in container.mounts:
                key = self._volume_key(mount)
                if key:
                    by_volume.setdefault(key[0], []).append(container.file)
                elif mount.kind == 'bind' and mount.rel:
                    binds.append((mount.rel, container.file))
            if container.labels.get('app'):
                by_app.setdefault(container.labels['app'], []).append(container.file)
            for network in container.networks:
                key = self._network_key(network)
                if key and self._network_links(key, container):
                    groups.union(container.file, f'net:{key}', f'Network={network}')
        for why, mapping in (('pod', by_pod), ('volume', by_volume), ('app label', by_app)):
            for key, members in mapping.items():
                for other in members[1:]:
                    groups.union(members[0], other, f'{why} {key}')
        for i, (rel_a, file_a) in enumerate(binds):
            for rel_b, file_b in binds[i + 1:]:
                if file_a != file_b and catalog_mod.paths_overlap(rel_a, rel_b):
                    groups.union(file_a, file_b, f'host directory {rel_a}')
        for a, b, why in groups.refused:
            if a.startswith('net:') or b.startswith('net:'):
                continue
            self.warnings.append(_warn('cross-app-link', f'{a} 與 {b} 標示為不同的應用（io.woowtech.app），但兩者有關聯'
                                                         f'（{_printable(why)}）；備份其中一個時另一個不會一起停止。'))
        components = {}
        for file in files:
            components.setdefault(groups.find(file), []).append(file)
        return [sorted(members) for members in components.values()], groups

    def _network_keys(self):
        keys = set()
        for container in self.containers.values():
            for network in container.networks:
                key = self._network_key(network)
                if key:
                    keys.add(key)
        return sorted(keys)

    def _network_key(self, value):
        if value.endswith('.network'):
            return value
        return value or None

    def _network_links(self, key, container):
        """A network links a container to an app only when its name is the container's family prefix."""
        stem = key[:-len('.network')] if key.endswith('.network') else key
        names = {stem}
        aux = self.aux.get(key)
        if aux:
            names.add(aux.name)
        return any(dash_prefix(name, container.stem) for name in names if name)

    # ------------------------------------------------------------ databases
    def _database(self, container):
        name, _tag = repository_name(container.image or '')
        dests = {posixpath.normpath(m.dest) for m in container.mounts if m.dest}
        env = container.env
        is_pg = name in PG_NAMES or (('postgres' in name or 'pgvector' in name or 'postgis' in name)
                                    and bool(dests & set(PG_DATA_DESTS)))
        if not is_pg and any(key.startswith('POSTGRES') for key in env) and dests & set(PG_DATA_DESTS):
            is_pg = True
        if is_pg:
            db = Database(container, 'postgres', major=image_major(container.image))
            pgdata = env.get('PGDATA') or ''
            candidates = [m for m in container.mounts if m.dest and m.kind in ('volume', 'qvolume', 'bind')]
            data = None
            if pgdata:
                for mount in candidates:
                    dest = posixpath.normpath(mount.dest)
                    if pgdata == dest or pgdata.startswith(dest.rstrip('/') + '/'):
                        if data is None or len(dest) > len(posixpath.normpath(data.dest)):
                            data = mount
            if data is None:
                for dest in PG_DATA_DESTS:
                    data = next((m for m in candidates if posixpath.normpath(m.dest) == dest), None)
                    if data:
                        break
            db.data = data
            user = env.get('POSTGRES_USER') or env.get('POSTGRESQL_USERNAME')
            database = env.get('POSTGRES_DB') or env.get('POSTGRESQL_DATABASE')
            hint_user, hint_db = self._pg_isready_hints(container.health_cmd)
            if not user and hint_user:
                user = hint_user
            if not database and hint_db:
                database = hint_db
            db.guessed = not (env.get('POSTGRES_USER') or env.get('POSTGRESQL_USERNAME'))
            db.user = user if user and PG_IDENT_RE.fullmatch(user) else 'postgres'
            db.database = database if database and PG_IDENT_RE.fullmatch(database) else db.user
            return db
        if name in CACHE_NAMES:
            return Database(container, 'cache')
        if name in COLD_DB_NAMES:
            return Database(container, 'other')
        return None

    @staticmethod
    def _pg_isready_hints(command):
        if not command or 'pg_isready' not in command:
            return None, None
        words = split_words(command)
        user = database = None
        for i, word in enumerate(words):
            nxt = words[i + 1] if i + 1 < len(words) else None
            if word in ('-U', '--username') and nxt:
                user = nxt
            elif word.startswith('--username='):
                user = word.split('=', 1)[1]
            elif word in ('-d', '--dbname') and nxt:
                database = nxt
            elif word.startswith('--dbname='):
                database = word.split('=', 1)[1]
        return user, database

    # ------------------------------------------------------------ app building
    def analyze(self):
        self._load()
        self._resolve_netns()
        components, _groups = self._group()
        apps = [self._app(members) for members in components]
        self._assign_aux(apps)
        self._name_apps(apps)
        stats = self._stat_all(apps)
        states = self.unit_states_fn([c.unit for c in self.containers.values()])
        result = []
        for app in sorted(apps, key=lambda a: a['id']):
            result.append(self._finish(app, stats, states))
        return {'apps': result, 'unassigned': self.unassigned, 'unsupported': self.unsupported,
                'warnings': self.warnings}

    def _app(self, members):
        containers = [self.containers[f] for f in members]
        return {'containers': containers, 'aux': [], 'warnings': [], 'notes': [], 'skipped': [], 'hints': []}

    def _assign_aux(self, apps):
        owner_of = {}
        for index, app in enumerate(apps):
            for container in app['containers']:
                owner_of[container.file] = index
        refs = {}
        for container in self.containers.values():
            index = owner_of[container.file]
            for mount in container.mounts:
                if mount.kind == 'qvolume':
                    if mount.source in self.aux:
                        refs.setdefault(mount.source, set()).add(index)
                    else:
                        apps[index]['warnings'].append(_warn(
                            'missing-file', f'{container.file} 參照 {_printable(mount.source)}，但找不到這個 Quadlet 檔。',
                            file=container.file))
            for network in container.networks:
                if network.endswith('.network'):
                    if network in self.aux:
                        refs.setdefault(network, set()).add(index)
                    else:
                        apps[index]['warnings'].append(_warn(
                            'missing-file', f'{container.file} 參照 {_printable(network)}，但找不到這個 Quadlet 檔。',
                            file=container.file))
            if container.pod and container.pod.endswith('.pod'):
                if container.pod in self.aux:
                    refs.setdefault(container.pod, set()).add(index)
        prelim = [self._preliminary_id(app) for app in apps]
        for name in sorted(self.aux):
            aux = self.aux[name]
            users = sorted(refs.get(name, set()))
            if len(users) == 1:
                apps[users[0]]['aux'].append(aux)
                continue
            if len(users) > 1:
                owner = next((i for i in users if dash_prefix(prelim[i], aux.stem) or prelim[i] == aux.stem), users[0])
                apps[owner]['aux'].append(aux)
                for i in users:
                    if i != owner:
                        apps[i]['warnings'].append(_warn('shared-file', f'{name} 也被應用 {prelim[owner]} 使用；全新部署時'
                                                                        '需要先部署那個應用。', file=name))
                continue
            candidates = [i for i, pid in enumerate(prelim) if dash_prefix(pid, aux.stem)]
            if candidates:
                best = max(candidates, key=lambda i: len(prelim[i]))
                apps[best]['aux'].append(aux)
                apps[best]['notes'].append(_warn('aux-by-name', f'{name} 沒有被任何容器使用，依名稱歸入此應用。',
                                                 level='info', file=name))
            else:
                self.unassigned.append({'file': name, 'reason': '沒有容器使用這個檔案，也無法依名稱判斷屬於哪個應用。'})

    def _preliminary_id(self, app):
        hard = {c.labels.get('io.woowtech.app') for c in app['containers']} - {None, ''}
        if len(hard) == 1:
            return sanitize_id(next(iter(hard)))
        prefix = common_dash_prefix([c.stem for c in app['containers']])
        if prefix:
            return sanitize_id(prefix)
        linked = sorted({key for c in app['containers'] for key in c.networks
                         if key.endswith('.network') and self._network_links(key, c)})
        if len(linked) == 1:
            return sanitize_id(linked[0][:-len('.network')])
        soft = {c.labels.get('app') for c in app['containers']} - {None, ''}
        if len(soft) == 1:
            return sanitize_id(next(iter(soft)))
        return sanitize_id(sorted(c.stem for c in app['containers'])[0])

    def _name_apps(self, apps):
        taken = set()
        installed_by_file = {}
        for entry in self.installed:
            for name in entry.quadlet_files:
                installed_by_file.setdefault(name, set()).add(entry.id)
        for app in apps:
            files = {c.file for c in app['containers']} | {a.file for a in app['aux']}
            matches = set()
            for name in files:
                matches |= installed_by_file.get(name, set())
            app['installed_ids'] = sorted(matches)
            app_id = self._preliminary_id(app)
            if len(matches) == 1:
                match = next(iter(matches))
                if match != app_id:
                    app['notes'].append(_warn('installed-id', f'沿用已安裝的應用設定 ID「{match}」（自動判斷為「{app_id}」）。',
                                              level='info'))
                app_id = match
            elif len(matches) > 1:
                app['warnings'].append(_warn('installed-split', '這些 Quadlet 檔分屬多個已安裝的應用設定：'
                                                                f'{"、".join(sorted(matches))}；請確認分組。'))
            base, n = app_id, 2
            while app_id in taken:
                app_id = sanitize_id(f'{base[:37]}-{n}')
                n += 1
            taken.add(app_id)
            if app_id in self.other_ids and not matches:
                app['warnings'].append(_warn('id-taken', f'ID「{app_id}」已被另一個擁有者的應用設定使用；安裝前請改用其他 ID。',
                                             level='error'))
                app['id_taken'] = True
            app['id'] = app_id

    # ------------------------------------------------------------ host paths
    def _stat_all(self, apps):
        rels = []
        for app in apps:
            for container in app['containers']:
                for mount in container.mounts:
                    if mount.kind == 'bind' and mount.rel:
                        rels.append(mount.rel)
                for _path, rel in container.env_files:
                    if rel:
                        rels.append(rel)
        wanted, seen = [], set()
        for rel in rels:
            if rel in seen:
                continue
            seen.add(rel)
            try:
                podman.validate_rel_path(rel)
            except BackupError:
                continue
            wanted.append(rel)
        stats = {}
        for start in range(0, len(wanted), MAX_STAT_PATHS):
            chunk = wanted[start:start + MAX_STAT_PATHS]
            try:
                stats.update(self.stat_fn(chunk))
            except BackupError as error:
                self.warnings.append(_warn('stat-failed', f'無法讀取掛載來源的狀態：{_printable(error.message)}'))
        return stats

    # ------------------------------------------------------------ one app
    def _finish(self, app, stats, states):
        app_id = app['id']
        containers = app['containers']
        databases = {c.file: db for c in containers for db in [self._database(c)] if db}
        order = self._start_order(containers, databases, app)
        app['order'] = order
        mounts_info = self._classify_mounts(app, containers, stats, databases)
        configs = self._config_files(app, containers, stats, mounts_info)
        secrets = self._secrets(app, containers)
        health = self._health(app, containers, order)
        pg = [db for db in (databases.get(c.file) for c in order) if db and db.kind == 'postgres']
        variants = self._variants(app, order, databases, pg, mounts_info, configs, secrets, health)
        warnings = list(app['warnings'])
        for container in containers:
            warnings.extend(container.notes)
            if container.secret_env:
                warnings.append(_warn('environment-secret', f'{container.file} 以 Environment= 直接寫入看似機密的變數 '
                                                            f'{"、".join(sorted(container.secret_env)[:5])}（值未顯示）：它會隨'
                                                            ' Quadlet 檔一起出現在備份中，建議改用 Podman secret。',
                                      file=container.file))
            if container.image and container.image.endswith(('.image', '.build')):
                warnings.append(_warn('image-ref', f'{container.file} 的 Image= 指向 {container.image[:80]}，備份元件不支援，'
                                                   '請改用映像名稱。', file=container.file))
            elif container.image and container.image.startswith('localhost/'):
                app['hints'].append(f'{container.file} 使用本機建置的映像 {_printable(container.image, 80)}：跨設備還原時'
                                    '備份必須包含映像。')
            elif not container.image:
                warnings.append(_warn('image-missing', f'{container.file} 沒有 Image=。', file=container.file))
        unit_states = {c.unit: states.get(c.unit, 'unknown') for c in order}
        if states and not any(state == 'active' for state in unit_states.values()):
            warnings.append(_warn('not-running', '這個應用目前沒有執行中的服務；請確認它仍在使用。', level='info'))
        selected = self._selected_variant(app, variants)
        installed = self._installed_view(app, variants, selected)
        if app.get('id_taken'):
            # Installing it would take over another owner's entry and its backups (review M3): not installable as is.
            for variant in variants:
                variant.update(valid=False, field='id',
                               problem=f'ID「{app_id}」已被另一個擁有者的應用設定使用；請把草稿的 id 改成其他名稱後再安裝。')
        chosen = next(v for v in variants if v['id'] == selected)
        return {
            'id': app_id,
            'containers': [{'file': c.file, 'unit': c.unit, 'container': c.name,
                            'image': _printable(c.image or '', 200), 'state': unit_states.get(c.unit, 'unknown')}
                           for c in order],
            'databases': [self._database_view(db) for db in (databases.get(c.file) for c in order) if db],
            'entry': chosen['entry'], 'valid': chosen['valid'], 'problem': chosen['problem'], 'field': chosen['field'],
            'variant': selected,
            'variants': variants if pg else [],
            'installed': installed,
            'warnings': warnings,
            'notes': app['notes'],
            'skipped': app['skipped'],
            'hints': app['hints'],
        }

    def _database_view(self, db):
        view = {'unit': db.container.unit, 'container': db.container.name, 'kind': db.kind,
                'image': _printable(db.container.image or '', 200)}
        if db.kind == 'postgres':
            view.update({'major': db.major, 'database': db.database, 'user': db.user, 'guessed': db.guessed,
                         'data': None})
            if db.data is not None:
                key = self._volume_key(db.data)
                if key:
                    view['data'] = {'volume': key[0]}
                elif db.data.kind == 'bind' and db.data.rel:
                    view['data'] = {'dir': db.data.rel}
        return view

    def _start_order(self, containers, databases, app):
        """Start order: After=/Before= and network namespaces are ordering edges (as for systemd); a unit's other
        dependencies (Requires/Wants/...) are taken as "start that one first" too unless that would be a cycle.
        Ties: databases, then caches, then the rest, by file name."""
        units = {c.unit: c for c in containers}

        def edges(soft):
            preds = {c.unit: set() for c in containers}
            for container in containers:
                keys = ORDER_DEPS if soft else ('After',)
                for key in keys:
                    for unit in container.deps.get(key, set()):
                        if unit in units and unit != container.unit:
                            preds[container.unit].add(unit)
                for unit in container.before:
                    if unit in units and unit != container.unit:
                        preds[unit].add(container.unit)
                if container.netns_target:
                    target = self.containers.get(container.netns_target)
                    if target and target.unit in units:
                        preds[container.unit].add(target.unit)
            return preds

        def tier(container):
            db = databases.get(container.file)
            if db and db.kind in ('postgres', 'other'):
                return 0
            if db and db.kind == 'cache':
                return 1
            return 2

        def kahn(preds, force=False):
            preds = {unit: set(items) for unit, items in preds.items()}
            heap = [(tier(c), c.file, c.unit) for c in containers if not preds[c.unit]]
            heapq.heapify(heap)
            done, order = set(), []
            while len(order) < len(containers):
                if not heap:
                    if not force:
                        return None
                    rest = sorted((tier(c), c.file, c.unit) for c in containers if c.unit not in done)
                    heap = [rest[0]]
                    preds[rest[0][2]] = set()
                _tier, _file, unit = heapq.heappop(heap)
                if unit in done:
                    continue
                done.add(unit)
                order.append(units[unit])
                for other in containers:
                    if other.unit not in done and unit in preds[other.unit]:
                        preds[other.unit].discard(unit)
                        if not preds[other.unit]:
                            heapq.heappush(heap, (tier(other), other.file, other.unit))
            return order

        order = kahn(edges(True)) or kahn(edges(False))
        if order is None:
            app['warnings'].append(_warn('dependency-cycle', '服務之間的 After=／Before= 有循環，啟動順序改依類型與名稱排列；'
                                                             '請確認。'))
            order = kahn(edges(False), force=True)
        return order

    def _classify_mounts(self, app, containers, stats, databases):
        """Volumes and host directories of the app: {'volumes': {name: info}, 'dirs': {rel: info}}."""
        volumes, dirs, files = {}, {}, {}
        db_data = {}
        for container in containers:
            db = databases.get(container.file)
            if db and db.kind == 'postgres' and db.data is not None:
                db_data[id(db.data)] = db
        for container in sorted(containers, key=lambda c: app['order'].index(c)):
            for mount in container.mounts:
                if mount.kind in ('volume', 'qvolume'):
                    key = self._volume_key(mount)
                    name = key[0]
                    if not catalog_mod.VOLUME_RE.fullmatch(name):
                        app['skipped'].append({'kind': 'volume', 'name': _printable(name),
                                               'reason': '資料卷名稱含有不支援的字元，無法列入。'})
                        continue
                    info = volumes.setdefault(name, {'name': name, 'users': [], 'rw': [], 'dests': [], 'db': None,
                                                     'file': key[1]})
                    info['users'].append(container)
                    info['dests'].append(mount.dest)
                    if not mount.read_only:
                        info['rw'].append(container)
                    if id(mount) in db_data:
                        info['db'] = db_data[id(mount)]
                elif mount.kind == 'anonymous':
                    app['skipped'].append({'kind': 'volume', 'name': '',
                                           'reason': f'{container.file} 有匿名資料卷 {_printable(mount.dest)}：容器移除時'
                                                     '一併刪除，不會備份；需要保存的資料請改用具名資料卷。'})
                elif mount.kind == 'bind':
                    self._classify_bind(app, container, mount, stats, dirs, files, db_data)
        # Runtime-only volumes (sockets, PID files) are not data.
        for name, info in list(volumes.items()):
            if info['db'] is None and info['dests'] and all(_runtime_dest(dest) for dest in info['dests']):
                app['skipped'].append({'kind': 'volume', 'name': name,
                                       'reason': '只掛載在執行期路徑（/run、/tmp 等），通常是 socket 或暫存檔，不列入備份。'})
                info['runtime'] = True
            if self.volume_names is not None and name not in self.volume_names:
                app['warnings'].append(_warn('volume-missing', f'資料卷 {name} 目前不存在（可能尚未啟動過）；備份時必須存在。'))
        # Outermost host directory wins; directories inside it are covered by it (inner ones merged first).
        for rel in sorted(list(dirs), key=len, reverse=True):
            outer = next((o for o in dirs if o != rel and len(o) < len(rel) and catalog_mod.paths_overlap(o, rel)),
                         None)
            if outer is None:
                continue
            inner = dirs.pop(rel)
            dirs[outer]['users'].extend(inner['users'])
            dirs[outer]['rw'].extend(inner['rw'])
            dirs[outer]['read_only'] = dirs[outer]['read_only'] and inner['read_only']
            if inner['db'] is not None and dirs[outer]['db'] is None:
                dirs[outer]['db'] = inner['db']
            app['notes'].append(_warn('dir-nested', f'~/{rel} 位於 ~/{outer} 之內，由外層資料夾一併備份。',
                                      level='info', path=rel))
        for rel, info in dirs.items():
            if info['read_only']:
                app['notes'].append(_warn('dir-read-only', f'~/{rel} 只以唯讀方式掛載（例如設定或程式資料夾），仍列為主機資料夾'
                                                           '一併備份；不需要時可從 data_dirs 移除。', level='info', path=rel))
        return {'volumes': volumes, 'dirs': dirs, 'files': files}

    def _classify_bind(self, app, container, mount, stats, dirs, files, db_data):
        source = mount.source
        if mount.problem:
            app['skipped'].append({'kind': 'bind', 'path': _printable(source),
                                   'reason': f'{container.file} 的掛載來源{mount.problem}，未列入。'})
            return
        if mount.rel is None:
            reason = '主機系統路徑，不列入應用備份。'
            if source.endswith('podman.sock') or source.endswith('docker.sock'):
                app['warnings'].append(_warn('podman-socket', f'{container.file} 掛載了 {_printable(source)}：容器可以控制'
                                                              '擁有者的 Podman，請確認這是必要的。', file=container.file))
                reason = 'Podman／Docker 控制通道，不列入備份。'
            app['skipped'].append({'kind': 'bind', 'path': _printable(source), 'reason': reason})
            return
        rel = mount.rel
        if rel == '':
            app['warnings'].append(_warn('bind-home', f'{container.file} 掛載了整個家目錄，無法備份；請改掛載需要的資料夾。',
                                         file=container.file))
            return
        state = stats.get(rel)
        kind = state.get('type') if isinstance(state, dict) else None
        if kind is None:
            app['skipped'].append({'kind': 'bind', 'path': _printable(rel),
                                   'reason': '路徑含有不支援的字元或無法讀取狀態，未列入。'})
            return
        if kind == 'missing':
            app['warnings'].append(_warn('bind-missing', f'~/{_printable(rel)} 不存在（{container.file} 掛載它）。',
                                         path=_printable(rel)))
            return
        if kind == 'link':
            app['warnings'].append(_warn('bind-symlink', f'~/{_printable(rel)} 是符號連結；備份元件不跟隨符號連結，請改掛載實際路徑。',
                                         path=_printable(rel)))
            return
        if kind in ('blocked', 'other'):
            app['warnings'].append(_warn('bind-blocked', f'無法以擁有者身分確認 ~/{_printable(rel)} 的類型，未列入。',
                                         path=_printable(rel)))
            return
        if kind == 'file':
            info = files.setdefault(rel, {'rel': rel, 'mode': state.get('mode'), 'users': [], 'rw': [],
                                          'source': 'bind'})
            info['users'].append(container)
            if not mount.read_only:
                info['rw'].append(container)
            return
        problem = _dir_problem(rel)
        if problem:
            code, reason = problem
            app['warnings'].append(_warn(code, f'~/{_printable(rel)}：{reason}', path=_printable(rel)))
            app['skipped'].append({'kind': 'dir', 'path': _printable(rel), 'reason': reason})
            return
        info = dirs.setdefault(rel, {'rel': rel, 'users': [], 'rw': [], 'dests': [], 'db': None,
                                     'read_only': True})
        info['users'].append(container)
        info['dests'].append(mount.dest)
        if not mount.read_only:
            info['rw'].append(container)
            info['read_only'] = False
        if id(mount) in db_data:
            info['db'] = db_data[id(mount)]

    def _config_files(self, app, containers, stats, mounts_info):
        """`config_files` items ({path, mode}) of environment files (0600) and bound files (0644, or 0600 when the file
        is not readable by group/others), in start order; files inside a proposed host directory are left to it."""
        app_id = app['id']
        result, seen = [], set()
        dirs = list(mounts_info['dirs'])

        def add(rel, actual, source):
            if rel in seen:
                return
            seen.add(rel)
            if any(catalog_mod.paths_overlap(d, rel) for d in dirs):
                app['notes'].append(_warn('config-in-dir', f'~/{rel} 位於要備份的主機資料夾中，不另外列為設定檔。',
                                          level='info', path=rel))
                return
            if not config_path_ok(rel, app_id):
                app['skipped'].append({'kind': 'config', 'path': _printable(rel),
                                       'reason': f'不在應用自己的設定目錄 .config/{app_id}/ 或 .local/share/{app_id}/ 之下，'
                                                 '目錄格式無法列入（可改應用 ID、搬移檔案，或改用 Podman secret）。'})
                return
            if source == 'env':
                mode = '0600'
            else:
                mode = '0600' if isinstance(actual, int) and not actual & 0o044 else '0644'
            if isinstance(actual, int) and actual & ~0o644:
                app['warnings'].append(_warn('config-mode', f'~/{rel} 目前的權限是 {actual:04o}，超過 0644；還原後會是 {mode}'
                                                            '（不可執行、群組與其他人不可寫入）。', path=rel))
            result.append({'path': rel, 'mode': mode})

        files = mounts_info['files']
        for container in app['order']:
            for path, rel in container.env_files:
                if rel is None:
                    app['skipped'].append({'kind': 'config', 'path': _printable(path),
                                           'reason': '環境變數檔不在擁有者家目錄中，不列入。'})
                    continue
                state = stats.get(rel)
                kind = state.get('type') if isinstance(state, dict) else None
                if kind == 'file':
                    add(rel, state.get('mode'), 'env')
                elif kind == 'missing':
                    app['warnings'].append(_warn('env-file-missing', f'環境變數檔 ~/{_printable(rel)} 不存在'
                                                                     f'（{container.file}）。', path=_printable(rel)))
                else:
                    app['skipped'].append({'kind': 'config', 'path': _printable(rel),
                                           'reason': '環境變數檔不是一般檔案或無法讀取狀態，未列入。'})
            for mount in container.mounts:
                if mount.kind == 'bind' and mount.rel and mount.rel in files:
                    info = files[mount.rel]
                    add(mount.rel, info['mode'], 'bind')
        return result

    def _secrets(self, app, containers):
        names = []
        for container in app['order']:
            for name in container.secrets:
                if not catalog_mod.SECRET_RE.fullmatch(name):
                    app['skipped'].append({'kind': 'secret', 'name': _printable(name),
                                           'reason': '密鑰名稱含有不支援的字元，無法列入。'})
                    continue
                if name not in names:
                    names.append(name)
        if self.secret_names is not None:
            for name in names:
                if name not in self.secret_names:
                    app['warnings'].append(_warn('secret-missing', f'Podman secret {name} 目前不存在；備份時必須存在。'))
        return names

    def _health(self, app, containers, order):
        urls, hints = [], []
        for container in order:
            command = container.health_cmd
            if not command:
                continue
            found = list(URL_IN_CMD_RE.finditer(command))
            if not found:
                ports = self._loopback_ports(container)
                if ports:
                    hints.append(f'{container.file} 的健康檢查不是 HTTP 請求；已發佈到本機的埠：'
                                 f'{"、".join(f"127.0.0.1:{hp}" for hp, _cp in ports[:4])}。需要時請自行加入健康檢查網址。')
                continue
            for match in found:
                scheme, _host, port, path = match.groups()
                if scheme == 'https':
                    hints.append(f'{container.file} 的健康檢查使用 HTTPS，備份元件只支援 http://127.0.0.1，未列入。')
                    continue
                cport = int(port) if port else 80
                path = (path or '/').rstrip('.,')
                if '?' in path:
                    # A query string may carry a token: the catalog entry is world-readable (0644) and health URLs
                    # appear in job logs, so it is never copied; the administrator adds it by hand if needed (L5).
                    path = path.split('?', 1)[0] or '/'
                    hints.append(f'{container.file} 的健康檢查網址有查詢參數（? 之後的部分，可能含有存取權杖），未列入草稿；'
                                 '應用設定可被所有帳號讀取，確實需要時再自行加入。')
                host_port = self._host_port(container, cport)
                if host_port is None:
                    hints.append(f'{container.file} 的健康檢查連到容器埠 {cport}，但它沒有發佈到 127.0.0.1，未列入。')
                    continue
                url = f'http://127.0.0.1:{host_port}{path}'
                if catalog_mod.URL_RE.fullmatch(url) and url not in urls:
                    urls.append(url)
        app['hints'].extend(hints)
        if not urls and not hints:
            app['hints'].append('沒有找到可用的健康檢查網址；建議加入一個在應用真正可用時才回應 200 的本機網址。')
        timeout = 300 if len(containers) >= 3 or any(self._database(c) for c in containers) else 180
        if urls:
            app['hints'].append('健康檢查的預期狀態碼假設為 200、逾時 '
                                f'{timeout} 秒；請以實際回應與冷啟動時間確認。')
        return [{'type': 'http', 'url': url, 'expect_status': 200, 'timeout_seconds': timeout}
                for url in urls[:MAX_HEALTH]]

    def _publishers(self, container):
        """Containers whose PublishPort lines expose this container's ports (itself, its netns owner, its pod)."""
        chain, seen = [container], {container.file}
        current = container
        while current.netns_target and current.netns_target in self.containers and current.netns_target not in seen:
            current = self.containers[current.netns_target]
            seen.add(current.file)
            chain.append(current)
        return chain

    def _host_port(self, container, cport):
        for publisher in self._publishers(container):
            if publisher.host_network:
                return cport
            for ip, host_port, port, proto in publisher.publish:
                if port == cport and proto == 'tcp' and host_port and loopback_usable(ip):
                    return host_port
            pod = self.aux.get(publisher.pod) if publisher.pod else None
            if pod:
                for value in values(pod.sections, 'Pod', 'PublishPort'):
                    for ip, host_port, port, proto in parse_publish(value):
                        if port == cport and proto == 'tcp' and host_port and loopback_usable(ip):
                            return host_port
        return None

    def _loopback_ports(self, container):
        ports = []
        for publisher in self._publishers(container):
            for ip, host_port, port, proto in publisher.publish:
                if host_port and proto == 'tcp' and loopback_usable(ip):
                    ports.append((host_port, port))
        return ports

    # ------------------------------------------------------------ variants
    def _variants(self, app, order, databases, pg, mounts_info, configs, secrets, health):
        modes = ['cold']
        if pg and all(db.data is not None and self._volume_key(db.data) for db in pg):
            modes += ['instance', 'database']
        variants = []
        for mode in modes:
            entry = self._entry(app, order, databases, pg, mounts_info, configs, secrets, health, mode)
            valid, problem, where = self._validate(entry)
            if not valid and (where or '').startswith('verify') and entry['verify']:
                entry['verify'] = []  # an engine without built-in digests: the draft stays installable
                valid, problem, where = self._validate(entry)
                app['notes'].append(_warn('no-digests', '這個版本的備份元件不支援內建資料核對，草稿未加入核對項目。',
                                          level='info'))
            variants.append({'id': mode, 'label': VARIANT_LABELS[mode] if pg else '', 'entry': entry, 'valid': valid,
                             'problem': problem, 'field': where})
        if any(v['entry']['verify'] for v in variants):
            app['hints'].append('草稿已加入內建資料核對（資料庫資料表的筆數與內容雜湊、資料卷與主機資料夾的檔案清單與雜湊）：'
                                '備份時在寫入服務停止期間計算，還原後在應用啟動前比對；資料量大的項目會延長停機時間，'
                                '可刪除不需要的核對項目。')
        if pg:
            for db in pg:
                if db.data is None:
                    app['warnings'].append(_warn('db-data-unknown', f'找不到 {db.container.file} 的資料位置（資料卷或主機資料夾）；'
                                                                    '請確認 PGDATA 與掛載。', file=db.container.file))
                elif not self._volume_key(db.data):
                    app['notes'].append(_warn('db-dir', f'{db.container.file} 的資料在主機資料夾中，只能使用冷備份'
                                                        '（整個執行個體與單一資料庫模式需要具名資料卷）。', level='info'))
                if db.major is None:
                    app['warnings'].append(_warn('db-tag', f'{db.container.file} 的映像沒有以主版本固定標籤'
                                                           f'（{_printable(db.container.image or "", 80)}）；冷備份還原時主版本'
                                                           '必須相同，建議改用例如 postgres:16-alpine。', file=db.container.file))
                if db.guessed:
                    app['notes'].append(_warn('db-guessed', f'{db.container.file} 的 Quadlet 檔沒有 POSTGRES_USER／'
                                                            'POSTGRES_DB'
                                                            '（可能在環境變數檔中，未讀取）；資料庫與帳號暫定為 '
                                                            f'{db.database}／{db.user}，使用匯出模式前請確認。',
                                            level='info', file=db.container.file))
                if (db.container.stop_timeout or 0) < 30:
                    app['hints'].append(f'使用冷備份時會停止 {db.container.file}：建議 PodmanArgs=--stop-timeout 60，讓 '
                                        'PostgreSQL 有時間正常關閉。')
                writers = set(self._writers(order, databases, mounts_info, 'database', configs))
                stoppers = {unit for key in ('Requires', 'BindsTo', 'PartOf', 'Requisite', 'Wants')
                            for unit in db.container.deps.get(key, set())}
                bad = sorted(stoppers & {c.unit for c in order if c.unit in writers})
                if bad:
                    app['warnings'].append(_warn('db-depends-on-writer', f'{db.container.file} 相依寫入服務 {"、".join(bad)}；'
                                                                         '匯出模式（整個執行個體、單一資料庫）需要資料庫在備份期間'
                                                                         '保持執行，不應相依寫入服務。', file=db.container.file))
        for db in databases.values():
            if db.kind == 'other' and image_major(db.container.image, 1, 999) is None:
                app['warnings'].append(_warn('db-tag', f'{db.container.file} 的映像沒有以主版本固定標籤'
                                                       f'（{_printable(db.container.image or "", 80)}）；冷備份還原時主版本'
                                                       '必須相同，建議固定主版本。', file=db.container.file))
            if db.kind == 'other':
                kind = repository_name(db.container.image)[0]
                app['notes'].append(_warn('db-other', f'{db.container.file} 看起來是 {kind} '
                                                      '資料庫：只能冷備份（一起停止、資料檔整份備份，還原需相同主版本）。',
                                          level='info', file=db.container.file))
            elif db.kind == 'cache' and any(info['users'] and db.container in info['rw']
                                            for info in mounts_info['volumes'].values()):
                app['notes'].append(_warn('cache', f'{db.container.file} 是 Redis 類快取／佇列，資料卷會在停止後備份'
                                                   '（AOF／RDB 已寫入磁碟）。', level='info', file=db.container.file))
        return variants

    def _writers(self, order, databases, mounts_info, mode, configs=()):
        logical = mode in ('instance', 'database')
        writers = set()
        listed = {item['path'] for item in configs}
        for rel, info in mounts_info['files'].items():
            if rel in listed:
                writers |= {c.unit for c in info['rw']}  # a config file bound read-write can be written
        db_units = {db.container.unit for db in databases.values() if db.kind == 'postgres'}
        for info in mounts_info['volumes'].values():
            if info.get('runtime'):
                continue
            if info['db'] is not None and logical:
                continue
            writers |= {c.unit for c in info['rw']}
        for info in mounts_info['dirs'].values():
            writers |= {c.unit for c in info['rw']}
        for db in databases.values():
            if db.kind in ('postgres', 'other') and not (logical and db.kind == 'postgres'):
                writers.add(db.container.unit)
        # Clients of a database write into it: stopped too, so the export matches the volumes and files.
        databases_units = {db.container.unit for db in databases.values() if db.kind in ('postgres', 'other')}
        for container in order:
            if container.unit in databases_units:
                continue
            used = {unit for key in DB_CLIENT_DEPS for unit in container.deps.get(key, set())}
            if used & databases_units:
                writers.add(container.unit)
        if logical:
            writers -= db_units
        changed = True
        while changed:
            changed = False
            for container in order:
                if container.unit in writers or (logical and container.unit in db_units):
                    continue
                stops = {unit for key in STOP_DEPS for unit in container.deps.get(key, set())}
                netns = self.containers.get(container.netns_target) if container.netns_target else None
                if stops & writers or (netns is not None and netns.unit in writers):
                    writers.add(container.unit)
                    changed = True
        return [c.unit for c in order if c.unit in writers]

    def _entry(self, app, order, databases, pg, mounts_info, configs, secrets, health, mode):
        app_id = app['id']
        logical = mode in ('instance', 'database')
        files = sorted(a.file for a in app['aux'] if a.kind == 'network')
        files += sorted(a.file for a in app['aux'] if a.kind == 'pod')
        files += sorted(a.file for a in app['aux'] if a.kind == 'volume')
        files += [c.file for c in order]
        postgres = []
        if logical:
            for index, db in enumerate(pg):
                item = {'id': 'main' if index == 0 else f'db{index + 1}', 'container': db.container.name,
                        'unit': db.container.unit, 'database': db.database, 'user': db.user,
                        'data_volume': self._volume_key(db.data)[0]}
                if mode == 'instance':
                    # Every database of the instance and its roles; the engine connects to `postgres` itself.
                    del item['database']
                    item['scope'] = 'instance'
                postgres.append(item)
        volumes = []
        for name, info in mounts_info['volumes'].items():
            if info.get('runtime'):
                continue
            if info['db'] is not None and logical:
                continue
            volumes.append({'name': name, 'label': self._label(info)})
        data_dirs = [{'path': rel, 'label': self._label(info)} for rel, info in mounts_info['dirs'].items()]
        counts = []
        if len(order) > 1:
            counts.append(f'{len(order)} 個服務')
        for db in pg:
            mode_text = {'cold': '冷備份', 'instance': '整個執行個體', 'database': '單一資料庫'}[mode]
            counts.append(f'PostgreSQL{f" {db.major}" if db.major else ""}（{mode_text}）')
        if volumes:
            counts.append(f'{len(volumes)} 個資料卷')
        if data_dirs:
            counts.append(f'{len(data_dirs)} 個主機資料夾')
        if configs:
            counts.append(f'{len(configs)} 個設定檔')
        if secrets:
            counts.append(f'{len(secrets)} 個密鑰')
        description = '自動產生的草稿：' + ('、'.join(counts) if counts else '沒有找到需要備份的資料') + '。請審查後再安裝。'
        entry = {
            'schema': catalog_mod.SCHEMA, 'id': app_id, 'name': app_id, 'description': description[:500],
            'owner': self.ctx.owner, 'adapter': 'quadlet-postgres',
            'quadlet': {'files': files},
            'units': [c.unit for c in order],
            'writer_units': self._writers(order, databases, mounts_info, mode, configs),
            'postgres': postgres,
            'volumes': volumes,
        }
        if data_dirs:
            entry['data_dirs'] = data_dirs
        writers = entry['writer_units']
        entry.update({'secrets': [{'name': name} for name in secrets], 'config_files': list(configs),
                      'health': [dict(item) for item in health],
                      'verify': self._digest_checks(pg, mode, mounts_info, volumes, data_dirs, writers)})
        return entry

    def _digest_checks(self, pg, mode, mounts_info, volumes, data_dirs, writers):
        """Built-in data verification (no app API needed): one postgres-digest per database (cold: by container,
        export modes: by postgres id) and one files-digest per backed-up volume and host directory, except the
        files of a PostgreSQL data directory (the table digest covers them)."""
        items, used = [], set()

        def ident(base):
            base = re.sub(r'[^a-z0-9_-]+', '-', base.lower()).strip('-_')[:32] or 'check'
            candidate, n = base, 2
            while candidate in used:
                candidate = f'{base[:28]}-{n}'
                n += 1
            used.add(candidate)
            return candidate

        logical = mode in ('instance', 'database')
        for index, db in enumerate(pg):
            pg_id = 'main' if index == 0 else f'db{index + 1}'
            if logical:
                items.append({'id': ident(f'db-{pg_id}'), 'type': 'postgres-digest', 'postgres': pg_id,
                              'label': 'PostgreSQL 資料表內容'})
            elif db.container.unit in writers:
                items.append({'id': ident(f'db-{pg_id}'), 'type': 'postgres-digest', 'container': db.container.name,
                              'unit': db.container.unit, 'user': db.user, 'label': 'PostgreSQL 資料表內容'})
        pg_volumes = {name for name, info in mounts_info['volumes'].items()
                      if info['db'] is not None and info['db'].kind == 'postgres'}
        pg_dirs = {rel for rel, info in mounts_info['dirs'].items()
                   if info['db'] is not None and info['db'].kind == 'postgres'}
        for volume in volumes:
            if volume['name'] not in pg_volumes:
                items.append({'id': ident(f'vol-{volume["name"]}'), 'type': 'files-digest', 'volume': volume['name'],
                              'label': _printable(f'資料卷 {volume["name"]}', 80)})
        for item in data_dirs:
            if item['path'] not in pg_dirs:
                items.append({'id': ident(f'dir-{item["path"].rsplit("/", 1)[-1]}'), 'type': 'files-digest',
                              'data_dir': item['path'], 'label': _printable(f'主機資料夾 ~/{item["path"]}', 80)})
        return items[:MAX_VERIFY]

    @staticmethod
    def _label(info):
        db = info.get('db')
        if db is not None and db.kind == 'postgres':
            return 'PostgreSQL 資料（冷備份）'
        users = info.get('users') or []
        for user in users:
            name, _tag = repository_name(user.image or '')
            if name in CACHE_NAMES:
                return f'{name.capitalize()} 資料'
        if users:
            dest = (info.get('dests') or [''])[0]
            text = f'{users[0].name}：{dest}' if dest else users[0].name
            return _printable(text, 80)
        return ''

    def _validate(self, entry):
        if self.paths is None:
            return True, None, None
        try:
            catalog_mod.validate_entry(entry, paths=self.paths, user_lookup=self.user_lookup)
        except BackupError as error:
            return False, error.message, error.details.get('field')
        return True, None, None

    def _selected_variant(self, app, variants):
        installed = next((entry for entry in self.installed if entry.id == app['id']), None)
        ids = [v['id'] for v in variants]
        if installed is not None and installed.postgres:
            scoped = any((p.get('scope') if isinstance(p, dict) else None) == 'instance' for p in installed.postgres)
            wanted = 'instance' if scoped else 'database'
            if wanted in ids:
                app['notes'].append(_warn('installed-mode', '已安裝的應用設定以匯出方式備份資料庫，草稿沿用相同方式；'
                                                            '改用冷備份會讓之前的備份無法以新設定還原。', level='info'))
                return wanted
        return 'cold'

    def _installed_view(self, app, variants, selected):
        """The installed entry of this app id (None when there is none). Every variant keeps the installed entry's
        human choices (`carry_over`), so the diff shows what the Quadlet files changed, not wording."""
        installed = next((entry for entry in self.installed if entry.id == app['id']), None)
        if installed is None:
            return None
        current = json.loads(json.dumps(installed.raw))
        for variant in variants:
            variant['entry'] = carry_over(current, variant['entry'])
            valid, problem, where = self._validate(variant['entry'])
            variant.update(valid=valid, problem=problem, field=where)
        chosen = next(v for v in variants if v['id'] == selected)
        changes = diff_entries(current, chosen['entry'])
        return {'id': installed.id, 'sha256': installed.sha256, 'entry': current, 'changes': changes,
                'drift': drift_notes(current, chosen['entry']), 'same': not changes}


def config_path_ok(rel, app_id):
    """The catalog's config file rule (CONTRACT section 4): inside `.config/<id>/` or `.local/share/<id>/`."""
    if rel.startswith('/') or not rel.startswith(tuple(f'{root}{app_id}/' for root in catalog_mod.CONFIG_ROOTS)):
        return False
    if any(segment in ('', '.', '..') or not catalog_mod.SEGMENT_RE.fullmatch(segment) for segment in rel.split('/')):
        return False
    return (not rel.startswith(catalog_mod.FORBIDDEN_CONFIG_PREFIXES) and not catalog_mod.forbidden_config_tree(rel)
            and len(rel) <= 1024)


def _runtime_dest(dest):
    dest = posixpath.normpath(dest or '/')
    return any(dest == root or dest.startswith(root + '/') for root in RUNTIME_DESTS)


def _dir_problem(rel):
    """(code, zh-TW reason) when a bind-mounted directory cannot or should not be proposed, else None."""
    lower = rel.lower()
    segments = rel.split('/')
    for segment in segments:
        if segment in ('', '.', '..') or not catalog_mod.SEGMENT_RE.fullmatch(segment):
            return 'bind-path-unsupported', '路徑含有不支援的字元（只能用 A-Z a-z 0-9 . _ @ + -），無法列入主機資料夾。'
    if '.woowbk-' in lower:
        return 'bind-path-unsupported', '路徑含有保留給還原暫存資料夾的「.woowbk-」，無法列入。'
    if len(segments[-1]) > catalog_mod.MAX_DATA_DIR_NAME:
        return 'bind-path-unsupported', '資料夾名稱過長，無法列入。'
    for forbidden in catalog_mod.FORBIDDEN_DATA_DIRS:
        if catalog_mod.paths_overlap(lower, forbidden):
            return 'bind-forbidden', (f'與 ~/{forbidden} 重疊（登入金鑰、服務定義、Podman 或使用者環境），'
                                      '規則上禁止列為主機資料夾，未列入。')
    if lower in SENSITIVE_EXACT or segments[0].lower() in SENSITIVE_TOP:
        return 'bind-sensitive', '這是個人或整個設定資料夾，可能含有與應用無關的私人資料或金鑰，預設不列入；確認備份範圍後可手動加入。'
    return None


# ---------------------------------------------------------------- comparison with the installed entry

def carry_over(installed, entry):
    """The draft with the installed entry's human choices kept: name, description, template_dir, labels of the same
    volumes and directories, health checks and data verification. Structural fields come from the Quadlet files."""
    result = json.loads(json.dumps(entry))
    for key in ('name', 'description'):
        if isinstance(installed.get(key), str):
            result[key] = installed[key]
    quadlet = installed.get('quadlet') if isinstance(installed.get('quadlet'), dict) else {}
    if 'template_dir' in quadlet:
        result['quadlet']['template_dir'] = quadlet['template_dir']
    for key, ident in (('volumes', 'name'), ('data_dirs', 'path')):
        labels = {item.get(ident): item.get('label') for item in installed.get(key) or [] if isinstance(item, dict)}
        for item in result.get(key) or []:
            if isinstance(labels.get(item[ident]), str):
                item['label'] = labels[item[ident]]
    if isinstance(installed.get('health'), list):
        result['health'] = json.loads(json.dumps(installed['health']))
    if isinstance(installed.get('verify'), list):
        # The installed checks stay; built-in digests of targets they do not cover yet are proposed after them.
        kept = json.loads(json.dumps(installed['verify']))
        targets = {digest_target(item) for item in kept if isinstance(item, dict)} - {None}
        ids = {item.get('id') for item in kept if isinstance(item, dict)}
        for item in result.get('verify') or []:
            if digest_target(item) not in targets and item['id'] not in ids and len(kept) < MAX_VERIFY:
                kept.append(item)
        result['verify'] = kept
    # Lists follow the installed order (new items last), so the diff only shows real changes. The start order is
    # only taken over when the draft adds no unit: a new unit may have to start before existing ones.
    for key, ident in (('volumes', 'name'), ('data_dirs', 'path'), ('secrets', 'name'), ('config_files', 'path'),
                       ('health', 'url')):
        if isinstance(result.get(key), list) and isinstance(installed.get(key), list):
            result[key] = _follow(installed[key], result[key], ident)
    if isinstance(quadlet.get('files'), list):
        result['quadlet']['files'] = _follow(quadlet['files'], result['quadlet']['files'])
    old_units = installed.get('units') if isinstance(installed.get('units'), list) else []
    if set(result['units']) <= set(old_units):
        result['units'] = _follow(old_units, result['units'])
    result['writer_units'] = [unit for unit in result['units'] if unit in set(result['writer_units'])]
    ordered = {}
    for key in list(installed) + [k for k in result if k not in installed]:
        if key in result and (key in installed or result[key] != []):  # an empty list the entry left out stays out
            ordered[key] = result[key]
    return ordered


def _follow(old_items, new_items, ident=None):
    """`new_items` ordered like `old_items` where both have them, the others after them in their own order."""
    def key(item):
        return json.dumps(item.get(ident) if ident and isinstance(item, dict) else item, sort_keys=True)
    position = {key(item): index for index, item in enumerate(old_items)}
    known = sorted((item for item in new_items if key(item) in position), key=lambda item: position[key(item)])
    return known + [item for item in new_items if key(item) not in position]


def digest_target(spec):
    """What a digest check reads (`volume:<name>`, `dir:<path>`, `postgres:<id>`, `container:<name>`), else None
    (the catalog's own rule: two checks of one target are refused)."""
    if not isinstance(spec, dict):
        return None
    if spec.get('type') == 'files-digest':
        return f'volume:{spec["volume"]}' if spec.get('volume') else f'dir:{spec.get("data_dir")}'
    if spec.get('type') == 'postgres-digest':
        return f'postgres:{spec["postgres"]}' if spec.get('postgres') else f'container:{spec.get("container")}'
    return None


def drift_notes(installed, draft):
    """zh-TW notes on what the Quadlet files have and the installed entry does not (and the other way round)."""
    notes = []

    def names(entry, key, ident):
        return [item.get(ident) for item in entry.get(key) or [] if isinstance(item, dict)]

    pairs = (('volumes', 'name', '資料卷'), ('data_dirs', 'path', '主機資料夾'), ('secrets', 'name', '密鑰'),
             ('config_files', 'path', '設定檔'))
    for key, ident, label in pairs:
        have, want = names(installed, key, ident), names(draft, key, ident)
        for item in want:
            if item not in have:
                notes.append(f'Quadlet 使用{label} {item}，但已安裝的設定沒有列入：它不會被備份。')
        for item in have:
            if item not in want:
                notes.append(f'已安裝的設定列有{label} {item}，但目前的 Quadlet 檔沒有使用它。')
    for key, label in (('units', '服務'), ('writer_units', '寫入服務')):
        have, want = installed.get(key) or [], draft.get(key) or []
        for unit in want:
            if unit not in have:
                notes.append(f'{label} {unit} 不在已安裝的設定中。')
        for unit in have:
            if unit not in want:
                notes.append(f'已安裝的設定列有{label} {unit}，草稿沒有。')
    have = set((installed.get('quadlet') or {}).get('files') or [])
    want = set((draft.get('quadlet') or {}).get('files') or [])
    for name in sorted(want - have):
        notes.append(f'Quadlet 檔 {name} 不在已安裝的設定中。')
    for name in sorted(have - want):
        notes.append(f'已安裝的設定列有 Quadlet 檔 {name}，但這個應用的分組中沒有它。')
    return notes[:50]


# ---------------------------------------------------------------- entry points

def list_owners(*, catalog=None, linger_dir=LINGER_DIR, user_lookup=None):
    """Accounts that can own apps: lingering users and owners of loaded catalog entries (never root)."""
    lookup = user_lookup or pwd.getpwnam
    lingering = set()
    try:
        for name in os.listdir(linger_dir):
            if catalog_mod.OWNER_RE.fullmatch(name) and name != 'root':
                lingering.add(name)
    except OSError:
        pass
    apps = {}
    for app in (catalog or {}).values():
        apps.setdefault(app.owner, []).append(app.id)
    rows = []
    for name in sorted(lingering | set(apps)):
        try:
            account = lookup(name)
        except KeyError:
            continue
        if account.pw_uid == 0:
            continue
        rows.append({'name': name, 'uid': int(account.pw_uid), 'linger': name in lingering,
                     'catalog_apps': sorted(apps.get(name, []))})
    return rows


def suggest(owner, *, paths, catalog=None, runner=None, user_lookup=None, linger_dir=LINGER_DIR):
    """`catalog-suggest`: drafts for the Quadlet apps of `owner` (None: only the list of owners)."""
    owners = list_owners(catalog=catalog, linger_dir=linger_dir, user_lookup=user_lookup)
    if owner is None:
        return {'owners': owners}
    runner = runner or podman.OwnerRunner(owner, user_lookup=user_lookup)
    scan = scan_quadlet_dir(runner)
    result = {'owner': owner, 'uid': int(runner.uid), 'quadlet_dir': QUADLET_DIR, 'state': scan['state'],
              'owners': owners, 'apps': [], 'unassigned': [], 'unsupported': [], 'warnings': []}
    if scan['state'] != 'ok':
        message = {'missing': f'帳號 {owner} 沒有 ~/{QUADLET_DIR} 資料夾（沒有 Quadlet 應用）。',
                   'blocked': f'無法開啟 ~/{QUADLET_DIR}（不是資料夾、是符號連結或沒有權限）。'}[scan['state']]
        result['warnings'].append(_warn(f'dir-{scan["state"]}', message))
        return result
    if scan['more']:
        result['warnings'].append(_warn('too-many-files', f'Quadlet 資料夾項目過多，有 {scan["more"]} 個沒有分析。'))
    has_containers = any(row['name'].endswith('.container') for row in scan['entries'])
    secrets = _owner_names(runner, 'secret', 'ls', '--format', '{{.Name}}') if has_containers else None
    volumes = _owner_names(runner, 'volume', 'ls', '--format', '{{.Name}}') if has_containers else None
    if has_containers and (secrets is None or volumes is None):
        result['warnings'].append(_warn('podman-list', '無法列出擁有者的 Podman 密鑰或資料卷，已略過「是否存在」的檢查。',
                                        level='info'))
    installed = [app for app in (catalog or {}).values() if app.owner == owner]
    other_ids = {app.id for app in (catalog or {}).values() if app.owner != owner}
    analyzer = Analyzer(owner, runner.uid, runner.home, scan['entries'], stat=runner.stat_files, secrets=secrets,
                        volumes=volumes, unit_states=lambda units: _unit_states(runner, units), installed=installed,
                        other_ids=other_ids, paths=paths, user_lookup=user_lookup)
    analysis = analyzer.analyze()
    result.update(apps=analysis['apps'], unassigned=analysis['unassigned'], unsupported=analysis['unsupported'])
    result['warnings'].extend(analysis['warnings'])
    for problem in getattr(catalog, 'problems', []) or []:
        if problem.get('id') and any(app['id'] == problem['id'] for app in result['apps']):
            result['warnings'].append(_warn('installed-problem', f'已安裝的應用設定 {problem["file"]} 沒有載入：'
                                                                 f'{_printable(problem["message"], 300)}'))
    return result
