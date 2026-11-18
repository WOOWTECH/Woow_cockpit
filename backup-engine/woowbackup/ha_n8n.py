"""Home Assistant import, n8n part: the WOOWTECH add-on `woow-n8n` -> this device's app `n8n` (CONTRACT section 9
"Home Assistant import"; design notes of branch feat/ha-import, section 4). Owner: E2.

The add-on runs n8n on SQLite: `config/.n8n/{database.sqlite, -wal, -shm, config (JSON encryptionKey), nodes/,
storage/}`; caches, Redis data, runner files, logs and `data/` are not moved. The target is n8n in queue mode on
PostgreSQL 16 with the same n8n version (the import's migration check requires it); its key lives only in the volume
`n8n_n8n_data` (`config`).

check: the SQLite files are copied into the job's root staging and read with the standard library (`PRAGMA
trusted_schema=OFF`, explicit columns of tables only): the owner account (email and password set, else nothing can be
moved), counts, the workflows that may need changes here (shell commands, SSH, local files, Home Assistant, HA-internal
addresses, Redis/MQTT, webhooks), and community packages (native `.node` files must be x86-64 for musl, like the n8n
image); the version must equal `n8n --version` of the live image.

convert: a throwaway volume holds the SQLite copy and HA's key; a throwaway n8n (live image, network none) runs
`export:entities --includeExecutionHistoryDataTables=true`; a throwaway PostgreSQL (the live n8n-postgres image, user
and database n8n, a random password) and a throwaway n8n on an internal network run `import:entities
--truncateTables=true` (it exits 0 even when it skipped, so every table's rows are counted on both sides); test mode
unpublishes every workflow; `pg_dump -Fc` becomes the archive's database `main`. `n8n_n8n_data` is built from scratch:
`config` with HA's key (0600, the container's node uid/gid), HA's `nodes/` and `storage/`; `n8n_valkey_data` is empty
(queued jobs of HA never run here).
"""
import io
import json
import os
import re
import secrets
import sqlite3
import struct
import tarfile
import time

from . import habackup, tempctr, util
from .errors import BackupError
from .ha_odoo import FileTar, _info, _int, check_volume_tar, quadlet_mounts

SLUG = 'woow-n8n'
APP_ID = 'n8n'
N8N_DIR = 'config/.n8n'
SQLITE_FILES = ('database.sqlite', 'database.sqlite-wal', 'database.sqlite-shm')
KEY_FILE = 'config'
MOVED_DIRS = ('nodes', 'storage')
MAX_KEY_FILE = 64 * 1024
MAX_PACKAGE_JSON = 1024 * 1024
MAX_NODES_JSON = 16 * 1024 * 1024
MAX_WORKFLOWS = 5000
MAX_NATIVE = 64 * 1024 * 1024
TABLE_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,62}\Z')
VERSION_RE = re.compile(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:[-+][A-Za-z0-9.-]{1,40})?\Z')
PACKAGE_RE = re.compile(r'(?:@[a-z0-9][a-z0-9._-]{0,100}/)?[a-z0-9][a-z0-9._-]{0,213}\Z')
KEY_RE = re.compile(r'[\x21-\x7e]{8,1024}\Z')
NO_OWNER = 'HA 的 n8n 還沒建立管理者帳號，沒有可搬的資料。'
# Tables a fresh PostgreSQL schema fills during its migrations or that are not entities of the export; their rows are
# not compared (the rest must match exactly: import:entities exits 0 even when it skipped a table).
NOT_COMPARED = frozenset({'migrations', 'sqlite_sequence', 'sqlite_stat1', 'sqlite_stat4'})
HA_HOST_RE = re.compile(r'(?:supervisor|homeassistant|homeassistant\.local|hassio|core-[a-z0-9_-]+|a0d7b954-[a-z0-9_-]+'
                        r'|localhost|127\.0\.0\.1|172\.30\.3[23]\.[0-9]{1,3})\Z', re.I)
URL_HOST_RE = re.compile(r'(?i)\b(?:https?|wss?|mqtts?|redis)://(?:[^@/\s"\'?#]*@)?(\[[^\]]+\]|[^/:\s"\'?#{}]+)')
FILE_NODES = {'n8n-nodes-base.readWriteFile', 'n8n-nodes-base.readBinaryFile', 'n8n-nodes-base.readBinaryFiles',
              'n8n-nodes-base.writeBinaryFile', 'n8n-nodes-base.localFileTrigger'}
EXEC_NODES = {'n8n-nodes-base.executeCommand'}
SSH_NODES = {'n8n-nodes-base.ssh'}
HA_NODES = {'n8n-nodes-base.homeAssistant', 'n8n-nodes-base.homeAssistantTrigger'}
QUEUE_NODES = {'n8n-nodes-base.redis', 'n8n-nodes-base.redisTrigger', 'n8n-nodes-base.mqtt',
               'n8n-nodes-base.mqttTrigger'}
URL_NODES = {'n8n-nodes-base.webhook', 'n8n-nodes-base.formTrigger', 'n8n-nodes-base.form',
             '@n8n/n8n-nodes-langchain.chatTrigger', '@n8n/n8n-nodes-langchain.mcpTrigger'}
PATH_KEYS = ('fileSelector', 'filePath', 'fileName', 'path', 'filePathOrName')


# ====================================================================== the add-on member

class Source:
    """What a pass over the n8n add-on's inner tar staged and learned: the SQLite copy, the key (never logged), the
    community packages and native files."""

    def __init__(self):
        self.addon = None
        self.sqlite = {}          # file name -> staged path
        self.key = None           # HA's encryptionKey (masked in every log of this process)
        self.packages = []        # [{name, version}]
        self.native_bad = []      # package names with native code that does not fit here
        self.native = 0
        self.files_tar = None     # staged nodes/ + storage/ (conversion only)
        self.files_bytes = 0


def _key_from(data):
    try:
        doc = util.loads_strict(data, max_bytes=MAX_KEY_FILE)
    except ValueError:
        return None
    key = doc.get('encryptionKey') if isinstance(doc, dict) else None
    return key if isinstance(key, str) and KEY_RE.fullmatch(key) else None


def packages_of(data):
    """[{name, version}] of nodes/package.json `dependencies` (community packages)."""
    try:
        doc = util.loads_strict(data, max_bytes=MAX_PACKAGE_JSON)
    except ValueError:
        return []
    deps = doc.get('dependencies') if isinstance(doc, dict) else None
    if not isinstance(deps, dict):
        return []
    return [{'name': name, 'version': str(version)[:64]} for name, version in sorted(deps.items())[:200]
            if isinstance(name, str) and PACKAGE_RE.fullmatch(name)]


def elf_fits(data):
    """True when an ELF shared object is x86-64 and does not need glibc (the n8n image is musl); False for another
    machine or glibc; None when it is not ELF."""
    if len(data) < 64 or data[:4] != b'\x7fELF':
        return None
    if data[4] != 2 or data[5] != 1:   # 64-bit little endian
        return False
    machine = struct.unpack_from('<H', data, 18)[0]
    if machine != 0x3E:
        return False
    return not _needs_glibc(data)


def _needs_glibc(data):
    """DT_NEEDED names of a 64-bit little-endian ELF include libc.so.6 (glibc). Bounded, never raises."""
    try:
        phoff, = struct.unpack_from('<Q', data, 32)
        phentsize, phnum = struct.unpack_from('<HH', data, 54)
        dynamic = loads = None
        segments = []
        for i in range(min(phnum, 64)):
            off = phoff + i * phentsize
            p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from('<IIQQQQ', data, off)
            if p_type == 2:
                dynamic = (p_offset, p_filesz)
            elif p_type == 1:
                segments.append((p_vaddr, p_offset, p_filesz))
        if dynamic is None:
            return False
        strtab, needed = None, []
        for i in range(0, min(dynamic[1], 64 * 1024), 16):
            tag, value = struct.unpack_from('<qQ', data, dynamic[0] + i)
            if tag == 0:
                break
            if tag == 5:
                strtab = value
            elif tag == 1:
                needed.append(value)
        if strtab is None:
            return False
        base = next((off + strtab - vaddr for vaddr, off, size in segments if vaddr <= strtab < vaddr + size), None)
        if base is None:
            return False
        for value in needed[:64]:
            end = data.find(b'\0', base + value, base + value + 256)
            if end > 0 and data[base + value:end] == b'libc.so.6':
                return True
        return False
    except struct.error:
        return False


def scan_member(stream, report, staging, *, files=None, guard=None, checkpoint=None):
    """One strict pass over the add-on's inner tar: the SQLite files and the key into `staging` (root 0600),
    package.json and native files of nodes/ checked; with `files` (a FileTar) nodes/** and storage/** are staged as
    `nodes/…` and `storage/…` (original modes). Returns a Source."""
    select = habackup.Select(include=tuple(f'{N8N_DIR}/{name}' for name in SQLITE_FILES + (KEY_FILE,) + MOVED_DIRS),
                             symlinks=(f'{N8N_DIR}/nodes',), hardlinks=False)
    src = Source()
    count = 0
    for entry in habackup.iter_entries(stream, select, report):
        count += 1
        if checkpoint is not None and count % 256 == 0:
            checkpoint()
        rel = entry.name[len(N8N_DIR) + 1:]
        if rel in SQLITE_FILES:
            if entry.kind != 'file':
                raise BackupError('corrupt-archive', 'HA 備份中 n8n 的資料庫不是一般檔案。', member=entry.name)
            path = staging / rel
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, 'wb') as out:
                entry.copy_to(_Counted(out, guard))
                out.flush()
                os.fsync(out.fileno())
            src.sqlite[rel] = path
            continue
        if rel == KEY_FILE:
            if entry.kind == 'file':
                src.key = _key_from(entry.read_all(MAX_KEY_FILE))
                if src.key is not None:
                    from . import jobs
                    jobs.mask_secret(src.key)
            continue
        top, _, tail = rel.partition('/')
        if top == 'nodes' and tail == 'package.json' and entry.kind == 'file':
            data = entry.read_all(MAX_PACKAGE_JSON)
            src.packages = packages_of(data)
            if files is not None:
                files.add_member(_info(rel, 'file', mode=entry.mode & 0o755 | 0o644, uid=0, gid=0, mtime=entry.mtime,
                                       size=len(data)), io.BytesIO(data))
            continue
        if top == 'nodes' and entry.kind == 'file' and tail.endswith('.node'):
            src.native += 1
            data = entry.read_all(MAX_NATIVE)
            if elf_fits(data) is False:
                package = _package_of(tail)
                if package and package not in src.native_bad:
                    src.native_bad.append(package)
            if files is not None:
                files.add_member(_info(rel, 'file', mode=entry.mode & 0o755 | 0o644, uid=0, gid=0, mtime=entry.mtime,
                                       size=len(data)), io.BytesIO(data))
            continue
        if files is not None:
            if entry.kind == 'file':
                src.files_bytes += entry.size
            if entry.kind == 'symlink':
                files.add_member(_info(rel, 'symlink', mode=0o777, uid=0, gid=0, mtime=entry.mtime,
                                       linkname=entry.linkname))
            else:
                files.add_entry(rel, entry, mode=(entry.mode & 0o755) | (0o755 if entry.kind == 'dir' else 0o644),
                                uid=0, gid=0)
    src.addon = report.addon
    return src


def _package_of(tail):
    parts = tail.split('/')
    if len(parts) > 2 and parts[0] == 'node_modules':
        return '/'.join(parts[1:3]) if parts[1].startswith('@') and len(parts) > 3 else parts[1]
    return None


class _Counted:
    def __init__(self, out, guard):
        self.out, self.guard = out, guard

    def write(self, data):
        if self.guard is not None:
            self.guard.wrote(len(data))
        return self.out.write(data)


# ====================================================================== the SQLite copy

COUNTED = {'workflows': 'workflow_entity', 'credentials': 'credentials_entity', 'executions': 'execution_entity',
           'users': 'user', 'projects': 'project', 'variables': 'variables', 'data_tables': 'data_table'}


def inspect_sqlite(path):
    """{owner_email, owner_ok, counts, workflows [(name, active, nodes json)], tables {name: rows}, migration} of
    the staged SQLite copy. Only tables are read, with explicit columns; views and triggers never run
    (`trusted_schema=OFF`)."""
    try:
        conn = sqlite3.connect(f'file:{path}?mode=rw', uri=True, isolation_level=None)
    except sqlite3.Error:
        raise BackupError('corrupt-archive', 'HA 備份中 n8n 的資料庫無法開啟。') from None
    try:
        conn.execute('PRAGMA trusted_schema=OFF')
        conn.execute('PRAGMA cell_size_check=ON')
        conn.execute('PRAGMA mmap_size=0')
        kinds = dict(conn.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view')").fetchall())
        conn.execute('PRAGMA query_only=ON')

        def table(name):
            return kinds.get(name) == 'table'

        def columns(name):
            return {row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')} if table(name) else set()

        tables = {}
        for name, kind in sorted(kinds.items()):
            if kind == 'table' and TABLE_RE.fullmatch(name):
                tables[name] = conn.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0]
        counts = {key: tables.get(name, 0) for key, name in COUNTED.items()}
        user_cols = columns('user')
        role_col = 'roleSlug' if 'roleSlug' in user_cols else 'role' if 'role' in user_cols else None
        owner_email, owner_ok = None, False
        if role_col and {'email', 'password'} <= user_cols:
            row = conn.execute(f'SELECT email, password FROM "user" WHERE "{role_col}" = ? ORDER BY createdAt LIMIT 1',
                               ('global:owner',)).fetchone()
            if row is not None:
                email = row[0] if isinstance(row[0], str) and 0 < len(row[0]) <= 254 else None
                owner_email = email
                owner_ok = email is not None and isinstance(row[1], str) and len(row[1]) > 0
        workflows = []
        wf_cols = columns('workflow_entity')
        if {'name', 'active', 'nodes'} <= wf_cols:
            archived = 'isArchived' in wf_cols
            sql = ('SELECT name, active, nodes' + (', isArchived' if archived else '') + ' FROM workflow_entity '
                   'ORDER BY name LIMIT ?')
            for row in conn.execute(sql, (MAX_WORKFLOWS,)):
                if archived and row[3]:
                    continue
                name = row[0] if isinstance(row[0], str) else ''
                nodes = row[2] if isinstance(row[2], str) and len(row[2]) <= MAX_NODES_JSON else '[]'
                workflows.append((name[:200], bool(row[1]), nodes))
        active = sum(1 for _n, flag, _nodes in workflows if flag)
        migration = None
        if {'name', 'timestamp'} <= columns('migrations'):
            row = conn.execute('SELECT name FROM migrations ORDER BY timestamp DESC LIMIT 1').fetchone()
            migration = str(row[0])[:200] if row else None
        return {'owner_email': owner_email, 'owner_ok': owner_ok, 'counts': counts, 'workflows_active': active,
                'workflows': workflows, 'tables': tables, 'migration': migration}
    except sqlite3.Error:
        raise BackupError('corrupt-archive', 'HA 備份中 n8n 的資料庫內容無法讀取。') from None
    finally:
        conn.close()


def _strings(value, depth=0):
    if depth > 32:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item, depth + 1)


def workflow_reasons(nodes_json):
    """zh-TW reasons why a workflow may need changes after moving here (sorted, unique, at most 10)."""
    try:
        nodes = json.loads(nodes_json)
    except (ValueError, RecursionError):
        return ['無法讀取工作流程的節點設定。']
    if not isinstance(nodes, list):
        return []
    reasons = []
    for node in nodes[:2000]:
        if not isinstance(node, dict):
            continue
        kind = node.get('type') if isinstance(node.get('type'), str) else ''
        params = node.get('parameters') if isinstance(node.get('parameters'), dict) else {}
        if kind in EXEC_NODES:
            reasons.append('使用「執行命令」節點：這台的系統環境和 HA 不同，請確認命令。')
        if kind in SSH_NODES:
            reasons.append('使用 SSH 節點：請確認連線的主機與金鑰。')
        if kind in FILE_NODES:
            paths = [params[key] for key in PATH_KEYS if isinstance(params.get(key), str) and params[key]]
            where = f'（{paths[0][:80]}）' if paths else ''
            reasons.append(f'讀寫本機檔案{where}：這台的資料夾和 HA 不同。')
        if kind in HA_NODES:
            reasons.append('使用 Home Assistant 節點：搬過來後請確認連到 HA 的網址與權杖。')
        if kind in QUEUE_NODES:
            reasons.append('使用 Redis 或 MQTT 節點：請確認連線位址（HA 內建的服務這台沒有）。')
        if kind in URL_NODES:
            reasons.append('網頁觸發（Webhook／表單）的網址會改成這台的網址，呼叫它的地方要一起更新。')
        for text in _strings(params):
            for match in URL_HOST_RE.finditer(text[:100000]):
                host = match.group(1).strip('[]').lower()
                if HA_HOST_RE.fullmatch(host):
                    reasons.append(f'連到 HA 內部的位址 {host}：這台連不到，請改成實際位址。')
    unique = []
    for reason in reasons:
        if reason not in unique:
            unique.append(reason)
    return unique[:10]


def workflows_to_fix(workflows, limit=200):
    found = []
    for name, active, nodes in workflows:
        reasons = workflow_reasons(nodes)
        if reasons:
            found.append({'name': name, 'active': active, 'reasons': reasons})
        if len(found) >= limit:
            break
    return found


# ====================================================================== the live target

class Target:
    """The n8n app's catalog items the import fills, resolved against the live Quadlet files."""

    def __init__(self, work, app):
        quadlets = work.quadlets(app)
        home = work.runner(app).home
        self.app = app
        if len(app.postgres) != 1 or app.postgres[0].get('scope', 'database') != 'database':
            raise BackupError('incompatible', '這台的 n8n 應用設定不是 HA 匯入支援的樣子（需要一個 PostgreSQL 資料庫）。',
                              app=app.id)
        self.pg = app.postgres[0]
        self.main_file = self.pg_file = self.valkey_file = None
        mounts = {}
        for name, text in quadlets.items():
            if not name.endswith('.container'):
                continue
            body = text.decode('utf-8', 'replace') if isinstance(text, bytes) else str(text)
            for source, target, _o in quadlet_mounts(quadlets, name, home):
                mounts.setdefault(source, []).append((name, target))
            container = [v for k, v in tempctr.parse_unit(body).get('Container', []) if k == 'ContainerName']
            if container and container[-1] == self.pg['container']:
                self.pg_file = name
        declared = [v['name'] for v in app.volumes]
        self.data_volume = next((src for src, users in mounts.items()
                                 if any(t == '/home/node/.n8n' for _n, t in users)), None)
        self.valkey_volume = next((v for v in declared if v != self.data_volume), None)
        self.main_file = next((n for n, t in mounts.get(self.data_volume, []) if t == '/home/node/.n8n'), None)
        if (self.pg_file is None or self.main_file is None or self.data_volume not in declared
                or len(declared) != 2 or self.valkey_volume is None):
            raise BackupError('incompatible', '這台的 n8n 應用設定和 Quadlet 檔不一致，無法匯入。', app=app.id)
        self.n8n_image = tempctr.quadlet_image(quadlets[self.main_file])
        self.pg_image = tempctr.quadlet_image(quadlets[self.pg_file])
        env = tempctr.quadlet_environment(quadlets[self.pg_file], {'POSTGRES_USER', 'POSTGRES_DB', 'PGDATA', 'LANG',
                                                                    'TZ', 'POSTGRES_INITDB_ARGS'})
        self.pg_env = env
        self.pg_target = next((t for _n, t in sum(mounts.values(), []) if t.startswith('/var/lib/postgresql')),
                              '/var/lib/postgresql/data')
        if not self.n8n_image or not self.pg_image:
            raise BackupError('incompatible', '這台 n8n 的 Quadlet 設定缺少映像。', app=app.id)
        if env.get('POSTGRES_USER', self.pg['user']) != self.pg['user'] or self.pg.get('database') is None:
            raise BackupError('incompatible', '這台 n8n 的資料庫設定和應用設定不一致。', app=app.id)


def target_version(tmp, image, role='n8n-version'):
    out = tmp.run(role, image, ['--version'], timeout=300, max_output=64 * 1024).stdout or b''
    lines = [line.strip() for line in out.decode('utf-8', 'replace').splitlines() if line.strip()]
    version = lines[-1] if lines else ''
    if not VERSION_RE.fullmatch(version):
        raise BackupError('job-failed', '無法讀取這台 n8n 的版本。')
    return version


def volume_root(work, app, name):
    """(uid, gid, mode) of a live volume's top directory, as the owner's namespace sees it."""
    runner = work.runner(app)
    mount = (runner.podman('volume', 'inspect', '--format', '{{.Mountpoint}}', name, timeout=60,
                           max_output=64 * 1024).stdout or b'').decode('utf-8', 'replace').strip()
    if not mount.startswith('/') or '\n' in mount or len(mount) > 1024:
        raise BackupError('job-failed', f'無法讀取資料卷 {name} 的位置。')
    out = (runner.podman('unshare', 'stat', '-c', '%u %g %a', '--', mount, timeout=60,
                         max_output=64 * 1024).stdout or b'').decode('ascii', 'replace').split()
    if len(out) != 3 or not out[0].isdigit() or not out[1].isdigit() or not re.fullmatch(r'[0-7]{1,4}', out[2]):
        raise BackupError('job-failed', f'無法讀取資料卷 {name} 的權限。')
    return int(out[0]), int(out[1]), int(out[2], 8)


# ====================================================================== the job steps

def member_pass(work, app, staging, *, files=None):
    member = work.addon_member(SLUG)
    report = habackup.Report()
    with work.open(member) as stream:
        src = scan_member(stream, report, staging, files=files, guard=work.guard, checkpoint=work.checkpoint)
    for note in report.warnings():
        work.log(note)
    return src


def analyse(src, info, version, target):
    blockers, warnings = [], []
    if 'database.sqlite' not in src.sqlite:
        blockers.append('HA 備份裡沒有 n8n 的資料庫。')
    if src.key is None:
        blockers.append('HA 備份裡沒有 n8n 的加密金鑰設定，搬過來的憑證會打不開。')
    if info is not None and not info['owner_ok']:
        blockers.append(NO_OWNER)
    if version != target:
        blockers.append(f'版本不同：HA 的 n8n 是 {version}，這台是 {target}。請先讓兩邊的 n8n 版本一致後再匯入。')
    for package in src.native_bad:
        warnings.append(f'社群節點 {package} 含有與這台不相容的程式，搬過來後需要重新安裝。')
    if src.packages:
        warnings.append(f'HA 的 n8n 裝了 {len(src.packages)} 個社群節點套件，搬過來後請確認它們能正常使用。')
    return blockers, warnings


def check(work, app):
    tmp = work.temp(app)
    items = Target(work, app)
    staging = work.staging / 'n8n-work'
    staging.mkdir(mode=0o700)
    addon = work.addon_info(SLUG)
    src = member_pass(work, app, staging)
    sqlite_bytes = sum(os.path.getsize(p) for p in src.sqlite.values())
    work.phase('check')
    info = inspect_sqlite(src.sqlite['database.sqlite']) if 'database.sqlite' in src.sqlite else None
    version = target_version(tmp, items.n8n_image)
    blockers, warnings = analyse(src, info, addon.version if addon else '', version)
    fix = workflows_to_fix(info['workflows']) if info else []
    counts = info['counts'] if info else {}
    return {'target_version': version, 'blockers': blockers, 'warnings': warnings,
            'sqlite_bytes': sqlite_bytes,
            'n8n': {'owner_email': info['owner_email'] if info else None,
                    'workflows': counts.get('workflows', 0), 'workflows_active': info['workflows_active'] if info else 0,
                    'credentials': counts.get('credentials', 0), 'executions': counts.get('executions', 0),
                    'users': counts.get('users', 0), 'projects': counts.get('projects', 0),
                    'variables': counts.get('variables', 0), 'data_tables': counts.get('data_tables', 0),
                    'community_packages': list(src.packages), 'workflows_to_fix': fix}}


def _source_tar(out, src, password, *, node_ids):
    """The throwaway volume `n8nsrc`: home/.n8n/{database.sqlite*, config} owned by the image's node user, an
    empty writable out/ and the temporary database password (pgpass, readable by both containers)."""
    uid, gid = node_ids
    tar = tarfile.open(fileobj=out, mode='w|', format=tarfile.PAX_FORMAT)
    now = time.time()
    tar.addfile(_info('.', 'dir', mode=0o755, uid=uid, gid=gid, mtime=now))
    for name in ('home', 'home/.n8n', 'out'):
        tar.addfile(_info(name, 'dir', mode=0o700 if name != 'out' else 0o755, uid=uid, gid=gid, mtime=now))
    for name, path in sorted(src.sqlite.items()):
        size = os.path.getsize(path)
        with open(path, 'rb') as handle:
            tar.addfile(_info(f'home/.n8n/{name}', 'file', mode=0o600, uid=uid, gid=gid, mtime=now, size=size), handle)
    key = json.dumps({'encryptionKey': src.key}).encode('utf-8')
    tar.addfile(_info('home/.n8n/config', 'file', mode=0o600, uid=uid, gid=gid, mtime=now, size=len(key)),
                io.BytesIO(key))
    data = password.encode('ascii')
    tar.addfile(_info('pgpass', 'file', mode=0o444, uid=uid, gid=gid, mtime=now, size=len(data)), io.BytesIO(data))
    tar.close()


def _n8n_env(extra):
    env = {'N8N_USER_FOLDER': '/work/home', 'N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS': 'true',
           'N8N_DIAGNOSTICS_ENABLED': 'false', 'N8N_VERSION_NOTIFICATIONS_ENABLED': 'false',
           'N8N_PERSONALIZATION_ENABLED': 'false', 'N8N_LOG_LEVEL': 'warn', 'NODE_ENV': 'production'}
    env.update(extra)
    return env


def count_rows(pg, tables):
    """{table: rows} in the throwaway PostgreSQL for the tables that exist there."""
    present = pg.query_json("SELECT coalesce(json_agg(tablename), '[]'::json) FROM pg_tables "
                            "WHERE schemaname = 'public'", 'n8n')
    present = {name for name in present if isinstance(name, str)} if isinstance(present, list) else set()
    names = [name for name in tables if name in present and TABLE_RE.fullmatch(name)]
    if not names:
        return {}
    parts = ', '.join(f"'{name}', (SELECT count(*) FROM \"{name}\")" for name in names)
    doc = pg.query_json(f'SELECT json_build_object({parts})', 'n8n')
    return {name: _int(doc.get(name)) for name in names} if isinstance(doc, dict) else {}


def convert(work, app, test_mode, out_dir):
    """Build the app's data items in `out_dir`; returns {volumes {name: path}, postgres {id: {...}}, counts,
    workflows_to_fix}."""
    from . import jobs
    from .ha_odoo import Cluster
    adapter = work.adapter(app)
    tmp = work.temp(app)
    items = Target(work, app)
    ids = adapter.owner_ids()
    staging = work.staging / 'n8n-work'
    staging.mkdir(mode=0o700)
    for sub in ('volumes', 'postgres'):
        (out_dir / sub).mkdir(mode=0o700, parents=True, exist_ok=True)
    addon = work.addon_info(SLUG)
    files = FileTar(staging / 'ha-n8n-files.tar', work.guard)
    try:
        src = member_pass(work, app, staging, files=files)
    finally:
        files.close()
    work.phase('convert')
    # Still to be written (review C-01): the copy in the throwaway volume, n8n's export, the new database and its
    # dump -- about three times the SQLite files (already staged).
    work.guard.check(3 * sum(os.path.getsize(p) for p in src.sqlite.values()))
    info = inspect_sqlite(src.sqlite['database.sqlite']) if 'database.sqlite' in src.sqlite else None
    # Closing the copy may have checkpointed its WAL into the main file (and removed -wal/-shm): keep what is left.
    src.sqlite = {name: path for name, path in src.sqlite.items() if os.path.lexists(path)}
    version = target_version(tmp, items.n8n_image)
    blockers, _warnings = analyse(src, info, addon.version if addon else '', version)
    if blockers:
        raise BackupError('incompatible', f'n8n 不能搬過來：{blockers[0]}', app=app.id)
    node_ids = tmp.user_ids('ids-node', items.n8n_image, 'node')
    password = secrets.token_urlsafe(24)
    jobs.mask_secret(password)
    tmp.volume('n8nsrc')
    tmp.volume_import('n8nsrc', lambda out: _source_tar(out, src, password, node_ids=node_ids))
    for path in src.sqlite.values():
        os.unlink(path)
    work.log('從 HA 的 n8n 資料庫匯出全部資料（含執行紀錄）')
    tmp.run('n8n-export', items.n8n_image, ['export:entities', '--outputDir=/work/out',
                                            '--includeExecutionHistoryDataTables=true'],
            volumes=[(tmp.name('n8nsrc'), '/work', None)],
            env=_n8n_env({'DB_TYPE': 'sqlite', 'DB_SQLITE_DATABASE': '/work/home/.n8n/database.sqlite'}),
            timeout=3600, max_output=4 * 1024 * 1024)
    network = tmp.network('n8n-net')
    tmp.volume('n8n-pgdata')
    pg_env = {key: value for key, value in items.pg_env.items() if key in ('POSTGRES_INITDB_ARGS', 'LANG', 'TZ')}
    pg_env.update({'POSTGRES_USER': items.pg['user'], 'POSTGRES_DB': items.pg['database'],
                   'POSTGRES_PASSWORD_FILE': '/work/pgpass'})
    tmp.run('n8n-pg', items.pg_image, [], detach=True, network=network,
            volumes=[(tmp.name('n8nsrc'), '/work', 'ro'), (tmp.name('n8n-pgdata'), items.pg_target, None)],
            env=pg_env)
    pg = Cluster(tmp, 'n8n-pg', superuser=items.pg['user'], log=work.log)
    pg.wait_ready(tcp=True, checkpoint=work.checkpoint)
    db_env = _n8n_env({'DB_TYPE': 'postgresdb', 'DB_POSTGRESDB_HOST': tmp.name('n8n-pg'), 'DB_POSTGRESDB_PORT': '5432',
                       'DB_POSTGRESDB_DATABASE': items.pg['database'], 'DB_POSTGRESDB_USER': items.pg['user'],
                       'DB_POSTGRESDB_PASSWORD_FILE': '/work/pgpass'})
    work.log('把資料匯入新的 PostgreSQL 資料庫')
    tmp.run('n8n-import', items.n8n_image, ['import:entities', '--inputDir=/work/out', '--truncateTables=true'],
            network=network, volumes=[(tmp.name('n8nsrc'), '/work', None)], env=db_env, timeout=3600,
            max_output=4 * 1024 * 1024)
    compared = {name: rows for name, rows in info['tables'].items() if rows and name not in NOT_COMPARED}
    found = count_rows(pg, compared)
    missing = [name for name in compared if name not in found]
    differ = [f'{name}（HA {rows}，匯入後 {found[name]}）' for name, rows in compared.items()
              if name in found and found[name] != rows]
    if missing or differ:
        raise BackupError('job-failed', 'n8n 匯入後的資料筆數和 HA 不同，已停止：'
                                        f'{"、".join((missing + differ)[:10])}。')
    work.log(f'n8n 資料匯入完成：{len(compared)} 個資料表的筆數都和 HA 相同')
    if test_mode:
        work.log('測試匯入：停用全部工作流程')
        tmp.run('n8n-unpublish', items.n8n_image, ['unpublish:workflow', '--all'], network=network,
                volumes=[(tmp.name('n8nsrc'), '/work', None)], env=db_env, timeout=1800, max_output=4 * 1024 * 1024)
        active = pg.query_json("SELECT to_json(count(*)) FROM workflow_entity WHERE active", items.pg['database'])
        if _int(active):
            raise BackupError('job-failed', '測試匯入沒有停用全部 n8n 工作流程。')
    number = pg.query_json('SELECT to_json(current_setting(\'server_version_num\'))', items.pg['database'])
    text = pg.query_json('SELECT to_json(current_setting(\'server_version\'))', items.pg['database'])
    try:
        major = int(str(number)) // 10000
    except ValueError:
        raise BackupError('job-failed', '無法判斷暫用資料庫的版本。') from None
    dump = out_dir / 'postgres' / f'{items.pg["id"]}.dump'
    with open(dump, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        tmp.exec('n8n-pg', ['pg_dump', '-w', '-U', items.pg['user'], '-d', items.pg['database'], '-Fc'],
                 stdout=handle, timeout=3 * 3600, max_output=work.guard.budget())
        handle.flush()
        os.fsync(handle.fileno())
    if os.path.getsize(dump) == 0:
        raise BackupError('job-failed', 'n8n 資料庫匯出結果為空。')
    with open(dump, 'rb') as handle:  # a full read (like the adapter's): every data block decompresses
        tmp.exec('n8n-pg', ['pg_restore', '-f', '/dev/null'], input=handle, timeout=3 * 3600, max_output=64 * 1024)
    for role in ('n8n-pg',):
        tmp.remove(role)
    for role in ('n8n-pgdata', 'n8nsrc'):
        tmp.remove_volume(role)
    # n8n_n8n_data from scratch and an empty n8n_valkey_data, their top directories owned like the live ones.
    data_path = out_dir / 'volumes' / f'{items.data_volume}.tar'
    root = volume_root(work, app, items.data_volume)
    out = FileTar(data_path, work.guard)
    try:
        uid, gid = node_ids
        out.add_member(_info('.', 'dir', mode=root[2], uid=root[0], gid=root[1], mtime=time.time()))
        key = json.dumps({'encryptionKey': src.key}).encode('utf-8')
        out.add_member(_info('config', 'file', mode=0o600, uid=uid, gid=gid, mtime=time.time(), size=len(key)),
                       io.BytesIO(key))
        seen = set()
        with tarfile.open(staging / 'ha-n8n-files.tar', 'r|', encoding=habackup.ENCODING,
                          errors=habackup.ERRORS) as tar:
            for member in tar:
                info_ = tarfile.TarInfo(member.name)
                info_.type, info_.mode, info_.mtime = member.type, member.mode, member.mtime
                info_.uid, info_.gid, info_.size, info_.linkname = uid, gid, member.size, member.linkname
                info_.uname = info_.gname = ''
                seen.add(member.name.split('/', 1)[0])
                out.add_member(info_, tar.extractfile(member) if member.isfile() else None)
                tar.members.clear()
        for name in MOVED_DIRS:
            if name not in seen:
                out.add_member(_info(name, 'dir', mode=0o755, uid=uid, gid=gid, mtime=time.time()))
    finally:
        out.close()
    os.unlink(staging / 'ha-n8n-files.tar')
    valkey_path = out_dir / 'volumes' / f'{items.valkey_volume}.tar'
    vroot = volume_root(work, app, items.valkey_volume)
    out = FileTar(valkey_path, work.guard)
    try:
        out.add_member(_info('.', 'dir', mode=vroot[2], uid=vroot[0], gid=vroot[1], mtime=time.time()))
    finally:
        out.close()
    check_volume_tar(data_path, ids)
    check_volume_tar(valkey_path, ids)
    return {'volumes': {items.data_volume: data_path, items.valkey_volume: valkey_path},
            'postgres': {items.pg['id']: {'database': items.pg['database'], 'server_version': str(text)[:32],
                                          'major': major, 'file': dump}},
            'counts': dict(info['counts'], workflows_active=info['workflows_active']),
            'owner_email': info['owner_email'],
            'workflows_to_fix': workflows_to_fix(info['workflows']), 'packages': list(src.packages)}
