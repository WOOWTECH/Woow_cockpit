"""Home Assistant import, n8n part: the WOOWTECH add-on `woow-n8n` -> this device's app `n8n` (CONTRACT section 9
"Home Assistant import"; design notes of branch feat/ha-import, section 4). Owner: E2.

The add-on runs n8n on SQLite: `config/.n8n/{database.sqlite, -wal, -shm, config (JSON encryptionKey), nodes/,
storage/}`; caches, Redis data, runner files, logs and `data/` are not moved. The target is n8n in queue mode on
PostgreSQL 16 with the same n8n version (the import's migration check requires it); its key lives only in the volume
`n8n_n8n_data` (`config`).

check: the SQLite files (database and WAL; never HA's `-shm` wal-index) are copied into the job's root staging and
read by a child process that drops to the account nobody (chrooted into the folder of its copy, no supplementary
groups, its own network namespace -- os.unshare, or libc's unshare on Python < 3.12; a child that cannot leave the
network stops with NO_NETNS and the check stops: no unisolated fallback --, CPU, memory, file size and process limits)
on a copy of its own, with `SQLITE_DBCONFIG_DEFENSIVE`, `trusted_schema=OFF`
and only ordinary tables (no virtual table or its shadow tables; explicit columns): the owner account (email and
password set, else nothing can be moved), counts, the names of the credentials, and the workflows one per line, whose
reasons (shell commands, SSH, local files, Home Assistant, HA-internal addresses, Redis/MQTT, webhooks) this process
works out row by row within a size budget (review HA-SEC-02, HA-SEC-05); community packages (native `.node` files must
be for this device's processor and for musl, like the n8n image); the version must equal `n8n --version` of the live
image (a version that cannot be read here is no gate: N8-10).

HAOS parity (2026-11-25, DESIGN F-a lane N8N). What this device's n8n looks like decides what is carried, never whether
the import may start: this device's own other volumes and folders go along as they are (N8-02, N8-27: `hatarget.carry`),
the queue (Valkey / Redis) volumes are the only ones that are emptied, and a data volume whose owner cannot be read gets
the owner of the image (N8-11, N8-12). The SQLite reader grows its time with the size of the file and, when it was killed
or timed out, is run once more with more time and memory (N8-06, N8-07, N8-09); a database that is broken stops only n8n.
No key in HA's backup is no gate either: the workflows and everything else move, the credentials cannot be opened and are
entered again, which is ONE line the customer confirms (N8-15; a key of any shape that n8n takes is used as it is). A
large community node or `package.json` is copied as a stream and never read whole into memory (N8-28). Findings go to
`work.sink(app)` (haissues) in the check and, by the same code, in the conversion (N8-18): a stop stops n8n, a line to
confirm that was not confirmed stops n8n (`confirmation-required`), nothing else.

convert: a throwaway volume holds the SQLite copy and HA's key; a throwaway n8n (live image, network none) runs
`export:entities --includeExecutionHistoryDataTables=true`; a throwaway PostgreSQL (the live n8n-postgres image, user
and database n8n, a random password) and a throwaway n8n on an internal network run `import:entities
--truncateTables=true` (it exits 0 even when it skipped, so every table's rows are counted on both sides); test mode
unpublishes every workflow; `pg_dump -Fc` becomes the archive's database `main`. `n8n_n8n_data` is built from scratch:
`config` with HA's key (0600, the container's node uid/gid), HA's `nodes/` and `storage/`; `n8n_valkey_data` is empty
(queued jobs of HA never run here).
"""
import contextlib
import io
import json
import os
import pwd
import re
import secrets
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import time

from pathlib import Path

from . import habackup, haissues, hatarget, podman, tempctr, util
from .errors import BackupError
from .ha_odoo import (EM_X86_64, PG_READY_TIMEOUT, FileTar, _Exact, _info, _int, check_volume_tar, host_elf_machine,
                      quadlet_container_name, quadlet_mounts)
from .haissues import Issue

SLUG = 'woow-n8n'
APP_ID = 'n8n'
N8N_DIR = 'config/.n8n'
# HA's `-shm` (the WAL index) is never staged: SQLite rebuilds it from the WAL, whose frames it checks (HA-SEC-02).
SQLITE_FILES = ('database.sqlite', 'database.sqlite-wal')
KEY_FILE = 'config'
MOVED_DIRS = ('nodes', 'storage')
MAX_KEY_FILE = 1024 * 1024              # was 64 KiB; a larger file is no key file: it is listed as skipped (N8-28)
MAX_PACKAGE_JSON = 1024 * 1024          # what is parsed for the list of community packages; a larger one is copied unread (N8-28)
NATIVE_HEAD = 64 * 1024 * 1024          # of a native `.node` file only this much is looked at (what was read whole before); the file is copied as a stream (N8-28)
MAX_NODES_JSON = 16 * 1024 * 1024       # one workflow's nodes; a larger one is "too large to analyse"
MAX_NODES_TOTAL = 256 * 1024 * 1024     # all workflows' nodes read; the rest are "too large to analyse"
MAX_WORKFLOWS = 5000
MAX_CREDENTIALS = 20000                 # names of credentials the SQLite child hands over (only names, never a value)
MAX_NAME = 200
SQLITE_TIMEOUT = 1800                   # the floor; the time of one read grows with the size of the file (N8-06)
SQLITE_MEMORY = 2 * 1024 * 1024 * 1024
SQLITE_MEMORY_CEILING = 8 * 1024 * 1024 * 1024
SQLITE_ATTEMPTS = 2                     # a read that was killed or timed out is run once more with more time and memory
MAX_LINE = 2 * MAX_NODES_JSON + 1024 * 1024  # one line of the SQLite child (bytes)
TOO_LARGE = '這個工作流程太大，無法自動分析，匯入後請自行確認它的節點設定。'
COUNT_CHUNK = 40  # tables per json_build_object call: 2 arguments each, PostgreSQL allows 100 (review C-11)
TABLE_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,62}\Z')
VERSION_RE = re.compile(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:[-+][A-Za-z0-9.-]{1,40})?\Z')
PACKAGE_RE = re.compile(r'(?:@[a-z0-9][a-z0-9._-]{0,100}/)?[a-z0-9][a-z0-9._-]{0,213}\Z')
# Any text n8n takes for its encryption key: not only 8..1024 printable ASCII characters (N8-15). Control characters are
# no key; the text is only ever written into a JSON file (json.dumps), never into a command line.
KEY_RE = re.compile(r'[^\x00-\x1f\x7f-\x9f]{1,1024}\Z')
MASK_MIN = 4                            # a key shorter than this cannot be hidden from a log without hiding ordinary text
# A container whose image is named valkey or redis (the last part of the name: `valkey/valkey:8`, `library/redis:7`,
# `woow-valkey:2026`) keeps n8n's queue: its volume is emptied by the import (HA's queued jobs never run here), every other
# volume of the app is this device's own data and goes along as it is (N8-02).
QUEUE_REPOSITORY_RE = re.compile(r'(?:^|[-_.])(?:valkey|redis)(?:$|[-_.])')
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

# What the customer is told (zh-TW, plain; names go into the issue's items, never a value). Every id of this module is here.
ISSUES = {
    'n8n.layout-unsupported': 'stop',       # N8-01 (the whole instance), N8-02: this device's n8n is not set up as the import knows
    'n8n.extras-carried': 'auto',           # N8-02, N8-27: this device's own other volumes and folders go along as they are
    'n8n.mount-skipped': 'notice',          # the n8n side of OD-08, OD-09: a mount that is no data of n8n is left out
    'n8n.no-database': 'stop',              # N8-14: HA's backup holds no SQLite database of n8n
    'n8n.no-owner': 'stop',                 # N8-16: HA's n8n has no owner account
    'n8n.database-unreadable': 'stop',      # N8-07, N8-09: the database cannot be opened or read
    'n8n.database-slow': 'stop',            # N8-06, N8-07, N8-09: it was not read in time, also the second time
    'n8n.no-key': 'confirm',                # N8-15: no usable key in HA's backup: the credentials are entered again
    'n8n.key-created': 'auto',              # N8-15: ... and HA's n8n has no credentials: nothing to enter again
    'n8n.fixed-key': 'stop',                # N8-13 (the second wave lifts it): this device's n8n has a key of its own
    'n8n.community-packages': 'notice',     # HA's community nodes move along
    'n8n.native-code': 'notice',            # ... some with code that does not run here
    'n8n.volume-root-default': 'auto',      # N8-11, N8-12: the owner and mode of a data volume could not be read
}
SETTINGS_ACTION = '請到「應用設定」修正這台 n8n 的設定，再重新檢查；這台的 n8n 不會有任何變更。'
NO_DATABASE = ('這份 HA 備份裡沒有 n8n 的資料庫檔（database.sqlite），沒有資料可以搬；HA 的 n8n 可能改用了別的資料庫。')
NO_DATABASE_ACTION = ('這次請不要匯入 n8n（其他應用不受影響）；若 HA 的 n8n 用的是內建資料庫，請在 HA 重新備份後再上傳。'
                      '這台的 n8n 不會有任何變更。')
NO_OWNER_ACTION = ('請先在 HA 的 n8n 建立管理者帳號並重新備份，或這次不匯入 n8n；這台的 n8n 不會有任何變更。'
                   '（匯入一個沒有管理者的 n8n，會讓第一個打開網頁的人自己當管理者。）')
UNREADABLE = 'HA 備份中 n8n 的資料庫無法開啟或內容無法讀取（檔案可能不完整，或是在 n8n 執行中複製下來的）。'
UNREADABLE_ACTION = '請在 HA 重新備份後再上傳匯入 n8n（其他應用不受影響）；這台的 n8n 不會有任何變更。'
SLOW = ('HA 備份中 n8n 的資料庫在 {minutes} 分鐘內沒有讀完（讀取中途被終止或逾時）；已自動加長時間、放寬記憶體再讀一次，仍然沒有完成。')
SLOW_ACTION = '請等這台比較不忙時再試一次；仍然不行時，請把作業紀錄交給工程人員。這台的 n8n 不會有任何變更。'


# ====================================================================== the add-on member

class Source:
    """What a pass over the n8n add-on's inner tar staged and learned: the SQLite copy, the key (never logged), the
    community packages and native files, and what the reader left out (`report`: a habackup.Report whose names are
    haissues.Names; the one line to confirm, `Sink.skipped`)."""

    def __init__(self):
        self.addon = None
        self.sqlite = {}          # file name -> staged path
        self.key = None           # HA's encryptionKey (masked in every log of this process)
        self.packages = []        # [{name, version}]
        self.packages_unlisted = False   # nodes/package.json was too large to read: copied, the packages are not listed (N8-28)
        self.native_bad = []      # package names with native code that does not fit here
        self.native = 0
        self.files_tar = None     # staged nodes/ + storage/ (conversion only)
        self.files_bytes = 0
        self.report = None        # the walk's habackup.Report (member_pass)


def _key_from(data):
    """HA's encryptionKey out of the `config` file (None: no file content that holds one n8n can use). Any text n8n takes
    is a key (KEY_RE): the shape of the one n8n makes itself is not a rule (N8-15)."""
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
    """True when an ELF shared object is for this device's processor (the n8n image's) and does not need glibc (the
    n8n image is musl); False for another machine or glibc; None when it is not ELF."""
    if len(data) < 64 or data[:4] != b'\x7fELF':
        return None
    if data[4] != 2 or data[5] != 1:   # 64-bit little endian
        return False
    machine = struct.unpack_from('<H', data, 18)[0]
    if machine != (host_elf_machine() or EM_X86_64):
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
    `nodes/…` and `storage/…` (original modes). Nothing is stopped for its size (N8-28): a `config` file that is far too
    large to be one is listed as skipped (`report`, kind `large`) and no key; a `package.json` too large to read is copied
    as a stream and its packages are not listed; of a native `.node` file only its first NATIVE_HEAD bytes are looked at
    and the file is copied as a stream. Returns a Source."""
    select = habackup.Select(include=tuple(f'{N8N_DIR}/{name}' for name in SQLITE_FILES + (KEY_FILE,) + MOVED_DIRS),
                             exclude=(f'{N8N_DIR}/database.sqlite-shm',), symlinks=(f'{N8N_DIR}/nodes',),
                             hardlinks=False)
    src = Source()
    src.report = report
    count = 0
    for entry in habackup.iter_entries(stream, select, report, checkpoint=checkpoint):
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
                data = entry.read_or_skip(MAX_KEY_FILE)   # N8-28: too large for a settings file = no key (and listed)
                src.key = _key_from(data) if data is not None else None
                if src.key is not None and len(src.key.strip()) >= MASK_MIN:
                    from . import jobs
                    jobs.mask_secret(src.key)
            continue
        top, _, tail = rel.partition('/')
        if top == 'nodes' and tail == 'package.json' and entry.kind == 'file':
            if entry.size <= MAX_PACKAGE_JSON:
                data = entry.read_all(MAX_PACKAGE_JSON)
                src.packages = packages_of(data)
                if files is not None:
                    files.add_member(_info(rel, 'file', mode=entry.mode & 0o755 | 0o644, uid=0, gid=0, mtime=entry.mtime,
                                           size=len(data)), io.BytesIO(data))
            else:   # N8-28: never read whole; the file moves as it is
                src.packages_unlisted = True
                if files is not None:
                    files.add_entry(rel, entry, mode=(entry.mode & 0o755) | 0o644, uid=0, gid=0)
            src.files_bytes += entry.size
            continue
        if top == 'nodes' and entry.kind == 'file' and tail.endswith('.node'):
            src.native += 1
            head = _head(entry, NATIVE_HEAD)
            if elf_fits(head) is False:
                package = _package_of(tail)
                if package and package not in src.native_bad:
                    src.native_bad.append(package)
            if files is not None:
                files.add_member(_info(rel, 'file', mode=entry.mode & 0o755 | 0o644, uid=0, gid=0, mtime=entry.mtime,
                                       size=entry.size), _Exact(_Replay(head, entry), None))
            src.files_bytes += entry.size
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


def _head(entry, limit):
    """The first `limit` bytes of a file entry (all of it when it is shorter); the entry goes on from there."""
    parts, have = [], 0
    while have < limit:
        data = entry.read(min(habackup.CHUNK, limit - have))
        if not data:
            break
        parts.append(data)
        have += len(data)
    return b''.join(parts)


class _Replay:
    """What was read of an entry already (`head`), then the rest of it: for a file that is copied after its beginning was
    looked at. An offset into the head, never a slice of it (a head of megabytes read in small pieces would copy itself
    again for every piece)."""

    def __init__(self, head, entry):
        self.head, self.entry, self.at = memoryview(head), entry, 0

    def read(self, n=-1):
        if self.at < len(self.head):
            end = len(self.head) if n is None or n < 0 else min(len(self.head), self.at + n)
            data = bytes(self.head[self.at:end])
            self.at = end
            if self.at >= len(self.head):
                self.head.release()
                self.head = memoryview(b'')
                self.at = 0
            return data
        return self.entry.read(n)


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

NO_NETNS = 3  # SQLITE_CHILD's exit status when, as root, it cannot leave the network namespace (as hasqlite.NO_NETNS)

# The child that reads HA's SQLite file: it drops its privileges before it opens the file and writes JSON lines (a
# header, then one line per workflow, then {"end": true}). argv: uid gid max_row max_total max_rows file_size max_line.
SQLITE_CHILD = r"""
import json, os, re, resource, sqlite3, sys
uid, gid, max_row, max_total, max_rows, fsize, max_line = (int(x) for x in sys.argv[1:8])
if os.geteuid() == 0:
    try:
        os.unshare(os.CLONE_NEWNET)
    except AttributeError:
        # Python < 3.12 (Debian 12: 3.11) has no os.unshare: the same system call through libc, still fail-closed.
        import ctypes
        if ctypes.CDLL(None, use_errno=True).unshare(0x40000000) != 0:  # CLONE_NEWNET, <linux/sched.h>
            os._exit(3)  # NO_NETNS
    except OSError:
        os._exit(3)  # NO_NETNS: never read an archive's database with the host's network
    # The folder of the copy becomes the whole file system: SQLite opens it by its full path, and the job's staging
    # folders above it are root's alone (0700).
    os.chroot(".")
    os.chdir("/")
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
for limit, value in ((resource.RLIMIT_AS, int(sys.argv[9]) if len(sys.argv) > 9 else %(memory)d),
                     (resource.RLIMIT_CPU, int(sys.argv[8]) if len(sys.argv) > 8 else %(cpu)d), (resource.RLIMIT_NOFILE, 64),
                     (resource.RLIMIT_FSIZE, fsize), (resource.RLIMIT_CORE, 0), (resource.RLIMIT_NPROC, 0)):
    try:
        resource.setrlimit(limit, (value, value))
    except (ValueError, OSError):
        if limit != resource.RLIMIT_NPROC:
            raise
out = sys.stdout
def emit(doc):
    line = json.dumps(doc, ensure_ascii=False)
    if len(line.encode("utf-8")) > max_line:
        line = json.dumps({"n": doc.get("n", ""), "a": doc.get("a", False), "big": True}, ensure_ascii=False)
    out.write(line + "\n")
name_re = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")
def main():
    conn = sqlite3.connect("file:database.sqlite?mode=rw", uri=True, isolation_level=None)
    conn.text_factory = lambda data: data.decode("utf-8", "replace")
    try:
        if hasattr(conn, "setconfig"):
            conn.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA cell_size_check=ON")
        conn.execute("PRAGMA mmap_size=0")
        schema = conn.execute("SELECT name, type, sql FROM sqlite_master WHERE type IN ('table', 'view')").fetchall()
        conn.execute("PRAGMA query_only=ON")
        virtual = [n for n, k, q in schema if k == "table" and isinstance(q, str) and q.lstrip()[:20].upper().replace(" ", "").startswith("CREATEVIRTUAL")]
        kinds = {}
        for n, k, q in schema:
            if not isinstance(n, str) or n in virtual or any(n.startswith(v + "_") for v in virtual):
                continue
            kinds[n] = k
        def table(n):
            return kinds.get(n) == "table"
        def columns(n):
            return {r[1] for r in conn.execute('PRAGMA table_info("%%s")' %% n)} if table(n) and name_re.match(n) else set()
        tables = {}
        for n, k in sorted(kinds.items()):
            if k == "table" and name_re.match(n):
                tables[n] = conn.execute('SELECT count(*) FROM "%%s"' %% n).fetchone()[0]
        user_cols = columns("user")
        role_col = "roleSlug" if "roleSlug" in user_cols else "role" if "role" in user_cols else None
        owner = None
        if role_col and {"email", "password"} <= user_cols:
            row = conn.execute('SELECT email, password FROM "user" WHERE "%%s" = ? ORDER BY createdAt LIMIT 1' %% role_col,
                               ("global:owner",)).fetchone()
            if row is not None:
                owner = [row[0] if isinstance(row[0], str) else None, isinstance(row[1], str) and len(row[1]) > 0]
        migration = None
        if {"name", "timestamp"} <= columns("migrations"):
            row = conn.execute("SELECT name FROM migrations ORDER BY timestamp DESC LIMIT 1").fetchone()
            migration = str(row[0])[:200] if row else None
        wf_cols = columns("workflow_entity")
        readable = {"name", "active", "nodes"} <= wf_cols
        cred_cols = columns("credentials_entity")
        credentials = []
        if "name" in cred_cols:
            for row in conn.execute('SELECT name FROM credentials_entity ORDER BY name LIMIT %(creds)d').fetchall():
                credentials.append((row[0] if isinstance(row[0], str) else "")[:%(name)d])
        emit({"tables": tables, "owner": owner, "migration": migration, "workflows": readable, "credentials": credentials})
        if readable:
            archived = "isArchived" in wf_cols
            sql = ("SELECT name, active, length(CAST(nodes AS BLOB))" + (", isArchived" if archived else "") +
                   ", rowid FROM workflow_entity ORDER BY name LIMIT ?")
            total = 0
            for row in conn.execute(sql, (max_rows,)).fetchall():
                if archived and row[3]:
                    continue
                name = row[0] if isinstance(row[0], str) else ""
                size = row[2] if isinstance(row[2], int) else 0
                doc = {"n": name[:200], "a": bool(row[1])}
                if size > max_row or total + size > max_total:
                    doc["big"] = True
                else:
                    total += size
                    nodes = conn.execute("SELECT nodes FROM workflow_entity WHERE rowid = ?", (row[-1],)).fetchone()
                    doc["j"] = nodes[0] if nodes and isinstance(nodes[0], str) else "[]"
                emit(doc)
        emit({"end": True})
    finally:
        conn.close()
try:
    main()
except MemoryError:
    emit({"failed": "memory"})
    sys.exit(4)
except sqlite3.DatabaseError:
    emit({"failed": "database"})
    sys.exit(5)
""" % {'memory': SQLITE_MEMORY, 'cpu': SQLITE_TIMEOUT, 'creds': MAX_CREDENTIALS, 'name': MAX_NAME}


def _nobody():
    try:
        account = pwd.getpwnam('nobody')
        return account.pw_uid, account.pw_gid
    except KeyError:
        return 65534, 65534


def sqlite_limits(size, attempt=0):
    """(seconds of CPU and of waiting, address space in bytes, file size in bytes) the child that reads `size` bytes of
    SQLite files gets in its `attempt`-th run (0 = the first). The time grows with the size of the files (N8-06; never
    below SQLITE_TIMEOUT, at most a day); a run that was killed or timed out is made again with twice the time and memory
    (N8-07, N8-09), the memory up to SQLITE_MEMORY_CEILING. The child's own use of memory does not grow with the database
    (it counts rows and reads each workflow within MAX_NODES_JSON / MAX_NODES_TOTAL), so the first run keeps the old
    2 GiB: a limit that is a protection against a crafted file is only raised for a file that already failed."""
    factor = 2 ** max(0, int(attempt))
    seconds = min(podman.scaled_timeout(SQLITE_TIMEOUT, size) * factor, podman.SCALE_TIMEOUT_CEILING)
    memory = min(SQLITE_MEMORY * factor, SQLITE_MEMORY_CEILING)
    return int(seconds), int(memory), (2 * int(size) + 64 * 1024 * 1024) * factor


class _Failed(BackupError):
    """A run of the SQLite child that did not give a result. `kind`: `data` (the database itself is broken: a second
    run reads the same), `limit` (it was killed or ran out of time or memory: a run with more room may do) or `unknown`
    (no word from the child: one more run may do, and is the last)."""

    def __init__(self, code, message, kind, **details):
        super().__init__(code, message, **details)
        self.kind = kind


def _child_lines(proc, *, deadline, checkpoint=None, max_line):
    """The child's stdout, line by line (each at most `max_line` bytes), until it ends; `checkpoint` is called while
    waiting (a cancel or the job's watchdog stops it)."""
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    buf = bytearray()
    try:
        while True:
            if checkpoint is not None:
                checkpoint()
            if time.monotonic() > deadline:
                raise _Failed('job-failed', 'HA 的 n8n 資料庫讀取逾時。', 'limit')
            if not selector.select(1.0):
                continue
            data = os.read(proc.stdout.fileno(), 1024 * 1024)
            if not data:
                if buf:
                    raise _Failed('corrupt-archive', 'HA 備份中 n8n 的資料庫內容無法讀取。', 'unknown')
                return
            buf += data
            start = 0
            while True:
                end = buf.find(b'\n', start)
                if end < 0:
                    break
                yield bytes(buf[start:end])
                start = end + 1
            del buf[:start]
            if len(buf) > max_line:
                raise _Failed('corrupt-archive', 'HA 備份中 n8n 的資料庫內容無法讀取。', 'data')
    finally:
        selector.close()


def inspect_sqlite(path, *, checkpoint=None, log=None):
    """{owner_email, owner_ok, counts, credential_names, workflows [(name, active, reasons)], workflows_active, tables
    {name: rows}, migration} of the staged SQLite copy at `path` (database.sqlite; its -wal beside it is used too). The
    file is read by SQLITE_CHILD as the account nobody, on a copy of its own (this process never opens it, and never
    uses anything the child touched); the workflows' reasons are worked out here, one row at a time.

    The time the child gets grows with the size of the files, and a run that was killed or timed out is made once more
    with twice the time and memory (`sqlite_limits`; N8-06, N8-07, N8-09). What still does not work stops only n8n:
    `n8n.database-unreadable` (the database is broken, the second run would read the same) or `n8n.database-slow`."""
    path = Path(path)
    work_dir = path.parent / 'inspect'
    size = sum(os.path.getsize(path.parent / name if name != 'database.sqlite' else path) for name in SQLITE_FILES
               if os.path.lexists(path.parent / name if name != 'database.sqlite' else path))
    last = None
    for attempt in range(SQLITE_ATTEMPTS):
        seconds, memory, fsize = sqlite_limits(size, attempt)
        try:
            return _run_child(path, work_dir, size, checkpoint, seconds, memory, fsize)
        except _Failed as error:
            last = error
            if error.kind == 'data' or attempt + 1 >= SQLITE_ATTEMPTS:
                break
            (log or (lambda _text: None))(f'讀取 HA 備份中 n8n 的資料庫沒有完成（第 {attempt + 1} 次），'
                                          '自動加長時間、放寬記憶體再讀一次。')
    if last.kind == 'data' or last.kind == 'unknown':
        raise haissues.stopped(Issue('n8n.database-unreadable', 'stop', UNREADABLE, action=UNREADABLE_ACTION),
                               'corrupt-archive') from last
    raise haissues.stopped(Issue('n8n.database-slow', 'stop', SLOW.format(minutes=max(1, seconds // 60)),
                                 action=SLOW_ACTION), 'job-failed') from last


def _run_child(path, work_dir, size, checkpoint, seconds, memory, fsize):
    work_dir.mkdir(mode=0o700)
    try:
        for name in SQLITE_FILES:
            source = path.parent / name if name != 'database.sqlite' else path
            if os.path.lexists(source):
                shutil.copyfile(source, work_dir / name, follow_symlinks=False)
        uid, gid = _nobody()
        if os.geteuid() == 0:
            for item in [work_dir] + sorted(work_dir.iterdir()):
                os.lchown(item, uid, gid)
        argv = [sys.executable, '-I', '-S', '-c', SQLITE_CHILD, str(uid), str(gid), str(MAX_NODES_JSON),
                str(MAX_NODES_TOTAL), str(MAX_WORKFLOWS), str(fsize), str(MAX_LINE), str(seconds), str(memory)]
        proc = subprocess.Popen(argv, cwd=work_dir, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True,
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        try:
            return _read_child(proc, checkpoint, timeout=seconds)
        finally:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            proc.stdout.close()
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _read_child(proc, checkpoint, timeout=SQLITE_TIMEOUT):
    header, workflows, ended, failed = None, [], False, None
    lines = _child_lines(proc, deadline=time.monotonic() + timeout, checkpoint=checkpoint, max_line=MAX_LINE)
    for line in lines:
        try:
            doc = json.loads(line)
        except (ValueError, RecursionError):
            doc = None
        if not isinstance(doc, dict) or ended:
            raise _Failed('corrupt-archive', 'HA 備份中 n8n 的資料庫內容無法讀取。', 'data')
        if header is None:
            header = doc
            if doc.get('failed') in ('memory', 'database'):   # the child's own word, before it has anything to say
                failed, header = doc['failed'], None
            continue
        if doc.get('failed') in ('memory', 'database'):
            failed = doc['failed']
            continue
        if doc.get('end') is True:
            ended = True
            continue
        if len(workflows) >= MAX_WORKFLOWS or not isinstance(doc.get('n'), str):
            raise _Failed('corrupt-archive', 'HA 備份中 n8n 的資料庫內容無法讀取。', 'data')
        if doc.get('big') is True or not isinstance(doc.get('j'), str):
            reasons = [TOO_LARGE]
        else:
            reasons = workflow_reasons(doc['j'])
        workflows.append((doc['n'][:200], doc.get('a') is True, reasons))
        if checkpoint is not None:
            checkpoint()
    status = proc.wait(timeout=60)
    if status == NO_NETNS and header is None and not workflows and not ended and failed is None:
        raise BackupError('job-failed', '無法替讀取 HA 備份中 n8n 資料庫的程序切斷網路（隔離失敗），已停止，沒有讀取任何資料。')
    if failed == 'database':
        raise _Failed('corrupt-archive', 'HA 備份中 n8n 的資料庫無法開啟或內容無法讀取。', 'data')
    if failed == 'memory' or status < 0:   # out of memory, or killed by a signal (the CPU limit, the kernel's memory kill)
        raise _Failed('job-failed', 'HA 備份中 n8n 的資料庫在讀取時用完了時間或記憶體。', 'limit')
    if status != 0 or header is None or not ended:
        raise _Failed('corrupt-archive', 'HA 備份中 n8n 的資料庫無法開啟或內容無法讀取。', 'unknown')
    tables = {name: rows for name, rows in (header.get('tables') or {}).items()
              if isinstance(name, str) and TABLE_RE.fullmatch(name) and isinstance(rows, int) and rows >= 0}
    owner = header.get('owner') if isinstance(header.get('owner'), list) and len(header['owner']) == 2 else None
    email = owner[0] if owner and isinstance(owner[0], str) and 0 < len(owner[0]) <= 254 else None
    migration = header.get('migration') if isinstance(header.get('migration'), str) else None
    credentials = [name[:MAX_NAME] for name in (header.get('credentials') or [])[:MAX_CREDENTIALS]
                   if isinstance(name, str)] if isinstance(header.get('credentials'), list) else []
    return {'owner_email': email, 'owner_ok': email is not None and owner[1] is True,
            'counts': {key: tables.get(name, 0) for key, name in COUNTED.items()},
            'credential_names': credentials,
            'workflows_active': sum(1 for _n, active, _r in workflows if active), 'workflows': workflows,
            'tables': tables, 'migration': migration[:200] if migration else None}


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
    """[{name, active, reasons}] of the workflows (name, active, reasons) that have reasons."""
    found = []
    for name, active, reasons in workflows:
        if reasons:
            found.append({'name': name, 'active': active, 'reasons': list(reasons)})
        if len(found) >= limit:
            break
    return found


# ====================================================================== the live target

def _sink(work, app, converting=False):
    """The issues of this app. A work without sinks (a lab harness) collects nowhere; in a conversion its sink still stops
    at a stop and at a line nobody confirmed."""
    maker = getattr(work, 'sink', None)
    app_id = getattr(app, 'id', None) or APP_ID
    if callable(maker):
        return maker(app_id)
    return haissues.Sink(app_id, () if converting else None)


def _layout(app, problem):
    """This device's n8n is not set up as the import knows: this app stops, nothing else (N8-01, N8-02)."""
    return haissues.stopped(Issue('n8n.layout-unsupported', 'stop',
                                  f'這台的 n8n 應用設定不是 HA 匯入支援的樣子：{problem}。', action=SETTINGS_ACTION),
                            'incompatible', app=getattr(app, 'id', APP_ID))


def _container_names(quadlets):
    """[(file, container name)] of the `.container` files: the ContainerName=, else the name systemd gives (a file whose
    name cannot be used is not the one the app settings name)."""
    found = []
    for file in quadlets:
        if file.endswith('.container'):
            try:
                found.append((file, quadlet_container_name(quadlets, file)))
            except BackupError:
                continue
    return found


class Target:
    """The n8n app's catalog items the import fills, resolved against the live Quadlet files.

    What the app settings hold beyond n8n's own data is this device's, not HA's, and goes along as it is (N8-02, N8-27):
    `extra_volumes` and `extra_dirs` (`hatarget.carry`). Only the volumes of the queue (a container whose image is Valkey or
    Redis: `queue_volumes`) are emptied. A mount that is no data of n8n (a time zone file, a path of its own) is left out of
    what a throwaway container sees (`skipped_mounts`, the n8n side of OD-08 and OD-09)."""

    def __init__(self, work, app, sink=None):
        quadlets = work.quadlets(app)
        home = work.runner(app).home
        sink = sink if sink is not None else _sink(work, app)
        self.app = app
        if len(app.postgres) != 1 or app.postgres[0].get('scope', 'database') != 'database':
            if any(item.get('scope') == 'instance' for item in app.postgres):
                # The converted backup holds one database dump (adapter.import_manifest); an instance's globals, roles and
                # databases are made by the backup of the app itself. Not producible from here (DESIGN H, N8-01 part).
                raise _layout(app, '它備份的是整個資料庫執行個體，HA 匯入目前只能放進「單一資料庫」的設定')
            raise _layout(app, '需要剛好一個 PostgreSQL 資料庫項目（單一資料庫）')
        self.pg = app.postgres[0]
        self.skipped_mounts = []
        mounts = {}
        for name in quadlets:
            if not name.endswith('.container'):
                continue
            for source, target, _o in quadlet_mounts(quadlets, name, home, skipped=self.skipped_mounts):
                mounts.setdefault(source, []).append((name, target))
        if self.skipped_mounts:
            sink.notice('n8n.mount-skipped', '這台 n8n 的容器有掛載不是 n8n 資料的路徑（例如時區檔），匯入不會用到它們，已略過；'
                        '它們在這台維持原樣。', [f'{file}：{target}' for file, target in self.skipped_mounts])
        declared = [v['name'] for v in app.volumes]
        self.pg_file = next((file for file, container in _container_names(quadlets)
                             if container == self.pg['container']), None)
        self.data_volume = next((src for src, users in mounts.items()
                                 if any(t == '/home/node/.n8n' for _n, t in users)), None)
        self.main_file = next((n for n, t in mounts.get(self.data_volume, []) if t == '/home/node/.n8n'), None)
        if self.pg_file is None:
            raise _layout(app, f'找不到名叫 {haissues.clean(self.pg["container"], 80)} 的資料庫容器的 Quadlet 檔')
        if self.main_file is None or self.data_volume is None:
            raise _layout(app, 'n8n 的資料夾（/home/node/.n8n）沒有掛在資料卷上（或掛的是這個匯入不支援的主機路徑）')
        if self.data_volume not in declared:
            raise _layout(app, f'n8n 的資料夾掛的資料卷 {haissues.clean(self.data_volume, 80)} 沒有列在應用設定的資料卷裡')
        self.queue_images = {}   # queue volume -> the image of its container
        for volume in declared:
            image = _queue_image(quadlets, mounts.get(volume, [])) if volume != self.data_volume else None
            if image:
                self.queue_images[volume] = image
        self.queue_volumes = list(self.queue_images)
        self.valkey_volume = self.queue_volumes[0] if self.queue_volumes else None
        self.extra_volumes, self.extra_dirs = hatarget.extras(app, handled_volumes=(self.data_volume, *self.queue_volumes))
        if self.extra_volumes or self.extra_dirs:
            sink.auto('n8n.extras-carried', '這台 n8n 的應用設定還有其他資料卷或資料夾，匯入時會照這台現在的內容原樣帶過去，'
                      '不會被 HA 的資料取代。', [*self.extra_volumes, *self.extra_dirs])
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


def _queue_image(quadlets, users):
    """The image of the queue (Valkey / Redis) that keeps a volume, when every container that mounts the volume (`users`:
    [(container file, target)]) is one and there is one; else None: the volume is data of this device's own."""
    image = None
    for file, _target in users:
        try:
            image = tempctr.quadlet_image(quadlets[file])
        except BackupError:
            return None
        if not image or not _is_queue_image(image):
            return None
    return image


def _is_queue_image(image):
    """True when the name of the image's repository (no registry, no organisation, no tag) says Valkey or Redis."""
    repository = image.split('@', 1)[0].rsplit('/', 1)[-1].split(':', 1)[0].lower()
    return QUEUE_REPOSITORY_RE.search(repository) is not None


def _queue_owner(tmp, image):
    """(uid, gid) of the account a queue's image runs its data folder as (valkey, redis); root when the image does not say."""
    user = 'valkey' if 'valkey' in image.lower() else 'redis'
    try:
        return tmp.user_ids('ids-queue', image, user)
    except BackupError as error:
        if haissues.is_job_wide(error) or error.code in ('insufficient-space', 'busy'):
            raise
        return 0, 0


def target_version(tmp, image, role='n8n-version'):
    """`n8n --version` of this device's image; None when what it prints is no version (N8-10: the versions are then not
    compared, and the customer is told)."""
    out = tmp.run(role, image, ['--version'], timeout=300, max_output=64 * 1024).stdout or b''
    lines = [line.strip() for line in out.decode('utf-8', 'replace').splitlines() if line.strip()]
    version = lines[-1] if lines else ''
    return version if VERSION_RE.fullmatch(version) else None


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


def volume_root_or_image(work, app, name, default, sink):
    """`volume_root`, or when the owner and mode of the volume cannot be read -- it is not there yet, podman does not
    tell -- the image's own: `default()` -> (uid, gid, mode) (N8-11, N8-12). One line says so. A restored volume the
    container cannot write makes the app's health check fail, and the restore puts everything back by itself; what
    ends the whole job (a full disk, a cancel) is never taken for a volume that cannot be read."""
    try:
        return volume_root(work, app, name)
    except BackupError as error:
        if haissues.is_job_wide(error) or error.code in ('insufficient-space', 'busy'):
            raise
    root = tuple(default())
    sink.auto('n8n.volume-root-default', f'讀不到這台 n8n 資料卷 {haissues.clean(name, 80)} 現在的擁有者和權限，'
              f'改用映像標準的擁有者（{root[0]}:{root[1]}）和權限（{root[2]:o}）；如果它寫不進去，匯入後的健康檢查不會過，'
              '這台會自動退回匯入前的樣子。', [name])
    return root


# ====================================================================== the job steps

def member_pass(work, app, staging, *, files=None):
    member = work.addon_member(SLUG)
    report = habackup.Report(names=haissues.Names)   # what is left out is told once (Sink.skipped), not only logged
    with work.open(member) as stream:
        src = scan_member(stream, report, staging, files=files, guard=work.guard, checkpoint=work.checkpoint)
    for note in report.warnings():
        work.log(note)
    return src


KEY_SETTINGS = ('N8N_ENCRYPTION_KEY', 'N8N_ENCRYPTION_KEY_FILE')
ENV_LINE_RE = re.compile(r'\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=')


def fixed_key_settings(work, app):
    """Where the live n8n sets its own encryption key (Environment=, Secret=…,type=env, an EnvironmentFile= in the
    owner's home: names only, values are never kept): HA's key could not be used there (review C-18)."""
    quadlets = work.quadlets(app)
    runner = work.runner(app)
    found = []
    for name, text in sorted(quadlets.items()):
        if not name.endswith('.container'):
            continue
        body = text.decode('utf-8', 'replace') if isinstance(text, bytes) else str(text)
        entries = tempctr.parse_unit(body).get('Container', [])
        for key, value in entries:
            if key == 'Environment' and any(re.search(rf'(?:^|\s|"){k}=', value) for k in KEY_SETTINGS):
                found.append(name)
            elif key == 'Secret' and any(f'target={k}' in value.split(',') for k in KEY_SETTINGS) \
                    and 'type=env' in value.split(','):
                found.append(name)
            elif key == 'EnvironmentFile' and value.lstrip('-').startswith('%h/'):
                rel = value.lstrip('-')[3:]
                try:
                    data = runner.read_file(rel, max_bytes=256 * 1024)
                except BackupError:
                    continue
                names = {m.group(1) for m in map(ENV_LINE_RE.match, data.decode('utf-8', 'replace').splitlines())
                         if m}
                if names & set(KEY_SETTINGS):
                    found.append(f'~/{rel}')
    return sorted(set(found))


NO_KEY = ('HA 備份裡找不到 n8n 能用的加密金鑰（沒有設定檔、格式不對，或金鑰是空的），所以 HA 儲存的 {count} 個憑證（帳號密碼、API 金鑰）'
          '在這台打不開。工作流程、使用者和執行紀錄照常搬過來，這台會自動產生新的金鑰；匯入後請把這些憑證重新輸入一次。')
KEY_CREATED = 'HA 備份裡找不到 n8n 的加密金鑰（HA 的 n8n 也沒有儲存任何憑證，沒有東西要重新輸入），這台自動產生了新的金鑰。'


def analyse_data(sink, src, info, *, fixed_key=()):
    """What HA's n8n holds, as issues (see `analyse`): the findings that need no look at the image of this device."""
    if fixed_key:
        sink.stop('n8n.fixed-key', '這台的 n8n 設定了固定的加密金鑰（N8N_ENCRYPTION_KEY）；匯入後 n8n 會因金鑰和 HA 的資料不同而無法啟動。',
                  items=fixed_key, action='請先移除這個設定（所在的檔案見名單）再匯入；這台的 n8n 不會有任何變更。')
    if 'database.sqlite' not in src.sqlite:
        sink.stop('n8n.no-database', NO_DATABASE, action=NO_DATABASE_ACTION)
    if info is not None and not info['owner_ok']:
        sink.stop('n8n.no-owner', NO_OWNER + '匯入的話，這台的 n8n 會變成沒有任何資料的空站，而且第一個打開網頁的人可以自己當管理者。',
                  action=NO_OWNER_ACTION)
    if src.key is None and info is not None:   # N8-15: nothing stops; what cannot be opened is entered again
        count = info['counts'].get('credentials', 0)
        if count:
            sink.confirm('n8n.no-key', NO_KEY.format(count=count), haissues.Names(info['credential_names']))
        else:
            sink.auto('n8n.key-created', KEY_CREATED)
    if src.native_bad:
        sink.notice('n8n.native-code', f'有 {len(src.native_bad)} 個社群節點含有與這台不相容的程式（{"、".join(src.native_bad[:5])}'
                    f'{"…" if len(src.native_bad) > 5 else ""}），搬過來後需要重新安裝。', src.native_bad)
    if src.packages or src.packages_unlisted:
        names = [package['name'] for package in src.packages]
        sink.notice('n8n.community-packages', (f'HA 的 n8n 裝了 {len(src.packages)} 個社群節點套件，' if src.packages else
                                              'HA 的 n8n 裝了社群節點套件（清單太大，沒有逐一列出），')
                    + '搬過來後請確認它們能正常使用。', names)


def analyse_version(sink, version, target):
    """The add-on's version against `n8n --version` here: both known and different stops n8n, a version that cannot be read
    here (`target` None, N8-10) or is not known is only told (CM-01, CM-02)."""
    sink.extend(haissues.version_issues('n8n', version, version or None, target))


def analyse(sink, src, info, version, target, *, fixed_key=()):
    """What HA's n8n and this device's make of each other, as issues in `sink` (the check collects them all; the
    conversion calls this again, with the same words, so that it stops at what stops and asks for what was not confirmed:
    N8-18). `version`: the add-on's version, `target`: `n8n --version` here, None when it cannot be read (N8-10: no
    comparison, a notice). `info`: inspect_sqlite's answer, None when there is no database to read."""
    analyse_data(sink, src, info, fixed_key=fixed_key)
    analyse_version(sink, version, target)


def _this_devices_version(work, app, tmp, items, sink):
    """`n8n --version` of this device's image (downloaded first when it is not here, CM-05), None when it prints none (N8-10).
    Not asked for an app that has stopped already: no image is downloaded for what cannot be imported."""
    if any(issue.level == 'stop' for issue in sink.found):
        return None
    hatarget.ensure_image(work, app, items.n8n_image)
    return target_version(tmp, items.n8n_image)


def check(work, app):
    sink = _sink(work, app)
    tmp = work.temp(app)
    items = Target(work, app, sink)
    staging = work.staging / 'n8n-work'
    staging.mkdir(mode=0o700)
    addon = work.addon_info(SLUG)
    src = member_pass(work, app, staging)
    sqlite_bytes = sum(os.path.getsize(p) for p in src.sqlite.values())
    work.phase('check')
    info = (inspect_sqlite(src.sqlite['database.sqlite'], checkpoint=work.checkpoint, log=work.log)
            if 'database.sqlite' in src.sqlite else None)
    analyse_data(sink, src, info, fixed_key=fixed_key_settings(work, app))
    version = _this_devices_version(work, app, tmp, items, sink)   # CM-05: an image that is not here is downloaded
    if not any(issue.level == 'stop' for issue in sink.found):
        analyse_version(sink, addon.version if addon else '', version)
    sink.skipped(src.report)   # the one line about what the reader left out (IN-19, IN-27, ..., N8-28)
    fix = workflows_to_fix(info['workflows']) if info else []
    counts = info['counts'] if info else {}
    return {'target_version': version or '',
            'sqlite_bytes': sqlite_bytes,
            'n8n': {'owner_email': info['owner_email'] if info else None,
                    'workflows': counts.get('workflows', 0), 'workflows_active': info['workflows_active'] if info else 0,
                    'credentials': counts.get('credentials', 0), 'executions': counts.get('executions', 0),
                    'users': counts.get('users', 0), 'projects': counts.get('projects', 0),
                    'variables': counts.get('variables', 0), 'data_tables': counts.get('data_tables', 0),
                    'community_packages': list(src.packages), 'workflows_to_fix': fix}}


def import_texts(data):
    """(notes, reminders) of a conversion (haimport.import_texts; CONTRACT section 7 HaImport)."""
    email = data.get('owner_email')
    shown = f'（{email}）' if email else ''
    notes = [f'n8n 的登入帳號會換成 HA 的管理者帳號{shown}。']
    reminders = [f'匯入後請用 HA 的 n8n 管理者帳號{shown}登入。']
    if data.get('packages'):
        notes.append('HA 的 n8n 社群節點會一起搬過來。')
        reminders.append('請確認 HA 的 n8n 社群節點能正常使用（必要時重新安裝）。')
    if data.get('credentials_to_enter'):
        notes.append('HA 備份裡沒有 n8n 能用的加密金鑰，這台已產生新的金鑰；HA 儲存的憑證打不開。')
        reminders.append(f'請把 n8n 裡 HA 儲存的 {data["credentials_to_enter"]} 個憑證（帳號密碼、API 金鑰）全部重新輸入一次。')
    return notes, reminders


def _source_tar(out, src, password, *, node_ids, key=None):
    """The throwaway volume `n8nsrc`: home/.n8n/{database.sqlite*, config} owned by the image's node user, an
    empty writable out/ and the temporary database password (pgpass, readable by both containers). `key`: the
    encryption key to write (HA's, from `src`, unless there is none: N8-15)."""
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
    key = json.dumps({'encryptionKey': key if key is not None else src.key}).encode('utf-8')
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


def count_rows(pg, tables, database='n8n'):
    """{table: rows} in the throwaway PostgreSQL for the tables that exist there (COUNT_CHUNK tables per query: a
    function takes at most 100 arguments; review C-11) in the database `database`: the name the app settings give (N8-21;
    it was always `n8n`)."""
    present = pg.query_json("SELECT coalesce(json_agg(tablename), '[]'::json) FROM pg_tables "
                            "WHERE schemaname = 'public'", database)
    present = {name for name in present if isinstance(name, str)} if isinstance(present, list) else set()
    names = [name for name in tables if name in present and TABLE_RE.fullmatch(name)]
    found = {}
    for start in range(0, len(names), COUNT_CHUNK):
        chunk = names[start:start + COUNT_CHUNK]
        parts = ', '.join(f"'{name}', (SELECT count(*) FROM \"{name}\")" for name in chunk)
        doc = pg.query_json(f'SELECT json_build_object({parts})', database)
        if isinstance(doc, dict):
            found.update({name: _int(doc.get(name)) for name in chunk if name in doc})
    return found


def convert(work, app, test_mode, out_dir):
    """Build the app's data items in `out_dir`; returns {volumes {name: path}, dirs {path: tar}, postgres {id: {...}},
    counts, workflows_to_fix}.

    The same findings as the check, by the same code (N8-18): what stops n8n stops it here, a line to confirm that was not
    confirmed -- or confirmed with other names -- is `confirmation-required`. This device's own other volumes and folders
    come along as they are (N8-02, N8-27), the queue's volumes are emptied, HA's key is used (a new one is made when HA's
    backup has none, N8-15)."""
    from . import jobs
    from .ha_odoo import Cluster
    sink = _sink(work, app, converting=True)
    adapter = work.adapter(app)
    tmp = work.temp(app)
    items = Target(work, app, sink)
    ids = adapter.owner_ids()
    size = hatarget.size_hint(getattr(work, 'ha', None))
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
    sqlite_bytes = sum(os.path.getsize(p) for p in src.sqlite.values())
    work.guard.check(4 * sqlite_bytes)
    info = (inspect_sqlite(src.sqlite['database.sqlite'], checkpoint=work.checkpoint, log=work.log)
            if 'database.sqlite' in src.sqlite else None)
    analyse_data(sink, src, info, fixed_key=fixed_key_settings(work, app))   # a stop or an unconfirmed line ends it here
    version = _this_devices_version(work, app, tmp, items, sink)             # CM-05: downloaded as the owner when not here
    analyse_version(sink, addon.version if addon else '', version)
    hatarget.ensure_image(work, app, items.pg_image)
    sink.skipped(src.report)
    carry_report = habackup.Report(names=haissues.Names)
    carried = {'volumes': {}, 'dirs': {}}
    if items.extra_volumes or items.extra_dirs:   # N8-02, N8-27: this device's own other data goes along as it is
        carried = hatarget.carry(work, app, out_dir, ids, volumes=items.extra_volumes, dirs=items.extra_dirs,
                                 report=carry_report, size=size)
        sink.skipped(carry_report)
    node_ids = tmp.user_ids('ids-node', items.n8n_image, 'node')
    key, new_key = src.key, False
    if key is None:   # N8-15: HA's credentials cannot be opened; n8n here gets a key of its own, made now
        key, new_key = secrets.token_urlsafe(24), True
        jobs.mask_secret(key)
    password = secrets.token_urlsafe(24)
    jobs.mask_secret(password)
    tmp.volume('n8nsrc')
    tmp.volume_import('n8nsrc', lambda out: _source_tar(out, src, password, node_ids=node_ids, key=key))
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
    pg_env = {key_: value for key_, value in items.pg_env.items() if key_ in ('POSTGRES_INITDB_ARGS', 'LANG', 'TZ')}
    pg_env.update({'POSTGRES_USER': items.pg['user'], 'POSTGRES_DB': items.pg['database'],
                   'POSTGRES_PASSWORD_FILE': '/work/pgpass'})
    tmp.run('n8n-pg', items.pg_image, [], detach=True, network=network,
            volumes=[(tmp.name('n8nsrc'), '/work', 'ro'), (tmp.name('n8n-pgdata'), items.pg_target, None)],
            env=pg_env)
    pg = Cluster(tmp, 'n8n-pg', superuser=items.pg['user'], log=work.log)
    pg.wait_ready(tcp=True, checkpoint=work.checkpoint, timeout=podman.scaled_timeout(PG_READY_TIMEOUT, sqlite_bytes))
    db_env = _n8n_env({'DB_TYPE': 'postgresdb', 'DB_POSTGRESDB_HOST': tmp.name('n8n-pg'), 'DB_POSTGRESDB_PORT': '5432',
                       'DB_POSTGRESDB_DATABASE': items.pg['database'], 'DB_POSTGRESDB_USER': items.pg['user'],
                       'DB_POSTGRESDB_PASSWORD_FILE': '/work/pgpass'})
    work.log('把資料匯入新的 PostgreSQL 資料庫')
    tmp.run('n8n-import', items.n8n_image, ['import:entities', '--inputDir=/work/out', '--truncateTables=true'],
            network=network, volumes=[(tmp.name('n8nsrc'), '/work', None)], env=db_env, timeout=3600,
            max_output=4 * 1024 * 1024)
    compared = {name: rows for name, rows in info['tables'].items() if rows and name not in NOT_COMPARED}
    found = count_rows(pg, compared, items.pg['database'])
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
    # n8n_n8n_data from scratch and the queue's volumes empty, their top directories owned like the live ones.
    data_path = out_dir / 'volumes' / f'{items.data_volume}.tar'
    root = volume_root_or_image(work, app, items.data_volume, lambda: (*node_ids, 0o755), sink)
    out = FileTar(data_path, work.guard)
    try:
        uid, gid = node_ids
        out.add_member(_info('.', 'dir', mode=root[2], uid=root[0], gid=root[1], mtime=time.time()))
        config = json.dumps({'encryptionKey': key}).encode('utf-8')
        out.add_member(_info('config', 'file', mode=0o600, uid=uid, gid=gid, mtime=time.time(), size=len(config)),
                       io.BytesIO(config))
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
    volumes = {items.data_volume: data_path}
    for name in items.queue_volumes:
        queue_path = out_dir / 'volumes' / f'{name}.tar'
        queue_root = volume_root_or_image(work, app, name, lambda name=name: (*_queue_owner(tmp, items.queue_images[name]), 0o755),
                                          sink)
        out = FileTar(queue_path, work.guard)
        try:
            out.add_member(_info('.', 'dir', mode=queue_root[2], uid=queue_root[0], gid=queue_root[1], mtime=time.time()))
        finally:
            out.close()
        volumes[name] = queue_path
    check_volume_tar(data_path, ids)
    for name in items.queue_volumes:
        check_volume_tar(volumes[name], ids)
    volumes.update(carried['volumes'])
    return {'volumes': volumes, 'dirs': dict(carried['dirs']),
            'postgres': {items.pg['id']: {'database': items.pg['database'], 'server_version': str(text)[:32],
                                          'major': major, 'file': dump}},
            'counts': dict(info['counts'], workflows_active=info['workflows_active']),
            'owner_email': info['owner_email'],
            'workflows_to_fix': workflows_to_fix(info['workflows']), 'packages': list(src.packages),
            'credentials_to_enter': info['counts'].get('credentials', 0) if new_key else 0}
