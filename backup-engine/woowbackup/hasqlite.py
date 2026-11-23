"""Home Assistant import: SQLite files of an HA backup (and, for Headscale, a copy of the live database) are opened
only by a child process that dropped its privileges -- the pattern of ha_n8n's SQLITE_CHILD, generalised for the batch
1 importers (CONTRACT section 9 "Home Assistant import", section 10 rule 18). Owner: E2.

`run(specs, files, work_dir, ...)` copies `files` ({name: staged path}) into a new folder `work_dir`, hands it to the
account nobody and starts CHILD (`python3 -I -S`): as root it leaves the network namespace (os.unshare, or libc's
unshare on Python < 3.12; a child that cannot leave it stops with NO_NETNS before it opens anything, and the job
stops: no unisolated fallback), chroots into the folder
(SQLite opens the copies by name; the job's 0700 staging above them stays out of reach), drops every group and its
ids, then sets CPU, memory, file size, open-file and process limits before it opens anything. Every database is
opened read-write on its own copy (a WAL or hot journal is applied there, never in staging) with
`SQLITE_DBCONFIG_DEFENSIVE`, `trusted_schema=OFF`, `cell_size_check=ON` and no mmap; only ordinary tables are ever
read (never a view, a virtual table or its shadow tables), with explicit columns. The Hermes state.db quick check
accepts only known FTS5 declarations. SQLite's quick_check then also runs FTS5's own check of those indexes (their
structure and segment pages, parsed here in the sandbox); it does not compare an index with its content views and
never runs those views (verified 2026-11-23 with SQLite 3.45.1). A database that is only read is
`query_only`. The child answers one JSON line per database and `{"end": true}`; this process never opens a database
itself.

A spec is {db: name, check: 'quick'|'integrity'|None, schema: bool, counts: [table], queries: [QUERIES key],
replace_api_keys_from: name|None}. The only write is Headscale's API keys: the target database's `api_keys` rows are
replaced by the rows of the source database (another file of the same folder, integrity-checked first), in one
transaction, on a database that has no trigger and no view, then the WAL is checkpointed and truncated; what this
process reads back of a written file (`outputs`) is opened by name below a descriptor of the folder with O_NOFOLLOW
and must be a regular file with one link and a bounded size (the child may have replaced it with anything).
"""
import contextlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

from .errors import BackupError

NAME_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z')
IDENT_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,62}\Z')
TIMEOUT = 1800
MEMORY = 2 * 1024 * 1024 * 1024
MAX_LINE = 32 * 1024 * 1024
MAX_DBS = 64
MAX_OUTPUT_FILE = 16 * 1024 ** 3
NO_NETNS = 3            # CHILD's exit status when, as root, it cannot leave the network namespace

# Fixed reads by name, sent to the child with the request (no other SQL ever is): (table, required columns,
# statement, kind); a table that is not an ordinary one or lacks a column answers None.
QUERIES = {
    'hermes.schema_version': ('schema_version', ('version',), 'SELECT max(version) FROM schema_version', 'scalar'),
    'headscale.version': ('database_versions', ('id', 'version'),
                          'SELECT version FROM database_versions WHERE id = 1', 'scalar'),
    'headscale.migrations': ('migrations', ('id',), 'SELECT id FROM migrations ORDER BY id LIMIT 5000', 'column'),
    'headscale.node_ips': ('nodes', ('ipv4', 'ipv6'), 'SELECT ipv4, ipv6 FROM nodes ORDER BY id LIMIT 100000', 'rows'),
    'headscale.api_key_prefixes': ('api_keys', ('prefix',), 'SELECT prefix FROM api_keys ORDER BY id LIMIT 1000',
                                   'column'),
}

CHILD = r'''
import json, os, re, resource, sqlite3, sys
uid, gid, fsize, cpu, memory = (int(x) for x in sys.argv[1:6])
request = json.loads(sys.stdin.read(4 * 1024 * 1024))
if os.geteuid() == 0:
    try:
        os.unshare(os.CLONE_NEWNET)
    except AttributeError:
        # Python < 3.12 (Debian 12: 3.11) has no os.unshare: the same system call through libc, still fail-closed.
        import ctypes
        if ctypes.CDLL(None, use_errno=True).unshare(0x40000000) != 0:  # CLONE_NEWNET, <linux/sched.h>
            os._exit(3)  # NO_NETNS
    except OSError:
        os._exit(3)  # NO_NETNS: never read an archive's databases with the host's network
    os.chroot(".")
    os.chdir("/")
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
for limit, value in ((resource.RLIMIT_AS, memory), (resource.RLIMIT_CPU, cpu), (resource.RLIMIT_NOFILE, 64),
                     (resource.RLIMIT_FSIZE, fsize), (resource.RLIMIT_CORE, 0), (resource.RLIMIT_NPROC, 0)):
    try:
        resource.setrlimit(limit, (value, value))
    except (ValueError, OSError):
        if limit != resource.RLIMIT_NPROC:
            raise
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")
QUERIES = request["queries"]
out = sys.stdout
def emit(doc):
    out.write(json.dumps(doc, ensure_ascii=False) + "\n")
    out.flush()
def connect(name):
    if not NAME.match(name) or not os.path.isfile(name) or os.path.islink(name):
        raise ValueError("not a database file")
    conn = sqlite3.connect("file:%s?mode=rw" % name, uri=True, isolation_level=None)
    conn.text_factory = lambda data: data.decode("utf-8", "replace")
    if hasattr(conn, "setconfig"):
        conn.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
    conn.execute("PRAGMA trusted_schema=OFF")
    conn.execute("PRAGMA cell_size_check=ON")
    conn.execute("PRAGMA mmap_size=0")
    return conn
def layout(conn):
    rows = conn.execute("SELECT name, type, sql FROM sqlite_master").fetchall()
    gap = r"(?:\s|--[^\n]*(?:\n|$)|/\*[\s\S]*?\*/)+"
    virtual = [n for n, k, q in rows if k == "table" and isinstance(q, str)
               and re.match(r"^\s*CREATE" + gap + r"VIRTUAL" + gap + r"TABLE\b", q, re.I)]
    tables = sorted(n for n, k, q in rows if k == "table" and isinstance(n, str) and n not in virtual
                    and not any(n.startswith(v + "_") for v in virtual))
    return {"tables": tables, "virtual": sorted(str(v) for v in virtual),
            "views": sum(1 for _n, k, _q in rows if k == "view"),
            "triggers": sum(1 for _n, k, _q in rows if k == "trigger")}
# Exact upstream Hermes FTS5 layouts; no tokenizer or content source is supplied by the archive.
HERMES_FTS = {
    "messages_fts": {
        "content", "content,content=messages,content_rowid=id",
        "content,tool_name,tool_calls,content='messages',content_rowid='id'",
        "content,tool_name,tool_calls,content='messages_fts_src',content_rowid='id'",
    },
    "messages_fts_trigram": {
        "content,tokenize='trigram'", "content,content=messages,content_rowid=id,tokenize='trigram'",
        "content,tool_name,tool_calls,content='messages_fts_trigram_src',content_rowid='id',tokenize='trigram'",
        "content,tool_name,content='messages_fts_trigram_src',content_rowid='id',tokenize='trigram'",
    },
}
def hermes_fts_ok(conn, info):
    # Only whitespace is ignored; comments, quoting changes, extra arguments and modules are rejected.
    rows = conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table'").fetchall()
    definitions = {n: q for n, q in rows if n in info["virtual"]}
    if len(definitions) != len(info["virtual"]):
        return False
    for name, sql in definitions.items():
        if name not in HERMES_FTS or not isinstance(sql, str):
            return False
        match = re.fullmatch(r"CREATE\s+VIRTUAL\s+TABLE\s+" + name + r"\s+USING\s+fts5\s*\(([^()]*)\)", sql, re.I)
        if not match:
            return False
        parts = re.split(r"('[^']*')", match.group(1))
        normalized = "".join(part if i % 2 else re.sub(r"\s+", "", part)
                             for i, part in enumerate(parts))
        if normalized not in HERMES_FTS[name]:
            return False
    return True

def columns(conn, table, info):
    if table not in info["tables"] or not IDENT.match(table):
        return set()
    return {r[1] for r in conn.execute('PRAGMA table_info("%s")' % table)}
def checked(conn, how):
    pragma = "quick_check" if how == "quick" else "integrity_check"
    return [str(r[0])[:300] for r in conn.execute("PRAGMA %s(20)" % pragma).fetchall()]
def api_keys(conn, info):
    if not {"prefix", "hash", "expiration", "last_seen", "created_at"} <= columns(conn, "api_keys", info):
        raise ValueError("api_keys table missing")
    return conn.execute("SELECT prefix, hash, expiration, last_seen, created_at FROM api_keys "
                        "ORDER BY id LIMIT 1001").fetchall()
for spec in request["dbs"]:
    name = spec["db"]
    doc = {"db": name}
    conn = None
    try:
        conn = connect(name)
        info = layout(conn)
        if info["virtual"] and not (spec.get("hermes_fts") and hermes_fts_ok(conn, info)):
            raise ValueError("virtual tables are not supported")
        if spec.get("check"):
            doc["check"] = checked(conn, spec["check"])
        if spec.get("schema"):
            doc["schema"] = info
        if not spec.get("replace_api_keys_from"):
            conn.execute("PRAGMA query_only=ON")
        counts = {}
        for table in spec.get("counts") or []:
            if table in info["tables"] and IDENT.match(table):
                counts[table] = conn.execute('SELECT count(*) FROM "%s"' % table).fetchone()[0]
        if spec.get("counts"):
            doc["counts"] = counts
        values = {}
        for key in spec.get("queries") or []:
            table, needed, sql, kind = QUERIES[key]
            if not set(needed) <= columns(conn, table, info):
                values[key] = None
                continue
            rows = conn.execute(sql).fetchall()
            if kind == "scalar":
                value = rows[0][0] if rows else None
                values[key] = value if isinstance(value, (int, str)) or value is None else str(value)
            elif kind == "column":
                values[key] = [r[0] if isinstance(r[0], (int, str)) else None for r in rows]
            else:
                values[key] = [[c if isinstance(c, (int, str)) else None for c in r] for r in rows]
        if spec.get("queries"):
            doc["values"] = values
        source = spec.get("replace_api_keys_from")
        if source:
            if info["triggers"] or info["views"]:
                raise ValueError("the database has triggers or views")
            other = connect(source)
            try:
                other_info = layout(other)
                if other_info["virtual"]:
                    raise ValueError("virtual tables are not supported")
                if checked(other, "integrity") != ["ok"]:
                    raise ValueError("the source database is damaged")
                rows = api_keys(other, other_info)
            finally:
                other.close()
            if len(rows) > 1000:
                raise ValueError("too many API keys")
            api_keys(conn, info)
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM api_keys")
            conn.executemany("INSERT INTO api_keys (prefix, hash, expiration, last_seen, created_at) "
                             "VALUES (?, ?, ?, ?, ?)", rows)
            conn.execute("COMMIT")
            written = [r[0] for r in conn.execute("SELECT prefix FROM api_keys ORDER BY id").fetchall()]
            if written != [r[0] for r in rows]:
                raise ValueError("the API keys were not written")
            checkpoint = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint is None or checkpoint[0] != 0 or checkpoint[1] != checkpoint[2]:
                raise ValueError("WAL checkpoint did not complete")
            doc["replaced"] = {"api_keys": len(rows), "prefixes": [str(p)[:64] for p in written]}
    except Exception as exc:
        doc["error"] = (type(exc).__name__ + ": " + str(exc))[:300]
    finally:
        if conn is not None:
            conn.close()
    emit(doc)
emit({"end": True})
'''


def nobody():
    import pwd
    try:
        account = pwd.getpwnam('nobody')
        return account.pw_uid, account.pw_gid
    except KeyError:
        return 65534, 65534


def _spec(spec, names):
    """A checked copy of one spec (only names the request copies, only known queries)."""
    if not isinstance(spec, dict) or spec.get('db') not in names:
        raise BackupError('internal-error', 'SQLite 讀取要求的格式不正確。')
    check = spec.get('check')
    source = spec.get('replace_api_keys_from')
    counts = list(spec.get('counts') or [])
    queries = list(spec.get('queries') or [])
    if (check not in (None, 'quick', 'integrity') or (source is not None and source not in names)
            or not all(isinstance(t, str) and IDENT_RE.fullmatch(t) for t in counts)
            or not all(q in QUERIES for q in queries)
            or (spec.get('hermes_fts', False) is not False and
                (spec.get('hermes_fts') is not True or spec['db'] != 'state.db' or source is not None
                 or check != 'quick'))):
        raise BackupError('internal-error', 'SQLite 讀取要求的格式不正確。')
    return {'db': spec['db'], 'check': check, 'schema': spec.get('schema') is True, 'counts': counts,
            'queries': queries, 'replace_api_keys_from': source, 'hermes_fts': spec.get('hermes_fts') is True}


def run(specs, files, work_dir, *, outputs=(), out_dir=None, checkpoint=None, timeout=TIMEOUT, what='資料庫'):
    """{db name: answer} of the child for `specs`; `files` {name: path} are copied into the new folder `work_dir`
    first (only regular files; the folder is removed at the end). `outputs`: names of files the child wrote that are
    copied into `out_dir` (root 0600) and returned as {name: path} under the key None. `what` names the data in
    messages. A child that fails or answers out of shape is corrupt-archive (`what` cannot be read)."""
    names = set(files)
    if not names or len(names) > MAX_DBS or not all(isinstance(n, str) and NAME_RE.fullmatch(n) for n in names):
        raise BackupError('internal-error', 'SQLite 讀取要求的格式不正確。')
    specs = [_spec(spec, names) for spec in specs]
    work_dir = Path(work_dir)
    work_dir.mkdir(mode=0o700)
    try:
        size = 0
        for name, source in sorted(files.items()):
            st = os.lstat(source)
            if not stat.S_ISREG(st.st_mode):
                raise BackupError('internal-error', '暫存的資料庫不是一般檔案。')
            shutil.copyfile(source, work_dir / name, follow_symlinks=False)
            os.chmod(work_dir / name, 0o600)
            size = max(size, st.st_size)
        uid, gid = nobody()
        if os.geteuid() == 0:
            for item in [work_dir] + sorted(work_dir.iterdir()):
                os.lchown(item, uid, gid)
        request = json.dumps({'dbs': specs, 'queries': QUERIES}).encode('utf-8')
        argv = [sys.executable, '-I', '-S', '-c', CHILD, str(uid), str(gid), str(2 * size + 64 * 1024 * 1024),
                str(int(timeout)), str(MEMORY)]
        proc = subprocess.Popen(argv, cwd=work_dir, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True,
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        try:
            with contextlib.suppress(BrokenPipeError):
                proc.stdin.write(request)
            proc.stdin.close()
            answers = _read(proc, {spec['db'] for spec in specs}, checkpoint=checkpoint, timeout=timeout, what=what)
        finally:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            proc.stdout.close()
        if outputs:
            answers[None] = {name: _copy_out(work_dir, name, Path(out_dir), what) for name in outputs}
        return answers
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _lines(proc, *, deadline, checkpoint, what):
    """The child's stdout line by line (each at most MAX_LINE bytes); `checkpoint` is called while waiting."""
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    buf = bytearray()
    try:
        while True:
            if checkpoint is not None:
                checkpoint()
            if time.monotonic() > deadline:
                raise BackupError('job-failed', f'讀取 HA 備份中的{what}逾時。')
            if not selector.select(1.0):
                continue
            data = os.read(proc.stdout.fileno(), 1024 * 1024)
            if not data:
                if buf:
                    raise BackupError('corrupt-archive', f'HA 備份中的{what}無法讀取。')
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
            if len(buf) > MAX_LINE:
                raise BackupError('corrupt-archive', f'HA 備份中的{what}無法讀取。')
    finally:
        selector.close()


def _read(proc, expected, *, checkpoint, timeout, what):
    answers, ended = {}, False
    bad = BackupError('corrupt-archive', f'HA 備份中的{what}無法讀取。')
    for line in _lines(proc, deadline=time.monotonic() + timeout, checkpoint=checkpoint, what=what):
        try:
            doc = json.loads(line)
        except (ValueError, RecursionError):
            doc = None
        if not isinstance(doc, dict) or ended:
            raise bad
        if doc.get('end') is True:
            ended = True
            continue
        if doc.get('db') not in expected or doc['db'] in answers:
            raise bad
        answers[doc['db']] = doc
    status = proc.wait(timeout=60)
    if status == NO_NETNS and not answers and not ended:
        raise BackupError('job-failed', f'無法替讀取 HA 備份中的{what}的程序切斷網路（隔離失敗），已停止，沒有讀取任何資料。')
    if status != 0 or not ended or set(answers) != expected:
        raise bad
    return answers


def _copy_out(work_dir, name, out_dir, what):
    """A file the child wrote, copied out without following anything it may have planted."""
    if not NAME_RE.fullmatch(name):
        raise BackupError('internal-error', '暫存檔名稱格式不正確。')
    dfd = os.open(work_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
        except OSError:
            raise BackupError('corrupt-archive', f'HA 備份中的{what}無法寫入轉換結果。') from None
    finally:
        os.close(dfd)
    dest = out_dir / name
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > MAX_OUTPUT_FILE:
            raise BackupError('corrupt-archive', f'HA 備份中的{what}轉換結果不是一般檔案。')
        out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(out, 'wb') as handle:
            while True:
                data = os.read(fd, 1024 * 1024)
                if not data:
                    break
                handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)
    return dest


def problem(answer):
    """A short reason when an answer says the database cannot be used (an error, or a check that is not ok)."""
    if answer.get('error'):
        return str(answer['error'])[:200]
    check = answer.get('check')
    if check is not None and check != ['ok']:
        return '；'.join(str(line)[:120] for line in check[:3]) or 'check failed'
    return None
