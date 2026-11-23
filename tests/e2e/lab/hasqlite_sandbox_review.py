#!/usr/bin/env python3
"""Independent security review harness: Hermes FTS5 allowance in hasqlite (R-COCKPIT feat/ha-import-batch1, 7f1cd1a).

Runs as root inside a throwaway --network=none container, against the real hasqlite.run / hasqlite.CHILD code.
Reports only structure: versions, outcome classes, timings, FTS declarations. Never prints database contents.
Usage: harness.py full | probe-only
"""
import hashlib
import json
import os
import random
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

MODE = sys.argv[1] if len(sys.argv) > 1 else 'full'
sys.path.insert(0, '/engine/backup-engine')
from woowbackup import hasqlite  # noqa: E402  (the module under review)
from woowbackup.errors import BackupError  # noqa: E402

OUT = Path('/out')
WORK = Path(tempfile.mkdtemp(prefix='hermes-review-'))
REAL = Path('/real/config')
RES = {'mode': MODE, 'sqlite_version': sqlite3.sqlite_version, 'python': sys.version.split()[0],
       'euid': os.geteuid(),
       'hasqlite_sha256': hashlib.sha256(Path(hasqlite.__file__).read_bytes()).hexdigest()}
HERMES_SPEC = {'db': 'state.db', 'check': 'quick', 'counts': ['sessions', 'messages'],
               'queries': ['hermes.schema_version'], 'hermes_fts': True}
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}


def log(*a):
    print(*a, flush=True)


def norm_decl(sql):
    """The hermes_fts_ok normalisation, for reporting only."""
    m = re.fullmatch(r"\s*CREATE\s+VIRTUAL\s+TABLE\s+(\S+)\s+USING\s+(\w+)\s*\(([^()]*)\)\s*", sql or '', re.I)
    if not m:
        return {'raw_prefix': (sql or '')[:60]}
    parts = re.split(r"('[^']*')", m.group(3))
    return {'name': m.group(1), 'module': m.group(2).lower(),
            'args': ''.join(p if i % 2 else re.sub(r'\s+', '', p) for i, p in enumerate(parts))}


# ---------------------------------------------------------------- sandbox probe (real CHILD setup lines)
def start_listener():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 0))
    s.listen(8)

    def accept():
        while True:
            try:
                c, _ = s.accept()
                c.close()
            except OSError:
                return
    threading.Thread(target=accept, daemon=True).start()
    return s, s.getsockname()[1]


PROBE_BODY = r'''
res = {}
res["ids"] = [os.getuid(), os.geteuid(), os.getgid(), os.getegid(), sorted(os.getgroups())]
try:
    res["root_listing"] = sorted(os.listdir("/"))
except OSError as e:
    res["root_listing"] = "errno=%s" % e.errno
for p in ("/etc/passwd", "/proc/self/status", "/engine", "/real", "/usr/bin/python3"):
    res["visible:" + p] = os.path.exists(p)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("127.0.0.1", PORT))  # numeric ASCII host: no idna codec import after chroot
    s.close()
    res["loopback_listener"] = "CONNECTED"
except OSError as e:
    res["loopback_listener"] = "blocked errno=%s" % e.errno
try:
    res["interfaces"] = sorted(n for _, n in socket.if_nameindex())
except OSError as e:
    res["interfaces"] = "errno=%s" % e.errno
try:
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)
    res["fork"] = "ALLOWED"
except OSError as e:
    res["fork"] = "blocked errno=%s" % e.errno
for what, fn in (("setuid0", lambda: os.setuid(0)), ("chroot_again", lambda: os.chroot("/"))):
    try:
        fn()
        res[what] = "ALLOWED"
    except OSError as e:
        res[what] = "blocked errno=%s" % e.errno
res["rlimits"] = {n: list(resource.getrlimit(getattr(resource, n))) for n in
                  ("RLIMIT_AS", "RLIMIT_CPU", "RLIMIT_NOFILE", "RLIMIT_FSIZE", "RLIMIT_CORE", "RLIMIT_NPROC")}
print(json.dumps(res))
'''


def sandbox_probe():
    child = hasqlite.CHILD
    prefix = child[:child.index('NAME = re.compile')]
    assert prefix.strip().startswith('import json, os, re, resource, sqlite3, sys')
    listener, port = start_listener()
    code = 'import socket\n' + prefix + PROBE_BODY.replace('PORT', str(port))
    work = WORK / 'probe'
    work.mkdir(mode=0o700)
    uid, gid = hasqlite.nobody()
    os.lchown(work, uid, gid)
    argv = [sys.executable, '-I', '-S', '-c', code, str(uid), str(gid), str(64 * 1024 * 1024), '60',
            str(hasqlite.MEMORY)]
    p = subprocess.run(argv, cwd=work, input=b'{"dbs": [], "queries": {}}', capture_output=True, timeout=90,
                       env=ENV, close_fds=True, start_new_session=True)
    listener.close()
    out = {'returncode': p.returncode, 'stderr_tail': p.stderr.decode(errors='replace')[-200:],
           'prefix_sha256': hashlib.sha256(prefix.encode()).hexdigest()}
    try:
        out.update(json.loads(p.stdout.decode().strip().splitlines()[-1]))
    except (ValueError, IndexError):
        out['stdout_tail'] = p.stdout.decode(errors='replace')[-200:]
    return out


# ---------------------------------------------------------------- running the real child
def run_raw(spec, path, timeout=60, memory=None):
    """The unmodified hasqlite.CHILD started exactly like run() does, keeping the exit status (signals visible)."""
    work = WORK / ('raw-%d' % time.monotonic_ns())
    work.mkdir(mode=0o700)
    shutil.copyfile(path, work / spec['db'])
    os.chmod(work / spec['db'], 0o600)
    uid, gid = hasqlite.nobody()
    for item in [work] + sorted(work.iterdir()):
        os.lchown(item, uid, gid)
    size = (work / spec['db']).stat().st_size
    req = json.dumps({'dbs': [hasqlite._spec(spec, {spec['db']})], 'queries': hasqlite.QUERIES}).encode()
    argv = [sys.executable, '-I', '-S', '-c', hasqlite.CHILD, str(uid), str(gid), str(2 * size + 64 * 1024 * 1024),
            str(timeout), str(memory or hasqlite.MEMORY)]
    t = time.monotonic()
    try:
        p = subprocess.run(argv, cwd=work, input=req, capture_output=True, timeout=timeout + 15, env=ENV,
                           close_fds=True, start_new_session=True)
        rc, lines = p.returncode, p.stdout.decode(errors='replace').splitlines()
    except subprocess.TimeoutExpired:
        rc, lines = 'timeout', []
    finally:
        shutil.rmtree(work, ignore_errors=True)
    doc = None
    for line in lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if isinstance(d, dict) and d.get('db') == spec['db']:
            doc = d
    if isinstance(rc, int) and rc < 0:
        cls = 'CRASH-signal:%s' % signal.Signals(-rc).name
    elif rc == 'timeout':
        cls = 'timeout'
    elif rc != 0 or doc is None:
        cls = 'child-exit-%s' % rc
    elif doc.get('error'):
        cls = 'refused-error'
    elif doc.get('check') not in (None, ['ok']):
        cls = 'refused-check'
    else:
        cls = 'ACCEPTED'
    return {'class': cls, 'elapsed': round(time.monotonic() - t, 2),
            'error': (doc.get('error') or '')[:110] if doc else None,
            'check_head': [str(x)[:110] for x in ((doc or {}).get('check') or [])[:2]]}


def run_official(specs, files, timeout=hasqlite.TIMEOUT, tag='x'):
    work = WORK / ('run-%s-%d' % (tag, time.monotonic_ns()))
    t = time.monotonic()
    try:
        answers = hasqlite.run(specs, files, work, timeout=timeout, what='Hermes 資料庫')
    except BackupError as e:
        return {'verdict': 'BackupError ' + ' / '.join(str(a)[:80] for a in e.args), 'elapsed': round(time.monotonic() - t, 2)}
    out = {'verdict': {n: (hasqlite.problem(a) or 'ok') for n, a in answers.items() if n is not None},
           'elapsed': round(time.monotonic() - t, 2)}
    st = answers.get('state.db') or {}
    out['state_counts'] = st.get('counts')
    out['state_values'] = st.get('values')
    return out


# ---------------------------------------------------------------- variants of a copy of the real state.db
def copy_real(tag):
    path = WORK / ('v-%s.db' % tag)
    shutil.copyfile(REAL / 'state.db', path)
    for side in ('-wal', '-journal'):
        if (REAL / ('state.db' + side)).exists():
            shutil.copyfile(REAL / ('state.db' + side), str(path) + side)
    con = sqlite3.connect(path, isolation_level=None)
    con.execute('PRAGMA journal_mode=DELETE')  # fold any WAL into the copy (generator side only)
    return path, con


def fts_names(con):
    return {n: q for n, q in con.execute("SELECT name, sql FROM sqlite_master WHERE type='table' "
                                         "AND sql LIKE 'CREATE VIRTUAL%'")}


def set_sql(con, name, sql):
    con.execute('PRAGMA writable_schema=ON')
    con.execute("UPDATE sqlite_master SET sql=? WHERE name=?", (sql, name))
    con.execute('PRAGMA writable_schema=OFF')


def blobs(con, table):
    return con.execute('SELECT id, block FROM "%s" ORDER BY id' % table).fetchall()


def main():
    OUT.mkdir(exist_ok=True)
    log('mode', MODE, 'sqlite', sqlite3.sqlite_version, 'euid', os.geteuid())
    RES['sandbox_probe'] = sandbox_probe()
    log('probe', json.dumps(RES['sandbox_probe'])[:600])
    if MODE == 'probe-only':
        return
    if MODE == 'failclosed':  # the real backup's databases through run(), in a container without SYS_ADMIN
        RES['real_official'] = run_official(*real_specs_files(), tag='real')
        log('real', json.dumps(RES['real_official'], ensure_ascii=False)[:400])
        return

    # Real backup layout (structure only)
    path, con = copy_real('inspect')
    rows = con.execute('SELECT type, name, sql FROM sqlite_master').fetchall()
    msg_cols = [r[1] for r in con.execute('PRAGMA table_info(messages)')]
    con.close()
    fts = {n: norm_decl(q) for t, n, q in rows if t == 'table' and (q or '').lstrip().upper().startswith('CREATE VIRTUAL')}
    RES['real_layout'] = {'tables': sum(1 for r in rows if r[0] == 'table'), 'views': [r[1] for r in rows if r[0] == 'view'],
                          'triggers': [r[1] for r in rows if r[0] == 'trigger'],
                          'virtual': fts, 'messages_columns': msg_cols,
                          'state_db_bytes': (REAL / 'state.db').stat().st_size}
    log('real layout', json.dumps(RES['real_layout'])[:900])
    fts_table = 'messages_fts' if 'messages_fts' in fts else (sorted(fts)[0] if fts else None)

    # R1: the real files exactly as ha_hermes stages them
    RES['real_official'] = run_official(*real_specs_files(), tag='real')
    RES['real_raw_state'] = run_raw(HERMES_SPEC, REAL / 'state.db')
    log('real', json.dumps(RES['real_official'])[:600], RES['real_raw_state'])
    if not fts_table:
        RES['note'] = 'real state.db has no virtual table: FTS path not exercised by the real backup'
        return
    data_table, shadow_cfg = fts_table + '_data', fts_table + '_config'
    if MODE == 'full':
        sections_abc(fts_table, data_table, shadow_cfg)
    sections_de(fts_table, msg_cols)


def sections_abc(fts_table, data_table, shadow_cfg):
    # A: does quick_check run the FTS5 integrity check?  (whitelisted declaration, damaged index)
    damage = {
        'struct_garbage': lambda c: c.execute('UPDATE "%s" SET block=randomblob(64) WHERE id=10' % data_table),
        'struct_empty': lambda c: c.execute("UPDATE \"%s\" SET block=X'' WHERE id=10" % data_table),
        'leaves_random': lambda c: c.execute('UPDATE "%s" SET block=randomblob(length(block)) WHERE id>10' % data_table),
        'config_version_999': lambda c: c.execute("UPDATE \"%s\" SET v=999 WHERE k='version'" % shadow_cfg),
        'docsize_dropped': lambda c: c.execute('DELETE FROM "%s_docsize"' % fts_table),
        'content_changed_index_stale': lambda c: c.execute(
            "UPDATE messages SET content = coalesce(content,'') || ' zz-review-marker' "
            "WHERE id IN (SELECT id FROM messages ORDER BY id LIMIT 5)"),
    }
    RES['damaged_index'] = {}
    for tag, fn in damage.items():
        p, c = copy_real('dmg-' + tag)
        try:
            fn(c)
        except sqlite3.Error as e:
            RES['damaged_index'][tag] = {'class': 'generator-error', 'error': str(e)[:100]}
            c.close()
            continue
        c.close()
        RES['damaged_index'][tag] = run_raw(HERMES_SPEC, p)
        log('damage', tag, RES['damaged_index'][tag])

    # B: random byte flips in the FTS index blobs (crash hunting), lowered memory cap for the container
    rng = random.Random(20261123)
    counts, crashes = {}, []
    for i in range(150):
        p, c = copy_real('fuzz-%d' % i)
        bl = [b for b in blobs(c, data_table) if b[1]]
        for _ in range(rng.randint(1, 8)):
            rid, block = rng.choice(bl)
            block = bytearray(block)
            pos = rng.randrange(len(block))
            block[pos] = rng.randrange(256)
            c.execute('UPDATE "%s" SET block=? WHERE id=?' % data_table, (bytes(block), rid))
        c.close()
        r = run_raw(HERMES_SPEC, p, timeout=60, memory=768 * 1024 * 1024)
        counts[r['class']] = counts.get(r['class'], 0) + 1
        if r['class'].startswith(('CRASH', 'timeout', 'child-exit')):
            crashes.append({'case': i, **r})
        p.unlink()
    RES['fuzz'] = {'cases': 150, 'classes': counts, 'abnormal': crashes[:10]}
    log('fuzz', RES['fuzz'])

    # C: whitelist bypass attempts (the archive controls sqlite_master)
    p0, c0 = copy_real('decl')
    real_sql = fts_names(c0)[fts_table]
    c0.close()
    m = re.fullmatch(r"\s*CREATE\s+VIRTUAL\s+TABLE\s+\S+\s+USING\s+fts5\s*\((.*)\)\s*", real_sql, re.I | re.S)
    args = m.group(1) if m else 'content'
    bypass = {
        'module_fts4': 'CREATE VIRTUAL TABLE %s USING fts4(content)' % fts_table,
        'module_rtree': 'CREATE VIRTUAL TABLE %s USING rtree(id, a, b)' % fts_table,
        'extra_option_detail_none': 'CREATE VIRTUAL TABLE %s USING fts5(%s, detail=none)' % (fts_table, args),
        'tokenizer_porter': 'CREATE VIRTUAL TABLE %s USING fts5(content, tokenize=\'porter\')' % fts_table,
        'content_other_table': "CREATE VIRTUAL TABLE %s USING fts5(content, content='sessions', content_rowid='id')" % fts_table,
        'quoted_name': 'CREATE VIRTUAL TABLE "%s" USING fts5(%s)' % (fts_table, args),
        'if_not_exists': 'CREATE VIRTUAL TABLE IF NOT EXISTS %s USING fts5(%s)' % (fts_table, args),
        'schema_qualified': 'CREATE VIRTUAL TABLE main.%s USING fts5(%s)' % (fts_table, args),
        'comment_between_keywords': 'CREATE /*x*/ VIRTUAL TABLE %s USING fts5(%s)' % (fts_table, args),
        'lowercase_keywords_same_args': 'create virtual table %s using FTS5(%s)' % (fts_table, args),
        'nbsp_inside_args': 'CREATE VIRTUAL TABLE %s USING fts5(%s)' % (fts_table, args.replace(',', ', ', 1)),
        'vertical_tab_keywords': 'CREATE\x0bVIRTUAL TABLE %s USING fts5(%s)' % (fts_table, args),
    }
    RES['bypass'] = {}
    for tag, sql in bypass.items():
        p, c = copy_real('byp-' + tag)
        try:
            set_sql(c, fts_table, sql)
        except sqlite3.Error as e:
            RES['bypass'][tag] = {'class': 'generator-error', 'error': str(e)[:100]}
            c.close()
            continue
        c.close()
        RES['bypass'][tag] = run_raw(HERMES_SPEC, p)
        log('bypass', tag, RES['bypass'][tag])
    for tag, sql in {'extra_fts5_table': 'CREATE VIRTUAL TABLE evil USING fts5(x)',
                     'hidden_by_comments_rtree': 'CREATE/**/VIRTUAL/**/TABLE evil USING rtree(id, a, b)'}.items():
        p, c = copy_real('byp-' + tag)
        c.execute(sql)
        c.close()
        RES['bypass'][tag] = run_raw(HERMES_SPEC, p)
        log('bypass', tag, RES['bypass'][tag])


def sections_de(fts_table, msg_cols):
    # D: attacker SQL through a whitelisted external-content name that is a VIEW (CPU bomb), 25 s limits
    view_decl = None
    for cand in sorted(hasqlite_fts_whitelist().get(fts_table, ())):
        if "content='" + fts_table + "_src'" in cand:
            view_decl = cand
            break
    if view_decl:
        p, c = copy_real('view-bomb')
        set_sql(c, fts_table, 'CREATE VIRTUAL TABLE %s USING fts5(%s)' % (fts_table, view_decl))
        cols = re.findall(r"(?:^|,)([a-z_]+)(?=,|$)", view_decl.split(',content=')[0] + ',')
        select = ', '.join(["x AS id"] + ["'a' AS %s" % col for col in cols])
        c.execute('DROP VIEW IF EXISTS %s_src' % fts_table)  # the real Hermes schema already defines this view
        c.execute('CREATE VIEW %s_src AS WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n) '
                  'SELECT %s FROM n' % (fts_table, select))
        c.close()
        RES['view_cpu_bomb'] = {'declaration': view_decl, 'raw': run_raw(HERMES_SPEC, p, timeout=25),
                                'official': run_official([dict(HERMES_SPEC)], {'state.db': p}, timeout=25, tag='bomb')}
        log('view bomb', RES['view_cpu_bomb'])

    # E: size/time: the real schema plus 60,000 synthetic messages (~600 chars), index rebuilt
    p, c = copy_real('large')
    textcols = [col for col in ('content', 'tool_name', 'tool_calls') if col in msg_cols]
    rng2 = random.Random(7)
    words = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', '中文', '測試', 'hermes', 'restore']
    sess = c.execute('SELECT id FROM sessions LIMIT 1').fetchone()
    other = [col for col in msg_cols if col not in textcols and col != 'id']
    t = time.monotonic()
    c.execute('BEGIN')
    for i in range(60000):
        vals = {col: ' '.join(rng2.choice(words) for _ in range(90)) for col in textcols}
        if 'session_id' in msg_cols and sess:
            vals['session_id'] = sess[0]
        if 'role' in msg_cols:
            vals['role'] = 'user'
        if 'timestamp' in msg_cols:
            vals['timestamp'] = 1795300000 + i
        keys = list(vals)
        try:
            c.execute('INSERT INTO messages (%s) VALUES (%s)' % (','.join(keys), ','.join('?' * len(keys))),
                      [vals[k] for k in keys])
        except sqlite3.Error as e:
            RES['large'] = {'generator_error': str(e)[:120], 'missing_required': other[:10]}
            break
    c.execute('COMMIT')
    for name in fts_names(c):
        try:
            c.execute("INSERT INTO %s(%s) VALUES('rebuild')" % (name, name))
        except sqlite3.Error as e:
            RES.setdefault('large_rebuild_errors', []).append(str(e)[:100])
    c.close()
    if 'large' not in RES:
        RES['large'] = {'generator_seconds': round(time.monotonic() - t, 1), 'db_bytes': p.stat().st_size,
                        'messages_added': 60000,
                        'official': run_official([dict(HERMES_SPEC)], {'state.db': p}, tag='large')}
        log('large', RES['large'])


def real_specs_files():
    """The real backup's Hermes databases staged like ha_hermes does (flat names, no -shm), and its specs."""
    files = {}
    for p in sorted(REAL.rglob('*')):
        rel = str(p.relative_to(REAL))
        if p.is_file() and not rel.endswith('-shm'):
            files[rel.replace('/', '.')] = p
    mains = sorted(n for n in files if not n.endswith(('-wal', '-journal')))
    return [dict(HERMES_SPEC) if n == 'state.db' else {'db': n, 'check': 'quick'} for n in mains], files


def hasqlite_fts_whitelist():
    """HERMES_FTS from the real CHILD source (it only exists inside the child program)."""
    scope = {}
    src = hasqlite.CHILD
    start = src.index('HERMES_FTS = {')
    end = src.index('def hermes_fts_ok')
    exec(src[start:end], scope)  # a literal dict in the reviewed source
    return scope['HERMES_FTS']


if __name__ == '__main__':
    t0 = time.monotonic()
    try:
        main()
    except Exception as e:  # keep partial results
        RES['harness_error'] = '%s: %s' % (type(e).__name__, str(e)[:300])
    RES['total_seconds'] = round(time.monotonic() - t0, 1)
    (OUT / ('result-%s.json' % MODE)).write_text(json.dumps(RES, ensure_ascii=False, indent=1))
    shutil.rmtree(WORK, ignore_errors=True)
    log('DONE', RES.get('harness_error', 'ok'), RES['total_seconds'])
