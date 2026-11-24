"""The real hasqlite CHILD set-up lines, run as root with this host's own Python (3.11.2 on .54), for three
versions: b2f63ce (before the fail-closed fix), a9d8643 (fail-closed fix) and this branch (libc fallback).

Python < 3.12 has no os.unshare, so before a9d8643 the child silently kept the host network on such a host, and
with a9d8643 it stops every SQLite read (NO_NETNS). The probe body is the one of
tests/e2e/lab/hasqlite_sandbox_review.py (a loopback listener in the parent's namespace, interfaces, ids,
rlimits). No database, archive or secret is used."""
import ast
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

from arm54_final_runtime import ROOT, private_dir, report

from woowbackup import hasqlite  # noqa: E402

VARIANT_DIR = ROOT / 'source/tests/e2e/lab/evidence/arm54-final-20261123/hasqlite-variants'
VARIANTS = {'b2f63ce-before-fix': VARIANT_DIR / 'hasqlite-b2f63ce.py',
            'a9d8643-fail-closed': VARIANT_DIR / 'hasqlite-a9d8643.py',
            'branch-libc-fallback': ROOT / 'source/backup-engine/woowbackup/hasqlite.py'}

PROBE_BODY = r'''
res = {}
res["ids"] = [os.getuid(), os.geteuid(), os.getgid(), os.getegid(), sorted(os.getgroups())]
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("127.0.0.1", PORT))
    s.close()
    res["loopback_listener"] = "CONNECTED"
except OSError as e:
    res["loopback_listener"] = "blocked errno=%s" % e.errno
try:
    res["interfaces"] = sorted(n for _, n in socket.if_nameindex())
except OSError as e:
    res["interfaces"] = "errno=%s" % e.errno
try:
    res["root_listing"] = sorted(os.listdir("/"))
except OSError as e:
    res["root_listing"] = "errno=%s" % e.errno
print(json.dumps(res))
'''


def child_of(path):
    tree = ast.parse(Path(path).read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == 'CHILD' for t in node.targets):
            return node.value.value
    raise AssertionError('child-not-found')


def listener():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 0))
    s.listen(8)

    def accept():
        while True:
            try:
                conn, _ = s.accept()
                conn.close()
            except OSError:
                return
    threading.Thread(target=accept, daemon=True).start()
    return s, s.getsockname()[1]


def probe(name, path):
    child = child_of(path)
    prefix = child[:child.index('NAME = re.compile')]
    assert prefix.strip().startswith('import json, os, re, resource, sqlite3, sys'), 'prefix-changed'
    sock, port = listener()
    code = 'import socket\n' + prefix + PROBE_BODY.replace('PORT', str(port))
    work = private_dir('work', 'probe-' + name)
    uid, gid = hasqlite.nobody()
    os.lchown(work, uid, gid)
    argv = [sys.executable, '-I', '-S', '-c', code, str(uid), str(gid), str(64 * 1024 * 1024), '60',
            str(hasqlite.MEMORY)]
    p = subprocess.run(argv, cwd=work, input=b'{"dbs": [], "queries": {}}', capture_output=True, timeout=90,
                       env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}, close_fds=True,
                       start_new_session=True)
    sock.close()
    out = {'returncode': p.returncode, 'child_prefix_sha256': hashlib.sha256(prefix.encode()).hexdigest(),
           'source_sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest()}
    try:
        out.update(json.loads(p.stdout.decode().strip().splitlines()[-1]))
    except (ValueError, IndexError):
        out['stdout_lines'] = len(p.stdout.splitlines())
    return out


result = {'status': 'failed', 'python': sys.version.split()[0], 'has_os_unshare': hasattr(os, 'unshare'),
          'euid': os.geteuid(), 'commercial_acceptance': 'not-complete', 'checks': {}}
started = time.monotonic()
try:
    for name, path in VARIANTS.items():
        result[name] = probe(name, path)
    before, closed, fixed = (result[n] for n in VARIANTS)
    checks = result['checks']
    checks['before_fix_child_kept_host_network'] = before['returncode'] == 0 and before.get('loopback_listener') == 'CONNECTED'
    checks['fail_closed_child_refuses_on_this_python'] = closed['returncode'] == hasqlite.NO_NETNS
    checks['libc_fallback_child_isolated'] = (fixed['returncode'] == 0
                                              and str(fixed.get('loopback_listener', '')).startswith('blocked')
                                              # a fresh namespace here: lo plus the unconfigured fallback tunnels
                                              and isinstance(fixed.get('interfaces'), list)
                                              and set(fixed['interfaces']) <= {'lo', 'sit0', 'ip6tnl0'}
                                              and fixed.get('ids', [0])[0] != 0)
    result['status'] = 'passed' if all(checks.values()) else 'failed'
except Exception as error:  # noqa: BLE001
    result['error_code'] = type(error).__name__
    result['failed_check'] = str(error)[:80] if isinstance(error, AssertionError) else None
finally:
    import shutil
    shutil.rmtree(ROOT / 'work', ignore_errors=True)
    result['elapsed_seconds'] = round(time.monotonic() - started, 1)
    report(ROOT / 'sandbox-probe-result.json', result)
    print(json.dumps(result, sort_keys=True))
    sys.exit(0 if result['status'] == 'passed' else 1)
