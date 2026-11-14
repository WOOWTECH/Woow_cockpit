#!/usr/bin/env python3
"""Host-directory (catalog `data_dirs`) end-to-end scenarios for backup & restore in the lab devices.

Fixture: catalog-examples/woowbk-dirs (PostgreSQL 16 whose data directory is a host directory, cold backup; an app
that writes a host directory as container uid 33: nested directories, a symlink, hard links, user xattrs, SQLite in
WAL mode). Every engine call is made the way the Cockpit page makes it (cli_e2e.py: the installed helper as root,
request JSON on stdin, one JSON object back; downloads/uploads through the device's real cockpit-bridge).

    python3 -I tests/e2e/lab/dirs_e2e.py prep      # preconditions: fixture on dev-a, catalog on both, ranges, engine
    python3 -I tests/e2e/lab/dirs_e2e.py selftest  # the driver's own tools (listings, kill tree, state injection,
                                                   # hostile tars vs the installed nested checks, the D3 drop-in);
                                                   # no engine feature needed
    python3 -I tests/e2e/lab/dirs_e2e.py d1        # dev-a: backup -> mutate everything -> in-place restore, all equal
    python3 -I tests/e2e/lab/dirs_e2e.py d2        # dev-a -> dev-b (other uid AND subuid range): fresh restore
    python3 -I tests/e2e/lab/dirs_e2e.py d3        # restore fails after the swap (database start refused by a marker
                                                   # only the backup carries) -> automatic rollback, original data
    python3 -I tests/e2e/lab/dirs_e2e.py d4        # SIGKILL during extraction / between the swap renames / after the
                                                   # swap -> recovery reaches a safe state; safety backup restores
    python3 -I tests/e2e/lab/dirs_e2e.py d5        # hostile dir tars (escape symlink, absolute, '..', ...) refused
                                                   # before any change; undeclared paths never written
    python3 -I tests/e2e/lab/dirs_e2e.py d6        # dev-b fresh restore onto an existing non-empty directory: refused
    python3 -I tests/e2e/lab/dirs_e2e.py d7        # dev-a: a tmpfs below the data dir, the data dir bind-mounted onto
                                                   # itself, other containers mounting it read-only / read-write:
                                                   # backups and restore preflights refuse what they must, nothing stops
    python3 -I tests/e2e/lab/dirs_e2e.py leaks     # app secrets / age keys never in records, logs, index, journal
    python3 -I tests/e2e/lab/dirs_e2e.py all       # prep d1 d3 d4 d5 d6 d7 d2 leaks

Prerequisites (prep checks them): both devices up, the engine with host-directory support installed on both
(deploy-src.sh a|b), the trusted catalog entry on both (dirs-catalog.sh a|b install), woowbk-dirs deployed on dev-a
(deploy-dirs.sh a), dev-b with its own subordinate id range (subids.sh b 10500:55000 --reset-storage), dev-a's device
key and emergency kit (cli_e2e.py s1 writes ~/.woowbk-lab/secrets/dev-a-kit.txt).

Evidence: ~/.woowbk-lab/evidence/dirs/<time>-<scenario>/ (driver.log, result.json, job records). Key material never
leaves the devices except the kit secret, which only travels in the stdin field `key`. Hostile archives are built
inside dev-a with its own device key (only ciphertext reaches the host). Only labpodman is used.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cli_e2e as e2e  # noqa: E402  (helper/bridge/evidence code shared with the woowbk-demo runner)
from cli_e2e import (DOWNLOADS, KIT_FILE, LAB, LP, SECRET_RE, Failed, dev_name, helper, kit_secret, ok,  # noqa: E402
                     owner, phase_states, redact, request_id, sh, wait_job)
from hardening import (backup_ids, canaries, file_sha256, no_job_keys, orphans, private_dir, py,  # noqa: E402
                       staging_empty, write_private_stream)

LAB_DIR = Path(__file__).resolve().parent
REPO = LAB_DIR.parents[2]
FIXTURE = REPO / 'catalog-examples' / 'woowbk-dirs'
TREELIST_SRC = (FIXTURE / 'app' / 'treelist.py').read_text(encoding='utf-8')
DIRS_EVIDENCE = LAB / 'evidence' / 'dirs'
STATE_FILE = DIRS_EVIDENCE / 'state.json'
WORK = LAB / 'run' / 'dirs'

APP = 'woowbk-dirs'
APP_URL = 'http://127.0.0.1:18091'
DEMO_URL = 'http://127.0.0.1:18090'
HOME = '/home/appowner'
PG_DIR, DATA_DIR = '.local/share/woowbk-dirs/postgres', 'woowbk-dirs/data'
DIRS = (PG_DIR, DATA_DIR)
DIR_LABELS = tuple(d['label'] for d in json.loads((FIXTURE / 'catalog.json').read_text(encoding='utf-8'))['data_dirs'])
PARENTS = ('.local/share/woowbk-dirs', 'woowbk-dirs')
DB_UNIT, APP_UNIT = 'woowbk-dirs-db.service', 'woowbk-dirs-app.service'
SEED = '/opt/woowbk-dirs/tools/seed.py'
CHECK = '/opt/woowbk-dirs/tools/check.py'
COMPARE = ('items', 'events', 'db_digest', 'db_meta', 'tree', 'tree_digest', 'sqlite', 'title', 'signatures_valid')
SECRET_NAMES = ('woowbk-dirs-db-password', 'woowbk-dirs-role-password', 'woowbk-dirs-app-key')
REFUSED_CODES = ('incompatible', 'corrupt-archive')
# The owner's symlink that leaves the data dir (tools/seed.py, tools/check.py OUTSIDE_LINK): a backup keeps it as a
# link (an engine that followed it would store the env file's bytes), a restore writes it back verbatim.
OUTSIDE_LINK = ('共享/設定連結', '../../../.config/woowbk-dirs/app.env')


# ------------------------------------------------------------------ evidence and state

class Evidence(e2e.Evidence):
    def __init__(self, scenario):  # noqa: D107 - same as cli_e2e.Evidence, other directory
        stamp = time.strftime('%Y%m%dT%H%M%S')
        self.dir = DIRS_EVIDENCE / f'{stamp}-{scenario}'
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.dir / 'driver.log'
        self.checks = []
        self.timings = {}
        self.t0 = time.monotonic()


def load_state():
    try:
        return json.loads(STATE_FILE.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}


def save_state(**fields):
    state = load_state()
    state.update(fields)
    DIRS_EVIDENCE.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(redact(state), ensure_ascii=False, indent=1) + '\n', encoding='utf-8')


def save_job(ev, name, job, log):
    ev.save(name, {'job': job, 'log': log})


def job_text(job, log):
    """Everything a job says (error, result, log) as one string, for "is it reported" checks."""
    return json.dumps({'error': job.get('error'), 'result': job.get('result')}, ensure_ascii=False) + '\n' + '\n'.join(log)


# ------------------------------------------------------------------ the app (inside the device, loopback)

def app_request(dev, method, path, body=None, timeout=30, url=APP_URL):
    data_args = f'-X {method} -H "Content-Type: application/json" --data-binary @-' if body is not None else f'-X {method}'
    proc = sh(dev, f'curl -sS --max-time {timeout} -o - -w "\\n%{{http_code}}" {data_args} "{url}{path}"',
              input=body, check=False, timeout=timeout + 30)
    text, _, status = proc.stdout.decode('utf-8', 'replace').rpartition('\n')
    return int(status or 0), text


def app_json(dev, path, url=APP_URL):
    status, text = app_request(dev, 'GET', path, url=url)
    if status != 200:
        raise Failed(f'GET {path} on dev-{dev} -> HTTP {status} {text[:200]}')
    return json.loads(text)


def summary(dev):
    return app_json(dev, '/api/summary')


def snapshot(dev):
    """Everything the app can show: summary, full tree listing, database rows + meta, SQLite rows."""
    db = app_json(dev, '/api/db')
    return {'summary': summary(dev), 'tree': app_json(dev, '/api/tree')['entries'],
            'db': {'items': [[i['id'], i['name'], i['sha256'], i['signature']] for i in db['items']],
                   'events': db['events'], 'meta': db['meta']},
            'sqlite': app_json(dev, '/api/sqlite')['docs']}


def compare(a, b):
    return {k: (a.get(k), b.get(k)) for k in COMPARE if a.get(k) != b.get(k)}


def snapshot_diff(a, b):
    """Which parts of two snapshots differ (summary keys, tree, db, sqlite)."""
    diff = {k: 'differs' for k in ('tree', 'db', 'sqlite') if a.get(k) != b.get(k)}
    diff.update({f'summary.{k}': v for k, v in compare(a['summary'], b['summary']).items()})
    if a.get('tree') != b.get('tree'):
        left = {e['path']: e for e in a.get('tree') or []}
        right = {e['path']: e for e in b.get('tree') or []}
        diff['tree_paths'] = sorted(p for p in set(left) | set(right) if left.get(p) != right.get(p))[:30]
    return diff


def wait_healthy(dev, timeout=240):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if app_request(dev, 'GET', '/healthz', timeout=5)[0] == 200:
            return True
        time.sleep(2)
    return False


def post_item(dev, name, body):
    status, text = app_request(dev, 'POST', '/api/items',
                               json.dumps({'name': name, 'body': body}, ensure_ascii=False).encode('utf-8'))
    return status, (json.loads(text) if status == 201 else text[:300])


def demo_summary(dev):
    status, text = app_request(dev, 'GET', '/api/summary', url=DEMO_URL)
    return json.loads(text) if status == 200 else None


class HealthMonitor(e2e.HealthMonitor):
    """cli_e2e's 0.25 s /healthz sampler, pointed at this app."""
    CODE = e2e.HealthMonitor.CODE.replace('127.0.0.1:18090', '127.0.0.1:18091')


def seed(dev, *args, timeout=900):
    proc = owner(dev, 'python3', SEED, *map(str, args), timeout=timeout)
    return json.loads(proc.stdout)


def psql(dev, sql, database='dirs'):
    """SQL on stdin as the superuser `dirs` over the database container's local socket."""
    proc = owner(dev, 'podman', 'exec', '-i', 'woowbk-dirs-db', 'psql', '-X', '-w', '-q', '-At', '-v', 'ON_ERROR_STOP=1',
                 '-U', 'dirs', '-d', database, input=sql.encode('utf-8'), timeout=120)
    return proc.stdout.decode('utf-8', 'replace').strip()


def engine_app(dev, ev):
    status = ok(dev, 'status', ev=ev)
    return status, next((a for a in status['apps'] if a['id'] == APP), None)


# ------------------------------------------------------------------ host directories (owner side)

# Runs as the owner inside the user namespace (`podman unshare python3 -I - <path>...`): treelist reports of the
# given paths (null when missing), so ids are what the containers see; works while the app is stopped or masked.
LIST_PROGRAM = f'SRC = {TREELIST_SRC!r}\n' + r'''
import json, os, sys
ns = {'__name__': 'woowbk_treelist'}
exec(compile(SRC, 'treelist.py', 'exec'), ns)
out = {}
for path in sys.argv[1:]:
    if not os.path.lexists(path):
        out[path] = None
        continue
    try:
        out[path] = ns['report'](path)
    except OSError as error:
        out[path] = {'error': '%s: %s' % (type(error).__name__, error)}
print(json.dumps(out, ensure_ascii=False))
'''


def listings(dev, *rels):
    """{rel: treelist report | None} of paths relative to the owner's home, read inside the user namespace."""
    paths = [f'{HOME}/{rel}' for rel in rels]
    proc = owner(dev, 'podman', 'unshare', 'python3', '-I', '-', *paths, input=LIST_PROGRAM.encode(), timeout=300)
    report = json.loads(proc.stdout)
    return {rel: report[path] for rel, path in zip(rels, paths)}


def entries_of(dev, rel):
    report = listings(dev, rel)[rel]
    if not report or 'entries' not in report:
        raise Failed(f'dev-{dev}: cannot list ~/{rel}: {report}')
    return report['entries']


# Runs as the owner (no user namespace): host view of paths and the siblings of every declared directory.
STATE_PROGRAM = r'''
import json, os, stat, sys
home, dirs, extra = sys.argv[1], sys.argv[2].split(','), [p for p in sys.argv[3].split(',') if p]
def info(path):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    kind = 'dir' if stat.S_ISDIR(st.st_mode) else 'symlink' if stat.S_ISLNK(st.st_mode) else 'other'
    return {'type': kind, 'uid': st.st_uid, 'gid': st.st_gid, 'mode': '%04o' % stat.S_IMODE(st.st_mode)}
out = {'paths': {}, 'siblings': {}}
for rel in dirs + extra:
    out['paths'][rel] = info(os.path.join(home, rel))
for rel in dirs:
    parent, base = os.path.split(os.path.join(home, rel))
    try:
        names = os.listdir(parent)
    except OSError:
        names = []
    out['siblings'][rel] = sorted(n for n in names if n.startswith(base + '.woowbk-'))
print(json.dumps(out))
'''


def dir_state(dev, extra=PARENTS):
    """Host view (owner, outside the namespace) of the declared directories and `extra` paths + their siblings."""
    proc = owner(dev, 'python3', '-I', '-c', STATE_PROGRAM, HOME, ','.join(DIRS), ','.join(extra))
    return json.loads(proc.stdout)


def leftover_siblings(dev):
    return {rel: names for rel, names in dir_state(dev)['siblings'].items() if names}


def id_maps(dev):
    """(uid ranges, gid ranges) of the owner's namespace: [(inside, outside, count)]."""
    out = {}
    for kind in ('uid', 'gid'):
        text = owner(dev, 'podman', 'unshare', 'cat', f'/proc/self/{kind}_map').stdout.decode()
        out[kind] = [tuple(int(x) for x in line.split()) for line in text.splitlines() if line.strip()]
    return out['uid'], out['gid']


def host_id(ranges, container_id):
    for inside, outside, count in ranges:
        if inside <= container_id < inside + count:
            return outside + container_id - inside
    return None


def subid_range(dev):
    """{'subuid': 'START:COUNT', 'subgid': ...} of appowner on the device (one line each in the lab)."""
    out = {}
    for name in ('subuid', 'subgid'):
        lines = [line.split(':') for line in sh(dev, f'cat /etc/{name}').stdout.decode().split() if line]
        out[name] = ':'.join(lines[0][1:]) if len(lines) == 1 and lines[0][0] == 'appowner' else None
    return out


def ownership_checks(ev, dev, tag, entries_data, pg_entries):
    """Container view (data dir and PostgreSQL directory) and host view (subuid mapping) of the restored dirs."""
    index = {e['path']: e for e in entries_data}
    ev.check(f'{tag}: data dir root is container root 0755, www/ uid 33 0750, everything below www/ uid/gid 33',
             (index['.']['uid'], index['.']['gid'], index['.']['mode']) == (0, 0, '0755')
             and (index['www']['uid'], index['www']['mode']) == (33, '0750')
             and all((e['uid'], e['gid']) == (33, 33) for e in entries_data if e['path'].startswith('www/')),
             {p: (e['uid'], e['gid'], e['mode']) for p, e in list(index.items())[:6]})
    pg_root = pg_entries[0]
    ev.check(f'{tag}: PostgreSQL directory is container uid/gid 70, root 0700, every entry uid/gid 70',
             (pg_root['path'], pg_root['uid'], pg_root['gid'], pg_root['mode']) == ('.', 70, 70, '0700')
             and all((e['uid'], e['gid']) == (70, 70) for e in pg_entries), (pg_root, len(pg_entries)))
    uids, gids = id_maps(dev)
    state = dir_state(dev, extra=(f'{DATA_DIR}/www',))
    want = {DATA_DIR: (host_id(uids, 0), host_id(gids, 0)), f'{DATA_DIR}/www': (host_id(uids, 33), host_id(gids, 33)),
            PG_DIR: (host_id(uids, 70), host_id(gids, 70))}
    got = {rel: ((state['paths'].get(rel) or {}).get('uid'), (state['paths'].get(rel) or {}).get('gid')) for rel in want}
    ev.check(f'{tag}: host view follows this device\'s namespace (container 0/33/70 -> {want})', got == want,
             {'got': got, 'uid_map': uids})
    return want


# ------------------------------------------------------------------ deployment footprint and fresh targets

FOOTPRINT = r'''
cd "$HOME"
ls .config/containers/systemd 2>/dev/null | grep '^woowbk-dirs' | sed 's/^/quadlet:/'
test -e .config/woowbk-dirs && echo config:.config/woowbk-dirs
for p in .local/share/woowbk-dirs woowbk-dirs; do if [ -e "$p" ] || [ -L "$p" ]; then echo "dir:$p"; fi; done
podman secret ls --format '{{.Name}}' | grep '^woowbk-dirs' | sed 's/^/secret:/'
podman ps -a --format '{{.Names}}' | grep '^woowbk-dirs' | sed 's/^/container:/'
podman network exists woowbk-dirs && echo network:woowbk-dirs
podman image exists localhost/woowbk-dirs-app:1 && echo image:localhost/woowbk-dirs-app:1
ls -A .config/systemd/user 2>/dev/null | grep woowbk-dirs | sed 's/^/systemd:/'
true
'''


def footprint(dev):
    return owner(dev, 'sh', '-c', FOOTPRINT).stdout.decode().split()


# {relative path: sha256} of a fixture copy (__pycache__ excluded): this working tree's or a device's /opt/woowbk-dirs.
FIXTURE_SUMS = r'''
import hashlib, json, os, sys
root, out = sys.argv[1], {}
for base, dirs, files in os.walk(root):
    dirs[:] = sorted(d for d in dirs if d != '__pycache__')
    for name in files:
        path = os.path.join(base, name)
        with open(path, 'rb') as handle:
            out[os.path.relpath(path, root)] = hashlib.sha256(handle.read()).hexdigest()
print(json.dumps(out, sort_keys=True))
'''


def fixture_sums_local():
    proc = subprocess.run([sys.executable, '-I', '-c', FIXTURE_SUMS, str(FIXTURE)], capture_output=True, check=True)
    return json.loads(proc.stdout)


def ensure_fixture(ev, dev='a'):
    """woowbk-dirs on `dev` deployed from THIS working tree's fixture and healthy. deploy-dirs.sh is idempotent:
    with --items 0 it only brings a running deployment up to date (copy, image, Quadlet files, missing items)."""
    installed = py(dev, FIXTURE_SUMS, '/opt/woowbk-dirs', check=False)
    current = installed.returncode == 0 and json.loads(installed.stdout or b'{}') == fixture_sums_local()
    healthy = wait_healthy(dev, 10)
    if current and healthy:
        return True
    items = '0' if healthy else '6'
    ev.log(f'woowbk-dirs on dev-{dev}: fixture {"current" if current else "differs from the working tree"}, '
           f'{"healthy" if healthy else "not healthy"}: running deploy-dirs.sh {dev} --items {items}')
    proc = subprocess.run([str(LAB_DIR / 'deploy-dirs.sh'), dev, '--items', items], capture_output=True, timeout=1800)
    ev.log(f'deploy-dirs.sh {dev}: rc={proc.returncode} {redact(proc.stderr.decode("utf-8", "replace")[-400:])}')
    return proc.returncode == 0


def teardown(dev, ev):
    """tests/e2e/lab/teardown-dirs.sh: owner-side removal of the whole deployment (a fresh restore target)."""
    proc = subprocess.run([str(LAB_DIR / 'teardown-dirs.sh'), dev], capture_output=True, timeout=900)
    out = proc.stdout.decode('utf-8', 'replace')
    left = out.split('left after teardown:', 1)[-1].replace('(end)', '').split()
    ev.log(f'teardown-dirs.sh {dev}: rc={proc.returncode} left={left}')
    if proc.returncode != 0 or left:
        raise Failed(f'teardown-dirs.sh {dev} failed rc={proc.returncode} left={left} '
                     f'{redact(proc.stderr.decode("utf-8", "replace")[-300:])}')


def delete_backup(dev, backup_id, ev):
    if backup_id in backup_ids(dev, ev):
        ok(dev, 'delete', {'backup_id': backup_id}, ev=ev)


# ------------------------------------------------------------------ backups

def backup(dev, ev, note, *, images=False, label='backup'):
    start = ok(dev, 'backup-start', {'apps': [APP], 'include_images': images, 'note': note,
                                     'request_id': request_id()}, ev=ev)
    job, log = wait_job(dev, start['job_id'], ev=ev, timeout=1800, label=label)
    save_job(ev, label, job, log)
    ev.require(f'{label}: backup job succeeded', job['state'] == 'succeeded', job.get('error'))
    return job, log


def restore(dev, ev, backup_id, *, label='restore', key=None, timeout=1800):
    request = {'backup_id': backup_id, 'apps': [APP], 'request_id': request_id(), 'confirm': True}
    if key:
        request['key'] = key
    start = ok(dev, 'restore-start', request, ev=ev)
    job, log = wait_job(dev, start['job_id'], ev=ev, timeout=timeout, label=label)
    save_job(ev, label, job, log)
    return job, log


def manifest_dirs(manifest_app):
    """Paths of the manifest summary's data_dirs (the page lists them; CONTRACT ManifestSummary)."""
    return [d.get('path') for d in manifest_app.get('data_dirs') or [] if isinstance(d, dict)]


def source_backup(ev, *, fresh=False):
    """A dev-a backup WITH images and its bridge download (reused while it is intact on both sides)."""
    state = load_state().get('source') or {}
    local = Path(state.get('file') or '/nonexistent')
    if (not fresh and state and local.is_file() and file_sha256(local) == state.get('sha256')
            and state.get('backup_id') in backup_ids('a', ev)):
        ev.log(f'reusing source backup {state["backup_id"]} ({local})')
        return state
    ev.require('dev-a app healthy before the source backup', wait_healthy('a', 120))
    snap = snapshot('a')
    job, _log = backup('a', ev, 'D2 跨設備來源（含映像）', images=True, label='backup[source]')
    backup_id = job['result']['backup_id']
    inspected = ok('a', 'inspect', {'backup_id': backup_id}, ev=ev)
    ev.save('source-inspect', inspected)
    mapp = inspected['manifest']['apps'][0]
    ev.check('source backup: manifest summary lists both host directories and every image as included',
             manifest_dirs(mapp) == list(DIRS) and mapp['images'] and all(i['included'] for i in mapp['images']),
             {'data_dirs': mapp.get('data_dirs'), 'images': mapp.get('images')})
    ev.check('source backup: the verify snapshot equals the state before the backup (stable across the restart)',
             compare((mapp.get('verify_snapshot') or {}).get('summary') or {}, snap['summary']) == {},
             mapp.get('verify_snapshot'))
    info = ok('a', 'download-info', {'backup_id': backup_id}, ev=ev)
    meta = next(b for b in ok('a', 'list', ev=ev)['backups'] if b['id'] == backup_id)
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    os.chmod(DOWNLOADS, 0o700)
    target = DOWNLOADS / f'dirs-{info["filename"]}'
    got = e2e.bridge_download('a', info['path'], target, ev=ev)
    ev.require('source download: size and sha256 equal the index on dev-a',
               got['bytes'] == info['size'] == meta['size'] and got['sha256'] == meta['sha256'], got)
    if state.get('file') and state['file'] != str(target):
        Path(state['file']).unlink(missing_ok=True)  # keep one dirs download on the host
    state = {'backup_id': backup_id, 'file': str(target), 'filename': info['filename'], 'sha256': got['sha256'],
             'size': got['bytes'], 'snapshot': snap, 'key_id': meta['key_id']}
    save_state(source=state)
    ev.timings['source_backup_bytes'] = got['bytes']
    return state


def ensure_uploaded(dev, source, ev):
    """The source backup on `dev` as an uploaded backup (re-uploaded when missing or different)."""
    listed = {b['id']: b for b in ok(dev, 'list', ev=ev)['backups']}
    current = listed.get(source['backup_id'])
    if current and current.get('sha256') == source['sha256']:
        ev.log(f'dev-{dev} already holds {source["backup_id"]}')
        return current
    if current:
        ok(dev, 'delete', {'backup_id': source['backup_id']}, ev=ev)
    _begin, (_rc, reply) = e2e.upload_file(dev, source['file'], ev=ev, filename=source.get('filename'))
    ev.require(f'upload of the source backup to dev-{dev} accepted', reply.get('ok'), reply.get('error'))
    return reply['backup']


# ------------------------------------------------------------------ scenario: prep

def scenario_prep(ev):
    avail = e2e_mem_available()
    ev.require('host MemAvailable >= 1200 MB', avail >= 1200, f'{avail} MB')
    for dev in ('a', 'b'):
        state = subprocess.run([LP, 'container', 'inspect', '--format', '{{.State.Status}}', dev_name(dev)],
                               capture_output=True, text=True).stdout.strip()
        ev.require(f'{dev_name(dev)} is running', state == 'running', state or 'absent')
    # 1. the fixture on dev-a, deployed from this working tree (deploy-dirs.sh a when missing, stale or unhealthy)
    ev.check('woowbk-dirs on dev-a is deployed from this working tree\'s fixture', ensure_fixture(ev, 'a'))
    ev.require('woowbk-dirs healthy on dev-a', wait_healthy('a', 120))
    check = owner('a', 'python3', CHECK, check=False, timeout=600)
    report = json.loads(check.stdout.decode().strip().splitlines()[-1])
    ev.save('prep-check', report)
    ev.check('tools/check.py (read-only) passes on dev-a', check.returncode == 0 and report['ok'], report['failures'])
    # 2. the trusted catalog entry on both devices
    want = hashlib.sha256((FIXTURE / 'catalog.json').read_bytes()).hexdigest()
    for dev in ('a', 'b'):
        got = sh(dev, 'sha256sum /etc/woowtech-cockpit/backup/apps/woowbk-dirs.json 2>/dev/null', check=False)
        if got.stdout.decode().split()[:1] != [want]:
            ev.log(f'installing the woowbk-dirs catalog entry on dev-{dev} (dirs-catalog.sh {dev} install)')
            proc = subprocess.run([str(LAB_DIR / 'dirs-catalog.sh'), dev, 'install'], capture_output=True, timeout=300)
            ev.check(f'dirs-catalog.sh {dev} install', proc.returncode == 0,
                     proc.stderr.decode('utf-8', 'replace')[-300:])
    # 3. the engine loads it (an engine without data_dirs reports the entry as a problem instead)
    for dev in ('a', 'b'):
        status, app = engine_app(dev, ev)
        problems = [w for w in status.get('warnings', []) if APP in json.dumps(w, ensure_ascii=False)]
        ev.check(f'dev-{dev}: engine {status.get("version")} loads woowbk-dirs (host-directory support)',
                 app is not None and not problems, problems or app)
        ev.check(f'dev-{dev}: no active job', status.get('active_job') is None, status.get('active_job'))
        if dev == 'a' and app:
            ev.check('dev-a: woowbk-dirs deployed and running, no problems',
                     app['deployed'] and app['state'] == 'running' and not app['problems'], app)
        if dev == 'b' and app:
            ev.log(f'dev-b woowbk-dirs state: {app["state"]} (d2/d6 tear it down first)')
    # 4. different subordinate id ranges and owner uids
    ranges = {dev: subid_range(dev) for dev in ('a', 'b')}
    ev.save('prep-subids', ranges)
    ev.check('dev-a and dev-b give appowner different subuid AND subgid ranges (subids.sh b 10500:55000 --reset-storage)',
             all(ranges[d][k] for d in 'ab' for k in ('subuid', 'subgid'))
             and ranges['a']['subuid'].split(':')[0] != ranges['b']['subuid'].split(':')[0]
             and ranges['a']['subgid'].split(':')[0] != ranges['b']['subgid'].split(':')[0], ranges)
    for dev in ('a', 'b'):
        uids, gids = id_maps(dev)
        ev.check(f'dev-{dev}: the owner namespace maps container ids 0, 33, 70 and 55000',
                 all(host_id(r, i) is not None for r in (uids, gids) for i in (0, 33, 70, 55000)), {'uid': uids, 'gid': gids})
    uid_a, uid_b = (int(sh(d, 'id -u appowner').stdout) for d in ('a', 'b'))
    ev.check('appowner uid differs (dev-a 1001, dev-b 1007)', (uid_a, uid_b) == (1001, 1007), (uid_a, uid_b))
    # 5. keys for the cross-device scenarios
    status = ok('a', 'status', ev=ev)
    ev.check('dev-a has a device key', bool(status.get('key')), status.get('key'))
    ev.check(f'emergency kit of dev-a stored at {KIT_FILE} (cli_e2e.py s1)', KIT_FILE.is_file()
             and len(SECRET_RE.findall(KIT_FILE.read_text(encoding='utf-8'))) == 1)
    ev.check('no .woowbk-new-/.woowbk-old- siblings next to the host directories on dev-a', not leftover_siblings('a'),
             leftover_siblings('a'))
    return {'subids': ranges}


def e2e_mem_available():
    with open('/proc/meminfo', encoding='ascii') as handle:
        for line in handle:
            if line.startswith('MemAvailable:'):
                return int(line.split()[1]) // 1024
    return 0


# ------------------------------------------------------------------ scenario: d1 in-place

def scenario_d1(ev):
    dev = 'a'
    _status, app = engine_app(dev, ev)
    ev.require('D1 woowbk-dirs deployed and running on dev-a', app and app['state'] == 'running', app)
    ev.require('D1 no leftover siblings before the scenario', not leftover_siblings(dev), leftover_siblings(dev))
    # An earlier run that stopped after its mutation leaves this database and role behind; they must not be in the backup.
    psql(dev, 'DROP DATABASE IF EXISTS woowbk_d1_extra;')
    psql(dev, 'DROP ROLE IF EXISTS woowbk_d1_extra;')
    seeded = seed(dev, '--items', 3, '--seed', 1113, '--owner-note', 'D1 備份前的擁有者說明')
    ev.log(f'seeded: +{len(seeded["items_added"])} items')
    before = snapshot(dev)
    data_before = entries_of(dev, DATA_DIR)
    ev.check('D1 the owner namespace view of the data dir equals the app\'s own listing', data_before == before['tree'])
    demo_before = demo_summary(dev)
    ev.save('d1-before', {'snapshot': before})

    monitor = HealthMonitor(dev, 900)
    t0 = time.monotonic()
    job, log = backup(dev, ev, 'D1 主機資料夾原位還原', label='backup[d1]')
    health = monitor.stop()
    result = job['result']
    backup_id = result['backup_id']
    ev.timings.update(d1_backup_wall_s=round(time.monotonic() - t0, 1), d1_backup_bytes=result['size'],
                      d1_backup_downtime_reported_s=result['downtime_seconds'],
                      d1_backup_healthz_longest_unhealthy_s=health['longest_unhealthy_s'])
    ev.check('D1 backup: writers (database included) were stopped: downtime > 0 and /healthz was down meanwhile',
             result['downtime_seconds'] > 0 and health['unhealthy_samples'] > 0, {'downtime': result['downtime_seconds'],
                                                                                   'health': health})
    text = '\n'.join(log)
    ev.check('D1 backup job log names both host directories (path or catalog label)',
             all(rel in text or label in text for rel, label in zip(DIRS, DIR_LABELS)),
             [line for line in log if 'woowbk-dirs' in line or '主機資料夾' in line][:8])
    ev.check(f'D1 backup job log notes the symlink that leaves the data dir ({OUTSIDE_LINK[0]}: kept as a link)',
             any('符號連結' in line and DATA_DIR in line for line in log), [line for line in log if '符號連結' in line][:3])
    ev.check('D1 app healthy again and data unchanged by the backup',
             wait_healthy(dev, 120) and compare(summary(dev), before['summary']) == {})

    inspected = ok(dev, 'inspect', {'backup_id': backup_id}, ev=ev)
    ev.save('d1-inspect', inspected)
    mapp, papp = inspected['manifest']['apps'][0], inspected['preflight']['apps'][0]
    ev.check('D1 inspect: in-place, restorable, preflight ok', inspected['preflight']['ok'] and papp['restorable']
             and papp['mode'] == 'inplace', papp)
    ev.check('D1 manifest summary: data_dirs lists both paths, no pg_dump databases, no volumes',
             manifest_dirs(mapp) == list(DIRS) and mapp['postgres'] == [] and mapp['volumes'] == [],
             {k: mapp.get(k) for k in ('data_dirs', 'postgres', 'volumes')})
    ev.check('D1 verify snapshot in the manifest equals the state before the backup (all 9 keys)',
             compare((mapp.get('verify_snapshot') or {}).get('summary') or {}, before['summary']) == {},
             mapp.get('verify_snapshot'))

    # Mutate every kind of state: rows in both databases, roles, an extra database, files of uid 33 (modes, xattr,
    # symlink, a stray file), files of the owner (container root), SQLite, the env file.
    mutated_seed = seed(dev, '--items', 2, '--delete', 1, '--title', 'D1 已變更的標題', '--owner-note', 'D1 備份後改寫')
    ev.check('D1 mutation rewrote the env file (app restarted)', mutated_seed['env_changed'] is True)
    psql(dev, 'CREATE ROLE woowbk_d1_extra NOLOGIN;')
    psql(dev, 'CREATE DATABASE woowbk_d1_extra OWNER woowbk_d1_extra;')
    owner(dev, 'podman', 'exec', 'woowbk-dirs-app', 'python3', '-c',
          'import glob, os\n'
          'docs = sorted(glob.glob("/srv/data/www/docs/*/*/*.txt"))\n'
          'os.chmod(docs[0], 0o600)\n'
          'os.setxattr(docs[-1], "user.woowbk.item", b"mutated")\n'
          'open("/srv/data/www/stray.txt", "w").write("stray\\n")\n'
          'os.unlink("/srv/data/www/latest"); os.symlink("archive", "/srv/data/www/latest")\n'
          'os.rmdir("/srv/data/www/tmp")\n')
    owner(dev, 'sh', '-c', 'rm -f "$HOME/woowbk-dirs/data/.storage/core.json" && chmod 0775 "$HOME/woowbk-dirs/data/共享"')
    mutated = snapshot(dev)
    ev.save('d1-mutated', mutated)
    changed = sorted(k for k in COMPARE if mutated['summary'][k] != before['summary'][k])
    ev.check('D1 mutation changed items, events, db_digest, db_meta, tree, tree_digest, sqlite and title',
             changed == sorted(set(COMPARE) - {'signatures_valid'}), changed)

    monitor = HealthMonitor(dev, 1200)
    t0 = time.monotonic()
    job, log = restore(dev, ev, backup_id, label='restore[d1]')
    health = monitor.stop()
    ev.timings.update(d1_restore_wall_s=round(time.monotonic() - t0, 1),
                      d1_restore_healthz_longest_unhealthy_s=health['longest_unhealthy_s'])
    ev.require('D1 in-place restore succeeded', job['state'] == 'succeeded', job.get('error'))
    result = job['result']
    ev.check('D1 result: safety backup, changed, health ok, verification match, not rolled back',
             result['safety_backup_id'] and result['changed'] is True and result['rolled_back'] is False
             and all(c['status'] == 'ok' for c in result['health'])
             and [v['match'] for v in result['verification']] == [True], result)
    after = snapshot(dev)
    ev.save('d1-after', after)
    ev.require('D1 everything equals the backup time (summary, full tree, database rows + meta, SQLite rows)',
               snapshot_diff(after, before) == {}, snapshot_diff(after, before))
    ev.check('D1 owner namespace view of the data dir equals the one before the backup',
             entries_of(dev, DATA_DIR) == data_before)
    link = next((e for e in after['tree'] if e['path'] == OUTSIDE_LINK[0]), {})
    ev.check('D1 the symlink that leaves the data dir is back verbatim (a link with the same target, never followed)',
             link.get('type') == 'symlink' and link.get('target') == OUTSIDE_LINK[1], link)
    ownership_checks(ev, dev, 'D1', after['tree'], entries_of(dev, PG_DIR))
    ev.check('D1 old copies deleted after success: no .woowbk-new-/.woowbk-old- siblings', not leftover_siblings(dev),
             leftover_siblings(dev))
    ev.check('D1 the role and the database created after the backup are gone (whole instance restored)',
             psql(dev, "SELECT count(*) FROM pg_roles WHERE rolname = 'woowbk_d1_extra';") == '0'
             and psql(dev, "SELECT count(*) FROM pg_database WHERE datname = 'woowbk_d1_extra';") == '0')
    status_code, item = post_item(dev, 'd1-after', 'D1 還原後寫入 𠮷')
    ev.check('D1 app writes again after the restore (POST /api/items -> 201)', status_code == 201, item)
    if status_code == 201:
        ev.check('D1 the new doc belongs to uid 33 inside the data dir',
                 next((e for e in app_json(dev, '/api/tree')['entries'] if e['path'] == f'www/{item["path"]}'), {})
                 .get('uid') == 33)
    _status, app = engine_app(dev, ev)
    ev.check('D1 status: running, no problems (units unmasked)', app['state'] == 'running' and not app['problems'], app)
    safety = next((b for b in ok(dev, 'list', ev=ev)['backups'] if b['id'] == result['safety_backup_id']), None)
    ev.check('D1 safety backup listed (type safety, verified)', safety and safety['type'] == 'safety'
             and (safety['verified'] or {}).get('ok'), safety)
    if safety:
        sapp = ok(dev, 'inspect', {'backup_id': safety['id']}, ev=ev)['manifest']['apps'][0]
        ev.check('D1 the safety backup holds both host directories (rollback material)', manifest_dirs(sapp) == list(DIRS),
                 sapp.get('data_dirs'))
    if demo_before is not None:
        ev.check('D1 woowbk-demo on the same device is untouched', demo_summary(dev) == demo_before)
    ev.timings['d1_restore_stop_to_app_start_s'] = e2e.log_window(log, f'停止服務 {APP_UNIT}', f'啟動服務 {APP_UNIT}')
    save_state(d1={'backup_id': backup_id, 'safety_backup_id': result['safety_backup_id']})
    return {'backup_id': backup_id}


# ------------------------------------------------------------------ scenario: d2 cross-device fresh

def scenario_d2(ev):
    ranges = {dev: subid_range(dev) for dev in ('a', 'b')}
    ev.require('D2 dev-b has another subuid/subgid range than dev-a (tests/e2e/lab/subids.sh)',
               ranges['a']['subuid'] != ranges['b']['subuid'] and ranges['a']['subgid'] != ranges['b']['subgid'], ranges)
    source = source_backup(ev)
    secret = kit_secret()
    snap = source['snapshot']

    teardown('b', ev)
    ev.require('D2 dev-b is a fresh target (no woowbk-dirs footprint)', footprint('b') == [], footprint('b'))
    _status, app = engine_app('b', ev)
    ev.require('D2 dev-b: app known to the engine and not deployed', app and app['state'] == 'not-deployed', app)
    uploaded = ensure_uploaded('b', source, ev)
    ev.check('D2 dev-b holds the backup as uploaded, key not on dev-b', uploaded['type'] == 'uploaded'
             and uploaded['key_available'] is False, uploaded)
    _rc, reply = helper('b', 'inspect', {'backup_id': source['backup_id']}, ev=ev)
    ev.check('D2 inspect without key -> key-required', not reply['ok'] and reply['error']['code'] == 'key-required',
             reply.get('error'))
    inspected = ok('b', 'inspect', {'backup_id': source['backup_id'], 'key': secret}, ev=ev)
    ev.save('d2-inspect', inspected)
    mapp, papp = inspected['manifest']['apps'][0], inspected['preflight']['apps'][0]
    ev.check('D2 inspect: from dev-a (owner uid 1001), data_dirs listed, preflight fresh + restorable',
             mapp['owner']['uid'] == 1001 and inspected['manifest']['source']['hostname'] == 'woowbk-dev-a'
             and manifest_dirs(mapp) == list(DIRS) and papp['mode'] == 'fresh' and papp['restorable']
             and inspected['preflight']['ok'], papp)
    ev.log('D2 preflight checks: ' + ' | '.join(f'{c["status"]}:{c["message"]}' for c in papp['checks']))

    t0 = time.monotonic()
    job, log = restore('b', ev, source['backup_id'], key=secret, label='restore[d2]')
    ev.timings['d2_restore_wall_s'] = round(time.monotonic() - t0, 1)
    ev.require('D2 fresh restore on dev-b succeeded', job['state'] == 'succeeded', job.get('error'))
    result = job['result']
    ev.check('D2 result: no safety backup (fresh), health ok, verification match',
             result['safety_backup_id'] is None and result['rolled_back'] is False
             and all(c['status'] == 'ok' for c in result['health'])
             and [v['match'] for v in result['verification']] == [True], result)
    ev.check('D2 phases: safety skipped, the rest done', phase_states(job).get('safety') == 'skipped'
             and all(s == 'done' for p, s in phase_states(job).items() if p != 'safety'), phase_states(job))
    after = snapshot('b')
    ev.save('d2-after', after)
    ev.require('D2 dev-b equals the dev-a backup time (summary, full tree incl. container ids/modes/mtimes/xattrs/'
               'hard links/symlink, database rows + roles/owners/cluster id, SQLite)', snapshot_diff(after, snap) == {},
               snapshot_diff(after, snap))
    link = next((e for e in after['tree'] if e['path'] == OUTSIDE_LINK[0]), {})
    ev.check('D2 the symlink that leaves the data dir arrived verbatim on dev-b (a link, same target)',
             link.get('type') == 'symlink' and link.get('target') == OUTSIDE_LINK[1], link)
    host_b = ownership_checks(ev, 'b', 'D2 dev-b', after['tree'], entries_of('b', PG_DIR))
    uids_a, _gids_a = id_maps('a')
    ev.check('D2 host ids on dev-b differ from dev-a for container uid 33 and 70 (remapped, not copied)',
             host_b[f'{DATA_DIR}/www'][0] != host_id(uids_a, 33) and host_b[PG_DIR][0] != host_id(uids_a, 70),
             {'dev-b': host_b, 'dev-a 33/70': (host_id(uids_a, 33), host_id(uids_a, 70))})
    state = dir_state('b')
    ev.check('D2 missing parents were created for the owner (uid 1007), not as symlinks',
             all((state['paths'][p] or {}).get('type') == 'dir' and (state['paths'][p] or {}).get('uid') == 1007
                 for p in PARENTS), {p: state['paths'][p] for p in PARENTS})
    ev.check('D2 no .woowbk-new-/.woowbk-old- siblings on dev-b', not leftover_siblings('b'), leftover_siblings('b'))

    status_code, item = post_item('b', 'd2-after', '跨設備還原後可寫入 𠮷')
    ev.check('D2 POST /api/items on dev-b -> 201 (role dirs_app logs in with the restored password)',
             status_code == 201, item)
    final = summary('b')
    ev.check('D2 counts +1 in both databases and SQLite, signatures valid',
             final['items'] == snap['summary']['items'] + 1 and final['events'] == snap['summary']['events'] + 1
             and final['sqlite']['docs'] == snap['summary']['sqlite']['docs'] + 1 and final['signatures_valid'], final)
    if status_code == 201:
        entry = next((e for e in app_json('b', '/api/tree')['entries'] if e['path'] == f'www/{item["path"]}'), {})
        ev.check('D2 the new doc belongs to uid 33 (container view)', entry.get('uid') == 33, entry)
    _status, app = engine_app('b', ev)
    ev.check('D2 dev-b status: deployed, running, no problems', app['deployed'] and app['state'] == 'running'
             and not app['problems'], app)
    ev.check('D2 job key file removed and no key imported on dev-b', no_job_keys('b')
             and ok('b', 'status', ev=ev)['imported_keys'] == [])
    save_state(d2={'backup_id': source['backup_id'], 'restore_job': job['id']})
    return {}


# ------------------------------------------------------------------ scenario: d3 rollback after the swap

D3_DROPIN = f'.config/systemd/user/{DB_UNIT}.d/woowbk-d3.conf'
D3_MARKER = 'woowbk-d3-fail-start'  # a file in the data dir root: the D3 backup holds it, the pre-restore state not


def d3_inject(dev, enable):
    """While installed, the database unit refuses to start when the data dir holds D3_MARKER (`ExecStartPre=`) and is
    never restarted automatically (`Restart=no`, so no start-rate limit can block the rollback's start).

    With a cold database the database unit is a writer: the restore's safety backup stops it and starts it again. A
    one-shot "fail the next start" like cli_e2e's F8 would therefore fail the safety backup (nothing changed) instead
    of the restore. Conditioned on a file that only the restored backup content carries, the safety backup's start
    works, the restore's start after the swap fails, and the rollback's start (safety backup content) works."""
    parent = str(Path(D3_DROPIN).parent)
    if enable:
        script = (f'mkdir -p "$HOME/{parent}" && printf "%s\\n" "[Service]" "Restart=no" '
                  f'"ExecStartPre=/bin/sh -c \'test ! -e %h/{DATA_DIR}/{D3_MARKER}\'" '
                  f'> "$HOME/{D3_DROPIN}" && systemctl --user daemon-reload')
    else:
        script = f'rm -f "$HOME/{D3_DROPIN}"; rmdir "$HOME/{parent}" 2>/dev/null; systemctl --user daemon-reload'
    owner(dev, 'sh', '-c', script)


def d3_marker(dev, present):
    """Create or remove D3_MARKER in the data dir root (a file of the owner, container root in the app)."""
    path = f'{HOME}/{DATA_DIR}/{D3_MARKER}'
    if present:
        owner(dev, 'sh', '-c', f'printf "D3: {DB_UNIT} refuses to start while this file exists\\n" > "{path}"')
    else:
        owner(dev, 'rm', '-f', path)


def d3_marker_present(dev):
    return owner(dev, 'test', '-e', f'{HOME}/{DATA_DIR}/{D3_MARKER}', check=False).returncode == 0


def scenario_d3(ev):
    dev = 'a'
    ev.require('D3 no leftover siblings before the scenario', not leftover_siblings(dev), leftover_siblings(dev))
    ev.require('D3 app healthy before the scenario', wait_healthy(dev, 120))
    d3_marker(dev, True)
    try:
        job, _log = backup(dev, ev, 'D3 回復測試（資料夾含啟動失敗標記）', label='backup[d3]')
    finally:
        d3_marker(dev, False)
    backup_id = job['result']['backup_id']
    seed(dev, '--items', 2, '--title', 'D3 還原前的狀態', '--owner-note', 'D3 還原前')
    ev.require('D3 app healthy before the restore', wait_healthy(dev, 120))
    pre = snapshot(dev)
    pre_data = entries_of(dev, DATA_DIR)
    ev.require('D3 only the backup carries the marker (the pre-restore data dir does not)',
               all(e['path'] != D3_MARKER for e in pre_data))
    t0 = time.monotonic()
    d3_inject(dev, True)
    try:
        job, log = restore(dev, ev, backup_id, label='restore[d3]')
    finally:
        d3_inject(dev, False)
        if d3_marker_present(dev):  # the restore did not roll back: keep later scenarios clean (reported below)
            ev.log('D3 cleanup: the data dir still holds the marker after the restore; removing it')
            d3_marker(dev, False)
            owner(dev, 'systemctl', '--user', 'start', APP_UNIT, check=False, timeout=600)
    ev.timings['d3_restore_with_rollback_wall_s'] = round(time.monotonic() - t0, 1)
    result = job.get('result') or {}
    ev.check('D3 job rolled-back, job-failed, result.rolled_back, changed, safety backup recorded',
             job['state'] == 'rolled-back' and (job.get('error') or {}).get('code') == 'job-failed'
             and result.get('rolled_back') is True and result.get('changed') is True and result.get('safety_backup_id'),
             {'state': job['state'], 'error': job.get('error')})
    ev.check('D3 phases: safety done (its database restart passed), restore done (directories swapped), start '
             'failed, rollback done', phase_states(job).get('safety') == 'done'
             and phase_states(job).get('restore') == 'done' and phase_states(job).get('start') == 'failed'
             and phase_states(job).get('rollback') == 'done', phase_states(job))
    ev.check('D3 the error names the database unit that failed to start', DB_UNIT in (job.get('error') or {}).get('message', ''),
             (job.get('error') or {}).get('message'))
    ev.check('D3 app healthy after the rollback', wait_healthy(dev, 240))
    after = snapshot(dev)
    ev.require('D3 data after the rollback equals the pre-restore state, not the backup (summary, tree, db, SQLite)',
               snapshot_diff(after, pre) == {}, snapshot_diff(after, pre))
    ev.check('D3 owner namespace view of the data dir equals the pre-restore one', entries_of(dev, DATA_DIR) == pre_data)
    ownership_checks(ev, dev, 'D3', after['tree'], entries_of(dev, PG_DIR))
    # The old copy is deleted only after a job succeeded: after a rollback the engine may keep the pre-restore content
    # next to the directory (never the only copy), and must say so. New copies must never stay.
    leftovers = leftover_siblings(dev)
    kept = [name for names in leftovers.values() for name in names]
    ev.check('D3 no .woowbk-new- copy left after the rollback', not any('.woowbk-new-' in n for n in kept), leftovers)
    ev.check('D3 every copy the rollback kept is reported in the job (warnings or log name it)',
             all(name in job_text(job, log) for name in kept), {'kept': kept, 'warnings': result.get('warnings')})
    ev.check('D3 the rollback moved each directory back from its pre-restore copy (no third copy extracted) and '
             "deleted the failed restore's data once verified (review M3)",
             all(f'已把主機資料夾 ~/{rel} 還原前的內容移回' in job_text(job, log) for rel in DIRS) and not kept,
             {'kept': kept, 'log': [line for line in job_text(job, log).splitlines() if '移回' in line or '刪除' in line]})
    for name in leftovers.get(DATA_DIR, []):
        ev.check(f'D3 the kept copy {name} holds the pre-restore content of the data dir',
                 entries_of(dev, f'{Path(DATA_DIR).parent}/{name}') == pre_data)
    if leftovers:
        ev.log(f'D3 the rollback kept {kept} (reported); removing them so later scenarios start clean')
        remove_leftovers(dev, ev, leftovers)
    _status, app = engine_app(dev, ev)
    ev.check('D3 status: running, no problems (units unmasked)', app['state'] == 'running' and not app['problems'], app)
    return {'backup_id': backup_id}


# ------------------------------------------------------------------ scenario: d4 interruption

# Root inside the device: waits for its trigger, then stops and kills the restore job's whole process tree at once
# (the unit's processes and every descendant, also owner processes that rootless podman moved into their own user
# scope, so no helper of the job can finish a rename afterwards), then SIGKILLs the unit. Prints one JSON line.
KILL_WATCH = r'''
import json, os, signal, subprocess, sys, time
job, mode, home, timeout = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
dirs, target = sys.argv[5].split(','), sys.argv[6]
# argv 7 and 8 (self-test only): another record file and unit
record = sys.argv[7] if len(sys.argv) > 7 else '/var/lib/woowtech-backup/jobs/%s.json' % job
unit = sys.argv[8] if len(sys.argv) > 8 else 'woowtech-backup-%s.service' % job
def siblings():
    found = {}
    for rel in dirs:
        parent, base = os.path.split(os.path.join(home, rel))
        try:
            names = os.listdir(parent)
        except OSError:
            names = []
        found[rel] = sorted(n for n in names if n.startswith(base + '.woowbk-'))
    return found
def job_record():
    try:
        with open(record) as handle:
            data = json.load(handle)
        return data.get('state'), data.get('phase')
    except (OSError, ValueError):
        return None, None
def cgroup():
    out = subprocess.run(['systemctl', 'show', '-P', 'ControlGroup', unit], capture_output=True, text=True).stdout
    return out.strip()
def tree(roots):
    parents = {}
    for name in os.listdir('/proc'):
        if name.isdigit():
            try:
                with open('/proc/%s/stat' % name) as handle:
                    fields = handle.read().rsplit(')', 1)[1].split()
                parents.setdefault(int(fields[1]), []).append(int(name))
            except (OSError, IndexError, ValueError):
                pass
    seen, todo = set(), list(roots)
    while todo:
        pid = todo.pop()
        if pid in seen:
            continue
        seen.add(pid)
        todo.extend(parents.get(pid, []))
    return seen
def comm(pid):
    try:
        with open('/proc/%d/comm' % pid) as handle:
            return handle.read().strip()
    except OSError:
        return '?'
deadline = time.time() + timeout
group, last_read, result = '', 0.0, {'triggered': False, 'mode': mode}
while time.time() < deadline:
    now = time.time()
    if not group:
        group = cgroup()
    trigger = None
    if mode == 'extract':
        # Since 2026-11-13 the copies are written in phase `stage`, before the safety backup and before anything stops.
        found = siblings()
        hit = [rel for rel in dirs if any('.woowbk-new-' in n for n in found[rel])]
        if hit:
            trigger = 'new sibling of %s' % hit[0]
    if trigger is None and now - last_read > 0.05:
        last_read = now
        state, phase = job_record()
        if mode == 'after-swap' and state == 'running' and phase == 'start':
            trigger = 'phase start'
        elif mode == 'between' and state == 'running' and phase == 'restore':
            trigger = 'phase restore (units stopped and masked, copies about to be swapped)'
        elif state not in (None, 'queued', 'running'):
            result.update(reason='job finished first', state=state, phase=phase)
            break
    if trigger:
        roots = set()
        if group:
            for base, _dirs, files in os.walk('/sys/fs/cgroup' + group):
                if 'cgroup.procs' in files:
                    with open(os.path.join(base, 'cgroup.procs')) as handle:
                        roots.update(int(x) for x in handle.read().split())
        pids = tree(roots) - {os.getpid()}
        for sig in (signal.SIGSTOP, signal.SIGKILL):
            for pid in pids:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
        names = sorted(comm(p) for p in pids)
        subprocess.run(['systemctl', 'kill', '--signal=SIGKILL', unit], capture_output=True)
        state, phase = job_record()
        try:
            with open(record[:-len('.json')] + '.log', 'rb') as handle:
                log_lines = handle.read().count(b'\n')
        except OSError:
            log_lines = 0
        result.update(triggered=True, trigger=trigger, phase=phase, killed=len(pids), killed_comm=names[:40],
                      siblings=siblings(), paths={rel: os.path.lexists(os.path.join(home, rel)) for rel in dirs},
                      log_lines=log_lines)
        break
    time.sleep(0.002)
print(json.dumps(result))
'''

# The owner (no namespace needed: the parent directories are the owner's): turn whatever the kill left for one
# directory into the state "killed between the two renames of the swap": <path> missing, the original content in
# <path>.woowbk-old-<job>, the new content in <path>.woowbk-new-<job>.
INJECT_BETWEEN = r'''
import json, os, sys
path = sys.argv[1]
parent, base = os.path.split(path)
names = os.listdir(parent)
new = sorted(n for n in names if n.startswith(base + '.woowbk-new-'))
old = sorted(n for n in names if n.startswith(base + '.woowbk-old-'))
present = os.path.lexists(path)
if present and new and not old:
    target = new[0].replace('.woowbk-new-', '.woowbk-old-', 1)
    os.rename(path, os.path.join(parent, target))
    action = 'killed before rename 1: renamed <path> -> %s (rename 1 done by the test)' % target
elif present and old and not new:
    target = old[0].replace('.woowbk-old-', '.woowbk-new-', 1)
    os.rename(path, os.path.join(parent, target))
    action = 'killed after rename 2: renamed <path> back to %s (rename 2 undone by the test)' % target
elif not present and old and new:
    action = 'killed between the renames: nothing to do'
else:
    action = 'unexpected state: present=%s new=%s old=%s' % (present, new, old)
after = sorted(n for n in os.listdir(parent) if n == base or n.startswith(base + '.woowbk-'))
print(json.dumps({'action': action, 'after': after}))
'''


def kill_watch(dev, job_id, mode, target=DATA_DIR, timeout=900):
    """Start the in-device watcher (returns the Popen); its stdout is one JSON line."""
    return subprocess.Popen([LP, 'exec', '-i', dev_name(dev), 'python3', '-I', '-', job_id, mode, HOME, str(timeout),
                             ','.join(DIRS), target], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)


def remove_leftovers(dev, ev, leftovers):
    """Test cleanup between cases: remove sibling copies the engine kept (logged; never the declared paths)."""
    for rel, names in leftovers.items():
        parent = str(Path(HOME, rel).parent)
        for name in names:
            if not name.startswith(Path(rel).name + '.woowbk-'):
                continue
            owner(dev, 'podman', 'unshare', 'rm', '-rf', '--', f'{parent}/{name}', timeout=300)
            ev.log(f'cleanup: removed leftover ~/{str(Path(rel).parent)}/{name}')


D4_CASES = ('extract', 'between', 'after-swap')


def d4_case(ev, dev, mode, backup_id):
    pre = snapshot(dev)
    pre_data = entries_of(dev, DATA_DIR)
    start = ok(dev, 'restore-start', {'backup_id': backup_id, 'apps': [APP], 'request_id': request_id(),
                                      'confirm': True}, ev=ev)
    job_id = start['job_id']
    watcher = kill_watch(dev, job_id, mode)
    out, err = watcher.communicate(KILL_WATCH.encode(), timeout=1000)
    report = json.loads(out.decode().strip().splitlines()[-1]) if out.strip() else {'error': err.decode()[-300:]}
    ev.save(f'd4-{mode}-kill', report)
    ev.require(f'D4 {mode}: the restore job was killed ({report.get("trigger")})', report.get('triggered'), report)
    ev.log(f'D4 {mode}: killed {report["killed"]} processes in phase {report["phase"]}: {report["killed_comm"]}; '
           f'siblings {report["siblings"]}; paths present {report["paths"]}')
    injected = None
    if mode == 'between':
        injected = json.loads(owner(dev, 'python3', '-I', '-c', INJECT_BETWEEN, f'{HOME}/{DATA_DIR}').stdout)
        ev.log(f'D4 between: {injected}')
        ev.require('D4 between: state is now "killed between the swap renames" (path missing, old + new siblings)',
                   not dir_state(dev)['paths'][DATA_DIR] and len(leftover_siblings(dev).get(DATA_DIR, [])) == 2,
                   {'injected': injected, 'state': dir_state(dev)})
    time.sleep(2)
    job, log = wait_job(dev, job_id, ev=ev, timeout=180, label=f'killed[{mode}]')  # job-status runs the recovery
    save_job(ev, f'd4-{mode}-killed-job', job, log)
    safety = (job.get('result') or {}).get('safety_backup_id')
    if report.get('phase') == 'stage':
        # Killed while the copies were written ahead (CONTRACT section 9): nothing had stopped, nothing existing had
        # changed and no safety backup exists yet; the recovery only removes the new copies.
        state = dir_state(dev)
        ev.check(f'D4 {mode}: job interrupted, no safety backup taken yet', job['state'] == 'interrupted' and not safety,
                 [job.get('state'), job.get('error')])
        ev.check(f'D4 {mode}: every declared directory exists and no .woowbk- sibling is left',
                 all((state['paths'][rel] or {}).get('type') == 'dir' for rel in DIRS)
                 and not any(names for names in state['siblings'].values()), state)
        ev.check(f'D4 {mode}: the data directory is unchanged', entries_of(dev, DATA_DIR) == pre_data)
        _status, app = engine_app(dev, ev)
        ev.check(f'D4 {mode}: the app kept running (nothing had stopped)', app['state'] == 'running' and wait_healthy(dev, 60),
                 app)
        after = snapshot(dev)
        ev.check(f'D4 {mode}: data equals the state before the killed restore', snapshot_diff(after, pre) == {},
                 snapshot_diff(after, pre))
        return {'kill': report, 'injected': None, 'job': job_id, 'safety': None, 'old_left': {}}
    ev.check(f'D4 {mode}: job interrupted with guidance naming the safety backup',
             job['state'] == 'interrupted' and safety and safety in (job.get('error') or {}).get('message', ''),
             job.get('error'))
    state = dir_state(dev)
    # Only what the recovery added counts as its report: the killed job's own log already names the directories.
    full_log = sh(dev, f'cat /var/lib/woowtech-backup/jobs/{job_id}.log', check=False).stdout.decode('utf-8', 'replace')
    recovery_lines = full_log.splitlines()[report.get('log_lines', 0):]
    ev.save(f'd4-{mode}-after-recovery', {'dirs': state, 'recovery_log': recovery_lines, 'error': job.get('error')})
    ev.check(f'D4 {mode}: after recovery every declared directory exists (never deleted the only copy)',
             all((state['paths'][rel] or {}).get('type') == 'dir' for rel in DIRS), state['paths'])
    ev.check(f'D4 {mode}: no .woowbk-new- sibling left (abandoned new copies removed)',
             not any('.woowbk-new-' in n for names in state['siblings'].values() for n in names), state['siblings'])
    text = (json.dumps([job.get('error'), (job.get('result') or {}).get('warnings')], ensure_ascii=False) + '\n'
            + '\n'.join(recovery_lines))
    touched = [rel for rel in DIRS if any(report['siblings'].get(rel) or [])] + ([DATA_DIR] if injected else [])
    ev.check(f'D4 {mode}: the recovery is reported (its message/log lines name each directory it tidied: {touched})',
             all(rel in text for rel in set(touched)), recovery_lines[-8:])
    if mode == 'between':
        ev.check('D4 between: the original directory was moved back (data dir equals the pre-restore content) and '
                 'no .woowbk-old- copy remains', entries_of(dev, DATA_DIR) == pre_data
                 and not state['siblings'][DATA_DIR], state['siblings'])
    old_left = {rel: names for rel, names in state['siblings'].items() if names}
    if old_left:
        ev.log(f'D4 {mode}: old copies kept by the recovery (allowed when reported): {old_left}')
        ev.check(f'D4 {mode}: kept old copies are reported', all(rel in text for rel in old_left), old_left)
    if mode != 'after-swap':  # killed while every unit was stopped and masked by the restore
        _status, app = engine_app(dev, ev)
        ev.check(f'D4 {mode}: overview shows the app as needing attention (not running; problems explain it)',
                 app['state'] != 'running' and app['problems'], app)

    t0 = time.monotonic()
    rjob, rlog = restore(dev, ev, safety, label=f'restore-safety[{mode}]')
    ev.timings[f'd4_{mode}_restore_safety_wall_s'] = round(time.monotonic() - t0, 1)
    ev.check(f'D4 {mode}: restoring the safety backup succeeds', rjob['state'] == 'succeeded', rjob.get('error'))
    after = snapshot(dev) if wait_healthy(dev, 240) else {}
    ev.check(f'D4 {mode}: data equals the state before the killed restore', after and snapshot_diff(after, pre) == {},
             after and snapshot_diff(after, pre))
    leftovers = leftover_siblings(dev)
    ev.check(f'D4 {mode}: after the safety restore no .woowbk-new- copy exists',
             not any('.woowbk-new-' in n for names in leftovers.values() for n in names), leftovers)
    if leftovers:
        remove_leftovers(dev, ev, leftovers)
    return {'kill': report, 'injected': injected, 'job': job_id, 'safety': safety, 'old_left': old_left}


def scenario_d4(ev):
    dev = 'a'
    cases = [c for c in os.environ.get('D4_CASES', '').split(',') if c] or list(D4_CASES)
    ev.require('D4 no leftover siblings before the scenario', not leftover_siblings(dev), leftover_siblings(dev))
    job, _log = backup(dev, ev, 'D4 中斷測試', label='backup[d4]')
    backup_id = job['result']['backup_id']
    seed(dev, '--items', 1, '--title', 'D4 還原前的狀態')  # the restore would visibly change the data
    results = {}
    for mode in cases:
        try:
            results[mode] = d4_case(ev, dev, mode, backup_id)
        except Failed as error:
            ev.check(f'D4 {mode}: case ran to completion', False, str(error))
            results[mode] = {'aborted': str(error)}
            break
        finally:
            ev.save('d4-cases', results)
    ev.check('D4 dev-a afterwards: app running, staging empty, no job keys, no orphans',
             engine_app(dev, ev)[1]['state'] == 'running' and staging_empty(dev) and no_job_keys(dev) and orphans(dev) == [])
    return {'cases': results}


# ------------------------------------------------------------------ scenario: d5 hostile dir tars

D5_TAG = 'woowbk-d5-planted'
D5_WORK = '/var/tmp/woowbk-d5-work'  # device root fs (/tmp is a tmpfs that counts against the device memory)

# Builds hostile variants of a directory tar (shared by the d5 crafting program and the self-test). Hostile members
# are appended after every real member, so a restore that streams before it checks would already have changed data.
HOSTILE = r'''
import io, tarfile, time
def _info(name, size=0, kind=tarfile.REGTYPE, link='', mode=0o644, uid=0, gid=0):
    ti = tarfile.TarInfo(name)
    ti.size, ti.type, ti.linkname, ti.mode, ti.uid, ti.gid, ti.mtime = size, kind, link, mode, uid, gid, int(time.time())
    return ti
def hostile_members(case, prefix, tag, home):
    data = ('%s %s (harmless lab canary)\n' % (tag, case)).encode()
    if case == 'symlink-abs-below':
        return [(_info(prefix + tag + '-esc', kind=tarfile.SYMTYPE, link=home + '/.config/systemd/user', mode=0o777), None),
                (_info(prefix + tag + '-esc/' + tag + '.service', len(data)), data)]
    if case == 'symlink-rel-below':
        return [(_info(prefix + 'www/' + tag + '-up', kind=tarfile.SYMTYPE, link='../../../.config/containers', mode=0o777,
                       uid=33, gid=33), None),
                (_info(prefix + 'www/' + tag + '-up/' + tag + '.conf', len(data), uid=33, gid=33), data)]
    if case == 'absolute-member':
        return [(_info(home + '/.config/systemd/user/' + tag + '-abs.service', len(data)), data)]
    if case == 'dotdot-member':
        return [(_info(prefix + '../../.config/systemd/user/' + tag + '-dotdot.service', len(data)), data)]
    if case == 'pax-path-dotdot':
        ti = _info(prefix + tag + '-pax.txt', len(data))
        ti.pax_headers = {'path': '../../' + tag + '-pax.txt'}
        return [(ti, data)]
    if case == 'below-file':
        return [(_info(prefix + 'README.txt/' + tag + '-below.txt', len(data)), data)]
    if case == 'hardlink-outside':
        return [(_info(prefix + tag + '-hl', kind=tarfile.LNKTYPE, link=home + '/.config/woowbk-dirs/app.env'), None)]
    if case == 'device-member':
        ti = _info(prefix + tag + '-null', kind=tarfile.CHRTYPE, mode=0o666)
        ti.devmajor, ti.devminor = 1, 3
        return [(ti, None)]
    if case == 'unmapped-owner':
        return [(_info(prefix + tag + '-uid.txt', len(data), uid=60000, gid=60000), data)]
    if case == 'duplicate-member':
        return [(_info(prefix + 'README.txt', len(data)), data)]
    raise SystemExit('unknown case ' + case)
def name_prefix(path):
    with tarfile.open(path, 'r:') as tar:
        names = [m.name for _i, m in zip(range(20), tar)]
    return './' if any(n.startswith('./') for n in names) else ''
def write_hostile(original, dest, case, tag, home):
    prefix = name_prefix(original)
    with open(original, 'rb') as raw, tarfile.open(fileobj=raw, mode='r|') as src, \
            open(dest, 'wb') as out_file, tarfile.open(fileobj=out_file, mode='w|', format=tarfile.PAX_FORMAT) as out:
        kept = 0
        for member in src:
            out.addfile(member, src.extractfile(member) if member.isreg() else None)
            kept += 1
        for info, data in hostile_members(case, prefix, tag, home):
            out.addfile(info, io.BytesIO(data) if data is not None else None)
    return kept
'''

# Diagnostic verdict of the INSTALLED engine's nested checks on a directory tar (reason and member only).
VERDICT = r'''
import subprocess
def owner_ids(owner='appowner'):
    import pwd
    uid = pwd.getpwnam(owner).pw_uid
    env = ['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'HOME=/home/' + owner, 'LANG=C.UTF-8',
           'XDG_RUNTIME_DIR=/run/user/%d' % uid, 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus' % uid]
    maps = []
    for kind in ('uid', 'gid'):
        out = subprocess.run(['/usr/sbin/runuser', '-u', owner, '--', *env, 'podman', 'unshare', 'cat',
                              '/proc/self/%s_map' % kind], capture_output=True, text=True, cwd='/home/' + owner).stdout
        maps.append(nested.IdMap(out))
    return tuple(maps)
def verdict(path, ids):
    check = getattr(nested, 'check_dir', None) or getattr(nested, 'check_data_dir', None)
    used = 'check_dir' if check else 'check_volume'
    try:
        if check is None:
            nested.check_volume(path, ids)
        else:
            try:
                check(path, ids)
            except TypeError:
                check(path)
        return {'accepted': True, 'checker': used}
    except BackupError as error:
        return {'accepted': False, 'checker': used, 'code': error.code, 'reason': error.details.get('reason'),
                'member': str(error.details.get('member'))[:200]}
'''

# Root inside dev-a: decrypt a base backup with the device key once, write one re-encrypted archive per case
# (device recipient) into the work directory, print a JSON report (ids, sizes, engine verdicts). Plaintext is deleted.
# A format 2 base (`archives/<id>.tar`, every backup since 2026-11-13) gives format 2 cases, written with the installed
# engine's own writer (valid backup.json, README and per-app manifest; only the directory tar is hostile); a format 1
# base (the self-test's synthetic source) gives format 1 cases.
CRAFT_D5 = r'''
import glob, hashlib, json, os, secrets, shutil, subprocess, sys, tarfile, time
sys.path.insert(0, '/usr/local/lib/woowtech-cockpit-backup')
sys.dont_write_bytecode = True
from woowbackup import nested
from woowbackup.errors import BackupError
''' + HOSTILE + VERDICT + r'''
base_id, work, tag, home, data_dir = sys.argv[1:6]
cases = sys.argv[6].split(',')
# argv 7 (self-test only): a synthetic source archive instead of the engine's archives/<base_id>.tar|.woowbackup
source = sys.argv[7] if len(sys.argv) > 7 else next(
    (p for p in ('/var/lib/woowtech-backup/archives/%s.tar' % base_id,
                 '/var/lib/woowtech-backup/archives/%s.woowbackup' % base_id) if os.path.exists(p)), '')
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
def pipeline(stages, source, sink):
    procs, stdin = [], source
    for i, argv in enumerate(stages):
        proc = subprocess.Popen(argv, stdin=stdin, stdout=sink if i == len(stages) - 1 else subprocess.PIPE, env=ENV)
        if stdin is not source:
            stdin.close()
        stdin = proc.stdout
        procs.append(proc)
    codes = [proc.wait() for proc in procs]
    if any(codes):
        raise SystemExit('%s exited %s' % ([s[0] for s in stages], codes))
def digest(path):
    h, size = hashlib.sha256(), 0
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size
def outer(name, size):
    ti = tarfile.TarInfo(name)
    ti.size, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname, ti.mtime = size, 0o600, 0, 0, 'root', 'root', int(time.time())
    return ti
def small_dir_tar(path, member):
    with tarfile.open(path, 'w', format=tarfile.PAX_FORMAT) as tar:
        root = tarfile.TarInfo('.')
        root.type, root.mode = tarfile.DIRTYPE, 0o755
        tar.addfile(root)
        data = ('%s (harmless lab canary)\n' % tag).encode()
        info = tarfile.TarInfo(member)
        info.size, info.mode = len(data), 0o644
        tar.addfile(info, __import__('io').BytesIO(data))
def craft_v2(recipient, keyfile):
    from woowbackup import archive as warchive
    outer_tar = tarfile.open(source, 'r:')
    doc = json.loads(outer_tar.extractfile('backup.json').read())
    sealed = os.path.join(work, 'app.sealed')
    with outer_tar.extractfile(doc['apps'][0]['file']) as raw, open(sealed, 'wb') as out:
        shutil.copyfileobj(raw, out, 1 << 20)
    outer_tar.close()
    plain_path = os.path.join(work, 'plain.tar')
    with open(sealed, 'rb') as src, open(plain_path, 'wb') as sink:
        pipeline([['age', '-d', '-i', keyfile], ['zstd', '-d', '-c', '-q']], src, sink)
    os.unlink(sealed)
    plain = tarfile.open(plain_path, 'r:')
    members = plain.getmembers()
    inner = json.loads(plain.extractfile(members[0]).read())
    app = inner['app']
    target = next((d for d in app.get('data_dirs') or [] if d.get('path') == data_dir), None)
    if target is None:
        raise SystemExit('the base backup has no data_dirs entry for ' + data_dir)
    sources = {}
    for index, member in enumerate(members[1:]):
        local = os.path.join(work, 'member-%d' % index)
        with plain.extractfile(member) as raw, open(local, 'wb') as out:
            shutil.copyfileobj(raw, out, 1 << 20)
        sources[member.name] = local
    plain.close()
    os.unlink(plain_path)
    original = sources[target['entry']]
    ids = owner_ids()
    report.update(entry=target['entry'], dir_members=sum(1 for _ in tarfile.open(original, 'r:')),
                  name_prefix=name_prefix(original), original_verdict=verdict(original, ids))
    for case in cases:
        a = json.loads(json.dumps(app))
        files = dict(sources)
        if case in ('undeclared-dir', 'forbidden-path'):
            path, number = ('woowbk-d5-planted-undeclared', 9) if case == 'undeclared-dir' else ('.config/systemd/user', 8)
            entry = 'apps/%s/dirs/%d.tar' % (a['id'], number)
            local = os.path.join(work, case + '.dir.tar')
            small_dir_tar(local, tag + '-' + case + '.service')
            a['data_dirs'].append({'path': path, 'entry': entry})
            files[entry] = local
        else:
            local = os.path.join(work, case + '.dir.tar')
            write_hostile(original, local, case, tag, home)
            files[target['entry']] = local
        refs = [e['path'] for e in inner['entries']] + [p for p in files if p not in sources]
        entries = []
        for path in refs:
            sha, size = digest(files[path])
            entries.append(warchive.Entry(path, files[path], size, sha))
        now = time.gmtime()
        new_id = time.strftime('%Y%m%dT%H%M%SZ', now) + '-' + secrets.token_hex(4)
        head = {key: inner[key] for key in warchive.HEAD_FIELDS}
        head.update(backup_id=new_id, created=time.strftime('%Y-%m-%dT%H:%M:%SZ', now), note='D5 ' + case,
                    type='manual')
        out_path = os.path.join(work, case + '.crafted.tar')
        with warchive.ArchiveWriter(out_path, head, [a], recipient, tmp_dir=work) as writer:
            writer.add_app(a, entries)
            writer.finish()
        report['cases'][case] = {'backup_id': new_id, 'path': out_path, 'size': os.path.getsize(out_path),
                                 'engine_verdict': verdict(local, ids)}
        os.unlink(local)
os.mkdir(work, 0o700)
report = {'cases': {}}
try:
    keyfiles = sorted(glob.glob('/etc/woowtech-cockpit/backup/keys/device-*.key'))
    if len(keyfiles) != 1:
        raise SystemExit('need exactly one device key')
    recipient = subprocess.run(['age-keygen', '-y', keyfiles[0]], capture_output=True, env=ENV,
                               check=True).stdout.decode().split()[0]
    with open(source, 'rb') as handle:
        magic, header_line = handle.readline(), handle.readline()
        offset = handle.tell()
    if magic != b'WOOWTECH-BACKUP/1\n':
        craft_v2(recipient, keyfiles[0])
        print(json.dumps(report))
        raise SystemExit(0)
    old_header = json.loads(header_line)
    plain_path = os.path.join(work, 'plain.tar')
    with open(source, 'rb') as src, open(plain_path, 'wb') as sink:
        src.seek(offset)
        pipeline([['age', '-d', '-i', keyfiles[0]], ['zstd', '-d', '-c', '-q']], src, sink)
    plain = tarfile.open(plain_path, 'r:')
    members = plain.getmembers()
    manifest = json.loads(plain.extractfile(members[0]).read())
    app = manifest['apps'][0]
    target = next((d for d in app.get('data_dirs') or [] if d.get('path') == data_dir), None)
    if target is None:
        raise SystemExit('the base backup has no data_dirs entry for ' + data_dir)
    by_name = {m.name: m for m in members}
    original = os.path.join(work, 'dir.orig.tar')
    with plain.extractfile(by_name[target['entry']]) as raw, open(original, 'wb') as out:
        shutil.copyfileobj(raw, out, 1 << 20)
    ids = owner_ids()
    report.update(entry=target['entry'], dir_members=sum(1 for _ in tarfile.open(original, 'r:')),
                  name_prefix=name_prefix(original), original_verdict=verdict(original, ids))
    for case in cases:
        m = json.loads(json.dumps(manifest))
        a = m['apps'][0]
        replaced, extra = {}, []
        if case in ('undeclared-dir', 'forbidden-path'):
            path, number = ('woowbk-d5-planted-undeclared', 9) if case == 'undeclared-dir' else ('.config/systemd/user', 8)
            entry = 'apps/%s/dirs/%d.tar' % (a['id'], number)
            local = os.path.join(work, case + '.dir.tar')
            small_dir_tar(local, tag + '-' + case + '.service')
            a['data_dirs'].append({'path': path, 'entry': entry})
            extra.append((entry, local))
            crafted_dir = local
        else:
            local = os.path.join(work, case + '.dir.tar')
            kept = write_hostile(original, local, case, tag, home)
            replaced[target['entry']] = local
            crafted_dir = local
        entries = [dict(e) for e in m['entries']]
        for e in entries:
            if e['path'] in replaced:
                e['sha256'], e['size'] = digest(replaced[e['path']])
        for entry, local in extra:
            sha, size = digest(local)
            entries.append({'path': entry, 'size': size, 'sha256': sha})
        m['entries'] = entries
        now = time.gmtime()
        new_id = time.strftime('%Y%m%dT%H%M%SZ', now) + '-' + secrets.token_hex(4)
        created = time.strftime('%Y-%m-%dT%H:%M:%SZ', now)
        m.update(backup_id=new_id, created=created, note='D5 ' + case)
        data = json.dumps(m, ensure_ascii=False, separators=(',', ':')).encode()
        new_plain = os.path.join(work, 'plain.new.tar')
        sizes = {e['path']: e['size'] for e in entries}
        with open(new_plain, 'wb') as out_file, tarfile.open(fileobj=out_file, mode='w', format=tarfile.PAX_FORMAT) as out:
            out.addfile(outer('manifest.json', len(data)), __import__('io').BytesIO(data))
            for member in members[1:]:
                if member.name in replaced:
                    with open(replaced[member.name], 'rb') as handle:
                        out.addfile(outer(member.name, sizes[member.name]), handle)
                else:
                    out.addfile(outer(member.name, member.size), plain.extractfile(member))
            for entry, local in extra:
                with open(local, 'rb') as handle:
                    out.addfile(outer(entry, sizes[entry]), handle)
        header = {'format': 1, 'backup_id': new_id, 'created': created, 'key_id': old_header['key_id'],
                  'encryption': 'age-x25519', 'compression': 'zstd'}
        out_path = os.path.join(work, case + '.woowbackup')
        with open(out_path, 'wb') as sink:
            sink.write(b'WOOWTECH-BACKUP/1\n' + json.dumps(header, separators=(',', ':')).encode() + b'\n')
            sink.flush()
            with open(new_plain, 'rb') as src:
                pipeline([['zstd', '-q', '-c', '-3'], ['age', '-e', '-r', recipient]], src, sink)
        report['cases'][case] = {'backup_id': new_id, 'path': out_path, 'size': os.path.getsize(out_path),
                                 'engine_verdict': verdict(crafted_dir, ids)}
        os.unlink(new_plain)
        os.unlink(crafted_dir)
    plain.close()
finally:
    keep = {os.path.basename(case['path']) for case in report['cases'].values()}
    for name in os.listdir(work):
        if name not in keep:
            os.unlink(os.path.join(work, name))
print(json.dumps(report))
'''

# expected outcome: 'refused' (failed before any change) or 'ignored' (refused, or restored without writing the path)
D5_CASES = {
    'symlink-abs-below': 'refused', 'symlink-rel-below': 'refused', 'absolute-member': 'refused',
    'dotdot-member': 'refused', 'pax-path-dotdot': 'refused', 'below-file': 'refused', 'hardlink-outside': 'refused',
    'device-member': 'refused', 'unmapped-owner': 'refused', 'duplicate-member': 'refused',
    'undeclared-dir': 'ignored', 'forbidden-path': 'ignored',
}
# Why the engine's nested checks (woowbackup/nested.py, `details.reason`) must refuse each hostile directory tar: its
# own defect, not something else in it. A symlink that merely points outside is allowed in a host directory (kept as
# a link, never followed; the fixture has one), so the escaping links only fail because a member lies below them.
BELOW = 'member below a symlink, hard link or file'
DOTDOT = 'member name with an empty, "." or ".." component'
D5_REASONS = {
    'symlink-abs-below': BELOW, 'symlink-rel-below': BELOW, 'absolute-member': 'absolute member name',
    'dotdot-member': DOTDOT, 'pax-path-dotdot': DOTDOT, 'below-file': BELOW,
    'hardlink-outside': 'absolute member name', 'device-member': 'member type not allowed (device, sparse or unknown)',
    'unmapped-owner': 'owner id outside the user namespace', 'duplicate-member': 'duplicate member',
}
# Engines before host-directory support only have the volume rules, which refuse any symlink that leaves the tree.
OLD_RULE = 'symlink pointing outside the volume'


def volume_rules_only(verdict):
    """The installed engine has no directory checks (check_volume refused the fixture's outside symlink)."""
    return verdict.get('checker') == 'check_volume' and verdict.get('reason') == OLD_RULE


def config_listing(dev):
    """Names, sizes and sha256 of the owner's ~/.config/systemd/user and ~/.config/containers files."""
    script = ('cd "$HOME"/.config && find systemd/user containers -xdev \\( -type f -o -type l \\) '
              '-printf "%y %s %p -> %l\\n" 2>/dev/null | sort; find systemd/user containers -xdev -type f '
              '-exec sha256sum {} + 2>/dev/null | sort; true')
    return owner(dev, 'sh', '-c', script).stdout.decode()


def outcome(job):
    phases = phase_states(job)
    if (job['state'] == 'failed' and phases.get('safety') == 'pending' and phases.get('stop') == 'pending'
            and (job.get('result') or {}).get('changed') is not True):
        return 'refused'
    return job['state']


def d5_case(ev, dev, case, meta, baseline):
    expect = D5_CASES[case]
    record = {'case': case, 'expect': expect, 'engine_verdict': meta['engine_verdict']}
    backup_id = meta['backup_id']
    before_ids = backup_ids(dev, ev)
    _begin, (_rc, reply) = e2e.upload_file(dev, meta['file'], ev=ev, filename=f'd5-{case}{Path(meta["file"]).suffix}')
    if not ev.check(f'D5 {case}: upload-finish accepts it (outer header, age header and size are valid)',
                    reply.get('ok') and reply['backup']['id'] == backup_id, reply.get('error')):
        return record
    _rc, inspected = helper(dev, 'inspect', {'backup_id': backup_id}, ev=ev)
    record['inspect'] = inspected['error']['code'] if not inspected.get('ok') else {
        'preflight_ok': inspected['preflight']['ok'],
        'checks': [f'{c["status"]}:{c["message"]}' for a in inspected['preflight']['apps'] for c in a['checks']
                   if c['status'] != 'ok']}
    job, log = restore(dev, ev, backup_id, label=f'restore[d5-{case}]', timeout=900)
    record.update(outcome=outcome(job), error=job.get('error'), phases=phase_states(job))
    if expect == 'refused':
        ev.check(f'D5 {case}: restore refused before any change ({"/".join(REFUSED_CODES)}; safety and stop never ran)',
                 record['outcome'] == 'refused' and (job.get('error') or {}).get('code') in REFUSED_CODES,
                 {'state': job['state'], 'error': job.get('error'), 'phases': phase_states(job)})
        text = job_text(job, log)
        ev.check(f'D5 {case}: the refusal is about the host directory (names it or 主機資料夾)',
                 DATA_DIR in text or '主機資料夾' in text, (job.get('error') or {}).get('message'))
        ev.check(f'D5 {case}: data, both directories and the app are unchanged; units active',
                 compare(summary(dev), baseline['summary']) == {} and entries_of(dev, DATA_DIR) == baseline['data']
                 and engine_app(dev, ev)[1]['state'] == 'running')
        ev.check(f'D5 {case}: no backup listed except the upload (no safety backup taken)',
                 backup_ids(dev, ev) - before_ids == {backup_id}, sorted(backup_ids(dev, ev) - before_ids))
    else:
        ev.check(f'D5 {case}: refused before any change, or restored while ignoring the undeclared directory',
                 record['outcome'] in ('refused', 'succeeded'), {'state': job['state'], 'error': job.get('error')})
        if record['outcome'] == 'succeeded':
            ev.check(f'D5 {case}: restored data equals the base backup (= state before D5)',
                     compare(summary(dev), baseline['summary']) == {} and entries_of(dev, DATA_DIR) == baseline['data'])
    found = canaries(dev, D5_TAG)
    ev.check(f'D5 {case}: no {D5_TAG} path anywhere on the device', found == [], found)
    ev.check(f"D5 {case}: the owner's ~/.config/systemd/user and ~/.config/containers are unchanged",
             config_listing(dev) == baseline['config'])
    ev.check(f'D5 {case}: no siblings, staging empty, no job keys, no orphan archives',
             not leftover_siblings(dev) and staging_empty(dev) and no_job_keys(dev) and orphans(dev) == [],
             {'siblings': leftover_siblings(dev), 'orphans': orphans(dev)})
    return record


def scenario_d5(ev):
    dev = 'a'
    cases = [c for c in os.environ.get('D5_CASES', '').split(',') if c] or list(D5_CASES)
    status = ok(dev, 'status', ev=ev)
    ev.require('D5 dev-a: device key, no active job, app running', status['key'] and status['active_job'] is None
               and engine_app(dev, ev)[1]['state'] == 'running', status.get('key'))
    ev.require('D5 no canary paths and no siblings before the scenario',
               canaries(dev, D5_TAG) == [] and not leftover_siblings(dev))
    created = []
    try:
        job, _log = backup(dev, ev, 'D5 惡意主機資料夾的基礎備份', label='backup[d5-base]')
        base_id = job['result']['backup_id']
        created.append(base_id)
        sh(dev, f'rm -rf {D5_WORK}', check=False)
        proc = py(dev, CRAFT_D5, base_id, D5_WORK, D5_TAG, HOME, DATA_DIR, ','.join(cases), timeout=1800, check=False)
        if proc.returncode != 0:
            raise Failed(f'D5 craft failed rc={proc.returncode}: {redact(proc.stderr.decode("utf-8", "replace")[-600:])}')
        crafted = json.loads(proc.stdout)
        work = private_dir(WORK / 'd5')
        for case, meta in crafted['cases'].items():
            local = work / f'{case}{".tar" if meta["path"].endswith(".tar") else ".woowbackup"}'
            write_private_stream(dev, meta['path'], local)
            meta.update(file=str(local), host_size=local.stat().st_size)
            created.append(meta['backup_id'])
        sh(dev, f'rm -rf {D5_WORK}', check=False)
        ev.save('d5-crafted', crafted)
        ev.log(f'D5 base dir tar {crafted["entry"]}: {crafted["dir_members"]} members, name prefix '
               f'{crafted["name_prefix"]!r}, engine verdict {crafted["original_verdict"]}')
        ev.check('D5 crafting: the unmodified directory tar passes the installed engine checks',
                 crafted['original_verdict'].get('accepted') is True, crafted['original_verdict'])
        for case, meta in crafted['cases'].items():
            if D5_CASES[case] == 'refused':
                ev.check(f'D5 crafting: the installed engine refuses the {case} tar for its own defect '
                         f'({meta["engine_verdict"].get("reason")})', meta['engine_verdict'].get('accepted') is False
                         and meta['engine_verdict'].get('reason') == D5_REASONS[case], meta['engine_verdict'])
        baseline = {'summary': summary(dev), 'data': entries_of(dev, DATA_DIR), 'config': config_listing(dev)}
        results = []
        for case in cases:
            try:
                results.append(d5_case(ev, dev, case, crafted['cases'][case], baseline))
            except Failed as error:
                ev.check(f'D5 {case}: case ran to completion', False, str(error))
                results.append({'case': case, 'aborted': str(error)})
            finally:
                ev.save('d5-cases', results)
        return {'cases': {r['case']: r.get('outcome') for r in results}}
    finally:
        for backup_id in created:
            delete_backup(dev, backup_id, ev)
        sh(dev, f'rm -rf {D5_WORK}', check=False)
        ev.check('D5 cleanup: app running, staging empty, no orphans, work directory removed',
                 engine_app(dev, ev)[1]['state'] == 'running' and staging_empty(dev) and orphans(dev) == []
                 and sh(dev, f'test -e {D5_WORK}', check=False).returncode != 0)


# ------------------------------------------------------------------ scenario: d6 fresh-mode conflict

def scenario_d6(ev):
    source = source_backup(ev)
    secret = kit_secret()
    teardown('b', ev)
    ev.require('D6 dev-b is a fresh target', footprint('b') == [], footprint('b'))
    ensure_uploaded('b', source, ev)
    results = {}
    for rel in (DATA_DIR, PG_DIR):
        keep = f'{HOME}/{rel}/woowbk-d6-keep.txt'
        owner('b', 'sh', '-c', f'mkdir -p "{HOME}/{rel}" && printf "existing data, keep\\n" > "{keep}"')
        before = {'footprint': footprint('b'), 'listing': entries_of('b', rel)}
        inspected = ok('b', 'inspect', {'backup_id': source['backup_id'], 'key': secret}, ev=ev)
        papp = inspected['preflight']['apps'][0]
        failing = [c for c in papp['checks'] if c['status'] == 'fail']
        ev.check(f'D6 {rel}: preflight (fresh) refuses the existing non-empty directory and names it',
                 papp['mode'] == 'fresh' and not papp['restorable'] and any(rel in c['message'] for c in failing),
                 failing or papp)
        job, log = restore('b', ev, source['backup_id'], key=secret, label=f'restore[d6-{Path(rel).name}]')
        ev.check(f'D6 {rel}: restore job fails in preflight with incompatible, nothing destructive ran',
                 outcome(job) == 'refused' and (job.get('error') or {}).get('code') == 'incompatible'
                 and phase_states(job).get('preflight') == 'failed', {'error': job.get('error'),
                                                                     'phases': phase_states(job)})
        after = {'footprint': footprint('b'), 'listing': entries_of('b', rel)}
        ev.check(f'D6 {rel}: nothing deleted or created (directory content, quadlets, secrets, settings, other dir)',
                 after == before, {'before': before['footprint'], 'after': after['footprint']})
        ev.check(f'D6 {rel}: no siblings, staging empty, no job keys',
                 not leftover_siblings('b') and staging_empty('b') and no_job_keys('b'))
        results[rel] = {'checks': failing, 'job': job['id']}
        owner('b', 'sh', '-c', f'rm -rf "{HOME}/{PARENTS[DIRS.index(rel)]}"')
    # An existing EMPTY directory: recorded only (the docs say it is accepted; the spec only refuses non-empty ones).
    owner('b', 'mkdir', '-p', f'{HOME}/{DATA_DIR}')
    inspected = ok('b', 'inspect', {'backup_id': source['backup_id'], 'key': secret}, ev=ev)
    papp = inspected['preflight']['apps'][0]
    results['empty-dir'] = {'restorable': papp['restorable'],
                            'checks': [f'{c["status"]}:{c["message"]}' for c in papp['checks'] if c['status'] != 'ok']}
    ev.log(f'D6 existing empty {DATA_DIR}: restorable={papp["restorable"]} {results["empty-dir"]["checks"]}')
    owner('b', 'sh', '-c', f'rm -rf "{HOME}/{PARENTS[1]}"')
    ev.check('D6 dev-b left as a fresh target', footprint('b') == [], footprint('b'))
    ev.save('d6-results', results)
    return results


# ------------------------------------------------------------------ scenario: d7 mount points and other containers

D7_MOUNT = f'{DATA_DIR}/woowbk-d7-mount'
D7_READER = 'woowbk-d7-reader'


def d7_mount(dev, how):
    """As root in the device: 'tmpfs' below the data dir, 'bind' the data dir onto itself (one filesystem: the same
    device, another mount id), or 'off'. The app keeps working on the same inodes throughout."""
    if how == 'tmpfs':
        owner(dev, 'podman', 'unshare', 'mkdir', '-p', f'{HOME}/{D7_MOUNT}')
        sh(dev, f'mount -t tmpfs -o size=1m tmpfs "{HOME}/{D7_MOUNT}"')
    elif how == 'bind':
        sh(dev, f'mount --bind "{HOME}/{DATA_DIR}" "{HOME}/{DATA_DIR}"')
    else:
        sh(dev, f'umount "{HOME}/{D7_MOUNT}" 2>/dev/null; umount "{HOME}/{DATA_DIR}" 2>/dev/null; true', check=False)
        owner(dev, 'podman', 'unshare', 'rmdir', f'{HOME}/{D7_MOUNT}', check=False)


def d7_reader(dev, mode):
    """A container outside the app that bind-mounts the data dir ('ro' or 'rw'); None removes it."""
    owner(dev, 'podman', 'rm', '-f', '-t', '0', D7_READER, check=False)
    if mode:
        spec = f'{HOME}/{DATA_DIR}:/data' + (':ro' if mode == 'ro' else '')
        owner(dev, 'podman', 'run', '-d', '--name', D7_READER, '--entrypoint', 'sleep', '-v', spec,
              'localhost/woowbk-dirs-app:1', '900')


def d7_refused_backup(dev, ev, label, needles):
    """A backup that must fail as incompatible naming `needles`, before any writer was stopped."""
    start = ok(dev, 'backup-start', {'apps': [APP], 'include_images': False, 'note': f'D7 {label}',
                                     'request_id': request_id()}, ev=ev)
    job, log = wait_job(dev, start['job_id'], ev=ev, timeout=600, label=f'backup[d7-{label}]')
    save_job(ev, f'backup[d7-{label}]', job, log)
    error = job.get('error') or {}
    ev.check(f'D7 {label}: backup refused (incompatible) naming the cause, and no writer was stopped',
             job['state'] == 'failed' and error.get('code') == 'incompatible'
             and all(n in error.get('message', '') for n in needles) and '暫停寫入服務' not in job_text(job, log),
             {'state': job['state'], 'error': error})


def d7_preflight(dev, ev, backup_id, label, check_id, needles):
    """The restore preflight of `backup_id` must refuse with `check_id` naming `needles` (None: restorable)."""
    papp = ok(dev, 'inspect', {'backup_id': backup_id}, ev=ev)['preflight']['apps'][0]
    failing = [c for c in papp['checks'] if c['status'] == 'fail']
    if check_id is None:
        ev.check(f'D7 {label}: restore preflight passes', papp['restorable'] and not failing, failing)
        return
    ev.check(f'D7 {label}: restore preflight refuses it ({check_id})',
             not papp['restorable'] and any(c['id'].split('/', 1)[1].startswith(check_id)
                                            and all(n in c['message'] for n in needles) for c in failing), failing)


def scenario_d7(ev):
    dev = 'a'
    ev.require('D7 no leftover siblings before the scenario', not leftover_siblings(dev), leftover_siblings(dev))
    ev.require('D7 app healthy before the scenario', wait_healthy(dev, 120))
    job, _log = backup(dev, ev, 'D7 基準備份', label='backup[d7-base]')
    backup_id = job['result']['backup_id']
    made = [backup_id]
    try:
        # Review M2: a mount point below the directory (tar stays on one filesystem; the replaced copy would be
        # deleted together with it) and the directory itself a mount point (it cannot be renamed); the bind mount
        # onto itself keeps the device number, only the mount id differs.
        for how, backup_needle, check_id, preflight_needle in (
                ('tmpfs', f'中有掛載點（~/{D7_MOUNT}）', 'dir-mounts', f'中有掛載點（~/{D7_MOUNT}）'),
                ('bind', f'主機資料夾 ~/{DATA_DIR} 是掛載點', 'dir-target', f'~/{DATA_DIR} 是掛載點')):
            d7_mount(dev, how)
            try:
                d7_refused_backup(dev, ev, f'mount-{how}', [backup_needle])
                d7_preflight(dev, ev, backup_id, f'mount-{how}', check_id, [preflight_needle])
            finally:
                d7_mount(dev, 'off')
            ev.check(f'D7 mount-{how}: app still healthy (nothing was stopped)', wait_healthy(dev, 60))
        # Review M5: another container using the directory. Read-only it cannot make a backup inconsistent, but a
        # restore would leave it on the replaced (then deleted) copy; read-write it fails both.
        d7_reader(dev, 'ro')
        try:
            job, _log = backup(dev, ev, 'D7 唯讀掛載的其他容器', label='backup[d7-reader-ro]')
            made.append(job['result']['backup_id'])
            ev.check('D7 reader-ro: a read-only reader does not block a backup', job['state'] == 'succeeded')
            d7_preflight(dev, ev, backup_id, 'reader-ro', 'dir-in-use', [f'容器 {D7_READER} 掛載了主機資料夾 ~/{DATA_DIR}'])
            d7_reader(dev, 'rw')
            d7_refused_backup(dev, ev, 'reader-rw', [f'容器 {D7_READER} 以可寫入方式掛載了主機資料夾 ~/{DATA_DIR}',
                                                     'writer_units'])
            d7_preflight(dev, ev, backup_id, 'reader-rw', 'dir-in-use', [D7_READER])
        finally:
            d7_reader(dev, None)
        d7_preflight(dev, ev, backup_id, 'all clear', None, [])
        ev.check('D7 app healthy, no siblings, staging empty, no job keys after the scenario',
                 wait_healthy(dev, 60) and not leftover_siblings(dev) and staging_empty(dev) and no_job_keys(dev))
    finally:
        d7_mount(dev, 'off')
        d7_reader(dev, None)
        for made_id in made:
            delete_backup(dev, made_id, ev)
    return {'backup_id': backup_id}


# ------------------------------------------------------------------ scenario: leaks

def scenario_leaks(ev):
    scan = e2e.LEAK_SCAN.replace("('woowbk-demo-db-password', 'woowbk-demo-app-key')", repr(SECRET_NAMES))
    if scan == e2e.LEAK_SCAN:
        raise Failed('cli_e2e.LEAK_SCAN changed: cannot point it at the woowbk-dirs secrets')
    for dev in ('a', 'b'):
        proc = sh(dev, f'python3 -I - {e2e.DEVICES[dev]["uid"]}', input=scan.encode(), timeout=300)
        report = json.loads(proc.stdout)
        ev.save(f'leaks-dev-{dev}', report)
        ev.check(f'dev-{dev}: no woowbk-dirs secret or age key in job records/logs/index/requests/journal '
                 f'({len(report["needles"])} needles, {report["files_scanned"]} files)', report['hits'] == {}, report['hits'])
        ev.check(f'dev-{dev}: no transient key files and no staging left',
                 not any(n.startswith('key-') for n in report['run_dir']) and report['staging'] == [],
                 {'run': report['run_dir'], 'staging': report['staging']})
    secret = kit_secret() if KIT_FILE.exists() else None
    hits = []
    for base, _dirs, names in os.walk(DIRS_EVIDENCE):
        for name in names:
            data = Path(base, name).read_bytes()
            if SECRET_RE.search(data.decode('utf-8', 'replace')) or (secret and secret.encode() in data):
                hits.append(str(Path(base, name)))
    ev.check('host evidence (dirs) contains no key material', hits == [], hits)
    return {}


# ------------------------------------------------------------------ scenario: selftest (no engine feature needed)

def selftest_kill_tree(ev, dev):
    """KILL_WATCH's process-tree kill against a stand-in unit whose owner child lives in another cgroup."""
    unit = f'woowbk-d4-selftest-{os.urandom(3).hex()}'
    marker = str(int.from_bytes(os.urandom(3), 'big') + 100000)  # a unique `sleep` length to find the processes
    script = f'sleep {marker} & /usr/local/bin/woowbk-owner podman unshare sleep {marker} & wait'
    sh(dev, f'systemd-run --unit={unit} --collect --quiet --property=KillMode=mixed sh -c \'{script}\'')
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        count = len(sh(dev, f'pgrep -f "^sleep {marker}$" || true').stdout.split())
        if count >= 2:
            break
        time.sleep(0.5)
    cgroups = sh(dev, f'for p in $(pgrep -f "^sleep {marker}$"); do cat /proc/$p/cgroup; done').stdout.decode()
    ev.log(f'selftest unit {unit}: sleeps running in cgroups {cgroups.split()}')
    ev.check('selftest: the stand-in job has a child outside its own cgroup (podman moved it to a user scope)',
             len(set(cgroups.split())) >= 2, cgroups)
    # Same trigger machinery, driven by a stand-in job record (outside the engine's data) that says phase "start".
    record = f'/var/tmp/woowbk-d4-selftest-{marker}.json'
    sh(dev, f'printf \'{{"state":"running","phase":"start"}}\' > {record}')
    try:
        proc = subprocess.run([LP, 'exec', '-i', dev_name(dev), 'python3', '-I', '-', 'jselftest', 'after-swap', HOME,
                               '30', ','.join(DIRS), DATA_DIR, record, f'{unit}.service'], input=KILL_WATCH.encode(),
                              capture_output=True, timeout=120)
        report = json.loads(proc.stdout.decode().strip().splitlines()[-1])
    finally:
        sh(dev, f'rm -f {record}', check=False)
    time.sleep(1)
    left = sh(dev, f'pgrep -f "^sleep {marker}$" || true').stdout.split()
    active = sh(dev, f'systemctl is-active {unit}.service || true', check=False).stdout.decode().strip()
    ev.check('selftest: the watcher killed every process of the stand-in job, including the one in another cgroup',
             report.get('triggered') and report.get('killed', 0) >= 3 and left == [] and active != 'active',
             {'report': report, 'left': left, 'unit': active})
    sh(dev, f'systemctl reset-failed {unit}.service 2>/dev/null || true', check=False)


def selftest_injection(ev, dev):
    scratch = f'{HOME}/woowbk-d4-scratch'
    owner(dev, 'sh', '-c', f'rm -rf "{scratch}" && mkdir -p "{scratch}/x/a" "{scratch}/x.woowbk-new-jself/a"')
    try:
        first = json.loads(owner(dev, 'python3', '-I', '-c', INJECT_BETWEEN, f'{scratch}/x').stdout)
        names = owner(dev, 'ls', '-A', scratch).stdout.decode().split()
        ev.check('selftest: injection after a kill before rename 1 leaves <path> missing with old + new siblings',
                 names == ['x.woowbk-new-jself', 'x.woowbk-old-jself'], {'report': first, 'names': names})
        owner(dev, 'sh', '-c', f'cd "{scratch}" && mv x.woowbk-new-jself x')  # as if rename 2 had happened
        second = json.loads(owner(dev, 'python3', '-I', '-c', INJECT_BETWEEN, f'{scratch}/x').stdout)
        names = owner(dev, 'ls', '-A', scratch).stdout.decode().split()
        ev.check('selftest: injection after a kill after rename 2 undoes it (same between-renames state)',
                 names == ['x.woowbk-new-jself', 'x.woowbk-old-jself'], {'report': second, 'names': names})
    finally:
        owner(dev, 'rm', '-rf', scratch)


SELFTEST_HOSTILE = r'''
import json, os, subprocess, sys, tarfile
sys.path.insert(0, '/usr/local/lib/woowtech-cockpit-backup')
sys.dont_write_bytecode = True
from woowbackup import nested
from woowbackup.errors import BackupError
''' + HOSTILE + VERDICT + r'''
source, work, tag, home = sys.argv[1:5]
cases = sys.argv[5].split(',')
ids = owner_ids()
out = {'original': verdict(source, ids), 'prefix': name_prefix(source), 'cases': {}}
for case in cases:
    dest = os.path.join(work, case + '.tar')
    kept = write_hostile(source, dest, case, tag, home)
    out['cases'][case] = dict(verdict(dest, ids), kept=kept)
    os.unlink(dest)
print(json.dumps(out))
'''


# Root inside dev-a: a synthetic backup in the shape the engine writes for this app (manifest with `data_dirs`, the data
# dir as a GNU tar made in the owner's namespace, a dummy PostgreSQL dir tar and a dummy secret), encrypted to the
# device recipient, in a work directory outside the engine's data. Only for the crafting self-test.
SYNTH = r'''
import glob, hashlib, io, json, os, pwd, secrets, subprocess, sys, tarfile, time
work, home, data_dir, pg_dir = sys.argv[1:5]
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
os.makedirs(work, 0o700)
keyfiles = sorted(glob.glob('/etc/woowtech-cockpit/backup/keys/device-*.key'))
if len(keyfiles) != 1:
    raise SystemExit('need exactly one device key')
recipient = subprocess.run(['age-keygen', '-y', keyfiles[0]], capture_output=True, env=ENV,
                           check=True).stdout.decode().split()[0]
uid = pwd.getpwnam('appowner').pw_uid
owner_env = ['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'HOME=' + home, 'LANG=C.UTF-8', 'XDG_RUNTIME_DIR=/run/user/%d' % uid,
             'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus' % uid]
dir1 = os.path.join(work, 'dir1.tar')
with open(dir1, 'wb') as out:
    code = subprocess.run(['/usr/sbin/runuser', '-u', 'appowner', '--', *owner_env, 'podman', 'unshare', 'tar', '--create',
                           '--file=-', '--format=posix', '--numeric-owner', '--xattrs', '-C', os.path.join(home, data_dir),
                           '.'], stdout=out, cwd=home).returncode
if code:
    raise SystemExit('tar of the data dir failed: %d' % code)
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tar:
    root = tarfile.TarInfo('./')
    root.type, root.mode, root.uid, root.gid = tarfile.DIRTYPE, 0o700, 70, 70
    tar.addfile(root)
members = [('apps/woowbk-dirs/dirs/0.tar', buf.getvalue()), ('apps/woowbk-dirs/dirs/1.tar', open(dir1, 'rb').read()),
           ('apps/woowbk-dirs/secrets/woowbk-dirs-app-key', b'synthetic self-test value, not a secret')]
now = time.gmtime()
backup_id = time.strftime('%Y%m%dT%H%M%SZ', now) + '-' + secrets.token_hex(4)
created = time.strftime('%Y-%m-%dT%H:%M:%SZ', now)
manifest = {'format': 1, 'backup_id': backup_id, 'created': created, 'type': 'manual', 'note': 'dirs_e2e selftest',
            'key_id': 'SELF-TEST-0000-0000', 'tool': {'name': 'dirs_e2e', 'version': '0'},
            'source': {'hostname': 'selftest'}, 'consistency': {'method': 'writers-stopped', 'downtime_seconds': 0},
            'apps': [{'id': 'woowbk-dirs', 'name': 'selftest', 'adapter': 'quadlet-postgres', 'adapter_version': 1,
                      'catalog_sha256': '0' * 64, 'owner': {'name': 'appowner', 'uid': uid}, 'images': [], 'postgres': [],
                      'volumes': [], 'data_dirs': [{'path': pg_dir, 'entry': members[0][0]},
                                                   {'path': data_dir, 'entry': members[1][0]}],
                      'secrets': [{'name': 'woowbk-dirs-app-key', 'entry': members[2][0]}], 'config_files': [],
                      'quadlet_files': [], 'verify_snapshot': {}}],
            'entries': [{'path': n, 'size': len(d), 'sha256': hashlib.sha256(d).hexdigest()} for n, d in members]}
plain = io.BytesIO()
with tarfile.open(fileobj=plain, mode='w', format=tarfile.PAX_FORMAT) as tar:
    for name, data in [('manifest.json', json.dumps(manifest).encode())] + members:
        info = tarfile.TarInfo(name)
        info.size, info.mode = len(data), 0o600
        tar.addfile(info, io.BytesIO(data))
packed = subprocess.run(['zstd', '-q', '-c', '-3'], input=plain.getvalue(), capture_output=True, env=ENV, check=True).stdout
cipher = subprocess.run(['age', '-e', '-r', recipient], input=packed, capture_output=True, env=ENV, check=True).stdout
header = {'format': 1, 'backup_id': backup_id, 'created': created, 'key_id': manifest['key_id'],
          'encryption': 'age-x25519', 'compression': 'zstd'}
path = os.path.join(work, 'src.woowbackup')
with open(path, 'wb') as out:
    out.write(b'WOOWTECH-BACKUP/1\n' + json.dumps(header).encode() + b'\n' + cipher)
os.unlink(dir1)
print(json.dumps({'path': path, 'backup_id': backup_id, 'dir_members': len(tarfile.open(fileobj=io.BytesIO(members[1][1])).getmembers())}))
'''

# Root inside dev-a: decrypt each crafted archive with the device key and check it is internally consistent (header and
# manifest ids, manifest first, entries == members with sizes and sha256) and carries its defect; plaintext deleted.
VERIFY_CRAFTED = r'''
import glob, hashlib, io, json, os, shutil, subprocess, sys, tarfile
files, work, data_dir = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3]
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
key = sorted(glob.glob('/etc/woowtech-cockpit/backup/keys/device-*.key'))[0]
os.mkdir(work, 0o700)
out = {}
try:
    for case, path in files.items():
        with open(path, 'rb') as handle:
            magic, header, cipher = handle.readline(), json.loads(handle.readline()), handle.read()
        plain = subprocess.run(['age', '-d', '-i', key], input=cipher, capture_output=True, env=ENV, check=True).stdout
        plain = subprocess.run(['zstd', '-d', '-c', '-q'], input=plain, capture_output=True, env=ENV, check=True).stdout
        tar = tarfile.open(fileobj=io.BytesIO(plain), mode='r:')
        members = tar.getmembers()
        manifest = json.loads(tar.extractfile(members[0]).read())
        listed = [(e['path'], e['size'], e['sha256']) for e in manifest['entries']]
        actual = [(m.name, m.size, hashlib.sha256(tar.extractfile(m).read()).hexdigest()) for m in members[1:]]
        app = manifest['apps'][0]
        target = next(d['entry'] for d in app['data_dirs'] if d['path'] == data_dir)
        inner = tarfile.open(fileobj=tar.extractfile(target), mode='r:')
        names = [m.name for m in inner.getmembers()]
        out[case] = {'magic': magic == b'WOOWTECH-BACKUP/1\n', 'ids': header['backup_id'] == manifest['backup_id'],
                     'manifest_first': members[0].name == 'manifest.json', 'entries_match': listed == actual,
                     'dir_paths': [d['path'] for d in app['data_dirs']], 'dir_members': len(names), 'last_names': names[-2:]}
finally:
    shutil.rmtree(work, ignore_errors=True)
print(json.dumps(out))
'''


def selftest_craft(ev, dev):
    """CRAFT_D5 end to end on a synthetic archive (device key, plaintext never leaves the device)."""
    work = '/var/tmp/woowbk-d5-selftest-craft'
    sh(dev, f'rm -rf {work}')
    try:
        synth = json.loads(py(dev, SYNTH, work, HOME, DATA_DIR, PG_DIR, timeout=300).stdout)
        proc = py(dev, CRAFT_D5, synth['backup_id'], f'{work}/out', D5_TAG, HOME, DATA_DIR, ','.join(D5_CASES),
                  synth['path'], timeout=900)
        crafted = json.loads(proc.stdout)
        files = {case: meta['path'] for case, meta in crafted['cases'].items()}
        report = json.loads(py(dev, VERIFY_CRAFTED, json.dumps(files), f'{work}/verify', DATA_DIR, timeout=900).stdout)
        leftovers = sh(dev, f'find {work} -type f ! -name "*.woowbackup" | wc -l').stdout.decode().strip()
    finally:
        sh(dev, f'rm -rf {work}', check=False)
    ev.save('selftest-craft', {'synthetic': synth, 'crafted': crafted, 'verified': report})
    original = crafted['original_verdict']
    old_engine = volume_rules_only(original)
    ev.check('selftest: crafting decrypted the synthetic backup and wrote one archive per case',
             sorted(files) == sorted(D5_CASES) and crafted['dir_members'] == synth['dir_members']
             and (original.get('accepted') is True or old_engine), {k: crafted[k] for k in ('entry', 'dir_members',
                                                                                            'name_prefix')})
    if old_engine:
        ev.log('selftest: the installed engine has no host-directory checks yet; its volume rules refuse the data dir '
               f'because of {OUTSIDE_LINK[0]} -> {OUTSIDE_LINK[1]}, so the refusals below are not specific to each case '
               'until the new engine is installed (deploy-src.sh)')
    ev.check('selftest: crafting left no plaintext in its work directory', leftovers == '0', leftovers)
    for case, info in report.items():
        defect = (info['dir_paths'][-1] in ('woowbk-d5-planted-undeclared', '.config/systemd/user')
                  if D5_CASES[case] == 'ignored' else
                  info['dir_members'] > synth['dir_members'] or case == 'duplicate-member')
        ev.check(f'selftest: crafted {case}: consistent (header/manifest ids, manifest first, entries = members with '
                 f'size and sha256) and carries its defect {info["last_names"] if D5_CASES[case] != "ignored" else info["dir_paths"][-1]}',
                 info['magic'] and info['ids'] and info['manifest_first'] and info['entries_match'] and defect, info)
        verdict = crafted['cases'][case]['engine_verdict']
        if D5_CASES[case] == 'refused':
            ev.check(f'selftest: crafted {case}: the installed nested checks refuse its directory tar '
                     f'({verdict.get("reason")})', verdict.get('accepted') is False
                     and (old_engine or verdict.get('reason') == D5_REASONS[case]), verdict)


def selftest_hostile(ev, dev):
    """The d5 builders against a real tar of the data dir (made in the owner's namespace, like an export) and the
    installed engine's volume rules, which the directory checks share."""
    work = '/var/tmp/woowbk-d5-selftest'
    sh(dev, f'rm -rf {work} && mkdir -m 0700 {work}')
    try:
        tar = owner(dev, 'podman', 'unshare', 'tar', '--numeric-owner', '--xattrs', '--xattrs-include=user.*', '-C',
                    f'{HOME}/{DATA_DIR}', '-cf', '-', '.', timeout=300).stdout
        sh(dev, f'cat > {work}/dir.tar', input=tar)
        cases = [c for c, kind in D5_CASES.items() if kind == 'refused']
        report = json.loads(py(dev, SELFTEST_HOSTILE, f'{work}/dir.tar', work, D5_TAG, HOME, ','.join(cases)).stdout)
    finally:
        sh(dev, f'rm -rf {work}', check=False)
    ev.save('selftest-hostile', report)
    old_engine = volume_rules_only(report['original'])
    if old_engine:
        ev.log('selftest: installed engine without host-directory checks: its volume rules refuse the real data dir tar '
               f'({OUTSIDE_LINK[0]} points outside); per-case reasons are only checked with the new engine')
    else:
        ev.check('selftest: a real tar of the data dir (incl. a symlink that points outside) passes the installed '
                 'directory rules', report['original'].get('accepted') is True, report['original'])
    for case in cases:
        verdict = report['cases'][case]
        ev.check(f'selftest: installed rules refuse the {case} variant ({verdict.get("reason")})',
                 verdict.get('accepted') is False and verdict.get('kept', 0) > 10
                 and (old_engine or verdict.get('reason') == D5_REASONS[case]), verdict)


def selftest_d3_injection(ev, dev):
    """D3's drop-in without the engine: the database (re)starts while the data dir has no marker, refuses to start and
    stays down (no automatic restart) while it has one, and starts again once the marker is gone."""
    def active(unit):
        return owner(dev, 'systemctl', '--user', 'show', '-P', 'ActiveState', unit, check=False).stdout.decode().strip()

    d3_marker(dev, False)
    d3_inject(dev, True)
    try:
        first = owner(dev, 'systemctl', '--user', 'restart', DB_UNIT, check=False, timeout=600)
        ev.check('selftest D3: with the drop-in and no marker the database restarts (as in the safety backup)',
                 first.returncode == 0 and active(DB_UNIT) == 'active', redact(first.stderr.decode('utf-8', 'replace'))[-300:])
        d3_marker(dev, True)
        failed = owner(dev, 'systemctl', '--user', 'restart', DB_UNIT, check=False, timeout=600)
        time.sleep(5)  # an automatic restart (Restart=on-failure of the unit) would have begun by now
        states = {unit: active(unit) for unit in (DB_UNIT, APP_UNIT)}
        ev.check('selftest D3: with the marker in the data dir the database refuses to start and stays down',
                 failed.returncode != 0 and states[DB_UNIT] in ('failed', 'inactive'), states)
        n_restarts = owner(dev, 'systemctl', '--user', 'show', '-P', 'NRestarts', DB_UNIT, check=False).stdout.decode().strip()
        ev.check('selftest D3: no automatic restart attempts (Restart=no)', n_restarts == '0', n_restarts)
    finally:
        d3_marker(dev, False)
        d3_inject(dev, False)
    again = owner(dev, 'systemctl', '--user', 'start', APP_UNIT, check=False, timeout=600)
    ev.check('selftest D3: without the marker and the drop-in both units start again', again.returncode == 0
             and wait_healthy(dev, 240), redact(again.stderr.decode('utf-8', 'replace'))[-300:])
    ev.check('selftest D3: drop-in removed', owner(dev, 'test', '-e', f'{HOME}/{D3_DROPIN}', check=False).returncode != 0)


def scenario_selftest(ev):
    dev = 'a'
    ev.check('woowbk-dirs on dev-a is deployed from this working tree\'s fixture', ensure_fixture(ev, dev))
    ev.require('woowbk-dirs healthy on dev-a', wait_healthy(dev, 60))
    start = summary(dev)
    tree = app_json(dev, '/api/tree')
    found = listings(dev, DATA_DIR, PG_DIR, 'woowbk-dirs-missing')
    ev.check('selftest: the owner namespace listing of the data dir equals the app\'s /api/tree',
             found[DATA_DIR]['entries'] == tree['entries'] and found[DATA_DIR]['digest'] == tree['digest'])
    link = next((e for e in tree['entries'] if e['path'] == OUTSIDE_LINK[0]), {})
    ev.check('selftest: the data dir has the owner symlink that points outside it', link.get('type') == 'symlink'
             and link.get('target') == OUTSIDE_LINK[1] and (link.get('uid'), link.get('gid')) == (0, 0), link)
    ev.check('selftest: listing a missing path returns null', found['woowbk-dirs-missing'] is None)
    pg = found[PG_DIR]['entries']
    ev.check('selftest: PostgreSQL directory entries are all container uid 70 (root 0700)',
             pg[0]['mode'] == '0700' and all((e['uid'], e['gid']) == (70, 70) for e in pg), pg[0])
    state = dir_state(dev)
    uids, gids = id_maps(dev)
    ev.check('selftest: host view of the declared directories follows the uid map',
             state['paths'][PG_DIR]['uid'] == host_id(uids, 70) and state['paths'][DATA_DIR]['uid'] == host_id(uids, 0),
             {'state': state['paths'], 'uid_map': uids})
    ev.check('selftest: no siblings', not leftover_siblings(dev), leftover_siblings(dev))
    ev.log(f'footprint dev-a: {footprint(dev)}; dev-b: {footprint("b")}')
    selftest_injection(ev, dev)
    selftest_kill_tree(ev, dev)
    selftest_hostile(ev, dev)
    selftest_craft(ev, dev)
    selftest_d3_injection(ev, dev)
    ev.check('selftest: woowbk-dirs healthy and unchanged at the end (summary as at the start, no siblings)',
             wait_healthy(dev, 120) and compare(summary(dev), start) == {} and not leftover_siblings(dev))
    return {}


# ------------------------------------------------------------------ main

SCENARIOS = {'prep': scenario_prep, 'selftest': scenario_selftest, 'd1': scenario_d1, 'd3': scenario_d3,
             'd4': scenario_d4, 'd5': scenario_d5, 'd6': scenario_d6, 'd7': scenario_d7, 'd2': scenario_d2,
             'leaks': scenario_leaks}
ALL = ('prep', 'd1', 'd3', 'd4', 'd5', 'd6', 'd7', 'd2', 'leaks')


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('scenario', choices=[*SCENARIOS, 'all'])
    args = parser.parse_args()
    names = list(ALL) if args.scenario == 'all' else [args.scenario]
    all_ok = True
    for name in names:
        ev = Evidence(name)
        try:
            extra = SCENARIOS[name](ev) or {}
        except Failed as error:
            ev.log(f'ABORTED: {error}')
            extra = {'aborted': str(error)}
        except Exception as error:  # noqa: BLE001 - record and continue to the summary
            ev.log(f'ABORTED with {type(error).__name__}: {redact(str(error))}')
            extra = {'aborted': f'{type(error).__name__}: {redact(str(error))}'}
        all_ok = ev.finish(extra) and 'aborted' not in extra and all_ok
        if 'aborted' in extra:
            ev.log(f'SCENARIO {name} ABORTED: it did not complete, so its passed checks prove nothing about the restore')
        if not all_ok and args.scenario == 'all':
            break  # later scenarios start from the state this one leaves behind
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())
