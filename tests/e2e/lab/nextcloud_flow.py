#!/usr/bin/env python3
"""Nextcloud: real x86 showcase HA backups (add-on woow-nextcloud-office 0.2.3, encrypted) -> dev-e's INSTALLED
Nextcloud (Podman package 19a7609, Nextcloud 35.0.1) through the product's HA-import flow, exactly the helper commands
the Cockpit page sends (lane nextcloud-import, 2026-11-23).

  python3 -I tests/e2e/lab/services_a_capture.py --private=FILE <evidence.json> nextcloud-x86-noshare -- \\
      python3 -I tests/e2e/lab/nextcloud_flow.py --negative
  python3 -I tests/e2e/lab/nextcloud_flow.py --self-check      (offline; never touches a device or a secret)

--negative: the real backup WITHOUT HA's share folder (woow-b2-nextcloud-x86-enc-noshare: database, config.php and
custom apps, but none of the users' files). One hold of /tmp/woowbk-dev-e-mutation.lock; dev-e's outer isolation
(`true none {}`) before and after; the checkout committed; deploy-src.sh e --src <this tree> --no-demo-catalog and the
installed engine == this tree; Nextcloud's five units active and status.php installed, 35.0.1.1, not in maintenance.
  before   dev-e's own markers (batch2_markers.py nextcloud read: the woowbk-lab-* users and the baseline user's WebDAV
           files with their SHA-256), config.php's SHA-256, the users, the storages, the data dir's top entries
  upload   upload-begin, the fixture copied to the given path, upload-finish: the record is the fixture, nextcloud is
           importable and installed
  check    ha-check-start nextcloud (the HA key on stdin only): the job succeeds, nextcloud is NOT ok, its blocker names
           the missing share folder and /share/nextcloud, and it is the only blocker; the section equals the backup's
           facts (Nextcloud 35.0.1.1, PostgreSQL 16, users 3, file cache 300, shares 1, tokens 125, calendar objects 2,
           contacts 3, custom apps notes/richdocuments/tasks, data directory /share/nextcloud not in the backup): HA's
           real cluster was opened and read by the product
  convert  ha-convert-start nextcloud: the job fails with the same blocker, no backup is added
  after    everything of `before` is unchanged; units active; status.php the same
  cleanup  the HA store record deleted; no job container, volume, network, staging folder or key file left
  leaks    the HA key and the HA-side test credentials appear nowhere in the engine's records, uploads, staging, run dir
           or the device journal, nor in this evidence

--candidate (INTERNAL candidate, never acceptance; same fixture): the same setup, before, upload and check; then
ha-convert-start is created through the helper's own command code, but its job runs in a root process inside dev-e
where ONLY ha_nextcloud.datadir_pass is replaced (the users' files are not in this backup: the data dir gets just
`.ncdata`); the product's refusal stays in the installed engine and in every public route. It exercises the real
conversion: pg_dump of HA's real database, the new cluster from the live image/env/secret, the live role and grants,
pg_restore as that role, the storage/Office/cron fix-ups and their verification against the live database, the
PostgreSQL settings, config.php merged and parsed back by the live PHP, the html/PostgreSQL/Redis dir tars and the
packaging. The converted backup is inspected (preflight passes, the four data dirs, settings same) and deleted, never
restored; dev-e's Nextcloud must be unchanged (after), cleanup and leaks as above.

stdout carries only fixed lines (`<check>: PASS|FAIL`, the source commit, the lock time); details go to the private,
redacted evidence folder ~/.woowbk-lab/evidence/nextcloud-flow/<time>/ (0700). Not covered by --negative (stated):
a restore (the product refuses to build one), the users' files, Office, a browser.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
DEVICE = 'woowbk-dev-e'
LOCK = '/tmp/woowbk-dev-e-mutation.lock'
HOLD_BUDGET = 40 * 60
FLOOR = 12 * 1024 ** 3          # the team keeps >= 12 GiB free on the host at every moment
NEED = 1536 * 1024 ** 2         # the upload copy in dev-e plus the check's throwaway cluster, with margin
FIXTURE = (LAB / 'ha-fixtures' / '20261123-batch2' / 'x86' / 'woow-b2-nextcloud-x86-enc-noshare'
           / 'woow-b2-nextcloud-x86-enc-noshare-20261123.tar')
FIXTURE_SHA = '88e0f79415473c3453fb2889375b5fe0167e5d0a685d17da768ccc641c3c027f'
SECTION = {'nextcloud_version': '35.0.1.1', 'pg_version': '16', 'users': 3, 'files': 300, 'shares': 1, 'tokens': 125,
           'calendar_objects': 2, 'contacts': 3, 'custom_apps': ['notes', 'richdocuments', 'tasks'],
           'datadir': '/share/nextcloud', 'datadir_in_backup': False}
UNITS = ('nextcloud-db.service', 'nextcloud-redis.service', 'nextcloud-app.service', 'nextcloud-office.service',
         'nextcloud-gateway.service')
SHARE_TEXT = '沒有包含 share 資料夾'
SAFE_LABEL = re.compile(r"[^A-Za-z0-9 ,()/:'<>.=_-]")
SECRET_FILES = (LAB / 'secrets' / 'ha-import-creds.env', LAB / 'secrets' / 'b1-creds.env')
MARKERS = LAB / 'secrets' / 'dev-e-markers.json'


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


drv = _load('ha_import_b1_e2e')
drv.DEVICE = DEVICE                       # every helper/owner/root call of the b1 driver goes to dev-e
drv.state_path = lambda: LAB / 'run' / 'nextcloud_flow.json'
Failed = drv.Failed


def label(text):
    return SAFE_LABEL.sub(' ', str(text))[:140].strip() or 'check'


def emit(line):
    print(line, flush=True)


class Ev(drv.Evidence):
    """The b1 driver's private, redacted evidence folder; stdout gets only `<label>: PASS|FAIL`."""

    def log(self, text):
        line = f'{time.strftime("%H:%M:%S")} {self.secrets.redact(str(text))}'
        with open(self.log_path, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')

    def check(self, name, ok, detail=''):
        result = super().check(name, ok, detail)
        emit(f'{label(name)}: {"PASS" if result else "FAIL"}')
        return result


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------- device-side programs (python3 -I -c, stdin JSON)

STATE = r'''
import json, subprocess, sys
REQ = json.loads(sys.stdin.read() or "{}")
def run(*argv):
    return subprocess.run(list(argv), capture_output=True, timeout=300)
def text(p):
    return p.stdout.decode("utf-8", "replace") if p.returncode == 0 else None
cfg = text(run("podman", "exec", "nextcloud-app", "sha256sum", "/var/www/html/config/config.php"))
users = text(run("podman", "exec", "-u", "www-data", "nextcloud-app", "php", "/var/www/html/occ", "user:list",
                 "--output=json", "--limit=1000"))
status = text(run("podman", "exec", "nextcloud-app", "curl", "-fsS", "-m", "20", "http://localhost/status.php"))
sql = "SELECT json_build_object('storages', (SELECT json_agg(id ORDER BY numeric_id) FROM oc_storages), " \
      "'files', (SELECT count(*) FROM oc_filecache), 'users', (SELECT count(*) FROM oc_users))"
db = text(run("podman", "exec", "nextcloud-db", "psql", "-X", "-At", "-U", "nextcloud", "-d", "nextcloud", "-c", sql))
top = text(run("podman", "exec", "nextcloud-app", "ls", "-1A", "/var/www/html/data"))
units = {u: (text(run("systemctl", "--user", "is-active", u)) or "inactive").strip() for u in REQ["units"]}
print(json.dumps({"config_sha256": cfg.split()[0] if cfg else None,
                  "users": sorted(json.loads(users)) if users else None,
                  "status": json.loads(status) if status else None,
                  "db": json.loads(db) if db else None,
                  "data_top": sorted(top.split()) if top is not None else None, "units": units}))
'''

ENGINE_HASHES = r'''
import hashlib, json, os
lib = "/usr/local/lib/woowtech-cockpit-backup/woowbackup"
out = {}
for d, dirs, files in os.walk(lib):
    dirs[:] = [x for x in dirs if x != "__pycache__"]
    for f in files:
        if f.endswith(".py"):
            p = os.path.join(d, f)
            out[os.path.relpath(p, lib)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
print(json.dumps(out))
'''

LEAKS = 'import json\n' + __import__('inspect').getsource(drv.secret_scan_needles) + r'''
import os, subprocess, sys
req = json.loads(sys.stdin.read())
secrets = {name: value.encode() for name, value in req["secrets"].items() if value}
needles = secret_scan_needles(secrets.values())
hits, scanned = 0, 0
roots = ["/var/lib/woowtech-backup/jobs", "/var/lib/woowtech-backup/ha-backups", "/var/lib/woowtech-backup/ha-imports.json",
         "/var/lib/woowtech-backup/archives", "/run/woowtech-backup", "/var/lib/woowtech-backup/uploads",
         "/var/lib/woowtech-backup/staging", "/var/lib/woowtech-backup/pending", "/var/lib/woowtech-backup/exports"]
for root in roots:
    if not os.path.exists(root):
        continue
    if os.path.islink(root):
        raise RuntimeError("unsafe scan root")
    paths = [root] if os.path.isfile(root) else []
    for d, dirs, files in os.walk(root, followlinks=False):
        paths.extend(os.path.join(d, f) for f in files)
    for path in paths:
        if path.endswith(".tar") and ("/ha-backups/" in path or "/archives/" in path):
            continue  # the uploaded HA file itself and the (encrypted) backups
        if os.path.islink(path):
            raise RuntimeError("unsafe scan path")
        data = open(path, "rb").read()
        scanned += 1
        hits += sum(data.count(s) for s in needles)
journal = subprocess.run(["journalctl", "-o", "cat", "--no-pager"], capture_output=True, check=True).stdout
hits += sum(journal.count(s) for s in needles)
print(json.dumps({"scanned": scanned, "journal_bytes": len(journal), "names": len(secrets), "hits": hits}))
'''


CANDIDATE = r'''
import io, json, sys, time
sys.path.insert(0, "/usr/local/lib/woowtech-cockpit-backup")
from unittest import mock
from woowbackup import cli, ha_nextcloud
from woowbackup.paths import Paths
req = json.loads(sys.stdin.read())
NCDATA = b"# Nextcloud data directory\n# Do not change this file\n"
def relaxed(work, src, *, out=None, ids=None):
    data = ha_nextcloud.DataDir()
    data.present = data.ncdata = True
    if out is not None:
        out.add(".ncdata", "file", mode=0o644, uid=ids[0], gid=ids[1], mtime=time.time(), size=len(NCDATA),
                fileobj=io.BytesIO(NCDATA))
    work.log("INTERNAL CANDIDATE: the users' files are not in this backup; the data dir gets only .ncdata")
    return data
svc = cli.Services(Paths(), launcher=lambda job_id: None)
def call(argv, request=None):
    out = io.StringIO()
    code = cli.main(argv, stdin=io.StringIO(json.dumps(request) if request is not None else ""), stdout=out,
                    services=svc)
    lines = out.getvalue().strip().splitlines()
    return code, json.loads(lines[-1]) if lines else {}
code, reply = call(["ha-convert-start"], req["request"])
if code != 0 or not reply.get("job_id"):
    print(json.dumps({"started": False, "error": (reply.get("error") or {}).get("code")}))
    sys.exit(0)
with mock.patch.object(ha_nextcloud, "datadir_pass", relaxed):
    code, run = call(["run-job", reply["job_id"]])
print(json.dumps({"started": True, "job_id": reply["job_id"], "state": run.get("state"), "code": code}))
'''


def isolation():
    proc = subprocess.run([drv.LP, 'inspect', DEVICE, '--format',
                           '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}'],
                          capture_output=True, timeout=60)
    return proc.stdout.decode().strip()


def clean_tree():
    proc = subprocess.run(['git', '-C', str(REPO), 'status', '--porcelain', '--untracked-files=no'],
                          capture_output=True, timeout=60, check=True)
    return not proc.stdout.strip()


def host_free():
    st = os.statvfs('/')
    return st.f_bavail * st.f_frsize


def tree_hashes():
    lib = REPO / 'backup-engine' / 'woowbackup'
    return {str(p.relative_to(lib)): sha256_file(p) for p in sorted(lib.rglob('*.py')) if '__pycache__' not in p.parts}


class Run:
    def __init__(self, args, ev):
        self.args, self.ev = args, ev
        self.lock_started = time.monotonic()
        self.created_store = None
        self.before = {}

    def budget(self, phase):
        if time.monotonic() - self.lock_started > HOLD_BUDGET:
            raise Failed(f'lock hold budget reached before {phase}')
        free = host_free()
        if free < FLOOR + NEED:
            raise Failed(f'host free space {free} below the floor plus the step need before {phase}')

    def state(self):
        return drv.device_python(STATE, {'units': list(UNITS)}, timeout=600)

    def markers(self):
        password = json.loads(MARKERS.read_text(encoding='utf-8'))['nextcloud']
        script = (HERE / 'batch2_markers.py').read_text(encoding='utf-8')
        proc = drv.owner('python3', '-I', '-c', script, 'nextcloud', 'read',
                         input=json.dumps({'password': password}).encode(), timeout=600)
        lines = [line for line in drv.out(proc).splitlines() if line.strip()]
        if proc.returncode != 0 or not lines:
            raise Failed('batch2_markers.py nextcloud read failed')
        return json.loads(lines[-1])

    def setup(self):
        ev = self.ev
        self.budget('setup')
        proc = subprocess.run([str(HERE / 'deploy-src.sh'), 'e', '--src', str(REPO), '--no-demo-catalog'],
                              capture_output=True, timeout=1800)
        ev.save('deploy-src.log', proc.stdout.decode('utf-8', 'replace')[-20000:] + proc.stderr.decode('utf-8', 'replace')[-5000:])
        if not ev.check('setup: deploy-src.sh e --src this tree', proc.returncode == 0, f'rc={proc.returncode}'):
            raise Failed('deploy-src')
        installed = drv.device_python(ENGINE_HASHES, as_owner=False)
        tree = tree_hashes()
        differ = sorted(k for k in set(tree) | set(installed) if tree.get(k) != installed.get(k))
        if not ev.check('setup: the installed engine is exactly this tree', not differ,
                        {'modules': len(tree), 'differ': differ[:10]}):
            raise Failed('engine differs')
        status = drv.ok('status', ev=ev)
        ev.check('setup: the helper answers status with this tree\'s VERSION',
                 status.get('version') == (REPO / 'VERSION').read_text().strip(), status.get('version'))
        entry = drv.catalog('nextcloud')
        ev.save('catalog-nextcloud.json', entry)
        ok = (set(UNITS) <= set(entry.get('units') or []) and not entry.get('postgres') and not entry.get('volumes')
              and len(entry.get('data_dirs') or []) == 4)
        if not ev.check('setup: the nextcloud catalog entry names the five units and the four data dirs', ok,
                        {'units': entry.get('units'), 'data_dirs': entry.get('data_dirs')}):
            raise Failed('catalog entry')
        key = drv.ok('key-init', ev=ev)
        ev.check('setup: a device key exists (key-init)', bool((key.get('key') or {}).get('key_id')),
                 {'created': key.get('created')})
        state = self.state()
        ev.save('state-setup.json', state)
        running = all(v == 'active' for v in (state.get('units') or {}).values())
        status = state.get('status') or {}
        if not ev.check('setup: Nextcloud runs (five units active, status.php installed 35.0.1.1, no maintenance)',
                        running and status.get('installed') is True and status.get('version') == '35.0.1.1'
                        and status.get('maintenance') is False, {'units': state.get('units'), 'status': status}):
            raise Failed('Nextcloud not running')

    def before_state(self):
        ev = self.ev
        self.before = {'markers': self.markers(), 'state': self.state()}
        ev.save('before.json', self.before)
        ev.check('before: dev-e\'s own markers read (baseline user and its WebDAV file)',
                 'woowbk-lab-baseline' in (self.before['markers'].get('users') or [])
                 and bool(self.before['markers'].get('files')), self.before['markers'])

    def upload(self):
        ev = self.ev
        self.budget('upload')
        if not ev.check('upload: the fixture is the recorded no-share backup', sha256_file(FIXTURE) == FIXTURE_SHA):
            raise Failed('fixture differs')
        started = time.monotonic()
        rc, reply = drv.upload(FIXTURE, ev=ev)
        meta = reply.get('ha_backup') or {}
        self.created_store = meta.get('id') if rc == 0 else None
        ev.save('ha-backup.json', meta)
        found = {a['app_id']: a['installed'] for a in meta.get('importable_apps') or []}
        ev.check('upload: upload-finish answers the HA record', rc == 0 and str(meta.get('id', '')).startswith('ha-'),
                 f'{time.monotonic() - started:.1f} s')
        ev.check('upload: nextcloud is importable and installed here', found.get('nextcloud') is True, found)
        if not self.created_store:
            raise Failed('upload')

    def check(self):
        ev = self.ev
        self.budget('check')
        job, took = drv.run_check(self.created_store, ['nextcloud'], ev=ev, key=self.args.secrets['HA_BACKUP_KEY'])
        ev.time('check', 'noshare', 'nextcloud', took, job)
        result = (job.get('result') or {}).get('ha_check') or {}
        apps = result.get('apps') or []
        app = apps[0] if apps else {}
        ev.save('check-result.json', result)
        ev.check('check: the job succeeds and answers one app', job.get('state') == 'succeeded' and len(apps) == 1,
                 {'state': job.get('state'), 'error': job.get('error')})
        blockers = app.get('blockers') or []
        ev.check('check: nextcloud is not ok and the first blocker names the missing share folder and /share/nextcloud',
                 app.get('ok') is False and bool(blockers) and SHARE_TEXT in blockers[0] and '/share/nextcloud' in blockers[0],
                 blockers)
        ev.check('check: the missing user files are the only blocker', len(blockers) == 1, blockers)
        section = app.get('nextcloud') or {}
        differ = {k: [v, section.get(k)] for k, v in SECTION.items() if section.get(k) != v}
        ev.check('check: the section equals the backup facts (HA cluster opened and read: users, files, tokens, apps)',
                 not differ, differ or section)
        ev.check('check: amd64, add-on 0.2.3, target 35.0.1.1',
                 (app.get('arch'), app.get('version'), app.get('target_version')) == ('amd64', '0.2.3', '35.0.1.1'),
                 {k: app.get(k) for k in ('arch', 'version', 'target_version')})
        self.blocker = blockers[0] if blockers else None

    def convert(self):
        ev = self.ev
        self.budget('convert')
        before = {b['id'] for b in drv.ok('list', ev=ev).get('backups') or []}
        job, took = drv.convert(self.created_store, ['nextcloud'], False, ev=ev, key=self.args.secrets['HA_BACKUP_KEY'],
                                tag='nc-noshare-convert')
        ev.time('convert', 'noshare', 'nextcloud', took, job)
        error = job.get('error') or {}
        ev.save('convert-job.json', {'state': job.get('state'), 'error': error})
        ev.check('convert: the job fails incompatible with the same sentence (nothing is built)',
                 job.get('state') == 'failed' and error.get('code') == 'incompatible'
                 and SHARE_TEXT in str(error.get('message')) and '/share/nextcloud' in str(error.get('message')),
                 {'state': job.get('state'), 'code': error.get('code')})
        after = {b['id'] for b in drv.ok('list', ev=ev).get('backups') or []}
        ev.check('convert: no backup was added', after == before, sorted(after - before))

    def candidate(self):
        ev = self.ev
        self.budget('candidate')
        before = {b['id'] for b in drv.ok('list', ev=ev).get('backups') or []}
        request = {'ha_backup_id': self.created_store, 'apps': ['nextcloud'], 'test_mode': False, 'confirm': True,
                   'request_id': drv.request_id('nc-candidate'), 'key': self.args.secrets['HA_BACKUP_KEY']}
        started = time.monotonic()
        run = drv.device_python(CANDIDATE, {'request': request}, as_owner=False, timeout=5400)
        took = time.monotonic() - started
        ev.save('candidate-run.json', run)
        job = drv.ok('job-status', {'job_id': run.get('job_id')}, ev=ev).get('job') if run.get('started') else {}
        ev.time('candidate-convert', 'noshare', 'nextcloud', took, job)
        result = (job or {}).get('result') or {}
        ev.save('candidate-job.json', {'job': job})
        backup = result.get('backup_id')
        if backup:
            drv.STATE.setdefault('created_backups', []).append(backup)
        if not ev.check('candidate: the internal conversion job succeeds (real dump, new cluster, role, restore, '
                        'fix-ups verified against the live database, PHP check, dir tars, packaging)',
                        run.get('started') and (job or {}).get('state') == 'succeeded' and bool(backup),
                        {'run': run, 'state': (job or {}).get('state'), 'error': (job or {}).get('error')}):
            return
        self.converted = backup
        row = result.get('ha_import') or {}
        ev.check('candidate: the notes and reminders name Collabora, the share folder rule and the MCP admin lines',
                 any('Collabora' in n for n in row.get('notes') or [])
                 and any('Woow Nextcloud MCP Server' in r for r in (row.get('reminders_by_app') or {}).get('nextcloud') or []),
                 row)
        inspect = drv.ok('inspect', {'backup_id': backup}, ev=ev, timeout=900)
        ev.save('candidate-inspect.json', inspect)
        pre = inspect.get('preflight') or {}
        failed = [c for c in pre.get('checks') or [] if c.get('status') == 'fail']
        ev.check('candidate: inspect: preflight passes, settings same, in place',
                 pre.get('ok') and not failed and all((a.get('settings') or {}).get('state') == 'same'
                                                      and a.get('mode') == 'inplace' for a in pre.get('apps') or []),
                 failed[:3] or [(a.get('id'), a.get('mode')) for a in pre.get('apps') or []])
        apps = (inspect.get('manifest') or {}).get('apps') or []
        dirs = sorted(d.get('path') for a in apps for d in a.get('data_dirs') or [] if isinstance(d, dict))
        ev.check('candidate: the converted backup holds the four Nextcloud data dirs',
                 dirs == sorted(f'.local/share/nextcloud-office/{n}' for n in ('data', 'html', 'postgres', 'redis')),
                 dirs)
        after = {b['id'] for b in drv.ok('list', ev=ev).get('backups') or []}
        ev.check('candidate: exactly the converted backup was added', after - before == {backup}, sorted(after - before))

    def after_state(self):
        ev = self.ev
        after = {'markers': self.markers(), 'state': self.state()}
        ev.save('after.json', after)
        ev.check('after: dev-e\'s own markers are unchanged', after['markers'] == self.before['markers'])
        b, a = self.before['state'], after['state']
        for key, text in (('config_sha256', 'config.php'), ('users', 'the users'), ('db', 'the storages, files and users in the database'),
                          ('data_top', 'the data dir top entries'), ('units', 'the five units'), ('status', 'status.php')):
            ev.check(f'after: {text} unchanged', a.get(key) == b.get(key) and a.get(key) is not None,
                     {'before': b.get(key), 'after': a.get(key)} if key != 'config_sha256' else '')

    def cleanup(self):
        ev = self.ev
        if getattr(self, 'converted', None):
            rc, _reply = drv.helper('delete', {'backup_id': self.converted, 'confirm': True})
            ev.check('cleanup: the internal candidate backup is deleted (never restored)', rc == 0)
        if self.created_store:
            rc, _reply = drv.helper('ha-delete', {'ha_backup_id': self.created_store, 'confirm': True})
            ev.check('cleanup: the HA store record of this run is deleted', rc == 0)
            if rc == 0:
                self.created_store = None
        objects = drv.labelled()
        ev.check('cleanup: no throwaway container, volume or network of a job left', not any(objects.values()), objects)
        listing = drv.device_python(drv.RUN_LIST, as_owner=False)
        staging = listing.get(drv.STAGING)
        keys = [n for n in listing.get('/run/woowtech-backup') or [] if isinstance(n, str) and n.startswith('key-')]
        ev.check('cleanup: no staging folder and no key file left', staging in ([], 'missing') and not keys, listing)

    def leaks(self):
        ev = self.ev
        names = ('HA_BACKUP_KEY', 'B2_NC_X86_NOSHARE_USER_PW', 'B2_NC_X86_NOSHARE_APP_PW')
        request = {'secrets': {name: self.args.secrets[name] for name in names}}
        report = drv.device_python(LEAKS, request, as_owner=False, timeout=900)
        host = drv.scan_host_evidence(ev.dir, self.args.secrets)
        ev.save('leaks.json', {'device': report, 'host': host})
        ev.check('leaks: the HA key and the HA test credentials are in no engine record, upload, staging, run dir or the '
                 'device journal, and not in this evidence',
                 report.get('hits') == 0 and report.get('scanned', 0) > 0 and not host.get('hits'),
                 {'device': report, 'host_hits': host.get('hits')})


def negative(args):
    secrets = drv.Secrets(SECRET_FILES, MARKERS)
    args.secrets = secrets
    ev = Ev(secrets, area='nextcloud-flow')
    emit(f'source commit {subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()}')
    if not ev.check('preflight: the checkout has no tracked change', clean_tree()):
        return 2
    if not ev.check('preflight: dev-e isolation true none {}', isolation() == 'true none {}', isolation()):
        return 2
    if not ev.check('preflight: the host keeps 12 GiB plus this run\'s need free', host_free() >= FLOOR + NEED,
                    f'{host_free()} B'):
        return 2
    with open(LOCK, 'a') as lock:
        deadline = time.monotonic() + 3600
        while True:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    ev.check('preflight: the dev-e mutation lock within an hour', False)
                    return 2
                time.sleep(10)
        run = Run(args, ev)
        try:
            steps = (run.setup, run.before_state, run.upload, run.check,
                     run.candidate if args.candidate else run.convert, run.after_state)
            for step in steps:
                step()
        except Failed as error:
            ev.check(f'run stopped: {label(error)}', False)
        finally:
            try:
                run.cleanup()
                run.leaks()
            except Failed as error:
                ev.check(f'cleanup stopped: {label(error)}', False)
            held = int(time.monotonic() - run.lock_started)
            emit(f'lock held for {held} s')
    ev.check('end: dev-e isolation true none {}', isolation() == 'true none {}', isolation())
    return 0 if ev.finish() else 1


def self_check():
    compile((HERE / 'nextcloud_flow.py').read_text(encoding='utf-8'), 'nextcloud_flow.py', 'exec')
    for script in (STATE, ENGINE_HASHES, LEAKS, CANDIDATE):
        compile(script, 'device', 'exec')
    assert all(SAFE_LABEL.sub('', name) == name for name in ('check: amd64, add-on 0.2.3, target 35.0.1.1',))
    print('self-check: PASS')
    return 0


def main(argv):
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--negative', action='store_true')
    group.add_argument('--candidate', action='store_true')
    group.add_argument('--self-check', action='store_true')
    args = parser.parse_args(argv)
    if args.self_check:
        return self_check()
    return negative(args)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
