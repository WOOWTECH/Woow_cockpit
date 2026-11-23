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

--run --facts FILE (the share-including backup, when it exists; the acceptance run): FILE (JSON, written from the
showcase lane's READY line) names {fixture, sha256, user, user_pw, app_pw (secret NAMES in the lab cred files),
files {name: sha256} of the HA test user's WebDAV marker files, section {expected check section values}}. Steps:
setup, before, upload, check (nextcloud ok, no blocker, the section as FILE says), import (ha-convert-start with the
product's SpaceGuard/Watchdog and the host-floor watchdog, inspect: preflight passes, restore-start in place with
its safety backup and health checks), verify (status.php through the gateway; the HA test user's WebDAV files
with the recorded SHA-256; OCS with the user's password AND with HA's app password (HA's `secret` moved); a wrong
password 401; the Office discovery served on this device's origin; in the database the root storage
local::/var/www/html/data/, the live wopi_url and the tables' owner), restart (nextcloud-app.service restarted,
verify again), rollback (a: a second restore with a one-shot ExecStartPre failure must end rolled-back; b: the
import's safety backup restored: dev-e's own markers are back and the HA test user is gone), cleanup, leaks.

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
import threading
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
DEVICE = 'woowbk-dev-e'
LOCK = '/tmp/woowbk-dev-e-mutation.lock'
HOLD_BUDGET = 40 * 60
FLOOR = 12 * 1024 ** 3          # the team keeps >= 12 GiB free on the host at every moment
NEED = 1536 * 1024 ** 2         # the upload copy in dev-e plus the check's throwaway cluster, with margin
CANDIDATE_NEED = 4608 * 1024 ** 2  # the candidate: live html pack + html dir tar + cluster export + the archive
WATCH_FLOOR = FLOOR + 256 * 1024 ** 2  # below it every running job of dev-e is cancelled (the job cleans up)
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


CLIENT = r'''
import base64, hashlib, json, subprocess, sys, urllib.error, urllib.parse, urllib.request
REQ = json.loads(sys.stdin.read())
NC = "http://127.0.0.1:18081"
def call(method, path, user=None, password=None, headers=None):
    h = dict(headers or {})
    if user is not None:
        h["Authorization"] = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(NC + path, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
def sql(statement):
    p = subprocess.run(["podman", "exec", "nextcloud-db", "psql", "-X", "-At", "-U", "nextcloud", "-d", "nextcloud",
                        "-c", statement], capture_output=True, timeout=120)
    return p.stdout.decode().strip() if p.returncode == 0 else None
user, pw, app = REQ["user"], REQ["user_pw"], REQ["app_pw"]
code, body = call("GET", "/status.php")
status = json.loads(body) if code == 200 else None
files = {}
for name in REQ["files"]:
    c, data = call("GET", "/remote.php/dav/files/%s/%s" % (urllib.parse.quote(user), urllib.parse.quote(name)), user, pw)
    files[name] = hashlib.sha256(data).hexdigest() if c == 200 else "HTTP%d" % c
ocs = {}
for kind, secret in (("password", pw), ("app_password", app), ("wrong", pw + "-wrong")):
    c, data = call("GET", "/ocs/v2.php/cloud/user?format=json", user, secret, {"OCS-APIRequest": "true"})
    try:
        ident = json.loads(data)["ocs"]["data"]["id"] if c == 200 else None
    except (ValueError, KeyError, TypeError):
        ident = None
    ocs[kind] = [c, ident == user]
c, data = call("GET", "/hosting/discovery")
print(json.dumps({"status": status, "files": files, "ocs": ocs,
                  "office": [c, b"urlsrc" in data and b"127.0.0.1:18081" in data],
                  "storage": sql("SELECT id FROM oc_storages WHERE id LIKE 'local::%' ORDER BY numeric_id"),
                  "wopi_url": sql("SELECT configvalue FROM oc_appconfig WHERE appid = 'richdocuments' AND configkey = 'wopi_url'"),
                  "owners": sql("SELECT string_agg(DISTINCT tableowner, ',') FROM pg_tables WHERE schemaname = 'public'")}))
'''
DROPIN_DIR_REL = '.config/systemd/user/nextcloud-app.service.d'
DROPIN_REL = DROPIN_DIR_REL + '/zz-ncflow-fail-once.conf'
FAIL_MARKER_REL = '.ncflow-fail-once'


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
        if not ev.check('upload: the fixture has the recorded SHA-256', sha256_file(FIXTURE) == FIXTURE_SHA):
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
        if self.args.run:
            ev.check('check: nextcloud is ok with no blocker', app.get('ok') is True and not blockers, blockers)
        else:
            self.negative_blockers(blockers, app)
        section = app.get('nextcloud') or {}
        differ = {k: [v, section.get(k)] for k, v in SECTION.items() if section.get(k) != v}
        ev.check('check: the section equals the backup facts (HA cluster opened and read: users, files, tokens, apps)',
                 not differ, differ or section)
        ev.check('check: amd64, add-on 0.2.3, target 35.0.1.1',
                 (app.get('arch'), app.get('version'), app.get('target_version')) == ('amd64', '0.2.3', '35.0.1.1'),
                 {k: app.get(k) for k in ('arch', 'version', 'target_version')})

    def negative_blockers(self, blockers, app):
        ev = self.ev
        ev.check('check: nextcloud is not ok and the first blocker names the missing share folder and /share/nextcloud',
                 app.get('ok') is False and bool(blockers) and SHARE_TEXT in blockers[0] and '/share/nextcloud' in blockers[0],
                 blockers)
        ev.check('check: the missing user files are the only blocker', len(blockers) == 1, blockers)

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

    def watch_host(self, stop, tripped):
        """While the candidate runs: the host floor (dev-e's engine only sees its own floor). On a breach every running
        job of dev-e is cancelled through the helper; the job stops and removes its objects itself."""
        while not stop.wait(2):
            if host_free() >= WATCH_FLOOR:
                continue
            tripped.append(host_free())
            try:
                jobs = drv.ok('jobs', ev=self.ev).get('jobs') or []
                for job in jobs:
                    if job.get('state') in ('queued', 'running'):
                        drv.helper('job-cancel', {'job_id': job['id']})
            except Failed:
                pass
            return

    def candidate(self):
        ev = self.ev
        self.budget('candidate')
        if not ev.check('candidate: the host keeps 12 GiB plus the candidate\'s need free', host_free() >= FLOOR + CANDIDATE_NEED,
                        f'{host_free()} B'):
            return
        before = {b['id'] for b in drv.ok('list', ev=ev).get('backups') or []}
        request = {'ha_backup_id': self.created_store, 'apps': ['nextcloud'], 'test_mode': False, 'confirm': True,
                   'request_id': drv.request_id('nc-candidate'), 'key': self.args.secrets['HA_BACKUP_KEY']}
        started = time.monotonic()
        stop, tripped = threading.Event(), []
        watcher = threading.Thread(target=self.watch_host, args=(stop, tripped), daemon=True)
        watcher.start()
        try:
            run = drv.device_python(CANDIDATE, {'request': request}, as_owner=False, timeout=5400)
        finally:
            stop.set()
            watcher.join(timeout=60)
        took = time.monotonic() - started
        ev.check('candidate: the host floor held during the conversion (no cancel needed)', not tripped, tripped)
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

    # -------- the acceptance run (share-including backup)
    def import_real(self):
        ev, facts = self.ev, self.args.facts
        self.budget('import')
        if not ev.check('import: the host keeps 12 GiB plus the conversion\'s need free',
                        host_free() >= FLOOR + CANDIDATE_NEED + int(facts.get('extra_need', 0)), f'{host_free()} B'):
            raise Failed('host space')
        stop, tripped = threading.Event(), []
        watcher = threading.Thread(target=self.watch_host, args=(stop, tripped), daemon=True)
        watcher.start()
        try:
            job, took = drv.convert(self.created_store, ['nextcloud'], False, ev=ev,
                                    key=self.args.secrets['HA_BACKUP_KEY'], tag='nc-share-convert')
        finally:
            stop.set()
            watcher.join(timeout=60)
        ev.time('convert', 'share', 'nextcloud', took, job)
        result = job.get('result') or {}
        ev.save('convert-job.json', {'state': job.get('state'), 'error': job.get('error'), 'result': result})
        self.converted = result.get('backup_id')
        drv.created_backup(self.converted)
        if not ev.check('import: ha-convert-start succeeds (the product\'s space guard; host floor held)',
                        job.get('state') == 'succeeded' and bool(self.converted) and not tripped,
                        {'state': job.get('state'), 'error': job.get('error'), 'tripped': tripped}):
            raise Failed('convert')
        inspect = drv.ok('inspect', {'backup_id': self.converted}, ev=ev, timeout=900)
        pre = inspect.get('preflight') or {}
        failed = [c for c in pre.get('checks') or [] if c.get('status') == 'fail']
        ev.check('import: inspect: preflight passes, settings same, in place',
                 pre.get('ok') and not failed and all((a.get('settings') or {}).get('state') == 'same'
                                                      and a.get('mode') == 'inplace' for a in pre.get('apps') or []),
                 failed[:3])
        job, took = drv.restore(self.converted, ['nextcloud'], ev=ev, tag='nc-share-restore')
        ev.time('restore', 'share', 'nextcloud', took, job)
        result = job.get('result') or {}
        self.safety = result.get('safety_backup_id')
        drv.created_backup(self.safety)
        health = result.get('health') or []
        if not ev.check('import: restore-start succeeds with its safety backup and every health check ok',
                        job.get('state') == 'succeeded' and bool(self.safety) and health
                        and all(h.get('status') == 'ok' for h in health),
                        {'state': job.get('state'), 'error': job.get('error'), 'took_s': round(took, 1)}):
            raise Failed('restore')

    def client(self):
        facts, secrets = self.args.facts, self.args.secrets
        request = {'user': facts['user'], 'user_pw': secrets[facts['user_pw']], 'app_pw': secrets[facts['app_pw']],
                   'files': sorted(facts['files'])}
        return drv.device_python(CLIENT, request, timeout=900)

    def verify(self, phase):
        ev, facts = self.ev, self.args.facts
        found = self.client()
        ev.save(f'client-{phase}.json', found)
        status = found.get('status') or {}
        ev.check(f'{phase}: status.php installed 35.0.1.1, no maintenance',
                 status.get('installed') is True and status.get('version') == '35.0.1.1' and status.get('maintenance') is False,
                 status)
        ev.check(f'{phase}: the HA test user\'s WebDAV files have the recorded SHA-256 (user files moved intact)',
                 found.get('files') == facts['files'], found.get('files'))
        ocs = found.get('ocs') or {}
        ev.check(f'{phase}: OCS login with the HA password and with HA\'s app password (secret moved); wrong password 401',
                 ocs.get('password') == [200, True] and ocs.get('app_password') == [200, True]
                 and (ocs.get('wrong') or [None])[0] == 401, ocs)
        ev.check(f'{phase}: Office discovery is served on this device\'s origin', found.get('office') == [200, True],
                 found.get('office'))
        ev.check(f'{phase}: database: root storage is this device\'s data dir, live wopi_url, tables owned by oc_admin',
                 found.get('storage') == 'local::/var/www/html/data/' and found.get('wopi_url') == 'http://nextcloud-office:9980'
                 and found.get('owners') == 'oc_admin', {k: found.get(k) for k in ('storage', 'wopi_url', 'owners')})
        return found

    def restart(self):
        ev = self.ev
        drv.owner('systemctl', '--user', 'restart', 'nextcloud-app.service', timeout=900)
        deadline = time.monotonic() + 600
        state = {}
        while time.monotonic() < deadline:
            state = self.state()
            if all(v == 'active' for v in (state.get('units') or {}).values()) and (state.get('status') or {}).get('installed'):
                break
            time.sleep(10)
        ev.check('restart: nextcloud-app restarted, five units active, status.php answers', bool((state.get('status') or {}).get('installed')),
                 state.get('units'))
        self.verify('restart')

    def inject(self, on):
        home = '/home/appowner/'
        if on:
            drv.owner('mkdir', '-p', home + DROPIN_DIR_REL, timeout=60)
            text = ("[Service]\nExecStartPre=/bin/sh -c 'if test -f %h/" + FAIL_MARKER_REL + "; then rm -f %h/"
                    + FAIL_MARKER_REL + "; exit 1; fi'\n")
            for rel, data, mode in ((DROPIN_REL, text.encode(), '0644'), (FAIL_MARKER_REL, b'fail-once\n', '0600')):
                drv.owner('sh', '-c', 'umask 077; cat > "$1" && chmod "$2" "$1"', 'sh', home + rel, mode, input=data,
                          timeout=60)
            drv.owner('systemctl', '--user', 'daemon-reload', timeout=120)
        else:
            drv.owner('rm', '-f', home + DROPIN_REL, home + FAIL_MARKER_REL, timeout=60)
            drv.owner('rmdir', home + DROPIN_DIR_REL, timeout=60)
            drv.owner('systemctl', '--user', 'daemon-reload', timeout=120)

    def rollback(self):
        ev = self.ev
        self.budget('auto rollback')
        self.inject(True)
        try:
            job, took = drv.restore(self.converted, ['nextcloud'], ev=ev, tag='nc-share-restore-inject')
        finally:
            consumed = drv.owner('test', '-e', '/home/appowner/' + FAIL_MARKER_REL, timeout=60).returncode != 0
            self.inject(False)
        result = job.get('result') or {}
        drv.created_backup(result.get('safety_backup_id'))
        ev.check('auto rollback: a restore with a one-shot ExecStartPre failure ends rolled-back',
                 job.get('state') == 'rolled-back' and result.get('rolled_back') is True and consumed,
                 {'state': job.get('state'), 'took_s': round(took, 1)})
        self.verify('auto rollback')
        self.budget('rollback')
        job, took = drv.restore(self.safety, ['nextcloud'], ev=ev, tag='nc-share-rollback')
        result = job.get('result') or {}
        drv.created_backup(result.get('safety_backup_id'))
        ev.check('rollback: the import\'s safety backup restored (manual rollback), every health check ok',
                 job.get('state') == 'succeeded' and all(h.get('status') == 'ok' for h in result.get('health') or []),
                 {'state': job.get('state'), 'took_s': round(took, 1)})
        found = self.markers()
        ev.check('rollback: dev-e\'s own markers are back exactly and the HA test user is gone',
                 found == self.before['markers'] and self.args.facts['user'] not in (self.state().get('users') or []),
                 found)

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
        for backup_id in [getattr(self, 'converted', None)] + list(drv.STATE.get('created_backups') or []):
            if backup_id and backup_id not in getattr(self, 'deleted', set()):
                rc, _reply = drv.helper('delete', {'backup_id': backup_id})
                ev.check('cleanup: a backup this run created is deleted', rc == 0)
                self.deleted = getattr(self, 'deleted', set()) | {backup_id}
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
        names = ['HA_BACKUP_KEY', 'B2_NC_X86_NOSHARE_USER_PW', 'B2_NC_X86_NOSHARE_APP_PW']
        if self.args.run:
            names += [self.args.facts['user_pw'], self.args.facts['app_pw']]
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
            if args.run:
                steps = (run.setup, run.before_state, run.upload, run.check, run.import_real,
                         lambda: run.verify('import'), run.restart, run.rollback, run.after_state)
            else:
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
    for script in (STATE, ENGINE_HASHES, LEAKS, CANDIDATE, CLIENT):
        compile(script, 'device', 'exec')
    assert all(SAFE_LABEL.sub('', name) == name for name in ('check: amd64, add-on 0.2.3, target 35.0.1.1',))
    print('self-check: PASS')
    return 0


def main(argv):
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--negative', action='store_true')
    group.add_argument('--candidate', action='store_true')
    group.add_argument('--run', action='store_true')
    parser.add_argument('--facts', type=Path)
    group.add_argument('--self-check', action='store_true')
    args = parser.parse_args(argv)
    if args.self_check:
        return self_check()
    if args.run:
        if args.facts is None:
            parser.error('--run needs --facts FILE')
        args.facts = json.loads(args.facts.read_text(encoding='utf-8'))
        global FIXTURE, FIXTURE_SHA, SECTION
        FIXTURE, FIXTURE_SHA = Path(args.facts['fixture']), args.facts['sha256']
        SECTION = dict(args.facts['section'])
    return negative(args)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
