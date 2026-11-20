#!/usr/bin/env python3
"""Home Assistant import batch 1, end to end on lab device dev-d (Omnigent, Hermes, EMQX, Headscale).

STATUS: Offline self-check only. All real scenarios and deployment are disabled pending verified
network isolation and secret-handling fixes. The scenarios below describe intended coverage, not
verified results.

dev-d runs production-like copies of the four apps with fresh secrets (tests/e2e/lab/README.md, dev-d). This driver
uploads the eight real HA backups of batch 1 (~/.woowbk-lab/ha-fixtures/20261119-b1/{x86,arm}/), runs the engine's HA
check and convert jobs through the installed helper (as root inside the device, like Cockpit), restores every converted
backup with the existing restore job and verifies each app from the inside -- not only the data but that a client set up
for the HA side keeps working with only the address changed ("seamless"):

  omnigent   HA's admin and member log in with HA's passwords, this device's admin and runner accounts still do, the
             agent, the paused task, the session with labels, comment and attachment (sha256), /v1/info; for the RPi5
             backup the real runner made against the RPi5 (lab container b1-omnigent-runner) re-pointed here keeps
             its login (HA's token and grant) and host id, comes online and answers a filesystem listing
  hermes     the dashboard takes THIS device's password, HA's sessions, memory, skill, cron job, kanban task and the
             masked dummy key, a webhook POST signed with the route's own secret is accepted, config.yaml is HA's
             (with the HA-internal URL warning), the files belong to the container user, health
  emqx       MQTT logins with HA's users get the 2 retained messages, an ACL-denied topic is denied, anonymous and
             banned clients are refused, the dashboard takes HA's admin and second user, rules/connector/action/
             banned client/API key are there and the API key works, no_match stays deny, the bootstrap user works
  headscale  users, nodes, the approved route and the DNS record; only this device's API key is left (and works); the
             Noise public key is HA's; for the RPi5 backup the real tailscale client made against the RPi5 (lab
             volume b1-ts-alice-state) re-pointed to this device's URL keeps its node, key and 100.64.0.2 without
             a new login (run inside dev-d in a network namespace that reaches only dev-d's Headscale)

  python3 -I tests/e2e/lab/ha_import_b1_e2e.py [--deploy LAB_DIR --src TREE] [scenario ...]
  scenarios (default: all, in this order):
    upload    the 8 HA backups (x86 enc/plain/unc/emqx-stopped, arm the same) -> ha_backup records
    check     one check job per upload and app: arch, versions and counts against ~/.woowbk-lab/evidence/b1-source
    x86       per app from the x86 encrypted backup (EMQX also from the stopped one): convert, restore, verify
    arm       per app from the RPi5 encrypted backup (EMQX also from the stopped one) + the two re-pointed clients
    forms     the unencrypted and the uncompressed backups of both machines: one conversion and one restore of all
              their apps each, verified the same way
    testmode  Omnigent in test mode: the scheduled tasks are paused
    baseline  dev-d's four baseline backups restored; its own marker data is back (batch1_markers.py)
    cleanup   no throwaway container/volume/network, staging, key file or helper process left; the test's own
              converted and safety backups deleted (--keep-backups keeps them)
    leaks     no test secret (HA key, test passwords, dev-d's app secrets) in job records, logs, index, ha-imports.json,
              uploads or the device journal
  single imports: import:<upload>:<app> (e.g. import:x86-enc:hermes); `runner` / `tailscale` rerun the client tests.

Secrets are read from ~/.woowbk-lab/secrets/{b1-creds.env,ha-import-creds.env,dev-d-markers.json} and dev-d's podman
secrets (inside the device); they are never printed: every evidence line is redacted. Evidence:
~/.woowbk-lab/evidence/b1-import/<ts>/ (run.log, results.json, timings.json, job records, probe outputs).
Only ~/.woowbk-lab/bin/labpodman is used; nothing on the host or on any HA machine is touched.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import time
from pathlib import Path

LAB = Path.home() / '.woowbk-lab'
LP = str(LAB / 'bin' / 'labpodman')
HERE = Path(__file__).resolve().parent
DEVICE = 'woowbk-dev-d'
HELPER = '/usr/local/libexec/woowtech-cockpit-backup'
OWNER = '/usr/local/bin/woowbk-owner'
SECRET_DIR = LAB / 'secrets'
FIXTURES = LAB / 'ha-fixtures' / '20261119-b1'
SOURCE = LAB / 'evidence' / 'b1-source' / 'summary.json'
STAGING = '/var/lib/woowtech-backup/staging'
JOB_LABEL = 'label=io.woowtech.backup.job'
APPS = ('omnigent', 'hermes', 'emqx', 'headscale')
# upload tag -> (machine, file name, key needed, apps in it, EMQX made while it ran)
UPLOADS = {
    'x86-active': ('x86', 'lab-made, see ACTIVE_FIXTURE', False, APPS, True),
    'x86-enc': ('x86', 'woow-b1-x86-enc', True, APPS, True),
    'x86-plain': ('x86', 'woow-b1-x86-plain', False, APPS, True),
    'x86-unc': ('x86', 'woow-b1-x86-enc-uncompressed', True, APPS, True),
    'x86-cold': ('x86', 'woow-b1-x86-emqx-stopped-enc', True, ('emqx',), False),
    'arm-enc': ('arm', 'woow-b1-arm-enc', True, ('omnigent', 'emqx', 'headscale'), True),
    'arm-plain': ('arm', 'woow-b1-arm-plain', False, ('omnigent', 'emqx', 'headscale'), True),
    'arm-unc': ('arm', 'woow-b1-arm-enc-uncompressed', True, ('omnigent', 'emqx', 'headscale'), True),
    'arm-cold': ('arm', 'woow-b1-arm-emqx-stopped-enc', True, ('emqx',), False),
}
# lab-made from x86-plain by tm_build.py (scratchpad b1labtest): the same file with ONE more Omnigent scheduled task,
# ACTIVE (a copy of HA's paused one, id b1ab0000a5c71ce0000000000000b1ab), so that test mode has something to pause
ACTIVE_FIXTURE = LAB / 'ha-fixtures' / '20261119-b1-lab' / 'woow-b1-x86-plain-active-task' / 'woow-b1-x86-plain-active-task.tar'
ACTIVE_TASK = 'b1ab0000a5c71ce0000000000000b1ab'
COUNT_OVERRIDES = {'x86-active': {'scheduled_tasks': 2, 'scheduled_tasks_active': 1}}
ARCH = {'x86': 'amd64', 'arm': 'aarch64'}
ADDON = {'omnigent': '0.1.23', 'hermes': '0.1.14', 'emqx': '5.9.1', 'headscale': '0.1.3'}
UPSTREAM = {'omnigent': '0.21.0', 'hermes': '0.22.5', 'emqx': '5.8.9', 'headscale': '0.29.4'}
BASELINE_IDS = {'omnigent': '20261119T072103Z-ea792b52', 'hermes': '20261119T072434Z-45b29e52',
                'emqx': '20261119T072831Z-168aaa02', 'headscale': '20261119T072939Z-d52b60b2'}
OMNI_URL = 'http://127.0.0.1:8000'
HS_URL = 'http://localhost:28080'  # this device's server_url (the target devices must use)
RUNNER_IMAGE = 'localhost/woow-omnigent-runner:0.21.0-2'
RUNNER_CTR = 'b1lab-omnigent-runner'
TS_DIR = '/var/lib/b1lab'  # root 0700 inside dev-d: tailscale binaries, the client's state copy, the relay
TS_RUN = '/run/b1lab'
ALL = ('upload', 'check', 'x86', 'arm', 'forms', 'testmode', 'baseline', 'cleanup', 'leaks', 'summary')
EXTRA = ('runner', 'tailscale', 'credentials')


class Failed(Exception):
    pass


# Load the adjacent helper explicitly: -I removes the script directory from sys.path.
import importlib.util as _importlib_util
_event_spec = _importlib_util.spec_from_file_location('b1_credential_events', Path(__file__).with_name('b1_credential_events.py'))
_event_module = _importlib_util.module_from_spec(_event_spec)
_event_spec.loader.exec_module(_event_module)


class Secrets:
    """Test secrets from files; `redact` replaces every value (and the HA key pattern) in evidence text. User names
    (keys ending in _USER / _USER<n>) are not secret and stay readable."""

    def __init__(self, files, markers):
        self.values = {}
        for path in files:
            for line in Path(path).read_text(encoding='utf-8').splitlines():
                key, sep, value = line.strip().partition('=')
                if sep and not key.startswith('#'):
                    self.values[key.strip()] = value.strip().strip('"\'')
        for app, value in json.loads(Path(markers).read_text(encoding='utf-8')).items():
            self.values[f'DEV_D_MARKER_{app.upper()}'] = value
        self.names = {k for k in self.values if re.search(r'_USER\d*$', k)}

    def __getitem__(self, name):
        return self.values[name]

    def register(self, name, value):
        if not isinstance(value, str) or len(value) < 6:
            raise ValueError('dynamic secret must be a string of at least six characters')
        if name in self.names:
            raise ValueError('secret name is classified as a username')
        if name in self.values and self.values[name] != value:
            raise ValueError('secret name already registered with a different value')
        self.values[name] = value

    def register_issued(self, values):
        """Retain every distinct issued value across repeated probes in this run."""
        for value in values:
            if value is None:
                continue
            if not isinstance(value, str) or len(value) < 6:
                raise ValueError('invalid issued credential')
            if value not in self.secret_values():
                name = f'ISSUED_TOKEN_{len(self.values)}'
                while name in self.values:
                    name += '_'
                self.register(name, value)

    def secret_values(self):
        return [v for k, v in self.values.items() if k not in self.names and len(v) >= 6]

    def redact(self, value):
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        for name, secret in sorted(self.values.items(), key=lambda kv: -len(kv[1])):
            if secret and name not in self.names and len(secret) >= 6:
                text = text.replace(secret, f'<{name}>')
        text = re.sub(r'hskey-(auth|api)-[A-Za-z0-9_-]{20,}', r'hskey-\1-<redacted>', text)
        text = re.sub(r'(privkey|nodekey|machinekey|discokey):[0-9a-f]{64}',
                      lambda m: m.group(0) if m.group(1) != 'privkey' else 'privkey:<redacted>', text)
        return re.sub(r'[A-Z0-9]{4}(?:-[A-Z0-9]{4}){6}', '<HA-KEY>', text)


class Evidence:
    def __init__(self, secrets, area='b1-import'):
        stamp = time.strftime('%Y%m%dT%H%M%S')
        self.dir = LAB / 'evidence' / area / stamp
        self.dir.mkdir(parents=True, exist_ok=False)
        os.chmod(self.dir, 0o700)
        self.secrets = secrets
        self.results = []
        self.timings = []
        self.log_path = self.dir / 'run.log'

    def log(self, text):
        line = f'{time.strftime("%H:%M:%S")} {self.secrets.redact(str(text))}'
        print(line, flush=True)
        with open(self.log_path, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')

    def check(self, name, ok, detail=''):
        detail = self.secrets.redact(detail if isinstance(detail, str) else json.dumps(detail, ensure_ascii=False))
        self.results.append({'check': name, 'ok': bool(ok), 'detail': detail[:1500]})
        self.log(f'{"PASS" if ok else "FAIL"} {name}{": " + detail[:400] if detail else ""}')
        return bool(ok)

    def time(self, kind, upload, app, seconds, job=None):
        result = (job or {}).get('result') or {}
        row = {'kind': kind, 'upload': upload, 'app': app, 'wall_s': round(seconds, 1),
               'state': (job or {}).get('state'), 'job_id': (job or {}).get('id'),
               'downtime_s': result.get('downtime_seconds'), 'evidence': self.dir.name}
        self.timings.append(row)
        STATE.setdefault('timings', []).append(row)
        self.save('timings.json', self.timings)

    def save(self, name, value):
        path = self.dir / name
        path.write_text(self.secrets.redact(value if isinstance(value, str) else
                                            json.dumps(value, ensure_ascii=False, indent=1)), encoding='utf-8')
        os.chmod(path, 0o600)

    def finish(self):
        failed = [r for r in self.results if not r['ok']]
        STATE.setdefault('runs', []).append({'evidence': str(self.dir), 'passed': len(self.results) - len(failed),
                                             'failed': [r['check'] for r in failed]})
        save_state()
        self.save('results.json', {'passed': len(self.results) - len(failed), 'failed': len(failed),
                                   'failed_checks': [r['check'] for r in failed], 'results': self.results})
        self.log(f'RESULT {len(self.results) - len(failed)}/{len(self.results)} passed; evidence {self.dir}')
        return not failed


def run(argv, *, input=None, stdin=None, timeout=600, check=False):
    proc = subprocess.run(argv, input=input, stdin=stdin, capture_output=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise Failed(f'{argv[:6]} exit {proc.returncode}: {proc.stderr.decode("utf-8", "replace")[-300:]}')
    return proc


def root(*argv, input=None, timeout=600, check=False):
    return run([LP, 'exec', '-i', DEVICE, *argv], input=input, timeout=timeout, check=check)


def owner(*argv, input=None, timeout=600, check=False):
    return run([LP, 'exec', '-i', DEVICE, OWNER, *argv], input=input, timeout=timeout, check=check)


def out(proc):
    return proc.stdout.decode('utf-8', 'replace')


def helper(command, request=None, *, timeout=1800):
    data = b'' if request is None else json.dumps(request, ensure_ascii=False).encode('utf-8')
    proc = root(HELPER, command, input=data, timeout=timeout)
    lines = [line for line in out(proc).splitlines() if line.strip()]
    if len(lines) != 1:
        raise Failed(f'{command}: {len(lines)} reply lines (rc={proc.returncode})')
    return proc.returncode, json.loads(lines[0])


def ok(command, request=None, *, ev, timeout=1800):
    rc, reply = helper(command, request, timeout=timeout)
    if rc != 0:
        raise Failed(f'{command} refused: {ev.secrets.redact(reply.get("error"))}')
    return reply


def request_id(tag):
    return f'b1-e2e-{re.sub(r"[^a-z0-9-]", "-", tag)}-{int(time.time() * 1000)}'


def wait_job(job_id, *, ev, timeout=5400):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        reply = ok('job-status', {'job_id': job_id}, ev=ev)
        job = reply['job']
        if job['phase'] != last:
            last = job['phase']
            ev.log(f'  job {job_id} {job["state"]} phase={job["phase"]} {job["progress"].get("message")}')
        if job['state'] not in ('queued', 'running'):
            ev.save(f'job-{job_id}.json', {'job': job, 'log': reply.get('log')})
            return job
        time.sleep(3)
    raise Failed(f'job {job_id} did not finish in {timeout} s')


def device_python(script, request=None, *, as_owner=True, timeout=600):
    """Run a Python script inside dev-d (as appowner by default); the request (with secrets) goes on stdin, one JSON
    object comes back on the last stdout line."""
    argv = ([OWNER] if as_owner else []) + ['python3', '-I', '-c', script]
    proc = run([LP, 'exec', '-i', DEVICE, *argv], input=json.dumps(request or {}).encode('utf-8'), timeout=timeout)
    if proc.returncode != 0:
        raise Failed(f'device probe failed (rc {proc.returncode}); diagnostic output suppressed')
    try:
        return json.loads(out(proc).strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Failed(f'device probe failed (rc {proc.returncode}); diagnostic output suppressed') \
            from None


def http_code(url):
    proc = root('curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20', url, timeout=60)
    return out(proc).strip()


def catalog(app):
    return json.loads(out(root('cat', f'/etc/woowtech-cockpit/backup/apps/{app}.json', check=True)))


# ---------------------------------------------------------------- state across runs

STATE = {}


def state_path():
    return LAB / 'run' / 'ha_import_b1_e2e.json'


def save_state():
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(STATE, handle, indent=1)
    os.chmod(path, 0o600)


def load_state():
    try:
        STATE.update(json.loads(state_path().read_text(encoding='utf-8')))
    except (OSError, ValueError):
        pass


def created_backup(backup_id):
    if backup_id:
        STATE.setdefault('created_backups', [])
        if backup_id not in STATE['created_backups']:
            STATE['created_backups'].append(backup_id)


# ---------------------------------------------------------------- device-side probes

PROBE_COMMON = r'''
import hashlib, json, os, subprocess, sys, time, urllib.error, urllib.request
REQ = json.loads(sys.stdin.read() or "{}")
def secret(name):
    return subprocess.run(["podman", "secret", "inspect", "--showsecret", "--format", "{{.SecretData}}", name],
                          capture_output=True, text=True, timeout=60).stdout.rstrip("\n")
def call(base, method, path, body=None, token=None, headers=None, raw=False, wait=0, basic=None):
    deadline = time.monotonic() + wait
    while True:
        data = body if isinstance(body, bytes) else (None if body is None else json.dumps(body).encode())
        r = urllib.request.Request(base + path, data=data, method=method)
        r.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            r.add_header(k, v)
        if token:
            r.add_header("Authorization", "Bearer " + token)
        if basic:
            import base64
            r.add_header("Authorization", "Basic " + base64.b64encode((basic[0] + ":" + basic[1]).encode()).decode())
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                code, content = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            code, content = e.code, e.read()
        except (urllib.error.URLError, OSError):
            if time.monotonic() < deadline:
                time.sleep(2)
                continue
            return 0, None
        starting = code in (502, 503, 504) or (code == 400 and b"not_initialized" in (content or b""))
        if starting and time.monotonic() < deadline:
            time.sleep(2)
            continue
        if raw:
            return code, content
        try:
            return code, json.loads(content) if content else None
        except ValueError:
            return code, None
def items(body, *keys):
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for k in keys + ("data", "items", "results"):
            if isinstance(body.get(k), list):
                return body[k]
    return []
def pexec(*argv, input=None, timeout=300):
    p = subprocess.run(["podman", "exec", "-i", *argv], input=input, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr
'''

OMNI_PROBE = PROBE_COMMON + r'''
B = "http://127.0.0.1:8000"
out = {}
code, info = call(B, "GET", "/v1/info", wait=180)
out["info"] = {"code": code, "server_version": (info or {}).get("server_version"), "needs_setup": (info or {}).get("needs_setup")}
def env(key, default):
    try:
        for line in open(".config/omnigent/omnigent.env", encoding="utf-8"):
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return default
def login(user, password):
    code, body = call(B, "POST", "/auth/login", {"username": user, "password": password})
    token = (body or {}).get("token") if code == 200 else None
    me = {}
    if token:
        c2, m = call(B, "GET", "/auth/me", token=token)
        m = m or {}
        me = m.get("user") if isinstance(m.get("user"), dict) else m
    return token, {"code": code, "id": me.get("id"), "is_admin": me.get("is_admin")}
tokens = {}
for role, (user, password) in (("ha_admin", REQ["ha_admin"]), ("ha_member", REQ["ha_member"]),
                               ("dev_admin", (env("OMNIGENT_ADMIN_USERNAME", "admin"), secret("omnigent-admin-password"))),
                               ("dev_operator", (env("OMNIGENT_RUNNER_USERNAME", "operator"), secret("omnigent-runner-password")))):
    tokens[role], out["login_" + role] = login(user, password)
    out["login_" + role]["user"] = user
# HA's admin with this device's admin password must not work (the account is HA's now)
out["login_ha_admin_with_dev_password"] = login(REQ["ha_admin"][0], secret("omnigent-admin-password"))[1]["code"]
t = tokens.get("ha_admin")
e = REQ["expect"]
if t:
    c, body = call(B, "GET", "/auth/users", token=t)
    out["users"] = sorted([u.get("id"), bool(u.get("is_admin"))] for u in items(body, "users"))
    c, body = call(B, "GET", "/v1/agents/" + e["agent_id"], token=t)
    out["agent"] = {"code": c, "name": (body or {}).get("name"), "id": (body or {}).get("id")}
    c, body = call(B, "GET", "/v1/scheduled-tasks/" + e["task_id"], token=t)
    b = body or {}
    out["task"] = {"code": c, "name": b.get("name"), "state": b.get("state"), "rrule": b.get("rrule"),
                   "last_run_at": b.get("last_run_at"), "agent_id": b.get("agent_id")}
    c, body = call(B, "GET", "/v1/scheduled-tasks", token=t)
    out["tasks_admin"] = sorted([x.get("id"), x.get("state")] for x in items(body, "scheduled_tasks", "tasks"))
    c, body = call(B, "GET", "/v1/sessions/" + e["session_id"], token=t)
    b = body or {}
    out["session"] = {"code": c, "title": b.get("title") or b.get("name"), "agent_id": b.get("agent_id")}
    c, body = call(B, "GET", "/v1/sessions/" + e["session_id"] + "/labels", token=t)
    out["labels"] = {"code": c, "body": body}
    c, body = call(B, "GET", "/v1/sessions/" + e["session_id"] + "/comments", token=t)
    out["comments"] = {"code": c, "count": len(items(body, "comments"))}
    c, content = call(B, "GET", "/v1/sessions/%s/resources/files/%s/content" % (e["session_id"], e["file_id"]), token=t, raw=True)
    out["attachment"] = {"code": c, "bytes": len(content or b""), "sha256": hashlib.sha256(content or b"").hexdigest()}
    c, body = call(B, "GET", "/v1/hosts", token=t)
    out["hosts_admin"] = {"code": c, "hosts": [[h.get("host_id") or h.get("id"), h.get("status"), h.get("name")] for h in items(body, "hosts")]}
tm = tokens.get("ha_member")
if tm:
    c, body = call(B, "GET", "/v1/sessions", token=tm)
    out["member_sessions"] = sorted(s.get("id") for s in items(body, "sessions", "conversations"))
    c, body = call(B, "GET", "/v1/hosts", token=tm)
    out["hosts_member"] = [[h.get("host_id") or h.get("id"), h.get("status"), h.get("name")] for h in items(body, "hosts")]
to = tokens.get("dev_operator")
if to:
    c, body = call(B, "GET", "/v1/hosts", token=to)
    out["hosts_operator"] = [[h.get("host_id") or h.get("id"), h.get("status"), h.get("name")] for h in items(body, "hosts")]
def sql(statement):
    rc, so, se = pexec("omnigent-postgres", "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "omnigent", "-d", "omnigent", "-Atc", statement)
    return so.strip() if rc == 0 else "ERROR " + se.strip()[-200:]
out["alembic"] = sql("SELECT version_num FROM alembic_version")
out["extensions"] = sql("SELECT string_agg(extname, ',' ORDER BY extname) FROM pg_extension")
counts = {}
for table in REQ["tables"]:
    counts[table] = sql("SELECT count(*) FROM %s" % table)
out["counts"] = counts
out["db_users"] = sql("SELECT string_agg(id || ':' || is_admin, ',' ORDER BY id) FROM users")
out["db_tasks"] = sql("SELECT string_agg(encode(id, 'hex') || ':' || state::text, ',' ORDER BY id) FROM scheduled_tasks")
out["db_hosts"] = sql("SELECT string_agg(encode(host_id, 'hex') || ':' || user_id || ':' || name || ':' || status::text, ',' ORDER BY host_id) FROM hosts")
out["_issued_credentials"] = [v for v in tokens.values() if v]
print(json.dumps(out))
'''

HERMES_PROBE = PROBE_COMMON + r'''
import hmac, http.cookiejar
out = {}
D = "http://127.0.0.1:19119"
for name, url in (("api", "http://127.0.0.1:18642/health"), ("webhook", "http://127.0.0.1:18644/health")):
    code, _ = call(url, "GET", "", raw=True, wait=240)
    out["health_" + name] = code
def dash_login(password):
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    r = urllib.request.Request(D + "/auth/password-login", data=json.dumps({"provider": "basic", "username": "admin", "password": password, "next": "/"}).encode(), headers={"Content-Type": "application/json"})
    try:
        with op.open(r, timeout=30) as resp:
            code = resp.status
    except urllib.error.HTTPError as e:
        code = e.code
    except OSError:
        code = 0
    return code, op
def get(op, path):
    try:
        with op.open(D + path, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, None
code, op = dash_login(secret("hermes-dashboard-password"))
c2, _ = get(op, "/api/config")
out["dashboard_login_device_password"] = [code, c2]
code_ha, op_ha = dash_login(REQ["ha_dashboard_password"])
c3, _ = get(op_ha, "/api/config")
out["dashboard_login_ha_password"] = [code_ha, c3]
c, body = get(op, "/api/sessions?limit=100")
out["dash_sessions"] = sorted([s.get("id"), s.get("message_count"), s.get("source")] for s in (body or {}).get("sessions") or [])
c, body = get(op, "/api/cron/jobs")
out["dash_cron"] = sorted([j.get("id"), j.get("name"), j.get("enabled"), j.get("state")] for j in (body or []))
c, body = get(op, "/api/skills")
names = []
for s in body or []:
    names.append(s.get("name") if isinstance(s, dict) else s)
out["dash_skills"] = {"count": len(names), "b1": [n for n in names if n and "b1" in str(n)]}
c, body = get(op, "/api/webhooks")
subs = (body or {}).get("subscriptions") or []
out["dash_webhooks"] = sorted(s.get("name") or s.get("route") or s.get("id") for s in subs if isinstance(s, dict))
c, body = get(op, "/api/plugins/kanban/board")
tasks = [t for col in (body or {}).get("columns") or [] for t in col.get("tasks") or []]
out["dash_kanban"] = {"code": c, "tasks": sorted([t.get("id"), t.get("title")] for t in tasks if isinstance(t, dict))}
c, body = get(op, "/api/env")
dummy = (body or {}).get("TEST_DUMMY_KEY") or {}
rv = dummy.get("redacted_value") or ""
out["dash_env_dummy"] = {"is_set": dummy.get("is_set"), "masked": bool(rv) and rv != REQ["dummy"]}
# inside the container as the hermes user: files, config and the .env value (compared inside, only verdicts)
INNER = r"""
import hashlib, json, os, sqlite3, sys
req = json.loads(sys.stdin.read())
o = {}
h = "/opt/data"
for name in ("MEMORY.md", "USER.md"):
    p = os.path.join(h, "memories", name)
    data = open(p, "rb").read() if os.path.exists(p) else b""
    o["mem_" + name] = [hashlib.sha256(data).hexdigest(), any(m.encode() in data for m in req["memory_markers"])]
skill = os.path.join(h, "skills", "b1-import-marker", "SKILL.md")
o["skill_marker"] = os.path.exists(skill) and req["skill_marker"].encode() in open(skill, "rb").read()
o["skill_md_count"] = sum(1 for d, _s, fs in os.walk(os.path.join(h, "skills")) for f in fs if f == "SKILL.md")
env = {}
for line in open(os.path.join(h, ".env"), encoding="utf-8", errors="replace"):
    k, s, v = line.rstrip("\n").partition("=")
    if s:
        env[k.strip()] = v.strip().strip("'\"")
o["env_dummy_matches"] = env.get("TEST_DUMMY_KEY") == req["dummy"]
o["env_managed_keys_present"] = sorted(k for k in env if k in ("API_SERVER_KEY", "WEBHOOK_SECRET") or k.startswith("HERMES_DASHBOARD_BASIC_AUTH"))
from ruamel.yaml import YAML
cfg = YAML(typ="safe").load(open(os.path.join(h, "config.yaml"))) or {}
m = cfg.get("model") or {}
o["config"] = {"version": cfg.get("_config_version"), "provider": m.get("provider"), "base_url": m.get("base_url"), "default": m.get("default")}
c = sqlite3.connect("file:" + os.path.join(h, "state.db") + "?mode=ro", uri=True)
o["sessions"] = sorted([sid, n] for sid, n in c.execute("SELECT s.id, (SELECT count(*) FROM messages m WHERE m.session_id = s.id) FROM sessions s"))
o["schema_version"] = c.execute("SELECT max(version) FROM schema_version").fetchone()[0]
o["integrity_state"] = c.execute("PRAGMA quick_check").fetchone()[0]
c.close()
k = sqlite3.connect("file:" + os.path.join(h, "kanban.db") + "?mode=ro", uri=True)
o["kanban"] = sorted([r[0], r[1]] for r in k.execute("SELECT id, title FROM tasks"))
k.close()
jobs = json.load(open(os.path.join(h, "cron", "jobs.json")))
jobs = jobs.get("jobs", jobs) if isinstance(jobs, dict) else jobs
o["cron"] = sorted([j.get("id"), j.get("name"), j.get("enabled"), j.get("state")] for j in jobs)
print(json.dumps(o))
"""
rc, so, se = pexec("--user", "hermes", "-w", "/opt/data", "hermes-agent", "/opt/hermes/.venv/bin/python", "-c", INNER,
                   input=json.dumps({"dummy": REQ["dummy"], "memory_markers": REQ["memory_markers"], "skill_marker": REQ["skill_marker"]}))
try:
    out["inner"] = json.loads(so.strip().splitlines()[-1])
except (ValueError, IndexError):
    out["inner"] = {"error": se.strip()[-300:]}
rc, so, se = pexec("hermes-agent", "find", "/opt/data", "(", "!", "-uid", "1000", "-o", "!", "-gid", "1000", ")", "-printf", "%U:%G %P\n")
out["owner_exceptions"] = so.strip().splitlines()[:40]
out["owner_exception_count"] = len(so.strip().splitlines())
# the webhook route b1test with its own secret (GitHub-style signature), then a wrong signature
body = json.dumps({"event": "b1-import-check", "message": "woowbk lab seamless check"}).encode()
sig = "sha256=" + hmac.new(REQ["route_secret"].encode(), body, hashlib.sha256).hexdigest()
code, resp = call("http://127.0.0.1:18644", "POST", "/webhooks/b1test", body, headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "ping"})
out["webhook_signed"] = [code, (resp or {}).get("status") if isinstance(resp, dict) else None]
bad = "sha256=" + hmac.new(b"not-the-route-secret", body, hashlib.sha256).hexdigest()
code, resp = call("http://127.0.0.1:18644", "POST", "/webhooks/b1test", body, headers={"X-Hub-Signature-256": bad, "X-GitHub-Event": "ping"})
out["webhook_wrong_signature"] = code
code, _ = call("http://127.0.0.1:18642", "GET", "/v1/models", token=secret("hermes-api-server-key"))
out["api_device_key"] = code
code, _ = call("http://127.0.0.1:18642", "GET", "/v1/models", token=REQ["ha_api_key"])
out["api_ha_key"] = code
print(json.dumps(out))
'''

MQTT_LIB = r'''
import socket, struct
def _str(s):
    b = s.encode()
    return struct.pack("!H", len(b)) + b
def _len(n):
    o = bytearray()
    while True:
        d = n % 128
        n //= 128
        o.append(d | (0x80 if n else 0))
        if not n:
            return bytes(o)
def _recv(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf
def read_packet(s):
    h = _recv(s, 1)[0]
    mult, n = 1, 0
    while True:
        b = _recv(s, 1)[0]
        n += (b & 0x7F) * mult
        mult *= 128
        if not b & 0x80:
            break
    return h >> 4, h & 0x0F, _recv(s, n)
def mqtt_connect(client_id, user=None, password=None, port=1883):
    """-> (socket or None, CONNACK return code or an error text)"""
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    flags = 0x02
    payload = _str(client_id)
    if user is not None:
        flags |= 0x80
        payload += _str(user)
    if password is not None:
        flags |= 0x40
        payload += _str(password)
    body = _str("MQTT") + bytes([4, flags]) + struct.pack("!H", 30) + payload
    s.sendall(bytes([0x10]) + _len(len(body)) + body)
    try:
        t, f, data = read_packet(s)
    except (EOFError, OSError) as e:
        s.close()
        return None, "closed:" + type(e).__name__
    if t != 2:
        s.close()
        return None, "type%d" % t
    if data[1] != 0:
        s.close()
        return None, data[1]
    return s, 0
def mqtt_subscribe(s, topic, qos=1, wait=4.0):
    """-> (SUBACK code, [(topic, retain, payload length)] received within `wait` s)"""
    body = struct.pack("!H", 7) + _str(topic) + bytes([qos])
    s.sendall(bytes([0x82]) + _len(len(body)) + body)
    code, got = None, []
    s.settimeout(wait)
    try:
        while True:
            t, f, data = read_packet(s)
            if t == 9:
                code = data[2]
            elif t == 3:
                tl = struct.unpack("!H", data[:2])[0]
                top = data[2:2 + tl].decode()
                q = (f >> 1) & 3
                pos = 2 + tl
                if q:
                    pid = data[pos:pos + 2]
                    pos += 2
                    s.sendall(bytes([0x40, 2]) + pid)
                got.append((top, f & 1, len(data) - pos))
    except (socket.timeout, EOFError, OSError):
        pass
    return code, got
def mqtt_close(s):
    try:
        s.sendall(b"\xe0\x00")
        s.close()
    except OSError:
        pass
'''

EMQX_PROBE = PROBE_COMMON + MQTT_LIB + r'''
out = {}
E = "http://127.0.0.1:18083"
# the dashboard API answers 10-20 s after a restore ends (the catalog has no health URL): wait for it
started = time.monotonic()
code, body = call(E, "POST", "/api/v5/login", {"username": "admin", "password": REQ["ha_admin_password"]}, wait=240)
out["api_ready_after_s"] = round(time.monotonic() - started, 1)
token = (body or {}).get("token") if code == 200 else None
out["dashboard_admin_ha_password"] = code
code2, body2 = call(E, "POST", "/api/v5/login", {"username": REQ["user2"], "password": REQ["user2_password"]})
out["dashboard_user2_ha_password"] = code2
code3, body3 = call(E, "POST", "/api/v5/login", {"username": "admin", "password": secret("woow-emqx-dashboard-password")})
out["dashboard_admin_device_password"] = code3
if token:
    # authenticators may still be loading for a few seconds
    c, body = call(E, "GET", "/api/v5/authentication/password_based:built_in_database/users?limit=1000", token=token, wait=120)
    out["mqtt_users"] = sorted([u.get("user_id"), u.get("is_superuser")] for u in items(body))
    c, body = call(E, "GET", "/api/v5/authentication", token=token)
    out["authenticators"] = [[a.get("id"), a.get("enable")] for a in items(body)]
    c, body = call(E, "GET", "/api/v5/authorization/settings", token=token)
    out["authz_settings"] = {k: (body or {}).get(k) for k in ("no_match", "deny_action")}
    c, body = call(E, "GET", "/api/v5/authorization/sources", token=token)
    out["authz_sources"] = [[x.get("type"), x.get("enable")] for x in items(body, "sources")]
    rules = {}
    for kind, path in (("users", "/api/v5/authorization/sources/built_in_database/rules/users?limit=1000"),
                       ("clients", "/api/v5/authorization/sources/built_in_database/rules/clients?limit=1000")):
        c, body = call(E, "GET", path, token=token)
        rules[kind] = sorted([r.get("username") or r.get("clientid"), len(r.get("rules") or [])] for r in items(body))
    c, body = call(E, "GET", "/api/v5/authorization/sources/built_in_database/rules/all", token=token)
    rules["all"] = len((body or {}).get("rules") or [])
    out["acl"] = rules
    c, body = call(E, "GET", "/api/v5/mqtt/retainer/messages?limit=1000", token=token)
    out["retained"] = sorted(m.get("topic") for m in items(body))
    c, body = call(E, "GET", "/api/v5/rules?limit=1000", token=token)
    out["rules"] = sorted([r.get("id"), r.get("enable")] for r in items(body))
    c, body = call(E, "GET", "/api/v5/connectors", token=token)
    out["connectors"] = sorted([x.get("type"), x.get("name"), x.get("status")] for x in items(body))
    c, body = call(E, "GET", "/api/v5/actions", token=token)
    out["actions"] = sorted([x.get("type"), x.get("name"), x.get("status")] for x in items(body))
    c, body = call(E, "GET", "/api/v5/banned?limit=1000", token=token)
    out["banned"] = sorted([b.get("as"), b.get("who")] for b in items(body))
    c, body = call(E, "GET", "/api/v5/users", token=token)
    out["dashboard_users"] = sorted(u.get("username") for u in items(body))
    c, body = call(E, "GET", "/api/v5/api_key", token=token)
    out["api_keys"] = sorted([k.get("name"), k.get("enable")] for k in items(body))
    c, body = call(E, "GET", "/api/v5/nodes", token=token)
    out["nodes"] = [[n.get("node"), n.get("version"), n.get("node_status")] for n in items(body)]
code, _ = call(E, "GET", "/api/v5/nodes", basic=(REQ["api_key"], REQ["api_secret"]))
out["api_key_works"] = code
# MQTT clients set up for HA, now pointed at this device: HA's users and passwords
mq = {}
for user, password in REQ["mqtt"]:
    s, rc = mqtt_connect("b1lab-" + user, user, password)
    mq["login_" + user] = rc
    if s:
        mqtt_close(s)
s, rc = mqtt_connect("b1lab-gateway-sub", REQ["gateway"][0], REQ["gateway"][1])
if s:
    code, got = mqtt_subscribe(s, "b1/retained/#")
    mq["gateway_retained"] = {"suback": code, "topics": sorted(t for t, r, n in got if r)}
    mqtt_close(s)
s, rc = mqtt_connect("b1lab-sensor-deny", REQ["sensor"][0], REQ["sensor"][1])
if s:
    code, got = mqtt_subscribe(s, "b1/secret/#", wait=2)
    mq["sensor_denied_topic_suback"] = code
    code, got = mqtt_subscribe(s, "b1/retained/#", wait=2)
    mq["sensor_unlisted_topic_suback"] = code
    mqtt_close(s)
s, rc = mqtt_connect("b1lab-anonymous")
mq["anonymous"] = rc
if s:
    mqtt_close(s)
s, rc = mqtt_connect("b1lab-wrong", REQ["gateway"][0], "wrong-password-for-the-test")
mq["wrong_password"] = rc
if s:
    mqtt_close(s)
s, rc = mqtt_connect("b1-banned-client", REQ["gateway"][0], REQ["gateway"][1])
mq["banned_client"] = rc
if s:
    mqtt_close(s)
s, rc = mqtt_connect("b1lab-bootstrap", "woow", secret("woow-emqx-mqtt-password"))
mq["bootstrap_woow"] = rc
if s:
    mqtt_close(s)
out["mqtt"] = mq
rc, so, se = pexec("woow-emqx", "emqx", "ctl", "status")
out["ctl_status"] = so.strip().splitlines()[:2]
out["_issued_credentials"] = [v for v in (token, (body2 or {}).get("token"), (body3 or {}).get("token")) if v]
print(json.dumps(out))
'''

HEADSCALE_PROBE = PROBE_COMMON + r'''
out = {}
def hs(*args):
    rc, so, se = pexec("headscale", "headscale", *args, "-o", "json")
    try:
        return json.loads(so) if so.strip() else []
    except ValueError:
        return {"error": se.strip()[-200:]}
code, _ = call("http://127.0.0.1:29090", "GET", "/metrics", raw=True, wait=180)
out["health_metrics"] = code
users = hs("users", "list") or []
out["users"] = sorted([u.get("id"), u.get("name")] for u in users if isinstance(u, dict))
nodes = hs("nodes", "list") or []
out["nodes"] = sorted([n.get("id"), n.get("given_name"), (n.get("user") or {}).get("name"), n.get("ip_addresses"),
                       n.get("approved_routes"), n.get("online"), (n.get("last_seen") or {}).get("seconds")]
                      for n in nodes if isinstance(n, dict))
keys = hs("apikeys", "list") or []
out["apikeys"] = sorted([k.get("id"), k.get("prefix")] for k in keys if isinstance(k, dict))
pak = hs("preauthkeys", "list") or []
out["preauthkeys"] = sorted([k.get("id"), (k.get("user") or {}).get("name"), bool(k.get("reusable")), bool(k.get("used"))]
                            for k in pak if isinstance(k, dict))
rc, so, se = pexec("headscale", "cat", "/var/lib/headscale/extra_records.json")
try:
    out["dns_records"] = sorted([r.get("name"), r.get("type"), r.get("value")] for r in json.loads(so or "[]"))
except ValueError:
    out["dns_records"] = "unreadable"
rc, so, se = pexec("headscale", "sha256sum", "/var/lib/headscale/noise_private.key")
out["noise_sha256"] = so.split()[0] if so else None
code, body = call("http://127.0.0.1:28080", "GET", "/key?v=120")
out["server_public_key"] = (body or {}).get("publicKey")
code, body = call("http://127.0.0.1:28080", "GET", "/api/v1/node", token=secret("headscale-headplane-api-key"))
out["api_device_key"] = [code, len((body or {}).get("nodes") or [])]
print(json.dumps(out))
'''


def omnigent_tables():
    return ['agents', 'files', 'users', 'preferences', 'account_tokens', 'connections', 'device_grants',
            'session_permissions', 'omnigent_conversation_metadata', 'projects', 'conversations', 'conversation_items',
            'conversation_labels', 'comments', 'policies', 'hosts', 'user_daily_cost', 'scheduled_tasks',
            'scheduled_task_runs']


# ---------------------------------------------------------------- source facts

def source(machine):
    return json.loads(SOURCE.read_text(encoding='utf-8'))['machines'][machine]


def mcp_name(app):
    return {'hermes': 'Woow Hermes MCP Server', 'emqx': 'Woow EMQX MCP Server',
            'headscale': 'Woow Headscale MCP Server'}.get(app)


# ---------------------------------------------------------------- upload and check

def upload(path, *, ev):
    size = path.stat().st_size
    begin = ok('upload-begin', {'filename': path.name, 'size': size}, ev=ev)
    with open(path, 'rb') as handle:
        proc = run([LP, 'exec', '-i', DEVICE, 'python3', '-I', '-c',
                    'import shutil, sys\nwith open(sys.argv[1], "wb") as f:\n    shutil.copyfileobj(sys.stdin.buffer, f, 1 << 20)',
                    begin['path']], stdin=handle, timeout=1800)
    if proc.returncode != 0:
        raise Failed(f'copying the upload into the device failed: {proc.stderr.decode("utf-8", "replace")[-300:]}')
    rc, reply = helper('upload-finish', {'upload_id': begin['upload_id']}, timeout=1800)
    if rc != 0:
        ok('upload-abort', {'upload_id': begin['upload_id']}, ev=ev)
    return rc, reply


def scenario_upload(ev, args):
    for tag, (machine, name, _key, apps, _hot) in UPLOADS.items():
        if tag == 'x86-active':
            continue
        path = FIXTURES / machine / name / f'{name}.tar'
        started = time.monotonic()
        rc, reply = upload(path, ev=ev)
        meta = reply.get('ha_backup') or {}
        took = time.monotonic() - started
        ev.check(f'upload {tag}: upload-finish answers ha_backup', rc == 0 and meta.get('id', '').startswith('ha-'),
                 f'{took:.1f} s {meta.get("id")} {reply.get("error") if rc else ""}')
        ev.time('upload', tag, '-', took)
        STATE[f'ha_{tag}'] = meta.get('id')
        found = {a['app_id']: a['installed'] for a in meta.get('importable_apps') or []}
        ev.check(f'upload {tag}: importable apps are exactly {"/".join(apps)}, all installed here',
                 found == {a: True for a in apps}, found)
        ev.save(f'ha-backup-{tag}.json', meta)
    listing = ok('list', ev=ev)
    ids = [item['id'] for item in listing.get('ha_backups') or []]
    ev.check('list shows the eight HA backups', all(STATE.get(f'ha_{t}') in ids for t in UPLOADS if t != 'x86-active'), ids)
    save_state()


def run_check(ha, apps, *, ev, key=None, tag='check'):
    request = {'ha_backup_id': ha, 'apps': list(apps), 'request_id': request_id(tag)}
    if key is not None:
        request['key'] = key
    started = time.monotonic()
    reply = ok('ha-check-start', request, ev=ev, timeout=300)
    job = wait_job(reply['job_id'], ev=ev)
    return job, time.monotonic() - started


def compare_check(ev, label, app, section, machine, hot, upload=None):
    src = source(machine)
    s = section.get(app) or {}
    if app == 'omnigent':
        o = src['omnigent']
        want = {'omnigent_version': '0.21.0', 'alembic': o['alembic'], 'users': 2, 'admins': 1,
                'conversations': o['db_counts']['conversations'], 'scheduled_tasks': o['db_counts']['scheduled_tasks'],
                'scheduled_tasks_active': 0, 'hosts': o['db_counts']['hosts'], 'agents': o['db_counts']['agents'],
                'files': o['db_counts']['files'], 'account_conflicts': []}
    elif app == 'hermes':
        h = src['hermes']
        want = {'hermes_version': '0.22.5', 'sessions': len(h['sessions']),
                'messages': sum(h['messages_per_session'].values()), 'schema_version': h['state_schema_version'][0],
                'config_version': h['config']['_config_version'], 'skills': h['skills_SKILL_md'],
                'cron_jobs': len(h['cron_jobs']), 'hardlinks': 0}
    elif app == 'emqx':
        e = src['emqx']
        sizes = e['mnesia_sizes']
        want = {'emqx_version': e['version'], 'target_version': '5.8.9', 'node_name': e['node'],
                'mqtt_users': sizes['emqx_authn_mnesia'], 'acl_rules': sizes['emqx_acl'],
                'dashboard_users': sizes['emqx_admin'], 'api_keys': sizes['emqx_app'], 'banned': sizes['emqx_banned'],
                'psk': sizes['emqx_psk'], 'retained_messages': sizes['emqx_retainer_message'],
                'default_dashboard_password': False, 'anonymous': False, 'hot_backup': hot}
    else:
        h = src['headscale']
        want = {'headscale_version': '0.29.4', 'target_version': '0.29.4', 'users': len(h['users']),
                'nodes': len(h['nodes']), 'pre_auth_keys': len(h['preauthkeys']), 'api_keys': h['apikeys'],
                'dns_records': len(h['dns_extra_records']), 'server_url': h['server_url'],
                'target_server_url': HS_URL, 'prefixes': {'v4': '100.64.0.0/10', 'v6': 'fd7a:115c:a1e0::/48'}}
    if app == 'omnigent':
        want.update(COUNT_OVERRIDES.get(upload) or {})
    at_least = set()
    if app == 'emqx':
        # the facts counted 2 retained messages right after the seed switched the retainer to disc storage; EMQX
        # writes its own 3 retained $SYS/brokers messages at its next start, so the backups made later hold 5 (the
        # x86 encrypted one was made while EMQX was still starting: 2). HA's 2 b1 topics at least.
        at_least.add('retained_messages')
    diff = {k: (s.get(k), v) for k, v in want.items()
            if (s.get(k) != v if k not in at_least else not (isinstance(s.get(k), int) and s.get(k) >= v))}
    ev.check(f'{label}: {app} section equals the source facts', not diff, diff or {k: s.get(k) for k in want})
    return s


def scenario_check(ev, args):
    key = args.secrets['HA_BACKUP_KEY']
    STATE.setdefault('checks', {})
    for tag, (machine, _name, needs_key, apps, hot) in UPLOADS.items():
        if tag == 'x86-active' or (args.only_upload and tag not in args.only_upload):
            continue
        for app in apps:
            if args.only_app and app not in args.only_app:
                continue
            label = f'check {tag}/{app}'
            job, took = run_check(STATE[f'ha_{tag}'], [app], ev=ev, key=key if needs_key else None,
                                  tag=f'check-{tag}-{app}')
            ev.time('check', tag, app, took, job)
            if not ev.check(f'{label}: job succeeded', job['state'] == 'succeeded', f'{took:.0f} s {job.get("error")}'):
                continue
            result = job['result']['ha_check']['apps'][0]
            ev.save(f'check-{tag}-{app}.json', result)
            STATE['checks'][f'{tag}/{app}'] = {'ok': result.get('ok'), 'warnings': result.get('warnings'),
                                              'blockers': result.get('blockers')}
            blockers = result.get('blockers') or []
            ev.check(f'{label}: ok, no blockers', result.get('ok') is True and not blockers, blockers)
            ev.check(f'{label}: source processor {ARCH[machine]}, add-on {ADDON[app]}, target {UPSTREAM[app]}',
                     result.get('arch') == ARCH[machine] and result.get('version') == ADDON[app]
                     and str(result.get('target_version', '')).lstrip('v').startswith(UPSTREAM[app]),
                     {k: result.get(k) for k in ('arch', 'version', 'target_version')})
            section = compare_check(ev, label, app, result, machine, hot, tag)
            warnings = result.get('warnings') or []
            if app == 'hermes':
                ev.check(f'{label}: the HA-internal URL of config.yaml is named (warning + ha_urls)',
                         any('9c1a67eb-woow-hermes' in u for u in section.get('ha_urls') or [])
                         and any('9c1a67eb-woow-hermes' in w for w in warnings), {'ha_urls': section.get('ha_urls'),
                                                                                  'warnings': warnings})
            if app == 'emqx':
                ev.check(f'{label}: {"hot backup flagged with the stop-the-add-on advice" if hot else "cold backup, no hot warning"}',
                         (any('停止 EMQX' in w for w in warnings)) == hot, warnings)
            if app == 'headscale':
                ev.check(f'{label}: warns that HA\'s API keys are not moved', any('API' in w for w in warnings),
                         warnings)
    leftovers = labelled()
    ev.check('check: no throwaway container, volume or network left', not any(leftovers.values()), leftovers)
    save_state()


# ---------------------------------------------------------------- convert, restore, verify

def convert(ha, apps, test_mode, *, ev, key, tag):
    request = {'ha_backup_id': ha, 'apps': list(apps), 'test_mode': test_mode, 'confirm': True,
               'request_id': request_id(tag)}
    if key:
        request['key'] = key
    started = time.monotonic()
    reply = ok('ha-convert-start', request, ev=ev, timeout=300)
    job = wait_job(reply['job_id'], ev=ev, timeout=5400)
    return job, time.monotonic() - started


def restore(backup_id, apps, *, ev, tag):
    started = time.monotonic()
    reply = ok('restore-start', {'backup_id': backup_id, 'apps': list(apps), 'confirm': True,
                                 'request_id': request_id(tag)}, ev=ev, timeout=300)
    job = wait_job(reply['job_id'], ev=ev, timeout=5400)
    return job, time.monotonic() - started


def import_once(ev, args, upload_tag, apps, *, test_mode=False, label=None, verify=True):
    """Convert `apps` of one upload in one job, restore them in one job, verify each. Returns the convert job."""
    machine, _name, needs_key, _all, hot = UPLOADS[upload_tag]
    label = label or f'import {upload_tag}/{"+".join(apps)}{" (test mode)" if test_mode else ""}'
    timing_app = apps[0] if len(apps) == 1 else '+'.join(apps)
    before = {b['id'] for b in ok('list', ev=ev)['backups']}
    job, took = convert(STATE[f'ha_{upload_tag}'], apps, test_mode, ev=ev,
                        key=args.secrets['HA_BACKUP_KEY'] if needs_key else None,
                        tag=f'convert-{upload_tag}-{timing_app}')
    ev.time('convert', upload_tag, timing_app, took, job)
    if job['state'] != 'succeeded':
        error = job.get('error') or {}
        if 'emqx' in apps and hot and error.get('code') == 'incompatible' and '停止 EMQX' in (error.get('message') or ''):
            ev.check(f'{label}: hot EMQX backup refused with the stop-the-add-on advice', True, f'{took:.0f} s {error}')
            STATE.setdefault('hot_refused', {})[upload_tag] = error.get('message')
            after = {b['id'] for b in ok('list', ev=ev)['backups']}
            objects = labelled()
            ev.check(f'{label}: the refusal left nothing (no backup, no throwaway object; the live EMQX untouched)',
                     after == before and not any(objects.values()), {'new_backups': sorted(after - before), **objects})
        else:
            ev.check(f'{label}: conversion succeeded', False, f'{took:.0f} s {error}')
        return None
    result = job['result']
    backup_id = result['backup_id']
    created_backup(backup_id)
    imp = result.get('ha_import') or {}
    ev.check(f'{label}: conversion succeeded with a backup id', True, f'{took:.0f} s {backup_id} {result.get("size")} B')
    ev.save(f'ha-import-{upload_tag}-{timing_app}{"-test" if test_mode else ""}.json', imp)
    product = {'omnigent': 'Omnigent', 'hermes': 'Hermes', 'emqx': 'EMQX', 'headscale': 'Headscale'}
    ev.check(f'{label}: ha_import names the apps, test mode {test_mode}, a note per app',
             imp.get('apps') == list(apps) and imp.get('test_mode') is test_mode
             and all(any(product[a] in n for n in imp.get('notes') or []) for a in apps),
             {k: imp.get(k) for k in ('apps', 'test_mode', 'notes')})
    by_app = imp.get('reminders_by_app') or {}
    for app in apps:
        lines = by_app.get(app) or []
        want_mcp = mcp_name(app)
        ev.check(f'{label}: {app} reminders returned{" (incl. the HA MCP server line)" if want_mcp else ""}',
                 bool(lines) and (not want_mcp or any(want_mcp in line for line in lines))
                 and (app != 'headscale' or any(HS_URL in line for line in lines)), lines)
    inspect = ok('inspect', {'backup_id': backup_id}, ev=ev, timeout=900)
    pre = inspect.get('preflight') or {}
    failed = [c for c in pre.get('checks') or [] if c.get('status') == 'fail']
    ev.check(f'{label}: inspect: preflight passes, settings same, in place',
             pre.get('ok') and not failed and all((a.get('settings') or {}).get('state') == 'same'
                                                  and a.get('mode') == 'inplace' for a in pre.get('apps') or []),
             failed[:3] or [(a.get('id'), a.get('mode'), (a.get('settings') or {}).get('state')) for a in
                            pre.get('apps') or []])
    if 'headscale' in apps:
        STATE['pre_hs_apikeys'] = device_python(HEADSCALE_PROBE, {}).get('apikeys')
    rjob, rtook = restore(backup_id, apps, ev=ev, tag=f'restore-{upload_tag}-{timing_app}')
    ev.time('restore', upload_tag, timing_app, rtook, rjob)
    rresult = rjob.get('result') or {}
    created_backup(rresult.get('safety_backup_id'))
    if not ev.check(f'{label}: restore of the converted backup succeeded', rjob['state'] == 'succeeded',
                    f'{rtook:.0f} s {rjob.get("error")} safety={rresult.get("safety_backup_id")}'):
        save_state()
        return job
    health = rresult.get('health') or []
    ev.check(f'{label}: restore made a safety backup, not rolled back, every health check ok',
             rresult.get('safety_backup_id') and rresult.get('rolled_back') is False
             and all(h.get('status') == 'ok' for h in health),
             {k: rresult.get(k) for k in ('safety_backup_id', 'rolled_back', 'downtime_seconds')}
             | {'health': [(h.get('id'), h.get('status')) for h in health]})
    STATE.setdefault('imports', {})[f'{upload_tag}/{timing_app}{"/test" if test_mode else ""}'] = {
        'backup_id': backup_id, 'safety': rresult.get('safety_backup_id')}
    save_state()
    if verify:
        for app in apps:
            try:
                VERIFY[app](ev, args, machine, f'{label} {app}', test_mode=test_mode, upload=upload_tag)
            except Failed as error:
                ev.check(f'{label} {app}: verification ran', False, str(error))
            app_health(ev, app, f'{label} {app}')
    return job


def app_health(ev, app, label):
    status = ok('status', ev=ev)
    state = next((a for a in status['apps'] if a['id'] == app), {})
    ev.check(f'{label}: engine status running, no problems', state.get('state') == 'running'
             and not state.get('problems'), {k: state.get(k) for k in ('state', 'problems')})
    codes = {}
    for entry in catalog(app).get('health') or []:
        deadline = time.monotonic() + 180
        while True:
            code = http_code(entry['url'])
            if code == str(entry['expect_status']) or time.monotonic() > deadline:
                break
            time.sleep(3)
        codes[entry['url']] = (code, str(entry['expect_status']))
    ev.check(f'{label}: the catalog health URLs answer as expected', all(a == e for a, e in codes.values()),
             codes or 'no health URL in the catalog')


def omnigent_probe(secrets, request):
    result = device_python(OMNI_PROBE, request)
    secrets.register_issued(result.pop('_issued_credentials'))
    return result


def verify_omnigent(ev, args, machine, label, test_mode=False, upload=None):
    src = source(machine)['omnigent']
    s = args.secrets
    expect = {'agent_id': src['agent']['id'], 'task_id': src['scheduled_task']['id'],
              'session_id': src['admin_session']['id'], 'file_id': src['attachment']['file_id']}
    probe = omnigent_probe(s, {'ha_admin': [s['B1_OMNI_ADMIN_USER'], s['B1_OMNI_ADMIN_PW']],
                                       'ha_member': [s['B1_OMNI_MEMBER_USER'], s['B1_OMNI_MEMBER_PW']],
                                       'expect': expect, 'tables': omnigent_tables()})
    ev.save(f'probe-omnigent-{machine}{"-test" if test_mode else ""}-{int(time.time())}.json', probe)
    ev.check(f'{label}: /v1/info 0.21.0, set up', probe['info'] == {'code': 200, 'server_version': '0.21.0',
                                                                  'needs_setup': False}, probe['info'])
    for role, admin in (('ha_admin', True), ('ha_member', False), ('dev_admin', True), ('dev_operator', False)):
        result = probe.get(f'login_{role}') or {}
        ev.check(f'{label}: {role} ({result.get("user")}) logs in with {"HA" if role.startswith("ha") else "this device"}\'s password',
                 result.get('code') == 200 and result.get('id') == result.get('user') and bool(result.get('is_admin')) == admin,
                 result)
    ev.check(f'{label}: HA\'s admin does not take this device\'s admin password',
             probe.get('login_ha_admin_with_dev_password') in (400, 401, 403), probe.get('login_ha_admin_with_dev_password'))
    want_users = sorted([u['id'], u['is_admin']] for u in src['users'])
    users = probe.get('users') or []
    ev.check(f'{label}: users = HA\'s two plus this device\'s admin and operator',
             all(u in users for u in want_users) and ['admin', True] in users and ['operator', False] in users,
             users)
    ev.check(f'{label}: the agent b1-import-agent', (probe.get('agent') or {}).get('name') == src['agent']['name'],
             probe.get('agent'))
    task = probe.get('task') or {}
    ev.check(f'{label}: the scheduled task is there and still paused, never ran',
             task.get('code') == 200 and task.get('name') == src['scheduled_task']['name'] and task.get('state') == 'paused'
             and task.get('rrule') == src['scheduled_task']['rrule'] and task.get('last_run_at') is None, task)
    ev.check(f'{label}: the session with its title', (probe.get('session') or {}).get('title') == src['admin_session']['title'],
             probe.get('session'))
    labels = json.dumps((probe.get('labels') or {}).get('body'), ensure_ascii=False)
    ev.check(f'{label}: the session labels (b1=import-test) and the comment',
             '"b1"' in labels and 'import-test' in labels and (probe.get('comments') or {}).get('count') ==
             src['admin_session']['comments'], {'labels': labels, 'comments': probe.get('comments')})
    att = probe.get('attachment') or {}
    ev.check(f'{label}: the attachment downloads with the same sha256',
             att.get('code') == 200 and att.get('sha256') == src['attachment']['sha256'] and att.get('bytes') == src['attachment']['bytes'],
             att)
    ev.check(f'{label}: the member sees the member session', src['member_sessions'][0]['id'] in (probe.get('member_sessions') or []),
             probe.get('member_sessions'))
    ev.check(f'{label}: alembic d0a1f879a01d, pg_trgm', probe.get('alembic') == src['alembic']
             and 'pg_trgm' in (probe.get('extensions') or ''), [probe.get('alembic'), probe.get('extensions')])
    counts = {k: int(v) if str(v).isdigit() else v for k, v in (probe.get('counts') or {}).items()}
    want = dict(src['db_counts'], users=src['db_counts']['users'] + 2)
    want.update({k: v for k, v in (COUNT_OVERRIDES.get(upload) or {}).items() if k in want})
    # the device's own runner registers a new host and gets its own tokens after the restore
    diff = {k: (counts.get(k), v) for k, v in want.items()
            if counts.get(k) != v and k not in ('hosts', 'account_tokens', 'device_grants', 'user_daily_cost')}
    ev.check(f'{label}: every table holds HA\'s rows (users + this device\'s 2)', not diff, diff or counts)
    tasks = [t.split(':') for t in (probe.get('db_tasks') or '').split(',') if ':' in t]
    if test_mode:
        ev.check(f'{label}: test mode: every scheduled task is paused (state 2), none active',
                 tasks and all(state == '2' for _id, state in tasks), tasks)
    elif upload == 'x86-active':
        ev.check(f'{label}: without test mode HA\'s active task stays active (state 1)',
                 [ACTIVE_TASK, '1'] in [list(t) for t in tasks], tasks)
    # this device's runner logged in as operator and registered (a fresh host id after the restart)
    deadline = time.monotonic() + 150
    while True:
        hosts = probe.get('hosts_operator') or []
        if any(h[1] in ('online', 1, 'ONLINE') for h in hosts) or time.monotonic() > deadline:
            break
        time.sleep(10)
        probe = omnigent_probe(s, {'ha_admin': [s['B1_OMNI_ADMIN_USER'], s['B1_OMNI_ADMIN_PW']],
                                           'ha_member': [s['B1_OMNI_MEMBER_USER'], s['B1_OMNI_MEMBER_PW']],
                                           'expect': expect, 'tables': omnigent_tables()})
    ev.check(f'{label}: this device\'s runner (operator) registered a host and is online',
             any(h[1] in ('online', 1, 'ONLINE') for h in probe.get('hosts_operator') or []),
             {'operator': probe.get('hosts_operator'), 'db': probe.get('db_hosts')})
    STATE['omni_probe_hosts'] = probe.get('db_hosts')


def verify_hermes(ev, args, machine, label, test_mode=False, upload=None):
    src = source(machine)['hermes']
    s = args.secrets
    markers = [m.split()[-1] for m in src['created_by_b1']['memory_markers']]
    probe = device_python(HERMES_PROBE, {'ha_dashboard_password': s['B1_HERMES_DASHBOARD_PW'],
                                         'route_secret': s['B1_HERMES_ROUTE_SECRET'], 'dummy': s['B1_HERMES_DUMMY_KEY'],
                                         'ha_api_key': s['B1_HERMES_API_KEY'], 'memory_markers': markers,
                                         'skill_marker': 'b1-hermes-skill-5e2a'}, timeout=900)
    ev.save(f'probe-hermes-{machine}-{int(time.time())}.json', probe)
    ev.check(f'{label}: health /health 200 on the API and webhook ports',
             probe.get('health_api') == 200 and probe.get('health_webhook') == 200,
             [probe.get('health_api'), probe.get('health_webhook')])
    ev.check(f'{label}: the dashboard takes THIS device\'s password',
             probe.get('dashboard_login_device_password') == [200, 200], probe.get('dashboard_login_device_password'))
    ev.check(f'{label}: the dashboard refuses HA\'s dashboard password (the device\'s secret wins)',
             (probe.get('dashboard_login_ha_password') or [0])[0] in (400, 401, 403), probe.get('dashboard_login_ha_password'))
    want = sorted([sid, n] for sid, n in src['messages_per_session'].items())
    inner = probe.get('inner') or {}
    ev.check(f'{label}: HA\'s 5 sessions with 3 messages each in state.db (schema 32, quick_check ok)',
             all(x in inner.get('sessions', []) for x in want) and inner.get('schema_version') == 32
             and inner.get('integrity_state') == 'ok', {k: inner.get(k) for k in ('sessions', 'schema_version',
                                                                                  'integrity_state', 'error')})
    dash = {x[0]: x[1] for x in probe.get('dash_sessions') or []}
    ev.check(f'{label}: the dashboard lists HA\'s sessions', all(dash.get(sid) == n for sid, n in want), probe.get('dash_sessions'))
    mem = {k: inner.get(f'mem_{k}') for k in ('MEMORY.md', 'USER.md')}
    ev.check(f'{label}: memory files carry HA\'s markers with HA\'s sha256',
             all((mem[k] or [None])[0] == src['memories_sha256'][k] and mem[k][1] for k in mem), mem)
    ev.check(f'{label}: the skill marker and {src["skills_SKILL_md"]} SKILL.md files',
             inner.get('skill_marker') is True and inner.get('skill_md_count') == src['skills_SKILL_md']
             and (probe.get('dash_skills') or {}).get('b1'), {k: inner.get(k) for k in ('skill_marker', 'skill_md_count')}
             | {'dashboard': probe.get('dash_skills')})
    job = src['cron_jobs'][0]
    want_cron = [job['id'], job['name'], True, 'scheduled']
    ev.check(f'{label}: the hourly cron job (jobs.json and the dashboard)', want_cron in (inner.get('cron') or [])
             and want_cron in (probe.get('dash_cron') or []), {'file': inner.get('cron'), 'dashboard': probe.get('dash_cron')})
    ev.check(f'{label}: the kanban task t_8c42df56', ['t_8c42df56', 'B1 import kanban task'] in (inner.get('kanban') or [])
             and ['t_8c42df56', 'B1 import kanban task'] in ((probe.get('dash_kanban') or {}).get('tasks') or []),
             {'db': inner.get('kanban'), 'dashboard': probe.get('dash_kanban')})
    ev.check(f'{label}: TEST_DUMMY_KEY present (same value, masked in the dashboard)',
             inner.get('env_dummy_matches') is True and probe.get('dash_env_dummy') == {'is_set': True, 'masked': True},
             {'file': inner.get('env_dummy_matches'), 'dashboard': probe.get('dash_env_dummy')})
    ev.check(f'{label}: HA\'s .env carries none of the keys this device manages',
             not inner.get('env_managed_keys_present'), inner.get('env_managed_keys_present'))
    cfg = inner.get('config') or {}
    ev.check(f'{label}: config.yaml is HA\'s (provider custom, the HA-internal base_url, version 51)',
             cfg == {'version': 51, 'provider': 'custom', 'base_url': src['config']['model']['base_url'],
                     'default': src['config']['model']['default']}, cfg)
    allowed = set(STATE.get('hermes_owner_exceptions_before') or []) | {'0:0 .woow-dotenv'}
    extra = [line for line in probe.get('owner_exceptions') or [] if line not in allowed]
    ev.check(f'{label}: every file 1000:1000 (container view) except what the image itself makes',
             not extra, {'not 1000:1000': probe.get('owner_exceptions'), 'count': probe.get('owner_exception_count'),
                         'allowed (as before the import)': sorted(allowed)})
    ev.check(f'{label}: the dashboard lists the webhook route b1test', 'b1test' in (probe.get('dash_webhooks') or []),
             probe.get('dash_webhooks'))
    ev.check(f'{label}: a POST signed with the route\'s own secret is accepted (202), a wrong signature is refused',
             probe.get('webhook_signed', [0])[0] == 202 and probe.get('webhook_wrong_signature') == 401,
             {'signed': probe.get('webhook_signed'), 'wrong': probe.get('webhook_wrong_signature')})
    ev.check(f'{label}: the API takes this device\'s key, not HA\'s', probe.get('api_device_key') == 200
             and probe.get('api_ha_key') == 401, [probe.get('api_device_key'), probe.get('api_ha_key')])


def verify_emqx(ev, args, machine, label, test_mode=False, upload=None):
    src = source(machine)['emqx']
    s = args.secrets
    prefix = 'B1_ARM' if machine == 'arm' else 'B1_X86'
    users = [(s[f'B1_MQTT_USER{i}'], s[f'B1_MQTT_PW{i}']) for i in (1, 2, 3)]
    probe = device_python(EMQX_PROBE, {'ha_admin_password': s['B1_EMQX_ADMIN_PW'], 'user2': s['B1_EMQX_USER2'],
                                       'user2_password': s['B1_EMQX_USER2_PW'], 'mqtt': users,
                                       'sensor': users[0], 'gateway': users[1],
                                       'api_key': s[f'{prefix}_EMQX_API_KEY'], 'api_secret': s[f'{prefix}_EMQX_API_SECRET']},
                          timeout=900)
    s.register_issued(probe.pop('_issued_credentials'))
    ev.save(f'probe-emqx-{machine}-{int(time.time())}.json', probe)
    ev.log(f'  EMQX API answered {probe.get("api_ready_after_s")} s after the restore job ended')
    ev.check(f'{label}: the dashboard takes HA\'s admin password and HA\'s second user',
             probe.get('dashboard_admin_ha_password') == 200 and probe.get('dashboard_user2_ha_password') == 200,
             {k: probe.get(k) for k in ('dashboard_admin_ha_password', 'dashboard_user2_ha_password',
                                        'dashboard_admin_device_password', 'api_ready_after_s')})
    want_users = sorted([u['user_id'], u['is_superuser']] for u in src['mqtt_users'])
    ev.check(f'{label}: HA\'s three MQTT users (+ this device\'s bootstrap user)',
             all(u in (probe.get('mqtt_users') or []) for u in want_users), probe.get('mqtt_users'))
    acl = probe.get('acl') or {}
    ev.check(f'{label}: HA\'s ACL rules (2 users, 1 client, 1 for all)',
             acl.get('users') == [['b1-gateway', 2], ['b1-sensor', 2]] and acl.get('clients') == [['b1-dashboard-panel', 1]]
             and acl.get('all') == 1, acl)
    ev.check(f'{label}: the 2 retained messages are stored', all(t in (probe.get('retained') or []) for t in src['retained_messages']),
             probe.get('retained'))
    rules = [r[0] for r in probe.get('rules') or []]
    ev.check(f'{label}: rules b1_rule_republish and b1_rule_http, connector b1_http, action b1_http_action',
             all(r in rules for r in src['rules']) and any(c[1] == 'b1_http' for c in probe.get('connectors') or [])
             and any(a[1] == 'b1_http_action' for a in probe.get('actions') or []),
             {k: probe.get(k) for k in ('rules', 'connectors', 'actions')})
    ev.check(f'{label}: the banned client', ['clientid', 'b1-banned-client'] in (probe.get('banned') or []), probe.get('banned'))
    ev.check(f'{label}: dashboard users admin and b1ops', all(u in (probe.get('dashboard_users') or []) for u in src['dashboard_users']),
             probe.get('dashboard_users'))
    ev.check(f'{label}: HA\'s API key b1-import-key is there and works', ['b1-import-key', True] in (probe.get('api_keys') or [])
             and probe.get('api_key_works') == 200, {'keys': probe.get('api_keys'), 'works': probe.get('api_key_works')})
    ev.check(f'{label}: authorization no_match stays deny (this device\'s policy)',
             (probe.get('authz_settings') or {}).get('no_match') == 'deny', {'settings': probe.get('authz_settings'),
                                                                            'sources': probe.get('authz_sources')})
    mq = probe.get('mqtt') or {}
    ev.check(f'{label}: MQTT: HA\'s three users log in with HA\'s passwords',
             all(mq.get(f'login_{u}') == 0 for u, _p in users), {k: v for k, v in mq.items() if k.startswith('login_')})
    retained = mq.get('gateway_retained') or {}
    ev.check(f'{label}: MQTT: b1-gateway subscribed to b1/retained/# gets the 2 retained messages',
             retained.get('suback') in (0, 1) and set(src['retained_messages']) <= set(retained.get('topics') or []),
             retained)
    ev.check(f'{label}: MQTT: an ACL-denied topic (b1-sensor on b1/secret/#) is refused (SUBACK 0x80)',
             mq.get('sensor_denied_topic_suback') == 0x80, mq.get('sensor_denied_topic_suback'))
    ev.check(f'{label}: MQTT: anonymous login refused, wrong password refused, banned client id refused',
             mq.get('anonymous') not in (0, None) and mq.get('wrong_password') not in (0, None)
             and mq.get('banned_client') not in (0, None),
             {k: mq.get(k) for k in ('anonymous', 'wrong_password', 'banned_client')})
    ev.check(f'{label}: MQTT: this device\'s bootstrap user woow still logs in', mq.get('bootstrap_woow') == 0,
             mq.get('bootstrap_woow'))
    ev.log(f'  note: b1-sensor on a topic no rule lists (b1/retained/#): SUBACK {mq.get("sensor_unlisted_topic_suback")}'
           ' (HA allowed it with no_match=allow; this device denies it)')
    ev.check(f'{label}: emqx ctl status: the node is started', any('is started' in line for line in probe.get('ctl_status') or []),
             probe.get('ctl_status'))
    STATE.setdefault('emqx_api_ready_after_s', []).append(probe.get('api_ready_after_s'))


def verify_headscale(ev, args, machine, label, test_mode=False, upload=None):
    src = source(machine)['headscale']
    probe = device_python(HEADSCALE_PROBE, {})
    ev.save(f'probe-headscale-{machine}-{int(time.time())}.json', probe)
    ev.check(f'{label}: users default, alice, bob', [u[1] for u in probe.get('users') or []] ==
             [u[1] for u in src['users']], probe.get('users'))
    nodes = {n[1]: n for n in probe.get('nodes') or []}
    want = {n['given_name']: n for n in src['nodes']}
    ok_nodes = all(name in nodes and nodes[name][0] == n['id'] and nodes[name][2] == n['user']
                   and nodes[name][3] == n['ip_addresses'] for name, n in want.items())
    ev.check(f'{label}: both nodes with their ids, users and 100.64 addresses', ok_nodes and len(nodes) == len(want),
             probe.get('nodes'))
    routes = {name: nodes.get(name, [None] * 5)[4] for name in want}
    ev.check(f'{label}: the approved route 192.168.88.0/24 of b1-bob-nas', routes.get('b1-bob-nas') == ['192.168.88.0/24'],
             routes)
    ev.check(f'{label}: HA\'s pre-auth keys (alice single-use, bob reusable)',
             sorted((k[1], k[2]) for k in probe.get('preauthkeys') or []) == [('alice', False), ('bob', True)],
             probe.get('preauthkeys'))
    ev.check(f'{label}: the DNS extra record b1-nas.ts.local', ['b1-nas.ts.local', 'A', '100.64.0.250'] in
             (probe.get('dns_records') or []), probe.get('dns_records'))
    before = STATE.get('pre_hs_apikeys') or []
    ev.check(f'{label}: only this device\'s API keys are left (same as before the import) and they work',
             probe.get('apikeys') == before and (probe.get('api_device_key') or [0])[0] == 200,
             {'after': probe.get('apikeys'), 'before': before, 'device key on /api/v1/node': probe.get('api_device_key')})
    ev.check(f'{label}: the Noise key moved: private key sha256 and public key equal HA\'s',
             probe.get('noise_sha256') == src['noise_private_key_sha256'] and probe.get('server_public_key') ==
             src['server_public_key'], {'sha_equal': probe.get('noise_sha256') == src['noise_private_key_sha256'],
                                        'public': probe.get('server_public_key')})
    ev.check(f'{label}: Headscale metrics answer 200', probe.get('health_metrics') == 200, probe.get('health_metrics'))


VERIFY = {'omnigent': verify_omnigent, 'hermes': verify_hermes, 'emqx': verify_emqx, 'headscale': verify_headscale}


def hermes_owner_baseline(ev):
    if STATE.get('hermes_owner_exceptions_before') is not None:
        return
    proc = owner('podman', 'exec', 'hermes-agent', 'find', '/opt/data', '(', '!', '-uid', '1000', '-o', '!', '-gid',
                 '1000', ')', '-printf', '%U:%G %P\n')
    STATE['hermes_owner_exceptions_before'] = out(proc).strip().splitlines()
    ev.log(f'hermes: files not 1000:1000 before any import (made by the image): '
           f'{STATE["hermes_owner_exceptions_before"]}')
    save_state()


def scenario_x86(ev, args):
    hermes_owner_baseline(ev)
    for app in ('omnigent', 'hermes', 'headscale', 'emqx'):
        import_once(ev, args, 'x86-enc', [app])
    import_once(ev, args, 'x86-cold', ['emqx'])


def scenario_arm(ev, args):
    import_once(ev, args, 'arm-enc', ['omnigent'])
    scenario_runner(ev, args)
    import_once(ev, args, 'arm-enc', ['headscale'], label='import arm-enc/headscale (WAL-only database)')
    scenario_tailscale(ev, args)
    import_once(ev, args, 'arm-enc', ['emqx'])
    import_once(ev, args, 'arm-cold', ['emqx'])


def scenario_forms(ev, args):
    """The unencrypted and the uncompressed backups of both machines: the apps other than EMQX in ONE conversion and
    ONE restore (multi-app jobs), EMQX (hot in these files) on its own so that a refusal cannot hide the others."""
    hermes_owner_baseline(ev)
    for tag in ('x86-plain', 'x86-unc', 'arm-plain', 'arm-unc'):
        import_once(ev, args, tag, [a for a in UPLOADS[tag][3] if a != 'emqx'])
        import_once(ev, args, tag, ['emqx'])


def scenario_testmode(ev, args):
    """Test mode on real data: HA's backups hold only a PAUSED task, so a lab-made copy of the x86 unencrypted file
    with one more, ACTIVE task (tm_build.py) is imported twice: in test mode every task ends paused; without it the
    active task stays active (so it is test mode that pauses it). The real x86 file in test mode as well."""
    if not STATE.get('ha_x86-active'):
        rc, reply = upload(ACTIVE_FIXTURE, ev=ev)
        meta = reply.get('ha_backup') or {}
        if not ev.check('testmode: the lab-made file (one active task) uploads as an HA backup', rc == 0 and meta.get('id'),
                        meta.get('id') or reply.get('error')):
            return
        STATE['ha_x86-active'] = meta['id']
        save_state()
    job, took = run_check(STATE['ha_x86-active'], ['omnigent'], ev=ev, tag='check-x86-active-omnigent')
    ev.time('check', 'x86-active', 'omnigent', took, job)
    section = ((job.get('result') or {}).get('ha_check') or {}).get('apps', [{}])[0].get('omnigent') or {}
    ev.check('testmode: the check sees 2 scheduled tasks, 1 active', job['state'] == 'succeeded'
             and section.get('scheduled_tasks') == 2 and section.get('scheduled_tasks_active') == 1,
             {k: section.get(k) for k in ('scheduled_tasks', 'scheduled_tasks_active')})
    for test_mode in (True, False):
        import_once(ev, args, 'x86-active', ['omnigent'], test_mode=test_mode)
        name = f'ha-import-x86-active-omnigent{"-test" if test_mode else ""}.json'
        reminders = []
        if (ev.dir / name).exists():
            reminders = json.loads((ev.dir / name).read_text(encoding='utf-8')).get('reminders_by_app', {}).get('omnigent') or []
        words = '測試匯入已暫停 1 個排程' if test_mode else 'HA 的 1 個啟用中的排程會在這台執行'
        ev.check(f'testmode: the Omnigent reminder {"says the active task was paused" if test_mode else "warns that the active task will run here"}',
                 any(words in line for line in reminders), reminders)
    import_once(ev, args, 'x86-enc', ['omnigent'], test_mode=True)


# ---------------------------------------------------------------- the re-pointed Omnigent runner (RPi5 backup)

RUNNER_REKEY = r'''
import glob, json, os, sys, time
req = json.loads(sys.stdin.read())
home = os.path.join(os.path.expanduser("~"), ".b1lab", "runner-home", ".omnigent")
path = os.path.join(home, "auth_tokens.json")
data = json.load(open(path))
old = sorted(k for k in data if k != req["url"])
entry = data[old[0]] if old else data[req["url"]]
new = {req["url"]: entry}
tmp = path + ".new"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(new, f)
os.replace(tmp, path)
removed = []
for p in [os.path.join(home, "host.pid")] + glob.glob(os.path.join(home, "daemons", "*.json")):
    if os.path.exists(p):
        os.remove(p)
        removed.append(os.path.relpath(p, home))
host = ""
for line in open(os.path.join(home, "config.yaml")):
    if line.strip().startswith("host_id:"):
        host = line.split(":", 1)[1].strip()
print(json.dumps({"old_urls": old, "user_id": entry.get("user_id"), "access_token_left_s": round(entry.get("expires_at", 0) - time.time()),
                  "refresh_grant": bool(entry.get("refresh_token")), "runtime_files_removed": removed, "host_id": host}))
'''

RUNNER_TOKEN = PROBE_COMMON + r'''
home = os.path.join(os.path.expanduser("~"), ".b1lab", "runner-home", ".omnigent")
entry = json.load(open(os.path.join(home, "auth_tokens.json")))[REQ["url"]]
out = {"access_token_left_s": round(entry.get("expires_at", 0) - time.time()), "_issued_credentials": [entry["token"], entry["refresh_token"]]}
code, me = call("http://127.0.0.1:8000", "GET", "/auth/me", token=entry["token"])
me = (me or {}).get("user") if isinstance((me or {}).get("user"), dict) else (me or {})
out["auth_me_with_ha_token"] = [code, me.get("id")]
print(json.dumps(out))
'''

RUNNER_HOST = PROBE_COMMON + r'''
B = "http://127.0.0.1:8000"
code, body = call(B, "POST", "/auth/login", {"username": REQ["member"][0], "password": REQ["member"][1]})
t = (body or {}).get("token")
out = {}
deadline = time.monotonic() + REQ.get("wait", 120)
while True:
    c, h = call(B, "GET", "/v1/hosts/" + REQ["host_id"], token=t)
    out["host"] = [c, (h or {}).get("status"), (h or {}).get("name"), (h or {}).get("user_id")]
    if (c == 200 and str((h or {}).get("status")).lower() in ("online", "1")) or time.monotonic() > deadline:
        break
    time.sleep(3)
c, fs = call(B, "GET", "/v1/hosts/%s/filesystem?limit=20" % REQ["host_id"], token=t)
out["filesystem"] = [c, len(items(fs, "entries", "files")) if isinstance(fs, (dict, list)) else None,
                     sorted(list(fs.keys()))[:8] if isinstance(fs, dict) else None]
rc, so, se = pexec("omnigent-postgres", "psql", "-X", "-q", "-U", "omnigent", "-d", "omnigent", "-Atc",
                   "SELECT encode(host_id, 'hex') || ':' || user_id || ':' || name || ':' || status::text FROM hosts WHERE host_id = decode('%s', 'hex')" % REQ["host_id"])
out["db_row"] = so.strip()
home = os.path.join(os.path.expanduser("~"), ".b1lab", "runner-home", ".omnigent")
entry = json.load(open(home + "/auth_tokens.json")).get(REQ["url"]) or {}
out["token_after"] = {"access_token_left_s": round(entry.get("expires_at", 0) - time.time()), "user_id": entry.get("user_id")}
out["_issued_credentials"] = [t, entry["token"], entry["refresh_token"]]
print(json.dumps(out))
'''


def owner_home():
    return out(owner('printenv', 'HOME', check=True)).strip()


def runner_probe(secrets, script, request, expected, *, timeout=600):
    """Register every required issued credential before returning data to evidence writers."""
    result = device_python(script, request, timeout=timeout)
    issued = result.pop('_issued_credentials', None)
    if not isinstance(issued, list) or len(issued) != expected or any(
            not isinstance(v, str) or len(v) < 6 for v in issued):
        raise Failed('runner credentials missing or invalid')
    secrets.register_issued(issued)
    return result


# These programs contact only the device-local Omnigent API, with no proxy or
# redirects. Each response reaches the registry before any next request.
CREDENTIAL_HTTP = r'''
import json, sys, urllib.error, urllib.request
req = json.loads(sys.stdin.read())
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
if req["stage"] == "login":
    path = "/auth/login"
    body = json.dumps({"username": req["username"], "password": req["password"], "issue_refresh": True}).encode()
    content_type = "application/json"
elif req["stage"] == "refresh":
    import urllib.parse
    path = "/oauth/token"
    body = urllib.parse.urlencode({"grant_type": "refresh_token", "refresh_token": req["refresh_token"]}).encode()
    content_type = "application/x-www-form-urlencoded"
else:
    raise SystemExit("invalid stage")
try:
    request = urllib.request.Request("http://127.0.0.1:8000" + path, data=body, headers={"Content-Type": content_type})
    with opener.open(request, timeout=15) as response:
        result = json.load(response)
        if response.status != 200 or not isinstance(result, dict):
            raise ValueError("invalid response")
except (urllib.error.URLError, OSError, ValueError):
    raise SystemExit("credential request failed") from None
if req["stage"] == "login":
    result = {"token": result.get("token"), "refresh_token": result.get("refresh_token")}
else:
    result = {k: result[k] for k in ("access_token", "refresh_token") if k in result}
print(json.dumps(result))
'''


def direct_credential_probe(secrets, username, password):
    """Collect one fresh lab login and refresh; proves only this probe's events."""
    login = device_python(CREDENTIAL_HTTP, {'stage': 'login', 'username': username, 'password': password})
    # Preserve valid returned values even if another required field is missing.
    for key in ('token', 'refresh_token'):
        value = login.get(key)
        if isinstance(value, str) and len(value) >= 6:
            secrets.register_issued([value])
    login_event = {'sequence': 0, 'kind': 'login', 'issue_refresh': True,
                   'token': login.get('token'), 'refresh_token': login.get('refresh_token')}
    # Validate the login before using the grant; no automatic retries.
    try:
        _event_module.register_runner_events([login_event, {'sequence': 1, 'kind': 'end'}],
                                             lambda name, value: secrets.register_issued([value]))
    except _event_module.CredentialCoverageError:
        raise Failed('credential login event missing or invalid') from None
    refresh = device_python(CREDENTIAL_HTTP, {'stage': 'refresh', 'refresh_token': login['refresh_token']})
    for key in ('access_token', 'refresh_token'):
        value = refresh.get(key)
        if isinstance(value, str) and len(value) >= 6:
            secrets.register_issued([value])
    refresh_event = {'sequence': 1, 'kind': 'refresh', 'access_token': refresh.get('access_token')}
    if 'refresh_token' in refresh:
        refresh_event['refresh_token'] = refresh['refresh_token']
    events = [login_event, refresh_event, {'sequence': 2, 'kind': 'end'}]
    try:
        count = _event_module.register_runner_events(events, lambda name, value: secrets.register_issued([value]))
    except _event_module.CredentialCoverageError:
        raise Failed('credential refresh event missing or invalid') from None
    return {'probe': 'direct-login-refresh', 'credential_count': count, 'runner_coverage': False}


def scenario_credentials(ev, args):
    # Separate explicitly provisioned disposable lab identity; never fall back to
    # the prior runner's rejected identity or its stored grant.
    try:
        username = args.secrets['B1_CREDENTIAL_LAB_USER']
        password = args.secrets['B1_CREDENTIAL_LAB_PASSWORD']
    except KeyError:
        raise Failed('fresh credential-probe lab identity missing') from None
    result = direct_credential_probe(args.secrets, username, password)
    ev.check('direct lab login and refresh events registered', True, result)


def scenario_runner(ev, args):
    # The legacy runner can refresh independently, between snapshots. No producer
    # exposes a complete event stream, so do not start it or touch its workspace.
    raise Failed('runner credential event source unavailable; coverage cannot be established')


# ---------------------------------------------------------------- the re-pointed tailscale client (RPi5 backup)

RELAY = r'''
# relay.py outer <unix socket> <host> <port>      : unix socket -> TCP host:port (dev-d's network namespace)
# relay.py inner <unix socket> <port> -- <cmd...>  : in a fresh network namespace: lo up, 127.0.0.1/::1:<port> ->
#                                                   unix socket, then run <cmd> (tailscaled) there
import os, socket, subprocess, sys, threading
def pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
def serve(listener, connect):
    while True:
        conn, _ = listener.accept()
        try:
            peer = connect()
        except OSError:
            conn.close()
            continue
        threading.Thread(target=pipe, args=(conn, peer), daemon=True).start()
        threading.Thread(target=pipe, args=(peer, conn), daemon=True).start()
mode, path = sys.argv[1], sys.argv[2]
if mode == "outer":
    host, port = sys.argv[3], int(sys.argv[4])
    if os.path.exists(path):
        os.remove(path)
    ls = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    ls.bind(path)
    os.chmod(path, 0o600)
    ls.listen(64)
    serve(ls, lambda: socket.create_connection((host, port), timeout=10))
else:
    port = int(sys.argv[3])
    cmd = sys.argv[sys.argv.index("--") + 1:]
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    def unix():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(path)
        return s
    for family, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        try:
            ls = socket.socket(family, socket.SOCK_STREAM)
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind((addr, port))
            ls.listen(64)
            threading.Thread(target=serve, args=(ls, unix), daemon=True).start()
        except OSError as e:
            print("relay: no listener on", addr, e, flush=True)
    sys.exit(subprocess.call(cmd))
'''


def ts(*argv, timeout=120):
    return root(f'{TS_DIR}/bin/tailscale', f'--socket={TS_RUN}/tailscaled.sock', *argv, timeout=timeout)


def ts_status():
    proc = ts('status', '--json')
    try:
        data = json.loads(out(proc))
    except ValueError:
        return {'error': proc.stderr.decode('utf-8', 'replace')[-200:]}
    me = data.get('Self') or {}
    return {'BackendState': data.get('BackendState'), 'AuthURL': bool(data.get('AuthURL')), 'ID': me.get('ID'),
            'HostName': me.get('HostName'), 'TailscaleIPs': me.get('TailscaleIPs'), 'PublicKey': me.get('PublicKey'),
            'Online': me.get('Online'), 'UserID': me.get('UserID'),
            'Peers': sorted([p.get('HostName'), (p.get('TailscaleIPs') or [None])[0]] for p in (data.get('Peer') or {}).values())}


def ts_stop():
    root('systemctl', 'stop', 'b1lab-tailscaled.service', 'b1lab-ts-relay.service', timeout=60)
    root('systemctl', 'reset-failed', 'b1lab-tailscaled.service', 'b1lab-ts-relay.service', timeout=60)


def scenario_tailscale(ev, args):
    """The real tailscale client that joined the RPi5's Headscale (lab volume b1-ts-alice-state, node b1-ts-alice,
    100.64.0.2) re-pointed to this device's server URL: its binaries (from the lab image) and a COPY of its state run
    inside dev-d as a transient unit, in a fresh network namespace whose only way out is a relay to dev-d's Headscale
    (localhost:28080), so the RPi5 is never contacted. No auth key is given: the node must continue, not re-register."""
    src = source('arm')
    client = src['tailscale_client']
    volume = LAB / 'storage' / 'volumes' / 'b1-ts-alice-state' / '_data'
    if not (volume / 'tailscaled.state').is_file():
        raise Failed(f'{volume}/tailscaled.state is missing')
    work = Path(args.scratch) / 'ts-bin'
    work.mkdir(parents=True, exist_ok=True)
    for name in ('tailscale', 'tailscaled'):
        if not (work / name).exists():
            run([LP, 'cp', f'b1-ts-alice:/usr/local/bin/{name}', str(work / name)], check=True, timeout=120)
    ts_stop()
    root('rm', '-rf', TS_DIR, TS_RUN)
    root('install', '-d', '-m', '0700', TS_DIR, f'{TS_DIR}/bin', f'{TS_DIR}/state', TS_RUN, check=True)
    for name in ('tailscale', 'tailscaled'):
        run([LP, 'cp', str(work / name), f'{DEVICE}:{TS_DIR}/bin/{name}'], check=True, timeout=120)
    root('chmod', '0755', f'{TS_DIR}/bin/tailscale', f'{TS_DIR}/bin/tailscaled', check=True)
    root('python3', '-I', '-c', 'import sys\nopen(sys.argv[1], "w").write(sys.stdin.read())', f'{TS_DIR}/relay.py',
         input=RELAY.encode(), check=True)
    tar = run(['tar', '-C', str(volume), '-cf', '-', '.'], timeout=120, check=True).stdout
    root('tar', '-C', f'{TS_DIR}/state', '--no-same-owner', '-xf', '-', input=tar, check=True)
    version = out(root(f'{TS_DIR}/bin/tailscale', 'version')).splitlines()[:1]
    root('systemd-run', '--unit=b1lab-ts-relay', '--quiet', 'python3', '-I', f'{TS_DIR}/relay.py', 'outer',
         f'{TS_RUN}/hs.sock', '127.0.0.1', '28080', check=True)
    root('systemd-run', '--unit=b1lab-tailscaled', '--quiet', 'unshare', '-n', 'python3', '-I', f'{TS_DIR}/relay.py',
         'inner', f'{TS_RUN}/hs.sock', '28080', '--', f'{TS_DIR}/bin/tailscaled', '--tun=userspace-networking',
         f'--state={TS_DIR}/state/tailscaled.state', f'--socket={TS_RUN}/tailscaled.sock', '--no-logs-no-support',
         '--encrypt-state=false',  # dev-d (privileged) sees the host's TPM device: never touch it
         check=True)
    first = {}
    for _ in range(30):
        time.sleep(1)
        first = ts_status()
        if first.get('BackendState') not in (None, 'NoState'):
            break
    ev.log(f'  tailscale {version}: state right after the start (old server unreachable): {first}')
    if first.get('BackendState') == 'Running':
        proc = ts('down')
        ev.log(f'  tailscale down: rc {proc.returncode} {proc.stderr.decode("utf-8", "replace")[-200:]}')
    started = time.monotonic()
    proc = ts('up', f'--login-server={HS_URL}', '--hostname=b1-ts-alice', '--accept-dns=false', '--timeout=90s',
              timeout=150)
    took = time.monotonic() - started
    up_text = (out(proc) + proc.stderr.decode('utf-8', 'replace'))[-800:]
    ev.check('tailscale: `tailscale up --login-server=<this device>` (no auth key, no --force-reauth) succeeds',
             proc.returncode == 0, f'rc {proc.returncode} in {took:.1f} s: {up_text}')
    after = {}
    for _ in range(30):
        after = ts_status()
        if after.get('BackendState') == 'Running' and after.get('TailscaleIPs'):
            break
        time.sleep(2)
    ev.save('tailscale-status.json', {'before': first, 'after': after, 'up_output': up_text})
    ev.check('tailscale: Running again with the same node (id, name, node key) and 100.64.0.2, no login URL',
             after.get('BackendState') == 'Running' and not after.get('AuthURL') and after.get('ID') == client['NodeID']
             and after.get('PublicKey') == client['NodePublicKey'] and after.get('TailscaleIPs') == client['TailscaleIPs'],
             {'after': after, 'expected': {k: client[k] for k in ('NodeID', 'NodePublicKey', 'TailscaleIPs')}})
    prefs = out(ts('debug', 'prefs'))
    try:
        control = json.loads(prefs).get('ControlURL')
    except ValueError:
        control = None
    ev.check('tailscale: the client\'s control server is now this device\'s URL', control == HS_URL, control)
    probe = device_python(HEADSCALE_PROBE, {})
    node = next((n for n in probe.get('nodes') or [] if n[1] == 'b1-ts-alice'), None)
    ev.check('tailscale: this device\'s Headscale shows b1-ts-alice online, same id 2 and 100.64.0.2, no new node',
             node is not None and node[0] == 2 and node[5] is True and node[3] == client['TailscaleIPs']
             and len(probe.get('nodes') or []) == len(src['headscale']['nodes']), probe.get('nodes'))
    query = ts('dns', 'query', 'b1-nas.ts.local', 'A')
    text = out(query) + query.stderr.decode('utf-8', 'replace')
    ev.check('tailscale: the extra DNS record resolves through the client (b1-nas.ts.local -> 100.64.0.250)',
             '100.64.0.250' in text, text[-400:])
    log = out(root('journalctl', '-u', 'b1lab-tailscaled.service', '-o', 'cat', '--no-pager', timeout=60))
    ev.save('tailscaled.log', log[-20000:])
    contacted = [line for line in log.splitlines() if '192.168.2.34' in line]
    ev.log(f'  tailscaled log lines naming the RPi5 address (blocked attempts only): {len(contacted)}')
    ev.check('tailscale: no new login was needed (no NeedsLogin/AuthURL in the log after the re-point)',
             'NeedsLogin' not in log.split('--login-server')[-1] and 'AuthURL is' not in log, 'see tailscaled.log')
    ts_stop()
    STATE['tailscale_tested'] = True
    save_state()


# ---------------------------------------------------------------- baseline, cleanup, leaks

MARKERS = (HERE / 'batch1_markers.py').read_text(encoding='utf-8')
BASELINE_MARKERS = {
    'omnigent': {'users:woowbk-lab-baseline', 'projects:woowbk-lab-baseline', 'scheduled_tasks:woowbk-lab-baseline'},
    'hermes': {'sessions:woowbk-lab-baseline', 'memory_markers:woowbk-lab-baseline', 'cron_jobs:woowbk-lab-baseline'},
    'emqx': {'mqtt_users:woowbk-lab-baseline', 'retained:woowbk-lab/baseline', 'banned:woowbk-lab-baseline'},
    'headscale': {'users:woowbk-lab-baseline', 'preauthkeys:woowbk-lab-baseline', 'nodes:woowbk-lab-baseline',
                  'dns_records:woowbk-lab-baseline.ts.local'},
}


def marker_names(found):
    names = set()
    for kind, value in found.items():
        if isinstance(value, dict):
            value = list(value)
        if isinstance(value, list):
            names |= {f'{kind}:{str(item).split(":")[0]}' for item in value if 'woowbk-lab' in str(item)}
    return names


def scenario_baseline(ev, args):
    for app in APPS:
        job, took = restore(BASELINE_IDS[app], [app], ev=ev, tag=f'baseline-{app}')
        ev.time('restore-baseline', '-', app, took, job)
        result = job.get('result') or {}
        created_backup(result.get('safety_backup_id'))
        ev.check(f'baseline: {app} restored from {BASELINE_IDS[app]}', job['state'] == 'succeeded',
                 f'{took:.0f} s {job.get("error")} safety={result.get("safety_backup_id")}')
        proc = run([LP, 'exec', '-i', DEVICE, OWNER, 'python3', '-I', '-c', MARKERS, app, 'read'], input=b'{}',
                   timeout=600)
        try:
            found = json.loads(out(proc).strip().splitlines()[-1])
        except (ValueError, IndexError):
            found = {'error': proc.stderr.decode('utf-8', 'replace')[-300:]}
        ev.save(f'baseline-markers-{app}.json', found)
        have = marker_names(found)
        ev.check(f'baseline: {app}: dev-d\'s own markers are back (batch1_markers.py read)',
                 BASELINE_MARKERS[app] <= have and not (have - BASELINE_MARKERS[app]), sorted(have))
        app_health(ev, app, f'baseline: {app}')
    # nothing of HA's left
    probe = device_python(HEADSCALE_PROBE, {})
    users = owner('podman', 'exec', 'omnigent-postgres', 'psql', '-X', '-q', '-U', 'omnigent', '-d', 'omnigent',
                  '-Atc', "SELECT count(*) FROM users WHERE id IN ('woow', 'b1member')")
    ev.check('baseline: no HA data left (Omnigent users woow/b1member, Headscale nodes of HA, its Noise key)',
             out(users).strip() == '0' and not any(n[1].startswith('b1-') for n in probe.get('nodes') or [])
             and probe.get('server_public_key') not in (source('x86')['headscale']['server_public_key'],
                                                        source('arm')['headscale']['server_public_key']),
             {'omnigent_ha_users': out(users).strip(), 'nodes': probe.get('nodes'),
              'public_key': probe.get('server_public_key')})
    save_state()


def labelled():
    found = {}
    for kind, argv, fmt in (('containers', ('ps', '-a'), '{{.Names}}'), ('volumes', ('volume', 'ls'), '{{.Name}}'),
                            ('networks', ('network', 'ls'), '{{.Name}}')):
        found[kind] = out(owner('podman', *argv, '--filter', JOB_LABEL, '--format', fmt)).split()
    return found


RUN_LIST = r'''
import json, os
out = {}
for path in ("/var/lib/woowtech-backup/staging", "/run/woowtech-backup"):
    try:
        out[path] = sorted(os.listdir(path))
    except OSError as e:
        out[path] = "missing" if isinstance(e, FileNotFoundError) else str(e)
print(json.dumps(out))
'''


def scenario_cleanup(ev, args):
    objects = labelled()
    ev.check('cleanup: no throwaway container, volume or network of a job left', not any(objects.values()), objects)
    listing = device_python(RUN_LIST, as_owner=False)
    staging = listing.get(STAGING)
    keys = [n for n in listing.get('/run/woowtech-backup') or [] if isinstance(n, str) and n.startswith('key-')]
    ev.check('cleanup: no staging folder and no key file left', staging in ([], 'missing') and not keys,
             listing)
    # this test's own helpers
    owner('podman', 'rm', '-f', '-t', '5', RUNNER_CTR)
    ts_stop()
    root('rm', '-rf', TS_DIR, TS_RUN)
    owner('rm', '-rf', '.b1lab')
    names = out(owner('podman', 'ps', '-a', '--format', '{{.Names}}')).split()
    units = out(root('systemctl', 'list-units', '--all', '--no-legend', 'b1lab-*')).strip()
    left = out(root('ls', '-d', TS_DIR, TS_RUN)).strip() + out(owner('ls', '-d', '.b1lab')).strip()
    ev.check('cleanup: the test\'s helpers are gone (runner container, tailscaled/relay units, copied state)',
             RUNNER_CTR not in names and not units and not left, {'containers': names, 'units': units, 'left': left})
    expected = {'omnigent-postgres', 'omnigent-server', 'omnigent-runner', 'hermes-postgresql', 'hermes-redis',
                'hermes-agent', 'woow-emqx', 'woow-emqx-entrance', 'headscale', 'headplane', 'headscale-entrance'}
    extra = sorted(set(names) - expected)
    ev.check('cleanup: appowner runs only the four apps\' containers', not extra and expected <= set(names),
             {'extra': extra, 'missing': sorted(expected - set(names))})
    if not args.keep_backups:
        listing = ok('list', ev=ev)
        present = {b['id'] for b in listing['backups']}
        deleted = []
        for backup_id in STATE.get('created_backups') or []:
            if backup_id in present and backup_id not in BASELINE_IDS.values():
                rc, reply = helper('delete', {'backup_id': backup_id, 'confirm': True})
                if rc == 0:
                    deleted.append(backup_id)
                else:
                    ev.log(f'  delete {backup_id}: {reply.get("error")}')
        listing = ok('list', ev=ev)
        left = sorted(b['id'] for b in listing['backups'])
        ev.check('cleanup: the test\'s converted and safety backups are deleted; dev-d\'s baseline backups stay',
                 all(b in left for b in BASELINE_IDS.values())
                 and not (set(left) & (set(STATE.get('created_backups') or []) - set(BASELINE_IDS.values()))),
                 {'deleted': len(deleted), 'left': left})
        STATE['created_backups'] = [b for b in STATE.get('created_backups') or [] if b not in deleted]
    save_state()


LEAK_SCAN = r'''
import json, os, subprocess, sys
req = json.loads(sys.stdin.read())
secrets = {name: value.encode() for name, value in req["secrets"].items() if value}
# this device's own app secrets (the import must never write them anywhere but the encrypted backups)
for name in req["podman_secrets"]:
    p = subprocess.run(["runuser", "-u", "appowner", "--", "env", "-i", "PATH=/usr/bin:/bin", "HOME=/home/appowner",
                        "XDG_RUNTIME_DIR=/run/user/%d" % req["uid"], "podman", "secret", "inspect", "--showsecret",
                        "--format", "{{.SecretData}}", name], capture_output=True, timeout=60)
    value = p.stdout.rstrip(b"\n")
    if p.returncode != 0 or len(value) < 8:
        raise RuntimeError("cannot inspect required device secret: " + name)
    secrets["device:" + name] = value
hits, scanned = {}, 0
roots = ["/var/lib/woowtech-backup/jobs", "/var/lib/woowtech-backup/ha-backups", "/var/lib/woowtech-backup/ha-imports.json",
         "/var/lib/woowtech-backup/index.json", "/var/lib/woowtech-backup/archives", "/run/woowtech-backup",
         "/var/lib/woowtech-backup/uploads", "/var/lib/woowtech-backup/staging"]
for root in roots:
    if not os.path.exists(root):
        continue
    paths = [root] if os.path.isfile(root) else [os.path.join(d, f) for d, _s, fs in os.walk(root) for f in fs]
    for path in paths:
        if path.endswith(".tar") and ("/ha-backups/" in path or "/archives/" in path):
            continue  # the uploaded HA files (encrypted or the test data) and the encrypted backups themselves
        try:
            data = open(path, "rb").read()
        except OSError as error:
            raise RuntimeError("cannot scan " + path) from error
        scanned += 1
        for name, secret in secrets.items():
            if secret in data:
                hits[path + " " + name] = data.count(secret)
journal = subprocess.run(["journalctl", "-o", "cat", "--no-pager"], capture_output=True, check=True).stdout
helper = subprocess.run(["journalctl", "-o", "cat", "--no-pager", "_COMM=woowtech-cockp", "+", "SYSLOG_IDENTIFIER=woowtech-cockpit-backup"], capture_output=True, check=True).stdout
for name, secret in secrets.items():
    if secret in journal:
        hits["journal " + name] = journal.count(secret)
    if secret in helper:
        hits["helper journal " + name] = helper.count(secret)
print(json.dumps({"scanned": scanned, "journal_bytes": len(journal), "names": len(secrets), "hits": hits}))
'''


def leak_scan_request(args):
    names = [n for n in args.secrets.values if n not in args.secrets.names]
    request = {'secrets': {n: args.secrets[n] for n in names if len(args.secrets[n]) >= 6},
               'podman_secrets': ['omnigent-postgres-password', 'omnigent-admin-password', 'omnigent-runner-password',
                                  'hermes-api-server-key', 'hermes-webhook-secret', 'hermes-dashboard-session-secret',
                                  'hermes-dashboard-password', 'hermes-postgres-password', 'woow-emqx-dashboard-password',
                                  'woow-emqx-node-cookie', 'woow-emqx-mqtt-password', 'headscale-headplane-cookie',
                                  'headscale-entrance-password', 'headscale-headplane-api-key'],
               'uid': 1019}
    return request


def scenario_leaks(ev, args):
    request = leak_scan_request(args)
    # Direct probe events cover only that probe; independently running services
    # and the old runner remain unobserved, so a zero-hit scan cannot pass.
    report = device_python(LEAK_SCAN, request, as_owner=False, timeout=900)
    ev.save('leaks-partial.json', report)
    raise Failed('credential coverage incomplete: runner and other service events unavailable')


def scenario_summary(ev, args):
    """Everything this test recorded across its runs (STATE): per app the check, convert and restore times, and
    every run's evidence folder with its result."""
    rows = STATE.get('timings') or []
    table = {}
    for row in rows:
        if row['kind'] in ('check', 'convert', 'restore', 'restore-baseline') and row.get('state') in ('succeeded', None):
            table.setdefault(f'{row["upload"]}/{row["app"]}', {}).setdefault(row['kind'], []).append(row['wall_s'])
    lines = [f'{key:36} ' + '  '.join(f'{kind} {",".join(str(s) for s in secs)} s' for kind, secs in sorted(kinds.items()))
             for key, kinds in sorted(table.items())]
    ev.save('summary-timings.txt', '\n'.join(lines) + '\n')
    ev.save('summary.json', {'timings': table, 'runs': STATE.get('runs'), 'hot_refused': STATE.get('hot_refused'),
                             'emqx_api_ready_after_s': STATE.get('emqx_api_ready_after_s')})
    for line in lines:
        ev.log('  ' + line)
    ev.check('summary written', True, f'{len(rows)} timings, {len(STATE.get("runs") or [])} runs')


# ---------------------------------------------------------------- main

def deploy(args, ev):
    script = Path(args.deploy) / 'deploy-src.sh'
    ev.log(f'deploying {args.src} to dev-d')
    proc = run([str(script), 'd', '--src', args.src], timeout=1800)
    ev.save('deploy.log', out(proc)[-20000:] + proc.stderr.decode('utf-8', 'replace')[-5000:])
    if proc.returncode != 0:
        raise Failed(f'deploy failed ({proc.returncode})')
    status = ok('status', ev=ev)
    ev.log(f'engine {status.get("version")} apps {[(a["id"], a["state"]) for a in status.get("apps") or []]}')


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--self-check', action='store_true', help='offline syntax check; never accesses the device or secrets')
    parser.add_argument('scenarios', nargs='*')
    parser.add_argument('--deploy', help='lab script directory with deploy-src.sh (deploys --src first)')
    parser.add_argument('--src', help='the Woow_cockpit tree to deploy')
    parser.add_argument('--only-upload', action='append', help='check: only these upload tags')
    parser.add_argument('--only-app', action='append', help='check: only these apps')
    parser.add_argument('--keep-backups', action='store_true', help='cleanup: keep the converted and safety backups')
    parser.add_argument('--scratch', default=str(LAB / 'run' / 'b1-import'),
                        help='host folder for the tailscale binaries copied out of the lab image')
    parser.add_argument('--evidence', default='b1-import', help='evidence folder below ~/.woowbk-lab/evidence')
    args = parser.parse_args()
    if args.self_check:
        names = ('OMNI_PROBE', 'HERMES_PROBE', 'EMQX_PROBE', 'HEADSCALE_PROBE',
                 'RUNNER_REKEY', 'RUNNER_TOKEN', 'RUNNER_HOST', 'RELAY', 'RUN_LIST', 'LEAK_SCAN', 'CREDENTIAL_HTTP')
        for name in names:
            compile(globals()[name], name, 'exec')
        print(f'offline self-check passed: {len(names)} embedded Python programs compiled')
        return
    # The privileged device has network access unless independently restricted. Do not
    # run real imports, deploy, or cleanup until lab isolation and secret handling are fixed.
    parser.error('real lab runs disabled pending verified network isolation and secret-handling fixes')
    args.secrets = Secrets([SECRET_DIR / 'b1-creds.env', SECRET_DIR / 'ha-import-creds.env'],
                           SECRET_DIR / 'dev-d-markers.json')
    ev = Evidence(args.secrets, re.sub(r'[^A-Za-z0-9_.-]', '', args.evidence) or 'b1-import')
    load_state()
    scenarios = args.scenarios or list(ALL)
    try:
        if args.deploy:
            deploy(args, ev)
        for name in scenarios:
            ev.log(f'== {name}')
            try:
                if name.startswith('import:'):
                    _, tag, apps = name.split(':', 2)
                    import_once(ev, args, tag, apps.split('+'))
                elif name in ALL + EXTRA:
                    globals()[f'scenario_{name}'](ev, args)
                else:
                    raise Failed(f'unknown scenario {name}')
            except Failed as error:
                ev.check(f'{name}: scenario ran', False, str(error))
            finally:
                save_state()
    finally:
        save_state()
    sys.exit(0 if ev.finish() else 1)


if __name__ == '__main__':
    main()
