"""Item C, Omnigent through the PUBLIC product path (lane arm54-2, 2026-11-24): a REAL RPi5 HA backup (add-on
woow-omnigent 0.1.23, plain 45670371 or encrypted a2dc9bfd) through the INTEGRATED production engine on .54 into the test
owner's rootless Omnigent 0.21.0 (arm64) under his user systemd.

usage (through arm54_final_control.py run): arm54_final_owner_omnigent_public.py <workspace> b1-plain|b1-enc

The earlier runs on .54 (72/72 rootful, owner-omnigent-attempt2 90/90) were made while the public import was held
(SECURITY_BLOCKER) and converted through the internal candidate. The owner's decision 1 replaced the hold by the product
path (integration 97c22c9); this run uses nothing else: the public HA check and the public conversion as ordinary jobs
(`run-job <id>` in their own process, production dependencies, OwnerRunner; nothing is injected or patched), with the
target running the whole time, like on any device.

One attempt = (1) remove what an earlier attempt of this script left (the engine directory is moved aside), (2) deploy the
target from the Woow Omnigent package quadlets 6e4f0c0 as the owner (systemctl --user), (3) the engine: key-init,
catalog-suggest (cold variant) + catalog-install, upload-begin/-finish, ha-check-start, ha-convert-start, restore-start,
job-status, list through cli.main as root; (4) logins with HA's passwords, the kept admin of this device, data, files,
the database schema and roles equal to this device's own before the import (HA's structure is never used), restart, an
AUTOMATIC rollback (a second restore whose server start fails once), the manual rollback (restore-start of the first
restore's own safety backup); (5) the Omnigent units are stopped at the end. The very FIRST restore of the converted backup is
one whose server start fails once (FIRST-IMPORT rollback): what comes back must be this device's own state from before any
import (asked for by the EMQX lane's verifier: a rollback that starts from the imported state cannot tell "rolled back" from
"nothing changed"); the job's log must show that every volume was rebuilt twice (import, then rollback).

Stated deviations: runner placeholder (the package's runner image is a local build without arm64; the pinned
PostgreSQL image is tagged localhost/woow-omnigent-runner:0.21.0-2 and the runner quadlet gets a shell that sleeps; the Pi
agent is out of scope); published port 127.0.0.1:28000 in the owner's private network namespace (lo only, memory cap); the
catalog draft gets the loopback health URL when suggest finds none.
Secrets: HA's test logins (and for b1-enc the HA backup key) arrive in 0600 files read and unlinked at start; the target's
passwords are generated here and only reach the owner's podman secrets; tokens stay in memory; the output is scanned for
every value before it is printed and replaced by a fixed failure if one is found."""
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid

from arm54_final_runtime import ROOT, kernel_state, private_dir, report, sha256_file
import arm54_final_owner_common as oc

from woowbackup import cli, habackup, haimport, ha_omnigent, hasecuretar  # noqa: E402
from woowbackup.paths import Paths  # noqa: E402

KIND = sys.argv[2] if len(sys.argv) > 2 else ''
assert KIND in ('b1-plain', 'b1-enc'), 'kind-refused'
# The RPi5's B1 backups, attested byte for byte against the RPi5 itself on 2026-11-23 (source-provenance-34).
ATTESTED = {'b1-plain': ('45670371', '1e6a4665315bc69fd114f8d43f7d429aecab53f07d07793ecf8c2c057a92c5d4'),
            'b1-enc': ('a2dc9bfd', '6d0647f0acb2e0d95043d66852c08bbc020d409d4f6747f817c10f94e2c33d1c')}
CHAIN = json.loads((ROOT / 'input' / ('chain-%s.json' % KIND)).read_text())
ARCHIVE = ROOT / 'input' / CHAIN['archive']
KEY_FILE = ROOT / 'input' / CHAIN['key_file'] if CHAIN.get('key_file') else None
PATHS = Paths(base=ROOT / 'engine')
PACKAGE = ROOT / 'source/tests/e2e/lab/evidence/arm54-final-20261123/omnigent-package-6e4f0c0/quadlet'
PG_IMAGE = ('docker.io/library/postgres:16.15-alpine3.24'
            '@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139')
SERVER_IMAGE = ('ghcr.io/omnigent-ai/omnigent-server:v0.21.0'
                '@sha256:9bba2964f015ddbb61da0924267effd1801c0db8f44ecec95f401f24d9a3f90c')
RUNNER_IMAGE = 'localhost/woow-omnigent-runner:0.21.0-2'
DB, SERVER, RUNNER = 'omnigent-postgres', 'omnigent-server', 'omnigent-runner'
UNITS = (DB + '.service', SERVER + '.service', RUNNER + '.service')
DBVOL, SERVERVOL, PIVOL = 'omnigent-postgres-data', 'omnigent-server-data', 'omnigent-pi-data'
VOLUMES = (DBVOL, SERVERVOL, PIVOL)
VOLUME_UNITS = ('omnigent-postgres-volume.service', 'omnigent-server-volume.service', 'omnigent-pi-volume.service')
SECRET_NAMES = ('omnigent-postgres-password', 'omnigent-database-url', 'omnigent-admin-password',
                'omnigent-runner-password')
TARGET_ADMIN, RUNNER_USER = 'a54-target-admin', 'a54-runner'
PORT = 28000
RENDER = {'@@OMNIGENT_BIND@@': '127.0.0.1', '@@OMNIGENT_PORT@@': str(PORT), '@@OMNIGENT_ACCOUNTS_BASE_URL@@': '',
          '@@OMNIGENT_ADMIN_USERNAME@@': TARGET_ADMIN, '@@OMNIGENT_RUNNER_USERNAME@@': RUNNER_USER,
          '@@OMNIGENT_PI_VOLUME@@': 'omnigent-pi.volume'}
# PID 1 of a container ignores SIGTERM without a handler (a bare `sleep` is killed after the stop timeout and its
# unit ends 'failed', owner-omnigent-attempt1), so the placeholder shell traps TERM and exits 0.
RUNNER_PLACEHOLDER = ('# lane arm54-2 placeholder (no arm64 runner image; the Pi agent is out of scope)\n'
                      'Entrypoint=/bin/sh\nExec=-c "trap \'exit 0\' TERM INT; sleep infinity & wait"\n'
                      'PodmanArgs=--image-volume=ignore\n')
BASE_URL = 'http://127.0.0.1:%d' % PORT
HEALTH = BASE_URL + '/health'
QUADLET_DIR, USER_UNIT_DIR = '.config/containers/systemd', '.config/systemd/user'
DROPIN, MARKER = USER_UNIT_DIR + '/omnigent-server.service.d/50-a54-one-shot.conf', '.a54-omnigent-fail-once'
RUN_JOB = '''import sys
for path in (%r, %r):
    sys.path.insert(0, path)
from woowbackup import cli
from woowbackup.paths import Paths
sys.exit(cli.main(['run-job', sys.argv[1]], paths=Paths(base=%r)))
''' % (str(ROOT / 'pydeps'), str(ROOT / 'source/backup-engine'), str(ROOT / 'engine'))
FRONTEND = 'http://127.0.0.1:8123/manifest.json'  # .54's own Home Assistant, read-only GET in .54's own namespace
MEM_FLOOR = 250 * 1024 ** 2

checks, facts, jobs_seen = {}, {}, {}
PRIVATE = []
out = {'status': 'failed', 'phase': 'start', 'commercial_acceptance': 'not-complete', 'owner': oc.OWNER,
       'runner': 'production OwnerRunner (runuser + rootless Podman + systemd --user) via the root CLI and run-job',
       'conversion': 'the PUBLIC product path (ha-check-start, ha-convert-start); nothing injected, target running',
       'source': {'host': '192.168.2.34', 'slug': CHAIN['slug'], 'archive_sha256': ATTESTED[KIND][1],
                  'addon': 'woow-omnigent 0.1.23', 'encrypted_backup': KEY_FILE is not None},
       'checks': checks, 'facts': facts, 'jobs': jobs_seen}
started = time.monotonic()
launched = []
WORK = private_dir('work', 'owner-omni-%d' % int(time.time()))
KERNEL_BEFORE = kernel_state()
facts['kernel_before'] = dict(KERNEL_BEFORE, modules=len(KERNEL_BEFORE['modules']))


def private(value):
    if isinstance(value, str):
        value = value.encode()
    if isinstance(value, bytes) and len(value.strip()) >= 6:
        PRIVATE.append(value)
        PRIVATE.append(value.strip())
    return value


def check(name, ok, **detail):
    checks[name] = bool(ok)
    if detail:
        facts[name] = detail
    return bool(ok)


def must(name, ok, **detail):
    if not check(name, ok, **detail):
        raise AssertionError(name)


def rid(tag):
    return 'a54m-%s-%s' % (tag, uuid.uuid4().hex[:12])


def call(command, request=None):
    buf = io.StringIO()
    svc = cli.Services(PATHS, launcher=launched.append, unit_active=lambda unit: False)
    code = cli.main([command], stdin=io.StringIO(json.dumps(request or {})), stdout=buf, services=svc)
    reply = json.loads(buf.getvalue().strip().splitlines()[-1])
    if code != 0 or not reply.get('ok'):
        err = reply.get('error') or {}
        facts['cli_refusal'] = {'command': command, 'code': err.get('code'),
                                'message': oc.LONG_TOKEN.sub('<masked>', str(err.get('message')))[:400]}
        raise RuntimeError('cli-refused')
    return reply


class Watch(threading.Thread):
    """Every 5 s in .54's own network namespace (started before the engine joins the owner's one): MemAvailable and,
    every 15 s, one GET of .54's own Home Assistant frontend. Below MEM_FLOOR three times in a row the owner's Omnigent
    units are stopped (the owner's manager is memory capped as well, so .54's own services are never the victims)."""

    def __init__(self):
        super().__init__(daemon=True)
        self.stop = threading.Event()
        self.min_mem, self.samples, self.low, self.tripped = None, 0, 0, False
        self.frontend = {'every_seconds': 15, 'ok': 0, 'failed': 0, 'max_latency_seconds': 0.0, 'over_5s': 0}

    def run(self):
        while not self.stop.is_set():
            for line in Path('/proc/meminfo').read_text().splitlines():
                if line.startswith('MemAvailable:'):
                    value = int(line.split()[1]) * 1024
                    self.min_mem = value if self.min_mem is None else min(self.min_mem, value)
                    self.low = self.low + 1 if value < MEM_FLOOR else 0
            if self.low >= 3 and not self.tripped:
                self.tripped = True
                oc.systemctl('stop', *reversed(UNITS), timeout=300, check=False)
            if self.samples % 3 == 0:
                t0 = time.monotonic()
                try:
                    with urllib.request.urlopen(FRONTEND, timeout=20) as response:
                        ok = response.status == 200
                except Exception:  # noqa: BLE001 - informational sample
                    ok = False
                took = time.monotonic() - t0
                self.frontend['ok' if ok else 'failed'] += 1
                self.frontend['max_latency_seconds'] = round(max(self.frontend['max_latency_seconds'], took), 3)
                self.frontend['over_5s'] += took > 5
            self.samples += 1
            self.stop.wait(5)


def run_job(label, start_command, request, timeout, expect='succeeded'):
    before = len(launched)
    job_id = call(start_command, request)['job_id']
    must('%s_launched_once' % label, launched[before:] == [job_id])
    t0 = time.monotonic()
    p = subprocess.run(['/usr/bin/python3', '-I', '-c', RUN_JOB, job_id], capture_output=True, timeout=timeout,
                       env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    status = call('job-status', {'job_id': job_id})
    job, log = status['job'], status.get('log') or []
    lines = log if isinstance(log, list) else str(log).splitlines()
    jobs_seen[label] = {'job_id': job_id, 'type': job.get('type'), 'state': job.get('state'),
                        'run_job_exit': p.returncode, 'seconds': round(time.monotonic() - t0, 1),
                        'error': (job.get('error') or {}).get('code'),
                        'rebuilt': {v: sum(('已重建資料卷 ' + v) in str(l) for l in lines) for v in VOLUMES},
                        'log_tail': [oc.safe_tail(str(l), 200) for l in lines[-10:]]}
    must('%s_%s' % (label, expect.replace('-', '_')), job.get('state') == expect, state=job.get('state'),
         error=jobs_seen[label]['error'], message=oc.safe_tail((job.get('error') or {}).get('message'), 300))
    return job


def verification_view(result):
    return [(e.get('app'), e.get('match'), [(c.get('id'), c.get('match')) for c in e.get('checks') or []])
            for e in result.get('verification') or [] if isinstance(e, dict)]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def http(method, path, body=None, token=None, digest=False, timeout=30):
    """One request to the target server on the owner's private loopback (this process joined that namespace)."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request(BASE_URL + path, data=data, headers=headers, method=method)
    try:
        with OPENER.open(request, timeout=timeout) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
            assert len(raw) <= 4 * 1024 * 1024, 'response-too-large'
            if digest:
                return response.status, {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
            try:
                return response.status, (json.loads(raw) if raw else None)
            except ValueError:
                return response.status, None
    except urllib.error.HTTPError as error:
        return error.code, None
    except (urllib.error.URLError, OSError):
        return None, None


def wait_server(seconds=300):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if http('GET', '/health', timeout=10)[0] == 200:
            return True
        time.sleep(3)
    raise AssertionError('server-not-ready')


def login(user, password):
    status, body = http('POST', '/auth/login', {'username': user, 'password': password})
    token = body.get('token') if status == 200 and isinstance(body, dict) else None
    if isinstance(body, dict):
        for key in ('token', 'refresh_token', 'access_token'):
            if isinstance(body.get(key), str):
                private(body[key])
    return status, token


def items(body, *keys):
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in keys + ('data', 'items', 'results'):
            if isinstance(body.get(key), list):
                return body[key]
    return []


def sql(statement):
    return oc.podman('exec', '-i', DB, 'psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-U', 'omnigent', '-d',
                     'omnigent', '-f', '-', input=statement.encode(), timeout=60).stdout.decode().strip()


def volume_tar(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tar:
        for name, data, mode in members:
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), mode, int(time.time())
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def export_file(volume, path):
    with open(path, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        oc.podman('volume', 'export', volume, stdout=handle, timeout=600)
    return path


def tar_files(path):
    found = {}
    with tarfile.open(path) as tar:
        for member in tar:
            if member.isfile():
                found[member.name.removeprefix('./')] = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
    return found


def server_cookie():
    data = oc.podman('exec', SERVER, 'cat', '/data/artifacts/accounts-cookie-secret', check=False).stdout or b''
    private(data)
    return data


def source_cookie(keys):
    with habackup.open_backup(ARCHIVE) as opened:
        member = opened.layout.addon('1b7b4ce7_woow-omnigent')
        with opened.open_member(member.name, keys) as stream:
            select = habackup.Select(include=('data/omnigent-home/.omnigent/artifacts/accounts-cookie-secret',),
                                     symlinks=(), hardlinks=False)
            for entry in habackup.iter_entries(stream, select, habackup.Report()):
                return private(entry.read_all(4096))
    return None


def active(unit):
    return oc.systemctl('is-active', unit, check=False).stdout.decode().strip()


def unit_marks():
    """When each unit last became active and how often systemd restarted it (equal = it ran without a break)."""
    return {u: oc.systemctl('show', '-p', 'ActiveEnterTimestampMonotonic', '-p', 'NRestarts', u,
                            check=False).stdout.decode().split() for u in UNITS}


def schema_digest():
    """The database structure as pg_dump writes it, without its comment lines and per-run restrict tokens."""
    text = oc.podman('exec', DB, 'pg_dump', '-U', 'omnigent', '-d', 'omnigent', '--schema-only', timeout=180).stdout.decode()
    lines = [l for l in text.splitlines() if l.strip() and not l.startswith(('--', '\\restrict', '\\unrestrict'))]
    return {'sha256': hashlib.sha256('\n'.join(lines).encode()).hexdigest(), 'lines': len(lines)}


def roles():
    return sql("SELECT rolname || ':' || rolsuper || ':' || rolcreaterole || ':' || rolcreatedb || ':' || rolcanlogin "
               "FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY 1;").splitlines()


def throwaways():
    found = {}
    for kind, argv in (('containers', ('ps', '-a', '--format', '{{.Names}}')), ('volumes', ('volume', 'ls', '--format', '{{.Name}}')),
                       ('networks', ('network', 'ls', '--format', '{{.Name}}')), ('secrets', ('secret', 'ls', '--format', '{{.Name}}'))):
        found[kind] = [n for n in oc.podman(*argv, timeout=60).stdout.decode().split() if n.startswith('woowbk-')]
    return found


def anonymous_volumes():
    return sorted(n for n in oc.podman('volume', 'ls', '--format', '{{.Name}}', timeout=60).stdout.decode().split()
                  if len(n) == 64 and all(c in '0123456789abcdef' for c in n))


def arm_one_shot_failure():
    """A drop-in of the owner's omnigent-server.service: its next start fails once (it removes its marker first)."""
    oc.write_owner_files({DROPIN: ('0644', '[Service]\nExecStartPre=/bin/sh -c \'if test -f %h/' + MARKER
                                   + '; then rm -f %h/' + MARKER + '; exit 1; fi\'\n'),
                          MARKER: ('0600', 'a54 one-shot failure\n')})
    oc.systemctl('daemon-reload', timeout=120)


def disarm_one_shot_failure():
    home = Path(oc.account().pw_dir)
    oc.owner(['/bin/rm', '-rf', str((home / DROPIN).parent), str(home / MARKER)], timeout=60)
    oc.systemctl('daemon-reload', timeout=120)


def start_stack():
    for unit in UNITS:
        oc.systemctl('start', unit, timeout=400)
    wait_server()


def stop_stack():
    oc.systemctl('stop', *reversed(UNITS), timeout=400, check=False)


def remove_previous():
    """Whatever an earlier attempt of this script left in the owner's account (idempotent)."""
    qdir = Path(oc.account().pw_dir) / QUADLET_DIR
    left = sorted(p.name for p in qdir.iterdir() if p.name.startswith('omnigent')) if qdir.is_dir() else []
    facts['previous_attempt_left'] = {'quadlets': len(left), 'engine_dir': (ROOT / 'engine').exists()}
    if left:
        stop_stack()
        oc.systemctl('stop', *VOLUME_UNITS, 'omnigent-network.service', timeout=200, check=False)
        oc.owner(['/bin/rm', '-f', *[str(qdir / name) for name in left]], timeout=60)
    disarm_one_shot_failure()
    for name in (RUNNER, SERVER, DB):
        oc.podman('rm', '--force', '--time', '10', name, timeout=120, check=False)
    for volume in VOLUMES:
        oc.podman('volume', 'rm', '--force', volume, timeout=60, check=False)
    for name in SECRET_NAMES:
        oc.podman('secret', 'rm', name, timeout=60, check=False)
    oc.podman('network', 'rm', '--force', 'omnigent', timeout=60, check=False)
    if (ROOT / 'engine').exists():
        n = 1
        while (ROOT / ('engine-before-omnigent-%d' % n)).exists():
            n += 1
        os.rename(ROOT / 'engine', ROOT / ('engine-before-omnigent-%d' % n))
        facts['engine_moved_to'] = 'engine-before-omnigent-%d' % n


def verify_restored(phase, expect, creds, passwords, ha_cookie, pi_files, server_marker, schema, role_list):
    pre = phase + '_'
    for unit in UNITS:
        must(pre + 'unit_active_' + unit.split('.')[0], active(unit) == 'active')
    now = schema_digest()
    must(pre + 'database_structure_is_this_devices_own', now == schema, lines=now['lines'])
    must(pre + 'database_roles_unchanged', roles() == role_list, roles=len(role_list))
    status, info = http('GET', '/v1/info')
    must(pre + 'info_version', status == 200 and (info or {}).get('server_version') == '0.21.0'
         and (info or {}).get('needs_setup') is False, status=status)
    a_status, admin = login(*creds['admin'])
    m_status, member = login(*creds['member'])
    t_status, target = login(TARGET_ADMIN, passwords['admin'])
    must(pre + 'ha_admin_login_ok', a_status == 200 and bool(admin), status=a_status)
    must(pre + 'ha_member_login_ok', m_status == 200 and bool(member), status=m_status)
    must(pre + 'target_admin_login_kept', t_status == 200 and bool(target), status=t_status)
    wrong, _tok = login(creds['admin'][0], passwords['admin'])
    must(pre + 'ha_admin_rejects_target_admin_login_value', wrong in (400, 401, 403), status=wrong)
    s, me = http('GET', '/auth/me', token=admin)
    must(pre + 'ha_admin_identity', s == 200 and (me or {}).get('id') == creds['admin'][0]
         and (me or {}).get('is_admin') is True)
    s, mm = http('GET', '/auth/me', token=member)
    must(pre + 'ha_member_identity', s == 200 and (mm or {}).get('id') == creds['member'][0]
         and not (mm or {}).get('is_admin'))
    s, users = http('GET', '/auth/users', token=admin)
    ids = {(u.get('id'), bool(u.get('is_admin'))) for u in items(users, 'users') if isinstance(u, dict)}
    want = {(u['id'], bool(u['is_admin'])) for u in expect['users']} | {(TARGET_ADMIN, True)}
    must(pre + 'users_include_ha_users_and_kept_admin', s == 200 and want <= ids, listed=len(ids))
    s, agent = http('GET', '/v1/agents/' + expect['agent']['id'], token=admin)
    must(pre + 'ha_agent', s == 200 and (agent or {}).get('name') == expect['agent']['name'])
    s, task = http('GET', '/v1/scheduled-tasks/' + expect['scheduled_task']['id'], token=admin)
    t = task or {}
    must(pre + 'ha_scheduled_task', s == 200 and t.get('name') == expect['scheduled_task']['name']
         and t.get('state') == expect['scheduled_task']['state'] and t.get('rrule') == expect['scheduled_task']['rrule']
         and t.get('last_run_at') is None, state=t.get('state'))
    sid = expect['admin_session']['id']
    s, session = http('GET', '/v1/sessions/' + sid, token=admin)
    must(pre + 'ha_admin_session_title', s == 200 and ((session or {}).get('title') or (session or {}).get('name'))
         == expect['admin_session']['title'])
    s, labels = http('GET', '/v1/sessions/' + sid + '/labels', token=admin)
    label_text = json.dumps(labels, ensure_ascii=False)
    must(pre + 'ha_admin_session_label_b1', s == 200 and '"b1"' in label_text
         and json.dumps(expect['admin_session']['labels']['b1'], ensure_ascii=False) in label_text)
    s, comments = http('GET', '/v1/sessions/' + sid + '/comments', token=admin)
    must(pre + 'ha_admin_session_comments', s == 200 and len(items(comments, 'comments'))
         == expect['admin_session']['comments'])
    att = expect['attachment']
    s, content = http('GET', '/v1/sessions/%s/resources/files/%s/content' % (sid, att['file_id']), token=admin,
                      digest=True)
    must(pre + 'ha_attachment_sha256', s == 200 and (content or {}).get('sha256') == att['sha256']
         and (content or {}).get('bytes') == att['bytes'], status=s)
    s, msessions = http('GET', '/v1/sessions', token=member)
    mids = {x.get('id') for x in items(msessions, 'sessions', 'conversations') if isinstance(x, dict)}
    must(pre + 'ha_member_session', s == 200 and expect['member_sessions'][0]['id'] in mids)
    must(pre + 'alembic_is_ha', sql('SELECT version_num FROM alembic_version;') == expect['alembic'])
    counts = {t_: int(sql('SELECT count(*) FROM %s;' % t_)) for t_ in ha_omnigent.TABLES}
    expected = dict(expect['db_counts'], users=expect['db_counts']['users'] + 1)
    grows = 'account_tokens'
    differ = sorted(k for k, v in expected.items() if k != grows and counts.get(k) != v)
    must(pre + 'table_counts_equal_ha_plus_kept_admin', not differ and counts[grows] >= expected[grows],
         differing=differ, tables=len(expected))
    cookie = server_cookie()
    must(pre + 'ha_cookie_installed', bool(cookie) and cookie == ha_cookie)
    pi_now = tar_files(export_file(PIVOL, WORK / ('pi-' + phase + '.tar')))
    must(pre + 'runner_pi_volume_unchanged', pi_now == pi_files, files=len(pi_now))
    marker = oc.podman('exec', SERVER, 'cat', '/data/a54-target-marker.txt', check=False).stdout
    must(pre + 'target_server_settings_kept', marker == server_marker)


def own_state(phase, own):
    """This device's own state from before any import, as a whole."""
    pre = phase + '_'
    for unit in UNITS:
        must(pre + 'unit_active_' + unit.split('.')[0], active(unit) == 'active')
    t_status, token = login(TARGET_ADMIN, own['admin_password'])
    refused = [login(*pair)[0] for pair in own['ha_logins']]
    must(pre + 'own_admin_in_ha_logins_refused', t_status == 200 and bool(token) and all(r in (400, 401, 403) for r in refused),
         own=t_status, ha=refused)
    s_, users = http('GET', '/auth/users', token=token)
    listed = {u.get('id') for u in items(users, 'users') if isinstance(u, dict)}
    a_status, _agent = http('GET', '/v1/agents/' + own['ha_agent'], token=token)
    must(pre + 'no_ha_user_no_ha_agent', s_ == 200 and TARGET_ADMIN in listed and not listed & own['ha_ids']
         and a_status in (403, 404), agent=a_status, listed=len(listed))
    must(pre + 'own_database_back', sql('SELECT count(*) FROM users;') == str(own['user_rows']) and schema_digest() == own['schema']
         and roles() == own['roles'])
    must(pre + 'own_server_volume_back', server_cookie() == own['cookie'] and oc.podman(
        'exec', SERVER, 'cat', '/data/a54-target-marker.txt', check=False).stdout == own['server_marker'])
    must(pre + 'own_runner_volume_back', tar_files(export_file(PIVOL, WORK / ('pi-' + phase + '.tar'))) == own['pi_files'])


creds_path = ROOT / 'input/omni-creds.json'
watch = Watch()
try:
    out['phase'] = 'inputs'
    acct = oc.account()
    must('owner_present', acct is not None)
    pid = oc.manager_pid(acct.pw_uid)
    manager = subprocess.run(['systemctl', 'show', 'user@%d.service' % acct.pw_uid, '-p', 'MemoryMax', '-p',
                              'MemorySwapMax', '-p', 'PrivateNetwork'], capture_output=True, text=True, timeout=30)
    facts['owner_manager'] = dict(l.split('=', 1) for l in manager.stdout.splitlines() if '=' in l)
    must('owner_manager_private_network_and_memory_cap', facts['owner_manager'].get('PrivateNetwork') == 'yes'
         and facts['owner_manager'].get('MemoryMax', 'infinity') != 'infinity')
    must('archive_is_the_attested_rpi5_backup', CHAIN['slug'] == ATTESTED[KIND][0] and CHAIN.get('sha256') == ATTESTED[KIND][1]
         and sha256_file(ARCHIVE) == ATTESTED[KIND][1])
    must('archive_kind_matches', (KEY_FILE is not None) == (KIND == 'b1-enc'))
    must('engine_has_the_product_path_not_the_hold', not hasattr(ha_omnigent, 'SECURITY_BLOCKER')
         and hasattr(ha_omnigent, 'trusted_schema'))
    key_text, keys = None, None
    if KEY_FILE is not None:
        key_text = haimport.read_key_file(KEY_FILE)
        private(key_text)
        KEY_FILE.unlink()
        keys = hasecuretar.Keys(key_text)
        import nacl
        facts['nacl'] = {'version': getattr(nacl, '__version__', None),
                         'from_workspace_wheel': Path(nacl.__file__).resolve().is_relative_to(ROOT / 'pydeps')}
    raw = json.loads(creds_path.read_text())
    creds_path.unlink()
    creds = {'admin': tuple(raw['admin']), 'member': tuple(raw['member'])}
    for _user, password in creds.values():
        private(password)
    expect = json.loads((ROOT / 'input/omni-expect.json').read_text())
    must('logins_match_recorded_source', creds['admin'][0] == expect['admin'] and creds['member'][0] == expect['member']
         and creds['admin'][0] == next(u['id'] for u in expect['users'] if u['is_admin']))
    ha_cookie = source_cookie(keys)
    must('source_cookie_read', bool(ha_cookie))
    watch.start()
    time.sleep(1)
    host_mnt, host_net = os.stat('/proc/1/ns/mnt').st_ino, oc.netns_inode(1)
    facts['engine_tools'] = oc.enter_tools_namespace(ROOT)
    oc.join_netns(pid)
    must('engine_in_private_mount_and_owner_netns', os.stat('/proc/self/ns/mnt').st_ino != host_mnt
         and os.stat('/proc/thread-self/ns/net').st_ino == oc.netns_inode(pid) != host_net)

    out['phase'] = 'previous-attempt'
    remove_previous()
    for unit in ('headscale.service', 'n8n.target', 'emqx.service'):  # memory: one stack at a time on .54
        oc.systemctl('stop', unit, timeout=300, check=False)
    facts['other_units_after_stop'] = {u: active(u) for u in ('headscale.service', 'n8n.service', 'emqx.service')}

    out['phase'] = 'target-images'
    pg_id = json.loads(oc.podman('image', 'inspect', PG_IMAGE, timeout=60).stdout)[0]['Id']
    server_info = json.loads(oc.podman('image', 'inspect', SERVER_IMAGE, timeout=60).stdout)[0]
    must('owner_images_arm64', server_info.get('Architecture') == 'arm64')
    oc.podman('tag', pg_id, RUNNER_IMAGE, timeout=60)
    facts['runner_placeholder_image'] = {'tag': RUNNER_IMAGE, 'is_pinned_pg_image': True, 'id': pg_id[:12]}

    out['phase'] = 'target-deploy'
    files = {}
    for path in sorted(PACKAGE.iterdir()):
        text = path.read_text()
        for key, value in RENDER.items():
            text = text.replace(key, value)
        assert '@@' not in text, 'unrendered-placeholder'
        if path.name == 'omnigent-runner.container':
            assert text.count('Image=' + RUNNER_IMAGE + '\n') == 1, 'runner-image-line-changed'
            text = text.replace('Image=' + RUNNER_IMAGE + '\n', 'Image=' + RUNNER_IMAGE + '\n' + RUNNER_PLACEHOLDER)
        files[QUADLET_DIR + '/' + path.name] = ('0644', text)
    publish = [line for _m, t in files.values() for line in t.splitlines() if line.startswith('PublishPort=')]
    must('published_only_on_loopback', publish == ['PublishPort=127.0.0.1:%d:8000' % PORT], publish=publish)
    oc.write_owner_files(files)
    passwords = {'db': secrets.token_urlsafe(32), 'admin': secrets.token_urlsafe(32), 'runner': secrets.token_urlsafe(32)}
    for value in passwords.values():
        private(value)
    db_url = 'postgresql://omnigent:%s@omnigent-postgres:5432/omnigent' % passwords['db']
    private(db_url)
    for name, value in zip(SECRET_NAMES, (passwords['db'], db_url, passwords['admin'], passwords['runner'])):
        oc.podman('secret', 'create', name, '-', input=value.encode(), timeout=60)
    oc.systemctl('daemon-reload', timeout=120)
    for unit in VOLUME_UNITS:
        oc.systemctl('start', unit, timeout=120)
    pi_marker = b'a54 owner target runner identity marker 20261124\n'
    server_marker = b'a54 owner target server runtime settings marker 20261124\n'
    oc.podman('volume', 'import', PIVOL, '-', input=volume_tar([('a54-runner-marker.txt', pi_marker, 0o600)]),
              timeout=120)
    oc.podman('volume', 'import', SERVERVOL, '-', input=volume_tar([('a54-target-marker.txt', server_marker, 0o644)]),
              timeout=120)
    start_stack()
    for unit in UNITS:
        must('target_unit_active_' + unit.split('.')[0], active(unit) == 'active')
    status, info = http('GET', '/v1/info')
    must('target_info', status == 200 and (info or {}).get('server_version') == '0.21.0'
         and (info or {}).get('needs_setup') is False, status=status)
    t_status, target_token = login(TARGET_ADMIN, passwords['admin'])
    must('target_admin_login_before_import', t_status == 200 and bool(target_token))
    s, users = http('GET', '/auth/users', token=target_token)
    listed = {u.get('id') for u in items(users, 'users') if isinstance(u, dict)}
    ha_ids = {u['id'] for u in expect['users']}
    must('target_live_users_own_admin_no_ha_user', s == 200 and TARGET_ADMIN in listed and not listed & ha_ids,
         listed=len(listed))
    ha_status, _tok = login(*creds['admin'])
    must('ha_admin_unknown_before_import', ha_status in (400, 401, 403), status=ha_status)
    must('target_alembic_equals_ha', sql('SELECT version_num FROM alembic_version;') == expect['alembic'])
    target_user_rows = int(sql('SELECT count(*) FROM users;'))
    facts['target_user_rows_before_import'] = target_user_rows
    target_cookie = server_cookie()
    must('target_has_own_cookie', bool(target_cookie) and target_cookie != ha_cookie)
    pi_files = tar_files(export_file(PIVOL, WORK / 'pi-pre.tar'))
    schema, role_list = schema_digest(), roles()
    facts['target_schema'], facts['target_roles'] = schema, role_list
    volumes_before = anonymous_volumes()
    must('host_netns_has_no_test_listener', b':%d' % PORT not in subprocess.run(
        ['nsenter', '--net=/proc/1/ns/net', 'ss', '-H', '-lnt'], capture_output=True, timeout=30).stdout)

    out['phase'] = 'engine-setup'
    PATHS.data.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    call('key-init')
    suggested = call('catalog-suggest', {'owner': oc.OWNER})
    apps = [a for a in suggested.get('apps') or [] if a.get('id') == 'omnigent']
    must('product_suggest_found_omnigent', len(apps) == 1,
         ids=[[a.get('id'), len(a.get('variants') or [])] for a in suggested.get('apps') or []])
    variant = next((v for v in apps[0].get('variants') or [] if v.get('id') == 'cold'), None)
    must('suggest_has_cold_variant_valid', variant is not None and variant.get('valid') is True,
         variants=[(v.get('id'), v.get('valid'), v.get('field')) for v in apps[0].get('variants') or []])
    facts['suggest_selected_variant'] = apps[0].get('selected') or apps[0].get('variant')
    entry = json.loads(json.dumps(variant['entry']))
    facts['suggested'] = {k: entry.get(k) for k in ('owner', 'units', 'writer_units', 'volumes', 'secrets', 'health',
                                                    'postgres', 'data_dirs')}
    facts['suggested']['verify'] = [(v.get('id'), v.get('type')) for v in entry.get('verify') or []]
    facts['suggest_notes'] = sorted({n.get('code') for n in apps[0].get('notes') or []})
    must('suggest_lists_every_secret', sorted(s if isinstance(s, str) else s.get('name') for s in entry.get('secrets') or [])
         == sorted(SECRET_NAMES))
    changes = []
    if not entry.get('health'):
        entry['health'] = [{'type': 'http', 'url': HEALTH, 'expect_status': 200, 'timeout_seconds': 240}]
        changes.append('health URL %s added (suggest found none)' % HEALTH)
    facts['installed_entry_changes'] = changes
    preview = call('catalog-install', {'entry': entry})
    must('catalog_preview_valid', preview.get('valid') is True and bool(preview.get('new_sha256'))
         and preview.get('expected_sha256') is None, error=(preview.get('error') or {}).get('code'))
    call('catalog-install', {'entry': entry, 'confirm': True, 'expected_sha256': preview['expected_sha256']})

    out['phase'] = 'ha-upload'
    begun = call('upload-begin', {'filename': 'rpi5-%s.tar' % CHAIN['slug'], 'size': ARCHIVE.stat().st_size})
    shutil.copyfile(ARCHIVE, begun['path'])
    ha = call('upload-finish', {'upload_id': begun['upload_id']}).get('ha_backup') or {}
    must('ha_backup_registered_with_omnigent', ha.get('id') == 'ha-' + ATTESTED[KIND][1][:20]
         and 'omnigent' in json.dumps(ha.get('importable_apps')))

    out['phase'] = 'public-check'
    with_key = {'key': key_text} if key_text else {}
    marks = unit_marks()
    job = run_job('ha_check', 'ha-check-start', {'ha_backup_id': ha['id'], 'apps': ['omnigent'],
                                                  'request_id': rid('check'), **with_key}, 1800)
    row = next((a for a in ((job.get('result') or {}).get('ha_check') or {}).get('apps') or []
                if a.get('app_id') == 'omnigent'), {})
    section = row.get('omnigent') or {}
    facts['public_check'] = {'ok': row.get('ok'), 'blockers': [oc.safe_tail(b, 200) for b in row.get('blockers') or []],
                             'warnings': [oc.safe_tail(w, 200) for w in row.get('warnings') or []], 'arch': row.get('arch'),
                             'version': row.get('version'), 'target_version': row.get('target_version'),
                             'section': {k: section.get(k) for k in (
                                 'omnigent_version', 'users', 'admins', 'conversations', 'scheduled_tasks',
                                 'scheduled_tasks_active', 'hosts', 'agents', 'files', 'public_sessions',
                                 'artifact_files', 'account_conflicts')}}
    must('public_check_ok_no_blocker', row.get('ok') is True and (row.get('blockers') or []) == [],
         blockers=len(row.get('blockers') or []))
    must('public_check_versions_equal', section.get('omnigent_version') == row.get('target_version') == '0.21.0')
    # the check counts people: every user row but 'local' and '__public__' (ha_omnigent.py:336), i.e. the recorded users
    must('public_check_counts_are_ha', section.get('users') == len(expect['users']) and section.get('admins') == 1
         and all(section.get(k) == expect['db_counts'][k] for k in ('conversations', 'agents', 'files', 'hosts', 'scheduled_tasks')),
         users=section.get('users'), recorded_users=len(expect['users']))
    must('check_left_nothing_behind', not any(throwaways().values()), **throwaways())

    out['phase'] = 'public-convert'
    job = run_job('ha_convert', 'ha-convert-start', {'ha_backup_id': ha['id'], 'apps': ['omnigent'], 'test_mode': False,
                                                      'confirm': True, 'request_id': rid('convert'), **with_key}, 3600)
    converted = job.get('result') or {}
    backup_id = converted.get('backup_id')
    must('converted_backup_made_encrypted', bool(backup_id) and converted.get('encrypted') is True,
         apps=converted.get('apps'), size=converted.get('size'))
    listed_row = next((b for b in call('list').get('backups') or [] if b.get('id') == backup_id), {})
    origin = listed_row.get('from_ha') or {}
    must('converted_backup_lists_its_ha_origin', origin.get('ha_backup_id') == ha['id'] and origin.get('apps') == ['omnigent'])
    must('convert_left_nothing_behind', not any(throwaways().values()), **throwaways())
    must('convert_left_no_anonymous_volume', anonymous_volumes() == volumes_before,
         new=len(set(anonymous_volumes()) - set(volumes_before)))
    must('target_ran_without_a_break_during_check_and_convert', unit_marks() == marks)
    t_status, target_token = login(TARGET_ADMIN, passwords['admin'])
    ha_status, _tok = login(*creds['admin'])
    must('target_untouched_by_check_and_convert', t_status == 200 and ha_status in (400, 401, 403)
         and sql('SELECT count(*) FROM users;') == str(target_user_rows) and schema_digest() == schema
         and roles() == role_list and server_cookie() == target_cookie, status=t_status, ha=ha_status)

    out['phase'] = 'first-import-rollback'
    own = {'admin_password': passwords['admin'], 'ha_logins': [creds['admin'], creds['member']], 'ha_ids': ha_ids,
           'ha_agent': expect['agent']['id'], 'user_rows': target_user_rows, 'schema': schema, 'roles': role_list,
           'cookie': target_cookie, 'server_marker': server_marker, 'pi_files': pi_files}
    marker_path = Path(acct.pw_dir) / MARKER
    arm_one_shot_failure()
    must('first_import_failure_armed', marker_path.exists())
    job = run_job('first_import_rollback', 'restore-start', {'backup_id': backup_id, 'apps': ['omnigent'], 'confirm': True,
                                                              'request_id': rid('first')}, 2400, expect='rolled-back')
    first = job.get('result') or {}
    facts['first_import_rollback'] = {'changed': first.get('changed'), 'rolled_back': first.get('rolled_back'),
                                      'error': oc.safe_tail((job.get('error') or {}).get('message'), 200),
                                      'rebuilt': jobs_seen['first_import_rollback']['rebuilt']}
    must('first_import_changed_then_rolled_back', first.get('changed') is True and first.get('rolled_back') is True
         and all(n == 2 for n in jobs_seen['first_import_rollback']['rebuilt'].values()),
         rebuilt=jobs_seen['first_import_rollback']['rebuilt'])
    must('first_import_failure_fired', not marker_path.exists())
    disarm_one_shot_failure()
    wait_server()
    own_state('first_import_rolled_back', own)

    out['phase'] = 'restore'
    job = run_job('restore', 'restore-start', {'backup_id': backup_id, 'apps': ['omnigent'], 'confirm': True,
                                                'request_id': rid('restore')}, 2400)
    restored = job.get('result') or {}
    safety = restored.get('safety_backup_id')
    facts['restore'] = {'changed': restored.get('changed'), 'rolled_back': restored.get('rolled_back'),
                        'safety_backup_id': safety, 'health': [(c.get('id'), c.get('status')) for c in restored.get('health') or []],
                        'verification': verification_view(restored), 'timing': restored.get('timing'),
                        'warnings': len(restored.get('warnings') or [])}
    must('restore_changed_not_rolled_back_with_safety', restored.get('changed') is True
         and restored.get('rolled_back') is False and bool(safety))
    must('restore_health_checks_ok', bool(restored.get('health'))
         and all(c.get('status') == 'ok' for c in restored.get('health')))
    must('restore_verification_no_mismatch', all(e.get('match') is not False for e in restored.get('verification') or []))
    wait_server()
    view = (expect, creds, passwords, ha_cookie, pi_files, server_marker, schema, role_list)
    verify_restored('installed', *view)

    out['phase'] = 'restart'
    stop_stack()
    must('stack_stopped_before_restart', all(active(u) != 'active' for u in UNITS))
    start_stack()
    verify_restored('restarted', *view)

    out['phase'] = 'automatic-rollback'
    # A second restore of the converted backup whose server start fails once: the engine must bring the state before it
    # (HA's data as installed) back by itself.
    arm_one_shot_failure()
    must('one_shot_failure_armed', marker_path.exists())
    job = run_job('automatic_rollback', 'restore-start', {'backup_id': backup_id, 'apps': ['omnigent'], 'confirm': True,
                                                           'request_id': rid('auto')}, 2400, expect='rolled-back')
    auto = job.get('result') or {}
    facts['automatic_rollback'] = {'changed': auto.get('changed'), 'rolled_back': auto.get('rolled_back'),
                                   'health': [(c.get('id'), c.get('status')) for c in auto.get('health') or []],
                                   'verification': verification_view(auto)}
    must('automatic_rollback_reported_rolled_back', auto.get('rolled_back') is True)
    must('one_shot_failure_fired', not marker_path.exists())
    disarm_one_shot_failure()
    wait_server()
    verify_restored('auto_rolled_back', *view)

    out['phase'] = 'rollback'
    job = run_job('rollback', 'restore-start', {'backup_id': safety, 'apps': ['omnigent'], 'confirm': True,
                                                 'request_id': rid('rollback')}, 2400)
    rolled = job.get('result') or {}
    entries = rolled.get('verification') or []
    facts['rollback'] = {'changed': rolled.get('changed'), 'rolled_back': rolled.get('rolled_back'),
                         'health': [(c.get('id'), c.get('status')) for c in rolled.get('health') or []],
                         'verification': verification_view(rolled)}
    must('rollback_restore_ok', rolled.get('changed') is True and rolled.get('rolled_back') is False
         and all(c.get('status') == 'ok' for c in rolled.get('health') or [])
         and all(e.get('match') is not False for e in entries))
    wait_server()
    own_state('rolled_back', own)

    out['phase'] = 'engine-leftovers'
    must('nothing_of_the_engine_left', not any(throwaways().values()) and anonymous_volumes() == volumes_before,
         **throwaways())
    staging = sorted(os.listdir(PATHS.staging)) if PATHS.staging.exists() else []
    must('no_staging_left', staging == [], staging=staging)
    must('memory_watch_never_stopped_the_stack', watch.tripped is False)
    out['status'] = 'passed'
    out['phase'] = 'done'
except Exception as error:  # noqa: BLE001
    out['error'] = type(error).__name__
    out['error_where'] = [[Path(f.filename).name, f.lineno, f.name] for f in traceback.extract_tb(error.__traceback__)[-4:]]
    if isinstance(error, (AssertionError, RuntimeError, oc.OwnerCommandFailed)):
        out['error_detail'] = oc.safe_tail(str(error), 400)
    try:
        facts['diagnosis_units'] = {u: active(u) for u in UNITS}
        rows = oc.podman('ps', '-a', '--format', '{{.Names}}|{{.Status}}', check=False, timeout=60).stdout.decode()
        facts['diagnosis_containers'] = sorted(l for l in rows.splitlines() if l.strip())[:20]
    except Exception:  # noqa: BLE001
        facts['diagnosis_units'] = 'unknown'
finally:
    for staged in (KEY_FILE, creds_path):
        if staged is not None and staged.exists():
            staged.unlink()
            facts['staged_file_removed_late'] = True
    try:
        disarm_one_shot_failure()
        stop_stack()  # memory on .54: the stack does not stay up after an attempt (files stay for the cleanup)
        facts['units_after_attempt'] = {u: active(u) for u in UNITS}
    except Exception:  # noqa: BLE001
        facts['units_after_attempt'] = 'unknown'
    watch.stop.set()
    if watch.is_alive():
        watch.join(timeout=30)
    facts['watch'] = {'samples': watch.samples, 'mem_available_min': watch.min_mem, 'tripped': watch.tripped,
                      'home_assistant_frontend': watch.frontend}
    shutil.rmtree(WORK, ignore_errors=True)
    after = kernel_state()
    facts['kernel_after'] = dict(after, modules=len(after['modules']))
    facts['modules_loaded_by_the_kernel_during_the_run'] = sorted(set(after['modules']) - set(KERNEL_BEFORE['modules']))
    for name, ok in (('no_new_oops', after['oops_count'] == KERNEL_BEFORE['oops_count']),
                     ('no_new_hung_task_report', after['hung_task_reports'] == KERNEL_BEFORE['hung_task_reports']),
                     ('no_new_d_state_task', after['d_state'] <= KERNEL_BEFORE['d_state']),
                     ('kernel_taint_unchanged', after['tainted'] == KERNEL_BEFORE['tainted']),
                     ('home_assistant_frontend_never_failed', watch.frontend['failed'] == 0)):
        if not check(name, ok) and out['status'] == 'passed':
            out['status'] = 'failed'
    out['elapsed_seconds'] = round(time.monotonic() - started, 1)
    out['failed_check'] = next((k for k, v in checks.items() if not v), None)
    out['checks_total'], out['checks_true'] = len(checks), sum(checks.values())
    needles = {v for v in PRIVATE if len(v) >= 6}
    encoded = json.dumps(out, sort_keys=True, ensure_ascii=False).encode()
    if any(v in encoded or json.dumps(v.decode('latin-1'))[1:-1].encode() in encoded for v in needles):
        out = {'status': 'failed', 'failed_check': 'secret_in_output_suppressed', 'commercial_acceptance': 'not-complete'}
    report(ROOT / 'owner-omnigent-public-result.json', out)
    print(json.dumps(out, sort_keys=True))
sys.exit(0 if out['status'] == 'passed' else 1)
