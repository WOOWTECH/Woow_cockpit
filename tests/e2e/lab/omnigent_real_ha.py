#!/usr/bin/env python3
"""Real HA Omnigent backup -> product internal candidate -> real installer, restart, rollback (services-a).

  PYTHONPATH=backup-engine:tests/e2e/lab python3 tests/e2e/lab/omnigent_real_ha.py --run --arch x86|arm \\
      --outer-isolation-confirmed

What is real here:
  * the source is the actual b1 Supervisor backup (sha256-bound to the recorded fixture), published into the
    engine's HA store with the product's own `HaStore.publish` and opened by the product (`haimport._open`):
    outer envelope, backup.json, add-on member, addon.json, embedded PostgreSQL 16 cluster and artifact store
    exactly as Home Assistant wrote them;
  * the target is a disposable Omnigent app in dev-d deployed as real Quadlet units (PostgreSQL 16, the
    omnigent-server 0.21.0 image, a runner placeholder holding the runner's pi volume), initialised by the real
    image with a freshly generated admin password; the product discovers it through its real adapter
    (`read_quadlets`, `probe`), its live `/v1/info` (answered by the running server, not replayed) and its live
    alembic revision;
  * conversion is `haimport._run_omnigent_candidate(..., schema_ddl_quiesced=True)`: the internal entry, which since
    2026-11-23 runs exactly the product conversion (the SECURITY_BLOCKER hold was replaced by it). The server
    is stopped right after the product's live discovery and before any schema capture, so no DDL writer exists;
  * installation is `haimport._install_omnigent_candidate` (flows.run_restore with its safety backup), then a
    restart, then a second install with an injected one-shot ExecStartPre failure that must roll back.
Checks after install/restart/rollback: HA's admin and member log in with HA's passwords (the fixture's
generated test credentials, read only through the b1 harness reader and never printed), this device's admin
logs in with its own password, HA's admin does not take this device's password, HA's agent, paused task,
session (title, labels, comment), attachment (sha256 computed inside the container), member session, alembic
and table counts; HA's cookie key bytes are installed; the runner's pi volume (its pairing/identity) is
byte-for-byte this device's (never HA's).
Limits stated in the evidence: the runner is a placeholder container (the Pi agent and runner pairing with a
model are out of scope); the engine runs on the host and reaches dev-d's owner through owner.sh (the lab
bridge), and the live /v1/info GET goes through `podman exec` into the running server.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import tarfile
import tempfile
import time
import traceback
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'backup-engine'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import omnigent_real_app_chain as chain  # noqa: E402  (register_private, event, login_registered, cookie readers)
import omnigent_install_rollback as installer  # noqa: E402  (DeviceOwner bridge, arm_once)
import dev_d_guard as guard  # noqa: E402  (clean tree, isolation record, team lock)
from woowbackup import (archive, catalog, flows, ha_omnigent, habackup, haimport, hastore, keys, storage,  # noqa: E402
                        tempctr, util)
from woowbackup.adapters import quadlet_postgres  # noqa: E402
from woowbackup.adapters.quadlet_postgres import QuadletPostgresAdapter  # noqa: E402
from woowbackup.errors import BackupError  # noqa: E402
from woowbackup.paths import Paths  # noqa: E402

LAB = Path.home() / '.woowbk-lab'
FIXTURE_SHA = {'arm': '1e6a4665315bc69fd114f8d43f7d429aecab53f07d07793ecf8c2c057a92c5d4',
               'x86': '3871a468e2f3a11488df7c6a00a4a8ed7c5b89c3ba2dbc2903ec3bd677013516'}
LOCK = '/tmp/woowbk-dev-d-mutation.lock'
WAITING = str(guard.WAITING)   # emqx-main asks for the next dev-d turn with this file
PG_IMAGE = chain.IMAGE              # docker.io/library/postgres:16.15-alpine3.24 (image id)
APP_IMAGE = chain.APP_IMAGE         # ghcr.io/omnigent-ai/omnigent-server:v0.21.0 (image id)
TARGET_ADMIN = 'target-admin'
PREFIX = 'woowbk-omni-realha-' + secrets.token_hex(4)
DB, SERVER, RUNNER = PREFIX + '-db', PREFIX + '-server', PREFIX + '-runner'
DBVOL, SERVERVOL, PIVOL = PREFIX + '-pg', PREFIX + '-data', PREFIX + '-pi'
SECRET = PREFIX + '-admin-password'
UNITS = [DB + '.service', SERVER + '.service', RUNNER + '.service']
FILES = [DB + '.container', SERVER + '.container', RUNNER + '.container']
TEMP_MEMORY = '512m'   # lab cap for the product's throwaway PostgreSQL containers (product default 2g)
event = chain.event
register_private = chain.register_private


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@contextlib.contextmanager
def dev_d_lock(timeout=3600):
    """The dev-d mutation lock as the team takes it (dev_d_guard.acquire: blocking like `flock -w`, yields to a
    waiting emqx-main run)."""
    try:
        fd, waited = guard.acquire(Path(LOCK), Path(WAITING), timeout)
    except guard.GuardError as error:
        raise RuntimeError(str(error)) from None
    try:
        yield waited
    finally:
        os.close(fd)


def isolation(when):
    """dev-d's outer isolation (owner.sh d --verify-isolation) as a fixed line and an event; raises otherwise."""
    try:
        line = guard.verify_isolation(chain.OWNER)
    except guard.GuardError:
        event('isolation', when=when, verified=False)
        raise RuntimeError('dev_d_isolation_failed') from None
    print(line, flush=True)
    event('isolation', when=when, verified=True, running=True, network='none', published_ports=0)


def committed_source():
    """The run must execute exactly the commit it names: no change outside the evidence folders."""
    clean, dirty = guard.clean_tree(ROOT)
    commit = guard.head(ROOT)
    print(f'source commit {commit}', flush=True)
    event('source', clean_tree=clean, changed_paths=len(dirty))
    require(clean, 'engine_or_harness_changes_not_committed')
    return commit


def quadlets():
    common = '\n[Service]\nRestart=no\nTimeoutStartSec=180\n'
    return {
        FILES[0]: ('[Container]\nImage=sha256:' + PG_IMAGE + '\nContainerName=' + DB +
                   '\nNetwork=none\nPull=never\nVolume=' + DBVOL + ':/var/lib/postgresql/data\n'
                   'Environment=POSTGRES_USER=postgres\nEnvironment=POSTGRES_DB=omnigent\n'
                   'Environment=POSTGRES_HOST_AUTH_METHOD=trust\nLogDriver=none\n'
                   'PodmanArgs=--memory=256m --pids-limit=128\n' + common),
        # The server keeps its log (no LogDriver=none) so the run can scan it for every registered secret.
        FILES[1]: ('[Unit]\nRequires=' + UNITS[0] + '\nAfter=' + UNITS[0] + '\n[Container]\n'
                   'Image=sha256:' + APP_IMAGE + '\nContainerName=' + SERVER +
                   '\nNetwork=container:' + DB + '\nPull=never\n'
                   'Volume=' + SERVERVOL + ':/data\n'
                   'Secret=' + SECRET + ',type=env,target=OMNIGENT_ACCOUNTS_INIT_ADMIN_PASSWORD\n'
                   'Environment=DATABASE_URL=postgresql://postgres@127.0.0.1:5432/omnigent\n'
                   'Environment=HOST=127.0.0.1\nEnvironment=PORT=8000\n'
                   'Environment=ARTIFACT_DIR=/data/artifacts\nEnvironment=OMNIGENT_AUTH_ENABLED=1\n'
                   'Environment=OMNIGENT_AUTH_PROVIDER=accounts\nEnvironment=OMNIGENT_PUBLIC_SHARING=0\n'
                   'Environment=OMNIGENT_ADMIN_CREDENTIALS_PATH=/data/admin-credentials\n'
                   'Environment=OMNIGENT_ACCOUNTS_INIT_ADMIN_USERNAME=' + TARGET_ADMIN + '\n'
                   'PodmanArgs=--memory=768m --cpus=1 --pids-limit=256 --cap-drop=ALL --security-opt=no-new-privileges\n'
                   + common + "ExecStartPre=/usr/bin/timeout 65 /bin/sh -c 'until /usr/bin/podman exec " + DB +
                   " pg_isready -q -h 127.0.0.1 -U postgres; do sleep 1; done'\n"),
        # Runner placeholder: holds the runner's own pi volume (identity/pairing); the Pi agent is out of scope.
        FILES[2]: ('[Container]\nImage=sha256:' + PG_IMAGE + '\nContainerName=' + RUNNER +
                   '\nNetwork=none\nPull=never\nLogDriver=none\nVolume=' + PIVOL + ':/data/pi-agent\n'
                   'Environment=OMNIGENT_RUNNER_USERNAME=' + TARGET_ADMIN + '\n'
                   'Exec=infinity\nPodmanArgs=--entrypoint=/bin/sleep --image-volume=ignore --memory=32m --pids-limit=32\n'
                   + common),
    }


def catalog_entry():
    return {'schema': 1, 'id': 'omnigent', 'name': 'Disposable Omnigent target (real HA import)',
            'owner': 'appowner', 'adapter': 'quadlet-postgres', 'quadlet': {'files': FILES},
            'units': UNITS, 'writer_units': UNITS,
            'volumes': [{'name': v} for v in (DBVOL, SERVERVOL, PIVOL)], 'secrets': [{'name': SECRET}],
            'health': [{'type': 'http', 'url': 'http://127.0.0.1:8000/health', 'timeout_seconds': 120}]}


class Reporter:
    """Engine job log lines are kept in memory only, for the secret scan; never printed (they can name accounts)."""
    cancellable = False

    def __init__(self):
        self.lines = []

    def log(self, *args, **kwargs):
        self.lines.append(' '.join(str(a) for a in args))

    def set_cancellable(self, flag):
        self.cancellable = flag
        return False

    def cancel_requested(self):
        return False

    def __getattr__(self, name):
        return lambda *a, **kw: None


API = r'''import json,sys,urllib.request,urllib.error
r=json.load(sys.stdin); data=json.dumps(r['body']).encode() if r.get('body') is not None else None
headers={'Content-Type':'application/json'}
if r.get('token'): headers['Authorization']='Bearer '+r['token']
q=urllib.request.Request('http://127.0.0.1:8000'+r['path'],data=data,headers=headers,method=r['method'])
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs): return None
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(q,timeout=30) as response:
  raw=response.read(4194305)
  if len(raw)>4194304: raise SystemExit(1)
  if r.get('digest'):
   import hashlib; print(json.dumps({'status':response.status,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}))
  else:
   print(json.dumps({'status':response.status,'body':json.loads(raw) if raw else None}))
except urllib.error.HTTPError as e:
 print(json.dumps({'status':e.code}))
'''

INFO = r'''import json,sys,urllib.request,urllib.error
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(sys.argv[1],timeout=15) as response:
  print(json.dumps({'status':response.status,'body':response.read(1048577).decode('latin-1')}))
except urllib.error.HTTPError as e:
 print(json.dumps({'status':e.code,'body':''}))
'''


class Lab:
    def __init__(self, device):
        self.device = device
        self.r = device.runner

    def api(self, request):
        result = self.r.podman('exec', '-i', SERVER, 'python3', '-I', '-c', API,
                               input=json.dumps(request).encode(), timeout=60, max_output=4 * 1024 * 1024)
        return json.loads(result.stdout)

    def live_get(self, url, timeout):
        """The product's loopback GET, answered by the RUNNING target server (podman exec transport, not replayed)."""
        require(url == 'http://127.0.0.1:8000/v1/info', 'unexpected_loopback_url')
        result = self.r.podman('exec', SERVER, 'python3', '-I', '-c', INFO, url, check=False, timeout=30,
                               max_output=2 * 1024 * 1024)
        if result.returncode != 0:
            raise OSError('target server not reachable')
        doc = json.loads(result.stdout)
        return doc['status'], doc['body'].encode('latin-1')

    def http_get(self, url, timeout, **kwargs):
        require(url == 'http://127.0.0.1:8000/health', 'unexpected_health_url')
        result = self.r.podman('exec', SERVER, 'curl', '-sS', '-o', '/dev/null', '-w', '%{http_code}', url,
                               check=False, timeout=10, max_output=4096)
        return (int(result.stdout) if result.returncode == 0 and result.stdout.strip().isdigit() else 503), b''

    def ready(self, seconds=180):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.http_get('http://127.0.0.1:8000/health', 10)[0] == 200:
                return
            time.sleep(2)
        raise RuntimeError('target_app_not_ready')

    def sql(self, statement):
        return self.r.podman('exec', '-i', DB, 'psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres',
                             '-d', 'omnigent', '-f', '-', input=statement.encode(), timeout=60).stdout.strip()

    def login_status(self, username, password):
        """HTTP status of a login that must FAIL; the body (a token if it unexpectedly succeeds) is never printed."""
        body = {'method': 'POST', 'path': '/auth/login', 'body': {'username': username, 'password': password}}
        response = self.api(body)
        if response.get('status') == 200:
            token = (response.get('body') or {}).get('token')
            if isinstance(token, str) and len(token) >= 6:
                register_private(token)
        return response.get('status')

    def volume_bytes(self, volume, path):
        with path.open('wb') as handle:
            os.chmod(path, 0o600)
            self.r.relay(['volume', 'export', volume], stdout=handle, timeout=300, max_output=512 * 1024 * 1024)
        return path

    def journal(self, unit):
        """The unit's journal (the server's container output with LogDriver journald), or None when unreadable."""
        try:
            result = self.r.run(['/usr/bin/journalctl', '--user', '-u', unit, '-o', 'cat', '--no-pager', '-n', '20000'],
                                check=False, timeout=60, max_output=16 * 1024 * 1024)
        except BackupError:
            return None
        return result.stdout if result.returncode == 0 else None


def tar_member(path, name):
    with tarfile.open(path, 'r:') as tar:
        for member in tar:
            if member.name.removeprefix('./').strip('/') == name and member.isfile():
                return tar.extractfile(member).read()
    return None


def tar_files(path):
    """{name: (mode, sha256)} of every regular file of a volume export (private, in memory)."""
    files = {}
    with tarfile.open(path, 'r:') as tar:
        for member in tar:
            name = member.name.removeprefix('./').strip('/')
            if member.isfile():
                files[name] = (member.mode, hashlib.sha256(tar.extractfile(member).read()).hexdigest())
    return files


def ha_member_cookie(backup):
    with habackup.open_backup(backup) as ha:
        found = [m for m in ha.layout.members if m.role == 'addon' and hastore.addon_suffix(m.slug) == 'woow-omnigent']
        require(len(found) == 1, 'omnigent_member_missing')
        select = habackup.Select(include=(ha_omnigent.ARTIFACTS + '/' + ha_omnigent.COOKIE,), symlinks=(),
                                 hardlinks=False)
        value = None
        with ha.open_member(found[0].name) as stream:
            for entry in habackup.iter_entries(stream, select, habackup.Report()):
                require(entry.kind == 'file' and value is None, 'ha_cookie_not_single_file')
                value = entry.read_all(4096)
        require(value, 'ha_cookie_missing')
        return value


def items(body, *keys):
    """The list of a response: the body itself, or its first list under `keys`, `data`, `items` or `results`
    (0.21.0 list endpoints answer PaginatedList {"object": "list", "data": [...]}, omnigent/server/schemas.py:42)."""
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in keys + ('data', 'items', 'results'):
            if isinstance(body.get(key), list):
                return body[key]
    return []


# Owner rule: any name containing these words is secret; such tables' counts are never printed.
SECRET_NAME = re.compile(r'PWD|PASS|KEY|TOKEN|SECRET|CRED|AUTH|SIG', re.I)


def printable(counts):
    return {k: v for k, v in counts.items() if not SECRET_NAME.search(k)}


def table_counts(lab):
    return {table: int(lab.sql('SELECT count(*) FROM %s;' % table)) for table in ha_omnigent.TABLES}


def verify_installed(lab, expect, creds, phase, observed, *, target_password, pi_files, ha_cookie):
    """Every fact of the restored HA data and this device's kept identity; returns tokens (registered)."""
    lab.ready()
    info = lab.api({'method': 'GET', 'path': '/v1/info', 'body': None})
    require(info.get('status') == 200 and (info.get('body') or {}).get('server_version') == '0.21.0'
            and (info.get('body') or {}).get('needs_setup') is False, phase + '_info_mismatch')
    admin = chain.login_registered(SERVER, creds['admin'][0], creds['admin'][1], phase + '_ha_admin', observed)
    member = chain.login_registered(SERVER, creds['member'][0], creds['member'][1], phase + '_ha_member', observed)
    chain.login_registered(SERVER, TARGET_ADMIN, target_password, phase + '_target_admin', observed)
    require(lab.login_status(creds['admin'][0], target_password) in (400, 401, 403), phase + '_ha_admin_took_target_password')
    me = lab.api({'method': 'GET', 'path': '/auth/me', 'body': None, 'token': admin})
    user = (me.get('body') or {}).get('user', me.get('body') or {})
    require(me.get('status') == 200 and user.get('id') == creds['admin'][0] and bool(user.get('is_admin')),
            phase + '_ha_admin_identity')
    mm = lab.api({'method': 'GET', 'path': '/auth/me', 'body': None, 'token': member})
    muser = (mm.get('body') or {}).get('user', mm.get('body') or {})
    require(mm.get('status') == 200 and muser.get('id') == creds['member'][0] and not muser.get('is_admin'),
            phase + '_ha_member_identity')
    users = lab.api({'method': 'GET', 'path': '/auth/users', 'body': None, 'token': admin})
    rows = items(users.get('body'), 'users')
    ids = {(u.get('id'), bool(u.get('is_admin'))) for u in rows if isinstance(u, dict)}
    require(all((u['id'], u['is_admin']) in ids for u in expect['users']) and (TARGET_ADMIN, True) in ids,
            phase + '_users_mismatch')
    agent = lab.api({'method': 'GET', 'path': '/v1/agents/' + expect['agent']['id'], 'body': None, 'token': admin})
    require(agent.get('status') == 200 and (agent.get('body') or {}).get('name') == expect['agent']['name'],
            phase + '_agent_missing')
    task = lab.api({'method': 'GET', 'path': '/v1/scheduled-tasks/' + expect['scheduled_task']['id'], 'body': None,
                    'token': admin})
    t = task.get('body') or {}
    require(task.get('status') == 200 and t.get('name') == expect['scheduled_task']['name']
            and t.get('state') == 'paused' and t.get('rrule') == expect['scheduled_task']['rrule']
            and t.get('last_run_at') is None, phase + '_task_mismatch')
    sid = expect['admin_session']['id']
    session = lab.api({'method': 'GET', 'path': '/v1/sessions/' + sid, 'body': None, 'token': admin})
    s = session.get('body') or {}
    require(session.get('status') == 200 and (s.get('title') or s.get('name')) == expect['admin_session']['title'],
            phase + '_session_mismatch')
    labels = lab.api({'method': 'GET', 'path': '/v1/sessions/' + sid + '/labels', 'body': None, 'token': admin})
    text = json.dumps(labels.get('body'), ensure_ascii=False)
    require(labels.get('status') == 200 and '"b1"' in text and 'import-test' in text, phase + '_labels_mismatch')
    comments = lab.api({'method': 'GET', 'path': '/v1/sessions/' + sid + '/comments', 'body': None, 'token': admin})
    crow = items(comments.get('body'), 'comments')
    require(comments.get('status') == 200 and len(crow) == expect['admin_session']['comments'],
            phase + '_comments_mismatch')
    att = expect['attachment']
    content = lab.api({'method': 'GET', 'path': '/v1/sessions/%s/resources/files/%s/content' % (sid, att['file_id']),
                       'body': None, 'token': admin, 'digest': True})
    require(content.get('status') == 200 and content.get('sha256') == att['sha256'] and content.get('bytes') == att['bytes'],
            phase + '_attachment_mismatch')
    msessions = lab.api({'method': 'GET', 'path': '/v1/sessions', 'body': None, 'token': member})
    mrows = items(msessions.get('body'), 'sessions', 'conversations')
    require(msessions.get('status') == 200 and expect['member_sessions'][0]['id'] in {x.get('id') for x in mrows if isinstance(x, dict)},
            phase + '_member_session_missing')
    require(lab.sql('SELECT version_num FROM alembic_version;').decode() == expect['alembic'], phase + '_alembic_mismatch')
    counts = table_counts(lab)
    want = dict(expect['db_counts'], users=expect['db_counts']['users'] + 1)
    # This run's logins write account_tokens and, because they ask for a refresh grant (issue_refresh), device_grants
    # (x86 attempt 3: device_grants 0 -> 3 after three logins). Those two may only grow; every other table must equal
    # HA's count plus the kept account exactly. hosts stays HA's: the placeholder runner never registers.
    grown = ('account_tokens', 'device_grants')
    require(all(counts.get(k, -1) >= want[k] for k in grown), phase + '_ha_tokens_or_grants_missing')
    differ = sorted(k for k, v in want.items() if k not in grown and counts.get(k) != v)
    if differ:
        # Table names and integer counts only (no row content): what differs from HA's counts plus the kept account.
        event('table_counts_differ', phase=phase, differ=printable({k: [want[k], counts.get(k)] for k in differ}))
    require(not differ, phase + '_table_counts_differ')
    cookie = lab.r.podman('exec', SERVER, 'cat', '/data/artifacts/accounts-cookie-secret', max_output=4096).stdout
    require(cookie == ha_cookie, phase + '_cookie_not_ha')
    pi = tar_files(lab.volume_bytes(PIVOL, lab.private / ('pi-' + phase + '.tar')))
    (lab.private / ('pi-' + phase + '.tar')).unlink()
    require(pi == pi_files, phase + '_runner_identity_moved')
    event('installed_app_verified', phase=phase, ha_admin_login=True, ha_member_login=True, target_admin_login=True,
          ha_admin_refuses_target_password=True, agent=True, paused_task=True, session_title_labels_comment=True,
          attachment_sha256=True, member_session=True, alembic=True, table_counts=len(want), ha_cookie_installed=True,
          runner_pi_volume_unchanged=True)
    return admin


def run(arch):
    backup = LAB / 'ha-fixtures' / '20261119-b1' / arch / f'woow-b1-{arch}-plain' / f'woow-b1-{arch}-plain.tar'
    require(file_sha256(backup) == FIXTURE_SHA[arch], 'fixture_sha256_mismatch')
    event('real_source', arch=arch, fixture_sha256_matches_record=True)
    import ha_import_b1_e2e as b1
    summary = json.loads(b1.SOURCE.read_text(encoding='utf-8'))['machines'][arch]['omnigent']
    s = b1.Secrets([b1.SECRET_DIR / 'b1-creds.env'], b1.SECRET_DIR / 'dev-d-markers.json')
    creds = {'admin': (s['B1_OMNI_ADMIN_USER'], s['B1_OMNI_ADMIN_PW']),
             'member': (s['B1_OMNI_MEMBER_USER'], s['B1_OMNI_MEMBER_PW'])}
    for _user, password in creds.values():
        register_private(password)
    require(creds['admin'][0] == next(u['id'] for u in summary['users'] if u['is_admin']), 'admin_name_mismatch')
    ha_cookie = ha_member_cookie(backup)
    register_private(ha_cookie)
    register_private(ha_cookie.strip())
    target_password = secrets.token_urlsafe(32)
    register_private(target_password)
    # Since 2026-11-23 (owner decision) the public conversion IS the trusted-schema product path; the internal entry
    # used below runs exactly it (haimport._run_omnigent_candidate -> _run_ha_convert -> ha_omnigent.convert).
    require(not hasattr(ha_omnigent, 'SECURITY_BLOCKER') and callable(getattr(ha_omnigent, 'trusted_schema', None)),
            'product_path_missing')
    event('public_guard', replaced_by_product_trusted_schema=True)

    device = installer.DeviceOwner()
    r = device.runner
    lab = Lab(device)
    root = Path(tempfile.mkdtemp(prefix='woowbk-omni-realha-'))
    os.chmod(root, 0o700)
    lab.private = root / 'private'
    lab.private.mkdir(mode=0o700)
    paths = Paths(base=root / 'engine')
    app = catalog.validate_entry(catalog_entry(), paths=paths, user_lookup=device.lookup)
    reporter = Reporter()
    armed = {'enabled': False, 'count': 0}
    marker = '.config/' + PREFIX + '-fail-once'
    dropdir = '.config/systemd/user/' + UNITS[1] + '.d'
    dropfile = dropdir + '/woowbk-inject.conf'
    created_files, created_dirs, secret_created = [], [], False
    observed, logs = [], []
    success = False

    def adapter_factory(app_, **kwargs):
        original = kwargs.get('imported_hook')

        def imported():
            if original:
                original()
            installer.arm_once(r, marker, armed)
        kwargs['imported_hook'] = imported
        return QuadletPostgresAdapter(app_, r, http_get=lab.http_get, runtime_ready=device.runtime_ready,
                                      statvfs=device.statvfs, **kwargs)

    deps = flows.Deps(storage=storage.Storage(paths), keys=keys.KeyStore(paths), archive=archive,
                      load_catalog=lambda: catalog.Catalog({'omnigent': app}), adapter_factory=adapter_factory,
                      host_info=lambda: {'hostname': 'isolated-dev-d', 'machine_id_sha256': '', 'arch': 'x86_64',
                                         'os': 'isolated lab', 'podman': 'lab'},
                      encrypt_by_default=lambda: True, audit=lambda line: None)

    def context():
        return flows.FlowContext(paths, 'j' + util.compact_utc() + '-' + secrets.token_hex(4), deps, reporter)

    class LabTemp(tempctr.TempObjects):
        def __init__(self, runner, job_id, **kwargs):
            kwargs.setdefault('memory', TEMP_MEMORY)
            super().__init__(runner, job_id, **kwargs)

    try:
        pending = ['.config/containers/systemd/' + name for name in FILES] + [dropdir, marker]
        require(all(v['type'] == 'missing' for v in r.stat_files(pending).values()), 'unit_path_collision')
        for unit in UNITS:
            require(r.systemctl('show', unit, '-p', 'LoadState', '--value', check=False).stdout.strip() == b'not-found',
                    'unit_name_collision')
        chain.require_names_absent(r, (('container', (DB, SERVER, RUNNER)), ('volume', (DBVOL, SERVERVOL, PIVOL)),
                                       ('secret', (SECRET,))))
        secret_created = True
        r.podman('secret', 'create', SECRET, '-', input=target_password.encode())
        for volume in (DBVOL, SERVERVOL, PIVOL):
            r.podman('volume', 'create', volume)
        # The runner's own identity/pairing lives in its pi volume: a distinguishable private marker.
        pi_marker = ('{"runner_identity": "' + secrets.token_hex(16) + '"}\n').encode()
        register_private(pi_marker.strip())
        with chain.small_volume([('auth.json', pi_marker)]) as handle:
            r.podman('volume', 'import', PIVOL, '-', input=handle)
        for name, text in quadlets().items():
            rel = '.config/containers/systemd/' + name
            r.write_file(rel, text.encode(), 0o600)
            created_files.append(rel)
        r.run(['/usr/bin/mkdir', '--', r.home + '/' + dropdir])
        created_dirs.append(dropdir)
        r.write_file(dropfile, ('[Service]\nExecStartPre=/bin/sh -c \'if test -f %h/' + marker +
                                '; then rm -f %h/' + marker + '; exit 1; fi\'\n').encode(), 0o600)
        created_files.append(dropfile)
        r.systemctl('daemon-reload')
        r.systemctl('start', '--', *UNITS, timeout=300)
        lab.ready()
        chain.login_registered(SERVER, TARGET_ADMIN, target_password, 'target_bootstrap', observed)
        target_cookie = chain.cookie_from_container(r, SERVER)
        require(target_cookie != ha_cookie, 'target_cookie_equals_ha')
        pi_files = tar_files(lab.volume_bytes(PIVOL, lab.private / 'pi-before.tar'))
        (lab.private / 'pi-before.tar').unlink()
        event('target_deployed', quadlet_units=3, independently_initialised=True, target_admin_login=True)

        # Publish the real backup into the engine's HA store exactly like an upload is published.
        deps.storage.ensure_layout()
        deps.keys.ensure_device_key()
        part = Path(paths.data) / ('.ha-import-' + secrets.token_hex(4) + '.part')
        part.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(backup, part)
        fd = os.open(part, os.O_RDONLY)
        try:
            st = os.fstat(fd)
            summary_doc = habackup.describe(fd).summary()
            os.lseek(fd, 0, os.SEEK_SET)
            sha256, size = util.sha256_fd(fd)
            require(sha256 == FIXTURE_SHA[arch] and size == st.st_size, 'published_copy_differs')
            record, created = hastore.HaStore(paths).publish(fd, st, part, summary_doc, sha256, backup.name)
        finally:
            os.close(fd)
        require(created, 'ha_store_publish_failed')
        event('ha_store_published', product_publish=True, sha256_matches_fixture=True)

        real_version = ha_omnigent.target_version
        real_alembic = ha_omnigent.live_alembic
        real_trusted_schema = ha_omnigent.trusted_schema
        quiesced = {}

        def observe_version(work, app_, url):
            value = real_version(work, app_, url)
            quiesced['live_version'] = value
            return value

        def observe_alembic(work, app_, target):
            value = real_alembic(work, app_, target)
            if not quiesced.get('server_stopped'):
                quiesced['live_alembic'] = value
            return value

        def stop_before_schema(work, app_, target, path, alembic):
            # The current conversion calls trusted_schema directly. Stop its only DDL writer immediately before the
            # product captures the trusted schema; PostgreSQL remains up for the product's own stability checks.
            r.systemctl('stop', '--', UNITS[1], timeout=120)
            require(r.podman('container', 'exists', SERVER, check=False).returncode == 1 or
                    b'running' not in r.podman('container', 'inspect', SERVER, '--format', '{{.State.Status}}',
                                               check=False).stdout, 'server_still_running')
            quiesced['server_stopped'] = True
            return real_trusted_schema(work, app_, target, path, alembic)

        params = {'ha_backup_id': record['id'], 'apps': ['omnigent'], 'test_mode': False, 'encrypt': True}
        with mock.patch.object(quadlet_postgres, 'loopback_get', lab.live_get), \
                mock.patch.object(ha_omnigent, 'target_version', observe_version), \
                mock.patch.object(ha_omnigent, 'live_alembic', observe_alembic), \
                mock.patch.object(ha_omnigent, 'trusted_schema', stop_before_schema), \
                mock.patch.object(tempctr, 'TempObjects', LabTemp):
            converted = haimport._run_omnigent_candidate(context(), params, schema_ddl_quiesced=True)
        require(quiesced.get('server_stopped') and quiesced.get('live_version') == '0.21.0'
                and quiesced.get('live_alembic') == [summary['alembic']], 'live_discovery_mismatch')
        require(converted['encrypted'] and converted['apps'] == ['omnigent'], 'candidate_not_packaged')
        event('candidate_converted', internal_entry=True, real_ha_store=True, real_adapter_discovery=True,
              live_info_from_running_server=True, live_alembic=True, server_stopped_before_schema_capture=True,
              encrypted=True, test_mode=False)

        result = haimport._install_omnigent_candidate(context(), converted['backup_id'])
        require(result['changed'] and not result['rolled_back'], 'install_failed')
        # Counts right after the restore (server started by the flow, before any login or API call of this run).
        fresh = table_counts(lab)
        want = dict(summary['db_counts'], users=summary['db_counts']['users'] + 1)
        event('installed_counts_before_login',
              equal_to_ha_plus_kept=sorted(k for k in printable(want) if fresh.get(k) == want[k]),
              differ=printable({k: [want[k], fresh.get(k)] for k in sorted(want) if fresh.get(k) != want[k]}),
              secret_named_tables_equal=all(fresh.get(k) == want[k] for k in want if k not in printable(want)))
        # Data integrity of the installed candidate: EVERY table (secret-named ones compared, not printed) holds
        # exactly HA's rows plus this device's kept account before anything else touches the database.
        require(all(fresh.get(k) == want[k] for k in want), 'installed_counts_before_login_differ')
        installer_meta = deps.storage.get(result['safety_backup_id'])
        require(installer_meta['type'] == 'safety' and installer_meta['encrypted'], 'safety_not_encrypted')
        verify_installed(lab, summary, creds, 'installed', observed, target_password=target_password,
                         pi_files=pi_files, ha_cookie=ha_cookie)
        r.systemctl('restart', '--', UNITS[1], timeout=240)
        verify_installed(lab, summary, creds, 'restarted', observed, target_password=target_password,
                         pi_files=pi_files, ha_cookie=ha_cookie)
        # Distinguishable pre-failure state that the automatic rollback must bring back.
        lab.sql("CREATE TABLE public.woowbk_rollback_marker(value text); "
                "INSERT INTO public.woowbk_rollback_marker VALUES ('before-failure');")
        r.podman('exec', '-i', SERVER, 'sh', '-c', 'cat > /data/woowbk-rollback-marker', input=b'before-failure\n')
        armed['enabled'] = True
        try:
            haimport._install_omnigent_candidate(context(), converted['backup_id'])
        except flows.RolledBack as outcome:
            require(outcome.result['rolled_back'] and armed['count'] == 1, 'automatic_rollback_missing')
        else:
            raise RuntimeError('one_shot_failure_not_observed')
        require(r.stat_files([marker])[marker]['type'] == 'missing', 'failure_marker_not_consumed')
        lab.ready()
        require(lab.sql('SELECT value FROM public.woowbk_rollback_marker;') == b'before-failure', 'rollback_db_marker')
        require(r.podman('exec', SERVER, 'cat', '/data/woowbk-rollback-marker').stdout == b'before-failure\n',
                'rollback_server_marker')
        lab.sql('DROP TABLE public.woowbk_rollback_marker;')
        r.podman('exec', SERVER, 'rm', '-f', '/data/woowbk-rollback-marker')
        verify_installed(lab, summary, creds, 'rolled_back', observed, target_password=target_password,
                         pi_files=pi_files, ha_cookie=ha_cookie)
        event('automatic_rollback', one_shot_systemd_failure=True, real_flow=True, db_and_server_markers=True)
        # Hashes of HA users' and tokens' secret columns are registered for the scan (values stay in memory).
        for column_sql in ("SELECT coalesce(string_agg(password_hash, E'\\n'), '') FROM users;",):
            for value in lab.sql(column_sql).split(b'\n'):
                if len(value) >= 6:
                    register_private(value)
        success = True
    finally:
        failures = []

        def attempt(fn, label):
            try:
                fn()
            except Exception:
                failures.append(label)
        for unit in UNITS:
            logs.append(lab.journal(unit) if created_files else None)
        if created_files:
            for unit in reversed(UNITS):
                attempt(lambda unit=unit: r.systemctl('stop', '--', unit, check=False, timeout=120), 'stop')
                attempt(lambda unit=unit: r.systemctl('unmask', '--', unit), 'unmask')
                attempt(lambda unit=unit: r.systemctl('reset-failed', unit, check=False), 'reset')
            for name in (RUNNER, SERVER, DB):
                attempt(lambda name=name: r.podman('rm', '--force', '--time', '10', name, check=False), 'container')
        for rel in reversed(created_files):
            attempt(lambda rel=rel: r.remove_file(rel), 'file')
        if armed['count']:
            attempt(lambda: r.remove_file(marker) if r.stat_files([marker])[marker]['type'] != 'missing' else None,
                    'marker')
        for rel in reversed(created_dirs):
            attempt(lambda rel=rel: r.run(['/usr/bin/rmdir', '--', r.home + '/' + rel]), 'dir')
        if created_files:
            attempt(lambda: r.systemctl('daemon-reload'), 'reload')
        for volume in (DBVOL, SERVERVOL, PIVOL):
            attempt(lambda volume=volume: r.podman('volume', 'rm', '--force', volume, check=False), 'volume')
        if secret_created:
            attempt(lambda: r.podman('secret', 'rm', SECRET, check=False), 'secret')
        remaining = any(r.podman('container', 'exists', n, check=False).returncode != 1 for n in (DB, SERVER, RUNNER))
        remaining |= any(r.podman('volume', 'exists', n, check=False).returncode != 1 for n in (DBVOL, SERVERVOL, PIVOL))
        remaining |= r.podman('secret', 'exists', SECRET, check=False).returncode != 1
        remaining |= any(v['type'] != 'missing' for v in r.stat_files(created_files + [marker]).values())
        needles = chain.scan_needles(chain.SECRET_VALUES)
        hits = sum(1 for text in logs if text is not None for n in needles if n in text)
        hits += sum(1 for line in reporter.lines for n in needles if n.decode('utf-8', 'ignore') in line)
        hits += sum(1 for record in chain.EVENT_RECORDS for n in needles if n in record)
        shutil.rmtree(root, ignore_errors=True)
        event('secret_scan', registered_values=len(chain.SECRET_VALUES), login_credential_sources=len(observed),
              journals_scanned=sum(t is not None for t in logs), engine_log_lines=len(reporter.lines), hits=hits)
        event('cleanup', complete=not failures and not remaining, private_engine_root_removed=not root.exists())
        # The server's journal (its container output) must have been readable: otherwise coverage is incomplete.
        require(not failures and not remaining and hits == 0 and (not created_files or logs[1] is not None),
                'cleanup_or_scan_failed')
    require(success, 'run_incomplete')
    event('omnigent_real_ha', arch=arch, result='PASS')


def inventory(runner):
    return tuple(tuple(sorted(n for n in runner.podman(*args, timeout=30, max_output=1024 * 1024).stdout.splitlines()
                              if n not in (b'headscale', b'headplane')))
                 for args in (('ps', '-a', '--format', '{{.Names}}'), ('volume', 'ls', '--format', '{{.Name}}'),
                              ('secret', 'ls', '--format', '{{.Name}}')))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--arch', choices=('x86', 'arm'), required=True)
    parser.add_argument('--outer-isolation-confirmed', action='store_true')
    args = parser.parse_args()
    if not args.run or not args.outer_isolation_confirmed:
        parser.error('explicit --run and --outer-isolation-confirmed are required')
    for tool in ('age', 'age-keygen', 'zstd'):
        require(util.find_tool(tool) is not None, 'missing_host_archive_tool')
    committed_source()
    with dev_d_lock() as waited:
        started = time.monotonic()
        event('dev_d_lock', held=True, waited_seconds=waited)
        isolation('before')
        try:
            chain.isolated_preflight()
            runner = chain.Runner()
            before = inventory(runner)
            try:
                run(args.arch)
            finally:
                unchanged = inventory(runner) == before
                event('inventory', containers_volumes_secrets_unchanged=unchanged,
                      lock_seconds=int(time.monotonic() - started))
                require(unchanged, 'inventory_changed')
        finally:
            isolation('after')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Exception messages and command stderr can contain test credentials: fixed fields only.
        code = str(error) if isinstance(error, RuntimeError) and re.fullmatch(r'[a-z0-9_]{3,80}', str(error)) else None
        event('failed', error_type=type(error).__name__, code=code or getattr(error, 'code', None),
              frames=[{'file': Path(f.filename).name, 'line': f.lineno, 'function': f.name.strip('<>')}
                      for f in traceback.extract_tb(error.__traceback__)][-6:])
        sys.exit(1)
