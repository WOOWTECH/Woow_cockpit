"""Real RPi5 HA backup (slug 45670371, add-on woow-omnigent 0.1.23) -> unmodified product Omnigent check and the
INTERNAL candidate converter -> restored Omnigent 0.21.0 (arm64) on .54 -> HA's admin and member log in with HA's
passwords; data, restart, rollback.

Runner scope (stated, not hidden): rootful Podman with a private store (RootfulRunner; overlay driver with
skip_mount_home, chosen at init), NOT the production OwnerRunner/rootless path; the restore replaces the volumes the
way the product restore does (safety export first) but is driven here (no systemd user units on this target).
Public import guard: `ha_omnigent.convert` and `check` keep SECURITY_BLOCKER (asserted, never bypassed). The
conversion is the internal candidate that `haimport._run_omnigent_candidate` wraps: `require_registered_secrets` then
`_convert_candidate(..., schema_ddl_quiesced=True)`; the caller's quiescence = the server (the only schema writer) is
stopped right after the product's live discovery and before any schema capture.
Target: the Woow Omnigent package quadlets (commit 6e4f0c0) rendered for .54 and translated to `podman run`; stated
deviations: one pod with network none instead of the omnigent bridge network, no published port, no health timers
(readiness polled here), memory caps, and a runner placeholder (the package's PostgreSQL image sleeping, holding the
runner's pi volume) instead of the locally built runner image (the Pi agent is out of scope).
Network: after the pod exists this process joins the pod's network namespace (libc setns; Python 3.11 has no
os.setns), so the product's own loopback GET of /v1/info and every login below reach the running target server at
127.0.0.1:8000; the namespace has only `lo`.
Secrets: HA's test logins arrive in a 0600 file read and unlinked at start; the target's passwords are generated here
and only reach podman secrets in the private store; tokens and cookie keys stay in memory; the output is scanned for
every value before it is printed and replaced by a fixed failure if one is found."""
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import traceback
import urllib.error
import urllib.request
from types import MethodType, SimpleNamespace
from unittest import mock

from arm54_final_runtime import DRIVER, LABEL, ROOT, RootfulRunner, private_dir, report, sha256_file, store_objects

from woowbackup import habackup, haimport, ha_omnigent, hasecuretar, tempctr  # noqa: E402
from woowbackup.adapters.quadlet_postgres import QuadletPostgresAdapter  # noqa: E402
from woowbackup.errors import BackupError  # noqa: E402

# Only RPi5 backups whose bytes were attested against the RPi5 (source-provenance-34.json) are accepted.
ATTESTED = {'45670371': '1e6a4665315bc69fd114f8d43f7d429aecab53f07d07793ecf8c2c057a92c5d4',
            'a2dc9bfd': '6d0647f0acb2e0d95043d66852c08bbc020d409d4f6747f817c10f94e2c33d1c'}
CHAIN = json.loads((ROOT / 'input/chain.json').read_text())
ARCHIVE = ROOT / 'input' / CHAIN['archive']
KEY_FILE = ROOT / 'input' / CHAIN['key_file'] if CHAIN.get('key_file') else None
KEYS = None
PACKAGE = ROOT / 'source/tests/e2e/lab/evidence/arm54-final-20261123/omnigent-package-6e4f0c0/quadlet'
PG_IMAGE = ('docker.io/library/postgres:16.15-alpine3.24'
            '@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139')
SERVER_IMAGE = ('ghcr.io/omnigent-ai/omnigent-server:v0.21.0'
                '@sha256:9bba2964f015ddbb61da0924267effd1801c0db8f44ecec95f401f24d9a3f90c')
POD = 'a54f-omni-pod'
DB, SERVER, RUNNER = 'omnigent-postgres', 'omnigent-server', 'omnigent-runner'
DBVOL, SERVERVOL, PIVOL = 'omnigent-postgres-data', 'omnigent-server-data', 'omnigent-pi-data'
VOLUMES = (DBVOL, SERVERVOL, PIVOL)
SECRET_NAMES = ('omnigent-postgres-password', 'omnigent-database-url', 'omnigent-admin-password',
                'omnigent-runner-password')
TARGET_ADMIN, RUNNER_USER = 'a54-target-admin', 'a54-runner'
RENDER = {'@@OMNIGENT_BIND@@': '127.0.0.1', '@@OMNIGENT_PORT@@': '28000', '@@OMNIGENT_ACCOUNTS_BASE_URL@@': '',
          '@@OMNIGENT_ADMIN_USERNAME@@': TARGET_ADMIN, '@@OMNIGENT_RUNNER_USERNAME@@': RUNNER_USER,
          '@@OMNIGENT_PI_VOLUME@@': 'omnigent-pi.volume'}
MEMORY = {DB: '384m', SERVER: '768m', RUNNER: '32m'}
JOB_CHECK, JOB_CONVERT = 'j20261123T100000Z-a54e0c01', 'j20261123T100000Z-a54e0c02'
COOKIE_MEMBER = 'data/omnigent-home/.omnigent/artifacts/accounts-cookie-secret'
BASE_URL = 'http://127.0.0.1:8000'
CLONE_NEWNET = 0x40000000

r = RootfulRunner()
checks = {}
facts = {}
PRIVATE = []          # every secret value of this run (bytes); the output must contain none of them
LOGS = []             # product job log lines (kept in memory only; may name accounts)
out = {'status': 'failed', 'phase': 'start', 'commercial_acceptance': 'not-complete', 'store_driver': DRIVER,
       'runner': 'rootful private store (RootfulRunner); not production OwnerRunner/rootless',
       'source': {'host': '192.168.2.34', 'slug': CHAIN['slug'], 'archive_sha256': ATTESTED.get(CHAIN['slug']),
                  'addon': 'woow-omnigent 0.1.23', 'encrypted_backup': KEY_FILE is not None},
       'checks': checks, 'facts': facts}
started = time.monotonic()


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


def podman(*args, **kw):
    return r.podman(*args, **kw)


def text(*args, **kw):
    return podman(*args, **kw).stdout.decode('utf-8', 'replace')


# ---------------------------------------------------------------- target deployment (package quadlets, rendered)

def render(data):
    for key, value in RENDER.items():
        data = data.replace(key, value)
    assert '@@' not in data, 'unrendered-placeholder'
    return data


def package_quadlets():
    files = {}
    for path in sorted(PACKAGE.iterdir()):
        files[path.name] = render(path.read_text())
    return files


def container_args(quadlets, name, *, image=None, entrypoint=None, command=(), placeholder=False):
    """`podman run` arguments of one package .container file: name, image, volumes (.volume units resolved), env,
    secrets and hardening; Network/PublishPort/Health*/UserNS are the stated deviations (pod network none)."""
    parsed = tempctr.parse_unit(quadlets[name]).get('Container', [])
    args, used = ['--detach', '--pod', POD, '--label', LABEL, '--pull=never'], set()
    container_name = image_ref = None
    for key, value in parsed:
        used.add(key)
        if key == 'ContainerName':
            container_name = value
        elif key == 'Image':
            image_ref = value
        elif key == 'Volume':
            source, _sep, rest = value.partition(':')
            if source.endswith('.volume'):
                source = [v for k, v in tempctr.parse_unit(quadlets[source]).get('Volume', []) if k == 'VolumeName'][-1]
            args += ['--volume', source + ':' + rest]
        elif key == 'Environment':
            args += ['--env', value]
        elif key == 'Secret':
            args += ['--secret', value]
        elif key == 'NoNewPrivileges' and value == 'true':
            args += ['--security-opt', 'no-new-privileges']
        elif key == 'DropCapability':
            args += ['--cap-drop', value]
        elif key == 'AddCapability':
            for cap in value.split():
                args += ['--cap-add', cap]
    skipped = sorted(used - {'ContainerName', 'Image', 'Volume', 'Environment', 'Secret', 'NoNewPrivileges',
                             'DropCapability', 'AddCapability', 'Pull'})
    args += ['--name', container_name, '--memory', MEMORY[container_name], '--pids-limit', '512']
    if entrypoint:
        args += ['--entrypoint', entrypoint]
    if placeholder:
        # The placeholder borrows the PostgreSQL image, whose VOLUME would otherwise get an anonymous volume.
        args += ['--image-volume', 'ignore']
    return container_name, args + [image or image_ref, *command], image_ref, skipped


def wait_db(seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        p = podman('exec', DB, 'pg_isready', '-h', '127.0.0.1', '-p', '5432', '-U', 'omnigent', '-d', 'omnigent',
                   check=False, timeout=20)
        if p.returncode == 0:
            return True
        time.sleep(2)
    raise AssertionError('db-not-ready')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def http(method, path, body=None, token=None, digest=False, timeout=30):
    """One request to the target server on the pod's loopback (this process is in the pod's netns)."""
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


def wait_server(seconds=240):
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
    """A list response: the body itself or its first list under `keys`, data, items, results (0.21.0 list endpoints
    answer PaginatedList {"object": "list", "data": [...]}, omnigent/server/schemas.py)."""
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in keys + ('data', 'items', 'results'):
            if isinstance(body.get(key), list):
                return body[key]
    return []


def sql(statement):
    return podman('exec', '-i', DB, 'psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-U', 'omnigent', '-d',
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
        podman('volume', 'export', volume, stdout=handle, timeout=600, max_output=2 * 1024 ** 3)
    return path


def import_file(volume, path):
    with open(path, 'rb') as handle:
        podman('volume', 'import', volume, '-', input=handle, timeout=600)


def tar_files(path):
    """{name: sha256} of the regular files of a volume tar (digests only, values never leave this process)."""
    found = {}
    with tarfile.open(path) as tar:
        for member in tar:
            if member.isfile():
                found[member.name.removeprefix('./')] = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
    return found


def tar_member(path, wanted):
    with tarfile.open(path) as tar:
        for member in tar:
            if member.isfile() and member.name.removeprefix('./') == wanted:
                return member.mode & 0o7777, tar.extractfile(member).read()
    return None, None


def server_cookie():
    data = podman('exec', SERVER, 'cat', '/data/artifacts/accounts-cookie-secret', max_output=4096,
                  check=False).stdout or b''
    private(data)
    return data


def source_cookie():
    """HA's accounts-cookie-secret, read from the RPi5 archive through the product's strict member stream."""
    with habackup.open_backup(ARCHIVE) as opened:
        member = opened.layout.addon('1b7b4ce7_woow-omnigent')
        with opened.open_member(member.name, KEYS) as stream:
            select = habackup.Select(include=(COOKIE_MEMBER,), symlinks=(), hardlinks=False)
            for entry in habackup.iter_entries(stream, select, habackup.Report()):
                if entry.name == COOKIE_MEMBER:
                    return private(entry.read_all(4096))
    return None


def setns_pod():
    infra = text('pod', 'inspect', POD, '--format', '{{.InfraContainerID}}').strip()
    pid = int(text('inspect', infra, '--format', '{{.State.Pid}}').strip())
    libc = ctypes.CDLL(None, use_errno=True)
    fd = os.open('/proc/%d/ns/net' % pid, os.O_RDONLY)
    try:
        if libc.setns(fd, CLONE_NEWNET) != 0:
            raise OSError(ctypes.get_errno(), 'setns')
    finally:
        os.close(fd)
    # if_nameindex asks the kernel in this thread's namespace (/sys/class/net would show the mount's namespace).
    return sorted(name for _index, name in socket.if_nameindex())


# ---------------------------------------------------------------- the stack

def start(name):
    container, args, _image, _skipped = SPECS[name]
    podman('run', *args, timeout=180)
    if name == DB:
        wait_db()
    elif name == SERVER:
        wait_server()


def stop_all(remove=True):
    for name in (RUNNER, SERVER, DB):
        podman('stop', '--time', '30', name, check=False, timeout=90)
        if remove:
            podman('rm', '--force', '--volumes', name, check=False, timeout=60)


def running(name):
    p = podman('container', 'inspect', name, '--format', '{{.State.Status}}', check=False, timeout=30)
    return p.returncode == 0 and p.stdout.strip() == b'running'


def verify_restored(phase, expect, creds, passwords, ha_cookie, pi_files, server_marker):
    """HA's data and logins on the restored target, and this device's kept identity (fatal checks)."""
    pre = phase + '_'
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
    grows = 'account_tokens'   # browser-form logins above may add rows; HA's rows must all be there
    differ = sorted(k for k, v in expected.items() if k != grows and counts.get(k) != v)
    must(pre + 'table_counts_equal_ha_plus_kept_admin', not differ and counts[grows] >= expected[grows],
         differing=differ, tables=len(expected))
    cookie = server_cookie()
    must(pre + 'ha_cookie_installed', bool(cookie) and cookie == ha_cookie)
    pi_now = tar_files(export_file(PIVOL, private_dir('work', 'probe') / ('pi-' + phase + '.tar')))
    must(pre + 'runner_pi_volume_unchanged', pi_now == pi_files, files=len(pi_now))
    marker = podman('exec', SERVER, 'cat', '/data/a54-target-marker.txt', check=False, max_output=4096).stdout
    must(pre + 'target_server_settings_kept', marker == server_marker)
    shutil.rmtree(ROOT / 'work' / 'probe', ignore_errors=True)


# ---------------------------------------------------------------- main

SPECS = {}
conversion = None
opened = None
try:
    out['phase'] = 'inputs'
    # The private store belongs to this lane's workspace only: anything a previous attempt left (an anonymous
    # volume of attempt 2) is reported and removed before this attempt starts; images stay.
    before = store_objects(r)
    facts['store_before_run'] = {k: len(v) for k, v in before.items()}
    for name in before['volumes']:
        r.podman('volume', 'rm', '--force', name, check=False, timeout=60)
    must('store_clean_before_run', not store_objects(r)['volumes'] and not before['containers'] and not before['pods'])
    must('archive_sha256_equals_source_attested', CHAIN['slug'] in ATTESTED and CHAIN.get('sha256')
         == ATTESTED[CHAIN['slug']] and sha256_file(ARCHIVE) == ATTESTED[CHAIN['slug']])
    if KEY_FILE is not None:
        key_text = haimport.read_key_file(KEY_FILE)   # the product's key reader; masked from now on
        private(key_text)
        KEYS = hasecuretar.Keys(key_text)
        del key_text
        os.unlink(KEY_FILE)
        import nacl
        facts['nacl'] = {'version': getattr(nacl, '__version__', None),
                         'from_workspace_wheel': Path(nacl.__file__).resolve().is_relative_to(ROOT / 'pydeps')}
    creds_path = ROOT / 'input/omni-creds.json'
    raw = json.loads(creds_path.read_text())
    creds_path.unlink()
    creds = {'admin': tuple(raw['admin']), 'member': tuple(raw['member'])}
    for _user, password in creds.values():
        private(password)
    expect = json.loads((ROOT / 'input/omni-expect.json').read_text())
    must('logins_match_recorded_source', creds['admin'][0] == expect['admin'] and creds['member'][0] == expect['member']
         and creds['admin'][0] == next(u['id'] for u in expect['users'] if u['is_admin']))
    images = text('images', '--format', '{{.Repository}} {{.Digest}}')
    must('images_present', 'ghcr.io/omnigent-ai/omnigent-server' in images
         and 'docker.io/library/postgres' in images)
    ha_cookie = source_cookie()
    must('source_cookie_read', bool(ha_cookie))

    out['phase'] = 'public-guard'
    try:
        ha_omnigent.convert(None, SimpleNamespace(id='omnigent'), False, None)
        public_refused = False
    except BackupError as error:
        public_refused = error.code == 'incompatible' and error.message == ha_omnigent.SECURITY_BLOCKER
    must('public_convert_still_refuses_security_blocker', public_refused)
    try:
        haimport._run_omnigent_candidate(None, {'apps': ['omnigent']}, schema_ddl_quiesced=False)
        internal_refused = False
    except BackupError as error:
        internal_refused = error.code == 'incompatible'
    must('internal_candidate_refuses_without_quiescence', internal_refused)

    out['phase'] = 'target-deploy'
    quadlets = package_quadlets()
    SPECS[DB] = container_args(quadlets, 'omnigent-postgres.container')
    SPECS[SERVER] = container_args(quadlets, 'omnigent-server.container')
    SPECS[RUNNER] = container_args(quadlets, 'omnigent-runner.container', image=PG_IMAGE, entrypoint='/bin/sleep',
                                   command=('infinity',), placeholder=True)
    must('package_images_are_the_pinned_ones', SPECS[DB][2] == PG_IMAGE and SPECS[SERVER][2] == SERVER_IMAGE)
    facts['quadlet_keys_not_translated'] = {name: SPECS[name][3] for name in SPECS}
    passwords = {'db': secrets.token_urlsafe(32), 'admin': secrets.token_urlsafe(32), 'runner': secrets.token_urlsafe(32)}
    for value in passwords.values():
        private(value)
    db_url = 'postgresql://omnigent:%s@127.0.0.1:5432/omnigent' % passwords['db']
    private(db_url)
    for name, value in zip(SECRET_NAMES, (passwords['db'], db_url, passwords['admin'], passwords['runner'])):
        podman('secret', 'create', '--label', LABEL, name, '-', input=value.encode(), timeout=60)
    for volume in VOLUMES:
        podman('volume', 'create', '--label', LABEL, volume, timeout=60)
    pi_marker = b'a54 target runner identity marker 20261123\n'
    server_marker = b'a54 target server runtime settings marker 20261123\n'
    podman('volume', 'import', PIVOL, '-', input=volume_tar([('a54-runner-marker.txt', pi_marker, 0o600)]),
           timeout=120)
    podman('volume', 'import', SERVERVOL, '-', input=volume_tar([('a54-target-marker.txt', server_marker, 0o644)]),
           timeout=120)
    podman('pod', 'create', '--name', POD, '--label', LABEL, '--network', 'none', timeout=120)
    podman('pod', 'start', POD, timeout=120)
    infra = text('pod', 'inspect', POD, '--format', '{{.InfraContainerID}}').strip()
    must('pod_network_none', text('inspect', infra, '--format', '{{.HostConfig.NetworkMode}}').strip() == 'none')
    facts['netns_links'] = setns_pod()
    # A new namespace also gets the kernel's fallback tunnel devices (sit0, ip6tnl0, ... when those modules are
    # loaded); they are down and unconfigured. Only lo may carry an address.
    addrs = subprocess.run(['ip', '-o', 'addr', 'show'], capture_output=True, text=True, timeout=30).stdout.split('\n')
    up = subprocess.run(['ip', '-o', 'link', 'show', 'up'], capture_output=True, text=True, timeout=30).stdout.split('\n')
    facts['netns_addressed'] = sorted({line.split()[1] for line in addrs if line.strip()})
    facts['netns_up'] = sorted({line.split(':')[1].strip().split('@')[0] for line in up if line.strip()})
    must('process_in_pod_netns_only_lo_configured', facts['netns_addressed'] == ['lo'] and facts['netns_up'] == ['lo']
         and set(facts['netns_links']) <= {'lo', 'sit0', 'ip6tnl0', 'tunl0', 'gre0', 'gretap0', 'erspan0', 'ip6gre0',
                                           'ip6_vti0', 'ip_vti0'})
    start(DB)
    start(SERVER)
    start(RUNNER)
    for name in (DB, SERVER, RUNNER):
        info = json.loads(text('inspect', name))[0]
        must('no_published_ports_' + name, not info['HostConfig'].get('PortBindings')
             and info['HostConfig'].get('NetworkMode', '').startswith('container:'))
    status, info = http('GET', '/v1/info')
    must('target_info', status == 200 and (info or {}).get('server_version') == '0.21.0'
         and (info or {}).get('needs_setup') is False)
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
    pi_files = tar_files(export_file(PIVOL, private_dir('work', 'pre') / 'pi.tar'))
    app = SimpleNamespace(id='omnigent', name='Omnigent', owner='arm54-rootful-private-store',
                          volumes=[{'name': v} for v in VOLUMES], postgres=[], data_dirs=[],
                          secrets=[{'name': n} for n in SECRET_NAMES],
                          health=[{'type': 'http', 'url': BASE_URL + '/health', 'timeout_seconds': 120}])

    out['phase'] = 'product-check'
    staging = private_dir('work', 'staging')
    # The product's own adapter class over the rootful private-store runner (image_inspect, owner_ids).
    adapter = QuadletPostgresAdapter(app, r, LOGS.append)
    temps = {'current': tempctr.TempObjects(r, JOB_CHECK, memory='512m', pids=512, cpus='1')}
    conversion = temps['current']
    opened = habackup.open_backup(ARCHIVE)
    work = SimpleNamespace(ha=opened, keys=KEYS, _addons={}, staging=staging,
                           guard=haimport.SpaceGuard([staging, ROOT], 12 * 1024 ** 3 + 128 * 1024 ** 2),
                           quadlets=lambda a: quadlets, runner=lambda a: r,
                           adapter=lambda a: adapter,
                           temp=lambda a: temps['current'], abort=lambda: None, checkpoint=lambda: None,
                           phase=lambda p: None, log=LOGS.append)
    for method in ('addon_member', 'addon_info', 'open'):
        setattr(work, method, MethodType(getattr(haimport.Work, method), work))
    try:
        checked = ha_omnigent.check(work, app)
    finally:
        left = conversion.cleanup()
    must('check_temp_objects_removed', not left)
    must('product_check_only_blocker_is_security_blocker', checked['blockers'] == [ha_omnigent.SECURITY_BLOCKER],
         blockers=len(checked['blockers']))
    must('product_check_target_version', checked['target_version'] == '0.21.0')
    section = checked['omnigent']
    facts['product_check'] = {k: section.get(k) for k in ('omnigent_version', 'alembic', 'users', 'admins',
                                                          'conversations', 'scheduled_tasks', 'scheduled_tasks_active',
                                                          'hosts', 'agents', 'files', 'public_sessions',
                                                          'artifact_files', 'override_files')}
    facts['product_check_warnings'] = len(checked['warnings'])

    out['phase'] = 'candidate-convert'
    conversion = temps['current'] = tempctr.TempObjects(r, JOB_CONVERT, memory='512m', pids=512, cpus='1')
    real_prepare = ha_omnigent._prepare
    quiesced = {}

    def prepare_then_quiesce(work_, app_):
        result = real_prepare(work_, app_)
        quiesced['live_version'], quiesced['live_alembic'] = result[1], result[2]
        # DDL quiescence (the caller's contract): the server, the only schema writer, stops before any capture.
        podman('stop', '--time', '30', SERVER, timeout=90)
        quiesced['server_stopped'] = not running(SERVER)
        return result

    converted_dir = private_dir('work', 'converted')
    try:
        with mock.patch.object(ha_omnigent, '_prepare', prepare_then_quiesce):
            ha_omnigent.require_registered_secrets(work, app)
            converted = ha_omnigent._convert_candidate(work, app, False, converted_dir, schema_ddl_quiesced=True)
    finally:
        left = conversion.cleanup()
        opened.close()
        opened = None
    must('convert_temp_objects_removed', not left)
    must('live_discovery_from_running_server_then_quiesced', quiesced.get('live_version') == '0.21.0'
         and quiesced.get('live_alembic') == [expect['alembic']] and quiesced.get('server_stopped') is True)
    must('candidate_kept_target_admin', converted['kept_accounts'] == [TARGET_ADMIN] and not converted['conflicts'],
         kept=converted['kept_accounts'])
    # The product counts people only (users without 'local'/'__public__', ha_omnigent.DETAIL_SQL); the recorded
    # source lists exactly those people in `users` while db_counts.users is the whole table.
    must('candidate_counts', converted['counts'].get('users') == len(expect['users'])
         and converted['counts'].get('conversations') == expect['db_counts']['conversations']
         and converted['counts'].get('hosts') == expect['db_counts']['hosts'], counts=converted['counts'])
    facts['candidate'] = {k: converted.get(k) for k in ('paused_tasks', 'scheduled_tasks_active', 'public_sessions',
                                                        'overrides', 'hosts')}
    volumes = converted['volumes']
    must('candidate_volumes', sorted(volumes) == sorted(VOLUMES))

    out['phase'] = 'integrity-before-start'
    mode, cookie_bytes = tar_member(volumes[SERVERVOL], 'artifacts/accounts-cookie-secret')
    private(cookie_bytes or b'')
    must('converted_cookie_is_ha_cookie_0600', cookie_bytes == ha_cookie and mode == 0o600)
    server_files = tar_files(volumes[SERVERVOL])
    must('converted_server_volume_keeps_target_settings', server_files.get('a54-target-marker.txt')
         == hashlib.sha256(server_marker).hexdigest())
    must('converted_pi_volume_is_target_pi', tar_files(volumes[PIVOL]) == pi_files)
    must('converted_attachment_present', any(k.startswith('artifacts/') for k in server_files),
         artifact_files=sum(k.startswith('artifacts/') for k in server_files))

    out['phase'] = 'restore'
    stop_all()
    safety = private_dir('work', 'safety')
    for volume in VOLUMES:
        export_file(volume, safety / (volume + '.tar'))
    for volume in VOLUMES:
        podman('volume', 'rm', volume, timeout=60)
        podman('volume', 'create', '--label', LABEL, volume, timeout=60)
        import_file(volume, volumes[volume])
    for name in (DB, SERVER, RUNNER):
        start(name)
    verify_restored('installed', expect, creds, passwords, ha_cookie, pi_files, server_marker)

    out['phase'] = 'restart'
    stop_all()
    for name in (DB, SERVER, RUNNER):
        start(name)
    verify_restored('restarted', expect, creds, passwords, ha_cookie, pi_files, server_marker)

    out['phase'] = 'rollback'
    stop_all()
    for volume in VOLUMES:
        podman('volume', 'rm', volume, timeout=60)
        podman('volume', 'create', '--label', LABEL, volume, timeout=60)
        import_file(volume, safety / (volume + '.tar'))
    for name in (DB, SERVER, RUNNER):
        start(name)
    t_status, target_token = login(TARGET_ADMIN, passwords['admin'])
    ha_status, _tok = login(*creds['admin'])
    s, users = http('GET', '/auth/users', token=target_token)
    a_status, _agent = http('GET', '/v1/agents/' + expect['agent']['id'], token=target_token)
    listed = {u.get('id') for u in items(users, 'users') if isinstance(u, dict)}
    must('rollback_restores_pre_import_target', t_status == 200 and ha_status in (400, 401, 403) and s == 200
         and TARGET_ADMIN in listed and not listed & ha_ids and a_status in (403, 404)
         and server_cookie() == target_cookie and sql('SELECT count(*) FROM users;') == str(target_user_rows),
         target=t_status, ha=ha_status, agent=a_status)
    stop_all()
    out.update(status='passed' if all(checks.values()) else 'partial', phase='done',
               false_checks=sorted(k for k, v in checks.items() if not v))
except Exception as error:  # noqa: BLE001
    out['error_code'] = type(error).__name__
    # Where it failed (file, line, function of the innermost frames); never the message (values may be inside).
    out['error_where'] = [[Path(f.filename).name, f.lineno, f.name]
                          for f in traceback.extract_tb(error.__traceback__)[-4:]]
    if isinstance(error, AttributeError):
        out['missing_attribute'] = getattr(error, 'name', None)
    if isinstance(error, AssertionError):
        out['failed_check'] = str(error)[:80]
    if hasattr(error, 'code'):
        out['product_error_code'] = error.code
finally:
    cleanup = {}
    for staged in (KEY_FILE, ROOT / 'input/omni-creds.json'):
        if staged is not None and staged.exists():
            cleanup['staged_file_removed_late'] = True
            staged.unlink()
    if opened is not None:
        opened.close()
    if conversion is not None:
        cleanup['temp_left'] = len(conversion.cleanup())
    for name in (RUNNER, SERVER, DB):
        r.podman('rm', '--force', '--volumes', '--time', '10', name, check=False, timeout=60)
    r.podman('pod', 'rm', '--force', POD, check=False, timeout=120)
    for volume in VOLUMES:
        r.podman('volume', 'rm', '--force', volume, check=False, timeout=60)
    for name in SECRET_NAMES:
        r.podman('secret', 'rm', name, check=False, timeout=60)
    shutil.rmtree(ROOT / 'work', ignore_errors=True)
    objects = store_objects(r)
    cleanup.update(store_after={k: len(v) for k, v in objects.items()}, volumes_left=objects['volumes'][:10],
                   work_removed=not (ROOT / 'work').exists(),
                   no_lab_containers=not objects['containers'], no_lab_pods=not objects['pods'],
                   no_lab_volumes=not objects['volumes'], no_lab_secrets=not objects['secrets'],
                   login_file_removed=not (ROOT / 'input/omni-creds.json').exists(),
                   unlock_file_removed=KEY_FILE is None or not KEY_FILE.exists())
    out['cleanup'] = cleanup
    if out['status'] == 'passed' and not all(cleanup[k] for k in ('no_lab_containers', 'no_lab_pods', 'no_lab_volumes',
                                                                  'no_lab_secrets', 'login_file_removed',
                                                                  'unlock_file_removed')):
        out['status'] = 'failed'
        out['failed_check'] = 'cleanup'
    out['elapsed_seconds'] = round(time.monotonic() - started, 1)
    out['podman_commands'] = len(r.commands)
    out['free_bytes_min'] = min(r.free) if r.free else None
    out['product_log_lines'] = len(LOGS)
    needles = {v for v in PRIVATE if len(v) >= 6}
    out['product_log_secret_hits'] = sum(line.encode().count(v) for line in LOGS for v in needles)
    encoded = json.dumps(out, sort_keys=True).encode()
    commands = json.dumps(r.commands).encode()
    if any(v in encoded or json.dumps(v.decode('latin-1'))[1:-1].encode() in encoded for v in needles) or \
            any(v in commands for v in needles):
        out = {'status': 'failed', 'failed_check': 'secret_in_output_suppressed', 'commercial_acceptance': 'not-complete'}
    report(ROOT / 'omnigent-result.json', out)
    print(json.dumps(out, sort_keys=True))
    sys.exit(0 if out['status'] == 'passed' else 1)
