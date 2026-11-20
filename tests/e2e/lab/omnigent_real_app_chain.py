#!/usr/bin/env python3
"""Real Omnigent bootstrap -> cold HA -> candidate -> restored app; isolated dev-d only."""
import argparse
import io
import json
import os
import re
from pathlib import Path
import secrets
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'backup-engine'))
from woowbackup import ha_omnigent as omni, habackup, tempctr, nested
from woowbackup.podman import default_runner

APP_IMAGE = '545fa9ea7c1946bbca7df95448b8d2d172777ad861b41599ef69a81b3b32e6d5'
IMAGE = '4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873'
OWNER = ROOT / 'tests/e2e/lab/owner.sh'
LAB = Path.home() / '.woowbk-lab/bin/labpodman'
PREFIX = 'woowbk-omni-appchain-' + secrets.token_hex(5)
SOURCE, TARGET, RESTORED = PREFIX + '-source', PREFIX + '-target', PREFIX + '-restored'
SOURCE_APP, TARGET_APP, RESTORED_APP = PREFIX + '-sourceapp', PREFIX + '-targetapp', PREFIX + '-restoredapp'
SOURCE_SECRET, TARGET_SECRET = PREFIX + '-source-password', PREFIX + '-target-password'
SOURCE_APPVOL, RESTORED_APPVOL = PREFIX + '-sourceappdata', PREFIX + '-restoredappdata'
RESTOREDVOL = PREFIX + '-restoredpg'
PGVOL, TARGETVOL, SERVERVOL, PIVOL = [PREFIX + x for x in ('-pg', '-targetpg', '-server', '-pi')]


SECRET_VALUES = []
EVENT_RECORDS = []


def register_private(value):
    if isinstance(value, str):
        value = value.encode('utf-8')
    if not isinstance(value, bytes) or not value:
        raise RuntimeError('empty_private_value')
    SECRET_VALUES.append(value)


def scan_needles(values):
    needles = set(values)
    for value in values:
        try:
            decoded = value.decode('utf-8')
        except UnicodeDecodeError:
            continue
        for ascii_only in (False, True):
            needles.add(json.dumps(decoded, ensure_ascii=ascii_only)[1:-1].encode('utf-8'))
    return needles


def event(stage, **values):
    encoded = json.dumps({'stage': stage, **values}, sort_keys=True).encode('utf-8')
    if any(value in encoded for value in scan_needles(SECRET_VALUES)):
        raise RuntimeError('sensitive_evidence_suppressed')
    EVENT_RECORDS.append(encoded)
    print(encoded.decode('utf-8'), flush=True)


from omnigent_lab_runner import Runner, require_names_absent
from b1_event_transport import run_events

def add(tar, name, data=None, *, kind='file', mode=0o755):
    info = tarfile.TarInfo(name)
    info.mode = mode
    if kind == 'dir':
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
    else:
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))


def small_volume(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as tar:
        add(tar, '.', kind='dir')
        for name, data in entries:
            add(tar, name, data, kind='dir' if data is None else 'file')
    out.seek(0)
    return out


def build_addon(cold, path, app_data):
    addon = {'user': {'version':'0.1.23', 'image':'ghcr.io/woowtech/woow-ha-omnigent-amd64', 'options': {}},
             'system': {'slug':'woow-omnigent', 'name':'Synthetic Omnigent'}, 'version':'0.1.23'}
    with tarfile.open(path, 'w', format=tarfile.PAX_FORMAT) as out:
        add(out, '.', kind='dir')
        add(out, 'addon.json', json.dumps(addon).encode())
        add(out, 'data', kind='dir')
        with tarfile.open(cold, 'r:') as src:
            for item in src:
                name = item.name.removeprefix('./').strip('/')
                item.name = 'data/postgres' + ('/' + name if name and name != '.' else '')
                item.uname = item.gname = ''
                out.addfile(item, src.extractfile(item) if item.isfile() else None)
        for name in ('data/omnigent-home', 'data/omnigent-home/.omnigent'):
            add(out, name, kind='dir')
        seen_cookie = False
        with tarfile.open(app_data, 'r:') as src:
            for item in src:
                name = item.name.removeprefix('./').strip('/')
                if name != 'artifacts' and not name.startswith('artifacts/'):
                    continue
                if not (item.isdir() or item.isfile()):
                    raise RuntimeError('unsupported_synthetic_artifact_type')
                item.name = 'data/omnigent-home/.omnigent/' + name
                item.uname = item.gname = ''
                seen_cookie |= name == 'artifacts/accounts-cookie-secret' and item.size > 0
                out.addfile(item, src.extractfile(item) if item.isfile() else None)
        if not seen_cookie:
            raise RuntimeError('synthetic_cookie_missing')


ADDON_SLUG = '1b7b4ce7_woow-omnigent'


def build_supervisor(addon, path):
    """Synthetic Supervisor outer tar containing the actual cold add-on tar."""
    doc = {'slug': 'c0ffee00', 'version': 2, 'name': 'synthetic', 'date': '2026-11-20T00:00:00Z',
           'type': 'partial', 'supervisor_version': '2026.11.0', 'extra': {}, 'homeassistant': None,
           'repositories': [], 'compressed': False, 'protected': False, 'folders': [],
           'addons': [{'slug': ADDON_SLUG, 'name': 'Synthetic Omnigent', 'version': '0.1.23'}]}
    with tarfile.open(path, 'w', format=tarfile.PAX_FORMAT) as outer:
        outer.add(addon, arcname=ADDON_SLUG + '.tar', recursive=False)
        add(outer, 'backup.json', json.dumps(doc).encode())


def fixture_quadlets(target_container, pg_volume, server_volume, pi_volume):
    """Synthetic catalog-backed Quadlets; none are installed or started by systemd."""
    def text(value): return value.encode('utf-8')
    return {
        'db.container': text('[Container]\nContainerName=' + target_container + '\nImage=' + IMAGE +
            '\nVolume=db.volume:/var/lib/postgresql/data\nEnvironment=POSTGRES_USER=postgres\n'
            'Environment=POSTGRES_DB=omnigent\nEnvironment=POSTGRES_HOST_AUTH_METHOD=trust\n'),
        'server.container': text('[Container]\nImage=' + APP_IMAGE + '\nVolume=server.volume:/data\n'
            'Environment=OMNIGENT_ACCOUNTS_INIT_ADMIN_USERNAME=target-admin\n'),
        'runner.container': text('[Container]\nImage=' + APP_IMAGE + '\nVolume=pi.volume:/data/pi-agent\n'
            'Environment=OMNIGENT_RUNNER_USERNAME=target-admin\n'),
        'db.volume': text('[Volume]\nVolumeName=' + pg_volume + '\n'),
        'server.volume': text('[Volume]\nVolumeName=' + server_volume + '\n'),
        'pi.volume': text('[Volume]\nVolumeName=' + pi_volume + '\n'),
    }


LOGIN_PRODUCER = r'''import json, sys, urllib.request, urllib.error
request = json.loads(sys.stdin.readline())
body = json.dumps({'username':request['username'], 'password':request['password'], 'issue_refresh':True}).encode()
req = urllib.request.Request('http://127.0.0.1:8000/auth/login', data=body,
                             headers={'Content-Type':'application/json'}, method='POST')
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None
try:
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(req, timeout=30) as response:
        status = response.status
        data = response.read(1048577)
except urllib.error.HTTPError as error:
    status, data = error.code, error.read(1048577)
if len(data) > 1048576: raise SystemExit(1)
try: parsed = json.loads(data)
except ValueError: parsed = {}
credentials = {key: parsed[key] for key in ('token', 'refresh_token', 'access_token') if isinstance(parsed, dict) and key in parsed}
def emit(event):
    print(json.dumps(event), flush=True)
    if sys.stdin.readline() != 'OK\n': raise SystemExit(1)
emit({'type':'auth', 'sequence':0, 'source':'/auth/login', 'status':status, 'credentials':credentials})
emit({'type':'summary', 'sequence':1, 'data':{'complete':True}})
emit({'type':'end', 'sequence':2})
'''


def login_registered(container, username, password, source, observed):
    """Every issued login token and refresh grant is registered before acknowledgement."""
    values = []
    def register(value):
        register_private(value)
        values.append(value)
    result = run_events([str(OWNER), 'd', 'podman', 'exec', '-i', container, 'python3', '-I', '-c', LOGIN_PRODUCER],
                        {'username':username, 'password':password}, register,
                        [('/auth/login', ('token', 'refresh_token'), True)], timeout=90)
    if result != {'complete':True} or len(values) != 2:
        raise RuntimeError('synthetic_login_event_incomplete')
    observed.extend([source + '.token', source + '.refresh_token'])
    return values[0]


def cookie_from_container(runner, container):
    """Read only this fresh app's private cookie and register it before further calls."""
    value = runner.podman('exec', container, 'cat', '/data/artifacts/accounts-cookie-secret',
                          max_output=4096).stdout.strip()
    if not re.fullmatch(rb'[0-9a-f]{64}', value):
        raise RuntimeError('synthetic_cookie_invalid')
    register_private(value)
    return value


def file_contains(path, needle):
    carry = b''
    with path.open('rb') as handle:
        while chunk := handle.read(1024 * 1024):
            data = carry + chunk
            if needle in data:
                return True
            carry = data[-(len(needle) - 1):] if len(needle) > 1 else b''
    return False


def cookie_from_tar(path):
    with tarfile.open(path, 'r:') as tar:
        entries = [m for m in tar if m.name.removeprefix('./').strip('/') == 'artifacts/accounts-cookie-secret']
        if len(entries) != 1 or not entries[0].isfile() or not 0 < entries[0].size <= 4096:
            raise RuntimeError('synthetic_cookie_missing')
        cookie = tar.extractfile(entries[0]).read()
    register_private(cookie)
    return cookie


def private_scan(paths, secrets_to_find):
    """Bounded streaming scan; values remain private and only aggregate counts escape."""
    longest = max(map(len, secrets_to_find), default=1)
    count = 0
    for path in paths:
        tail = b''
        with path.open('rb') as handle:
            while chunk := handle.read(1024 * 1024):
                block = tail + chunk
                count += sum(block.count(value) for value in secrets_to_find)
                tail = block[-(longest - 1):] if longest > 1 else b''
    return {'files':len(paths), 'matches':count}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', action='store_true')
    if not parser.parse_args().run:
        parser.error('explicit --run required')
    result = default_runner([str(LAB), 'inspect', '--format', '{{.State.Status}} {{.HostConfig.NetworkMode}} {{json .NetworkSettings.Ports}}',
                             'woowbk-dev-d'], timeout=30, max_output=4096)
    if result.returncode != 0 or result.stdout.strip() != b'running none {}':
        raise RuntimeError('dev_d_not_isolated')
    runner = Runner()
    for image in (IMAGE, APP_IMAGE):
        assert runner.podman('image', 'inspect', '--format', '{{.Id}}', image).stdout.decode().strip().removeprefix('sha256:') == image
    memory_result = default_runner([str(LAB), 'exec', 'woowbk-dev-d', 'sh', '-c',
        'cat /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.max'], timeout=30, max_output=4096)
    if memory_result.returncode != 0:
        raise RuntimeError('isolated_lab_memory_check_failed')
    memory = memory_result.stdout.split()
    if len(memory) != 2 or int(memory[1]) - int(memory[0]) < 1400 * 1024 * 1024:
        raise RuntimeError('insufficient_isolated_lab_memory')
    event('preflight', image_id=IMAGE, outer_network='none', max_pg_containers=2, each_memory_mib=128)
    created_volumes, containers, secrets_created, open_backups = [], [], [], []
    os.umask(0o077)
    source_password = secrets.token_urlsafe(32)
    target_password = secrets.token_urlsafe(32)
    register_private(source_password)
    register_private(target_password)
    observed_sources, observed_cookies, app_logs = [], [], []
    tmp = tempctr.TempObjects(runner, 'j20261120T120000Z-' + secrets.token_hex(4), memory='128m', pids=96, cpus=None)
    # Prove every intended random name absent before tracking anything for cleanup.
    require_names_absent(runner, (
        ('container', (SOURCE, TARGET, RESTORED, SOURCE_APP, TARGET_APP, RESTORED_APP,
                       *(tmp.name(role) for role in ('ids-pg', 'hapg', 'omni-db', 'controldata')))),
        ('volume', (PGVOL, TARGETVOL, SERVERVOL, PIVOL, RESTOREDVOL, SOURCE_APPVOL, RESTORED_APPVOL,
                    *(tmp.name(role) for role in ('hapg', 'omni-db')))),
        ('secret', (SOURCE_SECRET, TARGET_SECRET)),
    ))
    try:
        for volume in (PGVOL, TARGETVOL, SERVERVOL, PIVOL, RESTOREDVOL, SOURCE_APPVOL, RESTORED_APPVOL):
            created_volumes.append(volume)
            runner.podman('volume', 'create', volume)
        def start(name, volume):
            containers.append(name)
            runner.podman('run', '-d', '--name', name, '--network', 'none', '--pull=never', '--read-only',
                          '--memory', '128m', '--pids-limit', '96',
                          '--tmpfs', '/run/postgresql:rw,nosuid,nodev', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev',
                          '-v', volume + ':/var/lib/postgresql/data:rw,noexec,nosuid,nodev',
                          '-e', 'POSTGRES_USER=postgres', '-e', 'POSTGRES_DB=omnigent',
                          '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', IMAGE)
            for _ in range(60):
                if runner.podman('exec', name, 'pg_isready', '-q', '-h', '127.0.0.1', '-U', 'postgres', check=False).returncode == 0:
                    return
                time.sleep(1)
            raise RuntimeError('fixture_pg_not_ready')
        def sql(name, text):
            runner.podman('exec', '-i', name, 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres',
                          '-d', 'omnigent', '-f', '-', input=text.encode())
        secrets_created.append(SOURCE_SECRET)
        runner.podman('secret', 'create', SOURCE_SECRET, '-', input=source_password.encode())
        secrets_created.append(TARGET_SECRET)
        runner.podman('secret', 'create', TARGET_SECRET, '-', input=target_password.encode())
        def start_app(name, database, volume, secret, username):
            containers.append(name)
            runner.podman('run', '-d', '--name', name, '--pull=never', '--log-driver=none',
                '--network=container:' + database, '--memory=768m', '--cpus=1', '--pids-limit=256',
                '--cap-drop=ALL', '--security-opt=no-new-privileges', '-v', volume + ':/data',
                '--secret', secret + ',type=env,target=OMNIGENT_ACCOUNTS_INIT_ADMIN_PASSWORD',
                '-e', 'DATABASE_URL=postgresql://postgres@127.0.0.1:5432/omnigent',
                '-e', 'HOST=127.0.0.1', '-e', 'PORT=8000', '-e', 'ARTIFACT_DIR=/data/artifacts',
                '-e', 'OMNIGENT_AUTH_ENABLED=1', '-e', 'OMNIGENT_AUTH_PROVIDER=accounts',
                '-e', 'OMNIGENT_PUBLIC_SHARING=0', '-e', 'OMNIGENT_ADMIN_CREDENTIALS_PATH=/data/admin-credentials',
                '-e', 'OMNIGENT_ACCOUNTS_INIT_ADMIN_USERNAME=' + username, APP_IMAGE)
            for _ in range(90):
                if runner.podman('exec', name, 'curl', '-fsS', '-o', '/dev/null',
                                 'http://127.0.0.1:8000/health', check=False).returncode == 0:
                    return
                time.sleep(2)
            raise RuntimeError('synthetic_app_not_ready')
        def collect_logs(name):
            result = runner.podman('logs', name, check=False, max_output=4 * 1024 * 1024)
            app_logs.append(result.stdout if result.returncode == 0 else None)
        def api(name, request):
            code = """import json,sys,urllib.request,urllib.error
r=json.load(sys.stdin); data=json.dumps(r['body']).encode() if r.get('body') is not None else None
headers={'Content-Type':'application/json'}
if r.get('token'): headers['Authorization']='Bearer '+r['token']
q=urllib.request.Request('http://127.0.0.1:8000'+r['path'],data=data,headers=headers,method=r['method'])
try:
 with urllib.request.urlopen(q,timeout=30) as response:
  print(json.dumps({'status':response.status,'body':json.load(response)}))
except urllib.error.HTTPError as e:
 print(json.dumps({'status':e.code}))
"""
            result = runner.podman('exec', '-i', name, 'python3', '-I', '-c', code,
                                   input=json.dumps(request).encode())
            return json.loads(result.stdout)
        start(SOURCE, PGVOL)
        start_app(SOURCE_APP, SOURCE, SOURCE_APPVOL, SOURCE_SECRET, 'source-admin')
        source_cookie_live = cookie_from_container(runner, SOURCE_APP)
        observed_cookies.append('source_cookie')
        source_token = login_registered(SOURCE_APP, 'source-admin', source_password, 'source_login', observed_sources)
        agents = api(SOURCE_APP, {'method':'GET', 'path':'/v1/agents', 'body':None, 'token':source_token})
        body = agents.get('body')
        entries = body if isinstance(body, list) else (body.get('agents') or body.get('data') or body.get('items') or [])
        if agents.get('status') != 200 or not entries or not entries[0].get('id'):
            raise RuntimeError('synthetic_agent_missing')
        marker_title = 'woowbk-synthetic-' + secrets.token_hex(8)
        session = api(SOURCE_APP, {'method':'POST', 'path':'/v1/sessions', 'token':source_token,
                                  'body':{'agent_id':entries[0]['id'], 'title':marker_title}})
        if session.get('status') != 201 or not session.get('body', {}).get('id'):
            raise RuntimeError('synthetic_session_create_failed')
        marker_id = session['body']['id']
        if not isinstance(marker_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', marker_id):
            raise RuntimeError('synthetic_session_id_invalid')
        original = api(SOURCE_APP, {'method':'GET', 'path':'/v1/sessions/' + marker_id,
                                    'body':None, 'token':source_token})
        if original.get('status') != 200 or original.get('body', {}).get('title') != marker_title:
            raise RuntimeError('synthetic_session_read_failed')
        event('source_session_marker', created_and_read=True)
        source_me = api(SOURCE_APP, {'method':'GET', 'path':'/auth/me', 'body':None, 'token':source_token})
        source_user = source_me.get('body', {}).get('user', source_me.get('body', {}))
        source_id = source_user.get('id') if isinstance(source_user, dict) else None
        assert source_me.get('status') == 200 and source_id == 'source-admin'
        event('real_source_bootstrap', app_image=APP_IMAGE, login=True)
        collect_logs(SOURCE_APP)
        runner.podman('stop', '--time', '30', SOURCE_APP)
        runner.podman('rm', SOURCE_APP)
        containers.remove(SOURCE_APP)
        runner.podman('stop', '--time', '30', SOURCE)
        runner.podman('rm', SOURCE)
        containers.remove(SOURCE)
        event('source_cold')
        with tempfile.TemporaryDirectory(prefix='woowbk-omni-chain-') as d:
            root = Path(d)
            cold, addon, source_app = root / 'cold.tar', root / 'addon.tar', root / 'source-app.tar'
            outer = root / 'supervisor.tar'
            with cold.open('wb') as handle:
                runner.relay(['volume', 'export', PGVOL], stdout=handle, timeout=300)
            with source_app.open('wb') as handle:
                runner.relay(['volume', 'export', SOURCE_APPVOL], stdout=handle, timeout=300)
            source_cookie_registered = cookie_from_tar(source_app)
            assert source_cookie_live == source_cookie_registered
            build_addon(cold, addon, source_app)
            build_supervisor(addon, outer)
            ha = habackup.open_backup(outer)
            open_backups.append(ha)
            member = ha.layout.addon(ADDON_SLUG)
            event('supervisor_envelope', real_parser=True, member_found=True)
            with small_volume([('artifacts', None), ('artifacts/old', b'old'), ('sharing_mode', b'off')]) as handle:
                runner.podman('volume', 'import', SERVERVOL, '-', input=handle)
            with small_volume([('auth.json', b'synthetic-pi')]) as handle:
                runner.podman('volume', 'import', PIVOL, '-', input=handle)
            start(TARGET, TARGETVOL)
            event('target_started')
            # The target schema and account are created independently by the real image.
            start_app(TARGET_APP, TARGET, SERVERVOL, TARGET_SECRET, 'target-admin')
            target_cookie_live = cookie_from_container(runner, TARGET_APP)
            observed_cookies.append('target_cookie')
            login_registered(TARGET_APP, 'target-admin', target_password, 'target_login', observed_sources)
            target_info = api(TARGET_APP, {'method':'GET', 'path':'/v1/info', 'body':None})
            if target_info.get('status') != 200 or target_info.get('body', {}).get('server_version') != '0.21.0':
                raise RuntimeError('synthetic_target_info_invalid')
            collect_logs(TARGET_APP)
            runner.podman('stop', '--time', '30', TARGET_APP)
            runner.podman('rm', TARGET_APP)
            containers.remove(TARGET_APP)
            target_app_export = root / 'target-app.tar'
            with target_app_export.open('wb') as handle:
                runner.relay(['volume', 'export', SERVERVOL], stdout=handle, timeout=300)
            target_cookie_registered = cookie_from_tar(target_app_export)
            assert target_cookie_live == target_cookie_registered
            event('real_target_bootstrap', independently_initialized=True, login=True)
            guard = SimpleNamespace(check=lambda n: None, budget=lambda: 512 * 1024 * 1024, wrote=lambda n: None)
            ids = tuple(nested.IdMap(runner.podman('unshare', 'cat', '/proc/self/' + kind + '_map').stdout.decode())
                        for kind in ('uid', 'gid'))
            adapter = SimpleNamespace(owner_ids=lambda: ids, image_inspect=lambda image: {'env':['PG_MAJOR=16']})
            def addon_info(slug):
                assert slug == omni.SLUG
                with ha.open_member(member.name) as stream:
                    return habackup.read_addon_info(stream)
            work = SimpleNamespace(adapter=lambda app: adapter, temp=lambda app: tmp, runner=lambda app: runner,
                  guard=guard, staging=root / 'staging', abort=lambda: None, checkpoint=lambda: None,
                  phase=lambda phase: None, log=lambda msg: None, addon_member=lambda slug: member,
                  addon_info=addon_info, quadlets=lambda app: fixture_quadlets(TARGET, TARGETVOL, SERVERVOL, PIVOL),
                  open=lambda selected: ha.open_member(selected.name))
            work.staging.mkdir()
            app = SimpleNamespace(id='omnigent', name='Synthetic', owner='appowner', postgres=[], data_dirs=[],
                  volumes=[{'name': v} for v in (TARGETVOL, SERVERVOL, PIVOL)],
                  health=[{'type':'http', 'url':'http://127.0.0.1:8000/health'}])
            target = omni.Target(work, app)
            assert target.db_container == TARGET and target.db_volume == TARGETVOL
            revision = json.loads(runner.podman('exec', TARGET, 'psql', '-X', '-A', '-t', '-U', 'postgres',
                '-d', 'omnigent', '-c', omni.ALEMBIC_SQL).stdout)
            if not revision:
                raise RuntimeError('application_alembic_missing')
            # Exercise actual holder failure and malformed metadata, not a fake runner.
            for label, replacement in (
                ('statement_timeout', omni.SNAPSHOT_SCRIPT.replace('SELECT pg_export_snapshot();',
                    "SET LOCAL statement_timeout = '1s'; SELECT pg_sleep(3); SELECT pg_export_snapshot();")),
                ('invalid_metadata', omni.SNAPSHOT_SCRIPT.replace('__COLUMNS__', "SELECT 'invalid-json'")),
            ):
                output = root / ('failure-' + label)
                try:
                    with mock.patch.object(omni, 'SNAPSHOT_SCRIPT', replacement):
                        omni.capture_consistent_target_schema(work, app, target, output, revision)
                except Exception as exc:
                    from woowbackup.errors import BackupError
                    assert isinstance(exc, BackupError)
                else:
                    raise AssertionError(label + '_accepted')
                assert not output.exists() and not output.with_name(output.name + '.capture').exists()
                active = runner.podman('exec', TARGET, 'psql', '-X', '-A', '-t', '-U', 'postgres', '-d',
                    'omnigent', '-c', "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'woowbk-schema-snapshot'").stdout.strip()
                assert active == b'0'
                event('snapshot_failure', kind=label, capture_removed=True, holders=0)
            out = root / 'out'
            out.mkdir()
            event('candidate_started')
            # Target server is stopped to guarantee schema DDL quiescence; this fixture
            # replays only its previously captured authenticated-free /v1/info response.
            info_payload = json.dumps(target_info['body']).encode()
            with mock.patch('woowbackup.adapters.quadlet_postgres.loopback_get', return_value=(200, info_payload)):
                converted = omni._convert_candidate(work, app, True, out, schema_ddl_quiesced=True)
            assert converted['kept_accounts'] == ['target-admin']
            assert all(path.exists() and path.stat().st_size > 0 for path in converted['volumes'].values())
            with tarfile.open(addon) as tar:
                source_cookie = tar.extractfile('data/omnigent-home/.omnigent/artifacts/accounts-cookie-secret').read()
            with tarfile.open(converted['volumes'][SERVERVOL]) as tar:
                assert source_cookie == source_cookie_registered
                assert source_cookie and tar.extractfile('artifacts/accounts-cookie-secret').read() == source_cookie
            with tarfile.open(converted['volumes'][PIVOL]) as tar:
                assert tar.extractfile('auth.json').read() == b'synthetic-pi'
            with tarfile.open(converted['volumes'][TARGETVOL]) as tar:
                assert any(m.name.removeprefix('./') == 'PG_VERSION' for m in tar)
            with open(converted['volumes'][TARGETVOL], 'rb') as handle:
                runner.podman('volume', 'import', RESTOREDVOL, '-', input=handle, timeout=300)
            start(RESTORED, RESTOREDVOL)
            with open(converted['volumes'][SERVERVOL], 'rb') as handle:
                runner.podman('volume', 'import', RESTORED_APPVOL, '-', input=handle, timeout=300)
            start_app(RESTORED_APP, RESTORED, RESTORED_APPVOL, SOURCE_SECRET, 'source-admin')
            assert cookie_from_container(runner, RESTORED_APP) == source_cookie_registered
            observed_cookies.append('restored_cookie')
            source_new_token = login_registered(RESTORED_APP, 'source-admin', source_password, 'restored_source_login', observed_sources)
            login_registered(RESTORED_APP, 'target-admin', target_password, 'restored_target_login', observed_sources)
            prior = api(RESTORED_APP, {'method':'GET', 'path':'/auth/me', 'body':None, 'token':source_token})
            current = api(RESTORED_APP, {'method':'GET', 'path':'/auth/me', 'body':None, 'token':source_new_token})
            invalid = api(RESTORED_APP, {'method':'GET', 'path':'/auth/me', 'body':None, 'token':'invalid-synthetic-token'})
            prior_user = prior.get('body', {}).get('user', prior.get('body', {}))
            current_user = current.get('body', {}).get('user', current.get('body', {}))
            assert prior.get('status') == 200 and current.get('status') == 200
            assert isinstance(prior_user, dict) and isinstance(current_user, dict)
            assert prior_user.get('id') == current_user.get('id') == source_id
            assert invalid.get('status') in (401, 403)
            restored_marker = api(RESTORED_APP, {'method':'GET', 'path':'/v1/sessions/' + marker_id,
                                                'body':None, 'token':source_new_token})
            if restored_marker.get('status') != 200 or restored_marker.get('body', {}).get('title') != marker_title:
                raise RuntimeError('synthetic_session_restore_failed')
            collect_logs(RESTORED_APP)
            expected_sources = [prefix + '.' + field for prefix in
                ('source_login', 'target_login', 'restored_source_login', 'restored_target_login')
                for field in ('token', 'refresh_token')]
            if observed_sources != expected_sources or observed_cookies != ['source_cookie', 'target_cookie', 'restored_cookie']:
                raise RuntimeError('credential_source_list_incomplete')
            private = private_scan([source_app, target_app_export, cold, addon, outer,
                                    converted['volumes'][SERVERVOL], converted['volumes'][TARGETVOL],
                                    converted['volumes'][PIVOL]],
                                   scan_needles(SECRET_VALUES))
            if (private['matches'] == 0 or not file_contains(source_app, source_cookie_registered)
                    or not file_contains(target_app_export, target_cookie_registered)):
                raise RuntimeError('private_cookie_source_scan_failed')
            needles = scan_needles(SECRET_VALUES)
            if any(value in line for value in needles for line in EVENT_RECORDS):
                raise RuntimeError('sensitive_evidence_suppressed')
            if len(app_logs) != 3 or any(value in data for value in needles for data in app_logs if data is not None):
                raise RuntimeError('sensitive_log_suppressed')
            event('credential_coverage', credential_sources=expected_sources, cookie_sources=observed_cookies,
                  private_files_scanned=private['files'], evidence_scan_hits=0, readable_log_hits=0,
                  app_log_reads_available=sum(data is not None for data in app_logs), app_log_driver='none')
            event('restored_session_marker', same_id_and_title=True)
            event('restored_real_app', health=True, source_login=True, target_login=True,
                  previous_token_same_user=True, invalid_token_denied=True, cookie_bytes_match=True)
            event('cold_ha_to_candidate', actual_app_schema=True, real_member_pass=True, real_ha_cluster=True,
                  real_provider=True, real_new_cluster=True, real_output_volumes=True, carried_account=True)
    finally:
        for backup in open_backups:
            backup.close()
        leftovers = tmp.cleanup()
        for name in reversed(containers):
            runner.podman('rm', '--force', '--time', '10', name, check=False)
        for name in reversed(secrets_created):
            runner.podman('secret', 'rm', name, check=False)
        for name in reversed(created_volumes):
            runner.podman('volume', 'rm', '--force', name, check=False)
        remaining = any(runner.podman('container', 'exists', n, check=False).returncode != 1 for n in (SOURCE, TARGET, RESTORED, SOURCE_APP, TARGET_APP, RESTORED_APP))
        remaining |= any(runner.podman('volume', 'exists', n, check=False).returncode != 1 for n in created_volumes)
        remaining |= any(runner.podman('secret', 'exists', n, check=False).returncode != 1 for n in secrets_created)
        event('cleanup', synthetic_objects_removed=not leftovers and not remaining)
        if leftovers or remaining:
            raise RuntimeError('cleanup_incomplete')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        import traceback
        frames = [{'file': Path(f.filename).name, 'line': f.lineno, 'function': f.name}
                  for f in traceback.extract_tb(exc.__traceback__)]
        event('failed', error_type=type(exc).__name__, code=getattr(exc, 'code', None), frames=frames)
        sys.exit(1)
