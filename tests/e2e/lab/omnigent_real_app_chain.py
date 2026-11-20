#!/usr/bin/env python3
"""Real Omnigent bootstrap -> cold HA -> candidate -> restored app; isolated dev-d only."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'backup-engine'))
from woowbackup import ha_omnigent as omni, tempctr, nested
from woowbackup.podman import CommandError

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


def event(stage, **values):
    print(json.dumps({'stage': stage, **values}, sort_keys=True), flush=True)


from omnigent_lab_runner import Runner

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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', action='store_true')
    if not parser.parse_args().run:
        parser.error('explicit --run required')
    result = subprocess.run([str(LAB), 'inspect', '--format', '{{.State.Status}} {{.HostConfig.NetworkMode}} {{json .NetworkSettings.Ports}}',
                            'woowbk-dev-d'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    if result.stdout.strip() != b'running none {}':
        raise RuntimeError('dev_d_not_isolated')
    runner = Runner()
    for image in (IMAGE, APP_IMAGE):
        assert runner.podman('image', 'inspect', '--format', '{{.Id}}', image).stdout.decode().strip().removeprefix('sha256:') == image
    memory = subprocess.run([str(LAB), 'exec', 'woowbk-dev-d', 'sh', '-c',
        'cat /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.max'], capture_output=True, check=True).stdout.split()
    if len(memory) != 2 or int(memory[1]) - int(memory[0]) < 1400 * 1024 * 1024:
        raise RuntimeError('insufficient_isolated_lab_memory')
    event('preflight', image_id=IMAGE, outer_network='none', max_pg_containers=2, each_memory_mib=128)
    created_volumes, containers, secrets_created = [], [], []
    source_password = secrets.token_urlsafe(32)
    target_password = secrets.token_urlsafe(32)
    tmp = tempctr.TempObjects(runner, 'j20261120T120000Z-' + secrets.token_hex(4), memory='128m', pids=96, cpus=None)
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
        def login(name, username, password):
            result = api(name, {'method':'POST', 'path':'/auth/login',
                                'body':{'username':username, 'password':password, 'issue_refresh':True}})
            if result.get('status') != 200 or not result.get('body', {}).get('token'):
                raise RuntimeError('synthetic_login_failed')
            return result['body']['token']
        start(SOURCE, PGVOL)
        start_app(SOURCE_APP, SOURCE, SOURCE_APPVOL, SOURCE_SECRET, 'source-admin')
        source_token = login(SOURCE_APP, 'source-admin', source_password)
        event('real_source_bootstrap', app_image=APP_IMAGE, login=True)
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
            with cold.open('wb') as handle:
                runner.relay(['volume', 'export', PGVOL], stdout=handle, timeout=300)
            with source_app.open('wb') as handle:
                runner.relay(['volume', 'export', SOURCE_APPVOL], stdout=handle, timeout=300)
            build_addon(cold, addon, source_app)
            event('addon_tar_built')
            with small_volume([('artifacts', None), ('artifacts/old', b'old'), ('sharing_mode', b'off')]) as handle:
                runner.podman('volume', 'import', SERVERVOL, '-', input=handle)
            with small_volume([('auth.json', b'synthetic-pi')]) as handle:
                runner.podman('volume', 'import', PIVOL, '-', input=handle)
            start(TARGET, TARGETVOL)
            event('target_started')
            # The target schema and account are created independently by the real image.
            start_app(TARGET_APP, TARGET, SERVERVOL, TARGET_SECRET, 'target-admin')
            login(TARGET_APP, 'target-admin', target_password)
            runner.podman('stop', '--time', '30', TARGET_APP)
            runner.podman('rm', TARGET_APP)
            containers.remove(TARGET_APP)
            event('real_target_bootstrap', independently_initialized=True, login=True)
            guard = SimpleNamespace(check=lambda n: None, budget=lambda: 512 * 1024 * 1024, wrote=lambda n: None)
            ids = tuple(nested.IdMap(runner.podman('unshare', 'cat', '/proc/self/' + kind + '_map').stdout.decode())
                        for kind in ('uid', 'gid'))
            adapter = SimpleNamespace(owner_ids=lambda: ids, image_inspect=lambda image: {'env':['PG_MAJOR=16']})
            work = SimpleNamespace(adapter=lambda app: adapter, temp=lambda app: tmp, runner=lambda app: runner,
                  guard=guard, staging=root / 'staging', abort=lambda: None, checkpoint=lambda: None,
                  phase=lambda phase: None, log=lambda msg: None, addon_member=lambda slug: addon,
                  open=lambda member: member.open('rb'))
            work.staging.mkdir()
            app = SimpleNamespace(id='omnigent', name='Synthetic', owner='appowner')
            target = SimpleNamespace(db_image=IMAGE, db_target='/var/lib/postgresql/data', pgdata='/var/lib/postgresql/data',
                  db_env={'POSTGRES_USER':'postgres', 'POSTGRES_DB':'omnigent', 'POSTGRES_HOST_AUTH_METHOD':'trust'},
                  db_secrets=[], db_user='postgres', db_container=TARGET, database='omnigent', own_users=['target-admin'],
                  db_volume=TARGETVOL, server_volume=SERVERVOL, pi_volume=PIVOL)
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
            with mock.patch.object(omni, '_prepare', return_value=(target, '0.21.0', revision, None, None)):
                converted = omni._convert_candidate(work, app, True, out, schema_ddl_quiesced=True)
            assert converted['kept_accounts'] == ['target-admin']
            assert all(path.exists() and path.stat().st_size > 0 for path in converted['volumes'].values())
            with tarfile.open(converted['volumes'][SERVERVOL]) as tar:
                assert tar.extractfile('artifacts/accounts-cookie-secret').read()
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
            source_new_token = login(RESTORED_APP, 'source-admin', source_password)
            login(RESTORED_APP, 'target-admin', target_password)
            prior = api(RESTORED_APP, {'method':'GET', 'path':'/auth/me', 'body':None, 'token':source_token})
            current = api(RESTORED_APP, {'method':'GET', 'path':'/auth/me', 'body':None, 'token':source_new_token})
            assert prior.get('status') == 200 and current.get('status') == 200
            event('restored_real_app', health=True, source_login=True, target_login=True, previous_token_valid=True)
            event('cold_ha_to_candidate', actual_app_schema=True, real_member_pass=True, real_ha_cluster=True,
                  real_provider=True, real_new_cluster=True, real_output_volumes=True, carried_account=True)
    finally:
        leftovers = tmp.cleanup()
        for name in reversed(containers):
            runner.podman('rm', '--force', '--time', '10', name, check=False)
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
