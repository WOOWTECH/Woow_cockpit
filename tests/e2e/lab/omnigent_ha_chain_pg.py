#!/usr/bin/env python3
"""Real synthetic cold HA PostgreSQL -> candidate -> Podman volume tar; opt-in dev-d only."""
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

IMAGE = '4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873'
OWNER = ROOT / 'tests/e2e/lab/owner.sh'
LAB = Path.home() / '.woowbk-lab/bin/labpodman'
PREFIX = 'woowbk-omni-chain-' + secrets.token_hex(5)
SOURCE, TARGET, RESTORED = PREFIX + '-source', PREFIX + '-target', PREFIX + '-restored'
RESTOREDVOL = PREFIX + '-restoredpg'
PGVOL, TARGETVOL, SERVERVOL, PIVOL = [PREFIX + x for x in ('-pg', '-targetpg', '-server', '-pi')]


def event(stage, **values):
    print(json.dumps({'stage': stage, **values}, sort_keys=True), flush=True)


from omnigent_lab_runner import Runner, require_names_absent

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


def build_addon(cold, path):
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
        for name in ('data/omnigent-home', 'data/omnigent-home/.omnigent', 'data/omnigent-home/.omnigent/artifacts'):
            add(out, name, kind='dir')
        add(out, 'data/omnigent-home/.omnigent/artifacts/accounts-cookie-secret', b'synthetic-cookie', mode=0o600)


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
    assert runner.podman('image', 'inspect', '--format', '{{.Id}}', IMAGE).stdout.decode().strip().removeprefix('sha256:') == IMAGE
    event('preflight', image_id=IMAGE, outer_network='none', max_pg_containers=2, each_memory_mib=128)
    created_volumes, containers = [], []
    tmp = tempctr.TempObjects(runner, 'j20261120T120000Z-' + secrets.token_hex(4), memory='128m', pids=96, cpus=None)
    require_names_absent(runner, (
        ('container', (SOURCE, TARGET, RESTORED, *(tmp.name(role) for role in ('ids-pg', 'hapg', 'omni-db', 'controldata')))),
        ('volume', (PGVOL, TARGETVOL, SERVERVOL, PIVOL, RESTOREDVOL, *(tmp.name(role) for role in ('hapg', 'omni-db')))),
    ))
    try:
        for volume in (PGVOL, TARGETVOL, SERVERVOL, PIVOL, RESTOREDVOL):
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
        start(SOURCE, PGVOL)
        event('source_started')
        definitions = {
            'users': 'id text PRIMARY KEY, password_hash text, deleted_at timestamptz, is_admin boolean',
            'scheduled_tasks': 'id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, state integer',
            'agents': 'id integer PRIMARY KEY, bundle_location text', 'files':'id bytea PRIMARY KEY, blob_key bytea',
            'session_permissions':'id integer PRIMARY KEY, conversation_id text, user_id text',
            'connections':'id integer PRIMARY KEY, secret_enc text'}
        statements = ['CREATE TABLE alembic_version(version_num text NOT NULL);',
                      "INSERT INTO alembic_version VALUES ('same_revision');"]
        for table in omni.TABLES:
            statements.append(f'CREATE TABLE "{table}" ({definitions.get(table, "id integer PRIMARY KEY")});')
        statements.extend(["INSERT INTO users(id,password_hash,is_admin) VALUES ('alice','synthetic',true);",
                           'INSERT INTO scheduled_tasks(state) VALUES (1);', 'INSERT INTO conversations VALUES (1);'])
        sql(SOURCE, '\n'.join(statements))
        runner.podman('stop', '--time', '30', SOURCE)
        runner.podman('rm', SOURCE)
        containers.remove(SOURCE)
        event('source_cold')
        with tempfile.TemporaryDirectory(prefix='woowbk-omni-chain-') as d:
            root = Path(d)
            cold, addon = root / 'cold.tar', root / 'addon.tar'
            with cold.open('wb') as handle:
                runner.relay(['volume', 'export', PGVOL], stdout=handle, timeout=300)
            build_addon(cold, addon)
            event('addon_tar_built')
            with cold.open('rb') as handle:
                runner.podman('volume', 'import', TARGETVOL, '-', input=handle, timeout=300)
            with small_volume([('artifacts', None), ('artifacts/old', b'old'), ('sharing_mode', b'off')]) as handle:
                runner.podman('volume', 'import', SERVERVOL, '-', input=handle)
            with small_volume([('auth.json', b'synthetic-pi')]) as handle:
                runner.podman('volume', 'import', PIVOL, '-', input=handle)
            start(TARGET, TARGETVOL)
            event('target_started')
            sql(TARGET, "INSERT INTO users(id,password_hash,is_admin) VALUES ('admin','synthetic-admin',true);")
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
                  db_secrets=[], db_user='postgres', db_container=TARGET, database='omnigent', own_users=['admin'],
                  db_volume=TARGETVOL, server_volume=SERVERVOL, pi_volume=PIVOL)
            # Exercise actual holder failure and malformed metadata, not a fake runner.
            for label, replacement in (
                ('statement_timeout', omni.SNAPSHOT_SCRIPT.replace('SELECT pg_export_snapshot();',
                    "SET LOCAL statement_timeout = '1s'; SELECT pg_sleep(3); SELECT pg_export_snapshot();")),
                ('invalid_metadata', omni.SNAPSHOT_SCRIPT.replace('__COLUMNS__', "SELECT 'invalid-json'")),
            ):
                output = root / ('failure-' + label)
                try:
                    with mock.patch.object(omni, 'SNAPSHOT_SCRIPT', replacement):
                        omni.capture_consistent_target_schema(work, app, target, output, ['same_revision'])
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
            with mock.patch.object(omni, '_prepare', return_value=(target, '0.21.0', ['same_revision'], None, None)):
                converted = omni._convert_candidate(work, app, True, out, schema_ddl_quiesced=True)
            assert converted['kept_accounts'] == ['admin'] and converted['paused_tasks'] == 1
            assert all(path.exists() and path.stat().st_size > 0 for path in converted['volumes'].values())
            with tarfile.open(converted['volumes'][SERVERVOL]) as tar:
                assert tar.extractfile('artifacts/accounts-cookie-secret').read() == b'synthetic-cookie'
            with tarfile.open(converted['volumes'][PIVOL]) as tar:
                assert tar.extractfile('auth.json').read() == b'synthetic-pi'
            with tarfile.open(converted['volumes'][TARGETVOL]) as tar:
                assert any(m.name.removeprefix('./') == 'PG_VERSION' for m in tar)
            with open(converted['volumes'][TARGETVOL], 'rb') as handle:
                runner.podman('volume', 'import', RESTOREDVOL, '-', input=handle, timeout=300)
            start(RESTORED, RESTOREDVOL)
            readback = runner.podman('exec', RESTORED, 'psql', '-X', '-A', '-t', '-U', 'postgres',
                '-d', 'omnigent', '-c', """SELECT json_build_object('users',(SELECT count(*) FROM users),
                'admin',(SELECT count(*) FROM users WHERE id='admin'),
                'conversations',(SELECT count(*) FROM conversations),
                'active_tasks',(SELECT count(*) FROM scheduled_tasks WHERE state=1),
                'loader',(SELECT count(*) FROM pg_roles WHERE rolname='woowbk_restore'))""").stdout
            assert json.loads(readback) == {'users':2,'admin':1,'conversations':1,'active_tasks':0,'loader':0}
            event('installed_postgres_readback', users=2, admin=1, conversations=1, active_tasks=0, loader_roles=0)
            runner.podman('restart', RESTORED)
            for _ in range(30):
                if runner.podman('exec', RESTORED, 'pg_isready', '-q', '-h', '127.0.0.1', '-U', 'postgres', check=False).returncode == 0:
                    break
                time.sleep(1)
            sql(RESTORED, "DO $$ BEGIN IF (SELECT count(*) FROM users) != 2 THEN RAISE EXCEPTION 'count'; END IF; END $$;")
            event('installed_postgres_restart', persisted=True)
            event('cold_ha_to_candidate', real_member_pass=True, real_ha_cluster=True, real_provider=True,
                  real_new_cluster=True, real_output_volumes=True, carried_account=True, paused_task=True)
    finally:
        leftovers = tmp.cleanup()
        for name in reversed(containers):
            runner.podman('rm', '--force', '--time', '10', name, check=False)
        for name in reversed(created_volumes):
            runner.podman('volume', 'rm', '--force', name, check=False)
        remaining = any(runner.podman('container', 'exists', n, check=False).returncode != 1 for n in (SOURCE, TARGET, RESTORED))
        remaining |= any(runner.podman('volume', 'exists', n, check=False).returncode != 1 for n in created_volumes)
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
