#!/usr/bin/env python3
"""Opt-in dev-d synthetic PostgreSQL probe, including O-15's extra superuser-only objects.
Never uses live volumes or secrets. The archive is generated in real PostgreSQL, not from an HA backup.

Run: python3 tests/e2e/lab/omnigent_trusted_pg.py --run
Outputs only fixed stage names, booleans and the image ID; never SQL/data/stderr.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'backup-engine'))
from woowbackup import ha_odoo, ha_omnigent as omni
from woowbackup.errors import BackupError

IMAGE = '4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873'
LAB = Path.home() / '.woowbk-lab/bin/labpodman'
OWNER = ROOT / 'tests/e2e/lab/owner.sh'
NAME = 'woowbk-omni-synthetic-' + secrets.token_hex(6)


def event(stage, **fields):
    print(json.dumps({'stage': stage, **fields}, sort_keys=True), flush=True)


class SyntheticCommandError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__('synthetic_command_failed')


def call(argv, *, data=None, accept=False, timeout=120):
    proc = subprocess.run([str(OWNER), 'd', 'podman', *argv], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if proc.returncode and not accept:
        raise SyntheticCommandError(proc.returncode)
    return proc


def inside(argv, data=None, accept=False):
    return call(['exec', '-i', '--user', 'postgres', NAME, *argv], data=data, accept=accept)


def sql(db, text):
    return inside(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'omnigent', '-d', db, '-f', '-'], text.encode())


class Tmp:
    def exec(self, role, argv, **kwargs):
        incoming = kwargs.get('input')
        if hasattr(incoming, 'read'):
            incoming = incoming.read()
        out = inside(argv, incoming)
        return SimpleNamespace(stdout=out.stdout, returncode=out.returncode)


def full_candidate_pg_probe(directory, work, app, target):
    """Exercise the full candidate with real PG; volume/HA analysis adapters are synthetic."""
    from contextlib import ExitStack
    from unittest import mock

    class CandidateTmp:
        def volume(self, role): pass
        def volume_import(self, role, produce): pass
        def remove(self, role): pass
        def remove_volume(self, role): pass
        def name(self, role): return 'synthetic-' + role
        def user_ids(self, role, image, name): return (70, 70)
        def stop(self, role, timeout=300): return 0
        def volume_export(self, role, handle, **kwargs): handle.write(b'synthetic-volume')
        def run(self, role, image, args=(), **kwargs):
            return SimpleNamespace(stdout=b'Database cluster state: shut down\n' if role == 'controldata' else b'')
        def exec(self, role, argv, **kwargs):
            argv = list(argv)
            # Both roles are databases in the same dedicated synthetic container.
            if role == 'hapg':
                if '-d' in argv and argv[argv.index('-d') + 1] == 'candidate_dest':
                    argv[argv.index('-d') + 1] = 'source'
                if '-U' in argv and argv[argv.index('-U') + 1] == 'postgres':
                    argv[argv.index('-U') + 1] = 'omnigent'
            incoming = kwargs.get('input')
            if hasattr(incoming, 'read'):
                incoming = incoming.read()
            result = inside(argv, incoming)
            if kwargs.get('stdout') is not None:
                kwargs['stdout'].write(result.stdout)
                return SimpleNamespace(stdout=None, returncode=0)
            return SimpleNamespace(stdout=result.stdout, returncode=0)

    class CandidateRunner:
        def podman(self, *args, **kwargs):
            args = list(args)
            # Only the trusted synthetic DB substitutes for the live target.
            if args[0:2] == ['exec', '-i'] and args[-1] == 'candidate_dest':
                args[-1] = 'trusted'
            result = call(args, data=kwargs.get('input'))
            if kwargs.get('stdout') is not None:
                kwargs['stdout'].write(result.stdout)
            return result

    tmp = CandidateTmp()
    candidate_work = SimpleNamespace(
        runner=lambda app: CandidateRunner(), temp=lambda app: tmp,
        adapter=lambda app: SimpleNamespace(owner_ids=lambda: None),
        guard=SimpleNamespace(budget=lambda: 128 * 1024 * 1024, check=lambda n: None, wrote=lambda n: None),
        staging=directory / 'candidate-staging', abort=lambda: None, checkpoint=lambda: None,
        phase=lambda phase: None, log=lambda message: None)
    candidate_work.staging.mkdir()
    target.db_image = IMAGE
    target.db_target = '/var/lib/postgresql/data'
    target.pgdata = '/var/lib/postgresql/data'
    target.db_env = {}
    target.db_secrets = []
    target.db_volume = 'synthetic-postgres'
    target.pi_volume = 'synthetic-pi'
    target.server_volume = 'synthetic-server'
    target.own_users = ['admin']
    src = omni.Source()
    src.pg_version = '16'
    src.cookie = True
    found = {'objects': {'extensions': ['plpgsql']}, 'tables': ['users', 'scheduled_tasks', 'alembic_version'],
             'alembic': ['same_revision'], 'detail': {'users': 1, 'user_ids': ['alice'],
                  'scheduled_tasks_active': 1}, 'counts': {'users': 1, 'scheduled_tasks': 1, 'alembic_version': 1},
             'keys': {}, 'superuser': []}
    def server_volume(work, app, target, staging, out_dir):
        path = out_dir / 'volumes' / 'synthetic-server.tar'
        path.write_bytes(b'synthetic-server')
        return path
    def live_export(work, app, volume, path):
        path.write_bytes(b'synthetic-pi')
        return path
    out = directory / 'candidate-output'
    out.mkdir()
    inside(['createdb', '-U', 'omnigent', 'candidate_dest'])
    original_db = omni.DATABASE
    omni.DATABASE = 'candidate_dest'
    try:
        with ExitStack() as patches:
            patches.enter_context(mock.patch.object(omni, '_prepare', return_value=(target, '0.21.0', ['same_revision'], None, None)))
            patches.enter_context(mock.patch.object(omni, 'member_pass', return_value=src))
            patches.enter_context(mock.patch.object(ha_odoo, 'start_ha_cluster', return_value=ha_odoo.Cluster(tmp, 'hapg', superuser='omnigent')))
            patches.enter_context(mock.patch.object(omni, 'analyse', return_value=found))
            patches.enter_context(mock.patch.object(omni, 'verdict', return_value=([], [])))
            patches.enter_context(mock.patch.object(ha_odoo, 'target_pg_major', return_value=16))
            patches.enter_context(mock.patch.object(omni, 'live_users', return_value=[{'id':'admin', 'password_hash':'synthetic'}]))
            patches.enter_context(mock.patch.object(omni, 'server_volume', side_effect=server_volume))
            patches.enter_context(mock.patch.object(omni.hacommon, 'live_export', side_effect=live_export))
            patches.enter_context(mock.patch.object(ha_odoo, 'check_volume_tar'))
            result = omni._convert_candidate(candidate_work, app, True, out, schema_ddl_quiesced=True)
        assert result['kept_accounts'] == ['admin'] and result['paused_tasks'] == 1
        assert len(result['volumes']) == 3
        assert sql('candidate_dest', "SELECT 1 / CASE WHEN count(*) = 2 THEN 1 ELSE 0 END FROM users;").returncode == 0
        event('candidate_real_pg', complete=True, source_analysis_fixture=True, volume_adapters_fixture=True,
              real_snapshot_and_restore=True, accounts_and_pause=True)
    finally:
        omni.DATABASE = original_db


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', action='store_true')
    if not parser.parse_args().run:
        parser.error('explicit --run required')
    info = subprocess.run([str(LAB), 'inspect', '--format', '{{.State.Status}} {{.HostConfig.NetworkMode}} {{json .NetworkSettings.Ports}}',
                           'woowbk-dev-d'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout.strip()
    if info != b'running none {}':
        raise RuntimeError('dev_d_not_isolated')
    inspected = call(['image', 'inspect', '--format', '{{.Id}}', IMAGE]).stdout.decode().strip()
    if inspected.removeprefix('sha256:') != IMAGE:
        raise RuntimeError('image_id_mismatch')
    event('preflight', outer_network='none', published_ports=0, image_id=IMAGE)
    created = False
    try:
        call(['run', '-d', '--name', NAME, '--network', 'none', '--pull=never', '--read-only',
              '--memory', '256m', '--pids-limit', '96',
              '--tmpfs', '/var/lib/postgresql/data:rw,noexec,nosuid,nodev',
              '--tmpfs', '/run/postgresql:rw,nosuid,nodev', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev',
              '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'POSTGRES_USER=omnigent',
              '-e', 'POSTGRES_DB=omnigent', IMAGE])
        created = True
        for _ in range(45):
            if inside(['pg_isready', '-q', '-U', 'omnigent'], accept=True).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('postgres_not_ready')
        for db in ('trusted', 'source', 'bad_dest'):
            inside(['createdb', '-U', 'omnigent', db])
        schema = '''CREATE TABLE users (id text PRIMARY KEY, password_hash text);
CREATE TABLE scheduled_tasks (id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, state integer NOT NULL);
CREATE TABLE task_child (id integer PRIMARY KEY, task_id integer REFERENCES scheduled_tasks(id));
CREATE TABLE alembic_version (version_num text NOT NULL);'''
        for db in ('trusted', 'source'):
            sql(db, schema)
        sql('trusted', "INSERT INTO alembic_version VALUES ('same_revision');")
        sql('source', """INSERT INTO users VALUES ('alice','synthetic');
INSERT INTO scheduled_tasks(state) VALUES (1); INSERT INTO task_child VALUES (9,1);
INSERT INTO alembic_version VALUES ('same_revision');
ALTER TABLE users ADD CONSTRAINT evil CHECK (id <> 'admin' OR
 lo_export(lo_from_bytea(0,decode('70776e6564','hex')), '/tmp/woowbk-pwned') > 0) NOT VALID;""")
        sql('source', """CREATE FUNCTION public.woowbk_extra_event_fn() RETURNS event_trigger
 LANGUAGE plpgsql AS $$ BEGIN NULL; END $$;
CREATE EVENT TRIGGER woowbk_extra_event ON ddl_command_start
 EXECUTE FUNCTION public.woowbk_extra_event_fn();
CREATE FOREIGN DATA WRAPPER woowbk_extra_fdw;""")
        tmp = Tmp()
        class Runner:
            def podman(self, *args, **kwargs):
                result = call(list(args), data=kwargs.get('input'))
                output = kwargs.get('stdout')
                if output is not None:
                    output.write(result.stdout)
                return result
        work = SimpleNamespace(log=lambda message: None, runner=lambda app: Runner(),
                               guard=SimpleNamespace(budget=lambda: 128 * 1024 * 1024, check=lambda n: None), abort=lambda: None)
        app = SimpleNamespace(id='synthetic-omnigent')
        target = SimpleNamespace(db_container=NAME, db_user='omnigent')
        source = ha_odoo.Cluster(tmp, 'source', superuser='omnigent')
        original_db = omni.DATABASE
        with tempfile.TemporaryDirectory(prefix='woowbk-omni-pg-') as directory:
            directory = Path(directory)
            schema_path, data_path = directory / 'schema', directory / 'data'
            omni.DATABASE = 'trusted'
            target_columns = omni.capture_consistent_target_schema(work, app, target, schema_path, ['same_revision'])
            assert schema_path.read_bytes().startswith(b'PGDMP')
            try:
                omni.capture_consistent_target_schema(work, app, target, directory / 'wrong', ['wrong_revision'])
            except SyntheticCommandError as exc:
                assert exc.code == 22
                assert not (directory / 'wrong').exists()
            else:
                raise AssertionError('wrong_revision_accepted')
            event('snapshot_provider', schema_archive=True, revision_mismatch_rejected=True)
            # Hold the same snapshot open while a concurrent ALTER is attempted.
            import threading
            from unittest import mock
            attempts = []
            def concurrent_ddl():
                time.sleep(2)
                attempts.append(inside(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'omnigent',
                    '-d', 'trusted', '-c', "SET lock_timeout='1s'; ALTER TABLE alembic_version ADD COLUMN blocked integer"],
                    accept=True).returncode)
            worker = threading.Thread(target=concurrent_ddl)
            delayed = omni.SNAPSHOT_SCRIPT.replace('snapshot=$(cat', 'sleep 12\nsnapshot=$(cat')
            worker.start()
            with mock.patch.object(omni, 'SNAPSHOT_SCRIPT', delayed):
                held = omni.capture_consistent_target_schema(work, app, target, directory / 'held-schema', ['same_revision'])
            worker.join(timeout=20)
            assert not worker.is_alive() and attempts and attempts[0] != 0 and held == target_columns
            event('snapshot_lock', concurrent_alembic_ddl_blocked=True, dump_completed=True)
            data_path.write_bytes(inside(['pg_dump', '-U', 'omnigent', '-Fc', '-d', 'source']).stdout)
            listing = inside(['pg_restore', '-l'], data_path.read_bytes()).stdout.decode('utf-8', 'surrogateescape')
            kinds = omni.toc_kinds(listing)
            assert {'EVENT TRIGGER', 'FOREIGN DATA WRAPPER'} <= set(kinds)
            selected = omni.data_only_toc(listing, tables={'users', 'scheduled_tasks', 'task_child', 'alembic_version'},
                                          sequences={'scheduled_tasks_id_seq'})
            assert 'EVENT TRIGGER' not in selected and 'FOREIGN DATA WRAPPER' not in selected
            event('superuser_toc', real_pg_archive=True, event_trigger=True, foreign_data_wrapper=True,
                  selected_only_data=True)
            # Cluster uses DATABASE for queries; point it at source while collecting the signature.
            omni.DATABASE = 'source'
            columns = omni.schema_columns(source)
            omni.DATABASE = original_db
            assert columns == target_columns
            pg = omni.restore_trusted_data(work, tmp, schema_path, data_path, 'omnigent', source_columns=columns)
            assert omni.carry_accounts_restricted(pg, [{'id': 'admin', 'password_hash': 'synthetic'}]) == ['admin']
            ha_odoo.Cluster(tmp, 'omni-db', superuser=omni.RESTORE_ROLE).script(omni.PAUSE_SQL, 'omnigent')
            omni.finish_trusted_data(pg)
            output = pg.query_json("SELECT json_build_array((SELECT count(*) FROM users), "
                                   "(SELECT count(*) FROM users WHERE id='admin'), "
                                   "(SELECT count(*) FROM scheduled_tasks WHERE state=1), "
                                   "(SELECT count(*) FROM task_child), "
                                   "(SELECT count(*) FROM pg_constraint WHERE conname='evil'), "
                                   "(SELECT count(*) FROM pg_roles WHERE rolname='woowbk_restore'), "
                                   "nextval(pg_get_serial_sequence('scheduled_tasks','id')), "
                                   "(SELECT count(*) FROM pg_event_trigger WHERE evtname='woowbk_extra_event'), "
                                   "(SELECT count(*) FROM pg_foreign_data_wrapper WHERE fdwname='woowbk_extra_fdw'))", 'omnigent')
            assert output == [2, 1, 0, 1, 0, 0, 2, 0, 0]
            assert inside(['test', '!', '-e', '/tmp/woowbk-pwned'], accept=True).returncode == 0
            event('malicious_check', rejected=True, marker_absent=True, data_and_sequence_valid=True,
                  carried_account_valid=True, loader_removed=True, superuser_objects_absent=True)
            full_candidate_pg_probe(directory, work, app, target)
            # The revision remains equal: only the source columns are changed.
            for db in ('trusted', 'source'):
                revision = inside(['psql', '-X', '-A', '-t', '-U', 'omnigent', '-d', db,
                                   '-c', 'SELECT version_num FROM alembic_version']).stdout.strip()
                assert revision == b'same_revision'
            sql('source', 'ALTER TABLE users ADD COLUMN extra integer DEFAULT 123;')
            data_path.write_bytes(inside(['pg_dump', '-U', 'omnigent', '-Fc', '-d', 'source']).stdout)
            omni.DATABASE = 'source'
            altered = omni.schema_columns(source)
            omni.DATABASE = 'bad_dest'
            try:
                omni.restore_trusted_data(work, tmp, schema_path, data_path, 'omnigent', source_columns=altered)
            except BackupError as exc:
                assert exc.code == 'incompatible' and '欄位結構不同' in exc.message
            else:
                raise AssertionError('mismatched_columns_accepted')
            out = sql('bad_dest', "SELECT 1 / CASE WHEN count(*) = 0 THEN 1 ELSE 0 END FROM users;")
            assert out.returncode == 0
            event('same_revision_column_mismatch', rejected_before_data=True, users_empty=True)
            omni.DATABASE = original_db
    finally:
        if created:
            call(['rm', '--force', NAME])
            gone = call(['container', 'exists', NAME], accept=True).returncode == 1
            event('cleanup', synthetic_container_removed=gone)
            if not gone:
                raise RuntimeError('synthetic_cleanup_failed')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        event('failed', error_type=type(exc).__name__)
        sys.exit(1)
