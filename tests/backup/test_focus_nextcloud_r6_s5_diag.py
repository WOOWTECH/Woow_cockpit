"""Offline tests of the S5 check-PostgreSQL diagnosis (focus_nextcloud_r6_s5_diag). No lab, device or host podman.

The product is THIS repository's backup-engine (tests/backup/__init__.py). The worker runs as RENDERED (the text the
launcher hands to woowbk-owner) against a fake dev-e podman plugged into the product's own podman.OwnerRunner.run, so
classification, CommandError texts, TempObjects, PgSink, start_ha_cluster, Pinned and ha_database are the real code.
The launcher runs as rendered, locally, against an S5-A proof root made by S5-A's own build_fixture.
"""
import contextlib
import copy
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

LAB = Path(__file__).resolve().parents[1] / 'e2e/lab'
sys.path.insert(0, str(LAB))
import focus_nextcloud_r6_s5 as s5   # noqa: E402
import focus_nextcloud_r6_s5_diag as diag   # noqa: E402
import focus_nextcloud_r6_s5b as s5b   # noqa: E402
from focus_nextcloud_r6_inventory import ORIGINALS   # noqa: E402
from focus_nextcloud_r6_plan import DEVICE_CAP, GIB, MIB   # noqa: E402
from tests.backup.test_focus_nextcloud_r6_s5b import DeviceRoot   # noqa: E402
from woowbackup import errors, habackup, hacommon, haissues, ha_nextcloud, ha_odoo, hatarget, podman, tempctr   # noqa: E402

REPO = Path(__file__).resolve().parents[2]
LIB = SimpleNamespace(errors=errors, habackup=habackup, hacommon=hacommon, haissues=haissues, ha_nextcloud=ha_nextcloud,
                      ha_odoo=ha_odoo, hatarget=hatarget, podman=podman, tempctr=tempctr)
PGVECTOR = 'docker.io/pgvector/pgvector:0.8.6-pg16'
JOB = 'j20261128T120000Z-5d1a0042'
SECRETS = ('unit-salt-secret-0123', 'unit-secret-value-0123', 'unit-dbpassword-secret-01', 'hunter2-secret-value',
           'alice-secret-role', 'weird-name-secret')
ROLE_MISSING = ('psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: '
                'FATAL:  role "{}" does not exist\n')
# The first S5-A build's builder (run at 4163367c; in this history as the cherry-pick c46f9a31, the same bytes).
FIRST_BUILDER_IN_HISTORY = 'c46f9a317e47882ed962d3bf30ed0598906bc8a5'
FIRST_BUILDER_SHA256 = 'd55f2433a1a6419ee932434cb086bd853f97e2bba02bce26d583d012c5abe8b6'
# What the product (with 7a2023e8) says for a missing postgres role: S5-B's stop text with the account kind's sentence.
NOW_STOP = diag.S5B_STOP.replace('資料庫還沒有準備好（還在啟動，或沒有在執行）。', podman.SENTENCES['role-missing'])
CONTROLDATA = b"""pg_control version number:            1300
Catalog version number:               202307071
Database system identifier:           7441234567890123456
Database cluster state:               shut down
pg_control last modified:             Fri 28 Nov 2026 06:30:12 AM UTC
Latest checkpoint location:           0/1A3D2F8
Latest checkpoint's REDO location:    0/1A3D2F8
Latest checkpoint's REDO WAL file:    000000010000000000000001
Latest checkpoint's TimeLineID:       1
Latest checkpoint's PrevTimeLineID:   1
Latest checkpoint's full_page_writes: on
Latest checkpoint's NextXID:          0:1234
Time of latest checkpoint:            Fri 28 Nov 2026 06:30:12 AM UTC
Minimum recovery ending location:     0/0
Backup start location:                0/0
Backup end location:                  0/0
End-of-backup record required:        no
wal_level setting:                    replica
Data page checksum version:           0
Bytes per WAL segment:                16777216
Database block size:                  8192
Mock authentication nonce:            9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0
"""
CONTROLDATA_AFTER = CONTROLDATA.replace(b'shut down\n', b'in production\n')
LISTING = b"""directory|700|999|999|4096|.
regular file|600|999|999|3|PG_VERSION
directory|700|999|999|4096|base
directory|700|999|999|4096|global
directory|700|999|999|4096|pg_wal
regular file|600|999|999|16777216|pg_wal/000000010000000000000001
directory|700|999|999|4096|pg_wal/archive_status
regular file|600|999|999|47|pg_hba.conf
regular empty file|600|999|999|0|pg_ident.conf
regular file|600|999|999|36|postgresql.auto.conf
regular file|600|999|999|300|postgresql.conf
directory|700|999|999|4096|pg_xact
directory|700|999|999|4096|weird-name-secret
"""
SERVER_LOG = b"""
PostgreSQL Database directory appears to contain a database; Skipping initialization

2026-11-28 10:00:00.100 UTC [1] LOG:  starting PostgreSQL 16.11 (Debian 16.11-1.pgdg120+1) on x86_64-pc-linux-gnu, compiled by gcc (Debian 12.2.0-14+deb12u1) 12.2.0, 64-bit
2026-11-28 10:00:00.101 UTC [1] LOG:  listening on Unix socket "/var/run/postgresql/.s.PGSQL.5432"
2026-11-28 10:00:00.110 UTC [28] LOG:  database system was shut down at 2026-11-28 06:30:12 UTC
2026-11-28 10:00:00.120 UTC [1] LOG:  database system is ready to accept connections
2026-11-28 10:00:01.000 UTC [35] FATAL:  role "postgres" does not exist
2026-11-28 10:00:02.000 UTC [36] FATAL:  role "postgres" does not exist
"""
HOSTILE_LOG = SERVER_LOG + b"""2026-11-28 10:00:03.000 UTC [37] ERROR:  invalid input syntax for type integer: "hunter2-secret-value"
2026-11-28 10:00:03.000 UTC [37] STATEMENT:  SELECT 'hunter2-secret-value'
2026-11-28 10:00:04.000 UTC [38] FATAL:  role "alice-secret-role" does not exist
2026-11-28 10:00:05.000 UTC [1] LOG:  server process (PID 80) was terminated by signal 9: Killed
2026-11-28 10:00:05.000 UTC [1] DETAIL:  Failed process was running: SELECT password FROM oc_users WHERE uid = 'hunter2-secret-value'
2026-11-28 10:00:05.000 UTC [1] LOG:  terminating any other active server processes
2026-11-28 10:00:06.000 UTC [90] FATAL:  could not open file "pg_subtrans/0000": No such file or directory
some random entrypoint output with hunter2-secret-value
LINE 1: SELECT 'hunter2-secret-value'
"""


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def lookup(_name):
    return SimpleNamespace(pw_uid=1013, pw_gid=1013, pw_dir='/home/appowner')


def member_tar(dbuser='oc_s5owner', root_entry=False):
    """An add-on member in S5-A's packing (pack_tree: no entry for data/ or data/postgres/ unless asked, 999:999,
    0700/0600) with HA's own configuration and pid files, and a config.php holding secret values."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.PAX_FORMAT) as tar:
        def add(name, data=None, mode=0o600, uid=999, gid=999):
            info = tarfile.TarInfo(name)
            info.uid, info.gid, info.mode, info.mtime = uid, gid, mode, 1764300000
            if data is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        add('addon.json', json.dumps({'version': '0.2.3', 'state': 'stopped', 'system': {'slug': s5.SLUG, 'name': 'x'},
                                      'user': {'image': 'sha256:' + '0' * 64, 'options': {}}}).encode(), uid=0, gid=0)
        if root_entry:
            add('data/postgres', mode=0o700)
        for folder in ('base', 'base/1', 'global', 'pg_wal', 'pg_wal/archive_status', 'pg_xact'):
            add('data/postgres/' + folder, mode=0o700)
        add('data/postgres/PG_VERSION', b'16\n')
        add('data/postgres/global/pg_control', b'\0' * 8192)
        add('data/postgres/pg_wal/000000010000000000000001', b'\0' * 4096)
        add('data/postgres/base/1/123', b'x' * 100)
        add('data/postgres/postgresql.conf', b"shared_preload_libraries = 'evil'\n")
        add('data/postgres/pg_hba.conf', b'host all all 0.0.0.0/0 trust\n')
        add('data/postgres/postmaster.opts', b'/usr/lib/postgresql/16/bin/postgres\n')
        config = ("<?php\n$CONFIG = array (\n  'instanceid' => 'ocs5diag00001',\n  'passwordsalt' => 'unit-salt-secret-0123',\n"
                  "  'secret' => 'unit-secret-value-0123',\n  'version' => '35.0.1.1',\n  'installed' => true,\n"
                  "  'dbtype' => 'pgsql',\n  'dbtableprefix' => 'oc_',\n  'dbname' => 'nextcloud',\n"
                  f"  'dbuser' => '{dbuser}',\n  'dbpassword' => 'unit-dbpassword-secret-01',\n"
                  "  'datadirectory' => '/share/nextcloud',\n);\n")
        add('data/nextcloud/config/config.php', config.encode(), mode=0o640, uid=33, gid=33)
    return out.getvalue()


def missing_role(user, _db, sql):
    """S5-A's cluster: superuser nextcloud, Nextcloud's own role oc_s5owner, no role postgres."""
    if user in ('oc_s5owner', 'nextcloud'):
        if sql == diag.ROLE_PROBE_SQL:
            return 0, (b'{"bootstrap" : "nextcloud", "postgres_role" : false, "postgres_db" : true, "superusers" : 1, '
                       b'"roles" : 2}\n'), b''
        return 0, b'null\n', b''
    return 2, b'', ROLE_MISSING.format(user).encode()


def healthy(user, _db, sql):
    if user != 'postgres':
        return 2, b'', ROLE_MISSING.format(user).encode()
    if sql == ha_odoo.DATABASES_SQL:
        return 0, json.dumps([['nextcloud', 1000, 'en_US.utf8', 'en_US.utf8']]).encode(), b''
    if sql == ha_nextcloud.TABLES_SQL:
        return 0, json.dumps(['oc_appconfig', 'oc_filecache', 'oc_mimetypes', 'oc_storages', 'oc_users']).encode(), b''
    if sql == ha_nextcloud.SHAPE_SQL:
        shape = {key: 0 for key, _label in ha_nextcloud.SHAPE_LABELS}
        shape.update(role_settings=0, defaults=["''::character varying"])
        return 0, json.dumps(shape).encode(), b''
    if sql == ha_nextcloud.HA_SQL:
        return 0, json.dumps({'extensions': ['plpgsql'], 'schemas': [], 'local_storages': ['local::/share/nextcloud/'],
                              'enabled': ['encryption', 'files'], 'encryption': '1'}).encode(), b''
    if sql.startswith("SELECT json_build_object('users'"):
        return 0, json.dumps({'users': 1, 'files': 80}).encode(), b''
    if sql == ha_nextcloud.FILES_SQL:
        return 0, b'[["s5owner", 3, 100, 12345]]', b''
    if sql == diag.ROLE_PROBE_SQL:
        return 0, b'{"bootstrap": "postgres", "postgres_role": true, "postgres_db": true, "superusers": 1, "roles": 2}', b''
    return 0, b'null', b''


class Recovering:
    """The server answers 'in recovery mode' to the first `bad` connections, then normally."""

    def __init__(self, bad):
        self.bad = bad

    def __call__(self, user, db, sql):
        if user == 'postgres' and self.bad > 0:
            self.bad -= 1
            return 2, b'', (b'psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: '
                            b'FATAL:  the database system is in recovery mode\n')
        return healthy(user, db, sql)


VALUE_FLAGS = {'--name', '--label', '--log-driver', '--log-opt', '--network', '--security-opt', '--pids-limit', '--memory',
               '--cpus', '--user', '--workdir', '--add-host', '--entrypoint', '--env-file', '--env', '--volume', '--tmpfs',
               '--secret'}


class FakeDevice:
    """dev-e's rootless podman as the owner sees it: the executor podman.OwnerRunner.run hands its argv to."""

    def __init__(self, psql=missing_role, isready=(0,), images=None, logs=SERVER_LOG, stops=False, import_fails=False):
        self.psql, self.isready, self.logs, self.stops, self.import_fails = psql, list(isready), logs, stops, import_fails
        self.images = {PGVECTOR: 'sha256:' + '9b' * 32} if images is None else images
        self.containers, self.volumes, self.calls, self.prefixes = {}, {}, [], []

    def __call__(self, argv, *, input=None, stdout=None, timeout=None, cwd=None, env=None, max_output=None, abort=None):
        index = argv.index(podman.PODMAN)
        prefix, args = argv[:index], [str(a) for a in argv[index + 1:]]
        self.prefixes.append(prefix)
        if abort is not None and abort() is not None:
            raise abort()
        self.calls.append(args)
        rc, out, err = getattr(self, 'op_' + args[0])(args[1:], input)
        return podman.Result(rc, out, err)

    def op_image(self, args, _input):
        ref = args[-1]
        if ref in self.images:
            return 0, (self.images[ref] + '\n').encode(), b''
        return 125, b'', f'Error: {ref}: image not known'.encode()

    def op_volume(self, args, data):
        name = args[-1] if args[0] != 'import' else args[1]
        if args[0] == 'create':
            self.volumes[name] = {'members': None}
            return 0, name.encode(), b''
        if args[0] == 'import':
            if self.import_fails:
                data.read(512)
                return 125, b'', b'Error: write: no space left on device'
            raw = b''
            for block in iter(lambda: data.read(65536), b''):
                raw += block
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r|') as tar:
                self.volumes[name]['members'] = [(m.name, 'dir' if m.isdir() else 'file', m.mode, m.uid, m.gid,
                                                  tar.extractfile(m).read() if m.isfile() else None) for m in tar]
            return 0, b'', b''
        if args[0] == 'inspect':
            return 0, f'/home/appowner/.local/share/containers/storage/volumes/{name}/_data\n'.encode(), b''
        if args[0] == 'rm':
            return (0, b'', b'') if self.volumes.pop(name, None) is not None else (1, b'', b'Error: no such volume')
        if args[0] == 'exists':
            return (0 if name in self.volumes else 1), b'', b''
        raise AssertionError(args)

    def op_unshare(self, _args, _input):
        return 0, b'', b''

    def op_run(self, args, _input):
        opts, index = {}, 0
        while index < len(args) and args[index].startswith('--'):
            if args[index] in VALUE_FLAGS:
                opts.setdefault(args[index], []).append(args[index + 1])
                index += 2
            else:
                opts.setdefault(args[index], []).append(True)
                index += 1
        image, rest = args[index], args[index + 1:]
        name = opts['--name'][0]
        role = name.split(JOB + '-', 1)[1]
        assert image in self.images and opts['--pull=never'] and opts['--network'] == ['none'], args
        if role == 'ids-pg':
            assert opts['--entrypoint'] == ['sh'] and '--rm' in opts
            return 0, b'999\n999\n', b''
        if role == 'diag-ctl':
            assert opts['--volume'][0].endswith(':ro') and opts['--entrypoint'] == ['pg_controldata'] and '--read-only' in opts
            return 0, CONTROLDATA, b''
        if role == 'diag-ls':
            assert opts['--volume'][0].endswith(':ro') and opts['--entrypoint'] == ['sh'] and '--read-only' in opts
            return 0, LISTING, b''
        assert role == 'hapg' and '--detach' in opts and rest == ha_odoo.ha_server_args(), args
        self.containers[name] = {'running': not self.stops, 'log_driver': opts['--log-driver'][0], 'argv': args}
        return 0, b'0' * 64 + b'\n', b''

    def op_exec(self, args, _input):
        env, index = {}, 0
        while args[index].startswith('--'):
            if args[index] == '--interactive':
                index += 1
                continue
            if args[index] == '--env':
                key, _, value = args[index + 1].partition('=')
                env[key] = value
            index += 2
        name, program, rest = args[index], args[index + 1], args[index + 2:]
        if not (self.containers.get(name) or {}).get('running'):
            return 125, b'', b'Error: can only create exec sessions on running containers: container state improper'
        if program == 'pg_isready':
            if '-q' in rest:
                return (self.isready.pop(0) if self.isready else (2 if self.stops else 0)), b'', b''
            return 0, b'/var/run/postgresql:5432 - accepting connections\n', b''
        if program == 'psql':
            assert env.get('PGOPTIONS') == ha_nextcloud.PINNED_OPTIONS, args
            user = rest[rest.index('-U') + 1]
            db = rest[rest.index('-d') + 1] if '-d' in rest else env.get('PGDATABASE')
            return self.psql(user, db, rest[rest.index('-c') + 1])
        if program == 'pg_controldata':
            return 0, CONTROLDATA_AFTER, b''
        raise AssertionError(args)

    def op_container(self, args, _input):
        name = args[-1]
        if args[0] == 'exists':
            return (0 if name in self.containers else 1), b'', b''
        if name not in self.containers:
            return 125, b'', b'Error: no such container ' + name.encode()
        state = self.containers[name]
        fmt = args[args.index('--format') + 1]
        if fmt == '{{.State.Running}}':
            return 0, b'true\n' if state['running'] else b'false\n', b''
        if fmt == diag.INSPECT_FORMAT:
            running = state['running']
            return 0, json.dumps({'status': 'running' if running else 'exited', 'running': running,
                                  'exit': 0 if running else 1, 'oom': False, 'restarts': 0}).encode(), b''
        return 0, b'0\n', b''

    def op_logs(self, args, _input):
        if self.containers[args[-1]]['log_driver'] == 'none':
            return 125, b'', b"Error: this container is using the 'none' log driver, cannot read logs"
        return 0, b'', self.logs

    def op_rm(self, args, _input):
        if self.containers.pop(args[-1], None) is not None:
            return 0, args[-1].encode(), b''
        return 1, b'', b'Error: no such container'

    def op_network(self, args, _input):
        return (1, b'', b'') if args[0] == 'exists' else (0, b'[]', b'')

    def index(self, *head):
        return next(i for i, call in enumerate(self.calls) if tuple(call[:len(head)]) == head)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def rendered_worker():
    namespace = {'__name__': 'focus_nextcloud_r6_s5_diag_worker_under_test'}
    exec(compile(diag.worker_program(call=False), 'worker', 'exec'), namespace)   # noqa: S102 - the device program
    return namespace


def run_worker(device, member=None, **request):
    """The rendered worker's diagnose against `device`, with the product engine of this repository."""
    w = rendered_worker()
    clock = Clock()
    base = w['make_owner_runner'](podman, 'appowner', runner=device, user_lookup=lookup)
    runner = w['Recorder'](base, podman.classify, clock)
    stream = w['HashingReader'](io.BytesIO(member_tar() if member is None else member), w['MEMBER_LIMIT'])
    q = dict({'job_id': JOB, 'deadline': 2e9, 'schedule': list(diag.SCHEDULE), 'layout_size': 127600640}, **request)
    return w['diagnose'](q, stream, LIB, runner, clock=clock, sleep=clock.sleep, wall=lambda: 1.9e9)


# ====================================================================== the cause, in the product's own code

class ProductMechanismTests(unittest.TestCase):
    def test_the_first_build_made_superuser_nextcloud_the_product_opens_as_postgres_the_rebuild_uses_postgres(self):
        # The first build ran at 4163367c, which reached this history as the cherry-pick c46f9a31 (the builder file is
        # byte for byte the same); a checkout without 4163367c (CI) reads that copy, bound by the builder's SHA-256.
        name = 'tests/e2e/lab/focus_nextcloud_r6_s5.py'
        shown = subprocess.run(['git', '-C', str(REPO), 'show', s5b.HISTORY.source_commit + ':' + name], capture_output=True)
        if shown.returncode:
            shown = subprocess.run(['git', '-C', str(REPO), 'show', FIRST_BUILDER_IN_HISTORY + ':' + name], capture_output=True)
        self.assertEqual(shown.returncode, 0)
        self.assertEqual(hashlib.sha256(shown.stdout).hexdigest(), FIRST_BUILDER_SHA256)
        first = shown.stdout.decode()
        self.assertIn("'--env=POSTGRES_USER=" + diag.S5A_POSTGRES_USER + "'", first)   # the first build (history)
        self.assertEqual(inspect.signature(ha_odoo.Cluster).parameters['superuser'].default, 'postgres')
        self.assertIn("'pg_isready', '-q', '-U', self.superuser", inspect.getsource(ha_odoo.Cluster.wait_ready))
        args = s5.Native({'proof_root': '/var/lib/woowbk-nextcloud-s5-' + '0' * 16, 'deadline': 0,
                          'nonce': '0' * 16}).source_args('pg')
        self.assertIn('--env=POSTGRES_USER=postgres', args)                                # the rebuild
        self.assertEqual(s5.FIXTURE_SHAPE['superuser'], 'postgres')

    def test_a_missing_postgres_role_is_told_as_such_since_7a2023e8(self):
        # b058df27 (S5-B attempt 01, the diagnosis) filed this as db-not-ready, word for word S5B_STOP: libpq's
        # 'connection to server on socket' needle came first. Since 7a2023e8 the account kinds come first.
        stderr = ROLE_MISSING.format('postgres').encode()
        self.assertEqual(podman.classify(stderr, 2)[0], 'role-missing')
        device = FakeDevice()
        runner = podman.OwnerRunner('appowner', runner=device, user_lookup=lookup)    # the engine's own (runuser) form
        with tempctr.TempObjects(runner, JOB) as tmp:
            tmp.volume('hapg')
            cluster = ha_odoo.start_ha_cluster(SimpleNamespace(log=lambda _t: None, checkpoint=None),
                                               ha_nextcloud.Pinned(tmp, 'hapg'), PGVECTOR)   # pg_isready: 0
            with self.assertRaises(podman.CommandError) as caught:
                ha_nextcloud.ha_database(cluster, 'nextcloud')
        self.assertEqual(caught.exception.message, NOW_STOP)
        self.assertNotEqual(caught.exception.message, diag.S5B_STOP)
        self.assertEqual((caught.exception.returncode, caught.exception.reason), (2, 'role-missing'))
        self.assertEqual(device.prefixes[0][0], podman.RUNUSER)


# ====================================================================== the device programs

class ProgramTests(unittest.TestCase):
    def test_programs_compile_fit_one_argv_and_bind_the_real_values(self):
        for name, program in (('worker', diag.WORKER), ('launcher', diag.LAUNCHER), ('sweep', diag.SWEEP),
                              ('owner-objects', diag.OWNER_OBJECTS)):
            with self.subTest(program=name):
                compile(program, name, 'exec')
                self.assertLess(len(program.encode()), 120 * 1024)
        self.assertEqual(diag.WORKER_SHA, sha(diag.WORKER.encode()))
        h = s5b.HISTORY   # always the FIRST build's fixture, never S5-B's active binding
        for value in (f'PROOF_ROOT={h.proof_root!r}', f'FIXTURE_SHA={h.fixture_sha!r}', f'WORKER_SHA={diag.WORKER_SHA!r}',
                      f'S5A_COMMAND_RECORDS={h.command_records!r}', "OWNER_EXEC=('/usr/local/bin/woowbk-owner',)",
                      "OWNER='appowner'", "PRODUCT_LIB='/usr/local/lib/woowtech-cockpit-backup'", 'ROOT_UID=0',
                      "LAYOUT='retired-proof-root'"):
            self.assertIn(value, diag.LAUNCHER)
        self.assertEqual(h.proof_root, '/var/lib/woowbk-nextcloud-s5-afe8d885402badf3')
        for program in (diag.RETIRED_STATE, diag.RETIRE):
            compile(program, 'retire', 'exec')
            self.assertIn(f'PROOF_ROOT={h.proof_root!r}', program)
            self.assertIn(f'FIXTURE_SHA={h.fixture_sha!r}', program)
        self.assertIn("OWNER='appowner'", diag.WORKER)
        self.assertTrue(diag.WORKER.rstrip().endswith('worker_main()'))
        self.assertEqual(diag.DATA_DIR, ha_odoo.HA_DATA)
        self.assertEqual(diag.NAME_PATTERN + r'\Z', tempctr.NAME_RE.pattern)
        self.assertEqual(diag.JOB_PATTERN + r'\Z', tempctr.JOB_RE.pattern)
        self.assertTrue(tempctr.JOB_RE.fullmatch(diag.new_job_id()))
        self.assertTrue(diag.new_job_id().split('-')[1].startswith(diag.JOB_TAG))
        self.assertEqual(s5b.HISTORY.fixture, s5b.HISTORY.proof_root + '/owned/artifact/generated-s5-source.tar')

    def test_the_rendered_worker_defines_everything_it_uses(self):
        w = rendered_worker()
        for name in ('diagnose', 'worker_main', 'Recorder', 'HashingReader', 'make_owner_runner', 'role_probe'):
            self.assertTrue(callable(w[name]), name)

    def test_the_owner_runner_is_the_products_without_runuser(self):
        device = FakeDevice()
        runner = diag.make_owner_runner(podman, 'appowner', runner=device, user_lookup=lookup)
        self.assertIsInstance(runner, podman.OwnerRunner)
        self.assertEqual(runner.prefix(), podman.OwnerRunner('appowner', user_lookup=lookup).prefix()[4:])
        self.assertEqual(runner.prefix()[:2], [podman.ENV, '-i'])
        runner.podman('volume', 'create', 'x')
        self.assertNotIn(podman.RUNUSER, device.prefixes[0])
        with self.assertRaisesRegex(ValueError, 'not-the-owner'):
            diag.make_owner_runner(podman, 'appowner', user_lookup=lookup)   # this test process is not uid 1013

    def test_the_hapg_run_is_the_products_argv_with_only_the_log_driver_switched(self):
        tmp = tempctr.TempObjects(SimpleNamespace(uid=None, owner='appowner'), JOB)
        product = tmp.run_argv('hapg', PGVECTOR, ha_odoo.ha_server_args(), detach=True, read_only_root=True,
                               volumes=[(tmp.name('hapg'), ha_odoo.HA_DATA, 'rw,noexec,nosuid,nodev')])
        swapped = diag.swap_log_driver(product)
        at = product.index('--log-driver')
        self.assertEqual(product[at:at + 2], ['--log-driver', 'none'])
        self.assertEqual(swapped[:at] + swapped[at + 4:], product[:at] + product[at + 2:])
        self.assertEqual(swapped[at:at + 4], ['--log-driver', 'k8s-file', '--log-opt', 'max-size=4mb'])
        with self.assertRaisesRegex(ValueError, 'log-driver-not-found'):
            diag.swap_log_driver(swapped)

    def test_device_call_runs_root_and_owner_programs_and_keeps_raw_output_private(self):
        ev = SimpleNamespace(path=Path(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, ev.path, True)
        seen = []

        class Proc:
            returncode = 0

            def __init__(self, argv, stdin, stdout, stderr):
                seen.append(argv)
                self.out = stdout

            def communicate(self, data, timeout):
                seen.append(json.loads(data))
                self.out.write(b'{"status": "ran"}')

        reply = diag.device_call('PROGRAM', {'a': 1}, ev, 'launcher', root=True, timeout=5, popen=Proc)
        self.assertEqual(reply, {'status': 'ran'})
        self.assertEqual(seen[0], [str(diag.LP), 'exec', '-i', 'woowbk-dev-e', 'python3', '-I', '-c', 'PROGRAM'])
        self.assertEqual(seen[1], {'a': 1})
        diag.device_call('PROGRAM', {}, ev, 'sweep', root=False, timeout=5, popen=Proc)
        self.assertEqual(seen[2][:5], [str(diag.LP), 'exec', '-i', 'woowbk-dev-e', '/usr/local/bin/woowbk-owner'])
        for name in ('launcher.stdout.private', 'launcher.stderr.private', 'sweep.stdout.private'):
            self.assertEqual(os.stat(ev.path / name).st_mode & 0o777, 0o600)
        Proc.returncode = 1
        self.assertEqual(diag.device_call('P', {}, ev, 'bad', root=True, timeout=5, popen=Proc)['reason'],
                         'fixed-s5diag-device-program-failed')


# ====================================================================== default-deny filters

class FilterTests(unittest.TestCase):
    def test_server_log_lines_become_ids_and_no_secret_survives(self):
        out = diag.filter_lines(HOSTILE_LOG)
        text = json.dumps(out)
        for secret in SECRETS:
            self.assertNotIn(secret, text)
        counts = out['counts']
        self.assertEqual(counts['FATAL role-missing name=postgres'], 2)
        self.assertEqual(counts['FATAL role-missing name=other(len=17)'], 1)
        self.assertEqual(counts['LOG ready'], 1)
        self.assertEqual(counts['LOG was-shut-down'], 1)
        self.assertEqual(counts['LOG starting version=16.11'], 1)
        self.assertEqual(counts['entrypoint-skip-init'], 1)
        self.assertEqual(counts['ERROR unrecognized'], 1)
        self.assertEqual(counts['STATEMENT dropped'], 1)
        self.assertEqual(counts['DETAIL failed-process-running'], 1)
        self.assertEqual(counts['LOG process-ended how=was terminated by signal 9: Killed proc=server process'], 1)
        self.assertEqual(counts['LOG terminating-others'], 1)
        self.assertEqual(counts['FATAL could-not errno=No such file or directory path=pg_subtrans/0000 verb=open'], 1)
        self.assertEqual(counts['unrecognized'], 1)
        self.assertEqual(counts['psql-line-dropped'], 1)
        self.assertEqual(out['kept'][1], {'ts': '2026-11-28 10:00:00.100 UTC', 'pid': 1, 'id': 'LOG starting version=16.11'})

    def test_psql_stderr_of_the_s5b_stop_and_its_neighbours(self):
        def ident(text):
            return diag.filter_lines(text.encode())['kept'][0]['id']
        self.assertEqual(ident(ROLE_MISSING.format('postgres')), 'psql-connect FATAL role-missing name=postgres')
        self.assertEqual(ident(ROLE_MISSING.format('oc_s5owner')), 'psql-connect FATAL role-missing name=oc_s5owner')
        self.assertEqual(ident('psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: '
                               'FATAL:  the database system is in recovery mode'), 'psql-connect FATAL in-recovery')
        self.assertEqual(ident('psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: '
                               'No such file or directory'), 'psql-connect no-socket-file')
        self.assertEqual(ident('psql: error: connection to server on socket "/tmp/x" failed: FATAL:  database "secret-db" '
                               'does not exist'), 'psql-connect other-socket FATAL database-missing name=other(len=9)')
        self.assertEqual(ident('\tIs the server running locally and accepting connections on that socket?'),
                         'hint-is-server-running')
        self.assertEqual(ident('ERROR:  relation "public.secret_table" does not exist'),
                         'ERROR relation-missing name=other(len=19)')

    def test_bounds(self):
        out = diag.filter_lines(b'\n'.join([b'2026-11-28 10:00:00 UTC [9] FATAL:  role "postgres" does not exist'] * 900),
                                limit=5)
        self.assertEqual((out['lines'], len(out['kept']), out['counts']), (900, 5, {'FATAL role-missing name=postgres': 900}))

    def test_controldata_keeps_only_its_listed_fields(self):
        out = diag.parse_controldata(CONTROLDATA)
        self.assertEqual({k: out[k] for k in ('state', 'checkpoint', 'redo', 'redo_wal_file', 'timeline', 'wal_level')},
                         {'state': 'shut down', 'checkpoint': '0/1A3D2F8', 'redo': '0/1A3D2F8',
                          'redo_wal_file': '000000010000000000000001', 'timeline': '1', 'wal_level': 'replica'})
        self.assertEqual(out['other_lines'], 2)
        self.assertNotIn('7441234567890123456', json.dumps(out))
        self.assertNotIn('9f8e7d6c5b4a', json.dumps(out))
        self.assertEqual(diag.parse_controldata(b'Database cluster state: on fire\n')['state'], 'unreadable')

    def test_listing_names_missing_directories_and_wal_without_unknown_names(self):
        out = diag.parse_listing(LISTING)
        self.assertEqual(out['root'], {'type': 'directory', 'mode': '700', 'uid': 999, 'gid': 999, 'size': 4096})
        self.assertIn('pg_notify', out['missing_dirs'])
        self.assertIn('pg_logical/snapshots', out['missing_dirs'])
        self.assertNotIn('pg_wal/archive_status', out['missing_dirs'])
        self.assertEqual(out['missing_files'], [])
        self.assertEqual([w['name'] for w in out['wal']], ['000000010000000000000001'])
        self.assertEqual(out['unknown_entries'], 1)
        self.assertNotIn('weird-name-secret', json.dumps(out))

    def test_errors_keep_only_product_sentences(self):
        error = podman.CommandError(diag.S5B_STOP, returncode=2, stderr=ROLE_MISSING.format('postgres').encode(),
                                    reason='db-not-ready')
        row = diag.fixed_error(error)
        self.assertTrue(row['equals_s5b_stop'])
        self.assertEqual((row['message'], row['reason'], row['returncode']), (diag.S5B_STOP, 'db-not-ready', 2))
        self.assertEqual(list(row['stderr']['counts']), ['psql-connect FATAL role-missing name=postgres'])
        row = diag.fixed_error(errors.BackupError('job-failed', 'value hunter2-secret-value leaked'))
        self.assertNotIn('message', row)
        self.assertNotIn('hunter2', json.dumps(row))
        self.assertEqual(row['message_withheld']['chars'], len('value hunter2-secret-value leaked'))


# ====================================================================== the worker against a fake dev-e

class WorkerTests(unittest.TestCase):
    def assertNoSecret(self, value):
        text = json.dumps(value)
        for secret in SECRETS:
            self.assertNotIn(secret, text)

    def test_missing_role_is_shown_deterministically_and_everything_owned_goes_in_order(self):
        device = FakeDevice(logs=HOSTILE_LOG)
        out = run_worker(device)
        self.assertEqual(out['status'], 'completed', out.get('failure'))
        self.assertNoSecret(out)
        self.assertEqual(out['image']['ref'], PGVECTOR)
        self.assertEqual(out['pg_ids'], [999, 999])
        member = out['member']
        self.assertEqual((member['bytes'], member['sha256']), (len(member_tar()), sha(member_tar())))
        self.assertEqual((member['pg_version'], member['dbname'], member['dbuser']), ('16', 'nextcloud', 'oc_s5owner'))
        self.assertFalse(member['root_entry_in_member'])
        self.assertEqual(member['replaced_in_member'], ['pg_hba.conf', 'postgresql.conf'])
        self.assertEqual(out['controldata_before']['state'], 'shut down')
        self.assertEqual(out['controldata_after']['state'], 'in production')
        self.assertEqual([w['name'] for w in out['listing_before']['wal']], ['000000010000000000000001'])
        self.assertEqual(out['wait_ready']['ok'], True)
        self.assertEqual(out['isready_after_attempts'], {'rc': 0, 'answer': 'accepting connections'})
        hapg = f'woowbk-{JOB}-hapg'
        quiet = device.index('exec', '--user', 'postgres', '--env', 'PGOPTIONS=' + ha_nextcloud.PINNED_OPTIONS, hapg,
                             'pg_isready', '-q')
        self.assertEqual(device.calls[quiet + 1][5:7], [hapg, 'psql'])   # attempt 1 right after wait_ready, as the product
        attempts = out['attempts']
        self.assertEqual([a['at'] for a in attempts], list(diag.SCHEDULE))
        for attempt in attempts:
            self.assertFalse(attempt['ok'])
            self.assertFalse(attempt['error']['equals_s5b_stop'])   # since 7a2023e8: the account kind, not 'not ready'
            self.assertEqual(attempt['error']['reason'], 'role-missing')
            call = attempt['failed_call']
            self.assertEqual((call['program'], call['user'], call['database'], call['sql'], call['pinned'], call['rc']),
                             ('psql', 'postgres', 'postgres', 'databases', True, 2))
            self.assertEqual(diag.attempt_ids(attempt), ['psql-connect FATAL role-missing name=postgres'])
        probe = out['role_probe']
        self.assertEqual((probe['connected_as'], probe['bootstrap_superuser'], probe['postgres_role'],
                          probe['postgres_database']), ('config-dbuser', 'nextcloud', False, True))
        self.assertEqual([t['as'] for t in probe['tried']], ['postgres', 'postgres'])
        self.assertEqual(out['server']['state']['running'], True)
        self.assertEqual(out['server']['log']['counts']['FATAL role-missing name=postgres'], 2)
        # every attempt refused for the missing role and the probe confirms it: that is the cause, whatever else the log has
        self.assertEqual(diag.verdict(out), 'missing-postgres-role')
        self.assertEqual(out['order'], ['server-state', 'remove-container', 'remove-volume', 'cleanup'])
        self.assertEqual(out['left'], [])
        self.assertEqual((device.containers, device.volumes), ({}, {}))
        hapg = f'woowbk-{JOB}-hapg'
        self.assertLess(device.index('container', 'inspect', '--format', diag.INSPECT_FORMAT, hapg),
                        device.index('logs', '--tail', str(diag.LOG_TAIL), hapg))
        self.assertLess(device.index('logs'), device.index('rm', '--force', '--time', '10', hapg))
        self.assertLess(device.index('rm', '--force', '--time', '10', hapg), device.index('volume', 'rm', '--force', hapg))
        self.assertEqual(out['run_argv'], diag.swap_log_driver(device_run_argv(out)))
        self.assertEqual(out['deviations'], [ident for ident, _why in diag.DEVIATIONS])

    def test_the_volume_holds_what_the_products_pgsink_makes(self):
        device = FakeDevice()
        seen = {}
        original = device.op_volume

        def keep(args, data):
            result = original(args, data)
            if args[0] == 'import':
                seen.update({name: row for name, *row in device.volumes[args[1]]['members']})
            return result
        device.op_volume = keep
        run_worker(device)
        self.assertEqual(seen['pg_hba.conf'][-1], ha_odoo.PG_HBA)
        self.assertEqual(seen['postgresql.conf'][-1], ha_odoo.PG_CONF)
        self.assertNotIn('postmaster.opts', seen)
        self.assertEqual(seen['.'][:4], ['dir', 0o700, 999, 999])
        self.assertTrue(all(row[2:4] == [999, 999] for row in seen.values()))
        self.assertTrue(all(row[1] == (0o700 if row[0] == 'dir' else 0o600) for row in seen.values()))

    def test_a_healthy_cluster_is_not_reproduced_and_its_counts_are_read(self):
        out = run_worker(FakeDevice(psql=healthy))
        self.assertEqual(out['status'], 'completed')
        self.assertEqual(len(out['attempts']), 1)
        details = out['attempts'][0]['details']
        self.assertEqual((details['nextcloud'], details['tables'], details['counts'], details['encryption_enabled']),
                         (True, 5, {'users': 1, 'files': 80}, True))
        self.assertEqual(out['role_probe']['connected_as'], 'postgres')
        self.assertEqual(diag.verdict(out), 'not-reproduced-query-succeeded')
        self.assertNoSecret(out)

    def test_a_server_in_crash_recovery_that_comes_back(self):
        out = run_worker(FakeDevice(psql=Recovering(3), isready=(1, 0), logs=HOSTILE_LOG))
        self.assertEqual([a['ok'] for a in out['attempts']], [False, False, False, True])
        self.assertEqual(diag.attempt_ids(out['attempts'][0]), ['psql-connect FATAL in-recovery'])
        self.assertEqual(diag.verdict(out), 'server-crashed-then-recovered')
        self.assertEqual(diag.verdict(run_worker(FakeDevice(psql=Recovering(2)))), 'transient-not-ready-then-ok')

    def test_a_server_that_stops_is_the_other_message_and_still_cleaned_up(self):
        device = FakeDevice(stops=True)
        out = run_worker(device)
        self.assertEqual(out['failure']['stage'], 'start')
        self.assertEqual(out['wait_ready']['error']['message'], '暫用的 PostgreSQL 沒有啟動（資料可能不完整或版本不符）。')
        self.assertEqual(diag.verdict(out), 'server-did-not-start')
        self.assertEqual(out['order'], ['server-state', 'remove-container', 'remove-volume', 'cleanup'])
        self.assertEqual((device.containers, device.volumes, out['left']), ({}, {}, []))

    def test_a_failed_member_pass_removes_the_volume_and_starts_nothing(self):
        device = FakeDevice(import_fails=True)
        out = run_worker(device)
        self.assertEqual(out['failure']['stage'], 'member-pass')
        self.assertEqual(out['order'], ['remove-container', 'remove-volume', 'cleanup'])
        self.assertEqual((device.volumes, out['left']), ({}, []))
        self.assertFalse(any(call[0] == 'run' and f'woowbk-{JOB}-hapg' in call for call in device.calls))
        self.assertEqual(diag.verdict(out), 'failed-before-start:member-pass')

    def test_no_image_present_is_never_pulled(self):
        device = FakeDevice(images={})
        out = run_worker(device)
        self.assertEqual(out['failure']['error']['message'], 'fixed-s5diag-no-pg16-image-present-never-pulled')
        self.assertEqual([c[-1] for c in device.calls if c[0] == 'image'], [*ha_odoo.PG16_IMAGES, ha_odoo.PG16_PINNED])
        self.assertFalse(any(c[0] in ('pull', 'load') for c in device.calls))

    def test_a_past_deadline_or_a_foreign_job_id_touches_nothing(self):
        for request in ({'deadline': 1.0}, {'job_id': 'j20261128T120000Z-00000042'}):
            with self.subTest(request=sorted(request)):
                device = FakeDevice()
                out = run_worker(device, **request)
                self.assertEqual(out['status'], 'failed')
                self.assertEqual(device.calls, [])

    def test_the_deadline_stops_a_running_step_and_cleanup_still_runs(self):
        device = FakeDevice()
        w = rendered_worker()
        clock = Clock()
        times = iter([1.0] * 12 + [3.0] * 1000)   # passes the first checks, then every abort() says stop
        runner = w['Recorder'](w['make_owner_runner'](podman, 'appowner', runner=device, user_lookup=lookup),
                               podman.classify, clock)
        out = w['diagnose']({'job_id': JOB, 'deadline': 2.0, 'schedule': [0]},
                            w['HashingReader'](io.BytesIO(member_tar()), w['MEMBER_LIMIT']), LIB, runner,
                            clock=clock, sleep=clock.sleep, wall=lambda: next(times))
        self.assertEqual(out['status'], 'failed')
        self.assertEqual(out['order'][-1], 'cleanup')
        self.assertEqual((device.containers, device.volumes), ({}, {}))


def device_run_argv(out):
    """The product's own `podman run` argv of the hapg container for this run (rebuilt with the product's TempObjects)."""
    tmp = tempctr.TempObjects(SimpleNamespace(uid=lookup('appowner').pw_uid, owner='appowner'), JOB)   # the same --cpus
    return tmp.run_argv('hapg', out['image']['ref'], ha_odoo.ha_server_args(), detach=True, read_only_root=True,
                        volumes=[(tmp.name('hapg'), ha_odoo.HA_DATA, 'rw,noexec,nosuid,nodev')])


# ====================================================================== the launcher, run locally

FAKE_WORKER = r'''
import hashlib,json,sys
raw=sys.stdin.buffer
q=json.loads(raw.readline())
h=hashlib.sha256();n=0
for b in iter(lambda:raw.read(65536),b''):
 h.update(b);n+=len(b)
print(json.dumps({'status':'completed','received':{'bytes':n,'sha256':h.hexdigest()},'request':q}))
'''


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.dev = DeviceRoot(self)

    def overrides(self, **extra):
        dev = self.dev
        return dict({'PROOF_ROOT': str(dev.root), 'FIXTURE': str(dev.fixture), 'PROVENANCE': str(dev.provenance),
                     'FIXTURE_SHA': dev.built['sha256'], 'FIXTURE_BYTES': dev.built['bytes'],
                     'PROVENANCE_SHA': sha(dev.provenance.read_bytes()), 'S5A_COMMAND_RECORDS': 9,
                     'OWNER': pwd.getpwuid(os.getuid()).pw_name, 'ROOT_UID': os.getuid(),
                     'PRODUCT_LIB': str(REPO / 'backup-engine'), 'OWNER_EXEC': (), 'PYTHON': sys.executable,
                     'WORKER_SHA': sha(FAKE_WORKER.encode())}, **extra)

    def launch(self, worker=FAKE_WORKER, **extra):
        program = diag.launcher_program(self.overrides(**extra))
        request = {'worker': worker, 'timeout': 120, 'worker_request': {'job_id': JOB, 'deadline': 2e9}}
        p = subprocess.run([sys.executable, '-I', '-c', program], input=json.dumps(request).encode(), capture_output=True,
                           timeout=300)
        self.assertEqual(p.returncode, 0, p.stderr.decode()[-2000:])
        return json.loads(p.stdout)

    def member(self):
        with habackup.open_backup(self.dev.fixture) as opened, opened.open_addon(s5.SLUG) as stream:
            raw = b''
            for block in iter(lambda: stream.read(1 << 20), b''):
                raw += block
            return raw, opened.layout.size

    def test_the_owner_worker_gets_exactly_the_add_on_member_and_the_proof_root_stays(self):
        out = self.launch()
        raw, size = self.member()
        self.assertEqual(out['status'], 'ran')
        self.assertEqual(out['stream'], {'bytes': len(raw), 'sha256': sha(raw), 'broken': None})
        self.assertEqual(out['worker']['received'], {'bytes': len(raw), 'sha256': sha(raw)})
        self.assertEqual(out['worker']['request'], {'job_id': JOB, 'deadline': 2e9, 'layout_size': size})
        self.assertEqual(out['fixture']['sha256'], self.dev.built['sha256'])
        self.assertTrue(out['proof_root_unchanged'])
        self.assertEqual(out['worker_rc'], 0)
        names = []
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r|') as tar:
            names = [m.name for m in tar]
        self.assertIn('data/postgres/PG_VERSION', names)
        # The rebuilt packing (HA's tar order): the cluster's own directory before its files (the first build had none).
        self.assertLess(names.index('data/postgres'), names.index('data/postgres/PG_VERSION'))

    def test_a_changed_fixture_or_proof_root_or_worker_is_refused_before_anything_starts(self):
        marker = self.dev.tmp / 'worker-ran'
        worker = FAKE_WORKER + f"\nopen({str(marker)!r},'w').close()\n"
        faults = {'fixed-s5diag-fixture-sha': lambda d: d.fixture.write_bytes(d.fixture.read_bytes()[:-1] + b'\x01'),
                  'fixed-s5diag-proof-root-leaves': lambda d: d.write('extra.json', b'{}'),
                  'fixed-s5diag-provenance-sha': lambda d: d.provenance.write_bytes(d.provenance.read_bytes() + b' ')}
        for reason, fault in faults.items():
            with self.subTest(fault=reason):
                self.dev = DeviceRoot(self)
                expected = self.overrides(WORKER_SHA=sha(worker.encode()))
                fault(self.dev)
                program = diag.launcher_program(expected)
                request = {'worker': worker, 'timeout': 60, 'worker_request': {'job_id': JOB}}
                p = subprocess.run([sys.executable, '-I', '-c', program], input=json.dumps(request).encode(),
                                   capture_output=True, timeout=300, check=True)
                self.assertEqual(json.loads(p.stdout), {'status': 'refused', 'reason': reason})
                self.assertFalse(marker.exists())
        self.dev = DeviceRoot(self)
        self.assertEqual(self.launch(worker=worker)['reason'], 'fixed-s5diag-worker-binding')   # bound to FAKE_WORKER
        self.assertFalse(marker.exists())


# ====================================================================== the host side

def inventory_row():
    units = {name: {'ActiveState': 'inactive', 'SubState': 'dead', 'UnitFileState': 'generated'}
             for name in ('nextcloud.target', 'nextcloud-app.service', 'nextcloud-db.service')}
    images = [{'ref': ref, 'present': True, 'identity': {'id': 'sha256:' + cid, 'architecture': 'amd64', 'os': 'linux'}}
              for ref, cid in ORIGINALS.items()]
    return {'isolation': {'running': True, 'network': 'none', 'ports': {}, 'memory_limit': DEVICE_CAP},
            'root': {'memory_max': str(DEVICE_CAP), 'memory_current': 200 * MIB, 'varlib_free_bytes': 100 * GIB,
                     'installed_hashes': {'ha_nextcloud.py': 'a' * 64}, 'catalog_sha256': 'c' * 64},
            'host_memory_available_mib': 8000, 'host_free_bytes': 100 * GIB,
            'owner': {'units': units, 'images': images, 'quadlets': {'nextcloud-db.container': {'sha256': 'd' * 64}}}}


class FakeHost:
    """wake.device, collect and device_call of the host side, with the worker's real facts in the launcher reply."""

    def __init__(self, worker, *, running=False, launcher_status='ran', leave=False):
        self.worker, self.running, self.launcher_status, self.leave = worker, running, launcher_status, leave
        self.log, self.job_id = [], None

    def device(self, program, request=None, *, root=False, timeout=300):
        name = {s5.ENGINE_PROGRAM: 'engine', s5.TARGET_STATE: 'store', diag.OWNER_OBJECTS: 'objects'}.get(program)
        name = name or ('quiescent' if program == s5b.case.QUIESCENT else 'other')
        self.log.append(name)
        if name == 'engine':
            return s5.engine_manifest(REPO, s5b.PRODUCT_COMMIT)
        if name == 'store':
            return {'archives': [], 'ha-backups': [], 'uploads': [], 'jobs': []}
        if name == 'quiescent':
            return {'active_jobs': 0}
        if name == 'objects':
            rows = [['woowbk-j20261127T010101Z-00000001-hapg', 'j20261127T010101Z-00000001',
                     'running' if self.running else 'exited']]
            if self.leave and self.job_id:
                rows.append([f'woowbk-{self.job_id}-hapg', self.job_id, 'exited'])
            return {'containers': rows, 'volumes': [], 'networks': [], 'unnamed': 0}
        raise AssertionError(name)

    def inventory(self):
        self.log.append('collect')
        return inventory_row()

    def call(self, program, request, ev, prefix, *, root, timeout):
        self.log.append(prefix)
        if prefix == 'launcher':
            self.job_id = request['worker_request']['job_id']
            assert program == diag.LAUNCHER and root and request['worker'] == diag.WORKER
            if self.launcher_status == 'refused':
                return {'status': 'refused', 'reason': 'fixed-s5diag-fixture-sha'}
            worker = dict(self.worker, job_id=self.job_id)
            return {'status': 'ran', 'worker': worker, 'stream': {'sha256': worker['member']['sha256']},
                    'proof_root_unchanged': True}
        assert program == diag.SWEEP and not root and request == {'job_id': self.job_id}
        return {'removed': [], 'left': []}


class HostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.worker = run_worker(FakeDevice())
        self.binding = {'source_commit': 'c' * 40, 'phase': diag.PHASE}

    def run_locked(self, host):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = diag.run_locked(self.binding, device=host.device, inventory=host.inventory, call=host.call,
                                 evidence_root=self.tmp / 'evidence', markers=self.tmp / 'markers')
        return rc, json.loads(out.getvalue().strip().splitlines()[-1])

    def test_one_run_admission_launcher_sweep_after_state_and_private_evidence(self):
        host = FakeHost(self.worker)
        rc, line = self.run_locked(host)
        self.assertEqual(rc, 0, line)
        self.assertEqual((line['status'], line['verdict']), ('diagnosed', 'missing-postgres-role'))
        self.assertTrue(line['device_unchanged'] and line['proof_root_unchanged'] and line['stream_intact'])
        self.assertFalse(line['first_attempt_equals_s5b_stop'])   # since 7a2023e8 the product names the missing role
        self.assertEqual(line['role_probe'], {'connected_as': 'config-dbuser', 'bootstrap_superuser': 'nextcloud',
                                              'postgres_role': False, 'postgres_database': True})
        self.assertEqual(line['engine_relevant_differs_from_s5b_product'], [])
        self.assertEqual(line['controldata_before']['state'], 'shut down')
        self.assertEqual(line['pg_isready_quiet_rcs'], [0])
        self.assertEqual(sorted(line), sorted(diag.summary({})))   # one fixed shape
        self.assertEqual(host.log[:6], ['collect', 'engine', 'store', 'objects', 'quiescent', 'launcher'])
        self.assertEqual(host.log[6:], ['sweep', 'collect', 'engine', 'store', 'objects'])
        ev = Path(line['private_evidence'])
        self.assertEqual(ev.stat().st_mode & 0o777, 0o700)
        self.assertEqual(sorted(p.name for p in ev.iterdir()),
                         ['after.private.json', 'before.private.json', 'binding.json', 'fixed-result.json',
                          'launcher-result.private.json', 'record.private.json'])
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in ev.iterdir()))
        text = ''.join(p.read_text() for p in ev.iterdir())
        for secret in SECRETS:
            self.assertNotIn(secret, text)
        rc, again = self.run_locked(FakeHost(self.worker))     # one run per binding
        self.assertEqual((rc, again['status'], again['reason']), (2, 'refused', 'fixed-s5diag-already-run-once'))

    def test_admission_refuses_a_running_throwaway_container_and_starts_nothing(self):
        host = FakeHost(self.worker, running=True)
        rc, line = self.run_locked(host)
        self.assertEqual((rc, line['status'], line['reason']), (2, 'refused', 'fixed-s5diag-throwaway-container-running'))
        self.assertNotIn('launcher', host.log)
        self.assertFalse((self.tmp / 'markers').exists() and any((self.tmp / 'markers').iterdir()))

    def test_a_launcher_refusal_and_a_leftover_of_this_job_are_reported(self):
        rc, line = self.run_locked(FakeHost(self.worker, launcher_status='refused'))
        self.assertEqual((rc, line['status'], line['reason']), (1, 'refused', 'fixed-s5diag-fixture-sha'))
        self.binding = dict(self.binding, source_commit='d' * 40)
        rc, line = self.run_locked(FakeHost(self.worker, leave=True))
        self.assertEqual((rc, line['status'], line['device_unchanged']), (1, 'diagnosed', False))

    def test_lock_wait_has_a_timeout(self):
        path = self.tmp / 'lock'
        with open(path, 'a') as holder, open(path, 'a') as waiter:
            __import__('fcntl').flock(holder, __import__('fcntl').LOCK_EX)
            clock = Clock()
            with self.assertRaisesRegex(ValueError, 'fixed-s5diag-lock-timeout'):
                diag.acquire(waiter, 10, clock=clock, sleep=clock.sleep)
            self.assertGreaterEqual(clock.now, 1010)
            __import__('fcntl').flock(holder, __import__('fcntl').LOCK_UN)
            diag.acquire(waiter, 10, clock=clock, sleep=clock.sleep)

    def test_a_different_s5a_result_refuses_before_the_lock_and_the_device(self):
        doc = json.loads(s5b.HISTORY_RESULT.read_text())
        doc['fixture']['sha256'] = '0' * 64
        tampered = self.tmp / 's5a.json'
        tampered.write_text(json.dumps(doc))
        with patch.object(diag, 'HISTORY_RESULT', tampered), self.assertRaisesRegex(ValueError, 'fixed-s5b-history-result'):
            diag.tool_binding('c' * 40)
        never = lambda *a, **k: (_ for _ in ()).throw(AssertionError('no device step before the binding'))   # noqa: E731
        with patch.object(diag, 'HISTORY_RESULT', tampered), patch.object(diag.s5, 'checkout', return_value=('c' * 40, True)), \
                patch.dict(os.environ, {'HEAVY_FREE': diag.LOCK}), patch.object(diag, 'acquire', never), \
                patch.object(diag, 'run_locked', never), self.assertRaisesRegex(ValueError, 'fixed-s5b-history-result'):
            diag.main(['--run'])
        binding = diag.tool_binding('c' * 40)
        self.assertEqual(binding['s5a_result_sha256'], sha(s5b.HISTORY_RESULT.read_bytes()))
        self.assertEqual((binding['proof_root'], binding['fixture_sha256']), (s5b.HISTORY.proof_root, s5b.HISTORY.fixture_sha))

    def test_the_run_needs_the_heavy_seat_and_a_clean_checkout(self):
        with patch.dict(os.environ, {'HEAVY_FREE': ''}), self.assertRaisesRegex(ValueError, 'heavy-seat-required'):
            diag.main(['--run'])
        with patch.dict(os.environ, {'HEAVY_FREE': diag.LOCK}), patch.object(diag.s5, 'checkout', return_value=('c', False)), \
                self.assertRaisesRegex(ValueError, 'clean-checkout'):
            diag.main(['--run'])

    def test_contract_is_offline_and_names_every_deviation(self):
        doc = diag.contract()
        self.assertEqual(doc['deviations_from_the_product_check'], dict(diag.DEVIATIONS))
        self.assertEqual((doc['pulls'], doc['fixture_sha256'], doc['owner']), (0, s5b.HISTORY.fixture_sha, 'appowner'))

    def test_verdicts(self):
        base = copy.deepcopy(self.worker)
        self.assertEqual(diag.verdict(base), 'missing-postgres-role')
        self.assertEqual(diag.verdict(None), 'no-worker-result')
        probe_true = copy.deepcopy(base)
        probe_true['role_probe']['postgres_role'] = True
        self.assertEqual(diag.verdict(probe_true), 'other-see-evidence')
        missing_db = copy.deepcopy(base)
        for attempt in missing_db['attempts']:
            attempt['failed_call']['stderr']['counts'] = {'psql-connect FATAL database-missing name=postgres': 1}
        self.assertEqual(diag.verdict(missing_db), 'missing-database')
        early = {'stage': 'image', 'failure': {'stage': 'image'}}
        self.assertEqual(diag.verdict(early), 'failed-before-start:image')


# ====================================================================== S5-A's gate: the product's own check opens a fixture

def packed_member(dev):
    """The add-on member of a fixture packed by S5-A's own build_fixture (DeviceRoot) and its outer layout size."""
    with habackup.open_backup(dev.fixture) as opened, opened.open_addon(s5.SLUG) as stream:
        return b''.join(iter(lambda: stream.read(1 << 20), b'')), opened.layout.size


def launcher_reply(worker, member, **extra):
    """What the launcher hands back for one open check (its stream and proof root as they would be)."""
    return dict({'status': 'ran', 'worker': worker, 'stream': {'bytes': len(member), 'sha256': sha(member), 'broken': None},
                 'proof_root_unchanged': True, 'worker_rc': 0}, **extra)


class OpenCheckTests(unittest.TestCase):
    """A rebuilt fixture -- packed by S5-A's own build_fixture with the real add-on's shape -- opened through the product's
    own check path (the rendered worker on the repository's engine, a fake dev-e podman behind OwnerRunner.run)."""

    def setUp(self):
        self.dev = DeviceRoot(self)
        self.member, self.size = packed_member(self.dev)

    def worker(self, psql):
        return run_worker(FakeDevice(psql=psql), member=self.member, schedule=[0], layout_size=self.size)

    def test_a_rebuilt_fixture_opens_and_every_gate_fact_is_true(self):
        worker = self.worker(healthy)
        self.assertEqual(diag.judge_open(launcher_reply(worker, self.member), {'removed': [], 'left': []}),
                         {name: True for name in s5.OPEN_CHECKS})
        self.assertTrue(worker['member']['root_entry_in_member'])   # data/postgres came before its files
        self.assertEqual((worker['member']['dbuser'], worker['member']['dbname']), ('nextcloud', 'nextcloud'))
        self.assertEqual([a['at'] for a in worker['attempts']], [0])   # one attempt: the product's own call

    def test_the_first_builds_database_fails_the_gate(self):
        checks = diag.judge_open(launcher_reply(self.worker(missing_role), self.member), {'removed': [], 'left': []})
        self.assertEqual(sorted(name for name, ok in checks.items() if not ok),
                         ['encryption', 'nextcloud_database', 'product_call_answered', 'superuser', 'users'])

    def test_any_broken_fact_fails_the_gate(self):
        worker = self.worker(healthy)
        good = launcher_reply(worker, self.member)
        for name, reply, sweep in (('proof_unchanged', dict(good, proof_root_unchanged=False), {'left': []}),
                                   ('stream_intact', dict(good, stream=dict(good['stream'], sha256='0' * 64)), {'left': []}),
                                   ('stream_intact', dict(good, stream=dict(good['stream'], broken='reader-OSError')),
                                    {'left': []}),
                                   ('cleanup', dict(good, worker=dict(worker, left=['woowbk-x-hapg'])), {'left': []}),
                                   ('cleanup', good, {'left': ['woowbk-x-hapg']}), ('cleanup', good, None)):
            with self.subTest(fact=name):
                checks = diag.judge_open(reply, sweep)
                self.assertFalse(checks[name])
                self.assertTrue(all(ok for other, ok in checks.items() if other != name))
        self.assertFalse(any(diag.judge_open({'status': 'refused', 'reason': 'fixed-s5diag-fresh-file'}, {'left': []}).values()))

    def test_open_check_renders_the_fresh_build_launcher_and_sweeps_only_its_own_job(self):
        worker, calls, saved = self.worker(healthy), [], {}

        def call(program, request, ev, prefix, *, root, timeout):
            calls.append({'program': program, 'request': request, 'prefix': prefix, 'root': root, 'timeout': timeout})
            return launcher_reply(worker, self.member) if prefix == 'open-check' else {'removed': [], 'left': []}
        ev = SimpleNamespace(save=lambda name, value: saved.update({name: value}))
        root = '/var/lib/woowbk-nextcloud-s5-' + '7' * 16
        fixture = {'archive': root + s5b.ARTIFACT_TAIL, 'sha256': 'ab' * 32, 'bytes': 100, 'provenance_sha256': 'cd' * 32}
        result = diag.open_check(fixture, ev, deadline=10_000.0, call=call, now=lambda: 1_000.0)
        self.assertEqual((result['status'], result['reason'], result['checks']),
                         ('passed', None, {name: True for name in s5.OPEN_CHECKS}))
        launcher, sweep = calls
        for value in ("LAYOUT='fresh-build'", f'PROOF_ROOT={root!r}', f"FIXTURE={fixture['archive']!r}",
                      f"PROVENANCE={root + '/owned/artifact/provenance.private.json'!r}", f"FIXTURE_SHA={'ab' * 32!r}",
                      'FIXTURE_BYTES=100', f"PROVENANCE_SHA={'cd' * 32!r}", f'WORKER_SHA={diag.WORKER_SHA!r}'):
            self.assertIn(value, launcher['program'])
        self.assertEqual((launcher['root'], launcher['request']['worker']), (True, diag.WORKER))
        q = launcher['request']['worker_request']
        self.assertEqual((q['schedule'], q['deadline'], result['job_id']), ([0], 1_000.0 + diag.OPEN_BUDGET, q['job_id']))
        self.assertTrue(q['job_id'].split('-')[1].startswith(diag.JOB_TAG))
        self.assertEqual((sweep['program'], sweep['request'], sweep['root']), (diag.SWEEP, {'job_id': q['job_id']}, False))
        self.assertIn('open-check-launcher.private.json', saved)
        for bad, reason in (({'archive': s5b.HISTORY.fixture}, 'open-check-fixture'), ({'sha256': 'x'}, 'open-check-fixture'),
                            ({'archive': '/tmp/root' + s5b.ARTIFACT_TAIL}, 'open-check-fixture')):
            with self.subTest(bad=sorted(bad)), self.assertRaisesRegex(ValueError, reason):
                diag.open_check(dict(fixture, **bad), ev, deadline=10_000.0, call=call, now=lambda: 1_000.0)
        with self.assertRaisesRegex(ValueError, 'open-check-no-time-left'):
            diag.open_check(fixture, ev, deadline=1_300.0, call=call, now=lambda: 1_000.0)


class FreshLauncherTests(unittest.TestCase):
    """The launcher in layout 'fresh-build' (S5-A's open check): only the literal fixture and provenance are checked."""
    setUp, overrides, launch, member = LauncherTests.setUp, LauncherTests.overrides, LauncherTests.launch, LauncherTests.member

    def test_the_fresh_build_launcher_hands_the_member_over_and_checks_the_literal_files(self):
        out = self.launch(LAYOUT='fresh-build', S5A_COMMAND_RECORDS=-1)   # the record count plays no part here
        raw, size = self.member()
        self.assertEqual((out['status'], out['worker']['received']['sha256'], out['proof_root_unchanged']),
                         ('ran', sha(raw), True))
        self.assertEqual(len(out['proof_root_before']['files']), 2)
        copy_path = self.dev.tmp / 'copy.tar'
        copy_path.write_bytes(self.dev.fixture.read_bytes())
        self.assertEqual(self.launch(LAYOUT='fresh-build', FIXTURE=str(copy_path))['reason'],
                         'fixed-s5diag-fresh-literal-path')
        os.chmod(self.dev.work, 0o750)
        self.assertEqual(self.launch(LAYOUT='fresh-build')['reason'], 'fixed-s5diag-fresh-owned')
        os.chmod(self.dev.work, 0o700)
        self.assertEqual(self.launch(LAYOUT='other')['reason'], 'fixed-s5diag-layout')


# ====================================================================== retiring the first build's proof root

class RetireTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.diag_root = self.tmp / 'diag-evidence'
        self.diag_root.mkdir()

    def diag_run(self, name='20261129T010000-5d1a0001', binding=None, **line):
        h = s5b.HISTORY
        folder = self.diag_root / name
        folder.mkdir()
        (folder / 'fixed-result.json').write_text(json.dumps(dict(
            {'phase': diag.PHASE, 'status': 'diagnosed', 'proof_root_unchanged': True, 'job_id': JOB,
             'verdict': 'missing-postgres-role'}, **line)))
        (folder / 'binding.json').write_text(json.dumps(binding or {'phase': diag.PHASE, 'fixture': h.fixture,
                                                                    'fixture_sha256': h.fixture_sha, 'proof_root': h.proof_root}))
        return folder

    def test_only_a_diagnosed_run_on_the_first_builds_root_admits_the_removal(self):
        info = diag.diagnostic_evidence(self.diag_run(), evidence_root=self.diag_root)
        self.assertEqual((info['job_id'], info['verdict']), (JOB, 'missing-postgres-role'))
        h = s5b.HISTORY
        faults = {'refused': {'status': 'refused'}, 'changed-root': {'proof_root_unchanged': False},
                  'other-tool': {'phase': 'other'},
                  'other-fixture': {'binding': {'phase': diag.PHASE, 'fixture': h.fixture, 'fixture_sha256': '0' * 64,
                                                'proof_root': h.proof_root}},
                  'other-root': {'binding': {'phase': diag.PHASE, 'fixture': h.fixture, 'fixture_sha256': h.fixture_sha,
                                             'proof_root': '/var/lib/woowbk-nextcloud-s5-' + '0' * 16}}}
        for number, (name, change) in enumerate(faults.items()):
            with self.subTest(fault=name), self.assertRaisesRegex(ValueError, 'retire-diagnostic-evidence'):
                diag.diagnostic_evidence(self.diag_run(f'run-{number}', **change), evidence_root=self.diag_root)
        outside = self.tmp / 'elsewhere'
        outside.mkdir()
        with self.assertRaisesRegex(ValueError, 'retire-diagnostic-evidence'):
            diag.diagnostic_evidence(outside, evidence_root=self.diag_root)
        (self.diag_root / 'link').symlink_to(self.diag_run('real'))
        with self.assertRaisesRegex(ValueError, 'retire-diagnostic-evidence'):
            diag.diagnostic_evidence(self.diag_root / 'link', evidence_root=self.diag_root)

    def retire(self, states, removal=None):
        calls = []

        def device(program, request=None, *, root=False, timeout=300):
            calls.append((program, request, root))
            if program == diag.RETIRED_STATE:
                return states.pop(0)
            if program == diag.RETIRE:
                return removal or {'status': 'removed', 'files': 348, 'bytes': 127600640}
            return {'active_jobs': 0}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = diag.retire({'evidence': 'x', 'job_id': JOB}, 'c' * 40, device=device, inventory=inventory_row,
                             evidence_root=self.tmp / 'retire')
        return rc, json.loads(out.getvalue().strip().splitlines()[-1]), calls

    def test_retire_removes_exactly_the_first_builds_root_after_proving_it(self):
        rc, record, calls = self.retire([{'present': True, 'valid': True}, {'present': False}])
        self.assertEqual((rc, record['status'], record['root']), (0, 'removed', s5b.HISTORY.proof_root))
        [removal] = [c for c in calls if c[0] == diag.RETIRE]
        self.assertEqual(removal[1:], ({'root': s5b.HISTORY.proof_root, 'removal': 'retired-after-the-diagnostic'}, True))
        ev = Path(record['private_evidence'])
        self.assertEqual(sorted(p.name for p in ev.iterdir()), ['before.private.json', 'fixed-result.json'])
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in ev.iterdir()))

    def test_retire_refuses_a_root_that_is_not_as_s5a_left_it_or_gone(self):
        for states in ([{'present': True, 'valid': False, 'reason': 'fixed-s5diag-proof-root-leaves'}], [{'present': False}]):
            with self.subTest(states=states):
                rc, record, calls = self.retire(list(states))
                self.assertEqual((rc, record['status'], record['reason']), (1, 'failed',
                                                                             'fixed-s5diag-retired-root-not-as-s5a-left-it'))
                self.assertFalse(any(c[0] == diag.RETIRE for c in calls))

    def overrides(self, dev):
        return {'PROOF_ROOT': str(dev.root), 'FIXTURE': str(dev.fixture), 'PROVENANCE': str(dev.provenance),
                'FIXTURE_SHA': dev.built['sha256'], 'FIXTURE_BYTES': dev.built['bytes'],
                'PROVENANCE_SHA': sha(dev.provenance.read_bytes()), 'S5A_COMMAND_RECORDS': 9,
                'OWNER': pwd.getpwuid(os.getuid()).pw_name, 'ROOT_UID': os.getuid()}

    def program(self, program, request):
        p = subprocess.run([sys.executable, '-I', '-c', program], input=json.dumps(request).encode(), capture_output=True,
                           timeout=300)
        return p.returncode, (json.loads(p.stdout) if p.returncode == 0 else p.stderr.decode())

    def test_the_device_programs_prove_and_remove_only_the_root_s5a_left(self):
        dev = DeviceRoot(self)
        values = self.overrides(dev)
        state = diag.retired_state_program(values)
        rc, before = self.program(state, {})
        self.assertEqual((rc, before['present'], before['valid'], before['fixture_sha256']),
                         (0, True, True, dev.built['sha256']))
        rc, refused = self.program(diag.retire_program(values), {'root': str(dev.root), 'removal': 'always'})
        self.assertNotEqual(rc, 0)
        self.assertIn('fixed-s5diag-retire-binding', refused)
        self.assertTrue(dev.root.exists())
        rc, removed = self.program(diag.retire_program(values), {'root': str(dev.root),
                                                                 'removal': 'retired-after-the-diagnostic'})
        self.assertEqual((rc, removed['status'], removed['files']), (0, 'removed', 2 + 7 + 9))
        self.assertFalse(dev.root.exists())
        self.assertTrue(dev.varlib.exists())
        self.assertEqual(self.program(state, {}), (0, {'present': False}))

    def test_a_changed_root_is_reported_by_the_state_and_never_removed(self):
        dev = DeviceRoot(self)
        dev.write('extra.json', b'{}')
        values = self.overrides(dev)
        rc, state = self.program(diag.retired_state_program(values), {})
        self.assertEqual((rc, state['valid'], state['reason']), (0, False, 'fixed-s5diag-proof-root-leaves'))
        rc, _ = self.program(diag.retire_program(values), {'root': str(dev.root), 'removal': 'retired-after-the-diagnostic'})
        self.assertNotEqual(rc, 0)
        self.assertTrue((dev.work / 'extra.json').exists() and dev.fixture.exists())

    def test_main_needs_the_diagnostic_evidence_one_mode_and_the_heavy_seat(self):
        clean = patch.object(diag.s5, 'checkout', return_value=('c' * 40, True))
        never = lambda *a, **k: (_ for _ in ()).throw(AssertionError('no lock or device step'))   # noqa: E731
        with patch.dict(os.environ, {'HEAVY_FREE': ''}), self.assertRaisesRegex(ValueError, 'heavy-seat-required'):
            diag.main(['--remove-retired-root', '--diagnostic-evidence', str(self.diag_run())])
        with patch.dict(os.environ, {'HEAVY_FREE': diag.LOCK}), clean, patch.object(diag, 'acquire', never):
            with self.assertRaisesRegex(ValueError, 'diagnostic-evidence-required'):
                diag.main(['--remove-retired-root'])
            with self.assertRaisesRegex(ValueError, 'one-mode-at-a-time'):
                diag.main(['--run', '--remove-retired-root'])
            with self.assertRaisesRegex(ValueError, 'retire-diagnostic-evidence'):   # not this tool's evidence area
                diag.main(['--remove-retired-root', '--diagnostic-evidence', str(self.diag_run('other'))])
        seen = []
        with patch.dict(os.environ, {'HEAVY_FREE': diag.LOCK}), clean, \
                patch.object(diag, 'diagnostic_evidence', lambda path: {'evidence': str(path)}), \
                patch.object(diag, 'acquire', lambda lock, timeout: seen.append(('lock', timeout))), \
                patch.object(diag, 'open', lambda path, mode: contextlib.nullcontext(path), create=True), \
                patch.object(diag, 'retire', lambda info, commit: seen.append((info, commit)) or 0):
            self.assertEqual(diag.main(['--remove-retired-root', '--diagnostic-evidence', '/x']), 0)
        self.assertEqual(seen, [('lock', diag.LOCK_TIMEOUT), ({'evidence': '/x'}, 'c' * 40)])


if __name__ == '__main__':
    unittest.main()
