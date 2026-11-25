"""HA import, Omnigent part (ha_omnigent.py): the check and the whole product conversion against a fake owner whose
podman answers like the lab's -- versions, HA's hardened cluster, the trusted schema (this device's own, captured in
one snapshot and proven unchanged; B1-01), only HA's data loaded by a role without privileges, the new cluster's
schema and contents audited, this device's admin and runner accounts kept, test mode, the server volume with HA's
artifacts and cookie key (CONTRACT section 9). Team E2."""
import contextlib
import copy
import gzip
import io
import json
import re
import tarfile
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import ha_odoo, ha_omnigent, habackup, haimport, haissues, hatarget, jobs
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import hab1fakes as fk
from . import hafixtures as hx

SLUG = '1b7b4ce7_woow-omnigent'
AGENT = 'a' * 32
BUNDLE = f'{AGENT}/{"b" * 64}'
BLOB = 'c' * 32
ALEMBIC = 'd0a1f879a01d'
HASH = '$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo'
PAUSE = ha_omnigent.PAUSE_SQL.strip().rstrip(';')
QUADLETS = {
    'omnigent-postgres.container': b'[Container]\nContainerName=omnigent-postgres\n'
                                   b'Image=docker.io/library/postgres:16.15-alpine3.24\n'
                                   b'Volume=omnigent-postgres.volume:/var/lib/postgresql/data\n'
                                   b'Environment=POSTGRES_DB=omnigent\nEnvironment=POSTGRES_USER=omnigent\n'
                                   b'Environment=POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password\n'
                                   b'Secret=omnigent-postgres-password,type=mount,target=/run/secrets/postgres-password,'
                                   b'mode=0400\n',
    'omnigent-server.container': b'[Container]\nContainerName=omnigent-server\n'
                                 b'Image=ghcr.io/omnigent-ai/omnigent-server:v0.21.0\n'
                                 b'Volume=omnigent-server.volume:/data\n'
                                 b'Secret=omnigent-database-url,type=env,target=DATABASE_URL\n'
                                 b'Environment=OMNIGENT_ACCOUNTS_INIT_ADMIN_USERNAME=admin\n',
    'omnigent-runner.container': b'[Container]\nContainerName=omnigent-runner\nImage=localhost/woow-omnigent-runner:0.21.0-2\n'
                                 b'Volume=omnigent-pi.volume:/data/pi-agent\nEnvironment=OMNIGENT_RUNNER_USERNAME=operator\n',
    'omnigent-postgres.volume': b'[Volume]\nVolumeName=omnigent-postgres-data\n',
    'omnigent-server.volume': b'[Volume]\nVolumeName=omnigent-server-data\n',
    'omnigent-pi.volume': b'[Volume]\nVolumeName=omnigent-pi-data\n',
    'omnigent.network': b'[Network]\n',
}
TOC = (b';\n; Archive created\n;\n2; 3079 16385 EXTENSION - pg_trgm \n'
       b'3; 0 0 COMMENT - EXTENSION pg_trgm \n'
       b'210; 1259 16400 TABLE public users omnigent\n'
       b'211; 1259 16401 TABLE public alembic_version omnigent\n'
       b'212; 2604 16402 DEFAULT public users created_at omnigent\n'
       b'3456; 0 16400 TABLE DATA public users omnigent\n'
       b'3457; 0 16401 TABLE DATA public alembic_version omnigent\n'
       b'3458; 0 0 SEQUENCE SET public conversation_items_id_seq omnigent\n'
       b'3500; 2606 16500 CONSTRAINT public users users_pkey omnigent\n'
       b'3501; 2606 16501 CHECK CONSTRAINT public users ck_users_evil omnigent\n'
       b'3600; 1259 16600 INDEX public ix_conv_title_trgm omnigent\n')
DATA_LINES = ['3456; 0 16400 TABLE DATA public users omnigent', '3457; 0 16401 TABLE DATA public alembic_version omnigent',
              '3458; 0 0 SEQUENCE SET public conversation_items_id_seq omnigent']
COLUMNS = [['users', 'id', 'character varying(128)', True, '', ''], ['users', 'is_admin', 'boolean', True, '', ''],
           ['scheduled_tasks', 'state', 'integer', True, '', '']]
SEQUENCE = ['conversation_items_id_seq', 'bigint', 1, 1, 9223372036854775807, 1, 1, False, 'conversation_items.id']
# pg_restore 16.16's own lines around SEQUENCE SET entries in `pg_restore -f - -L <list>` (seen in the lab)
SEQ_SCRIPT_HEAD = ('--\n-- PostgreSQL database dump\n--\n\n\\restrict MFQHEcMGZEG4IdZN2cpRjhUeEY3QP6WXheUlcz80zZn6\n\n'
                   '-- Dumped from database version 16.16\n-- Dumped by pg_dump version 16.16\n\n'
                   'SET statement_timeout = 0;\nSET lock_timeout = 0;\nSET idle_in_transaction_session_timeout = 0;\n'
                   "SET client_encoding = 'UTF8';\nSET standard_conforming_strings = on;\n"
                   "SELECT pg_catalog.set_config('search_path', '', false);\nSET check_function_bodies = false;\n"
                   'SET xmloption = content;\nSET client_min_messages = warning;\nSET row_security = off;\n\n'
                   '--\n-- Name: conversation_items_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres\n--\n\n')
# pg_controldata 16's output (an excerpt): the cluster's state is one line among others
CONTROLDATA = (b'pg_control version number:            1300\n'
               b'Catalog version number:               202307071\n'
               b'Database system identifier:           7442424242424242424\n'
               b'Database cluster state:               %s\n'
               b'pg_control last modified:             Tue Nov 24 00:00:00 2026\n'
               b'Latest checkpoint location:           0/1A2B3C8\n')


def signature():
    """The trusted schema's signature as SCHEMA_SIGNATURE_SQL answers it (a short excerpt of Omnigent's)."""
    found = {key: [] for key in ha_omnigent.SIGNATURE_KEYS}
    found.update(relations=[[name, 'r', 'p', False, False, '', False] for name in sorted(ha_omnigent.KNOWN_TABLES)]
                 + [[SEQUENCE[0], 'S', 'p', False, False, '', False]],
                 columns=[row + ['false' if row[1] == 'is_admin' else '', ''] for row in COLUMNS],
                 constraints=[['users', 'users_pkey', 'p', 'PRIMARY KEY (id)', False, False, True, False]],
                 indexes=[['users', 'users_pkey', 'CREATE UNIQUE INDEX users_pkey ON public.users USING btree (id)']],
                 sequences=[list(SEQUENCE)], extensions=[['pg_trgm', '1.6', 'public'], ['plpgsql', '1.0', 'pg_catalog']],
                 other={name: 0 for name in ha_omnigent.OTHER_CATALOGS})
    return found


def addon_tar(*, version='0.1.23', cookie=True, extra=(), artifacts=True, pg_version=b'16\n'):
    addon = {'user': {'version': version, 'image': 'ghcr.io/woowtech/woow-ha-omnigent-amd64',
                      'options': {'admin_password': 'ha-admin-secret'}},
             'system': {'slug': 'woow-omnigent', 'name': 'Woow Omnigent'}, 'version': version}
    art = 'data/omnigent-home/.omnigent/artifacts'
    entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': json.dumps(addon).encode()},
               {'name': 'data', 'type': 'dir'}, {'name': 'data/options.json', 'data': b'{"admin_password": "x"}'},
               {'name': 'data/postgres', 'type': 'dir', 'mode': 0o700},
               {'name': 'data/postgres/PG_VERSION', 'data': pg_version},
               {'name': 'data/postgres/base', 'type': 'dir'}, {'name': 'data/postgres/base/1', 'type': 'dir'},
               {'name': 'data/postgres/base/1/1259', 'data': b'page'},
               {'name': 'data/postgres/pg_hba.conf', 'data': b'host all all 0.0.0.0/0 trust\n'},
               {'name': 'data/postgres/postgresql.conf', 'data': b"shared_preload_libraries = 'evil'\n"},
               {'name': 'data/postgres/postmaster.pid', 'data': b'1\n'},
               {'name': 'data/omnigent-home', 'type': 'dir'}, {'name': 'data/omnigent-home/.omnigent', 'type': 'dir'},
               {'name': 'data/omnigent-home/.omnigent/telemetry.json', 'data': b'{"installation_id": "ha"}'},
               {'name': 'data/artifacts', 'type': 'dir'}, {'name': 'data/sharing_mode', 'data': b'public'}]
    if artifacts:
        entries += [{'name': art, 'type': 'dir'}, {'name': f'{art}/{AGENT}', 'type': 'dir'},
                    {'name': f'{art}/{BUNDLE}', 'data': b'bundle'}, {'name': f'{art}/{BLOB}', 'data': b'blob'},
                    {'name': f'{art}/.cache', 'type': 'dir'}, {'name': f'{art}/.cache/x', 'data': b'cache'}]
        if cookie:
            entries.append({'name': f'{art}/accounts-cookie-secret', 'data': b'f' * 64, 'mode': 0o600})
    return gzip.compress(hx.tar_bytes(entries + list(extra)), mtime=0)


class Owner(fk.Owner):
    """The fakes' owner that can also start and stop the units of this device (hatarget.ensure_running)."""

    def systemctl(self, *args, **kwargs):
        self.calls.append(('systemctl', *args))
        self.world.units.append(args[:3])
        if args[0] == 'start':
            self.world.db_stopped = False
        elif args[0] == 'stop':
            self.world.db_stopped = True
        return Result(0, b'', b'')


class World(fk.World):
    def __init__(self):
        super().__init__()
        self.owner = Owner(self)
        self.db_stopped = False               # this device's own database is not running (until its unit is started)
        self.units = []                       # (verb, '--', unit) of every systemctl call
        self.quadlets = {'omnigent': QUADLETS}
        self.ha_alembic = [ALEMBIC]
        self.live_alembic = [ALEMBIC]
        self.objects = {'tables': list(ha_omnigent.TABLES) + ['alembic_version'], 'schemas': [], 'functions': 0,
                        'triggers': 0, 'views': 0, 'rules': 0, 'policies': 0, 'extensions': ['pg_trgm', 'plpgsql'],
                        'encoding': 'UTF8', 'collate': 'C'}
        self.counts = {table: 2 for table in ha_omnigent.TABLES}
        self.counts['alembic_version'] = 1
        self.ha_users = ['alice', 'bob']
        self.keys = {'bundles': [BUNDLE], 'blobs': [BLOB]}
        self.toc = TOC
        self.live_rows = [{'workspace_id': 0, 'id': 'admin', 'is_admin': True, 'deleted_at': None,
                           'password_hash': HASH, 'created_at': 1, 'last_login_at': None, 'account_generation': None},
                          {'workspace_id': 0, 'id': 'operator', 'is_admin': False, 'deleted_at': None,
                           'password_hash': HASH + 'op', 'created_at': 1, 'last_login_at': None,
                           'account_generation': None}]
        self.written = {}
        self.ha_columns, self.live_columns = copy.deepcopy(COLUMNS), copy.deepcopy(COLUMNS)
        self.ha_signature, self.live_signature = signature(), signature()
        self.restored_signature = None        # None: the new cluster's schema is the trusted one
        self.live_reads = 0                   # SCHEMA_SIGNATURE_SQL answers of the live database so far
        self.after_capture = None             # a change of the live schema once the snapshot was taken
        self.snapshot_columns = None          # the snapshot's columns when they differ from the live ones
        self.snapshots = []                   # the snapshot scripts the capture ran in the live database
        self.audit = {'roles': ['omnigent'], 'role_settings': 0, 'auto_conf': 0, 'large_objects': 0}
        self.exec_users = []                  # (--user or None, podman exec argv)
        self.seq_script = SEQ_SCRIPT_HEAD + "SELECT pg_catalog.setval('public.conversation_items_id_seq', 7, true);\n"
        self.exec_failure = None              # (role, command) -> a failing Result, or None
        self.cluster_state = b'shut down'     # what pg_controldata says of the new cluster after its stop
        self.extra_members = {}               # volume (or throwaway role) -> members its export holds besides the usual
        self.live_major = 16                  # what this device's database answers to server_version_num / 10000 (O-18)
        self.superuser = []                   # the kinds of object only a database superuser can make that HA's database holds
        self.toc_declared = None              # what the header of `pg_restore -l` says (None: the number of entries)

    def podman(self, args, data, stdout):
        if self.db_stopped and args[:2] == ['container', 'inspect'] and args[-1] == 'omnigent-postgres':
            return Result(0, b'false\n', b'')
        if self.db_stopped and args[:1] == ['exec'] and 'omnigent-postgres' in args:
            from woowbackup.podman import CommandError
            raise CommandError('podman exec 執行失敗（結束碼 125）。', returncode=125,
                               stderr=b'Error: no container with name or id "omnigent-postgres": no such container')
        if args[:1] == ['exec']:
            self.exec_users.append((args[args.index('--user') + 1] if '--user' in args else None, list(args)))
        if args[:5] == ['exec', '-i', 'omnigent-postgres', 'sh', '-s']:
            # capture_consistent_target_schema: the live database's columns line, then its schema-only archive.
            self.snapshots.append((args[5:], data))
            columns = self.snapshot_columns if self.snapshot_columns is not None else self.live_columns
            stdout.write(json.dumps(columns).encode() + b'\nPGDMP-trusted-schema')
            if self.after_capture:
                self.after_capture(self)
            return Result(0, None, b'')
        return super().podman(args, data, stdout)

    def run(self, role, image, command, options, data):
        if role == 'controldata':
            return Result(0, CONTROLDATA % self.cluster_state, b'')
        return Result(0, b'', b'')

    def exec(self, role, command, data, stdout):
        failed = self.exec_failure(role, command) if self.exec_failure else None
        if failed is not None:
            return failed
        if command[0] == 'pg_dump':
            stdout.write(b'PGDMP-' + role.encode())
            return Result(0, None, b'')
        if command[:2] == ['pg_restore', '-l']:
            count = len(re.findall(rb'(?m)^\s*\d+;\s+\d+\s+\d+\s', self.toc))
            declared = count if self.toc_declared is None else self.toc_declared
            return Result(0, b';\n;     TOC Entries: %d\n;\n' % declared + self.toc, b'')   # the header pg_restore prints
        if command[:3] == ['pg_restore', '-f', '-']:   # the selected SEQUENCE SET entries as pg_restore prints them
            return Result(0, self.seq_script.encode(), b'')
        if command[:2] == ['sh', '-c']:
            self.written[command[2].rsplit('> ', 1)[1]] = data
        return Result(0, b'', b'')

    def executed(self, role):
        return [statement for _db, statement, _t in self.psql[role].executed] if role in self.psql else []

    def answer(self, role, sql, database):
        if sql == ha_omnigent.SCHEMA_COLUMNS_SQL:
            return {'omnigent-postgres': self.live_columns, 'hapg': self.ha_columns}.get(role, self.live_columns)
        if sql == ha_omnigent.SCHEMA_SIGNATURE_SQL:
            if role == 'omnigent-postgres':
                self.live_reads += 1
                return self.live_signature
            if role == 'hapg':
                return self.ha_signature
            return self.restored_signature if self.restored_signature is not None else self.live_signature
        if sql == ha_omnigent.AUDIT_SQL and role == 'omni-db':
            return self.audit
        if role == 'omnigent-postgres':  # the live database (read only)
            if 'server_version_num' in sql:
                return self.live_major
            if 'alembic_version' in sql:
                return self.live_alembic
            if sql.startswith('SELECT coalesce(json_agg(u ORDER BY u.id)'):
                return self.live_rows
        if role in ('hapg', 'omni-db'):
            if sql == ha_odoo.DATABASES_SQL:
                return [['omnigent', 9000, 'C', 'C']]
            if sql == ha_omnigent.OBJECTS_SQL:
                return self.objects
            if sql == ha_omnigent.HAS_ALEMBIC_SQL:
                return True
            if sql == ha_omnigent.ALEMBIC_SQL:
                return self.ha_alembic
            if sql == ha_omnigent.DETAIL_SQL:
                return {'users': 2, 'admins': 1, 'user_ids': self.ha_users, 'conversations': 5,
                        'scheduled_tasks': 2, 'scheduled_tasks_active': 1, 'hosts': 1, 'agents': 3, 'files': 1,
                        'public_sessions': 1, 'connections_with_secrets': 0}
            if sql == ha_omnigent.KEYS_SQL:
                if role == 'omni-db' and any('SET bundle_location' in statement for statement in self.executed('omni-db')):
                    return dict(self.keys, bundles=[k for k in self.keys.get('bundles', []) if ha_omnigent.key_ok(k)])
                return self.keys
            if sql == ha_odoo.SUPERUSER_SQL:
                return list(self.superuser)
            if sql.startswith('SELECT json_build_object(') and '(SELECT count(*) FROM' in sql:
                counts = dict(self.counts)
                if role == 'omni-db':
                    counts['users'] += len(self.carried())
                return {name: counts[name] for name in re.findall(r"'([a-z_]+)', \(SELECT", sql)}
            if sql.startswith('SELECT coalesce(json_agg(id)'):
                return [u for u in self.ha_users if u in sql]
            if sql == ha_omnigent.ACTIVE_SQL:
                return 0 if PAUSE in self.executed('omni-db') else 1
        return None

    def restricted(self):
        """The SQL the role without privileges (woowbk_restore) ran in the new cluster."""
        return [data.decode() for role, cmd, data in self.execs if role == 'omni-db' and cmd[0] == 'psql'
                and cmd[cmd.index('-U') + 1] == ha_omnigent.RESTORE_ROLE and data]

    def carried(self):
        """The accounts the restricted role added back (the rows of its INSERT ... json_populate_recordset)."""
        rows = []
        for sql in self.restricted():
            match = re.search(r"json_populate_recordset\(NULL::users, '(.*)'::json\)", sql, re.S)
            if match:
                rows += json.loads(match.group(1).replace("''", "'"))
        return rows

    def members(self, volume):
        if volume == 'omnigent-server-data':
            return [{'name': '.', 'type': 'dir', 'uid': 0, 'gid': 0},
                    {'name': 'artifacts', 'type': 'dir', 'uid': 0, 'gid': 0},
                    {'name': 'artifacts/accounts-cookie-secret', 'data': b'live-cookie', 'mode': 0o600},
                    {'name': f'artifacts/{"e" * 32}', 'type': 'dir'}, {'name': 'sharing_mode', 'data': b'off'}]
        if volume == 'omnigent-pi-data':
            return [{'name': '.', 'type': 'dir', 'uid': 0}, {'name': 'auth.json', 'data': b'pi-login'}]
        return [{'name': '.', 'type': 'dir', 'uid': 70, 'gid': 70, 'mode': 0o700},
                {'name': 'PG_VERSION', 'data': b'16\n', 'uid': 70, 'gid': 70, 'mode': 0o600}]

    def export(self, volume):
        return fk.tar_of(self.members(volume) + self.extra_members.get(fk.role_of(volume), []))

    def exported(self):
        """The throwaway roles and live volumes `podman volume export` read so far, in order."""
        return [fk.role_of(call[-1]) for call in self.owner.calls if call[:3] == ('relay', 'volume', 'export')]

    def forget(self):
        """The next conversion of the same test starts with nothing recorded."""
        for record in (self.runs, self.execs, self.exec_users, self.snapshots, self.psql, self.written, self.imported,
                       self.manifests, self.volume_data, self.owner.calls):
            record.clear()
        self.live_reads = 0


class OmnigentCase(fk.ConversionCase):
    world_class = World

    def setUp(self):
        super().setUp()
        patcher = mock.patch('woowbackup.adapters.quadlet_postgres.loopback_get',
                             side_effect=lambda url, timeout: self.info(url))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(hatarget, '_sleep', lambda _seconds: None)   # the pauses between tries
        patcher.start()
        self.addCleanup(patcher.stop)
        self.server_version = '0.21.0'
        self.addCleanup(jobs.unmask_secret, HASH)
        self.addCleanup(jobs.unmask_secret, HASH + 'op')

    @staticmethod
    def issues(result, issue_id=None, level=None):
        """The issues of a check result (optionally one id / one level)."""
        return [i for i in result['issues'] if issue_id in (None, i['id']) and level in (None, i['level'])]

    def confirmed(self, result):
        """`acknowledged` of a conversion that confirms every line of this check result."""
        return {'omnigent': [i['key'] for i in result['issues'] if i['level'] == 'confirm']}

    def check_one(self, **upload):
        return self.check(self.upload_omnigent(**upload), ['omnigent'])[0]

    @contextlib.contextmanager
    def answering(self, role, wanted, value, *, skip=0):
        """`role`'s answer to the statement `wanted` (its whole text or its start) is `value`, after `skip` answers as
        usual."""
        real, asked = self.world.answer, []

        def answer(found, sql, database):
            if found == role and sql.startswith(wanted):
                asked.append(sql)
                if len(asked) > skip:
                    return value
            return real(found, sql, database)
        self.world.answer = answer
        try:
            yield
        finally:
            self.world.answer = real
        self.assertGreater(len(asked), skip, 'the statement was asked')

    def assert_nothing_loaded(self):
        self.assertFalse([cmd for role, cmd, _d in self.world.execs if role == 'omni-db' and cmd[0] == 'pg_restore'
                          and '-U' in cmd and ha_omnigent.RESTORE_ROLE in cmd], 'no HA data was loaded')
        self.assertEqual(self.storage.list_backups(), [])

    def info(self, url):
        self.assertEqual(url, 'http://127.0.0.1:8000/v1/info')
        if self.server_version is None:
            raise OSError('connection refused')
        return 200, json.dumps({'server_version': self.server_version, 'needs_setup': False}).encode()

    def catalog_apps(self):
        return {'omnigent': fk.app('omnigent', 'Omnigent 協作平台',
                                   volumes=[{'name': 'omnigent-postgres-data'}, {'name': 'omnigent-server-data'},
                                            {'name': 'omnigent-pi-data'}],
                                   secrets=[{'name': 'omnigent-postgres-password'}, {'name': 'omnigent-database-url'}],
                                   health=[{'type': 'http', 'url': 'http://127.0.0.1:8000/health'}])}

    def upload_omnigent(self, **kwargs):
        return self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', addon_tar(**kwargs))], hx.ha_doc(addons=(SLUG,))))


class CheckTests(OmnigentCase):
    def test_has_pg_version_and_backup_name_cannot_forge_a_job_log_line(self):
        """secreview SR-6 (real in the lab: attack v7): HA's PG_VERSION (PostgreSQL reads only the number of its first
        token, '16.') reaches the job log as HA wrote it; the HA backup's name is cleaned when the file is read
        (habackup.clean_text, HAOS parity lane READ). Through the real JobStore every message stays one line without control characters: no forged
        line reaches the page."""
        from types import SimpleNamespace
        ha_id = self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', addon_tar(pg_version=b'16.\x0bFORGED OK\n'))],
                                           hx.ha_doc(addons=(SLUG,), name='WOOW FORGED 轉換完成：全部成功')))
        self.check(ha_id, ['omnigent'])
        logged = [str(message) for message in self.reporter.logs]
        self.assertTrue(any('PostgreSQL 16.\x0bFORGED' in m for m in logged), 'the source: HA text as it is')
        self.assertTrue(any('WOOW FORGED' in m for m in logged), 'the name: cleaned when the file is read (habackup)')
        (self.root / 'joblog').mkdir()
        store = jobs.JobStore(SimpleNamespace(jobs=str(self.root / 'joblog')))
        job = jobs.new_job_id()
        for message in logged:
            store.append_log(job, message)
        read = store.read_log(job, limit=10000)
        self.assertEqual(len(read), len(logged))
        self.assertFalse([line for line in read if line.startswith('FORGED')])
        self.assertFalse([line for line in read if re.search(r'[\x00-\x1f\x7f-\x9f  ]', line)])

    def test_has_text_cannot_reorder_a_message_or_a_log_line(self):
        """The verifier's SR-6 gap: a table name of HA's database (HA's backup name too, until habackup.clean_text) can carry a Unicode bidirectional control; U+202E reverses how the rest of the line reads on the
        page. The check's blockers show it as '?' (hacommon.names) and, through the real JobStore, no job log line
        keeps one (jobs.LOG_CONTROL_RE)."""
        from types import SimpleNamespace
        bidi = set('\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069')
        self.world.objects = dict(self.world.objects, tables=self.world.objects['tables'] + ['evil\u202eLIAF'])
        ha_id = self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', addon_tar())],
                                           hx.ha_doc(addons=(SLUG,), name='WOOW\u202e\u2066 LIAF')))
        result = self.check(ha_id, ['omnigent'])[0]
        self.assertTrue(result['importable'])
        listed = [item for issue in self.issues(result, 'omnigent.skipped') for item in issue['items']]
        self.assertEqual(listed, ['資料表 evil LIAF'], 'a name of HA is an item, shown with a space for every invisible character')
        shown = json.dumps(result, ensure_ascii=False)
        self.assertFalse(set(shown) & bidi)
        logged = [str(message) for message in self.reporter.logs]
        self.assertTrue(any('WOOW   LIAF' in m for m in logged), 'the name: cleaned when the file is read (habackup)')
        (self.root / 'joblog').mkdir()
        store = jobs.JobStore(SimpleNamespace(jobs=str(self.root / 'joblog')))
        job = jobs.new_job_id()
        for message in logged:
            store.append_log(job, message)
        read = store.read_log(job, limit=10000)
        self.assertEqual(len(read), len(logged))
        self.assertFalse([line for line in read if set(line) & bidi])
        self.assertTrue(any('WOOW   LIAF' in line for line in read))

    def test_a_clean_backup(self):
        result = self.check(self.upload_omnigent(), ['omnigent'])[0]
        self.assertEqual((result['ok'], result['importable'], result['blockers'], result['version'],
                          result['target_version']), (True, True, [], '0.1.23', '0.21.0'))
        section = result['omnigent']
        self.assertEqual((section['omnigent_version'], section['alembic'], section['users'], section['artifact_files']),
                         ('0.21.0', ALEMBIC, 2, 3))
        self.assertEqual(section['override_files'], ['sharing_mode'])
        self.assertEqual(section['account_conflicts'], [])
        self.assertEqual([i['items'] for i in self.issues(result, 'omnigent.settings-not-moved')], [['sharing_mode']])
        self.assertTrue(any('1 個啟用中的排程' in w for w in result['warnings']))
        self.assertEqual(self.issues(result, level='confirm'), [], 'nothing is left out: nothing to confirm')
        hapg = self.runs('hapg')[0]
        self.assertIn('--read-only', hapg[3])
        self.assertEqual(hapg[3]['--network'], ['none'])
        self.assertTrue(any(v.endswith(':rw,noexec,nosuid,nodev') for v in hapg[3]['--volume']))
        self.assertIn('shared_preload_libraries=', hapg[2])
        self.assertFalse(self.runs('omni-db'), 'a check changes nothing')
        staged = self.world.imported['hapg']
        with tarfile.open(fileobj=io.BytesIO(staged)) as tar:
            members = {m.name: m for m in tar.getmembers()}
            hba = tar.extractfile('pg_hba.conf').read()
        self.assertNotIn('postmaster.pid', members)
        self.assertEqual(hba, ha_odoo.PG_HBA)
        self.assertEqual({(m.uid, m.gid) for m in members.values()}, {(70, 70)})

    def test_versions(self):
        """O-23, O-24, O-25: a version the table does not know, a version that cannot be read and two different ones are
        notices; the data decides: another structure version stops this app only."""
        for kwargs, words in (({'version': '0.1.19'}, 'HA 的 Omnigent 是 0.20.0'), ({'version': '0.9.0'}, '還不認得')):
            result = self.check_one(**kwargs)
            self.assertTrue(result['importable'], kwargs)
            self.assertTrue(any(words in issue['message'] for issue in self.issues(result, level='notice')), kwargs)
        self.assertEqual([i['id'] for i in self.issues(self.check_one(version='0.1.19'), level='notice')
                          if 'version' in i['id']], ['omnigent.version-different'])
        self.assertEqual([i['id'] for i in self.issues(self.check_one(version='0.9.0'), level='notice')
                          if 'version' in i['id']], ['version.addon-unknown'])
        self.world.ha_alembic = ['older']
        result = self.check_one()
        self.assertFalse(result['importable'])
        self.assertEqual([i['id'] for i in self.issues(result, level='stop')], ['omnigent.alembic-different'])
        self.assertTrue(any('資料庫結構版本不同' in b for b in result['blockers']))
        self.world.ha_alembic = [ALEMBIC]
        self.server_version = None
        result = self.check_one()
        self.assertTrue(result['importable'])
        self.assertEqual([i['id'] for i in self.issues(result, level='notice') if i['id'].startswith('version')],
                         ['version.target-unknown'])
        self.assertEqual(result['target_version'], '')

    def test_what_the_check_leaves_out_and_what_it_still_refuses(self):
        """HAOS would restore all of it; this device keeps its own structure: a table, an object or a link that is not
        Omnigent's is left out and listed in ONE line to confirm (O-12, O-14), a missing login key is a notice (O-20), files
        the database names that the backup lacks and locations that could leave the store are lines of their own (O-22,
        O-21). What stays a stop: another structure version, another columns."""
        self.world.objects = dict(self.world.objects, functions=1, tables=self.world.objects['tables'] + ['evil'])
        result = self.check_one(cookie=False)
        self.assertTrue(result['importable'])
        skipped = self.issues(result, 'omnigent.skipped')
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]['level'], 'confirm')
        self.assertEqual(sorted(skipped[0]['items']), ['函式', '資料表 evil'])
        self.assertFalse(result['ok'], 'a line to confirm: the older page shows the app as not ready')
        self.assertEqual([i['id'] for i in self.issues(result, 'omnigent.cookie-missing')], ['omnigent.cookie-missing'])
        self.assertIn('重新登入', ' '.join(i['message'] for i in self.issues(result, 'omnigent.cookie-missing')))
        self.world.objects = dict(self.world.objects, functions=0, tables=list(ha_omnigent.TABLES) + ['alembic_version'])
        self.world.keys = {'bundles': [BUNDLE, f'{AGENT}/{"9" * 64}'], 'blobs': ['../../etc']}
        result = self.check_one()
        self.assertTrue(result['importable'])
        missing = self.issues(result, 'omnigent.files-missing')
        self.assertEqual((len(missing), missing[0]['level'], missing[0]['items']), (1, 'confirm', [f'{AGENT}/{"9" * 64}']))
        self.assertIn('1 個代理程式包或檔案', missing[0]['message'])
        skipped = self.issues(result, 'omnigent.skipped')
        self.assertEqual([item for issue in skipped for item in issue['items']],
                         ['會跑出檔案區的代理程式位置（會被清空） ../../etc'])
        for stopped in ({'cookie': True}, {}):
            self.world.ha_columns = COLUMNS + [['users', 'extra', 'integer', False, '', '']]
            self.assertFalse(self.check_one(**stopped)['importable'])
            self.world.ha_columns = list(COLUMNS)

    def test_names_from_has_database_cannot_forge_lines(self):
        """secreview SR-4: a table, schema or alembic name of HA's database (control characters allowed in quoted
        PostgreSQL names, proven in the lab: the check's blocker carried a line break) never reaches the job log or
        the page with a control character."""
        forged = 'evil\n轉換完成\x1b[32m'
        self.world.objects = dict(self.world.objects, tables=self.world.objects['tables'] + [forged],
                                  schemas=['s\r\nx'])
        self.world.ha_alembic = ['older\nline']
        result = self.check(self.upload_omnigent(), ['omnigent'])[0]
        self.assertFalse(result['ok'])
        text = json.dumps(result, ensure_ascii=False)
        self.assertIn('evil 轉換完成 [32m', text, 'an item: every invisible character is a space')
        self.assertIn('older?line', text, 'a message: every invisible character is a ?')
        for blocker in result['blockers'] + [result['omnigent']['alembic']] + [
                item for issue in result['issues'] for item in issue['items']]:
            self.assertIsNone(re.search(r'[\x00-\x1f\x7f]', blocker), blocker)

    def test_a_different_schema_is_a_blocker_naming_the_tables(self):
        self.world.ha_columns = COLUMNS + [['users', 'extra', 'integer', False, '', '']]
        result = self.check(self.upload_omnigent(), ['omnigent'])[0]
        self.assertFalse(result['ok'])
        self.assertEqual([b for b in result['blockers'] if '資料庫結構不同' in b],
                         [ha_omnigent.schema_blocker(['users']) + ha_omnigent.ACTION_UNCHANGED])
        self.assertEqual([i['id'] for i in self.issues(result, level='stop')], ['omnigent.schema-different'])
        self.assertEqual(self.world.live_reads, 1, "the live schema is read once, read only")
        self.assertFalse(self.runs('omni-db'), 'a check changes nothing')

    def test_a_same_named_account_is_a_warning(self):
        self.world.ha_users = ['admin', 'alice']
        result = self.check(self.upload_omnigent(), ['omnigent'])[0]
        self.assertTrue(result['ok'])
        self.assertEqual(result['omnigent']['account_conflicts'], ['admin'])
        self.assertEqual([i['items'] for i in self.issues(result, 'omnigent.account-conflict')], [['admin']])


class ConvertTests(OmnigentCase):
    def restores(self):
        """Every pg_restore that writes into the new cluster: (role it runs as, argv, what it read)."""
        return [(cmd[cmd.index('-U') + 1], cmd, data) for role, cmd, data in self.world.execs
                if role == 'omni-db' and cmd[0] == 'pg_restore' and '-U' in cmd]

    def assert_nothing_loaded(self):
        self.assertFalse([r for r in self.restores() if r[0] == ha_omnigent.RESTORE_ROLE], 'no HA data was loaded')
        self.assertEqual(self.storage.list_backups(), [])

    def test_the_whole_conversion_in_test_mode(self):
        result = self.convert(self.upload_omnigent(), ['omnigent'], test_mode=True)
        imp = result['ha_import']
        self.assertEqual(imp['apps'], ['omnigent'])
        self.assertTrue(any('admin、operator' in line for line in imp['notes']), imp['notes'])
        self.assertTrue(any('資料庫結構' in line and '這台' in line for line in imp['notes']), imp['notes'])
        self.assertTrue(any('runner' in line for line in imp['reminders_by_app']['omnigent']))
        self.assertTrue(any('暫停 1 個排程' in line for line in imp['reminders_by_app']['omnigent']))
        self.assertFalse(any('MCP 管理' in line for line in imp['reminders_by_app']['omnigent']), 'no admin app here')
        # The new cluster: the live image, environment and secret, hardened like HA's.
        new = self.runs('omni-db')[0]
        self.assertEqual(new[1], 'docker.io/library/postgres:16.15-alpine3.24')
        self.assertIn('POSTGRES_USER=omnigent', new[3]['--env'])
        self.assertEqual(new[3]['--secret'], ['omnigent-postgres-password,type=mount,target=/run/secrets/postgres-password,'
                                              'mode=0400'])
        self.assertIn('--read-only', new[3])
        self.assertTrue(any(v.endswith(':rw,noexec,nosuid,nodev') for v in new[3]['--volume']))
        # HA's own cluster is gone before the new one starts; the new one is ready when it answers on TCP (the image's
        # temporary server of its first start listens on the socket only).
        steps = [(' '.join(call[:2] if call[0] == 'volume' else call[:1]),
                  [fk.role_of(a) for a in call if a.startswith(f'woowbk-{self.job_id}-') and ':' not in a])
                 for call in self.world.owner.calls]
        before = steps[:steps.index(('run', ['omni-db']))]
        self.assertIn(('rm', ['hapg']), before)
        self.assertIn(('volume rm', ['hapg']), before)
        self.assertIn(['pg_isready', '-q', '-U', 'omnigent', '-h', '127.0.0.1', '-p', '5432'],
                      [cmd for role, cmd, _d in self.world.execs if role == 'omni-db'])
        # The trusted schema: this device's, from one snapshot with the live revision; read before and after.
        self.assertEqual(len(self.world.snapshots), 1)
        self.assertEqual(self.world.snapshots[0][0], ['--', 'omnigent', 'omnigent'])
        self.assertIn(json.dumps([ALEMBIC]).encode(), self.world.snapshots[0][1])
        self.assertEqual(self.world.live_reads, 2, 'the live schema before and after the capture')
        # Three writes into the new cluster: this device's pre-data and post-data as the app role, HA's DATA (only the
        # entries of the -L list) as the role without privileges -- HA's archive never provides DDL.
        restores = self.restores()
        self.assertEqual([(user, '--section=pre-data' in cmd, '-L' in cmd, '--section=post-data' in cmd)
                          for user, cmd, _data in restores],
                         [('omnigent', True, False, False), (ha_omnigent.RESTORE_ROLE, False, True, False),
                          ('omnigent', False, False, True)])
        self.assertEqual(restores[0][2], b'PGDMP-trusted-schema')
        self.assertEqual(restores[2][2], b'PGDMP-trusted-schema')
        self.assertEqual(restores[1][2], b'PGDMP-hapg', 'the data comes from HA')
        for _user, cmd, _data in restores:
            self.assertTrue({'--no-owner', '--no-acl', '--exit-on-error', '--single-transaction'} <= set(cmd))
        toc = self.world.written['/tmp/woowbk-omnigent.toc'].decode()
        self.assertEqual(toc.splitlines(), DATA_LINES, 'only TABLE DATA and SEQUENCE SET of HA')
        statements = self.world.executed('omni-db')
        create = next(s for s in statements if s.startswith('CREATE ROLE woowbk_restore'))
        self.assertIn('NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', create)
        self.assertFalse([s for s in statements if 'GRANT CREATE' in s or 'REASSIGN OWNED' in s or 'pg_read_file' in s])
        self.assertIn('DROP ROLE woowbk_restore', statements)
        restricted = self.world.restricted()
        self.assertTrue(any(PAUSE in sql for sql in restricted), 'test mode pauses as the restricted role')
        self.assertEqual([row['id'] for row in self.world.carried()], ['admin', 'operator'])
        # The hashes travel only on the restricted loader's stdin: never in an argv or a log line.
        self.assertFalse([cmd for _r, cmd, _d in self.world.execs if any(HASH in str(a) for a in cmd)])
        self.assertFalse([run for run in self.world.runs if HASH in json.dumps(run, default=str)])
        self.assertTrue(any(HASH in sql for sql in restricted))
        # The new cluster was audited and its schema compared twice (after post-data, after the last write).
        audits = [s for s in statements if s == ha_omnigent.AUDIT_SQL]
        self.assertEqual(len(audits), 1)
        self.assertEqual(len([s for s in statements if s == ha_omnigent.SCHEMA_SIGNATURE_SQL]), 2)
        # The volumes.
        self.assertEqual(sorted(self.world.manifests['omnigent']), ['volumes'])
        server = self.volume('omnigent-server-data')
        self.assertEqual(server['artifacts/accounts-cookie-secret'][1], b'f' * 64, "HA's key replaces the live one")
        self.assertEqual(server['artifacts/accounts-cookie-secret'][0].mode, 0o600)
        self.assertEqual(server[f'artifacts/{BUNDLE}'][0].mode, 0o644)
        self.assertEqual(server['sharing_mode'][1], b'off', 'the live settings stay')
        self.assertNotIn(f'artifacts/{"e" * 32}', server, 'the live artifacts go')
        self.assertFalse([n for n in server if '.cache' in n or 'telemetry' in n])
        self.assertEqual({(m.uid, m.gid) for m, _d in server.values()}, {(0, 0)})
        self.assertEqual(self.volume('omnigent-pi-data')['auth.json'][1], b'pi-login', 'the runner keeps its own')
        self.assertIn('PG_VERSION', self.volume('omnigent-postgres-data'))
        self.assertNotIn(HASH, '\n'.join(self.reporter.logs))
        self.assertTrue(any('略過' in line for line in self.reporter.logs), 'the skipped structure entries are logged')
        self.assertNotIn(HASH, jobs.redact(f'x {HASH} y'), 'masked as soon as it was read')

    def test_what_the_job_writes_is_private_to_it(self):
        """HA's dump (password hashes, connections), this device's schema dump and the three volumes exist in the
        job's staging folder only, 0600 in folders of mode 0700."""
        modes = {}

        def mode(path):
            return Path(path).stat().st_mode & 0o777
        real_restore, real_manifest = ha_omnigent.restore_trusted_data, fk.Adapter.import_manifest

        def restore(work, tmp, schema_dump, data_dump, *args, **kwargs):
            modes.update(schema=mode(schema_dump), data=mode(data_dump), folder=mode(Path(data_dump).parent))
            return real_restore(work, tmp, schema_dump, data_dump, *args, **kwargs)

        def manifest(adapter, staging_dir, **items):
            modes.update({name: mode(source) for name, source in items['volumes'].items()})
            self.assertFalse((Path(staging_dir).parent.parent / 'omnigent-work' / 'omnigent.dump').exists())
            return real_manifest(adapter, staging_dir, **items)
        with mock.patch.object(ha_omnigent, 'restore_trusted_data', restore), \
                mock.patch.object(fk.Adapter, 'import_manifest', manifest):
            self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual(modes, {'schema': 0o600, 'data': 0o600, 'folder': 0o700, 'omnigent-postgres-data': 0o600,
                                 'omnigent-server-data': 0o600, 'omnigent-pi-data': 0o600})

    def test_a_same_named_ha_account_wins(self):
        self.world.ha_users = ['admin', 'alice']
        self.world.live_rows.append(dict(self.world.live_rows[0], id='mallory'))   # not asked for, never carried
        result = self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual([row['id'] for row in self.world.carried()], ['operator'])
        self.assertTrue(any('HA 也有帳號 admin' in line for line in result['ha_import']['notes']))
        self.assertFalse(any(PAUSE in sql for sql in self.world.restricted()), 'not a test import')

    def test_code_in_has_database_never_runs(self):
        """HAOS restores HA's functions as they are; this device never loads code of HA (O-14): a database with code is
        converted only when the customer confirmed that it is left out, and the list of HA's dump never selects any of it."""
        self.world.objects = dict(self.world.objects, functions=1)
        ha_id = self.upload_omnigent()
        with self.assertRaises(BackupError) as caught:      # not confirmed: this app only, before anything is dumped
            self.convert(ha_id, ['omnigent'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertIn('只會略過它們', caught.exception.message)
        self.assertFalse(self.runs('omni-db'))
        self.assert_nothing_loaded()
        self.assertFalse([cmd for _r, cmd, _d in self.world.execs if cmd[0] == 'pg_dump'], 'HA was not even dumped')
        # HA's dump list with code, defaults and checks: none of those entries is ever selected.
        self.world.toc = TOC + b'3700; 1255 16700 FUNCTION public evil() omnigent\n'
        keys = self.confirmed(self.check(ha_id, ['omnigent'])[0])
        self.convert(self.upload_omnigent(), ['omnigent'], acknowledged=keys)
        self.assertEqual(self.world.written['/tmp/woowbk-omnigent.toc'].decode().splitlines(), DATA_LINES)

    def test_a_listing_that_came_back_short_stops_before_anything_is_loaded(self):
        """pg-stdin follow-up F4: the entries of `pg_restore -l` are counted against the `TOC Entries:` of its own header; a
        listing that is short (a stdin transfer that arrived short under load) would restore only the part it names."""
        for declared in (40, 15):                  # 11 entries come back: short by 29 and by 4 (more than the 3 settings)
            with self.subTest(declared=declared):
                self.world.toc_declared = declared
                self.world.forget()
                with self.assertRaises(BackupError) as caught:
                    self.convert(self.upload_omnigent(), ['omnigent'])
                self.assertEqual((caught.exception.code, caught.exception.message), ('job-failed', ha_omnigent.INCOMPLETE_LIST))
                self.assertEqual(caught.exception.details, {'listed': 11, 'declared': declared})
                self.assert_nothing_loaded()
        for declared in (11, 12, 13, 14):          # the header counts the settings a plain listing may leave out: 0 to 3
            with self.subTest(declared=declared):
                self.world.toc_declared = declared
                self.world.forget()
                self.convert(self.upload_omnigent(), ['omnigent'])
        self.world.toc_declared = 10               # more entries than the header says: not a listing of this archive
        self.world.forget()
        with self.assertRaises(BackupError):
            self.convert(self.upload_omnigent(), ['omnigent'])

    def test_a_name_with_a_line_break_cannot_add_an_entry(self):
        """pg_restore -L reads only the id at the start of a line: a second "users" line (or the same sequence twice) would
        be any entry of HA's, so a trusted name once more stops this app; an entry of another table or sequence is not
        selected (O-28: left out, told) and the rest of the conversion goes on."""
        for extra in (b'3701; 0 0 TABLE DATA public users x\n', b'3703; 0 0 SEQUENCE SET public conversation_items_id_seq x\n'):
            with self.subTest(extra=extra):
                self.world.toc = TOC + extra
                self.world.execs.clear()
                with self.assertRaises(BackupError) as caught:
                    self.convert(self.upload_omnigent(), ['omnigent'])
                self.assertEqual(caught.exception.code, 'incompatible')
                self.assertIn('出現兩次', caught.exception.message)
                self.assert_nothing_loaded()
        for extra in (b'3702; 0 0 TABLE DATA public evil x\n', b'3703; 0 0 SEQUENCE SET public other_seq x\n',
                      b'3704; 0 0 TABLE DATA other users x\n', b'3705; 0 0 TABLE DATA public users two owners\n'):
            with self.subTest(extra=extra):
                self.world.forget()
                self.world.toc = TOC + extra
                result = self.convert(self.upload_omnigent(), ['omnigent'])
                self.assertEqual(self.world.written['/tmp/woowbk-omnigent.toc'].decode().splitlines(), DATA_LINES)
                issue = next(i for i in result['results'][0]['issues'] if i['id'] == 'omnigent.entries-skipped')
                self.assertEqual((issue['level'], issue['items']),
                                 ('notice', [extra.decode().strip().split('; 0 0 ', 1)[1]]))

    def test_has_pg_dump_runs_as_another_os_user_than_has_server(self):
        """secreview SR-2b: code HA's catalog runs inside its server (uid 70, proven in the lab) could open pg_dump's
        stdout through /proc and write the archive the conversion restores, or signal pg_dump, when both are the same
        OS user; pg_dump runs as an unrelated uid."""
        self.convert(self.upload_omnigent(), ['omnigent'], test_mode=True)
        dumps = [user for user, args in self.world.exec_users
                 if 'pg_dump' in args and any(a.endswith('-hapg') for a in args)]
        self.assertEqual(dumps, ['65534:65534'])     # the fakes' owner maps 1-65536
        analysis = {user for user, args in self.world.exec_users
                    if 'psql' in args and any(a.endswith('-hapg') for a in args)}
        self.assertEqual(analysis, {'postgres'})   # only the queries run as postgres; their answers are checked (SR-1)

    def test_the_dump_user_is_one_the_owners_namespace_can_represent(self):
        """SR-2b on dev-d: its nested rootless namespace maps only 1-54999, and `podman exec --user 65534:65534`
        failed there (exit 255). The id comes from the owner's own maps; never root, never the image's postgres."""
        from woowbackup import nested
        devd = nested.IdMap('0 1019 1\n1 10000 55000\n')
        wide = nested.IdMap('0 1000 1\n1 100000 65536\n')
        self.assertEqual(ha_omnigent.dump_user((wide, wide), (70, 70)), '65534:65534')
        self.assertEqual(ha_omnigent.dump_user((devd, devd), (70, 70)), '32767:32767')
        self.assertEqual(ha_omnigent.dump_user((devd, devd), (32767, 32767)), '9999:9999')   # never postgres's ids
        self.assertEqual(ha_omnigent.dump_user((wide, devd), (70, 70)), '32767:32767')        # uid AND gid mapped
        # O-01: no id of the list is mapped: any other id both maps hold is taken (the highest), never root or postgres's
        tiny = nested.IdMap('0 1000 1\n1 100000 100\n')
        self.assertEqual(ha_omnigent.dump_user((tiny, tiny), (70, 70)), '100:100')
        self.assertEqual(ha_omnigent.dump_user((tiny, tiny), (100, 100)), '99:99')
        self.assertEqual(ha_omnigent.dump_user((tiny, nested.IdMap('0 1000 1\n1 100000 50\n')), (70, 70)), '50:50')
        self.assertEqual(ha_omnigent.dump_user((tiny, tiny), (99, 100)), '98:98')
        # ... and when none is left (only root, only the image's postgres, uid and gid ranges that do not meet) it stops
        for ids, pg in (((nested.IdMap('0 1000 1\n'),) * 2, (70, 70)), ((nested.IdMap('0 1 1\n70 5 1\n'),) * 2, (70, 70)),
                        ((nested.IdMap('0 1 1\n5 5 10\n'), nested.IdMap('0 1 1\n50 5 10\n')), (70, 70))):
            with self.subTest(ids=ids[0].describe()), self.assertRaises(BackupError) as caught:
                ha_omnigent.dump_user(ids, pg)
            self.assertEqual(caught.exception.code, 'job-failed')

    def test_a_sequence_value_that_is_sql_never_runs(self):
        """secreview SR-3: pg_dump writes a sequence's last_value as HA's server sent it into the SEQUENCE SET
        statement (a crafted catalog made it a DO block in the lab); only exact setval statements of trusted
        sequences are loaded, checked on pg_restore's own text before anything is restored."""
        injected = ("SELECT pg_catalog.setval('public.conversation_items_id_seq', 1, true); DO $x$ BEGIN "
                    "PERFORM lo_from_bytea(0, 'x'); END $x$; SELECT pg_catalog.setval('public.conversation_items_id_seq', 1, true);")
        for script in (SEQ_SCRIPT_HEAD + injected + '\n',
                       SEQ_SCRIPT_HEAD + "SELECT pg_catalog.setval('public.conversation_items_id_seq', 1, true);\n"
                                         'CREATE TABLE public.evil (i int);\n',
                       "SET role = postgres;\n" + self.world.seq_script,
                       SEQ_SCRIPT_HEAD + "SELECT pg_catalog.setval('public.other_seq', 1, true);\n", ''):
            with self.subTest(script=script[-60:]):
                self.world.seq_script = script
                self.world.execs.clear()
                with self.assertRaises(BackupError) as caught:
                    self.convert(self.upload_omnigent(), ['omnigent'])
                self.assertEqual(caught.exception.code, 'incompatible')
                self.assertIn('SEQUENCE SET', caught.exception.message)
                self.assertFalse([r for r in self.restores() if '-d' in r[1]], 'nothing was restored at all')
                self.assert_nothing_loaded()

    def test_the_sequence_script_is_one_setval_for_each_selected_sequence(self):
        """The same rule on its own: nothing but comments follows a setval, not even one of pg_restore's own header
        lines, and there are as many setval as selected entries, each of another trusted sequence."""
        def setval(name, value):
            return f"SELECT pg_catalog.setval('public.{name}', {value}, true);\n"
        one, other = setval('conversation_items_id_seq', 7), setval('other_seq', -1)
        tail = '\n--\n-- PostgreSQL database dump complete\n--\n\n\\unrestrict x1\n'
        trusted = ['conversation_items_id_seq', 'other_seq']
        for script, count in ((SEQ_SCRIPT_HEAD + one + tail, 1), (SEQ_SCRIPT_HEAD + one + other + tail, 2),
                              (SEQ_SCRIPT_HEAD + tail, 0)):
            ha_omnigent.require_sequence_sets(script, count, trusted)
        for name, script, count in (
                ('a search path after a setval (a value that ends in a comment)',
                 one + "SELECT pg_catalog.set_config('search_path', 'evil', false);\n-- , true);\n", 1),
                ('a setting after a setval', one + 'SET row_security = off;\n', 1),
                ('one sequence twice, one entry', one + one, 1), ('one sequence twice, two entries', one + one, 2),
                ('a setval more', one + other, 1), ('a setval less', one, 2),
                ('a sequence this device does not have', one + setval('evil_seq', 1), 2)):
            with self.subTest(name=name), self.assertRaises(BackupError) as caught:
                ha_omnigent.require_sequence_sets(SEQ_SCRIPT_HEAD + script + tail, count, trusted)
            self.assertEqual((caught.exception.code, caught.exception.message),
                             ('incompatible', ha_omnigent.SEQUENCE_SET_ODD))

    def assert_stopped(self, code, message, *, exported=(), upload=(), **params):
        """One conversion that must end with `code` and exactly `message`: no backup, nothing packed, only the
        volumes in `exported` were read out, the staging folder is gone."""
        self.world.forget()
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_omnigent(**dict(upload)), ['omnigent'], **params)
        self.assertEqual((caught.exception.code, caught.exception.message), (code, message))
        self.assertEqual(self.storage.list_backups(), [])
        self.assertEqual(self.world.manifests, {}, 'nothing was packed')
        self.assertEqual(self.world.exported(), list(exported))
        self.assertFalse((Path(self.paths.staging) / self.job_id).exists(), 'staging is removed')

    def test_a_version_that_does_not_match_is_no_reason_to_stop_the_conversion(self):
        """O-25, O-49: the conversion asks the same questions as the check (no check had to run first): an add-on version
        that ships another Omnigent, one that this engine does not know and a live version that cannot be read are
        notices; the structure version of HA's database against this device's decides (the next test)."""
        for number, (addon, live, ids) in enumerate((('0.1.19', '0.21.0', ['omnigent.version-different']),
                                                     ('0.9.0', '0.21.0', ['version.addon-unknown']),
                                                     ('0.1.23', '0.22.0', ['omnigent.version-different']),
                                                     ('0.1.23', None, ['version.target-unknown'])), 1):
            with self.subTest(addon=addon, live=live):
                self.server_version = live
                self.world.forget()
                result = self.convert(self.upload_omnigent(version=addon), ['omnigent'])
                issues = result['results'][0]['issues']
                self.assertEqual([i['id'] for i in issues if i['id'].endswith(('different', 'unknown'))], ids)
                self.assertTrue(all(i['level'] == 'notice' for i in issues if i['id'].endswith(('different', 'unknown'))))
                self.assertEqual(len(self.storage.list_backups()), number)

    def test_another_structure_version_stops_the_conversion_itself(self):
        """What replaced the version gate (O-19, a stop of this app only): HA's structure version is not this device's:
        nothing is dumped, created or packed, whatever the add-on and live versions say."""
        self.world.ha_alembic = ['older']
        for addon, live in (('0.1.23', '0.21.0'), ('0.1.19', '0.21.0'), ('0.9.0', '0.22.0')):
            with self.subTest(addon=addon, live=live):
                self.server_version = live
                self.assert_stopped('incompatible', f'資料庫結構版本不同：HA 是 older，這台是 {ALEMBIC}。',
                                    upload={'version': addon})
                self.assertFalse([cmd for _r, cmd, _d in self.world.execs if cmd[0] == 'pg_dump'])
                self.assertEqual(self.runs('omni-db'), [])
                self.assert_nothing_loaded()

    @contextlib.contextmanager
    def after_the_last_write(self, change):
        """What the new cluster answers once the restricted role is dropped becomes `change(sql, answer)`: only the
        schema, the audit and the final comparison are asked after that."""
        real = self.world.answer

        def answer(role, sql, database):
            value = real(role, sql, database)
            if role == 'omni-db' and 'DROP ROLE woowbk_restore' in self.world.executed('omni-db'):
                return change(sql, value)
            return value
        self.world.answer = answer
        try:
            yield
        finally:
            self.world.answer = real

    def test_counts_that_differ_stop_the_conversion(self):
        """The final comparison, after the last write into the new cluster (require_answers compared HA's answers right
        after the data load, TrustedSchemaTests; this one also sees what adding this device's accounts and the
        test-mode pause did): every table holds HA's rows, users this device's kept accounts too, and the revision is
        HA's. Otherwise nothing is exported; the cluster is not even stopped."""
        def counts(**changed):
            def change(sql, value):
                if not (sql.startswith('SELECT json_build_object(') and "'conversations', (SELECT count(*)" in sql):
                    return value
                return {k: v for k, v in dict(value, **changed).items() if v is not None}
            return change

        def revision(found):
            return lambda sql, value: found if sql == ha_omnigent.ALEMBIC_SQL else value

        for name, test_mode, change, words in (
                ('a table lost a row', False, counts(conversations=1), 'conversations（HA 2，匯入後 1）'),
                ('a table got a row', True, counts(scheduled_tasks=3), 'scheduled_tasks（HA 2，匯入後 3）'),
                ('a table does not answer', False, counts(hosts=None), 'hosts（HA 2，匯入後 None）'),
                ('the kept accounts are not there', False, counts(users=2), 'users（HA 4，匯入後 2）'),
                ('two tables', True, counts(agents=0, files=0), 'agents（HA 2，匯入後 0）、files（HA 2，匯入後 0）'),
                ('another revision', False, revision(['0000000000aa']), '結構版本'),
                ('a second revision', True, revision([ALEMBIC, '0000000000aa']), '結構版本'),
                ('no revision', False, revision(None), '結構版本')):
            with self.subTest(name=name), self.after_the_last_write(change):
                self.assert_stopped('job-failed', f'Omnigent 匯入後的資料和 HA 不同，已停止：{words}。', test_mode=test_mode)
                self.assertIn(ha_omnigent.AUDIT_SQL, self.world.executed('omni-db'),
                              'the answers after the data load, the schema and the audit were fine')
                self.assertEqual(self.runs('controldata'), [])

    def test_test_mode_that_left_a_task_active_stops_the_conversion(self):
        """Test mode counts the active tasks again after its pause: a backup whose tasks would still run on this
        device is never made (what the pause changed is asked, not assumed)."""
        real = self.world.answer
        self.world.answer = lambda role, sql, database: (
            1 if role == 'omni-db' and sql == ha_omnigent.ACTIVE_SQL else real(role, sql, database))
        self.addCleanup(setattr, self.world, 'answer', real)
        self.assert_stopped('job-failed', '測試匯入沒有暫停全部 Omnigent 排程。', test_mode=True)
        self.assertTrue(any(PAUSE in sql for sql in self.world.restricted()), 'the pause itself ran')
        self.assertEqual(self.world.executed('omni-db').count(ha_omnigent.ACTIVE_SQL), 2, 'before and after the pause')
        self.assertEqual(self.runs('controldata'), [])
        self.world.forget()   # without test mode the active task is HA's to keep: nothing is asked or paused
        self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertNotIn(ha_omnigent.ACTIVE_SQL, self.world.executed('omni-db'))

    def test_a_cluster_that_did_not_stop_cleanly_is_never_exported(self):
        """O-54: PostgreSQL's smart/fast shutdown ends with 0; 137 is the SIGKILL of `podman stop` after its grace time, 1
        an error during the shutdown. The exit code alone is no refusal any more -- pg_controldata, the second and
        independent answer about the same thing, is: a cluster that was killed says so there and is never exported; one that
        shut down completely is, whatever the code of its container."""
        for code in (137, 1, 143):
            with self.subTest(code=code, state='in production'):
                self.world.exit_codes['omni-db'] = code
                self.world.cluster_state = b'in production'
                self.assert_stopped('job-failed', '新的 PostgreSQL 叢集沒有正常關閉。')
                self.assertEqual(len(self.runs('controldata')), 1, 'asked after every code')
                self.assertTrue(any(f'結束碼是 {code}' in line for line in self.reporter.logs))
        self.assertIn(('stop', '--time', '300', f'woowbk-{self.job_id}-omni-db'), self.world.owner.calls)
        self.world.cluster_state = b'shut down'
        for code in (137, 1):
            with self.subTest(code=code, state='shut down'):
                self.world.exit_codes['omni-db'] = code
                self.world.forget()
                self.convert(self.upload_omnigent(), ['omnigent'])
                self.assertEqual(len(self.runs('controldata')), 1)
                self.assertIn('omnigent-postgres-data', self.world.volume_data, 'exported')

    def test_only_a_cluster_that_pg_controldata_calls_shut_down_is_exported(self):
        """The second, independent answer about the same thing: pg_controldata of the live image reads the stopped
        cluster's control file (its volume read only, no server running) and must say exactly "shut down" (every other
        state of PostgreSQL 16's dbState(), or no answer, stops the job)."""
        for state in (b'in production', b'shutting down', b'shut down in recovery', b'in crash recovery',
                      b'in archive recovery', b'starting up', b'unrecognized status code', b''):
            with self.subTest(state=state):
                self.world.cluster_state = state
                self.assert_stopped('job-failed', '新的 PostgreSQL 叢集沒有正常關閉。')
                role, image, command, options = self.runs('controldata')[0]
                self.assertEqual((image, command), ('docker.io/library/postgres:16.15-alpine3.24',
                                                    ['pg_controldata', '/var/lib/postgresql/data']))
                self.assertEqual(options['--volume'], [f'woowbk-{self.job_id}-omni-db:/var/lib/postgresql/data:ro'])
                self.assertEqual((options['--user'], options['--network']), (['postgres'], ['none']))
                self.assertIn('--read-only', options)
                self.assertIn(('stop', '--time', '300', f'woowbk-{self.job_id}-omni-db'), self.world.owner.calls)
        self.world.cluster_state = b'shut down'
        self.world.forget()
        self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual(len(self.storage.list_backups()), 1)

    def test_a_volume_podman_could_not_import_is_never_packed(self):
        """Every volume of the converted backup is read as a restore would read it (nested.check_volume with the
        owner's id maps) before it is packed: a restore empties the live volume first, so `podman volume import` must
        not fail half-way. The database comes from the new cluster's export, the server and pi volumes from this
        device's own (with HA's artifacts in the first)."""
        owner = {'name': 'woowbk-unmapped', 'data': b'x', 'uid': 70000}     # the fakes' owner maps 0-65536
        link = {'name': 'woowbk-outside', 'type': 'symlink', 'linkname': '../../outside'}
        device = {'name': 'woowbk-device', 'type': 'chr'}
        everything = ('omni-db', 'omnigent-server-data', 'omnigent-pi-data')
        for source, member, reason in (
                ('omni-db', owner, 'owner id outside the user namespace'),
                ('omni-db', link, 'symlink pointing outside the volume'),
                ('omni-db', device, 'member type not allowed (device, sparse or unknown)'),
                ('omnigent-server-data', owner, 'owner id outside the user namespace'),
                ('omnigent-pi-data', owner, 'owner id outside the user namespace'),
                ('omnigent-pi-data', link, 'symlink pointing outside the volume'),
                ('omnigent-pi-data', device, 'member type not allowed (device, sparse or unknown)')):
            with self.subTest(source=source, member=member['name']):
                self.world.extra_members = {source: [member]}
                self.world.forget()
                with self.assertRaises(BackupError) as caught:
                    self.convert(self.upload_omnigent(), ['omnigent'])
                self.assertEqual(caught.exception.code, 'job-failed')
                self.assertTrue(caught.exception.message.startswith('轉換後的資料卷內容無法匯入（'), caught.exception.message)
                self.assertEqual(caught.exception.details.get('reason'), reason)
                self.assertEqual(sorted(self.world.exported()), sorted(everything), 'read out, but')
                self.assertEqual(self.world.manifests, {}, 'never packed')
                self.assertEqual(self.storage.list_backups(), [])
        self.world.extra_members = {}
        self.world.forget()
        self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual(len(self.storage.list_backups()), 1)


class TrustedSchemaTests(OmnigentCase):
    """What the product enforces itself instead of a caller's promise (B1-01): each case stops before HA's data is
    loaded or before anything is exported, and no backup is made."""

    def assert_refused(self, code, words, *, loaded=False):
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual(caught.exception.code, code)
        self.assertIn(words, caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])
        data = [cmd for role, cmd, _d in self.world.execs if role == 'omni-db' and cmd[0] == 'pg_restore'
                and ha_omnigent.RESTORE_ROLE in cmd]
        if not loaded:
            self.assertEqual(data, [], 'stopped before any HA data was loaded')
        self.assertFalse([p for p in self.world.volume_data if p == 'omnigent-postgres-data'], 'nothing exported')
        return caught.exception

    def test_ddl_during_the_capture_stops(self):
        def change(world):
            world.live_signature = dict(world.live_signature, indexes=world.live_signature['indexes'] + [
                ['users', 'ix_new', 'CREATE INDEX ix_new ON public.users USING btree (is_admin)']])
        self.world.after_capture = change
        self.assert_refused('incompatible', '資料庫結構在轉換期間改變了')

    def test_snapshot_columns_must_be_the_live_ones(self):
        self.world.snapshot_columns = COLUMNS + [['users', 'extra', 'integer', False, '', '']]
        self.assert_refused('incompatible', '資料庫結構在轉換期間改變了')

    def test_a_revision_that_moved_since_the_check_stops(self):
        real = self.world.answer
        calls = {'n': 0}

        def answer(role, sql, database):
            if role == 'omnigent-postgres' and 'alembic_version' in sql:
                calls['n'] += 1
                return self.world.live_alembic if calls['n'] == 1 else ['newer']
            return real(role, sql, database)

        self.world.answer = answer
        self.assert_refused('incompatible', '資料庫結構在轉換期間改變了')

    def test_has_columns_must_equal_the_trusted_ones(self):
        self.world.ha_columns = COLUMNS + [['users', 'x', 'integer', False, '', '']]
        error = self.assert_refused('incompatible', '資料庫結構不同（users）')
        self.assertIn('版本一致', error.message)

    def test_has_sequences_and_types_must_equal_the_trusted_ones(self):
        seq = list(SEQUENCE)
        seq[8] = 'users.id'
        self.world.ha_signature = dict(signature(), sequences=[seq])
        self.assert_refused('incompatible', 'conversation_items_id_seq')
        self.world.ha_signature = dict(signature(), types=[['mood', 'e', '', False, '', ['ok', 'sad']]])
        self.assert_refused('incompatible', 'mood')

    def test_has_defaults_checks_and_indexes_are_not_compared(self):
        # They are never used (the trusted ones apply), so a different one is no reason to refuse.
        self.world.ha_signature = dict(signature(), constraints=[['users', 'ck_evil', 'c', 'CHECK (lo_export(0, \'/x\') > 0)',
                                                                  False, False, False, False]], indexes=[])
        cols = signature()['columns']
        self.world.ha_signature['columns'] = [row[:6] + ['lo_export(0, \'/x\')', ''] for row in cols]
        self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual(len(self.storage.list_backups()), 1)

    def test_the_new_clusters_schema_must_be_the_trusted_one(self):
        self.world.restored_signature = dict(signature(), constraints=signature()['constraints'] + [
            ['users', 'ck_evil', 'c', "CHECK (lo_export(0, '/x') > 0)", False, False, False, False]])
        error = self.assert_refused('job-failed', '新的 PostgreSQL 叢集的資料庫結構和這台 Omnigent 的不同', loaded=True)
        self.assertIn('constraints', error.message)

    def test_the_new_cluster_holds_nothing_else(self):
        for key, value, words in (('roles', ['evil', 'omnigent'], '多出的資料庫角色'),
                                  ('role_settings', 1, '角色或資料庫設定'), ('auto_conf', 1, 'ALTER SYSTEM 設定'),
                                  ('large_objects', 1, '大型物件')):
            with self.subTest(key=key):
                self.world.audit = {**{'roles': ['omnigent'], 'role_settings': 0, 'auto_conf': 0, 'large_objects': 0},
                                    key: value}
                self.world.execs.clear()
                self.assert_refused('job-failed', words, loaded=True)

    def test_answers_of_has_cluster_that_lie_stop_the_conversion(self):
        """secreview SR-1: HA's cluster answered the check (a crafted backup can make it lie: a pg_-named schema of
        same-count views and its own per-role search_path, proven in the lab); the new cluster, which holds exactly
        HA's data on this device's schema and server, must answer the same before anything is exported."""
        real = self.world.answer
        cases = (
            ('scheduled_tasks_active', ha_omnigent.DETAIL_SQL, lambda v: dict(v, scheduled_tasks_active=3)),
            ('public_sessions', ha_omnigent.DETAIL_SQL, lambda v: dict(v, public_sessions=2)),
            ('user_ids', ha_omnigent.DETAIL_SQL, lambda v: dict(v, user_ids=['admin', 'alice', 'bob'])),
            ('bundles', ha_omnigent.KEYS_SQL, lambda v: dict(v, bundles=[BUNDLE, '../../../etc/passwd'])),
            ('scheduled_tasks（HA 2，實際 5）', None, lambda v: dict(v, scheduled_tasks=5)))
        for name, query, change in cases:
            with self.subTest(name=name):
                def answer(role, sql, database, query=query, change=change):
                    value = real(role, sql, database)
                    if role != 'omni-db' or not isinstance(value, dict):
                        return value
                    if query is None:   # the table counts (several statements of 40 tables)
                        return change(value) if 'scheduled_task_runs' in value else value
                    return change(value) if sql == query else value
                self.world.answer = answer
                self.world.execs.clear()
                error = self.assert_refused('incompatible', '回報的內容和它實際的資料不一致', loaded=True)
                self.assertIn(name, error.message)
                self.assertNotIn('etc/passwd', error.message)   # a value is never repeated
        self.world.answer = real

    def test_names_in_the_answers_message_cannot_forge_lines(self):
        """Verifier finding 2026-11-23 (SR-4 class, in the SR-1 fix): the names HA_ANSWERS_DIFFER lists are the keys of
        HA's answers, which a crafted cluster chooses (a shadowed json_build_object): never a line break, never more
        than 60 characters of one name."""
        real = self.world.answer
        forged = 'x\n2026-11-23T00:00:00Z 作業結束：成功' + 'y' * 300

        def answer(role, sql, database):
            value = real(role, sql, database)
            if role == 'hapg' and sql == ha_omnigent.DETAIL_SQL and isinstance(value, dict):
                return dict(value, **{forged: 1})
            return value
        self.world.answer = answer
        try:
            error = self.assert_refused('incompatible', '回報的內容和它實際的資料不一致', loaded=True)
        finally:
            self.world.answer = real
        self.assertIn('x?2026-11-23', error.message)
        self.assertNotIn('\n', error.message)
        self.assertNotIn('y' * 40, error.message)

    def test_has_rows_this_devices_schema_refuses_end_with_a_plain_message(self):
        """HA's rows that this device's constraints refuse (security review v5, real: a CHECK HA had dropped; also NOT
        NULL, duplicate keys at post-data, dangling references, bad values) stop the job as 'incompatible' with a plain
        message; pg_restore's stderr (it holds HA's row values) never reaches the message or the job log; any other
        failure of the same command stays what it was."""
        canary = 'CANARY-HA-ROW-7f3a'
        cases = (
            ('data', 'COPY failed for table "users": ERROR:  new row for relation "users" violates check constraint '
                     '"ck_users_id"'),
            ('data', 'ERROR:  null value in column "id" of relation "agents" violates not-null constraint'),
            ('data', 'ERROR:  invalid input syntax for type integer: "x"'),
            ('post-data', 'ERROR:  could not create unique index "users_pkey"'),
            ('post-data', 'ERROR:  insert or update on table "comments" violates foreign key constraint "fk_c"'))
        for step, error in cases:
            with self.subTest(step=step, error=error[:40]):
                def fail(role, command, step=step, error=error):
                    if role != 'omni-db' or command[:1] != ['pg_restore'] or '-d' not in command:
                        return None
                    if (step == 'data') != (ha_omnigent.RESTORE_ROLE in command) or \
                            (step == 'post-data') != ('--section=post-data' in command):
                        return None
                    return Result(1, b'', f'pg_restore: error: {error}\nDETAIL:  Failing row contains ({canary}).\n'
                                  .encode())
                self.world.exec_failure = fail
                self.world.execs.clear()
                self.reporter.logs.clear()
                refused = self.assert_refused('incompatible', ha_omnigent.DATA_REFUSED, loaded=True)
                self.assertNotIn(canary, refused.message)
                self.assertFalse([line for line in self.reporter.logs if canary in line])
        self.world.exec_failure = lambda role, command: (
            Result(1, b'', b'pg_restore: error: connection to server lost\n')
            if role == 'omni-db' and ha_omnigent.RESTORE_ROLE in command and '-d' in command else None)
        self.world.execs.clear()
        other = self.assert_refused('job-failed', '執行失敗', loaded=True)
        self.assertNotEqual(other.message, ha_omnigent.DATA_REFUSED)
        self.world.exec_failure = None

    def test_unregistered_quadlet_secrets_are_told_and_the_conversion_goes_on(self):
        """O-48: a secret of the Quadlet files that the app settings do not list (or list twice) only matters when the
        backup is restored on a new device; here, in place, the secret is there: a notice with the names, in the check
        (where the customer reads it) and in the conversion; never a value."""
        password, url = {'name': 'omnigent-postgres-password'}, {'name': 'omnigent-database-url'}
        for name, declared, names in (('one is missing', [password], ['omnigent-database-url']),
                                      ('one is declared twice', [password, url, password], ['omnigent-postgres-password']),
                                      ('none is listed', [], ['omnigent-database-url', 'omnigent-postgres-password'])):
            with self.subTest(name=name):
                self.catalog['omnigent'].secrets = declared
                result = self.check_one()
                self.assertTrue(result['importable'])
                self.assertEqual([i['items'] for i in self.issues(result, 'omnigent.secrets-unregistered')], [names])
                self.world.forget()
                converted = self.convert(self.upload_omnigent(), ['omnigent'])
                self.assertEqual([i['items'] for i in converted['results'][0]['issues']
                                  if i['id'] == 'omnigent.secrets-unregistered'], [names])
        self.assertEqual(ha_omnigent.unregistered_secrets(self.ctx_work(), self.catalog['omnigent']),
                         ['omnigent-database-url', 'omnigent-postgres-password'])

    def ctx_work(self):
        from types import SimpleNamespace
        return SimpleNamespace(quadlets=lambda app: dict(QUADLETS))

    def test_a_structure_that_is_still_moving_is_waited_for(self):
        """O-42, O-43: this device's server upgrades or restarts while the structure is read: the capture is waited for and
        read again (3 times in all); one that settles is imported, one that keeps changing stops the job as it did."""
        moves = {'left': 1}

        def once(world):
            if moves['left']:
                moves['left'] -= 1
                world.live_signature = dict(world.live_signature, indexes=world.live_signature['indexes'] + [
                    ['users', 'ix_new', 'CREATE INDEX ix_new ON public.users USING btree (is_admin)']])
        self.world.after_capture = once
        self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual(len(self.world.snapshots), 2, 'read again once it was steady')
        self.assertEqual(len(self.storage.list_backups()), 1)
        self.assertTrue(any('還在變動' in line for line in self.reporter.logs), 'the customer can read that it waited')
        # a revision that moved and came back, as a server that restarts does
        calls = {'n': 0}
        real = self.world.answer

        def answer(role, sql, database):
            if role == 'omnigent-postgres' and 'alembic_version' in sql:
                calls['n'] += 1
                return ['newer'] if calls['n'] == 2 else self.world.live_alembic
            return real(role, sql, database)
        self.world.answer = answer
        self.world.forget()
        self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual(len(self.storage.list_backups()), 2)
        self.assertEqual(len(self.world.snapshots), 1, 'the first read of the new try was fine')


class RefusalTests(OmnigentCase):
    """The import's other refusals, one case each: a device that is not set up like the Omnigent package, an HA
    database that is not this Omnigent's, and answers that are not what was asked for (never guessed, never read as
    "nothing")."""

    def refused(self, code, message, *, upload=(), check=None):
        """The conversion ends with `code` and a message that starts with `message`: no backup, nothing packed.
        `check`: the same words are the check's blocker too."""
        self.world.forget()
        ha_id = self.upload_omnigent(**dict(upload))
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['omnigent'])
        self.assertEqual((caught.exception.code, caught.exception.message[:len(message)]), (code, message))
        self.assertEqual((self.storage.list_backups(), self.world.manifests), ([], {}))
        if check is not None:
            self.world.forget()
            result = self.check(ha_id, ['omnigent'])[0]
            self.assertFalse(result['ok'])
            self.assertIn(check, '\n'.join(result['blockers']))

    def test_a_device_that_is_not_set_up_like_the_package_is_no_target(self):
        layout = '這台的 Omnigent 應用設定不是 HA 匯入支援的樣子：'
        missing = layout + '找不到 PostgreSQL、伺服器或 runner 的 Quadlet 檔'
        items = layout + '應用設定含有資料庫匯出項目或主機資料夾'
        mixed = '這台的 Omnigent 資料卷、資料庫設定和 Quadlet 檔不一致，無法匯入。'
        pg, runner = 'omnigent-postgres.container', 'omnigent-runner.container'

        def text(name, old, new):
            def change(app, files):
                self.assertIn(old, files[name])
                files[name] = files[name].replace(old, new)
            return change

        def one_volume_twice(app, files):
            text(runner, b'omnigent-pi.volume', b'omnigent-server.volume')(app, files)
            app.volumes.pop()
        for name, change, message in (
                ('a database item', lambda app, files: setattr(app, 'postgres', [{'id': 'omnigent'}]), items),
                ('a host folder', lambda app, files: setattr(app, 'data_dirs', [{'path': 'omnigent'}]), items),
                ('no database', lambda app, files: files.pop(pg), missing),
                ('no server', lambda app, files: files.pop('omnigent-server.container'), missing),
                ('no runner', lambda app, files: files.pop(runner), missing),
                ('one volume less', lambda app, files: app.volumes.pop(), mixed),
                ('another volume', lambda app, files: app.volumes.append(dict(app.volumes.pop(), name='omnigent-other')),
                 mixed),
                ('two folders in one volume', one_volume_twice, mixed),
                ('another database', text(pg, b'POSTGRES_DB=omnigent', b'POSTGRES_DB=other'), mixed),
                ('a user name', text(pg, b'POSTGRES_USER=omnigent', b'POSTGRES_USER=bad-name'), mixed),
                ('a data folder', text(pg, b'POSTGRES_USER=omnigent',
                                       b'POSTGRES_USER=omnigent PGDATA=relative/path'), mixed),
                ('no image', text(pg, b'Image=docker.io/library/postgres:16.15-alpine3.24\n', b''),
                 '這台 Omnigent 的 Quadlet 設定缺少映像。')):
            with self.subTest(name=name):
                self.catalog, files = self.catalog_apps(), dict(QUADLETS)
                change(self.catalog['omnigent'], files)
                self.world.quadlets = {'omnigent': files}
                self.refused('incompatible', message, check=message)
                self.assertEqual((self.world.runs, self.world.imported), ([], {}), 'nothing of HA was read')

    def test_what_has_database_must_be(self):
        """What still keeps this app from being imported (the check shows each as a stop, the conversion stops with it
        before anything of HA is dumped): another database encoding, a PostgreSQL newer than the image that opens it, another
        structure version, no revision on either side."""
        objects = dict(self.world.objects)
        for name, changed, upload, ident, words in (
                ('encoding', {'encoding': 'SQL_ASCII'}, {}, 'omnigent.encoding', 'HA 的 Omnigent 資料庫不是 UTF8 編碼。'),
                ('a newer PostgreSQL', {}, {'pg_version': b'17\n'}, 'omnigent.pg-newer',
                 'HA 的 PostgreSQL 是 17 版，這台的資料庫是 16 版，打不開比自己新的資料。')):
            with self.subTest(name=name):
                self.world.objects = dict(objects, **changed)
                self.refused('incompatible', words, upload=upload, check=words)
                self.assertEqual([i['id'] for i in self.issues(self.check_one(**upload), level='stop')], [ident])
                self.assertFalse([cmd for _r, cmd, _d in self.world.execs if cmd[0] == 'pg_dump'])
                self.assertEqual(self.runs('omni-db'), [])
        self.world.objects = objects
        for value, words, ident in ((None, '無法讀取這台 Omnigent 的資料庫結構版本。', 'omnigent.target-unreadable'),
                                    (['older'], '資料庫結構版本不同：HA 是', 'omnigent.alembic-different')):
            self.world.live_alembic = value
            self.refused('incompatible', words, check=words)
            self.assertEqual([i['id'] for i in self.issues(self.check_one(), level='stop')], [ident])
        self.world.ha_alembic = []
        for live, shown in (([ALEMBIC], ALEMBIC), ([], '未知')):   # no revision is none to compare, also on both sides
            self.world.live_alembic = live
            words = f'資料庫結構版本不同：HA 是 未知，這台是 {shown}。'
            self.refused('incompatible', words, check=words)
        self.world.ha_alembic, self.world.live_alembic = [ALEMBIC], [ALEMBIC]
        # a table HA lacks is no block of its own: the comparison of the columns says it (O-13)
        self.world.objects = dict(objects, tables=[t for t in objects['tables'] if t != 'hosts'])
        self.world.live_columns = COLUMNS + [['hosts', 'id', 'text', True, '', '']]
        self.world.ha_columns = list(COLUMNS)
        words = ha_omnigent.schema_blocker(['hosts'])
        self.refused('incompatible', words, check=words)
        self.world.objects = objects
        self.world.ha_columns = self.world.live_columns = list(COLUMNS)
        # an image that tells no PG_MAJOR: the database it runs here says it (O-18); when that says nothing either, the
        # PostgreSQL that opens HA's folder decides
        with mock.patch.object(self.world, 'image_info', lambda image: {'id': 'sha256:' + 'c' * 64, 'env': []}):
            self.world.live_major = 15
            words = 'HA 的 PostgreSQL 是 16 版，這台的資料庫是 15 版，打不開比自己新的資料。'
            self.refused('incompatible', words, check=words)
            self.world.live_major = 16
            self.assertTrue(self.check_one()['importable'], 'the same major: no gate')
            self.world.live_major = None
            self.assertTrue(self.check_one()['importable'], 'unknown: the PostgreSQL that opens the folder decides')

    def test_answers_that_are_not_what_was_asked_for_stop_the_job(self):
        no_tables, no_schema = '無法確認 Omnigent 的資料表結構。', '無法確認 Omnigent 的資料庫結構。'
        mine, no_revision = '無法確認這台 Omnigent 的資料表結構。', '無法讀取這台 Omnigent 的資料庫結構版本。'
        short = {key: value for key, value in signature().items() if key != 'triggers'}
        longer = dict(signature(), more=[])
        live, odd_row = 'omnigent-postgres', COLUMNS + [['users', 'x']]
        columns, whole = ha_omnigent.SCHEMA_COLUMNS_SQL, ha_omnigent.SCHEMA_SIGNATURE_SQL
        revision, accounts = 'SELECT coalesce(json_agg(version_num)', 'SELECT coalesce(json_agg(u ORDER BY u.id)'
        for name, role, wanted, value, skip, code, message in (
                ('no omnigent database', 'hapg', ha_odoo.DATABASES_SQL, [['other', 1, 'C', 'C']], 0,
                 'incompatible', 'HA 的 Omnigent 沒有 omnigent 資料庫，沒有資料可以搬。'),
                ('no objects', 'hapg', ha_omnigent.OBJECTS_SQL, [], 0, 'job-failed', '無法讀取 HA 的 Omnigent 資料庫。'),
                ("HA's columns: none", 'hapg', columns, [], 0, 'incompatible', no_tables),
                ("HA's columns: no list", 'hapg', columns, {'users': 1}, 0, 'incompatible', no_tables),
                ("HA's columns: a number", 'hapg', columns, 5, 0, 'incompatible', no_tables),
                ("HA's columns: a short row", 'hapg', columns, odd_row, 0, 'incompatible', no_tables),
                ("HA's signature: none", 'hapg', whole, None, 0, 'incompatible', no_schema),
                ("HA's signature: a part missing", 'hapg', whole, short, 0, 'incompatible', no_schema),
                ("HA's signature: a part more", 'hapg', whole, longer, 0, 'incompatible', no_schema),
                ('live columns: none', live, columns, [], 0, 'incompatible', mine),
                ('live columns: no list', live, columns, None, 0, 'incompatible', mine),
                ('live columns: a number', live, columns, 5, 0, 'incompatible', mine),
                ('live columns: a short row', live, columns, odd_row, 0, 'incompatible', mine),
                ('live signature: a part missing', live, whole, short, 0, 'incompatible', no_schema),
                ('live signature after the capture', live, whole, None, 1, 'incompatible', no_schema),
                ('live revision before the capture', live, revision, {}, 1, 'incompatible', no_revision),
                ('live revision after the capture', live, revision, [1], 2, 'incompatible', no_revision),
                ('new cluster: columns', 'omni-db', columns, None, 0, 'incompatible', no_tables),
                ('new cluster: schema after the load', 'omni-db', whole, short, 0, 'incompatible', no_schema),
                ('new cluster: schema after the last write', 'omni-db', whole, None, 1, 'incompatible', no_schema),
                ("HA's accounts in the new cluster", 'omni-db', 'SELECT coalesce(json_agg(id)', None, 0,
                 'job-failed', '無法確認 Omnigent 帳號。'),
                ('audit', 'omni-db', ha_omnigent.AUDIT_SQL, None, 0, 'job-failed', '無法檢查新的 PostgreSQL 叢集。')):
            with self.subTest(name=name), self.answering(role, wanted, value, skip=skip):
                self.refused(code, message)

    def test_a_live_version_that_cannot_be_read_is_no_version(self):
        """The live version is what this device's own server answers on the loopback address, or none (the loopback rule is
        a protection and stays); none is a notice, in the check and in the conversion (O-24): the data decides."""
        def reply(status, body):
            return lambda url: (status, body)
        for name, info in (('an error page', reply(503, b'{"server_version": "0.21.0"}')),
                           ('no JSON', reply(200, b'<html>')), ('no object', reply(200, b'["0.21.0"]')),
                           ('no version', reply(200, b'{}')), ('no text', reply(200, b'{"server_version": 21}')),
                           ('no x.y.z', reply(200, b'{"server_version": "0.21.0\\n"}'))):
            with self.subTest(name=name), mock.patch.object(self, 'info', info):
                result = self.check_one()
                self.assertTrue(result['importable'])
                self.assertEqual(result['target_version'], '')
                self.assertEqual([i['id'] for i in self.issues(result, level='notice') if i['id'].startswith('version')],
                                 ['version.target-unknown'])
                self.world.forget()
                converted = self.convert(self.upload_omnigent(), ['omnigent'])
                self.assertIn('version.target-unknown', [i['id'] for i in converted['results'][0]['issues']])
        for url in ('http://192.0.2.1:8000/health', 'https://127.0.0.1:8000/health', None):
            with self.subTest(url=url), mock.patch.object(self, 'info', side_effect=AssertionError('asked')) as info:
                self.catalog['omnigent'].health = [{'type': 'http', 'url': url}] if url else []
                self.assertTrue(self.check_one()['importable'])
                info.assert_not_called()

    def test_a_schema_that_changed_with_the_last_write_stops_the_conversion(self):
        """The second comparison on its own: the new cluster's schema was the trusted one after the data load and is
        not any more after the accounts and the test-mode pause."""
        changed = dict(signature(), triggers=[['users', 'evil', 'CREATE TRIGGER evil ...']])
        with self.answering('omni-db', ha_omnigent.SCHEMA_SIGNATURE_SQL, changed, skip=1):
            self.refused('job-failed', '新的 PostgreSQL 叢集的資料庫結構和這台 Omnigent 的不同（triggers）')
        self.assertIn('DROP ROLE woowbk_restore', self.world.executed('omni-db'))

    def test_the_space_check_of_the_conversion(self):
        """HA's cluster, the new one and its WAL must fit above the floor before HA's cluster is even started (the
        first estimate of the job, three times the add-on's member, passed)."""
        with mock.patch.object(haimport.SpaceGuard, 'free', lambda guard: guard.floor + ha_odoo.WAL_ALLOWANCE):
            self.refused('insufficient-space', '空間不足：轉換需要再保留')
        self.assertIn('hapg', self.world.imported)
        self.assertEqual(self.runs('hapg'), [])


class ScanTests(unittest.TestCase):
    def test_what_is_never_read_or_moved(self):
        report = habackup.Report()
        data = gzip.decompress(addon_tar())
        src = ha_omnigent.scan_member(io.BytesIO(data), report)
        self.assertEqual(report.secret_files, 1)
        self.assertEqual(src.pg_version, '16')
        self.assertEqual(src.keys, {BUNDLE, BLOB, 'accounts-cookie-secret'})
        self.assertTrue(src.cookie)
        self.assertEqual(src.overrides, ['sharing_mode'])

    def test_links_in_the_cluster_are_copied_and_out_of_the_store_are_left_out(self):
        """O-02: a hard link in HA's database folder comes as an ordinary file with the content (the reader hands the same
        name out again after the walk). O-03: a hard link of the artifact store to a file outside it is never carried and
        never copied, whether the reader hands it out as a link (its file was handed out) or as a copy of a file that the
        scan does not keep."""
        link = {'name': 'data/postgres/base/1/2', 'type': 'hardlink', 'linkname': 'data/postgres/base/1/1259'}
        report = habackup.Report(names=haissues.Names)
        src = ha_omnigent.scan_member(io.BytesIO(gzip.decompress(addon_tar(extra=[link]))), report)
        self.assertEqual(src.pg_links.first, ['base/1/2'])
        self.assertEqual((src.pg_files, report.copied_links), (6, 1), 'the copy is a file of the folder like the five others '
                         '(PG_VERSION, base/1/1259, pg_hba.conf, postgresql.conf, postmaster.pid)')
        for extra, left_out in (([{'name': 'data/omnigent-home/.omnigent/artifacts/x', 'type': 'hardlink',
                                   'linkname': 'data/postgres/base/1/1259'}], ['x']),
                                ([{'name': 'data/omnigent-home/.omnigent/artifacts/y', 'type': 'hardlink',
                                   'linkname': 'data/omnigent-home/.omnigent/telemetry.json'}], ['y'])):
            with self.subTest(extra=extra[0]['name']):
                report = habackup.Report(names=haissues.Names)
                src = ha_omnigent.scan_member(io.BytesIO(gzip.decompress(addon_tar(extra=extra))), report)
                self.assertEqual(src.outside_links.first, [f'檔案區裡指到區外的硬連結 {name}' for name in left_out])
                self.assertEqual(src.keys, {BUNDLE, BLOB, 'accounts-cookie-secret'}, 'it is no key of the store')
                self.assertEqual(src.artifact_files, 3)
        # a link that comes BEFORE the file it names (the reader hands it out after the walk, as a link: copied just the same)
        early = [{'name': 'data/postgres/base/1/3', 'type': 'hardlink', 'linkname': 'data/postgres/base/1/late'},
                 {'name': 'data/postgres/base/1/late', 'data': b'late'}]
        report = habackup.Report(names=haissues.Names)
        src = ha_omnigent.scan_member(io.BytesIO(gzip.decompress(addon_tar(extra=early))), report)
        self.assertEqual((src.pg_links.first, report.copied_links, src.pg_files), (['base/1/3'], 1, 7))
        art = 'data/omnigent-home/.omnigent/artifacts'
        early_in = [{'name': f'{art}/z', 'type': 'hardlink', 'linkname': f'{art}/late'}, {'name': f'{art}/late', 'data': b'x'}]
        src = ha_omnigent.scan_member(io.BytesIO(gzip.decompress(addon_tar(extra=early_in))), habackup.Report())
        self.assertEqual((src.outside_links.count, 'z' in src.keys, 'late' in src.keys), (0, True, True))
        inside = [{'name': 'data/omnigent-home/.omnigent/artifacts/z', 'type': 'hardlink',
                   'linkname': f'data/omnigent-home/.omnigent/artifacts/{BLOB}'}]
        src = ha_omnigent.scan_member(io.BytesIO(gzip.decompress(addon_tar(extra=inside))), habackup.Report())
        self.assertEqual((src.outside_links.count, 'z' in src.keys), (0, True), 'a link inside the store stays a link')

    def test_a_tablespace_or_a_symlink_in_the_cluster_is_refused(self):
        for extra in ([{'name': 'data/postgres/pg_tblspc', 'type': 'dir'},
                       {'name': 'data/postgres/pg_tblspc/16999', 'type': 'symlink', 'linkname': '/mnt/other'}],
                      [{'name': 'data/postgres/base/1/9999', 'type': 'symlink', 'linkname': '1259'}]):
            with self.subTest(extra=extra[-1]['name']), self.assertRaises(BackupError) as caught:
                ha_omnigent.scan_member(io.BytesIO(gzip.decompress(addon_tar(extra=extra))), habackup.Report())
            self.assertEqual(caught.exception.code, 'incompatible')
            self.assertIn('表空間', caught.exception.message)

    def test_toc_kinds(self):
        text = TOC.decode() + '3700; 1255 16700 FUNCTION public evil() omnigent\n9; 1 2 WEIRD thing\n'
        kinds = ha_omnigent.toc_kinds(text)
        self.assertIn('TABLE DATA', kinds)
        self.assertIn('COMMENT', kinds)
        self.assertIn('FUNCTION', kinds)
        self.assertIn('UNKNOWN WEIRD', kinds)


class SkippedLineTests(OmnigentCase):
    """HAOS parity (O-03, O-12, O-14, O-15, O-16, O-21, O-28): what this device cannot take over -- tables, objects,
    extensions and links that are not Omnigent's, locations that could leave the artifact store -- is no refusal any more:
    it is left out, listed in ONE line to confirm, and the rest is moved. For each kind: the line is not confirmed -> only
    this app stops, before anything of HA is loaded; confirmed -> the conversion goes on and leaves exactly that out; one
    more name -> the same line asks again."""

    def restores(self):
        """Every pg_restore that writes into the new cluster: (role it runs as, argv, what it read)."""
        return [(cmd[cmd.index('-U') + 1], cmd, data) for role, cmd, data in self.world.execs
                if role == 'omni-db' and cmd[0] == 'pg_restore' and '-U' in cmd]

    def kind_tables(self, more=False):
        extra = ['evil', 'evil2'] if more else ['evil']
        self.world.objects = dict(self.world.objects, tables=self.world.objects['tables'] + extra)
        self.world.toc = TOC + b''.join(f'39{n}; 0 0 TABLE DATA public {t} x\n'.encode() for n, t in enumerate(extra))
        self.world.ha_columns = COLUMNS + [[t, 'id', 'integer', False, '', ''] for t in extra]
        sequences = [list(SEQUENCE)] + [[f'{t}_id_seq', 'bigint', 1, 1, 9223372036854775807, 1, 1, False, f'{t}.id']
                                        for t in extra]
        self.world.ha_signature = dict(signature(), sequences=sequences)
        return {}, [f'資料表 {t}' for t in extra]

    def kind_objects(self, more=False):
        self.world.objects = dict(self.world.objects, functions=1, **({'views': 2} if more else {}))
        self.world.toc = TOC + b'3700; 1255 16700 FUNCTION public evil() omnigent\n'
        return {}, ['函式'] + (['檢視表'] if more else [])

    def kind_superuser(self, more=False):
        self.world.superuser = ['EVENT TRIGGER'] + (['CAST'] if more else [])
        return {}, [f'只有資料庫超級使用者能建立的物件 {k}' for k in self.world.superuser]

    def kind_extensions(self, more=False):
        extra = ['dblink'] + (['hstore'] if more else [])
        self.world.objects = dict(self.world.objects, extensions=extra + ['pg_trgm', 'plpgsql'])
        return {}, [f'擴充功能 {e}' for e in extra]

    def kind_links(self, more=False):
        art = 'data/omnigent-home/.omnigent/artifacts'
        names = ['x', 'y'] if more else ['x']
        links = [{'name': f'{art}/{n}', 'type': 'hardlink', 'linkname': 'data/postgres/base/1/1259'} for n in names]
        return {'extra': links}, [f'檔案區裡指到區外的硬連結 {n}' for n in names]

    def kind_locations(self, more=False):
        bad = ['../../etc/passwd'] + (['/etc/shadow'] if more else [])
        self.world.keys = {'bundles': [BUNDLE, *bad], 'blobs': [BLOB]}
        return {}, [f'會跑出檔案區的代理程式位置（會被清空） {b}' for b in bad]

    def line_of(self, kind, more=False):
        upload, items = getattr(self, f'kind_{kind}')(more)
        ha_id = self.upload_omnigent(**upload)
        result = self.check(ha_id, ['omnigent'])[0]
        return ha_id, result, items

    def assert_not_confirmed(self, kind):
        ha_id, result, items = self.line_of(kind)
        self.assertTrue(result['importable'], 'a line to confirm is no stop')
        line = self.issues(result, 'omnigent.skipped')
        self.assertEqual((len(line), line[0]['level'], sorted(line[0]['items'])), (1, 'confirm', sorted(items)))
        self.assertEqual(self.issues(result, level='stop'), [])
        self.assertTrue(line[0]['key'].startswith('omnigent.skipped:'))
        key = line[0]['key']
        for acknowledged in (None, {}, {'omnigent': []}, {'hermes': [key]}, {'omnigent': ['omnigent.skipped:' + '0' * 16]}):
            self.world.forget()
            with self.assertRaises(BackupError) as caught:
                self.convert(ha_id, ['omnigent'], **({} if acknowledged is None else {'acknowledged': acknowledged}))
            self.assertEqual(caught.exception.code, 'confirmation-required', acknowledged)
            self.assertEqual(self.runs('omni-db'), [], 'nothing was created')
            self.assertFalse([cmd for _r, cmd, _d in self.world.execs if cmd[0] == 'pg_dump'], 'HA was not dumped')
            self.assert_nothing_loaded()

    def assert_confirmed_goes_on(self, kind):
        ha_id, result, items = self.line_of(kind)
        converted = self.convert(ha_id, ['omnigent'], acknowledged=self.confirmed(result))
        self.assertEqual(len(self.storage.list_backups()), 1)
        line = [i for i in converted['results'][0]['issues'] if i['id'] == 'omnigent.skipped']
        self.assertEqual([sorted(i['items']) for i in line], [sorted(items)], 'the conversion says what it left out')
        self.assertEqual(self.world.written['/tmp/woowbk-omnigent.toc'].decode().splitlines(), DATA_LINES,
                         'only the trusted TABLE DATA and SEQUENCE SET entries are loaded')
        return converted

    def assert_one_more_asks(self, kind):
        ha_id, result, _items = self.line_of(kind)
        keys = self.confirmed(result)
        self.world.forget()
        ha_id, more, items = self.line_of(kind, more=True)
        self.assertNotEqual(self.confirmed(more), keys, 'one more name is another key')
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['omnigent'], acknowledged=keys)
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertIn('請再確認一次', caught.exception.message)
        self.assert_nothing_loaded()
        self.world.forget()
        self.convert(ha_id, ['omnigent'], acknowledged=self.confirmed(more))
        self.assertEqual(len(self.storage.list_backups()), 1)

    def test_tables_not_confirmed(self):
        self.assert_not_confirmed('tables')

    def test_tables_confirmed(self):
        self.assert_confirmed_goes_on('tables')
        moved = self.world.volume_data
        self.assertEqual(sorted(moved), ['omnigent-pi-data', 'omnigent-postgres-data', 'omnigent-server-data'])

    def test_tables_one_more(self):
        self.assert_one_more_asks('tables')

    def test_objects_not_confirmed(self):
        self.assert_not_confirmed('objects')

    def test_objects_confirmed(self):
        self.assert_confirmed_goes_on('objects')

    def test_objects_one_more(self):
        self.assert_one_more_asks('objects')

    def test_superuser_objects_not_confirmed(self):
        self.assert_not_confirmed('superuser')

    def test_superuser_objects_confirmed(self):
        self.assert_confirmed_goes_on('superuser')

    def test_superuser_objects_one_more(self):
        self.assert_one_more_asks('superuser')

    def test_extensions_not_confirmed(self):
        self.assert_not_confirmed('extensions')

    def test_extensions_confirmed(self):
        self.assert_confirmed_goes_on('extensions')

    def test_extensions_one_more(self):
        self.assert_one_more_asks('extensions')

    def test_a_table_both_have_that_this_module_does_not_know_stops_instead_of_loading_unverified_data(self):
        """The one way the left-out list and the trusted schema could disagree (an Omnigent newer than this module's list of
        19 tables adds a table that HA's database has too): the table is not compared (it is not Omnigent's as far as this
        module knows), but its data would be selected -- the conversion compares the columns of the tables that are moved with
        the new cluster's first, and stops: nothing of HA is ever loaded into a table whose shape was not compared."""
        future = [['future', 'id', 'integer', True, '', '']]
        self.world.objects = dict(self.world.objects, tables=self.world.objects['tables'] + ['future'])
        self.world.ha_columns = COLUMNS + future
        self.world.live_columns = COLUMNS + future
        self.world.restored_signature = None
        self.world.toc = TOC + b'3990; 0 0 TABLE DATA public future x\n'
        real = self.world.answer

        def answer(role, sql, database):
            if sql == ha_omnigent.SCHEMA_SIGNATURE_SQL and role != 'hapg':
                found = dict(real(role, sql, database))
                found['relations'] = found['relations'] + [['future', 'r', 'p', False, False, '', False]]
                return found
            return real(role, sql, database)
        self.world.answer = answer
        ha_id = self.upload_omnigent()
        result = self.check(ha_id, ['omnigent'])[0]
        self.assertEqual([i['items'] for i in self.issues(result, 'omnigent.skipped')], [['資料表 future']])
        self.world.forget()
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['omnigent'], acknowledged=self.confirmed(result))
        self.assertEqual((caught.exception.code, caught.exception.message), ('incompatible', 'HA 與目標 Omnigent 的資料表欄位結構不同。'))
        self.assert_nothing_loaded()

    def test_nothing_of_the_superuser_kinds_is_ever_selected(self):
        """O-15 (security re-review, DESIGN H-c): the objects only a database superuser can make stay in HA's cluster, which
        is opened in the isolated throwaway as it was for the check; what the conversion restores into the new cluster
        is the list of table data and sequence values of this device's own tables, whatever else HA's dump lists, and
        it is loaded by the role without privileges (never the superuser)."""
        kinds = ha_odoo.SUPERUSER_KINDS + ('FUNCTION', 'TRIGGER', 'VIEW', 'RULE', 'POLICY', 'EXTENSION hstore', 'SCHEMA evil',
                                           'FOREIGN TABLE', 'LARGE OBJECT')
        listing = ''.join(f'4{n:03d}; 1255 17{n:03d} {kind} public x{n} omnigent\n' for n, kind in enumerate(kinds))
        self.world.toc = TOC + listing.encode()
        self.world.superuser = ['EVENT TRIGGER', 'FOREIGN DATA WRAPPER']
        ha_id = self.upload_omnigent()
        result = self.check(ha_id, ['omnigent'])[0]
        self.convert(ha_id, ['omnigent'], acknowledged=self.confirmed(result))
        self.assertEqual(self.world.written['/tmp/woowbk-omnigent.toc'].decode().splitlines(), DATA_LINES)
        data = [(user, cmd) for user, cmd, _d in self.restores() if '-L' in cmd]
        self.assertEqual([(u, c[c.index('-L') + 1]) for u, c in data], [(ha_omnigent.RESTORE_ROLE, '/tmp/woowbk-omnigent.toc')])
        self.assertEqual([user for user, cmd, _d in self.restores() if '-L' not in cmd], ['omnigent', 'omnigent'],
                         "the rest is this device's own schema, by the app role")
        self.assertEqual(len(self.runs('omni-db')), 1)

    def test_links_not_confirmed(self):
        self.assert_not_confirmed('links')

    def test_links_confirmed(self):
        self.assert_confirmed_goes_on('links')
        server = self.volume('omnigent-server-data')
        self.assertNotIn('artifacts/x', server, 'a link to a file outside the store is never carried, nor copied')
        self.assertIn(f'artifacts/{BUNDLE}', server)

    def test_links_one_more(self):
        self.assert_one_more_asks('links')

    def test_locations_not_confirmed(self):
        self.assert_not_confirmed('locations')

    def test_locations_confirmed(self):
        self.assert_confirmed_goes_on('locations')

    def test_locations_one_more(self):
        self.assert_one_more_asks('locations')


class RowTests(OmnigentCase):
    """The rows of the HAOS parity list that are not a line to confirm (DESIGN F-d): what is done by itself (auto), what is
    only told (notice), what is no refusal any more (removed). Each shows that it works and that what cannot be handled
    still stops this app only."""

    LIVE_USERS = 'SELECT coalesce(json_agg(u ORDER BY u.id)'

    def stopped_with(self, code, words):
        self.world.forget()
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual((caught.exception.code, caught.exception.message[:len(words)]), (code, words))
        self.assertEqual(self.storage.list_backups(), [])
        return caught.exception

    # ------------------------------------------------------------------ O-01
    def test_the_dump_runs_as_a_spare_id_when_the_list_has_none(self):
        from woowbackup import nested
        tiny = nested.IdMap('0 1013 1\n1 100000 100\n')      # none of 65534, 32767, 9999, 999 is mapped
        with mock.patch.object(fk, 'IDS', (tiny, tiny)):
            self.convert(self.upload_omnigent(), ['omnigent'])
        dumps = [user for user, args in self.world.exec_users if 'pg_dump' in args and any(a.endswith('-hapg') for a in args)]
        self.assertEqual(dumps, ['100:100'])

    def test_no_id_at_all_stops_the_conversion_before_the_dump(self):
        from woowbackup import nested
        only_root = nested.IdMap('0 1013 1\n')
        with mock.patch.object(fk, 'IDS', (only_root, only_root)):
            error = self.stopped_with('job-failed', '這台的使用者命名空間沒有可用來匯出 HA 資料庫的帳號 ID')
        self.assertFalse([cmd for _r, cmd, _d in self.world.execs if cmd[0] == 'pg_dump'])
        self.assertEqual(self.world.manifests, {})
        self.assertEqual(error.code, 'job-failed')

    # ------------------------------------------------------------------ O-02
    def test_hard_links_in_has_database_folder_are_copied_as_files(self):
        link = {'name': 'data/postgres/base/1/2', 'type': 'hardlink', 'linkname': 'data/postgres/base/1/1259'}
        result = self.check_one(extra=[link])
        self.assertTrue(result['importable'])
        auto = self.issues(result, 'omnigent.hardlinks-copied')
        self.assertEqual((auto[0]['level'], auto[0]['items']), ('auto', ['base/1/2']))
        self.convert(self.upload_omnigent(extra=[link]), ['omnigent'])
        with tarfile.open(fileobj=io.BytesIO(self.world.imported['hapg'])) as tar:
            members = {m.name: m for m in tar.getmembers()}
            self.assertTrue(members['base/1/2'].isfile(), 'an ordinary file in the throwaway cluster, not a link')
            self.assertEqual(tar.extractfile('base/1/2').read(), b'page', "with the content of the file it named")
        self.assertEqual(len(self.storage.list_backups()), 1)

    def test_a_hard_link_with_no_file_behind_it_is_asked_about_and_stops_only_this_app(self):
        link = {'name': 'data/postgres/base/1/9', 'type': 'hardlink', 'linkname': 'data/postgres/base/1/nowhere'}
        result = self.check_one(extra=[link])
        line = self.issues(result, 'files.skipped')
        self.assertEqual((len(line), line[0]['level']), (1, 'confirm'))
        self.assertTrue(result['importable'])
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_omnigent(extra=[link]), ['omnigent'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assert_nothing_loaded()

    # ------------------------------------------------------------------ O-07
    def test_this_devices_other_volumes_go_along_as_they_are(self):
        self.catalog['omnigent'].volumes = self.catalog['omnigent'].volumes + [{'name': 'omnigent-extra-data'}]
        result = self.check_one()
        self.assertTrue(result['importable'])
        auto = self.issues(result, 'omnigent.extras-carried')
        self.assertEqual((auto[0]['level'], auto[0]['items']), ('auto', ['omnigent-extra-data']))
        converted = self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertIn('omnigent-extra-data', self.world.exported(), 'read from this device while the app runs')
        self.assertEqual(sorted(self.world.manifests['omnigent']['volumes']),
                         ['omnigent-extra-data', 'omnigent-pi-data', 'omnigent-postgres-data', 'omnigent-server-data'])
        self.assertIn('PG_VERSION', self.volume('omnigent-extra-data'))
        notes = converted['ha_import']['notes']
        self.assertTrue(any('omnigent-extra-data' in line and '原樣帶過去' in line for line in notes), notes)

    def test_a_missing_or_doubled_volume_still_stops_with_extra_ones_around(self):
        extra = {'name': 'omnigent-extra-data'}
        for name, change in (('one of the three is missing', lambda vols: [v for v in vols if v['name'] != 'omnigent-pi-data']),
                             ('one is listed twice', lambda vols: vols + [dict(vols[0])])):
            with self.subTest(name=name):
                self.catalog['omnigent'].volumes = change(self.catalog_apps()['omnigent'].volumes + [extra])
                result = self.check_one()
                self.assertFalse(result['importable'])
                self.assertIn('資料卷、資料庫設定和 Quadlet 檔不一致', '\n'.join(result['blockers']))

    # ------------------------------------------------------------------ O-09
    def test_this_devices_accounts_that_cannot_be_read_are_not_kept_and_the_import_goes_on(self):
        with self.answering('omnigent-postgres', self.LIVE_USERS, {}):
            converted = self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual(self.world.carried(), [])
        issue = next(i for i in converted['results'][0]['issues'] if i['id'] == 'omnigent.accounts-unreadable')
        self.assertEqual((issue['level'], issue['items']), ('notice', ['admin', 'operator']))
        self.assertTrue(any('帳號沒有讀到' in line for line in converted['ha_import']['reminders_by_app']['omnigent']))
        self.assertEqual(len(self.storage.list_backups()), 1)

    def test_a_read_that_fails_once_is_read_again(self):
        real, asked = self.world.answer, []

        def answer(role, sql, database):
            if role == 'omnigent-postgres' and sql.startswith(self.LIVE_USERS):
                asked.append(sql)
                if len(asked) == 1:
                    return {}
            return real(role, sql, database)
        self.world.answer = answer
        self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual((len(asked), [row['id'] for row in self.world.carried()]), (2, ['admin', 'operator']))

    def test_a_read_that_is_refused_stops_this_app(self):
        from woowbackup.podman import CommandError
        real = self.world.answer

        def answer(role, sql, database):
            if role == 'omnigent-postgres' and sql.startswith(self.LIVE_USERS):
                raise CommandError('podman exec 執行失敗（結束碼 2）。', returncode=2,
                                   stderr=b'FATAL:  password authentication failed for user "omnigent"')
            return real(role, sql, database)
        self.world.answer = answer
        error = self.stopped_with('job-failed', '無法讀取這台「Omnigent 協作平台」的資料庫')
        self.assertIn('帳號或密碼', error.message)

    # ------------------------------------------------------------------ O-40, O-41
    def test_a_database_that_is_not_running_is_started_to_be_read_and_put_back(self):
        """CM-07 for O-40, O-41, O-32..: this device's database is stopped: its own unit is started, the structure is read,
        and the unit is stopped again when the app's throwaway objects are cleaned up (check and conversion alike)."""
        for step in ('check', 'convert'):
            with self.subTest(step=step):
                self.world.forget()
                self.world.units.clear()
                self.world.db_stopped = True
                if step == 'check':
                    self.assertTrue(self.check_one()['importable'])
                else:
                    self.convert(self.upload_omnigent(), ['omnigent'])
                started = [unit for unit in self.world.units if unit[0] == 'start']
                self.assertEqual(started, [('start', '--', 'omnigent-postgres.service')])
                self.assertEqual(self.world.units[-1], ('stop', '--', 'omnigent-postgres.service'), 'put back')
                self.assertTrue(self.world.db_stopped)

    def test_this_devices_structure_is_read_again_when_the_answer_is_odd(self):
        for name, wanted, odd in (('the structure version', 'SELECT coalesce(json_agg(version_num)', {}),
                                  ('the columns', ha_omnigent.SCHEMA_COLUMNS_SQL, []),
                                  ('the signature', ha_omnigent.SCHEMA_SIGNATURE_SQL, None)):
            with self.subTest(name=name):
                real, asked = self.world.answer, []

                def answer(role, sql, database, wanted=wanted, odd=odd):
                    if role == 'omnigent-postgres' and sql.startswith(wanted):
                        asked.append(1)
                        if len(asked) == 1:
                            return odd
                    return real(role, sql, database)
                self.world.answer = answer
                self.world.forget()
                self.assertTrue(self.check_one()['importable'])
                self.assertGreaterEqual(len(asked), 2, 'read again')
                self.world.answer = real

    def test_this_devices_structure_that_is_never_readable_stops_this_app(self):
        revision = 'SELECT coalesce(json_agg(version_num)'
        for name, wanted, odd, ident, message in (
                ('the structure version', revision, {}, 'omnigent.target-unreadable', '無法讀取這台 Omnigent 的資料庫結構版本。'),
                ('the columns', ha_omnigent.SCHEMA_COLUMNS_SQL, [], 'failure.incompatible', '無法確認這台 Omnigent 的資料表結構。'),
                ('the signature', ha_omnigent.SCHEMA_SIGNATURE_SQL, None, 'failure.incompatible', '無法確認 Omnigent 的資料庫結構。')):
            with self.subTest(name=name), self.answering('omnigent-postgres', wanted, odd):
                result = self.check_one()
                self.assertEqual([(i['id'], i['message']) for i in self.issues(result, level='stop')][0][0], ident)
                self.assertIn(message, '\n'.join(result['blockers']))
                self.assertFalse(result['importable'])
                self.stopped_with('incompatible', message)

    # ------------------------------------------------------------------ O-18
    def test_an_image_without_pg_major_is_asked_through_its_database(self):
        with mock.patch.object(self.world, 'image_info', lambda image: {'id': 'sha256:' + 'c' * 64, 'env': []}):
            self.assertTrue(self.check_one()['importable'], 'the database it runs here says 16')
            self.world.forget()
            self.convert(self.upload_omnigent(), ['omnigent'])
            self.assertEqual(len(self.storage.list_backups()), 1)

    def test_a_postgresql_newer_than_the_image_stops_this_app(self):
        for name, env, live, pg_version in (('PG_MAJOR says 16', ['PG_MAJOR=16'], 16, b'17\n'),
                                            ('the database says 15', [], 15, b'16\n')):
            with self.subTest(name=name), mock.patch.object(self.world, 'image_info', lambda image, env=env: {
                    'id': 'sha256:' + 'c' * 64, 'env': env}):
                self.world.live_major = live
                result = self.check_one(pg_version=pg_version)
                self.assertEqual([i['id'] for i in self.issues(result, level='stop')], ['omnigent.pg-newer'])
                self.assertFalse(result['importable'])

    # ------------------------------------------------------------------ O-20
    def test_a_missing_login_key_is_a_notice_and_nothing_of_it_is_carried(self):
        result = self.check_one(cookie=False)
        self.assertTrue(result['importable'])
        self.assertEqual([i['level'] for i in self.issues(result, 'omnigent.cookie-missing')], ['notice'])
        converted = self.convert(self.upload_omnigent(cookie=False), ['omnigent'])
        self.assertNotIn('artifacts/accounts-cookie-secret', self.volume('omnigent-server-data'),
                         'neither HA\'s nor this device\'s: Omnigent makes a new one')
        self.assertTrue(any('自己產生新的' in line for line in converted['ha_import']['notes']))

    def test_an_empty_or_huge_login_key_is_no_key(self):
        art = 'data/omnigent-home/.omnigent/artifacts'
        for name, data in (('empty', b''), ('huge', b'k' * 5000)):
            with self.subTest(name=name):
                extra = [{'name': f'{art}/accounts-cookie-secret', 'data': data, 'mode': 0o600}]
                result = self.check_one(cookie=False, extra=extra)
                self.assertEqual([i['id'] for i in self.issues(result, 'omnigent.cookie-missing')], ['omnigent.cookie-missing'])
                src = ha_omnigent.scan_member(io.BytesIO(gzip.decompress(addon_tar(cookie=False, extra=extra))),
                                              habackup.Report())
                self.assertEqual((src.cookie, src.cookie_unusable, 'accounts-cookie-secret' in src.keys), (False, True, False))

    # ------------------------------------------------------------------ O-21
    def test_the_rule_of_an_artifact_key(self):
        for key in (BUNDLE, BLOB, 'a b/c', 'ünï/çode', 'a/b/c/d/e/f', 'a' * 255, 'x.y/z-1_2+3', 'a/' * 15 + 'b'):
            self.assertTrue(ha_omnigent.key_ok(key), key)
        for key in ('', '/abs/olute', '../x', 'a/../b', 'a//b', 'a/./b', '.', '..', 'a\\b', 'x\x00y', 'a/‮/b', 'a\nb',
                    'a' * 256, 'a/' * 16 + 'b', ('a' * 100 + '/') * 6, None, 5):
            self.assertFalse(ha_omnigent.key_ok(key), repr(key))

    def test_the_locations_that_could_leave_the_store_are_cleared_by_the_role_without_privileges(self):
        self.world.keys = {'bundles': [BUNDLE, '../../etc/passwd', "x'y/../z"], 'blobs': [BLOB]}
        ha_id = self.upload_omnigent()
        result = self.check(ha_id, ['omnigent'])[0]
        converted = self.convert(ha_id, ['omnigent'], acknowledged=self.confirmed(result))
        statements = self.world.executed('omni-db')
        grant = [s for s in statements if s.startswith('GRANT SELECT (bundle_location), UPDATE (bundle_location)')]
        self.assertEqual(len(grant), 1)
        self.assertIn(f'TO {ha_omnigent.RESTORE_ROLE}', grant[0])
        update = [s for s in self.world.restricted() if "SET bundle_location = ''" in s]
        self.assertEqual(len(update), 1, 'by the role without privileges, on stdin')
        text = update[0]
        literal = re.search(r"json_array_elements_text\('((?:[^']|'')*)'::json\)", text)
        outside = text.replace(literal.group(0), '')
        self.assertTrue(outside.startswith("BEGIN;\nUPDATE public.agents SET bundle_location = '' WHERE bundle_location IN"))
        self.assertNotIn('passwd', outside, 'nothing of HA outside the one literal')
        payload = json.loads(literal.group(1).replace("''", "'"))
        self.assertEqual(payload, sorted(["../../etc/passwd", "x'y/../z"]), 'the unsafe ones; the safe one is left alone')
        self.assertTrue(any('已清空' in note for note in converted['ha_import']['notes']))
        self.assertTrue(any('清空了 2 個' in line for line in self.reporter.logs))

    def test_a_location_that_is_still_unsafe_after_the_clearing_stops_the_conversion(self):
        self.world.keys = {'bundles': [BUNDLE, '../../etc/passwd'], 'blobs': [BLOB]}
        ha_id = self.upload_omnigent()
        keys = self.confirmed(self.check(ha_id, ['omnigent'])[0])
        real = self.world.answer

        def answer(role, sql, database):
            if role == 'omni-db' and sql == ha_omnigent.KEYS_SQL:
                return self.world.keys      # the new cluster still holds the unsafe one
            return real(role, sql, database)
        self.world.answer = answer
        self.world.forget()
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['omnigent'], acknowledged=keys)
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertIn('仍有會跑出檔案區的代理程式位置', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])

    # ------------------------------------------------------------------ O-22
    def missing_files(self, more=False):
        self.world.keys = {'bundles': [BUNDLE, f'{AGENT}/{"9" * 64}'] + ([f'{AGENT}/{"8" * 64}'] if more else []), 'blobs': [BLOB]}

    def test_missing_files_not_confirmed(self):
        self.missing_files()
        ha_id = self.upload_omnigent()
        result = self.check(ha_id, ['omnigent'])[0]
        line = self.issues(result, 'omnigent.files-missing')
        self.assertEqual((len(line), line[0]['level'], line[0]['items']), (1, 'confirm', [f'{AGENT}/{"9" * 64}']))
        self.assertTrue(result['importable'])
        for acknowledged in (None, {}, {'omnigent': []}):
            self.world.forget()
            with self.assertRaises(BackupError) as caught:
                self.convert(ha_id, ['omnigent'], **({} if acknowledged is None else {'acknowledged': acknowledged}))
            self.assertEqual(caught.exception.code, 'confirmation-required')
            self.assert_nothing_loaded()

    def test_missing_files_confirmed(self):
        self.missing_files()
        ha_id = self.upload_omnigent()
        converted = self.convert(ha_id, ['omnigent'], acknowledged=self.confirmed(self.check(ha_id, ['omnigent'])[0]))
        self.assertEqual(len(self.storage.list_backups()), 1)
        self.assertEqual([i['items'] for i in converted['results'][0]['issues'] if i['id'] == 'omnigent.files-missing'],
                         [[f'{AGENT}/{"9" * 64}']])

    def test_missing_files_one_more(self):
        self.missing_files()
        ha_id = self.upload_omnigent()
        keys = self.confirmed(self.check(ha_id, ['omnigent'])[0])
        self.missing_files(more=True)
        self.world.forget()
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['omnigent'], acknowledged=keys)
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assert_nothing_loaded()

    def test_when_no_file_of_the_store_is_there_at_all_the_line_says_so(self):
        result = self.check_one(artifacts=False)
        line = self.issues(result, 'omnigent.files-missing')
        self.assertEqual(len(line), 1)
        self.assertIn('完全沒有它們要的檔案', line[0]['message'])
        self.assertEqual(sorted(line[0]['items']), sorted([BUNDLE, BLOB]))

    # ------------------------------------------------------------------ O-44
    def test_a_newer_extension_version_of_the_new_cluster_is_no_difference(self):
        newer = dict(signature(), extensions=[['pg_trgm', '1.7', 'public'], ['plpgsql', '1.0', 'pg_catalog']])
        self.world.restored_signature = newer
        converted = self.convert(self.upload_omnigent(), ['omnigent'])
        issue = next(i for i in converted['results'][0]['issues'] if i['id'] == 'omnigent.extension-version')
        self.assertEqual((issue['level'], issue['items']), ('auto', ['pg_trgm 1.6 -> 1.7']))
        self.assertEqual(len(self.storage.list_backups()), 1)

    def test_another_set_of_extensions_still_stops(self):
        for name, extensions in (('one more', [['pg_trgm', '1.6', 'public'], ['plpgsql', '1.0', 'pg_catalog'],
                                                ['hstore', '1.8', 'public']]),
                                 ('one less', [['plpgsql', '1.0', 'pg_catalog']]),
                                 ('another schema', [['pg_trgm', '1.6', 'evil'], ['plpgsql', '1.0', 'pg_catalog']])):
            with self.subTest(name=name):
                self.world.restored_signature = dict(signature(), extensions=extensions)
                self.world.forget()
                with self.assertRaises(BackupError) as caught:
                    self.convert(self.upload_omnigent(), ['omnigent'])
                self.assertEqual(caught.exception.code, 'job-failed')
                self.assertIn('extensions', caught.exception.message)
                self.assertEqual(self.storage.list_backups(), [])

    def test_the_drift_rule_on_its_own(self):
        live = [['pg_trgm', '1.6', 'public'], ['plpgsql', '1.0', 'pg_catalog']]
        self.assertEqual(ha_omnigent.extension_drift(live, live), [])
        self.assertEqual(ha_omnigent.extension_drift([['pg_trgm', '1.5', 'public'], live[1]], live), ['pg_trgm 1.6 -> 1.5'])
        for found in (live[:1], live + [['x', '1', 'public']], [['pg_trgm', '1.6', 'other'], live[1]], 'x', [[1]]):
            self.assertIsNone(ha_omnigent.extension_drift(found, live), found)

    # ------------------------------------------------------------------ O-50
    def test_the_conversion_says_what_the_check_said(self):
        """The conversion asks the same questions again and tells the same findings (the same ids, levels and names)."""
        self.world.objects = dict(self.world.objects, functions=1, tables=self.world.objects['tables'] + ['evil'])
        self.world.keys = {'bundles': [BUNDLE, f'{AGENT}/{"9" * 64}'], 'blobs': [BLOB]}
        ha_id = self.upload_omnigent(cookie=False)
        result = self.check(ha_id, ['omnigent'])[0]
        converted = self.convert(ha_id, ['omnigent'], acknowledged=self.confirmed(result))
        shape = lambda issues: sorted((i['id'], i['level'], tuple(i['items'])) for i in issues  # noqa: E731
                                      if i['id'] != 'omnigent.entries-skipped')
        self.assertEqual(shape(converted['results'][0]['issues']), shape(result['issues']))
        self.assertEqual({i['level'] for i in result['issues']} >= {'confirm', 'notice'}, True)

    def test_the_first_stop_of_the_conversion_is_the_check_s(self):
        self.world.objects = dict(self.world.objects, encoding='SQL_ASCII', functions=1)
        self.world.ha_alembic = ['older']
        result = self.check_one()
        stops = [i['id'] for i in self.issues(result, level='stop')]
        self.assertEqual(stops, ['omnigent.encoding', 'omnigent.alembic-different'])
        error = self.stopped_with('incompatible', 'HA 的 Omnigent 資料庫不是 UTF8 編碼。')
        self.assertEqual(error.issues[0].id, 'omnigent.encoding', 'a stop comes before a question')

    # ------------------------------------------------------------------ O-61
    def test_a_huge_pg_version_file_is_read_by_its_start_only(self):
        result = self.check_one(pg_version=b'16\n' + b'x' * 70000)
        self.assertTrue(result['importable'])
        src = ha_omnigent.scan_member(io.BytesIO(gzip.decompress(addon_tar(pg_version=b'16\n' + b'x' * 70000))),
                                      habackup.Report())
        self.assertEqual(src.pg_version, '16')
        self.convert(self.upload_omnigent(pg_version=b'16\n' + b'x' * 70000), ['omnigent'])
        with tarfile.open(fileobj=io.BytesIO(self.world.imported['hapg'])) as tar:
            self.assertEqual(len(tar.extractfile('PG_VERSION').read()), 70003, 'the whole file is copied; PostgreSQL judges it')

    # ------------------------------------------------------------------ O-13
    def test_a_table_that_ha_lacks_is_found_by_the_comparison_of_the_columns(self):
        self.world.objects = dict(self.world.objects, tables=[t for t in self.world.objects['tables'] if t != 'hosts'])
        self.world.live_columns = COLUMNS + [['hosts', 'id', 'text', True, '', '']]
        result = self.check_one()
        self.assertEqual([(i['id']) for i in self.issues(result, level='stop')], ['omnigent.schema-different'])
        self.assertIn('hosts', ha_omnigent.schema_blocker(['hosts']))
        self.assertIn('資料庫結構不同（hosts）', '\n'.join(result['blockers']))
        self.assertNotIn('缺少資料表', '\n'.join(result['blockers']), 'no block of its own any more')


if __name__ == '__main__':
    unittest.main()
