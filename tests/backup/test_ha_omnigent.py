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

from woowbackup import ha_odoo, ha_omnigent, habackup, haimport, jobs
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


class World(fk.World):
    def __init__(self):
        super().__init__()
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

    def podman(self, args, data, stdout):
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
            return Result(0, self.toc, b'')
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
                return self.keys
            if sql == ha_odoo.SUPERUSER_SQL:
                return []
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
        self.server_version = '0.21.0'
        self.addCleanup(jobs.unmask_secret, HASH)
        self.addCleanup(jobs.unmask_secret, HASH + 'op')

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
        token, '16.') and the HA backup's name (hastore refuses only C0 control characters) reach the job log as HA
        wrote them. Through the real JobStore every message stays one line without control characters: no forged
        line reaches the page."""
        from types import SimpleNamespace
        ha_id = self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', addon_tar(pg_version=b'16.\x0bFORGED OK\n'))],
                                           hx.ha_doc(addons=(SLUG,), name='WOOW FORGED 轉換完成：全部成功')))
        self.check(ha_id, ['omnigent'])
        logged = [str(message) for message in self.reporter.logs]
        self.assertTrue(any('PostgreSQL 16.\x0bFORGED' in m for m in logged), 'the source: HA text as it is')
        self.assertTrue(any('WOOW FORGED' in m for m in logged), 'the source: HA text as it is')
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
        """The verifier's SR-6 gap: HA's backup name (hastore refuses only C0 control characters) and a table name of
        HA's database can carry a Unicode bidirectional control; U+202E reverses how the rest of the line reads on the
        page. The check's blockers show it as '?' (hacommon.names) and, through the real JobStore, no job log line
        keeps one (jobs.LOG_CONTROL_RE)."""
        from types import SimpleNamespace
        bidi = set('\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069')
        self.world.objects = dict(self.world.objects, tables=self.world.objects['tables'] + ['evil\u202eLIAF'])
        ha_id = self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', addon_tar())],
                                           hx.ha_doc(addons=(SLUG,), name='WOOW\u202e\u2066 LIAF')))
        result = self.check(ha_id, ['omnigent'])[0]
        self.assertFalse(result['ok'])
        self.assertTrue(any('evil?LIAF' in blocker for blocker in result['blockers']), result['blockers'])
        self.assertFalse([blocker for blocker in result['blockers'] if set(blocker) & bidi])
        logged = [str(message) for message in self.reporter.logs]
        self.assertTrue(any('WOOW\u202e\u2066 LIAF' in m for m in logged), 'the source: HA text as it is')
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
        self.assertEqual((result['ok'], result['blockers'], result['version'], result['target_version']),
                         (True, [], '0.1.23', '0.21.0'))
        section = result['omnigent']
        self.assertEqual((section['omnigent_version'], section['alembic'], section['users'], section['artifact_files']),
                         ('0.21.0', ALEMBIC, 2, 3))
        self.assertEqual(section['override_files'], ['sharing_mode'])
        self.assertEqual(section['account_conflicts'], [])
        self.assertTrue(any('sharing_mode' in w for w in result['warnings']))
        self.assertTrue(any('1 個啟用中的排程' in w for w in result['warnings']))
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
        for kwargs, words in (({'version': '0.1.19'}, 'HA 的 Omnigent 是 0.20.0'),
                              ({'version': '0.9.0'}, '還不認得')):
            result = self.check(self.upload_omnigent(**kwargs), ['omnigent'])[0]
            self.assertFalse(result['ok'])
            self.assertIn(words, result['blockers'][0])
        self.world.ha_alembic = ['older']
        result = self.check(self.upload_omnigent(), ['omnigent'])[0]
        self.assertTrue(any('資料庫結構版本不同' in b for b in result['blockers']))
        self.world.ha_alembic = [ALEMBIC]
        self.server_version = None
        result = self.check(self.upload_omnigent(), ['omnigent'])[0]
        self.assertIn('無法讀取這台 Omnigent 的版本', result['blockers'][0])

    def test_what_the_check_refuses(self):
        self.world.objects = dict(self.world.objects, functions=1, tables=self.world.objects['tables'] + ['evil'])
        result = self.check(self.upload_omnigent(cookie=False), ['omnigent'])[0]
        joined = '\n'.join(result['blockers'])
        for words in ('evil', '函式', 'accounts-cookie-secret'):
            self.assertIn(words, joined)
        self.world.objects = dict(self.world.objects, functions=0, tables=list(ha_omnigent.TABLES) + ['alembic_version'])
        self.world.keys = {'bundles': [BUNDLE, f'{AGENT}/{"9" * 64}'], 'blobs': ['../../etc']}
        result = self.check(self.upload_omnigent(), ['omnigent'])[0]
        joined = '\n'.join(result['blockers'])
        self.assertIn('1 個代理程式包或檔案不在備份的檔案區裡', joined)
        self.assertNotIn('../../etc）', joined.split('格式不明')[0])
        self.assertIn('格式不明', joined)

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
        self.assertIn('evil?轉換完成?[32m', text)
        for blocker in result['blockers'] + [result['omnigent']['alembic']]:
            self.assertIsNone(re.search(r'[\x00-\x1f\x7f]', blocker), blocker)

    def test_a_different_schema_is_a_blocker_naming_the_tables(self):
        self.world.ha_columns = COLUMNS + [['users', 'extra', 'integer', False, '', '']]
        result = self.check(self.upload_omnigent(), ['omnigent'])[0]
        self.assertFalse(result['ok'])
        self.assertEqual([b for b in result['blockers'] if '資料庫結構不同' in b],
                         [ha_omnigent.schema_blocker(['users'])])
        self.assertEqual(self.world.live_reads, 1, "the live schema is read once, read only")
        self.assertFalse(self.runs('omni-db'), 'a check changes nothing')

    def test_a_same_named_account_is_a_warning(self):
        self.world.ha_users = ['admin', 'alice']
        result = self.check(self.upload_omnigent(), ['omnigent'])[0]
        self.assertTrue(result['ok'])
        self.assertEqual(result['omnigent']['account_conflicts'], ['admin'])
        self.assertTrue(any('相同名稱的帳號（admin）' in w for w in result['warnings']))


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

    def test_a_same_named_ha_account_wins(self):
        self.world.ha_users = ['admin', 'alice']
        self.world.live_rows.append(dict(self.world.live_rows[0], id='mallory'))   # not asked for, never carried
        result = self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual([row['id'] for row in self.world.carried()], ['operator'])
        self.assertTrue(any('HA 也有帳號 admin' in line for line in result['ha_import']['notes']))
        self.assertFalse(any(PAUSE in sql for sql in self.world.restricted()), 'not a test import')

    def test_code_in_has_database_never_runs(self):
        # A database with code is refused before anything is dumped or created.
        self.world.objects = dict(self.world.objects, functions=1)
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('函式', caught.exception.message)
        self.assertFalse(self.runs('omni-db'))
        self.assert_nothing_loaded()
        # HA's dump list with code, defaults and checks: none of those entries is ever selected.
        self.world.objects = dict(self.world.objects, functions=0)
        self.world.toc = TOC + b'3700; 1255 16700 FUNCTION public evil() omnigent\n'
        self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual(self.world.written['/tmp/woowbk-omnigent.toc'].decode().splitlines(), DATA_LINES)

    def test_a_name_with_a_line_break_cannot_add_an_entry(self):
        # pg_restore -L reads only the id at the start of a line: a second "users" line would be any entry of HA's.
        for extra in (b'3701; 0 0 TABLE DATA public users x\n', b'3702; 0 0 TABLE DATA public evil x\n',
                      b'3703; 0 0 SEQUENCE SET public other_seq x\n'):
            with self.subTest(extra=extra):
                self.world.toc = TOC + extra
                self.world.execs.clear()
                with self.assertRaises(BackupError) as caught:
                    self.convert(self.upload_omnigent(), ['omnigent'])
                self.assertIn('不屬於這台 Omnigent 資料庫結構', caught.exception.message)
                self.assert_nothing_loaded()

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
        tiny = nested.IdMap('0 1000 1\n1 100000 100\n')
        with self.assertRaises(BackupError):
            ha_omnigent.dump_user((tiny, tiny), (70, 70))

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

    def test_a_version_that_does_not_match_stops_the_conversion_itself(self):
        """The version rule of the check holds in the conversion too (nothing makes a job run the check first): an
        add-on version that ships another Omnigent or that this engine does not know, another live version and a live
        version that cannot be read stop before HA's database is read or anything is created."""
        for addon, live, words in (
                ('0.1.19', '0.21.0', '版本不同：HA 的 Omnigent 是 0.20.0（附加元件 0.1.19），這台是 0.21.0。'
                                     '請先讓兩邊的 Omnigent 版本一致後再匯入。'),
                ('0.9.0', '0.21.0', '無法確認 HA 附加元件版本 0.9.0 搭配的 Omnigent 版本（這台的資料表還不認得它），'
                                    '為避免版本不同而無法匯入；請先更新這台的 Cockpit。'),
                ('0.1.23', '0.22.0', '版本不同：HA 的 Omnigent 是 0.21.0（附加元件 0.1.23），這台是 0.22.0。'
                                     '請先讓兩邊的 Omnigent 版本一致後再匯入。'),
                ('0.1.23', None, '無法讀取這台 Omnigent 的版本。')):
            with self.subTest(addon=addon, live=live):
                self.server_version = live
                self.assert_stopped('incompatible', f'Omnigent 不能搬過來：{words}', upload={'version': addon})
                self.assertEqual(self.world.runs, [], 'no throwaway container, not even for the ids of an image')
                self.assertEqual(self.world.imported, {}, "HA's cluster was not read")
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
        """PostgreSQL's smart/fast shutdown ends with 0; 137 is the SIGKILL of `podman stop` after its grace time, 1
        an error during the shutdown. The files are then no clean copy: no export, not even pg_controldata."""
        for code in (137, 1, 143):
            with self.subTest(code=code):
                self.world.exit_codes['omni-db'] = code
                self.assert_stopped('job-failed', f'新的 PostgreSQL 叢集沒有正常關閉（結束碼 {code}）。')
                self.assertEqual(self.runs('controldata'), [])
        self.assertIn(('stop', '--time', '300', f'woowbk-{self.job_id}-omni-db'), self.world.owner.calls)

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

    def test_unregistered_quadlet_secrets_refuse_before_anything(self):
        self.catalog['omnigent'].secrets = [{'name': 'omnigent-postgres-password'}]
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertIn('機密未完整登記', caught.exception.message)
        self.assertFalse(self.runs('hapg'))


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
                ('one volume more', lambda app, files: app.volumes.append({'name': 'omnigent-other'}), mixed),
                ('one volume less', lambda app, files: app.volumes.pop(), mixed),
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
        """Each part of the verdict on its own: the check shows it as its only blocker and the conversion stops with
        it before anything of HA is dumped."""
        objects = dict(self.world.objects)
        odd = 'HA 的 Omnigent 資料庫含有 Omnigent 不會建立的物件（{}），無法安全地搬過來。'
        for name, changed, upload, words in (
                ('triggers', {'triggers': 1}, {}, odd.format('觸發程序')),
                ('views', {'views': 2}, {}, odd.format('檢視表')),
                ('rules', {'rules': 1}, {}, odd.format('規則')),
                ('policies', {'policies': 1}, {}, odd.format('資料列政策')),
                ('functions', {'functions': 1}, {}, odd.format('函式')),
                ('schemas', {'schemas': ['evil']}, {}, odd.format('其他結構描述（evil）')),
                ('extensions', {'extensions': ['dblink', 'pg_trgm', 'plpgsql']}, {},
                 'HA 的 Omnigent 資料庫使用了這台不支援的擴充功能：dblink。'),
                ('encoding', {'encoding': 'SQL_ASCII'}, {}, 'HA 的 Omnigent 資料庫不是 UTF8 編碼。'),
                ('a table more', {'tables': objects['tables'] + ['evil']}, {},
                 'HA 的 Omnigent 資料庫有 Omnigent 不會建立的資料表（evil），無法安全地搬過來。'),
                ('a newer PostgreSQL', {}, {'pg_version': b'17\n'},
                 'HA 的 PostgreSQL 是 17 版，這台是 16 版；只能從相同或較舊的版本搬過來。'),
                ('no PostgreSQL version', {}, {'pg_version': b'x\n'},
                 'HA 的 PostgreSQL 是 未知 版，這台是 16 版；只能從相同或較舊的版本搬過來。'),
                ('no cookie key', {}, {'cookie': False}, 'HA 備份裡找不到 Omnigent 的登入金鑰（accounts-cookie-secret）')):
            with self.subTest(name=name):
                self.world.objects = dict(objects, **changed)
                self.refused('incompatible', f'Omnigent 不能搬過來：{words}', upload=upload, check=words)
                self.assertFalse([cmd for _r, cmd, _d in self.world.execs if cmd[0] == 'pg_dump'])
                self.assertEqual(self.runs('omni-db'), [])
        self.world.objects = objects
        with self.answering('hapg', ha_odoo.SUPERUSER_SQL, ['EVENT TRIGGER']):
            words = 'HA 的 Omnigent 資料庫含有只有資料庫超級使用者才能建立的物件（EVENT TRIGGER），無法安全地搬過來。'
            self.refused('incompatible', f'Omnigent 不能搬過來：{words}', check=words)
        for value, words in ((None, '無法讀取這台 Omnigent 的資料庫結構版本。'), (['older'], '資料庫結構版本不同：HA 是')):
            self.world.live_alembic = value
            self.refused('incompatible', 'Omnigent 不能搬過來：資料庫結構版本不同', check=words)
        self.world.live_alembic, self.world.ha_alembic = [ALEMBIC], []
        self.refused('incompatible', 'Omnigent 不能搬過來：資料庫結構版本不同：HA 是 未知', check='資料庫結構版本不同：HA 是 未知')
        self.world.ha_alembic = [ALEMBIC]
        self.world.objects = dict(objects, tables=[t for t in objects['tables'] if t != 'hosts'])
        words = 'HA 的 Omnigent 資料庫缺少資料表（hosts），版本或資料可能不完整。'
        self.refused('incompatible', f'Omnigent 不能搬過來：{words}', check=words)
        self.world.objects = objects
        words = 'HA 的 PostgreSQL 是 16 版，這台是 未知 版；只能從相同或較舊的版本搬過來。'
        with mock.patch.object(self.world, 'image_info', lambda image: {'id': 'sha256:' + 'c' * 64, 'env': []}):
            self.refused('incompatible', f'Omnigent 不能搬過來：{words}', check=words)

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
                 'incompatible', 'HA 的 Omnigent 沒有 omnigent 資料庫。'),
                ('no objects', 'hapg', ha_omnigent.OBJECTS_SQL, [], 0, 'job-failed', '無法讀取 HA 的 Omnigent 資料庫。'),
                ("HA's columns: none", 'hapg', columns, [], 0, 'incompatible', no_tables),
                ("HA's columns: no list", 'hapg', columns, {'users': 1}, 0, 'incompatible', no_tables),
                ("HA's columns: a short row", 'hapg', columns, odd_row, 0, 'incompatible', no_tables),
                ("HA's signature: none", 'hapg', whole, None, 0, 'incompatible', no_schema),
                ("HA's signature: a part missing", 'hapg', whole, short, 0, 'incompatible', no_schema),
                ("HA's signature: a part more", 'hapg', whole, longer, 0, 'incompatible', no_schema),
                ('live columns: none', live, columns, [], 0, 'incompatible', mine),
                ('live columns: no list', live, columns, None, 0, 'incompatible', mine),
                ('live columns: a short row', live, columns, odd_row, 0, 'incompatible', mine),
                ('live signature: a part missing', live, whole, short, 0, 'incompatible', no_schema),
                ('live signature after the capture', live, whole, None, 1, 'incompatible', no_schema),
                ('live revision before the capture', live, revision, {}, 1, 'incompatible', no_revision),
                ('live revision after the capture', live, revision, [1], 2, 'incompatible', no_revision),
                ('new cluster: columns', 'omni-db', columns, None, 0, 'incompatible', no_tables),
                ('new cluster: schema after the load', 'omni-db', whole, short, 0, 'incompatible', no_schema),
                ('new cluster: schema after the last write', 'omni-db', whole, None, 1, 'incompatible', no_schema),
                ("this device's accounts", live, accounts, {}, 0, 'job-failed', '無法讀取這台 Omnigent 的帳號。'),
                ("HA's accounts in the new cluster", 'omni-db', 'SELECT coalesce(json_agg(id)', None, 0,
                 'job-failed', '無法確認 Omnigent 帳號。'),
                ('audit', 'omni-db', ha_omnigent.AUDIT_SQL, None, 0, 'job-failed', '無法檢查新的 PostgreSQL 叢集。')):
            with self.subTest(name=name), self.answering(role, wanted, value, skip=skip):
                self.refused(code, message)

    def test_a_live_version_that_cannot_be_read_is_no_version(self):
        """The live version is what this device's own server answers on the loopback address, or none: the conversion
        (and the check) then refuse instead of assuming a version."""
        def reply(status, body):
            return lambda url: (status, body)
        for name, info in (('an error page', reply(503, b'{"server_version": "0.21.0"}')),
                           ('no JSON', reply(200, b'<html>')), ('no object', reply(200, b'["0.21.0"]')),
                           ('no version', reply(200, b'{}')), ('no text', reply(200, b'{"server_version": 21}')),
                           ('no x.y.z', reply(200, b'{"server_version": "0.21.0\\n"}'))):
            with self.subTest(name=name), mock.patch.object(self, 'info', info):
                self.refused('incompatible', 'Omnigent 不能搬過來：無法讀取這台 Omnigent 的版本。',
                             check='無法讀取這台 Omnigent 的版本。')
        for url in ('http://192.0.2.1:8000/health', 'https://127.0.0.1:8000/health', None):
            with self.subTest(url=url), mock.patch.object(self, 'info', side_effect=AssertionError('asked')) as info:
                self.catalog['omnigent'].health = [{'type': 'http', 'url': url}] if url else []
                self.refused('incompatible', 'Omnigent 不能搬過來：無法讀取這台 Omnigent 的版本。')
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

    def test_links_in_the_cluster_or_out_of_the_store_are_refused(self):
        for extra in ([{'name': 'data/postgres/base/1/2', 'type': 'hardlink', 'linkname': 'data/postgres/base/1/1259'}],
                      [{'name': 'data/omnigent-home/.omnigent/artifacts/x', 'type': 'hardlink',
                        'linkname': 'data/postgres/base/1/1259'}]):
            with self.subTest(extra=extra[0]['name']), self.assertRaises(BackupError) as caught:
                ha_omnigent.scan_member(io.BytesIO(gzip.decompress(addon_tar(extra=extra))), habackup.Report())
            self.assertEqual(caught.exception.code, 'incompatible')

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


if __name__ == '__main__':
    unittest.main()
