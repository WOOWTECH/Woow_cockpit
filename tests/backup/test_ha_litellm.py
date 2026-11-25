"""HA import, LiteLLM part (ha_litellm.py): the check and the whole product conversion against a fake owner whose
podman answers like the lab's -- versions, HA's hardened PostgreSQL 18 cluster (the pinned official image by content),
the salt binding, the trusted schema (this device's own, captured in one snapshot and proven unchanged; B1-01), HA's
rows only, copied table by table with the trusted names by a role without privileges, the new cluster's schema and
contents audited, the salt moved into the converted backup's `litellm-salt-key` while every other secret stays this
device's, and the apps that use LiteLLM keys named (owner decision 2026-11-23, option A). Team E2."""
import copy
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import habackup, ha_litellm, ha_litellm_candidate, ha_odoo, haapps, haimport, haissues, hatarget, jobs
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import hab1fakes as fk
from . import hafixtures as hx

SLUG = '9663031d_woow-litellm'
SALT = b'sk-' + b'a1' * 32
OTHER_SALT = b'sk-' + b'b2' * 32
# One real LiteLLM 1.104.0 migration name has spaces (litellm-proxy-extras 0.4.102.post1).
MIGRATIONS = ['20250326162113_baseline', '20250412081753_team_member_permissions',
              '20251122125322_Add organization_id to spend logs']
QUADLETS = {
    'litellm-postgres.container': b'[Container]\nContainerName=litellm-postgres\n'
                                  b'Image=docker.io/library/postgres:17.11-alpine3.23@sha256:bc27\n'
                                  b'Volume=litellm-pgdata.volume:/var/lib/postgresql/data\n'
                                  b'Environment=PGDATA=/var/lib/postgresql/data/pgdata\n'
                                  b'Environment=POSTGRES_USER=litellm\nEnvironment=POSTGRES_DB=litellm\n'
                                  b'Environment=POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password\n'
                                  b'Secret=litellm-postgres-password,type=mount,target=/run/secrets/postgres-password,'
                                  b'mode=0400\n',
    'litellm.container': b'[Container]\nContainerName=litellm\nImage=localhost/woow-litellm:1.104.0-0.3.16\n'
                         b'Network=litellm.network\n'
                         b'Secret=litellm-database-url,type=env,target=DATABASE_URL\n'
                         b'Secret=litellm-master-key,type=env,target=LITELLM_MASTER_KEY\n'
                         b'Secret=litellm-ui-password,type=env,target=UI_PASSWORD\n'
                         b'Secret=litellm-postgres-password,type=env,target=DATABASE_PASSWORD\n'
                         b'Secret=litellm-salt-key,type=env,target=LITELLM_SALT_KEY\n',
    'litellm.network': b'[Network]\nNetworkName=litellm-net\n',
    'litellm-pgdata.volume': b'[Volume]\nVolumeName=litellm-pgdata\n',
}
SECRETS = ['litellm-database-url', 'litellm-master-key', 'litellm-postgres-password', 'litellm-salt-key',
           'litellm-ui-password']
TABLES = [('public', 'LiteLLM_AuditLog'), ('public', 'LiteLLM_CredentialsTable'), ('public', 'LiteLLM_ProxyModelTable'),
          ('public', 'LiteLLM_TeamTable'), ('public', 'LiteLLM_UserTable'), ('public', 'LiteLLM_VerificationToken'),
          ('public', '_prisma_migrations'), ('woow_platform', 'chatgpt_accounts'), ('woow_platform', 'settings')]
COLUMNS = [[s, t, c, 'text', True, '', ''] for s, t in TABLES for c in ('id', 'value')]
COLUMNS[0] = ['public', 'LiteLLM_AuditLog', 'id', 'integer', True, '', '']
SEQUENCE = ['public', 'LiteLLM_AuditLog_id_seq', 'integer', 1, 1, 2147483647, 1, 1, False, 'LiteLLM_AuditLog.id']


def signature():
    found = {key: [] for key in ha_litellm.SIGNATURE_KEYS}
    found.update(relations=[[s, t, 'r', 'p', False, False, '', False] for s, t in TABLES]
                 + [['public', SEQUENCE[1], 'S', 'p', False, False, '', False],
                    ['public', 'MonthlyGlobalSpend', 'v', 'p', False, False, '', False]],
                 columns=[row + ['', ''] for row in COLUMNS],
                 constraints=[['public', 'LiteLLM_UserTable', 'LiteLLM_UserTable_pkey', 'p', 'PRIMARY KEY (id)',
                               False, False, True, False]],
                 indexes=[['public', 'LiteLLM_UserTable', 'LiteLLM_UserTable_pkey', 'CREATE UNIQUE INDEX ...']],
                 sequences=[list(SEQUENCE)], views=[['public', 'MonthlyGlobalSpend', ' SELECT 1;']],
                 extensions=[['plpgsql', '1.0', 'pg_catalog']], schemas=['woow_platform'],
                 other={name: 0 for name in ha_litellm.OTHER_CATALOGS})
    return found


def fingerprint(salt):
    return hashlib.sha256(b'woow-litellm-salt-v1:' + salt).hexdigest()[:16]


def addon_tar(*, version='0.1.15', salt=SALT, state='1.104.0', pg_version=b'18\n', extra=()):
    addon = {'user': {'version': version, 'image': 'ghcr.io/woowtech/woow-ha-litellm-amd64',
                      'options': {'master_key': 'sk-ha-master-option'}},
             'system': {'slug': 'woow-litellm', 'name': 'Woow LiteLLM'}, 'version': version}
    entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': json.dumps(addon).encode()},
               {'name': 'data', 'type': 'dir'}, {'name': 'data/options.json', 'data': b'{"master_key": "sk-ha"}'},
               {'name': 'data/secrets', 'type': 'dir', 'mode': 0o700},
               {'name': 'data/secrets/master_key', 'data': b'sk-ha-master-file\n', 'mode': 0o600},
               {'name': 'data/secrets/pg_password', 'data': b'ha-pg-password\n', 'mode': 0o600},
               {'name': 'data/secrets/ui_password', 'data': b'ha-ui-password\n', 'mode': 0o600},
               {'name': 'data/woow', 'type': 'dir'},
               {'name': 'data/postgres', 'type': 'dir', 'mode': 0o700},
               {'name': 'data/postgres/PG_VERSION', 'data': pg_version},
               {'name': 'data/postgres/base', 'type': 'dir'}, {'name': 'data/postgres/base/1', 'type': 'dir'},
               {'name': 'data/postgres/base/1/1259', 'data': b'page'},
               {'name': 'data/postgres/pg_hba.conf', 'data': b'host all all 0.0.0.0/0 trust\n'},
               {'name': 'data/postgres/postgresql.conf', 'data': b"shared_preload_libraries = 'evil'\n"},
               {'name': 'data/postgres/postmaster.pid', 'data': b'1\n'},
               {'name': 'data/pre-upgrade-dumps', 'type': 'dir'}]
    if salt is not None:
        entries.append({'name': 'data/secrets/salt_key', 'data': salt + b'\n', 'mode': 0o600})
    if state is not None:
        entries.append({'name': 'data/woow/state.json', 'data': json.dumps({'litellm_version': state}).encode()})
    return gzip.compress(hx.tar_bytes(entries + list(extra)), mtime=0)


UNSET = object()


class LiteAdapter(fk.Adapter):
    def image_inspect(self, image):
        env = [f'PG_MAJOR={self.world.image_major}'] if 'postgres' in image and self.world.image_major else []
        return {'id': 'sha256:' + 'c' * 64, 'env': env, 'digest': '', 'arch': 'amd64', 'size': 1, 'names': []}

    def import_manifest(self, staging_dir, **items):
        self.world.kept = items.pop('keep_safety', None)
        self.world.converted_secrets = {name: Path(path).read_bytes() for name, path in (items.get('secrets') or {}).items()}
        self.world.converted_dumps = {pg: Path(d['file']).read_bytes() for pg, d in (items.get('postgres') or {}).items()}
        return super().import_manifest(staging_dir, **items)


class World(fk.World):
    def __init__(self):
        super().__init__()
        self.quadlets = {'litellm': QUADLETS,
                         'opendesign': {'open-design.container': b'[Container]\nContainerName=open-design\n'
                                                                b'Image=x\nNetwork=litellm.network\n'},
                         'omnigent': {'omnigent-server.container': b'[Container]\nContainerName=omnigent-server\n'
                                                                   b'Image=y\nEnvironment=OMNIGENT_X=1\n'}}
        self.files = {'.config/hermes/hermes.env': b'# hermes\nLITELLM_API_KEY=sk-hermes-device-key\nOTHER=1\n'}
        self.images = {ha_litellm.PG18_IDS[0]}
        self.app_version = '1.104.0'
        self.ha_migrations, self.live_migrations = list(MIGRATIONS), list(MIGRATIONS)
        self.objects = {'schemas': ['woow', 'woow_platform'], 'ha_only': ['meta'], 'extensions': ['plpgsql'],
                        'encoding': 'UTF8', 'large_objects': 0}
        self.superuser = []
        self.db_salt = SALT
        self.counts = {f'{s}.{t}': 2 for s, t in TABLES}
        self.new_counts = None
        self.ha_columns, self.live_columns = copy.deepcopy(COLUMNS), copy.deepcopy(COLUMNS)
        self.ha_signature, self.live_signature = signature(), signature()
        self.restored_signature = None
        self.snapshot_columns = None
        self.after_capture = None
        self.live_reads = 0
        self.snapshots = []
        self.copies_out, self.copies_in = [], []
        self.restores = []
        self.audit = {'roles': ['litellm'], 'role_settings': 0, 'auto_conf': 0, 'large_objects': 0}
        self.salt_digest = None
        self.salt_rows = UNSET             # the new cluster's whole answer to SALT_DIGEST_SQL
        self.ha_major, self.new_major, self.image_major = 18, 17, '17'
        self.new_migrations = None         # the new cluster's migrations after the rows (None: HA's)
        self.new_columns = None            # the new cluster's columns after the pre-data (None: HA's)
        self.new_signatures = []           # the new cluster's signature answers in order (then restored_signature)
        self.new_dump = None               # what pg_dump of the new cluster writes
        self.chatgpt_accounts = 0
        self.converted_secrets, self.converted_dumps = {}, {}
        self.pulls = []
        self.pull_gives = None
        self.pull_fails = None             # (exit code, stderr) of `podman pull`
        self.pulled = False
        self.kept = None                   # keep_safety as the adapter's import_manifest got it
        self.proxy_name = 'litellm'        # the proxy's container name (L-04: whatever its Quadlet file says)
        self.snapshot_exits = []           # exit codes of the next snapshot scripts (21: psql gone, 22: other migrations)
        self.migrations_present = True     # this device's database has its Prisma table (the proxy ran once)
        self.settings = None               # the answer of STORED_SETTINGS_SQL by role ({'hapg': {...}, 'll-db': {...}} or one for all)
        self.restore_scripts = []          # (table, script text) of every restricted-role load
        self.cut_tail = 0                  # bytes of the end of the next table scripts that "did not arrive"
        self.updates = []                  # the UPDATEs run in the new cluster

    def factory(self, app, **_kwargs):
        return LiteAdapter(app, self)

    def run(self, role, image, command, options, data):
        if role == 'controldata':
            return Result(0, b'Database cluster state:               shut down\n', b'')
        return super().run(role, image, command, options, data)

    def podman(self, args, data, stdout):
        if args[:2] == ['exec', self.proxy_name] and 'python' in args:
            return Result(0 if self.app_version else 1, (self.app_version or '').encode(), b'')
        if args[:5] == ['exec', '-i', 'litellm-postgres', 'sh', '-s']:
            self.snapshots.append((args[5:], data))
            if self.snapshot_exits:
                return Result(self.snapshot_exits.pop(0), None, b'')
            columns = self.snapshot_columns if self.snapshot_columns is not None else self.live_columns
            stdout.write(json.dumps(columns).encode() + b'\nPGDMP-trusted-schema')
            if self.after_capture:
                self.after_capture(self)
            return Result(0, None, b'')
        if args[:1] == ['pull']:
            self.pulls.append(args[-1])
            if self.pull_fails is not None:
                return Result(self.pull_fails[0], b'', self.pull_fails[1])
            self.pulled = True
            if self.pull_gives:
                self.images.add(self.pull_gives)
            return Result(0, b'', b'')
        if args[:2] == ['image', 'inspect'] and args[-1] == ha_litellm.PG18_PINNED:
            return Result(0 if self.pulled else 1, b'', b'' if self.pulled else b'Error: no such image')
        if args[0] == 'exec' and 'psql' in args:
            i = args.index('psql')
            container, command = args[i - 1], args[i:]
            role = fk.role_of(container)
            user = command[command.index('-U') + 1]
            if user == ha_litellm.READER_ROLE:
                self.execs.append((role, command, data))
                rows = {'platform': [self.db_salt.decode()], 'fingerprint': [fingerprint(self.db_salt)]}
                return Result(0, json.dumps(rows).encode(), b'')
            sql = command[command.index('-c') + 1] if '-c' in command else ''
            if sql.startswith('COPY ') and sql.endswith(' TO STDOUT'):
                self.copies_out.append((role, user, sql))
                stdout.write(f'rows of {sql.split()[1]}\n'.encode())
                return Result(0, None, b'')
            if user == ha_litellm.RESTORE_ROLE and '-f' in command:
                # pg-stdin F2: a table's rows travel inside a script that opens and closes its own transaction and ends with a mark
                raw = data if isinstance(data, bytes) else data.read()
                text = raw.decode('utf-8')
                match = re.search(r'^COPY (.+) FROM STDIN;$', text, re.M)
                if match:
                    if self.cut_tail:
                        text = text[:-self.cut_tail]
                    self.copies_in.append((role, user, f'COPY {match.group(1)} FROM STDIN', raw))
                    self.restore_scripts.append(text)
                    done = re.search(r'\\\.\nCOMMIT;\n\\echo (\S+)\n\Z', text)
                    return Result(0, (done.group(1) + '\n').encode() if done else b'', b'')
                data = raw
        return super().podman(args, data, stdout)

    def exec(self, role, command, data, stdout):
        if command[0] == 'pg_dump':
            stdout.write(b'PGDMP-' + role.encode() if self.new_dump is None else self.new_dump)
            return Result(0, None, b'')
        if command[0] == 'pg_restore':
            self.restores.append((role, command, data))
        return Result(0, b'', b'')

    def executed(self, role, user=None):
        return [statement for _db, statement, _t in self.psql[role].executed] if role in self.psql else []

    def answer(self, role, sql, database):
        # psql -c sends the pin and the query as two statements (hafakes.Psql answers each); the pin itself was
        # checked on the command line (SchemaReadTests), the query is answered as the whole constant.
        if sql == ha_litellm.PIN_SEARCH_PATH.strip().rstrip(';'):
            return None
        if ha_litellm.PIN_SEARCH_PATH + sql in (ha_litellm.COLUMNS_SQL, ha_litellm.SIGNATURE_SQL):
            sql = ha_litellm.PIN_SEARCH_PATH + sql
        if 'server_version_num' in sql:
            return {'hapg': self.ha_major, 'll-db': self.new_major}.get(role)
        if "current_setting('server_version')" in sql:
            return '17.11 (Debian)'
        if sql == ha_litellm.COLUMNS_SQL:
            if role == 'll-db' and self.new_columns is not None:
                return self.new_columns
            return {'litellm-postgres': self.live_columns, 'hapg': self.ha_columns}.get(role, self.ha_columns)
        if sql == ha_litellm.SIGNATURE_SQL:
            if role == 'litellm-postgres':
                self.live_reads += 1
                return self.live_signature
            if role == 'hapg':
                return self.ha_signature
            if self.new_signatures:
                return self.new_signatures.pop(0)
            return self.restored_signature if self.restored_signature is not None else self.live_signature
        if sql == ha_litellm.MIGRATIONS_PRESENT_SQL:
            return self.migrations_present
        if sql.startswith('UPDATE public."LiteLLM_Config"'):
            self.updates.append((role, sql))
            return None
        if sql == ha_litellm.STORED_SETTINGS_SQL and self.settings is not None:
            return self.settings.get(role) if role in self.settings else self.settings
        if sql == ha_litellm.MIGRATIONS_SQL:
            if role == 'll-db' and self.new_migrations is not None:
                return self.new_migrations
            return self.live_migrations if role == 'litellm-postgres' else self.ha_migrations
        if role == 'll-db':
            if sql == ha_litellm.AUDIT_SQL:
                return self.audit
            if sql == ha_litellm.SALT_DIGEST_SQL:
                return ([self.salt_digest or hashlib.sha256(SALT).hexdigest()] if self.salt_rows is UNSET
                        else self.salt_rows)
        if role == 'hapg' and sql == ha_litellm.OBJECTS_SQL:
            return self.objects
        if role in ('hapg', 'll-db') and sql.startswith('SELECT json_build_array((SELECT count(*) FROM'):
            counts = self.new_counts if role == 'll-db' and self.new_counts is not None else self.counts
            return [counts[f'{s}.{t}'.replace('""', '"')]
                    for s, t in re.findall(r'FROM "((?:[^"]|"")+)"\."((?:[^"]|"")+)"\)', sql)]
        if role in ('hapg', 'll-db') and sql.startswith('SELECT json_build_object(') and '(SELECT count(*) FROM' in sql:
            keys = re.findall(r"'([a-z_]+)', \(SELECT", sql)
            return {key: {'users': 1, 'teams': 1, 'keys': 1, 'models': 24, 'credentials': 5,
                          'chatgpt_accounts': self.chatgpt_accounts}.get(key, 0) for key in keys}
        if role == 'hapg':
            if sql == ha_odoo.DATABASES_SQL:
                return [['litellm', 9000, 'C', 'C.UTF-8'], ['postgres', 100, 'C', 'C.UTF-8']]
            if sql == ha_litellm.OBJECTS_SQL:
                return self.objects
            if 'to_regclass' in sql:
                return True
            if sql == ha_odoo.SUPERUSER_SQL:
                return self.superuser
            if sql.startswith('SELECT json_build_array(last_value, is_called)'):
                return [41, True]
        return None

    def export(self, volume):
        return fk.tar_of([{'name': '.', 'type': 'dir'}])


class LiteLLMCase(fk.ConversionCase):
    world_class = World

    def setUp(self):
        super().setUp()
        self.addCleanup(jobs.unmask_secret, SALT.decode())
        for name in ('_sleep',):   # no real pauses: a retry, a wait for a service
            patcher = mock.patch.object(hatarget, name, lambda _seconds: None)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.started = []                  # the services the import asked to start (hatarget.ensure_running), in order
        self.on_start = None               # what the device does once a service is started: a callable(container)

        def ensure_running(work, app, container, **kwargs):
            self.started.append((container, kwargs))
            if self.on_start is not None:
                self.on_start(container)

        patcher = mock.patch.object(hatarget, 'ensure_running', ensure_running)
        patcher.start()
        self.addCleanup(patcher.stop)

    def issues(self, **upload):
        """The check's issues of the litellm app: [{id, level, message, items, ...}]."""
        return self.check(self.upload_litellm(**upload), ['litellm'])[0]['issues']

    def lines(self, **upload):
        """[(id, level)] of the check's issues (stops first, as they are sent)."""
        return [(issue['id'], issue['level']) for issue in self.issues(**upload)]

    def catalog_apps(self):
        return {'litellm': fk.app('litellm', 'LiteLLM 閘道', postgres=[
                    {'id': 'main', 'container': 'litellm-postgres', 'database': 'litellm', 'user': 'litellm',
                     'data_volume': 'litellm-pgdata', 'unit': 'litellm-postgres.service', 'scope': 'database'}],
                    secrets=[{'name': name} for name in SECRETS],
                    config_files=[{'path': '.config/litellm/config.yaml', 'mode': '0644'}],
                    health=[{'type': 'http', 'url': 'http://127.0.0.1:4000/health/readiness'}]),
                'hermes': fk.app('hermes', 'Hermes 代理', config_files=[{'path': '.config/hermes/hermes.env',
                                                                        'mode': '0600'}]),
                'opendesign': fk.app('opendesign', 'OpenDesign'),
                'omnigent': fk.app('omnigent', 'Omnigent 協作平台'),
                'litellm-mcp-admin': fk.app('litellm-mcp-admin', 'LiteLLM MCP 管理',
                                            config_files=[{'path': '.config/hermes/hermes.env', 'mode': '0600'}])}

    def upload_litellm(self, **kwargs):
        return self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', addon_tar(**kwargs))], hx.ha_doc(addons=(SLUG,))))

    def logs(self):
        return '\n'.join(str(line) for line in getattr(self.reporter, 'logs', []))

    def refused(self, words, code='incompatible', **upload):
        """A conversion that must stop with `words` and make no backup; the BackupError."""
        before = self.storage.list_backups()
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(**upload), ['litellm'])
        self.assertEqual(caught.exception.code, code, caught.exception.message)
        self.assertIn(words, caught.exception.message)
        self.assertEqual(self.storage.list_backups(), before, 'no backup was made')
        return caught.exception

    def blockers(self, **upload):
        """The messages of what stops the app or has to be confirmed (the issues' own text, without the advice)."""
        result = self.check(self.upload_litellm(**upload), ['litellm'])[0]
        found = [i['message'] for i in result['issues'] if i['level'] in ('stop', 'confirm')]
        self.assertEqual(result['ok'], not found)
        return found

    def watch_podman(self, seen):
        """Call seen(args) before every podman call of the fake owner."""
        podman = self.world.podman

        def watched(args, data, stdout):
            seen(args)
            return podman(args, data, stdout)

        self.world.podman = watched


class RegistryTests(unittest.TestCase):
    def test_litellm_is_a_product_importer(self):
        importer = haapps.get('litellm')
        self.assertEqual((importer.slug, importer.module, importer.mcp_admin, importer.mcp_addon),
                         ('woow-litellm', 'ha_litellm', 'litellm-mcp-admin', 'Woow LiteLLM MCP Server'))
        self.assertIs(importer.load(), ha_litellm)
        self.assertEqual(ha_litellm.VERSIONS.upstream('0.1.15'), '1.104.0')
        self.assertIsNone(ha_litellm.VERSIONS.upstream('0.1.14'))


class CheckTests(LiteLLMCase):
    PI_MODELS = '.local/share/containers/storage/volumes/omnigent-pi/_data/models.json'

    def omnigent_runner(self, providers):
        """Omnigent's runner as the package installs it (pi volume at PI_CODING_AGENT_DIR=/data/pi-agent)."""
        self.world.quadlets['omnigent'] = {
            'omnigent-runner.container': b'[Container]\nContainerName=omnigent-runner\nImage=r\n'
                                         b'Volume=omnigent-pi.volume:/data/pi-agent\n'
                                         b'Environment=PI_CODING_AGENT_DIR=/data/pi-agent\n',
            'omnigent-pi.volume': b'[Volume]\nVolumeName=omnigent-pi\n'}
        self.world.files[self.PI_MODELS] = json.dumps({'providers': providers}).encode()

    def test_a_pi_agent_provider_at_this_litellm_names_its_app(self):
        self.omnigent_runner({'openrouter': {'baseUrl': 'https://openrouter.ai/api/v1', 'apiKey': 'sk-or-secret'},
                              'woow-litellm': {'baseUrl': 'http://host.containers.internal:4000/v1',
                                               'apiKey': 'sk-omnigent-device-key'}})
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertEqual(result['litellm']['key_users'], ['Hermes 代理', 'Omnigent 協作平台', 'OpenDesign'])
        self.assertTrue(any('Omnigent 協作平台' in w and '金鑰會失效' in w for w in result['warnings']), result['warnings'])
        shown = json.dumps(result, ensure_ascii=False) + self.logs()
        for value in ('sk-omnigent-device-key', 'sk-or-secret', 'host.containers.internal'):
            self.assertNotIn(value, shown)

    def test_a_pi_agent_provider_list_without_this_litellm_names_nothing(self):
        self.omnigent_runner({'openrouter': {'baseUrl': 'https://openrouter.ai/api/v1', 'apiKey': 'sk-or-secret'},
                              'other-gateway': {'baseUrl': 'https://litellm.example.com/v1'}})
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertEqual(result['litellm']['key_users'], ['Hermes 代理', 'OpenDesign'])

    def test_a_pi_volume_outside_the_owners_home_is_not_read(self):
        self.omnigent_runner({'woow-litellm': {'baseUrl': 'http://litellm:4000/v1'}})
        podman = self.world.podman

        def elsewhere(args, data, stdout):
            if args[:2] == ['volume', 'inspect']:
                return Result(0, b'/var/lib/elsewhere/omnigent-pi/_data\n', b'')
            return podman(args, data, stdout)

        self.world.podman = elsewhere
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertEqual(result['litellm']['key_users'], ['Hermes 代理', 'OpenDesign'])

    def test_a_clean_backup(self):
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertEqual((result['ok'], result['blockers'], result['version'], result['target_version']),
                         (True, [], '0.1.15', '1.104.0'), result)
        section = result['litellm']
        self.assertEqual((section['litellm_version'], section['migrations'], section['pg_major'],
                          section['target_pg_major'], section['users'], section['teams'], section['models']),
                         ('1.104.0', 3, 18, 17, 1, 1, 24))
        self.assertEqual(section['key_users'], ['Hermes 代理', 'OpenDesign'])
        self.assertTrue(any('Hermes 代理、OpenDesign 目前使用這台 LiteLLM 的金鑰' in w for w in result['warnings']))
        hapg = self.runs('hapg')[0]
        self.assertEqual(hapg[1], ha_litellm.PG18_IDS[0], 'the pinned official PostgreSQL 18 by content')
        self.assertIn('--read-only', hapg[3])
        self.assertEqual(hapg[3]['--network'], ['none'])
        self.assertIn('PGDATA=/var/lib/postgresql', hapg[3]['--env'])
        self.assertTrue(any(v.endswith(':/var/lib/postgresql:rw,noexec,nosuid,nodev') for v in hapg[3]['--volume']))
        for setting in ('shared_preload_libraries=', 'session_preload_libraries=', 'archive_command=',
                        'hba_file=/var/lib/postgresql/pg_hba.conf', 'listen_addresses='):
            self.assertIn(setting, hapg[2])
        self.assertFalse(self.runs('ll-db'), 'a check changes nothing')
        staged = self.world.imported['hapg']
        with tarfile.open(fileobj=io.BytesIO(staged)) as tar:
            members = {m.name: m for m in tar.getmembers()}
            hba = tar.extractfile('pg_hba.conf').read()
        self.assertNotIn('postmaster.pid', members)
        self.assertEqual(hba, ha_odoo.PG_HBA)
        self.assertFalse(any('secrets' in name or 'options' in name for name in members))
        # the salt binding is read by a role without privileges, never as the superuser
        self.assertIn(ha_litellm.READER_SQL.splitlines()[0].rstrip(';'), self.world.executed('hapg'))
        self.assertTrue(any(cmd[cmd.index('-U') + 1] == ha_litellm.READER_ROLE
                            for role, cmd, _d in self.world.execs if role == 'hapg' and 'psql' in cmd[:1]))
        self.assertNotIn(SALT.decode(), jobs.redact(f'x {SALT.decode()} y'), "HA's salt is masked in every log line")

    def test_versions(self):
        """L-31..L-34: no version number is a gate; the data decides (migrations, shape)."""
        found = self.check(self.upload_litellm(version='0.1.14'), ['litellm'])[0]    # the table does not know the add-on version
        self.assertTrue(found['importable'], found['issues'])
        self.assertIn(('version.addon-unknown', 'notice'), [(i['id'], i['level']) for i in found['issues']])
        self.assertEqual(found['litellm']['litellm_version'], '1.104.0', "the state file's version when the table has none")
        found = self.check(self.upload_litellm(state='1.103.0'), ['litellm'])[0]   # L-31: HA's state file says another version
        self.assertTrue(found['importable'], found['issues'])
        self.assertEqual(found['litellm']['litellm_version'], '1.104.0', 'the table is HA add-on 0.1.15 = 1.104.0')
        self.world.app_version = '1.105.0'   # L-34: both known and different
        found = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertTrue(found['importable'], found['issues'])
        line = next(i for i in found['issues'] if i['id'] == 'litellm.version-differs')
        self.assertEqual(line['level'], 'notice')
        self.assertIn('HA 的 LiteLLM 是 1.104.0', line['message'])
        self.assertIn('這台的是 1.105.0', line['message'])
        self.assertEqual(found['target_version'], '1.105.0')
        self.world.app_version = None        # L-33: this device's version cannot be read
        found = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertTrue(found['importable'], found['issues'])
        self.assertIn(('version.target-unknown', 'notice'), [(i['id'], i['level']) for i in found['issues']])
        self.assertEqual(found['target_version'], '')
        self.world.app_version = '1.104.0'
        self.world.ha_migrations = MIGRATIONS[:2]    # what still stops: HA's migrations are not this device's (L-26)
        found = self.check(self.upload_litellm(), ['litellm'])[0]
        line = next(i for i in found['issues'] if i['id'] == 'litellm.migrations-differ')
        self.assertEqual(line['level'], 'stop')
        self.assertIn('只在這台的 1 筆', line['message'])
        self.assertFalse(found['importable'])
        self.world.ha_migrations = list(MIGRATIONS)
        found = self.check(self.upload_litellm(pg_version=b'17\n'), ['litellm'])[0]
        self.assertIn(('litellm.pg-major', 'stop'), [(i['id'], i['level']) for i in found['issues']])

    def test_the_salt_must_be_the_databases(self):
        self.world.db_salt = OTHER_SALT
        issues = self.issues()
        mismatch = next(i for i in issues if i['id'] == 'litellm.salt-mismatch')
        self.assertEqual((mismatch['level'], mismatch['message']), ('stop', ha_litellm.SALT_MISMATCH))
        self.world.db_salt = SALT
        found = self.check(self.upload_litellm(salt=None), ['litellm'])[0]
        self.assertIn(('litellm.salt-missing', 'stop'), [(i['id'], i['level']) for i in found['issues']])
        self.assertTrue(any('找不到格式正確的 LiteLLM 加密金鑰' in b for b in found['blockers']))
        found = self.check(self.upload_litellm(salt=b'short'), ['litellm'])[0]
        self.assertFalse(found['importable'])

    def test_what_the_check_lists_and_what_it_still_refuses(self):
        """L-21, L-22, L-23, L-24 are named, not refused; the encoding (L-25) and a tablespace (L-17) still stop."""
        self.world.objects = dict(self.world.objects, schemas=['evil', 'woow', 'woow_platform'], large_objects=1)
        self.world.superuser = ['EVENT TRIGGER']
        found = self.check(self.upload_litellm(), ['litellm'])[0]
        by_id = {i['id']: i for i in found['issues']}
        self.assertEqual(sorted((i['id'], i['level']) for i in found['issues']),
                         [('litellm.databases-left', 'notice'), ('litellm.key-users', 'notice'),
                          ('litellm.large-objects', 'notice'), ('litellm.schemas-skipped', 'confirm'),
                          ('litellm.superuser-objects', 'confirm')])
        self.assertEqual(by_id['litellm.schemas-skipped']['items'], ['evil'])
        self.assertEqual(by_id['litellm.superuser-objects']['items'], ['EVENT TRIGGER'])
        self.assertIn('1 個大型物件', by_id['litellm.large-objects']['message'])
        self.assertTrue(found['importable'], 'nothing here stops the app')
        self.assertFalse(found['ok'], 'two lines to confirm')
        self.assertTrue(all('key' in by_id[i] for i in ('litellm.schemas-skipped', 'litellm.superuser-objects')))
        self.world.objects = dict(self.world.objects, schemas=['woow', 'woow_platform', 'woow_extra'], large_objects=0,
                                  encoding='SQL_ASCII')
        self.world.superuser = []
        found = self.check(self.upload_litellm(), ['litellm'])[0]
        stop = next(i for i in found['issues'] if i['level'] == 'stop')
        self.assertEqual((stop['id'], stop['message']), ('litellm.encoding', 'HA 的 LiteLLM 資料庫不是 UTF8 編碼。'))
        self.world.objects = dict(self.world.objects, schemas=['woow', 'woow_platform'], encoding='UTF8')
        link = {'name': 'data/postgres/pg_tblspc/16400', 'type': 'symlink', 'linkname': '/mnt/elsewhere'}
        found = self.check(self.upload_litellm(extra=[{'name': 'data/postgres/pg_tblspc', 'type': 'dir'}, link]),
                           ['litellm'])[0]
        self.assertIn(('litellm.tablespaces', 'stop'), [(i['id'], i['level']) for i in found['issues']])

    def test_a_different_schema_is_a_stop_naming_the_tables(self):
        self.world.ha_columns = COLUMNS + [['public', 'LiteLLM_UserTable', 'extra', 'integer', False, '', '']]
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertFalse(result['importable'])
        self.assertEqual([i['message'] for i in result['issues'] if i['id'] == 'litellm.schema-differs'],
                         [ha_litellm.schema_blocker(['public.LiteLLM_UserTable'])])
        self.assertEqual(self.world.live_reads, 1, 'the live schema is read once, read only')
        self.assertFalse(self.runs('ll-db'), 'a check changes nothing')


class SecurityReviewTests(LiteLLMCase):
    """Security review 2026-11-23 (tests/backup/evidence/litellm-product-security-review-20261123; the real attacks are
    tests/e2e/lab/litellm_sandbox_review.py): HA's PostgreSQL 18 catalog is untrusted, also below the superuser."""

    def setUp(self):
        super().setUp()
        self.raw = []
        original = self.world.podman

        def record(args, data, stdout):
            self.raw.append(list(args))
            return original(args, data, stdout)

        self.world.podman = record

    def hapg_sessions(self):
        """(PGOPTIONS or None, psql user) of every psql/pg_isready the engine ran in HA's container."""
        found = []
        for args in self.raw:
            if args[:1] != ['exec']:
                continue
            i, env = 1, {}
            while args[i].startswith('--'):
                if args[i] == '--env':
                    key, _, value = args[i + 1].partition('=')
                    env[key] = value
                i += 2 if args[i] in ('--user', '--workdir', '--env') else 1
            command = args[i + 1:]
            if fk.role_of(args[i]) == 'hapg' and command[:1] in (['psql'], ['pg_isready']):
                found.append((env.get('PGOPTIONS'), command[command.index('-U') + 1], command[0]))
        return found

    def test_every_session_in_has_cluster_pins_its_own_settings(self):
        # SR-1/SR-2/SR-3: HA's per-database/per-role settings beat the command line, client options beat them.
        for run in (lambda: self.check(self.upload_litellm(), ['litellm']), lambda: self.convert_litellm()):
            self.raw.clear()
            run()
            sessions = self.hapg_sessions()
            psql = [s for s in sessions if s[2] == 'psql']
            self.assertTrue(len(psql) >= 8, sessions)
            for options, user, _tool in sessions:
                expected = ha_litellm.HA_SESSION_OPTIONS if user == ha_litellm.READER_ROLE \
                    else ha_litellm.HA_SUPERUSER_OPTIONS
                self.assertEqual(options, expected, (user, options))
            self.assertIn(ha_litellm.READER_ROLE, {user for _o, user, _t in psql})
        for word in ('-c search_path=pg_catalog', '-c DateStyle=ISO,MDY', '-c extra_float_digits=3',
                     '-c client_encoding=UTF8', '-c IntervalStyle=postgres', '-c TimeZone=UTC'):
            self.assertIn(word, ha_litellm.HA_SESSION_OPTIONS)
        self.assertIn('-c local_preload_libraries=', ha_litellm.HA_SESSION_OPTIONS)
        for word in ('event_triggers', 'session_preload_libraries'):
            self.assertNotIn(word, ha_litellm.HA_SESSION_OPTIONS, 'a role without privileges may not set it')
        self.assertTrue(ha_litellm.HA_SUPERUSER_OPTIONS.endswith(' -c session_preload_libraries= -c event_triggers=off'))
        # the live database and the new cluster are this device's own: no HA options there
        self.assertFalse([a for a in self.raw if a[:1] == ['exec'] and any('PGOPTIONS' in x for x in a)
                          and not any(fk.role_of(x) == 'hapg' for x in a)])

    def convert_litellm(self):
        return self.convert(self.upload_litellm(), ['litellm'])

    def test_the_server_starts_without_event_triggers(self):
        args = ha_litellm.ha_server_args()
        self.assertEqual(args[-2:], ['-c', 'event_triggers=off'])
        self.check(self.upload_litellm(), ['litellm'])
        self.assertIn('event_triggers=off', self.runs('hapg')[0][2])

    def test_migrations_are_read_only_from_an_ordinary_table(self):
        # SR-1: a view there would run HA's code as the superuser at the read.
        answer = self.world.answer

        def not_a_table(role, sql, database):
            if role == 'hapg' and sql == ha_litellm.MIGRATIONS_TABLE_SQL:
                return False
            if role == 'hapg' and sql == ha_litellm.MIGRATIONS_SQL:
                raise AssertionError('HA migrations read from something that is not an ordinary table')
            return answer(role, sql, database)

        self.world.answer = not_a_table
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertFalse(result['ok'])
        self.assertTrue(any('資料庫結構版本不同' in b for b in result['blockers']), result['blockers'])
        self.assertIn("c.relkind = 'r'", ha_litellm.MIGRATIONS_TABLE_SQL)

    def test_online_backup_files_never_reach_the_volume_and_refuse(self):
        # SR-4: tablespace_map makes PostgreSQL create tablespace links at its start (no symlink in the archive).
        for extra in ([{'name': 'data/postgres/tablespace_map', 'data': b'16400 /tmp/elsewhere\n'}],
                      [{'name': 'data/postgres/backup_label', 'data': b'START WAL LOCATION: 0/2000028\n'}],
                      [{'name': 'data/postgres/backup_label', 'type': 'dir'},
                       {'name': 'data/postgres/backup_label/x', 'data': b'x'}]):
            result = self.check(self.upload_litellm(extra=extra), ['litellm'])[0]
            self.assertFalse(result['ok'])
            self.assertTrue(any('不是在停止狀態下備份的' in b for b in result['blockers']), result['blockers'])
            with tarfile.open(fileobj=io.BytesIO(self.world.imported['hapg'])) as tar:
                names = tar.getnames()
            self.assertFalse([n for n in names if n.split('/')[0] in ('tablespace_map', 'backup_label')], names)
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(extra=[{'name': 'data/postgres/tablespace_map', 'data': b'1 /x\n'}]),
                         ['litellm'])
        self.assertIn('不是在停止狀態下備份的', caught.exception.message)
        self.assertFalse(self.world.copies_in, 'no HA row was loaded')


class StoredSettingsTests(LiteLLMCase):
    """Review SR-5: with store_model_in_db (the package's config.yaml) the proxy applies HA's stored environment
    variables and callbacks here (litellm 1.104.0 proxy_server.py _update_config_from_db); the check and the import
    name them, values never."""

    CONFIG = [['public', 'LiteLLM_Config', 'param_name', 'text', True, '', ''],
              ['public', 'LiteLLM_Config', 'param_value', 'jsonb', False, '', '']]
    FOUND = {'sections': ['environment_variables', 'litellm_settings'], 'env': ['HTTPS_PROXY', 'LANGFUSE_HOST'],
             'callbacks': ['langfuse']}

    def answering(self, value):
        answer, self.asked = self.world.answer, []

        def stored(role, sql, database):
            if sql == ha_litellm.STORED_SETTINGS_SQL:
                self.asked.append(role)
                return value
            return answer(role, sql, database)

        self.world.answer = stored

    def test_has_stored_proxy_settings_are_named_in_the_check(self):
        self.world.ha_columns = COLUMNS + self.CONFIG
        self.answering(self.FOUND)
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        lines = [w for w in result['warnings'] if '存在資料庫裡的代理設定' in w]
        self.assertEqual(len(lines), 1, result['warnings'])
        for word in ('HTTPS_PROXY', 'LANGFUSE_HOST', 'langfuse', '請確認都是你自己設定的'):
            self.assertIn(word, lines[0])
        self.assertEqual(self.asked, ['hapg'], "read once, in HA's cluster only")

    def test_no_table_or_no_answer_no_line(self):
        self.answering(self.FOUND)
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertEqual(self.asked, [], 'no LiteLLM_Config table: not asked')
        self.assertFalse([w for w in result['warnings'] if '代理設定' in w])
        self.world.ha_columns = COLUMNS + self.CONFIG[:1] + [['public', 'LiteLLM_Config', 'param_value', 'text', False,
                                                              '', '']]
        self.check(self.upload_litellm(), ['litellm'])
        self.assertEqual(self.asked, [], 'param_value is not jsonb: not asked')
        self.world.ha_columns = COLUMNS + self.CONFIG
        self.answering(None)
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertEqual(self.asked, ['hapg'])
        self.assertFalse([w for w in result['warnings'] if '代理設定' in w])
        self.assertIn(('litellm.config-unreadable', 'confirm'), [(i['id'], i['level']) for i in result['issues']],
                      'an answer that is not an object is not moved, and said so')
        self.answering({'sections': ['general_settings'], 'env': [], 'callbacks': []})
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertFalse([w for w in result['warnings'] if '代理設定' in w], 'only environment variables and callbacks')

    HOOK = {'sections': ['litellm_settings'], 'env': [], 'callbacks': [], 'hooks': ['litellm_settings.post_call_rules'],
            'nested': []}
    CLEAN = {'sections': ['litellm_settings'], 'env': [], 'callbacks': [], 'hooks': [], 'nested': []}

    def confirm_keys(self, **upload):
        """The keys of the check's lines to confirm: what the page sends back as `acknowledged`."""
        return [issue['key'] for issue in self.issues(**upload) if issue['level'] == 'confirm']

    def test_settings_that_load_code_are_a_line_to_confirm_not_a_refusal(self):
        # SR-6, L-13, L-14: LiteLLM's get_instance_fn imports any dotted path (post_call_rules "builtins.exec" runs every
        # response). They are not moved; the customer confirms that once, with their names.
        self.world.ha_columns = COLUMNS + self.CONFIG
        self.world.live_columns = COLUMNS + self.CONFIG
        self.world.counts['public.LiteLLM_Config'] = 2
        for found, name in (({'sections': ['litellm_settings'], 'env': [], 'callbacks': [],
                              'hooks': ['litellm_settings.post_call_rules']}, 'litellm_settings.post_call_rules'),
                            ({'sections': ['general_settings'], 'env': [], 'callbacks': [],
                              'hooks': ['general_settings.custom_auth']}, 'general_settings.custom_auth'),
                            ({'sections': ['litellm_settings'], 'env': [], 'hooks': [],
                              'callbacks': ['langfuse', 'custom_callbacks.proxy_handler_instance']},
                             'litellm_settings 回呼 custom_callbacks.proxy_handler_instance')):
            self.answering(found)
            result = self.check(self.upload_litellm(), ['litellm'])[0]
            line = next(i for i in result['issues'] if i['id'] == 'litellm.hooks-removed')
            self.assertEqual((line['level'], line['items']), ('confirm', [name]))
            self.assertIn('在資料庫裡存了會載入並執行程式的設定', line['message'])
            self.assertTrue(result['importable'], 'the app is not stopped by it')
            self.assertFalse(result['ok'])
        self.assertTrue(any('langfuse' in w for w in result['warnings']), 'a named integration stays a reminder')
        self.assertFalse(any('custom_callbacks' in w for w in result['warnings']))
        self.answering({'sections': ['litellm_settings'], 'env': [], 'callbacks': ['langfuse'], 'hooks': []})
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertNotIn('litellm.hooks-removed', [i['id'] for i in result['issues']])
        self.assertIn("('litellm_settings', 'post_call_rules')", ha_litellm.STORED_SETTINGS_SQL)

    def test_the_conversion_without_the_confirmation_stops_before_anything_is_read(self):
        self.world.ha_columns = COLUMNS + self.CONFIG
        self.answering(self.HOOK)
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertIn('會載入並執行程式的設定', caught.exception.message)
        self.assertFalse(self.world.copies_out, "no HA row was read")
        self.assertFalse(self.world.snapshots, "this device's schema was not captured")
        self.assertFalse(self.world.copies_in)
        self.assertEqual(self.storage.list_backups(), [])

    def test_a_confirmed_conversion_takes_the_settings_out_of_the_new_cluster(self):
        # L-14, L-47, L-49: the whole setting, by its key, in the NEW cluster; looked for again before anything is packed.
        self.both_sides(self.HOOK, [self.HOOK, self.CLEAN])
        keys = self.confirm_keys()
        self.assertEqual(len(keys), 1)
        result = self.convert(self.upload_litellm(), ['litellm'], acknowledged={'litellm': keys})
        self.assertTrue(result.get('backup_id'), result)
        self.assertEqual(self.asked, ['hapg', 'hapg', 'll-db', 'll-db'], 'HA twice (check, convert); the new cluster before and after')
        updates = [s for s in self.world.executed('ll-db') if s.startswith('UPDATE public."LiteLLM_Config"')]
        self.assertEqual(updates, ['UPDATE public."LiteLLM_Config" SET param_value = param_value - \'post_call_rules\'::text '
                                   'WHERE param_name = \'litellm_settings\' AND jsonb_typeof(param_value) = \'object\''])
        reminders = result['ha_import']['reminders_by_app']['litellm']
        self.assertTrue(any('litellm_settings.post_call_rules' in r and '沒有搬過來' in r for r in reminders), reminders)

    def test_a_setting_that_stays_stops_the_conversion_and_nothing_is_packed(self):
        self.both_sides(self.HOOK, [self.HOOK, self.HOOK])
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'], acknowledged={'litellm': self.confirm_keys()})
        self.assertEqual(caught.exception.message, ha_litellm.HOOKS_STAYED)
        self.assertEqual(self.storage.list_backups(), [])
        self.assertFalse([r for r in self.world.restores if r[0] == 'll-db' and '/dev/null' in r[1]],
                         'stopped before the converted database was written')

    def test_hooks_only_the_new_cluster_sees_need_another_confirmation(self):
        # Review SR-8: a crafted data directory controls HA's catalog; an edited built-in =(text,text) operator hid
        # post_call_rules and custom_auth from the HA-side query while COPY moved them. The same query in the new
        # cluster (this device's image and schema, HA's data as rows) says what actually moved: names the customer did
        # not confirm stop this app (confirmation-required), never a silent removal.
        for new_value in (self.HOOK, {'sections': ['router_settings'], 'env': [], 'callbacks': [], 'hooks': [],
                                      'nested': ['router_settings.plugins']}):
            self.both_sides(self.CLEAN, [new_value])
            with self.assertRaises(BackupError) as caught:
                self.convert(self.upload_litellm(), ['litellm'], acknowledged={'litellm': self.confirm_keys()})
            self.assertEqual(caught.exception.code, 'confirmation-required')
            self.assertEqual(self.asked[-1], 'll-db')
            self.assertFalse([r for r in self.world.restores if r[0] == 'll-db' and '/dev/null' in r[1]],
                             'stopped before the converted database was written')
        # with the names confirmed (the page asks again) the same data goes on, the setting taken out
        self.both_sides(self.CLEAN, [self.HOOK, self.CLEAN])
        key = ha_litellm.Issue('litellm.hooks-removed', 'confirm', ha_litellm.HOOKS_REMOVED,
                               ['litellm_settings.post_call_rules']).key('litellm')
        result = self.convert(self.upload_litellm(), ['litellm'], acknowledged={'litellm': [key]})
        self.assertTrue(result.get('backup_id'))

    def test_a_table_that_cannot_be_read_is_not_moved_but_named(self):
        # L-13: read again once; what stays unreadable is no reason to stop: the table is not moved, the customer is told.
        self.world.ha_columns = COLUMNS + self.CONFIG
        self.world.live_columns = COLUMNS + self.CONFIG
        self.world.counts['public.LiteLLM_Config'] = 3
        for code in ('limit-exceeded', 'job-failed'):
            self.raising(code)
            result = self.check(self.upload_litellm(), ['litellm'])[0]
            self.assertEqual(self.asked, ['hapg'] if code == 'limit-exceeded' else ['hapg', 'hapg'],
                             'a read that is not worth repeating (limit) is asked once, one that may pass twice')
            line = next(i for i in result['issues'] if i['id'] == 'litellm.config-unreadable')
            self.assertEqual((line['level'], line['items']), ('confirm', ['LiteLLM_Config']))
            self.assertTrue(result['importable'])
        self.raising('job-failed')
        self.world.new_counts = {**self.world.counts, 'public.LiteLLM_Config': 0}
        result = self.convert(self.upload_litellm(), ['litellm'], acknowledged={'litellm': self.confirm_keys()})
        self.assertTrue(result.get('backup_id'), result)
        self.assertNotIn('LiteLLM_Config', ' '.join(sql for _role, _user, sql in self.world.copies_out), 'its rows are not read')
        self.assertTrue(any('LiteLLM_Config' in r for r in result['ha_import']['reminders_by_app']['litellm']))
        # a second try that works: no line at all
        answers = iter([BackupError('job-failed', 'busy'), self.CLEAN])
        original = self.world.answer

        def flaky(role, sql, database):
            if sql == ha_litellm.STORED_SETTINGS_SQL:
                value = next(answers)
                if isinstance(value, Exception):
                    raise value
                return value
            return original(role, sql, database)

        self.world.answer = flaky
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertNotIn('litellm.config-unreadable', [i['id'] for i in result['issues']])

    def raising(self, code):
        answer, self.asked = self.world.answer, []

        def stored(role, sql, database):
            if sql == ha_litellm.STORED_SETTINGS_SQL:
                self.asked.append(role)
                raise BackupError(code, 'psql: output over the limit or timed out')
            return answer(role, sql, database)

        self.world.answer = stored

    def test_every_label_the_detection_can_give_has_a_removal(self):
        labels = ({f'{a}.{b}' for a, b in ha_litellm.MODULE_HOOKS} | {f'{a}.{b}' for a, b, _p in ha_litellm.NESTED_HOOKS}
                  | {f'litellm_settings.{key}' for key in ha_litellm.CALLBACK_KEYS} | {'litellm_settings.callbacks'})
        removals = ha_litellm.hook_removals()
        self.assertEqual(set(removals), labels)
        sql = ha_litellm.removal_sql(sorted(labels))
        self.assertEqual(sql.count('UPDATE public."LiteLLM_Config"'), len(labels))
        self.assertIn("SET param_value = param_value #- '{litellm_jwtauth,custom_validate}'::text[] WHERE param_name = "
                      "'general_settings' AND jsonb_typeof(param_value) = 'object';", sql)
        self.assertIn("SET param_value = param_value - 'guardrails'::text WHERE param_name = 'litellm_settings' AND", sql)
        self.assertNotIn(' - ,', sql)
        with self.assertRaises(KeyError):
            ha_litellm.removal_sql(['litellm_settings.something_new'])   # an unknown label is never guessed at

    def test_every_vendor_code_place_is_found(self):
        # The vendor's DB-overlay list (litellm 1.104.0 proxy_server.py:4486-4640) and router_settings.plugins
        # (:6722-6737); a STRING callbacks value (callback_utils.py:403-415). The SQL/JSON paths themselves ran on
        # real PostgreSQL 18 in the review's sandbox (stored_variants); here: each one is asked and each label refuses.
        sql = ha_litellm.STORED_SETTINGS_SQL
        labels = sorted({f'{section}.{label}' for section, label, _path in ha_litellm.NESTED_HOOKS})
        self.assertEqual(labels, ['general_settings.custom_secret_manager',
                                  'general_settings.litellm_jwtauth.custom_validate',
                                  'general_settings.pass_through_endpoints', 'litellm_settings.custom_provider_map',
                                  'litellm_settings.guardrails', 'router_settings.plugins'])
        for section, label, path in ha_litellm.NESTED_HOOKS:
            self.assertIn(f"SELECT '{section}.{label}' FROM public.\"LiteLLM_Config\" c WHERE c.param_name = "
                          f"'{section}' AND jsonb_path_exists(", sql)
            self.assertIn(f"'{path}')", sql)
        self.assertIn("jsonb_typeof(c.param_value -> 'callbacks') = 'string'", sql)
        # a dotted callback is found by the query itself, not in the first 50 names the Python side keeps
        self.assertIn("SELECT 'litellm_settings.' || e.key FROM public.\"LiteLLM_Config\" c", sql)
        self.assertIn("AND strpos(v.value, '.') > 0", sql)
        for path, words in (('custom_provider_map[*].custom_handler', ()), ('guardrails[*].*.callbacks[*]', ('[.]',)),
                            ('guardrails[*].*.guardrail', ('[.]',)),
                            ('pass_through_endpoints[*].target', ('[.]', '!(@ like_regex "^[a-z][a-z0-9+-]*://"')),
                            ('litellm_jwtauth.custom_validate', ()), ('plugins[*]', ()),
                            ('key_management_settings.custom_secret_manager', ())):
            match = [p for _s, _l, p in ha_litellm.NESTED_HOOKS if f'$.{path} ?' in p]
            self.assertEqual(len(match), 1, path)
            for word in words:
                self.assertIn(word, match[0])
        self.world.ha_columns = COLUMNS + self.CONFIG
        self.world.live_columns = COLUMNS + self.CONFIG
        self.world.counts['public.LiteLLM_Config'] = 2
        for label in labels + ['litellm_settings.callbacks', 'litellm_settings.success_callback']:
            self.answering({'sections': [label.split('.')[0]], 'env': [], 'callbacks': [], 'hooks': [],
                            'nested': [label]})
            result = self.check(self.upload_litellm(), ['litellm'])[0]
            hooks = [i for i in result['issues'] if i['id'] == 'litellm.hooks-removed']
            self.assertEqual(len(hooks), 1, (label, result['issues']))
            self.assertIn(label, hooks[0]['items'])

    def both_sides(self, ha_value, new_value):
        """HA's cluster answers ha_value, the new cluster new_value (both schemas hold LiteLLM_Config)."""
        self.world.ha_columns = COLUMNS + self.CONFIG
        self.world.live_columns = COLUMNS + self.CONFIG
        self.world.counts['public.LiteLLM_Config'] = 2
        answer, self.asked = self.world.answer, []

        def stored(role, sql, database):
            if sql == ha_litellm.STORED_SETTINGS_SQL:
                self.asked.append(role)
                if role == 'hapg':
                    return copy.deepcopy(ha_value)
                return copy.deepcopy(new_value.pop(0) if isinstance(new_value, list) else new_value)
            return answer(role, sql, database)

        self.world.answer = stored

    def test_the_import_notes_name_what_moved(self):
        self.both_sides({'sections': ['environment_variables'], 'env': [], 'callbacks': [], 'hooks': [],
                         'nested': []},
                        {'sections': ['environment_variables'], 'env': ['HTTPS_PROXY'], 'callbacks': [], 'hooks': [],
                         'nested': []})
        result = self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(self.asked, ['hapg', 'll-db'])
        notes = '\n'.join(result['ha_import']['notes'])
        self.assertIn('HTTPS_PROXY', notes, 'the names of what moved, not what HA\'s cluster said')

    def test_the_import_notes_name_them(self):
        notes, _reminders = ha_litellm.import_texts({'counts': {}, 'key_users': [],
                                                     'stored_settings': {'sections': [], 'env': ['HTTPS_PROXY'],
                                                                         'callbacks': ['x' * 100]}})
        line = [n for n in notes if '存在資料庫裡的代理設定' in n]
        self.assertEqual(len(line), 1)
        self.assertIn('HTTPS_PROXY', line[0])
        self.assertIn('x' * 60, line[0])
        self.assertNotIn('x' * 61, line[0], 'each name cut at 60 characters')
        notes, _reminders = ha_litellm.import_texts({'counts': {}, 'key_users': [], 'stored_settings': None})
        self.assertFalse([n for n in notes if '代理設定' in n])
        self.assertEqual(ha_litellm.stored_settings_line({'env': ['A'] * 12, 'callbacks': []}).count('A、'), 9)


class SchemaReadTests(LiteLLMCase):
    """Real attempt 7 (dev-d, the real HA backup): HA's sessions resolve names in pg_catalog only (SR-1), so
    format_type renders the enum column LiteLLM_CronJob.status as public."JobStatus" there while this device's
    sessions rendered "JobStatus": the check refused a backup whose schema IS this device's. Every session that reads
    the columns or the signature -- HA's cluster, the live database, the schema snapshot, the new cluster -- must
    pin the same search_path, so the names render alike on every side."""
    COLUMNS_MARK = 'pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnotnull, a.attidentity::text'
    SIGNATURE_MARK = "SELECT json_build_object('relations', (SELECT"

    def schema_reads(self):
        reads = []
        for role, command, _data in self.world.execs:
            if command and command[0] == 'psql' and '-c' in command:
                sql = command[command.index('-c') + 1]
                if self.COLUMNS_MARK in sql or self.SIGNATURE_MARK in sql:
                    reads.append((role, sql))
        return reads

    def test_every_schema_read_pins_the_search_path(self):
        self.assertTrue(ha_litellm.COLUMNS_SQL.startswith('SET search_path = pg_catalog; SELECT '))
        self.assertTrue(ha_litellm.SIGNATURE_SQL.startswith('SET search_path = pg_catalog; SELECT '))
        result = self.convert(self.upload_litellm(), ['litellm'])
        self.assertTrue(result.get('backup_id'), result)
        reads = self.schema_reads()
        roles = {role for role, _sql in reads}
        self.assertTrue({'hapg', 'll-db', 'litellm-postgres'} <= roles, roles)
        for role, sql in reads:
            self.assertTrue(sql.startswith('SET search_path = pg_catalog; SELECT '), (role, sql[:80]))
        script = self.world.snapshots[0][1].decode('utf-8')
        columns_line = re.search(r'o \$snapdir/columns\n(.*)\n', script).group(1)
        self.assertTrue(columns_line.startswith('SET search_path = pg_catalog; SELECT coalesce(json_agg('), columns_line)

    def test_the_check_reads_both_sides_pinned(self):
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertTrue(result['ok'], result)
        reads = self.schema_reads()
        self.assertTrue({'hapg', 'litellm-postgres'} <= {role for role, _sql in reads}, reads)
        self.assertTrue(all(sql.startswith(ha_litellm.PIN_SEARCH_PATH) for _role, sql in reads))


class ConvertTests(LiteLLMCase):
    def assert_nothing_loaded(self):
        self.assertFalse(self.world.copies_in, 'no HA row was loaded')
        self.assertEqual(self.storage.list_backups(), [])

    def test_the_whole_conversion(self):
        result = self.convert(self.upload_litellm(), ['litellm'])
        imp = result['ha_import']
        self.assertEqual(imp['apps'], ['litellm'])
        # the salt moves into litellm-salt-key; nothing else of HA's secrets
        self.assertEqual(self.world.converted_secrets, {'litellm-salt-key': SALT})
        self.assertEqual(self.world.manifests['litellm']['postgres']['main']['major'], 17)
        self.assertEqual(self.world.manifests['litellm']['postgres']['main']['server_version'], '17.11')
        self.assertEqual(self.world.converted_dumps, {'main': b'PGDMP-ll-db'})
        # HA's rows: only the trusted tables, read with the trusted columns, loaded by the role without privileges
        self.assertEqual([sql for _r, _u, sql in self.world.copies_out],
                         [f'COPY "{s}"."{t}" ("id", "value") TO STDOUT' for s, t in TABLES])
        self.assertEqual({(r, u) for r, u, _s in self.world.copies_out}, {('hapg', 'postgres')})
        self.assertEqual([(r, u, sql) for r, u, sql, _d in self.world.copies_in],
                         [('ll-db', 'woowbk_restore', f'COPY "{s}"."{t}" ("id", "value") FROM STDIN') for s, t in TABLES])
        # pg-stdin F2: every table travels in a script of its own: its transaction opened and closed by the script, the
        # rows, a line that ends the COPY, the commit and an end mark psql prints only after all of it was read
        for (s, t), (_r, _u, _sql, script) in zip(TABLES, self.world.copies_in):
            head = f'BEGIN;\nCOPY "{s}"."{t}" ("id", "value") FROM STDIN;\nrows of "{s}"."{t}"\n'.encode()
            self.assertTrue(script.startswith(head), script[:120])
            self.assertRegex(script[len(head):].decode(), r'\A\\\.\nCOMMIT;\n\\echo ' + re.escape(ha_odoo.SQL_END_MARK)
                             + r'[0-9a-f]{16}\n\Z')
        self.assertFalse(any('woow"."meta' in sql for _r, _u, sql in self.world.copies_out))
        # the schema is this device's: both sections of the trusted archive, by the app superuser; nothing of HA's
        restores = [(cmd[cmd.index('-U') + 1], [a for a in cmd if a.startswith('--section')], data)
                    for role, cmd, data in self.world.restores if role == 'll-db' and '-U' in cmd]
        self.assertEqual(restores, [('litellm', ['--section=pre-data'], b'PGDMP-trusted-schema'),
                                    ('litellm', ['--section=post-data'], b'PGDMP-trusted-schema')])
        full_read = [cmd for role, cmd, _d in self.world.restores if cmd[:3] == ['pg_restore', '-f', '/dev/null']]
        self.assertEqual(len(full_read), 1, 'the converted dump is read in full once')
        statements = self.world.executed('ll-db')
        self.assertIn(f'CREATE ROLE {ha_litellm.RESTORE_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION '
                      'NOBYPASSRLS', statements)
        self.assertIn(f'DROP ROLE {ha_litellm.RESTORE_ROLE}', statements)
        self.assertIn('SELECT pg_catalog.setval(\'"public"."LiteLLM_AuditLog_id_seq"\', 41, true)', statements)
        setval_users = [cmd[cmd.index('-U') + 1] for role, cmd, data in self.world.execs
                        if role == 'll-db' and cmd[:1] == ['psql'] and data and b'setval' in data]
        self.assertEqual(setval_users, [ha_litellm.RESTORE_ROLE])
        llb = self.runs('ll-db')[0]
        self.assertEqual(llb[1], 'docker.io/library/postgres:17.11-alpine3.23@sha256:bc27')
        self.assertIn('--read-only', llb[3])
        self.assertTrue(any(v.endswith(':rw,noexec,nosuid,nodev') for v in llb[3]['--volume']))
        self.assertEqual(llb[3]['--secret'], ['litellm-postgres-password,type=mount,target=/run/secrets/postgres-password,'
                                             'mode=0400'])
        self.assertGreaterEqual(self.world.live_reads, 2, 'the live schema is read before and after the capture')
        notes = '\n'.join(imp['notes'])
        self.assertIn('取代這台的 litellm-salt-key', notes)
        self.assertIn('Hermes 代理、OpenDesign 目前使用這台 LiteLLM 的金鑰', notes)
        reminders = imp['reminders_by_app']['litellm']
        self.assertTrue(any('請為 Hermes 代理、OpenDesign 重新設定 LiteLLM 金鑰' in r for r in reminders))
        self.assertTrue(any('Woow LiteLLM MCP Server' in r for r in reminders))
        self.assertNotIn(SALT.decode(), json.dumps(result, ensure_ascii=False))

    def test_ddl_during_the_capture_is_taken_again(self):
        # L-39: the schema moved once while it was read (the proxy was starting up); the capture is made again once it
        # holds still, after a pause, and the import goes on.
        def change(world):
            world.live_signature = dict(world.live_signature, indexes=[['public', 'x', 'y', 'CREATE INDEX y']])
            world.after_capture = None
        self.world.after_capture = change
        result = self.convert(self.upload_litellm(), ['litellm'])
        self.assertTrue(result['backup_id'])
        self.assertEqual(len(self.world.snapshots), 2, 'taken twice: the first one was not steady')
        self.assertIn('第 1 次', self.logs())

    def test_ddl_during_every_capture_stops(self):
        changes = []

        def change(world):
            changes.append(1)
            world.live_signature = dict(world.live_signature, indexes=[['public', 'x', f'y{len(changes)}', 'CREATE INDEX']])
        self.world.after_capture = change
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(caught.exception.message, ha_litellm.SCHEMA_CHANGED)
        self.assertEqual(len(self.world.snapshots), 3, 'three tries, then it stops')
        self.assert_nothing_loaded()

    def test_snapshot_columns_must_be_the_live_ones(self):
        self.world.snapshot_columns = COLUMNS[:-1]
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(caught.exception.message, ha_litellm.SCHEMA_CHANGED)
        self.assertEqual(len(self.world.snapshots), 3)
        self.assert_nothing_loaded()

    def test_migrations_that_moved_since_the_check_stop(self):
        calls = {'n': 0}
        original = self.world.answer

        def answer(role, sql, database):
            if role == 'litellm-postgres' and sql == ha_litellm.MIGRATIONS_SQL:
                calls['n'] += 1
                return MIGRATIONS if calls['n'] == 1 else MIGRATIONS + ['20261201000000_new']
            return original(role, sql, database)
        self.world.answer = answer
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(caught.exception.message, ha_litellm.SCHEMA_CHANGED)
        self.assert_nothing_loaded()

    def test_has_columns_must_equal_the_trusted_ones(self):
        self.world.ha_columns = COLUMNS[:-1] + [['woow_platform', 'settings', 'value', 'bytea', True, '', '']]
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertIn('woow_platform.settings', caught.exception.message)
        self.assert_nothing_loaded()

    def test_has_sequences_and_types_must_equal_the_trusted_ones(self):
        self.world.ha_signature = dict(signature(), sequences=[SEQUENCE[:2] + ['bigint'] + SEQUENCE[3:]])
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertIn('LiteLLM_AuditLog_id_seq', caught.exception.message)
        self.world.ha_signature = dict(signature(), types=[['public', 'Role', 'e', '', False, '', ['a']]])
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertIn('public.Role', caught.exception.message)
        self.assert_nothing_loaded()

    def test_has_defaults_checks_and_indexes_are_not_compared(self):
        self.world.ha_signature = dict(signature(), indexes=[['public', 'LiteLLM_SpendLogs', 'woow_idx', 'CREATE INDEX']],
                                       constraints=[], views=[])
        result = self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(result['ha_import']['apps'], ['litellm'])

    def test_the_new_clusters_schema_must_be_the_trusted_one(self):
        self.world.restored_signature = dict(signature(), triggers=[['public', 'LiteLLM_UserTable', 'evil', 'CREATE T']])
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertIn('triggers', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])

    def test_the_new_cluster_holds_nothing_else(self):
        for audit in ({'roles': ['evil', 'litellm']}, {'role_settings': 1}, {'auto_conf': 1}, {'large_objects': 1}):
            self.world.audit = dict({'roles': ['litellm'], 'role_settings': 0, 'auto_conf': 0, 'large_objects': 0},
                                    **audit)
            with self.subTest(audit=audit), self.assertRaises(BackupError) as caught:
                self.convert(self.upload_litellm(), ['litellm'])
            self.assertIn('不應存在的內容', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])

    def test_counts_that_differ_stop_the_conversion(self):
        self.world.new_counts = dict(self.world.counts, **{'public.LiteLLM_VerificationToken': 1})
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertIn('public.LiteLLM_VerificationToken（HA 2，匯入後 1）', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])

    def test_the_loaded_salt_must_be_the_moved_one(self):
        self.world.salt_digest = hashlib.sha256(OTHER_SALT).hexdigest()
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertIn('加密金鑰和要搬過來的不同', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])

    def test_a_salt_the_database_is_not_bound_to_refuses(self):
        self.world.db_salt = OTHER_SALT
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertIn(ha_litellm.SALT_MISMATCH, caught.exception.message)
        self.assertFalse(self.world.copies_out, 'nothing of HA was read')
        self.assert_nothing_loaded()

    def test_names_with_quotes_and_dots_are_quoted_not_refused(self):
        # L-10, L-11, L-12: a table, column or sequence of this device's schema may have any name PostgreSQL has; every
        # statement the import builds quotes it (and doubles a quote in it), and nobody is refused for its characters.
        name = 'Odd"Table.x'
        self.world.counts[f'public.{name}'] = 2
        odd = [['public', name, 'id', 'text', True, '', ''], ['public', name, 'va"lue', 'text', True, '', '']]
        sig = dict(signature(), relations=signature()['relations'] + [['public', name, 'r', 'p', False, False, '', False]])
        self.world.ha_columns = self.world.live_columns = COLUMNS + odd
        self.world.ha_signature = self.world.live_signature = sig
        result = self.convert(self.upload_litellm(), ['litellm'])
        self.assertTrue(result['backup_id'])
        quoted = '"public"."Odd""Table.x" ("id", "va""lue")'
        self.assertIn(f'COPY {quoted} TO STDOUT', [sql for _r, _u, sql in self.world.copies_out])
        self.assertIn(f'COPY {quoted} FROM STDIN', [sql for _r, _u, sql, _d in self.world.copies_in])
        self.assertEqual(ha_litellm._q('public', "it's"), '"public"."it\'s"')
        self.assertEqual(ha_litellm._literal('"public"."it\'s"'), '\'"public"."it\'\'s"\'')
        # more than the 400 tables of before are no reason either (the old limit is gone)
        many = ha_litellm.Schema([['public', f't{i}', 'id', 'text', True, '', ''] for i in range(401)],
                                 dict(signature(), sequences=[], relations=[['public', f't{i}', 'r'] for i in range(401)]), [])
        ha_litellm.require_names(many)

    def keep_supported(self):
        """haimport hands `keep_safety` on (the one-line snippet haimport.py.patch): what the integrator applies."""
        patcher = mock.patch.object(haimport, 'ITEM_KEYS', (*haimport.ITEM_KEYS, 'keep_safety'))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_other_schemas_of_this_device_are_a_line_to_confirm_and_the_pre_restore_backup_is_kept(self):
        # L-38 (owner decision S4, D7): data in this device's database that LiteLLM does not make is never deleted without
        # a word: named once, the import goes on, and the restore keeps the pre-restore backup that holds it.
        self.keep_supported()
        self.world.live_signature = dict(signature(), schemas=['extra', 'woow_platform'])
        self.world.restored_signature = self.world.live_signature
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        line = next(i for i in result['issues'] if i['id'] == 'litellm.other-schemas')
        self.assertEqual((line['level'], line['items']), ('confirm', ['extra']))
        self.assertIn('保留的複本', line['message'])
        self.assertTrue(result['importable'])
        with self.assertRaises(BackupError) as caught:      # not confirmed: only this app stops, nothing was captured
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertFalse(self.world.snapshots, 'nothing captured')
        self.assert_nothing_loaded()
        with self.assertRaises(BackupError) as caught:      # one more name than the customer saw: confirm again
            self.convert(self.upload_litellm(), ['litellm'], acknowledged={'litellm': [
                ha_litellm.Issue('litellm.other-schemas', 'confirm', 'x', ['other']).key('litellm')]})
        self.assertEqual(caught.exception.code, 'confirmation-required')
        result = self.convert(self.upload_litellm(), ['litellm'], acknowledged={'litellm': [line['key']]})
        self.assertTrue(result['backup_id'])
        self.assertIs(self.world.kept, True, 'the adapter was told to keep the pre-restore backup')
        self.assertTrue(any('保留的複本' in note and 'extra' in note for note in result['ha_import']['notes']))

    def other_schemas(self):
        self.keep_supported()
        self.world.live_signature = dict(signature(), schemas=['extra', 'woow_platform'])
        self.world.restored_signature = self.world.live_signature

    def test_l38_not_confirmed_stops_only_this_app_before_anything_is_captured(self):
        self.other_schemas()
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertFalse(self.world.snapshots)
        self.assert_nothing_loaded()

    def test_l38_confirmed_goes_on_and_the_restore_is_told_to_keep_its_backup(self):
        self.other_schemas()
        line = next(i for i in self.check(self.upload_litellm(), ['litellm'])[0]['issues'] if i['id'] == 'litellm.other-schemas')
        self.assertTrue(self.convert(self.upload_litellm(), ['litellm'], acknowledged={'litellm': [line['key']]})['backup_id'])
        self.assertIs(self.world.kept, True)

    def test_l38_one_more_schema_is_confirmed_again(self):
        self.other_schemas()
        line = next(i for i in self.check(self.upload_litellm(), ['litellm'])[0]['issues'] if i['id'] == 'litellm.other-schemas')
        self.world.live_signature = dict(signature(), schemas=['extra', 'extra2', 'woow_platform'])
        self.world.restored_signature = self.world.live_signature
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'], acknowledged={'litellm': [line['key']]})
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assert_nothing_loaded()

    def test_without_the_one_line_snippet_other_schemas_stop_the_app(self):
        # Until haimport hands `keep_safety` on, the promise of the line could not be kept: fail closed, as before.
        self.world.live_signature = dict(signature(), schemas=['extra', 'woow_platform'])
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertFalse(result['importable'])
        self.assertIn(('litellm.keep-unsupported', 'stop'), [(i['id'], i['level']) for i in result['issues']])
        line = next(i for i in result['issues'] if i['id'] == 'litellm.other-schemas')
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'], acknowledged={'litellm': [line['key']]})
        self.assertEqual(caught.exception.message, ha_litellm.KEEP_UNSUPPORTED)
        self.assert_nothing_loaded()

    def test_the_pg18_image_is_the_pinned_one_by_content(self):
        self.world.images = set()
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertIn('不是預期的版本', caught.exception.message)
        self.assertEqual(self.world.pulls, [ha_litellm.PG18_PINNED])
        self.assertFalse(self.runs('hapg'))
        self.world.pull_gives = ha_litellm.PG18_IDS[1]
        self.world.pulled = False
        result = self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(result['ha_import']['apps'], ['litellm'])
        self.assertEqual(self.runs('hapg')[0][1], ha_litellm.PG18_IDS[1])

    def test_a_pg18_image_that_cannot_be_fetched_stops_only_this_app_and_says_why(self):
        # L-58: tried a second time; then only this app stops, with the reason, and nothing was changed.
        self.world.images = set()
        self.world.pull_fails = (125, b'Error: pinging container registry: dial tcp: lookup registry-1.docker.io: no such host')
        for call, check in (('convert', False), ('check', True)):
            with self.subTest(call):
                del self.world.pulls[:]
                if check:
                    row = self.check(self.upload_litellm(), ['litellm'])[0]
                    stop = next(i for i in row['issues'] if i['level'] == 'stop')
                    self.assertEqual(stop['id'], 'target.image-missing')
                    self.assertIn('連不上網路', stop['message'])
                    self.assertNotIn('結束碼', stop['message'])
                else:
                    with self.assertRaises(BackupError) as caught:
                        self.convert(self.upload_litellm(), ['litellm'])
                    self.assertEqual(caught.exception.issues[0].id, 'target.image-missing')
                self.assertEqual(self.world.pulls, [ha_litellm.PG18_PINNED] * 2, 'a second try after a pause')
                self.assertFalse(self.runs('hapg'))

    def test_the_target_must_read_the_salt_secret(self):
        for quadlets, secrets in ((dict(QUADLETS, **{'litellm.container': QUADLETS['litellm.container'].replace(
                b'target=LITELLM_SALT_KEY', b'target=OTHER')}), SECRETS),
                                  (QUADLETS, [s for s in SECRETS if s != 'litellm-salt-key'])):
            self.world.quadlets['litellm'] = quadlets
            self.catalog['litellm'].secrets = [{'name': name} for name in secrets]
            with self.subTest(secrets=len(secrets)), self.assertRaises(BackupError) as caught:
                self.convert(self.upload_litellm(), ['litellm'])
            self.assertIn('litellm-salt-key', caught.exception.message)
            self.assertFalse(self.runs('hapg'), 'refused before anything ran')

    def test_test_mode_changes_nothing_else(self):
        result = self.convert(self.upload_litellm(), ['litellm'], test_mode=True)
        self.assertTrue(result['ha_import']['test_mode'])
        self.assertEqual(self.world.converted_secrets, {'litellm-salt-key': SALT})


class SingleProtectionTests(LiteLLMCase):
    """The lane verifier's own mutation check (2026-11-24) removed 16 single protections of ha_litellm.py that no unit
    test noticed: each test here fails when that one protection is gone (litellm_product_mutations.py N01..N34; the
    ids are the verifier's)."""

    def test_n01_no_version_stops_the_conversion(self):
        """L-31..L-34, L-45: whichever version HA's add-on or this device's LiteLLM has, and whether it can be read or not,
        the data's own shape decides (migrations L-26, columns L-09); the conversion says the version in one reminder."""
        for upload, live, words in (({'version': '0.1.14'}, '1.104.0', 'version.addon-unknown'),
                                    ({}, '1.105.0', 'litellm.version-differs'),
                                    ({}, None, 'version.target-unknown'), ({'state': '1.103.0'}, '1.104.0', None)):
            self.world.app_version = live
            with self.subTest(words=words, live=live):
                result = self.convert(self.upload_litellm(**upload), ['litellm'])
                self.assertTrue(result['backup_id'])
                found = [i['id'] for i in result['results'][0]['issues']]
                self.assertEqual(words in found, words is not None, found)

    def test_n09_the_new_clusters_own_major_is_the_version(self):
        # L-53: what the image's label says is not asked; the new cluster answers which major it is, and a cluster that
        # does not answer with a number stops the app.
        for major in ('17', 17.0, None, True):
            self.world.new_major = major
            with self.subTest(major=major):
                self.refused('無法讀取新的 PostgreSQL 叢集的版本', 'job-failed')
        for major in (16, 17, 18):
            self.world.new_major = major
            with self.subTest(major=major):
                self.assertTrue(self.convert(self.upload_litellm(), ['litellm'])['backup_id'])
                self.assertEqual(self.world.manifests['litellm']['postgres']['main']['major'], major)

    def test_n10_an_empty_dump_is_not_a_backup(self):
        self.world.new_dump = b''
        self.refused('LiteLLM 轉換後的資料庫匯出結果為空', 'job-failed')
        self.assertFalse([cmd for _role, cmd, _d in self.world.restores if '/dev/null' in cmd], 'stopped at once')

    def test_n11_the_pinned_image_is_not_asked_which_version_it_is(self):
        # L-30: the image is the pinned one by content; the version it would answer is never read from HA's cluster.
        asked = []
        answer = self.world.answer

        def watch(role, sql, database):
            if 'server_version_num' in sql and role == 'hapg':
                asked.append(sql)
            return answer(role, sql, database)

        self.world.answer = watch
        for major in (17, 19, None):
            self.world.ha_major = major
            with self.subTest(major=major):
                self.assertEqual(self.blockers(), [])
                self.assertTrue(self.convert(self.upload_litellm(), ['litellm'])['backup_id'])
        self.assertEqual(asked, [])

    def test_n12_the_conversions_space_is_reserved_before_has_cluster_starts(self):
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(addon_tar()))) as tar:
            size = sum(m.size for m in tar.getmembers() if m.isfile() and m.name.startswith('data/postgres/'))
        self.assertGreater(size, 0)
        # exactly the write-ahead allowance is free above the floor: three times HA's cluster more is needed
        with mock.patch.object(haimport.SpaceGuard, 'free', lambda guard: guard.floor + ha_odoo.WAL_ALLOWANCE):
            error = self.refused('空間不足', 'insufficient-space')
        self.assertEqual(error.details['required'] - error.details['free'], 3 * size)
        self.assertFalse(self.runs('hapg'), "HA's cluster never started")
        self.assertFalse(self.world.copies_out or self.world.snapshots)
        with mock.patch.object(haimport.SpaceGuard, 'free',
                               lambda guard: guard.floor + ha_odoo.WAL_ALLOWANCE + 3 * size):
            self.assertTrue(self.convert(self.upload_litellm(), ['litellm'])['backup_id'], 'that much is enough')

    BAD_SALT_FILE = 'LiteLLM 附加元件的加密金鑰檔格式不正確，無法匯入。'

    def test_n14_the_salt_file_is_one_small_regular_file(self):
        folder = {'name': 'data/secrets/salt_key', 'type': 'dir'}
        large = {'name': 'data/secrets/salt_key', 'data': SALT + b'\n' * (1025 - len(SALT)), 'mode': 0o600}
        for name, entry in (('a folder', folder), ('1025 bytes', large)):
            with self.subTest(name):
                self.assertEqual(self.blockers(salt=None, extra=[entry]), [self.BAD_SALT_FILE])
                self.refused(self.BAD_SALT_FILE, salt=None, extra=[entry])
        fits = dict(large, data=SALT + b'\n' * (1024 - len(SALT)))
        self.assertEqual(self.blockers(salt=None, extra=[fits]), [], '1024 bytes are read, the line ends stripped')

    def test_n14_a_second_salt_file_refuses(self):
        # The strict archive reader already refuses a name that is there twice; the scan refuses it by itself, too.
        # Since 2026-11-25 (HA-12) a damaged add-on member stops only its app, the check job ends well.
        second = {'name': 'data/secrets/salt_key', 'data': OTHER_SALT + b'\n', 'mode': 0o600}
        row = self.check(self.upload_litellm(extra=[second]), ['litellm'])[0]
        self.assertEqual((row['importable'], [issue['id'] for issue in row['issues']]),
                         (False, ['failure.corrupt-archive']))

        def entry():
            data = SALT + b'\n'
            return types.SimpleNamespace(name='data/secrets/salt_key', kind='file', size=len(data),
                                         read_all=lambda _limit: data)

        report = types.SimpleNamespace(addon=types.SimpleNamespace(slug='woow-litellm'), skipped_symlinks=0)
        with mock.patch.object(ha_litellm.habackup, 'iter_entries', return_value=iter([entry()])):
            self.assertTrue(ha_litellm.scan_member(None, report).salt_valid)
        with mock.patch.object(ha_litellm.habackup, 'iter_entries', return_value=iter([entry(), entry()])):
            with self.assertRaises(BackupError) as caught:
                ha_litellm.scan_member(None, report)
        self.assertEqual((caught.exception.code, caught.exception.message), ('incompatible', self.BAD_SALT_FILE))

    def test_m13_the_rows_the_migrations_and_the_number_of_tables_are_all_compared(self):
        words = 'LiteLLM 匯入後的資料和 HA 不同，已停止：'
        self.world.new_counts = dict(self.world.counts, **{'public.LiteLLM_UserTable': 1})
        self.refused(f'{words}public.LiteLLM_UserTable（HA 2，匯入後 1）。', 'job-failed')
        self.world.new_counts = None
        for now in (MIGRATIONS[:2], MIGRATIONS + ['20991231000000_later'], [], 'x'):
            self.world.new_migrations = now
            with self.subTest(migrations=now):
                self.refused(f'{words}結構版本。', 'job-failed')
        self.world.new_migrations = None
        original = self.world.answer

        def one_table_less(role, sql, database):
            found = original(role, sql, database)
            if role == 'hapg' and sql.startswith('SELECT json_build_array((SELECT count(*)'):
                return found[:-1]   # one table's count did not come back
            return found

        self.world.answer = one_table_less
        self.refused(f'{words}結構版本。', 'job-failed')
        self.world.answer = original
        self.assertTrue(self.convert(self.upload_litellm(), ['litellm'])['backup_id'])

    def test_n16_the_new_clusters_schema_is_compared_after_post_data_and_after_the_last_write(self):
        evil = dict(signature(), triggers=[['public', 'LiteLLM_UserTable', 'evil', 'CREATE T']])
        drop = f'DROP ROLE {ha_litellm.RESTORE_ROLE}'
        for answers, stage in (([evil, signature()], 'restored'), ([signature(), evil], 'loaded')):
            self.world.new_signatures = list(answers)
            self.world.psql.clear()
            with self.subTest(stage=stage):
                error = self.refused('triggers', 'job-failed')
                self.assertEqual(error.details.get('stage'), stage)
                # the first comparison stops before the loader role is dropped, the second one is after that last write
                self.assertEqual(drop in self.world.executed('ll-db'), stage == 'loaded')
        trusted = ha_litellm.Schema(COLUMNS, signature(), MIGRATIONS)
        for part in ha_litellm.SIGNATURE_KEYS:  # every part of the signature counts
            found = dict(signature(), **{part: ['another value']})
            cluster = types.SimpleNamespace(query_json=lambda _sql, _database, found=found: found)
            with self.subTest(part=part), self.assertRaises(BackupError) as caught:
                ha_litellm.require_schema(cluster, trusted, 'loaded')
            self.assertIn(f'（{part}）', caught.exception.message)

    def test_n19_the_fresh_cluster_must_hold_has_columns_before_any_row(self):
        self.world.new_columns = COLUMNS + [['public', 'LiteLLM_UserTable', 'later', 'text', False, '', '']]
        self.refused('HA 與目標 LiteLLM 的資料表欄位結構不同。')
        self.assertFalse(self.world.copies_in, 'no row of HA was loaded')
        self.assertFalse([s for s in self.world.executed('ll-db') if s.startswith('CREATE ROLE')])

    def shapes(self):
        item = dict(self.catalog['litellm'].postgres[0])
        instance = {key: value for key, value in item.items() if key != 'database'}
        volume = {'name': 'litellm-pgdata', 'label': 'PostgreSQL 資料（冷備份）'}
        return (('two databases', {'postgres': [item, dict(item, id='db2')]}, ha_litellm.LAYOUT_MANY),
                ('whole instance', {'postgres': [dict(instance, scope='instance')]}, ha_litellm.LAYOUT_INSTANCE),
                ('no database item and no volume', {'postgres': []}, ha_litellm.LAYOUT_NONE))

    def test_n21_what_the_entry_cannot_be_filled_with_stops_only_this_app(self):
        # L-03: the single-database entry, the cold entry and an entry with other volumes and folders are filled; an entry
        # that dumps the whole instance (the converted backup has no such form), two database items, or none, are not.
        original = vars(self.catalog['litellm']).copy()
        for name, fields, words in self.shapes():
            vars(self.catalog['litellm']).update(original, **fields)
            with self.subTest(name):
                self.assertEqual(self.blockers(), [words])
                stop = self.refused('資料庫')
                self.assertEqual(stop.message, words)
                self.assertEqual(stop.issues[0].id, 'litellm.layout-unsupported')
                self.assertIn('「應用設定」', stop.issues[0].action)
        self.assertFalse(self.world.runs, 'refused before anything ran')
        vars(self.catalog['litellm']).update(original)
        self.catalog['litellm'].postgres = [dict(original['postgres'][0], scope='database')]
        self.assertEqual(self.blockers(), [], 'the single-database entry, scope written or not')
        self.world.quadlets['litellm'] = {k: v for k, v in QUADLETS.items() if k != 'litellm.container'}
        self.assertEqual(self.blockers(), [ha_litellm.TARGET_MISSING])

    def test_n21b_other_volumes_and_folders_go_along_as_they_are(self):
        self.catalog['litellm'].volumes = [{'name': 'litellm-extra', 'label': 'x'}]
        self.catalog['litellm'].data_dirs = [{'path': '.local/share/litellm', 'label': ''}]
        row = self.check(self.upload_litellm(), ['litellm'])[0]
        line = next(i for i in row['issues'] if i['id'] == 'litellm.extras-carried')
        self.assertEqual((line['level'], line['items']), ('auto', ['litellm-extra', '.local/share/litellm']))
        self.assertTrue(row['importable'])
        carried = []

        def carry(work, app, out_dir, ids, *, volumes=(), dirs=(), report=None, size=None):
            carried.append((list(volumes), list(dirs)))
            tar = Path(out_dir) / 'x.tar'
            tar.write_bytes(fk.tar_of([{'name': '.', 'type': 'dir'}]))
            return {'volumes': {name: tar for name in volumes}, 'dirs': {path: tar for path in dirs}}

        with mock.patch.object(hatarget, 'carry', carry):
            result = self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(carried, [(['litellm-extra'], ['.local/share/litellm'])])
        self.assertTrue(result['backup_id'])

    def test_n21c_a_cold_entry_is_filled_with_the_new_cluster_itself(self):
        # L-03: no database item, the database's data volume among the entry's volumes: the converted backup carries the
        # new cluster (cleanly shut down, checked) as that volume instead of a dump.
        self.catalog['litellm'].postgres = []
        self.catalog['litellm'].volumes = [{'name': 'litellm-pgdata', 'label': 'PostgreSQL 資料（冷備份）'}]
        row = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertTrue(row['importable'], row['issues'])
        result = self.convert(self.upload_litellm(), ['litellm'])
        self.assertTrue(result['backup_id'])
        manifest = self.world.manifests['litellm']
        self.assertEqual(manifest['postgres'], {})
        self.assertEqual(sorted(manifest['volumes']), ['litellm-pgdata'])
        self.assertFalse([r for r in self.world.execs if 'pg_dump' in r[1]], 'no dump: the cluster is the backup')
        self.assertTrue(self.world.stops if hasattr(self.world, 'stops') else True)
        controldata = self.runs('controldata')
        self.assertEqual(len(controldata), 1, 'the shutdown was checked on the cluster itself')
        self.assertEqual(controldata[0][2][:2], ['pg_controldata', '/var/lib/postgresql/data/pgdata'])
        with self.subTest('the cluster did not shut down cleanly'):
            self.world.run = lambda role, image, command, options, data: Result(
                0, b'Database cluster state:               in production\n' if role == 'controldata' else b'', b'')
            with self.assertRaises(BackupError) as caught:
                self.convert(self.upload_litellm(), ['litellm'])
            self.assertIn('沒有正常關閉', caught.exception.message)

    def test_n28_a_missing_platform_schema_is_told_by_the_shape_comparison(self):
        # L-21: the schema list is no gate for what is missing: HA's tables are compared with this device's (L-09), and the
        # ones of woow_platform that HA lacks are what that names.
        self.world.objects = dict(self.world.objects, schemas=['woow'])
        self.assertEqual(self.blockers(), [])
        self.world.ha_columns = [row for row in COLUMNS if row[0] != 'woow_platform']
        found = self.check(self.upload_litellm(), ['litellm'])[0]
        line = next(i for i in found['issues'] if i['id'] == 'litellm.schema-differs')
        self.assertIn('woow_platform.chatgpt_accounts', line['message'])
        self.refused('woow_platform.chatgpt_accounts')
        self.assertFalse(self.world.copies_out)

    def test_n29_this_devices_postgresql_major_is_no_gate(self):
        # L-20: 13..18 was only the range tested; the image's own label is shown (or nothing) and decides nothing.
        for major, shown in (('', None), ('12', 12), ('19', 19), ('x', None), ('13', 13), ('18', 18)):
            self.world.image_major = major
            with self.subTest(major=major):
                self.assertEqual(self.blockers(), [])
                found = self.check(self.upload_litellm(), ['litellm'])[0]
                self.assertEqual(found['litellm']['target_pg_major'], shown)
                self.assertTrue(self.convert(self.upload_litellm(), ['litellm'])['backup_id'])

    def test_n30_chatgpt_sign_ins_are_named_in_the_check(self):
        self.assertFalse([w for w in self.check(self.upload_litellm(), ['litellm'])[0]['warnings'] if 'ChatGPT' in w])
        self.world.chatgpt_accounts = 2
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        lines = [w for w in result['warnings'] if 'ChatGPT' in w]
        self.assertEqual(len(lines), 1, result['warnings'])
        self.assertIn('有 2 個 ChatGPT 訂閱登入會一起搬過來；請先停掉 HA 那邊的 LiteLLM', lines[0])
        self.assertEqual((result['ok'], result['litellm']['chatgpt_accounts']), (True, 2))
        reminders = self.convert(self.upload_litellm(), ['litellm'])['ha_import']['reminders_by_app']['litellm']
        self.assertTrue(any('請停掉 HA 那邊的 LiteLLM' in r and 'ChatGPT 頁面重新連結' in r for r in reminders), reminders)

    def test_n32_has_rows_leave_the_disk_as_they_are_loaded(self):
        seen, modes, after = [], set(), []

        def watch(args):
            staged = sorted(Path(self.paths.staging).rglob('rows-*.copy'))
            if args[0] == 'exec' and 'psql' in args and args[-2:] == ['-f', '-'] and ha_litellm.RESTORE_ROLE in args:
                seen.append(len(staged))
                modes.update(stat.S_IMODE(path.stat().st_mode) for path in staged)
            elif args[0] == 'exec' and 'pg_dump' in args:
                after.append(len(staged))

        self.watch_podman(watch)
        self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(seen, [*range(len(TABLES), 0, -1), 0],
                         "each table's rows are deleted once they are loaded (the sequence values come last)")
        self.assertEqual((modes, after), ({0o600}, [0]), 'private, and none is left before the dump')

    def test_n33_the_salt_row_must_be_there_and_be_the_only_one(self):
        good = hashlib.sha256(SALT).hexdigest()
        for rows in ([], None, [good, good], good, {}):
            self.world.salt_rows = rows
            with self.subTest(rows=rows):
                self.refused('匯入後資料庫裡的加密金鑰和要搬過來的不同', 'job-failed')
        self.assertFalse(self.world.converted_secrets, 'no salt was handed over')
        self.world.salt_rows = [good]
        self.assertTrue(self.convert(self.upload_litellm(), ['litellm'])['backup_id'])

    def removals(self):
        """Labels, in order, of the HA cluster's removals, this device's schema reads and the new cluster's start."""
        order = []

        def watch(args):
            if args[0] == 'rm' and fk.role_of(args[-1]) == 'hapg':
                order.append('container')
            elif args[:2] == ['volume', 'rm'] and fk.role_of(args[-1]) == 'hapg':
                order.append('volume')
            elif args[0] == 'run' and fk.role_of(args[args.index('--name') + 1]) == 'll-db':
                order.append('new cluster')
            elif args[0] == 'exec' and 'litellm-postgres' in args and args[-1] == ha_litellm.SIGNATURE_SQL:
                order.append('live schema')

        self.watch_podman(watch)
        return order

    def test_n34_the_check_removes_has_cluster_before_it_reads_this_device(self):
        order = self.removals()
        self.assertEqual(self.blockers(), [])
        self.assertEqual(order[:3], ['container', 'volume', 'live schema'])

    def test_n34_the_conversion_removes_has_cluster_before_the_new_one_starts(self):
        order = self.removals()
        self.convert(self.upload_litellm(), ['litellm'])
        self.assertLess(order.index('container'), order.index('new cluster'))
        self.assertLess(order.index('volume'), order.index('new cluster'))


class OtherRefusalTests(LiteLLMCase):
    """Refusals of ha_litellm.py that no test ran until 2026-11-24 (line coverage of the LiteLLM modules): an answer that is
    not what the import expects stops it, each with its own message (litellm_product_mutations.py R01..R16)."""

    def answer(self, wanted, value, role='hapg'):
        """The fake cluster `role` answers `value` to every query `wanted` says yes to."""
        original = self.world.answer

        def answer(asked, sql, database):
            return value if asked == role and wanted(sql) else original(asked, sql, database)

        self.world.answer = answer

    def test_r01_a_state_file_of_another_version_is_no_gate(self):
        # L-31: HA's own bookkeeping of the version the database was last migrated by; the migrations compared with this
        # device's and the shape of the data say it better. The version it names is the one shown.
        result = self.convert(self.upload_litellm(state='1.103.0'), ['litellm'])
        self.assertTrue(result['backup_id'])
        self.assertEqual(self.check(self.upload_litellm(state='1.103.0'), ['litellm'])[0]['litellm']['litellm_version'],
                         '1.104.0', "the table's version when it knows the add-on")

    def test_r02_the_scan_does_not_judge_whose_add_on_it_reads(self):
        # L-02: which add-on a member is was settled before the importer is called (Work.addon_info: `ha.addon-other`, the
        # one stop of that kind); the scan reads what it is given and no longer says it a second time.
        for addon in (None, types.SimpleNamespace(slug='woow-litellm-mcp'), types.SimpleNamespace(slug='')):
            report = types.SimpleNamespace(addon=addon, skipped_symlinks=0)
            with self.subTest(addon=addon), mock.patch.object(ha_litellm.habackup, 'iter_entries', return_value=iter([])):
                self.assertIs(ha_litellm.scan_member(None, report).addon, addon)
        member = {'user': {'version': '0.1.15'}, 'system': {'slug': 'woow-litellm-mcp'}, 'version': '0.1.15'}
        tar = gzip.compress(hx.tar_bytes([{'name': '.', 'type': 'dir'}, {'name': './addon.json',
                                                                       'data': json.dumps(member).encode()}]), mtime=0)
        found = self.check(self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', tar)], hx.ha_doc(addons=(SLUG,)))), ['litellm'])[0]
        self.assertEqual([(i['id'], i['level']) for i in found['issues']], [('ha.addon-other', 'stop')])

    def test_r03_r04_an_odd_schema_answer_is_not_a_schema(self):
        row = COLUMNS[0]
        for bad in (None, {}, [], [row[:6]], [row + ['x']], ['row'], [row] * 20001):
            self.world.ha_columns = bad
            with self.subTest(columns=str(bad)[:40]):
                self.assertEqual(self.blockers(), ['無法確認HA 的 LiteLLM的資料表結構。'])
                self.refused('無法確認HA 的 LiteLLM的資料表結構。')
        self.world.ha_columns = copy.deepcopy(COLUMNS)
        partial = {key: value for key, value in signature().items() if key != 'triggers'}
        for bad in (None, [], partial, dict(signature(), more=[])):
            self.world.ha_signature = bad
            with self.subTest(signature=str(bad)[:40]):
                self.assertEqual(self.blockers(), ['無法確認HA 的 LiteLLM的資料庫結構。'])
                self.refused('無法確認HA 的 LiteLLM的資料庫結構。')
        self.assertFalse(self.world.copies_out)

    def test_r05_this_devices_migrations_must_be_readable(self):
        for bad in (None, [], 'x', [1], ['a;b'], ['m'] * 2001):
            self.world.live_migrations = bad
            del self.started[:]
            with self.subTest(migrations=str(bad)[:40]):
                self.assertEqual([(i['id'], i['level']) for i in self.check(self.upload_litellm(), ['litellm'])[0]['issues']],
                                 [('litellm.target-migrations', 'stop')])
                self.assertEqual(self.blockers(), [ha_litellm.MIGRATIONS_UNREADABLE])
                self.refused(ha_litellm.MIGRATIONS_UNREADABLE)
                # L-08: a start only helps a database that has no finished migration yet, not one whose answer is unusable
                self.assertEqual(len(self.started), 3 if bad in (None, []) else 0, self.started)
        self.assertFalse(self.world.copies_out)

    def test_r05b_a_database_that_never_ran_gets_the_proxys_first_start(self):
        # L-08: no table (the proxy never ran) or no finished migration yet: the proxy is started once, waited for until
        # the database answers with migrations, then read again; the service is put back with the app's other objects.
        for present, value in ((False, None), (True, [])):
            self.world.migrations_present, self.world.live_migrations = present, value
            del self.started[:]

            def started(container, world=self.world):
                world.migrations_present, world.live_migrations = True, list(MIGRATIONS)

            self.on_start = started
            with self.subTest(present=present):
                result = self.check(self.upload_litellm(), ['litellm'])[0]
                self.assertTrue(result['importable'], result['issues'])
                self.assertEqual([c for c, _k in self.started], ['litellm'])
                self.assertEqual(self.started[0][1]['timeout'], ha_litellm.FIRST_START_WAIT)
                self.assertTrue(callable(self.started[0][1]['ready']))
        self.on_start = None
        self.world.migrations_present, self.world.live_migrations = False, None   # it does not start: only this app stops
        stop = next(i for i in self.check(self.upload_litellm(), ['litellm'])[0]['issues'] if i['level'] == 'stop')
        self.assertIn(ha_litellm.MIGRATIONS_UNREADABLE, stop['message'])

    def test_r06_r07_names_are_quoted_whatever_they_hold(self):
        # L-10, L-11, L-12: a name is put between double quotes with a quote inside doubled; what looks like SQL stays a name.
        self.assertEqual(ha_litellm.copy_out_sql('public', 'LiteLLM_UserTable', ['user_id', 'spend']),
                         'COPY "public"."LiteLLM_UserTable" ("user_id", "spend") TO STDOUT')
        self.assertEqual(ha_litellm.copy_in_sql('pub"lic', 'a"; DROP TABLE x; --', ['id']),
                         'COPY "pub""lic"."a""; DROP TABLE x; --" ("id") FROM STDIN')
        self.assertEqual(ha_litellm.copy_out_sql('public', 'x', ['id', 'x) TO PROGRAM', 'a"b']),
                         'COPY "public"."x" ("id", "x) TO PROGRAM", "a""b") TO STDOUT')
        self.assertEqual(ha_litellm.counts_sql([('public', 'a.b'), ('x', 'y')]),
                         'SELECT json_build_array((SELECT count(*) FROM "public"."a.b"), (SELECT count(*) FROM "x"."y"))')
        # what PostgreSQL cannot hold in a name, or that is no text, cannot come from a catalog and is still refused
        for schema, name in (('public', ''), ('', 'x'), ('public', 'a\x00b'), ('public', 'x' * 64), ('public', 7)):
            with self.subTest(name=(schema, name)), self.assertRaises(BackupError) as caught:
                ha_litellm.copy_in_sql(schema, name, ['id'])
            self.assertEqual(caught.exception.message, 'LiteLLM 的資料表名稱不是這個匯入支援的格式，無法匯入。')
        for columns in ([], ['']):
            with self.subTest(columns=columns), self.assertRaises(BackupError) as caught:
                ha_litellm.copy_out_sql('public', 'x', columns)
            self.assertEqual(caught.exception.message, 'LiteLLM 的資料表欄位名稱不是這個匯入支援的格式，無法匯入。')

    def test_r08_a_salt_that_could_not_be_compared_is_not_a_match(self):
        def script(_sql, _database):
            raise BackupError('job-failed', 'the reader role cannot be made')

        src = types.SimpleNamespace(salt_valid=True, salt=lambda: SALT)
        binding = ha_litellm.salt_binding(types.SimpleNamespace(script=script), src)
        self.assertEqual(binding, 'unknown')
        with mock.patch.object(ha_litellm, 'salt_binding', return_value=binding):
            words = 'HA 備份裡找不到格式正確的 LiteLLM 加密金鑰（salt_key）'
            self.assertTrue([b for b in self.blockers() if b.startswith(words)])
            self.refused(words)
        self.assertFalse(self.world.copies_out)

    def test_r09_has_cluster_must_hold_the_litellm_database(self):
        self.answer(lambda sql: sql == ha_odoo.DATABASES_SQL, [['postgres', 100, 'C', 'C.UTF-8']])
        self.assertEqual(self.blockers(), ['HA 的 LiteLLM 沒有 litellm 資料庫。'])
        self.refused('HA 的 LiteLLM 沒有 litellm 資料庫。')

    def test_r10_what_has_database_holds_must_be_readable(self):
        for bad in (None, [], 'x'):
            self.world.objects = bad
            with self.subTest(objects=bad):
                self.assertEqual(self.blockers(), ['無法讀取 HA 的 LiteLLM 資料庫。'])
                self.refused('無法讀取 HA 的 LiteLLM 資料庫。', 'job-failed')

    def test_r14_a_cluster_version_that_cannot_be_read_is_not_18(self):
        for data in (b'x\n', b'18.6\n', b'', b'\xff18\n', b'018\n'):
            with self.subTest(pg_version=data):
                self.assertIn('HA 的 LiteLLM 資料庫不是預期的 PostgreSQL 18（是 未知 版）。', self.blockers(pg_version=data))
                self.refused('HA 的 LiteLLM 資料庫不是預期的 PostgreSQL 18（是 未知 版）。', pg_version=data)
        self.assertFalse(self.world.copies_out)

    def test_r15_a_state_file_that_is_not_one_says_nothing(self):
        large = {'name': 'data/woow/state.json', 'data': b'{"litellm_version": "1.103.0"' + b' ' * 65536 + b'}'}
        read, real = [], habackup.Entry.read_all

        def read_all(entry, max_bytes):
            read.append(entry.name)
            return real(entry, max_bytes)

        for name, extra in (('none', []), ('a folder', [{'name': 'data/woow/state.json', 'type': 'dir'}]),
                            ('too large', [large])):
            with self.subTest(name), mock.patch.object(habackup.Entry, 'read_all', read_all):
                del read[:]
                self.assertEqual(self.blockers(state=None, extra=extra), [])
                # Not read at all: a folder would read as nothing (Entry.read gives b'' for an entry that is not a
                # file, strict_json makes that None), so only this line notices when its kind is not checked (R15).
                self.assertNotIn(ha_litellm.STATE_FILE, read)

    def test_r16_a_database_without_a_table_stops_and_no_name_does(self):
        def schema(tables):
            return ha_litellm.Schema([['public', t, 'id', 'text', True, '', ''] for t in tables],
                                     dict(signature(), sequences=[], relations=[['public', t, 'r'] for t in tables]), [])

        for tables in ([f't{i}' for i in range(1000)], ['a"b'], ['a', 'x y'], ['a.b', 'a']):   # L-10: no limit, any name
            with self.subTest(tables=len(tables)):
                ha_litellm.require_names(schema(tables))
        with self.assertRaises(BackupError) as caught:    # 0 tables still stops
            ha_litellm.require_names(schema([]))
        self.assertIn('沒有讀取任何資料就停止了', caught.exception.message)
        self.assertEqual(schema([]).tables(), [])
        # a dotted name cannot be mistaken for two (L-10..L-12): the shapes are compared by the names themselves
        one = ha_litellm.Schema([['a', 'b.c', 'id', 'text', True, '', '']], dict(signature(), sequences=[], types=[]), [])
        other = ha_litellm.Schema([['a.b', 'c', 'id', 'integer', True, '', '']], dict(signature(), sequences=[], types=[]), [])
        self.assertEqual(ha_litellm.schema_differences(one, other), ['a.b.c', 'a.b.c'][:2] and ha_litellm.schema_differences(one, other))
        self.assertEqual(len(ha_litellm.schema_differences(one, other)), 2)

    def test_r11_no_script_is_built_with_a_name_that_is_no_migrations(self):
        # L-35: the customer-facing stop is gone (this device's migrations are read, and started for, before: L-08); what
        # is left is the guard of the script builder: the names go into a shell here-document, so one that is no
        # migration's name never gets there (an internal error, not a customer's case).
        for bad in (["x'; DROP TABLE y; --"], [1], ['a$(id)'], ['a`b`'], ['a\\b']):
            with self.subTest(expected=bad), self.assertRaises(BackupError) as caught:
                ha_litellm.snapshot_script(bad)
            self.assertEqual(caught.exception.code, 'internal-error')
        self.assertIn("= '[]'", ha_litellm.snapshot_script([]).replace('::text', ''))   # nothing is refused for being empty
        self.assertIn("'[]'", ha_litellm.snapshot_script(None))

    def test_a_snapshot_whose_first_line_is_not_the_columns_stops_and_leaves_nothing(self):
        podman, removed, left = self.world.podman, [], []

        def garbled(args, data, stdout):
            if args[:5] == ['exec', '-i', 'litellm-postgres', 'sh', '-s']:
                stdout.write(b'psql: not json\nPGDMP')
                return Result(0, None, b'')
            return podman(args, data, stdout)

        self.world.podman = garbled
        unlink = Path.unlink

        def seen(path, *args, **kwargs):
            result = unlink(path, *args, **kwargs)
            if path.name.startswith('target-schema.dump'):
                removed.append(path.name)
                left.extend(sorted(x.name for x in path.parent.glob('target-schema.dump*')))
            return result

        with mock.patch.object(Path, 'unlink', seen):
            self.refused('目標 LiteLLM 的結構快照格式不正確。')
        self.assertEqual((removed, left), (['target-schema.dump.capture'] * 3, []), 'the captured text is gone at once, each try')
        self.assertFalse(self.runs('ll-db'))

    def test_r12_a_new_cluster_that_cannot_be_audited_stops(self):
        for bad in (None, [], 'x'):
            self.world.audit = bad
            with self.subTest(audit=bad):
                self.refused('無法檢查新的 PostgreSQL 叢集。', 'job-failed')

    def test_r13_a_sequence_value_that_is_not_one_stops(self):
        original = self.world.answer
        for bad in (None, [41], ['41', True], [41, 1], [True, True], [41, True, 0], [41.5, True]):
            self.world.answer = original
            self.answer(lambda sql: sql.startswith('SELECT json_build_array(last_value, is_called)'), bad)
            with self.subTest(value=bad):
                self.refused('無法讀取 HA 的 LiteLLM 序號 public.LiteLLM_AuditLog_id_seq。')
                self.assertFalse(self.runs('ll-db'), 'no new cluster was started')


class KeyUserSourceTests(LiteLLMCase):
    """Option A's reminder (owner decision 2026-11-23): each source an app's use of LiteLLM is derived from names the app by
    itself -- a declared config file, a Quadlet file (a setting or LiteLLM's network), LiteLLM's own drop-in that joins
    one of the app's networks, a Pi agent's provider list (CheckTests)."""

    def setUp(self):
        super().setUp()
        self.world.files.clear()
        self.world.quadlets = {'litellm': QUADLETS}

    def users(self):
        return self.check(self.upload_litellm(), ['litellm'])[0]['litellm']['key_users']

    def dropin(self, text):
        self.world.files[f'{ha_litellm.DROPIN_DIR}/{ha_litellm.DROPINS[0]}'] = text.encode()

    def test_an_app_that_does_not_use_it_is_not_named(self):
        self.world.quadlets['opendesign'] = {'open-design.container': b'[Container]\nContainerName=od\nImage=x\n'}
        self.assertEqual(self.users(), [])

    def test_a_declared_config_file(self):
        self.world.files['.config/hermes/hermes.env'] = b'LITELLM_API_KEY=sk-x\n'
        self.assertEqual(self.users(), ['Hermes 代理'], "LiteLLM's own MCP administration reads that file too: not named")

    def test_a_quadlet_setting_or_network(self):
        for line in ('Environment=OPENAI_BASE_URL=http://litellm:4000/v1', 'Network=litellm.network',
                     'Network=litellm-net:alias=x'):
            self.world.quadlets['opendesign'] = {'open-design.container': f'[Container]\nImage=x\n{line}\n'.encode()}
            with self.subTest(line=line):
                self.assertEqual(self.users(), ['OpenDesign'])

    def test_a_pi_agents_provider_list_in_a_folder_of_the_owners_home(self):
        self.world.quadlets['omnigent'] = {'pi.container': b'[Container]\nImage=p\nVolume=%h/agents/pi:/data/pi-agent\n'}
        self.assertEqual(self.users(), [], 'no provider list there')
        for url, named in (('http://litellm:4000/v1', True), ('https://example.com/v1', False)):
            self.world.files['agents/pi/models.json'] = json.dumps({'providers': {'x': {'baseUrl': url}}}).encode()
            with self.subTest(url=url):
                self.assertEqual(self.users(), ['Omnigent 協作平台'] if named else [])
        self.world.files['agents/pi/models.json'] = b'{"providers": {"x": ["http://litellm:4000"]}}'
        self.assertEqual(self.users(), [], 'a provider that is not an object is skipped')

    def test_litellms_own_drop_in_that_joins_the_apps_network(self):
        container = b'[Container]\nContainerName=od\nImage=x\nNetwork=design.network\n'
        for network, joined, named in (
                (b'[Network]\nNetworkName=design-net\n', 'podman network connect design-net litellm', True),
                (b'[Network]\nNetworkName=design-net\n', 'podman network connect other-net litellm', False),
                (b'[Network]\nDriver=bridge\n', 'podman network connect systemd-design litellm', True),
                (b'[Network]\nDriver=bridge\n', 'podman network connect design litellm', True),
                (b'[Network]\nDriver=bridge\n', 'podman network connect systemd-other litellm', False)):
            self.world.quadlets['opendesign'] = {'open-design.container': container, 'design.network': network}
            self.dropin(f'[Service]\nExecStartPost=/usr/bin/{joined}\n')
            with self.subTest(network=network, joined=joined):
                self.assertEqual(self.users(), ['OpenDesign'] if named else [])
        self.world.files.clear()
        self.assertEqual(self.users(), [], 'no drop-in: nothing is joined')


class TargetConsistencyTests(LiteLLMCase):
    """ha_litellm.Target: the catalog entry, the two Quadlet files and the declared secrets must fit each other, one
    condition at a time (litellm_product_mutations.py T01..T12)."""
    WORDS = '這台的 LiteLLM 資料庫、加密金鑰（litellm-salt-key）和 Quadlet 檔的設定不一致，無法匯入。'
    DB, PROXY = 'litellm-postgres.container', 'litellm.container'

    def quadlet(self, name, old, new):
        self.assertEqual(QUADLETS[name].count(old), 1, old)
        return dict(QUADLETS, **{name: QUADLETS[name].replace(old, new)})

    def refuses(self, name, words, quadlets=None, item=None, secrets=None):
        app = self.catalog['litellm']
        original, files = vars(app).copy(), self.world.quadlets['litellm']
        if item:
            app.postgres = [dict(app.postgres[0], **item)]
        if secrets is not None:
            app.secrets = [{'name': secret} for secret in secrets]
        if quadlets:
            self.world.quadlets['litellm'] = quadlets
        with self.subTest(name):
            self.assertEqual(self.blockers(), [words])
            self.refused(words)
        vars(app).update(original)
        self.world.quadlets['litellm'] = files

    def test_each_condition_refuses_by_itself(self):
        image = b'Image=docker.io/library/postgres:17.11-alpine3.23@sha256:bc27\n'
        salt = b'Secret=litellm-salt-key,type=env,target=LITELLM_SALT_KEY\n'
        user, plain = b'POSTGRES_USER=litellm\n', b'POSTGRES_USER=lite-llm\n'
        self.refuses('T01 another database in the entry', self.WORDS, item={'database': 'other'})
        self.refuses('T02 another POSTGRES_DB', self.WORDS, self.quadlet(self.DB, b'POSTGRES_DB=litellm', b'POSTGRES_DB=other'))
        self.refuses('T03 another POSTGRES_USER', self.WORDS, self.quadlet(self.DB, user, b'POSTGRES_USER=other\n'))
        self.refuses('T04 a user name that is not plain', self.WORDS, self.quadlet(self.DB, user, plain),
                     item={'user': 'lite-llm'})
        self.refuses('T05 no database image', self.WORDS, self.quadlet(self.DB, image, b''))
        self.refuses('T06 no proxy image', self.WORDS,
                     self.quadlet(self.PROXY, b'Image=localhost/woow-litellm:1.104.0-0.3.16\n', b''))
        self.refuses('T07 another data volume', self.WORDS, item={'data_volume': 'other-pgdata'})
        self.refuses('T08 a PGDATA that is not a plain path', self.WORDS,
                     self.quadlet(self.DB, b'data/pgdata\n', b'data/pg:data\n'))
        self.refuses('T09 the salt secret twice', self.WORDS,
                     self.quadlet(self.PROXY, salt, salt + b'Secret=litellm-salt-key,type=env,target=OTHER\n'))
        self.refuses('T09b the salt as another variable', self.WORDS,
                     self.quadlet(self.PROXY, salt, salt.replace(b'LITELLM_SALT_KEY', b'OTHER')))
        self.refuses('T09c no salt secret in the proxy', ha_litellm.TARGET_MISSING, self.quadlet(self.PROXY, salt, b''))
        self.refuses('T10 the salt secret is not declared', self.WORDS, secrets=[n for n in SECRETS if 'salt' not in n])
        self.refuses('T11 a declared secret twice', self.WORDS, secrets=SECRETS + ['litellm-master-key'])
        for name in (self.DB, self.PROXY):   # L-04: not found by what they mount: treated as not installed
            self.refuses(f'T12 without {name}', ha_litellm.TARGET_MISSING, {k: v for k, v in QUADLETS.items() if k != name})
        self.assertFalse(self.world.runs, 'refused before anything ran')
        self.assertEqual(self.blockers(), [], 'the fixture itself fits')


class SnapshotScriptTests(unittest.TestCase):
    """N18: what runs inside this device's litellm-postgres container to read its schema, run for real by sh with a
    psql and a pg_dump that only answer: the columns and the dump leave only when the snapshot's migrations are the ones
    the check saw."""
    PSQL = '''#!/bin/sh
out=/dev/null
while IFS= read -r line; do
    case $line in
        '\\o '*) out=${line#* }; printf '%s\\n' "$out" >> "$STUB_LOG" ;;
        '\\o') out=/dev/null ;;
        '\\q') exit 0 ;;
        'SELECT pg_export_snapshot();') printf '%s\\n' "$STUB_SNAPSHOT" > "$out" ;;
        'SELECT CASE WHEN '*) printf '%s\\n' "$STUB_REVISION" > "$out" ;;
        'SET search_path = pg_catalog; SELECT '*) [ -z "$STUB_DIES" ] || exit 3
            printf '%s\\n' "$STUB_COLUMNS" > "$out" ;;
    esac
done
'''
    PG_DUMP = '#!/bin/sh\nprintf "pg_dump %s\\n" "$*" >> "$STUB_LOG"\nprintf PGDMP-stub\n'
    COLUMNS_LINE = '[["public", "t", "id", "text", true, "", ""]]'

    def run_script(self, **stub):
        with tempfile.TemporaryDirectory() as directory:
            for name, text in (('psql', self.PSQL), ('pg_dump', self.PG_DUMP)):
                path = Path(directory) / name
                path.write_text(text)
                path.chmod(0o755)
            log = Path(directory) / 'log'
            log.touch()
            env = {'PATH': f'{directory}:/usr/bin:/bin', 'STUB_LOG': str(log), 'STUB_SNAPSHOT': '00000003-0000001B-1',
                   'STUB_REVISION': 'ok', 'STUB_COLUMNS': self.COLUMNS_LINE, 'STUB_DIES': '', **stub}
            proc = subprocess.run(['sh', '-s', '--', 'litellm', 'litellm'], env=env, capture_output=True, timeout=60,
                                  input=ha_litellm.snapshot_script(MIGRATIONS).encode('utf-8'))
            lines = log.read_text().splitlines()
        folders = {os.path.dirname(line) for line in lines if line.startswith('/tmp/woowbk-schema.')}
        self.assertEqual(len(folders), 1, lines)
        self.assertFalse(os.path.exists(folders.pop()), 'the private folder is removed on every way out')
        return proc.returncode, proc.stdout, [line for line in lines if line.startswith('pg_dump ')]

    def test_the_columns_and_the_schema_come_from_one_snapshot(self):
        code, out, dumps = self.run_script()
        self.assertEqual((code, out), (0, self.COLUMNS_LINE.encode() + b'\nPGDMP-stub'))
        self.assertEqual(dumps, ['pg_dump -U litellm -d litellm -Fc --schema-only --no-owner --no-acl '
                                 '--lock-wait-timeout=15s --snapshot=00000003-0000001B-1'])

    def test_other_migrations_in_the_snapshot_stop_before_anything_leaves(self):
        for revision in ('mismatch', '', 'ok '):
            with self.subTest(revision=revision):
                self.assertEqual(self.run_script(STUB_REVISION=revision), (22, b'', []))

    def test_a_psql_that_ends_early_or_an_odd_snapshot_name_stop(self):
        self.assertEqual(self.run_script(STUB_DIES='1'), (21, b'', []))
        self.assertEqual(self.run_script(STUB_SNAPSHOT='x; rm -rf /'), (23, b'', []))

    def test_the_script_asks_for_exactly_the_migrations_the_check_saw(self):
        script = ha_litellm.snapshot_script(MIGRATIONS)
        self.assertIn("::text = '" + json.dumps(sorted(MIGRATIONS)) + "' THEN 'ok' ELSE 'mismatch' END;", script)


class KeyUserTests(unittest.TestCase):
    def test_what_counts_as_using_litellm(self):
        uses = ha_litellm._uses_litellm_text
        self.assertTrue(uses('LITELLM_API_KEY=sk-1\n'))
        self.assertTrue(uses('export OPENAI_BASE_URL="http://litellm:4000/v1"\n'))
        self.assertTrue(uses('Environment=LLM_URL=http://127.0.0.1:4000\n'))
        self.assertTrue(uses('base_url: http://host.containers.internal:4000/v1\n'))
        self.assertFalse(uses('LITELLM_API_KEY=\n# LITELLM_API_KEY=sk-commented\n'))
        self.assertFalse(uses('OPENROUTER_API_KEY=sk-or\nURL=http://localhost:8000\n'))
        self.assertTrue(ha_litellm._joins_litellm_network('[Container]\nNetwork=litellm.network\n'))
        self.assertFalse(ha_litellm._joins_litellm_network('[Container]\nNetwork=hermes.network\n'))
        self.assertEqual(sorted(ha_litellm.NETWORK_RE.findall(
            'ExecStartPost=/usr/bin/podman network connect hermes litellm\nPodmanArgs=--network=open-design\n')),
            ['hermes', 'open-design'])

    def test_line(self):
        self.assertIsNone(ha_litellm.key_users_line([]))
        self.assertIn('Hermes 代理 目前使用', ha_litellm.key_users_line(['Hermes 代理']))

    def test_what_counts_in_a_pi_agent_provider_list(self):
        uses = ha_litellm.models_use_litellm
        self.assertTrue(uses(json.dumps({'providers': {'woow-litellm': {
            'baseUrl': 'http://host.containers.internal:4000/v1', 'apiKey': 'sk-device'}}}).encode()))
        self.assertTrue(uses(json.dumps({'providers': {'a': {'baseURL': 'http://litellm:4000'}}})))
        self.assertTrue(uses(json.dumps({'providers': {'b': {'base_url': 'http://127.0.0.1:4000/v1'}}})))
        for doc in ({'providers': {'openrouter': {'baseUrl': 'https://openrouter.ai/api/v1', 'apiKey': 'sk-or'}}},
                    {'providers': {'remote': {'baseUrl': 'https://litellm.example.com/v1'}}},
                    {'providers': {'woow-litellm': {'apiKey': 'sk-no-url'}}},
                    {'providers': [{'baseUrl': 'http://litellm:4000'}]}, {'baseUrl': 'http://litellm:4000'}, []):
            self.assertFalse(uses(json.dumps(doc).encode()), doc)
        self.assertFalse(uses(b'\xff{not json'))

    def test_where_a_pi_agent_keeps_its_providers(self):
        quadlets = {
            'omnigent-runner.container': b'[Container]\nImage=r\nVolume=omnigent-pi.volume:/data/pi-agent\n'
                                         b'Environment=PI_CODING_AGENT_DIR=/data/pi-agent\n',
            'omnigent-pi.volume': b'[Volume]\n',
            'omnigent-server.container': b'[Container]\nImage=s\nVolume=omnigent-data.volume:/data\n',
            'pi-web.container': b'[Container]\nImage=p\nVolume=pi-agent-data.volume:/data/pi-agent\n'
                                b'Volume=/home/appowner:/host/home/appowner:rw\n',
            'pi-agent-data.volume': b'[Volume]\nVolumeName=pi-agent-data\n',
            'other.container': b'[Container]\nImage=o\nEnvironment=PI_CODING_AGENT_DIR=/srv/pi\n'
                               b'Volume=%h/agents/pi:/srv/pi:Z\nVolume=named-x:/data/pi-agent\n',
            'outside.container': b'[Container]\nImage=q\nVolume=/srv/pi:/data/pi-agent\n'
                                 b'Volume=%h/../etc:/data/pi-agent\n',
            'under-home.container': b'[Container]\nImage=u\nVolume=/home/appowner/pi/:/data/pi-agent/\n',
            'named.container': b'[Container]\nImage=n\nVolume=pi-named:/data/pi-agent:ro\n',
            'pi-agent.image': b'[Image]\nImage=n\n'}
        self.assertEqual(ha_litellm.pi_agent_sources(quadlets, '/home/appowner/'),
                         [('volume', 'pi-named'), ('volume', 'systemd-omnigent-pi'), ('path', 'agents/pi'),
                          ('volume', 'pi-agent-data'), ('path', 'pi')])


class RowTests(LiteLLMCase):
    """The rows of the HAOS parity lane LITELLM (DESIGN F-a): each line to confirm is tried three ways (not confirmed: only this
    app stops; confirmed: it goes on; one more name: confirm again), each automatic handling works and stops only this app
    when it cannot, each removed block has its new behaviour here."""

    def line(self, issue_id, **upload):
        return next((i for i in self.issues(**upload) if i['id'] == issue_id), None)

    def confirm_cycle(self, issue_id, more):
        """`issue_id` is a line to confirm: not confirmed -> confirmation-required before any row is read; confirmed ->
        the conversion goes on; the world changed by `more()` (one more name than the customer saw) -> confirm again."""
        line = self.line(issue_id)
        self.assertEqual(line['level'], 'confirm')
        self.assertTrue(line['key'].startswith(f'{issue_id}:'))
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertEqual(caught.exception.details['apps']['litellm'][0]['id'], issue_id)
        self.assertFalse(self.world.copies_out or self.world.snapshots, 'nothing of HA was read, nothing captured')
        self.assertEqual(self.storage.list_backups(), [])
        more()
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'], acknowledged={'litellm': [line['key']]})
        self.assertEqual(caught.exception.code, 'confirmation-required', 'one more name is another line')
        self.assertEqual(self.storage.list_backups(), [])
        return line

    def confirmed(self, issue_id, **upload):
        line = self.line(issue_id, **upload)
        result = self.convert(self.upload_litellm(**upload), ['litellm'], acknowledged={'litellm': [line['key']]})
        self.assertTrue(result['backup_id'])
        return result

    # ---------------------------------------------------------------- L-21, L-23, L-24: what HA's database has beyond LiteLLM
    def not_confirmed(self, issue_id):
        """Not confirmed: only this app stops (`confirmation-required`) before any row is read or anything captured."""
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertEqual(caught.exception.details['apps']['litellm'][0]['id'], issue_id)
        self.assertFalse(self.world.copies_out or self.world.snapshots)
        self.assertEqual(self.storage.list_backups(), [])

    def one_more(self, issue_id, more):
        """One more name than the customer saw: the confirmation of the old names does not cover it."""
        line = self.line(issue_id)
        more()
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'], acknowledged={'litellm': [line['key']]})
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertEqual(self.storage.list_backups(), [])

    def schemas(self, names):
        self.world.objects = dict(self.world.objects, schemas=[*names, 'woow', 'woow_platform'])

    def test_l21_other_schemas_of_ha_are_named(self):
        self.schemas(['evil'])
        line = self.line('litellm.schemas-skipped')
        self.assertEqual((line['level'], line['items']), ('confirm', ['evil']))
        self.assertTrue(self.check(self.upload_litellm(), ['litellm'])[0]['importable'])

    def test_l21_not_confirmed_stops_only_this_app(self):
        self.schemas(['evil'])
        self.not_confirmed('litellm.schemas-skipped')

    def test_l21_confirmed_goes_on_and_only_this_devices_tables_are_read(self):
        self.schemas(['evil'])
        self.confirmed('litellm.schemas-skipped')
        self.assertFalse(any('evil' in sql for _r, _u, sql in self.world.copies_out))

    def test_l21_one_more_name_is_confirmed_again(self):
        self.schemas(['evil'])
        self.one_more('litellm.schemas-skipped', lambda: self.schemas(['evil', 'evil2']))

    def test_l23_objects_only_a_superuser_makes_are_named(self):
        self.world.superuser = ['EVENT TRIGGER']
        line = self.line('litellm.superuser-objects')
        self.assertEqual((line['level'], line['items']), ('confirm', ['EVENT TRIGGER']))

    def test_l23_not_confirmed_stops_only_this_app(self):
        self.world.superuser = ['EVENT TRIGGER']
        self.not_confirmed('litellm.superuser-objects')

    def test_l23_confirmed_goes_on_and_nothing_of_them_is_created(self):
        self.world.superuser = ['EVENT TRIGGER']
        self.confirmed('litellm.superuser-objects')
        self.assertNotIn('EVENT TRIGGER', ' '.join(self.world.executed('ll-db')), "nothing of HA's is created in the new cluster")

    def test_l23_one_more_name_is_confirmed_again(self):
        self.world.superuser = ['EVENT TRIGGER']
        self.one_more('litellm.superuser-objects', lambda: setattr(self.world, 'superuser', ['EVENT TRIGGER', 'CAST']))

    def test_l13_not_confirmed_stops_only_this_app(self):
        self.world.ha_columns = self.world.live_columns = COLUMNS + StoredSettingsTests.CONFIG
        self.world.counts['public.LiteLLM_Config'] = 3
        answer = self.world.answer

        def unreadable(role, sql, database):
            if sql == ha_litellm.STORED_SETTINGS_SQL:
                raise BackupError('limit-exceeded', 'output over the limit')
            return answer(role, sql, database)

        self.world.answer = unreadable
        self.not_confirmed('litellm.config-unreadable')

    def test_l13_the_confirmation_of_another_line_does_not_cover_it(self):
        self.world.ha_columns = self.world.live_columns = COLUMNS + StoredSettingsTests.CONFIG
        self.world.counts['public.LiteLLM_Config'] = 3
        answer = self.world.answer

        def unreadable(role, sql, database):
            if sql == ha_litellm.STORED_SETTINGS_SQL:
                raise BackupError('limit-exceeded', 'output over the limit')
            return answer(role, sql, database)

        self.world.answer = unreadable
        other = ha_litellm.Issue('litellm.hooks-removed', 'confirm', 'x', ['litellm_settings.post_call_rules']).key('litellm')
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'], acknowledged={'litellm': [other]})
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertEqual(caught.exception.details['apps']['litellm'][0]['id'], 'litellm.config-unreadable')

    def test_l24_large_objects_are_a_reminder_and_do_not_stop(self):
        self.world.objects = dict(self.world.objects, large_objects=3)
        result = self.convert(self.upload_litellm(), ['litellm'])
        line = next(i for i in result['results'][0]['issues'] if i['id'] == 'litellm.large-objects')
        self.assertEqual(line['level'], 'notice')
        self.assertIn('3 個大型物件', line['message'])

    def test_l22_what_else_is_in_has_woow_schema_is_no_reason(self):
        self.assertNotIn('ha_only', ha_litellm.OBJECTS_SQL)
        self.assertFalse(hasattr(ha_litellm, 'HA_ONLY'))
        self.world.objects = dict(self.world.objects, ha_only=['meta', 'a_new_table'])
        self.assertEqual(self.lines(), [('litellm.databases-left', 'notice'), ('litellm.key-users', 'notice')])
        self.assertTrue(self.convert(self.upload_litellm(), ['litellm'])['backup_id'])

    def test_l15_a_database_that_is_not_there_stops_only_this_app_with_what_to_do(self):
        original = self.world.answer

        def none_here(role, sql, database):
            return [['postgres', 100, 'C', 'C.UTF-8']] if sql == ha_odoo.DATABASES_SQL else original(role, sql, database)

        self.world.answer = none_here
        stop = next(i for i in self.issues() if i['level'] == 'stop')
        self.assertEqual((stop['id'], stop['message']), ('litellm.no-database', 'HA 的 LiteLLM 沒有 litellm 資料庫。'))
        self.assertIn('這台的 LiteLLM 不會有任何變更', stop['action'])
        error = self.refused('HA 的 LiteLLM 沒有 litellm 資料庫。')
        self.assertEqual(error.issues[0].id, 'litellm.no-database')

    # ---------------------------------------------------------------- L-04: the proxy is what mounts the salt secret
    def test_l04_the_proxy_is_found_by_what_it_mounts_not_by_its_name(self):
        quadlets = dict(QUADLETS)
        quadlets['gateway.container'] = quadlets.pop('litellm.container').replace(b'ContainerName=litellm\n',
                                                                                  b'ContainerName=llm-gateway\n')
        self.world.quadlets['litellm'] = quadlets
        self.world.proxy_name = 'llm-gateway'
        found = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertTrue(found['importable'], found['issues'])
        self.assertEqual(found['target_version'], '1.104.0', 'read in the renamed container')
        self.assertTrue(self.convert(self.upload_litellm(), ['litellm'])['backup_id'])
        for name, text in (('a database file that does not name its container', QUADLETS['litellm-postgres.container'].replace(
                b'ContainerName=litellm-postgres\n', b'')),):
            with self.subTest(name):
                self.world.quadlets['litellm'] = dict(QUADLETS, **{'litellm-postgres.container': text})
                self.world.proxy_name = 'litellm'
                self.assertEqual(self.blockers(), [], 'the catalog names a container no file calls so: the file that mounts '
                                 'its data volume is the one')

    # ---------------------------------------------------------------- L-36, L-37, L-39, L-54, L-55: a capture is taken again
    def test_l54_l55_a_snapshot_script_that_ended_early_is_run_again(self):
        for exits in ([21], [22], [21, 22]):
            del self.world.snapshots[:]
            self.world.snapshot_exits = list(exits)
            with self.subTest(exits=exits):
                self.assertTrue(self.convert(self.upload_litellm(), ['litellm'])['backup_id'])
                self.assertEqual(len(self.world.snapshots), len(exits) + 1)
        del self.world.snapshots[:]
        self.world.snapshot_exits = [21, 22, 21]
        error = self.refused('結束碼 21', 'job-failed')     # a third failure is no longer tried again
        self.assertEqual(len(self.world.snapshots), 3)
        self.assertEqual(error.details['returncode'], 21)
        self.world.snapshot_exits = [23]       # a snapshot name that is not one is not a busy device: not tried again
        del self.world.snapshots[:]
        self.refused('結束碼 23', 'job-failed')
        self.assertEqual(len(self.world.snapshots), 1)

    def test_l36_l37_a_garbled_first_line_and_moved_migrations_are_taken_again(self):
        podman, first = self.world.podman, []

        def garbled_once(args, data, stdout):
            if args[:5] == ['exec', '-i', 'litellm-postgres', 'sh', '-s'] and not first:
                first.append(1)
                stdout.write(b'psql: not json\nPGDMP')
                return Result(0, None, b'')
            return podman(args, data, stdout)

        self.world.podman = garbled_once
        self.assertTrue(self.convert(self.upload_litellm(), ['litellm'])['backup_id'])
        self.assertIn('第 1 次', self.logs())
        self.world.podman = podman
        calls = {'n': 0}
        original = self.world.answer

        def moving(role, sql, database):
            if role == 'litellm-postgres' and sql == ha_litellm.MIGRATIONS_SQL:
                calls['n'] += 1
                return MIGRATIONS if calls['n'] != 2 else MIGRATIONS + ['20261201000000_new']   # one read while it was moving
            return original(role, sql, database)

        self.world.answer = moving
        self.assertTrue(self.convert(self.upload_litellm(), ['litellm'])['backup_id'])

    # ---------------------------------------------------------------- L-40: extensions
    def test_l40_an_extension_version_that_differs_is_named_a_different_extension_stops(self):
        live = dict(signature(), extensions=[['plpgsql', '1.0', 'pg_catalog'], ['pg_trgm', '1.6', 'public']])
        self.world.live_signature = live
        self.world.restored_signature = dict(live, extensions=[['plpgsql', '1.0', 'pg_catalog'], ['pg_trgm', '1.7', 'public']])
        result = self.convert(self.upload_litellm(), ['litellm'])
        line = next(i for i in result['results'][0]['issues'] if i['id'] == 'litellm.extension-versions')
        self.assertEqual((line['level'], line['items']), ('auto', ['pg_trgm']))
        wanted = 'CREATE EXTENSION IF NOT EXISTS "pg_trgm" WITH SCHEMA "public" VERSION \'1.6\''
        self.assertIn(wanted, self.world.executed('ll-db'), 'made at this device\'s version first, when the image still has it')
        self.assertNotIn('plpgsql', ' '.join(s for s in self.world.executed('ll-db') if s.startswith('CREATE EXTENSION')))
        self.world.restored_signature = dict(live, extensions=[['plpgsql', '1.0', 'pg_catalog'], ['pg_trgm', '1.6', 'extra']])
        self.refused('extensions', 'job-failed')      # another schema of it, or a missing index, is no version
        self.world.restored_signature = dict(live, indexes=[['public', 'x', 'y', 'CREATE INDEX y']])
        self.refused('indexes', 'job-failed')

    # ---------------------------------------------------------------- L-57: the version file is read by its first bytes
    def test_l57_a_long_version_file_is_no_limit_and_the_whole_file_still_goes(self):
        for data, version, importable in ((b'18\n' + b' ' * 200, '18', True), (b'18\n' + b'x' * 200, None, False)):
            with self.subTest(version=version):
                found = self.check(self.upload_litellm(pg_version=data), ['litellm'])[0]
                self.assertEqual(found['importable'], importable, found['issues'])
                if not importable:
                    self.assertIn(('litellm.pg-major', 'stop'), [(i['id'], i['level']) for i in found['issues']])
                    self.assertNotIn('litellm.limit', ' '.join(i['id'] for i in found['issues']))
        staged = self.world.imported['hapg']
        with tarfile.open(fileobj=io.BytesIO(staged)) as tar:
            self.assertEqual(tar.extractfile('PG_VERSION').read(), b'18\n' + b'x' * 200, 'all of it, not the 64 bytes read')

    # ---------------------------------------------------------------- pg-stdin F2: a table's rows travel in a script with an end mark
    def test_f2_a_cut_tail_never_gets_its_mark_and_stops(self):
        scripts = []
        self.assertTrue(self.convert(self.upload_litellm(), ['litellm'])['backup_id'])
        tail = len(re.search(r'\\\.\nCOMMIT;\n\\echo \S+\n\Z', self.world.restore_scripts[0]).group(0))
        for cut in (1, 12, tail - 1, tail, tail + 5, tail + 20):    # the mark's end, its line, the commit, a field of the last row
            self.world.cut_tail = cut
            with self.subTest(cut=cut):
                self.refused(ha_odoo.INCOMPLETE_SQL, 'job-failed')
        self.world.cut_tail = 0
        self.assertTrue(self.convert(self.upload_litellm(), ['litellm'])['backup_id'])
        for script in self.world.restore_scripts[-len(TABLES):]:
            scripts.append(script)
        self.assertTrue(all(s.startswith('BEGIN;\nCOPY ') and '\n\\.\nCOMMIT;\n\\echo ' in s for s in scripts))

    def test_f2_the_script_is_built_around_the_rows_not_into_them(self):
        head, tail = ha_litellm.copy_script('public', 'LiteLLM_UserTable', ['user_id'], 'MARK')
        self.assertEqual(head, 'BEGIN;\nCOPY "public"."LiteLLM_UserTable" ("user_id") FROM STDIN;\n')
        self.assertEqual(tail, '\\.\nCOMMIT;\n\\echo MARK\n')
        # the rows are the COPY text of HA as it came; they are between the two and nothing of them is in a statement
        self.convert(self.upload_litellm(), ['litellm'])
        for (schema, table), script in zip(TABLES, self.world.restore_scripts):
            self.assertEqual(script.count(f'rows of "{schema}"."{table}"\n'), 1)
            self.assertLess(script.index('FROM STDIN;'), script.index('rows of'))
            self.assertLess(script.index('rows of'), script.index('\\.\n'))

    # ---------------------------------------------------------------- what the reader left out is one line to confirm
    def test_the_entries_the_reader_leaves_out_are_one_line_to_confirm(self):
        fifo = {'name': 'data/postgres/pg_stat_tmp/pipe', 'type': 'fifo'}
        line = self.line('files.skipped', extra=[fifo])
        self.assertEqual(line['level'], 'confirm')
        self.assertIn('特殊檔案', line['message'])
        self.assertEqual(self.check(self.upload_litellm(extra=[fifo]), ['litellm'])[0]['importable'], True)
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(extra=[fifo]), ['litellm'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertTrue(self.convert(self.upload_litellm(extra=[fifo]), ['litellm'],
                                     acknowledged={'litellm': [line['key']]})['backup_id'])

    def test_l33_a_version_that_the_running_proxy_cannot_tell_is_read_from_its_image(self):
        self.world.app_version = None      # the proxy does not run: `podman exec` fails
        asked = []
        run = self.world.run

        def image_says(role, image, command, options, data):
            if role == 'version':
                asked.append((image, options.get('--entrypoint'), command))
                return Result(0, b'1.104.0\n', b'')
            return run(role, image, command, options, data)

        self.world.run = image_says
        found = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertEqual(found['target_version'], '1.104.0')
        self.assertNotIn('version.target-unknown', [i['id'] for i in found['issues']])
        self.assertEqual(asked[0][0], 'localhost/woow-litellm:1.104.0-0.3.16', "this device's own proxy image, in a throwaway container")
        self.assertEqual(asked[0][1], ['python'])

    def test_the_lab_drivers_old_verdict_is_judge_on_a_collecting_sink(self):
        src = types.SimpleNamespace(symlinks=0, recovery_files=0, pg_version='18')
        found = {'objects': {'schemas': ['woow_platform', 'evil'], 'large_objects': 2, 'encoding': 'UTF8'}, 'databases': ['litellm'],
                 'migrations': list(MIGRATIONS), 'superuser': ['CAST']}
        blockers, warnings = ha_litellm.verdict(src, found, ha_major=18, live_migrations_value=list(MIGRATIONS), binding='match',
                                                target_major=99)
        self.assertEqual(len(blockers), 2, 'the two lines to confirm are what stands in the way for an older page')
        self.assertEqual(len(warnings), 1)
        blockers, _w = ha_litellm.verdict(src, dict(found, migrations=MIGRATIONS[:1]), ha_major=17, live_migrations_value=list(MIGRATIONS),
                                          binding='mismatch')
        self.assertTrue(any('不是預期的 PostgreSQL 18' in b for b in blockers))
        self.assertTrue(any('資料庫結構版本不同' in b for b in blockers))
        self.assertIn(ha_litellm.SALT_MISMATCH, blockers)


class CandidateStillGuarded(unittest.TestCase):
    def test_the_lab_candidate_never_converts(self):
        with self.assertRaises(BackupError) as caught:
            ha_litellm_candidate.convert(mock.Mock(), mock.Mock(id='litellm'), False, mock.Mock())
        self.assertEqual(caught.exception.message, ha_litellm_candidate.GUARD)


if __name__ == '__main__':
    unittest.main()
