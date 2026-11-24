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

from woowbackup import habackup, ha_litellm, ha_litellm_candidate, ha_odoo, haapps, haimport, jobs
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

    def factory(self, app, **_kwargs):
        return LiteAdapter(app, self)

    def podman(self, args, data, stdout):
        if args[:2] == ['exec', 'litellm'] and 'python' in args:
            return Result(0 if self.app_version else 1, (self.app_version or '').encode(), b'')
        if args[:5] == ['exec', '-i', 'litellm-postgres', 'sh', '-s']:
            self.snapshots.append((args[5:], data))
            columns = self.snapshot_columns if self.snapshot_columns is not None else self.live_columns
            stdout.write(json.dumps(columns).encode() + b'\nPGDMP-trusted-schema')
            if self.after_capture:
                self.after_capture(self)
            return Result(0, None, b'')
        if args[:1] == ['pull']:
            self.pulls.append(args[-1])
            if self.pull_gives:
                self.images.add(self.pull_gives)
            return Result(0, b'', b'')
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
            if sql.startswith('COPY ') and sql.endswith(' FROM STDIN'):
                self.copies_in.append((role, user, sql, data))
                return Result(0, b'', b'')
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
        if role in ('hapg', 'll-db') and sql.startswith('SELECT json_build_object(') and '(SELECT count(*) FROM' in sql:
            names = re.findall(r"'([A-Za-z_]+\.[A-Za-z_]+)', \(SELECT", sql)
            if names:
                counts = self.new_counts if role == 'll-db' and self.new_counts is not None else self.counts
                return {name: counts[name] for name in names}
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
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(**upload), ['litellm'])
        self.assertEqual(caught.exception.code, code, caught.exception.message)
        self.assertIn(words, caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])
        return caught.exception

    def blockers(self, **upload):
        result = self.check(self.upload_litellm(**upload), ['litellm'])[0]
        self.assertEqual(result['ok'], not result['blockers'])
        return result['blockers']

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
        for kwargs, words in (({'version': '0.1.14'}, '還不認得'), ({'state': '1.103.0'}, '最後由 LiteLLM 1.103.0 遷移')):
            result = self.check(self.upload_litellm(**kwargs), ['litellm'])[0]
            self.assertFalse(result['ok'])
            self.assertTrue(any(words in b for b in result['blockers']), result['blockers'])
        self.world.app_version = '1.105.0'
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertIn('版本不同：HA 的 LiteLLM 是 1.104.0', result['blockers'][0])
        self.world.app_version = None
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertIn('無法讀取這台 LiteLLM 的版本', result['blockers'][0])
        self.world.app_version = '1.104.0'
        self.world.ha_migrations = MIGRATIONS[:2]
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertTrue(any('資料庫結構版本不同' in b and '只在這台的 1 筆' in b for b in result['blockers']))
        self.world.ha_migrations = list(MIGRATIONS)
        result = self.check(self.upload_litellm(pg_version=b'17\n'), ['litellm'])[0]
        self.assertTrue(any('不是預期的 PostgreSQL 18' in b for b in result['blockers']))

    def test_the_salt_must_be_the_databases(self):
        self.world.db_salt = OTHER_SALT
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertIn(ha_litellm.SALT_MISMATCH, result['blockers'])
        self.world.db_salt = SALT
        result = self.check(self.upload_litellm(salt=None), ['litellm'])[0]
        self.assertTrue(any('找不到格式正確的 LiteLLM 加密金鑰' in b for b in result['blockers']))
        result = self.check(self.upload_litellm(salt=b'short'), ['litellm'])[0]
        self.assertFalse(result['ok'])

    def test_what_the_check_refuses(self):
        self.world.objects = dict(self.world.objects, schemas=['evil', 'woow', 'woow_platform'], ha_only=['meta', 'x'],
                                  large_objects=1, encoding='SQL_ASCII')
        self.world.superuser = ['EVENT TRIGGER']
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        joined = '\n'.join(result['blockers'])
        for words in ('evil', 'woow 結構描述有不認得的物件', 'EVENT TRIGGER', '大型物件', 'UTF8'):
            self.assertIn(words, joined)
        self.world.objects = dict(self.world.objects, schemas=['woow', 'woow_platform'], ha_only=['meta'],
                                  large_objects=0, encoding='UTF8')
        self.world.superuser = []
        link = {'name': 'data/postgres/pg_tblspc/16400', 'type': 'symlink', 'linkname': '/mnt/elsewhere'}
        result = self.check(self.upload_litellm(extra=[{'name': 'data/postgres/pg_tblspc', 'type': 'dir'}, link]),
                            ['litellm'])[0]
        self.assertTrue(any('表格空間或符號連結' in b for b in result['blockers']), result['blockers'])

    def test_a_different_schema_is_a_blocker_naming_the_tables(self):
        self.world.ha_columns = COLUMNS + [['public', 'LiteLLM_UserTable', 'extra', 'integer', False, '', '']]
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertFalse(result['ok'])
        self.assertEqual([b for b in result['blockers'] if '資料庫結構不同' in b],
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
        self.assertTrue([b for b in result['blockers'] if '無法完整讀取' in b], 'an answer that is not an object refuses')
        self.answering({'sections': ['general_settings'], 'env': [], 'callbacks': []})
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertFalse([w for w in result['warnings'] if '代理設定' in w], 'only environment variables and callbacks')

    def test_settings_that_load_code_refuse(self):
        # SR-6: LiteLLM's get_instance_fn imports any dotted path (post_call_rules "builtins.exec" runs every response).
        self.world.ha_columns = COLUMNS + self.CONFIG
        for found, words in (({'sections': ['litellm_settings'], 'env': [], 'callbacks': [],
                               'hooks': ['litellm_settings.post_call_rules']}, 'litellm_settings.post_call_rules'),
                             ({'sections': ['general_settings'], 'env': [], 'callbacks': [],
                               'hooks': ['general_settings.custom_auth']}, 'general_settings.custom_auth'),
                             ({'sections': ['litellm_settings'], 'env': [], 'hooks': [],
                               'callbacks': ['langfuse', 'custom_callbacks.proxy_handler_instance']},
                              'custom_callbacks.proxy_handler_instance')):
            self.answering(found)
            result = self.check(self.upload_litellm(), ['litellm'])[0]
            hooks = [b for b in result['blockers'] if '會載入並執行程式的設定' in b]
            self.assertEqual(len(hooks), 1, result['blockers'])
            self.assertIn(words, hooks[0])
        self.assertTrue(any('langfuse' in w for w in result['warnings']), 'a named integration stays a warning')
        self.assertFalse(any('custom_callbacks' in w for w in result['warnings']))
        self.answering({'sections': ['litellm_settings'], 'env': [], 'callbacks': ['langfuse'], 'hooks': []})
        result = self.check(self.upload_litellm(), ['litellm'])[0]
        self.assertFalse([b for b in result['blockers'] if '會載入並執行程式的設定' in b])
        self.assertIn("('litellm_settings', 'post_call_rules')", ha_litellm.STORED_SETTINGS_SQL)

    def test_settings_that_load_code_stop_the_conversion_before_anything_is_read(self):
        self.world.ha_columns = COLUMNS + self.CONFIG
        self.answering({'sections': ['litellm_settings'], 'env': [], 'callbacks': [],
                        'hooks': ['litellm_settings.post_call_rules']})
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertIn('會載入並執行程式的設定', caught.exception.message)
        self.assertFalse(self.world.copies_out, "no HA row was read")
        self.assertFalse(self.world.snapshots, "this device's schema was not captured")
        self.assertFalse(self.world.copies_in)

    def raising(self, code):
        answer, self.asked = self.world.answer, []

        def stored(role, sql, database):
            if sql == ha_litellm.STORED_SETTINGS_SQL:
                self.asked.append(role)
                raise BackupError(code, 'psql: output over the limit or timed out')
            return answer(role, sql, database)

        self.world.answer = stored

    def test_an_answer_that_cannot_be_read_refuses(self):
        # Review iteration 2: stored_settings() returned None on any read error, so ~1M stored environment-variable
        # names (over the 16 MiB answer limit; HA's non-superuser owner can store them) or a timeout hid a hook.
        self.world.ha_columns = COLUMNS + self.CONFIG
        for code in ('limit-exceeded', 'job-failed'):
            self.raising(code)
            result = self.check(self.upload_litellm(), ['litellm'])[0]
            self.assertEqual(self.asked, ['hapg'])
            self.assertTrue([b for b in result['blockers'] if '無法完整讀取' in b], (code, result['blockers']))
            with self.assertRaises(BackupError) as caught:
                self.convert(self.upload_litellm(), ['litellm'])
            self.assertIn('無法完整讀取', caught.exception.message)
            self.assertFalse(self.world.copies_out, 'no HA row was read')

    def test_every_vendor_code_place_refuses(self):
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
        for label in labels + ['litellm_settings.callbacks', 'litellm_settings.success_callback']:
            self.answering({'sections': [label.split('.')[0]], 'env': [], 'callbacks': [], 'hooks': [],
                            'nested': [label]})
            result = self.check(self.upload_litellm(), ['litellm'])[0]
            hooks = [b for b in result['blockers'] if '會載入並執行程式的設定' in b]
            self.assertEqual(len(hooks), 1, (label, result['blockers']))
            self.assertIn(label, hooks[0])

    def both_sides(self, ha_value, new_value):
        """HA's cluster answers ha_value, the new cluster new_value (both schemas hold LiteLLM_Config)."""
        self.world.ha_columns = COLUMNS + self.CONFIG
        self.world.live_columns = COLUMNS + self.CONFIG
        self.world.counts['public.LiteLLM_Config'] = 2
        answer, self.asked = self.world.answer, []

        def stored(role, sql, database):
            if sql == ha_litellm.STORED_SETTINGS_SQL:
                self.asked.append(role)
                return copy.deepcopy(ha_value if role == 'hapg' else new_value)
            return answer(role, sql, database)

        self.world.answer = stored

    def test_the_conversion_decides_again_on_what_moved(self):
        # Review SR-8: a crafted data directory controls HA's catalog; an edited built-in =(text,text) operator hid
        # post_call_rules and custom_auth from the HA-side query while COPY moved them (sandbox t2_hidden_hooks).
        # The same query in the new cluster (this device's image and schema, HA's data as rows) must refuse.
        clean = {'sections': ['litellm_settings'], 'env': [], 'callbacks': [], 'hooks': [], 'nested': []}
        for new_value, words in (({'sections': ['litellm_settings'], 'env': [], 'callbacks': [],
                                   'hooks': ['litellm_settings.post_call_rules'], 'nested': []},
                                  '會載入並執行程式的設定'),
                                 ({'sections': ['router_settings'], 'env': [], 'callbacks': [], 'hooks': [],
                                   'nested': ['router_settings.plugins']}, 'router_settings.plugins'),
                                 (None, '無法完整讀取')):
            self.both_sides(clean, new_value)
            with self.assertRaises(BackupError) as caught:
                self.convert(self.upload_litellm(), ['litellm'])
            self.assertIn(words, caught.exception.message)
            self.assertEqual(self.asked, ['hapg', 'll-db'], 'asked in HA\'s cluster, then in the new one')
            full_reads = [r for r in self.world.restores if r[0] == 'll-db' and '/dev/null' in r[1]]
            self.assertFalse(full_reads, 'stopped before the converted database was written')

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
        self.assertEqual([d for *_x, d in self.world.copies_in], [f'rows of "{s}"."{t}"\n'.encode() for s, t in TABLES])
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

    def test_ddl_during_the_capture_stops(self):
        def change(world):
            world.live_signature = dict(world.live_signature, indexes=[['public', 'x', 'y', 'CREATE INDEX y']])
        self.world.after_capture = change
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(caught.exception.message, ha_litellm.SCHEMA_CHANGED)
        self.assert_nothing_loaded()

    def test_snapshot_columns_must_be_the_live_ones(self):
        self.world.snapshot_columns = COLUMNS[:-1]
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(caught.exception.message, ha_litellm.SCHEMA_CHANGED)
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

    def test_names_that_are_not_plain_identifiers_refuse(self):
        odd = [['public', 'Odd"Table', 'id', 'text', True, '', '']]
        sig = dict(signature(), relations=signature()['relations'] + [['public', 'Odd"Table', 'r', 'p', False, False,
                                                                          '', False]])
        self.world.ha_columns = self.world.live_columns = COLUMNS + odd
        self.world.ha_signature = self.world.live_signature = sig
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertIn('1 個資料表、欄位或序號的名稱不是這個匯入支援的格式', caught.exception.message)
        self.assertFalse(self.world.copies_out, 'refused before any HA row is read')
        self.assert_nothing_loaded()

    def test_a_live_database_with_other_schemas_is_not_captured(self):
        self.world.live_signature = dict(signature(), schemas=['extra', 'woow_platform'])
        self.world.ha_signature = signature()
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertIn('LiteLLM 不會建立的結構描述', caught.exception.message)
        self.assertFalse(self.world.snapshots, 'nothing captured')
        self.assert_nothing_loaded()

    def test_the_pg18_image_is_the_pinned_one_by_content(self):
        self.world.images = set()
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_litellm(), ['litellm'])
        self.assertIn('不是預期的版本', caught.exception.message)
        self.assertEqual(self.world.pulls, [ha_litellm.PG18_PINNED])
        self.assertFalse(self.runs('hapg'))
        self.world.pull_gives = ha_litellm.PG18_IDS[1]
        result = self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(result['ha_import']['apps'], ['litellm'])
        self.assertEqual(self.runs('hapg')[0][1], ha_litellm.PG18_IDS[1])

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

    def test_n01_a_version_the_check_refuses_never_converts(self):
        for upload, live, words in (({'version': '0.1.14'}, '1.104.0', '還不認得'),
                                    ({}, '1.105.0', '版本不同：HA 的 LiteLLM 是 1.104.0'),
                                    ({}, None, '無法讀取這台 LiteLLM 的版本')):
            self.world.app_version = live
            with self.subTest(words=words):
                error = self.refused(words, **upload)
                self.assertTrue(error.message.startswith('LiteLLM 不能搬過來：'), error.message)
                self.assertNotIn('hapg', self.world.imported, "HA's cluster was not read")
                self.assertFalse(self.world.runs, 'no throwaway container ran')
                self.assertFalse(self.world.copies_out or self.world.copies_in or self.world.snapshots)

    def test_n09_the_new_cluster_must_be_this_devices_major(self):
        for major in (16, 18, '17', 17.0, None, True):
            self.world.new_major = major
            with self.subTest(major=major):
                self.refused('新的 PostgreSQL 叢集版本和這台的不同', 'job-failed')
        self.world.new_major = 17
        self.assertTrue(self.convert(self.upload_litellm(), ['litellm'])['backup_id'])

    def test_n10_an_empty_dump_is_not_a_backup(self):
        self.world.new_dump = b''
        self.refused('LiteLLM 轉換後的資料庫匯出結果為空', 'job-failed')
        self.assertFalse([cmd for _role, cmd, _d in self.world.restores if '/dev/null' in cmd], 'stopped at once')

    def test_n11_has_cluster_must_open_as_postgresql_18(self):
        for major in (17, 19, None):
            self.world.ha_major = major
            with self.subTest(major=major):
                self.assertEqual(self.blockers(), ['暫用的 PostgreSQL 18 版本不符，已停止，這台的應用沒有任何變更。'])
                self.refused('暫用的 PostgreSQL 18 版本不符', 'job-failed')
        self.assertFalse(self.world.copies_out, "nothing of HA's database was read")

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
        second = {'name': 'data/secrets/salt_key', 'data': OTHER_SALT + b'\n', 'mode': 0o600}
        with self.assertRaises(BackupError):
            self.check(self.upload_litellm(extra=[second]), ['litellm'])

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
            if role == 'hapg' and isinstance(found, dict) and 'public.LiteLLM_UserTable' in found:
                return {key: value for key, value in found.items() if key != 'public.LiteLLM_UserTable'}
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
        return (('cold draft', {'postgres': [], 'volumes': [volume]}), ('extra volume', {'volumes': [volume]}),
                ('host directory', {'data_dirs': [{'path': '.local/share/litellm', 'label': ''}]}),
                ('two databases', {'postgres': [item, dict(item, id='db2')]}),
                ('whole instance', {'postgres': [dict(instance, scope='instance')]}))

    def test_n21_only_the_single_database_entry_is_filled(self):
        original = vars(self.catalog['litellm']).copy()
        for name, fields in self.shapes():
            vars(self.catalog['litellm']).update(original, **fields)
            with self.subTest(name):
                self.assertEqual(self.blockers(), [ha_litellm.TARGET_SHAPE])
                self.assertEqual(self.refused('單一資料庫').message, ha_litellm.TARGET_SHAPE)
        self.assertFalse(self.world.runs, 'refused before anything ran')
        for words in ('「單一資料庫」', '冷備份與整個執行個體都不能匯入', '「應用設定」', '無法以新設定還原'):
            self.assertIn(words, ha_litellm.TARGET_SHAPE, 'what the owner has to choose, where, and what it costs')
        vars(self.catalog['litellm']).update(original)
        self.catalog['litellm'].postgres = [dict(original['postgres'][0], scope='database')]
        self.assertEqual(self.blockers(), [], 'the single-database entry, scope written or not')
        self.world.quadlets['litellm'] = {k: v for k, v in QUADLETS.items() if k != 'litellm.container'}
        self.assertEqual(self.blockers(), ['這台的 LiteLLM 應用設定不是 HA 匯入支援的樣子：找不到 litellm-postgres 或 litellm 的 '
                                           'Quadlet 檔。'])

    def test_n28_has_database_must_have_the_platform_schema(self):
        self.world.objects = dict(self.world.objects, schemas=['woow'])
        self.assertEqual(self.blockers(), ['HA 的 LiteLLM 資料庫的結構描述不是 LiteLLM 會建立的（缺少 woow_platform），無法安全地搬過來。'])
        self.refused('缺少 woow_platform')
        self.assertFalse(self.world.copies_out)

    def test_n29_this_devices_postgresql_must_be_known_and_supported(self):
        for major, shown in (('', '未知'), ('12', '12'), ('19', '19'), ('x', '未知')):
            self.world.image_major = major
            with self.subTest(major=major):
                words = f'無法確認這台 LiteLLM 的 PostgreSQL 版本（{shown}）。'
                self.assertEqual(self.blockers(), [words])
                self.refused(words)
        self.assertFalse(self.world.copies_out)
        for major in ('13', '17', '18'):
            self.world.image_major = major
            self.assertEqual(self.blockers(), [], major)

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
            if args[0] == 'exec' and args[-1].startswith('COPY ') and args[-1].endswith(' FROM STDIN'):
                seen.append(len(staged))
                modes.update(stat.S_IMODE(path.stat().st_mode) for path in staged)
            elif args[0] == 'exec' and 'pg_dump' in args:
                after.append(len(staged))

        self.watch_podman(watch)
        self.convert(self.upload_litellm(), ['litellm'])
        self.assertEqual(seen, list(range(len(TABLES), 0, -1)), "each table's rows are deleted once they are loaded")
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

    def test_r01_a_state_file_of_another_version_never_converts(self):
        error = self.refused('最後由 LiteLLM 1.103.0 遷移', state='1.103.0')
        self.assertTrue(error.message.startswith('LiteLLM 不能搬過來：'), error.message)
        self.assertFalse(self.world.copies_out or self.world.snapshots or self.runs('ll-db'))

    def test_r02_another_add_ons_member_is_not_litellm(self):
        for addon in (None, types.SimpleNamespace(slug='woow-litellm-mcp'), types.SimpleNamespace(slug='')):
            report = types.SimpleNamespace(addon=addon, skipped_symlinks=0)
            with self.subTest(addon=addon), mock.patch.object(ha_litellm.habackup, 'iter_entries', return_value=iter([])):
                with self.assertRaises(BackupError) as caught:
                    ha_litellm.scan_member(None, report)
            self.assertEqual((caught.exception.code, caught.exception.message),
                             ('incompatible', '備份不是可辨識的 LiteLLM 附加元件。'))

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
            with self.subTest(migrations=str(bad)[:40]):
                self.assertEqual(self.blockers(), ['無法讀取這台 LiteLLM 的資料庫結構版本（Prisma 遷移紀錄）。'])
                self.refused('資料庫結構版本不同（Prisma 遷移紀錄：')
        self.assertFalse(self.world.copies_out)

    def test_r06_r07_names_are_quoted_only_when_they_are_plain(self):
        self.assertEqual(ha_litellm.copy_out_sql('public', 'LiteLLM_UserTable', ['user_id', 'spend']),
                         'COPY "public"."LiteLLM_UserTable" ("user_id", "spend") TO STDOUT')
        for schema, name in (('public', 'a"; DROP TABLE x; --'), ('pub"lic', 'x'), ('public', ''), ('', 'x')):
            with self.subTest(name=(schema, name)), self.assertRaises(BackupError) as caught:
                ha_litellm.copy_in_sql(schema, name, ['id'])
            self.assertEqual(caught.exception.message, 'LiteLLM 的資料表名稱不是這個匯入支援的格式，無法匯入。')
        for columns in ([], ['a"b'], ['id', 'x) TO PROGRAM']):
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

    def test_r16_the_names_of_a_schema_are_bounded(self):
        def schema(tables):
            return ha_litellm.Schema([['public', t, 'id', 'text', True, '', ''] for t in tables],
                                     dict(signature(), sequences=[], relations=[['public', t, 'r'] for t in tables]), [])

        ha_litellm.require_names(schema([f't{i}' for i in range(ha_litellm.MAX_TABLES)]))
        for tables in ([f't{i}' for i in range(ha_litellm.MAX_TABLES + 1)], [], ['a"b'], ['a', 'x y']):
            with self.subTest(tables=len(tables)), self.assertRaises(BackupError) as caught:
                ha_litellm.require_names(schema(tables))
            self.assertIn('沒有讀取任何資料就停止了', caught.exception.message)

    def test_r11_no_snapshot_is_taken_for_migrations_that_are_not_known(self):
        for bad in (None, [], ["x'; DROP TABLE y; --"], [1]):
            with self.subTest(expected=bad), self.assertRaises(BackupError) as caught:
                ha_litellm.capture_schema(mock.Mock(), mock.Mock(id='litellm'), mock.Mock(), Path('/nonexistent/x'), bad)
            self.assertEqual(caught.exception.message, '目標 LiteLLM 的資料庫結構版本不明。')

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
        self.assertEqual((removed, left), (['target-schema.dump.capture'], []), 'the captured text is gone at once')
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
        self.refuses('T09c no salt secret in the proxy', self.WORDS, self.quadlet(self.PROXY, salt, b''))
        self.refuses('T10 the salt secret is not declared', self.WORDS, secrets=[n for n in SECRETS if 'salt' not in n])
        self.refuses('T11 a declared secret twice', self.WORDS, secrets=SECRETS + ['litellm-master-key'])
        missing = '這台的 LiteLLM 應用設定不是 HA 匯入支援的樣子：找不到 litellm-postgres 或 litellm 的 Quadlet 檔。'
        for name in (self.DB, self.PROXY):
            self.refuses(f'T12 without {name}', missing, {k: v for k, v in QUADLETS.items() if k != name})
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


class CandidateStillGuarded(unittest.TestCase):
    def test_the_lab_candidate_never_converts(self):
        with self.assertRaises(BackupError) as caught:
            ha_litellm_candidate.convert(mock.Mock(), mock.Mock(id='litellm'), False, mock.Mock())
        self.assertEqual(caught.exception.message, ha_litellm_candidate.GUARD)


if __name__ == '__main__':
    unittest.main()
