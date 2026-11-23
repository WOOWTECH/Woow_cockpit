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
import re
import tarfile
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import ha_litellm, ha_litellm_candidate, ha_odoo, haapps, jobs
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


class LiteAdapter(fk.Adapter):
    def image_inspect(self, image):
        env = ['PG_MAJOR=17'] if 'postgres' in image else []
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
            stdout.write(b'PGDMP-' + role.encode())
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
            return {'hapg': 18, 'll-db': 17}.get(role)
        if "current_setting('server_version')" in sql:
            return '17.11 (Debian)'
        if sql == ha_litellm.COLUMNS_SQL:
            return {'litellm-postgres': self.live_columns, 'hapg': self.ha_columns}.get(role, self.ha_columns)
        if sql == ha_litellm.SIGNATURE_SQL:
            if role == 'litellm-postgres':
                self.live_reads += 1
                return self.live_signature
            if role == 'hapg':
                return self.ha_signature
            return self.restored_signature if self.restored_signature is not None else self.live_signature
        if sql == ha_litellm.MIGRATIONS_SQL:
            return self.live_migrations if role == 'litellm-postgres' else self.ha_migrations
        if role == 'll-db':
            if sql == ha_litellm.AUDIT_SQL:
                return self.audit
            if sql == ha_litellm.SALT_DIGEST_SQL:
                return [self.salt_digest or hashlib.sha256(SALT).hexdigest()]
        if role == 'hapg' and sql == ha_litellm.OBJECTS_SQL:
            return self.objects
        if role in ('hapg', 'll-db') and sql.startswith('SELECT json_build_object(') and '(SELECT count(*) FROM' in sql:
            names = re.findall(r"'([A-Za-z_]+\.[A-Za-z_]+)', \(SELECT", sql)
            if names:
                counts = self.new_counts if role == 'll-db' and self.new_counts is not None else self.counts
                return {name: counts[name] for name in names}
            keys = re.findall(r"'([a-z_]+)', \(SELECT", sql)
            return {key: {'users': 1, 'teams': 1, 'keys': 1, 'models': 24, 'credentials': 5}.get(key, 0) for key in keys}
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
            'under-home.container': b'[Container]\nImage=u\nVolume=/home/appowner/pi/:/data/pi-agent/\n'}
        self.assertEqual(ha_litellm.pi_agent_sources(quadlets, '/home/appowner/'),
                         [('volume', 'systemd-omnigent-pi'), ('path', 'agents/pi'), ('volume', 'pi-agent-data'),
                          ('path', 'pi')])


class CandidateStillGuarded(unittest.TestCase):
    def test_the_lab_candidate_never_converts(self):
        with self.assertRaises(BackupError) as caught:
            ha_litellm_candidate.convert(mock.Mock(), mock.Mock(id='litellm'), False, mock.Mock())
        self.assertEqual(caught.exception.message, ha_litellm_candidate.GUARD)


if __name__ == '__main__':
    unittest.main()
