"""HA import, Omnigent part (ha_omnigent.py): the check and the whole conversion against a fake owner whose podman
answers like the lab's -- versions, HA's hardened cluster, the dump restored by a role without privileges, this
device's admin and runner accounts kept, test mode, the server volume with HA's artifacts and cookie key (CONTRACT
section 9). Team E2."""
import gzip
import io
import json
import re
import tarfile
import unittest
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
       b'3456; 0 16400 TABLE DATA public users omnigent\n'
       b'3500; 2606 16500 CONSTRAINT public users users_pkey omnigent\n'
       b'3600; 1259 16600 INDEX public ix_conv_title_trgm omnigent\n')


def addon_tar(*, version='0.1.23', cookie=True, extra=(), artifacts=True):
    addon = {'user': {'version': version, 'image': 'ghcr.io/woowtech/woow-ha-omnigent-amd64',
                      'options': {'admin_password': 'ha-admin-secret'}},
             'system': {'slug': 'woow-omnigent', 'name': 'Woow Omnigent'}, 'version': version}
    art = 'data/omnigent-home/.omnigent/artifacts'
    entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': json.dumps(addon).encode()},
               {'name': 'data', 'type': 'dir'}, {'name': 'data/options.json', 'data': b'{"admin_password": "x"}'},
               {'name': 'data/postgres', 'type': 'dir', 'mode': 0o700},
               {'name': 'data/postgres/PG_VERSION', 'data': b'16\n'},
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

    def run(self, role, image, command, options, data):
        if role == 'controldata':
            return Result(0, b'Database cluster state:               shut down\n', b'')
        return Result(0, b'', b'')

    def exec(self, role, command, data, stdout):
        if command[0] == 'pg_dump':
            stdout.write(b'PGDMP-' + role.encode())
            return Result(0, None, b'')
        if command[:2] == ['pg_restore', '-l']:
            return Result(0, self.toc, b'')
        if command[:2] == ['sh', '-c']:
            self.written[command[2].rsplit('> ', 1)[1]] = data
        return Result(0, b'', b'')

    def executed(self, role):
        return [statement for _db, statement, _t in self.psql[role].executed] if role in self.psql else []

    def answer(self, role, sql, database):
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

    def carried(self):
        data = self.written.get('/tmp/woowbk-omnigent-users.json')
        return json.loads(data) if data else []

    def export(self, volume):
        if volume == 'omnigent-server-data':
            return fk.tar_of([{'name': '.', 'type': 'dir', 'uid': 0, 'gid': 0},
                              {'name': 'artifacts', 'type': 'dir', 'uid': 0, 'gid': 0},
                              {'name': 'artifacts/accounts-cookie-secret', 'data': b'live-cookie', 'mode': 0o600},
                              {'name': f'artifacts/{"e" * 32}', 'type': 'dir'},
                              {'name': 'sharing_mode', 'data': b'off'}])
        if volume == 'omnigent-pi-data':
            return fk.tar_of([{'name': '.', 'type': 'dir', 'uid': 0}, {'name': 'auth.json', 'data': b'pi-login'}])
        return fk.tar_of([{'name': '.', 'type': 'dir', 'uid': 70, 'gid': 70, 'mode': 0o700},
                          {'name': 'PG_VERSION', 'data': b'16\n', 'uid': 70, 'gid': 70, 'mode': 0o600}])


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
                                   health=[{'type': 'http', 'url': 'http://127.0.0.1:8000/health'}])}

    def upload_omnigent(self, **kwargs):
        return self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', addon_tar(**kwargs))], hx.ha_doc(addons=(SLUG,))))


class CheckTests(OmnigentCase):
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

    def test_a_same_named_account_is_a_warning(self):
        self.world.ha_users = ['admin', 'alice']
        result = self.check(self.upload_omnigent(), ['omnigent'])[0]
        self.assertTrue(result['ok'])
        self.assertEqual(result['omnigent']['account_conflicts'], ['admin'])
        self.assertTrue(any('相同名稱的帳號（admin）' in w for w in result['warnings']))


class ConvertTests(OmnigentCase):
    def test_the_whole_conversion_in_test_mode(self):
        result = self.convert(self.upload_omnigent(), ['omnigent'], test_mode=True)
        imp = result['ha_import']
        self.assertEqual(imp['apps'], ['omnigent'])
        self.assertTrue(any('admin、operator' in line for line in imp['notes']), imp['notes'])
        self.assertTrue(any('runner' in line for line in imp['reminders_by_app']['omnigent']))
        self.assertTrue(any('暫停 1 個排程' in line for line in imp['reminders_by_app']['omnigent']))
        self.assertFalse(any('MCP 管理' in line for line in imp['reminders_by_app']['omnigent']), 'no admin app here')
        # The new cluster: the live image, environment and secret; restored by a role without privileges.
        new = self.runs('omni-db')[0]
        self.assertEqual(new[1], 'docker.io/library/postgres:16.15-alpine3.24')
        self.assertIn('POSTGRES_USER=omnigent', new[3]['--env'])
        self.assertEqual(new[3]['--secret'], ['omnigent-postgres-password,type=mount,target=/run/secrets/postgres-password,'
                                              'mode=0400'])
        restore = next(cmd for role, cmd, _d in self.world.execs if role == 'omni-db' and cmd[0] == 'pg_restore'
                       and '-U' in cmd)
        self.assertEqual(restore[restore.index('-U') + 1], ha_omnigent.RESTORE_ROLE)
        self.assertIn('--no-owner', restore)
        statements = self.world.executed('omni-db')
        self.assertTrue(any(s.startswith('CREATE ROLE woowbk_restore LOGIN NOSUPERUSER') for s in statements))
        self.assertTrue(any(s.startswith('REASSIGN OWNED BY woowbk_restore TO "omnigent"') for s in statements))
        self.assertIn('DROP ROLE woowbk_restore', statements)
        self.assertIn(PAUSE, statements)
        self.assertNotIn(HASH, '\n'.join(statements), 'the hashes travel in a file, never in a statement')
        toc = self.world.written['/tmp/woowbk-omnigent.toc'].decode()
        self.assertNotIn('EXTENSION', toc)
        self.assertEqual([row['id'] for row in self.world.carried()], ['admin', 'operator'])
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
        self.assertTrue(self.reporter.logs)
        self.assertNotIn(HASH, jobs.redact(f'x {HASH} y'), 'masked as soon as it was read')

    def test_a_same_named_ha_account_wins(self):
        self.world.ha_users = ['admin', 'alice']
        result = self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual([row['id'] for row in self.world.carried()], ['operator'])
        self.assertTrue(any('HA 也有帳號 admin' in line for line in result['ha_import']['notes']))
        self.assertNotIn(PAUSE, self.world.executed('omni-db'), 'not a test import')

    def test_a_dump_with_code_is_refused_before_the_restore(self):
        self.world.toc = TOC + b'3700; 1255 16700 FUNCTION public evil() omnigent\n'
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('FUNCTION', caught.exception.message)
        self.assertFalse([cmd for role, cmd, _d in self.world.execs if role == 'omni-db' and cmd[0] == 'pg_restore'
                          and '-U' in cmd])
        self.assertEqual(self.storage.list_backups(), [])

    def test_counts_that_differ_stop_the_conversion(self):
        real = self.world.answer

        def answer(role, sql, database):
            value = real(role, sql, database)
            if role == 'omni-db' and isinstance(value, dict) and 'conversations' in value:
                value = dict(value, conversations=0)
            return value

        self.world.answer = answer
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_omnigent(), ['omnigent'])
        self.assertIn('conversations', caught.exception.message)


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

    def test_toc_kinds(self):
        text = TOC.decode() + '3700; 1255 16700 FUNCTION public evil() omnigent\n9; 1 2 WEIRD thing\n'
        kinds = ha_omnigent.toc_kinds(text)
        self.assertIn('TABLE DATA', kinds)
        self.assertIn('COMMENT', kinds)
        self.assertIn('FUNCTION', kinds)
        self.assertIn('UNKNOWN WEIRD', kinds)


if __name__ == '__main__':
    unittest.main()
