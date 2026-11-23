"""The whole HA conversions (haimport.run_ha_convert with the real ha_odoo.convert / ha_n8n.convert, the real
TempObjects and Cluster) against a fake owner whose podman answers like the lab's (review FIXPLAN item 21: the
container steps were only covered by the lab). The psql emulator refuses what PostgreSQL refuses in a transaction
block (C-19) and the row counts refuse more than 100 function arguments (C-11). Team E2."""
import gzip
import io
import json
import re
import sqlite3
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import ha_n8n, ha_odoo, haimport, jobs, nested
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import hafakes
from . import hafixtures as hx
from .test_ha_import import FlowCase, HaWorld
from .test_ha_odoo import MANIFEST, QUADLETS, odoo_tar

WEB_ID = 'sha256:' + 'b' * 64
MARKER = json.dumps({'digest': WEB_ID, 'core_date': '18.0.20260926'}, separators=(',', ':'))
VERIFIER = 'SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy'
N8N_KEY = 'n8nFlowKey-0123456789abcdefABCDEF'
N8N_QUADLETS = {
    'n8n.container': b'[Container]\nContainerName=n8n\nImage=docker.io/n8nio/n8n:2.43.6\n'
                     b'Volume=n8n-data.volume:/home/node/.n8n\n',
    'n8n-postgres.container': b'[Container]\nContainerName=n8n-postgres\nImage=docker.io/library/postgres:16.15-alpine\n'
                              b'Environment=POSTGRES_USER=n8n\nEnvironment=POSTGRES_DB=n8n\n'
                              b'Volume=n8n-pg.volume:/var/lib/postgresql/data\n',
    'n8n-valkey.container': b'[Container]\nContainerName=n8n-valkey\nImage=docker.io/valkey/valkey:8\n'
                            b'Volume=n8n-valkey.volume:/data\n',
    'n8n-data.volume': b'[Volume]\nVolumeName=n8n_n8n_data\n',
    'n8n-pg.volume': b'[Volume]\nVolumeName=n8n_postgres_data\n',
    'n8n-valkey.volume': b'[Volume]\nVolumeName=n8n_valkey_data\n',
}
SKIP = {'--name', '--label', '--log-driver', '--network', '--security-opt', '--pids-limit', '--memory', '--cpus',
        '--user', '--workdir', '--entrypoint', '--env', '--env-file', '--volume', '--secret'}
FLAGS = {'--pull=never', '--detach', '--rm', '--interactive', '--read-only'}
IDS = (nested.IdMap('0 1013 1\n1 100000 65536\n'), nested.IdMap('0 1013 1\n1 100000 65536\n'))


def tar_of(entries):
    return hx.tar_bytes(entries)


class FakeOwner:
    """The app owner's podman, answering like the lab device: `world.answer(container, sql, database)` answers psql,
    every call is in `calls` (argv tuples)."""

    def __init__(self, world):
        self.world = world
        self.home = '/home/appowner'
        self.owner = 'appowner'
        self.uid = None
        self.calls = []
        self.psql = {}

    def _psql(self, container):
        if container not in self.psql:
            self.psql[container] = hafakes.Psql(lambda sql, db, c=container: self.world.answer(c, sql, db))
        return self.psql[container]

    def podman(self, *args, input=None, stdout=None, timeout=None, max_output=None, check=True, abort=None):
        self.calls.append(args)
        data = input.read() if hasattr(input, 'read') else input
        result = self.dispatch(args, data, stdout)
        if check and result.returncode != 0:
            from woowbackup.podman import CommandError
            raise CommandError(f'podman {args[0]} 執行失敗（結束碼 {result.returncode}）。', returncode=result.returncode)
        return result

    def dispatch(self, args, data, stdout):
        verb = args[0]
        if verb == 'run':
            i, name = 1, None
            while args[i] in FLAGS or args[i] in SKIP or args[i].startswith('--pull'):
                if args[i] == '--name':
                    name = args[i + 1]
                i += 2 if args[i] in SKIP else 1
            return self.world.run(name, args[i], list(args[i + 1:]), args, data)
        if verb == 'exec':
            i = 1
            while args[i].startswith('--'):
                i += 2 if args[i] in ('--user', '--workdir', '--env') else 1
            container, command = args[i], list(args[i + 1:])
            if command[0] == 'psql':
                return self._psql(container)(command, data)
            return self.world.exec(container, command, data, stdout)
        if verb == 'image' and args[1] == 'exists':
            return Result(0 if args[2] in self.world.images else 1, b'', b'')
        if verb == 'container' and args[1] == 'inspect':
            fmt = args[3]
            return Result(0, b'0\n' if 'ExitCode' in fmt else b'true\n', b'')
        if verb == 'volume' and args[1] == 'import':
            self.world.imported[args[2]] = data
            return Result(0, b'', b'')
        if verb == 'volume' and args[1] == 'inspect':
            return Result(0, f'{self.home}/.local/share/containers/storage/volumes/{args[-1]}/_data\n'.encode(), b'')
        if verb == 'unshare' and args[1] == 'stat':
            return Result(0, b'1000 1000 755\n', b'')
        return Result(0, b'', b'')

    def relay(self, args, *, stdout, timeout=None, max_output=None, check=True, abort=None):
        self.calls.append(('relay', *args))
        stdout.write(self.world.export(args[-1]))
        return Result(0, None, b'')

    def dir_pack(self, rel, *, stdout, timeout=None, max_output=None, abort=None):
        self.calls.append(('dir_pack', rel))
        stdout.write(tar_of([{'name': './', 'type': 'dir'}, {'name': './live_mod', 'type': 'dir'},
                             {'name': './live_mod/__manifest__.py', 'data': b"{'version': '18.0.1.0.0'}"}]))

    def read_file(self, rel, max_bytes=None):
        raise BackupError('not-found', 'x')


class FakeAdapter:
    def __init__(self, app, world):
        self.app, self.world = app, world
        self.runner = world.owner

    def probe(self):
        return {'deployed': True, 'problems': [], 'units': []}

    def owner_ids(self):
        return IDS

    def image_inspect(self, image):
        if image == self.world.web_image:
            return {'id': WEB_ID, 'env': []}
        return {'id': 'sha256:' + 'c' * 64, 'env': ['PG_MAJOR=17' if 'paas-postgres' in image else 'PG_MAJOR=16']}

    def read_quadlets(self):
        return dict(self.world.quadlets[self.app.id])

    def import_manifest(self, staging_dir, **items):
        self.world.manifests[self.app.id] = items
        self.world.volume_data = {name: Path(source).read_bytes() for name, source in (items.get('volumes') or {}).items()}
        from woowbackup.archive import Entry
        from woowbackup.adapters.quadlet_postgres import file_digest
        entries = []
        for name, source in sorted((items.get('volumes') or {}).items()):
            size, digest = file_digest(source)
            entries.append(Entry(path=f'apps/{self.app.id}/volumes/{name}.tar', source=Path(source), size=size,
                                 sha256=digest))
        return {'id': self.app.id, 'name': self.app.name, 'items': sorted(items)}, entries


class World(HaWorld):
    """What the fake podman answers: the HA cluster (hapg), the new PostgreSQL 17 (odoo-db), the live database
    (odoo18-db), n8n's throwaway PostgreSQL (n8n-pg)."""

    def __init__(self):
        super().__init__()
        self.owner = FakeOwner(self)
        self.web_image = 'localhost/woow-odoo-tenant-ha:20261101.1152-51856b0@sha256:b128'
        self.images = {'docker.io/library/postgres:16.15-alpine'}
        self.quadlets = {'odoo': QUADLETS, 'n8n': N8N_QUADLETS}
        self.imported, self.manifests, self.runs, self.execs = {}, {}, [], []
        self.live_settings = [['work_mem', '8192', 'configuration file', 'user'],
                              ['search_path', '"$user", public', 'configuration file', 'user']]
        self.ha_modules = [['base', '18.0.1.3', 'installed'], ['woow_import_probe', '18.0.1.0.0', 'installed']]
        self.domains_cleared = False
        self.toc_extra = b''
        self.n8n_tables = {}
        self.unpublished = False

    def factory(self, app, **_kwargs):
        return FakeAdapter(app, self)

    # ---------------------------------------------------------- containers
    def run(self, name, image, args, argv, data):
        role = re.sub(r'^woowbk-j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}-', '', name)
        self.runs.append((role, image, args, argv))
        if args[:1] == ['-c'] and 'id -u' in args[1]:
            user = args[1].split()[2]
            return Result(0, {'postgres': b'70\n70\n', 'odoo': b'100\n101\n', 'node': b'1000\n1000\n'}[user], b'')
        if role == 'scan':
            modules = [['base', '18.0.1.3', True, '/usr/lib/python3/dist-packages/odoo/addons'],
                       ['live_mod', '18.0.1.0.0', True, '/mnt/extra-addons']]
            doc = {'version': '18.0-20260926', 'paths': [], 'modules': modules, 'python': {'lxml': True},
                   'bin': {'wkhtmltopdf': True}}
            return Result(0, json.dumps(doc).encode(), b'')
        if role == 'controldata':
            return Result(0, b'Database cluster state:               shut down\n', b'')
        if role == 'n8n-version':
            return Result(0, b'2.43.6\n', b'')
        if role == 'n8n-import':
            self.n8n_tables = dict(self.sqlite_tables)
        if role == 'n8n-unpublish':
            self.unpublished = True
        return Result(0, b'', b'')

    def exec(self, container, command, data, stdout):
        role = re.sub(r'^woowbk-j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}-', '', container)
        self.execs.append((role, command, data))
        if command[0] == 'pg_dump':
            stdout.write(b'PGDMP-' + role.encode())
            return Result(0, None, b'')
        if command[:2] == ['pg_restore', '-l']:
            toc = (b';\n; Archive created\n;\n2; 3079 16385 EXTENSION - pg_trgm \n'
                   b'3456; 1259 16400 TABLE public res_partner odoo\n'
                   b'3457; 0 16400 TABLE DATA public res_partner odoo\n') + self.toc_extra
            return Result(0, toc, b'')
        return Result(0, b'', b'')

    def export(self, volume):
        if volume == 'odoo18-web-data':
            return tar_of([{'name': '.', 'type': 'dir', 'uid': 100, 'gid': 101},
                           {'name': 'filestore', 'type': 'dir', 'uid': 100, 'gid': 101},
                           {'name': 'filestore/odoo', 'type': 'dir', 'uid': 100, 'gid': 101},
                           {'name': 'filestore/odoo/old', 'data': b'old', 'uid': 100, 'gid': 101},
                           {'name': 'sessions', 'type': 'dir', 'uid': 100, 'gid': 101, 'mode': 0o700},
                           {'name': 'sessions/s1', 'data': b's', 'uid': 100, 'gid': 101},
                           {'name': 'addons', 'type': 'dir', 'uid': 100, 'gid': 101}])
        # the new PostgreSQL 17 cluster (owner postgres = 999 in the container)
        return tar_of([{'name': '.', 'type': 'dir', 'uid': 999, 'gid': 999, 'mode': 0o700},
                       {'name': 'PG_VERSION', 'data': b'17\n', 'uid': 999, 'gid': 999, 'mode': 0o600}])

    # ---------------------------------------------------------- SQL
    def answer(self, container, sql, database):
        role = re.sub(r'^woowbk-j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}-', '', container)
        if role == 'odoo18-db':  # the live database, read only
            if sql == ha_odoo.LIVE_SQL:
                return {'base_url': 'https://cockpit.example', 'freeze': 'True', 'marker': MARKER}
            if sql == ha_odoo.LIVE_ROLE_SQL:
                return {'password': VERIFIER, 'super': False, 'login': True, 'createdb': False, 'createrole': False,
                        'replication': False, 'bypassrls': False, 'connlimit': -1}
            if sql == ha_odoo.SETTINGS_SQL:
                return self.live_settings
        if role == 'hapg':
            if sql == ha_odoo.DATABASES_SQL:
                return [['woowtest', 9000000, 'C', 'C']]
            if sql == ha_odoo.IS_ODOO_SQL:
                return [True] * 7
            if sql == ha_odoo.DETAIL_SQL:
                return {'modules': self.ha_modules, 'partners': 5, 'users': 2, 'attachments': 1,
                        'attachment_bytes': 10, 'crons_active': 1, 'mail_servers_active': 0, 'size': 9000000,
                        'extensions': [['plpgsql', '1.0'], ['pg_trgm', '1.6']], 'base_url': 'https://ha.local'}
            if sql == ha_odoo.SUPERUSER_SQL:
                return []
            if sql == ha_odoo.HAS_WEBSITE_SQL:
                return True
            if sql == ha_odoo.WEBSITE_DOMAINS_SQL:
                return ['https://shop.ha.example']
            if 'database.uuid' in sql:
                return 'uuid-ha'
        if role == 'odoo-db':
            if sql == ha_odoo.VERIFY_SQL:
                return {'modules': self.ha_modules, 'partners': 5, 'attachments': 1, 'marker': MARKER, 'attempt': 0,
                        'base_url': 'https://cockpit.example', 'uuid': 'uuid-new'}
            if sql == ha_odoo.HAS_WEBSITE_SQL:
                return True
            if sql == ha_odoo.WEBSITE_DOMAINS_SQL:
                cleared = any('UPDATE website SET domain = NULL' in s for _db, s, _t in self.owner.psql[container].executed)
                return [] if cleared else ['https://shop.ha.example']
            if sql == ha_odoo.SETTINGS_SQL:
                return []
            if sql == ha_odoo.FILE_SETTINGS_SQL:
                return [[name, value, ''] for name, value in self.owner.psql[container].auto_conf.items()]
        if role == 'n8n-pg':
            if 'pg_tables' in sql:
                return list(self.n8n_tables)
            if sql.startswith('SELECT json_build_object('):
                if sql.count('(SELECT count(*)') * 2 > 100:
                    raise BackupError('job-failed', 'cannot pass more than 100 arguments to a function')
                return {name: self.n8n_tables[name] for name in re.findall(r"'([A-Za-z0-9_]+)', \(SELECT", sql)}
            if 'WHERE active' in sql:
                return 0 if self.unpublished else 1
            if 'server_version_num' in sql:
                return '160015'
            if 'server_version' in sql:
                return '16.15'
        return None


def odoo_member(extra=()):
    return gzip.compress(odoo_tar(extra), mtime=0)


def app(app_id, name, **fields):
    base = {'id': app_id, 'name': name, 'owner': 'appowner', 'postgres': [], 'volumes': [], 'data_dirs': []}
    base.update(fields)
    return types.SimpleNamespace(**base)


class ConversionCase(FlowCase):
    def setUp(self):
        super().setUp()
        self.world = World()
        self.deps.adapter_factory = self.world.factory
        self.catalog = {
            'odoo': app('odoo', 'Odoo 18', volumes=[{'name': 'odoo18-db-data-isolated'}, {'name': 'odoo18-web-data'}],
                        data_dirs=[{'path': '.local/share/odoo18/addons'}]),
            'n8n': app('n8n', 'n8n 工作流程', volumes=[{'name': 'n8n_n8n_data'}, {'name': 'n8n_valkey_data'}],
                       postgres=[{'id': 'main', 'container': 'n8n-postgres', 'user': 'n8n', 'database': 'n8n'}])}
        self.deps.load_catalog = lambda: self.catalog
        patcher = mock.patch.object(haimport.SpaceGuard, 'free', lambda guard: 1024 ** 4)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(jobs.unmask_secret, VERIFIER)
        self.addCleanup(jobs.unmask_secret, N8N_KEY)

    def convert(self, ha_id, apps, **params):
        base = {'source': 'ha', 'ha_backup_id': ha_id, 'apps': apps, 'odoo_database': 'woowtest' if 'odoo' in apps
                else None, 'test_mode': False, 'encrypt': True, 'key_provided': False}
        base.update(params)
        from woowbackup import flows
        return flows.run_backup(self.ctx(), base)

    def runs(self, role):
        return [run for run in self.world.runs if run[0] == role]


class OdooConversionTests(ConversionCase):
    def upload_odoo(self, extra=()):
        return self.upload(hx.outer_bytes([(f'{hx.ODOO}.tar.gz', odoo_member(extra))], hx.ha_doc(addons=(hx.ODOO,))))

    def test_the_whole_conversion_in_test_mode(self):
        result = self.convert(self.upload_odoo(), ['odoo'], test_mode=True)
        imp = result['ha_import']
        self.assertEqual(imp['apps'], ['odoo'])
        self.assertTrue(any('woow_import_probe' in line for line in imp['notes']))
        self.assertTrue(any('https://shop.ha.example' in line for line in imp['notes']), 'C-02')
        # HA's cluster: read only root, data volume noexec, every library/command setting overridden (HA-SEC-01).
        _role, image, args, argv = self.runs('hapg')[0]
        self.assertEqual(image, 'docker.io/library/postgres:16.15-alpine')
        self.assertIn('--read-only', argv)
        self.assertTrue(any(a.endswith(':/var/lib/postgresql/data:rw,noexec,nosuid,nodev') for a in argv))
        self.assertIn('shared_preload_libraries=', args)
        hapg_volume = next(data for name, data in self.world.imported.items() if name.endswith('-hapg'))
        with tarfile.open(fileobj=io.BytesIO(hapg_volume)) as tar:
            files = {m.name: tar.extractfile(m).read() if m.isfile() else None for m in tar}
        self.assertEqual(files['pg_hba.conf'], ha_odoo.PG_HBA)
        self.assertNotIn('postmaster.pid', files)
        # The dump is restored as odoo, from stdin, without EXTENSION entries.
        restore = next(cmd for role, cmd, _d in self.world.execs if cmd[0] == 'pg_restore' and '-d' in cmd)
        self.assertEqual(restore[:3], ['pg_restore', '-U', 'odoo'])
        stdin = next(d for role, cmd, d in self.world.execs if cmd is restore)
        self.assertEqual(stdin, b'PGDMP-hapg')
        db = next(c for c in self.world.owner.psql if c.endswith('-odoo-db'))
        executed = self.world.owner.psql[db].executed
        # C-19: ALTER SYSTEM outside a transaction, then reload; C-06: list setting element by element.
        alters = [(s, tx) for _db, s, tx in executed if s.startswith('ALTER SYSTEM')]
        self.assertEqual(len(alters), 2)
        self.assertFalse(any(tx for _s, tx in alters))
        self.assertIn("ALTER SYSTEM SET search_path TO '$user', 'public'", [s for s, _tx in alters])
        self.assertTrue(any('UPDATE website SET domain = NULL' in s for _db, s, _tx in executed), 'C-02')
        self.assertTrue(any('gen_random_uuid' in s for _db, s, _tx in executed), 'test mode: a new uuid')
        self.assertTrue(any("'web.base.url', 'https://cockpit.example'" in s for _db, s, _tx in executed))
        # C-12: neutralize sees the custom modules folder as it will be (a throwaway volume), not the live one.
        _r, _i, neutralize_args, neutralize_argv = self.runs('neutralize')[0]
        mounts = [neutralize_argv[i + 1] for i, a in enumerate(neutralize_argv) if a == '--volume']
        self.assertTrue(any(m.endswith('-odoo-addons:/mnt/extra-addons:ro') for m in mounts), mounts)
        self.assertFalse(any(m.startswith('/home/appowner/.local/share/odoo18/addons') for m in mounts))
        addons = next(data for name, data in self.world.imported.items() if name.endswith('-odoo-addons'))
        with tarfile.open(fileobj=io.BytesIO(addons)) as tar:
            names = set(tar.getnames())
        self.assertTrue({'./live_mod/__manifest__.py', './woow_import_probe/__manifest__.py'} <= names)
        # The archive's items and nothing left behind.
        items = self.world.manifests['odoo']
        self.assertEqual(sorted(items['volumes']), ['odoo18-db-data-isolated', 'odoo18-web-data'])
        self.assertEqual(list(items['dirs']), ['.local/share/odoo18/addons'])
        self.assertEqual(self.reporter.partial.get('temp_owners'), [])
        self.assertFalse((Path(self.paths.staging) / self.job_id).exists())

    def test_a_dump_that_needs_a_superuser_is_refused_and_nothing_is_kept(self):
        self.world.toc_extra = b'3500; 3466 16500 EVENT TRIGGER - grab postgres\n'
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_odoo(), ['odoo'])
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('EVENT TRIGGER', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])
        self.assertEqual(haimport.load_registry(self.paths), {})
        removed = {call[-1] for call in self.world.owner.calls if call[:2] == ('volume', 'rm')}
        created = {call[-1] for call in self.world.owner.calls if call[:2] == ('volume', 'create')}
        self.assertEqual(created - removed, set(), 'every throwaway volume removed')

    def test_a_live_marker_of_another_image_is_refused_before_any_work(self):
        original = self.world.answer

        def answer(container, sql, database):
            if sql == ha_odoo.LIVE_SQL:
                return {'base_url': None, 'freeze': None, 'marker': MARKER.replace('b' * 64, 'd' * 64)}
            return original(container, sql, database)

        self.world.answer = answer
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_odoo(), ['odoo'])
        self.assertIn('升級標記', caught.exception.message)
        self.assertEqual(self.world.runs, [])


class OdooCheckTests(ConversionCase):
    def check(self, ha_id):
        from woowbackup import flows
        return flows.run_verify(self.ctx(), {'source': 'ha', 'ha_backup_id': ha_id, 'apps': ['odoo'],
                                             'key_provided': False})['ha_check']['apps'][0]

    def upload_odoo(self):
        return self.upload(hx.outer_bytes([(f'{hx.ODOO}.tar.gz', odoo_member())], hx.ha_doc(addons=(hx.ODOO,))))

    def test_the_check_reads_what_the_conversion_will_need(self):
        result = self.check(self.upload_odoo())
        self.assertTrue(result['ok'], result['blockers'])
        database = result['odoo']['databases'][0]
        self.assertIn('網站原本使用的網域 https://shop.ha.example 會改成這台的網址。', database['warnings'])
        self.assertEqual(database['custom_modules'], [{'name': 'woow_import_probe', 'version': '18.0.1.0.0',
                                                       'from': 'data/addons'}])
        self.assertEqual(self.reporter.partial.get('temp_owners'), [])

    def test_the_check_refuses_what_the_conversion_would_refuse(self):
        """Review C-05: the live upgrade marker and the odoo role are checked here too."""
        original = self.world.answer

        def answer(container, sql, database):
            if sql == ha_odoo.LIVE_ROLE_SQL:
                return {'password': VERIFIER, 'super': True}
            return original(container, sql, database)

        self.world.answer = answer
        result = self.check(self.upload_odoo())
        self.assertFalse(result['ok'])
        self.assertIn('超級使用者', result['blockers'][0])
        self.assertEqual(self.runs('hapg'), [], 'refused before HA data is read')


class VerifyConvertedTests(unittest.TestCase):
    """verify_converted: what the conversion checks before it exports the new cluster."""

    def setUp(self):
        self.details = {'modules': [('base', '18.0.1.3', 'installed'), ('woow_import_probe', '18.0.1.0.0',
                                                                           'installed')], 'partners': 5,
                        'attachments': 1}
        self.target = {'modules': {'base': ('18.0.1.3', True, '/usr/lib')}}
        self.copy = {'woow_import_probe': {'manifest': {'version': '18.0.1.0.0'}}}
        self.live = {'base_url': 'https://cockpit.example', 'marker': MARKER}

    def doc(self, **fields):
        doc = {'modules': [['base', '18.0.1.3', 'installed'], ['woow_import_probe', '18.0.1.0.0', 'installed']],
               'partners': 5, 'attachments': 1, 'marker': MARKER, 'attempt': 0, 'base_url': 'https://cockpit.example',
               'uuid': 'new', 'website_domains': []}
        doc.update(fields)
        return doc

    def problems(self, doc, test_mode=False):
        return ha_odoo.verify_converted(doc, self.details, self.target, self.copy, self.live, test_mode=test_mode,
                                        old_uuid='old')

    def test_each_promise_is_checked(self):
        self.assertEqual(self.problems(self.doc()), [])
        self.assertEqual(self.problems(None), ['無法讀取轉換後的資料庫。'])
        cases = {
            'state': (self.doc(modules=[['base', '18.0.1.3', 'to upgrade'], ['woow_import_probe', '18.0.1.0.0',
                                                                             'installed']]), '狀態是 to upgrade'),
            'version': (self.doc(modules=[['base', '18.0.1.4', 'installed'], ['woow_import_probe', '18.0.1.0.0',
                                                                              'installed']]), '版本 18.0.1.4'),
            'set': (self.doc(modules=[['base', '18.0.1.3', 'installed']]), '已安裝模組和 HA 的不同'),
            'counts': (self.doc(partners=4), '聯絡人或附件數量'),
            'marker': (self.doc(attempt=1), '升級標記'),
            'address': (self.doc(base_url='https://ha.local'), '網址'),
            'website': (self.doc(website_domains=['https://shop.ha.example']), '網站的網域'),
        }
        for name, (doc, words) in cases.items():
            with self.subTest(name):
                self.assertTrue(any(words in p for p in self.problems(doc)), self.problems(doc))
        self.assertTrue(any('識別碼' in p for p in self.problems(self.doc(uuid='old'), test_mode=True)))
        self.assertEqual(self.problems(self.doc(uuid='old')), [], 'a real import keeps the uuid')


class N8nConversionTests(ConversionCase):
    def n8n_member(self, tables=60):
        folder = Path(self.root) / 'n8n-src'
        folder.mkdir()
        db = folder / 'database.sqlite'
        conn = sqlite3.connect(db)
        conn.executescript("""
            CREATE TABLE user (id TEXT, email TEXT, password TEXT, roleSlug TEXT, createdAt TEXT);
            CREATE TABLE workflow_entity (id TEXT, name TEXT, active INTEGER, nodes TEXT, isArchived INTEGER);
            CREATE TABLE migrations (id INTEGER, timestamp INTEGER, name TEXT);
            INSERT INTO user VALUES ('u1', 'ha-probe@probe.invalid', '$2a$10$hash', 'global:owner', '1');
            INSERT INTO migrations VALUES (1, 1, 'M1');
        """)
        conn.execute("INSERT INTO workflow_entity VALUES ('w1', 'ha', 1, ?, 0)",
                     (json.dumps([{'type': 'n8n-nodes-base.homeAssistant'}]),))
        for i in range(tables):
            conn.execute(f'CREATE TABLE data_table_user_{i} (id INTEGER)')
            conn.execute(f'INSERT INTO data_table_user_{i} VALUES (1)')
        conn.commit()
        conn.close()
        self.world.sqlite_tables = {'user': 1, 'workflow_entity': 1,
                                    **{f'data_table_user_{i}': 1 for i in range(tables)}}
        addon = json.dumps({'user': {'version': '2.43.6', 'image': 'ghcr.io/woowtech/woow-ha-n8n-amd64'},
                            'system': {'slug': 'woow-n8n', 'name': 'Woow n8n'}, 'version': '2.43.6'}).encode()
        entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': addon},
                   {'name': 'config', 'type': 'dir'}, {'name': 'config/.n8n', 'type': 'dir'},
                   {'name': 'config/.n8n/database.sqlite', 'data': db.read_bytes()},
                   {'name': 'config/.n8n/database.sqlite-shm', 'data': b'HA wal index'},
                   {'name': 'config/.n8n/config', 'data': json.dumps({'encryptionKey': N8N_KEY}).encode()},
                   {'name': 'config/.n8n/nodes', 'type': 'dir'},
                   {'name': 'config/.n8n/nodes/package.json', 'data': b'{"dependencies": {}}'},
                   {'name': 'config/.n8n/storage', 'type': 'dir'}]
        return gzip.compress(tar_of(entries), mtime=0)

    def test_the_whole_conversion_with_many_tables_in_test_mode(self):
        ha_id = self.upload(hx.outer_bytes([(f'{hx.N8N}.tar.gz', self.n8n_member())], hx.ha_doc(addons=(hx.N8N,))))
        result = self.convert(ha_id, ['n8n'], test_mode=True)
        imp = result['ha_import']
        self.assertEqual(imp['workflows_to_fix'][0]['name'], 'ha')
        self.assertIn('ha-probe@probe.invalid', imp['reminders_by_app']['n8n'][0])
        self.assertTrue(self.world.unpublished)
        items = self.world.manifests['n8n']
        self.assertEqual(sorted(items['volumes']), ['n8n_n8n_data', 'n8n_valkey_data'])
        self.assertEqual(items['postgres']['main']['major'], 16)
        source = next(data for name, data in self.world.imported.items() if name.endswith('-n8nsrc'))
        with tarfile.open(fileobj=io.BytesIO(source)) as tar:
            names = set(tar.getnames())
        self.assertIn('home/.n8n/database.sqlite', names)
        self.assertNotIn('home/.n8n/database.sqlite-shm', names, 'HA-SEC-02: HA wal index never used')
        with tarfile.open(fileobj=io.BytesIO(self.world.volume_data['n8n_n8n_data'])) as tar:
            key = json.loads(tar.extractfile('config').read())
        self.assertEqual(key, {'encryptionKey': N8N_KEY})
        self.assertEqual(self.reporter.partial.get('temp_owners'), [])

    def test_a_table_that_lost_rows_stops_the_conversion(self):
        ha_id = self.upload(hx.outer_bytes([(f'{hx.N8N}.tar.gz', self.n8n_member(tables=3))],
                                           hx.ha_doc(addons=(hx.N8N,))))
        original = self.world.run

        def run(name, image, args, argv, data):
            result = original(name, image, args, argv, data)
            if 'n8n-import' in name:
                self.world.n8n_tables['data_table_user_1'] = 0
            return result

        self.world.run = run
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['n8n'])
        self.assertIn('data_table_user_1', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])


if __name__ == '__main__':
    unittest.main()
