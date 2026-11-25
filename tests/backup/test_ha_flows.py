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
SKIP |= {'--tmpfs'}  # tempctr: a read-only root with a secret file gets a tmpfs at /run/secrets (98410bd)
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
        self.container_files = hafakes.ContainerFiles()   # what Cluster.write_file's writes received
        self.limits = []                                  # (argv, timeout, max_output) of every call

    def _psql(self, container):
        if container not in self.psql:
            self.psql[container] = hafakes.Psql(lambda sql, db, c=container: self.world.answer(c, sql, db))
        return self.psql[container]

    def podman(self, *args, input=None, stdout=None, timeout=None, max_output=None, check=True, abort=None):
        self.calls.append(args)
        self.limits.append((args, timeout, max_output))
        data = input.read() if hasattr(input, 'read') else input
        result = self.dispatch(args, data, stdout)
        if check and result.returncode != 0:
            from woowbackup.podman import CommandError
            raise CommandError(f'podman {args[0]} 執行失敗（結束碼 {result.returncode}）。', returncode=result.returncode,
                               stderr=result.stderr)
        return result

    def systemctl(self, *args, timeout=None, max_output=None, abort=None, check=True):
        self.calls.append(('systemctl', *args))
        if args[0] == 'start':
            self.world.live_db_stopped = False
        return Result(0, b'', b'')

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
            i, env = 1, {}
            while args[i].startswith('--'):
                if args[i] == '--env':
                    key, _eq, value = args[i + 1].partition('=')
                    env[key] = value
                i += 2 if args[i] in ('--user', '--workdir', '--env') else 1
            container, command = args[i], list(args[i + 1:])
            self.world.exec_env.append((container, command, env))
            if container == 'odoo18-db' and self.world.live_db_stopped:
                return Result(125, b'', b'Error: no container with name or ID "odoo18-db" found: no such container')
            if command[0] == 'psql':
                # the double reads the database from `-d`; the real command carries it in PGDATABASE (OD-31)
                return self._psql(container)(command + (['-d', env['PGDATABASE']] if 'PGDATABASE' in env else []), data)
            answer = self.container_files.read_back(container, command)
            if answer is not None:
                return answer
            return self.container_files.wrote(container, command, data, self.world.exec(container, command, data, stdout))
        if verb == 'image' and args[1] == 'exists':
            return Result(0 if args[2] in self.world.images else 1, b'', b'')
        if verb == 'image' and args[1] == 'inspect':
            present = args[-1] in self.world.images
            return Result(0 if present else 1, b'sha256:' + b'c' * 64 + b'\n' if present else b'', b'' if present else b'no such image')
        if verb == 'pull':
            self.world.pulls.append(args[-1])
            if self.world.pull_works:
                self.world.images.add(args[-1])
                return Result(0, b'', b'')
            return Result(125, b'', b'Error: unable to pull: connection refused')
        if verb == 'container' and args[1] == 'inspect':
            fmt = args[3]
            stopped = args[-1] == 'odoo18-db' and self.world.live_db_stopped
            return Result(0, b'0\n' if 'ExitCode' in fmt else b'false\n' if stopped else b'true\n', b'')
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
            return {'id': WEB_ID, 'env': [f'ODOO_RELEASE={self.world.web_release}'] if self.world.web_release else []}
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
        self.db_image = 'jcr-prod.woowtech.io/woow-paas-docker-local/paas-postgres:17.11-20260928.1549@sha256:7a47'
        self.images = {'docker.io/library/postgres:16.15-alpine', self.web_image, self.db_image}
        self.quadlets = {'odoo': QUADLETS, 'n8n': N8N_QUADLETS}
        self.imported, self.manifests, self.runs, self.execs = {}, {}, [], []
        self.live_settings = [['work_mem', '8192', 'configuration file', 'user'],
                              ['search_path', '"$user", public', 'configuration file', 'user']]
        self.ha_modules = [['base', '18.0.1.3', 'installed'], ['woow_import_probe', '18.0.1.0.0', 'installed']]
        self.domains_cleared = False
        self.toc_extra = b''
        self.exec_env, self.pulls, self.pull_works = [], [], True
        self.conf = {'db_name': 'odoo', 'db_user': 'odoo', 'db_password': 'conf-secret-Pw-0123456789'}
        self.live_table = True
        self.live_base_url = 'https://cockpit.example'
        self.live_marker = MARKER
        self.live_role = {'password': VERIFIER, 'super': False, 'login': True, 'createdb': False, 'createrole': False,
                          'replication': False, 'bypassrls': False, 'connlimit': -1}
        self.live_extensions = [['plpgsql', True], ['pg_trgm', True], ['unaccent', True], ['vector', True],
                                ['pgcrypto', True], ['dblink', False]]
        self.ha_extensions = [['plpgsql', '1.0'], ['pg_trgm', '1.6']]
        self.ha_databases = [['woowtest', 9000000, 'C', 'C']]
        self.scan_broken = []
        self.live_db_stopped = False
        self.superuser_kinds = []
        self.not_odoo = set()          # HA databases that are no Odoo databases
        self.unreadable = {}           # HA database -> what its DETAIL_SQL read does: 'raise' | 'junk' | 'modules'
        self.verify_base_url = 'https://cockpit.example'
        self.verify_domains = None     # None: what the new cluster really holds (cleared); else a list
        self.refuse_setting = None     # a setting the new cluster refuses until it is reset
        self.web_release = '18.0.20260926'
        self.n8n_tables = {}
        self.unpublished = False

    def factory(self, app, **_kwargs):
        return FakeAdapter(app, self)

    def expected_marker(self, container):
        """The upgrade marker the settings SQL of the new cluster wrote (what VERIFY_SQL then reads back)."""
        for _db, statement, _tx in self.owner.psql[container].executed:
            if "'woow_paas_platform.upgrade_done'" in statement and statement.startswith('INSERT'):
                return statement.split("'woow_paas_platform.upgrade_done', '", 1)[1].split("', 1,", 1)[0]
        return None

    # ---------------------------------------------------------- containers
    def run(self, name, image, args, argv, data):
        role = re.sub(r'^woowbk-j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}-', '', name)
        self.runs.append((role, image, args, argv))
        if args[:1] == ['-c'] and 'id -u' in args[1]:
            user = args[1].split()[2]
            return Result(0, {'postgres': b'70\n70\n', 'odoo': b'100\n101\n', 'node': b'1000\n1000\n'}[user], b'')
        if role == 'conf':
            return Result(0, json.dumps(self.conf).encode(), b'')
        if role == 'scan':
            modules = [['base', '18.0.1.3', True, '/usr/lib/python3/dist-packages/odoo/addons'],
                       ['live_mod', '18.0.1.0.0', True, '/mnt/extra-addons']]
            doc = {'version': '18.0-20260926', 'paths': [], 'modules': modules, 'python': {'lxml': True},
                   'bin': {'wkhtmltopdf': True}, 'broken': self.scan_broken}
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
            lines = [b'2; 3079 16385 EXTENSION - pg_trgm ', b'3456; 1259 16400 TABLE public res_partner odoo',
                     b'3457; 0 16400 TABLE DATA public res_partner odoo', *self.toc_extra.splitlines()]
            return Result(0, hx.toc_listing(lines), b'')
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
            if sql == ha_odoo.LIVE_TABLE_SQL:
                return self.live_table
            if sql == ha_odoo.LIVE_SQL:
                return {'base_url': self.live_base_url, 'freeze': 'True', 'marker': self.live_marker}
            if 'FROM pg_authid' in sql:
                return self.live_role
            if sql == ha_odoo.AVAILABLE_EXTENSIONS_SQL:
                return self.live_extensions
            if sql == ha_odoo.SETTINGS_SQL:
                return self.live_settings
        if role == 'hapg':
            if sql == ha_odoo.DATABASES_SQL:
                return self.ha_databases
            if sql == ha_odoo.IS_ODOO_SQL:
                return [False] * 7 if database in self.not_odoo else [True] * 7
            if sql == ha_odoo.DETAIL_SQL:
                kind = self.unreadable.get(database)
                if kind == 'raise':
                    raise BackupError('job-failed', 'psql 執行失敗')
                if kind == 'junk':
                    return ['not a document']
                modules = [['bad-name', '1', 'installed']] if kind == 'modules' else self.ha_modules
                return {'modules': modules, 'partners': 5, 'users': 2, 'attachments': 1,
                        'attachment_bytes': 10, 'crons_active': 1, 'mail_servers_active': 0, 'size': 9000000,
                        'extensions': self.ha_extensions, 'base_url': 'https://ha.local'}
            if sql == ha_odoo.SUPERUSER_SQL:
                return self.superuser_kinds
            if sql == ha_odoo.HAS_WEBSITE_SQL:
                return True
            if sql == ha_odoo.WEBSITE_DOMAINS_SQL:
                return ['https://shop.ha.example']
            if 'database.uuid' in sql:
                return 'uuid-ha'
        if role == 'odoo-db':
            if sql == ha_odoo.VERIFY_SQL:
                return {'modules': self.ha_modules, 'partners': 5, 'attachments': 1, 'marker': self.expected_marker(container),
                        'attempt': 0, 'base_url': self.verify_base_url, 'uuid': 'uuid-new'}
            if sql == ha_odoo.HAS_WEBSITE_SQL:
                return True
            if sql == ha_odoo.WEBSITE_DOMAINS_SQL:
                if self.verify_domains is not None:
                    return self.verify_domains
                cleared = any('UPDATE website SET domain = NULL' in s for _db, s, _t in self.owner.psql[container].executed)
                return [] if cleared else ['https://shop.ha.example']
            if sql == ha_odoo.SETTINGS_SQL:
                return []
            if sql == ha_odoo.FILE_SETTINGS_SQL:
                psql = self.owner.psql[container]
                reset = any(s.startswith('ALTER SYSTEM RESET') for _db, s, _t in psql.executed)
                return [[name, value, 'invalid value' if name == self.refuse_setting and not reset else '']
                        for name, value in psql.auto_conf.items()]
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

    def test_objects_only_a_superuser_can_create_are_left_out_after_the_customer_confirmed_them(self):
        """OD-41, OD-58: the check names the kinds, the conversion needs exactly those confirmed, then restores the rest;
        unconfirmed it stops only Odoo and keeps nothing."""
        self.world.superuser_kinds = ['EVENT TRIGGER']
        self.world.toc_extra = b'3500; 3466 16500 EVENT TRIGGER - grab postgres'
        ha_id = self.upload_odoo()
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['odoo'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertEqual([i.id for i in caught.exception.issues], ['odoo.superuser-objects'])
        self.assertEqual(self.storage.list_backups(), [])
        self.assertEqual(haimport.load_registry(self.paths), {})
        removed = {call[-1] for call in self.world.owner.calls if call[:2] == ('volume', 'rm')}
        created = {call[-1] for call in self.world.owner.calls if call[:2] == ('volume', 'create')}
        self.assertEqual(created - removed, set(), 'every throwaway volume removed')
        key = caught.exception.issues[0].key('odoo')
        result = self.convert(ha_id, ['odoo'], acknowledged={'odoo': [key]})
        self.assertEqual(result['apps'], ['odoo'])
        written = next(data for (_c, path), data in self.world.owner.container_files.files.items()
                       if path == '/tmp/woowbk-odoo.toc').decode()
        self.assertIn(';3500; 3466 16500 EVENT TRIGGER - grab postgres', written.splitlines())
        self.assertIn('3456; 1259 16400 TABLE public res_partner odoo', written.splitlines())

    def test_a_dump_that_lists_what_the_check_did_not_see_is_still_restored_without_it(self):
        """OD-58, the second look: the list holds a kind the SQL of the check did not report; it is left out and said."""
        self.world.toc_extra = b'3500; 3466 16500 EVENT TRIGGER - grab postgres'
        result = self.convert(self.upload_odoo(), ['odoo'])
        (line,) = [i for i in result['results'][0]['issues'] if i['id'] == 'odoo.superuser-skipped']
        self.assertEqual((line['level'], line['items']), ('notice', ['EVENT TRIGGER']))

    def test_a_live_marker_of_another_image_is_written_new_by_the_engine(self):
        """OD-18: no refusal; the marker of the live image is written into the converted database, and said."""
        self.world.live_marker = MARKER.replace('b' * 64, 'd' * 64)
        result = self.convert(self.upload_odoo(), ['odoo'])
        db = next(c for c in self.world.owner.psql if c.endswith('-odoo-db'))
        marker = next(s for _d, s, _t in self.world.owner.psql[db].executed
                      if s.startswith('INSERT') and "'woow_paas_platform.upgrade_done'" in s)
        self.assertIn(WEB_ID, marker)
        self.assertIn('18.0.20260926', marker)
        self.assertNotIn('d' * 64, marker)
        self.assertIn('odoo.marker-written', [i['id'] for i in result['results'][0]['issues']])

    def test_without_a_release_date_in_the_image_no_marker_can_be_written_and_nothing_is_touched(self):
        self.world.live_marker = None
        self.world.web_release = None
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_odoo(), ['odoo'])
        self.assertEqual([i.id for i in caught.exception.issues], ['odoo.marker-unwritable'])
        self.assertEqual([run[0] for run in self.world.runs], ['conf'], 'only this device was read: before any HA work')
        self.assertEqual(self.storage.list_backups(), [])


class OdooCase(ConversionCase):
    """A conversion world with helpers for one Odoo add-on backup."""

    def upload_odoo(self, extra=()):
        return self.upload(hx.outer_bytes([(f'{hx.ODOO}.tar.gz', odoo_member(extra))], hx.ha_doc(addons=(hx.ODOO,))))

    def check(self, ha_id=None, **params):
        from woowbackup import flows
        base = {'source': 'ha', 'ha_backup_id': ha_id or self.upload_odoo(), 'apps': ['odoo'], 'key_provided': False}
        return flows.run_verify(self.ctx(), {**base, **params})['ha_check']['apps'][0]

    @staticmethod
    def issues(row, database=None, *, only=None):
        return [i for i in row['issues'] if (database is None or i.get('database') == database)
                and (only is None or i['level'] == only)]

    @staticmethod
    def ids(row, database=None):
        return {i['id']: i['level'] for i in OdooCase.issues(row, database)}

    @staticmethod
    def keys(row):
        return [i['key'] for i in row['issues'] if i['level'] == 'confirm']

    def executed(self):
        db = next(c for c in self.world.owner.psql if c.endswith('-odoo-db'))
        return [s for _d, s, _t in self.world.owner.psql[db].executed]


class OdooCheckTests(OdooCase):
    def test_the_check_reads_what_the_conversion_will_need(self):
        result = self.check(self.upload_odoo())
        self.assertTrue(result['ok'], result['blockers'])
        database = result['odoo']['databases'][0]
        self.assertIn('網站原本使用的網域會改成這台的網址。', database['warnings'])
        (line,) = [i for i in result['issues'] if i['id'] == 'odoo.website-domains']
        self.assertEqual((line['database'], line['items']), ('woowtest', ['https://shop.ha.example']))
        self.assertEqual(database['custom_modules'], [{'name': 'woow_import_probe', 'version': '18.0.1.0.0',
                                                       'from': 'data/addons'}])
        self.assertEqual(result['choices']['database'], [{'value': 'woowtest', 'label': 'woowtest', 'ok': True,
                                                          'default': True}])
        self.assertEqual(self.reporter.partial.get('temp_owners'), [])

    def test_a_live_database_that_cannot_be_read_stops_the_app_before_ha_is_read(self):
        """Review C-05: this device's side is read first; what cannot be read stops only this app, with the reason."""
        original = self.world.answer

        def answer(container, sql, database):
            if sql == ha_odoo.LIVE_SQL:
                raise BackupError('job-failed', 'psql 執行失敗')
            return original(container, sql, database)

        self.world.answer = answer
        result = self.check(self.upload_odoo())
        self.assertFalse(result['importable'])
        self.assertEqual(result['issues'][0]['id'], 'failure.job-failed')
        self.assertIn('請確認它正在執行', result['issues'][0]['message'])
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
            'set': (self.doc(modules=[['base', '18.0.1.3', 'installed']]), '轉換後的模組和 HA 的不同'),
            'counts': (self.doc(partners=4), '聯絡人或附件數量'),
            'marker': (self.doc(attempt=1), '升級標記'),
        }
        for name, (doc, words) in cases.items():
            with self.subTest(name):
                self.assertTrue(any(words in p for p in self.problems(doc)), self.problems(doc))
        self.assertTrue(any('識別碼' in p for p in self.problems(self.doc(uuid='old'), test_mode=True)))
        self.assertEqual(self.problems(self.doc(uuid='old')), [], 'a real import keeps the uuid')

    def test_what_is_only_a_reminder_does_not_fail_the_conversion(self):
        """OD-61, OD-66, OD-67: the same state as HA, another address, website domains that are still HA's."""
        for name, change in (('address', {'base_url': 'https://ha.local'}),
                             ('website', {'website_domains': ['https://shop.ha.example']})):
            with self.subTest(name):
                self.assertEqual(self.problems(self.doc(**change)), [])
        notes = ha_odoo.converted_notes(self.doc(base_url='https://ha.local', website_domains=['https://shop.ha.example']),
                                        self.details, self.live)
        self.assertEqual([n[0] for n in notes], ['odoo.url-differs', 'odoo.website-domain-kept'])
        waiting = self.doc(modules=[['base', '18.0.1.3', 'to upgrade'], ['woow_import_probe', '18.0.1.0.0', 'installed']])
        self.details['modules'] = [('base', '18.0.1.3', 'to upgrade'), ('woow_import_probe', '18.0.1.0.0', 'installed')]
        self.assertEqual(self.problems(waiting), [], 'the state HA had')
        self.assertEqual(ha_odoo.converted_notes(waiting, self.details, self.live)[0][0], 'odoo.modules-pending')
        changed = self.doc(modules=[['base', '18.0.1.3', 'to remove'], ['woow_import_probe', '18.0.1.0.0', 'installed']])
        self.assertTrue(any('和 HA 的 to upgrade 不同' in p for p in self.problems(changed)))


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
