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
from .test_ha_odoo import MANIFEST, QUADLETS, elf, odoo_tar

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
        self.limits.append((('relay', *args), timeout, max_output))
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
        self.world.dir_data = {rel: Path(source).read_bytes() for rel, source in (items.get('dirs') or {}).items()}
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
        self.extensions_by_db = {}
        self.dir_data = {}
        self.extra_symlink = False
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
        if volume == 'odoo-extra-vol':
            link = [{'name': 'escape', 'type': 'symlink', 'linkname': '../../etc/passwd'}] if self.extra_symlink else []
            return tar_of([{'name': '.', 'type': 'dir'}, {'name': 'kept.txt', 'data': b'this device'}, *link])
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
                        'extensions': self.extensions_by_db.get(database, self.ha_extensions),
                        'base_url': 'https://ha.local'}
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
    def confirm_keys(row, database=None):
        return [i['key'] for i in row['issues'] if i['level'] == 'confirm' and (database is None or i.get('database') == database)]

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


class OdooTargetTests(OdooCase):
    """HAOS parity, this device's side: what the check reads is made ready instead of refused (rows OD-14 .. OD-23)."""

    def test_an_image_this_device_lacks_is_downloaded_and_said(self):
        """OD-14, OD-23."""
        self.world.images.discard(self.world.db_image)
        self.world.images.discard('docker.io/library/postgres:16.15-alpine')
        row = self.check()
        self.assertTrue(row['importable'], row['blockers'])
        self.assertEqual(sorted(self.world.pulls), sorted([self.world.db_image, ha_odoo.PG16_PINNED]))
        pulled = [i for i in row['issues'] if i['id'] == 'target.image-pulled']
        self.assertEqual(sorted(i['items'][0] for i in pulled), sorted([self.world.db_image, ha_odoo.PG16_PINNED]))
        self.assertTrue(all(i['level'] == 'auto' for i in pulled))

    def test_an_image_that_cannot_be_had_stops_only_this_app_and_nothing_is_read(self):
        """OD-14, OD-23: offline: Odoo is out of this import, with the reason; this device and HA's data stay as they are."""
        self.world.images.discard('docker.io/library/postgres:16.15-alpine')
        self.world.pull_works = False
        row = self.check()
        self.assertFalse(row['importable'])
        self.assertEqual([(i['id'], i['level']) for i in row['issues']], [('target.image-missing', 'stop')])
        self.assertIn('連不上網路', row['issues'][0]['message'])
        self.assertEqual(self.runs('hapg'), [], 'HA data was not read')
        self.world.images.discard(self.world.db_image)       # the same for this device's own database image
        row = self.check()
        self.assertEqual([i['id'] for i in row['issues']], ['target.image-missing'])
        self.assertEqual(self.reporter.partial.get('temp_owners'), [])

    def test_a_locally_built_odoo_image_that_is_gone_cannot_be_pulled_and_says_so(self):
        self.world.images.discard(self.world.web_image)
        row = self.check()
        self.assertFalse(row['importable'])
        self.assertIn('在這台自己建置的', row['issues'][0]['message'])
        self.assertEqual(self.world.pulls, [], 'a local image is never pulled')

    def test_a_stopped_live_database_is_started_read_and_put_back(self):
        """OD-15."""
        self.world.live_db_stopped = True
        row = self.check()
        self.assertTrue(row['importable'], row['blockers'])
        calls = self.world.owner.calls
        self.assertIn(('systemctl', 'start', '--', 'odoo-db.service'), calls)
        self.assertIn(('systemctl', 'stop', '--', 'odoo-db.service'), calls, 'put back when the check is over')
        self.assertIn('target.service-started', [i['id'] for i in row['issues']])

    def test_the_database_and_the_account_are_those_of_the_configuration(self):
        """OD-15, OD-20: the live database is read under the name its odoo.conf gives; the converted one gets it too."""
        self.world.conf = {'db_name': 'prod', 'db_user': 'odoo18', 'db_password': 'conf-secret-Pw-0123456789'}
        self.world.live_role = None            # no role odoo18 yet
        ha_id = self.upload_odoo()
        row = self.check(ha_id)
        self.assertTrue(row['importable'], row['blockers'])
        reads = [args for args in self.world.owner.calls if args[:2] == ('exec', 'odoo18-db')]
        self.assertTrue(reads and all('prod' in args or 'postgres' in args for args in reads))
        self.assertIn('odoo.role-created', self.ids(row))
        result = self.convert(ha_id, ['odoo'])
        executed = self.executed()
        self.assertTrue(any(s.startswith('CREATE ROLE "odoo18" LOGIN') for s in executed), executed)
        create = next(cmd for _r, cmd, _d in self.world.execs if cmd[:1] == ['createdb'])
        self.assertEqual((create[create.index('-O') + 1], create[-1]), ('odoo18', 'prod'))
        restore = next(cmd for _r, cmd, _d in self.world.execs if cmd[:1] == ['pg_restore'] and '-d' in cmd)
        self.assertEqual((restore[restore.index('-U') + 1], restore[restore.index('-d') + 1]), ('odoo18', 'prod'))
        self.assertTrue(any(db == 'prod' for psql in self.world.owner.psql.values() for db, _s, _t in psql.executed))
        self.assertEqual(result['apps'], ['odoo'])

    def test_a_role_password_that_is_no_verifier_is_set_again_from_the_configuration(self):
        """OD-21: only a SCRAM or md5 verifier is taken over; anything else (a plain text, nothing) is not."""
        for password in (None, '', 'plain-text-password', 'SCRAM-SHA-256$bad', "md5'; DROP ROLE x; --"):
            with self.subTest(password=password):
                self.world.live_role = {**self.world.live_role, 'password': password}
                row = self.check()
                self.assertEqual(self.ids(row)['odoo.role-password-reset'], 'auto')

    def test_a_password_of_the_configuration_never_reaches_a_command_line_or_a_log(self):
        """OD-20, OD-21: it is sent on stdin to psql and masked."""
        self.world.live_role = {**self.world.live_role, 'password': None}      # no usable password (OD-21)
        row = self.check()
        self.assertEqual(self.ids(row)['odoo.role-password-reset'], 'auto')
        self.convert(self.upload_odoo(), ['odoo'])
        secret = self.world.conf['db_password']
        self.assertFalse([args for args in self.world.owner.calls if any(secret in str(part) for part in args)])
        self.assertFalse([cmd for _r, cmd, _d in self.world.execs if any(secret in part for part in cmd)])
        create = [s for s in self.executed() if s.startswith('CREATE ROLE odoo')]
        self.assertEqual(len(create), 1)
        self.assertIn(f"PASSWORD '{secret}'", create[0], 'the new cluster hashes it itself')
        self.assertNotIn(secret, '\n'.join(self.reporter.logs if hasattr(self.reporter, 'logs') else []))

    def test_a_role_without_any_password_anywhere_stops_only_this_app(self):
        self.world.live_role = {**self.world.live_role, 'password': None}
        self.world.conf = {'db_name': 'odoo', 'db_user': 'odoo'}
        row = self.check()
        self.assertFalse(row['importable'])
        self.assertEqual([(i['id'], i['level']) for i in row['issues']], [('odoo.role-unusable', 'stop')])
        self.assertEqual(self.runs('hapg'), [])

    def test_a_superuser_role_becomes_an_ordinary_one(self):
        """OD-22: HA's content never runs as a superuser: the new role has none of the live role's powers."""
        self.world.live_role = {**self.world.live_role, 'super': True, 'createrole': True, 'replication': True,
                                'bypassrls': True}
        ha_id = self.upload_odoo()
        row = self.check(ha_id)
        self.assertTrue(row['importable'])
        self.assertEqual(self.ids(row)['odoo.role-normalised'], 'auto')
        self.convert(ha_id, ['odoo'])
        (create,) = [s for s in self.executed() if s.startswith('CREATE ROLE odoo')]
        self.assertTrue(create.startswith('CREATE ROLE odoo LOGIN NOSUPERUSER CREATEDB NOCREATEROLE NOREPLICATION '
                                          'NOBYPASSRLS'), create)

    def test_settings_that_cannot_be_read_get_the_defaults_and_a_reminder(self):
        """OD-16, OD-17, OD-18: no settings table: the default address, a marker written by the engine."""
        self.world.live_table = False
        ha_id = self.upload_odoo()
        row = self.check(ha_id)
        self.assertTrue(row['importable'])
        self.assertEqual({k: v for k, v in self.ids(row).items() if k.startswith('odoo.')},
                         {'odoo.settings-unreadable': 'notice', 'odoo.marker-written': 'auto',
                          'odoo.website-domains': 'notice', 'odoo.crons-active': 'notice'})
        self.convert(ha_id, ['odoo'])
        executed = self.executed()
        self.assertIn("DELETE FROM ir_config_parameter WHERE key = 'web.base.url'", '\n'.join(executed))
        self.assertTrue(any("'woow_paas_platform.upgrade_done'" in s and '"core_date":"18.0.20260926"' in s
                            for s in executed))

    def test_an_address_that_is_not_text_is_replaced_by_the_default(self):
        """OD-19."""
        self.world.live_base_url = 12345
        row = self.check()
        self.assertTrue(row['importable'])
        self.assertEqual(self.ids(row)['odoo.base-url-invalid'], 'notice')

    def test_a_mount_that_is_no_odoo_data_is_left_out_and_said(self):
        """OD-08, OD-09: a time zone file or another host path is no reason to refuse; it is never mounted anywhere."""
        quadlets = dict(QUADLETS)
        quadlets['odoo.container'] += b'Volume=/etc/localtime:/etc/localtime:ro\nVolume=%h/../elsewhere:/mnt/x:ro\n'
        quadlets['odoo-db.container'] += b'Volume=/mnt/data:/mnt/data\n'
        self.world.quadlets['odoo'] = quadlets
        ha_id = self.upload_odoo()
        row = self.check(ha_id)
        self.assertTrue(row['importable'], row['blockers'])
        (line,) = [i for i in row['issues'] if i['id'] == 'odoo.mount-skipped']
        self.assertEqual(sorted(line['items']), sorted(['odoo-db.container：/mnt/data', 'odoo.container：/mnt/x',
                                                         'odoo.container：/etc/localtime']))
        self.convert(ha_id, ['odoo'])
        mounted = [part for run in self.world.runs for part in run[3] if '/etc/localtime' in str(part) or '/mnt/data' in str(part)]
        self.assertEqual(mounted, [], 'a skipped mount is in no throwaway container')

    def test_a_database_user_with_odd_characters_is_no_longer_a_reason_to_refuse(self):
        """OD-05: the name is handed over as one argument and never put into a shell or SQL."""
        quadlets = dict(QUADLETS)
        quadlets['odoo-db.container'] = QUADLETS['odoo-db.container'].replace(
            b'Environment=POSTGRES_USER=postgres', b'Environment="POSTGRES_USER=my admin$1"')
        self.world.quadlets['odoo'] = quadlets
        row = self.check()
        self.assertTrue(row['importable'], row['blockers'])
        user = [args[args.index('-U') + 1] for args in self.world.owner.calls if args[:2] == ('exec', 'odoo18-db')]
        self.assertTrue(user and set(user) == {'my admin$1'})


def module_entries(name, manifest, *, extra=()):
    """The tar entries of a custom module of the HA add-on (data/addons/<name>)."""
    return [{'name': f'data/addons/{name}', 'type': 'dir'},
            {'name': f'data/addons/{name}/__manifest__.py', 'data': manifest},
            {'name': f'data/addons/{name}/__init__.py', 'data': b''}, *extra]


def manifest_of(*, python=(), binaries=(), installable=True, version='18.0.1.0.0'):
    return (f"{{'name': 'M', 'version': '{version}', 'depends': ['base'], 'installable': {installable!r}, "
            f"'external_dependencies': {{'python': {list(python)!r}, 'bin': {list(binaries)!r}}}}}").encode()


class OdooDatabaseTests(OdooCase):
    """HAOS parity, HA's side: every database has its own verdict (rows OD-31 .. OD-50, UI-20)."""

    def several(self):
        self.world.ha_databases = [['woowtest', 9000000, 'C', 'C'], ['notodoo', 10, 'C', 'C'],
                                   ['broken', 10, 'C', 'C'], ['junkmods', 10, 'C', 'C'], ['ha prod=1$', 9000000, 'C', 'C']]
        self.world.not_odoo = {'notodoo'}
        self.world.unreadable = {'broken': 'raise', 'junkmods': 'modules'}

    def test_a_database_that_cannot_be_read_stops_only_itself(self):
        """OD-32, OD-33, OD-34: not an Odoo database, a module list nobody can read, a content query that fails."""
        self.several()
        row = self.check()
        self.assertTrue(row['importable'])
        self.assertEqual(self.ids(row, 'notodoo'), {'odoo.not-odoo': 'stop'})
        self.assertEqual(self.ids(row, 'broken'), {'odoo.db-unreadable': 'stop'})
        self.assertEqual(self.ids(row, 'junkmods'), {'odoo.db-unreadable': 'stop'})
        self.assertIn('模組清單', self.issues(row, 'junkmods')[0]['message'])
        self.assertIn('資料庫的內容', self.issues(row, 'broken')[0]['message'])
        self.assertEqual({row_['value']: row_['ok'] for row_ in row['choices']['database']},
                         {'woowtest': True, 'notodoo': False, 'broken': False, 'junkmods': False, 'ha prod=1$': True})
        databases = {db['name']: db for db in row['odoo']['databases']}
        self.assertEqual((databases['woowtest']['ok'], databases['notodoo']['ok']), (True, False))
        self.assertEqual(databases['notodoo']['blockers'], [ha_odoo.MSG_NOT_ODOO])
        self.assertEqual(self.world.runs and sum(1 for run in self.world.runs if run[0] == 'hapg'), 1, 'one server for all')

    def test_there_is_no_database_or_none_that_can_move(self):
        """OD-47, OD-48: only the app stops."""
        self.world.ha_databases = []
        row = self.check()
        self.assertFalse(row['importable'])
        self.assertEqual([(i['id'], i['level']) for i in row['issues']], [('odoo.no-database', 'stop')])
        self.world.ha_databases = [['notodoo', 10, 'C', 'C']]
        self.world.not_odoo = {'notodoo'}
        row = self.check()
        self.assertFalse(row['importable'])
        self.assertEqual({i['id'] for i in row['issues'] if i['level'] == 'stop'}, {'odoo.not-odoo', 'odoo.no-movable-database'})

    def test_a_database_name_is_handed_to_the_tools_through_pgdatabase_never_on_a_command_line(self):
        """OD-31: spaces, `=`, `$`, any text; `psql -d` would read `a=b` as a connection string."""
        self.several()
        name = 'ha prod=1$'
        ha_id = self.upload_odoo()
        row = self.check(ha_id)
        self.assertEqual(self.ids(row, name).get('odoo.not-odoo'), None)
        result = self.convert(ha_id, ['odoo'], odoo_database=name, acknowledged={'odoo': self.confirm_keys(row, name)})
        self.assertEqual(result['ha_import']['odoo_database'], name)
        with_name = [(c, cmd, env) for c, cmd, env in self.world.exec_env if env.get('PGDATABASE') == name]
        self.assertTrue(any(cmd[0] == 'pg_dump' for _c, cmd, _e in with_name), 'pg_dump')
        self.assertTrue(any(cmd[0] == 'psql' for _c, cmd, _e in with_name), 'psql')
        for _c, cmd, env in with_name:
            self.assertNotIn('-d', cmd)
            self.assertFalse([part for part in cmd if name in part])
        calls = [args for args in self.world.owner.calls if args[0] == 'exec']
        self.assertFalse([args for args in calls if '-d' in args and name == args[args.index('-d') + 1]],
                         'the name is never the argument of -d')
        self.assertFalse([args for args in calls if name in args], 'nor any other argument')

    def test_a_name_that_cannot_be_passed_stops_only_that_database(self):
        self.world.ha_databases = [['woowtest', 9000000, 'C', 'C'], ['bad\nname', 1, 'C', 'C']]
        row = self.check()
        self.assertEqual(self.ids(row, 'bad\nname'), {'odoo.database-name': 'stop'})
        self.assertEqual({r['value']: r['ok'] for r in row['choices']['database']}, {'woowtest': True, 'bad\nname': False})

    def test_the_conversion_looks_at_its_database_again_by_the_same_rules(self):
        """OD-50: what stops the database in the check stops its conversion, only that app; nothing is kept."""
        self.several()
        ha_id = self.upload_odoo()
        for name, code in (('notodoo', 'odoo.not-odoo'), ('broken', 'odoo.db-unreadable')):
            with self.subTest(name), self.assertRaises(BackupError) as caught:
                self.convert(ha_id, ['odoo'], odoo_database=name)
            self.assertEqual(caught.exception.code, 'incompatible')
            self.assertEqual([i.id for i in caught.exception.issues], [code])
        self.assertEqual(self.storage.list_backups(), [])
        self.assertEqual(self.reporter.partial.get('temp_owners'), [])
        self.world.ha_modules = [['base', '18.0.1.4', 'installed'], *self.world.ha_modules[1:]]   # it changed since the check
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['odoo'])
        self.assertEqual([i.id for i in caught.exception.issues], ['odoo.module-version-different'])

    def test_the_databases_that_stay_on_ha_are_said_and_recorded(self):
        """UI-20, S6: one line to confirm per database that can move; the conversion returns the names that stay."""
        self.several()
        ha_id = self.upload_odoo()
        row = self.check(ha_id)
        (line,) = [i for i in self.issues(row, 'woowtest') if i['id'] == 'odoo.databases-left']
        self.assertEqual(line['level'], 'confirm')
        self.assertEqual(sorted(line['items']), ['broken', 'ha prod=1$', 'junkmods', 'notodoo'])
        self.assertIn('以後再匯入另一個會取代這次的', line['message'])
        self.assertIn('odoo.databases-left', self.ids(row, 'ha prod=1$'))
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['odoo'])      # not confirmed: only this app, nothing kept
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertEqual(self.storage.list_backups(), [])
        result = self.convert(ha_id, ['odoo'], acknowledged={'odoo': [line['key']]})
        self.assertEqual(result['ha_import']['left_databases'], ['notodoo', 'broken', 'junkmods', 'ha prod=1$'])
        self.assertTrue(any('會留在 HA' in note for note in result['ha_import']['notes']))
        self.assertEqual([i['id'] for i in result['results'][0]['issues'] if i['level'] == 'confirm'],
                         ['odoo.databases-left'])

    def test_one_more_database_on_ha_needs_the_confirmation_again(self):
        self.several()
        ha_id = self.upload_odoo()
        row = self.check(ha_id)
        keys = self.confirm_keys(row, 'woowtest')
        self.world.ha_databases = [*self.world.ha_databases, ['newcomer', 10, 'C', 'C']]
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['odoo'], acknowledged={'odoo': keys})
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertIn('請再確認一次', caught.exception.message)

    def test_a_module_the_device_lacks_is_a_line_to_confirm_and_the_data_moves_with_it(self):
        """OD-37: the functions of the module stop, the data stays; the message says the next update is stopped."""
        self.world.ha_modules = [*self.world.ha_modules, ['gone_mod', '18.0.1.0.0', 'installed']]
        ha_id = self.upload_odoo()
        row = self.check(ha_id)
        self.assertTrue(row['importable'])
        (line,) = [i for i in row['issues'] if i['id'] == 'odoo.modules-missing']
        self.assertEqual((line['level'], line['items'], line['database']), ('confirm', ['gone_mod'], 'woowtest'))
        self.assertIn('結束碼 4', line['message'])
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['odoo'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertEqual(self.storage.list_backups(), [])
        result = self.convert(ha_id, ['odoo'], acknowledged={'odoo': [line['key']]})
        self.assertEqual(result['apps'], ['odoo'])
        self.world.ha_modules = [*self.world.ha_modules, ['gone_two', '18.0.1.0.0', 'installed']]   # one more name
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['odoo'], acknowledged={'odoo': [line['key']]})
        self.assertEqual(caught.exception.code, 'confirmation-required')

    def test_a_custom_module_that_needs_a_missing_package_stays_out_and_the_rest_moves(self):
        """OD-44."""
        entries = module_entries('needs_zeep', manifest_of(python=['zeep']))
        self.world.ha_modules = [*self.world.ha_modules, ['needs_zeep', '18.0.1.0.0', 'installed']]
        ha_id = self.upload_odoo(entries)
        row = self.check(ha_id)
        (line,) = [i for i in row['issues'] if i['id'] == 'odoo.modules-skipped-deps']
        self.assertEqual((line['level'], line['items']), ('confirm', ['needs_zeep（缺 zeep）']))
        self.assertEqual([c['name'] for c in row['odoo']['databases'][0]['custom_modules']], ['woow_import_probe'])
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['odoo'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.convert(ha_id, ['odoo'], acknowledged={'odoo': [line['key']]})
        names = set(tarfile.open(fileobj=io.BytesIO(self.world.dir_data['.local/share/odoo18/addons'])).getnames())
        self.assertIn('./woow_import_probe/__manifest__.py', names)
        self.assertFalse([n for n in names if 'needs_zeep' in n], 'its files stay behind')

    def test_custom_modules_with_odd_needs_are_copied_and_reminded(self):
        """OD-43, OD-45, OD-46."""
        entries = (module_entries('not_installable', manifest_of(installable=False))
                   + module_entries('needs_program', manifest_of(binaries=['antiword']))
                   + module_entries('native', manifest_of(), extra=[{'name': 'data/addons/native/lib.so',
                                                                     'data': elf(0xB7) + b'x'}]))
        self.world.ha_modules = [*self.world.ha_modules] + [[n, '18.0.1.0.0', 'installed']
                                                           for n in ('not_installable', 'needs_program', 'native')]
        ha_id = self.upload_odoo(entries)
        row = self.check(ha_id)
        self.assertTrue(row['importable'])
        found = {i['id']: i for i in row['issues'] if i['id'].startswith(('odoo.module-', 'odoo.program'))}
        self.assertEqual({k: v['level'] for k, v in found.items()},
                         {'odoo.module-not-installable': 'notice', 'odoo.program-missing': 'notice',
                          'odoo.module-foreign-native': 'notice'})
        self.assertEqual(found['odoo.module-foreign-native']['items'], ['native'])
        self.convert(ha_id, ['odoo'])     # nothing to confirm: all three are copied
        names = set(tarfile.open(fileobj=io.BytesIO(self.world.dir_data['.local/share/odoo18/addons'])).getnames())
        self.assertTrue({'./not_installable/__manifest__.py', './needs_program/__manifest__.py',
                         './native/lib.so'} <= names)

    def test_modules_waiting_for_an_installation_move_as_they_are_and_are_said_once(self):
        """OD-36, OD-61."""
        self.world.ha_modules = [*self.world.ha_modules, ['pending_mod', '18.0.1.0.0', 'to upgrade']]
        ha_id = self.upload_odoo()
        row = self.check(ha_id)
        self.assertEqual(self.ids(row, 'woowtest')['odoo.modules-pending'], 'notice')
        result = self.convert(ha_id, ['odoo'])
        self.assertEqual([i['id'] for i in result['results'][0]['issues']].count('odoo.modules-pending'), 1)

    def test_the_target_modules_that_cannot_be_read_are_left_out_of_the_comparison(self):
        """OD-35: one broken module no longer hides the rest of the list."""
        self.world.scan_broken = ['broken_one']
        row = self.check()
        self.assertTrue(row['importable'])
        (line,) = [i for i in row['issues'] if i['id'] == 'odoo.target-modules-partial']
        self.assertEqual((line['level'], line['items']), ('notice', ['broken_one']))

    def test_a_target_whose_module_list_cannot_be_read_at_all_stops_only_odoo(self):
        original = self.world.run

        def run(name, image, args, argv, data):
            if name.endswith('-scan'):
                return Result(0, json.dumps({'error': 'ImportError', 'python': {}, 'bin': {}}).encode(), b'')
            return original(name, image, args, argv, data)

        self.world.run = run
        row = self.check()
        self.assertFalse(row['importable'])
        self.assertEqual(row['issues'][0]['id'], 'failure.job-failed')
        self.assertIn('模組清單', row['issues'][0]['message'])

    def test_an_extension_the_device_has_and_trusts_is_created_one_it_does_not_trust_stops_the_database(self):
        """OD-39."""
        self.world.ha_databases = [['woowtest', 9000000, 'C', 'C'], ['linked', 10, 'C', 'C']]
        self.world.extensions_by_db = {'woowtest': [['plpgsql', '1.0'], ['pgcrypto', '1.3']],
                                       'linked': [['plpgsql', '1.0'], ['dblink', '1.2'], ['postgis', '3.4']]}
        ha_id = self.upload_odoo()
        row = self.check(ha_id)
        self.assertEqual(self.ids(row, 'linked')['odoo.extension-unsupported'], 'stop')
        self.assertEqual(sorted(self.issues(row, 'linked')[0]['items']), ['dblink', 'postgis'])
        self.assertTrue({r['value']: r['ok'] for r in row['choices']['database']}['woowtest'])
        self.convert(ha_id, ['odoo'], acknowledged={'odoo': self.confirm_keys(row, 'woowtest')})
        self.assertIn('CREATE EXTENSION IF NOT EXISTS "pgcrypto"', '\n'.join(self.executed()))

    def test_vector_is_created_only_when_the_image_has_it_or_the_database_uses_it(self):
        """OD-57."""
        self.world.live_extensions = [['plpgsql', True], ['pg_trgm', True], ['unaccent', True]]
        ha_id = self.upload_odoo()
        self.convert(ha_id, ['odoo'])
        executed = '\n'.join(self.executed())
        self.assertIn('CREATE EXTENSION IF NOT EXISTS "pg_trgm"', executed)
        self.assertNotIn('vector', executed)
        self.world.live_extensions = [['plpgsql', True], ['pg_trgm', True], ['vector', True]]
        self.world.owner.psql.clear()
        self.convert(ha_id, ['odoo'])
        executed = '\n'.join(self.executed())
        self.assertIn('CREATE EXTENSION IF NOT EXISTS "vector"', executed)
        self.assertIn('ALTER EXTENSION vector UPDATE', executed)

    def test_the_image_that_reads_vector_is_downloaded_and_the_database_read_again(self):
        """OD-40."""
        self.world.ha_extensions = [['plpgsql', '1.0'], ['vector', '0.8.0']]
        row = self.check()
        self.assertTrue(row['importable'], row['blockers'])
        self.assertEqual(self.world.pulls, [ha_odoo.PG16_IMAGES[0]])
        images = [run[1] for run in self.runs('hapg')]
        self.assertEqual(images, ['docker.io/library/postgres:16.15-alpine', ha_odoo.PG16_IMAGES[0]])
        self.assertIn('target.image-pulled', self.ids(row))

    def test_a_second_walk_of_the_backup_does_not_say_the_same_line_twice(self):
        self.world.ha_extensions = [['plpgsql', '1.0'], ['vector', '0.8.0']]
        row = self.check(self.upload_odoo([{'name': 'data/addons/woow_import_probe/node0', 'type': 'chr'}]))
        self.assertEqual(len(self.runs('hapg')), 2, 'it was read twice')
        self.assertEqual([i['id'] for i in row['issues']].count('files.skipped'), 1)

    def test_without_the_vector_image_only_the_databases_that_use_it_stop(self):
        self.world.ha_databases = [['woowtest', 9000000, 'C', 'C'], ['plain', 10, 'C', 'C']]
        self.world.extensions_by_db = {'woowtest': [['plpgsql', '1.0'], ['vector', '0.8.0']]}
        self.world.ha_extensions = [['plpgsql', '1.0']]
        self.world.pull_works = False
        row = self.check()
        self.assertTrue(row['importable'])
        self.assertEqual(self.ids(row, 'woowtest'), {'odoo.vector-image-missing': 'stop', 'odoo.databases-left': 'confirm',
                                                     'odoo.crons-active': 'notice', 'odoo.website-domains': 'notice'})
        self.assertEqual({r['value']: r['ok'] for r in row['choices']['database']}, {'woowtest': False, 'plain': True})

    def test_reminders_after_the_conversion_do_not_stop_it(self):
        """OD-66, OD-67, OD-69."""
        self.world.verify_base_url = 'https://ha.local'
        self.world.verify_domains = ['https://shop.ha.example']
        self.world.refuse_setting = 'work_mem'
        result = self.convert(self.upload_odoo(), ['odoo'])
        ids = {i['id']: i for i in result['results'][0]['issues']}
        self.assertEqual({ids[k]['level'] for k in ('odoo.url-differs', 'odoo.website-domain-kept',
                                                    'odoo.settings-not-carried')}, {'notice'})
        self.assertEqual(ids['odoo.settings-not-carried']['items'], ['work_mem'])
        self.assertEqual(ids['odoo.website-domain-kept']['items'], ['https://shop.ha.example'])

    def test_a_modules_folder_that_the_settings_do_not_list_is_not_filled(self):
        """OD-72: the check says so; nothing fails at the end; the module of the backup counts as missing."""
        self.catalog['odoo'].data_dirs = []
        ha_id = self.upload_odoo()
        row = self.check(ha_id)
        self.assertTrue(row['importable'])
        self.assertEqual(self.ids(row)['odoo.addons-folder-undeclared'], 'notice')
        (line,) = [i for i in row['issues'] if i['id'] == 'odoo.modules-missing']
        self.assertEqual(line['items'], ['woow_import_probe'])
        result = self.convert(ha_id, ['odoo'], acknowledged={'odoo': [line['key']]})
        self.assertEqual(self.world.manifests['odoo']['dirs'] if 'dirs' in self.world.manifests['odoo'] else {}, {})
        self.assertEqual(result['apps'], ['odoo'])

    def test_this_devices_other_volumes_and_folders_go_along_as_they_are(self):
        """OD-12, OD-13."""
        self.catalog['odoo'].volumes = [*self.catalog['odoo'].volumes, {'name': 'odoo-extra-vol'}]
        self.catalog['odoo'].data_dirs = [*self.catalog['odoo'].data_dirs, {'path': '.local/share/odoo-extra'}]
        ha_id = self.upload_odoo()
        row = self.check(ha_id)
        self.assertTrue(row['importable'], row['blockers'])
        (line,) = [i for i in row['issues'] if i['id'] == 'odoo.extras-carried']
        self.assertEqual((line['level'], line['items']), ('auto', ['odoo-extra-vol', '.local/share/odoo-extra']))
        self.convert(ha_id, ['odoo'])
        items = self.world.manifests['odoo']
        self.assertEqual(sorted(items['volumes']), ['odoo-extra-vol', 'odoo18-db-data-isolated', 'odoo18-web-data'])
        self.assertEqual(sorted(items['dirs']), ['.local/share/odoo-extra', '.local/share/odoo18/addons'])
        with tarfile.open(fileobj=io.BytesIO(self.world.volume_data['odoo-extra-vol'])) as tar:
            self.assertEqual(tar.extractfile('kept.txt').read(), b'this device')

    def test_a_link_of_this_devices_own_volume_that_leaves_it_is_left_out_and_confirmed_once(self):
        """OD-12, X-NS-08: the restore would refuse the volume for it; the link is left out and listed instead."""
        self.catalog['odoo'].volumes = [*self.catalog['odoo'].volumes, {'name': 'odoo-extra-vol'}]
        self.world.extra_symlink = True
        ha_id = self.upload_odoo()
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['odoo'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        (line,) = caught.exception.issues
        self.assertEqual((line.id, list(line.names)), ('files.skipped', ['odoo-extra-vol：escape']))
        self.assertEqual([run[0] for run in self.world.runs if run[0] in ('hapg', 'odoo-db')], [], 'before the heavy part')
        self.convert(ha_id, ['odoo'], acknowledged={'odoo': [line.key('odoo')]})
        with tarfile.open(fileobj=io.BytesIO(self.world.volume_data['odoo-extra-vol'])) as tar:
            self.assertEqual(tar.getnames(), ['.', 'kept.txt'])

    def test_a_layout_the_import_does_not_know_still_stops_only_odoo_and_says_what_to_do(self):
        self.catalog['odoo'].volumes = [{'name': 'odoo18-db-data-isolated'}]      # the data dir volume is not declared
        row = self.check()
        self.assertFalse(row['importable'])
        self.assertEqual([(i['id'], i['level']) for i in row['issues']], [('odoo.layout-unsupported', 'stop')])
        self.assertIn('應用設定', row['issues'][0]['action'])

    def test_what_the_reader_leaves_out_of_the_backup_is_one_line_to_confirm_again_at_the_conversion(self):
        """IN-27 and the other reading rows of READ, for this importer: a device file in a module is left out, listed,
        confirmed once with its name; one more such name needs the confirmation again."""
        entries = [{'name': 'data/addons/woow_import_probe/node0', 'type': 'chr'}]
        ha_id = self.upload_odoo(entries)
        row = self.check(ha_id)
        (line,) = [i for i in row['issues'] if i['id'] == 'files.skipped']
        self.assertEqual((line['level'], line['items']), ('confirm', ['data/addons/woow_import_probe/node0']))
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['odoo'], acknowledged={'odoo': []})
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertEqual(self.storage.list_backups(), [])
        self.convert(ha_id, ['odoo'], acknowledged={'odoo': [line['key']]})
        with tarfile.open(fileobj=io.BytesIO(self.world.dir_data['.local/share/odoo18/addons'])) as tar:
            self.assertNotIn('./woow_import_probe/node0', tar.getnames())
            self.assertIn('./woow_import_probe/__manifest__.py', tar.getnames())
        more = self.upload_odoo(entries + [{'name': 'data/addons/woow_import_probe/node1', 'type': 'chr'}])
        with self.assertRaises(BackupError) as caught:
            self.convert(more, ['odoo'], acknowledged={'odoo': [line['key']]})
        self.assertEqual(caught.exception.code, 'confirmation-required')

    def test_a_manifest_that_is_too_large_is_listed_and_its_module_stays_behind(self):
        """IN-19 for the module manifests: it no longer stops the whole add-on."""
        big = [{'name': 'data/addons/big_manifest', 'type': 'dir'},
               {'name': 'data/addons/big_manifest/__manifest__.py', 'data': b'#' * (ha_odoo.MAX_MANIFEST + 1)}]
        self.world.ha_modules = [*self.world.ha_modules, ['big_manifest', '18.0.1.0.0', 'installed']]
        row = self.check(self.upload_odoo(big))
        self.assertTrue(row['importable'])
        self.assertEqual({i['id'] for i in row['issues'] if i['level'] == 'confirm'}, {'files.skipped', 'odoo.modules-missing'})
        (missing,) = [i for i in row['issues'] if i['id'] == 'odoo.modules-missing']
        self.assertEqual(missing['items'], ['big_manifest'])

    def test_a_big_backup_is_given_the_time_and_room_it_needs(self):
        """OD-28, OD-73: the exports, the module scan and the dump wait longer; the module list gets more room."""
        with mock.patch.object(ha_odoo.hatarget, 'size_hint', lambda _ha: 200 * 1024 ** 3):
            self.convert(self.upload_odoo(), ['odoo'])
        limits = self.world.owner.limits
        export = next(timeout for args, timeout, _m in limits if args[:3] == ('relay', 'volume', 'export'))
        self.assertGreater(export, 3 * 3600)
        scan = next((timeout, room) for args, timeout, room in limits
                    if any(str(part).endswith('-scan') for part in args) and args[0] == 'run')
        self.assertGreater(scan[0], 600)
        self.assertGreater(scan[1], ha_odoo.SCAN_OUTPUT)
        dump = next(timeout for args, timeout, _m in limits if 'pg_dump' in args)
        self.assertGreater(dump, ha_odoo.DUMP_TIMEOUT)


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
