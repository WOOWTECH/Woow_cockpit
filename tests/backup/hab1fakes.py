"""Test doubles for the batch 1 importers' whole conversions (haimport.run_ha_check / run_ha_convert with the real
app modules, the real TempObjects, Cluster and SQLite child): an app owner whose podman answers like the lab's,
through a World that each test file fills in. Team E2."""
import io
import json
import re
import tarfile
import types
from pathlib import Path

from woowbackup import jobs, nested
from woowbackup.errors import BackupError
from woowbackup.podman import CommandError, Result

from . import hafakes
from . import hafixtures as hx
from .test_ha_import import FlowCase

IDS = (nested.IdMap('0 1013 1\n1 100000 65536\n'), nested.IdMap('0 1013 1\n1 100000 65536\n'))
ROLE_RE = re.compile(r'^woowbk-j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}-')
VALUE_OPTIONS = {'--name', '--label', '--log-driver', '--network', '--security-opt', '--pids-limit', '--memory',
                 '--cpus', '--user', '--workdir', '--entrypoint', '--env', '--env-file', '--volume', '--secret', '--add-host'}
FLAG_OPTIONS = {'--pull=never', '--detach', '--rm', '--interactive', '--read-only'}


def role_of(name):
    return ROLE_RE.sub('', name)


def tar_of(entries):
    return hx.tar_bytes(entries)


def parse_run(args):
    """(options {name: [values]}, image, command) of `podman run` args (without 'run')."""
    options, i = {}, 0
    while i < len(args):
        arg = args[i]
        if arg in FLAG_OPTIONS:
            options.setdefault(arg, []).append(True)
            i += 1
        elif arg in VALUE_OPTIONS:
            options.setdefault(arg, []).append(args[i + 1])
            i += 2
        else:
            break
    return options, args[i], list(args[i + 1:])


class Owner:
    """The app owner's runner: podman through the world, files of his home in `world.files`."""

    def __init__(self, world):
        self.world = world
        self.home = '/home/appowner'
        self.owner = 'appowner'
        self.uid = None
        self.calls = []

    def podman(self, *args, input=None, stdout=None, timeout=None, max_output=None, check=True, abort=None):
        self.calls.append(args)
        data = input.read() if hasattr(input, 'read') else input
        result = self.world.podman(list(args), data, stdout)
        if check and result.returncode != 0:
            # like podman.Runner.run: the child's stderr is kept on the error (diagnostics only)
            raise CommandError(f'podman {args[0]} 執行失敗（結束碼 {result.returncode}）。', returncode=result.returncode,
                               stderr=result.stderr)
        return result

    def relay(self, args, *, stdout, timeout=None, max_output=None, check=True, abort=None):
        self.calls.append(('relay', *args))
        stdout.write(self.world.export(args[-1]))
        return Result(0, None, b'')

    def read_file(self, rel, max_bytes=None):
        if rel not in self.world.files:
            raise BackupError('not-found', f'找不到檔案 ~/{rel}。')
        return self.world.files[rel]


class Adapter:
    def __init__(self, app, world):
        self.app, self.world = app, world
        self.runner = world.owner

    def probe(self):
        return {'deployed': True, 'problems': [], 'units': []}

    def owner_ids(self):
        return IDS

    def image_inspect(self, image):
        return self.world.image_info(image)

    def read_quadlets(self):
        return dict(self.world.quadlets[self.app.id])

    def import_manifest(self, staging_dir, **items):
        from woowbackup.adapters.quadlet_postgres import file_digest
        from woowbackup.archive import Entry
        self.world.manifests[self.app.id] = items
        self.world.volume_data.update({name: Path(source).read_bytes()
                                       for name, source in (items.get('volumes') or {}).items()})
        entries = []
        for name, source in sorted((items.get('volumes') or {}).items()):
            size, digest = file_digest(source)
            entries.append(Entry(path=f'apps/{self.app.id}/volumes/{name}.tar', source=Path(source), size=size,
                                 sha256=digest))
        for pg_id, dump in sorted((items.get('postgres') or {}).items()):
            size, digest = file_digest(dump['file'])
            entries.append(Entry(path=f'apps/{self.app.id}/postgres/{pg_id}.dump', source=Path(dump['file']),
                                 size=size, sha256=digest))
        return {'id': self.app.id, 'name': self.app.name, 'items': sorted(items)}, entries

    def _dump_database(self, pg, staging):
        dest = Path(staging) / 'postgres' / f'{pg["id"]}.dump'
        dest.write_bytes(b'PGDMP-live-' + pg['database'].encode())
        self.world.live_dumps.append(pg['id'])
        return {'id': pg['id'], 'database': pg['database'], 'server_version': '15.19', 'major': 15, 'file': dest}


class World:
    """What the fake podman answers. Subclasses answer `run`, `exec`, `answer` (psql), `export` and `labels`."""

    def __init__(self):
        self.owner = Owner(self)
        self.quadlets = {}
        self.files = {}
        self.images = set()
        self.manifests, self.volume_data, self.imported = {}, {}, {}
        self.runs, self.execs, self.live_dumps = [], [], []
        self.psql = {}
        self.exit_codes = {}

    def factory(self, app, **_kwargs):
        return Adapter(app, self)

    def image_info(self, image):
        return {'id': 'sha256:' + 'c' * 64, 'env': ['PG_MAJOR=16'], 'digest': '', 'arch': 'amd64', 'size': 1,
                'names': []}

    def labels(self, image):
        return {}

    # ---------------------------------------------------------- podman
    def podman(self, args, data, stdout):
        verb = args[0]
        if verb == 'run':
            options, image, command = parse_run(args[1:])
            name = options['--name'][0]
            role = role_of(name)
            self.runs.append((role, image, command, options))
            if command[:1] == ['-c'] and 'id -u' in command[1]:
                return Result(0, self.user_ids(command[1].split()[2]), b'')
            return self.run(role, image, command, options, data)
        if verb == 'exec':
            i = 1
            while args[i].startswith('--'):
                i += 2 if args[i] in ('--user', '--workdir', '--env') else 1
            container, command = args[i], list(args[i + 1:])
            role = role_of(container)
            self.execs.append((role, command, data))
            if command[0] == 'psql':
                if role not in self.psql:
                    self.psql[role] = hafakes.Psql(lambda sql, db, r=role: self.answer(r, sql, db))
                return self.psql[role](command, data)
            return self.exec(role, command, data, stdout)
        if verb == 'image' and args[1] == 'exists':
            return Result(0 if args[2] in self.images else 1, b'', b'')
        if verb == 'image' and args[1] == 'inspect':
            return Result(0, json.dumps(self.labels(args[-1])).encode() + b'\n', b'')
        if verb == 'container' and args[1] == 'inspect':
            role = role_of(args[-1])
            return Result(0, f'{self.exit_codes.get(role, 0)}\n'.encode() if 'ExitCode' in args[3] else b'true\n',
                          b'')
        if verb == 'volume' and args[1] == 'import':
            self.imported[role_of(args[2])] = data
            return Result(0, b'', b'')
        if verb == 'volume' and args[1] == 'inspect':
            return Result(0, f'/home/appowner/.local/share/containers/storage/volumes/{args[-1]}/_data\n'.encode(), b'')
        if verb == 'unshare' and args[1] == 'stat':
            return Result(0, self.volume_root(args[-1]), b'')
        return Result(0, b'', b'')

    def user_ids(self, user):
        return {'postgres': b'70\n70\n', 'emqx': b'1000\n1000\n'}.get(user, b'1000\n1000\n')

    def volume_root(self, mount):
        return b'0 0 755\n'

    def run(self, role, image, command, options, data):
        return Result(0, b'', b'')

    def exec(self, role, command, data, stdout):
        return Result(0, b'', b'')

    def answer(self, role, sql, database):
        return None

    def export(self, volume):
        return tar_of([{'name': '.', 'type': 'dir'}])


def app(app_id, name, **fields):
    base = {'id': app_id, 'name': name, 'owner': 'appowner', 'postgres': [], 'volumes': [], 'data_dirs': [],
            'health': [], 'secrets': [], 'config_files': []}
    base.update(fields)
    return types.SimpleNamespace(**base)


class ConversionCase(FlowCase):
    """FlowCase with a World (`world_class`) and the catalog entry of the app under test (`catalog_app()`)."""
    world_class = World

    def setUp(self):
        super().setUp()
        from unittest import mock

        from woowbackup import haimport
        self.world = self.world_class()
        self.deps.adapter_factory = self.world.factory
        self.catalog = self.catalog_apps()
        self.deps.load_catalog = lambda: self.catalog
        patcher = mock.patch.object(haimport.SpaceGuard, 'free', lambda guard: 1024 ** 4)
        patcher.start()
        self.addCleanup(patcher.stop)

    def catalog_apps(self):
        return {}

    def convert(self, ha_id, apps, **params):
        from woowbackup import flows
        base = {'source': 'ha', 'ha_backup_id': ha_id, 'apps': apps, 'odoo_database': None, 'test_mode': False,
                'encrypt': True, 'key_provided': False}
        base.update(params)
        return flows.run_backup(self.ctx(), base)

    def check(self, ha_id, apps):
        from woowbackup import flows
        return flows.run_verify(self.ctx(), {'source': 'ha', 'ha_backup_id': ha_id, 'apps': apps,
                                             'key_provided': False})['ha_check']['apps']

    def runs(self, role):
        return [run for run in self.world.runs if run[0] == role]

    def volume(self, name):
        with tarfile.open(fileobj=io.BytesIO(self.world.volume_data[name])) as tar:
            return {m.name: (m, tar.extractfile(m).read() if m.isfile() else None) for m in tar.getmembers()}

    def tearDown(self):
        super().tearDown()
        for secret in getattr(self, 'masked', ()):
            jobs.unmask_secret(secret)
