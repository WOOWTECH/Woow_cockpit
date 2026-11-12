"""QuadletPostgresAdapter against a stateful fake owner (podman, systemctl --user, file helper).

Asserts the exact argv of every owner command, that secrets never reach argv/env/logs, that
writers are restarted whatever fails, when restores become destructive, and the preflight rules.
"""
import http.server
import json
import os
import shutil
import tempfile
import threading
import types
import unittest
from pathlib import Path

from woowbackup import catalog, podman
from woowbackup.adapters import get_adapter
from woowbackup.adapters import quadlet_postgres as qp
from woowbackup.errors import BackupError
from woowbackup.paths import Paths

from .test_catalog import demo_entry, lookup as user_lookup

PODMAN, SYSTEMCTL, PYTHON, HELPER = podman.PODMAN, podman.SYSTEMCTL, podman.PYTHON, podman.FILE_HELPER
Q = '.config/containers/systemd/'
PG_REF = 'docker.io/library/postgres:16-alpine'
APP_REF = 'localhost/woowbk-demo-app:1'
PG_ID = 'sha256:' + 'a' * 64
APP_ID = 'sha256:' + 'b' * 64
DB_PASSWORD = b'pw-Sup3r-S3cret-value'
APP_KEY = b'app-key-\x00\xff-binary\n'
QUADLETS = {
    'woowbk-demo.network': b'[Network]\n',
    'woowbk-demo-db.container': (b'[Unit]\nDescription=db\n[Container]\nImage=docker.io/library/postgres:16-alpine\n'
                                 b'ContainerName=woowbk-demo-db\nSecret=woowbk-demo-db-password,type=env,target=POSTGRES_PASSWORD\n'
                                 b'Volume=woowbk-demo-pgdata:/var/lib/postgresql/data\nNetwork=woowbk-demo.network\n'),
    'woowbk-demo-app.container': (b'[Container]\nImage=localhost/woowbk-demo-app:1\nContainerName=woowbk-demo-app\n'
                                  b'Volume=woowbk-demo-files:/data\n# Image=ignored-comment\n'),
}
DUMP = b'PGDMP' + bytes(range(256)) * 4
VOLUME_TAR = b'TAR!' + bytes(4092)
CONFIG = b'TITLE=Demo\n'
SUMMARY = {'notes': 12, 'files': 4, 'digest': 'abc', 'title': 'Demo', 'signatures_valid': True, 'uptime': 99}
PREFIX = ['/usr/sbin/runuser', '-u', 'appowner', '--', '/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
          'HOME=/home/appowner', 'LANG=C.UTF-8', 'XDG_RUNTIME_DIR=/run/user/1001',
          'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus']


def helper(op, *args):
    return [PYTHON, '-I', '-c', HELPER, op, *args]


def psql(sql, database='notes'):
    return [PODMAN, 'exec', 'woowbk-demo-db', 'psql', '-X', '-w', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-U', 'notes',
            '-d', database, '-c', sql]


class FakeOwner:
    """State machine standing in for the rootless owner behind OwnerRunner (no real processes)."""

    def __init__(self, deployed=True):
        self.calls = []
        self.files, self.modes, self.links = {}, {}, set()
        self.units, self.secrets, self.volumes = {}, {}, {}
        if deployed:
            self.files = {Q + name: data for name, data in QUADLETS.items()}
            self.files['.config/woowbk-demo/app.env'] = CONFIG
            self.units = {'woowbk-demo-db.service': 'active', 'woowbk-demo-app.service': 'active'}
            self.secrets = {'woowbk-demo-db-password': DB_PASSWORD, 'woowbk-demo-app-key': APP_KEY}
            self.volumes = {'woowbk-demo-files': VOLUME_TAR, 'woowbk-demo-pgdata': b'PGDATA'}
        self.images = {PG_REF: PG_ID, APP_REF: APP_ID}
        self.known_ids = {PG_ID, APP_ID}
        self.image_env = {PG_REF: ['PG_MAJOR=16'], APP_REF: []}
        self.pullable = set()
        self.arch = 'amd64'
        self.db = {'data': DUMP if deployed else b'', 'num': '160015', 'version': '16.15', 'databases': {'notes'}}
        self.containers = {'woowbk-demo-db': 'woowbk-demo-db.service'}
        self.fail = []

    # ------------------------------------------------------------- plumbing
    def __call__(self, argv, *, input=None, stdout=None, timeout=None, cwd=None, env=None):
        assert argv[:len(PREFIX)] == PREFIX, argv[:len(PREFIX)]
        assert cwd == '/home/appowner' and env == podman.ROOT_ENV, (cwd, env)
        inner = list(argv[len(PREFIX):])
        # Real podman distinguishes a pipe (bytes fed by the runner) from a regular-file stdin.
        self.input_kind = 'pipe' if isinstance(input, (bytes, bytearray)) else ('file' if input is not None else None)
        data = input if input is None or isinstance(input, (bytes, bytearray)) else input.read()
        self.calls.append({'argv': inner, 'input': data, 'timeout': timeout, 'env': env, 'kind': self.input_kind})
        text = self.text(inner)
        for needle, code in self.fail:
            if needle in text:
                return podman.Result(code, b'', b'injected failure\nCommand was: SELECT secret')
        if inner[:3] == [PYTHON, '-I', '-c']:
            assert inner[3] == HELPER
            return self.helper(inner[4], inner[5:], data, stdout)
        if inner[0] == SYSTEMCTL:
            assert inner[1] == '--user'
            return self.systemctl(inner[2:])
        if inner[0] == PODMAN:
            return self.podman(inner[1:], data, stdout)
        raise AssertionError(f'unexpected command {inner}')

    @staticmethod
    def text(inner):
        return ' '.join('HELPER' if part == HELPER else part for part in inner)

    def argvs(self):
        return [call['argv'] for call in self.calls]

    @staticmethod
    def out(code, payload, stdout):
        if stdout is None:
            return podman.Result(code, payload, b'')
        if stdout is not podman.DEVNULL:
            stdout.write(payload)
        return podman.Result(code, None, b'')

    # ------------------------------------------------------------- commands
    def helper(self, op, args, data, stdout):
        if op == 'read':
            rel, limit = args[0], int(args[1])
            if rel in self.links:
                return podman.Result(4, b'', b'not-regular\n')
            if rel not in self.files:
                return podman.Result(3, b'', b'not-found\n')
            if len(self.files[rel]) > limit:
                return podman.Result(5, b'', b'too-large\n')
            return self.out(0, self.files[rel], stdout)
        if op == 'write':
            self.files[args[0]] = bytes(data)
            self.modes[args[0]] = args[1]
            return podman.Result(0, b'', b'')
        if op == 'remove':
            existed = self.files.pop(args[0], None) is not None
            return podman.Result(0, b'removed' if existed else b'absent', b'')
        if op == 'stat':
            rows = []
            for rel in args:
                if rel in self.links:
                    rows.append({'path': rel, 'type': 'link'})
                elif rel in self.files:
                    rows.append({'path': rel, 'type': 'file', 'size': len(self.files[rel]), 'mode': 0o644})
                else:
                    rows.append({'path': rel, 'type': 'missing'})
            return podman.Result(0, json.dumps(rows).encode(), b'')
        if op == 'relay':
            assert args[0] == PODMAN
            return self.podman(args[1:], data, stdout)
        raise AssertionError(op)

    def systemctl(self, args):
        verb = args[0]
        if verb == 'show':
            blocks = []
            for unit in args[args.index('--') + 1:]:
                if unit in self.units:
                    blocks.append(f'Id={unit}\nLoadState=loaded\nActiveState={self.units[unit]}\nSubState=x')
                else:
                    blocks.append(f'Id={unit}\nLoadState=not-found\nActiveState=inactive\nSubState=dead')
            return podman.Result(0, ('\n\n'.join(blocks) + '\n').encode(), b'')
        if verb in ('start', 'stop'):
            assert args[1] == '--'
            unit = args[2]
            if unit not in self.units:
                return podman.Result(5, b'', b'Unit not found.')
            self.units[unit] = 'active' if verb == 'start' else 'inactive'
            return podman.Result(0, b'', b'')
        if verb == 'daemon-reload':
            for name in QUADLETS:
                unit = qp.quadlet_unit(name)
                if name.endswith('.container'):
                    if Q + name in self.files:
                        self.units.setdefault(unit, 'inactive')
                    elif self.units.get(unit) == 'inactive':
                        del self.units[unit]
            return podman.Result(0, b'', b'')
        if verb == 'reset-failed':
            return podman.Result(0, b'', b'')
        raise AssertionError(args)

    def podman(self, args, data, stdout):
        ok = podman.Result(0, b'', b'')
        missing = podman.Result(125, b'', b'Error: no such object')
        cmd = args[0]
        if cmd == 'exec':
            rest = args[1:]
            if rest[0] == '-i':
                rest = rest[1:]
            container, tool = rest[0], rest[1:]
            if self.units.get(self.containers.get(container)) != 'active':
                return missing
            if tool[0] == 'psql':
                sql = tool[tool.index('-c') + 1]
                if sql == 'SHOW server_version_num':
                    value = self.db['num']
                elif sql == 'SHOW server_version':
                    value = self.db['version']
                elif 'pg_database_size' in sql:
                    value = '8000000'
                elif 'FROM pg_database WHERE datname' in sql:
                    value = '1' if 'notes' in self.db['databases'] else ''
                else:
                    raise AssertionError(sql)
                return self.out(0, (value + '\n').encode(), stdout)
            if tool[0] == 'pg_dump':
                return self.out(0, self.db['data'], stdout)
            if tool[0] == 'pg_restore':
                valid = bool(data) and data.startswith(b'PGDMP')
                if '--list' in tool:
                    return self.out(0 if valid else 1, b'', stdout)
                if not valid:
                    return podman.Result(1, b'', b'pg_restore: error: not a valid archive')
                self.db['data'] = bytes(data)
                return ok
            if tool[0] == 'pg_isready':
                return ok
            if tool[0] == 'createdb':
                self.db['databases'].add(tool[-1])
                return ok
            raise AssertionError(tool)
        if cmd == 'secret':
            verb, name = args[1], args[-1]
            if verb == 'inspect':
                return self.out(0, self.secrets[name] + b'\n', stdout) if name in self.secrets else missing
            if verb == 'exists':
                return podman.Result(0 if name in self.secrets else 1, b'', b'')
            if verb == 'rm':
                return ok if self.secrets.pop(name, None) is not None else missing
            if verb == 'create':
                name = args[2]
                assert args[3] == '-'
                if self.input_kind != 'pipe':  # verified with podman 4.9: a regular-file stdin is refused
                    return podman.Result(125, b'', b'Error: if `-` is used, data must be passed into stdin')
                if name in self.secrets or not data:
                    return podman.Result(125, b'', b'Error: secret name in use')
                self.secrets[name] = bytes(data)
                return ok
        if cmd == 'volume':
            verb = args[1]
            if verb == 'export':
                return self.out(0, self.volumes[args[2]], stdout) if args[2] in self.volumes else missing
            if verb == 'exists':
                return podman.Result(0 if args[2] in self.volumes else 1, b'', b'')
            if verb == 'rm':
                assert args[2] == '-f'
                self.volumes.pop(args[3], None)
                return ok
            if verb == 'create':
                if args[2] in self.volumes:
                    return podman.Result(125, b'', b'Error: volume already exists')
                self.volumes[args[2]] = b''
                return ok
            if verb == 'import':
                assert args[3] == '-'
                if args[2] not in self.volumes:
                    return missing
                self.volumes[args[2]] = bytes(data)
                return ok
            if verb == 'inspect':
                if args[-1] not in self.volumes:
                    return missing
                return self.out(0, f'/home/appowner/.local/share/containers/storage/volumes/{args[-1]}/_data\n'.encode(),
                                stdout)
        if cmd == 'unshare':
            assert args[1:6] == ['du', '-s', '-B1', '--apparent-size', '--']
            return self.out(0, b'4096\t' + args[6].encode() + b'\n', stdout)
        if cmd == 'image':
            verb, target = args[1], args[-1]
            if verb == 'inspect':
                if target not in self.images:
                    return missing
                info = [{'Id': self.images[target][7:], 'Digest': 'sha256:' + 'd' * 64, 'Architecture': self.arch,
                         'Size': 1000, 'Config': {'Env': self.image_env.get(target, [])}}]
                return self.out(0, json.dumps(info).encode(), stdout)
            if verb == 'exists':
                found = target in self.images or 'sha256:' + target in self.known_ids
                return podman.Result(0 if found else 1, b'', b'')
        if cmd == 'tag':
            self.images[args[2]] = 'sha256:' + args[1]
            return ok
        if cmd == 'save':
            assert args[1:4] == ['--quiet', '--format', 'oci-archive']
            return self.out(0, f'IMAGE|{args[-1]}|{self.images[args[-1]]}'.encode(), stdout)
        if cmd == 'load':
            assert args[1:] == ['--quiet']
            _, ref, image_id = data.decode().split('|')
            self.images[ref] = image_id
            self.known_ids.add(image_id)
            return ok
        if cmd == 'pull':
            if args[-1] not in self.pullable:
                return missing
            self.images[args[-1]] = 'sha256:' + 'c' * 64
            return ok
        if cmd == 'manifest':
            return podman.Result(0 if args[-1] in self.pullable else 125, b'', b'')
        if cmd in ('network', 'pod'):
            return ok
        raise AssertionError(args)


class FakeHttp:
    def __init__(self):
        self.health_status = 200
        self.summary = dict(SUMMARY)
        self.fail_summary = False
        self.calls = []

    def __call__(self, url, timeout):
        self.calls.append(url)
        if url.endswith('/healthz'):
            return self.health_status, b'ok'
        if url.endswith('/api/summary'):
            if self.fail_summary:
                raise OSError('connection refused')
            return 200, json.dumps(self.summary).encode()
        raise OSError('refused')


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


def extract_entries(entries, root):
    """Lay staged entries out as extract_archive would (root/<entry path>)."""
    for entry in entries:
        dest = Path(root) / entry.path
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(entry.source, dest)


class AdapterCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.paths = Paths(base=self.root)
        self.app = catalog.validate_entry(demo_entry(self.paths), paths=self.paths, user_lookup=user_lookup)
        self.owner = FakeOwner()
        self.http = FakeHttp()
        self.clock = FakeClock()
        self.logs, self.phases = [], []
        self.free = 10 ** 12
        self.adapter = self.make_adapter()
        self.staging = self.root / 'staging'
        self.staging.mkdir(mode=0o700)
        self.write_templates()

    def tearDown(self):
        self.tmp.cleanup()

    def make_adapter(self, owner=None):
        runner = podman.OwnerRunner('appowner', runner=owner or self.owner, user_lookup=user_lookup)
        self.hook_calls = []
        return qp.QuadletPostgresAdapter(
            self.app, runner, self.logs.append, phase=self.phases.append, writers_hook=self.hook_calls.append,
            http_get=self.http, clock=self.clock.now,
            sleep=self.clock.sleep, runtime_ready=lambda: True, templates_uid=os.getuid(),
            statvfs=lambda _path: types.SimpleNamespace(f_bavail=self.free // 4096, f_frsize=4096))

    def write_templates(self):
        folder = Path(self.app.template_dir)
        folder.mkdir(parents=True)
        for part in [folder, *folder.parents]:
            if part == self.root:
                break
            os.chmod(part, 0o755)
        for name, data in QUADLETS.items():
            (folder / name).write_bytes(data)
            os.chmod(folder / name, 0o644)

    def run_backup(self, include_images=False):
        return self.adapter.backup(self.staging / 'app', include_images=include_images)

    def everything_logged(self):
        return '\n'.join(self.logs)


GOLDEN_BACKUP = [
    helper('stat', Q + 'woowbk-demo.network', Q + 'woowbk-demo-db.container', Q + 'woowbk-demo-app.container'),
    [SYSTEMCTL, '--user', 'show', '--property=Id,LoadState,ActiveState,SubState', '--', 'woowbk-demo-db.service',
     'woowbk-demo-app.service'],
    helper('read', Q + 'woowbk-demo.network', '1048576'),
    helper('read', Q + 'woowbk-demo-db.container', '1048576'),
    helper('read', Q + 'woowbk-demo-app.container', '1048576'),
    [PODMAN, 'image', 'inspect', PG_REF],
    [PODMAN, 'image', 'inspect', APP_REF],
    [SYSTEMCTL, '--user', 'stop', '--', 'woowbk-demo-app.service'],
    psql('SHOW server_version_num'),
    psql('SHOW server_version'),
    [PODMAN, 'exec', 'woowbk-demo-db', 'pg_dump', '-w', '-U', 'notes', '-d', 'notes', '-Fc'],
    [PODMAN, 'exec', '-i', 'woowbk-demo-db', 'pg_restore', '--list'],
    helper('relay', PODMAN, 'volume', 'export', 'woowbk-demo-files'),
    [PODMAN, 'secret', 'inspect', '--showsecret', '--format', '{{.SecretData}}', 'woowbk-demo-db-password'],
    [PODMAN, 'secret', 'inspect', '--showsecret', '--format', '{{.SecretData}}', 'woowbk-demo-app-key'],
    helper('read', '.config/woowbk-demo/app.env', '16777216'),
    [SYSTEMCTL, '--user', 'start', '--', 'woowbk-demo-app.service'],
]


class BackupTests(AdapterCase):
    def test_registry(self):
        self.assertIs(get_adapter('quadlet-postgres'), qp.QuadletPostgresAdapter)
        self.assertIsNone(get_adapter('shell'))

    def test_exact_argv_and_manifest(self):
        manifest, entries = self.run_backup()
        self.assertEqual(self.owner.argvs(), GOLDEN_BACKUP)
        self.assertEqual(self.phases, ['stop', 'dump', 'export', 'start'])
        self.assertEqual(self.hook_calls, [['woowbk-demo-app.service'], []])
        self.assertEqual(manifest['owner'], {'name': 'appowner', 'uid': 1001})
        self.assertEqual(manifest['catalog_sha256'], self.app.sha256)
        self.assertEqual(manifest['postgres'], [{'id': 'main', 'database': 'notes', 'server_version': '16.15',
                                                 'major': 16, 'entry': 'apps/woowbk-demo/postgres/main.dump'}])
        self.assertEqual([i['ref'] for i in manifest['images']], [PG_REF, APP_REF])
        self.assertTrue(all('entry' not in i for i in manifest['images']))
        self.assertEqual(manifest['images'][0]['id'], PG_ID)
        self.assertEqual(manifest['verify_snapshot'], {'summary': {k: SUMMARY[k] for k in
                                                                   ('notes', 'files', 'digest', 'title', 'signatures_valid')}})
        self.assertEqual([e.path for e in entries], [
            'apps/woowbk-demo/postgres/main.dump', 'apps/woowbk-demo/volumes/woowbk-demo-files.tar',
            'apps/woowbk-demo/secrets/woowbk-demo-db-password', 'apps/woowbk-demo/secrets/woowbk-demo-app-key',
            'apps/woowbk-demo/config/0', 'apps/woowbk-demo/quadlet/woowbk-demo.network',
            'apps/woowbk-demo/quadlet/woowbk-demo-db.container', 'apps/woowbk-demo/quadlet/woowbk-demo-app.container'])
        contents = {e.path: e.source.read_bytes() for e in entries}
        self.assertEqual(contents['apps/woowbk-demo/postgres/main.dump'], DUMP)
        self.assertEqual(contents['apps/woowbk-demo/secrets/woowbk-demo-app-key'], APP_KEY)
        self.assertEqual(contents['apps/woowbk-demo/secrets/woowbk-demo-db-password'], DB_PASSWORD)
        self.assertEqual(contents['apps/woowbk-demo/config/0'], CONFIG)
        for entry in entries:
            self.assertEqual(entry.size, len(contents[entry.path]))
            self.assertEqual(entry.source.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.owner.units['woowbk-demo-app.service'], 'active')
        self.assertEqual(self.owner.units['woowbk-demo-db.service'], 'active')

    def test_include_images_saves_after_writers_restart(self):
        manifest, entries = self.run_backup(include_images=True)
        tail = self.owner.argvs()[len(GOLDEN_BACKUP):]
        self.assertEqual(tail, [[PODMAN, 'save', '--quiet', '--format', 'oci-archive', PG_REF],
                                [PODMAN, 'image', 'inspect', PG_REF],
                                [PODMAN, 'save', '--quiet', '--format', 'oci-archive', APP_REF],
                                [PODMAN, 'image', 'inspect', APP_REF]])
        self.assertEqual([i['entry'] for i in manifest['images']],
                         ['apps/woowbk-demo/images/0.oci.tar', 'apps/woowbk-demo/images/1.oci.tar'])
        self.assertEqual(entries[-1].path, 'apps/woowbk-demo/images/1.oci.tar')

    def test_secrets_never_in_argv_env_logs_or_errors(self):
        self.run_backup()
        for call in self.owner.calls:
            joined = '\0'.join(call['argv']).encode() + json.dumps(call['env']).encode()
            self.assertNotIn(DB_PASSWORD, joined)
            self.assertNotIn(APP_KEY.strip(b'\n'), joined)
        self.assertNotIn(DB_PASSWORD.decode(), self.everything_logged())
        self.owner.fail = [('secret inspect', 125)]
        with self.assertRaises(BackupError) as caught:
            self.make_adapter().backup(self.staging / 'again', include_images=False)
        self.assertNotIn(DB_PASSWORD.decode(), caught.exception.message + json.dumps(caught.exception.details))
        self.assertNotIn('Command was', self.everything_logged())

    def test_writers_restarted_whatever_step_fails(self):
        for needle in ('pg_dump', 'pg_restore --list', 'volume export', 'secret inspect',
                       'HELPER read .config/woowbk-demo/app.env', 'SHOW server_version_num'):
            with self.subTest(step=needle):
                owner = FakeOwner()
                owner.fail = [(needle, 1)]
                with self.assertRaises(BackupError):
                    self.make_adapter(owner).backup(self.staging / needle.replace(' ', '_').replace('/', '_'),
                                                    include_images=False)
                argvs = owner.argvs()
                self.assertIn([SYSTEMCTL, '--user', 'stop', '--', 'woowbk-demo-app.service'], argvs)
                self.assertEqual(argvs[-1], [SYSTEMCTL, '--user', 'start', '--', 'woowbk-demo-app.service'])
                self.assertEqual(owner.units['woowbk-demo-app.service'], 'active')

    def test_empty_or_invalid_dump_fails_and_restarts(self):
        self.owner.db['data'] = b'garbage'
        with self.assertRaises(BackupError):
            self.run_backup()
        self.assertEqual(self.owner.units['woowbk-demo-app.service'], 'active')

    def test_restart_failure_is_an_error(self):
        self.owner.fail = [('start -- woowbk-demo-app.service', 1)]
        with self.assertRaises(BackupError) as caught:
            self.run_backup()
        self.assertIn('woowbk-demo-app.service', caught.exception.message)
        starts = [a for a in self.owner.argvs() if a[:3] == [SYSTEMCTL, '--user', 'start']]
        self.assertEqual(len(starts), 2)  # one retry
        self.assertEqual(self.hook_calls, [['woowbk-demo-app.service'], ['woowbk-demo-app.service']])

    def test_inactive_writer_is_neither_stopped_nor_started(self):
        self.owner.units['woowbk-demo-app.service'] = 'inactive'
        self.http.fail_summary = True
        manifest, _ = self.run_backup()
        verbs = [a[2] for a in self.owner.argvs() if a[0] == SYSTEMCTL]
        self.assertNotIn('stop', verbs)
        self.assertNotIn('start', verbs)
        self.assertEqual(manifest['verify_snapshot'], {})
        self.assertIn('無法取得備份時的資料核對快照', self.everything_logged())

    def test_app_not_running_skips_post_backup_health_wait(self):
        # Integration finding: a safety backup of an app left down by a killed restore waited the whole
        # catalog health timeout (90 s) for an app the backup never stopped.
        self.owner.units['woowbk-demo-app.service'] = 'inactive'
        self.http.fail_summary = True
        self.http.health_status = 503
        start = self.clock.t
        self.run_backup()
        self.assertFalse([url for url in self.http.calls if url.endswith('/healthz')])
        self.assertEqual(self.adapter.last_downtime, 0.0)
        self.assertLess(self.clock.t - start, 5)
        self.assertIn('略過備份後的健康檢查', self.everything_logged())

    def test_running_app_still_gets_post_backup_health_check(self):
        self.http.health_status = 503
        self.run_backup()
        self.assertTrue([url for url in self.http.calls if url.endswith('/healthz')])
        self.assertIn('健康檢查未通過', self.everything_logged())
        self.assertGreater(self.adapter.last_downtime, -1)

    def test_database_must_be_running(self):
        self.owner.units['woowbk-demo-db.service'] = 'inactive'
        with self.assertRaises(BackupError) as caught:
            self.run_backup()
        self.assertIn('woowbk-demo-db.service', caught.exception.message)
        self.assertNotIn('stop', [a[2] for a in self.owner.argvs() if a[0] == SYSTEMCTL])

    def test_not_deployed(self):
        owner = FakeOwner(deployed=False)
        with self.assertRaises(BackupError) as caught:
            self.make_adapter(owner).backup(self.staging / 'x', include_images=False)
        self.assertEqual(caught.exception.code, 'not-deployed')

    def test_estimate_bytes(self):
        self.assertEqual(self.adapter.estimate_bytes(), 1024 * 1024 + 8000000 + 4096)
        self.assertEqual(self.adapter.estimate_bytes(include_images=True), 1024 * 1024 + 8000000 + 4096 + 2000)
        self.assertIn([PODMAN, 'unshare', 'du', '-s', '-B1', '--apparent-size', '--',
                       '/home/appowner/.local/share/containers/storage/volumes/woowbk-demo-files/_data'],
                      self.owner.argvs())
        del self.owner.volumes['woowbk-demo-files']
        with self.assertRaises(BackupError):
            self.adapter.estimate_bytes()


class ProbeTests(AdapterCase):
    def test_states(self):
        self.assertEqual(self.adapter.probe()['state'], 'running')
        self.owner.units['woowbk-demo-app.service'] = 'inactive'
        probe = self.adapter.probe()
        self.assertEqual((probe['state'], probe['units'][1]), ('partial', {'name': 'woowbk-demo-app.service',
                                                                          'active': False}))
        self.owner.units['woowbk-demo-db.service'] = 'failed'
        self.assertEqual(self.adapter.probe()['state'], 'stopped')
        del self.owner.files[Q + 'woowbk-demo.network']
        probe = self.adapter.probe()
        self.assertEqual(probe['state'], 'error')
        self.assertTrue(probe['problems'])
        self.assertEqual(self.make_adapter(FakeOwner(deployed=False)).probe(),
                         {'deployed': False, 'state': 'not-deployed', 'problems': [],
                          'units': [{'name': 'woowbk-demo-db.service', 'active': False},
                                    {'name': 'woowbk-demo-app.service', 'active': False}]})

    def test_symlinked_quadlet_is_a_problem(self):
        self.owner.links.add(Q + 'woowbk-demo-app.container')
        del self.owner.files[Q + 'woowbk-demo-app.container']
        probe = self.adapter.probe()
        self.assertEqual(probe['state'], 'error')
        with self.assertRaises(BackupError):
            self.adapter.detect_mode()

    def test_runtime_missing(self):
        adapter = self.make_adapter()
        adapter._runtime_ready_fn = lambda: False
        probe = adapter.probe()
        self.assertEqual(probe['state'], 'error')
        self.assertIn('linger', probe['problems'][0])
        self.assertEqual(self.owner.calls, [])

    def test_detect_mode(self):
        self.assertEqual(self.adapter.detect_mode(), 'inplace')
        self.assertEqual(self.make_adapter(FakeOwner(deployed=False)).detect_mode(), 'fresh')
        del self.owner.files[Q + 'woowbk-demo.network']
        with self.assertRaises(BackupError) as caught:
            self.adapter.detect_mode()
        self.assertEqual(caught.exception.code, 'incompatible')


class SafetyHelperTests(AdapterCase):
    def test_start_units_in_catalog_order(self):
        self.owner.units = {u: 'inactive' for u in self.owner.units}
        self.assertEqual(self.adapter.start_units(['woowbk-demo-app.service', 'woowbk-demo-db.service']), [])
        self.assertEqual(self.owner.argvs(), [[SYSTEMCTL, '--user', 'start', '--', 'woowbk-demo-db.service'],
                                              [SYSTEMCTL, '--user', 'start', '--', 'woowbk-demo-app.service']])
        self.owner.fail = [('start -- woowbk-demo-app.service', 1)]
        self.assertEqual(self.adapter.start_units(['woowbk-demo-app.service']), ['woowbk-demo-app.service'])

    def test_ensure_databases_running_starts_only_stopped_databases(self):
        self.assertEqual(self.adapter.ensure_databases_running(), [])
        self.owner.calls.clear()
        self.owner.units['woowbk-demo-db.service'] = 'inactive'
        self.assertEqual(self.adapter.ensure_databases_running(), ['woowbk-demo-db.service'])
        self.assertEqual(self.owner.argvs(), [
            [SYSTEMCTL, '--user', 'show', '--property=Id,LoadState,ActiveState,SubState', '--', 'woowbk-demo-db.service',
             'woowbk-demo-app.service'],
            [SYSTEMCTL, '--user', 'start', '--', 'woowbk-demo-db.service'],
            [PODMAN, 'exec', 'woowbk-demo-db', 'pg_isready', '-h', '127.0.0.1', '-p', '5432', '-U', 'notes', '-d',
             'notes', '-t', '5']])
        self.owner.units['woowbk-demo-db.service'] = 'inactive'
        self.owner.fail = [('start -- woowbk-demo-db.service', 1)]
        with self.assertRaises(BackupError):
            self.adapter.ensure_databases_running()

    def test_secret_bytes_are_fed_through_a_pipe(self):
        manifest, entries = self.run_backup()
        extract = self.root / 'x'
        extract_entries(entries, extract)
        owner = FakeOwner()
        self.make_adapter(owner).restore(manifest, extract, mode='inplace')
        kinds = {c['kind'] for c in owner.calls if c['argv'][:3] == [PODMAN, 'secret', 'create']}
        self.assertEqual(kinds, {'pipe'})


class RestoreTests(AdapterCase):
    def setUp(self):
        super().setUp()
        self.manifest, self.entries = self.run_backup(include_images=self.include_images())
        self.extract = self.root / 'extract'
        self.extract.mkdir(mode=0o700)
        extract_entries(self.entries, self.extract)
        self.logs.clear()
        self.phases.clear()

    def include_images(self):
        return False

    def mutate(self, owner):
        owner.secrets['woowbk-demo-db-password'] = b'changed'
        owner.volumes['woowbk-demo-files'] = b'TAR!changed'
        owner.files['.config/woowbk-demo/app.env'] = b'TITLE=Changed\n'
        owner.db['data'] = b'PGDMPchanged'

    def test_inplace_exact_argv_and_state(self):
        owner = FakeOwner()
        self.mutate(owner)
        adapter = self.make_adapter(owner)
        adapter.restore(self.manifest, self.extract, mode='inplace')
        if self.include_images():  # included images are loaded, then the ref is checked
            images = [[PODMAN, 'load', '--quiet'], [PODMAN, 'image', 'inspect', PG_REF],
                      [PODMAN, 'load', '--quiet'], [PODMAN, 'image', 'inspect', APP_REF]]
        else:  # the exact image used at backup time is still present: only (re)tag if needed
            images = [[PODMAN, 'image', 'exists', 'a' * 64], [PODMAN, 'image', 'inspect', PG_REF],
                      [PODMAN, 'image', 'exists', 'b' * 64], [PODMAN, 'image', 'inspect', APP_REF]]
        self.assertEqual(owner.argvs(), [
            helper('read', Q + 'woowbk-demo.network', '1048576'),
            helper('read', Q + 'woowbk-demo-db.container', '1048576'),
            helper('read', Q + 'woowbk-demo-app.container', '1048576'),
            *images,
            [SYSTEMCTL, '--user', 'stop', '--', 'woowbk-demo-app.service'],
            [SYSTEMCTL, '--user', 'stop', '--', 'woowbk-demo-db.service'],
            [SYSTEMCTL, '--user', 'stop', '--', 'woowbk-demo-network.service'],
            [PODMAN, 'secret', 'exists', 'woowbk-demo-db-password'], [PODMAN, 'secret', 'rm', 'woowbk-demo-db-password'],
            [PODMAN, 'secret', 'create', 'woowbk-demo-db-password', '-'],
            [PODMAN, 'secret', 'exists', 'woowbk-demo-app-key'], [PODMAN, 'secret', 'rm', 'woowbk-demo-app-key'],
            [PODMAN, 'secret', 'create', 'woowbk-demo-app-key', '-'],
            helper('write', '.config/woowbk-demo/app.env', '0600', '16777216'),
            [PODMAN, 'volume', 'rm', '-f', 'woowbk-demo-files'], [PODMAN, 'volume', 'create', 'woowbk-demo-files'],
            [PODMAN, 'volume', 'import', 'woowbk-demo-files', '-'],
            [PODMAN, 'volume', 'rm', '-f', 'woowbk-demo-pgdata'],
            [SYSTEMCTL, '--user', 'start', '--', 'woowbk-demo-db.service'],
            [PODMAN, 'exec', 'woowbk-demo-db', 'pg_isready', '-h', '127.0.0.1', '-p', '5432', '-U', 'notes', '-d',
             'notes', '-t', '5'],
            psql('SHOW server_version_num', 'postgres'),
            psql("SELECT 1 FROM pg_database WHERE datname = 'notes'", 'postgres'),
            [PODMAN, 'exec', '-i', 'woowbk-demo-db', 'pg_restore', '--exit-on-error', '--single-transaction',
             '--no-owner', '--no-privileges', '-w', '-U', 'notes', '-d', 'notes'],
            [SYSTEMCTL, '--user', 'start', '--', 'woowbk-demo-app.service'],
        ])
        self.assertEqual(self.phases, ['stop', 'restore', 'start'])
        self.assertTrue(adapter.destructive_started)
        self.assertEqual(owner.secrets, {'woowbk-demo-db-password': DB_PASSWORD, 'woowbk-demo-app-key': APP_KEY})
        self.assertEqual(owner.volumes['woowbk-demo-files'], VOLUME_TAR)
        self.assertNotIn('woowbk-demo-pgdata', owner.volumes)
        self.assertEqual(owner.files['.config/woowbk-demo/app.env'], CONFIG)
        self.assertEqual(owner.db['data'], DUMP)
        self.assertEqual(set(owner.units.values()), {'active'})
        for call in owner.calls:  # secret bytes only ever travel on stdin
            self.assertNotIn(DB_PASSWORD, '\0'.join(call['argv']).encode())
        creates = [c for c in owner.calls if c['argv'][:3] == [PODMAN, 'secret', 'create']]
        self.assertEqual([c['input'] for c in creates], [DB_PASSWORD, APP_KEY])
        self.assertNotIn(DB_PASSWORD.decode(), self.everything_logged())

    def test_destructive_flag_tracks_first_change(self):
        owner = FakeOwner()
        owner.fail = [('HELPER read ' + Q + 'woowbk-demo-db.container', 3)]
        adapter = self.make_adapter(owner)
        with self.assertRaises(BackupError):
            adapter.restore(self.manifest, self.extract, mode='inplace')
        self.assertFalse(adapter.destructive_started)
        self.assertEqual(set(owner.units.values()), {'active'})
        owner = FakeOwner()
        owner.fail = [('volume import', 125)]
        adapter = self.make_adapter(owner)
        with self.assertRaises(BackupError):
            adapter.restore(self.manifest, self.extract, mode='inplace')
        self.assertTrue(adapter.destructive_started)

    def test_missing_local_items_and_bad_entries(self):
        manifest = json.loads(json.dumps(self.manifest))
        manifest['secrets'] = manifest['secrets'][:1]
        with self.assertRaises(BackupError) as caught:
            self.make_adapter(FakeOwner()).restore(manifest, self.extract, mode='inplace')
        self.assertEqual(caught.exception.code, 'incompatible')
        for bad in ('apps/other-app/volumes/woowbk-demo-files.tar', '../../etc/passwd',
                    'apps/woowbk-demo/volumes/missing.tar'):
            manifest = json.loads(json.dumps(self.manifest))
            manifest['volumes'][0]['entry'] = bad
            owner = FakeOwner()
            with self.assertRaises(BackupError) as caught:
                self.make_adapter(owner).restore(manifest, self.extract, mode='inplace')
            self.assertEqual(caught.exception.code, 'corrupt-archive')
            self.assertEqual(owner.calls, [])
        victim = self.extract / 'apps/woowbk-demo/volumes/woowbk-demo-files.tar'
        victim.unlink()
        os.symlink('/etc/passwd', victim)
        with self.assertRaises(BackupError) as caught:
            self.make_adapter(FakeOwner()).restore(self.manifest, self.extract, mode='inplace')
        self.assertEqual(caught.exception.code, 'corrupt-archive')

    def test_target_postgres_older_than_backup(self):
        owner = FakeOwner()
        owner.db['num'] = '150004'
        with self.assertRaises(BackupError) as caught:
            self.make_adapter(owner).restore(self.manifest, self.extract, mode='inplace')
        self.assertEqual(caught.exception.code, 'incompatible')

    def test_extra_archive_items_are_ignored(self):
        manifest = json.loads(json.dumps(self.manifest))
        manifest['secrets'].append({'name': 'not-in-catalog', 'entry': 'apps/woowbk-demo/secrets/not-in-catalog'})
        owner = FakeOwner()
        self.make_adapter(owner).restore(manifest, self.extract, mode='inplace')
        self.assertNotIn('not-in-catalog', owner.secrets)


class FreshRestoreTests(RestoreTests):
    def include_images(self):
        return True

    def test_fresh_installs_trusted_templates_and_loads_images(self):
        owner = FakeOwner(deployed=False)
        owner.images, owner.known_ids = {}, set()
        adapter = self.make_adapter(owner)
        adapter.restore(self.manifest, self.extract, mode='fresh')
        argvs = owner.argvs()
        self.assertEqual(argvs[:4], [[PODMAN, 'load', '--quiet'], [PODMAN, 'image', 'inspect', PG_REF],
                                     [PODMAN, 'load', '--quiet'], [PODMAN, 'image', 'inspect', APP_REF]])
        writes = [a for a in argvs if a[:5] == helper('write')]
        self.assertEqual([w[5:] for w in writes[:3]], [[Q + 'woowbk-demo.network', '0644', '16777216'],
                                                       [Q + 'woowbk-demo-db.container', '0644', '16777216'],
                                                       [Q + 'woowbk-demo-app.container', '0644', '16777216']])
        self.assertEqual(argvs[argvs.index(writes[2]) + 1: argvs.index(writes[2]) + 3],
                         [[SYSTEMCTL, '--user', 'daemon-reload'],
                          [SYSTEMCTL, '--user', 'stop', '--', 'woowbk-demo-network.service']])
        self.assertNotIn([SYSTEMCTL, '--user', 'stop', '--', 'woowbk-demo-db.service'], argvs)
        self.assertEqual([owner.files[Q + n] for n in QUADLETS], list(QUADLETS.values()))
        self.assertEqual(owner.secrets['woowbk-demo-db-password'], DB_PASSWORD)
        self.assertEqual(owner.volumes['woowbk-demo-files'], VOLUME_TAR)
        self.assertEqual(owner.db['data'], DUMP)
        self.assertEqual(owner.units, {'woowbk-demo-db.service': 'active', 'woowbk-demo-app.service': 'active'})
        self.assertEqual(owner.images[APP_REF], APP_ID)

    def test_fresh_cleanup_removes_everything_declared(self):
        owner = FakeOwner(deployed=False)
        adapter = self.make_adapter(owner)
        adapter.restore(self.manifest, self.extract, mode='fresh')
        owner.calls.clear()
        adapter.remove_fresh()
        self.assertEqual(owner.argvs(), [
            [SYSTEMCTL, '--user', 'stop', '--', 'woowbk-demo-app.service'],
            [SYSTEMCTL, '--user', 'stop', '--', 'woowbk-demo-db.service'],
            [SYSTEMCTL, '--user', 'stop', '--', 'woowbk-demo-network.service'],
            helper('remove', Q + 'woowbk-demo.network'), helper('remove', Q + 'woowbk-demo-db.container'),
            helper('remove', Q + 'woowbk-demo-app.container'),
            [SYSTEMCTL, '--user', 'daemon-reload'],
            [SYSTEMCTL, '--user', 'reset-failed', '--', 'woowbk-demo-db.service'],
            [SYSTEMCTL, '--user', 'reset-failed', '--', 'woowbk-demo-app.service'],
            [SYSTEMCTL, '--user', 'reset-failed', '--', 'woowbk-demo-network.service'],
            [PODMAN, 'volume', 'rm', '-f', 'woowbk-demo-pgdata'], [PODMAN, 'volume', 'rm', '-f', 'woowbk-demo-files'],
            [PODMAN, 'secret', 'exists', 'woowbk-demo-db-password'], [PODMAN, 'secret', 'rm', 'woowbk-demo-db-password'],
            [PODMAN, 'secret', 'exists', 'woowbk-demo-app-key'], [PODMAN, 'secret', 'rm', 'woowbk-demo-app-key'],
            helper('remove', '.config/woowbk-demo/app.env'),
            [PODMAN, 'network', 'rm', '-f', 'systemd-woowbk-demo'],
        ])
        self.assertEqual((owner.files, owner.secrets, owner.volumes, owner.units), ({}, {}, {}, {}))

    def test_untrusted_templates_are_refused(self):
        os.chmod(Path(self.app.template_dir) / 'woowbk-demo-db.container', 0o666)
        owner = FakeOwner(deployed=False)
        with self.assertRaises(BackupError) as caught:
            self.make_adapter(owner).restore(self.manifest, self.extract, mode='fresh')
        self.assertEqual(caught.exception.code, 'permission-denied')
        self.assertEqual(owner.calls, [])


class PreflightTests(AdapterCase):
    def setUp(self):
        super().setUp()
        self.manifest, self.entries = self.run_backup(include_images=False)
        self.sizes = {e.path: e.size for e in self.entries}

    def statuses(self, checks):
        return {c['id']: c['status'] for c in checks}

    def test_inplace_ok(self):
        checks = self.adapter.preflight(self.manifest, mode='inplace', entry_sizes=self.sizes)
        self.assertNotIn('fail', self.statuses(checks).values(), checks)
        self.assertIn('woowbk-demo/safety', self.statuses(checks))
        self.assertTrue(all(c['message'] for c in checks))
        self.assertEqual(len({c['id'] for c in checks}), len(checks))

    def test_missing_and_extra_items(self):
        manifest = json.loads(json.dumps(self.manifest))
        manifest['volumes'] = []
        manifest['secrets'].append({'name': 'extra', 'entry': 'apps/woowbk-demo/secrets/extra'})
        statuses = self.statuses(self.adapter.preflight(manifest, mode='inplace'))
        self.assertEqual((statuses['woowbk-demo/items'], statuses['woowbk-demo/extra']), ('fail', 'warn'))

    def test_newer_adapter_and_catalog_drift(self):
        manifest = dict(self.manifest, adapter_version=2, catalog_sha256='0' * 64)
        statuses = self.statuses(self.adapter.preflight(manifest, mode='inplace'))
        self.assertEqual((statuses['woowbk-demo/adapter'], statuses['woowbk-demo/catalog']), ('fail', 'warn'))

    def test_fresh_missing_local_only_image_fails(self):
        owner = FakeOwner(deployed=False)
        owner.images = {PG_REF: PG_ID}
        owner.pullable = {PG_REF}
        checks = self.make_adapter(owner).preflight(self.manifest, mode='fresh', entry_sizes=self.sizes)
        failing = [c['message'] for c in checks if c['status'] == 'fail']
        self.assertEqual(len(failing), 1)
        self.assertIn(APP_REF, failing[0])

    def test_fresh_existing_volume_conflicts(self):
        owner = FakeOwner(deployed=False)
        owner.volumes = {'woowbk-demo-pgdata': b'old'}
        owner.secrets = {'woowbk-demo-app-key': b'old'}
        statuses = self.statuses(self.make_adapter(owner).preflight(self.manifest, mode='fresh'))
        self.assertEqual(statuses['woowbk-demo/volume-conflict'], 'fail')
        self.assertEqual(statuses['woowbk-demo/secret-existing'], 'warn')

    def test_included_image_with_other_arch(self):
        manifest = json.loads(json.dumps(self.manifest))
        manifest['images'][1].update(entry='apps/woowbk-demo/images/1.oci.tar', arch='riscv64')
        owner = FakeOwner()
        statuses = [c for c in self.make_adapter(owner).preflight(manifest, mode='inplace') if c['status'] == 'fail']
        self.assertTrue(any('riscv64' in c['message'] for c in statuses))

    def test_postgres_major_rules(self):
        manifest = json.loads(json.dumps(self.manifest))
        manifest['postgres'][0]['major'] = 17
        failing = [c for c in self.adapter.preflight(manifest, mode='inplace') if c['status'] == 'fail']
        self.assertTrue(any('17' in c['message'] for c in failing))
        self.owner.image_env[PG_REF] = []
        warn = [c for c in self.adapter.preflight(self.manifest, mode='inplace')
                if c['id'].startswith('woowbk-demo/postgres-version')]
        self.assertEqual(warn[0]['status'], 'warn')

    def test_stopped_database_is_flagged_for_safety_backup(self):
        self.owner.units['woowbk-demo-db.service'] = 'inactive'
        statuses = self.statuses(self.adapter.preflight(self.manifest, mode='inplace'))
        self.assertEqual(statuses['woowbk-demo/database-down'], 'warn')

    def test_space_check_on_owner_home(self):
        self.free = 100
        statuses = self.statuses(self.adapter.preflight(self.manifest, mode='inplace', entry_sizes=self.sizes))
        self.assertEqual(statuses['woowbk-demo/space'], 'fail')

    def test_missing_units_and_templates(self):
        del self.owner.units['woowbk-demo-app.service']
        self.assertEqual(self.statuses(self.adapter.preflight(self.manifest, mode='inplace'))['woowbk-demo/units'],
                         'fail')
        shutil.rmtree(self.app.template_dir)
        owner = FakeOwner(deployed=False)
        statuses = self.statuses(self.make_adapter(owner).preflight(self.manifest, mode='fresh'))
        self.assertEqual(statuses['woowbk-demo/templates'], 'fail')


class CheckTests(AdapterCase):
    def test_health_ok_and_timeout(self):
        self.assertEqual(self.adapter.health(), [{'id': 'woowbk-demo/health-1', 'status': 'ok',
                                                  'message': '健康檢查通過（http://127.0.0.1:18090/healthz）'}])
        self.http.health_status = 503
        start = self.clock.t
        checks = self.adapter.health()
        self.assertEqual(checks[0]['status'], 'fail')
        self.assertIn('HTTP 503', checks[0]['message'])
        self.assertGreaterEqual(self.clock.t - start, 90)

    def test_verify_snapshot(self):
        self.assertEqual(self.adapter.verify_snapshot(), {'summary': {'notes': 12, 'files': 4, 'digest': 'abc',
                                                                      'title': 'Demo', 'signatures_valid': True}})
        self.http.fail_summary = True
        with self.assertRaises(BackupError):
            self.adapter.verify_snapshot()

    def test_quadlet_parsing(self):
        sections = qp.parse_unit_file('[Container]\nImage=a\\\n  b\n;c\n#Image=x\nImage=final\n')
        self.assertEqual(qp.last_value(sections, 'Container', 'Image'), 'final')
        self.assertEqual(qp.quadlet_unit('x.network'), 'x-network.service')
        self.assertEqual(qp.quadlet_unit('x.container'), 'x.service')
        for bad in (b'[Container]\nImage=-rm evil\n', b'[Container]\nImage=x y\n', b'[Container]\nImage=app.image\n'):
            with self.assertRaises(BackupError):
                self.adapter.container_images({'woowbk-demo-db.container': bad})


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == '/json':
            body = b'{"notes": 1}'
            self.send_response(200)
        elif self.path == '/redirect':
            body = b''
            self.send_response(302)
            self.send_header('Location', 'http://192.0.2.1/')
        elif self.path == '/big':
            body = b'x' * (qp.MAX_HTTP_BODY + 10)
            self.send_response(200)
        else:
            body = b'no'
            self.send_response(404)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class LoopbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_real_loopback_get(self):
        self.assertEqual(qp.loopback_get(f'http://127.0.0.1:{self.port}/json', 5), (200, b'{"notes": 1}'))
        self.assertEqual(qp.loopback_get(f'http://127.0.0.1:{self.port}/missing', 5)[0], 404)
        self.assertEqual(qp.loopback_get(f'http://127.0.0.1:{self.port}/redirect', 5)[0], 302)
        with self.assertRaises(ValueError):
            qp.loopback_get(f'http://127.0.0.1:{self.port}/big', 5)

    def test_ignores_proxy_environment(self):
        os.environ['http_proxy'] = 'http://192.0.2.1:9'
        try:
            self.assertEqual(qp.loopback_get(f'http://127.0.0.1:{self.port}/json', 5)[0], 200)
        finally:
            del os.environ['http_proxy']

    def test_refuses_non_loopback(self):
        for url in ('http://192.0.2.1/x', 'https://127.0.0.1/x', 'http://user:pw@127.0.0.1:1/x'):
            with self.assertRaises(ValueError):
                qp.loopback_get(url, 1)


if __name__ == '__main__':
    unittest.main()
