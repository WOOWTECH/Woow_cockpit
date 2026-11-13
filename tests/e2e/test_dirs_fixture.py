"""Offline checks of the woowbk-dirs fixture (no containers, no PostgreSQL, no pg8000 needed).

    python3 -B -m unittest discover -s tests/e2e -p 'test_*.py' -v

The live behaviour (real PostgreSQL in a host directory, container uids 33/70, Podman secrets, Quadlet units)
is exercised in the lab by tests/e2e/lab/deploy-dirs.sh, catalog-examples/woowbk-dirs/tools/check.py and
tests/e2e/lab/dirs_e2e.py.
"""
import base64
import datetime
import hashlib
import hmac
import importlib.util
import json
import os
import posixpath
import pwd
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'catalog-examples' / 'woowbk-dirs'
LAB = ROOT / 'tests' / 'e2e' / 'lab'
sys.path.insert(0, str(ROOT / 'backup-engine'))
sys.dont_write_bytecode = True

SUMMARY_KEYS = ['items', 'events', 'db_digest', 'db_meta', 'tree', 'tree_digest', 'sqlite', 'title', 'signatures_valid']
# Feature spec (catalog `data_dirs`): forbidden roots and the segment alphabet of a host directory path.
FORBIDDEN_DIRS = ('.ssh', '.gnupg', '.config/systemd', '.config/containers', '.local/share/containers',
                  '.config/environment.d', '.config/autostart', '.config/dbus-1')
SEGMENT_RE = re.compile(r'[A-Za-z0-9._@+-]+\Z')


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_unit(text):
    sections, current = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in '#;':
            continue
        if line.startswith('[') and line.endswith(']'):
            current = sections.setdefault(line[1:-1], [])
            continue
        key, value = line.split('=', 1)
        current.append((key.strip(), value.strip()))
    return sections


def values(sections, section, key):
    return [v for k, v in sections.get(section, []) if k == key]


def load_catalog():
    from woowbackup import catalog
    return catalog.parse_json_bytes((FIXTURE / 'catalog.json').read_bytes())


def inside(path, root):
    return path == root or path.startswith(root + '/')


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.data = load_catalog()
        self.units = {p.name: parse_unit(p.read_text(encoding='utf-8')) for p in (FIXTURE / 'quadlet').iterdir()}

    def account(self):
        return pwd.struct_passwd(('appowner', 'x', 1001, 1001, '', '/home/appowner', '/bin/bash'))

    def test_engine_validator_accepts_everything_but_data_dirs(self):
        # Holds with every engine: the rest of the entry (cold database, secrets, config file, checks) is valid.
        from woowbackup import catalog
        from woowbackup.paths import Paths
        rest = {k: v for k, v in self.data.items() if k != 'data_dirs'}
        app = catalog.validate_entry(rest, paths=Paths(), user_lookup=lambda _name: self.account())
        self.assertEqual(app.id, 'woowbk-dirs')
        self.assertEqual(app.postgres, ())
        self.assertEqual(app.writer_units, app.units)

    def test_engine_validator_accepts_data_dirs(self):
        from woowbackup import catalog
        from woowbackup.paths import Paths
        if 'data_dirs' not in getattr(catalog, 'TOP_OPTIONAL', ()):
            self.skipTest('installed engine library has no catalog data_dirs support yet')
        app = catalog.validate_entry(self.data, paths=Paths(), user_lookup=lambda _name: self.account())
        dirs = getattr(app, 'data_dirs', None)
        self.assertIsNotNone(dirs, 'App has no data_dirs attribute')
        paths = [d['path'] if isinstance(d, dict) else getattr(d, 'path') for d in dirs]
        self.assertEqual(paths, [d['path'] for d in self.data['data_dirs']])

    def test_data_dirs_follow_the_path_rules(self):
        dirs = self.data['data_dirs']
        self.assertTrue(1 <= len(dirs) <= 16)
        paths = []
        for item in dirs:
            self.assertLessEqual(set(item), {'path', 'label'})
            path = item['path']
            self.assertEqual(posixpath.normpath(path), path)
            self.assertFalse(path.startswith('/') or path in ('', '.'))
            for segment in path.split('/'):
                self.assertNotIn(segment, ('', '.', '..'))
                self.assertRegex(segment, SEGMENT_RE)
            for forbidden in FORBIDDEN_DIRS:
                self.assertFalse(inside(path, forbidden), f'{path} is inside {forbidden}')
            self.assertIsInstance(item.get('label', ''), str)
            paths.append(path)
        configs = [c['path'] for c in self.data['config_files']]
        for i, path in enumerate(paths):
            for other in paths[i + 1:] + configs:
                self.assertFalse(inside(other, path) or inside(path, other), f'{path} overlaps {other}')

    def test_cold_database_pattern(self):
        # No pg_dump entries; every unit (the database included) is stopped during a backup.
        self.assertEqual(self.data['postgres'], [])
        self.assertNotIn('volumes', self.data)
        self.assertEqual(self.data['units'][0], 'woowbk-dirs-db.service')
        self.assertEqual(self.data['writer_units'], self.data['units'])
        db = self.units['woowbk-dirs-db.container']
        mounts = values(db, 'Container', 'Volume')
        self.assertEqual(mounts, [f'%h/{self.data["data_dirs"][0]["path"]}:/var/lib/postgresql/data'])
        args = ' '.join(values(db, 'Container', 'PodmanArgs'))
        self.assertIn('--stop-timeout 60', args)  # time for a clean (fast) shutdown before the copy

    def test_templates_agree_with_catalog(self):
        data = self.data
        self.assertEqual(sorted(self.units), sorted(data['quadlet']['files']))
        self.assertEqual(data['quadlet']['template_dir'],
                         '/usr/local/share/woowtech-cockpit-backup/catalog/woowbk-dirs/quadlet')
        self.assertEqual(values(self.units['woowbk-dirs.network'], 'Network', 'NetworkName'), ['woowbk-dirs'])
        db, app = self.units['woowbk-dirs-db.container'], self.units['woowbk-dirs-app.container']
        self.assertEqual(values(db, 'Container', 'ContainerName'), ['woowbk-dirs-db'])
        self.assertEqual(values(db, 'Container', 'Image'), ['docker.io/library/postgres:16-alpine'])
        self.assertEqual(values(db, 'Container', 'User'), ['70:70'])
        self.assertIn('woowbk-dirs-db-password,type=env,target=POSTGRES_PASSWORD', values(db, 'Container', 'Secret'))
        self.assertEqual(values(app, 'Container', 'ContainerName'), ['woowbk-dirs-app'])
        self.assertEqual(values(app, 'Container', 'Image'), ['localhost/woowbk-dirs-app:1'])
        self.assertEqual(values(app, 'Container', 'User'), ['33:33'])
        self.assertEqual(values(app, 'Container', 'Volume'), [f'%h/{data["data_dirs"][1]["path"]}:/srv/data'])
        self.assertEqual(sorted(values(app, 'Container', 'Secret') + ['woowbk-dirs-db-password']),
                         sorted(s['name'] for s in data['secrets']))
        self.assertEqual(values(app, 'Container', 'EnvironmentFile'), [f'%h/{data["config_files"][0]["path"]}'])
        self.assertEqual(values(app, 'Unit', 'Requires'), ['woowbk-dirs-db.service'])
        self.assertEqual(values(app, 'Unit', 'After'), ['woowbk-dirs-db.service'])
        self.assertTrue(values(app, 'Container', 'PublishPort')[0].startswith('127.0.0.1:18091:'))
        for url in [h['url'] for h in data['health']] + [v['url'] for v in data['verify']]:
            self.assertTrue(url.startswith('http://127.0.0.1:18091/'), url)
        for unit in (db, app):
            self.assertTrue(any('--memory ' in v for v in values(unit, 'Container', 'PodmanArgs')))
            self.assertEqual(values(unit, 'Install', 'WantedBy'), ['default.target'])

    def test_every_host_mount_is_declared_and_never_fixed_up(self):
        # Review checklist: each `Volume=%h/...` is a declared host directory; no :U/:Z/:O option that would repair
        # or hide ownership at start (ownership must come from the restore).
        declared = {d['path'] for d in self.data['data_dirs']}
        mounted = set()
        for name, unit in self.units.items():
            for volume in values(unit, 'Container', 'Volume'):
                source, _target, *options = volume.split(':')
                self.assertTrue(source.startswith('%h/'), f'{name}: {volume} is not a host directory')
                mounted.add(source[3:])
                self.assertEqual(options, [], f'{name}: {volume} has mount options')
        self.assertEqual(mounted, declared)

    def test_verify_compares_every_summary_key(self):
        self.assertEqual(self.data['verify'][0]['compare'], SUMMARY_KEYS)
        check = load_module('woowbk_dirs_check', FIXTURE / 'tools' / 'check.py')
        self.assertEqual(check.SUMMARY_KEYS, set(SUMMARY_KEYS))

    def test_adapter_reads_images_from_templates(self):
        try:
            from woowbackup.adapters import quadlet_postgres as qp
        except Exception as error:  # noqa: BLE001 - engine modules are owned by other teams
            self.skipTest(f'engine adapter not importable: {error}')
        sources = {p.name: p.read_bytes() for p in (FIXTURE / 'quadlet').iterdir()}
        adapter = qp.QuadletPostgresAdapter.__new__(qp.QuadletPostgresAdapter)
        adapter.app = type('App', (), {'quadlet_files': tuple(self.data['quadlet']['files']), 'id': 'woowbk-dirs'})()
        self.assertEqual(adapter.container_images(sources),
                         {'woowbk-dirs-db.service': 'docker.io/library/postgres:16-alpine',
                          'woowbk-dirs-app.service': 'localhost/woowbk-dirs-app:1'})


def xattrs_supported(directory):
    probe = os.path.join(directory, '.xattr-probe')
    with open(probe, 'wb'):
        pass
    try:
        os.setxattr(probe, 'user.probe', b'1')
        return True
    except OSError:
        return False
    finally:
        os.unlink(probe)


class TreelistTests(unittest.TestCase):
    def setUp(self):
        self.treelist = load_module('woowbk_dirs_treelist', FIXTURE / 'app' / 'treelist.py')
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / 'data'
        root = self.root
        (root / 'www' / 'docs' / 'ab' / 'cd').mkdir(parents=True)
        (root / 'www' / 'archive').mkdir()
        (root / 'empty').mkdir()
        doc = root / 'www' / 'docs' / 'ab' / 'cd' / '00001-a.txt'
        doc.write_bytes(b'hello\n')
        os.utime(doc, (1700000000.7, 1700000000.7))
        os.link(doc, root / 'www' / 'archive' / '00001-a.txt')
        (root / 'www' / 'latest').symlink_to('docs/ab/cd/00001-a.txt')
        (root / 'escape').symlink_to('/etc/passwd')
        (root / '共享').mkdir()
        (root / '共享' / '說明 文件.txt').write_text('中文\n', encoding='utf-8')
        os.mkfifo(root / 'pipe')
        (root / 'www' / 'app.sqlite').write_bytes(b'SQLite format 3\x00' + b'\x00' * 100)
        for volatile in ('app.sqlite-wal', 'app.sqlite-shm', 'x-journal', '.healthz-1', '.tmp-latest-1'):
            (root / 'www' / volatile).write_bytes(b'volatile')
        (root / os.fsdecode(b'raw-\xff.bin')).write_bytes(b'x')
        self.xattrs = xattrs_supported(str(root))
        if self.xattrs:
            os.setxattr(doc, 'user.woowbk.item', b'1')

    def tearDown(self):
        self.tmp.cleanup()

    def test_listing(self):
        entries = self.treelist.listing(self.root)
        index = {e['path']: e for e in entries}
        self.assertEqual(entries[0]['path'], '.')
        self.assertEqual([e['path'] for e in entries],
                         ['.', 'empty', 'escape', 'pipe', 'raw-\\xff.bin', 'www', 'www/app.sqlite', 'www/archive',
                          'www/archive/00001-a.txt', 'www/docs', 'www/docs/ab', 'www/docs/ab/cd',
                          'www/docs/ab/cd/00001-a.txt', 'www/latest', '共享', '共享/說明 文件.txt'])
        archive, doc = index['www/archive/00001-a.txt'], index['www/docs/ab/cd/00001-a.txt']
        self.assertEqual((archive['type'], archive['size'], archive['sha256'], archive['mtime']),
                         ('file', 6, hashlib.sha256(b'hello\n').hexdigest(), 1700000000))
        self.assertNotIn('link', archive)            # first name in walk order
        self.assertEqual(doc['link'], 'www/archive/00001-a.txt')
        self.assertEqual(index['www/latest'], {'path': 'www/latest', 'type': 'symlink', 'mode': '0777',
                                               'uid': os.getuid(), 'gid': os.getgid(),
                                               'target': 'docs/ab/cd/00001-a.txt'})
        self.assertEqual(index['escape']['target'], '/etc/passwd')  # recorded, never followed
        self.assertEqual(index['pipe']['type'], 'fifo')
        self.assertEqual(set(index['www/app.sqlite']), {'path', 'type', 'mode', 'uid', 'gid'})
        self.assertEqual(index['empty']['type'], 'dir')
        self.assertNotIn('mtime', index['www'])
        if self.xattrs:
            self.assertEqual(doc['xattrs'], {'user.woowbk.item': hashlib.sha256(b'1').hexdigest()})
        report = json.loads(subprocess.run([sys.executable, '-I', '-B', str(FIXTURE / 'app' / 'treelist.py'),
                                            str(self.root)], capture_output=True, check=True).stdout)
        self.assertEqual((report['count'], report['digest']), (len(entries), self.treelist.digest(entries)))

    def test_digest_tracks_what_a_restore_must_keep(self):
        base = self.treelist.digest(self.treelist.listing(self.root))
        doc = self.root / 'www' / 'docs' / 'ab' / 'cd' / '00001-a.txt'
        (self.root / 'www' / 'app.sqlite-wal').write_bytes(b'changed')       # volatile: ignored
        (self.root / 'www' / '.healthz-2').write_bytes(b'probe')
        os.utime(self.root / 'www', (1, 1))                                    # directory mtime: ignored
        self.assertEqual(self.treelist.digest(self.treelist.listing(self.root)), base)
        for change in (lambda: os.chmod(doc, 0o600), lambda: os.utime(doc, (1700000100, 1700000100)),
                       lambda: doc.write_bytes(b'hellO\n'), lambda: (self.root / 'www' / 'archive' / '00001-a.txt').unlink(),
                       lambda: (self.root / 'empty').rmdir()):
            change()
            changed = self.treelist.digest(self.treelist.listing(self.root))
            self.assertNotEqual(changed, base)
            base = changed

    def test_not_a_directory(self):
        with self.assertRaises(NotADirectoryError):
            self.treelist.listing(self.root / 'www' / 'latest')


class FakeDatabase:
    """Just enough of pg8000.native.Connection for app.py's statements, shared by both databases."""

    def __init__(self, unavailable):
        self.seq = 0
        self.items = []
        self.events = []
        self.up = True
        self.unavailable = unavailable  # app.Unavailable: what the real connect() raises (HTTP 503)

    def connect(self, which):
        if not self.up:
            raise self.unavailable(f'{which}: down')
        return FakeConnection(self, which)


class FakeConnection:
    def __init__(self, db, which):
        self.db, self.which = db, which

    def run(self, sql, **params):
        db, sql = self.db, ' '.join(sql.split())
        if sql.startswith('CREATE TABLE IF NOT EXISTS') or sql == 'SELECT 1':
            return [[1]]
        if sql.startswith('SELECT nextval('):
            db.seq += 1
            return [[db.seq]]
        if sql.startswith('INSERT INTO items'):
            created = datetime.datetime(2026, 11, 13, 2, 0, tzinfo=datetime.timezone.utc)
            db.items.append([params['id'], params['name'], params['sha'], params['sig'], created])
            return []
        if sql.startswith('SELECT id, name, sha256, signature, created FROM items ORDER BY id'):
            return sorted(db.items)
        if sql.startswith('DELETE FROM items WHERE id = :id RETURNING name'):
            gone = [row for row in db.items if row[0] == params['id']]
            db.items = [row for row in db.items if row[0] != params['id']]
            return [[row[1]] for row in gone]
        if sql.startswith('INSERT INTO events'):
            action = 'create' if "'create'" in sql else 'delete'
            db.events.append([len(db.events) + 1, params['id'], action, params['name']])
            return []
        if sql.startswith('SELECT id, item_id, action, name FROM events ORDER BY id'):
            return list(db.events)
        if sql.startswith('SELECT current_user::text'):
            return [['dirs_app', 16]]
        if sql.startswith('SELECT system_identifier FROM pg_control_system()'):
            return [[7707575594321125394]]
        if sql.startswith('SELECT rolname::text'):
            return [['dirs', True, True], ['dirs_app', True, False]]
        if sql.startswith('SELECT datname::text'):
            return [[params['main'], 'dirs'], [params['audit'], 'dirs_app']]
        if sql.startswith('SELECT tableowner::text'):
            return [['dirs_app']]
        raise AssertionError(f'unexpected SQL: {sql}')

    def close(self):
        pass


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.data = base / 'data'
        (self.data / 'www').mkdir(parents=True)
        (self.data / 'README.txt').write_text('owner\n', encoding='utf-8')
        self.key_file = base / 'app-key'
        self.key_file.write_bytes(b'k' * 64)
        os.environ.update({'DATA_DIR': str(self.data), 'APP_KEY_FILE': str(self.key_file),
                           'DB_PASSWORD_FILE': str(base / 'missing'), 'APP_TITLE': '主機資料夾（測試）'})
        self.app = load_module('woowbk_dirs_app', FIXTURE / 'app' / 'app.py')
        self.treelist = sys.modules['treelist']
        self.db = FakeDatabase(self.app.Unavailable)
        self.app.connect = self.db.connect
        self.app.Handler.log_message = lambda *_args: None
        self.app.prepare_www()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), self.app.Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f'http://127.0.0.1:{self.server.server_address[1]}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        if self.app._sqlite is not None:
            self.app._sqlite.close()
        self.tmp.cleanup()
        for key in ('DATA_DIR', 'APP_KEY_FILE', 'DB_PASSWORD_FILE', 'APP_TITLE'):
            os.environ.pop(key, None)

    def call(self, method, path, body=None, content_type='application/json'):
        request = urllib.request.Request(self.base + path, data=body, method=method)
        if body is not None:
            request.add_header('Content-Type', content_type)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def post(self, name, body):
        return self.call('POST', '/api/items', json.dumps({'name': name, 'body': body}, ensure_ascii=False).encode())

    def test_health(self):
        healthy = {'ok': True, 'database': True, 'audit_database': True, 'data_writable': True, 'sqlite': True}
        self.assertEqual(self.call('GET', '/healthz'), (200, healthy))
        self.db.up = False
        self.assertEqual(self.call('GET', '/healthz'), (503, {**healthy, 'ok': False, 'database': False,
                                                              'audit_database': False}))
        self.assertEqual(self.call('GET', '/api/summary')[0], 503)
        self.db.up = True
        self.assertEqual(sorted(os.listdir(self.data / 'www')), ['archive', 'db', 'docs'])  # probes removed

    def test_items_write_nested_files_links_and_sqlite(self):
        status, first = self.post('report', '第一個 𠮷')
        self.assertEqual(status, 201)
        status, second = self.post('plan', 'second')
        self.assertEqual(status, 201)
        www = self.data / 'www'
        doc = www / second['path']
        self.assertRegex(second['path'], r'docs/[0-9a-f]{2}/[0-9a-f]{2}/00002-plan\.txt\Z')
        self.assertEqual(stat.S_IMODE(doc.stat().st_mode), 0o640)
        self.assertEqual(doc.stat().st_nlink, 2)
        self.assertTrue(os.path.samefile(doc, www / second['archive']))
        self.assertEqual(os.readlink(www / 'latest'), second['path'])
        if xattrs_supported(str(www)):
            self.assertEqual(os.getxattr(doc, 'user.woowbk.item'), b'2')
        # Committed rows stay in the WAL (no checkpoint); a separate reader still sees them.
        wal = www / 'db' / 'app.sqlite-wal'
        self.assertGreater(wal.stat().st_size, 0)
        with sqlite3.connect(f'file:{www / "db" / "app.sqlite"}?mode=ro', uri=True) as reader:
            rows = reader.execute('SELECT item_id, name, path, sha256 FROM docs ORDER BY item_id').fetchall()
        self.assertEqual([r[:3] for r in rows], [(1, 'report', first['path']), (2, 'plan', second['path'])])
        status, deleted = self.call('DELETE', f'/api/items/{second["id"]}')
        self.assertEqual((status, deleted['deleted']), (200, True))
        self.assertFalse(doc.exists() or (www / second['archive']).exists())
        self.assertEqual(os.readlink(www / 'latest'), first['path'])
        self.assertEqual(self.call('DELETE', '/api/items/99')[0], 404)

    def test_summary(self):
        for name in ('a', 'b', 'c'):
            self.assertEqual(self.post(name, f'內容 {name}')[0], 201)
        self.call('DELETE', '/api/items/2')
        status, summary = self.call('GET', '/api/summary')
        self.assertEqual(status, 200)
        self.assertEqual(sorted(summary), sorted(SUMMARY_KEYS))
        rows = [[r[0], r[1], r[2], r[3]] for r in sorted(self.db.items)]
        for item_id, name, sha, signature in rows:
            message = json.dumps([item_id, name, sha], ensure_ascii=False, separators=(',', ':')).encode()
            self.assertEqual(signature, hmac.new(b'k' * 64, message, hashlib.sha256).hexdigest())
        canonical = lambda value: hashlib.sha256(json.dumps(value, ensure_ascii=False, separators=(',', ':'),  # noqa: E731
                                                            sort_keys=True).encode()).hexdigest()
        entries = self.treelist.listing(str(self.data))
        _status, docs = self.call('GET', '/api/sqlite')
        self.assertEqual(summary, {
            'items': 2, 'events': 4, 'db_digest': canonical({'items': rows, 'events': self.db.events}),
            'db_meta': {'user': 'dirs_app', 'system_identifier': '7707575594321125394', 'server_major': 16,
                        'roles': [['dirs', True, True], ['dirs_app', True, False]],
                        'owners': {'database:dirs': 'dirs', 'database:dirs_audit': 'dirs_app',
                                   'table:dirs.items': 'dirs_app', 'table:dirs_audit.events': 'dirs_app'}},
            'tree': len(entries), 'tree_digest': self.treelist.digest(entries),
            'sqlite': {'docs': 2, 'digest': canonical(docs['docs'])}, 'title': '主機資料夾（測試）',
            'signatures_valid': True})
        _status, tree = self.call('GET', '/api/tree')
        self.assertEqual((tree['count'], tree['digest'], tree['entries']), (len(entries), summary['tree_digest'], entries))
        self.key_file.write_bytes(b'k' * 64 + b'\n')  # one extra byte: every signature fails
        self.assertFalse(self.call('GET', '/api/summary')[1]['signatures_valid'])

    def test_rejects_bad_input(self):
        for body in (b'{bad', b'{"name": ""}', b'{"name": "../x"}', b'{"name": "x", "other": 1}',
                     b'{"name": ".hidden"}', json.dumps({'name': 'x', 'body': 'y' * 70000}).encode()):
            self.assertEqual(self.call('POST', '/api/items', body)[0], 400, body[:40])
        self.assertEqual(self.call('GET', '/missing')[0], 404)
        self.assertEqual(self.call('POST', '/healthz', b'{}')[0], 405)
        self.assertEqual(self.call('DELETE', '/api/items/x')[0], 405)
        self.assertEqual(self.call('GET', '/')[1], {'app': 'woowbk-dirs', 'title': '主機資料夾（測試）'})


class FakeUnshare:
    """tools/seed.py's `podman unshare` calls, run against a temp home without a user namespace."""

    def __init__(self):
        self.chowned = {}

    def __call__(self, *argv):
        if argv[0] == 'mkdir':
            os.mkdir(argv[-1], int(argv[2], 8))
            os.chmod(argv[-1], int(argv[2], 8))
        elif argv[0] == 'chown':
            self.chowned[argv[-1]] = argv[1]
        else:
            raise AssertionError(argv)


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.seed = load_module('woowbk_dirs_seed', FIXTURE / 'tools' / 'seed.py')

    def test_tools_compile(self):
        for path in [FIXTURE / 'tools' / 'seed.py', FIXTURE / 'tools' / 'check.py', FIXTURE / 'app' / 'app.py',
                     FIXTURE / 'app' / 'treelist.py']:
            compile(path.read_text(encoding='utf-8'), str(path), 'exec')

    def test_seed_env_file_round_trip(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, self.seed.ENV_REL)
            self.assertIsNone(self.seed.read_title(path))
            self.seed.write_env(path, '主機資料夾示範（dev）')
            self.assertEqual(self.seed.read_title(path), '主機資料夾示範（dev）')
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(os.path.dirname(path)).st_mode & 0o777, 0o700)

    def test_scram_verifier_matches_rfc7677(self):
        # RFC 7677 section 3: user "user", password "pencil"; the verifier must yield the published proof and
        # server signature for that exchange, i.e. PostgreSQL accepts the password the app reads from its secret.
        salt = base64.b64decode('W22ZaJ0SNY7soEsUEjb6gQ==')
        verifier = self.seed.scram_verifier(b'pencil', salt=salt, iterations=4096)
        match = re.fullmatch(r'SCRAM-SHA-256\$4096:([^$]+)\$([^:]+):(.+)', verifier)
        self.assertEqual(base64.b64decode(match.group(1)), salt)
        stored_key, server_key = base64.b64decode(match.group(2)), base64.b64decode(match.group(3))
        auth = ('n=user,r=rOprNGfwEbeRWgbNEkqO,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,'
                's=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0').encode()
        proof = base64.b64decode('dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=')
        client_key = bytes(a ^ b for a, b in zip(proof, hmac.new(stored_key, auth, hashlib.sha256).digest()))
        self.assertEqual(hashlib.sha256(client_key).digest(), stored_key)
        self.assertEqual(base64.b64encode(hmac.new(server_key, auth, hashlib.sha256).digest()).decode(),
                         '6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=')

    def test_ensure_dirs_matches_check_expectations(self):
        check = load_module('woowbk_dirs_check2', FIXTURE / 'tools' / 'check.py')
        treelist = load_module('woowbk_dirs_treelist2', FIXTURE / 'app' / 'treelist.py')
        fake = FakeUnshare()
        with tempfile.TemporaryDirectory() as home:
            self.seed.home = lambda rel='': os.path.join(home, rel) if rel else home
            self.seed.unshare = fake
            created = self.seed.ensure_dirs()
            self.assertEqual(self.seed.ensure_dirs(), [])   # idempotent: existing items are never changed
            self.assertIn('woowbk-dirs/data/www/tmp', created)
            self.assertEqual(fake.chowned, {os.path.join(home, rel): owner for rel, owner in (
                ('.local/share/woowbk-dirs/postgres', '70:70'), ('woowbk-dirs/data/www', '33:33'),
                ('woowbk-dirs/data/www/tmp', '33:33'))})
            modes = {rel: stat.S_IMODE(os.stat(os.path.join(home, rel)).st_mode) for rel in (
                '.local/share/woowbk-dirs/postgres', 'woowbk-dirs', 'woowbk-dirs/data', 'woowbk-dirs/data/www',
                'woowbk-dirs/data/www/tmp')}
            self.assertEqual(modes, {'.local/share/woowbk-dirs/postgres': 0o700, 'woowbk-dirs': 0o750,
                                     'woowbk-dirs/data': 0o755, 'woowbk-dirs/data/www': 0o750,
                                     'woowbk-dirs/data/www/tmp': 0o700})
            entries = treelist.listing(os.path.join(home, 'woowbk-dirs/data'))
            owner_items = {e['path']: (e['type'], e['mode']) for e in entries
                           if e['path'] != '.' and not e['path'].startswith('www')}
            self.assertEqual(owner_items, check.OWNER_ITEMS)
            link = next(e for e in entries if e['path'] == check.OUTSIDE_LINK[0])
            self.assertEqual(link['target'], check.OUTSIDE_LINK[1])
            # The target really leaves the data directory (up to the home) and names the env file there.
            resolved = posixpath.normpath(posixpath.join('woowbk-dirs/data', posixpath.dirname(link['path']),
                                                         link['target']))
            self.assertEqual(resolved, self.seed.ENV_REL)


def load_driver():
    """tests/e2e/lab/dirs_e2e.py (importing it has no side effects: paths only)."""
    if str(LAB) not in sys.path:
        sys.path.insert(0, str(LAB))
    import dirs_e2e
    return dirs_e2e


def gnu_tar_of(directory, out_path):
    """The engine's export of a host directory (podman.DIR_HELPER `pack`), minus the user namespace."""
    with open(out_path, 'wb') as out:
        subprocess.run(['tar', '--create', '--file=-', '--format=posix', '--numeric-owner', '--xattrs', '--no-acls',
                        '--no-selinux', '.'], cwd=directory, stdout=out, check=True)


class DriverTests(unittest.TestCase):
    """tests/e2e/lab/dirs_e2e.py against this working tree's engine and fixture (no lab needed)."""

    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver()
        cls.check = load_module('woowbk_dirs_check3', FIXTURE / 'tools' / 'check.py')

    def test_embedded_programs_compile(self):
        d = self.driver
        programs = {name: getattr(d, name) for name in ('LIST_PROGRAM', 'STATE_PROGRAM', 'KILL_WATCH', 'INJECT_BETWEEN',
                                                        'CRAFT_D5', 'SELFTEST_HOSTILE', 'SYNTH', 'VERIFY_CRAFTED',
                                                        'FIXTURE_SUMS', 'FOOTPRINT')}
        for name, code in programs.items():
            if name != 'FOOTPRINT':
                compile(code, name, 'exec')
        subprocess.run(['sh', '-n', '-c', programs['FOOTPRINT']], check=True)
        scan = d.e2e.LEAK_SCAN.replace("('woowbk-demo-db-password', 'woowbk-demo-app-key')", repr(d.SECRET_NAMES))
        self.assertNotEqual(scan, d.e2e.LEAK_SCAN, 'leaks: cli_e2e.LEAK_SCAN no longer names the demo secrets')
        compile(scan, 'LEAK_SCAN', 'exec')

    def test_constants_agree_with_fixture(self):
        d, data = self.driver, load_catalog()
        self.assertEqual(list(d.DIRS), [item['path'] for item in data['data_dirs']])
        self.assertEqual(list(d.COMPARE), data['verify'][0]['compare'])
        self.assertEqual(sorted(d.SECRET_NAMES), sorted(s['name'] for s in data['secrets']))
        self.assertEqual(d.OUTSIDE_LINK, self.check.OUTSIDE_LINK)
        self.assertEqual(d.APP_URL + '/healthz', data['health'][0]['url'])
        self.assertEqual(set(d.D5_REASONS), {case for case, kind in d.D5_CASES.items() if kind == 'refused'})
        self.assertEqual(d.PARENTS, tuple(posixpath.dirname(p) for p in d.DIRS))

    def test_fixture_sums_skip_caches(self):
        out = subprocess.run([sys.executable, '-I', '-c', self.driver.FIXTURE_SUMS, str(FIXTURE)], capture_output=True,
                             check=True).stdout
        sums = json.loads(out)
        self.assertIn('catalog.json', sums)
        self.assertIn('tools/seed.py', sums)
        self.assertFalse(any('__pycache__' in name for name in sums))
        self.assertEqual(sums['catalog.json'], hashlib.sha256((FIXTURE / 'catalog.json').read_bytes()).hexdigest())

    def make_data_dir(self, base):
        """A small host directory shaped like the fixture's data dir: nested files, a hard link, an inside and an
        outside symlink, an empty directory, a UTF-8 name."""
        root = Path(base) / 'data'
        (root / 'www' / 'docs' / 'ab' / 'cd').mkdir(parents=True)
        (root / 'www' / 'archive').mkdir()
        (root / 'www' / 'tmp').mkdir()
        (root / '共享').mkdir()
        for i in range(12):
            (root / 'www' / 'docs' / 'ab' / 'cd' / f'{i:05d}-doc.txt').write_text(f'文件 {i}\n', encoding='utf-8')
        os.link(root / 'www' / 'docs' / 'ab' / 'cd' / '00001-doc.txt', root / 'www' / 'archive' / '00001-doc.txt')
        (root / 'www' / 'latest').symlink_to('docs/ab/cd/00011-doc.txt')
        (root / 'README.txt').write_text('owner\n', encoding='utf-8')
        (root / '共享' / '設定連結').symlink_to(self.check.OUTSIDE_LINK[1])
        (root / '共享' / 'absolute').symlink_to('/etc/hostname')
        return root

    def test_hostile_dir_tars_refused_for_their_own_defect(self):
        from woowbackup import nested
        from woowbackup.errors import BackupError
        d = self.driver
        if os.getuid() > 55000 or os.getgid() > 55000:
            self.skipTest('the lab ID map (0..55000) cannot hold this test user')
        # The lab owner's namespace: container 0 -> the owner, 1..55000 -> subordinate ids.
        ids = (nested.IdMap('0 1001 1\n1 10000 55000'), nested.IdMap('0 1001 1\n1 10000 55000'))
        ns = {}
        exec(compile(d.HOSTILE, 'HOSTILE', 'exec'), ns)  # noqa: S102 - the driver's own builder code
        with tempfile.TemporaryDirectory() as base:
            data = self.make_data_dir(base)
            original = os.path.join(base, 'dir.tar')
            gnu_tar_of(data, original)
            self.assertEqual(ns['name_prefix'](original), './')
            report = nested.check_dir(original, ids=ids)          # outside symlinks are kept in a host directory
            self.assertEqual(report.outside_links, 2)
            with self.assertRaises(BackupError) as caught:       # ... but a volume refuses them (old engines)
                nested.check_volume(original, ids=ids)
            self.assertEqual(caught.exception.details.get('reason'), d.OLD_RULE)
            for case, reason in d.D5_REASONS.items():
                with self.subTest(case=case):
                    hostile = os.path.join(base, f'{case}.tar')
                    kept = ns['write_hostile'](original, hostile, case, d.D5_TAG, '/home/appowner')
                    self.assertGreater(kept, 10)
                    with self.assertRaises(BackupError) as caught:
                        nested.check_dir(hostile, ids=ids)
                    self.assertIn(caught.exception.code, d.REFUSED_CODES)
                    self.assertEqual(caught.exception.details.get('reason'), reason)
                    # The canonical copy a restore would extract is never produced either.
                    with open(os.devnull, 'wb') as sink, self.assertRaises(BackupError):
                        nested.stream_dir(hostile, sink, ids=ids)

    def helper(self, home, *args):
        from woowbackup import podman
        env = {'PATH': '/usr/bin:/bin', 'HOME': home, 'LANG': 'C.UTF-8'}
        return subprocess.run([sys.executable, '-I', '-c', podman.DIR_HELPER, *args], env=env, capture_output=True)

    def test_between_injection_is_what_the_engine_recovery_settles(self):
        d = self.driver
        treelist = load_module('woowbk_dirs_treelist3', FIXTURE / 'app' / 'treelist.py')
        token = 'j20261113T120000Z-0123abcd'
        with tempfile.TemporaryDirectory() as home:
            data = self.make_data_dir(home)  # ~/data: the original
            before = treelist.listing(data)
            new = Path(home) / f'data.woowbk-new-{token}'
            (new / 'partial').mkdir(parents=True)  # killed while the new copy was being written
            for step in ('killed before rename 1', 'killed after rename 2'):
                with self.subTest(step=step):
                    if step == 'killed after rename 2':
                        os.rename(Path(home) / f'data.woowbk-old-{token}', data)  # undo the first injection: rename 1
                        os.rename(new, Path(home) / 'data.tmp')                     # back, then "do" rename 2 over it:
                        os.rename(data, Path(home) / f'data.woowbk-old-{token}')    # original aside,
                        os.rename(Path(home) / 'data.tmp', data)                    # new copy in place
                    out = subprocess.run([sys.executable, '-I', '-c', d.INJECT_BETWEEN, str(data)], capture_output=True,
                                         check=True).stdout
                    self.assertIn('renamed <path>', json.loads(out)['action'])
                    state = json.loads(self.helper(home, 'state', token, 'data').stdout)
                    self.assertEqual([{k: row[k] for k in ('path', 'type', 'empty', 'mount', 'siblings', 'more')}
                                      for row in state], [{'path': 'data', 'type': 'missing', 'empty': None,
                                                           'mount': False, 'more': 0, 'siblings': [
                        {'kind': 'new', 'token': token, 'type': 'dir'}, {'kind': 'old', 'token': token, 'type': 'dir'}]}])
            # What QuadletPostgresAdapter.recover_dirs does for a missing directory: move the old copy back, drop new.
            self.assertEqual(self.helper(home, 'back', 'data', token).returncode, 0)
            self.assertEqual(self.helper(home, 'drop', 'data', 'new', token).returncode, 0)
            self.assertEqual(treelist.listing(data), before)
            self.assertEqual(sorted(os.listdir(home)), ['data'])

    def test_d3_dropin_refuses_start_only_with_the_marker(self):
        d = self.driver
        scripts = []
        original_owner = d.owner
        d.owner = lambda _dev, *argv, **_kw: scripts.append(argv)
        try:
            d.d3_inject('a', True)
            d.d3_inject('a', False)
        finally:
            d.owner = original_owner
        self.assertEqual([argv[:2] for argv in scripts], [('sh', '-c'), ('sh', '-c')])
        with tempfile.TemporaryDirectory() as home:
            stub = Path(home) / 'stub-bin'
            stub.mkdir()
            (stub / 'systemctl').write_text('#!/bin/sh\nexit 0\n', encoding='ascii')  # never the real systemctl
            os.chmod(stub / 'systemctl', 0o755)
            env = {'PATH': f'{stub}:/usr/bin:/bin', 'HOME': home, 'LANG': 'C.UTF-8'}
            subprocess.run(['sh', '-c', scripts[0][2]], env=env, check=True)
            dropin = Path(home) / d.D3_DROPIN
            self.assertEqual(dropin.read_text(encoding='ascii').splitlines(), [
                '[Service]', 'Restart=no',
                f"ExecStartPre=/bin/sh -c 'test ! -e %h/{d.DATA_DIR}/{d.D3_MARKER}'"])
            subprocess.run(['sh', '-c', scripts[1][2]], env=env, check=True)
            self.assertFalse(dropin.parent.exists())
        self.assertEqual(posixpath.dirname(d.D3_MARKER), '')  # in the data dir root: part of the backup's tree


if __name__ == '__main__':
    unittest.main()
