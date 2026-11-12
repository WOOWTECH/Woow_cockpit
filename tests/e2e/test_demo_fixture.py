"""Offline checks of the woowbk-demo fixture (no containers, no PostgreSQL, no pg8000 needed).

    python3 -B -m unittest discover -s tests/e2e -p 'test_*.py' -v

The live behaviour (real PostgreSQL, Podman secrets, Quadlet units, volumes) is exercised in the
lab by tests/e2e/lab/deploy-demo.sh and catalog-examples/woowbk-demo/tools/check.py.
"""
import datetime
import hashlib
import hmac
import importlib.util
import json
import os
import pwd
import re
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'catalog-examples' / 'woowbk-demo'
sys.path.insert(0, str(ROOT / 'backup-engine'))
sys.dont_write_bytecode = True


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


class CatalogTests(unittest.TestCase):
    def test_equals_contract_example(self):
        text = (ROOT / 'docs/backup/CONTRACT.md').read_text(encoding='utf-8')
        section = text.split('## 4. Trusted catalog entry', 1)[1]
        example = json.loads(re.search(r'```json\n(.*?)```', section, re.S).group(1))
        self.assertEqual(load_catalog(), example)

    def test_engine_validator_accepts_it(self):
        from woowbackup import catalog
        from woowbackup.paths import Paths
        account = pwd.struct_passwd(('appowner', 'x', 1001, 1001, '', '/home/appowner', '/bin/bash'))
        app = catalog.validate_entry(load_catalog(), paths=Paths(), user_lookup=lambda _name: account)
        self.assertEqual(app.id, 'woowbk-demo')
        self.assertEqual(app.writer_units, ('woowbk-demo-app.service',))

    def test_templates_agree_with_catalog(self):
        data = load_catalog()
        files = sorted(p.name for p in (FIXTURE / 'quadlet').iterdir())
        self.assertEqual(files, sorted(data['quadlet']['files']))
        units = {name: parse_unit((FIXTURE / 'quadlet' / name).read_text()) for name in files}
        net = units['woowbk-demo.network']
        self.assertEqual(values(net, 'Network', 'NetworkName'), ['woowbk-demo'])
        db, app = units['woowbk-demo-db.container'], units['woowbk-demo-app.container']
        pg = data['postgres'][0]
        self.assertEqual(values(db, 'Container', 'ContainerName'), [pg['container']])
        self.assertEqual(values(db, 'Container', 'Image'), ['docker.io/library/postgres:16-alpine'])
        self.assertIn(f'{pg["data_volume"]}:/var/lib/postgresql/data', values(db, 'Container', 'Volume'))
        self.assertIn('woowbk-demo-db-password,type=env,target=POSTGRES_PASSWORD', values(db, 'Container', 'Secret'))
        env = ' '.join(values(db, 'Container', 'Environment'))
        self.assertIn(f'POSTGRES_USER={pg["user"]}', env)
        self.assertIn(f'POSTGRES_DB={pg["database"]}', env)
        self.assertEqual(values(app, 'Container', 'Image'), ['localhost/woowbk-demo-app:1'])
        self.assertEqual(values(app, 'Container', 'Volume'), [f'{data["volumes"][0]["name"]}:/data'])
        self.assertEqual(sorted(values(app, 'Container', 'Secret')), sorted(s['name'] for s in data['secrets']))
        self.assertEqual(values(app, 'Container', 'EnvironmentFile'), [f'%h/{data["config_files"][0]["path"]}'])
        self.assertEqual(values(app, 'Unit', 'Requires'), [pg['unit']])
        self.assertEqual(values(app, 'Unit', 'After'), [pg['unit']])
        port = values(app, 'Container', 'PublishPort')[0]
        self.assertTrue(port.startswith('127.0.0.1:18090:'), port)
        for url in [h['url'] for h in data['health']] + [v['url'] for v in data['verify']]:
            self.assertTrue(url.startswith('http://127.0.0.1:18090/'), url)
        for unit in (db, app):
            self.assertTrue(any(v.startswith('--memory ') for v in values(unit, 'Container', 'PodmanArgs')))
            self.assertEqual(values(unit, 'Install', 'WantedBy'), ['default.target'])

    def test_adapter_reads_images_from_templates(self):
        try:
            from woowbackup.adapters import quadlet_postgres as qp
        except Exception as error:  # noqa: BLE001 - engine modules are owned by other teams
            self.skipTest(f'engine adapter not importable: {error}')
        sources = {p.name: p.read_bytes() for p in (FIXTURE / 'quadlet').iterdir()}
        adapter = qp.QuadletPostgresAdapter.__new__(qp.QuadletPostgresAdapter)
        adapter.app = type('App', (), {'quadlet_files': tuple(load_catalog()['quadlet']['files']), 'id': 'woowbk-demo'})()
        self.assertEqual(adapter.container_images(sources),
                         {'woowbk-demo-db.service': 'docker.io/library/postgres:16-alpine',
                          'woowbk-demo-app.service': 'localhost/woowbk-demo-app:1'})


class FakeConnection:
    """Just enough of pg8000.native.Connection for app.py's statements."""

    def __init__(self, store):
        self.store = store

    def run(self, sql, **params):
        sql = ' '.join(sql.split())
        if sql.startswith('CREATE TABLE IF NOT EXISTS notes') or sql == 'SELECT 1':
            return [[1]]
        if sql.startswith('SELECT nextval('):
            self.store['seq'] += 1
            return [[self.store['seq']]]
        if sql.startswith('INSERT INTO notes'):
            created = datetime.datetime(2026, 11, 13, 2, 0, tzinfo=datetime.timezone.utc)
            self.store['rows'].append([params['id'], params['title'], params['body'], params['sig'], created])
            return [[created]]
        if sql.startswith('SELECT id, title, body, signature, created FROM notes ORDER BY id'):
            return sorted(self.store['rows'], key=lambda r: r[0])
        raise AssertionError(f'unexpected SQL: {sql}')

    def close(self):
        pass


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        (base / 'data').mkdir()
        self.key_file = base / 'app-key'
        self.key_file.write_bytes(b'k' * 64)
        os.environ.update({'DATA_DIR': str(base / 'data'), 'APP_KEY_FILE': str(self.key_file),
                           'DB_PASSWORD_FILE': str(base / 'missing'), 'APP_TITLE': '示範筆記（測試）'})
        spec = importlib.util.spec_from_file_location('woowbk_demo_app', FIXTURE / 'app' / 'app.py')
        self.app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.app)
        self.store = {'seq': 0, 'rows': []}
        self.db_up = True

        def connect():
            if not self.db_up:
                raise self.app.Unavailable('down')
            return FakeConnection(self.store)

        self.app.connect = connect
        self.app.Handler.log_message = lambda *_args: None  # keep test output quiet
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), self.app.Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f'http://127.0.0.1:{self.server.server_address[1]}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()
        for key in ('DATA_DIR', 'APP_KEY_FILE', 'DB_PASSWORD_FILE', 'APP_TITLE'):
            os.environ.pop(key, None)

    def call(self, method, path, body=None, content_type=None):
        request = urllib.request.Request(self.base + path, data=body, method=method)
        if content_type:
            request.add_header('Content-Type', content_type)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=10) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def post_note(self, title, body):
        payload = json.dumps({'title': title, 'body': body}, ensure_ascii=False).encode()
        return self.call('POST', '/api/notes', payload, 'application/json')

    def test_health_requires_database_and_writable_data(self):
        status, body = self.call('GET', '/healthz')
        self.assertEqual((status, json.loads(body)), (200, {'ok': True, 'database': True, 'data_writable': True}))
        self.db_up = False
        status, body = self.call('GET', '/healthz')
        self.assertEqual((status, json.loads(body)), (503, {'ok': False, 'database': False, 'data_writable': True}))
        self.assertEqual(self.call('GET', '/api/summary')[0], 503)
        self.db_up = True
        os.chmod(os.environ['DATA_DIR'], 0o500)
        try:
            if os.access(os.environ['DATA_DIR'], os.W_OK):
                self.skipTest('running as root: cannot make the data dir read-only')
            status, body = self.call('GET', '/healthz')
            self.assertEqual((status, json.loads(body)['data_writable']), (503, False))
        finally:
            os.chmod(os.environ['DATA_DIR'], 0o700)
        self.assertEqual(sorted(os.listdir(os.environ['DATA_DIR'])), ['files'])  # probe files are removed

    def test_summary_digest_and_signatures(self):
        self.assertEqual(self.post_note('第一則', '內容 𠮷 ✓')[0], 201)
        self.assertEqual(self.post_note('second', '')[0], 201)
        data = b'\x00\x01binary\xff' * 100
        status, body = self.call('POST', '/api/files?name=a.bin', data, 'application/octet-stream')
        self.assertEqual((status, json.loads(body)['sha256']), (201, hashlib.sha256(data).hexdigest()))
        self.assertEqual(self.call('GET', '/api/files/a.bin'), (200, data))
        status, body = self.call('GET', '/api/summary')
        summary = json.loads(body)
        rows = [[r[0], r[1], r[2], r[3]] for r in self.store['rows']]
        for note_id, title, text, signature in rows:
            message = json.dumps([note_id, title, text], ensure_ascii=False, separators=(',', ':')).encode()
            self.assertEqual(signature, hmac.new(b'k' * 64, message, hashlib.sha256).hexdigest())
        canonical = json.dumps({'notes': rows, 'files': [['a.bin', hashlib.sha256(data).hexdigest()]]},
                               ensure_ascii=False, separators=(',', ':'), sort_keys=True)
        self.assertEqual(summary, {'notes': 2, 'files': 1, 'digest': hashlib.sha256(canonical.encode()).hexdigest(),
                                   'title': '示範筆記（測試）', 'signatures_valid': True})
        # A different key (even one extra trailing newline) invalidates every signature.
        self.key_file.write_bytes(b'k' * 64 + b'\n')
        self.assertFalse(json.loads(self.call('GET', '/api/summary')[1])['signatures_valid'])
        self.key_file.write_bytes(b'k' * 64)
        self.store['rows'][0][2] = 'tampered'
        changed = json.loads(self.call('GET', '/api/summary')[1])
        self.assertFalse(changed['signatures_valid'])
        self.assertNotEqual(changed['digest'], summary['digest'])

    def test_files_listing_skips_temporaries_links_and_dirs(self):
        files = Path(os.environ['DATA_DIR']) / 'files'
        files.mkdir(exist_ok=True)
        (files / 'keep.txt').write_bytes(b'x')
        (files / '.upload-abc').write_bytes(b'partial')
        (files / 'sub').mkdir()
        (files / 'link').symlink_to(files / 'keep.txt')
        status, body = self.call('GET', '/api/files')
        self.assertEqual([f['name'] for f in json.loads(body)['files']], ['keep.txt'])
        self.assertEqual(self.call('GET', '/api/files/link')[0], 404)

    def test_rejects_bad_input(self):
        for method, path, body in [('POST', '/api/files?name=../x', b'x'), ('POST', '/api/files?name=.h', b'x'),
                                   ('POST', '/api/files', b'x'), ('GET', '/api/files/..%2Fx', None),
                                   ('POST', '/api/notes', b'{bad'), ('POST', '/api/notes', b'{"title": ""}'),
                                   ('POST', '/api/notes', b'{"title": "t", "other": 1}')]:
            status, _ = self.call(method, path, body, 'application/json')
            self.assertEqual(status, 400, f'{method} {path}')
        self.assertEqual(self.call('GET', '/missing')[0], 404)
        self.assertEqual(self.call('POST', '/healthz', b'')[0], 405)


class ToolTests(unittest.TestCase):
    def test_tools_compile(self):
        for path in [FIXTURE / 'tools' / 'seed.py', FIXTURE / 'tools' / 'check.py', FIXTURE / 'app' / 'app.py']:
            compile(path.read_text(encoding='utf-8'), str(path), 'exec')

    def test_seed_env_file_round_trip(self):
        spec = importlib.util.spec_from_file_location('woowbk_demo_seed', FIXTURE / 'tools' / 'seed.py')
        seed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(seed)
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, seed.ENV_REL)
            self.assertIsNone(seed.read_title(path))
            seed.write_env(path, '示範筆記（dev）')
            self.assertEqual(seed.read_title(path), '示範筆記（dev）')
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(os.path.dirname(path)).st_mode & 0o777, 0o700)


if __name__ == '__main__':
    unittest.main()
