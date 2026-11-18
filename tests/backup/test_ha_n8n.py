"""HA import, n8n part (ha_n8n.py; CONTRACT section 9 "Home Assistant import"): the pass over the add-on tar, the
SQLite copy (owner, counts, no views), the workflows to fix, community packages and native code, and the throwaway
source volume. Team E2."""
import io
import json
import re
import sqlite3
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import ha_n8n, habackup, jobs
from woowbackup.errors import BackupError

from . import hafixtures as hx

KEY = 'n8nTestKey-0123456789abcdefABCDEF'
ADDON_JSON = json.dumps({'user': {'version': '2.43.6', 'image': 'ghcr.io/woowtech/woow-ha-n8n-amd64'},
                         'system': {'slug': 'woow-n8n', 'name': 'Woow n8n'}, 'version': '2.43.6'}).encode()


def elf(machine=0x3E, glibc=False, bits=2):
    """A minimal 64-bit little-endian ELF shared object with one PT_LOAD and a PT_DYNAMIC listing DT_NEEDED."""
    strtab = b'\0libc.musl-x86_64.so.1\0libc.so.6\0'
    needed = 23 if glibc else 1
    dynamic = struct.pack('<qQqQqQ', 1, needed, 5, 0x1000, 0, 0)
    phoff, phnum = 64, 2
    data_off = phoff + 56 * phnum
    dyn_off = data_off + len(strtab)
    header = bytearray(64)
    header[:4] = b'\x7fELF'
    header[4], header[5] = bits, 1
    struct.pack_into('<H', header, 18, machine)
    struct.pack_into('<Q', header, 32, phoff)
    struct.pack_into('<HH', header, 54, 56, phnum)
    load = struct.pack('<IIQQQQQQ', 1, 5, data_off, 0x1000, 0x1000, len(strtab), len(strtab), 0x1000)
    dyn = struct.pack('<IIQQQQQQ', 2, 6, dyn_off, 0x2000, 0x2000, len(dynamic), len(dynamic), 8)
    return bytes(header) + load + dyn + strtab + dynamic


def sqlite_db(path, *, owner=True, view=False):
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE user (id TEXT, email TEXT, password TEXT, roleSlug TEXT, createdAt TEXT);
        CREATE TABLE credentials_entity (id TEXT, name TEXT, data TEXT);
        CREATE TABLE execution_entity (id INTEGER, workflowId TEXT);
        CREATE TABLE project (id TEXT);
        CREATE TABLE variables (id TEXT);
        CREATE TABLE migrations (id INTEGER, timestamp INTEGER, name TEXT);
        INSERT INTO migrations VALUES (1, 1791209478293, 'CreateAgentBudgetSpendTables1791209478293');
        INSERT INTO credentials_entity VALUES ('c1', 'HA probe header', 'ciphertext');
        INSERT INTO execution_entity VALUES (1, 'w2');
        INSERT INTO project VALUES ('p1');
    """)
    if view:
        conn.execute('CREATE VIEW workflow_entity AS SELECT 1 AS name, 1 AS active, 2 AS nodes')
    else:
        conn.execute('CREATE TABLE workflow_entity (id TEXT, name TEXT, active INTEGER, nodes TEXT, '
                     'isArchived INTEGER)')
        conn.executemany('INSERT INTO workflow_entity VALUES (?, ?, ?, ?, ?)', [
            ('w1', 'manual', 0, '[]', 0), ('w2', 'scheduled', 1, '[{"type": "n8n-nodes-base.scheduleTrigger"}]', 0),
            ('w3', 'archived', 1, '[]', 1)])
    if owner:
        conn.execute("INSERT INTO user VALUES ('u1', 'ha-probe@probe.invalid', '$2a$10$hash', 'global:owner', '1')")
    else:
        conn.execute("INSERT INTO user VALUES ('u1', NULL, NULL, 'global:owner', '1')")
    conn.commit()
    conn.close()


class SqliteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'database.sqlite'

    def tearDown(self):
        self.tmp.cleanup()

    def test_owner_counts_and_workflows(self):
        sqlite_db(self.path)
        info = ha_n8n.inspect_sqlite(self.path)
        self.assertEqual((info['owner_email'], info['owner_ok']), ('ha-probe@probe.invalid', True))
        self.assertEqual(info['counts']['workflows'], 3)
        self.assertEqual((info['counts']['credentials'], info['counts']['executions'], info['counts']['users']),
                         (1, 1, 1))
        self.assertEqual([w[0] for w in info['workflows']], ['manual', 'scheduled'], 'archived ones are left out')
        self.assertEqual(info['workflows_active'], 1)
        self.assertEqual(info['migration'], 'CreateAgentBudgetSpendTables1791209478293')

    def test_no_owner_and_views_are_never_read(self):
        sqlite_db(self.path, owner=False, view=True)
        info = ha_n8n.inspect_sqlite(self.path)
        self.assertFalse(info['owner_ok'])
        self.assertEqual(info['workflows'], [], 'a view named like a table is not read')
        blockers, _w = ha_n8n.analyse(_source(), info, '2.43.6', '2.43.6')
        self.assertIn(ha_n8n.NO_OWNER, blockers)

    def test_garbage_is_corrupt(self):
        self.path.write_bytes(b'SQLite format 3\x00' + b'\xff' * 4000)
        with self.assertRaises(BackupError) as caught:
            ha_n8n.inspect_sqlite(self.path)
        self.assertEqual(caught.exception.code, 'corrupt-archive')
        self.assertFalse((self.path.parent / 'inspect').exists())

    def test_virtual_tables_and_their_shadow_tables_are_never_read(self):
        sqlite_db(self.path)
        conn = sqlite3.connect(self.path)
        conn.execute('CREATE VIRTUAL TABLE workflow_fts USING fts5(name)')
        conn.execute('CREATE VIRTUAL TABLE geo USING rtree(id, x0, x1)')
        conn.execute("INSERT INTO workflow_fts VALUES ('x')")
        conn.commit()
        conn.close()
        info = ha_n8n.inspect_sqlite(self.path)
        self.assertFalse([name for name in info['tables'] if name.startswith(('workflow_fts', 'geo'))])
        self.assertIn('workflow_entity', info['tables'])

    def test_the_file_is_read_by_a_child_on_a_copy_of_its_own(self):
        conn = sqlite3.connect(self.path)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.close()
        sqlite_db(self.path)
        conn = sqlite3.connect(self.path)
        conn.execute('PRAGMA wal_autocheckpoint=0')
        conn.execute("INSERT INTO project VALUES ('p2')")
        conn.commit()
        wal = self.path.parent / 'database.sqlite-wal'
        before = (self.path.read_bytes(), wal.read_bytes())
        # The WAL must survive the close below: copy it aside like the member pass stages it.
        staged = Path(self.tmp.name) / 'staged'
        staged.mkdir()
        (staged / 'database.sqlite').write_bytes(before[0])
        (staged / 'database.sqlite-wal').write_bytes(before[1])
        conn.close()
        with mock.patch.object(ha_n8n.subprocess, 'Popen', wraps=ha_n8n.subprocess.Popen) as popen:
            info = ha_n8n.inspect_sqlite(staged / 'database.sqlite')
        self.assertEqual(info['counts']['projects'], 2, 'the WAL is read')
        argv = popen.call_args.args[0]
        self.assertEqual(argv[:4], [ha_n8n.sys.executable, '-I', '-S', '-c'])
        self.assertEqual(popen.call_args.kwargs['cwd'], staged / 'inspect')
        self.assertEqual(((staged / 'database.sqlite').read_bytes(), (staged / 'database.sqlite-wal').read_bytes()),
                         before, 'the staged files stay as they came from the backup')
        self.assertFalse((staged / 'inspect').exists())
        self.assertIn('os.setuid(uid)', ha_n8n.SQLITE_CHILD)
        self.assertIn('SQLITE_DBCONFIG_DEFENSIVE', ha_n8n.SQLITE_CHILD)

    def test_workflow_rows_are_bounded_and_analysed_one_by_one(self):
        sqlite_db(self.path)
        conn = sqlite3.connect(self.path)
        big = json.dumps([{'type': 'n8n-nodes-base.set', 'parameters': {'v': 'x' * 2000}}])
        conn.execute("INSERT INTO workflow_entity VALUES ('w9', 'huge', 0, ?, 0)", (big,))
        conn.execute("INSERT INTO workflow_entity VALUES ('w8', 'ha', 0, ?, 0)",
                     (json.dumps([{'type': 'n8n-nodes-base.homeAssistant'}]),))
        conn.commit()
        conn.close()
        seen = []
        with mock.patch.object(ha_n8n, 'MAX_NODES_JSON', 1000):
            info = ha_n8n.inspect_sqlite(self.path, checkpoint=lambda: seen.append(1))
        by_name = {name: reasons for name, _active, reasons in info['workflows']}
        self.assertEqual(by_name['huge'], [ha_n8n.TOO_LARGE])
        self.assertTrue(any('Home Assistant' in r for r in by_name['ha']))
        self.assertEqual(by_name['manual'], [])
        self.assertGreaterEqual(len(seen), len(info['workflows']))
        with mock.patch.object(ha_n8n, 'MAX_NODES_TOTAL', 10):
            info = ha_n8n.inspect_sqlite(self.path)
        self.assertEqual({name: reasons for name, _a, reasons in info['workflows']}['ha'], [ha_n8n.TOO_LARGE])

    def test_a_cancel_while_reading_stops_the_child(self):
        sqlite_db(self.path)

        class Stop(Exception):
            pass

        def checkpoint():
            raise Stop()

        with self.assertRaises(Stop):
            ha_n8n.inspect_sqlite(self.path, checkpoint=checkpoint)
        self.assertFalse((self.path.parent / 'inspect').exists())


def _source(**fields):
    src = ha_n8n.Source()
    src.sqlite = {'database.sqlite': '/x'}
    src.key = KEY
    for key, value in fields.items():
        setattr(src, key, value)
    return src


class AnalyseTests(unittest.TestCase):
    def test_version_key_and_native_code(self):
        info = {'owner_ok': True}
        self.assertEqual(ha_n8n.analyse(_source(), info, '2.43.6', '2.43.6'), ([], []))
        blockers, _w = ha_n8n.analyse(_source(), info, '2.43.6', '2.44.0')
        self.assertIn('HA 的 n8n 是 2.43.6，這台是 2.44.0', blockers[0])
        blockers, _w = ha_n8n.analyse(_source(key=None), info, '2.43.6', '2.43.6')
        self.assertIn('加密金鑰', blockers[0])
        _b, warnings = ha_n8n.analyse(_source(native_bad=['n8n-nodes-x'], packages=[{'name': 'n8n-nodes-x',
                                                                                     'version': '1'}]),
                                      info, '2.43.6', '2.43.6')
        self.assertTrue(any('n8n-nodes-x' in w and '重新安裝' in w for w in warnings))

    def test_elf(self):
        self.assertTrue(ha_n8n.elf_fits(elf()))
        self.assertFalse(ha_n8n.elf_fits(elf(glibc=True)), 'glibc code does not run on the musl image')
        self.assertFalse(ha_n8n.elf_fits(elf(machine=0xB7)), 'aarch64')
        self.assertFalse(ha_n8n.elf_fits(elf(bits=1)), '32-bit')
        self.assertIsNone(ha_n8n.elf_fits(b'not elf' * 20))

    def test_packages(self):
        data = json.dumps({'dependencies': {'n8n-nodes-a': '^1.0.0', '@scope/n8n-nodes-b': '2.0.0',
                                            '../evil': '1'}}).encode()
        self.assertEqual(ha_n8n.packages_of(data), [{'name': '@scope/n8n-nodes-b', 'version': '2.0.0'},
                                                    {'name': 'n8n-nodes-a', 'version': '^1.0.0'}])
        self.assertEqual(ha_n8n.packages_of(b'{'), [])


class WorkflowScanTests(unittest.TestCase):
    def test_reasons(self):
        nodes = [{'type': 'n8n-nodes-base.readWriteFile', 'parameters': {'fileSelector': '/share/probe.txt'}},
                 {'type': 'n8n-nodes-base.httpRequest', 'parameters': {'url': 'http://supervisor/core/api/states'}},
                 {'type': 'n8n-nodes-base.httpRequest', 'parameters': {'url': 'https://api.example.com/x'}},
                 {'type': 'n8n-nodes-base.webhook', 'parameters': {'path': 'ha-probe'}},
                 {'type': 'n8n-nodes-base.executeCommand', 'parameters': {'command': 'ls'}},
                 {'type': 'n8n-nodes-base.ssh'}, {'type': 'n8n-nodes-base.homeAssistant'},
                 {'type': 'n8n-nodes-base.redis'},
                 {'type': 'n8n-nodes-base.set', 'parameters': {'value': 'ws://172.30.32.1:8123/api/websocket'}}]
        reasons = ha_n8n.workflow_reasons(json.dumps(nodes))
        joined = '\n'.join(reasons)
        for text in ('/share/probe.txt', 'supervisor', '網頁觸發', '執行命令', 'SSH', 'Home Assistant 節點', 'Redis',
                     '172.30.32.1'):
            self.assertIn(text, joined)
        self.assertNotIn('api.example.com', joined)
        self.assertLessEqual(len(reasons), 10)
        self.assertEqual(ha_n8n.workflow_reasons('{not json'), ['無法讀取工作流程的節點設定。'])
        fix = ha_n8n.workflows_to_fix([('ok', True, []),
                                       ('fix me', False, ha_n8n.workflow_reasons(json.dumps(nodes[:1])))])
        self.assertEqual([(w['name'], w['active']) for w in fix], [('fix me', False)])


def n8n_tar(extra=()):
    entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': ADDON_JSON},
               {'name': 'data', 'type': 'dir'}, {'name': 'data/options.json', 'data': b'{"x": "secret"}'},
               {'name': 'data/n8n-runners-auth-token', 'data': b'token'},
               {'name': 'config', 'type': 'dir'}, {'name': 'config/.n8n', 'type': 'dir'},
               {'name': 'config/.n8n/database.sqlite', 'data': b'SQLITE'},
               {'name': 'config/.n8n/database.sqlite-wal', 'data': b'WAL'},
               {'name': 'config/.n8n/database.sqlite-shm', 'data': b'SHM'},
               {'name': 'config/.n8n/config', 'data': json.dumps({'encryptionKey': KEY}).encode(), 'mode': 0o600},
               {'name': 'config/.n8n/n8nEventLog.log', 'data': b'log'},
               {'name': 'config/.n8n/nodes', 'type': 'dir'},
               {'name': 'config/.n8n/nodes/package.json',
                'data': json.dumps({'dependencies': {'n8n-nodes-x': '1.0.0'}}).encode()},
               {'name': 'config/.n8n/nodes/node_modules', 'type': 'dir'},
               {'name': 'config/.n8n/nodes/node_modules/n8n-nodes-x', 'type': 'dir'},
               {'name': 'config/.n8n/nodes/node_modules/n8n-nodes-x/build.node', 'data': elf(glibc=True)},
               {'name': 'config/.n8n/nodes/node_modules/.bin', 'type': 'dir'},
               {'name': 'config/.n8n/nodes/node_modules/.bin/x', 'type': 'symlink', 'linkname': '../n8n-nodes-x/x'},
               {'name': 'config/.n8n/nodes/node_modules/.bin/evil', 'type': 'symlink', 'linkname': '/etc/passwd'},
               {'name': 'config/.n8n/storage', 'type': 'dir'},
               {'name': 'config/.cache', 'type': 'dir'}, {'name': 'config/.cache/x', 'data': b'cache'},
               {'name': 'config/redis', 'type': 'dir'}, {'name': 'config/redis/dump.rdb', 'data': b'queue'},
               *extra]
    return hx.tar_bytes(entries)


class ScanTests(unittest.TestCase):
    def test_sqlite_key_packages_and_files(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        files = ha_n8n.FileTar(root / 'files.tar')
        report = habackup.Report()
        self.addCleanup(jobs.unmask_secret, KEY)
        src = ha_n8n.scan_member(io.BytesIO(n8n_tar()), report, root, files=files)
        files.close()
        self.assertTrue(report.complete)
        self.assertEqual(report.secret_files, 2)
        self.assertEqual(sorted(src.sqlite), ['database.sqlite', 'database.sqlite-wal'])
        self.assertEqual((root / 'database.sqlite').read_bytes(), b'SQLITE')
        self.assertEqual((root / 'database.sqlite').stat().st_mode & 0o777, 0o600)
        self.assertEqual(src.key, KEY)
        self.assertIn('[已遮蔽]', jobs.redact(f'key {KEY}'), 'the key is masked as soon as it is read')
        self.assertEqual(src.packages, [{'name': 'n8n-nodes-x', 'version': '1.0.0'}])
        self.assertEqual(src.native_bad, ['n8n-nodes-x'])
        self.assertEqual(report.skipped_symlinks, 1, 'the absolute link is dropped')
        with tarfile.open(root / 'files.tar') as tar:
            names = {m.name: m for m in tar.getmembers()}
        self.assertIn('nodes/package.json', names)
        self.assertIn('nodes/node_modules/.bin/x', names)
        self.assertNotIn('nodes/node_modules/.bin/evil', names)
        self.assertIn('storage', names)
        self.assertFalse(any(n.startswith(('config', 'database', 'n8nEventLog', '.cache', 'redis')) for n in names))

    def test_source_volume_tar(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / 'database.sqlite').write_bytes(b'db')
        src = _source(sqlite={'database.sqlite': root / 'database.sqlite'})
        out = io.BytesIO()
        ha_n8n._source_tar(out, src, 'temp-password', node_ids=(1000, 1000))
        with tarfile.open(fileobj=io.BytesIO(out.getvalue())) as tar:
            members = {m.name: m for m in tar.getmembers()}
            key = json.loads(tar.extractfile('home/.n8n/config').read())
        self.assertEqual(key, {'encryptionKey': KEY})
        self.assertEqual(members['home/.n8n/config'].mode, 0o600)
        self.assertEqual({(m.uid, m.gid) for m in members.values()}, {(1000, 1000)})
        self.assertEqual(members['pgpass'].mode, 0o444)
        self.assertEqual(members['out'].mode, 0o755)


class CountTests(unittest.TestCase):
    def test_many_tables_stay_within_postgresqls_argument_limit(self):
        tables = {f'data_table_user_{i}': i + 1 for i in range(130)}
        calls = []

        class Pg:
            def query_json(self, sql, database):
                if 'pg_tables' in sql:
                    return list(tables)
                arguments = sql.count("(SELECT count(*)") * 2
                if arguments > 100:
                    raise BackupError('job-failed', 'cannot pass more than 100 arguments to a function')
                calls.append(arguments)
                return {name: tables[name] for name in re.findall(r"'([a-z0-9_]+)', \(SELECT", sql)}

        self.assertEqual(ha_n8n.count_rows(Pg(), tables), tables)
        self.assertEqual(len(calls), 4)
        self.assertLessEqual(max(calls), 100)

    def test_rows_counted_only_for_tables_that_exist(self):
        asked = []

        class Pg:
            def query_json(self, sql, database):
                asked.append(sql)
                if 'pg_tables' in sql:
                    return ['workflow_entity', 'user']
                return {'workflow_entity': 3, 'user': 1}

        found = ha_n8n.count_rows(Pg(), {'workflow_entity': 3, 'user': 1, 'gone': 2, 'bad name': 1})
        self.assertEqual(found, {'workflow_entity': 3, 'user': 1})
        self.assertNotIn('bad name', asked[-1])


if __name__ == '__main__':
    unittest.main()
