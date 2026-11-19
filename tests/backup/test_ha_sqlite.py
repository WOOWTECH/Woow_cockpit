"""The sandboxed SQLite child of the batch 1 importers (hasqlite.py): reads only ordinary tables, answers per database,
writes only Headscale's API keys, and what it wrote is copied out without following anything (CONTRACT section 9,
section 10 rule 18). Team E2."""
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import hasqlite
from woowbackup.errors import BackupError


def headscale_db(path, *, prefixes, triggers=False, wal=False):
    conn = sqlite3.connect(path)
    if wal:
        conn.execute('PRAGMA journal_mode=WAL')
    conn.executescript("""
        CREATE TABLE migrations(id text, PRIMARY KEY(id));
        CREATE TABLE users(id integer PRIMARY KEY AUTOINCREMENT, name text);
        CREATE TABLE api_keys(id integer PRIMARY KEY AUTOINCREMENT, prefix text, hash blob, expiration datetime,
                              last_seen datetime, created_at datetime);
        CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix);
        CREATE TABLE nodes(id integer PRIMARY KEY AUTOINCREMENT, ipv4 text, ipv6 text, user_id integer);
        CREATE TABLE database_versions(id integer PRIMARY KEY, version text NOT NULL, updated_at datetime);
        INSERT INTO migrations VALUES ('202507021200');
        INSERT INTO users(name) VALUES ('alice');
        INSERT INTO nodes(ipv4, ipv6, user_id) VALUES ('100.64.0.1', 'fd7a:115c:a1e0::1', 1);
        INSERT INTO database_versions VALUES (1, 'v0.29.4', '2026-11-01');
    """)
    conn.executemany('INSERT INTO api_keys(prefix, hash, created_at) VALUES (?, ?, ?)',
                     [(p, b'hash-of-' + p.encode(), '2026-11-01') for p in prefixes])
    if triggers:
        conn.execute("CREATE TRIGGER keep AFTER DELETE ON api_keys BEGIN "
                     "INSERT INTO api_keys(prefix, hash) VALUES (old.prefix, old.hash); END")
    conn.commit()
    if not wal:
        conn.close()
    return conn


class ChildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_reads_only_ordinary_tables_and_fixed_queries(self):
        path = self.root / 'state.db'
        conn = sqlite3.connect(path)
        conn.executescript("""
            CREATE TABLE sessions(id TEXT); CREATE TABLE messages(id TEXT);
            CREATE TABLE schema_version(version INTEGER);
            INSERT INTO schema_version VALUES (31); INSERT INTO schema_version VALUES (32);
            INSERT INTO sessions VALUES ('s1'); INSERT INTO messages VALUES ('m1'), ('m2');
            CREATE VIEW recent AS SELECT * FROM messages;
        """)
        conn.commit()
        conn.close()
        answers = hasqlite.run([{'db': 'state.db', 'check': 'quick', 'schema': True,
                                 'counts': ['sessions', 'messages', 'recent', 'msg_fts', 'msg_fts_data'],
                                 'queries': ['hermes.schema_version']}],
                               {'state.db': path}, self.root / 'work')
        answer = answers['state.db']
        self.assertIsNone(hasqlite.problem(answer))
        self.assertEqual(answer['counts'], {'sessions': 1, 'messages': 2})
        self.assertEqual(answer['values'], {'hermes.schema_version': 32})
        self.assertEqual(answer['schema']['views'], 1)
        self.assertEqual(answer['schema']['virtual'], [])
        self.assertNotIn('msg_fts_data', answer['schema']['tables'])
        self.assertFalse((self.root / 'work').exists(), 'the folder goes')

    def test_disguised_virtual_table_is_refused_before_integrity_check(self):
        for i, gap in enumerate(('\t', '\n', ' /* comment */ ')):
            path = self.root / ('virtual%d.db' % i)
            conn = sqlite3.connect(path)
            conn.execute('CREATE' + gap + 'VIRTUAL TABLE sessions USING fts5(body)')
            conn.execute("INSERT INTO sessions VALUES ('hello')")
            conn.execute("UPDATE sessions_config SET v=99 WHERE k='version'")
            conn.commit()
            conn.close()
            answer = hasqlite.run([{'db': 'x.db', 'check': 'quick', 'counts': ['sessions']}],
                                  {'x.db': path}, self.root / ('work%d' % i))['x.db']
            self.assertIn('virtual tables', answer.get('error', ''))
            self.assertNotIn('check', answer)
            self.assertNotIn('counts', answer)

    def test_a_wal_is_applied_on_the_childs_copy_only(self):
        conn = headscale_db(self.root / 'db.sqlite', prefixes=['aaaa'], wal=True)
        conn.execute('PRAGMA wal_autocheckpoint=0')
        conn.execute("INSERT INTO users(name) VALUES ('bob')")
        conn.commit()
        staged = self.root / 'staged'
        staged.mkdir()
        for name in ('db.sqlite', 'db.sqlite-wal'):
            (staged / name).write_bytes((self.root / name).read_bytes())
        conn.close()
        before = {name: (staged / name).read_bytes() for name in ('db.sqlite', 'db.sqlite-wal')}
        answers = hasqlite.run([{'db': 'db.sqlite', 'counts': ['users']}],
                               {'db.sqlite': staged / 'db.sqlite', 'db.sqlite-wal': staged / 'db.sqlite-wal'},
                               self.root / 'work')
        self.assertEqual(answers['db.sqlite']['counts'], {'users': 2})
        self.assertEqual({name: (staged / name).read_bytes() for name in before}, before)

    def test_garbage_is_an_answer_not_a_crash(self):
        (self.root / 'x.db').write_bytes(b'SQLite format 3\x00' + b'\xff' * 4000)
        answer = hasqlite.run([{'db': 'x.db', 'check': 'integrity'}], {'x.db': self.root / 'x.db'},
                              self.root / 'work')['x.db']
        self.assertIsNotNone(hasqlite.problem(answer))

    def test_requests_are_checked(self):
        for spec in ({'db': 'other'}, {'db': 'x.db', 'queries': ['DROP TABLE x']}, {'db': 'x.db', 'counts': ['a b']},
                     {'db': 'x.db', 'check': 'full'}, {'db': 'x.db', 'replace_api_keys_from': 'elsewhere'}):
            with self.subTest(spec=spec), self.assertRaises(BackupError):
                hasqlite.run([spec], {'x.db': self.root / 'x.db'}, self.root / 'work')
        with self.assertRaises(BackupError):
            hasqlite.run([], {'../x': self.root / 'x.db'}, self.root / 'work')

    def test_a_cancel_stops_the_child(self):
        headscale_db(self.root / 'db.sqlite', prefixes=[])

        class Stop(Exception):
            pass

        def checkpoint():
            raise Stop()

        with self.assertRaises(Stop):
            hasqlite.run([{'db': 'db.sqlite'}], {'db.sqlite': self.root / 'db.sqlite'}, self.root / 'work',
                         checkpoint=checkpoint)
        self.assertFalse((self.root / 'work').exists())

    def test_the_child_drops_its_privileges_before_it_opens_anything(self):
        child = hasqlite.CHILD
        self.assertLess(child.index('os.chroot(".")'), child.index('os.setuid(uid)'))
        self.assertLess(child.index('os.setuid(uid)'), child.index('sqlite3.connect('))
        self.assertIn('SQLITE_DBCONFIG_DEFENSIVE', child)
        self.assertIn('PRAGMA trusted_schema=OFF', child)
        with mock.patch.object(hasqlite.subprocess, 'Popen', wraps=hasqlite.subprocess.Popen) as popen:
            headscale_db(self.root / 'db.sqlite', prefixes=[])
            hasqlite.run([{'db': 'db.sqlite'}], {'db.sqlite': self.root / 'db.sqlite'}, self.root / 'work')
        self.assertEqual(popen.call_args.args[0][:4], [hasqlite.sys.executable, '-I', '-S', '-c'])


class ApiKeyTests(unittest.TestCase):
    """Headscale (D3): HA's API keys must not stay valid here; this device's must."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / 'out'
        self.out.mkdir()

    def replace(self, ha, live):
        return hasqlite.run([{'db': 'live.sqlite', 'check': 'integrity'},
                             {'db': 'ha.sqlite', 'check': 'integrity', 'replace_api_keys_from': 'live.sqlite',
                              'queries': ['headscale.api_key_prefixes']}],
                            {'ha.sqlite': ha, 'live.sqlite': live}, self.root / 'work', outputs=('ha.sqlite',),
                            out_dir=self.out)

    def test_the_live_keys_replace_has(self):
        headscale_db(self.root / 'ha', prefixes=['ha-key-1', 'ha-key-2'])
        headscale_db(self.root / 'live', prefixes=['live-headplane', 'live-mcp'])
        answers = self.replace(self.root / 'ha', self.root / 'live')
        self.assertEqual(answers['ha.sqlite']['replaced'], {'api_keys': 2, 'prefixes': ['live-headplane', 'live-mcp']})
        self.assertEqual(answers['ha.sqlite']['values']['headscale.api_key_prefixes'], ['ha-key-1', 'ha-key-2'],
                         'read before the write')
        written = answers[None]['ha.sqlite']
        self.assertEqual(os.stat(written).st_mode & 0o777, 0o600)
        conn = sqlite3.connect(written)
        rows = conn.execute('SELECT prefix, hash FROM api_keys ORDER BY id').fetchall()
        users = conn.execute('SELECT name FROM users').fetchall()
        conn.close()
        self.assertEqual(rows, [('live-headplane', b'hash-of-live-headplane'), ('live-mcp', b'hash-of-live-mcp')])
        self.assertEqual(users, [('alice',)], "HA's other data is kept")
        self.assertNotIn('hash-of', repr(answers), 'no hash ever leaves the child')

    def test_busy_checkpoint_is_rejected(self):
        headscale_db(self.root / 'ha', prefixes=['ha-key'])
        headscale_db(self.root / 'live', prefixes=['live'])
        child = hasqlite.CHILD.replace('conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()', '(1, 5, 2)')
        with mock.patch.object(hasqlite, 'CHILD', child):
            answers = self.replace(self.root / 'ha', self.root / 'live')
        self.assertIn('checkpoint did not complete', answers['ha.sqlite']['error'])
        self.assertNotIn('replaced', answers['ha.sqlite'])

    def test_a_trigger_that_would_keep_has_keys_is_refused(self):
        headscale_db(self.root / 'ha', prefixes=['ha-key'], triggers=True)
        headscale_db(self.root / 'live', prefixes=['live'])
        answers = self.replace(self.root / 'ha', self.root / 'live')
        self.assertIn('triggers', answers['ha.sqlite']['error'])

    def test_a_damaged_live_copy_stops_the_swap(self):
        headscale_db(self.root / 'ha', prefixes=['ha-key'])
        (self.root / 'live').write_bytes(b'SQLite format 3\x00' + b'\xff' * 4000)
        answers = self.replace(self.root / 'ha', self.root / 'live')
        self.assertIsNotNone(hasqlite.problem(answers['ha.sqlite']))
        self.assertIsNotNone(hasqlite.problem(answers['live.sqlite']))

    def test_what_the_child_left_is_copied_out_without_following_links(self):
        work = self.root / 'w'
        work.mkdir()
        (self.root / 'secret').write_bytes(b'host secret')
        os.symlink(self.root / 'secret', work / 'a.sqlite')
        with self.assertRaises(BackupError):
            hasqlite._copy_out(work, 'a.sqlite', self.out, '資料庫')
        os.link(self.root / 'secret', work / 'b.sqlite')
        with self.assertRaises(BackupError):
            hasqlite._copy_out(work, 'b.sqlite', self.out, '資料庫')
        (work / 'c.sqlite').mkdir()
        with self.assertRaises(BackupError):
            hasqlite._copy_out(work, 'c.sqlite', self.out, '資料庫')
        self.assertEqual(sorted(os.listdir(self.out)), [])


if __name__ == '__main__':
    unittest.main()
