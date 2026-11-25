"""The sandboxed SQLite child of the batch 1 importers (hasqlite.py): reads only ordinary tables, answers per database,
writes only Headscale's API keys, and what it wrote is copied out without following anything (CONTRACT section 9,
section 10 rule 18). Team E2."""
import os
import re
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

    def test_hermes_fts_is_strictly_scoped_and_still_checked(self):
        definitions = [
            ("messages_fts USING fts5(content)", True),
            ("messages_fts_trigram USING fts5(content, tokenize='trigram')", True),
            ("messages_fts USING fts5(content, tokenize='porter')", False),
            ("other USING fts5(content)", False),
        ]
        for i, (definition, allowed) in enumerate(definitions):
            path = self.root / ('fts%d.db' % i)
            conn = sqlite3.connect(path)
            conn.execute('CREATE TABLE messages(id INTEGER)')
            conn.execute('CREATE VIRTUAL TABLE ' + definition)
            conn.close()
            def run(spec, suffix):
                return hasqlite.run([spec], {'state.db': path}, self.root / ('work%d%s' % (i, suffix)))['state.db']
            spec = {'db': 'state.db', 'check': 'quick', 'counts': ['messages', 'messages_fts_data'], 'hermes_fts': True}
            answer = run(spec, 'a')
            if allowed:
                self.assertEqual(answer.get('check'), ['ok'])
                self.assertEqual(answer['counts'], {'messages': 0})
            else:
                self.assertIn('virtual tables', answer.get('error', ''))
                self.assertNotIn('check', answer)
            self.assertIn('virtual tables', run({'db': 'state.db', 'check': 'quick'}, 'b').get('error', ''))
        with self.assertRaises(BackupError):
            hasqlite.run([{'db': 'state.db', 'check': 'integrity', 'hermes_fts': True}],
                         {'state.db': path}, self.root / 'invalid')

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

    def test_python_without_os_unshare_uses_libc_and_still_fails_closed(self):
        # Python < 3.12 has no os.unshare (Debian 12 ships 3.11, e.g. the ARM54 target, where the 2026-11-23 child
        # stopped every import with NO_NETNS): the child makes the same system call through libc and still stops
        # with NO_NETNS when it is refused. tests/e2e/lab/arm54_final_sandbox_probe.py runs it as root on 3.11.
        child = hasqlite.CHILD
        start, chroot = child.index('if os.geteuid() == 0:'), child.index('os.chroot(".")')
        block = child[start:chroot]
        self.assertIn('ctypes.CDLL(None, use_errno=True).unshare(0x40000000)', block)
        self.assertIsNone(re.search(r'\bpass\b', block))
        if os.geteuid() == 0:
            self.skipTest('root may leave the network namespace; the refusal needs an unprivileged run')
        code = ('import os\nif hasattr(os, "unshare"):\n    del os.unshare\n'
                + block.replace('if os.geteuid() == 0:\n', 'if True:\n', 1) + 'print("continued")\n')
        proc = hasqlite.subprocess.run([hasqlite.sys.executable, '-I', '-S', '-c', code], capture_output=True,
                                       timeout=30)
        self.assertEqual(proc.returncode, hasqlite.NO_NETNS)
        self.assertNotIn(b'continued', proc.stdout)

    def test_a_child_that_cannot_leave_the_network_stops_the_job(self):
        # Run as root it must not fall back to the host's network (found by the 2026-11-23 review: the old child
        # passed over a failed unshare and could connect to 127.0.0.1). Unprivileged tests check the order and the
        # parent's mapping; tests/e2e/lab/hasqlite_sandbox_review.py runs the real child as root.
        child = hasqlite.CHILD
        start, chroot = child.index('os.unshare(os.CLONE_NEWNET)'), child.index('os.chroot(".")')
        self.assertLess(start, chroot)
        self.assertIn('os._exit(3)', child[start:chroot])
        self.assertIsNone(re.search(r'\bpass\b', child[start:chroot]))
        self.assertEqual(hasqlite.NO_NETNS, 3)
        proc = hasqlite.subprocess.Popen([hasqlite.sys.executable, '-c', 'import sys; sys.exit(3)'],
                                         stdout=hasqlite.subprocess.PIPE)
        with self.assertRaises(BackupError) as caught:
            hasqlite._read(proc, {'x.db'}, checkpoint=None, timeout=30, what='資料庫')
        proc.stdout.close()
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertIn('切斷網路', caught.exception.message)
        # The same status after an answer is a broken run, not a network refusal.
        proc = hasqlite.subprocess.Popen([hasqlite.sys.executable, '-c',
                                          'import json, sys; print(json.dumps({"db": "x.db"})); sys.exit(3)'],
                                         stdout=hasqlite.subprocess.PIPE)
        with self.assertRaises(BackupError) as caught:
            hasqlite._read(proc, {'x.db'}, checkpoint=None, timeout=30, what='資料庫')
        proc.stdout.close()
        self.assertEqual(caught.exception.code, 'corrupt-archive')


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


class PolicyTests(unittest.TestCase):
    """Headscale (S3): a policy of this device's own database is kept when HA's database comes (`replace_policies_from`); HA's
    own policy rows go, the other data stays; the same checks as for the API keys."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / 'out'
        self.out.mkdir()

    def database(self, name, texts, *, extra_column=False, triggers=False):
        headscale_db(self.root / name, prefixes=['key'], triggers=triggers)
        conn = sqlite3.connect(self.root / name)
        conn.execute('CREATE TABLE policies(id integer PRIMARY KEY AUTOINCREMENT, created_at datetime, updated_at datetime, '
                     f'deleted_at datetime, data text{", note text" if extra_column else ""})')
        conn.executemany('INSERT INTO policies(created_at, data) VALUES (?, ?)', [('2026-11-01', text) for text in texts])
        conn.commit()
        conn.close()

    def copy(self, ha='ha', live='live', keys=False):
        spec = {'db': 'ha.sqlite', 'check': 'integrity', 'counts': ['policies', 'users'], 'replace_policies_from': 'live.sqlite'}
        if keys:
            spec['replace_api_keys_from'] = 'live.sqlite'
        out = Path(tempfile.mkdtemp(dir=self.root))   # one folder for every run
        return hasqlite.run([{'db': 'live.sqlite', 'check': 'integrity'}, spec], {'ha.sqlite': self.root / ha, 'live.sqlite': self.root / live},
                            self.root / 'work', outputs=('ha.sqlite',), out_dir=out)

    def rows(self, path):
        conn = sqlite3.connect(path)
        try:
            return conn.execute('SELECT id, created_at, data FROM policies ORDER BY id').fetchall()
        finally:
            conn.close()

    def test_this_devices_policies_replace_has(self):
        self.database('ha', ['{"acls": ["ha"]}'])
        self.database('live', ['{"acls": ["one"]}', '{"acls": ["two"]}'])
        answers = self.copy()
        self.assertEqual(answers['ha.sqlite']['replaced'], {'policies': 2})
        self.assertEqual(answers['ha.sqlite']['counts'], {'policies': 1, 'users': 1}, 'read before the write')
        written = answers[None]['ha.sqlite']
        self.assertEqual(os.stat(written).st_mode & 0o777, 0o600)
        self.assertEqual(self.rows(written), [(1, '2026-11-01', '{"acls": ["one"]}'), (2, '2026-11-01', '{"acls": ["two"]}')])
        conn = sqlite3.connect(written)
        self.assertEqual(conn.execute('SELECT name FROM users').fetchall(), [('alice',)], "HA's other data is kept")
        conn.close()

    def test_a_device_without_a_policy_empties_has(self):
        self.database('ha', ['{"acls": ["stale"]}'])
        self.database('live', [])
        answers = self.copy()
        self.assertEqual(answers['ha.sqlite']['replaced'], {'policies': 0})
        self.assertEqual(self.rows(answers[None]['ha.sqlite']), [])

    def test_together_with_the_api_keys(self):
        self.database('ha', ['{"acls": ["ha"]}'])
        self.database('live', ['{"acls": ["mine"]}'])
        answers = self.copy(keys=True)
        self.assertEqual(answers['ha.sqlite']['replaced'], {'api_keys': 1, 'prefixes': ['key'], 'policies': 1})
        self.assertEqual([row[2] for row in self.rows(answers[None]['ha.sqlite'])], ['{"acls": ["mine"]}'])

    def test_nothing_is_written_without_the_request(self):
        self.database('ha', ['{"acls": ["ha"]}'])
        self.database('live', ['{"acls": ["mine"]}'])
        answers = hasqlite.run([{'db': 'ha.sqlite', 'check': 'integrity', 'counts': ['policies']}],
                               {'ha.sqlite': self.root / 'ha'}, self.root / 'work', outputs=('ha.sqlite',), out_dir=self.out)
        self.assertNotIn('replaced', answers['ha.sqlite'])
        self.assertEqual([row[2] for row in self.rows(answers[None]['ha.sqlite'])], ['{"acls": ["ha"]}'])

    def test_what_does_not_fit_stops_it(self):
        self.database('ha', ['ha'])
        self.database('live', ['mine'], extra_column=True)
        self.assertIn('differ', self.copy()['ha.sqlite']['error'])
        self.database('ha2', ['ha'], triggers=True)
        self.database('live2', ['mine'])
        self.assertIn('triggers', self.copy('ha2', 'live2')['ha.sqlite']['error'])
        self.database('ha3', ['ha'])
        (self.root / 'live3').write_bytes(b'SQLite format 3\x00' + b'\xff' * 4000)
        answers = self.copy('ha3', 'live3')
        self.assertIsNotNone(hasqlite.problem(answers['ha.sqlite']))
        self.database('ha4', ['ha'])
        conn = sqlite3.connect(self.root / 'live4')
        conn.execute('CREATE TABLE other(id integer)')
        conn.commit()
        conn.close()
        self.assertIn('policies table missing', self.copy('ha4', 'live4')['ha.sqlite']['error'])

    def test_too_many_policies_stop_it(self):
        self.database('ha', ['ha'])
        self.database('live', [f'p{n}' for n in range(1001)])
        self.assertIn('too many policies', self.copy()['ha.sqlite']['error'])

    def test_the_request_is_checked(self):
        self.database('ha', ['ha'])
        for bad in ('elsewhere', 'ha.sqlite'):
            with self.subTest(source=bad), self.assertRaises(BackupError):
                hasqlite.run([{'db': 'ha.sqlite', 'replace_policies_from': bad}], {'ha.sqlite': self.root / 'ha'}, self.root / 'work')

    def test_the_capability_is_announced(self):
        self.assertIs(hasqlite.COPY_POLICIES, True)


if __name__ == '__main__':
    unittest.main()
