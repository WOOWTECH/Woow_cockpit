"""HA import, n8n part (ha_n8n.py; CONTRACT section 9 "Home Assistant import"): the pass over the add-on tar, the
SQLite copy (owner, counts, no views), the workflows to fix, community packages and native code, and the throwaway
source volume. Team E2."""
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import ha_instance_access, ha_n8n, ha_odoo, habackup, haissues, hatarget, jobs, tempctr
from woowbackup.errors import BackupError
from woowbackup.flows import Cancelled
from woowbackup.haissues import Sink
from woowbackup.podman import CommandError, Result

from . import hab1fakes as fk
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


def sqlite_db(path, *, owner=True, view=False, credentials=('HA probe header',)):
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE user (id TEXT, email TEXT, password TEXT, roleSlug TEXT, createdAt TEXT);
        CREATE TABLE credentials_entity (id TEXT, name TEXT, data TEXT);
        CREATE TABLE execution_entity (id INTEGER, workflowId TEXT);
        CREATE TABLE project (id TEXT);
        CREATE TABLE variables (id TEXT);
        CREATE TABLE migrations (id INTEGER, timestamp INTEGER, name TEXT);
        INSERT INTO migrations VALUES (1, 1791209478293, 'CreateAgentBudgetSpendTables1791209478293');
        INSERT INTO execution_entity VALUES (1, 'w2');
        INSERT INTO project VALUES ('p1');
    """)
    conn.executemany("INSERT INTO credentials_entity VALUES (?, ?, 'ciphertext')",
                     [(f'c{i}', name) for i, name in enumerate(credentials)])
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
        issue = issues_of(_source(), info)['n8n.no-owner']
        self.assertEqual(issue.level, 'stop')
        self.assertIn(ha_n8n.NO_OWNER, issue.message)

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
        # As root the child chroots into its folder before it drops to nobody: SQLite opens the file by its full path,
        # and nobody may not pass the job's 0700 staging folders above it (found on dev-c, 2026-11-18).
        child = ha_n8n.SQLITE_CHILD
        self.assertLess(child.index('os.chroot(".")'), child.index('os.setuid(uid)'))
        self.assertLess(child.index('os.setuid(uid)'), child.index('sqlite3.connect('))

    def test_child_that_cannot_leave_the_network_stops_the_check(self):
        # Python < 3.12 has no os.unshare (Debian 12 ships 3.11, e.g. the ARM54 target): the old child passed over
        # the AttributeError (and any OSError) and read HA's n8n database with the host's network. It now makes the
        # same system call through libc and exits NO_NETNS when it cannot; the parent stops with a clear message.
        # tests/e2e/lab/arm54_final_n8n_sandbox_probe.py runs the real child set-up as root on .54 (Python 3.11).
        child = ha_n8n.SQLITE_CHILD
        start, chroot = child.index('if os.geteuid() == 0:'), child.index('os.chroot(".")')
        block = child[start:chroot]
        self.assertIn('ctypes.CDLL(None, use_errno=True).unshare(0x40000000)', block)
        self.assertIn('os._exit(3)', block)
        self.assertIsNone(re.search(r'\bpass\b', block))
        self.assertEqual(ha_n8n.NO_NETNS, 3)
        proc = ha_n8n.subprocess.Popen([ha_n8n.sys.executable, '-c', 'import sys; sys.exit(3)'],
                                       stdout=ha_n8n.subprocess.PIPE)
        try:
            with self.assertRaises(BackupError) as caught:
                ha_n8n._read_child(proc, None)
        finally:
            proc.stdout.close()
        self.assertEqual(caught.exception.code, 'job-failed')
        if os.geteuid() == 0:
            self.skipTest('root may leave the network namespace; the refusal needs an unprivileged run')
        code = ('import os\nif hasattr(os, "unshare"):\n    del os.unshare\n'
                + block.replace('if os.geteuid() == 0:\n', 'if True:\n', 1) + 'print("continued")\n')
        done = ha_n8n.subprocess.run([ha_n8n.sys.executable, '-I', '-S', '-c', code], capture_output=True, timeout=30)
        self.assertEqual(done.returncode, ha_n8n.NO_NETNS)
        self.assertNotIn(b'continued', done.stdout)

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



OK_CHILD = """
import json
print(json.dumps({"tables": {"user": 1, "credentials_entity": 1}, "owner": ["a@b.c", True], "migration": None,
                  "workflows": True, "credentials": ["HA probe header"]}))
print(json.dumps({"end": True}))
"""


class SqliteLimitTests(unittest.TestCase):
    """N8-06, N8-07, N8-09: time by size, a second run with more room for what was killed or timed out, and a broken
    database that stops only n8n with its own words."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'database.sqlite'
        sqlite_db(self.path, credentials=('Telegram bot', 'x' * 500, 'OpenAI'))
        self.size = os.path.getsize(self.path)

    def run_child(self, script, *, expect=None, log=None):
        with mock.patch.object(ha_n8n, 'SQLITE_CHILD', script), \
                mock.patch.object(ha_n8n.subprocess, 'Popen', wraps=ha_n8n.subprocess.Popen) as popen:
            try:
                return ha_n8n.inspect_sqlite(self.path, log=log), popen
            except BackupError as error:
                if expect is None:
                    raise
                self.assertEqual(popen.call_count, expect, 'the number of runs')
                return error, popen

    def test_the_names_of_the_credentials_come_with_the_counts(self):
        info = ha_n8n.inspect_sqlite(self.path)
        self.assertEqual(info['counts']['credentials'], 3)
        self.assertEqual(info['credential_names'], ['OpenAI', 'Telegram bot', 'x' * 200], 'sorted, a long name is cut')

    def test_the_time_grows_with_the_size_and_a_second_run_gets_more_room(self):
        gib = 1024 ** 3
        self.assertEqual(ha_n8n.sqlite_limits(0), (1800, 2 * gib, 64 * 1024 ** 2), 'what a small file always got')
        seconds, memory, fsize = ha_n8n.sqlite_limits(100 * gib)
        self.assertEqual((seconds, memory, fsize), (1800 + 100 * gib // (20 * 1024 ** 2), 2 * gib, 200 * gib + 64 * 1024 ** 2))
        self.assertGreater(seconds, 1800, 'N8-06: a 100 GiB database is given more than 30 minutes')
        self.assertEqual(ha_n8n.sqlite_limits(100 * gib, 1), (2 * seconds, 4 * gib, 2 * fsize))
        self.assertEqual(ha_n8n.sqlite_limits(10 ** 15, 5)[0], 24 * 3600, 'never more than a day')
        self.assertEqual(ha_n8n.sqlite_limits(0, 9)[1], 8 * gib, 'the memory has a ceiling')

    def test_the_child_is_given_its_time_and_memory(self):
        info, popen = self.run_child(OK_CHILD)
        argv = popen.call_args.args[0]
        seconds, memory, fsize = ha_n8n.sqlite_limits(self.size)
        self.assertEqual(argv[-2:], [str(seconds), str(memory)])
        self.assertTrue(info['owner_ok'])
        self.assertIn('int(sys.argv[8]) if len(sys.argv) > 8', ha_n8n.SQLITE_CHILD)
        self.assertIn('int(sys.argv[9]) if len(sys.argv) > 9', ha_n8n.SQLITE_CHILD)

    def test_a_read_that_was_killed_is_made_again_with_more_time_and_memory(self):
        first = ha_n8n.sqlite_limits(self.size)[0]
        script = f'import os, signal, sys\nif int(sys.argv[8]) == {first}:\n    os.kill(os.getpid(), signal.SIGKILL)\n' + OK_CHILD
        said = []
        info, popen = self.run_child(script, log=said.append)
        self.assertEqual(popen.call_count, 2)
        self.assertEqual([call.args[0][-2:] for call in popen.call_args_list],
                         [[str(first), str(2 * 1024 ** 3)], [str(2 * first), str(4 * 1024 ** 3)]])
        self.assertTrue(info['owner_ok'])
        self.assertEqual(len(said), 1)
        self.assertIn('再讀一次', said[0])
        self.assertFalse((self.path.parent / 'inspect').exists())

    def test_a_child_that_ran_out_of_memory_says_so_and_is_made_again(self):
        first = ha_n8n.sqlite_limits(self.size)[1]
        script = ('import json, sys\nif int(sys.argv[9]) == %d:\n    print(json.dumps({"failed": "memory"}))\n'
                  '    sys.exit(4)\n' % first) + OK_CHILD
        info, popen = self.run_child(script)
        self.assertEqual((popen.call_count, info['owner_ok']), (2, True))

    def test_a_read_that_never_gets_done_stops_n8n_only_and_says_what_to_do(self):
        script = 'import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n'
        error, _popen = self.run_child(script, expect=2)
        self.assertEqual(error.code, 'job-failed')
        issue = error.issues[0]
        self.assertEqual((issue.id, issue.level), ('n8n.database-slow', 'stop'))
        self.assertIn('分鐘內沒有讀完', issue.message)
        self.assertIn('這台的 n8n 不會有任何變更', issue.action)
        self.assertFalse((self.path.parent / 'inspect').exists())

    def test_a_timeout_is_a_limit_too(self):
        script = 'import time\ntime.sleep(30)\n'
        with mock.patch.object(ha_n8n, 'sqlite_limits', lambda size, attempt=0: (0.3, 2 ** 31, 2 ** 26)):
            error, _popen = self.run_child(script, expect=2)
        self.assertEqual((error.code, error.issues[0].id), ('job-failed', 'n8n.database-slow'))

    def test_a_broken_database_is_not_read_twice(self):
        script = 'import json, sys\nprint(json.dumps({"failed": "database"}))\nsys.exit(5)\n'
        error, _popen = self.run_child(script, expect=1)
        self.assertEqual(error.code, 'corrupt-archive')
        issue = error.issues[0]
        self.assertEqual((issue.id, issue.level), ('n8n.database-unreadable', 'stop'))
        self.assertIn('在 HA 重新備份', issue.action)
        self.assertIn('其他應用不受影響', issue.action)

    def test_the_real_child_reports_a_database_that_is_none(self):
        self.path.write_bytes(b'SQLite format 3\x00' + b'\xff' * 4000)
        with mock.patch.object(ha_n8n.subprocess, 'Popen', wraps=ha_n8n.subprocess.Popen) as popen:
            with self.assertRaises(BackupError) as caught:
                ha_n8n.inspect_sqlite(self.path)
        self.assertEqual(popen.call_count, 1, 'what the database is does not change with more time')
        self.assertEqual(caught.exception.issues[0].id, 'n8n.database-unreadable')

    def test_a_child_with_no_word_is_tried_once_more_and_then_the_database_is_the_reason(self):
        error, _popen = self.run_child('import sys\nsys.exit(1)\n', expect=2)
        self.assertEqual((error.code, error.issues[0].id), ('corrupt-archive', 'n8n.database-unreadable'))

    def test_a_cancel_is_not_a_reason_to_read_again(self):
        class Stop(Exception):
            pass

        def checkpoint():
            raise Stop()

        with mock.patch.object(ha_n8n.subprocess, 'Popen', wraps=ha_n8n.subprocess.Popen) as popen:
            with self.assertRaises(Stop):
                ha_n8n.inspect_sqlite(self.path, checkpoint=checkpoint)
        self.assertEqual(popen.call_count, 1)

    def test_the_isolation_of_the_child_is_what_it_was(self):
        child = ha_n8n.SQLITE_CHILD
        for line in ('os.unshare(os.CLONE_NEWNET)', 'unshare(0x40000000)', 'os._exit(3)', 'os.chroot(".")', 'os.setgroups([])',
                     'os.setuid(uid)', 'SQLITE_DBCONFIG_DEFENSIVE', 'PRAGMA trusted_schema=OFF', 'PRAGMA query_only=ON'):
            self.assertIn(line, child)
        self.assertLess(child.index('os.setuid(uid)'), child.index('for limit, value in'))
        self.assertLess(child.index('for limit, value in'), child.index('sqlite3.connect('))
        self.assertNotIn('%', child[:child.index('for limit, value in')], 'the set-up lines carry no placeholder')


def _source(**fields):
    src = ha_n8n.Source()
    src.sqlite = {'database.sqlite': '/x'}
    src.key = KEY
    for key, value in fields.items():
        setattr(src, key, value)
    return src


def good_info(credentials=('HA probe header',), owner=True):
    """What inspect_sqlite answers for a good database (only what `analyse` reads)."""
    return {'owner_ok': owner, 'owner_email': 'ha-probe@probe.invalid', 'credential_names': list(credentials),
            'counts': {'credentials': len(credentials)}}


def issues_of(src, info='good', version='2.43.6', target='2.43.6', **kwargs):
    """{issue id: Issue} of what `analyse` finds (a collecting sink: the check's)."""
    sink = Sink('n8n')
    ha_n8n.analyse(sink, src, good_info() if info == 'good' else info, version, target, **kwargs)
    return {issue.id: issue for issue in sink.found}


class AnalyseTests(unittest.TestCase):
    """What HA's n8n and this device's make of each other: one id and level for every finding (haissues)."""

    def levels(self, src=None, info='good', **kwargs):
        return {issue_id: issue.level for issue_id, issue in issues_of(src or _source(), info, **kwargs).items()}

    def test_a_good_pair_says_nothing(self):
        self.assertEqual(self.levels(), {})

    def test_known_and_different_versions_still_stop_n8n_only(self):
        found = issues_of(_source(), 'good', '2.43.6', '2.44.0')
        self.assertEqual({i: x.level for i, x in found.items()}, {'version.different': 'stop'})
        self.assertIn('2.43.6', found['version.different'].message)
        self.assertIn('2.44.0', found['version.different'].message)
        self.assertEqual(self.levels(version='2.43.6-1'), {'version.different': 'stop'}, 'a suffixed add-on version is no table hit')

    def test_a_version_that_cannot_be_read_here_is_no_gate(self):
        """N8-10: the output of `n8n --version` is not x.y.z: nothing is compared, the customer is told."""
        found = issues_of(_source(), 'good', '2.43.6', None)
        self.assertEqual({i: x.level for i, x in found.items()}, {'version.target-unknown': 'notice'})
        self.assertIn('n8n', found['version.target-unknown'].message)
        self.assertEqual(self.levels(version='', target=None),
                         {'version.addon-unknown': 'notice', 'version.target-unknown': 'notice'})

    def test_no_database_in_the_backup_stops_n8n_and_says_what_to_do(self):
        """N8-14: HA's n8n has no SQLite database (it may use another one): only n8n is left out."""
        found = issues_of(_source(sqlite={}), None)
        self.assertEqual({i: x.level for i, x in found.items()}, {'n8n.no-database': 'stop'})
        self.assertIn('這台的 n8n 不會有任何變更', found['n8n.no-database'].action)
        self.assertIn('其他應用不受影響', found['n8n.no-database'].action)

    def test_an_n8n_without_an_owner_stops_n8n_only(self):
        """N8-16: nothing to move, and the first person to open the page would become the owner."""
        found = issues_of(_source(), good_info(owner=False))
        self.assertEqual({i: x.level for i, x in found.items()}, {'n8n.no-owner': 'stop'})
        self.assertIn(ha_n8n.NO_OWNER, found['n8n.no-owner'].message)
        self.assertIn('第一個打開網頁的人', found['n8n.no-owner'].message)
        self.assertIn('不匯入 n8n', found['n8n.no-owner'].action)

    def test_a_fixed_key_of_this_device_still_stops_n8n(self):
        found = issues_of(_source(), 'good', fixed_key=['n8n.container', '~/.config/n8n/n8n.env'])
        self.assertEqual({i: x.level for i, x in found.items()}, {'n8n.fixed-key': 'stop'})
        self.assertEqual(found['n8n.fixed-key'].names, ('n8n.container', '~/.config/n8n/n8n.env'))

    def test_no_key_is_one_line_to_confirm_with_the_names_of_the_credentials(self):
        """N8-15: the workflows move, the credentials cannot be opened and are entered again: the customer is asked once."""
        found = issues_of(_source(key=None), good_info(credentials=('Telegram bot', 'OpenAI')))
        self.assertEqual({i: x.level for i, x in found.items()}, {'n8n.no-key': 'confirm'})
        issue = found['n8n.no-key']
        self.assertEqual(issue.names, ('Telegram bot', 'OpenAI'))
        self.assertIn('2 個憑證', issue.message)
        self.assertIn('重新輸入', issue.message)
        self.assertNotIn('Telegram', issue.message, 'names are items, never part of the sentence (the key counts them)')

    def test_no_key_and_no_credentials_loses_nothing_so_nothing_is_asked(self):
        found = issues_of(_source(key=None), good_info(credentials=()))
        self.assertEqual({i: x.level for i, x in found.items()}, {'n8n.key-created': 'auto'})

    def test_no_key_line_in_a_conversion(self):
        """A conversion stops n8n at the line unless the customer confirmed exactly it; one more name asks again."""
        src, info = _source(key=None), good_info(credentials=('Telegram bot',))
        line = issues_of(src, info)['n8n.no-key']
        with self.assertRaises(BackupError) as caught:
            ha_n8n.analyse(Sink('n8n', ()), src, info, '2.43.6', '2.43.6')
        self.assertEqual(caught.exception.code, 'confirmation-required')
        sink = Sink('n8n', [line.key('n8n')])
        ha_n8n.analyse(sink, src, info, '2.43.6', '2.43.6')
        self.assertEqual([i.id for i in sink.found], ['n8n.no-key'])
        with self.assertRaises(BackupError) as caught:
            ha_n8n.analyse(Sink('n8n', [line.key('n8n')]), src, good_info(credentials=('Telegram bot', 'New one')),
                           '2.43.6', '2.43.6')
        self.assertEqual(caught.exception.code, 'confirmation-required')

    def test_a_stop_is_a_stop_in_a_conversion_too(self):
        """N8-18: the conversion looks again with the same words and does not go on past what stops n8n."""
        with self.assertRaises(BackupError) as caught:
            ha_n8n.analyse(Sink('n8n', ()), _source(), good_info(owner=False), '2.43.6', '2.43.6')
        self.assertEqual(caught.exception.issues[0].id, 'n8n.no-owner')
        with self.assertRaises(BackupError) as caught:
            ha_n8n.analyse(Sink('n8n', ()), _source(), good_info(), '2.43.6', '2.44.0')
        self.assertEqual(caught.exception.issues[0].id, 'version.different')

    def test_native_code_and_community_packages_are_only_told(self):
        found = issues_of(_source(native_bad=['n8n-nodes-x'], packages=[{'name': 'n8n-nodes-x', 'version': '1'}]))
        self.assertEqual({i: x.level for i, x in found.items()},
                         {'n8n.native-code': 'notice', 'n8n.community-packages': 'notice'})
        self.assertIn('n8n-nodes-x', found['n8n.native-code'].message)
        self.assertIn('重新安裝', found['n8n.native-code'].message)
        self.assertEqual(found['n8n.community-packages'].names, ('n8n-nodes-x',))
        unlisted = issues_of(_source(packages_unlisted=True))['n8n.community-packages']
        self.assertIn('清單太大', unlisted.message)

    def test_elf(self):
        self.assertTrue(ha_n8n.elf_fits(elf()))
        self.assertFalse(ha_n8n.elf_fits(elf(glibc=True)), 'glibc code does not run on the musl image')
        self.assertFalse(ha_n8n.elf_fits(elf(machine=0xB7)), 'aarch64')
        self.assertFalse(ha_n8n.elf_fits(elf(bits=1)), '32-bit')
        self.assertIsNone(ha_n8n.elf_fits(b'not elf' * 20))

    def test_elf_follows_the_devices_processor(self):
        with mock.patch.object(ha_n8n, 'host_elf_machine', lambda: 0xB7):  # an ARM64 device (lane arm54-2, .54)
            self.assertTrue(ha_n8n.elf_fits(elf(machine=0xB7)), 'aarch64 musl code runs on the arm64 image')
            self.assertFalse(ha_n8n.elf_fits(elf(machine=0xB7, glibc=True)), 'glibc code does not')
            self.assertFalse(ha_n8n.elf_fits(elf()), 'x86-64 code does not')
            self.assertFalse(ha_n8n.elf_fits(elf(machine=0xB7, bits=1)), '32-bit')
        with mock.patch.object(ha_n8n, 'host_elf_machine', lambda: None):  # unknown: as before, x86-64
            self.assertTrue(ha_n8n.elf_fits(elf()))
            self.assertFalse(ha_n8n.elf_fits(elf(machine=0xB7)))

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


class KeyTests(unittest.TestCase):
    """N8-15: the key of HA's n8n is any text n8n takes, not only the shape of the one n8n makes itself."""

    def test_any_text_without_control_characters_is_a_key(self):
        for key in ('short', 'a b c d', 'ü中文密碼-0123', 'x' * 1024, ' leading and trailing '):
            self.assertEqual(ha_n8n._key_from(json.dumps({'encryptionKey': key}).encode()), key, key[:20])

    def test_what_is_no_key_is_no_key(self):
        for doc in ({'encryptionKey': ''}, {'encryptionKey': 'x' * 1025}, {'encryptionKey': 'two\nlines'},
                    {'encryptionKey': 'tab\there'}, {'encryptionKey': 'nul\x00'}, {'encryptionKey': 5},
                    {'encryptionKey': None}, {'other': 'KEY'}, ['encryptionKey']):
            self.assertIsNone(ha_n8n._key_from(json.dumps(doc).encode()), doc)
        self.assertIsNone(ha_n8n._key_from(b'{not json'))
        self.assertIsNone(ha_n8n._key_from(b''))

    def test_a_key_too_short_to_hide_is_not_masked_in_every_log_line(self):
        for key, masked in (('abc', False), ('abcd', True), ('  abc  ', False)):
            self.addCleanup(jobs.unmask_secret, key)
            tmp = tempfile.TemporaryDirectory()
            self.addCleanup(tmp.cleanup)
            data = json.dumps({'encryptionKey': key}).encode()
            entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': ADDON_JSON},
                       {'name': 'config/.n8n/config', 'data': data, 'mode': 0o600}]
            src = ha_n8n.scan_member(io.BytesIO(hx.tar_bytes(entries)), habackup.Report(), Path(tmp.name))
            self.assertEqual(src.key, key)
            self.assertEqual(jobs.redact(f'about {key.strip()} here') != f'about {key.strip()} here', masked, key)


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



class LargeFileTests(unittest.TestCase):
    """N8-28: no size makes n8n stop; a big file is copied as a stream and never read whole into memory."""

    def scan(self, entries, *, files=True, **limits):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        report = habackup.Report(names=haissues.Names)
        tar = ha_n8n.FileTar(root / 'files.tar') if files else None
        base = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': ADDON_JSON},
                {'name': 'config', 'type': 'dir'}, {'name': 'config/.n8n', 'type': 'dir'},
                {'name': 'config/.n8n/nodes', 'type': 'dir'}]
        with contextlib_patch(limits):
            src = ha_n8n.scan_member(io.BytesIO(hx.tar_bytes(base + entries)), report, root, files=tar)
        if tar is not None:
            tar.close()
            with tarfile.open(root / 'files.tar') as archive:
                names = {m.name: archive.extractfile(m).read() if m.isfile() else None for m in archive.getmembers()}
        else:
            names = {}
        return src, report, names

    def test_a_native_node_bigger_than_what_is_looked_at_is_copied_whole(self):
        big = elf(glibc=True) + b'\x00' * 300_000
        read = []
        original = habackup.Entry.read_all

        def read_all(entry, max_bytes):
            read.append((entry.name, entry.size))
            return original(entry, max_bytes)

        with mock.patch.object(habackup.Entry, 'read_all', read_all):
            src, report, names = self.scan([{'name': 'config/.n8n/nodes/node_modules/n8n-nodes-big/build.node', 'data': big}],
                                           NATIVE_HEAD=64 * 1024)
        self.assertEqual(names['nodes/node_modules/n8n-nodes-big/build.node'], big, 'every byte is moved')
        self.assertEqual(src.native_bad, ['n8n-nodes-big'], 'the beginning says glibc: it does not run here')
        self.assertEqual([item for item in read if item[1] > 1000], [], 'no big file is read whole into memory')
        self.assertEqual(report.skip_count(), 0, 'nothing is left out')

    def test_only_a_look_at_the_beginning_is_needed_for_a_check_that_moves_nothing(self):
        sizes = []
        original = ha_n8n._head

        def head(entry, limit):
            data = original(entry, limit)
            sizes.append(len(data))
            return data

        big = elf(machine=0xB7) + b'\x00' * 300_000
        with mock.patch.object(ha_n8n, '_head', head):
            src, _report, names = self.scan([{'name': 'config/.n8n/nodes/node_modules/n8n-nodes-arm/a.node', 'data': big}],
                                            files=False, NATIVE_HEAD=64 * 1024)
        self.assertEqual(sizes, [64 * 1024])
        self.assertEqual(src.native_bad, ['n8n-nodes-arm'], 'another processor is told by the first bytes')
        self.assertEqual(names, {})

    def test_a_package_json_too_large_to_read_is_copied_and_not_listed(self):
        data = json.dumps({'dependencies': {'n8n-nodes-x': '1.0.0'}, 'pad': 'x' * 600}).encode()
        src, report, names = self.scan([{'name': 'config/.n8n/nodes/package.json', 'data': data}], MAX_PACKAGE_JSON=500)
        self.assertEqual((src.packages, src.packages_unlisted), ([], True))
        self.assertEqual(names['nodes/package.json'], data)
        self.assertEqual(report.skip_count(), 0)
        src, _report, names = self.scan([{'name': 'config/.n8n/nodes/package.json', 'data': data}], MAX_PACKAGE_JSON=5000)
        self.assertEqual((src.packages, src.packages_unlisted), ([{'name': 'n8n-nodes-x', 'version': '1.0.0'}], False))

    def test_a_key_file_too_large_to_be_one_is_listed_as_skipped_and_is_no_key(self):
        data = json.dumps({'encryptionKey': KEY, 'pad': 'x' * 600}).encode()
        src, report, _names = self.scan([{'name': 'config/.n8n/config', 'data': data}], MAX_KEY_FILE=500)
        self.assertIsNone(src.key)
        self.assertEqual(report.skip_count('large'), 1)
        self.assertEqual(list(report.skips['large'].first), ['config/.n8n/config'])
        line = Sink('n8n').skipped(report)
        self.assertEqual((line.id, line.level), ('files.skipped', 'confirm'), 'the one line about what was left out names it')
        with self.assertRaises(BackupError) as caught:
            Sink('n8n', []).skipped(report)
        self.assertEqual(caught.exception.code, 'confirmation-required')

    def test_what_streams_is_still_counted_by_the_space_guard_and_a_full_disk_stops_the_job(self):
        """Nothing stops n8n for the size of a file, but the disk still does: the bytes are counted while they are written."""
        class Guard:
            def __init__(self):
                self.total = 0

            def wrote(self, n):
                self.total += n
                if self.total > 100_000:
                    from woowbackup import haissues as issues
                    raise issues.job_wide(BackupError('insufficient-space', '空間不足'))

        guard = Guard()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        files = ha_n8n.FileTar(root / 'files.tar', guard)
        big = elf(glibc=True) + b'\x00' * 300_000
        entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': ADDON_JSON}, {'name': 'config', 'type': 'dir'},
                   {'name': 'config/.n8n', 'type': 'dir'}, {'name': 'config/.n8n/nodes', 'type': 'dir'},
                   {'name': 'config/.n8n/nodes/node_modules/n8n-nodes-big/b.node', 'data': big}]
        with contextlib_patch({'NATIVE_HEAD': 64 * 1024}), self.assertRaises(BackupError) as caught:
            ha_n8n.scan_member(io.BytesIO(hx.tar_bytes(entries)), habackup.Report(), root, files=files, guard=guard)
        self.assertEqual(caught.exception.code, 'insufficient-space')
        self.assertTrue(haissues.is_job_wide(caught.exception))
        files.close()

    def test_a_truncated_native_file_still_stops_the_app_with_the_member_named_in_the_error(self):
        big = elf(glibc=True) + b'\x00' * 300_000
        entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': ADDON_JSON}, {'name': 'config', 'type': 'dir'},
                   {'name': 'config/.n8n', 'type': 'dir'}, {'name': 'config/.n8n/nodes', 'type': 'dir'},
                   {'name': 'config/.n8n/nodes/node_modules/n8n-nodes-big/b.node', 'data': big}]
        data = hx.tar_bytes(entries)
        cut = data[:len(data) - 200_000]    # the end of the archive and the second half of the file are gone
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        files = ha_n8n.FileTar(root / 'files.tar')
        self.addCleanup(files.close)
        with contextlib_patch({'NATIVE_HEAD': 64 * 1024}), self.assertRaises(BackupError) as caught:
            ha_n8n.scan_member(io.BytesIO(cut), habackup.Report(), root, files=files)
        self.assertEqual(caught.exception.code, 'corrupt-archive')

    def test_the_old_limits_are_raised_not_removed(self):
        self.assertGreaterEqual(ha_n8n.MAX_KEY_FILE, 1024 * 1024)
        self.assertGreaterEqual(ha_n8n.NATIVE_HEAD, 64 * 1024 * 1024)
        self.assertGreater(ha_n8n.MAX_PACKAGE_JSON, 0)


def contextlib_patch(values):
    """mock.patch.object(ha_n8n, name, value) for every (name, value) of `values`, as one context."""
    import contextlib
    stack = contextlib.ExitStack()
    for name, value in values.items():
        stack.enter_context(mock.patch.object(ha_n8n, name, value))
    return stack



QUADLETS = {
    'n8n.container': b'[Container]\nContainerName=n8n\nImage=docker.io/n8nio/n8n:2.43.6\n'
                     b'Network=n8n.network\nEnvironment=DB_POSTGRESDB_HOST=n8n-postgres\n'
                     b'Volume=n8n-data.volume:/home/node/.n8n\n',
    'n8n-postgres.container': b'[Container]\nContainerName=n8n-postgres\nImage=docker.io/library/postgres:16.15-alpine\n'
                              b'Environment=POSTGRES_USER=n8n\nEnvironment=POSTGRES_DB=n8n\n'
                              b'Network=n8n.network\n'
                              b'Volume=n8n-pg.volume:/var/lib/postgresql/data\n',
    'n8n-valkey.container': b'[Container]\nContainerName=n8n-valkey\nImage=docker.io/valkey/valkey:8\n'
                            b'Volume=n8n-valkey.volume:/data\n',
    'n8n-data.volume': b'[Volume]\nVolumeName=n8n_n8n_data\n',
    'n8n-pg.volume': b'[Volume]\nVolumeName=n8n_postgres_data\n',
    'n8n-valkey.volume': b'[Volume]\nVolumeName=n8n_valkey_data\n',
}
PG = {'id': 'main', 'container': 'n8n-postgres', 'user': 'n8n', 'database': 'n8n'}


def n8n_app(*, volumes=('n8n_n8n_data', 'n8n_valkey_data'), data_dirs=(), postgres=None):
    return types.SimpleNamespace(id='n8n', name='n8n 工作流程', owner='appowner', postgres=[PG] if postgres is None else postgres,
                                 volumes=[{'name': name} for name in volumes], data_dirs=[{'path': path} for path in data_dirs])


VENDOR_CONFIG = Path(__file__).resolve().parents[2] / 'snippets/focus-instance-db-resolution/vendor'

# Run the product's fixed JS with the pinned, actual vendor Config/Env implementation. Only DI registration/metadata
# and the container's /proc/module locations are fixtures; setting precedence and normalization execute vendor code.
CONNECTION_HARNESS = r"""
const nativeFS = require('node:fs');
const moduleAPI = require('node:module');
const fixture = JSON.parse(nativeFS.readFileSync(0, 'utf8'));
if (fixture.self_cmdline) {
    // A real container lists the probe itself: it runs as `node -e <its whole source>`, so its OWN command line is far
    // longer than any n8n start command. Model that entry before any file-system override below is installed.
    const own = fixture.root + '/proc/' + process.pid;
    nativeFS.mkdirSync(own, {recursive: true});
    nativeFS.writeFileSync(own + '/cmdline', Buffer.alloc(fixture.self_cmdline, 0x61));
}
const factories = new Map(), metadata = new WeakMap();
Reflect.defineMetadata = (kind, type, target, key) => {
    let fields = metadata.get(target); if (!fields) metadata.set(target, fields = new Map()); fields.set(key, type);
};
Reflect.getMetadata = (kind, target, key) => metadata.get(target)?.get(key);
const Container = {get: target => factories.get(target)()};
const Service = ({factory}) => target => factories.set(target, factory);
const z = {ZodType: class {}};
let source = nativeFS.readFileSync(fixture.vendor, 'utf8');
source = source.replace(/^import .*;\n/gm, '');
source = moduleAPI.stripTypeScriptTypes(source).replace(/^export /gm, '');
const vendor = new Function('readFileSync', 'Container', 'Service', 'z', source + '\nreturn {Config, Env};')(
    (...args) => nativeFS.readFileSync(...args), Container, Service, z);
const realOpen = nativeFS.openSync, realReadFile = nativeFS.readFileSync;
nativeFS.openSync = function(file, ...args) {
    if (file.includes('/password')) throw new Error('password read forbidden');
    return realOpen.call(this, file.startsWith('/proc/') ? fixture.root + file : file, ...args);
};
nativeFS.readFileSync = function(file, ...args) {
    if (typeof file === 'string' && file.includes('/password')) throw new Error('password read forbidden');
    return realReadFile.call(this, file, ...args);
};
const realReaddir = nativeFS.readdirSync, realRealpath = nativeFS.realpathSync;
const realReadlink = nativeFS.readlinkSync;
nativeFS.readlinkSync = file => file.startsWith('/proc/') && file.endsWith('/exe') ? '/usr/local/bin/node' : realReadlink(file);
nativeFS.readdirSync = (file, ...args) => realReaddir(file === '/proc' ? fixture.root + file : file, ...args);
nativeFS.realpathSync = file => file === '/usr/local/bin/n8n' ? '/usr/local/lib/node_modules/n8n/bin/n8n' : realRealpath(file);
const realChdir = process.chdir;
process.chdir = file => realChdir(file.startsWith('/proc/') ? fixture.root + file : file);
moduleAPI.createRequire = file => {
    const loader = name => {
        if (name === './decorators') return vendor;
        if (name === '@n8n/di') return {Container};
        if (name === 'dotenv') return require(fixture.dotenv);
        throw new Error('unexpected vendor module');
    };
    loader.resolve = name => {
        if (name !== '@n8n/config') throw new Error('unexpected resolution');
        return '/vendor/config/index.js';
    };
    return loader;
};
"""


class ConnectionRunner:
    home = '/home/appowner'

    def __init__(self, env=None, *, exec_env=None, files=None, processes=1, command=None, self_cmdline=None):
        self.env, self.exec_env, self.files = env or {}, exec_env or {}, files or {}
        self.processes, self.command, self.self_cmdline = processes, command, self_cmdline
        self.calls = []

    def podman(self, *args, **kwargs):
        if args[:4] == ('container', 'inspect', '--format', '{{.State.Running}}'):
            return Result(0, b'true', b'')
        if not shutil.which('node'):
            raise unittest.SkipTest('node is needed to execute the fixed selected-field reader')
        assert args == ('exec', '--env', 'NODE_OPTIONS=', '--env', 'NODE_PATH=', 'n8n', 'node', '-e', ha_n8n.CONNECTION_PROBE)
        assert kwargs == {'timeout': 30, 'max_output': 1024, 'check': False}
        self.calls.append(args)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for index in range(self.processes):
                process = root / 'proc' / str(index + 7)
                process.mkdir(parents=True)
                (process / 'cwd').mkdir()
                (process / 'cmdline').write_bytes(self.command or b'n8n\0\0\0')
                (process / 'environ').write_bytes(b''.join(k.encode() + b'=' + v.encode() + b'\0' for k, v in self.env.items()))
                for name, data in self.files.items():
                    if data is None:
                        (process / 'cwd' / name).mkdir()
                    else:
                        (process / 'cwd' / name).write_bytes(data)
            if not self.processes:
                (root / 'proc').mkdir()
            fixture = {'root': folder, 'vendor': str(VENDOR_CONFIG / 'decorators.ts'),
                       'dotenv': str(VENDOR_CONFIG / 'dotenv/lib/main.js'), 'self_cmdline': self.self_cmdline}
            result = subprocess.run([shutil.which('node'), '--disable-warning=ExperimentalWarning', '-e', CONNECTION_HARNESS + args[-1]],
                                    input=json.dumps(fixture).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env={'PATH': os.defpath, 'LANG': 'C.UTF-8', **self.exec_env}, timeout=10)
            # Never expose raw stderr, even in a failed assertion.
            assert len(result.stdout) <= 1024, 'probe output exceeded its fixed-field budget'
            return Result(result.returncode, result.stdout, b'private bounded diagnostics omitted')


def target_of(quadlets=None, app=None, runner=None):
    """(Target, the sink it told its findings to) for these Quadlet files and app settings."""
    quadlets = dict(QUADLETS if quadlets is None else quadlets)
    runner = runner or ConnectionRunner(ha_n8n.tempctr.quadlet_environment(
        quadlets.get('n8n.container', b''), {'DB_POSTGRESDB_DATABASE', 'DB_POSTGRESDB_USER',
                                          'DB_POSTGRESDB_HOST', 'DB_POSTGRESDB_PORT'}))
    work = types.SimpleNamespace(quadlets=lambda _app: quadlets, runner=lambda _app: runner)
    sink = Sink('n8n')
    return ha_n8n.Target(work, app or n8n_app(), sink), sink


class ConnectionTests(unittest.TestCase):
    def connection(self, env=None, **kwargs):
        return ha_n8n.read_target_connection(ConnectionRunner(env, **kwargs), 'n8n')

    def endpoint(self, env=None, **kwargs):
        return ha_n8n.read_app_endpoint(ConnectionRunner(env, **kwargs), QUADLETS)

    def test_probe_ignores_its_own_huge_command_line_in_the_process_list(self):
        # dev-c, real n8n 2.43.6: the probe runs as `node -e <its whole source>`, so its OWN /proc entry has a command line
        # far above the 4096-byte read limit. Reading it threw 'oversized input' and every readiness poll failed for 300 s.
        for size in (5000, 70000):
            with self.subTest(self_cmdline=size):
                self.assertEqual(self.endpoint(self_cmdline=size),
                                 {'database': 'n8n', 'user': 'postgres', 'host': 'localhost', 'port': 5432})

    def test_a_foreign_oversized_command_line_still_fails_closed(self):
        # Only the probe itself is exempt: another process with an oversized command line is an anomaly, not a candidate.
        with self.assertRaises(BackupError):
            self.endpoint(processes=2, command=b'n8n\0' + b'a' * 5000)

    def test_endpoint_defaults_and_exact_two_field_projection(self):
        self.assertEqual(self.endpoint(), {'database': 'n8n', 'user': 'postgres', 'host': 'localhost', 'port': 5432})
        self.assertEqual(set(self.connection()), {'database', 'user'})

    def test_endpoint_uses_vendor_direct_file_precedence_dotenv_and_process_title(self):
        env = {'DB_POSTGRESDB_HOST': 'n8n-postgres', 'DB_POSTGRESDB_PORT': '6543',
               'DB_POSTGRESDB_HOST_FILE': 'missing', 'DB_POSTGRESDB_PORT_FILE': 'missing'}
        self.assertEqual((self.endpoint(env)['host'], self.endpoint(env)['port']), ('n8n-postgres', 6543))
        endpoint = self.endpoint({'DB_POSTGRESDB_HOST_FILE': 'host', 'DB_POSTGRESDB_PORT_FILE': 'port'},
                                 files={'host': b'  "n8n-postgres"\n', 'port': b' 6543\n'}, command=b'n8n start\0')
        self.assertEqual((endpoint['host'], endpoint['port']), ('n8n-postgres', 6543))
        endpoint = self.endpoint(files={'.env': b'DB_POSTGRESDB_HOST=n8n-postgres\nDB_POSTGRESDB_PORT=6543\n'})
        self.assertEqual((endpoint['host'], endpoint['port']), ('n8n-postgres', 6543))
        self.assertEqual(self.endpoint({'DB_POSTGRESDB_HOST': '::1'})['host'], '::1')

    def test_endpoint_rejects_unsafe_hosts_ports_and_incomplete_output(self):
        for env in ({'DB_POSTGRESDB_HOST': '/var/run/postgresql'}, {'DB_POSTGRESDB_HOST': 'host name'},
                    {'DB_POSTGRESDB_HOST': 'x' * 254}, {'DB_POSTGRESDB_PORT': '0'},
                    {'DB_POSTGRESDB_PORT': '65536'}, {'DB_POSTGRESDB_PORT': '12.5'}):
            with self.subTest(keys=sorted(env)), self.assertRaises(BackupError):
                self.endpoint(env)
        for port in (True, '5432', 0, 65536):
            body = json.dumps({'database': 'n8n', 'user': 'postgres', 'host': 'localhost', 'port': port}).encode()
            runner = types.SimpleNamespace(podman=lambda *a, **k: Result(0, body, b'private'))
            with self.subTest(port_type=type(port).__name__), self.assertRaises(BackupError):
                ha_n8n._read_target_endpoint(runner, 'n8n')

    def test_default_is_n8n_and_postgres_independently_of_server_bootstrap(self):
        self.assertEqual(self.connection({'POSTGRES_DB': 'unrelated', 'POSTGRES_USER': 'bootstrap'}),
                         {'database': 'n8n', 'user': 'postgres'})

    def test_reference_is_bound_to_the_trusted_vendor_revision_and_actual_defaults(self):
        reference = json.loads((VENDOR_CONFIG / 'source.json').read_bytes())
        self.assertEqual(reference['revision'], 'ffbb9ec54fc02e7f8b54a0b6f41d0a84d0a817f5')
        for row in reference['files']:
            self.assertEqual(hashlib.sha256((VENDOR_CONFIG / row['file']).read_bytes()).hexdigest(), row['sha256'])
        database = (VENDOR_CONFIG / 'database.config.ts').read_text()
        self.assertRegex(database, r"@Env\('DB_POSTGRESDB_DATABASE'\)\s+database: string = 'n8n';")
        self.assertRegex(database, r"@Env\('DB_POSTGRESDB_USER'\)\s+user: string = 'postgres';")
        self.assertRegex(database, r"@Env\('DB_POSTGRESDB_HOST'\)\s+host: string = 'localhost';")
        self.assertRegex(database, r"@Env\('DB_POSTGRESDB_PORT'\)\s+port: number = 5432;")

    def test_direct_values_win_over_file_values_in_actual_vendor_config(self):
        self.assertEqual(self.connection({'DB_POSTGRESDB_DATABASE': 'automation', 'DB_POSTGRESDB_USER': 'app_role',
                                          'DB_POSTGRESDB_DATABASE_FILE': 'missing-db', 'DB_POSTGRESDB_USER_FILE': 'missing-user'}),
                         {'database': 'automation', 'user': 'app_role'})

    def test_file_values_use_actual_vendor_whitespace_and_quotes_normalization(self):
        self.assertEqual(self.connection({'DB_POSTGRESDB_DATABASE_FILE': 'db', 'DB_POSTGRESDB_USER_FILE': 'user'},
                                         files={'db': b'  "automation"\n', 'user': b' app_role\r\n'}),
                         {'database': 'automation', 'user': 'app_role'})
        self.assertEqual(self.connection({'DB_POSTGRESDB_DATABASE': '  "automation"\n', 'DB_POSTGRESDB_USER': " 'app_role' "}),
                         {'database': 'automation', 'user': 'app_role'})

    def test_entrypoint_process_environment_wins_over_podman_exec_environment(self):
        self.assertEqual(self.connection({'DB_POSTGRESDB_DATABASE': 'automation', 'DB_POSTGRESDB_USER': 'app_role'},
                                         exec_env={'DB_POSTGRESDB_DATABASE': 'wrong_exec_db', 'DB_POSTGRESDB_USER': 'wrong_user'}),
                         {'database': 'automation', 'user': 'app_role'})

    def test_vendor_cli_process_title_is_recognized_and_old_startup_argv_also_works(self):
        for command in (b'n8n\0\0', b'n8n start\0', b'node\0/usr/local/bin/n8n\0start\0'):
            with self.subTest(command=command):
                self.assertEqual(self.connection({'DB_POSTGRESDB_DATABASE': 'automation'}, command=command)['database'],
                                 'automation')

    def test_actual_vendor_dotenv_startup_selects_only_missing_settings(self):
        self.assertEqual(self.connection(files={'.env': b'DB_POSTGRESDB_DATABASE="automation"\nDB_POSTGRESDB_USER=app_role\n'}),
                         {'database': 'automation', 'user': 'app_role'})
        self.assertEqual(self.connection({'DB_POSTGRESDB_DATABASE': 'inline'},
                                         files={'.env': b'DB_POSTGRESDB_DATABASE=automation\n'})['database'], 'inline')
        self.assertEqual(self.connection({'E2E_TESTS': 'true'},
                                         files={'.env': b'DB_POSTGRESDB_DATABASE=automation\n'})['database'], 'n8n')

    def test_main_container_selection_is_shared_with_restore_preflight_and_rejects_ambiguity(self):
        runner = ConnectionRunner({'DB_POSTGRESDB_DATABASE': 'automation'})
        self.assertEqual(ha_n8n.read_app_connection(runner, QUADLETS)['database'], 'automation')
        with_workers = dict(QUADLETS, **{
            'n8n-worker.container': QUADLETS['n8n.container'] + b'Exec=worker\n',
            'n8n-webhook.container': QUADLETS['n8n.container'] + b'Exec=webhook\n',
            'n8n.container': QUADLETS['n8n.container'] + b'Volume=/etc/localtime:/etc/localtime:ro\n'})
        self.assertEqual(ha_n8n.read_app_connection(runner, with_workers)['database'], 'automation')
        self.assertEqual(ha_n8n.main_container(runner, with_workers), 'n8n')
        self.assertEqual(ha_n8n.read_app_endpoint(runner, with_workers)['database'], 'automation')
        for quadlets in ({}, dict(QUADLETS, **{'other.container': QUADLETS['n8n.container']})):
            with self.subTest(files=sorted(quadlets)), self.assertRaises(BackupError):
                ha_n8n.read_app_connection(runner, quadlets)

    def test_never_reads_passwords_or_ignored_secret_files(self):
        env = {'DB_POSTGRESDB_DATABASE': 'automation', 'DB_POSTGRESDB_DATABASE_FILE': '/password-ignored',
               'DB_POSTGRESDB_PASSWORD': 'private-password-sentinel', 'DB_POSTGRESDB_PASSWORD_FILE': '/password-secret'}
        self.assertEqual(self.connection(env), {'database': 'automation', 'user': 'postgres'})

    def test_ordinary_node_memory_options_do_not_hide_the_connection(self):
        self.assertEqual(self.connection({'NODE_OPTIONS': '--max-old-space-size=512 --enable-source-maps'}),
                         {'database': 'n8n', 'user': 'postgres'})

    def test_unknown_or_unreadable_inputs_stop_only_this_app(self):
        cases = [({'DB_POSTGRESDB_DATABASE': '', 'DB_POSTGRESDB_DATABASE_FILE': 'valid'}, {'files': {'valid': b'automation'}}),
                 ({'DB_POSTGRESDB_DATABASE': 'template1'}, {}),
                 ({'DB_POSTGRESDB_DATABASE': 'unsafe;DROP'}, {}), ({'DB_POSTGRESDB_USER': 'x' * 64}, {}),
                 ({'DB_POSTGRESDB_DATABASE_FILE': 'missing'}, {}),
                 ({'DB_POSTGRESDB_DATABASE_FILE': 'huge'}, {'files': {'huge': b'x' * 4097}}),
                 ({'DB_POSTGRESDB_DATABASE_FILE': 'directory'}, {'files': {'directory': None}}),
                 ({'N8N_CONFIG_FILES': 'custom.json'}, {}), ({'NODE_OPTIONS': '--require custom.js'}, {}),
                 ({}, {'processes': 0}), ({}, {'processes': 2}),
                 ({}, {'command': b'node\0/custom/bootstrap.js\0'})]
        for env, kwargs in cases:
            with self.subTest(keys=sorted(env), variant=sorted(kwargs)), self.assertRaises(BackupError) as caught:
                self.connection(env, **kwargs)
            self.assertEqual(caught.exception.code, 'incompatible')
            self.assertEqual(caught.exception.issues[0].id, 'n8n.layout-unsupported')
            self.assertNotIn('private-password-sentinel', str(caught.exception))

    def test_malformed_or_partial_reader_output_never_falls_back(self):
        for body in (b'', b'true', b'{}', b'{"database":"automation"}',
                     b'{"database":"automation","user":"role","password":"private"}'):
            runner = types.SimpleNamespace(podman=lambda *args, **kwargs: Result(0, body, b'private stderr'))
            with self.subTest(body=body), self.assertRaises(BackupError) as caught:
                ha_n8n.read_target_connection(runner, 'n8n')
            self.assertNotIn('private', str(caught.exception))


def without(name, *removed):
    """The standard Quadlet files without the files `removed`, and `name` (a file) changed by the caller afterwards."""
    return {key: value for key, value in QUADLETS.items() if key not in removed}


class TargetTests(unittest.TestCase):
    """How this device's n8n may look (N8-01, N8-02, N8-27 and the n8n side of OD-08, OD-09): what is data of its own goes along
    as it is, only the queue is emptied, and only what the import cannot tell (not a layout it knows) stops n8n."""

    def ids(self, sink):
        return {issue.id: issue.level for issue in sink.found}

    def stopped(self, quadlets, app=None):
        with self.assertRaises(BackupError) as caught:
            target_of(quadlets, app)
        self.assertEqual((caught.exception.code, caught.exception.issues[0].id, caught.exception.issues[0].level),
                         ('incompatible', 'n8n.layout-unsupported', 'stop'))
        return caught.exception.issues[0]

    def test_the_standard_layout_says_nothing(self):
        target, sink = target_of()
        self.assertEqual((target.data_volume, target.queue_volumes, target.pg_file, target.main_file),
                         ('n8n_n8n_data', ['n8n_valkey_data'], 'n8n-postgres.container', 'n8n.container'))
        self.assertEqual((target.extra_volumes, target.extra_dirs, sink.found), ([], [], []))
        self.assertEqual((target.n8n_image, target.pg_image), ('docker.io/n8nio/n8n:2.43.6', 'docker.io/library/postgres:16.15-alpine'))

    def test_a_database_container_without_a_name_has_the_one_systemd_gives_it(self):
        quadlets = dict(QUADLETS, **{'n8n-postgres.container': QUADLETS['n8n-postgres.container'].replace(b'ContainerName=n8n-postgres\n', b'')})
        app = n8n_app(postgres=[dict(PG, container='systemd-n8n-postgres')])
        target, _sink = target_of(quadlets, app)
        self.assertEqual(target.pg_file, 'n8n-postgres.container')
        issue = self.stopped(quadlets)   # the settings call it n8n-postgres, which nothing is named
        self.assertIn('n8n-postgres', issue.message)

    def test_an_n8n_without_a_queue_moves_too(self):
        """N8-02: the regular mode has one volume, the data."""
        target, sink = target_of(without('x', 'n8n-valkey.container', 'n8n-valkey.volume'), n8n_app(volumes=('n8n_n8n_data',)))
        self.assertEqual((target.queue_volumes, target.extra_volumes, sink.found), ([], [], []))

    def test_another_volume_is_this_devices_own_and_is_carried_not_emptied(self):
        """N8-02: it was refused (and, with two volumes, taken for the queue and emptied)."""
        quadlets = dict(QUADLETS, **{'n8n.container': QUADLETS['n8n.container'] + b'Volume=n8n-files.volume:/files\n',
                                     'n8n-files.volume': b'[Volume]\nVolumeName=n8n_files\n'})
        target, sink = target_of(quadlets, n8n_app(volumes=('n8n_n8n_data', 'n8n_valkey_data', 'n8n_files')))
        self.assertEqual((target.queue_volumes, target.extra_volumes), (['n8n_valkey_data'], ['n8n_files']))
        self.assertEqual(self.ids(sink), {'n8n.extras-carried': 'auto'})
        self.assertEqual(sink.found[0].names, ('n8n_files',))
        self.assertIn('原樣帶過去', sink.found[0].message)

    def test_a_second_volume_that_is_no_queue_is_never_emptied(self):
        quadlets = dict(QUADLETS, **{'n8n.container': QUADLETS['n8n.container'] + b'Volume=n8n-files.volume:/files\n',
                                     'n8n-files.volume': b'[Volume]\nVolumeName=n8n_files\n'})
        target, _sink = target_of(without('x', 'n8n-valkey.container', 'n8n-valkey.volume') | {
            k: v for k, v in quadlets.items() if k in ('n8n.container', 'n8n-files.volume')}, n8n_app(volumes=('n8n_n8n_data', 'n8n_files')))
        self.assertEqual((target.queue_volumes, target.extra_volumes), ([], ['n8n_files']))

    def test_a_volume_nobody_mounts_and_one_the_queue_shares_are_carried(self):
        target, _sink = target_of(app=n8n_app(volumes=('n8n_n8n_data', 'n8n_valkey_data', 'n8n_orphan')))
        self.assertEqual((target.queue_volumes, target.extra_volumes), (['n8n_valkey_data'], ['n8n_orphan']))
        shared = dict(QUADLETS, **{'n8n.container': QUADLETS['n8n.container'] + b'Volume=n8n-valkey.volume:/shared\n'})
        target, _sink = target_of(shared)
        self.assertEqual((target.queue_volumes, target.extra_volumes), ([], ['n8n_valkey_data']),
                         'a volume that n8n itself also mounts is not the queue\'s alone')

    def test_the_queue_is_what_its_image_says(self):
        for image, queue in (('docker.io/valkey/valkey:8', True), ('docker.io/library/redis:7.4-alpine', True),
                             ('localhost/woow-valkey:20261101', True), ('docker.io/bitnami/valkey@sha256:' + 'a' * 64, True),
                             ('localhost/my-cache:1', False), ('docker.io/redislabs/n8n:1', False),
                             ('registry.example:5000/valkeys/n8n:1', False)):
            quadlets = dict(QUADLETS, **{'n8n-valkey.container': QUADLETS['n8n-valkey.container'].replace(b'docker.io/valkey/valkey:8', image.encode())})
            target, _sink = target_of(quadlets)
            self.assertEqual(target.queue_volumes == ['n8n_valkey_data'], queue, image)

    def test_a_host_folder_of_the_app_settings_is_carried_as_it_is(self):
        """N8-27: the conversion ended with internal-error because the folder was no item of it."""
        target, sink = target_of(app=n8n_app(data_dirs=('.local/share/n8n-files',)))
        self.assertEqual((target.extra_volumes, target.extra_dirs), ([], ['.local/share/n8n-files']))
        self.assertEqual(self.ids(sink), {'n8n.extras-carried': 'auto'}, 'the check says so already')

    def test_a_mount_that_is_no_data_is_left_out_and_told(self):
        """The n8n side of OD-08 and OD-09: a time zone file stopped the whole app."""
        quadlets = dict(QUADLETS, **{'n8n.container': QUADLETS['n8n.container'] + b'Volume=/etc/localtime:/etc/localtime:ro\n'
                                                       b'Volume=%h/../elsewhere:/x\n'})
        target, sink = target_of(quadlets)
        self.assertEqual(self.ids(sink), {'n8n.mount-skipped': 'notice'})
        self.assertEqual(sink.found[0].names, ('n8n.container：/etc/localtime', 'n8n.container：/x'))
        self.assertEqual(target.data_volume, 'n8n_n8n_data')

    def test_n8n_data_on_a_host_path_stops_n8n_with_the_reason(self):
        quadlets = dict(QUADLETS, **{'n8n.container': b'[Container]\nContainerName=n8n\nImage=docker.io/n8nio/n8n:2.43.6\n'
                                                     b'Volume=/srv/n8n:/home/node/.n8n\n'})
        issue = self.stopped(quadlets)
        self.assertIn('/home/node/.n8n', issue.message)
        self.assertIn('應用設定', issue.action)
        self.assertIn('這台的 n8n 不會有任何變更', issue.action)

    def test_what_is_not_in_the_app_settings_stops_n8n(self):
        issue = self.stopped(None, n8n_app(volumes=('n8n_valkey_data',)))
        self.assertIn('n8n_n8n_data', issue.message)
        self.stopped(without('x', 'n8n-postgres.container'))

    def test_the_whole_instance_resolves_the_app_database_separately(self):
        app = n8n_app(postgres=[dict(PG, scope='instance', database='postgres')])
        target, _sink = target_of(app=app)
        self.assertTrue(target.instance)
        self.assertEqual(target.pg['database'], 'n8n')
        self.assertEqual(app.postgres[0]['database'], 'postgres', 'the normalized catalog is never changed')
        quadlets = dict(QUADLETS, **{'n8n.container': QUADLETS['n8n.container']
                                   + b'Environment=DB_POSTGRESDB_DATABASE=automation\n'})
        target, _sink = target_of(quadlets, app)
        self.assertEqual(target.pg['database'], 'automation')
        self.stopped(None, n8n_app(postgres=[PG, dict(PG, id='second', container='other')]))



class RootTests(unittest.TestCase):
    """N8-11, N8-12: the owner and mode of a data volume that cannot be read are the image's own, and it is said; the shared
    `volume_root` (EMQX, Hermes, ... use it) still refuses."""

    def work(self, mount='/home/appowner/.local/share/containers/storage/volumes/v/_data\n', stat='1000 1000 755\n', raises=None):
        class Runner:
            def podman(self, *args, **_kwargs):
                if raises is not None and args[:2] == raises[0]:
                    raise raises[1]
                if args[:2] == ('volume', 'inspect'):
                    return Result(0, mount.encode(), b'')
                if args[:2] == ('unshare', 'stat'):
                    return Result(0, stat.encode(), b'')
                raise AssertionError(args)

        return types.SimpleNamespace(runner=lambda _app: Runner())

    def root(self, **kwargs):
        sink = Sink('n8n')
        work = self.work(**kwargs)
        return ha_n8n.volume_root_or_image(work, None, 'n8n_n8n_data', lambda: (1000, 1000, 0o755), sink), sink

    def test_a_volume_that_can_be_read_is_taken_as_it_is(self):
        root, sink = self.root(stat='1013 1013 700\n')
        self.assertEqual((root, sink.found), ((1013, 1013, 0o700), []))

    def test_a_location_that_cannot_be_read_gives_the_images_owner_and_says_so(self):
        for kwargs in ({'mount': 'not a path'}, {'mount': '/a\n/b\n'}, {'stat': 'what'}, {'stat': '1 2 999999'},
                       {'raises': (('volume', 'inspect'), BackupError('job-failed', 'podman volume 執行失敗'))},
                       {'raises': (('unshare', 'stat'), BackupError('job-failed', 'podman unshare 執行失敗'))}):
            root, sink = self.root(**kwargs)
            self.assertEqual(root, (1000, 1000, 0o755), kwargs)
            self.assertEqual([(i.id, i.level, i.names) for i in sink.found],
                             [('n8n.volume-root-default', 'auto', ('n8n_n8n_data',))])
            self.assertIn('1000:1000', sink.found[0].message)
            self.assertIn('自動退回', sink.found[0].message)

    def test_what_ends_the_job_is_not_a_volume_that_cannot_be_read(self):
        for error in (haissues.job_wide(BackupError('insufficient-space', '磁碟空間不足。')),
                      BackupError('insufficient-space', '磁碟空間不足。'), BackupError('busy', '忙碌')):
            with self.assertRaises(BackupError) as caught:
                self.root(raises=(('volume', 'inspect'), error))
            self.assertIs(caught.exception, error)

    def test_the_shared_function_still_refuses(self):
        for kwargs in ({'mount': 'not a path'}, {'stat': 'what'}):
            with self.assertRaises(BackupError) as caught:
                ha_n8n.volume_root(self.work(**kwargs), None, 'some_volume')
            self.assertEqual(caught.exception.code, 'job-failed')


class QueueOwnerTests(unittest.TestCase):
    def test_the_account_of_the_queues_image_or_root(self):
        class Tmp:
            def __init__(self, answer):
                self.answer, self.asked = answer, []

            def user_ids(self, role, image, user):
                self.asked.append((role, image, user))
                if isinstance(self.answer, Exception):
                    raise self.answer
                return self.answer

        tmp = Tmp((999, 999))
        self.assertEqual(ha_n8n._queue_owner(tmp, 'docker.io/valkey/valkey:8'), (999, 999))
        self.assertEqual(ha_n8n._queue_owner(tmp, 'docker.io/library/redis:7'), (999, 999))
        self.assertEqual([user for _r, _i, user in tmp.asked], ['valkey', 'redis'])
        self.assertEqual(ha_n8n._queue_owner(Tmp(BackupError('job-failed', 'no such user')), 'docker.io/valkey/valkey:8'), (0, 0))
        with self.assertRaises(BackupError):
            ha_n8n._queue_owner(Tmp(haissues.job_wide(BackupError('insufficient-space', 'x'))), 'docker.io/valkey/valkey:8')


class FixedKeyTests(unittest.TestCase):
    """Review C-18: a live n8n with its own N8N_ENCRYPTION_KEY could not use HA's key."""

    def work(self, quadlets, files=None):
        class Runner:
            def read_file(self, rel, max_bytes=None):
                if rel not in (files or {}):
                    raise BackupError('not-found', 'x')
                return files[rel]

        return types.SimpleNamespace(quadlets=lambda _app: quadlets, runner=lambda _app: Runner())

    def test_environment_secret_and_env_file_are_found_by_name(self):
        base = b'[Container]\nImage=docker.io/n8nio/n8n:2.43.6\n'
        self.assertEqual(ha_n8n.fixed_key_settings(self.work({'n8n.container': base}), None), [])
        cases = {
            'n8n.container': base + b'Environment=N8N_ENCRYPTION_KEY=abc\n',
            'worker.container': base + b'Secret=n8n-key,type=env,target=N8N_ENCRYPTION_KEY\n',
            'other.container': base + b'EnvironmentFile=%h/.config/n8n/n8n.env\n',
        }
        files = {'.config/n8n/n8n.env': b'# comment\nDB_TYPE=postgresdb\nexport N8N_ENCRYPTION_KEY_FILE=/run/k\n'}
        found = ha_n8n.fixed_key_settings(self.work(cases, files), None)
        self.assertEqual(found, ['n8n.container', 'worker.container', '~/.config/n8n/n8n.env'])
        quiet = {'n8n.container': base + b'Environment=N8N_HOST=x\nEnvironmentFile=%h/missing.env\n'
                                         b'Secret=n8n-key,type=mount,target=N8N_ENCRYPTION_KEY\n'}
        self.assertEqual(ha_n8n.fixed_key_settings(self.work(quiet), None), [])
        issue = issues_of(_source(), None, fixed_key=found)['n8n.fixed-key']
        self.assertEqual((issue.level, issue.names), ('stop', tuple(found)))
        self.assertIn('N8N_ENCRYPTION_KEY', issue.message)


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

    def test_the_rows_are_counted_in_the_database_of_the_app_settings(self):
        """N8-21: it was always `n8n`; a catalog entry with another database name ended in a psql error nobody could read."""
        asked = []

        class Pg:
            def query_json(self, sql, database):
                asked.append(database)
                if 'pg_tables' in sql:
                    return ['workflow_entity']
                return {'workflow_entity': 3}

        self.assertEqual(ha_n8n.count_rows(Pg(), {'workflow_entity': 3}, 'automation'), {'workflow_entity': 3})
        self.assertEqual(set(asked), {'automation'})
        asked.clear()
        ha_n8n.count_rows(Pg(), {'workflow_entity': 3})
        self.assertEqual(set(asked), {'n8n'}, 'the old default is kept for whoever does not say')

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


# ====================================================================== the whole check and conversion (haimport, real TempObjects)

def tables_of(path):
    conn = sqlite3.connect(path)
    try:
        names = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        return {name: conn.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0] for name in names}
    finally:
        conn.close()


def member(*, key=KEY, credentials=('HA probe header',), owner=True, extra=(), config=None, package=b'{"dependencies": {}}'):
    """(the add-on's inner tar of an HA backup, {table: rows} of its database); `key` None: no `config` file, `config`: its raw bytes."""
    tmp = tempfile.TemporaryDirectory()
    try:
        path = Path(tmp.name) / 'database.sqlite'
        sqlite_db(path, owner=owner, credentials=credentials)
        database, tables = path.read_bytes(), tables_of(path)
    finally:
        tmp.cleanup()
    entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': ADDON_JSON},
               {'name': 'config', 'type': 'dir'}, {'name': 'config/.n8n', 'type': 'dir'},
               {'name': 'config/.n8n/database.sqlite', 'data': database},
               {'name': 'config/.n8n/database.sqlite-shm', 'data': b'HA wal index'},
               {'name': 'config/.n8n/nodes', 'type': 'dir'}, {'name': 'config/.n8n/nodes/package.json', 'data': package},
               {'name': 'config/.n8n/storage', 'type': 'dir'}]
    if config is not None:
        entries.append({'name': 'config/.n8n/config', 'data': config, 'mode': 0o600})
    elif key is not None:
        entries.append({'name': 'config/.n8n/config', 'data': json.dumps({'encryptionKey': key}).encode(), 'mode': 0o600})
    return gzip.compress(hx.tar_bytes(entries + list(extra)), mtime=0), tables


class Adapter(fk.Adapter):
    def import_manifest(self, staging_dir, **items):
        self.world.dir_data.update({rel: Path(source).read_bytes() for rel, source in (items.get('dirs') or {}).items()})
        return super().import_manifest(staging_dir, **items)


class N8nOwner(fk.Owner):
    def systemctl(self, *args, **kwargs):
        self.calls.append(('systemctl', *args))
        mapping = {name.removesuffix('.container') + '.service': ha_n8n.quadlet_container_name(self.world.quadlets['n8n'], name)
                   for name in self.world.quadlets['n8n'] if name.endswith('.container')}
        if args[0] == 'show':
            rows = []
            for unit in args[args.index('--') + 1:]:
                container = mapping[unit]
                deps = ' '.join(name + '.service' for name in sorted(self.world.service_dependencies.get(container, ())))
                rows.append(f'Id={unit}\nLoadState=loaded\nActiveState={"inactive" if container in self.world.down else "active"}'
                            f'\nRequires={deps}\nWants=\nBindsTo=')
            return Result(0, ('\n\n'.join(rows) + '\n').encode(), b'')
        container = mapping[args[-1]]
        if args[0] == 'start':
            def start(name):
                for dep in self.world.service_dependencies.get(name, ()):
                    start(dep)
                self.world.down.discard(name)
            start(container)
            if container in self.world.start_errors:
                raise self.world.start_errors[container]
        elif args[0] == 'stop':
            assert 'abort' not in kwargs, 'cleanup must work after cancellation'
            self.world.down.add(container)
        else:
            raise AssertionError(args[0])
        return Result(0, b'', b'')


class World(fk.World):
    """What the fake podman answers for n8n: its version, the throwaway PostgreSQL's tables, this device's own volumes."""

    def factory(self, app, **_kwargs):
        return Adapter(app, self)

    def __init__(self):
        super().__init__()
        self.owner = N8nOwner(self)
        self.down, self.start_errors, self.service_dependencies = set(), {}, {}
        self.connection_error, self.probe_unready = None, False
        self.quadlets = {'n8n': dict(QUADLETS)}
        self.connection_env = {'DB_POSTGRESDB_HOST': 'n8n-postgres'}
        self.version = b'2.43.6\n'
        self.tables, self.n8n_tables = {}, {}      # what HA's database holds / what the import made of it
        self.unpublished = False
        self.present = None                        # None: every image is here, else the set of those that are
        self.pulls = []
        self.unreadable = set()                    # volumes whose top folder podman cannot be asked about
        self.asked = []                            # (role, database) of every question the new PostgreSQL answered
        self.sequence_answer = {'sequences': 3, 'advanced': 1}   # what ADVANCE_SEQUENCES answers in the new PostgreSQL
        self.sequence_asked = []                   # (role, database, roles run so far, dumped so far) when it was asked
        self.dumped = False                        # pg_dump ran or the new cluster's volume was exported
        self.live = {}                             # this device's own volumes: volume -> entries of a tar
        self.root = b'1000 1000 755\n'
        self.dir_data = {}                         # the folders the adapter was handed: path -> tar
        self.controldata_state = 'shut down'       # what `pg_controldata` says of the new cluster (a cold backup)

    def podman(self, args, data, stdout):
        if args[:4] == ['container', 'inspect', '--format', '{{.State.Running}}']:
            return fk.Result(0, b'false' if args[-1] in self.down else b'true', b'')
        if args[:2] == ['image', 'inspect'] and self.present is not None and args[-1] not in self.present:
            return fk.Result(125, b'', b'Error: no such image')
        if args[0] == 'pull':
            self.pulls.append(args[-1])
            self.present = set(self.present or ()) | {args[-1]}
            return fk.Result(0, b'', b'')
        if args[:2] == ['unshare', 'stat'] and any(f'/{name}/' in args[-1] for name in self.unreadable):
            return fk.Result(125, b'', b'Error: cannot stat')
        return super().podman(args, data, stdout)

    def user_ids(self, user):
        return {'node': b'1000\n1000\n', 'valkey': b'999\n999\n', 'postgres': b'70\n70\n'}.get(user, b'1000\n1000\n')

    def volume_root(self, mount):
        return b'999 999 755\n' if '/n8n_valkey_data/' in mount else self.root

    def run(self, role, image, command, options, data):
        if role == 'n8n-version':
            return fk.Result(0, self.version, b'')
        if role == 'controldata':
            return fk.Result(0, f'Database cluster state:               {self.controldata_state}\n'.encode(), b'')
        if role == 'n8n-import':
            self.n8n_tables = dict(self.tables)
        if role == 'n8n-unpublish':
            self.unpublished = True
        return fk.Result(0, b'', b'')

    def exec(self, role, command, data, stdout):
        if command == ['node', '-e', ha_n8n.CONNECTION_PROBE]:
            if self.connection_error is not None:
                raise self.connection_error
            if 'n8n' in self.down or self.probe_unready:
                return fk.Result(125, b'', b'not ready')
            return ConnectionRunner(self.connection_env).podman('exec', '--env', 'NODE_OPTIONS=', '--env', 'NODE_PATH=', 'n8n', *command,
                                                               timeout=30, max_output=1024, check=False)
        if command[0] == 'pg_dump':
            self.dumped = True
            stdout.write(b'PGDMP-n8n')
        return fk.Result(0, b'', b'')

    def answer(self, role, sql, database):
        self.asked.append((role, database))
        if role == 'n8n-pg' and sql == ha_n8n.ADVANCE_SEQUENCES:
            self.sequence_asked.append((role, database, [run[0] for run in self.runs], self.dumped))
            return self.sequence_answer
        if role == 'n8n-pg':
            if 'pg_tables' in sql:
                return list(self.n8n_tables)
            if sql.startswith('SELECT json_build_object('):
                return {name: self.n8n_tables[name] for name in re.findall(r"'([A-Za-z0-9_]+)', \(SELECT", sql)}
            if 'WHERE active' in sql:
                return 0 if self.unpublished else 1
            if 'server_version_num' in sql:
                return '160015'
            if 'server_version' in sql:
                return '16.15'
        return None

    def export(self, volume):
        if volume.endswith('n8n-pgdata'):   # the new cluster of a cold backup (owner postgres = 70 in the image)
            self.dumped = True
            return fk.tar_of([{'name': '.', 'type': 'dir', 'uid': 70, 'gid': 70, 'mode': 0o700},
                              {'name': 'PG_VERSION', 'data': b'16\n', 'uid': 70, 'gid': 70, 'mode': 0o600}])
        return fk.tar_of(self.live.get(volume, [{'name': '.', 'type': 'dir'}]))


def haimport_registry(case):
    from woowbackup import haimport
    return haimport.load_registry(case.paths)


class N8nCase(fk.ConversionCase):
    world_class = World
    volumes = ('n8n_n8n_data', 'n8n_valkey_data')
    data_dirs = ()
    database = 'n8n'

    def setUp(self):
        super().setUp()
        self.addCleanup(jobs.unmask_secret, KEY)

    def catalog_apps(self):
        return {'n8n': fk.app('n8n', 'n8n 工作流程', volumes=[{'name': name} for name in self.volumes],
                              data_dirs=[{'path': path} for path in self.data_dirs],
                              postgres=[dict(PG, database=self.database)])}

    def upload_n8n(self, **kwargs):
        data, tables = member(**kwargs)
        self.world.tables = tables
        return self.upload(hx.outer_bytes([(f'{hx.N8N}.tar.gz', data)], hx.ha_doc(addons=(hx.N8N,))))

    def row(self, **kwargs):
        return self.check(self.upload_n8n(**kwargs), ['n8n'])[0]

    @staticmethod
    def issue(row, issue_id):
        return next((issue for issue in row['issues'] if issue['id'] == issue_id), None)

    def levels(self, row):
        return {issue['id']: issue['level'] for issue in row['issues']}

    def convert_stopped(self, ha_id, **params):
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['n8n'], **params)
        return caught.exception

    def built(self, since=0):
        """The roles of the throwaway containers that were started after the first `since` runs."""
        return [run[0] for run in self.world.runs[since:]]

    def data_tar(self, name='n8n_n8n_data'):
        return {entry: (info, data) for entry, (info, data) in self.volume(name).items()}


class SequenceTests(N8nCase):
    """dev-c instance flow attempt 5 (real n8n 2.43.6): after the conversion every new execution collided with an imported id (HTTP 500
    "There is already an entry with this name"), because import:entities advances only IDENTITY sequences, not serial ones."""

    def test_every_owned_sequence_is_moved_after_the_import_and_before_any_data_leaves(self):
        result = self.convert(self.upload_n8n(), ['n8n'])
        self.assertEqual(result['results'][0]['status'], 'converted')
        (role, database, runs, dumped), = self.world.sequence_asked
        self.assertEqual((role, database), ('n8n-pg', self.database))
        self.assertIn('n8n-import', runs)
        self.assertEqual(runs[-1], 'n8n-import')        # right after the import, before anything else is started
        self.assertFalse(dumped)                        # and before the dump or the cluster export
        self.assertTrue(self.world.dumped)

    def test_a_missing_answer_stops_n8n_before_any_data_leaves(self):
        self.world.sequence_answer = None
        error = self.convert_stopped(self.upload_n8n())
        self.assertEqual(error.code, 'job-failed'); self.assertIn('自動編號', error.message)
        self.assertFalse(self.world.dumped)

    def test_more_moved_than_owned_stops_n8n(self):
        self.world.sequence_answer = {'sequences': 3, 'advanced': 4}
        self.assertIn('自動編號', self.convert_stopped(self.upload_n8n()).message)
        self.assertFalse(self.world.dumped)

    def test_a_boolean_or_an_extra_field_is_not_a_count(self):
        self.world.sequence_answer = {'sequences': True, 'advanced': 0}
        self.assertIn('自動編號', self.convert_stopped(self.upload_n8n()).message)

    def test_an_answer_with_an_extra_field_stops_n8n(self):
        self.world.sequence_answer = {'sequences': 3, 'advanced': 1, 'note': 0}
        self.assertIn('自動編號', self.convert_stopped(self.upload_n8n()).message)

    def test_nothing_to_move_is_fine(self):
        self.world.sequence_answer = {'sequences': 0, 'advanced': 0}
        self.assertEqual(self.convert(self.upload_n8n(), ['n8n'])['results'][0]['status'], 'converted')

    def test_the_statement_moves_only_column_owned_sequences_and_only_forward(self):
        sql = ha_n8n.ADVANCE_SEQUENCES
        self.assertNotIn(';', sql)                                         # one statement: it goes through psql -c
        self.assertIn('pg_get_serial_sequence(', sql)                      # serial AND identity columns own their sequence
        self.assertIn("setval(seq::regclass, top, true)", sql)
        self.assertIn('top IS NOT NULL AND top > last', sql)                # never backwards, never for an empty table
        self.assertIn("CASE WHEN is_called THEN last_value ELSE last_value - 1 END", sql)
        for system in ("'pg_catalog'", "'information_schema'", "'^pg_'"):
            self.assertIn(system, sql)
        self.assertIn("json_build_object('sequences'", sql)


class StoppedTargetTests(N8nCase):
    """Real ensure_running + TempObjects cleanup, including dependency starts before a failing/cancelled main start."""

    def setUp(self):
        super().setUp()
        self.catalog['n8n'].postgres = [dict(PG, scope='instance', database='postgres')]
        self.world.service_dependencies = {'n8n': {'n8n-postgres', 'n8n-valkey'}}
        self.world.down = {'n8n', 'n8n-postgres'}
        self.initial = set(self.world.down)

    def service_calls(self, verb):
        return [call[-1] for call in self.world.owner.calls if call[:2] == ('systemctl', verb)]

    def test_check_temporarily_starts_main_and_database_and_restores_exact_running_set(self):
        row = self.check(self.upload_n8n(), ['n8n'])[0]
        self.assertTrue(row['importable'])
        self.assertEqual(self.world.down, self.initial)
        self.assertEqual(self.service_calls('start'), ['n8n-postgres.service', 'n8n.service'])
        self.assertEqual(set(self.service_calls('stop')), {'n8n.service', 'n8n-postgres.service'})
        self.assertNotIn('n8n-valkey.service', self.service_calls('stop'))

    def test_scoped_restore_hook_puts_back_before_the_restore_can_restart_services(self):
        app = self.catalog['n8n']
        tmp = tempctr.TempObjects(self.world.owner, 'j20261118T120000Z-0123abcd')
        work = types.SimpleNamespace(runner=lambda _app: self.world.owner,
                                     quadlets=lambda _app: self.world.quadlets['n8n'], temp=lambda _app: tmp)
        with tmp:
            endpoint = ha_n8n.prepare_app_endpoint(work, app)
            self.assertEqual(endpoint, {'database': 'n8n', 'user': 'postgres', 'host': 'n8n-postgres', 'port': 5432})
            self.assertEqual(self.world.down, set())
            self.assertTrue(tmp._puts_back)
        self.assertEqual(self.world.down, self.initial)
        self.world.owner.systemctl('start', '--', 'n8n.service')
        tmp.cleanup()
        self.assertEqual(self.world.down, set(), 'preflight cleanup cannot later stop the restored application')

    def test_read_only_api_does_not_start_a_stopped_main(self):
        with self.assertRaises(BackupError):
            ha_n8n.read_app_endpoint(self.world.owner, self.world.quadlets['n8n'])
        self.assertEqual(self.service_calls('start'), [])
        self.assertEqual(self.world.down, self.initial)

    def test_already_running_main_and_dependencies_are_never_stopped(self):
        self.world.down = set()
        self.assertTrue(self.check(self.upload_n8n(), ['n8n'])[0]['importable'])
        self.assertEqual((self.service_calls('start'), self.service_calls('stop')), ([], []))

    def test_partial_main_start_failure_restores_main_and_previously_stopped_dependencies(self):
        self.world.start_errors['n8n'] = CommandError('start failed', returncode=1, stderr=b'fixture failure')
        row = self.check(self.upload_n8n(), ['n8n'])[0]
        self.assertFalse(row['importable'])
        self.assertEqual(self.issue(row, 'target.service-failed')['level'], 'stop')
        self.assertEqual(self.world.down, self.initial)
        self.assertIn('n8n.service', self.service_calls('stop'), 'intent registered before the failed start')

    def test_cancel_during_partial_start_restores_main_and_dependencies_without_watchdog(self):
        cancel = Cancelled()
        self.world.start_errors['n8n'] = cancel
        with self.assertRaises(Cancelled) as caught:
            self.check(self.upload_n8n(), ['n8n'])
        self.assertIs(caught.exception, cancel)
        self.assertEqual(self.world.down, self.initial)

    def test_cancel_during_connection_read_restores_started_services(self):
        cancel = Cancelled()
        self.world.connection_error = cancel
        with self.assertRaises(Cancelled) as caught:
            self.check(self.upload_n8n(), ['n8n'])
        self.assertIs(caught.exception, cancel)
        self.assertEqual(self.world.down, self.initial)

    def test_partial_dependency_start_failure_is_restored_before_main_ever_starts(self):
        self.world.start_errors['n8n-postgres'] = CommandError('start failed', returncode=1, stderr=b'fixture failure')
        row = self.check(self.upload_n8n(), ['n8n'])[0]
        self.assertFalse(row['importable'])
        self.assertEqual(self.world.down, self.initial)
        self.assertNotIn('n8n.service', self.service_calls('start'))
        self.assertIn('n8n-postgres.service', self.service_calls('stop'))

    def test_untracked_dependency_or_cycle_stops_before_starting_any_services(self):
        for graph in ({'n8n': {'foreign-service'}}, {'n8n': {'n8n-postgres'}, 'n8n-postgres': {'n8n'}}):
            self.world.service_dependencies = graph
            with self.subTest(graph=graph):
                row = self.check(self.upload_n8n(), ['n8n'])[0]
                self.assertFalse(row['importable'])
                self.assertEqual(self.issue(row, 'n8n.layout-unsupported')['level'], 'stop')
                self.assertEqual(self.service_calls('start'), [])
                self.assertEqual(self.world.down, self.initial)

    def test_readiness_failure_restores_started_services(self):
        self.world.probe_unready = True
        with mock.patch.object(hatarget, 'wait_until', side_effect=lambda condition, **_kwargs: condition()):
            row = self.check(self.upload_n8n(), ['n8n'])[0]
        self.assertFalse(row['importable'])
        self.assertEqual(self.issue(row, 'target.service-failed')['level'], 'stop')
        self.assertEqual(self.world.down, self.initial)

    def test_conversion_failure_after_the_live_read_restores_stopped_services(self):
        self.world.version = b'2.44.0\n'
        error = self.convert_stopped(self.upload_n8n())
        self.assertEqual(error.code, 'incompatible')
        self.assertEqual(self.world.down, self.initial)
        self.assertEqual(self.world.manifests, {})


class TargetBackendTests(N8nCase):
    """Conversion must bind the actual endpoint to catalog PG before any database snapshot or temporary import."""

    def setUp(self):
        super().setUp()
        self.catalog['n8n'].postgres = [dict(PG, scope='instance', database='postgres')]

    def test_remote_host_or_nonstandard_port_refuses_before_snapshot_or_conversion(self):
        ha_id = self.upload_n8n()
        for endpoint in ({'DB_POSTGRESDB_HOST': 'foreign-pg'},
                         {'DB_POSTGRESDB_HOST': 'n8n-postgres', 'DB_POSTGRESDB_PORT': '6543'}):
            self.world.connection_env = dict(endpoint, DB_POSTGRESDB_DATABASE='n8n')
            with self.subTest(keys=sorted(endpoint)), mock.patch.object(
                    Adapter, 'import_instance_database', create=True,
                    side_effect=BackupError('internal-error', 'unexpected snapshot attempted')) as snapshot:
                error = self.convert_stopped(ha_id)
            self.assertEqual(error.code, 'incompatible')
            self.assertEqual(error.issues[0].id, 'n8n.layout-unsupported')
            snapshot.assert_not_called()
            self.assertEqual(self.world.live_dumps, [])
            self.assertEqual(self.world.runs, [])
            self.assertEqual(self.world.manifests, {})
            self.assertEqual(self.storage.list_backups(), [])

    def test_local_container_name_and_declared_alias_are_accepted(self):
        self.world.quadlets['n8n']['n8n-postgres.container'] += b'NetworkAlias=n8n-database\n'
        for host in ('n8n-postgres', 'n8n-database'):
            self.world.connection_env = {'DB_POSTGRESDB_HOST': host, 'DB_POSTGRESDB_PORT': '5432'}
            with self.subTest(host=host):
                row = self.check(self.upload_n8n(), ['n8n'])[0]
                self.assertTrue(row['importable'])

    def test_backend_binding_uses_unique_main_filename_when_worker_and_webhook_share_data(self):
        quadlets = self.world.quadlets['n8n']
        for role in ('worker', 'webhook'):
            quadlets[f'n8n-{role}.container'] = (QUADLETS['n8n.container'].replace(b'ContainerName=n8n\n',
                f'ContainerName=n8n-{role}\n'.encode()).replace(b'Network=n8n.network', b'Network=other.network')
                + f'Exec={role}\n'.encode())
        self.world.quadlets['n8n'] = {name: quadlets[name] for name in
                                     ['n8n-worker.container', 'n8n-webhook.container',
                                      *(name for name in quadlets if name not in ('n8n-worker.container', 'n8n-webhook.container'))]}
        real = ha_instance_access.local_backend
        with mock.patch.object(ha_instance_access, 'local_backend', wraps=real) as binding:
            row = self.check(self.upload_n8n(), ['n8n'])[0]
        self.assertTrue(row['importable'])
        binding.assert_called_once()
        self.assertEqual(binding.call_args.args[2], 'n8n.container')
        self.assertEqual(binding.call_args.args[0]['host'], 'n8n-postgres')


class CheckFlowTests(N8nCase):
    def test_a_clean_backup_is_importable_and_says_what_it_found(self):
        row = self.row()
        self.assertEqual((row['importable'], row['ok'], self.levels(row)), (True, True, {}))
        self.assertEqual(row['target_version'], '2.43.6')
        section = row['n8n']
        self.assertEqual((section['owner_email'], section['workflows'], section['credentials']),
                         ('ha-probe@probe.invalid', 3, 1))

    def test_no_key_is_one_line_to_confirm_and_the_check_stays_importable(self):
        """N8-15: it was a stop that said 'no key' for a short one too."""
        row = self.row(key=None, credentials=('Telegram bot', 'OpenAI'))
        self.assertEqual((row['importable'], row['ok']), (True, False))
        self.assertEqual(self.levels(row), {'n8n.no-key': 'confirm'})
        line = self.issue(row, 'n8n.no-key')
        self.assertEqual(sorted(line['items']), ['OpenAI', 'Telegram bot'])
        self.assertRegex(line['key'], r'^n8n\.no-key:[0-9a-f]{16}$')
        self.assertEqual([i['id'] for i in row['issues'] if i['level'] == 'stop'], [])

    def test_a_key_of_any_shape_is_no_reason_to_ask(self):
        for config in (json.dumps({'encryptionKey': 'short'}).encode(), json.dumps({'encryptionKey': '中文 key with spaces'}).encode()):
            row = self.row(config=config)
            self.assertEqual((row['ok'], self.levels(row)), (True, {}), config)

    def test_no_database_no_owner_and_a_database_that_is_none_stop_only_n8n(self):
        row = self.row(owner=False)
        self.assertEqual((row['importable'], self.levels(row)), (False, {'n8n.no-owner': 'stop'}))
        entries_without_database = [{'name': 'config/.n8n/nothing', 'data': b'x'}]
        data = gzip.compress(hx.tar_bytes([{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': ADDON_JSON},
                                           {'name': 'config', 'type': 'dir'}, {'name': 'config/.n8n', 'type': 'dir'},
                                           *entries_without_database]), mtime=0)
        ha_id = self.upload(hx.outer_bytes([(f'{hx.N8N}.tar.gz', data)], hx.ha_doc(addons=(hx.N8N,))))
        row = self.check(ha_id, ['n8n'])[0]
        self.assertEqual((row['importable'], self.levels(row)), (False, {'n8n.no-database': 'stop'}))
        self.assertIn('這台的 n8n 不會有任何變更', self.issue(row, 'n8n.no-database')['action'])
        garbage = gzip.compress(hx.tar_bytes([{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': ADDON_JSON},
                                              {'name': 'config', 'type': 'dir'}, {'name': 'config/.n8n', 'type': 'dir'},
                                              {'name': 'config/.n8n/database.sqlite', 'data': b'SQLite format 3\x00' + b'\xff' * 4000},
                                              {'name': 'config/.n8n/config', 'data': json.dumps({'encryptionKey': KEY}).encode()}]), mtime=0)
        row = self.check(self.upload(hx.outer_bytes([(f'{hx.N8N}.tar.gz', garbage)], hx.ha_doc(addons=(hx.N8N,)))), ['n8n'])[0]
        self.assertEqual((row['importable'], self.levels(row)), (False, {'n8n.database-unreadable': 'stop'}))
        self.assertIn('在 HA 重新備份', self.issue(row, 'n8n.database-unreadable')['action'])

    def test_a_version_that_cannot_be_read_here_is_told_and_no_gate(self):
        """N8-10"""
        self.world.version = b'n8n: command not found\n'
        row = self.row()
        self.assertEqual((row['importable'], row['ok'], self.levels(row)), (True, True, {'version.target-unknown': 'notice'}))
        self.assertEqual(row['target_version'], '')

    def test_another_version_stops_n8n(self):
        self.world.version = b'2.44.0\n'
        row = self.row()
        self.assertEqual((row['importable'], self.levels(row)), (False, {'version.different': 'stop'}))

    def test_another_volume_and_a_host_folder_are_told_and_a_time_zone_file_is_no_reason(self):
        """N8-02, N8-27 and the n8n side of OD-08, OD-09: said in the check, nothing stops."""
        type(self).volumes = ('n8n_n8n_data', 'n8n_valkey_data', 'n8n_files')
        type(self).data_dirs = ('.local/share/n8n-files',)
        self.addCleanup(setattr, type(self), 'volumes', ('n8n_n8n_data', 'n8n_valkey_data'))
        self.addCleanup(setattr, type(self), 'data_dirs', ())
        self.catalog = self.catalog_apps()
        self.deps.load_catalog = lambda: self.catalog
        self.world.quadlets['n8n'] = dict(QUADLETS, **{
            'n8n.container': QUADLETS['n8n.container'] + b'Volume=n8n-files.volume:/files\nVolume=/etc/localtime:/etc/localtime:ro\n',
            'n8n-files.volume': b'[Volume]\nVolumeName=n8n_files\n'})
        row = self.row()
        self.assertEqual((row['importable'], row['ok']), (True, True))
        self.assertEqual(self.levels(row), {'n8n.extras-carried': 'auto', 'n8n.mount-skipped': 'notice'})
        self.assertEqual(sorted(self.issue(row, 'n8n.extras-carried')['items']), ['.local/share/n8n-files', 'n8n_files'])

    def test_no_image_is_downloaded_for_an_app_that_cannot_be_imported(self):
        """Gigabytes for nothing: n8n stops at its data, the version of this device's image is not asked."""
        self.world.present = {'docker.io/library/postgres:16.15-alpine'}
        row = self.row(owner=False)
        self.assertEqual((self.world.pulls, row['importable'], row['target_version']), ([], False, ''))
        self.assertEqual([r for r in self.built() if r == 'n8n-version'], [])

    def test_an_image_that_is_not_here_is_downloaded_first(self):
        """CM-05: the check runs `n8n --version` in it."""
        self.world.present = {'docker.io/library/postgres:16.15-alpine'}
        row = self.row()
        self.assertEqual(self.world.pulls, ['docker.io/n8nio/n8n:2.43.6'])
        self.assertEqual((row['importable'], self.levels(row)), (True, {'target.image-pulled': 'auto'}))



class ConvertFlowTests(N8nCase):
    def converted(self, ha_id=None, **params):
        return self.convert(ha_id or self.upload_n8n(), ['n8n'], **params)

    def test_a_clean_conversion_builds_the_items_and_empties_only_the_queue(self):
        self.world.live['n8n_valkey_data'] = [{'name': '.', 'type': 'dir'}, {'name': 'appendonly.aof', 'data': b'queued jobs of this device'}]
        result = self.converted()
        self.assertEqual(result['results'][0]['status'], 'converted')
        items = self.world.manifests['n8n']
        self.assertEqual(sorted(items['volumes']), ['n8n_n8n_data', 'n8n_valkey_data'])
        self.assertEqual(sorted(items['postgres']), ['main'])
        data = self.data_tar()
        self.assertEqual(json.loads(data['config'][1]), {'encryptionKey': KEY})
        self.assertEqual({name: (info.uid, info.gid) for name, (info, _d) in data.items() if name == '.'}, {'.': (1000, 1000)})
        queue = self.volume('n8n_valkey_data')
        self.assertEqual(list(queue), ['.'], 'HA\'s queued jobs never run here, this device\'s old ones neither')
        self.assertEqual((queue['.'][0].uid, queue['.'][0].gid), (999, 999))

    def test_instance_conversion_keeps_credentials_key_and_all_live_databases(self):
        from .test_adapter_ha_instance import conversion_adapter
        app = self.catalog['n8n']
        app.postgres = [dict(app.postgres[0], scope='instance', database='postgres')]
        adapter, owner = conversion_adapter(app, app.postgres[0], 'n8n')
        captured = {}

        def complete(_fake, pg, converted, staging):
            result = adapter.import_instance_database(pg, converted, staging)
            captured.update(result)
            return result

        with mock.patch.object(Adapter, 'import_instance_database', complete, create=True):
            result = self.converted()
        self.assertEqual(result['results'][0]['status'], 'converted')
        item = self.world.manifests['n8n']['postgres']['main']
        self.assertEqual((item['scope'], item['ha_database'], item['database']), ('instance', 'n8n', 'postgres'))
        self.assertEqual({db['name'] for db in item['databases']}, set(owner.instance))
        self.assertEqual(next(db for db in captured['databases'] if db['name'] == 'n8n')['file'].name, 'main.dump')
        self.assertEqual(json.loads(self.data_tar()['config'][1]), {'encryptionKey': KEY})
        self.assertTrue(all(db == 'n8n' for role, db in self.world.asked if role == 'n8n-pg'))

    def test_instance_env_file_selects_automation_when_both_databases_exist(self):
        from .test_adapter_ha_instance import conversion_adapter, encoded
        app = self.catalog['n8n']
        app.postgres = [dict(app.postgres[0], scope='instance', database='postgres')]
        self.world.quadlets['n8n']['n8n.container'] += b'EnvironmentFile=%h/.config/n8n/db.env\n'
        self.world.files['.config/n8n/db.env'] = b'DB_POSTGRESDB_DATABASE=automation\nDB_POSTGRESDB_USER=n8n\n'
        # This is the effective environment Podman gives the existing application, not the PG server's environment.
        self.world.connection_env = {'DB_POSTGRESDB_DATABASE': 'automation', 'DB_POSTGRESDB_USER': 'n8n',
                                     'DB_POSTGRESDB_HOST': 'n8n-postgres'}
        adapter, owner = conversion_adapter(app, app.postgres[0], 'n8n')
        owner.instance['automation'] = dict(owner.instance['n8n'], data=b'old automation rows')
        unrelated = dict(owner.instance['n8n'])
        captured = {}
        selected_dump = []
        original_exec = self.world.exec

        def execute(role, command, data, stdout):
            if command[0] == 'pg_dump':
                name = command[command.index('-d') + 1]
                stdout.write(encoded(name, dict(owner.instance[name], data=b'HA automation rows')))
                return fk.Result(0, b'', b'')
            return original_exec(role, command, data, stdout)

        def complete(_fake, pg, converted, staging):
            result = adapter.import_instance_database(pg, converted, staging)
            captured.update(result)
            selected_dump.append(next(db['file'] for db in result['databases'] if db['name'] == result['ha_database']).read_bytes())
            return result

        self.world.exec = execute
        with mock.patch.object(Adapter, 'import_instance_database', complete, create=True):
            result = self.converted()
        self.assertEqual(result['results'][0]['status'], 'converted')
        item = self.world.manifests['n8n']['postgres']['main']
        self.assertEqual(item['ha_database'], 'automation')
        self.assertEqual({db['name'] for db in item['databases']}, set(owner.instance))
        self.assertTrue(all(db == 'automation' for role, db in self.world.asked if role == 'n8n-pg'))
        selected = next(db for db in captured['databases'] if db['name'] == item['ha_database'])
        with tempfile.TemporaryDirectory() as folder:
            dump = Path(folder) / 'converted.dump'
            dump.write_bytes(selected_dump[0])
            adapter._restore_ha_instance_database(app.postgres[0], selected, dump)
        self.assertEqual(owner.dropped, ['automation'])
        self.assertEqual(owner.instance['automation']['data'], b'HA automation rows')
        self.assertEqual(owner.instance['n8n'], unrelated)

    def test_unresolved_instance_connection_stops_before_any_conversion_work(self):
        app = self.catalog['n8n']
        app.postgres = [dict(app.postgres[0], scope='instance', database='postgres')]
        self.world.connection_env = {'DB_POSTGRESDB_DATABASE_FILE': 'missing-setting-file'}
        error = self.convert_stopped(self.upload_n8n())
        self.assertEqual(error.code, 'incompatible')
        self.assertEqual(error.issues[0].id, 'n8n.layout-unsupported')
        self.assertEqual(self.world.runs, [])
        self.assertEqual(self.world.manifests, {})
        self.assertEqual(self.storage.list_backups(), [])

    def test_no_key_asks_once_and_nothing_is_built_until_it_is_confirmed(self):
        """N8-15, the three of a line to confirm."""
        ha_id = self.upload_n8n(key=None, credentials=('Telegram bot', 'OpenAI'))
        line = self.issue(self.check(ha_id, ['n8n'])[0], 'n8n.no-key')
        for acknowledged in (None, {}, {'n8n': []}, {'odoo': [line['key']]}, {'n8n': ['n8n.no-key:0123456789abcdef']}):
            seen = len(self.world.runs)
            with self.subTest(acknowledged=acknowledged):
                error = self.convert_stopped(ha_id, **({} if acknowledged is None else {'acknowledged': acknowledged}))
                self.assertEqual(error.code, 'confirmation-required')
                self.assertEqual(error.result['results'][0]['status'], 'skipped')
                self.assertEqual([r for r in self.built(seen) if r in ('n8nsrc', 'n8n-export', 'n8n-pg', 'n8n-import')], [],
                                 'nothing of n8n is built')
        self.assertEqual((self.world.manifests, self.storage.list_backups()), ({}, []))
        result = self.convert(ha_id, ['n8n'], acknowledged={'n8n': [line['key']]})
        self.assertEqual(result['results'][0]['status'], 'converted')
        registered = haimport_registry(self)[result['backup_id']]
        self.assertEqual([(c['app_id'], c['id'], sorted(c['items'])) for c in registered['confirmed']],
                         [('n8n', 'n8n.no-key', ['OpenAI', 'Telegram bot'])])

    def test_one_more_credential_asks_again(self):
        row = self.row(key=None, credentials=('Telegram bot',))
        line = self.issue(row, 'n8n.no-key')
        more = self.upload_n8n(key=None, credentials=('Telegram bot', 'New one'))
        error = self.convert_stopped(more, acknowledged={'n8n': [line['key']]})
        self.assertEqual(error.code, 'confirmation-required')
        again = self.issue(self.check(more, ['n8n'])[0], 'n8n.no-key')
        self.assertNotEqual(again['key'], line['key'])

    def test_with_no_key_the_new_one_is_made_here_written_and_never_shown(self):
        ha_id = self.upload_n8n(key=None, credentials=('Telegram bot',))
        line = self.issue(self.check(ha_id, ['n8n'])[0], 'n8n.no-key')
        result = self.convert(ha_id, ['n8n'], acknowledged={'n8n': [line['key']]})
        key = json.loads(self.data_tar()['config'][1])['encryptionKey']
        self.addCleanup(jobs.unmask_secret, key)
        self.assertRegex(key, r'^[A-Za-z0-9_-]{32}$')
        self.assertGreater(len(set(key)), 12, 'a random key, not a constant')
        self.assertNotEqual(key, KEY)
        self.assertIn('[已遮蔽]', jobs.redact(f'key {key}'), 'masked like HA\'s key')
        source = next(data for name, data in self.world.imported.items() if name.endswith('n8nsrc'))
        with tarfile.open(fileobj=io.BytesIO(source)) as tar:
            self.assertEqual(json.loads(tar.extractfile('home/.n8n/config').read()), {'encryptionKey': key},
                             'the throwaway n8n that exports HA\'s data has the same file')
        reminders = result['ha_import']['reminders_by_app']['n8n']
        self.assertTrue(any('1 個憑證' in text and '重新輸入' in text for text in reminders), reminders)
        self.assertNotIn(key, json.dumps(result, ensure_ascii=False))

    def test_no_key_and_no_credentials_loses_nothing_and_asks_nothing(self):
        result = self.converted(self.upload_n8n(key=None, credentials=()))
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertEqual([i['id'] for i in result['results'][0]['issues']], ['n8n.key-created'])
        key = json.loads(self.data_tar()['config'][1])['encryptionKey']
        self.addCleanup(jobs.unmask_secret, key)
        self.assertEqual(len(key), 32)
        self.assertEqual(result['ha_import']['reminders_by_app']['n8n'][0].startswith('匯入後請用'), True)
        self.assertFalse(any('重新輸入' in text for text in result['ha_import']['reminders_by_app']['n8n']))

    def test_the_conversion_looks_again_and_stops_n8n_at_what_the_check_did_not_see(self):
        """N8-18: the device changed between the two (a new n8n version); only n8n stops, nothing was built."""
        ha_id = self.upload_n8n()
        self.assertEqual(self.check(ha_id, ['n8n'])[0]['importable'], True)
        self.world.version = b'2.44.0\n'
        seen = len(self.world.runs)
        error = self.convert_stopped(ha_id)
        self.assertEqual(error.code, 'incompatible')
        result = error.result['results'][0]
        self.assertEqual((result['app_id'], result['status']), ('n8n', 'skipped'))
        self.assertEqual([i['id'] for i in result['issues'] if i['level'] == 'stop'], ['version.different'])
        self.assertEqual([r for r in self.built(seen) if r.startswith('n8n-') and r != 'n8n-version'], [])

    def test_an_n8n_without_an_owner_or_with_a_broken_database_is_left_out_in_the_conversion_too(self):
        error = self.convert_stopped(self.upload_n8n(owner=False))
        self.assertEqual(error.result['results'][0]['issues'][0]['id'], 'n8n.no-owner')
        self.assertEqual(self.storage.list_backups(), [])

    def test_a_version_that_cannot_be_read_does_not_stop_the_conversion(self):
        self.world.version = b'no idea\n'
        result = self.converted()
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertEqual([i['id'] for i in result['results'][0]['issues']], ['version.target-unknown'])


class ThisDevicesOwnDataTests(N8nCase):
    """N8-02, N8-27 (and the n8n side of OD-08, OD-09): what the app settings hold beyond n8n's data is this device's own."""
    volumes = ('n8n_n8n_data', 'n8n_valkey_data', 'n8n_files')
    data_dirs = ('.local/share/n8n-files',)

    def setUp(self):
        super().setUp()
        self.world.quadlets['n8n'] = dict(QUADLETS, **{
            'n8n.container': QUADLETS['n8n.container'] + b'Volume=n8n-files.volume:/files\nVolume=/etc/localtime:/etc/localtime:ro\n',
            'n8n-files.volume': b'[Volume]\nVolumeName=n8n_files\n'})
        self.world.live['n8n_files'] = [{'name': '.', 'type': 'dir'}, {'name': 'report.csv', 'data': b'this device\'s own file'}]
        self.world.dirs['.local/share/n8n-files'] = fk.tar_of([{'name': './', 'type': 'dir'}, {'name': './notes.txt', 'data': b'kept'}])

    def test_every_item_of_the_app_settings_has_its_data_the_way_the_adapter_wants_it(self):
        result = self.converted()
        self.assertEqual(result['results'][0]['status'], 'converted')
        items, app = self.world.manifests['n8n'], self.catalog['n8n']
        self.assertEqual((set(items['volumes']), set(items['dirs'])),
                         ({v['name'] for v in app.volumes}, {d['path'] for d in app.data_dirs}),
                         'the adapter refuses anything else: internal-error at the very end (N8-27)')
        self.assertIn('n8n.extras-carried', [i['id'] for i in result['results'][0]['issues']])

    def converted(self):
        return self.convert(self.upload_n8n(), ['n8n'])

    def test_the_other_volume_and_the_folder_are_carried_exactly_and_the_queue_is_emptied(self):
        self.world.live['n8n_valkey_data'] = [{'name': '.', 'type': 'dir'}, {'name': 'queue.aof', 'data': b'old jobs'}]
        self.converted()
        files = self.volume('n8n_files')
        self.assertEqual(files['report.csv'][1], b'this device\'s own file')
        self.assertEqual(list(self.volume('n8n_valkey_data')), ['.'])
        self.assertEqual(self.world.dir_data['.local/share/n8n-files'], self.world.dirs['.local/share/n8n-files'])
        self.assertIn(('relay', 'volume', 'export', 'n8n_files'), self.world.owner.calls)
        self.assertNotIn(('relay', 'volume', 'export', 'n8n_valkey_data'), self.world.owner.calls, 'the queue is not even read')

    def test_a_link_that_leaves_this_devices_volume_is_left_out_and_asked_about(self):
        """X-NS-08: the restore refuses it, so it is listed and the customer decides; the rest of the volume is carried."""
        self.world.live['n8n_files'] = [{'name': '.', 'type': 'dir'}, {'name': 'ok.txt', 'data': b'x'},
                                        {'name': 'escape', 'type': 'symlink', 'linkname': '../../etc/passwd'}]
        ha_id = self.upload_n8n()
        error = self.convert_stopped(ha_id)
        self.assertEqual(error.code, 'confirmation-required')
        line = next(i for i in error.result['results'][0]['issues'] if i['id'] == 'files.skipped')
        self.assertIn('escape', line['items'][0])
        result = self.convert(ha_id, ['n8n'], acknowledged={'n8n': [line['key']]})
        self.assertEqual(list(self.volume('n8n_files')), ['.', 'ok.txt'])
        self.assertEqual(result['results'][0]['status'], 'converted')

    def test_a_volume_that_is_no_queue_is_not_emptied_even_when_it_is_the_only_other_one(self):
        """The old rule took 'the other of two volumes' for the queue: a volume of this device's own data was emptied."""
        type(self).volumes = ('n8n_n8n_data', 'n8n_files')
        type(self).data_dirs = ()
        self.addCleanup(setattr, type(self), 'volumes', ('n8n_n8n_data', 'n8n_valkey_data', 'n8n_files'))
        self.addCleanup(setattr, type(self), 'data_dirs', ('.local/share/n8n-files',))
        self.catalog = self.catalog_apps()
        self.deps.load_catalog = lambda: self.catalog
        self.world.quadlets['n8n'] = {k: v for k, v in self.world.quadlets['n8n'].items() if 'valkey' not in k}
        self.converted()
        self.assertEqual(self.volume('n8n_files')['report.csv'][1], b'this device\'s own file')
        self.assertEqual(sorted(self.world.manifests['n8n']['volumes']), ['n8n_files', 'n8n_n8n_data'])


class RootFlowTests(N8nCase):
    def test_a_data_volume_whose_owner_cannot_be_read_gets_the_images_owner_and_it_is_said(self):
        """N8-11, N8-12"""
        self.world.unreadable = {'n8n_n8n_data'}
        result = self.convert(self.upload_n8n(), ['n8n'])
        self.assertEqual(result['results'][0]['status'], 'converted')
        top = self.data_tar()['.'][0]
        self.assertEqual((top.uid, top.gid, top.mode), (1000, 1000, 0o755))
        issue = next(i for i in result['results'][0]['issues'] if i['id'] == 'n8n.volume-root-default')
        self.assertEqual((issue['level'], issue['items']), ('auto', ['n8n_n8n_data']))

    def test_the_queues_folder_gets_the_account_of_its_image(self):
        self.world.unreadable = {'n8n_valkey_data'}
        result = self.convert(self.upload_n8n(), ['n8n'])
        top = self.volume('n8n_valkey_data')['.'][0]
        self.assertEqual((top.uid, top.gid), (999, 999))
        self.assertEqual([i['items'] for i in result['results'][0]['issues'] if i['id'] == 'n8n.volume-root-default'],
                         [['n8n_valkey_data']])


class ImagesAndNamesFlowTests(N8nCase):
    database = 'automation'

    def setUp(self):
        super().setUp()
        self.world.quadlets['n8n'] = dict(QUADLETS, **{
            'n8n-postgres.container': QUADLETS['n8n-postgres.container'].replace(b'POSTGRES_DB=n8n', b'POSTGRES_DB=automation')})

    def test_the_rows_are_counted_in_the_database_of_the_app_settings(self):
        """N8-21: it was always `n8n`."""
        result = self.convert(self.upload_n8n(), ['n8n'])
        self.assertEqual(result['results'][0]['status'], 'converted')
        asked = {database for role, database in self.world.asked if role == 'n8n-pg'}
        self.assertEqual(asked, {'automation'})
        self.assertEqual(self.world.manifests['n8n']['postgres']['main']['database'], 'automation')

    def test_the_images_of_this_device_are_downloaded_first_in_the_conversion_too(self):
        """CM-05: the throwaway containers never pull; the owner does it before they are made."""
        self.world.present = {'docker.io/valkey/valkey:8'}
        result = self.convert(self.upload_n8n(), ['n8n'])
        self.assertEqual(sorted(self.world.pulls), ['docker.io/library/postgres:16.15-alpine', 'docker.io/n8nio/n8n:2.43.6'])
        self.assertEqual(result['results'][0]['status'], 'converted')

    def test_an_image_that_cannot_be_had_stops_only_n8n(self):
        self.world.present = {'docker.io/valkey/valkey:8'}
        original = self.world.podman

        def podman(args, data, stdout):
            if args[0] == 'pull':
                return fk.Result(125, b'', b'Error: unable to pull: connection refused')
            return original(args, data, stdout)

        self.world.podman = podman
        error = self.convert_stopped(self.upload_n8n())
        self.assertEqual(error.issues[0].id, 'target.image-missing')
        self.assertEqual(error.result['results'][0]['status'], 'skipped')


class BigFilesFlowTests(N8nCase):
    def test_a_config_file_too_large_to_be_a_key_file_is_listed_once_and_no_key_is_the_other_line(self):
        """N8-28 with N8-15: the file is left out and listed (not a stop), and without a key there is the second line to confirm."""
        config = json.dumps({'encryptionKey': KEY, 'pad': 'x' * 3000}).encode()
        with contextlib_patch({'MAX_KEY_FILE': 500}):
            ha_id = self.upload_n8n(config=config, credentials=('Telegram bot',))
            row = self.check(ha_id, ['n8n'])[0]
            self.assertEqual(self.levels(row), {'files.skipped': 'confirm', 'n8n.no-key': 'confirm'})
            self.assertEqual((row['importable'], row['ok']), (True, False))
            self.assertEqual(self.issue(row, 'files.skipped')['items'], ['config/.n8n/config'])
            only_one = {'n8n': [self.issue(row, 'n8n.no-key')['key']]}
            error = self.convert_stopped(ha_id, acknowledged=only_one)
            self.assertEqual(error.code, 'confirmation-required')
            both = {'n8n': [self.issue(row, 'n8n.no-key')['key'], self.issue(row, 'files.skipped')['key']]}
            result = self.convert(ha_id, ['n8n'], acknowledged=both)
        self.assertEqual(result['results'][0]['status'], 'converted')
        key = json.loads(self.data_tar()['config'][1])['encryptionKey']
        self.addCleanup(jobs.unmask_secret, key)
        self.assertNotEqual(key, KEY, 'HA\'s key was in the file that was left out: it is not used')

    def test_a_big_native_node_and_a_big_package_json_are_moved_and_the_conversion_is_not_stopped(self):
        """N8-28 as a whole: no limit-exceeded any more."""
        big = elf(glibc=True) + b'\x00' * 300_000
        package = json.dumps({'dependencies': {'n8n-nodes-big': '1.0.0'}, 'pad': 'x' * 3000}).encode()
        data, tables = member(package=package, extra=[{'name': 'config/.n8n/nodes/node_modules', 'type': 'dir'},
                                     {'name': 'config/.n8n/nodes/node_modules/n8n-nodes-big', 'type': 'dir'},
                                     {'name': 'config/.n8n/nodes/node_modules/n8n-nodes-big/b.node', 'data': big}])
        self.world.tables = tables
        with contextlib_patch({'NATIVE_HEAD': 64 * 1024, 'MAX_PACKAGE_JSON': 100}):
            ha_id = self.upload(hx.outer_bytes([(f'{hx.N8N}.tar.gz', data)], hx.ha_doc(addons=(hx.N8N,))))
            row = self.check(ha_id, ['n8n'])[0]
            self.assertEqual(self.levels(row), {'n8n.native-code': 'notice', 'n8n.community-packages': 'notice'})
            self.assertEqual((row['importable'], row['ok']), (True, True))
            result = self.convert(ha_id, ['n8n'])
        self.assertEqual(result['results'][0]['status'], 'converted')
        volume = self.data_tar()
        self.assertEqual(volume['nodes/node_modules/n8n-nodes-big/b.node'][1], big)



COLD_QUADLETS = dict(QUADLETS, **{
    'n8n-postgres.container': QUADLETS['n8n-postgres.container'] + b'Secret=n8n-db-password,type=env,target=POSTGRES_PASSWORD\n',
})
COLD_VOLUMES = ('n8n_n8n_data', 'n8n_valkey_data', 'n8n_postgres_data')


class ColdTargetTests(unittest.TestCase):
    """N8-01: this device's app settings may hold the database's data folder as a volume (a cold backup) instead of one database
    item; full instance entries are covered separately."""

    def target(self, quadlets=COLD_QUADLETS, volumes=COLD_VOLUMES):
        return target_of(quadlets, n8n_app(volumes=volumes, postgres=[]))

    def test_the_database_volume_is_found_and_is_neither_queue_nor_extra(self):
        target, sink = self.target()
        self.assertEqual((target.cold, target.pg_data_volume, target.queue_volumes, target.extra_volumes, sink.found),
                         (True, 'n8n_postgres_data', ['n8n_valkey_data'], [], []))
        self.assertEqual((target.pg['container'], target.pg['user'], target.pg['database'], target.pg_file),
                         ('n8n-postgres', 'n8n', 'n8n', 'n8n-postgres.container'))
        self.assertEqual((target.import_secrets, target.import_env),
                         (['n8n-db-password,type=env,target=DB_POSTGRESDB_PASSWORD'], {}))
        self.assertEqual(target.pg_secrets, ['n8n-db-password,type=env,target=POSTGRES_PASSWORD'])

    def test_a_password_file_secret_is_handed_over_as_the_file_it_is(self):
        pg = QUADLETS['n8n-postgres.container'] + (b'Environment=POSTGRES_PASSWORD_FILE=/run/secrets/dbpass\n'
                                                   b'Secret=n8n-db-password,type=mount,target=/run/secrets/dbpass\n')
        target, _sink = self.target(dict(QUADLETS, **{'n8n-postgres.container': pg}))
        self.assertEqual((target.import_secrets, target.import_env),
                         (['n8n-db-password,type=mount,target=/run/secrets/dbpass'],
                          {'DB_POSTGRESDB_PASSWORD_FILE': '/run/secrets/dbpass'}))

    def test_what_cannot_be_made_like_this_devices_own_cluster_stops_n8n(self):
        def stopped(quadlets, volumes=COLD_VOLUMES):
            with self.assertRaises(BackupError) as caught:
                self.target(quadlets, volumes)
            self.assertEqual((caught.exception.code, caught.exception.issues[0].id), ('incompatible', 'n8n.layout-unsupported'))
            return caught.exception.issues[0].message

        self.assertIn('podman 機密', stopped(QUADLETS), 'a password that is no podman secret cannot be handed over safely')
        self.assertIn('POSTGRES_USER', stopped(dict(COLD_QUADLETS, **{
            'n8n-postgres.container': COLD_QUADLETS['n8n-postgres.container'].replace(b'Environment=POSTGRES_USER=n8n\n', b'')})))
        self.assertIn('PostgreSQL 容器', stopped(COLD_QUADLETS, ('n8n_n8n_data', 'n8n_valkey_data')), 'its volume is not listed')


class ColdFlowTests(N8nCase):
    """The whole conversion for a cold app: the new cluster is made like this device's own and is the volume that goes back."""
    volumes = COLD_VOLUMES

    def catalog_apps(self):
        return {'n8n': fk.app('n8n', 'n8n 工作流程', volumes=[{'name': name} for name in self.volumes], postgres=[])}

    def setUp(self):
        super().setUp()
        self.world.quadlets['n8n'] = dict(COLD_QUADLETS)

    def runs_of(self, role):
        return [run for run in self.world.runs if run[0] == role]

    def test_the_check_is_the_same(self):
        row = self.row()
        self.assertEqual((row['importable'], row['ok'], self.levels(row)), (True, True, {}))

    def test_the_cluster_is_the_volume_and_there_is_no_dump(self):
        result = self.convert(self.upload_n8n(), ['n8n'])
        self.assertEqual(result['results'][0]['status'], 'converted')
        items = self.world.manifests['n8n']
        self.assertEqual((sorted(items['volumes']), items['postgres']), (list(sorted(COLD_VOLUMES)), {}))
        cluster = self.volume('n8n_postgres_data')
        self.assertEqual(cluster['PG_VERSION'][1], b'16\n')
        self.assertEqual([command[0] for _r, command, _d in self.world.execs if command[0] in ('pg_dump', 'pg_restore')], [])
        self.assertEqual(self.runs_of('controldata')[0][2], ['pg_controldata', '/var/lib/postgresql/data'])

    def test_the_new_cluster_and_the_import_get_the_password_from_the_podman_secret_never_as_a_value(self):
        self.convert(self.upload_n8n(), ['n8n'])
        _role, image, _command, options = self.runs_of('n8n-pg')[0]
        self.assertEqual(image, 'docker.io/library/postgres:16.15-alpine')
        self.assertEqual(options['--secret'], ['n8n-db-password,type=env,target=POSTGRES_PASSWORD'])
        self.assertNotIn('POSTGRES_PASSWORD_FILE=/work/pgpass', options.get('--env', []))
        self.assertFalse([v for v in options.get('--volume', []) if '/work' in v], 'the throwaway source is not mounted into it')
        for role in ('n8n-import',):
            _r, _i, _c, import_options = self.runs_of(role)[0]
            self.assertEqual(import_options['--secret'], ['n8n-db-password,type=env,target=DB_POSTGRESDB_PASSWORD'])
            self.assertFalse([e for e in import_options['--env'] if 'PASSWORD' in e], import_options['--env'])

    def test_unpublished_in_test_mode_with_the_same_secret(self):
        self.convert(self.upload_n8n(), ['n8n'], test_mode=True)
        self.assertTrue(self.world.unpublished)
        _r, _i, _c, options = self.runs_of('n8n-unpublish')[0]
        self.assertEqual(options['--secret'], ['n8n-db-password,type=env,target=DB_POSTGRESDB_PASSWORD'])

    def test_a_cluster_that_was_not_shut_down_cleanly_is_never_used(self):
        self.world.controldata_state = 'in production'
        error = self.convert_stopped(self.upload_n8n())
        self.assertEqual(error.code, 'job-failed')
        self.assertEqual(error.result['results'][0]['status'], 'failed')
        self.assertEqual((self.world.manifests, self.storage.list_backups()), ({}, []))

    def test_a_cluster_that_exited_with_an_error_is_never_used(self):
        self.world.exit_codes['n8n-pg'] = 137
        error = self.convert_stopped(self.upload_n8n())
        self.assertEqual(error.code, 'job-failed')
        self.assertEqual(self.world.manifests, {})

    def test_the_other_findings_still_hold_for_a_cold_app(self):
        error = self.convert_stopped(self.upload_n8n(owner=False))
        self.assertEqual(error.result['results'][0]['issues'][0]['id'], 'n8n.no-owner')
        self.assertEqual(self.built().count('n8n-pg'), 0)


class ReferenceHostTests(unittest.TestCase):
    """The Quadlet files of the reference host (names, mounts and dependencies only: tests/backup/fixtures/reference-host): the
    real shape of n8n in queue mode, in the two ways its app settings can describe it."""
    FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'reference-host' / 'quadlet'

    def quadlets(self):
        return {path.name: path.read_bytes() for path in sorted(self.FIXTURES.iterdir()) if path.name.startswith('n8n')}

    def test_instance_reader_selects_main_and_not_worker_or_webhook_on_the_real_queue_layout(self):
        connection = ha_n8n.read_app_connection(ConnectionRunner({'DB_POSTGRESDB_DATABASE': 'automation'}), self.quadlets())
        self.assertEqual(connection['database'], 'automation')

    def target(self, volumes, postgres):
        quadlets = self.quadlets()
        work = types.SimpleNamespace(quadlets=lambda _app: quadlets,
                                     runner=lambda _app: types.SimpleNamespace(home='/home/appowner'))
        sink = Sink('n8n')
        return ha_n8n.Target(work, n8n_app(volumes=volumes, postgres=postgres), sink), sink

    def test_the_single_database_entry_is_filled_as_it_is(self):
        target, sink = self.target(('n8n_n8n_data', 'n8n_valkey_data'), [dict(PG)])
        self.assertEqual((target.cold, target.data_volume, target.queue_volumes, target.extra_volumes, sink.found),
                         (False, 'n8n_n8n_data', ['n8n_valkey_data'], [], []))
        self.assertEqual((target.main_file, target.pg_file, target.n8n_image),
                         ('n8n-webhook.container', 'n8n-postgres.container', 'docker.n8n.io/n8nio/n8n:1.119.2'))
        self.assertEqual(target.skipped_mounts, [], 'the host files inside the home are no skipped mounts')

    def test_the_cold_entry_is_filled_too_with_the_secret_of_the_database_password(self):
        """N8-01: the real container gets `n8n-db-password` as POSTGRES_PASSWORD, the throwaway n8n as DB_POSTGRESDB_PASSWORD."""
        target, sink = self.target(('n8n_n8n_data', 'n8n_valkey_data', 'n8n_postgres_data'), [])
        self.assertEqual((target.cold, target.pg_data_volume, target.queue_volumes, target.extra_volumes, sink.found),
                         (True, 'n8n_postgres_data', ['n8n_valkey_data'], [], []))
        self.assertEqual((target.pg['user'], target.pg['database'], target.pg_target), ('n8n', 'n8n', '/var/lib/postgresql/data'))
        self.assertEqual(target.import_secrets, ['n8n-db-password,type=env,target=DB_POSTGRESDB_PASSWORD'])


@unittest.skipUnless(os.environ.get('WOOWBK_HA_FIXTURES'), 'set WOOWBK_HA_FIXTURES to read the real HA backups made for this feature')
class RealN8nBackupTests(unittest.TestCase):
    """The n8n add-on of a REAL HA backup (Supervisor 2026.11.0, plain, never committed; only structure is asserted, nothing is
    printed): the strict pass, the sandboxed SQLite child on the real database and what the check says of it."""

    def test_the_real_n8n_addon_is_read_whole_and_says_nothing_that_stops_it(self):
        path = Path(os.environ['WOOWBK_HA_FIXTURES']) / 'woow-import-test-plain' / 'woow-import-test-plain.tar'
        if not path.exists():
            self.skipTest('the plain real backup is not in WOOWBK_HA_FIXTURES')
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / 'stage').mkdir()
        report = habackup.Report(names=haissues.Names)
        files = ha_n8n.FileTar(root / 'files.tar')
        with habackup.open_backup(path) as ha:
            member = next(m for m in ha.layout.members if m.role == 'addon' and m.name.endswith('woow-n8n.tar.gz'))
            with ha.open_member(member.name, None) as stream:
                src = ha_n8n.scan_member(stream, report, root / 'stage', files=files)
        files.close()
        self.addCleanup(lambda: src.key and jobs.unmask_secret(src.key))
        self.assertTrue(report.complete)
        self.assertEqual(report.skip_count(), 0, 'nothing of a real n8n add-on is left out')
        self.assertEqual((src.addon.slug, src.addon.arch), ('woow-n8n', 'amd64'))
        self.assertEqual(sorted(src.sqlite), ['database.sqlite', 'database.sqlite-wal'])
        self.assertIsNotNone(src.key, 'the key of a real n8n is a key')
        info = ha_n8n.inspect_sqlite(src.sqlite['database.sqlite'])
        self.assertTrue(info['owner_ok'])
        self.assertGreater(len(info['tables']), 100, 'the real schema has more than a hundred tables')
        self.assertEqual(len(info['credential_names']), info['counts']['credentials'])
        self.assertTrue(info['migration'])
        sink = Sink('n8n')
        ha_n8n.analyse_data(sink, src, info)
        self.assertEqual([issue.id for issue in sink.found], [])

    def test_the_real_arm_made_n8n_addons_are_read_too_and_a_native_node_for_another_processor_is_told(self):
        """The add-ons of the real backups made on the ARM test machine (Supervisor of 2026-11-19, plain): the same reader on a
        second processor (`aarch64`); `woow-arm-native` holds a native community node for that processor, which an x86-64
        device cannot run (a notice, never a stop). Only structure is asserted, nothing is printed."""
        base = Path(os.environ['WOOWBK_HA_FIXTURES']).parent / '20261119-arm'
        x86 = ha_odoo.host_elf_machine() in (None, ha_odoo.EM_X86_64)
        read = 0
        for name, native in (('woow-arm-plain', False), ('woow-arm-downloaded', False), ('woow-arm-native', True)):
            path = base / name / f'{name}.tar'
            if not path.exists():
                continue
            read += 1
            with self.subTest(backup=name):
                tmp = tempfile.TemporaryDirectory()
                self.addCleanup(tmp.cleanup)
                root = Path(tmp.name)
                (root / 'stage').mkdir()
                report = habackup.Report(names=haissues.Names)
                with habackup.open_backup(path) as ha:
                    member = next(m for m in ha.layout.members
                                  if m.role == 'addon' and m.name.endswith(('woow-n8n.tar.gz', 'woow-n8n.tar')))
                    with ha.open_member(member.name, None) as stream:
                        src = ha_n8n.scan_member(stream, report, root / 'stage')
                self.addCleanup(lambda src=src: src.key and jobs.unmask_secret(src.key))
                self.assertTrue(report.complete)
                self.assertEqual(report.skip_count(), 0, 'nothing of a real n8n add-on is left out')
                self.assertEqual((src.addon.slug, src.addon.arch), ('woow-n8n', 'aarch64'))
                self.assertEqual(sorted(src.sqlite), ['database.sqlite', 'database.sqlite-wal'])
                self.assertIsNotNone(src.key)
                self.assertTrue(src.packages, 'the community package of the test machine is listed')
                info = ha_n8n.inspect_sqlite(src.sqlite['database.sqlite'])
                self.assertTrue(info['owner_ok'])
                sink = Sink('n8n')
                ha_n8n.analyse_data(sink, src, info)
                levels = {issue.id: issue.level for issue in sink.found}
                self.assertEqual(levels.get('n8n.community-packages'), 'notice')
                self.assertEqual('n8n.native-code' in levels, native and x86, levels)
                self.assertEqual([i.id for i in sink.found if i.level in ('stop', 'confirm')], [],
                                 'nothing of a real ARM-made n8n stops it or asks')
        if not read:
            self.skipTest('the ARM-made real backups are not next to WOOWBK_HA_FIXTURES')


if __name__ == '__main__':
    unittest.main()
