"""What the engine sends into a throwaway PostgreSQL container on a `podman exec` stdin must arrive whole
(pg-stdin-fix 2026-11-24; final verification 21:53: under host load ~21 a real ARM Odoo conversion restored only part
of its pg_restore list, the engine noticed nothing, and only a later psql failed). Every test here feeds ha_odoo.Cluster
a transport that drops or cuts what it sends: Cluster.write_file must read the file back, write it again at most twice
more and then stop with INCOMPLETE_FILE; Cluster.script and Cluster.statement must never commit a lost tail they could
have noticed and must stop with INCOMPLETE_SQL. Neither message nor log ever holds the content or a digest of it.
The psql behaviour the emulator models was measured with real psql 17.11 in the lab (evidence pg-stdin-real-20261124)."""
import collections
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from woowbackup import ha_odoo
from woowbackup.errors import BackupError
from woowbackup.podman import CommandError, Result

from . import hafakes
from . import hafixtures as hx

TOC = ''.join(f'{n}; 1259 {16000 + n} TABLE public t{n} odoo\n' for n in range(1, 4001)).encode()   # ~150 KiB
PATH = '/tmp/woowbk-odoo.toc'
SECRET = 'SCRAM-SHA-256$4096:c2FsdHNhbHQ=$c3RvcmVka2V5$c2VydmVya2V5'   # a made-up verifier, never a real one


def is_write(argv):
    return argv[:2] == ['sh', '-c'] and hafakes.WRITE_RE.fullmatch(argv[2]) is not None


def is_script(argv, data):
    return argv[:1] == ['psql'] and argv[-2:] == ['-f', '-'] and data is not None


class Lossy(hafakes.FakeTmp):
    """FakeTmp whose `podman exec` stdin transfer loses data: `cut(kind, n, data)` gives what arrives in the
    container for the n-th write ('write') or psql script ('psql'). `sent`: what the engine sent, per kind."""

    def __init__(self, cut=lambda _kind, _n, data: data, **kwargs):
        super().__init__(**kwargs)
        self.cut = cut
        self.sent = collections.defaultdict(list)

    def exec(self, role, argv, *, input=None, **kwargs):
        data = input.read() if hasattr(input, 'read') else input
        kind = 'write' if is_write(argv) else 'psql' if is_script(argv, data) else None
        if kind is not None:
            self.sent[kind].append(data)
            data = self.cut(kind, len(self.sent[kind]), data)
        return super().exec(role, argv, input=data, **kwargs)


class Recorder:
    def __init__(self):
        self.lines, self.pauses = [], []

    def log(self, text):
        self.lines.append(text)

    def sleep(self, seconds):
        self.pauses.append(seconds)


def cluster(tmp, rec, superuser='postgres'):
    return ha_odoo.Cluster(tmp, 'odoo-db', superuser=superuser, log=rec.log, sleep=rec.sleep)


def drop_middle(data):
    return data[:4096] + data[8192:]


def flip_one_byte(data):   # same size, other content
    return data[:100] + bytes([data[100] ^ 0x01]) + data[101:]


class WriteFileTests(unittest.TestCase):
    def assert_quiet(self, rec, error=None):
        """No content and no digest in the log or the message."""
        texts = list(rec.lines) + ([error.message, str(error.details)] if error is not None else [])
        for text in texts:
            for needle in ('TABLE public', 't4000', hashlib.sha256(TOC).hexdigest(), str(len(TOC))):
                self.assertNotIn(needle, text)

    def test_a_whole_copy_is_read_back_once_and_kept(self):
        tmp, rec = Lossy(), Recorder()
        cluster(tmp, rec).write_file(PATH, TOC)
        self.assertEqual(tmp.files.files, {('odoo-db', PATH): TOC})
        commands = [argv for _role, argv, _data in tmp.calls]
        self.assertEqual(commands, [['sh', '-c', f'umask 077 && cat > {PATH}'],
                                    ['sh', '-c', ha_odoo.READBACK.format(path=PATH)]])
        self.assertIsNone(tmp.calls[1][2], 'the read-back sends nothing')
        self.assertEqual((rec.lines, rec.pauses), ([], []))

    def test_a_short_copy_is_written_again(self):
        for name, cut in (('tail lost', lambda data: data[:len(data) // 2]), ('all lost', lambda data: b''),
                          ('a middle chunk lost', drop_middle), ('one byte changed', flip_one_byte),
                          ('last byte lost', lambda data: data[:-1])):
            with self.subTest(name):
                tmp, rec = Lossy(lambda _k, n, data, cut=cut: cut(data) if n == 1 else data), Recorder()
                cluster(tmp, rec).write_file(PATH, TOC)
                self.assertEqual(tmp.files.files, {('odoo-db', PATH): TOC})
                self.assertEqual(tmp.sent['write'], [TOC, TOC])
                self.assertEqual(len(rec.lines), 1)
                self.assertIn('沒有完整寫入，重新寫入（第 2 次，共 3 次）', rec.lines[0])
                self.assertEqual(rec.pauses, [ha_odoo.WRITE_RETRY_PAUSE])
                self.assert_quiet(rec)

    def test_three_short_copies_stop_the_job_and_say_why(self):
        for name, cut in (('tail lost', lambda data: data[:len(data) // 2]), ('all lost', lambda data: b''),
                          ('a middle chunk lost', drop_middle), ('one byte changed', flip_one_byte)):
            with self.subTest(name):
                tmp, rec = Lossy(lambda _k, _n, data, cut=cut: cut(data)), Recorder()
                with self.assertRaises(BackupError) as caught:
                    cluster(tmp, rec).write_file(PATH, TOC)
                self.assertEqual(caught.exception.code, 'job-failed')
                self.assertEqual(caught.exception.message, ha_odoo.INCOMPLETE_FILE)
                self.assertIn('主機可能太忙', caught.exception.message)
                self.assertIn('沒有做任何變更', caught.exception.message)
                self.assertEqual(len(tmp.sent['write']), ha_odoo.WRITE_ATTEMPTS)
                self.assertEqual(ha_odoo.WRITE_ATTEMPTS, 3, 'the first write and at most 2 more')
                self.assertEqual(rec.pauses, [ha_odoo.WRITE_RETRY_PAUSE] * 2)
                self.assert_quiet(rec, caught.exception)

    def test_a_read_back_that_fails_or_says_nothing_useful_counts_as_a_short_copy(self):
        whole = hafakes.readback_answer(TOC).stdout
        replies = {'exit 1': Result(1, b'', b'no such file'), 'empty': Result(0, b'', b''),
                   'exit 1 after a right-looking answer': Result(1, whole, b''),
                   'no digest line': Result(0, f'{len(TOC)}\nsha256\n'.encode(), b''),
                   'unknown kind': Result(0, f'{len(TOC)}\nmd5\n{"0" * 32}  -\n'.encode(), b''),
                   'size not a number': Result(0, b'12x\nsha256\n' + b'0' * 64 + b'  -\n', b''),
                   'cksum with another size': Result(0, f'{len(TOC)}\ncksum\n1 {len(TOC) - 1}\n'.encode(), b'')}
        for name, reply in replies.items():
            with self.subTest(name):
                tmp, rec = Lossy(), Recorder()
                tmp.files.read_back = lambda _key, argv, reply=reply: reply if hafakes.readback_path(argv[2]) else None
                with self.assertRaises(BackupError) as caught:
                    cluster(tmp, rec).write_file(PATH, TOC)
                self.assertEqual(caught.exception.message, ha_odoo.INCOMPLETE_FILE)
                self.assertEqual(len(tmp.sent['write']), 3)

    def test_without_sha256sum_the_posix_cksum_is_compared(self):
        def cksum_reply(data):
            size, crc = ha_odoo.source_digest(data, None, 'cksum')
            return Result(0, f'   {len(data)}\ncksum\n{crc} {size}\n'.encode(), b'')
        for name, cut, passes in (('whole', lambda data: data, True), ('short', lambda data: data[:-10], False),
                                  ('changed', flip_one_byte, False)):
            with self.subTest(name):
                tmp, rec = Lossy(lambda _k, _n, data, cut=cut: cut(data)), Recorder()
                tmp.files.read_back = lambda key, argv: (cksum_reply(tmp.files.files[(key, PATH)])
                                                         if hafakes.readback_path(argv[2]) else None)
                if passes:
                    cluster(tmp, rec).write_file(PATH, TOC)
                    self.assertEqual(len(tmp.sent['write']), 1)
                else:
                    with self.assertRaises(BackupError):
                        cluster(tmp, rec).write_file(PATH, TOC)
                    self.assertEqual(len(tmp.sent['write']), 3)

    def test_the_posix_cksum_is_the_one_cksum_prints(self):
        # POSIX cksum check values (GNU coreutils and busybox print the same: `printf 123456789 | cksum`)
        self.assertEqual(ha_odoo.source_digest(b'123456789', None, 'cksum'), (9, '930766865'))
        self.assertEqual(ha_odoo.source_digest(b'', None, 'cksum'), (0, '4294967295'))
        self.assertEqual(ha_odoo.source_digest(b'a', None, 'cksum'), (1, '1220704766'))
        self.assertEqual(ha_odoo.source_digest(TOC, None, 'sha256'), (len(TOC), hashlib.sha256(TOC).hexdigest()))
        tool = shutil.which('cksum')
        if tool:   # the host's own cksum on data longer than one length byte
            for data in (TOC, os.urandom(70000), b'\x00' * 256):
                out = subprocess.run([tool], input=data, capture_output=True, check=True).stdout.split()
                self.assertEqual(ha_odoo.source_digest(data, None, 'cksum'), (int(out[1]), out[0].decode()))

    def test_an_open_file_is_sent_from_where_it_stood_and_rewound_for_every_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'list'
            path.write_bytes(b'HEAD' + TOC)
            for name, opener in (('in memory', lambda: io.BytesIO(b'HEAD' + TOC)), ('a file', lambda: open(path, 'rb'))):
                with self.subTest(name), opener() as handle:
                    handle.read(4)
                    tmp, rec = Lossy(lambda _k, n, data: data[:100] if n == 1 else data), Recorder()
                    cluster(tmp, rec).write_file(PATH, handle)
                    self.assertEqual(tmp.files.files, {('odoo-db', PATH): TOC})
                    self.assertEqual(tmp.sent['write'], [TOC, TOC])

    def test_a_source_that_cannot_be_read_again_is_refused_before_anything_runs(self):
        class Pipe:
            def read(self, _n=-1):
                return b'x'

        tmp, rec = Lossy(), Recorder()
        with self.assertRaises(BackupError) as caught:
            cluster(tmp, rec).write_file(PATH, Pipe())
        self.assertEqual(caught.exception.code, 'internal-error')
        self.assertEqual(tmp.calls, [])

    def test_the_path_rule_is_unchanged(self):
        for bad in ('/tmp/other', '/tmp/woowbk-a b', '/tmp/woowbk-x;rm', '/var/tmp/woowbk-x', '/tmp/woowbk-'):
            with self.subTest(bad), self.assertRaises(BackupError):
                cluster(Lossy(), Recorder()).write_file(bad, TOC)

    def test_a_failing_write_still_fails_as_before(self):
        tmp, rec = Lossy(), Recorder()

        def refuse(role, argv, *, input=None, **kwargs):
            if is_write(argv):
                raise CommandError('podman exec 執行失敗（結束碼 1）。', returncode=1)
            return hafakes.FakeTmp.exec(tmp, role, argv, input=input, **kwargs)
        tmp.exec = refuse
        with self.assertRaises(CommandError):
            cluster(tmp, rec).write_file(PATH, TOC)
        self.assertEqual(rec.pauses, [], 'a failing command is no short copy: no retry')

    def test_the_read_back_command_works_in_a_real_shell(self):
        """READBACK and its parsing against this host's sh and coreutils (busybox: the lab evidence)."""
        if not shutil.which('sha256sum') or not shutil.which('sh'):
            self.skipTest('no sh/sha256sum here')
        with tempfile.TemporaryDirectory() as directory:
            def real(cut):
                class Real(hafakes.FakeTmp):
                    def exec(self, role, argv, *, input=None, check=True, **kwargs):
                        data = input.read() if hasattr(input, 'read') else input
                        self.calls.append((role, list(argv), data))
                        command = argv[2].replace('/tmp/woowbk-', directory + '/woowbk-')
                        if is_write(argv):
                            data = cut(data)
                        proc = subprocess.run(['sh', '-c', command], input=data, capture_output=True, timeout=60)
                        if check and proc.returncode:
                            raise CommandError('sh 執行失敗', returncode=proc.returncode)
                        return Result(proc.returncode, proc.stdout, proc.stderr)
                return Real()
            tmp, rec = real(lambda data: data), Recorder()
            cluster(tmp, rec).write_file(PATH, TOC)
            self.assertEqual((Path(directory) / 'woowbk-odoo.toc').read_bytes(), TOC)
            self.assertEqual(oct((Path(directory) / 'woowbk-odoo.toc').stat().st_mode & 0o777), '0o600')
            tmp, rec = real(lambda data: data[:-1]), Recorder()
            with self.assertRaises(BackupError) as caught:
                cluster(tmp, rec).write_file(PATH, TOC)
            self.assertEqual(caught.exception.message, ha_odoo.INCOMPLETE_FILE)


STATEMENTS = ("UPDATE t SET a = 'y' WHERE id = 1;\n"
              "UPDATE t SET a = 'z' WHERE id = 2;\n")


class ScriptTests(unittest.TestCase):
    def run_script(self, cut, sql=STATEMENTS, superuser='postgres'):
        psql = hafakes.Psql()
        tmp, rec = Lossy(lambda _k, _n, data: cut(data), psql=psql), Recorder()
        error = None
        try:
            cluster(tmp, rec, superuser).script(sql, 'odoo')
        except BackupError as caught:
            error = caught
        return tmp, psql, rec, error

    def test_the_input_opens_and_closes_its_own_transaction_then_asks_for_the_end_mark(self):
        tmp, psql, rec, error = self.run_script(lambda data: data)
        self.assertIsNone(error)
        (role, argv, data), = [call for call in tmp.calls if call[1][0] == 'psql']
        self.assertEqual(argv, ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'odoo', '-f', '-'])
        self.assertNotIn('-1', argv)
        text = data.decode()
        self.assertTrue(text.startswith('BEGIN;\n' + STATEMENTS))
        self.assertRegex(text, r'\nCOMMIT;\n\\echo woowbk-sql-end-[0-9a-f]{16}\n\Z')
        self.assertEqual([(s, tx) for _db, s, tx in psql.executed],
                         [("UPDATE t SET a = 'y' WHERE id = 1", True), ("UPDATE t SET a = 'z' WHERE id = 2", True)])
        self.assertEqual(rec.lines, [])

    def test_a_lost_tail_commits_nothing_and_stops_the_job(self):
        def at(marker):
            return lambda data: data[:data.index(marker)]
        for name, cut in (('at a statement boundary', at(b"UPDATE t SET a = 'z'")),
                          ('inside the last statement (its prefix is valid SQL)', at(b' WHERE id = 2')),
                          ('inside COMMIT', at(b'MIT;\n\\echo')),
                          ('COMMIT and the mark', at(b'COMMIT;')),
                          ('all of it', lambda data: b'')):
            with self.subTest(name):
                tmp, psql, rec, error = self.run_script(cut)
                self.assertIsNotNone(error)
                self.assertEqual((error.code, error.message), ('job-failed', ha_odoo.INCOMPLETE_SQL))
                self.assertIn('主機可能太忙', error.message)
                self.assertEqual(psql.executed, [], 'rolled back: nothing of the transaction was committed')

    def test_a_lost_end_mark_alone_is_noticed_although_the_script_committed(self):
        tmp, psql, rec, error = self.run_script(lambda data: data[:data.index(b'\\echo')])
        self.assertEqual(error.message, ha_odoo.INCOMPLETE_SQL)
        self.assertEqual(len(psql.executed), 2)

    def test_the_end_mark_is_new_for_every_call_and_must_end_the_output(self):
        seen = []
        tmp = Lossy()
        replies = iter([lambda data: hafakes.echoed(data),                       # the right mark
                        lambda data: b' setval\n--------\n 42\n(1 row)\n\n' + hafakes.echoed(data),   # rows before it
                        lambda data: seen[0],                                     # an earlier call's mark
                        lambda data: hafakes.echoed(data) + b'tail\n',             # something after it
                        lambda data: hafakes.echoed(data).upper()])                # not exactly it
        marks = []

        def fake(role, argv, *, input=None, **kwargs):
            marks.append(hafakes.echoed(input))
            if not seen:
                seen.append(hafakes.echoed(input))
            return Result(0, next(replies)(input), b'')
        tmp.exec = fake
        db = ha_odoo.Cluster(tmp, 'odoo-db')
        db.script(STATEMENTS)
        db.script(STATEMENTS)
        for _ in range(3):
            with self.assertRaises(BackupError) as caught:
                db.script(STATEMENTS)
            self.assertEqual(caught.exception.message, ha_odoo.INCOMPLETE_SQL)
        self.assertEqual(len(set(marks)), len(marks), 'a new mark for every call')

    def test_an_sql_error_still_fails_as_the_command_error_it_was(self):
        def failing(role, argv, *, input=None, **kwargs):
            raise CommandError('podman exec 執行失敗（結束碼 3）。', returncode=3, stderr=b'ERROR: x')
        tmp = Lossy()
        tmp.exec = failing
        with self.assertRaises(CommandError):
            ha_odoo.Cluster(tmp, 'odoo-db').script(STATEMENTS)

    def test_values_stay_out_of_argv_messages_and_logs(self):
        role = {'password': SECRET, 'login': True}
        for cut in (lambda data: data, lambda data: data[:-20]):
            with self.subTest(cut=cut):
                tmp, psql, rec, error = self.run_script(cut, sql=ha_odoo.role_sql(role), superuser='postgres')
                for _role, argv, _data in tmp.calls:
                    self.assertFalse([arg for arg in argv if SECRET in arg or 'c2FsdHNhbHQ' in arg])
                for text in rec.lines + ([error.message, str(error.details)] if error else []):
                    self.assertNotIn('c2FsdHNhbHQ', text)
        self.assertEqual(error.message, ha_odoo.INCOMPLETE_SQL)

    def test_a_script_is_text(self):
        with self.assertRaises(BackupError) as caught:
            ha_odoo.Cluster(Lossy(), 'odoo-db').script(STATEMENTS.encode())
        self.assertEqual(caught.exception.code, 'internal-error')


class StatementTests(unittest.TestCase):
    def test_one_statement_outside_any_transaction_block_then_the_end_mark(self):
        psql = hafakes.Psql()
        tmp = Lossy(psql=psql)
        ha_odoo.Cluster(tmp, 'odoo-db').statement("ALTER SYSTEM SET work_mem TO '8MB';")
        (_role, argv, data), = tmp.calls
        self.assertNotIn('-1', argv)
        self.assertEqual(argv[-2:], ['-f', '-'])
        self.assertRegex(data.decode(), r"\AALTER SYSTEM SET work_mem TO '8MB';\n\\echo woowbk-sql-end-[0-9a-f]{16}\n\Z")
        self.assertNotIn(b'BEGIN', data)
        self.assertEqual(psql.executed, [('postgres', "ALTER SYSTEM SET work_mem TO '8MB'", False)])
        self.assertEqual(psql.auto_conf, {'work_mem': "'8MB'"})

    def test_a_statement_without_its_semicolon_gets_one_before_the_mark(self):
        tmp = Lossy()
        ha_odoo.Cluster(tmp, 'odoo-db').statement('CHECKPOINT')
        self.assertRegex(tmp.calls[0][2].decode(), r'\ACHECKPOINT;\n\\echo woowbk-sql-end-[0-9a-f]{16}\n\Z')

    def test_a_lost_tail_is_noticed(self):
        for name, cut in (('the mark', lambda data: data[:data.index(b'\\echo')]),
                          ('half the mark', lambda data: data[:-10]), ('all of it', lambda data: b'')):
            with self.subTest(name):
                tmp = Lossy(lambda _k, _n, data, cut=cut: cut(data))
                with self.assertRaises(BackupError) as caught:
                    ha_odoo.Cluster(tmp, 'odoo-db').statement('CHECKPOINT;')
                self.assertEqual((caught.exception.code, caught.exception.message),
                                 ('job-failed', ha_odoo.INCOMPLETE_SQL))

    def test_the_one_statement_rule_is_unchanged(self):
        tmp = Lossy()
        for bad in ("ALTER SYSTEM SET a TO '1'; ALTER SYSTEM SET b TO '2';", '', '   ', None):
            with self.subTest(bad), self.assertRaises(BackupError):
                ha_odoo.Cluster(tmp, 'odoo-db').statement(bad)
        self.assertEqual(tmp.calls, [])
        ha_odoo.Cluster(tmp, 'odoo-db').statement("ALTER SYSTEM SET a TO 'x;y';")
        self.assertIn(b"ALTER SYSTEM SET a TO 'x;y';\n", tmp.calls[0][2])


LISTING = [f'{n}; 1259 {16000 + n} TABLE public t{n} odoo' for n in range(1, 401)]   # a few hundred entries


def run_restore(listing, *, cut_write=None, sink=None):
    """Odoo's restore_dump against a double: `pg_restore -l` prints `listing`, everything else works; `cut_write(n, data)`
    is what arrives of the n-th file written into the container."""
    def pg_restore(role, argv, data, stdout):
        return Result(0, listing if argv[:2] == ['pg_restore', '-l'] else b'', b'')

    tmp = Lossy(cut=(lambda kind, n, data: cut_write(n, data) if kind == 'write' and cut_write else data),
                handlers={'pg_restore': pg_restore})
    rec = Recorder()
    with tempfile.TemporaryDirectory() as folder:
        dump = Path(folder) / 'odoo.dump'
        dump.write_bytes(b'PGDMP-data')
        try:
            ha_odoo.restore_dump(__import__('types').SimpleNamespace(log=rec.log), tmp, dump, 'woowtest', sink=sink)
            error = None
        except BackupError as caught:
            error = caught
    return tmp, rec, error


class ListingTests(unittest.TestCase):
    """pg-stdin follow-up F4: the list `pg_restore -l` prints is checked against the entry count in its own header before
    anything is restored from it (a list that came back short would restore only the part it names)."""

    def test_a_whole_listing_passes_with_and_without_the_archive_settings_shown(self):
        hidden = hx.toc_listing(LISTING)                        # the plain listing: ENCODING, STDSTRINGS, SEARCHPATH kept back
        self.assertEqual(ha_odoo.check_listing(hidden.decode()), len(LISTING))
        shown = hx.toc_listing(['1; 0 0 ENCODING - ENCODING', '2; 0 0 STDSTRINGS - STDSTRINGS',
                                '3; 0 0 SEARCHPATH - SEARCHPATH', *LISTING], hidden=0)
        self.assertEqual(ha_odoo.check_listing(shown.decode()), len(LISTING) + 3)

    def test_a_listing_that_lost_entries_is_refused_wherever_they_were_lost(self):
        whole = hx.toc_listing(LISTING).decode()
        lines = whole.splitlines()
        first = lines.index(LISTING[0])
        cases = {'the last line': lines[:-1], 'a middle line': lines[:first + 100] + lines[first + 101:],
                 'the first entry': lines[:first] + lines[first + 1:], 'half': lines[:first + 200],
                 'every entry': lines[:first], 'a few at the end': lines[:-3]}
        for name, kept in cases.items():
            with self.subTest(name), self.assertRaises(BackupError) as caught:
                ha_odoo.check_listing('\n'.join(kept) + '\n')
            self.assertEqual((caught.exception.code, caught.exception.message), ('job-failed', ha_odoo.INCOMPLETE_LIST))
            self.assertEqual(caught.exception.details['declared'], len(LISTING) + 3, 'the numbers say what was counted')
            self.assertLess(caught.exception.details['listed'], len(LISTING))
        shown = hx.toc_listing(['1; 0 0 ENCODING - ENCODING', '2; 0 0 STDSTRINGS - STDSTRINGS',
                                '3; 0 0 SEARCHPATH - SEARCHPATH', *LISTING], hidden=0).decode().splitlines()
        with self.assertRaises(BackupError):
            ha_odoo.check_listing('\n'.join(shown[:-1]) + '\n')

    def test_a_listing_without_its_header_or_with_a_header_that_is_no_count_cannot_be_checked(self):
        body = ''.join(line + '\n' for line in LISTING)
        for name, text in (('no header', ';\n; Archive created\n;\n' + body), ('nothing', ''),
                           ('no number', ';     TOC Entries: many\n' + body),
                           ('negative', ';     TOC Entries: -3\n' + body),
                           ('twice the lines', hx.toc_listing(LISTING + LISTING, declared=len(LISTING) + 3).decode())):
            with self.subTest(name), self.assertRaises(BackupError) as caught:
                ha_odoo.check_listing(text)
            self.assertEqual(caught.exception.message, ha_odoo.INCOMPLETE_LIST)
        self.assertIn('主機可能太忙', ha_odoo.INCOMPLETE_LIST)
        self.assertIn('沒有做任何變更', ha_odoo.INCOMPLETE_LIST)

    def test_a_short_listing_stops_the_restore_before_anything_is_written_or_restored(self):
        whole = hx.toc_listing(LISTING)
        tmp, rec, error = run_restore(whole[:len(whole) - 2000])
        self.assertEqual((error.code, error.message), ('job-failed', ha_odoo.INCOMPLETE_LIST))
        commands = [argv for _role, argv, _data in tmp.calls]
        self.assertEqual([c for c in commands if c[:1] == ['sh']], [], 'no list was written into the container')
        self.assertEqual([c for c in commands if c[:1] == ['pg_restore'] and '-d' in c], [], 'nothing restored')
        for text in rec.lines + [error.message, str(error.details)]:
            self.assertNotIn('TABLE public', text)

    def test_a_whole_listing_restores(self):
        tmp, _rec, error = run_restore(hx.toc_listing(LISTING))
        self.assertIsNone(error)
        self.assertTrue([argv for _r, argv, _d in tmp.calls if argv[:1] == ['pg_restore'] and '-d' in argv])


class RestoreLogTests(unittest.TestCase):
    """pg-stdin follow-up F3: the note that the list had to be written again reaches the job's log."""

    def test_the_rewrite_of_the_list_is_in_the_job_log(self):
        tmp, rec, error = run_restore(hx.toc_listing(LISTING), cut_write=lambda n, data: data[:100] if n == 1 else data)
        self.assertIsNone(error)
        self.assertEqual(len(tmp.sent['write']), 2)
        notes = [line for line in rec.lines if '沒有完整寫入，重新寫入' in line]
        self.assertEqual(len(notes), 1, rec.lines)
        for line in rec.lines:
            self.assertNotIn('TABLE public', line)
            self.assertNotIn(hashlib.sha256(tmp.sent['write'][0]).hexdigest(), line)

    def test_three_short_writes_stop_this_conversion_with_the_reason(self):
        tmp, rec, error = run_restore(hx.toc_listing(LISTING), cut_write=lambda n, data: data[:100])
        self.assertEqual((error.code, error.message), ('job-failed', ha_odoo.INCOMPLETE_FILE))
        self.assertEqual(len([line for line in rec.lines if '沒有完整寫入，重新寫入' in line]), 2)
        self.assertEqual([argv for _r, argv, _d in tmp.calls if argv[:1] == ['pg_restore'] and '-d' in argv], [])


class EmulatorTests(unittest.TestCase):
    """The emulator's psql semantics the tests above rely on (measured with real psql 17.11, lab evidence)."""

    def test_backslash_commands_never_reach_the_server_and_echo_prints(self):
        psql = hafakes.Psql()
        result = psql(['psql', '-f', '-'], b"SELECT 1;\n\\echo one two\nSELECT 'a\\b';\n")
        self.assertEqual([s for _d, s, _t in psql.executed], ['SELECT 1', "SELECT 'a\\b'"])
        self.assertEqual(result.stdout, b'one two\n')

    def test_an_input_that_ends_inside_its_transaction_block_keeps_nothing(self):
        psql = hafakes.Psql()
        psql(['psql', '-f', '-'], b'BEGIN;\nINSERT INTO t VALUES (1);\n')
        self.assertEqual(psql.executed, [])
        psql(['psql', '-f', '-'], b'BEGIN;\nINSERT INTO t VALUES (1);\nCOMMIT;\n')
        self.assertEqual(psql.executed, [('postgres', 'INSERT INTO t VALUES (1)', True)])

    def test_alter_system_inside_a_block_is_refused(self):
        with self.assertRaises(CommandError):
            hafakes.Psql()(['psql', '-f', '-'], b"BEGIN;\nALTER SYSTEM SET work_mem TO '1';\nCOMMIT;\n")


if __name__ == '__main__':
    unittest.main()
