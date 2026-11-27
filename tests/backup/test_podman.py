"""OwnerRunner: exact runuser/env prefix, error mapping, and the owner-side file helper.

The FILE_HELPER snippet is executed for real (as the current user, with HOME pointing at a temp
home) to prove the O_NOFOLLOW component walk, atomic writes and modes.
"""
import io
import json
import os
import stat
import subprocess
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import podman
from woowbackup.errors import BackupError

OWNER = types.SimpleNamespace(pw_name='appowner', pw_uid=1001, pw_gid=1001, pw_dir='/home/appowner')
REAL_DEFAULT_RUNNER = podman.default_runner   # the executor itself: UserManagerTests replace the module's name for it
EXPECTED_PREFIX = ['/usr/sbin/runuser', '-u', 'appowner', '--', '/usr/bin/env', '-i',
                   'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'HOME=/home/appowner', 'LANG=C.UTF-8',
                   'XDG_RUNTIME_DIR=/run/user/1001', 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus']


class Recorder:
    def __init__(self, result=None, exc=None):
        self.calls = []
        self.result = result or podman.Result(0, b'out', b'')
        self.exc = exc

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.exc:
            raise self.exc
        return self.result


def owner_lookup(home='/home/appowner'):
    def lookup(name):
        if name == 'appowner':
            return types.SimpleNamespace(pw_name='appowner', pw_uid=1001, pw_gid=1001, pw_dir=home)
        if name == 'zeroalias':
            return types.SimpleNamespace(pw_name='zeroalias', pw_uid=0, pw_gid=0, pw_dir='/root')
        raise KeyError(name)
    return lookup


class LocalRunner:
    """Executes the command after the runuser prefix as the current user (env -i keeps it hermetic)."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, *, input=None, stdout=None, timeout=None, cwd=None, env=None, max_output=None):
        assert argv[:4] == ['/usr/sbin/runuser', '-u', 'appowner', '--'], argv[:4]
        self.calls.append(argv)
        return podman.default_runner(argv[4:], input=input, stdout=stdout, timeout=timeout, cwd=cwd, env=env,
                                     max_output=max_output)


class PrefixTests(unittest.TestCase):
    def runner(self, **kwargs):
        rec = Recorder(**kwargs)
        return podman.OwnerRunner('appowner', runner=rec, user_lookup=owner_lookup()), rec

    def test_exact_prefix_cwd_and_root_env(self):
        runner, rec = self.runner()
        runner.run(['/usr/bin/podman', 'ps', '--all'])
        argv, kwargs = rec.calls[0]
        self.assertEqual(argv, EXPECTED_PREFIX + ['/usr/bin/podman', 'ps', '--all'])
        self.assertEqual(kwargs['cwd'], '/home/appowner')
        self.assertEqual(kwargs['env'], {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})
        self.assertEqual(kwargs['timeout'], 300)

    def test_podman_and_systemctl_helpers(self):
        runner, rec = self.runner()
        runner.podman('volume', 'exists', 'x', timeout=5)
        runner.systemctl('start', '--', 'a.service')
        self.assertEqual(rec.calls[0][0][len(EXPECTED_PREFIX):], ['/usr/bin/podman', 'volume', 'exists', 'x'])
        self.assertEqual(rec.calls[0][1]['timeout'], 5)
        self.assertEqual(rec.calls[1][0][len(EXPECTED_PREFIX):], ['/usr/bin/systemctl', '--user', 'start', '--', 'a.service'])

    def test_relay_wraps_podman_in_the_owner_helper(self):
        runner, rec = self.runner()
        sink = io.BytesIO()
        runner.relay(['volume', 'export', 'vol'], stdout=sink)
        inner = rec.calls[0][0][len(EXPECTED_PREFIX):]
        self.assertEqual(inner[:3], ['/usr/bin/python3', '-I', '-c'])
        self.assertEqual(inner[3], podman.FILE_HELPER)
        self.assertEqual(inner[4:], ['relay', '/usr/bin/podman', 'volume', 'export', 'vol'])
        self.assertIs(rec.calls[0][1]['stdout'], sink)

    def test_nonzero_exit_raises_command_error_without_stdout(self):
        runner, _ = self.runner(result=podman.Result(125, b'SECRET-STDOUT', b'Error: no such volume'))
        with self.assertRaises(podman.CommandError) as caught:
            runner.podman('volume', 'export', 'missing')
        error = caught.exception
        self.assertEqual((error.code, error.returncode), ('job-failed', 125))
        self.assertIn('podman volume export missing', error.message)
        self.assertNotIn('SECRET-STDOUT', error.message + str(error.details))
        self.assertEqual(error.stderr, b'Error: no such volume')

    def test_check_false_returns_result(self):
        runner, _ = self.runner(result=podman.Result(1, b'', b''))
        self.assertEqual(runner.podman('secret', 'exists', 'x', check=False).returncode, 1)

    def test_timeout_and_missing_tool(self):
        runner, _ = self.runner(exc=subprocess.TimeoutExpired('x', 1))
        with self.assertRaises(BackupError) as caught:
            runner.systemctl('stop', '--', 'a.service', timeout=1)
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertIn('逾時', caught.exception.message)
        runner, _ = self.runner(exc=FileNotFoundError())
        with self.assertRaises(BackupError) as caught:
            runner.podman('ps')
        self.assertEqual(caught.exception.code, 'owner-missing')

    def test_owner_validation(self):
        for name in ('root', 'Bad', '-x', '', None):
            with self.assertRaises(BackupError):
                podman.OwnerRunner(name, runner=Recorder(), user_lookup=owner_lookup())
        with self.assertRaises(BackupError) as caught:
            podman.OwnerRunner('ghost', runner=Recorder(), user_lookup=owner_lookup())
        self.assertEqual(caught.exception.code, 'owner-missing')
        with self.assertRaises(BackupError):
            podman.OwnerRunner('zeroalias', runner=Recorder(), user_lookup=owner_lookup())
        with self.assertRaises(BackupError):
            podman.OwnerRunner('appowner', runner=Recorder(), user_lookup=owner_lookup(home='relative/home'))

    def test_nul_in_argv_refused(self):
        runner, rec = self.runner()
        with self.assertRaises(BackupError):
            runner.run(['/usr/bin/podman', 'a\0b'])
        self.assertEqual(rec.calls, [])

    def test_rel_path_validation_happens_before_running(self):
        runner, rec = self.runner()
        for bad in ('../etc/passwd', '/etc/passwd', 'a//b', './x', 'a/../b', '', 'a\nb', 'x' * 2000):
            with self.assertRaises(BackupError):
                runner.read_file(bad)
            with self.assertRaises(BackupError):
                runner.write_file(bad, b'x', 0o600)
        with self.assertRaises(BackupError):
            runner.write_file('.config/x', b'x', 0o755)
        self.assertEqual(rec.calls, [])

    def test_describe_never_contains_helper_code(self):
        text = podman.describe(['/usr/bin/python3', '-I', '-c', podman.FILE_HELPER, 'read', '.config/a', '10'])
        self.assertEqual(text, 'owner-file read .config/a')
        self.assertEqual(podman.describe(['/usr/bin/python3', '-I', '-c', podman.FILE_HELPER, 'relay',
                                          '/usr/bin/podman', 'volume', 'export', 'v']), 'podman volume export v')

    def test_stderr_tail_drops_sql_echo_and_warnings(self):
        err = (b'time="x" level=warning msg="noise"\npg_restore: error: relation "t" already exists\n'
               b'Command was: CREATE TABLE t (secret text);\nmore sql')
        self.assertEqual(podman.stderr_tail(err), ['pg_restore: error: relation "t" already exists'])


class FileHelperTests(unittest.TestCase):
    """Real execution of FILE_HELPER with an isolated HOME."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / 'home'
        self.home.mkdir()
        self.outside = Path(self.tmp.name) / 'outside'
        self.outside.mkdir()
        self.local = LocalRunner()
        self.runner = podman.OwnerRunner('appowner', runner=self.local, user_lookup=owner_lookup(str(self.home)))

    def tearDown(self):
        self.tmp.cleanup()

    def test_read_regular_file(self):
        (self.home / '.config' / 'app').mkdir(parents=True)
        (self.home / '.config/app/app.env').write_bytes(b'TITLE=x\n\x00\xff')
        self.assertEqual(self.runner.read_file('.config/app/app.env'), b'TITLE=x\n\x00\xff')

    def test_read_errors(self):
        (self.home / '.config').mkdir()
        with self.assertRaises(BackupError) as caught:
            self.runner.read_file('.config/missing')
        self.assertEqual(caught.exception.code, 'not-found')
        (self.outside / 'secret').write_text('outside')
        os.symlink(self.outside / 'secret', self.home / '.config' / 'link')
        with self.assertRaises(BackupError) as caught:
            self.runner.read_file('.config/link')
        self.assertEqual(caught.exception.code, 'permission-denied')
        os.symlink(self.outside, self.home / '.config' / 'dirlink')
        with self.assertRaises(BackupError) as caught:
            self.runner.read_file('.config/dirlink/secret')
        self.assertEqual(caught.exception.code, 'permission-denied')
        (self.home / '.config' / 'big').write_bytes(b'x' * 100)
        with self.assertRaises(BackupError) as caught:
            self.runner.read_file('.config/big', max_bytes=10)
        self.assertEqual(caught.exception.code, 'limit-exceeded')
        os.mkfifo(self.home / '.config' / 'fifo')
        with self.assertRaises(BackupError) as caught:
            self.runner.read_file('.config/fifo')
        self.assertEqual(caught.exception.code, 'permission-denied')

    def test_write_creates_private_dirs_and_exact_mode(self):
        self.runner.write_file('.config/woowbk-demo/app.env', b'A=1\n', '0600')
        target = self.home / '.config/woowbk-demo/app.env'
        self.assertEqual(target.read_bytes(), b'A=1\n')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.home / '.config/woowbk-demo').stat().st_mode), 0o700)
        self.runner.write_file('.config/woowbk-demo/app.env', io.BytesIO(b'B=2\n'), 0o644)
        self.assertEqual(target.read_bytes(), b'B=2\n')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
        leftovers = [p.name for p in (self.home / '.config/woowbk-demo').iterdir() if p.name != 'app.env']
        self.assertEqual(leftovers, [])

    def test_write_never_follows_symlinks(self):
        (self.home / '.config').mkdir()
        os.symlink(self.outside, self.home / '.config' / 'woowbk-demo')
        with self.assertRaises(BackupError) as caught:
            self.runner.write_file('.config/woowbk-demo/app.env', b'x', 0o600)
        self.assertEqual(caught.exception.code, 'permission-denied')
        self.assertEqual(list(self.outside.iterdir()), [])
        (self.outside / 'victim').write_text('keep')
        os.symlink(self.outside / 'victim', self.home / '.config' / 'final')
        self.runner.write_file('.config/final', b'new', 0o600)
        self.assertEqual((self.outside / 'victim').read_text(), 'keep')
        self.assertFalse((self.home / '.config/final').is_symlink())
        self.assertEqual((self.home / '.config/final').read_bytes(), b'new')

    def test_write_onto_directory_fails_cleanly(self):
        (self.home / '.config' / 'adir').mkdir(parents=True)
        with self.assertRaises(BackupError):
            self.runner.write_file('.config/adir', b'x', 0o600)
        self.assertEqual([p.name for p in (self.home / '.config').iterdir()], ['adir'])

    def test_remove_and_stat(self):
        (self.home / '.config').mkdir()
        (self.home / '.config/file').write_text('x')
        (self.outside / 'target').write_text('keep')
        os.symlink(self.outside / 'target', self.home / '.config' / 'link')
        os.symlink(self.outside, self.home / '.config' / 'dirlink')
        (self.home / '.config/sub').mkdir()
        stats = self.runner.stat_files(['.config/file', '.config/link', '.config/missing', '.config/dirlink/target',
                                        '.config/sub'])
        self.assertEqual({k: v['type'] for k, v in stats.items()},
                         {'.config/file': 'file', '.config/link': 'link', '.config/missing': 'missing',
                          '.config/dirlink/target': 'blocked', '.config/sub': 'dir'})
        self.assertTrue(self.runner.remove_file('.config/file'))
        self.assertFalse(self.runner.remove_file('.config/file'))
        self.assertTrue(self.runner.remove_file('.config/link'))
        self.assertEqual((self.outside / 'target').read_text(), 'keep')
        with self.assertRaises(BackupError):
            self.runner.remove_file('.config/sub')
        self.assertFalse(self.runner.remove_file('.config/nothere/x'))

    def test_relay_only_runs_podman(self):
        result = self.runner.run(['/usr/bin/python3', '-I', '-c', podman.FILE_HELPER, 'relay', '/bin/sh', '-c', 'id'],
                                 check=False)
        self.assertEqual(result.returncode, 8)

    def test_relay_accepts_only_the_fixed_podman_paths(self):
        # /usr/local/bin/podman is accepted (an upstream install, e.g. on an ARM64 test machine); a look-alike is not. No Podman
        # is ever started here: the helper's fixed tuple is checked as text, and the same acceptance code runs with
        # the paths renamed (p0dman) and the started program swapped for /bin/true, so no argv names podman (the
        # host-test guard refuses any) and the host's Podman is never run.
        self.assertIn("PODMANS = ('/usr/bin/podman', '/usr/local/bin/podman')\n", podman.FILE_HELPER)
        helper = podman.FILE_HELPER.replace("PODMANS = ('/usr/bin/podman', '/usr/local/bin/podman')",
                                            "PODMANS = ('/usr/bin/p0dman', '/usr/local/bin/p0dman')")
        helper = helper.replace('proc = subprocess.Popen(argv, stdout=subprocess.PIPE)',
                                "proc = subprocess.Popen(['/bin/true'], stdout=subprocess.PIPE)")
        self.assertEqual(helper.count('p0dman'), 2)
        self.assertIn("subprocess.Popen(['/bin/true']", helper)
        for argv0, refused in (('/usr/local/bin/p0dman', False), ('/usr/bin/p0dman', False),
                               ('/usr/local/bin/p0dmanx', True), ('/usr/local/sbin/p0dman', True), ('p0dman', True)):
            result = self.runner.run(['/usr/bin/python3', '-I', '-c', helper, 'relay', argv0, '--version'],
                                     check=False)
            self.assertEqual(result.returncode == 8, refused, argv0)
            if not refused:
                self.assertEqual(result.returncode, 0, argv0)

    def test_relay_copies_stream_and_exit_code(self):
        # Same relay logic with the allowed binary swapped for /bin/sh (podman is never run on the host).
        helper = podman.FILE_HELPER.replace("PODMANS = ('/usr/bin/podman', '/usr/local/bin/podman')",
                                            "PODMANS = ('/bin/sh',)")
        self.assertNotEqual(helper, podman.FILE_HELPER)
        with tempfile.TemporaryFile() as sink:
            result = self.runner.run(['/usr/bin/python3', '-I', '-c', helper, 'relay', '/bin/sh', '-c',
                                      'head -c 300000 /dev/zero; exit 3'], stdout=sink, check=False)
            sink.seek(0)
            self.assertEqual(len(sink.read()), 300000)
        self.assertEqual(result.returncode, 3)

    def test_environment_is_hermetic(self):
        os.environ['WOOWBK_LEAK_TEST'] = 'leak'
        try:
            out = self.runner.run(['/usr/bin/env']).stdout.decode()
        finally:
            del os.environ['WOOWBK_LEAK_TEST']
        names = sorted(line.split('=', 1)[0] for line in out.splitlines())
        self.assertEqual(names, ['DBUS_SESSION_BUS_ADDRESS', 'HOME', 'LANG', 'PATH', 'XDG_RUNTIME_DIR'])

    def test_timeout_kills_process_group(self):
        with self.assertRaises(BackupError) as caught:
            self.runner.run(['/bin/sh', '-c', 'sleep 30 & sleep 30'], timeout=1)
        self.assertIn('逾時', caught.exception.message)


class BoundedOutputTests(unittest.TestCase):
    """Review finding SEC-3: nothing a child prints can grow the root helper or fill the disk."""

    def test_capture_is_limited_and_the_child_is_killed(self):
        with self.assertRaises(podman.OutputLimitExceeded) as caught:
            podman.default_runner(['/bin/sh', '-c', 'head -c 100000000 /dev/zero; sleep 30'], max_output=1 << 20,
                                  timeout=20)
        self.assertFalse(caught.exception.to_file)

    def test_default_capture_limit(self):
        self.assertEqual(podman.MAX_CAPTURE, podman.MAX_FILE_BYTES + 64 * 1024)
        with self.assertRaises(podman.OutputLimitExceeded):
            podman.default_runner(['/bin/sh', '-c', f'head -c {podman.MAX_CAPTURE + 1} /dev/zero'], timeout=60)

    def test_file_output_has_a_byte_budget(self):
        with tempfile.TemporaryFile() as sink:
            with self.assertRaises(podman.OutputLimitExceeded) as caught:
                podman.default_runner(['/bin/sh', '-c', 'head -c 5000000 /dev/zero; sleep 30'], stdout=sink,
                                      max_output=1000000, timeout=20)
            self.assertTrue(caught.exception.to_file)
            sink.seek(0, os.SEEK_END)
            self.assertLessEqual(sink.tell(), 1000000 + podman.READ_CHUNK)
        with tempfile.TemporaryFile() as sink:
            result = podman.default_runner(['/bin/sh', '-c', 'head -c 3000000 /dev/zero'], stdout=sink, timeout=20)
            sink.seek(0, os.SEEK_END)
            self.assertEqual((result.returncode, result.stdout, sink.tell()), (0, None, 3000000))

    def test_stderr_keeps_only_a_tail(self):
        result = podman.default_runner(['/bin/sh', '-c', 'head -c 3000000 /dev/zero >&2; echo END >&2'], timeout=20)
        self.assertEqual(len(result.stderr), podman.STDERR_TAIL)
        self.assertTrue(result.stderr.endswith(b'END\n'))

    def test_large_stdin_and_stdout_do_not_deadlock(self):
        data = os.urandom(3 * 1024 * 1024)
        result = podman.default_runner(['/bin/cat'], input=data, timeout=30)
        self.assertEqual(result.stdout, data)

    def test_owner_runner_maps_overflows(self):
        runner = podman.OwnerRunner('appowner', runner=Recorder(exc=podman.OutputLimitExceeded(10, to_file=False)),
                                    user_lookup=owner_lookup())
        with self.assertRaises(BackupError) as caught:
            runner.podman('exec', 'db', 'psql', max_output=10)
        self.assertEqual(caught.exception.code, 'limit-exceeded')
        runner = podman.OwnerRunner('appowner', runner=Recorder(exc=podman.OutputLimitExceeded(10, to_file=True)),
                                    user_lookup=owner_lookup())
        with self.assertRaises(BackupError) as caught:
            runner.podman('exec', 'db', 'pg_dump', stdout=io.BytesIO(), max_output=10)
        self.assertEqual(caught.exception.code, 'insufficient-space')
        rec = Recorder()
        podman.OwnerRunner('appowner', runner=rec, user_lookup=owner_lookup()).podman('ps', max_output=7)
        self.assertEqual(rec.calls[0][1]['max_output'], 7)


SECRET_STDERR = (b'Error: initializing source docker://deploy:S3cr3tTokenValue@registry.example/app:1: pinging container '
                 b'registry registry.example: Get "https://registry.example/v2/": dial tcp 10.0.0.9:443: connect: '
                 b'connection refused\n')


class FailureReasonTests(unittest.TestCase):
    """X-PD-07: a failed command says why, in one fixed sentence per kind of failure; none of its own words are shown."""

    CASES = (
        (b'Error: writing blob: storage: no space left on device', 'no-space'),
        (b'Failed to connect to bus: No such file or directory', 'no-user-manager'),
        (b'Failed to start x.service: Unit x.service is masked.', 'unit-masked'),
        (b'Failed to start y.service: Unit y.service not found.', 'unit-missing'),
        (b'Job for z.service failed because the control process exited with error code.', 'unit-failed'),
        (b'psql: error: connection to server on socket "/run/postgresql/.s.PGSQL.5432" failed: FATAL:  the database '
         b'system is starting up', 'db-not-ready'),
        (b'psql: error: connection to server at "10.0.0.2", port 5432 failed: Connection refused', 'db-not-ready'),
        (b'psql: error: ... FATAL:  password authentication failed for user "odoo"', 'db-auth'),
        (b'psql: error: ... FATAL:  database "prod" does not exist', 'db-missing'),
        (b'psql: error: ... FATAL:  role "odoo" does not exist', 'role-missing'),
        (b'Error: copying system image: pull access denied, repository does not exist or may require authorization',
         'pull-denied'),
        (b'Error: initializing source docker://x:1: reading manifest 1 in x: manifest unknown', 'image-missing'),
        (b'Error: x: image not known', 'image-missing'),
        (b'Get "https://r/v2/": dial tcp: lookup r on 1.1.1.1:53: no such host', 'network'),
        (b'Error: no container with name or ID "woowbk-x" found: no such container', 'no-container'),
        (b'Error: creating container storage: the container name "x" is already in use by container abc', 'name-in-use'),
        (b'Error: mkdir /home/x/.local: permission denied', 'permission'),
        (b'fatal error: out of memory', 'memory'),
        (b'Error: cannot set up namespace using "/usr/bin/newuidmap": exit status 1', 'subid'),
        (b'Error: acquiring lock 0 for container: resource temporarily unavailable', 'storage-busy'),
        (b'Error: crun: creating cgroup directory failed', 'runtime'),
        (b'Error: executable file not found in $PATH: No such file or directory: OCI runtime attempted',
         'no-program'),
    )

    def test_every_kind_of_failure_is_told_by_its_own_words(self):
        for stderr, code in self.CASES:
            with self.subTest(code=code, stderr=stderr[:40]):
                found, sentence = podman.classify(stderr, 125)
                self.assertEqual(found, code)
                self.assertTrue(sentence.endswith('。') and not sentence.isascii(), sentence)
        self.assertEqual({code for _s, code in self.CASES if code} - {row[0] for row in podman.REASONS}, set())
        self.assertEqual({row[0] for row in podman.REASONS} - {code for _s, code in self.CASES}, set(),
                         'every kind in the table is tried once')

    def test_the_exit_code_tells_when_the_words_do_not(self):
        self.assertEqual(podman.classify(b'', 137)[0], 'memory')
        self.assertEqual(podman.classify(b'', 127)[0], 'no-program')
        self.assertEqual(podman.classify(b'', 126)[0], 'no-program')
        self.assertEqual(podman.classify(b'nothing known', 1), (None, ''))
        self.assertEqual(podman.classify(None, None), (None, ''))
        self.assertEqual(podman.classify('text instead of bytes: no space left on device', 1)[0], 'no-space')

    def test_the_specific_kind_wins_over_the_general_one(self):
        # a database that refuses a connection is "not ready", a registry that does is "network"
        self.assertEqual(podman.classify(b'psql: error: connection to server on socket failed: Connection refused')[0],
                         'db-not-ready')
        self.assertEqual(podman.classify(b'dial tcp 10.0.0.9:443: connect: connection refused')[0], 'network')
        self.assertEqual(podman.classify(b'pull access denied for x, repository does not exist')[0], 'pull-denied')
        self.assertEqual(podman.classify(b'Error: mkdir /home/x/.local: permission denied: unknown')[0], 'permission',
                         'a refusal of the file system is not a registry that refuses')

    def test_only_the_tail_of_a_huge_stderr_is_read(self):
        noise = b'x' * (podman.STDERR_TAIL * 2)
        self.assertEqual(podman.classify(b'no space left on device\n' + noise)[0], None)
        self.assertEqual(podman.classify(noise + b'no space left on device\n')[0], 'no-space')

    def runner(self, result):
        return podman.OwnerRunner('appowner', runner=Recorder(result=result), user_lookup=owner_lookup())

    def test_a_failed_command_says_why_and_never_in_the_commands_words(self):
        runner = self.runner(podman.Result(125, b'', SECRET_STDERR))
        with self.assertRaises(podman.CommandError) as caught:
            runner.podman('pull', 'registry.example/app:1')
        error = caught.exception
        self.assertEqual(error.reason, 'network')
        self.assertEqual(error.details['reason'], 'network')
        self.assertEqual(error.message, 'podman pull registry.example/app:1 執行失敗（結束碼 125）：連不上網路（映像倉庫沒有回應）。')
        shown = error.message + repr(error.details) + str(error)
        for word in ('S3cr3tTokenValue', 'deploy', '10.0.0.9', 'pinging'):
            self.assertNotIn(word, shown)
        self.assertEqual(error.stderr, SECRET_STDERR, 'the journal copy stays for the engineers')

    def test_data_in_the_commands_words_never_reaches_the_message(self):
        stderr = (b'ERROR:  duplicate key value violates unique constraint "users_email_key"\n'
                  b'DETAIL:  Key (email)=(boss@example.com) already exists.\nCommand was: INSERT INTO users VALUES '
                  b"('boss@example.com', 'hunter2-password');\nFATAL:  password authentication failed for user \"x\"")
        with self.assertRaises(podman.CommandError) as caught:
            self.runner(podman.Result(1, b'', stderr)).podman('exec', 'db', 'psql')
        shown = caught.exception.message + repr(caught.exception.details)
        self.assertIn('資料庫帳號或密碼和這台的設定不符', shown)
        for word in ('boss@example.com', 'hunter2', 'INSERT', 'users_email_key'):
            self.assertNotIn(word, shown)

    def test_an_unknown_failure_reads_as_before(self):
        with self.assertRaises(podman.CommandError) as caught:
            self.runner(podman.Result(3, b'', b'something new')).podman('volume', 'export', 'v')
        self.assertEqual(caught.exception.message, 'podman volume export v 執行失敗（結束碼 3）。')
        self.assertIsNone(caught.exception.reason)
        self.assertNotIn('reason', caught.exception.details)

    def test_the_reason_of_an_error_is_found_whoever_raised_it(self):
        # one of this runner (reason set), one that only carries a code in its details, one of another runner (only stderr)
        self.assertEqual(podman.reason_code(podman.CommandError('x', returncode=1, reason='network')), 'network')
        self.assertEqual(podman.reason_code(BackupError('job-failed', 'x', reason='timeout')), 'timeout')
        other = podman.CommandError('x', returncode=125, stderr=b'Error: write: no space left on device')
        self.assertIsNone(other.reason)
        self.assertEqual(podman.reason_code(other), 'no-space', 'what its stderr says')
        self.assertEqual(podman.reason_code(podman.CommandError('x', returncode=137)), 'memory', 'what its exit code says')
        for nothing in (BackupError('job-failed', 'x'), BackupError('job-failed', 'x', reason='some English sentence'),
                        podman.CommandError('x', returncode=1, stderr=b'something new'), ValueError('x')):
            self.assertIsNone(podman.reason_code(nothing), nothing)

    def test_a_timeout_says_what_to_do_and_a_command_that_checks_for_itself_gets_the_reason(self):
        runner = podman.OwnerRunner('appowner', runner=Recorder(exc=subprocess.TimeoutExpired('x', 1)),
                                    user_lookup=owner_lookup())
        with self.assertRaises(BackupError) as caught:
            runner.podman('exec', 'db', 'psql', timeout=7)
        self.assertIn('（7 秒）', caught.exception.message)
        self.assertIn('請稍後再試一次', caught.exception.message)
        self.assertEqual(caught.exception.details['reason'], 'timeout')
        result = podman.Result(125, b'', b'Error: no such image')
        self.assertEqual(podman.reason_of(result), 'image-missing')
        self.assertIsNone(podman.reason_of(podman.Result(0, b'', b'no such image')))
        self.assertIsNone(podman.reason_of(None))
        self.assertLessEqual(podman.RETRYABLE, {row[0] for row in podman.REASONS})


class ScaledLimitTests(unittest.TestCase):
    """X-PD-05 and X-PD-04: waits and limits grow with the data they are about; what a call had is the floor."""

    def test_a_wait_never_gets_shorter_and_grows_with_the_data(self):
        self.assertEqual(podman.scaled_timeout(600), 600)
        for none in (None, 0, -5, True, 'big', float('nan') * 0):
            self.assertEqual(podman.scaled_timeout(600, none), 600, none)
        self.assertEqual(podman.scaled_timeout(600, 1024), 600, 'a small app keeps the old value')
        gib = 1024 ** 3
        self.assertEqual(podman.scaled_timeout(600, 100 * gib, rate=gib), 700)
        self.assertGreater(podman.scaled_timeout(600, 100 * gib), podman.scaled_timeout(600, 10 * gib))
        self.assertEqual(podman.scaled_timeout(600, 1 << 60), podman.SCALE_TIMEOUT_CEILING, 'never more than a day')
        self.assertEqual(podman.scaled_timeout(2 * podman.SCALE_TIMEOUT_CEILING, 1 << 60), 2 * podman.SCALE_TIMEOUT_CEILING,
                         'a call that already waits longer than the ceiling keeps its own value')
        self.assertEqual(podman.scaled_timeout(600, 5, rate=0), 600)
        self.assertIsNone(podman.scaled_timeout(None, 10 ** 12), 'no wait at all stays no wait')
        self.assertEqual(podman.scaled_timeout(True, 10 ** 12), True)

    def test_an_output_limit_never_gets_smaller_and_has_a_ceiling(self):
        mib = 1024 * 1024
        self.assertEqual(podman.scaled_limit(4 * mib), 4 * mib)
        self.assertEqual(podman.scaled_limit(4 * mib, 1 * mib), 4 * mib)
        self.assertEqual(podman.scaled_limit(4 * mib, 100 * mib), 100 * mib)
        self.assertEqual(podman.scaled_limit(4 * mib, 100 * mib, ratio=2), 200 * mib)
        self.assertEqual(podman.scaled_limit(4 * mib, 1 << 60), podman.SCALE_OUTPUT_CEILING, 'a runaway is still stopped')
        self.assertEqual(podman.scaled_limit(4 * mib, None), 4 * mib)
        self.assertEqual(podman.scaled_limit(4 * mib, True), 4 * mib)


class LineStreamTests(unittest.TestCase):
    """X-PD-04: a listing of any length is read line by line, never held whole."""

    def test_lines_are_handed_over_as_they_arrive(self):
        got = []
        sink = podman.LineSink(got.append)
        for chunk in (b'one\ntw', b'o\n\nthree', b'\n', b'last without a newline'):
            self.assertEqual(sink.write(chunk), len(chunk))
        self.assertEqual(got, [b'one', b'two', b'', b'three'], 'the last line waits for its end')
        sink.close()
        self.assertEqual(got[-1], b'last without a newline')
        self.assertEqual((sink.lines, sink.total), (5, 37))
        sink.close()
        self.assertEqual(len(got), 5, 'closed twice: nothing again')
        self.assertIsNone(sink.flush())

    def test_however_the_stream_is_cut_the_lines_are_the_same(self):
        import random
        rnd = random.Random(20261125)
        for round_ in range(300):
            lines = [bytes(rnd.choice(b'abc \x00\xff\r') for _ in range(rnd.randint(0, 12))) for _ in range(rnd.randint(0, 25))]
            data = b'\n'.join(lines) + (b'\n' if rnd.random() < 0.5 and lines else b'')
            expected = data.split(b'\n')
            if expected and expected[-1] == b'':
                expected.pop()
            got = []
            sink = podman.LineSink(got.append)
            position = 0
            while position < len(data):
                step = rnd.randint(1, 9)
                sink.write(data[position:position + step])
                position += step
            sink.close()
            self.assertEqual(got, expected, (round_, data))
            self.assertEqual(sink.total, len(data))

    def test_the_memory_is_one_line_not_the_listing(self):
        count = []
        sink = podman.LineSink(count.append)
        row = b'x' * 99 + b'\n'
        for _ in range(60000):                 # 6 MB of rows in chunks that cut rows in half
            sink.write(row[:57])
            sink.write(row[57:])
        self.assertEqual(len(count), 60000)
        self.assertLess(len(sink._pending), 200)

    def test_a_runaway_is_stopped(self):
        sink = podman.LineSink(lambda _line: None, max_line=100, max_total=1000, what='podman exec')
        with self.assertRaises(BackupError) as caught:
            sink.write(b'x' * 101)                 # a line with no end
        self.assertEqual(caught.exception.code, 'limit-exceeded')
        self.assertIn('podman exec 的一行輸出超過上限', caught.exception.message)
        sink = podman.LineSink(lambda _line: None, max_line=100, max_total=1000)
        with self.assertRaises(BackupError):
            sink.write(b'x' * 101 + b'\n')         # a long line with its end
        sink = podman.LineSink(lambda _line: None, max_line=100, max_total=1000)
        with self.assertRaises(BackupError) as caught:
            for _ in range(20):
                sink.write(b'y' * 60 + b'\n')
        self.assertIn('輸出超過上限', caught.exception.message)

    def local(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return podman.OwnerRunner('appowner', runner=LocalRunner(), user_lookup=owner_lookup(tmp.name))

    def test_a_real_command_is_read_to_its_end_and_a_runaway_is_killed(self):
        got = []
        runner = self.local()
        result = runner.stream_lines(['/bin/sh', '-c', 'seq 1 200000'], got.append, timeout=60)
        self.assertEqual((result.returncode, result.stdout, len(got), got[-1]), (0, None, 200000, b'200000'))
        tail = []
        runner.stream_lines(['/bin/sh', '-c', 'printf "a\\nb"'], tail.append, timeout=60)
        self.assertEqual(tail, [b'a', b'b'], 'the last line has no newline: it is handed over when the command ends')
        started = time.monotonic()
        with self.assertRaises(BackupError) as caught:
            runner.stream_lines(['/bin/sh', '-c', 'head -c 50000000 /dev/zero; sleep 30'], got.append, timeout=60,
                                max_line=1 << 16)
        self.assertEqual(caught.exception.code, 'limit-exceeded')
        self.assertLess(time.monotonic() - started, 20, 'the command is killed, not waited for')

    def test_a_failing_command_still_says_why_and_the_caller_sees_the_lines_it_printed(self):
        got = []
        runner = self.local()
        with self.assertRaises(podman.CommandError) as caught:
            runner.stream_lines(['/bin/sh', '-c', 'echo row1; echo "no space left on device" >&2; exit 5'], got.append,
                                timeout=60)
        self.assertEqual((got, caught.exception.reason), ([b'row1'], 'no-space'))
        result = runner.stream_lines(['/bin/sh', '-c', 'echo a; exit 5'], got.append, check=False, timeout=60)
        self.assertEqual(result.returncode, 5)


class UserManagerTests(unittest.TestCase):
    """X-AD-01: an owner without a running user manager is given one (linger), and only the real runner can do that."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.run_dir = Path(self.tmp.name)
        outer = self

        class Runner(podman.OwnerRunner):
            runtime_dir = property(lambda self: str(outer.run_dir))

        self.runner = Runner('appowner', runner=Recorder(), user_lookup=owner_lookup())
        self.calls, self.notes, self.slept = [], [], []
        # Whatever the code under test decides, the real executor (a root command on this host) is never reached here.
        patcher = mock.patch.object(podman, 'default_runner', self.never_the_real_one)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.real_calls = []

    def never_the_real_one(self, argv, **kwargs):
        self.real_calls.append(argv)
        return podman.Result(1, None, b'refused by the test: the real executor must not run')

    def root(self, code=0, stderr=b'', start=True, exc=None):
        def run(argv, **kwargs):
            self.calls.append((argv, kwargs))
            if exc:
                raise exc
            if code == 0 and start:
                (self.run_dir / 'bus').write_text('')   # logind starts the manager once linger is on
            return podman.Result(code, None, stderr)
        return run

    def ensure(self, root, **kwargs):
        clock = iter(range(0, 1000))
        return self.runner.ensure_user_manager(log=self.notes.append, root_run=root, trusted=lambda _path: True,
                                               sleep=self.slept.append, clock=lambda: next(clock), **kwargs)

    def test_a_running_user_manager_is_left_alone(self):
        (self.run_dir / 'bus').write_text('')
        self.assertTrue(self.runner.user_manager_ready())
        self.assertFalse(self.ensure(self.root()))
        self.assertEqual((self.calls, self.notes), ([], []))

    def test_linger_is_enabled_as_root_with_a_fixed_command_and_the_manager_is_waited_for(self):
        self.assertFalse(self.runner.user_manager_ready())
        self.assertTrue(self.ensure(self.root()))
        argv, kwargs = self.calls[0]
        self.assertEqual(argv, ['/usr/bin/loginctl', 'enable-linger', 'appowner'])
        self.assertEqual((kwargs['cwd'], kwargs['env'], kwargs['timeout']), ('/', dict(podman.ROOT_ENV), 60))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(self.notes), 1)
        self.assertIn('loginctl enable-linger', self.notes[0])
        self.assertIn('會保留', self.notes[0])
        self.assertTrue(self.runner.user_manager_ready())
        self.assertFalse(self.ensure(self.root()), 'now it runs: nothing more is done')
        self.assertEqual(len(self.calls), 1)

    def test_the_manager_that_comes_up_a_moment_later_is_waited_for(self):
        state = {'polls': 0}

        def late(argv, **kwargs):
            self.calls.append(argv)
            return podman.Result(0, None, b'')

        def sleep(_seconds):
            state['polls'] += 1
            if state['polls'] == 3:
                (self.run_dir / 'bus').write_text('')

        self.assertTrue(self.runner.ensure_user_manager(root_run=late, trusted=lambda _p: True, sleep=sleep, wait=30))
        self.assertEqual(state['polls'], 3)

    def test_a_manager_that_does_not_come_up_stops_only_that_app_with_the_reason(self):
        with self.assertRaises(BackupError) as caught:
            self.ensure(self.root(start=False), wait=5)
        self.assertEqual((caught.exception.code, caught.exception.details['reason']), ('job-failed', 'no-user-manager'))
        self.assertIn('帳號 appowner', caught.exception.message)
        self.assertIn('5 秒', caught.exception.message)

    def test_a_loginctl_that_fails_is_told_with_the_fix_and_no_command_text(self):
        for code, stderr, words in ((1, b'Failed to enable linger: Access denied', '權限不足'), (5, b'weird', '結束碼 5')):
            with self.subTest(code=code), self.assertRaises(BackupError) as caught:
                self.ensure(self.root(code=code, stderr=stderr))
            self.assertIn(words, caught.exception.message)
            self.assertIn('loginctl enable-linger appowner', caught.exception.message)
            self.assertNotIn('Failed to enable', caught.exception.message)
        for exc in (subprocess.TimeoutExpired('loginctl', 60), OSError('gone')):
            with self.subTest(exc=type(exc).__name__), self.assertRaises(BackupError):
                self.ensure(self.root(exc=exc))

    def test_an_untrusted_loginctl_is_never_run(self):
        calls = []
        with self.assertRaises(BackupError) as caught:
            self.runner.ensure_user_manager(root_run=lambda *a, **k: calls.append(a), trusted=lambda _path: False)
        self.assertEqual(calls, [])
        self.assertIn('找不到可以信任的 loginctl', caught.exception.message)

    def test_the_real_executor_runs_the_fixed_command_with_a_sanitized_environment(self):
        # A stand-in program takes the place of loginctl (the path is a module constant): what the real executor is given.
        script = self.run_dir / 'fake-loginctl'
        script.write_text(f'#!/bin/sh\nprintf "%s\\n" "$0" "$@" "cwd=$(pwd)" > {self.run_dir}/seen\nenv >> {self.run_dir}/seen\n'
                          f': > {self.run_dir}/bus\n')
        script.chmod(0o755)
        with mock.patch.object(podman, 'LOGINCTL', str(script)):
            self.assertTrue(self.runner.ensure_user_manager(root_run=REAL_DEFAULT_RUNNER, trusted=lambda _path: True))
        seen = (self.run_dir / 'seen').read_text().splitlines()
        self.assertEqual(seen[:4], [str(script), 'enable-linger', 'appowner', 'cwd=/'])
        environment = {line.split('=', 1)[0] for line in seen[4:] if '=' in line}
        self.assertLessEqual(environment, {'PATH', 'LANG', 'LC_ALL', 'PWD', 'SHLVL', '_', 'OLDPWD'}, environment)
        self.assertTrue(self.runner.user_manager_ready())
        self.assertEqual(self.real_calls, [])

    def test_only_the_real_runner_acts_as_root(self):
        # a runner made with another executor (every test, every lab double) never touches the device
        self.assertFalse(self.runner.ensure_user_manager(trusted=lambda _path: True))
        self.assertFalse(self.runner.user_manager_ready())
        self.assertEqual(self.real_calls, [], 'no root command was tried')
        calls = []

        def fake_default(argv, **kwargs):
            calls.append(argv)
            return podman.Result(0, None, b'')

        outer = self

        class Real(podman.OwnerRunner):
            runtime_dir = property(lambda self: str(outer.run_dir))

        with mock.patch.object(podman, 'default_runner', fake_default):
            real = Real('appowner', user_lookup=owner_lookup())      # no executor given: the real one
            with self.assertRaises(BackupError):                    # nothing creates the socket here: it is waited for
                real.ensure_user_manager(trusted=lambda _path: True, wait=0)
        self.assertEqual(calls, [['/usr/bin/loginctl', 'enable-linger', 'appowner']])


if __name__ == '__main__':
    unittest.main()


class UnshareLocalRunner:
    """Runs owner commands as the current user, with `podman unshare` (and the relay in front of it) taken off: the
    directory helper and GNU tar then run for real against a temp HOME. As root (the test runner) owners are kept."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, *, input=None, stdout=None, timeout=None, cwd=None, env=None, max_output=None):
        assert argv[:4] == ['/usr/sbin/runuser', '-u', 'appowner', '--'], argv[:4]
        prefix, command = argv[4:11], list(argv[11:])
        self.calls.append(command)
        if command[:5] == [podman.PYTHON, '-I', '-c', podman.FILE_HELPER, 'relay']:
            command = command[5:]  # the relay only copies podman's stdout (tested above)
        assert command[:2] == [podman.PODMAN, 'unshare'], command[:2]
        return podman.default_runner(prefix + command[2:], input=input, stdout=stdout, timeout=timeout, cwd=cwd,
                                     env=env, max_output=max_output)


def tree(root):
    """{relative path: (type, mode, size, link target, content digest, mtime_ns, uid, gid)} below `root`."""
    import hashlib
    rows = {}
    for folder, dirs, files in os.walk(root):
        for name in dirs + files:
            path = Path(folder) / name
            st = os.lstat(path)
            kind = stat.S_IFMT(st.st_mode)
            content = hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(st.st_mode) else ''
            rows[str(path.relative_to(root))] = (kind, stat.S_IMODE(st.st_mode), st.st_size if stat.S_ISREG(st.st_mode) else 0,
                                                 os.readlink(path) if stat.S_ISLNK(st.st_mode) else '', content,
                                                 st.st_mtime_ns if not stat.S_ISLNK(st.st_mode) else 0, st.st_uid, st.st_gid)
    return rows


class DirHelperTests(unittest.TestCase):
    """Real execution of DIR_HELPER and GNU tar (podman unshare taken off), like FileHelperTests."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / 'home'
        self.home.mkdir()
        self.local = UnshareLocalRunner()
        self.runner = podman.OwnerRunner('appowner', runner=self.local, user_lookup=owner_lookup(str(self.home)))
        self.root = os.geteuid() == 0

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, rel='apps/data'):
        top = self.home / rel
        top.mkdir(parents=True)
        (top / 'pg').mkdir(mode=0o700)
        (top / 'pg' / 'PG_VERSION').write_text('16\n')
        os.chmod(top / 'pg' / 'PG_VERSION', 0o600)
        (top / 'www').mkdir()
        os.chmod(top / 'www', 0o2775)
        (top / 'www' / 'config.php').write_text('<?php\n')
        os.chmod(top / 'www' / 'config.php', 0o640)
        os.link(top / 'www' / 'config.php', top / 'www' / 'second-name.php')
        os.symlink('config.php', top / 'www' / 'rel-link')
        os.symlink('/etc/hostname', top / 'www' / 'abs-link')
        os.symlink('../../secrets.yaml', top / 'www' / 'escaping-link')
        os.mkfifo(top / 'fifo', 0o640)
        (top / ('L' * 200)).write_text('long name')
        (top / 'empty').mkdir(mode=0o750)
        os.utime(top / 'www' / 'config.php', ns=(1_700_000_000_123_456_789, 1_700_000_000_123_456_789))
        try:
            os.setxattr(top / 'pg' / 'PG_VERSION', 'user.woowbk', b'kept')
            self.xattrs = True
        except OSError:
            self.xattrs = False
        if self.root:  # container users (namespace ids) are kept as numeric owners
            os.chown(top / 'pg', 70, 70)
            os.chown(top / 'pg' / 'PG_VERSION', 70, 70)
            os.chown(top / 'www' / 'config.php', 33, 33)
            os.lchown(top / 'www' / 'rel-link', 0, 33)
        os.chmod(top, 0o750)
        os.utime(top, ns=(1_600_000_000_000_000_001, 1_600_000_000_000_000_001))
        return top

    def pack(self, rel):
        target = Path(self.tmp.name) / 'pack.tar'
        with open(target, 'wb') as out:
            self.runner.dir_pack(rel, stdout=out)
        return target

    def unpack(self, rel, token, source):
        from woowbackup import nested
        with nested.pipe_from(lambda out: nested.stream_dir(source, out)) as feed:
            return self.runner.dir_unpack(rel, token, input=feed)

    def test_round_trip_keeps_the_tree(self):
        top = self.build()
        before = tree(top)
        before_root = os.stat(top)
        packed = self.pack('apps/data')
        from woowbackup import nested
        report = nested.check_dir(packed)
        self.assertEqual(report.members, len(before) + 1, 'every entry plus the root')
        self.assertEqual(report.outside_links, 2)
        created = self.unpack('restored/deep/data', 'j20261113T020000Z-a1b2c3d4', packed)
        self.assertEqual(created, ['restored', 'restored/deep'])
        self.assertEqual(stat.S_IMODE(os.stat(self.home / 'restored').st_mode), 0o700)
        state = self.runner.dir_states(['restored/deep/data'])['restored/deep/data']
        self.assertEqual(state['type'], 'missing')
        self.assertEqual(state['siblings'], [{'kind': 'new', 'token': 'j20261113T020000Z-a1b2c3d4', 'type': 'dir'}])
        self.assertEqual(self.runner.dir_swap('restored/deep/data', 'j20261113T020000Z-a1b2c3d4', fresh=True),
                         {'replaced': False, 'removed_empty': False})
        restored = self.home / 'restored/deep/data'
        after = tree(restored)
        self.assertEqual(after, before)
        root = os.stat(restored)
        self.assertEqual((stat.S_IMODE(root.st_mode), root.st_mtime_ns, root.st_uid),
                         (0o750, before_root.st_mtime_ns, before_root.st_uid), 'the root entry sets the directory itself')
        self.assertEqual(os.stat(restored / 'www/config.php').st_ino, os.stat(restored / 'www/second-name.php').st_ino)
        self.assertTrue(stat.S_ISFIFO(os.lstat(restored / 'fifo').st_mode))
        if self.xattrs:
            self.assertEqual(os.getxattr(restored / 'pg' / 'PG_VERSION', 'user.woowbk'), b'kept')
        if self.root:
            self.assertEqual((after['pg'][6], after['www/config.php'][6], after['www/rel-link'][7]), (70, 33, 33))

    def test_inplace_swap_keeps_the_old_copy_until_dropped(self):
        top = self.build()
        packed = self.pack('apps/data')
        (top / 'added-later').write_text('new')
        self.unpack('apps/data', 'j1', packed)
        self.assertEqual(self.runner.dir_swap('apps/data', 'j1'), {'replaced': True, 'removed_empty': False})
        self.assertFalse((top / 'added-later').exists(), 'replaced as a whole, not merged')
        self.assertTrue((self.home / 'apps/data.woowbk-old-j1/added-later').exists())
        state = self.runner.dir_states(['apps/data'])['apps/data']
        self.assertEqual((state['type'], state['empty'], state['siblings']),
                         ('dir', False, [{'kind': 'old', 'token': 'j1', 'type': 'dir'}]))
        self.assertTrue(self.runner.dir_drop('apps/data', 'old', 'j1'))
        self.assertFalse(self.runner.dir_drop('apps/data', 'old', 'j1'), 'already gone')
        self.assertEqual(sorted(os.listdir(self.home / 'apps')), ['data'])

    def test_no_replace_fresh_conflicts_and_moving_back(self):
        top = self.build()
        packed = self.pack('apps/data')
        self.unpack('apps/data', 'j1', packed)
        with self.assertRaises(BackupError) as caught:  # fresh mode never replaces a non-empty directory
            self.runner.dir_swap('apps/data', 'j1', fresh=True)
        self.assertEqual(caught.exception.code, 'incompatible')
        os.mkdir(self.home / 'apps/data.woowbk-old-j1')
        with self.assertRaises(BackupError) as caught:  # renameat2(RENAME_NOREPLACE): an existing name stays
            self.runner.dir_swap('apps/data', 'j1')
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertTrue((top / 'pg').is_dir() and (self.home / 'apps/data.woowbk-new-j1').is_dir())
        with self.assertRaises(BackupError):  # the directory exists: nothing is moved back over it
            self.runner.dir_back('apps/data', 'j1')
        os.rmdir(self.home / 'apps/data.woowbk-old-j1')
        # A kill between the two renames: <dir> moved aside, the new copy not yet in place.
        os.rename(top, self.home / 'apps/data.woowbk-old-j1')
        self.runner.dir_back('apps/data', 'j1')
        self.assertTrue((top / 'pg').is_dir())
        self.assertTrue(self.runner.dir_drop('apps/data', 'new', 'j1'))
        empty = self.home / 'apps/empty'
        empty.mkdir()
        self.unpack('apps/empty', 'j2', packed)
        self.assertEqual(self.runner.dir_swap('apps/empty', 'j2', fresh=True), {'replaced': False, 'removed_empty': True})
        self.assertTrue((empty / 'pg').is_dir())

    def test_symlinks_on_the_path_are_refused(self):
        self.build()
        os.symlink(self.home / 'apps', self.home / 'linked')
        os.symlink(self.home / 'apps/data', self.home / 'apps/data-link')
        for rel in ('linked/data', 'apps/data-link'):
            with self.subTest(rel), self.assertRaises(BackupError) as caught:
                self.pack(rel)
            self.assertEqual(caught.exception.code, 'permission-denied')
            with self.assertRaises(BackupError):
                self.runner.dir_measure(rel)
        states = self.runner.dir_states(['linked/data', 'apps/data-link', 'apps/missing', 'nothing/here'])
        self.assertEqual({rel: row['type'] for rel, row in states.items()},
                         {'linked/data': 'blocked', 'apps/data-link': 'link', 'apps/missing': 'missing',
                          'nothing/here': 'missing'})
        with self.assertRaises(BackupError) as caught:
            self.pack('apps/missing')
        self.assertEqual(caught.exception.code, 'not-found')
        with self.assertRaises(BackupError):  # unpacking below a symlinked component is refused too
            self.unpack('linked/new', 'j1', self.pack('apps/data'))
        self.assertFalse((self.home / 'apps/new.woowbk-new-j1').exists())

    def test_drop_never_follows_a_symlink(self):
        self.build()
        outside = Path(self.tmp.name) / 'outside'
        outside.mkdir()
        (outside / 'keep').write_text('keep')
        os.symlink(outside, self.home / 'apps/data.woowbk-old-j9')
        with self.assertRaises(BackupError):
            self.runner.dir_drop('apps/data', 'old', 'j9')
        self.assertTrue((outside / 'keep').exists())
        inner = self.home / 'apps/data.woowbk-new-j9'
        inner.mkdir()
        os.symlink(outside, inner / 'link')
        self.assertTrue(self.runner.dir_drop('apps/data', 'new', 'j9'))
        self.assertTrue((outside / 'keep').exists(), 'rmtree removes the link, not its target')

    def test_measure_and_failed_unpack(self):
        top = self.build()
        info = self.runner.dir_measure('apps/data')
        expected = sum(row[2] for path, row in tree(top).items() if path != 'www/second-name.php')
        self.assertEqual((info['bytes'], info['members']), (expected, len(tree(top)) + 1))
        self.assertEqual((info['mount_root'], info['mounts'], info['more_mounts'], info['acls']), (False, [], 0, 0))
        self.assertEqual(self.runner.dir_mounts('apps/data'), {'mount_root': False, 'mounts': [], 'more_mounts': 0})
        garbage = Path(self.tmp.name) / 'garbage'
        garbage.write_bytes(b'not a tar' * 100)
        with open(garbage, 'rb') as feed, self.assertRaises(BackupError) as caught:
            self.runner.dir_unpack('apps/other', 'j1', input=feed)
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertFalse((self.home / 'apps/other.woowbk-new-j1').exists(), 'a failed extraction removes its copy')
        (self.home / 'apps/other.woowbk-new-j1').mkdir()
        with self.assertRaises(BackupError) as caught:
            self.unpack('apps/other', 'j1', self.pack('apps/data'))
        self.assertIn('旁已有同名的資料夾', caught.exception.message)

    def test_revert_moves_the_previous_content_back_without_a_copy(self):
        # Review M3: a rollback moves the failed restore's data aside and the content before it back (two renames).
        top = self.build()
        before = tree(top)
        packed = self.pack('apps/data')
        (top / 'added-later').write_text('pre-restore only')
        before_restore = tree(top)
        self.unpack('apps/data', 'j1', packed)
        self.runner.dir_swap('apps/data', 'j1')
        self.assertEqual(tree(top), before)
        self.assertEqual(self.runner.dir_revert('apps/data', 'j1', 'j1-rollback'), {'replaced': True})
        self.assertEqual(tree(top), before_restore, 'what the directory held before the restore')
        self.assertEqual(tree(self.home / 'apps/data.woowbk-old-j1-rollback'), before, "the failed restore's data")
        self.assertFalse((self.home / 'apps/data.woowbk-old-j1').exists())
        with self.assertRaises(BackupError) as caught:  # nothing to move back any more
            self.runner.dir_revert('apps/data', 'j1', 'j1-rollback')
        self.assertEqual(caught.exception.code, 'not-found')
        os.rename(top, self.home / 'apps/data.woowbk-old-j2')  # the directory is missing: only the move back
        self.assertEqual(self.runner.dir_revert('apps/data', 'j2', 'j2-rollback'), {'replaced': False})
        self.assertEqual(tree(top), before_restore)

    def test_an_old_copy_is_renamed_before_it_is_deleted(self):
        # Review L4: a deletion cut short leaves `-del-<token>`, never something that looks like content to keep.
        self.build()
        old = self.home / 'apps/data.woowbk-old-j3'
        (old / 'deep').mkdir(parents=True)
        (old / 'deep/file').write_text('old')
        stale = self.home / 'apps/data.woowbk-del-j3'
        stale.mkdir()
        (stale / 'rest').write_text('half deleted')
        state = self.runner.dir_states(['apps/data'], tokens=['j3'])['apps/data']
        self.assertEqual(state['siblings'], [{'kind': 'del', 'token': 'j3', 'type': 'dir'},
                                             {'kind': 'old', 'token': 'j3', 'type': 'dir'}])
        self.assertTrue(self.runner.dir_drop('apps/data', 'old', 'j3'))
        self.assertEqual(sorted(os.listdir(self.home / 'apps')), ['data'], 'the stale del copy went first')
        stale.mkdir()
        self.assertTrue(self.runner.dir_drop('apps/data', 'del', 'j3'))
        self.assertFalse(self.runner.dir_drop('apps/data', 'del', 'j3'), 'already gone')

    def test_state_always_lists_the_requested_tokens(self):
        # Review M4: with many older siblings the job's own were cut off by the cap and the recovery did nothing.
        self.build()
        apps = self.home / 'apps'
        for i in range(120):
            (apps / f'data.woowbk-old-a{i:03d}').mkdir()
        (apps / 'data.woowbk-old-zz-mine').mkdir()
        (apps / 'data.woowbk-new-zz-mine').mkdir()
        mine = self.runner.dir_states(['apps/data'], tokens=['zz-mine', 'zz-mine-rollback'])['apps/data']
        self.assertEqual(mine['siblings'][:2], [{'kind': 'new', 'token': 'zz-mine', 'type': 'dir'},
                                                {'kind': 'old', 'token': 'zz-mine', 'type': 'dir'}])
        self.assertEqual((len(mine['siblings']), mine['more']), (52, 70))
        plain = self.runner.dir_states(['apps/data'])['apps/data']
        self.assertEqual((len(plain['siblings']), plain['more']), (50, 72))
        self.assertEqual(plain['siblings'][0]['token'], 'a000', 'sorted, so the listing is stable')

    def test_state_reports_the_filesystem_of_each_directory(self):
        top = self.build()
        state = self.runner.dir_states(['apps/data', 'apps/missing'])
        self.assertEqual((state['apps/data']['dev'], state['apps/data']['mount']), (os.stat(top.parent).st_dev, False))
        self.assertGreater(state['apps/data']['free'], 0)
        self.assertEqual(state['apps/missing']['dev'], os.stat(top.parent).st_dev, 'the parent exists')
        self.assertEqual(self.runner.dir_states(['nothing/here'])['nothing/here']['dev'], None)

    def test_arguments_are_validated_before_anything_runs(self):
        for call in (lambda: self.runner.dir_states(['../x']), lambda: self.runner.dir_drop('a', 'old', '../x'),
                     lambda: self.runner.dir_swap('a', 'tok en'), lambda: self.runner.dir_back('/etc', 'j1'),
                     lambda: self.runner.dir_drop('a', 'everything', 'j1')):
            with self.assertRaises(BackupError):
                call()
        self.assertEqual(self.local.calls, [])


class DirArgvTests(unittest.TestCase):
    def setUp(self):
        self.rec = Recorder(podman.Result(0, b'{"replaced": true, "removed_empty": false}', b''))
        self.runner = podman.OwnerRunner('appowner', runner=self.rec, user_lookup=owner_lookup())

    def test_exact_argv(self):
        unshare = [podman.PODMAN, 'unshare', podman.PYTHON, '-I', '-c', podman.DIR_HELPER]
        with tempfile.TemporaryFile() as sink:
            self.runner.dir_pack('.local/share/app/html', stdout=sink, max_output=123)
        self.runner.dir_swap('homeassistant/config', 'j20261113T020000Z-a1b2c3d4')
        self.runner.dir_swap('homeassistant/config', 'j20261113T020000Z-a1b2c3d4-rollback', fresh=True)
        argvs = [call[0] for call in self.rec.calls]
        self.assertEqual(argvs[0], EXPECTED_PREFIX + [podman.PYTHON, '-I', '-c', podman.FILE_HELPER, 'relay', *unshare,
                                                      'pack', '.local/share/app/html'])
        self.assertEqual(self.rec.calls[0][1]['max_output'], 123)
        self.assertEqual(argvs[1], EXPECTED_PREFIX + unshare + ['swap', 'homeassistant/config',
                                                                'j20261113T020000Z-a1b2c3d4', 'inplace'])
        self.assertEqual(argvs[2][-2:], ['j20261113T020000Z-a1b2c3d4-rollback', 'fresh'])
        self.assertEqual(podman.describe(argvs[0][len(EXPECTED_PREFIX):]), 'owner-dir pack .local/share/app/html')
        self.assertEqual(podman.describe(argvs[1][len(EXPECTED_PREFIX):]), 'owner-dir swap homeassistant/config')

    def test_owner_controlled_answers_of_another_shape_are_errors(self):
        # Review M1: the helper runs in a namespace the owner controls (he can bind-mount over python3 there), so
        # its answers are untrusted; anything but the documented shape is a BackupError, never a TypeError.
        row = {'path': 'data', 'type': 'dir', 'empty': False, 'mount': False, 'dev': 1, 'free': 2, 'siblings': [],
               'more': 0}
        sibling = {'kind': 'old', 'token': 'j1', 'type': 'dir'}
        bad_states = [b'', b'\xff', b'[' * 50000 + b']' * 50000, b'{}', b'[]', json.dumps([row, row]),
                      json.dumps([{**row, 'path': 'other'}]), json.dumps([{**row, 'type': 'socket'}]),
                      json.dumps([{**row, 'empty': 0}]), json.dumps([{**row, 'more': -1}]),
                      json.dumps([{**row, 'extra': 1}]), json.dumps([{**row, 'siblings': [{**sibling, 'token': '../x'}]}]),
                      json.dumps([{**row, 'siblings': [{**sibling, 'kind': 'all'}]}]),
                      json.dumps([{**row, 'siblings': [sibling] * 65}]), json.dumps([{**row, 'dev': 'x'}])]
        calls = [(lambda: self.runner.dir_states(['data']), [s.encode() if isinstance(s, str) else s for s in bad_states]),
                 (lambda: self.runner.dir_swap('data', 'j1'), [b'[]', b'{"replaced": 1, "removed_empty": false}',
                                                               b'{"replaced": true}']),
                 (lambda: self.runner.dir_revert('data', 'j1', 'j1-rollback'), [b'{"replaced": "yes"}', b'null']),
                 (lambda: self.runner.dir_unpack('data/deep', 'j1', input=b''), [b'{"created": ["/etc"]}',
                                                                                 b'{"created": "data"}', b'{}']),
                 (lambda: self.runner.dir_measure('data'), [b'{"bytes": 1}', b'{"bytes": -1, "members": 1, "acls": 0, '
                                                            b'"mount_root": false, "mounts": [], "more_mounts": 0}']),
                 (lambda: self.runner.dir_mounts('data'), [b'{"mount_root": 0, "mounts": [], "more_mounts": 0}',
                                                           b'{"mount_root": false, "mounts": [1], "more_mounts": 0}'])]
        for call, answers in calls:
            for answer in answers:
                with self.subTest(answer=answer[:40]):
                    self.rec.result = podman.Result(0, answer, b'')
                    with self.assertRaises(BackupError) as caught:
                        call()
                    self.assertEqual(caught.exception.code, 'job-failed')
                    self.assertIn('結果格式不正確', caught.exception.message)
        self.rec.result = podman.Result(0, json.dumps([{**row, 'siblings': [sibling]}]).encode(), b'')
        self.assertEqual(self.runner.dir_states(['data'], tokens=['j1'])['data']['siblings'], [sibling])
        self.assertEqual(self.rec.calls[-1][0][-2:], ['j1', 'data'], 'the tokens come first')

    def test_error_mapping(self):
        cases = {3: ('not-found', '找不到主機資料夾 ~/data'), 4: ('permission-denied', '不是資料夾'),
                 12: ('incompatible', '是掛載點或其中有掛載點'),
                 9: ('job-failed', '旁已有同名的資料夾'), 10: ('incompatible', '不是空的資料夾'),
                 11: ('job-failed', '無法以擁有者身分替換主機資料夾 ~/data'), 125: ('job-failed', '結束碼 125')}
        for code, (error_code, needle) in cases.items():
            with self.subTest(code=code):
                self.rec.result = podman.Result(code, b'', b'exists: data.woowbk-old-j1\n')
                with self.assertRaises(BackupError) as caught:
                    self.runner.dir_swap('data', 'j1')
                self.assertEqual(caught.exception.code, error_code)
                self.assertIn(needle, caught.exception.message)
                self.assertNotIn('import', caught.exception.message, 'never the helper code')


class PodmanPathTests(unittest.TestCase):
    """The fixed podman path: /usr/bin/podman, else /usr/local/bin/podman (lane arm54-2, an ARM64 test machine)."""

    def test_helper_accepts_exactly_the_candidates(self):
        self.assertIn('PODMANS = %r' % (podman.PODMAN_PATHS,), podman.FILE_HELPER)
        self.assertEqual(podman.PODMAN_PATHS, ('/usr/bin/podman', '/usr/local/bin/podman'))

    def test_distribution_path_first(self):
        self.assertEqual(podman.find_podman(trusted=lambda p: True), '/usr/bin/podman')

    def test_local_bin_when_distribution_path_is_missing(self):
        self.assertEqual(podman.find_podman(trusted=lambda p: p == '/usr/local/bin/podman'), '/usr/local/bin/podman')

    def test_falls_back_to_distribution_path_when_none_is_trusted(self):
        self.assertEqual(podman.find_podman(trusted=lambda p: False), '/usr/bin/podman')

    def test_module_constant_is_a_candidate(self):
        self.assertIn(podman.PODMAN, podman.PODMAN_PATHS)

    def test_root_only_accepts_a_system_binary(self):
        self.assertTrue(podman.root_only('/usr/bin/env'))

    def test_root_only_refuses_missing_user_owned_writable_and_directories(self):
        self.assertFalse(podman.root_only('/nonexistent/podman'))
        self.assertFalse(podman.root_only('/usr/bin'))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'podman'
            path.write_bytes(b'#!/bin/sh\n')
            path.chmod(0o755)
            self.assertFalse(podman.root_only(str(path)))  # not root-owned (tests never run as root)
            link = Path(tmp) / 'link'
            link.symlink_to('/usr/bin/env')
            self.assertFalse(podman.root_only(str(link)))  # the link's own directory is user-owned

    def test_root_only_follows_a_root_owned_symlink_target(self):
        # /usr/bin/sh -> dash on Debian/Ubuntu: both directories root-owned.
        if os.path.islink('/usr/bin/sh'):
            self.assertTrue(podman.root_only('/usr/bin/sh'))
