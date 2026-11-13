"""OwnerRunner: exact runuser/env prefix, error mapping, and the owner-side file helper.

The FILE_HELPER snippet is executed for real (as the current user, with HOME pointing at a temp
home) to prove the O_NOFOLLOW component walk, atomic writes and modes.
"""
import io
import os
import stat
import subprocess
import tempfile
import types
import unittest
from pathlib import Path

from woowbackup import podman
from woowbackup.errors import BackupError

OWNER = types.SimpleNamespace(pw_name='appowner', pw_uid=1001, pw_gid=1001, pw_dir='/home/appowner')
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

    def test_relay_copies_stream_and_exit_code(self):
        # Same relay logic with the allowed binary swapped for /bin/sh (podman is never run on the host).
        helper = podman.FILE_HELPER.replace("argv[0] != '/usr/bin/podman'", "argv[0] != '/bin/sh'")
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
        size, members = self.runner.dir_measure('apps/data')
        expected = sum(row[2] for path, row in tree(top).items() if path != 'www/second-name.php')
        self.assertEqual((size, members), (expected, len(tree(top)) + 1))
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

    def test_error_mapping(self):
        cases = {3: ('not-found', '找不到主機資料夾 ~/data'), 4: ('permission-denied', '不是資料夾'),
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
