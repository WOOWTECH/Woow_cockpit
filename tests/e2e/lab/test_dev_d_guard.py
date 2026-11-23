"""Offline tests of dev_d_guard (services-a-2): clean-tree check, isolation record, the team's dev-d lock.
No device, no real lock, no credential."""
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import dev_d_guard as guard  # noqa: E402


def git_repo(directory):
    subprocess.run(['git', 'init', '-q', directory], check=True)
    for key, value in (('user.email', 'lab@example.invalid'), ('user.name', 'lab')):
        subprocess.run(['git', '-C', directory, 'config', key, value], check=True)
    Path(directory, 'backup-engine').mkdir()
    Path(directory, 'backup-engine', 'x.py').write_text('a = 1\n')
    Path(directory, 'tests/e2e/lab/evidence').mkdir(parents=True)
    Path(directory, 'tests/e2e/lab/run.py').write_text('b = 1\n')
    subprocess.run(['git', '-C', directory, 'add', '-A'], check=True)
    subprocess.run(['git', '-C', directory, 'commit', '-qm', 'init'], check=True)


class CleanTreeTest(unittest.TestCase):
    def test_clean_modified_untracked_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            git_repo(directory)
            self.assertEqual(guard.clean_tree(directory), (True, []))
            self.assertRegex(guard.head(directory), r'^[0-9a-f]{40}$')
            # a pending evidence record of an earlier attempt does not block the next run
            Path(directory, 'tests/e2e/lab/evidence/attempt1.json').write_text('{}\n')
            self.assertEqual(guard.clean_tree(directory), (True, []))
            # an untracked harness file or a modified engine file does
            Path(directory, 'tests/e2e/lab/new.py').write_text('c = 1\n')
            self.assertEqual(guard.clean_tree(directory), (False, ['tests/e2e/lab/new.py']))
            os.unlink(Path(directory, 'tests/e2e/lab/new.py'))
            Path(directory, 'backup-engine', 'x.py').write_text('a = 2\n')
            self.assertEqual(guard.clean_tree(directory), (False, ['backup-engine/x.py']))

    def test_rename_names_both_sides(self):
        with tempfile.TemporaryDirectory() as directory:
            git_repo(directory)
            subprocess.run(['git', '-C', directory, 'mv', 'backup-engine/x.py', 'backup-engine/y.py'], check=True)
            clean, dirty = guard.clean_tree(directory)
            self.assertFalse(clean)
            self.assertEqual(sorted(dirty), ['backup-engine/x.py', 'backup-engine/y.py'])

    def test_git_failure_raises(self):
        fake = lambda *a, **k: SimpleNamespace(returncode=128, stdout=b'', stderr=b'fatal')
        with self.assertRaisesRegex(guard.GuardError, 'git_status_failed'):
            guard.clean_tree('/nonexistent', run=fake)


class IsolationTest(unittest.TestCase):
    def test_only_the_exact_line_passes(self):
        good = lambda *a, **k: SimpleNamespace(returncode=0, stdout=b'dev-d isolation: true none {}\n')
        self.assertEqual(guard.verify_isolation('owner.sh', run=good), 'dev-d isolation: true none {}')
        for rc, text in ((0, b'dev-d isolation: true bridge {}\n'), (1, b'dev-d isolation: true none {}\n'),
                         (0, b''), (0, b'dev-d isolation: true none {}\nextra\n')):
            bad = lambda *a, rc=rc, text=text, **k: SimpleNamespace(returncode=rc, stdout=text)
            with self.assertRaisesRegex(guard.GuardError, 'dev_d_isolation_failed'):
                guard.verify_isolation('owner.sh', run=bad)


class LockTest(unittest.TestCase):
    def test_acquire_free_lock_and_release(self):
        with tempfile.TemporaryDirectory() as directory:
            lock, waiting = Path(directory, 'lock'), Path(directory, 'waiting')
            fd, waited = guard.acquire(lock, waiting, 5, holds=lambda _l: False)
            self.assertEqual(waited, 0)
            other = os.open(lock, os.O_RDONLY)
            with self.assertRaises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.close(fd)
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.close(other)

    def test_times_out_while_held(self):
        with tempfile.TemporaryDirectory() as directory:
            lock, waiting = Path(directory, 'lock'), Path(directory, 'waiting')
            lock.write_text('')
            holder = os.open(lock, os.O_RDONLY)
            fcntl.flock(holder, fcntl.LOCK_EX)
            try:
                started = time.monotonic()
                with self.assertRaisesRegex(guard.GuardError, 'dev_d_lock_timeout'):
                    guard.acquire(lock, waiting, 0, holds=lambda _l: False)
                self.assertLess(time.monotonic() - started, 5)
            finally:
                os.close(holder)

    def test_yields_to_a_waiting_emqx_main_and_ignores_a_stale_file(self):
        with tempfile.TemporaryDirectory() as directory:
            lock, waiting = Path(directory, 'lock'), Path(directory, 'waiting')
            waiting.write_text('')
            sleeps = []

            def sleep(seconds):
                sleeps.append(seconds)
                if len(sleeps) == 3:
                    os.unlink(waiting)   # emqx-main took its turn and removed the file

            fd, _waited = guard.acquire(lock, waiting, 60, holds=lambda _l: False, sleep=sleep)
            os.close(fd)
            self.assertEqual(sleeps, [5, 5, 5])
            # a waiting file seen while emqx-main itself holds the lock is stale: no yielding for it afterwards
            waiting.write_text('')
            calls = []
            fd, _waited = guard.acquire(lock, waiting, 60, holds=lambda _l: calls.append(1) or len(calls) == 1,
                                        sleep=lambda s: self.fail('must not wait for a stale file'))
            os.close(fd)

    def test_refuses_a_lock_file_of_someone_else_or_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory, 'real')
            real.write_text('')
            link = Path(directory, 'link')
            link.symlink_to(real)
            with self.assertRaises(OSError):
                guard.acquire(link, Path(directory, 'waiting'), 1, holds=lambda _l: False)
            os.link(real, Path(directory, 'hard'))
            with self.assertRaisesRegex(guard.GuardError, 'unsafe_dev_d_lock_file'):
                guard.acquire(real, Path(directory, 'waiting'), 1, holds=lambda _l: False)

    def test_emqx_main_holder_detection_reads_fdinfo(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory, 'lock')
            lock.write_text('')
            proc = Path(directory, 'proc')
            for pid, cmd, locked in (('11', b'bash\0run_emqx_real_owner.sh\0--x\0', True),
                                     ('12', b'python3\0other.py\0', True)):
                (proc / pid / 'fd').mkdir(parents=True)
                (proc / pid / 'fdinfo').mkdir()
                (proc / pid / 'cmdline').write_bytes(cmd)
                os.symlink(str(lock), proc / pid / 'fd' / '9')
                (proc / pid / 'fdinfo' / '9').write_text('pos:\t0\nlock:\t1: FLOCK  ADVISORY  WRITE 1 00:00:1 0 EOF\n'
                                                         if locked else 'pos:\t0\n')
            self.assertTrue(guard.emqx_main_holds_lock(lock, proc))
            (proc / '11' / 'fdinfo' / '9').write_text('pos:\t0\n')   # open, not holding: a busy retry
            self.assertFalse(guard.emqx_main_holds_lock(lock, proc))


if __name__ == '__main__':
    unittest.main()
