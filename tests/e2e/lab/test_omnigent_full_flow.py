"""Offline tests of omnigent_full_flow.py's pure parts: the team's dev-d lock rule (like `flock -w`, never while
emqx-main's waiting file exists), the committed-tree rule, fixed output labels and the embedded programs. Nothing here
reaches a device, labpodman or a secret."""
import contextlib
import fcntl
import io
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('omnigent_full_flow', HERE / 'omnigent_full_flow.py')
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)


class ConfirmationGateTests(unittest.TestCase):
    def test_a_notice_is_read_but_a_new_confirmation_stops_the_real_import(self):
        flow.require_reviewed_check({'ok': True, 'importable': True, 'issues': [
            {'id': 'omnigent.version-unknown', 'level': 'notice'}]})
        with self.assertRaises(flow.Failed) as caught:
            flow.require_reviewed_check({'ok': True, 'importable': True, 'issues': [
                {'id': 'omnigent.skipped', 'level': 'confirm'}]})
        self.assertIn('omnigent.skipped', str(caught.exception))

    def test_refused_or_malformed_result_stops_the_real_import(self):
        for result in ({}, {'ok': False, 'importable': True, 'issues': []},
                       {'ok': True, 'importable': False, 'issues': []},
                       {'ok': True, 'importable': True},
                       {'ok': True, 'importable': True, 'issues': [{'id': 'odd'}]}):
            with self.subTest(result=result), self.assertRaises(flow.Failed):
                flow.require_reviewed_check(result)


class LockTests(unittest.TestCase):
    def test_waits_for_the_waiting_file_then_queues_on_the_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            lock, waiting = Path(directory) / 'lock', Path(directory) / 'waiting'
            waiting.write_text('')
            clock = {'t': 0}
            tries = []

            def sleep(seconds):
                clock['t'] += seconds
                if clock['t'] == 10:
                    waiting.unlink()          # emqx-main started its run

            def block(fd, seconds):
                tries.append(clock['t'])
                clock['t'] += seconds
                if len(tries) < 3:
                    return False              # emqx-main still holds the lock
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            fd, waited = flow.acquire(lock, waiting, 3600, sleep=sleep, clock=lambda: clock['t'], tick=30,
                                      block=block)
            try:
                self.assertEqual(tries, [10, 40, 70])
                self.assertEqual(waited, 100)
            finally:
                os.close(fd)

    def test_gives_the_lock_back_when_emqx_asks_meanwhile(self):
        with tempfile.TemporaryDirectory() as directory:
            lock, waiting = Path(directory) / 'lock', Path(directory) / 'waiting'
            clock = {'t': 0}
            held = []

            def sleep(seconds):
                clock['t'] += seconds
                if waiting.exists():
                    waiting.unlink()

            def block(fd, seconds):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                held.append(clock['t'])
                if len(held) == 1:
                    waiting.write_text('')    # emqx-main asked while this waiter got the lock
                return True
            fd, _waited = flow.acquire(lock, waiting, 3600, sleep=sleep, clock=lambda: clock['t'], block=block)
            try:
                self.assertEqual(len(held), 2)
                other = os.open(lock, os.O_RDWR)
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.close(other)
            finally:
                os.close(fd)

    def test_gives_up_after_the_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            lock, waiting = Path(directory) / 'lock', Path(directory) / 'waiting'
            clock = {'t': 0}

            def block(fd, seconds):
                clock['t'] += seconds
                return False
            with self.assertRaises(flow.Failed):
                flow.acquire(lock, waiting, 60, clock=lambda: clock['t'], tick=30, block=block)

    def test_the_real_blocking_wait_times_out_and_then_holds(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / 'lock'
            holder = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(holder, fcntl.LOCK_EX)
            fd = os.open(lock, os.O_RDWR)
            try:
                self.assertFalse(flow._block(fd, 1))
                os.close(holder)
                self.assertTrue(flow._block(fd, 1))
            finally:
                os.close(fd)


class TreeTests(unittest.TestCase):
    def test_only_the_evidence_folders_may_differ(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            (repo / 'tests/e2e/lab/evidence').mkdir(parents=True)
            (repo / 'tests/e2e/lab/evidence/a.json').write_text('{}')
            self.assertEqual(flow.clean_tree(repo), (True, []))
            (repo / 'engine.py').write_text('x')
            self.assertEqual(flow.clean_tree(repo), (False, ['engine.py']))


class OutputTests(unittest.TestCase):
    def test_labels_keep_only_the_fixed_vocabulary(self):
        self.assertEqual(flow.label('check x86-enc/omnigent: ok「中文」\n'), 'check x86-enc/omnigent: ok')
        self.assertEqual(flow.label(''), 'check')

    def test_the_fixture_paths_and_digests(self):
        self.assertEqual(flow.fixture_path('arm', 'enc').name, 'woow-b1-arm-enc.tar')
        self.assertEqual(sorted(flow.FIXTURE_SHA), [('arm', 'enc'), ('arm', 'plain'), ('x86', 'active'), ('x86', 'enc'),
                                                    ('x86', 'plain')])

    def test_the_active_task_fixture_is_the_lab_made_x86_copy(self):
        self.assertEqual(flow.fixture_path('x86', 'active'), flow.ACTIVE_FIXTURE)
        self.assertEqual(flow.ACTIVE_FIXTURE.name, 'woow-b1-x86-plain-active-task.tar')
        self.assertIn('20261119-b1-lab', flow.ACTIVE_FIXTURE.parts)   # never one of the real HA files' folders
        with self.assertRaises(flow.Failed):
            flow.fixture_path('arm', 'active')
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                flow.main(['--run', '--arch', 'arm', '--form', 'active', '--test-mode'])

    def test_the_embedded_programs_compile_and_print_no_value(self):
        flow.self_check()
        for program in (flow.STATE_PROBE, flow.SPACE):
            self.assertNotIn('--showsecret', program)
        self.assertIn('sha256', flow.STATE_PROBE)

    def test_the_leak_scan_reads_only_roots_this_engine_keeps(self):
        # x86-plain attempt 1: the b1 driver's scan required index.json, which this engine does not write.
        self.assertNotIn('index.json', flow.LEAKS)
        for root in ('/var/lib/woowtech-backup/jobs', '/var/lib/woowtech-backup/requests.json', 'journalctl'):
            self.assertIn(root, flow.LEAKS)
        self.assertNotIn('print(json.dumps(secrets', flow.LEAKS)


if __name__ == '__main__':
    unittest.main()
