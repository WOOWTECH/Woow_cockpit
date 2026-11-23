"""Offline tests of omnigent_full_flow.py's pure parts: the team's dev-d lock rule (like `flock -w`, never while
emqx-main's waiting file exists), the committed-tree rule, fixed output labels and the embedded programs. Nothing here
reaches a device, labpodman or a secret."""
import fcntl
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


class LockTests(unittest.TestCase):
    def test_waits_for_the_waiting_file_and_a_holder(self):
        with tempfile.TemporaryDirectory() as directory:
            lock, waiting = Path(directory) / 'lock', Path(directory) / 'waiting'
            waiting.write_text('')
            holder = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(holder, fcntl.LOCK_EX)
            clock = {'t': 0}
            events = []

            def sleep(seconds):
                clock['t'] += seconds
                events.append(clock['t'])
                if clock['t'] == 10:
                    waiting.unlink()          # emqx-main started its run ...
                if clock['t'] == 20:
                    os.close(holder)          # ... and finished it
            fd, waited = flow.acquire(lock, waiting, 3600, sleep=sleep, clock=lambda: clock['t'])
            try:
                self.assertEqual(waited, 20)
                self.assertEqual(events, [5, 10, 15, 20])
            finally:
                os.close(fd)

    def test_gives_up_after_the_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            lock, waiting = Path(directory) / 'lock', Path(directory) / 'waiting'
            waiting.write_text('')
            clock = {'t': 0}

            def sleep(seconds):
                clock['t'] += seconds
            with self.assertRaises(flow.Failed):
                flow.acquire(lock, waiting, 30, sleep=sleep, clock=lambda: clock['t'])


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
        self.assertEqual(sorted(flow.FIXTURE_SHA), [('arm', 'enc'), ('arm', 'plain'), ('x86', 'enc'), ('x86', 'plain')])

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
