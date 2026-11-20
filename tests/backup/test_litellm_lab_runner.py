"""Real child process checks for the isolated LiteLLM harness runner; no lab access."""
import importlib.util
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from woowbackup.errors import BackupError

SCRIPT = Path(__file__).resolve().parents[1] / 'e2e/lab/litellm_version_candidate.py'
spec = importlib.util.spec_from_file_location('litellm_lab_runner', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LabRunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.child = Path(self.directory.name) / 'child'
        self.child.write_text('''#!/usr/bin/python3
import os, sys, time
mode = sys.argv[-1]
if mode == 'overflow':
    os.write(1, b'x' * 16384)
    time.sleep(30)
elif mode == 'boundary':
    os.write(1, b'x' * 4096)
elif mode == 'timeout':
    time.sleep(30)
elif mode == 'stderr':
    os.write(2, b'secret' * 500000)
    os.write(1, b'ok')
elif mode == 'fail':
    os.write(2, b'private-child-error')
    sys.exit(7)
else:
    data = sys.stdin.buffer.read()
    sys.stdout.buffer.write(data)
''')
        self.child.chmod(0o700)
        patcher = mock.patch.object(module, 'LABPODMAN', str(self.child))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.runner = module.DevDRunner()

    def test_real_child_overflow_is_bounded_and_sanitized(self):
        start = time.monotonic()
        with self.assertRaises(BackupError) as caught:
            self.runner.podman('overflow', timeout=10, max_output=128)
        self.assertEqual(caught.exception.code, 'limit-exceeded')
        self.assertLess(time.monotonic() - start, 5)
        self.assertNotIn('xxxx', str(caught.exception))

    def test_exact_reader_capture_boundary(self):
        result = self.runner.podman('boundary', timeout=10, max_output=4096)
        self.assertEqual(len(result.stdout), 4096)
        with self.assertRaises(BackupError) as caught:
            self.runner.podman('boundary', timeout=10, max_output=4095)
        self.assertEqual(caught.exception.code, 'limit-exceeded')

    def test_real_child_timeout_is_sanitized(self):
        start = time.monotonic()
        with self.assertRaises(BackupError) as caught:
            self.runner.podman('timeout', timeout=0.3, max_output=128)
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertLess(time.monotonic() - start, 5)

    def test_stderr_and_failures_are_not_returned(self):
        result = self.runner.podman('stderr', timeout=10, max_output=16)
        self.assertEqual((result.stdout, result.stderr), (b'ok', b''))
        result = self.runner.podman('fail', timeout=10, check=False)
        self.assertEqual((result.returncode, result.stderr), (7, b''))
        with self.assertRaises(BackupError) as caught:
            self.runner.podman('fail', timeout=10)
        self.assertNotIn('private-child-error', str(caught.exception))

    def test_input_and_file_output_are_forwarded_and_bounded(self):
        with tempfile.TemporaryFile() as output:
            result = self.runner.podman('echo', input=b'hello', stdout=output, max_output=5, timeout=10)
            self.assertIsNone(result.stdout)
            output.seek(0)
            self.assertEqual(output.read(), b'hello')
        with tempfile.TemporaryFile() as output, self.assertRaises(BackupError) as caught:
            self.runner.podman('echo', input=b'hello', stdout=output, max_output=4, timeout=10)
        self.assertEqual(caught.exception.code, 'limit-exceeded')

    def test_abort_is_forwarded(self):
        cancellation = BackupError('job-failed', 'cancelled')
        with self.assertRaises(BackupError) as caught:
            self.runner.podman('timeout', timeout=10, abort=lambda: cancellation)
        self.assertIs(caught.exception, cancellation)


if __name__ == '__main__':
    unittest.main()
