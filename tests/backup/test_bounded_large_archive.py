"""Safety checks of the opt-in large archive harness; never generate large data."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from . import bounded_large_archive as probe


class HarnessSafetyTests(unittest.TestCase):
    def test_refuses_low_space_before_writing_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as root:
            output = io.StringIO()
            with mock.patch('sys.argv', ['probe', '--mib', '1', '--scratch-parent', root]), \
                 mock.patch.object(probe.resource, 'setrlimit'), \
                 mock.patch.object(probe.os, 'sched_setaffinity'), \
                 mock.patch.object(probe.SpaceGuard, 'free', return_value=probe.RESERVE), \
                 mock.patch.object(probe.archive, 'write_archive') as write, \
                 contextlib.redirect_stdout(output):
                self.assertEqual(probe.main(), 1)
            report = json.loads(output.getvalue())
            self.assertEqual(report['status'], 'failed')
            self.assertEqual(report['error_type'], 'BackupError')
            self.assertTrue(report['temporary_payloads_removed'])
            self.assertEqual(list(Path(root).iterdir()), [])
            write.assert_not_called()

    def test_cli_refuses_more_than_two_gib(self):
        with mock.patch('sys.argv', ['probe', '--mib', '2049']), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                probe.main()
        self.assertEqual(caught.exception.code, 2)

    def run_isolated_failure(self, setup):
        # Resource limits/signals/affinity must stay confined to a child process.
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as root:
            code = ('import sys, os\nfrom pathlib import Path\nfrom unittest import mock\n'
                    'from tests.backup import bounded_large_archive as p\n'
                    f'sys.argv = ["probe", "--profile", "compressible-sequential", "--mib", "8", '
                    f'"--scratch-parent", {root!r}]\n' + setup + '\nsys.exit(p.main())\n')
            result = subprocess.run([sys.executable, '-c', code], cwd=probe.ROOT,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 1, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['status'], 'failed')
            self.assertTrue(report['temporary_payloads_removed'])
            self.assertEqual(list(Path(root).iterdir()), [])
            return report

    def test_real_archive_file_cap_aborts_and_cleans(self):
        report = self.run_isolated_failure(
            'p.ARCHIVE_CAP = 32768\n'
            'p.payload_block = lambda *args: os.urandom(1024**2)')
        self.assertIn('source_sha256', report)  # Generation completed before cap was applied.
        self.assertNotIn('archive_sha256', report)
        self.assertIn(report['error_type'], ('BackupError', 'RuntimeError'))

    def test_verification_failure_prevents_source_release_and_extraction(self):
        report = self.run_isolated_failure(
            'def fail_verify(path, *args, **kwargs):\n'
            '    assert (Path(path).parent / "source.bin").is_file()\n'
            '    raise RuntimeError("injected verification failure")\n'
            'p.archive.verify_archive = fail_verify\n'
            'p.archive.extract_archive = mock.Mock(side_effect=AssertionError("must not extract"))')
        self.assertEqual(report['error'], 'injected verification failure')
        self.assertNotIn('source_removed_before_extract', report)

    def test_runtime_space_loss_aborts_and_cleans(self):
        report = self.run_isolated_failure(
            'original_free = p.SpaceGuard.free\n'
            'def falling_free(self):\n'
            '    if any((Path(f) / "source.bin").exists() for f in self.folders):\n'
            '        return p.RESERVE\n'
            '    return original_free(self)\n'
            'p.SpaceGuard.free = falling_free')
        self.assertEqual(report['error_type'], 'BackupError')
        self.assertNotIn('archive_bytes', report)

    def test_sequential_cli_refuses_above_8193_mib(self):
        with mock.patch('sys.argv', ['probe', '--profile', 'compressible-sequential', '--mib', '8194']), \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                probe.main()
        self.assertEqual(caught.exception.code, 2)
