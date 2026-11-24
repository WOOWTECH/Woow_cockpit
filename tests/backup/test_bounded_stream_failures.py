"""Small safety checks; real crypto negative smoke is a separate opt-in invocation."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from . import bounded_stream_failures as probe


# probe.main() sets the process umask to 077, as the probe does when it runs as its own program. Give the unittest
# process its umask back after this module, so later modules (tests.e2e.test_dirs_fixture in the CI's discover order)
# run under the CI's umask and not under 077.
_UMASK = []


def setUpModule():
    _UMASK.append(os.umask(0o077))
    os.umask(_UMASK[0])


def tearDownModule():
    os.umask(_UMASK.pop())


class FailureHarnessTests(unittest.TestCase):
    def test_rejects_above_two_gib(self):
        with mock.patch('sys.argv', ['probe', '--mib', '2049']), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                probe.main()
        self.assertEqual(caught.exception.code, 2)

    def test_low_space_prevents_fixture_generation(self):
        with tempfile.TemporaryDirectory() as root:
            output = io.StringIO()
            with mock.patch('sys.argv', ['probe', '--mib', '128', '--scratch-parent', root]), \
                 mock.patch.object(probe.resource, 'setrlimit'), \
                 mock.patch.object(probe.os, 'sched_setaffinity'), \
                 mock.patch.object(probe.SpaceGuard, 'free', return_value=probe.RESERVE), \
                 mock.patch.object(probe.common, 'encryption_dependencies') as deps, \
                 contextlib.redirect_stdout(output):
                self.assertEqual(probe.main(), 1)
            report = json.loads(output.getvalue())
            self.assertEqual(report['error_code'], 'insufficient-space')
            self.assertEqual(report['fixture_generations'], 0)
            self.assertTrue(report['harness_removed_private_scratch_and_key'])
            deps.assert_not_called()
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_harness_cleanup_is_not_misattributed_to_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'extract'
            result = {}
            def leave_partial(path, ids, dest, *, limits, progress):
                (dest / 'payload.bin').write_bytes(b'partial')
                progress(8 * probe.MIB, 16 * probe.MIB)  # propagates caller cancellation
            with mock.patch.object(probe.archive, 'extract_archive', side_effect=leave_partial), \
                 mock.patch.object(probe, 'tool_children', return_value=[]):
                with self.assertRaisesRegex(RuntimeError, 'engine left partial content'):
                    probe.run_case(None, [], root, 'payload.bin', 16 * probe.MIB,
                                   'cancel-extract', lambda: None, result)
            self.assertTrue(result['same_cancellation_instance'])
            self.assertFalse(result['engine_removed_partial_contents'])
            self.assertEqual(result['remaining_paths_before_harness_cleanup'], 1)
            self.assertTrue(result['root_exists_before_harness_cleanup'])
            self.assertTrue(result['harness_removed_owned_root'])
            self.assertFalse(root.exists())

    def test_unexpected_success_is_failure(self):
        with mock.patch.object(probe.archive, 'verify_archive', return_value={}):
            with self.assertRaisesRegex(RuntimeError, 'negative unexpectedly succeeded'):
                probe.run_case(None, [], Path('/unused'), 'payload.bin', 128 * probe.MIB,
                               'corrupt-verify', lambda: None)
