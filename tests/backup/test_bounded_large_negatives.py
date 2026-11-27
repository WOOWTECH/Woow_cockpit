"""Safety checks of the bounded large negatives harness; the real crypto runs are separate opt-in invocations."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from . import bounded_large_negatives as probe
from . import bounded_stream_window as window
from woowbackup.errors import BackupError


# probe.main() sets the process umask to 077, as the probe does when it runs as its own program. Give the unittest
# process its umask back after this module, so later modules (tests.e2e.test_dirs_fixture in the CI's discover order)
# run under the CI's umask and not under 077.
_UMASK = []


def setUpModule():
    _UMASK.append(os.umask(0o077))
    os.umask(_UMASK[0])


def tearDownModule():
    os.umask(_UMASK.pop())


MIB = window.MIB


def small_block(index):
    return hashlib.shake_256(f'unit:{index}'.encode()).digest(MIB)


class ChildrenWhileActive:
    """tool_children() stand-in: two fake children only while a fake consumer runs."""

    def __init__(self):
        self.active = False

    def __call__(self):
        return [101, 102] if self.active else []


class WindowSourceTests(unittest.TestCase):
    def test_reader_gets_exact_keystream_with_bounded_allocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = window.WindowSource(Path(tmp) / 'src.bin', 48, small_block, ahead=32 * MIB, behind=4 * MIB)
            try:
                self.assertEqual(os.stat(source.path).st_size, 48 * MIB)
                digest, done = hashlib.sha256(), 0
                with open(source.path, 'rb') as reader:
                    while chunk := reader.read(MIB):
                        digest.update(chunk)
                        done += len(chunk)
                        if done % (8 * MIB) == 0:
                            source.advance(done)
                self.assertEqual(digest.hexdigest(), window.keystream_sha256(48, small_block))
                self.assertLessEqual(source.max_allocated, (32 + 4 + 8 + 1) * MIB)
                self.assertLess(os.stat(source.path).st_blocks * 512, 48 * MIB)
                self.assertEqual(source.bytes_written, 48 * MIB)
            finally:
                source.close()

    def test_progress_past_the_written_window_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = window.WindowSource(Path(tmp) / 'src.bin', 80, small_block, ahead=32 * MIB)
            try:
                with self.assertRaisesRegex(RuntimeError, 'passed the written window'):
                    source.advance(33 * MIB)
            finally:
                source.close()

    def test_window_too_small_for_progress_step_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                window.WindowSource(Path(tmp) / 'src.bin', 8, small_block, ahead=8 * MIB)
            self.assertFalse((Path(tmp) / 'src.bin').exists())

    def test_output_puncher_keeps_logical_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'out.bin'
            puncher = window.OutputPuncher(path, behind=4 * MIB)
            puncher.advance(MIB)  # missing file: nothing to do
            with open(path, 'wb') as out:
                for index in range(40):
                    out.write(small_block(index))
                    out.flush()
                    puncher.advance((index + 1) * MIB)
            st = os.stat(path)
            self.assertEqual(st.st_size, 40 * MIB)
            self.assertLessEqual(st.st_blocks * 512, 6 * MIB)
            self.assertEqual(puncher.max_logical, 40 * MIB)
            self.assertEqual(puncher.punched, 36 * MIB)


class HarnessTests(unittest.TestCase):
    def run_main(self, argv):
        output = io.StringIO()
        with mock.patch('sys.argv', ['probe', *argv]), contextlib.redirect_stdout(output):
            code = probe.main()
        return code, json.loads(output.getvalue())

    def test_cli_bounds(self):
        for mib in ('127', '8194'):
            with mock.patch('sys.argv', ['probe', '--mib', mib]), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    probe.main()
            self.assertEqual(caught.exception.code, 2)

    def test_low_space_prevents_any_payload(self):
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(probe.resource, 'setrlimit'), \
                 mock.patch.object(probe.os, 'sched_setaffinity'), \
                 mock.patch.object(probe.SpaceGuard, 'free', return_value=probe.RESERVE + probe.MARGIN), \
                 mock.patch.object(probe.common, 'encryption_dependencies') as deps:
                code, report = self.run_main(['--mib', '8193', '--scratch-parent', root])
            self.assertEqual(code, 1)
            self.assertEqual(report['error_code'], 'insufficient-space')
            self.assertEqual(report['fixture_generations'], 0)
            self.assertEqual(report['commercial_acceptance'], 'not-complete')
            self.assertTrue(report['harness_removed_private_scratch_and_key'])
            deps.assert_not_called()
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_unexpected_success_or_wrong_code_is_failure(self):
        with self.assertRaisesRegex(RuntimeError, 'negative unexpectedly succeeded'):
            probe.expect_corrupt(lambda: None)

        def wrong():
            raise BackupError('wrong-key', 'x')
        with self.assertRaisesRegex(RuntimeError, 'unexpected refusal code'):
            probe.expect_corrupt(wrong)

    def fake_extract(self, children, *, remove, total, fail_at):
        def extract(path, ids, dest, *, progress=None, **_):
            target = Path(dest) / probe.ENTRY
            target.parent.mkdir(parents=True)
            children.active = True
            try:
                with open(target, 'wb') as out:
                    for done in range(8 * MIB, total + 1, 8 * MIB):
                        out.write(bytes(8 * MIB))
                        out.flush()
                        progress(done, total)
                        if done >= fail_at:
                            raise BackupError('corrupt-archive', 'x')
            except BaseException:
                if remove:
                    target.unlink()
                    os.rmdir(target.parent)
                    os.rmdir(target.parent.parent)
                    os.rmdir(target.parent.parent.parent)
                raise
            finally:
                children.active = False
        return extract

    def test_partial_output_left_by_engine_is_detected(self):
        children, total = ChildrenWhileActive(), 128 * MIB
        report = {}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'extract'
            with mock.patch.object(probe.archive, 'extract_archive',
                                   self.fake_extract(children, remove=False, total=total, fail_at=total)), \
                 mock.patch.object(probe, 'tool_children', children), \
                 mock.patch.object(probe, 'open_fds', return_value=0):
                with self.assertRaisesRegex(RuntimeError, 'engine left partial content'):
                    probe.tail_extract('t', None, [], root, total, lambda: None, report)
            case = report['cases']['t']
            self.assertFalse(case['engine_removed_partial_contents'])
            self.assertTrue(case['harness_removed_owned_root'])
            self.assertFalse(root.exists())

    def test_early_failure_is_not_late_tail(self):
        children, total = ChildrenWhileActive(), 256 * MIB
        report = {}
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(probe.archive, 'extract_archive',
                                   self.fake_extract(children, remove=True, total=total, fail_at=64 * MIB)), \
                 mock.patch.object(probe, 'tool_children', children), \
                 mock.patch.object(probe, 'open_fds', return_value=0):
                with self.assertRaisesRegex(RuntimeError, 'too early'):
                    probe.tail_extract('t', None, [], Path(tmp) / 'x', total, lambda: None, report)

    def test_real_job_cancel_reaches_consumer_as_flows_cancelled(self):
        children, total = ChildrenWhileActive(), 128 * MIB
        report = {}
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            guard = mock.Mock(free=mock.Mock(return_value=10 ** 12))
            with mock.patch.object(probe.archive, 'extract_archive',
                                   self.fake_extract(children, remove=True, total=total, fail_at=total + 1)), \
                 mock.patch.object(probe, 'tool_children', children), \
                 mock.patch.object(probe, 'open_fds', return_value=0):
                probe.cancel_extract(None, [], folder, total, lambda: None, guard, report)
            case = report['cases']['cancel-extract']
            self.assertEqual(case['status'], 'passed')
            self.assertEqual(case['exception'], 'flows.Cancelled')
            self.assertEqual(case['cancel_command_exit'], 0)
            self.assertTrue(case['cancel_command_response']['ok'])
            self.assertIn(case['cancel_command_response']['state'], ('cancelled', 'running'))
            self.assertTrue(case['cancel_request_recorded'])
            self.assertEqual(case['job_final_state'], 'cancelled')
            self.assertFalse(case['job_cancellable_after'])
            self.assertTrue(case['cancel_request_cleared'])
            self.assertEqual(case['cancel_requested_at_bytes'], 64 * MIB)
            self.assertEqual(case['max_progress_bytes'], 64 * MIB)
            self.assertFalse((folder / 'cancel-extract').exists())

    def test_cancel_command_that_records_nothing_fails_the_case(self):
        children, total = ChildrenWhileActive(), 128 * MIB
        report = {}
        refuse = "import sys\nsys.stdout.write('{\"ok\": false, \"error\": {\"code\": \"not-cancellable\"}}')\nsys.exit(1)\n"
        with tempfile.TemporaryDirectory() as tmp:
            guard = mock.Mock(free=mock.Mock(return_value=10 ** 12))
            with mock.patch.object(probe.archive, 'extract_archive',
                                   self.fake_extract(children, remove=True, total=total, fail_at=total + 1)), \
                 mock.patch.object(probe, 'tool_children', children), \
                 mock.patch.object(probe, 'open_fds', return_value=0), \
                 mock.patch.object(probe, 'CLI_SCRIPT', refuse):
                with self.assertRaisesRegex(RuntimeError, 'did not record a request'):
                    probe.cancel_extract(None, [], Path(tmp), total, lambda: None, guard, report)
            self.assertTrue(report['cases']['cancel-extract']['harness_removed_owned_root'])

    def test_unknown_case_name_is_rejected(self):
        with mock.patch('sys.argv', ['probe', '--mib', '128', '--cases', 'cancel-extract,bogus']), \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                probe.main()
        self.assertEqual(caught.exception.code, 2)

    def test_cancelled_consumer_that_finishes_is_failure(self):
        report = {}

        def finishes(path, ids, dest, *, progress=None, **_):
            return {}
        with tempfile.TemporaryDirectory() as tmp:
            guard = mock.Mock(free=mock.Mock(return_value=10 ** 12))
            with mock.patch.object(probe.archive, 'extract_archive', finishes):
                with self.assertRaisesRegex(RuntimeError, 'unexpectedly succeeded'):
                    probe.cancel_extract(None, [], Path(tmp), 128 * MIB, lambda: None, guard, report)
            self.assertTrue(report['cases']['cancel-extract']['harness_removed_owned_root'])


if __name__ == '__main__':
    unittest.main()
