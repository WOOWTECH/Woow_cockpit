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
