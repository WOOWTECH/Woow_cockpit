"""Offline safety checks for the code-server real-flow harness; no device access."""
import importlib.util
from pathlib import Path
import sys
import unittest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('codeserver_full_flow', HERE / 'codeserver_full_flow.py')
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)


class ConfirmationGateTests(unittest.TestCase):
    def test_reviewed_notices_can_continue(self):
        flow.require_reviewed_check({'ok': True, 'importable': True, 'blockers': [], 'issues': [
            {'id': 'codeserver.no-share', 'level': 'notice'}]})

    def test_new_confirmation_stops_before_import(self):
        with self.assertRaises(flow.Failed) as caught:
            flow.require_reviewed_check({'ok': True, 'importable': True, 'blockers': [], 'issues': [
                {'id': 'codeserver.no-share', 'level': 'notice'},
                {'id': 'codeserver.databases-unchecked', 'level': 'confirm'}]})
        self.assertIn('codeserver.databases-unchecked', str(caught.exception))

    def test_refused_or_malformed_checks_stop(self):
        good = {'ok': True, 'importable': True, 'blockers': [], 'issues': []}
        bad = [
            good | {'ok': False},
            good | {'importable': False},
            good | {'blockers': ['unreadable']},
            good | {'issues': None},
            good | {'issues': [None]},
            good | {'issues': [{'level': 'notice'}]},
            good | {'issues': [{'id': 'new', 'level': 'unknown'}]},
            good | {'issues': [{'id': 'codeserver.no-data', 'level': 'stop'}]},
        ]
        for result in bad:
            with self.subTest(result=result), self.assertRaises(flow.Failed):
                flow.require_reviewed_check(result)


if __name__ == '__main__':
    unittest.main()
