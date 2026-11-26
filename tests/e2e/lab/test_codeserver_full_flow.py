"""Offline safety checks for the code-server real-flow harness; no device access."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


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


class StoppedLabUnitTests(unittest.TestCase):
    class StopHere(Exception):
        pass

    def evidence(self):
        ev = mock.Mock()
        ev.check.side_effect = lambda _name, ok, _detail='': bool(ok)
        return ev

    def test_cleanly_stopped_unit_is_started_then_restored_to_stopped(self):
        run = flow.Run(None, self.evidence())
        run.headroom = mock.Mock(side_effect=[None, self.StopHere()])
        with mock.patch.object(flow, 'isolation', return_value='true none {}'), \
             mock.patch.object(flow, 'clean_tree', return_value=True), \
             mock.patch.object(flow, 'sha256_file', return_value=flow.FIXTURE_SHA), \
             mock.patch.object(flow, 'unit_state', side_effect=['inactive', 'active']), \
             mock.patch.object(flow.drv, 'owner', return_value=SimpleNamespace(returncode=0)) as owner:
            with self.assertRaises(self.StopHere):
                run.setup()
        owner.assert_called_once_with('systemctl', '--user', 'start', flow.UNIT, timeout=420)
        self.assertEqual(run.unit_found, 'inactive')
        self.assertTrue(run.started_unit)
        self.assertEqual(run.headroom.call_count, 2)
        with mock.patch.object(flow, 'unit_state', return_value='inactive'), \
             mock.patch.object(flow.drv, 'owner', return_value=SimpleNamespace(returncode=0)) as owner, \
             mock.patch.object(flow.drv, 'labelled', side_effect=self.StopHere):
            with self.assertRaises(self.StopHere):
                run.step_cleanup()
        owner.assert_called_once_with('systemctl', '--user', 'stop', flow.UNIT, timeout=300)

    def test_active_unit_is_used_without_starting_or_stopping_it(self):
        run = flow.Run(None, self.evidence())
        run.headroom = mock.Mock(side_effect=self.StopHere())
        with mock.patch.object(flow, 'isolation', return_value='true none {}'), \
             mock.patch.object(flow, 'clean_tree', return_value=True), \
             mock.patch.object(flow, 'sha256_file', return_value=flow.FIXTURE_SHA), \
             mock.patch.object(flow, 'unit_state', return_value='active'), \
             mock.patch.object(flow.drv, 'owner') as owner:
            with self.assertRaises(self.StopHere):
                run.setup()
        owner.assert_not_called()
        self.assertFalse(run.started_unit)


if __name__ == '__main__':
    unittest.main()
