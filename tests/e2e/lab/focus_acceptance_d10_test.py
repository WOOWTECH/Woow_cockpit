"""Offline boundaries of the bounded real D10 case; these are not acceptance."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('focus_d10', Path(__file__).with_name('focus_acceptance_d10.py'))
d10 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d10)


class ConfirmationTests(unittest.TestCase):
    def preflight(self, **issue):
        return {'ok': True, 'apps': [{'id': d10.APP, 'issues': [dict(
            {'id': 'restore.pauses', 'level': 'confirm', 'items': ['case-home', 'case-desktop'],
             'key': 'restore.pauses:1234567890abcdef', 'more': 0}, **issue)]}]}

    def test_accepts_only_reviewed_names_independent_of_order(self):
        self.assertEqual(d10.pause_keys(self.preflight(), ['case-desktop', 'case-home']),
                         ['restore.pauses:1234567890abcdef'])

    def test_added_consumer_is_not_automatically_confirmed(self):
        with self.assertRaises(ValueError):
            d10.pause_keys(self.preflight(items=['case-home', 'case-desktop', 'unexpected']),
                           ['case-home', 'case-desktop'])

    def test_hidden_consumers_are_refused(self):
        with self.assertRaises(ValueError):
            d10.pause_keys(self.preflight(more=1), ['case-home', 'case-desktop'])

    def test_unreviewed_confirmation_is_refused(self):
        pre = self.preflight()
        pre['apps'][0]['issues'].append({'id': 'restore.other-databases', 'level': 'confirm'})
        with self.assertRaises(ValueError):
            d10.pause_keys(pre, ['case-home', 'case-desktop'])

    def test_bad_key_stop_and_failed_preflight_are_refused(self):
        for kwargs in ({'key': 'anything'}, {'level': 'stop'}, {'id': 'unreviewed'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                d10.pause_keys(self.preflight(**kwargs), ['case-home', 'case-desktop'])
        pre = self.preflight()
        pre['ok'] = False
        with self.assertRaises(ValueError):
            d10.pause_keys(pre, ['case-home', 'case-desktop'])

    def test_no_or_wrong_app_is_not_ready(self):
        for apps in ([], [{'id': 'hermes', 'issues': []}]):
            with self.subTest(apps=apps), self.assertRaises(ValueError):
                d10.pause_keys({'ok': True, 'apps': apps}, [])


class ConsumerTests(unittest.TestCase):
    def test_a_missed_sample_can_use_an_ordered_real_service_cycle(self):
        self.assertTrue(d10.ordered_restart([[20, 'started'], [10, 'stopped']]))
        for events in ([], [[10, 'started']], [[10, 'started'], [20, 'stopped']],
                       [[10, 'stopped'], [10, 'started']]):
            with self.subTest(events=events):
                self.assertFalse(d10.ordered_restart(events))

    def test_consumer_is_pinned_isolated_and_has_no_install_or_restart_policy(self):
        for whole, suffix in ((False, 'desktop'), (True, 'home')):
            text = d10.consumer_unit('woowbk-focus-d10-0123456789ab-' + suffix, whole)
            self.assertIn('Image=sha256:' + d10.IMAGE, text)
            self.assertIn('Network=none\n', text)
            self.assertIn('--entrypoint=/bin/sh', text)
            self.assertNotIn('\nEntrypoint=', text)  # dev-e's installed generator rejects that newer key
            self.assertIn('--pull=never', text)
            self.assertNotIn('Restart=', text)
            self.assertNotIn('[Install]', text)
            self.assertNotIn('PublishPort=', text)

    def test_resource_names_cannot_escape_case_scope(self):
        for name in ('code-server', '../escape', 'woowbk-focus-d10-0123456789ab-home\nExec=oops'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                d10.consumer_unit(name, True)


class SavedN8nPreparationTests(unittest.TestCase):
    def test_default_never_enters_real_saved_flow(self):
        spec = importlib.util.spec_from_file_location('prepared_n8n', Path(__file__).with_name('focus_acceptance_n8n.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(module, '_run', side_effect=AssertionError('unleased runtime')) as run:
            self.assertEqual(module.main([]), 0)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
