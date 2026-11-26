"""Offline contracts of the H-03 real-lab case; no device, subprocess or secret."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('hermes_instance_test', HERE / 'hermes_instance_real.py')
case = importlib.util.module_from_spec(spec)
spec.loader.exec_module(case)


class InstanceCaseTests(unittest.TestCase):
    def test_catalog_change_keeps_every_other_setting_and_the_input(self):
        original = {'postgres': [{'id': 'main', 'database': 'hermes', 'scope': 'database', 'user': 'hermes'}],
                    'secrets': [{'name': 'existing'}], 'volumes': [{'name': 'data'}]}
        before = copy.deepcopy(original)
        changed = case.instance_entry(original)
        expected = copy.deepcopy(original)
        expected['postgres'][0].pop('database')
        expected['postgres'][0]['scope'] = 'instance'
        self.assertEqual(original, before)
        self.assertEqual(changed, expected)

    def test_an_unexpected_catalog_is_refused(self):
        for postgres in ([], [{'scope': 'other'}], [{}, {}]):
            with self.subTest(postgres=postgres):
                with self.assertRaises(case.hr.Failed):
                    case.instance_entry({'postgres': postgres})

    def test_only_the_cases_own_names_can_reach_probe_ddl(self):
        for name in ('woowbk_instance_aabbcc001122', 'woowbk_instance_aabbcc001122_role'):
            self.assertEqual(case.identifier(name), '"' + name + '"')
        for name in ('hermes', 'postgres', 'woowbk_instance_abcdef', 'woowbk_instance_aabbcc001122; SELECT 1',
                     'woowbk_instance_aabbcc001122\n', 'woowbk_instance_aabbcc001122"'):
            with self.subTest(name=name):
                with self.assertRaises(case.hr.Failed):
                    case.identifier(name)
