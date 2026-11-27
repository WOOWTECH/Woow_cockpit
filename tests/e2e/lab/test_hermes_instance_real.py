"""Offline contracts of the H-03 real-lab case; no device, subprocess or secret."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('hermes_instance_test', HERE / 'hermes_instance_real.py')
case = importlib.util.module_from_spec(spec)
spec.loader.exec_module(case)


class InstanceCaseTests(unittest.TestCase):
    def test_fixture_publication_uploads_only_when_absent_and_checks_its_identity(self):
        digest = 'f82422e327f151ec819d' + '0' * 44
        store = case.hr.STORE_IDS['x86-enc']
        for present in (False, True):
            with self.subTest(present=present), mock.patch.object(case.hr, 'sha256_file', return_value=digest), \
                    mock.patch.object(case.drv, 'ok', return_value={'ha_backups': [{'id': store}] if present else []}), \
                    mock.patch.object(case.drv, 'upload', return_value=(0, {'ha_backup': {'id': store}})) as upload, \
                    mock.patch.object(case.drv, 'STATE', {}):
                created = set()
                case.ensure_fixture('x86-enc', mock.Mock(), created)
                self.assertEqual(upload.call_count, 0 if present else 1)
                self.assertEqual(created, set() if present else {store})
                self.assertEqual(case.drv.STATE['fixture_sha256']['x86-enc'], digest)

    def test_wrong_original_fixture_is_refused_before_upload_or_probe(self):
        with mock.patch.object(case.hr, 'sha256_file', return_value='0' * 64), \
                mock.patch.object(case.drv, 'upload') as upload:
            with self.assertRaises(case.hr.Failed):
                case.ensure_fixture('x86-enc', mock.Mock(), set())
            upload.assert_not_called()

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
