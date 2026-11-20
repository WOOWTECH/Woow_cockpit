"""Version-reviewed roots through the internal candidate, using fixture transport."""
import copy
import unittest
from woowbackup.errors import BackupError
from . import test_ha_emqx_candidate_flow as flow

class FilelessRootsTests(unittest.TestCase):
    def invoke(self, transport):
        return flow.CandidateFlowTests.invoke(self, transport)

    def test_reviewed_roots_survive_import_and_restore(self):
        class ChangedRoot(flow.Transport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    self.running_config['alarm']['size_limit'] = 1
                    self.running_config['rule_engine'] = {'rules': {'ha': {}}}
                return result
        transport = ChangedRoot()
        roots = {'alarm': {'actions': ['log'], 'size_limit': 200, 'validity_period': '24h'},
                 'slow_subs': {'enable': False, 'threshold': '500ms', 'expire_interval': '300s',
                               'top_k_num': 10, 'stats_type': 'whole'},
                 'trace': {'payload_encode': 'hidden'}}
        transport.config.update(roots)
        transport.running_config = copy.deepcopy(transport.config)
        self.invoke(transport)
        for root in roots:
            self.assertEqual(transport.running_config[root], roots[root])
        self.assertIn('ha', transport.running_config['rule_engine']['rules'])

    def test_unknown_field_refused_before_export(self):
        transport = flow.Transport()
        transport.config['alarm'] = {'path': '/outside/file'}
        with self.assertRaises(BackupError):
            self.invoke(transport)
        self.assertNotIn('export', transport.events)

    def test_nested_reference_and_unsupported_action_refused(self):
        for root, value in [('trace', {'payload_encode': {'file': '/outside'}}),
                            ('alarm', {'actions': ['shell']})]:
            with self.subTest(root=root):
                transport = flow.Transport()
                transport.config[root] = value
                with self.assertRaises(BackupError):
                    self.invoke(transport)
                self.assertNotIn('export', transport.events)
