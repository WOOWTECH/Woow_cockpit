"""Offline checks for the automatic reconnection acceptance predicate."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('auto_check', Path(__file__).with_name('headscale-auto-reconnect-check.py'))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class AutoReconnectTest(unittest.TestCase):
    def setUp(self):
        self.nodes = [{'id': 1, 'online': True, 'ip_addresses': ['100.64.0.1', 'fd7a::1']},
                      {'id': 2, 'online': True, 'ip_addresses': ['100.64.0.2', 'fd7a::2']}]
        self.pairs = []
        for number in (1, 2):
            status = {'BackendState': 'Running', 'Self': {'ID': 'stable' + str(number),
                      'PublicKey': 'nodekey' + str(number),
                      'TailscaleIPs': [f'100.64.0.{number}', f'fd7a::{number}']}}
            self.pairs.append((copy.deepcopy(status), copy.deepcopy(status)))

    def test_both_connected_matching_identities(self):
        self.assertTrue(check.check(self.nodes, self.pairs))

    def test_offline_or_changed_identity_and_node_address_fail(self):
        nodes = copy.deepcopy(self.nodes)
        nodes[1]['online'] = False
        self.assertFalse(check.check(nodes, self.pairs))
        pairs = copy.deepcopy(self.pairs)
        pairs[0][1]['Self']['PublicKey'] = 'changed'
        self.assertFalse(check.check(self.nodes, pairs))
        nodes = copy.deepcopy(self.nodes)
        nodes[1]['ip_addresses'] = ['100.64.0.99']
        self.assertFalse(check.check(nodes, self.pairs))

    def test_missing_nodes_or_duplicate_client_id_fail(self):
        self.assertFalse(check.check(self.nodes[:1], self.pairs))
        pairs = copy.deepcopy(self.pairs)
        pairs[1][0]['Self']['ID'] = pairs[1][1]['Self']['ID'] = 'stable1'
        self.assertFalse(check.check(self.nodes, pairs))


if __name__ == '__main__':
    unittest.main()
