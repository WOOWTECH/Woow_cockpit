"""n8ndiag verdicts on synthetic device output (AST-extracted, no lab, no real credentials)."""
import ast
import json
from pathlib import Path
import types
import unittest

ROOT = Path(__file__).resolve().parent


class Failed(Exception):
    pass


class Evidence:
    def __init__(self):
        self.checks, self.saved = [], {}

    def check(self, name, ok, detail=''):
        self.checks.append((name, bool(ok)))

    def save(self, name, value):
        self.saved[name] = value


ARM_OK = {'login': True, 'listing': {'error_type': 'TimeoutError', 'seconds': 150.0}, 'process_samples': 40,
          'npm_outdated_seen': [1.2, 148.0, 38], 'n8n_packages': [['n8n-nodes-globals', '1.1.0', False]],
          'n8n_community_nodes_checked': 1, 'local_probe_seconds': 0.4}


class DiagnosisTests(unittest.TestCase):
    def setUp(self):
        tree = ast.parse((ROOT / 'ha_import_e2e.py').read_text())
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'scenario_n8ndiag']
        self.assertEqual(len(nodes), 1)
        self.ns = {'json': json, 'Failed': Failed, 'EXPECT': {'arch': 'aarch64'}, 'OWNER_EMAIL': 'x@probe.invalid',
                   'N8N_DIAGNOSIS': 'synthetic', 'require_isolated_device': lambda: None}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<driver>', 'exec'), self.ns)

    def verdict(self, result, arch='aarch64'):
        self.ns['EXPECT']['arch'] = arch
        sent = []
        def root(*argv, input=None, timeout=None):
            sent.append(json.loads(input))
            return types.SimpleNamespace(stdout=json.dumps(result).encode())
        self.ns['root'] = root
        ev = Evidence()
        args = types.SimpleNamespace(secrets={'N8N_OWNER_PW': 'SYNTHETIC-PW'})
        self.ns['scenario_n8ndiag'](ev, args)
        self.assertNotIn('SYNTHETIC-PW', json.dumps(ev.saved))
        self.assertEqual(sent[0]['timeout'], 150)
        return all(ok for _, ok in ev.checks), ev

    def test_arm_root_cause_proven(self):
        self.assertTrue(self.verdict(ARM_OK)[0])

    def test_arm_needs_npm_seen(self):
        self.assertFalse(self.verdict(dict(ARM_OK, npm_outdated_seen=[]))[0])

    def test_arm_fast_listing_disproves(self):
        self.assertFalse(self.verdict(dict(ARM_OK, listing={'status': 200, 'seconds': 2.0,
                                                           'packages': [['n8n-nodes-globals', '1.1.0', False]]}))[0])

    def test_arm_slow_listing_counts(self):
        self.assertTrue(self.verdict(dict(ARM_OK, listing={'status': 200, 'seconds': 75.0, 'packages': []}))[0])

    def test_arm_local_probe_must_pass(self):
        self.assertFalse(self.verdict(dict(ARM_OK, n8n_packages=[], n8n_community_nodes_checked=0,
                                           n8n_community_error_code='node_type_not_loaded'))[0])

    def test_login_required(self):
        self.assertFalse(self.verdict(dict(ARM_OK, login=False))[0])

    def test_x86_empty_list_without_npm(self):
        result = {'login': True, 'listing': {'status': 200, 'packages': [], 'seconds': 0.3}, 'npm_outdated_seen': []}
        self.assertTrue(self.verdict(result, arch='amd64')[0])
        self.assertFalse(self.verdict(dict(result, npm_outdated_seen=[0.5, 0.5, 1]), arch='amd64')[0])
        self.assertFalse(self.verdict(dict(result, listing={'error_type': 'TimeoutError', 'seconds': 150}),
                                      arch='amd64')[0])

    def test_garbage_output_fails(self):
        self.ns['root'] = lambda *a, **k: types.SimpleNamespace(stdout=b'not json')
        with self.assertRaises(Failed):
            self.ns['scenario_n8ndiag'](Evidence(), types.SimpleNamespace(secrets={'N8N_OWNER_PW': 'x'}))


if __name__ == '__main__':
    unittest.main()
