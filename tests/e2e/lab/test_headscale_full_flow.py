"""Offline tests of the Headscale full product-flow harness (services-a-2): the lab DERP config edit, the private
key extraction for the leak scan, the fixed output vocabulary and the always-cleanup order. No device, no backup,
no credential (every key below is generated)."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('headscale_full_flow', HERE / 'headscale_full_flow.py')
hsff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hsff)
cspec = importlib.util.spec_from_file_location('services_a_capture_h', HERE / 'services_a_capture.py')
capture = importlib.util.module_from_spec(cspec)
cspec.loader.exec_module(capture)

DEV_D_CONFIG = '''---
server_url: http://localhost:28080
listen_addr: "0.0.0.0:8080"
noise:
  private_key_path: /var/lib/headscale/noise_private.key

prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48

derp:
  server:
    enabled: false
  urls: []
  auto_update_enabled: false
  update_frequency: 24h

node:
  expiry: "0"

dns:
  magic_dns: true
  base_domain: ts.local
  extra_records_path: /var/lib/headscale/extra_records.json
'''


def key(prefix='privkey'):
    return f'{prefix}:{secrets.token_hex(32)}'


class LabConfigTest(unittest.TestCase):
    def test_only_the_derp_block_changes(self):
        out = hsff.lab_config(DEV_D_CONFIG)
        self.assertIn(hsff.LAB_DERP, out)
        before, after = DEV_D_CONFIG.split('derp:\n', 1)
        self.assertTrue(out.startswith(before))
        rest = after.split('\nnode:', 1)[1]
        self.assertTrue(out.endswith('\nnode:' + rest))
        self.assertNotIn('\n    enabled: false\n', out)
        self.assertEqual(out.count('\nderp:'), 1)
        self.assertIn('server_url: http://localhost:28080', out)
        self.assertIn('extra_records_path: /var/lib/headscale/extra_records.json', out)

    def test_refuses_no_or_two_derp_blocks(self):
        with self.assertRaises(hsff.Failed):
            hsff.lab_config(DEV_D_CONFIG.replace('derp:', 'relay:'))
        with self.assertRaises(hsff.Failed):
            hsff.lab_config(DEV_D_CONFIG + 'derp:\n  urls: []\n')

    def test_lab_derp_is_valid_yaml_shape(self):
        lines = hsff.LAB_DERP.splitlines()
        self.assertEqual(lines[0], 'derp:')
        self.assertTrue(all(line.startswith('  ') for line in lines[1:]))
        for needed in ('enabled: true', 'region_id: 999', 'region_code: lab', 'stun_listen_addr: 0.0.0.0:3478',
                       'automatically_add_embedded_derp_region: true', 'urls: []'):
            self.assertIn(needed, hsff.LAB_DERP)


class PrivateKeysTest(unittest.TestCase):
    def state(self, machine, node, old, lock):
        profile = {'Config': {'PrivateNodeKey': node, 'OldPrivateNodeKey': old, 'NetworkLockKey': lock,
                              'UserProfile': {'LoginName': 'alice'}}}
        doc = {'_machinekey': base64.b64encode(machine.encode()).decode(),
               '_current-profile': base64.b64encode(b'profile-1234').decode(),
               'profile-1234': base64.b64encode(json.dumps(profile).encode()).decode()}
        return json.dumps(doc).encode()

    def test_finds_every_private_key_and_skips_zero_keys(self):
        machine, node, lock = key(), key(), key('nlpriv')
        zero = 'privkey:' + '0' * 64
        found = hsff.state_private_keys(self.state(machine, node, zero, lock))
        self.assertEqual(found, sorted([machine, node, lock]))

    def test_rejects_non_json(self):
        with self.assertRaises(hsff.Failed):
            hsff.state_private_keys(b'not json')


class MemberSecretsTest(unittest.TestCase):
    def fixture(self, directory, *, noise=None):
        noise = noise or key()
        inner = io.BytesIO()
        with tarfile.open(fileobj=inner, mode='w:gz') as tar:
            for name, data in (('./addon.json', b'{}'), ('./image.tar', b'x' * 100000),
                               ('data/noise_private.key', noise.encode()),
                               ('data/.headplane_api_key', b'hskey-api-abcdefghijkl-' + secrets.token_hex(16).encode()),
                               ('data/.headplane_cookie_secret', secrets.token_hex(16).encode())):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        path = Path(directory, 'ha.tar')
        with tarfile.open(path, 'w') as outer:
            info = tarfile.TarInfo('5ad331fe_woow-headscale.tar.gz')
            info.size = len(inner.getvalue())
            outer.addfile(info, io.BytesIO(inner.getvalue()))
        return path, noise

    def test_reads_the_three_values_in_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            path, noise = self.fixture(directory)
            values, sha = hsff.ha_member_secrets(path)
        self.assertEqual(set(values), {'HA_HS_NOISE_KEY', 'HA_HEADPLANE_API_KEY', 'HA_HEADPLANE_COOKIE'})
        self.assertEqual(values['HA_HS_NOISE_KEY'], noise)
        self.assertEqual(sha, hashlib.sha256(noise.encode()).hexdigest())

    def test_refuses_a_bad_noise_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _noise = self.fixture(directory, noise='not-a-key')
            with self.assertRaises(hsff.Failed):
                hsff.ha_member_secrets(path)


class NodesTest(unittest.TestCase):
    def test_match_by_id_user_and_addresses(self):
        src = {'nodes': [{'id': 1, 'given_name': 'b1-bob-nas', 'user': 'bob', 'ip_addresses': ['100.64.0.1', 'fd7a::1']},
                         {'id': 2, 'given_name': 'b1-ts-alice', 'user': 'alice', 'ip_addresses': ['100.64.0.2', 'fd7a::2']}]}
        probe = {'nodes': [[1, 'b1-bob-nas', 'bob', ['100.64.0.1', 'fd7a::1'], ['192.168.88.0/24'], False, []],
                           [2, 'b1-ts-alice', 'alice', ['100.64.0.2', 'fd7a::2'], [], True, []]]}
        self.assertTrue(hsff.ha_nodes_match(probe, src))
        self.assertEqual(hsff.node_rows(probe)['b1-ts-alice'][4], True)
        probe['nodes'][1][0] = 3
        self.assertFalse(hsff.ha_nodes_match(probe, src))


class OutputTest(unittest.TestCase):
    def test_check_prints_only_the_fixed_line(self):
        with tempfile.TemporaryDirectory() as directory:
            secret_value = 'hskey-auth-' + secrets.token_hex(12)
            fake = mock.Mock()
            fake.values = {'B1_X86_HS_KEY_BOB_REUSABLE': secret_value}
            fake.names = set()
            fake.redact = lambda text: str(text).replace(secret_value, '<k>')
            fake.redact_structure = lambda value: json.loads(fake.redact(json.dumps(value)))
            with mock.patch.object(hsff.drv, 'LAB', Path(directory)):
                ev = hsff.Ev(fake, 'unit')
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                ev.check('client x86: new device 1 joins with HA\'s reusable pre-auth key', True, {'key': secret_value})
                ev.check('bad "label" + {value}', False, secret_value)
            lines = out.getvalue().splitlines()
            self.assertEqual(lines, ['client x86: new device 1 joins with HA\'s reusable pre-auth key: PASS',
                                     'bad  label     value: FAIL'])
            self.assertNotIn(secret_value, (ev.dir / 'run.log').read_text())
            self.assertTrue(all(capture.status_lines(line) == [line] for line in lines))

    def test_capture_keeps_every_fixed_line_of_the_harness(self):
        lines = ['source commit ' + 'a' * 40, 'source tree committed: PASS',
                 'dev-d mutation lock acquired: PASS (waited 12 s)', 'dev-d isolation: true none {}',
                 'dev-d memory current=1995173888 limit=4294967296; headroom >= 1.19 GiB; host MemAvailable 3434832 KiB',
                 'headscale full flow arm: 97/97 PASS', 'lock held for 812 s',
                 hsff.label('import x86-plain: real space: free space of staging/home/storage above the product\'s floor '
                            '(running reserve + watch margin) the convert job enforces') + ': PASS']
        self.assertEqual(capture.status_lines('\n'.join(lines)), lines)

    def test_self_check(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            hsff.self_check()
        self.assertIn('6 embedded programs compiled', out.getvalue())


class MainGuardsTest(unittest.TestCase):
    def test_dirty_tree_never_takes_the_lock(self):
        out = io.StringIO()
        with mock.patch.object(hsff.guard, 'clean_tree', return_value=(False, ['backup-engine/x.py'])), \
                mock.patch.object(hsff.guard, 'head', return_value='b' * 40), \
                mock.patch.object(hsff.guard, 'acquire', side_effect=AssertionError('lock taken')), \
                contextlib.redirect_stdout(out):
            rc = hsff.main(['--run', '--arch', 'x86'])
        self.assertEqual(rc, 2)
        self.assertEqual(out.getvalue().splitlines(), ['source commit ' + 'b' * 40, 'source tree committed: FAIL'])

    def test_requires_run_and_arch(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            hsff.main(['--arch', 'x86'])


class CleanupOrderTest(unittest.TestCase):
    def fake_run(self, fail_at, *, safety):
        calls = []
        run = mock.Mock()
        run.private = '/home/appowner/.services-a2-hsff.AbCdEfGh'
        run.safety = safety
        run.ev = mock.Mock()
        run.ev.check = lambda name, ok, detail='': calls.append(('check', name, ok)) or ok

        def step(name):
            def inner(*_a, **_k):
                calls.append(name)
                if name == fail_at:
                    raise hsff.Failed('stop')
            return inner

        for name in ('setup', 'load_secrets', 'lab_config_on', 'step_before', 'step_upload', 'step_check',
                     'step_import', 'clients_phase', 'step_restart', 'step_auto_rollback', 'clients_stop', 'inject_off',
                     'step_rollback_to_own', 'lab_config_off', 'step_cleanup', 'step_leaks'):
            setattr(run, name, step(name))
        run.verify = step('verify')
        run.budget = lambda _phase: None
        run.remove_private = lambda: calls.append('remove_private') or True
        return run, calls

    def test_a_failed_phase_still_cleans_up_in_order(self):
        run, calls = self.fake_run('clients_phase', safety='20261123T000000Z-abcdef12')
        with mock.patch.object(hsff, 'keep_volume_keys', lambda *a: calls.append('keep')), \
                mock.patch.object(hsff, 'app_status', lambda *a: calls.append('status')), \
                mock.patch.object(hsff.drv, 'app_health', lambda *a: calls.append('health')):
            failure = hsff.run_all(run)
        self.assertIsInstance(failure, hsff.Failed)
        names = [c for c in calls if isinstance(c, str)]
        self.assertEqual(names[names.index('clients_phase'):],
                         ['clients_phase', 'clients_stop', 'inject_off', 'step_rollback_to_own', 'lab_config_off',
                          'step_cleanup', 'step_leaks', 'remove_private'])
        self.assertNotIn('step_restart', names)

    def test_no_restore_means_no_rollback_restore(self):
        run, calls = self.fake_run('step_import', safety=None)
        with mock.patch.object(hsff, 'keep_volume_keys', lambda *a: None):
            hsff.run_all(run)
        names = [c for c in calls if isinstance(c, str)]
        self.assertNotIn('step_rollback_to_own', names)
        self.assertEqual(names[-5:], ['inject_off', 'lab_config_off', 'step_cleanup', 'step_leaks', 'remove_private'])


if __name__ == '__main__':
    unittest.main()
