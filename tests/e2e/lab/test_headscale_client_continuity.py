"""Offline transport fixtures; never start Podman, systemd, or the lab."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from headscale_client_continuity import Continuity, network_address


class Clock:
    now = 0
    def __call__(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


class Transport:
    def __init__(self, clock):
        self.clock, self.calls = clock, []
        self.offline, self.direct, self.restart, self.fail = False, False, False, False
        self.changed, self.delay = None, 0
        self.nodes = [{'id': i, 'online': True, 'ip_addresses': [f'100.64.0.{i}']} for i in (1, 2)]
        self.statuses = [{'BackendState': 'Running', 'Self': {'ID': f'stable{i}',
                          'PublicKey': f'nodekey{i}', 'TailscaleIPs': [f'100.64.0.{i}']}} for i in (1, 2)]
        self.network = {'name': 'hs-test-abcd1234', 'internal': True,
                        'labels': {'io.woowtech.test': 'headscale-derp'},
                        'subnets': [{'subnet': '10.89.0.0/24'}]}

    def podman(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        assert 0 < kwargs['timeout'] <= 5 and kwargs['max_output'] == 65536
        self.clock.sleep(min(self.delay, kwargs['timeout']))
        if self.fail:
            return SimpleNamespace(returncode=1, stdout=b'private-error-must-not-be-printed')
        if args[:2] == ('network', 'inspect'):
            data = [self.network]
        elif args[:2] == ('container', 'inspect'):
            data = [{'Id': args[2], 'State': {'Running': True, 'StartedAt': 'new' if self.restart else 'original', 'Pid': 1},
                     'HostConfig': {'PortBindings': {}},
                     'NetworkSettings': {'Networks': {self.network['name']: {}}}}]
        elif args[2] == 'headscale':
            data = copy.deepcopy(self.nodes)
            if self.offline:
                data[0]['online'] = False
        elif 'status' in args:
            data = copy.deepcopy(self.statuses[0 if args[1].startswith('hs-a-') else 1])
            if self.changed:
                data['Self'][self.changed] = 'replacement'
        elif 'ping' in args:
            route = b'10.89.0.2:1234' if self.direct else b'DERP(lab)'
            return SimpleNamespace(returncode=0, stdout=b'pong from peer via ' + route + b' in 1ms\n')
        else:
            raise AssertionError(args)
        return SimpleNamespace(returncode=0, stdout=json.dumps(data).encode())


class ContinuityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'headscale-internal.abcd1234'
        self.root.mkdir()
        self.clock = Clock()
        self.transport = Transport(self.clock)
        for letter, status in zip('ab', self.transport.statuses):
            (self.root / f'hs-{letter}-abcd1234.before.json').write_text(json.dumps(status))
        self.check = Continuity(self.transport, self.root, '10.89.0.10', clock=self.clock, sleep=self.clock.sleep)

    def verify(self, phase='installed'):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.check.verify('hs-install-fixture', phase)
        return output.getvalue()

    def test_each_phase_requires_same_clients_and_bidirectional_derp(self):
        for phase in ('installed', 'rolled_back', 'restarted'):
            output = self.verify(phase)
            self.assertIn(f'{phase}:PASS', output)
            self.assertNotIn('nodekey', output)
        pings = [args for args, _ in self.transport.calls if 'ping' in args]
        self.assertEqual([args[-1] for args in pings], ['100.64.0.2', '100.64.0.1'] * 3)
        self.assertFalse(any(set(args) & {'up', 'down', 'start', 'stop', 'restart', '--authkey'}
                             for args, _ in self.transport.calls))

    def test_offline_nodes_fail_at_deadline_even_with_cached_running_clients(self):
        self.transport.offline = True
        with self.assertRaisesRegex(RuntimeError, 'continuity_deadline'):
            self.verify()
        self.assertEqual(self.clock.now, 60)
        self.assertFalse(any('ping' in args for args, _ in self.transport.calls))

    def test_reconnect_retries_then_succeeds_without_reset(self):
        self.transport.offline = True
        def reconnect(seconds):
            self.clock.sleep(seconds)
            self.transport.offline = False
        self.check.sleep = reconnect
        self.assertIn('attempts=2', self.verify())

    def test_changed_key_id_and_addresses_cannot_pass(self):
        for field in ('ID', 'PublicKey', 'TailscaleIPs'):
            self.transport.changed = field
            with self.assertRaisesRegex(RuntimeError, 'continuity_deadline'):
                self.verify()

    def test_direct_traffic_does_not_satisfy_derp(self):
        self.transport.direct = True
        with self.assertRaisesRegex(RuntimeError, 'continuity_deadline'):
            self.verify()

    def test_restarted_client_fails_immediately(self):
        self.transport.restart = True
        with self.assertRaisesRegex(RuntimeError, 'continuity_client_process_replaced'):
            self.verify('rolled_back')
        self.assertEqual(self.clock.now, 0)

    def test_command_failure_fails_closed_without_output(self):
        self.transport.fail = True
        with self.assertRaisesRegex(RuntimeError, '^continuity_observation_failed$'):
            self.verify()

    def test_slow_commands_share_deadline_and_shrink_final_timeout(self):
        self.transport.offline, self.transport.delay = True, 4
        with self.assertRaisesRegex(RuntimeError, 'continuity_deadline'):
            self.verify()
        self.assertEqual(self.clock.now, 60)
        self.assertLess(self.transport.calls[-1][1]['timeout'], 5)

    def test_network_and_ip_guards(self):
        for field, value in [('internal', False), ('name', 'original-network'), ('labels', {})]:
            info = copy.deepcopy(self.transport.network)
            info[field] = value
            with self.assertRaisesRegex(RuntimeError, 'continuity_network_not_isolated'):
                network_address(info, self.check.network, '10.89.0.10')
        for address in ('10.90.0.1', '10.89.0.0', '10.89.0.255'):
            with self.assertRaisesRegex(RuntimeError, 'continuity_ip_outside_network'):
                network_address(self.transport.network, self.check.network, address)
        with self.assertRaises(ValueError):
            network_address(self.transport.network, self.check.network, '10.89.0.10\nPublishPort=8080')

    def test_baseline_symlink_and_oversize_rejected(self):
        path = self.root / 'hs-a-abcd1234.before.json'
        path.unlink()
        path.symlink_to(self.root / 'hs-b-abcd1234.before.json')
        with self.assertRaisesRegex(RuntimeError, 'continuity_invalid_baseline'):
            Continuity(self.transport, self.root, '10.89.0.10', clock=self.clock)
        path.unlink()
        path.write_bytes(b'x' * 65537)
        with self.assertRaisesRegex(RuntimeError, 'continuity_invalid_baseline'):
            Continuity(self.transport, self.root, '10.89.0.10', clock=self.clock)

    def test_harness_keeps_clients_alive_and_stages_helper(self):
        lab = Path(__file__).parent
        script = (lab / 'headscale-product-runner.sh').read_text()
        install = script.index('--run --client-address')
        self.assertLess(script.index('podman rm "$target_server"', script.index('# Release the converted endpoint')), install)
        self.assertGreater(script.index('podman stop "$client_a"'), install)
        self.assertGreater(script.index('private_source client_a_identity_after'), install)
        self.assertIn('tests/e2e/lab/headscale_client_continuity.py', (lab / 'headscale-product-test.sh').read_text())


if __name__ == '__main__':
    unittest.main()
