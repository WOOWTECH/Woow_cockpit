"""Offline tests of the real-HA Headscale harness pieces (services-a). Synthetic JSON/tar fixtures only:
nothing here opens a real backup, a device or a credential file."""
import base64
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / 'backup-engine'))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checks = load('headscale_real_checks', 'headscale_real_checks.py')
profile = load('headscale_real_events', 'headscale_real_events.py')
private = load('headscale_private_sources_real', 'headscale-private-sources.py')
convert = load('headscale_real_convert', 'headscale_real_convert.py')
capture = load('services_a_capture', 'services_a_capture.py')
install = load('headscale_real_install', 'headscale_real_install.py')

NODE_KEY = 'nodekey:' + '1' * 64
SERVER_KEY = 'mkey:' + '2' * 64
EXPECT = {
    'users': [[1, 'default'], [2, 'alice'], [3, 'bob']],
    'nodes': [{'id': 1, 'given_name': 'b1-bob-nas', 'user': 'bob', 'ip_addresses': ['100.64.0.1', 'fd7a:115c:a1e0::1'],
               'approved_routes': ['192.168.88.0/24']},
              {'id': 2, 'given_name': 'b1-ts-alice', 'user': 'alice', 'ip_addresses': ['100.64.0.2', 'fd7a:115c:a1e0::2'],
               'approved_routes': None}],
    'preauthkeys': [{'id': 1, 'reusable': None, 'used': True}, {'id': 2, 'reusable': True, 'used': None}],
    'dns_extra_records': [{'name': 'b1-nas.ts.local', 'type': 'A', 'value': '100.64.0.250'}],
    'server_public_key': SERVER_KEY,
    'client': {'NodeID': '2', 'NodePublicKey': NODE_KEY, 'TailscaleIPs': ['100.64.0.2', 'fd7a:115c:a1e0::2'],
               'HostName': 'b1-ts-alice'},
}


def server_node(node_id, name, user, ips, online=False, routes=None):
    return {'id': node_id, 'given_name': name, 'user': {'id': 9, 'name': user}, 'ip_addresses': ips,
            'online': online, 'approved_routes': routes}


def nodes_ok(online2=True, extra=()):
    rows = [server_node(1, 'b1-bob-nas', 'bob', ['fd7a:115c:a1e0::1', '100.64.0.1'], routes=['192.168.88.0/24']),
            server_node(2, 'b1-ts-alice', 'alice', ['100.64.0.2', 'fd7a:115c:a1e0::2'], online=online2)]
    return rows + list(extra)


class ChecksTest(unittest.TestCase):
    def test_nodes_pass_and_failures(self):
        checks.check_nodes(EXPECT, nodes_ok(), online=['2'])
        with self.assertRaises(checks.CheckError):
            checks.check_nodes(EXPECT, nodes_ok(online2=False), online=['2'])
        with self.assertRaises(checks.CheckError):
            checks.check_nodes(EXPECT, nodes_ok()[:1])
        new = server_node(3, 'probe', 'bob', ['100.64.0.3'], online=True)
        with self.assertRaises(checks.CheckError):
            checks.check_nodes(EXPECT, nodes_ok(extra=[new]))
        checks.check_nodes(EXPECT, nodes_ok(extra=[new]), extra=1)
        moved = nodes_ok()
        moved[1]['ip_addresses'] = ['100.64.0.9', 'fd7a:115c:a1e0::2']
        with self.assertRaises(checks.CheckError):
            checks.check_nodes(EXPECT, moved)
        renamed = nodes_ok()
        renamed[0]['approved_routes'] = []
        with self.assertRaises(checks.CheckError):
            checks.check_nodes(EXPECT, renamed)

    def test_users_preauth_records_server_key(self):
        checks.check_users(EXPECT, [{'id': 3, 'name': 'bob'}, {'id': '1', 'name': 'default'}, {'id': 2, 'name': 'alice'}])
        with self.assertRaises(checks.CheckError):
            checks.check_users(EXPECT, [{'id': 1, 'name': 'default'}])
        checks.check_preauth(EXPECT, [{'id': 2, 'reusable': True}, {'id': 1, 'used': True}])
        with self.assertRaises(checks.CheckError):
            checks.check_preauth(EXPECT, [{'id': 2, 'reusable': True, 'used': True}, {'id': 1, 'used': True}])
        checks.check_records(EXPECT, [{'name': 'b1-nas.ts.local', 'type': 'A', 'value': '100.64.0.250'}])
        with self.assertRaises(checks.CheckError):
            checks.check_records(EXPECT, [])
        checks.check_server_key(EXPECT, {'publicKey': SERVER_KEY, 'legacyPublicKey': 'mkey:' + '3' * 64})
        with self.assertRaises(checks.CheckError):
            checks.check_server_key(EXPECT, {'publicKey': 'mkey:' + '4' * 64})

    def test_client_identity(self):
        status = {'BackendState': 'Running', 'Self': {'ID': '2', 'PublicKey': NODE_KEY, 'HostName': 'b1-ts-alice',
                                                      'TailscaleIPs': ['fd7a:115c:a1e0::2', '100.64.0.2']}}
        checks.check_client(EXPECT, status)
        for change in ({'BackendState': 'NeedsLogin'}, {'AuthURL': 'https://x/register/y'}):
            with self.assertRaises(checks.CheckError):
                checks.check_client(EXPECT, dict(status, **change))
        for key, value in (('ID', '3'), ('PublicKey', 'nodekey:' + '5' * 64), ('TailscaleIPs', ['100.64.0.3']),
                           ('HostName', 'other')):
            with self.assertRaises(checks.CheckError):
                checks.check_client(EXPECT, dict(status, Self=dict(status['Self'], **{key: value})))

    def test_main_prints_fixed_lines_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'expect.json').write_text(json.dumps(EXPECT))
            (root / 'nodes.json').write_text(json.dumps(nodes_ok()))
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(checks.main(['nodes', str(root / 'expect.json'), str(root / 'nodes.json'), '2', '0']), 0)
                self.assertEqual(checks.main(['client', str(root / 'expect.json'), str(root / 'nodes.json')]), 1)
                self.assertEqual(checks.main(['bogus', str(root / 'expect.json')]), 1)
            text = out.getvalue()
            self.assertIn('PASS', text)
            self.assertNotIn(NODE_KEY, text)
            self.assertNotIn('100.64.0', text)


class EventProfileTest(unittest.TestCase):
    def test_profiles(self):
        expected, auth, logs = profile.profile('arm', '1')
        self.assertEqual(expected[:7], ('ca_private', 'tls_private', 'target_api', 'target_noise', 'target_derp',
                                        'ha_noise', 'configtest_keys'))
        self.assertEqual(expected[-1], 'client_identity_after')
        self.assertLess(expected.index('client_identity_before'), expected.index('ha_preauth'))
        self.assertIn('installed_keys', expected)
        self.assertEqual(auth, frozenset({'target_api', 'ha_preauth'}))
        self.assertIn('installed_server', logs)
        self.assertIn('client_alice', logs)
        expected, _auth, logs = profile.profile('x86', '0')
        self.assertNotIn('client_identity_before', expected)
        self.assertIn('probe_b_identity', expected)
        self.assertNotIn('installed_keys', expected)
        self.assertNotIn('installed_server', logs)
        for bad in (('', '1'), ('arm', '2'), ('ARM', '0')):
            with self.assertRaises(ValueError):
                profile.profile(*bad)

    def test_configure_sets_controller_lists(self):
        profile.configure({'HS_REAL_ARCH': 'arm', 'HS_REAL_INSTALLER': '0'})
        self.assertEqual(profile.events.EXPECTED, profile.profile('arm', '0')[0])
        self.assertEqual(profile.events.LOGS, profile.profile('arm', '0')[2])
        with self.assertRaises(ValueError):
            profile.configure({})


def real_shaped_state(machine, node, old, lock):
    """A tailscaled.state shaped like ipn/store's: base64 values, the profile JSON with a Config persist."""
    prof = {'ControlURL': 'http://192.0.2.10:28080', 'Hostname': 'b1-ts-alice',
            'Config': {'PrivateNodeKey': node, 'OldPrivateNodeKey': old, 'NetworkLockKey': lock,
                       'NodeID': '2', 'UserProfile': {'ID': 2, 'LoginName': 'alice'}}}
    enc = lambda value: base64.b64encode(value.encode()).decode()
    return json.dumps({'_machinekey': enc(machine), '_current-profile': enc('profile-8e33'),
                       'profile-8e33': enc(json.dumps(prof)), '_profiles': enc(json.dumps({'8e33': {'ID': '8e33'}}))}).encode()


class PrivateSourcesTest(unittest.TestCase):
    def test_real_state_covers_old_node_and_network_lock_keys(self):
        machine, node = 'privkey:' + 'a' * 64, 'privkey:' + 'b' * 64
        old, lock = 'privkey:' + 'c' * 64, 'nlpriv:' + 'd' * 64
        values = private.client_keys(real_shaped_state(machine, node, old, lock))
        for value in (machine, node, old, lock, 'a' * 64, 'b' * 64, 'c' * 64, 'd' * 64):
            self.assertIn(value, values)
        zero_old = private.client_keys(real_shaped_state(machine, node, 'privkey:' + '0' * 64, lock))
        self.assertNotIn('0' * 64, zero_old)

    def test_volume_all_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'v.tar'
            with tarfile.open(path, 'w') as archive:
                for name, value in (('noise.key', b'privkey:' + b'1' * 64), ('derp.key', b'privkey:' + b'2' * 64),
                                    ('db.sqlite', b'not a key')):
                    info = tarfile.TarInfo(name)
                    info.size = len(value)
                    archive.addfile(info, io.BytesIO(value))
            values = private.volume_all_keys(path)
            self.assertIn('1' * 64, values)
            self.assertIn('privkey:' + '2' * 64, values)
            empty = root / 'e.tar'
            with tarfile.open(empty, 'w') as archive:
                info = tarfile.TarInfo('db.sqlite')
                info.size = 1
                archive.addfile(info, io.BytesIO(b'x'))
            with self.assertRaises(ValueError):
                private.volume_all_keys(empty)
            bad = root / 'b.tar'
            with tarfile.open(bad, 'w') as archive:
                info = tarfile.TarInfo('derp.key')
                info.type = tarfile.SYMTYPE
                info.linkname = '/etc/shadow'
                archive.addfile(info)
            with self.assertRaises(ValueError):
                private.volume_all_keys(bad)


class ConvertHelpersTest(unittest.TestCase):
    def test_select_member(self):
        member = lambda slug, role='addon': SimpleNamespace(slug=slug, role=role)
        layout = SimpleNamespace(members=(member('1b7b4ce7_woow-headscale'), member('1b7b4ce7_woow-omnigent'),
                                          member('share', 'folder')))
        self.assertEqual(convert.select_member(layout).slug, '1b7b4ce7_woow-headscale')
        with self.assertRaises(RuntimeError):
            convert.select_member(SimpleNamespace(members=(member('x_woow-headscale'), member('y_woow-headscale'))))
        with self.assertRaises(RuntimeError):
            convert.select_member(SimpleNamespace(members=(member('woow-headscale-old'),)))

    def test_instrument_keeps_configtest_output_and_volume(self):
        calls = []

        class Tmp:
            runner = SimpleNamespace(relay=lambda args, stdout, timeout: (calls.append(('export', args[-1])),
                                                                          stdout.write(b'tar-bytes')))
            def name(self, role):
                return 'j-' + role
            def run(self, role, *args, **kwargs):
                calls.append(('run', role))
                return SimpleNamespace(stdout=b'configtest ok', stderr=b'')
            def remove_volume(self, role):
                calls.append(('remove', role))
        tmp = Tmp()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            saved = convert.instrument(tmp, root)
            tmp.run('hs-configtest', 'image', ['configtest'])
            tmp.run('other', 'image', [])
            tmp.remove_volume('hs-check')
            tmp.remove_volume('hapg')
            self.assertEqual(saved, {'configtest_output': True, 'configtest_volume': True})
            self.assertEqual(calls, [('run', 'hs-configtest'), ('run', 'other'), ('export', 'j-hs-check'),
                                     ('remove', 'hs-check'), ('remove', 'hapg')])
            self.assertEqual((root / 'configtest-private.tar').read_bytes(), b'tar-bytes')
            self.assertEqual((root / 'configtest-private.tar').stat().st_mode & 0o777, 0o600)
            self.assertIn(b'configtest ok', (root / 'configtest-output.log').read_bytes())

    def test_sha256(self):
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(b'abc')
            handle.flush()
            self.assertEqual(convert.file_sha256(handle.name),
                             'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')


class FakeRunner:
    """podman(...) answers from a script of JSON documents per command."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def podman(self, *args, **kwargs):
        self.calls.append(args)
        key = args[0] if args[0] != 'exec' else 'exec:' + args[2]
        value = self.answers[key]
        value = value() if callable(value) else value
        return SimpleNamespace(returncode=0, stdout=json.dumps(value).encode())


def inspect_doc(started='t0', pid=7, network='hs-real-abcdefgh'):
    return [{'Id': 'c1', 'State': {'Running': True, 'StartedAt': started, 'Pid': pid}, 'HostConfig': {},
             'NetworkSettings': {'Networks': {network: {}}}}]


class InstallContinuityTest(unittest.TestCase):
    def status(self, **changes):
        me = {'ID': '2', 'PublicKey': NODE_KEY, 'TailscaleIPs': ['100.64.0.2', 'fd7a:115c:a1e0::2']}
        me.update(changes)
        return {'BackendState': 'Running', 'Self': me}

    def test_real_client_reconnects(self):
        clock = [0.0]
        runner = FakeRunner({'container': inspect_doc(), 'exec:headscale': nodes_ok(online2=True),
                             'exec:tailscale': self.status()})
        cont = install.RealContinuity(runner, 'hs-real-abcdefgh', 'hs-ralice-abcdefgh', EXPECT,
                                      clock=lambda: clock[0], sleep=lambda s: clock.__setitem__(0, clock[0] + s))
        out = io.StringIO()
        with redirect_stdout(out):
            cont.verify('srv', 'installed')
        self.assertIn('HEADSCALE_REAL_CONTINUITY=installed:PASS', out.getvalue())

    def test_offline_then_online_and_failures(self):
        clock = [0.0]
        seq = [nodes_ok(online2=False), nodes_ok(online2=True)]
        runner = FakeRunner({'container': inspect_doc(), 'exec:headscale': lambda: seq.pop(0) if len(seq) > 1 else seq[0],
                             'exec:tailscale': self.status()})
        cont = install.RealContinuity(runner, 'hs-real-abcdefgh', 'hs-ralice-abcdefgh', EXPECT,
                                      clock=lambda: clock[0], sleep=lambda s: clock.__setitem__(0, clock[0] + s))
        with redirect_stdout(io.StringIO()):
            cont.verify('srv', 'rolled_back')
        changed = FakeRunner({'container': inspect_doc(), 'exec:headscale': nodes_ok(),
                              'exec:tailscale': self.status(PublicKey='nodekey:' + '9' * 64)})
        cont = install.RealContinuity(changed, 'hs-real-abcdefgh', 'hs-ralice-abcdefgh', EXPECT,
                                      clock=lambda: clock[0], sleep=lambda s: None)
        with self.assertRaisesRegex(RuntimeError, 'client_identity_changed'):
            cont.verify('srv', 'restarted')
        extra = FakeRunner({'container': inspect_doc(), 'exec:headscale': nodes_ok(extra=[server_node(3, 'p', 'bob', ['100.64.0.3'])]),
                            'exec:tailscale': self.status()})
        cont = install.RealContinuity(extra, 'hs-real-abcdefgh', 'hs-ralice-abcdefgh', EXPECT,
                                      clock=lambda: clock[0], sleep=lambda s: None)
        with self.assertRaisesRegex(RuntimeError, 'installed_nodes_not_ha_nodes'):
            cont.verify('srv', 'installed')
        replaced = [inspect_doc(), inspect_doc(pid=8)]
        moved = FakeRunner({'container': lambda: replaced.pop(0) if len(replaced) > 1 else replaced[0],
                            'exec:headscale': nodes_ok(), 'exec:tailscale': self.status()})
        cont = install.RealContinuity(moved, 'hs-real-abcdefgh', 'hs-ralice-abcdefgh', EXPECT,
                                      clock=lambda: clock[0], sleep=lambda s: None)
        with self.assertRaisesRegex(RuntimeError, 'client_process_replaced'):
            cont.verify('srv', 'installed')

    def test_deadline_without_reconnect(self):
        clock = [0.0]
        runner = FakeRunner({'container': inspect_doc(), 'exec:headscale': nodes_ok(online2=False),
                             'exec:tailscale': dict(self.status(), BackendState='Starting')})
        cont = install.RealContinuity(runner, 'hs-real-abcdefgh', 'hs-ralice-abcdefgh', EXPECT,
                                      clock=lambda: clock[0], sleep=lambda s: clock.__setitem__(0, clock[0] + 1))
        with self.assertRaisesRegex(RuntimeError, 'continuity_deadline'):
            cont.verify('srv', 'installed')

    def test_no_client_x86(self):
        runner = FakeRunner({'exec:headscale': nodes_ok(online2=False)})
        cont = install.RealContinuity(runner, 'hs-real-abcdefgh', '', EXPECT, clock=lambda: 0.0, sleep=lambda s: None)
        with redirect_stdout(io.StringIO()):
            cont.verify('srv', 'installed')

    def test_inputs_and_log_bytes(self):
        with self.assertRaisesRegex(RuntimeError, 'invalid_real_root'):
            install.inputs('/tmp/headscale-internal.abcdefgh', 'hs-rtarget-abcdefgh', 'hs-rplane-abcdefgh')
        text = 'é' * 700000
        data = install.log_bytes(text)
        self.assertLessEqual(len(data), 1024 * 1024)
        data.decode('utf-8')


class CaptureTest(unittest.TestCase):
    def test_status_vocabulary_only(self):
        text = '\n'.join(['HEADSCALE_REAL_HA_ARM=PASS', 'Registered: secret-ish free text',
                          'Real client kept node id, node key, addresses and hostname, logged in: PASS',
                          'product convert: PASS users=3 nodes=2 ha_api_keys_removed=1 target_api_keys_kept=1 dns_records=1',
                          'pong from x via DERP(lab) in 3ms', 'controller exit=0', 'CHECK nodes: FAIL node_not_online',
                          'last runner step: real_client', 'last runner step: ../etc'])
        lines = capture.status_lines(text)
        self.assertIn('HEADSCALE_REAL_HA_ARM=PASS', lines)
        self.assertIn('controller exit=0', lines)
        self.assertNotIn('Registered: secret-ish free text', lines)
        self.assertNotIn('pong from x via DERP(lab) in 3ms', lines)
        self.assertIn('last runner step: real_client', lines)
        self.assertEqual(len(lines), 6)

    def test_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'attempt.json'
            target.write_text('{}')
            with self.assertRaises(SystemExit):
                capture.main([str(target), 'scope', '--', 'true'])


class ShellSyntaxTest(unittest.TestCase):
    def test_bash_syntax(self):
        for name in ('headscale-real-runner.sh', 'headscale-real-test.sh'):
            subprocess.run(['bash', '-n', str(HERE / name)], check=True)


if __name__ == '__main__':
    unittest.main()
