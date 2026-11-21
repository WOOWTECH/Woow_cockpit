"""Offline transport/guard tests; no call reaches owner.sh or a device."""
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'e2e/lab'))
import omnigent_install_rollback as harness
from woowbackup import archive, catalog, keys, podman, storage
from woowbackup.paths import Paths
from . import test_ha_omnigent_install as install_tests


class TransportTests(unittest.TestCase):
    def owner(self):
        execute = mock.Mock(return_value=podman.Result(0, b'1019\n', b''))
        return harness.DeviceOwner(execute=execute), execute

    def test_real_owner_helper_and_systemd_are_bridged_only_to_dev_d(self):
        device, execute = self.owner()
        execute.reset_mock()
        execute.return_value = podman.Result(0, b'payload', b'')
        self.assertEqual(device.runner.read_file('.config/synthetic'), b'payload')
        argv = execute.call_args.args[0]
        self.assertEqual(argv[:3], [str(harness.chain.OWNER), 'd', podman.PYTHON])
        self.assertIn(podman.FILE_HELPER, argv)
        self.assertNotIn('cwd', execute.call_args.kwargs)
        device.runner.systemctl('daemon-reload')
        self.assertEqual(execute.call_args.args[0][2:], [podman.SYSTEMCTL, '--user', 'daemon-reload'])
        out = io.BytesIO()
        abort = lambda: None
        device.runner.relay(['volume', 'export', 'synthetic'], stdout=out,
                            timeout=7, max_output=123, abort=abort)
        self.assertIs(execute.call_args.kwargs['stdout'], out)
        self.assertEqual(execute.call_args.kwargs['timeout'], 7)
        self.assertEqual(execute.call_args.kwargs['max_output'], 123)
        self.assertIs(execute.call_args.kwargs['abort'], abort)

    def test_wrong_owner_or_prefix_fails_before_transport(self):
        execute = mock.Mock(return_value=podman.Result(0, b'0\n', b''))
        with self.assertRaisesRegex(RuntimeError, 'unexpected_dev_d_owner'):
            harness.DeviceOwner(execute=execute)
        device, execute = self.owner()
        execute.reset_mock()
        with self.assertRaisesRegex(RuntimeError, 'unexpected_owner_transport'):
            device.bridge(['/usr/bin/podman', 'ps'], cwd='/home/appowner', env=podman.ROOT_ENV)
        execute.assert_not_called()

    def test_explicit_run_flags_required_without_device_contact(self):
        for args in ([], ['--run'], ['--outer-isolation-confirmed']):
            with self.subTest(args=args), mock.patch.object(sys, 'argv', ['probe', *args]), \
                    mock.patch.object(harness.chain, 'isolated_preflight') as preflight, \
                    mock.patch('sys.stderr', new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as caught:
                    harness.main()
                self.assertEqual(caught.exception.code, 2)
                preflight.assert_not_called()

    def test_one_shot_marker_is_not_rearmed_during_rollback(self):
        runner = mock.Mock()
        state = {'enabled': False, 'count': 0}
        harness.arm_once(runner, 'synthetic-marker', state)
        runner.write_file.assert_not_called()
        state['enabled'] = True
        harness.arm_once(runner, 'synthetic-marker', state)
        harness.arm_once(runner, 'synthetic-marker', state)
        runner.write_file.assert_called_once_with('synthetic-marker', b'fail once\n', 0o600)
        self.assertEqual(state['count'], 1)

    def test_catalog_has_every_volume_secret_writer_and_isolated_quadlets(self):
        device, _ = self.owner()
        raw, quadlets, _ = harness.specification()
        with tempfile.TemporaryDirectory() as tmp:
            app = catalog.validate_entry(raw, paths=Paths(base=Path(tmp)), user_lookup=device.lookup)
        self.assertEqual(set(app.units), set(app.writer_units))
        self.assertEqual(set(app.quadlet_files), set(quadlets))
        self.assertEqual(len(app.volumes), 3)
        references = {line.split('=', 1)[1].split(',')[0] for value in quadlets.values()
                      for line in value.splitlines() if line.startswith('Secret=')}
        self.assertEqual(references, {entry['name'] for entry in app.secrets})
        for value in quadlets.values():
            self.assertIn('Pull=never', value)
            self.assertIn('LogDriver=none', value)
            self.assertNotIn('PublishPort=', value)
            self.assertNotIn('Restart=always', value)

    def test_runtime_mount_or_network_escape_refused(self):
        chain = harness.chain
        _, _, sleeper = harness.specification()
        rows = {}
        for name, image, volume, target, memory in (
            (chain.TARGET, chain.IMAGE, chain.TARGETVOL, '/var/lib/postgresql/data', 128),
            (chain.TARGET_APP, chain.APP_IMAGE, chain.SERVERVOL, '/data', 768),
            (sleeper, chain.IMAGE, chain.PIVOL, '/data/pi-agent', 32)):
            rows[name] = {'Id': name + '-id', 'Name': name, 'Image': image,
                          'HostConfig': {'NetworkMode': 'none', 'Memory': memory * 1024 * 1024},
                          'Mounts': [{'Type': 'volume', 'Name': volume, 'Destination': target}]}
        rows[chain.TARGET_APP]['HostConfig']['NetworkMode'] = 'container:' + chain.TARGET
        runner = mock.Mock()
        runner.podman.side_effect = lambda *args: podman.Result(0, json.dumps([rows[args[-1]]]).encode(), b'')
        harness.validate_runtime(runner, sleeper)
        rows[chain.TARGET_APP]['HostConfig']['NetworkMode'] = 'host'
        with self.assertRaisesRegex(RuntimeError, 'runtime_network_mismatch'):
            harness.validate_runtime(runner, sleeper)
        rows[chain.TARGET_APP]['HostConfig']['NetworkMode'] = 'container:' + chain.TARGET
        rows[sleeper]['Mounts'][0]['Name'] = 'production-volume'
        with self.assertRaisesRegex(RuntimeError, 'runtime_mount_mismatch'):
            harness.validate_runtime(runner, sleeper)


class RealArchiveInstallTests(install_tests.InstallTests):
    """Same real adapter/flows with fixture owner, but actual storage, keys and age/zstd archives."""
    def setUp(self):
        super().setUp()
        self.storage = storage.Storage(self.paths)
        self.deps.storage = self.storage
        self.keys = keys.KeyStore(self.paths)
        self.keys.ensure_device_key()
        self.archive = archive
        self.deps.keys = self.keys
        self.deps.archive = archive
