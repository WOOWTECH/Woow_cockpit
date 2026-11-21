"""Real binding/decrypt/scan/build/package; fake runtime, no Podman operations."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_real_candidate as caller
import ha_real_fixture as gate
from emqx_ha_candidate import Budget
from tests.backup import hafixtures as hx
from woowbackup import ha_emqx, hasecuretar, nested
from woowbackup.podman import Result
from woowbackup.errors import BackupError


class Runtime:
    def __init__(self):
        self.events = []
        self.label = '5.8.9'
        self.cleanup_failed = False
        self.source = None
        self.imported = b''

    def podman(self, *args, **kwargs):
        self.events.append(args)
        if args[:2] == ('image', 'inspect'):
            return Result(0, json.dumps({'org.opencontainers.image.version': self.label}).encode(), b'')
        if args[:2] == ('volume', 'inspect'):
            return Result(0, b'/fake/log', b'')
        if args[:2] == ('unshare', 'stat'):
            return Result(0, b'1000 1000 700', b'')
        raise AssertionError('unexpected runtime operation')

    def volume(self, role):
        self.events.append(('volume', role))

    def volume_import(self, role, produce):
        out = io.BytesIO()
        produce(out)
        self.imported = out.getvalue()

    def stop(self, role, **kwargs):
        self.events.append(('stop', role))
        return 0

    def remove(self, role):
        self.events.append(('remove', role))

    def remove_volume(self, role):
        self.events.append(('remove-volume', role))

    def user_ids(self, *args):
        return (1000, 1000)

    def volume_export(self, role, handle, **kwargs):
        handle.write(hx.tar_bytes([
            {'name': '.', 'type': 'dir', 'uid': 1000, 'gid': 1000},
            {'name': 'mnesia/emqx@fixture/schema.DAT', 'data': b'candidate-only', 'uid': 1000, 'gid': 1000}]))

    def cleanup(self):
        self.events.append(('cleanup',))
        return self.cleanup_failed


class RealCallerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.runtime = Runtime()
        self.work = SimpleNamespace(runner=lambda app: self.runtime, guard=Budget(), abort=None,
                                    checkpoint=lambda: None, phase=lambda name: None,
                                    log=lambda text: self.fail('unexpected log'),
                                    addon_member='original-member', addon_info='original-info', open='original-open')
        self.target = SimpleNamespace(image='sha256:' + 'a' * 64,
                                      data_volume='reviewed-data', log_volume='reviewed-log')
        self.adapter = SimpleNamespace(owner_ids=lambda: (nested.IdMap('0 100000 65536'),) * 2)
        self.keys = hasecuretar.Keys(hx.PASSWORD)
        self.app = SimpleNamespace(id='emqx')

    def fixture(self, *, version='5.9.0', state='stopped', encrypted=True, arch='aarch64'):
        self.slug = 'fedcba98_woow-emqx'
        addon = {'system': {'slug': 'woow-emqx'}, 'user': {'image': 'test/' + arch + '-addon-woow-emqx',
                 'options': {'password': 'PRIVATE-OPTIONS-MARKER'}}, 'version': version, 'state': state}
        payload = hx.tar_bytes([
            {'name': 'addon.json', 'data': json.dumps(addon).encode()},
            {'name': 'data/emqx/node.name', 'data': b'emqx@fixture'},
            {'name': 'data/emqx/data/configs/cluster.hocon', 'data': b'mqtt {max_packet_size = "1MB"}'},
            {'name': 'data/emqx/data/mnesia/emqx@fixture/schema.DAT', 'data': b'SOURCE-DATA-MARKER'},
            {'name': 'data/emqx/node.cookie', 'data': b'PRIVATE-COOKIE-MARKER'},
        ], compress=True)
        doc = hx.ha_doc((self.slug,), protected=encrypted)
        doc['addons'][0]['version'] = version
        self.path = self.root / 'encrypted.tar'
        self.path.write_bytes(hx.outer_bytes([(self.slug + '.tar.gz', hx.v3_encrypt(payload)
                                             if encrypted else payload)], doc))
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def broker(self, work, tmp, target, src, node, **kwargs):
        self.runtime.source = src
        self.assertEqual(work.addon_member('woow-emqx'), self.slug)
        self.assertEqual(work.addon_info('woow-emqx').version, src.addon.version)
        self.assertEqual(node, 'emqx@fixture')
        return {'default_admin': False, 'authn': [], 'strict': ('deny', 'ignore'),
                'counts': {}, 'export': '/fake/export'}

    def export(self, work, tmp, name, staging):
        path = staging / 'broker-export.tar'
        path.write_bytes(b'fake-runtime-export')
        return path

    def invoke(self):
        with contextlib.ExitStack() as stack:
            self.temp_factory = stack.enter_context(patch.object(caller.tempctr, 'TempObjects', return_value=self.runtime))
            stack.enter_context(patch.object(ha_emqx, 'ha_broker', side_effect=self.broker))
            stack.enter_context(patch.object(ha_emqx, 'take_export', side_effect=self.export))
            stack.enter_context(patch.object(ha_emqx, 'candidate_from_target', return_value=({}, {}, ('deny', 'ignore'), [])))
            return caller.build_verified_candidate(
                self.work, self.app, self.adapter, self.target, self.path, self.root,
                'j20261121T000000Z-12345678', expected_sha256=self.digest, keys=self.keys)

    def test_actual_binding_builder_and_packager_use_source_identity(self):
        for version, arch in [('5.9.0', 'aarch64'), ('5.8.9', 'amd64')]:
            with self.subTest(version=version, arch=arch):
                self.fixture(version=version, arch=arch)
                result = self.invoke()
                self.assertEqual(self.runtime.source.addon.version, version)
                self.assertEqual(self.runtime.source.addon.arch, arch)
                self.assertIn(b'SOURCE-DATA-MARKER', self.runtime.imported)
                self.assertNotIn(b'PRIVATE-COOKIE-MARKER', self.runtime.imported)
                self.assertNotIn(b'PRIVATE-OPTIONS-MARKER', self.runtime.imported)
                self.assertEqual(set(result), {'reviewed-data', 'reviewed-log'})
                for path in result.values():
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(self.runtime.events[-1], ('cleanup',))
                self.assertEqual(self.work.open, 'original-open')
                self.assertEqual(self.work.addon_member, 'original-member')
                self.assertEqual(self.work.addon_info, 'original-info')
                self.assertFalse(hasattr(self.work, 'keys'))
                for artifact in self.root.rglob('*'):
                    if artifact.is_file():
                        self.assertFalse(hx.PASSWORD.encode() in artifact.read_bytes(),
                                         'private key persisted in an artifact')
                for path in result.values():
                    path.unlink()

    def test_invalid_sources_refused_before_temp_objects(self):
        cases = [('hot', {'state': 'started'}), ('plain', {'encrypted': False}),
                 ('version', {'version': '99.0.0'}), ('digest', {}), ('wrong-key', {}), ('missing-key', {})]
        for name, options in cases:
            with self.subTest(case=name):
                self.fixture(**options)
                self.keys = hasecuretar.Keys(hx.PASSWORD)
                if name == 'digest':
                    self.digest = '0' * 64
                if name == 'wrong-key':
                    self.keys = hasecuretar.Keys(hx.WRONG_PASSWORD)
                if name == 'missing-key':
                    self.keys = None
                with self.assertRaises((gate.Refused, BackupError)):
                    self.invoke()
                self.temp_factory.assert_not_called()
                self.assertEqual(self.runtime.imported, b'')
                self.assertFalse((self.root / 'candidate-output').exists())

    def test_target_label_and_pin_are_required(self):
        self.fixture()
        for label, image in [(None, 'sha256:' + 'a' * 64), ('5.8.8', 'sha256:' + 'a' * 64),
                             ('5.8.9', 'emqx:latest')]:
            with self.subTest(label=label, image=image):
                self.runtime.label, self.target.image = label, image
                with self.assertRaises(gate.Refused):
                    self.invoke()
                self.temp_factory.assert_not_called()

    def test_real_builder_failure_cleans_roles_without_packaging(self):
        self.fixture()
        def failed_broker(*args, **kwargs):
            raise RuntimeError('offline broker failure')
        self.broker = failed_broker
        with self.assertRaisesRegex(RuntimeError, 'offline broker failure'):
            self.invoke()
        self.assertIn(b'SOURCE-DATA-MARKER', self.runtime.imported)
        self.assertEqual(self.runtime.events[-1], ('cleanup',))
        self.assertFalse((self.root / 'candidate-output').exists())
        self.assertEqual(self.work.open, 'original-open')

    def test_cleanup_failure_refuses_result(self):
        self.fixture()
        self.runtime.cleanup_failed = True
        with self.assertRaisesRegex(RuntimeError, 'real-fixture temporary objects remain'):
            self.invoke()

    def test_source_change_during_build_refuses_result_after_cleanup(self):
        self.fixture()
        original_broker = self.broker
        def changing_broker(*args, **kwargs):
            readings = original_broker(*args, **kwargs)
            with self.path.open('ab') as out:
                out.write(b'changed')
            return readings
        self.broker = changing_broker
        with self.assertRaisesRegex(gate.Refused, 'source-changed'):
            self.invoke()
        self.assertEqual(self.runtime.events[-1], ('cleanup',))
        self.assertEqual(self.work.open, 'original-open')

    def test_wrong_app_and_malformed_digest_refused_before_transport(self):
        self.fixture()
        self.app.id = 'headscale'
        with self.assertRaisesRegex(gate.Refused, 'wrong-app-binding'):
            self.invoke()
        self.app.id = 'emqx'
        self.digest = 'not-a-digest'
        with self.assertRaisesRegex(gate.Refused, 'invalid-source-digest'):
            self.invoke()
        self.assertEqual(self.runtime.events, [])
