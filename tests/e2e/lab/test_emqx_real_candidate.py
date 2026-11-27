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
            # The candidate is patched out above, so is the readback read from it (ha_emqx.candidate_readback).
            stack.enter_context(patch.object(ha_emqx, 'candidate_readback', return_value=({}, ('file',))))
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

    def test_builder_completes_its_own_source_stream_after_preflight(self):
        self.fixture()
        consumed = []
        original = gate.habackup.iter_entries

        def observed(stream, select=None, report=None, **kwargs):
            # Spy only: every byte/parser/final-tag check is the real reader.
            yield from original(stream, select, report, **kwargs)
            if report is not None:
                consumed.append((stream, report))

        with patch.object(gate.habackup, 'iter_entries', side_effect=observed):
            self.invoke()
        self.assertEqual(len(consumed), 2, 'one preflight and one builder pass required')
        self.assertIsNot(consumed[0][0], consumed[1][0])
        self.assertIsNot(consumed[0][1], consumed[1][1])
        for stream, report in consumed:
            self.assertTrue(stream.closed)
            self.assertTrue(report.complete)
            self.assertEqual(report.addon.slug, 'woow-emqx')

    def test_public_conversion_never_reuses_the_private_candidate_build(self):
        # Owner decision 2026-11-23 「決定1 做」: the blanket PRESERVATION_BLOCKER is gone; the public conversion is
        # the product path and enforces the protections itself (tests/backup/test_ha_emqx_product.py). What stays
        # here: a private build leaves nothing the public conversion picks up -- given this lab's bound work (not a
        # product job's Work: no adapter) it stops before any runtime event and writes no output.
        self.fixture()
        self.invoke()
        before = list(self.runtime.events)
        self.assertFalse(hasattr(ha_emqx, 'PRESERVATION_BLOCKER'))
        with self.assertRaises((BackupError, AttributeError)):
            ha_emqx.convert(self.work, self.app, True, self.root / 'public-output')
        self.assertEqual(self.runtime.events, before)
        self.assertFalse((self.root / 'public-output').exists())

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
        self.assertEqual(set(self.root.iterdir()), {self.path})
        self.assertEqual(self.work.open, 'original-open')

    def test_cleanup_failure_refuses_result(self):
        self.fixture()
        self.runtime.cleanup_failed = True
        with self.assertRaisesRegex(RuntimeError, 'real-fixture temporary objects remain'):
            self.invoke()
        self.assertEqual(set(self.root.iterdir()), {self.path})

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
        self.assertEqual(set(self.root.iterdir()), {self.path})

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

    def test_private_staging_required_before_transport(self):
        self.fixture()
        for mode in (0o755, 0o770, 0o1700):
            self.root.chmod(mode)
            try:
                with self.assertRaisesRegex(gate.Refused, 'unsafe-staging'):
                    self.invoke()
            finally:
                self.root.chmod(0o700)
        real = self.root
        link = real / 'link'
        link.symlink_to(real, target_is_directory=True)
        self.root = link
        try:
            with self.assertRaisesRegex(gate.Refused, 'unsafe-staging'):
                self.invoke()
            nested = real / 'nested'
            nested.mkdir(mode=0o700)
            self.root = link / 'nested'
            with self.assertRaisesRegex(gate.Refused, 'unsafe-staging'):
                self.invoke()
        finally:
            self.root = real
        self.assertEqual(self.runtime.events, [])

    def test_volume_path_escape_and_alias_refused_before_transport(self):
        self.fixture()
        for volume in ('../escape', '/tmp/escape', 'bad/name', 'reviewed-log', ''):
            self.target.data_volume = volume
            with self.assertRaisesRegex(gate.Refused, 'invalid-target-volumes'):
                self.invoke()
        self.assertEqual(self.runtime.events, [])

    def test_exclusive_work_directory_ignores_preexisting_output_links(self):
        self.fixture()
        outside = self.root / 'sentinel'
        outside.write_bytes(b'unchanged')
        (self.root / 'candidate-output').symlink_to(outside)
        result = self.invoke()
        self.assertEqual(outside.read_bytes(), b'unchanged')
        for path in result.values():
            private = path.parents[2]
            self.assertEqual(private.parent, self.root)
            self.assertEqual(private.stat().st_mode & 0o777, 0o700)
            self.assertFalse(private.is_symlink())

    def test_temp_factory_failure_removes_private_directory(self):
        self.fixture()
        with patch.object(caller.tempctr, 'TempObjects', side_effect=RuntimeError('factory failed')):
            with self.assertRaisesRegex(RuntimeError, 'factory failed'):
                caller.build_verified_candidate(
                    self.work, self.app, self.adapter, self.target, self.path, self.root,
                    'j20261121T000000Z-12345678', expected_sha256=self.digest, keys=self.keys)
        self.assertEqual(set(self.root.iterdir()), {self.path})

    def test_invalid_job_refused_before_transport(self):
        self.fixture()
        with self.assertRaisesRegex(gate.Refused, 'invalid-job-id'):
            caller.build_verified_candidate(
                self.work, self.app, self.adapter, self.target, self.path, self.root,
                '../escape', expected_sha256=self.digest, keys=self.keys)
        self.assertEqual(self.runtime.events, [])

    def test_packaging_failure_and_cancellation_remove_partial_files(self):
        self.fixture()
        for failure in (RuntimeError('package failed'), KeyboardInterrupt()):
            def failed_package(work, tmp, target, staging, *args, **kwargs):
                (staging / 'partial-private').write_bytes(b'fixture-private')
                raise failure
            with patch.object(ha_emqx, '_package_candidate', side_effect=failed_package):
                with self.assertRaises(type(failure)):
                    self.invoke()
            self.assertEqual(set(self.root.iterdir()), {self.path})
            self.assertEqual(self.runtime.events[-1], ('cleanup',))

    def test_private_cleanup_error_is_fixed_field_and_does_not_return_result(self):
        self.fixture()
        self.runtime.cleanup_failed = True
        with patch.object(caller.shutil, 'rmtree', side_effect=OSError('PRIVATE-PATH-MARKER')):
            with self.assertRaisesRegex(RuntimeError, '^real-fixture private cleanup failed$'):
                self.invoke()
