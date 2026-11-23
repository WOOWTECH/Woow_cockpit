"""Only incremental producer/error/ENOSPC/cancellation cases; no live services."""
import errno
import traceback
import unittest
from unittest.mock import patch

import emqx_private_boundary as boundary
import test_emqx_real_candidate as fixtures
from woowbackup import ha_emqx

MARKER = b'generated-only-private-"\\-secret'


def producer(registry):
    for source in sorted(boundary.SOURCES):
        registry.register(source, [MARKER] if source in ('source-cookie', 'backup-key') else [])


class PrivateBoundaryTests(unittest.TestCase):
    def test_registration_precedes_builder_and_incomplete_producer_refuses(self):
        for callback in (lambda r: None,
                         lambda r: r.register('unknown-source', [MARKER]),
                         lambda r: r.register('tls', [MARKER], encoding='unsupported')):
            with patch.object(boundary, 'build_verified_candidate') as build:
                with self.assertRaisesRegex(boundary.PrivateFailure, '^candidate-refused$'):
                    boundary.build_registered_candidate(object(), producer=callback)
                build.assert_not_called()

    def test_complete_producer_acknowledged_before_execution_and_logs_discarded(self):
        work = type('Work', (), {'log': lambda *a: self.fail('raw log escaped')})()
        def build(bound):
            bound.log('UNREGISTERED-PRIVATE-LOG')
            return {'private-path': 'internal-only'}
        with patch.object(boundary, 'build_verified_candidate', side_effect=build):
            self.assertEqual(boundary.build_registered_candidate(work, producer=producer),
                             {'private-path': 'internal-only'})

    def test_failures_do_not_publish_exception_or_producer_values(self):
        for error in (OSError(errno.ENOSPC, MARKER.decode()), RuntimeError(MARKER.decode()),
                      KeyboardInterrupt(MARKER.decode()), SystemExit(MARKER.decode())):
            def failed(registry):
                raise error
            try:
                boundary.build_registered_candidate(object(), producer=failed)
            except boundary.PrivateFailure as exc:
                formatted = ''.join(traceback.format_exception(exc))
                self.assertNotIn(MARKER.decode(), formatted)
                self.assertIn(str(exc), ('candidate-refused', 'candidate-cancelled'))
            else:
                self.fail('failure was accepted')

    def test_registry_bounds_duplicates_atomicity_and_sealing(self):
        registry = boundary.Registry()
        for values in ([b''], ['text'], [b'x' * (boundary.MAX_VALUE + 1)],
                       [b'x'] * (boundary.MAX_VALUES + 1)):
            with self.assertRaises(boundary.PrivateFailure):
                registry.register('tls', values)
        producer(registry)
        with self.assertRaises(boundary.PrivateFailure):
            registry.register('tls', [])
        registry.seal()
        with self.assertRaises(boundary.PrivateFailure):
            registry.register('tls', [])
        self.assertNotIn(MARKER.decode(), repr(registry))

    def test_actual_reader_outputs_registered_before_builder_without_persistence(self):
        calls = []
        def reader(source):
            calls.append(source)
            return [MARKER] if source == 'backup-key' else []
        source = boundary.Producer({name: lambda name=name: reader(name)
                                    for name in boundary.SOURCES})
        registry = boundary.Registry()
        source(registry)
        registry.seal()
        self.assertEqual(set(calls), boundary.SOURCES)
        with self.assertRaises(boundary.PrivateFailure):
            registry.scan(MARKER)
        for readers in ({}, {'unknown': lambda: []}):
            with self.assertRaises(boundary.PrivateFailure):
                boundary.Producer(readers)
        broken = {name: lambda: [] for name in boundary.SOURCES}
        with patch.object(boundary, 'build_verified_candidate') as build:
            with self.assertRaises(boundary.PrivateFailure):
                boundary.build_registered_candidate(object(), producer=boundary.Producer(broken))
            build.assert_not_called()

    def test_total_registration_limit_is_atomic(self):
        registry = boundary.Registry()
        values = [bytes([index]) * boundary.MAX_VALUE for index in range(17)]
        with self.assertRaisesRegex(boundary.PrivateFailure, '^private-registration-refused$'):
            registry.register('tls', values)
        registry.register('tls', [])
        self.assertEqual(registry._total, 0)
        self.assertEqual(registry._values, set())

    def test_diagnostic_scan_supported_encodings_and_bounds(self):
        import base64
        import json
        from urllib.parse import quote_from_bytes
        registry = boundary.Registry()
        producer(registry)
        registry.seal()
        for value in (MARKER, base64.b64encode(MARKER), MARKER.hex().encode(),
                      quote_from_bytes(MARKER, safe='').encode(),
                      json.dumps(MARKER.decode())[1:-1].encode()):
            with self.assertRaisesRegex(boundary.PrivateFailure, '^private-diagnostic-leak$'):
                registry.scan(value)
        registry.scan(b'{"status":"refused"}')
        with self.assertRaises(boundary.PrivateFailure):
            registry.scan(b'x' * (boundary.MAX_TOTAL + 1))


class CleanupIncrementTests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.RealCallerTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.case.fixture()

    def invoke(self):
        with patch.object(fixtures.caller, 'build_verified_candidate',
                          side_effect=lambda *a, **k: boundary.build_registered_candidate(
                              *a, producer=producer, **k)):
            return self.case.invoke()

    def test_enospc_during_build_package_and_directory_creation(self):
        for phase in ('build', 'package', 'mkdir'):
            def failed(*args, **kwargs):
                if phase != 'mkdir':
                    staging = args[4] if phase == 'build' else args[3]
                    (staging / 'partial-private').write_bytes(MARKER)
                raise OSError(errno.ENOSPC, MARKER.decode())
            obj, name = ((fixtures.caller.tempfile, 'mkdtemp') if phase == 'mkdir' else
                         (ha_emqx, '_build_candidate' if phase == 'build' else '_package_candidate'))
            self.case.runtime.events.clear()
            with patch.object(obj, name, side_effect=failed):
                with self.assertRaisesRegex(boundary.PrivateFailure, '^candidate-refused$'):
                    self.invoke()
            self.assertEqual(set(self.case.root.iterdir()), {self.case.path})
            if phase != 'mkdir':
                self.assertEqual(self.case.runtime.events[-1], ('cleanup',))
            else:
                self.case.temp_factory.assert_not_called()

    def test_cancellation_in_build_and_role_cleanup_still_cleans_private_files(self):
        for phase in ('build', 'cleanup'):
            def cancelled(*args, **kwargs):
                if phase == 'build':
                    (args[4] / 'partial-private').write_bytes(MARKER)
                raise KeyboardInterrupt(MARKER.decode())
            obj, name = ((ha_emqx, '_build_candidate') if phase == 'build' else
                         (self.case.runtime, 'cleanup'))
            with patch.object(obj, name, side_effect=cancelled):
                with self.assertRaisesRegex(boundary.PrivateFailure, '^candidate-cancelled$'):
                    self.invoke()
            self.assertEqual(set(self.case.root.iterdir()), {self.case.path})

    def test_enospc_and_filesystem_cleanup_failure_refuses_with_private_residue(self):
        with patch.object(ha_emqx, '_package_candidate',
                          side_effect=OSError(errno.ENOSPC, MARKER.decode())), \
             patch.object(fixtures.caller.shutil, 'rmtree',
                          side_effect=OSError(errno.ENOSPC, MARKER.decode())):
            with self.assertRaisesRegex(boundary.PrivateFailure, '^candidate-refused$'):
                self.invoke()
        self.assertTrue(any(p.is_dir() for p in self.case.root.iterdir()))
        self.assertEqual(self.case.runtime.events[-1], ('cleanup',))
