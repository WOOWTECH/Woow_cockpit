"""Synthetic owner transports; no live broker/network or production credentials."""
import base64
import io
import json
from pathlib import Path
import tempfile
import traceback
import unittest
from unittest.mock import patch

from emqx_private_boundary import Registry, SOURCES, PrivateFailure, MAX_VALUE
import emqx_runtime_credentials as runtime
import emqx_target_snapshots as snapshots
import emqx_runtime_workflow as workflow

TOKEN = b'fixture.jwt-private-token'
PASSWORD = b'fixture-dashboard-password'


def doc(records):
    return json.dumps({'schema': 1, 'complete': True, 'records': records}).encode()


def target_docs():
    cert = '-----BEGIN CERTIFICATE-----\nZml4dHVyZS1jZXJ0\n-----END CERTIFICATE-----\n'
    key = '-----BEGIN PRIVATE KEY-----\nZml4dHVyZS1rZXk=\n-----END PRIVATE KEY-----\n'
    return {
        'mqtt-auth': doc([{'username': 'fixture-mqtt-user', 'password_hash': 'fixture-hash', 'salt': 'fixture-salt'}]),
        'api-keys': doc([{'api_key': 'fixture-api-id', 'api_secret': 'fixture-api-secret'}]),
        'connectors': doc([{'type': 'mqtt', 'username': 'fixture-connector', 'password': 'fixture-connector-password'}]),
        'tls': doc([{'cert_pem': cert, 'key_pem': key, 'password': ''}]),
        'target-bootstrap': doc([{'username': 'fixture-bootstrap', 'password': 'fixture-bootstrap-password'}]),
    }


def readers(docs=None):
    return {name: lambda raw=raw: io.BytesIO(raw) for name, raw in (docs or target_docs()).items()}


def transport(username, password):
    return 200, 'application/json', io.BytesIO(json.dumps({'token': TOKEN.decode(), 'version': '5.8.9'}).encode())


def source_registry(secret=b'fixture-source-cookie'):
    registry = Registry()
    for category in SOURCES:
        registry.register(category, [b'fixture-backup-key'] if category == 'backup-key'
                          else [secret] if category == 'source-cookie' else [])
    registry.seal()
    return registry


class RuntimeTests(unittest.TestCase):
    def test_token_registered_before_private_use_and_all_encodings_scan(self):
        registry = runtime.RuntimeRegistry()
        snapshots.register_target_snapshots(registry, readers())
        credential = runtime.login_registered(registry, transport, username=b'fixture-admin', password=PASSWORD)
        self.assertNotIn(TOKEN.decode(), repr(credential))
        self.assertEqual(credential.with_bearer(lambda raw: raw), b'Bearer ' + TOKEN)
        for raw in (TOKEN, b'Bearer ' + TOKEN, PASSWORD, base64.b64encode(TOKEN), TOKEN.hex().encode()):
            with self.assertRaises(PrivateFailure):
                registry.scan(raw)
        registry.scan(b'{"phase":"preflight","result":"passed"}')

    def test_input_registration_precedes_request_and_token_commit_precedes_return(self):
        class Checked(runtime.RuntimeRegistry):
            def register_bundle(self, values, **kwargs):
                if 'runtime-login-token' in values:
                    raise RuntimeError(TOKEN.decode())
                super().register_bundle(values, **kwargs)
        registry = Checked()
        def checked(username, password):
            self.assertIn(password, registry._values)
            return transport(username, password)
        with self.assertRaisesRegex(PrivateFailure, '^runtime-private-refused$'):
            runtime.login_registered(registry, checked, username=b'fixture-admin', password=PASSWORD)
        self.assertNotIn(TOKEN, registry._values)

    def test_invalid_or_late_responses_close_and_never_return_token(self):
        class Late(io.BytesIO):
            def read(self, size):
                if self.tell():
                    raise OSError(TOKEN.decode())
                return super().read(size)
        responses = [(401, 'application/json', io.BytesIO(b'{"token":"private"}')),
                     (200, 'text/plain', io.BytesIO(TOKEN)),
                     (200, 'application/json', io.BytesIO(b'{"token":"one","token":"two"}')),
                     (200, 'application/json', io.BytesIO(b'{"token":"bad token"}')),
                     (200, 'application/json', io.BytesIO(b'{"token":"ok","unknown":"private"}')),
                     (200, 'application/json', io.BytesIO(b'x' * (MAX_VALUE + 1))),
                     (200, 'application/json', Late(b'{"token":"fixture-token"}'))]
        for response in responses:
            with self.subTest(status=response[0]):
                try:
                    runtime.login_registered(runtime.RuntimeRegistry(), lambda *a: response,
                                             username=b'fixture-admin', password=PASSWORD)
                except PrivateFailure as exc:
                    self.assertNotIn(TOKEN.decode(), ''.join(traceback.format_exception(exc)))
                    self.assertTrue(response[2].closed)
                else:
                    self.fail('invalid response accepted')

    def test_transport_error_and_cancellation_have_fixed_diagnostics(self):
        for error in (OSError(TOKEN.decode()), KeyboardInterrupt(TOKEN.decode())):
            def broken(*args):
                raise error
            try:
                runtime.login_registered(runtime.RuntimeRegistry(), broken,
                                         username=b'fixture-admin', password=PASSWORD)
            except PrivateFailure as exc:
                self.assertNotIn(TOKEN.decode(), ''.join(traceback.format_exception(exc)))
                self.assertIn(str(exc), ('runtime-private-refused', 'runtime-private-cancelled'))
            else:
                self.fail('transport error accepted')

    def test_registry_failclosed_and_atomic_limits(self):
        registry = runtime.RuntimeRegistry()
        with self.assertRaises(PrivateFailure):
            registry.scan(b'{}')
        with self.assertRaises(PrivateFailure):
            registry.register_bundle({'runtime-login-token': [b'valid', b'x' * (MAX_VALUE + 1)]})
        self.assertEqual(registry._values, set())
        with self.assertRaises(PrivateFailure):
            registry.register_bundle({'unknown': [TOKEN]})

    def test_snapshot_values_and_tls_derived_forms_are_registered(self):
        registry = runtime.RuntimeRegistry()
        summary = snapshots.register_target_snapshots(registry, readers())
        self.assertEqual(set(summary), runtime.TARGET_CATEGORIES)
        for raw in (b'fixture-api-secret', b'fixture-hash', b'fixture-connector-password',
                    b'fixture-bootstrap-password', b'fixture-key', b'Zml4dHVyZS1rZXk='):
            with self.assertRaises(PrivateFailure):
                registry.scan(raw)
        with self.assertRaises(PrivateFailure):
            snapshots.register_target_snapshots(registry, readers())

    def test_missing_redacted_referenced_incomplete_unknown_snapshots_refuse_atomically(self):
        bad = []
        missing = target_docs()
        del missing['tls']
        bad.append(missing)
        for replacement in (b'{"schema":1,"complete":false,"records":[]}',
                            b'{"schema":1,"complete":true,"records":[],"cursor":"next"}',
                            doc([{'api_key': 'fixture', 'api_secret': '******'}]),
                            doc([{'api_key': 'fixture', 'api_secret': 'file:/secret'}]),
                            doc([{'api_key': 'fixture'}])):
            docs = target_docs()
            docs['api-keys'] = replacement
            bad.append(docs)
        for docs in bad:
            registry = runtime.RuntimeRegistry()
            with self.assertRaises(PrivateFailure):
                snapshots.register_target_snapshots(registry, readers(docs))
            self.assertEqual(registry._values, set())
            with self.assertRaises(PrivateFailure):
                registry.scan(b'{}')

    def test_snapshot_reader_error_closes_and_rolls_back_all_categories(self):
        class Broken(io.BytesIO):
            def read(self, size):
                raise OSError('fixture-private-path')
        stream = Broken()
        inputs = readers()
        inputs['tls'] = lambda: stream
        registry = runtime.RuntimeRegistry()
        with self.assertRaisesRegex(PrivateFailure, '^runtime-private-refused$'):
            snapshots.register_target_snapshots(registry, inputs)
        self.assertTrue(stream.closed)
        self.assertEqual(registry._values, set())
        docs = target_docs()
        docs['connectors'] = doc([{'type': 'unsupported', 'username': 'fixture', 'password': 'fixture-secret'}])
        with self.assertRaises(PrivateFailure):
            snapshots.register_target_snapshots(registry, readers(docs))

    def test_explicit_empty_snapshots_and_bad_tls(self):
        registry = runtime.RuntimeRegistry()
        summary = snapshots.register_target_snapshots(registry, readers({name: doc([]) for name in runtime.TARGET_CATEGORIES}))
        self.assertTrue(all(count == 0 for count in summary.values()))
        for key in ('/etc/key.pem', '-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----'):
            docs = target_docs()
            docs['tls'] = doc([{'cert_pem': 'not-pem', 'key_pem': key, 'password': ''}])
            with self.assertRaises(PrivateFailure):
                snapshots.register_target_snapshots(runtime.RuntimeRegistry(), readers(docs))


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.kwargs = dict(source_registry=source_registry(),
                           source_counts={'backup-key': 1, 'source-options': 0, 'source-cookie': 1},
                           target_readers=readers(), private_transport=transport,
                           username=b'fixture-admin', password=PASSWORD,
                           evidence_directory=self.path)

    def test_false_source_counts_stop_before_transport_and_publication(self):
        for name in workflow.SOURCE_CATEGORIES:
            counts = dict(self.kwargs['source_counts'])
            counts[name] += 1
            with self.subTest(source=name), patch.object(workflow, 'login_registered') as login, \
                 patch.object(workflow, 'publish') as publish:
                with self.assertRaisesRegex(PrivateFailure, '^runtime-private-refused$'):
                    workflow.login_preflight(**dict(self.kwargs, source_counts=counts))
                login.assert_not_called()
                publish.assert_not_called()
        self.assertEqual(list(self.path.iterdir()), [])

    def test_actual_parent_publish_consumes_combined_registry_exact_bytes(self):
        payloads = []
        original = workflow.CombinedRegistry.scan
        def scanned(registry, payload):
            payloads.append(payload)
            return original(registry, payload)
        with patch.object(workflow.CombinedRegistry, 'scan', scanned):
            session = workflow.login_preflight(**self.kwargs)
        evidence = self.path / 'credential-preflight.json'
        self.assertEqual(evidence.read_bytes(), payloads[0])
        self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(evidence.read_bytes())['phase'], 'preflight')
        self.assertEqual(set(session.coverage), SOURCES)
        for secret in (TOKEN, PASSWORD, b'fixture-source-cookie', b'fixture-api-secret'):
            with self.assertRaises(PrivateFailure):
                session.registry.scan(secret)
            self.assertNotIn(secret, evidence.read_bytes())

    def test_source_or_runtime_collision_blocks_file_creation(self):
        for kind in ('source', 'runtime'):
            args = dict(self.kwargs)
            if kind == 'source':
                args['source_registry'] = source_registry(b'passed')
            else:
                args['private_transport'] = lambda *a: (200, 'application/json', io.BytesIO(b'{"token":"passed"}'))
            with self.assertRaises(PrivateFailure):
                workflow.login_preflight(**args)
            self.assertEqual(list(self.path.iterdir()), [])

    def test_token_registration_failure_never_reaches_publisher(self):
        original = runtime.RuntimeRegistry.register_bundle
        def reject(registry, values, **kwargs):
            if 'runtime-login-token' in values:
                raise RuntimeError(TOKEN.decode())
            return original(registry, values, **kwargs)
        with patch.object(runtime.RuntimeRegistry, 'register_bundle', reject), \
             patch.object(workflow, 'publish') as publish:
            with self.assertRaisesRegex(PrivateFailure, '^runtime-private-refused$'):
                workflow.login_preflight(**self.kwargs)
            publish.assert_not_called()
        self.assertEqual(list(self.path.iterdir()), [])

    def test_unsealed_missing_target_or_login_failure_never_publishes(self):
        for change in ({'source_registry': Registry()}, {'target_readers': {}},
                       {'private_transport': lambda *a: (401, 'application/json', io.BytesIO(b'{}'))}):
            with patch.object(workflow, 'publish') as publish:
                with self.assertRaises(PrivateFailure):
                    workflow.login_preflight(**dict(self.kwargs, **change))
                publish.assert_not_called()
            self.assertEqual(list(self.path.iterdir()), [])
