"""Synthetic contract regression only; no native exporter/broker execution."""
import json
import unittest

from test_emqx_semantic_readers import RAW, binary, term, mnesia
from emqx_target_capture import (mqtt_password_table, mqtt_table_reader,
                                 exact_target_readers, TargetCaptureUnsupported)
from emqx_target_snapshots import register_target_snapshots
from emqx_runtime_credentials import RuntimeRegistry
from emqx_private_boundary import PrivateFailure


def fixture():
    return mnesia(rows=[term('tuple', [term('atom', 'user_info'),
        term('tuple', [binary(b'fixture-group'), binary(b'fixture-user')]),
        binary(b'fixture-hash'), binary(b''), term('atom', 'false')])])


class TargetCaptureTests(unittest.TestCase):
    def capture(self, doc):
        return mqtt_password_table(RAW, exporter=lambda _: json.dumps(doc).encode(),
                                   username_group=b'fixture-group')

    def test_projection_and_explicit_empty_salt(self):
        self.assertEqual(json.loads(self.capture(fixture()))['records'],
            [{'username': 'fixture-user', 'password_hash': 'fixture-hash', 'salt': ''}])

    def test_empty_requires_complete_native_export(self):
        self.assertEqual(json.loads(self.capture(mnesia(rows=[])))['records'], [])
        doc = mnesia(rows=[]); doc['complete'] = False
        with self.assertRaises(TargetCaptureUnsupported):
            self.capture(doc)

    def test_missing_wrong_group_scram_reference_binary_duplicate_refuse(self):
        docs = []
        doc = fixture(); doc['rows'][0]['value'].pop(3); docs.append(doc)
        doc = fixture(); doc['rows'][0]['value'][1]['value'][0] = binary(b'other'); docs.append(doc)
        doc = fixture(); doc['rows'][0]['value'][2] = binary(b'\xff'); docs.append(doc)
        doc = fixture(); doc['rows'][0]['value'][3] = binary(b'${SECRET}'); docs.append(doc)
        doc = fixture(); doc['rows'] *= 2; docs.append(doc)
        docs.append(mnesia('emqx_authn_scram_mnesia'))
        docs.append(mnesia('emqx_app'))
        for doc in docs:
            with self.subTest(), self.assertRaises(TargetCaptureUnsupported) as caught:
                self.capture(doc)
            self.assertEqual(str(caught.exception), 'target-capture-unsupported')

    def test_exporter_once_and_stream_compatible(self):
        calls = []
        def export(raw):
            calls.append(raw)
            return json.dumps(fixture()).encode()
        reader = mqtt_table_reader(RAW, exporter=export, username_group=b'fixture-group')
        self.assertEqual(calls, [RAW])
        with reader() as stream:
            self.assertEqual(json.load(stream)['schema'], 1)

    def test_no_exporter_or_full_target_shortcut(self):
        with self.assertRaises(TargetCaptureUnsupported):
            mqtt_password_table(RAW, exporter=None, username_group=b'fixture-group')
        readers = exact_target_readers(RAW,
            exporter=lambda _: json.dumps(fixture()).encode(),
            username_group=b'fixture-group')
        with readers['mqtt-auth']() as stream:
            self.assertEqual(json.load(stream)['records'][0]['username'], 'fixture-user')
        for category in ('api-keys', 'connectors', 'tls', 'target-bootstrap'):
            with self.assertRaises(TargetCaptureUnsupported):
                readers[category]()
        registry = RuntimeRegistry()
        with self.assertRaises(PrivateFailure):
            register_target_snapshots(registry, readers)
        with self.assertRaises(PrivateFailure):
            registry.summary()

    def test_errors_do_not_echo_private_diagnostics(self):
        def broken(_):
            raise ValueError('fixture-private-secret')
        with self.assertRaises(TargetCaptureUnsupported) as caught:
            mqtt_password_table(RAW, exporter=broken, username_group=b'fixture-group')
        self.assertNotIn('fixture-private', str(caught.exception))


class ObservedTargetTests(unittest.TestCase):
    def observation(self):
        import base64
        from emqx_target_capture import EFFECTIVE_ROOTS
        return {'contract': 'emqx-target-observation-v1', 'schema': 1,
            'version': '5.8.9', 'complete': True, 'generation': 'synthetic-generation',
            'quiesced': True, 'references': [],
            'persistent_inventory': {'complete': True, 'generation': 'synthetic-generation',
                'tables': ['emqx_authn_mnesia', 'emqx_app', 'emqx_admin',
                           'emqx_admin_jwt', 'emqx_acl', 'emqx_retainer_message']},
            'mqtt_checkpoint': base64.b64encode(RAW).decode(),
            'app_checkpoint': base64.b64encode(b'synthetic-app-checkpoint').decode(),
            'effective_config': {'root_presence': sorted(EFFECTIVE_ROOTS), 'document': {
                'authentication': [{'mechanism': 'password_based',
                    'backend': 'built_in_database', 'user_id_type': 'username'}],
                'connectors': {}, 'bridges': {}, 'gateway': {}, 'exhook': {'servers': []},
                'cluster': {'discovery_strategy': 'manual'}, 'rpc': {'driver': 'tcp'},
                'node': {'dist_proto': 'inet_tcp'}, 'api_key': {'bootstrap_file': ''},
                'listeners': {'tcp': {'default': {'enable': True, 'bind': 1883}},
                    'ssl': {}, 'ws': {}, 'wss': {}},
                'dashboard': {'listeners': {'http': {'bind': 18083}, 'https': {'bind': 0}}}}},
            'bootstrap': {'generation': 'synthetic-generation', 'complete': True,
                'producer': 'private-bootstrap-input-v1',
                'records': [{'username': 'synthetic-admin', 'password': 'synthetic-password'}]}}

    def run_capture(self, doc, app=None, calls=None):
        import hashlib
        import io
        from emqx_target_capture import observed_target_readers
        def export(raw):
            if calls is not None:
                calls.append(raw)
            output = fixture() if raw == RAW else (app if app is not None else mnesia('emqx_app', []))
            output = dict(output, input_sha256=hashlib.sha256(raw).hexdigest(), input_bytes=len(raw))
            return json.dumps(output).encode()
        from test_emqx_persisted_values import captured, native_documents
        native = native_documents()
        native['emqx_authn_mnesia'] = (RAW, fixture())
        native['emqx_app'] = (b'synthetic-app-checkpoint',
                            app if app is not None else mnesia('emqx_app', []))
        companion = captured(native)
        return observed_target_readers(private_capture=lambda: io.BytesIO(json.dumps(doc).encode()),
            exporter=export, username_group=b'fixture-group', persisted_values=companion)

    def test_five_readers_register_and_scan_actual_bootstrap_values(self):
        calls = []
        readers = self.run_capture(self.observation(), calls=calls)
        self.assertEqual(len(calls), 2)
        registry = RuntimeRegistry()
        result = register_target_snapshots(registry, readers)
        self.assertEqual(result, {'mqtt-auth': 2, 'api-keys': 0, 'connectors': 0,
                                 'tls': 0, 'target-bootstrap': 2})
        for secret in (b'synthetic-admin', b'synthetic-password', b'fixture-hash'):
            with self.assertRaises(PrivateFailure):
                registry.scan(secret)
        registry.scan(b'bounded-safe-result')

    def test_required_presence_version_complete_and_generation(self):
        import copy
        doc = self.observation()
        variations = []
        for field, value in [('version', '5.9.0'), ('schema', True), ('complete', False),
                             ('quiesced', False), ('references', ['env:SECRET'])]:
            changed = copy.deepcopy(doc); changed[field] = value; variations.append(changed)
        for root in doc['effective_config']['document']:
            changed = copy.deepcopy(doc)
            del changed['effective_config']['document'][root]; variations.append(changed)
        changed = copy.deepcopy(doc); changed['effective_config']['root_presence'].pop(); variations.append(changed)
        changed = copy.deepcopy(doc); changed['effective_config']['document']['unknown'] = {}; variations.append(changed)
        changed = copy.deepcopy(doc); changed['bootstrap']['generation'] = 'other'; variations.append(changed)
        for changed in variations:
            with self.subTest(), self.assertRaises(TargetCaptureUnsupported):
                self.run_capture(changed)

    def test_not_absent_tls_reference_and_unknown_paths_refuse(self):
        import copy
        for root, replacement in [
            ('connectors', {'mqtt': {'existing': {'password': 'synthetic-secret'}}}),
            ('bridges', {'mqtt': {}}), ('gateway', {'stomp': {}}),
            ('api_key', {'bootstrap_file': '/private/keys'}),
            ('listeners', {'tcp': {}, 'ssl': {'default': {'enable': False, 'keyfile': '/key'}}, 'ws': {}, 'wss': {}}),
            ('dashboard', {'listeners': {'http': {'bind': 18083}, 'https': {'bind': False}}}),
            ('dashboard', {'listeners': {'http': {'bind': 18083}, 'https': {'bind': 0, 'keyfile': '/key'}}}),
            ('node', {'dist_proto': 'inet_tls'})]:
            changed = copy.deepcopy(self.observation()); changed['effective_config']['document'][root] = replacement
            with self.subTest(root=root), self.assertRaises(TargetCaptureUnsupported):
                self.run_capture(changed)

    def test_existing_app_hash_never_becomes_plaintext_even_if_disabled(self):
        with self.assertRaises(TargetCaptureUnsupported):
            self.run_capture(self.observation(), app=mnesia('emqx_app'))
        for field, value in [('complete', False), ('attributes', []), ('schema_validated', False)]:
            app = mnesia('emqx_app', []); app[field] = value
            with self.subTest(field=field), self.assertRaises(PrivateFailure):
                self.run_capture(self.observation(), app=app)

    def test_bootstrap_missing_masked_unknown_and_empty_refuse(self):
        import copy
        for records in ([], [{'username': 'synthetic-admin'}],
                        [{'username': 'synthetic-admin', 'password': '******'}],
                        [{'username': 'synthetic-admin', 'password': '${SECRET}'}],
                        [{'username': 'synthetic-admin', 'password': 'x', 'unknown': 'x'}]):
            doc = copy.deepcopy(self.observation()); doc['bootstrap']['records'] = records
            with self.subTest(), self.assertRaises(TargetCaptureUnsupported):
                self.run_capture(doc)

    def test_private_stream_closed_and_errors_fixed(self):
        import io
        from emqx_target_capture import observed_target_readers
        stream = io.BytesIO(b'{"private-secret":true}')
        with self.assertRaises(TargetCaptureUnsupported) as caught:
            observed_target_readers(private_capture=lambda: stream, exporter=None, username_group=b'x')
        self.assertTrue(stream.closed)
        self.assertEqual(str(caught.exception), 'target-capture-unsupported')

    def test_uncovered_or_incomplete_inventory_refuses_before_projection(self):
        import copy
        for inventory in (None,
                {'complete': False, 'generation': 'synthetic-generation', 'tables': []},
                {'complete': True, 'generation': 'other', 'tables': ['emqx_authn_mnesia', 'emqx_app']},
                {'complete': True, 'generation': 'synthetic-generation',
                 'tables': ['emqx_authn_mnesia', 'emqx_app', 'emqx_admin_jwt']},
                {'complete': True, 'generation': 'synthetic-generation',
                 'tables': ['emqx_authn_mnesia', 'emqx_app', 'emqx_admin_jwt.DCD']}):
            doc = copy.deepcopy(self.observation())
            doc['persistent_inventory'] = inventory
            calls = []
            with self.subTest(), self.assertRaises(TargetCaptureUnsupported):
                self.run_capture(doc, calls=calls)
            self.assertEqual(calls, [])
