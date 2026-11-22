"""One-shot five-category producer contracts; no real broker acceptance claim."""
import base64
import copy
import hashlib
import io
import json
import unittest

from emqx_target_capture import capture_observed_target_readers
from emqx_target_snapshots import register_target_snapshots
from emqx_runtime_credentials import RuntimeRegistry
from emqx_private_boundary import PrivateFailure
import test_emqx_target_capture as target_fixtures
from test_emqx_persisted_values import native_documents
from test_emqx_semantic_readers import mnesia, term


class CompleteTargetTests(unittest.TestCase):
    def sources(self):
        observation = target_fixtures.ObservedTargetTests().observation()
        native = native_documents()
        # A genuine multi-table checkpoint can have identical raw bytes for
        # different exported tables: dispatch must use table, not a raw-byte key.
        checkpoint = b'synthetic-multi-table-checkpoint'
        mqtt = target_fixtures.fixture()
        mqtt['rows'][0]['value'][1]['value'][0] = term('atom', 'fixture-group')
        native['emqx_authn_mnesia'] = checkpoint, mqtt
        native['emqx_app'] = checkpoint, mnesia('emqx_app', [])
        for key in ('mqtt_checkpoint', 'app_checkpoint'):
            observation[key] = base64.b64encode(checkpoint).decode()
        inventory = {'contract': 'emqx-persistent-inventory-v1', 'version': '5.8.9',
            'generation': 'synthetic-generation', 'scope': 'target',
            'complete': True, 'eof': True, 'tables': []}
        exports = {}
        for table, (raw, original) in native.items():
            doc = dict(original, input_bytes=len(raw), input_sha256=hashlib.sha256(raw).hexdigest())
            inventory['tables'].append({key: doc[key] for key in
                ('table', 'record_name', 'attributes', 'input_bytes', 'input_sha256')})
            exports[table] = raw, json.dumps(doc).encode()
        return observation, inventory, exports

    def capture(self, observation, inventory, exports, calls):
        def observed():
            calls.append(('observation',))
            return io.BytesIO(json.dumps(observation).encode())
        def listed():
            calls.append(('inventory',))
            return io.BytesIO(json.dumps(inventory).encode())
        def opened(table):
            calls.append(('read', table))
            return io.BytesIO(exports[table][0])
        def exported(table, raw):
            calls.append(('export', table))
            self.assertEqual(raw, exports[table][0])
            return exports[table][1]
        return capture_observed_target_readers(private_capture=observed,
            private_inventory=listed, private_table=opened, exporter=exported,
            username_group=b'fixture-group', generation='synthetic-generation')

    def test_all_five_readers_with_full_inventory_capture_exactly_once(self):
        observation, inventory, exports = self.sources()
        calls = []
        readers = self.capture(observation, inventory, exports, calls)
        self.assertEqual(calls.count(('observation',)), 1)
        self.assertEqual(calls.count(('inventory',)), 1)
        for table in exports:
            self.assertEqual(calls.count(('read', table)), 1)
            self.assertEqual(calls.count(('export', table)), 1)
        before = copy.deepcopy(calls)
        runtime = RuntimeRegistry()
        register_target_snapshots(runtime, readers)
        self.assertEqual(calls, before)
        self.assertEqual(set(readers), {'mqtt-auth', 'api-keys', 'connectors', 'tls', 'target-bootstrap'})
        for payload in (b'synthetic-private-emqx_admin_jwt', b'synthetic-private-emqx_acl'):
            with self.assertRaises(PrivateFailure):
                readers.persisted_values.scan(payload)
        with self.assertRaises(PrivateFailure):
            runtime.scan(b'synthetic-password')

    def test_generation_mismatch_refuses_before_inventory_and_reads(self):
        observation, inventory, exports = self.sources()
        observation['generation'] = 'other'
        calls = []
        with self.assertRaises(PrivateFailure):
            self.capture(observation, inventory, exports, calls)
        self.assertEqual(calls, [('observation',)])

    def test_projection_input_mismatch_and_existing_app_rows_refuse(self):
        for variation in ('binding', 'api-hash'):
            observation, inventory, exports = self.sources()
            if variation == 'binding':
                observation['mqtt_checkpoint'] = base64.b64encode(b'other-checkpoint').decode()
            else:
                raw, encoded = exports['emqx_app']
                doc = json.loads(encoded)
                doc['rows'] = mnesia('emqx_app')['rows']
                exports['emqx_app'] = raw, json.dumps(doc).encode()
            with self.subTest(variation=variation), self.assertRaises(PrivateFailure):
                self.capture(observation, inventory, exports, [])

    def test_unsafe_native_table_refuses_before_table_read(self):
        observation, inventory, exports = self.sources()
        inventory['tables'][-1]['table'] = '../escape'
        calls = []
        with self.assertRaises(PrivateFailure):
            self.capture(observation, inventory, exports, calls)
        self.assertEqual(calls, [('observation',), ('inventory',)])

    def test_short_private_values_still_scan_exactly(self):
        from test_emqx_semantic_readers import binary
        observation, inventory, exports = self.sources()
        raw, encoded = exports['emqx_admin_jwt']
        doc = json.loads(encoded)
        doc['rows'][0]['value'][1] = term('list', [binary(b'0'), binary(b'1'),
            term('atom', 'true'), term('atom', 'false')])
        exports['emqx_admin_jwt'] = raw, json.dumps(doc).encode()
        readers = self.capture(observation, inventory, exports, [])
        for value in (b'0', b'1', b'true', b'false'):
            with self.subTest(value=value), self.assertRaises(PrivateFailure):
                readers.persisted_values.scan(value)
