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
