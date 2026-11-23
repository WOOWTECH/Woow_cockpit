"""Synthetic native contract fixtures; never claimed as real broker inventory."""
import base64
import copy
import hashlib
import io
import json
import unittest

from emqx_persisted_values import capture_persisted_values
from emqx_private_boundary import PrivateFailure
from test_emqx_semantic_readers import binary, term


def native_documents():
    result = {}
    # Representative fixtures only, not an asserted full real deployment list.
    for table in ('emqx_authn_mnesia', 'emqx_app', 'emqx_admin', 'emqx_admin_jwt',
                  'emqx_acl', 'emqx_retainer_message'):
        raw = ('synthetic-checkpoint-' + table).encode()
        doc = {'contract': 'emqx-mnesia-checkpoint-json-v1', 'version': '5.8.9',
            'input_sha256': hashlib.sha256(raw).hexdigest(), 'input_bytes': len(raw),
            'complete': True, 'schema_validated': True, 'table': table,
            'record_name': table, 'attributes': ['private_value'],
            'rows': [term('tuple', [term('atom', table),
                binary(('synthetic-private-' + table).encode())])]}
        result[table] = raw, doc
    return result


def captured(native=None, *, inventory_edit=None, export_edit=None, stream_factory=io.BytesIO,
             scope='target'):
    native = native_documents() if native is None else native
    descriptors, by_raw = [], {}
    for table, (raw, original) in native.items():
        doc = dict(original, input_sha256=hashlib.sha256(raw).hexdigest(), input_bytes=len(raw))
        descriptors.append({key: doc[key] for key in
                           ('table', 'input_sha256', 'input_bytes', 'record_name', 'attributes')})
        by_raw[raw] = doc
    inventory = {'contract': 'emqx-persistent-inventory-v1', 'version': '5.8.9',
        'generation': 'synthetic-generation', 'scope': scope,
        'complete': True, 'eof': True, 'tables': descriptors}
    if inventory_edit:
        inventory_edit(inventory)
    def exporter(table, raw):
        doc = copy.deepcopy(by_raw[raw])
        if export_edit:
            export_edit(doc)
        return json.dumps(doc).encode()
    return capture_persisted_values(
        private_inventory=lambda: io.BytesIO(json.dumps(inventory).encode()),
        private_table=lambda table: stream_factory(native[table][0]), exporter=exporter,
        generation='synthetic-generation', scope=scope)


class PersistedValueTests(unittest.TestCase):
    def test_multi_table_nonempty_jwt_superset_scans_all_encodings(self):
        companion = captured()
        self.assertEqual(len(companion.tables), 6)
        secret = b'synthetic-private-emqx_admin_jwt'
        for payload in (secret, base64.b64encode(secret), secret.hex().encode()):
            with self.assertRaisesRegex(PrivateFailure, '^persisted-private-leak$'):
                companion.scan(payload)
        self.assertNotIn('synthetic', repr(companion))
        companion.scan(b'bounded-safe-diagnostic')

    def test_empty_jwt_requires_real_native_contract_and_eof(self):
        native = native_documents()
        native['emqx_admin_jwt'][1]['rows'] = []
        self.assertIn('emqx_admin_jwt', captured(native).tables)
        for edit in (lambda doc: doc.update(complete=False),
                     lambda doc: doc.update(schema_validated=False),
                     lambda doc: doc.update(input_sha256='0' * 64)):
            with self.assertRaises(PrivateFailure):
                captured(native, export_edit=edit)

    def test_inventory_and_table_coverage_mismatch(self):
        for edit in (lambda inv: inv.update(eof=False),
                     lambda inv: inv.update(complete=False),
                     lambda inv: inv.update(generation='other'),
                     lambda inv: inv.update(scope='source'),
                     lambda inv: inv['tables'].append(inv['tables'][0]),
                     lambda inv: inv['tables'][0].update(attributes=['other'])):
            with self.assertRaises(PrivateFailure):
                captured(inventory_edit=edit)

    def test_native_unknown_nonempty_terms_refuse_and_late_eof_failure_closes(self):
        def unsupported(doc):
            doc['rows'][0]['value'][1] = term('etf', 'do-not-decode')
        with self.assertRaises(PrivateFailure):
            captured(export_edit=unsupported)
        streams = []
        class FailedFinish(io.BytesIO):
            def finish(self):
                raise ValueError('private-native-error')
        def stream(raw):
            result = FailedFinish(raw); streams.append(result); return result
        with self.assertRaisesRegex(PrivateFailure, '^persisted-values-unsupported$'):
            captured(stream_factory=stream)
        self.assertTrue(all(s.closed for s in streams))

    def test_binary_nested_charlist_and_fullscan_integration(self):
        from emqx_runtime_workflow import CombinedRegistry
        native = native_documents()
        native['emqx_admin_jwt'][1]['rows'][0]['value'][1] = term('map', [
            [binary(b'private-field'), term('list', [term('integer', x) for x in b'jwt-charlist'])],
            [binary(b'opaque-field'), binary(b'\x00\xff\x80secret')]])
        companion = captured(native, scope='source')
        class Base:
            def scan(self, raw):
                pass
        combined = CombinedRegistry(Base(), Base(), [companion])
        for value in (b'jwt-charlist', b'\x00\xff\x80secret', b'private-field'):
            with self.assertRaises(PrivateFailure):
                combined.scan(value)


    def test_inventory_cardinality_not_limited_to_six_or_two(self):
        native = native_documents()
        for index in range(16):
            table = 'synthetic_additional_table_' + str(index)
            raw = table.encode()
            template = copy.deepcopy(native['emqx_admin'][1])
            template.update(table=table, record_name=table,
                rows=[term('tuple', [term('atom', table), binary(b'synthetic-extra-value')])])
            native[table] = raw, template
        companion = captured(native)
        self.assertEqual(len(companion.tables), 22)
        with self.assertRaises(PrivateFailure):
            companion.scan(b'synthetic-extra-value')

    def test_preflight_automatically_carries_observed_target_companion(self):
        from test_emqx_target_capture import ObservedTargetTests
        from test_emqx_runtime_credentials import source_registry, transport, PASSWORD
        from emqx_runtime_workflow import login_preflight
        import tempfile
        from pathlib import Path
        helper = ObservedTargetTests()
        readers = helper.run_capture(helper.observation())
        with tempfile.TemporaryDirectory() as directory:
            session = login_preflight(source_registry=source_registry(),
                source_counts={'backup-key': 1, 'source-options': 0, 'source-cookie': 1},
                target_readers=readers, private_transport=transport,
                username=b'fixture-admin', password=PASSWORD,
                evidence_directory=Path(directory))
            self.assertTrue((Path(directory) / 'credential-preflight.json').exists())
            with self.assertRaises(PrivateFailure):
                session.registry.scan(b'synthetic-private-emqx_admin_jwt')

    def test_preflight_source_companion_blocks_persisted_value_in_real_publish_bytes(self):
        from test_emqx_runtime_credentials import source_registry, readers, transport, PASSWORD
        from emqx_runtime_workflow import login_preflight
        import tempfile
        from pathlib import Path
        native = native_documents()
        native['emqx_admin_jwt'][1]['rows'][0]['value'][1] = binary(b'passed')
        companion = captured(native, scope='source')
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(PrivateFailure):
                login_preflight(source_registry=source_registry(),
                    source_counts={'backup-key': 1, 'source-options': 0, 'source-cookie': 1},
                    target_readers=readers(), private_transport=transport,
                    username=b'fixture-admin', password=PASSWORD,
                    evidence_directory=Path(directory), source_persisted_values=companion,
                    source_generation='synthetic-generation')
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_cold_history_bridge_uses_existing_inventory_contract_and_overall_finish(self):
        from emqx_persisted_values import capture_cold_persisted_values
        from emqx_semantic_readers import Values
        events = []
        raw = b'synthetic-cold-log'
        path = 'data/emqx/data/mnesia/emqx_admin_jwt.DCD'
        expected = {path: {'kind': 'dcd', 'bytes': len(raw),
                           'sha256': hashlib.sha256(raw).hexdigest()}}
        # Contract fixture only; actual HistoryInventory/native tests belong to
        # Mencius. This test verifies bridge ordering, not native decoding.
        class History:
            def __init__(self, receipts, decoder=None):
                self.receipts = receipts
            def consume(self, name, payload):
                events.append('consume')
                self.assert_payload = payload == raw and name == path
            def finish(self):
                events.append('history-finish')
                values = Values(); values.add(b'synthetic-historical-jwt'); return values
        def finish():
            events.append('archive-finish')
        result = capture_cold_persisted_values(expected=expected,
            private_file=lambda _: io.BytesIO(raw), finish_inventory=finish,
            generation='synthetic-generation', history_factory=History)
        self.assertEqual(events, ['consume', 'archive-finish', 'history-finish'])
        self.assertEqual(result.files, {path})
        with self.assertRaises(PrivateFailure):
            result.scan(b'synthetic-historical-jwt')
        def failed_finish():
            raise ValueError('synthetic-late-integrity-failure')
        with self.assertRaises(PrivateFailure):
            capture_cold_persisted_values(expected=expected, private_file=lambda _: io.BytesIO(raw),
                finish_inventory=failed_finish, generation='synthetic-generation', history_factory=History)

    def test_owner_readers_bind_companion_without_restricted_effective_profile(self):
        from emqx_target_capture import bind_target_persisted
        from test_emqx_runtime_credentials import readers
        companion = captured()
        calls = []
        def observed(name, reader):
            calls.append(name)
            return reader()
        original = readers()
        once = {name: (lambda name=name, reader=reader: observed(name, reader))
                for name, reader in original.items()}
        bound = bind_target_persisted(once, persisted_values=companion,
                                     generation='synthetic-generation')
        self.assertIs(bound.persisted_values, companion)
        self.assertEqual(len(bound), 5)
        for reader in bound.values():
            with reader() as stream:
                self.assertTrue(stream.read())
        self.assertCountEqual(calls, original)
        with self.assertRaises(PrivateFailure):
            bind_target_persisted(readers(), persisted_values=companion, generation='stale')

    def test_native_names_rejected_before_any_table_callback(self):
        from emqx_persisted_values import capture_persisted_values
        from unittest.mock import Mock
        for field in ('table', 'record_name', 'attributes'):
            for bad in ('', '../secret', 'a/b', '..', 'a\\b', '/tmp/value', 'a\n',
                        'a\x00b', 'a\tb', 'MixedCase', 'é', '1table', '_table',
                        'a-b', 'a.' , 'a' * 256):
                inv = {'contract': 'emqx-persistent-inventory-v1', 'version': '5.8.9',
                    'generation': 'synthetic-generation', 'scope': 'target',
                    'complete': True, 'eof': True, 'tables': [
                        {'table': 'safe_table', 'record_name': 'safe_record',
                         'attributes': ['safe_attr'], 'input_bytes': 1, 'input_sha256': '0' * 64},
                        {'table': 'second_table', 'record_name': 'safe_record',
                         'attributes': ['safe_attr'], 'input_bytes': 1, 'input_sha256': '0' * 64}]}
                # Bad metadata in the LAST descriptor also prevents opening first.
                inv['tables'][1][field] = [bad] if field == 'attributes' else bad
                table, export = Mock(), Mock()
                with self.subTest(field=field, bad=repr(bad)), self.assertRaises(PrivateFailure):
                    capture_persisted_values(
                        private_inventory=lambda: io.BytesIO(json.dumps(inv).encode()),
                        private_table=table, exporter=export,
                        generation='synthetic-generation', scope='target')
                table.assert_not_called(); export.assert_not_called()

    def test_native_atom_name_boundary_and_known_emqx_shapes(self):
        from emqx_persisted_values import native_name
        for value in ('a', 'emqx_admin_jwt', 'user_info', 'api_secret_hash',
                      'a' * 255):
            self.assertTrue(native_name(value))
        native = native_documents()
        name = 'a' * 255
        doc = copy.deepcopy(native['emqx_admin'][1])
        doc.update(table=name, record_name=name, attributes=[name],
                   rows=[term('tuple', [term('atom', name), binary(b'boundary-private')])])
        native[name] = (b'synthetic-boundary-checkpoint', doc)
        companion = captured(native)
        self.assertIn(name, companion.tables)
        with self.assertRaises(PrivateFailure):
            companion.scan(b'boundary-private')

    def test_evidence_scope_and_generation_binding_negative_cases(self):
        from emqx_target_capture import bind_target_persisted, ObservedTargetReaders
        from emqx_runtime_workflow import login_preflight
        from test_emqx_runtime_credentials import source_registry, readers, PASSWORD
        from unittest.mock import Mock
        from pathlib import Path
        import tempfile
        target, source = captured(), captured(scope='source')
        for companion, generation in ((source, 'synthetic-generation'),
                                       (target, 'other'), (target, ''), (target, None)):
            with self.subTest(), self.assertRaises(PrivateFailure):
                bind_target_persisted(readers(), persisted_values=companion, generation=generation)
        valid = bind_target_persisted(readers(), persisted_values=target,
                                     generation='synthetic-generation')
        invalid_target = []
        for companion, generation in ((source, 'synthetic-generation'),
                                       (target, 'other'), (target, None)):
            mapping = ObservedTargetReaders(valid)
            mapping.persisted_values = companion
            if generation is not None:
                mapping.generation = generation
            invalid_target.append(mapping)
        variations = [{'target_readers': mapping} for mapping in invalid_target]
        variations += [{'source_persisted_values': companion, 'source_generation': generation}
                       for companion, generation in ((target, 'synthetic-generation'),
                           (source, 'other'), (source, ''), (source, None))]
        with tempfile.TemporaryDirectory() as directory:
            for changes in variations:
                transport = Mock()
                kwargs = dict(source_registry=source_registry(),
                    source_counts={'backup-key': 1, 'source-options': 0, 'source-cookie': 1},
                    target_readers=valid, private_transport=transport,
                    username=b'fixture-admin', password=PASSWORD, evidence_directory=Path(directory))
                kwargs.update(changes)
                with self.subTest(), self.assertRaises(PrivateFailure):
                    login_preflight(**kwargs)
                transport.assert_not_called()
                self.assertEqual(list(Path(directory).iterdir()), [])
