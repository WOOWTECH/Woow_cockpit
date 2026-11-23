"""Contract tests only: generated fixtures, no broker, filesystem or credentials."""
import base64
import hashlib
import json
import unittest
from unittest.mock import patch

import emqx_semantic_readers as reader

RAW = b'private-fixture-source'


def term(kind, value):
    return {'type': kind, 'value': value}


def binary(value):
    return term('binary', base64.b64encode(value).decode('ascii'))


def envelope(kind):
    return {'contract': kind, 'version': '5.8.9', 'input_sha256': hashlib.sha256(RAW).hexdigest(),
            'input_bytes': len(RAW), 'complete': True}


def hocon(document=None):
    return dict(envelope('emqx-hocon-json-v1'), resolution='disabled', references=[],
                document=document if document is not None else {'authentication': [
                    {'password': 'fixture-password', 'nested': {'fixture-key': 'fixture-value'}}]})


def mnesia(table='emqx_authn_mnesia', rows=None):
    record, attrs = reader.TABLES[table]
    if rows is None:
        rows = [term('tuple', [term('atom', record)] + [binary(b'fixture-secret')] * len(attrs))]
    return dict(envelope('emqx-mnesia-checkpoint-json-v1'), table=table, record_name=record,
                attributes=list(attrs), rows=rows, schema_validated=True)


def adapter(doc):
    return lambda raw: json.dumps(doc).encode()


class SemanticReaderTests(unittest.TestCase):
    def assert_refused(self, callback):
        with self.assertRaises(reader.SemanticRefused) as caught:
            callback()
        self.assertEqual(str(caught.exception), 'emqx-semantic-source-unsupported')
        self.assertTrue(caught.exception.__suppress_context__)

    def test_hocon_complete_tree_keys_and_values_are_private(self):
        values = reader.read_hocon(RAW, adapter(hocon()))
        self.assertIn(b'fixture-password', values.values)
        self.assertIn(b'fixture-key', values.values)
        self.assertIn(b'fixture-value', values.values)
        self.assertNotIn('fixture', repr(values))

    def test_no_default_parser_or_binary_decoder(self):
        for raw in (b'a.b = "fixture-password"', b'{"password":"fixture-password"}',
                    b'\x83h\x02w\x04test', b'not-a-checkpoint'):
            self.assert_refused(lambda: reader.read_hocon(raw))
            self.assert_refused(lambda: reader.read_mnesia(raw, 'emqx_authn_mnesia'))

    def test_hocon_no_resolution_references_or_unknown_contract(self):
        for key, value in [('references', ['include.conf']), ('references', ['${ENV}']),
                           ('resolution', 'enabled'), ('complete', False),
                           ('version', '5.9.0'), ('input_bytes', True),
                           ('input_sha256', '0' * 64), ('unexpected', 'fixture-secret')]:
            doc = hocon(); doc[key] = value
            self.assert_refused(lambda: reader.read_hocon(RAW, adapter(doc)))
        for document in ({'password': '${SECRET}'}, {'password': 'file:/private'},
                         {'tls': {'keyfile': '/private/key'}}, {'init_file': 'users.csv'}):
            self.assert_refused(lambda: reader.read_hocon(RAW, adapter(hocon(document))))

    def test_json_duplicates_trailing_invalid_utf8_and_nonfinite_refuse(self):
        good = json.dumps(hocon()).encode()
        for encoded in (good + b' {}', b'\xff', good.decode().encode('utf-16'), good.replace(b'"complete": true',
                         b'"complete": true, "complete": false'),
                        json.dumps(hocon({'number': float('nan')})).encode()):
            self.assert_refused(lambda: reader.read_hocon(RAW, lambda _: encoded))

    def test_bounds_input_output_depth_nodes_value_count_and_total(self):
        for constant, bound, doc in [('MAX_INPUT', 1, hocon()), ('MAX_OUTPUT', 1, hocon()),
                                     ('MAX_VALUE', 2, hocon()), ('MAX_NODES', 2, hocon()),
                                     ('MAX_VALUES', 2, hocon())]:
            with patch.object(reader, constant, bound):
                self.assert_refused(lambda: reader.read_hocon(RAW, adapter(doc)))
        nested = 'fixture-secret'
        for _ in range(reader.MAX_DEPTH + 1):
            nested = [nested]
        self.assert_refused(lambda: reader.read_hocon(RAW, adapter(hocon({'nested': nested}))))
        values = reader.Values()
        with patch.object(reader, 'MAX_OUTPUT', 3):
            self.assert_refused(lambda: values.add(b'four'))

    def test_all_supported_record_layouts_collect_binary_secrets(self):
        for table in reader.TABLES:
            with self.subTest(table=table):
                self.assertIn(b'fixture-secret', reader.read_mnesia(RAW, table, adapter(mnesia(table))).values)
                self.assertEqual(reader.read_mnesia(RAW, table, adapter(mnesia(table, []))).values, ())

    def test_typed_nested_binary_keys_values_and_charlists(self):
        doc = mnesia()
        nested = term('map', [[binary(b'fixture-map-key'), term('list', [
            term('integer', x) for x in b'fixture-charlist'])]])
        doc['rows'][0]['value'][1] = nested
        values = reader.read_mnesia(RAW, 'emqx_authn_mnesia', adapter(doc))
        self.assertIn(b'fixture-map-key', values.values)
        self.assertIn(b'fixture-charlist', values.values)

    def test_unknown_tables_schema_and_records_refuse(self):
        self.assert_refused(lambda: reader.read_mnesia(RAW, 'schema.DAT', adapter(mnesia())))
        for key, value in [('table', 'other'), ('attributes', ['unknown']),
                           ('schema_validated', False), ('record_name', 'other'),
                           ('rows', None), ('complete', False)]:
            doc = mnesia(); doc[key] = value
            self.assert_refused(lambda: reader.read_mnesia(RAW, 'emqx_authn_mnesia', adapter(doc)))
        for row in (term('tuple', []), term('tuple', [term('atom', 'wrong')] * 5)):
            self.assert_refused(lambda: reader.read_mnesia(RAW, 'emqx_authn_mnesia', adapter(mnesia(rows=[row]))))

    def test_unsafe_terms_and_malformed_binaries_never_deserialize(self):
        for bad in (term('fun', 'fixture-secret'), term('pid', 'fixture-secret'),
                    term('reference', 'fixture-secret'), term('etf', 'fixture-secret'),
                    term('binary', '***'), term('binary', 'Zh=='), term('integer', True),
                    term('integer', 2 ** 80), {'type': 'atom', 'value': 'x', 'extra': True},
                    term('map', [[binary(b'x'), binary(b'y')], [binary(b'x'), binary(b'z')]])):
            doc = mnesia(); doc['rows'][0]['value'][1] = bad
            self.assert_refused(lambda: reader.read_mnesia(RAW, 'emqx_authn_mnesia', adapter(doc)))

    def test_input_rejected_before_trusted_adapter_and_late_failure_returns_nothing(self):
        from unittest.mock import Mock
        callback = Mock()
        with patch.object(reader, 'MAX_INPUT', 1):
            self.assert_refused(lambda: reader.read_hocon(RAW, callback))
            self.assert_refused(lambda: reader.read_mnesia(RAW, 'emqx_admin', callback))
        callback.assert_not_called()
        doc = mnesia()
        doc['rows'].append(term('tuple', [term('atom', 'wrong')]))
        self.assert_refused(lambda: reader.read_mnesia(RAW, 'emqx_authn_mnesia', adapter(doc)))

    def test_adapter_errors_are_fixed_and_never_logged(self):
        def broken(raw):
            raise RuntimeError('fixture-private-error')
        with patch('builtins.print') as output:
            self.assert_refused(lambda: reader.read_hocon(RAW, broken))
            self.assert_refused(lambda: reader.read_mnesia(RAW, 'emqx_admin', broken))
        output.assert_not_called()


if __name__ == '__main__':
    unittest.main()
