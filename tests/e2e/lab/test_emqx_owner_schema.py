"""Canonical persistent schema code/consumer and public offline native fixtures."""
import base64
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest

import emqx_broker_owner_target as adapter
from emqx_owner_target import owner_target_readers
from emqx_private_boundary import PrivateFailure
from test_emqx_owner_target import Atom, reply_document, typed

ROOT = Path(__file__).parent


class OwnerSchemaTests(unittest.TestCase):
    def test_canonical_reads_cover_every_table_and_both_receipts(self):
        source = (ROOT / 'emqx_owner_target.expr').read_text()
        self.assertNotIn('mnesia:table_info(T,all)', source)
        self.assertIn('Defs = [CanonicalSchema(T,ets:lookup(schema,T)) || T <- All]', source)
        self.assertIn('DefsAfter = [CanonicalSchema(T,ets:lookup(schema,T)) || T <- All]', source)
        self.assertIn('true = lists:member(schema,All)', source)
        self.assertIn('case SchemaBefore =:= SchemaAfter', source)
        self.assertIn('All =:= lists:sort(mnesia:system_info(tables))', source)
        self.assertIn('{Typed(Defs,0),Data,SchemaBefore,SchemaAfter}', source)

    def test_kind_diagnostics_are_fixed_enums(self):
        for reason in ('unsupported_pid','unsupported_reference','unsupported_port',
                       'unsupported_function','unsupported_bitstring','schema_record_invalid'):
            self.assertEqual(adapter.fixed_native_diagnostic(
                f'WOOWTARGETFAIL:schema_terms:{reason}:ENDok'.encode()),
                {'native_fixed_stage':'schema_terms','native_fixed_reason':reason})

    def test_private_canonical_properties_remain_scanned(self):
        @contextmanager
        def quiesce():
            yield
        def evaluate(expression):
            import re
            nonce = re.search(r'generation => <<"([0-9a-f]{32})">>', expression)[1]
            doc = reply_document(nonce)
            for definition in doc['schema_metadata']['value']:
                _, properties = definition['value']
                properties['value'].extend([
                    typed((Atom('index'), [3])),
                    typed((Atom('user_properties'), [(Atom('private_key'), b'fixture-canonical-schema-private')])),
                    typed((Atom('mnesia_backend_types'), [(Atom('null_copies'), Atom('mria_mnesia_null_storage'))]))])
            return b'WOOWTARGET:' + base64.b64encode(json.dumps(doc).encode()) + b':ENDok'
        with owner_target_readers(private_eval=evaluate, quiesce=quiesce) as readers:
            self.assertEqual(len(readers),5)
            with self.assertRaises(PrivateFailure):
                readers.persisted_values.scan(b'fixture-canonical-schema-private')

    def test_exact_closures_and_full_fixed_parser_in_local_pinned_runtime(self):
        from emqx_native_runtime import run_native
        with tempfile.TemporaryDirectory(prefix='emqx-public-schema-policy-') as directory:
            root = Path(directory)
            for name in ('emqx_owner_schema_fixture.escript','emqx_owner_target.expr'):
                (root/name).write_bytes((ROOT/name).read_bytes())
                (root/name).chmod(0o600)
            with tempfile.TemporaryFile() as output:
                code = run_native(root,'emqx_owner_schema_fixture.escript',
                    args=('/input/emqx_owner_target.expr',),output=output)
                output.seek(0)
                self.assertEqual((code,output.read(128)),(0,b'OWNERSCHEMAFIXTUREOK'))
