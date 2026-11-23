"""Actual fresh native Mnesia schema boundary; no broker/lab/customer input."""
import base64
from contextlib import contextmanager
import copy
import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_broker_owner_target as harness
from emqx_owner_target import owner_target_readers,OwnerCaptureRefused,_decode,CONSUMER_REASONS
from emqx_semantic_readers import Values
from emqx_private_boundary import PrivateFailure
from test_emqx_owner_target import reply_document,term

ROOT=Path(__file__).parent


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from emqx_native_runtime import run_native
        with tempfile.TemporaryDirectory(prefix='emqx-public-inventory-') as directory, \
             tempfile.TemporaryDirectory(prefix='emqx-public-mnesia-') as writable:
            root=Path(directory)
            for name in ('emqx_owner_inventory_fixture.escript','emqx_owner_target.expr'):
                (root/name).write_bytes((ROOT/name).read_bytes());(root/name).chmod(0o600)
            with tempfile.TemporaryFile() as output:
                code=run_native(root,'emqx_owner_inventory_fixture.escript',
                    args=('/input/emqx_owner_target.expr',),writable_directory=Path(writable),output=output)
                output.seek(0);raw=output.read(1048577)
                if code or len(raw)>1048576:
                    raise AssertionError('native synthetic inventory fixture failed')
                cls.native=json.loads(raw)

    @contextmanager
    def quiesce(self):
        yield

    def transport(self,edit=None):
        def evaluate(expression):
            nonce=re.search(r'generation => <<"([0-9a-f]{32})">>',expression)[1]
            doc=reply_document(nonce);doc.update(copy.deepcopy(self.native))
            if edit:edit(doc)
            return b'WOOWTARGET:'+base64.b64encode(json.dumps(doc).encode())+b':ENDok'
        return evaluate

    def test_actual_native_canonical_schemas_pass_pair_contract_and_scan_all_values(self):
        schema=_decode(self.native['schema_metadata'],Values())
        self.assertTrue(all(type(entry) is tuple and len(entry)==2 for entry in schema))
        self.assertEqual({name for name,_ in schema},set(self.native['table_names']))
        jwt=dict(dict(schema)['emqx_admin_jwt'])
        self.assertEqual(jwt['index'],[(3,'ordered')])
        self.assertIn(('private_property',b'fixture-native-canonical-private'),jwt['user_properties'])
        app=next(t for t in self.native['tables'] if t['table']=='emqx_app')
        self.assertEqual((app['row_count'],app['rows']),(0,[]))
        with owner_target_readers(private_eval=self.transport(),quiesce=self.quiesce) as readers:
            self.assertEqual(len(readers),5)
            self.assertEqual(readers.persisted_values.tables,frozenset(self.native['table_names']))
            for payload in (b'fixture-native-canonical-private',b'fixture-native-jwt-private',b'fixture-native-hash'):
                with self.assertRaises(PrivateFailure):readers.persisted_values.scan(payload)

    def test_inventory_negatives_preserve_refusal_and_expose_only_fixed_reason(self):
        def pair_to_list(doc):
            doc['schema_metadata']['value'][0]['type']='list'
        def pair_to_triple(doc):
            entry=doc['schema_metadata']['value'][0]['value']
            entry.insert(0,term('atom','schema'))
        def wrong_name(doc):
            doc['schema_metadata']['value'][0]['value'][0]=term('atom','private_wrong_binding')
        cases=[('inventory_names_type',lambda d:d.update(table_names='private-not-a-list')),
            ('inventory_names_bound',lambda d:d.update(table_names=[])),
            ('inventory_name_shape',lambda d:d['table_names'].__setitem__(0,'private/../table')),
            ('inventory_duplicate_name',lambda d:d['table_names'].append(d['table_names'][0])),
            ('inventory_missing_schema',lambda d:d['table_names'].remove('schema')),
            ('inventory_schema_type',lambda d:d.update(schema_metadata=term('atom','private-schema'))),
            ('inventory_schema_count',lambda d:d['schema_metadata']['value'].pop()),
            ('inventory_schema_entry_shape',pair_to_list),('inventory_schema_entry_shape',pair_to_triple),
            ('inventory_schema_name_kind',lambda d:d['schema_metadata']['value'][0]['value'].__setitem__(0,term('integer',42))),
            ('inventory_schema_duplicate',lambda d:d['schema_metadata']['value'].__setitem__(0,copy.deepcopy(d['schema_metadata']['value'][1]))),
            ('inventory_schema_binding',wrong_name),('inventory_tables_type',lambda d:d.update(tables={})),
            ('inventory_tables_count',lambda d:d['tables'].pop())]
        for reason,edit in cases:
            with self.subTest(reason=reason),self.assertRaises(OwnerCaptureRefused) as caught:
                with owner_target_readers(private_eval=self.transport(edit),quiesce=self.quiesce):pass
            self.assertEqual((caught.exception.phase,caught.exception.reason),('inventory',reason))
            self.assertNotIn('private',str(caught.exception))
            self.assertNotIn('private_',repr(caught.exception))

    def test_only_exact_live_builtin_name_is_supported(self):
        from emqx_persisted_values import native_name
        from emqx_owner_target import _live_table_name
        name='$mria_rlog_sync'
        self.assertFalse(native_name(name))  # No generic callback/path exception.
        self.assertTrue(_live_table_name(name))
        self.assertEqual([n for n in self.native['table_names'] if not native_name(n)],[name])
        entry=next(t for t in self.native['tables'] if t['table']==name)
        self.assertEqual((entry['record_name'],entry['attributes'],entry['row_count'],entry['rows']),
            (name,['reply_to','shard','extra'],0,[]))
        for value in ('$mria_other','$mria_rlog_sync/../x','mria.rlog_sync','../table','table/path',
                      '$mria_rlog_sync\x00','$mria_meta_shard','a'*256):
            self.assertFalse(_live_table_name(value))

    def test_builtin_record_schema_storage_and_empty_binding_refuse(self):
        def table(doc):
            return next(t for t in doc['tables'] if t['table']=='$mria_rlog_sync')
        def property_change(doc,key,value):
            record=next(t for t in doc['schema_metadata']['value']
                if t['value'][0]['value']=='$mria_rlog_sync')
            for prop in record['value'][1]['value']:
                if prop['value'][0]['value']==key:
                    from test_emqx_owner_target import typed
                    prop['value'][1]=typed(value)
        cases=[lambda d:table(d).update(record_name='unknown'),
            lambda d:table(d).update(attributes=['reply_to','shard','unknown']),
            lambda d:table(d).update(row_count=True),
            lambda d:table(d).update(row_count=1,rows=[term('tuple',[])]),
            lambda d:property_change(d,'null_copies',[]),
            lambda d:property_change(d,'ram_copies',['private-node'])]
        for edit in cases:
            with self.subTest(edit=edit),self.assertRaises(OwnerCaptureRefused) as caught:
                with owner_target_readers(private_eval=self.transport(edit),quiesce=self.quiesce):pass
            self.assertEqual((caught.exception.phase,caught.exception.reason),('inventory','inventory_builtin_profile'))

    def test_harness_publishes_fixed_reason_not_exception_or_config(self):
        @contextmanager
        def refused(**kwargs):
            raise OwnerCaptureRefused('inventory','inventory_schema_entry_shape')
            yield
        report={'checks':{}}
        with patch.object(harness,'broker_target_readers',refused):
            with self.assertRaises(OwnerCaptureRefused):
                harness.run_owner_target(Path('/not-opened'),'fixture',[],report,owned_container_id='a'*64)
        self.assertEqual(report['consumer_fixed_reason'],'inventory_schema_entry_shape')
        unknown=OwnerCaptureRefused('private-phase','private-reason')
        self.assertEqual((unknown.phase,unknown.reason),('wire','private_refused'))
        self.assertIn(unknown.reason,CONSUMER_REASONS)
