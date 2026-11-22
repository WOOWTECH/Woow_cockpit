"""Actual native DETS/disk_log superset tests; generated data, no broker startup."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from emqx_native_runtime import run_native
from emqx_semantic_readers import SemanticRefused
from emqx_cold_history import HistoryInventory, read_cold_history, native_cold_history

HERE=Path(__file__).parent
KINDS={'schema.DAT':'schema-dat','table.DCD':'dcd','table.DCL':'dcl',
       'LATEST.LOG':'transaction-log','DECISION.LOG':'decision-log',
       'DECISION_TAB.LOG':'decision-tab'}


class ColdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='emqx-cold-synthetic-')
        cls.root=Path(cls.temp.name)
        code=cls.root/'code'; code.mkdir(mode=0o700)
        (code/'emqx_cold_fixture.escript').write_bytes((HERE/'emqx_cold_fixture.escript').read_bytes())
        with tempfile.TemporaryFile() as output:
            code_status=run_native(code,'emqx_cold_fixture.escript',
                                   writable_directory=cls.root,output=output)
        if code_status:
            cls.temp.cleanup()
            raise AssertionError('synthetic native fixture generation failed')
        cls.fixtures=cls.root/'fixtures'
        cls.raw={name:path.read_bytes() for path in cls.fixtures.iterdir() if (name:=path.name)}
        cls.encoded={name:native_cold_history(cls.raw[name],kind) for name,kind in KINDS.items()}

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def decoder(self,raw,kind):
        for name,expected in KINDS.items():
            if expected==kind and raw==self.raw[name]:
                return self.encoded[name]
        raise ValueError('unmatched synthetic source')

    def receipts(self):
        return {name:{'kind':kind,'bytes':len(self.raw[name]),
                      'sha256':hashlib.sha256(self.raw[name]).hexdigest()}
                for name,kind in KINDS.items()}

    def test_all_native_formats_enumerate_history_not_final_rows(self):
        inventory=HistoryInventory(self.receipts(),self.decoder)
        for name in KINDS:
            inventory.consume(name,self.raw[name])
        values=inventory.finish().values
        for secret in (b'emqx_admin_jwt',b'schema-private-history',b'old-dump-private',
                       b'new-log-private',b'deleted-charlist-private',b'delete-metadata-private',
                       b'unreplayed-history-private',b'transaction-map-private',
                       b'decision-private',b'decision-tab-private',b'1.25'):
            self.assertIn(secret,values)
        self.assertFalse((self.root/'EXECUTED').exists())
        for name,encoded in self.encoded.items():
            doc=json.loads(encoded)
            self.assertTrue(doc['complete'])
            self.assertFalse(doc['final_state'])
            self.assertEqual(doc['input_sha256'],hashlib.sha256(self.raw[name]).hexdigest())
            self.assertEqual(doc['term_count'],len(doc['terms']))
            self.assertEqual((self.fixtures/name).read_bytes(),self.raw[name])

    def test_actual_native_runtime_terms_never_execute_and_late_prefix_not_returned(self):
        for name in ('fun.DCL','pid.DCL','ref.DCL','port.DCL','improper.DCL','deep.DCL','big.DCL'):
            with self.subTest(name=name), self.assertRaises(SemanticRefused):
                read_cold_history(self.raw[name],'dcl',native_cold_history)
        with self.assertRaises(SemanticRefused):
            read_cold_history(self.raw['executable-schema.DAT'],'schema-dat',native_cold_history)
        with self.assertRaises(SemanticRefused):
            read_cold_history(self.raw['backend-schema.DAT'],'schema-dat',native_cold_history)
        self.assertFalse((self.root/'EXECUTED').exists())

    def test_native_truncation_trailers_and_container_confusion_refuse(self):
        for name in ('schema.DAT','table.DCD','table.DCL','LATEST.LOG'):
            for suffix in ('.truncated','.trailing'):
                with self.subTest(name=name+suffix), self.assertRaises(SemanticRefused):
                    read_cold_history(self.raw[name+suffix],KINDS[name],native_cold_history)
        for name in ('wrong-header.DCD','unknown-version.DCD'):
            with self.subTest(name=name),self.assertRaises(SemanticRefused):
                read_cold_history(self.raw[name],'dcd',native_cold_history)
        with self.assertRaises(SemanticRefused):
            read_cold_history(b'unknown-native-container','dcd',native_cold_history)

    def test_inventory_missing_duplicate_unknown_hash_and_late_failure_poison(self):
        inventory=HistoryInventory(self.receipts(),self.decoder)
        for name in list(KINDS)[:-1]: inventory.consume(name,self.raw[name])
        with self.assertRaises(SemanticRefused): inventory.finish()
        for path,raw in (('unknown.DCD',b'x'),('table.DCD',self.raw['table.DCD']+b'x')):
            inventory=HistoryInventory(self.receipts(),self.decoder)
            with self.assertRaises(SemanticRefused): inventory.consume(path,raw)
            with self.assertRaises(SemanticRefused): inventory.finish()
        inventory=HistoryInventory(self.receipts(),self.decoder)
        inventory.consume('table.DCD',self.raw['table.DCD'])
        with self.assertRaises(SemanticRefused): inventory.consume('table.DCD',self.raw['table.DCD'])
        with self.assertRaises(SemanticRefused): inventory.finish()
        receipts=self.receipts(); receipts['table.DCL']['kind']='unknown-format'
        with self.assertRaises(SemanticRefused): HistoryInventory(receipts,self.decoder)

    def test_late_typed_failure_poison_prevents_prior_file_values_escaping(self):
        def late_decoder(raw,kind):
            encoded=self.decoder(raw,kind)
            if kind=='dcl':
                doc=json.loads(encoded)
                doc['terms'].append({'type':'fun','value':'late-private'})
                doc['term_count']+=1
                return json.dumps(doc).encode()
            return encoded
        inventory=HistoryInventory(self.receipts(),late_decoder)
        inventory.consume('table.DCD',self.raw['table.DCD'])
        with self.assertRaises(SemanticRefused):
            inventory.consume('table.DCL',self.raw['table.DCL'])
        with self.assertRaises(SemanticRefused): inventory.finish()
        self.assertEqual(repr(inventory),'<EMQX private cold history inventory>')

    def test_contract_and_hash_binding_no_default_decoder_no_partial_results(self):
        raw=self.raw['table.DCD']
        with self.assertRaises(SemanticRefused): read_cold_history(raw,'dcd')
        for field,value in (('complete',False),('final_state',True),('term_count',0),
                            ('container','unknown'),('input_sha256','0'*64)):
            doc=json.loads(self.encoded['table.DCD']);doc[field]=value
            with self.subTest(field=field),self.assertRaises(SemanticRefused):
                read_cold_history(raw,'dcd',lambda *_:json.dumps(doc).encode())
        callback=Mock()
        receipt=self.receipts(); receipt['table.DCD']['bytes']=8*1024*1024+1
        with self.assertRaises(SemanticRefused): HistoryInventory(receipt,callback)
        callback.assert_not_called()
