"""Actual generated HA v3 decryption/SHA/spool; offline decoder boundary mocked."""
import base64
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_retained_history as m
import test_emqx_owner_source_capture as source_fixtures
from emqx_cold_history import CONTAINERS
from emqx_private_boundary import PrivateFailure


def term(kind,value):return {'type':kind,'value':value}
def binary(raw):return term('binary',base64.b64encode(raw).decode())
def atom(value):return term('atom',value)
def record(topic,payload):
    msg=term('tuple',[atom('message'),binary(b'generated-id'),term('integer',1),binary(b'generated-user'),
        term('map',[]),term('map',[]),binary(topic),binary(payload),term('integer',0),term('map',[])])
    return term('tuple',[atom('retained_message'),term('list',[binary(x) for x in topic.split(b'/')]),msg,term('integer',0)])


class RetainedHistoryTests(unittest.TestCase):
    def setUp(self):
        source_fixtures.OwnerHarnessTests.fixture(self)
        self.topics=(b'b1/retained/one',b'b1/retained/two')
        self.terms=[record(self.topics[0],b'generated-original-one'),record(self.topics[1],b'generated-original-two')]
        self.profile=SimpleNamespace(archive=self.path,sha256=self.digest,arch='aarch64',fixture_profile=None)
        self.calls=[]

    def decoder(self,raw,kind):
        self.calls.append(kind)
        terms=[atom('schema')] if kind=='schema-dat' else self.terms
        container,traversal=CONTAINERS[kind]
        return json.dumps(dict(contract='emqx-cold-history-json-v1',version='5.8.9',otp_release='26',
            erts_version='14.2.5.11',input_sha256=hashlib.sha256(raw).hexdigest(),input_bytes=len(raw),
            complete=True,kind=kind,container=container,traversal=traversal,
            semantics='historical-value-superset',final_state=False,empty_container=False,
            term_count=len(terms),terms=terms)).encode()

    def collect(self,**changes):
        kwargs=dict(source_mode=m.MODES[0],password=self.password,topics=self.topics,spool_directory=self.spool)
        kwargs.update(changes)
        with patch.object(m,'source_profile',return_value=self.profile), \
             patch.object(m,'native_cold_history',side_effect=self.decoder), \
             patch('emqx_private_spool.RESERVE',0):
            return m.collect_original_retained_payloads(**kwargs)

    def refuse(self,**changes):
        with self.assertRaisesRegex(PrivateFailure,'^retained-history-refused$'):
            self.collect(**changes)
        self.assertEqual(list(self.spool.iterdir()),[])

    def test_original_encrypted_sha_bound_history_returns_private_payloads_not_final_truth(self):
        result=self.collect()
        self.assertEqual(self.calls,['schema-dat','dcd'])
        self.assertEqual(result.private_pairs(),tuple(zip(self.topics,(b'generated-original-one',b'generated-original-two'))))
        self.assertFalse(result.final_state)
        self.assertEqual(result.source_sha256,self.digest)
        self.assertEqual(repr(result),'<B1 private original retained payload history>')
        self.assertEqual(list(self.spool.iterdir()),[])
        for raw in (b'generated-original-one',b'generated-original-two',self.password.encode()):
            with self.assertRaises(PrivateFailure):result.scan(raw)

    def test_repeated_equal_historical_values_are_unambiguous(self):
        self.terms.append(record(self.topics[0],b'generated-original-one'))
        self.assertFalse(self.collect().final_state)

    def test_nested_transaction_history_is_not_skipped(self):
        self.terms=[term('tuple',[atom('transaction'),term('list',self.terms)])]
        self.assertEqual(len(self.collect().private_pairs()),2)
        self.terms[0]['value'][1]['value'].append(record(self.topics[0],b'conflicting-history'))
        self.refuse()

    def test_incomplete_native_receipt_refuses(self):
        original=self.decoder
        def incomplete(raw,kind):
            doc=json.loads(original(raw,kind));doc['complete']=False
            return json.dumps(doc).encode()
        self.decoder=incomplete
        self.refuse()

    def test_different_historical_payload_refuses_even_if_last_record_looks_expected(self):
        self.terms.insert(0,record(self.topics[0],b'different-old-value'))
        self.refuse()

    def test_missing_topic_and_empty_payload_refuse(self):
        self.terms=self.terms[:1];self.refuse()
        self.terms=[record(self.topics[0],b''),record(self.topics[1],b'two')];self.refuse()

    def test_wrong_original_sha_or_key_refuses_before_native(self):
        original=self.profile.sha256
        self.profile.sha256='0'*64;self.refuse();self.assertEqual(self.calls,[])
        self.profile.sha256=original
        self.refuse(password='generated-wrong-key');self.assertEqual(self.calls,[])

    def test_unknown_layout_key_topic_mismatch_and_opaque_terms_refuse(self):
        self.terms[0]['value'][2]['value'][6]=binary(b'b1/retained/other');self.refuse()
        self.terms=[term('tuple',[atom('retained_message')])];self.refuse()
        self.terms=[term('function','unsupported')];self.refuse()

    def test_closed_frame_input_constraints_and_deadline_refuse(self):
        self.refuse(topics=[self.topics[0],self.topics[0]])
        self.refuse(source_mode='arbitrary-source')
        self.refuse(topics=[b'/etc/passwd',self.topics[1]])
        with patch.object(m,'SECONDS',0):self.refuse()

    def test_source_mutation_at_native_observation_refuses_final_stamp(self):
        original=self.decoder
        def changed(raw,kind):
            encoded=original(raw,kind)
            with self.path.open('ab') as handle:handle.write(b'changed')
            return encoded
        self.decoder=changed
        self.refuse()


if __name__=='__main__':unittest.main()
