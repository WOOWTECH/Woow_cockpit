"""Generated encrypted Capture/join and API boundaries, no commercial claims."""
import copy
import hashlib
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_b1_object_integrity as m
import test_emqx_owner_preflight as joins
from emqx_private_boundary import PrivateFailure
from emqx_source_consumer import Capture
from emqx_source_api_validator import SourceAPIResult


class ObjectIntegrityTests(unittest.TestCase):
    tracked_readers=joins.JoinTests.tracked_readers
    source=joins.JoinTests.source
    join=joins.JoinTests.join

    def setUp(self):
        joins.JoinTests.setUp(self)
        self.config={'rule_engine':{'rules':{
            'b1_rule_republish':{'sql':'SELECT payload FROM "generated/#"','enable':True,
                                'actions':[{'function':'republish','args':{'topic':'generated/out','payload':'generated-private-payload'}}]},
            'b1_rule_http':{'sql':'SELECT * FROM "generated/http"','actions':['http:b1_http_action']}}},
            'connectors':{'http':{'b1_http':{'enable':True,'url':'http://unexecuted.example/private','headers':{'authorization':'generated-source-header'}}}},
            'actions':{'http':{'b1_http_action':{'connector':'b1_http','parameters':{'path':'/ingest','method':'post'}}}}}
        self.parser=self.native
        self.profile=SimpleNamespace(sha256=self.digest,arch='aarch64')

    def native(self,raw):
        return json.dumps({'contract':'emqx-hocon-json-v1','version':'5.8.9',
            'input_sha256':hashlib.sha256(raw).hexdigest(),'input_bytes':len(raw),
            'complete':True,'resolution':'disabled','references':[],'document':copy.deepcopy(self.config)}).encode()

    def mint(self,captured,session,**changes):
        kwargs=dict(captured=captured,session=session,source_mode=m.MODES[0]);kwargs.update(changes)
        with patch.object(m,'source_profile',return_value=self.profile):return m.capture_b1_object_expectations(**kwargs)

    def observed(self,session):
        documents={'rules':{'data':[dict(copy.deepcopy(rule),id=name) for name,rule in self.config['rule_engine']['rules'].items()],
                            'meta':{'count':2}},
                   'actions':[dict(copy.deepcopy(obj),type=kind,name=name) for kind,objects in self.config['actions'].items() for name,obj in objects.items()],
                   'connectors':[dict(copy.deepcopy(obj),type=kind,name=name) for kind,objects in self.config['connectors'].items() for name,obj in objects.items()]}
        # Process-boundary API fixture only. Actual HTTP registration/ownership
        # is covered by test_emqx_source_api_validator; this tests comparison.
        return SourceAPIResult(session.registry,session.registry._runtime,documents,{})

    def test_actual_source_capture_join_readonly_replay_and_private_fields_survive_close(self):
        with self.source() as (captured,binding):
            session=self.join(captured)
            with patch.object(Capture,'__call__',side_effect=AssertionError('second Capture forbidden')):
                expected=self.mint(captured,session)
            observed=self.observed(session)
        compared=m.compare_b1_objects(expected=expected,source_api=observed)
        for secret in (b'generated-source-header',b'generated-private-payload',b'generated-login-password'):
            with self.assertRaises(PrivateFailure):compared.scan(secret)
        self.assertIn('not-final-mnesia',compared.scope()[1])
        self.assertEqual(repr(expected),'<EMQX private original object expectations>')

    def test_changed_sql_actions_connector_and_masked_secret_refuse(self):
        with self.source() as (captured,_):
            session=self.join(captured);expected=self.mint(captured,session)
            for edit in (lambda d:d['rules']['data'][0].update(sql='SELECT altered'),
                         lambda d:d['rules']['data'][0].update(enable=1),
                         lambda d:d['rules']['data'][0].update(actions=[]),
                         lambda d:d['actions'][0].update(connector='other'),
                         lambda d:d['connectors'][0]['headers'].update(authorization='******')):
                observed=self.observed(session);edit(observed._documents)
                with self.assertRaisesRegex(PrivateFailure,'^object-integrity-refused$'):
                    m.compare_b1_objects(expected=expected,source_api=observed)

    def test_api_defaults_and_runtime_added_objects_are_not_source_row_counts(self):
        with self.source() as (captured,_):
            session=self.join(captured);expected=self.mint(captured,session);observed=self.observed(session)
            observed._documents['rules']['data'][0]['description']='api-added-default'
            observed._documents['rules']['data'].append({'id':'runtime-added-rule'})
            observed._documents['rules']['meta']['count']=3
            self.assertIsInstance(m.compare_b1_objects(expected=expected,source_api=observed),m.ObjectComparison)

    def test_missing_duplicate_and_incomplete_api_objects_refuse(self):
        with self.source() as (captured,_):
            session=self.join(captured);expected=self.mint(captured,session)
            for edit in (lambda d:d.update(actions=[]),
                         lambda d:d['connectors'].append(copy.deepcopy(d['connectors'][0])),
                         lambda d:d['rules']['meta'].update(count=3)):
                observed=self.observed(session);edit(observed._documents)
                with self.assertRaises(PrivateFailure):m.compare_b1_objects(expected=expected,source_api=observed)

    def test_unsealed_failed_login_closed_capture_and_wrong_sha_refuse(self):
        with self.source() as (captured,_):
            with self.assertRaises(PrivateFailure):self.mint(captured,SimpleNamespace())
            self.transport.side_effect=lambda *_:(401,'application/json',io.BytesIO(b'{}'))
            with self.assertRaises(PrivateFailure):self.join(captured)
        with self.assertRaises(PrivateFailure):self.mint(captured,SimpleNamespace())
        self.setUp()
        with self.source() as (captured,_):
            session=self.join(captured);self.profile.sha256='0'*64
            with self.assertRaises(PrivateFailure):self.mint(captured,session)

    def test_wrong_architecture_unissued_token_and_mixed_registry_refuse(self):
        with self.source() as (captured,_):
            session=self.join(captured);self.profile.arch='amd64'
            with self.assertRaises(PrivateFailure):self.mint(captured,session)
            self.profile.arch='aarch64';expected=self.mint(captured,session)
            observed=self.observed(session)
            from emqx_runtime_workflow import CombinedRegistry
            observed._prior=CombinedRegistry(session.registry._source,session.registry._runtime)
            with self.assertRaises(PrivateFailure):m.compare_b1_objects(expected=expected,source_api=observed)
            with self.assertRaises(PrivateFailure):m.compare_b1_objects(expected=m.SourceObjects(),source_api=self.observed(session))

    def test_native_context_wrapper_and_supplemental_prior_keep_same_join_identity(self):
        with self.source() as (captured,_):
            session=self.join(captured);original=captured._hocon_parser
            def context(raw):
                doc=json.loads(original(raw));doc['contract']=m.SQL_CONTRACT
                doc['document']={'parsed':doc['document'],'syntax_strings':['generated-syntax-private'],
                    'string_bindings':[],'concat_strings':[],'alias_bindings':[]}
                return json.dumps(doc).encode()
            captured._hocon_parser=context
            expected=self.mint(captured,session);observed=self.observed(session)
            persisted=m.PersistedValues('generated-phase','source',{},[b'generated-new-native-private'])
            observed._prior=m.PostRestoreValues(session.registry,persisted,('generated-phase',),())
            compared=m.compare_b1_objects(expected=expected,source_api=observed)
            for raw in (b'generated-syntax-private',b'generated-new-native-private'):
                with self.assertRaises(PrivateFailure):compared.scan(raw)

    def test_default_strict_hocon_guard_still_rejects_context_reference(self):
        from emqx_semantic_readers import read_hocon,SemanticRefused
        raw=b'generated'
        def reference(data):
            doc=json.loads(self.native(data));doc['document']={'path':'${UNVERIFIED_FILE}'}
            return json.dumps(doc).encode()
        with self.assertRaises(SemanticRefused):read_hocon(raw,reference)

    def test_missing_original_objects_is_not_invented_empty_success(self):
        self.config.pop('actions')
        with self.source() as (captured,_):
            session=self.join(captured)
            with self.assertRaises(PrivateFailure):self.mint(captured,session)

    def test_incomplete_or_resolving_native_receipt_and_late_finish_refuse(self):
        with self.source() as (captured,_):
            session=self.join(captured);original=captured._hocon_parser
            for key,value in [('complete',False),('resolution','enabled'),('references',['external'])]:
                def altered(raw,key=key,value=value):
                    document=json.loads(original(raw));document[key]=value;return json.dumps(document).encode()
                captured._hocon_parser=altered
                with self.assertRaises(PrivateFailure):self.mint(captured,session)
            captured._hocon_parser=original
            with patch.object(m.time,'monotonic',side_effect=[0,121]):
                with self.assertRaises(PrivateFailure):self.mint(captured,session)


if __name__=='__main__':unittest.main()
