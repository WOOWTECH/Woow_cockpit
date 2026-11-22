"""Generated encrypted Capture + actual collector issuance; HTTP/native mocked.

No actual native process, broker, lab, or commercial restore is exercised.
"""
import copy
import unittest
from unittest.mock import patch

import emqx_native_object_integrity as m
import emqx_post_restore_values as post
import test_emqx_b1_object_integrity as source_tests
import test_emqx_source_api_validator as api_tests
import test_emqx_post_restore_values as native_tests
from test_emqx_owner_target import Atom, typed
from emqx_private_boundary import PrivateFailure
from emqx_source_api_validator import SourceAPIResult


class NativeObjectTests(unittest.TestCase):
    quiesce=api_tests.SourceAPITests.quiesce
    run_api=api_tests.SourceAPITests.run_api

    def setUp(self):
        self.api_mode=True
        api_tests.SourceAPITests.setUp(self)
        self.source_side=source_tests.ObjectIntegrityTests()
        self.source_side.setUp();self.addCleanup(self.source_side.doCleanups)
        self.secret='generated-original-connector-password'
        self.source_side.config['connectors']['http']['b1_http']['password']=self.secret
        context=self.source_side.source()
        captured,binding=context.__enter__();self.captured=captured;self.addCleanup(context.__exit__,None,None,None)
        self.session=self.source_side.join(captured)
        self.expected=self.source_side.mint(captured,self.session)
        self.prior=self.session.registry;self.runtime=self.prior._runtime
        source=self.source_side.config
        self.documents['rules']={'data':[dict(copy.deepcopy(v),id=k) for k,v in source['rule_engine']['rules'].items()],
                                 'meta':{'count':2,'hasnext':False}}
        for category in ('connectors','actions'):
            self.documents[category]=[dict(copy.deepcopy(obj),type=kind,name=name)
                for kind,objects in source[category].items() for name,obj in objects.items()]
            self.config[category]=copy.deepcopy(source[category])
        self.config['rule_engine']=copy.deepcopy(source['rule_engine'])
        self.path=['connectors','http','b1_http','password']
        self.native_version=2
        self.native_secret=self.secret.encode()
        self.wrapper_path=list(self.path)
        self.edit=self.secret_doc
        self.documents['connectors'][0]['password']='******'
        self.observed=self.run_api()
        self.api_mode=False

    def podman(self,*args,**kwargs):
        if self.api_mode:return api_tests.SourceAPITests.podman(self,*args,**kwargs)
        return native_tests.PostNativeTests.podman(self,*args,**kwargs)

    def secret_doc(self,doc):
        if self.native_version==1:return
        doc['contract']='emqx-owner-live-target-v2'
        wrapper={'module':Atom('emqx_secret'),'name':Atom('-wrap/1-fun-0-'),'arity':0,
            'type':Atom('local'),'index':0,'new_index':0,'uniq':85191762,
            'new_uniq':b'A27D8A4F73E7689F1F8B78E0DCB7C91B',
            'path':[(Atom('map'),Atom(part)) for part in self.wrapper_path],
            'env':[self.native_secret]}
        doc['config_secret_wrappers']=typed([wrapper])

    def native(self,**changes):
        kwargs=dict(prior_registry=self.prior,provision=self.provision,
                    expected_container_id=self.cid,quiesce=self.quiesce)
        kwargs.update(changes)
        return post.collect_post_restore_values(**kwargs)

    def compare(self,native,**changes):
        kwargs=dict(expected=self.expected,source_api=self.observed,native_values=native)
        kwargs.update(changes)
        return m.compare_b1_objects_native(**kwargs)

    def refuse(self,native,**changes):
        with self.assertRaisesRegex(PrivateFailure,'^native-object-integrity-refused$'):self.compare(native,**changes)

    def workflow_refuse(self,native,stage,**changes):
        import emqx_real_owner_workflow as workflow
        kwargs=dict(expected=self.expected,source_api=self.observed,native_values=native)
        kwargs.update(changes)
        with self.assertRaises(workflow.RealOwnerRefused) as caught:
            workflow._compare_source_objects(**kwargs)
        self.assertEqual(caught.exception.phase,'object_integrity_'+stage)
        self.assertIn(caught.exception.phase,workflow.PHASES)
        with self.assertRaises(m.NativeObjectPhaseRefused) as inner:
            m.compare_b1_objects_native(**kwargs)
        self.assertEqual(str(inner.exception),'native-object-integrity-refused')

    def metadata_profile(self):
        metadata={'created_at':1700000000123,'last_modified_at':1700000001000}
        for key,rule in self.source_side.config['rule_engine']['rules'].items():
            rule['metadata']=copy.deepcopy(metadata)
            self.config['rule_engine']['rules'][key]['metadata']=copy.deepcopy(metadata)
        self.expected=self.source_side.mint(self.captured,self.session)
        for row in self.documents['rules']['data']:
            row['created_at']='2023-11-14T22:13:20.123+00:00'
            row['last_modified_at']='2023-11-15T06:13:21.000+08:00'
        self.refresh_api()

    def refresh_api(self):
        self.api_mode=True
        try:self.observed=self.run_api()
        finally:self.api_mode=False

    def test_metadata_actual_collectors_three_way_and_all_source_fields(self):
        self.metadata_profile()
        self.compare(self.native())
        self.documents['rules']['data'][0]['sql']='generated-changed-sql'
        self.refresh_api()
        self.workflow_refuse(self.native(),'rules_value')

    def test_metadata_native_changed_missing_type_unknown(self):
        for change,reason in (('changed','value'),('missing','missing'),('type','type'),('unknown','value')):
            with self.subTest(change=change):
                self.metadata_profile()
                md=self.config['rule_engine']['rules']['b1_rule_republish']['metadata']
                if change=='changed':md['created_at']+=1
                elif change=='missing':del md['created_at']
                elif change=='type':md['created_at']=True
                else:md['unknown']=1
                self.workflow_refuse(self.native(),'rules_'+reason)

    def test_metadata_api_time_missing_precision_timezone_and_changed(self):
        for value in (None, '2023-11-14T22:13:20.124+00:00',
                      '2023-11-14T22:13:20.123Z','2023-11-14t22:13:20.123+00:00',
                      '2023-11-14T22:13:20.12+00:00','2023-11-14T22:13:20.123-00:00',
                      '2023-11-14T22:13:20.123+24:00', '2023-11-14T22:13:60.123+00:00',17):
            with self.subTest(case_type=type(value).__name__):
                self.metadata_profile()
                row=self.documents['rules']['data'][0]
                if value is None:del row['created_at']
                else:row['created_at']=value
                self.refresh_api()
                self.workflow_refuse(self.native(),'rules_'+('missing' if value is None else 'type' if type(value) is not str else 'value'))

    def test_metadata_original_unknown_missing_type_overflow(self):
        for change,reason in (('unknown','value'),('missing','missing'),('bool','type'),
                              ('float','type'),('string','type'),('negative','value'),('overflow','value')):
            with self.subTest(change=change):
                self.metadata_profile()
                md=self.source_side.config['rule_engine']['rules']['b1_rule_republish']['metadata']
                if change=='unknown':md['unknown']=1
                elif change=='missing':del md['created_at']
                else:md['created_at']={'bool':True,'float':1.0,'string':'1','negative':-1,'overflow':253402214400001}[change]
                self.expected=self.source_side.mint(self.captured,self.session)
                self.workflow_refuse(self.native(),'rules_'+reason)

    def test_metadata_actual_collectors_unsigned_supported_endpoints(self):
        self.metadata_profile()
        for key,rule in self.source_side.config['rule_engine']['rules'].items():
            rule['metadata']={'created_at':0,'last_modified_at':253402214400000}
            self.config['rule_engine']['rules'][key]['metadata']=copy.deepcopy(rule['metadata'])
        self.expected=self.source_side.mint(self.captured,self.session)
        for row in self.documents['rules']['data']:
            row['created_at']='1970-01-01T08:00:00.000+08:00'
            row['last_modified_at']='9999-12-31T00:00:00.000+00:00'
        self.refresh_api()
        self.compare(self.native())

    def test_action_integer_timestamps_remain_exact_without_rule_mapping(self):
        self.metadata_profile()
        action=self.source_side.config['actions']['http']['b1_http_action']
        action.update(created_at=1700000000123,last_modified_at=1700000001000)
        self.expected=self.source_side.mint(self.captured,self.session)
        row=self.documents['actions'][0]
        row.update(created_at=1700000000123,last_modified_at=1700000001000)
        self.refresh_api()
        self.compare(self.native())
        row['created_at']='2023-11-14T22:13:20.123+00:00'
        self.refresh_api()
        self.workflow_refuse(self.native(),'actions_type')

    def test_metadata_epoch_bounds_and_integer_exact_offsets(self):
        self.assertEqual(m._timestamp_ms('1970-01-01T00:00:00.000+00:00'),0)
        self.assertEqual(m._timestamp_ms('1969-12-31T23:00:00.001-01:00'),1)
        self.assertEqual(m._timestamp_ms('9999-12-31T00:00:00.000+00:00'),253402214400000)
        with self.assertRaises(m._Difference):m._timestamp_ms('9999-12-31T00:00:00.001+00:00')

    def test_actual_collectors_to_workflow_category_type_missing_value_phases(self):
        baseline=copy.deepcopy(self.documents)
        for category,field in (('rules','sql'),('actions','connector'),('connectors','url')):
            for reason in ('type','missing','value'):
                with self.subTest(category=category,reason=reason):
                    self.documents=copy.deepcopy(baseline)
                    rows=self.documents[category]
                    if category=='rules':rows=rows['data']
                    if reason=='type':rows[0][field]=17
                    elif reason=='missing':del rows[0][field]
                    else:rows[0][field]+=' generated-difference'
                    self.api_mode=True;self.observed=self.run_api();self.api_mode=False
                    self.workflow_refuse(self.native(),category+'_'+reason)

    def test_actual_collectors_to_workflow_secret_wrapper_and_success(self):
        import emqx_real_owner_workflow as workflow
        native=self.native()
        result=workflow._compare_source_objects(self.expected,self.observed,native)
        self.assertIs(type(result),m.NativeObjectComparison)
        with self.assertRaises(PrivateFailure):result.scan(self.secret.encode())
        self.config['connectors']['http']['b1_http']['other_password']=self.secret
        self.wrapper_path[-1]='other_password'
        self.workflow_refuse(self.native(),'connectors_secret_wrapper')

    def test_actual_collectors_to_workflow_identity_phase(self):
        self.cid='c'*64;self.doc[0]['Id']=self.cid
        self.workflow_refuse(self.native(),'identity')

    def test_actual_collectors_to_workflow_registry_phase(self):
        from emqx_runtime_workflow import CombinedRegistry
        self.prior=CombinedRegistry(self.prior._source,self.prior._runtime,self.prior._persisted)
        self.workflow_refuse(self.native(),'registry')

    def test_actual_collectors_to_workflow_order_phase(self):
        native=self.native()
        self.api_mode=True;self.observed=self.run_api();self.api_mode=False
        self.workflow_refuse(native,'order')

    def test_workflow_collector_phase_rejects_handmade_or_mutated_receipts(self):
        native=self.native()
        handmade=post.PostRestoreValues(native._previous,native._persisted,native._generations,native._preflight_generations)
        self.workflow_refuse(handmade,'collector')
        self.observed._documents['connectors'][0]['password']='generated-post-observation-change'
        self.workflow_refuse(native,'collector')

    def test_api_mask_needs_exact_validated_native_secret_path(self):
        native=self.native()
        result=self.compare(native)
        self.assertEqual(repr(result),'<EMQX private native-path object comparison>')
        for value in (self.secret.encode(),b'generated-jwt-admin',b'generated-private-payload'):
            with self.assertRaises(PrivateFailure):result.scan(value)
        from emqx_b1_object_integrity import compare_b1_objects
        with self.assertRaises(PrivateFailure):compare_b1_objects(expected=self.expected,source_api=self.observed)

    def test_same_plaintext_elsewhere_does_not_prove_expected_path(self):
        self.config['connectors']['http']['b1_http']['other_password']=self.secret
        self.wrapper_path[-1]='other_password'
        self.refuse(self.native())

    def test_native_secret_mismatch_refuses_even_if_scanner_has_original_bytes(self):
        self.runtime.register_bundle({'runtime-login-token':[self.secret.encode()]})
        self.native_secret=b'generated-different-native-secret'
        self.config['connectors']['http']['b1_http']['password']=self.native_secret
        self.refuse(self.native())

    def test_v1_unwrapped_config_and_handmade_scanners_cannot_authorize_mask(self):
        self.native_version=1;native=self.native();self.refuse(native)
        handmade=post.PostRestoreValues(native._previous,native._persisted,native._generations,native._preflight_generations)
        self.refuse(handmade)
        api=SourceAPIResult(self.observed._prior,self.observed._runtime,self.observed.private_documents(),{})
        self.refuse(native,source_api=api)

    def test_wrong_wrapper_value_or_unknown_typed_term_refuses_collection(self):
        self.native_secret=b'wrong-wrapper-env'
        with self.assertRaisesRegex(PrivateFailure,'^post-native-values-refused$'):self.native()
        def bad(doc):
            self.secret_doc(doc);doc['config_secret_wrappers']={'type':'function','value':'opaque'}
        self.edit=bad
        with self.assertRaises(PrivateFailure):self.native()

    def test_api_nonsecret_difference_has_no_native_normalization_fallback(self):
        # Mint an actual second API result whose SQL changed; API's own ID facts
        # still pass. Native equality cannot waive the public field mismatch.
        self.api_mode=True
        self.documents['rules']['data'][0]['sql']='SELECT changed'
        self.observed=self.run_api();self.api_mode=False
        self.refuse(self.native())

    def test_different_current_cid_or_runtime_identity_refuses(self):
        old=self.cid;self.cid='c'*64;self.doc[0]['Id']=self.cid
        native=self.native();self.refuse(native)
        self.cid=old;self.doc[0]['Id']=old
        self.doc[0]['Config']['Env'].append('ADDED=generated-private-metadata')
        self.refuse(self.native())

    def test_same_source_and_runtime_but_different_combined_registry_refuses(self):
        from emqx_runtime_workflow import CombinedRegistry
        self.prior=CombinedRegistry(self.prior._source,self.prior._runtime,self.prior._persisted)
        self.refuse(self.native())

    def test_later_api_needs_fresh_native_and_edited_api_receipt_refuses(self):
        native=self.native()
        self.api_mode=True;self.observed=self.run_api();self.api_mode=False
        self.refuse(native)
        native=self.native();self.compare(native)
        self.observed._documents['connectors'][0]['password']='changed-after-observation'
        self.refuse(native)

    def test_failed_lease_cannot_mint_native_or_api_receipt(self):
        from contextlib import contextmanager
        @contextmanager
        def fail_exit():
            yield
            raise ValueError('generated-private-lease')
        with self.assertRaises(PrivateFailure):self.native(quiesce=fail_exit)
        self.api_mode=True
        with self.assertRaises(PrivateFailure):self.run_api(quiesce=fail_exit)


if __name__=='__main__':unittest.main()
