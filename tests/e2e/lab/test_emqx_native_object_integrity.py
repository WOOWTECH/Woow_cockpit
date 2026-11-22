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
        captured,binding=context.__enter__();self.addCleanup(context.__exit__,None,None,None)
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
