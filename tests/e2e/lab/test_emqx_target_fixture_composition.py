"""Generated real capability issuance/helper -> held native consumer composition.

Fake owner subprocess runner and generated wire only: no broker or lab execution.
"""
from contextlib import contextmanager
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import emqx_owner_fixture_files as files
import emqx_owner_vendor_files as vendor
from emqx_owner_target import owner_target_readers,_no_refs
from emqx_target_vendor_policy import vendor_observer,policy_from_observation,REFERENCES
from emqx_target_fixture_policy import HeldFixtureObservation
import test_emqx_owner_fixture_files as issued
import test_emqx_target_vendor_policy as policy_fixtures
import test_emqx_owner_target as fixtures


class FixtureCompositionTests(unittest.TestCase):
    def setUp(self):
        self.issued=issued.FixtureFilesTests()
        self.issued.setUp()
        self.addCleanup(self.issued.doCleanups)
        self.issued.doc[0]['HostConfig']['LogConfig']={'Type':'none'}
        self.vendor_calls=[]

    def vendor_capture(self,refs,**kwargs):
        self.assertEqual(refs,REFERENCES)
        self.assertIs(kwargs['fixture_capability'],self.issued.cap)
        self.assertTrue(vendor._authorized_broker(kwargs['broker'],kwargs['owned_container_id'],kwargs['fixture_capability']))
        kwargs['private_values'].add(b'generated-vendor-complete-bytes')
        self.vendor_calls.append(True)
        return policy_fixtures.VendorACLPolicyTests().observed()

    def observer(self):
        return vendor_observer(broker=self.issued.f.prefix,owned_container_id=self.issued.cid,
            private_eval=self.issued.evaluate,private_inspect=self.issued.inspect,
            fixture_capability=self.issued.cap)

    def config(self):
        config=fixtures.cooked_config()
        config['authentication'][0].update(bootstrap_file=files.BOOTSTRAP,
            bootstrap_type=fixtures.Atom('plain'))
        config['authorization']={'sources':[{'type':fixtures.Atom('file'),
            'enable':True,'path':files.ACL}]}
        return config

    @contextmanager
    def quiet(self): yield

    def test_issued_create_files_composed_with_native_readers_and_private_scan(self):
        transport=fixtures.OwnerProducerTests().transport([],config=self.config())
        with patch.object(vendor,'observe_vendor_files',self.vendor_capture):
            with owner_target_readers(private_eval=transport,quiesce=self.quiet,
                    vendor_observer=self.observer()) as readers:
                self.assertEqual(len(readers),5)
                for value in (issued.BASE,issued.ACL,issued.CSV,b'generated,password',
                              b'generated-user',b'generated-config-secret',b'generated-vendor-complete-bytes'):
                    with self.subTest(value=value),self.assertRaises(Exception): readers.persisted_values.scan(value)
        self.assertEqual(len(self.vendor_calls),2)
        self.assertEqual(self.issued.events,['inspect','eval','inspect']*2)

    def test_generation_and_forged_observation_cannot_authorize_custom_paths(self):
        from emqx_semantic_readers import Values
        with patch.object(vendor,'observe_vendor_files',self.vendor_capture):
            with self.observer()(generation='a'*32,private_values=Values()) as observed:
                policy=policy_from_observation(observed,'a'*32)
                decoded=fixtures.typed(self.config())
                from emqx_owner_target import _decode
                _no_refs(_decode(decoded,Values()),vendor_policy=policy)
                with self.assertRaises(Exception): policy_from_observation(observed,'b'*32)
                forged=HeldFixtureObservation()
                for attr in ('receipts','fixture_receipts','token','broker','cid','generation'):
                    setattr(forged,attr,getattr(observed,attr))
                with self.assertRaises(Exception): policy_from_observation(forged,'a'*32)
                # JSON-like receipt data cannot select fixture authorization.
                public_only=policy_from_observation(SimpleNamespace(receipts=observed.receipts),'a'*32)
                with self.assertRaises(Exception): _no_refs(_decode(decoded,Values()),vendor_policy=public_only)

    def test_target_file_identity_change_and_revocation_fail_on_lease_exit(self):
        from emqx_semantic_readers import Values
        for mode in ('identity','revoke'):
            if mode=='revoke' and self.issued.cap not in files._RECORDS: break
            with self.subTest(mode=mode),patch.object(vendor,'observe_vendor_files',self.vendor_capture):
                with self.assertRaises(Exception):
                    with self.observer()(generation='a'*32,private_values=Values()):
                        if mode=='identity': self.issued.files['files'][0]['identity'][1]+=1
                        else: files.revoke(self.issued.cap)

    def test_vendor_lab_name_requires_live_bound_authentic_capability(self):
        name,cid,cap=self.issued.f.prefix,self.issued.cid,self.issued.cap
        self.assertFalse(vendor._authorized_broker(name,cid,None))
        self.assertFalse(vendor._authorized_broker(name,cid,cap)) # not yet observed/bound
        for fake in ({'complete':True},files.FixtureFiles()):
            with self.assertRaises(Exception): vendor._authorized_broker(name,cid,fake)
        self.issued.observe()
        self.assertTrue(vendor._authorized_broker(name,cid,cap))
        self.assertFalse(vendor._authorized_broker(name,'b'*64,cap))
        self.assertFalse(vendor._authorized_broker('woowbk-emqxlab-ffffffff',cid,cap))
        files.revoke(cap)
        with self.assertRaises(Exception): vendor._authorized_broker(name,cid,cap)

    def test_vendor_actual_entry_gates_capability_before_baseline_read(self):
        from emqx_semantic_readers import Values
        kwargs=dict(private_eval=lambda _:b'',private_inspect=self.issued.inspect,
            broker=self.issued.f.prefix,owned_container_id=self.issued.cid,private_values=Values())
        with patch.object(vendor,'_image_files',side_effect=RuntimeError('fixed-stop')) as baseline:
            with self.assertRaises(Exception): vendor.observe_vendor_files(REFERENCES,**kwargs)
            baseline.assert_not_called()
            with self.assertRaises(Exception):
                vendor.observe_vendor_files(REFERENCES,fixture_capability=self.issued.cap,**kwargs)
            baseline.assert_not_called()
            self.issued.observe() # Actual fixture observer binds cid in real registry.
            with self.assertRaises(Exception):
                vendor.observe_vendor_files(REFERENCES,fixture_capability=self.issued.cap,**kwargs)
            baseline.assert_called_once()
