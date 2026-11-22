"""Synthetic callback/lease tests: no broker or vendor private-key reads."""
import copy
from contextlib import contextmanager
import unittest
from types import SimpleNamespace
from emqx_native_runtime import IMAGE
from emqx_owner_target import _no_refs, owner_target_readers
from emqx_target_vendor_policy import DisabledVendorTLS, FILES
import test_emqx_owner_target as fixtures


def receipt():
    return SimpleNamespace(receipts=tuple({'path':'/opt/emqx/etc/certs/'+name,
        'image':IMAGE,'container_id':'a'*64,'bytes':20,'sha256':'b'*64,
        'image_identity':(1,), 'target_identity':(2,)} for name in FILES.values()))


class VendorPolicyTests(unittest.TestCase):
    def test_exact_disabled_only(self):
        policy=DisabledVendorTLS(receipt())
        config={'listeners':{'ssl':{'default':{'enable':'false','ssl_options':{
            key:'${EMQX_ETC_DIR}/certs/'+name for key,name in FILES.items()}}}}}
        _no_refs(config,vendor_policy=policy)
        for change in ('active','literal','path','authorizer'):
            bad=copy.deepcopy(config)
            listener=bad['listeners']['ssl']['default']
            if change=='active': listener['enable']='true'
            if change=='literal': listener['ssl_options']['certfile']='${EMQX_ETC_DIR}/certs/custom.pem'
            if change=='path': bad['other']=listener.pop('ssl_options')
            if change=='authorizer': bad['authorization']={'type':'file'}
            with self.subTest(change=change), self.assertRaises(Exception):
                _no_refs(bad,vendor_policy=policy)

    def test_lease_and_private_registry(self):
        events=[]
        @contextmanager
        def quiesce():
            events.append('quiet')
            yield
            events.append('resume')
        @contextmanager
        def observe(*,generation,private_values):
            self.assertEqual(len(generation),32)
            events.append('observe')
            private_values.add(b'generated-vendor-private-bytes')
            yield receipt()
            events.append('recheck')
        config=fixtures.cooked_config()
        for kind in ('ssl','wss'):
            config['listeners'][kind]['default']['ssl_options']={
                key:'${EMQX_ETC_DIR}/certs/'+name for key,name in FILES.items()}
        transport=fixtures.OwnerProducerTests().transport(events,config=config)
        with owner_target_readers(private_eval=transport,quiesce=quiesce,vendor_observer=observe) as readers:
            with self.assertRaises(Exception):
                readers.persisted_values.scan(b'generated-vendor-private-bytes')
            events.append('use')
            self.assertEqual(set(readers),{'mqtt-auth','api-keys','connectors','tls','target-bootstrap'})
        self.assertEqual(events,['quiet','observe','eval','use','recheck','resume'])

    def test_missing_or_wrong_image_receipt(self):
        for change in ('missing','image','binding'):
            observed=receipt()
            if change=='missing': observed.receipts=observed.receipts[:-1]
            if change=='image': observed.receipts[0]['image']='unknown'
            if change=='binding': observed.receipts[0]['container_id']='c'*64
            with self.subTest(change=change),self.assertRaises(Exception): DisabledVendorTLS(observed)

    def test_bound_helper_rechecks_and_rejects_change(self):
        import sys
        from unittest.mock import patch
        from emqx_semantic_readers import Values
        from emqx_target_vendor_policy import vendor_observer, REFERENCES
        events=[]
        def helper(refs, **kwargs):
            self.assertEqual(refs, REFERENCES)
            self.assertEqual(kwargs['broker'], 'fixed-owned-broker')
            kwargs['private_values'].add(b'synthetic-file-content')
            result=receipt()
            events.append('read')
            if len(events)>1: result.receipts[0]['sha256']='c'*64
            return result
        observe=vendor_observer(broker='fixed-owned-broker',owned_container_id='a'*64,
            private_eval=lambda _:None,private_inspect=lambda:None)
        with patch.dict(sys.modules, {'emqx_owner_vendor_files':SimpleNamespace(observe_vendor_files=helper)}):
            with self.assertRaises(Exception):
                with observe(generation='d'*32,private_values=Values()):
                    self.assertEqual(events,['read'])
        self.assertEqual(events,['read','read'])
