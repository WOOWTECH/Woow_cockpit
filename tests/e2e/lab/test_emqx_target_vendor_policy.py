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

    def test_cross_sidecar_identity_is_not_target_identity(self):
        import sys
        from unittest.mock import patch
        from emqx_semantic_readers import Values
        from emqx_target_vendor_policy import vendor_observer
        for changed in ('image_identity','target_identity','sha256'):
            calls=[]
            def helper(*args,**kwargs):
                result=receipt()
                if calls:
                    result.receipts[0][changed]='c'*64 if changed=='sha256' else (99,)
                calls.append(True)
                return result
            observe=vendor_observer(broker='fixed-owned-broker',owned_container_id='a'*64,
                private_eval=lambda _:None,private_inspect=lambda:None)
            with self.subTest(changed=changed), patch.dict(sys.modules,{
                    'emqx_owner_vendor_files':SimpleNamespace(observe_vendor_files=helper)}):
                if changed=='image_identity':
                    with observe(generation='d'*32,private_values=Values()): pass
                else:
                    with self.assertRaises(Exception):
                        with observe(generation='d'*32,private_values=Values()): pass
                self.assertEqual(len(calls),2)


class DefaultOriginPolicyTests(unittest.TestCase):
    def config(self, kind='ws'):
        from emqx_target_vendor_policy import DEFAULT_ORIGINS
        return {'listeners':{kind:{'default':{'enable':'false','websocket':{
            'check_origin_enable':'false','check_origins':list(DEFAULT_ORIGINS)}}}}}

    def test_exact_defaults_are_passive_only(self):
        for kind in ('ws','wss'):
            _no_refs(self.config(kind))
        for case in ('active','checking','missing_flag','custom','userinfo','reorder','wrong_listener','wrong_name','string'):
            config=self.config()
            listener=config['listeners']['ws']['default']
            ws=listener['websocket']
            if case=='active': listener['enable']='true'
            if case=='checking': ws['check_origin_enable']='true'
            if case=='missing_flag': del ws['check_origin_enable']
            if case=='custom': ws['check_origins'][0]=b'http://example.invalid'
            if case=='userinfo': ws['check_origins'][0]=b'http://user:private@localhost:18083'
            if case=='reorder': ws['check_origins'].reverse()
            if case=='wrong_listener': config['listeners']['tcp']=config['listeners'].pop('ws')
            if case=='wrong_name': config['listeners']['ws']['custom']=config['listeners']['ws'].pop('default')
            if case=='string': ws['check_origins']=[item.decode() for item in ws['check_origins']]
            with self.subTest(case=case),self.assertRaises(Exception): _no_refs(config)

    def test_native_values_remain_registered(self):
        from emqx_owner_target import _decode
        from emqx_semantic_readers import Values
        from emqx_persisted_values import PersistedValues
        values=Values()
        config=fixtures.cooked_config()
        config['listeners']['ws']['default']['websocket']={
            'check_origin_enable':False,'check_origins':[
                b'http://localhost:18083',b'http://127.0.0.1:18083']}
        decoded=_decode(fixtures.typed(config),values)
        _no_refs(decoded)
        companion=PersistedValues('generation','target',{},values.values)
        for origin in (b'http://localhost:18083',b'http://127.0.0.1:18083'):
            with self.assertRaises(Exception): companion.scan(origin)


class ActiveBootstrapPolicyTests(unittest.TestCase):
    def observed(self):
        from emqx_target_vendor_policy import BOOTSTRAP_PATH
        observed=receipt()
        item=dict(observed.receipts[0],path=BOOTSTRAP_PATH)
        observed.receipts=observed.receipts+(item,)
        return observed

    def config(self):
        from emqx_target_vendor_policy import BOOTSTRAP_REFERENCE
        return {'authentication':[{'enable':'true','mechanism':b'password_based',
            'backend':b'built_in_database','user_id_type':b'username',
            'bootstrap_type':'plain','bootstrap_file':BOOTSTRAP_REFERENCE}]}

    def test_exact_active_dependency_requires_observation(self):
        policy=DisabledVendorTLS(self.observed())
        _no_refs(self.config(),vendor_policy=policy)
        with self.assertRaises(Exception):
            _no_refs(self.config(),vendor_policy=DisabledVendorTLS(receipt()))
        for field,value in (('bootstrap_file','${EMQX_ETC_DIR}/custom.csv'),
                ('bootstrap_type','hash'),('backend',b'http'),('enable','false')):
            config=self.config()
            config['authentication'][0][field]=value
            with self.subTest(field=field),self.assertRaises(Exception):
                _no_refs(config,vendor_policy=policy)

    def test_wrong_scope_and_missing_file_receipt_refused(self):
        policy=DisabledVendorTLS(self.observed())
        config=self.config()
        config['authentication'].append(dict(config['authentication'][0]))
        with self.assertRaises(Exception): _no_refs(config,vendor_policy=policy)
        observed=self.observed()
        observed.receipts[-1]['bytes']=0
        with self.assertRaises(Exception): DisabledVendorTLS(observed)

    def test_complete_csv_values_survive_consumer_projection(self):
        from emqx_target_vendor_policy import BOOTSTRAP_REFERENCE
        events=[]
        @contextmanager
        def quiet(): yield
        @contextmanager
        def observer(*,generation,private_values):
            # Trusted helper contract: whole bytes AND every parsed cell, EOF.
            for value in (b'user_id,password,is_superuser\nfixture-csv-user,fixture-csv-secret,false\n',
                    b'fixture-csv-user',b'fixture-csv-secret',b'false'):
                private_values.add(value)
            yield self.observed()
        config=fixtures.cooked_config()
        config['authentication'][0].update(bootstrap_type=fixtures.Atom('plain'),
            bootstrap_file=BOOTSTRAP_REFERENCE)
        transport=fixtures.OwnerProducerTests().transport(events,config=config)
        with owner_target_readers(private_eval=transport,quiesce=quiet,vendor_observer=observer) as readers:
            for value in (b'fixture-csv-user',b'fixture-csv-secret'):
                with self.assertRaises(Exception): readers.persisted_values.scan(value)


class VendorACLPolicyTests(unittest.TestCase):
    def observed(self):
        from emqx_target_vendor_policy import ACL_PATH
        observed=ActiveBootstrapPolicyTests().observed()
        observed.receipts=observed.receipts+(dict(observed.receipts[0],path=ACL_PATH),)
        return observed

    def config(self, value=None):
        from emqx_target_vendor_policy import ACL_REFERENCE
        return {'authorization':{'sources':[{'type':'file','enable':'true',
            'path':ACL_REFERENCE if value is None else value}]}}

    def test_exact_explicit_path_and_typed_enable(self):
        from emqx_target_vendor_policy import ACL_REFERENCE,ACL_PATH
        policy=DisabledVendorTLS(self.observed())
        for path in (ACL_REFERENCE,ACL_PATH,ACL_REFERENCE.encode(),list(ACL_REFERENCE.encode())):
            _no_refs(self.config(path),vendor_policy=policy)
        for change in ('implicit','custom','untyped','unknown_ref','wrong_root','missing_receipt'):
            config=self.config()
            source=config['authorization']['sources'][0]
            if change=='implicit': del source['path']
            if change=='custom': source['path']='/mounted/custom-acl.conf'
            if change=='untyped': source['enable']=True
            if change=='unknown_ref': source['private_extra']='vault:private'
            if change=='wrong_root': config={'other':source}
            active_policy=DisabledVendorTLS(receipt()) if change=='missing_receipt' else policy
            with self.subTest(change=change),self.assertRaises(Exception):
                _no_refs(config,vendor_policy=active_policy)
        with self.assertRaises(Exception): _no_refs(self.config())

    def test_root_binds_same_source_object(self):
        policy=DisabledVendorTLS(self.observed())
        config=self.config()
        source=config['authorization']['sources'][0]
        self.assertTrue(policy.acl_source(config,('authorization','sources',0),source))
        self.assertFalse(policy.acl_source(config,('authorization','sources',0),dict(source)))

    def test_actual_acl_values_remain_in_private_companion(self):
        events=[]
        @contextmanager
        def quiet(): yield
        @contextmanager
        def observer(*,generation,private_values):
            # Synthetic trusted helper: real helper must parse complete terms EOF.
            for value in (b'{allow,{username,"fixture-acl-user"},subscribe,["fixture/topic"]}.',
                          b'fixture-acl-user',b'fixture/topic'):
                private_values.add(value)
            yield self.observed()
        config=fixtures.cooked_config()
        config.update(self.config())
        config['authorization']['sources'][0]['type']=fixtures.Atom('file')
        config['authorization']['sources'][0]['enable']=True
        transport=fixtures.OwnerProducerTests().transport(events,config=config)
        with owner_target_readers(private_eval=transport,quiesce=quiet,vendor_observer=observer) as readers:
            for value in (b'fixture-acl-user',b'fixture/topic'):
                with self.assertRaises(Exception): readers.persisted_values.scan(value)
