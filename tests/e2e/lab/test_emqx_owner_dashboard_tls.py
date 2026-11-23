"""Actual pinned dashboard schema callback -> exact consumer; no TLS file reads."""
import base64
from contextlib import contextmanager
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest
from emqx_owner_target import owner_target_readers
from emqx_private_boundary import PrivateFailure
from emqx_target_vendor_policy import DisabledVendorTLS,FILES
import test_emqx_owner_target as fixtures
import test_emqx_target_vendor_policy as file_fixtures

ROOT=Path(__file__).parent


class DashboardTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from emqx_native_runtime import run_native
        with tempfile.TemporaryDirectory(prefix='emqx-public-dashboard-tls-') as directory:
            root=Path(directory)
            for name in ('emqx_owner_dashboard_tls_fixture.escript','emqx_owner_target.expr'):
                (root/name).write_bytes((ROOT/name).read_bytes())
            with tempfile.TemporaryFile() as output:
                code=run_native(root,'emqx_owner_dashboard_tls_fixture.escript',
                    args=('/input/emqx_owner_target.expr',),output=output)
                output.seek(0)
                raw=output.read(1048577)
                if code or len(raw)>1048576: raise AssertionError('pinned dashboard TLS schema fixture refused')
                cls.native=json.loads(raw)

    @contextmanager
    def quiet(self): yield

    @contextmanager
    def observer(self,*,generation,private_values):
        private_values.add(b'generated-vendor-file-bytes')
        yield file_fixtures.VendorACLPolicyTests().observed()

    def transport(self,edit=None):
        def evaluate(expression):
            nonce=re.search(r'generation => <<"([0-9a-f]{32})">>',expression)[1]
            doc=fixtures.reply_document(nonce)
            native=copy.deepcopy(self.native)
            dashboard=native['config']['value'][0][1]
            if edit: edit(dashboard)
            for pair in doc['config']['value']:
                if pair[0]['value']=='dashboard':pair[1]=dashboard
            doc['contract']='emqx-owner-live-target-v2'
            doc['config_secret_wrappers']=native['config_secret_wrappers']
            return b'WOOWTARGET:'+base64.b64encode(json.dumps(doc).encode())+b':ENDok'
        return evaluate

    def test_pinned_callback_and_vendor_defaults_enter_exact_readers(self):
        with owner_target_readers(private_eval=self.transport(),quiesce=self.quiet,vendor_observer=self.observer) as readers:
            self.assertEqual(len(readers),5)
            with readers['target-bootstrap']() as stream:
                self.assertEqual(json.load(stream)['records'],[{
                    'username':'fixture-dashboard-tls-user','password':'fixture-dashboard-tls-password'}])
            for value in (b'emqx_tls_psk',b'lookup',b'F2653DFD1072A73E2E6FEC1D77865D1F',
                    b'DE702B30F75648B1435B584233503E51347F769A39B94DC5A2237781179633D6',
                    b'generated-vendor-file-bytes',b'fixture-dashboard-tls-password'):
                with self.assertRaises(PrivateFailure):readers.persisted_values.scan(value)

    def test_unobserved_files_still_refuse(self):
        with self.assertRaises(PrivateFailure):
            with owner_target_readers(private_eval=self.transport(),quiesce=self.quiet):pass

    def test_active_missing_or_untyped_bind_and_custom_file_refuse(self):
        for mode in ('active','missing','string','custom'):
            def edit(dashboard):
                listeners=next(v for k,v in dashboard['value'] if k['value']=='listeners')
                https=next(v for k,v in listeners['value'] if k['value']=='https')
                if mode=='missing':https['value'][:]=[p for p in https['value'] if p[0]['value']!='bind']
                elif mode in ('active','string'):
                    next(p for p in https['value'] if p[0]['value']=='bind')[1]=fixtures.typed(18084 if mode=='active' else '0')
                else:
                    options=next(v for k,v in https['value'] if k['value']=='ssl_options')
                    next(p for p in options['value'] if p[0]['value']=='certfile')[1]=fixtures.typed('${EMQX_ETC_DIR}/certs/custom.pem')
            with self.subTest(mode=mode),self.assertRaises(PrivateFailure):
                with owner_target_readers(private_eval=self.transport(edit),quiesce=self.quiet,vendor_observer=self.observer):pass


    def test_policy_requires_all_three_defaults_and_their_receipts(self):
        config={'dashboard':{'listeners':{'https':{'bind':0,'ssl_options':{
            key:'${EMQX_ETC_DIR}/certs/'+filename for key,filename in FILES.items()}}}}}
        policy=DisabledVendorTLS(file_fixtures.VendorACLPolicyTests().observed())
        self.assertTrue(policy.dashboard_https_defaults(config))
        for key in FILES:
            changed=copy.deepcopy(config)
            del changed['dashboard']['listeners']['https']['ssl_options'][key]
            self.assertFalse(policy.dashboard_https_defaults(changed))
        observed=file_fixtures.VendorACLPolicyTests().observed()
        observed.receipts=tuple(r for r in observed.receipts if not r['path'].endswith('/key.pem'))
        with self.assertRaises(Exception):DisabledVendorTLS(observed)
