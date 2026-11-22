"""Pinned schema-derived dashboard config through exact consumer, no lab."""
import base64
from contextlib import contextmanager
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest
from emqx_owner_target import owner_target_readers,OwnerCaptureRefused
import test_emqx_owner_target as fixtures

ROOT=Path(__file__).parent


class DashboardProfileTests(unittest.TestCase):
    @contextmanager
    def quiet(self): yield

    def test_present_bad_https_and_credentials_have_fixed_reasons(self):
        cases=(('https_type',None),('https_bind_missing',{}),('https_bind_type',{'bind':'0'}),
               ('https_enabled',{'bind':18084}))
        for code,value in cases:
            config=fixtures.cooked_config()
            config['dashboard']['listeners']['https']=value if value is not None else fixtures.Atom('undefined')
            self.refused(config,code)
        for label,key in (('username','default_username'),('password','default_password')):
            for kind in ('missing','type','charlist','invalid'):
                config=fixtures.cooked_config()
                if kind=='missing': del config['dashboard'][key]
                else: config['dashboard'][key]={'type':{},'charlist':[97,98],'invalid':b''}[kind]
                self.refused(config,label+'_'+kind)

    def refused(self,config,code):
        with self.subTest(code=code),self.assertRaises(OwnerCaptureRefused) as caught:
            with owner_target_readers(private_eval=fixtures.OwnerProducerTests().transport([],config=config),
                    quiesce=self.quiet): pass
        self.assertEqual(caught.exception.phase,'dashboard')
        self.assertEqual(caught.exception.reason,'dashboard_'+code)

    def test_missing_listeners_is_not_proven_absence(self):
        config=fixtures.cooked_config()
        del config['dashboard']['listeners']
        self.refused(config,'listeners_missing')

    def test_native_schema_omitted_https_and_binary_credentials(self):
        from emqx_native_runtime import run_native
        with tempfile.TemporaryDirectory(prefix='emqx-public-dashboard-fixture-') as directory:
            root=Path(directory)
            for name in ('emqx_owner_dashboard_fixture.escript','emqx_owner_target.expr'):
                (root/name).write_bytes((ROOT/name).read_bytes())
            with tempfile.TemporaryFile() as output:
                self.assertEqual(run_native(root,'emqx_owner_dashboard_fixture.escript',
                    args=('/input/emqx_owner_target.expr',),output=output),0)
                output.seek(0)
                native=json.loads(output.read(1048577))
        def evaluate(expression):
            nonce=re.search(r'generation => <<"([0-9a-f]{32})">>',expression)[1]
            doc=fixtures.reply_document(nonce)
            dashboard=native['config']['value'][0][1]
            for pair in doc['config']['value']:
                if pair[0]['value']=='dashboard': pair[1]=copy.deepcopy(dashboard)
            doc['contract']='emqx-owner-live-target-v2'
            doc['config_secret_wrappers']=copy.deepcopy(native['config_secret_wrappers'])
            return b'WOOWTARGET:'+base64.b64encode(json.dumps(doc).encode())+b':ENDok'
        with owner_target_readers(private_eval=evaluate,quiesce=self.quiet) as readers:
            with readers['target-bootstrap']() as stream:
                self.assertEqual(json.load(stream)['records'],[{
                    'username':'fixture-schema-dashboard-user','password':'fixture-schema-dashboard-password'}])
            for value in (b'fixture-schema-dashboard-user',b'fixture-schema-dashboard-password'):
                with self.assertRaises(Exception): readers.persisted_values.scan(value)
