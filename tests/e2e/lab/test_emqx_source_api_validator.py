"""Generated issuance + real identity/private registration; HTTP boundary simulated.

No commercial API, broker, lab or restore was exercised by these tests.
"""
import base64
import copy
from contextlib import contextmanager
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_source_api_validator as m
import emqx_owner_fixture_files as files
import test_emqx_post_restore_values as fixtures
from emqx_private_boundary import PrivateFailure


class SourceAPITests(unittest.TestCase):
    quiesce=fixtures.PostNativeTests.quiesce

    def setUp(self):
        fixtures.PostNativeTests.setUp(self)
        self.http=[];self.fail=None;self.edit_http=None
        self.topics=(b'b1/retained/one',b'b1/retained/two')
        self.credentials=dict(admin_username=b'admin',admin_password=b'generated-ha-admin-password',
            second_username=b'b1ops',second_password=b'generated-ha-second-password',
            api_key=b'generated-source-api-key',api_secret=b'generated-source-api-secret')
        self.documents={
          'mqtt_users':[{'user_id':'b1-gateway','is_superuser':False}],
          'acl_users':[{'username':'b1-gateway','rules':[{},{}]},{'username':'b1-sensor','rules':[{},{}]}],
          'acl_clients':[{'clientid':'b1-dashboard-panel','rules':[{}]}],
          'acl_all':{'rules':[{}]},'authorization_settings':{'no_match':'deny'},
          'authorization_sources':{'sources':[{'type':'file','enable':True}]},
          'banned':[{'as':'clientid','who':'b1-banned-client'}],
          'rules':[{'id':'b1_rule_republish','enable':True},{'id':'b1_rule_http','enable':True}],
          'connectors':[{'type':'http','name':'b1_http','password':'generated-returned-connector-secret'}],
          'actions':[{'type':'http','name':'b1_http_action'}],
          'retainer':[{'topic':x.decode()} for x in self.topics],
          'dashboard_users':[{'username':'admin'},{'username':'b1ops'}],
          'api_keys':[{'name':'b1-import-key','enable':True,'api_secret':'******'}],
          'nodes':[{'node':'emqx@127.0.0.1','version':'5.8.9'}],
        }
        for key in m.PAGED:
            rows=self.documents[key];self.documents[key]={'data':rows,'meta':{'count':len(rows),'page':1,'hasnext':False}}

    def podman(self,*args,**kwargs):
        self.commands.append((args,kwargs))
        if args[:2]==('container','inspect'):
            self.events.append('inspect')
            return SimpleNamespace(returncode=0,stdout=json.dumps(self.doc).encode())
        self.events.append('http');self.http.append((args,kwargs))
        self.assertEqual(args,('exec','-i',self.cid,'curl','-q','--config','-'))
        self.assertEqual({k:v for k,v in kwargs.items() if k!='input'},dict(timeout=10,max_output=m.HTTP_OUTPUT,check=False))
        config=kwargs['input'].decode()
        self.assertIn('proxy = ""',config);self.assertIn('noproxy = "*"',config)
        self.assertIn('max-redirs = 0',config);self.assertIn('max-time = 5',config)
        self.assertNotIn('generated-',repr(args))
        for value in self.credentials.values():
            with self.assertRaises(PrivateFailure): self.prior.scan(value)
        url=json.loads(config.splitlines()[0].split(' = ',1)[1])
        self.assertTrue(url.startswith('http://127.0.0.1:18083/api/v5/'))
        if url.endswith('/login'):
            data=json.loads(json.loads(next(x[7:] for x in config.splitlines() if x.startswith('data = '))))
            doc={'token':'generated-jwt-'+data['username'],'username':data['username'],'role':'administrator'}
        else:
            key=next(k for k,v in m.PATHS.items() if url.endswith('/api/v5'+v))
            for raw in (b'generated-jwt-admin',b'Bearer generated-jwt-admin',
                        b'generated-jwt-b1ops',b'Bearer generated-jwt-b1ops',
                        b'Basic '+base64.b64encode(self.credentials['api_key']+b':'+self.credentials['api_secret'])):
                with self.assertRaises(PrivateFailure):self.prior.scan(raw)
            doc=copy.deepcopy(self.documents[key])
        raw=json.dumps(doc).encode()+b'\napplication/json\n200'
        if self.edit_http:raw=self.edit_http(url,raw)
        if self.fail=='timeout':raise TimeoutError('generated-private-error-must-not-escape')
        return SimpleNamespace(returncode=0,stdout=raw,stderr=b'generated-private-stderr')

    def run_api(self,**changes):
        kwargs=dict(prior_registry=self.prior,provision=self.provision,expected_container_id=self.cid,
            quiesce=self.quiesce,port=18083,retained_topics=self.topics,**self.credentials)
        kwargs.update(changes)
        return m.validate_source_api(**kwargs)

    def refuse(self,**changes):
        with self.assertRaisesRegex(PrivateFailure,'^source-api-refused$'):self.run_api(**changes)

    def test_actual_issuance_current_identity_and_private_http_contract(self):
        old=files._record(self.cap)[0]['cid']
        result=self.run_api()
        self.assertEqual(len(self.http),18)
        self.assertEqual(self.events[0:2],['enter','inspect'])
        self.assertEqual(self.events[-2:],['inspect','exit'])
        self.assertEqual(files._record(self.cap)[0]['cid'],old)
        self.assertEqual(repr(result),'<EMQX private B1 API observation>')
        facts=result.private_facts()
        self.assertEqual(facts['acl_scope'],'source-mnesia-data-only')
        self.assertEqual(facts['active_file_acl_behavior'],'requires-separate-mqtt-validation')
        self.assertEqual(facts['rules']['count'],2)
        for value in (b'generated-old-source-key',b'generated-ha-admin-password',b'generated-source-api-secret',
                      b'generated-jwt-b1ops',b'Bearer generated-jwt-admin',b'generated-returned-connector-secret',b'******'):
            with self.assertRaises(PrivateFailure):result.scan(value)
        docs=result.private_documents();docs.clear();self.assertTrue(result.private_documents())

    def test_login_and_basic_auth_failures_emit_only_fixed_error(self):
        for suffix in ('/login','/nodes'):
            with self.subTest(suffix=suffix):
                self.edit_http=lambda url,raw:raw[:-3]+b'401' if url.endswith(suffix) else raw
                self.refuse()

    def test_missing_groundtruth_fact_and_truncated_inventory_refuse(self):
        self.documents['rules']['data'][0]['id']='unrelated';self.refuse()
        self.documents['rules']['data'][0]['id']='b1_rule_republish'
        self.documents['rules']['meta']['count']=1001;self.refuse()
        self.documents['rules']['meta']['count']=2;self.documents['rules']['meta']['hasnext']=True;self.refuse()

    def test_duplicate_json_unknown_type_oversize_and_content_type_refuse(self):
        for raw in (b'{"token":"one","token":"two"}\napplication/json\n200',
                    b'NaN\napplication/json\n200',b'x'*(m.HTTP_OUTPUT+1),b'{}\ntext/html\n200'):
            with self.subTest(size=len(raw)):
                self.edit_http=lambda url,body:raw;self.refuse()

    def test_timeout_refuses_without_private_error_text(self):
        self.fail='timeout';self.refuse()

    def test_identity_pin_network_and_current_cid_fail_before_http(self):
        for change in (lambda d:d.update(Id='c'*64),lambda d:d.update(Image='sha256:'+'0'*64),
                       lambda d:d['HostConfig'].update(NetworkMode='host')):
            saved=copy.deepcopy(self.doc);change(self.doc[0]);self.refuse();self.doc=saved
        self.assertEqual(self.http,[])

    def test_late_identity_change_refuses(self):
        original=self.podman
        def changed(*args,**kwargs):
            result=original(*args,**kwargs)
            if self.http:self.doc[0]['Config']['Env'].append('UNEXPECTED=value')
            return result
        self.runner.podman=changed;self.refuse()

    def test_old_file_cap_cannot_be_rebound_and_closed_cap_refuses(self):
        old=files._record(self.cap)[0]['cid']
        self.run_api();self.assertEqual(files._record(self.cap)[0]['cid'],old)
        files.revoke(self.cap);self.http.clear();self.refuse();self.assertEqual(self.http,[])

    def test_incomplete_prior_or_invalid_credentials_refuse_before_http(self):
        self.refuse(prior_registry=m.RuntimeRegistry())
        self.refuse(api_key=b'bad:key');self.refuse(api_secret=b'newline\nsecret')
        self.refuse(port=True);self.refuse(second_username=b'admin')
        self.assertEqual(self.http,[])

    def test_quiescence_exit_failure_and_late_finish_return_nothing(self):
        @contextmanager
        def broken_exit():
            yield
            raise RuntimeError('generated-private-lease-error')
        self.refuse(quiesce=broken_exit)
        with patch.object(m.time,'monotonic',side_effect=[0,121]):self.refuse()

    def test_failed_second_login_and_failed_basic_key_refuse(self):
        def second_fails(url,raw):
            return raw[:-3]+b'401' if b'generated-jwt-b1ops' in raw else raw
        self.edit_http=second_fails;self.refuse()
        self.edit_http=None
        original=self.podman
        def basic_fails(*args,**kwargs):
            result=original(*args,**kwargs)
            if args[0]=='exec' and b'Authorization: Basic ' in kwargs['input']:
                result.stdout=result.stdout[:-3]+b'401'
            return result
        self.runner.podman=basic_fails;self.refuse()

    def test_supplemental_native_and_dynamic_runtime_scanners_are_retained(self):
        from emqx_persisted_values import PersistedValues
        self.runtime.register_bundle({'runtime-login-token':[b'generated-old-runtime-token']})
        persisted=PersistedValues('generated-post-phase','source',{},[b'generated-prior-native-value'])
        prior=m.PostRestoreValues(self.prior,persisted,('generated-post-phase',),())
        result=self.run_api(prior_registry=prior)
        for value in (b'generated-old-runtime-token',b'generated-prior-native-value'):
            with self.assertRaises(PrivateFailure):result.scan(value)

    def test_empty_paged_acl_is_not_invented_mnesia_success(self):
        self.documents['acl_users']={'data':[],'meta':{'count':0}};self.refuse()


if __name__=='__main__':unittest.main()
