"""Generated fixture/process-boundary integration only: no lab or broker execution."""
import base64
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import re
import struct
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_fresh_owner_workflow as workflow
import emqx_private_owner_driver as driver
import emqx_owner_source_capture as source_owner
import emqx_real_candidate as real
import emqx_owner_vendor_files as vendor_files
from emqx_target_vendor_policy import FILES, REFERENCES
from emqx_private_boundary import PrivateFailure
from emqx_source_profiles import ARM_SOURCE
from test_emqx_source_cold_capture import decoder


class FixtureRunner:
    owner = 'appowner'
    uid = os.geteuid()
    def __init__(self):
        self.calls, self.events, self.volumes, self.containers = [], [], {}, {}
        from test_emqx_owner_vendor_files import VendorFilesTests
        self.vendor = VendorFilesTests()
        self.vendor.setUp()
        self.vendor.paths = sorted(vendor_files.ALIASES[p] for p in REFERENCES)
        for doc in (self.vendor.image, self.vendor.actual):
            doc['files'] = [f for f in doc['files'] if f['path'] in self.vendor.paths]
        self.failure = None
        self.target_edit = None
        self.login_status = 200
        self.config_paths, self.credentials = [], []
        self.volumes['unrelated-fixture'] = {'Name':'unrelated-fixture','Labels':{}}

    def result(self,raw=b'',code=0):
        return SimpleNamespace(returncode=code,stdout=raw,stderr=b'generated-private-diagnostic')

    def podman(self,*args,**kwargs):
        self.calls.append((args,kwargs))
        if args[:2] == ('image','inspect'):
            return self.result(json.dumps([{'Id':'sha256:'+workflow.IMAGE,
                'Config':{'Labels':{'org.opencontainers.image.version':'5.8.9'}}}]).encode())
        if args[0] in ('container','volume') and args[1]=='exists':
            objects = self.containers if args[0]=='container' else self.volumes
            if self.failure == 'collision' and args[0]=='container':
                return self.result(code=0)
            return self.result(code=0 if args[2] in objects else 1)
        if args[:2] == ('volume','create'):
            name = args[-1]
            nonce = args[args.index('--label')+1].split('=',1)[1]
            self.volumes[name] = {'Name':name,'Labels':{workflow.LABEL:nonce}}
            if self.failure=='volume-timeout': raise subprocess.TimeoutExpired('generated',15)
            return self.result(name.encode())
        if args[0]=='run':
            self.events.append('empty-target-started')
            name = args[args.index('--name')+1]
            nonce = args[args.index('--label')+1].split('=',1)[1]
            mounts = [args[i+1] for i,arg in enumerate(args) if arg=='-v']
            self.assert_mounts(mounts)
            config = Path(mounts[2].split(':/opt/emqx/etc/emqx.conf:ro')[0])
            raw = config.read_text()
            self.config_paths.append(config)
            assert config.stat().st_mode&0o777 == 0o600
            assert config.parent.stat().st_mode&0o777 == 0o700
            user = re.search(r'dashboard.default_username="([^"]+)"',raw)[1]
            password = re.search(r'dashboard.default_password="([^"]+)"',raw)[1]
            self.credentials.append((user,password))
            assert user not in repr((args,kwargs)) and password not in repr((args,kwargs))
            assert '--network=none' in args and '--pull=never' in args
            assert '--log-driver=none' in args and '--image-volume=ignore' in args
            assert not any('publish' in a for a in args)
            self.containers[name] = {'Id':'a'*64,'Name':'/'+name,'Image':'sha256:'+workflow.IMAGE,
                'Config':{'Labels':{workflow.LABEL:nonce},'Env':[]},'State':{'Running':True},
                'HostConfig':{'NetworkMode':'none','PortBindings':{},'LogConfig':{'Type':'none'},
                    'Memory':768*1024**2,'PidsLimit':256,'NanoCpus':750000000},
                'Mounts':[{'Type':'volume','Name':mounts[0].split(':')[0],'Destination':'/opt/emqx/data'},
                          {'Type':'volume','Name':mounts[1].split(':')[0],'Destination':'/opt/emqx/log'},
                          {'Type':'bind','Source':str(config),'Destination':'/opt/emqx/etc/emqx.conf','RW':False}]}
            if self.failure=='run-timeout': raise subprocess.TimeoutExpired('generated',15)
            return self.result(b'a'*64+b'\n')
        if args[0] in ('container','volume') and args[1]=='inspect':
            objects = self.containers if args[0]=='container' else self.volumes
            return self.result(json.dumps([objects[args[2]]]).encode())
        if args[0]=='inspect':
            assert 'ticker-suspended' in self.events
            self.events.append('held-vendor-inspect')
            return self.result(json.dumps([self.containers[args[1]]]).encode())
        if args[0]=='rm':
            self.events.append('target-removed')
            self.containers.pop(args[-1])
            return self.result()
        if args[:2]==('volume','rm'):
            if any(any(m.get('Name')==args[-1] for m in c['Mounts']) for c in self.containers.values()):
                return self.result(code=1)
            self.volumes.pop(args[-1])
            return self.result()
        if args[0]=='exec' and args[2:]==('emqx','ctl','status'):
            return self.result(b'not ready',code=1) if self.failure=='ready-timeout' else self.result(b'emqx is started')
        if args[:2]==('exec','-i'):
            self.events.append('registered-login')
            from emqx_private_owner_driver import HTTP_OUTPUT
            assert kwargs['max_output']==HTTP_OUTPUT
            config = kwargs['input'].decode().splitlines()
            data = next(line[7:] for line in config if line.startswith('data = '))
            user,password = self.credentials[-1]
            assert json.loads(json.loads(data)) == {'username':user,'password':password}
            return self.result(b'{"token":"generated-fresh-private-token"}\napplication/json\n'+str(self.login_status).encode())
        if args[0]=='exec' and args[2:4]==('emqx','eval'):
            expression = args[4]
            if expression==workflow.SUSPEND_SYS_EXPR:
                self.events.append('ticker-suspended')
                return self.result(b'WOOWSYS:<0.1.0>:suspendedok')
            if expression==workflow.TICKER_STATUS_EXPR.replace('{pid}','<0.1.0>'):
                return self.result(b'ticker_unchanged')
            if 'OWNERNOCLIENTS' in expression:
                return self.result(b'OWNERNOCLIENTSok')
            if kwargs.get('timeout') == 10:
                assert 'ticker-suspended' in self.events
                self.events.append('held-vendor-observed')
                return self.result(self.vendor.eval_callback(expression))
            from test_emqx_owner_target import reply_document,cooked_config
            generation = re.search(r'generation => <<"([0-9a-f]{32})">>',expression)[1]
            user,password = self.credentials[-1]
            config = cooked_config()
            for kind in ('ssl','wss'):
                config['listeners'][kind]['default']['ssl_options'] = {
                    key:'${EMQX_ETC_DIR}/certs/'+name for key,name in FILES.items()}
            config['dashboard']['default_username']=user
            config['dashboard']['default_password']=password
            doc = reply_document(generation,config)
            if self.target_edit: self.target_edit(doc)
            self.events.append('actual-target-consumer')
            return self.result(b'WOOWTARGET:'+base64.b64encode(json.dumps(doc).encode())+b':ENDok\n')
        raise AssertionError('unexpected generated boundary command')

    def assert_mounts(self,mounts):
        assert len(mounts)==3
        assert mounts[0].endswith(':/opt/emqx/data')
        assert mounts[1].endswith(':/opt/emqx/log')
        assert mounts[2].endswith(':/opt/emqx/etc/emqx.conf:ro')
        assert 'encrypted-source.tar' not in repr(mounts)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        from test_emqx_owner_source_capture import OwnerHarnessTests
        OwnerHarnessTests.fixture(self)
        self.parser = OwnerHarnessTests.hocon
        self.profile = replace(ARM_SOURCE,archive=self.path,sha256=self.digest,cold_receipt=None)
        self.runner = FixtureRunner()
        self.evidence = self.root/'evidence'; self.evidence.mkdir(mode=0o700)
        self.staging = self.root/'candidate'; self.staging.mkdir(mode=0o700)
        self.work = SimpleNamespace(log=lambda *a:None,runner=lambda app:self.runner)
        self.app = SimpleNamespace(id='emqx')
        self.realm = patch.object(workflow.socket,'gethostname',return_value='woowbk-dev-d')
        self.realm.start(); self.addCleanup(self.realm.stop)
        native = patch.object(vendor_files, 'run_native',
            side_effect=lambda *args,**kwargs:self.runner.vendor.native(*args,**kwargs))
        native.start(); self.addCleanup(native.stop)

    def frame(self,**changes):
        raw = self.path.read_bytes()
        key = self.password.encode('ascii')
        return io.BytesIO(struct.pack('!I',len(key))+key+struct.pack('!Q',len(raw))+raw)

    def invoke(self,frame=None):
        return workflow.build_fresh_framed_candidate(self.work,self.app,object(),
            self.frame() if frame is None else frame,self.staging,'j20261122T000000Z-12345678',
            runner=self.runner,private_parent=self.root,source_mode='--source',
            evidence_directory=self.evidence,evidence_name='fresh-preflight.json')

    def assert_owned_cleanup(self):
        self.assertEqual(self.runner.containers,{})
        self.assertEqual(set(self.runner.volumes),{'unrelated-fixture'})
        self.assertTrue(all(not p.exists() for p in self.runner.config_paths))
        self.assertEqual(list(self.root.glob('emqx-framed-private-*')),[])
        self.assertEqual(list(self.root.glob('emqx-fresh-private-*')),[])
        self.assertNotIn('prune',repr(self.runner.calls))

    def test_real_framed_callsite_through_actual_driver_gates_and_bridge_byte_boundary(self):
        observed = []
        def inner(work,app,tmp,target,private,**kwargs):
            self.assertTrue((self.evidence/'fresh-preflight.json').is_file())
            self.assertIn('registered-login',self.runner.events)
            self.assertTrue(Path(target.files[0][0]).exists())
            with work.open('fedcba98_woow-emqx') as replay:
                self.assertFalse(replay.writable())
                observed.append(replay.read())
            self.runner.events.append('gated-source-byte-boundary')
            raise RuntimeError('generated-stop-before-source-broker')
        with patch.object(workflow,'source_profile',return_value=self.profile), \
             patch.object(source_owner,'native_hocon',self.parser), \
             patch.object(source_owner,'native_cold_history',decoder), \
             patch.object(workflow,'build_owner_candidate',wraps=driver.build_owner_candidate) as callsite, \
             patch.object(real.hacommon,'image_labels',return_value={'org.opencontainers.image.version':'5.8.9'}), \
             patch.object(real.tempctr,'TempObjects') as objects, \
             patch.object(real.ha_emqx,'_build_candidate',side_effect=inner) as boundary, \
             patch.object(real.ha_emqx,'_package_candidate') as package:
            objects.return_value.cleanup.return_value=[]
            with self.assertRaisesRegex(PrivateFailure,'^private-fresh-workflow-refused$'): self.invoke()
            callsite.assert_called_once(); boundary.assert_called_once(); package.assert_not_called()
            self.assertEqual(callsite.call_args.kwargs['username'].decode(),self.runner.credentials[-1][0])
            self.assertEqual(callsite.call_args.kwargs['password'].decode(),self.runner.credentials[-1][1])
        self.assertEqual(observed,[self.raw])
        self.assertIn('held-vendor-inspect',self.runner.events)
        self.assertEqual(self.runner.events.count('held-vendor-observed'), 1)
        # The deliberate inner-byte failure still unwinds the held observer;
        # after-observation only runs on normal return by its existing contract.
        self.assertLess(self.runner.events.index('held-vendor-observed'),
                        self.runner.events.index('actual-target-consumer'))
        for args,kwargs in self.runner.calls:
            self.assertNotIn(self.password,repr(args))
            self.assertNotIn('env',kwargs)
            for username,password in self.runner.credentials:
                self.assertNotIn(password,repr(args))
        self.assertLess(self.runner.events.index('gated-source-byte-boundary'),self.runner.events.index('target-removed'))
        self.assert_owned_cleanup()
        self.assertEqual(json.loads((self.evidence/'fresh-preflight.json').read_bytes())['phase'],'preflight')

    def test_target_matches_product_attribute_contract_and_preserves_implicit_authorization(self):
        with workflow.fresh_target(runner=self.runner,private_parent=self.root) as fixture:
            target = fixture.target
            self.assertEqual(set(vars(target)),{'container','image','data_volume','log_volume',
                                                'env','secrets','files','node'})
            config = fixture.config.read_text()
            self.assertNotIn('authorization',config)
            self.assertIn('node.name="'+target.node+'"',config)
            self.assertEqual(target.env['EMQX_NODE__NAME'],target.node)
            self.assertEqual(target.secrets,[])
            self.assertEqual(target.files,[(str(fixture.config),'/opt/emqx/etc/emqx.conf','ro')])
            run = next(args for args,_ in self.runner.calls if args[0]=='run')
            self.assertIn('EMQX_NODE__NAME='+target.node,run)
        self.assert_owned_cleanup()

    def test_target_or_login_refusal_cleans_fixture_and_never_reaches_candidate_bridge(self):
        for failure in ('target','login','references'):
            self.runner = FixtureRunner()
            if failure=='target': self.runner.target_edit=lambda doc:doc.update(generation='wrong')
            if failure=='login': self.runner.login_status=401
            if failure=='references':
                def file_authorizer(doc):
                    from test_emqx_owner_target import typed,cooked_config,Atom
                    config=cooked_config()
                    config['authorization']={'sources':[{'type':Atom('file'),'enable':True,
                        'path':'${EMQX_ETC_DIR}/acl.conf'}]}
                    doc['config']=typed(config)
                self.runner.target_edit=file_authorizer
            with patch.object(workflow,'source_profile',return_value=self.profile), \
                 patch.object(source_owner,'native_hocon',self.parser), \
                 patch.object(source_owner,'native_cold_history',decoder), \
                 patch.object(driver,'build_captured_candidate') as bridge:
                with self.assertRaises(PrivateFailure): self.invoke()
                bridge.assert_not_called()
            self.assertEqual(list(self.evidence.iterdir()),[])
            self.assert_owned_cleanup()

    def test_bad_frame_sha_trailing_short_and_late_finish_create_no_target(self):
        class Late(io.BytesIO):
            def finish(self): raise ValueError('generated-private-finish-error')
        good = self.frame().getvalue()
        for frame in (io.BytesIO(good[:-1]),io.BytesIO(good+b'x'),io.BytesIO(good[:-1]+b'x'),Late(good)):
            with patch.object(workflow,'source_profile',return_value=self.profile):
                with self.assertRaises(PrivateFailure): self.invoke(frame)
            self.assertEqual(self.runner.calls,[])
            self.assert_owned_cleanup()

    def test_fresh_target_collision_and_partial_create_timeouts_cleanup_only_owned_names(self):
        for failure in ('collision','volume-timeout','run-timeout'):
            self.runner = FixtureRunner(); self.runner.failure=failure
            with self.assertRaises(PrivateFailure):
                with workflow.fresh_target(runner=self.runner,private_parent=self.root):
                    self.fail('failed setup yielded')
            self.assert_owned_cleanup()

    def test_readiness_deadline_cleans_named_container_and_both_volumes(self):
        self.runner.failure='ready-timeout'
        with patch.object(workflow.time,'monotonic',side_effect=[0,1,80]), \
             patch.object(workflow.time,'sleep'):
            with self.assertRaises(PrivateFailure):
                with workflow.fresh_target(runner=self.runner,private_parent=self.root):
                    self.fail('unready target yielded')
        self.assert_owned_cleanup()

    def test_replaced_identity_or_label_is_not_deleted_by_fixture_cleanup(self):
        with self.assertRaises(PrivateFailure):
            with workflow.fresh_target(runner=self.runner,private_parent=self.root) as fixture:
                self.runner.containers[fixture.name]['Config']['Labels'][workflow.LABEL]='unowned-replacement'
        self.assertIn(fixture.name,self.runner.containers)
        self.assertFalse(any(args[0]=='rm' for args,_ in self.runner.calls))

    def test_wrong_owner_realm_refuses_before_runner_or_frame_reads(self):
        with patch.object(workflow.socket,'gethostname',return_value='not-dev-d'):
            with self.assertRaises(PrivateFailure): self.invoke(io.BytesIO(b''))
        self.assertEqual(self.runner.calls,[])

    def test_missing_or_forged_vendor_file_contract_prevents_bridge(self):
        for case in ('missing','forged'):
            self.runner = FixtureRunner()
            if case == 'missing': self.runner.vendor.actual['files'].pop()
            else: self.runner.vendor.actual['files'][0]['sha256'] = '0'*64
            with self.subTest(case=case), patch.object(workflow,'source_profile',return_value=self.profile), \
                 patch.object(source_owner,'native_hocon',self.parser), \
                 patch.object(source_owner,'native_cold_history',decoder), \
                 patch.object(driver,'build_captured_candidate') as bridge:
                with self.assertRaises(PrivateFailure): self.invoke()
                bridge.assert_not_called()
            self.assertNotIn('actual-target-consumer',self.runner.events)
            self.assert_owned_cleanup()
