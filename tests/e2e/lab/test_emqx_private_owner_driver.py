"""Generated owner/curl subprocess boundaries only; no lab, network or restore."""
import base64
from contextlib import contextmanager
import io
import json
import re
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import emqx_private_owner_driver as driver
import emqx_owner_source_capture as source_owner
import emqx_real_candidate as real
import emqx_owner_vendor_files as vendor_files
from emqx_target_vendor_policy import FILES
from emqx_private_boundary import PrivateFailure
from emqx_runtime_credentials import RuntimeRegistry, login_registered
from emqx_runtime_workflow import CombinedRegistry
from test_emqx_source_cold_capture import decoder

BROKER = 'woowbk-emqx-fresh-012345abcdef'
URL = 'http://127.0.0.1:18083/api/v5/login'
USER, PASSWORD = b'generated-owner-user', b'generated-owner-password'
TOKEN = b'generated-owner-private-token'


def response(status=200, body=None):
    if body is None: body = json.dumps({'token':TOKEN.decode()}).encode()
    return SimpleNamespace(returncode=0,stdout=body+b'\napplication/json; charset=utf-8\n'+str(status).encode(),
                           stderr=b'generated-private-curl-diagnostic')


class CurlTests(unittest.TestCase):
    def test_lazy_stdin_config_and_actual_runtime_registration_before_exec(self):
        registry = RuntimeRegistry()
        def podman(*args,**kwargs):
            self.assertEqual(registry._categories['runtime-login-input'],2)
            self.assertEqual(args,('exec','-i',BROKER,'curl','-q','--config','-'))
            self.assertEqual(kwargs['timeout'],10)
            self.assertEqual(kwargs['max_output'],driver.HTTP_OUTPUT)
            self.assertFalse(kwargs['check'])
            self.assertNotIn('env',kwargs)
            self.assertNotIn(PASSWORD.decode(),repr(args))
            self.assertNotIn(USER.decode(),repr(args))
            config = kwargs['input'].decode().splitlines()
            data = next(line.split(' = ',1)[1] for line in config if line.startswith('data = '))
            self.assertEqual(json.loads(json.loads(data)),{'username':USER.decode(),'password':PASSWORD.decode()})
            self.assertIn('url = '+json.dumps(URL),config)
            self.assertIn('max-time = 5',config)
            return response()
        runner = SimpleNamespace(podman=Mock(side_effect=podman))
        transport = driver.curl_login_transport(runner=runner,broker=BROKER,login_url=URL)
        runner.podman.assert_not_called()
        credential = login_registered(registry,transport,username=USER,password=PASSWORD)
        self.assertEqual(credential.with_bearer(lambda value:value),b'Bearer '+TOKEN)
        for value in (USER,PASSWORD,TOKEN,b'Bearer '+TOKEN):
            with self.assertRaises(PrivateFailure): registry.scan_login_evidence(value)
        with self.assertRaises(PrivateFailure): registry.summary()  # no invented target completeness

    def test_quotes_newlines_unicode_remain_inside_one_stdin_data_directive(self):
        user = 'generated-用戶'.encode()
        password = b'generated"\nurl = "http://external.invalid"\nprivate'
        runner = SimpleNamespace(podman=Mock(return_value=response()))
        registry = RuntimeRegistry()
        login_registered(registry,driver.curl_login_transport(runner=runner,broker=BROKER,login_url=URL),
                         username=user,password=password)
        call = runner.podman.call_args
        config = call.kwargs['input'].decode().splitlines()
        self.assertEqual(sum(line.startswith('url = ') for line in config),1)
        self.assertEqual(sum(line.startswith('data = ') for line in config),1)
        data = next(line[7:] for line in config if line.startswith('data = '))
        self.assertEqual(json.loads(json.loads(data)),{'username':user.decode(),'password':password.decode()})
        self.assertNotIn('external.invalid',repr(call.args))

    def test_failed_status_malformed_oversize_timeout_and_diagnostics_never_return_credential(self):
        malformed = [response(401,b'generated-private-denial'),
            SimpleNamespace(returncode=7,stdout=b'generated-private-error',stderr=b'private'),
            SimpleNamespace(returncode=0,stdout=b'no-framing-private',stderr=b'private'),
            response(body=b'x'*(driver.MAX_VALUE+1)),
            response(body=b'{"token":"generated-private","extra":"private"}'),
            SimpleNamespace(returncode=0,stdout=b'{}\napplication/json\n000',stderr=b'private')]
        for result in malformed:
            runner = SimpleNamespace(podman=Mock(return_value=result))
            registry = RuntimeRegistry()
            transport = driver.curl_login_transport(runner=runner,broker=BROKER,login_url=URL)
            streams = []
            def observe(user,password):
                status,mime,stream = transport(user,password)
                streams.append(stream)
                return status,mime,stream
            with self.assertRaisesRegex(PrivateFailure,'^runtime-private-refused$'):
                login_registered(registry,observe,username=USER,password=PASSWORD)
            self.assertTrue(all(stream.closed for stream in streams))
            with self.assertRaises(PrivateFailure): registry.scan_login_evidence(b'fixed-metadata')
        runner = SimpleNamespace(podman=Mock(side_effect=subprocess.TimeoutExpired('private-command',10)))
        with self.assertRaisesRegex(PrivateFailure,'^runtime-private-refused$'):
            login_registered(RuntimeRegistry(),driver.curl_login_transport(runner=runner,broker=BROKER,login_url=URL),
                             username=USER,password=PASSWORD)

    def test_no_implicit_or_remote_login_destination(self):
        runner = SimpleNamespace(podman=Mock())
        for url in ('http://external.invalid/api/v5/login','http://127.0.0.1:18083/api/v5/login?x=1',
                    'http://admin:password@127.0.0.1:18083/api/v5/login','http://127.0.0.1:0/api/v5/login',''):
            with self.assertRaises(PrivateFailure):
                driver.curl_login_transport(runner=runner,broker=BROKER,login_url=url)
        runner.podman.assert_not_called()


class DriverTests(unittest.TestCase):
    def setUp(self):
        from test_emqx_owner_source_capture import OwnerHarnessTests
        OwnerHarnessTests.fixture(self)
        from test_emqx_owner_vendor_files import VendorFilesTests
        self.vendor = VendorFilesTests()
        self.vendor.setUp()
        self.vendor.broker = BROKER
        self.vendor.inspect[0]['Name'] = '/' + BROKER
        self.vendor.paths = sorted(p for p in vendor_files.PATHS if '/certs/' in p)
        for doc in (self.vendor.image, self.vendor.actual):
            doc['files'] = [f for f in doc['files'] if '/certs/' in f['path']]
        self.inspect_override = None
        self.parser = OwnerHarnessTests.hocon
        self.evidence = self.root/'evidence'
        self.evidence.mkdir(mode=0o700)
        self.staging = self.root/'candidate'
        self.staging.mkdir(mode=0o700)
        self.events = []
        self.live = False
        self.capture = None
        self.login_registry = None
        self.target_edit = None
        self.login_response = response()
        self.runner = SimpleNamespace(podman=Mock(side_effect=self.podman))
        self.work = SimpleNamespace(log=Mock(),runner=lambda app:self.runner)
        self.app = SimpleNamespace(id='emqx')
        self.target = SimpleNamespace(container=BROKER,image='sha256:'+'a'*64,
                                      data_volume='reviewed-data',log_volume='reviewed-log')

    @contextmanager
    def quiesce(self):
        self.assertIsNotNone(self.capture)
        self.assertFalse(self.capture._closed)
        self.live = True
        self.events.append('locked')
        try: yield
        finally:
            self.live = False
            self.events.append('unlocked')

    def podman(self,*args,**kwargs):
        self.assertTrue(self.live)
        self.assertFalse(self.capture._closed)
        if args == ('inspect', BROKER):
            self.events.append('vendor-inspect')
            self.assertEqual(kwargs, {'timeout':5, 'max_output':vendor_files.LIMIT})
            raw = self.vendor.inspect_callback()
            if self.inspect_override: raw = self.inspect_override(raw)
            return SimpleNamespace(returncode=0, stdout=raw)
        if args[:4] == ('exec',BROKER,'emqx','eval') and kwargs['timeout'] == 10:
            self.events.append('vendor-observed')
            self.assertEqual(kwargs, {'timeout':10, 'max_output':vendor_files.MAX_WIRE})
            return SimpleNamespace(returncode=0, stdout=self.vendor.eval_callback(args[4]))
        if args[:4] == ('exec',BROKER,'emqx','eval'):
            from test_emqx_owner_target import reply_document
            self.events.append('target-observed')
            self.assertEqual(kwargs,{'timeout':30,'max_output':driver.MAX_WIRE,'check':False})
            generation = re.search(r'generation => <<"([0-9a-f]{32})">>',args[4])[1]
            from test_emqx_owner_target import cooked_config
            config = cooked_config()
            for kind in ('ssl', 'wss'):
                config['listeners'][kind]['default']['ssl_options'] = {
                    key:'${EMQX_ETC_DIR}/certs/' + name for key,name in FILES.items()}
            document = reply_document(generation, config=config)
            if self.target_edit: self.target_edit(document)
            wire = b'WOOWTARGET:'+base64.b64encode(json.dumps(document).encode())+b':ENDok\n'
            return SimpleNamespace(returncode=0,stdout=wire,stderr=b'private-target-diagnostic')
        self.assertEqual(args,('exec','-i',BROKER,'curl','-q','--config','-'))
        self.events.append('curl-login')
        self.assertIsNotNone(self.login_registry)
        self.assertTrue(self.login_registry._target_complete)
        self.assertEqual(self.login_registry._categories['runtime-login-input'],2)
        self.capture.registry.summary()  # actual full source registry is sealed
        return self.login_response

    @contextmanager
    def producers(self):
        source = driver.capture_owner_source
        @contextmanager
        def held(*args,**kwargs):
            with source(*args,**kwargs) as (captured,binding):
                self.capture = captured
                self.events.append('source-held')
                yield captured,binding
            self.events.append('source-closed')
        register = RuntimeRegistry.register_bundle
        def registered(registry,categories,**kwargs):
            result = register(registry,categories,**kwargs)
            if 'runtime-login-input' in categories:
                self.login_registry = registry
                self.events.append('login-input-registered')
            return result
        scan = CombinedRegistry.scan
        def scanned(registry,raw):
            scan(registry,raw)
            if raw:
                self.assertFalse((self.evidence/'driver-preflight.json').exists())
                self.events.append('combined-scanned')
        with patch.object(source_owner,'native_hocon',self.parser), \
             patch.object(source_owner,'native_cold_history',decoder), \
             patch.object(vendor_files,'run_native',self.vendor.native), \
             patch.object(driver,'capture_owner_source',held), \
             patch.object(RuntimeRegistry,'register_bundle',registered), \
             patch.object(CombinedRegistry,'scan',scanned):
            yield

    def invoke(self,**changes):
        args = dict(source_password=self.password,expected_sha256=self.digest,
            spool_directory=self.spool,source_options={},runner=self.runner,quiesce=self.quiesce,
            login_url=URL,username=USER,password=PASSWORD,evidence_directory=self.evidence,
            evidence_name='driver-preflight.json')
        args.update(changes)
        return driver.build_owner_candidate(self.work,self.app,object(),self.target,self.path,
                                            self.staging,'j20261122T000000Z-12345678',**args)

    def test_real_source_target_curl_join_and_bridge_hold_contexts_until_inner_byte_boundary(self):
        inspected = []
        def inner(work,app,tmp,target,private,**kwargs):
            self.assertTrue(self.live)
            self.assertFalse(self.capture._closed)
            self.assertIn('combined-scanned',self.events)
            self.assertTrue((self.evidence/'driver-preflight.json').is_file())
            with work.open('fedcba98_woow-emqx') as replay:
                self.assertFalse(replay.writable())
                inspected.append(replay.read())
            self.events.append('inner-byte-boundary')
            raise RuntimeError('generated-boundary-stop-before-broker')
        with self.producers(), \
             patch.object(real.hacommon,'image_labels',return_value={'org.opencontainers.image.version':'5.8.9'}), \
             patch.object(real.tempctr,'TempObjects') as objects, \
             patch.object(real.ha_emqx,'_build_candidate',side_effect=inner) as build, \
             patch.object(real.ha_emqx,'_package_candidate') as package:
            objects.return_value.cleanup.return_value = []
            with self.assertRaisesRegex(PrivateFailure,'^private-owner-driver-refused$'): self.invoke()
            build.assert_called_once()
            package.assert_not_called()
        self.assertEqual(inspected,[self.raw])
        self.assertLess(self.events.index('target-observed'),self.events.index('login-input-registered'))
        self.assertLess(self.events.index('login-input-registered'),self.events.index('curl-login'))
        self.assertLess(self.events.index('curl-login'),self.events.index('combined-scanned'))
        self.assertLess(self.events.index('inner-byte-boundary'),self.events.index('unlocked'))
        self.assertTrue(self.capture._closed)
        self.assertEqual(list(self.spool.iterdir()),[])
        self.assertEqual(list(self.staging.iterdir()),[])
        raw = (self.evidence/'driver-preflight.json').read_bytes()
        doc = json.loads(raw)
        self.assertEqual(set(doc),{'phase','result','coverage'})
        self.assertEqual(doc['phase'],'preflight')
        self.assertIsInstance(doc['coverage'],list)
        self.assertEqual((self.evidence/'driver-preflight.json').stat().st_mode&0o777,0o600)
        for value in (USER,PASSWORD,TOKEN,b'fixture-private-emqx_admin_jwt'):
            self.assertNotIn(value,raw)
        self.work.log.assert_not_called()

    def test_successful_authorized_bridge_handoff_returns_only_after_context_cleanup(self):
        # A private handoff sentinel, never a manufactured candidate/restore result.
        sentinel = object()
        def handoff(*args,**kwargs):
            from emqx_captured_candidate import _authorized
            self.assertTrue(self.live)
            _authorized(kwargs['captured'],kwargs['private_binding'],kwargs['session'],
                        kwargs['expected_sha256'])
            with kwargs['private_binding']['open']('fedcba98_woow-emqx') as stream:
                self.assertEqual(stream.read(),self.raw)
            self.events.append('authorized-handoff')
            return sentinel
        with self.producers(), patch.object(driver,'build_captured_candidate',side_effect=handoff):
            self.assertIs(self.invoke(),sentinel)
        self.assertLess(self.events.index('combined-scanned'),self.events.index('authorized-handoff'))
        self.assertLess(self.events.index('authorized-handoff'),self.events.index('unlocked'))
        self.assertEqual(self.events.count('vendor-observed'), 2)
        self.assertLess(self.events.index('locked'), self.events.index('vendor-inspect'))
        self.assertGreater(self.events.index('vendor-observed', self.events.index('authorized-handoff')),
                           self.events.index('authorized-handoff'))
        self.assertTrue(all(not d.exists() for d in self.vendor.directories))
        self.assertFalse(self.live)
        self.assertTrue(self.capture._closed)
        self.assertEqual(list(self.spool.iterdir()),[])

    def test_wrong_source_target_generation_login_and_scan_failure_never_call_bridge(self):
        cases = ('source','target','login','scan')
        for case in cases:
            self.events.clear(); self.capture = None; self.login_registry = None
            self.target_edit = None; self.login_response = response()
            if case == 'target': self.target_edit = lambda doc:doc.update(generation='wrong-generation')
            if case == 'login': self.login_response = response(401,b'generated-private-denial')
            if case == 'scan':
                def collide(doc):
                    from test_emqx_owner_target import typed, cooked_config
                    config = cooked_config(); config['additional_native_root']['opaque'] = 'preflight'
                    doc['config'] = typed(config)
                self.target_edit = collide
            with self.subTest(case=case), self.producers(), \
                 patch.object(driver,'build_captured_candidate') as bridge:
                with self.assertRaisesRegex(PrivateFailure,'^private-owner-driver-refused$'):
                    self.invoke(**({'expected_sha256':'0'*64} if case=='source' else {}))
                bridge.assert_not_called()
            self.assertEqual(list(self.evidence.iterdir()),[])
            self.assertEqual(list(self.spool.iterdir()),[])
            self.assertFalse(self.live)
            if case == 'source': self.runner.podman.assert_not_called()
            else:
                self.assertIn('unlocked',self.events)
                self.assertTrue(self.capture._closed)
            self.runner.podman.reset_mock()

    def test_invalid_private_inspect_and_provenance_never_reach_builder(self):
        cases = ('malformed', 'duplicate', 'cid', 'name', 'image', 'mount', 'changed-cid')
        import copy
        original = copy.deepcopy(self.vendor.inspect)
        for case in cases:
            self.vendor.inspect = copy.deepcopy(original)
            self.events.clear()
            self.inspect_override = None
            if case == 'malformed': self.inspect_override = lambda raw:b'private-not-json'
            if case == 'duplicate':
                self.inspect_override = lambda raw:raw.replace(b'"Id":', b'"Id":"' + b'b'*64 + b'","Id":', 1)
            if case == 'cid': self.vendor.inspect[0]['Id'] = 'invalid'
            if case == 'name': self.vendor.inspect[0]['Name'] = '/different-owner'
            if case == 'image': self.vendor.inspect[0]['Image'] = 'sha256:'+'0'*64
            if case == 'mount': self.vendor.inspect[0]['Mounts'].append({'Type':'bind','Destination':'/opt/emqx/etc/certs'})
            if case == 'changed-cid':
                def changed(raw):
                    if self.events.count('vendor-inspect') > 1:
                        raw = raw.replace(b'a'*64, b'b'*64)
                    return raw
                self.inspect_override = changed
            with self.subTest(case=case), self.producers(), patch.object(driver,'build_captured_candidate') as bridge:
                with self.assertRaisesRegex(PrivateFailure, '^private-owner-driver-refused$'): self.invoke()
                bridge.assert_not_called()
            self.assertNotIn('target-observed',self.events)
            self.assertNotIn('curl-login',self.events)
            self.assertTrue(self.capture._closed)
            self.assertFalse(self.live)
            self.assertEqual(list(self.spool.iterdir()), [])
            self.assertEqual(list(self.evidence.iterdir()), [])

    def test_vendor_change_on_lease_exit_refuses_return_and_cleans_up(self):
        def handoff(*args, **kwargs):
            self.vendor.actual['files'][0]['identity'][2] += 1
            return object()
        with self.producers(), patch.object(driver,'build_captured_candidate',side_effect=handoff) as bridge:
            with self.assertRaisesRegex(PrivateFailure, '^private-owner-driver-refused$'): self.invoke()
            bridge.assert_called_once()  # late recheck refuses result, not an earlier handoff
        self.assertTrue(self.capture._closed)
        self.assertFalse(self.live)
        self.assertEqual(list(self.spool.iterdir()), [])

    def test_enabled_tls_and_unknown_reference_still_prevent_builder(self):
        for case in ('enabled', 'unknown'):
            def edit(doc):
                from test_emqx_owner_target import cooked_config, typed
                config = cooked_config()
                listener = config['listeners']['ssl']['default']
                listener['enable'] = case == 'enabled'
                listener['ssl_options'] = {'certfile': '${EMQX_ETC_DIR}/certs/' +
                    ('cert.pem' if case == 'enabled' else 'unknown.pem')}
                doc['config'] = typed(config)
            self.target_edit = edit
            with self.subTest(case=case), self.producers(), patch.object(driver,'build_captured_candidate') as bridge:
                with self.assertRaisesRegex(PrivateFailure, '^private-owner-driver-refused$'): self.invoke()
                bridge.assert_not_called()
            self.assertTrue(self.capture._closed)
            self.assertFalse(self.live)
            self.assertEqual(list(self.evidence.iterdir()), [])
