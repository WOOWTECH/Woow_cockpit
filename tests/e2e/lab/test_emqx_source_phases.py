"""Generated encrypted inputs / fake native adapters; no lab or real values."""
import contextlib
import hashlib
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from emqx_private_boundary import PrivateFailure, SourcePhaseFailure
import test_emqx_owner_source_capture as fixture
from test_emqx_source_cold_capture import decoder
import emqx_owner_source_capture as owner
import emqx_arm_source_owner as framed


class PhaseTests(unittest.TestCase):
    def setUp(self):
        fixture.OwnerHarnessTests.fixture(self)

    def attempt(self, *, digest=None, parser=None, cold=decoder, **kwargs):
        with patch.object(owner,'native_hocon',parser or fixture.OwnerHarnessTests.hocon), \
             patch.object(owner,'native_cold_history',cold):
            with owner.capture_owner_source(self.path,password=self.password,
                    expected_sha256=self.digest if digest is None else digest,
                    spool_directory=self.spool,**kwargs) as pair:
                return pair

    def assert_failure(self, phase, **kwargs):
        with self.assertRaises(SourcePhaseFailure) as caught:
            self.attempt(**kwargs)
        self.assertEqual(caught.exception.phase,phase)
        self.assertEqual(str(caught.exception),'private-owner-source-refused')
        self.assertEqual(list(self.spool.iterdir()),[])

    def test_binding_profile_native_contract_and_cold_failures_distinct_after_cleanup(self):
        from emqx_semantic_readers import SemanticRefused
        def fail(*args):raise SemanticRefused('generated-private-error-do-not-publish')
        self.assert_failure('BIND',digest='0'*64)
        self.assert_failure('PROFILE',file_dependency_profile='unknown')
        self.assert_failure('HOCON_NATIVE',parser=fail)
        self.assert_failure('HOCON_CONTRACT',parser=lambda _:b'{}')
        self.assert_failure('COLD_NATIVE',cold=fail)
        def late(raw,kind):
            result=json.loads(decoder(raw,kind));result['complete']=False
            return json.dumps(result).encode()
        self.assert_failure('COLD_TYPED',cold=late)

    def test_typed_syntax_and_vendor_observer_have_fixed_phases(self):
        import emqx_owner_file_hocon as vendor
        from test_emqx_owner_file_hocon import document
        def contract(raw):
            doc=document();doc.update(input_sha256=hashlib.sha256(raw).hexdigest(),input_bytes=len(raw))
            if syntax_bad:doc['document']['syntax_strings'].append('${generated_unknown}')
            return json.dumps(doc).encode()
        for syntax_bad,phase in ((True,'HOCON_SYNTAX'),(False,'VENDOR_OBSERVER')):
            with patch.object(vendor,'observe_vendor_acl',side_effect=RuntimeError('generated-private-detail')) as observe:
                self.assert_failure(phase,parser=contract,file_dependency_profile=vendor.PROFILE,
                                    product_image=vendor.IMAGE)
                if syntax_bad:observe.assert_not_called()
                else:observe.assert_called_once()

    def test_capability_and_late_binding_failures_not_mislabeled_as_capture(self):
        with patch('emqx_captured_candidate._verify_owner_binding',side_effect=RuntimeError('generated-private')):
            self.assert_failure('CAPABILITY')
        def changed(raw,kind):
            with self.path.open('ab') as output:output.write(b'\0')
            return decoder(raw,kind)
        self.assert_failure('BIND_FINISH',cold=changed)

    def test_registration_and_cleanup_failure_phases_after_private_files_removed(self):
        from emqx_private_boundary import Registry
        original=Registry.register
        def failed_registration(registry,source,values,**kwargs):
            if source=='source-options':raise RuntimeError('generated-private-detail')
            return original(registry,source,values,**kwargs)
        with patch.object(Registry,'register',failed_registration):
            self.assert_failure('REGISTER')
        import emqx_private_spool as spool
        real_capture=spool.capture
        @contextlib.contextmanager
        def failed_cleanup(*args,**kwargs):
            with real_capture(*args,**kwargs) as captured:
                yield captured
            raise RuntimeError('generated-private-cleanup-error')
        with patch.object(spool,'capture',failed_cleanup):
            self.assert_failure('CLEANUP')

    def test_cli_opt_in_fixed_only_default_silent_and_unknown_phase_sanitized(self):
        cases=((None,0,'SOURCE COMPLETE PASSED\n'),
               (SourcePhaseFailure('private-source-frame-refused','HOCON_NATIVE'),1,'SOURCE HOCON_NATIVE REFUSED\n'),
               (RuntimeError('generated-private-message'),1,'SOURCE CAPTURE REFUSED\n'),
               (SourcePhaseFailure('arbitrary-private-message','generated-private-phase'),1,'SOURCE CAPTURE REFUSED\n'))
        for diagnostic in (False,True):
            for failure,status,wanted in cases:
                out,err=io.StringIO(),io.StringIO()
                with patch.object(framed,'_owner_realm',return_value=True), \
                     patch.object(framed.sys,'stdin',SimpleNamespace(buffer=io.BytesIO())), \
                     patch.object(framed.signal,'signal'),patch.object(framed.signal,'setitimer'), \
                     patch.object(framed,'consume_source_frame',side_effect=failure) as consume, \
                     contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                    argv=['--source-vendor-acl-http-body']+(['--diagnose'] if diagnostic else [])
                    result=framed.main(argv)
                self.assertEqual(result,status)
                self.assertEqual(out.getvalue(),wanted if diagnostic else '')
                self.assertEqual(err.getvalue(),'')
                consume.assert_called_once()

    def test_frame_phase_and_owner_phase_preserved_with_original_fixed_code(self):
        with self.assertRaises(SourcePhaseFailure) as caught:
            framed.consume_source_frame(io.BytesIO(),staging_parent=self.spool)
        self.assertEqual(caught.exception.phase,'FRAME_KEY')
        self.assertEqual(str(caught.exception),'private-source-frame-refused')
        from dataclasses import replace
        import emqx_source_profiles as profiles
        import struct
        key=self.password.encode();cipher=self.path.read_bytes()
        frame=struct.pack('!I',len(key))+key+struct.pack('!Q',len(cipher))+cipher
        profile=replace(profiles.ARM_SOURCE,sha256=self.digest,cold_receipt=(2,29))
        with patch.object(profiles,'ARM_SOURCE',profile), \
             patch.object(framed,'capture_owner_source',side_effect=SourcePhaseFailure('private-owner-source-refused','COLD_FINISH')):
            with self.assertRaises(SourcePhaseFailure) as caught:
                framed.consume_source_frame(io.BytesIO(frame),staging_parent=self.spool)
        self.assertEqual(caught.exception.phase,'COLD_FINISH')
        self.assertEqual(str(caught.exception),'private-source-frame-refused')
        self.assertEqual(list(self.spool.iterdir()),[])
