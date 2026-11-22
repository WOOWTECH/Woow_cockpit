"""Generated front gates and archive verification; inner build only inspects bytes.

No native processes, brokers, candidate artifacts, restore or commercial claims.
"""
import io
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import emqx_captured_candidate as bridge
import emqx_owner_source_capture as source_owner
import emqx_real_candidate as real
import test_emqx_owner_preflight as fixtures
from emqx_private_boundary import PrivateFailure
from emqx_runtime_workflow import PrivateSession
from emqx_source_consumer import Capture
from test_emqx_source_cold_capture import decoder


class BoundaryReached(Exception):
    pass


class BridgeTests(unittest.TestCase):
    tracked_readers = fixtures.JoinTests.tracked_readers
    source = fixtures.JoinTests.source
    join = fixtures.JoinTests.join

    def setUp(self):
        fixtures.JoinTests.setUp(self)
        self.work = SimpleNamespace(log=Mock(), runner=lambda app: object(),
            open='original-open', addon_member='original-member', addon_info='original-info')
        self.app = SimpleNamespace(id='emqx')
        self.target = SimpleNamespace(image='sha256:'+'a'*64,
            data_volume='reviewed-data', log_volume='reviewed-log')
        self.staging = self.root/'candidate-staging'
        self.staging.mkdir(mode=0o700)

    def build(self, captured, binding, session, **changes):
        kwargs = dict(captured=captured, private_binding=binding, session=session,
                      expected_sha256=self.digest)
        kwargs.update(changes)
        return bridge.build_captured_candidate(self.work, self.app, object(), self.target,
            self.path, self.staging, 'j20261122T000000Z-12345678', **kwargs)

    def test_real_frontgates_and_archive_reverification_reach_readonly_bytes_without_recapture(self):
        inspected = []
        def inspect(work, app, tmp, target, private, *, version):
            self.assertEqual(version,'5.8.9')
            self.assertEqual(work.addon_member('woow-emqx'),'fedcba98_woow-emqx')
            self.assertEqual(work.addon_info('woow-emqx').version,'5.9.0')
            work.log('generated-private-log-must-be-discarded')
            with work.open('fedcba98_woow-emqx') as replay:
                self.assertFalse(replay.writable())
                with self.assertRaises(io.UnsupportedOperation): replay.write(b'changed')
                inspected.append(replay.read())
            raise BoundaryReached()  # stop before any broker/product build work
        with self.source() as (captured,binding):
            self.assertEqual(captured._owner_source_proof[1],self.digest)
            with self.assertRaises(PrivateFailure):
                with binding['open']('fedcba98_woow-emqx'):
                    self.fail('unsealed replay')
            session = self.join(captured)
            self.assertTrue((self.evidence/'joined-preflight.json').is_file())
            with patch.object(real.hacommon,'image_labels',return_value={'org.opencontainers.image.version':'5.8.9'}), \
                 patch.object(real.tempctr,'TempObjects') as objects, \
                 patch.object(real.ha_emqx,'_build_candidate',side_effect=inspect) as inner, \
                 patch.object(real.ha_emqx,'_package_candidate') as package, \
                 patch.object(bridge,'build_verified_candidate',wraps=real.build_verified_candidate) as verified, \
                 patch.object(Capture,'__call__',side_effect=AssertionError('second Capture is forbidden')) as recapture:
                objects.return_value.cleanup.return_value = []
                with self.assertRaisesRegex(PrivateFailure,'^candidate-refused$'):
                    self.build(captured,binding,session)
                inner.assert_called_once()
                package.assert_not_called()
                recapture.assert_not_called()
                self.assertIs(verified.call_args.kwargs['keys'],captured.keys)
                self.assertIsNot(verified.call_args.kwargs['private_capture'],captured)
                objects.return_value.cleanup.assert_called_once()
            self.assertEqual(inspected,[self.raw])
            self.assertEqual(list(self.staging.iterdir()),[])
            self.work.log.assert_not_called()
            self.assertEqual(self.work.open,'original-open')
            self.assertEqual(self.work.addon_member,'original-member')
            self.assertEqual(self.work.addon_info,'original-info')
        self.assertEqual(list(self.spool.iterdir()),[])

    def test_bad_sha_copied_binding_handmade_session_and_swapped_registry_refuse_before_wrapper(self):
        with self.source() as (captured,binding):
            session = self.join(captured)
            clone = PrivateSession(session.credential,session.registry,session.coverage,session.evidence)
            with patch.object(bridge,'build_verified_candidate') as build:
                for kwargs in ({'expected_sha256':'0'*64}, {'private_binding':dict(binding)},
                               {'session':clone}, {'session':True}):
                    args = dict(captured=captured,private_binding=binding,session=session,
                                expected_sha256=self.digest)
                    args.update(kwargs)
                    with self.subTest(kwargs=tuple(kwargs)), self.assertRaises(PrivateFailure):
                        bridge.build_captured_candidate(self.work,self.app,object(),self.target,
                            self.path,self.staging,'j20261122T000000Z-12345678',**args)
                registry = session.registry
                session.registry = SimpleNamespace(_source=captured.registry)
                with self.assertRaises(PrivateFailure): self.build(captured,binding,session)
                session.registry = registry
                original = binding['open']
                binding['open'] = lambda _: io.BytesIO(b'uncaptured bytes')
                with self.assertRaises(PrivateFailure): self.build(captured,binding,session)
                binding['open'] = original
                build.assert_not_called()

    def test_mixed_successful_capture_sessions_cannot_authorize_each_other(self):
        with self.source() as (first,one):
            session1 = self.join(first)
            with self.source() as (second,two):
                session2 = self.join(second,evidence_name='second-preflight.json')
                with patch.object(bridge,'build_verified_candidate') as build:
                    for capture,binding,session in ((first,one,session2), (second,two,session1),
                                                    (first,two,session1)):
                        with self.assertRaises(PrivateFailure): self.build(capture,binding,session)
                    build.assert_not_called()

    def test_closed_unsealed_and_failed_login_contexts_cannot_reach_wrapper(self):
        with self.source() as (captured,binding):
            with patch.object(bridge,'build_verified_candidate') as build:
                with self.assertRaises(PrivateFailure): self.build(captured,binding,object())
                build.assert_not_called()
            self.transport.side_effect = None
            self.transport.return_value = (401,'application/json',io.BytesIO(b'generated-failure'))
            with self.assertRaises(PrivateFailure): self.join(captured)
            fake = PrivateSession(object(),SimpleNamespace(_source=captured.registry),{}, {'passed':True})
            with patch.object(bridge,'build_verified_candidate') as build:
                with self.assertRaises(PrivateFailure): self.build(captured,binding,fake)
                build.assert_not_called()
            self.assertEqual(list(self.evidence.iterdir()),[])
        with patch.object(bridge,'build_verified_candidate') as build:
            with self.assertRaises(PrivateFailure): self.build(captured,binding,fake)
            build.assert_not_called()
        self.assertEqual(list(self.spool.iterdir()),[])

    def test_closed_successful_session_and_changed_archive_refuse_before_inner_builder(self):
        with self.source() as (captured,binding):
            session = self.join(captured)
            with self.path.open('ab') as output: output.write(b'changed-encrypted-archive')
            with patch.object(real.hacommon,'image_labels',return_value={'org.opencontainers.image.version':'5.8.9'}), \
                 patch.object(real.tempctr,'TempObjects') as objects, \
                 patch.object(real.ha_emqx,'_build_candidate') as inner:
                with self.assertRaises(PrivateFailure): self.build(captured,binding,session)
                inner.assert_not_called()
                objects.assert_not_called()
        with patch.object(bridge,'build_verified_candidate') as build:
            with self.assertRaises(PrivateFailure): self.build(captured,binding,session)
            build.assert_not_called()

    def test_final_owner_stamp_failure_never_mints_verified_capability(self):
        captures = []
        original = Capture.__call__
        def recorded(captured,source,**kwargs):
            result = original(captured,source,**kwargs)
            captures.append(captured)
            return result
        def mutate(raw,kind):
            with self.path.open('ab') as output: output.write(b'late-binding-change')
            return decoder(raw,kind)
        with patch.object(source_owner,'native_hocon',self.parser), \
             patch.object(source_owner,'native_cold_history',mutate), \
             patch.object(Capture,'__call__',recorded), \
             patch.object(bridge,'_verify_owner_binding',wraps=bridge._verify_owner_binding) as verify:
            with self.assertRaises(PrivateFailure):
                with source_owner.capture_owner_source(self.path,password=self.password,
                        expected_sha256=self.digest,spool_directory=self.spool):
                    self.fail('late stamp yielded')
            verify.assert_not_called()
        self.assertEqual(len(captures),1)
        self.assertIsNone(captures[0]._owner_source_proof)
        self.assertTrue(captures[0]._closed)
        self.assertEqual(list(self.spool.iterdir()),[])
