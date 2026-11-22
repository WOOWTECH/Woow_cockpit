"""Generated framed encrypted source only; no lab/native process/real data."""
import contextlib
import io
import struct
import unittest
from unittest.mock import patch

import test_emqx_owner_source_capture as fixtures
from test_emqx_source_cold_capture import decoder
import emqx_owner_source_capture as capture_module


class SourceFrameTests(unittest.TestCase):
    def setUp(self):
        fixtures.OwnerHarnessTests.fixture(self)

    def frame(self, *, tail=b''):
        key = self.password.encode('ascii')
        archive = self.path.read_bytes()
        return io.BytesIO(struct.pack('!I', len(key)) + key +
                          struct.pack('!Q', len(archive)) + archive + tail)

    def test_generated_frame_uses_actual_capture_and_returns_only_unsealed_receipt(self):
        import emqx_arm_source_owner as owner
        calls = []
        def cold(raw, kind):
            calls.append(kind)
            return decoder(raw, kind)
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(owner, 'ARCHIVE_SHA256', self.digest), \
             patch.object(owner, 'EXPECTED_COLD_FILES', 2), \
             patch.object(owner, 'EXPECTED_COLD_BYTES', 29), \
             patch.object(capture_module, 'native_hocon', fixtures.OwnerHarnessTests.hocon), \
             patch.object(capture_module, 'native_cold_history', cold), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            receipt = owner.consume_source_frame(self.frame(), staging_parent=self.spool)
        self.assertEqual(calls, ['schema-dat', 'dcd'])
        self.assertEqual(receipt, {'scope': 'source-only-registration',
            'registry': 'unsealed', 'source_completeness': 'not-assessed',
            'target_completeness': 'not-assessed', 'full_scan': 'not-performed',
            'restore': 'not-performed'})
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(errors.getvalue(), '')
        self.assertEqual(list(self.spool.iterdir()), [])

    def test_bad_frames_refuse_before_capture_and_remove_partial_staging(self):
        import emqx_arm_source_owner as owner
        from emqx_private_boundary import PrivateFailure
        good = self.frame().getvalue()
        key = self.password.encode('ascii')
        cases = [b'', struct.pack('!I', 0), struct.pack('!I', 1025),
                 struct.pack('!I', 1) + b'\xff',
                 struct.pack('!I', 1) + b'\n',
                 struct.pack('!I', len(key)) + key + struct.pack('!Q', owner.MAX_ARCHIVE + 1),
                 good[:-1], good + b'late-frame-data']
        for frame in cases:
            with self.subTest(frame_bytes=len(frame)), \
                 patch.object(owner, 'ARCHIVE_SHA256', self.digest), \
                 patch.object(owner, 'capture_owner_source') as capture:
                with self.assertRaisesRegex(PrivateFailure, '^private-source-frame-refused$'):
                    owner.consume_source_frame(io.BytesIO(frame), staging_parent=self.spool)
                capture.assert_not_called()
                self.assertEqual(list(self.spool.iterdir()), [])

    def test_wrong_fixed_archive_hash_refuses_before_capture(self):
        import emqx_arm_source_owner as owner
        from emqx_private_boundary import PrivateFailure
        with patch.object(owner, 'capture_owner_source') as capture:
            with self.assertRaisesRegex(PrivateFailure, '^private-source-frame-refused$'):
                owner.consume_source_frame(self.frame(), staging_parent=self.spool)
            capture.assert_not_called()
        self.assertEqual(list(self.spool.iterdir()), [])

    def test_wrong_key_authentication_and_late_decoder_failure_clean_all_private_files(self):
        import emqx_arm_source_owner as owner
        from emqx_private_boundary import PrivateFailure
        from emqx_semantic_readers import SemanticRefused
        for wrong_key in (True, False):
            def late(raw, kind):
                if kind == 'dcd':
                    raise SemanticRefused()
                return decoder(raw, kind)
            with self.subTest(wrong_key=wrong_key), \
                 patch.object(owner, 'ARCHIVE_SHA256', self.digest), \
                 patch.object(capture_module, 'native_hocon', fixtures.OwnerHarnessTests.hocon), \
                 patch.object(capture_module, 'native_cold_history', late):
                if wrong_key:
                    key = b'generated-wrong-key'
                    archive = self.path.read_bytes()
                    frame = io.BytesIO(struct.pack('!I', len(key)) + key +
                                       struct.pack('!Q', len(archive)) + archive)
                else:
                    frame = self.frame()
                with self.assertRaisesRegex(PrivateFailure, '^private-source-frame-refused$'):
                    owner.consume_source_frame(frame, staging_parent=self.spool)
            self.assertEqual(list(self.spool.iterdir()), [])

    def test_actual_complete_inventory_must_match_fixed_source_receipt(self):
        import emqx_arm_source_owner as owner
        from emqx_private_boundary import PrivateFailure
        # Generated inventory is 2 files/29 bytes; production policy stays28/57502.
        with patch.object(owner, 'ARCHIVE_SHA256', self.digest), \
             patch.object(capture_module, 'native_hocon', fixtures.OwnerHarnessTests.hocon), \
             patch.object(capture_module, 'native_cold_history', decoder):
            with self.assertRaisesRegex(PrivateFailure, '^private-source-frame-refused$'):
                owner.consume_source_frame(self.frame(), staging_parent=self.spool)
        self.assertEqual(list(self.spool.iterdir()), [])

    def test_frame_cancellation_cleans_partial_archive_and_uses_fixed_failure(self):
        import emqx_arm_source_owner as owner
        from emqx_private_boundary import PrivateFailure
        header = self.frame().getvalue()[:4 + len(self.password.encode()) + 8]
        class Cancelled(io.BytesIO):
            def read(self, size=-1):
                if self.tell() >= len(header):
                    raise KeyboardInterrupt('generated-private-cancellation')
                return super().read(size)
        with self.assertRaisesRegex(PrivateFailure, '^private-source-frame-cancelled$'):
            owner.consume_source_frame(Cancelled(header), staging_parent=self.spool)
        self.assertEqual(list(self.spool.iterdir()), [])

    def test_cli_source_status_is_silent_and_does_not_expose_receipt_or_replay(self):
        from types import SimpleNamespace
        import emqx_arm_source_owner as owner
        for valid_frame in (True, False):
            output, errors = io.StringIO(), io.StringIO()
            frame = self.frame() if valid_frame else io.BytesIO(b'bad-frame')
            with self.subTest(valid_frame=valid_frame), \
                 patch.object(owner, '_owner_realm', return_value=True), \
                 patch.object(owner.Path, 'home', return_value=self.spool), \
                 patch.object(owner.sys, 'stdin', SimpleNamespace(buffer=frame)), \
                 patch.object(owner.signal, 'signal'), patch.object(owner.signal, 'setitimer'), \
                 patch.object(owner, 'ARCHIVE_SHA256', self.digest), \
                 patch.object(owner, 'EXPECTED_COLD_FILES', 2), \
                 patch.object(owner, 'EXPECTED_COLD_BYTES', 29), \
                 patch.object(capture_module, 'native_hocon', fixtures.OwnerHarnessTests.hocon), \
                 patch.object(capture_module, 'native_cold_history', decoder), \
                 contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                status = owner.main(['--source'])
            self.assertEqual(status, 0 if valid_frame else 1)
            self.assertEqual(output.getvalue(), '')
            self.assertEqual(errors.getvalue(), '')
            self.assertEqual(list(self.spool.iterdir()), [])

    def test_cli_wrong_mode_or_realm_never_reads_input(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        import emqx_arm_source_owner as owner
        stream = Mock()
        with patch.object(owner.sys, 'stdin', SimpleNamespace(buffer=stream)), \
             patch.object(owner.socket, 'gethostname', return_value='generated-host-only'):
            self.assertEqual(owner.main([]), 2)
            self.assertEqual(owner.main(['--source', '--sha', 'untrusted']), 2)
            self.assertEqual(owner.main(['--source']), 1)
        stream.read.assert_not_called()
