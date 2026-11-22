"""Generated framed encrypted source only; no lab/native process/real data."""
from dataclasses import replace
import emqx_source_profiles as profiles
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

    def profile(self, *, measured=False):
        return replace(profiles.ARM_SOURCE, sha256=self.digest,
                       cold_receipt=(2, 29) if measured else (28, 57502))

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
        with patch.object(profiles, 'ARM_SOURCE', self.profile(measured=True)), \
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
                 patch.object(profiles, 'ARM_SOURCE', self.profile()), \
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
                 patch.object(profiles, 'ARM_SOURCE', self.profile()), \
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
        with patch.object(profiles, 'ARM_SOURCE', self.profile()), \
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
                 patch.object(profiles, 'ARM_SOURCE', self.profile(measured=True)), \
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

    def amd64_fixture(self):
        import gzip
        import hashlib
        import json
        import tarfile
        from tests.backup import hafixtures as hx
        entries = []
        with tarfile.open(fileobj=io.BytesIO(self.raw), mode='r:') as archive:
            for member in archive:
                data = archive.extractfile(member).read()
                if member.name == 'addon.json':
                    addon = json.loads(data)
                    addon['user']['image'] = 'test/amd64-addon-woow-emqx'
                    data = json.dumps(addon).encode()
                entries.append({'name': member.name, 'data': data})
        self.raw = hx.tar_bytes(entries)
        slug = 'fedcba98_woow-emqx'
        outer = hx.ha_doc((slug,), protected=True)
        outer['addons'][0]['version'] = '5.9.0'
        self.path.write_bytes(hx.outer_bytes([
            (slug + '.tar.gz', hx.v3_encrypt(gzip.compress(self.raw)))], outer))
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_x86_actual_capture_profile_and_amd64_without_guessing_cold_counts(self):
        import emqx_arm_source_owner as owner
        import emqx_private_spool as spool
        self.amd64_fixture()
        calls = []
        def cold(raw, kind):
            calls.append(kind)
            return decoder(raw, kind)
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(profiles, 'X86_SOURCE', replace(profiles.X86_SOURCE, sha256=self.digest)), \
             patch.object(spool, 'X86_SHA256', self.digest), \
             patch.object(spool, 'X86_SIZE', len(self.raw)), \
             patch.object(capture_module, 'native_hocon', fixtures.OwnerHarnessTests.hocon), \
             patch.object(capture_module, 'native_cold_history', cold), \
             patch.object(spool, 'fixture_limits', wraps=spool.fixture_limits) as limits, \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            receipt = owner.consume_source_frame(self.frame(), staging_parent=self.spool, mode='--x86-source')
        # This generated inventory is2/29, not ARM28/57502, and comes from actual Capture.
        self.assertEqual(calls, ['schema-dat', 'dcd'])
        self.assertEqual(limits.call_count, 2)
        limits.assert_called_with('owner-x86-20261121', self.digest)
        self.assertEqual(receipt['registry'], 'unsealed')
        self.assertEqual(receipt['full_scan'], 'not-performed')
        self.assertEqual(receipt['restore'], 'not-performed')
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(errors.getvalue(), '')
        self.assertEqual(list(self.spool.iterdir()), [])
        self.assertEqual(spool.MAX_SOURCE, 256 * 1024**2)
        self.assertEqual(spool.X86_SIZE, 290785280)

    def test_x86_wrong_digest_and_mode_refuse_before_capture(self):
        import emqx_arm_source_owner as owner
        from emqx_private_boundary import PrivateFailure
        for mode in ('--x86-source', '--unknown', '--x86-source=/tmp/override'):
            with self.subTest(mode=mode), patch.object(owner, 'capture_owner_source') as capture:
                with self.assertRaisesRegex(PrivateFailure, '^private-source-frame-refused$'):
                    owner.consume_source_frame(self.frame(), staging_parent=self.spool, mode=mode)
                capture.assert_not_called()
            self.assertEqual(list(self.spool.iterdir()), [])

    def test_x86_wrong_spool_profile_or_non_amd64_source_refuses_and_cleans(self):
        import emqx_arm_source_owner as owner
        import emqx_private_spool as spool
        from emqx_private_boundary import PrivateFailure
        # Keep the generated archive aarch64 to prove mode alone cannot attest amd64.
        for fixture_profile in ('owner-x86-20261121', 'unknown-owner-profile'):
            chosen = replace(profiles.X86_SOURCE, sha256=self.digest, fixture_profile=fixture_profile)
            with self.subTest(profile=fixture_profile), \
                 patch.object(profiles, 'X86_SOURCE', chosen), \
                 patch.object(spool, 'X86_SHA256', self.digest), \
                 patch.object(spool, 'X86_SIZE', len(self.raw)), \
                 patch.object(capture_module, 'native_hocon', fixtures.OwnerHarnessTests.hocon), \
                 patch.object(capture_module, 'native_cold_history', decoder):
                with self.assertRaisesRegex(PrivateFailure, '^private-source-frame-refused$'):
                    owner.consume_source_frame(self.frame(), staging_parent=self.spool, mode='--x86-source')
            self.assertEqual(list(self.spool.iterdir()), [])

    def test_x86_receipt_requires_exact_historical_nonempty_bounded_typed_shape(self):
        from types import SimpleNamespace
        from emqx_private_boundary import PrivateFailure, Registry
        import emqx_arm_source_owner as owner
        valid = {'scope': 'historical-values-only', 'files': 2, 'bytes': 29, 'final_state': False}
        malformed = [None, {}, dict(valid, unknown='private'),
                     dict(valid, scope='final-state'), dict(valid, final_state=True),
                     dict(valid, final_state=0), dict(valid, files=True),
                     dict(valid, files=0), dict(valid, files=65),
                     dict(valid, bytes=True), dict(valid, bytes=0),
                     dict(valid, bytes=1), dict(valid, bytes=32*1024**2+1),
                     dict(valid, files=1, bytes=8388609)]
        for bad in malformed:
            @contextlib.contextmanager
            def malformed_capture(*args, **kwargs):
                yield SimpleNamespace(cold_receipt=bad, registry=Registry()), {
                    'addon_info': lambda slug: SimpleNamespace(arch='amd64')}
            with self.subTest(receipt=bad), \
                 patch.object(profiles, 'X86_SOURCE', replace(profiles.X86_SOURCE, sha256=self.digest)), \
                 patch.object(owner, 'capture_owner_source', malformed_capture):
                with self.assertRaisesRegex(PrivateFailure, '^private-source-frame-refused$'):
                    owner.consume_source_frame(self.frame(), staging_parent=self.spool, mode='--x86-source')
            self.assertEqual(list(self.spool.iterdir()), [])
