"""Actual private disk IO; generated input only, no containers or real secrets."""
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from emqx_private_spool import capture, RESERVE
from emqx_private_boundary import PrivateFailure


class SpoolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)

    def test_complete_finish_then_private_seekable_bytes_and_cleanup(self):
        raw = b'generated-only' * 10000
        class Source(io.BytesIO):
            finished = False
            def finish(self):
                self.finished = True
        source = Source(raw)
        with capture(source, self.root, maximum=len(raw)) as (stream, size, digest):
            self.assertTrue(source.finished)
            self.assertEqual(size, len(raw))
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
            self.assertEqual(stream.read(), raw)
            stream.seek(0)
            self.assertEqual(stream.read(), raw)
            self.assertEqual(next(self.root.iterdir()).stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_late_finish_size_and_consumer_failures_remove_owned_bytes(self):
        class Late(io.BytesIO):
            def finish(self):
                raise RuntimeError('generated-private-marker')
        for source, limit in ((Late(b'valid-prefix'), 64), (io.BytesIO(b'x'*65), 64)):
            entered = False
            with self.assertRaisesRegex(PrivateFailure, '^private-source-refused$'):
                with capture(source, self.root, maximum=limit):
                    entered = True
            self.assertFalse(entered)
            self.assertEqual(list(self.root.iterdir()), [])
        with self.assertRaisesRegex(PrivateFailure, '^private-source-refused$'):
            with capture(io.BytesIO(b'valid'), self.root, maximum=64):
                raise RuntimeError('generated-private-marker')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_midstream_cancellation_removes_partial_before_return(self):
        class CancelledInput:
            reads = 0
            def read(self, maximum):
                self.reads += 1
                if self.reads == 2:
                    raise KeyboardInterrupt('generated-private-marker')
                return b'x' * min(maximum, 32)
        with self.assertRaisesRegex(PrivateFailure, '^private-source-cancelled$'):
            with capture(CancelledInput(), self.root, maximum=64):
                self.fail('yielded before authenticated EOF')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_symlink_directory_refuses_and_preserves_unrelated_file(self):
        other = self.root / 'original'
        other.write_bytes(b'preserve')
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(PrivateFailure):
            with capture(io.BytesIO(b'x'), link, maximum=64):
                self.fail('yielded')
        self.assertEqual(other.read_bytes(), b'preserve')
        self.assertEqual(set(p.name for p in self.root.iterdir()), {'original', 'link'})

    def test_reserve_and_permissions_refuse_before_input(self):
        with patch('emqx_private_spool.shutil.disk_usage', return_value=SimpleNamespace(free=RESERVE)), \
             patch('emqx_private_spool.tempfile.mkstemp') as create:
            with self.assertRaises(PrivateFailure):
                with capture(io.BytesIO(b'x'), self.root, maximum=64):
                    self.fail('yielded')
            create.assert_not_called()
        self.root.chmod(0o755)
        with self.assertRaises(PrivateFailure):
            with capture(io.BytesIO(b'x'), self.root, maximum=64):
                self.fail('yielded')
        self.assertEqual(list(self.root.iterdir()), [])

class FixtureProfileTests(SpoolTests):
    def test_generated_exact_capacity_finish_permissions_cleanup(self):
        import emqx_private_spool as spool
        class Generated:
            remaining = spool.X86_SIZE
            finished = False
            def read(self, maximum):
                count = min(maximum, self.remaining)
                self.remaining -= count
                return b'x' * count
            def finish(self):
                self.finished = True
        source = Generated()
        with capture(source, self.root, fixture_profile=spool.X86_PROFILE,
                     verified_sha256=spool.X86_SHA256) as (stream, size, digest):
            self.assertTrue(source.finished)
            self.assertEqual(size, 290785280)
            self.assertEqual(stream.seek(0, 2), size)
            self.assertEqual(next(self.root.iterdir()).stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(spool.MAX_SOURCE, 256 * 1024 ** 2)

    def test_profile_refuses_unknown_digest_profile_short_and_deadline(self):
        import emqx_private_spool as spool
        for profile, digest in ((spool.X86_PROFILE, '0' * 64),
                                ('unknown', spool.X86_SHA256)):
            with patch.object(spool.tempfile, 'mkstemp') as create:
                with self.assertRaises(PrivateFailure):
                    with capture(io.BytesIO(b'x'), self.root,
                                 fixture_profile=profile, verified_sha256=digest):
                        self.fail('yielded')
                create.assert_not_called()
        class Finished(io.BytesIO):
            def finish(self):
                pass
        with self.assertRaises(PrivateFailure):
            with capture(Finished(b'short'), self.root,
                         fixture_profile=spool.X86_PROFILE, verified_sha256=spool.X86_SHA256):
                self.fail('short yielded')
        with patch.object(spool.time, 'monotonic', side_effect=[0, 0, 121]):
            with self.assertRaises(PrivateFailure):
                with capture(Finished(b'x'), self.root,
                             fixture_profile=spool.X86_PROFILE, verified_sha256=spool.X86_SHA256):
                    self.fail('expired yielded')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_profile_late_finish_and_oversize_refuse(self):
        import emqx_private_spool as spool
        class Late(io.BytesIO):
            def finish(self):
                raise ValueError('generated finish failure')
        # Scaled size exercises the same exact-size/overflow contract cheaply.
        with patch.object(spool, 'X86_SIZE', 64):
            for source in (Late(b'x' * 64), io.BytesIO(b'x' * 65)):
                with self.assertRaises(PrivateFailure):
                    with capture(source, self.root, fixture_profile=spool.X86_PROFILE,
                                 verified_sha256=spool.X86_SHA256):
                        self.fail('yielded')
                self.assertEqual(list(self.root.iterdir()), [])
            clock = [0]
            class SlowFinish(io.BytesIO):
                def finish(self):
                    clock[0] = 121
            with patch.object(spool.time, 'monotonic', side_effect=lambda: clock[0]):
                with self.assertRaises(PrivateFailure):
                    with capture(SlowFinish(b'x' * 64), self.root,
                                 fixture_profile=spool.X86_PROFILE, verified_sha256=spool.X86_SHA256):
                        self.fail('late finish yielded')
        self.assertEqual(list(self.root.iterdir()), [])
