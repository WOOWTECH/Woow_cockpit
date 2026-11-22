"""Generated private pipe/receipt boundaries only. No owner/lab/native process."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import emqx_framed_preflight as framed
from emqx_private_evidence import SOURCE_NAMES


def artifact():
    from emqx_private_evidence import names_receipt
    return names_receipt('preflight','passed',SOURCE_NAMES)


class FrameTests(unittest.TestCase):
    def test_exact_scanned_artifact_retained_privately_no_reencoding_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = artifact()
            out,err = io.StringIO(),io.StringIO()
            with patch.object(framed,'PRIVATE_PARENT',root), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                path = framed.retain_evidence(framed.evidence_frame(raw))
            self.assertEqual(path.read_bytes(),raw)
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertEqual(path.parent.stat().st_mode&0o777,0o700)
            self.assertEqual((out.getvalue(),err.getvalue()),('',''))
            self.assertEqual(list(root.glob('emqx-preflight-pending-*')),[])

    def test_wrong_digest_trailing_short_unscanned_payload_and_symlink_parent_refuse(self):
        good = framed.evidence_frame(artifact())
        bad = (good[:-1],good+b'x',good[:-1]+bytes([good[-1]^1]),
               framed.evidence_frame(b'private arbitrary response'),
               framed.evidence_frame(artifact()+b'\n'),
               framed.evidence_frame(b' '+artifact()),b'')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with patch.object(framed,'PRIVATE_PARENT',root):
                for raw in bad:
                    with self.assertRaises(ValueError): framed.retain_evidence(raw)
                    self.assertEqual(list(root.iterdir()),[])
            link=root/'alias';link.symlink_to(root,target_is_directory=True)
            with patch.object(framed,'PRIVATE_PARENT',link):
                with self.assertRaises(ValueError): framed.retain_evidence(good)

    def child(self, code):
        child = subprocess.Popen([sys.executable,'-c',code],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        def clean():
            if child.poll() is None: child.kill()
            child.wait(); child.stdout.close()
        self.addCleanup(clean)
        return child

    def test_live_pipe_bound_eof_timeout_and_child_returncode(self):
        child=self.child('import sys;sys.stdout.buffer.write(b"generated-frame")')
        self.assertEqual(framed.read_child_frame(child,timeout=3),b'generated-frame')
        for code in ('import sys;sys.stdout.buffer.write(b"x"*70000)',
                     'import sys;sys.stdout.buffer.write(b"frame");sys.exit(7)',
                     'import time;time.sleep(2)'):
            with self.subTest(code=code):
                with self.assertRaises(ValueError): framed.read_child_frame(self.child(code),timeout=0.1)

    def test_only_fixed_failure_stage_is_released_on_child_failure(self):
        from emqx_preflight_stage import PreflightStageRefused
        child=self.child("import sys;sys.stdout.buffer.write(b'PREFLIGHT-REFUSED:target_capture\\n');sys.exit(1)")
        with self.assertRaises(PreflightStageRefused) as failure:
            framed.read_child_frame(child,timeout=3)
        self.assertEqual(failure.exception.stage,'target_capture')
        child=self.child("import sys;sys.stdout.buffer.write(b'PREFLIGHT-REFUSED:private-value\\n');sys.exit(1)")
        with self.assertRaises(ValueError) as failure:
            framed.read_child_frame(child,timeout=3)
        self.assertNotIsInstance(failure.exception,PreflightStageRefused)

    def test_cli_fixed_mode_and_realm_refuse_before_consuming_stdin_or_runner(self):
        with patch('emqx_arm_source_owner._owner_realm',return_value=False), \
             patch('emqx_adapter_owner.LabOwnerRunner') as runner:
            for args,expected in ((['--preflight'],1),(['--x86-preflight'],1),
                (['--preflight','--sha','override'],2),(['--source'],2)):
                self.assertEqual(framed.main(args),expected)
            runner.assert_not_called()

    def test_final_directory_collisions_preserve_existing_empty_and_nonempty_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            empty=root/'emqx-preflight-evidence-collision-empty';empty.mkdir(mode=0o700)
            occupied=root/'emqx-preflight-evidence-collision-full';occupied.mkdir(mode=0o700)
            marker=occupied/'owner-preflight.txt';marker.write_bytes(b'preserve-existing')
            with patch.object(framed,'PRIVATE_PARENT',root), \
                 patch.object(framed.tempfile,'_get_candidate_names',return_value=iter([
                     'collision-empty','collision-full','fresh'])):
                path=framed.retain_evidence(framed.evidence_frame(artifact()))
            self.assertEqual(path.parent.name,'emqx-preflight-evidence-fresh')
            self.assertTrue(empty.is_dir())
            self.assertEqual(list(empty.iterdir()),[])
            self.assertEqual(marker.read_bytes(),b'preserve-existing')
            self.assertEqual(path.read_bytes(),artifact())

    def test_write_or_fsync_failure_removes_only_created_artifact(self):
        for boundary in ('fdopen','fsync'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                existing=root/'preserved.json';existing.write_bytes(b'existing')
                with patch.object(framed,'PRIVATE_PARENT',root), \
                     patch.object(framed.os,boundary,side_effect=OSError('generated-failure')):
                    with self.assertRaises(OSError): framed.retain_evidence(framed.evidence_frame(artifact()))
                self.assertEqual(list(root.iterdir()),[existing])
                self.assertEqual(existing.read_bytes(),b'existing')

    def test_bad_parent_mode_refuses_without_chmod(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o755)
            with patch.object(framed,'PRIVATE_PARENT',root):
                with self.assertRaises(ValueError): framed.retain_evidence(framed.evidence_frame(artifact()))
            self.assertEqual(root.stat().st_mode&0o777,0o755)
            self.assertEqual(list(root.iterdir()),[])
