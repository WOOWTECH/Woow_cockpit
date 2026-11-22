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
    return (json.dumps({'phase':'preflight','result':'passed',
        'coverage':[SOURCE_NAMES[k] for k in sorted(SOURCE_NAMES)]},
        sort_keys=True,ensure_ascii=False)+'\n').encode()


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
               framed.evidence_frame(b'private arbitrary response'),b'')
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

    def test_cli_fixed_mode_and_realm_refuse_before_consuming_stdin_or_runner(self):
        with patch('emqx_arm_source_owner._owner_realm',return_value=False), \
             patch('emqx_adapter_owner.LabOwnerRunner') as runner:
            for args,expected in ((['--preflight'],1),(['--x86-preflight'],1),
                (['--preflight','--sha','override'],2),(['--source'],2)):
                self.assertEqual(framed.main(args),expected)
            runner.assert_not_called()
