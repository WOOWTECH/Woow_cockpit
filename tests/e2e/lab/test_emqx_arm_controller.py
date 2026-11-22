"""Controller failure-path integration only; fake child/owner, no real backup."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT=Path(__file__).with_name('run_emqx_arm_cold.sh')

class ControllerTests(unittest.TestCase):
    def run_case(self,child=0,post=0,lock_kind=None,args=()):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'owner.lock').write_bytes(b'preserve-main-lock')
            (root/'volume.lock').write_bytes(b'preserve-volume-lock')
            if lock_kind=='symlink':
                (root/'unrelated').write_bytes(b'preserve-main-lock')
                (root/'owner.lock').unlink()
                (root/'owner.lock').symlink_to(root/'unrelated')
            elif lock_kind=='hardlink':
                os.link(root/'owner.lock',root/'other-link')
            (root/'lib.sh').write_text('LAB_DIR="'+directory+'"\nREPO_ROOT="'+directory+'"\nLP="'+directory+'/lp"\nNAME=fixture\ndevice_vars() { :; }\ndie() { exit 1; }\n')
            files={
                'git':'exit 0',
                'lp':'echo "0 1073741824"',
                'owner.sh':'if [ "$2" = --verify-isolation ]; then exit 0; fi\nexit "$POST_STATUS"',
                'python3':'exit "$CHILD_STATUS"',
            }
            for name,body in files.items():
                p=root/name;p.write_text('#!/bin/bash\n'+body+'\n');p.chmod(0o700)
            source=SCRIPT.read_text().replace('/tmp/woowbk-dev-d-mutation.lock',directory+'/owner.lock').replace('/tmp/headscale-dev-d-private-volume.lock',directory+'/volume.lock')
            (root/'run.sh').write_text(source)
            env=dict(os.environ,PATH=directory+':'+os.environ['PATH'],CHILD_STATUS=str(child),POST_STATUS=str(post))
            result=subprocess.run(['bash',str(root/'run.sh'),*args],env=env,capture_output=True,text=True)
            self.assertEqual((root/'owner.lock').read_bytes(),b'preserve-main-lock')
            self.assertEqual((root/'volume.lock').read_bytes(),b'preserve-volume-lock')
            return result

    def test_success_requires_postflight(self):
        result=self.run_case()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'ARM POSTFLIGHT PASSED\n')

    def test_child_failure_still_runs_postflight_and_preserves_exit(self):
        result=self.run_case(child=7)
        self.assertEqual(result.returncode,7,result.stderr)
        self.assertEqual(result.stdout,'ARM POSTFLIGHT PASSED\n')

    def test_postflight_failure_overrides_success_and_failure(self):
        for child in (0,7):
            with self.subTest(child=child):
                result=self.run_case(child=child,post=1)
                self.assertEqual(result.returncode,1,result.stderr)
                self.assertEqual(result.stdout,'ARM POSTFLIGHT REFUSED\n')

    def test_existing_aliases_refuse_without_changing_original_bytes(self):
        for kind in ('symlink','hardlink'):
            with self.subTest(kind=kind):
                result=self.run_case(lock_kind=kind)
                self.assertEqual(result.returncode,1,result.stderr)
                self.assertEqual(result.stdout,'')

    def test_both_fixed_preflight_modes_still_require_successful_postflight(self):
        for mode in ('--preflight','--x86-preflight'):
            for post,expected in ((0,0),(1,1)):
                with self.subTest(mode=mode,post=post):
                    result=self.run_case(post=post,args=(mode,))
                    self.assertEqual(result.returncode,expected,result.stderr)
                    self.assertEqual(result.stdout,'ARM POSTFLIGHT '+('PASSED' if post==0 else 'REFUSED')+'\n')
