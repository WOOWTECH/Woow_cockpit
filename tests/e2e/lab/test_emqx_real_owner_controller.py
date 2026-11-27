"""Generated shell/controller doubles only; never invokes the real lab wrapper."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT=Path(__file__).with_name('run_emqx_real_owner.sh')
class ControllerTests(unittest.TestCase):
    def run_case(self,*,headroom=2*1024**3,child=0,post=0,alias=False,args=('--real-restore',)):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);lock=root/'owner.lock';lock.write_bytes(b'preserve-owner')
            volume=root/'volume.lock';volume.write_bytes(b'preserve-volume')
            if alias:os.link(lock,root/'hardlink')
            (root/'lib.sh').write_text('LAB_DIR="'+d+'"\nREPO_ROOT="'+d+'"\nLP="'+d+'/lp"\nNAME=fixture\ndevice_vars(){ :; }\ndie(){ exit 1; }\n')
            for name,body in {'git':'exit 0','lp':'echo "0 '+str(headroom)+'"','python3':'exit "$CHILD_STATUS"',
                'owner.sh':'if [ ! -f "'+d+'/seen" ]; then touch "'+d+'/seen"; fi\nif [ "$2" = --verify-isolation ]; then\n n=$(cat "'+d+'/counter" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "'+d+'/counter"\n if [ "$n" -gt 1 ]; then exit "$POST_STATUS"; fi\nfi\nexit 0'}.items():
                p=root/name;p.write_text('#!/bin/bash\n'+body+'\n');p.chmod(0o700)
            text=SCRIPT.read_text().replace('/tmp/woowbk-dev-d-mutation.lock',str(lock)).replace('/tmp/headscale-dev-d-private-volume.lock',str(volume))
            script=root/'run.sh';script.write_text(text)
            env=dict(os.environ,PATH=d+':'+os.environ['PATH'],CHILD_STATUS=str(child),POST_STATUS=str(post));env.pop('WOOWBK_LAB_HOME',None)
            result=subprocess.run(['bash',str(script),*args],capture_output=True,env=env,text=True,timeout=5)
            self.assertEqual(lock.read_bytes(),b'preserve-owner');self.assertEqual(volume.read_bytes(),b'preserve-volume')
            return result

    def test_fixed_arm_x86_modes_keep_full_budget_and_readonly_lock_identity(self):
        for mode in ('--real-restore','--x86-real-restore','--real-restore-staged','--x86-real-restore-staged','--real-restore-dependencies','--issued-target-probe'):
            self.assertEqual(self.run_case(args=(mode,),headroom=1800*1024**2).returncode,0)
            self.assertEqual(self.run_case(args=(mode,),headroom=1800*1024**2-1).returncode,1)
        self.assertEqual(self.run_case(alias=True).returncode,1)

    def test_child_failure_postflight_and_bad_args_cannot_claim_success(self):
        run=self.run_case(child=7);self.assertEqual(run.returncode,7);self.assertEqual(run.stdout,'REAL OWNER POSTFLIGHT PASSED\n')
        run=self.run_case(post=1);self.assertEqual(run.returncode,1);self.assertEqual(run.stdout,'REAL OWNER POSTFLIGHT REFUSED\n')
        for args in ((),('--source',),('--real-restore','extra')):
            self.assertEqual(self.run_case(args=args).returncode,2)
