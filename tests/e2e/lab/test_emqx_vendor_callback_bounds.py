"""Bounded vendor transport: synthetic local processes, never broker/key reads."""
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from emqx_target_vendor_policy import bounded_vendor_callbacks
from emqx_private_boundary import PrivateFailure
from woowbackup.podman import default_runner


class CallbackBoundsTests(unittest.TestCase):
    def callbacks(self, runner):
        module=SimpleNamespace(MAX_WIRE=1398168,LIMIT=65536)
        context=patch.dict(sys.modules,{'emqx_owner_vendor_files':module})
        context.start()
        self.addCleanup(context.stop)
        return bounded_vendor_callbacks(broker='fixed-owned-broker',runner=runner)

    def test_exact_actual_runner_limits_and_argv(self):
        calls=[]
        class Runner:
            def podman(self,*args,**kwargs):
                calls.append((args,kwargs))
                return SimpleNamespace(returncode=0,stdout=b'private')
        evaluate,inspect=self.callbacks(Runner())
        self.assertEqual(evaluate('fixed expression'),b'private')
        self.assertEqual(inspect(),b'private')
        self.assertEqual(calls,[(('exec','fixed-owned-broker','emqx','eval','fixed expression'),
            {'timeout':10,'max_output':1398168}),
            (('inspect','fixed-owned-broker'),{'timeout':5,'max_output':65536})])

    def test_failure_does_not_return_output(self):
        for result in (SimpleNamespace(returncode=1,stdout=b'private-error'),
                       SimpleNamespace(returncode=0,stdout=b'x'*65537)):
            class Runner:
                def podman(self,*args,**kwargs): return result
            _,inspect=self.callbacks(Runner())
            with self.assertRaises(PrivateFailure): inspect()

    def test_product_runner_enforces_live_output_bound(self):
        with self.assertRaises(Exception):
            default_runner([sys.executable,'-c',
                'import os; os.write(1,b"x"*131072)'],timeout=2,max_output=64)

    def test_product_runner_timeout_reaps_group(self):
        import os
        import tempfile
        import time
        with tempfile.TemporaryDirectory() as directory:
            marker=directory+'/escaped'
            source=('import os,time; p=os.fork(); '
                'time.sleep(0.5) if p==0 else time.sleep(5); '
                'open('+repr(marker)+',"w").close()')
            with self.assertRaises(Exception):
                default_runner([sys.executable,'-c',source],timeout=0.1,max_output=64)
            time.sleep(0.6)
            self.assertFalse(os.path.exists(marker))
