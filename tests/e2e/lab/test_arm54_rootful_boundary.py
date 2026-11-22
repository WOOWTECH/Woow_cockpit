"""Only new rootful transport safety cases; no SSH, Podman or service actions."""
import ast
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from woowbackup.podman import Result


class RootfulBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name)
        class Base:
            def __init__(self): self.commands=[]
            def podman(self,*args,**kwargs): return ('delegated',args)
        parsed=ast.parse(Path(__file__).with_name('arm54_service_native.py').read_text())
        node=next(n for n in parsed.body if isinstance(n,ast.ClassDef) and n.name=='RootfulRunner')
        scope={'Runner':Base,'ROOT':self.root,'Path':Path,'subprocess':subprocess,'Result':Result}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<rootful-boundary>','exec'),scope)
        self.runner=scope['RootfulRunner']()

    def test_unknown_unshare_and_external_stat_refused_before_process(self):
        for args in (('unshare','sh','-c','echo unsafe'),('unshare','stat','-c','%u %g %a','--','/etc')):
            with patch.object(subprocess,'run') as run:
                with self.assertRaises(AssertionError): self.runner.podman(*args)
                run.assert_not_called()

    def test_actual_owned_volume_stat_is_not_fabricated(self):
        volume=self.root/'store/volumes/owned/_data';volume.mkdir(parents=True,mode=0o700)
        result=self.runner.podman('unshare','stat','-c','%u %g %a','--',str(volume))
        self.assertEqual(result.returncode,0)
        info=volume.stat()
        self.assertEqual(result.stdout.decode().split(),[str(info.st_uid),str(info.st_gid),'700'])

    def test_normal_podman_operation_delegates(self):
        self.assertEqual(self.runner.podman('image','inspect','fixture'),('delegated',('image','inspect','fixture')))
