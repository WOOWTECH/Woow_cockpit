"""Bounded transport to this run's private rootful store; no default mutations."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys

ROOT = Path(sys.argv[1])
assert ROOT.parent == Path('/var/tmp') and ROOT.name.startswith('woow-arm54-ha-20261122-')
assert ROOT.is_dir() and not ROOT.is_symlink() and ROOT.stat().st_mode & 0o777 == 0o700
sys.path.insert(0, str(ROOT/'source/backup-engine'))
from woowbackup.podman import Result, CommandError

BASE = ['podman','--root',str(ROOT/'store'),'--runroot',str(ROOT/'run'),'--storage-driver','vfs',
        '--events-backend','file','--tmpdir',str(ROOT/'tmp')]
ENV = dict(os.environ,HOME=str(ROOT),XDG_CONFIG_HOME=str(ROOT/'config'),
           REGISTRY_AUTH_FILE=str(ROOT/'empty-auth.json'),TMPDIR=str(ROOT/'tmp'),PYTHONDONTWRITEBYTECODE='1')
os.environ.update({k:v for k,v in ENV.items() if k in ('TMPDIR','PYTHONDONTWRITEBYTECODE')})
os.umask(0o077)


class Runner:
    uid = 0
    home = str(ROOT)
    def __init__(self):
        self.commands=[]; self.free=[]
    def capacity(self):
        free=shutil.disk_usage(ROOT).free; self.free.append(free)
        if free < 12*1024**3+128*1024**2:
            raise RuntimeError('capacity-reserve-refused')
    def podman(self,*args,input=None,stdout=None,timeout=60,max_output=None,check=True,abort=None):
        self.capacity(); self.commands.append(list(args))
        if abort is not None and abort() is not None:
            raise abort()
        stream=hasattr(input,'read')
        with tempfile.TemporaryFile(dir=ROOT/'tmp') as out, tempfile.TemporaryFile(dir=ROOT/'tmp') as err:
            p=subprocess.run(BASE+list(args),env=ENV,stdin=input if stream else None,
                input=None if stream else input,stdout=out,stderr=err,timeout=min(timeout,300))
            size=out.tell(); limit=max_output if max_output is not None else 8*1024**2
            if size > limit: raise RuntimeError('capture-limit-refused')
            out.seek(0); err.seek(max(0,err.tell()-8192)); error=err.read()
            if stdout is not None:
                shutil.copyfileobj(out,stdout); data=b''
            else: data=out.read()
        self.capacity()
        if check and p.returncode:
            raise CommandError('isolated podman failed',returncode=p.returncode,stderr=b'suppressed')
        return Result(p.returncode,data,error)
    def relay(self,args,**kwargs): return self.podman(*args,**kwargs)
    def read_file(self,path,max_bytes):
        p=ROOT/path
        assert p.is_relative_to(ROOT) and '..' not in Path(path).parts
        assert p.stat().st_size<=max_bytes
        return p.read_bytes()


def report(path,doc):
    path.write_text(json.dumps(doc,sort_keys=True,indent=2)+'\n')
