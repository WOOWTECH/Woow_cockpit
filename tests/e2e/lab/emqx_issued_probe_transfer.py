"""Fixed no-source issued-runtime probe transport. No key/credential file IO."""
from contextlib import ExitStack
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import stat
import struct
import subprocess
import sys
import time
from emqx_arm_cold_transfer import ROOT, BOOTSTRAP as SOURCE_BOOTSTRAP, dependencies
from emqx_framed_preflight import MAGIC, MAX_FRAME, evidence_frame
from emqx_issued_target_probe import TARGET_RECEIPT, PHASES

DISPATCH=r'''
 if mode==b'T':
  import hashlib,signal
  from emqx_issued_target_probe import run_issued_target_probe,IssuedProbeRefused
  from emqx_framed_preflight import evidence_frame
  def deadline(*_):raise RuntimeError('fixed-probe-deadline')
  signal.signal(signal.SIGALRM,deadline);signal.alarm(360)
  try:
   result=run_issued_target_probe()
   sys.stdout.buffer.write(evidence_frame(result));sys.stdout.buffer.flush()
   raise SystemExit(0)
  except IssuedProbeRefused as failure:
   sys.stdout.buffer.write(b'ISSUED-PROBE-REFUSED:'+failure.phase.encode()+b'\n');sys.stdout.buffer.flush()
   raise SystemExit(1)
  finally:signal.alarm(0)
'''
ANCHOR=" if mode==b'P':"
if SOURCE_BOOTSTRAP.count(ANCHOR)!=1:raise RuntimeError('fixed-bootstrap-contract')
BOOTSTRAP=SOURCE_BOOTSTRAP.replace(ANCHOR,DISPATCH+ANCHOR)

class ProbeTransportRefused(ValueError):
    def __init__(self,phase='transport'):
        self.phase=phase if phase in PHASES else 'transport'
        super().__init__('fixed-issued-probe-refused')

def decode_result(raw,status):
    if type(raw) is not bytes or len(raw)>MAX_FRAME:raise ProbeTransportRefused()
    if status!=0:
        for phase in PHASES:
            if raw==b'ISSUED-PROBE-REFUSED:'+phase.encode()+b'\n':raise ProbeTransportRefused(phase)
        raise ProbeTransportRefused()
    if raw!=evidence_frame(TARGET_RECEIPT):raise ProbeTransportRefused()
    return TARGET_RECEIPT

def read_result(child,timeout=480):
    end=time.monotonic()+timeout;result=bytearray()
    with selectors.DefaultSelector() as selected:
        selected.register(child.stdout,selectors.EVENT_READ)
        while True:
            remaining=end-time.monotonic()
            if remaining<=0 or not selected.select(remaining):raise ProbeTransportRefused()
            part=os.read(child.stdout.fileno(),min(65536,MAX_FRAME+1-len(result)))
            if not part:break
            result.extend(part)
            if len(result)>MAX_FRAME:raise ProbeTransportRefused()
    return decode_result(bytes(result),child.wait(timeout=max(.01,end-time.monotonic())))

def public_bundle():
    files=subprocess.check_output(['git','ls-tree','-r','--name-only','HEAD','tests/e2e/lab'],cwd=ROOT).decode().splitlines()
    files=[p for p in files if Path(p).suffix in ('.py','.expr','.escript') and not Path(p).name.startswith('test_')]
    files+=['tests/e2e/lab/emqx_public_function_catalog.json','backup-engine/woowbackup']
    return subprocess.check_output(['git','archive','HEAD',*files],cwd=ROOT)

def locks(stack):
    for name in ('/tmp/woowbk-dev-d-mutation.lock','/tmp/headscale-dev-d-private-volume.lock'):
        before=os.lstat(name)
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW);stack.callback(os.close,fd)
        after=os.fstat(fd)
        if (not stat.S_ISREG(after.st_mode) or after.st_uid!=os.geteuid() or after.st_nlink!=1 or
                (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino)):
            raise ProbeTransportRefused()
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)

def postflight():
    command=[str(ROOT/'tests/e2e/lab/owner.sh'),'d']
    checked=subprocess.run(command+['--verify-isolation'],capture_output=True,timeout=15)
    if checked.returncode:raise ProbeTransportRefused()
    code='''import pathlib,subprocess,sys
for args in (("ps","-aq","--filter","name=woowbk-emqxlab-"),("volume","ls","-q","--filter","name=woowbk-emqxlab-")):
 p=subprocess.run(["podman",*args],capture_output=True); assert p.returncode==0 and not p.stdout.strip()
'''
    checked=subprocess.run(command+['python3','-c',code],capture_output=True,timeout=15)
    if checked.returncode:raise ProbeTransportRefused()

def main():
    child=None;started=time.monotonic();report={'scope':'actual-issued-target-only','restore_executed':False}
    try:
        if len(sys.argv)!=1:raise ProbeTransportRefused()
        if subprocess.run(['git','diff','--quiet','HEAD'],cwd=ROOT).returncode:raise ProbeTransportRefused()
        report['source_commit']=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
        with ExitStack() as stack:
            locks(stack);postflight()
            try:
                code=public_bundle();deps=dependencies()
                child=subprocess.Popen([str(ROOT/'tests/e2e/lab/owner.sh'),'d','/usr/bin/python3','-c',BOOTSTRAP],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
                child.stdin.write(struct.pack('!Q',len(code))+code)
                child.stdin.write(struct.pack('!Q',len(deps))+deps+b'T');child.stdin.close()
                read_result(child)
                report['result']='passed'
            finally:
                if child is not None and child.poll() is None:
                    child.terminate();child.wait(timeout=30)
                postflight();report['isolation_cleanup']='passed'
    except ProbeTransportRefused as failure:
        report.update(result='refused',fixed_phase=failure.phase)
    except BaseException:
        report.update(result='refused',fixed_phase='transport')
    report['elapsed_seconds']=time.monotonic()-started
    print(json.dumps(report,sort_keys=True))
    return 0 if report.get('result')=='passed' and report.get('isolation_cleanup')=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
