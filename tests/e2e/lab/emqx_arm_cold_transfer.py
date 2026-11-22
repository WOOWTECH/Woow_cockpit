"""Host controller. Reads ONLY HA_BACKUP_KEY; never sources env or exports key.

Exclusive lab locks required by caller. Child sees framed code/key/ciphertext
stdin, fixed summaries stdout, suppressed private stderr. Key exists only in RAM.
"""
import hashlib
import io
import tarfile
import os
from pathlib import Path
import shlex
import stat
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[3]
ARCHIVE=Path('/home/woowtechopenclaw/.woowbk-lab/ha-fixtures/20261119-b1/arm/woow-b1-arm-emqx-stopped-enc/woow-b1-arm-emqx-stopped-enc.tar')
CREDS=Path('/home/woowtechopenclaw/.woowbk-lab/secrets/ha-import-creds.env')
SHA='b6eb257cc5790bee30500f929d51ade66bfa8354dbe5bb61ba7c4bc08582f664'
BOOTSTRAP=r'''
import ctypes,io,os,pathlib,runpy,shutil,struct,sys,tarfile,tempfile
sys.dont_write_bytecode=True
work=None
try:
 def exact(n):
  out=[]
  while n:
   c=sys.stdin.buffer.read(min(n,65536))
   if not c:raise ValueError()
   out.append(c);n-=len(c)
  return b''.join(out)
 size=struct.unpack('!Q',exact(8))[0]
 if not 0<size<=16*1024*1024:raise ValueError()
 code=exact(size)
 work=pathlib.Path(tempfile.mkdtemp(prefix='woowbk-arm-code-'))
 work.chmod(0o700)
 with tarfile.open(fileobj=io.BytesIO(code),mode='r:') as archive:
  archive.extractall(work,filter='data')
 dep_size=struct.unpack('!Q',exact(8))[0]
 if not 0<dep_size<=32*1024*1024:raise ValueError()
 deps=work/'deps';deps.mkdir(mode=0o700)
 with tarfile.open(fileobj=io.BytesIO(exact(dep_size)),mode='r:') as archive:
  archive.extractall(deps,filter='data')
 sys.path[:0]=[str(deps),str(work/'backup-engine'),str(work/'tests/e2e/lab')]
 ctypes.CDLL(str(deps/'libsodium.so.23'),mode=ctypes.RTLD_GLOBAL)
 import cryptography,nacl.bindings,nacl.pwhash.argon2id
 mode=exact(1)
 if mode==b'P':
  print('ARM DEPENDENCIES PASSED',flush=True);raise SystemExit(0)
 if mode not in (b'R',b'C'):raise ValueError()
 runpy.run_path(str(work/'tests/e2e/lab/emqx_arm_cold_owner.py'),run_name='__main__',init_globals={'CONFIGURATION_ONLY':mode==b'C'})
finally:
 if work is not None:shutil.rmtree(work)
'''


def dependencies():
    # Public installed Ubuntu Python3.12 code/libraries only, never user data.
    result=io.BytesIO()
    def filtered(info):
        if '__pycache__' in info.name or info.name.endswith('.pyc'):return None
        return info
    with tarfile.open(fileobj=result,mode='w',dereference=True) as archive:
        for name in ('cryptography','nacl'):
            archive.add('/usr/lib/python3/dist-packages/'+name,arcname=name,filter=filtered)
        archive.add('/usr/lib/python3/dist-packages/_cffi_backend.cpython-312-x86_64-linux-gnu.so',arcname='_cffi_backend.cpython-312-x86_64-linux-gnu.so')
        archive.add('/lib/x86_64-linux-gnu/libsodium.so.23',arcname='libsodium.so.23')
    return result.getvalue()


def main():
    child=None
    try:
        deps=dependencies()
        probe=sys.argv[1:]==['--probe']
        configuration=sys.argv[1:]==['--configuration']
        if sys.argv[1:] and not (probe or configuration):raise ValueError()
        if probe:
            files=['backup-engine/woowbackup','tests/e2e/lab/emqx_arm_cold_owner.py']
            code=subprocess.check_output(['git','archive','HEAD',*files],cwd=ROOT)
            child=subprocess.Popen([str(ROOT/'tests/e2e/lab/owner.sh'),'d','/usr/bin/python3','-c',BOOTSTRAP],stdin=subprocess.PIPE,stderr=subprocess.DEVNULL)
            child.stdin.write(struct.pack('!Q',len(code)));child.stdin.write(code)
            child.stdin.write(struct.pack('!Q',len(deps)));child.stdin.write(deps);child.stdin.write(b'P')
            child.stdin.close();return child.wait(timeout=30)
        fd=os.open(CREDS,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as source:
            info=os.fstat(source.fileno())
            if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
            key=None
            for _ in range(128):
                line=source.readline(8193)
                if len(line)>8192:raise ValueError()
                if not line:break
                if line.startswith(b'HA_BACKUP_KEY='):
                    values=shlex.split(line[len(b'HA_BACKUP_KEY='):].decode('ascii').strip(),comments=False,posix=True)
                    if len(values)!=1:raise ValueError()
                    key=values[0].encode('ascii');break
            if key is None or not 1<=len(key)<=1024 or b'\n' in key or b'\r' in key:raise ValueError()
        files=['backup-engine/woowbackup','tests/e2e/lab/emqx_arm_cold_owner.py','tests/e2e/lab/emqx_cold_history.py','tests/e2e/lab/emqx_cold_terms.escript','tests/e2e/lab/emqx_native_runtime.py','tests/e2e/lab/emqx_semantic_readers.py','tests/e2e/lab/emqx_private_spool.py','tests/e2e/lab/ha_real_fixture.py','tests/e2e/lab/emqx_broker_workload.py','tests/e2e/lab/emqx_runtime_live.py','tests/e2e/lab/emqx_runtime_credentials.py','tests/e2e/lab/emqx_private_boundary.py','tests/e2e/lab/emqx_real_candidate.py','tests/e2e/lab/emqx_source_consumer.py','tests/e2e/lab/emqx_native_hocon.py','tests/e2e/lab/emqx_hocon_native.escript']
        code=subprocess.check_output(['git','archive','HEAD',*files],cwd=ROOT)
        fd=os.open(ARCHIVE,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as archive:
            before=os.fstat(archive.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=512*1024*1024:raise ValueError()
            child=subprocess.Popen([str(ROOT/'tests/e2e/lab/owner.sh'),'d','/usr/bin/python3','-c',BOOTSTRAP],stdin=subprocess.PIPE,stderr=subprocess.DEVNULL)
            child.stdin.write(struct.pack('!Q',len(code)));child.stdin.write(code)
            child.stdin.write(struct.pack('!Q',len(deps)));child.stdin.write(deps);child.stdin.write(b'C' if configuration else b'R')
            child.stdin.write(struct.pack('!I',len(key)));child.stdin.write(key)
            child.stdin.write(struct.pack('!Q',before.st_size))
            digest=hashlib.sha256()
            while True:
                chunk=archive.read(65536)
                if not chunk:break
                digest.update(chunk);child.stdin.write(chunk)
            after=os.fstat(archive.fileno())
            if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or digest.hexdigest()!=SHA:raise ValueError()
            child.stdin.close()
            return child.wait(timeout=900)
    except BaseException:
        if child is not None:
            try:child.stdin.close();child.wait(timeout=30)
            except BaseException:child.terminate()
        print('ARM TRANSFER REFUSED',flush=True)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
