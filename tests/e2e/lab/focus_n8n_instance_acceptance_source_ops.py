"""Fixed source-only transaction. No package manager, helper call or service start.

Only the private case directory, installed engine directory and helper are
written. VERSION lives inside the engine swap. Importing performs no I/O.
"""
import base64
from contextlib import contextmanager
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

if __name__ == '__main__':   # only as the device program: importing it on the host must not change the host process
    sys.dont_write_bytecode = True
    sys.pycache_prefix = '/nonexistent/woowbk-focus-n8n-pycache'
import focus_n8n_instance_acceptance_ops as common

LIB = Path('/usr/local/lib/woowtech-cockpit-backup')
HELPER = Path('/usr/local/libexec/woowtech-cockpit-backup')
CASE_ROOT = Path('/var/lib/woowtech-backup/focus-n8n-instance')
RUN = Path('/run/woowtech-backup')
MAX_BYTES = 64*1024**2
FROZEN = 'd09f4fe8e06305aff6a1150f41d6de719e7b7f6a'


def metadata(st):
    return {'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'mtime_ns':st.st_mtime_ns}


def tree(path):
    """Exact bounded regular tree, including pre-existing bytecode/unknown files."""
    path=Path(path); result={'directories':{},'files':{}}; total=0; count=0
    for p in [path]+sorted(path.rglob('*')):
        st=p.lstat(); rel='.' if p==path else p.relative_to(path).as_posix(); count+=1
        if count>4096 or len(p.relative_to(path).parts)>8:raise ValueError('unbounded engine tree')
        if stat.S_ISDIR(st.st_mode):result['directories'][rel]=metadata(st)
        elif stat.S_ISREG(st.st_mode) and st.st_nlink==1:
            data,meta=common.read_regular(p,MAX_BYTES);total+=len(data)
            if total>MAX_BYTES:raise ValueError('unbounded engine bytes')
            result['files'][rel]=dict(meta,bytes=len(data))
        else:raise ValueError('non-regular engine object')
    return result


def remove_tree(path, expected):
    if tree(path)!=expected:raise ValueError('changed owned source staging retained')
    for rel in expected['files']:(Path(path)/rel).unlink()
    for rel in sorted(expected['directories'],key=lambda x:len(Path(x).parts),reverse=True):
        (Path(path)/rel).rmdir()


def copy_tree(source, target, expected, *, private=False):
    if tree(source)!=expected:raise ValueError('protected prior engine changed')
    target=Path(target)
    for rel in sorted(expected['directories'],key=lambda x:len(Path(x).parts)):
        p=target/rel;p.mkdir(mode=0o700 if private else expected['directories'][rel]['mode'])
    for rel,meta in expected['files'].items():
        data=common.read_regular(Path(source)/rel,MAX_BYTES)[0]
        common.atomic(target/rel,data,mode=0o600 if private else meta['mode'],
                      uid=os.geteuid() if private else meta['uid'],gid=os.getegid() if private else meta['gid'],
                      mtime_ns=meta['mtime_ns'])
    if not private:restore_directory_metadata(target,expected)


def restore_directory_metadata(path, expected):
    for rel,meta in sorted(expected['directories'].items(),key=lambda x:len(Path(x[0]).parts),reverse=True):
        p=Path(path)/rel;os.chown(p,meta['uid'],meta['gid']);os.chmod(p,meta['mode'])
        os.utime(p,ns=(p.stat().st_atime_ns,meta['mtime_ns']))


def exchange(first, second):
    """Atomic Linux directory exchange; no delete/rename-gap fallback."""
    libc=ctypes.CDLL(None,use_errno=True)
    fn=getattr(libc,'renameat2',None)
    if fn is None:raise RuntimeError('atomic directory exchange unavailable')
    fn.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    fn.restype=ctypes.c_int
    if fn(-100,os.fsencode(first),-100,os.fsencode(second),2):
        raise OSError(ctypes.get_errno(),'atomic source exchange failed')
    for parent in {Path(first).parent,Path(second).parent}:
        fd=os.open(parent,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)


@contextmanager
def engine_locks(run=RUN):
    """Same paths/order as jobs.py: start decision lock, then engine lock."""
    fds=[]
    try:
        for name in ('jobs.lock','engine.lock'):
            fd=os.open(Path(run)/name,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);fds.append(fd)
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600:
                raise ValueError('unsafe production source lock')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:
        for fd in reversed(fds):os.close(fd)


def decode_payload(payload):
    if payload.get('source_commit')!=FROZEN:raise ValueError('wrong source')
    files={};total=0
    for name,encoded in payload['files'].items():
        if name!='VERSION' and not re.fullmatch(r'woowbackup/(?:adapters/)?[A-Za-z_][A-Za-z0-9_]*\.py',name):
            raise ValueError('out-of-scope source path')
        b=base64.b64decode(encoded,validate=True);total+=len(b)
        if total>MAX_BYTES:raise ValueError('unbounded source payload')
        if name.endswith('.py'):compile(b,name,'exec')
        files[name]=b
    if not {'VERSION','woowbackup/__init__.py','woowbackup/cli.py','woowbackup/adapters/__init__.py'}<=files.keys():
        raise ValueError('incomplete source')
    helper=base64.b64decode(payload['helper'],validate=True)
    if len(helper)>1024**2 or not helper.startswith(b'#!/usr/bin/python3 -I\n'):raise ValueError('invalid trusted helper')
    compile(helper,'<candidate helper>','exec')
    hashes={k:common.digest(v) for k,v in files.items()};hashes['helper']=common.digest(helper)
    if hashes!=payload['sha256']:raise ValueError('source payload hash mismatch')
    return files,helper


def tool_probe(candidate):
    code=("import sys;sys.dont_write_bytecode=True;sys.pycache_prefix='/nonexistent/woowbk-focus-n8n-pycache';"
          "sys.path.insert(0,"+repr(str(candidate))+");"
          "from nacl import bindings;from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes;"
          "from woowbackup import cli,ha_n8n,ha_instance_access;from woowbackup.adapters import quadlet_postgres;"
          "assert cli.__file__.startswith("+repr(str(candidate)+'/')+");print('ready')")
    commands=[['age','--version'],['age-keygen','--version'],['zstd','--version'],['python3','-B','-I','-c',code]]
    for argv in commands:
        p=subprocess.run(argv,capture_output=True,timeout=30,env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
        if p.returncode:raise RuntimeError('existing dependency/import probe failed; raw stderr withheld')


class Transaction:
    def __init__(self,name,*,lib=LIB,helper=HELPER,parent=CASE_ROOT):
        if not common.BASE.fullmatch(name):raise ValueError('invalid source case')
        self.name=name;self.lib=Path(lib);self.helper=Path(helper);self.parent=Path(parent)/name
        # Sibling of the image/flow Store: its cleanup must not remove the
        # private source recovery copy, which survives until source-recover.
        self.path=self.parent.with_name(self.parent.name+'-source')
        self.stage=self.lib.with_name(self.lib.name+'.'+name+'.new')
        self.hstage=self.helper.with_name(self.helper.name+'.'+name+'.new')
        self.recovery=self.lib.with_name(self.lib.name+'.'+name+'.recover')
        self.state=json.loads(common.read_regular(self.path/'state.json',8*1024**2)[0]) if self.path.exists() else {}

    def save(self):common.atomic(self.path/'state.json',json.dumps(self.state).encode())

    def original_copy(self):
        if not self.parent.is_dir() or self.parent.is_symlink() or self.path.exists():raise ValueError('source case missing or exists')
        for p in (self.lib,self.lib.parent,self.helper.parent,self.parent):
            st=p.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o022:
                raise ValueError('untrusted source parent')
        if any(os.path.lexists(p) for p in (self.stage,self.hstage,self.recovery)):raise ValueError('source staging exists')
        original=tree(self.lib);helper,hmeta=common.read_regular(self.helper)
        for meta in list(original['directories'].values())+[v for k,v in original['files'].items() if k.endswith('.py')]+[hmeta]:
            if meta['uid']!=os.geteuid() or meta['mode']&0o022:raise ValueError('untrusted prior engine code')
        self.path.mkdir(mode=0o700)
        dfd=os.open(self.path.parent,os.O_DIRECTORY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
        # Incomplete copies are never eligible for publication or recovery.
        self.state={'original':original,'helper':hmeta,'copy_complete':False,'publish_intent':False,'complete':False}
        self.save();copy_tree(self.lib,self.path/'prior-library',original,private=True)
        common.atomic(self.path/'prior-helper',helper)
        self.state['private_tree']=tree(self.path/'prior-library')
        self.state['copy_complete']=True;self.save()

    def stage_candidate(self,payload):
        files,helper=decode_payload(payload)
        self.state['stage_intent']=True;self.save()
        self.stage.mkdir(mode=0o755)
        (self.stage/'woowbackup').mkdir(mode=0o755);(self.stage/'woowbackup/adapters').mkdir(mode=0o755)
        for name,data in files.items():common.atomic(self.stage/name,data,mode=0o644)
        common.atomic(self.hstage,helper,mode=0o755)
        tool_probe(self.stage)  # before publishing anything; imports cannot write/read caches
        self.state['candidate']=tree(self.stage)
        self.state['candidate_helper']=common.read_regular(self.hstage)[1]
        self.save()

    def install(self,payload):
        decode_payload(payload)  # reject before snapshot/staging writes
        self.original_copy()
        try:
            self.stage_candidate(payload)
            if tree(self.lib)!=self.state['original'] or common.read_regular(self.helper)[1]!=self.state['helper']:
                raise ValueError('prior source changed while staging')
            self.state['publish_intent']=True;self.save()
            exchange(self.stage,self.lib)
            os.replace(self.hstage,self.helper)
            fd=os.open(self.helper.parent,os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
            self.verify_candidate(payload)
            self.state['complete']=True;self.save()
        except BaseException:
            if self.state.get('publish_intent'):self.restore()
            raise

    def verify_candidate(self,payload):
        if tree(self.lib)!=self.state['candidate'] or common.read_regular(self.helper)[1]!=self.state['candidate_helper']:
            raise ValueError('published source differs')
        expected=payload['sha256'];actual={k:v['sha256'] for k,v in tree(self.lib)['files'].items()}
        actual['helper']=common.read_regular(self.helper)[1]['sha256']
        if actual!=expected:raise ValueError('published source hashes mismatch')
        tool_probe(self.lib)

    def restore(self):
        if self.state.get('copy_complete') is not True:raise ValueError('incomplete prior copy retained')
        if tree(self.path/'prior-library')!=self.state['private_tree']:raise ValueError('private source copy changed')
        old_helper=common.read_regular(self.path/'prior-helper')[0]
        if common.digest(old_helper)!=self.state['helper']['sha256']:raise ValueError('private helper changed')
        current=tree(self.lib)
        if current not in (self.state['original'],self.state.get('candidate')):raise ValueError('unknown current engine retained')
        current_helper=common.read_regular(self.helper)[1]
        if current_helper not in (self.state['helper'],self.state.get('candidate_helper')):raise ValueError('unknown current helper retained')
        if current!=self.state['original']:
            if os.path.lexists(self.recovery):raise ValueError('recovery staging exists; retain for inspection')
            # Private copy's files are0600; rebuild using original exact metadata.
            self.recovery.mkdir(mode=self.state['original']['directories']['.']['mode'])
            for rel,meta in sorted(self.state['original']['directories'].items(),key=lambda x:len(Path(x[0]).parts)):
                if rel!='.':(self.recovery/rel).mkdir(mode=meta['mode'])
            for rel,meta in self.state['original']['files'].items():
                data=common.read_regular(self.path/'prior-library'/rel,MAX_BYTES)[0]
                common.atomic(self.recovery/rel,data,mode=meta['mode'],uid=meta['uid'],gid=meta['gid'],mtime_ns=meta['mtime_ns'])
            restore_directory_metadata(self.recovery,self.state['original'])
            self.state['recovery_publish_intent']=True;self.save()
            exchange(self.recovery,self.lib)
        meta=self.state['helper']
        common.atomic(self.helper,old_helper,mode=meta['mode'],uid=meta['uid'],gid=meta['gid'],mtime_ns=meta['mtime_ns'])
        if tree(self.lib)!=self.state['original'] or common.read_regular(self.helper)[1]!=meta:
            raise ValueError('exact original source recovery failed')
        self.state['restored']=True;self.state['complete']=False;self.save()
        # Keep all private copies and recognized staging for a later explicit cleanup.


def dispatch(q):
    if os.geteuid()!=0:raise ValueError('source transaction requires root')
    with engine_locks():
        before=common.inventory()
        if before['active_jobs'] or before['running']:raise ValueError('source requires idle stopped device')
        if before['protected']!=q['protected']:raise ValueError('protected baseline changed')
        if any(before['units'][u]['ActiveState']!='inactive' for u in common.UNITS):raise ValueError('application service is active')
        tx=Transaction(q['case'])
        if q['phase']=='source-install':
            tx.install(q['payload'])
        elif q['phase']=='source-recover':tx.restore()
        else:raise ValueError('unknown source phase')
        after=common.inventory()
        for key in ('catalog','files','protected','units','timer','volumes','images','running','active_jobs','retention_sha256'):
            if before[key]!=after[key]:raise ValueError('source-only durable boundary changed')
        return {'phase':q['phase'],'source_hashes':{k:v['sha256'] for k,v in tree(tx.lib)['files'].items()},
                'helper_sha256':common.read_regular(tx.helper)[1]['sha256'],
                'prior_source_sha256':common.digest(json.dumps(tx.state['original'],sort_keys=True).encode()),
                'source_installed':tx.state.get('complete') is True,'source_restored':tx.state.get('restored') is True,
                'protected_equal':True,'durable_equal':True,'private_prior_copy_retained':True,'bytecode_disabled':True}


if __name__=='__main__':
    try:
        raw=sys.stdin.buffer.read(96*1024**2+1)
        if len(raw)>96*1024**2:raise ValueError('unbounded source request')
        print(json.dumps(dispatch(json.loads(raw))))
    except Exception as error:
        print(json.dumps({'error_class':type(error).__name__}),file=sys.stderr)
        raise SystemExit(1)
