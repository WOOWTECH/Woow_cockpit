"""Standalone LL source phase: per-file publication, whole prior copy, CAS return.

Only engine Python, VERSION and helper are writable. Import performs no I/O.
The live merged library directory is never renamed. Private journals/copies
remain available after success, cancellation or an interrupted transport.
"""
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys

import focus_litellm_instance_acceptance_ops as common

OLD='1adf4df2b548bff1626e21d1d84e677f9622e4bc'
NEW='59a1b0f95132ea51c899f590eea7e3b02c5dba43'
LIB=Path('/usr/local/lib/woowtech-cockpit-backup')
HELPER=Path('/usr/local/libexec/woowtech-cockpit-backup')
PARENT=Path('/var/lib/woowtech-backup/focus-litellm-source')
CASE=re.compile(r'woowbk_focus_litellm_source_[0-9a-f]{12}\Z')
PY=re.compile(r'woowbackup/(?:adapters/)?[A-Za-z_][A-Za-z0-9_]*\.py\Z')
MAX=64*1024**2
SELECTED=('woow-emqx','woow-emqx-entrance','hermes-postgresql','hermes-redis',
          'hermes-agent','omnigent-postgres','omnigent-server','omnigent-runner')


def managed(name):return name=='VERSION' or bool(PY.fullmatch(name))
def digest(value):return hashlib.sha256(value).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def fsync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def meta(s):
    return {'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtime_ns':s.st_mtime_ns}


def file_meta(path):
    data,result=common.read_regular(path,MAX)
    s=Path(path).lstat()
    if os.listxattr(path,follow_symlinks=False):raise ValueError('source-xattrs')
    return dict(result,mtime_ns=s.st_mtime_ns,bytes=len(data))


def tree(root):
    root=Path(root);result={'directories':{},'files':{}};total=0;count=0
    def walk(path,depth):
        nonlocal total,count
        count+=1
        if count>4096 or depth>8:raise ValueError('source-tree-bound')
        s=path.lstat();name=str(path.relative_to(root))
        if os.listxattr(path,follow_symlinks=False):raise ValueError('source-xattrs')
        if stat.S_ISDIR(s.st_mode):
            result['directories'][name]=meta(s)
            for child in sorted(path.iterdir()):walk(child,depth+1)
        elif stat.S_ISREG(s.st_mode):
            result['files'][name]=file_meta(path);total+=s.st_size
            if total>MAX:raise ValueError('source-tree-bytes')
        else:raise ValueError('source-nonregular')
    walk(root,0);return result


def trusted(path,root):
    path=Path(path);root=Path(root)
    if path!=root and root not in path.parents:raise ValueError('source-untrusted-root')
    for p in (path,*path.parents):
        s=p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o022:
            raise ValueError('source-untrusted-parent')
        if p==root:break


def decode(payload):
    if payload['source_commit']!=NEW or type(payload['mtime_ns']) is not int or payload['mtime_ns']<=0:
        raise ValueError('source-payload-pin')
    raw=payload['files']
    if not isinstance(raw,dict) or len(raw)>100 or not {'helper','VERSION','woowbackup/__init__.py',
                'woowbackup/adapters/__init__.py','woowbackup/cli.py'}<=set(raw):raise ValueError('source-payload-members')
    if any(n!='helper' and not managed(n) for n in raw):raise ValueError('source-payload-path')
    files={n:base64.b64decode(b,validate=True) for n,b in raw.items()}
    if sum(map(len,files.values()))>MAX or {n:digest(b) for n,b in files.items()}!=payload['sha256']:
        raise ValueError('source-payload-hash')
    for n,b in files.items():
        if n=='helper' or n.endswith('.py'):compile(b,n,'exec')
    return files


def check_caches(lib,prior,files,mtime_ns):
    # Normal helper starts must not accept a stale cache either. Preserve all
    # prior caches, but refuse a changed/new module whose *usable* old cache
    # would bypass the new source. Different Python cache tags are irrelevant.
    tag=sys.implementation.cache_tag
    for n,b in files.items():
        if not n.endswith('.py') or prior['files'].get(n,{}).get('sha256')==digest(b):continue
        p=Path(n);cache=str(p.parent/'__pycache__'/(p.stem+'.'+tag+'.pyc'))
        if cache not in prior['files']:continue
        header=common.read_regular(Path(lib)/cache,MAX)[0][:16]
        if len(header)!=16 or header[:4]!=importlib.util.MAGIC_NUMBER:continue
        flags=int.from_bytes(header[4:8],'little')
        if flags==1 or flags in (0,2) and (int.from_bytes(header[8:12],'little')==((mtime_ns//10**9)&0xffffffff)
                and int.from_bytes(header[12:16],'little')==(len(b)&0xffffffff)):
            raise ValueError('source-stale-bytecode-collision')


class Transaction:
    def __init__(self,name,*,lib=LIB,helper=HELPER,parent=PARENT,trusted_root=Path('/')):
        if not CASE.fullmatch(name):raise ValueError('source-case')
        self.name=name;self.lib=Path(lib);self.helper=Path(helper);self.path=Path(parent)/name
        self.trusted_root=Path(trusted_root)
        self.libown=self.lib.parent/('.'+name+'-library')
        self.helpown=self.helper.parent/('.'+name+'-helper')
        self.state={}
        if os.path.lexists(self.path):
            trusted(self.path,self.trusted_root)
            self.state=json.loads(common.read_regular(self.path/'state.json',8*1024**2)[0])
            if self.state['paths']!=[str(self.lib),str(self.helper)]:raise ValueError('source-journal-paths')

    def save(self):
        raw=canonical(self.state)
        if len(raw)>8*1024**2:raise ValueError('source-journal-bound')
        common.atomic(self.path/'state.json',raw)

    def step(self,name,fn):
        self.state['pending']=name;self.save()
        try:value=fn()
        except BaseException as error:
            self.state['error']={'stage':name,'class':type(error).__name__,
                                 'errno':error.errno if isinstance(error,OSError) else None}
            self.save();raise
        self.state['pending']=None;self.save();return value

    def prepare(self,payload,expected):
        files=decode(payload)
        if self.state or any(os.path.lexists(p) for p in (self.path,self.libown,self.helpown)):
            raise ValueError('source-never-replay')
        if not os.path.lexists(self.path.parent):
            trusted(self.path.parent.parent,self.trusted_root)
            self.path.parent.mkdir(mode=0o700);fsync_dir(self.path.parent.parent)
        for p in (self.path.parent,self.lib,self.helper.parent):trusted(p,self.trusted_root)
        original=tree(self.lib);helper=file_meta(self.helper)
        actual={n:m['sha256'] for n,m in original['files'].items() if managed(n)}|{'helper':helper['sha256']}
        if actual!=expected:raise ValueError('source-not-exact-old')
        check_caches(self.lib,original,files,payload['mtime_ns'])
        for n in original['files']:
            if n.endswith('.py') and not managed(n):raise ValueError('source-unknown-python')
        for m in [*original['directories'].values(),*original['files'].values(),helper]:
            if m['uid']!=os.geteuid() or m['mode']&0o022:raise ValueError('source-prior-metadata')
        for n in files:
            if n!='helper' and str(Path(n).parent) not in original['directories']:
                raise ValueError('source-new-directory-unsupported')
        self.path.mkdir(mode=0o700);fsync_dir(self.path.parent)
        self.state={'paths':[str(self.lib),str(self.helper)],'old':OLD,'new':NEW,'original':original,
            'helper':helper,'lib_identity':[self.lib.stat().st_dev,self.lib.stat().st_ino],
            'prepared':False,'complete':False,'restored':False,'mutations':{},'temporaries':{},'pending':None}
        self.save()
        def copy_prior():
            dest=self.path/'prior-library';dest.mkdir(mode=0o700)
            for n in sorted(original['directories'],key=lambda n:len(Path(n).parts)):
                if n!='.':(dest/n).mkdir(mode=0o700)
            for n,m in original['files'].items():
                b=common.read_regular(self.lib/n,MAX)[0]
                if digest(b)!=m['sha256']:raise ValueError('source-prior-copy-race')
                common.atomic(dest/n,b)
            common.atomic(self.path/'prior-helper',common.read_regular(self.helper,MAX)[0])
            self.state['private_tree']=tree(dest);self.state['private_helper']=file_meta(self.path/'prior-helper')
            for n,m in original['files'].items():
                if self.state['private_tree']['files'][n]['sha256']!=m['sha256']:raise ValueError('source-copy-hash')
            if self.state['private_helper']['sha256']!=helper['sha256']:raise ValueError('source-helper-copy-hash')
        self.step('whole-prior-copy',copy_prior)
        def stage():
            for p in (self.libown,self.helpown):p.mkdir(mode=0o700);fsync_dir(p.parent)
            candidate=self.path/'candidate';candidate.mkdir(mode=0o700)
            (candidate/'woowbackup').mkdir(mode=0o700);(candidate/'woowbackup/adapters').mkdir(mode=0o700)
            after={}
            for n,b in files.items():
                common.atomic(candidate/n,b)
                after[n]={'sha256':digest(b),'bytes':len(b),'mode':0o755 if n=='helper' else 0o644,
                          'uid':os.geteuid(),'gid':os.getegid(),'mtime_ns':payload['mtime_ns']}
            self.state['candidate_tree']=tree(candidate);self.state['desired']=after
            self.state['sha256']=payload['sha256']
        self.step('stage-candidate',stage)
        self.state['prepared']=True;self.save();self.validate_live()

    def verify_copies(self):
        if not self.state.get('prepared'):raise ValueError('source-incomplete-prior-copy-or-stage')
        for p in (self.path,self.libown,self.helpown):trusted(p,self.trusted_root)
        if (tree(self.path/'prior-library')!=self.state['private_tree'] or
                file_meta(self.path/'prior-helper')!=self.state['private_helper'] or
                tree(self.path/'candidate')!=self.state['candidate_tree']):raise ValueError('source-private-copy-changed')

    def validate_live(self):
        self.verify_copies();now=tree(self.lib);prior=self.state['original'];mut=self.state['mutations']
        if [self.lib.stat().st_dev,self.lib.stat().st_ino]!=self.state['lib_identity']:
            raise ValueError('source-library-replaced')
        names=set(prior['files'])|{n for n in mut if n!='helper'}
        if set(now['files'])-names:raise ValueError('source-foreign-file')
        for n in names:
            m=now['files'].get(n)
            if m!=prior['files'].get(n) and (n not in mut or m!=mut[n]['after']):
                raise ValueError('source-foreign-file-metadata')
        if set(now['directories'])!=set(prior['directories']):raise ValueError('source-foreign-directory')
        affected={str(Path(n).parent) for n in mut if n!='helper'}
        for n,m in prior['directories'].items():
            a=now['directories'][n]
            if any(a[k]!=m[k] for k in ('mode','uid','gid')) or n not in affected and a['mtime_ns']!=m['mtime_ns']:
                raise ValueError('source-foreign-directory-metadata')
        h=file_meta(self.helper)
        if h!=self.state['helper'] and ('helper' not in mut or h!=mut['helper']['after']):
            raise ValueError('source-foreign-helper')

    def replace_file(self,name,data,metadata):
        self.validate_live();live=self.helper if name=='helper' else self.lib/name
        own=self.helpown if name=='helper' else self.libown
        if len(self.state['temporaries'])>=256:raise ValueError('source-temporary-bound')
        key='pending-'+str(len(self.state['temporaries']));temp=own/key
        self.state['temporaries'][key]={'helper':name=='helper','identity':None};self.save()
        def write():
            fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                s=os.fstat(fd);self.state['temporaries'][key]['identity']=[s.st_dev,s.st_ino];self.save()
                with os.fdopen(os.dup(fd),'wb') as out:out.write(data);out.flush()
                os.fchown(fd,metadata['uid'],metadata['gid']);os.fchmod(fd,metadata['mode'])
                os.utime(fd,ns=(os.fstat(fd).st_atime_ns,metadata['mtime_ns']));os.fsync(fd)
            finally:os.close(fd)
        self.step('write-private-samefs-temporary',write)
        if file_meta(temp)!=metadata:raise ValueError('source-temporary-hash')
        self.validate_live()
        if temp.stat().st_dev!=live.parent.stat().st_dev:raise ValueError('source-cross-filesystem')
        self.step('replace-live-file',lambda:os.replace(temp,live));fsync_dir(live.parent)

    def publish(self):
        if self.state.get('publish_started'):raise ValueError('source-never-replay-publish')
        self.validate_live();self.state['publish_started']=True;self.save()
        desired=self.state['desired'];prior=self.state['original']['files']
        stale=sorted(n for n in prior if managed(n) and n not in desired)
        names=sorted(n for n in desired if n not in ('helper','VERSION'))+stale+['VERSION','helper']
        for name in names:
            self.validate_live()
            self.state['mutations'][name]={'before':self.state['helper'] if name=='helper' else prior.get(name),
                                           'after':desired.get(name)}
            self.save()  # durable intent, including prior absence, BEFORE any live write/delete
            if name in desired:self.replace_file(name,common.read_regular(self.path/'candidate'/name,MAX)[0],desired[name])
            else:self.step('delete-only-trusted-stale-python',lambda n=name:(self.lib/n).unlink());fsync_dir((self.lib/name).parent)
        self.validate_live()
        if self.hashes()!=self.state['sha256']:raise ValueError('source-published-hashes')
        self.state['complete']=True;self.save()

    def hashes(self):
        return {n:file_meta(self.helper if n=='helper' else self.lib/n)['sha256'] for n in self.state['sha256']}

    def restore(self):
        self.validate_live()  # validate ALL live and private state before the first return write
        for name,row in reversed(list(self.state['mutations'].items())):
            self.validate_live();live=self.helper if name=='helper' else self.lib/name
            now=file_meta(live) if os.path.lexists(live) else None
            if now==row['before']:continue
            if row['before'] is None:
                self.step('remove-only-owned-added-file',live.unlink);fsync_dir(live.parent)
            else:
                source=self.path/'prior-helper' if name=='helper' else self.path/'prior-library'/name
                self.replace_file(name,common.read_regular(source,MAX)[0],row['before'])
        for n,m in sorted(self.state['original']['directories'].items(),key=lambda r:len(Path(r[0]).parts),reverse=True):
            p=self.lib/n
            if p.stat().st_mtime_ns!=m['mtime_ns']:
                self.step('restore-directory-time',lambda p=p,m=m:os.utime(p,ns=(p.stat().st_atime_ns,m['mtime_ns'])))
                fsync_dir(p)
        if tree(self.lib)!=self.state['original'] or file_meta(self.helper)!=self.state['helper']:
            raise ValueError('source-not-exact-return')
        # Only inode-proven private temporaries may be removed. Unknown partial
        # scratch stays outside live source; it never blocks exact source return.
        for key,row in self.state['temporaries'].items():
            p=(self.helpown if row['helper'] else self.libown)/key
            if os.path.lexists(p):
                s=p.lstat()
                if stat.S_ISREG(s.st_mode) and s.st_nlink==1 and row['identity']==[s.st_dev,s.st_ino]:
                    self.step('remove-owned-private-temporary',p.unlink);fsync_dir(p.parent)
        self.state['restored']=True;self.state['complete']=False;self.save()


@contextmanager
def engine_locks(run=Path('/run/woowtech-backup')):
    fds=[]
    try:
        for name in ('jobs.lock','engine.lock'):
            fd=os.open(Path(run)/name,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(fd);s=os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o600:
                raise ValueError('source-unsafe-lock')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:
        for fd in reversed(fds):os.close(fd)


def probe(lib,cache):
    # -B alone prevents writes but can READ stale pyc. An absent private cache
    # prefix also prevents those reads. Compile helper separately without exec.
    if os.path.lexists(cache):raise ValueError('source-cache-prefix-exists')
    code="""import sys,pathlib
sys.dont_write_bytecode=True
sys.pycache_prefix=sys.argv[2]
sys.path.insert(0,sys.argv[1])
from nacl import bindings
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from woowbackup import cli,ha_litellm
from woowbackup.adapters import quadlet_postgres
for m in (cli,ha_litellm,quadlet_postgres):
 if not pathlib.Path(m.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]).resolve()):raise ValueError('wrong import root')
"""
    before=tree(lib)
    common.call(['python3','-B','-I','-c',code,str(lib),str(cache)],timeout=45)
    if tree(lib)!=before or os.path.lexists(cache):raise ValueError('source-import-wrote-files')


def metadata_listing(root):
    """Archive sidecars are arbitrary regular files; no archive/glob assumption."""
    root=Path(root)
    if not os.path.lexists(root):return None
    result={}
    for p in itertools.chain((root,),root.rglob('*')):
        if len(result)>=8192:raise ValueError('source-protected-listing-bound')
        s=p.lstat()
        if not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)) or s.st_nlink!=1 and not stat.S_ISDIR(s.st_mode):
            raise ValueError('source-protected-listing-type')
        result[str(p.relative_to(root))]=dict(meta(s),bytes=s.st_size,kind='directory' if p.is_dir() else 'file')
    return result


def snapshot():
    value=common.inventory()
    # Full raw inventories stay private. ALL IDs remain strict, including
    # unrelated transient IDs: churn produces an honest failure, never a reset.
    selected={}
    for name in SELECTED:
        matches=[]
        for path in Path(common.QDIR).glob('*.container'):
            section=None;fields={}
            for line in common.read_regular(path)[0].decode().splitlines():
                line=line.strip()
                if line.startswith('[') and line.endswith(']'):section=line[1:-1]
                elif section=='Container' and '=' in line:
                    k,v=line.split('=',1)
                    if k in ('ContainerName','Image'):
                        if k in fields:raise ValueError('source-duplicate-quadlet-binding')
                        fields[k]=v
            if fields.get('ContainerName')==name:matches.append((path,fields))
        if len(matches)!=1 or not matches[0][1].get('Image'):raise ValueError('source-selected-quadlet-binding')
        path,fields=matches[0]
        lines=common.owner('podman','container','inspect','--format',
            '{{.Image}}\n{{.State.Running}}\n{{.Name}}',name).stdout.decode().splitlines()
        declared=common.owner('podman','image','inspect','--format','{{.ID}}',fields['Image']).stdout.decode().strip()
        if len(lines)!=3 or lines[1]!='true' or lines[2].lstrip('/')!=name:
            raise ValueError('source-selected-container-not-running')
        identity=lines[0].removeprefix('sha256:')
        if not re.fullmatch(r'[0-9a-f]{64}',identity) or identity!=declared.removeprefix('sha256:'):
            raise ValueError('source-selected-image-binding')
        selected[name]={'unit':common.unit_state(path.stem+'.service'),'image':identity,'quadlet':str(path)}
    configs={};units={}
    for p in Path(common.CATALOG).parent.glob('*.json'):
        entry=json.loads(common.read_regular(p)[0])
        if entry.get('owner')!='appowner':raise ValueError('source-unexpected-catalog-owner')
        for unit in entry.get('units',[]):
            if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,202}\.service',unit):raise ValueError('source-catalog-unit')
            units[unit]=common.unit_state(unit)
        for row in entry.get('config_files',[]):
            rel=Path(row['path'])
            if rel.is_absolute() or '..' in rel.parts or not rel.parts or rel.parts[0] not in ('.config','.local'):
                raise ValueError('source-untrusted-config-path')
            path=Path(common.APP)/rel
            if any(x.is_symlink() for x in (path,*path.parents)):raise ValueError('source-config-symlink')
            configs[str(path)]=file_meta(path) if os.path.lexists(path) else None
    value['selected']=selected;value['app_config_files']=configs;value['catalog_units']=units
    value['protected_trees']={p:tree(p) if Path(p).exists() else None for p in (
        '/etc/woowtech-cockpit/backup','/usr/local/share/cockpit/woowtechbackup',
        '/usr/local/share/woowtech-cockpit-backup/catalog')}
    value['archives']=metadata_listing('/var/lib/woowtech-backup/archives')
    value['active_job_units']=common.call(['systemctl','list-units','--type=service','--state=activating,active',
        '--plain','--no-legend','woowtech-backup-j*.service']).stdout.decode().splitlines()
    return value


def validate_boundary(value):
    if (value['active_jobs'] or value['active_job_units'] or not set(SELECTED)<=set(value['running'])
            or set(value['selected'])!=set(SELECTED)
            or any(v['unit']['ActiveState']!='active' for v in value['selected'].values())
            or value['timer']['ActiveState']!='inactive'
            or value['timer']['UnitFileState'] not in ('masked','masked-runtime')):
        raise ValueError('source-jobs-timer-or-original-apps')


def resource_floor():
    paths=(common.APP,'/var/lib/woowtech-backup/staging','/var/lib/woowtech-backup',str(LIB.parent),str(HELPER.parent))
    free=min(os.statvfs(p).f_bavail*os.statvfs(p).f_frsize for p in paths)
    rows=Path('/sys/fs/cgroup/memory.stat').read_text().splitlines()
    used=sum(int(r.split()[1]) for r in rows if r.startswith(('anon ','kernel ')))
    headroom=int(Path('/sys/fs/cgroup/memory.max').read_text())-used
    if free<(13*1024**3+512*1024**2) or headroom<1900*1024**2:raise ValueError('source-device-resource-floor')
    return {'free':free,'headroom':headroom}


def dispatch(q):
    if os.geteuid()!=0:raise ValueError('source-root-required')
    with engine_locks():
        resource_floor();before=snapshot();validate_boundary(before)
        if q['phase']=='source-snapshot':return {'ok':True,'baseline':before,'baseline_sha256':digest(canonical(before))}
        if digest(canonical(before))!=q['baseline_sha256']:raise ValueError('source-baseline-pin')
        return transact(Transaction(q['case']),q,before)


def transact(tx,q,before):
    """Filesystem seam; dispatch supplies root identity, both locks and baseline."""
    try:
        if q['phase']=='source-install':
            tx.prepare(q['payload'],q['old_sha256']);tx.state['baseline']=before;tx.save()
            for tool in ('age','age-keygen','zstd'):common.call([tool,'--version'],timeout=10)
            tx.step('probe-private-candidate',lambda:probe(tx.path/'candidate',tx.path/'absent-candidate-cache'))
            tx.publish()
            tx.step('probe-live-candidate',lambda:probe(tx.lib,tx.path/'absent-live-cache'))
        elif q['phase']=='source-recover':
            if before!=tx.state.get('baseline'):raise ValueError('source-recovery-protected-changed')
            tx.restore()
        else:raise ValueError('source-phase')
        after=snapshot();tx.state['after']=after;tx.save()
        if after!=before:raise ValueError('source-protected-state-changed')
        tx.validate_live();resource_floor()
        hashes=(tx.hashes() if tx.state['complete'] else
            {n:file_meta(tx.lib/n)['sha256'] for n in tx.state['original']['files'] if managed(n)}|
            {'helper':file_meta(tx.helper)['sha256']})
        return {'ok':True,'installed':tx.state['complete'],'restored':tx.state['restored'],
                'hashes':hashes,'protected_equal':True,'private_copies_retained':True}
    except BaseException as error:
        if tx.state:
            tx.state['failure']={'stage':tx.state.get('pending'),'class':type(error).__name__,
                                 'errno':error.errno if isinstance(error,OSError) else None};tx.save()
            if q['phase']=='source-install' and tx.state.get('mutations'):
                try:tx.restore();tx.state['automatic_return']=True
                except BaseException as recovery:tx.state['return_error_class']=type(recovery).__name__
                tx.save()
        raise


if __name__=='__main__':
    def cancelled(_signum,_frame):raise InterruptedError('source-cancelled')
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,cancelled)
    try:
        raw=sys.stdin.buffer.read(96*1024**2+1)
        if len(raw)>96*1024**2:raise ValueError('source-request-bound')
        print(json.dumps(dispatch(json.loads(raw))))
    except BaseException as error:
        print(json.dumps({'ok':False,'private_error_class':type(error).__name__,
                          'private_errno':error.errno if isinstance(error,OSError) else None}))
        raise SystemExit(1)
