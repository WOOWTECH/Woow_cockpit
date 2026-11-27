"""Preserve TWO preexisting safety pairs; never adopt ownership or prune them.

Existing Store/read_regular/atomic primitives, one private sibling case root.
Return only missing managed files, exclusively, after successful own-job prune
proof and original-data/cold return. No retention/config/index editing.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

PARENT = '/var/lib/woowtech-backup/focus-n8n-preserved-safety'
ARCHIVES = '/var/lib/woowtech-backup/archives'
KNOWN = {
    '20261124T152230Z-5f41c20c': {
        'index_sha256':'1f09e9894b14283c325d29da0faf422515f50ac3b51019ad50bb518612603ae9',
        'apps':['odoo','n8n'], 'bytes':12103680, 'mtime_ns':1795533865849123502,
        'index_mtime_ns':1795533867143150283},
    '20261124T153132Z-ee42afe1': {
        'index_sha256':'2641a0157c7e872323956dddea39c957373207b14ccd2d4bd837beeecfc0d122',
        'apps':['n8n'], 'bytes':1372160, 'mtime_ns':1795534383692512014,
        'index_mtime_ns':1795534383830514720},
}
JOB = re.compile(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
JOBS = Path('/var/lib/woowtech-backup/jobs')
# Actual SAFETY2 readonly inventory:124 files/566,460,445bytes, max12,564,480.
# This is a READ budget, not additional disk allocation or a data-floor waiver.
INVENTORY_BYTES = 1024**3
FILE_BYTES = 64*1024**2


@contextmanager
def native_locks():
    fds=[]
    try:
        for name in ('jobs.lock','engine.lock'):
            fd=os.open('/run/woowtech-backup/'+name,os.O_RDWR|os.O_NOFOLLOW);fds.append(fd);st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600:
                raise ValueError('untrusted native lock')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:
        for fd in reversed(fds):os.close(fd)


class PreservedSafeties:
    def __init__(self, common, name, *, parent=PARENT, archives=ARCHIVES, known=KNOWN):
        self.c=common; self.name=name; self.parent=Path(parent); self.archives=Path(archives); self.known=known
        self.store=common.Store(name,parent=parent)

    def current(self):
        """All preexisting managed archive/index bytes+attrs; no hidden originals."""
        parent=self.archives.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.geteuid() or parent.st_mode&0o022:
            raise ValueError('untrusted managed archive directory')
        out={}; total=0
        for p in sorted(self.archives.iterdir()):
            if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.(?:tar|woowbackup|json)',p.name): continue
            fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
            try:
                before=os.fstat(fd); total+=before.st_size
                if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>FILE_BYTES:
                    raise ValueError('unsafe or unbounded case file')
                if total>INVENTORY_BYTES or len(out)>=1024: raise ValueError('preserved inventory bound')
                h=hashlib.sha256(); count=0
                while chunk:=os.read(fd,1024**2):
                    count+=len(chunk)
                    if count>before.st_size: raise ValueError('preserved file changed during read')
                    h.update(chunk)
                def signature(s):
                    return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,
                            s.st_size,s.st_mtime_ns,s.st_ctime_ns)
                if count!=before.st_size or signature(before)!=signature(os.fstat(fd)) or signature(before)!=signature(p.lstat()):
                    raise ValueError('preserved file changed during read')
                out[str(p)]={'sha256':h.hexdigest(),'mode':stat.S_IMODE(before.st_mode),
                    'uid':before.st_uid,'gid':before.st_gid,'mtime_ns':before.st_mtime_ns,'bytes':count}
            finally: os.close(fd)
        return out

    def verify(self, *, originals=True):
        state=self.store.state
        if not state.get('complete'): raise ValueError('preserved copy incomplete')
        for path,meta in state['original'].items():
            _,copy=self.c.read_regular(self.store.path/meta['copy'],16*1024**2)
            if copy!={k:v for k,v in meta.items() if k!='copy'}: raise ValueError('preserved copy changed')
        if originals:
            now=self.current()
            if any(now.get(p)!=m for p,m in state['before'].items()): raise ValueError('preexisting archive changed')

    def prepare(self):
        if self.store.path.exists():
            self.verify(); return self.summary()
        before=self.current(); paths=[]
        for bid,expected in self.known.items():
            arc=self.archives/(bid+'.tar'); idx=self.archives/(bid+'.json')
            if (self.archives/(bid+'.woowbackup')).exists(): raise ValueError('ambiguous preserved archive')
            data,meta=self.c.read_regular(idx); record=json.loads(data)
            if (meta['sha256']!=expected['index_sha256'] or meta['mtime_ns']!=expected['index_mtime_ns'] or
                    record.get('type')!='safety' or sorted(a['id'] for a in record.get('apps',[]))!=sorted(expected['apps'])):
                raise ValueError('preserved index binding changed')
            a=before[str(arc)]
            if (a['bytes']!=expected['bytes'] or a['mtime_ns']!=expected['mtime_ns'] or
                    a['sha256']!=record.get('sha256') or any(m['mode']!=0o600 or m['uid']!=os.geteuid() or
                    m['gid']!=os.getegid() for m in (a,meta))): raise ValueError('preserved archive binding changed')
            paths.extend((str(arc),str(idx)))
        self.store=self.c.Store(self.name,parent=self.parent,create=True)
        self.store.capture(paths,limit=16*1024**2,copy_mtime=True)
        self.store.state.update(before=before,complete=True,return_intents={},returned=False); self.store.save()
        self.verify(); return self.summary()

    def summary(self):
        return {'protected_old_ids':sorted(self.known),'private_files':len(self.store.state['original']),
            'private_copy_verified':True,'preexisting_managed_files':len(self.store.state['before']),
            'files_sha256':{Path(p).name:m['sha256'] for p,m in self.store.state['original'].items()}}

    def put_back(self, witnesses, *, original_returned):
        self.verify(originals=False); state=self.store.state; now=self.current(); missing=[]
        # Validate EVERY preexisting path/private copy before ANY return write.
        protected={str(self.archives/(bid+suffix)) for bid in self.known for suffix in ('.tar','.json')}
        for p,meta in state['before'].items():
            if p not in protected and now.get(p)!=meta: raise ValueError('unrelated preexisting archive changed')
            if p in now and now[p]!=meta: raise ValueError('foreign preserved path retained')
        for bid in self.known:
            pair=[str(self.archives/(bid+s)) for s in ('.tar','.json')]
            absent=[p for p in pair if p not in now]
            if not absent: continue
            old=state['return_intents'].get(bid)
            if len(absent)!=2 and not old: raise ValueError('unproven partial archive loss')
            if not original_returned or bid not in witnesses: raise ValueError('successful case prune proof required')
            state['return_intents'][bid]={'both_absent_observed':True,'witness':witnesses[bid]}
            missing.extend(absent)
        self.store.save()  # exact pair absence+witness durable before O_EXCL
        for p in missing:
            meta=state['original'][p]; data,copy=self.c.read_regular(self.store.path/meta['copy'],16*1024**2)
            if copy!={k:v for k,v in meta.items() if k!='copy'}: raise ValueError('preserved copy changed before return')
            fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            st=os.fstat(fd);state['return_intents'].setdefault('created_inodes',{})[p]=[st.st_dev,st.st_ino];self.store.save()
            with os.fdopen(fd,'wb') as out:
                out.write(data);out.flush();os.fchmod(out.fileno(),meta['mode']);os.fchown(out.fileno(),meta['uid'],meta['gid'])
                os.utime(out.fileno(),ns=(os.fstat(out.fileno()).st_atime_ns,meta['mtime_ns']));os.fsync(out.fileno())
            dfd=os.open(self.archives,os.O_DIRECTORY)
            try: os.fsync(dfd)
            finally: os.close(dfd)
        self.verify();state['returned']=True;self.store.save()
        return dict(self.summary(),restored_files=len(missing),all_preexisting_files_exact=True,
                    pruning_proofs={bid:state['return_intents'][bid]['witness'] for bid in self.known if bid in state['return_intents']})


def pruning_witnesses(c,name,jobs,full_safety):
    witnesses={}; initial_return=False
    if len(jobs)>16: raise ValueError('owned job bound')
    for jid in jobs:
        if not JOB.fullmatch(jid): raise ValueError('owned job id')
        raw,jmeta=c.read_regular(JOBS/(jid+'.json'))
        j=json.loads(raw); result=j.get('result') or {}; params=j.get('params') or {}
        if not str(j.get('request_id') or '').startswith(name+'-'): raise ValueError('foreign job')
        if j.get('state') in ('queued','running'): raise ValueError('owned job active')
        unit=j.get('unit')
        if unit!='woowtech-backup-'+jid+'.service': raise ValueError('owned unit')
        p=c.call(['systemctl','show',unit,'-P','ActiveState'],check=False)
        if p.stdout.strip() not in (b'inactive',b'failed'): raise ValueError('owned unit not quiescent')
        if j.get('state')!='succeeded' or j.get('type')!='restore': continue
        if (params.get('backup_id')==full_safety and j.get('request_id')==name+'-recover' and
                result.get('rolled_back') is False and result.get('health') and
                all(x.get('status')=='ok' for x in result['health'])): initial_return=True
        log,lmeta=c.read_regular(JOBS/(jid+'.log'),8*1024**2)
        for bid in KNOWN:
            event='已刪除較舊的還原前備份 '+bid
            lines=[line for line in log.decode('utf-8').splitlines() if re.fullmatch(r'[0-9TZ:_.+-]+ '+re.escape(event),line)]
            if lines: witnesses[bid]={'job_id':jid,'job_sha256':jmeta['sha256'],'log_sha256':lmeta['sha256'],
                'event_sha256':c.digest(lines[-1].encode()),'state':'succeeded','type':'restore'}
    return witnesses,initial_return


def operate(q,c):
    try:
        with native_locks(): return _operate_locked(q,c)
    except Exception as error:
        # No foreign exception text. Persist fixed operation/class/errno before
        # the controller can enter its data-recovery finally block.
        try:
            s=c.Store(q['case'],parent=PARENT)
            if s.path.exists():
                s.state['failure']={'operation':q['op'],'error_class':type(error).__name__,
                    'errno':error.errno if isinstance(error,OSError) else None};s.save()
        except Exception: pass
        raise


def _operate_locked(q,c):
    inv=c.inventory()
    if inv['active_jobs']: raise ValueError('preserved safety operation requires no active jobs')
    obj=PreservedSafeties(c,q['case'])
    if q['op']=='preserved_safety_copies': obj.verify(originals=False); return obj.summary()
    if inv['running'] or any(inv['units'][u]['ActiveState']!='inactive' for u in c.UNITS):
        raise ValueError('preserved safety operation requires quiescence')
    if q['op']=='preserved_safety_prepare':
        result=obj.prepare()
        if 'original_inventory' not in obj.store.state:
            obj.store.state['original_inventory']=inv;obj.store.save()
        return result
    if q['op']=='preserved_safety_check': obj.verify(); return obj.summary()
    if q['op']=='preserved_safety_return':
        keys=('catalog','files','protected','units','timer','volumes','images','running','active_jobs','retention_sha256')
        if any(inv[k]!=obj.store.state['original_inventory'][k] for k in keys):
            raise ValueError('original catalog cold state not returned')
        witness,returned=pruning_witnesses(c,q['case'],q['jobs'],q.get('full_safety'))
        return obj.put_back(witness,original_returned=returned and q.get('baseline_restored') is True)
    raise ValueError('preserved safety operation')
