#!/usr/bin/env python3
"""Leased original n8n instance controller; default is offline, never device access.

Separate phases: images, images-recover, safety, flow, recover. No phase is
dispatched without --execute and an unexpired exact coordinator lease. Images
never starts services or opens a DB; safety captures a fresh full instance then
returns catalog/services/timer. Flow always recovers through that full copy.
"""
import argparse
import base64
from datetime import datetime, timezone
import fcntl
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0,str(HERE))
import focus_n8n_instance_acceptance as plan
import focus_n8n_instance_acceptance_ops as ops

PHASES = ('images','images-recover','safety','flow','recover')
JOB = re.compile(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
BACKUP = re.compile(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
FROZEN_PRODUCT = 'd09f4fe8e06305aff6a1150f41d6de719e7b7f6a'
IMAGE_ARCHIVES = {config:{'compressed_sha256':sha,'compressed_bytes':size}
                  for config,(sha,size) in plan.ARCHIVES.items()}
BOUNDS = {'host_available_mib':1200,'host_reserve_gib':13,'host_write_budget_gib':8,
          'device_headroom_mib':1900,'recovery_reserve_seconds':600,
          'load_timeout_seconds':300,'kill_after_seconds':30,'load_wait_seconds':350}

API_PAUSE = r'''
import http.cookiejar,json,sys,urllib.request,re
q=json.load(sys.stdin);jar=http.cookiejar.CookieJar()
client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
def call(method,path,body=None):
 r=urllib.request.Request('http://127.0.0.1:15678/rest/'+path,method=method,
  data=None if body is None else json.dumps(body).encode(),
  headers={'Content-Type':'application/json','browser-id':'woow-focus-instance'})
 with client.open(r,timeout=20) as f:
  b=f.read(4*1024*1024+1);assert f.status==200 and len(b)<=4*1024*1024
  return json.loads(b)
call('POST','login',{'emailOrLdapLoginId':q['email'],'password':q['password']})
rows=call('GET','workflows')['data']; selected=[w for w in rows if w.get('name')=='WOOW 匯入測試 - 排程']
assert len(selected)==1
wid=selected[0]['id'];assert re.fullmatch(r'[A-Za-z0-9_-]{1,128}',wid)
wf=call('GET','workflows/'+wid)['data']
body={'expectedChecksum':wf['checksum']} if isinstance(wf.get('checksum'),str) else {}
value=call('POST','workflows/'+wid+'/deactivate',body)['data']
print(json.dumps(value.get('active') is False))
'''


def git(path, *args):
    return subprocess.check_output(['git','-C',str(path),*args],text=True,timeout=30).strip()


def validate_lease(lease, phase, *, now, driver_commit, source_commit):
    if (lease.get('granted') is not True or lease.get('device') != plan.DEVICE
            or lease.get('case') != 'n8n-instance-original' or phase not in lease.get('phases',[])
            or lease.get('driver_commit') != driver_commit
            or lease.get('source_commit') != source_commit
            or lease.get('catalog_sha256') != plan.FOUND_SHA
            or not ops.BASE.fullmatch(lease.get('name',''))):
        raise ValueError('coordinator lease does not authorize this phase/source')
    if phase not in ('images','images-recover') and source_commit!=FROZEN_PRODUCT:
        raise ValueError('coordinator product source mismatch')
    if phase in ('images','images-recover') and (lease.get('image_archives') != IMAGE_ARCHIVES
                                                or lease.get('bounds') != BOUNDS):
        raise ValueError('reviewed image archive/bounds binding mismatch')
    expires = datetime.fromisoformat(lease['expires_utc']).timestamp()
    if expires <= now or expires-now > 40*60:
        raise ValueError('lease expired or exceeds bounded window')
    if lease.get('image_policy') not in ('retain-for-case','remove-own-after-case'):
        raise ValueError('explicit image recovery policy required')
    return expires


def save_receipt(path, value):
    path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if path.is_symlink():raise ValueError('unsafe receipt')
    temp=path.with_name(path.name+'.new')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(value,f,ensure_ascii=False);f.flush();os.fsync(f.fileno())
        os.replace(temp,path)
        dfd=os.open(path.parent,os.O_DIRECTORY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    finally:
        temp.unlink(missing_ok=True)


def same_found(current, original, *, images=False):
    """Durable state, not transient container IDs. No untracked field omission."""
    keys=('catalog','files','protected','units','timer','volumes','running','retention_sha256')
    return (all(current.get(k)==original.get(k) for k in keys)
            and not current.get('active_jobs') and (not images or current['images']==original['images']))


def successful_restore(job):
    result=job.get('result') or {}
    health=result.get('health') or []
    checks=[c for v in result.get('verification',[]) for c in v.get('checks',[])]
    return (job.get('state')=='succeeded' and result.get('rolled_back') is False
            and bool(result.get('safety_backup_id')) and health and all(x.get('status')=='ok' for x in health)
            and all(x.get('match') is True for x in checks))


def recording_api_program(program, path):
    """Keep EVERY cookie issuance, including overwritten values and exceptions."""
    if program.count('http.cookiejar.CookieJar()') != 1: raise ValueError('fixed API cookie constructor')
    program = program.replace('http.cookiejar.CookieJar()', 'RecordedJar()')
    # Reuse our bounded reader and durable private writer; their module main is
    # disabled. API code is a fixed driver constant, never an archive program.
    prefix = "__name__='fixed_api_cookie_recording'\n"+(HERE/'focus_n8n_instance_acceptance_ops.py').read_text()
    body = '''
import http.cookiejar
issued=set()
class RecordedJar(http.cookiejar.CookieJar):
 def set_cookie(self,cookie,*args,**kwargs):
  issued.add(cookie.value)
  return super().set_cookie(cookie,*args,**kwargs)
try:
 exec(compile(PROGRAM,'<fixed vendor API probe>','exec'))
finally:
 p=Path(COOKIE_PATH); parent=p.parent.lstat()
 if p.parent.is_symlink() or parent.st_uid!=os.geteuid() or stat.S_IMODE(parent.st_mode)!=0o700:
  raise RuntimeError('fixed cookie directory unsafe')
 old=[]
 if os.path.lexists(p):
  raw,meta=read_regular(p)
  if meta['uid']!=os.geteuid() or meta['mode']!=0o600:raise RuntimeError('fixed cookie file unsafe')
  old=json.loads(raw)
 if not isinstance(old,list):raise RuntimeError('fixed cookie journal invalid')
 values=sorted(set(old)|issued)
 if len(values)>100 or not all(isinstance(v,str) and v and len(v)<=16384 for v in values):
  raise RuntimeError('fixed cookie journal bound')
 atomic(p,json.dumps(values).encode())
'''.replace('PROGRAM', repr(program)).replace('COOKIE_PATH', repr(str(path)))
    return prefix+'\n'+body


def scan_input_prefix(path, since, attempted, ops_source):
    body = '''
import io
values=json.load(sys.stdin); p=Path(COOKIE_PATH)
if ATTEMPTED:
 raw,meta=read_regular(p)
 if meta['uid']!=os.geteuid() or meta['mode']!=0o600:raise RuntimeError('fixed cookie file unsafe')
 issued=json.loads(raw)
else:
 if os.path.lexists(p):raise RuntimeError('fixed cookie file without intent')
 issued=[]
sys.stdin=io.StringIO(json.dumps({'values':values+issued,'since':SINCE}))
__name__='__main__'
'''.replace('COOKIE_PATH', repr(str(path))).replace('ATTEMPTED', repr(bool(attempted))).replace('SINCE', repr(since))
    return "__name__='fixed_scan_input'\n"+ops_source+'\n'+body


class Controller:
    def __init__(self,args,lease,transport,*,clock=time.time,sleep=time.sleep):
        self.args=args;self.lease=lease;self.h=transport;self.clock=clock;self.sleep=sleep
        self.name=lease['name'];self.deadline=datetime.fromisoformat(lease['expires_utc']).timestamp()
        self.source=Path(args.source).resolve();self.path=Path(args.receipt)
        if self.path.is_symlink():raise ValueError('unsafe existing receipt')
        if self.path.exists():
            raw,meta=ops.read_regular(self.path)
            if meta['uid']!=os.geteuid() or meta['mode']!=0o600:raise ValueError('receipt must be private and owned')
            previous=json.loads(raw)
        else:previous=None
        self.r=previous if previous is not None else {
            'name':self.name,'device':plan.DEVICE,'version':1,'created_backups':[],
            'jobs':{},'pending':None,'owned_images':[],'image_intents':[],
            'full_safety':None,'safety_verified':False,'fixture_intent':False,
            'hook_intent':False,'timer_intent':False,'catalog_intent':False,
            'recovery_verified':False,'complete':False,'started':int(clock())}
        if self.r['name']!=self.name or self.r.get('device')!=plan.DEVICE:
            raise ValueError('receipt belongs to another case')
        self.results=[];self.recovering=False
        # Fixed small preservation helper, loaded from memory, never deployed.
        protected=(HERE/'focus_n8n_instance_acceptance_safeties.py').read_text()
        prelude=("import sys,types\n_m=types.ModuleType('focus_n8n_instance_acceptance_safeties');"
                 "sys.modules[_m.__name__]=_m\nexec(compile("+repr(protected)+",'<fixed safety preservation>','exec'),_m.__dict__)\n")
        self.ops_source=prelude+(HERE/'focus_n8n_instance_acceptance_ops.py').read_text()
        self.secrets=None

    def save(self):save_receipt(self.path,self.r)

    def require(self,label,condition):
        self.results.append({'check':label,'ok':bool(condition)})
        print(json.dumps({'stage':label,'ok':bool(condition)}),flush=True)
        if not condition:raise RuntimeError(label)

    def budget(self,*,reserve=0):
        if self.clock()+reserve>=self.deadline:raise TimeoutError('lease recovery reserve reached')

    def root_json(self,script,request=None,*,timeout=180):
        prelude="import sys;sys.dont_write_bytecode=True;sys.pycache_prefix='/nonexistent/woowbk-focus-n8n-pycache'\n"
        p=self.h.root('python3','-B','-I','-c',prelude+script,input=json.dumps(request or {}).encode(),timeout=timeout)
        if p.returncode:
            self.r['device_exit_code']=p.returncode
            try:
                error=json.loads(p.stderr)
                if set(error)=={'error_class'} and re.fullmatch(r'[A-Za-z]{1,40}',error['error_class']):
                    self.r['device_error_class']=error['error_class']
            except (ValueError,TypeError,KeyError):pass
            self.save()
            raise RuntimeError('fixed device operation failed; raw output withheld')
        return json.loads(p.stdout)

    def op(self,operation,**kwargs):
        self.r['last_operation']=operation;self.save()
        return self.root_json(self.ops_source,dict(kwargs,op=operation,case=self.name))

    def command(self,*argv,root=False,timeout=180):
        p=(self.h.root if root else self.h.owner)(*argv,timeout=timeout)
        if p.returncode:raise RuntimeError('fixed service/image command failed; raw output withheld')
        return p.stdout

    def helper(self,command,request=None):
        rc,result=self.h.helper(command,request,timeout=180)
        if rc or result.get('ok') is not True:raise RuntimeError('fixed helper request refused: '+command)
        return result

    def resources(self):
        self.budget(reserve=0 if self.recovering else 600)
        available=next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines()
                       if x.startswith('MemAvailable:'))
        s=os.statvfs(REPO)
        self.require('host_memory',available>=1200*1024)
        self.require('host_disk_reserve',s.f_bavail*s.f_frsize>=(13+8)*1024**3)
        memory=self.root_json("from pathlib import Path;import json;s=Path('/sys/fs/cgroup/memory.stat').read_text().splitlines();used=sum(int(x.split()[1]) for x in s if x.startswith(('anon ','kernel ')));print(json.dumps(int(Path('/sys/fs/cgroup/memory.max').read_text())-used))")
        self.require('device_memory',memory>=1900*1024**2)

    def acquire_original(self):
        before=self.op('inventory')
        self.require('original_catalog_pin',before['catalog'].get('n8n.json')==plan.FOUND_SHA)
        self.require('reviewed_protected_baselines',before['protected']==plan.reviewed_baselines())
        self.require('original_services_stopped',not before['running'] and all(
            before['units'][u]['ActiveState']=='inactive' for u in ops.UNITS))
        self.require('no_active_jobs',not before['active_jobs'])
        if 'before' not in self.r:
            self.r['before']=before;self.r['init_intent']=True;self.save()
            captured=self.op('init')
            self.require('original_capture_stable',same_found(captured,before,images=True))
            self.r['init_complete']=True;self.save()
        else:
            self.require('original_files_still_match',same_found(before,self.r['before']))
        return before

    def frozen_engine(self):
        expected={str(p.relative_to(self.source/'backup-engine/woowbackup')):plan.sha(p)
                  for p in (self.source/'backup-engine/woowbackup').rglob('*.py') if '__pycache__' not in p.parts}
        expected['../woowtech-cockpit-backup']=plan.sha(self.source/'backup-engine/woowtech-cockpit-backup')
        self.require('installed_engine_source',self.op('hashes')==expected)
        self.r['engine_hashes']=expected;self.r['source_commit']=self.lease['source_commit'];self.save()

    def start_units(self,units):
        # Every initially stopped service is recorded before its potentially partial start.
        self.op('dependencies')  # loaded Requires/Wants/BindsTo, including override-introduced app dependencies
        self.r['service_intents']=list(ops.UNITS);self.save()  # includes main's Wants/Requires app dependencies
        for unit in units:
            if unit not in ops.UNITS:raise ValueError('foreign service')
            self.r.setdefault('service_intents',[]).append(unit);self.save()
            self.command('systemctl','--user','start',unit,timeout=600)

    def stop_units(self):
        self.command('systemctl','--user','stop',*reversed(ops.UNITS),timeout=300)

    def pause_timer(self):
        self.r['timer_intent']=True;self.save()
        self.command('systemctl','mask','--runtime','--now',plan.TIMER,root=True)

    def restore_timer(self):
        if not self.r.get('timer_intent'):return
        found=self.r['before']['timer']
        self.command('systemctl','unmask','--runtime',plan.TIMER,root=True)
        if found['ActiveState']=='active':self.command('systemctl','start',plan.TIMER,root=True)
        elif found['ActiveState']=='inactive':self.command('systemctl','stop',plan.TIMER,root=True)
        else:raise ValueError('unsupported original timer state')
        self.r['timer_intent']=False;self.save()

    def scope_instance(self):
        before=self.r['before'];target=plan.instance_entry(before['entry'])
        preview=self.helper('catalog-install',{'entry':target})
        self.require('catalog_preview_cas',preview.get('valid') is True and
                     preview.get('expected_sha256')==plan.FOUND_SHA)
        encoded=self.op('catalog_bytes',entry=target)
        self.require('catalog_new_bytes_pin',encoded['sha256']==preview.get('new_sha256'))
        self.op('authorize_catalog',bytes=encoded['bytes'])
        self.r['catalog_intent']=True;self.save()
        self.helper('catalog-install',{'entry':target,'confirm':True,'expected_sha256':plan.FOUND_SHA})
        self.require('catalog_only_scope',self.op('inventory')['entry']==target)

    def restore_catalog(self):
        if self.r.get('catalog_intent'):
            self.op('restore_catalog');self.r['catalog_intent']=False;self.save()

    def wait_job(self,jid):
        if not JOB.fullmatch(jid):raise ValueError('invalid job ID')
        deadline=min(self.deadline,self.clock()+600)
        while self.clock()<deadline:
            reply=self.helper('job-status',{'job_id':jid});job=reply['job']
            if job.get('state') not in ('queued','running'):
                if not self.op('job_quiescent',job_id=jid):
                    self.sleep(1);continue
                self.r['jobs'][jid]={'state':job.get('state'),'type':job.get('type')}
                for key in ('backup_id','safety_backup_id'):
                    bid=(job.get('result') or {}).get(key)
                    if bid:
                        if not BACKUP.fullmatch(bid) or bid in self.r.get('before_backups',[]):
                            raise ValueError('backup ownership cannot be established')
                        if bid not in self.r['created_backups']:self.r['created_backups'].append(bid)
                self.save();return job
            self.sleep(2)
        raise TimeoutError('owned job still active; retain receipt and all copies')

    def settle(self):
        pending=self.r.get('pending')
        if not pending:return None
        # A missing reply is reconciled against the engine's own dedup journal.
        jid=pending.get('job_id') or self.op('intent',request_id=pending['request_id'])
        if not jid:
            raise RuntimeError('uncertain start not in journal; retain state for explicit reconciliation')
        self.r['pending']['job_id']=jid;self.save()
        job=self.wait_job(jid)
        if pending['tag']=='full-safety' and job.get('state')=='succeeded':
            self.r['full_safety']=job['result']['backup_id']
        self.r['last_job_id']=jid;self.r['pending']=None;self.save()
        return job

    def job(self,command,request,tag):
        if self.r.get('pending'):raise RuntimeError('previous job unresolved')
        self.budget(reserve=0 if self.recovering else 600)
        if command=='restore-start':self.op('preserved_safety_copies')
        request=dict(request,request_id=self.name+'-'+tag)
        self.r['pending']={'command':command,'request_id':request['request_id'],'tag':tag}
        self.save()  # never store request keys/passwords in the receipt
        response=self.helper(command,request)
        self.r['pending']['job_id']=response['job_id'];self.save()
        return self.settle()

    def archive_probe(self,bid):
        return self.root_json(plan.MANIFEST_PROBE,{'backup_id':bid})

    def images(self):
        self.resources();before=self.acquire_original()
        self.r['verified_image_archives']=plan.verify_cache()
        self.save()  # compressed byte/length proof before the first load intent
        for ref,config in plan.IMAGE_IDS.items():
            if config in plan.ARCHIVES:
                self.require('image_initially_absent',config not in before['images'])
            else:self.require('existing_pg_queue_pin',config in before['images'])
        for config in plan.ARCHIVES:
            self.resources()
            archive=plan.LAB/'evidence/parity-space-20261126/dev-c-images'/(config+'.tar.gz')
            self.r['image_intents'].append(config);self.save()
            # gzip stays on the host; only labpodman exec loads INSIDE dev-c.
            producer=subprocess.Popen(['gzip','-dc','--',str(archive)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            consumer=None
            try:
                consumer=subprocess.Popen([self.h.LP,'exec','-i',plan.DEVICE,'timeout','--kill-after=30','300',
                                            ops.OWNER,'podman','load'],stdin=producer.stdout,
                                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                producer.stdout.close()
                rc=consumer.wait(timeout=350);prc=producer.wait(timeout=30)
                self.require('exact_image_load',rc==0 and prc==0)
            finally:
                for child in (consumer,producer):
                    if child is not None and child.poll() is None:
                        child.terminate()
                        try:child.wait(timeout=5)
                        except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
            actual=self.command('podman','image','inspect','sha256:'+config,'--format','{{.ID}}').decode().strip().removeprefix('sha256:')
            self.require('loaded_image_config_pin',actual==config)
            self.r['owned_images'].append(config);self.save()
        after=self.op('inventory')
        self.require('image_phase_no_app_changes',same_found(after,before))
        self.require('image_phase_only_owned_ids',set(after['images'])-set(before['images'])==set(self.r['owned_images']))
        self.r['images_ready']=True;self.save()

    def images_recover(self):
        self.settle()
        before=self.r['before'];now=self.op('inventory')
        self.require('image_recovery_no_app_changes',same_found(now,before))
        # A partial load is owned only if initial absence AND prior exact intent prove it.
        owned=set(self.r['image_intents'])-set(before['images'])
        extra=set(now['images'])-set(before['images'])
        self.require('no_unknown_loaded_image',extra<=owned)
        for config in sorted(extra):
            self.command('podman','image','rm','--no-prune','sha256:'+config)
        self.require('image_baseline_returned',same_found(self.op('inventory'),before,images=True))
        self.r['images_ready']=False;self.r['images_recovered']=True;self.save()

    def safety(self):
        self.resources();self.acquire_original();self.frozen_engine()
        self.require('no_previous_safety',not self.r['full_safety'])
        self.require('all_exact_images',set(plan.IMAGE_IDS.values())<=set(self.op('inventory')['images']))
        self.require_image_references()
        protected=self.op('preserved_safety_prepare')
        self.r['preserved_old_safeties']=protected;self.save()
        self.require('old_pairs_private_copy_verified',protected.get('private_copy_verified') is True and protected.get('private_files')==4)
        listing=self.helper('list');self.r['before_backups']=[x['id'] for x in listing['backups']]
        self.r['before_uploads']=[x['id'] for x in listing.get('ha_backups',[])];self.save()
        self.require('no_manual_retention_deletion',self.r['before']['retention_keep'] is None)
        old={x['id'] for x in listing['backups'] if x.get('type')=='safety' and
             any(a.get('id')=='n8n' for a in x.get('apps',[]))}
        self.require('only_exact_preserved_old_safeties',old==set(protected['protected_old_ids']))
        try:
            self.pause_timer();self.scope_instance();self.start_units(['n8n-postgres.service'])
            self.pg_ready();self.r['original_db']=self.op('snapshot',tag='original')
            self.require('known_original_baseline_marker',self.sql('n8n',ops.MARKER_SQL) is True)
            self.r['original_secrets']=self.op('secrets');self.save()
            job=self.job('backup-start',{'apps':['n8n'],'encrypt':True,'include_images':False,
                         'note':'original n8n instance case full safety'},'full-safety')
            self.require('fresh_full_safety_job',job.get('state')=='succeeded')
            bid=job['result']['backup_id'];self.r['full_safety']=bid;self.save()
            p=self.archive_probe(bid)
            self.require('full_safety_complete_unmarked',p['scope']=='instance' and p['ha_database'] is None
                         and p['globals_present'] and p['roles_count']>0 and
                         {x[0] for x in p['databases']}==set(self.r['original_db']['database_names']))
            inspected=self.helper('inspect',{'backup_id':bid})
            self.require('fresh_safety_encrypted',inspected['backup'].get('encrypted') is True)
            self.r['safety_verified']=True;self.save()
        finally:
            # Never race uncertain helper startup/active jobs. A failure retains copies.
            self.settle();self.stop_units();self.restore_catalog();self.restore_timer()
            self.require('safety_stage_returns_original_services',same_found(self.op('inventory'),self.r['before']))
            self.op('preserved_safety_check')

    def require_image_references(self):
        for ref,config in plan.IMAGE_IDS.items():
            self.r['last_image_reference']=ref;self.save()
            p=self.h.owner('podman','image','inspect',ref,'--format','{{.ID}}',timeout=30)
            self.require('catalog_image_reference_pin',p.returncode==0 and
                p.stdout.decode().strip().removeprefix('sha256:')==config)

    def sql(self,database,query,*,json_result=True):
        if database not in ('n8n','postgres',self.name,self.name+'_outside'):
            raise ValueError('SQL outside reviewed instance case')
        p=self.h.owner('podman','exec','-i','n8n-postgres','psql','-X','-w','-Atq','-v','ON_ERROR_STOP=1',
                       '-U','n8n','-d',database,'-f','-',input=query.encode(),timeout=180)
        if p.returncode:raise RuntimeError('fixed fixture SQL failed; raw output withheld')
        return json.loads(p.stdout) if json_result else None

    def pg_ready(self):
        end=min(self.deadline,self.clock()+90)
        while self.clock()<end:
            p=self.h.owner('podman','exec','n8n-postgres','pg_isready','-U','n8n','-d','postgres',timeout=10)
            if p.returncode==0:return
            self.sleep(1)
        raise TimeoutError('PG readiness')

    def endpoint(self):
        found=self.root_json(plan.ENDPOINT_PROBE)
        self.require('live_endpoint_main_local',found.get('main')=='n8n' and found.get('database')==self.name
                     and found.get('user')=='n8n' and found.get('port')==5432 and found.get('local') is True)
        return found

    def app_ready(self):
        end=min(self.deadline,self.clock()+180)
        while self.clock()<end:
            if (self.h.http_code('http://127.0.0.1:15678/healthz/readiness')=='200'
                    and self.h.http_code('http://127.0.0.1:15679/healthz')=='200'):return
            self.sleep(2)
        raise TimeoutError('real n8n health')

    def credentials(self):
        if self.secrets is None:
            self.secrets=self.h.Secrets(plan.LAB/'secrets/ha-import-creds.env',
                                       plan.LAB/'secrets/ha-import-n8n-testdata.sh')
        return self.secrets

    def private_api(self,program):
        self.r['cookie_intent']=True;self.r['cookie_probes']=self.r.get('cookie_probes',0)+1;self.save()
        # Issued cookies stay in the root0700 recovery directory, and join the
        # existing encoded-needle scan before any case copies can be deleted.
        path='/var/lib/woowtech-backup/focus-n8n-instance/'+self.name+'/issued.json'
        s=self.credentials()
        result=self.root_json(recording_api_program(program,path),{'email':self.h.OWNER_EMAIL,'password':s['N8N_OWNER_PW']})
        self.r['cookie_intent']=False;self.save()
        return result

    def api(self):
        s=self.credentials()
        found=self.private_api(plan.API_ACTION_PROBE)
        self.require('real_owner_api_credential_action',found=={'login':True,'credential_visible':True,'manual_action':True})
        target='/tmp/'+self.name+'-creds.json'
        self.command('podman','exec','n8n','test','!','-e',target)
        decrypted=self.root_json(self.h.CREDENTIAL_PROBE.replace('/tmp/woowbk-creds.json',target),
                                {'name':self.h.CREDENTIAL,'value':s['N8N_CREDENTIAL_VALUE']},timeout=400)
        self.require('real_vendor_credential_decryption',decrypted.get('found') is True and decrypted.get('match') is True)
        self.require('three_ha_workflows_in_selected_db',self.sql(self.name,'SELECT to_json(count(*)=3) FROM workflow_entity;') is True)
        self.require('original_database_has_no_ha_workflows',self.sql('n8n','SELECT to_json(count(*)=0) FROM workflow_entity;') is True)
        # The safe manual workflow's action must have persisted a real successful execution.
        self.require('real_action_persisted_in_selected_db',self.sql(self.name,
            'SELECT to_json(count(*)>0) FROM execution_entity e JOIN workflow_entity w ON e."workflowId"=w.id '
            "WHERE w.name='WOOW 匯入測試 - 手動' AND e.status='success';") is True)

    def kept(self,tag):
        expected=self.r['kept_state']
        now=self.op('snapshot',tag=tag,databases=list(expected['databases']))
        self.require('original_outside_rows_types_access_roles',now==expected)
        self.require('retained_current_secret_ids_values',self.op('secrets')==self.r['kept_secrets'])
        return now

    def flow(self):
        self.resources();self.frozen_engine()
        self.require('fresh_full_safety_required',self.r.get('safety_verified') is True and bool(self.r.get('full_safety')))
        self.require('case_not_already_mutated',not self.r.get('fixture_intent'))
        self.acquire_original()
        self.op('preserved_safety_check')
        # Revalidate the safety source before every destructive case, not merely
        # because a previous process wrote a receipt flag.
        safety=self.archive_probe(self.r['full_safety'])
        self.require('safety_still_complete_unmarked',safety['scope']=='instance' and safety['ha_database'] is None)
        try:
            self.pause_timer();self.scope_instance();self.start_units(['n8n-postgres.service']);self.pg_ready()
            original=self.op('snapshot',tag='before_case')
            self.require('fresh_safety_matches_current_original',original==self.r['original_db'])
            self.r['fixture_intent']=True;self.save()
            sql=plan.case_sql(self.name)
            # Exact existence check before any CREATE; no application connection
            # can still hold the source template because all seven services stopped.
            missing=self.sql('postgres',"SELECT to_json(NOT EXISTS(SELECT 1 FROM pg_database WHERE datname IN ('"+
                             self.name+"','"+self.name+"_outside')) AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='"+
                             self.name+"_reader'));")
            self.require('unique_database_role_names',missing is True)
            self.sql('postgres',sql['clone_on_postgres'],json_result=False)
            self.sql('postgres',sql['outside_on_postgres'],json_result=False)
            self.sql(self.name+'_outside',sql['outside_on_own_database'],json_result=False)
            self.op('fixture',database=self.name);self.command('systemctl','--user','daemon-reload')
            self.r['before_convert']=self.op('snapshot',tag='before_convert');self.save()
            self.stop_units()
            fixture=plan.LAB/'ha-fixtures/20261118/woow-import-test-enc/woow-import-test-enc.tar'
            self.r['fixture_sha256']=plan.sha(fixture);self.r['ha_id']='ha-'+self.r['fixture_sha256'][:20]
            self.r['upload_intent']=True;self.save()
            s=self.credentials()
            # Reuse the saved original34 driver transport/credential reader. The
            # expected content ID is recorded before even upload-begin.
            class Ev:
                secrets=s
                def log(self,*args):pass
            if self.r['ha_id'] not in self.r['before_uploads']:
                rc,reply=self.h.upload(fixture,ev=Ev())
                self.require('original_fixture_uploaded',rc==0 and reply.get('ha_backup',{}).get('id')==self.r['ha_id'])
                self.r['owned_upload']=True;self.save()
            check=self.job('ha-check-start',{'ha_backup_id':self.r['ha_id'],'apps':['n8n'],
                           'key':s['HA_BACKUP_KEY']},'ha-check')
            apps=((check.get('result') or {}).get('ha_check') or {}).get('apps') or []
            self.require('actual_stopped_vendor_check',check.get('state')=='succeeded' and len(apps)==1 and
                         apps[0].get('app_id')=='n8n' and apps[0].get('ok') is True and
                         apps[0].get('importable') is True and not apps[0].get('blockers') and
                         not any(i.get('level') in ('confirm','stop') for i in apps[0].get('issues',[])))
            self.require('check_restores_stopped_services',all(self.op('inventory')['units'][u]['ActiveState']=='inactive' for u in ops.UNITS))
            conversion=self.job('ha-convert-start',{'ha_backup_id':self.r['ha_id'],'apps':['n8n'],
                                'confirm':True,'test_mode':False,'key':s['HA_BACKUP_KEY']},'convert')
            self.require('actual_vendor_conversion',conversion.get('state')=='succeeded')
            self.r['converted']=conversion['result']['backup_id'];self.save()
            self.require('convert_restores_stopped_services',all(self.op('inventory')['units'][u]['ActiveState']=='inactive' for u in ops.UNITS))
            converted=self.archive_probe(self.r['converted'])
            self.require('real_marker_selects_file_database',converted['scope']=='instance' and
                         converted['ha_database']==self.name and converted['ha_access_valid'] and
                         converted['globals_present'] and {x[0] for x in converted['databases']}==set(self.r['before_convert']['database_names']))
            self.start_units(['n8n-postgres.service']);self.pg_ready()
            self.require('conversion_did_not_mutate_live_data',self.op('snapshot',tag='after_convert')==self.r['before_convert'])
            self.sql(self.name+'_outside',sql['late_outside_write'],json_result=False)
            self.r['kept_state']=self.op('snapshot',tag='kept',databases=self.r['original_db']['database_names']+[self.name+'_outside'])
            self.r['kept_secrets']=self.op('secrets');self.save()
            self.mismatch_case()
            self.resources();self.start_units(ops.UNITS);self.app_ready();self.endpoint()
            inspection=self.helper('inspect',{'backup_id':self.r['converted']})
            self.require('selective_restore_preflight',plan.preflight_ready(inspection))
            imported=self.job('restore-start',{'backup_id':self.r['converted'],'apps':['n8n'],'confirm':True},'import')
            self.require('real_selective_import',successful_restore(imported))
            self.app_ready();self.endpoint();self.kept('after_import');self.api()
            self.r['service_intents'].extend(ops.UNITS);self.save()
            self.command('systemctl','--user','restart','n8n.target',timeout=600)
            self.app_ready();self.endpoint();self.kept('after_restart');self.api()
            self.forced_rollback()
            self.r['flow_checks_passed']=True;self.save()
        finally:
            self.recover()

    def mismatch_case(self):
        self.op('fixture',database='n8n');self.command('systemctl','--user','daemon-reload')
        self.start_units(ops.UNITS);self.app_ready()
        found=self.root_json(plan.ENDPOINT_PROBE)
        self.require('mismatch_has_actual_other_database',found.get('database')=='n8n' and found.get('local') is True)
        before=self.op('snapshot',tag='mismatch_before')
        rid=self.name+'-mismatch'
        self.r['negative_request_intent']=rid;self.save()
        rc,response=self.h.helper('restore-start',{'backup_id':self.r['converted'],'apps':['n8n'],'confirm':True,
                                           'request_id':rid},timeout=180)
        error=response.get('error') or {}
        self.require('mismatch_refuses_before_job',rc!=0 and '重新轉換' in error.get('message','') and
                     self.op('intent',request_id=rid) is None)
        self.require('mismatch_no_database_change',self.op('snapshot',tag='mismatch_after')==before)
        self.stop_units();self.op('fixture',database=self.name);self.command('systemctl','--user','daemon-reload')

    def forced_rollback(self):
        self.resources()
        self.endpoint();self.require('known_original_marker_copied',self.op('copy_original_marker') is True)
        # Pause the active scheduled workflow through the actual vendor API so
        # an all-row snapshot is meaningful across startup and rollback.
        s=self.credentials()
        paused=self.private_api(API_PAUSE)
        self.require('scheduled_workflow_paused',paused is True)
        self.stop_units();self.start_units(['n8n-postgres.service']);self.pg_ready()
        self.r['before_forced']=self.op('snapshot',tag='before_forced');self.save()
        self.start_units(ops.UNITS);self.app_ready();self.endpoint()
        self.require('forced_snapshot_stable',self.op('snapshot',tag='forced_stable')==self.r['before_forced'])
        self.r['hook_intent']=True;self.save();self.op('hook_on');self.command('systemctl','--user','daemon-reload')
        try:
            job=self.job('restore-start',{'backup_id':self.r['converted'],'apps':['n8n'],'confirm':True},'forced')
            witness=self.op('hook_state')
            marker=self.sql(self.name,ops.MARKER_SQL) is True
            after=self.op('snapshot',tag='after_forced')
            equal=after==self.r['before_forced']
            self.require('deterministic_hook_failed_and_allowed',witness['refused'] is True and witness['allowed'] is True)
            self.app_ready();self.endpoint();self.kept('after_rollback');self.api()
            self.require('automatic_full_rollback_proven',plan.rollback_proven(job,consumed=witness['refused'],
                         marker=marker,digests=equal,application=True))
        finally:
            self.settle();self.op('hook_off');self.command('systemctl','--user','daemon-reload')
            self.r['hook_intent']=False;self.save()

    def recover(self):
        self.recovering=True;self.settle()
        self.require('recovery_no_active_job',not self.op('inventory')['active_jobs'])
        if self.r.get('hook_intent'):
            self.op('hook_off');self.command('systemctl','--user','daemon-reload')
            self.r['hook_intent']=False;self.save()
        self.stop_units()
        if self.r.get('fixture_intent'):
            self.require('recovery_has_verified_full_safety',self.r.get('safety_verified') is True)
            self.op('restore_files');self.command('systemctl','--user','daemon-reload')
            # Full safety has no HA marker: this is the ordinary complete-instance
            # restore, including the original authentication/configuration state.
            pre=self.helper('inspect',{'backup_id':self.r['full_safety']})
            self.require('full_safety_recovery_preflight',plan.preflight_ready(pre))
            job=self.job('restore-start',{'backup_id':self.r['full_safety'],'apps':['n8n'],'confirm':True},'recover')
            self.require('full_original_instance_restored',successful_restore(job))
            self.stop_units();self.start_units(['n8n-postgres.service']);self.pg_ready()
            self.require('original_full_database_state_returned',self.op('snapshot',tag='recovered')==self.r['original_db'])
            current=self.op('secrets')
            self.require('original_authentication_values_returned',{k:v['value_sha256'] for k,v in current.items()}==
                         {k:v['value_sha256'] for k,v in self.r['original_secrets'].items()})
            self.r['fixture_intent']=False;self.r['baseline_restored']=True;self.save()
        self.stop_units()
        # The ordinary archive can normalize file timestamps. Reapply protected
        # original bytes and metadata after the job has exited and apps stopped.
        self.op('restore_files');self.command('systemctl','--user','daemon-reload')
        self.restore_catalog();self.restore_timer()
        self.require('original_durable_services_catalog_files',same_found(self.op('inventory'),self.r['before']))
        returned=self.op('preserved_safety_return',jobs=list(self.r['jobs']),full_safety=self.r.get('full_safety'),
                         baseline_restored=self.r.get('baseline_restored') is True)
        self.require('preserved_old_pairs_returned',returned.get('all_preexisting_files_exact') is True)
        self.r['preserved_old_safeties_return']=returned;self.save()
        self.r['recovery_verified']=True;self.save()
        if self.r.get('upload_intent'):
            self.scan_secrets()
        self.cleanup_owned()

    def scan_secrets(self):
        s=self.credentials()
        values=[s[x] for x in ('HA_BACKUP_KEY','N8N_OWNER_PW','N8N_CREDENTIAL_VALUE')]
        self.require('all_issued_cookies_registered',not self.r.get('cookie_intent'))
        path='/var/lib/woowtech-backup/focus-n8n-instance/'+self.name+'/issued.json'
        prefix=scan_input_prefix(path,self.r['started'],self.r.get('cookie_probes',0)>0,self.ops_source)
        scanner=(HERE/'focus_n8n_instance_acceptance_scan.py').read_text()
        report=self.root_json(prefix+scanner,values,timeout=180)
        self.require('registered_secret_scan_zero',report['hits']==0 and report['scanned']>0 and
                     report['regular_json_roots_scanned']==2 and report['archive_index_sidecars_scanned']>0 and
                     report['archive_index_sidecars_scanned']==report['actual_archive_index_sidecars_expected'])
        self.r['secret_scan_report']=report;self.save()
        self.r['secret_scan']=True;self.save()

    def cleanup_owned(self):
        self.require('cleanup_recovery_proven',self.r.get('recovery_verified') is True and not self.r.get('pending'))
        if self.r.get('upload_intent'):self.require('cleanup_secret_scan_proven',self.r.get('secret_scan') is True)
        # The fresh safety is kept after the safety phase and throughout any
        # uncertainty. Deletions happen only after complete baseline recovery.
        for bid in self.r['created_backups']:
            self.require('delete_only_case_backup',bid not in self.r.get('before_backups',[]) and bid not in ops.PROTECTED)
            self.helper('delete',{'backup_id':bid})
        if self.r.get('ha_id') and self.r['ha_id'] not in self.r.get('before_uploads',[]):
            listed={x['id'] for x in self.helper('list').get('ha_backups',[])}
            if self.r['ha_id'] in listed:self.helper('ha-delete',{'ha_backup_id':self.r['ha_id'],'confirm':True})
        if self.lease['image_policy']=='remove-own-after-case':self.images_recover()
        self.require('protected_baselines_untouched',self.op('inventory')['protected']==self.r['before']['protected'])
        self.op('preserved_safety_check')
        self.op('cleanup_store',verified=True);self.r['complete']=True;self.save()


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--execute',action='store_true');p.add_argument('--phase',choices=PHASES)
    p.add_argument('--lease',type=Path);p.add_argument('--source',type=Path)
    p.add_argument('--receipt',type=Path);args=p.parse_args(argv)
    if not args.execute:
        compile((HERE/'focus_n8n_instance_acceptance_ops.py').read_text(),'<fixed device operations>','exec')
        print(json.dumps({'stage':'n8n_controller_offline','device_access':False,'phases':PHASES}));return 0
    if not all((args.phase,args.lease,args.source,args.receipt)):p.error('--execute needs phase,lease,source,receipt')
    lease=json.loads(args.lease.read_text());driver=git(REPO,'rev-parse','HEAD');source=git(args.source,'rev-parse','HEAD')
    validate_lease(lease,args.phase,now=time.time(),driver_commit=driver,source_commit=source)
    if git(REPO,'status','--porcelain') or git(args.source,'status','--porcelain'):
        raise ValueError('exact committed clean driver and product source required')
    import ha_import_e2e as h
    h.DEVICE=plan.DEVICE;h.require_isolated_device()
    fd=os.open(plan.LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        c=Controller(args,lease,h)
        c.r['active_phase']=args.phase;c.save()
        function=getattr(c,{'images':'images','images-recover':'images_recover','safety':'safety',
                           'flow':'flow','recover':'recover'}[args.phase])
        try:function()
        except Exception as e:
            c.r['failure_class']=type(e).__name__;c.save()
            if args.phase=='images' and 'images-recover' in lease['phases'] and c.r.get('before'):
                try:c.images_recover()
                except Exception as recovery:
                    c.r['recovery_failure_class']=type(recovery).__name__;c.save()
            print(json.dumps({'stage':'phase_failed','phase':args.phase,'failure_class':type(e).__name__}))
            return 1
        print(json.dumps({'stage':'phase_complete','phase':args.phase,'checks':len(c.results),
                          'runtime_acceptance':bool(args.phase=='flow' and c.r.get('flow_checks_passed') and c.r.get('complete'))}))
        return 0
    finally:os.close(fd)


if __name__=='__main__':raise SystemExit(main())
