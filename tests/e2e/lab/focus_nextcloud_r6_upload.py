#!/usr/bin/env python3
"""Leased cold UPLOAD ONLY repro. Default offline; never wakes/deploys/starts jobs.

Diagnostic receipts are private and written BEFORE own abort. One successfully
verified owned HA store is retained for a separately leased full-share case.
"""
import argparse
import datetime
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time
import traceback

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import focus_nextcloud_r6_source as source
import focus_nextcloud_r6_wake as wake
from focus_nextcloud_r6_case import QUIESCENT,admission
from focus_nextcloud_r6_inventory import collect,FIXTURE,FIXTURE_SHA,LP,DEVICE
from focus_nextcloud_r6_plan import lease_check,RESERVE,MARGIN,DEVICE_CAP,FIXTURE_BYTES

REPO=HERE.parents[2]
HELPER_SHA='539c32a6a0c7689797f2d571f2ea56a038a79a647955df42f4cfb97a6bc03678'
VERSION_SHA='29ddb46f49384f63c69c2112c1e9b03c1ff2c4993904cc4723ff544fcb32ee92'
PRIOR_SHA='cb23acdb178c1614b0cbc24b5d294a0652959ac36c2c0a651ff44917da8c02e1'
HA_ID='ha-'+FIXTURE_SHA[:20]
THROTTLE=64*1024**2
TRANSITIONS={'new':{'begin-requested'},'begin-requested':{'begun'},'begun':{'streaming'},
 'streaming':{'streamed'},'streamed':{'finish-requested'},'finish-requested':{'finished'},'finished':{'retained'}}


def advance(state,target,**values):
    if target not in TRANSITIONS.get(state['phase'],set()):raise ValueError('fixed-upload-fsm-transition-refused')
    if target=='retained' and (not state.get('upload_id') or state.get('ha_backup_id')!=HA_ID):
        raise ValueError('fixed-upload-retained-state-unbound')
    state.update(values,phase=target)


def validate_begin(reply):
    uid=reply.get('upload_id','')
    if not re.fullmatch('u[0-9a-f]{16}',uid) or reply.get('path')!='/var/lib/woowtech-backup/uploads/'+uid+'.part':
        raise ValueError('fixed-upload-begin-binding-refused')
    return uid


def owned_abort(state):
    # A lost begin reply never licenses a guessed upload ID. A finish uncertainty
    # retains the known upload/store for reconciliation, never aborts publication.
    return (state.get('upload_id') if state['phase'] in ('begun','streaming','streamed')
            and state.get('writer_reaped',True) else None)


def diagnostic(error,stage,offset):
    return {'stage':stage,'chunk_offset':offset,'exception_class':type(error).__name__,
            'errno':getattr(error,'errno',None),'exception_text':str(error),'traceback':traceback.format_exc()}


def retained_credit(receipt,proof):
    if (receipt.get('status')!='passed' or receipt.get('phase')!='upload-only' or receipt.get('pending') is not False
            or receipt.get('ha_backup_id')!=HA_ID or receipt.get('sha256')!=FIXTURE_SHA or receipt.get('bytes')!=FIXTURE_BYTES
            or receipt.get('expected_store_absent_before') is not True or not re.fullmatch('u[0-9a-f]{16}',receipt.get('upload_id',''))
            or proof.get('status')!='passed' or proof.get('ha_backup_id')!=HA_ID or proof.get('sha256')!=FIXTURE_SHA or proof.get('bytes')!=FIXTURE_BYTES
            or proof.get('identity')!=receipt.get('ha_file_identity') or proof.get('sidecar_sha256')!=receipt.get('sidecar_sha256')
            or type(proof.get('allocated_bytes')) is not int or proof['allocated_bytes']<=0):
        raise ValueError('fixed-upload-retained-provenance-refused')
    return min(FIXTURE_BYTES,proof['allocated_bytes'])


# Rendered into BOTH long-running device processes. No RPC-based watcher thread.
WATCH=r'''
metrics={'minimum_free_bytes':None,'peak_memory_current_bytes':0};stage='watch';offset=0;watch_failure=None
def watch():
 global watch_failure
 try:
  if time.time()>=deadline:raise RuntimeError('fixed-upload-expiry')
  free=min(shutil.disk_usage('/home').free,shutil.disk_usage('/var/lib').free)
  memory=int(pathlib.Path('/sys/fs/cgroup/memory.current').read_text())
  metrics['minimum_free_bytes']=min(metrics['minimum_free_bytes'] or free,free)
  metrics['peak_memory_current_bytes']=max(metrics['peak_memory_current_bytes'],memory)
  if free<13*1024**3+512*1024**2:raise RuntimeError('fixed-upload-reserve')
  if memory>3*1024**3-512*1024**2:raise RuntimeError('fixed-upload-memory')
 except Exception as error:
  watch_failure={'exception_class':type(error).__name__,'errno':getattr(error,'errno',None),'reason':str(error)}
  raise
'''
WRITER=r'''
import hashlib,json,os,pathlib,select,shutil,stat,sys,time,traceback
q=json.loads(sys.argv[1]);deadline=q['deadline']
'''+WATCH+r'''
fd=None
try:
 stage='open-owned-upload';p=pathlib.Path(q['path'])
 assert p==pathlib.Path('/var/lib/woowtech-backup/uploads')/(q['upload_id']+'.part')
 fd=os.open(p,os.O_WRONLY|os.O_NOFOLLOW);st=os.fstat(fd)
 assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and st.st_size==0 and not st.st_mode&0o022
 identity={'dev':st.st_dev,'ino':st.st_ino};h=hashlib.sha256();stage='stream'
 while True:
  watch()
  if not select.select([sys.stdin.fileno()],[],[],1)[0]:continue
  chunk=os.read(sys.stdin.fileno(),65536)
  if not chunk:break
  assert offset+len(chunk)<=q['size'];h.update(chunk);data=memoryview(chunk)
  while data:
   written=os.write(fd,data);offset+=written;data=data[written:]
 stage='stream-eof';os.fsync(fd)
 assert offset==q['size'] and h.hexdigest()==q['sha256']
 print(json.dumps({'status':'passed','bytes':offset,'sha256':h.hexdigest(),'identity':identity,'metrics':metrics}))
except BaseException as error:
 print(json.dumps({'status':'failed','stage':stage,'chunk_offset':offset,'exception_class':type(error).__name__,
  'errno':getattr(error,'errno',None),'watch_failure':watch_failure,'metrics':metrics}))
 traceback.print_exc(file=sys.stderr);sys.exit(2)
finally:
 if fd is not None:os.close(fd)
'''
RPC=r'''
import hashlib,json,os,pathlib,selectors,shutil,signal,stat,subprocess,sys,time,traceback
q=json.load(sys.stdin);deadline=q['deadline'];child=None;out=bytearray();err=bytearray();returncode=None
'''+WATCH+r'''
try:
 stage='helper-binding';helper=pathlib.Path('/usr/local/libexec/woowtech-cockpit-backup');s=helper.lstat()
 assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and not s.st_mode&0o022
 assert hashlib.sha256(helper.read_bytes()).hexdigest()==q['helper_sha256']
 command=q['command'];request=q['request']
 assert command in ('upload-begin','upload-finish','upload-abort')
 assert set(request)==({'filename','size'} if command=='upload-begin' else {'upload_id'})
 if command!='upload-begin':assert request['upload_id']==q['owned_upload_id']
 watch();stage=command
 child=subprocess.Popen([str(helper),command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 child.stdin.write(json.dumps(request).encode());child.stdin.close()
 selector=selectors.DefaultSelector()
 selector.register(child.stdout,selectors.EVENT_READ,out);selector.register(child.stderr,selectors.EVENT_READ,err)
 while selector.get_map():
  watch()
  for key,_ in selector.select(0.5):
   block=os.read(key.fileobj.fileno(),65536)
   if not block:selector.unregister(key.fileobj);continue
   key.data.extend(block)
   if len(out)>1048576 or len(err)>262144:raise RuntimeError('fixed-upload-rpc-output-limit')
 returncode=child.wait(timeout=10)
 print(json.dumps({'status':'reaped','rpc_returncode':returncode,'stdout':out.decode('utf-8','replace'),
  'stderr':err.decode('utf-8','replace'),'metrics':metrics}))
except BaseException as error:
 if child is not None and child.poll() is None:
  os.killpg(child.pid,signal.SIGTERM)
  try:child.wait(timeout=10)
  except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=10)
 print(json.dumps({'status':'failed','stage':stage,'rpc_returncode':child.returncode if child else None,
  'exception_class':type(error).__name__,'errno':getattr(error,'errno',None),'watch_failure':watch_failure,
  'stdout':out.decode('utf-8','replace'),'stderr':err.decode('utf-8','replace'),'metrics':metrics}))
 traceback.print_exc(file=sys.stderr);sys.exit(2)
'''
META=r'''
q=json.load(sys.stdin);root=Path('/var/lib/woowtech-backup');ha=root/'ha-backups'
for directory in (root,root/'uploads',ha):
 if directory.exists():
  st=directory.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022
j=json.loads(Path('/usr/local/lib/.focus-nextcloud-r6-24d1dc3d14bfc94e/transaction.json').read_text())
assert j['state']=='restored' and manifest_hash(j['prior'])==q['prior_sha256']
assert tree_snapshot(Path('/usr/local/lib/woowtech-cockpit-backup'))==j['prior']['library']
assert tree_snapshot(Path('/usr/local/libexec/woowtech-cockpit-backup'))==j['prior']['helper']
helper=Path('/usr/local/libexec/woowtech-cockpit-backup').read_bytes()
assert hashlib.sha256(helper).hexdigest()==q['helper_sha256']
assert helper.startswith(b'#!/usr/bin/python3 -I\n') and b'sys.dont_write_bytecode = True' in helper and b'sys.pycache_prefix =' in helper
assert digest(Path('/usr/local/lib/woowtech-cockpit-backup/VERSION'))==q['version_sha256']
entries=list(ha.iterdir()) if ha.exists() else []
assert len(entries)<=2000
for p in entries:
 st=p.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not st.st_mode&0o022
 assert p.suffix in ('.tar','.json')
stems={p.stem for p in entries}
assert all((ha/(stem+'.tar')).is_file() and (ha/(stem+'.json')).is_file() for stem in stems)
u=root/'uploads';uploads=sorted(p.name for p in u.iterdir()) if u.exists() else []
print(json.dumps({'status':'passed','helper_sha256':q['helper_sha256'],'version_sha256':q['version_sha256'],
 'prior_source_exact':True,'isolated_no_bytecode_policy':True,'uploads':uploads,
 'expected_store_absent':not any(p.name.startswith(q['ha_id']+'.') for p in entries)}))
'''
VERIFY=r'''
import hashlib,json,os,pathlib,shutil,stat,sys,time,traceback
q=json.load(sys.stdin);deadline=q['deadline']
'''+WATCH+r'''
try:
 stage='retained-file-hash';root=pathlib.Path('/var/lib/woowtech-backup/ha-backups');bid=q['ha_backup_id']
 for directory in (root,root.parent):
  st=directory.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022
 assert bid==q['expected_id']
 p=root/(bid+'.tar');side=root/(bid+'.json');s=p.lstat();ss=side.lstat()
 for st in (s,ss):assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not st.st_mode&0o022
 assert ss.st_size<=4*1024**2 and s.st_size==q['size']
 raw=side.read_bytes();rec=json.loads(raw);assert rec['id']==bid and rec['sha256']==q['sha256'] and rec['size']==q['size']
 h=hashlib.sha256()
 with p.open('rb') as f:
  for block in iter(lambda:f.read(1024**2),b''):watch();h.update(block);offset+=len(block)
 assert h.hexdigest()==q['sha256']
 stable=lambda st:(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns,st.st_mode,st.st_uid,st.st_gid,st.st_nlink)
 assert stable(p.lstat())==stable(s) and stable(side.lstat())==stable(ss)
 print(json.dumps({'status':'passed','ha_backup_id':bid,'bytes':offset,'sha256':h.hexdigest(),
  'identity':{'dev':s.st_dev,'ino':s.st_ino},'sidecar_sha256':hashlib.sha256(raw).hexdigest(),
  'allocated_bytes':min(s.st_size,s.st_blocks*512),'metrics':metrics}))
except BaseException as error:
 print(json.dumps({'status':'failed','stage':stage,'chunk_offset':offset,'exception_class':type(error).__name__,
  'errno':getattr(error,'errno',None),'watch_failure':watch_failure,'metrics':metrics}))
 traceback.print_exc(file=sys.stderr);sys.exit(2)
'''


def meta_program():
    return ('import hashlib,json,os,stat,sys\nfrom pathlib import Path\nMAX_FILE='+str(source.MAX_FILE)+
            '\nMAX_TOTAL='+str(source.MAX_TOTAL)+'\n'+inspect.getsource(source.digest)+'\n'+
            inspect.getsource(source.manifest_hash)+'\n'+inspect.getsource(source.tree_snapshot)+'\n'+META)


class Evidence:
    def __init__(self,path):
        self.path=path;path.mkdir(parents=True,mode=0o700,exist_ok=False);os.chmod(path.parent,0o700);self.number=0
    def save(self,name,value):
        fd=os.open(self.path/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:
            json.dump(value,f,indent=2);f.flush();os.fsync(f.fileno())
    def event(self,value):
        self.number+=1;self.save('%04d-event.private.json'%self.number,value)


def device_process(body,args,ev,prefix,input_data=None,timeout=3600):
    # RPC/verify raw output is bounded inside-device, private stdout/stderr retained BEFORE any cleanup.
    with (ev.path/(prefix+'.stdout.private')).open('xb') as out,(ev.path/(prefix+'.stderr.private')).open('xb') as err:
        p=subprocess.Popen([str(LP),'exec','-i',DEVICE,'python3','-I','-c',body,*args],stdin=subprocess.PIPE,stdout=out,stderr=err)
        try:p.communicate(input=input_data,timeout=timeout)
        except BaseException as error:
            ev.event(diagnostic(error,prefix,0))
            # Device's own deadline still reaps its writer/helper; do not race an abort with a live client.
            p.wait(timeout=60);raise
    raw=(ev.path/(prefix+'.stdout.private')).read_bytes()
    ev.event({'stage':prefix,'transport_returncode':p.returncode,'stdout_sha256':hashlib.sha256(raw).hexdigest(),
              'stderr_sha256':source.digest(ev.path/(prefix+'.stderr.private'))})
    if len(raw)>2*1024**2:raise ValueError('fixed-upload-device-output-limit')
    reply=json.loads(raw)
    ev.save(prefix+'-diagnostic.private.json',reply)
    if p.returncode or reply.get('status')=='failed':raise RuntimeError('fixed-upload-device-step-failed')
    return reply


def rpc(command,request,state,ev,deadline):
    if command=='upload-abort' and request.get('upload_id')!=owned_abort(state):
        raise ValueError('fixed-upload-abort-not-owned-or-live-writer')
    q={'command':command,'request':request,'deadline':deadline,'helper_sha256':HELPER_SHA,'owned_upload_id':state.get('upload_id')}
    packet=device_process(RPC,[],ev,command,json.dumps(q).encode(),max(1,deadline-time.time()+30))
    if packet['rpc_returncode']!=0:raise RuntimeError('fixed-upload-helper-rpc-failed')
    result=json.loads(packet['stdout'])
    if result.get('ok') is not True:raise RuntimeError('fixed-upload-helper-refused')
    return result


def verify_retained(ha_id,deadline,ev,prefix='verify-retained'):
    q={'deadline':deadline,'ha_backup_id':ha_id,'expected_id':HA_ID,'sha256':FIXTURE_SHA,'size':FIXTURE_BYTES}
    return device_process(VERIFY,[],ev,prefix,json.dumps(q).encode(),max(1,deadline-time.time()+30))


def adopt_receipt(path,expected_sha,deadline,ev):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        s=os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size>65536:
            raise ValueError('fixed-upload-retained-receipt-type-refused')
        raw=f.read(65537)
    if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!=expected_sha:
        raise ValueError('fixed-upload-retained-receipt-sha-refused')
    receipt=json.loads(raw);proof=verify_retained(receipt.get('ha_backup_id'),deadline,ev)
    return receipt,proof,retained_credit(receipt,proof)


def stream(state,begin,ev,deadline):
    q={'deadline':deadline,'path':begin['path'],'upload_id':state['upload_id'],'size':FIXTURE_BYTES,'sha256':FIXTURE_SHA}
    h=hashlib.sha256();offset=0;next_checkpoint=THROTTLE;last=time.monotonic();state['writer_reaped']=False
    with (ev.path/'writer.stdout.private').open('xb') as out,(ev.path/'writer.stderr.private').open('xb') as err:
        p=subprocess.Popen([str(LP),'exec','-i',DEVICE,'python3','-I','-c',WRITER,json.dumps(q)],stdin=subprocess.PIPE,stdout=out,stderr=err)
        try:
            os.set_blocking(p.stdin.fileno(),False)
            with FIXTURE.open('rb') as f:
                for chunk in iter(lambda:f.read(1024**2),b''):
                    if offset+len(chunk)>FIXTURE_BYTES:raise ValueError('fixed-upload-host-length-bound')
                    data=memoryview(chunk)
                    while data:
                        if time.time()>=deadline:raise TimeoutError('fixed-upload-host-expiry')
                        if p.poll() is not None:raise BrokenPipeError(32,'fixed-upload-writer-exited')
                        if not select.select([],[p.stdin],[],1)[1]:continue
                        n=os.write(p.stdin.fileno(),data);offset+=n;state['chunk_offset']=offset;data=data[n:]
                    h.update(chunk)
                    if offset>=next_checkpoint or time.monotonic()-last>=15:
                        # Progress checkpoint only: resource/expiry are owned INSIDE the writer.
                        ev.event({'stage':'host-stream','chunk_offset':offset,'writer_transport_returncode':p.poll()})
                        next_checkpoint=offset+THROTTLE;last=time.monotonic()
            if offset!=FIXTURE_BYTES or h.hexdigest()!=FIXTURE_SHA:raise ValueError('fixed-upload-host-sha-length')
        except BaseException as error:
            ev.event(diagnostic(error,'host-stream',offset));raise
        finally:
            p.stdin.close();p.wait(timeout=120);state['writer_reaped']=True
            ev.event({'stage':'writer-reaped-before-cleanup','chunk_offset':offset,'transport_returncode':p.returncode,
                      'stderr_sha256':source.digest(ev.path/'writer.stderr.private')})
    reply=json.loads((ev.path/'writer.stdout.private').read_text());ev.save('writer-diagnostic.private.json',reply)
    if p.returncode or reply.get('status')!='passed':raise RuntimeError('fixed-upload-writer-failed')
    if reply['bytes']!=offset or reply['sha256']!=FIXTURE_SHA:raise ValueError('fixed-upload-writer-proof-mismatch')
    return reply


def transfer(state,ev,deadline,rpc_call=rpc,stream_call=stream,verify_call=verify_retained):
    proof=None;writer=None;failure=None
    try:
        advance(state,'begin-requested');ev.event(dict(state))
        begin=rpc_call('upload-begin',{'filename':FIXTURE.name,'size':FIXTURE_BYTES},state,ev,deadline)
        uid=validate_begin(begin);advance(state,'begun',upload_id=uid);ev.event(dict(state))
        advance(state,'streaming');ev.event(dict(state));writer=stream_call(state,begin,ev,deadline)
        advance(state,'streamed');ev.event(dict(state))
        advance(state,'finish-requested');ev.event(dict(state))
        result=rpc_call('upload-finish',{'upload_id':uid},state,ev,deadline);rec=result['ha_backup']
        if rec.get('id')!=HA_ID or rec.get('sha256')!=FIXTURE_SHA or rec.get('size')!=FIXTURE_BYTES:
            raise ValueError('fixed-upload-finish-binding-refused')
        advance(state,'finished',ha_backup_id=HA_ID);ev.event(dict(state))
        proof=verify_call(HA_ID,deadline,ev)
        if proof['identity']!=writer['identity']:raise ValueError('fixed-upload-published-inode-not-owned')
        advance(state,'retained');ev.event(dict(state))
    except BaseException as error:
        failure='fixed-upload-case-stopped';ev.event(diagnostic(error,state['phase'],state.get('chunk_offset',0)))
        # Explicit diagnostics are durable before the only authorized cleanup operation.
        abort=owned_abort(state)
        if abort:
            try:rpc_call('upload-abort',{'upload_id':abort},state,ev,deadline+300);ev.event({'stage':'own-upload-aborted','upload_id':abort})
            except Exception as cleanup_error:ev.event(diagnostic(cleanup_error,'abort-own-upload',0))
    return proof,writer,failure


def run(lease,commit):
    lease_check(lease,commit,'upload-only')
    if lease.get('helper_sha256')!=HELPER_SHA or lease.get('prior_source_sha256')!=PRIOR_SHA or lease.get('retain_finished_store') is not True or lease.get('cleanup_grace_seconds')!=300:
        raise ValueError('fixed-upload-exact-helper-retention-lease-required')
    deadline=datetime.datetime.fromisoformat(lease['expires_utc'].replace('Z','+00:00')).timestamp()
    if deadline-time.time()<1800:raise ValueError('fixed-upload-lease-headroom')
    ev=Evidence(Path.home()/'.woowbk-lab/evidence/focus-nextcloud-r6-upload-only'/time.strftime('%Y%m%dT%H%M%S'))
    ev.save('source-binding.json',{'source_commit':commit,'controller_sha256':source.digest(Path(__file__))})
    marker=Path.home()/'.woowbk-lab/run/focus-nextcloud-r6-upload-leases'
    marker.mkdir(parents=True,mode=0o700,exist_ok=True)
    lease_sha=source.manifest_hash(lease)
    fd=os.open(marker/(lease_sha+'.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:
        json.dump({'source_commit':commit,'private_receipt_dir':str(ev.path)},f);f.flush();os.fsync(f.fileno())
    ev.save('lease-binding.json',{'lease_sha256':lease_sha,'single_attempt':True})
    try:
        return run_attempt(lease,commit,deadline,ev)
    except BaseException as error:
        ev.event(diagnostic(error,'preflight-or-final-validation',0))
        ev.save('unresolved-result.json',{'status':'failed','phase':'upload-only','pending':True,'source_commit':commit,'fixed_failure':'fixed-upload-unresolved-preflight-or-final-validation'})
        raise


def run_attempt(lease,commit,deadline,ev):
    before=collect();admission(before)
    if min(before['host_free_bytes'],before['root']['varlib_free_bytes'])<RESERVE+FIXTURE_BYTES+MARGIN:
        raise ValueError('fixed-upload-fresh-peak-refused')
    meta=device_process(meta_program(),[],ev,'old-helper-preflight',json.dumps({'prior_sha256':PRIOR_SHA,'helper_sha256':HELPER_SHA,'version_sha256':VERSION_SHA,'ha_id':HA_ID}).encode(),120)
    if meta['uploads'] or not meta['expected_store_absent'] or wake.device(QUIESCENT,root=True)['active_jobs']:
        raise ValueError('fixed-upload-foreign-upload-store-or-writer')
    ev.save('before.private.json',before);ev.save('old-helper-policy-binding.json',meta)
    state={'phase':'new','upload_id':None,'writer_reaped':True};proof=None;writer=None;failure=None
    proof,writer,failure=transfer(state,ev,deadline)
    after=collect()
    preserved=(after['owner']==before['owner'] and after['isolation']==before['isolation']
               and after['root']['catalog_sha256']==before['root']['catalog_sha256']
               and after['root']['installed_hashes']==before['root']['installed_hashes']
               and after['root']['memory_max']==str(DEVICE_CAP) and wake.device(QUIESCENT,root=True)['active_jobs']==0)
    # Recheck complete prior engine/helper/cache without touching any source or policy.
    finalmeta=device_process(meta_program(),[],ev,'old-helper-final',json.dumps({'prior_sha256':PRIOR_SHA,'helper_sha256':HELPER_SHA,'version_sha256':VERSION_SHA,'ha_id':HA_ID}).encode(),120)
    passed=(state['phase']=='retained' and preserved and finalmeta['prior_source_exact']
            and min(after['host_free_bytes'],after['root']['varlib_free_bytes'])>=RESERVE+MARGIN)
    record={'status':'passed' if passed else 'failed','phase':'upload-only','source_commit':commit,'pending':not passed,
     'upload_id':state.get('upload_id'),'ha_backup_id':state.get('ha_backup_id'),'expected_store_absent_before':True,
     'bytes':proof['bytes'] if proof else None,'sha256':proof['sha256'] if proof else None,
     'ha_file_identity':proof['identity'] if proof else None,'sidecar_sha256':proof['sidecar_sha256'] if proof else None,
     'allocated_bytes':proof['allocated_bytes'] if proof else 0,'cold_units_source_catalog_images_isolation_preserved':preserved,
     'helper_sha256':HELPER_SHA,'initial_fullshare_stop_cause':'unknown-not-recorded','fixed_failure':failure,
     'app_starts':0,'jobs_started':0,'pulls':0,'reserve_bytes':RESERVE,'memory_cap_bytes':DEVICE_CAP,
     'private_event_count':ev.number,'private_receipt_dir':str(ev.path),'last_fsm_phase':state['phase']}
    ev.save('after.private.json',after);ev.save('fixed-result.json',record)
    print(json.dumps({k:record[k] for k in ('status','phase','bytes','sha256','pending','private_event_count')}))
    return 0 if passed else 1


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',action='store_true');p.add_argument('--lease',type=Path);a=p.parse_args()
    if not a.run:print('offline upload-only preparation; no device or credential access');return 0
    if a.lease is None:p.error('--run requires NEW upload-only lease')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip()
    if subprocess.check_output(['git','status','--porcelain'],cwd=REPO,text=True).strip():raise ValueError('fixed-upload-clean-committed-source')
    lease=json.loads(a.lease.read_text());lease_check(lease,commit,'upload-only')
    with open('/tmp/woowbk-dev-e-mutation.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);return run(lease,commit)


if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,RuntimeError,BlockingIOError):print('fixed-upload-preflight-or-unresolved-step-refused',file=sys.stderr);sys.exit(2)
