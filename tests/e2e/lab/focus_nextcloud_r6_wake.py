#!/usr/bin/env python3
"""R6 leased same-config Quadlet pin refresh / wake / baseline / cold return.

Default is offline. This phase neither exports images nor installs/deploys code.
It keeps exact private prior Quadlet copies and restores them before completing.
Recovered original images remain loaded for subsequent separately leased cases.
"""
import argparse
import base64
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from focus_nextcloud_r6_inventory import collect, ORIGINALS, LP, DEVICE
from focus_nextcloud_r6_plan import BASELINE, DEVICE_CAP, GIB, MIB, RESERVE, lease_check

REPO = HERE.parents[2]
FILES = dict(zip(('nextcloud-app.container', 'nextcloud-office.container', 'nextcloud-db.container',
                  'nextcloud-redis.container', 'nextcloud-gateway.container'), ORIGINALS.items()))


def render_pin(data, config_id, original_ref):
    if not re.fullmatch('[0-9a-f]{64}', config_id):
        raise ValueError('fixed-pin-config-refused')
    lines = data.decode('utf-8').splitlines(keepends=True)
    if [x.strip() for x in lines if x.startswith('Image=')] != ['Image=' + original_ref]:
        raise ValueError('fixed-pin-image-line-refused')
    pulls = [x.strip() for x in lines if x.startswith('Pull=')]
    if pulls not in ([], ['Pull=never']):
        raise ValueError('fixed-pin-pull-policy-refused')
    result = []
    for line in lines:
        if line.startswith('Image='):
            ending = '\r\n' if line.endswith('\r\n') else '\n'
            result.append('Image=sha256:' + config_id + ending)
            if not pulls:
                result.append('Pull=never' + ending)
        else:
            result.append(line)
    return ''.join(result).encode('utf-8')


UNIT_BODY = r'''
q=json.load(sys.stdin)
root=pathlib.Path.home()/'.config/containers/systemd'
assert root.is_dir() and not root.is_symlink()
def raw(name):
 p=root/name;s=p.lstat()
 assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid() and s.st_size<=65536
 assert not os.listxattr(p)
 with p.open('rb') as f:data=f.read(65537)
 assert len(data)<=65536
 return s,data
def identity(ref):
 p=subprocess.run(['podman','image','inspect','--format','{{.Id}} {{.Architecture}} {{.Os}}',ref],capture_output=True,timeout=30)
 assert p.returncode==0
 fields=p.stdout.decode().strip().split()
 assert len(fields)==3 and fields[1:]==['amd64','linux']
 return fields[0].removeprefix('sha256:')
if q['action']=='snapshot':
 rows=[]
 for name,(ref,expected) in FILES.items():
  s,data=raw(name)
  refs=[x[6:] for x in data.decode().splitlines() if x.startswith('Image=')]
  assert len(refs)==1 and identity(refs[0])==expected and identity(ref)==expected
  new=render_pin(data,expected,refs[0])
  rows.append({'name':name,'data_b64':base64.b64encode(data).decode(),'sha256':hashlib.sha256(data).hexdigest(),
   'pinned_sha256':hashlib.sha256(new).hexdigest(),'config_id':expected,'original_ref':refs[0],
   'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'mtime_ns':s.st_mtime_ns})
 print(json.dumps({'rows':rows}))
else:
 assert q['action'] in ('pin','revert')
 rows=q['snapshot']['rows'];assert len(rows)==len(FILES) and {x['name'] for x in rows}==set(FILES)
 pending=[]
 for row in rows:
  name=row['name'];ref,expected=FILES[name];original=base64.b64decode(row['data_b64'],validate=True)
  assert len(original)<=65536 and hashlib.sha256(original).hexdigest()==row['sha256']
  assert row['config_id']==expected
  pinned=render_pin(original,expected,row['original_ref'])
  assert hashlib.sha256(pinned).hexdigest()==row['pinned_sha256']
  s,current=raw(name)
  assert (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(row['uid'],row['gid'],row['mode'])
  assert hashlib.sha256(current).hexdigest() in (row['sha256'],row['pinned_sha256'])
  if q['action']=='pin':
   assert current==original and identity(row['original_ref'])==expected and identity(ref)==expected
  pending.append((row,pinned if q['action']=='pin' else original))
 for row,data in pending:
  name=row['name'];p=root/name
  tmp=root/('.'+name+'.focus-r6-'+secrets.token_hex(6))
  fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   with os.fdopen(fd,'wb') as f:
    f.write(data);f.flush();os.fchown(f.fileno(),row['uid'],row['gid']);os.fchmod(f.fileno(),row['mode']);os.fsync(f.fileno())
    os.utime(f.fileno(),ns=(row['mtime_ns'],row['mtime_ns']))
   os.replace(tmp,p)
  finally:tmp.unlink(missing_ok=True)
 print(json.dumps({'status':'pinned' if q['action']=='pin' else 'reverted','files':len(rows)}))
'''

CONTROL = r'''
import json,os,pathlib,shutil,signal,subprocess,sys,time
q=json.load(sys.stdin)
units=['nextcloud-cron.timer','nextcloud-cron.service','nextcloud.target','nextcloud-app.service','nextcloud-db.service',
       'nextcloud-office.service','nextcloud-gateway.service','nextcloud-redis.service']
def stop():
 p=subprocess.run(['systemctl','--user','stop',*units],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=180)
 assert p.returncode==0
if q['action']=='stop':
 stop();print(json.dumps({'status':'stopped'}));sys.exit(0)
assert q['action']=='start'
deadline=min(q['expires_epoch'],time.time()+900)
ok=False;lowest=2**63;peak=0
try:
 for unit in ('nextcloud.target','nextcloud-cron.timer'):
  p=subprocess.Popen(['systemctl','--user','start',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
  try:
   while p.poll() is None:
    free=min(shutil.disk_usage('/home').free,shutil.disk_usage('/var/lib').free);lowest=min(lowest,free)
    mem=int(pathlib.Path('/sys/fs/cgroup/memory.current').read_text());peak=max(peak,mem)
    if free<13*1024**3+512*1024**2 or mem>3*1024**3-512*1024**2 or time.time()>=deadline:break
    time.sleep(0.5)
   else:
    assert p.returncode==0
    continue
   raise RuntimeError('fixed-wake-budget-stop')
  finally:
   if p.poll() is None:
    os.killpg(p.pid,signal.SIGTERM)
    try:p.wait(timeout=30)
    except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
 ok=True
finally:
 if not ok:stop()
print(json.dumps({'status':'started','minimum_free_bytes':lowest,'peak_memory_bytes':peak}))
'''

BASELINE_HASH = r'''
import hashlib,json,pathlib,stat
root=pathlib.Path('/var/lib/woowtech-backup/archives');rows=[]
for p in sorted(root.glob('20261123T132013Z-34811d90*')):
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
 h=hashlib.sha256()
 with p.open('rb') as f:
  for part in iter(lambda:f.read(1<<20),b''):h.update(part)
 rows.append({'name':p.name,'size':s.st_size,'sha256':h.hexdigest()})
assert len(rows)==2 and any(x['size']==422031360 for x in rows)
print(json.dumps(rows))
'''


def unit_program():
    return ('import base64,hashlib,json,os,pathlib,re,secrets,stat,subprocess,sys\n' +
            'FILES=' + repr(FILES) + '\n' + inspect.getsource(render_pin) + '\n' + UNIT_BODY)


def device(program, request=None, *, root=False, timeout=300):
    argv = [str(LP), 'exec', '-i', DEVICE]
    if not root:
        argv.append('/usr/local/bin/woowbk-owner')
    p = subprocess.run(argv + ['python3', '-I', '-c', program], input=json.dumps(request or {}).encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    if p.returncode or len(p.stdout) > 512 * 1024:
        raise RuntimeError('fixed-wake-device-step-failed')
    return json.loads(p.stdout)


def run_locked(lease, commit):
    lease_check(lease, commit, 'wake-baseline')
    if lease.get('pin_refresh_policy') != 'same-config-only-private-copy-revert':
        raise ValueError('fixed-pin-refresh-lease-required')
    before = collect()
    if (before['isolation']['memory_limit'] != DEVICE_CAP or before['root']['memory_max'] != str(DEVICE_CAP)
            or before['host_memory_available_mib'] < 2200
            or DEVICE_CAP-before['root']['memory_current'] < 1536*MIB
            or min(before['host_free_bytes'],before['root']['varlib_free_bytes']) < RESERVE+4*GIB
            or any(x.get('ActiveState') != 'inactive' for x in before['owner']['units'].values())):
        raise ValueError('fixed-cold-wake-resource-preflight-refused')
    for row in before['owner']['images']:
        ident=row.get('identity') or {}
        if (not row['present'] or ident.get('id','').removeprefix('sha256:') != ORIGINALS[row['ref']]
                or ident.get('architecture')!='amd64' or ident.get('os')!='linux'):
            raise ValueError('fixed-original-loaded-image-required')
    expires=int(__import__('datetime').datetime.fromisoformat(lease['expires_utc'].replace('Z','+00:00')).timestamp())
    if expires-time.time()<1800:
        raise ValueError('fixed-wake-lease-headroom-required')
    ev=Path.home()/'.woowbk-lab/evidence/focus-nextcloud-r6-wake'/time.strftime('%Y%m%dT%H%M%S')
    ev.mkdir(parents=True,mode=0o700,exist_ok=False);os.chmod(ev.parent,0o700)
    def save(name,value):
        fd=os.open(ev/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:json.dump(value,f,indent=2)
    baseline_before=device(BASELINE_HASH,root=True,timeout=600)
    snapshot=device(unit_program(),{'action':'snapshot'})
    save('prior-units.private.json',snapshot) # exact bytes/metadata BEFORE the first write
    save('prior-inventory.private.json',before)
    save('baseline-hashes.json',baseline_before)
    stopped=threading.Event();tripped=threading.Event();started=False;verified=False;reverted=False;failure=None
    resource="import json,shutil;print(json.dumps({'free':min(shutil.disk_usage('/home').free,shutil.disk_usage('/var/lib').free)}))"
    def watch():
        while not stopped.wait(2):
            try:enough=device(resource,root=True,timeout=30)['free']>=RESERVE+512*MIB and time.time()<expires
            except Exception:enough=False
            if enough:continue
            tripped.set()
            try:device(CONTROL,{'action':'stop'},timeout=240)
            except Exception:pass
            return
    watcher=threading.Thread(target=watch,daemon=True)
    try:
        device(unit_program(),{'action':'pin','snapshot':snapshot})
        p=subprocess.run([str(LP),'exec','-i',DEVICE,'/usr/local/bin/woowbk-owner','systemctl','--user','daemon-reload'],
                         stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120)
        if p.returncode:raise RuntimeError('fixed-pinned-reload-failed')
        started=True;watcher.start()
        result=device(CONTROL,{'action':'start','expires_epoch':expires},timeout=1200)
        save('wake-fixed-result.json',result)
        p=subprocess.run([sys.executable,'-I',str(HERE/'batch2_baseline.py'),'--verify','nextcloud'],
                         stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                         timeout=min(1200,max(1,int(expires-time.time()))))
        verified=p.returncode==0 and not tripped.is_set()
    except Exception:
        failure='fixed-wake-or-baseline-step-failed'
    finally:
        stopped.set()
        if started:watcher.join(timeout=250)
        try:
            if started and watcher.is_alive():raise RuntimeError('fixed-wake-watch-not-reaped')
            device(CONTROL,{'action':'stop'},timeout=240)
            cold=collect()
            if any(x.get('ActiveState')!='inactive' for x in cold['owner']['units'].values()):
                raise RuntimeError('fixed-wake-inactive-return-failed')
            device(unit_program(),{'action':'revert','snapshot':snapshot})
            p=subprocess.run([str(LP),'exec','-i',DEVICE,'/usr/local/bin/woowbk-owner','systemctl','--user','daemon-reload'],
                             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120)
            reverted=p.returncode==0
        except Exception:failure='fixed-wake-revert-needs-private-copy-recovery'
    preserved=False;baseline_after=None;after=None
    try:
        after=collect();baseline_after=device(BASELINE_HASH,root=True,timeout=600)
        preserved=(after['owner']['units']==before['owner']['units'] and after['owner']['quadlets']==before['owner']['quadlets']
                   and after['root']['catalog_sha256']==before['root']['catalog_sha256'] and baseline_after==baseline_before
                   and after['isolation']==before['isolation'] and after['root']['memory_max']==str(DEVICE_CAP))
    except Exception:failure='fixed-wake-final-snapshot-failed'
    record={'status':'passed' if verified and reverted and preserved else 'failed','source_commit':commit,
            'phase':'wake-baseline','baseline_verified':verified,'prior_quadlet_bytes_restored':reverted,
            'units_quadlets_catalog_baseline_archive_and_isolation_preserved':preserved,
            'baseline_id':BASELINE,'baseline_hashes':baseline_after,'memory_cap_bytes':DEVICE_CAP,
            'reserve_bytes':RESERVE,'final_free_bytes':after['root']['varlib_free_bytes'] if after else None,
            'fixed_failure':failure,'private_prior_copy_retained':True,
            'rotation_policy':'return-original-inactive-units-and-exact-quadlets-retain-five-loaded-images',
            'installer':False,'source_deployment':False,'pulls':0}
    save('fixed-result.json',record)
    print(json.dumps({k:record[k] for k in ('status','phase','baseline_verified','prior_quadlet_bytes_restored','pulls')}))
    return 0 if record['status']=='passed' else 1


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',action='store_true');p.add_argument('--lease',type=Path)
    args=p.parse_args()
    if not args.run:
        print('offline wake-baseline preparation; no device/credentials accessed');return 0
    if args.lease is None:p.error('--run requires separate reviewed wake-baseline lease')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip()
    if subprocess.check_output(['git','status','--porcelain'],cwd=REPO,text=True).strip():raise ValueError('fixed-committed-source-required')
    lease=json.loads(args.lease.read_text());lease_check(lease,commit,'wake-baseline')
    with open('/tmp/woowbk-dev-e-mutation.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return run_locked(lease,commit)


if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,RuntimeError,BlockingIOError):
        print('fixed-wake-phase-stopped; preserve-private-prior-unit-copy',file=sys.stderr);sys.exit(2)
