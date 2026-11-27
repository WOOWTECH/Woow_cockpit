#!/usr/bin/env python3
"""Authorized read-only fresh before capture after R8; at most three samples."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

HERE=Path(__file__).resolve().parent;REPO=HERE.parents[2]
BASE=Path('/tmp/parity-focus-20261127');LAB=Path.home()/'.woowbk-lab'
FROZEN='f39666e9162f9c581e172256b574f5718a0fbf77'
PRODUCT='59a1b0f95132ea51c899f590eea7e3b02c5dba43'
NAMES=('woow-emqx','woow-emqx-entrance','hermes-postgresql','hermes-redis',
       'hermes-agent','omnigent-postgres','omnigent-server','omnigent-runner')


def blob(commit,path):return subprocess.check_output(['git','-C',str(REPO),'show',commit+':'+path],timeout=30)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def exclusive(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
    fd=os.open(path.parent,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def program():
    prefix='tests/e2e/lab/focus_litellm_instance_acceptance_'
    common=blob(FROZEN,prefix+'ops.py').decode();source=blob(FROZEN,prefix+'source_ops.py').decode()
    return ("import sys,types,json,os;sys.dont_write_bytecode=True\n"
        "m=types.ModuleType('focus_litellm_instance_acceptance_ops');sys.modules[m.__name__]=m\n"
        "exec(compile("+repr(common)+",'<frozen f396 metadata>','exec'),m.__dict__)\n"
        "n=types.ModuleType('ll_r8_source_metadata');exec(compile("+repr(source)+",'<frozen f396 source metadata>','exec'),n.__dict__)\n"+r'''
from datetime import datetime,timezone
from pathlib import Path
if os.geteuid()!=0:raise ValueError('root metadata only')
n.resource_floor()
for attempt in range(1,4):
 start=datetime.now(timezone.utc).isoformat();current=n.snapshot();configs=m.image_configs();bindings={}
 for name,selected in current['selected'].items():
  unit=Path(selected['quadlet']).stem+'.service'
  result=m.owner('systemctl','--user','show',unit,'--property=Id,LoadState,ActiveState,SubState,SourcePath,FragmentPath')
  fields=dict(row.split('=',1) for row in result.stdout.decode().splitlines() if '=' in row)
  bindings[name]={'unit':fields,'source_meta':m.read_regular(selected['quadlet'])[1]}
 h=m.owner('systemctl','--user','show','headscale.service',
  '--property=Id,ActiveState,SubState,Result,NRestarts,MainPID,ExecMainCode,ExecMainStatus,SourcePath,FragmentPath')
 headscale=dict(row.split('=',1) for row in h.stdout.decode().splitlines() if '=' in row)
 hashes=m.engine_hashes();hashes['VERSION']=m.read_regular('/usr/local/lib/woowtech-cockpit-backup/VERSION')[1]['sha256']
 sample={'attempt':attempt,'started_utc':start,'ended_utc':datetime.now(timezone.utc).isoformat(),
  'current':current,'configs':configs,'bindings':bindings,'headscale':headscale,'engine_hashes':hashes}
 print(json.dumps(sample),flush=True)
 known=(headscale.get('ActiveState')=='activating' and headscale.get('SubState')=='auto-restart'
  and headscale.get('Result')=='exit-code' and headscale.get('MainPID')=='0'
  and headscale.get('NRestarts','').isdigit() and int(headscale['NRestarts'])>0)
 if known and set(current['containers'])==set(n.SELECTED) and set(current['running'])==set(n.SELECTED):break
''')


def diff(a,b,path=''):
    if a==b:return []
    if isinstance(a,dict) and isinstance(b,dict):
        return sum((diff(a.get(k),b.get(k),path+'.'+k) for k in sorted(set(a)|set(b))),[])
    return [path]


def main():
    head=subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True,timeout=30).strip()
    rel=str(Path(__file__).resolve().relative_to(REPO))
    if blob(head,rel)!=Path(__file__).read_bytes():raise ValueError('exact committed read-only program required')
    private=BASE/'litellm-r8-fresh-before-01.private.json';public=BASE/'litellm-r8-fresh-before-01.json'
    if private.exists() or public.exists():raise ValueError('unique capture required')
    guard_path=LAB/'run/focus_acceptance_ui.json';guard_raw=guard_path.read_bytes();guard=json.loads(guard_raw)
    native_path=BASE/'r8-page5-native.json';native_raw=native_path.read_bytes();native=json.loads(native_raw)
    if (guard['phase']!='complete' or guard['baseline_restored'] is not True or guard['recovery_verified'] is not True
            or guard['inflight'] is not None or guard['source_commit']!=PRODUCT or native['exit']!=0):
        raise ValueError('R8 terminal original return required')
    s=os.statvfs(REPO)
    available=next(int(r.split()[1]) for r in Path('/proc/meminfo').read_text().splitlines() if r.startswith('MemAvailable:'))
    if s.f_bavail*s.f_frsize<13*1024**3+512*1024**2 or available<1200*1024:raise ValueError('host metadata floor')
    fd=os.open('/tmp/woowbk-dev-d-mutation.lock',os.O_RDWR|os.O_NOFOLLOW)
    try:
        if Path('/tmp/woowbk-dev-d-emqx-main-waiting').exists():raise ValueError('priority pending')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        lp=str(LAB/'bin/labpodman')
        isolation=subprocess.run([lp,'inspect','woowbk-dev-d','--format',
            '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}'],capture_output=True,timeout=30)
        if isolation.returncode or isolation.stdout.strip()!=b'true none {}':raise ValueError('outer isolation')
        script=program();compile(script,'<read-only fixed metadata>','exec')
        p=subprocess.run([lp,'exec','-i','woowbk-dev-d','timeout','--signal=TERM','--kill-after=30s','480s',
            'python3','-B','-I','-c',script],capture_output=True,timeout=540)
        samples=[]
        for row in p.stdout.splitlines():
            try:samples.append(json.loads(row))
            except ValueError:pass
        capture={'program_commit':head,'frozen_helpers':FROZEN,'source_commit':PRODUCT,
            'r8_guard_sha256':sha(guard_raw),'r8_native_sha256':sha(native_raw),
            'r8_markers_sha256':sha(canonical(guard['before_markers'])),
            'r8_evidence_dir':guard['evidence_dir'],'r8_original_images':guard['original_images'],
            'r8_original_unit_metadata':guard['original_unit_metadata'],
            'transport_returncode':p.returncode,'samples':samples,'private_stderr_b64':__import__('base64').b64encode(p.stderr[:16384]).decode()}
        exclusive(private,canonical(capture)) # retain ALL complete samples BEFORE assertions/diff
        if not samples:raise ValueError('no complete sample; private transport diagnostic retained')
        old=json.loads((BASE/'litellm-instance-images-verify-01.capture.private.json').read_text())['facts']
        prior=json.loads((BASE/'litellm-source-baseline-01.private.json').read_text())['private_result']['baseline']
        last=samples[-1];current=last['current'];hashes={}
        names=subprocess.check_output(['git','-C',str(REPO),'ls-tree','-r','--name-only',PRODUCT,'--','backup-engine/woowbackup'],text=True,timeout=30).splitlines()
        for name in names:hashes[name.removeprefix('backup-engine/woowbackup/')]=sha(blob(PRODUCT,name))
        hashes['../woowtech-cockpit-backup']=sha(blob(PRODUCT,'backup-engine/woowtech-cockpit-backup'))
        hashes['VERSION']=sha(blob(PRODUCT,'VERSION'))
        out={'private_sha256':sha(canonical(capture)),'sample_count':len(samples),'transport_returncode':p.returncode,
            'candidate_baseline_sha256':sha(canonical({k:current[k] for k in old['current']})),
            'old_image_inventory_diff':diff(old['current'],{k:current[k] for k in old['current']}),
            'old_source_snapshot_diff':diff(prior,current),'source53_exact':last['engine_hashes']==hashes,
            'image_configs_exact':last['configs']==old['configs'],'actual_container_names':sorted(current['containers']),
            'selected8_image_bindings_exact':all(current['selected'][name]['image']==guard['original_images'][name] for name in NAMES),
            'selected_sourcepath_bindings_exact':all(last['bindings'][name]['unit'].get('SourcePath')==current['selected'][name]['quadlet']
                and last['bindings'][name]['source_meta']==old['current']['files'][current['selected'][name]['quadlet']] for name in NAMES),
            'active_job_count':len(current['active_jobs']),'headscale_fixed_state':last['headscale'],
            'r8_guard_sha256':sha(guard_raw),'r8_native_sha256':sha(native_raw),'approval_required':True}
        exclusive(public,canonical(out));print(json.dumps(out),flush=True)
    finally:os.close(fd)


if __name__=='__main__':main()
