#!/usr/bin/env python3
"""Offline by default; leased source-only install/recovery for stopped dev-c.

Payload is exactly frozen d09 engine *.py + VERSION + helper. No installer,
package manager, catalog, key initialization, daemon reload or app wakeup.
"""
import argparse
import base64
from datetime import datetime,timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import focus_n8n_instance_acceptance as plan
import focus_n8n_instance_acceptance_ops as common
import focus_n8n_instance_acceptance_source_ops as remote
from focus_n8n_instance_acceptance_run import save_receipt

REPO=HERE.parents[2]
PHASES=('source-install','source-recover')
BOUNDS={'host_available_mib':1200,'host_reserve_gib':13,'host_write_budget_gib':8,
        'device_headroom_mib':1900,'recovery_reserve_seconds':600,'operation_timeout_seconds':300}


def git(root,*args):
    return subprocess.check_output(['git','-C',str(root),*args],text=True,timeout=30).strip()


def manifest_sha(payload):
    return hashlib.sha256(json.dumps(payload['sha256'],sort_keys=True,separators=(',',':')).encode()).hexdigest()


def payload(source):
    source=Path(source)
    if git(source,'rev-parse','HEAD')!=remote.FROZEN or git(source,'status','--porcelain'):
        raise ValueError('exact clean frozen product source required')
    files={}
    for p in sorted((source/'backup-engine/woowbackup').rglob('*')):
        if '__pycache__' in p.parts:continue
        if p.is_symlink():raise ValueError('source symlink')
        if p.is_file():
            if p.suffix!='.py':raise ValueError('unexpected engine payload file')
            name=p.relative_to(source/'backup-engine').as_posix()
            files[name]=common.read_regular(p,remote.MAX_BYTES)[0]
    files['VERSION']=common.read_regular(source/'VERSION')[0]
    helper=common.read_regular(source/'backup-engine/woowtech-cockpit-backup')[0]
    result={'source_commit':remote.FROZEN,'files':{n:base64.b64encode(b).decode() for n,b in files.items()},
            'helper':base64.b64encode(helper).decode(),
            'sha256':{n:common.digest(b) for n,b in files.items()}|{'helper':common.digest(helper)}}
    remote.decode_payload(result)
    return result


def validate(lease,phase,*,driver,source_payload,image_receipt,now):
    if (lease.get('granted') is not True or lease.get('device')!=plan.DEVICE or lease.get('case')!='n8n-instance-source'
        or phase not in lease.get('phases',[]) or lease.get('driver_commit')!=driver
        or lease.get('source_commit')!=remote.FROZEN or lease.get('name')!=image_receipt.get('name')
        or not common.BASE.fullmatch(lease.get('name','')) or image_receipt.get('images_ready') is not True
        or set(image_receipt.get('owned_images',[]))!=set(plan.ARCHIVES)
        or lease.get('source_manifest_sha256')!=manifest_sha(source_payload) or lease.get('bounds')!=BOUNDS
        or lease.get('protected_capture_sha256')!=plan.sha(REPO/'snippets'/plan.AREA/'protected-baselines-readonly.json')):
        raise ValueError('source lease/source/image ownership binding mismatch')
    expiry=datetime.fromisoformat(lease['expires_utc']).timestamp()
    if now>=expiry or expiry-now>2400 or now<datetime.fromisoformat(lease['not_before_utc']).timestamp():
        raise ValueError('source lease outside bounded time')
    return expiry


def program():
    # Fixed committed common operations are imported from memory, never installed.
    common_source=(HERE/'focus_n8n_instance_acceptance_ops.py').read_text()
    prelude=("import sys,types;sys.dont_write_bytecode=True;sys.pycache_prefix='/nonexistent/woowbk-focus-n8n-pycache'\n"
             "_m=types.ModuleType('focus_n8n_instance_acceptance_ops');sys.modules[_m.__name__]=_m\n"
             "exec(compile("+repr(common_source)+",'<fixed common operations>','exec'),_m.__dict__)\n")
    return prelude+(HERE/'focus_n8n_instance_acceptance_source_ops.py').read_text()


def invoke(h,request):
    p=h.root('python3','-B','-I','-c',program(),input=json.dumps(request).encode(),timeout=BOUNDS['operation_timeout_seconds'])
    if p.returncode:
        try:
            err=json.loads(p.stderr)
            kind=err['error_class'] if set(err)=={'error_class'} and err['error_class'].isalpha() else 'FixedSourceError'
        except Exception:kind='FixedSourceError'
        raise RuntimeError(kind)
    return json.loads(p.stdout)


def resources(h,expiry,*,recovering=False,write_budget_bytes=None):
    if time.time()+(0 if recovering else BOUNDS['recovery_reserve_seconds'])>=expiry:
        raise TimeoutError('source recovery reserve reached')
    available=next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
    s=os.statvfs(REPO)
    budget=BOUNDS['host_write_budget_gib']*1024**3 if write_budget_bytes is None else write_budget_bytes
    if type(budget) is not int or budget<0:raise ValueError('invalid source write budget')
    if available<1200*1024 or s.f_bavail*s.f_frsize<13*1024**3+budget:raise RuntimeError('source host resource floor')
    p=h.root('python3','-B','-I','-c',"from pathlib import Path;import json;s=Path('/sys/fs/cgroup/memory.stat').read_text().splitlines();u=sum(int(x.split()[1]) for x in s if x.startswith(('anon ','kernel ')));print(json.dumps(int(Path('/sys/fs/cgroup/memory.max').read_text())-u))",timeout=30)
    if p.returncode or json.loads(p.stdout)<1900*1024**2:raise RuntimeError('source device resource floor')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true');parser.add_argument('--phase',choices=PHASES)
    parser.add_argument('--source',type=Path);parser.add_argument('--lease',type=Path)
    parser.add_argument('--receipt',type=Path);parser.add_argument('--image-receipt',type=Path)
    args=parser.parse_args(argv)
    if not args.execute:
        compile(program(),'<fixed source transaction>','exec')
        print(json.dumps({'stage':'source_controller_offline','device_access':False,'phases':PHASES}));return 0
    if not all((args.phase,args.source,args.lease,args.receipt,args.image_receipt)):
        parser.error('--execute needs phase/source/lease/receipt/image-receipt')
    driver=git(REPO,'rev-parse','HEAD')
    if git(REPO,'status','--porcelain'):raise ValueError('committed clean driver required')
    source_payload=payload(args.source);lease=json.loads(args.lease.read_text())
    raw,meta=common.read_regular(args.image_receipt)
    if meta['uid']!=os.geteuid() or meta['mode']!=0o600:raise ValueError('unsafe image receipt')
    image_receipt=json.loads(raw)
    expiry=validate(lease,args.phase,driver=driver,source_payload=source_payload,image_receipt=image_receipt,now=time.time())
    import ha_import_e2e as h
    h.DEVICE=plan.DEVICE;h.require_isolated_device()
    lock=os.open(plan.LOCK,os.O_RDWR|os.O_NOFOLLOW)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        resources(h,expiry,recovering=args.phase=='source-recover')
        receipt={'driver_commit':driver,'source_commit':remote.FROZEN,'name':lease['name'],'phase':args.phase,
                 'source_manifest_sha256':manifest_sha(source_payload),'intent':True,'completed':False}
        if args.receipt.exists():
            prior,pmeta=common.read_regular(args.receipt)
            if pmeta['uid']!=os.geteuid() or pmeta['mode']!=0o600 or json.loads(prior)['name']!=lease['name']:
                raise ValueError('foreign source receipt')
            if args.phase=='source-install':raise ValueError('source install is never replayed; inspect/recover first')
            receipt['prior_receipt_sha256']=common.digest(prior)
        save_receipt(args.receipt,receipt)
        request={'case':lease['name'],'phase':args.phase,'protected':plan.reviewed_baselines()}
        if args.phase=='source-install':request['payload']=source_payload
        try:
            result=invoke(h,request)
            if args.phase=='source-install' and (result['source_hashes']|{'helper':result['helper_sha256']})!=source_payload['sha256']:
                raise RuntimeError('installed fixed source hash mismatch')
            receipt.update(completed=True,result=result);save_receipt(args.receipt,receipt)
            print(json.dumps({'stage':'source_phase_complete','phase':args.phase,'source_installed':result['source_installed'],
                              'source_restored':result['source_restored'],'source_files':len(result['source_hashes']),
                              'durable_equal':result['durable_equal'],'protected_equal':result['protected_equal']}));return 0
        except Exception as error:
            receipt['failure_class']=type(error).__name__;save_receipt(args.receipt,receipt)
            if args.phase=='source-install' and 'source-recover' in lease['phases']:
                try:
                    resources(h,expiry,recovering=True)
                    receipt['recovery']=invoke(h,dict(request,phase='source-recover'))
                except Exception as recovery:receipt['recovery_failure_class']=type(recovery).__name__
                save_receipt(args.receipt,receipt)
            print(json.dumps({'stage':'source_phase_failed','phase':args.phase,'failure_class':type(error).__name__,
                              'recovery_verified':receipt.get('recovery',{}).get('source_restored') is True}));return 1
    finally:os.close(lock)


if __name__=='__main__':raise SystemExit(main())
