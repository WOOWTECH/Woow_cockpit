#!/usr/bin/env python3
"""Offline by default. Separate exact lease for a dev-d SOURCE-ONLY phase."""
import argparse
import base64
from datetime import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import focus_litellm_instance_acceptance_source_ops as ops

REPO=HERE.parents[2]
DEVICE='woowbk-dev-d'
LOCK='/tmp/woowbk-dev-d-mutation.lock'
PRIORITY=Path('/tmp/woowbk-dev-d-emqx-main-waiting')
PHASES=('source-snapshot','source-install','source-recover')
METHOD='per-file-os.replace-whole-prior-cas-v1'
BOUNDS={'operation_seconds':300,'kill_after_seconds':45,'transport_seconds':390,
        'recovery_reserve_seconds':600,'host_available_mib':1200,'device_headroom_mib':1900,
        'free_reserve_gib':13,'write_budget_mib':512}


def git(*args,raw=False):
    b=subprocess.check_output(['git','-C',str(REPO),*args],timeout=30)
    return b if raw else b.decode().strip()


def source_files(commit):
    if git('rev-parse',commit)!=commit:raise ValueError('source-full-commit-required')
    names=git('ls-tree','-r','--name-only',commit,'--','backup-engine/woowbackup').splitlines()
    if not names or any(not ops.PY.fullmatch(n.removeprefix('backup-engine/')) for n in names):
        raise ValueError('source-git-members')
    mapping={n.removeprefix('backup-engine/'):n for n in names}
    mapping.update(VERSION='VERSION',helper='backup-engine/woowtech-cockpit-backup')
    result={}
    for name,path in mapping.items():
        row=git('ls-tree',commit,'--',path).split()
        if len(row)!=4 or row[0] not in ('100644','100755') or row[1]!='blob':raise ValueError('source-git-regular-file')
        result[name]=git('show',commit+':'+path,raw=True)
    return result


def payload():
    files=source_files(ops.NEW)
    result={'source_commit':ops.NEW,'mtime_ns':int(git('show','-s','--format=%ct',ops.NEW))*10**9,
            'files':{n:base64.b64encode(b).decode() for n,b in files.items()},
            'sha256':{n:ops.digest(b) for n,b in files.items()}}
    ops.decode(result);return result


def bindings():
    p=payload();old={n:ops.digest(b) for n,b in source_files(ops.OLD).items()}
    return p,old,{'old_commit':ops.OLD,'new_commit':ops.NEW,
        'old_manifest_sha256':ops.digest(ops.canonical(old)),
        'new_manifest_sha256':ops.digest(ops.canonical(p['sha256'])),
        'payload_sha256':ops.digest(ops.canonical(p))}


def program():
    # The image controller files remain byte-for-byte frozen. Load its existing
    # atomic/read primitives into memory; install none of this harness on device.
    name='focus_litellm_instance_acceptance_ops'
    raw=(HERE/(name+'.py')).read_text()
    prelude=("import sys,types;sys.dont_write_bytecode=True;sys.pycache_prefix='/nonexistent/woowbk-focus-ll-source-cache'\n"
        "_m=types.ModuleType("+repr(name)+");sys.modules[_m.__name__]=_m\n"
        "exec(compile("+repr(raw)+",'<frozen LL primitives>','exec'),_m.__dict__)\n")
    return prelude+(HERE/'focus_litellm_instance_acceptance_source_ops.py').read_text()


def validate(lease,phase,driver,bound,now):
    if (lease.get('granted') is not True or lease.get('case')!='litellm-instance-source'
            or lease.get('device')!=DEVICE or lease.get('method')!=METHOD
            or not ops.CASE.fullmatch(lease.get('name',''))
            or lease.get('driver_commit')!=driver or not re.fullmatch(r'[0-9a-f]{40}',driver)
            or not isinstance(lease.get('phases'),list) or phase not in lease['phases']
            or not set(lease['phases'])<=set(PHASES) or lease.get('bounds')!=BOUNDS
            or any(lease.get(k)!=v for k,v in bound.items())
            or phase!='source-snapshot' and not re.fullmatch(r'[0-9a-f]{64}',lease.get('baseline_sha256',''))):
        raise ValueError('source-exact-lease-required')
    start=datetime.fromisoformat(lease['not_before_utc']);end=datetime.fromisoformat(lease['expires_utc'])
    if start.tzinfo is None or end.tzinfo is None or not start.timestamp()<=now<end.timestamp()<=now+45*60:
        raise ValueError('source-bounded-lease-time')
    return end.timestamp()


def resources(expiry,recovering):
    if time.time()+(0 if recovering else BOUNDS['recovery_reserve_seconds'])>=expiry:
        raise TimeoutError('source-recovery-reserve')
    available=next(int(r.split()[1]) for r in Path('/proc/meminfo').read_text().splitlines() if r.startswith('MemAvailable:'))
    s=os.statvfs(REPO)
    if available<1200*1024 or s.f_bavail*s.f_frsize<13*1024**3+512*1024**2:
        raise RuntimeError('source-host-resource-floor')


def private_read(path):
    raw,meta=ops.common.read_regular(path,8*1024**2)
    if meta['uid']!=os.geteuid() or meta['mode']!=0o600:raise ValueError('source-private-receipt')
    return json.loads(raw)


def save(path,value):
    raw=ops.canonical(value)
    if len(raw)>8*1024**2:raise ValueError('source-receipt-bound')
    ops.common.atomic(path,raw)


def invoke(h,request):
    p=h.root('timeout','--signal=TERM','--kill-after=45s','300s','python3','-B','-I','-c',program(),
             input=ops.canonical(request),timeout=BOUNDS['transport_seconds'])
    try:value=json.loads(p.stdout)
    except Exception:value={'ok':False,'private_error_class':'InvalidFixedResponse','private_errno':None}
    if p.returncode and value.get('ok') is True:value={'ok':False,'private_error_class':'TransportExit','private_errno':None}
    return value


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true');parser.add_argument('--phase',choices=PHASES)
    parser.add_argument('--lease',type=Path);parser.add_argument('--receipt',type=Path)
    parser.add_argument('--output',type=Path);args=parser.parse_args(argv)
    p,old,bound=bindings();compile(program(),'<source-only root program>','exec')
    if not args.execute:
        print(json.dumps(dict(stage='source_offline',device_access=False,files=len(p['files']),method=METHOD,bounds=BOUNDS,**bound)))
        return 0
    if not all((args.phase,args.lease,args.receipt,args.output)):parser.error('execute requires phase/lease/receipt/output')
    driver=git('rev-parse','HEAD')
    if git('status','--porcelain'):raise ValueError('source-clean-committed-driver-required')
    lease=json.loads(ops.common.read_regular(args.lease)[0]);expiry=validate(lease,args.phase,driver,bound,time.time())
    prior=private_read(args.receipt) if args.receipt.exists() else None
    if prior and (prior['name']!=lease['name'] or prior['bindings']!=bound or args.phase!='source-recover'):
        raise ValueError('source-foreign-receipt-or-replayed-install')
    if args.output.exists() or args.output.is_symlink():raise ValueError('source-new-attempt-output-required')
    # Transport import is delayed until exact lease and source validation. No
    # credentials/saved80 import or device access in the default offline path.
    import ha_import_e2e as h
    h.DEVICE=DEVICE;h.require_isolated_device()
    if PRIORITY.exists():raise ValueError('source-priority-lane-pending')
    fd=os.open(LOCK,os.O_RDWR|os.O_NOFOLLOW)
    receipt={'name':lease['name'],'phase':args.phase,'driver_commit':driver,'bindings':bound,
             'baseline_sha256':lease.get('baseline_sha256'),'intent':False,'completed':False,'prior':prior}
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if PRIORITY.exists():raise ValueError('source-priority-lane-pending')
        validate(lease,args.phase,driver,bound,time.time());resources(expiry,args.phase=='source-recover')
        receipt['intent']=True;save(args.receipt,receipt)
        request={'case':lease['name'],'phase':args.phase,'baseline_sha256':lease.get('baseline_sha256'),
                 'old_sha256':old,'payload':p}
        try:
            result=invoke(h,request);receipt['private_result']=result;save(args.receipt,receipt)
            if result.get('ok') is True and args.phase=='source-install' and result.get('hashes')!=p['sha256']:
                raise ValueError('source-host-postcheck-hashes')
            receipt['completed']=result.get('ok') is True
            if not receipt['completed'] and args.phase=='source-install' and 'source-recover' in lease['phases']:
                resources(expiry,True);receipt['private_recovery']=invoke(h,dict(request,phase='source-recover'))
        except Exception as error:
            receipt['private_transport_error_class']=type(error).__name__
            # Lost install response is never replayed. Explicit journal recovery
            # is authorized only by the separate recovery phase in this lease.
            if args.phase=='source-install' and 'source-recover' in lease['phases']:
                try:
                    resources(expiry,True);receipt['private_recovery']=invoke(h,dict(request,phase='source-recover'))
                except Exception as recovery:receipt['private_recovery_error_class']=type(recovery).__name__
        save(args.receipt,receipt)
        public={'stage':'source_phase_result','phase':args.phase,'ok':receipt['completed'],
                'receipt_sha256':ops.digest(ops.common.read_regular(args.receipt,8*1024**2)[0])}
        if args.phase=='source-snapshot' and receipt['completed']:
            public['baseline_sha256']=receipt['private_result']['baseline_sha256']
        out=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(out,'wb') as stream:stream.write(ops.canonical(public));stream.flush();os.fsync(stream.fileno())
        print(json.dumps(public));return 0 if receipt['completed'] else 1
    finally:os.close(fd)


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        print(json.dumps({'stage':'source_phase_stopped','ok':False,'private_receipt_retained':True}));raise SystemExit(1)
