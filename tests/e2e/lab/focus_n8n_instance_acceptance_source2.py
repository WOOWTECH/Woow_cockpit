#!/usr/bin/env python3
"""NEW source2 namespace/lease/receipt. Offline default; no source1 replay."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import focus_n8n_instance_acceptance_source as previous
import focus_n8n_instance_acceptance_source2_ops as ops

PHASES=('source2-install','source2-recover')
CASE='n8n-instance-source-attempt2'
METHOD='samefs-per-file-os.replace-journal-v3'
REPO=previous.REPO


def program():
    text="import sys,types;sys.dont_write_bytecode=True;sys.pycache_prefix='/nonexistent/woowbk-focus-n8n-source2-pycache'\n"
    for name in ('focus_n8n_instance_acceptance_ops','focus_n8n_instance_acceptance_source_ops'):
        raw=(HERE/(name+'.py')).read_text()
        text+=("_m=types.ModuleType("+repr(name)+");sys.modules[_m.__name__]=_m\n"
               "exec(compile("+repr(raw)+",'<fixed readonly dependencies>','exec'),_m.__dict__)\n")
    return text+(HERE/'focus_n8n_instance_acceptance_source2_ops.py').read_text()


def validate(lease,phase,driver,payload,image,now):
    # Reuse the previously reviewed hash/time/image/bounds validator, with an
    # explicit source2 contract. It never sees a source1 lease as authorization.
    if (lease.get('case')!=CASE or lease.get('method')!=METHOD or phase not in lease.get('phases',[])
            or not set(lease['phases'])<=set(PHASES)):
        raise ValueError('source2 exact phase/method required')
    transformed=dict(lease,case='n8n-instance-source',phases=['source-install' if p=='source2-install' else 'source-recover'
                                                         for p in lease['phases']])
    return previous.validate(transformed,'source-install' if phase=='source2-install' else 'source-recover',
        driver=driver,source_payload=payload,image_receipt=image,now=now)


def invoke(h,request):
    p=h.root('python3','-B','-I','-c',program(),input=json.dumps(request).encode(),timeout=300)
    # The complete fixed error response stays in a private host receipt. Public
    # capture emits only success/failure, never inner class/errno/foreign strings.
    try:result=json.loads(p.stdout)
    except Exception:return {'ok':False,'private_error_class':'InvalidFixedResponse','private_errno':None,'private_stage':'transport'}
    if p.returncode and result.get('ok') is True:
        return {'ok':False,'private_error_class':'TransportExit','private_errno':None,'private_stage':'transport'}
    return result


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--execute',action='store_true');p.add_argument('--phase',choices=PHASES)
    p.add_argument('--source',type=Path);p.add_argument('--lease',type=Path);p.add_argument('--receipt',type=Path)
    p.add_argument('--image-receipt',type=Path);args=p.parse_args(argv)
    if not args.execute:
        compile(program(),'<source2 program>','exec')
        print(json.dumps({'stage':'source2_offline','device_access':False}));return 0
    if not all((args.phase,args.source,args.lease,args.receipt,args.image_receipt)):p.error('all source2 arguments required')
    driver=previous.git(REPO,'rev-parse','HEAD')
    if previous.git(REPO,'status','--porcelain'):raise ValueError('clean committed source2 required')
    payload=previous.payload(args.source);lease=json.loads(args.lease.read_text())
    raw,meta=previous.common.read_regular(args.image_receipt)
    if meta['uid']!=os.geteuid() or meta['mode']!=0o600:raise ValueError('private image receipt required')
    expiry=validate(lease,args.phase,driver,payload,json.loads(raw),time.time())
    # Explicitly refuse the immutable source1 host receipt even on recover.
    if args.receipt.name!='focus_n8n_instance_source2.json':raise ValueError('new source2 receipt name required')
    if args.receipt.exists():
        old,meta=previous.common.read_regular(args.receipt)
        if meta['uid']!=os.geteuid() or meta['mode']!=0o600 or json.loads(old)['name']!=lease['name']:
            raise ValueError('foreign source2 receipt')
        if args.phase=='source2-install':raise ValueError('never replay source2 install')
    import ha_import_e2e as h
    h.DEVICE=previous.plan.DEVICE;h.require_isolated_device()
    lock=os.open(previous.plan.LOCK,os.O_RDWR|os.O_NOFOLLOW)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        previous.resources(h,expiry,recovering=args.phase=='source2-recover')
        receipt={'driver_commit':driver,'name':lease['name'],'phase':args.phase,'method':METHOD,
                 'manifest_sha256':previous.manifest_sha(payload),'intent':True,'completed':False}
        previous.save_receipt(args.receipt,receipt)
        request={'case':lease['name'],'phase':args.phase,'protected':previous.plan.reviewed_baselines()}
        if args.phase=='source2-install':request['payload']=payload
        result=invoke(h,request);receipt['private_result']=result
        previous.save_receipt(args.receipt,receipt)  # preserve exact inner diagnostics before any later check
        if result.get('ok') is True and args.phase=='source2-install' and result['source_sha256']!=payload['sha256']:
            result={'ok':False,'private_error_class':'HashMismatch','private_errno':None,'private_stage':'host_hash_validation'}
            receipt['private_result']=result
        previous.resources(h,expiry,recovering=True)
        receipt['completed']=result.get('ok') is True;previous.save_receipt(args.receipt,receipt)
        print(json.dumps({'stage':'source2_phase_result','phase':args.phase,'ok':receipt['completed']}))
        return 0 if receipt['completed'] else 1
    except Exception as error:
        # Keep transport class privately too. No source1 mutation/fallback/retry.
        if 'receipt' in locals():
            receipt['private_transport_error_class']=type(error).__name__;previous.save_receipt(args.receipt,receipt)
        print(json.dumps({'stage':'source2_phase_result','phase':args.phase,'ok':False}));return 1
    finally:os.close(lock)


if __name__=='__main__':raise SystemExit(main())
