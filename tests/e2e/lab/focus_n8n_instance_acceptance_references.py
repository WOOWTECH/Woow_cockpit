#!/usr/bin/env python3
"""Offline by default. Separate leased two-reference prep; no loads or pulls."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import time
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import focus_n8n_instance_acceptance_run as run
import focus_n8n_instance_acceptance_references_ops as refs

PHASES=('image-references','image-references-reconcile')
CASE='n8n-instance-image-references'


def dependencies():
    text="import sys,types;sys.dont_write_bytecode=True;sys.pycache_prefix='/nonexistent/woowbk-focus-n8n-references-pycache'\n"
    for name in ('focus_n8n_instance_acceptance_ops','focus_n8n_instance_acceptance_source_ops',
                 'focus_n8n_instance_acceptance_safeties','focus_n8n_instance_acceptance_references_ops'):
        raw=(HERE/(name+'.py')).read_text()
        text+=("_m=types.ModuleType("+repr(name)+");sys.modules[_m.__name__]=_m\n"
               "exec(compile("+repr(raw)+",'<fixed reference dependencies>','exec'),_m.__dict__)\n")
    return text


ENTRY='''
import json,os,re
q={}
try:
 q=json.loads(sys.stdin.buffer.read(1024*1024+1))
 result=sys.modules['focus_n8n_instance_acceptance_references_ops'].dispatch(q)
 print(json.dumps({'ok':True,'result':result}))
except Exception as e:
 print(json.dumps({'ok':False,'private_stage':q.get('op'),'private_error_class':type(e).__name__,
  'private_errno':e.errno if isinstance(e,OSError) else None,
  'private_fixed_code':str(e) if isinstance(e,ValueError) and re.fullmatch('fixed-reference-[a-z-]+',str(e)) else None}))
 raise SystemExit(1)
'''


def validate(lease,phase,driver,source,now):
    if (lease.get('case')!=CASE or phase not in PHASES or
            not set(lease.get('phases',[]))<=set(PHASES) or
            lease.get('expected_references')!=refs.EXPECTED or lease.get('allowed_new_references')!=refs.ALLOWED or
            lease.get('source_fullflow_receipt_sha256')!=refs.SOURCE_RECEIPT_SHA or
            lease.get('bounds')!=run.BOUNDS or lease.get('image_policy')!='retain-for-case'):
        raise ValueError('exact reference-prep contract required')
    return run.validate_lease(dict(lease,case='n8n-instance-original'),phase,
        now=now,driver_commit=driver,source_commit=source)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true')
    parser.add_argument('--phase',choices=PHASES)
    for name in ('lease','source','receipt'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args(argv)
    if not args.execute:
        compile(dependencies()+ENTRY,'<fixed reference program>','exec')
        print(json.dumps({'stage':'reference_prep_offline','device_access':False}));return 0
    if not all((args.phase,args.lease,args.source,args.receipt)):parser.error('explicit phase/lease/source/receipt required')
    if args.receipt.name!='focus_n8n_instance_acceptance.references.json': raise ValueError('separate reference receipt required')
    lease=json.loads(args.lease.read_bytes());driver=run.git(run.REPO,'rev-parse','HEAD')
    validate(lease,args.phase,driver,run.git(args.source,'rev-parse','HEAD'),time.time())
    if run.git(run.REPO,'status','--porcelain') or run.git(args.source,'status','--porcelain'):
        raise ValueError('clean exact reference driver/source required')
    import ha_import_e2e as h
    h.DEVICE=run.plan.DEVICE;h.require_isolated_device()
    fd=os.open(run.plan.LOCK,os.O_RDWR|os.O_NOFOLLOW)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.phase==PHASES[0] and args.receipt.exists(): raise ValueError('new reference receipt required')
        controller=run.Controller(SimpleNamespace(source=args.source,receipt=args.receipt),lease,h)
        controller.r['reference_driver']=driver;controller.save()
        def invoke(op,**kw):
            controller.r['reference_operation']=op;controller.save()
            p=h.root('python3','-B','-I','-c',dependencies()+ENTRY,
                input=json.dumps(dict(kw,op=op,case=lease['name'])).encode(),timeout=180)
            try: reply=json.loads(p.stdout)
            except (ValueError,UnicodeError):
                reply={'ok':False,'private_error_class':'InvalidFixedResponse','private_stage':op,
                    'stdout_sha256':run.hashlib.sha256(p.stdout).hexdigest(),
                    'stderr_sha256':run.hashlib.sha256(p.stderr).hexdigest(),'returncode':p.returncode}
            # Save the full fixed private response BEFORE any assertion/cleanup.
            controller.r.setdefault('reference_responses',[]).append(reply);controller.save()
            if p.returncode or reply.get('ok') is not True: raise RuntimeError('fixed reference operation refused')
            return reply['result']
        try:
            controller.resources();controller.frozen_engine()
            if args.phase==PHASES[0]:
                first=invoke('reference-snapshot')
                for ref in first['planned']:
                    controller.resources();invoke('reference-bind',reference=ref)
            result=invoke('reference-reconcile')
            controller.require('references_protected_state_exact',result['protected_state_exact'])
            controller.require('references_complete',result['complete'])
            controller.r['reference_result']=result;controller.save()
            print(json.dumps({'stage':'references_complete','approved_aliases':len(result['applied']),
                'retain_for_case':True,'source_or_services_changed':False}));return 0
        except Exception as e:
            controller.r['reference_failure_class']=type(e).__name__
            controller.r['reference_failure_errno']=e.errno if isinstance(e,OSError) else None;controller.save()
            print(json.dumps({'stage':'references_failed','failure_class':type(e).__name__}));return 1
    finally:os.close(fd)


if __name__=='__main__':raise SystemExit(main())
