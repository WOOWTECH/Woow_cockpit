#!/usr/bin/env python3
"""One separately leased, read-only image verification; never rebuild/rebase."""
import argparse
from datetime import datetime,timezone
import fcntl
import json
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import focus_litellm_instance_acceptance_run as driver
import focus_litellm_instance_acceptance_source as source

plan=driver.plan;common=driver.ops
BOUNDS={'reserve_gib':13,'metadata_budget_mib':512,'host_available_mib':1200,
        'device_headroom_mib':1900,'operation_seconds':180,'transport_seconds':240}
METHOD='stored-build-strict-current-no-writes-v1'


def verify(facts,*,before,derived,source_hashes):
    state=facts['state'];build=state['image_build'];current=facts['current'];configs=facts['configs']
    if (not facts['journal_unchanged'] or state['before']!=before or build['before']!=before or not driver.unchanged(build['after'],before)
            or not driver.unchanged(current,before)):
        raise ValueError('original-inventory-diff')
    if (build['verified'] is not True or build['result']['ok'] is not True or build['result']['terminal'] is not True
            or build['unknown_images'] or build['owned_images']!=[derived] or build['iid']!=derived
            or build['derivation_sha256']!=plan.DERIVATION_SHA or facts['engine_hashes']!=source_hashes):
        raise ValueError('stored-build-or-source-proof')
    original=build['configs_before']
    if derived in before['images'] or plan.APP_BASE not in original or set(original)!=set(before['images']):
        raise ValueError('stored-base-proof')
    if (original[plan.APP_BASE]['architecture']!='amd64' or original[plan.APP_BASE]['os']!='linux'
            or original[plan.APP_BASE]['volumes']):raise ValueError('stored-base-config')
    for inventory in (build['after'],current):
        if (set(inventory['images'])!=set(before['images'])|{derived}
                or inventory['image_refs']!=dict(before['image_refs'],**{plan.APP_TAG:derived})):
            raise ValueError('unknown-image-or-tag')
    if set(configs)!=set(original)|{derived} or any(configs[i]!=c for i,c in original.items()):
        raise ValueError('original-image-config-diff')
    c=configs[derived];layers=original[plan.APP_BASE]['layers']
    if (build['configs_after']!=configs or c['case']!=facts['name'] or c['base']!='sha256:'+plan.APP_BASE
            or c['user']!='1000:0' or c['architecture']!='amd64' or c['os']!='linux'
            or c['volumes'] or c['layers'][:len(layers)]!=layers):
        raise ValueError('derived-image-config-label-or-layers')
    return True


def program():
    raw=(HERE/'focus_litellm_instance_acceptance_ops.py').read_text()
    return ("import sys,types;sys.dont_write_bytecode=True;sys.pycache_prefix='/nonexistent/ll-images-verify-cache'\n"
        "m=types.ModuleType('ll_verify_ops');exec(compile("+repr(raw)+",'<frozen image ops>','exec'),m.__dict__)\n"+r'''
import json,os
from datetime import datetime,timezone
from pathlib import Path
q=json.load(sys.stdin)
if os.geteuid()!=0 or not m.BASE.fullmatch(q['name']):raise ValueError('case/root')
free={p:os.statvfs(p).f_bavail*os.statvfs(p).f_frsize for p in
      ('/home/appowner','/var/lib/woowtech-backup','/var/lib/woowtech-backup/staging')}
rows=Path('/sys/fs/cgroup/memory.stat').read_text().splitlines()
used=sum(int(r.split()[1]) for r in rows if r.startswith(('anon ','kernel ')))
headroom=int(Path('/sys/fs/cgroup/memory.max').read_text())-used
if min(free.values())<13*1024**3+512*1024**2 or headroom<1900*1024**2:raise ValueError('metadata resource floor')
store=m.Store(q['name']);p=store.path/'state.json';prior=m.read_regular(p)[1]
configs=m.image_configs();current=m.inventory()
engine={('helper' if n=='../woowtech-cockpit-backup' else 'woowbackup/'+n):v for n,v in m.engine_hashes().items()}
engine['VERSION']=m.read_regular('/usr/local/lib/woowtech-cockpit-backup/VERSION')[1]['sha256']
print(json.dumps({'name':q['name'],'state':store.state,'current':current,'configs':configs,
 'engine_hashes':engine,'root_journal_meta':prior,'free_bytes':free,'headroom':headroom,
 'journal_unchanged':m.read_regular(p)[1]==prior,
 'captured_utc':datetime.now(timezone.utc).isoformat()}))
''')


def exclusive(path,value):
    raw=source.ops.canonical(value)
    if len(raw)>8*1024**2:raise ValueError('verification receipt bound')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
    return common.digest(raw)


def validate(lease,args,commit):
    if (lease.get('granted') is not True or lease.get('case')!='litellm-instance-images-verify'
            or lease.get('device')!=plan.DEVICE or lease.get('driver_commit')!=commit
            or lease.get('source_commit')!=plan.FROZEN_PRODUCT or lease.get('phases')!=['images-verify']
            or lease.get('method')!=METHOD
            or not plan.CASE.fullmatch(lease.get('name','')) or lease.get('bounds')!=BOUNDS
            or lease.get('derivation_sha256')!=plan.DERIVATION_SHA
            or not plan.SHA256.fullmatch(lease.get('baseline_sha256',''))
            or not plan.SHA256.fullmatch(lease.get('derived_image',''))
            or lease.get('capture_filename')!=args.capture.name or lease.get('output_filename')!=args.output.name):
        raise ValueError('exact verification lease required')
    expiry=datetime.fromisoformat(lease['expires_utc'])
    if expiry.tzinfo is None or not time.time()+60<expiry.timestamp()<=time.time()+45*60:
        raise ValueError('verification lease time')


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--execute',action='store_true');p.add_argument('--lease',type=Path)
    p.add_argument('--receipt',type=Path);p.add_argument('--capture',type=Path);p.add_argument('--output',type=Path)
    a=p.parse_args(argv)
    if not a.execute:
        compile(program(),'<read-only verification>','exec')
        print(json.dumps({'stage':'images_verify_offline','device_access':False,'bounds':BOUNDS}));return 0
    if not all((a.lease,a.receipt,a.capture,a.output)):p.error('lease/receipt/capture/output required')
    commit=source.git('rev-parse','HEAD');lease=json.loads(common.read_regular(a.lease)[0]);validate(lease,a,commit)
    if source.git('status','--porcelain') or any(os.path.lexists(x) for x in (a.capture,a.output)):
        raise ValueError('clean committed driver and unique attempt paths required')
    if (driver.git('/tmp/parity-focus-final-product-20261127','rev-parse','HEAD')!=plan.FROZEN_PRODUCT
            or driver.git('/tmp/parity-focus-final-product-20261127','status','--porcelain')):
        raise ValueError('clean frozen product source required')
    raw,meta=common.read_regular(a.receipt,8*1024**2);r=json.loads(raw)
    if (meta['uid']!=os.geteuid() or meta['mode']!=0o600 or r['name']!=lease['name']
            or r['device']!=plan.DEVICE or r.get('install_intent') or r.get('images_ready')
            or r.get('derived_image')!=lease['derived_image']
            or common.digest(source.ops.canonical(r['before']))!=lease['baseline_sha256']):
        raise ValueError('original case receipt/baseline required')
    s=os.statvfs(plan.REPO)
    available=next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
    if s.f_bavail*s.f_frsize<13*1024**3+512*1024**2 or available<1200*1024:raise ValueError('host metadata floor')
    import ha_import_e2e as h
    h.DEVICE=plan.DEVICE
    if source.PRIORITY.exists():raise ValueError('priority lane pending')
    fd=os.open(source.LOCK,os.O_RDWR|os.O_NOFOLLOW)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if source.PRIORITY.exists():raise ValueError('priority lane pending')
        validate(lease,a,commit);h.require_isolated_device()
        result=h.root('timeout','--signal=TERM','--kill-after=30s','180s','python3','-B','-I','-c',program(),
                      input=source.ops.canonical({'name':r['name']}),timeout=240)
        capture={'phase':'images-verify','driver_commit':commit,'case_receipt_sha256':common.digest(raw),
                 'case_receipt_meta':meta,'case_receipt_before':r,'transport_rc':result.returncode}
        try:capture['facts']=json.loads(result.stdout)
        except Exception:capture['private_error_class']='InvalidFixedResponse'
        # Immutable full current inventory + actual stored proof precede EVERY
        # proof assertion. A failed sample can never disappear as images01 did.
        capture_sha=exclusive(a.capture,capture)
        out={'phase':'images-verify','ok':False,'capture_sha256':capture_sha,'images01_preserved':True}
        try:
            if result.returncode:raise ValueError('metadata capture failed')
            facts=capture['facts']
            verify(facts,before=r['before'],derived=r['derived_image'],source_hashes=source.payload()['sha256'])
            current_raw,current_meta=common.read_regular(a.receipt,8*1024**2)
            if current_raw!=raw or current_meta!=meta:raise ValueError('case receipt CAS changed')
            r['images_ready']=True
            r['images_verification']={'phase':'images-verify','capture_sha256':capture_sha,
                'driver_commit':commit,'current_inventory_sha256':common.digest(source.ops.canonical(facts['current'])),
                'derived_image':r['derived_image'],'captured_utc':facts['captured_utc']}
            driver.save_receipt(a.receipt,r)
            out.update(ok=True,images_ready=True,derived_image=r['derived_image'])
        except Exception as error:out['fixed_error_class']=type(error).__name__
        exclusive(a.output,out);print(json.dumps(out));return 0 if out['ok'] else 1
    finally:os.close(fd)


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        print(json.dumps({'phase':'images-verify','ok':False,'error':'verification stopped; preserve receipt'}));raise SystemExit(1)
