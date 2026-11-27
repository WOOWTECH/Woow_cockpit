#!/usr/bin/env python3
"""Separately leased pause/resume of one already failing lab Headscale unit."""
import argparse
from datetime import datetime,timezone
import fcntl
import json
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import focus_litellm_instance_acceptance_run as driver
import focus_litellm_instance_acceptance_source as source
import focus_litellm_instance_acceptance_images_verify as capture

UNIT='headscale.service'
QFILE='/home/appowner/.config/containers/systemd/headscale.container'
METHOD='known-failed-headscale-pause-resume-v1'
BOUNDS={'reserve_gib':13,'metadata_budget_mib':512,'host_available_mib':1200,
        'device_headroom_mib':1900,'command_seconds':45,'resume_seconds':45,
        'metadata_seconds':60,'transport_seconds':80,'outer_seconds':300}
FIELDS=('Id','LoadState','ActiveState','SubState','Result','NRestarts','MainPID',
        'ExecMainCode','ExecMainStatus','UnitFileState','SourcePath','FragmentPath')


def failure(unit):
    return tuple(unit[k] for k in ('Result','ExecMainCode','ExecMainStatus'))


def known_failure(unit):
    return (unit['ActiveState']=='activating' and unit['SubState']=='auto-restart'
        and unit['Result']=='exit-code' and unit['MainPID']=='0'
        and unit['NRestarts'].isdigit() and int(unit['NRestarts'])>0
        and unit['ExecMainCode']=='1' and unit['ExecMainStatus'].isdigit()
        and 0<int(unit['ExecMainStatus'])<=255)


def binding(facts,baseline,original=None):
    u=facts['unit'];meta=baseline['files'][QFILE]
    if (set(u)!=set(FIELDS) or u['Id']!=UNIT or u['LoadState']!='loaded'
            or u['UnitFileState']!='generated' or u['SourcePath']!=QFILE
            or u['FragmentPath']!=f'/run/user/{meta["uid"]}/systemd/generator/{UNIT}'
            or facts['source']!=meta or not facts['fragment']['sha256']
            or original is not None and facts['fragment']!=original['fragment']):
        raise ValueError('foreign unit/config binding')


def exact_inventory(facts,receipt):
    current=facts['inventory'];before=receipt['before']
    if (not driver.unchanged(current,before)
            or set(current['images'])!=set(before['images'])|{receipt['derived_image']}
            or current['image_refs']!=dict(before['image_refs'],**{driver.plan.APP_TAG:receipt['derived_image']})):
        raise ValueError('strict original inventory differs')


class Protocol:
    def __init__(self,receipt,journal,*,read,act,save,clock=time.monotonic,sleep=time.sleep):
        self.r=receipt;self.j=journal;self.read=read;self.act=act;self.save=save
        self.clock=clock;self.sleep=sleep

    def pause(self):
        if self.j:raise ValueError('pause intent already exists; use resume')
        facts=self.read(True);self.j['initial_observation']=facts;self.save()
        binding(facts,self.r['before']);exact_inventory(facts,self.r)
        if not known_failure(facts['unit']):raise ValueError('unit is not the known failed auto-restart')
        self.j.update(original=facts,pending='pause',paused=False,resumed=False)
        self.save()  # full original metadata + durable obligation BEFORE stop
        latest=self.read(False);self.j['before_stop_recheck']=latest;self.save()
        binding(latest,self.r['before'],facts)
        if latest['unit']!=facts['unit']:raise ValueError('unit changed before pause')
        self.act('stop')
        after=self.read(True);self.j['after_pause']=after;self.save() # retain failed samples too
        binding(after,self.r['before'],facts);exact_inventory(after,self.r)
        if (after['unit']['ActiveState'],after['unit']['SubState'],after['unit']['MainPID'])!=('inactive','dead','0'):
            raise ValueError('pause not proven; resume obligation retained')
        self.j.update(pending=None,paused=True);self.save()

    def resume(self):
        original=self.j['original'];binding(original,self.r['before'])
        if not known_failure(original['unit']):raise ValueError('untrusted original failure state')
        if self.j.get('resumed'):raise ValueError('resume already complete')
        self.j['pending']='resume';self.save()
        facts=self.read(True);self.j['before_resume']=facts;self.save()
        binding(facts,self.r['before'],original);exact_inventory(facts,self.r)
        # Adopt an already returned failure state after a lost stop/start reply.
        # Never replay start while an earlier start is running or uncertain.
        if (facts['unit']['ActiveState'],facts['unit']['SubState'],facts['unit']['MainPID'])==('inactive','dead','0'):
            if self.j.get('start_intent'):raise ValueError('prior start outcome uncertain; intent retained')
            self.j['start_intent']=True;self.save();self.act('start')
        until=self.clock()+BOUNDS['resume_seconds']
        while True:
            facts=self.read(False);binding(facts,self.r['before'],original)
            self.j['last_resume']=facts;self.save()
            if known_failure(facts['unit']) and failure(facts['unit'])==failure(original['unit']):break
            if self.clock()>=until:raise ValueError('as-found failure condition not proven; intent retained')
            self.sleep(1)
        self.j.update(pending=None,resumed=True,paused=False);self.save()


def program():
    raw=(HERE/'focus_litellm_instance_acceptance_ops.py').read_text()
    return ("import sys,types;sys.dont_write_bytecode=True\n"
        "m=types.ModuleType('ll_pause_ops');exec(compile("+repr(raw)+",'<fixed LL metadata>','exec'),m.__dict__)\n"+r'''
import json,os
from pathlib import Path
q=json.load(sys.stdin)
if os.geteuid()!=0 or set(q)!={'inventory'} or type(q['inventory']) is not bool:raise ValueError('fixed read request')
free=min(os.statvfs(p).f_bavail*os.statvfs(p).f_frsize for p in
 ('/home/appowner','/var/lib/woowtech-backup','/var/lib/woowtech-backup/staging'))
rows=Path('/sys/fs/cgroup/memory.stat').read_text().splitlines()
used=sum(int(r.split()[1]) for r in rows if r.startswith(('anon ','kernel ')))
if free<13*1024**3+512*1024**2 or int(Path('/sys/fs/cgroup/memory.max').read_text())-used<1900*1024**2:
 raise ValueError('metadata resource floor')
facts={'inventory':m.inventory()} if q['inventory'] else {}
path='/home/appowner/.config/containers/systemd/headscale.container'
meta=m.read_regular(path)[1]
fragment=f'/run/user/{meta["uid"]}/systemd/generator/headscale.service'
facts.update(source=meta,fragment=m.read_regular(fragment)[1])
fields='Id,LoadState,ActiveState,SubState,Result,NRestarts,MainPID,ExecMainCode,ExecMainStatus,UnitFileState,SourcePath,FragmentPath'
p=m.owner('systemctl','--user','show','headscale.service','--property='+fields)
facts['unit']=dict(line.split('=',1) for line in p.stdout.decode().splitlines() if '=' in line)
facts['observed_utc']=__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()
print(json.dumps(facts))
''')


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--execute',action='store_true')
    p.add_argument('--phase',choices=('pause','resume'),required=True)
    for name in ('lease','receipt','journal','output'):p.add_argument('--'+name,type=Path)
    args=p.parse_args(argv)
    if not args.execute:
        compile(program(),'<read-only unit metadata>','exec');print(json.dumps({'runtime_authorized':False,'unit':UNIT,'bounds':BOUNDS}));return
    if not all((args.lease,args.receipt,args.journal,args.output)):p.error('lease/receipt/journal/output required')
    commit=source.git('rev-parse','HEAD');lease=source.private_read(args.lease);r=source.private_read(args.receipt)
    expires=datetime.fromisoformat(lease['expires_utc'])
    if (lease.get('granted') is not True or lease.get('case')!='litellm-instance-quiesce'
            or lease.get('device')!=driver.plan.DEVICE or lease.get('driver_commit')!=commit
            or lease.get('source_commit')!=driver.plan.FROZEN_PRODUCT or lease.get('method')!=METHOD
            or lease.get('name')!=r['name'] or lease.get('unit')!=UNIT or lease.get('bounds')!=BOUNDS
            or lease.get('source_path')!=QFILE or lease.get('source_sha256')!=r['before']['files'][QFILE]['sha256']
            or lease.get('baseline_sha256')!=source.ops.digest(source.ops.canonical(r['before']))
            or args.phase not in lease.get('phases',[]) or not set(lease['phases'])<=set(('pause','resume'))
            or lease.get('journal_filename')!=args.journal.name
            or expires.tzinfo is None or not time.time()+360<expires.timestamp()<=time.time()+90*60):
        raise ValueError('exact bounded quiescence lease required')
    if source.git('status','--porcelain') or os.path.lexists(args.output):raise ValueError('clean source and unique output required')
    source.resources(expires.timestamp(),True)
    if (driver.git('/tmp/parity-focus-final-product-20261127','rev-parse','HEAD')!=driver.plan.FROZEN_PRODUCT
            or driver.git('/tmp/parity-focus-final-product-20261127','status','--porcelain')):
        raise ValueError('clean frozen source required')
    if args.phase=='pause':
        if os.path.lexists(args.journal) or r['install_intent'] or r['full_safety'] or r['pending'] or r['jobs']:
            raise ValueError('fresh pause before any LL activity required')
        journal={'name':r['name'],'driver_commit':commit,'source_commit':driver.plan.FROZEN_PRODUCT,
                 'baseline_sha256':lease['baseline_sha256'],'state':{}}
    else:
        journal=source.private_read(args.journal)
        if (journal['name']!=r['name'] or journal['baseline_sha256']!=lease['baseline_sha256']
                or journal['driver_commit']!=commit or journal['source_commit']!=driver.plan.FROZEN_PRODUCT):
            raise ValueError('foreign pause journal')
        if r['pending'] or any(v['state'] in ('queued','running') for v in r['jobs'].values()):
            raise ValueError('LL job unresolved; recover first')
        if r['install_intent'] and not r['complete']:raise ValueError('LL recovery incomplete')
    saved=driver.load_saved();fd=os.open(source.LOCK,os.O_RDWR|os.O_NOFOLLOW)
    try:
        if source.PRIORITY.exists():raise ValueError('priority pending')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if source.PRIORITY.exists():raise ValueError('priority pending')
        saved.verify_isolation()
        def read(full):
            result=saved.drv.root('timeout','--signal=TERM','--kill-after=10s','60s','python3','-B','-I','-c',program(),
                input=json.dumps({'inventory':full}).encode(),timeout=80)
            if result.returncode:raise ValueError('fixed metadata read failed')
            return json.loads(result.stdout)
        def act(verb):
            result=saved.drv.owner('systemctl','--user',verb,UNIT,timeout=BOUNDS['command_seconds'])
            if result.returncode:raise ValueError('unit command outcome uncertain; intent retained')
        protocol=Protocol(r,journal['state'],read=read,act=act,save=lambda:source.save(args.journal,journal))
        ok=False
        try:
            getattr(protocol,args.phase)();ok=True
        finally:
            capture.exclusive(args.output,{'phase':args.phase,'ok':ok,'unit':UNIT,'driver_commit':commit,
                'journal_sha256':source.ops.digest(source.ops.canonical(journal)),
                'pending':journal['state'].get('pending'),'paused':journal['state'].get('paused',False),
                'resumed':journal['state'].get('resumed',False)})
        print(json.dumps({'phase':args.phase,'ok':True,'unit':UNIT}))
    finally:os.close(fd)


if __name__=='__main__':
    try:main()
    except Exception:
        print(json.dumps({'ok':False,'error':'quiescence stopped; retain private journal'}));sys.exit(1)
