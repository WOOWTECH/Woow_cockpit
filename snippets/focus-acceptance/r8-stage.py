#!/usr/bin/env python3
"""One authorized frozen-source stage, existing deploy-src only; default offline."""
import datetime
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

REPO=Path(__file__).resolve().parents[2]
SOURCE=Path('/tmp/parity-focus-r8-source-20261127')
PIN='1adf4df2b548bff1626e21d1d84e677f9622e4bc'
LEASE=Path('/tmp/parity-focus-20261127/lease-r8-dev-d.json')
LP=str(Path.home()/'.woowbk-lab/bin/labpodman')
TIMER='woowtech-cockpit-backup-schedule.timer'
EVIDENCE=Path.home()/'.woowbk-lab/evidence/focus-acceptance-ui-stage'


def run():
    lease=json.loads(LEASE.read_text())
    assert lease['device']=='woowbk-dev-d' and lease['source_commit']==PIN[:8] and lease['driver_commit']=='a8003e7d'
    expires=datetime.datetime.fromisoformat(lease['expires'])
    assert (expires-datetime.datetime.now(datetime.timezone.utc)).total_seconds()>=45*60, 'insufficient lease time for bounded flow/recovery'
    assert subprocess.check_output(['git','-C',str(SOURCE),'rev-parse','HEAD'],text=True).strip()==PIN
    for tree in (REPO,SOURCE):
        assert not subprocess.check_output(['git','-C',str(tree),'status','--porcelain','--untracked-files=no'],text=True).strip(), 'tracked source dirty'
    lock=os.open('/tmp/woowbk-dev-d-mutation.lock',os.O_RDWR|os.O_CREAT,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    os.umask(0o077)
    evidence=EVIDENCE/time.strftime('%Y%m%dT%H%M%S')
    evidence.mkdir(parents=True,mode=0o700,exist_ok=False)
    def device(argv,stdin=None,timeout=180):
        return subprocess.run([LP,'exec','-i','woowbk-dev-d',*argv],input=stdin,capture_output=True,timeout=timeout)
    def probe(code):
        p=device(['python3','-B','-I','-c',code])
        assert p.returncode==0, 'fixed probe failed'
        return json.loads(p.stdout)
    def timer():
        p=device(['systemctl','show',TIMER,'--property=UnitFileState,ActiveState'])
        assert p.returncode==0
        return dict(x.split('=',1) for x in p.stdout.decode().splitlines())
    def save(name,obj):
        (evidence/name).write_text(json.dumps(obj,indent=2)+'\n')
    before=None
    masked=False
    try:
        isolation=subprocess.run([LP,'inspect','woowbk-dev-d','--format','{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}'],capture_output=True,timeout=30)
        assert isolation.returncode==0 and isolation.stdout.strip()==b'true none {}'
        free=os.statvfs(REPO).f_bavail*os.statvfs(REPO).f_frsize
        ram=next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
        headroom=probe('from pathlib import Path; import json; s=Path("/sys/fs/cgroup/memory.stat").read_text().splitlines(); used=sum(int(x.split()[1]) for x in s if x.startswith(("anon ","kernel "))); print(json.dumps(int(Path("/sys/fs/cgroup/memory.max").read_text())-used))')
        assert free>=21*1024**3 and ram>=1200*1024 and headroom>=1900*1024**2, 'lease resource floor'
        state=probe('import json,hashlib,subprocess; from pathlib import Path; p=Path("/etc/woowtech-cockpit/backup/apps"); u=subprocess.run(["/usr/local/bin/woowbk-owner","systemctl","--user","list-units","--all","--output=json","--no-pager"],capture_output=True,check=True); units={x["unit"]:[x["active"],x["sub"]] for x in json.loads(u.stdout) if x["unit"].startswith(("hermes-","omnigent-","emqx.","emqx-")) and x["unit"].endswith((".service",".timer"))}; print(json.dumps({"catalog":{x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in p.glob("*.json")},"units":units}))')
        before=timer()
        save('before.json',dict(state,timer=before,host_free_bytes=free,host_available_kib=ram,device_headroom_bytes=headroom,source_commit=PIN))
        assert before['ActiveState'] in ('inactive','failed'), 'active schedule precondition'
        assert state['units'] and all(v[0]=='active' for k,v in state['units'].items() if k.endswith('.service')), 'original app units not active'
        p=device(['python3','-B','/opt/woow-cockpit-src/scripts/manage.py','status'])
        tools=json.loads(p.stdout)
        required={'age','age-keygen','zstd','python3-nacl','python3-cryptography'}
        assert p.returncode==0 and tools['status']=='ready' and not tools['packages'] and set(tools['tools'])==required and all(tools['tools'].values()), 'read-only tools status requires repair; stop'
        save('tools.json',{'status':'ready','tools':tools['tools'],'packages':[]})
        if before['UnitFileState'] not in ('masked','masked-runtime'):
            masked=True
            assert device(['systemctl','mask',TIMER]).returncode==0
        p=subprocess.run(['bash',str(REPO/'tests/e2e/lab/deploy-src.sh'),'d','--src',str(SOURCE),'--no-demo-catalog'],capture_output=True,timeout=600)
        (evidence/'deploy.private.log').write_bytes(p.stdout+b'\n--- stderr ---\n'+p.stderr)
        result=json.loads(p.stdout)
        assert p.returncode==0 and not result.get('packages') and not result.get('missing_packages'), 'source stage failed or tried package repair'
        assert b'apt auto' not in p.stderr and '正在用 apt 自動補裝'.encode() not in p.stderr, 'apt repair observed'
        save('result.json',{'exit':p.returncode,'changed':result.get('changed'),'status':result.get('status'),'packages':result.get('packages',[]),'source_commit':PIN,'apt_needed':False})
        print(json.dumps({'stage':'r8_source_stage','source':PIN,'tools_available':5,'apt_needed':False,'source_stage_exit':0,'host_free_mib':free//1024**2,'device_headroom_mib':headroom//1024**2}))
    finally:
        if masked:
            assert device(['systemctl','unmask',TIMER]).returncode==0, 'own schedule mask recovery failed'
        if before is not None:
            after=timer()
            save('after-timer.json',after)
            assert after==before, 'original schedule state not returned; retain receipt'
        os.close(lock)


if __name__=='__main__':
    if sys.argv[1:]==['--run']:
        run()
    elif not sys.argv[1:]:
        compile(Path(__file__).read_text(),__file__,'exec')
        print('R8 frozen-source stage prepared: offline syntax PASS')
    else:
        raise SystemExit('expected --run only after current lease/globalheavy admission')
