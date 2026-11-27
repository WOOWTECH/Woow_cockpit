#!/usr/bin/env python3
"""One separately leased read-only cookie diagnosis; default is offline only."""
import argparse
import datetime
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
PHASE='cookie-observer-readonly'
SNAPSHOT=r'''
import hashlib,json,subprocess
from pathlib import Path
base=Path('/var/lib/woowtech-backup')
out={}
for area in ('archives','ha-backups'):
 p=base/area;rows={}
 for f in p.iterdir():
  assert not f.is_symlink() and f.is_file()
  rows[f.name]=[f.stat().st_size,hashlib.sha256(f.read_bytes()).hexdigest() if f.suffix=='.json' else None]
 out[area]=rows
p=Path('/etc/woowtech-cockpit/backup/apps')
out['catalog']={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in p.glob('*.json')}
out['schedule']=subprocess.run(['systemctl','show','woowtech-cockpit-backup-schedule.timer',
 '--property=ActiveState,UnitFileState'],capture_output=True,check=True,timeout=30).stdout.decode()
out['active_jobs']=sum(1 for f in (base/'jobs').glob('*.json')
 if json.loads(f.read_bytes()).get('state') in ('queued','running'))
print(json.dumps(out))
'''


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def run(expected_guard):
    sys.path.insert(0,str(HERE))
    import focus_acceptance_ui as ui
    import focus_acceptance_ui_cookie_scan as scanner
    import ha_import_b1_e2e as b
    import ha_import_e2e as h
    from focus_acceptance_ui_relay import Relay
    lease=json.loads(ui.LEASE.read_bytes())
    commit=subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip()
    assert (lease['device']=='woowbk-dev-d' and lease['active_reviewed_phase']==PHASE
            and lease['driver_commit']==commit and Path(lease['driver_worktree']).resolve()==REPO
            and lease.get('cookie_probe_guard_sha256')==expected_guard)
    assert (datetime.datetime.fromisoformat(lease['expires'])-datetime.datetime.now(datetime.timezone.utc)).total_seconds()>=12*60
    assert not subprocess.check_output(['git','-C',str(REPO),'status','--porcelain','--untracked-files=no'])
    assert subprocess.check_output(['git','-C',lease['source'],'rev-parse','HEAD'],text=True).strip()=='1adf4df2b548bff1626e21d1d84e677f9622e4bc'
    assert not subprocess.check_output(['git','-C',lease['source'],'status','--porcelain','--untracked-files=no'])
    assert sha(ui.STATE)==expected_guard
    old=json.loads(ui.STATE.read_bytes());case=Path(old['evidence_dir'])
    assert old.get('baseline_restored') is True and not old.get('inflight')
    assert case.parent==ui.LAB/'evidence/focus-acceptance-ui' and case.resolve()==case
    protected={str(p):sha(p) for p in [ui.STATE,*(case/name for name in ('summary.json','recovery.json','browser.json','results.json'))]}
    fd=os.open(ui.LOCK,os.O_RDWR|os.O_CREAT,0o600)
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    os.umask(0o077)
    h.DEVICE='woowbk-dev-d'
    try:
        h.require_isolated_device()
        available=next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
        stat=os.statvfs(REPO)
        assert available>=1200*1024 and stat.f_bavail*stat.f_frsize>=21*1024**3
        memory=h.root('python3','-B','-I','-c','from pathlib import Path; s=Path("/sys/fs/cgroup/memory.stat").read_text().splitlines(); print(int(Path("/sys/fs/cgroup/memory.max").read_text())-sum(int(x.split()[1]) for x in s if x.startswith(("anon ","kernel "))))',timeout=30)
        assert memory.returncode==0 and int(memory.stdout)>=1900*1024**2
        def snapshot():
            p=h.root('python3','-B','-I','-c',SNAPSHOT,timeout=60)
            assert p.returncode==0
            value=json.loads(p.stdout);assert value['active_jobs']==0
            return value
        before=snapshot()
        ev=ui.LAB/'evidence/focus-acceptance-ui-cookie'/time.strftime('%Y%m%dT%H%M%S')
        ev.mkdir(parents=True,exist_ok=False);ev.chmod(0o700)
        scan=scanner.program(inspect.getsource(b.secret_scan_needles),inspect.getsource(ui.scan_paths))
        rendered=REPO/'snippets/focus-acceptance/r8-cookie-scan-rendered.py'
        assert rendered.read_text()==scan
        (ev/'rendered-scan.py').write_text(scan)
        secrets=b.Secrets([ui.LAB/'secrets/b1-creds.env',ui.LAB/'secrets/ha-import-creds.env'],ui.LAB/'secrets/dev-d-markers.json')
        password=(ui.LAB/'secrets/devadmin.pass').read_text().strip()
        secrets.register('COOKIE_PROBE_LOGIN_PASSWORD',password)
        with Relay() as relay:
            config={'base':relay.base,'password':password,'registered':secrets.secret_values(),
                    'playwright':str(ui.PLAYWRIGHT),'chromium':str(ui.CHROMIUM),
                    'scan':scan,'evidence':str(ev),'since':int(time.time())-60}
            p=subprocess.run(['node',str(HERE/'focus_acceptance_ui_cookie_probe.mjs'),'--run'],
                             input=json.dumps(config).encode(),capture_output=True,timeout=8*60)
        # No raw child stdout/stderr, cookie, header, frame or exception escapes.
        after=snapshot();unchanged=before==after and all(sha(Path(path))==value for path,value in protected.items())
        h.require_isolated_device()
        receipt={'scope':PHASE,'driver_commit':commit,'exit':p.returncode,'child_stderr_bytes':len(p.stderr),
                 'guard_sha256':expected_guard,'protected_case_files_unchanged':unchanged,
                 'catalog_archive_HA_schedule_inventory_unchanged':before==after,
                 'network_isolation_preserved':True,'acceptance_passed':False,
                 'result_sha256':sha(ev/'result.json'),'rendered_scan_sha256':sha(ev/'rendered-scan.py')}
        with (ev/'receipt.json').open('x') as f:json.dump(receipt,f,indent=2);f.write('\n')
        print('Cookie observer: immutable metadata receipt '+str(ev/'receipt.json'))
        print('Cookie observer: protected inventory and old case '+('PASS' if unchanged else 'FAIL'))
        print('Cookie observer: receipt SHA256 '+sha(ev/'receipt.json'))
        return 0 if p.returncode==0 and unchanged else 1
    finally:os.close(fd)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true');parser.add_argument('--guard-sha256')
    args=parser.parse_args()
    if not args.run:
        compile(Path(__file__).read_text(),__file__,'exec')
        print('Cookie observer prepared: offline only; separate reviewed lease required')
        return 0
    if not re.fullmatch(r'[0-9a-f]{64}',args.guard_sha256 or ''):parser.error('exact protected failed guard SHA required')
    return run(args.guard_sha256)


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('Cookie observer stopped: '+type(error).__name__+' (details private; no automatic retry)')
        raise SystemExit(1) from None
