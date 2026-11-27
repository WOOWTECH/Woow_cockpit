#!/usr/bin/env python3
"""Independent recovery-only proof for failed R8 attempt1 or exact attempt3.

Verify original live data/states, remove only the recorded own catalog entry,
retain every old archive/upload/capture. No HA import/restore or old-file rewrite.
Default offline; --run uses current R8 lease, heavy.sh and the existing mutex.
"""
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
LAB=Path.home()/'.woowbk-lab'
GUARD=LAB/'run/focus_acceptance_ui.json'
LEASE=Path('/tmp/parity-focus-20261127/lease-r8-dev-d.json')
SOURCE=Path('/tmp/parity-focus-r8-source-20261127')
PIN='1adf4df2b548bff1626e21d1d84e677f9622e4bc'
PUBLIC=REPO/'tests/backup/evidence/focus-acceptance-20261127/r8-independent-recovery.json'


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(attempt=1, expected_guard_sha=None):
    sys.path.insert(0,str(HERE))
    import focus_acceptance_ui as ui
    import ha_import_b1_e2e as b
    import ha_import_e2e as h
    h.DEVICE='woowbk-dev-d'
    assert attempt in (1,3)
    if attempt==1:
        expected_guard_sha='e63eaed2bc2684aaec500ece00c56bef21175df7e35294ed5e255345caba11e6'
    assert re.fullmatch(r'[0-9a-f]{64}',expected_guard_sha or '')
    public_path=PUBLIC if attempt==1 else PUBLIC.with_name('r8-attempt3-independent-recovery.json')
    assert not public_path.exists(), 'immutable independent public receipt already exists'
    lease=json.loads(LEASE.read_text())
    assert lease['device']==h.DEVICE and lease['source_commit']=='1adf4df2'
    assert datetime.datetime.now(datetime.timezone.utc)<datetime.datetime.fromisoformat(lease['expires'])
    assert subprocess.check_output(['git','-C',str(SOURCE),'rev-parse','HEAD'],text=True).strip()==PIN
    fd=os.open(ui.LOCK,os.O_RDWR|os.O_CREAT,0o600)
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    os.umask(0o077)
    try:
        h.require_isolated_device()
        raw_guard=GUARD.read_bytes(); old=json.loads(raw_guard)
        assert hashlib.sha256(raw_guard).hexdigest()==expected_guard_sha
        assert old['phase']=='recovery-retained' and old['baseline_restored'] is True and not old.get('inflight')
        case=Path(old['evidence_dir']).resolve()
        assert case.parent==(LAB/'evidence/focus-acceptance-ui').resolve()
        if attempt==3:
            assert case.name=='20261127T073833' and old['driver_commit'].startswith('f0f61598')
            assert digest(case/'summary.json')=='d52c2a6e399ee47806ab927ae68d4e14ca3001c39b83cdf05dc467d31a553457'
            assert digest(case/'recovery.json')=='12c1c8d6ff908a42e0e76bd3c73cb62e84fa485b1a5fa4c0887bd7a580101d36'
            assert digest(case/'browser.json')=='e7044ddca575a1ce2d1925eae9ac30c6917e49c3afac7fd936cdbdb43e576dec'
        protected=[GUARD,case/'recovery.json',case/'summary.json',case/'browser.json',case/'results.json',
                   Path('/tmp/parity-focus-20261127/acceptance-r8-attempt%d.private.log'%attempt),
                   REPO/('tests/backup/evidence/focus-acceptance-20261127/r8-attempt%d.json'%attempt)]
        if attempt==3:
            older=json.loads((case/'previous-guard.json').read_text())
            older_case=Path(older['evidence_dir']).resolve()
            assert older_case.parent==(LAB/'evidence/focus-acceptance-ui').resolve()
            protected.extend([case/'previous-guard.json',*(older_case/name for name in ('recovery.json','summary.json','browser.json','results.json')),
                              Path('/tmp/parity-focus-20261127/acceptance-r8-attempt1.private.log'),Path('/tmp/parity-focus-20261127/acceptance-r8-attempt2.private.log'),
                              REPO/'tests/backup/evidence/focus-acceptance-20261127/r8-attempt1.json',REPO/'tests/backup/evidence/focus-acceptance-20261127/r8-attempt2.json'])
        hashes={str(p):digest(p) for p in protected}
        browser=json.loads((case/'browser.json').read_text())
        assert browser['issued_values_scanned'] is False  # missing coverage remains missing
        secrets=b.Secrets([b.SECRET_DIR/'b1-creds.env',b.SECRET_DIR/'ha-import-creds.env'],b.SECRET_DIR/'dev-d-markers.json')
        secrets.redact_tree=secrets.redact_structure
        secrets.register('COCKPIT_PASSWORD',(b.SECRET_DIR/'devadmin.pass').read_text().strip())
        secrets.register('DEV_D_KIT',(b.SECRET_DIR/'dev-d-kit.txt').read_text().strip())
        ev=h.Evidence(secrets,'focus-acceptance-ui-recovery')
        def check(name,yes):
            print(name+(': PASS' if yes else ': FAIL'),flush=True)
            if not yes:raise RuntimeError(name)
        def ok(command,request=None):return h.ok(command,request,ev=ev,timeout=180)
        def root_json(code,request=None):
            p=h.root('python3','-B','-I','-c',code,input=json.dumps(request or {}).encode(),timeout=180)
            if p.returncode:raise RuntimeError('strict fixed recovery probe failed')
            return json.loads(p.stdout)
        def catalog():
            return root_json('from pathlib import Path; import hashlib,json; p=Path("/etc/woowtech-cockpit/backup/apps"); print(json.dumps({x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in p.glob("*.json")}))')
        def unit_states():
            p=h.owner('systemctl','--user','list-units','--all','--output=json','--no-pager',timeout=60)
            assert p.returncode==0
            rows=json.loads(p.stdout)
            names=[x['unit'] for x in rows if x['unit'].startswith(('hermes-','omnigent-','emqx.','emqx-')) and x['unit'].endswith(('.service','.timer'))]
            p=h.owner('systemctl','--user','show','--property=Id,Type,RemainAfterExit,Unit,UnitFileState','--',*names,timeout=60)
            assert p.returncode==0
            props={}
            for block in p.stdout.decode().strip().split('\n\n'):
                fields=dict(x.split('=',1) for x in block.splitlines() if '=' in x)
                if fields.get('Id'):props[fields['Id']]=fields
            return ui.stable_units(rows,props),props
        marker=ui.marker_program((HERE/'batch1_markers.py').read_text())
        def markers(app):
            p=h.owner('python3','-B','-I','-c',marker,app,'read',input=b'{}',timeout=180)
            assert p.returncode==0
            d=json.loads(p.stdout);secrets.register_issued(d['issued'])
            if app=='emqx':assert d['issued']
            return d['markers']
        check('recovery only: no active backup job',not ok('status').get('active_job'))
        for app in ui.APPS:check('recovery only: exact original '+app+' markers',markers(app)==old['before_markers'][app])
        current_units,properties=unit_states()
        check('recovery only: original durable unit and timer states',
              ui.units_equal(current_units,old['original_units'],properties) if attempt==3 else current_units==old['original_units'])
        p=h.owner('podman','ps','--format','{{.Names}} {{.ImageID}}',timeout=60);assert p.returncode==0
        images=dict(x.split() for x in p.stdout.decode().splitlines())
        if attempt==3:
            p=h.owner('systemctl','--user','show','--property=Id,SourcePath','--',*ui.IMAGE_UNITS,timeout=60);assert p.returncode==0
            sources={}
            for block in p.stdout.decode().strip().split('\n\n'):
                fields=dict(x.split('=',1) for x in block.splitlines() if '=' in x)
                if fields.get('Id') in ui.IMAGE_UNITS:sources[fields['Id']]=fields.get('SourcePath')
            bindings=root_json('''import configparser,hashlib,json,sys
from pathlib import Path
sources=json.load(sys.stdin)["sources"];out={}
for unit,value in sources.items():
 p=Path(value)
 assert p.parent==Path("/home/appowner/.config/containers/systemd") and not p.is_symlink() and p.resolve()==p
 data=p.read_bytes();c=configparser.ConfigParser(interpolation=None,strict=False);c.read_string(data.decode())
 out[unit]={"source":str(p),"source_sha256":hashlib.sha256(data).hexdigest(),"container_name":c["Container"]["ContainerName"]}
print(json.dumps(out))''',{'sources':sources})
            images=ui.project_images(images,bindings)
        check('recovery only: exact original image configs',images==old['original_images'])
        p=h.root('systemctl','show',ui.TIMER,'--property=UnitFileState,ActiveState',timeout=60);assert p.returncode==0
        timer=dict(x.split('=',1) for x in p.stdout.decode().splitlines())
        check('recovery only: exact original schedule state',timer==old['original_timer'])
        check('recovery only: original HA fixture hash',ui.sha(ui.FIXTURE)==ui.FIXTURE_SHA)
        listing=ok('list');by_id={x['id']:x for x in listing.get('backups',[])}
        retained=set(old['created_backups']);check('recovery only: all six old case archives retained',len(retained)==6 and retained<=set(by_id))
        older_retained=set(old.get('protected_existing_backups',[]))
        if attempt==3:
            check('recovery only: all six older protected archives retained',len(older_retained)==6 and older_retained<=set(by_id) and not older_retained&retained)
        uploaded={x['id']:x for x in listing.get('ha_backups',[])}
        check('recovery only: old HA upload retained with original derived hash',old['ha_id'] in uploaded and uploaded[old['ha_id']].get('sha256')==old['derived_fixture_sha256'])
        check('recovery only: old derived host copy retained',(case/'full-ha-corrupt-emqx.tar').is_file() and ui.sha(case/'full-ha-corrupt-emqx.tar')==old['derived_fixture_sha256'])
        if attempt==3:
            check('recovery only: older derived host copy retained',(older_case/'full-ha-corrupt-emqx.tar').is_file() and ui.sha(older_case/'full-ha-corrupt-emqx.tar')==older['derived_fixture_sha256'])
        scan=ui.scan_program(inspect.getsource(b.secret_scan_needles))
        if attempt==3:
            rendered=REPO/'snippets/focus-acceptance/r8-scan-rendered.py'
            check('recovery only: exact reviewed rendered scanner parity',rendered.read_text()==scan)
            with (ev.dir/'rendered-scan.py').open('x') as f:f.write(scan)
        report=root_json(scan,{'values':secrets.secret_values(),'since':int(min(p.stat().st_mtime for p in case.iterdir() if p.is_file()))-60,
                              'podman_secrets':['omnigent-postgres-password','omnigent-admin-password','omnigent-runner-password',
                              'hermes-api-server-key','hermes-webhook-secret','hermes-dashboard-session-secret','hermes-dashboard-password','hermes-postgres-password',
                              'woow-emqx-dashboard-password','woow-emqx-node-cookie','woow-emqx-mqtt-password']})
        check('recovery only: registered and new probe values zero hits',report['hits']==0 and report['scanned']>0 and report['archive_index_sidecars_scanned']>=len(retained|older_retained))
        if attempt==3:
            expected_sidecars=root_json('from pathlib import Path; import json; print(json.dumps(len(list(Path("/var/lib/woowtech-backup/archives").rglob("*.json")))))')
            check('recovery only: both actual regular JSON roots scanned',report['regular_json_roots_scanned']==2)
            check('recovery only: every actual archive JSON sidecar scanned',report['archive_index_sidecars_scanned']==expected_sidecars)
            ev.save('scan-result.json',report)
        # This scan includes archives/<id>.json sidecars and requests/pending/
        # exports, never a fictional aggregate index. No past cookie claim.
        current=catalog();removed=False
        if current!=old['original_catalog']:
            expected=dict(old['original_catalog'],**{'omnigent.json':old['catalog_expected_sha256']})
            check('recovery only: catalog differs only by recorded own entry',old['catalog_added'] and current==expected)
            preview=ok('catalog-remove',{'id':'omnigent'})
            check('recovery only: own catalog removal exact SHA',preview.get('expected_sha256')==old['catalog_expected_sha256'])
            ok('catalog-remove',{'id':'omnigent','confirm':True,'expected_sha256':old['catalog_expected_sha256']})
            removed=True
        check('recovery only: exact original catalog hashes',catalog()==old['original_catalog'])
        check('recovery only: no active job after catalog recovery',not ok('status').get('active_job'))
        h.require_isolated_device()
        check('recovery only: old guard receipt summary and captures unchanged',all(digest(Path(p))==value for p,value in hashes.items()))
        # All old archive/index/upload inventories are retained, no delete call.
        after=ok('list')
        check('recovery only: archive inventory unchanged',{x['id'] for x in after.get('backups',[])}==set(by_id))
        check('recovery only: HA inventory unchanged',{x['id'] for x in after.get('ha_backups',[])}==set(uploaded))
        facts={'scope':'r8-independent-recovery-only','data_recovery_verified':True,'acceptance_passed':False,
               'source_commit':PIN,'old_guard_sha256':hashes[str(GUARD)],'old_receipt_sha256':hashes[str(case/'recovery.json')],
               'old_summary_sha256':hashes[str(case/'summary.json')],'old_cookie_coverage':'absent-not-retroactively-proved',
               'original_markers_equal':True,'original_units_equal':True,'original_images_equal':True,'original_timer_equal':True,
               'original_catalog_equal':True,'original_fixture_hash_equal':True,'active_jobs':0,'network_isolation_preserved':True,
               'own_catalog_removed_exact_sha':removed,'old_archives_retained':6,'old_ha_retained':True,'old_captures_unchanged':True,
               'old_guard_unchanged':True,'old_summary_unchanged':True,'scan':report,'scan_covers_archive_index_sidecars':True,
               'scan_covers_requests_pending_exports':True,'cookie_coverage_of_old_attempt':False,
               'guard_override_performed':False,'commercial_acceptance':'not-complete'}
        facts.update(purpose_attempt=attempt,older_protected_archives_retained=len(older_retained),
                     total_case_archives_retained=len(retained|older_retained),cookie_values_recovered=False)
        if attempt==3:
            facts.update(rendered_scan_sha256=hashlib.sha256(scan.encode()).hexdigest(),
                         actual_archive_index_sidecars_expected=expected_sidecars,
                         actual_regular_json_roots_scanned=report['regular_json_roots_scanned'],
                         postscan_catalog_guard_inventory_checks_completed=True)
        receipt=ev.dir/'receipt.json'
        with receipt.open('x') as f:json.dump(facts,f,indent=2);f.write('\n')
        public=dict(facts,independent_receipt_sha256=digest(receipt))
        with public_path.open('x') as f:json.dump(public,f,indent=2);f.write('\n')
        print('recovery only: immutable independent receipt written: PASS')
        print('recovery only: mutex released for parent: PASS')
    finally:os.close(fd)


if __name__=='__main__':
    if sys.argv[1:]==['--run']:run()
    elif len(sys.argv)==4 and sys.argv[1:3]==['--run-attempt3','--guard-sha256']:
        run(3,sys.argv[3])
    elif not sys.argv[1:]:
        compile(Path(__file__).read_text(),__file__,'exec');print('R8 independent recovery prepared: offline syntax PASS')
    else:raise SystemExit('expected --run or --run-attempt3 --guard-sha256 SHA under reviewed R8 lease and heavy guard')
