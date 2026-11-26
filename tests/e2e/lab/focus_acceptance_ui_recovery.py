#!/usr/bin/env python3
"""Independent recovery-only proof for failed R8 attempt1; no guard override.

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


def run():
    sys.path.insert(0,str(HERE))
    import focus_acceptance_ui as ui
    import ha_import_b1_e2e as b
    import ha_import_e2e as h
    h.DEVICE='woowbk-dev-d'
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
        assert old['phase']=='recovery-retained' and old['baseline_restored'] is True and not old.get('inflight')
        case=Path(old['evidence_dir']).resolve()
        assert case.parent==(LAB/'evidence/focus-acceptance-ui').resolve()
        protected=[GUARD,case/'recovery.json',case/'summary.json',case/'browser.json',case/'results.json',
                   Path('/tmp/parity-focus-20261127/acceptance-r8-attempt1.private.log'),
                   REPO/'tests/backup/evidence/focus-acceptance-20261127/r8-attempt1.json']
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
            names=[x['unit'] for x in rows if x['unit'].startswith(('hermes-','omnigent-','emqx.','emqx-')) and x['unit'].endswith('.service')]
            p=h.owner('systemctl','--user','show','--property=Id,Type,RemainAfterExit','--',*names,timeout=60)
            assert p.returncode==0
            props={}
            for block in p.stdout.decode().strip().split('\n\n'):
                fields=dict(x.split('=',1) for x in block.splitlines() if '=' in x)
                if fields.get('Id'):props[fields['Id']]=fields
            return ui.stable_units(rows,props)
        marker=ui.marker_program((HERE/'batch1_markers.py').read_text())
        def markers(app):
            p=h.owner('python3','-B','-I','-c',marker,app,'read',input=b'{}',timeout=180)
            assert p.returncode==0
            d=json.loads(p.stdout);secrets.register_issued(d['issued'])
            if app=='emqx':assert d['issued']
            return d['markers']
        check('recovery only: no active backup job',not ok('status').get('active_job'))
        for app in ui.APPS:check('recovery only: exact original '+app+' markers',markers(app)==old['before_markers'][app])
        check('recovery only: original durable unit and timer states',unit_states()==old['original_units'])
        p=h.owner('podman','ps','--format','{{.Names}} {{.ImageID}}',timeout=60);assert p.returncode==0
        images=dict(x.split() for x in p.stdout.decode().splitlines())
        check('recovery only: exact original image configs',images==old['original_images'])
        p=h.root('systemctl','show',ui.TIMER,'--property=UnitFileState,ActiveState',timeout=60);assert p.returncode==0
        timer=dict(x.split('=',1) for x in p.stdout.decode().splitlines())
        check('recovery only: exact original schedule state',timer==old['original_timer'])
        check('recovery only: original HA fixture hash',ui.sha(ui.FIXTURE)==ui.FIXTURE_SHA)
        listing=ok('list');by_id={x['id']:x for x in listing.get('backups',[])}
        retained=set(old['created_backups']);check('recovery only: all six old case archives retained',len(retained)==6 and retained<=set(by_id))
        uploaded={x['id']:x for x in listing.get('ha_backups',[])}
        check('recovery only: old HA upload retained with original derived hash',old['ha_id'] in uploaded and uploaded[old['ha_id']].get('sha256')==old['derived_fixture_sha256'])
        check('recovery only: old derived host copy retained',(case/'full-ha-corrupt-emqx.tar').is_file() and ui.sha(case/'full-ha-corrupt-emqx.tar')==old['derived_fixture_sha256'])
        scan=ui.scan_program(inspect.getsource(b.secret_scan_needles))
        report=root_json(scan,{'values':secrets.secret_values(),'since':int(min(p.stat().st_mtime for p in case.iterdir() if p.is_file()))-60,
                              'podman_secrets':['omnigent-postgres-password','omnigent-admin-password','omnigent-runner-password',
                              'hermes-api-server-key','hermes-webhook-secret','hermes-dashboard-session-secret','hermes-dashboard-password','hermes-postgres-password',
                              'woow-emqx-dashboard-password','woow-emqx-node-cookie','woow-emqx-mqtt-password']})
        check('recovery only: registered and new probe values zero hits',report['hits']==0 and report['scanned']>0 and report['archive_index_sidecars_scanned']>=len(retained))
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
        receipt=ev.dir/'receipt.json'
        with receipt.open('x') as f:json.dump(facts,f,indent=2);f.write('\n')
        public=dict(facts,independent_receipt_sha256=digest(receipt))
        with PUBLIC.open('x') as f:json.dump(public,f,indent=2);f.write('\n')
        print('recovery only: immutable independent receipt written: PASS')
        print('recovery only: mutex released for parent: PASS')
    finally:os.close(fd)


if __name__=='__main__':
    if sys.argv[1:]==['--run']:run()
    elif not sys.argv[1:]:
        compile(Path(__file__).read_text(),__file__,'exec');print('R8 independent recovery prepared: offline syntax PASS')
    else:raise SystemExit('expected --run under current R8 lease and heavy guard')
