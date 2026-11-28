#!/usr/bin/env python3
"""Cold-to-cold orchestration for the separately leased original R6 full-share case."""
import datetime
import json
import inspect
import os
from pathlib import Path
import secrets
import subprocess
import time

import focus_nextcloud_r6_cold as cold
import focus_nextcloud_r6_source as source
import focus_nextcloud_r6_wake as wake
from focus_nextcloud_r6_inventory import collect, ORIGINALS, LP, DEVICE
from focus_nextcloud_r6_plan import BASELINE, DEVICE_CAP, GIB, MIB, RESERVE, lease_check

SOURCE_POLICY = 'always-return-exact-prior-engine-helper-version-after-data-recovery'
PIN_POLICY = 'same-config-only-private-copy-revert'
RESOURCE = """
import json,pathlib,shutil
print(json.dumps({'free':min(shutil.disk_usage('/home').free,shutil.disk_usage('/var/lib').free),
 'memory':int(pathlib.Path('/sys/fs/cgroup/memory.current').read_text())}))
"""
def open_encrypted_baseline(keys, archive, path, key, baseline):
    header = archive.read_header(path)
    assert header.get('encryption') != 'none'
    # KeyStore accepts this native TEMP_NAME_RE name; it is not a TempObjects job ID.
    # Its context manager removes the temporary private key on success AND exception.
    with keys.temp_identity(key, 'key-inspect-focus-r6') as identity:
        manifest = archive.read_manifest(path, [identity])
    assert manifest['backup_id'] == baseline and [a['id'] for a in manifest['apps']] == ['nextcloud']
    return manifest


BASELINE_INSPECT = inspect.getsource(open_encrypted_baseline) + r'''
import json,sys
sys.dont_write_bytecode=True
sys.pycache_prefix='/nonexistent/focus-nextcloud-r6'
sys.path.insert(0,'/usr/local/lib/woowtech-cockpit-backup')
from woowbackup.cli import Services,Paths,build_preflight
q=json.load(sys.stdin);svc=Services(Paths());bid='20261123T132013Z-34811d90'
meta=svc.storage.get(bid);path=svc.storage.archive_path(bid)
manifest=open_encrypted_baseline(svc.keys,svc.archive,path,q['key'],bid)
pre=build_preflight(svc,manifest,meta)
assert manifest['backup_id']==bid and [a['id'] for a in manifest['apps']]==['nextcloud']
assert pre.get('ok') is True and len(pre.get('apps',[]))==1
assert all(a.get('restorable') is True and a.get('mode')=='inplace' and
           a.get('settings',{}).get('state')=='same' for a in pre['apps']) and not any(c.get('status')=='fail' for c in pre.get('checks',[]))
print(json.dumps({'status':'passed','baseline_id':bid,'encrypted_manifest_opened':True,
 'preflight_ok_settings_same_inplace':True,'persistent_key_import':False,'record_update':False}))
'''

QUIESCENT = r'''
import json,pathlib,stat
root=pathlib.Path('/var/lib/woowtech-backup/jobs');active=0;count=0
for p in root.glob('j*.json'):
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=1048576
 count+=1;assert count<=1000
 with p.open() as f:row=json.load(f)
 active+=row.get('state') in ('queued','running')
print(json.dumps({'active_jobs':active}))
'''

UPLOAD = r'''
import hashlib,json,os,pathlib,select,shutil,stat,sys,time
path,size,sha,deadline=sys.argv[1:];size=int(size);deadline=float(deadline)
assert path.startswith('/var/lib/woowtech-backup/uploads/') and '..' not in pathlib.Path(path).parts
fd=os.open(path,os.O_WRONLY|os.O_NOFOLLOW);st=os.fstat(fd)
assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==0 and st.st_size==0
count=0;h=hashlib.sha256()
try:
 while True:
  assert time.time()<deadline
  assert min(shutil.disk_usage('/home').free,shutil.disk_usage('/var/lib').free)>=13*1024**3+512*1024**2
  if not select.select([sys.stdin.fileno()],[],[],2)[0]:continue
  chunk=os.read(sys.stdin.fileno(),65536)
  if not chunk:break
  count+=len(chunk);assert count<=size;h.update(chunk)
  data=memoryview(chunk)
  while data:data=data[os.write(fd,data):]
 os.fsync(fd)
 assert count==size and h.hexdigest()==sha
finally:os.close(fd)
print(json.dumps({'status':'passed','bytes':count,'sha256':h.hexdigest()}))
'''


def reload_units():
    p=subprocess.run([str(LP),'exec','-i',DEVICE,'/usr/local/bin/woowbk-owner',
                      'systemctl','--user','daemon-reload'],stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL,timeout=120)
    if p.returncode: raise RuntimeError('fixed-r6-daemon-reload-failed')


def admission(before):
    if (before['isolation'] != {'running':True,'network':'none','ports':{},'memory_limit':DEVICE_CAP}
            or before['root']['memory_max'] != str(DEVICE_CAP)
            or before['host_memory_available_mib'] < 2200
            or DEVICE_CAP-before['root']['memory_current'] < 1536*MIB
            or min(before['host_free_bytes'],before['root']['varlib_free_bytes']) < RESERVE+4*GIB
            or any(x.get('ActiveState')!='inactive' for x in before['owner']['units'].values())):
        raise ValueError('fixed-r6-cold-resource-admission-refused')
    rows=before['owner']['images']
    if len(rows)!=5 or {x['ref'] for x in rows}!=set(ORIGINALS):
        raise ValueError('fixed-r6-five-original-image-rows-required')
    for row in rows:
        ident=row.get('identity') or {}
        if (not row['present'] or ident.get('id','').removeprefix('sha256:')!=ORIGINALS[row['ref']]
                or ident.get('architecture')!='amd64' or ident.get('os')!='linux'):
            raise ValueError('fixed-r6-original-image-required')


def run(args, lease, commit, facts, flow, binding=None):
    """Caller has acquired whole-device mutex. No nested locks or old setup/install.

    `binding` (None = the R6 full share): another case of this lane on the same cold-to-cold path -- its lease phase,
    product commit, frozen-manifest reader, evidence area and result phase (focus_nextcloud_r6_s5b.BINDING)."""
    phase_name=binding.phase if binding else 'fullshare'
    product_commit=binding.product_commit if binding else source.PRODUCT_COMMIT
    frozen=binding.frozen_manifest if binding else source.frozen_manifest
    lease_check(lease,commit,phase_name)
    if (lease.get('product_commit')!=product_commit or lease.get('source_policy')!=SOURCE_POLICY
            or lease.get('pin_refresh_policy')!=PIN_POLICY or lease.get('recovery_grace_seconds')!=1800):
        raise ValueError('fixed-r6-source-pin-recovery-lease-required')
    paths,manifest=frozen(args.product_source)
    if lease.get('product_manifest_sha256')!=source.manifest_hash(manifest):
        raise ValueError('fixed-r6-frozen-manifest-lease-required')
    before=collect();admission(before)
    retained_path=getattr(args,'retained_upload_receipt',None)
    args.retained_upload=None;args.retained_credit_bytes=0
    if retained_path is not None:
        import focus_nextcloud_r6_upload as upload
        expected=lease.get('retained_upload_receipt_sha256')
        if not expected:raise ValueError('fixed-retained-upload-lease-binding-required')
        trace=upload.Evidence(Path.home()/'.woowbk-lab/evidence/focus-nextcloud-r6-retained-check'/time.strftime('%Y%m%dT%H%M%S'))
        end=datetime.datetime.fromisoformat(lease['expires_utc'].replace('Z','+00:00')).timestamp()
        args.retained_upload,args.retained_proof,args.retained_credit_bytes=upload.adopt_receipt(retained_path,expected,end,trace)
    elif lease.get('retained_upload_receipt_sha256'):
        raise ValueError('fixed-retained-upload-receipt-required')
    if wake.device(QUIESCENT,root=True)['active_jobs']:
        raise ValueError('fixed-r6-existing-job-writer-refused')
    expires=datetime.datetime.fromisoformat(lease['expires_utc'].replace('Z','+00:00')).timestamp()
    if expires-time.time()<75*60: raise ValueError('fixed-r6-case-lease-headroom-required')
    if flow.RECEIPT.exists() and json.loads(flow.RECEIPT.read_text()).get('pending'):
        raise ValueError('fixed-r6-previous-recovery-pending')
    ev=Path.home()/'.woowbk-lab/evidence'/(binding.area if binding else 'focus-nextcloud-r6-control')/time.strftime('%Y%m%dT%H%M%S')
    ev.mkdir(parents=True,mode=0o700,exist_ok=False);os.chmod(ev.parent,0o700)
    def save(name,value):
        fd=os.open(ev/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f: json.dump(value,f,indent=2)
    snapshot=wake.device(wake.unit_program(),{'action':'snapshot'})
    baseline=wake.device(wake.BASELINE_HASH,root=True,timeout=600)
    save('prior-units.private.json',snapshot);save('prior-inventory.private.json',before)
    save('baseline-hashes.json',baseline);save('product-manifest.json',manifest)
    nonce=secrets.token_hex(8);save('source-transaction.json',{'nonce':nonce,'product_commit':product_commit})
    installed=False;attempted=False;rc=1;reverted=False;preserved=False;data_safe=True;source_return=False
    failure=None;phase='source-staging';case_entered=False;office_claim=None
    try:
        attempted=True
        deployed=source.transact('install',nonce,paths,manifest,expires)
        installed=True;save('source-installed.json',deployed)
        args.product_hashes={n.removeprefix('woowbackup/'):r['sha256'] for n,r in manifest.items() if n.startswith('woowbackup/')}
        lease_check(lease,commit,phase_name)
        phase='native-wake';wake.device(wake.unit_program(),{'action':'pin','snapshot':snapshot});reload_units()
        started=wake.device(wake.CONTROL,{'action':'start','expires_epoch':expires},timeout=1200)
        save('wake-result.json',started)
        office_claim=wake.device(cold.CLAIM);save('owned-office-invocation.json',office_claim)
        if not flow.baseline_verify(): raise RuntimeError('fixed-r6-baseline-before-import-failed')
        phase='current-'+phase_name;case_entered=True;data_safe=False
        rc=flow.run_locked(args,lease,commit,facts,before)
        data_safe=flow.RECEIPT.exists() and not json.loads(flow.RECEIPT.read_text()).get('pending',True)
        if not data_safe: raise RuntimeError('fixed-r6-baseline-recovery-incomplete')
    except Exception as error:
        # Never echo arbitrary exception contents, paths, file bodies or engine responses.
        failure='fixed-r6-'+phase+'-failed'
        if isinstance(error,RuntimeError) and str(error).startswith('fixed-source-'):
            failure=str(error)  # source module emits only whitelisted fixed constants
    finally:
        try:
            if wake.device(QUIESCENT,root=True)['active_jobs']:
                raise RuntimeError('fixed-r6-job-writer-not-quiescent-retain-code-and-copies')
            # Return native stack to cold even on failure. Keep current source if jobs/data recovery uncertain.
            stop_result=cold.stop(before['owner']['units']['nextcloud-office.service'],office_claim)
            save('cold-stop-result.json',stop_result)
            cold_state=collect()
            if any(x.get('ActiveState')!='inactive' for x in cold_state['owner']['units'].values()):
                raise RuntimeError('fixed-r6-cold-return-failed')
            wake.device(wake.unit_program(),{'action':'revert','snapshot':snapshot});reload_units()
            reverted=wake.device(wake.unit_program(),{'action':'snapshot'})==snapshot
            if attempted and data_safe:
                result=source.transact('restore',nonce,{},manifest,expires+1800)
                save('source-return.json',result);source_return=result['status']=='restored'
            after=collect();archive_after=wake.device(wake.BASELINE_HASH,root=True,timeout=600)
            save('after-inventory.private.json',after);save('baseline-hashes-after.json',archive_after)
            preserved=(after['owner']['units']==before['owner']['units']
                       and after['owner']['quadlets']==before['owner']['quadlets']
                       and after['owner']['images']==before['owner']['images']
                       and after['root']['catalog_sha256']==before['root']['catalog_sha256']
                       and after['root']['installed_hashes']==before['root']['installed_hashes']
                       and archive_after==baseline and after['isolation']==before['isolation']
                       and after['root']['memory_max']==str(DEVICE_CAP))
        except Exception:
            failure='fixed-r6-cold-or-source-return-needs-private-copy-recovery'
    passed=rc==0 and data_safe and reverted and preserved and source_return
    record={'status':'passed' if passed else 'failed','phase':binding.result_phase if binding else 'fullshare-cold-return',
            'source_commit':commit,'product_commit':product_commit,'product_manifest_sha256':source.manifest_hash(manifest),
            'source_deployed':installed,'case_entered':case_entered,'data_baseline_safe':data_safe,
            'prior_quadlets_exact':reverted,'prior_engine_helper_version_exact':source_return,
            'units_images_catalog_baseline_archive_isolation_preserved':preserved,
            'baseline_id':BASELINE,'reserve_bytes':RESERVE,'memory_cap_bytes':DEVICE_CAP,
            'pulls':0,'installer':False,'fixture_copy':False,'fixed_failure':failure,
            'source_transaction_nonce':nonce,'private_copies_retained':True}
    save('fixed-result.json',record)
    print(json.dumps({k:record[k] for k in ('status','phase','product_commit','data_baseline_safe','pulls')}))
    return 0 if passed else 1
