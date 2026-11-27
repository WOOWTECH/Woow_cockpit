#!/usr/bin/env python3
"""Leased original LiteLLM instance controller. Default invocation is offline.

Reuses the saved 80-check flow's credential readers and actual API/decryption
probes. It does not call that flow's setup/run_all/cleanup or its ordinary DB
conversion path. Every required instance checkpoint is mandatory.
"""
import argparse
import base64
import hashlib
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import focus_litellm_instance_acceptance as plan
import focus_litellm_instance_acceptance_ops as ops


def load_saved():
    spec = importlib.util.spec_from_file_location('focus_litellm_saved80',HERE/'litellm_full_flow.py')
    saved = importlib.util.module_from_spec(spec); spec.loader.exec_module(saved)
    return saved


def git(path, *args):
    return subprocess.check_output(['git','-C',str(path),*args],text=True,timeout=30).strip()


def delete_request(backup_id):
    """Exactly what the engine's `delete` accepts: the CLI schema is {backup_id} and rejects any other field (a `confirm` here
    stopped the b7 cleanup on dev-d with both case backups still present)."""
    return {'backup_id': backup_id}


def ha_delete_request(ha_backup_id):
    return {'ha_backup_id': ha_backup_id, 'confirm': True}


def snapshot_difference(current, original, *, limit=30):
    """WHERE two case snapshots differ, by field name only: digests, names and ids are never saved."""
    out = []
    def walk(a, b, path):
        if len(out) >= limit or a == b: return
        if isinstance(a,dict) and isinstance(b,dict):
            for key in sorted(set(a)|set(b),key=str): walk(a.get(key),b.get(key),path+'.'+str(key))
        else: out.append(path)
    walk(current,original,'')
    return out


def validate_lease(lease, phase, *, now, driver_commit, source_commit):
    if (lease.get('granted') is not True or lease.get('case') != 'litellm-instance-original'
            or lease.get('device') != plan.DEVICE or phase not in lease.get('phases',[])
            or phase not in plan.PHASES or lease.get('driver_commit') != driver_commit
            or not plan.CASE.fullmatch(lease.get('name',''))
            or lease.get('fixture_sha256') != plan.FIXTURE_SHA
            or lease.get('derivation_sha256') != plan.DERIVATION_SHA
            or lease.get('package_commit') != plan.PACKAGE_COMMIT
            or not isinstance(lease.get('baseline_sha256'),str) or not plan.SHA256.fullmatch(lease['baseline_sha256'])
            or lease.get('source_commit') != source_commit or source_commit != plan.FROZEN_PRODUCT
            or lease.get('baseline_policy') != 'require-litellm-absent'
            or lease.get('image_policy') not in ('retain-for-case','remove-own-after-case')):
        raise ValueError('exact coordinator lease does not authorize this phase')
    expiry = datetime.fromisoformat(lease['expires_utc'])
    if expiry.tzinfo is None: raise ValueError('lease expiry requires timezone')
    expires = expiry.timestamp()
    if not now < expires <= now+80*60: raise ValueError('expired or unbounded lease')
    return expires


def save_receipt(path, value):
    path = Path(path); path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if path.is_symlink(): raise ValueError('unsafe receipt')
    ops.atomic(path,json.dumps(value,ensure_ascii=False).encode())


def unchanged(current, original, *, images=False):
    keys = ('catalogs','files','volumes','secrets','containers','external_containers','networks','running','units','timer','package','config_directory')
    return (all(current.get(k) == original.get(k) for k in keys) and not current.get('active_jobs')
            and (not images or (current['images'] == original['images'] and current['image_refs']==original['image_refs'])))


class Controller:
    def __init__(self,args,lease,saved,*,clock=time.time,sleep=time.sleep):
        self.args=args; self.lease=lease; self.saved=saved; self.h=saved.drv
        self.clock=clock; self.sleep=sleep; self.path=Path(args.receipt); self.name=lease['name']
        self.deadline=datetime.fromisoformat(lease['expires_utc']).timestamp(); self.recovering=False
        self.ops_source=(HERE/'focus_litellm_instance_acceptance_supervisor.py').read_text()+'\n'+(
            HERE/'focus_litellm_instance_acceptance_ops.py').read_text()
        self.r=json.loads(ops.read_regular(self.path)[0]) if self.path.exists() else {
            'name':self.name,'device':plan.DEVICE,'version':1,'pending':None,'jobs':{},
            'created_backups':[],'full_safety':None,'safety_verified':False,
            'catalog_intent':False,'timer_intent':False,'install_intent':False,
            'hook_intent':False,'recovery_verified':False,'complete':False}
        if self.r['name'] != self.name or self.r['device'] != plan.DEVICE: raise ValueError('foreign receipt')
        self.run=None; self.results=[]

    def save(self): save_receipt(self.path,self.r)

    def require(self,label,condition):
        self.results.append({'check':label,'ok':bool(condition)})
        print(json.dumps({'stage':label,'ok':bool(condition)}),flush=True)
        if not condition: raise RuntimeError(label)

    def budget(self, reserve=900):
        if self.clock()+reserve >= self.deadline: raise TimeoutError('lease recovery reserve reached')

    def command(self,*args,root=False,timeout=180,input=None):
        p=(self.h.root if root else self.h.owner)(*args,input=input,timeout=timeout)
        if p.returncode:
            path=self.path.with_name(self.path.name+'.private-error-'+str(time.time_ns()))
            ops.atomic(path,p.stdout[:32768]+b'\nSTDERR\n'+getattr(p,'stderr',b'')[:16384])
            raise subprocess.CalledProcessError(p.returncode,['fixed-case-command'],output=p.stdout,stderr=getattr(p,'stderr',b''))
        return p.stdout

    def root_json(self,script,request=None,timeout=180):
        return json.loads(self.command('python3','-I','-c',script,root=True,
            input=json.dumps(request or {}).encode(),timeout=timeout))

    def op(self,operation,*,_timeout=180,**kwargs):
        self.r['pending_operation']={'operation':operation,'started_ns':time.time_ns()};self.save()
        try:
            value=self.root_json(self.ops_source,dict(kwargs,op=operation,case=self.name),timeout=_timeout)
        except Exception as exc:
            report=ops.failure_record(operation,exc)
            raw=getattr(exc,'output',None)
            if isinstance(raw,bytes) and len(raw)<=32768:
                try:report['device_error']=json.loads(raw)['operation_error']
                except (ValueError,KeyError,TypeError):pass
            path=self.path.with_name(self.path.name+'.operation-error-'+str(time.time_ns()))
            data=json.dumps(report).encode();ops.atomic(path,data)
            self.r.setdefault('operation_failures',[]).append({'operation':operation,'file':path.name,'sha256':ops.digest(data)})
            self.r['pending_operation']=None;self.save()
            raise
        self.r['pending_operation']=None;self.save();return value

    def helper(self,command,request=None,timeout=180):
        rc,value=self.h.helper(command,request,timeout=timeout)
        if rc or value.get('ok') is not True: raise RuntimeError('helper refused: '+command)
        return value

    def resources(self):
        self.budget(0 if self.recovering else 900)
        available=next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
        s=os.statvfs(plan.REPO)
        self.require('host_memory_floor',available >= 1200*1024)
        self.require('host_disk_reserve_plus_peak',s.f_bavail*s.f_frsize >= plan.MIN_FREE+plan.PEAK)
        found=self.root_json('''import json,os
from pathlib import Path
m=Path('/sys/fs/cgroup/memory.stat').read_text().splitlines()
used=sum(int(x.split()[1]) for x in m if x.startswith(('anon ','kernel ')))
paths=['/home/appowner','/var/lib/woowtech-backup/staging','/var/lib/woowtech-backup']
free=[]
for p in paths:
 s=os.statvfs(p);free.append(s.f_bavail*s.f_frsize)
print(json.dumps({'headroom':int(Path('/sys/fs/cgroup/memory.max').read_text())-used,'free':min(free)}))
''')
        self.require('device_memory_floor',found['headroom'] >= 1900*1024**2)
        self.require('actual_staging_disk_reserve_plus_peak',found['free'] >= plan.MIN_FREE+plan.PEAK)

    def begin(self):
        if 'before' in self.r:
            self.require('captured_device_receipt_matches',self.op('receipt').get('before')==self.r['before'])
            return
        before=self.op('inventory')
        observations=self.r.setdefault('baseline_observations',[])
        if len(observations)>=10: raise ValueError('too many pre-mutation attempts; review retained receipts')
        observations.append({'at':int(self.clock()),'inventory':before}); self.save()
        observed=hashlib.sha256(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.require('reviewed_baseline_pin',observed==self.lease['baseline_sha256'])
        self.require('no_active_jobs',not before['active_jobs'])
        self.require('fresh_owned_package_namespace',not before['package'] and not before['config_directory']
            and 'litellm.json' not in before['catalogs'] and not any(x.startswith('litellm') for x in before['volumes'])
            and not any(x.startswith('litellm') for x in before['containers'])
            and 'litellm-net' not in before['networks']
            and not any(x in before['secrets'] for x in plan.SECRETS)
            and not any(Path(x).name.startswith('litellm') for x in before['files'])
            and all(v['ActiveState']=='inactive' for v in before['units'].values()))
        self.r['before']=before; self.r['init_intent']=True; self.save()
        self.require('stable_original_capture',unchanged(self.op('init',image_reuse=self.r.get('image_reuse')),before,images=True))
        self.r['init_complete']=True; self.save()

    def frozen_engine(self):
        source=Path(self.args.source); root=source/'backup-engine/woowbackup'
        expected={str(p.relative_to(root)):plan.sha(p) for p in root.rglob('*.py') if '__pycache__' not in p.parts}
        expected['../woowtech-cockpit-backup']=plan.sha(source/'backup-engine/woowtech-cockpit-backup')
        self.require('exact_installed_frozen_engine',self.op('hashes') == expected)

    def image_facts(self, ref):
        lines=self.command('podman','image','inspect','--format','{{.ID}} {{.Architecture}} {{.Os}}',ref).decode().split()
        self.require('image_architecture_and_identity',len(lines)==3 and lines[1:]==['amd64','linux'])
        return plan.image_id(lines[0])

    def images(self):
        self.resources(); self.begin()
        self.require('phase_baseline_still_exact',unchanged(self.op('inventory'),self.r['before']))
        self.require('cached_app_base_pin',self.image_facts('sha256:'+plan.APP_BASE)==plan.APP_BASE)
        self.require('cached_pg17_pin',self.image_facts('sha256:'+plan.PG)==plan.PG)
        self.require('derived_tag_initially_absent',self.h.owner('podman','image','exists',plan.APP_TAG).returncode != 0)
        program=self.saved.DERIVE.encode()
        self.require('reviewed_saved80_bytes',plan.sha(HERE/'litellm_full_flow.py')==plan.SAVED_DRIVER_SHA)
        self.require('exact_builder_FROM_and_program',program.splitlines()[0]==('FROM sha256:'+plan.APP_BASE).encode()
            and hashlib.sha256(program).hexdigest()==plan.DERIVATION_SHA)
        self.r['image_intent']=True; self.save()
        built=self.op('image_build',program=base64.b64encode(program).decode(),_timeout=720)
        self.r['image_build_result']=built; self.r['owned_images']=built['owned_images']; self.save()
        self.require('owned_build_group_terminal',built['result']['terminal'] is True)
        self.require('bound_derivation_verified',built['verified'] is True)
        self.r['derived_image']=built['iid']; self.save()
        self.require('derived_tag_exact_id',self.image_facts(plan.APP_TAG)==self.r['derived_image'])
        self.require('only_derived_image_added',set(self.op('inventory')['images'])-
            set(self.r['before']['images']) == {self.r['derived_image']})
        self.require('images_no_application_changes',unchanged(self.op('inventory'),self.r['before']))
        self.r['images_ready']=True; self.save()

    def wait_job(self,jid):
        if not plan.JOB.fullmatch(jid): raise ValueError('job ID')
        stop=min(self.deadline,self.clock()+900)
        while self.clock()<stop:
            reply=self.helper('job-status',{'job_id':jid}); job=reply['job']
            if job.get('state') not in ('queued','running') and self.op('job_quiescent',job_id=jid):
                self.r['jobs'][jid]={'state':job['state'],'type':job.get('type')}
                for key in ('backup_id','safety_backup_id'):
                    bid=(job.get('result') or {}).get(key)
                    if bid:
                        if not plan.BACKUP.fullmatch(bid) or bid in self.r.get('before_backups',[]): raise ValueError('foreign backup')
                        if bid not in self.r['created_backups']: self.r['created_backups'].append(bid)
                if self.run: self.run.ev.save('instance-job-'+jid+'.json',reply)
                self.save(); return job
            self.sleep(3)
        raise TimeoutError('owned job unresolved; retain all safety copies and receipt')

    def settle(self):
        pending=self.r.get('pending')
        if not pending: return None
        jid=pending.get('job_id') or self.op('intent',request_id=pending['request_id'])
        if not jid: raise RuntimeError('uncertain start; no blind replay or cleanup')
        self.r['pending']['job_id']=jid; self.save(); job=self.wait_job(jid)
        tag=pending['tag']
        if tag=='full-safety' and job.get('state')=='succeeded': self.r['full_safety']=job['result']['backup_id']
        if tag=='convert' and job.get('state')=='succeeded': self.r['converted']=job['result']['backup_id']
        self.r['last_job']=job; self.r['last_tag']=tag; self.r['pending']=None; self.save()
        return job

    def job(self,command,request,tag):
        if self.r.get('pending'): raise RuntimeError('previous job unresolved')
        self.budget(0 if self.recovering else 900)
        if self.r.get('catalog_intent'):
            self.require('owned_catalog_before_job',self.op('inventory')['catalogs'].get('litellm.json')==self.r['catalog_sha'])
        request=dict(request,request_id=self.name+'-'+tag)
        self.r['pending']={'command':command,'request_id':request['request_id'],'tag':tag}; self.save()
        reply=self.helper(command,request)
        self.r['pending']['job_id']=reply['job_id']; self.save()
        return self.settle()

    def catalog(self, entry):
        current=self.op('inventory')['catalogs'].get('litellm.json')
        expected=self.r.get('catalog_sha',self.r['before']['catalogs'].get('litellm.json'))
        self.require('catalog_current_owned',current==expected)
        preview=self.helper('catalog-install',{'entry':entry})
        self.require('catalog_preview_cas',preview.get('valid') is True and preview.get('expected_sha256')==current)
        encoded=self.op('catalog_bytes',entry=entry)
        self.require('catalog_exact_prospective_bytes',encoded['sha256']==preview.get('new_sha256'))
        self.op('authorize_catalog',bytes=encoded['bytes'])
        self.r['catalog_intent']=True; self.r['catalog_sha']=encoded['sha256']; self.save()
        self.helper('catalog-install',{'entry':entry,'confirm':True,'expected_sha256':current})
        self.require('catalog_installed_exactly',self.op('inventory')['catalogs']['litellm.json']==encoded['sha256'])

    def credentials(self):
        if (self.recovering or getattr(self.args,'phase',None)=='recover') and 'generated_credentials' not in self.r:
            raise ValueError('missing persisted case credentials')
        if self.run: return
        # Redirect the saved driver's state before any reader/decoder runs.
        self.h.state_path=lambda:Path(self.args.receipt).with_suffix('.saved80-private.json')
        args=argparse.Namespace(secrets=self.h.Secrets(
            [self.h.SECRET_DIR/'b1-creds.env',self.h.SECRET_DIR/'ha-import-creds.env'],
            self.h.SECRET_DIR/'dev-d-markers.json'))
        ev=self.saved.Ev(args.secrets,area='focus-litellm-instance-acceptance')
        run=self.saved.Run(args,ev)
        if self.r.get('before_probe'): run.before=self.r['before_probe']
        own=('OWN_LITELLM_KEY','OWN_SEED_CREDENTIAL','WRONG_SALT')
        if 'generated_credentials' in self.r:
            persisted=self.r['generated_credentials']
            if (not isinstance(persisted,dict) or not set(own)<=set(persisted)
                    or not set(persisted)<=set(own)|{'OWN_INSTANCE_OUTSIDE_PASSWORD'}):
                raise ValueError('incomplete persisted case credentials')
            # The real reader refuses replacement of a registered value. Restore
            # these first and initialize HA inputs without generating new ones.
            for name,value in persisted.items(): args.secrets.register(name,value)
            if any(not args.secrets.values.get(n) for n in ('HA_BACKUP_KEY','LITELLM_TEST_VKEY')):
                raise ValueError('required harness credential missing')
            files=self.saved.ha_secret_files(args.secrets['HA_BACKUP_KEY'])
            for name,value in files.items(): args.secrets.register('HA_LITELLM_'+name.upper(),value)
            run.ha_salt_sha=hashlib.sha256(files['salt_key'].encode()).hexdigest()
            run.own_key=args.secrets['OWN_LITELLM_KEY']
            ev.check('secrets: persisted case values and HA inputs registered for recovery',True,
                     {'ha_files':sorted(files),'persisted_names':sorted(persisted)})
        else:
            run.load_secrets()
            self.r['generated_credentials']={name:args.secrets[name] for name in own}
            self.save()
        self.run=run

    def app_assertions(self, method, *args):
        count=len(self.run.ev.results); getattr(self.run,method)(*args)
        self.require('saved80_'+method,all(x['ok'] for x in self.run.ev.results[count:]))

    def install(self):
        self.require('images_prepared_separately',self.r.get('images_ready') is True and
            self.image_facts(plan.APP_TAG)==self.r['derived_image'])
        self.r['install_intent']=True; self.save()
        self.op('claim_install')
        rev=git(self.saved.PACKAGE,'rev-parse',plan.PACKAGE_REV+'^{commit}')
        self.require('trusted_package_full_commit',rev==plan.PACKAGE_COMMIT)
        archive=subprocess.check_output(['git','-C',str(self.saved.PACKAGE),'archive','--format=tar',rev],timeout=180)
        self.command('mkdir','-m','700',ops.APP+'/Woow_podman_litellm')
        private=ops.APP+'/.local/state/'+self.name
        self.command('mkdir','-m','700',private)
        self.command('mkdir','-m','700',private+'/tmp')
        self.command('tar','-C',ops.APP+'/Woow_podman_litellm','-xf','-',input=archive)
        if plan.PG_TAG not in self.r['before']['image_refs']:
            self.r['pg_tag_intent']=True; self.save()
            self.command('podman','tag','sha256:'+plan.PG,plan.PG_TAG)
        self.require('existing_pg_tag_pin',self.image_facts(plan.PG_TAG)==plan.PG)
        digest=self.command('podman','image','inspect','--format','{{.Digest}}',plan.PG_TAG).decode().strip()
        self.op('patch_package_pg',digest=digest)
        # Keep the package's daily timer stopped and avoid an unrelated smoke
        # test issuing credentials outside this controller's readers.
        self.command('env','QL_STATE_ROOT='+private+'/quadlet-state','TMPDIR='+private+'/tmp',
            ops.APP+'/Woow_podman_litellm/scripts/install.sh','--no-pull','--no-start',timeout=300)
        self.op('capture_installed')  # before the first app start, including partial failure
        self.command('systemctl','--user','start',*plan.UNITS,timeout=900)
        self.op('capture_installed')
        self.r['installed']=True; self.r['installed_inventory']=self.op('inventory'); self.save()
        suggestion=self.helper('catalog-suggest',{'owner':'appowner'})
        draft=next(x for x in suggestion['apps'] if x['id']=='litellm'); entry=draft['entry']
        self.require('trusted_fresh_draft',not self.saved.fresh_draft_problems(draft))
        self.r['database_entry']=entry; self.save(); self.catalog(entry)
        self.catalog(plan.instance_entry(entry))
        self.helper('key-init')
        seeded=self.run.probe('instance-seed',action='seed',seed={'credential':self.run.args.secrets['OWN_SEED_CREDENTIAL'],
            'key':self.run.own_key},wait=600)
        self.require('own_api_seed',seeded.get('seed')=={'credential':200,'model':200,'key':200,'key_echo_matches':True})
        self.app_assertions('step_before'); self.r['before_probe']=self.run.before; self.save()

    def endpoint(self):
        found=self.root_json(plan.ENDPOINT_PROBE)
        self.require('actual_installed_proxy_reader',found=={'database':'litellm','user':'litellm','host':'litellm-postgres','port':5432})

    def archive(self,bid): return self.root_json(plan.MANIFEST_PROBE,{'backup_id':bid})

    def full_archive(self,bid):
        found=self.archive(bid)
        self.require('full_unmarked_safety',found['scope']=='instance' and found['ha_database'] is None
            and found['globals_present'] and found['roles_count']>0 and 'postgres-digest' in found['digests'])
        return found

    def upload(self):
        self.require('original_fixture_sha256',plan.sha(self.saved.FIXTURE)==plan.FIXTURE_SHA)
        self.r['upload_intent']=True; self.save()
        # The content-addressed HA-store identity and initial listing prove ownership
        # even when the upload reply is lost. Raw upload credentials use stdin.
        rc,reply=self.h.upload(self.saved.FIXTURE,ev=self.run.ev)
        self.require('original_fixture_upload',rc==0 and (reply.get('ha_backup') or {}).get('id')=='ha-'+plan.FIXTURE_SHA[:20])
        self.r['store_id']='ha-'+plan.FIXTURE_SHA[:20]; self.save()

    def witness(self, action):
        request={'action':action,'name':self.name,'value':self.run.args.secrets['OWN_SEED_CREDENTIAL']}
        found=self.h.device_python(plan.API_WITNESS,request,as_owner=True,timeout=60)
        self.require('later_app_api_witness_'+action,found.get('status')==200 and found.get('found') is True)

    def flow(self):
        self.resources(); self.begin()
        self.require('phase_baseline_still_exact',unchanged(self.op('inventory'),self.r['before']))
        self.frozen_engine(); self.credentials()
        self.require('fresh_flow_only',not self.r['install_intent'] and not self.r['complete'])
        listing=self.helper('list'); self.r['before_backups']=[x['id'] for x in listing['backups']]
        self.r['before_uploads']=[x['id'] for x in listing.get('ha_backups',[])]; self.save()
        self.require('no_prior_litellm_safety_pruning',not any(x.get('type')=='safety' and any(
            a.get('id')=='litellm' for a in x.get('apps',[])) for x in listing['backups']))
        try:
            timer=self.r['before']['timer']
            if timer['UnitFileState'] not in ('masked','masked-runtime'):
                self.r['timer_intent']=True; self.save()
                self.command('systemctl','mask','--runtime','--now',plan.TIMER,root=True)
            else: self.require('preexisting_masked_timer_inactive',timer['ActiveState']=='inactive')
            self.install(); self.endpoint()
            self.r['original_db']=self.op('snapshot',tag='original'); self.save()
            full=self.job('backup-start',{'apps':['litellm'],'encrypt':True,'include_images':False,
                'note':'original LiteLLM whole-instance case full safety'},'full-safety')
            self.require('fresh_full_safety_succeeded',full.get('state')=='succeeded')
            manifest=self.full_archive(self.r['full_safety'])
            self.require('fresh_safety_all_databases',{d[0] for d in manifest['databases']}==set(self.r['original_db']['database_names']))
            self.r['safety_verified']=True; self.save()
            self.op('fixture',action='create'); self.upload()
            key=self.run.args.secrets['HA_BACKUP_KEY']
            checked=self.job('ha-check-start',{'ha_backup_id':self.r['store_id'],'apps':['litellm'],'key':key},'check')
            self.require('original_check_succeeded',checked.get('state')=='succeeded')
            check=checked['result']['ha_check']['apps'][0]; self.saved.require_reviewed_check(check)
            self.require('original_fixture_shape',all(check.get('litellm',{}).get(k)==v for k,v in self.saved.EXPECTED.items()))
            self.endpoint()
            converted=self.job('ha-convert-start',{'ha_backup_id':self.r['store_id'],'apps':['litellm'],
                'key':key,'test_mode':False,'confirm':True},'convert')
            self.require('instance_conversion_succeeded',converted.get('state')=='succeeded')
            marker=self.archive(self.r['converted'])
            self.require('actual_complete_instance_manifest',marker['scope']=='instance' and marker['ha_database']=='litellm'
                and marker['ha_access_valid'] and marker['globals_present'] and marker['roles_count']>0
                and {x[0] for x in marker['databases']}=={'postgres','litellm',self.name+'_outside'})
            password=os.urandom(24).hex(); self.run.args.secrets.register('OWN_INSTANCE_OUTSIDE_PASSWORD',password)
            self.r['generated_credentials']['OWN_INSTANCE_OUTSIDE_PASSWORD']=password; self.save()
            self.op('fixture',action='late',password=password)
            before=self.op('snapshot',tag='late'); self.endpoint()
            imported=self.job('restore-start',{'backup_id':self.r['converted'],'apps':['litellm'],'confirm':True},'import')
            self.require('selective_instance_import',plan.success(imported))
            self.full_archive(imported['result']['safety_backup_id'])
            self.require('live_later_outsiders_roles_passwords_preserved',plan.outsiders_equal(before,self.op('snapshot',tag='imported')))
            self.app_assertions('verify','instance-import')
            self.app_assertions('step_restart'); self.endpoint()
            self.witness('create')
            current=self.op('snapshot',tag='before_failure')
            self.r['hook_intent']=True; self.save(); self.op('hook',enable=True)
            failed=self.job('restore-start',{'backup_id':self.r['converted'],'apps':['litellm'],'confirm':True},'forced-failure')
            consumed=self.op('hook_consumed'); self.op('hook',enable=False); self.r['hook_intent']=False; self.save()
            after=self.op('snapshot',tag='after_failure'); self.witness('check')
            full_safety=self.full_archive(failed['result']['safety_backup_id'])
            log='\n'.join(str(x) for x in self.helper('job-status',{'job_id':failed['id']}).get('log',[]))
            digest_log='資料摘要 db-main 與備份時一致' in log and '未比對資料' not in log
            self.require('automatic_full_current_safety_rollback',plan.rollback_proven(failed,hook=consumed,witness=True,
                before=current,after=after,full_safety=bool(full_safety),digest_log=digest_log))
            self.app_assertions('verify','instance-automatic-rollback')
            self.r['flow_verified']=True; self.save()
        finally:
            self.recover()

    def verify_recovered_snapshot(self):
        """The restored catalog, roles and rows equal the original. Every snapshot writes its digest listings exclusively, so a
        repeated recovery needs a tag no earlier one used. The original is re-stated with the volatile tables excluded (a snapshot
        taken that way is unchanged); a lasting difference is saved by field NAME before the check fails."""
        used=set(self.op('receipt').get('snapshots') or {})
        tag=next(t for t in ('recovered','recovered_again','recovered_third','recovered_fourth') if t not in used)
        recovered=self.op('snapshot',tag=tag); expected=self.op('snapshot_restate',tag='original')
        if recovered!=expected:
            self.r['recovery_snapshot_difference']=snapshot_difference(recovered,expected); self.save()
        self.require('original_full_catalog_roles_rows',recovered==expected)

    def recover(self):
        self.recovering=True; self.settle()
        if self.r.get('hook_intent'):
            self.op('hook',enable=False); self.r['hook_intent']=False; self.save()
        if self.r.get('recovery_verified'):
            # An earlier pass restored and verified the data and own state, then stopped in the cleanup below (b7: the delete
            # request). The stack may already be removed, so nothing is restored or verified again; only the saved credential
            # values are re-registered for the leak scan that guards the cleanup.
            self.credentials()
        elif self.r.get('full_safety'):
            self.credentials()
            restored=self.job('restore-start',{'backup_id':self.r['full_safety'],'apps':['litellm'],'confirm':True},'recover-full')
            self.require('original_full_safety_restored',plan.success(restored,digest=True))
            self.verify_recovered_snapshot()
            self.app_assertions('own_state','instance-full-recovery')
            self.r['recovery_verified']=True; self.save()
        elif self.r.get('install_intent'):
            self.require('no_app_mutation_before_verified_safety',not self.r.get('safety_verified') and not self.r.get('upload_intent'))
        self.require('all_jobs_terminal',not self.op('inventory')['active_jobs'])
        if self.run:
            self.app_assertions('step_leaks')
        # Copies survive every uncertainty. Cleanup runs only after successful
        # recovery and the saved credential scanner, never in a blind finally.
        self.op('cleanup_owned_package')
        if self.r.get('pg_tag_intent'):
            self.require('owned_pg_tag_pin_before_untag',self.image_facts(plan.PG_TAG)==plan.PG)
            self.command('podman','untag','sha256:'+plan.PG,plan.PG_TAG)
            self.r['pg_tag_intent']=False; self.save()
        if self.r.get('catalog_intent'): self.op('restore_catalog'); self.r['catalog_intent']=False; self.save()
        if self.r.get('timer_intent'):
            self.command('systemctl','unmask','--runtime',plan.TIMER,root=True)
            state=self.r['before']['timer']['ActiveState']
            self.require('known_original_timer_state',state in ('active','inactive'))
            self.command('systemctl','start' if state=='active' else 'stop',plan.TIMER,root=True)
            self.r['timer_intent']=False; self.save()
        self.require('original_device_durable_state',unchanged(self.op('inventory'),self.r['before']))
        listing=self.helper('list'); existing={x['id'] for x in listing['backups']}
        self.require('preexisting_backups_preserved',set(self.r.get('before_backups',[])) <= existing)
        for bid in self.r['created_backups']:
            if bid in existing: self.helper('delete',delete_request(bid))
        sid=self.r.get('store_id')
        if sid and sid not in self.r.get('before_uploads',[]): self.helper('ha-delete',ha_delete_request(sid))
        self.r['complete']=True; self.save()

    def images_recover(self):
        self.settle(); self.require('no_application_left',unchanged(self.op('inventory'),self.r['before']))
        state=self.op('receipt').get('image_build',{})
        self.require('build_terminal_receipt',state.get('process',{}).get('terminal') is True)
        self.require('no_unknown_image_ownership',not state.get('unknown_images',[]))
        images=self.r.get('owned_images') or state.get('owned_images',[])
        current=self.op('inventory')
        if self.r.get('image_intent'):
            self.require('known_owned_derived_ids',bool(images) and not (set(images)&set(self.r['before']['images'])))
            remaining=set(current['images'])-set(self.r['before']['images'])
            removals=self.r.setdefault('image_removal_intents',[])
            self.require('exact_owned_image_delta',remaining<=set(images) and set(images)-remaining<=set(removals))
            before_refs=self.r['before']['image_refs']
            self.require('no_foreign_image_tags',all(current['image_refs'].get(k)==v for k,v in before_refs.items())
                and set(current['image_refs'])-set(before_refs)<={plan.APP_TAG})
            self.op('image_context_cleanup')
            for image in sorted(remaining,key=lambda i:i!=state.get('iid')):
                if image not in removals: removals.append(image); self.save()
                self.command('podman','image','rm','--no-prune','sha256:'+image)
        self.require('original_images_returned',unchanged(self.op('inventory'),self.r['before'],images=True))
        self.r['images_recovered']=True; self.save()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=plan.PHASES,default='flow'); parser.add_argument('--execute',action='store_true')
    parser.add_argument('--source',default='/tmp/parity-focus-final-product-20261127')
    parser.add_argument('--lease'); parser.add_argument('--receipt'); parser.add_argument('--output')
    args=parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({'preparation_only':True,'source_commit':plan.FROZEN_PRODUCT,'device':plan.DEVICE,
            'phases':plan.PHASES,'fixture_sha256':plan.FIXTURE_SHA,'reserve_bytes':plan.MIN_FREE,
            'peak_bytes':plan.PEAK,'runtime_authorized':False})); return 0
    if not all((args.lease,args.receipt,args.output)): parser.error('execute requires lease, receipt and unique output')
    if Path(args.output).exists(): parser.error('attempt output already exists')
    lease=json.loads(ops.read_regular(args.lease)[0])
    validate_lease(lease,args.phase,now=time.time(),driver_commit=git(plan.REPO,'rev-parse','HEAD'),source_commit=git(args.source,'rev-parse','HEAD'))
    if git(plan.REPO,'status','--porcelain') or git(args.source,'status','--porcelain'): raise ValueError('dirty source')
    saved=load_saved(); saved.verify_isolation()
    fd,_waited=saved.acquire()  # caller must also hold the existing global heavy slot
    controller=None
    def interrupted(_signum,_frame): raise InterruptedError('case interrupted; recover receipt')
    for signum in (signal.SIGINT,signal.SIGTERM): signal.signal(signum,interrupted)
    try:
        validate_lease(lease,args.phase,now=time.time(),driver_commit=git(plan.REPO,'rev-parse','HEAD'),source_commit=git(args.source,'rev-parse','HEAD'))
        controller=Controller(args,lease,saved); controller.r['phase_succeeded']=False; controller.save()
        getattr(controller,args.phase.replace('-','_'))()
        controller.require('outer_isolation_returned',saved.verify_isolation()=='dev-d isolation: true none {}')
        controller.r['phase_succeeded']=True; controller.save()
        return 0
    finally:
        if controller:
            save_receipt(args.output,{'preparation_only':False,'case':'litellm-instance-original',
                'phase':args.phase,'driver_commit':lease['driver_commit'],'source_commit':lease['source_commit'],
                'phase_succeeded':controller.r.get('phase_succeeded',False),
                'baseline_sha256':lease['baseline_sha256'],'derivation_sha256':plan.DERIVATION_SHA,
                'owned_images':controller.r.get('owned_images',[]),'images_ready':controller.r.get('images_ready',False),
                'complete':controller.r['complete'],'flow_verified':controller.r.get('flow_verified',False),
                'recovery_verified':controller.r['recovery_verified'],'checks':controller.results})
        os.close(fd)


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception:
        print(json.dumps({'ok':False,'error':'case stopped; private receipt retained; raw diagnostics withheld'}),flush=True)
        sys.exit(1)
