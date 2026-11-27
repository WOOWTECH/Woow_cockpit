"""Offline controller guards/recovery, real local file journal, fixed hook proof.

These tests never contact a device and do not claim vendor/native acceptance.
"""
from contextlib import redirect_stdout
from datetime import datetime,timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import focus_n8n_instance_acceptance_run as run
import focus_n8n_instance_acceptance_ops as ops

NAME='woowbk_focus_n8n_abcdef012345'
JID='j20261127T010101Z-abcdef01'
BID='20261127T010102Z-abcdef02'


def lease():
    return dict(granted=True,device=run.plan.DEVICE,case='n8n-instance-original',phases=list(run.PHASES),
                driver_commit='a'*40,source_commit=run.FROZEN_PRODUCT,catalog_sha256=run.plan.FOUND_SHA,
                name=NAME,image_policy='retain-for-case',expires_utc=datetime.fromtimestamp(2000,timezone.utc).isoformat(),
                image_archives=run.IMAGE_ARCHIVES,bounds=run.BOUNDS)


def inventory():
    return {'catalog':{'n8n.json':run.plan.FOUND_SHA},'entry':{},'files':{},'protected':{'old':'hash'},
            'units':{u:{'ActiveState':'inactive'} for u in ops.UNITS},'timer':{'ActiveState':'active'},
            'retention_keep':None,'retention_sha256':None,'volumes':['original'],
            'images':[v for k,v in run.plan.IMAGE_IDS.items() if v not in run.plan.ARCHIVES],
            'running':[],'active_jobs':[]}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        self.path=Path(self.folder.name)
        self.clock=[1000]
        self.wire=SimpleNamespace(LP='/isolated/labpodman')
        self.c=run.Controller(SimpleNamespace(source=run.REPO,receipt=self.path/'receipt.json'),lease(),self.wire,
                              clock=lambda:self.clock[0],sleep=lambda n:self.clock.__setitem__(0,self.clock[0]+n))
        self.addCleanup(patch.stopall)
        patch('sys.stdout',new=io.StringIO()).start()


class LeaseTests(unittest.TestCase):
    def test_lease_attempt_must_be_a_small_positive_integer(self):
        valid=lease()
        for value in (0,100,-1,'2',True,2.5):
            with self.subTest(attempt=value),self.assertRaises(ValueError):
                run.validate_lease(dict(valid,attempt=value),'flow',now=1000,driver_commit='a'*40,
                                   source_commit=run.FROZEN_PRODUCT)
        self.assertEqual(run.validate_lease(dict(valid,attempt=2),'flow',now=1000,driver_commit='a'*40,
                                            source_commit=run.FROZEN_PRODUCT),2000)

    def test_exact_product_driver_phase_expiration_and_image_policy_are_required(self):
        valid=lease()
        self.assertEqual(run.validate_lease(valid,'flow',now=1000,driver_commit='a'*40,
                                           source_commit=run.FROZEN_PRODUCT),2000)
        changes=[('granted',False),('device','other'),('driver_commit','b'*40),('source_commit','b'*40),
                 ('catalog_sha256','f'*64),('name','n8n'),('image_policy',None),('phases',['images']),
                 ('expires_utc',datetime.fromtimestamp(999,timezone.utc).isoformat())]
        for key,value in changes:
            with self.subTest(key=key),self.assertRaises(ValueError):
                run.validate_lease(dict(valid,**{key:value}),'flow',now=1000,driver_commit='a'*40,
                                   source_commit=run.FROZEN_PRODUCT)

    def test_images_does_not_require_deploying_product_or_waking_app(self):
        self.assertEqual(run.validate_lease(lease(),'images',now=1000,
                         driver_commit='a'*40,source_commit=run.FROZEN_PRODUCT),2000)
        for key,value in (('source_commit','b'*40),('image_archives',{}),('bounds',{})):
            with self.subTest(key=key),self.assertRaises(ValueError):
                run.validate_lease(dict(lease(),**{key:value}),'images',now=1000,
                                   driver_commit='a'*40,source_commit=run.FROZEN_PRODUCT)

    def test_default_never_constructs_controller_or_device_transport(self):
        with patch.object(run,'Controller',side_effect=AssertionError('no device')), \
                patch.object(run,'git',side_effect=AssertionError('no runtime')),redirect_stdout(io.StringIO()):
            self.assertEqual(run.main([]),0)


class JournalTests(Fixture):
    def test_device_diagnostic_accepts_only_fixed_class_and_never_raw_stderr(self):
        self.wire.root=lambda *a,**kw:SimpleNamespace(returncode=1,stderr=b'{"error_class":"ValueError","raw":"private-fixture"}')
        with self.assertRaises(RuntimeError):self.c.root_json('pass')
        self.assertNotIn('private-fixture',self.c.path.read_text())
        self.assertNotIn('device_error_class',self.c.r)
        self.wire.root=lambda *a,**kw:SimpleNamespace(returncode=1,stderr=b'{"error_class":"ValueError"}')
        with self.assertRaises(RuntimeError):self.c.root_json('pass')
        self.assertEqual(self.c.r['device_error_class'],'ValueError')

    def test_receipt_atomic_private_and_old_record_survives_interrupted_temp(self):
        self.c.save();self.assertEqual(self.c.path.stat().st_mode&0o777,0o600)
        old=self.c.path.read_bytes();self.c.path.with_name('receipt.json.new').write_text('incomplete')
        with self.assertRaises(FileExistsError):self.c.save()
        self.assertEqual(self.c.path.read_bytes(),old)

    def test_lost_start_reply_adopts_engine_journal_and_waits_service_exit(self):
        self.c.r['pending']={'request_id':'own-request','tag':'full-safety','command':'backup-start'}
        calls=[];quiet=iter([False,True])
        self.c.op=lambda op,**kw: JID if op=='intent' else next(quiet)
        def helper(command,request):
            calls.append(command)
            return {'job':{'id':JID,'state':'succeeded','type':'backup','result':{'backup_id':BID}}}
        self.c.helper=helper
        job=self.c.settle()
        self.assertEqual(job['id'],JID);self.assertIsNone(self.c.r['pending'])
        self.assertEqual(self.c.r['full_safety'],BID)
        self.assertEqual(self.c.r['created_backups'],[BID])
        self.assertEqual(calls,['job-status','job-status'])

    def test_uncertain_job_never_replays_start_or_stops_services(self):
        self.c.r['pending']={'request_id':'uncertain','tag':'convert','command':'ha-convert-start'}
        self.c.op=lambda *a,**k:None
        commands=[];self.c.command=lambda *a,**k:commands.append(a)
        with self.assertRaises(RuntimeError):self.c.recover()
        self.assertEqual(commands,[]);self.assertIsNotNone(self.c.r['pending'])

    def test_still_running_job_timeout_keeps_every_copy_and_does_not_restore(self):
        self.c.deadline=1004
        self.c.r['pending']={'request_id':'own','job_id':JID,'tag':'convert','command':'ha-convert-start'}
        self.c.helper=lambda *a,**k:{'job':{'state':'running'}}
        commands=[];self.c.command=lambda *a,**k:commands.append(a)
        with self.assertRaises(TimeoutError):self.c.recover()
        self.assertEqual(commands,[]);self.assertIsNotNone(self.c.r['pending'])

    def test_existing_backup_cannot_be_adopted_as_owned(self):
        self.c.r['before_backups']=[BID]
        self.c.op=lambda *a,**k:True
        self.c.helper=lambda *a,**k:{'job':{'state':'succeeded','result':{'backup_id':BID}}}
        with self.assertRaises(ValueError):self.c.wait_job(JID)
        self.assertEqual(self.c.r['created_backups'],[])


class ImageTests(Fixture):
    def test_changed_reviewed_sidecar_refuses_before_original_copy_or_load(self):
        before=inventory();calls=[]
        self.c.op=lambda op,**kw:calls.append(op) or before
        with patch.object(run.plan,'reviewed_baselines',return_value={'old':'changed-sidecar'}),self.assertRaises(RuntimeError):
            self.c.acquire_original()
        self.assertEqual(calls,['inventory']);self.assertEqual(self.c.r['image_intents'],[])

    def test_partial_image_cleanup_removes_only_proven_own_id_without_force_or_prune(self):
        before=inventory();config=next(iter(run.plan.ARCHIVES));now=dict(before,images=before['images']+[config])
        self.c.r.update(before=before,image_intents=[config]);commands=[]
        self.c.op=lambda *a,**k:now
        def command(*args,**kwargs):
            commands.append(args);now['images'].remove(args[-1].removeprefix('sha256:'))
        self.c.command=command
        self.c.images_recover()
        self.assertEqual(commands,[('podman','image','rm','--no-prune','sha256:'+config)])
        self.assertNotIn('--force',commands[0]);self.assertEqual(now['images'],before['images'])

    def test_unknown_image_is_retained_and_no_delete_occurs(self):
        before=inventory();self.c.r.update(before=before,image_intents=list(run.plan.ARCHIVES))
        self.c.op=lambda *a,**k:dict(before,images=before['images']+['unknown'])
        commands=[];self.c.command=lambda *a,**k:commands.append(a)
        with self.assertRaises(RuntimeError):self.c.images_recover()
        self.assertEqual(commands,[])

    def test_image_pipeline_only_executes_load_inside_lab_and_records_intent_first(self):
        before=inventory();self.c.resources=lambda:None
        self.c.acquire_original=lambda:before
        self.c.op=lambda *a,**k:dict(before,images=before['images']+list(self.c.r['owned_images']))
        inspections=[]
        def command(*args,**kwargs):
            inspections.append(args)
            # Podman ImageInspectReport exposes ID, not Docker's Id. Reject the
            # actual invalid command rather than returning the requested ID for any argv.
            self.assertEqual(args,('podman','image','inspect','sha256:'+self.c.r['image_intents'][-1],
                                   '--format','{{.ID}}'))
            return args[3].encode()
        self.c.command=command
        seen=[]
        class Child:
            stdout=SimpleNamespace(close=lambda:None)
            def wait(self,timeout):return 0
            def poll(self):return 0
        def popen(argv,**kwargs):
            seen.append(argv)
            if argv[0]==self.wire.LP:
                self.assertIn(self.c.r['image_intents'][-1],run.plan.ARCHIVES)
                self.assertEqual(json.loads(self.c.path.read_text())['image_intents'],self.c.r['image_intents'])
            return Child()
        with patch.object(run.plan,'verify_cache',return_value=[]),patch.object(run.subprocess,'Popen',side_effect=popen):
            self.c.images()
        self.assertEqual(len(seen),4)
        for argv in seen:
            if argv[0]!='gzip':
                self.assertEqual(argv[:4],[self.wire.LP,'exec','-i',run.plan.DEVICE])
                self.assertEqual(argv[-2:],['podman','load'])
        self.assertTrue(self.c.r['images_ready'])
        self.assertEqual(len(inspections),2)


class FilesAndPredicateTests(Fixture):
    def store(self):
        source=self.path/'original.env';source.write_bytes(b'private-original\n')
        store=ops.Store(NAME,parent=self.path/'cases',create=True);store.capture([str(source)])
        return source,store

    def test_protected_bytes_restore_mode_owner_mtime_and_refuse_external_edit(self):
        source,store=self.store();original=source.read_bytes();before=source.stat()
        store.replace(str(source),b'case\n');store.restore([str(source)])
        self.assertEqual(source.read_bytes(),original)
        after=source.stat()
        self.assertEqual((after.st_mode,after.st_uid,after.st_gid,after.st_mtime_ns),
                         (before.st_mode,before.st_uid,before.st_gid,before.st_mtime_ns))
        source.write_bytes(b'operator-change\n')
        with self.assertRaises(ValueError):store.restore([str(source)])
        self.assertEqual(source.read_bytes(),b'operator-change\n')

    def test_archive_and_per_id_json_sidecar_are_both_hashed_and_absence_preserved(self):
        for bid,suffix in zip(ops.PROTECTED,('.tar','.woowbackup')):
            (self.path/(bid+suffix)).write_bytes(b'protected archive')
        bid=ops.PROTECTED[0];side=self.path/(bid+'.json');side.write_bytes(b'{"inspected":false}')
        first=ops.protected_inventory(self.path)
        self.assertEqual(first[bid]['archive']['sha256'],ops.digest(b'protected archive'))
        self.assertEqual(first[bid]['sidecar']['sha256'],ops.digest(side.read_bytes()))
        self.assertEqual(first[bid]['archive']['filename'],bid+'.tar')
        self.assertEqual(first[bid]['sidecar']['filename'],bid+'.json')
        self.assertIsNone(first[ops.PROTECTED[1]]['sidecar'])
        side.write_bytes(b'{"inspected":true}')
        self.assertNotEqual(first,ops.protected_inventory(self.path))
        side.unlink()
        self.assertNotEqual(first,ops.protected_inventory(self.path))

    def test_protected_archive_rejects_symlink_duplicate_and_missing_archive(self):
        for bid in ops.PROTECTED:(self.path/(bid+'.tar')).write_bytes(b'archive')
        bid=ops.PROTECTED[0];other=self.path/(bid+'.woowbackup');other.write_bytes(b'duplicate')
        with self.assertRaises(ValueError):ops.protected_inventory(self.path)
        other.unlink();side=self.path/(bid+'.json');side.symlink_to(self.path/(bid+'.tar'))
        with self.assertRaises(OSError):ops.protected_inventory(self.path)
        side.unlink();archive=self.path/(bid+'.tar');archive.unlink();archive.symlink_to(other)
        with self.assertRaises(OSError):ops.protected_inventory(self.path)
        archive.unlink();side.write_bytes(b'{}')
        with self.assertRaises(ValueError):ops.protected_inventory(self.path)

    def test_file_replacement_intent_survives_atomic_write_failure(self):
        source,store=self.store();real=ops.atomic
        def atomic(path,data,**kwargs):
            if Path(path)==source:raise OSError('partial failure')
            return real(path,data,**kwargs)
        with patch.object(ops,'atomic',side_effect=atomic),self.assertRaises(OSError):
            store.replace(str(source),b'case')
        reread=ops.Store(NAME,parent=self.path/'cases')
        self.assertIn(ops.digest(b'case'),reread.state['allowed'][str(source)])
        self.assertEqual(source.read_bytes(),b'private-original\n')

    def test_changed_recovery_copy_never_restores(self):
        source,store=self.store();meta=store.state['original'][str(source)]
        (store.path/meta['copy']).write_bytes(b'changed recovery')
        with self.assertRaises(ValueError):store.restore([str(source)])

    def test_hook_refuses_repeated_starts_until_original_marker_restored(self):
        program=ops.predicate_script(NAME,self.path)
        exits=[];calls=[]
        for answer in (b'false\n',b'false\n',b'true\n'):
            def call(argv,**kwargs):
                calls.append((argv,kwargs));return SimpleNamespace(returncode=0,stdout=answer)
            with patch.object(subprocess,'run',side_effect=call),self.assertRaises(SystemExit) as e:
                exec(program,{'__name__':'hook'})
            exits.append(e.exception.code)
        self.assertEqual(exits,[1,1,0])
        self.assertTrue((self.path/'refused').is_file());self.assertTrue((self.path/'allowed').is_file())
        for argv,kwargs in calls:
            self.assertEqual(argv[-1],'-');self.assertNotIn('PASSWORD',' '.join(argv))
            self.assertEqual(kwargs['input'],ops.MARKER_SQL.encode())
            for word in ('INSERT','UPDATE','DELETE','CREATE','DROP'):self.assertNotIn(word,ops.MARKER_SQL)

    def test_hook_rejects_non_case_database(self):
        with self.assertRaises(ValueError):ops.predicate_script('n8n',self.path)

    def test_symlink_recovery_file_is_never_read(self):
        source=self.path/'file';source.write_text('private');link=self.path/'link';link.symlink_to(source)
        with self.assertRaises(OSError):ops.read_regular(link)

    def test_foreign_loaded_dependency_refuses_before_any_service_start(self):
        calls=[]
        self.c.op=lambda op,**kwargs: (_ for _ in ()).throw(ValueError('foreign dependency'))
        self.c.command=lambda *a,**kw:calls.append(a)
        with self.assertRaises(ValueError):self.c.start_units(['n8n.service'])
        self.assertEqual(calls,[])

    def test_loaded_requires_wants_bindsto_are_checked_for_every_app_unit(self):
        p=SimpleNamespace(returncode=0,stdout=b'LoadState=loaded\nRequires=other-app.service\nWants=\nBindsTo=\n')
        with patch.object(ops,'owner',return_value=p),self.assertRaises(ValueError):
            ops.dependencies({'quadlet':{'files':[]}})


class RestoreTests(Fixture):
    def safety_fixture(self,private_copies=True):
        before=inventory();before['images']=list(run.plan.IMAGE_IDS.values());self.c.r['before']=before;order=[]
        snap={'database_names':['n8n','postgres'],'databases':{}}
        # The preserved old safety pairs (cbbc68f7) and the four canonical image references (7820caf1) are read by
        # safety() before any service, catalog or timer action; these fakes answer exactly those fixed questions.
        prepared={'private_copy_verified':private_copies,'private_files':4 if private_copies else 0,'protected_old_ids':[]}
        self.c.h.owner=lambda *a,**kw:SimpleNamespace(returncode=0,stdout=run.plan.IMAGE_IDS[a[3]].encode())
        self.c.resources=lambda:None;self.c.acquire_original=lambda:before;self.c.frozen_engine=lambda:None
        self.c.op=lambda op,**kw: (before if op=='inventory' else snap if op=='snapshot'
                                   else prepared if op=='preserved_safety_prepare' else {})
        def helper(command,request=None):
            if command=='list':return {'backups':[],'ha_backups':[]}
            if command=='inspect':return {'backup':{'encrypted':True}}
            raise AssertionError(command)
        self.c.helper=helper
        self.c.pause_timer=lambda:order.append('pause')
        self.c.scope_instance=lambda:order.append('scope')
        self.c.start_units=lambda units:order.append('start-pg')
        self.c.pg_ready=lambda:None;self.c.sql=lambda *a,**kw:True
        self.c.stop_units=lambda:order.append('stop-all')
        self.c.restore_catalog=lambda:order.append('catalog-back')
        self.c.restore_timer=lambda:order.append('timer-back')
        self.c.archive_probe=lambda bid:{'scope':'instance','ha_database':None,'globals_present':True,
                                        'roles_count':1,'databases':[['n8n','n8n'],['postgres','n8n']]}
        return order

    def test_fresh_full_safety_stage_returns_services_catalog_and_timer(self):
        order=self.safety_fixture()
        self.c.job=lambda *a,**kw:{'state':'succeeded','result':{'backup_id':BID}}
        self.c.safety()
        self.assertEqual(order,['pause','scope','start-pg','stop-all','catalog-back','timer-back'])
        self.assertEqual(self.c.r['full_safety'],BID);self.assertTrue(self.c.r['safety_verified'])

    def test_safety_job_failure_still_returns_original_lifecycle(self):
        order=self.safety_fixture()
        self.c.job=lambda *a,**kw:(_ for _ in ()).throw(TimeoutError('no job started'))
        with self.assertRaises(TimeoutError):self.c.safety()
        self.assertEqual(order[-3:],['stop-all','catalog-back','timer-back'])
        self.assertFalse(self.c.r['safety_verified'])

    def test_retry_uses_a_new_request_id_and_an_engine_replay_of_an_old_job_is_refused(self):
        seen=[];reply={'job_id':'j20261127T000000Z-0000000a'}
        self.c.helper=lambda command,request=None:(seen.append(request['request_id']),dict(reply))[1]
        def settle():
            self.c.r['pending']=None;return {'state':'succeeded'}
        self.c.settle=settle
        self.c.job('backup-start',{},'full-safety')
        self.c.lease=dict(self.c.lease,attempt=2);reply['job_id']='j20261127T000000Z-0000000b'
        self.c.job('backup-start',{},'full-safety')
        self.assertEqual(seen,[NAME+'-full-safety',NAME+'-full-safety-a2'])
        # SAFETY4 on dev-c: the engine answered the repeated id with the failed SAFETY3 job; that must be refused.
        self.c.r['jobs']={'j20261127T000000Z-0000000c':{'state':'failed','type':'backup'}}
        reply['job_id']='j20261127T000000Z-0000000c'
        with self.assertRaisesRegex(RuntimeError,'earlier job'):self.c.job('backup-start',{},'full-safety')
        self.assertIsNone(self.c.r.get('pending'))

    def test_original_state_check_waits_for_a_late_settling_difference_and_names_a_lasting_one(self):
        before=inventory();self.c.r['before']=before
        states=[dict(before,running=['n8n-postgres']),dict(before,running=['n8n-postgres']),before]
        self.c.op=lambda op,**kw:states.pop(0) if len(states)>1 else states[0]
        self.c.require_original_state('state')                      # settles on the third read
        self.assertEqual(len(states),1);self.assertNotIn('original_state_difference',self.c.r)
        self.c.op=lambda op,**kw:dict(before,running=['a-private-looking-value'],files={'/etc/x':{'sha256':'f'*64}},active_jobs=['j1'])
        with self.assertRaisesRegex(RuntimeError,'state'):self.c.require_original_state('state')
        names=self.c.r['original_state_difference']
        self.assertEqual(names,['files./etc/x','running','active_jobs'])
        self.assertNotIn('a-private-looking-value',json.dumps(names))   # field names only, never values

    def test_unverified_private_copies_refuse_before_any_service_catalog_or_timer_action(self):
        order=self.safety_fixture(private_copies=False)
        self.c.job=lambda *a,**kw:self.fail('no backup job may start without the private copies')
        with self.assertRaisesRegex(RuntimeError,'old_pairs_private_copy_verified'):self.c.safety()
        self.assertEqual(order,[]);self.assertFalse(self.c.r['safety_verified'])

    def test_unconfigured_optional_digests_are_not_invented_and_any_real_failure_stops(self):
        job={'state':'succeeded','result':{'rolled_back':False,'safety_backup_id':BID,'health':[{'status':'ok'}]}}
        self.assertTrue(run.successful_restore(job))
        job['result']['verification']=[{'checks':[{'match':False}]}]
        self.assertFalse(run.successful_restore(job))

    def test_recover_settles_before_unhook_or_any_service_stop(self):
        order=[]
        self.c.settle=lambda:order.append('settle')
        self.c.op=lambda op,**kw:order.append(op) or dict(inventory(),active_jobs=[JID])
        self.c.stop_units=lambda:order.append('stop')
        with self.assertRaises(RuntimeError):self.c.recover()
        self.assertEqual(order,['settle','inventory'])

    def test_no_safety_no_destructive_recovery(self):
        self.c.r.update(before=inventory(),fixture_intent=True,safety_verified=False)
        self.c.op=lambda *a,**k:inventory()
        order=[];self.c.stop_units=lambda:order.append('stop');self.c.job=lambda *a,**k:order.append('restore')
        with self.assertRaises(RuntimeError):self.c.recover()
        self.assertNotIn('restore',order)

    def test_recovery_restores_declared_file_mtime_after_product_archive_restore(self):
        files=[self.path/'main.container',self.path/'runners.json']
        for i,p in enumerate(files):
            p.write_bytes(('original-'+str(i)).encode());os.utime(p,ns=(1000000000,1200000000+i))
        store=ops.Store(NAME,parent=self.path/'cases',create=True);store.capture([str(p) for p in files])
        def found():return dict(inventory(),files={str(p):ops.read_regular(p)[1] for p in files})
        before=found();snapshot={'databases':{'n8n':'all-rows'}}
        self.c.r.update(before=before,fixture_intent=True,safety_verified=True,full_safety=BID,
                        original_db=snapshot,original_secrets={})
        self.c.helper=lambda *a,**kw:{}
        self.c.stop_units=lambda:None;self.c.start_units=lambda *a:None;self.c.pg_ready=lambda:None
        self.c.restore_catalog=lambda:None;self.c.restore_timer=lambda:None;self.c.cleanup_owned=lambda:None
        self.c.command=lambda *a,**kw:None
        def operation(op,**kwargs):
            if op=='inventory':return found()
            if op=='restore_files':store.restore([str(p) for p in files]);return True
            if op=='snapshot':return snapshot
            if op=='secrets':return {}
            if op=='preserved_safety_return':return {'all_preexisting_files_exact':True}
            raise AssertionError(op)
        self.c.op=operation
        def job(*a,**kw):
            # Real archive restore can replace unchanged files with new mtimes.
            for p in files:p.write_bytes(p.read_bytes());os.utime(p,ns=(3000000000,3000000000))
            return {'state':'succeeded','result':{'rolled_back':False,'safety_backup_id':BID,
                                                'health':[{'status':'ok'}]}}
        self.c.job=job
        with patch.object(run.plan,'preflight_ready',return_value=True):self.c.recover()
        self.assertEqual(found(),before);self.assertTrue(self.c.r['recovery_verified'])

    def test_recovery_is_not_verified_until_the_old_safety_pairs_are_returned_exactly(self):
        self.c.r.update(before=inventory(),fixture_intent=False,safety_verified=False)
        self.c.helper=lambda *a,**kw:{}
        self.c.stop_units=lambda:None;self.c.restore_catalog=lambda:None;self.c.restore_timer=lambda:None
        self.c.cleanup_owned=lambda:self.fail('no cleanup before recovery is verified')
        self.c.command=lambda *a,**kw:None
        def operation(op,**kwargs):
            if op=='inventory':return inventory()
            if op=='restore_files':return True
            if op=='preserved_safety_return':return {'all_preexisting_files_exact':False}
            raise AssertionError(op)
        self.c.op=operation
        with self.assertRaisesRegex(RuntimeError,'preserved_old_pairs_returned'):self.c.recover()
        self.assertFalse(self.c.r.get('recovery_verified'))

    def test_no_cleanup_with_cookie_scan_uncertainty(self):
        self.c.r.update(recovery_verified=True,upload_intent=True,secret_scan=False)
        deletes=[];self.c.helper=lambda *a,**k:deletes.append(a)
        with self.assertRaises(RuntimeError):self.c.cleanup_owned()
        self.assertEqual(deletes,[])

    def test_inventory_comparison_preserves_active_target_timer_and_file_owners(self):
        before=inventory();now=inventory();now['units']=dict(before['units'],**{'n8n.target':{'ActiveState':'active'}})
        self.assertFalse(run.same_found(now,before))
        self.assertTrue(run.same_found(dict(before,images=['different']),before))
        self.assertFalse(run.same_found(dict(before,images=['different']),before,images=True))


class MismatchTests(Fixture):
    """Real flow attempt 2 (dev-c): the engine ACCEPTS a restore whose converted backup names another database and refuses it inside
    the job (error code incompatible, nothing changed, no safety backup). The case must prove exactly that, and own the job."""
    MESSAGE='相容性檢查未通過：應用連線設定在轉換後已變更，無法確認下次啟動仍使用相同資料庫；請先套用目前設定再重新轉換。'

    def setUp(self):
        super().setUp()
        self.log=[];self.snapshots={'mismatch_before':{'rows':1},'mismatch_after':{'rows':1}}
        self.c.r['converted']=BID
        self.c.op=lambda op,**kw:(self.log.append((op,kw.get('tag') or kw.get('database'))),
                                  self.snapshots.get(kw.get('tag')) if op=='snapshot' else {})[1]
        self.c.command=lambda *a,**kw:self.log.append(('command',a[0]))
        self.c.start_units=lambda units:self.log.append(('start',len(units)))
        self.c.stop_units=lambda:self.log.append(('stop',None))
        self.c.app_ready=lambda:None
        self.c.root_json=lambda script,request=None,**kw:{'database':'n8n','local':True}
        self.sent=[]
        self.verdict={'state':'failed','error':{'code':'incompatible','message':self.MESSAGE},
                      'result':{'changed':False,'rolled_back':False,'safety_backup_id':None}}
        self.c.job=lambda command,request,tag:(self.sent.append((command,request,tag)),self.verdict)[1]
        self.c.helper=lambda *a,**kw:self.fail('the request must be tracked through the controller job, never sent directly')

    def test_an_accepted_request_that_the_job_refuses_without_change_passes_and_the_job_is_tracked(self):
        self.c.mismatch_case()
        self.assertEqual(self.sent,[('restore-start',{'backup_id':BID,'apps':['n8n'],'confirm':True},'mismatch')])
        self.assertEqual(self.log[-3:],[('stop',None),('fixture',NAME),('command','systemctl')])      # the case config is put back
        self.assertEqual([x for x in self.log if x[0]=='snapshot'],[('snapshot','mismatch_before'),('snapshot','mismatch_after')])

    def test_every_other_outcome_is_a_failure(self):
        cases={'the restore succeeded':{'state':'succeeded','result':{'changed':True,'rolled_back':False,'safety_backup_id':None}},
               'another error code':dict(self.verdict,error={'code':'failed','message':self.MESSAGE}),
               'another message':dict(self.verdict,error={'code':'incompatible','message':'缺少映像'}),
               'data was changed':dict(self.verdict,result={'changed':True,'rolled_back':False,'safety_backup_id':None}),
               'it had to roll back':dict(self.verdict,result={'changed':False,'rolled_back':True,'safety_backup_id':None}),
               'a safety backup was taken':dict(self.verdict,result={'changed':False,'rolled_back':False,'safety_backup_id':BID}),
               'no result at all':{'state':'failed','error':{'code':'incompatible','message':self.MESSAGE}}}
        for label,verdict in cases.items():
            with self.subTest(label):
                self.verdict=verdict;self.log.clear()
                with self.assertRaises(RuntimeError):self.c.mismatch_case()
                self.assertNotIn(('stop',None),self.log)

    def test_a_changed_database_is_a_failure_even_when_the_job_refused(self):
        self.snapshots['mismatch_after']={'rows':2}
        with self.assertRaisesRegex(RuntimeError,'mismatch_no_database_change'):self.c.mismatch_case()

    def test_the_request_id_follows_the_lease_attempt(self):
        seen=[];reply={'job_id':'j20261127T000000Z-0000000a'}
        del self.c.job                                                    # use the real job(): it owns the request id
        self.c.helper=lambda command,request=None:(seen.append(request['request_id']),dict(reply))[1]
        self.c.settle=lambda:(self.c.r.__setitem__('pending',None),self.verdict)[1]
        self.c.mismatch_case()
        self.c.lease=dict(self.c.lease,attempt=3);reply['job_id']='j20261127T000000Z-0000000b';self.c.mismatch_case()
        self.assertEqual(seen,[NAME+'-mismatch',NAME+'-mismatch-a3'])


class ProbeReportTests(Fixture):
    def test_only_fixed_fact_names_with_plain_values_reach_the_receipt(self):
        found={'login':True,'credential_visible':False,'manual_action':False,'stage':'run','error':'HTTPError','http':400,
               'credential_total':3,'credential_matches':1,'workflow_total':3,'workflow_matches':1,'polls':2,
               'execution_status':'error','execution_finished':None,'error_message':'Cannot read properties of undefined',
               'node_types':['n8n-nodes-base.manualTrigger','n8n-nodes-base.set'],
               'password':'do-not-keep','cookie':'do-not-keep','message':'free text does not belong here'}
        report=run.safe_probe_report(found)
        self.assertEqual(set(report),set(run.PROBE_FACTS))
        self.assertIsNone(report['execution_finished'])
        self.assertNotIn('password',report);self.assertNotIn('do-not-keep',json.dumps(report))

    def test_free_form_nested_or_oversized_values_are_dropped(self):
        found={'stage':'a free sentence with spaces','error':{'nested':'x'},'http':10**9,'polls':-1,'execution_status':['a'],
               'node_types':['fine','has a space'],'workflow_total':3.5,'credential_total':'3','login':'yes'}
        self.assertEqual(run.safe_probe_report(found),{})
        self.assertEqual(run.safe_probe_report({'node_types':['x']*11}),{})
        self.assertEqual(run.safe_probe_report({'stage':'中文'}),{})

    def test_a_short_plain_error_text_is_kept_and_anything_riskier_is_dropped(self):
        ok="Cannot read properties of undefined (reading 'x') <masked> 一些中文"
        self.assertEqual(run.safe_probe_report({'error_message':ok}),{'error_message':ok})
        for bad in ('x'*161,'abcdefghijklmnopqrstuvwxyz0123456789','bell \x07','line\nbreak','',5,None,['a'],{'a':1}):
            with self.subTest(repr(bad)[:30]):self.assertEqual(run.safe_probe_report({'error_message':bad}),{})

    def test_a_missing_or_foreign_answer_is_recorded_as_such(self):
        for value in (None,[],'text',5):self.assertEqual(run.safe_probe_report(value),{'answer':'not-a-dict'})
        self.assertEqual(run.safe_probe_report({}),{})

    def api_fixture(self,found):
        self.c.credentials=lambda:{'N8N_CREDENTIAL_VALUE':'x'}
        self.c.private_api=lambda program:found
        self.c.h=SimpleNamespace(CREDENTIAL_PROBE='/tmp/woowbk-creds.json',CREDENTIAL='HA probe header')
        self.c.command=lambda *a,**k:b''
        self.c.root_json=lambda *a,**k:{'found':True,'match':True}
        self.c.sql=lambda *a,**k:True

    def test_api_keeps_where_the_probe_stopped_before_it_judges(self):
        found={'login':True,'credential_visible':True,'manual_action':False,'stage':'execution','execution_status':'error',
               'cookie':'do-not-keep'}
        self.api_fixture(found)
        with self.assertRaisesRegex(RuntimeError,'real_owner_api_credential_action'):self.c.api()
        self.assertEqual(self.c.r['api_probe'],{'login':True,'credential_visible':True,'manual_action':False,
                                                 'stage':'execution','execution_status':'error'})
        saved=json.loads((self.path/'receipt.json').read_text())
        self.assertNotIn('do-not-keep',json.dumps(saved));self.assertEqual(saved['api_probe']['stage'],'execution')

    def test_the_verdict_needs_exactly_three_true_booleans(self):
        good={'login':True,'credential_visible':True,'manual_action':True,'stage':'execution'}
        self.api_fixture(good);self.c.api()                                  # passes through every later check with fakes
        for key in ('login','credential_visible','manual_action'):
            for value in (False,None,1,'true',0):
                with self.subTest(key=key,value=value):
                    self.api_fixture(dict(good,**{key:value}))
                    with self.assertRaisesRegex(RuntimeError,'real_owner_api_credential_action'):self.c.api()
        for answer in (None,{},[],'text'):
            with self.subTest(answer=answer):
                self.api_fixture(answer)
                with self.assertRaises(RuntimeError):self.c.api()


class ApiLogTests(Fixture):
    SECRETS=['owner-secret-value','credential-secret-value','ha-key-secret-value']

    def setUp(self):
        super().setUp()
        self.calls=[]
        self.c.credentials=lambda:{'N8N_OWNER_PW':self.SECRETS[0],'N8N_CREDENTIAL_VALUE':self.SECRETS[1],'HA_BACKUP_KEY':self.SECRETS[2]}
        self.c.private_api=lambda program:self.found
        self.c.h=SimpleNamespace(CREDENTIAL_PROBE='/tmp/woowbk-creds.json',CREDENTIAL='HA probe header')
        self.c.root_json=lambda *a,**k:{'found':True,'match':True}
        self.c.sql=lambda *a,**k:True
        self.log=(b'INFO started\nError: Cannot read properties of undefined (reading id) for ha-probe@probe.invalid\n'
                  b'    at WorkflowExecutionService.executeManually (/usr/local/lib/node_modules/n8n/dist/x.js:1:2)\n'
                  b'warn password owner-secret-value token abcdefghijklmnopqrstuvwxyz0123456789 \x07 bell\nINFO fine line\n')
        def command(*argv,**kw):
            self.calls.append(argv)
            if argv[:3]==('podman','logs','--tail'):return self.log
            return b''
        self.c.command=command

    def test_a_failed_action_keeps_n8ns_scrubbed_error_lines_before_it_judges(self):
        self.found={'login':True,'credential_visible':True,'manual_action':False,'stage':'run','http':500,'error':'HTTPError'}
        with self.assertRaisesRegex(RuntimeError,'real_owner_api_credential_action'):self.c.api()
        self.assertEqual(self.calls,[('podman','logs','--tail','300','n8n')])
        lines=self.c.r['api_probe_log']
        self.assertEqual(len(lines),3)          # the error, its stack frame and the warning; the two INFO lines are dropped
        text=' | '.join(lines)
        for forbidden in ('ha-probe@probe.invalid',*self.SECRETS,'abcdefghijklmnopqrstuvwxyz','\x07','INFO'):
            self.assertNotIn(forbidden,text)
        self.assertIn('Cannot read properties of undefined (reading id) for <masked>',text)
        saved=json.loads((self.path/'receipt.json').read_text());self.assertEqual(saved['api_probe_log'],lines)

    def test_a_good_action_takes_no_log(self):
        self.found={'login':True,'credential_visible':True,'manual_action':True}
        self.c.api()
        self.assertFalse(any(c[:2]==('podman','logs') for c in self.calls));self.assertNotIn('api_probe_log',self.c.r)

    def test_a_log_capture_that_fails_never_hides_the_real_failure(self):
        self.found={'login':True,'credential_visible':True,'manual_action':False}
        def broken(*argv,**kw):raise RuntimeError('fixed service/image command failed; raw output withheld')
        self.c.command=broken
        with self.assertRaisesRegex(RuntimeError,'real_owner_api_credential_action'):self.c.api()
        self.assertEqual(self.c.r['api_probe_log'],['log capture failed: RuntimeError'])

    def test_scrub_log_keeps_only_a_bounded_number_of_short_plain_lines(self):
        text='\n'.join('error line %d %s'%(i,'x'*400) for i in range(100))
        lines=run.scrub_log(text,[])
        self.assertEqual(len(lines),40);self.assertTrue(all(len(x)<=240 for x in lines));self.assertTrue(lines[-1].startswith('error line 99'))
        self.assertEqual(run.scrub_log('nothing interesting\nall fine',[]),[])
        self.assertEqual(run.scrub_log('error short',['sh']),['error short'])          # secrets under 4 characters are never substituted


class SecretKeepTests(Fixture):
    KEPT={'n8n-db-password':{'id':'a'*12,'value_sha256':'1'*64},'n8n-runners-auth-token':{'id':'b'*12,'value_sha256':'2'*64},
          'n8n-valkey-password':{'id':'c'*12,'value_sha256':'3'*64}}

    def setUp(self):
        super().setUp()
        self.c.r.update(kept_state={'databases':{'n8n':{}}},kept_secrets=self.KEPT)
        self.now=json.loads(json.dumps(self.KEPT))
        self.c.op=lambda op,**kw:{'databases':{'n8n':{}}} if op=='snapshot' else self.now

    def test_secret_difference_names_what_differs_and_never_a_value(self):
        self.now['n8n-db-password']['id']='z'*12;self.now['n8n-valkey-password']['value_sha256']='9'*64
        del self.now['n8n-runners-auth-token']
        self.assertEqual(run.secret_difference(self.now,self.KEPT),
                         ['n8n-db-password:id','n8n-runners-auth-token:missing','n8n-valkey-password:value'])
        self.assertEqual(run.secret_difference(self.KEPT,self.KEPT),[])

    def test_after_the_import_ids_and_values_must_stay(self):
        self.c.kept('after_import')
        self.now['n8n-db-password']['id']='z'*12
        with self.assertRaisesRegex(RuntimeError,'retained_current_secret_ids_values'):self.c.kept('after_restart')
        self.assertEqual(self.c.r['secret_differences']['after_restart'],['n8n-db-password:id'])

    def test_after_a_rollback_new_ids_are_fine_but_not_a_new_value_or_a_missing_secret(self):
        for name in self.KEPT:self.now[name]['id']='z'*12
        self.c.kept('after_rollback',ids_may_change=True)
        self.assertEqual(len(self.c.r['secret_differences']['after_rollback']),3)
        self.now['n8n-valkey-password']['value_sha256']='9'*64
        with self.assertRaisesRegex(RuntimeError,'rolled_back_secret_names_values_kept'):self.c.kept('after_rollback',ids_may_change=True)
        self.now=json.loads(json.dumps(self.KEPT));del self.now['n8n-db-password']
        with self.assertRaisesRegex(RuntimeError,'rolled_back_secret_names_values_kept'):self.c.kept('after_rollback',ids_may_change=True)

    def test_recovery_passes_the_exact_attempt_request_id_of_its_full_safety_return(self):
        seen={}
        self.c.lease=dict(self.c.lease,attempt=11)
        self.assertEqual(self.c.request_id('recover'),NAME+'-recover-a11')
        def op(name,**kw):
            if name=='preserved_safety_return':seen.update(kw);raise RuntimeError('stop here')
            return inventory() if name=='inventory' else {}
        self.c.op=op;self.c.r['before']=inventory();self.c.settle=lambda:None
        self.c.stop_units=lambda:None;self.c.command=lambda *a,**k:b'';self.c.restore_catalog=lambda:None;self.c.restore_timer=lambda:None
        with self.assertRaisesRegex(RuntimeError,'stop here'):self.c.recover()
        self.assertEqual(seen['recover_request_id'],NAME+'-recover-a11')


class ImportHygieneTests(unittest.TestCase):
    def test_importing_the_device_operations_does_not_change_the_hosts_bytecode_settings(self):
        # final integration tip: a later py_compile in the same test process was sent to /nonexistent by such an import
        for module in ('focus_n8n_instance_acceptance_ops','focus_n8n_instance_acceptance_source_ops',
                       'focus_n8n_instance_acceptance_source2_ops'):
            with self.subTest(module):
                code=("import sys;sys.path.insert(0,%r);before=(sys.pycache_prefix,sys.dont_write_bytecode);"
                      "import %s;print(before==(sys.pycache_prefix,sys.dont_write_bytecode))")%(str(Path(run.__file__).parent),module)
                p=subprocess.run([sys.executable,'-I','-c',code],capture_output=True,timeout=60)
                self.assertEqual((p.returncode,p.stdout.strip()),(0,b'True'),p.stderr[-300:])

    def test_as_the_device_program_it_still_turns_bytecode_off_first(self):
        text=(Path(run.__file__).parent/'focus_n8n_instance_acceptance_ops.py').read_text()
        guarded=text.index("if __name__ == '__main__':")
        self.assertLess(guarded,text.index("sys.pycache_prefix = '/nonexistent/woowbk-focus-n8n-pycache'"))
        self.assertLess(text.index("sys.pycache_prefix = '/nonexistent/woowbk-focus-n8n-pycache'"),text.index('APP = '))
        prelude=''.join(c for c in run.Controller.root_json.__code__.co_consts if isinstance(c,str))   # every device program's own start
        self.assertIn("sys.pycache_prefix='/nonexistent/woowbk-focus-n8n-pycache'",prelude)


if __name__=='__main__':unittest.main()
