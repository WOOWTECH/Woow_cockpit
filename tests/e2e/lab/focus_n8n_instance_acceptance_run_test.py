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
    def safety_fixture(self):
        before=inventory();before['images']=list(run.plan.IMAGE_IDS.values());self.c.r['before']=before;order=[]
        snap={'database_names':['n8n','postgres'],'databases':{}}
        self.c.resources=lambda:None;self.c.acquire_original=lambda:before;self.c.frozen_engine=lambda:None
        self.c.op=lambda op,**kw: before if op=='inventory' else snap if op=='snapshot' else {}
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


if __name__=='__main__':unittest.main()
