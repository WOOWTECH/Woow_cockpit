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
                name=NAME,image_policy='retain-for-case',expires_utc=datetime.fromtimestamp(2000,timezone.utc).isoformat())


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
        self.assertEqual(run.validate_lease(dict(lease(),source_commit='b'*40),'images',now=1000,
                         driver_commit='a'*40,source_commit='c'*40),2000)

    def test_default_never_constructs_controller_or_device_transport(self):
        with patch.object(run,'Controller',side_effect=AssertionError('no device')), \
                patch.object(run,'git',side_effect=AssertionError('no runtime')),redirect_stdout(io.StringIO()):
            self.assertEqual(run.main([]),0)


class JournalTests(Fixture):
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
        self.c.command=lambda *a,**k:a[3].encode()  # requested sha256:id
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


class FilesAndPredicateTests(Fixture):
    def store(self):
        source=self.path/'original.env';source.write_bytes(b'private-original\n')
        store=ops.Store(NAME,parent=self.path/'cases',create=True);store.capture([str(source)])
        return source,store

    def test_protected_bytes_restore_exact_mode_and_refuse_external_edit(self):
        source,store=self.store();original=source.read_bytes();mode=source.stat().st_mode&0o777
        store.replace(str(source),b'case\n');store.restore([str(source)])
        self.assertEqual(source.read_bytes(),original);self.assertEqual(source.stat().st_mode&0o777,mode)
        source.write_bytes(b'operator-change\n')
        with self.assertRaises(ValueError):store.restore([str(source)])
        self.assertEqual(source.read_bytes(),b'operator-change\n')

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


class RestoreTests(Fixture):
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
