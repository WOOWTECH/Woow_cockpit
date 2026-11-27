"""Upload-only FSM, diagnostic retention, store ownership and precise Office gate; offline."""
import contextlib
import copy
import errno
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parents[1]/'e2e/lab'
sys.path.insert(0,str(HERE))
import focus_nextcloud_r6_upload as upload
import focus_nextcloud_r6_cold as cold
from focus_nextcloud_r6_plan import acceptance_budget,verified_credit_budget,RESERVE,FIXTURE_BYTES

UID='u0123456789abcdef'
BEGIN={'upload_id':UID,'path':'/var/lib/woowtech-backup/uploads/'+UID+'.part'}
IDENTITY={'dev':1,'ino':2}


class Events:
    def __init__(self):self.rows=[]
    def event(self,row):self.rows.append(copy.deepcopy(row))


class FSMTests(unittest.TestCase):
    def invoke(self,fault=None):
        state={'phase':'new','upload_id':None,'writer_reaped':True};events=Events();commands=[]
        def rpc(cmd,req,*a):
            commands.append(cmd)
            if fault==cmd:raise OSError(errno.EIO,'injected RPC reply loss')
            if cmd=='upload-begin':return dict(BEGIN)
            if cmd=='upload-finish':return {'ha_backup':{'id':upload.HA_ID,'sha256':upload.FIXTURE_SHA,'size':FIXTURE_BYTES}}
            # The exact failure is persisted before deletion is even requested.
            self.assertTrue(any(r.get('exception_class') for r in events.rows))
            self.assertEqual(req,{'upload_id':UID});return {'ok':True}
        def stream(state,*a):
            if fault in ('stream','live-writer'):
                state.update(chunk_offset=123456,writer_reaped=fault!='live-writer')
                raise BrokenPipeError(errno.EPIPE,'injected partial stream')
            return {'identity':IDENTITY}
        def verify(*a):return {'identity':{'dev':1,'ino':99} if fault=='foreign-inode' else IDENTITY}
        result=upload.transfer(state,events,9999999999,rpc,stream,verify)
        return state,events,commands,result

    def test_real_fsm_success_reaches_retained_once(self):
        state,_,commands,result=self.invoke()
        self.assertEqual(state['phase'],'retained');self.assertIsNone(result[-1])
        self.assertEqual(commands,['upload-begin','upload-finish'])

    def test_begin_window_is_recorded_even_when_the_begin_reply_is_lost(self):
        for fault in (None,'upload-begin'):
            with self.subTest(fault=fault):
                state,*_=self.invoke(fault)
                self.assertLessEqual(state['begin_sent_at'],state['begin_returned_at'])

    def test_broken_pipe_offset_class_errno_persist_before_own_abort(self):
        state,events,commands,_=self.invoke('stream')
        failure=next(x for x in events.rows if x.get('exception_class')=='BrokenPipeError')
        self.assertEqual((failure['errno'],failure['chunk_offset']),(errno.EPIPE,123456))
        self.assertIn('injected partial stream',failure['exception_text']);self.assertIn('Traceback',failure['traceback'])
        self.assertEqual(commands,['upload-begin','upload-abort'])
        self.assertEqual(state['phase'],'streaming')

    def test_lost_begin_reply_never_guesses_or_aborts_a_foreign_id(self):
        state,_,commands,_=self.invoke('upload-begin')
        self.assertEqual(state['phase'],'begin-requested');self.assertEqual(commands,['upload-begin'])
        self.assertIsNone(upload.owned_abort(state))

    def test_lost_finish_reply_preserves_uncertain_publication(self):
        state,_,commands,_=self.invoke('upload-finish')
        self.assertEqual(state['phase'],'finish-requested');self.assertNotIn('upload-abort',commands)

    def test_unreaped_writer_prevents_cleanup(self):
        state,_,commands,_=self.invoke('live-writer')
        self.assertIsNone(upload.owned_abort(state));self.assertNotIn('upload-abort',commands)

    def test_foreign_inode_preserves_finished_store_and_refuses_retained_state(self):
        state,_,commands,_=self.invoke('foreign-inode')
        self.assertEqual(state['phase'],'finished');self.assertNotIn('upload-abort',commands)

    def test_skip_rewind_and_repeat_finish_refuse(self):
        for old,new in [('new','streaming'),('retained','finish-requested'),('finished','begun')]:
            with self.subTest(old=old),self.assertRaises(ValueError):upload.advance({'phase':old},new)

    def test_rpc_begin_path_is_exact_owned_id_not_a_link_or_alternate_path(self):
        self.assertEqual(upload.validate_begin(BEGIN),UID)
        for path in ('/tmp/file','/var/lib/woowtech-backup/uploads/../other.part',BEGIN['path']+'.extra'):
            with self.subTest(path=path),self.assertRaises(ValueError):upload.validate_begin(dict(BEGIN,path=path))


class ProvenanceTests(unittest.TestCase):
    def records(self):
        receipt={'status':'passed','phase':'upload-only','pending':False,'ha_backup_id':upload.HA_ID,
                 'upload_id':UID,'sha256':upload.FIXTURE_SHA,'bytes':FIXTURE_BYTES,'expected_store_absent_before':True,
                 'ha_file_identity':IDENTITY,'sidecar_sha256':'a'*64}
        proof={'status':'passed','ha_backup_id':upload.HA_ID,'sha256':upload.FIXTURE_SHA,'bytes':FIXTURE_BYTES,
               'identity':IDENTITY,'sidecar_sha256':'a'*64,'allocated_bytes':FIXTURE_BYTES}
        return receipt,proof

    def test_only_verified_owned_existing_allocated_bytes_are_credited(self):
        receipt,proof=self.records();self.assertEqual(upload.retained_credit(receipt,proof),FIXTURE_BYTES)
        proof['allocated_bytes']=4096;self.assertEqual(upload.retained_credit(receipt,proof),4096)

    def test_false_owner_status_changed_bytes_id_inode_sidecar_or_size_refuse(self):
        for side,key,value in [('receipt','status','failed'),('receipt','pending',True),('receipt','expected_store_absent_before',False),
                               ('receipt','upload_id','foreign'),('proof','status','failed'),('proof','sha256','b'*64),
                               ('proof','ha_backup_id','ha-foreign'),('proof','identity',{'dev':1,'ino':99}),
                               ('proof','sidecar_sha256','c'*64),('proof','bytes',0),('proof','allocated_bytes',-1),
                               ('proof','allocated_bytes',True)]:
            receipt,proof=self.records();(receipt if side=='receipt' else proof)[key]=value
            with self.subTest(side=side,key=key),self.assertRaises(ValueError):upload.retained_credit(receipt,proof)

    def test_credit_never_exceeds_logical_verified_bytes(self):
        receipt,proof=self.records();proof['allocated_bytes']=FIXTURE_BYTES+4096
        self.assertEqual(upload.retained_credit(receipt,proof),FIXTURE_BYTES)

    def test_credit_reduces_remaining_peak_once_and_preserves_thirteen_gib_floor(self):
        base=acceptance_budget(849259813,75382634,234187031,1024**3,1024**3)
        result=verified_credit_budget(base,FIXTURE_BYTES)
        self.assertEqual(result['additional_peak_bytes'],base['additional_peak_bytes']-FIXTURE_BYTES)
        self.assertEqual(result['minimum_after_wake_free_bytes'],RESERVE+result['additional_peak_bytes'])
        self.assertEqual(result['reserve_bytes'],RESERVE)
        with self.assertRaises(ValueError):verified_credit_budget(result,FIXTURE_BYTES)
        for bad in (-1,FIXTURE_BYTES+1,True):
            with self.assertRaises(ValueError):verified_credit_budget(base,bad)


class DiagnosticTests(unittest.TestCase):
    def test_actual_writer_epipe_diagnostic_is_read_before_abort(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev=upload.Evidence(Path(tmp)/'attempt');fixture=Path(tmp)/'fixture';fixture.write_bytes(b'ab')
            packet={'status':'failed','stage':'stream','chunk_offset':0,'watch_failure':{'reason':'fixed-upload-reserve'}}
            class Process:
                returncode=None
                def __init__(self,*args,**kwargs):
                    r,w=os.pipe();os.close(r);self.stdin=os.fdopen(w,'wb',buffering=0)
                    self.out=kwargs['stdout'];self.err=kwargs['stderr']
                def poll(self):return None
                def wait(self,**kwargs):
                    self.returncode=2;self.out.write(json.dumps(packet).encode());self.out.flush()
                    self.err.write(b'private writer traceback');self.err.flush();return 2
            def rpc(command,*args):
                if command=='upload-begin':return BEGIN
                self.assertEqual(command,'upload-abort')
                self.assertEqual(json.loads((ev.path/'writer-diagnostic.private.json').read_text()),packet)
                return {'ok':True}
            state={'phase':'new','upload_id':None,'writer_reaped':True}
            with patch.object(upload,'FIXTURE',fixture),patch.object(upload,'FIXTURE_BYTES',2),patch.object(upload.subprocess,'Popen',Process):
                result=upload.transfer(state,ev,9999999999,rpc_call=rpc)
            self.assertEqual(result[-1],'fixed-upload-case-stopped')
            self.assertTrue(any(json.loads(p.read_text()).get('stage')=='own-upload-aborted' for p in ev.path.glob('*event.private.json')))

    def test_done_caches_reach_transfer_instead_of_blanket_empty_directory_gate(self):
        class ReachedTransfer(Exception):pass
        meta={'uploads':[UID+'.done'],'completed_uploads':[],'expected_store_absent':True}
        before={'host_free_bytes':100*1024**3,'root':{'varlib_free_bytes':100*1024**3}}
        with patch.object(upload,'collect',return_value=before),patch.object(upload,'admission'),\
                patch.object(upload,'device_process',return_value=meta),patch.object(upload.wake,'device',return_value={'active_jobs':0}),\
                patch.object(upload,'transfer',side_effect=ReachedTransfer),patch.object(upload.Evidence,'save'):
            ev=object.__new__(upload.Evidence)
            with self.assertRaises(ReachedTransfer):upload.run_attempt({},'source',9999999999,ev)

    def test_transport_nonzero_keeps_raw_rpc_watch_reason_and_stderr_before_raising(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev=upload.Evidence(Path(tmp)/'attempt')
            packet={'status':'failed','rpc_returncode':137,'exception_class':'RuntimeError','errno':None,
                    'watch_failure':{'reason':'fixed-upload-reserve'},'stderr':'private exact child stderr'}
            class Process:
                returncode=2
                def __init__(self,*args,**kwargs):self.out=kwargs['stdout'];self.err=kwargs['stderr']
                def communicate(self,**kwargs):self.out.write(json.dumps(packet).encode());self.err.write(b'outer-private-stderr')
            with patch.object(upload.subprocess,'Popen',Process),self.assertRaises(RuntimeError):
                upload.device_process('program',[],ev,'rpc-test',b'{}',30)
            self.assertEqual(json.loads((ev.path/'rpc-test-diagnostic.private.json').read_text()),packet)
            self.assertEqual((ev.path/'rpc-test.stderr.private').read_bytes(),b'outer-private-stderr')
            event=json.loads(next(ev.path.glob('*event.private.json')).read_text())
            self.assertEqual(event['transport_returncode'],2)

    def test_actual_rendered_watch_distinguishes_reserve_expiry_memory_and_probe_errno(self):
        for kind in ('reserve','expiry','memory','probe'):
            def read_text():
                if kind=='probe':raise FileNotFoundError(errno.ENOENT,'injected cgroup probe missing')
                return str(upload.DEVICE_CAP if kind=='memory' else 100)
            namespace={'time':types.SimpleNamespace(time=lambda:100), 'deadline':99 if kind=='expiry' else 1000,
                       'shutil':types.SimpleNamespace(disk_usage=lambda p:types.SimpleNamespace(
                           free=upload.RESERVE if kind=='reserve' else 100*1024**3)),
                       'pathlib':types.SimpleNamespace(Path=lambda p:types.SimpleNamespace(read_text=read_text))}
            exec(compile(upload.WATCH,'<actual-watch>','exec'),namespace)
            with self.subTest(kind=kind),self.assertRaises(Exception):namespace['watch']()
            failure=namespace['watch_failure']
            if kind=='probe':self.assertEqual((failure['exception_class'],failure['errno']),('FileNotFoundError',errno.ENOENT))
            else:self.assertEqual(failure['reason'],'fixed-upload-'+kind)

    def test_changed_or_linked_retained_receipt_refuses_before_any_device_hash(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(upload,'verify_retained') as verify:
            p=Path(tmp)/'receipt';p.write_text('{}')
            with self.assertRaises(ValueError):upload.adopt_receipt(p,'f'*64,1000,None)
            p.unlink();p.symlink_to('/etc/passwd')
            with self.assertRaises(OSError):upload.adopt_receipt(p,'f'*64,1000,None)
            verify.assert_not_called()

    def test_default_does_no_io_and_all_rendered_programs_compile(self):
        for body in (upload.WRITER,upload.RPC,upload.VERIFY,upload.meta_program(),cold.CLAIM,cold.STOP):compile(body,'<device>','exec')
        with patch.object(sys,'argv',['driver']),patch.object(upload.subprocess,'run',side_effect=AssertionError),\
                patch.object(upload.subprocess,'check_output',side_effect=AssertionError),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(upload.main(),0)


class CompletedCacheTests(unittest.TestCase):
    def cache(self,root,name=UID+'.done',record=None):
        p=root/name;p.write_text(json.dumps(record or {'ha_backup_id':upload.HA_ID,'at':'1970-01-02T03:46:40Z'}))
        p.chmod(0o600);os.utime(p,(100000,100000));return p

    def snapshot(self,root,now=101000):
        with patch.object(upload.time,'time',return_value=now):
            return upload.completed_uploads(root,uid=os.getuid())

    def test_ten_native_done_caches_are_valid_and_do_not_change_bytes_or_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for i in range(10):self.cache(root,'u%016x.done'%i)
            before=self.snapshot(root);self.assertEqual(len(before),10)
            self.assertEqual(self.snapshot(root),before)
            self.assertEqual(sorted(p.name for p in root.iterdir()),[r['name'] for r in before])

    def test_unfinished_unknown_symlink_hardlink_mode_owner_and_oversize_refuse(self):
        for kind in ('part','json','lock','unknown','symlink','hardlink','mode','owner','oversize','dangling-root'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'uploads';root.mkdir(mode=0o700);p=self.cache(root)
                if kind in ('part','json','lock'):p.rename(root/(UID+'.'+kind))
                elif kind=='unknown':p.rename(root/'other.done')
                elif kind=='symlink':p.unlink();p.symlink_to('/etc/passwd')
                elif kind=='hardlink':os.link(p,Path(tmp)/'second')
                elif kind=='mode':p.chmod(0o644)
                elif kind=='owner':root.chmod(0o777)
                elif kind=='oversize':p.write_bytes(b'x'*4097)
                else:p.unlink();root.rmdir();root.symlink_to(Path(tmp)/'absent')
                with self.assertRaises((OSError,ValueError)):self.snapshot(root)

    def test_malformed_duplicate_keys_target_date_and_future_time_refuse(self):
        for raw in ('{}','{"at":"1970-01-02T03:46:40Z","ha_backup_id":"bad"}',
                    '{"at":"1970-01-02T03:46:40Z","at":"1970-01-02T03:46:40Z","ha_backup_id":"'+upload.HA_ID+'"}',
                    '{"at":"not-time","ha_backup_id":"'+upload.HA_ID+'"}'):
            with self.subTest(raw=raw),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);p=self.cache(root);p.write_text(raw);os.utime(p,(100000,100000))
                with self.assertRaises(ValueError):self.snapshot(root)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.cache(root)
            with self.assertRaisesRegex(ValueError,'cache-future-time'):self.snapshot(root,99999)

    def test_caches_a_day_old_are_admitted_for_the_native_cleanup(self):
        # begin_upload's own 24h cleanup may delete them; completed_uploads_preserved accounts for exactly that.
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.cache(root)
            self.assertEqual(len(self.snapshot(root,100000+3*upload.DAY)),1)

    def test_native_24h_cleanup_at_begin_is_the_only_admitted_removal(self):
        own='u1111111111111111';sent=100000+upload.DAY+50
        state={'phase':'retained','upload_id':own,'begin_sent_at':sent,'begin_returned_at':sent+2}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);names={}
            for kind,mtime in (('old',100000),('band',100051),('young',100060)):
                names[kind]=self.cache(root,'u%016x.done'%mtime).name;os.utime(root/names[kind],(mtime,mtime))
            before=self.snapshot(root,sent+10)
            self.cache(root,own+'.done');os.utime(root/(own+'.done'),(sent+10,sent+10))
            full=self.snapshot(root,sent+11)
            def without(rows,*kinds):return [r for r in rows if r['name'] not in {names[k] for k in kinds}]
            self.assertTrue(upload.completed_uploads_preserved(before,without(full,'old'),state))
            self.assertTrue(upload.completed_uploads_preserved(before,without(full,'old','band'),state))
            self.assertEqual(upload.native_cleanup_removed(before,without(full,'old','band')),sorted([names['old'],names['band']]))
            for rows,why in ((full,'a cache older than the cutoff survived the cleanup'),
                             (without(full,'old','young'),'a cache younger than a day was removed')):
                with self.subTest(why=why):self.assertFalse(upload.completed_uploads_preserved(before,rows,state))
            unanswered={'phase':'begin-requested','upload_id':None,'begin_sent_at':sent,'begin_returned_at':sent+2}
            self.assertTrue(upload.completed_uploads_preserved(before,before,unanswered))
            self.assertTrue(upload.completed_uploads_preserved(before,without(before,'old'),unanswered))
            self.assertFalse(upload.completed_uploads_preserved(before,without(before,'old'),{'phase':'new','upload_id':None}))

    def test_no_active_native_helper_or_fd_on_upload_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'uploads';root.mkdir();proc=Path(tmp)/'proc';proc.mkdir()
            p=proc/'123';p.mkdir();(p/'fd').mkdir();(p/'cmdline').write_bytes(b'python3\0-I\0')
            self.assertEqual(upload.no_upload_writers(root,proc)['active_upload_writers'],0)
            (p/'cmdline').write_bytes(b'python3\0/usr/local/libexec/woowtech-cockpit-backup\0upload-finish\0')
            with self.assertRaisesRegex(ValueError,'native-helper-active'):upload.no_upload_writers(root,proc)
            (p/'cmdline').write_bytes(b'python3\0-I\0');(p/'fd'/'4').symlink_to(root/(UID+'.done'))
            with self.assertRaisesRegex(ValueError,'existing-file-open'):upload.no_upload_writers(root,proc)

    def test_prior_caches_must_stay_exact_only_own_finish_addition_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.cache(root);before=self.snapshot(root)
            other='u1111111111111111';self.cache(root,other+'.done');after=self.snapshot(root)
            state={'phase':'retained','upload_id':other}
            self.assertTrue(upload.completed_uploads_preserved(before,after,state))
            self.assertFalse(upload.completed_uploads_preserved(before,before,state))
            for change in ('hash','metadata','missing','foreign','wrong-target','unfinished'):
                new=copy.deepcopy(after);s=state.copy()
                if change=='hash':new[0]['sha256']='f'*64
                elif change=='metadata':new[0]['stat'][-1]+=1
                elif change=='missing':new=new[1:]
                elif change=='foreign':s['upload_id']='u2222222222222222'
                elif change=='wrong-target':new[1]['record']['ha_backup_id']='ha-'+'f'*20
                else:s['phase']='streaming'
                with self.subTest(change=change):self.assertFalse(upload.completed_uploads_preserved(before,new,s))


class ColdStopTests(unittest.TestCase):
    def rows(self):
        prior={'ActiveState':'inactive','UnitFileState':'generated'}
        claimed={'ActiveState':'active','MainPID':'123','InvocationID':'a'*32}
        post={'ActiveState':'failed','SubState':'failed','MainPID':'0','InvocationID':'a'*32,'Result':'exit-code',
              'ExecMainStatus':'137','ExecMainExitTimestampMonotonic':'1001','UnitFileState':'generated'}
        return prior,claimed,post

    def test_only_owned_known_137_after_stop_is_clearable(self):self.assertTrue(cold.may_clear(*self.rows(),1000))

    def test_preexisting_failure_other_invocation_pid_status_or_prior_active_refuse(self):
        for side,key,value in [('prior','ActiveState','active'),('post','InvocationID','b'*32),('post','MainPID','99'),
                               ('post','ExecMainStatus','1'),('post','Result','oom-kill'),
                               ('post','ExecMainExitTimestampMonotonic','999'),('post','UnitFileState','enabled')]:
            prior,claimed,post=self.rows();(prior if side=='prior' else post)[key]=value
            with self.subTest(key=key):self.assertFalse(cold.may_clear(prior,claimed,post,1000))
        prior,_,post=self.rows();self.assertFalse(cold.may_clear(prior,None,post,1000))


if __name__=='__main__':unittest.main()
