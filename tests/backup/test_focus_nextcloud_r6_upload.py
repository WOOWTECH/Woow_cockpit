"""Upload-only FSM, diagnostic retention, store ownership and precise Office gate; offline."""
import contextlib
import copy
import errno
import io
import json
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
