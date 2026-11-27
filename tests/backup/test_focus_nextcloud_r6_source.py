"""Offline source-only transaction and cold-controller boundary tests. No lab I/O."""
import contextlib
import copy
import hashlib
import fcntl
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1] / 'e2e/lab'
sys.path.insert(0, str(HERE))
import focus_nextcloud_r6_source as source
import focus_nextcloud_r6_case as case
import focus_nextcloud_r6 as flow


def payload():
    return {'helper': b'#!/usr/bin/python3 -I\nprint("new")\n', 'VERSION': b'unchanged-release-version\n',
            'woowbackup/__init__.py': b'# new\n', 'woowbackup/cli.py': b'# new cli\n'}


def manifest(data):
    return {n: {'size':len(v), 'sha256':hashlib.sha256(v).hexdigest()} for n,v in data.items()}


def archive(data, extra=None):
    buf=io.BytesIO()
    with tarfile.open(fileobj=buf,mode='w',format=tarfile.USTAR_FORMAT) as tar:
        for name,value in data.items():
            m=tarfile.TarInfo(name);m.size=len(value);tar.addfile(m,io.BytesIO(value))
        if extra:
            m,value=extra;tar.addfile(m,io.BytesIO(value))
    buf.seek(0)
    return buf


class StreamTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.lib=self.base/'lib';self.lib.mkdir()
        self.helper=self.base/'helper'

    def receive(self, buf, rows=None):
        source.receive(buf, rows or manifest(payload()),self.lib,self.helper,lambda:None)

    def test_exact_stream_matches_every_file(self):
        self.receive(archive(payload()))
        for n,v in payload().items():
            self.assertEqual((self.helper if n=='helper' else self.lib/n).read_bytes(),v)

    def test_missing_member_and_wrong_hash_refuse(self):
        for data in ({k:v for k,v in payload().items() if k!='VERSION'},
                     dict(payload(), VERSION=b'wrong-content-same-size!\n')):
            with self.subTest(data=list(data)), tempfile.TemporaryDirectory() as tmp:
                lib=Path(tmp)/'lib';lib.mkdir()
                with self.assertRaises(ValueError):
                    source.receive(archive(data),manifest(payload()),lib,Path(tmp)/'helper',lambda:None)

    def test_links_paths_duplicate_and_oversize_refuse(self):
        for kind in ('symlink','hardlink','path','duplicate','oversize'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                lib=Path(tmp)/'lib';lib.mkdir();m=tarfile.TarInfo('VERSION');value=b''
                if kind=='symlink': m.type=tarfile.SYMTYPE;m.linkname='/etc/passwd'
                if kind=='hardlink': m.type=tarfile.LNKTYPE;m.linkname='helper'
                if kind=='path': m.name='../escape'
                if kind=='oversize': m.size=1;value=b'x'
                with self.assertRaises(ValueError):
                    source.receive(archive(payload(),(m,value)),manifest(payload()),lib,Path(tmp)/'helper',lambda:None)
                self.assertFalse((Path(tmp)/'escape').exists())

    def test_manifest_rejects_foreign_paths_and_unbounded_size(self):
        for key,value in [('../VERSION',{'size':1,'sha256':'a'*64}),
                          ('woowbackup/new.py',{'size':source.MAX_FILE+1,'sha256':'a'*64}),
                          ('woowbackup/bad.py',{'size':True,'sha256':'a'*64})]:
            m=manifest(payload());m[key]=value
            with self.subTest(key=key), self.assertRaises(ValueError):source.validate_manifest(m)

    def test_reserve_failure_stops_receive(self):
        with self.assertRaisesRegex(ValueError,'test-floor'):
            source.receive(archive(payload()),manifest(payload()),self.lib,self.helper,
                           lambda: (_ for _ in ()).throw(ValueError('test-floor')))


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        base=Path(self.tmp.name);self.lp=base/'lib';self.hp=base/'libexec';self.lp.mkdir();self.hp.mkdir()
        self.lib=self.lp/source.LIBNAME;self.lib.mkdir(mode=0o755);(self.lib/'woowbackup').mkdir(mode=0o755)
        (self.lib/'woowbackup/cli.py').write_bytes(b'# prior cli\n');(self.lib/'VERSION').write_bytes(b'prior\n')
        self.helper=self.hp/source.LIBNAME;self.helper.write_bytes(b'#!/usr/bin/python3 -I\n# prior\n');self.helper.chmod(0o755)
        for p in self.lib.rglob('*'):
            p.chmod(0o755 if p.is_dir() else 0o644)
        self.lib.chmod(0o755)
        self.nonce='0123456789abcdef'
        real=source.tree_snapshot
        self.snap=lambda p:real(p,uid=os.getuid())
        self.prior=[self.snap(self.lib),self.snap(self.helper)]
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(source,'mutation_locks',return_value=contextlib.nullcontext()))
        self.stack.enter_context(patch.object(source,'secure_dir')) # temp paths are never production destinations
        self.stack.enter_context(patch.object(source,'tree_snapshot',side_effect=self.snap))
        self.stack.enter_context(patch.object(shutil,'disk_usage',return_value=types.SimpleNamespace(free=100*1024**3)))

    def call(self, action='install', buf=None):
        with patch.object(sys,'stdin',types.SimpleNamespace(buffer=buf or archive(payload()))):
            return source.device_transaction(action,self.nonce,manifest(payload()),time.time()+300,self.lp,self.hp)

    def test_installs_then_restores_exact_prior_bytes_and_attributes(self):
        self.assertEqual(self.call()['status'],'installed')
        self.assertEqual((self.lib/'VERSION').read_bytes(),payload()['VERSION'])
        self.assertEqual(self.call('restore')['status'],'restored')
        self.assertEqual([self.snap(self.lib),self.snap(self.helper)],self.prior)
        self.assertEqual(self.call('restore')['status'],'restored')

    def test_every_partial_rename_has_a_bounded_restore(self):
        rename=os.rename
        for position in (1,2,3,4):
            with self.subTest(position=position):
                calls=[]
                def interrupted(a,b):
                    calls.append(1)
                    if len(calls)==position:raise OSError('injected local filesystem interruption')
                    return rename(a,b)
                with patch.object(os,'rename',side_effect=interrupted),self.assertRaises(OSError):self.call()
                self.assertEqual(self.call('restore')['status'],'restored')
                self.assertEqual([self.snap(self.lib),self.snap(self.helper)],self.prior)
                # Only delete test-owned transaction leaves between test scenarios.
                shutil.rmtree(self.lp/('.focus-nextcloud-r6-'+self.nonce))
                shutil.rmtree(self.hp/('.focus-nextcloud-r6-'+self.nonce))

    def test_interrupted_restore_resumes_only_from_proven_owned_copies(self):
        rename=os.rename
        for position in (1,2,3,4):
            with self.subTest(position=position):
                self.call();calls=[]
                def interrupted(a,b):
                    calls.append(1)
                    if len(calls)==position:raise OSError('injected restore interruption')
                    return rename(a,b)
                with patch.object(os,'rename',side_effect=interrupted),self.assertRaises(OSError):self.call('restore')
                self.assertEqual(self.call('restore')['status'],'restored')
                self.assertEqual([self.snap(self.lib),self.snap(self.helper)],self.prior)
                shutil.rmtree(self.lp/('.focus-nextcloud-r6-'+self.nonce))
                shutil.rmtree(self.hp/('.focus-nextcloud-r6-'+self.nonce))

    def test_foreign_edit_refuses_without_overwriting_it(self):
        self.call();p=self.lib/'VERSION';p.write_bytes(b'foreign edit\n')
        with self.assertRaisesRegex(ValueError,'foreign-edit'):self.call('restore')
        self.assertEqual(p.read_bytes(),b'foreign edit\n')

    def test_failed_stream_preserves_prior_and_can_return(self):
        with self.assertRaises(ValueError):self.call(buf=archive({'VERSION':b'bad'}))
        self.assertEqual([self.snap(self.lib),self.snap(self.helper)],self.prior)
        self.assertEqual(self.call('restore')['status'],'restored')

    def test_prepared_reserve_failure_restores_untouched_originals_and_preserves_staging(self):
        journal=self.lp/('.focus-nextcloud-r6-'+self.nonce)/'transaction.json'
        def free(_path):
            prepared=journal.exists() and json.loads(journal.read_text())['state']=='prepared'
            return types.SimpleNamespace(free=source.FLOOR-1 if prepared else 100*1024**3)
        with patch.object(shutil,'disk_usage',side_effect=free),self.assertRaisesRegex(ValueError,'resource-or-expiry'):
            self.call()
        self.assertEqual(json.loads(journal.read_text())['state'],'prepared')
        self.assertEqual([self.snap(self.lib),self.snap(self.helper)],self.prior)
        self.assertEqual(self.call('restore')['status'],'restored')
        self.assertTrue((journal.parent/'new-library').is_dir())

    def test_existing_transaction_root_is_never_overwritten(self):
        self.call()
        with self.assertRaises(FileExistsError):self.call()


@unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen') and shutil.which('zstd'),
                     'needs existing age, age-keygen, zstd; no package installation')
class NativeBaselineProbeTests(unittest.TestCase):
    def test_compiled_native_key_and_encrypted_manifest_probe_cleans_on_success_and_error(self):
        from tests.backup.test_archive import Workspace, demo_manifest, demo_payloads
        from woowbackup import archive as native_archive
        ws=Workspace(self)
        doc=json.loads(json.dumps(demo_manifest(ws.key.key_id,backup_id=case.BASELINE)).replace('woowbk-demo','nextcloud'))
        data={k.replace('woowbk-demo','nextcloud'):v for k,v in demo_payloads().items()}
        path,_result,_entries=ws.write(data,doc)
        # Compile the SAME function rendered into BASELINE_INSPECT; no mock key store/archive.
        namespace={}
        exec(compile(case.BASELINE_INSPECT.split('import json,sys',1)[0],'<actual-key-probe>','exec'),namespace)
        probe=namespace['open_encrypted_baseline']
        secret=ws.key.path.read_text()
        before={p.name for p in ws.paths.run.iterdir()} if ws.paths.run.exists() else set()
        opened=probe(ws.keys,native_archive,path,secret,case.BASELINE)
        self.assertEqual(opened['backup_id'],case.BASELINE)
        self.assertEqual({p.name for p in ws.paths.run.iterdir()},before)
        with tempfile.TemporaryDirectory() as tmp:
            from woowbackup.keys import KeyStore
            from woowbackup.paths import Paths
            wrong,_=KeyStore(Paths(base=Path(tmp))).ensure_device_key()
            with self.assertRaises(Exception):probe(ws.keys,native_archive,path,wrong.path.read_text(),case.BASELINE)
        self.assertEqual({p.name for p in ws.paths.run.iterdir()},before)
        self.assertFalse((ws.paths.run/'key-inspect-focus-r6').exists())


class NativeMutationLockTests(unittest.TestCase):
    def test_busy_native_start_lock_refuses_before_scheduler_or_engine_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=Path(tmp);jobs=run/'jobs';jobs.mkdir()
            fd=os.open(run/'jobs.lock',os.O_RDWR|os.O_CREAT,0o600)
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with patch.object(source,'secure_dir'),patch.object(source.subprocess,'run') as command:
                    with self.assertRaises(BlockingIOError):
                        with source.mutation_locks(run,jobs,uid=os.getuid()):self.fail('must refuse')
                    command.assert_not_called()
            finally:os.close(fd)

    def test_scheduler_and_all_job_records_rechecked_with_both_native_locks(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=Path(tmp);jobs=run/'jobs';jobs.mkdir()
            with patch.object(source,'secure_dir'),patch.object(source.subprocess,'run',return_value=types.SimpleNamespace(
                    returncode=0,stdout=b'active\ninactive\n')):
                with self.assertRaisesRegex(ValueError,'schedule-not-inactive'):
                    with source.mutation_locks(run,jobs,uid=os.getuid()):self.fail('must refuse')
            (jobs/'j20261127T000000Z-01234567.json').write_text(json.dumps({'state':'queued'}))
            with patch.object(source,'secure_dir'),patch.object(source.subprocess,'run',return_value=types.SimpleNamespace(
                    returncode=0,stdout=b'inactive\ninactive\n')):
                with self.assertRaisesRegex(ValueError,'native-job-active'):
                    with source.mutation_locks(run,jobs,uid=os.getuid()):self.fail('must refuse')
            # Both files are unlocked after refusal; no process or global engine lock leaks.
            for name in ('jobs.lock','engine.lock'):
                fd=os.open(run/name,os.O_RDWR)
                try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(fd)


class GuardTests(unittest.TestCase):
    def test_actual_orchestrator_claims_stops_and_returns_units_and_source(self):
        events=[];nonce='abcdef0123456789';rows=manifest(payload())
        before={'isolation':{'running':True,'network':'none','ports':{},'memory_limit':case.DEVICE_CAP},
                'root':{'memory_max':str(case.DEVICE_CAP),'memory_current':0,'varlib_free_bytes':30*case.GIB,
                        'catalog_sha256':'a'*64,'installed_hashes':{'cli.py':'b'*64}},
                'host_memory_available_mib':3000,'host_free_bytes':30*case.GIB,
                'owner':{'units':{n:{'ActiveState':'inactive','UnitFileState':'generated'} for n in flow.INACTIVE_UNITS},
                         'quadlets':{'prior':'exact'},'images':[
                             {'ref':r,'present':True,'identity':{'id':v,'architecture':'amd64','os':'linux'}}
                             for r,v in case.ORIGINALS.items()]}}
        snapshot={'rows':[{'name':n} for n in case.wake.FILES]}
        claim={'ActiveState':'active','MainPID':'123','InvocationID':'a'*32}
        lease={'lane':'nextcloud-r6','device':'woowbk-dev-e','source_commit':'c'*40,'phases':['fullshare'],
               'product_commit':source.PRODUCT_COMMIT,'product_manifest_sha256':source.manifest_hash(rows),
               'source_policy':case.SOURCE_POLICY,'pin_refresh_policy':case.PIN_POLICY,'recovery_grace_seconds':1800,
               'reserve_bytes':case.RESERVE,'memory_cap_bytes':case.DEVICE_CAP,
               'not_before_utc':'2026-01-01T00:00:00Z','expires_utc':'2099-01-01T00:00:00Z'}
        def device(body,request=None,**kwargs):
            if body==case.QUIESCENT:return {'active_jobs':0}
            if body==case.wake.BASELINE_HASH:return [{'sha256':'d'*64}]
            if body=='unit-program':
                action=request['action'];events.append(action)
                return snapshot if action=='snapshot' else {'status':action}
            if body==case.wake.CONTROL:events.append('start');return {'status':'started'}
            if body==case.cold.CLAIM:events.append('claim');return claim
            if body==case.cold.STOP:
                self.assertEqual(request,{'prior':before['owner']['units']['nextcloud-office.service'],'claimed':claim})
                events.append('stop');return {'status':'stopped'}
            self.fail('unexpected device boundary')
        def transact(action,actual_nonce,*args):
            self.assertEqual(actual_nonce,nonce);self.assertNotEqual(actual_nonce,'24d1dc3d14bfc94e')
            events.append('source-'+action);return {'status':'restored' if action=='restore' else 'installed'}
        with tempfile.TemporaryDirectory() as tmp,contextlib.ExitStack() as stack:
            home=Path(tmp);receipt=home/'flow-receipt.json'
            def run_flow(*args):events.append('flow');receipt.write_text('{"pending":false}');return 0
            fakeflow=types.SimpleNamespace(RECEIPT=receipt,baseline_verify=lambda:True,run_locked=run_flow)
            stack.enter_context(patch.object(Path,'home',return_value=home))
            stack.enter_context(patch.object(case,'collect',side_effect=lambda:copy.deepcopy(before)))
            stack.enter_context(patch.object(case.source,'frozen_manifest',return_value=({},rows)))
            source_call=stack.enter_context(patch.object(case.source,'transact',side_effect=transact))
            stack.enter_context(patch.object(case.secrets,'token_hex',return_value=nonce))
            stack.enter_context(patch.object(case.wake,'unit_program',return_value='unit-program'))
            wake_call=stack.enter_context(patch.object(case.wake,'device',side_effect=device))
            stop_device=stack.enter_context(patch.object(case.cold,'device',side_effect=device))
            stop_call=stack.enter_context(patch.object(case.cold,'stop',wraps=case.cold.stop))
            stack.enter_context(patch.object(case,'reload_units',side_effect=lambda:events.append('reload')))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            args=types.SimpleNamespace(product_source=home,retained_upload_receipt=None)
            self.assertEqual(case.run(args,lease,'c'*40,{},fakeflow),0)
            wake_call.assert_any_call(case.cold.CLAIM)
            stop_call.assert_called_once_with(before['owner']['units']['nextcloud-office.service'],claim)
            stop_device.assert_called_once_with(case.cold.STOP,{'prior':before['owner']['units']['nextcloud-office.service'],
                                                               'claimed':claim},timeout=240)
            self.assertEqual([c.args[0] for c in source_call.call_args_list],['install','restore'])
            self.assertEqual(events,['snapshot','source-install','pin','reload','start','claim','flow','stop',
                                     'revert','reload','snapshot','source-restore'])
            result=json.loads(next(home.glob('.woowbk-lab/evidence/focus-nextcloud-r6-control/*/fixed-result.json')).read_text())
            self.assertTrue(all(result[k] for k in ('data_baseline_safe','prior_quadlets_exact',
                            'prior_engine_helper_version_exact','units_images_catalog_baseline_archive_isolation_preserved')))
            self.assertEqual(result['source_transaction_nonce'],nonce)

    def test_owner_writable_parents_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);p.chmod(0o777)
            with self.assertRaisesRegex(ValueError,'trusted-parent'):source.secure_dir(p,uid=os.getuid())

    def test_prior_link_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'link';p.symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):source.tree_snapshot(p,uid=os.getuid())

    def test_device_and_baseline_programs_compile_without_execution(self):
        compile(source.program(),'<source-device>','exec');compile(case.BASELINE_INSPECT,'<baseline>','exec')
        for body in (case.UPLOAD,case.QUIESCENT,case.RESOURCE,case.wake.CONTROL,case.wake.BASELINE_HASH,case.wake.unit_program()):
            compile(body,'<rendered-device>','exec')
        nc=flow.load_flow()
        rendered=flow.render_office(nc.OFFICE,'123456789abc')
        self.assertIn('--image-volume=ignore',rendered)
        self.assertNotIn('woowbk-ncoffice-relay',rendered)
        self.assertNotIn('docker.io/nginxinc/nginx-unprivileged:1.29.3-alpine',rendered)
        for body in (nc.STATE,nc.CLIENT,rendered,nc.ENGINE_HASHES,nc.ENTRY_READ,nc.ENTRY_WRITE):
            compile(body,'<rendered-legacy-probe>','exec')

    def test_cold_admission_refuses_wrong_cap_missing_image_and_active_service(self):
        base={'isolation':{'running':True,'network':'none','ports':{},'memory_limit':case.DEVICE_CAP},
              'root':{'memory_max':str(case.DEVICE_CAP),'memory_current':0,'varlib_free_bytes':30*case.GIB},
              'host_memory_available_mib':3000,'host_free_bytes':30*case.GIB,
              'owner':{'units':{'nextcloud.target':{'ActiveState':'inactive'}},
                       'images':[{'ref':r,'present':True,'identity':{'id':v,'architecture':'amd64','os':'linux'}}
                                 for r,v in case.ORIGINALS.items()]}}
        case.admission(base)
        for change in ('cap','image','active','reserve'):
            b=copy.deepcopy(base)
            if change=='cap':b['isolation']['memory_limit']=4*case.GIB
            if change=='image':b['owner']['images'].pop()
            if change=='active':b['owner']['units']['nextcloud.target']['ActiveState']='active'
            if change=='reserve':b['root']['varlib_free_bytes']=case.RESERVE
            with self.subTest(change=change),self.assertRaises(ValueError):case.admission(b)

    def test_foreign_backups_and_original_baseline_never_enter_delete_or_restore(self):
        state={'created_backups':['owned-id'],'ha_backup_id':'ha-owned-id'}
        for command in ('delete','restore-start'):
            flow.owned_command(command,{'backup_id':'owned-id'},state)
            for bad in (case.BASELINE,'foreign-id',None):
                with self.subTest(command=command,bad=bad),self.assertRaises(ValueError):
                    flow.owned_command(command,{'backup_id':bad},state)
        flow.owned_command('ha-delete',{'ha_backup_id':'ha-owned-id'},state)
        with self.assertRaises(ValueError):flow.owned_command('ha-delete',{'ha_backup_id':'ha-foreign'},state)

    def test_default_fullshare_entrypoint_has_no_lab_calls(self):
        with patch.object(sys,'argv',['driver']),patch.object(flow.subprocess,'run',side_effect=AssertionError),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(flow.main(),0)


if __name__=='__main__':unittest.main()
