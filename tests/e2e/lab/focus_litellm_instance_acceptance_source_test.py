"""Source-only transaction: real files, interrupted publication and exact CAS return."""
import base64
from datetime import datetime,timezone
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
NAME='woowbk_focus_litellm_source_012345abcdef'


def load():
    spec=importlib.util.spec_from_file_location('ll_source_ops',HERE/'focus_litellm_instance_acceptance_source_ops.py')
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def payload(ops):
    files={'VERSION':b'new\n','helper':b'#!/usr/bin/python3 -I\n# new\n',
           'woowbackup/__init__.py':b'', 'woowbackup/adapters/__init__.py':b'',
           'woowbackup/cli.py':b"VALUE='new'\n",'woowbackup/new.py':b'VALUE=2\n'}
    return {'source_commit':ops.NEW,'mtime_ns':1800000000000000000,
            'files':{k:base64.b64encode(v).decode() for k,v in files.items()},
            'sha256':{k:hashlib.sha256(v).hexdigest() for k,v in files.items()}}


class SourceTransactionTests(unittest.TestCase):
    def fixture(self,root):
        m=load();root=Path(root);lib=root/'lib';lib.mkdir(mode=0o755)
        for name in ('woowbackup','woowbackup/adapters','woowbackup/__pycache__'):(lib/name).mkdir(mode=0o755)
        files={'VERSION':b'old\n','woowbackup/__init__.py':b'', 'woowbackup/adapters/__init__.py':b'',
               'woowbackup/cli.py':b"VALUE='old'\n",'woowbackup/old.py':b'VALUE=1\n',
               'woowbackup/__pycache__/opaque.pyc':b'untouched-cache','opaque.json':b'{"keep":true}'}
        for name,data in files.items():
            p=lib/name;p.write_bytes(data);p.chmod(0o640);os.utime(p,ns=(1000000000,1000000123))
        helper=root/'helper';helper.write_bytes(b'#!/usr/bin/python3 -I\n# old\n');helper.chmod(0o750)
        cases=root/'cases';cases.mkdir(mode=0o700)
        old={k:v['sha256'] for k,v in m.tree(lib)['files'].items() if m.managed(k)}
        old['helper']=m.file_meta(helper)['sha256']
        tx=m.Transaction(NAME,lib=lib,helper=helper,parent=cases,trusted_root=root)
        return m,tx,old

    def test_per_file_publish_and_exact_whole_return_keep_live_directory_inode(self):
        with tempfile.TemporaryDirectory() as root:
            m,tx,old=self.fixture(root);before=m.tree(tx.lib);helper=m.file_meta(tx.helper);inode=tx.lib.stat().st_ino
            tx.prepare(payload(m),old)
            with patch.object(m.os,'rename',side_effect=AssertionError('no directory rename')):tx.publish()
            self.assertEqual(tx.lib.stat().st_ino,inode)
            self.assertEqual((tx.lib/'VERSION').read_bytes(),b'new\n')
            self.assertFalse((tx.lib/'woowbackup/old.py').exists())
            self.assertEqual((tx.lib/'woowbackup/__pycache__/opaque.pyc').read_bytes(),b'untouched-cache')
            tx.restore();self.assertEqual(m.tree(tx.lib),before);self.assertEqual(m.file_meta(tx.helper),helper)
            tx.restore();self.assertEqual(m.tree(tx.lib),before)

    def test_foreign_helper_edit_refuses_all_rollback_writes(self):
        with tempfile.TemporaryDirectory() as root:
            m,tx,old=self.fixture(root);tx.prepare(payload(m),old);tx.publish();before=m.tree(tx.lib)
            tx.helper.chmod(0o700)
            with patch.object(m.os,'replace',side_effect=AssertionError('must not write')),self.assertRaises(ValueError):tx.restore()
            self.assertEqual(m.tree(tx.lib),before);self.assertEqual(tx.helper.stat().st_mode&0o777,0o700)

    def killed(self,tx,phase):
        script='''import sys,os
sys.dont_write_bytecode=True
sys.path.insert(0,sys.argv[1])
import focus_litellm_instance_acceptance_source_ops as m
t=m.Transaction(sys.argv[2],lib=sys.argv[3],helper=sys.argv[4],parent=sys.argv[5],trusted_root=sys.argv[6])
replace=m.os.replace
def killed(a,b):
 replace(a,b)
 if str(b).startswith(str(t.lib)+'/') or str(b)==str(t.helper):os._exit(73)
m.os.replace=killed
getattr(t,sys.argv[7])()
'''
        p=subprocess.run([sys.executable,'-B','-I','-c',script,str(HERE),NAME,str(tx.lib),str(tx.helper),
            str(tx.path.parent),str(tx.trusted_root),phase],capture_output=True,timeout=15)
        self.assertEqual(p.returncode,73,p.stderr.decode())

    def test_hard_exit_after_real_replace_recovery_uses_durable_intent(self):
        with tempfile.TemporaryDirectory() as root:
            m,tx,old=self.fixture(root);before=m.tree(tx.lib);helper=m.file_meta(tx.helper)
            tx.prepare(payload(m),old);self.killed(tx,'publish')
            reload=m.Transaction(NAME,lib=tx.lib,helper=tx.helper,parent=tx.path.parent,trusted_root=root)
            self.assertTrue(reload.state['mutations']);reload.restore()
            self.assertEqual(m.tree(tx.lib),before);self.assertEqual(m.file_meta(tx.helper),helper)

    def test_hard_exit_during_return_is_idempotently_recoverable(self):
        with tempfile.TemporaryDirectory() as root:
            m,tx,old=self.fixture(root);before=m.tree(tx.lib);helper=m.file_meta(tx.helper)
            tx.prepare(payload(m),old);tx.publish();self.killed(tx,'restore')
            reload=m.Transaction(NAME,lib=tx.lib,helper=tx.helper,parent=tx.path.parent,trusted_root=root)
            reload.restore();reload.restore()
            self.assertEqual(m.tree(tx.lib),before);self.assertEqual(m.file_meta(tx.helper),helper)

    def test_foreign_cache_or_private_copy_refuses_before_any_return_write(self):
        for target in ('cache','copy'):
            with self.subTest(target=target),tempfile.TemporaryDirectory() as root:
                m,tx,old=self.fixture(root);tx.prepare(payload(m),old);tx.publish()
                p=tx.lib/'woowbackup/__pycache__/opaque.pyc' if target=='cache' else tx.path/'prior-helper'
                p.write_bytes(b'foreign');before=m.tree(tx.lib)
                with patch.object(m.os,'replace',side_effect=AssertionError('no write')),self.assertRaises(ValueError):tx.restore()
                self.assertEqual(m.tree(tx.lib),before)

    def test_old_manifest_cas_and_symlinks_fail_before_prior_directory_creation(self):
        for kind in ('hash','symlink','hardlink'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as root:
                m,tx,old=self.fixture(root)
                if kind=='hash':old['VERSION']='0'*64
                elif kind=='symlink':(tx.lib/'foreign').symlink_to(tx.helper)
                else:os.link(tx.helper,tx.lib/'foreign')
                with self.assertRaises(ValueError):tx.prepare(payload(m),old)
                self.assertFalse(tx.path.exists())

    def test_exception_mid_publish_can_return_without_replaying_publish(self):
        with tempfile.TemporaryDirectory() as root:
            m,tx,old=self.fixture(root);before=m.tree(tx.lib);tx.prepare(payload(m),old)
            replace=tx.replace_file;count=0
            def fail(name,data,meta):
                nonlocal count
                count+=1
                if count==3:raise InterruptedError('injected cancellation')
                return replace(name,data,meta)
            with patch.object(tx,'replace_file',side_effect=fail),self.assertRaises(InterruptedError):tx.publish()
            with self.assertRaises(ValueError):tx.publish()
            tx.restore();self.assertEqual(m.tree(tx.lib),before)

    def test_temporary_budget_refuses_before_any_live_publication(self):
        with tempfile.TemporaryDirectory() as root:
            m,tx,old=self.fixture(root);before=m.tree(tx.lib);tx.prepare(payload(m),old)
            tx.state['temporaries']={str(i):{'helper':False,'identity':None} for i in range(256)};tx.save()
            with self.assertRaisesRegex(ValueError,'temporary-bound'):tx.publish()
            self.assertEqual(m.tree(tx.lib),before);tx.restore();self.assertEqual(m.tree(tx.lib),before)

    def test_locks_are_jobs_then_engine_and_busy_engine_releases_jobs(self):
        with tempfile.TemporaryDirectory() as root:
            m=load();run=Path(root)
            for name in ('jobs.lock','engine.lock'):(run/name).touch(mode=0o600)
            events=[];original=m.fcntl.flock
            def flock(fd,flags):events.append(Path(os.readlink('/proc/self/fd/'+str(fd))).name);return original(fd,flags)
            with patch.object(m.fcntl,'flock',side_effect=flock),m.engine_locks(run):pass
            self.assertEqual(events,['jobs.lock','engine.lock'])
            fd=os.open(run/'engine.lock',os.O_RDWR);original(fd,m.fcntl.LOCK_EX|m.fcntl.LOCK_NB)
            try:
                with self.assertRaises(BlockingIOError),m.engine_locks(run):pass
                check=os.open(run/'jobs.lock',os.O_RDWR)
                try:original(check,m.fcntl.LOCK_EX|m.fcntl.LOCK_NB)
                finally:os.close(check)
            finally:os.close(fd)

    def test_guard_preserves_running_originals_requires_masked_schedule_and_no_jobs(self):
        m=load();value={'active_jobs':[],'active_job_units':[],'running':list(m.SELECTED),
                       'selected':{n:{'unit':{'ActiveState':'active'}} for n in m.SELECTED},
                       'timer':{'ActiveState':'inactive','UnitFileState':'masked-runtime'}}
        m.validate_boundary(value)
        for key,change in (('active_jobs',['j20261127T000000Z-01234567']),('active_job_units',['unit']),
                           ('running',[]),('timer',{'ActiveState':'inactive','UnitFileState':'enabled'})):
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_boundary(dict(value,**{key:change}))

    def test_archive_metadata_handles_directory_and_arbitrary_sidecars(self):
        with tempfile.TemporaryDirectory() as root:
            m=load();p=Path(root);(p/'app').mkdir();(p/'app'/'backup.json').write_text('{}')
            (p/'app'/'backup.tar.age').write_bytes(b'opaque')
            listing=m.metadata_listing(p)
            self.assertEqual(set(listing),{'.','app','app/backup.json','app/backup.tar.age'})

    def test_live_probe_failure_automatically_returns_real_prior_files_and_helper(self):
        with tempfile.TemporaryDirectory() as root:
            m,tx,old=self.fixture(root);before=m.tree(tx.lib);helper=m.file_meta(tx.helper)
            q={'phase':'source-install','old_sha256':old,'payload':payload(m)}
            with patch.object(m.common,'call'),patch.object(m,'probe',side_effect=[None,RuntimeError('injected')]),self.assertRaises(RuntimeError):
                m.transact(tx,q,{'protected':'unchanged'})
            self.assertTrue(tx.state['automatic_return']);self.assertEqual(m.tree(tx.lib),before)
            self.assertEqual(m.file_meta(tx.helper),helper)

    def test_foreign_protected_change_fails_and_returns_only_source_without_app_repair(self):
        with tempfile.TemporaryDirectory() as root:
            m,tx,old=self.fixture(root);before=m.tree(tx.lib)
            q={'phase':'source-install','old_sha256':old,'payload':payload(m)}
            with patch.object(m.common,'call'),patch.object(m,'probe'),patch.object(m,'snapshot',return_value={'foreign':'churn'}),self.assertRaises(ValueError):
                m.transact(tx,q,{'original':'kept'})
            self.assertEqual(m.tree(tx.lib),before);self.assertEqual(tx.state['after'],{'foreign':'churn'})


class SourceControllerTests(unittest.TestCase):
    def test_exact_git_payload_compiles_and_binds_every_frozen_managed_file(self):
        import focus_litellm_instance_acceptance_source as c
        p,old,bound=c.bindings();self.assertEqual(len(p['files']),53)
        self.assertEqual(set(p['files']),set(p['sha256']));self.assertIn('helper',old);self.assertIn('VERSION',old)
        self.assertEqual(bound['payload_sha256'],c.ops.digest(c.ops.canonical(p)))
        compile(c.program(),'<embedded source>','exec')

    def test_full_frozen_payload_imports_and_returns_exact_whole_old_library(self):
        import focus_litellm_instance_acceptance_source as c
        with tempfile.TemporaryDirectory() as root:
            m,tx,_=SourceTransactionTests().fixture(root)
            for name in list(m.tree(tx.lib)['files']):
                if m.managed(name):(tx.lib/name).unlink()
            original=c.source_files(m.OLD)
            for n,b in original.items():
                p=tx.helper if n=='helper' else tx.lib/n;p.write_bytes(b);p.chmod(0o640)
            before=m.tree(tx.lib);helper=m.file_meta(tx.helper)
            tx.prepare(c.payload(),{n:m.digest(b) for n,b in original.items()})
            m.probe(tx.path/'candidate',tx.path/'absent-staged-cache');tx.publish()
            m.probe(tx.lib,tx.path/'absent-live-cache')
            self.assertEqual(tx.hashes(),c.payload()['sha256']);tx.restore()
            self.assertEqual(m.tree(tx.lib),before);self.assertEqual(m.file_meta(tx.helper),helper)

    def test_usable_stale_cache_is_refused_without_deleting_opaque_cache(self):
        import focus_litellm_instance_acceptance_source as c
        import py_compile
        with tempfile.TemporaryDirectory() as root:
            m,tx,old=SourceTransactionTests().fixture(root);cli=tx.lib/'woowbackup/cli.py'
            stamp=payload(m)['mtime_ns'];os.utime(cli,ns=(stamp,stamp));py_compile.compile(str(cli),doraise=True)
            before=m.tree(tx.lib)
            with self.assertRaisesRegex(ValueError,'stale-bytecode'):tx.prepare(payload(m),old)
            self.assertEqual(m.tree(tx.lib),before);self.assertFalse(tx.path.exists())

    def test_exact_lease_does_not_accept_image_lease_or_wrong_source_or_unpinned_baseline(self):
        import focus_litellm_instance_acceptance_source as c
        bound={'old_commit':c.ops.OLD,'new_commit':c.ops.NEW,'payload_sha256':'a'*64}
        now=1800000000;lease=dict(granted=True,case='litellm-instance-source',device=c.DEVICE,method=c.METHOD,
            name=NAME,driver_commit='b'*40,phases=list(c.PHASES),bounds=c.BOUNDS,baseline_sha256='c'*64,
            not_before_utc=datetime.fromtimestamp(now-1,timezone.utc).isoformat(),
            expires_utc=datetime.fromtimestamp(now+1200,timezone.utc).isoformat(),**bound)
        self.assertEqual(c.validate(lease,'source-install','b'*40,bound,now),now+1200)
        for k,v in (('case','litellm-instance-original'),('new_commit','0'*40),('baseline_sha256',None),
                    ('bounds',{}),('driver_commit','b'*8),('phases',['images'])):
            with self.subTest(k=k),self.assertRaises((ValueError,TypeError)):c.validate(dict(lease,**{k:v}),'source-install','b'*40,bound,now)

    def test_import_probe_reads_source_instead_of_stale_bytecode_and_writes_nothing(self):
        import focus_litellm_instance_acceptance_source as c
        import py_compile
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);lib=root/'lib';(lib/'woowbackup/adapters').mkdir(parents=True)
            for name in ('__init__.py','ha_litellm.py','adapters/__init__.py','adapters/quadlet_postgres.py'):
                (lib/'woowbackup'/name).write_text('')
            cli=lib/'woowbackup/cli.py';old="raise RuntimeError('stale cache must not execute')\n";cli.write_text(old)
            st=cli.stat()
            py_compile.compile(str(cli),doraise=True)
            cli.write_text('VALUE=True'+(' '*(len(old)-len('VALUE=True\n')))+'\n')
            os.utime(cli,ns=(st.st_atime_ns,st.st_mtime_ns));before=c.ops.tree(lib)
            c.ops.probe(lib,root/'absent-cache')
            self.assertEqual(c.ops.tree(lib),before);self.assertFalse((root/'absent-cache').exists())


if __name__=='__main__':unittest.main()
