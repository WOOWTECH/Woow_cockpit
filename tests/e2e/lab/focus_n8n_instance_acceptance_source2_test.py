"""Offline per-file FSM: real replace/unlink, process kills, exact CAS return."""
import base64
from contextlib import redirect_stdout
from datetime import datetime,timezone
import errno
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import focus_n8n_instance_acceptance_source2 as host
import focus_n8n_instance_acceptance_source2_ops as ops
from focus_n8n_instance_acceptance_source_test import payload,NAME


def candidate():
    result=payload();data=b'NEW_VALUE=5\n';name='woowbackup/new_module.py'
    result['files'][name]=base64.b64encode(data).decode();result['sha256'][name]=ops.common.digest(data)
    return result


class FileFSMTests(unittest.TestCase):
    def setUp(self):
        self.probe=patch.object(ops.base,'tool_probe',side_effect=self.probe_import)
        self.probe.start();self.addCleanup(self.probe.stop)

    def probe_import(self,path):
        before=ops.base.tree(path)
        code="import sys;sys.dont_write_bytecode=True;sys.pycache_prefix='/nonexistent/source2-test';sys.path.insert(0,"+repr(str(path))+");from woowbackup import cli;assert cli.value=='candidate'"
        p=subprocess.run([sys.executable,'-B','-I','-c',code],capture_output=True,timeout=10)
        self.assertEqual(p.returncode,0);self.assertEqual(ops.base.tree(path),before)

    def setup_tree(self,root,*,adapters=True):
        root=Path(root);lib=root/'lib';lib.mkdir(mode=0o755)
        dirs=['woowbackup','woowbackup/__pycache__']+(['woowbackup/adapters'] if adapters else [])
        for rel in dirs:(lib/rel).mkdir(mode=0o755)
        for rel,data in {'VERSION':b'original\n','woowbackup/cli.py':b'value="original"\n',
                         'woowbackup/stale.py':b'stale managed module\n','opaque.data':b'opaque keep\n',
                         'woowbackup/__pycache__/existing.pyc':b'opaque prior bytecode'}.items():
            p=lib/rel;p.write_bytes(data);p.chmod(0o640);os.utime(p,ns=(1000000000,1000000123))
        helper=root/'helper';helper.write_bytes(b'#!/usr/bin/python3 -I\n# original\n');helper.chmod(0o750)
        parent=root/'cases';parent.mkdir(mode=0o700);(parent/NAME).mkdir(mode=0o700)
        old=ops.base.Transaction(NAME,lib=lib,helper=helper,parent=parent)
        old.original_copy();old.stage_candidate(candidate());old.state['restored']=True;old.save()
        return ops.Transaction2(NAME,lib=lib,helper=helper,parent=parent,trusted_root=root)

    def reread(self,tx):return ops.Transaction2(NAME,lib=tx.lib,helper=tx.helper,parent=tx.path.parent,trusted_root=tx.trusted_root)

    def assert_original(self,tx):
        self.assertEqual(ops.checked_tree(tx.lib),tx.state['original'])
        self.assertEqual(ops.checked_file(tx.helper),tx.state['helper'])
        self.assertEqual(tx.source1_fingerprint(),tx.state['source1_fingerprint'])

    def child_crash(self,tx,action,n,mode='replace'):
        code='''import sys,os,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import focus_n8n_instance_acceptance_source2_ops as x
t=x.Transaction2(sys.argv[2],lib=sys.argv[3],helper=sys.argv[4],parent=sys.argv[5],trusted_root=sys.argv[6])
real_replace=x.os.replace;real_unlink=x.os.unlink;real_open=x.os.open;count=0
def live(p):return Path(p)==t.helper or t.lib in Path(p).parents
def crash():
 global count
 count+=1
 if count==int(sys.argv[8]):os._exit(23)
def replace(a,b):
 if live(b) and sys.argv[9]=='before_replace':crash()
 real_replace(a,b)
 if live(b) and sys.argv[9]=='replace':crash()
def unlink(p,*a,**kw):
 real_unlink(p,*a,**kw)
 if live(p) and sys.argv[9]=='unlink':crash()
def open_file(p,*a,**kw):
 fd=real_open(p,*a,**kw)
 if Path(p).name.startswith('pending-') and sys.argv[9]=='open':os._exit(23)
 return fd
x.os.replace=replace;x.os.unlink=unlink;x.os.open=open_file
if sys.argv[7]=='publish':t.publish(json.loads(sys.stdin.read()))
else:t.restore()
'''
        p=subprocess.run([sys.executable,'-B','-I','-c',code,str(host.HERE),NAME,str(tx.lib),str(tx.helper),
                          str(tx.path.parent),str(tx.trusted_root),action,str(n),mode],
                         input=json.dumps(candidate()).encode(),capture_output=True,timeout=30)
        self.assertEqual(p.returncode,23)

    def test_real_publish_and_return_preserve_library_inode_opaque_cache_and_source1(self):
        with tempfile.TemporaryDirectory() as folder:
            tx=self.setup_tree(folder);inode=tx.lib.stat().st_ino;tx.prepare(candidate(),{})
            with patch.object(ops.os,'rename',side_effect=AssertionError('no directory rename')),patch.object(ops.base,'exchange',side_effect=AssertionError('no exchange')):
                tx.publish(candidate());self.assertEqual(tx.lib.stat().st_ino,inode)
                self.assertEqual((tx.lib/'opaque.data').read_bytes(),b'opaque keep\n')
                self.assertEqual((tx.lib/'woowbackup/__pycache__/existing.pyc').read_bytes(),b'opaque prior bytecode')
                self.assertFalse((tx.lib/'woowbackup/stale.py').exists())
                self.assertEqual(list(tx.state['mutations'])[-2:],['VERSION','helper'])
                tx.restore();self.assert_original(tx);self.assertEqual(tx.lib.stat().st_ino,inode)

    def test_hard_exit_after_each_live_file_publication_recovers_exact_original(self):
        for n in range(1,len(candidate()['sha256'])+1):
            with self.subTest(file=n),tempfile.TemporaryDirectory() as folder:
                tx=self.setup_tree(folder);tx.prepare(candidate(),{});self.child_crash(tx,'publish',n)
                resumed=self.reread(tx);self.assertEqual(resumed.state['pending_step'],'replace_live_file')
                resumed.restore();self.assert_original(resumed)

    def test_hard_exit_after_each_original_file_return_and_owned_new_delete_resumes(self):
        # cli, stale.py, VERSION and helper return by replace; three added files
        # (__init__, adapters/__init__, new_module) return by owned-only unlink.
        for mode,count in (('replace',4),('unlink',3)):
            for n in range(1,count+1):
                with self.subTest(mode=mode,file=n),tempfile.TemporaryDirectory() as folder:
                    tx=self.setup_tree(folder);tx.prepare(candidate(),{});tx.publish(candidate())
                    self.child_crash(tx,'restore',n,mode);resumed=self.reread(tx)
                    resumed.restore();self.assert_original(resumed)

    def test_hard_exit_before_first_replace_cleans_only_inode_proven_temporary(self):
        with tempfile.TemporaryDirectory() as folder:
            tx=self.setup_tree(folder);tx.prepare(candidate(),{});self.child_crash(tx,'publish',1,'before_replace')
            resumed=self.reread(tx);resumed.restore();self.assert_original(resumed)
            self.assertFalse(any(resumed.libown.glob('pending-*')))

    def test_hard_exit_after_trusted_stale_python_delete_restores_exact_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            tx=self.setup_tree(folder);tx.prepare(candidate(),{});self.child_crash(tx,'publish',1,'unlink')
            resumed=self.reread(tx);resumed.restore();self.assert_original(resumed)

    def test_kill_before_temporary_inode_receipt_retains_unknown_and_returns_verified_source(self):
        with tempfile.TemporaryDirectory() as folder:
            tx=self.setup_tree(folder);tx.prepare(candidate(),{});self.child_crash(tx,'publish',1,'open')
            resumed=self.reread(tx);resumed.restore();self.assert_original(resumed)
            self.assertEqual(resumed.state['unproven_temporaries_retained'],['pending-0'])
            self.assertTrue((resumed.libown/'pending-0').exists())

    def test_new_directory_is_owned_removed_and_original_directory_times_return(self):
        with tempfile.TemporaryDirectory() as folder:
            tx=self.setup_tree(folder,adapters=False);tx.prepare(candidate(),{});tx.publish(candidate())
            self.assertIn('woowbackup/adapters',tx.state['new_directories'])
            tx.restore();self.assert_original(tx);self.assertFalse((tx.lib/'woowbackup/adapters').exists())

    def test_syscall_failure_preserves_exact_prior_absence_sha_mode_stage_class_errno(self):
        with tempfile.TemporaryDirectory() as folder:
            tx=self.setup_tree(folder);tx.prepare(candidate(),{});real=os.replace
            def fail(a,b):
                if tx.lib in Path(b).parents:
                    saved=json.loads((tx.path/'state.json').read_text())
                    self.assertEqual(saved['pending_step'],'replace_live_file')
                    row=saved['mutations']['woowbackup/__init__.py']
                    self.assertTrue(row['prior_absent']);self.assertIsNone(row['prior'])
                    self.assertEqual(row['after']['mode'],0o644)
                    raise OSError(errno.EXDEV,'foreign text never public')
                return real(a,b)
            with patch.object(ops.os,'replace',side_effect=fail),self.assertRaises(OSError):tx.publish(candidate())
            saved=json.loads((tx.path/'state.json').read_text())
            self.assertEqual(saved['last_error']['step'],'replace_live_file')
            self.assertEqual(saved['last_error']['error_class'],'OSError');self.assertEqual(saved['last_error']['errno'],errno.EXDEV)
            self.assertNotIn('foreign text',json.dumps(saved));tx.restore();self.assert_original(tx)

    def test_foreign_helper_or_new_file_metadata_refuses_all_return_writes(self):
        for mode in ('helper','new-file'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as folder:
                tx=self.setup_tree(folder);tx.prepare(candidate(),{});tx.publish(candidate())
                (tx.helper if mode=='helper' else tx.lib/'woowbackup/new_module.py').chmod(0o700)
                before=ops.base.tree(tx.lib)
                with self.assertRaises(ValueError):tx.restore()
                self.assertEqual(ops.base.tree(tx.lib),before)

    def test_foreign_opaque_cache_file_directory_or_xattr_is_retained(self):
        for mode in ('opaque','cache','directory','xattr'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as folder:
                tx=self.setup_tree(folder);tx.prepare(candidate(),{});tx.publish(candidate())
                if mode=='opaque':(tx.lib/'opaque.data').write_bytes(b'operator')
                if mode=='cache':(tx.lib/'woowbackup/__pycache__/existing.pyc').write_bytes(b'operator')
                if mode=='directory':(tx.lib/'woowbackup').chmod(0o700)
                if mode=='xattr':os.setxattr(tx.lib/'VERSION','user.focus-source2',b'operator')
                before=ops.base.tree(tx.lib)
                with self.assertRaises(ValueError):tx.restore()
                self.assertEqual(ops.base.tree(tx.lib),before)

    def test_damaged_private_or_source1_copy_refuses_before_publication(self):
        for mode in ('private-library','private-helper-mode','source1-stage'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as folder:
                tx=self.setup_tree(folder);tx.prepare(candidate(),{})
                if mode=='private-library':(tx.path/'private-library/VERSION').write_bytes(b'changed')
                if mode=='private-helper-mode':(tx.path/'private-helper').chmod(0o640)
                if mode=='source1-stage':(tx.source1.stage/'VERSION').write_bytes(b'changed')
                before=ops.base.tree(tx.lib)
                with self.assertRaises(ValueError):tx.publish(candidate())
                self.assertEqual(ops.base.tree(tx.lib),before)

    def test_unknown_added_file_and_unproven_temporary_are_never_deleted(self):
        for mode in ('file','temporary'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as folder:
                tx=self.setup_tree(folder);tx.prepare(candidate(),{})
                if mode=='file':
                    p=tx.lib/'unknown';p.write_bytes(b'foreign')
                else:
                    p=tx.libown/'pending-foreign';p.write_bytes(b'foreign')
                    tx.state['temporary']['pending-foreign']={'helper':False,'prior_absent':True,'identity':None};tx.save()
                if mode=='file':
                    with self.assertRaises(ValueError):tx.restore()
                else:
                    tx.restore();self.assert_original(tx)
                    self.assertIn('pending-foreign',tx.state['unproven_temporaries_retained'])
                self.assertEqual(p.read_bytes(),b'foreign')

    def test_existing_namespace_not_replayed_and_prepublication_failure_no_live_rewrite(self):
        with tempfile.TemporaryDirectory() as folder:
            tx=self.setup_tree(folder)
            with patch.object(ops.base,'tool_probe',side_effect=ValueError('fixed-source2-probe')),self.assertRaises(ValueError):tx.prepare(candidate(),{})
            tx.restore();self.assert_original(tx);state=(tx.path/'state.json').read_bytes()
            with self.assertRaises(ValueError):self.reread(tx).prepare(candidate(),{})
            self.assertEqual((tx.path/'state.json').read_bytes(),state)


class HostTests(unittest.TestCase):
    def test_exact_new_lease_method_phase_driver_manifest_and_image_case(self):
        source=candidate();image={'name':NAME,'images_ready':True,'owned_images':list(host.previous.plan.ARCHIVES)}
        lease={'granted':True,'device':host.previous.plan.DEVICE,'case':host.CASE,'method':host.METHOD,
            'phases':list(host.PHASES),'driver_commit':'a'*40,'source_commit':ops.base.FROZEN,'name':NAME,
            'source_manifest_sha256':host.previous.manifest_sha(source),'bounds':host.previous.BOUNDS,
            'protected_capture_sha256':host.previous.plan.sha(host.REPO/'snippets'/host.previous.plan.AREA/'protected-baselines-readonly.json'),
            'not_before_utc':datetime.fromtimestamp(900,timezone.utc).isoformat(),
            'expires_utc':datetime.fromtimestamp(2000,timezone.utc).isoformat()}
        self.assertEqual(host.validate(lease,'source2-install','a'*40,source,image,1000),2000)
        for key,value in (('case','n8n-instance-source'),('method','samefs-four-os.rename-journal-v2'),
                          ('phases',['source-install']),('driver_commit','b'*40),('source_manifest_sha256','b'*64)):
            with self.subTest(key=key),self.assertRaises(ValueError):host.validate(dict(lease,**{key:value}),'source2-install','a'*40,source,image,1000)

    def test_default_offline_and_inner_error_response_stays_exact_private(self):
        with patch.object(host,'invoke',side_effect=AssertionError('no device')),redirect_stdout(io.StringIO()):self.assertEqual(host.main([]),0)
        class H:
            def root(self,*a,**kw):return type('P',(),{'returncode':1,'stdout':b'{"ok":false,"private_error_class":"OSError","private_errno":18,"private_stage":"replace_live_file"}'})()
        result=host.invoke(H(),{})
        self.assertEqual(result['private_error_class'],'OSError');self.assertEqual(result['private_errno'],18)
        self.assertEqual(result['private_stage'],'replace_live_file')


if __name__=='__main__':unittest.main()
