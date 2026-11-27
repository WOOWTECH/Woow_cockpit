"""Bounded offline real-file transaction/recovery and PG16 query source guards."""
import ast
import base64
from contextlib import redirect_stdout
from datetime import datetime,timezone
import fcntl
import hashlib
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
import focus_n8n_instance_acceptance_ops as common
import focus_n8n_instance_acceptance_source_ops as ops
import focus_n8n_instance_acceptance_source as host

NAME='woowbk_focus_n8n_28a4a4b1cbcd'


def payload():
    files={'VERSION':b'new-version\n','woowbackup/__init__.py':b'',
           'woowbackup/cli.py':b'value="candidate"\n','woowbackup/adapters/__init__.py':b''}
    helper=b'#!/usr/bin/python3 -I\n# candidate helper\n'
    return {'source_commit':ops.FROZEN,'files':{k:base64.b64encode(v).decode() for k,v in files.items()},
            'helper':base64.b64encode(helper).decode(),
            'sha256':{k:common.digest(v) for k,v in files.items()}|{'helper':common.digest(helper)}}


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.lib=self.root/'library';self.lib.mkdir(mode=0o755)
        for name in ('woowbackup','woowbackup/adapters','woowbackup/__pycache__'):(self.lib/name).mkdir(mode=0o755)
        for name,data in {'VERSION':b'old-version\n','woowbackup/cli.py':b'old source\n',
                          'woowbackup/__pycache__/old.pyc':b'opaque prior bytecode','prior-private.data':b'opaque prior file'}.items():
            p=self.lib/name;p.write_bytes(data);os.chmod(p,0o640);os.utime(p,ns=(1200000000,1200000123))
        self.helper=self.root/'helper';self.helper.write_bytes(b'#!/usr/bin/python3 -I\n# prior\n')
        os.chmod(self.helper,0o750);os.utime(self.helper,ns=(1200000000,1300000123))
        self.parent=self.root/'cases';(self.parent/NAME).mkdir(mode=0o700,parents=True)
        self.tx=ops.Transaction(NAME,lib=self.lib,helper=self.helper,parent=self.parent)
        self.before=ops.tree(self.lib);self.hbefore=common.read_regular(self.helper)
        self.probe=patch.object(ops,'tool_probe',side_effect=self.import_candidate);self.probe.start();self.addCleanup(self.probe.stop)

    def import_candidate(self,path):
        # Real isolated Python import before/after tree comparison. It neither
        # reads old bytecode nor creates caches next to protected source files.
        before=ops.tree(path)
        code="import sys;sys.dont_write_bytecode=True;sys.pycache_prefix='/nonexistent/focus-source-test';sys.path.insert(0,"+repr(str(path))+");from woowbackup import cli;assert cli.value=='candidate'"
        p=subprocess.run([sys.executable,'-B','-I','-c',code],capture_output=True,timeout=10)
        self.assertEqual(p.returncode,0);self.assertEqual(ops.tree(path),before)

    def assert_original(self):
        self.assertEqual(ops.tree(self.lib),self.before);self.assertEqual(common.read_regular(self.helper),self.hbefore)

    def test_install_and_recover_exact_prior_tree_helper_version_metadata_and_opaque_files(self):
        self.tx.install(payload())
        self.assertEqual((self.lib/'VERSION').read_bytes(),b'new-version\n')
        self.assertNotIn('prior-private.data',ops.tree(self.lib)['files'])
        self.assertTrue(self.tx.state['copy_complete']);self.assertTrue(self.tx.state['complete'])
        self.tx.restore();self.assert_original()
        self.assertTrue((self.tx.path/'prior-library/prior-private.data').is_file())

    def test_helper_publish_failure_automatically_restores_engine_and_exact_helper(self):
        real=os.replace
        def replace(src,dst):
            if Path(src)==self.tx.hstage:raise OSError('injected helper publish failure')
            return real(src,dst)
        with patch.object(ops.os,'replace',side_effect=replace),self.assertRaises(OSError):self.tx.install(payload())
        self.assert_original();self.assertTrue(self.tx.state['restored'])

    def test_lost_process_after_library_exchange_recovers_from_prior_intent(self):
        self.tx.original_copy();self.tx.stage_candidate(payload())
        self.tx.state['publish_intent']=True;self.tx.save();ops.exchange(self.tx.stage,self.lib)
        recovered=ops.Transaction(NAME,lib=self.lib,helper=self.helper,parent=self.parent)
        recovered.restore();self.assert_original()

    def test_unknown_live_file_prevents_recovery_and_is_retained(self):
        self.tx.install(payload());(self.lib/'operator.data').write_bytes(b'unknown')
        with self.assertRaises(ValueError):self.tx.restore()
        self.assertEqual((self.lib/'operator.data').read_bytes(),b'unknown')
        self.assertEqual((self.lib/'VERSION').read_bytes(),b'new-version\n')

    def test_damaged_private_copy_refuses_before_restoring_any_target(self):
        self.tx.install(payload());before=ops.tree(self.lib)
        (self.tx.path/'prior-library/VERSION').write_bytes(b'changed')
        with self.assertRaises(ValueError):self.tx.restore()
        self.assertEqual(ops.tree(self.lib),before)

    def test_symlink_prior_object_rejected_without_snapshot_or_target_write(self):
        (self.lib/'external').symlink_to(self.helper)
        with self.assertRaises(ValueError):self.tx.install(payload())
        self.assertFalse(self.tx.path.exists());self.assertEqual(common.read_regular(self.helper),self.hbefore)

    def test_existing_stage_and_replayed_install_never_overwrite_original(self):
        self.tx.stage.mkdir()
        with self.assertRaises(ValueError):self.tx.install(payload())
        self.assert_original();self.tx.stage.rmdir();self.tx.install(payload())
        with self.assertRaises(ValueError):self.tx.install(payload())

    def test_tool_failure_before_publish_retains_prior_and_complete_private_copy(self):
        with patch.object(ops,'tool_probe',side_effect=RuntimeError('dependency unavailable')),self.assertRaises(RuntimeError):
            self.tx.install(payload())
        self.assert_original();self.assertTrue(self.tx.state['copy_complete']);self.assertFalse(self.tx.state['publish_intent'])

    def test_incomplete_private_copy_cannot_authorize_restore(self):
        with patch.object(ops,'copy_tree',side_effect=OSError('interrupted copy')),self.assertRaises(OSError):self.tx.install(payload())
        with self.assertRaises(ValueError):self.tx.restore()
        self.assert_original()


class BoundaryTests(unittest.TestCase):
    def test_bad_payload_paths_hashes_missing_modules_and_syntax_refuse(self):
        for mode in ('path','hash','missing','syntax'):
            p=payload()
            if mode=='path':p['files']['../VERSION']=p['files']['VERSION']
            if mode=='hash':p['sha256']['VERSION']='0'*64
            if mode=='missing':del p['files']['woowbackup/cli.py']
            if mode=='syntax':p['files']['woowbackup/cli.py']=base64.b64encode(b'def broken(').decode()
            with self.subTest(mode=mode),self.assertRaises((ValueError,SyntaxError)):ops.decode_payload(p)

    def test_production_lock_order_contention_releases_start_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);fd=os.open(root/'engine.lock',os.O_RDWR|os.O_CREAT,0o600)
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    with ops.engine_locks(root):self.fail('engine lock was held')
                start=os.open(root/'jobs.lock',os.O_RDWR)
                try:fcntl.flock(start,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(start)
            finally:os.close(fd)

    def test_real_frozen_payload_exact_installer_engine_helper_and_version_selection(self):
        source=Path('/tmp/parity-focus-final-gate2-20261127')
        p=host.payload(source);files,helper=ops.decode_payload(p)
        expected={str(x.relative_to(source/'backup-engine')) for x in (source/'backup-engine/woowbackup').rglob('*.py')
                  if '__pycache__' not in x.parts}|{'VERSION'}
        self.assertEqual(set(files),expected)
        self.assertEqual(helper,(source/'backup-engine/woowtech-cockpit-backup').read_bytes())
        self.assertEqual(files['VERSION'],(source/'VERSION').read_bytes())

    def test_lease_binds_manifest_driver_image_case_phase_protected_capture_bounds_and_time(self):
        p=payload();image={'name':NAME,'images_ready':True,'owned_images':list(host.plan.ARCHIVES)}
        lease={'granted':True,'device':host.plan.DEVICE,'case':'n8n-instance-source','phases':list(host.PHASES),
               'driver_commit':'a'*40,'source_commit':ops.FROZEN,'name':NAME,'source_manifest_sha256':host.manifest_sha(p),
               'bounds':host.BOUNDS,'protected_capture_sha256':host.plan.sha(host.REPO/'snippets'/host.plan.AREA/'protected-baselines-readonly.json'),
               'not_before_utc':datetime.fromtimestamp(900,timezone.utc).isoformat(),
               'expires_utc':datetime.fromtimestamp(2000,timezone.utc).isoformat()}
        self.assertEqual(host.validate(lease,'source-install',driver='a'*40,source_payload=p,image_receipt=image,now=1000),2000)
        for key,value in (('driver_commit','b'*40),('source_manifest_sha256','b'*64),('bounds',{}),('name','other'),
                          ('protected_capture_sha256','b'*64),('phases',['source-recover']),('granted',False)):
            with self.subTest(key=key),self.assertRaises(ValueError):
                host.validate(dict(lease,**{key:value}),'source-install',driver='a'*40,source_payload=p,image_receipt=image,now=1000)
        with self.assertRaises(ValueError):host.validate(lease,'source-install',driver='a'*40,source_payload=p,image_receipt=image,now=800)

    def test_default_offline_never_imports_transport_or_builds_device_request(self):
        with patch.object(host,'invoke',side_effect=AssertionError('no device')),patch.object(host,'payload',side_effect=AssertionError('no payload')),redirect_stdout(io.StringIO()):
            self.assertEqual(host.main([]),0)

    def test_probe_commands_only_existing_versions_and_isolated_bytecode_free_imports(self):
        calls=[]
        def invoke(argv,**kwargs):calls.append((argv,kwargs));return type('Result',(),{'returncode':0})()
        with patch.object(ops.subprocess,'run',side_effect=invoke):ops.tool_probe(Path('/fixed/candidate'))
        self.assertEqual([x[0] for x in calls[:3]],[['age','--version'],['age-keygen','--version'],['zstd','--version']])
        self.assertEqual(calls[3][0][:4],['python3','-B','-I','-c'])
        code=calls[3][0][4]
        self.assertLess(code.index('sys.pycache_prefix='),code.index('from woowbackup'))
        self.assertTrue(all(x[1]['timeout']==30 for x in calls))


class PG16SourceTests(unittest.TestCase):
    def reference(self):
        return json.loads((host.REPO/'snippets'/host.plan.AREA/'pg16-role-query-reference.json').read_text())

    def test_exact_role_queries_match_actual_successful_pinned_pg16_helper(self):
        ref=self.reference()
        raw=subprocess.check_output(['git','show',ref['reference_commit']+':'+ref['helper_path']],cwd=host.REPO)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),ref['helper_sha256'])
        remote=next(ast.literal_eval(n.value) for n in ast.parse(raw).body if isinstance(n,ast.Assign)
                    and any(isinstance(t,ast.Name) and t.id=='REMOTE' for t in n.targets))
        fn=next(n for n in ast.parse(remote).body if isinstance(n,ast.FunctionDef) and n.name=='snapshot')
        queries={n.targets[0].id:ast.literal_eval(n.value.args[2]) for n in fn.body if isinstance(n,ast.Assign)
                 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('roles','settings')}
        self.assertEqual(common.ROLE_ROWS_SQL,queries['roles']);self.assertEqual(common.ROLE_SETTINGS_SQL,queries['settings'])
        self.assertEqual(ref['existing_real_pg_evidence']['checks'],87)
        self.assertTrue(ref['existing_real_pg_evidence']['all_pass'])

    def test_each_global_role_database_setting_changes_snapshot_hash(self):
        rows=[['app','db',['search_path=public']],['app',None,['statement_timeout=5s']],
              [None,'db',['lock_timeout=1s']],[None,None,['work_mem=4MB']]]
        with patch.object(common,'sql',side_effect=lambda db,q:rows if q==common.ROLE_SETTINGS_SQL else ['role-facts']):
            original=common.role_state()
            for i in range(len(rows)):
                old=rows[i];rows[i]=[old[0],old[1],['changed=1']]
                self.assertNotEqual(common.role_state()['role_settings'],original['role_settings']);rows[i]=old
        self.assertNotIn('rolconfig',common.ROLE_ROWS_SQL)
        self.assertFalse(any('rolconfig' in q for q in host.plan.case_sql(NAME).values()))
        self.assertNotIn('WHERE',common.ROLE_SETTINGS_SQL.upper())
        self.assertEqual(common.ROLE_SETTINGS_SQL.count('LEFT JOIN'),2)

    def test_every_standalone_product_import_disables_cache_before_import(self):
        for code in (host.program(),host.plan.MANIFEST_PROBE,host.plan.ENDPOINT_PROBE):
            self.assertLess(code.index('sys.dont_write_bytecode'),code.index('from woowbackup') if 'from woowbackup' in code else len(code))
            self.assertIn("sys.pycache_prefix=",code.replace(' ',''))


if __name__=='__main__':unittest.main()
