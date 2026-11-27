"""Offline boundaries of the leased original LiteLLM instance controller."""
import importlib.util
import base64
import copy
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CatalogRecovery(unittest.TestCase):
    def test_raw_original_and_permissions_return_after_instance_cas(self):
        ops = load('focus_litellm_instance_acceptance_ops')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root/'litellm.json'
            original = b'{ "schema": 1, "id": "litellm" }\n'
            path.write_bytes(original); path.chmod(0o640)
            store = ops.Store('woowbk_focus_litellm_012345abcdef', parent=root/'private', create=True)
            store.capture([str(path)])
            store.authorize(str(path), b'{"id":"litellm","postgres":[{"scope":"instance"}]}\n')
            path.write_bytes(b'{"id":"litellm","postgres":[{"scope":"instance"}]}\n')
            store.restore([str(path)])
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_foreign_catalog_edit_refuses_restoration_without_overwrite(self):
        ops = load('focus_litellm_instance_acceptance_ops')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root/'litellm.json'; path.write_bytes(b'original')
            store = ops.Store('woowbk_focus_litellm_012345abcdef', parent=root/'private', create=True)
            store.capture([str(path)]); store.authorize(str(path), b'owned-instance')
            path.write_bytes(b'foreign');
            with self.assertRaisesRegex(ValueError, 'outside'):
                store.restore([str(path)])
            self.assertEqual(path.read_bytes(), b'foreign')

    def test_initially_absent_catalog_removed_only_at_owned_hash(self):
        ops = load('focus_litellm_instance_acceptance_ops')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root/'litellm.json'
            store = ops.Store('woowbk_focus_litellm_012345abcdef', parent=root/'private', create=True)
            store.capture([str(path)])
            store.authorize(str(path), b'owned'); path.write_bytes(b'owned')
            store.restore([str(path)]); self.assertFalse(path.exists())

    def test_foreign_broken_symlink_refuses_without_replacing_it(self):
        ops = load('focus_litellm_instance_acceptance_ops')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); path=root/'litellm.json'
            store=ops.Store('woowbk_focus_litellm_012345abcdef',parent=root/'private',create=True)
            store.capture([str(path)]); path.symlink_to(root/'missing')
            with self.assertRaises(OSError): store.restore([str(path)])
            self.assertTrue(path.is_symlink())


class InstanceContract(unittest.TestCase):
    def test_changes_only_scope_and_maintenance_database_input(self):
        p = load('focus_litellm_instance_acceptance')
        entry = {'id':'litellm','owner':'appowner','adapter':'quadlet-postgres',
                 'postgres':[{'id':'main','container':'litellm-postgres','unit':'litellm-postgres.service',
                              'database':'litellm','user':'litellm','data_volume':'litellm-pgdata'}],
                 'secrets':[{'name':'litellm-salt-key'}]}
        original = json.loads(json.dumps(entry)); changed = p.instance_entry(entry)
        self.assertEqual(entry, original)
        self.assertEqual(changed['postgres'][0]['scope'], 'instance')
        self.assertNotIn('database', changed['postgres'][0])
        changed['postgres'][0].pop('scope'); changed['postgres'][0]['database']='litellm'
        self.assertEqual(changed, original)

    def test_full_failure_proof_rejects_stale_roles_outsiders_app_or_missing_hook(self):
        p=load('focus_litellm_instance_acceptance')
        snapshot={'roles':'current-password-hash','members':[],'settings':[],'metadata':['current-owner'],
                  'database_names':['postgres','litellm','outside'],
                  'databases':{'litellm':{'digest':'later-app-row'},'outside':{'digest':'later-outside-row'}}}
        job={'state':'rolled-back','result':{'rolled_back':True,'safety_backup_id':'owned'}}
        params=dict(hook=True,witness=True,before=snapshot,after=copy.deepcopy(snapshot),full_safety=True,digest_log=True)
        self.assertTrue(p.rollback_proven(job,**params))
        for key in ('roles','databases'):
            after=copy.deepcopy(snapshot)
            if key=='roles': after[key]='conversion-time-password'
            else: after[key]['outside']['digest']='conversion-time-row'
            self.assertFalse(p.rollback_proven(job,**dict(params,after=after)))
        after=copy.deepcopy(snapshot);after['databases']['litellm']['digest']='HA-without-later-app-row'
        self.assertFalse(p.rollback_proven(job,**dict(params,after=after)))
        for key in ('hook','witness','full_safety','digest_log'):
            self.assertFalse(p.rollback_proven(job,**dict(params,**{key:False})))

    def test_real_catalog_validation_normalizes_instance_maintenance_separately_from_app(self):
        sys.path.insert(0,str(HERE.parents[2]/'backup-engine'))
        from woowbackup import catalog
        from woowbackup.paths import Paths
        p=load('focus_litellm_instance_acceptance')
        source={'schema':1,'id':'litellm','name':'LiteLLM','owner':'appowner','adapter':'quadlet-postgres',
            'quadlet':{'files':list(p.QFILES)},'units':list(p.UNITS),'writer_units':['litellm.service'],
            'postgres':[{'id':'main','container':'litellm-postgres','unit':'litellm-postgres.service',
                         'database':'litellm','user':'litellm','data_volume':'litellm-pgdata'}],
            'volumes':[],'secrets':[{'name':n} for n in p.SECRETS],
            'config_files':[{'path':'.config/litellm/config.yaml','mode':'0644'},
                            {'path':'.config/litellm/litellm.env','mode':'0600'}],
            'health':[{'type':'http','url':'http://127.0.0.1:4000/health/readiness',
                       'expect_status':200,'timeout_seconds':600}],
            'verify':[{'id':'db-main','type':'postgres-digest','postgres':'main'}]}
        normalized=catalog.validate_entry(p.instance_entry(source),paths=Paths(),
            user_lookup=lambda _:SimpleNamespace(pw_name='appowner',pw_uid=1019,pw_gid=1019,pw_dir='/home/appowner'))
        self.assertEqual(normalized.postgres[0]['scope'],'instance')
        self.assertEqual(normalized.postgres[0]['database'],'postgres')
        self.assertEqual(source['postgres'][0]['database'],'litellm')
        self.assertEqual(normalized.verify[0]['type'],'postgres-digest')


def lease(p, now=1800000000):
    return {'granted':True,'case':'litellm-instance-original','device':p.DEVICE,'phases':list(p.PHASES),
            'driver_commit':'a'*40,'source_commit':p.FROZEN_PRODUCT,'name':'woowbk_focus_litellm_012345abcdef',
            'fixture_sha256':p.FIXTURE_SHA,'derivation_sha256':p.DERIVATION_SHA,'package_commit':p.PACKAGE_COMMIT,
            'baseline_sha256':'b'*64,'baseline_policy':'require-litellm-absent','image_policy':'retain-for-case',
            'expires_utc':datetime.fromtimestamp(now+3600,timezone.utc).isoformat()}


class LeaseAndIntentTests(unittest.TestCase):
    def test_exact_image_and_flow_lease_bindings_and_expiry(self):
        m=load('focus_litellm_instance_acceptance_run'); value=lease(m.plan)
        for phase in m.plan.PHASES:
            m.validate_lease(value,phase,now=1800000000,driver_commit='a'*40,source_commit=m.plan.FROZEN_PRODUCT)
        for key,bad in (('granted',False),('device','woowbk-dev-c'),('driver_commit','b'*40),
                        ('source_commit','c'*40),('derivation_sha256','d'*64),('package_commit','e'*40),
                        ('baseline_policy','adopt-existing-app'),('name','litellm'),('phases',[])):
            with self.subTest(key=key),self.assertRaises(ValueError):
                m.validate_lease(dict(value,**{key:bad}),'images',now=1800000000,driver_commit='a'*40,source_commit=m.plan.FROZEN_PRODUCT)
        with self.assertRaises(ValueError):
            m.validate_lease(value,'images',now=1800004000,driver_commit='a'*40,source_commit=m.plan.FROZEN_PRODUCT)

    def test_default_has_no_device_or_credential_access(self):
        m=load('focus_litellm_instance_acceptance_run')
        with mock.patch.object(m,'load_saved',side_effect=AssertionError('device/credential boundary')),redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main([]),0)
        self.assertTrue(json.loads(out.getvalue())['preparation_only'])

    def test_lost_start_reply_adopts_journal_job_without_redispatch_and_keeps_safety(self):
        m=load('focus_litellm_instance_acceptance_run')
        now=1800000000; jid='j20261127T120000Z-01234567'; bid='20261127T120000Z-12345678'
        class Transport:
            def __init__(self): self.starts=0;self.requests={}
            def helper(self,command,request,**_kwargs):
                if command=='backup-start':
                    self.starts+=1;self.requests[request['request_id']]=jid
                    raise TimeoutError('transport reply lost after engine accepted job')
                if command=='job-status':
                    return 0,{'ok':True,'job':{'id':jid,'type':'backup','state':'succeeded','result':{'backup_id':bid}}}
                raise AssertionError(command)
            def root(self,*_args,input,**_kwargs):
                q=json.loads(input)
                if q['op']=='intent':value=self.requests.get(q['request_id'])
                elif q['op']=='job_quiescent':value=True
                else:raise AssertionError(q['op'])
                return SimpleNamespace(returncode=0,stdout=json.dumps(value).encode())
        with tempfile.TemporaryDirectory() as directory,redirect_stdout(io.StringIO()):
            path=Path(directory)/'receipt.json'; h=Transport()
            c=m.Controller(SimpleNamespace(receipt=path,source='unused'),lease(m.plan),SimpleNamespace(drv=h),clock=lambda:now)
            with self.assertRaises(TimeoutError): c.job('backup-start',{'apps':['litellm']},'full-safety')
            self.assertIsNone(json.loads(path.read_text())['pending'].get('job_id'))
            # A new controller process recovers the existing durable intent.
            recovered=m.Controller(SimpleNamespace(receipt=path,source='unused'),lease(m.plan),SimpleNamespace(drv=h),clock=lambda:now)
            recovered.settle()
            self.assertEqual(h.starts,1)
            self.assertEqual(recovered.r['full_safety'],bid)
            self.assertEqual(recovered.r['created_backups'],[bid])
            self.assertIsNone(recovered.r['pending'])
            self.assertEqual(path.stat().st_mode&0o777,0o600)

    def test_unknown_start_cannot_be_replayed_or_cleaned(self):
        m=load('focus_litellm_instance_acceptance_run')
        h=SimpleNamespace(root=lambda *_a,**_kw:SimpleNamespace(returncode=0,stdout=b'null'))
        with tempfile.TemporaryDirectory() as directory:
            c=m.Controller(SimpleNamespace(receipt=Path(directory)/'receipt',source='unused'),lease(m.plan),SimpleNamespace(drv=h))
            c.r['pending']={'request_id':'case-start','tag':'full-safety'};c.save()
            with self.assertRaisesRegex(RuntimeError,'uncertain'): c.settle()
            self.assertIsNotNone(json.loads(c.path.read_text())['pending'])

    def test_image_recovery_adopts_lost_removal_reply_without_touching_base_or_apps(self):
        m=load('focus_litellm_instance_acceptance_run'); image='c'*64; base='a'*64
        before={k:{} for k in ('catalogs','files','volumes','secrets','containers','external_containers','networks','units')}
        before.update(containers={'original-eight':'durable-id'},external_containers={'original-eight':'durable-id'},
            running=['original-eight'],timer={'ActiveState':'inactive'},package=False,config_directory=False,
            active_jobs=[],images=[base],image_refs={'original:tag':base})
        class Transport:
            def __init__(self):
                self.state=copy.deepcopy(before);self.state['images'].append(image)
                self.state['image_refs'][m.plan.APP_TAG]=image;self.removals=0;self.context_cleaned=False
            def root(self,*_args,input,**_kwargs):
                q=json.loads(input)
                if q['op']=='inventory':value=self.state
                elif q['op']=='receipt':value={'image_build':{'process':{'terminal':True},
                    'owned_images':[image],'unknown_images':[],'iid':image}}
                elif q['op']=='image_context_cleanup':self.context_cleaned=True;value=True
                else:raise AssertionError(q['op'])
                return SimpleNamespace(returncode=0,stdout=json.dumps(value).encode())
            def owner(self,*argv,**_kwargs):
                assert argv==('podman','image','rm','--no-prune','sha256:'+image)
                self.removals+=1;self.state['images'].remove(image);self.state['image_refs'].pop(m.plan.APP_TAG)
                raise TimeoutError('lost image removal reply after successful owned deletion')
        with tempfile.TemporaryDirectory() as directory,redirect_stdout(io.StringIO()):
            args=SimpleNamespace(receipt=Path(directory)/'private.json',source='unused'); h=Transport()
            c=m.Controller(args,lease(m.plan),SimpleNamespace(drv=h))
            c.r.update(before=before,owned_images=[image],image_intent=True);c.save()
            with self.assertRaises(TimeoutError):c.images_recover()
            recovered=m.Controller(args,lease(m.plan),SimpleNamespace(drv=h));recovered.images_recover()
            self.assertEqual(h.removals,1);self.assertTrue(h.context_cleaned)
            self.assertTrue(recovered.r['images_recovered'])
            self.assertEqual(h.state,before)


class RealProcessGroupTests(unittest.TestCase):
    def test_root_or_ambiguous_builder_identity_is_rejected_before_spawn(self):
        m=load('focus_litellm_instance_acceptance_supervisor')
        with tempfile.TemporaryDirectory() as directory:
            with (Path(directory)/'private.log').open('wb') as log, \
                    mock.patch.object(m.subprocess,'Popen',side_effect=AssertionError('must not spawn')):
                for uid in (0,True,None):
                    with self.subTest(uid=uid),self.assertRaises(ValueError):
                        m.supervise(['unused'],log,identity={'uid':uid,'gid':1019})

    def test_timeout_terminates_and_waits_real_child_and_grandchild_group(self):
        m=load('focus_litellm_instance_acceptance_supervisor')
        with tempfile.TemporaryDirectory() as directory:
            pidfile=Path(directory)/'pids'
            child=("import os,signal,subprocess,sys,time;from pathlib import Path;"
                   "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                   "p=subprocess.Popen([sys.executable,'-c','import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)']);"
                   "Path(sys.argv[1]).write_text(str(os.getpid())+' '+str(p.pid));time.sleep(30)")
            records=[]
            with (Path(directory)/'private.log').open('wb') as log:
                result=m.supervise([sys.executable,'-I','-c',child,str(pidfile)],log,timeout=0.7,grace=0.1,checkpoint=records.append)
            self.assertTrue(pidfile.exists(),'the grandchild actually started')
            self.assertTrue(result['timed_out']);self.assertFalse(result['ok']);self.assertTrue(result['terminal'])
            self.assertEqual(m.group_members(records[0]['pgid']),[])
            self.assertTrue(records[-1]['terminal'])

    def test_success_and_resource_abort_both_wait_own_process_group(self):
        m=load('focus_litellm_instance_acceptance_supervisor')
        with tempfile.TemporaryDirectory() as directory:
            with (Path(directory)/'private.log').open('wb') as log:
                done=m.supervise([sys.executable,'-I','-c','pass'],log,timeout=2,grace=0.1)
                abort=m.supervise([sys.executable,'-I','-c','import time;time.sleep(30)'],log,
                                  timeout=2,grace=0.1,guard=lambda:False)
            self.assertTrue(done['ok']);self.assertTrue(done['terminal'])
            self.assertTrue(abort['resource_lost']);self.assertFalse(abort['ok']);self.assertTrue(abort['terminal'])

    def test_successful_parent_with_live_child_is_not_a_success_and_child_is_settled(self):
        m=load('focus_litellm_instance_acceptance_supervisor'); records=[]
        child="import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])"
        with tempfile.TemporaryDirectory() as directory:
            with (Path(directory)/'private.log').open('wb') as log:
                result=m.supervise([sys.executable,'-I','-c',child],log,timeout=2,grace=0.1,checkpoint=records.append)
        self.assertFalse(result['ok']);self.assertTrue(result['orphaned']);self.assertTrue(result['terminal'])
        self.assertEqual(m.group_members(records[0]['pgid']),[])


class ProgramBindings(unittest.TestCase):
    def test_saved_driver_derivation_source_and_compiled_device_program_are_bound(self):
        m=load('focus_litellm_instance_acceptance_run'); saved=m.load_saved()
        self.assertEqual(m.plan.sha(HERE/'litellm_full_flow.py'),m.plan.SAVED_DRIVER_SHA)
        self.assertEqual(hashlib.sha256(saved.DERIVE.encode()).hexdigest(),m.plan.DERIVATION_SHA)
        self.assertEqual(saved.DERIVE.splitlines()[0],'FROM sha256:'+m.plan.APP_BASE)
        program=(HERE/'focus_litellm_instance_acceptance_supervisor.py').read_text()+'\n'+(
            HERE/'focus_litellm_instance_acceptance_ops.py').read_text()
        compile(program,'fixed-device-program','exec')
        for name in ('MANIFEST_PROBE','ENDPOINT_PROBE','API_WITNESS'):
            compile(getattr(m.plan,name),name,'exec')

    def test_transient_or_foreign_id_changes_are_a_failure_with_raw_receipts_preserved(self):
        m=load('focus_litellm_instance_acceptance_run')
        before={k:{} for k in ('catalogs','files','volumes','secrets','containers','external_containers','networks','units')}
        before.update(containers={'original8':'exact-id'},running=['original8'],timer={'ActiveState':'inactive'},
                      package=False,config_directory=False,active_jobs=[],images=['base'],image_refs={'base:tag':'base'})
        current=copy.deepcopy(before);current['containers']['headscale-transient']='later-id'
        self.assertFalse(m.unchanged(current,before))
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'raw-before-after.json';m.save_receipt(path,{'before':before,'after':current})
            self.assertEqual(json.loads(path.read_text()),{'before':before,'after':current})

    def test_package_cleanup_handles_quadlet_removal_and_refuses_a_foreign_replacement(self):
        m=load('focus_litellm_instance_acceptance_ops'); owned='c'*64;foreign='d'*64;original='e'*64
        for phase in ('already-removed','still-owned','foreign-replacement'):
            state={'hermes-agent':original}; removals=[]
            if phase=='still-owned':state['litellm']=owned
            if phase=='foreign-replacement':state['litellm']=foreign
            def owner(*args,**_kwargs):
                if args[:3]==('podman','container','exists'):
                    return SimpleNamespace(returncode=0 if args[3] in state or args[3] in state.values() else 1)
                if args[:3]==('podman','inspect','--format'):
                    return SimpleNamespace(stdout=state[args[-1]].encode())
                if args[:2]==('podman','rm'):
                    removals.append(args[2]);state.pop('litellm');return SimpleNamespace(returncode=0)
                raise AssertionError(args)
            with self.subTest(phase=phase),mock.patch.object(m,'owner',owner):
                if phase=='foreign-replacement':
                    with self.assertRaisesRegex(ValueError,'replaced'):m.remove_owned_containers({'litellm':owned})
                else:m.remove_owned_containers({'litellm':owned})
                self.assertEqual(state.get('hermes-agent'),original)
                self.assertEqual(removals,[owned] if phase=='still-owned' else [])


if __name__ == '__main__':
    unittest.main()
