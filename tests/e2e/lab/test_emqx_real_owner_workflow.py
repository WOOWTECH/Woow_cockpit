"""Code-only same-target foundation tests. No broker, real archive or lab IO.

Actual issuance/class/catalog/adapter factories execute on generated owner files.
Product packaging/restore IO is replaced at the explicit orchestration boundary;
these tests are NOT a restore/rollback or commercial acceptance receipt.
"""
import copy
import io
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

import emqx_real_owner_workflow as m
import emqx_adapter_owner as owner
import emqx_owner_fixture_files as files
from test_emqx_owner_fixture_files import GeneratedRunner, BASE, ACL, CSV
from woowbackup import catalog, flows
from woowbackup.errors import BackupError
from woowbackup.paths import Paths
from woowbackup.adapters.quadlet_postgres import QuadletPostgresAdapter

JOB='j20261122T000000Z-12345678'


class FoundationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        generated=GeneratedRunner(self.root)
        # Actual runner CLASS, with only generated process/file IO substituted.
        self.runner=owner.LabOwnerRunner.__new__(owner.LabOwnerRunner)
        self.runner.owner='appowner';self.runner.home=str(self.root)
        self.runner.uid=os.geteuid();self.runner.gid=os.getegid()
        for method in ('run','write_file','stat_files','systemctl','podman'):
            setattr(self.runner,method,getattr(generated,method))
        self.runner.remove_file=lambda rel:(self.root/rel).unlink(missing_ok=True)
        self.generated=generated
        with patch.object(owner,'LabOwnerRunner',return_value=self.runner):
            self.provision=owner.OwnerProvision(m.IMAGE.removeprefix('sha256:'))
        self.fixture=self.provision.create(BASE,ACL,CSV,b'generated-dashboard-only')
        self.addCleanup(files.revoke,self.provision.file_capability)
        user=SimpleNamespace(pw_uid=self.runner.uid,pw_gid=self.runner.gid,pw_dir=str(self.root))
        lookup=patch.object(catalog.pwd,'getpwnam',return_value=user)
        lookup.start();self.addCleanup(lookup.stop)

    def context(self):return m.flow_context(self.provision,self.root,JOB)

    def test_logical_emqx_catalog_changes_only_id_and_uses_actual_scoped_adapter(self):
        before=copy.deepcopy(self.fixture.catalog())
        ctx,app,state=self.context()
        self.assertIsInstance(ctx,flows.FlowContext)
        self.assertEqual(set(ctx.catalog()),{'emqx'})
        expected=copy.deepcopy(before);expected['id']='emqx'
        self.assertEqual(app.raw,expected)
        self.assertEqual(self.fixture.catalog(),before)
        self.assertEqual(app.units,(self.fixture.unit,))
        self.assertEqual({v['name'] for v in app.volumes},set(self.fixture.volumes))
        self.assertEqual({s['name'] for s in app.secrets},{self.fixture.secret,self.fixture.dashboard_secret})
        adapter=ctx.adapter(app)
        self.assertIs(type(adapter),QuadletPostgresAdapter)
        self.assertIs(adapter.runner,self.runner)
        self.assertIs(adapter.app,app)
        self.assertEqual(adapter.job_id,JOB)
        self.assertEqual(ctx.paths,Paths(base=self.root/'engine'))
        self.assertIsNone(ctx.deps.sweep_temp)
        target=m.bound_target(self.provision,app)
        self.assertEqual(target.container,self.fixture.prefix)
        self.assertEqual((target.data_volume,target.log_volume),self.fixture.volumes)
        self.assertIn(self.fixture.secret,target.secrets[0])
        self.assertIn(self.fixture.dashboard_secret,target.secrets[1])
        self.assertNotIn('woowbk-emqx-fresh-',repr(vars(target)))

    def test_changed_resources_or_another_fixture_cannot_be_packaged(self):
        ctx,app,_=self.context()
        for key,value in (('units',['unrelated.service']),('volumes',[{'name':'unrelated','label':'x'}]),
                          ('secrets',[{'name':'unrelated'}]),('id',self.fixture.prefix)):
            raw=copy.deepcopy(app.raw);raw[key]=value
            # Immutable App is copied with mutated carried declarations to probe binding.
            from dataclasses import replace
            wrong=replace(app,raw=raw)
            with self.subTest(key=key), self.assertRaises(ValueError):ctx.adapter(wrong)
        with patch.object(flows,'_package') as package:
            with self.assertRaises(ValueError):
                m._package_same_target(ctx,app,self.provision,{'fresh-data':self.root/'wrong.tar'},self.root)
            package.assert_not_called()
        files.revoke(self.provision.file_capability)
        with self.assertRaises(ValueError):m.bound_target(self.provision,app)

    def test_missing_composite_observer_refuses_before_frame_reads_or_provision(self):
        class Unreadable:
            def read(self,*args):raise AssertionError('frame must remain unread')
        with patch.object(m,'OwnerProvision') as provision:
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m.run_real_framed_owner(Unreadable(),private_parent=self.root,
                    source_mode='--source-vendor-acl-sql-aliases')
            self.assertEqual(caught.exception.phase,'observer_dependency')
            provision.assert_not_called()
        for mode in ('--source','--x86-source','--source=/tmp/other'):
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m.run_real_framed_owner(Unreadable(),private_parent=self.root,source_mode=mode)
            self.assertEqual(caught.exception.phase,'profile')

    def test_product_package_boundary_uses_same_logical_catalog_and_fixture_volumes(self):
        ctx,app,_=self.context()
        volumes={name:self.root/(name+'.tar') for name in self.fixture.volumes}
        for path in volumes.values():path.write_bytes(b'generated-converted-volume-placeholder')
        def imported(adapter,where,**kwargs):
            self.assertIs(type(adapter),QuadletPostgresAdapter)
            self.assertIs(adapter.runner,self.runner)
            self.assertEqual(adapter.app.raw,m._logical_raw(self.fixture))
            self.assertEqual(kwargs,{'volumes':volumes})
            self.assertEqual(where,self.root/'package/apps/emqx')
            return {'id':'emqx','volumes':[{'name':v} for v in volumes]},[]
        def packaged(context,apps,staging,**kwargs):
            self.assertIs(context,ctx);self.assertEqual(apps,[app])
            self.assertEqual(staging,self.root/'package')
            self.assertEqual(kwargs['manifest_apps'][0]['id'],'emqx')
            return {'backup_id':'generated-private-product-package'}
        with patch.object(QuadletPostgresAdapter,'import_manifest',autospec=True,side_effect=imported), \
             patch.object(flows,'_package',side_effect=packaged) as product:
            result=m._package_same_target(ctx,app,self.provision,volumes,self.root)
        self.assertEqual(result,'generated-private-product-package')
        product.assert_called_once()

    def test_restore_automatic_rollback_and_restart_call_same_product_context_and_cleanup_dropin(self):
        ctx,app,state=self.context()
        (self.root/'.config/systemd/user').mkdir(parents=True)
        calls=[]
        def restore(context,request):
            self.assertIs(context,ctx)
            self.assertEqual(request,{'backup_id':'generated-private-package','apps':['emqx'],
                                      'accept_unauthenticated':True})
            calls.append('restore')
            if len(calls)==1:return {'changed':True,'rolled_back':False}
            ctx.adapter(app).imported_hook()
            marker=self.root/'.config'/self.fixture.prefix/'fail-once'
            self.assertTrue(marker.is_file())
            marker.unlink()  # generated service boundary consumes startup failure
            raise flows.RolledBack(BackupError('job-failed','generated startup failure'),{'rolled_back':True})
        with patch.object(flows,'run_restore',side_effect=restore), \
             patch.object(m,'_ready') as ready:
            m._restore_and_rollback(ctx,app,self.provision,'generated-private-package',state)
        self.assertEqual(calls,['restore','restore'])
        self.assertEqual(ready.call_count,3)
        self.assertTrue(state['injected']);self.assertFalse(state['armed'])
        self.assertFalse((self.root/'.config/systemd/user'/ (self.fixture.unit+'.d')).exists())
        self.assertIn(('systemctl',('restart','--',self.fixture.unit)),self.generated.calls)

    def test_restore_refusal_cannot_be_reported_as_rollback_success(self):
        ctx,app,state=self.context()
        with patch.object(flows,'run_restore',return_value={'changed':False}) as restore:
            with self.assertRaises(ValueError):
                m._restore_and_rollback(ctx,app,self.provision,'generated-private-package',state)
            restore.assert_called_once()
        self.assertFalse(state['injected'])

    def test_candidate_budget_is_bounded_and_rejects_invalid_accounting(self):
        budget=m.CandidateBudget()
        budget.wrote(2*1024**3)
        self.assertEqual(budget.budget(),0)
        with self.assertRaises(ValueError):budget.wrote(1)
        with self.assertRaises(ValueError):m.CandidateBudget().wrote(-1)

    def test_private_alias_does_not_relax_public_catalog_namespace_guard(self):
        # Public install validation stays strict; alias exists only in this
        # private context after the original fixture was fully validated.
        with self.assertRaises(BackupError):
            catalog.validate_entry(m._logical_raw(self.fixture),paths=Paths(base=self.root/'engine'))
        ctx,app,_=self.context()
        self.assertEqual(app.id,'emqx')
        self.assertEqual(app.config_files,tuple(self.fixture.catalog()['config_files']))

    def test_noncallable_observer_ack_refuses_before_mutation(self):
        import emqx_target_vendor_policy as policy
        with patch.object(policy,'fixture_vendor_observer',True,create=True), \
             patch.object(m,'OwnerProvision') as provision:
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m.run_real_framed_owner(io.BytesIO(b''),private_parent=self.root,
                    source_mode='--source-vendor-acl-sql-aliases')
            self.assertEqual(caught.exception.phase,'observer_dependency')
            provision.assert_not_called()

    def test_full_restore_budget_keeps_1800mib_minimum(self):
        for maximum,passes in ((str(1800*1024**2),True),(str(1800*1024**2-1),False),('max',False)):
            with patch.object(Path,'read_text',side_effect=['0',maximum]):
                if passes:m._full_restore_budget()
                else:
                    with self.assertRaises(ValueError):m._full_restore_budget()

    def test_fixture_with_persistent_broker_logging_refuses_before_source_use(self):
        import json
        doc={'Name':'/'+self.fixture.prefix,'Image':m.IMAGE,
             'HostConfig':{'NetworkMode':'none','PortBindings':{},'Memory':768*1024**2,
                           'NanoCpus':1000000000,'LogConfig':{'Type':'k8s-file'}},
             'Mounts':[{'Type':'volume','Name':name} for name in self.fixture.volumes]}
        with patch.object(self.runner,'podman',return_value=SimpleNamespace(
                returncode=0,stdout=json.dumps([doc]).encode())):
            with self.assertRaises(ValueError):m._inspect(self.provision)
        doc['HostConfig']['LogConfig']['Type']='none'
        with patch.object(self.runner,'podman',return_value=SimpleNamespace(
                returncode=0,stdout=json.dumps([doc]).encode())):
            self.assertEqual(m._inspect(self.provision)['Name'],'/'+self.fixture.prefix)

    def test_malformed_frame_does_not_create_or_cleanup_an_unstarted_fixture(self):
        # Only the as-yet-missing dependency lookup is replaced here; the actual
        # frame reader/realm checks execute before any observer/producer/build.
        with patch.object(m,'_composite_observer_factory',return_value=Mock()), \
             patch.object(m,'OwnerProvision',return_value=self.provision), \
             patch.object(Path,'read_text',side_effect=['0',str(4*1024**3)]), \
             patch('emqx_fresh_owner_workflow.socket.gethostname',return_value='woowbk-dev-d'), \
             patch.object(self.provision,'create') as create, \
             patch.object(self.provision,'cleanup') as cleanup:
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m.run_real_framed_owner(io.BytesIO(b'bad'),private_parent=self.root,
                    source_mode='--source-vendor-acl-sql-aliases')
            self.assertEqual(caught.exception.phase,'frame')
            create.assert_not_called();cleanup.assert_not_called()
