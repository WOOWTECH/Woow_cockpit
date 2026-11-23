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

    def test_fixed_composite_api_binding_and_invalid_modes_before_mutation(self):
        from emqx_target_fixture_policy import issued_fixture_observer
        self.assertIs(m._composite_observer_factory(),issued_fixture_observer)
        callback=m._composite_observer_factory()(self.provision)
        self.assertTrue(callable(callback))
        # Factory is lazy: actual issued observer will inspect under quiescence.
        for mode in ('--source','--x86-source','--source=/tmp/other'):
            with patch.object(m,'OwnerProvision') as provision:
                with self.assertRaises(m.RealOwnerRefused) as caught:
                    m.run_real_framed_owner(io.BytesIO(b''),private_parent=self.root,source_mode=mode)
                self.assertEqual(caught.exception.phase,'profile')
                provision.assert_not_called()

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

    def second_restore_refusal(self,second,*,ready=None,mqtt=None,restart=None,first=None):
        """Generated product outcomes only; returns the fixed refusal phase."""
        ctx,app,state=self.context()
        (self.root/'.config/systemd/user').mkdir(parents=True,exist_ok=True)
        calls=[]
        def restore(context,request):
            calls.append('restore')
            if len(calls)==1:
                if first is not None:raise first
                return {'changed':True,'rolled_back':False}
            ctx.adapter(app).imported_hook()
            (self.root/'.config'/self.fixture.prefix/'fail-once').unlink()
            return second(state)
        clients=self.clients() if mqtt is not None else None
        original=self.runner.systemctl
        def systemctl(*args,**kwargs):
            if args[:1]==('restart',) and restart is not None:raise restart
            return original(*args,**kwargs)
        with patch.object(flows,'run_restore',side_effect=restore), \
             patch.object(m,'_ready',side_effect=ready), \
             patch.object(m,'validate_source_mqtt',side_effect=mqtt), \
             patch.object(self.runner,'systemctl',side_effect=systemctl):
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m._restore_and_rollback(ctx,app,self.provision,'generated-private-package',state,clients=clients)
        self.assertIn(caught.exception.phase,m.PHASES)
        self.assertNotIn('generated-private',caught.exception.phase)
        self.assertFalse((self.root/'.config/systemd/user'/(self.fixture.unit+'.d')).exists())
        self.assertFalse(state['armed'])
        return caught.exception.phase

    def test_second_restore_outcomes_have_fixed_round_labels(self):
        def rolled(state,result=None,injected=True):
            state['injected']=injected
            raise flows.RolledBack(BackupError('job-failed','generated-private start'),result or {'rolled_back':True})
        def incomplete(text):
            def second(state):
                error=BackupError('job-failed','generated-private 「emqx」'+text+' backup generated-private-id')
                error.result={'changed':True,'rolled_back':False};raise error
            return second
        def refused(code):
            def second(state):
                error=BackupError(code,'generated-private refusal');error.result={'changed':False,'rolled_back':False}
                raise error
            return second
        cases=((lambda state:{'changed':True},'rollback_not_raised'),
               (lambda state:rolled(state,{'rolled_back':False}),'rollback_result'),
               (lambda state:rolled(state,injected=False),'rollback_result'),
               (incomplete('回復後健康檢查未通過'),'rollback_incomplete_health'),
               (incomplete('回復後資料與還原前不一致'),'rollback_incomplete_verify'),
               (incomplete('：無法啟動服務 generated.service'),'rollback_incomplete_start'),
               (incomplete('無法重新啟動服務 generated.service'),'rollback_incomplete_writers'),
               (incomplete('generated unknown problem'),'rollback_incomplete_other'),
               (refused('busy'),'rollback_error_busy'),(refused('wrong-key'),'rollback_error_wrong_key'),
               (lambda state:(_ for _ in ()).throw(OSError('generated-private')),'rollback_other'))
        for second,phase in cases:
            with self.subTest(phase=phase):
                self.assertEqual(self.second_restore_refusal(second),phase)

    def test_round_step_failures_and_prefixed_round_activity_labels(self):
        def rolled(state):
            raise flows.RolledBack(BackupError('job-failed','generated'),{'rolled_back':True})
        counts={'ready':0,'mqtt':0}
        def ready_at(n):
            def ready(provision):
                counts['ready']+=1
                if counts['ready']==n:raise ValueError('generated-private')
            return ready
        def mqtt_at(n):
            def mqtt(*args,**kwargs):
                counts['mqtt']+=1
                if counts['mqtt']==n:
                    m._mqtt_step('retained_one');m._mqtt_fail('exit_27')
            return mqtt
        for n,phase in ((1,'restore_ready'),(2,'rollback_ready'),(3,'restart_ready')):
            with self.subTest(phase=phase):
                counts['ready']=0
                self.assertEqual(self.second_restore_refusal(rolled,ready=ready_at(n)),phase)
        for n,phase in ((1,'mqtt_retained_one_exit_27'),(2,'rollback_mqtt_retained_one_exit_27'),
                        (3,'restart_mqtt_retained_one_exit_27')):
            with self.subTest(phase=phase):
                counts['mqtt']=0
                self.assertEqual(self.second_restore_refusal(rolled,mqtt=mqtt_at(n)),phase)
        self.assertEqual(self.second_restore_refusal(rolled,restart=ValueError('generated-private')),'restart')
        first=BackupError('busy','generated-private');first.result={'changed':False,'rolled_back':False}
        self.assertEqual(self.second_restore_refusal(rolled,first=first),'restore_error_busy')
        self.assertEqual(self.second_restore_refusal(
            rolled,first=flows.RolledBack(BackupError('job-failed','generated'),{'rolled_back':True})),'restore_rolled_back')

    def test_post_capture_refusal_names_fixed_collector_and_quiescence_stage(self):
        import emqx_post_restore_values as post
        current={'Id':'a'*64}
        def collector(stage,quiesce_state=None):
            def collect(**kwargs):
                if quiesce_state is not None:m._QUIESCE_STATE.set(quiesce_state)
                raise post.PostCaptureRefused(stage)
            return collect
        cases=((collector('exec'),'post_capture_exec'),(collector('decode'),'post_capture_decode'),
               (collector('quiesce_enter','enter_clients'),'post_capture_enter_clients'),
               (collector('quiesce_exit','exit_ticker'),'post_capture_exit_ticker'),
               (collector('quiesce_enter','generated-private'),'post_capture'),
               (ValueError('generated-private'),'post_capture'))
        for effect,phase in cases:
            with self.subTest(phase=phase), patch.object(m,'_inspect',return_value=current), \
                 patch.object(files,'_record',return_value=({'cid':'a'*64},self.provision)), \
                 patch.object(post,'collect_post_restore_values',side_effect=effect):
                with self.assertRaises(m.RealOwnerRefused) as caught:
                    m._post_activity_capture(self.provision,object())
                self.assertEqual(caught.exception.phase,phase)
                self.assertEqual(m._QUIESCE_STATE.get(),'none')
        for phase in ('rollback_post_capture_exec','restart_post_capture_enter_clients','post_capture_final'):
            self.assertIn(phase,m.PHASES)
        with self.assertRaises(m.RealOwnerRefused) as caught:m.final_private_receipt(object())
        self.assertEqual(caught.exception.phase,'post_capture_final')

    def test_ready_retries_runner_timeout_but_not_identity_refusal(self):
        calls=[]
        def podman(*args,**kwargs):
            calls.append(args)
            if len(calls)==1:raise BackupError('job-failed','generated-private timeout')
            return SimpleNamespace(returncode=0,stdout=b'Node is started')
        with patch.object(m,'_inspect') as inspect,patch.object(self.runner,'podman',side_effect=podman), \
             patch.object(m.time,'sleep'):
            m._ready(self.provision)
        self.assertEqual(len(calls),2);self.assertEqual(inspect.call_count,2)
        self.assertEqual(calls[0][:4],('exec',self.fixture.prefix,'emqx','ctl'))
        with patch.object(m,'_inspect',side_effect=ValueError('generated-isolation')), \
             patch.object(self.runner,'podman') as never:
            with self.assertRaises(ValueError):m._ready(self.provision)
        never.assert_not_called()

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
        import emqx_target_fixture_policy as policy
        with patch.object(policy,'issued_fixture_observer',True), \
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
            self.assertEqual(caught.exception.phase,'api_frame')
            create.assert_not_called();cleanup.assert_not_called()

    def client_values(self):
        return [b'b1-sensor',b'generated-sensor-password',b'b1-gateway',b'generated-gateway-password',
                b'generated-third',b'generated-third-password',b'b1/retained/one',b'generated-payload-one',
                b'b1/retained/two',b'\x00generated\xffpayload-two']

    def client_frame(self,values=None,mode=b'A'):
        import struct
        return m.CLIENT_MAGIC+mode+b''.join(struct.pack('!H',len(raw))+raw
            for raw in (self.client_values() if values is None else values))

    def api_values(self):
        return (b'admin',b'generated-admin-password',b'b1ops',b'generated-ops-password',b'generated-api-key',b'generated-api-secret')

    def api_frame(self):
        import struct
        return m.API_MAGIC+b'A'+b''.join(struct.pack('!H',len(v))+v for v in self.api_values())

    def owner_prefix(self):return self.api_frame()+self.client_frame()

    def clients(self):return m.read_source_clients(io.BytesIO(self.client_frame()),m.SOURCE_MODES[0])

    def test_fixed_client_prefix_is_bounded_private_profile_bound_and_leaves_cipher_frame(self):
        frame=self.client_frame()+b'unchanged-key-ciphertext-frame'
        stream=io.BytesIO(frame)
        clients=m.read_source_clients(stream,m.SOURCE_MODES[0])
        self.assertEqual(repr(clients),'<SourceClients private>')
        self.assertEqual(stream.read(),b'unchanged-key-ciphertext-frame')
        self.assertEqual([clients.fields[name] for name in m.CLIENT_FIELDS],self.client_values())
        self.assertNotIn(clients.fields['negative_password'],self.client_values())
        m.read_source_clients(io.BytesIO(self.client_frame(mode=b'B')),m.SOURCE_MODES[1])
        cases=[self.client_frame(mode=b'B'),self.client_frame()[:-1],m.CLIENT_MAGIC+b'A'+b'\x10\x01']
        for index,value in ((1,b'bad\n-P injected'),(6,b'b1/retained/#'),(8,b'b1/retained/one'),
                            (4,b'b1-gateway'),(4,b'lab'),(0,b'arbitrary-role'),(9,b'x'*4097)):
            values=self.client_values();values[index]=value;cases.append(self.client_frame(values))
        for raw in cases:
            with self.assertRaises(ValueError):m.read_source_clients(io.BytesIO(raw),m.SOURCE_MODES[0])

    def test_default_no_live_reads_actual_staged_frame_without_any_provision_or_capture(self):
        from dataclasses import replace
        import hashlib,struct
        from emqx_source_profiles import ARM_SQL_ALIASES
        cipher=b'generated-encrypted-ciphertext-only'
        key=b'generated-ram-key'
        framed=self.owner_prefix()+struct.pack('!I',len(key))+key+struct.pack('!Q',len(cipher))+cipher
        profile=replace(ARM_SQL_ALIASES,sha256=hashlib.sha256(cipher).hexdigest())
        with patch.object(m,'OwnerProvision',return_value=self.provision), \
             patch('emqx_fresh_owner_workflow.source_profile',return_value=profile), \
             patch.object(Path,'read_text',side_effect=['0',str(4*1024**3)]), \
             patch('emqx_fresh_owner_workflow.socket.gethostname',return_value='woowbk-dev-d'), \
             patch.object(self.provision,'create') as create, \
             patch.object(self.provision,'cleanup') as cleanup, \
             patch.object(m,'capture_owner_source') as capture, \
             patch.object(m,'_payload_history') as history, \
             patch.object(m,'build_captured_candidate') as build:
            receipt=m.run_real_framed_owner(io.BytesIO(framed),private_parent=self.root,source_mode=m.SOURCE_MODES[0])
        self.assertEqual(receipt['scope'],'sha-bound-ciphertext-and-client-frame-only')
        self.assertEqual(receipt['source_authentication'],'not-performed')
        for operation in (create,cleanup,capture,build,history):operation.assert_not_called()
        self.assertEqual(list(self.root.glob('emqx-framed-private-*')),[])

    def test_final_receipt_scans_exact_bytes_with_original_and_post_values(self):
        from emqx_private_boundary import Registry,SOURCES,PrivateFailure
        from emqx_persisted_values import PersistedValues
        from emqx_post_restore_values import PostRestoreValues
        from emqx_private_evidence import names_receipt,SOURCE_NAMES
        def scanner(secret,generations=('a','b','c')):
            prior=Registry()
            for source in SOURCES:prior.register(source,[b'original-private'] if source=='backup-key' else [])
            prior.seal()
            persisted=PersistedValues('a'*32,'target',{},[secret])
            return PostRestoreValues(prior,persisted,generations,())
        registry=scanner(b'post-operation-private')
        raw=m.final_private_receipt(registry)
        self.assertEqual(raw,names_receipt('restore','passed',SOURCE_NAMES))
        for secret in (b'original-private',b'post-operation-private'):
            with self.assertRaises(PrivateFailure):registry.scan(secret)
        with self.assertRaises(PrivateFailure):m.final_private_receipt(scanner('通過'.encode()))
        for registry in (object(),scanner(b'private',('a','b'))):
            with self.assertRaises(m.RealOwnerRefused):m.final_private_receipt(registry)

    def test_target_base_uses_canonical_pinned_fields_and_disabled_alternate_listeners(self):
        raw=m._target_base()
        for leaf in (b'node.name="emqx@127.0.0.1"',b'node.data_dir="/opt/emqx/data"',
            b'cluster.discovery_strategy=manual',b'cluster.proto_dist=inet_tcp',b'rpc.protocol=tcp',
            b'listeners.ssl.default.enable=false',b'listeners.ws.default.enable=false',
            b'listeners.wss.default.enable=false'):
            self.assertIn(leaf+b'\n',raw)
        self.assertNotIn(b'node.dist_proto',raw);self.assertNotIn(b'rpc.driver',raw)
        self.assertNotIn(b'dashboard.listeners.https',raw)

    def test_logging_opt_in_changes_only_exact_issued_unit_and_preserves_global_fixture(self):
        self.runner.read_file=lambda rel,**kwargs:(self.root/rel).read_bytes()
        original=self.fixture.container_unit()
        other=self.root/'.config/containers/systemd/unrelated.container';other.write_bytes(b'preserved')
        m._opt_in_private_unit(self.provision)
        path=self.root/'.config/containers/systemd'/(self.fixture.prefix+'.container')
        self.assertIn(b'--log-driver=none --image-volume=ignore',path.read_bytes())
        self.assertEqual(path.stat().st_mode&0o777,0o600)
        self.assertEqual(self.fixture.container_unit(),original)
        self.assertEqual(other.read_bytes(),b'preserved')
        self.assertIs(files._record(self.provision.file_capability)[1],self.provision)
        path.write_bytes(b'unexpected unit')
        with self.assertRaises(ValueError):m._opt_in_private_unit(self.provision)
        self.assertEqual(path.read_bytes(),b'unexpected unit')

    def mqtt_reply(self,code=0,suback=1,connack=0):
        return SimpleNamespace(returncode=code,stdout=(
            'Client generated received CONNACK ('+str(connack)+')\nSubscribed (mid: 1): '+str(suback)+'\n').encode(),stderr=b'')

    def test_source_mqtt_readiness_distinguishes_connack_allow_deny_wrong_password_and_retained(self):
        clients=self.clients()
        def call(provision,values,role,**kwargs):
            self.assertIs(provision,self.provision);self.assertIs(values,clients)
            if kwargs.get('wrong_password'):
                return self.mqtt_reply(code=134,connack=134)
            if kwargs.get('retained'):
                index=1 if kwargs['topic'].endswith('/one') else 2
                topic=clients.fields['retained_topic'+str(index)]
                payload=clients.fields['retained_payload'+str(index)]
                return SimpleNamespace(returncode=0,stdout=b'1:'+topic+b':'+payload.hex().encode()+b'\n',stderr=b'')
            return self.mqtt_reply(suback=135 if kwargs['topic']=='b1/secret/#' else 1)
        with patch.object(m,'_mqtt_private',side_effect=call) as mqtt:
            m.validate_source_mqtt(self.provision,clients)
            self.assertEqual(mqtt.call_count,7)
        # Timeout, absent reason, allowed denial and wrong retained flag refuse.
        for reply in (SimpleNamespace(returncode=27,stdout=b'',stderr=b'timed out'),
                      self.mqtt_reply(suback=135), self.mqtt_reply(connack=135)):
            with patch.object(m,'_mqtt_private',return_value=reply):
                with self.assertRaises(ValueError):m.validate_source_mqtt(self.provision,clients)
        def wrong_retain(*args,**kwargs):
            result=call(*args,**kwargs)
            if kwargs.get('retained'):result.stdout=b'0'+result.stdout[1:]
            return result
        with patch.object(m,'_mqtt_private',side_effect=wrong_retain):
            with self.assertRaises(ValueError):m.validate_source_mqtt(self.provision,clients)

    def test_imported_acl_mqtt_requires_sensor_puback_lab_control_gateway_retained_and_sensor_deny(self):
        clients=self.clients();clients.fields.update(lab_user=b'lab',lab_password=b'generated-lab-password')
        calls=[]
        def reply(provision,provided,role,**kw):
            self.assertIs(provided,clients);calls.append((role,kw))
            if kw.get('publish'):
                return SimpleNamespace(returncode=0,stdout=b'Client generated received CONNACK (0)\nClient generated received PUBACK (Mid: 1, RC:0)\n',stderr=b'')
            if kw.get('wrong_password'):return self.mqtt_reply(code=134,connack=134)
            if kw.get('retained'):
                i=1 if kw['topic'].endswith('/one') else 2
                return SimpleNamespace(returncode=0,stdout=b'1:'+clients.fields['retained_topic'+str(i)]+b':'+clients.fields['retained_payload'+str(i)].hex().encode()+b'\n',stderr=b'')
            return self.mqtt_reply(suback=135 if kw['topic']=='b1/secret/#' else 1)
        with patch.object(m,'_mqtt_private',side_effect=reply):
            m.validate_source_mqtt(self.provision,clients,target_mode=m.IMPORTED_MNESIA)
        self.assertEqual([(r,k['topic']) for r,k in calls if k.get('publish')],
            [('sensor','b1/sensor/b1-sensor/probe'),('lab','lab/owner-probe')])
        self.assertIn(('sensor',{'topic':'b1/secret/#'}),calls)
        for raw,code,reason in ((b'received CONNACK (0)',0,'puback_shape'),(b'received CONNACK (0)\nreceived PUBACK (Mid: 1, RC:135)',0,'puback_135'),
                (b'received CONNACK (0)\nreceived PUBACK (Mid: 2, RC:0)',0,'puback_mid'),
                (b'received CONNACK (0)\nreceived PUBACK (Mid: 1, RC:0)',27,'exit_27')):
            with patch.object(m,'_mqtt_private',return_value=SimpleNamespace(returncode=code,stdout=raw,stderr=b'')):
                with self.assertRaises(m.RealOwnerRefused) as caught:m._validate_phase_mqtt(self.provision,clients,m.IMPORTED_MNESIA)
                self.assertEqual(caught.exception.phase,'mqtt_publish_sensor_'+reason)

    def test_actual_owner_provisions_selected_policy_only_after_original_source_frame_and_history(self):
        from contextlib import contextmanager
        @contextmanager
        def staged(*args,**kw):
            self.assertEqual(kw['source_mode'],m.SOURCE_MODES[0])
            yield self.root/'generated-cipher',b'generated-key',self.root,object(),self.root
        for target_mode in (m.FILE_BASELINE,m.IMPORTED_MNESIA):
            seen=[]
            def create(base,acl,bootstrap,dashboard):
                seen.append((base,acl,bootstrap));raise ValueError('generated-stop-after-policy')
            with patch.object(m,'OwnerProvision',return_value=self.provision),patch.object(m,'_full_restore_budget'), \
                 patch.object(m,'staged_owner_frame',side_effect=staged),patch.object(m,'_payload_history',return_value=object()) as history, \
                 patch.object(self.provision,'create',side_effect=create),patch.object(self.provision,'cleanup'):
                with self.assertRaises(m.RealOwnerRefused) as caught:
                    m.run_real_framed_owner(io.BytesIO(self.owner_prefix()),private_parent=self.root,
                        source_mode=m.SOURCE_MODES[0],no_live=False,target_mode=target_mode)
            self.assertEqual(caught.exception.phase,'provision');history.assert_called_once()
            self.assertEqual(len(seen),1);base,acl,bootstrap=seen[0]
            if target_mode==m.IMPORTED_MNESIA:
                self.assertIn(b'type=built_in_database,enable=true',base)
                self.assertEqual(acl,b'{allow, {username, "lab"}, all, ["lab/#"]}.\n')
                self.assertNotIn(b'b1-',acl)
            else:
                self.assertNotIn(b'type=built_in_database',base);self.assertEqual(acl,m._target_acl())
            self.assertTrue(bootstrap.startswith(b'user_id,password,is_superuser\nlab,'))

    def test_publish_transport_private_config_fixed_topic_owned_cleanup_and_no_retain(self):
        import json
        from emqx_owned_client import LABEL
        from emqx_adapter_mqtt import CLIENT
        clients=self.clients();running={};configs=[];removed=[]
        def podman(*args,**kwargs):
            if args[:2]==('container','exists'):
                return SimpleNamespace(returncode=0 if any(args[2] in (n,d['Id']) for n,d in running.items()) else 1,stdout=b'',stderr=b'')
            if args[:2]==('container','inspect'):
                return SimpleNamespace(returncode=0,stdout=json.dumps([running[args[2]]]).encode(),stderr=b'')
            if args[0]=='rm':
                self.assertEqual(args[-1],'a'*64);removed.append(args[-1]);running.clear()
                return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
            name=args[args.index('--name')+1];label,nonce=args[args.index('--label')+1].split('=',1)
            self.assertEqual(label,LABEL)
            running[name]={'Id':'a'*64,'Name':name,'Image':CLIENT,'Config':{'Labels':{LABEL:nonce}}}
            path=Path(args[args.index('-v')+1].removesuffix(':/work:ro'))/'mosquitto_pub';configs.append(path)
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertIn(b'-P '+clients.fields['sensor_password'],path.read_bytes())
            self.assertIn(b'-t b1/sensor/b1-sensor/probe',path.read_bytes())
            self.assertNotIn(clients.fields['sensor_password'].decode(),repr(args))
            self.assertNotIn('b1/sensor/b1-sensor/probe',args)
            self.assertIn('--entrypoint=mosquitto_pub',args);self.assertIn('--image-volume=ignore',args)
            self.assertNotIn('-r',args);self.assertEqual(args[-3:],('-m','owner-probe','-d'))
            return SimpleNamespace(returncode=0,stdout=b'generated-private-ack',stderr=b'')
        with patch.object(self.runner,'podman',side_effect=podman),patch.object(m,'_ram_client_parent',return_value=self.root):
            m._mqtt_private(self.provision,clients,'sensor',topic='b1/sensor/b1-sensor/probe',publish=True)
        self.assertEqual(removed,['a'*64]);self.assertTrue(all(not p.exists() for p in configs))
        for kw in ({'topic':'b1/secret/arbitrary','publish':True},{'topic':'b1/sensor/b1-sensor/probe','publish':True,'retained':True}):
            with patch.object(self.runner,'podman') as run:
                with self.assertRaises(ValueError):m._mqtt_private(self.provision,clients,'sensor',**kw)
                run.assert_not_called()

    def test_imported_policy_requires_private_non_superuser_roles_and_all_acl_scopes(self):
        from test_emqx_source_api_validator import SourceAPITests
        issued=SourceAPITests();issued.setUp();self.addCleanup(issued.doCleanups)
        issued.documents['mqtt_users']['data'].append({'user_id':'b1-sensor','is_superuser':False})
        issued.documents['mqtt_users']['meta']['count']=2
        issued.documents['authorization_sources']['sources'].append({'type':'built_in_database','enable':True})
        observed=issued.run_api();m._assert_imported_acl_api(observed)
        for mutation in ('superuser','missing_role','disabled_db','client_scope','all_scope'):
            docs=copy.deepcopy(observed._documents);facts=copy.deepcopy(observed._facts)
            if mutation=='superuser':observed._documents['mqtt_users']['data'][0]['is_superuser']=True
            elif mutation=='missing_role':observed._documents['mqtt_users']['data'].pop()
            elif mutation=='disabled_db':observed._documents['authorization_sources']['sources'][1]['enable']=False
            elif mutation=='client_scope':observed._facts['acl_clients']['rule_counts']={}
            else:observed._facts['acl_all']['count']=0
            with self.assertRaises(m.RealOwnerRefused) as caught:m._assert_imported_acl_api(observed)
            self.assertEqual(caught.exception.phase,'source_api')
            observed._documents=docs;observed._facts=facts

    def test_mqtt_transport_keeps_inputs_out_of_argv_env_and_cleans_timeout_and_bad_reply(self):
        clients=self.clients()
        import json
        from emqx_owned_client import LABEL
        from emqx_adapter_mqtt import CLIENT
        configs=[];running={};removals=[]
        def podman(*args,**kwargs):
            if args[:2]==('container','exists'):
                return SimpleNamespace(returncode=0 if any(args[2] in (name,doc['Id']) for name,doc in running.items()) else 1,stdout=b'',stderr=b'')
            if args[:2]==('container','inspect'):
                return SimpleNamespace(returncode=0,stdout=json.dumps([running[args[2]]]).encode(),stderr=b'')
            if args[0]=='rm':
                self.assertEqual(args,('rm','--force','--ignore','a'*64));removals.append(args[-1])
                for name in list(running):
                    if running[name]['Id']==args[-1]:del running[name]
                return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
            self.assertEqual(args[0],'run')
            name=args[args.index('--name')+1]
            label,nonce=args[args.index('--label')+1].split('=',1)
            self.assertEqual(label,LABEL);self.assertRegex(nonce,r'^[0-9a-f]{64}$')
            running[name]={'Id':'a'*64,'Name':'/'+name,'Image':CLIENT,'Config':{'Labels':{label:nonce}}}
            config=Path(args[args.index('-v')+1].removesuffix(':/work:ro'))/'mosquitto_sub'
            configs.append(config)
            self.assertEqual(config.stat().st_mode&0o777,0o600)
            self.assertEqual(config.parent.stat().st_mode&0o777,0o700)
            self.assertEqual(config.read_bytes(),b'-u '+clients.fields['gateway_user']+
                b'\n-P '+clients.fields['gateway_password']+b'\n-t b1/retained/one\n')
            self.assertNotIn('env',kwargs)
            for private in (clients.fields['gateway_user'],clients.fields['gateway_password'],b'b1/retained/one'):
                self.assertNotIn(private.decode(),repr(args))
            self.assertIn('--network=container:'+self.fixture.prefix,args)
            self.assertIn('--log-driver=none',args);self.assertIn('--image-volume=ignore',args)
            self.assertEqual(kwargs['max_output'],65536)
            self.assertEqual(args[-2:],('-F','%r:%t:%x'))
            if fail[0]=='timeout':
                import subprocess
                raise subprocess.TimeoutExpired('generated',20)
            return SimpleNamespace(returncode=0,stdout=b'x'*65537 if fail[0]=='oversize' else b'generated-private-reply',stderr=b'')
        for case in ('pass','timeout','oversize'):
            fail=[case]
            with patch.object(self.runner,'podman',side_effect=podman), \
                 patch.object(m,'_ram_client_parent',return_value=self.root):
                if case=='pass':m._mqtt_private(self.provision,clients,'gateway',topic='b1/retained/one',retained=True)
                else:
                    with self.assertRaises(Exception):m._mqtt_private(self.provision,clients,'gateway',topic='b1/retained/one',retained=True)
            self.assertEqual(running,{})
            self.assertEqual(removals[-1],'a'*64)
            self.assertTrue(all(not path.parent.exists() for path in configs))

    def test_client_registration_requires_complete_real_runtime_and_keeps_scanner_strict(self):
        from emqx_runtime_workflow import PrivateSession,CombinedRegistry
        from emqx_runtime_credentials import RuntimeRegistry
        from emqx_private_boundary import Registry
        # Incomplete runtime must refuse, even though the client prefix is valid.
        runtime=RuntimeRegistry()
        session=PrivateSession(object(),CombinedRegistry(Registry(),runtime),{},None)
        with self.assertRaises(Exception):m._register_client_inputs(session,self.clients(),self.root/'not-created.txt')
        self.assertEqual(runtime._categories,{})

    def test_actual_joined_registry_registers_clients_then_rescans_identical_publication_bytes(self):
        from test_emqx_owner_preflight import JoinTests
        from emqx_private_boundary import PrivateFailure
        joined=JoinTests();joined.setUp();self.addCleanup(joined.doCleanups)
        clients=self.clients();clients.fields.update(lab_user=b'lab',lab_password=b'generated-target-lab-control-password')
        with joined.source() as (captured,binding):
            session=joined.join(captured)
            artifacts=list(joined.evidence.iterdir())
            self.assertEqual(len(artifacts),1)
            path=artifacts[0]  # scan the actual publisher artifact without assuming its encoding or suffix
            before=path.read_bytes()
            api=m.SourceAPICredentials(self.api_values())
            m._register_client_inputs(session,clients,path,api_credentials=api)
            self.assertEqual(path.read_bytes(),before)
            actual=session.registry._runtime.summary()
            self.assertEqual(session.coverage['target-bootstrap'],actual['target-bootstrap']+
                actual['runtime-login-input']+actual['runtime-login-token'])
            for name in (*m.CLIENT_FIELDS[:6],'negative_password','lab_user','lab_password'):
                with self.subTest(name=name), self.assertRaises(PrivateFailure):
                    session.registry.scan(clients.fields[name])
            import base64
            basic=api.fields[4]+b':'+api.fields[5]
            for value in (*api.fields,basic,b'Basic '+base64.b64encode(basic)):
                with self.assertRaises(PrivateFailure):session.registry.scan(value)
            self.assertFalse(captured._closed)

    def test_last_client_activity_precedes_phase_validation_at_restore_rollback_and_restart(self):
        ctx,app,state=self.context()
        (self.root/'.config/systemd/user').mkdir(parents=True)
        clients=self.clients();events=[]
        def restore(context,request):
            events.append('restore')
            if events.count('restore')==1:return {'changed':True}
            ctx.adapter(app).imported_hook()
            (self.root/'.config'/self.fixture.prefix/'fail-once').unlink()
            raise flows.RolledBack(BackupError('job-failed','generated'),{'rolled_back':True})
        with patch.object(flows,'run_restore',side_effect=restore), patch.object(m,'_ready'), \
             patch.object(m,'validate_source_mqtt',side_effect=lambda p,c,**kw:events.append('mqtt')) as mqtt:
            m._restore_and_rollback(ctx,app,self.provision,'generated-package',state,clients=clients)
        self.assertEqual(events,['restore','mqtt','restore','mqtt','mqtt'])
        self.assertEqual(mqtt.call_count,3)

    def test_changed_postrestore_cid_uses_independent_value_proof_without_rebinding(self):
        from test_emqx_owner_fixture_files import FixtureFilesTests
        import emqx_post_restore_values as post
        issued=FixtureFilesTests();issued.setUp();self.addCleanup(issued.doCleanups)
        issued.observe()  # actual issued observer over generated full native contracts binds old CID
        before=files._record(issued.cap)[0]['cid']
        current=dict(issued.doc[0]);current['Id']='b'*64
        with patch.object(m,'_inspect',return_value=current), \
             patch.object(post,'collect_post_restore_values') as collect:
            prior=object()
            result=m._post_activity_capture(issued.provision,prior)
            self.assertIs(result,collect.return_value)
            kwargs=collect.call_args.kwargs
            self.assertIs(kwargs['prior_registry'],prior)
            self.assertIs(kwargs['provision'],issued.provision)
            self.assertEqual(kwargs['expected_container_id'],'b'*64)
            self.assertEqual(set(kwargs),{'prior_registry','provision','expected_container_id','quiesce'})
            with patch.object(m,'fixture_quiescence') as lease:
                kwargs['quiesce']()
                lease.assert_called_once_with(issued.provision)
            collect.side_effect=ValueError()
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m._post_activity_capture(issued.provision,prior)
            self.assertEqual(caught.exception.phase,'post_capture')
        self.assertEqual(files._record(issued.cap)[0]['cid'],before)
        self.assertEqual(before,'a'*64)

    def test_each_last_client_activity_is_followed_by_accumulation_preserving_prior_registry(self):
        ctx,app,state=self.context()
        (self.root/'.config/systemd/user').mkdir(parents=True)
        clients=self.clients();events=[]
        original=object();scanners=[original,object(),object(),object()]
        session=SimpleNamespace(registry=original)
        def restore(context,request):
            events.append('restore')
            if events.count('restore')==1:return {'changed':True}
            ctx.adapter(app).imported_hook()
            (self.root/'.config'/self.fixture.prefix/'fail-once').unlink()
            raise flows.RolledBack(BackupError('job-failed','generated'),{'rolled_back':True})
        def capture(provision,prior):
            index=events.count('capture')
            self.assertIs(prior,scanners[index]);events.append('capture')
            return scanners[index+1]
        with patch.object(flows,'run_restore',side_effect=restore), patch.object(m,'_ready'), \
             patch.object(m,'validate_source_mqtt',side_effect=lambda p,c,**kw:events.append('mqtt')), \
             patch.object(m,'_post_activity_capture',side_effect=capture):
            result=m._restore_and_rollback(ctx,app,self.provision,'generated-package',state,
                clients=clients,session=session)
        self.assertEqual(events,['restore','mqtt','capture','restore','mqtt','capture','mqtt','capture'])
        self.assertIs(result,scanners[-1])
        self.assertIs(session.registry,original)  # no session capability overwrite

    def test_target_file_acl_has_only_explicit_fixture_readiness_permissions(self):
        acl=m._target_acl()
        self.assertEqual(acl,(b'{allow, {username, "lab"}, all, ["lab/#"]}.\n'
            b'{allow, {username, "b1-gateway"}, subscribe, ["b1/retained/#"]}.\n'
            b'{deny, {username, "b1-sensor"}, subscribe, ["b1/secret/#"]}.\n'
            b'{deny, all}.\n'))
        self.assertNotIn(b'{allow, all}',acl)

    def test_actual_framed_live_gate_requires_history_before_any_target_mutation(self):
        from dataclasses import replace
        import hashlib,struct
        from emqx_source_profiles import ARM_SQL_ALIASES
        from emqx_retained_history import RetainedHistory
        cipher=b'generated-encrypted-cipher-only';key=b'generated-key-only'
        framed=self.owner_prefix()+struct.pack('!I',len(key))+key+struct.pack('!Q',len(cipher))+cipher
        profile=replace(ARM_SQL_ALIASES,sha256=hashlib.sha256(cipher).hexdigest())
        clients=self.clients()
        expected=tuple((clients.fields['retained_topic'+str(i)],clients.fields['retained_payload'+str(i)]) for i in (1,2))
        for kind in ('match','different-payload','wrong-sha','boolean','native-failure'):
            events=[]
            result=RetainedHistory(expected,Mock(),profile.sha256)
            if kind=='different-payload':result=RetainedHistory(((expected[0][0],b'foreign-generated'),expected[1]),Mock(),profile.sha256)
            if kind=='wrong-sha':result=RetainedHistory(expected,Mock(),'0'*64)
            if kind=='boolean':result=True
            def collect(**kwargs):
                events.append('history')
                self.assertEqual(kwargs['source_mode'],m.SOURCE_MODES[0])
                self.assertEqual(kwargs['password'],'generated-key-only')
                self.assertEqual(kwargs['topics'],tuple(t for t,_ in expected))
                self.assertEqual(kwargs['source_path'].read_bytes(),cipher)
                self.assertEqual(kwargs['source_path'].parent,kwargs['spool_directory'].parent)
                if kind=='native-failure':raise ValueError()
                return result
            def create(*args):
                events.append('provision')
                raise ValueError()  # End this generated boundary before any target IO.
            with patch.object(m,'OwnerProvision',return_value=self.provision), \
                 patch('emqx_fresh_owner_workflow.source_profile',return_value=profile), \
                 patch.object(Path,'read_text',side_effect=['0',str(4*1024**3)]), \
                 patch('emqx_fresh_owner_workflow.socket.gethostname',return_value='woowbk-dev-d'), \
                 patch('emqx_retained_history.collect_original_retained_payloads',side_effect=collect) as collector, \
                 patch.object(self.provision,'create',side_effect=create) as provision, \
                 patch.object(self.provision,'cleanup') as cleanup,patch.object(m,'build_captured_candidate') as build, \
                 patch.object(m,'capture_owner_source') as capture:
                with self.assertRaises(m.RealOwnerRefused) as caught:
                    m.run_real_framed_owner(io.BytesIO(framed),private_parent=self.root,source_mode=m.SOURCE_MODES[0],no_live=False)
            self.assertEqual(collector.call_count,1,caught.exception.phase)
            if kind=='match':
                self.assertEqual(events,['history','provision']);self.assertEqual(caught.exception.phase,'provision')
                provision.assert_called_once();cleanup.assert_called_once()
            else:
                self.assertEqual(events,['history']);self.assertEqual(caught.exception.phase,'payload_history')
                provision.assert_not_called();cleanup.assert_not_called()
            build.assert_not_called();capture.assert_not_called()
            self.assertEqual(list(self.root.glob('emqx-framed-private-*')),[])

    def test_missing_or_invalid_host_admission_cannot_reach_history_or_provision(self):
        from dataclasses import replace
        import hashlib,struct
        import emqx_real_owner_transport as transport
        from emqx_source_profiles import ARM_SQL_ALIASES
        cipher=b'generated-cipher-valid-sha';key=b'generated-only-key'
        body=self.owner_prefix()+struct.pack('!I',len(key))+key+struct.pack('!Q',len(cipher))+cipher
        profile=replace(ARM_SQL_ALIASES,sha256=hashlib.sha256(cipher).hexdigest())
        for trailer in (b'',transport.ADMISSION[:-1],b'x'*len(transport.ADMISSION),transport.ADMISSION+b'private-trailing'):
            stream=transport.AdmittedStream(io.BytesIO(struct.pack('!Q',len(body))+body+trailer))
            with patch.object(m,'OwnerProvision',return_value=self.provision), \
                 patch('emqx_fresh_owner_workflow.source_profile',return_value=profile), \
                 patch.object(Path,'read_text',side_effect=['0',str(4*1024**3)]), \
                 patch('emqx_fresh_owner_workflow.socket.gethostname',return_value='woowbk-dev-d'), \
                 patch.object(self.provision,'create') as create,patch.object(self.provision,'cleanup') as cleanup, \
                 patch.object(m,'_payload_history') as history,patch.object(m,'capture_owner_source') as capture, \
                 patch.object(m,'build_captured_candidate') as build:
                with self.assertRaises(m.RealOwnerRefused) as caught:
                    m.run_real_framed_owner(stream,private_parent=self.root,source_mode=m.SOURCE_MODES[0],no_live=False)
            self.assertEqual(caught.exception.phase,'frame')
            for operation in (create,cleanup,history,capture,build):operation.assert_not_called()
            self.assertEqual(list(self.root.glob('emqx-framed-private-*')),[])

    def test_host_metadata_refusal_closes_valid_cipher_without_admitting_actual_child(self):
        from dataclasses import replace
        import contextlib,hashlib,struct
        import emqx_real_owner_transport as transport
        from emqx_source_profiles import ARM_SQL_ALIASES
        cipher=b'generated-cipher-same-bytes';key=b'generated-key'
        archive=self.root/'generated-cipher';archive.write_bytes(cipher)
        profile=replace(ARM_SQL_ALIASES,archive=archive,sha256=hashlib.sha256(cipher).hexdigest())
        class Sink(io.BytesIO):
            def close(self):pass
            def write(self,raw):
                n=super().write(raw)
                if raw==cipher:
                    st=archive.stat();os.utime(archive,ns=(st.st_atime_ns,st.st_mtime_ns+1000000))
                return n
        sink=Sink();child=Mock(stdin=sink);out=io.StringIO()
        with patch.object(transport,'bundle_code',return_value=b'code'),patch.object(transport,'dependencies',return_value=b'deps'), \
             patch.object(transport,'client_prefix',return_value=self.owner_prefix()), \
             patch.object(transport,'read_fixed_fields',return_value=[key]),patch.object(transport,'source_profile',return_value=profile), \
             patch.object(transport.subprocess,'Popen',return_value=child),patch.object(transport,'read_result') as result,contextlib.redirect_stdout(out):
            self.assertEqual(transport.main(['--real-restore']),1)
        self.assertEqual(out.getvalue(),'REAL OWNER ARCHIVE_BINDING REFUSED\n');result.assert_not_called()
        raw=io.BytesIO(sink.getvalue())
        for expected in (b'code',b'deps'):self.assertEqual(raw.read(struct.unpack('!Q',raw.read(8))[0]),expected)
        self.assertEqual(raw.read(1),b'G')
        stream=transport.AdmittedStream(raw)
        with patch.object(m,'OwnerProvision',return_value=self.provision), \
             patch('emqx_fresh_owner_workflow.source_profile',return_value=profile), \
             patch.object(Path,'read_text',side_effect=['0',str(4*1024**3)]), \
             patch('emqx_fresh_owner_workflow.socket.gethostname',return_value='woowbk-dev-d'), \
             patch.object(self.provision,'create') as create,patch.object(self.provision,'cleanup') as cleanup, \
             patch.object(m,'_payload_history') as history,patch.object(m,'build_captured_candidate') as build:
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m.run_real_framed_owner(stream,private_parent=self.root,source_mode=m.SOURCE_MODES[0],no_live=False)
        self.assertEqual(caught.exception.phase,'frame')
        for operation in (create,cleanup,history,build):operation.assert_not_called()
        self.assertEqual(list(self.root.glob('emqx-framed-private-*')),[])

    def test_partial_upload_recovers_fixed_budget_refusal_without_admitting_actual_consumer(self):
        import contextlib,hashlib,struct,subprocess,sys
        from dataclasses import replace
        import emqx_real_owner_transport as transport
        from emqx_source_profiles import source_profile
        key=b'generated-key';cipher=b'generated-cipher-bytes-not-authenticated'
        archive=self.root/'generated-source.tar';archive.write_bytes(cipher)
        profile=replace(source_profile(m.SOURCE_MODES[0]),archive=archive,sha256=hashlib.sha256(cipher).hexdigest())
        class Sink(io.BytesIO):
            def close(self):pass
            def write(self,raw):
                if raw==cipher:
                    super().write(raw[:len(raw)//2]);raise BrokenPipeError()
                return super().write(raw)
        from emqx_framed_preflight import evidence_frame
        for reply,status,expected in ((b'REALOWNER-REFUSED:budget\n',1,'BUDGET'),
                (evidence_frame(transport.canonical_receipt()),0,'TRANSFER'),
                (b'generated-private-output-not-an-enum',1,'TRANSFER')):
            process=subprocess.Popen([sys.executable,'-c','import sys;sys.stdout.buffer.write('+repr(reply)+');sys.exit('+str(status)+')'],
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            sink=Sink();child=SimpleNamespace(stdin=sink,stdout=process.stdout,wait=process.wait,terminate=Mock(wraps=process.terminate))
            out=io.StringIO()
            try:
                with patch.object(transport,'bundle_code',return_value=b'code'),patch.object(transport,'dependencies',return_value=b'deps'), \
                     patch.object(transport,'client_prefix',return_value=self.owner_prefix()),patch.object(transport,'read_fixed_fields',return_value=[key]), \
                     patch.object(transport,'source_profile',return_value=profile),patch.object(transport.subprocess,'Popen',return_value=child), \
                     patch.object(transport,'retain_restore_evidence') as retain,contextlib.redirect_stdout(out):
                    self.assertEqual(transport.main(['--real-restore']),1)
                self.assertEqual(out.getvalue(),'REAL OWNER '+expected+' REFUSED\n');retain.assert_not_called();child.terminate.assert_not_called()
                self.assertNotIn(transport.ADMISSION,sink.getvalue())
            finally:process.wait();process.stdout.close()
        frame=sink.getvalue();self.assertNotIn(transport.ADMISSION,frame)
        raw=io.BytesIO(frame)
        for expected in (b'code',b'deps'):self.assertEqual(raw.read(struct.unpack('!Q',raw.read(8))[0]),expected)
        self.assertEqual(raw.read(1),b'G');stream=transport.AdmittedStream(raw)
        with patch.object(m,'OwnerProvision',return_value=self.provision),patch.object(m,'_full_restore_budget'), \
             patch('emqx_fresh_owner_workflow.source_profile',return_value=profile), \
             patch('emqx_fresh_owner_workflow.socket.gethostname',return_value='woowbk-dev-d'), \
             patch.object(self.provision,'create') as create,patch.object(self.provision,'cleanup') as cleanup, \
             patch.object(m,'_payload_history') as history,patch.object(m,'build_captured_candidate') as build:
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m.run_real_framed_owner(stream,private_parent=self.root,source_mode=m.SOURCE_MODES[0],no_live=False)
        self.assertEqual(caught.exception.phase,'frame')
        for operation in (create,cleanup,history,build):operation.assert_not_called()
        self.assertEqual(list(self.root.glob('emqx-framed-private-*')),[])

    def test_budget_refusal_precedes_frame_and_has_fixed_phase_without_provision(self):
        with patch.object(m,'OwnerProvision',return_value=self.provision), \
             patch.object(m,'_full_restore_budget',side_effect=ValueError('generated-private-budget-error')), \
             patch.object(m,'read_source_api_credentials') as frame,patch.object(self.provision,'create') as create:
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m.run_real_framed_owner(io.BytesIO(b''),private_parent=self.root,source_mode=m.SOURCE_MODES[0],no_live=False)
        self.assertEqual(caught.exception.phase,'budget');frame.assert_not_called();create.assert_not_called()

    def test_api_credential_prefix_is_versioned_profile_bound_and_private(self):
        import struct
        fields=(b'admin',b'generated-admin-password',b'b1ops',b'generated-ops-password',b'generated-api-key',b'generated-api-secret')
        raw=b'WOOWREALAPI1:'+b'A'+b''.join(struct.pack('!H',len(v))+v for v in fields)
        result=m.read_source_api_credentials(io.BytesIO(raw),m.SOURCE_MODES[0])
        self.assertEqual(result.fields,fields)
        self.assertEqual(repr(result),'<Source API credentials private>')
        for invalid in (self.client_frame(),raw[:-1],raw.replace(b'WOOWREALAPI1:',b'WOOWREALAPI0:'),raw[:len(b'WOOWREALAPI1:')]+b'B'+raw[len(b'WOOWREALAPI1:')+1:]):
            with self.assertRaises(ValueError):m.read_source_api_credentials(io.BytesIO(invalid),m.SOURCE_MODES[0])

    def test_restore_rollback_restart_run_api_and_negative_after_mqtt_before_each_native_capture(self):
        ctx,app,state=self.context();(self.root/'.config/systemd/user').mkdir(parents=True)
        clients=self.clients();credentials=m.SourceAPICredentials(self.api_values());events=[]
        original=object();scanners=[original,object(),object(),object()]
        session=SimpleNamespace(registry=original);api_results=[];observations=[object(),object(),object()]
        object_results=[];object_expected=object()
        negative_results=[];negative_observations=[object(),object(),object()]
        def restore(context,request):
            events.append('restore')
            if events.count('restore')==1:return {'changed':True}
            ctx.adapter(app).imported_hook();(self.root/'.config'/self.fixture.prefix/'fail-once').unlink()
            raise flows.RolledBack(BackupError('job-failed','generated'),{'rolled_back':True})
        def api(provision,prior,supplied,actual_clients,actual_credentials):
            i=events.count('api');self.assertIs(prior,scanners[i]);self.assertIs(supplied,session)
            self.assertIs(actual_clients,clients);self.assertIs(actual_credentials,credentials)
            events.append('api');return observations[i]
        def negative(provision,supplied,actual_clients,observed):
            i=events.count('negative');self.assertIs(supplied,session);self.assertIs(actual_clients,clients)
            self.assertIs(observed,observations[i]);events.append('negative');return negative_observations[i]
        def native(provision,prior):
            i=events.count('capture');self.assertIs(prior,scanners[i]);events.append('capture');return scanners[i+1]
        def compared(expected,observed,native):
            i=events.count('objects');self.assertIs(expected,object_expected)
            self.assertIs(observed,observations[i]);self.assertIs(native,scanners[i+1])
            self.assertEqual(events[-1],'capture');events.append('objects');return object()
        with patch.object(flows,'run_restore',side_effect=restore),patch.object(m,'_ready'), \
             patch.object(m,'validate_source_mqtt',side_effect=lambda *a,**kw:events.append('mqtt')), \
             patch.object(m,'_source_api_activity',side_effect=api),patch.object(m,'_source_negative_activity',side_effect=negative), \
             patch.object(m,'_post_activity_capture',side_effect=native), \
             patch.object(m,'_assert_imported_acl_api',side_effect=lambda observed:events.append('acl_api')) as acl_api, \
             patch.object(m,'_compare_source_objects',side_effect=compared):
            result=m._restore_and_rollback(ctx,app,self.provision,'generated-package',state,clients=clients,
                session=session,api_credentials=credentials,api_results=api_results,negative_results=negative_results,target_mode=m.IMPORTED_MNESIA,object_expected=object_expected,object_results=object_results)
        self.assertEqual(events,['restore','mqtt','api','negative','acl_api','capture','objects','restore','mqtt','api','negative','acl_api','capture','objects','mqtt','api','negative','acl_api','capture','objects'])
        self.assertEqual(api_results,observations);self.assertEqual(negative_results,negative_observations)
        self.assertEqual(len(object_results),3);self.assertEqual(len({id(r) for r in object_results}),3)
        self.assertIs(result,scanners[-1]);self.assertIs(session.registry,original)

    def test_api_refusal_stops_before_post_native_capture(self):
        ctx,app,state=self.context();session=SimpleNamespace(registry=object())
        with patch.object(flows,'run_restore',return_value={'changed':True}),patch.object(m,'_ready'), \
             patch.object(m,'validate_source_mqtt'),patch.object(m,'_source_api_activity',side_effect=m.RealOwnerRefused('source_api')), \
             patch.object(m,'_post_activity_capture') as native:
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m._restore_and_rollback(ctx,app,self.provision,'generated-package',state,clients=self.clients(),
                    session=session,api_credentials=m.SourceAPICredentials(self.api_values()),api_results=[],negative_results=[],object_expected=object(),object_results=[])
        self.assertEqual(caught.exception.phase,'source_api');native.assert_not_called()

    def test_negative_refusal_stops_native_capture_and_later_restore_phases(self):
        ctx,app,state=self.context();session=SimpleNamespace(registry=object())
        api_results=[];negative_results=[]
        with patch.object(flows,'run_restore',return_value={'changed':True}) as restore,patch.object(m,'_ready'), \
             patch.object(m,'validate_source_mqtt'),patch.object(m,'_source_api_activity',return_value=object()), \
             patch.object(m,'_compare_source_objects',return_value=object()), \
             patch.object(m,'_source_negative_activity',side_effect=m.RealOwnerRefused('source_negative')), \
             patch.object(m,'_post_activity_capture') as native:
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m._restore_and_rollback(ctx,app,self.provision,'generated-package',state,clients=self.clients(),
                    session=session,api_credentials=m.SourceAPICredentials(self.api_values()),
                    api_results=api_results,negative_results=negative_results,object_expected=object(),object_results=[])
        self.assertEqual(caught.exception.phase,'source_negative');native.assert_not_called()
        self.assertEqual(restore.call_count,1);self.assertEqual(len(api_results),1);self.assertEqual(negative_results,[])

    def test_real_api_validator_boundary_keeps_original_runtime_and_all_final_scanners(self):
        from test_emqx_source_api_validator import SourceAPITests
        from emqx_runtime_workflow import PrivateSession
        from emqx_private_evidence import names_receipt,SOURCE_NAMES
        from emqx_private_boundary import PrivateFailure
        issued=SourceAPITests();issued.setUp();self.addCleanup(issued.doCleanups)
        session=PrivateSession(object(),issued.prior,{},None)
        credentials=m.SourceAPICredentials(tuple(issued.credentials[k] for k in m.API_FIELDS))
        old=files._record(issued.cap)[0]['cid'];results=[]
        with patch.object(m,'_inspect',return_value=issued.doc[0]),patch.object(m,'fixture_quiescence',side_effect=lambda p:issued.quiesce()):
            for _ in range(3):results.append(m._source_api_activity(issued.provision,issued.prior,session,self.clients(),credentials))
        self.assertEqual(len(issued.http),54)
        self.assertEqual(files._record(issued.cap)[0]['cid'],old)
        self.assertTrue(all(r._runtime is issued.runtime for r in results));self.assertIs(session.registry,issued.prior)
        raw=names_receipt('restore','passed',SOURCE_NAMES)
        m._scan_source_api_receipt(raw,results,session)
        issued.runtime.register_bundle({'runtime-login-token':[b'generated-late-api-token']})
        for value in (b'generated-late-api-token',b'generated-jwt-admin',b'generated-jwt-b1ops',b'generated-returned-connector-secret',credentials.fields[-1]):
            with self.assertRaises(m.RealOwnerRefused):m._scan_source_api_receipt(value,results,session)
        with self.assertRaises(m.RealOwnerRefused):m._scan_source_api_receipt(raw,results[:2],session)
        with self.assertRaises(m.RealOwnerRefused):m._scan_source_api_receipt(raw,[results[0]]*3,session)
        with patch.object(m,'_inspect',return_value=issued.doc[0]),patch('emqx_source_api_validator.validate_source_api',return_value=True):
            with self.assertRaises(m.RealOwnerRefused):m._source_api_activity(issued.provision,issued.prior,session,self.clients(),credentials)

    def test_negative_callsite_uses_api_bound_cid_actual_helper_and_final_private_scan(self):
        from test_emqx_source_mqtt_negative import NegativeTests
        from emqx_runtime_workflow import PrivateSession
        from emqx_private_evidence import names_receipt,SOURCE_NAMES
        import emqx_owner_fixture_files as files
        issued=NegativeTests();issued.setUp();self.addCleanup(issued.doCleanups)
        session=PrivateSession(object(),issued.prior,{},None)
        credentials=m.SourceAPICredentials(tuple(issued.credentials[k] for k in m.API_FIELDS))
        clients=self.clients();clients.fields['gateway_password']=b'generated-gateway-password'
        old=files._record(issued.cap)[0]['cid'];results=[];apis=[]
        with patch.object(m,'_inspect',return_value=issued.doc[0]),patch.object(m,'fixture_quiescence',side_effect=lambda p:issued.quiesce()):
            # A result not issued through this API callsite cannot authorize a negative probe.
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m._source_negative_activity(issued.provision,session,clients,issued.observed)
            self.assertEqual(caught.exception.phase,'source_negative');self.assertEqual(issued.probes,[])
            for _ in range(3):
                issued.api_mode=True
                observed=m._source_api_activity(issued.provision,issued.prior,session,clients,credentials)
                issued.api_mode=False;issued.observed=observed;issued.probes.clear()
                result=m._source_negative_activity(issued.provision,session,clients,observed)
                self.assertEqual(len(issued.probes),2);self.assertFalse(issued.active)
                apis.append(observed);results.append(result)
            # A replacement after the API observation is not adopted by name.
            issued.probes.clear();issued.doc[0]['Id']='c'*64
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m._source_negative_activity(issued.provision,session,clients,apis[-1])
            self.assertEqual(caught.exception.phase,'source_negative');self.assertEqual(issued.probes,[])
        self.assertEqual(files._record(issued.cap)[0]['cid'],old)
        receipt=names_receipt('restore','passed',SOURCE_NAMES)
        m._scan_source_negative_receipt(receipt,results,apis,session)
        issued.runtime.register_bundle({'runtime-login-token':[b'generated-final-negative-token']})
        for raw,rs,observed in ((b'generated-final-negative-token',results,apis),
                (receipt,[results[0]]*3,apis),(receipt,results,list(reversed(apis))),
                (receipt,results[:2],apis)):
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m._scan_source_negative_receipt(raw,rs,observed,session)
            self.assertEqual(caught.exception.phase,'source_negative')

    def test_actual_owner_entry_captures_objects_under_original_hold_before_builder(self):
        from contextlib import contextmanager
        from test_emqx_b1_object_integrity import ObjectIntegrityTests
        import emqx_b1_object_integrity as integrity
        fixture=ObjectIntegrityTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        profile=SimpleNamespace(sha256=fixture.digest,arch='aarch64',fixture_profile='generated-only',file_dependency_profile=None)
        real_capture=m._capture_source_objects
        for malformed in (False,True):
            events=[];held=[False]
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                @contextmanager
                def staged(*args,**kw):yield fixture.path,b'generated-key',fixture.spool,profile,root
                @contextmanager
                def source(*args,**kw):
                    with fixture.source() as result:
                        held[0]=True
                        try:yield result
                        finally:held[0]=False
                @contextmanager
                def readers(**kw):yield SimpleNamespace(generation='generated-only')
                def join(**kw):
                    self.assertTrue(held[0]);events.append('join')
                    return fixture.join(kw['captured'],evidence_directory=kw['evidence_directory'],evidence_name=kw['evidence_name'])
                def capture(captured,session,mode):
                    self.assertTrue(held[0]);events.append('objects')
                    if malformed:fixture.config['rule_engine']['rules']['b1_rule_http']['sql']=None
                    return real_capture(captured,session,mode)
                def build(*args,**kw):
                    self.assertTrue(held[0]);self.assertEqual(events,['join','objects'])
                    events.append('build');raise ValueError('generated-stop-before-product')
                with patch.object(owner,'LabOwnerRunner',return_value=self.runner),patch.object(m,'_full_restore_budget'), \
                     patch.object(m,'staged_owner_frame',side_effect=staged),patch.object(m,'_payload_history',return_value=object()), \
                     patch.object(owner.OwnerProvision,'cleanup',autospec=True,side_effect=lambda p:files.revoke(p.file_capability)), \
                     patch.object(m,'_opt_in_private_unit'),patch.object(m,'_ready'), \
                     patch.object(m,'capture_owner_source',side_effect=source),patch.object(m,'validate_source_capture'), \
                     patch.object(m,'owner_target_readers',side_effect=readers),patch.object(m,'owner_preflight',side_effect=join), \
                     patch.object(m,'_capture_source_objects',side_effect=capture),patch.object(integrity,'source_profile',return_value=profile), \
                     patch.object(m,'build_captured_candidate',side_effect=build),patch.object(m,'_package_same_target') as package:
                    with self.assertRaises(m.RealOwnerRefused) as caught:
                        m.run_real_framed_owner(io.BytesIO(self.owner_prefix()),private_parent=root,
                            source_mode=m.SOURCE_MODES[0],no_live=False)
                self.assertFalse(held[0]);package.assert_not_called()
                self.assertEqual(events,['join','objects'] if malformed else ['join','objects','build'],caught.exception.phase)
                self.assertEqual(caught.exception.phase,'object_integrity' if malformed else 'build')

    def test_actual_native_object_comparisons_and_receipt_scan_require_fresh_collector_chain(self):
        from test_emqx_native_object_integrity import NativeObjectTests
        from emqx_private_evidence import names_receipt,SOURCE_NAMES
        from emqx_b1_object_integrity import ObjectComparison
        fixture=NativeObjectTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        session=fixture.session;expected=fixture.expected;apis=[];results=[]
        for index in range(3):
            if index:
                fixture.api_mode=True;fixture.observed=fixture.run_api();fixture.api_mode=False
            observed=fixture.observed;native=fixture.native()
            result=m._compare_source_objects(expected,observed,native)
            self.assertIs(result._native,native);self.assertIs(result._api,observed)
            apis.append(observed);results.append(result);fixture.prior=native
        receipt=names_receipt('restore','passed',SOURCE_NAMES)
        m._scan_object_receipt(receipt,expected,results,apis,session)
        session.registry._runtime.register_bundle({'runtime-login-token':[b'generated-object-late-token']})
        for raw,compared,observed in ((fixture.secret.encode(),results,apis),
                (b'generated-object-late-token',results,apis),(receipt,[results[0]]*3,apis),
                (receipt,results,list(reversed(apis))),(receipt,results[:2],apis),
                (receipt,[ObjectComparison(expected,api) for api in apis],apis)):
            with self.assertRaises(m.RealOwnerRefused) as caught:m._scan_object_receipt(raw,expected,compared,observed,session)
            self.assertEqual(caught.exception.phase,'object_integrity')
        # Actual collector order protects against borrowing an older native receipt.
        with self.assertRaises(m.RealOwnerRefused):m._compare_source_objects(expected,apis[-1],results[0]._native)
        apis[0]._documents['rules']['data'][0]['sql']='SELECT altered'
        with self.assertRaises(m.RealOwnerRefused) as caught:m._compare_source_objects(expected,apis[0],results[0]._native)
        self.assertEqual(caught.exception.phase,'object_integrity_collector')

    def test_native_object_callsite_refuses_wrong_cid_and_same_bytes_at_another_path(self):
        from test_emqx_native_object_integrity import NativeObjectTests
        fixture=NativeObjectTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        old=fixture.cid;fixture.cid='c'*64;fixture.doc[0]['Id']=fixture.cid
        native=fixture.native()
        with self.assertRaises(m.RealOwnerRefused) as caught:m._compare_source_objects(fixture.expected,fixture.observed,native)
        self.assertEqual(caught.exception.phase,'object_integrity_identity')
        fixture.cid=old;fixture.doc[0]['Id']=old
        fixture.config['connectors']['http']['b1_http']['other_password']=fixture.secret
        fixture.wrapper_path[-1]='other_password'
        native=fixture.native()
        with self.assertRaises(m.RealOwnerRefused) as caught:m._compare_source_objects(fixture.expected,fixture.observed,native)
        self.assertEqual(caught.exception.phase,'object_integrity_connectors_secret_wrapper')

    def test_object_dependency_failure_and_boolean_ack_have_only_fixed_phase(self):
        import builtins
        original=builtins.__import__
        def missing(name,*args,**kwargs):
            if name in ('emqx_b1_object_integrity','emqx_native_object_integrity'):raise ImportError('generated-private-error-not-output')
            return original(name,*args,**kwargs)
        with patch.object(builtins,'__import__',side_effect=missing):
            for call in (lambda:m._capture_source_objects(None,None,m.SOURCE_MODES[0]),
                         lambda:m._compare_source_objects(None,None,None),
                         lambda:m._scan_object_receipt(b'',None,[],[],None)):
                with self.assertRaises(m.RealOwnerRefused) as caught:call()
                self.assertEqual(caught.exception.phase,'object_integrity')
        with patch('emqx_native_object_integrity.compare_b1_objects_native',return_value=True):
            with self.assertRaises(m.RealOwnerRefused) as caught:m._compare_source_objects(object(),object(),object())
            self.assertEqual(caught.exception.phase,'object_integrity')

    def test_object_mismatch_after_native_stops_later_product_phases(self):
        ctx,app,state=self.context();session=SimpleNamespace(registry=object());results=[]
        with patch.object(flows,'run_restore',return_value={'changed':True}) as restore,patch.object(m,'_ready'), \
             patch.object(m,'validate_source_mqtt'),patch.object(m,'_source_api_activity',return_value=object()), \
             patch.object(m,'_compare_source_objects',side_effect=m.RealOwnerRefused('object_integrity')), \
             patch.object(m,'_source_negative_activity') as negative,patch.object(m,'_post_activity_capture') as native:
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m._restore_and_rollback(ctx,app,self.provision,'generated-package',state,clients=self.clients(),
                    session=session,api_credentials=m.SourceAPICredentials(self.api_values()),api_results=[],negative_results=[],
                    object_expected=object(),object_results=results)
        self.assertEqual(caught.exception.phase,'object_integrity');self.assertEqual(results,[])
        negative.assert_called_once();native.assert_called_once();self.assertEqual(restore.call_count,1)

    def test_old_complete_cipher_frame_refuses_before_history_or_target(self):
        import struct
        old=self.client_frame()+struct.pack('!I',3)+b'key'+struct.pack('!Q',6)+b'cipher'
        with patch.object(m,'OwnerProvision',return_value=self.provision),patch.object(m,'_full_restore_budget'), \
             patch.object(self.provision,'create') as create,patch.object(m,'_payload_history') as history, \
             patch.object(m,'staged_owner_frame') as staged:
            with self.assertRaises(m.RealOwnerRefused) as caught:
                m.run_real_framed_owner(io.BytesIO(old),private_parent=self.root,source_mode=m.SOURCE_MODES[0],no_live=False)
        self.assertEqual(caught.exception.phase,'api_frame')
        for operation in (create,history,staged):operation.assert_not_called()

    def test_api_prefix_rejects_unbounded_lengths_control_fields_and_wrong_fixed_users(self):
        import struct
        raw=self.api_frame()
        for invalid in (m.API_MAGIC+b'A'+b'\x00\x00',m.API_MAGIC+b'A'+struct.pack('!H',4097)+b'x'*4097):
            with self.assertRaises(ValueError):m.read_source_api_credentials(io.BytesIO(invalid),m.SOURCE_MODES[0])
        for index,value in ((0,b'owner'),(2,b'arbitrary-user'),(4,b'bad:key'),(5,b'bad\nsecret'),(1,b'bad\x00password'),(1,b'\xff')):
            fields=list(self.api_values());fields[index]=value
            invalid=m.API_MAGIC+b'A'+b''.join(struct.pack('!H',len(v))+v for v in fields)
            with self.assertRaises(ValueError):m.read_source_api_credentials(io.BytesIO(invalid),m.SOURCE_MODES[0])

    def test_positive_mqtt_preexisting_collision_never_runs_or_deletes(self):
        calls=[]
        def podman(*args,**kwargs):
            calls.append(args)
            self.assertEqual(args[:2],('container','exists'))
            return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
        with patch.object(self.runner,'podman',side_effect=podman),patch.object(m,'_ram_client_parent',return_value=self.root):
            with self.assertRaises(Exception):m._mqtt_private(self.provision,self.clients(),'gateway',topic='b1/retained/one',retained=True)
        self.assertEqual(len(calls),1)
        self.assertFalse(list(self.root.glob(self.fixture.prefix+'-mqtt-*')))

    def test_positive_mqtt_late_foreign_or_malformed_ownership_never_deletes_by_name_or_cid(self):
        import json,subprocess
        from emqx_owned_client import LABEL
        from emqx_adapter_mqtt import CLIENT
        for case in ('foreign','malformed'):
            calls=[];state={}
            def podman(*args,**kwargs):
                calls.append(args)
                if args[:2]==('container','exists'):
                    return SimpleNamespace(returncode=0 if state else 1,stdout=b'',stderr=b'')
                if args[:2]==('container','inspect'):
                    raw=b'invalid-private-inspect' if case=='malformed' else json.dumps([state]).encode()
                    return SimpleNamespace(returncode=0,stdout=raw,stderr=b'')
                self.assertEqual(args[0],'run')
                name=args[args.index('--name')+1]
                label,nonce=args[args.index('--label')+1].split('=',1)
                self.assertEqual(label,LABEL);self.assertRegex(nonce,r'^[0-9a-f]{64}$')
                state.update(Id='b'*64,Name='/'+name,Image=CLIENT,Config={'Labels':{LABEL:'foreign-label'}})
                raise subprocess.TimeoutExpired('generated-private-run-failure',20)
            with patch.object(self.runner,'podman',side_effect=podman),patch.object(m,'_ram_client_parent',return_value=self.root):
                with self.assertRaises(Exception):m._mqtt_private(self.provision,self.clients(),'gateway',topic='b1/retained/one',retained=True)
            self.assertFalse(any(a[0]=='rm' for a in calls))
            self.assertEqual(state['Id'],'b'*64)
            self.assertFalse(list(self.root.glob(self.fixture.prefix+'-mqtt-*')))
