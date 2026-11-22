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
            self.assertEqual(caught.exception.phase,'client_frame')
            create.assert_not_called();cleanup.assert_not_called()

    def client_values(self):
        return [b'b1-sensor',b'generated-sensor-password',b'b1-gateway',b'generated-gateway-password',
                b'generated-third',b'generated-third-password',b'b1/retained/one',b'generated-payload-one',
                b'b1/retained/two',b'\x00generated\xffpayload-two']

    def client_frame(self,values=None,mode=b'A'):
        import struct
        return m.CLIENT_MAGIC+mode+b''.join(struct.pack('!H',len(raw))+raw
            for raw in (self.client_values() if values is None else values))

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
        framed=self.client_frame()+struct.pack('!I',len(key))+key+struct.pack('!Q',len(cipher))+cipher
        profile=replace(ARM_SQL_ALIASES,sha256=hashlib.sha256(cipher).hexdigest())
        with patch.object(m,'OwnerProvision',return_value=self.provision), \
             patch('emqx_fresh_owner_workflow.source_profile',return_value=profile), \
             patch.object(Path,'read_text',side_effect=['0',str(4*1024**3)]), \
             patch('emqx_fresh_owner_workflow.socket.gethostname',return_value='woowbk-dev-d'), \
             patch.object(self.provision,'create') as create, \
             patch.object(self.provision,'cleanup') as cleanup, \
             patch.object(m,'capture_owner_source') as capture, \
             patch.object(m,'build_captured_candidate') as build:
            receipt=m.run_real_framed_owner(io.BytesIO(framed),private_parent=self.root,source_mode=m.SOURCE_MODES[0])
        self.assertEqual(receipt['scope'],'sha-bound-ciphertext-and-client-frame-only')
        self.assertEqual(receipt['source_authentication'],'not-performed')
        for operation in (create,cleanup,capture,build):operation.assert_not_called()
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

    def test_mqtt_transport_keeps_inputs_out_of_argv_env_and_cleans_timeout_and_bad_reply(self):
        clients=self.clients()
        configs=[];running=[]
        def podman(*args,**kwargs):
            if args[:2]==('container','exists'):
                return SimpleNamespace(returncode=0 if args[2] in running else 1,stdout=b'',stderr=b'')
            if args[0]=='rm':
                running.remove(args[-1]);return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
            self.assertEqual(args[0],'run')
            name=args[args.index('--name')+1];running.append(name)
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
            self.assertEqual(running,[])
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
        clients=self.clients()
        with joined.source() as (captured,binding):
            session=joined.join(captured)
            artifacts=list(joined.evidence.iterdir())
            self.assertEqual(len(artifacts),1)
            path=artifacts[0]  # scan the actual publisher artifact without assuming its encoding or suffix
            before=path.read_bytes()
            m._register_client_inputs(session,clients,path)
            self.assertEqual(path.read_bytes(),before)
            actual=session.registry._runtime.summary()
            self.assertEqual(session.coverage['target-bootstrap'],actual['target-bootstrap']+
                actual['runtime-login-input']+actual['runtime-login-token'])
            for name in (*m.CLIENT_FIELDS[:6],'negative_password'):
                with self.subTest(name=name), self.assertRaises(PrivateFailure):
                    session.registry.scan(clients.fields[name])
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
             patch.object(m,'validate_source_mqtt',side_effect=lambda p,c:events.append('mqtt')) as mqtt:
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
             patch.object(m,'validate_source_mqtt',side_effect=lambda p,c:events.append('mqtt')), \
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
