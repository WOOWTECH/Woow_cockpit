"""Focused offline producer/profile/cache-export boundaries. Never runs a native producer, export or package shell."""
import ast
import datetime
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(HERE))
import focus_emqx_r4_profile as profile
import focus_emqx_r4_artifact as artifact
import focus_emqx_r4_prepare as prepare
import focus_emqx_r4_cached_images as images
from tests.e2e.lab.focus_emqx_r4_tests import runtime_parts


def own_parts(*names):
    tree=ast.parse((HERE/'focus_emqx_r4_producer_runtime.py').read_text())
    nodes=[node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in names]
    base=runtime_parts('Runner');scope={'rt':SimpleNamespace(Runner=base['Runner']),'profile':profile,'re':re,'io':io,'tarfile':tarfile}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),'<owned-producer>','exec'),scope)
    return scope


class ProfileBoundaries(unittest.TestCase):
    def test_destination_literal_client_must_resolve_to_exact_client_config(self):
        tree=ast.parse((HERE/'focus_emqx_r4_inner.py').read_text())
        node=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='require_loaded_client')
        scope={'artifact':artifact};exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),'<client-binding>','exec'),scope)
        pod=mock.Mock(return_value=SimpleNamespace(stdout=(artifact.IMAGES['client']+'\n').encode()))
        scope['require_loaded_client'](pod)
        pod.assert_called_once_with('image','inspect',artifact.CLIENT_REF,'--format','{{.Id}}')
        pod.return_value.stdout=(artifact.IMAGES['broker']+'\n').encode()
        self.assertRaisesRegex(ValueError,'client_config_mismatch',scope['require_loaded_client'],pod)

    def test_one_immutable_profile_binds_package_bootstrap_environment_and_files(self):
        source=json.loads((ROOT/'snippets/focus-emqx-r4/package-provision-source.json').read_text())
        self.assertEqual(profile.PACKAGE_FILES,source['files']);self.assertEqual(profile.PACKAGE_COMMIT,source['commit'])
        first=profile.receipt();first['definition']['effective_environment'].clear()
        self.assertEqual(profile.receipt()['definition']['effective_environment']['EMQX_NODE__NAME'],'emqx@127.0.0.1')
        self.assertEqual(profile.receipt()['definition']['initial_target_cluster_config'],{})
        self.assertEqual(profile.receipt()['definition']['bootstrap_metadata'],'400:1000:1000')
        self.assertIn('/opt/emqx/etc/woow-mqtt-bootstrap.csv',profile.material_hashes())
        self.assertIn('0.0.0.0:18093',profile.ENV['EMQX_DASHBOARD__LISTENERS__HTTP__BIND'])
        self.assertFalse(any(x.startswith(('EMQX_AUTHENTICATION','EMQX_AUTHORIZATION')) for x in profile.ENV))

    def test_actual_candidate_material_read_is_fixed_and_rejects_missing_or_changed_bytes(self):
        wanted=profile.material_hashes()
        output=''.join(value+'  '+path+'\n' for path,value in wanted.items()).encode()
        tmp=SimpleNamespace(exec=mock.Mock(side_effect=[SimpleNamespace(returncode=0,stdout=output),SimpleNamespace(returncode=0,stdout=b'400:1000:1000\n')]))
        artifact.verify_profile_material(tmp)
        self.assertEqual(tmp.exec.call_args_list[0].args,('emqx-new',['sha256sum',*wanted]))
        tmp.exec=mock.Mock(return_value=SimpleNamespace(returncode=1,stdout=b''))
        self.assertRaisesRegex(ValueError,'material_missing',artifact.verify_profile_material,tmp)
        tmp.exec=mock.Mock(return_value=SimpleNamespace(returncode=0,stdout=output.replace(next(iter(wanted.values())).encode(),b'0'*64)))
        self.assertRaisesRegex(ValueError,'material_hash',artifact.verify_profile_material,tmp)

    def test_bootstrap_metadata_is_mandatory_even_when_file_hashes_match(self):
        output=''.join(value+'  '+path+'\n' for path,value in profile.material_hashes().items()).encode()
        tmp=SimpleNamespace(exec=mock.Mock(side_effect=[SimpleNamespace(returncode=0,stdout=output),SimpleNamespace(returncode=0,stdout=b'644:1019:1019\n')]))
        self.assertRaisesRegex(ValueError,'bootstrap_metadata',artifact.verify_profile_material,tmp)

    def test_package_file_bind_keeps_original_foreign_target_and_resource_guards(self):
        scope=own_parts('PackageRunner');runner=scope['PackageRunner']();volume='woowbk-offline-r4-package-files'
        source='/home/appowner/.local/share/containers/storage/volumes/'+volume+'/_data/base.hocon'
        runner.profile_volume=volume;runner.profile_bindings={source:'/opt/emqx/etc/base.hocon'}
        def args(mount):return ['run','--name','woowbk-offline-r4-source','--memory','768m','--network','none','--pull=never',
                                '--volume',mount,artifact.IMAGES['broker']]
        runner.validate(args(source+':/opt/emqx/etc/base.hocon:ro'))
        for mount in [source+':/opt/emqx/etc/base.hocon:rw',source+':/etc:ro','/etc:/fixture:ro']:
            self.assertRaises(ValueError,runner.validate,args(mount))
        self.assertRaises(ValueError,runner.validate,args(source+':/opt/emqx/etc/base.hocon:ro')+['--publish','1883:1883'])

    def test_package_target_files_have_actual_uid_and_private_bootstrap_from_owned_volume(self):
        scope=own_parts('package_mounts');runner=SimpleNamespace(profile_bindings={},podman=mock.Mock(
            return_value=SimpleNamespace(stdout=b'/home/appowner/store/volumes/woowbk-offline-r4-package-files/_data\n')))
        archives=[]
        def imported(role,writer):
            stream=io.BytesIO();writer(stream);stream.seek(0)
            with tarfile.open(fileobj=stream) as archive:archives.extend((x.name,x.uid,x.gid,x.mode) for x in archive)
        tmp=SimpleNamespace(volume=mock.Mock(),name=lambda _: 'woowbk-offline-r4-package-files',volume_import=imported)
        mounts=scope['package_mounts'](tmp,runner,{'config/base.hocon':b'base','config/acl.conf':b'acl'},(1000,1000))
        self.assertIn(('bootstrap.csv',1000,1000,0o400),archives);self.assertEqual(len(mounts),3)
        self.assertTrue(all(mode=='ro' for _,_,mode in mounts))
        self.assertRaises(ValueError,scope['package_mounts'],tmp,runner,{},(1001,1001))


class PreparationLeaseBoundaries(unittest.TestCase):
    def lease(self,phase='producer'):
        return {'expires':'2026-11-27T01:00:00+00:00','phase':phase,'generated_case':'noauth' if phase=='producer' else None,
            'case':'EMQX-R4-package-producer:noauth' if phase=='producer' else 'EMQX-R4-cached-image-export',
            'source_commit':'a'*40,'device':'woowbk-dev-d','profile_sha256':profile.receipt()['sha256'],
            'image_configs':dict(artifact.IMAGES),'package_commands':False,'inputs':'controlled-generated-only',
            'artifact_export':True,'payload_token':'012345abcdef',
            'output_dir':str(prepare.STATE/('emqx-r4-prepared-'+('producer-noauth' if phase=='producer' else 'images')+'-012345abcdef'))}

    def test_plan_has_no_native_process_or_source_export(self):
        with mock.patch('subprocess.run',side_effect=AssertionError('no native')):
            with mock.patch('sys.stdout',new_callable=io.StringIO) as output:self.assertEqual(prepare.main([]),0)
        doc=json.loads(output.getvalue());self.assertFalse(doc['native_executed']);self.assertFalse(doc['pull_load_tag_install_or_upgrade'])

    def test_old_generated_or_provisioning_lease_cannot_export_candidate_or_images(self):
        now=datetime.datetime(2026,11,27,tzinfo=datetime.timezone.utc)
        for phase in ('producer','images'):
            doc=self.lease(phase);prepare.validate_lease(doc,'a'*40,now=now)
            for key,value in [('case','EMQX-R4-generated:noauth'),('artifact_export',False),('package_commands',True),
                              ('source_commit','b'*40),('profile_sha256','0'*64),('image_configs',{}),
                              ('payload_token','../../original'),('output_dir','/home/appowner'),('device','woowbk-dev-e')]:
                with self.subTest(phase=phase,key=key):self.assertRaises(ValueError,prepare.validate_lease,dict(doc,**{key:value}),'a'*40,now=now)

    def test_recovery_requires_separate_cleanup_lease(self):
        doc=self.lease();now=datetime.datetime(2026,11,27,tzinfo=datetime.timezone.utc)
        self.assertRaises(ValueError,prepare.validate_lease,doc,'a'*40,cleanup=True,now=now)
        self.assertEqual(prepare.validate_lease(dict(doc,cleanup_only=True),'a'*40,cleanup=True,now=now)['payload_token'],doc['payload_token'])

    def test_transport_refuses_arbitrary_filename_before_any_read(self):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder);root=home/'woowbk-r4-prepare-012345abcdef';root.mkdir()
            with mock.patch('pathlib.Path.home',return_value=home),mock.patch('sys.argv',['read',str(root),'../foreign',str(128)]):
                self.assertRaises(AssertionError,exec,compile(prepare.READ_ONE,'<read-owned>','exec'),{})
        for source in (prepare.BOOTSTRAP,prepare.READ_ONE,prepare.CLEAN_PAYLOAD):ast.parse(source)

    def test_payload_cleanup_refuses_foreign_context_before_removal(self):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder);root=home/'woowbk-r4-prepare-012345abcdef';root.mkdir()
            context={'phase':'images','payload_token':'012345abcdef','source_commit':'a'*40}
            (root/'context.json').write_text(json.dumps(dict(context,source_commit='b'*40)))
            with mock.patch('pathlib.Path.home',return_value=home),mock.patch('sys.argv',['clean',json.dumps(context)]),\
                 mock.patch('shutil.rmtree') as removed:
                self.assertRaises(AssertionError,exec,compile(prepare.CLEAN_PAYLOAD,'<cleanup-owned>','exec'),{})
                removed.assert_not_called()

    def test_recovery_preserves_original_result_and_never_restarts_production(self):
        with tempfile.TemporaryDirectory() as folder:
            state=Path(folder);doc=self.lease('images');doc.update(cleanup_only=True,
                expires=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat(),
                output_dir=str(state/'emqx-r4-prepared-images-012345abcdef'))
            with mock.patch.object(prepare,'STATE',state):
                context=prepare.validate_lease(doc,'a'*40,cleanup=True)
                output=Path(doc['output_dir']);output.mkdir()
                original={'context':context,'native':{'ok':False,'reason':'original_failure'},'payload_removed':False}
                result=output/'result.json';result.write_text(json.dumps(original));doc['result_sha256']=artifact.sha_file(result,1024**2)
                lease_path=state/'lease.json';lease_path.write_text(json.dumps(doc))
                fd=os.open(state/'owned-lock',os.O_CREAT|os.O_RDWR,0o600)
                guard=SimpleNamespace(head=lambda _: 'a'*40,clean_tree=lambda _:(True,[]),
                    verify_isolation=lambda _,**__:None,acquire=lambda **_:(fd,0))
                process=SimpleNamespace(returncode=0,stdout=b'owned_preparation_payload_removed\n',stderr=b'')
                with mock.patch.dict('sys.modules',{'dev_d_guard':guard}),mock.patch('subprocess.run',return_value=process) as run,\
                     mock.patch('sys.stdout',new_callable=io.StringIO):
                    self.assertEqual(prepare.main(['--run','--cleanup','--lease',str(lease_path)]),0)
                actual=json.loads(result.read_text());self.assertEqual(actual['native'],original['native']);self.assertTrue(actual['payload_removed'])
                self.assertEqual(run.call_count,1);self.assertIn(prepare.CLEAN_PAYLOAD,run.call_args.args[0])
                self.assertNotIn(prepare.BOOTSTRAP,run.call_args.args[0])

    def test_expired_cleanup_budget_refuses_before_any_device_command(self):
        with tempfile.TemporaryDirectory() as folder:
            state=Path(folder);doc=self.lease('images');doc.update(cleanup_only=True,
                expires=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat(),
                output_dir=str(state/'emqx-r4-prepared-images-012345abcdef'))
            with mock.patch.object(prepare,'STATE',state):
                context=prepare.validate_lease(doc,'a'*40,cleanup=True)
                output=Path(doc['output_dir']);output.mkdir()
                original={'context':context,'native':{'ok':False,'reason':'original_failure'},'payload_removed':False}
                result=output/'result.json';result.write_text(json.dumps(original));doc['result_sha256']=artifact.sha_file(result,1024**2)
                lease_path=state/'lease.json';lease_path.write_text(json.dumps(doc))
                fd=os.open(state/'owned-lock',os.O_CREAT|os.O_RDWR,0o600)
                guard=SimpleNamespace(head=lambda _:'a'*40,clean_tree=lambda _:(True,[]),
                    verify_isolation=lambda _,**__:None,acquire=lambda **_:(fd,0))
                with mock.patch.dict('sys.modules',{'dev_d_guard':guard}),mock.patch('subprocess.run') as run,\
                     mock.patch.object(prepare.time,'monotonic',side_effect=[0,301]),\
                     mock.patch('sys.stdout',new_callable=io.StringIO):
                    self.assertEqual(prepare.main(['--run','--cleanup','--lease',str(lease_path)]),1)
                run.assert_not_called();self.assertEqual(json.loads(result.read_text()),original)


class CacheExportBoundaries(unittest.TestCase):
    def test_actual_cached_inspect_argv_uses_go_ID_and_only_reviewed_metadata(self):
        template='{"id":{{json .ID}},"manifest":{{json .Digest}},"os":{{json .Os}},"arch":{{json .Architecture}},"size":{{.Size}},"repo_digests":{{json .RepoDigests}}}'
        for role,identity in artifact.IMAGES.items():
            doc={'id':identity,'manifest':'sha256:d4ec63c4065c745507e7652d9c0213134697dc1317d8a431b167ae7651c4e937',
                 'os':'linux','arch':'amd64','size':11516017,'repo_digests':[images.CLIENT_REPO_DIGEST]}
            pod=mock.Mock(return_value=json.dumps(doc).encode())
            self.assertEqual(images.inspect_cached(pod,role),doc)
            reference=artifact.CLIENT_REF if role=='client' else identity
            pod.assert_called_once_with('image','inspect',reference,'--format',template)
        pod=mock.Mock(side_effect=AssertionError('foreign image must not be inspected'))
        self.assertRaisesRegex(ValueError,'only_reviewed_cached_images',images.inspect_cached,pod,'customer-image')
        pod.assert_not_called()

    def test_only_three_cached_references_can_be_saved_no_pull_tag_or_container(self):
        for role in artifact.IMAGES:
            args=images.save_args(role,Path('/owned/artifact'))
            self.assertEqual(args[:4],['image','save','--format','oci-archive'])
            self.assertEqual(args[-1],artifact.CLIENT_REF if role=='client' else artifact.IMAGES[role])
            self.assertEqual(args[-2],'/owned/artifact/'+role+'.oci.tar')
        self.assertRaises(ValueError,images.save_args,'customer-image',Path('/owned/artifact'))

    def test_cache_metadata_must_bind_config_manifest_platform_and_client_literal(self):
        doc={'id':artifact.IMAGES['client'],'manifest':'sha256:'+'a'*64,'os':'linux','arch':'amd64','size':11516017,
             'repo_digests':[images.CLIENT_REPO_DIGEST]}
        self.assertEqual(images.cached_record(json.dumps(doc),'client'),doc)
        for key,value in [('id',artifact.IMAGES['broker']),('arch','arm64'),('manifest','unknown'),('repo_digests',[])]:
            self.assertRaises(ValueError,images.cached_record,json.dumps(dict(doc,**{key:value})),'client')
        broker=dict(doc,id=artifact.IMAGES['broker']);self.assertRaisesRegex(ValueError,'broker_manifest',images.cached_record,json.dumps(broker),'broker')

    def test_all_preparation_sources_parse_without_native_import_or_execution(self):
        for name in ('profile','prepare','producer_runtime','cached_images'):
            ast.parse((HERE/('focus_emqx_r4_'+name+'.py')).read_text())


if __name__=='__main__':unittest.main()
