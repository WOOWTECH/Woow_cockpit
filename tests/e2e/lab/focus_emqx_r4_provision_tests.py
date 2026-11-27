"""Offline trust/resource/cleanup boundaries. No Podman, device, package shell or network execution."""
import ast
import copy
import datetime
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(HERE))
import focus_emqx_r4_artifact as artifact
import focus_emqx_r4_provision as provision
import focus_emqx_r4_client_guard as client

DEVICE='woowbk-r4-package-012345abcdef'
COMMIT='a'*40
NOW=datetime.datetime(2026,11,27,tzinfo=datetime.timezone.utc)


def tar(path, entries):
    with tarfile.open(path,'w') as out:
        for name,data,kind in entries:
            item=tarfile.TarInfo(name);item.uid=item.gid=1000;item.mode=0o600
            item.type=kind;item.size=len(data) if kind==tarfile.REGTYPE else 0
            out.addfile(item,io.BytesIO(data) if item.isfile() else None)


def record():
    return {'kind':'emqx-readback','version':1,'config_roots':{'authentication':'b'*64},
            'tables':{name:[1 if name=='emqx_admin' else 0,'c'*64] for name in artifact.TABLES}}


def lease():
    return {'expires':'2026-11-27T01:00:00+00:00','source_commit':COMMIT,'device':DEVICE,
        'case':'EMQX-R4-package-fixture:plain','base_image':artifact.BASE,'image_configs':dict(artifact.IMAGES),
        'inputs':'controlled-generated-only','installer_or_upgrader':False,'package_smoke':True,
        'data_sha256':'d'*64,'manifest_sha256':'e'*64,'image_archives':{x:'f'*64 for x in artifact.IMAGES}}


class ProvisionBoundaries(unittest.TestCase):
    def test_plan_has_no_process_and_requires_separate_provision_lease(self):
        with mock.patch('subprocess.run',side_effect=AssertionError('no native')):
            with mock.patch('sys.stdout',new_callable=io.StringIO) as output: self.assertEqual(provision.main([]),0)
        plan=json.loads(output.getvalue());self.assertFalse(plan['native_executed']);self.assertEqual(plan['dev_d_commands'],0)
        doc=lease();self.assertEqual(provision.validate_lease(doc,COMMIT,now=NOW),DEVICE)
        for key,value in [('device','woowbk-dev-d'),('source_commit','b'*40),('case','EMQX-R4-generated:plain'),
                          ('installer_or_upgrader',True),('inputs','real-source'),('expires','2026-11-27T00:15:00+00:00'),
                          ('image_configs',{}),('base_image','wrong'),('image_archives',{})]:
            with self.subTest(key=key):self.assertRaises(ValueError,provision.validate_lease,dict(doc,**{key:value}),COMMIT,now=NOW)

    def test_outer_create_exact_three_owned_volumes_none_no_ports_and_cap(self):
        controller=provision.Controller(DEVICE,run=mock.Mock())
        args=controller.create_args()
        self.assertEqual(args[args.index('--network')+1],'none')
        self.assertIn('--image-volume=ignore',args);self.assertIn('--pull=never',args)
        self.assertEqual(args[args.index('--memory')+1],'2304m');self.assertEqual(args[args.index('--memory-swap')+1],'2304m')
        self.assertNotIn('--publish',args);self.assertNotIn('-p',args)
        self.assertEqual({args[i+1] for i,x in enumerate(args) if x=='--volume'},
                         {x+':'+y for x,y in provision.volumes(DEVICE).items()})
        for call in [('exec','-i','woowbk-dev-d','true',DEVICE),('rm','--force','--volumes','woowbk-dev-d',DEVICE),
                     ('volume','rm','foreign',DEVICE),('pull',artifact.BASE),('run',*args[1:],'--publish','1883:1883')]:
            self.assertRaises(ValueError,controller.call,*call)
        controller.run.assert_not_called()

    def test_cleanup_needs_prior_absence_intent_label_and_exact_owned_names(self):
        run=mock.Mock(return_value=subprocess.CompletedProcess([],0,b'',b''));controller=provision.Controller(DEVICE,run=run)
        self.assertRaises(ValueError,controller.cleanup,{'device':DEVICE,'absent_before':False});run.assert_not_called()
        responses=[subprocess.CompletedProcess([],1,b'',b''),subprocess.CompletedProcess([],0,b'',b''),
                   subprocess.CompletedProcess([],0,b'foreign-label\n',b'')]
        run.side_effect=responses
        self.assertRaisesRegex(ValueError,'foreign_volume_label',controller.cleanup,
            {'device':DEVICE,'absent_before':True,'volume_create_intended':list(provision.volumes(DEVICE))})
        self.assertFalse(any('rm' in c.args[0] for c in run.call_args_list))

    def test_low_resource_floor_does_not_prevent_exact_owned_cleanup(self):
        run=mock.Mock(return_value=subprocess.CompletedProcess([],0,b'',b''));controller=provision.Controller(DEVICE,run=run)
        with mock.patch.object(provision,'resource_floor',side_effect=ValueError('low')):
            self.assertRaises(ValueError,controller.call,*controller.create_args());run.assert_not_called()
            controller.call('rm','--force','--volumes',DEVICE,cleanup=True)
        self.assertEqual(run.call_count,1)

    def test_cleanup_inventory_difference_never_marks_complete(self):
        receipt={'cleanup_complete':False,'before_inventory_sha256':'a'*64}
        controller=SimpleNamespace(cleanup=mock.Mock(),inventory=lambda:[['unexpected'],[],[]])
        self.assertRaisesRegex(ValueError,'inventory_changed',provision.finish_cleanup,controller,receipt)
        self.assertFalse(receipt['cleanup_complete']);controller.cleanup.assert_called_once_with(receipt)

    def test_package_source_is_eleven_hash_bound_files_without_install_upgrade(self):
        doc=json.loads((ROOT/'snippets/focus-emqx-r4/package-provision-source.json').read_text())
        self.assertEqual(doc['commit'],'ea5886c58ef2c6ab1f4e6a4d01908cc9dc4525de');self.assertEqual(len(doc['files']),11)
        self.assertFalse(doc['installer_or_upgrader_included']);self.assertFalse(doc['working_tree_used'])
        self.assertTrue(all(artifact.HASH.fullmatch(x) for x in doc['files'].values()))
        self.assertFalse(any('install' in x or 'upgrade' in x for x in doc['files']))


class ArtifactBoundaries(unittest.TestCase):
    def test_candidate_lease_binds_bytes_profile_and_nonempty_admin(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);data=path/'candidate.tar';manifest=path/'candidate.json'
            tar(data,[('configs/cluster.hocon',b'{}',tarfile.REGTYPE),('mnesia/owned.DCD',b'generated',tarfile.REGTYPE)])
            data_sha=artifact.sha_file(data,artifact.MAX_DATA)
            doc={'kind':'owned-generated-emqx-candidate','version':1,'profile':artifact.PROFILE,'case':'plain',
                'source_commit':COMMIT,'image':artifact.IMAGES['broker'],'data_sha256':data_sha,
                'profile_sha256':artifact.profile.receipt()['sha256'],'target_record':record(),
                'origin':'controlled-generated-only','restart_checked':True,'vendor_postcheck':True,
                'exact_configuration_and_tables':True,'record':record()}
            def verify(value):
                manifest.write_text(json.dumps(value))
                return artifact.verify_candidate(data,manifest,case='plain',source_commit=COMMIT,data_sha=data_sha,
                    manifest_sha=artifact.sha_file(manifest,256*1024))
            verify(doc)
            for key,value in [('profile','broker-only'),('profile_sha256','0'*64),('origin','real-backup'),('restart_checked',False),('vendor_postcheck',False)]:
                with self.subTest(key=key):self.assertRaises(ValueError,verify,dict(doc,**{key:value}))
            bad=copy.deepcopy(doc);bad['record']['tables']['emqx_admin'][0]=0;self.assertRaises(ValueError,verify,bad)
            data.write_bytes(b'changed');self.assertRaises((ValueError,tarfile.ReadError),verify,doc)

    def test_generated_data_refuses_links_traversal_code_and_duplicate_members(self):
        good=[('configs/cluster.hocon',b'{}',tarfile.REGTYPE),('mnesia/owned.DCD',b'ok',tarfile.REGTYPE)]
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'candidate.tar'
            for entry in [('mnesia/link',b'',tarfile.SYMTYPE),('../elsewhere',b'x',tarfile.REGTYPE),
                          ('plugins/plugin.beam',b'x',tarfile.REGTYPE),('mnesia/code.beam',b'x',tarfile.REGTYPE),good[0]]:
                with self.subTest(path=entry[0]):
                    tar(path,good+[entry]);self.assertRaises(ValueError,artifact.verify_data_tar,path)

    def test_image_compressed_and_expanded_layer_hashes_bind_exact_config(self):
        # Tiny generated OCI archive, no image code. Test production verifier without replacing any pin.
        layer=b'owned-generated-layer';compressed=gzip.compress(layer,mtime=0)
        digest=lambda b:hashlib.sha256(b).hexdigest()
        def make(path,bad_diff=False,corrupt=False):
            config=json.dumps({'os':'linux','architecture':'amd64','rootfs':{'diff_ids':['sha256:'+('0'*64 if bad_diff else digest(layer))]}}).encode()
            desc=lambda b:{'digest':'sha256:'+digest(b),'size':len(b)}
            manifest=json.dumps({'config':desc(config),'layers':[desc(compressed)]}).encode()
            entries=[('oci-layout',b'{"imageLayoutVersion":"1.0.0"}',tarfile.REGTYPE),
                     ('index.json',json.dumps({'manifests':[desc(manifest)]}).encode(),tarfile.REGTYPE)]
            entries += [('blobs/sha256/'+digest(b),b if not(corrupt and b==compressed) else b'x'*len(b),tarfile.REGTYPE)
                        for b in [config,manifest,compressed]]
            tar(path,entries);return 'sha256:'+digest(config)
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'image.tar';identity=make(path);self.assertEqual(artifact.verify_oci(path,identity)['config'],identity)
            self.assertRaisesRegex(ValueError,'pinned_config',artifact.verify_oci,path,'sha256:'+'0'*64)
            identity=make(path,bad_diff=True);self.assertRaisesRegex(ValueError,'image_diffid',artifact.verify_oci,path,identity)
            identity=make(path,corrupt=True);self.assertRaisesRegex(ValueError,'oci_blob_digest',artifact.verify_oci,path,identity)


class ClientAndUnitBoundaries(unittest.TestCase):
    def test_package_active_healthcheck_is_real_and_only_for_owned_containers(self):
        for name in ('woow-emqx','woow-emqx-entrance'):
            args=['healthcheck','run',name]
            self.assertEqual(client.guarded_args(args,'/owned/scratch'),args)
        self.assertRaises(ValueError,client.guarded_args,['healthcheck','run','customer-app'],'/owned/scratch')
        self.assertRaises(ValueError,client.guarded_args,['healthcheck','run','customer-app','woow-emqx'],'/owned/scratch')

    def test_real_client_keeps_auth_command_and_network_adds_only_resource_bounds(self):
        command=['mosquitto_pub','-h','woow-emqx','-p','1883','-t','woow/smoke/owned','-m','owned','-q','1']
        args=['run','--rm','--pull=missing','--network','woow_emqx_network',client.CLIENT,*command]
        bounded=client.guarded_args(args,'/owned/scratch')
        self.assertEqual(bounded[bounded.index(client.CLIENT)+1:],command);self.assertIn('--pull=never',bounded)
        self.assertIn('--image-volume=ignore',bounded);self.assertIn('--memory=128m',bounded)
        for wrong in [args[:5]+['-v','/etc:/cfg:ro',*args[5:]],
                      [x if x!='woow-emqx' else 'foreign' for x in args],args[:5]+['foreign-image',*command]]:
            self.assertRaises(ValueError,client.guarded_args,wrong,'/owned/scratch')
        with tempfile.TemporaryDirectory() as folder:
            auth=args[:5]+['-e','XDG_CONFIG_HOME=/cfg','-v',folder+'/cfg:/cfg:ro',*args[5:]]
            self.assertIn(folder+'/cfg:/cfg:ro',client.guarded_args(auth,folder))
            self.assertRaises(ValueError,client.guarded_args,auth,'/different-owned-root')
        self.assertRaises(ValueError,client.guarded_args,['secret','inspect','real-customer-secret'],'/owned/scratch')

    def test_unit_rendering_preserves_actual_ports_volumes_env_and_real_checks(self):
        tree=ast.parse((HERE/'focus_emqx_r4_inner.py').read_text())
        node=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='render_unit')
        scope={'artifact':artifact};exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),'<unit-render>','exec'),scope)
        # Representative trusted template tests port rendering + no missing template passthrough, not an expected-state broker stub.
        body='[Container]\nImage=pinned\nVolume=emqx-data.volume:/opt/emqx/data\nPublishPort=@@EMQX_PUBLISH_MQTT@@:1883\nHealthCmd=emqx ctl status\n[Service]\n'
        out=scope['render_unit']('emqx.container',body)
        self.assertIn('PublishPort=127.0.0.1:1883:1883',out);self.assertIn('HealthCmd=emqx ctl status',out)
        self.assertIn('Environment="ERL_AFLAGS=+S 1:1"',out);self.assertIn('Volume=emqx-data.volume:/opt/emqx/data',out)
        self.assertIn(artifact.IMAGES['broker'],out);self.assertIn('--image-volume=ignore',out)
        self.assertRaises(ValueError,scope['render_unit'],'emqx.container','@@UNKNOWN@@')


if __name__=='__main__':unittest.main()
