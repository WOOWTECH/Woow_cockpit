"""One successor-case boundary: image provenance and exclusive receipts only."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import focus_litellm_instance_acceptance_new_case as n
from focus_litellm_instance_acceptance_images_verify_test import fixture


class NewCaseTests(unittest.TestCase):
    def test_new_host_and_root_receipts_reuse_original_proof_without_resetting_old_case(self):
        facts,args=fixture()
        facts=json.loads(json.dumps(facts).replace(args['derived'],n.DERIVED))
        for inventory in (facts['state']['before'],facts['state']['image_build']['before'],
                          facts['state']['image_build']['after'],facts['current']):
            inventory['containers']={name:format(i+1,'064x') for i,name in enumerate(n.source.ops.SELECTED)}
            inventory['running']=sorted(n.source.ops.SELECTED)
        prior={'name':n.OLD,'before':facts['state']['before'],'derived_image':n.DERIVED,
               'complete':True,'full_safety':None,'jobs':{},'pending':None,
               'generated_credentials':{'OLD_CASE_TEST_ONLY':'keep-old-value'}}
        output={'driver_commit':'f39666e9162f9c581e172256b574f5718a0fbf77',
                'source_commit':n.source.ops.NEW,'phase':'flow','complete':True,'phase_succeeded':False,
                'flow_verified':False,'checks':[{'check':k,'ok':True} for k in n.CHECKS]}
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);paths={name:root/(name+'.json') for name in ('image_capture','old_receipt','old_output','flow_receipt','pause_receipt')}
            for key,value in (('image_capture',{'facts':facts}),('old_receipt',prior),('old_output',output)):
                n.source.save(paths[key],value)
            originals={p:p.read_bytes() for p in list(paths.values())[:3]}
            sha=n.source.ops.digest(paths['image_capture'].read_bytes())
            prior_sha=n.source.ops.digest(paths['old_receipt'].read_bytes());output_sha=n.source.ops.digest(paths['old_output'].read_bytes())
            with patch.object(n,'CAPTURE_SHA',sha),patch.object(n,'CLEANUP_RECEIPT_SHA',prior_sha),\
                 patch.object(n,'CLEANUP_OUTPUT_SHA',output_sha),\
                 patch.object(n.source,'payload',return_value={'sha256':args['source_hashes']}):
                result=n.prepare(**paths)
                with self.assertRaisesRegex(ValueError,'exclusive'):n.prepare(**paths)
            flow=json.loads(paths['flow_receipt'].read_text());pause=json.loads(paths['pause_receipt'].read_text())
            self.assertEqual(flow['name'],n.NEW);self.assertNotIn('before',flow)
            self.assertNotIn('generated_credentials',flow);self.assertFalse(flow['install_intent']);self.assertFalse(flow['complete'])
            self.assertEqual(pause['purpose'],'pause-admission-only');self.assertEqual(pause['before'],facts['current'])
            self.assertEqual(result['baseline_sha256'],n.source.ops.digest(n.source.ops.canonical(facts['current'])))
            self.assertEqual(flow['owned_images'],[])
            self.assertEqual(facts['configs'][n.DERIVED]['case'],n.OLD)
            for p,b in originals.items():self.assertEqual(p.read_bytes(),b)
            ops=n.images.driver.ops;real_store=ops.Store;real_atomic=ops.atomic;uid=os.geteuid;parent=root/'device'
            old=real_store(n.OLD,parent=parent,create=True)
            old.state={'package_cleaned':True,'image_build':facts['state']['image_build']};old.save()
            old_bytes=(old.path/'state.json').read_bytes()
            def store(name,**kw):
                with patch.object(ops.os,'geteuid',uid):return real_store(name,parent=parent,**kw)
            def atomic(*a,**kw):
                kw['uid']=uid()
                with patch.object(ops.os,'geteuid',uid):return real_atomic(*a,**kw)
            with patch.object(ops.os,'geteuid',return_value=0),patch.object(ops,'Store',side_effect=store),\
                 patch.object(ops,'atomic',side_effect=atomic),patch.object(ops,'CATALOG',str(root/'absent-catalog.json')),\
                 patch.object(ops,'inventory',return_value=facts['current']),\
                 patch.dict(ops.RETAINED_IMAGE,verification_sha256=sha,
                            cleanup_receipt_sha256=prior_sha,cleanup_output_sha256=output_sha):
                self.assertEqual(ops.dispatch({'op':'init','case':n.NEW,'image_reuse':flow['image_reuse']}),facts['current'])
                with self.assertRaises(FileExistsError):ops.dispatch({'op':'init','case':n.NEW,'image_reuse':flow['image_reuse']})
            state=json.loads((parent/n.NEW/'state.json').read_text())
            self.assertEqual(state['image_reuse']['root_prior_sha256'],ops.digest(old_bytes))
            self.assertEqual((old.path/'state.json').read_bytes(),old_bytes)


class FreshBaselineTests(unittest.TestCase):
    """The post-R8 inventory may become the new strict baseline ONLY for ids R8 recreated (Hermes and Omnigent)."""
    def capture(self,facts,**changes):
        current=copy.deepcopy(facts['current'])
        for key,value in changes.items():
            section,name=key.split('__',1);current.setdefault(section,{})[name.replace('_','-')]=value
        names=list(n.source.ops.SELECTED)
        current['selected']={name:{'image':format(i+1,'064x'),'quadlet':'/q/'+name} for i,name in enumerate(names)}
        return {'transport_returncode':0,'source_commit':n.source.ops.NEW,
                'r8_original_images':{name:format(i+1,'064x')[:12] for i,name in enumerate(names)},
                'samples':[{'current':current,'configs':copy.deepcopy(facts['configs'])}]}

    def facts(self):
        facts,args=fixture()
        facts=json.loads(json.dumps(facts).replace(args['derived'],n.DERIVED))
        for inventory in (facts['state']['before'],facts['state']['image_build']['before'],
                          facts['state']['image_build']['after'],facts['current']):
            inventory['containers']={name:format(i+1,'064x') for i,name in enumerate(n.source.ops.SELECTED)}
            inventory['running']=sorted(n.source.ops.SELECTED)
        return facts,args

    def test_only_the_recreated_hermes_and_omnigent_ids_are_adopted(self):
        facts,_=self.facts();old=facts['current']
        fresh=self.capture(facts,containers__hermes_agent='a'*64,external_containers__omnigent_runner='d'*64,
                           secrets__hermes_api_server_key='b'*64,volumes__omnigent_server_data='c'*8)
        before,changed=n.adopt_fresh_before(old,facts['configs'],fresh)
        self.assertEqual(sorted(changed),['.containers.hermes-agent','.external_containers.omnigent-runner',
                                          '.secrets.hermes-api-server-key','.volumes.omnigent-server-data'])
        self.assertEqual(before['containers']['hermes-agent'],'a'*64);self.assertNotIn('selected',before)
        self.assertEqual(set(before),set(old))
        unchanged,none=n.adopt_fresh_before(old,facts['configs'],self.capture(facts))
        self.assertEqual((unchanged,none),(old,[]))

    def test_any_other_difference_or_incomplete_capture_is_refused(self):
        facts,_=self.facts();old=facts['current'];configs=facts['configs']
        def refuse(message,fresh):
            with self.subTest(message=message),self.assertRaisesRegex(ValueError,message):
                n.adopt_fresh_before(old,configs,fresh)
        refuse('outside',self.capture(facts,catalogs__litellm_json='f'*64))
        refuse('outside',self.capture(facts,containers__woow_emqx='9'*64))
        refuse('outside',self.capture(facts,containers__headscale='8'*64))
        refuse('outside',self.capture(facts,volumes__foreign_data='7'*8))
        listed=self.capture(facts);listed['samples'][0]['current']['images'].append('f'*64);refuse('outside',listed)
        timer=self.capture(facts);timer['samples'][0]['current']['timer']={'ActiveState':'active'};refuse('outside',timer)
        changed=self.capture(facts);changed['samples'][0]['configs']['x']={};refuse('image configs',changed)
        image=self.capture(facts);image['samples'][0]['current']['selected']['woow-emqx']['image']='f'*64
        refuse('no longer run',image)
        for key,value in (('transport_returncode',1),('samples',[]),('source_commit','0'*40)):
            refuse('incomplete',dict(self.capture(facts),**{key:value}))

    def test_prepare_puts_the_adopted_baseline_into_the_pause_admission_and_reports_its_hash(self):
        facts,args=self.facts()
        prior={'name':n.OLD,'before':facts['state']['before'],'derived_image':n.DERIVED,
               'complete':True,'full_safety':None,'jobs':{},'pending':None}
        output={'driver_commit':'f39666e9162f9c581e172256b574f5718a0fbf77',
                'source_commit':n.source.ops.NEW,'phase':'flow','complete':True,'phase_succeeded':False,
                'flow_verified':False,'checks':[{'check':k,'ok':True} for k in n.CHECKS]}
        fresh=self.capture(facts,containers__hermes_agent='a'*64,secrets__omnigent_admin_password='b'*64)
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);names=('image_capture','old_receipt','old_output','fresh_before','flow_receipt','pause_receipt')
            paths={name:root/(name+'.json') for name in names}
            for key,value in (('image_capture',{'facts':facts}),('old_receipt',prior),('old_output',output),
                              ('fresh_before',fresh)):n.source.save(paths[key],value)
            sha={key:n.source.ops.digest(paths[key].read_bytes()) for key in names[:4]}
            with patch.object(n,'CAPTURE_SHA',sha['image_capture']),patch.object(n,'CLEANUP_RECEIPT_SHA',sha['old_receipt']),\
                 patch.object(n,'CLEANUP_OUTPUT_SHA',sha['old_output']),patch.object(n,'FRESH_SHA',sha['fresh_before']),\
                 patch.object(n.source,'payload',return_value={'sha256':args['source_hashes']}):
                result=n.prepare(**paths)
                # A capture that is not the pinned file is refused before any receipt exists.
                with patch.object(n,'FRESH_SHA','0'*64),self.assertRaisesRegex(ValueError,'pin'):
                    n.prepare(**dict(paths,flow_receipt=root/'a.json',pause_receipt=root/'b.json'))
                self.assertFalse((root/'a.json').exists() or (root/'b.json').exists())
            pause=json.loads(paths['pause_receipt'].read_text())
            adopted={k:fresh['samples'][0]['current'][k] for k in facts['current']}
            self.assertEqual(pause['before'],adopted);self.assertNotEqual(pause['before'],facts['current'])
            self.assertEqual(result['baseline_sha256'],n.source.ops.digest(n.source.ops.canonical(adopted)))
            self.assertEqual(result['adopted_post_r8_id_changes'],2)


if __name__=='__main__':unittest.main()
