"""Successor case of a completed LiteLLM instance case: read-only capture and host-only exclusive receipts. No device."""
import copy
from datetime import datetime, timedelta, timezone
import fcntl
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import focus_litellm_instance_acceptance_successor as s

PRIOR='woowbk_focus_litellm_b7d2480c9e36'
NEW='woowbk_focus_litellm_c8e3591da0f7'


def digest(value):return s.source.ops.digest(s.source.ops.canonical(value))


class Fixture:
    def __init__(self,root):
        self.root=Path(root)
        self.before={'containers':{'woow-emqx':'a'*64,'hermes-agent':'b'*64},'images':['c'*64,'d'*64],'image_refs':{'x':'c'*64},
                     'catalogs':{'n8n.json':'e'*64},'files':{'/q/a':{'sha256':'f'*64}},'active_jobs':[],'package':False}
        reuse=dict(s.source.ops.common.RETAINED_IMAGE)
        self.prior={'name':PRIOR,'device':s.plan.DEVICE,'before':self.before,'complete':True,'recovery_verified':True,
                    'pending':None,'pending_operation':None,'catalog_intent':False,'pg_tag_intent':False,'hook_intent':False,
                    'timer_intent':False,'images_ready':True,'owned_images':[],'derived_image':reuse['derived_image'],
                    'image_reuse':reuse,'created_backups':['20261127T062347Z-b872183e','20261127T062657Z-cb247387'],
                    'before_backups':['20260101T000000Z-aaaaaaaa'],'store_id':'ha-own','before_uploads':['ha-old'],
                    'generated_credentials':{'OLD_CASE_TEST_ONLY':'never-copied'}}
        self.output={'phase':'recover','phase_succeeded':True,'complete':True,'recovery_verified':True,
                     'baseline_sha256':digest(self.before),
                     'checks':[{'check':c,'ok':True} for c in sorted(s.RECOVERY_CHECKS|{'outer_isolation_returned'})]}
        self.live={'device':s.plan.DEVICE,'case':PRIOR,'at':1,'inventory':copy.deepcopy(self.before),
                   'inventory_sha256':digest(self.before),'backup_ids':['20260101T000000Z-aaaaaaaa'],'ha_upload_ids':['ha-old']}

    def write(self,prior=None,output=None,live=None):
        paths={}
        for key,value in (('prior_receipt',prior or self.prior),('prior_output',output or self.output),('live',live or self.live)):
            paths[key]=self.root/(key+'.json');paths[key].write_bytes(s.source.ops.canonical(value));paths[key].chmod(0o600)
        return paths

    def arguments(self,paths,**changes):
        base=dict(prior_receipt=paths['prior_receipt'],prior_receipt_sha=s.source.ops.digest(paths['prior_receipt'].read_bytes()),
                  prior_output=paths['prior_output'],prior_output_sha=s.source.ops.digest(paths['prior_output'].read_bytes()),
                  live=paths['live'],live_sha=s.source.ops.digest(paths['live'].read_bytes()),new_name=NEW,
                  flow_receipt=self.root/'flow.private.json',pause_receipt=self.root/'pause.private.json')
        return dict(base,**changes)


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.f=Fixture(self.tmp.name)

    def test_two_private_exclusive_receipts_without_the_predecessors_credentials_or_state(self):
        paths=self.f.write();kwargs=self.f.arguments(paths);originals={p:p.read_bytes() for p in paths.values()}
        result=s.prepare(**kwargs)
        flow=json.loads(kwargs['flow_receipt'].read_text());pause=json.loads(kwargs['pause_receipt'].read_text())
        self.assertEqual(flow['name'],NEW);self.assertNotIn('before',flow);self.assertNotIn('generated_credentials',flow)
        self.assertEqual((flow['created_backups'],flow['jobs'],flow['full_safety'],flow['pending']),([],{},None,None))
        for key in ('install_intent','complete','recovery_verified','safety_verified','catalog_intent','timer_intent','hook_intent'):
            self.assertFalse(flow[key],key)
        self.assertTrue(flow['images_ready']);self.assertEqual(flow['owned_images'],[])
        self.assertEqual(flow['image_reuse'],s.source.ops.common.RETAINED_IMAGE)
        self.assertEqual(pause['purpose'],'pause-admission-only');self.assertEqual(pause['before'],self.f.before)
        self.assertEqual(pause['name'],NEW)
        for path in (kwargs['flow_receipt'],kwargs['pause_receipt']):self.assertEqual(path.stat().st_mode&0o777,0o600)
        self.assertEqual(result['baseline_sha256'],digest(self.f.before));self.assertEqual(result['predecessor'],PRIOR)
        for p,b in originals.items():self.assertEqual(p.read_bytes(),b)        # the predecessor's files are never touched
        with self.assertRaisesRegex(ValueError,'exclusive'):s.prepare(**kwargs)  # never overwrites

    def test_a_flow_that_failed_and_recovered_by_itself_is_an_accepted_predecessor(self):
        # dev-d b8: the flow stopped at one check, its own recovery then completed (no outer-isolation check on that path)
        self.f.output.update(phase='flow',phase_succeeded=False,flow_verified=False,
                             checks=[{'check':c,'ok':True} for c in sorted(s.RECOVERY_CHECKS)])
        kwargs=self.f.arguments(self.f.write())
        self.assertEqual(s.prepare(**kwargs)['predecessor'],PRIOR)
        for label,mutate in (('the flow succeeded',lambda o:o.update(phase_succeeded=True)),
                             ('the flow was verified',lambda o:o.update(flow_verified=True)),
                             ('the flow verification is unknown',lambda o:o.pop('flow_verified')),
                             ('recovery incomplete',lambda o:o.update(complete=False)),
                             ('recovery unverified',lambda o:o.update(recovery_verified=False)),
                             ('a recovery check missing',lambda o:o.update(checks=o['checks'][1:])),
                             ('a recovery check failed',lambda o:o['checks'][0].update(ok=False))):
            with self.subTest(label),tempfile.TemporaryDirectory() as root:
                f=Fixture(root);f.output.update(phase='flow',phase_succeeded=False,flow_verified=False,
                                                checks=[{'check':c,'ok':True} for c in sorted(s.RECOVERY_CHECKS)]);mutate(f.output)
                kw=f.arguments(f.write())
                with self.assertRaises(ValueError):s.prepare(**kw)
                self.assertFalse(os.path.lexists(kw['flow_receipt']))

    def test_every_unproven_predecessor_or_device_state_is_refused_before_anything_is_written(self):
        cases=[('not complete',lambda f:f.prior.update(complete=False)),
               ('recovery not verified',lambda f:f.prior.update(recovery_verified=False)),
               ('pending job',lambda f:f.prior.update(pending={'tag':'x'})),
               ('pending operation',lambda f:f.prior.update(pending_operation={'operation':'x'})),
               ('pg tag intent left',lambda f:f.prior.update(pg_tag_intent=True)),
               ('timer intent left',lambda f:f.prior.update(timer_intent=True)),
               ('owns an image',lambda f:f.prior.update(owned_images=['x'])),
               ('images not ready',lambda f:f.prior.update(images_ready=False)),
               ('output of an unknown phase',lambda f:f.output.update(phase='images')),
               ('recover pass without the isolation proof',lambda f:f.output.update(checks=[c for c in f.output['checks'] if c['check']!='outer_isolation_returned'])),
               ('output failed',lambda f:f.output.update(phase_succeeded=False)),
               ('output incomplete',lambda f:f.output.update(complete=False)),
               ('output without recovery',lambda f:f.output.update(recovery_verified=False)),
               ('output check failed',lambda f:f.output['checks'][0].update(ok=False)),
               ('output check missing',lambda f:f.output.update(checks=f.output['checks'][1:])),
               ('output belongs to another baseline',lambda f:f.output.update(baseline_sha256='0'*64)),
               ('foreign image record',lambda f:f.prior['image_reuse'].update(from_case='woowbk_focus_litellm_000000000000')),
               ('image mismatch',lambda f:f.prior.update(derived_image='0'*64)),
               ('live inventory differs',lambda f:f.live['inventory']['containers'].update({'hermes-agent':'9'*64})),
               ('live inventory lost an image',lambda f:f.live['inventory'].update(images=['c'*64])),
               ('live capture of another device',lambda f:f.live.update(device='woowbk-dev-c')),
               ('live capture digest wrong',lambda f:f.live.update(inventory_sha256='1'*64)),
               ('case backup still present',lambda f:f.live['backup_ids'].append('20261127T062347Z-b872183e')),
               ('preexisting backup missing',lambda f:f.live.update(backup_ids=[])),
               ('own upload still present',lambda f:f.live['ha_upload_ids'].append('ha-own')),
               ('preexisting upload missing',lambda f:f.live.update(ha_upload_ids=[]))]
        for label,mutate in cases:
            with self.subTest(label),tempfile.TemporaryDirectory() as root:
                f=Fixture(root);mutate(f)
                if label in ('live capture digest wrong',):pass
                else:
                    f.live['inventory_sha256']=digest(f.live['inventory']) if 'live' not in label or label=='live capture of another device' else f.live['inventory_sha256']
                kwargs=f.arguments(f.write())
                with self.assertRaises(ValueError):s.prepare(**kwargs)
                self.assertFalse(os.path.lexists(kwargs['flow_receipt']) or os.path.lexists(kwargs['pause_receipt']))

    def test_a_difference_names_the_inventory_field_it_found(self):
        self.f.live['inventory']['containers']['hermes-agent']='9'*64;self.f.live['inventory_sha256']=digest(self.f.live['inventory'])
        with self.assertRaisesRegex(ValueError,r'\.containers\.hermes-agent'):s.prepare(**self.f.arguments(self.f.write()))

    def test_pins_names_modes_and_paths(self):
        paths=self.f.write()
        for key,pin in (('prior_receipt_sha','prior_receipt'),('prior_output_sha','prior_output'),('live_sha','live')):
            with self.subTest(pin):
                with self.assertRaisesRegex(ValueError,'pin'):s.prepare(**self.f.arguments(paths,**{key:'0'*64}))
        paths['live'].chmod(0o644)
        with self.assertRaisesRegex(ValueError,'pin'):s.prepare(**self.f.arguments(paths))
        paths['live'].chmod(0o600)
        for name in (PRIOR,'not-a-case','woowbk_focus_litellm_ABCDEF012345'):
            with self.subTest(name),self.assertRaises(ValueError):s.prepare(**self.f.arguments(paths,new_name=name))
        same=self.f.root/'same.json'
        with self.assertRaises(ValueError):s.prepare(**self.f.arguments(paths,flow_receipt=same,pause_receipt=same))


class CaptureTests(unittest.TestCase):
    def transport(self,*,inventory=None,returncode=0,listing=None):
        calls=[]
        def root(*argv,input=None,timeout=0):
            calls.append((argv,json.loads(input)))
            return SimpleNamespace(returncode=returncode,stdout=json.dumps(inventory if inventory is not None else {'containers':{}}).encode(),stderr=b'')
        def helper(command,request=None,timeout=0):
            calls.append((command,request))
            return 0,listing if listing is not None else {'ok':True,'backups':[{'id':'b2'},{'id':'b1'}],'ha_backups':[{'id':'u1'}]}
        return SimpleNamespace(DEVICE=None,root=root,helper=helper,require_isolated_device=lambda:calls.append('isolated'),calls=calls)

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.lock=self.root/'lock';self.lock.write_bytes(b'')

    def test_capture_is_one_read_only_inventory_and_two_sorted_id_lists_in_a_private_file(self):
        t=self.transport(inventory={'containers':{'a':'1'}});out=self.root/'live.private.json'
        got=s.capture(out,transport=t,case=NEW,lock=str(self.lock),clock=lambda:1234.9)
        value=json.loads(out.read_text())
        self.assertEqual(value,{'device':s.plan.DEVICE,'case':NEW,'at':1234,'inventory':{'containers':{'a':'1'}},'looks':1,
            'inventory_sha256':digest({'containers':{'a':'1'}}),'backup_ids':['b1','b2'],'ha_upload_ids':['u1']})
        self.assertEqual(out.stat().st_mode&0o777,0o600);self.assertEqual(got,s.source.ops.digest(out.read_bytes()))
        self.assertEqual(t.DEVICE,s.plan.DEVICE)
        (argv,request),=[c for c in t.calls if isinstance(c,tuple) and c[0][:1]==('python3',)]
        self.assertEqual(argv[:4],('python3','-B','-I','-c'));self.assertEqual(argv[4],s.ops_source())
        self.assertEqual(request,{'op':'inventory','case':NEW})
        self.assertEqual([c for c in t.calls if isinstance(c,tuple) and not isinstance(c[0],tuple)],[('list',None)])  # the only helper request
        self.assertEqual(t.calls[0],'isolated')                                                                       # before anything else
        with self.assertRaisesRegex(ValueError,'unique'):s.capture(out,transport=t,case=NEW,lock=str(self.lock))

    def test_with_an_expected_baseline_the_capture_looks_again_past_the_failing_units_own_container(self):
        base={'containers':{'a':'1'}};flapping={'containers':{'a':'1','headscale':'9'}}
        answers=[flapping,flapping,base]
        t=self.transport();calls=t.calls
        def root(*argv,input=None,timeout=0):
            calls.append((argv,json.loads(input)))
            return SimpleNamespace(returncode=0,stdout=json.dumps(answers.pop(0) if len(answers)>1 else answers[0]).encode(),stderr=b'')
        t.root=root;slept=[]
        out=self.root/'live.private.json'
        s.capture(out,transport=t,case=NEW,lock=str(self.lock),expect=digest(base),sleep=slept.append)
        value=json.loads(out.read_text())
        self.assertEqual((value['inventory'],value['looks'],slept),(base,3,[2,2]))
        # a difference that never goes away: the last look is kept (and --prepare names it), after exactly `tries` looks
        t2=self.transport(inventory=flapping);out2=self.root/'live2.private.json'
        s.capture(out2,transport=t2,case=NEW,lock=str(self.lock),expect=digest(base),tries=4,sleep=lambda n:None)
        self.assertEqual((json.loads(out2.read_text())['looks'],len([c for c in t2.calls if isinstance(c,tuple) and c[0][:1]==('python3',)])),(4,4))

    def test_failures_write_nothing_and_a_busy_device_lock_refuses(self):
        out=self.root/'live.private.json'
        for label,t in (('operation failed',self.transport(returncode=1)),
                        ('list refused',self.transport(listing={'ok':False}))):
            with self.subTest(label),self.assertRaises(RuntimeError):s.capture(out,transport=t,case=NEW,lock=str(self.lock))
            self.assertFalse(out.exists())
        holder=os.open(self.lock,os.O_RDWR);fcntl.flock(holder,fcntl.LOCK_EX)
        self.addCleanup(os.close,holder)
        t=self.transport()
        with self.assertRaises(BlockingIOError):s.capture(out,transport=t,case=NEW,lock=str(self.lock))
        self.assertEqual(t.calls,[]);self.assertFalse(out.exists())

    def test_the_offline_default_does_nothing(self):
        with patch.object(s.source,'git',side_effect=AssertionError('no runtime')),patch('sys.stdout',new_callable=io.StringIO) as out:
            self.assertEqual(s.main([]),0)
        self.assertFalse(json.loads(out.getvalue())['writes'])


class ProductBindingTests(unittest.TestCase):
    def test_the_current_product_is_the_fix_and_the_images_phase_stays_on_the_historic_one(self):
        p=s.plan
        for value in (p.FROZEN_PRODUCT,p.HISTORIC_PRODUCT):self.assertRegex(value,r'[0-9a-f]{40}\Z')
        self.assertNotEqual(p.FROZEN_PRODUCT,p.HISTORIC_PRODUCT)
        self.assertEqual(p.HISTORIC_PRODUCT,s.source.ops.NEW)           # the retained image's verification is of that engine
        self.assertNotEqual(p.PRODUCT_DIR,p.HISTORIC_PRODUCT_DIR)
        lease={'granted':True,'case':'litellm-instance-images-verify','device':p.DEVICE,'driver_commit':'a'*40,'phases':['images-verify'],
               'method':s.images.METHOD,'name':'woowbk_focus_litellm_012345abcdef','bounds':s.images.BOUNDS,
               'derivation_sha256':p.DERIVATION_SHA,'baseline_sha256':'1'*64,'derived_image':'2'*64,
               'capture_filename':'c.json','output_filename':'o.json',
               'expires_utc':(datetime.now(timezone.utc)+timedelta(minutes=30)).isoformat()}
        args=SimpleNamespace(capture=Path('c.json'),output=Path('o.json'))
        s.images.validate(dict(lease,source_commit=p.HISTORIC_PRODUCT),args,'a'*40)      # the images phase stays on its own product
        with self.assertRaises(ValueError):
            s.images.validate(dict(lease,source_commit=p.FROZEN_PRODUCT),args,'a'*40)


if __name__=='__main__':unittest.main()
