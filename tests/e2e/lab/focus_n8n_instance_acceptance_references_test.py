"""Bounded offline tag-intent and actual rendered-wrapper regressions."""
from contextlib import redirect_stderr,redirect_stdout
import copy
from datetime import datetime,timezone
import io
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import focus_n8n_instance_acceptance_ops as common
import focus_n8n_instance_acceptance_references as prep
import focus_n8n_instance_acceptance_references_ops as refs

NAME='woowbk_focus_n8n_abcdef012345'


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.parent=self.root/'private'
        self.live={'durables':{'catalog':'original','images':sorted(refs.EXPECTED.values())},
            'source':{'all_files':'original','qualified_receipt':'unchanged'},'backups':{'all_originals':'exact'},
            'quadlet_refs':dict(refs.EXPECTED),'resolution':dict(refs.EXPECTED),
            'cache':{x:{'platform':['linux','amd64',''],'stable_fields_sha256':'fixed-'+x,
                        'tags':[],'history':[]} for x in refs.EXPECTED.values()}}
        for ref in refs.ALLOWED:self.live['resolution'][ref]=None
        for ref,config in self.live['resolution'].items():
            if config:self.live['cache'][config]['tags']=[ref]
        self.commands=[];self.lose_reply=False
        self.obj=refs.References(NAME,parent=self.parent,read=lambda _:copy.deepcopy(self.live))
        self.addCleanup(patch.stopall)
        patch.object(common,'owner',side_effect=self.owner).start()

    def owner(self,*args,**kwargs):
        self.commands.append(args)
        if args[:3]==('podman','image','exists'):
            return SimpleNamespace(returncode=1 if self.live['resolution'][args[3]] is None else 0,stdout=b'')
        if args[:3]==('podman','image','inspect'):
            self.assertEqual(args[4:],('--format','{{.ID}}'))
            config=self.live['resolution'][args[3]]
            return SimpleNamespace(returncode=0 if config else 125,stdout=(config or '').encode())
        if args[:2]==('podman','tag'):
            config=args[2].removeprefix('sha256:');ref=args[3]
            self.assertIsNone(self.live['resolution'][ref])
            # Real durable journal exists BEFORE the actual command boundary.
            s=json.loads((self.obj.store.path/'state.json').read_bytes())
            self.assertEqual(s['intents'][ref],{'config':config,'absent_observed':True,'done':False})
            self.assertEqual(s['before']['source'],self.live['source'])
            self.live['resolution'][ref]=config
            self.live['cache'][config]['tags'].append(ref)
            self.live['cache'][config]['history'].append(ref)
            if self.lose_reply: raise subprocess.TimeoutExpired('fixed tag fixture',1)
            return SimpleNamespace(returncode=0,stdout=b'')
        raise AssertionError('unknown or unsafe command at local fixture boundary')

    def test_only_missing_known_alias_is_bound_and_existing_alias_is_strict(self):
        runner=list(refs.ALLOWED)[1];config=refs.ALLOWED[runner]
        self.live['resolution'][runner]=config;self.live['cache'][config]['tags']=[runner]
        start=self.obj.begin();self.assertEqual(start['planned'],{next(iter(refs.ALLOWED)):next(iter(refs.ALLOWED.values()))})
        for ref in start['planned']:self.obj.bind(ref)
        result=self.obj.reconcile();self.assertTrue(result['complete'])
        self.assertEqual(len([x for x in self.commands if x[:2]==('podman','tag')]),1)
        self.assertTrue(result['protected_state_exact']);self.assertTrue(self.obj.store.state['retain_for_case'])

    def test_foreign_existing_reference_refuses_before_journal_or_mutation(self):
        self.live['resolution'][next(iter(refs.ALLOWED))]='f'*64
        with self.assertRaisesRegex(ValueError,'foreign'):self.obj.begin()
        self.assertFalse(self.obj.store.path.exists());self.assertEqual(self.commands,[])

    def test_interrupted_reply_is_reconciled_by_identity_without_repeating_tag(self):
        runner=list(refs.ALLOWED)[1];config=refs.ALLOWED[runner]
        self.live['resolution'][runner]=config;self.live['cache'][config]['tags']=[runner]
        self.obj.begin();ref=next(iter(refs.ALLOWED));self.lose_reply=True
        with self.assertRaises(subprocess.TimeoutExpired):self.obj.bind(ref)
        self.assertFalse(self.obj.store.state['intents'][ref]['done'])
        before=len(self.commands)
        restarted=refs.References(NAME,parent=self.parent,read=lambda _:copy.deepcopy(self.live))
        self.assertTrue(restarted.reconcile()['complete']);self.assertEqual(len(self.commands),before)
        with self.assertRaisesRegex(ValueError,'not-new'):restarted.bind(ref)
        self.live['resolution'][ref]='e'*64
        with self.assertRaisesRegex(ValueError,'foreign'):restarted.reconcile()
        self.assertEqual(len(self.commands),before)

    def test_changed_protected_state_or_unapproved_alias_stops_before_tag(self):
        for kind in ('source','backups','cache_fields','other_alias'):
            with self.subTest(kind=kind):
                parent=self.root/kind;obj=refs.References(NAME,parent=parent,read=lambda _:copy.deepcopy(self.live))
                original=copy.deepcopy(self.live);obj.begin()
                if kind in ('source','backups'):self.live[kind]['foreign']='change'
                else:
                    image=self.live['cache'][next(iter(refs.EXPECTED.values()))]
                    if kind=='cache_fields':image['stable_fields_sha256']='foreign'
                    else:image['tags'].append('docker.io/foreign/alias:1')
                with self.assertRaises(ValueError):obj.bind(next(iter(refs.ALLOWED)))
                self.assertEqual(self.commands,[]);self.live=original

    def test_actual_safety_calls_canonical_reference_before_copy_or_service_sql(self):
        for kind in ('main_missing','main_foreign','runner_missing','all_correct'):
            with self.subTest(kind=kind):
                self.live['resolution']=dict(refs.EXPECTED)
                if kind=='main_missing':self.live['resolution'][next(iter(refs.ALLOWED))]=None
                if kind=='main_foreign':self.live['resolution'][next(iter(refs.ALLOWED))]='e'*64
                if kind=='runner_missing':self.live['resolution'][list(refs.ALLOWED)[1]]=None
                self.commands=[];ops=[]
                transport=SimpleNamespace(owner=self.owner)
                lease={'name':NAME,'expires_utc':datetime.fromtimestamp(2000,timezone.utc).isoformat()}
                ctrl=prep.run.Controller(SimpleNamespace(source=prep.run.REPO,receipt=self.root/'receipt.json'),lease,transport,
                    clock=lambda:1000)
                ctrl.resources=lambda:None;ctrl.acquire_original=lambda:None;ctrl.frozen_engine=lambda:None
                def operation(op,**kwargs):
                    ops.append(op)
                    if op=='inventory':return {'images':list(refs.EXPECTED.values())}
                    raise LookupError('preservation reached only after valid references')
                ctrl.op=operation
                with redirect_stdout(io.StringIO()):
                    with self.assertRaises(LookupError if kind=='all_correct' else RuntimeError):ctrl.safety()
                # Missing main OR missing runner must refuse, even with ALL IDs cached.
                self.assertEqual(ops,['inventory','preserved_safety_prepare'] if kind=='all_correct' else ['inventory'])
                self.assertFalse(ctrl.r['timer_intent']);self.assertFalse(ctrl.r['catalog_intent'])
                self.assertFalse(any(x[:2]==('podman','tag') for x in self.commands))

    def test_offline_default_and_fixed_alias_lease_rejects_changed_binding(self):
        with patch.object(prep.run,'git',side_effect=AssertionError('no runtime')),redirect_stdout(io.StringIO()):
            self.assertEqual(prep.main([]),0)
        lease={'case':prep.CASE,'phases':list(prep.PHASES),'expected_references':refs.EXPECTED,
            'allowed_new_references':refs.ALLOWED,'source_fullflow_receipt_sha256':refs.SOURCE_RECEIPT_SHA,
            'bounds':prep.run.BOUNDS,'image_policy':'retain-for-case','granted':True,'device':prep.run.plan.DEVICE,
            'driver_commit':'a'*40,'source_commit':prep.run.FROZEN_PRODUCT,'catalog_sha256':prep.run.plan.FOUND_SHA,
            'name':NAME,'expires_utc':datetime.fromtimestamp(2000,timezone.utc).isoformat()}
        self.assertEqual(prep.validate(lease,prep.PHASES[0],'a'*40,prep.run.FROZEN_PRODUCT,1000),2000)
        for key,value in (('allowed_new_references',{}),('source_fullflow_receipt_sha256','f'*64),('granted',False)):
            with self.subTest(key=key),self.assertRaises(ValueError):
                prep.validate(dict(lease,**{key:value}),prep.PHASES[0],'a'*40,prep.run.FROZEN_PRODUCT,1000)

    def test_complete_rendered_reference_entry_loads_modules_dispatches_and_reconciles(self):
        self.obj.begin();module_names=[]
        original_modules=dict(sys.modules);original_prefix=sys.pycache_prefix
        for key in ('jobs.lock','engine.lock'):
            p=self.root/key;p.write_bytes(b'');p.chmod(0o600)
        actual_open=os.open;uid=os.geteuid()
        def local_open(path,*a,**k):
            p=os.fspath(path)
            if p.startswith('/run/woowtech-backup/'):p=str(self.root/Path(p).name)
            elif not p.startswith(str(self.root)+'/'):raise AssertionError('non-fixture open')
            return actual_open(p,*a,**k)
        def load(code,namespace):
            exec(code,namespace);module_names.append(namespace['__name__'])
            if namespace['__name__']=='focus_n8n_instance_acceptance_references_ops':
                namespace['References'].__init__.__kwdefaults__.update(parent=self.parent,read=lambda _:copy.deepcopy(self.live))
        stdout,stderr=io.StringIO(),io.StringIO()
        try:
            with patch('os.open',side_effect=local_open),patch('os.geteuid',side_effect=itertools.chain([0],itertools.repeat(uid))), \
                    patch('sys.stdin',SimpleNamespace(buffer=io.BytesIO(json.dumps({'case':NAME,'op':'reference-reconcile'}).encode()))), \
                    redirect_stdout(stdout),redirect_stderr(stderr):
                exec(compile(prep.dependencies()+prep.ENTRY,'<actual rendered reference wrapper>','exec'),{'__name__':'__main__','exec':load})
        finally:
            sys.pycache_prefix=original_prefix
            for key in module_names:
                if key in original_modules:sys.modules[key]=original_modules[key]
                else:sys.modules.pop(key,None)
        reply=json.loads(stdout.getvalue());self.assertTrue(reply['ok'])
        self.assertFalse(reply['result']['complete']);self.assertEqual(self.commands,[])


if __name__=='__main__':unittest.main()
