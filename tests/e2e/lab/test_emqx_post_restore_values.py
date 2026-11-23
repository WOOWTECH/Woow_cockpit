"""Generated native/process contracts only: no actual broker, lab or restore."""
import base64
from contextlib import contextmanager
import copy
import json
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_post_restore_values as m
import emqx_adapter_owner as owner
import emqx_owner_fixture_files as files
from emqx_private_boundary import PrivateFailure, Registry, SOURCES
from emqx_runtime_credentials import RuntimeRegistry, TARGET_CATEGORIES
from emqx_runtime_workflow import CombinedRegistry
from emqx_owner_target import _build
import test_emqx_owner_fixture_files as fixture_tests
from test_emqx_owner_fixture_files import GeneratedRunner
from test_emqx_owner_target import reply_document, cooked_config, binary, term


class GeneratedLabRunner(GeneratedRunner, owner.LabOwnerRunner):
    """Only process boundary substituted; no LabOwnerRunner runtime invocation."""


class PostNativeTests(unittest.TestCase):
    def setUp(self):
        # Actual OwnerProvision.create and file/secret issuance on generated files.
        with patch('test_emqx_owner_fixture_files.GeneratedRunner', GeneratedLabRunner):
            fixture_tests.FixtureFilesTests.setUp(self)
        self.doc[0]['HostConfig']['LogConfig'] = {'Type':'none'}
        self.old_cid = 'b'*64
        files._record(self.cap)[0]['cid'] = self.old_cid
        self.runner.podman = self.podman
        source = Registry()
        for category in SOURCES:
            source.register(category, [b'generated-old-source-key'] if category == 'backup-key' else [])
        source.seal()
        self.runtime = RuntimeRegistry()
        self.runtime.register_bundle({x:[] for x in TARGET_CATEGORIES}, target=True)
        self.prior = CombinedRegistry(source, self.runtime)
        self.events, self.commands, self.generations = [], [], []
        self.edit = None
        self.hash = b'generated-post-native-api-secret-hash'
        self.config = cooked_config()
        self.config['connectors'] = {'restored': {'password':'generated-connector-secret',
                                                'url':'https://unexecuted.example/path'}}
        self.config['rule_engine'] = {'rules': {'restored': {'sql':'SELECT payload FROM "restored/#"'}}}
        self.config['authentication'][0]['bootstrap_file'] = 'file:/unexecuted/reference.csv'
        self.config['api_key'] = {'bootstrap_file':'${UNEXECUTED_ENV}/input'}
        self.last_wire = None

    @contextmanager
    def quiesce(self):
        self.events.append('enter')
        try:
            yield
        finally:
            self.events.append('exit')

    def podman(self, *args, **kwargs):
        self.commands.append((args, kwargs))
        if args[:2] == ('container','inspect'):
            self.events.append('inspect')
            self.assertEqual(args[2], self.cid)
            self.assertEqual(kwargs, {'timeout':5,'max_output':files.LIMIT,'check':False})
            return SimpleNamespace(returncode=0, stdout=json.dumps(self.doc).encode())
        self.events.append('eval')
        self.assertEqual(args[:4], ('exec',self.cid,'emqx','eval'))
        self.assertEqual(kwargs, {'timeout':30,'max_output':m.MAX_WIRE,'check':False})
        expression = args[4]
        self.assertNotIn('\n',expression)
        self.assertNotIn('generated-connector-secret',expression)
        for native_check in ('mnesia:foldl','table_receipts','config_changed','provider_changed','emqx_cm:all_channels'):
            self.assertIn(native_check, expression)
        generation = re.search(r'generation => <<"([0-9a-f]{32})">>',expression)[1]
        self.generations.append(generation)
        doc = reply_document(generation,self.config)
        api = next(t for t in doc['tables'] if t['table']=='emqx_app')
        api['rows'] = [term('tuple',[term('atom',api['record_name'])] +
            [binary(self.hash if attr=='api_secret_hash' else ('generated-'+attr).encode())
             for attr in api['attributes']])]
        api['row_count'] = 1
        if self.edit:
            self.edit(doc)
        self.last_wire = b'WOOWTARGET:'+base64.b64encode(json.dumps(doc).encode())+b':ENDok\n'
        return SimpleNamespace(returncode=0,stdout=self.last_wire)

    def collect(self, prior=None, **changes):
        kwargs = dict(prior_registry=self.prior if prior is None else prior,
                      provision=self.provision, expected_container_id=self.cid, quiesce=self.quiesce)
        kwargs.update(changes)
        return m.collect_post_restore_values(**kwargs)

    def refuse(self, **changes):
        with self.assertRaisesRegex(PrivateFailure,'^post-native-values-refused$'):
            self.collect(**changes)

    def stage_of(self, **changes):
        with self.assertRaisesRegex(PrivateFailure,'^post-native-values-refused$') as caught:
            self.collect(**changes)
        self.assertIs(type(caught.exception),m.PostCaptureRefused)
        self.assertIn(caught.exception.stage,m.CAPTURE_STAGES)
        return caught.exception.stage

    def test_refusal_names_fixed_collector_stage_only(self):
        @contextmanager
        def enter_fails():
            raise ValueError('generated-private-enter')
            yield
        @contextmanager
        def exit_fails():
            yield
            raise ValueError('generated-private-exit')
        self.assertEqual(self.stage_of(quiesce=enter_fails),'quiesce_enter')
        self.assertEqual(self.stage_of(quiesce=exit_fails),'quiesce_exit')
        self.assertEqual(self.stage_of(expected_container_id='generated-private-cid'),'input')
        original=self.podman
        def failing_exec(*args,**kwargs):
            if args[:1]==('exec',):return SimpleNamespace(returncode=1,stdout=b'generated-private-output')
            return original(*args,**kwargs)
        with patch.object(self,'podman',side_effect=failing_exec):
            self.runner.podman=self.podman
            self.assertEqual(self.stage_of(),'exec')
        self.runner.podman=self.podman
        def bad_wire(doc):doc['contract']='generated-unknown-contract'
        self.edit=bad_wire
        self.assertEqual(self.stage_of(),'decode')

    def test_populated_api_rules_connectors_and_unexecuted_refs_are_values_only(self):
        with patch('emqx_owner_target._absence_profile',side_effect=AssertionError('no initial profile')), \
             patch('emqx_owner_target._build_checked',side_effect=AssertionError('no business projection')):
            result = self.collect()
        self.assertEqual(self.events,['enter','inspect','eval','inspect','exit'])
        self.assertEqual(repr(result),'<EMQX private post-operation native values>')
        for marker in (self.hash,b'generated-connector-secret',b'SELECT payload FROM "restored/#"',
                       b'file:/unexecuted/reference.csv',b'${UNEXECUTED_ENV}/input',
                       b'fixture-private-emqx_admin_jwt',b'fixture-private-emqx_retainer_message'):
            for encoded in (marker,base64.b64encode(marker),marker.hex().encode()):
                with self.assertRaises(PrivateFailure):result.scan(encoded)
        result.scan(b'ZZZ-plaintext-never-supplied')
        # Old initial producer still refuses this SAME populated capture.
        with self.assertRaises(PrivateFailure):_build(self.last_wire,self.generations[-1])

    def test_nonempty_api_table_alone_is_not_subject_to_initial_projection(self):
        self.config=cooked_config()
        result=self.collect()
        with self.assertRaises(PrivateFailure):result.scan(self.hash)
        with self.assertRaises(PrivateFailure) as caught:_build(self.last_wire,self.generations[-1])
        self.assertEqual(getattr(caught.exception,'phase',None),'mqtt_projection')

    def test_values_from_unknown_but_native_valid_table_are_not_projected_away(self):
        def extra(doc):
            name='generated_extra_native'
            doc['table_names'].append(name)
            doc['tables'].append({'table':name,'record_name':name,'attributes':['opaque'],
                'row_count':1,'rows':[term('tuple',[term('atom',name),binary(b'generated-extra-native-private')])]})
            doc['schema_metadata']['value'].append(term('tuple',[term('atom',name),term('list',[])]))
        self.edit=extra
        result=self.collect()
        with self.assertRaises(PrivateFailure):result.scan(b'generated-extra-native-private')

    def test_prior_source_and_dynamic_runtime_are_not_replaced(self):
        result = self.collect()
        self.runtime.register_bundle({'runtime-login-token':[b'generated-later-login-token']})
        for marker in (b'generated-old-source-key',b'generated-later-login-token'):
            with self.assertRaises(PrivateFailure):result.scan(marker)

    def test_new_runtime_native_proof_does_not_rebind_old_file_capability(self):
        self.collect()
        self.assertEqual(files._record(self.cap)[0]['cid'],self.old_cid)
        with self.assertRaises(PrivateFailure):
            files.observe_fixture_files(self.cap,private_eval=lambda _:self.fail('old token must refuse'),
                private_inspect=lambda:json.dumps(self.doc).encode(),private_values=files.Values())
        self.assertEqual(files._record(self.cap)[0]['cid'],self.old_cid)

    def test_wrong_cid_image_name_volume_or_unit_mapping_refuses_before_native(self):
        original = copy.deepcopy(self.doc)
        edits = [lambda d:d.update(Id='c'*64), lambda d:d.update(Image='sha256:'+'0'*64),
            lambda d:d.update(Name='/production'),lambda d:d['Mounts'][0].update(Name='unowned-volume'),
            lambda d:d['Config']['CreateCommand'].__setitem__(5,'wrong-secret,type=mount'),
            lambda d:d['HostConfig']['LogConfig'].update(Type='journald')]
        for edit in edits:
            self.doc=copy.deepcopy(original)
            edit(self.doc[0]);self.events.clear();self.refuse()
            self.assertNotIn('eval',self.events)

    def test_unknown_or_shadowed_mounts_and_swapped_volume_destinations_refuse(self):
        original = copy.deepcopy(self.doc)
        for extra in ({'Type':'bind','Source':'/unowned','Destination':'/opt/emqx/data','RW':True},
                      {'Type':'bind','Source':'/unowned','Destination':'/unowned','RW':False},
                      {'Type':'bind','Source':'/unowned','Destination':files.BOOTSTRAP,'RW':False}):
            self.doc=copy.deepcopy(original);self.doc[0]['Mounts'].append(extra);self.refuse()
        self.doc=copy.deepcopy(original)
        first,second=self.doc[0]['Mounts'][:2]
        first['Destination'],second['Destination']=second['Destination'],first['Destination']
        self.refuse()
        self.assertNotIn('eval',self.events)

    def test_native_process_failure_and_oversize_wire_refuse(self):
        original=self.runner.podman
        def failed(*args,**kwargs):
            if args[0]=='exec':return SimpleNamespace(returncode=1,stdout=b'generated-private-error')
            return original(*args,**kwargs)
        self.runner.podman=failed;self.refuse()
        def oversized(*args,**kwargs):
            if args[0]=='exec':return SimpleNamespace(returncode=0,stdout=b'x'*(m.MAX_WIRE+1))
            return original(*args,**kwargs)
        self.runner.podman=oversized;self.refuse()

    def test_no_default_transport_foreign_owner_or_unsealed_prior(self):
        for changes in ({'expected_container_id':True},{'provision':object()},
                        {'prior_registry':{'complete':True}},
                        {'prior_registry':CombinedRegistry(Registry(),RuntimeRegistry())}):
            self.refuse(**changes)
        self.assertEqual(self.events,[])

    def test_nonce_inventory_schema_rows_and_unknown_typed_terms_refuse(self):
        edits = [lambda d:d.update(generation='0'*32),lambda d:d.update(complete=False),
            lambda d:d['tables'].pop(),lambda d:d['table_names'].append('unobserved'),
            lambda d:d['tables'][0].update(row_count=999),
            lambda d:d['tables'][0]['rows'][0]['value'].__setitem__(2,{'type':'function','value':'private'}),
            lambda d:d.update(config={'type':'reference','value':'private'}),
            lambda d:d['tables'][0].update(attributes=['duplicate','duplicate'])]
        for edit in edits:
            self.edit=edit;self.refuse()
            self.assertEqual(self.events[-1],'exit')

    def test_runtime_identity_change_during_native_capture_refuses(self):
        def changed(doc):self.doc[0]['Id']='c'*64
        self.edit=changed;self.refuse()
        self.assertEqual(self.events[-1],'exit')

    def test_revoked_original_owner_lifetime_refuses(self):
        self.edit=lambda doc:files.revoke(self.cap)
        self.refuse()

    def test_old_file_cid_mutation_is_not_tolerated(self):
        self.edit=lambda doc:files._record(self.cap)[0].__setitem__('cid',self.cid)
        self.refuse()

    def test_historical_native_values_accumulate_bounded_generations(self):
        scanner=self.prior;hashes=[]
        for i in range(m.MAX_CAPTURES):
            self.hash=('generated-native-hash-%d'%i).encode();hashes.append(self.hash)
            scanner=self.collect(prior=scanner)
        for marker in hashes:
            with self.assertRaises(PrivateFailure):scanner.scan(marker)
        before=list(self.events);self.refuse(prior=scanner);self.assertEqual(before,self.events)

    def test_reused_generation_refuses_even_with_matching_reply(self):
        first=self.collect()
        with patch.object(m.uuid,'uuid4',return_value=SimpleNamespace(hex=self.generations[0])):
            self.refuse(prior=first)

    def test_cleanup_cannot_rebind_the_old_file_token(self):
        @contextmanager
        def changed():
            yield
            files._record(self.cap)[0]['cid']=self.cid
        self.refuse(quiesce=changed)

    def test_cleanup_failure_emits_no_scanner(self):
        @contextmanager
        def failed():
            yield
            raise RuntimeError('generated-private-cleanup')
        self.refuse(quiesce=failed)


if __name__=='__main__':unittest.main()
