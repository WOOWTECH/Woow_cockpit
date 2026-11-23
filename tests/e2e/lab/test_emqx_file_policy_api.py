"""Generated FILE-target API/native boundaries; HTTP and native wire are simulated.

Actual collectors/issuance/registries run on generated fixtures. No broker, lab,
real HA source, restore or commercial acceptance is exercised or claimed here.
Vendor facts (EMQX 5.8.9, minirest 1.4.8) are cited in emqx_source_api_validator.
"""
from contextlib import contextmanager
import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_file_policy_api as profile
import emqx_source_api_validator as api
import emqx_native_object_integrity as objects
import emqx_post_restore_values as post
import emqx_real_owner_workflow as workflow
import test_emqx_source_api_validator as api_tests
import test_emqx_native_object_integrity as native_tests
import test_emqx_real_owner_workflow as workflow_tests
from test_emqx_owner_target import Atom, typed
from emqx_private_boundary import PrivateFailure
from emqx_runtime_workflow import PrivateSession
from woowbackup import flows
from woowbackup.errors import BackupError

TARGET_ACL = workflow.target_policy_for_mode(workflow.FILE_BASELINE).acl
# Exact jsx encoding of the vendor map (flatmap keys in term order: code < message).
VENDOR_404 = b'{"code":"NOT_FOUND","message":"Not found: built_in_database"}'
FILE_SOURCES = {'sources': [{'type': 'file', 'enable': True, 'rules': TARGET_ACL.decode()}]}
FILE_SETTINGS = {'no_match': 'deny', 'deny_action': 'ignore',
                 'cache': {'enable': True, 'max_size': 32, 'ttl': '1m', 'excludes': []}}


def b1_rows():
    """Generated stored-term rows shaped like emqx_authz_mnesia #emqx_acl records."""
    acl = Atom('emqx_acl')
    return [(acl, (1, b'b1-gateway'), [(Atom('allow'), Atom('subscribe'), b'b1/retained/#'),
                                       (Atom('allow'), Atom('publish'), b'b1/gateway/#')]),
            (acl, (1, b'b1-sensor'), [(Atom('allow'), Atom('publish'), b'b1/sensor/#'),
                                      (Atom('deny'), Atom('subscribe'), (Atom('eq'), b'b1/secret/#'))]),
            (acl, (2, b'b1-dashboard-panel'), [(Atom('allow'), Atom('subscribe'), b'b1/#')]),
            (acl, 0, [(Atom('deny'), Atom('all'), b'#')])]


def acl_table(rows, *, record='emqx_acl', attributes=('who', 'rules')):
    typed_rows = [typed(row) for row in rows]
    return {'table': 'emqx_acl', 'record_name': record, 'attributes': list(attributes),
            'row_count': len(typed_rows), 'rows': typed_rows}


class FileHTTP:
    """Mixin: every builtin ACL endpoint answers the exact vendor 404 unless changed."""
    def response(self, url, raw):
        for name, path in api.PATHS.items():
            if url.endswith('/api/v5' + path):
                if name in self.changes:
                    return self.changes[name]
                if name in api.INACTIVE_ACL_ENDPOINTS:
                    return VENDOR_404 + b'\napplication/json\n404'
        return raw


class FilePolicyAPITests(FileHTTP, unittest.TestCase):
    def setUp(self):
        self.fixture = api_tests.SourceAPITests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.documents['authorization_sources'] = copy.deepcopy(FILE_SOURCES)
        self.fixture.documents['authorization_settings'] = copy.deepcopy(FILE_SETTINGS)
        self.fixture.edit_http = self.response
        self.changes = {}
        self.inputs = dict(prior_registry=self.fixture.prior, provision=self.fixture.provision,
                           expected_container_id=self.fixture.cid, quiesce=self.fixture.quiesce, port=18083,
                           retained_topics=self.fixture.topics, **self.fixture.credentials)

    def observe(self, **changes):
        kwargs = dict(self.inputs, target_file_acl=TARGET_ACL)
        kwargs.update(changes)
        return profile.validate_file_policy_source_api(**kwargs)

    def refused(self, phase, **changes):
        with self.assertRaises(api.SourceAPIPhaseRefused) as caught:
            self.observe(**changes)
        self.assertEqual(caught.exception.phase, phase)
        self.assertEqual(str(caught.exception), 'source-api-refused')
        self.assertIn(phase, workflow.PHASES)

    def activity(self, target_mode):
        session = PrivateSession(object(), self.fixture.prior, {}, None)
        clients = workflow.SourceClients(dict(retained_topic1=self.fixture.topics[0],
                                              retained_topic2=self.fixture.topics[1]))
        credentials = workflow.SourceAPICredentials(tuple(self.fixture.credentials[k] for k in workflow.API_FIELDS))
        with patch.object(workflow, '_inspect', return_value=self.fixture.doc[0]), \
             patch.object(workflow, 'fixture_quiescence', side_effect=lambda p: self.fixture.quiesce()):
            return workflow._source_api_activity(self.fixture.provision, self.fixture.prior, session,
                                                 clients, credentials, target_mode=target_mode), session

    def test_exact_vendor_404_and_exact_file_readback_mint_no_acl_fact(self):
        observed = self.observe()
        self.assertIs(type(observed), api.SourceAPIResult)
        self.assertEqual(len(self.fixture.http), 18)
        self.assertEqual(set(observed.private_documents()), set(api.PATHS) - api.INACTIVE_ACL_ENDPOINTS)
        facts = observed.private_facts()
        self.assertEqual(facts['acl_scope'], api.FILE_POLICY_ACL_SCOPE)
        for name in api.INACTIVE_ACL_ENDPOINTS:
            self.assertNotIn(name, facts)
        self.assertEqual(facts['builtin_acl_api'],
                         {name: {'status': 404, 'code': 'NOT_FOUND'} for name in api.INACTIVE_ACL_ENDPOINTS})
        self.assertEqual(facts['active_file_acl_readback'], 'exact-target-file-policy-bytes')
        self.assertEqual(facts['source_acl_rows'], 'requires-native-emqx-acl-inventory')
        self.assertIn(observed, objects._API)
        self.assertIn(observed, profile._FILE_POLICY_API)
        for _, kwargs in self.fixture.http:
            for method in (b'PUT', b'DELETE', b'PATCH'):
                self.assertNotIn(b'request = "' + method + b'"', kwargs['input'])
        for raw in (b'generated-jwt-admin', b'generated-jwt-b1ops', self.fixture.credentials['api_secret'],
                    TARGET_ACL, b'generated-returned-connector-secret'):
            with self.assertRaises(PrivateFailure):
                observed.scan(raw)

    def test_strict_and_imported_modes_still_refuse_the_same_404(self):
        with self.assertRaises(api.SourceAPIPhaseRefused) as caught:
            api.validate_source_api(**self.inputs)
        self.assertEqual(caught.exception.phase, 'source_api_acl_users_http_404')
        for mode in (workflow.IMPORTED_MNESIA, None):
            before = dict(workflow._SOURCE_API_CIDS)
            with self.assertRaises(workflow.RealOwnerRefused) as caught:
                self.activity(mode)
            self.assertEqual(caught.exception.phase, 'source_api_acl_users_http_404')
            self.assertEqual(dict(workflow._SOURCE_API_CIDS), before)

    def test_only_explicit_file_mode_selects_profile_with_issued_target_bytes(self):
        observed, session = self.activity(workflow.FILE_BASELINE)
        self.assertIn(observed, workflow._SOURCE_API_CIDS)
        self.assertEqual(observed.private_facts()['acl_scope'], api.FILE_POLICY_ACL_SCOPE)
        self.assertEqual(TARGET_ACL, workflow._target_acl())
        self.fixture.http.clear()
        with self.assertRaises(workflow.RealOwnerRefused) as caught:
            self.activity('generated-unknown-mode')
        self.assertEqual(caught.exception.phase, 'source_api')
        self.assertEqual(self.fixture.http, [])
        self.fixture.documents['authorization_sources']['sources'][0]['rules'] += '\n'
        with self.assertRaises(workflow.RealOwnerRefused) as caught:
            self.activity(workflow.FILE_BASELINE)
        self.assertEqual(caught.exception.phase, 'source_api_facts_contract')

    def test_file_mode_classifies_200_and_other_statuses_on_builtin_endpoints(self):
        inventories = {name: json.dumps(self.fixture.documents[name]).encode()
                       for name in api.INACTIVE_ACL_ENDPOINTS}
        for name in sorted(api.INACTIVE_ACL_ENDPOINTS):
            for status in (200, 401, 403, 429, 500, 204):
                with self.subTest(name=name, status=status):
                    self.changes = {name: inventories[name] + b'\napplication/json\n' + str(status).encode()}
                    expected = 'http_' + str(status) if status in (200, 401, 403, 429) else 'http_other'
                    self.refused('source_api_' + name + '_' + expected)
        # Mixed: users 404 (accepted shape) but clients still serve a full 200 inventory.
        self.changes = {'acl_clients': inventories['acl_clients'] + b'\napplication/json\n200'}
        self.refused('source_api_acl_clients_http_200')

    def test_malformed_or_non_vendor_404_bodies_refuse(self):
        cases = [
            (b'{"code":"NOT_FOUND","message":"Not Found"}', 'contract'),        # rule-row not found
            (b'{"code":"NOT_FOUND","message":"Not found: file"}', 'contract'),
            (b'{"code":"BAD_REQUEST","message":"\'built_in_database\' type source is not found."}', 'contract'),
            (b'{"code":"NOT_FOUND","message":"Not found: built_in_database","extra":true}', 'contract'),
            (b'{"code":"NOT_FOUND"}', 'contract'),
            (b'{"message":"Not found: built_in_database"}', 'contract'),
            (b'{"code":"NOT_FOUND","message":null}', 'contract'),
            (b'["NOT_FOUND","Not found: built_in_database"]', 'contract'),
            (b'not-json', 'parse'),
            (b'', 'parse'),
            (b'{"code":"NOT_FOUND","code":"NOT_FOUND","message":"Not found: built_in_database"}', 'parse'),
        ]
        for name in sorted(api.INACTIVE_ACL_ENDPOINTS):
            for body, reason in cases:
                with self.subTest(name=name, body=body):
                    self.changes = {name: body + b'\napplication/json\n404'}
                    self.refused('source_api_' + name + '_' + reason)
            for ctype in (b'text/plain', b'application/json; charset=utf-8', b'APPLICATION/JSON', b''):
                with self.subTest(name=name, ctype=ctype):
                    self.changes = {name: VENDOR_404 + b'\n' + ctype + b'\n404'}
                    self.refused('source_api_' + name + '_contract')
            self.changes = {name: b'broken-frame'}
            self.refused('source_api_' + name + '_parse')

    def test_vendor_404_on_any_other_endpoint_refuses(self):
        for name in ('mqtt_users', 'connectors', 'authorization_sources', 'authorization_settings', 'retainer'):
            with self.subTest(name=name):
                self.changes = {name: VENDOR_404 + b'\napplication/json\n404'}
                self.refused('source_api_' + name + '_http_404')

    def test_file_readback_and_target_settings_must_equal_issued_policy(self):
        text = TARGET_ACL.decode()
        variants = [
            [{'type': 'file', 'enable': True, 'rules': text + '\n'}],
            [{'type': 'file', 'enable': True, 'rules': text[:-1]}],
            [{'type': 'file', 'enable': True, 'path': '/opt/emqx/etc/lab-acl.conf'}],
            [{'type': 'file', 'enable': True, 'rules': text, 'path': '/opt/emqx/etc/lab-acl.conf'}],
            [{'type': 'file', 'enable': False, 'rules': text}],
            [{'type': 'file', 'enable': 1, 'rules': text}],
            [{'type': 'file', 'enable': True, 'rules': text}, {'type': 'built_in_database', 'enable': False}],
            [{'type': 'built_in_database', 'enable': True}, {'type': 'file', 'enable': True, 'rules': text}],
            [],
        ]
        for sources in variants:
            with self.subTest(sources=sources):
                self.fixture.documents['authorization_sources'] = {'sources': sources}
                self.refused('source_api_facts_contract')
        self.fixture.documents['authorization_sources'] = copy.deepcopy(FILE_SOURCES['sources'])
        self.refused('source_api_facts_contract')
        self.fixture.documents['authorization_sources'] = dict(copy.deepcopy(FILE_SOURCES), extra=[])
        self.refused('source_api_facts_contract')
        self.fixture.documents['authorization_sources'] = copy.deepcopy(FILE_SOURCES)
        for settings in ({'no_match': 'allow', 'deny_action': 'ignore'},
                         {'no_match': 'deny', 'deny_action': 'disconnect'}, {'no_match': 'deny'}):
            with self.subTest(settings=settings):
                self.fixture.documents['authorization_settings'] = settings
                self.refused('source_api_facts_contract')
        self.fixture.documents['authorization_settings'] = copy.deepcopy(FILE_SETTINGS)
        self.assertIs(type(self.observe()), api.SourceAPIResult)

    def test_profile_inputs_are_explicit_and_refuse_before_http(self):
        for value in (None, TARGET_ACL.decode(), b'', b'x' * (api.MAX_VALUE + 1), b'nul\x00acl', b'\xff\xfe'):
            with self.subTest(value=value[:8] if value else value):
                self.fixture.http.clear()
                self.refused('source_api_input_contract', target_file_acl=value)
                self.assertEqual(self.fixture.http, [])
        for selected, value in (('generated-unknown-profile', TARGET_ACL), (api.STRICT_API_PROFILE, TARGET_ACL),
                                (api.FILE_POLICY_API_PROFILE, None)):
            with self.assertRaises(api.SourceAPIPhaseRefused) as caught:
                api._observe_source_api(api_profile=selected, target_file_acl=value, **self.inputs)
            self.assertEqual(caught.exception.phase, 'source_api_input_contract')
        self.assertEqual(self.fixture.http, [])
        with self.assertRaises(TypeError):
            api.validate_source_api(target_file_acl=TARGET_ACL, **self.inputs)

    def test_failed_exclusion_or_late_finish_never_returns_a_file_observation(self):
        minted = len(profile._FILE_POLICY_API)

        @contextmanager
        def failed_exit():
            yield
            raise ValueError('generated-private-exit-error')
        with self.assertRaises(api.SourceAPIPhaseRefused):
            self.observe(quiesce=failed_exit)
        with patch.object(api.time, 'monotonic', side_effect=[0, 121]):
            with self.assertRaises(api.SourceAPIPhaseRefused):
                self.observe()
        self.assertLessEqual(len(profile._FILE_POLICY_API), minted)  # weak registry: GC may only shrink it

    def test_imported_acl_assertion_requires_strict_scope_even_with_matching_counts(self):
        docs = {'mqtt_users': {'data': [{'user_id': 'b1-sensor', 'is_superuser': False},
                                        {'user_id': 'b1-gateway', 'is_superuser': False}], 'meta': {'count': 2}},
                'authorization_sources': {'sources': [{'type': 'file', 'enable': True},
                                                      {'type': 'built_in_database', 'enable': True}]},
                'authorization_settings': {'no_match': 'deny'}}
        facts = {'acl_scope': 'source-mnesia-data-only', 'acl_users': {'rule_counts': {'b1-gateway': 2, 'b1-sensor': 2}},
                 'acl_clients': {'rule_counts': {'b1-dashboard-panel': 1}}, 'acl_all': {'count': 1}}
        workflow._assert_imported_acl_api(api.SourceAPIResult(None, None, docs, facts))  # positive control
        for scope in (api.FILE_POLICY_ACL_SCOPE, None):
            changed = dict(facts, acl_scope=scope)
            with self.assertRaises(workflow.RealOwnerRefused) as caught:
                workflow._assert_imported_acl_api(api.SourceAPIResult(None, None, docs, changed))
            self.assertEqual(caught.exception.phase, 'source_api')

    def test_file_observation_is_never_imported_acl_proof_but_keeps_receipt_scans(self):
        from emqx_private_evidence import names_receipt, SOURCE_NAMES
        results, session = [], None
        for _ in range(3):
            observed, session = self.activity(workflow.FILE_BASELINE)
            results.append(observed)
        for observed in results:
            with self.assertRaises(workflow.RealOwnerRefused) as caught:
                workflow._assert_imported_acl_api(observed)
            self.assertEqual(caught.exception.phase, 'source_api')
        session = PrivateSession(object(), self.fixture.prior, {}, None)
        workflow._scan_source_api_receipt(names_receipt('restore', 'passed', SOURCE_NAMES), results, session)
        with self.assertRaises(workflow.RealOwnerRefused):
            workflow._scan_source_api_receipt(TARGET_ACL, results, session)


class NativeProjectionTests(unittest.TestCase):
    def test_exact_b1_rows_project_to_the_strict_api_inventory(self):
        self.assertEqual(profile._project_acl([acl_table(b1_rows())]), ('ok', profile.B1_NATIVE_ACL_INVENTORY))
        fixture = api_tests.SourceAPITests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        docs = fixture.documents
        derived = {('username', r['username']): len(r['rules']) for r in docs['acl_users']['data']}
        derived.update({('clientid', r['clientid']): len(r['rules']) for r in docs['acl_clients']['data']})
        derived[('all', None)] = len(docs['acl_all']['rules'])
        self.assertEqual(derived, profile.B1_NATIVE_ACL_INVENTORY)
        api._facts(copy.deepcopy(docs), b'admin', b'b1ops', fixture.topics)  # strict accepts the same inventory
        docs['acl_users']['data'][0]['rules'].append({})
        with self.assertRaises(ValueError):
            api._facts(copy.deepcopy(docs), b'admin', b'b1ops', fixture.topics)

    def test_table_and_row_shapes_are_fixed_classifications(self):
        self.assertEqual(profile._project_acl([]), ('table', None))
        self.assertEqual(profile._project_acl([acl_table(b1_rows())] * 2), ('table', None))
        self.assertEqual(profile._project_acl([acl_table(b1_rows(), record='emqx_acl_v2')]), ('table', None))
        self.assertEqual(profile._project_acl([acl_table(b1_rows(), attributes=('rules', 'who'))]), ('table', None))
        acl = Atom('emqx_acl')
        rule = (Atom('allow'), Atom('all'), b'#')
        for row in [(acl, 3, [rule]), (acl, (1, b''), [rule]), (acl, (3, b'x'), [rule]),
                    (acl, (Atom('username'), b'x'), [rule]), (acl, (1, b'\xff'), [rule]),
                    (acl, (1, 'generated-text-is-binary-here'), b'not-a-list'),
                    (acl, (1, b'x'), [(Atom('allow'), Atom('all'))]),
                    (acl, (1, b'x'), [(Atom('maybe'), Atom('all'), b'#')]),
                    (acl, (1, b'x'), [(b'allow', Atom('all'), b'#')]),
                    (Atom('other'), 0, [rule]), (acl, 0, [rule], b'extra'), (acl, True, [rule])]:
            with self.subTest(row=row):
                self.assertEqual(profile._project_acl([acl_table(b1_rows() + [row])]), ('row', None))
        duplicate = b1_rows() + [b1_rows()[0]]
        self.assertEqual(profile._project_acl([acl_table(duplicate)]), ('row', None))
        status, inventory = profile._project_acl([acl_table(b1_rows()[:-1])])
        self.assertEqual(status, 'ok')
        self.assertNotEqual(inventory, profile.B1_NATIVE_ACL_INVENTORY)
        self.assertEqual(profile._project_acl([acl_table([])]), ('ok', {}))

    def test_refusal_labels_are_fixed_and_printable(self):
        for stage in profile.FILE_POLICY_ACL_STAGES:
            self.assertIn('file_policy_acl_' + stage, workflow.PHASES)
        self.assertIn('file_policy_acl', workflow.PHASES)
        for name in api.INACTIVE_ACL_ENDPOINTS:
            self.assertIn('source_api_' + name + '_http_200', workflow.PHASES)
        error = profile.FilePolicyACLRefused('generated-private-value')
        self.assertEqual(error.phase, 'file_policy_acl_api')
        self.assertEqual(str(error), 'file-policy-acl-refused')


class FilePolicyNativeTests(FileHTTP, unittest.TestCase):
    """Actual API + native collectors and existing object comparator, generated IO."""
    def setUp(self):
        self.n = native_tests.NativeObjectTests()
        self.n.setUp()
        self.addCleanup(self.n.doCleanups)
        self.strict = self.n.observed  # minted by the strict profile in fixture setUp
        self.n.documents['authorization_sources'] = copy.deepcopy(FILE_SOURCES)
        self.n.documents['authorization_settings'] = copy.deepcopy(FILE_SETTINGS)
        self.n.edit_http = self.response
        self.changes = {}
        self.rows = b1_rows()
        self.acl_override = None
        self.n.edit = self.native_doc
        self.observed = self.file_api()

    def native_doc(self, doc):
        self.n.secret_doc(doc)
        table = next(t for t in doc['tables'] if t['table'] == 'emqx_acl')
        table.update(acl_table(self.rows))
        if self.acl_override is not None:
            table.update(self.acl_override)

    def file_api(self):
        self.n.api_mode = True
        try:
            return profile.validate_file_policy_source_api(target_file_acl=TARGET_ACL, prior_registry=self.n.prior,
                provision=self.n.provision, expected_container_id=self.n.cid, quiesce=self.n.quiesce, port=18083,
                retained_topics=self.n.topics, **self.n.credentials)
        finally:
            self.n.api_mode = False

    def refused(self, stage, source_api, native):
        with self.assertRaises(profile.FilePolicyACLRefused) as caught:
            profile.compare_file_policy_native_acl(source_api=source_api, native_values=native)
        self.assertEqual(caught.exception.phase, 'file_policy_acl_' + stage)
        with self.assertRaises(workflow.RealOwnerRefused) as caught:
            workflow._assert_file_policy_native_acl(source_api, native)
        self.assertEqual(caught.exception.phase, 'file_policy_acl_' + stage)
        self.assertIn(caught.exception.phase, workflow.PHASES)

    def test_file_api_then_fresh_native_capture_prove_exact_inactive_b1_inventory(self):
        native = self.n.native()
        self.n.compare(native, source_api=self.observed)  # existing object proof accepts the FILE observation
        proof = profile.compare_file_policy_native_acl(source_api=self.observed, native_values=native)
        self.assertIs(type(proof), profile.FilePolicyNativeACL)
        self.assertIn('inactive-under-target-file-authorizer-api404-not-used-as-proof', proof.scope())
        self.assertIs(type(workflow._assert_file_policy_native_acl(self.observed, native)), profile.FilePolicyNativeACL)
        for raw in (b'generated-jwt-admin', TARGET_ACL, self.n.native_secret):
            with self.assertRaises(PrivateFailure):
                proof.scan(raw)

    def test_api_404_never_substitutes_for_native_rows(self):
        acl = Atom('emqx_acl')
        cases = [('inventory', lambda rows: rows.pop()),
                 ('inventory', lambda rows: rows[0][2].pop()),
                 ('inventory', lambda rows: rows[2][2].append((Atom('deny'), Atom('all'), b'#'))),
                 ('inventory', lambda rows: rows.append((acl, (1, b'b1-extra'), []))),
                 ('inventory', lambda rows: rows.__setitem__(slice(None), [])),
                 ('inventory', lambda rows: rows.__setitem__(0, (acl, (2, b'b1-gateway'), rows[0][2]))),
                 ('row', lambda rows: rows.append((acl, 7, []))),
                 ('row', lambda rows: rows[3][2].append((Atom('maybe'), Atom('all'), b'#')))]
        for stage, change in cases:
            with self.subTest(stage=stage):
                self.rows = b1_rows()
                change(self.rows)
                self.refused(stage, self.observed, self.n.native())
        self.rows = b1_rows()
        self.acl_override = {'attributes': ['rules', 'who']}  # collector-valid, not the pinned emqx_acl schema
        self.refused('table', self.observed, self.n.native())

    def test_generic_native_fixture_stays_lenient_for_other_modes_but_refuses_here(self):
        self.n.edit = self.n.secret_doc  # original illustrative emqx_acl row from the shared fixture
        native = self.n.native()
        self.assertEqual(profile._NATIVE_ACL[native]['projection'], ('row', None))
        self.n.compare(native, source_api=self.strict)  # existing strict object path unaffected
        self.refused('row', self.observed, native)
        with self.assertRaises(ValueError):
            profile._record_native_acl(native, self.n.last_wire, native._persisted.generation)

    def test_unminted_file_scope_observation_is_never_accepted(self):
        # A genuine FILE-profile collector result that bypassed validate_file_policy_source_api
        # carries the FILE acl_scope and the same facts, but no mint: it must still refuse.
        self.n.api_mode = True
        try:
            unminted = api._observe_source_api(api_profile=api.FILE_POLICY_API_PROFILE, target_file_acl=TARGET_ACL,
                prior_registry=self.n.prior, provision=self.n.provision, expected_container_id=self.n.cid,
                quiesce=self.n.quiesce, port=18083, retained_topics=self.n.topics, **self.n.credentials)
        finally:
            self.n.api_mode = False
        self.assertEqual(unminted._facts.get('acl_scope'), api.FILE_POLICY_ACL_SCOPE)
        self.assertNotIn(unminted, profile._FILE_POLICY_API)
        self.refused('api', unminted, self.n.native())

    def test_binding_order_and_minting_are_enforced(self):
        native = self.n.native()
        self.refused('api', self.strict, native)  # strict observation was never minted as FILE
        self.refused('api', object(), native)
        handmade = post.PostRestoreValues(native._previous, native._persisted, native._generations,
                                          native._preflight_generations)
        self.refused('binding', self.observed, handmade)
        later = self.file_api()  # newer API observation than this native capture
        self.refused('order', later, native)
        self.n.compare(self.n.native(), source_api=later)
        mutated = self.file_api()
        fresh = self.n.native()
        mutated._facts['acl_scope'] = 'source-mnesia-data-only'
        self.refused('api', mutated, fresh)
        other = self.file_api()
        fresh = self.n.native()
        objects._NATIVE[fresh]['cid'] = 'f' * 64
        self.refused('binding', other, fresh)
        other = self.file_api()
        fresh = self.n.native()
        profile._NATIVE_ACL[fresh]['generation'] = '0' * 32
        self.refused('binding', other, fresh)


class FileBaselineWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.w = workflow_tests.FoundationTests()
        self.w.setUp()
        self.addCleanup(self.w.doCleanups)

    def run_phases(self, target_mode, native_acl):
        w = self.w
        ctx, app, state = w.context()
        (w.root / '.config/systemd/user').mkdir(parents=True)
        clients = w.clients()
        credentials = workflow.SourceAPICredentials(w.api_values())
        events = []
        original = object()
        scanners = [original, object(), object(), object()]
        session = SimpleNamespace(registry=original)
        self.events = events
        observations = [object(), object(), object()]
        negatives = [object(), object(), object()]
        expected_objects = object()

        def restore(context, request):
            events.append('restore')
            if events.count('restore') == 1:
                return {'changed': True}
            ctx.adapter(app).imported_hook()
            (w.root / '.config' / w.fixture.prefix / 'fail-once').unlink()
            raise flows.RolledBack(BackupError('job-failed', 'generated'), {'rolled_back': True})

        def activity(provision, prior, supplied, actual_clients, actual_credentials, *, target_mode):
            self.assertEqual(target_mode, expected_mode)
            i = events.count('api')
            self.assertIs(prior, scanners[i])
            events.append('api')
            return observations[i]

        def native(provision, prior):
            i = events.count('capture')
            events.append('capture')
            return scanners[i + 1]

        def compared(expected, observed, native_values):
            events.append('objects')
            return object()

        def acl(observed, native_values):
            i = events.count('file_acl')
            self.assertIs(observed, observations[i])
            self.assertIs(native_values, scanners[i + 1])
            self.assertEqual(events[-1], 'objects')
            events.append('file_acl')
            return native_acl(observed, native_values)
        expected_mode = target_mode
        with patch.object(flows, 'run_restore', side_effect=restore), patch.object(workflow, '_ready'), \
             patch.object(workflow, 'validate_source_mqtt', side_effect=lambda *a, **k: events.append('mqtt')), \
             patch.object(workflow, '_source_api_activity', side_effect=activity), \
             patch.object(workflow, '_source_negative_activity',
                          side_effect=lambda p, s, c, o: (events.append('negative'), negatives[events.count('negative') - 1])[1]), \
             patch.object(workflow, '_post_activity_capture', side_effect=native), \
             patch.object(workflow, '_assert_imported_acl_api', side_effect=lambda o: events.append('acl_api')), \
             patch.object(workflow, '_compare_source_objects', side_effect=compared), \
             patch.object(workflow, '_assert_file_policy_native_acl', side_effect=acl):
            result = workflow._restore_and_rollback(ctx, app, w.provision, 'generated-package', state,
                clients=clients, session=session, api_credentials=credentials, api_results=[],
                negative_results=[], target_mode=target_mode, object_expected=expected_objects, object_results=[])
        return events, result, scanners

    def test_file_baseline_requires_native_acl_after_objects_in_every_phase(self):
        events, result, scanners = self.run_phases(workflow.FILE_BASELINE, lambda o, n: object())
        phase = ['mqtt', 'api', 'negative', 'capture', 'objects', 'file_acl']
        self.assertEqual(events, ['restore'] + phase + ['restore'] + phase + phase)
        self.assertIs(result, scanners[-1])

    def test_imported_mode_never_uses_the_file_native_acl_step(self):
        events, _, _ = self.run_phases(workflow.IMPORTED_MNESIA, lambda o, n: self.fail('file step in imported mode'))
        self.assertNotIn('file_acl', events)
        self.assertEqual(events.count('acl_api'), 3)

    def test_native_acl_refusal_stops_before_rollback_phase(self):
        def refuse(observed, native_values):
            raise workflow.RealOwnerRefused('file_policy_acl_inventory')
        with self.assertRaises(workflow.RealOwnerRefused) as caught:
            self.run_phases(workflow.FILE_BASELINE, refuse)
        self.assertEqual(caught.exception.phase, 'file_policy_acl_inventory')
        self.assertEqual(self.events.count('restore'), 1)
        self.assertEqual(self.events[-2:], ['objects', 'file_acl'])

    def test_later_round_native_acl_refusal_names_its_round(self):
        for failing, expected in ((1, 'rollback_file_policy_acl_inventory'), (2, 'restart_file_policy_acl_inventory')):
            with self.subTest(round=failing):
                self.setUp()
                calls = []

                def refuse_in_round(observed, native_values, failing=failing):
                    calls.append(observed)
                    if len(calls) - 1 == failing:
                        raise workflow.RealOwnerRefused('file_policy_acl_inventory')
                    return object()
                with self.assertRaises(workflow.RealOwnerRefused) as caught:
                    self.run_phases(workflow.FILE_BASELINE, refuse_in_round)
                self.assertEqual(caught.exception.phase, expected)
                self.assertIn(expected, workflow.PHASES)
                self.assertEqual(len(calls), failing + 1)

    def test_wrapper_dependency_failure_has_only_fixed_phase(self):
        import builtins
        original = builtins.__import__

        def missing(name, *args, **kwargs):
            if name == 'emqx_file_policy_api':
                raise ImportError('generated-private-error-not-output')
            return original(name, *args, **kwargs)
        with patch.object(builtins, '__import__', side_effect=missing):
            with self.assertRaises(workflow.RealOwnerRefused) as caught:
                workflow._assert_file_policy_native_acl(object(), object())
        self.assertEqual(caught.exception.phase, 'file_policy_acl')
        with patch('emqx_file_policy_api.compare_file_policy_native_acl', return_value=True):
            with self.assertRaises(workflow.RealOwnerRefused) as caught:
                workflow._assert_file_policy_native_acl(object(), object())
        self.assertEqual(caught.exception.phase, 'file_policy_acl')


if __name__ == '__main__':
    unittest.main()
