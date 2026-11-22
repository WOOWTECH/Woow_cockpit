"""Local transport-to-registry integration fixtures. Never starts a broker/lab."""
import base64
from contextlib import contextmanager
import copy
import inspect
import io
import json
from pathlib import Path
import re
import tempfile
import unittest

from emqx_owner_target import owner_target_readers, broker_target_readers
from emqx_target_snapshots import register_target_snapshots
from emqx_runtime_credentials import RuntimeRegistry
from emqx_private_boundary import PrivateFailure
from emqx_semantic_readers import TABLES
from test_emqx_semantic_readers import binary, term


class Atom(str):
    pass


def typed(value):
    if type(value) is Atom:
        return term('atom', str(value))
    if type(value) is bool:
        return term('atom', 'true' if value else 'false')
    if type(value) is str:
        return binary(value.encode())
    if type(value) is bytes:
        return binary(value)
    if type(value) is int:
        return term('integer', value)
    if type(value) is float:
        return term('float', value)
    if type(value) in (tuple, list):
        return term('tuple' if type(value) is tuple else 'list', [typed(x) for x in value])
    if type(value) is dict:
        return term('map', [[term('atom', key), typed(child)] for key, child in value.items()])
    raise TypeError()


def cooked_config():
    return {'connectors': {}, 'bridges': {}, 'actions': {}, 'sources': {},
        'gateway': {}, 'exhook': {'servers': []},
        'authentication': [{'mechanism': Atom('password_based'),
            'backend': Atom('built_in_database'), 'user_id_type': Atom('username'),
            'enable': True, 'password_hash_algorithm': {'name': Atom('sha256'), 'salt_position': Atom('suffix')}}],
        'listeners': {'tcp': {'default': {'enable': True, 'bind': ((127,0,0,1),1883),
            'authentication': []}}, 'ssl': {'default': {'enable': False}},
            'ws': {'default': {'enable': False}}, 'wss': {'default': {'enable': False}}},
        'dashboard': {'listeners': {'http': {'bind': ((127,0,0,1),18083)}, 'https': {'bind': 0}},
            'default_username': 'fixture-admin', 'default_password': 'fixture-bootstrap-private'},
        'api_key': {'bootstrap_file': ''}, 'cluster': {'discovery_strategy': Atom('manual')},
        'rpc': {'driver': Atom('tcp')}, 'node': {'dist_proto': Atom('inet_tcp'),
            'cookie': Atom('fixture-private-cookie')},
        'mqtt': {'max_inflight': 32}, 'additional_native_root': {'opaque': 'fixture-other-config-private'}}


def reply_document(generation, config=None):
    tables = []
    def table(name, rows=None):
        record, attrs = TABLES.get(name, (name, ('private_value',)))
        tables.append({'table': name, 'record_name': record, 'attributes': list(attrs),
                       'row_count': len(rows or []), 'rows': rows or []})
    table('emqx_authn_mnesia', [term('tuple', [term('atom', 'user_info'),
        term('tuple', [term('atom', 'mqtt:global'), binary(b'fixture-user')]),
        binary(b'fixture-password-hash'), binary(b''), term('atom', 'false')])])
    table('emqx_app')
    table('emqx_admin')
    for name in ('emqx_admin_jwt', 'emqx_acl', 'emqx_retainer_message'):
        # Generic fixtures use illustrative native schemas, not real schema proof.
        record, attrs = TABLES.get(name, (name, ('private_value',)))
        table(name, [term('tuple', [term('atom', record)] +
            [binary(('fixture-private-' + name).encode()) for _ in attrs])])
    names = ['schema'] + [t['table'] for t in tables]
    definitions = []
    for name in names:
        record, attrs = TABLES.get(name, (name, ('fixture_attr',)))
        definitions.append((Atom(name), [(Atom('record_name'), Atom(record)),
            (Atom('attributes'), [Atom(attr) for attr in attrs]),
            (Atom('storage_type'), Atom('disc_copies'))]))
    providers = [{'id': 'password_based:built_in_database', 'provider': Atom('emqx_authn_mnesia'),
        'enable': True, 'state': {'user_id_type': Atom('username'), 'user_group': Atom('mqtt:global')}}]
    return {'contract': 'emqx-owner-live-target-v1', 'version': '5.8.9', 'otp_release': '26',
        'erts_version': '14.2.5.11', 'generation': generation, 'complete': True,
        'config': typed(cooked_config() if config is None else config), 'providers': typed(providers),
        'schema_metadata': typed(definitions), 'table_names': names, 'tables': tables}


class OwnerProducerTests(unittest.TestCase):
    def transport(self, events, edit=None, config=None):
        def evaluate(expression):
            events.append('eval')
            self.assertNotIn('\n', expression)
            self.assertNotIn('%%', expression)
            self.assertIn('emqx:get_config([])', expression)
            self.assertIn('mnesia:system_info(tables)', expression)
            self.assertIn('mnesia:foldl', expression)
            self.assertNotIn('__OWNER_NONCE__', expression)
            generation = re.search(r'generation => <<"([0-9a-f]{32})">>', expression)[1]
            doc = reply_document(generation, config)
            if edit:
                edit(doc)
            return b'WOOWTARGET:' + base64.b64encode(json.dumps(doc).encode()) + b':ENDok\n'
        return evaluate

    @contextmanager
    def lock(self, events):
        events.append('locked')
        try:
            yield
        finally:
            events.append('unlocked')

    def test_actual_callable_derives_readers_from_structured_broker_response(self):
        events = []
        with owner_target_readers(private_eval=self.transport(events),
                                  quiesce=lambda: self.lock(events)) as readers:
            self.assertEqual(events, ['locked', 'eval'])
            runtime = RuntimeRegistry()
            summary = register_target_snapshots(runtime, readers)
            self.assertEqual(summary['mqtt-auth'], 2)
            self.assertEqual(summary['target-bootstrap'], 2)
            for category in ('api-keys', 'connectors', 'tls'):
                with readers[category]() as stream:
                    self.assertEqual(json.load(stream)['records'], [])
            self.assertIn('emqx_admin_jwt', readers.persisted_values.tables)
            for value in (b'fixture-private-emqx_admin_jwt', b'fixture-other-config-private',
                          b'fixture-private-cookie', b'0', b'1', b'true', b'false'):
                with self.subTest(value=value), self.assertRaises(PrivateFailure):
                    readers.persisted_values.scan(value)
            with self.assertRaises(PrivateFailure):
                runtime.scan(b'fixture-bootstrap-private')
        self.assertEqual(events, ['locked', 'eval', 'unlocked'])

    def test_broker_export_checked_transport_adapter_is_lazy(self):
        events = []
        evaluate = self.transport(events)
        def checked(*args):
            self.assertEqual(args[:4], ('exec', 'invocation-owned-broker', 'emqx', 'eval'))
            return evaluate(args[4])
        capture = broker_target_readers(broker='invocation-owned-broker', checked=checked,
                                      quiesce=lambda: self.lock(events))
        self.assertEqual(events, [])
        with capture as readers:
            register_target_snapshots(RuntimeRegistry(), readers)
        self.assertEqual(events.count('eval'), 1)

    def test_no_fabricated_absence_missing_root_or_native_rows(self):
        variations = []
        for root in ('connectors', 'listeners', 'api_key', 'dashboard'):
            config = cooked_config(); del config[root]; variations.append(config)
        config = cooked_config(); config['connectors'] = {'mqtt': {'configured': {}}}; variations.append(config)
        config = cooked_config(); config['listeners']['ssl']['default']['enable'] = True; variations.append(config)
        config = cooked_config(); config['listeners']['ssl']['default']['keyfile'] = '/private/key'; variations.append(config)
        config = cooked_config(); config['api_key']['bootstrap_file'] = '/private/bootstrap'; variations.append(config)
        config = cooked_config(); config['authentication'][0]['bootstrap_file'] = '/private/mqtt'; variations.append(config)
        config = cooked_config(); del config['dashboard']['default_password']; variations.append(config)
        for config in variations:
            events = []
            with self.subTest(), self.assertRaises(PrivateFailure):
                with owner_target_readers(private_eval=self.transport(events, config=config),
                                          quiesce=lambda: self.lock(events)):
                    pass
            self.assertEqual(events[-1], 'unlocked')

    def test_unobserved_file_authorizer_never_returns_complete_target_readers(self):
        # All other config/native facts remain valid; only add an unsupported
        # file source. A missing path is an implicit dependency, not absence.
        for source in ({'type': Atom('file'), 'path': '/fixture/private-acl'},
                       {'type': Atom('file'), 'path': '${EMQX_ETC_DIR}/acl.conf'},
                       {'type': Atom('file')}):
            config=cooked_config()
            config['authorization']={'sources':[source]}
            events=[]
            with self.subTest(source=source), self.assertRaises(PrivateFailure):
                with owner_target_readers(private_eval=self.transport(events, config=config),
                                          quiesce=lambda:self.lock(events)):
                    pass
            self.assertEqual(events[-1],'unlocked')

    def test_nonempty_api_hash_unknown_native_terms_and_binding_refuse(self):
        def app_rows(doc):
            app = next(t for t in doc['tables'] if t['table'] == 'emqx_app')
            app['rows'] = [term('tuple', [term('atom', 'emqx_app')] + [binary(b'hash-not-plaintext')] * 7)]
            app['row_count'] = 1
        def group_mismatch(doc):
            doc['tables'][0]['rows'][0]['value'][1]['value'][0] = term('atom', 'other-group')
        for edit in (app_rows, group_mismatch, lambda d: d.update(generation='wrong'),
                     lambda d: d.update(complete=False), lambda d: d['tables'].pop(),
                     lambda d: d.update(schema_metadata=term('fun', 'unsupported')),
                     lambda d: d['tables'][-1].update(table='../private')):
            events = []
            with self.subTest(), self.assertRaises(PrivateFailure):
                with owner_target_readers(private_eval=self.transport(events, edit=edit),
                                          quiesce=lambda: self.lock(events)):
                    pass

    def test_unsupported_raw_eval_output_is_not_exposed_and_lock_released(self):
        events = []
        with self.assertRaisesRegex(PrivateFailure, '^target-capture-unsupported$'):
            with owner_target_readers(private_eval=lambda _: b'private-broker-error',
                                      quiesce=lambda: self.lock(events)):
                pass
        self.assertEqual(events, ['locked', 'unlocked'])

    def test_names_mode_preflight_integration_when_main_dependency_available(self):
        import emqx_runtime_workflow as workflow
        from emqx_private_evidence import publish
        from test_emqx_runtime_credentials import source_registry, transport, PASSWORD
        if 'coverage_mode' not in inspect.signature(publish).parameters:
            self.skipTest('main-owned names-mode publisher not present in this branch')
        events = []
        with tempfile.TemporaryDirectory() as directory:
            with owner_target_readers(private_eval=self.transport(events),
                                      quiesce=lambda: self.lock(events)) as readers:
                session = workflow.login_preflight(source_registry=source_registry(),
                    source_counts={'backup-key': 1, 'source-options': 0, 'source-cookie': 1},
                    target_readers=readers, private_transport=transport,
                    username=b'fixture-admin', password=PASSWORD, evidence_directory=Path(directory))
                evidence = json.loads((Path(directory) / 'credential-preflight.json').read_bytes())
                self.assertIsInstance(evidence['coverage'], list)
                self.assertTrue(all(type(count) is int for count in session.coverage.values()))
                with self.assertRaises(PrivateFailure):
                    session.registry.scan(b'fixture-private-emqx_admin_jwt')
