"""Generated rule-engine maps only; no IO, runtime, resolution or real data."""
import unittest


def rule_engine(**args):
    return {'rules': {'generated-rule': {'sql': 'SELECT * FROM "generated/#"',
        'actions': [{'function': 'republish', 'args': {
            'topic': 'generated/${clientid}/${payload.site}',
            'payload': 'literal-private-${payload.body}-suffix-private',
            'qos': '${qos}', 'retain': '${flags.retain}', **args}}]}}}


class RepublishTests(unittest.TestCase):
    def test_exact_republish_context_keeps_full_strings_components_and_numeric_literals(self):
        from emqx_republish_templates import collect_rule_engine_values, PROFILE
        values = collect_rule_engine_values(rule_engine(), profile=PROFILE).values
        for value in (b'literal-private-${payload.body}-suffix-private',
                      b'literal-private-', b'-suffix-private', b'${payload.body}',
                      b'payload.body', b'body', b'${qos}', b'${flags.retain}',
                      b'generated-rule', b'SELECT * FROM "generated/#"', b'republish'):
            self.assertIn(value, values)
        literals = collect_rule_engine_values(rule_engine(qos=0, retain=False), profile=PROFILE).values
        self.assertIn(b'0', literals)
        self.assertIn(b'false', literals)

    def refused(self, doc, **kwargs):
        from emqx_republish_templates import collect_rule_engine_values, PROFILE
        from emqx_semantic_readers import SemanticRefused
        with self.assertRaisesRegex(SemanticRefused, '^emqx-semantic-source-unsupported$'):
            collect_rule_engine_values(doc, profile=kwargs.get('profile', PROFILE))

    def test_profile_is_explicit_and_no_default_bypass(self):
        self.refused(rule_engine(), profile=None)
        self.refused(rule_engine(), profile='unknown')

    def test_wrong_context_unknown_function_and_extra_argument_refs_refuse(self):
        import copy
        base = rule_engine()
        for function in ('console', 'unknown', 'module:republish', 'emqx_rule_actions:republish', None):
            doc = copy.deepcopy(base)
            doc['rules']['generated-rule']['actions'][0]['function'] = function
            with self.subTest(function=function):
                self.refused(doc)
        plain = rule_engine(payload='literal', topic='literal', qos=0, retain=False)
        plain['rules']['generated-rule']['actions'][0]['function'] = 'unknown'
        self.refused(plain)
        for key in ('description', 'sql', 'metadata'):
            doc = copy.deepcopy(base)
            doc['rules']['generated-rule'][key] = '${payload}'
            self.refused(doc)
        for key in ('user_properties', 'direct_dispatch', 'mqtt_properties', 'unknown'):
            self.refused(rule_engine(**{key: '${payload}'}))
        for doc in ({'password': '${payload}'}, {'actions': base['rules']['generated-rule']['actions']},
                    {'rules': {'generated-rule': {'actions': {'0': base['rules']['generated-rule']['actions'][0]}}}},
                    {'rule_engine': base}, {'rules': {'': base['rules']['generated-rule']}}):
            self.refused(doc)

    def test_no_env_file_vault_include_or_function_placeholder_escape(self):
        values = ('${HOME}', '${env.HOME}', '${file.secret}', '${vault.token}',
                  '${EMQX_ETC_DIR}', '${payload:-fallback}', '${?payload}',
                  '${payload[0]}', '${payload..x}', '${payload.func()}', '${payload',
                  '${}', '${$}', '$${payload}', '${unknown}',
                  'file:/private-${payload}', 'env:HOME-${payload}', 'vault:token-${payload}',
                  'ENV:HOME-${payload}')
        for value in values:
            with self.subTest(template=value):
                self.refused(rule_engine(payload=value))

    def test_qos_retain_are_single_message_variables_or_typed_literals(self):
        for field, value in (('qos', True), ('qos', 3), ('qos', -1), ('qos', 1.0),
                             ('qos', '1'), ('qos', 'prefix-${qos}'),
                             ('retain', 1), ('retain', 'false'),
                             ('retain', '${qos}${retain}'), ('retain', ' ${retain}'),
                             ('payload', []), ('topic', {}), ('payload', None),
                             ('topic', '${.}')):
            with self.subTest(field=field, value=value):
                self.refused(rule_engine(**{field: value}))
        from emqx_republish_templates import collect_rule_engine_values, PROFILE
        for args in ({'payload': '${.}'}, {'payload': '${.payload.user.name}'},
                     {'payload': '${payload.map.0}', 'qos': '${payload.qos}', 'retain': True}):
            collect_rule_engine_values(rule_engine(**args), profile=PROFILE)

    def test_nested_unknown_refs_and_external_file_keys_remain_refused(self):
        for args in ({'unknown': {'nested': '${payload}'}},
                     {'keyfile': '/private/key'}, {'unknown': {'type': 'file', 'path': 'acl.conf'}}):
            self.refused(rule_engine(**args))
        self.refused({'rules': {'${payload}': {'actions': []}}})

    def test_helper_is_bounded_without_raising_shared_limits(self):
        from unittest.mock import patch
        import emqx_semantic_readers as semantic
        self.refused(rule_engine(payload='x' * (semantic.MAX_VALUE + 1)))
        self.refused(rule_engine(payload='${payload.' + '.'.join(['deep'] * semantic.MAX_DEPTH) + '}'))
        for bound in ('MAX_VALUES', 'MAX_NODES', 'MAX_OUTPUT'):
            with self.subTest(bound=bound), patch.object(semantic, bound, 1):
                self.refused(rule_engine())

    def test_default_full_readers_and_unlocated_syntax_gate_stay_strict(self):
        import json
        from unittest.mock import patch
        from emqx_semantic_readers import read_hocon, SemanticRefused
        import emqx_owner_file_hocon as vendor
        import test_emqx_owner_file_hocon as fixture
        from test_emqx_semantic_readers import RAW
        doc = fixture.document()
        doc['document']['parsed']['rule_engine'] = rule_engine()
        doc['document']['syntax_strings'].append('${payload}')
        parser = lambda raw: json.dumps(doc).encode()
        for kwargs in ({}, {'file_profile': vendor.PROFILE, 'product_image': vendor.IMAGE}):
            with patch.object(vendor, 'observe_vendor_acl') as observe:
                with self.assertRaises(SemanticRefused):
                    read_hocon(RAW, parser, **kwargs)
                observe.assert_not_called()
