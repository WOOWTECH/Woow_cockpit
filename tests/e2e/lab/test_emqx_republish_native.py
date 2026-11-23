"""New public synthetic native checks only; no broker/dev-d/archive/key access."""
import json
from pathlib import Path
import tempfile
import unittest

from emqx_native_hocon import native_hocon
from emqx_native_runtime import run_native
from emqx_semantic_readers import read_hocon, SemanticRefused
from emqx_republish_templates import collect_rule_engine_values, PROFILE


class NativeRepublishTests(unittest.TestCase):
    def test_quoted_native_message_templates_are_data_but_default_stays_strict(self):
        raw = b'''rule_engine.rules.generated_rule {
          sql = "SELECT * FROM \\"generated/#\\""
          actions = [{ function = republish
            args { topic = "generated/${clientid}/${payload.site}"
                   payload = "generated-prefix-${payload.body}-suffix"
                   qos = "${qos}"\n retain = "${flags.retain}" }
          }]
        }'''
        encoded = native_hocon(raw)
        doc = json.loads(encoded)
        values = collect_rule_engine_values(doc['document']['parsed']['rule_engine'], profile=PROFILE).values
        for value in (b'generated-prefix-', b'-suffix', b'${payload.body}', b'${qos}', b'${flags.retain}'):
            self.assertIn(value, values)
        self.assertIn('generated-prefix-${payload.body}-suffix', doc['document']['syntax_strings'])
        with self.assertRaises(SemanticRefused):
            read_hocon(raw, lambda _: encoded)
        # The native lexer remains strict; quoted runtime strings are not a
        # permission to resolve true HOCON substitutions or include directives.
        for invalid in (b'payload=${payload}', b'include "generated-missing.conf"'):
            with self.subTest(invalid=invalid), self.assertRaises(SemanticRefused):
                native_hocon(invalid)

    def test_pinned_public_action_preprocessing_is_template_parse_not_resolution(self):
        script = b'''#!/usr/bin/env escript
%%! +S 1:1 +A 1 +t 65536 +hmax 8388608 +hmaxel false -noshell
-mode(compile).
main(_) ->
 code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
 Args=#{topic => <<"generated/${clientid}/${payload.site}">>,
        qos => <<"${qos}">>, retain => <<"${flags.retain}">>,
        payload => <<"prefix-${payload.body}">>, mqtt_properties => #{},
        user_properties => <<"${pub_props.'User-Property'}">>, direct_dispatch => false},
 #{preprocessed_tmpl := #{topic := Topic, payload := Payload,
   qos := [{var,"qos",[<<"qos">>]}],
   retain := [{var,"flags.retain",[<<"flags">>,<<"retain">>]}]}} =
     emqx_rule_actions:pre_process_action_args(republish,Args),
 ["clientid","payload.site"] = emqx_template:placeholders(Topic),
 ["payload.body"] = emqx_template:placeholders(Payload),
 io:put_chars("public-message-template-parse-passed").
'''
        with tempfile.TemporaryDirectory(prefix='emqx-republish-public-') as directory:
            root = Path(directory)
            (root / 'check.escript').write_bytes(script)
            (root / 'check.escript').chmod(0o600)
            with tempfile.TemporaryFile() as output:
                status = run_native(root, 'check.escript', output=output)
                output.seek(0)
                fixed = output.read(128)
        self.assertEqual(status, 0)
        self.assertEqual(fixed, b'public-message-template-parse-passed')
        self.assertFalse(root.exists())
