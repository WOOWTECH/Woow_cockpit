"""Generated pinned-native payload grammar; no source values, render or lab."""
import json
import unittest
from unittest.mock import patch

from emqx_republish_templates import _template, TemplateRefused, TEMPLATE_REASONS
from emqx_semantic_readers import Values, SemanticRefused, MAX_VALUE, MAX_DEPTH, read_hocon
from emqx_hocon_context import HTTP_PROFILE
from emqx_native_hocon import native_hocon_http_context
from test_emqx_hocon_context_native import BASE, observe
import emqx_owner_file_hocon as vendor


class PayloadGrammarTests(unittest.TestCase):
    def test_fixed_reasons_and_all_existing_reference_negative_controls_remain(self):
        for value,reason in (('${generated_alias}','unknown_root'),('${HOME}','unknown_root'),
                             ('${env.HOME}','unknown_root'),('${payload[0]}','grammar'),
                             ('${}','grammar'),('${payload','grammar'),('$${payload}','escape'),
                             ('env:HOME-${payload}','loader'),('file:/private','loader'),
                             ('vault:token','loader'),('x'*(MAX_VALUE+1),'size'),
                             ('${payload.'+'.'.join(['nested']*MAX_DEPTH)+'}','depth')):
            with self.subTest(reason=reason),self.assertRaises(TemplateRefused) as caught:
                _template(value,'payload',Values())
            self.assertEqual(caught.exception.reason,reason)
            self.assertEqual(str(caught.exception),'emqx-semantic-source-unsupported')
        from unittest.mock import patch
        with patch('emqx_semantic_readers.MAX_OUTPUT',1),self.assertRaises(TemplateRefused) as caught:
            _template('generated-long','payload',Values())
        self.assertEqual(caught.exception.reason,'budget')
        self.assertEqual(TemplateRefused('generated-private').reason,'grammar')

    def test_native_whole_context_and_json_embedded_known_fields_pass_unknown_root_refuses(self):
        cases=(('${.}',None),
               ('{"nested":{"value":"${payload.sensor.value}"},"client":"${clientid}"}',None),
               ('{"value":"${generated_alias}"}','syntax_republish_payload_unknown_root'),
               ('{"value":"${payload[0]}"}','syntax_republish_payload_grammar'))
        with patch.object(vendor,'observe_vendor_acl',observe):
            for payload,reason in cases:
                raw=BASE+('rule_engine.rules.generated.actions=[{function=republish,args.payload='+
                          json.dumps(payload)+'}]').encode()
                encoded=native_hocon_http_context(raw)
                if reason:
                    with self.assertRaises(SemanticRefused) as caught:
                        read_hocon(raw,lambda _:encoded,file_profile=HTTP_PROFILE,product_image=vendor.IMAGE)
                    self.assertEqual(caught.exception.owner_phase,reason)
                else:
                    values=read_hocon(raw,lambda _:encoded,file_profile=HTTP_PROFILE,product_image=vendor.IMAGE)
                    self.assertIn(payload.encode(),values.values)
                    if 'payload.sensor.value' in payload:
                        self.assertIn(b'${payload.sensor.value}',values.values)
                        self.assertIn(b'sensor',values.values)

    def test_pinned_republish_preprocessor_parses_whole_context_and_embedded_json_without_render(self):
        import tempfile
        from pathlib import Path
        from emqx_native_runtime import run_native
        script=b'''#!/usr/bin/env escript
%%! +S 1:1 +A 1 +t 65536 +hmax 8388608 +hmaxel false -noshell
main(_) ->
 code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
 Args=#{topic => <<"generated/${clientid}">>, qos => 0, retain => false,
        mqtt_properties => #{}, user_properties => <<"${pub_props.'User-Property'}">>,
        direct_dispatch => false},
 lists:foreach(fun({Body,Names}) ->
   #{preprocessed_tmpl := #{payload := Template}} =
      emqx_rule_actions:pre_process_action_args(republish,Args#{payload=>Body}),
   Names=emqx_template:placeholders(Template)
 end,[{<<"${.}">>,[""]},
       {<<"{\\"value\\":\\"${payload.sensor.value}\\",\\"client\\":\\"${clientid}\\"}">>,
        ["payload.sensor.value","clientid"]}]),
 io:put_chars("public-payload-preprocess-passed").
'''
        with tempfile.TemporaryDirectory(prefix='emqx-payload-public-') as directory:
            path=Path(directory)/'check.escript';path.write_bytes(script);path.chmod(0o600)
            with tempfile.TemporaryFile() as output:
                status=run_native(directory,path.name,output=output);output.seek(0);result=output.read(128)
        self.assertEqual(status,0)
        self.assertEqual(result,b'public-payload-preprocess-passed')
