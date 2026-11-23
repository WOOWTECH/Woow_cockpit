"""Pinned public message schema and pure data-accessor collection; no lab/IO."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from emqx_republish_templates import _template, TemplateRefused
from emqx_semantic_readers import Values, read_hocon, SemanticRefused
from emqx_hocon_context import HTTP_PROFILE
from emqx_native_hocon import native_hocon_http_context
from emqx_native_runtime import run_native
import emqx_owner_file_hocon as vendor
from test_emqx_hocon_context_native import BASE, observe

NEW_SCALARS=('timestamp','id','node','event','peerhost','peername','publish_received_at')
NEW_MAPS=('flags.dup','headers.username','headers.properties.generated',
          'pub_props.generated','client_attrs.generated','metadata.rule_id')


class MessageRootTests(unittest.TestCase):
    def test_pinned_fields_are_collected_as_data_literals_and_accessor_components(self):
        for name in NEW_SCALARS+NEW_MAPS:
            with self.subTest(field=name):
                values=Values();_template('prefix-${'+name+'}-suffix','payload',values)
                for value in (('prefix-${'+name+'}-suffix').encode(),('${'+name+'}').encode(),name.encode(),b'prefix-',b'-suffix'):
                    self.assertIn(value,values.values)
        # Nested access is only for the proven map roots, never arbitrary scalars.
        for name in ('timestamp.secret','id.secret','node.secret','env.HOME','file.secret',
                     'vault.token','include.path','generated_alias','metadata.unknown'):
            with self.subTest(field=name),self.assertRaises(TemplateRefused):
                _template('${'+name+'}','payload',Values())
        with self.assertRaises(TemplateRefused) as caught:
            _template('${timestamp.secret}','payload',Values())
        self.assertEqual(caught.exception.reason,'field_contract')
        for name in ('headers[0]','pub_props.func()','headers..x','headers.unknown:-fallback'):
            with self.assertRaises(TemplateRefused):_template('${'+name+'}','payload',Values())

    def test_native_context_collects_new_roots_and_keeps_default_and_unknown_contexts_closed(self):
        payload=json.dumps({name:'${'+name+'}' for name in NEW_SCALARS+NEW_MAPS})
        raw=BASE+('rule_engine.rules.generated.actions=[{function=republish,args.payload='+json.dumps(payload)+'}]').encode()
        encoded=native_hocon_http_context(raw)
        with patch.object(vendor,'observe_vendor_acl',observe):
            values=read_hocon(raw,lambda _:encoded,file_profile=HTTP_PROFILE,product_image=vendor.IMAGE)
        self.assertIn(payload.encode(),values.values)
        self.assertIn(b'${timestamp}',values.values)
        self.assertIn(b'${pub_props.generated}',values.values)
        with self.assertRaises(SemanticRefused):read_hocon(raw,lambda _:encoded)
        bad=BASE+b'outside="${timestamp}"\n'
        with patch.object(vendor,'observe_vendor_acl') as observer:
            with self.assertRaises(SemanticRefused):
                read_hocon(bad,native_hocon_http_context,file_profile=HTTP_PROFILE,product_image=vendor.IMAGE)
            observer.assert_not_called()

    def test_cached_pinned_message_schema_and_actual_republish_preprocessor_without_render(self):
        script=b'''#!/usr/bin/env escript
%%! +S 1:1 +A 1 +t 65536 +hmax 8388608 +hmaxel false -noshell
main(_) ->
 code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
 Msg=emqx_message:make(<<"generated-client">>,0,<<"generated/topic">>,<<"generated-body">>),
 {Columns,Envs}=emqx_rule_events:eventmsg_publish(Msg),
 Expected=[id,clientid,username,payload,peerhost,peername,topic,qos,flags,pub_props,
           publish_received_at,client_attrs,event,timestamp,node],
 true=lists:sort(Expected)=:=lists:sort(maps:keys(Columns)),
 [headers]=maps:keys(Envs),
 {ok,{_,[{abstract_code,{raw_abstract_v1,Forms}}]}}=
     beam_lib:chunks(code:which(emqx_rule_runtime),[abstract_code]),
 [AddMetadata]=[F||F={function,_,add_metadata,2,_}<-Forms],
 [ApplyRule]=[F||F={function,_,apply_rule,3,_}<-Forms],
 true=has_key(AddMetadata,metadata),true=has_key(ApplyRule,rule_id),
 Names=["timestamp","id","node","event","peerhost","peername","publish_received_at",
        "flags.dup","headers.username","headers.properties.generated","pub_props.generated",
        "client_attrs.generated","metadata.rule_id"],
 Body=iolist_to_binary(lists:join(<<"/">>,[[<<"${">>,N,<<"}">>]||N<-Names])),
 Args=#{topic=><<"generated/topic">>,qos=>0,retain=>false,payload=>Body,
        mqtt_properties=>#{},user_properties=><<"${pub_props.'User-Property'}">>,direct_dispatch=>false},
 #{preprocessed_tmpl:=#{payload:=Template}}=emqx_rule_actions:pre_process_action_args(republish,Args),
 Names=emqx_template:placeholders(Template),
 io:put_chars("public-message-schema-preprocess-passed").
has_key({map_field_assoc,_,{atom,_,Key},_},Key)->true;
has_key(T,K) when is_tuple(T)->has_key(tuple_to_list(T),K);
has_key(L,K) when is_list(L)->lists:any(fun(X)->has_key(X,K) end,L);
has_key(_,_) -> false.
'''
        with tempfile.TemporaryDirectory(prefix='emqx-message-public-') as directory:
            path=Path(directory)/'check.escript';path.write_bytes(script);path.chmod(0o600)
            with tempfile.TemporaryFile() as output:
                status=run_native(directory,path.name,output=output);output.seek(0);fixed=output.read(128)
        self.assertEqual(status,0)
        self.assertEqual(fixed,b'public-message-schema-preprocess-passed')

    def test_actual_owner_capture_registers_new_field_values_and_keeps_unsealed_gate(self):
        import gzip
        import hashlib
        import io
        import tarfile
        import test_emqx_owner_source_capture as fixture
        from test_emqx_source_cold_capture import decoder
        from tests.backup import hafixtures as hx
        from emqx_private_boundary import PrivateFailure
        import emqx_owner_source_capture as owner
        fixture.OwnerHarnessTests.fixture(self)
        raw=BASE+b'rule_engine.rules.generated.actions=[{function=republish,args.payload="${timestamp}/${id}/${headers.username}/${pub_props.generated}"}]'
        with tarfile.open(fileobj=io.BytesIO(self.raw)) as tar:
            entries=[dict(name=m.name,data=raw if m.name.endswith('/configs/cluster.hocon')
                          else tar.extractfile(m).read()) for m in tar if m.isfile()]
        self.raw=hx.tar_bytes(entries);slug='fedcba98_woow-emqx'
        doc=hx.ha_doc((slug,),protected=True);doc['addons'][0]['version']='5.9.0'
        self.path.write_bytes(hx.outer_bytes([(slug+'.tar.gz',hx.v3_encrypt(gzip.compress(self.raw)))],doc))
        digest=hashlib.sha256(self.path.read_bytes()).hexdigest()
        with patch.object(owner,'native_cold_history',decoder),patch.object(vendor,'observe_vendor_acl',observe):
            with owner.capture_owner_source(self.path,password=self.password,expected_sha256=digest,
                 spool_directory=self.spool,file_dependency_profile=HTTP_PROFILE,product_image=vendor.IMAGE) as (captured,bound):
                for value in (b'${timestamp}',b'${id}',b'${headers.username}',b'${pub_props.generated}',b'username'):
                    self.assertIn(value,captured.registry._values)
                self.assertNotIn('mqtt-auth',captured.registry._sources)
                for operation in (captured.registry.seal,captured.registry.summary,
                                  lambda:captured.registry.scan(b'generated')):
                    with self.assertRaises(PrivateFailure):operation()
        self.assertEqual(list(self.spool.iterdir()),[])
