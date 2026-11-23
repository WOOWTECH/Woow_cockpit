"""Public generated HTTP body AST and source Capture; no broker/network/lab."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import emqx_native_hocon as native
from emqx_native_runtime import IMAGE, run_native
from emqx_semantic_readers import read_hocon, SemanticRefused
import emqx_owner_file_hocon as vendor
from test_emqx_hocon_context_native import BASE, ACTION, observe, ACL

PROFILE='owner-pinned-image-vendor-acl-http-body-context-v1'
CONFIG=b'''connectors.http.generated_conn {url="http://generated.invalid"}
actions.http.generated_action {connector=generated_conn
 parameters.body="before-${payload.body}-${clientid}-${.}-after"}
rule_engine.rules.http_rule.actions=["http:generated_action"]
'''
RAW=BASE+ACTION+CONFIG


def read(raw):
    return read_hocon(raw,native.native_hocon_http_context,file_profile=PROFILE,product_image=IMAGE)


class HttpContextTests(unittest.TestCase):
    def test_positive_original_http_action_body_and_v1_still_refuses(self):
        with patch.object(vendor,'observe_vendor_acl',observe):
            values=read(RAW)
        for value in (b'before-${payload.body}-${clientid}-${.}-after',b'before-',b'-after',
                      b'${payload.body}',b'${clientid}',b'${.}',b'http:generated_action',
                      b'http://generated.invalid',b'prefix-${payload.body}',ACL):
            self.assertIn(value,values.values)
        from emqx_hocon_context import PROFILE as V1
        with patch.object(vendor,'observe_vendor_acl') as observer:
            with self.assertRaises(SemanticRefused):
                read_hocon(RAW,native.native_hocon_context,file_profile=V1,product_image=IMAGE)
            observer.assert_not_called()

    def test_wrong_context_binding_headers_and_loaders_refuse_before_observation(self):
        cases=[
            CONFIG.replace(b'parameters.body',b'parameters.headers.authorization'),
            CONFIG.replace(b'parameters.body',b'parameters.path'),
            CONFIG.replace(b'actions.http.generated_action',b'actions.unknown.generated_action'),
            CONFIG.replace(b'connector=generated_conn',b'connector=missing'),
            CONFIG.replace(b'connector=generated_conn',b'connector=generated_conn\nconnector=missing'),
            CONFIG.replace(b'connector=generated_conn\n',b''),
            CONFIG.replace(b'connectors.http.generated_conn',b'connectors.other.generated_conn'),
            CONFIG+b'outside="${payload.body}"\noutside="safe"\n',
            CONFIG+b'"${payload.body}"="safe"\n',
            CONFIG.replace(b'${payload.body}',b'${env.HOME}'),
            CONFIG.replace(b'${payload.body}',b'${file.secret}'),
            CONFIG.replace(b'${payload.body}',b'${vault.token}'),
            CONFIG.replace(b'${payload.body}',b'${HOME}'),
            CONFIG.replace(b'${payload.body}',b'file:/private'),
            CONFIG.replace(b'${payload.body}',b'ENV:HOME'),
            CONFIG.replace(b'parameters.body',b'parameters.keyfile'),
        ]
        with patch.object(vendor,'observe_vendor_acl') as observer:
            for index,config in enumerate(cases):
                with self.subTest(case=index),self.assertRaises(SemanticRefused):read(BASE+ACTION+config)
            observer.assert_not_called()

    def test_overrides_kept_and_old_unbound_declaration_cannot_borrow(self):
        old=CONFIG.replace(b'before-${payload.body}',b'historical-${payload.old}')
        with patch.object(vendor,'observe_vendor_acl',observe):
            values=read(BASE+ACTION+old+CONFIG)
        self.assertIn(b'historical-${payload.old}-${clientid}-${.}-after',values.values)
        for earlier in (old.replace(b'connector=generated_conn',b'connector=missing'),
                        old.replace(b'connector=generated_conn\n',b''),
                        old.replace(b'parameters.body',b'parameters.headers.authorization')):
            with patch.object(vendor,'observe_vendor_acl') as observer:
                with self.assertRaises(SemanticRefused):read(BASE+ACTION+earlier+CONFIG)
                observer.assert_not_called()
        for body in (b'"$" "{payload}"',b'"${payload}" "suffix"'):
            raw=BASE+CONFIG.replace(b'"before-${payload.body}-${clientid}-${.}-after"',body)
            with self.assertRaises(SemanticRefused):native.native_hocon_http_context(raw)

    def test_public_http_formatter_uses_template_parser_without_rendering(self):
        script=b'''#!/usr/bin/env escript
%%! +S 1:1 +A 1 +t 65536 +hmax 8388608 +hmaxel false -noshell
main(_) ->
 code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
 Body = <<"before-${payload.body}-${clientid}-${.}-after">>,
 %% Assert the formatter's ACTUAL pinned beam uses this parser for body.
 {ok,{_,[{abstract_code,{raw_abstract_v1,Forms}}]}}=
     beam_lib:chunks(code:which(emqx_bridge_http_connector),[abstract_code]),
 [Parse]=[F || F={function,_,parse_template,1,_} <- Forms],
 true=contains(Parse,{remote_call,emqx_template,parse}),
 [Request]=[F || F={function,_,preprocess_request,1,_} <- Forms],
 true=contains(Request,body_parse),
 T=emqx_template:parse(Body),
 ["payload.body","clientid",""]=emqx_template:placeholders(T),
 io:put_chars("public-http-template-parse-passed").
contains({call,_,{remote,_,{atom,_,M},{atom,_,F}},_},{remote_call,M,F}) -> true;
contains({call,_,{atom,_,maybe_parse_template},[{atom,_,body},_]},body_parse) -> true;
contains(T,P) when is_tuple(T) -> contains(tuple_to_list(T),P);
contains(L,P) when is_list(L) -> lists:any(fun(X)->contains(X,P) end,L);
contains(_,_) -> false.
'''
        with tempfile.TemporaryDirectory(prefix='emqx-http-public-') as directory:
            p=Path(directory)/'check.escript';p.write_bytes(script);p.chmod(0o600)
            with tempfile.TemporaryFile() as output:
                status=run_native(directory,p.name,output=output);output.seek(0);fixed=output.read(128)
        self.assertEqual(status,0)
        self.assertEqual(fixed,b'public-http-template-parse-passed')

    def test_owner_fixed_frame_actual_capture_native_registry_unsealed_and_cleanup(self):
        from test_emqx_owner_source_capture import OwnerHarnessTests
        from test_emqx_source_cold_capture import decoder
        from tests.backup import hafixtures as hx
        import emqx_owner_source_capture as owner
        import emqx_arm_source_owner as framed
        import emqx_source_profiles as profiles
        from dataclasses import replace
        from emqx_private_boundary import PrivateFailure
        OwnerHarnessTests.fixture(self)
        with tarfile.open(fileobj=io.BytesIO(self.raw)) as tar:
            entries=[dict(name=m.name,data=RAW if m.name.endswith('/configs/cluster.hocon')
                          else tar.extractfile(m).read()) for m in tar if m.isfile()]
        self.raw=hx.tar_bytes(entries);slug='fedcba98_woow-emqx'
        doc=hx.ha_doc((slug,),protected=True);doc['addons'][0]['version']='5.9.0'
        self.path.write_bytes(hx.outer_bytes([(slug+'.tar.gz',hx.v3_encrypt(gzip.compress(self.raw)))],doc))
        self.digest=hashlib.sha256(self.path.read_bytes()).hexdigest()
        actual=owner.capture_owner_source
        import contextlib
        @contextlib.contextmanager
        def inspect_capture(*args,**kwargs):
            with actual(*args,**kwargs) as (captured,bound):
                self.assertIn(b'before-${payload.body}-${clientid}-${.}-after',captured.registry._values)
                self.assertIn(b'before-',captured.registry._values)
                self.assertNotIn('mqtt-auth',captured.registry._sources)
                for operation in (captured.registry.seal,captured.registry.summary,
                                  lambda:captured.registry.scan(b'generated')):
                    with self.assertRaises(PrivateFailure):operation()
                yield captured,bound
        key=self.password.encode();cipher=self.path.read_bytes()
        frame=struct.pack('!I',len(key))+key+struct.pack('!Q',len(cipher))+cipher
        compiled=replace(profiles.ARM_HTTP_CONTEXT,sha256=self.digest,cold_receipt=(2,29))
        with patch.object(owner,'native_cold_history',decoder),patch.object(vendor,'observe_vendor_acl',observe), \
             patch.object(framed,'capture_owner_source',inspect_capture),patch.object(profiles,'ARM_HTTP_CONTEXT',compiled), \
             patch.object(native,'native_hocon_http_context',wraps=native.native_hocon_http_context) as parser:
            receipt=framed.consume_source_frame(io.BytesIO(frame),staging_parent=self.spool,
                                               mode='--source-vendor-acl-http-body')
            parser.assert_called_once_with(RAW)
        self.assertEqual(receipt['registry'],'unsealed')
        self.assertEqual(receipt['full_scan'],'not-performed')
        self.assertEqual(receipt['restore'],'not-performed')
        self.assertEqual(list(self.spool.iterdir()),[])
