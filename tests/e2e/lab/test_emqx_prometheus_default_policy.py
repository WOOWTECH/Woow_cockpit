"""Exact inactive public template policy. No broker, config values or env reads."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from emqx_owner_target import _no_refs, owner_target_readers, OwnerCaptureRefused
from emqx_target_vendor_policy import PROMETHEUS_DEFAULT_JOB
import test_emqx_owner_target as fixtures


class PrometheusDefaultPolicyTests(unittest.TestCase):
    def config(self,modern):
        fields={'enable':'false','job_name':PROMETHEUS_DEFAULT_JOB}
        return {'prometheus':{'push_gateway':fields} if modern else fields}

    def test_exact_disabled_profiles_only(self):
        for modern in (False,True):
            _no_refs(self.config(modern))
            for change in ('enabled','missing','boolean','custom','env','wrong_path','mixed'):
                config=self.config(modern)
                root=config['prometheus']
                fields=root['push_gateway'] if modern else root
                if change=='enabled': fields['enable']='true'
                if change=='missing': del fields['enable']
                if change=='boolean': fields['enable']=False
                if change=='custom': fields['job_name']=b'${custom}'
                if change=='env': fields['job_name']=b'${ENV_SECRET}'
                if change=='wrong_path': fields['custom']=fields.pop('job_name')
                if change=='mixed':
                    if modern: root['enable']='false'
                    else: root['push_gateway']={'enable':'false'}
                with self.subTest(modern=modern,change=change),self.assertRaises(OwnerCaptureRefused) as caught:
                    _no_refs(config)
                self.assertEqual(caught.exception.reason,'reference_template')
                if change not in ('wrong_path',): self.assertEqual(caught.exception.reference['key'],'job_name')

    def test_full_five_readers_and_registered_template(self):
        @contextmanager
        def quiet(): yield
        for modern in (False,True):
            config=fixtures.cooked_config()
            fields={'enable':False,'job_name':PROMETHEUS_DEFAULT_JOB}
            config['prometheus']={'push_gateway':fields} if modern else fields
            transport=fixtures.OwnerProducerTests().transport([],config=config)
            with owner_target_readers(private_eval=transport,quiesce=quiet) as readers:
                self.assertEqual(len(readers),5)
                with self.assertRaises(Exception): readers.persisted_values.scan(PROMETHEUS_DEFAULT_JOB)

    def test_fixed_pinned_public_schema_and_semantics(self):
        from emqx_native_runtime import run_native
        source=r'''#!/usr/bin/env escript
%%! +S 1:1 +A 1 -noshell
main([]) -> try
    code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
    Default = <<"${name}/instance/${name}~${host}">>,
    lists:foreach(fun(Section) ->
        Fields=emqx_prometheus_schema:fields(Section),
        Default=maps:get(default,proplists:get_value(job_name,Fields)),
        false=maps:get(default,proplists:get_value(enable,Fields))
    end,[push_gateway,legacy_deprecated_setting]),
    false=emqx_prometheus_config:is_push_gateway_server_enabled(
        #{enable=>false,push_gateway_server=>"http://127.0.0.1:9091"}),
    true=emqx_prometheus_config:is_push_gateway_server_enabled(
        #{enable=>true,push_gateway_server=>"http://127.0.0.1:9091"}),
    false=emqx_prometheus_config:is_push_gateway_server_enabled(
        #{push_gateway=>#{enable=>false,url=>"http://127.0.0.1:9091"}}),
    true=emqx_prometheus_config:is_push_gateway_server_enabled(
        #{push_gateway=>#{enable=>true,url=>"http://127.0.0.1:9091"}}),
    {Rendered,[]}=emqx_template:render(emqx_template:parse(Default),
        #{<<"name">>=><<"fixture">>,<<"host">>=><<"host">>,<<"cluster_name">>=><<"cluster">>}),
    <<"fixture/instance/fixture~host">>=unicode:characters_to_binary(Rendered),
    io:put_chars("public_schema_pass")
catch _:_ -> halt(2) end.
'''
        with tempfile.TemporaryDirectory(prefix='emqx-public-prometheus-fixture-') as directory:
            root=Path(directory)
            script=root/'schema.escript'
            script.write_text(source)
            with tempfile.TemporaryFile() as output:
                self.assertEqual(run_native(root,script.name,output=output),0)
                output.seek(0)
                self.assertEqual(output.read(128),b'public_schema_pass')
