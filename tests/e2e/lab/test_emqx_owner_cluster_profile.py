"""Canonical pinned cooked cluster fields; no synthetic boot default fallback."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from emqx_owner_target import owner_target_readers,OwnerCaptureRefused
import test_emqx_owner_target as fixtures


class ClusterProfileTests(unittest.TestCase):
    @contextmanager
    def quiet(self): yield

    def test_missing_wrong_and_untyped_fields_fail_with_fixed_reason(self):
        for root,key,prefix in (('cluster','discovery_strategy','cluster_discovery'),
                ('rpc','protocol','cluster_rpc_protocol'),
                ('cluster','proto_dist','cluster_proto_dist')):
            for mode in ('missing','type','unsupported'):
                config=fixtures.cooked_config()
                if mode=='missing': del config[root][key]
                elif mode=='type': config[root][key]=42
                else: config[root][key]=fixtures.Atom('private_unknown_protocol')
                transport=fixtures.OwnerProducerTests().transport([],config=config)
                with self.subTest(root=root,key=key,mode=mode),self.assertRaises(OwnerCaptureRefused) as caught:
                    with owner_target_readers(private_eval=transport,quiesce=self.quiet): pass
                self.assertEqual(caught.exception.phase,'cluster')
                self.assertEqual(caught.exception.reason,prefix+'_'+mode)
                self.assertNotIn('private_unknown',caught.exception.reason)

    def test_old_invented_fields_cannot_substitute_for_canonical_fields(self):
        config=fixtures.cooked_config()
        config['rpc']['driver']=config['rpc'].pop('protocol')
        config['node']['dist_proto']=config['cluster'].pop('proto_dist')
        with self.assertRaises(OwnerCaptureRefused) as caught:
            with owner_target_readers(private_eval=fixtures.OwnerProducerTests().transport([],config=config),
                    quiesce=self.quiet): pass
        self.assertEqual(caught.exception.reason,'cluster_rpc_protocol_missing')

    def test_actual_pinned_public_schema_names_defaults_and_alias(self):
        from emqx_native_runtime import run_native
        source=r'''#!/usr/bin/env escript
%%! +S 1:1 +A 1 -noshell
main([]) -> try
    code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
    Cluster=emqx_conf_schema:fields("cluster"),
    RPC=emqx_conf_schema:fields("rpc"),
    Node=emqx_conf_schema:fields("node"),
    inet_tcp=maps:get(default,proplists:get_value("proto_dist",Cluster)),
    manual=maps:get(default,proplists:get_value("discovery_strategy",Cluster)),
    Protocol=proplists:get_value("protocol",RPC),
    tcp=maps:get(default,Protocol), [driver]=maps:get(aliases,Protocol),
    undefined=proplists:get_value("driver",RPC),
    undefined=proplists:get_value("dist_proto",Node),
    undefined=proplists:get_value("proto_dist",Node),
    io:put_chars("canonical_schema_pass")
catch _:_ -> halt(2) end.
'''
        with tempfile.TemporaryDirectory(prefix='emqx-public-cluster-schema-') as directory:
            root=Path(directory)
            (root/'schema.escript').write_text(source)
            with tempfile.TemporaryFile() as out:
                self.assertEqual(run_native(root,'schema.escript',output=out),0)
                out.seek(0)
                self.assertEqual(out.read(128),b'canonical_schema_pass')
