"""Generated pinned SQL AST / native HOCON / actual source Capture, no lab."""
import copy
import gzip
import hashlib
import io
import json
import struct
import tarfile
import unittest
from unittest.mock import patch

from emqx_hocon_context import SQL_PROFILE, HTTP_PROFILE
from emqx_native_hocon import native_hocon_sql_context, native_hocon_http_context
from emqx_semantic_readers import read_hocon, SemanticRefused
from emqx_native_runtime import IMAGE
from test_emqx_hocon_context_native import BASE, observe
import emqx_owner_file_hocon as vendor

SQL="SELECT payload.temperature AS temperature, timestamp AS ts, payload.sensor AS sensor FROM 'generated/#'"
BODY='${temperature}/${ts}/${sensor.value}'


def rule(sql=SQL, body=BODY, name='generated'):
    return ('rule_engine.rules.'+name+' {sql='+json.dumps(sql)+'\nactions=[{function=republish,args.payload='+json.dumps(body)+'}]}\n').encode()


def read(raw, encoded=None):
    return read_hocon(raw,(lambda _:encoded) if encoded else native_hocon_sql_context,
                      file_profile=SQL_PROFILE,product_image=IMAGE)


class NativeSqlAliasTests(unittest.TestCase):
    def test_native_pure_aliases_occurrence_hash_and_all_literals_collected(self):
        raw=BASE+rule()
        encoded=native_hocon_sql_context(raw)
        document=json.loads(encoded)['document']
        receipts=document['alias_bindings'];self.assertEqual(len(receipts),1)
        receipt=receipts[0]
        self.assertEqual(receipt['rule_path'],['rule_engine','rules','generated'])
        self.assertEqual(receipt['sql_sha256'],hashlib.sha256(SQL.encode()).hexdigest())
        self.assertEqual(receipt['aliases'],{'temperature':['payload','temperature'],'ts':['timestamp'],'sensor':['payload','sensor']})
        self.assertEqual(document['string_bindings'][receipt['binding_index']]['value'],BODY)
        with patch.object(vendor,'observe_vendor_acl',observe):
            values=read(raw,encoded)
        for value in (SQL.encode(),BODY.encode(),b'${temperature}',b'${ts}',b'${sensor.value}',
                      b'temperature',b'ts',b'timestamp',b'sensor'):
            self.assertIn(value,values.values)
        with patch.object(vendor,'observe_vendor_acl') as observer:
            with self.assertRaises(SemanticRefused):
                read_hocon(raw,native_hocon_http_context,file_profile=HTTP_PROFILE,product_image=IMAGE)
            observer.assert_not_called()

    def test_original_rule_effective_sql_overrides_and_concat_cannot_borrow(self):
        cases=[
            rule()+rule(sql="SELECT payload.other AS other FROM 'generated/#'",body='${other}'),
            rule(sql="SELECT payload.temperature AS temperature FROM 'generated/#'",body='${temperature}')+
                b'rule_engine.rules.generated.sql="SELECT payload.other AS other FROM \'generated/#\'"\n',
            ('rule_engine.rules.generated.sql='+json.dumps(SQL)+'\n').encode()+
                ('rule_engine.rules.generated.actions=[{function=republish,args.payload='+json.dumps(BODY)+'}]').encode(),
            rule(name='other',body='literal')+rule(sql="SELECT timestamp FROM 'generated/#'",body='${temperature}'),
            rule()+b'outside="${temperature}"\noutside="plain"\n',
            ('rule_engine.rules.generated {sql='+json.dumps(SQL)+'\nsql='+json.dumps(SQL)+
             '\nactions=[{function=republish,args.payload="${temperature}"}]}').encode(),
            ('rule_engine.rules.generated {sql="SELECT payload.temperature AS " "temperature FROM \'generated/#\'"\n'
             'actions=[{function=republish,args.payload="${temperature}"}]}').encode(),
        ]
        with patch.object(vendor,'observe_vendor_acl') as observer:
            for index,case in enumerate(cases):
                with self.subTest(case=index),self.assertRaises(SemanticRefused):read(BASE+case)
            observer.assert_not_called()
        # Identical SQL in complete separate original rule objects is safe;
        # BOTH historical template occurrences must retain their own witnesses.
        raw=BASE+rule(body='old-${temperature}')+rule(body='new-${temperature}')
        with patch.object(vendor,'observe_vendor_acl',observe):values=read(raw)
        self.assertIn(b'old-${temperature}',values.values)
        self.assertIn(b'new-${temperature}',values.values)

    def test_functions_reserved_aliases_sources_duplicates_and_unknown_aliases_stay_refused(self):
        cases=[
            ("SELECT json_decode(payload) AS parsed FROM 'generated/#'",'${parsed}'),
            ("SELECT unknown_module.danger(payload) AS parsed FROM 'generated/#'",'${parsed}'),
            ("SELECT timestamp + 1 AS future FROM 'generated/#'",'${future}'),
            ("SELECT env.HOME AS value FROM 'generated/#'",'${value}'),
            ("SELECT file.secret AS value FROM 'generated/#'",'${value}'),
            ("SELECT vault.token AS value FROM 'generated/#'",'${value}'),
            ("SELECT payload.value AS env FROM 'generated/#'",'${env}'),
            ("SELECT payload.value AS file FROM 'generated/#'",'${file}'),
            ("SELECT payload.value AS vault FROM 'generated/#'",'${vault}'),
            ("SELECT payload.value AS HOME FROM 'generated/#'",'${HOME}'),
            ("SELECT payload.a AS value, payload.b AS value FROM 'generated/#'",'${value}'),
            (SQL,'${unbound_alias}'),(SQL,'${ts.child}'),
        ]
        with patch.object(vendor,'observe_vendor_acl') as observer:
            for index,(sql,body) in enumerate(cases):
                with self.subTest(case=index),self.assertRaises(SemanticRefused):read(BASE+rule(sql,body))
            observer.assert_not_called()

    def test_native_witness_tampering_indices_effective_sql_and_reserved_names_refuse(self):
        raw=BASE+rule();original=json.loads(native_hocon_sql_context(raw))
        for kind in ('missing','duplicate','wrong_index','wrong_rule','wrong_hash','loader_source','loader_alias'):
            doc=copy.deepcopy(original);rows=doc['document']['alias_bindings'];row=rows[0]
            if kind=='missing':rows.clear()
            elif kind=='duplicate':rows.append(copy.deepcopy(row))
            elif kind=='wrong_index':row['binding_index']=0
            elif kind=='wrong_rule':row['rule_path'][2]='other'
            elif kind=='wrong_hash':row['sql_sha256']='0'*64
            elif kind=='loader_source':row['aliases']['temperature']=['env','HOME']
            else:row['aliases']['env']=['payload','value']
            with self.subTest(case=kind),patch.object(vendor,'observe_vendor_acl') as observer:
                with self.assertRaises(SemanticRefused):read(raw,json.dumps(doc).encode())
                observer.assert_not_called()

    def test_generated_fixed_frame_actual_capture_registry_unsealed_and_cleanup(self):
        from test_emqx_owner_source_capture import OwnerHarnessTests
        from test_emqx_source_cold_capture import decoder
        from tests.backup import hafixtures as hx
        from emqx_private_boundary import PrivateFailure
        import emqx_owner_source_capture as owner
        import emqx_arm_source_owner as framed
        import emqx_source_profiles as profiles
        from dataclasses import replace
        import contextlib
        OwnerHarnessTests.fixture(self)
        raw=BASE+rule()
        with tarfile.open(fileobj=io.BytesIO(self.raw)) as tar:
            entries=[dict(name=m.name,data=raw if m.name.endswith('/configs/cluster.hocon')
                          else tar.extractfile(m).read()) for m in tar if m.isfile()]
        self.raw=hx.tar_bytes(entries);slug='fedcba98_woow-emqx'
        doc=hx.ha_doc((slug,),protected=True);doc['addons'][0]['version']='5.9.0'
        self.path.write_bytes(hx.outer_bytes([(slug+'.tar.gz',hx.v3_encrypt(gzip.compress(self.raw)))],doc))
        digest=hashlib.sha256(self.path.read_bytes()).hexdigest()
        key=self.password.encode();cipher=self.path.read_bytes()
        frame=struct.pack('!I',len(key))+key+struct.pack('!Q',len(cipher))+cipher
        actual=owner.capture_owner_source
        @contextlib.contextmanager
        def inspect(*args,**kwargs):
            with actual(*args,**kwargs) as (captured,bound):
                for value in (SQL.encode(),BODY.encode(),b'${temperature}',b'${ts}',b'${sensor.value}'):
                    self.assertIn(value,captured.registry._values)
                self.assertNotIn('mqtt-auth',captured.registry._sources)
                for operation in (captured.registry.seal,captured.registry.summary,
                                  lambda:captured.registry.scan(b'generated')):
                    with self.assertRaises(PrivateFailure):operation()
                yield captured,bound
        compiled=replace(profiles.ARM_SQL_ALIASES,sha256=digest,cold_receipt=(2,29))
        with patch.object(profiles,'ARM_SQL_ALIASES',compiled),patch.object(framed,'capture_owner_source',inspect), \
             patch.object(owner,'native_cold_history',decoder),patch.object(vendor,'observe_vendor_acl',observe):
            receipt=framed.consume_source_frame(io.BytesIO(frame),staging_parent=self.spool,
                                               mode='--source-vendor-acl-sql-aliases')
        self.assertEqual(receipt['registry'],'unsealed');self.assertEqual(receipt['full_scan'],'not-performed')
        self.assertEqual(receipt['restore'],'not-performed');self.assertEqual(list(self.spool.iterdir()),[])

    def test_pinned_sql_ast_and_republish_preprocess_never_evaluate_alias_expressions(self):
        import tempfile
        from pathlib import Path
        from emqx_native_runtime import run_native
        script=b'''#!/usr/bin/env escript
%%! +S 1:1 +A 1 +t 65536 +hmax 8388608 +hmaxel false -noshell
main(_) ->
 code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
 {ok,Ast}=emqx_rule_sqlparser:parse(<<"SELECT payload.temperature AS temperature, timestamp AS ts FROM 'generated/#'">>),
 [{as,{path,[{key,<<"payload">>},{key,<<"temperature">>}]},{var,<<"temperature">>}},
  {as,{var,<<"timestamp">>},{var,<<"ts">>}}]=emqx_rule_sqlparser:select_fields(Ast),
 %% An external function stays an AST value; no module/function lookup or call.
 {ok,External}=emqx_rule_sqlparser:parse(<<"SELECT nonexistent_module.danger(payload) AS denied FROM 'generated/#'">>),
 [{as,{'fun',_,_},{var,<<"denied">>}}]=emqx_rule_sqlparser:select_fields(External),
 Args=#{topic=><<"generated/topic">>,qos=>0,retain=>false,payload=><<"${temperature}/${ts}">>,
        mqtt_properties=>#{},user_properties=><<"${pub_props.'User-Property'}">>,direct_dispatch=>false},
 #{preprocessed_tmpl:=#{payload:=Template}}=emqx_rule_actions:pre_process_action_args(republish,Args),
 ["temperature","ts"]=emqx_template:placeholders(Template),
 io:put_chars("public-sql-ast-preprocess-passed").
'''
        with tempfile.TemporaryDirectory(prefix='emqx-sql-public-') as directory:
            path=Path(directory)/'check.escript';path.write_bytes(script);path.chmod(0o600)
            with tempfile.TemporaryFile() as output:
                status=run_native(directory,path.name,output=output);output.seek(0);fixed=output.read(128)
        self.assertEqual(status,0)
        self.assertEqual(fixed,b'public-sql-ast-preprocess-passed')
