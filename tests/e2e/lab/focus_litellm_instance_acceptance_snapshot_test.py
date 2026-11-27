"""Snapshot wire contract and retained failures; no PostgreSQL/device process."""
import base64
import json
import errno
from pathlib import Path
import sys
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
sys.path.insert(0,str(HERE.parents[2]/'backup-engine'))
import focus_litellm_instance_acceptance_run as driver
ops=driver.ops


class SnapshotTests(unittest.TestCase):
    def test_snapshot_real_json_reader_and_adapter_digest_accept_both_scalar_hashes(self):
        from woowbackup import cli,digests,ha_instance_access
        from woowbackup.adapters.quadlet_postgres import QuadletPostgresAdapter
        schema='123abcdef0123456789abcdef01234567';roles='abcdef0123456789abcdef0123456789'
        role_queries=[];table_queries=[]
        def pg_output(statement):
            # Only the external psql wire is simulated. PostgreSQL emits text
            # for md5(), and a quoted JSON string for to_json(md5()).
            if statement==digests.ROLES_SQL:role_queries.append(statement);return b'[[],[]]'
            elif "current_setting('server_version_num')" in statement:return b'["170011"]'
            elif statement==digests.LIST_SQL:   # the product lists the tables first when exclude_tables is not empty
                return b'[[11,"public","LiteLLM_Config"],[12,"public","LiteLLM_DailyUserSpend"],[13,"public","LiteLLM_ProxyWorkerHeartbeat"]]'
            elif statement.startswith('BEGIN ISOLATION'):table_queries.append(statement);return b'[]'
            elif statement.startswith('SELECT json_agg(datname'):return b'["litellm","postgres"]'
            elif statement==ha_instance_access.capture_sql('litellm'):
                return json.dumps({'database':['litellm',[]],'schemas':[],'relations':[],'columns':[],'extensions':[]}).encode()
            elif 'FROM pg_attribute a JOIN pg_class' in statement:value=schema
            elif 'FROM pg_authid;' in statement:value=roles
            elif 'pg_db_role_setting' in statement or 'pg_auth_members;' in statement:return b'[]'
            elif 'FROM pg_database;' in statement:return b'[["litellm","litellm"],["postgres","litellm"]]'
            else:raise AssertionError('unexpected SQL contract')
            return (json.dumps(value) if statement.startswith('SELECT to_json(md5(') else value).encode()
        def owner(*argv,**kw):return SimpleNamespace(returncode=0,stdout=pg_output(kw['data'].decode()),stderr=b'')
        class Runner:
            def podman(self,*argv,**kw):
                raw=pg_output(kw['input'].decode()) if 'input' in kw else b'1'
                return SimpleNamespace(returncode=0,stdout=raw,stderr=b'')
        app=SimpleNamespace(id='litellm',postgres=[{'id':'main','scope':'instance','container':'litellm-postgres','user':'litellm'}])
        adapter=QuadletPostgresAdapter(app,Runner(),lambda _line:None)
        svc=SimpleNamespace(catalog=lambda:{'litellm':app},adapter=lambda _app:adapter)
        with tempfile.TemporaryDirectory() as root,patch.object(cli,'Services',return_value=svc),patch.object(ops,'owner',side_effect=owner):
            store=ops.Store('woowbk_focus_litellm_012345abcdef',parent=Path(root),create=True)
            result=ops.snapshot(store,'original')
            self.assertEqual(result['roles'],roles)
            self.assertEqual([v['schema'] for v in result['databases'].values()],[schema,schema])
            self.assertEqual(len(role_queries),2) # actual adapter exercised roles=True
            self.assertEqual(json.loads((store.path/'state.json').read_text())['snapshots']['original'],result)
            self.assertEqual(len(list(store.path.glob('original-*.digest'))),2)
            # The proxy's own background tables are left out of the digest: only table 11 (Config) is digested.
            self.assertEqual(set(table_queries),{digests.in_snapshot(digests.tables_sql([11]))})
            self.assertEqual(ops.restate(store,'original'),result)   # a snapshot taken with the exclusion is unchanged

    def test_restate_leaves_out_only_the_proxys_background_tables_and_never_user_data(self):
        # dev-d fullflow03: after the restore ONLY LiteLLM_DailyTeamSpend, LiteLLM_DailyUserSpend and
        # LiteLLM_ProxyWorkerHeartbeat differed from the snapshot taken before; every other table matched.
        from woowbackup import digests
        def lines(daily,heartbeat,config=1):
            return digests.pg_lines({'litellm':[['public','LiteLLM_Config','r',config,10,11],
                ['public','LiteLLM_DailyTeamSpend','r',daily,5,6],['public','LiteLLM_DailyUserSpend','r',daily,5,6],
                ['public','LiteLLM_ProxyWorkerHeartbeat','r',1,heartbeat,7],['public','LiteLLM_SpendLogs','r',2,8,9]]})
        with tempfile.TemporaryDirectory() as root:
            store=ops.Store('woowbk_focus_litellm_012345abcdef',parent=Path(root),create=True)
            for tag,rows in (('original',lines(0,3)),('recovered',lines(1,4)),('changed',lines(1,4,config=2))):
                digests.write_lines(store.path/(tag+'-0.digest'),rows)
            full=lambda tag:digests.read_pg_detail(store.path/(tag+'-0.digest'),what='t')[1]
            store.state['snapshots']={tag:{'database_names':['litellm'],'roles':'r',
                'databases':{'litellm':{'digest':full(tag),'access':'a','schema':'s'}}} for tag in ('original','recovered','changed')}
            store.save()
            self.assertNotEqual(full('original'),full('recovered'))            # the old whole-table comparison failed here
            original,recovered=ops.restate(store,'original'),ops.restate(store,'recovered')
            self.assertEqual(original,recovered)
            self.assertNotEqual(ops.restate(store,'changed'),original)          # a changed user-data table still shows
            self.assertEqual(ops.restate(store,'original'),original)            # idempotent
            self.assertEqual(json.loads((store.path/'state.json').read_text())['snapshots']['original']['databases']['litellm']['digest'],
                             full('original'))                                  # the stored snapshot itself is never rewritten
        for pattern in ('public.LiteLLM_Config','public.LiteLLM_SpendLogs','public.LiteLLM_VerificationToken','public.LiteLLM_CredentialsTable',
                        'public.LiteLLM_ProxyModelTable','public.settings','public._prisma_migrations'):
            self.assertFalse(digests.excluded_table(ops.VOLATILE_TABLES,*pattern.split('.',1)),pattern)
        for pattern in ('public.LiteLLM_DailyTeamSpend','public.LiteLLM_DailyUserSpend','public.LiteLLM_ProxyWorkerHeartbeat'):
            self.assertTrue(digests.excluded_table(ops.VOLATILE_TABLES,*pattern.split('.',1)),pattern)

    def test_recovery_compares_the_restated_original_with_a_fresh_tag_and_names_a_lasting_difference(self):
        with tempfile.TemporaryDirectory() as root:
            lease={'name':'woowbk_focus_litellm_012345abcdef','expires_utc':'2026-11-27T04:00:00+00:00'}
            c=driver.Controller(SimpleNamespace(receipt=Path(root)/'case.private.json'),lease,SimpleNamespace(drv=None))
            taken={'original':{}};asked=[]
            def run(recovered,expected):
                def op(name,**kw):
                    asked.append((name,kw.get('tag')))
                    if name=='receipt':return {'snapshots':dict(taken)}
                    if name=='snapshot':taken[kw['tag']]={};return recovered
                    if name=='snapshot_restate':return expected
                    raise AssertionError(name)
                c.op=op
            same={'roles':'r','databases':{'litellm':{'digest':'d1'}}}
            run(same,dict(same));c.verify_recovered_snapshot()
            self.assertEqual(asked,[('receipt',None),('snapshot','recovered'),('snapshot_restate','original')])
            asked.clear();run(same,dict(same));c.verify_recovered_snapshot()   # a repeated recovery never reuses a tag
            self.assertEqual(asked[1],('snapshot','recovered_again'))
            bad={'roles':'r2','databases':{'litellm':{'digest':'SECRET-LOOKING'}}}
            run(bad,same)
            with self.assertRaisesRegex(RuntimeError,'original_full_catalog_roles_rows'):c.verify_recovered_snapshot()
            self.assertEqual(c.r['recovery_snapshot_difference'],['.databases.litellm.digest','.roles'])
            self.assertNotIn('SECRET-LOOKING',json.dumps(c.r['recovery_snapshot_difference']))

    def test_cleanup_requests_are_accepted_by_the_engines_own_request_validation(self):
        # dev-d, b7 recover: the cleanup sent {"backup_id", "confirm"} to `delete`; the CLI schema has no such field, the request
        # was refused and both case backups stayed. The real validator now judges exactly what the controller builds.
        from woowbackup import cli
        self.assertEqual(driver.delete_request('20261127T062347Z-b872183e'),{'backup_id':'20261127T062347Z-b872183e'})
        self.assertTrue(cli.validate('delete',driver.delete_request('20261127T062347Z-b872183e')))
        self.assertTrue(cli.validate('ha-delete',driver.ha_delete_request('ha-9dc5994497d9d6ff4c3e')))
        with self.assertRaises(Exception):   # the old request really is refused by the same validator
            cli.validate('delete',{'backup_id':'20261127T062347Z-b872183e','confirm':True})

    def test_the_package_cleanup_is_not_repeated_once_it_finished_and_still_refuses_active_jobs(self):
        with tempfile.TemporaryDirectory() as root:
            store=ops.Store('woowbk_focus_litellm_012345abcdef',parent=Path(root),create=True)
            store.state.update(before={},install_intent=True,package_cleaned=True);store.save()
            with patch.object(ops,'inventory',return_value={'active_jobs':[]}),patch.object(ops,'owner',side_effect=AssertionError('no device call')):
                self.assertTrue(ops.cleanup_owned_package(store))
            with patch.object(ops,'inventory',return_value={'active_jobs':['j1']}),self.assertRaisesRegex(ValueError,'active jobs'):
                ops.cleanup_owned_package(store)
            store.state.pop('package_cleaned');store.state['installed_files']=None
            with patch.object(ops,'inventory',return_value={'active_jobs':[]}),self.assertRaisesRegex(ValueError,'partial install'):
                ops.cleanup_owned_package(store)   # without the flag the old protections are untouched

    def test_a_repeated_recovery_after_verified_data_skips_the_restore_and_finishes_the_cleanup(self):
        from woowbackup import cli
        with tempfile.TemporaryDirectory() as root:
            lease={'name':'woowbk_focus_litellm_012345abcdef','expires_utc':'2026-11-27T04:00:00+00:00'}
            c=driver.Controller(SimpleNamespace(receipt=Path(root)/'case.private.json'),lease,SimpleNamespace(drv=None))
            before={k:{} for k in ('catalogs','files','volumes','secrets','containers','external_containers','networks','units','timer')}
            before.update(running=[],package=False,config_directory=False,active_jobs=[],images=[],image_refs={})
            mine=['20261127T062347Z-b872183e','20261127T062657Z-cb247387']
            c.r.update(before=before,recovery_verified=True,full_safety=mine[0],install_intent=True,created_backups=mine,
                       before_backups=['20260101T000000Z-aaaaaaaa'],store_id='ha-9dc5994497d9d6ff4c3e',before_uploads=[])
            calls=[]
            c.credentials=lambda:calls.append('credentials');c.run=None
            c.job=lambda *a,**k:self.fail('no restore job may start again')
            def op(name,**kw):
                calls.append(name)
                if name=='inventory':return before
                if name=='cleanup_owned_package':return True
                raise AssertionError(name)
            c.op=op
            def helper(command,request=None):
                calls.append(command)
                if command=='list':return {'backups':[{'id':x} for x in ['20260101T000000Z-aaaaaaaa']+mine]}
                self.assertTrue(cli.validate(command,request))      # every request the cleanup sends is valid for the engine
                return {}
            c.helper=helper
            c.recover()
            self.assertEqual(calls.count('delete'),2);self.assertEqual(calls.count('ha-delete'),1)
            self.assertNotIn('snapshot',calls);self.assertTrue(c.r['complete'])

    def test_failed_operation_is_retained_on_device_and_host_before_cleanup(self):
        for denied in (False,True):
            with self.subTest(errno=denied),tempfile.TemporaryDirectory() as root:
                store=ops.Store('woowbk_focus_litellm_012345abcdef',parent=Path(root)/'device',create=True)
                secret_message='private exception message must not be serialized'
                stderr=b'fixed test error\n'+b'x'*40000
                def dispatch(q):
                    if q['op']=='snapshot':
                        if denied:raise PermissionError(errno.EACCES,secret_message)
                        # Run the actual nonzero subprocess boundary too.
                        with patch.object(ops.subprocess,'run',return_value=SimpleNamespace(
                                returncode=7,stdout=b'discarded SQL data',stderr=stderr)):
                            return ops.call(['fixed-test-psql'])
                    self.assertEqual(q['op'],'cleanup_owned_package')
                    self.assertEqual(len(list(store.path.glob('operation-error-*.json'))),1)
                    self.assertEqual(len(list(Path(root).glob('case.private.json.operation-error-*'))),1)
                    return True
                def transport(*_args,input,**_kwargs):
                    with patch.object(ops,'dispatch',side_effect=dispatch),patch.object(ops,'Store',return_value=store):
                        code,result=ops.run_request(json.loads(input))
                    return SimpleNamespace(returncode=code,stdout=json.dumps(result).encode(),stderr=b'')
                args=SimpleNamespace(receipt=Path(root)/'case.private.json')
                lease={'name':store.name,'expires_utc':'2026-11-27T04:00:00+00:00'}
                c=driver.Controller(args,lease,SimpleNamespace(drv=SimpleNamespace(root=transport)))
                with self.assertRaises(subprocess.CalledProcessError):c.op('snapshot',tag='original')
                device=json.loads(next(store.path.glob('operation-error-*.json')).read_text())
                host=json.loads(next(Path(root).glob('case.private.json.operation-error-*')).read_text())
                self.assertEqual(device['operation'],'snapshot')
                self.assertEqual(device['errno'],errno.EACCES if denied else None)
                self.assertEqual(device['class'],'PermissionError' if denied else 'CalledProcessError')
                self.assertEqual(host['device_error'],device)
                if not denied:
                    self.assertEqual(device['returncode'],7)
                    self.assertEqual(base64.b64decode(device['stderr_b64']),stderr[:16384])
                    self.assertTrue(device['stderr_truncated'])
                self.assertNotIn(secret_message,json.dumps(device))
                self.assertNotIn('discarded SQL data',json.dumps(device))
                c.op('cleanup_owned_package')
                self.assertEqual(len(c.r['operation_failures']),1)


if __name__=='__main__':unittest.main()
