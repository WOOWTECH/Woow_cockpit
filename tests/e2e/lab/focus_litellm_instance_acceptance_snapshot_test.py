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
        role_queries=[]
        def pg_output(statement):
            # Only the external psql wire is simulated. PostgreSQL emits text
            # for md5(), and a quoted JSON string for to_json(md5()).
            if statement==digests.ROLES_SQL:role_queries.append(statement);return b'[[],[]]'
            elif "current_setting('server_version_num')" in statement:return b'["170011"]'
            elif statement.startswith('BEGIN ISOLATION'):return b'[]'
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
