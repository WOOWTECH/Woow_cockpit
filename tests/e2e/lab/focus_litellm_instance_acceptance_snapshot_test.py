"""Snapshot wire contract and retained failures; no PostgreSQL/device process."""
import base64
import json
from pathlib import Path
import sys
import tempfile
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


if __name__=='__main__':unittest.main()
