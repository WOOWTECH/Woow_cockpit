"""Structured instance access: app data objects only, bounded facts and quoted identifiers."""
import copy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from woowbackup import ha_instance_access as access
from woowbackup import ha_n8n
from woowbackup import ha_litellm, hatarget, tempctr
from woowbackup.flows import Cancelled
from woowbackup.podman import Result
from woowbackup.adapters.quadlet_postgres import QuadletPostgresAdapter
from woowbackup.errors import BackupError
from .test_adapter_ha_instance import access_plan


class AccessPlanTests(unittest.TestCase):
    def test_actual_litellm_probe_reads_process_url_and_refuses_config_overrides(self):
        # Execute the production fixed probe, redirecting ONLY /proc enumeration to bounded synthetic process files.
        # URL/YAML parsing, file reads and redaction run unchanged; no podman response stands in for this resolver.
        with tempfile.TemporaryDirectory() as directory:
            proc=Path(directory)/'3141599'; proc.mkdir()
            config=Path(directory)/'config.yaml'
            current=b'DATABASE_URL=postgresql://app:private-password@litellm-postgres:5432/litellm\0'
            def probe(args,body):
                (proc/'cmdline').write_bytes(b'\0'.join(a.encode() for a in ['/usr/local/bin/litellm',*args]))
                (proc/'environ').write_bytes(current)
                config.write_text(body)
                original=Path.iterdir
                def iterdir(path):
                    return iter([proc]) if str(path)=='/proc' else original(path)
                output=io.StringIO()
                with mock.patch.object(Path,'iterdir',iterdir),contextlib.redirect_stdout(output):
                    exec(compile(ha_litellm.CONNECTION_PROBE,'fixed-litellm-probe','exec'),{})
                self.assertNotIn('private-password',output.getvalue())
                return json.loads(output.getvalue())
            valid='general_settings:\n  database_url: os.environ/DATABASE_URL\n'
            for args in (['--config',str(config)],['--config='+str(config)],['-c',str(config)]):
                self.assertEqual(probe(args,valid),{'database':'litellm','user':'app','host':'litellm-postgres','port':5432})
            for body in ('general_settings:\n  database_url: postgresql://app:x@other/another\n',
                         'environment_variables:\n  DATABASE_URL: postgresql://app:x@litellm-postgres/another\n'):
                with self.assertRaises(SystemExit):
                    probe(['--config='+str(config)],body)
            with self.assertRaises(SystemExit):
                probe(['--database_url=postgresql://app:x@litellm-postgres/another'],'{}')

    def test_litellm_stopped_proxy_dependencies_and_partial_failure_cancel_are_scoped(self):
        from .test_ha_litellm import QUADLETS
        sources = dict(QUADLETS, **{'queue.container': b'[Container]\nContainerName=queue\n'})
        names = {'litellm.service':'litellm', 'litellm-postgres.service':'litellm-postgres', 'queue.service':'queue'}
        pg = {'container':'litellm-postgres'}
        app = SimpleNamespace(id='litellm', name='LiteLLM', postgres=[pg])
        for phase, failure in ((None,None), ('litellm',BackupError('job-failed','partial start')),
                               ('litellm-postgres',Cancelled()), ('read',Cancelled())):
            original = {'litellm':False, 'litellm-postgres':False, 'queue':True}
            state, events, temps = dict(original), [], []
            class Runner:
                owner='appowner'; uid=1000; home='/home/appowner'
                def systemctl(self, *args, **kwargs):
                    if args[0]=='show':
                        rows=[]
                        for unit in args[args.index('--')+1:]:
                            active='active' if state[names[unit]] else 'inactive'
                            deps='litellm-postgres.service queue.service' if unit=='litellm.service' else ''
                            rows.append(f'Id={unit}\nLoadState=loaded\nActiveState={active}\nRequires={deps}\nWants=\nBindsTo=')
                        return Result(0,'\n\n'.join(rows).encode(),b'')
                    container=names[args[-1]]
                    events.append((args[0],container))
                    state[container]=args[0]=='start'
                    if args[0]=='start' and container==phase: raise failure
                    if args[0]=='stop': assert 'abort' not in kwargs
                    return Result(0,b'',b'')
                def podman(self,*args,**kwargs):
                    if args[:2]==('container','inspect'):
                        return Result(0,b'true' if state[args[-1]] else b'false',b'')
                    if args[0]=='exec' and 'pg_isready' in args:
                        return Result(0 if state[args[1]] else 1,b'',b'')
                    if ha_litellm.CONNECTION_PROBE in args:
                        assert state['litellm'] and state['litellm-postgres']
                        if phase=='read': raise failure
                        return Result(0,json.dumps({'database':'litellm','user':'app_login',
                            'host':'litellm-postgres','port':5432}).encode(),b'')
                    raise AssertionError(args[:2])
            real_temp=tempctr.TempObjects
            def construct(*args,**kwargs):
                value=real_temp(*args,**kwargs); temps.append(value); return value
            adapter=QuadletPostgresAdapter(app,Runner(),lambda _line:None)
            with mock.patch.object(hatarget,'ensure_user_manager',lambda *_a:None), \
                    mock.patch.object(tempctr,'TempObjects',side_effect=construct):
                if failure:
                    with self.assertRaises(type(failure)):
                        adapter._read_ha_app_connection(pg,sources)
                else:
                    self.assertEqual(adapter._read_ha_app_connection(pg,sources)['database'],'litellm')
            self.assertEqual(state,original)
            self.assertNotIn(('stop','queue'),events)
            if phase!='litellm-postgres':
                self.assertLess(events.index(('start','litellm-postgres')),events.index(('start','litellm')))
            state['litellm']=True
            self.assertEqual(temps[0].cleanup(),[])
            self.assertTrue(state['litellm'],'scoped callbacks cannot later stop the restored proxy')

    def test_endpoint_lifecycle_finishes_before_restore_and_on_error_or_cancel(self):
        from .test_adapter import QUADLETS
        sources = dict(QUADLETS)
        sources['woowbk-demo-app.container'] += b'Network=woowbk-demo.network\n'
        runner = SimpleNamespace(owner='appowner', uid=1000, home='/home/appowner')
        app = SimpleNamespace(id='n8n')
        adapter = QuadletPostgresAdapter(app, runner, lambda _line: None)
        pg = {'container': 'woowbk-demo-db'}
        for failure in (None, BackupError('job-failed', 'bounded failure'), Cancelled()):
            state, temps = {'running': False}, []
            def prepare(work, current, *, quadlets):
                self.assertIs(current, app)
                self.assertIs(quadlets, sources)
                temp = work.temp(app)
                temps.append(temp)
                temp.put_back_later('main', lambda: state.update(running=False))
                state['running'] = True
                if failure:
                    raise failure
                return {'database': 'notes', 'user': 'app', 'host': 'woowbk-demo-db', 'port': 5432}
            with mock.patch.object(ha_n8n, 'prepare_app_endpoint', prepare, create=True), \
                    mock.patch.object(ha_n8n, 'main_container', return_value='woowbk-demo-app', create=True):
                if failure:
                    with self.assertRaises(type(failure)) as caught:
                        adapter._read_ha_app_connection(pg, sources)
                    self.assertIs(caught.exception, failure)
                else:
                    self.assertEqual(adapter._read_ha_app_connection(pg, sources)['database'], 'notes')
            self.assertFalse(state['running'], 'scoped cleanup already completed')
            state['running'] = True  # ordinary restore has now started the restored application
            self.assertEqual(temps[0].cleanup(), [])
            self.assertTrue(state['running'], 'no deferred callback may stop the restored application')

    def test_valid_app_access_and_installed_extension_facts(self):
        for app_id in ('n8n', 'litellm'):
            plan = access_plan('db_owner', table_owner='table_owner', app_role='app_login', extension=True)
            self.assertIs(access.validate(plan, app_id), plan)

    def test_malformed_program_or_omitted_schema_facts_are_rejected(self):
        plan = access_plan('db_owner', table_owner='table_owner')
        mutations = [lambda p: p.update(programs=['arbitrary SQL']),
                     lambda p: p['schemas'].append(['omitted', 'db_owner', []]),
                     lambda p: p['relations'][0].__setitem__(2, 'f'),
                     lambda p: p['relations'][0].__setitem__(0, 'omitted'),
                     lambda p: p['relations'][0][-1].append(['app', 'SUPERUSER', False]),
                     lambda p: p['relations'][0][-1].append(['app', 'SELECT', 1]),
                     lambda p: p['extensions'].append(['vector', 'missing; SQL', 'public']),
                     lambda p: p['extensions'].append(['vector', '1.0', 'omitted'])]
        for mutate in mutations:
            bad = copy.deepcopy(plan)
            mutate(bad)
            with self.subTest(mutate=mutate), self.assertRaises((ValueError, TypeError)):
                access.validate(bad, 'litellm')
        with self.assertRaises(ValueError):
            access.validate(plan, 'hermes')

    def test_replay_intersects_moved_objects_and_never_recreates_programs_or_omitted_data(self):
        plan = access_plan('db_owner', table_owner='table_owner', app_role='app_login')
        plan['relations'].append(['public', 'old_table_omitted', 'r', 'table_owner', []])
        present = copy.deepcopy(plan)
        present['relations'].pop()
        script = access.restore_sql(plan, present, 'litellm')
        self.assertIn('ALTER TABLE "public"."marker" OWNER TO "table_owner";', script)
        self.assertIn('GRANT INSERT ON TABLE "public"."marker" TO "app_login";', script)
        self.assertIn('GRANT CREATE ON SCHEMA "public" TO "app_login";', script)
        self.assertNotIn('old_table_omitted', script)
        self.assertNotIn('CREATE SCHEMA', script)
        self.assertNotIn('FUNCTION', script)
        self.assertNotIn('omitted', access.capture_sql('litellm'))

    def test_catalog_identifiers_are_quoted_as_data(self):
        self.assertEqual(access.ident('a";b'), '"a"";b"')
        self.assertEqual(access.literal("v'1"), "'v''1'")

    def test_column_privileges_remain_narrow_and_keep_grant_options(self):
        plan = access_plan('db_owner', table_owner='table_owner')
        plan['columns'] = [['public', 'marker', 'value', [['app_login', 'SELECT', True]]]]
        access.validate(plan, 'n8n')
        script = access.restore_sql(plan, plan, 'n8n')
        self.assertIn('GRANT SELECT ("value") ON TABLE "public"."marker" TO "app_login" WITH GRANT OPTION;', script)
        self.assertNotIn('GRANT SELECT ON TABLE "public"."marker" TO "app_login";', script)

    def test_password_rotation_only_masks_known_password_components(self):
        pairs = [(b'DB_POSTGRESDB_PASSWORD=old\nDB_POSTGRESDB_DATABASE=notes\n',
                  b'DB_POSTGRESDB_PASSWORD=new\nDB_POSTGRESDB_DATABASE=notes\n'),
                 (b'DATABASE_URL=postgresql://app:old@pg:5432/litellm\n',
                  b'DATABASE_URL=postgresql://app:new@pg:5432/litellm\n')]
        for before, after in pairs:
            self.assertTrue(access.password_only_change(before, after))
            self.assertFalse(access.password_only_change(before, after.replace(b'notes', b'other').replace(b'/litellm', b'/other')))
        self.assertFalse(access.password_only_change(b'UNKNOWN_PASSWORD=old\n', b'UNKNOWN_PASSWORD=new\n'))
        self.assertFalse(access.password_only_change(b'DATABASE_URL=postgresql://app:pw@pg/litellm\n',
                                                    b'DATABASE_URL=postgresql://app:pw@other/litellm\n'))

    def test_backend_binding_refuses_an_equally_named_foreign_database(self):
        from .test_adapter import QUADLETS
        quadlets = dict(QUADLETS)
        quadlets['woowbk-demo-app.container'] += b'Network=woowbk-demo.network\n'
        postgres = {'container': 'woowbk-demo-db'}
        self.assertTrue(access.local_backend({'host': 'woowbk-demo-db', 'port': 5432}, quadlets,
                                            'woowbk-demo-app.container', postgres))
        self.assertFalse(access.local_backend({'host': 'foreign-db', 'port': 5432}, quadlets,
                                             'woowbk-demo-app.container', postgres))
