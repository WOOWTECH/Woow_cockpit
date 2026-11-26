"""Offline preparation boundaries. No application/runtime acceptance is claimed."""
import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO/'backup-engine'))
spec = importlib.util.spec_from_file_location('focus_n8n_instance', HERE/'focus_n8n_instance_acceptance.py')
case = importlib.util.module_from_spec(spec)
spec.loader.exec_module(case)
from woowbackup import catalog
from woowbackup.paths import Paths

NAME = 'woowbk_focus_n8n_0123456789ab'


def original():
    return json.loads((REPO/'snippets/focus-n8n-instance-acceptance/found-metadata.json').read_text())['entry']


class CatalogTests(unittest.TestCase):
    def test_complete_found_entry_validates_and_changes_only_scope(self):
        before = original()
        after = case.instance_entry(before)
        expected = copy.deepcopy(before)
        expected['postgres'][0]['scope'] = 'instance'
        del expected['postgres'][0]['database']
        self.assertEqual(after, expected)
        self.assertEqual(before, original())
        user = SimpleNamespace(pw_name='appowner', pw_uid=1013, pw_gid=1013, pw_dir='/home/appowner')
        app = catalog.validate_entry(after, paths=Paths(), user_lookup=lambda _: user)
        self.assertEqual(app.postgres[0]['scope'], 'instance')
        self.assertEqual(app.postgres[0]['database'], 'postgres')
        self.assertEqual(app.config_files[0]['path'], '.config/n8n/n8n.env')

    def test_other_app_owner_instance_or_missing_volume_is_not_guessed(self):
        changes = [('owner', 'someone'), ('id', 'litellm')]
        for key, value in changes:
            entry = original(); entry[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                case.instance_entry(entry)
        for key, value in [('scope', 'instance'), ('database', 'postgres'), ('user', 'postgres'),
                           ('data_volume', None), ('container', 'other-pg')]:
            entry = original(); entry['postgres'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                case.instance_entry(entry)

    def test_two_pg_items_are_refused(self):
        entry = original(); entry['postgres'] *= 2
        with self.assertRaises(ValueError):
            case.instance_entry(entry)


class ResolverFixtureTests(unittest.TestCase):
    def units(self):
        return {name: ('[Container]\nEnvironmentFile=%h/.config/n8n/n8n.env\n'
                       'Environment=DB_POSTGRESDB_DATABASE=n8n\n'
                       'Environment=DB_POSTGRESDB_USER=n8n\n' +
                       ('Exec=worker\n' if 'worker' in name else '')).encode() for name in case.APP_FILES}

    def test_all_three_queue_units_use_retained_env_without_changing_other_settings(self):
        units = self.units(); env = b'EXAMPLE_UNRELATED_VALUE=private-fixture\n'
        changed = case.resolver_files(units, env, NAME)
        for name in case.APP_FILES:
            self.assertEqual(changed[name], units[name].replace(b'Environment=DB_POSTGRESDB_DATABASE=n8n\n', b''))
        self.assertEqual(changed['.config/n8n/n8n.env'], env + ('DB_POSTGRESDB_DATABASE='+NAME+'\n').encode())
        self.assertIn(b'Environment=DB_POSTGRESDB_DATABASE=n8n\n', units['n8n.container'])

    def test_an_env_file_without_final_newline_has_separate_assignment(self):
        changed = case.resolver_files(self.units(), b'TZ=Asia/Taipei', NAME)
        self.assertIn(b'Asia/Taipei\nDB_POSTGRESDB_DATABASE=', changed['.config/n8n/n8n.env'])

    def test_existing_direct_or_file_value_refuses_instead_of_inventing_precedence(self):
        for line in (b'DB_POSTGRESDB_DATABASE=old', b'DB_POSTGRESDB_DATABASE_FILE=/run/secret',
                     b' export DB_POSTGRESDB_DATABASE = old'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                case.resolver_files(self.units(), line, NAME)

    def test_an_inline_shadow_or_secret_input_refuses_fixture(self):
        for extra in (b'Environment=DB_POSTGRESDB_DATABASE_FILE=/tmp/name\n',
                      b'PodmanArgs=--env DB_POSTGRESDB_DATABASE=old\n',
                      b'Secret=db,type=env,target=DB_POSTGRESDB_DATABASE\n'):
            units = self.units(); units['n8n-webhook.container'] += extra
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                case.resolver_files(units, b'TZ=UTC\n', NAME)

    def test_changed_line_ending_missing_worker_or_unknown_layout_refuses(self):
        for change in ('crlf', 'missing_worker', 'different_path', 'two_assignments'):
            units = self.units()
            if change == 'crlf': units['n8n.container'] = units['n8n.container'].replace(b'\n', b'\r\n')
            if change == 'missing_worker': del units['n8n-worker.container']
            if change == 'different_path': units['n8n.container'] = units['n8n.container'].replace(b'/n8n.env', b'/other.env')
            if change == 'two_assignments': units['n8n.container'] += b'Environment=DB_POSTGRESDB_DATABASE=n8n\n'
            with self.subTest(change=change), self.assertRaises(ValueError):
                case.resolver_files(units, b'TZ=UTC\n', NAME)


class SafetyTests(unittest.TestCase):
    def test_sql_names_cannot_escape_own_namespace(self):
        for name in ('n8n', 'postgres', NAME+'"; DROP DATABASE n8n;--', '../marker', NAME+'\n'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                case.case_sql(name)

    def test_both_databases_exist_and_marker_requires_real_rollback(self):
        sql = case.case_sql(NAME)
        self.assertEqual(sql['clone_on_postgres'], 'CREATE DATABASE "'+NAME+'" WITH TEMPLATE "n8n" OWNER "n8n";')
        self.assertFalse(any('DROP DATABASE' in value for value in sql.values()))
        self.assertIn('after-import', sql['rollback_marker'])
        self.assertIn('to_json(count(*)=1)', sql['rollback_check'])

    def test_failure_is_once_at_app_start_with_restart_policy_disabled(self):
        text = case.failure_dropin(NAME)
        self.assertIn('Restart=no\nExecStartPre=', text)
        self.assertIn('rm -f %h/.local/state/'+NAME+'.fail-once; exit 1;', text)
        self.assertNotIn('postgres', text)

    def test_preflight_needs_exact_app_mode_and_every_check(self):
        reply = {'preflight': {'ok': True, 'checks': [{'status': 'ok'}], 'apps': [
            {'id': 'n8n', 'mode': 'inplace', 'restorable': True, 'checks': [{'status': 'ok'}]}]}}
        self.assertTrue(case.preflight_ready(reply))
        for mutate in (lambda r: r['preflight']['apps'].append({'id':'odoo'}),
                       lambda r: r['preflight']['apps'][0].update(mode='fresh'),
                       lambda r: r['preflight']['checks'].append({'status':'fail'}),
                       lambda r: r['preflight']['apps'][0]['checks'].append({'status':'fail'}),
                       lambda r: r['preflight']['apps'][0].update(issues=[{'level':'confirm'}])):
            bad = copy.deepcopy(reply); mutate(bad)
            self.assertFalse(case.preflight_ready(bad))

    def test_failed_start_without_positive_rollback_witness_cannot_pass(self):
        job = {'state': 'rolled-back', 'result': {'rolled_back': True, 'safety_backup_id': 'saved'}}
        proof = dict(consumed=True, marker=True, digests=True, application=True)
        self.assertTrue(case.rollback_proven(job, **proof))
        for key in proof:
            bad = dict(proof, **{key: False})
            self.assertFalse(case.rollback_proven(job, **bad))
        self.assertFalse(case.rollback_proven(dict(job, state='failed'), **proof))
        self.assertFalse(case.rollback_proven({'state':'rolled-back','result':{'rolled_back':True}}, **proof))

    def test_uncertain_recovery_never_authorizes_deletion(self):
        proof = dict(jobs_terminal=True, full_safety_restored=True, original_state=True, secret_scan=True)
        self.assertTrue(case.may_clean(**proof))
        for key in proof:
            for value in (False, None, 1):
                with self.subTest(key=key, value=value):
                    self.assertFalse(case.may_clean(**dict(proof, **{key: value})))

    def test_device_probe_programs_compile_and_do_not_emit_password_fields(self):
        for program in (case.MANIFEST_PROBE, case.ENDPOINT_PROBE, case.API_ACTION_PROBE):
            compile(program, '<prepared read-only probe>', 'exec')
            self.assertNotIn('rolpassword', program)
            self.assertNotIn('PASSWORD', program)
        self.assertIn('read_app_endpoint(r,q)', case.ENDPOINT_PROBE)
        self.assertIn('main_container(r,q)', case.ENDPOINT_PROBE)
        self.assertIn('local_backend(', case.ENDPOINT_PROBE)
        self.assertIn("s.archive.read_manifest(p,list(s.keys.identities()))", case.MANIFEST_PROBE)


class ApiProbeTests(unittest.TestCase):
    def execute(self, extra_node=False):
        requests = []
        def open_request(request, timeout):
            requests.append(request)
            path = request.full_url.removeprefix('http://127.0.0.1:15678')
            nodes = [{'name':'Start','type':'n8n-nodes-base.manualTrigger'},
                     {'name':'Set','type':'n8n-nodes-base.set'}]
            if extra_node:
                nodes.append({'name':'External','type':'n8n-nodes-base.httpRequest'})
            value = {
                '/rest/login': {'data':{}},
                '/rest/credentials': {'data':[{'name':'HA probe header','private':'do-not-publish'}]},
                '/rest/workflows': {'data':[{'name':'WOOW 匯入測試 - 手動','id':'fixture123'}]},
                '/rest/workflows/fixture123': {'data':{'nodes':nodes}},
                '/rest/workflows/fixture123/run': {'data':{'executionId':'1234'}},
                '/rest/executions/1234': {'data':{'workflowId':'fixture123','finished':True,'status':'success'}},
            }[path]
            class Response:
                status = 200
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def read(self, size): return json.dumps(value).encode()
            return Response()
        client = SimpleNamespace(open=open_request)
        stdout = io.StringIO()
        with patch('urllib.request.build_opener', return_value=client), \
                patch('sys.stdin', io.StringIO('{"email":"fixture@example.invalid","password":"do-not-publish"}')), \
                redirect_stdout(stdout):
            exec(case.API_ACTION_PROBE, {})
        self.assertNotIn('do-not-publish', stdout.getvalue())
        return json.loads(stdout.getvalue()), requests

    def test_fixed_safe_manual_workflow_uses_vendor_payload_and_only_reports_verdicts(self):
        result, requests = self.execute()
        self.assertEqual(result, dict(login=True, credential_visible=True, manual_action=True))
        action = next(r for r in requests if r.full_url.endswith('/run'))
        self.assertEqual(json.loads(action.data), {'triggerToStartFrom':{'name':'Start'}})

    def test_unexpected_workflow_node_never_starts_an_action(self):
        result, requests = self.execute(extra_node=True)
        self.assertFalse(result['manual_action'])
        self.assertFalse(any(r.full_url.endswith('/run') for r in requests))


class PacketTests(unittest.TestCase):
    def test_packet_is_source_bound_preparation_and_uses_fresh_full_safety(self):
        p = case.packet(REPO, 'a'*40, original(), NAME)
        self.assertEqual(p['stage'], 'preparation_only')
        self.assertFalse(any(p['authorization'].values()))
        self.assertEqual(p['helper_requests']['recover']['backup_id_from'], 'fresh_safety.result.backup_id')
        self.assertEqual(p['helper_requests']['fresh_safety']['request']['apps'], ['n8n'])
        self.assertIn('ha_n8n.py', p['engine_sha256'])
        self.assertLess(p['phase_order'].index('fresh_full_instance_safety'),
                        p['phase_order'].index('clone_and_environmentfile_fixture'))
        self.assertIn('limited_app_role_vendor_flow', p['not_proven'])

    def test_missing_cache_stops_without_any_container_command(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(case, 'LAB', Path(folder)), \
                patch.object(case.subprocess, 'check_output', side_effect=AssertionError('no command')):
            with self.assertRaises(ValueError):
                case.verify_cache()

    def test_run_flag_is_not_an_execution_backdoor(self):
        with patch.object(case.subprocess, 'check_output', side_effect=AssertionError('no command')):
            with self.assertRaises(SystemExit) as raised:
                case.main(['--run'])
            self.assertNotEqual(raised.exception.code, 0)


if __name__ == '__main__':
    unittest.main()
