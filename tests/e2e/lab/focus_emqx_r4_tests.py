"""Offline checks only: generated inputs, exact lease and Runner targets. No process/network/native fixture."""
import ast
import datetime
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fx = load('focus_emqx_r4_fixtures')


def runtime_parts(*names):
    source = ast.parse((HERE / 'focus_emqx_r4_runtime.py').read_text())
    nodes = [x for x in source.body if isinstance(x, (ast.FunctionDef, ast.ClassDef)) and x.name in names]
    scope = {'Path': Path, 're': __import__('re'), 'ROOT': HERE, 'JOB': 'offline-r4', 'fx': fx,
             'base64': __import__('base64'), 'subprocess': SimpleNamespace(PIPE=-1, run=mock.Mock()),
             'shutil': SimpleNamespace(disk_usage=lambda _: SimpleNamespace(free=20 * 1024**3))}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), '<r4-owned-functions>', 'exec'), scope)
    return scope


class GeneratedInputsTests(unittest.TestCase):
    def test_exact_missing_matrix_preserves_d0_instead_of_rerunning_it(self):
        self.assertEqual(set(fx.BY_ID), {'plain', 'dead_row', 'noauth', 'http_dummy', 'file_dummy', 'jq_constant',
                         'env_dummy', 'admin_public', 'changed_acl', 'psk', 'lost_auth_setting'})
        self.assertNotIn('D0', {x.decision for x in fx.CASES})

    def test_input_factories_are_fresh_and_accept_no_credentials_or_paths(self):
        first = fx.config('plain'); first['authentication'].clear()
        self.assertEqual(fx.config('plain')['authentication'][0]['password_hash_algorithm']['name'], 'plain')
        self.assertRaises(ValueError, fx.config, '../anything')
        self.assertTrue(all('/' not in name for name in fx.files()))
        self.assertIn(fx.DUMMY_PASSWORD.encode(), fx.files()['source.csv'])

    def test_all_input_urls_are_loopback_or_the_exact_owned_dummy_file(self):
        urls = []
        def walk(value):
            if isinstance(value, dict):
                for item in value.values(): walk(item)
            elif isinstance(value, list):
                for item in value: walk(item)
            elif isinstance(value, str) and '://' in value: urls.append(value)
        for case in fx.CASES: walk(fx.config(case.id))
        self.assertEqual(set(urls), {'http://127.0.0.1:18091/authn', 'http://127.0.0.1:18091/authz',
                                     'file:///fixture/file-dummy.txt'})
        self.assertNotIn('/proc', json.dumps([fx.config(x.id) for x in fx.CASES]))

    def test_env_jq_reads_only_the_named_synthetic_variable(self):
        sql = fx.config('env_dummy')['rule_engine']['rules']['r4_jq']['sql']
        self.assertIn('env.WOOW_R4_DUMMY', sql)
        self.assertEqual(fx.files()['dummy.env'], ('WOOW_R4_DUMMY=' + fx.DUMMY_ENV + '\n').encode())
        self.assertNotIn('env', fx.config('jq_constant')['rule_engine']['rules']['r4_jq']['sql'])

    def test_dead_row_uses_a_normal_algorithm_change_and_no_database_payload(self):
        self.assertEqual(fx.config('dead_row')['authentication'][0]['password_hash_algorithm']['name'], 'plain')
        self.assertEqual(fx.dead_row_update()['authentication'][0]['password_hash_algorithm']['name'], 'sha256')
        self.assertEqual(set(fx.dead_row_update()), {'authentication'})

    def test_noauth_and_real_acl_replacement_are_explicit(self):
        self.assertEqual(fx.config('noauth')['authentication'], [])
        self.assertNotEqual(fx.SOURCE_ACL, fx.TARGET_ACL)
        self.assertEqual(fx.config('changed_acl', target=True)['authorization']['sources'][0]['type'], 'built_in_database')
        self.assertEqual([x['type'] for x in fx.config('changed_acl')['authorization']['sources']], ['file'])

    def test_psk_uses_same_owned_identity_with_different_owned_values(self):
        files = fx.files()
        self.assertEqual(files['source.psk'].split(b':')[0], files['target.psk'].split(b':')[0])
        self.assertNotEqual(files['source.psk'], files['target.psk'])
        self.assertIn('emqx.device-psk', fx.BY_ID['psk'].confirms)


class DriverBoundaryTests(unittest.TestCase):
    def test_default_plan_and_bundle_start_no_process(self):
        with mock.patch('subprocess.run', side_effect=AssertionError('offline process forbidden')):
            module = load('focus_emqx_r4')
            with mock.patch('sys.stdout', new_callable=io.StringIO) as output:
                self.assertEqual(module.main([]), 0)
            self.assertFalse(json.loads(output.getvalue())['native_executed'])
            payload = module.bundle()
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            self.assertTrue(all(m.isfile() and not m.name.startswith('/') and '..' not in m.name.split('/')
                                for m in archive.getmembers()))
            self.assertIn('focus_emqx_r4_runtime.py', archive.getnames())
            self.assertFalse(any('installer' in x or x.endswith('.sh') for x in archive.getnames()))
        self.assertLessEqual(len(payload), 16 * 1024**2)

    def test_lease_is_bound_to_exact_case_commit_image_and_expiry(self):
        module = load('focus_emqx_r4')
        now = datetime.datetime(2026, 11, 27, tzinfo=datetime.timezone.utc)
        lease = {'device': 'woowbk-dev-d', 'case': 'EMQX-R4-generated:noauth', 'source_commit': 'a' * 40,
                 'image_config': fx.IMAGE, 'package_commands': False, 'expires': '2026-11-27T00:20:00+00:00',
                 'command': 'python3 -B -I tests/e2e/lab/focus_emqx_r4.py --run --case noauth'}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'lease.json'; path.write_text(json.dumps(lease))
            module.validate_lease(path, 'noauth', 'a' * 40, now)
            for key, wrong in [('case', 'E44-disposable-plugin-broker'), ('source_commit', 'b' * 40),
                               ('image_config', 'sha256:wrong'), ('expires', '2026-11-26T00:00:00+00:00'),
                               ('package_commands', True), ('device', 'woowbk-dev-e')]:
                with self.subTest(key=key):
                    path.write_text(json.dumps(dict(lease, **{key: wrong})))
                    self.assertRaises(ValueError, module.validate_lease, path, 'noauth', 'a' * 40, now)

    def test_actual_mutation_target_must_be_owned_not_just_some_argument(self):
        scope = runtime_parts('Runner'); runner = scope['Runner']()
        for args in [('exec', 'existing-app', 'woowbk-offline-r4-fake-argument'),
                     ('rm', 'existing-app', 'woowbk-offline-r4-fake-argument'),
                     ('volume', 'import', 'existing-volume', '-'), ('container', 'exists', 'existing-app'),
                     ('secret', 'inspect', 'existing-secret'), ('pull', fx.IMAGE), ('network', 'create', 'new-network')]:
            with self.subTest(verb=args[0]): self.assertRaises(ValueError, runner.validate, list(args))

    def test_owned_product_volume_import_inspect_and_permissions_are_allowed(self):
        scope = runtime_parts('Runner'); runner = scope['Runner'](); name = 'woowbk-offline-r4-device'
        for args in [('volume', 'import', name, '-'), ('volume', 'inspect', '--format', '{{.Mountpoint}}', name),
                     ('volume', 'exists', name), ('container', 'inspect', '--format', '{{.State.Running}}', name),
                     ('unshare', 'chown', '--no-dereference', '1000:1000', '--', '/home/x/volumes/' + name + '/_data'),
                     ('unshare', 'chmod', '0755', '--', '/home/x/volumes/' + name + '/_data')]:
            runner.validate(list(args))

    def test_native_run_has_no_pull_no_network_no_ports_and_no_image_volumes(self):
        scope = runtime_parts('Runner'); runner = scope['Runner']()
        scope['subprocess'].run.return_value = SimpleNamespace(returncode=0, stdout=b'ok', stderr=b'')
        args = ['run', '--name', 'woowbk-offline-r4-source', '--memory', '768m', '--network', 'none',
                '--pull=never', fx.IMAGE]
        runner.podman(*args)
        called = scope['subprocess'].run.call_args.args[0]
        self.assertIn('--image-volume=ignore', called); self.assertIn('--memory-swap=768m', called)
        self.assertRaises(ValueError, runner.validate, args[:-1] + ['--volume', '/etc:/fixture:ro', fx.IMAGE])
        self.assertRaises(ValueError, runner.validate, args[:-1] + ['--publish', '1883:1883', fx.IMAGE])
        self.assertRaises(ValueError, runner.validate, [x if x != '768m' else '2g' for x in args])

    def test_low_disk_refuses_writes_but_allows_owned_cleanup(self):
        scope = runtime_parts('Runner'); runner = scope['Runner']()
        scope['shutil'].disk_usage = lambda _: SimpleNamespace(free=12 * 1024**3)
        self.assertRaisesRegex(RuntimeError, 'disk_floor', runner.podman, 'start', 'woowbk-offline-r4-source')
        scope['subprocess'].run.assert_not_called()
        scope['subprocess'].run.return_value = SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
        runner.podman('rm', '--force', 'woowbk-offline-r4-source')

    def test_protocol_packets_contain_only_controlled_synthetic_input(self):
        scope = runtime_parts('mqtt_packet')
        anonymous = scope['mqtt_packet'](); named = scope['mqtt_packet']('r4_source', fx.DUMMY_PASSWORD)
        self.assertEqual(anonymous[9], 2); self.assertEqual(named[9], 194)
        self.assertEqual(named[1], len(named) - 2)
        self.assertIn(fx.DUMMY_PASSWORD.encode(), named)

    def test_all_prepared_python_is_parseable_without_executing_native(self):
        for path in HERE.glob('focus_emqx_r4*.py'): ast.parse(path.read_text())


class PackageBoundaryTests(unittest.TestCase):
    def test_package_plan_executes_nothing(self):
        with mock.patch('subprocess.run', side_effect=AssertionError('no package or native command')):
            module = load('focus_emqx_r4_package')
            with mock.patch('sys.stdout', new_callable=io.StringIO) as output: self.assertEqual(module.main([]), 0)
        self.assertFalse(json.loads(output.getvalue())['installer_or_upgrader'])

    def test_package_lease_never_selects_existing_dev_d_or_apps(self):
        module = load('focus_emqx_r4_package')
        now = datetime.datetime(2026, 11, 27, tzinfo=datetime.timezone.utc)
        lease = {'expires': '2026-11-27T00:20:00+00:00', 'case': 'EMQX-R4-package:noauth',
                 'source_commit': 'a' * 40, 'fixture_inputs': 'synthetic-owned-only', 'installer_or_upgrader': False,
                 'device': 'woowbk-r4-package-012345abcdef'}
        self.assertEqual(module.validate_lease(lease, 'noauth', 'a' * 40, now), lease['device'])
        for device in ('woowbk-dev-d', 'woow-emqx', 'woowbk-r4-package-../dev-d'):
            self.assertRaises(ValueError, module.validate_lease, dict(lease, device=device), 'noauth', 'a' * 40, now)

    def test_package_results_never_echo_values_or_arbitrary_diagnostics(self):
        module = load('focus_emqx_r4_package')
        raw = b'FAIL A4 dashboard dummy-value HTTP 401\nWARN A5/A6/A10 dummy-value\nprivate diagnostic dummy-value\n'
        self.assertEqual(module.smoke_status(raw), [{'status': 'FAIL', 'check': 'A4'},
                                                   {'status': 'WARN', 'check': 'A5/A6/A10'}])
        self.assertNotIn('dummy-value', json.dumps(module.smoke_status(raw)))

    def test_package_manifest_binds_the_exact_reviewed_source(self):
        manifest = json.loads((ROOT / 'snippets/focus-emqx-r4/package-source.json').read_text())
        self.assertEqual(manifest['head_commit'], 'ea5886c58ef2c6ab1f4e6a4d01908cc9dc4525de')
        self.assertTrue(manifest['working_tracked_files_match_head'])
        self.assertFalse(manifest['installer_upgrader_executed'])


if __name__ == '__main__': unittest.main()
