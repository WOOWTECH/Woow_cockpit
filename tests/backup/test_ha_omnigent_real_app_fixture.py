"""Exercise the application cold fixture without starting containers."""
import importlib.util
import io
from pathlib import Path
import tarfile
import sys
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / 'e2e/lab/omnigent_real_app_chain.py'
sys.path.insert(0, str(PATH.parent))
spec = importlib.util.spec_from_file_location('omnigent_real_app_chain', PATH)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class RealAppFixtureTests(unittest.TestCase):
    def test_addon_maps_real_app_artifact_tree_and_requires_cookie(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cold, app, addon = root / 'cold.tar', root / 'app.tar', root / 'addon.tar'
            with tarfile.open(cold, 'w') as tar:
                probe.add(tar, '.', kind='dir')
                probe.add(tar, 'PG_VERSION', b'16')
            with tarfile.open(app, 'w') as tar:
                probe.add(tar, '.', kind='dir')
                probe.add(tar, 'artifacts', kind='dir')
                probe.add(tar, 'artifacts/accounts-cookie-secret', b'synthetic-cookie', mode=0o600)
            probe.build_addon(cold, addon, app)
            with tarfile.open(addon) as tar:
                self.assertEqual(tar.extractfile('data/postgres/PG_VERSION').read(), b'16')
                self.assertEqual(tar.extractfile('data/omnigent-home/.omnigent/artifacts/accounts-cookie-secret').read(),
                                 b'synthetic-cookie')
            with tarfile.open(app, 'w') as tar:
                probe.add(tar, '.', kind='dir')
            with self.assertRaisesRegex(RuntimeError, 'synthetic_cookie_missing'):
                probe.build_addon(cold, addon, app)


class BoundedRunnerTests(unittest.TestCase):
    def test_budget_abort_timeout_and_stderr_suppression(self):
        from unittest import mock
        from types import SimpleNamespace
        import omnigent_lab_runner as lab
        runner = lab.Runner()
        abort = lambda: None
        result = SimpleNamespace(stdout=b'ok', returncode=0, stderr=b'sensitive')
        with mock.patch.object(lab, 'default_runner', return_value=result) as run:
            self.assertEqual(runner.podman('ps', timeout=7, max_output=50, abort=abort).stdout, b'ok')
            self.assertEqual(run.call_args.kwargs['max_output'], 50)
            self.assertEqual(run.call_args.kwargs['timeout'], 7)
            self.assertIs(run.call_args.kwargs['abort'], abort)
            self.assertFalse(hasattr(runner.podman('ps'), 'stderr'))
        with mock.patch.object(lab, 'default_runner', return_value=SimpleNamespace(returncode=1, stderr=b'secret')):
            with self.assertRaises(lab.CommandError) as caught:
                runner.podman('ps')
            self.assertNotIn('secret', str(caught.exception))


class ResourcePreflightTests(unittest.TestCase):
    def test_only_proven_absent_names_allow_creation(self):
        from types import SimpleNamespace
        class Runner:
            def __init__(self, status):
                self.status = status
                self.calls = []
            def podman(self, *args, **kwargs):
                self.calls.append(args)
                return SimpleNamespace(returncode=self.status)
        for status in (0, 125):
            runner = Runner(status)
            with self.assertRaisesRegex(RuntimeError, 'not_proven_absent'):
                probe.require_names_absent(runner, [('secret', ['collision'])])
            self.assertEqual(runner.calls, [('secret', 'exists', 'collision')])
        runner = Runner(1)
        probe.require_names_absent(runner, [('container', ['c']), ('volume', ['v']), ('secret', ['s'])])
        self.assertEqual(len(runner.calls), 3)

    def test_supervisor_outer_and_real_prepare_with_synthetic_quadlets(self):
        from types import SimpleNamespace
        from unittest import mock
        from woowbackup import habackup, ha_omnigent as omni
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cold, app_data, addon, outer = (root / n for n in ('cold.tar', 'app.tar', 'addon.tar', 'outer.tar'))
            with tarfile.open(cold, 'w') as tar:
                probe.add(tar, '.', kind='dir')
                probe.add(tar, 'PG_VERSION', b'16')
            with tarfile.open(app_data, 'w') as tar:
                probe.add(tar, '.', kind='dir')
                probe.add(tar, 'artifacts', kind='dir')
                probe.add(tar, 'artifacts/accounts-cookie-secret', b'synthetic-cookie', mode=0o600)
            probe.build_addon(cold, addon, app_data)
            probe.build_supervisor(addon, outer)
            with habackup.open_backup(outer) as ha:
                member = ha.layout.addon(probe.ADDON_SLUG)
                def info(slug):
                    self.assertEqual(slug, omni.SLUG)
                    with ha.open_member(member.name) as stream:
                        return habackup.read_addon_info(stream)
                work = SimpleNamespace(quadlets=lambda app: probe.fixture_quadlets('synthetic-db', 'pg', 'server', 'pi'),
                    runner=lambda app: SimpleNamespace(home='/home/appowner'), addon_info=info)
                app = SimpleNamespace(id='omnigent', postgres=[], data_dirs=[],
                    volumes=[{'name': n} for n in ('pg', 'server', 'pi')],
                    health=[{'url':'http://127.0.0.1:8000/health'}])
                with mock.patch('woowbackup.adapters.quadlet_postgres.loopback_get',
                                return_value=(200, b'{"server_version":"0.21.0"}')), \
                     mock.patch.object(omni, 'live_alembic', return_value=['revision']):
                    target, version, alembic, addon_info, blocker = omni._prepare(work, app)
                self.assertEqual((target.db_container, target.db_volume, target.server_volume, target.pi_volume),
                                 ('synthetic-db', 'pg', 'server', 'pi'))
                self.assertEqual((target.own_users, version, alembic, addon_info.version, blocker),
                                 (['target-admin'], '0.21.0', ['revision'], '0.1.23', None))
                with ha.open_member(member.name) as stream:
                    source = omni.scan_member(stream, habackup.Report())
                self.assertEqual(source.pg_version, '16')
                self.assertTrue(source.cookie)


class CredentialCoverageTests(unittest.TestCase):
    def setUp(self):
        probe.SECRET_VALUES.clear()
        probe.EVENT_RECORDS.clear()
        self.addCleanup(probe.SECRET_VALUES.clear)
        self.addCleanup(probe.EVENT_RECORDS.clear)

    def test_acknowledged_transport_registers_before_child_continues(self):
        import sys
        child = r'''import json,sys
sys.stdin.readline()
print(json.dumps({'type':'auth','sequence':0,'source':'/auth/login','status':200,
                  'credentials':{'token':'synthetic-token','refresh_token':'synthetic-refresh'}}),flush=True)
if sys.stdin.readline() != 'OK\n': raise SystemExit(1)
print(json.dumps({'type':'summary','sequence':1,'data':{'complete':True}}),flush=True)
if sys.stdin.readline() != 'OK\n': raise SystemExit(1)
print(json.dumps({'type':'end','sequence':2}),flush=True)
if sys.stdin.readline() != 'OK\n': raise SystemExit(1)
'''
        result = probe.run_events([sys.executable, '-I', '-c', child], {}, probe.register_private,
                                  [('/auth/login', ('token','refresh_token'), True)], timeout=5)
        self.assertEqual(result, {'complete':True})
        self.assertEqual(probe.SECRET_VALUES, [b'synthetic-token', b'synthetic-refresh'])

    def test_missing_refresh_fails_after_observed_token_registered(self):
        import sys
        from b1_event_transport import Incomplete
        child = r'''import json,sys
sys.stdin.readline()
print(json.dumps({'type':'auth','sequence':0,'source':'/auth/login','status':200,
                  'credentials':{'token':'synthetic-token'}}),flush=True)
sys.stdin.readline()
'''
        with self.assertRaises(Incomplete):
            probe.run_events([sys.executable, '-I', '-c', child], {}, probe.register_private,
                             [('/auth/login', ('token','refresh_token'), True)], timeout=5)
        self.assertIn(b'synthetic-token', probe.SECRET_VALUES)

    def test_login_requires_exact_two_registered_fields(self):
        from unittest import mock
        def consume(argv, request, register, expected, timeout):
            self.assertEqual(expected, [('/auth/login', ('token','refresh_token'), True)])
            register('synthetic-token')
            register('synthetic-refresh')
            return {'complete':True}
        observed = []
        with mock.patch.object(probe, 'run_events', side_effect=consume):
            result = probe.login_registered('synthetic-container', 'synthetic-user', 'synthetic-password',
                                            'source_login', observed)
        self.assertEqual(result, 'synthetic-token')
        self.assertEqual(observed, ['source_login.token', 'source_login.refresh_token'])

    def test_private_cookie_registered_and_boundary_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tar_path = root / 'private.tar'
            cookie = b'0123456789abcdef' * 4
            with tarfile.open(tar_path, 'w') as tar:
                probe.add(tar, 'artifacts', kind='dir')
                probe.add(tar, 'artifacts/accounts-cookie-secret', cookie, mode=0o600)
            self.assertEqual(probe.cookie_from_tar(tar_path), cookie)
            self.assertIn(cookie, probe.SECRET_VALUES)
            self.assertTrue(probe.file_contains(tar_path, cookie))
            boundary = root / 'boundary'
            boundary.write_bytes(b'x' * (1024 * 1024 - 3) + cookie)
            self.assertTrue(probe.file_contains(boundary, cookie))
            self.assertGreater(probe.private_scan([boundary], {cookie})['matches'], 0)

    def test_event_suppresses_registered_credential(self):
        probe.register_private('synthetic-secret')
        with self.assertRaisesRegex(RuntimeError, 'sensitive_evidence_suppressed'):
            probe.event('synthetic-secret')

    def test_wrong_event_source_is_rejected_after_registration(self):
        import sys
        from b1_event_transport import Incomplete
        child = r'''import json,sys
sys.stdin.readline()
print(json.dumps({'type':'auth','sequence':0,'source':'/unexpected','status':200,
                  'credentials':{'token':'synthetic-token','refresh_token':'synthetic-refresh'}}),flush=True)
sys.stdin.readline()
'''
        with self.assertRaises(Incomplete):
            probe.run_events([sys.executable, '-I', '-c', child], {}, probe.register_private,
                             [('/auth/login', ('token','refresh_token'), True)], timeout=5)
        self.assertIn(b'synthetic-token', probe.SECRET_VALUES)
        self.assertIn(b'synthetic-refresh', probe.SECRET_VALUES)

    def test_container_cookie_is_registered_and_invalid_cookie_rejected(self):
        from types import SimpleNamespace
        class Runner:
            def __init__(self, value): self.value = value
            def podman(self, *args, **kwargs): return SimpleNamespace(stdout=self.value)
        cookie = b'0123456789abcdef' * 4
        self.assertEqual(probe.cookie_from_container(Runner(cookie), 'synthetic'), cookie)
        self.assertIn(cookie, probe.SECRET_VALUES)
        with self.assertRaisesRegex(RuntimeError, 'synthetic_cookie_invalid'):
            probe.cookie_from_container(Runner(b'bad'), 'synthetic')

    def test_duplicate_event_fields_are_rejected(self):
        import sys
        from b1_event_transport import Incomplete
        child = r'''import sys
sys.stdin.readline()
print('{"type":"auth","type":"auth","sequence":0,"source":"/auth/login","status":200,"credentials":{"token":"synthetic-token","refresh_token":"synthetic-refresh"}}',flush=True)
sys.stdin.readline()
'''
        with self.assertRaises(Incomplete):
            probe.run_events([sys.executable, '-I', '-c', child], {}, probe.register_private,
                             [('/auth/login', ('token','refresh_token'), True)], timeout=5)
