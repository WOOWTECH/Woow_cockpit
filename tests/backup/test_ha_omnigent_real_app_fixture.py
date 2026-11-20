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
