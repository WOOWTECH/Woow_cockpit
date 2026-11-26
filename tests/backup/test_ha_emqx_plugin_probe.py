"""Offline guard tests for the disposable E-44 driver; never import its device-side entry point or run a broker."""
import ast
import importlib.util
import io
import os
from pathlib import Path
from types import SimpleNamespace
import tarfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'snippets/focus-emqx-plugins'


def driver():
    spec = importlib.util.spec_from_file_location('e44_probe_driver', HERE / 'probe.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DisposableDriverTests(unittest.TestCase):
    def test_plan_and_payload_do_not_run_any_command_or_touch_installed_sources(self):
        with mock.patch('subprocess.run', side_effect=AssertionError('offline plan must not execute')):
            module = driver()
            payload = module.bundle()
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            members = archive.getmembers()
            self.assertTrue(all(m.isfile() and not m.name.startswith('/') and '..' not in m.name.split('/') for m in members))
            self.assertIn('runtime_probe.py', archive.getnames())
            self.assertIn('woow_e44_fixture.erl', archive.getnames())
            self.assertEqual(archive.extractfile('woowbackup/ha_emqx.py').read(),
                             (ROOT / 'backup-engine/woowbackup/ha_emqx.py').read_bytes())
        self.assertLessEqual(len(payload), 16 * 1024 * 1024)
        self.assertEqual(module.PLAN['image'], 'sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b')
        self.assertEqual(module.PLAN['lock'], '/tmp/woowbk-dev-d-mutation.lock')
        self.assertEqual(module.PLAN['published_ports'], 0)

    def test_every_fixture_run_disables_image_volumes_and_matches_swap_to_memory(self):
        # Compile only Runner: importing the child entry point would alter process resource/alarm state.
        source = ast.parse((HERE / 'runtime_probe.py').read_text())
        runner = next(node for node in source.body if isinstance(node, ast.ClassDef) and node.name == 'Runner')
        program = compile(ast.fix_missing_locations(ast.Module(body=[runner], type_ignores=[])), '<e44-runner>', 'exec')
        run = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout=b'ok', stderr=b''))
        scope = {'Path': Path, 'os': os, 'ROOT': HERE, 'LIMIT': 256 * 1024 * 1024,
                 'shutil': SimpleNamespace(disk_usage=lambda _: SimpleNamespace(free=20 * 1024**3)),
                 'subprocess': SimpleNamespace(run=run, PIPE=-1)}
        exec(program, scope)
        for memory in ('256m', '768m'):
            scope['Runner']().podman('run', '--memory', memory, '--pull=never', 'sha256:fixed')
            argv = run.call_args.args[0]
            self.assertEqual(argv[:3], ['podman', '--runtime=crun', 'run'])
            self.assertIn('--image-volume=ignore', argv)
            self.assertIn('--memory-swap=' + memory, argv)
            self.assertIn('--pull=never', argv)

    def test_resource_floor_stops_before_starting_a_container(self):
        source = ast.parse((HERE / 'runtime_probe.py').read_text())
        runner = next(node for node in source.body if isinstance(node, ast.ClassDef) and node.name == 'Runner')
        run = mock.Mock(side_effect=AssertionError('low disk must not execute'))
        scope = {'Path': Path, 'os': os, 'ROOT': HERE, 'LIMIT': 256 * 1024 * 1024,
                 'shutil': SimpleNamespace(disk_usage=lambda _: SimpleNamespace(free=12 * 1024**3)),
                 'subprocess': SimpleNamespace(run=run, PIPE=-1)}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[runner], type_ignores=[])), '<e44-runner>', 'exec'), scope)
        with self.assertRaisesRegex(RuntimeError, 'disk_floor'):
            scope['Runner']().podman('run', '--memory', '768m', 'sha256:fixed')
        run.assert_not_called()
        run.side_effect = None
        run.return_value = SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
        scope['Runner']().podman('rm', '--force', 'owned-job-container')
        self.assertEqual(run.call_args.args[0][-3:], ['rm', '--force', 'owned-job-container'])


if __name__ == '__main__':
    unittest.main()
