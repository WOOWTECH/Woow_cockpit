"""Runtime-brand validation and installer rejection before deployment commands."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import runtime_brand

ROOT = Path(__file__).resolve().parents[1]


def profile(brand='apporo'):
    return {
        'schema': 1, 'id': brand,
        'colors': {
            'light': {'primary': '#8B6B24', 'hover': '#8B6B24', 'on_primary': '#FFFFFF'},
            'dark': {'primary': '#C49E53', 'hover': '#C49E53', 'on_primary': '#1C1C1E'},
        },
    }


def invalid_documents():
    yield 'malformed JSON', '{'
    for value in (None, {}, [], False, 0, 'apporo'):
        yield f'root {value!r}', json.dumps(value)
    for key, values in (('schema', (None, True, 1.0, '1', 2)),
                        ('id', (None, [], 'unknown')),
                        ('colors', (None, [], 'gold'))):
        for value in values:
            data = profile()
            data[key] = value
            yield f'{key} {value!r}', json.dumps(data)
    for mode in ('light', 'dark'):
        for value in (None, [], '#8B6B24'):
            data = profile()
            data['colors'][mode] = value
            yield f'{mode} palette {value!r}', json.dumps(data)
        for key in ('primary', 'hover', 'on_primary'):
            data = profile()
            del data['colors'][mode][key]
            yield f'missing {mode}.{key}', json.dumps(data)
        for value in (None, 123456, ['#8B6B24'], '#fff', '#GGGGGG', '#8B6B24\n'):
            data = profile()
            data['colors'][mode]['primary'] = value
            yield f'{mode} primary {value!r}', json.dumps(data)
    data = profile()
    data['extra'] = float('nan')
    yield 'non-JSON constant', json.dumps(data)


class RuntimeBrandTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / 'brand.json'

    def test_valid_profiles_preserve_brand_and_allow_additive_metadata(self):
        for brand in ('woowtech', 'apporo'):
            data = profile(brand)
            data.update(display_name='設備管理', assets={'icon': 'assets/icon.png'})
            data['colors']['dark']['primary'] = '#c49e53'
            data['colors']['light']['page'] = '#FFFFFF'
            self.path.write_text(json.dumps(data))
            self.assertEqual(runtime_brand.selected_brand(path=self.path), brand)
            self.assertEqual(runtime_brand.selected_brand(brand, path=self.path), brand)

    def test_missing_profile_defaults_to_woowtech(self):
        self.assertEqual(runtime_brand.selected_brand(path=self.path), 'woowtech')
        self.assertEqual(runtime_brand.selected_brand('woowtech', path=self.path), 'woowtech')
        with self.assertRaises(ValueError):
            runtime_brand.selected_brand('apporo', path=self.path)
        self.assertFalse(self.path.exists())

    def test_explicit_mismatch_cannot_switch_brand(self):
        self.path.write_text(json.dumps(profile()))
        for requested in ('woowtech', 'unknown'):
            with self.assertRaisesRegex(ValueError, 'matching Cockpit brand'):
                runtime_brand.selected_brand(requested, path=self.path)

    def test_invalid_documents_are_rejected_even_with_explicit_brand(self):
        for name, data in invalid_documents():
            with self.subTest(case=name):
                self.path.write_text(data)
                with self.assertRaises(ValueError):
                    runtime_brand.selected_brand(path=self.path)
                with self.assertRaises(ValueError):
                    runtime_brand.selected_brand('apporo', path=self.path)
                self.assertEqual(self.path.read_text(), data)

    def test_gateway_size_limit_applies_before_installation(self):
        data = profile()
        data['extra'] = '\U0001f600' * 8192
        self.path.write_text(json.dumps(data, ensure_ascii=False))
        with self.assertRaisesRegex(ValueError, 'too large'):
            runtime_brand.selected_brand(path=self.path)

    def test_read_errors_are_not_treated_as_missing_configuration(self):
        with patch.object(Path, 'read_text', side_effect=PermissionError('fixture unreadable')):
            with self.assertRaises(PermissionError):
                runtime_brand.selected_brand(path=self.path)
        self.path.mkdir()
        with self.assertRaises(IsADirectoryError):
            runtime_brand.selected_brand(path=self.path)

    def test_cli_prints_selected_brand_and_reports_validation_errors(self):
        command = [sys.executable, '-B', str(ROOT / 'scripts/runtime_brand.py'), '--profile', str(self.path)]
        self.path.write_text(json.dumps(profile()))
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, 'apporo\n')
        self.assertEqual(result.stderr, '')
        self.path.write_text('null')
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertIn('Brand validation failed:', result.stderr)
        self.assertNotIn('Traceback', result.stderr)


class InstallerBrandPreflightTests(unittest.TestCase):
    """Run real shell entry points; all deployment commands are guarded stubs."""
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.fixture = Path(temp.name)
        self.path = self.fixture / 'brand.json'
        self.log = self.fixture / 'commands.log'
        self.bin = self.fixture / 'bin'
        self.bin.mkdir()
        # Redirect only the helper's input file. The real helper and installer
        # sources execute unchanged, without reading the live runtime profile.
        self.executable('python3', f'''#!{sys.executable}
import os, sys
from pathlib import Path
if len(sys.argv) > 1 and Path(sys.argv[1]).name == 'runtime_brand.py':
    os.execv({sys.executable!r}, [{sys.executable!r}, '-B', *sys.argv[1:], '--profile', {str(self.path)!r}])
with open({str(self.log)!r}, 'a') as log:
    log.write('unexpected-python-command\\n')
sys.exit(97)
''')
        self.executable('id', '#!/bin/sh\nprintf "0\\n"\n')
        for command in ('mktemp', 'install', 'systemctl', 'systemd-analyze', 'ip', 'ss', 'node', 'sed', 'chmod'):
            self.executable(command, f'''#!{sys.executable}
import sys
with open({str(self.log)!r}, 'a') as log:
    log.write({command!r} + '\\n')
sys.exit(97)
''')
        self.env = {**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                    'PYTHONDONTWRITEBYTECODE': '1'}
        self.env.pop('BRAND', None)

    def executable(self, name, text):
        target = self.bin / name
        target.write_text(text)
        target.chmod(0o755)

    def run_installer(self, installer, requested=None):
        env = dict(self.env)
        if requested is not None:
            env['BRAND'] = requested
        return subprocess.run(['/bin/bash', str(ROOT / installer / 'install.sh'), '127.0.0.1'],
                              cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)

    def assert_rejected_without_commands(self, installer, requested=None):
        before = self.path.read_bytes()
        result = self.run_installer(installer, requested)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('Brand validation failed:', result.stderr)
        self.assertFalse(self.log.exists(), 'installer reached a deployment command')
        self.assertEqual(self.path.read_bytes(), before)

    def test_invalid_profiles_fail_before_writes_or_service_commands(self):
        for installer in ('pi-web-integration', 'pwa-gateway'):
            for name, data in invalid_documents():
                with self.subTest(installer=installer, case=name):
                    self.path.write_text(data)
                    self.assert_rejected_without_commands(installer)

    def test_mismatched_brand_fails_before_writes_or_service_commands(self):
        self.path.write_text(json.dumps(profile()))
        for installer in ('pi-web-integration', 'pwa-gateway'):
            with self.subTest(installer=installer):
                self.assert_rejected_without_commands(installer, 'woowtech')

    def test_valid_and_absent_profiles_reach_the_guard_after_preflight(self):
        # Prove the harness distinguishes a successful preflight. Stop at the
        # first subsequent command, so no network/service/deployment occurs.
        for installer, first in (('pi-web-integration', 'ip'), ('pwa-gateway', 'mktemp')):
            for brand in ('apporo', 'woowtech', None):
                with self.subTest(installer=installer, brand=brand):
                    if brand is None:
                        self.path.unlink(missing_ok=True)
                    else:
                        self.path.write_text(json.dumps(profile(brand)))
                    result = self.run_installer(installer)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn('Brand validation failed:', result.stderr)
                    self.assertEqual(self.log.read_text(), first + '\n')
                    self.log.unlink()


if __name__ == '__main__':
    unittest.main()
