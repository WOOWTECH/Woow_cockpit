"""Brand plans/installations use an isolated root; no host services are called."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import brand_profile, manage

REPO = Path(__file__).resolve().parents[1]


class BrandInstallation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'host'
        for name, data in {
            'var/lib/dpkg/status': b'Package: cockpit-bridge\nStatus: install ok installed\nVersion: 362-1\n\n',
            'usr/share/cockpit/shell/index.html': b'<html><head></head><body>native shell</body></html>',
            'usr/share/cockpit/systemd/logs.html': b'<html><head></head><body>native logs</body></html>',
            'etc/cockpit/cockpit.conf': b'[WebService]\nAllowUnencrypted=false\n',
            'etc/woowtech-cockpit/services.json': b'{"owners":["existingowner"]}\n',
            'var/lib/woowtech-cockpit/app-links.json': b'{"fixture":"retain"}',
            'var/lib/woowtech-backup/archives/customer.tar': b'fixture-only archive',
            'etc/woowtech-cockpit/backup/keys/fixture-marker': b'not a key; preserve runtime',
        }.items():
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        self.original = self.snapshot()

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode))
                for p in self.root.rglob('*') if p.is_file() and not p.is_relative_to(self.root / manage.BACKUPS)}

    def plan(self, brand='woowtech'):
        return manage.desired_files(self.root, brand=brand)

    def install(self, brand='woowtech'):
        desired, state = self.plan(brand)
        return manage.install(self.root, desired, state)

    def test_profiles_and_runtime_contract(self):
        for brand in ('woowtech', 'apporo'):
            with self.subTest(brand=brand):
                profile = brand_profile.load_profile(brand)
                assets = brand_profile.asset_mapping(profile)
                self.assertEqual(set(assets), set(brand_profile.ASSET_TARGETS))
                self.assertTrue(all(p.is_absolute() and p.is_file() for p in assets.values()))
                public = json.loads(brand_profile.render_runtime_json(profile))
                self.assertEqual(public['schema'], 1)
                self.assertEqual(public['id'], brand)
                self.assertNotIn('provenance', public)
                self.assertNotIn(str(REPO), json.dumps(public))
                for mode in ('light', 'dark'):
                    self.assertTrue({'primary', 'hover', 'on_primary'} <= public['colors'][mode].keys())
        woow = brand_profile.load_profile('woowtech')
        self.assertEqual(woow['colors']['light'], {'primary': '#6183FC', 'hover': '#6183FC', 'on_primary': '#111A3A'})
        apporo = brand_profile.load_profile('apporo')
        self.assertEqual(apporo['display_name'], 'apporo 設備管理')
        self.assertEqual(apporo['colors']['light']['primary'], '#8B6B24')
        self.assertEqual(apporo['colors']['dark']['on_primary'], '#1C1C1E')
        self.assertEqual(apporo['assets']['logo_wordmark_light'], 'assets/company/apporo-mark-source.svg')

    def test_default_woow_is_visually_byte_identical_and_repeatable(self):
        desired, state = self.plan()
        for name in brand_profile.CSS_FILES | brand_profile.HTML_FILES | {'backup/backup.js', 'apps-catalog/apps.js'}:
            data = (REPO / name).read_bytes()
            self.assertEqual(brand_profile.render_file(name, data, brand_profile.load_profile('woowtech')), data)
        for name in ('branding.css', 'assets/logo-symbol.svg', 'assets/logo-lockup-white.svg'):
            self.assertEqual(desired[f'{manage.BRAND}/{name}'][0], (REPO / 'branding' / name).read_bytes())
        self.assertEqual(state['brand'], 'woowtech')
        self.assertEqual(self.snapshot(), self.original, 'plan must not mutate the target root')
        self.install()
        self.assertEqual(self.install()['changed'], 0)
        self.assertEqual(manage.verify(self.root)['status'], 'verified')
        self.assertEqual(stat.S_IMODE((self.root / manage.BRAND_CONFIG).stat().st_mode), 0o644)

    def test_brand_switch_rollback_and_device_data(self):
        first = self.install()
        previous = self.snapshot()
        second = self.install('apporo')
        self.assertEqual(json.loads((self.root / manage.BRAND_CONFIG).read_text())['id'], 'apporo')
        self.assertEqual(self.install('apporo')['changed'], 0)
        self.assertEqual(manage.verify(self.root)['status'], 'verified')
        for name, value in self.original.items():
            if name.startswith(('var/lib/woowtech-backup/', 'etc/woowtech-cockpit/', 'var/lib/woowtech-cockpit/app-links')) or name == 'etc/cockpit/cockpit.conf':
                self.assertEqual(self.snapshot()[name][0], value[0], name)
        manage.rollback(self.root, second['backup_id'])
        self.assertEqual(self.snapshot(), previous)
        manage.rollback(self.root, first['backup_id'])
        self.assertEqual(self.snapshot(), self.original)

    def test_apporo_assets_exact_and_source_unchanged(self):
        source_hash = {p: hashlib.sha256(p.read_bytes()).digest()
                       for base in ('branding', 'brands/apporo/assets') for p in (REPO / base).rglob('*') if p.is_file()}
        self.install('apporo')
        profile = brand_profile.load_profile('apporo')
        assets = brand_profile.asset_mapping(profile)
        for role, target in brand_profile.ASSET_TARGETS.items():
            self.assertEqual((self.root / manage.BRAND / target).read_bytes(), assets[role].read_bytes(), role)
        for shape in ('lockup', 'wordmark'):
            for suffix, role in (('', 'light'), ('-blue', 'light'), ('-white', 'dark'), ('-dark', 'dark')):
                name = f'assets/logo-{shape}{suffix}.svg'
                self.assertEqual((self.root / manage.BRAND / name).read_bytes(), assets[f'logo_{shape}_{role}'].read_bytes())
        for p, before in source_hash.items():
            self.assertEqual(hashlib.sha256(p.read_bytes()).digest(), before, str(p))

    def test_backend_protocol_and_application_labels_are_never_rendered(self):
        desired, _ = self.plan('apporo')
        for p in (REPO / 'backup-engine/woowbackup').rglob('*.py'):
            target = manage.BACKUP_ENGINE + '/' + p.relative_to(REPO / 'backup-engine/woowbackup').as_posix()
            self.assertEqual(desired[target][0], p.read_bytes(), target)
            self.assertEqual(brand_profile.render_file(p.relative_to(REPO).as_posix(), p.read_bytes(), brand_profile.load_profile('apporo')), p.read_bytes())
        self.assertEqual(desired[manage.BACKUP_HELPER][0], (REPO / 'backup-engine/woowtech-cockpit-backup').read_bytes())
        self.assertEqual(desired[manage.HELPER][0], (REPO / 'services/service-manager.py').read_bytes())
        self.assertEqual(desired[manage.APPS + '/apps.js'][0], (REPO / 'apps-catalog/apps.js').read_bytes())
        self.assertEqual(desired[manage.APPS + '/stacks.js'][0], (REPO / 'apps-catalog/stacks.js').read_bytes())
        rendered_ui = desired[manage.BACKUP_UI + '/backup.js'][0].decode()
        self.assertIn('/usr/local/libexec/woowtech-cockpit-backup', rendered_ui)
        self.assertIn('"woowtech-backup-key.txt"', rendered_ui)
        self.assertIn('APPORO UNION INC.', rendered_ui)

    def test_css_render_is_bounded_and_preserves_status_palette(self):
        profile = brand_profile.load_profile('apporo')
        for name in brand_profile.CSS_FILES:
            css = brand_profile.render_file(name, (REPO / name).read_bytes(), profile).decode()
            self.assertNotRegex(css.lower(), r'#(?:6183fc|4a6bd4|3455bf|8aa4ff)\b')
            self.assertIn('--brand-primary: #8B6B24', css)
            self.assertIn('--brand-primary: #C49E53', css)
            self.assertIn('system-ui, -apple-system', css)
            self.assertNotIn('@font-face', css)
            self.assertNotIn('color-mix(', css)
        backup = brand_profile.render_file('backup/backup.css', (REPO / 'backup/backup.css').read_bytes(), profile)
        self.assertIn(b'#c63b4b', backup)
        self.assertIn(b'#ff8a96', backup)
        branding = brand_profile.render_file('branding/branding.css', (REPO / 'branding/branding.css').read_bytes(), profile)
        self.assertIn(b'border-radius: 8px !important', branding)
        for name in ('native/podman/managed-owners.js', 'pi-web-integration/gateway.mjs', 'services/service-manager.py'):
            data = (REPO / name).read_bytes()
            self.assertEqual(brand_profile.render_file(name, data, profile), data)

    def source_fixture(self):
        source = Path(self.temp.name) / 'source'
        shutil.copytree(REPO / 'brands/apporo', source / 'brands/apporo')
        return source

    def test_missing_asset_rejected_before_host_mutation(self):
        source = self.source_fixture()
        (source / 'brands/apporo/assets/smart/pwa-icon-192.png').unlink()
        with patch.object(manage.brand_profile, 'SOURCE_ROOT', source):
            with self.assertRaisesRegex(ValueError, 'Missing official brand asset'):
                self.install('apporo')
        self.assertEqual(self.snapshot(), self.original)
        self.assertFalse((self.root / manage.BACKUPS).exists())

    def test_invalid_color_unknown_brand_duplicate_key_and_path_rejected(self):
        source = self.source_fixture()
        path = source / 'brands/apporo/brand.json'
        original = path.read_text()
        cases = []
        bad = json.loads(original); bad['colors']['dark']['primary'] = 'red; color: blue'; cases.append(bad)
        bad = json.loads(original); del bad['colors']['light']['on_primary']; cases.append(bad)
        bad = json.loads(original); bad['assets']['favicon'] = '../../outside.ico'; cases.append(bad)
        bad = json.loads(original); bad['id'] = 'woowtech'; cases.append(bad)
        bad = json.loads(original); bad['schema'] = True; cases.append(bad)
        for bad in cases:
            path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):
                brand_profile.load_profile('apporo', source_root=source)
        path.write_text(original.replace('"schema": 1', '"schema": 1, "schema": 1'))
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            brand_profile.load_profile('apporo', source_root=source)
        with self.assertRaisesRegex(ValueError, 'Unknown brand'):
            brand_profile.load_profile('../apporo')

    def test_symlink_asset_rejected(self):
        source = self.source_fixture()
        p = source / 'brands/apporo/assets/smart/pwa-icon-192.png'
        original = p.with_name('original.png')
        p.rename(original)
        p.symlink_to(original.name)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            brand_profile.load_profile('apporo', source_root=source)

    def test_runtime_drift_permissions_and_newer_work_protected(self):
        result = self.install('apporo')
        target = self.root / manage.BRAND_CONFIG
        target.chmod(0o666)
        self.assertIn(manage.BRAND_CONFIG, manage.verify(self.root)['drift'])
        self.install('apporo')
        target.write_text('{"newer":"operator work"}')
        self.assertIn(manage.BRAND_CONFIG, manage.verify(self.root)['drift'])
        with self.assertRaisesRegex(ValueError, 'Changed since installation'):
            manage.rollback(self.root, result['backup_id'])

    def test_cli_brand_option_and_read_only_plan(self):
        command = [sys.executable, '-B', str(REPO / 'scripts/manage.py'), '--root', str(self.root), 'plan', '--brand', 'apporo']
        result = subprocess.run(command, cwd=REPO, capture_output=True, text=True, check=True)
        plan = json.loads(result.stdout)
        self.assertEqual(plan['brand'], 'apporo')
        self.assertIn(manage.BRAND_CONFIG, plan['changed'])
        self.assertEqual(self.snapshot(), self.original)
        result = subprocess.run(command[:-1] + ['unknown'], cwd=REPO, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), self.original)

    def test_cli_omitted_brand_keeps_installed_apporo(self):
        command = [sys.executable, '-B', str(REPO / 'scripts/manage.py'), '--root', str(self.root)]
        fresh = subprocess.run(command + ['plan'], cwd=REPO, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(fresh.stdout)['brand'], 'woowtech')
        self.install('apporo')
        before = self.snapshot()
        plan = subprocess.run(command + ['plan'], cwd=REPO, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(plan.stdout)['brand'], 'apporo')
        self.assertEqual(json.loads(plan.stdout)['changed'], [])
        install = subprocess.run(command + ['install'], cwd=REPO, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(install.stdout)['brand'], 'apporo')
        self.assertEqual(json.loads(install.stdout)['changed'], 0)
        self.assertEqual(self.snapshot(), before)

    def test_cli_invalid_installed_identity_fails_without_writes(self):
        self.install('apporo')
        command = [sys.executable, '-B', str(REPO / 'scripts/manage.py'), '--root', str(self.root), 'install']
        for data in ('not JSON', '{"schema":1,"id":"unknown"}', '{"schema":true,"id":"apporo"}'):
            (self.root / manage.BRAND_CONFIG).write_text(data)
            before = self.snapshot()
            result = subprocess.run(command, cwd=REPO, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('brand.json', result.stderr)
            self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
