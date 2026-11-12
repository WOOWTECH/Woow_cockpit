import gzip
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('manage', Path(__file__).parents[1] / 'scripts/manage.py')
manage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manage)


class InstallationContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = base / 'host'
        self.source = base / 'source'
        for file, data in {
            'var/lib/dpkg/status': b'Package: cockpit-bridge\nStatus: install ok installed\nVersion: 362-1\n\n',
            'etc/cockpit/cockpit.conf': b'[WebService]\nAllowUnencrypted=false\n',
            'usr/share/cockpit/systemd/logs.html': b'<html><head></head><body>native log view</body></html>',
            'usr/share/cockpit/systemd/services.html.gz': gzip.compress(b'<html><head></head>services</html>', mtime=0),
            'usr/local/share/cockpit/woowtechpreview/screenshots/customer.png': b'customer capture, retain',
            'etc/cockpit/branding/branding.css': b'previous theme',
        }.items():
            target = self.root / file
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (self.root / 'etc/cockpit/branding/branding.css').chmod(0o640)
        for file, data in {'VERSION': b'test.1', 'branding/branding.css': b'new theme',
                           'branding/favicon.ico': b'icon', 'branding/assets/logo.svg': b'<svg/>',
                           'branding/fonts/font.ttf': b'font', 'preview/index.html': b'gallery',
                           'preview/manifest.json': b'{"tools":{"index":{"label":"Reference"}}}'}.items():
            path = self.source / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.source_patch = patch.object(manage, 'SOURCE', self.source)
        self.source_patch.start()
        self.addCleanup(self.source_patch.stop)
        self.original = self.snapshot()

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.read_bytes(), p.stat().st_mode & 0o777)
                for p in self.root.rglob('*') if p.is_file() and manage.BACKUPS not in str(p)}

    def install(self):
        desired, state = manage.desired_files(self.root)
        return manage.install(self.root, desired, state)

    def test_install_repeat_and_rollback_preserve_customer_files(self):
        result = self.install()
        self.assertEqual(manage.verify(self.root)['status'], 'verified')
        self.assertIn(manage.LINK.encode(), (self.root / 'usr/share/cockpit/systemd/logs.html').read_bytes())
        self.assertIn(manage.LINK.encode(), gzip.decompress((self.root / 'usr/share/cockpit/systemd/services.html.gz').read_bytes()))
        self.assertEqual(self.install()['changed'], 0)
        self.assertEqual((self.root / 'etc/cockpit/cockpit.conf').read_bytes(), self.original['etc/cockpit/cockpit.conf'][0])
        manage.rollback(self.root, result['backup_id'])
        self.assertEqual(self.snapshot(), self.original)

    def test_upstream_upgrade_is_rebased_and_old_rollback_refuses_it(self):
        original_install = self.install()
        target = self.root / 'usr/share/cockpit/systemd/logs.html'
        upgraded = b'<html><head><!-- newer upstream --></head>new native behavior</html>'
        target.write_bytes(upgraded)
        self.assertEqual(manage.verify(self.root)['status'], 'drift')
        with self.assertRaisesRegex(ValueError, 'Changed since installation'):
            manage.rollback(self.root, original_install['backup_id'])
        self.assertEqual(target.read_bytes(), upgraded)
        new_install = self.install()
        self.assertIn(b'new native behavior', target.read_bytes())
        manage.rollback(self.root, new_install['backup_id'])
        self.assertEqual(target.read_bytes(), upgraded)

    def test_bad_native_template_stops_before_any_mutation(self):
        (self.root / 'usr/share/cockpit/systemd/logs.html').write_bytes(b'not an HTML template')
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'Unknown native template'):
            self.install()
        self.assertEqual(before, self.snapshot())

    def test_symlink_cannot_redirect_root_writes(self):
        target = self.root / 'etc/cockpit/branding/branding.css'
        outside = Path(self.temp.name) / 'outside'
        outside.write_bytes(b'keep')
        target.unlink()
        target.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.install()
        self.assertEqual(outside.read_bytes(), b'keep')

    def test_partial_write_failure_restores_applied_changes(self):
        original_write = manage.atomic_write
        failed = False

        def fail_once(path, data, mode=0o644):
            nonlocal failed
            if str(path).endswith('etc/cockpit/branding/branding.css') and data == b'new theme' and not failed:
                failed = True
                raise OSError('simulated disk failure')
            original_write(path, data, mode)

        with patch.object(manage, 'atomic_write', fail_once):
            with self.assertRaisesRegex(OSError, 'simulated disk failure'):
                self.install()
        self.assertEqual(self.snapshot(), self.original)

    def test_corrupt_backup_is_rejected_before_restoring_any_file(self):
        result = self.install()
        saved = self.root / manage.BACKUPS / result['backup_id'] / 'files/etc/cockpit/branding/branding.css'
        saved.write_bytes(b'corrupt')
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'Corrupt backup'):
            manage.rollback(self.root, result['backup_id'])
        self.assertEqual(before, self.snapshot())

    def test_older_cockpit_is_rejected(self):
        (self.root / 'var/lib/dpkg/status').write_text('Package: cockpit-bridge\nStatus: install ok installed\nVersion: 314-1\n\n')
        with self.assertRaisesRegex(ValueError, 'requires Cockpit'):
            self.install()


if __name__ == '__main__':
    unittest.main()
