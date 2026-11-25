import contextlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('manage', REPO / 'scripts/manage.py')
manage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manage)

QUADLETS = ('woowbk-demo.network', 'woowbk-demo-db.container', 'woowbk-demo-app.container')
DEMO_ENTRY = {
    'schema': 1, 'id': 'woowbk-demo', 'name': '示範筆記應用', 'owner': 'appowner', 'adapter': 'quadlet-postgres',
    'quadlet': {'files': list(QUADLETS),
                'template_dir': '/usr/local/share/woowtech-cockpit-backup/catalog/woowbk-demo/quadlet'},
    'units': ['woowbk-demo-db.service', 'woowbk-demo-app.service'],
}
UI_SOURCE = {
    'backup/manifest.json': '{"version": 1, "requires": {"cockpit": "362"}, "menu": {"index": {"label": "備份與還原"}}}',
    'backup/index.html': '<!doctype html><title>備份與還原</title>',
    'backup/backup.css': '.page { color: #6183fc; }',
    'backup/backup.js': '"use strict";',
}
ENGINE_SOURCE = {
    'backup-engine/woowtech-cockpit-backup': '#!/usr/bin/python3 -I\n"""Root helper (test payload)."""\n',
    'backup-engine/woowbackup/__init__.py': '"""engine"""\n',
    'backup-engine/woowbackup/cli.py': 'def main(argv):\n    return 0\n',
    'backup-engine/woowbackup/archive.py': 'FORMAT = 1\n',
    'backup-engine/woowbackup/adapters/__init__.py': '',
    'backup-engine/woowbackup/adapters/quadlet_postgres.py': 'ADAPTER_VERSION = 1\n',
    # The scheduled-backup units ship with the engine (排程備份).
    'backup-engine/systemd/woowtech-cockpit-backup-schedule.service': '[Unit]\nDescription=tick (test payload)\n',
    'backup-engine/systemd/woowtech-cockpit-backup-schedule.timer': '[Unit]\nDescription=timer (test payload)\n',
    # Bytecode caches in a checkout must never be deployed.
    'backup-engine/woowbackup/__pycache__/cli.cpython-312.pyc': 'stale bytecode',
    'backup-engine/woowbackup/adapters/__pycache__/base.cpython-312.pyc': 'stale bytecode',
}
DEMO_SOURCE = {
    'catalog-examples/woowbk-demo/catalog.json': json.dumps(DEMO_ENTRY, ensure_ascii=False, indent=2),
    **{f'catalog-examples/woowbk-demo/quadlet/{name}': f'# {name}\n[Unit]\n' for name in QUADLETS},
    # Lab tooling next to the fixture: not templates, never installed.
    'catalog-examples/woowbk-demo/README.md': '# fixture\n',
    'catalog-examples/woowbk-demo/app/app.py': 'print("demo")\n',
    'catalog-examples/woowbk-demo/app/Containerfile': 'FROM python:3.12-alpine\n',
    'catalog-examples/woowbk-demo/app/__pycache__/app.cpython-312.pyc': 'cache',
    'catalog-examples/woowbk-demo/tools/seed.py': 'print("seed")\n',
}
# Directory trees the backup package creates or lives in, plus the engine's runtime trees.
BACKUP_TREES = ('usr/local/lib', 'usr/local/libexec', manage.BACKUP_UI, manage.BACKUP_SHARE,
                'etc/woowtech-cockpit', 'var/lib/woowtech-backup', 'run')
RUNTIME_TREES = ('var/lib/woowtech-backup', 'etc/woowtech-cockpit/backup/keys', 'run/woowtech-backup')


def mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


@contextlib.contextmanager
def umask(value):
    previous = os.umask(value)
    try:
        yield
    finally:
        os.umask(previous)


class RootOwnedView:
    """`os` stand-in for the entrypoint: the test user's files look root-owned, as in a rootless container."""

    def __getattr__(self, name):
        return getattr(os, name)

    @staticmethod
    def lstat(path):
        st = os.lstat(path)
        uid = 0 if st.st_uid == os.getuid() else st.st_uid
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, uid, st.st_gid, st.st_size,
                               int(st.st_atime), int(st.st_mtime), int(st.st_ctime)))


def load_entrypoint():
    """The real helper entrypoint as a module (its __main__ block does not run), or None."""
    path = REPO / 'backup-engine/woowtech-cockpit-backup'
    if not path.is_file():
        return None
    module = types.ModuleType('woowbk_entrypoint')
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), 'exec'), module.__dict__)  # noqa: S102 - repository source
    if not callable(getattr(module, 'library_trusted', None)) or not isinstance(getattr(module, 'LIB', None), str):
        return None
    module.os = RootOwnedView()
    return module


class HostFixture(unittest.TestCase):
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
            'usr/share/cockpit/shell/index.html': b'<html><head></head><body>native shell</body></html>',
            'usr/share/cockpit/systemd/services.html.gz': gzip.compress(b'<html><head></head>services</html>', mtime=0),
            'usr/local/share/cockpit/woowtechpreview/screenshots/customer.png': b'customer capture, retain',
            'etc/cockpit/branding/branding.css': b'previous theme',
        }.items():
            target = self.root / file
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (self.root / 'etc/cockpit/branding/branding.css').chmod(0o640)
        for file, data in {'VERSION': b'test.1', 'branding/branding.css': b'new theme',
                           'branding/mobile-navigation.js': b'local navigation script',
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

    def install(self, **options):
        desired, state = manage.desired_files(self.root, **options)
        return manage.install(self.root, desired, state)


class InstallationContract(HostFixture):
    def test_install_repeat_and_rollback_preserve_customer_files(self):
        result = self.install()
        self.assertEqual(manage.verify(self.root)['status'], 'verified')
        self.assertIn(manage.LINK.encode(), (self.root / 'usr/share/cockpit/systemd/logs.html').read_bytes())
        self.assertIn(manage.SHELL_SCRIPT.encode(), (self.root / 'usr/share/cockpit/shell/index.html').read_bytes())
        self.assertIn(manage.LINK.encode(), gzip.decompress((self.root / 'usr/share/cockpit/systemd/services.html.gz').read_bytes()))
        self.assertEqual(self.install()['changed'], 0)
        self.assertEqual((self.root / 'etc/cockpit/cockpit.conf').read_bytes(), self.original['etc/cockpit/cockpit.conf'][0])
        manage.rollback(self.root, result['backup_id'])
        self.assertEqual(self.snapshot(), self.original)

    def test_app_catalog_is_installed_verified_and_rolled_back(self):
        catalog = self.source / 'apps-catalog'
        catalog.mkdir()
        (catalog / 'manifest.json').write_text('{"tools":{"index":{"label":"應用軟體"}}}')
        (catalog / 'index.html').write_text('application catalogue')
        services = self.source / 'services'
        services.mkdir()
        for name in ('manifest.json', 'index.html', 'service.css', 'service.js', 'service-manager.py'):
            (services / name).write_text('fixture')
        result = self.install()
        target = self.root / manage.APPS / 'index.html'
        self.assertEqual(target.read_text(), 'application catalogue')
        self.assertEqual(manage.verify(self.root)['status'], 'verified')
        self.assertEqual(self.install()['changed'], 0)
        manage.rollback(self.root, result['backup_id'])
        self.assertFalse(target.exists())

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

    def test_held_cockpit_can_install_and_verify(self):
        status = self.root / 'var/lib/dpkg/status'
        status.write_text(status.read_text().replace('Status: install ok installed', 'Status: hold ok installed'))
        self.install()
        self.assertEqual(manage.verify(self.root)['status'], 'verified')

    def test_held_older_cockpit_still_fails_version_gate(self):
        (self.root / 'var/lib/dpkg/status').write_text('Package: cockpit-bridge\nStatus: hold ok installed\nVersion: 314-1\n\n')
        with self.assertRaisesRegex(ValueError, 'requires Cockpit'):
            self.install()

    def test_held_unconfigured_cockpit_is_not_accepted(self):
        (self.root / 'var/lib/dpkg/status').write_text('Package: cockpit-bridge\nStatus: hold ok unpacked\nVersion: 362-1\n\n')
        with self.assertRaisesRegex(ValueError, 'not installed'):
            self.install()

    def test_services_install_has_executable_helper_private_config_and_exact_rollback(self):
        source = self.source / 'services'
        source.mkdir()
        for name in ('service-manager.py', 'manifest.json', 'index.html', 'service.css', 'service.js'):
            (source / name).write_text('test payload')
        desired, state = manage.desired_files(self.root, service_owners=['operator'])
        result = manage.install(self.root, desired, state)
        helper = self.root / manage.HELPER
        config = self.root / manage.SERVICE_CONFIG
        self.assertEqual(helper.stat().st_mode & 0o777, 0o755)
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(config.read_text()), {'owners': ['operator']})
        self.assertNotIn('service-manager.py', [p.name for p in (self.root / manage.SERVICES).iterdir()])
        desired, state = manage.desired_files(self.root)
        self.assertEqual(manage.install(self.root, desired, state)['changed'], 0)
        self.assertEqual(manage.verify(self.root)['status'], 'verified')
        manage.rollback(self.root, result['backup_id'])
        self.assertEqual(self.snapshot(), self.original)

    def test_services_configuration_and_helper_permission_drift_is_repaired(self):
        source = self.source / 'services'
        source.mkdir()
        for name in ('service-manager.py', 'manifest.json', 'index.html', 'service.css', 'service.js'):
            (source / name).write_text('test payload')
        desired, state = manage.desired_files(self.root, service_owners=['operator'])
        manage.install(self.root, desired, state)
        helper = self.root / manage.HELPER
        config = self.root / manage.SERVICE_CONFIG
        helper.chmod(0o666)
        config.chmod(0o644)
        self.assertEqual(set(manage.verify(self.root)['drift']), {manage.HELPER, manage.SERVICE_CONFIG})
        desired, state = manage.desired_files(self.root)
        manage.install(self.root, desired, state)
        self.assertEqual(manage.verify(self.root)['status'], 'verified')
        self.assertEqual(json.loads(config.read_text())['owners'], ['operator'])

    def test_service_owner_input_cannot_be_a_path_or_option(self):
        source = self.source / 'services'
        source.mkdir()
        for name in ('service-manager.py', 'manifest.json', 'index.html', 'service.css', 'service.js'):
            (source / name).write_text('test payload')
        for owner in ('root', '../operator', '--help', 'a;id'):
            with self.assertRaisesRegex(ValueError, 'Invalid service owner'):
                manage.desired_files(self.root, service_owners=[owner])
        self.assertEqual(self.snapshot(), self.original)

    def test_native_podman_bundle_is_version_gated_and_rollback_restores_distribution(self):
        native = self.source / 'native/podman/dist'
        (native / 'licenses').mkdir(parents=True)
        (native / 'index.js.gz').write_bytes(gzip.compress(b'integrated JavaScript'))
        (native / 'index.js.LEGAL.txt').write_text('license notice')
        (native / 'licenses/NOTICE').write_text('runtime attribution')
        target = self.root / manage.PODMAN / 'index.js.gz'
        target.parent.mkdir(parents=True)
        original = gzip.compress(b'distribution JavaScript')
        target.write_bytes(original)
        status = self.root / 'var/lib/dpkg/status'
        cockpit = status.read_text()
        for version in ('125-1', '124-1~bpo24.04.1'):
            status.write_text(cockpit + f'Package: cockpit-podman\nStatus: install ok installed\nVersion: {version}\n\n')
            before = self.snapshot()
            desired, state = manage.desired_files(self.root)
            result = manage.install(self.root, desired, state)
            expected = b'integrated JavaScript' if version.startswith('124-') else b'distribution JavaScript'
            self.assertEqual(gzip.decompress(target.read_bytes()), expected)
            manage.rollback(self.root, result['backup_id'])
            self.assertEqual(self.snapshot(), before)


class BackupPackageContract(HostFixture):
    """Backup & restore package: docs/backup/CONTRACT.md section 3 layout, modes and runtime boundary."""

    def add_source(self, files):
        for name, text in files.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def add_backup_source(self, ui=True, engine=True, demo=True):
        for wanted, files in ((ui, UI_SOURCE), (engine, ENGINE_SOURCE), (demo, DEMO_SOURCE)):
            if wanted:
                self.add_source(files)

    def tree(self, *bases):
        """Files, directories and links (with modes) below the given relative trees."""
        found = {}
        for base in bases:
            top = self.root / base
            for path in ([top] if os.path.lexists(top) else []) + sorted(top.rglob('*') if top.is_dir() else []):
                st = os.lstat(path)
                rel = path.relative_to(self.root).as_posix()
                if stat.S_ISLNK(st.st_mode):
                    found[rel] = ('link', os.readlink(path))
                elif stat.S_ISDIR(st.st_mode):
                    found[rel] = ('dir', stat.S_IMODE(st.st_mode))
                else:
                    found[rel] = ('file', stat.S_IMODE(st.st_mode), path.read_bytes())
        return found

    def state(self):
        return json.loads((self.root / manage.STATE).read_text())

    def journal(self, backup_id):
        return json.loads((self.root / manage.BACKUPS / backup_id / 'transaction.json').read_text())

    def test_default_install_places_backup_package_with_contract_modes(self):
        self.add_backup_source()
        # A restrictive umask must not leave the page unreadable for the Cockpit bridge (login user).
        with umask(0o077):
            result = self.install()
        self.assertEqual(result['status'], 'installed')
        ui = self.root / manage.BACKUP_UI
        for name in ('manifest.json', 'index.html', 'backup.css', 'backup.js'):
            self.assertEqual((ui / name).read_text(), UI_SOURCE[f'backup/{name}'])
            self.assertEqual(mode(ui / name), 0o644, name)
        engine = self.root / manage.BACKUP_ENGINE
        for name, text in ENGINE_SOURCE.items():
            relative = name.removeprefix('backup-engine/woowbackup/')
            if name.endswith('.py'):
                self.assertEqual((engine / relative).read_text(), text)
                self.assertEqual(mode(engine / relative), 0o644, relative)
        self.assertEqual(list(engine.rglob('__pycache__')) + list(engine.rglob('*.pyc')), [])
        helper = self.root / manage.BACKUP_HELPER
        self.assertEqual(helper.read_text(), ENGINE_SOURCE['backup-engine/woowtech-cockpit-backup'])
        self.assertEqual(mode(helper), 0o755)
        version = self.root / manage.BACKUP_VERSION
        self.assertEqual(version.read_bytes(), b'test.1')
        self.assertEqual(mode(version), 0o644)
        for directory in (manage.BACKUP_UI, manage.BACKUP_LIB, manage.BACKUP_ENGINE, f'{manage.BACKUP_ENGINE}/adapters',
                          manage.BACKUP_CATALOG):
            self.assertTrue((self.root / directory).is_dir(), directory)
            self.assertEqual(mode(self.root / directory), 0o755, directory)
        self.assertEqual(list((self.root / manage.BACKUP_CATALOG).iterdir()), [])
        # The demo fixture is lab-only and never part of a default installation.
        self.assertFalse((self.root / manage.BACKUP_SHARE).exists())
        state = self.state()
        self.assertTrue(state['backup'])
        self.assertFalse(state['backup_demo_catalog'])
        self.assertEqual(state['files'][manage.BACKUP_HELPER]['role'], 'backup-helper')
        self.assertIn(manage.BACKUP_CATALOG, state['directories'])
        self.assertEqual(manage.verify(self.root)['status'], 'verified')

    def test_reinstall_is_idempotent(self):
        self.add_backup_source()
        with umask(0o002):
            first = self.install(backup_demo_catalog=True)
            self.assertGreater(first['changed'], 0)
            self.assertEqual(self.install(backup_demo_catalog=True), {'changed': 0, 'status': 'already-current'})
            self.assertEqual(self.install(backup_demo_catalog=True)['changed'], 0)
        self.assertEqual([p.name for p in (self.root / manage.BACKUPS).iterdir()], [first['backup_id']])
        desired, state = manage.desired_files(self.root, backup_demo_catalog=True)
        self.assertEqual(manage.changes(self.root, desired), [])
        self.assertEqual(manage.directory_plan(self.root, state), [])

    def test_installed_layout_passes_the_entrypoint_trust_check(self):
        entrypoint = load_entrypoint()
        if entrypoint is None:
            self.skipTest('backup-engine/woowtech-cockpit-backup with library_trusted() is not available yet')
        self.add_backup_source(demo=False)
        with umask(0o002):  # a permissive umask must not produce group-writable directories
            self.install()
        entrypoint.LIB = str(self.root / manage.BACKUP_LIB)
        self.assertTrue(entrypoint.library_trusted())
        adapters = self.root / manage.BACKUP_ENGINE / 'adapters'
        adapters.chmod(0o775)
        self.assertFalse(entrypoint.library_trusted())
        self.assertEqual(manage.verify(self.root)['drift'], [f'{manage.BACKUP_ENGINE}/adapters/'])
        self.install()
        self.assertTrue(entrypoint.library_trusted())
        (self.root / manage.BACKUP_ENGINE / 'cli.py').chmod(0o664)
        self.assertFalse(entrypoint.library_trusted())
        self.install()
        self.assertTrue(entrypoint.library_trusted())
        self.assertEqual(manage.verify(self.root)['status'], 'verified')

    def test_no_backup_leaves_existing_backup_files_untouched(self):
        # A device that already has (other) backup files: an older helper, engine and page.
        existing = {manage.BACKUP_HELPER: ('#!/usr/bin/python3 -I\n# old helper\n', 0o700),
                    f'{manage.BACKUP_ENGINE}/cli.py': ('OLD = True\n', 0o640),
                    f'{manage.BACKUP_UI}/backup.js': ('/* customised */', 0o664)}
        for name, (text, file_mode) in existing.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            path.chmod(file_mode)
        self.add_backup_source()
        before = self.tree(*BACKUP_TREES)
        notices = []
        desired, state = manage.desired_files(self.root, include_backup=False, notices=notices)
        self.assertEqual([name for name in desired if manage.backup_path(name)], [])
        self.assertEqual(state['directories'], [])
        self.assertFalse(state['backup'])
        self.assertEqual(notices, [])
        result = manage.install(self.root, desired, state)
        self.assertEqual(self.tree(*BACKUP_TREES), before)
        self.assertFalse((self.root / manage.BACKUP_CATALOG).exists())
        self.assertEqual(manage.verify(self.root)['status'], 'verified')
        manage.rollback(self.root, result['backup_id'])
        self.assertEqual(self.tree(*BACKUP_TREES), before)
        # After a managed install, --no-backup neither upgrades nor prunes the installed package.
        self.install()
        managed = self.tree(*BACKUP_TREES)
        (self.source / 'backup-engine/woowbackup/archive.py').unlink()
        (self.source / 'backup-engine/woowbackup/cli.py').write_text('NEW = True\n')
        self.install(include_backup=False)
        self.assertEqual(self.tree(*BACKUP_TREES), managed)
        self.assertEqual(manage.verify(self.root)['status'], 'verified')

    def test_demo_catalog_installs_trusted_entry_and_quadlet_templates_only(self):
        self.add_backup_source()
        before, before_files = self.tree(*BACKUP_TREES), self.snapshot()
        with umask(0o002):
            result = self.install(backup_demo_catalog=True)
        catalog = self.root / manage.DEMO_CATALOG
        self.assertEqual(catalog.read_bytes(), (self.source / 'catalog-examples/woowbk-demo/catalog.json').read_bytes())
        self.assertEqual(mode(catalog), 0o644)
        templates = self.root / manage.DEMO_TEMPLATES / 'quadlet'
        self.assertEqual(json.loads(catalog.read_text())['quadlet']['template_dir'], f'/{manage.DEMO_TEMPLATES}/quadlet')
        self.assertEqual(sorted(p.name for p in templates.iterdir()), sorted(QUADLETS))
        for name in QUADLETS:
            self.assertEqual((templates / name).read_text(), DEMO_SOURCE[f'catalog-examples/woowbk-demo/quadlet/{name}'])
            self.assertEqual(mode(templates / name), 0o644)
        for directory in (manage.BACKUP_SHARE, manage.BACKUP_TEMPLATES, manage.DEMO_TEMPLATES,
                          f'{manage.DEMO_TEMPLATES}/quadlet', manage.BACKUP_CATALOG):
            self.assertEqual(mode(self.root / directory), 0o755, directory)
        new_files = set(self.snapshot()) - set(before_files)
        for tooling in ('README.md', 'app.py', 'Containerfile', 'seed.py', 'app.cpython-312.pyc'):
            self.assertFalse([name for name in new_files if posixpath.basename(name) == tooling], tooling)
        self.assertEqual(manage.verify(self.root)['status'], 'verified')
        self.assertEqual(self.install(backup_demo_catalog=True)['changed'], 0)
        manage.rollback(self.root, result['backup_id'])
        self.assertEqual(self.tree(*BACKUP_TREES), before)
        self.assertEqual(self.snapshot(), before_files)

    def test_demo_catalog_problems_stop_before_anything_is_written(self):
        self.add_backup_source()
        before, before_files = self.tree(*BACKUP_TREES), self.snapshot()
        with self.assertRaisesRegex(ValueError, 'needs the backup package'):
            manage.desired_files(self.root, include_backup=False, backup_demo_catalog=True)
        catalog = self.source / 'catalog-examples/woowbk-demo/catalog.json'
        good = catalog.read_text()
        moved = json.loads(good)
        moved['quadlet']['template_dir'] = '/usr/local/share/woowtech-cockpit-backup/catalog/other/quadlet'
        extra = json.loads(good)
        extra['quadlet']['files'].append('woowbk-demo-extra.container')
        for text, message in ((json.dumps(moved), 'template_dir'),
                              (json.dumps(extra), 'woowbk-demo-extra.container.*is missing'),
                              ('{"id": "woowbk-demo", "id": "x"}', 'not valid JSON'),
                              (None, 'catalog.json not found')):
            with self.subTest(message=message):
                if text is None:
                    catalog.unlink()
                else:
                    catalog.write_text(text)
                with self.assertRaisesRegex(ValueError, message):
                    self.install(backup_demo_catalog=True)
                self.assertEqual(self.tree(*BACKUP_TREES), before)
                self.assertEqual(self.snapshot(), before_files)

    def test_verify_reports_backup_drift_and_install_repairs_it(self):
        self.add_backup_source()
        self.install(backup_demo_catalog=True)
        engine = self.root / manage.BACKUP_ENGINE
        cases = (
            (lambda: (engine / 'cli.py').write_text('tampered = True\n'), f'{manage.BACKUP_ENGINE}/cli.py'),
            (lambda: (engine / 'archive.py').chmod(0o664), f'{manage.BACKUP_ENGINE}/archive.py'),
            (lambda: (self.root / manage.BACKUP_HELPER).chmod(0o644), manage.BACKUP_HELPER),
            (lambda: (self.root / manage.BACKUP_VERSION).write_text('9999.1\n'), manage.BACKUP_VERSION),
            (lambda: (self.root / manage.BACKUP_UI / 'backup.js').unlink(), f'{manage.BACKUP_UI}/backup.js'),
            (lambda: (engine / 'adapters').chmod(0o775), f'{manage.BACKUP_ENGINE}/adapters/'),
            (lambda: (self.root / manage.BACKUP_CATALOG).chmod(0o777), f'{manage.BACKUP_CATALOG}/'),
            (lambda: (self.root / manage.DEMO_CATALOG).write_text('{}'), manage.DEMO_CATALOG),
            (lambda: (self.root / manage.DEMO_TEMPLATES / 'quadlet').chmod(0o700), f'{manage.DEMO_TEMPLATES}/quadlet/'),
        )
        for damage, expected in cases:
            with self.subTest(drift=expected):
                damage()
                result = manage.verify(self.root)
                self.assertEqual((result['status'], result['drift']), ('drift', [expected]))
                repair = self.install(backup_demo_catalog=True)
                self.assertEqual(repair['changed'], 1)
                self.assertEqual(manage.verify(self.root)['status'], 'verified')
        # Repairing a group/world-writable directory is never undone by rolling the repair back.
        (self.root / manage.BACKUP_CATALOG).chmod(0o777)
        repair = self.install(backup_demo_catalog=True)
        manage.rollback(self.root, repair['backup_id'])
        self.assertEqual(mode(self.root / manage.BACKUP_CATALOG), 0o755)

    def test_upgrade_removes_obsolete_modules_and_rollback_restores_each_version(self):
        self.add_backup_source()
        with umask(0o002):
            original = self.tree(*BACKUP_TREES), self.snapshot()
            first = self.install(backup_demo_catalog=True)
            version_one = self.tree(*BACKUP_TREES), self.snapshot()
            (self.source / 'backup-engine/woowbackup/archive.py').unlink()
            (self.source / 'catalog-examples/woowbk-demo/quadlet/woowbk-demo.network').write_text('# renamed\n')
            self.add_source({'backup-engine/woowbackup/cli.py': 'def main(argv):\n    return 2\n',
                             'backup-engine/woowbackup/adapters/fresh.py': 'NEW = 1\n',
                             'backup-engine/woowbackup/staging/__init__.py': '',
                             'backup/backup.js': '"use strict"; /* v2 */',
                             'VERSION': 'test.2'})
            second = self.install(backup_demo_catalog=True)
        self.assertEqual(second['removed'], 1)
        engine = self.root / manage.BACKUP_ENGINE
        self.assertFalse((engine / 'archive.py').exists())
        self.assertEqual((engine / 'adapters/fresh.py').read_text(), 'NEW = 1\n')
        self.assertEqual(mode(engine / 'staging'), 0o755)
        self.assertEqual((self.root / manage.BACKUP_VERSION).read_text(), 'test.2')
        self.assertEqual(manage.verify(self.root)['status'], 'verified')
        manage.rollback(self.root, second['backup_id'])
        self.assertEqual((self.tree(*BACKUP_TREES), self.snapshot()), version_one)
        self.assertEqual(manage.verify(self.root)['status'], 'verified')
        manage.rollback(self.root, first['backup_id'])
        self.assertEqual((self.tree(*BACKUP_TREES), self.snapshot()), original)
        with self.assertRaisesRegex(ValueError, 'refusing repeat rollback'):
            manage.rollback(self.root, first['backup_id'])

    def test_rollback_refuses_newer_changes_to_backup_files(self):
        self.add_backup_source()
        result = self.install()
        helper = self.root / manage.BACKUP_HELPER
        helper.write_text('#!/usr/bin/python3 -I\n# hotfix\n')
        before = self.tree(*BACKUP_TREES)
        with self.assertRaisesRegex(ValueError, 'Changed since installation'):
            manage.rollback(self.root, result['backup_id'])
        self.assertEqual(self.tree(*BACKUP_TREES), before)

    def test_runtime_data_is_never_managed_backed_up_verified_or_rolled_back(self):
        self.add_backup_source()
        runtime = {
            'var/lib/woowtech-backup/archives/20261113T020000Z-a1b2c3d4.woowbackup': b'WOOWTECH-BACKUP/1\n{}\n',
            'var/lib/woowtech-backup/archives/20261113T020000Z-a1b2c3d4.json': b'{"id": "20261113T020000Z-a1b2c3d4"}',
            'var/lib/woowtech-backup/jobs/j20261113T020000Z-a1b2c3d4.json': b'{"state": "succeeded"}',
            'var/lib/woowtech-backup/requests.json': b'{}',
            'etc/woowtech-cockpit/backup/keys/device-ABCD-EF01-2345-6789.key': b'AGE-SECRET-KEY-1TESTONLY\n',
            'etc/woowtech-cockpit/backup/keys/keys.json': b'{"device": "ABCD-EF01-2345-6789"}',
            'run/woowtech-backup/engine.lock': b'',
        }
        with umask(0o077):  # created by the engine as root with umask 077
            for name, data in runtime.items():
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        (self.root / 'etc/woowtech-cockpit').chmod(0o755)
        before = self.tree(*RUNTIME_TREES)
        self.assertEqual(mode(self.root / manage.BACKUP_CONFIG), 0o700)
        first = self.install(backup_demo_catalog=True)
        self.assertEqual(self.tree(*RUNTIME_TREES), before)
        self.assertEqual(mode(self.root / manage.BACKUP_CONFIG), 0o700, 'stricter engine mode kept')
        self.assertEqual(mode(self.root / manage.BACKUP_CATALOG), 0o755)
        self.assertEqual(manage.verify(self.root)['status'], 'verified')
        self.add_source({'backup-engine/woowbackup/cli.py': 'def main(argv):\n    return 3\n'})
        second = self.install(backup_demo_catalog=True)
        for backup_id in (first['backup_id'], second['backup_id']):
            journal = self.journal(backup_id)
            touched = [rec['path'] for rec in journal['files'] + journal['directories']]
            saved = [p.relative_to(self.root / manage.BACKUPS / backup_id / 'files').as_posix()
                     for p in (self.root / manage.BACKUPS / backup_id / 'files').rglob('*')]
            self.assertEqual([p for p in touched + saved if manage.runtime_path(p)], [])
        state = self.state()
        self.assertEqual([p for p in list(state['files']) + state['directories'] if manage.runtime_path(p)], [])
        manage.rollback(self.root, second['backup_id'])
        manage.rollback(self.root, first['backup_id'])
        self.assertEqual(self.tree(*RUNTIME_TREES), before)
        self.assertEqual(mode(self.root / manage.BACKUP_CONFIG), 0o700)
        self.assertFalse((self.root / manage.BACKUP_CATALOG).exists(), 'created by the install, removed again')
        for name in runtime:
            self.assertFalse(manage.allowed_target(name), name)
            self.assertFalse(manage.allowed_directory(posixpath.dirname(name)), name)

    def test_rollback_refuses_a_journal_that_points_at_runtime_data(self):
        self.add_backup_source()
        key = self.root / 'etc/woowtech-cockpit/backup/keys/device-ABCD-EF01-2345-6789.key'
        key.parent.mkdir(parents=True)
        key.write_bytes(b'AGE-SECRET-KEY-1TESTONLY\n')
        result = self.install()
        path = self.root / manage.BACKUPS / result['backup_id'] / 'transaction.json'
        pristine = path.read_text()
        tampered_file = {'path': 'etc/woowtech-cockpit/backup/keys/device-ABCD-EF01-2345-6789.key', 'existed': False,
                         'before_sha256': None, 'after_sha256': manage.digest(key.read_bytes())}
        tampered_dir = {'path': 'var/lib/woowtech-backup', 'existed': False, 'mode_before': None, 'mode_after': 0o755}
        for section, record in (('files', tampered_file), ('directories', tampered_dir)):
            with self.subTest(section=section):
                journal = json.loads(pristine)
                journal[section].append(record)
                path.write_text(json.dumps(journal))
                before = self.tree(*BACKUP_TREES), self.snapshot()
                with self.assertRaisesRegex(ValueError, 'unmanaged path'):
                    manage.rollback(self.root, result['backup_id'])
                self.assertEqual((self.tree(*BACKUP_TREES), self.snapshot()), before)
        self.assertEqual(key.read_bytes(), b'AGE-SECRET-KEY-1TESTONLY\n')

    def test_missing_backup_sources_are_skipped_and_installed_copies_kept(self):
        page = self.root / manage.BACKUP_UI / 'backup.js'
        page.parent.mkdir(parents=True)
        page.write_text('/* installed earlier */')
        notices = []
        desired, state = manage.desired_files(self.root, notices=notices)
        self.assertEqual(len(notices), 2)
        self.assertIn('backup/manifest.json', notices[0])
        self.assertIn('backup-engine/woowtech-cockpit-backup', notices[1])
        self.assertEqual([name for name in desired if manage.backup_path(name)], [])
        self.assertEqual(state['directories'], [manage.BACKUP_CATALOG])
        manage.install(self.root, desired, state)
        self.assertEqual(page.read_text(), '/* installed earlier */')
        self.assertEqual(mode(self.root / manage.BACKUP_CATALOG), 0o755)
        # The engine arrives first: it is installed, the page source is still missing and kept as is.
        self.add_backup_source(ui=False, demo=False)
        notices = []
        desired, state = manage.desired_files(self.root, notices=notices)
        manage.install(self.root, desired, state)
        self.assertEqual(len(notices), 1)
        self.assertTrue((self.root / manage.BACKUP_HELPER).is_file())
        self.assertEqual(page.read_text(), '/* installed earlier */')
        self.assertEqual(manage.verify(self.root)['status'], 'verified')

    def test_helper_without_isolated_python_shebang_is_refused(self):
        self.add_backup_source()
        (self.source / 'backup-engine/woowtech-cockpit-backup').write_text('#!/usr/bin/env python3\n')
        before = self.tree(*BACKUP_TREES), self.snapshot()
        with self.assertRaisesRegex(ValueError, 'python3 -I'):
            self.install()
        self.assertEqual((self.tree(*BACKUP_TREES), self.snapshot()), before)

    def test_symlinks_cannot_redirect_backup_files(self):
        self.add_backup_source()
        outside = Path(self.temp.name) / 'outside-lib'
        outside.mkdir()
        (self.root / 'usr/local/lib').mkdir(parents=True)
        (self.root / manage.BACKUP_LIB).symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.install()
        self.assertEqual(list(outside.iterdir()), [])
        (self.root / manage.BACKUP_LIB).unlink()
        (self.source / 'backup-engine/woowbackup/link.py').symlink_to(self.source / 'backup-engine/woowbackup/cli.py')
        with self.assertRaisesRegex(ValueError, 'Source symlink'):
            self.install()
        self.assertFalse((self.root / manage.BACKUP_LIB).exists())

    def test_live_install_refuses_unsafe_or_foreign_directories(self):
        self.add_backup_source()
        desired, state = manage.desired_files(self.root)
        # As on a real device: every directory on the way is writable by its owner only.
        for path in [self.root, *self.root.rglob('*')]:
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o755)
        libexec = self.root / 'usr/local/libexec'
        libexec.mkdir(mode=0o755)
        libexec.chmod(0o775)
        with self.assertRaisesRegex(ValueError, 'usr/local/libexec is writable by group/others'):
            manage.directory_plan(self.root, state, live=True, uid=os.getuid())
        libexec.chmod(0o755)
        planned = [rec['path'] for rec in manage.directory_plan(self.root, state, live=True, uid=os.getuid())]
        self.assertIn(manage.BACKUP_ENGINE, planned)
        self.assertNotIn('usr/local/libexec', planned)
        with self.assertRaisesRegex(ValueError, 'root-owned'):
            manage.directory_plan(self.root, state, live=True, uid=os.getuid() + 1)

    def test_repository_payload_installs_and_passes_the_trust_check(self):
        required = ('backup/manifest.json', 'backup-engine/woowtech-cockpit-backup', 'backup-engine/woowbackup/cli.py',
                    'catalog-examples/woowbk-demo/catalog.json')
        missing = [name for name in required if not (REPO / name).is_file()]
        if missing:
            self.skipTest(f'pending other teams: {", ".join(missing)}')
        with patch.object(manage, 'SOURCE', REPO), umask(0o002):
            notices = []
            desired, state = manage.desired_files(self.root, include_preview=False, include_services=False,
                                                  backup_demo_catalog=True, notices=notices)
            result = manage.install(self.root, desired, state)
        self.assertEqual(notices, [])
        engine = self.root / manage.BACKUP_ENGINE
        shipped = sorted(p.relative_to(REPO / 'backup-engine/woowbackup').as_posix()
                         for p in (REPO / 'backup-engine/woowbackup').rglob('*.py') if '__pycache__' not in p.parts)
        self.assertEqual(sorted(p.relative_to(engine).as_posix() for p in engine.rglob('*') if p.is_file()), shipped)
        self.assertEqual((self.root / manage.BACKUP_VERSION).read_bytes(), (REPO / 'VERSION').read_bytes())
        self.assertEqual(mode(self.root / manage.BACKUP_HELPER), 0o755)
        templates = self.root / manage.DEMO_TEMPLATES / 'quadlet'
        catalog = json.loads((self.root / manage.DEMO_CATALOG).read_text())
        self.assertEqual(catalog['quadlet']['template_dir'], f'/{manage.DEMO_TEMPLATES}/quadlet')
        self.assertTrue(set(catalog['quadlet']['files']) <= {p.name for p in templates.iterdir()})
        entrypoint = load_entrypoint()
        if entrypoint is not None:
            entrypoint.LIB = str(self.root / manage.BACKUP_LIB)
            self.assertTrue(entrypoint.library_trusted())
        self.assertEqual(manage.verify(self.root)['status'], 'verified')
        manage.rollback(self.root, result['backup_id'])
        self.assertFalse((self.root / manage.BACKUP_LIB).exists())

    def test_command_line_flags(self):
        if not all((REPO / name).is_file() for name in ('backup/manifest.json', 'backup-engine/woowbackup/cli.py',
                                                         'catalog-examples/woowbk-demo/catalog.json')):
            self.skipTest('pending other teams: backup sources not complete')

        def run(*args):
            return subprocess.run([sys.executable, str(REPO / 'scripts/manage.py'), '--root', str(self.root), *args],
                                  capture_output=True, text=True, timeout=120)

        help_text = run('install', '--help').stdout
        self.assertIn('--backup-demo-catalog', help_text)
        self.assertIn('--no-backup', help_text)
        light = ('--no-preview', '--no-services')
        plan = run('plan', *light, '--backup-demo-catalog')
        self.assertEqual(plan.returncode, 0, plan.stderr)
        planned = json.loads(plan.stdout)
        self.assertIn(manage.DEMO_CATALOG, planned['changed'])
        self.assertIn(f'{manage.BACKUP_ENGINE}/', planned['directories'])
        self.assertFalse((self.root / manage.BACKUP_LIB).exists(), 'plan changes nothing')
        conflict = run('plan', '--no-backup', '--backup-demo-catalog')
        self.assertEqual(conflict.returncode, 1)
        self.assertIn('needs the backup package', conflict.stderr)
        installed = run('install', *light, '--backup-demo-catalog')
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.assertIn('never use it on customer devices', installed.stderr)
        backup_id = json.loads(installed.stdout)['backup_id']
        self.assertEqual(json.loads(run('install', *light, '--backup-demo-catalog').stdout)['changed'], 0)
        self.assertEqual(json.loads(run('verify').stdout)['status'], 'verified')
        (self.root / manage.BACKUP_LIB).chmod(0o775)
        drift = run('verify')
        self.assertEqual(drift.returncode, 1)
        self.assertEqual(json.loads(drift.stdout)['drift'], [f'{manage.BACKUP_LIB}/'])
        (self.root / manage.BACKUP_LIB).chmod(0o755)
        rolled = run('rollback', backup_id)
        self.assertEqual(rolled.returncode, 0, rolled.stderr)
        self.assertFalse((self.root / manage.BACKUP_UI).exists())


class FakeSystemctl:
    """systemctl of a fixture root (the runner `manage.Systemd` takes): keeps the timer's enabled/active state the way
    PID 1 would, needs the unit file below the root for enable/disable/start, records every changing call. `masked`:
    `systemctl mask` was run (show says so; enable and start refuse, stop and disable work)."""

    def __init__(self, root, *, enabled=False, active=False, fail=(), masked=False):
        self.root = root
        self.enabled, self.active, self.masked = enabled, active, masked
        self.fail = set(fail)
        self.calls = []

    def unit_file(self):
        return (self.root / manage.TIMER_FILE).is_file()

    def __call__(self, argv):
        assert argv[0] == manage.SYSTEMCTL, argv
        args = list(argv[1:])
        if args[0] == 'show':
            assert args[-2:] == ['--', manage.SCHEDULE_TIMER], args
            loaded = self.unit_file()
            unit_file = ('enabled' if self.enabled else 'disabled') if loaded else ''
            load = 'loaded' if loaded else 'not-found'
            if self.masked:
                load = unit_file = 'masked'
            return 0, (f'LoadState={load}\nUnitFileState={unit_file}\n'
                       f'ActiveState={"active" if self.active else "inactive"}\n'), ''
        command = ' '.join(args)
        self.calls.append(command)
        if command in self.fail:
            return 1, '', 'Failed (test)'
        if args == ['daemon-reload']:
            return 0, '', ''
        assert args[0] in ('enable', 'disable', 'start', 'stop') and args[-1] == manage.SCHEDULE_TIMER, args
        if self.masked and args[0] in ('enable', 'start'):
            return 1, '', f'Failed to {args[0]} unit: Unit file /etc/systemd/system/{manage.SCHEDULE_TIMER} is masked.'
        if args[0] in ('enable', 'disable', 'start') and not self.unit_file():
            return 1, '', 'Unit file does not exist.'
        if args[0] == 'enable':
            self.enabled = True
            self.active = self.active or '--now' in args
        elif args[0] == 'disable':
            self.enabled = False
            self.active = self.active and '--now' not in args
        else:
            self.active = args[0] == 'start'
        return 0, '', ''


def load_check_source():
    spec = importlib.util.spec_from_file_location('check_source', REPO / 'scripts/check_source.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ScheduleTimerContract(HostFixture):
    """排程備份: the timer and its tick service ship with the engine; on the live root the installer stops the timer while
    it writes, reloads systemd when a unit changed and enables the timer (never a masked one); the journal keeps its
    earlier state for the rollback, which touches the timer only for backup files; --no-backup, --root and a live root
    without a running systemd run no systemctl (docs/backup/CONTRACT.md section 8, docs/deployment.md)."""

    TIMER = manage.SCHEDULE_TIMER
    # The backup package's helpers, without running its tests a second time.
    add_source = BackupPackageContract.add_source
    add_backup_source = BackupPackageContract.add_backup_source
    tree = BackupPackageContract.tree
    state = BackupPackageContract.state
    journal = BackupPackageContract.journal

    def live(self, runner, **options):
        desired, state = manage.desired_files(self.root, **options)
        return manage.install(self.root, desired, state, systemd=manage.Systemd(runner))

    def test_units_install_with_the_engine_and_verify_like_its_files(self):
        self.add_backup_source()
        before = self.tree(*BACKUP_TREES)
        result = self.install()
        for name in manage.UNIT_FILES:
            path = self.root / name
            source = ENGINE_SOURCE[f'backup-engine/systemd/{posixpath.basename(name)}']
            self.assertEqual((path.read_text(), mode(path)), (source, 0o644))
            self.assertEqual(self.state()['files'][name]['role'], 'backup-unit')
        self.assertEqual(mode(self.root / manage.UNIT_DIR), 0o755)
        verified = manage.verify(self.root)
        self.assertEqual((verified['status'], verified['timer']), ('verified', 'not-checked'))
        (self.root / manage.TIMER_FILE).chmod(0o664)
        self.assertEqual(manage.verify(self.root)['drift'], [manage.TIMER_FILE])
        self.install()
        manage.rollback(self.root, result['backup_id'])
        self.assertEqual(self.tree(*BACKUP_TREES), before, 'the unit files and the directories made for them are gone')

    def test_a_first_live_install_reloads_and_enables_the_timer_and_journals_its_state(self):
        self.add_backup_source()
        runner = FakeSystemctl(self.root)
        result = self.live(runner)
        self.assertEqual(runner.calls, ['daemon-reload', f'enable --now {self.TIMER}'])
        self.assertEqual(result['systemctl'], runner.calls)
        self.assertEqual((result['timer']['enabled'], result['timer']['active']), (True, True))
        self.assertEqual(self.journal(result['backup_id'])['systemd'], {
            'timer': self.TIMER, 'stopped': False,
            'before': {'load_state': 'not-found', 'unit_file_state': '', 'active_state': 'inactive', 'enabled': False,
                       'active': False}})
        verified = manage.verify(self.root, systemd=manage.Systemd(runner))
        self.assertEqual((verified['status'], verified['timer']['active']), ('verified', True))
        runner.active = False  # stopped by hand: reported, never drift
        verified = manage.verify(self.root, systemd=manage.Systemd(runner))
        self.assertEqual((verified['status'], verified['drift'], verified['timer']['active']), ('verified', [], False))

    def test_an_upgrade_stops_the_timer_while_it_writes_and_enables_it_again(self):
        self.add_backup_source()
        runner = FakeSystemctl(self.root)
        self.live(runner)
        runner.calls.clear()
        self.add_source({'backup-engine/woowbackup/cli.py': 'def main(argv):\n    return 9\n'})
        seen = []
        original = manage.atomic_write

        def spy(path, data, mode=0o644):
            if '/woowbackup/' in str(path) and manage.BACKUPS not in str(path):  # the installed copies
                seen.append(runner.active)
            return original(path, data, mode)

        with patch.object(manage, 'atomic_write', spy):
            result = self.live(runner)
        self.assertEqual(runner.calls, [f'stop {self.TIMER}', f'enable --now {self.TIMER}'], 'no unit changed')
        self.assertTrue(seen and not any(seen), 'no tick can start while the engine files change')
        self.assertTrue(self.journal(result['backup_id'])['systemd']['stopped'])
        runner.calls.clear()
        self.add_source({'backup-engine/systemd/woowtech-cockpit-backup-schedule.timer': '[Unit]\nDescription=v2\n'})
        self.live(runner)
        self.assertEqual(runner.calls, [f'stop {self.TIMER}', 'daemon-reload', f'enable --now {self.TIMER}'])
        self.assertEqual(manage.timer_plan([manage.TIMER_FILE], self.state(), {'enabled': True, 'active': True}),
                         [f'stop {self.TIMER}', 'daemon-reload', f'enable --now {self.TIMER}'])

    def test_an_install_with_nothing_to_change_enables_a_timer_turned_off_by_hand(self):
        self.add_backup_source()
        runner = FakeSystemctl(self.root)
        self.live(runner)
        runner.enabled = runner.active = False
        runner.calls.clear()
        result = self.live(runner)
        self.assertEqual((result['status'], result['changed']), ('already-current', 0))
        self.assertEqual((runner.calls, result['systemctl']), ([f'enable --now {self.TIMER}'],) * 2)
        runner.calls.clear()
        self.assertNotIn('systemctl', self.live(runner))
        self.assertEqual(runner.calls, [], 'enabled and running: nothing to do')

    def test_rollback_disables_and_stops_the_timer_removes_the_units_and_reloads(self):
        self.add_backup_source()
        runner = FakeSystemctl(self.root)
        first = self.live(runner)
        runner.calls.clear()
        result = manage.rollback(self.root, first['backup_id'], systemd=manage.Systemd(runner))
        self.assertEqual(runner.calls, [f'stop {self.TIMER}', f'disable {self.TIMER}', 'daemon-reload'])
        self.assertEqual((runner.enabled, runner.active), (False, False))
        self.assertFalse(any((self.root / name).exists() for name in manage.UNIT_FILES))
        self.assertEqual((result['timer']['enabled'], result['timer']['active']), (False, False))
        self.assertNotIn('warnings', result)
        again = self.live(runner)
        self.assertEqual((again['status'], runner.enabled, runner.active), ('installed', True, True), 'reinstall')

    def test_rollback_of_an_upgrade_puts_the_previous_units_and_timer_back(self):
        self.add_backup_source()
        runner = FakeSystemctl(self.root)
        self.live(runner)
        old_unit = (self.root / manage.TIMER_FILE).read_text()
        self.add_source({'backup-engine/systemd/woowtech-cockpit-backup-schedule.timer': '[Unit]\nDescription=v2\n'})
        second = self.live(runner)
        runner.calls.clear()
        manage.rollback(self.root, second['backup_id'], systemd=manage.Systemd(runner))
        self.assertEqual(runner.calls, [f'stop {self.TIMER}', f'disable {self.TIMER}', 'daemon-reload',
                                        f'enable {self.TIMER}', f'start {self.TIMER}'])
        self.assertEqual(((self.root / manage.TIMER_FILE).read_text(), runner.enabled, runner.active),
                         (old_unit, True, True))
        # An engine-only upgrade: the timer is stopped while the files go back and runs again afterwards.
        self.live(runner)  # the source still has the second timer
        self.add_source({'backup-engine/woowbackup/cli.py': 'def main(argv):\n    return 8\n'})
        third = self.live(runner)
        runner.calls.clear()
        manage.rollback(self.root, third['backup_id'], systemd=manage.Systemd(runner))
        self.assertEqual(runner.calls, [f'stop {self.TIMER}', f'enable {self.TIMER}', f'start {self.TIMER}'])

    def test_a_failed_install_restores_the_files_and_the_timer(self):
        self.add_backup_source()
        before = self.tree(*BACKUP_TREES), self.snapshot()
        runner = FakeSystemctl(self.root, fail={f'enable --now {self.TIMER}'})
        with self.assertRaisesRegex(ValueError, 'systemctl enable --now'):
            self.live(runner)
        self.assertEqual((self.tree(*BACKUP_TREES), self.snapshot()), before)
        self.assertEqual(runner.calls, ['daemon-reload', f'enable --now {self.TIMER}', f'disable --now {self.TIMER}',
                                        'daemon-reload'])
        self.assertEqual((runner.enabled, runner.active), (False, False))
        backup_id = next(p.name for p in (self.root / manage.BACKUPS).iterdir())
        self.assertEqual(self.journal(backup_id)['status'], 'failed-restored')
        # An upgrade that fails while writing: the files go back and the stopped timer runs again.
        runner = FakeSystemctl(self.root)
        self.live(runner)
        self.add_source({'backup-engine/woowbackup/cli.py': 'def main(argv):\n    return 7\n'})
        original = manage.atomic_write

        def broken(path, data, mode=0o644):
            if str(path).endswith('/woowbackup/cli.py') and manage.BACKUPS not in str(path):
                raise OSError('simulated disk failure')
            return original(path, data, mode)

        runner.calls.clear()
        with patch.object(manage, 'atomic_write', broken), self.assertRaisesRegex(OSError, 'simulated'):
            self.live(runner)
        self.assertEqual(runner.calls, [f'stop {self.TIMER}', f'enable {self.TIMER}', f'start {self.TIMER}'])
        self.assertEqual((runner.enabled, runner.active), (True, True))

    def test_no_backup_and_root_never_run_systemctl(self):
        self.add_backup_source()
        runner = FakeSystemctl(self.root)
        self.live(runner)
        runner.calls.clear()
        self.add_source({'backup-engine/systemd/woowtech-cockpit-backup-schedule.timer': '[Unit]\nDescription=v3\n'})
        self.live(runner, include_backup=False)
        self.assertEqual(runner.calls, [], '--no-backup leaves the units and the timer alone')
        self.assertNotEqual((self.root / manage.TIMER_FILE).read_text(), '[Unit]\nDescription=v3\n')

        def forbidden(argv):
            raise AssertionError(f'systemctl ran for a --root install: {argv}')

        with patch.object(manage, 'run_systemctl', forbidden):
            result = self.install()  # self.root is not "/": no systemctl at all
            self.assertEqual(result['status'], 'installed')
            self.assertNotIn('systemctl', result)
            self.assertEqual(manage.verify(self.root)['timer'], 'not-checked')
            self.assertNotIn('systemctl', manage.rollback(self.root, result['backup_id']))
        self.assertIsNone(manage.live_systemd(self.root))
        self.assertIsNone(manage.live_systemd(self.root, running=lambda: True))
        self.assertIsInstance(manage.live_systemd(Path('/'), running=lambda: True), manage.Systemd)

    def test_a_live_root_without_a_running_systemd_runs_no_systemctl(self):
        # "/" in a chroot or an image build: systemd is not PID 1 (no /run/systemd/system, what sd_booted checks). Like
        # --root the files install and no systemctl runs (review: daemon-reload failed and rolled the install back).
        marker = Path(self.temp.name) / 'run/systemd/system'
        with patch.object(manage, 'SYSTEMD_RUNNING', marker):
            self.assertFalse(manage.systemd_running())
            self.assertIsNone(manage.live_systemd(Path('/')))
            marker.mkdir(parents=True)
            self.assertTrue(manage.systemd_running())
            self.assertIsInstance(manage.live_systemd(Path('/')), manage.Systemd)
        self.assertIsNone(manage.live_systemd(Path('/'), running=lambda: False))
        self.assertEqual(manage.SYSTEMD_RUNNING, Path('/run/systemd/system'))

    def test_a_masked_timer_is_the_administrators_decision(self):
        # systemctl mask: no install enables or starts it (nothing to change, a theme or an engine update); the files
        # install as usual and `notices` says why the schedule checks do not run (review: every install failed and
        # rolled back). Other systemctl failures still fail the install (test_a_failed_install_restores_...).
        self.add_backup_source()
        runner = FakeSystemctl(self.root)
        self.live(runner)
        runner.masked, runner.enabled, runner.active = True, False, False  # systemctl mask --now
        runner.calls.clear()
        result = self.live(runner)
        self.assertEqual((result['status'], runner.calls), ('already-current', []))
        self.assertEqual(result['timer']['unit_file_state'], 'masked')
        self.assertEqual(result['notices'], [manage.MASKED_NOTICE])
        self.assertIn(f'systemctl unmask {self.TIMER}', manage.MASKED_NOTICE)
        self.add_source({'branding/branding.css': 'newer theme',
                         'backup-engine/woowbackup/cli.py': 'def main(argv):\n    return 6\n'})
        result = self.live(runner)
        self.assertEqual((result['status'], result['systemctl'], result['notices']),
                         ('installed', [], [manage.MASKED_NOTICE]))
        self.assertEqual((self.root / manage.BACKUP_ENGINE / 'cli.py').read_text(), 'def main(argv):\n    return 6\n')
        self.assertEqual(self.journal(result['backup_id'])['status'], 'installed')
        before = manage.Systemd(runner).timer_state()
        self.assertEqual(manage.timer_plan([manage.TIMER_FILE], self.state(), before), ['daemon-reload'])
        # Masked while it still runs (mask without --now): stopped while the files change, not started again.
        runner.active = True
        self.add_source({'backup-engine/woowbackup/cli.py': 'def main(argv):\n    return 5\n'})
        result = self.live(runner)
        self.assertEqual((runner.calls, result['notices']), ([f'stop {self.TIMER}'], [manage.MASKED_NOTICE]))
        self.assertEqual((runner.enabled, runner.active), (False, False))
        # Unmasked: the next install turns the schedule checks on again.
        runner.masked = False
        runner.calls.clear()
        result = self.live(runner)
        self.assertEqual((runner.calls, runner.enabled, runner.active), ([f'enable --now {self.TIMER}'], True, True))
        self.assertNotIn('notices', result)

    def test_rolling_back_a_no_backup_install_leaves_the_timer_alone(self):
        # A --no-backup (theme-only) transaction never touched the timer; its rollback neither stops it nor puts back
        # the state it had then (review: it stopped a timer the administrator had turned on again since).
        self.add_backup_source()
        runner = FakeSystemctl(self.root)
        self.live(runner)
        runner.enabled = runner.active = False  # paused by hand: systemctl disable --now
        self.add_source({'branding/branding.css': 'newer theme'})
        theme = self.live(runner, include_backup=False)
        self.assertEqual(theme['systemctl'], [])
        runner.enabled = runner.active = True  # resumed by hand
        runner.calls.clear()
        result = manage.rollback(self.root, theme['backup_id'], systemd=manage.Systemd(runner))
        self.assertEqual((result['status'], runner.calls, runner.enabled, runner.active),
                         ('rolled-back', [], True, True))
        self.assertNotIn('systemctl', result)
        self.assertEqual((self.root / manage.BRAND / 'branding.css').read_text(), 'new theme')

    def test_rolling_back_an_install_that_found_the_timer_off_pauses_it_and_leaves_it_as_found(self):
        # The install neither stopped the timer (it was off) nor changed a unit; it turned it on. Its rollback pauses
        # the running timer while the engine files go back (as the install does) and starts it again: the snapshot
        # taken before that install is not applied.
        self.add_backup_source()
        runner = FakeSystemctl(self.root)
        self.live(runner)
        runner.enabled = runner.active = False
        self.add_source({'backup-engine/woowbackup/cli.py': 'def main(argv):\n    return 4\n'})
        upgrade = self.live(runner)
        self.assertEqual((upgrade['systemctl'], self.journal(upgrade['backup_id'])['systemd']['stopped']),
                         ([f'enable --now {self.TIMER}'], False))
        runner.calls.clear()
        seen = []
        original = manage.atomic_write

        def spy(path, data, mode=0o644):
            if '/woowbackup/' in str(path) and manage.BACKUPS not in str(path):  # the installed copies
                seen.append(runner.active)
            return original(path, data, mode)

        with patch.object(manage, 'atomic_write', spy):
            result = manage.rollback(self.root, upgrade['backup_id'], systemd=manage.Systemd(runner))
        self.assertEqual((runner.calls, result['systemctl']), ([f'stop {self.TIMER}', f'start {self.TIMER}'],) * 2)
        self.assertTrue(seen and not any(seen), 'no tick runs while the engine files go back')
        self.assertEqual((runner.enabled, runner.active), (True, True))
        self.assertEqual((self.root / manage.BACKUP_ENGINE / 'cli.py').read_text(), 'def main(argv):\n    return 0\n')

    def test_rollback_refuses_a_journal_with_a_foreign_unit(self):
        self.add_backup_source()
        runner = FakeSystemctl(self.root)
        result = self.live(runner)
        path = self.root / manage.BACKUPS / result['backup_id'] / 'transaction.json'
        pristine = json.loads(path.read_text())
        for change in ({'timer': 'ssh.service'}, {'stopped': 'yes'}, {'extra': 1},
                       {'before': {'enabled': True, 'active': True}}):
            with self.subTest(change=change):
                journal = json.loads(json.dumps(pristine))
                journal['systemd'].update(change)
                path.write_text(json.dumps(journal))
                runner.calls.clear()
                before = self.tree(*BACKUP_TREES), self.snapshot()
                with self.assertRaisesRegex(ValueError, 'invalid systemd record'):
                    manage.rollback(self.root, result['backup_id'], systemd=manage.Systemd(runner))
                self.assertEqual((self.tree(*BACKUP_TREES), self.snapshot(), runner.calls), (*before, []))

    def test_the_unit_directory_is_a_shared_parent_that_must_be_safe(self):
        self.add_backup_source()
        desired, state = manage.desired_files(self.root)
        for path in [self.root, *self.root.rglob('*')]:
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o755)
        planned = [rec['path'] for rec in manage.directory_plan(self.root, state, live=True, uid=os.getuid())]
        self.assertIn(manage.UNIT_DIR, planned)
        units = self.root / manage.UNIT_DIR
        units.mkdir(parents=True)
        for path in (units, *units.parents):
            if self.root in path.parents:
                path.chmod(0o755)
        units.chmod(0o750)
        self.assertNotIn(manage.UNIT_DIR, [rec['path'] for rec in manage.directory_plan(self.root, state, live=True,
                                                                                         uid=os.getuid())],
                         'an existing safe directory is not re-moded')
        units.chmod(0o775)
        with self.assertRaisesRegex(ValueError, 'lib/systemd/system is writable by group/others'):
            manage.directory_plan(self.root, state, live=True, uid=os.getuid())
        self.assertTrue(manage.allowed_directory(manage.UNIT_DIR))
        self.assertTrue(all(manage.allowed_target(name) and manage.backup_path(name) for name in manage.UNIT_FILES))
        self.assertFalse(manage.allowed_target(f'{manage.UNIT_DIR}/ssh.service'))

    def test_missing_unit_sources_are_skipped_with_a_notice(self):
        self.add_backup_source()
        for name in (manage.SCHEDULE_SERVICE, manage.SCHEDULE_TIMER):
            (self.source / 'backup-engine/systemd' / name).unlink()
        notices = []
        desired, state = manage.desired_files(self.root, notices=notices)
        self.assertEqual(len(notices), 1)
        self.assertIn('Skipped the scheduled-backup timer', notices[0])
        self.assertFalse(any(name in desired for name in manage.UNIT_FILES))
        self.assertIn(manage.BACKUP_HELPER, desired, 'the engine itself is still installed')

    def test_the_repository_units_pass_the_source_check_and_changes_are_refused(self):
        check = load_check_source()
        self.assertEqual(check.check_units(), 2)
        units = Path(self.temp.name) / 'units'
        bad = {
            'Persistent': (manage.SCHEDULE_TIMER,
                           lambda text: text.replace('AccuracySec=15s', 'AccuracySec=15s\nPersistent=true')),
            'OnCalendar': (manage.SCHEDULE_TIMER, lambda text: text.replace('*:0/5', 'daily')),
            'Install': (manage.SCHEDULE_SERVICE, lambda text: text + '\n[Install]\nWantedBy=multi-user.target\n'),
            'LogLevelMax': (manage.SCHEDULE_SERVICE, lambda text: text.replace('LogLevelMax=notice\n', '')),
            # stderr follows StandardOutput=null unless set: tracebacks and launch errors would be lost.
            'StandardError': (manage.SCHEDULE_SERVICE, lambda text: text.replace('StandardError=journal\n', '')),
            'stderr discarded': (manage.SCHEDULE_SERVICE,
                                 lambda text: text.replace('StandardError=journal', 'StandardError=null')),
            'ExecStart': (manage.SCHEDULE_SERVICE, lambda text: text.replace('schedule-tick', 'schedule-tick --x')),
            'repeated': (manage.SCHEDULE_SERVICE,
                         lambda text: text.replace('Type=oneshot', 'Type=oneshot\nType=simple')),
            'ASCII': (manage.SCHEDULE_TIMER, lambda text: text + '# 排程\n'),
        }
        for label, (name, damage) in bad.items():
            with self.subTest(label=label):
                if units.exists():
                    for path in units.iterdir():
                        path.unlink()
                else:
                    units.mkdir()
                for unit in (manage.SCHEDULE_SERVICE, manage.SCHEDULE_TIMER):
                    text = (REPO / 'backup-engine/systemd' / unit).read_text()
                    (units / unit).write_text(damage(text) if unit == name else text)
                with self.assertRaises(AssertionError):
                    check.check_units(units)
        parsed = check.parse_unit((REPO / 'backup-engine/systemd' / manage.SCHEDULE_SERVICE).read_text(), 'service')
        self.assertEqual(parsed['Service']['ExecStart'], '/usr/local/libexec/woowtech-cockpit-backup schedule-tick')
        output = {key: parsed['Service'].get(key) for key in ('StandardOutput', 'StandardError', 'SyslogLevel')}
        self.assertEqual(output, {'StandardOutput': 'null', 'StandardError': 'journal', 'SyslogLevel': 'warning'},
                         'stdout (the JSON reply) is dropped, stderr reaches the journal as warnings')
        self.assertFalse(manage.SCHEDULE_TIMER.startswith('woowtech-backup-'), 'outside the job units glob')

    def test_root_installs_print_what_to_run_on_the_target(self):
        if not (REPO / 'backup-engine/systemd' / manage.SCHEDULE_TIMER).is_file():
            self.skipTest('units not in the repository')
        result = subprocess.run([sys.executable, str(REPO / 'scripts/manage.py'), '--root', str(self.root), 'plan',
                                 '--no-preview', '--no-services'], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'systemctl enable --now {manage.SCHEDULE_TIMER}', result.stderr)
        planned = json.loads(result.stdout)
        self.assertEqual(planned['systemctl'], [])
        self.assertIn(manage.TIMER_FILE, planned['changed'])
        self.assertIn(f'{manage.UNIT_DIR}/', planned['directories'])


# What the real apt-get 2.8.4 wrote in the C locale: {case: (update, install)}, each (exit code, stdout, stderr). Recorded
# 2026-11-25 with the exact argv of manage.HostTools in a private unprivileged apt root (local repository, dpkg replaced by a
# stub; host names, ports and paths replaced), every line as apt wrote it. The raw files and the script that made them:
# tests/backup/evidence/parity-pkg-20261125/real-apt/.
APT_RECORDED = {
    'offline-no-index': (
        (0,
         'Ign:1 http://repo.example:80/ubuntu ./ InRelease\n'
         'Err:1 http://repo.example:80/ubuntu ./ InRelease\n'
         '  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'Reading package lists...\n',
         'W: Failed to fetch http://repo.example:80/ubuntu/./InRelease  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'W: Some index files failed to download. They have been ignored, or old ones used instead.\n'),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n',
         'E: Unable to locate package age\n'
         'E: Unable to locate package zstd\n'
         'E: Unable to locate package python3-nacl\n'
         'E: Unable to locate package python3-cryptography\n')),
    'offline-dns': (
        (0,
         'Ign:1 http://no-such-host.invalid/ubuntu ./ InRelease\n'
         'Err:1 http://no-such-host.invalid/ubuntu ./ InRelease\n'
         "  Could not resolve 'no-such-host.invalid'\n"
         'Reading package lists...\n',
         "W: Failed to fetch http://no-such-host.invalid/ubuntu/./InRelease  Could not resolve 'no-such-host.invalid'\n"
         'W: Some index files failed to download. They have been ignored, or old ones used instead.\n'),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n',
         'E: Unable to locate package age\n'
         'E: Unable to locate package zstd\n'
         'E: Unable to locate package python3-nacl\n'
         'E: Unable to locate package python3-cryptography\n')),
    'offline-old-index': (
        (0,
         'Ign:1 http://repo.example:80 ./ InRelease\n'
         'Err:1 http://repo.example:80 ./ InRelease\n'
         '  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'Reading package lists...\n',
         'W: Failed to fetch http://repo.example:80/./InRelease  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'W: Some index files failed to download. They have been ignored, or old ones used instead.\n'),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n'
         'The following NEW packages will be installed:\n'
         '  age python3-cryptography python3-nacl zstd\n'
         '0 upgraded, 4 newly installed, 0 to remove and 0 not upgraded.\n'
         'Need to get 2468 B of archives.\n'
         'After this operation, 0 B of additional disk space will be used.\n'
         'Ign:1 http://repo.example:80 ./ age 1.1.1-1\n'
         'Ign:2 http://repo.example:80 ./ python3-cryptography 41.0.7-4\n'
         'Ign:3 http://repo.example:80 ./ python3-nacl 1.5.0-4\n'
         'Ign:4 http://repo.example:80 ./ zstd 1.5.5-1\n'
         'Err:1 http://repo.example:80 ./ age 1.1.1-1\n'
         '  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'Err:2 http://repo.example:80 ./ python3-cryptography 41.0.7-4\n'
         '  Unable to connect to repo.example:80:\n'
         'Err:3 http://repo.example:80 ./ python3-nacl 1.5.0-4\n'
         '  Unable to connect to repo.example:80:\n'
         'Err:4 http://repo.example:80 ./ zstd 1.5.5-1\n'
         '  Unable to connect to repo.example:80:\n',
         'E: Failed to fetch http://repo.example:80/./age_1.1.1-1_all.deb  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'E: Failed to fetch http://repo.example:80/./python3-cryptography_41.0.7-4_all.deb  Unable to connect to repo.example:80:\n'
         'E: Failed to fetch http://repo.example:80/./python3-nacl_1.5.0-4_all.deb  Unable to connect to repo.example:80:\n'
         'E: Failed to fetch http://repo.example:80/./zstd_1.5.5-1_all.deb  Unable to connect to repo.example:80:\n'
         'E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?\n')),
    'dists-offline-old-index': (
        (0,
         'Ign:1 http://repo.example:80/ubuntu noble InRelease\n'
         'Err:1 http://repo.example:80/ubuntu noble InRelease\n'
         '  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'Reading package lists...\n',
         'W: Failed to fetch http://repo.example:80/ubuntu/dists/noble/InRelease  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'W: Some index files failed to download. They have been ignored, or old ones used instead.\n'),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n'
         'The following NEW packages will be installed:\n'
         '  age python3-cryptography python3-nacl zstd\n'
         '0 upgraded, 4 newly installed, 0 to remove and 0 not upgraded.\n'
         'Need to get 2464 B of archives.\n'
         'After this operation, 0 B of additional disk space will be used.\n'
         'Ign:1 http://repo.example:80/ubuntu noble/universe amd64 age all 1.1.1-1\n'
         'Ign:2 http://repo.example:80/ubuntu noble/main amd64 python3-cryptography all 41.0.7-4\n'
         'Ign:3 http://repo.example:80/ubuntu noble/main amd64 python3-nacl all 1.5.0-4\n'
         'Ign:4 http://repo.example:80/ubuntu noble/main amd64 zstd all 1.5.5-1\n'
         'Err:1 http://repo.example:80/ubuntu noble/universe amd64 age all 1.1.1-1\n'
         '  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'Err:2 http://repo.example:80/ubuntu noble/main amd64 python3-cryptography all 41.0.7-4\n'
         '  Unable to connect to repo.example:80:\n'
         'Err:3 http://repo.example:80/ubuntu noble/main amd64 python3-nacl all 1.5.0-4\n'
         '  Unable to connect to repo.example:80:\n'
         'Err:4 http://repo.example:80/ubuntu noble/main amd64 zstd all 1.5.5-1\n'
         '  Unable to connect to repo.example:80:\n',
         'E: Failed to fetch http://repo.example:80/ubuntu/pool/universe/age_1.1.1-1_all.deb  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'E: Failed to fetch http://repo.example:80/ubuntu/pool/main/python3-cryptography_41.0.7-4_all.deb  Unable to connect to repo.example:80:\n'
         'E: Failed to fetch http://repo.example:80/ubuntu/pool/main/python3-nacl_1.5.0-4_all.deb  Unable to connect to repo.example:80:\n'
         'E: Failed to fetch http://repo.example:80/ubuntu/pool/main/zstd_1.5.5-1_all.deb  Unable to connect to repo.example:80:\n'
         'E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?\n')),
    'proxy-407': (
        (100,
         'Ign:1 http://repo.example:80 ./ InRelease\n'
         'Ign:2 http://repo.example:80 ./ Release\n'
         'Ign:3 http://repo.example:80 ./ Packages\n'
         'Ign:4 http://repo.example:80 ./ Translation-en\n'
         'Ign:3 http://repo.example:80 ./ Packages\n'
         'Ign:4 http://repo.example:80 ./ Translation-en\n'
         'Ign:3 http://repo.example:80 ./ Packages\n'
         'Ign:4 http://repo.example:80 ./ Translation-en\n'
         'Ign:3 http://repo.example:80 ./ Packages\n'
         'Ign:4 http://repo.example:80 ./ Translation-en\n'
         'Ign:3 http://repo.example:80 ./ Packages\n'
         'Ign:4 http://repo.example:80 ./ Translation-en\n'
         'Ign:3 http://repo.example:80 ./ Packages\n'
         'Ign:4 http://repo.example:80 ./ Translation-en\n'
         'Err:3 http://repo.example:80 ./ Packages\n'
         '  407  Proxy Authentication Required [IP: 192.0.2.2 80]\n'
         'Ign:4 http://repo.example:80 ./ Translation-en\n'
         'Reading package lists...\n',
         'E: Failed to fetch http://repo.example:80/./Packages  407  Proxy Authentication Required [IP: 192.0.2.2 80]\n'
         'E: Some index files failed to download. They have been ignored, or old ones used instead.\n'),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n',
         'E: Unable to locate package age\n'
         'E: Unable to locate package zstd\n'
         'E: Unable to locate package python3-nacl\n'
         'E: Unable to locate package python3-cryptography\n')),
    'captive-portal': (
        (100,
         'Get:1 http://repo.example:80 ./ InRelease [39 B]\n'
         'Err:1 http://repo.example:80 ./ InRelease\n'
         "  Clearsigned file isn't valid, got 'NOSPLIT' (does the network require authentication?)\n"
         'Reading package lists...\n',
         "E: Failed to fetch http://repo.example:80/./InRelease  Clearsigned file isn't valid, got 'NOSPLIT' (does the network require authentication?)\n"
         "E: The repository 'http://repo.example:80 ./ InRelease' is not signed.\n"),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n',
         'E: Unable to locate package age\n'
         'E: Unable to locate package zstd\n'
         'E: Unable to locate package python3-nacl\n'
         'E: Unable to locate package python3-cryptography\n')),
    'dists-universe-off': (
        (0,
         'Ign:1 http://repo.example:80/ubuntu noble InRelease\n'
         'Get:2 http://repo.example:80/ubuntu noble Release [1056 B]\n'
         'Ign:3 http://repo.example:80/ubuntu noble Release.gpg\n'
         'Get:4 http://repo.example:80/ubuntu noble/main amd64 Packages [1463 B]\n'
         'Fetched 2519 B in 0s (115 kB/s)\n'
         'Reading package lists...\n',
         ''),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n',
         'E: Unable to locate package age\n')),
    'no-sources': (
        (0,
         'Reading package lists...\n',
         ''),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n',
         'E: Unable to locate package age\n'
         'E: Unable to locate package zstd\n'
         'E: Unable to locate package python3-nacl\n'
         'E: Unable to locate package python3-cryptography\n')),
    'third-party-404': (
        (100,
         'Ign:1 http://third.example:80/thirdparty noble InRelease\n'
         'Err:2 http://third.example:80/thirdparty noble Release\n'
         '  404  Not Found [IP: 192.0.2.2 80]\n'
         'Ign:3 http://repo.example:80 ./ InRelease\n'
         'Get:4 http://repo.example:80 ./ Release [816 B]\n'
         'Ign:5 http://repo.example:80 ./ Release.gpg\n'
         'Get:6 http://repo.example:80 ./ Packages [1438 B]\n'
         'Reading package lists...\n',
         "E: The repository 'http://third.example:80/thirdparty noble Release' does not have a Release file.\n"),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n',
         'E: Unable to locate package age\n')),
    'third-party-down': (
        (0,
         'Ign:1 http://third.example:80/thirdparty noble InRelease\n'
         'Ign:2 http://repo.example:80 ./ InRelease\n'
         'Get:3 http://repo.example:80 ./ Release [816 B]\n'
         'Ign:4 http://repo.example:80 ./ Release.gpg\n'
         'Get:5 http://repo.example:80 ./ Packages [1438 B]\n'
         'Err:1 http://third.example:80/thirdparty noble InRelease\n'
         '  Could not connect to third.example:80 (192.0.2.2). - connect (111: Connection refused)\n'
         'Fetched 2254 B in 1s (2211 B/s)\n'
         'Reading package lists...\n',
         'W: Failed to fetch http://third.example:80/thirdparty/dists/noble/InRelease  Could not connect to third.example:80 (192.0.2.2). - connect (111: Connection refused)\n'
         'W: Some index files failed to download. They have been ignored, or old ones used instead.\n'),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n',
         'E: Unable to locate package age\n')),
    'sources-unreadable': (
        (100,
         '',
         'E: Malformed entry 1 in list file <root>/etc/sources.list.d/broken.list (Suite)\n'
         'E: The list of sources could not be read.\n'),
        (100,
         '',
         'E: Malformed entry 1 in list file <root>/etc/sources.list.d/broken.list (Suite)\n'
         'E: The list of sources could not be read.\n')),
    'signature-no-key': (
        (100,
         'Get:1 http://repo.example:80 ./ InRelease [1020 B]\n'
         'Err:1 http://repo.example:80 ./ InRelease\n'
         "  The following signatures couldn't be verified because the public key is not available: NO_PUBKEY 0000000000000000\n"
         'Reading package lists...\n',
         "W: GPG error: http://repo.example:80 ./ InRelease: The following signatures couldn't be verified because the public key is not available: NO_PUBKEY 0000000000000000\n"
         "E: The repository 'http://repo.example:80 ./ InRelease' is not signed.\n"),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n',
         'E: Unable to locate package age\n'
         'E: Unable to locate package zstd\n'
         'E: Unable to locate package python3-nacl\n'
         'E: Unable to locate package python3-cryptography\n')),
    'release-expired': (
        (100,
         'Get:1 http://repo.example:80 ./ InRelease [1063 B]\n'
         'Reading package lists...\n',
         'E: Release file for http://repo.example:80/./InRelease is expired (invalid since 1059d 2h 20min 28s). Updates for this repository will not be applied.\n'),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n',
         'E: Unable to locate package age\n'
         'E: Unable to locate package zstd\n'
         'E: Unable to locate package python3-nacl\n'
         'E: Unable to locate package python3-cryptography\n')),
    'dists-release-expired': (
        (100,
         'Get:1 http://repo.example:80/ubuntu noble InRelease [1636 B]\n'
         'Reading package lists...\n',
         'E: Release file for http://repo.example:80/ubuntu/dists/noble/InRelease is expired (invalid since 1059d 2h 33min 31s). Updates for this repository will not be applied.\n'),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n',
         'E: Unable to locate package age\n'
         'E: Unable to locate package zstd\n'
         'E: Unable to locate package python3-nacl\n'
         'E: Unable to locate package python3-cryptography\n')),
    'dists-release-not-valid-yet': (
        (100,
         'Get:1 http://repo.example:80/ubuntu noble InRelease [1591 B]\n'
         'Reading package lists...\n',
         'E: Release file for http://repo.example:80/ubuntu/dists/noble/InRelease is not valid yet (invalid for another 1497d 21h 38min 58s). Updates for this repository will not be applied.\n'),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n',
         'E: Unable to locate package age\n'
         'E: Unable to locate package zstd\n'
         'E: Unable to locate package python3-nacl\n'
         'E: Unable to locate package python3-cryptography\n')),
    'unsigned-source': (
        (100,
         'Ign:1 http://repo.example:80 ./ InRelease\n'
         'Get:2 http://repo.example:80 ./ Release [483 B]\n'
         'Ign:3 http://repo.example:80 ./ Release.gpg\n'
         'Reading package lists...\n',
         "E: The repository 'http://repo.example:80 ./ Release' is not signed.\n"),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n',
         'E: Unable to locate package age\n'
         'E: Unable to locate package zstd\n'
         'E: Unable to locate package python3-nacl\n'
         'E: Unable to locate package python3-cryptography\n')),
    'locked': (
        (100,
         'Reading package lists...\n',
         'E: Could not get lock <root>/lists/lock. It is held by process 606600 (python3)\n'
         'E: Unable to lock directory <root>/lists/\n'),
        (100,
         'Waiting for cache lock: Could not get lock <root>/dpkg/lock-frontend. It is held by process 606604 (python3)...\n'
         'Waiting for cache lock: Could not get lock <root>/dpkg/lock-frontend. It is held by process 606604 (python3)...\n',
         'E: Unable to acquire the dpkg frontend lock (<root>/dpkg/lock-frontend), is another process using it?\n')),
    'package-gone': (
        (0,
         'Ign:1 http://repo.example:80 ./ InRelease\n'
         'Hit:2 http://repo.example:80 ./ Release\n'
         'Ign:3 http://repo.example:80 ./ Release.gpg\n'
         'Reading package lists...\n',
         ''),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n'
         'The following NEW packages will be installed:\n'
         '  age python3-cryptography python3-nacl zstd\n'
         '0 upgraded, 4 newly installed, 0 to remove and 0 not upgraded.\n'
         'Need to get 2472 B of archives.\n'
         'After this operation, 0 B of additional disk space will be used.\n'
         'Err:1 http://repo.example:80 ./ age 1.1.1-1\n'
         '  404  File not found [IP: 192.0.2.1 80]\n'
         'Err:2 http://repo.example:80 ./ python3-cryptography 41.0.7-4\n'
         '  404  File not found [IP: 192.0.2.1 80]\n'
         'Err:3 http://repo.example:80 ./ python3-nacl 1.5.0-4\n'
         '  404  File not found [IP: 192.0.2.1 80]\n'
         'Err:4 http://repo.example:80 ./ zstd 1.5.5-1\n'
         '  404  File not found [IP: 192.0.2.1 80]\n',
         'E: Failed to fetch http://repo.example:80/./age_1.1.1-1_all.deb  404  File not found [IP: 192.0.2.1 80]\n'
         'E: Failed to fetch http://repo.example:80/./python3-cryptography_41.0.7-4_all.deb  404  File not found [IP: 192.0.2.1 80]\n'
         'E: Failed to fetch http://repo.example:80/./python3-nacl_1.5.0-4_all.deb  404  File not found [IP: 192.0.2.1 80]\n'
         'E: Failed to fetch http://repo.example:80/./zstd_1.5.5-1_all.deb  404  File not found [IP: 192.0.2.1 80]\n'
         'E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?\n')),
    'disk-full': (
        (0,
         'Ign:1 http://repo.example:80 ./ InRelease\n'
         'Get:2 http://repo.example:80 ./ Release [483 B]\n'
         'Ign:3 http://repo.example:80 ./ Release.gpg\n'
         'Get:4 http://repo.example:80 ./ Packages [1943 B]\n'
         'Fetched 2426 B in 0s (124 kB/s)\n'
         'Reading package lists...\n',
         ''),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n'
         'The following NEW packages will be installed:\n'
         '  age python3-cryptography python3-nacl zstd\n'
         '0 upgraded, 4 newly installed, 0 to remove and 0 not upgraded.\n'
         'Need to get 4000 TB of archives.\n'
         'After this operation, 0 B of additional disk space will be used.\n',
         "E: You don't have enough free space in <root>/cache/archives/.\n")),
    'dpkg-interrupted': (
        (0,
         'Ign:1 http://repo.example:80 ./ InRelease\n'
         'Get:2 http://repo.example:80 ./ Release [483 B]\n'
         'Ign:3 http://repo.example:80 ./ Release.gpg\n'
         'Get:4 http://repo.example:80 ./ Packages [1891 B]\n'
         'Fetched 2374 B in 0s (47.3 kB/s)\n'
         'Reading package lists...\n',
         ''),
        (100,
         '',
         "E: dpkg was interrupted, you must manually run 'dpkg --configure -a' to correct the problem. \n")),
    'held': (
        (0,
         'Ign:1 http://repo.example:80 ./ InRelease\n'
         'Get:2 http://repo.example:80 ./ Release [483 B]\n'
         'Ign:3 http://repo.example:80 ./ Release.gpg\n'
         'Get:4 http://repo.example:80 ./ Packages [1891 B]\n'
         'Fetched 2374 B in 0s (36.8 kB/s)\n'
         'Reading package lists...\n',
         ''),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n'
         'The following NEW packages will be installed:\n'
         '  python3-cryptography python3-nacl zstd\n'
         'The following held packages will be changed:\n'
         '  age\n'
         'The following packages will be upgraded:\n'
         '  age\n'
         '1 upgraded, 3 newly installed, 0 to remove and 0 not upgraded.\n',
         'E: Held packages were changed and -y was used without --allow-change-held-packages.\n')),
    'conflict': (
        (0,
         'Ign:1 http://repo.example:80 ./ InRelease\n'
         'Get:2 http://repo.example:80 ./ Release [483 B]\n'
         'Ign:3 http://repo.example:80 ./ Release.gpg\n'
         'Get:4 http://repo.example:80 ./ Packages [1907 B]\n'
         'Fetched 2390 B in 0s (51.9 kB/s)\n'
         'Reading package lists...\n',
         ''),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n'
         'Some packages could not be installed. This may mean that you have\n'
         'requested an impossible situation or if you are using the unstable\n'
         'distribution that some required packages have not yet been created\n'
         'or been moved out of Incoming.\n'
         'The following information may help to resolve the situation:\n'
         '\n'
         'The following packages have unmet dependencies:\n'
         ' age : Conflicts: zstd but 1.5.5-1 is to be installed\n',
         'E: Unable to correct problems, you have held broken packages.\n')),
    'unmet-dependencies': (
        (0,
         'Ign:1 http://repo.example:80 ./ InRelease\n'
         'Get:2 http://repo.example:80 ./ Release [483 B]\n'
         'Ign:3 http://repo.example:80 ./ Release.gpg\n'
         'Get:4 http://repo.example:80 ./ Packages [1923 B]\n'
         'Fetched 2406 B in 0s (26.4 kB/s)\n'
         'Reading package lists...\n',
         ''),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n'
         'Some packages could not be installed. This may mean that you have\n'
         'requested an impossible situation or if you are using the unstable\n'
         'distribution that some required packages have not yet been created\n'
         'or been moved out of Incoming.\n'
         'The following information may help to resolve the situation:\n'
         '\n'
         'The following packages have unmet dependencies:\n'
         ' age : Depends: woowbk-no-such-library but it is not installable\n',
         'E: Unable to correct problems, you have held broken packages.\n')),
    'dpkg-fails': (
        (0,
         'Ign:1 http://repo.example:80 ./ InRelease\n'
         'Get:2 http://repo.example:80 ./ Release [483 B]\n'
         'Ign:3 http://repo.example:80 ./ Release.gpg\n'
         'Get:4 http://repo.example:80 ./ Packages [1891 B]\n'
         'Fetched 2374 B in 0s (42.9 kB/s)\n'
         'Reading package lists...\n',
         ''),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n'
         'The following NEW packages will be installed:\n'
         '  age python3-cryptography python3-nacl zstd\n'
         '0 upgraded, 4 newly installed, 0 to remove and 0 not upgraded.\n'
         'Need to get 2470 B of archives.\n'
         'After this operation, 0 B of additional disk space will be used.\n'
         'Get:1 http://repo.example:80 ./ age 1.1.1-1 [604 B]\n'
         'Get:2 http://repo.example:80 ./ python3-cryptography 41.0.7-4 [634 B]\n'
         'Get:3 http://repo.example:80 ./ python3-nacl 1.5.0-4 [622 B]\n'
         'Get:4 http://repo.example:80 ./ zstd 1.5.5-1 [610 B]\n'
         'Fetched 2470 B in 0s (84.6 kB/s)\n',
         'E: Sub-process <root>/dpkg-stub returned an error code (1)\n')),
    'damaged-offline-no-index': (
        (0,
         'Ign:1 http://repo.example:80/ubuntu ./ InRelease\n'
         'Err:1 http://repo.example:80/ubuntu ./ InRelease\n'
         '  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'Reading package lists...\n',
         'W: Failed to fetch http://repo.example:80/ubuntu/./InRelease  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'W: Some index files failed to download. They have been ignored, or old ones used instead.\n'),
        (0,
         'Reading package lists...\n'
         'Building dependency tree...\n'
         'Reinstallation of age is not possible, it cannot be downloaded.\n'
         'Reinstallation of zstd is not possible, it cannot be downloaded.\n'
         'Reinstallation of python3-nacl is not possible, it cannot be downloaded.\n'
         'Reinstallation of python3-cryptography is not possible, it cannot be downloaded.\n'
         '0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n',
         '')),
    'damaged-offline-old-index': (
        (0,
         'Ign:1 http://repo.example:80 ./ InRelease\n'
         'Err:1 http://repo.example:80 ./ InRelease\n'
         '  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'Reading package lists...\n',
         'W: Failed to fetch http://repo.example:80/./InRelease  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'W: Some index files failed to download. They have been ignored, or old ones used instead.\n'),
        (100,
         'Reading package lists...\n'
         'Building dependency tree...\n'
         '0 upgraded, 0 newly installed, 4 reinstalled, 0 to remove and 0 not upgraded.\n'
         'Need to get 2470 B of archives.\n'
         'After this operation, 0 B of additional disk space will be used.\n'
         'Ign:1 http://repo.example:80 ./ age 1.1.1-1\n'
         'Ign:2 http://repo.example:80 ./ python3-cryptography 41.0.7-4\n'
         'Ign:3 http://repo.example:80 ./ python3-nacl 1.5.0-4\n'
         'Ign:4 http://repo.example:80 ./ zstd 1.5.5-1\n'
         'Err:1 http://repo.example:80 ./ age 1.1.1-1\n'
         '  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'Err:2 http://repo.example:80 ./ python3-cryptography 41.0.7-4\n'
         '  Unable to connect to repo.example:80:\n'
         'Err:3 http://repo.example:80 ./ python3-nacl 1.5.0-4\n'
         '  Unable to connect to repo.example:80:\n'
         'Err:4 http://repo.example:80 ./ zstd 1.5.5-1\n'
         '  Unable to connect to repo.example:80:\n',
         'E: Failed to fetch http://repo.example:80/./age_1.1.1-1_all.deb  Could not connect to repo.example:80 (192.0.2.1). - connect (111: Connection refused)\n'
         'E: Failed to fetch http://repo.example:80/./python3-cryptography_41.0.7-4_all.deb  Unable to connect to repo.example:80:\n'
         'E: Failed to fetch http://repo.example:80/./python3-nacl_1.5.0-4_all.deb  Unable to connect to repo.example:80:\n'
         'E: Failed to fetch http://repo.example:80/./zstd_1.5.5-1_all.deb  Unable to connect to repo.example:80:\n'
         'E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?\n')),
}


class FakeHost:
    """The device behind `manage.HostTools` (its runner): the tools that do not work and what apt-get does about it.
    `adds`: the packages apt can add; `update` and `install`: (exit code, stdout, stderr) of the two apt-get runs;
    `seen(argv)`: called before apt-get acts (another package job may change files meanwhile)."""

    def __init__(self, broken=(), *, adds=manage.TOOL_PACKAGES, update=(0, '', ''), install=(0, '', ''),
                 seen=lambda argv: None):
        self.broken, self.adds, self.update, self.install, self.seen = set(broken), set(adds), update, install, seen
        self.apt = []

    def __call__(self, argv):
        if argv[0] != manage.APT_GET:
            tool = next(tool for tool, _package, probe in manage.HOST_TOOLS if list(probe) == argv)
            return (127 if tool in self.broken else 0), '', ''
        self.seen(argv)
        self.apt.append(argv)
        if argv == list(manage.APT_UPDATE):
            return self.update
        wanted = set(argv[len(manage.APT_INSTALL):])
        assert wanted and wanted <= set(manage.TOOL_PACKAGES), argv
        self.broken -= {tool for tool, package, _probe in manage.HOST_TOOLS if package in wanted & self.adds}
        return self.install


ALL_TOOLS = tuple(tool for tool, _package, _probe in manage.HOST_TOOLS)


def recorded(case, **options):
    """A device whose tools are all missing and whose apt-get answers as it did in APT_RECORDED[case]."""
    update, install = APT_RECORDED[case]
    return FakeHost(ALL_TOOLS, adds=(), update=update, install=install, **options)


class HostToolsContract(HostFixture):
    """Rows KEY-14, KEY-15, X-AR-06 and X-KEY-02 of the HA import (on HAOS the tools are simply there): the packages the
    backup engine needs come with it. An install on the live root adds missing ones with apt before it changes a file;
    when that does not work it goes on all the same and says what is missing, why and what does not work meanwhile (an
    offline device is not refused its update); plan and status report them; --no-backup and --root run nothing. Without
    its tools the engine itself still stops."""

    # row: (the tool that does not work, the package that brings it)
    ROWS = {'KEY-14': ('python3-nacl', 'python3-nacl'), 'KEY-15': ('python3-cryptography', 'python3-cryptography'),
            'X-AR-06 age': ('age', 'age'), 'X-AR-06 zstd': ('zstd', 'zstd'), 'X-KEY-02': ('age-keygen', 'age')}
    # recorded case -> what the reason in the notice must say (the sentence of manage.py, or parts of it)
    REASONS = {
        'offline-no-index': [manage.OFFLINE], 'offline-dns': [manage.OFFLINE], 'offline-old-index': [manage.OFFLINE],
        'dists-offline-old-index': [manage.OFFLINE], 'proxy-407': [manage.OFFLINE], 'captive-portal': [manage.OFFLINE],
        'damaged-offline-no-index': [manage.OFFLINE], 'damaged-offline-old-index': [manage.OFFLINE],
        'dists-universe-off': ['這台啟用的套件來源沒有 age', 'sudo add-apt-repository universe'],
        'no-sources': ['這台啟用的套件來源沒有 age、zstd、python3-nacl、python3-cryptography', 'main 與 universe 都要啟用'],
        'third-party-404': ['有套件來源無法更新（網址不存在），其他來源沒有 age', '也請確認已啟用 universe'],
        'third-party-down': ['有套件來源無法更新（連不上），其他來源沒有 age', '也請確認已啟用 universe'],
        'sources-unreadable': ['套件來源的設定檔有錯', 'sources.list.d'],
        'signature-no-key': [manage.SIGNATURE], 'release-expired': [manage.SIGNATURE],
        'dists-release-expired': [manage.SIGNATURE], 'dists-release-not-valid-yet': [manage.SIGNATURE],
        'unsigned-source': [manage.SIGNATURE],
        'locked': ['另一個套件作業（例如系統自動更新）正在進行'], 'package-gone': [manage.GONE],
        'disk-full': ['磁碟空間不足'], 'dpkg-interrupted': ['sudo dpkg --configure -a'],
        'held': ['套件被鎖定（apt-mark hold）'], 'conflict': [manage.CONFLICT_REASON],
        'unmet-dependencies': ['相依的套件湊不齊'], 'dpkg-fails': ['原因不明（apt-get 結束碼 100）'],
    }
    add_source = BackupPackageContract.add_source
    add_backup_source = BackupPackageContract.add_backup_source
    tree = BackupPackageContract.tree

    def setUp(self):
        super().setUp()
        self.add_backup_source()

    def reset(self):
        """The device as it was before any install (a fresh one for the next case of a loop)."""
        shutil.rmtree(self.root)
        for name, (data, file_mode) in self.original.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(file_mode)

    def live(self, host, systemctl=None, **options):
        """An install as on the live root (what main() does): `host` answers for the tools, `systemctl` for the timer;
        the plan is made again after the packages step."""
        desired, state = manage.desired_files(self.root, **options)
        self.notes = io.StringIO()
        with contextlib.redirect_stderr(self.notes):
            return manage.install_with_tools(self.root, desired, state, lambda: manage.desired_files(self.root, **options),
                                             systemd=manage.Systemd(systemctl) if systemctl else None,
                                             tools=manage.HostTools(host))

    def main(self, *args, host=None):
        """manage.main() on the fixture root: (exit code, its JSON, stderr); `host` answers for the tools."""
        out, err = io.StringIO(), io.StringIO()
        tools = (lambda root, engine, tools=None: manage.HostTools(host) if engine else None) if host else manage.engine_tools
        with (patch.object(sys, 'argv', ['manage.py', '--root', str(self.root), *args]),
              patch.object(manage, 'engine_tools', tools),
              contextlib.redirect_stdout(out), contextlib.redirect_stderr(err)):
            code = manage.main()
        return code, json.loads(out.getvalue()), err.getvalue()

    def test_the_installer_the_bootstrap_and_the_engine_mean_the_same_tools(self):
        bootstrap = (REPO / 'scripts/bootstrap-ubuntu.sh').read_text()
        self.assertEqual([tuple(words.split()) for words in re.findall(r'(?m)^backup_packages=\((.*)\)$', bootstrap)],
                         [manage.TOOL_PACKAGES])
        self.assertEqual({(tool, package) for tool, package, _probe in manage.HOST_TOOLS}, set(self.ROWS.values()))
        # Probed where the engine looks for a program and with the interpreter of its helper.
        engine = REPO / 'backup-engine/woowbackup'
        source = ''.join(path.read_text() for path in sorted(engine.rglob('*.py')))
        self.assertIn(f"SAFE_PATH = '{manage.TOOL_ENV['PATH']}'\n", (engine / 'util.py').read_text())
        self.assertEqual(set(re.findall(r"find_tool\('([^']+)'\)", source)),
                         {probe[0] for _tool, _package, probe in manage.HOST_TOOLS if not probe[0].startswith('/')})
        self.assertEqual(manage.HELPER_SHEBANG.decode(), f'#!{" ".join(manage.PROBE[:2])}\n')
        for module in ('nacl import bindings', 'nacl.pwhash import argon2id',
                       'cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes'):
            self.assertIn(f'from {module}\n', source)
            self.assertEqual(sum(module in probe[-1] for _tool, _package, probe in manage.HOST_TOOLS), 1, module)

    # What each Python probe needs from its package: (file, the name defined there). The stand-in tree is complete or lacks one.
    STAND_IN = {
        'python3-nacl': {
            'nacl/__init__.py': '', 'nacl/bindings.py': 'crypto_secretstream_xchacha20poly1305_init_pull = 1\n',
            'nacl/exceptions.py': 'class CryptoError(Exception): pass\n', 'nacl/pwhash/__init__.py': '',
            'nacl/pwhash/argon2id.py': 'def kdf(*args): pass\n'},
        'python3-cryptography': {
            'cryptography/__init__.py': '', 'cryptography/hazmat/__init__.py': '',
            'cryptography/hazmat/primitives/__init__.py': '',
            'cryptography/hazmat/primitives/ciphers/__init__.py': (
                'class Cipher:\n    def __init__(self, algorithm, mode): pass\n    def decryptor(self): return self\n'
                '    def update(self, data):\n        open(__file__ + ".used", "w").close()\n        return data\n'
                'class algorithms:\n    AES = staticmethod(lambda key: key)\n'
                'class modes:\n    CBC = staticmethod(lambda iv: iv)\n')},
    }
    STAND_IN_NAMES = {
        'python3-nacl': (('nacl/bindings.py', 'crypto_secretstream_xchacha20poly1305_init_pull'),
                         ('nacl/exceptions.py', 'CryptoError'), ('nacl/pwhash/argon2id.py', 'kdf')),
        'python3-cryptography': (('cryptography/hazmat/primitives/ciphers/__init__.py', 'Cipher'),
                                 ('cryptography/hazmat/primitives/ciphers/__init__.py', 'algorithms'),
                                 ('cryptography/hazmat/primitives/ciphers/__init__.py', 'modes')),
    }

    def run_probe(self, probe, files):
        """The probe code, run by an isolated interpreter (-I), with a package tree made of `files` in front."""
        with tempfile.TemporaryDirectory() as directory:
            for name, text in files.items():
                path = Path(directory) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            code = f'import sys; sys.path.insert(0, {directory!r}); {probe[-1]}'
            returncode = subprocess.run([sys.executable, '-I', '-B', '-c', code], capture_output=True).returncode
            self.used = sorted(str(path.relative_to(Path(directory) / 'cryptography/hazmat/primitives'))
                               for path in Path(directory).rglob('*.used'))
            return returncode

    def test_the_probes_really_run_and_every_name_they_use_counts(self):
        """Not through a stand-in runner: a misspelled import or name in a probe fails here (KEY-14, KEY-15, X-KEY-02)."""
        for tool, package, probe in manage.HOST_TOOLS:
            with self.subTest(tool=tool, where='this machine'):
                if probe[0].startswith('/'):
                    module = {'python3-nacl': 'nacl', 'python3-cryptography': 'cryptography'}[package]
                    present = subprocess.run([*manage.PROBE, f'import {module}'], capture_output=True).returncode == 0
                else:
                    present = shutil.which(probe[0], path=manage.TOOL_ENV['PATH']) is not None
                if not present:
                    self.skipTest(f'{tool} is not installed on this machine')
                self.assertEqual(manage.run_tool(list(probe))[0], 0)
        # On every machine: a complete stand-in for the package passes the probe, and each name the probe uses is needed.
        for tool, package, probe in manage.HOST_TOOLS:
            if not probe[0].startswith('/'):
                continue
            with self.subTest(tool=tool, stand_in='complete'):
                self.assertEqual(self.run_probe(probe, self.STAND_IN[package]), 0)
                if package == 'python3-cryptography':  # it does what the engine does: a decryptor that works
                    self.assertEqual(self.used, ['ciphers/__init__.py.used'])
            for module, name in self.STAND_IN_NAMES[package]:
                with self.subTest(tool=tool, without=name):
                    files = dict(self.STAND_IN[package])
                    renamed = re.sub(rf'\b{name}\b', f'{name}_gone', files[module])
                    self.assertNotEqual(renamed, files[module])
                    files[module] = renamed
                    self.assertNotEqual(self.run_probe(probe, files), 0)
        # A program that is not there, or does not answer, does not work (X-KEY-02).
        self.assertEqual(manage.run_fixed(['woowbk-no-such-program'])[0], 127)
        self.assertEqual(manage.run_fixed(['/bin/sleep', '30'], timeout=0.2)[0], 127)

    def test_with_every_tool_working_nothing_runs_and_nothing_is_reported(self):
        host = FakeHost()
        for status in ('installed', 'already-current'):
            result = self.live(host)
            self.assertEqual((result['status'], host.apt, self.notes.getvalue()), (status, [], ''))
            for key in ('packages', 'missing_packages', 'notices'):
                self.assertNotIn(key, result)

    def test_a_missing_package_is_added_before_a_file_changes(self):
        for number, (row, (tool, package)) in enumerate(self.ROWS.items()):
            with self.subTest(row=row):
                self.add_source({'backup-engine/woowbackup/cli.py': f'VERSION = {number}\n'})
                before, at_apt = self.tree(''), []
                host = FakeHost({tool}, seen=lambda argv, at=at_apt: at.append(self.tree('')))
                result = self.live(host)
                self.assertEqual((result['status'], result['packages']), ('installed', [package]))
                self.assertEqual(host.apt, [list(manage.APT_UPDATE), [*manage.APT_INSTALL, package]])
                self.assertEqual(at_apt, [before, before], 'apt-get runs before anything changes')
                self.assertIn(f'備份與還原需要的套件沒有裝好：{package}。正在用 apt 自動補裝', self.notes.getvalue())
                self.assertEqual((self.root / manage.BACKUP_ENGINE / 'cli.py').read_text(), f'VERSION = {number}\n')
                for key in ('missing_packages', 'notices'):
                    self.assertNotIn(key, result)
                # Removed later (e.g. apt autoremove): installing again adds it, with no file to change.
                host.broken.add(tool)
                host.apt.clear()
                result = self.live(host)
                self.assertEqual((result['status'], result['changed'], result['packages']),
                                 ('already-current', 0, [package]))
                self.assertEqual(host.apt, [list(manage.APT_UPDATE), [*manage.APT_INSTALL, package]])
                host.apt.clear()
                self.assertNotIn('packages', self.live(host))
                self.assertEqual(host.apt, [], 'idempotent')

    def test_every_missing_package_goes_into_one_apt_run(self):
        host = FakeHost(ALL_TOOLS)
        self.assertEqual(self.live(host)['packages'], ['age', 'zstd', 'python3-nacl', 'python3-cryptography'])
        self.assertEqual(host.apt, [list(manage.APT_UPDATE), [*manage.APT_INSTALL, *manage.TOOL_PACKAGES]])

    def test_an_install_that_cannot_add_them_goes_on_and_says_what_is_missing(self):
        """No refusal because of the environment (decision of 2026-11-25): an offline device is updated all the same."""
        self.assertEqual(set(self.REASONS), set(APT_RECORDED), 'every recorded case has an expectation')
        names = '、'.join(manage.TOOL_PACKAGES)
        for number, case in enumerate(APT_RECORDED):
            with self.subTest(case=case):
                self.reset()
                self.add_source({'backup-engine/woowbackup/cli.py': f'VERSION = {number}\n'})
                host, systemctl = recorded(case), FakeSystemctl(self.root)
                result = self.live(host, systemctl)
                self.assertEqual(result['status'], 'installed')
                self.assertEqual((self.root / manage.BACKUP_ENGINE / 'cli.py').read_text(), f'VERSION = {number}\n')
                self.assertEqual(systemctl.calls, ['daemon-reload', f'enable --now {manage.SCHEDULE_TIMER}'],
                                 'the rest of the update is done, the schedule timer included')
                self.assertEqual((result['packages'], result['missing_packages']), ([], list(manage.TOOL_PACKAGES)))
                self.assertEqual(len(result['notices']), 1)
                notice = result['notices'][0]
                self.assertIn(f'備份與還原需要的套件沒有裝好：{names}。自動補裝沒有成功：', notice)
                for reason in self.REASONS[case]:
                    self.assertIn(reason, notice)
                for part in ('更新照常進行，裝好之前：缺 age、zstd 不能建立、檢查與還原加密的備份（預設的備份都是加密的',
                             '缺 age 不能建立與檢查加密金鑰', '缺 python3-nacl 不能讀取 2026 年 3 月以後的 HA 加密備份',
                             '缺 python3-cryptography 不能讀取 2026 年 3 月以前的 HA 加密備份',
                             'sudo python3 scripts/manage.py install', '.deb',
                             f'sudo apt-get install {" ".join(manage.TOOL_PACKAGES)}', 'sudo python3 scripts/manage.py status'):
                    self.assertIn(part, notice)
                self.assertIn(f'Note: {notice}', self.notes.getvalue())
                self.assertEqual(host.apt, [list(manage.APT_UPDATE), [*manage.APT_INSTALL, *manage.TOOL_PACKAGES]])
                # What is missing is not forgotten: status says it.
                status = manage.status(self.root, tools=manage.HostTools(host))
                self.assertEqual((status['status'], status['packages']), ('tools-missing', list(manage.TOOL_PACKAGES)))
        # The same files as on a device that has the tools.
        self.reset()
        self.live(recorded('offline-no-index'))
        offline = self.snapshot()
        self.reset()
        self.live(FakeHost())
        self.assertEqual(offline, self.snapshot())

    def test_the_reason_is_told_from_what_the_real_apt_wrote(self):
        self.assertEqual(set(self.REASONS), set(APT_RECORDED))
        for case, (update, install) in APT_RECORDED.items():
            with self.subTest(case=case):
                reason = manage.apt_reason(update, install, list(manage.TOOL_PACKAGES))
                for part in self.REASONS[case]:
                    self.assertIn(part, reason)
        # Only some of the packages are missing: the reason names what apt could not find.
        update, install = APT_RECORDED['dists-universe-off']
        self.assertIn('沒有 age', manage.apt_reason(update, install, ['age']))
        self.assertIn('沒有 age', manage.apt_reason(update, install, ['age', 'zstd']))
        self.assertIn('沒有 zstd', manage.apt_reason(update, (100, '', 'E: Unable to locate package zstd\n'), ['zstd']))

    def test_what_apt_wrote_is_never_shown(self):
        for case, (update, install) in APT_RECORDED.items():
            with self.subTest(case=case):
                notice = self.live_notice(recorded(case))
                apt_lines = [line for stream in (*update[1:], *install[1:]) for line in stream.splitlines()]
                for line in apt_lines:
                    if len(line) > 10:
                        self.assertNotIn(line.strip(), notice)
                for part in ('repo.example', 'third.example', '192.0.2', 'no-such-host', 'http', 'E:', 'W:', 'N:', 'Err:', '<root>'):
                    self.assertNotIn(part, notice)

    def live_notice(self, host):
        self.reset()
        return self.live(host)['notices'][0]

    def test_what_is_not_proven_is_called_unknown_with_the_exit_code(self):
        missing = [100, '', 'E: Unable to locate package age\n']
        cases = (  # (update, install, left, what the reason says)
            ((100, '', 'E: something odd\n'), tuple(missing), ['age'], '原因不明（apt-get update 結束碼 100）'),
            ((0, '', ''), (100, '', 'E: something odd\n'), ['zstd'], '原因不明（apt-get 結束碼 100）'),
            ((0, '', ''), (0, '', ''), ['zstd'], manage.BROKEN_TOOL),
            ((127, '', 'OSError'), (127, '', 'OSError'), ['zstd'], manage.NO_APT),
            # Several sources, each with its own problem: all of them are named.
            ((100, 'Err:1 http://a.example/ubuntu noble InRelease\n  Could not resolve \'a.example\'\n'
                   'Err:2 http://b.example/extra noble Release\n  404  Not Found [IP: 192.0.2.9 80]\n', ''),
             tuple(missing), ['age'], '套件來源都無法更新（連不上、網址不存在）'),
            ((0, 'Err:1 http://a.example/ubuntu noble InRelease\n  Hash Sum mismatch\n', ''), tuple(missing), ['age'],
             '套件來源都無法更新（索引和檔案對不上）'),
            # Only stderr says why a download failed (no Err lines in the progress).
            ((0, '', ''), (100, '', 'E: Failed to fetch http://a.example/x/age.deb  Could not resolve \'a.example\'\n'
                           'E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?\n'),
             ['age'], manage.OFFLINE),
            # A download that ends on a mirror that is being synchronised.
            ((0, '', ''), (100, 'Err:1 http://a.example/ubuntu noble/main amd64 age 1.1.1\n  Hash Sum mismatch\n',
                           'E: Failed to fetch http://a.example/ubuntu/pool/age.deb  Hash Sum mismatch\n'), ['age'], manage.GONE),
            # A hash problem and a lost connection together: not enough to say which one it is.
            ((0, '', ''), (100, 'Err:1 http://a.example/x noble/main amd64 age 1.1.1\n  Hash Sum mismatch\n'
                           'Err:2 http://a.example/x noble/main amd64 zstd 1.5\n  Could not resolve \'a.example\'\n', ''),
             ['age', 'zstd'], '原因不明（apt-get 結束碼 100）'),
        )
        for number, (update, install, left, reason) in enumerate(cases):
            with self.subTest(number=number):
                self.assertIn(reason, manage.apt_reason(update, install, left))

    def test_texts_of_apt_that_were_not_provoked_are_told_from_its_catalogue(self):
        """Synthetic, one line each: messages of apt's own catalogue (libapt-pkg, libc) that no recording has."""
        fine, source = (0, '', ''), 'http://a.example/ubuntu noble/main amd64 age 1.1.1'

        def download(why):  # a download that failed: its Err line of the progress and the line of stderr
            return 100, f'Err:1 {source}\n  {why}\n', f'E: Failed to fetch http://a.example/pool/age.deb  {why}\n'

        def lists(*lines, code=100):  # what apt-get update says only on stderr, about a source it did fetch from
            return (code, 'Get:1 http://a.example/ubuntu noble InRelease [1 kB]\n', ''.join(f'{line}\n' for line in lines))

        missing = (100, '', 'E: Unable to locate package age\n')
        cases = (  # (update, install, what the reason holds)
            (fine, (100, '', 'E: Could not get lock /var/lib/dpkg/lock. It is held by process 42 (apt)\n'), '另一個套件作業'),
            (fine, (100, '', 'E: Write error - write (28: No space left on device)\n'), '磁碟空間不足'),
            (fine, (100, '', 'E: Packages need to be removed but remove is disabled.\n'), '要先移除別的套件'),
            (fine, (100, '', "E: Unmet dependencies. Try 'apt --fix-broken install' with no packages (or specify a solution).\n"),
             '相依的套件湊不齊'),
            (fine, (100, ' age : Breaks: zstd (< 2) but 1.5.5 is to be installed\n', ''), manage.CONFLICT_REASON),
            (fine, download("Temporary failure resolving 'a.example'"), manage.OFFLINE),
            (fine, download("Something wicked happened resolving 'a.example:80' (-5 - No address associated with hostname)"),
             manage.OFFLINE),
            (fine, download('Cannot initiate the connection to a.example:80 (192.0.2.1). - connect (101: Network is unreachable)'),
             manage.OFFLINE),
            (fine, download('Could not connect to a.example:80 (192.0.2.1), connection timed out'), manage.OFFLINE),
            (fine, download('Connection timed out [IP: 192.0.2.1 80]'), manage.OFFLINE),
            (fine, download('Cannot initiate the connection to a.example:80 (192.0.2.1).'), manage.OFFLINE),
            (fine, download('Connection failed [IP: 192.0.2.1 80]'), manage.OFFLINE),
            (fine, download('Connection reset by peer'), manage.OFFLINE),
            (fine, download('Could not connect to a.example:80 (192.0.2.1). - connect (113: No route to host)'), manage.OFFLINE),
            # Other transports (a libcurl one) say it in their own words.
            (fine, download('Failed to connect to a.example port 443: Network is unreachable'), manage.OFFLINE),
            (fine, download('Failed to connect to a.example port 443: No route to host'), manage.OFFLINE),
            (fine, download('407  Proxy Authentication Required [IP: 192.0.2.1 80]'), manage.OFFLINE),
            (fine, download('410  Gone [IP: 192.0.2.1 80]'), manage.GONE),
            (fine, download('File has unexpected size (10 != 20). Mirror sync in progress? [IP: 192.0.2.1 80]'), manage.GONE),
            (fine, download('Hash Sum mismatch'), manage.GONE),
            (fine, (100, '', "E: Package 'age' has no installation candidate\n"), '這台啟用的套件來源沒有 age'),
            # What update says only on stderr about a source: each kind of text, and a text of no kind at all.
            (lists("E: The repository 'http://a.example/ubuntu noble InRelease' is no longer signed."), missing, manage.SIGNATURE),
            (lists("W: GPG error: http://a.example/ubuntu noble InRelease: something about the key"), missing, manage.SIGNATURE),
            (lists("E: Release file for http://a.example/ubuntu/dists/noble/InRelease is not valid yet (invalid for another 1d)."),
             missing, manage.SIGNATURE),
            (lists("E: Failed to fetch http://a.example/ubuntu/dists/noble/InRelease  403  Forbidden [IP: 192.0.2.1 80]"),
             missing, '套件來源都無法更新（其他錯誤）'),
            (lists("W: Skipping acquire of configured file 'universe/binary-amd64/Packages' as repository "
                   "'http://a.example/ubuntu noble InRelease' doesn't have the component 'universe'", code=0),
             missing, '這台啟用的套件來源沒有 age'),
        )
        for number, (update, install, reason) in enumerate(cases):
            with self.subTest(number=number, install=install[2][:60] or install[1][:60]):
                self.assertIn(reason, manage.apt_reason(update, install, ['age']))

    def test_what_the_downloads_say_beats_what_the_index_lacks(self):
        """A package apt cannot reinstall and another that cannot be downloaded: the network is the reason, not the sources."""
        install = (100, 'Reinstallation of age is not possible, it cannot be downloaded.\n'
                        'Err:1 http://a.example/ubuntu noble/main amd64 zstd 1.5.5\n  Could not resolve \'a.example\'\n',
                   'E: Failed to fetch http://a.example/pool/zstd.deb  Could not resolve \'a.example\'\n')
        update = (0, 'Hit:1 http://a.example/ubuntu noble InRelease\n', '')
        self.assertIn(manage.OFFLINE, manage.apt_reason(update, install, ['age', 'zstd']))

    def test_the_notices_of_the_install_and_of_the_packages_come_together(self):
        result = self.live(recorded('offline-no-index'), FakeSystemctl(self.root, masked=True))
        self.assertEqual(len(result['notices']), 2)
        self.assertTrue(result['notices'][0].startswith('備份與還原需要的套件沒有裝好：'))
        self.assertEqual(result['notices'][1], manage.MASKED_NOTICE)

    def test_the_install_uses_the_new_plan_as_a_whole(self):
        """Desired files and state come from the same new plan: Cockpit changed while apt-get ran."""
        status = self.root / 'var/lib/dpkg/status'
        before = status.read_text()

        def another_job(_argv):
            status.write_text(before.replace('362-1', '363-1'))

        with patch.object(manage, 'install', wraps=manage.install) as install:
            self.live(FakeHost({'zstd'}, seen=another_job))
        (_root, desired, state, _systemd), _options = install.call_args
        self.assertEqual(state['cockpit_version'], '363-1')
        self.assertEqual(json.loads(desired[manage.STATE][0])['cockpit_version'], '363-1')
        self.assertEqual(json.loads((self.root / manage.STATE).read_text())['cockpit_version'], '363-1')

    def test_what_works_afterwards_decides_not_the_exit_code_of_apt(self):
        # apt is content, age-keygen still does not answer: said so, nothing is claimed about the network.
        host = FakeHost({'age-keygen', 'zstd'}, adds={'zstd'})
        result = self.live(host)
        self.assertEqual((result['packages'], result['missing_packages']), (['zstd'], ['age']))
        self.assertIn(f'自動補裝沒有成功：{manage.BROKEN_TOOL}。', result['notices'][0])
        # apt reports a failure of a hook of another package, the tool works all the same: no notice.
        self.reset()
        host = FakeHost({'zstd'}, install=(100, '', 'E: a hook of another package failed\n'))
        result = self.live(host)
        self.assertEqual(result['packages'], ['zstd'])
        self.assertNotIn('notices', result)
        # Offline, a damaged tool: apt has nothing to reinstall it from and ends with 0 (recorded).
        self.reset()
        update, install = APT_RECORDED['damaged-offline-no-index']
        self.assertEqual(install[0], 0)
        result = self.live(FakeHost({'zstd'}, adds=(), update=update, install=install))
        self.assertEqual(result['missing_packages'], ['zstd'])
        self.assertIn(f'自動補裝沒有成功：{manage.OFFLINE}。', result['notices'][0])

    def test_a_page_changed_while_apt_ran_is_not_overwritten(self):
        """apt-get can wait minutes for the dpkg lock of an automatic update: the plan is made again afterwards."""
        page = self.root / 'usr/share/cockpit/systemd/logs.html'

        def another_job(_argv):
            page.write_bytes(b'<html><head></head><body>native log view of the newer Cockpit</body></html>')

        host = FakeHost({'zstd'}, seen=another_job)
        code, result, _notes = self.main('install', '--no-preview', '--no-services', host=host)
        self.assertEqual((code, result['status'], result['packages']), (0, 'installed', ['zstd']))
        html = page.read_bytes()
        self.assertIn(b'native log view of the newer Cockpit', html, 'the newer page is not replaced by the old one')
        self.assertIn(b'static/branding.css', html, 'and it gets the branding link all the same')
        # The same when apt-get could not add anything (it may have waited just as long).
        self.reset()
        host = recorded('locked', seen=another_job)
        code, result, _notes = self.main('install', '--no-preview', '--no-services', host=host)
        self.assertEqual((code, result['status'], result['packages']), (0, 'installed', []))
        self.assertIn(b'native log view of the newer Cockpit', page.read_bytes())

    def test_a_cockpit_podman_upgraded_while_apt_ran_keeps_its_new_bundle(self):
        native = self.source / 'native/podman/dist'
        (native / 'licenses').mkdir(parents=True)
        (native / 'index.js.gz').write_bytes(gzip.compress(b'integrated JavaScript'))
        (native / 'index.js.LEGAL.txt').write_text('license notice')
        (native / 'licenses/NOTICE').write_text('runtime attribution')
        target = self.root / manage.PODMAN / 'index.js.gz'
        target.parent.mkdir(parents=True)
        target.write_bytes(gzip.compress(b'distribution JavaScript'))
        status = self.root / 'var/lib/dpkg/status'
        cockpit = status.read_text()
        status.write_text(cockpit + 'Package: cockpit-podman\nStatus: install ok installed\nVersion: 124-1~bpo24.04.1\n\n')

        def another_job(_argv):  # cockpit-podman 125 arrives (automatic update) while apt-get waits
            status.write_text(cockpit + 'Package: cockpit-podman\nStatus: install ok installed\nVersion: 125-1\n\n')
            target.write_bytes(gzip.compress(b'newer distribution JavaScript'))

        host = FakeHost({'zstd'}, seen=another_job)
        code, result, _notes = self.main('install', '--no-preview', host=host)
        self.assertEqual((code, result['status']), (0, 'installed'))
        self.assertEqual(gzip.decompress(target.read_bytes()), b'newer distribution JavaScript')
        # Without the package step the same install replaces the bundle of 124 (the gate works).
        self.reset()
        target.parent.mkdir(parents=True)
        target.write_bytes(gzip.compress(b'distribution JavaScript'))
        status.write_text(cockpit + 'Package: cockpit-podman\nStatus: install ok installed\nVersion: 124-1~bpo24.04.1\n\n')
        self.main('install', '--no-preview', host=FakeHost())
        self.assertEqual(gzip.decompress(target.read_bytes()), b'integrated JavaScript')

    def test_the_installers_own_refusal_comes_before_apt(self):
        for name in ('changes', 'directory_plan'):
            with self.subTest(refusal=name):
                host = FakeHost(ALL_TOOLS)
                with patch.object(manage, name, side_effect=ValueError('refused by the installer (test)')):
                    with self.assertRaisesRegex(ValueError, 'refused by the installer'):
                        self.live(host)
                self.assertEqual(host.apt, [], 'no apt-get ran, nothing was changed')
        # And a refusal after the packages step (the plan is made again) leaves the files alone.
        before = self.snapshot()
        seen = []

        def unreadable_page(argv):
            seen.append(argv)
            (self.root / 'usr/share/cockpit/systemd/logs.html').write_bytes(b'<html>no head here</html>')

        host = FakeHost({'zstd'}, seen=unreadable_page)
        with self.assertRaisesRegex(ValueError, 'Unknown native template'):
            self.live(host)
        (self.root / 'usr/share/cockpit/systemd/logs.html').write_bytes(before['usr/share/cockpit/systemd/logs.html'][0])
        self.assertEqual(self.snapshot(), before)

    def test_no_backup_and_other_roots_check_and_run_nothing(self):
        host = FakeHost({'age', 'zstd'}, adds=())
        result = self.live(host, include_backup=False)
        self.assertEqual((result['status'], host.apt), ('installed', []))
        for key in ('packages', 'missing_packages', 'notices'):
            self.assertNotIn(key, result)
        # A source tree without the engine (its helper is not installed by this run) needs no tools either.
        (self.source / 'backup-engine/woowbackup/cli.py').unlink()
        self.assertEqual((self.live(host)['status'], host.apt), ('installed', []))
        self.add_backup_source()

        def forbidden(*args):
            raise AssertionError(f'run for a --root install: {args}')

        with patch.object(manage, 'run_fixed', forbidden):
            self.assertEqual(self.install()['status'], 'installed')  # self.root is not "/"
            self.assertEqual(manage.status(self.root), {'status': 'not-checked', 'source_version': 'test.1',
                                                        'tools': 'not-checked', 'packages': []})
            code, planned, notes = self.main('plan', '--no-preview', '--no-services')
        self.assertEqual((code, planned['packages']), (0, []))
        self.assertIn(f'sudo apt-get install {" ".join(manage.TOOL_PACKAGES)}', notes)
        _code, planned, notes = self.main('plan', '--no-preview', '--no-services', '--no-backup')
        self.assertEqual((planned['packages'], notes), ([], ''))
        self.assertIsNone(manage.engine_tools(self.root, True))
        self.assertIsInstance(manage.engine_tools(Path('/'), True), manage.HostTools)
        self.assertIsNone(manage.engine_tools(Path('/'), False))

    def test_status_after_no_backup_still_checks_the_engine_that_is_there(self):
        """The advice of an earlier refusal was --no-backup: the engine it leaves on the device needs its tools all the same."""
        self.live(FakeHost())
        helper = self.root / manage.BACKUP_HELPER
        self.assertTrue(helper.is_file())
        (self.source / 'VERSION').write_bytes(b'test.2')
        broken = FakeHost({'python3-nacl', 'age'}, adds=())
        result = self.live(broken, include_backup=False)
        self.assertEqual((result['status'], broken.apt), ('installed', []), 'this run manages no engine: nothing probed or run')
        self.assertTrue(helper.is_file(), 'the engine stays')
        self.assertNotIn(manage.BACKUP_HELPER, json.loads((self.root / manage.STATE).read_text())['files'])
        status = manage.status(self.root, tools=manage.HostTools(broken))
        self.assertEqual((status['status'], status['source_version'], status['packages']),
                         ('tools-missing', 'test.2', ['age', 'python3-nacl']))
        code, out, notes = self.main('status', host=broken)
        self.assertEqual((code, out['status'], out['packages']), (1, 'tools-missing', ['age', 'python3-nacl']))
        self.assertIn('裝好之前：缺 age 不能建立、檢查與還原加密的備份', notes)
        self.assertEqual(self.main('status', host=FakeHost())[0:2], (0, {
            'status': 'ready', 'source_version': 'test.2', 'packages': [], 'tools': dict.fromkeys(ALL_TOOLS, True)}))
        # No engine on the device at all: nothing to check.
        self.reset()
        self.live(FakeHost(), include_backup=False)
        self.assertFalse(helper.exists())
        host = FakeHost(ALL_TOOLS, adds=())
        self.assertEqual(self.main('status', host=host)[0:2], (0, {
            'status': 'ready', 'source_version': 'test.2', 'packages': [], 'tools': 'no-engine'}))
        self.assertEqual(host.apt, [])

    def test_plan_and_status_report_missing_packages_and_change_nothing(self):
        self.live(FakeHost())
        host = FakeHost({'age-keygen', 'python3-nacl'})
        before = self.tree('')
        code, planned, notes = self.main('plan', '--no-preview', '--no-services', host=host)
        self.assertEqual((code, planned['packages']), (0, ['age', 'python3-nacl']))
        self.assertIn('沒有裝好：age、python3-nacl。執行 install 時會用 apt 自動補裝（補不了也會照常更新）。', notes)
        code, result, notes = self.main('status', host=host)
        self.assertEqual((code, result), (1, {
            'status': 'tools-missing', 'source_version': 'test.1', 'packages': ['age', 'python3-nacl'],
            'tools': {'age': True, 'age-keygen': False, 'zstd': True, 'python3-nacl': False, 'python3-cryptography': True}}))
        self.assertIn('沒有裝好：age、python3-nacl。', notes)
        for part in ('裝好之前：缺 age 不能建立、檢查與還原加密的備份', '缺 age 不能建立與檢查加密金鑰',
                     '缺 python3-nacl 不能讀取 2026 年 3 月以後的 HA 加密備份'):
            self.assertIn(part, notes)
        self.assertIn('請重新執行安裝（sudo python3 scripts/manage.py install）', notes)
        host.broken.clear()
        code, result, notes = self.main('status', host=host)
        self.assertEqual((code, result['status'], set(result['tools'].values()), notes), (0, 'ready', {True}, ''))
        self.assertEqual(self.main('plan', '--no-preview', '--no-services', host=host)[1]['packages'], [])
        self.assertEqual((self.tree(''), host.apt), (before, []), 'read-only')

    def test_the_command_line_goes_on_with_a_notice_and_status_exits_1(self):
        host = recorded('offline-no-index')
        code, result, notes = self.main('install', '--no-preview', '--no-services', host=host)
        self.assertEqual((code, result['status'], result['packages'], result['missing_packages']),
                         (0, 'installed', [], list(manage.TOOL_PACKAGES)))
        self.assertIn(f'Note: {result["notices"][0]}\n', notes)
        self.assertIn(manage.OFFLINE, result['notices'][0])
        self.assertIn('After installation, sign out/in', notes)
        code, status, _notes = self.main('status', host=host)
        self.assertEqual((code, status['status'], status['packages']), (1, 'tools-missing', list(manage.TOOL_PACKAGES)))
        # Installing again once the device has the packages (network back): they are added, no notice.
        host.update, host.install, host.adds = (0, '', ''), (0, '', ''), set(manage.TOOL_PACKAGES)
        code, result, _notes = self.main('install', '--no-preview', '--no-services', host=host)
        self.assertEqual((code, result['status'], result['packages']), (0, 'already-current', list(manage.TOOL_PACKAGES)))
        self.assertNotIn('notices', result)
        self.assertEqual(self.main('status', host=host)[0], 0)

    def test_status_needs_the_administrator_to_read_the_install_record(self):
        self.live(FakeHost())
        with patch.object(Path, 'read_text', side_effect=PermissionError(13, 'Permission denied')):
            with self.assertRaisesRegex(ValueError, 'sudo python3 scripts/manage.py status'):
                manage.status(self.root)
        out, err = io.StringIO(), io.StringIO()
        with (patch.object(sys, 'argv', ['manage.py', '--root', str(self.root), 'status']),
              patch.object(Path, 'read_text', side_effect=PermissionError(13, 'Permission denied')),
              contextlib.redirect_stdout(out), contextlib.redirect_stderr(err)):
            self.assertEqual(manage.main(), 1)
        self.assertIn('請用 sudo 執行', err.getvalue())

    def test_how_the_tools_and_apt_are_run(self):
        calls, interrupts, before = [], [], signal.getsignal(signal.SIGINT)

        def run_fixed(*args):
            calls.append(args)
            interrupts.append(signal.getsignal(signal.SIGINT))
            return 127, '', ''

        environ = {'http_proxy': 'http://proxy.example:3128', 'no_proxy': 'localhost', 'PATH': '/home/user/bin',
                   'PYTHONPATH': '/home/user/lib', 'LD_PRELOAD': '/home/user/x.so', 'APT_CONFIG': '/home/user/apt.conf'}
        with (patch.object(manage, 'run_fixed', run_fixed),
              patch.dict(os.environ, environ, clear=True), contextlib.redirect_stderr(io.StringIO())):
            report = manage.HostTools().ensure()
        self.assertEqual(report['missing_packages'], list(manage.TOOL_PACKAGES))
        self.assertIn(manage.NO_APT, report['notices'][0])
        probes = [(list(probe), manage.TOOL_ENV, 30) for _tool, _package, probe in manage.HOST_TOOLS]
        apt_env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                   'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_SUSPEND': '1',
                   'http_proxy': 'http://proxy.example:3128', 'no_proxy': 'localhost'}
        self.assertEqual(calls, [*probes, (list(manage.APT_UPDATE), apt_env, None),
                                 ([*manage.APT_INSTALL, *manage.TOOL_PACKAGES], apt_env, None), *probes])
        # Ctrl-C does not reach apt-get or the wait for it (a killed apt-get leaves dpkg half-way), only these two.
        self.assertEqual(interrupts, [*[before] * len(probes), signal.SIG_IGN, signal.SIG_IGN, *[before] * len(probes)])
        self.assertEqual(signal.getsignal(signal.SIGINT), before)
        for option in ('-y', '--no-remove', '--no-install-recommends', '--reinstall', 'DPkg::Lock::Timeout=300'):
            self.assertIn(option, manage.APT_INSTALL)
        self.assertEqual((manage.APT_UPDATE[0], manage.APT_INSTALL[0], manage.APT_INSTALL[-1]),
                         ('/usr/bin/apt-get', '/usr/bin/apt-get', 'install'))
        self.assertEqual(manage.run_fixed(['/bin/sh', '-c', 'cat; printf %s "$HOME$LANG"; exit 3']), (3, 'C.UTF-8', ''))

    def test_the_engine_still_stops_without_its_tools(self):
        # X-AR-06 and X-KEY-02 at run time; KEY-14 and KEY-15: tests/backup/test_ha_securetar.py MissingPackageTests.
        engine = str(REPO / 'backup-engine')
        if engine not in sys.path:
            sys.path.insert(0, engine)
        from woowbackup import archive, keys
        from woowbackup.errors import BackupError
        from woowbackup.paths import Paths

        def stopped(callable_):
            with self.assertRaises(BackupError) as error:
                callable_()
            self.assertEqual(error.exception.code, 'internal-error')
            return error.exception.message

        def without(gone):
            return patch('woowbackup.util.find_tool', lambda name: None if name == gone else f'/usr/bin/{name}')

        for tool in ('age', 'zstd'):
            with self.subTest(tool=tool), without(tool):
                self.assertIn('age 或 zstd', stopped(archive._tools))
        store = keys.KeyStore(Paths(base=Path(self.temp.name) / 'engine'))
        with without('age-keygen'):
            self.assertIn('age-keygen', stopped(store.ensure_device_key))
        with without(None), patch.object(keys.subprocess, 'run',
                                         side_effect=subprocess.TimeoutExpired(['age-keygen'], keys.KEYGEN_TIMEOUT)):
            self.assertIn('沒有回應', stopped(store.ensure_device_key))
        self.assertEqual((store.device_key(), list(store.dir.glob('*.key'))), (None, []), 'no key was made')


class BootstrapContract(unittest.TestCase):
    """scripts/bootstrap-ubuntu.sh with stub commands (a copy whose root and release checks are opened for the test):
    running it again is harmless, and an offline device is only refused when a package is really missing."""

    BACKUP = ['age', 'zstd', 'python3-nacl', 'python3-cryptography']
    COCKPIT = ['cockpit', 'cockpit-podman', 'cockpit-storaged', 'cockpit-networkmanager', 'cockpit-packagekit']
    # The stub device: a file per installed package in $STATE/installed (its content: the dpkg selection) and per package
    # of the index in $STATE/index; $STATE/offline: nothing can be downloaded, $STATE/newer: newer versions exist.
    STUBS = {
        'dpkg-query': """[[ -f $STATE/installed/$3 ]] || exit 1
read -r want < "$STATE/installed/$3"
printf '%s ok installed 1.0-1' "$want"
""",
        'apt-cache': '[[ -f $STATE/installed/$2 || -f $STATE/index/$2 ]]\n',
        'systemctl': ':\n',
        'apt-get': """if [[ $1 == update ]]; then [[ ! -f $STATE/offline ]] || exit 100; exit 0; fi
names=()
while (( $# )); do case $1 in -t) shift ;; -*|install) ;; *) names+=("$1") ;; esac; shift; done
for name in "${names[@]}"; do
  if [[ -f $STATE/installed/$name ]]; then
    read -r want < "$STATE/installed/$name"
    if [[ -f $STATE/newer && $want == hold ]]; then printf 'E: Held packages were changed\\n' >&2; exit 100; fi
    if [[ -f $STATE/newer && -f $STATE/offline ]]; then printf 'E: Failed to fetch\\n' >&2; exit 100; fi
  elif [[ -f $STATE/offline ]]; then
    printf 'E: Failed to fetch\\n' >&2; exit 100
  fi
done
for name in "${names[@]}"; do [[ -f $STATE/installed/$name ]] || printf 'install\\n' > "$STATE/installed/$name"; done
""",
    }

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name)
        self.bin, self.device = base / 'bin', base / 'device'
        for directory in (self.bin, self.device / 'installed', self.device / 'index'):
            directory.mkdir(parents=True)
        for name, body in self.STUBS.items():
            (self.bin / name).write_text(f'#!/bin/bash\nprintf "%s\\n" "{name} $*" >> "$STATE/calls"\n{body}')
            (self.bin / name).chmod(0o755)
        (base / 'os-release').write_text('ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\nPRETTY_NAME=test\n')
        text = (REPO / 'scripts/bootstrap-ubuntu.sh').read_text()
        for real, opened in (('. /etc/os-release\n', f'. {base}/os-release\n'), ('[[ $EUID -ne 0 ]]', '[[ 0 -ne 0 ]]')):
            self.assertEqual(text.count(real), 1)
            text = text.replace(real, opened)
        self.script = base / 'bootstrap.sh'
        self.script.write_text(text)

    def package(self, *names, where='installed', want='install'):
        for name in names:
            (self.device / where / name).write_text(want + '\n')

    def flag(self, *names):
        for name in names:
            (self.device / name).touch()

    def run_script(self, *args):
        """(result, the changing calls). Only the stubs are on PATH: no command of this host can run."""
        calls = self.device / 'calls'
        calls.unlink(missing_ok=True)
        result = subprocess.run(['/bin/bash', str(self.script), *args], capture_output=True, text=True, timeout=60,
                                env={'PATH': str(self.bin), 'STATE': str(self.device), 'LC_ALL': 'C.UTF-8'})
        made = calls.read_text().splitlines() if calls.exists() else []
        return result, [call for call in made if not call.startswith(('dpkg-query', 'apt-cache'))]

    def installed(self):
        return sorted(path.name for path in (self.device / 'installed').iterdir())

    def test_plan_changes_nothing_and_shows_held_packages_as_installed(self):
        self.package('zstd', want='hold')
        result, calls = self.run_script()
        self.assertEqual((result.returncode, calls, self.installed()), (0, [], ['zstd']))
        self.assertIn('  zstd: installed 1.0-1\n', result.stdout)
        self.assertIn('  age: not installed\n', result.stdout)

    def test_apply_installs_everything_and_again_is_harmless(self):
        self.package(*self.BACKUP, where='index')  # only these are looked up beforehand
        steps = ['apt-get update --error-on=any', f'apt-get install -y -t noble-backports {" ".join(self.COCKPIT)}',
                 f'apt-get install -y {" ".join(self.BACKUP)}', 'systemctl enable --now cockpit.socket']
        for _run in ('first', 'again'):
            result, calls = self.run_script('--apply')
            self.assertEqual((result.returncode, calls, result.stderr), (0, steps, ''))
            self.assertEqual(self.installed(), sorted(self.COCKPIT + self.BACKUP))

    def test_an_offline_device_that_has_everything_is_not_refused(self):
        self.package(*self.COCKPIT, *self.BACKUP)
        self.flag('offline')
        result, calls = self.run_script('--apply')
        self.assertEqual((result.returncode, calls[-1]), (0, 'systemctl enable --now cockpit.socket'))
        self.assertIn('套件索引無法更新', result.stderr)

    def test_a_newer_version_that_cannot_be_installed_is_no_reason_to_refuse(self):
        self.package(*self.COCKPIT)
        self.package(*self.BACKUP, want='hold')
        self.flag('newer')
        result, calls = self.run_script('--apply')
        self.assertEqual((result.returncode, calls[-1]), (0, 'systemctl enable --now cockpit.socket'))
        self.assertNotIn('沒有裝好', result.stderr)

    def test_a_held_tool_does_not_keep_a_missing_one_from_being_added(self):
        self.package(*self.COCKPIT, 'zstd', 'python3-cryptography')
        self.package('age', want='hold')
        self.package('python3-nacl', where='index')
        self.flag('newer')
        result, calls = self.run_script('--apply')
        self.assertEqual((result.returncode, calls[-2:]), (0, ['apt-get install -y python3-nacl',
                                                               'systemctl enable --now cockpit.socket']))
        self.assertIn('python3-nacl', self.installed())

    def test_missing_and_offline_is_refused_with_the_names(self):
        self.package(*self.COCKPIT, 'age', 'zstd')
        self.package('python3-nacl', 'python3-cryptography', where='index')
        self.flag('offline')
        result, calls = self.run_script('--apply')
        self.assertEqual(result.returncode, 1)
        self.assertIn('備份與還原需要的套件沒有裝好：python3-nacl python3-cryptography。', result.stderr)
        self.assertNotIn('systemctl enable --now cockpit.socket', calls)

    def test_the_cockpit_packages_step_is_as_before_it_still_needs_the_network(self):
        """The relaxed checks are about the four backup packages only: what happens to the five Cockpit packages is unchanged."""
        self.package(*self.COCKPIT, *self.BACKUP)
        self.flag('offline', 'newer')  # the index knows newer versions that cannot be downloaded
        result, calls = self.run_script('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls[-1], f'apt-get install -y -t noble-backports {" ".join(self.COCKPIT)}')
        self.assertNotIn('systemctl enable --now cockpit.socket', calls)
        self.reset_device()
        self.package(*self.BACKUP)  # a Cockpit package that is not installed, no network
        self.flag('offline')
        result, calls = self.run_script('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('systemctl enable --now cockpit.socket', calls)

    def reset_device(self):
        for where in ('installed', 'index'):
            for path in (self.device / where).iterdir():
                path.unlink()
        for name in ('offline', 'newer', 'calls'):
            (self.device / name).unlink(missing_ok=True)

    def test_a_package_no_index_knows_is_refused_before_anything_is_installed(self):
        self.package(*self.COCKPIT, 'zstd', 'python3-nacl', 'python3-cryptography', where='index')
        result, calls = self.run_script('--apply')
        self.assertEqual((result.returncode, calls, self.installed()), (1, ['apt-get update --error-on=any'], []))
        self.assertIn('age is not available from the configured apt sources', result.stderr)
        self.assertIn('套件庫找不到 age：', result.stderr)
        self.assertIn('沒有安裝任何套件', result.stderr)


if __name__ == '__main__':
    unittest.main()
