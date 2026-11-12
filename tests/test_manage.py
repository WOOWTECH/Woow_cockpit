import contextlib
import gzip
import importlib.util
import json
import os
from pathlib import Path
import posixpath
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

    def install(self, **options):
        desired, state = manage.desired_files(self.root, **options)
        return manage.install(self.root, desired, state)


class InstallationContract(HostFixture):
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


if __name__ == '__main__':
    unittest.main()
