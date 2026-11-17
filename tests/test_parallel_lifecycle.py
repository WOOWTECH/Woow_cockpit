"""Deployment transitions with a disposable host and no live service commands."""
import configparser
import copy
from contextlib import ExitStack, nullcontext
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('parallel_lifecycle_renderer', ROOT / 'parallel-ingress/render.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
with patch.dict(sys.modules, {'render': r}):
    spec = importlib.util.spec_from_file_location('parallel_lifecycle_manager', ROOT / 'parallel-ingress/manage.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

REAL_RUN = subprocess.run
REAL_STAT = Path.stat
REAL_LSTAT = Path.lstat


def config():
    return r.config(dict(schema=1, instance='apporo', brand='apporo', owner='operator',
                         public_origin='https://apporo.example.test', listen_port=29092,
                         pi_public_port=19096, pi_local_port=19097))


class HostFixture(unittest.TestCase):
    """Real fixture files; ownership is simulated so the suite needs no sudo."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='parallel-lifecycle-')
        self.addCleanup(temporary.cleanup)
        self.host = Path(temporary.name) / 'host'
        self.host.mkdir(mode=0o755)
        self.c = config()
        self.base = self.host / 'etc/cockpit/parallel-ingress/apporo'
        self.conf = self.host / 'etc/cockpit/cockpit.conf'
        self.qpath = self.host / 'home/operator/.config/containers/systemd/apporo-cockpit-pwa.container'
        self.units = [self.host / 'etc/systemd/system' / unit for unit in m.unit_names(self.c)]
        self.calls = []
        self.owners = {}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)

        host = self.host

        class InstalledPath(type(Path())):
            def relative_to(path, *other, **kwargs):
                # Receipt inventories use paths relative to the installed root.
                if other == ('/',) and path.is_relative_to(host):
                    return super().relative_to(host, **kwargs)
                return super().relative_to(*other, **kwargs)

        def installed_path(value='.'):
            path = Path(value)
            if path == Path('/'):
                return InstalledPath(host)
            if path.is_absolute() and path.parts[1] in ('etc', 'usr', 'home', 'var', 'run'):
                return InstalledPath(host / path.relative_to('/'))
            return InstalledPath(path)

        def trusted_stat(original, path, *args, **kwargs):
            values = list(original(path, *args, **kwargs))
            if path == host or path.is_relative_to(host):
                values[4] = self.owners.get(path, 0)
            elif path in host.parents:
                # The temporary root stands in for /, not a world-writable /tmp ancestor.
                values[0] = stat.S_IFDIR | 0o755
                values[4] = 0
            return os.stat_result(values)

        self.stack.enter_context(patch.object(m, 'Path', installed_path))
        self.stack.enter_context(patch.object(m, 'BASE', str(self.base.parent)))
        self.stack.enter_context(patch.object(Path, 'stat', lambda p, *a, **k: trusted_stat(REAL_STAT, p, *a, **k)))
        self.stack.enter_context(patch.object(Path, 'lstat', lambda p, *a, **k: trusted_stat(REAL_LSTAT, p, *a, **k)))
        self.stack.enter_context(patch.object(m.os, 'geteuid', return_value=0))
        self.stack.enter_context(patch.object(m, 'paths', return_value=(self.base, self.qpath)))
        # Fail closed if a new code path tries to execute a live command.
        self.stack.enter_context(patch.object(m, 'command', side_effect=AssertionError('Unexpected service command')))
        self.stack.enter_context(patch.object(m, 'user_command', side_effect=AssertionError('Unexpected owner command')))
        self.stack.enter_context(patch.object(m.subprocess, 'run', side_effect=AssertionError('Unexpected subprocess')))
        self.stack.enter_context(patch.object(m.urllib.request, 'build_opener', side_effect=AssertionError('Unexpected network')))
        self.stack.enter_context(patch.object(m.os, 'chown', side_effect=self.fake_chown))

    def fake_chown(self, path, uid, gid):
        self.assertTrue(Path(path).is_relative_to(self.host))
        self.assertNotEqual(Path(path), self.qpath, 'root must never chown the owner-controlled Quadlet')

    def put(self, path, data=b'fixture', mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        for parent in path.parents:
            if parent == self.host or parent.is_relative_to(self.host):
                parent.chmod(0o755)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def setup_install(self, existing=True, frontend_active=False):
        self.put(self.host / 'usr/bin/node', mode=0o755)
        self.put(self.conf, b'[WebService]\nAllowUnencrypted = true')
        self.qpath.parent.mkdir(parents=True)
        for unit in self.units:
            unit.parent.mkdir(parents=True, exist_ok=True)
            if existing:
                self.put(unit, f'ExecStart=/usr/bin/node {self.base}/current/pi-gateway.mjs\n'.encode())
        if existing:
            self.put(self.qpath, b'[Container]\nContainerName=apporo-cockpit-pwa\n# previous\n', 0o600)
        public, local = m.unit_names(self.c)
        self.state = {
            public: {'enabled': existing, 'active': False},
            local: {'enabled': False, 'active': existing},
            'frontend_active': frontend_active,
        }
        self.before_state = copy.deepcopy(self.state)
        self.before_files = {p: p.read_bytes() if p.exists() else None for p in [self.conf, self.qpath, *self.units]}

        def system(args, **kwargs):
            args = list(map(str, args))
            self.calls.append(('system', args))
            if args[0] == 'systemctl' and args[-1] in self.state:
                unit, action = args[-1], args[1]
                if action in ('is-enabled', 'is-active'):
                    value = self.state[unit]['enabled' if action == 'is-enabled' else 'active']
                    return subprocess.CompletedProcess(args, 0 if value else 1)
                if action == 'enable': self.state[unit]['enabled'] = True
                if action in ('start', 'restart'): self.state[unit]['active'] = True
                if action == 'disable': self.state[unit] = {'enabled': False, 'active': False}
            return subprocess.CompletedProcess(args, 0)

        def owner(owner, *args, **kwargs):
            self.assertEqual(owner, self.c['owner'])
            self.calls.append(('owner', list(args)))
            if args[:3] == ('systemctl', '--user', 'show'):
                return subprocess.CompletedProcess(args, 0, stdout='active\n' if self.state['frontend_active'] else 'inactive\n')
            if args[:3] == ('systemctl', '--user', 'stop'): self.state['frontend_active'] = False
            if args[:3] == ('systemctl', '--user', 'restart'): self.state['frontend_active'] = True
            return subprocess.CompletedProcess(args, 0)

        def owner_write(c, path, data, mode=0o644):
            self.assertEqual(c['owner'], 'operator')
            self.assertEqual(path, self.qpath)
            self.calls.append(('quadlet', data))
            if data is None: path.unlink(missing_ok=True)
            else: self.put(path, data, mode)

        def payload(c, out):
            for name in ('nginx.conf', 'pi-gateway.mjs', 'pi-public.service', 'pi-local.service',
                         'public/branding/brand.json', 'public/packages/woowpiweb/index.html'):
                path = out / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'payload')

        real_write = m.write
        real_snapshot = m.snapshot

        def root_write(path, *args, **kwargs):
            self.assertNotEqual(path, self.qpath, 'Quadlet mutations must run as the owner')
            self.assertTrue(path.is_relative_to(self.host))
            return real_write(path, *args, **kwargs)

        def canonical_snapshot(files):
            result = real_snapshot(files)
            # restore() spells this one allowlisted shared path literally.
            result['/etc/cockpit/cockpit.conf'] = result.pop(str(self.conf))
            return result

        for name, value in [('command', system), ('user_command', owner), ('write_quadlet', owner_write),
                            ('render', payload), ('write', root_write), ('snapshot', canonical_snapshot)]:
            self.stack.enter_context(patch.object(m, name, side_effect=value))
        self.stack.enter_context(patch.object(m.subprocess, 'run', side_effect=system))
        self.stack.enter_context(patch.object(m, 'metadata', side_effect=lambda c: {
            'config': copy.deepcopy(c), 'source_commit': 'a' * 40, 'source_tree': 'b' * 40}))
        self.stack.enter_context(patch.object(m, 'backend_hashes', return_value={}))

    def assert_restored(self):
        self.assertEqual(self.state, self.before_state)
        for path, content in self.before_files.items():
            self.assertEqual(path.read_bytes() if path.exists() else None, content, str(path))
        self.assertFalse((self.base / 'current').is_symlink())


class DeploymentTransitions(HostFixture):
    def test_late_health_failure_restores_bytes_modes_and_independent_unit_states(self):
        self.setup_install(existing=True, frontend_active=False)
        with patch.object(m, 'verify', side_effect=ValueError('health failed')):
            with self.assertRaisesRegex(ValueError, 'health failed'):
                m.install(self.c)
        self.assert_restored()
        self.assertEqual(stat.S_IMODE(self.qpath.stat().st_mode), 0o600)
        writes = [data for kind, data in self.calls if kind == 'quadlet']
        self.assertEqual(len(writes), 2)
        self.assertEqual(writes[-1], self.before_files[self.qpath])

    def test_failed_first_install_deletes_quadlet_as_owner_and_leaves_no_new_units(self):
        self.setup_install(existing=False)
        with patch.object(m, 'verify', side_effect=ValueError('health failed')):
            with self.assertRaisesRegex(ValueError, 'health failed'):
                m.install(self.c)
        self.assert_restored()
        self.assertIn(('quadlet', None), self.calls)

    def test_failed_upgrade_restarts_previously_running_frontend(self):
        self.setup_install(existing=True, frontend_active=True)
        with patch.object(m, 'verify', side_effect=ValueError('health failed')):
            with self.assertRaisesRegex(ValueError, 'health failed'):
                m.install(self.c)
        self.assert_restored()

    def test_release_root_and_dynamic_user_inputs_are_readable_with_umask_077(self):
        self.setup_install(existing=False)
        previous = os.umask(0o077)
        try:
            with patch.object(m, 'verify', return_value={'status': 'verified'}):
                m.install(self.c)
        finally:
            os.umask(previous)
        release = (self.base / 'current').resolve()
        for path in [release, *release.rglob('*')]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755 if path.is_dir() else 0o644, str(path))
        journal = next((self.base / 'transactions').glob('*.json'))
        self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)

    def test_verification_retries_startup_but_propagates_persistent_health_failure(self):
        self.setup_install(existing=False)
        with patch.object(m, 'verify', return_value={'status': 'verified'}):
            m.install(self.c)
        opener = Mock()
        opener.open.side_effect = [ConnectionRefusedError('starting'),
                                   nullcontext(SimpleNamespace(status=200))]
        with patch.object(m.urllib.request, 'build_opener', return_value=opener), patch.object(m.time, 'sleep') as sleep:
            self.assertEqual(m.verify('apporo')['status'], 'verified')
            self.assertEqual(opener.open.call_count, 2)
            sleep.assert_called_once()
            opener.open.reset_mock(side_effect=True)
            opener.open.side_effect = ConnectionRefusedError('still unavailable')
            with self.assertRaisesRegex(ConnectionRefusedError, 'still unavailable'):
                m.verify('apporo')
            self.assertGreater(opener.open.call_count, 1)
            self.assertLessEqual(opener.open.call_count, 30)

    def test_incompatible_previous_release_aborts_restore_before_any_service_or_file_change(self):
        self.setup_install(existing=True)
        self.base.mkdir(parents=True, exist_ok=True)
        previous = 'releases/20261117T010203Z'
        self.put(self.base / previous / 'receipt.json', b'{"files":{},"backend_hashes":{}}')
        (self.base / 'current').symlink_to('releases/20261117T040506Z')
        record = {'previous': previous, 'before': m.snapshot([self.qpath, self.conf, *self.units]),
                  'service_state': copy.deepcopy(self.state)}
        self.calls.clear()
        with patch.object(m, 'audit_receipt', return_value=['backend revision mismatch']) as audit:
            with self.assertRaisesRegex(ValueError, 'Previous release'):
                m.restore(self.c, record)
        audit.assert_called_once()
        self.assertEqual(self.calls, [])
        self.assertEqual(os.readlink(self.base / 'current'), 'releases/20261117T040506Z')
        for path, content in self.before_files.items(): self.assertEqual(path.read_bytes(), content)

    def test_non_symlink_current_is_rejected_before_render_or_service_changes(self):
        self.setup_install(existing=False)
        self.put(self.base / 'current', b'do not replace')
        with self.assertRaisesRegex(ValueError, 'non-symlink'):
            m.install(self.c)
        self.assertEqual((self.base / 'current').read_bytes(), b'do not replace')
        self.assertEqual(self.calls, [])

    def test_global_lock_rejects_concurrent_operation_and_releases_after_exception(self):
        with self.assertRaisesRegex(RuntimeError, 'simulated failure'):
            with m.deployment_lock():
                with self.assertRaisesRegex(ValueError, 'Another parallel ingress'):
                    with m.deployment_lock(): self.fail('concurrent operation entered')
                raise RuntimeError('simulated failure')
        with m.deployment_lock(): pass


class ConfigurationTrust(HostFixture):
    def setUp(self):
        super().setUp()
        self.file = self.put(self.host / 'etc/parallel/config.json', json.dumps(self.c).encode())

    def test_trusted_config_and_unterminated_webservice_line(self):
        self.assertEqual(m.read_config(self.file), self.c)
        before = '[WebService]\nAllowUnencrypted = true'
        after = m.origins(before, [self.c['public_origin']])
        parsed = configparser.ConfigParser(); parsed.read_string(after)
        self.assertEqual(parsed['WebService']['AllowUnencrypted'], 'true')
        self.assertEqual(parsed['WebService']['Origins'], self.c['public_origin'])
        self.assertEqual(m.origins(after, [self.c['public_origin']]), after)

    def test_nonroot_config_or_ancestor_rejected(self):
        for path in (self.file, self.file.parent):
            with self.subTest(path=path):
                self.owners[path] = 1000
                try:
                    with self.assertRaisesRegex(ValueError, 'root ownership'): m.read_config(self.file)
                finally: self.owners.clear()

    def test_writable_config_or_ancestor_rejected(self):
        for path, mode in ((self.file, 0o666), (self.file.parent, 0o775)):
            with self.subTest(path=path):
                previous = stat.S_IMODE(path.stat().st_mode); path.chmod(mode)
                try:
                    with self.assertRaisesRegex(ValueError, 'writable'): m.read_config(self.file)
                finally: path.chmod(previous)

    def test_symlink_file_and_ancestor_rejected(self):
        for path, destination in ((self.file.parent / 'link.json', self.file),
                                  (self.file.parent.parent / 'linked', self.file.parent)):
            path.symlink_to(destination)
            candidate = path if destination.is_file() else path / self.file.name
            with self.assertRaisesRegex(ValueError, 'symlink'): m.read_config(candidate)

    def test_relative_path_rejected(self):
        with self.assertRaisesRegex(ValueError, 'absolute'): m.read_config(Path('config.json'))


class ReceiptIntegrity(HostFixture):
    def setUp(self):
        super().setUp()
        self.release = self.host / 'release'
        asset = self.put(self.release / 'public/index.html', b'original')
        self.backend_name = 'usr/local/lib/woowtech-cockpit-backup/woowbackup/core.py'
        self.backend = self.put(self.host / self.backend_name, b'# engine')
        self.meta = {'files': {'public/index.html': m.digest(asset.read_bytes())},
                     'backend_hashes': {self.backend_name: m.digest(self.backend.read_bytes())}}
        self.put(self.release / 'receipt.json', json.dumps(self.meta).encode())
        for path in [self.release, *self.release.rglob('*')]:
            if path.is_dir(): path.chmod(0o755)

    def test_matching_release_and_backend_pass(self):
        self.assertEqual(m.audit_receipt(self.release, self.meta), [])

    def test_added_backend_module_and_public_asset_are_detected(self):
        self.put(self.backend.parent / 'injected.py')
        self.put(self.release / 'public/unrecorded.js')
        drift = m.audit_receipt(self.release, self.meta)
        self.assertIn('backend inventory', drift)
        self.assertIn('release inventory', drift)

    def test_hash_and_permission_drift_are_detected_independently(self):
        self.backend.write_bytes(b'# another engine')
        self.release.chmod(0o700)
        drift = m.audit_receipt(self.release, self.meta)
        self.assertIn(self.backend_name, drift)
        self.assertTrue(any('permissions' in item for item in drift))

    def test_symlink_asset_is_rejected_even_with_identical_bytes(self):
        asset = self.release / 'public/index.html'
        original = self.put(self.host / 'outside.html', asset.read_bytes())
        asset.unlink(); asset.symlink_to(original)
        self.assertTrue(any('permissions' in item for item in m.audit_receipt(self.release, self.meta)))


class OwnerQuadletWriter(HostFixture):
    def test_write_delete_and_symlink_rejection_use_owner_command(self):
        self.qpath.parent.mkdir(parents=True)
        calls = []

        def owner(owner, *args, **kwargs):
            self.assertEqual(owner, 'operator')
            self.assertEqual(args[:2], ('python3', '-c'))
            self.assertEqual(Path(args[3]), self.qpath)
            calls.append(args[-1])
            # Execute only the captured writer, as this test's unprivileged user.
            return REAL_RUN([sys.executable, *args[1:]], input=kwargs['input'],
                            check=True, capture_output=True)

        with patch.object(m, 'user_command', side_effect=owner):
            m.write_quadlet(self.c, self.qpath, b'original', mode=0o600)
            self.assertEqual(self.qpath.read_bytes(), b'original')
            self.assertEqual(stat.S_IMODE(self.qpath.stat().st_mode), 0o600)
            m.write_quadlet(self.c, self.qpath, b'replaced')
            self.assertEqual(self.qpath.read_bytes(), b'replaced')
            m.write_quadlet(self.c, self.qpath, None)
            self.assertFalse(self.qpath.exists())
            target = self.put(self.host / 'protected', b'unchanged', 0o600)
            self.qpath.symlink_to(target)
            for data in (b'hostile', None):
                with self.assertRaises(subprocess.CalledProcessError):
                    m.write_quadlet(self.c, self.qpath, data)
            self.assertEqual(target.read_bytes(), b'unchanged')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(calls, ['write', 'write', 'remove', 'write', 'remove'])


if __name__ == '__main__':
    unittest.main()
