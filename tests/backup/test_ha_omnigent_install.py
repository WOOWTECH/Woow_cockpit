"""Local candidate -> real import_manifest -> flows/adapter install and rollback.

Only owner transport, HTTP, conversion PG/snapshot, archive encryption are fixtures.
No adapter restore, safety backup, rollback, or preflight method is replaced.
"""
import io
import os
import tarfile
import types
from unittest import mock

from woowbackup import catalog, flows, haimport, podman
from woowbackup.adapters import quadlet_postgres as qp
from woowbackup.errors import BackupError
from . import hab1fakes as fk
from .test_adapter import FakeOwner, FakeClock, Q
from .test_catalog import demo_entry, lookup
from .test_ha_omnigent import QUADLETS, OmnigentCase
from . import test_ha_omnigent_candidate as candidate
from .tarfixtures import image_id


def contents(data):
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        return {m.name.removeprefix('./'): archive.extractfile(m).read()
                for m in archive if m.isfile()}


class InstallTests(OmnigentCase):
    world_class = candidate.CandidateWorld
    synthetic_snapshot = candidate.CandidateFlowTests.synthetic_snapshot

    def setUp(self):
        super().setUp()
        raw = demo_entry(self.paths)
        raw.update(id='omnigent', name='Omnigent', postgres=[], data_dirs=[],
                   volumes=[{'name': name} for name in ('omnigent-postgres-data', 'omnigent-server-data',
                                                       'omnigent-pi-data')],
                   secrets=[{'name': 'omnigent-postgres-password'}, {'name': 'omnigent-database-url'}],
                   config_files=[], verify=[],
                   units=['omnigent-postgres.service', 'omnigent-server.service', 'omnigent-runner.service'],
                   writer_units=['omnigent-postgres.service', 'omnigent-server.service', 'omnigent-runner.service'],
                   health=[{'type': 'http', 'url': 'http://127.0.0.1:8000/health', 'timeout_seconds': 1}])
        raw['quadlet'] = {'files': list(QUADLETS),
                          'template_dir': str(self.paths.templates / 'omnigent' / 'quadlet')}
        self.app = catalog.validate_entry(raw, paths=self.paths, user_lookup=lookup)
        self.catalog = {'omnigent': self.app}
        self.owner = FakeOwner(False)
        self.owner.files = {Q + name: data for name, data in QUADLETS.items()}
        self.owner.units = {unit: 'active' for unit in self.app.units}
        self.owner.after, self.owner.requires = {}, {}
        self.owner.secrets = {'omnigent-postgres-password': b'local-pg-secret\n',
                              'omnigent-database-url': b'local-db-url'}
        self.original_secrets = dict(self.owner.secrets)
        self.owner.volumes = {v['name']: self.world.export(v['name']) for v in self.app.volumes}
        self.original_volumes = {name: contents(data) for name, data in self.owner.volumes.items()}
        refs = [line.split('=', 1)[1] for data in QUADLETS.values()
                for line in data.decode().splitlines() if line.startswith('Image=')]
        for ref in refs:
            env = ['PG_MAJOR=16'] if 'postgres:' in ref else []
            self.owner.images[ref] = image_id(ref, env)
            self.owner.known_ids.add(image_id(ref, env))
            self.owner.image_env[ref] = env
        self.clock = FakeClock()
        self.fail_health = False
        self.fail_imports = 0
        self.failure_states = []
        original = self.owner.podman

        def transport(args, data, stdout):
            if args[:3] == ['volume', 'import', 'omnigent-pi-data'] and self.fail_imports:
                self.failure_states.append({name: contents(value) for name, value in self.owner.volumes.items()
                                            if value})
                self.fail_imports -= 1
                return podman.Result(1, b'', b'synthetic import failure')
            return original(args, data, stdout)
        self.owner.podman = transport

    def health(self, *args, **kwargs):
        server = self.owner.volumes.get('omnigent-server-data')
        candidate_cookie = server and contents(server).get('artifacts/accounts-cookie-secret') == b'f' * 64
        return (503 if self.fail_health and candidate_cookie else 200), b'local health fixture'

    def real_adapter(self, app, **kwargs):
        return qp.QuadletPostgresAdapter(app,
            podman.OwnerRunner('appowner', runner=self.owner, user_lookup=lookup),
            http_get=self.health,
            clock=self.clock.now, sleep=self.clock.sleep, runtime_ready=lambda: True,
            templates_uid=os.getuid(),
            statvfs=lambda _: types.SimpleNamespace(f_bavail=10**9, f_frsize=4096), **kwargs)

    def run_candidate(self, **kwargs):
        real = self.real_adapter(self.app, log=self.reporter.log)
        world = self.world

        class PackagingAdapter(fk.Adapter):
            def import_manifest(self, *args, **kw):
                return real.import_manifest(*args, **kw)

        self.deps.adapter_factory = lambda app, **kw: PackagingAdapter(app, world)
        params = {'source': 'ha', 'ha_backup_id': self.upload_omnigent(), 'apps': ['omnigent'],
                  'encrypt': True, 'test_mode': True, **kwargs}
        from woowbackup import ha_omnigent as omni
        with mock.patch.object(omni, 'capture_consistent_target_schema', self.synthetic_snapshot):
            result = haimport._run_omnigent_candidate(self.ctx(), params, schema_ddl_quiesced=True)
        self.deps.adapter_factory = self.real_adapter
        self.job_id = 'j20261121T120000Z-0123abcd'
        return result

    def test_candidate_installs_with_real_adapter_and_safety_backup(self):
        result = self.run_candidate()
        installed = haimport._install_omnigent_candidate(self.ctx(), result['backup_id'])
        self.assertTrue(installed['changed'])
        self.assertFalse(installed['rolled_back'])
        self.assertTrue(installed['safety_backup_id'])
        self.assertEqual(contents(self.owner.volumes['omnigent-server-data'])['artifacts/accounts-cookie-secret'],
                         b'f' * 64)
        self.assertEqual(contents(self.owner.volumes['omnigent-pi-data'])['auth.json'], b'pi-login')
        self.assertEqual(self.owner.secrets, self.original_secrets)
        self.assertFalse(self.owner.masked)

    def test_failed_install_restores_actual_volume_bytes_and_secrets(self):
        result = self.run_candidate()
        self.owner.secrets['omnigent-database-url'] = b'new-target-secret-before-install\n'
        before = dict(self.owner.secrets)
        self.fail_imports = 1
        with self.assertRaises(flows.RolledBack) as caught:
            haimport._install_omnigent_candidate(self.ctx(), result['backup_id'])
        self.assertEqual(self.failure_states[0]['omnigent-server-data']['artifacts/accounts-cookie-secret'],
                         b'f' * 64)
        self.assertTrue(caught.exception.result['rolled_back'])
        self.assertTrue(caught.exception.result['safety_backup_id'])
        self.assertEqual({name: contents(data) for name, data in self.owner.volumes.items()}, self.original_volumes)
        self.assertEqual(self.owner.secrets, before)
        self.assertFalse(self.owner.masked)
        self.assertTrue(all(self.owner.units[u] == 'active' for u in self.app.units))
        self.assertIn('rollback', self.reporter.phases())
        logs = '\n'.join(self.reporter.logs)
        for value in before.values():
            self.assertNotIn(value.decode().strip(), logs)

    def test_failed_rollback_reports_incomplete_and_retains_safety(self):
        result = self.run_candidate()
        self.fail_imports = 2
        with self.assertRaises(BackupError):
            haimport._install_omnigent_candidate(self.ctx(), result['backup_id'])
        self.assertFalse(self.reporter.partial.get('rolled_back', False))
        self.assertTrue(self.owner.masked)
        self.assertTrue(any(b['type'] == 'safety' for b in self.storage.list_backups()))

    def test_install_requires_registered_candidate_before_touch(self):
        with self.assertRaises(BackupError):
            haimport._install_omnigent_candidate(self.ctx(), 'missing')
        self.assertEqual(self.owner.calls, [])

    def test_corrupt_registry_refuses_before_owner_commands(self):
        haimport.registry_path(self.paths).write_text('{broken')
        with self.assertRaises(BackupError):
            haimport._install_omnigent_candidate(self.ctx(), 'missing')
        self.assertEqual(self.owner.calls, [])

    def test_health_failure_after_all_imports_rolls_back(self):
        result = self.run_candidate()
        self.fail_health = True
        with self.assertRaises(flows.RolledBack) as caught:
            haimport._install_omnigent_candidate(self.ctx(), result['backup_id'])
        self.assertTrue(caught.exception.result['rolled_back'])
        self.assertEqual({name: contents(data) for name, data in self.owner.volumes.items()}, self.original_volumes)
        self.assertEqual(self.owner.secrets, self.original_secrets)
        self.assertFalse(self.owner.masked)

    def test_registered_but_missing_secret_prevents_packaging(self):
        del self.owner.secrets['omnigent-database-url']
        with self.assertRaises(BackupError):
            self.run_candidate()
        self.assertEqual(self.storage.list_backups(), [])
        self.assertEqual({name: contents(data) for name, data in self.owner.volumes.items()}, self.original_volumes)
        self.assertFalse(any(call['argv'][:3] == [podman.SYSTEMCTL, '--user', 'stop']
                             for call in self.owner.calls))

    def test_other_app_origin_refuses_before_owner_commands(self):
        result = self.run_candidate()
        row = haimport.load_registry(self.paths)[result['backup_id']]
        row['apps'] = ['emqx']
        haimport.register(self.paths, result['backup_id'], row)
        self.owner.calls.clear()
        with self.assertRaises(BackupError) as caught:
            haimport._install_omnigent_candidate(self.ctx(), result['backup_id'])
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertEqual(self.owner.calls, [])

    def test_missing_images_refuses_before_stopping_writers(self):
        result = self.run_candidate()
        self.owner.images.clear()
        self.owner.known_ids.clear()
        self.owner.calls.clear()
        with self.assertRaises(BackupError):
            haimport._install_omnigent_candidate(self.ctx(), result['backup_id'])
        self.assertEqual({name: contents(data) for name, data in self.owner.volumes.items()}, self.original_volumes)
        self.assertEqual(self.owner.secrets, self.original_secrets)
        self.assertFalse(self.owner.masked)
        self.assertTrue(all(self.owner.units[u] == 'active' for u in self.app.units))
        self.assertFalse(any(call['argv'][:3] == [podman.SYSTEMCTL, '--user', 'stop']
                             for call in self.owner.calls))
        self.assertNotIn('safety', self.reporter.phases())

    def test_failed_safety_export_restarts_writers_without_candidate_import(self):
        result = self.run_candidate()
        self.owner.calls.clear()
        self.owner.fail = [('volume export omnigent-pi-data', 1)]
        with self.assertRaises(BackupError) as caught:
            haimport._install_omnigent_candidate(self.ctx(), result['backup_id'])
        self.assertTrue(caught.exception.result['safety_failed'])
        self.assertFalse(caught.exception.result['changed'])
        self.assertEqual({name: contents(data) for name, data in self.owner.volumes.items()}, self.original_volumes)
        self.assertEqual(self.owner.secrets, self.original_secrets)
        self.assertFalse(self.owner.masked)
        self.assertTrue(all(self.owner.units[u] == 'active' for u in self.app.units))
        self.assertFalse(any(call['argv'][:3] == [podman.PODMAN, 'volume', 'import']
                             for call in self.owner.calls))
        self.assertNotIn('rollback', self.reporter.phases())
