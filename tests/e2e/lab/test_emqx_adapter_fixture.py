"""Pure offline fixture-boundary tests; no Podman or lab access."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
import tempfile
from unittest.mock import patch

from woowbackup import catalog
from woowbackup.paths import Paths

spec = importlib.util.spec_from_file_location('emqx_adapter_fixture', Path(__file__).with_name('emqx_adapter_fixture.py'))
fixture = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = fixture
spec.loader.exec_module(fixture)


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.Fixture('woowbk-emqxlab-aabb0011', 'appowner',
                                 fixture.IMAGE_ID_PREFIX + '0' * 52)
        self.inspection = {'Name': '/' + self.f.prefix,
                           'Image': 'sha256:' + self.f.image_id,
                           'HostConfig': {'NetworkMode': 'none', 'PortBindings': {},
                                          'Memory': 768 * 1024 * 1024, 'NanoCpus': 1_000_000_000},
                           'Mounts': [{'Type': 'volume', 'Name': name} for name in self.f.volumes]}

    def test_catalog_is_valid_and_unit_has_no_published_port(self):
        user = SimpleNamespace(pw_uid=1019, pw_gid=1019, pw_dir='/home/' + self.f.owner)
        app = catalog.validate_entry(self.f.catalog(), paths=Paths(base=Path('/tmp/fixture')),
                                     user_lookup=lambda name: user)
        self.assertEqual(app.units, (self.f.unit,))
        unit = self.f.container_unit()
        self.assertIn('Network=none\n', unit)
        self.assertIn('--memory=768m --cpus=1', unit)
        self.assertNotIn('PublishPort=', unit)

    def test_rejects_non_synthetic_owner_and_namespace(self):
        for prefix, owner in [('emqx', 'appowner'), (self.f.prefix, 'root'),
                              ('woowbk-emqxlab-../../x', 'woowbk-emqxlab-../../x')]:
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                fixture.Fixture(prefix, owner, self.f.image_id)
        with self.assertRaises(ValueError):
            fixture.Fixture(self.f.prefix, self.f.owner, fixture.IMAGE_ID_PREFIX)

    def test_inspection_requires_isolated_resources(self):
        self.f.validate_inspection(self.inspection)
        import copy
        for mutate in (lambda x: x['HostConfig'].update(NetworkMode='host'),
                       lambda x: x['HostConfig'].update(PortBindings={'1883/tcp': [{}]}),
                       lambda x: x['HostConfig'].update(Memory=0),
                       lambda x: x['HostConfig'].update(NanoCpus=0),
                       lambda x: x['Mounts'].append({'Type': 'volume', 'Name': 'production'}),
                       lambda x: x.update(Image='sha256:' + '0' * 64),
                       lambda x: x.update(Name='emqx')):
            candidate = copy.deepcopy(self.inspection)
            mutate(candidate)
            with self.assertRaises(ValueError):
                self.f.validate_inspection(candidate)

    def test_real_adapter_entry_points_are_ordered_after_isolation_checks(self):
        from woowbackup.podman import OwnerRunner
        user = SimpleNamespace(pw_uid=1019, pw_gid=1019, pw_dir='/home/' + self.f.owner)
        app = catalog.validate_entry(self.f.catalog(), paths=Paths(base=Path('/tmp/fixture')),
                                     user_lookup=lambda name: user)
        runner = OwnerRunner(self.f.owner, user_lookup=lambda name: user)
        volumes = {name: Path('/tmp') / (name + '.tar') for name in self.f.volumes}
        with tempfile.TemporaryDirectory() as directory, patch(
                'woowbackup.adapters.quadlet_postgres.QuadletPostgresAdapter') as adapter_type:
            adapter = adapter_type.return_value
            candidate, safety = object(), object()
            adapter.import_manifest.return_value = candidate
            adapter.backup.return_value = safety
            stage = Path(directory) / 'staging'
            with self.assertRaises(ValueError):
                fixture.prepare_adapter_inputs(self.f, app, runner, self.inspection, 'wrong', volumes, stage)
            adapter_type.assert_not_called()
            self.assertFalse(stage.exists())
            actual = fixture.prepare_adapter_inputs(self.f, app, runner, self.inspection, '5.8.9', volumes, stage)
            self.assertEqual(actual, (adapter, candidate, safety))
            adapter.import_manifest.assert_called_once_with(stage / 'candidate', volumes=volumes)
            adapter.backup.assert_called_once_with(stage / 'safety', include_images=False)


if __name__ == '__main__':
    unittest.main()
