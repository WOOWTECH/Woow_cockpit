"""Offline boundaries of the leased original LiteLLM instance controller."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CatalogRecovery(unittest.TestCase):
    def test_raw_original_and_permissions_return_after_instance_cas(self):
        ops = load('focus_litellm_instance_acceptance_ops')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root/'litellm.json'
            original = b'{ "schema": 1, "id": "litellm" }\n'
            path.write_bytes(original); path.chmod(0o640)
            store = ops.Store('woowbk_focus_litellm_012345abcdef', parent=root/'private', create=True)
            store.capture([str(path)])
            store.authorize(str(path), b'{"id":"litellm","postgres":[{"scope":"instance"}]}\n')
            path.write_bytes(b'{"id":"litellm","postgres":[{"scope":"instance"}]}\n')
            store.restore([str(path)])
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_foreign_catalog_edit_refuses_restoration_without_overwrite(self):
        ops = load('focus_litellm_instance_acceptance_ops')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root/'litellm.json'; path.write_bytes(b'original')
            store = ops.Store('woowbk_focus_litellm_012345abcdef', parent=root/'private', create=True)
            store.capture([str(path)]); store.authorize(str(path), b'owned-instance')
            path.write_bytes(b'foreign');
            with self.assertRaisesRegex(ValueError, 'outside'):
                store.restore([str(path)])
            self.assertEqual(path.read_bytes(), b'foreign')

    def test_initially_absent_catalog_removed_only_at_owned_hash(self):
        ops = load('focus_litellm_instance_acceptance_ops')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root/'litellm.json'
            store = ops.Store('woowbk_focus_litellm_012345abcdef', parent=root/'private', create=True)
            store.capture([str(path)])
            store.authorize(str(path), b'owned'); path.write_bytes(b'owned')
            store.restore([str(path)]); self.assertFalse(path.exists())


class InstanceContract(unittest.TestCase):
    def test_changes_only_scope_and_maintenance_database_input(self):
        p = load('focus_litellm_instance_acceptance')
        entry = {'id':'litellm','owner':'appowner','adapter':'quadlet-postgres',
                 'postgres':[{'id':'main','container':'litellm-postgres','unit':'litellm-postgres.service',
                              'database':'litellm','user':'litellm','data_volume':'litellm-pgdata'}],
                 'secrets':[{'name':'litellm-salt-key'}]}
        original = json.loads(json.dumps(entry)); changed = p.instance_entry(entry)
        self.assertEqual(entry, original)
        self.assertEqual(changed['postgres'][0]['scope'], 'instance')
        self.assertNotIn('database', changed['postgres'][0])
        changed['postgres'][0].pop('scope'); changed['postgres'][0]['database']='litellm'
        self.assertEqual(changed, original)


if __name__ == '__main__':
    unittest.main()
