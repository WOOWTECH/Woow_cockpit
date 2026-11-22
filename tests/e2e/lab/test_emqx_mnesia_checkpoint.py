"""Actual synthetic native checkpoint export; no lab or production mounts."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from emqx_native_runtime import run_native
from emqx_checkpoint_json import read_owned_checkpoint_export
from emqx_semantic_readers import TABLES, SemanticRefused, read_mnesia

HERE = Path(__file__).parent


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='emqx-checkpoint-synthetic-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.code = self.root / 'code'
        self.code.mkdir(mode=0o700)
        self.work = self.root / 'work'
        self.work.mkdir(mode=0o700)
        for name in ('emqx_mnesia_checkpoint.erl', 'emqx_mnesia_fixture.escript',
                     'emqx_mnesia_export.escript'):
            (self.code / name).write_bytes((HERE / name).read_bytes())

    def fixture(self, scenario='good', table='emqx_authn_mnesia'):
        with tempfile.TemporaryFile() as output:
            return run_native(self.code, 'emqx_mnesia_fixture.escript', (table, scenario),
                              writable_directory=self.work, output=output)

    def test_actual_native_checkpoint_all_pinned_tables_and_safe_json_readback(self):
        for table in TABLES:
            with self.subTest(table=table):
                self.assertEqual(self.fixture(table=table), 0)
                raw = (self.work / 'source.checkpoint').read_bytes()
                path = self.work / 'export.json'
                document = json.loads(path.read_bytes())
                self.assertTrue(document['complete'])
                self.assertTrue(document['schema_validated'])
                self.assertEqual(document['input_sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(document['input_bytes'], len(raw))
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                values = read_owned_checkpoint_export(raw, table, path).values
                for secret in (b'fixture-user', b'fixture-map-key', b'fixture-private-binary',
                               b'fixture-private-charlist', b'synthetic_atom', b'nested'):
                    self.assertIn(secret, values)
                self.assertFalse((self.work / 'export.json.partial').exists())
                # Fresh isolated DB for the next actual checkpoint.
                import shutil
                shutil.rmtree(self.work)
                self.work.mkdir(mode=0o700)

    def test_empty_checkpoint_is_complete_not_missing_schema(self):
        self.assertEqual(self.fixture('empty'), 0)
        raw = (self.work / 'source.checkpoint').read_bytes()
        self.assertEqual(read_owned_checkpoint_export(
            raw, 'emqx_authn_mnesia', self.work / 'export.json').values, ())

    def test_native_unsafe_terms_bounds_schema_and_corruption_refuse_no_output(self):
        import shutil
        for scenario in ('fun', 'pid', 'ref', 'port', 'improper', 'float',
                         'huge_integer', 'deep', 'oversize', 'wrong_schema',
                         'extra_schema', 'duplicate_schema', 'late_unknown',
                         'truncated', 'trailing'):
            with self.subTest(scenario=scenario):
                try:
                    self.assertEqual(self.fixture(scenario), 2)
                    self.assertFalse((self.work / 'export.json').exists())
                    self.assertFalse((self.work / 'export.json.partial').exists())
                finally:
                    shutil.rmtree(self.work)
                    self.work.mkdir(mode=0o700)

    def test_atomic_publication_no_overwrite_and_actual_owner_entrypoint(self):
        self.assertEqual(self.fixture(), 0)
        target = self.work / 'export.json'
        original = target.read_bytes()
        with tempfile.TemporaryFile() as output:
            self.assertEqual(run_native(self.code, 'emqx_mnesia_export.escript',
                ('--owner-created-checkpoint', 'emqx_authn_mnesia',
                 '/work/source.checkpoint', '/work/export.json'),
                writable_directory=self.work, output=output), 2)
        self.assertEqual(target.read_bytes(), original)
        self.assertFalse((self.work / 'export.json.partial').exists())
        target.unlink()
        with tempfile.TemporaryFile() as output:
            self.assertEqual(run_native(self.code, 'emqx_mnesia_export.escript',
                ('--owner-created-checkpoint', 'emqx_authn_mnesia',
                 '/work/source.checkpoint', '/work/export.json'),
                writable_directory=self.work, output=output), 0)
        self.assertEqual(json.loads(target.read_bytes()), json.loads(original))

    def test_json_binding_permissions_links_and_trailing_content_refuse(self):
        self.assertEqual(self.fixture(), 0)
        target = self.work / 'export.json'
        original = target.read_bytes()
        raw = (self.work / 'source.checkpoint').read_bytes()
        for bad in (raw+b'x', b'cold-DAT-is-not-a-checkpoint'):
            with self.assertRaises(SemanticRefused):
                read_owned_checkpoint_export(bad, 'emqx_authn_mnesia', target)
        # Default raw-source path still cannot invoke any native decoder.
        with self.assertRaises(SemanticRefused):
            read_mnesia(raw, 'emqx_authn_mnesia')
        target.chmod(0o644)
        with self.assertRaises(SemanticRefused):
            read_owned_checkpoint_export(raw, 'emqx_authn_mnesia', target)
        target.chmod(0o600)
        os.link(target, self.work / 'second-link')
        with self.assertRaises(SemanticRefused):
            read_owned_checkpoint_export(raw, 'emqx_authn_mnesia', target)
        (self.work / 'second-link').unlink()
        link = self.work / 'link'
        link.symlink_to(target)
        with self.assertRaises(SemanticRefused):
            read_owned_checkpoint_export(raw, 'emqx_authn_mnesia', link)
        target.write_bytes(original + b' {}')
        with self.assertRaises(SemanticRefused):
            read_owned_checkpoint_export(raw, 'emqx_authn_mnesia', target)
