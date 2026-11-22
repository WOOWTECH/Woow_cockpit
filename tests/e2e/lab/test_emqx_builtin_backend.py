"""Actual native traversal of pinned built-in metadata, never backend execution."""
from pathlib import Path
import tempfile
import unittest
from emqx_native_runtime import run_native
from emqx_cold_history import read_cold_history, native_cold_history, native_cold_diagnostic
from emqx_semantic_readers import SemanticRefused


class BuiltinBackendTests(unittest.TestCase):
    def test_exact_builtin_alias_is_data_unknown_modules_and_duplicates_still_refuse(self):
        with tempfile.TemporaryDirectory(prefix='emqx-builtin-backend-test-') as directory:
            root=Path(directory);code=root/'code';code.mkdir(mode=0o700)
            script=Path(__file__).with_name('emqx_cold_fixture.escript')
            (code/script.name).write_bytes(script.read_bytes())
            with tempfile.TemporaryFile() as output:
                self.assertEqual(run_native(code,script.name,writable_directory=root,output=output),0)
            fixtures=root/'fixtures'
            values=read_cold_history((fixtures/'builtin-backend-schema.DAT').read_bytes(),
                                     'schema-dat',native_cold_history).values
            self.assertIn(b'rocksdb_copies',values)
            self.assertIn(b'mnesia_rocksdb',values)
            extra=read_cold_history((fixtures/'builtin-pairset-schema.DAT').read_bytes(),
                                   'schema-dat',native_cold_history).values
            self.assertIn(b'mria_mnesia_null_storage',extra)
            for filename in ('duplicate-builtin-backend-schema.DAT','backend-schema.DAT','wrong-builtin-backend-schema.DAT',
                             'duplicate-backend-schema.DAT'):
                with self.subTest(filename=filename),self.assertRaises(SemanticRefused):
                    read_cold_history((fixtures/filename).read_bytes(),'schema-dat',native_cold_history)
            self.assertFalse((root/'EXECUTED').exists())
