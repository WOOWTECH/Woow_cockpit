"""Pinned public schema only; no broker startup, Mnesia or private file reads."""
from pathlib import Path
import tempfile
import unittest
from emqx_native_runtime import run_native
from woowbackup.ha_emqx_authorizers import builtin_database_references

class NativeBuiltinSchemaTests(unittest.TestCase):
    def test_native_schema_accepts_both_exact_python_profiles(self):
        for enabled in (True,False):
            self.assertEqual(builtin_database_references({'type':'built_in_database','enable':enabled}),frozenset())
        name='emqx_builtin_authorizer_schema_fixture.escript'
        with tempfile.TemporaryDirectory(prefix='emqx-public-builtin-schema-') as directory,tempfile.TemporaryFile() as output:
            root=Path(directory)
            (root/name).write_bytes(Path(__file__).with_name(name).read_bytes())
            code=run_native(root,name,output=output)
            output.seek(0);raw=output.read(65537)
        self.assertEqual(code,0,'pinned builtin schema profile refused')
        self.assertEqual(raw,b'FIXED_BUILTIN_SCHEMA_PASS')
