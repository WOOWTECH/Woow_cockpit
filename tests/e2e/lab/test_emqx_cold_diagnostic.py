"""Actual offline native fixed-phase diagnostics; generated data only."""
import json
from pathlib import Path
import tempfile
import unittest
from emqx_native_runtime import run_native
from emqx_cold_history import native_cold_diagnostic, native_cold_history
from emqx_semantic_readers import SemanticRefused


class DiagnosticTests(unittest.TestCase):
    def test_fixed_phases_never_return_private_terms_or_open_a_recovery_gate(self):
        with tempfile.TemporaryDirectory(prefix='emqx-native-diagnostic-test-') as directory:
            root = Path(directory)
            code = root / 'code'
            code.mkdir(mode=0o700)
            script = Path(__file__).with_name('emqx_cold_fixture.escript')
            (code / script.name).write_bytes(script.read_bytes())
            with tempfile.TemporaryFile() as output:
                self.assertEqual(run_native(code, script.name, writable_directory=root, output=output), 0)
            fixtures = root / 'fixtures'
            valid = (fixtures / 'schema.DAT').read_bytes()
            self.assertEqual(native_cold_diagnostic(valid, 'schema-dat'),
                             {'phase':'COMPLETE','result':'PASSED'})
            # Production still emits the full private contract only to its caller.
            self.assertIn(b'emqx-cold-history-json-v1', native_cold_history(valid, 'schema-dat'))
            for filename, kind, phase in (
                    ('backend-schema.DAT','schema-dat','SCHEMA_BACKEND_UNREVIEWED_MODULE'),
                    ('pid.DCL','dcl','UNSUPPORTED_PID')):
                raw = (fixtures / filename).read_bytes()
                result = native_cold_diagnostic(raw, kind)
                self.assertEqual(result, {'phase':phase,'result':'REFUSED'})
                self.assertNotIn(b'private', json.dumps(result).encode())
                with self.assertRaises(SemanticRefused):
                    native_cold_history(raw, kind)
            self.assertFalse((root / 'EXECUTED').exists())
