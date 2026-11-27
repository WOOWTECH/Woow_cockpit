"""Real evidence files; device OS/journal boundary is a fixture, not lab proof."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('encoding_driver', Path(__file__).with_name('ha_import_b1_e2e.py'))
b1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b1)


class EncodingTests(unittest.TestCase):
    def test_host_detects_raw_and_both_json_encodings_in_keys_and_values(self):
        token = 'synthetic-"\\\n-金鑰-secret'
        secrets = SimpleNamespace(secret_values=lambda: [token])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for encoded in (token.encode(), *(json.dumps({token: [token]}, ensure_ascii=a).encode() for a in (False, True))):
                with self.subTest(encoded_form=len(encoded)):
                    (root / 'evidence.json').write_bytes(encoded)
                    self.assertGreater(b1.scan_host_evidence(root, secrets)['hits'], 0)
            (root / 'evidence.json').write_text('{"detail":"<MASKED>"}')
            self.assertEqual(b1.scan_host_evidence(root, secrets)['hits'], 0)

    def test_raw_only_scanner_mutation_misses_fixture(self):
        token = 'synthetic-"\\\n-secret'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'evidence.json').write_text(json.dumps({'detail': token}))
            secrets = SimpleNamespace(secret_values=lambda: [token])
            self.assertGreater(b1.scan_host_evidence(root, secrets)['hits'], 0)
            with patch.object(b1, 'secret_scan_needles', return_value={token.encode()}):
                self.assertEqual(b1.scan_host_evidence(root, secrets)['hits'], 0)

    def test_device_program_detects_encoded_file_and_journal(self):
        token = 'synthetic-"\\\n-金鑰-secret'
        for location in ('file', 'journal'):
            with self.subTest(location=location):
                data = json.dumps({'detail': token}).encode()
                request = json.dumps({'secrets': {'issued': token}, 'podman_secrets': [], 'uid': 1019})
                output = io.StringIO()
                with patch('sys.stdin', io.StringIO(request)), contextlib.redirect_stdout(output), \
                     patch('os.path.exists', return_value=True), patch('os.path.islink', return_value=False), \
                     patch('os.path.isfile', return_value=True), \
                     patch('builtins.open', side_effect=lambda *a, **k: io.BytesIO(data if location == 'file' else b'clean')), \
                     patch('subprocess.run', return_value=SimpleNamespace(stdout=data if location == 'journal' else b'')):
                    exec(compile(b1.LEAK_SCAN, '<device-scan-fixture>', 'exec'), {})
                summary = json.loads(output.getvalue())
                self.assertGreater(summary['hits'], 0)
                self.assertNotIn(token, output.getvalue())
                self.assertEqual(summary['names'], 1)


if __name__ == '__main__':
    unittest.main()
