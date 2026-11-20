"""Synthetic fixtures only; tests never read a real device or service."""
import base64
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('private_sources', Path(__file__).with_name('headscale-private-sources.py'))
private = importlib.util.module_from_spec(spec)
spec.loader.exec_module(private)


class PrivateSourceTest(unittest.TestCase):
    def test_private_pem_contains_actual_material_and_lines(self):
        body = base64.b64encode(b'actual-synthetic-test-key-material-1234567890').decode()
        pem = ('-----BEGIN PRIVATE KEY-----\n' + body + '\n-----END PRIVATE KEY-----\n').encode()
        values = private.pem_values(pem)
        self.assertIn(body, values)
        self.assertIn(pem.decode().strip(), values)
        with self.assertRaises(ValueError):
            private.pem_values(b'-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----')

    def test_state_extracts_nested_actual_private_keys_but_not_hashes(self):
        machine = 'privkey:' + 'a' * 64
        node = 'privkey:' + 'b' * 64
        encoded = base64.b64encode(json.dumps({'PrivateNodeKey': node, 'hash': 'c' * 64}).encode()).decode()
        state = json.dumps({'_machinekey': base64.b64encode(machine.encode()).decode(), 'profile': encoded}).encode()
        values = private.client_keys(state)
        self.assertIn(machine, values)
        self.assertIn(node, values)
        self.assertNotIn('c' * 64, values)
        with self.assertRaises(ValueError):
            private.client_keys(json.dumps({'PrivateNodeKey': node, 'hash': 'c' * 64}).encode())
        with self.assertRaises(ValueError):
            private.client_keys(json.dumps({'PrivateNodeKey': node, 'PrivateOldNodeKey': machine}).encode())

    def test_empty_corrupt_or_ambiguous_volume_private_key_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'data.tar'
            with tarfile.open(path, 'w') as archive:
                for value in (b'privkey:' + b'1' * 64, b'privkey:' + b'2' * 64):
                    info = tarfile.TarInfo('noise.key'); info.size = len(value)
                    archive.addfile(info, io.BytesIO(value))
            with self.assertRaises(ValueError):
                private.volume_key(path, 'noise.key')
            with self.assertRaises(ValueError):
                private.volume_key(path, 'missing.key')
        with self.assertRaises(ValueError):
            private.private_key(b'')
        with self.assertRaises(ValueError):
            private.private_key(b'privkey:' + b'0' * 64)

    def test_failed_extractor_suppresses_source_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state'
            path.write_text('sensitive-unparsed-synthetic-content')
            result = subprocess.run([sys.executable, private.__file__, 'client', str(path)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')
            self.assertNotIn(b'sensitive-unparsed', result.stderr)


if __name__ == '__main__':
    unittest.main()
