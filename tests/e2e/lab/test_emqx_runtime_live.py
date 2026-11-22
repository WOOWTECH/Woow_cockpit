"""Boundary regression only; live broker evidence is produced by the lab wrapper."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from emqx_private_boundary import PrivateFailure
from emqx_runtime_credentials import RuntimeRegistry, login_registered
from emqx_runtime_live import publish_login


class RuntimeOnlyTests(unittest.TestCase):
    def registered(self):
        registry = RuntimeRegistry()
        login_registered(registry, lambda *_: (200, 'application/json', io.BytesIO(
            json.dumps({'token': 'generated-unit-token-private'}).encode())),
            username=b'generated-unit-user', password=b'generated-unit-password')
        return registry

    def test_runtime_scan_does_not_enable_full_scan_or_summary(self):
        registry = self.registered()
        registry.scan_login_evidence(b'fixed-status')
        for operation in (lambda: registry.scan(b'fixed-status'), registry.summary):
            with self.assertRaises(PrivateFailure):
                operation()

    def test_no_login_no_publication(self):
        with tempfile.TemporaryDirectory() as work:
            with self.assertRaises(PrivateFailure):
                publish_login(Path(work), RuntimeRegistry())
            self.assertEqual(list(Path(work).iterdir()), [])

    def test_exact_bytes_and_exclusive_file(self):
        registry = self.registered()
        with tempfile.TemporaryDirectory() as work:
            directory = Path(work)
            raw = publish_login(directory, registry)
            self.assertEqual((directory / 'runtime-login.json').read_bytes(), raw)
            with self.assertRaises(FileExistsError):
                publish_login(directory, registry)
            self.assertEqual((directory / 'runtime-login.json').read_bytes(), raw)

    def test_scan_failure_before_create(self):
        registry = self.registered()
        with tempfile.TemporaryDirectory() as work:
            with patch.object(registry, 'scan_login_evidence', side_effect=PrivateFailure('refused')):
                with self.assertRaises(PrivateFailure):
                    publish_login(Path(work), registry)
            self.assertEqual(list(Path(work).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
