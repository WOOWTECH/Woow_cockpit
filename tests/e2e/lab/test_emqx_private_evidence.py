"""Real filesystem evidence boundary, generated secrets; no broker claims."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from emqx_private_boundary import Registry, SOURCES, PrivateFailure
from emqx_private_evidence import publish


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.coverage = dict.fromkeys(SOURCES, 0)
        self.registry = Registry()
        for source in SOURCES:
            self.registry.register(source, [b'generated-private-token'] if source == 'backup-key' else [])
        self.registry.seal()

    def write(self, **kwargs):
        args = dict(registry=self.registry, phase='mqtt', result='passed', coverage=self.coverage)
        args.update(kwargs)
        return publish(self.root, 'mqtt.json', **args)

    def test_actual_scan_and_written_bytes_match_and_file_private(self):
        seen = []
        scan = self.registry.scan
        def checked(raw):
            self.assertFalse((self.root / 'mqtt.json').exists())
            scan(raw)
            seen.append(raw)
        with patch.object(self.registry, 'scan', side_effect=checked):
            self.assertTrue(self.write()['scanned'])
        path = self.root / 'mqtt.json'
        self.assertEqual(path.read_bytes(), seen[0])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(path.read_bytes())['coverage'], self.coverage)

    def test_names_only_evidence_keeps_numeric_secrets_blocked_without_emitting_counts(self):
        registry = Registry()
        for source in SOURCES:
            registry.register(source, [b'0', b'1', b'true'] if source == 'backup-key' else [])
        registry.seal()
        with self.assertRaises(PrivateFailure):
            self.write(registry=registry)
        self.assertEqual(list(self.root.iterdir()), [])
        self.write(registry=registry, coverage_mode='names')
        raw = (self.root / 'mqtt.json').read_bytes()
        registry.scan(raw)
        self.assertEqual(json.loads(raw)['coverage'], sorted(SOURCES))
        self.assertNotIn(b'0', raw)
        self.assertNotIn(b'1', raw)
        with self.assertRaises(PrivateFailure):
            registry.scan(b'1')  # No short secret exemption or scanner weakening.

    def test_leak_or_missing_registration_creates_no_evidence(self):
        for registry in (Registry(), self.registry):
            if registry is self.registry:
                registry = Registry()
                for source in SOURCES:
                    registry.register(source, [b'passed'] if source == 'backup-key' else [])
                registry.seal()
            with self.subTest(registry=repr(registry)), self.assertRaises(PrivateFailure):
                self.write(registry=registry)
            self.assertEqual(list(self.root.iterdir()), [])

    def test_missing_source_bad_count_and_arbitrary_text_refused(self):
        for changes in ({'coverage': {}}, {'coverage': dict(self.coverage, tls=True)},
                        {'result': 'generated-private-token'}, {'phase': '../secret'}):
            with self.subTest(changes=changes), self.assertRaises(PrivateFailure):
                self.write(**changes)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_file_symlink_and_public_directory_refused(self):
        original = self.root / 'mqtt.json'
        original.write_bytes(b'existing')
        with self.assertRaises(PrivateFailure):
            self.write()
        self.assertEqual(original.read_bytes(), b'existing')
        original.unlink()
        original.symlink_to(self.root / 'elsewhere')
        with self.assertRaises(PrivateFailure):
            self.write()
        self.assertFalse((self.root / 'elsewhere').exists())
        original.unlink()
        self.root.chmod(0o755)
        with self.assertRaises(PrivateFailure):
            self.write()

    def test_failed_write_removes_owned_partial_and_masks_error(self):
        with patch('emqx_private_evidence.os.fsync', side_effect=OSError('generated-private-token')):
            with self.assertRaisesRegex(PrivateFailure, '^private-evidence-refused$'):
                self.write()
        self.assertEqual(list(self.root.iterdir()), [])
