"""Incremental safety checks for the native probe; no network/Podman."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native_arm_archive as probe


class NativeProbeSafetyTests(unittest.TestCase):
    def test_reserve_refuses_before_work(self):
        with patch.object(probe.shutil, 'disk_usage', return_value=SimpleNamespace(free=probe.RESERVE)):
            with self.assertRaisesRegex(RuntimeError, '^capacity-reserve-refused$'):
                probe.capacity(Path('/unused'))

    def test_arm_gate_precedes_archive_access(self):
        with patch.object(probe.platform, 'machine', return_value='x86_64'):
            with self.assertRaisesRegex(RuntimeError, '^native-arm-required$'):
                probe.unpack(Path('/unused'), Path('/unread'), Path('/unread'), require_arm=True)

    def test_transfer_digest_mismatch_does_not_create_extraction_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = root / 'expected.json'
            expected.write_text(json.dumps({'archive_sha256': '0' * 64}))
            source = root / 'synthetic.tar'
            source.write_bytes(b'synthetic-corrupted-transfer')
            with self.assertRaisesRegex(RuntimeError, '^archive-transfer-sha256-mismatch$'):
                probe.unpack(root, expected, source, require_arm=False)
            self.assertFalse((root / 'unpacked').exists())
