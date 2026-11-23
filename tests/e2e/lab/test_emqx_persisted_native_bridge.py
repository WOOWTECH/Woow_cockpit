"""Optional Mencius integration; actual synthetic native files, never real HA.

Requires matching cold-history/semantic-reader revision. Does not copy/change
native code. DETS and disk_log results are reported separately.
"""
import hashlib
import importlib.util
import inspect
import io
from pathlib import Path
import tempfile
import unittest

from emqx_private_boundary import PrivateFailure
from emqx_persisted_values import capture_cold_persisted_values
from emqx_semantic_readers import _term

READY = (importlib.util.find_spec('emqx_cold_history') is not None
         and 'historical' in inspect.signature(_term).parameters)


@unittest.skipUnless(READY, 'requires matching Mencius cold-history dependency')
class NativeBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import emqx_cold_history as native
        from emqx_native_runtime import run_native
        cls.native = native
        cls.temp = tempfile.TemporaryDirectory(prefix='emqx-companion-native-synthetic-')
        cls.root = Path(cls.temp.name)
        code = cls.root / 'code'; code.mkdir(mode=0o700)
        script = Path(native.__file__).with_name('emqx_cold_fixture.escript')
        (code / script.name).write_bytes(script.read_bytes())
        with tempfile.TemporaryFile() as output:
            status = run_native(code, script.name, writable_directory=cls.root, output=output)
        if status:
            cls.temp.cleanup()
            raise AssertionError('synthetic native fixture creation failed')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def bridge(self, files):
        raw = {name: (self.root / 'fixtures' / name).read_bytes() for name in files}
        expected = {name: {'kind': kind, 'bytes': len(raw[name]),
                          'sha256': hashlib.sha256(raw[name]).hexdigest()}
                    for name, kind in files.items()}
        finished = []
        companion = capture_cold_persisted_values(expected=expected,
            private_file=lambda name: io.BytesIO(raw[name]),
            finish_inventory=lambda: finished.append(True),
            generation='synthetic-native-generation', decoder=self.native.native_cold_history)
        self.assertEqual(finished, [True])
        return companion

    def test_actual_native_schema_values_reach_companion_fullscan(self):
        companion = self.bridge({'schema.DAT': 'schema-dat'})
        for value in (b'schema-private-history', b'emqx_admin_jwt'):
            with self.assertRaises(PrivateFailure):
                companion.scan(value)

    def test_actual_native_disklog_history_reaches_companion_fullscan(self):
        companion = self.bridge({'table.DCD': 'dcd', 'table.DCL': 'dcl',
                                 'LATEST.LOG': 'transaction-log'})
        for value in (b'old-dump-private', b'new-log-private', b'deleted-charlist-private', b'1.25'):
            with self.assertRaises(PrivateFailure):
                companion.scan(value)
