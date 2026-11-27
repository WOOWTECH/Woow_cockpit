"""Small real-file/archive boundary tests. NOT native SSE or import acceptance.

The tiny cluster/key bytes below are structural unit inputs, never released as
an S5 fixture. Runtime proof still requires actual OCC/WebDAV/cipher/key/PG gates.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'e2e/lab'))
import focus_nextcloud_r6_s5 as s5
from woowbackup import habackup


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)/'owned'; self.work.mkdir(mode=0o700)
        for path in ('html/config', 'html/custom_apps', 'pg', 'data'):
            (self.work/path).mkdir(parents=True)
        self.write('pg/PG_VERSION', b'16\n')
        self.write('pg/base/1/123', b'structural unit input only')
        self.write('html/config/config.php', b'''<?php
$CONFIG = array ('instanceid' => 'ocs5structural', 'passwordsalt' => 'unit-salt',
'secret' => 'unit-secret', 'version' => '35.0.1.1', 'installed' => true,
'dbtype' => 'pgsql', 'dbtableprefix' => 'oc_', 'dbname' => 'nextcloud',
'datadirectory' => '/share/nextcloud');
''')
        self.write('data/.ncdata', b'# Nextcloud data directory')
        # A >1MiB file exercises repeated bounded reads through the actual writer.
        self.write('data/s5owner/files/s5-binary.bin', b'x'*(3*s5.MIB+7))
        self.write('data/files_encryption/OC_DEFAULT_MODULE/master_unit.privateKey', b'unit-key-not-native')
        self.proof = {'webdav_before': True, 'webdav_after_restart': True, 'master_key_enabled': True,
                      'pg_shutdown': True, 'cipher_and_keys': {}}
        for name in ('s5owner/files/s5-binary.bin', 'files_encryption/OC_DEFAULT_MODULE/master_unit.privateKey'):
            p = self.work/'data'/name
            self.proof['cipher_and_keys'][name] = {'bytes': p.stat().st_size, 'sha256': s5.digest(p)}

    def write(self, name, raw):
        p = self.work/name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(raw); p.chmod(0o600)

    def test_real_stream_packaging_strict_parser_and_truthful_provenance(self):
        sizes = []; read = s5.HashedReader.read
        def bounded(reader, size): sizes.append(size); return read(reader, size)
        with patch.object(s5.HashedReader, 'read', bounded):
            result = s5.build_fixture(self.work, self.proof)
        self.assertEqual(result['status'], 'passed'); self.assertFalse(result['haos_export'])
        self.assertFalse(result['s5_import_acceptance']); self.assertLessEqual(max(sizes), s5.MIB)
        path = Path(result['archive']); self.assertEqual(s5.digest(path), result['sha256'])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sorted(p.name for p in path.parent.iterdir()),
                         ['generated-s5-source.tar', 'provenance.private.json'])
        provenance = json.loads((path.parent/'provenance.private.json').read_text())
        self.assertEqual(provenance['actual_components']['images'], s5.IMAGES)
        self.assertEqual(provenance['native_proof'], self.proof)
        with tarfile.open(path) as tar:
            self.assertEqual([m.name for m in tar], [s5.SLUG+'.tar', 'share.tar', './backup.json'])
            doc = json.load(tar.extractfile('./backup.json'))
        self.assertFalse(doc['protected']); self.assertFalse(doc['extra']['haos_export'])
        self.assertTrue(doc['extra']['generated_test_fixture'])
        with habackup.open_backup(path) as opened:
            with opened.open_member('share.tar') as stream:
                report = habackup.Report(); names = {}
                for entry in habackup.iter_entries(stream, habackup.Select(), report):
                    if entry.kind == 'file':
                        h = hashlib.sha256()
                        for raw in iter(lambda: entry.read(65536), b''): h.update(raw)
                        names[entry.name] = h.hexdigest()
                self.assertTrue(report.complete)
                for name, row in self.proof['cipher_and_keys'].items():
                    self.assertEqual(names['nextcloud/'+name], row['sha256'])

    def test_link_hardlink_and_special_file_refused_without_following(self):
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                p = self.work/'data/unsafe'
                if kind == 'symlink': p.symlink_to('/etc/passwd')
                elif kind == 'hardlink': os.link(self.work/'data/.ncdata', p)
                else: os.mkfifo(p)
                try:
                    with self.assertRaisesRegex(ValueError, 'source-link-or-special'): s5.tree(self.work/'data')
                finally: p.unlink()

    def test_missing_or_changed_actual_key_binding_refuses(self):
        for fault in ('missing', 'digest', 'length', 'runtime-proof'):
            with self.subTest(fault=fault):
                proof = copy.deepcopy(self.proof)
                row = proof['cipher_and_keys']['files_encryption/OC_DEFAULT_MODULE/master_unit.privateKey']
                if fault == 'missing':
                    proof['cipher_and_keys']['missing/key'] = row
                elif fault == 'digest': row['sha256'] = '0'*64
                elif fault == 'length': row['bytes'] += 1
                else: proof['webdav_after_restart'] = False
                with self.assertRaises(ValueError): s5.build_fixture(self.work, proof)
                (self.work/'artifact').rmdir()

    def test_config_outside_share_refuses_in_actual_product_layout_scan(self):
        p = self.work/'html/config/config.php'
        p.write_bytes(p.read_bytes().replace(b'/share/nextcloud', b'/elsewhere/nextcloud'))
        with self.assertRaisesRegex(ValueError, 'native-config-layout'):
            s5.build_fixture(self.work, self.proof)

    def test_wrong_pg_major_and_live_pid_refuse(self):
        for fault in ('major', 'pid'):
            with self.subTest(fault=fault):
                self.write('pg/PG_VERSION', b'15\n' if fault == 'major' else b'16\n')
                if fault == 'pid': self.write('pg/postmaster.pid', b'123\n')
                with self.assertRaises(ValueError): s5.build_fixture(self.work, self.proof)
                (self.work/'artifact').rmdir()

    def test_output_is_exclusive_and_cold_file_change_refuses(self):
        artifact = self.work/'artifact'; artifact.mkdir()
        self.write('artifact/keep', b'previous-failed-attempt')
        with self.assertRaises(FileExistsError): s5.build_fixture(self.work, self.proof)
        self.assertEqual((artifact/'keep').read_bytes(), b'previous-failed-attempt')
        rows = s5.tree(self.work/'data')
        self.write('data/.ncdata', b'changed')
        class NoWriter:
            def add_member(self, *args): self.fail('changed source must refuse before writing')
        with self.assertRaisesRegex(ValueError, 'cold-source-changed'):
            s5.pack_tree(NoWriter(), self.work/'data', 'nextcloud', rows, lambda: None)

    def test_stream_reader_refuses_unbounded_reads(self):
        import io
        reader = s5.HashedReader(io.BytesIO(b'test'), lambda: None)
        for size in (-1, s5.MIB+1):
            with self.assertRaisesRegex(ValueError, 'stream-read-bound'): reader.read(size)

    def test_rendered_native_program_compiles_and_does_not_run_host_cli(self):
        source = Path(s5.__file__).read_text()
        compile(s5.native_program(source), 'actual-rendered-s5-program', 'exec')
        # The actual module body is library-only in the device program. No I/O.
        with patch.object(sys, 'argv', ['-c', '--run']), patch.object(s5.subprocess, 'Popen', side_effect=AssertionError):
            namespace = {'__name__': 's5_native_scope'}
            exec(compile(source, 'actual-s5-library', 'exec'), namespace)
        self.assertEqual(namespace['IMAGES'], s5.IMAGES)


if __name__ == '__main__': unittest.main()
