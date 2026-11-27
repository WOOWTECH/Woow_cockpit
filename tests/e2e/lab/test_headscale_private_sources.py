"""Synthetic fixtures only; tests never read a real device or service."""
import base64
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

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

    def test_volume_source_policy_and_valid_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'volume.tar'
            value = b'privkey:' + b'1' * 64
            with tarfile.open(path, 'w') as archive:
                info = tarfile.TarInfo('noise.key')
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
            self.assertEqual(private.volume_key(path, 'noise.key'),
                             [value.decode(), '1' * 64])
            compressed = root / 'compressed.tar.gz'
            import gzip
            compressed.write_bytes(gzip.compress(path.read_bytes()))
            with self.assertRaises(tarfile.ReadError):
                private.volume_key(compressed, 'noise.key')
            link = root / 'link'
            link.symlink_to(path)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            # Exercise the real CLI with a deadline: a FIFO must never block.
            cases = [(link, None), (fifo, None), (root, None),
                     (root / 'missing', None), (path, 32)]
            for source, limit in cases:
                with self.subTest(source=source.name, limit=limit):
                    code = (
                        "import importlib.util; "
                        "s=importlib.util.spec_from_file_location('p', __import__('sys').argv[1]); "
                        "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                        + (f"m.MAX_FILE={limit}; " if limit else "") +
                        "__import__('sys').argv=['helper','volume',__import__('sys').argv[2],'noise.key']; m.main()"
                    )
                    result = subprocess.run([sys.executable, '-c', code, private.__file__, str(source)],
                                            capture_output=True, timeout=2)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, b'')
                    self.assertEqual(result.stderr,
                                     b'Synthetic private source missing, invalid or unsupported\n')

    def test_source_size_boundary_uses_bounded_read(self):
        # A tiny substituted limit exercises the exact boundary without large
        # allocations. Observe the read request as well as its return value.
        fdopen = os.fdopen
        reads = []

        @contextmanager
        def tracked_open(*args, **kwargs):
            with fdopen(*args, **kwargs) as source:
                reader = mock.Mock(wraps=source)
                reads.append(reader.read)
                yield reader

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(private, 'MAX_FILE', 32), \
                mock.patch.object(private.os, 'fdopen', side_effect=tracked_open):
            path = Path(directory) / 'source'
            for size in (0, 31, 32, 33):
                with self.subTest(size=size):
                    path.write_bytes(b'x' * size)
                    if 0 < size <= 32:
                        self.assertEqual(private.read_source(path), b'x' * size)
                    else:
                        with self.assertRaises(ValueError):
                            private.read_source(path)
                    reads[-1].assert_called_once_with(33)

    def test_source_policy_and_oversize_errors_are_generic(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(private, 'MAX_FILE', 32):
            root = Path(directory)
            source = root / 'private-source'
            source.write_bytes(b'synthetic-secret-content-' + b'x' * 9)
            link = root / 'link'
            link.symlink_to(source)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            for path in (source, link, fifo, root, root / 'missing'):
                for kind in ('client', 'pem'):
                    with self.subTest(path=path.name, kind=kind), \
                            mock.patch.object(sys, 'argv', [private.__file__, kind, str(path)]), \
                            mock.patch.object(private, 'client_keys') as client_parser, \
                            mock.patch.object(private, 'pem_values') as pem_parser, \
                            redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                        with self.assertRaises(SystemExit) as raised:
                            private.main()
                        self.assertEqual(raised.exception.code, 1)
                        self.assertEqual(out.getvalue(), '')
                        self.assertEqual(err.getvalue(),
                                         'Synthetic private source missing, invalid or unsupported\n')
                        client_parser.assert_not_called()
                        pem_parser.assert_not_called()
            # A symlink to even an otherwise valid-size regular file is rejected.
            source.write_bytes(b'x')
            with self.assertRaises(OSError):
                private.read_source(link)

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
