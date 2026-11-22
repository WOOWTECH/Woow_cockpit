"""Controller generated files/fake child only; no owner, lab or real credentials."""
from dataclasses import replace
import contextlib
import hashlib
import io
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch

import emqx_arm_cold_transfer as transfer
import emqx_source_profiles as profiles


class Buffer(io.BytesIO):
    def close(self):
        self.was_closed = True


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / 'generated-cipher.tar'
        self.cipher = b'generated-encrypted-archive'
        self.archive.write_bytes(self.cipher)
        self.creds = self.root / 'generated-creds.env'
        self.creds.write_bytes(b'UNRELATED=not-sourced\nHA_BACKUP_KEY="generated-ram-only-key"\n')
        self.creds.chmod(0o600)
        self.digest = hashlib.sha256(self.cipher).hexdigest()

    def invoke(self, mode, *, digest=None, status=0, mutate=False):
        profile_name = {'--source': 'ARM_SOURCE', '--x86-source': 'X86_SOURCE',
            '--source-vendor-acl': 'ARM_VENDOR_ACL',
            '--x86-source-vendor-acl': 'X86_VENDOR_ACL',
            '--source-vendor-acl-republish':'ARM_CONTEXT',
            '--x86-source-vendor-acl-republish':'X86_CONTEXT',
            '--source-vendor-acl-http-body':'ARM_HTTP_CONTEXT',
            '--x86-source-vendor-acl-http-body':'X86_HTTP_CONTEXT'}[mode]
        chosen = replace(getattr(profiles, profile_name), archive=self.archive,
                         sha256=self.digest if digest is None else digest)
        sink = Buffer()
        if mutate:
            write = sink.write
            def changed(chunk):
                result = write(chunk)
                if chunk == self.cipher:
                    before = self.archive.stat()
                    os.utime(self.archive, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000))
                return result
            sink.write = changed
        child = Mock(stdin=sink)
        child.wait.return_value = status
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(profiles, profile_name, chosen), \
             patch.object(transfer, 'CREDS', self.creds), \
             patch.object(transfer, 'dependencies', return_value=b'public-dependencies'), \
             patch.object(transfer.subprocess, 'check_output', return_value=b'public-code') as archive, \
             patch.object(transfer.subprocess, 'Popen', return_value=child) as spawn, \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = transfer.main([mode])
        return code, sink.getvalue(), archive, spawn, output.getvalue(), errors.getvalue()

    def test_fixed_modes_preserve_private_frame_and_bundle_all_required_code(self):
        for mode, expected_byte in (('--source', b'S'), ('--x86-source', b'X'),
                ('--source-vendor-acl', b'V'), ('--x86-source-vendor-acl', b'W'),
                ('--source-vendor-acl-republish', b'Y'), ('--x86-source-vendor-acl-republish', b'Z'),
                ('--source-vendor-acl-http-body', b'H'), ('--x86-source-vendor-acl-http-body', b'J')):
            with self.subTest(mode=mode):
                status, framed, archive, spawn, out, err = self.invoke(mode)
                self.assertEqual(status, 0)
                stream = io.BytesIO(framed)
                def part():
                    return stream.read(struct.unpack('!Q', stream.read(8))[0])
                self.assertEqual(part(), b'public-code')
                self.assertEqual(part(), b'public-dependencies')
                self.assertEqual(stream.read(1), expected_byte)
                key = stream.read(struct.unpack('!I', stream.read(4))[0])
                self.assertEqual(key, b'generated-ram-only-key')
                self.assertEqual(part(), self.cipher)
                self.assertEqual(stream.read(), b'')
                files = archive.call_args.args[0]
                for name in ('emqx_source_profiles.py', 'emqx_owner_file_hocon.py',
                             'emqx_vendor_acl.escript', 'emqx_owner_source_capture.py',
                             'emqx_hocon_context.py','emqx_hocon_context_native.escript','emqx_republish_templates.py',
                             'emqx_captured_candidate.py'):
                    self.assertIn('tests/e2e/lab/' + name, files)
                command = spawn.call_args.args[0]
                self.assertEqual(command[1:3], ['d', '/usr/bin/python3'])
                self.assertNotIn(key.decode(), repr(command))
                self.assertNotIn('env', spawn.call_args.kwargs)
                self.assertEqual((out, err), ('', ''))

    def test_wrong_digest_or_same_bytes_changed_stamp_refuses(self):
        for kwargs in ({'digest': '0' * 64}, {'mutate': True}):
            with self.subTest(case=kwargs):
                code, _, _, _, out, err = self.invoke('--x86-source', **kwargs)
                self.assertEqual(code, 1)
                self.assertEqual(out, 'ARM TRANSFER REFUSED\n')
                self.assertEqual(err, '')

    def test_nonzero_source_child_status_preserved_without_source_output(self):
        status, _, _, _, out, err = self.invoke('--x86-source-vendor-acl', status=7)
        self.assertEqual(status, 7)
        self.assertEqual((out, err), ('', ''))

    def test_unknown_or_override_args_refuse_before_key_or_archive_reads(self):
        for args in (['--x86-source', '--sha', 'override'], ['--source', '--vendor-acl'],
                     ['--x86-source-vendor-acl=/tmp/other'], ['--x86-source', '--key', 'private']):
            with self.subTest(args=args), patch.object(transfer, 'dependencies') as deps, \
                 patch.object(transfer.os, 'open') as opened, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(transfer.main(args), 1)
                deps.assert_not_called()
                opened.assert_not_called()
