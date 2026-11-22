"""Controller generated files/fake child only; no owner, lab or real credentials."""
from dataclasses import replace
import contextlib
import hashlib
import io
import os
from pathlib import Path
import struct
import shutil
import subprocess
import sys
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

    def invoke(self, mode, *, digest=None, status=0, mutate=False, diagnostic=False, preflight_error=False):
        profile_name = {'--source': 'ARM_SOURCE', '--x86-source': 'X86_SOURCE',
            '--source-vendor-acl': 'ARM_VENDOR_ACL',
            '--x86-source-vendor-acl': 'X86_VENDOR_ACL',
            '--source-vendor-acl-republish':'ARM_CONTEXT',
            '--x86-source-vendor-acl-republish':'X86_CONTEXT',
            '--source-vendor-acl-http-body':'ARM_HTTP_CONTEXT',
            '--x86-source-vendor-acl-http-body':'X86_HTTP_CONTEXT',
            '--source-vendor-acl-sql-aliases':'ARM_SQL_ALIASES',
            '--x86-source-vendor-acl-sql-aliases':'X86_SQL_ALIASES',
            '--preflight':'ARM_SQL_ALIASES','--x86-preflight':'X86_SQL_ALIASES'}[mode]
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
             patch.object(transfer,'read_child_frame',return_value=b'generated-private-evidence-frame',
                 side_effect=ValueError if preflight_error else None) as reader, \
             patch.object(transfer,'retain_evidence') as retained, \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = transfer.main([mode]+(['--diagnose'] if diagnostic else []))
        if mode in transfer.PREFLIGHT_MODES and code == 0:
            reader.assert_called_once_with(child)
            retained.assert_called_once_with(b'generated-private-evidence-frame')
        if mode in transfer.PREFLIGHT_MODES and code != 0:
            retained.assert_not_called()
        return code, sink.getvalue(), archive, spawn, output.getvalue(), errors.getvalue()

    def test_staged_preflight_bundle_executes_vendor_policy_without_repository_imports(self):
        status, _, archive, _, _, _ = self.invoke('--preflight')
        self.assertEqual(status,0)
        staged=self.root/'code';staged.mkdir()
        for relative in archive.call_args.args[0][3:]:
            source=transfer.ROOT/relative; target=staged/relative
            target.parent.mkdir(parents=True,exist_ok=True)
            if source.is_dir(): shutil.copytree(source,target)
            else: shutil.copy2(source,target)
        code = """
import sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path[:0]=[str(root/'backup-engine'),str(root/'tests/e2e/lab')]
from emqx_target_vendor_policy import policy_from_observation, REFERENCES
from emqx_owner_vendor_files import VendorFiles, _paths
from emqx_native_runtime import IMAGE
receipts=[dict(path=p,image=IMAGE,bytes=1,sha256='a'*64,container_id='b'*64,
               image_identity=(1,),target_identity=(1,)) for p in _paths(REFERENCES)]
policy_from_observation(VendorFiles(receipts),'c'*32)
"""
        result=subprocess.run([sys.executable,'-I','-c',code,str(staged)],
                              cwd=staged,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace')[-1000:])
        self.assertEqual(result.stdout,b'')
        (staged/'tests/e2e/lab/emqx_target_fixture_policy.py').unlink()
        missing=subprocess.run([sys.executable,'-I','-c',code,str(staged)],
                               cwd=staged,capture_output=True,timeout=10)
        self.assertNotEqual(missing.returncode,0)
        self.assertEqual(missing.stdout,b'')

    def test_fixed_modes_preserve_private_frame_and_bundle_all_required_code(self):
        for mode, expected_byte in (('--source', b'S'), ('--x86-source', b'X'),
                ('--source-vendor-acl', b'V'), ('--x86-source-vendor-acl', b'W'),
                ('--source-vendor-acl-republish', b'Y'), ('--x86-source-vendor-acl-republish', b'Z'),
                ('--source-vendor-acl-http-body', b'H'), ('--x86-source-vendor-acl-http-body', b'J'),
                ('--source-vendor-acl-sql-aliases', b'A'), ('--x86-source-vendor-acl-sql-aliases', b'B')):
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
                             'emqx_captured_candidate.py','emqx_sql_aliases.py'):
                    self.assertIn('tests/e2e/lab/' + name, files)
                command = spawn.call_args.args[0]
                self.assertEqual(command[1:3], ['d', '/usr/bin/python3'])
                self.assertNotIn(key.decode(), repr(command))
                self.assertNotIn('env', spawn.call_args.kwargs)
                self.assertEqual((out, err), ('', ''))

    def test_fixed_diagnostic_prefix_before_source_mode_and_bootstrap_syntax(self):
        status, framed, _, _, out, err = self.invoke('--source-vendor-acl-sql-aliases',diagnostic=True)
        self.assertEqual(status,0)
        stream=io.BytesIO(framed)
        for _ in range(2):
            size=struct.unpack('!Q',stream.read(8))[0];stream.read(size)
        self.assertEqual(stream.read(2),b'QA')
        self.assertEqual((out,err),('',''))
        compile(transfer.BOOTSTRAP,'<fixed-bootstrap>','exec')

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
        for args in (['--configuration','--diagnose'], ['--probe','--diagnose'],
                     ['--x86-source', '--sha', 'override'], ['--source', '--vendor-acl'],
                     ['--x86-source-vendor-acl=/tmp/other'], ['--x86-source', '--key', 'private']):
            with self.subTest(args=args), patch.object(transfer, 'dependencies') as deps, \
                 patch.object(transfer.os, 'open') as opened, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(transfer.main(args), 1)
                deps.assert_not_called()
                opened.assert_not_called()

    def test_preflight_modes_have_private_pipe_and_complete_actual_consumer_bundle(self):
        for mode, expected in (('--preflight',b'E'),('--x86-preflight',b'F')):
            status, framed, archive, spawn, out, err = self.invoke(mode)
            self.assertEqual(status,0)
            stream = io.BytesIO(framed)
            for _ in range(2):
                size=struct.unpack('!Q',stream.read(8))[0];stream.read(size)
            self.assertEqual(stream.read(1),expected)
            self.assertEqual(spawn.call_args.kwargs['stdout'],transfer.subprocess.PIPE)
            self.assertEqual(out,'PREFLIGHT REGISTRATION LOGIN PASSED\n')
            self.assertEqual(err,'')
            files = archive.call_args.args[0]
            for name in ('emqx_framed_preflight.py','emqx_fresh_owner_workflow.py',
                'emqx_private_owner_driver.py','emqx_owner_preflight.py','emqx_owner_target.py',
                'emqx_owner_target.expr','emqx_target_vendor_policy.py','emqx_owner_vendor_files.py',
                'emqx_bootstrap_csv.py','emqx_target_capture.py','emqx_target_snapshots.py',
                'emqx_persisted_values.py','emqx_runtime_workflow.py','emqx_private_evidence.py',
                'emqx_adapter_owner.py','emqx_captured_candidate.py','emqx_sql_aliases.py'):
                self.assertIn('tests/e2e/lab/'+name,files)
        compile(transfer.BOOTSTRAP,'<fixed-bootstrap>','exec')

    def test_refused_child_frame_does_not_retain_or_publish_payload(self):
        code, _, _, _, out, err = self.invoke('--preflight',preflight_error=True)
        self.assertEqual(code,1)
        self.assertEqual((out,err),('ARM TRANSFER REFUSED\n',''))

    def test_extracted_direct_host_script_without_pythonpath_has_fixed_refusal(self):
        # Code-only extraction, executed by the actual python script command.
        # Invalid mode refuses before dependencies/key/archive/owner IO.
        import shutil
        import subprocess
        import sys
        extracted=self.root/'extracted';lab=extracted/'tests/e2e/lab';lab.mkdir(parents=True)
        source=Path(transfer.__file__).parent
        for path in source.iterdir():
            if path.suffix in ('.py','.escript','.expr','.json'):
                shutil.copyfile(path,lab/path.name)
        shutil.copytree(transfer.ROOT/'backup-engine/woowbackup',extracted/'backup-engine/woowbackup',
                        ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        env=dict(os.environ);env.pop('PYTHONPATH',None);env['PYTHONDONTWRITEBYTECODE']='1'
        result=subprocess.run([sys.executable,str(lab/'emqx_arm_cold_transfer.py'),'--invalid-mode'],
            cwd=self.root,env=env,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,1)
        self.assertEqual(result.stdout,b'ARM TRANSFER REFUSED\n')
        self.assertEqual(result.stderr,b'')
