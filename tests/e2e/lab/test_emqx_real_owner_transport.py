"""Generated host files/framing and staged extracted invocation only; no lab."""
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

class TransportTests(unittest.TestCase):
    def test_private_fixed_credentials_are_data_only_and_fully_validated(self):
        import emqx_real_owner_transport as m
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'generated.env'
            path.write_bytes(b'UNRELATED=$(do-not-execute)\nB1_MQTT_USER1=b1-sensor\nB1_MQTT_PW1=generated-one\nB1_MQTT_USER2=b1-gateway\nB1_MQTT_PW2=generated-two\nB1_MQTT_USER3=generated-third\nB1_MQTT_PW3=generated-three\n')
            path.chmod(0o600)
            with patch.object(m,'CLIENT_CREDS',path):
                self.assertEqual(m.read_client_credentials(),[b'b1-sensor',b'generated-one',b'b1-gateway',b'generated-two',b'generated-third',b'generated-three'])
                path.chmod(0o644)
                with self.assertRaises(Exception):m.read_client_credentials()

    def test_aliases_duplicates_nonregular_and_oversize_credentials_refuse(self):
        import emqx_real_owner_transport as m
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'creds';p.write_bytes(b'K=one\n');p.chmod(0o600)
            link=root/'alias';link.symlink_to(p)
            with self.assertRaises(Exception):m.read_fixed_fields(link,('K',))
            hard=root/'hard';os.link(p,hard)
            with self.assertRaises(Exception):m.read_fixed_fields(p,('K',))
            hard.unlink()
            for raw in (b'K=one\nK=two\n',b'K="unterminated\n',b'OTHER=one\n',b'K='+b'x'*8193,b'x'*(1024*1024+1)):
                p.write_bytes(raw)
                with self.assertRaises(Exception):m.read_fixed_fields(p,('K',))
            with self.assertRaises(Exception):m.read_fixed_fields(root,('K',))

    def test_ten_field_prefix_matches_actual_consumer_and_wrong_profile_refuses(self):
        import emqx_real_owner_transport as m
        from emqx_real_owner_workflow import read_source_clients
        credentials=[b'b1-sensor',b'generated-one',b'b1-gateway',b'generated-two',b'generated-third',b'generated-three']
        expectations=[b'b1/retained/one',b'generated-payload-one',b'b1/retained/two',b'\x00generated\xfftwo']
        with patch.object(m,'read_client_credentials',return_value=credentials),patch.object(m,'retained_expectations',return_value=expectations):
            arm=m.client_prefix('--source-vendor-acl-sql-aliases')
            clients=read_source_clients(io.BytesIO(arm),'--source-vendor-acl-sql-aliases')
            self.assertEqual(clients.fields['retained_payload2'],b'\x00generated\xfftwo')
            with self.assertRaises(Exception):read_source_clients(io.BytesIO(arm),'--x86-source-vendor-acl-sql-aliases')
            with self.assertRaises(Exception):m.client_prefix('--source')

    def test_exact_restore_receipt_retained_no_dict_or_preflight_fallback(self):
        import emqx_real_owner_transport as m
        from emqx_framed_preflight import evidence_frame
        from emqx_private_evidence import names_receipt,SOURCE_NAMES
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch.object(m,'PRIVATE_PARENT',root):
                raw=m.canonical_receipt();frame=evidence_frame(raw)
                a=m.retain_restore_evidence(frame);b=m.retain_restore_evidence(frame)
                self.assertNotEqual(a,b);self.assertEqual(a.read_bytes(),raw)
                self.assertEqual(a.stat().st_mode&0o777,0o600)
                self.assertEqual(a.parent.stat().st_mode&0o777,0o700)
                for bad in (frame+b'x',frame[:-1],evidence_frame(names_receipt('preflight','passed',SOURCE_NAMES)),evidence_frame(b'{"evidence_bytes":"fake"}')):
                    with self.assertRaises(Exception):m.retain_restore_evidence(bad)
                roots=set(root.iterdir())
                with patch.object(m.os,'fsync',side_effect=OSError()):
                    with self.assertRaises(Exception):m.retain_restore_evidence(frame)
                self.assertEqual(set(root.iterdir()),roots)

    def test_extracted_public_bundle_invokes_actual_dependencies_without_pythonpath(self):
        import emqx_real_owner_transport as m
        import struct,subprocess
        code=m.bundle_code();deps=m.dependencies()
        frame=struct.pack('!Q',len(code))+code+struct.pack('!Q',len(deps))+deps+b'T'
        with tempfile.TemporaryDirectory() as d:
            env=dict(os.environ);env.pop('PYTHONPATH',None);env['TMPDIR']=d
            run=subprocess.run(['/usr/bin/python3','-c',m.BOOTSTRAP],input=frame,capture_output=True,cwd=d,env=env,timeout=60)
            self.assertEqual(run.returncode,0,run.stderr.decode())
            self.assertEqual(run.stdout,b'REAL OWNER DEPENDENCIES PASSED\n')
            self.assertEqual(run.stderr,b'');self.assertEqual(list(Path(d).iterdir()),[])

    def test_removed_fixture_policy_module_fails_actual_extracted_invocation(self):
        import emqx_real_owner_transport as m
        import struct,subprocess,tarfile
        raw=m.bundle_code();altered=io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(raw)) as old,tarfile.open(fileobj=altered,mode='w') as new:
            for item in old:
                if Path(item.name).name=='emqx_target_fixture_policy.py':continue
                new.addfile(item,old.extractfile(item) if item.isfile() else None)
        code=altered.getvalue();deps=m.dependencies()
        frame=struct.pack('!Q',len(code))+code+struct.pack('!Q',len(deps))+deps+b'T'
        with tempfile.TemporaryDirectory() as d:
            env=dict(os.environ);env.pop('PYTHONPATH',None);env['TMPDIR']=d
            run=subprocess.run(['/usr/bin/python3','-c',m.BOOTSTRAP],input=frame,capture_output=True,cwd=d,env=env,timeout=60)
            self.assertNotEqual(run.returncode,0)
            self.assertEqual(run.stdout,b'');self.assertEqual(list(Path(d).iterdir()),[])

    def test_fixed_child_failure_enum_and_private_output_never_escape(self):
        import emqx_real_owner_transport as m
        import subprocess,sys
        for raw,expected in ((b'REALOWNER-REFUSED:mqtt\n','mqtt'),(b'REALOWNER-REFUSED:private-raw-secret\n','child')):
            child=subprocess.Popen([sys.executable,'-c','import sys;sys.stdout.buffer.write('+repr(raw)+');sys.exit(1)'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            try:
                with self.assertRaises(m.TransportRefused) as caught:m.read_result(child,timeout=3)
                self.assertEqual(caught.exception.phase,expected)
            finally:child.wait();child.stdout.close()

    def test_original_fixed_modes_only_no_argv_path_hash_or_key(self):
        import emqx_real_owner_transport as m
        import contextlib
        for args in ([],['--source'],['--real-restore','arbitrary-path'],['--real-restore','--key=secret']):
            out=io.StringIO()
            with patch.object(m,'bundle_code') as bundle,contextlib.redirect_stdout(out):
                self.assertEqual(m.main(args),1)
                bundle.assert_not_called()
            self.assertEqual(out.getvalue(),'REAL OWNER PROFILE REFUSED\n')
