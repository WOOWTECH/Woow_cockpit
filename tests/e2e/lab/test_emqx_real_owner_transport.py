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
        with patch.object(m,'read_client_credentials',return_value=credentials),patch.object(m,'retained_expectations',return_value=expectations), \
             patch.object(m,'read_source_api_credentials',return_value=(b'admin',b'generated-admin',b'b1ops',b'generated-ops',b'generated-key',b'generated-secret')):
            arm=m.client_prefix('--source-vendor-acl-sql-aliases')
            from emqx_real_owner_workflow import read_source_api_credentials
            stream=io.BytesIO(arm);read_source_api_credentials(stream,'--source-vendor-acl-sql-aliases')
            clients=read_source_clients(stream,'--source-vendor-acl-sql-aliases')
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

    def test_removed_object_integrity_module_fails_actual_extracted_dependencies(self):
        import emqx_real_owner_transport as m
        import struct,subprocess,tarfile
        raw=m.bundle_code();altered=io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(raw)) as old,tarfile.open(fileobj=altered,mode='w') as new:
            for item in old:
                if Path(item.name).name=='emqx_b1_object_integrity.py':continue
                new.addfile(item,old.extractfile(item) if item.isfile() else None)
        code=altered.getvalue();deps=m.dependencies()
        frame=struct.pack('!Q',len(code))+code+struct.pack('!Q',len(deps))+deps+b'T'
        with tempfile.TemporaryDirectory() as d:
            env=dict(os.environ);env.pop('PYTHONPATH',None);env['TMPDIR']=d
            run=subprocess.run(['/usr/bin/python3','-c',m.BOOTSTRAP],input=frame,capture_output=True,cwd=d,env=env,timeout=60)
            self.assertNotEqual(run.returncode,0)
            self.assertEqual(run.stdout,b'');self.assertEqual(list(Path(d).iterdir()),[])

    def test_removed_native_object_module_fails_actual_extracted_dependency_invocation(self):
        import emqx_real_owner_transport as m
        import struct,subprocess,tarfile
        raw=m.bundle_code();altered=io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(raw)) as old,tarfile.open(fileobj=altered,mode='w') as new:
            for item in old:
                if Path(item.name).name=='emqx_native_object_integrity.py':continue
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
        for raw,expected in ((b'REALOWNER-REFUSED:mqtt\n','mqtt'),(b'REALOWNER-REFUSED:object_integrity\n','object_integrity'),(b'REALOWNER-REFUSED:private-raw-secret\n','child')):
            child=subprocess.Popen([sys.executable,'-c','import sys;sys.stdout.buffer.write('+repr(raw)+');sys.exit(1)'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            try:
                with self.assertRaises(m.TransportRefused) as caught:m.read_result(child,timeout=3)
                self.assertEqual(caught.exception.phase,expected)
            finally:child.wait();child.stdout.close()

    def test_broken_pipe_reader_only_propagates_complete_allowlisted_nonzero_refusal(self):
        import emqx_real_owner_transport as m
        import subprocess,sys
        from types import SimpleNamespace
        from unittest.mock import Mock
        for raw,code,expected in ((b'REALOWNER-REFUSED:budget\n',1,'budget'),
                (b'REALOWNER-REFUSED:realm\n',1,'realm'),
                (b'REALOWNER-REFUSED:budget\n',0,None),
                (b'REALOWNER-REFUSED:budget',1,None),
                (b'REALOWNER-REFUSED:private-generated-value\n',1,None),
                (b'REALOWNER-REFUSED:budget\nextra-generated-output',1,None),
                (b'generated-success',0,None)):
            process=subprocess.Popen([sys.executable,'-c','import sys;sys.stdout.buffer.write('+repr(raw)+');sys.exit('+str(code)+')'],
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            stdin=Mock();stdin.close.side_effect=BrokenPipeError()
            child=SimpleNamespace(stdin=stdin,stdout=process.stdout,wait=process.wait)
            try:self.assertEqual(m._broken_pipe_refusal(child),expected)
            finally:process.wait();process.stdout.close()
            stdin.close.assert_called_once()

    def test_fixed_imported_mode_dispatch_preserves_independent_source_frame(self):
        import emqx_real_owner_transport as m
        import emqx_real_owner_workflow as workflow
        import struct
        from types import SimpleNamespace
        for flag in ('--real-restore-mnesia-acl','--x86-real-restore-mnesia-acl'):
            source_mode,wire,no_live=m.MODES[flag]
            self.assertFalse(no_live);self.assertIn(wire,m.IMPORTED_MODES)
            self.assertIn(repr(wire),m._dispatch)
            body=b'generated-original-source-frame'
            stream=io.BytesIO(struct.pack('!Q',len(body))+body+m.ADMISSION)
            output=io.BytesIO()
            def run(admitted,**kw):
                self.assertEqual(kw['source_mode'],source_mode)
                self.assertEqual(kw['target_mode'],workflow.IMPORTED_MNESIA)
                self.assertFalse(kw['no_live']);self.assertEqual(admitted.read(len(body)),body)
                self.assertEqual(admitted.read(1),b'');admitted.finish()
                return {'evidence_bytes':m.canonical_receipt()}
            with patch('emqx_arm_source_owner._owner_realm',return_value=True), \
                 patch.object(workflow,'run_real_framed_owner',side_effect=run) as entry, \
                 patch.object(m.sys,'stdin',SimpleNamespace(buffer=stream)), \
                 patch.object(m.sys,'stdout',SimpleNamespace(buffer=output)):
                self.assertEqual(m.owner_main(wire),0)
            entry.assert_called_once()
            from emqx_framed_preflight import evidence_frame
            self.assertEqual(output.getvalue(),evidence_frame(m.canonical_receipt()))

    def test_original_fixed_modes_only_no_argv_path_hash_or_key(self):
        import emqx_real_owner_transport as m
        import contextlib
        for args in ([],['--source'],['--real-restore','arbitrary-path'],['--real-restore','--key=secret']):
            out=io.StringIO()
            with patch.object(m,'bundle_code') as bundle,contextlib.redirect_stdout(out):
                self.assertEqual(m.main(args),1)
                bundle.assert_not_called()
            self.assertEqual(out.getvalue(),'REAL OWNER PROFILE REFUSED\n')

    def test_host_actual_controller_frames_only_fixed_profile_and_exact_cipher_eof(self):
        import emqx_real_owner_transport as m
        from emqx_source_profiles import source_profile
        from emqx_framed_preflight import evidence_frame
        from emqx_real_owner_workflow import read_source_clients
        from dataclasses import replace
        import contextlib,hashlib,struct
        from unittest.mock import Mock
        class Sink(io.BytesIO):
            def close(self):pass
        for mode in ('--real-restore','--x86-real-restore','--real-restore-mnesia-acl','--x86-real-restore-mnesia-acl'):
            with tempfile.TemporaryDirectory() as d:
                root=Path(d);cipher=b'generated-cipher-only';archive=root/'cipher.tar';archive.write_bytes(cipher)
                creds=root/'clients';creds.write_bytes(b'B1_MQTT_USER1=b1-sensor\nB1_MQTT_PW1=generated-one\nB1_MQTT_USER2=b1-gateway\nB1_MQTT_PW2=generated-two\nB1_MQTT_USER3=generated-third\nB1_MQTT_PW3=generated-three\n');creds.chmod(0o600)
                key=root/'key';key.write_bytes(b'HA_BACKUP_KEY=generated-private-key\n');key.chmod(0o600)
                source_mode,wire_mode,_=m.MODES[mode]
                profile=replace(source_profile(source_mode),archive=archive,sha256=hashlib.sha256(cipher).hexdigest())
                sink=Sink();child=Mock(stdin=sink);out=io.StringIO()
                with patch.object(m,'CLIENT_CREDS',creds),patch.object(m,'KEY_CREDS',key), \
                     patch.object(m,'retained_expectations',return_value=[b'b1/retained/one',b'generated-first',b'b1/retained/two',b'generated-second']), \
                     patch.object(m,'read_source_api_credentials',return_value=(b'admin',b'generated-admin',b'b1ops',b'generated-ops',b'generated-api-key',b'generated-api-secret')), \
                     patch.object(m,'source_profile',return_value=profile),patch.object(m,'bundle_code',return_value=b'generated-code'), \
                     patch.object(m,'dependencies',return_value=b'generated-public-deps'),patch.object(m.subprocess,'Popen',return_value=child) as spawn, \
                     patch.object(m,'read_result',return_value=evidence_frame(m.canonical_receipt())),patch.object(m,'retain_restore_evidence') as retain, \
                     contextlib.redirect_stdout(out):
                    self.assertEqual(m.main([mode]),0)
                stream=io.BytesIO(sink.getvalue())
                def part():return stream.read(struct.unpack('!Q',stream.read(8))[0])
                self.assertEqual(part(),b'generated-code');self.assertEqual(part(),b'generated-public-deps')
                self.assertEqual(stream.read(1),wire_mode)
                stream=m.AdmittedStream(stream)
                from emqx_real_owner_workflow import read_source_api_credentials
                api=read_source_api_credentials(stream,source_mode)
                self.assertEqual(api.fields[-1],b'generated-api-secret')
                clients=read_source_clients(stream,source_mode)
                self.assertEqual(clients.fields['sensor_password'],b'generated-one')
                self.assertEqual(stream.read(struct.unpack('!I',stream.read(4))[0]),b'generated-private-key')
                self.assertEqual(part(),cipher);self.assertEqual(stream.read(1),b'');stream.finish()
                self.assertNotIn('env',spawn.call_args.kwargs)
                self.assertEqual(spawn.call_args.args[0][:3],[str(m.ROOT/'tests/e2e/lab/owner.sh'),'d','/usr/bin/python3'])
                retain.assert_called_once_with(evidence_frame(m.canonical_receipt()))
                self.assertEqual(out.getvalue(),'REAL OWNER RESTORE ROLLBACK PASSED\n')
                self.assertNotIn('generated-private-key',repr(spawn.call_args))

    def test_missing_retained_binding_refuses_before_key_or_child(self):
        import emqx_real_owner_transport as m
        import contextlib
        out=io.StringIO()
        with patch.object(m,'bundle_code',return_value=b'code'),patch.object(m,'dependencies',return_value=b'deps'), \
             patch.object(m,'read_client_credentials',return_value=[b'b1-sensor',b'a',b'b1-gateway',b'b',b'third',b'c']), \
             patch.object(m,'retained_expectations',side_effect=m.TransportRefused('retained_binding')), \
             patch.object(m,'read_fixed_fields') as read,patch.object(m.subprocess,'Popen') as spawn,contextlib.redirect_stdout(out):
            self.assertEqual(m.main(['--real-restore']),1)
        read.assert_not_called();spawn.assert_not_called()
        self.assertEqual(out.getvalue(),'REAL OWNER RETAINED_BINDING REFUSED\n')

    def test_probe_host_dispatch_has_no_source_inputs_and_retains_exact_scanned_target_bytes(self):
        import emqx_real_owner_transport as m
        from emqx_issued_target_probe import TARGET_RECEIPT
        from emqx_framed_preflight import evidence_frame
        import contextlib,struct
        from unittest.mock import Mock
        class Sink(io.BytesIO):
            def close(self):pass
        sink=Sink();child=Mock(stdin=sink);out=io.StringIO()
        with patch.object(m,'bundle_code',return_value=b'generated-code'),patch.object(m,'dependencies',return_value=b'generated-deps'), \
             patch.object(m.subprocess,'Popen',return_value=child) as spawn,patch.object(m,'read_result',return_value=evidence_frame(TARGET_RECEIPT)), \
             patch.object(m,'read_fixed_fields') as creds,patch.object(m,'client_prefix') as prefix,patch.object(m,'source_profile') as profile, \
             patch.object(m,'_retain_evidence') as retain,contextlib.redirect_stdout(out):
            self.assertEqual(m.main(['--issued-target-probe']),0)
        self.assertEqual(sink.getvalue(),struct.pack('!Q',14)+b'generated-code'+struct.pack('!Q',14)+b'generated-deps'+b'U')
        creds.assert_not_called();prefix.assert_not_called();profile.assert_not_called()
        retain.assert_called_once_with(evidence_frame(TARGET_RECEIPT),TARGET_RECEIPT,'emqx-issued-target-evidence-','issued-target.txt')
        self.assertNotIn('env',spawn.call_args.kwargs)
        self.assertEqual(out.getvalue(),'ISSUED TARGET PROBE PASSED\n')

    def test_probe_child_calls_actual_helper_contract_and_refuses_trailing_or_foreign_receipt(self):
        import emqx_real_owner_transport as m
        import emqx_arm_source_owner as realm
        import emqx_issued_target_probe as probe
        import contextlib
        from types import SimpleNamespace
        from emqx_framed_preflight import evidence_frame
        for extra,returned,code in ((b'',probe.TARGET_RECEIPT,0),(b'x',probe.TARGET_RECEIPT,1),(b'',b'private-foreign-result',1)):
            out=io.BytesIO()
            with patch.object(realm,'_owner_realm',return_value=True), \
                 patch.object(probe,'run_issued_target_probe',return_value=returned) as run, \
                 patch.object(m.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(extra))), \
                 patch.object(m.sys,'stdout',SimpleNamespace(buffer=out)):
                self.assertEqual(m.owner_main(b'U'),code)
            if extra:run.assert_not_called()
            else:run.assert_called_once_with()
            if code==0:self.assertEqual(out.getvalue(),evidence_frame(probe.TARGET_RECEIPT))
            else:self.assertEqual(out.getvalue(),b'ISSUEDPROBE-REFUSED:realm\n')
        for phase in probe.PHASES:
            out=io.BytesIO()
            with patch.object(realm,'_owner_realm',return_value=True), \
                 patch.object(probe,'run_issued_target_probe',side_effect=probe.IssuedProbeRefused(phase)), \
                 patch.object(m.sys,'stdin',SimpleNamespace(buffer=io.BytesIO())),patch.object(m.sys,'stdout',SimpleNamespace(buffer=out)):
                self.assertEqual(m.owner_main(b'U'),1)
            self.assertEqual(out.getvalue(),b'ISSUEDPROBE-REFUSED:'+phase.encode()+b'\n')

    def test_wrong_digest_or_changed_cipher_never_reads_or_retains_success(self):
        import emqx_real_owner_transport as m
        from emqx_source_profiles import source_profile
        from dataclasses import replace
        import contextlib,hashlib
        from unittest.mock import Mock
        for change in ('digest','metadata','growth'):
            with tempfile.TemporaryDirectory() as d:
                root=Path(d);cipher=b'generated-private-cipher';archive=root/'cipher';archive.write_bytes(cipher)
                profile=replace(source_profile('--source-vendor-acl-sql-aliases'),archive=archive,
                    sha256='0'*64 if change=='digest' else hashlib.sha256(cipher).hexdigest())
                class Sink(io.BytesIO):
                    def close(self):pass
                    def write(self,raw):
                        result=super().write(raw)
                        if raw==cipher:
                            if change=='metadata':
                                before=archive.stat();os.utime(archive,ns=(before.st_atime_ns,before.st_mtime_ns+1000000))
                            if change=='growth':
                                with archive.open('ab') as out:out.write(b'extra')
                        return result
                child=Mock(stdin=Sink());child.wait.return_value=1;out=io.StringIO()
                with patch.object(m,'bundle_code',return_value=b'code'),patch.object(m,'dependencies',return_value=b'deps'), \
                     patch.object(m,'client_prefix',return_value=b'generated-prefix'),patch.object(m,'read_fixed_fields',return_value=[b'generated-key']), \
                     patch.object(m,'source_profile',return_value=profile),patch.object(m.subprocess,'Popen',return_value=child), \
                     patch.object(m,'read_result') as read,patch.object(m,'retain_restore_evidence') as retain,contextlib.redirect_stdout(out):
                    self.assertEqual(m.main(['--real-restore']),1)
                read.assert_not_called();retain.assert_not_called()
                self.assertEqual(out.getvalue(),'REAL OWNER ARCHIVE_BINDING REFUSED\n')

    def test_original_seed_literals_bind_both_archives_without_execution_or_payload_output(self):
        import emqx_real_owner_transport as m
        from emqx_source_profiles import source_profile
        import contextlib,json
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);seed=root/'seed';seed.mkdir(mode=0o700)
            pairs={'b1/retained/generated-one':'generated-original-α','b1/retained/generated-two':'generated-original-β'}
            script=b'#!/bin/sh\n# inert: never executed\n'+b''.join(b'fixture "$BASE" POST /publish -d \''+json.dumps({'topic':t,'payload':v,'qos':1,'retain':True},ensure_ascii=False).encode()+b"'\n" for t,v in pairs.items())
            for name in ('emqx-body.sh','emqx-arm.sh','emqx-x86.sh'):(seed/name).write_bytes(script)
            summary=root/'summary.json'
            doc={'machines':{a:{'emqx':{'retained_messages':list(pairs)}} for a in ('arm','x86')},'backups':{}}
            for arch,mode in (('arm','--source-vendor-acl-sql-aliases'),('x86','--x86-source-vendor-acl-sql-aliases')):
                profile=source_profile(mode)
                doc['backups'][arch]=[{'sha256':profile.sha256,'local_copy':str(profile.archive),'local_ok':True,'protected':True}]
            summary.write_text(json.dumps(doc));summary.chmod(0o600)
            out=io.StringIO()
            with patch.object(m,'SEED_ROOT',seed),patch.object(m,'SOURCE_SUMMARY',summary),contextlib.redirect_stdout(out):
                for mode in ('--source-vendor-acl-sql-aliases','--x86-source-vendor-acl-sql-aliases'):
                    self.assertEqual(m.retained_expectations(mode),[b'b1/retained/generated-one','generated-original-α'.encode(),b'b1/retained/generated-two','generated-original-β'.encode()])
            self.assertEqual(out.getvalue(),'')

class OriginalProducerTests(unittest.TestCase):
    def setUp(self):
        import emqx_real_owner_transport as m
        import json
        from emqx_source_profiles import source_profile
        self.m=m;self.json=json
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.seed=self.root/'seed';self.seed.mkdir(mode=0o700)
        self.topics=['b1/retained/generated-one','b1/retained/generated-two']
        self.script=b'#!/bin/sh\n'+b''.join(b'fixture "$BASE" POST /publish -d \''+json.dumps({'topic':t,'payload':'generated-only-'+str(i),'qos':1,'retain':True}).encode()+b"'\n" for i,t in enumerate(self.topics))
        for name in ('emqx-body.sh','emqx-arm.sh','emqx-x86.sh'):
            (self.seed/name).write_bytes(self.script);(self.seed/name).chmod(0o664)
        self.summary=self.root/'summary.json'
        self.doc={'machines':{a:{'emqx':{'retained_messages':self.topics[:]}} for a in ('arm','x86')},'backups':{}}
        for arch,mode in (('arm','--source-vendor-acl-sql-aliases'),('x86','--x86-source-vendor-acl-sql-aliases')):
            profile=source_profile(mode)
            self.doc['backups'][arch]=[{'sha256':profile.sha256,'local_copy':str(profile.archive),'local_ok':True,'protected':True}]
        self.write_summary()
        for name,value in (('SEED_ROOT',self.seed),('SOURCE_SUMMARY',self.summary)):
            p=patch.object(m,name,value);p.start();self.addCleanup(p.stop)

    def write_summary(self):
        self.summary.write_text(self.json.dumps(self.doc));self.summary.chmod(0o600)

    def refused(self):
        with self.assertRaises(self.m.TransportRefused) as caught:self.m.retained_expectations('--source-vendor-acl-sql-aliases')
        self.assertEqual(caught.exception.phase,'retained_binding')

    def test_cross_arch_conflict_additional_publish_duplicate_json_and_nonliteral_body_refuse(self):
        path=self.seed/'emqx-arm.sh'
        for raw in (self.script.replace(b'generated-only-0',b'conflicting-original'),
                    self.script+self.script.splitlines(keepends=True)[1],
                    self.script.replace(b'"qos": 1',b'"qos": 1,"qos": 1'),
                    self.script.replace(b'"retain": true',b'"retain": false'),
                    self.script.replace(b"-d '",b'-d "',1),
                    self.script.replace(b'"payload": "generated-only-0"',b'"payload": NaN'),
                    self.script+b'fixture "$BASE" POST /publish -d "$BODY"\n'):
            with self.subTest(case=len(raw)):
                path.write_bytes(raw);self.refused()
        path.write_bytes(self.script)
        self.assertEqual(len(self.m.retained_expectations('--source-vendor-acl-sql-aliases')),4)

    def test_unique_source_sha_exact_original_path_topics_and_case_flags_required(self):
        import copy
        original=copy.deepcopy(self.doc)
        mutations=(lambda d:d['backups']['arm'].append(copy.deepcopy(d['backups']['arm'][0])),
                   lambda d:d['backups']['arm'][0].update(sha256='0'*64),
                   lambda d:d['backups']['arm'][0].update(local_copy='/different-case/archive.tar'),
                   lambda d:d['backups']['arm'][0].update(local_ok=False),
                   lambda d:d['backups']['arm'][0].update(protected=False),
                   lambda d:d['machines']['arm']['emqx'].update(retained_messages=['b1/retained/foreign','b1/retained/generated-two']))
        for mutate in mutations:
            self.doc=copy.deepcopy(original);mutate(self.doc);self.write_summary();self.refused()
        self.doc=original;self.write_summary()
        self.summary.write_bytes(self.summary.read_bytes().replace(b'"backups":',b'"backups":{},"backups":',1));self.refused()

    def test_original_files_refuse_symlink_hardlink_world_write_and_replacement_during_read(self):
        path=self.seed/'emqx-body.sh';saved=self.root/'original';path.rename(saved);path.symlink_to(saved)
        self.refused();path.unlink();saved.rename(path)
        os.link(path,self.root/'alias');self.refused();(self.root/'alias').unlink()
        path.chmod(0o666);self.refused();path.chmod(0o664)
        read=self.m._read_original
        def changed(p,limit):
            raw=read(p,limit)
            if p==self.summary:
                # Rewrite the first producer only after its own bounded read.
                (self.seed/'emqx-body.sh').write_bytes(self.script+b'# changed\n')
            return raw
        with patch.object(self.m,'_read_original',side_effect=changed):self.refused()

class APICredentialTransportTests(unittest.TestCase):
    def test_fixed_api_fields_merge_unambiguously_and_both_profiles_roundtrip(self):
        import emqx_real_owner_transport as m
        from emqx_real_owner_workflow import API_MAGIC,CLIENT_MODES,read_source_api_credentials
        import struct
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);client=root/'clients.env';key=root/'ha.env'
            client.write_bytes(b'UNRELATED=$(never-run)\nB1_EMQX_ADMIN_PW=generated-admin\nB1_EMQX_USER2=b1ops\nB1_EMQX_USER2_PW=generated-ops\n')
            key.write_bytes(b'HA_BACKUP_KEY=not-api-input\nB1_ARM_EMQX_API_KEY=generated-arm-key\nB1_ARM_EMQX_API_SECRET=generated-arm-secret\nB1_X86_EMQX_API_KEY=generated-x86-key\nB1_X86_EMQX_API_SECRET=generated-x86-secret\n')
            client.chmod(0o600);key.chmod(0o600)
            with patch.object(m,'CLIENT_CREDS',client),patch.object(m,'KEY_CREDS',key):
                for mode,expected in (('--source-vendor-acl-sql-aliases',b'generated-arm-secret'),('--x86-source-vendor-acl-sql-aliases',b'generated-x86-secret')):
                    fields=m.read_source_api_credentials(mode)
                    self.assertEqual(fields[:4],(b'admin',b'generated-admin',b'b1ops',b'generated-ops'))
                    self.assertEqual(fields[-1],expected)
                    raw=API_MAGIC+CLIENT_MODES[mode]+b''.join(struct.pack('!H',len(v))+v for v in fields)
                    self.assertEqual(read_source_api_credentials(io.BytesIO(raw),mode).fields,fields)
                key.write_bytes(key.read_bytes()+b'B1_EMQX_ADMIN_PW=generated-admin\n')
                with self.assertRaises(Exception):m.read_source_api_credentials('--source-vendor-acl-sql-aliases')
                key.chmod(0o644)
                with self.assertRaises(Exception):m.read_source_api_credentials('--source-vendor-acl-sql-aliases')
