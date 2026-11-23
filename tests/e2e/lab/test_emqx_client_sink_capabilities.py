"""Generated process/owner boundaries only, no real image/container/lab IO."""
import io
import json
import os
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_client_sink_capabilities as m
import emqx_adapter_owner as owner
from emqx_owned_client import LABEL


class CapabilityTests(unittest.TestCase):
    def setUp(self):
        self.runner=owner.LabOwnerRunner.__new__(owner.LabOwnerRunner)
        self.runner.owner='appowner';self.runner.uid=os.geteuid();self.runner.gid=os.getegid();self.runner.home='/generated-unused-home'
        self.runner.podman=self.podman
        self.doc=None;self.calls=[];self.names=[];self.removed=[]
        self.output=b'[\n[[\nhttpd\nnc\nsh\ntimeout\n';self.stderr=b'';self.code=0
        self.timeout=False;self.foreign=False;self.collision=False;self.rm_failure=False
        factory=patch.object(owner,'LabOwnerRunner',return_value=self.runner)
        factory.start();self.addCleanup(factory.stop)
        create=patch.object(owner.OwnerProvision,'create');self.create=create.start();self.addCleanup(create.stop)
        cleanup=patch.object(owner.OwnerProvision,'cleanup');self.cleanup=cleanup.start();self.addCleanup(cleanup.stop)

    def podman(self,*args,**kwargs):
        self.calls.append((args,kwargs))
        if args[:2]==('container','exists'):
            exists=self.collision or (self.doc is not None and args[2] in (self.doc['Name'],self.doc['Id']))
            return SimpleNamespace(returncode=0 if exists else 1,stdout=b'',stderr=b'')
        if args[:2]==('container','inspect'):
            return SimpleNamespace(returncode=0,stdout=json.dumps([self.doc]).encode(),stderr=b'')
        if args[0]=='rm':
            self.assertEqual(args,('rm','--force','--ignore','a'*64));self.removed.append(args[-1])
            if not self.rm_failure:self.doc=None
            return SimpleNamespace(returncode=1 if self.rm_failure else 0,stdout=b'',stderr=b'')
        self.assertEqual(args[0],'run');name=args[args.index('--name')+1];self.names.append(name)
        self.assertRegex(name,r'^woowbk-emqxlab-[0-9a-f]{8}-mqtt-[0-9a-f]{12}$')
        label,nonce=args[args.index('--label')+1].split('=',1)
        self.assertEqual(label,LABEL);self.assertRegex(nonce,r'^[0-9a-f]{64}$')
        self.doc={'Id':'a'*64,'Name':name,'Image':m.CLIENT,'Config':{'Labels':{LABEL:'foreign' if self.foreign else nonce}}}
        for option in ('--read-only','--network=none','--image-volume=ignore','--log-driver=none','--pull=never',
                '--memory=32m','--cpus=0.25','--pids-limit=16','--timeout=15'):
            self.assertIn(option,args)
        self.assertEqual(args[-3:],('--entrypoint=/bin/busybox',m.CLIENT,'--list'))
        self.assertFalse(any(x in args for x in ('-v','--volume','-e','--env','-p','--publish')))
        self.assertEqual(kwargs,dict(timeout=20,max_output=65536,check=False))
        if self.timeout:raise subprocess.TimeoutExpired('generated-private-timeout',20)
        return SimpleNamespace(returncode=self.code,stdout=self.output,stderr=self.stderr)

    def run_probe(self):
        result=m.run_client_sink_capabilities();self.create.assert_not_called();self.cleanup.assert_not_called();return result

    def test_actual_constructor_owned_nonce_cid_cleanup_before_fixed_receipt(self):
        self.assertEqual(self.run_probe(),m.RECEIPT);self.assertIsNone(self.doc)
        self.assertEqual(self.removed,['a'*64])
        self.assertNotIn('coverage',m.RECEIPT.decode().lower());self.assertNotIn('restore',m.RECEIPT.decode().lower())

    def test_each_missing_applet_or_substring_only_is_fixed_refusal_and_cleanup(self):
        for required in m.REQUIRED:
            self.output=b''.join(x.encode()+b'\n' for x in m.REQUIRED if x!=required)+required.encode()+b'x\n'
            with self.assertRaises(m.ClientSinkRefused) as caught:self.run_probe()
            self.assertEqual(caught.exception.phase,'missing_'+required);self.assertIsNone(self.doc)

    def test_unknown_ascii_shape_duplicate_control_bytes_oversize_or_stderr_refuses(self):
        for output in (b'',b'nc\nhttpd\ntimeout\nsh',b'nc\r\nhttpd\ntimeout\nsh\n',
                b'nc\nhttpd\ntimeout\nsh\nsh\n',b'nc\nhttpd\ntimeout\nsh\n\xff\n',b'x'*65537):
            self.output=output
            with self.assertRaises(m.ClientSinkRefused):self.run_probe()
            self.assertIsNone(self.doc)
        self.output=b'nc\nhttpd\ntimeout\nsh\n';self.stderr=b'generated-private-stderr'
        with self.assertRaises(m.ClientSinkRefused):self.run_probe()
        self.assertIsNone(self.doc)

    def test_timeout_uses_guarded_cid_cleanup_and_foreign_collision_is_never_deleted(self):
        self.timeout=True
        with self.assertRaises(m.ClientSinkRefused):self.run_probe()
        self.assertEqual(self.removed,['a'*64]);self.assertIsNone(self.doc)
        self.timeout=False;self.foreign=True;self.removed=[]
        with self.assertRaises(m.ClientSinkRefused):self.run_probe()
        self.assertEqual(self.removed,[]);self.assertIsNotNone(self.doc)

    def test_preexisting_name_and_failed_cleanup_cannot_publish(self):
        self.collision=True
        with self.assertRaises(m.ClientSinkRefused):self.run_probe()
        self.assertEqual(self.names,[]);self.assertEqual(self.removed,[])
        self.collision=False;self.rm_failure=True
        with self.assertRaises(m.ClientSinkRefused) as caught:self.run_probe()
        self.assertEqual(caught.exception.phase,'cleanup')

    def test_actual_child_dispatch_runs_probe_without_source_inputs_or_broker_create(self):
        import emqx_real_owner_transport as transport
        out=io.BytesIO()
        with patch('emqx_arm_source_owner._owner_realm',return_value=True), \
             patch.object(transport.sys,'stdin',SimpleNamespace(buffer=io.BytesIO())), \
             patch.object(transport.sys,'stdout',SimpleNamespace(buffer=out)):
            self.assertEqual(transport.owner_main(b'K'),0)
        self.assertEqual(out.getvalue(),m.RECEIPT);self.create.assert_not_called();self.assertIsNone(self.doc)
        out=io.BytesIO()
        with patch('emqx_arm_source_owner._owner_realm',return_value=True), \
             patch.object(transport.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(b'forbidden-input'))), \
             patch.object(transport.sys,'stdout',SimpleNamespace(buffer=out)), \
             patch.object(m,'run_client_sink_capabilities') as probe:
            self.assertEqual(transport.owner_main(b'K'),1)
        probe.assert_not_called();self.assertEqual(out.getvalue(),b'CLIENTSINK-REFUSED:input\n')


if __name__=='__main__':unittest.main()
