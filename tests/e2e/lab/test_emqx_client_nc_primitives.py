"""Generated process receipts and shell syntax only; no network/image/lab IO."""
import io
import shlex
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_client_nc_primitives as m
import test_emqx_client_sink_capabilities as fixtures
from emqx_owned_client import LABEL


def wire(applets=m.REQUIRED,tail=m.PASS):
    return m.BEGIN+b''.join(name.encode()+b'\n' for name in applets)+m.END+tail


class NCTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.CapabilityTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.output=wire();self.code=0;self.error=b'';self.timeout=False
        self.fixture.runner.podman=self.podman

    def podman(self,*args,**kwargs):
        if args[0]!='run':return self.fixture.podman(*args,**kwargs)
        name=args[args.index('--name')+1];label,nonce=args[args.index('--label')+1].split('=',1)
        self.assertEqual(label,LABEL);self.assertRegex(nonce,r'^[0-9a-f]{64}$')
        self.fixture.names.append(name)
        self.fixture.doc={'Id':'a'*64,'Name':name,'Image':m.CLIENT,
            'Config':{'Labels':{LABEL:'foreign' if self.fixture.foreign else nonce}}}
        for option in ('--pull=never','--read-only','--network=none','--image-volume=ignore','--log-driver=none',
                '--memory=32m','--cpus=0.25','--pids-limit=16','--timeout=20'):
            self.assertIn(option,args)
        self.assertEqual(args[args.index('--tmpfs')+1],m.TMPFS)
        self.assertIn('size=1048576,mode=0700,uid=1000,gid=1000',m.TMPFS)
        self.assertEqual(args[-5:],('--entrypoint=/bin/busybox',m.CLIENT,'sh','-c',m.SCRIPT))
        for forbidden in ('-v','--volume','-e','--env','-p','--publish'):self.assertNotIn(forbidden,args)
        self.assertEqual(kwargs,dict(timeout=25,max_output=65536,check=False))
        if self.timeout:raise subprocess.TimeoutExpired('generated-public-probe',25)
        return SimpleNamespace(returncode=self.code,stdout=self.output,stderr=self.error)

    def test_one_sidecar_guarded_tmpfs_cleanup_and_fixed_nc_only_receipt(self):
        self.assertEqual(m.run_client_nc_primitives(),m.RECEIPT)
        self.assertEqual(len(self.fixture.names),1);self.assertIsNone(self.fixture.doc)
        self.assertEqual(self.fixture.removed,['a'*64])
        self.fixture.create.assert_not_called();self.fixture.cleanup.assert_not_called()
        self.assertNotIn('httpd',m.REQUIRED);self.assertNotIn('delivery',m.RECEIPT.decode().lower())

    def test_exact_required_applets_and_behavior_cannot_be_substituted_by_inventory(self):
        for name in m.REQUIRED:
            self.output=wire(tuple(x for x in m.REQUIRED if x!=name)+(name+'x',),b'NCPRIMITIVE-REFUSED:missing_'+name.encode()+b'\n')
            self.code=1
            with self.assertRaises(m.ClientNCRefused) as caught:m.run_client_nc_primitives()
            self.assertEqual(caught.exception.phase,'missing_'+name);self.assertIsNone(self.fixture.doc)
        for tail,code in ((b'',0),(m.PASS,1),(m.PASS+b'extra',0),(b'NCPRIMITIVE-REFUSED:unknown-private-value\n',1)):
            self.output=wire(tail=tail);self.code=code
            with self.assertRaises(m.ClientNCRefused):m.run_client_nc_primitives()
            self.assertIsNone(self.fixture.doc)

    def test_fixed_listener_empty_repeated_and_exact_http_failure_stages(self):
        for phase in m.BEHAVIOR:
            self.output=wire(tail=b'NCPRIMITIVE-REFUSED:'+phase.encode()+b'\n');self.code=1
            with self.assertRaises(m.ClientNCRefused) as caught:m.run_client_nc_primitives()
            self.assertEqual(caught.exception.phase,phase);self.assertIsNone(self.fixture.doc)
        self.output=wire(tail=b'');self.code=124
        with self.assertRaises(m.ClientNCRefused) as caught:m.run_client_nc_primitives()
        self.assertEqual(caught.exception.phase,'timeout')

    def test_timeout_cid_cleanup_and_foreign_nonce_never_deleted(self):
        self.timeout=True
        with self.assertRaises(m.ClientNCRefused):m.run_client_nc_primitives()
        self.assertEqual(self.fixture.removed,['a'*64]);self.assertIsNone(self.fixture.doc)
        self.timeout=False;self.fixture.foreign=True;self.fixture.removed=[]
        with self.assertRaises(m.ClientNCRefused):m.run_client_nc_primitives()
        self.assertEqual(self.fixture.removed,[]);self.assertIsNotNone(self.fixture.doc)

    def test_public_script_outer_and_inner_are_valid_shell_and_only_fixed_protocol(self):
        inner=next(token for token in shlex.split(m.SCRIPT) if token.startswith('\nphase=listener'))
        for script in (m.SCRIPT,inner):
            result=subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True,timeout=3)
            self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertIn('for n in 1 2 3',inner)
        self.assertIn('[ ! -s /work/request.1 ]',inner)
        self.assertIn('/bin/busybox cmp -s /work/send.$n /work/request.$n',inner)
        self.assertIn('/bin/busybox cmp -s /work/response /work/received.$n',inner)
        self.assertIn('exec /bin/busybox timeout 18',m.SCRIPT)
        self.assertNotIn('httpd',m.SCRIPT)

    def test_actual_child_mode_keeps_source_input_forbidden_and_existing_httpd_mode(self):
        import emqx_real_owner_transport as transport
        import emqx_client_sink_capabilities as old
        self.assertIn('httpd',old.REQUIRED)
        output=io.BytesIO()
        with patch('emqx_arm_source_owner._owner_realm',return_value=True), \
             patch.object(transport.sys,'stdin',SimpleNamespace(buffer=io.BytesIO())), \
             patch.object(transport.sys,'stdout',SimpleNamespace(buffer=output)):
            self.assertEqual(transport.owner_main(b'L'),0)
        self.assertEqual(output.getvalue(),m.RECEIPT)
        self.fixture.create.assert_not_called();self.assertIsNone(self.fixture.doc)
        output=io.BytesIO()
        with patch('emqx_arm_source_owner._owner_realm',return_value=True), \
             patch.object(transport.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(b'forbidden-input'))), \
             patch.object(transport.sys,'stdout',SimpleNamespace(buffer=output)), \
             patch.object(m,'run_client_nc_primitives') as probe:
            self.assertEqual(transport.owner_main(b'L'),1)
        probe.assert_not_called();self.assertEqual(output.getvalue(),b'CLIENTNC-REFUSED:input\n')


if __name__=='__main__':unittest.main()
