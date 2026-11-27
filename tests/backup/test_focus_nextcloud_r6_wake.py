"""Offline same-config pin refresh and exact prior-unit recovery boundaries."""
import base64
import contextlib
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]/'e2e/lab'
sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('focus_r6_wake',HERE/'focus_nextcloud_r6_wake.py')
wake=importlib.util.module_from_spec(spec);spec.loader.exec_module(wake)


class PinTests(unittest.TestCase):
    def test_only_image_and_explicit_never_pull_change(self):
        original=b'[Container]\nImage=example/ref:tag\nEnvironmentFile=%h/private.env\nVolume=%h/data:/data\n'
        result=wake.render_pin(original,'a'*64,'example/ref:tag')
        self.assertEqual(result,b'[Container]\nImage=sha256:'+b'a'*64+
                         b'\nPull=never\nEnvironmentFile=%h/private.env\nVolume=%h/data:/data\n')

    def test_duplicate_or_different_original_image_and_pull_policy_refuse(self):
        for raw in (b'Image=wrong\n',b'Image=ref\nImage=ref\n',b'Image=ref\nPull=always\n',
                    b'Image=ref\nPull=never\nPull=never\n'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):wake.render_pin(raw,'a'*64,'ref')

    def test_existing_never_pull_and_other_bytes_survive(self):
        original=b'[Container]\r\nImage=ref\r\nPull=never\r\n# exact comment\r\n'
        self.assertEqual(wake.render_pin(original,'a'*64,'ref'),
                         original.replace(b'Image=ref',b'Image=sha256:'+b'a'*64))


class ActualFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name);self.root=self.home/'.config/containers/systemd';self.root.mkdir(parents=True)
        self.original={}
        for name,(ref,expected) in wake.FILES.items():
            raw=('[Container]\nImage='+ref+'\nEnvironmentFile=%h/private.env\n').encode()
            p=self.root/name;p.write_bytes(raw);p.chmod(0o640);os.utime(p,ns=(1700000000000000000,1700000000123456789))
            self.original[name]=(raw,p.stat().st_mode,p.stat().st_mtime_ns,p.stat().st_uid,p.stat().st_gid)

    def inspect(self,argv,**kwargs):
        self.assertEqual(argv[:3],['podman','image','inspect'])
        ref=argv[-1]
        expected=dict(wake.FILES.values())[ref]
        return types.SimpleNamespace(returncode=0,stdout=(expected+' amd64 linux\n').encode())

    def execute(self,action,snapshot=None,inspect=None):
        request={'action':action}
        if snapshot is not None:request['snapshot']=snapshot
        stdout=io.StringIO()
        with patch.object(Path,'home',return_value=self.home),patch.object(sys,'stdin',io.StringIO(json.dumps(request))), \
                patch.object(subprocess,'run',side_effect=inspect or self.inspect),contextlib.redirect_stdout(stdout):
            exec(compile(wake.unit_program(),'<private unit program>','exec'),{})
        return json.loads(stdout.getvalue())

    def unchanged(self):
        for name,(raw,mode,mtime,uid,gid) in self.original.items():
            p=self.root/name;s=p.stat()
            self.assertEqual((p.read_bytes(),s.st_mode,s.st_mtime_ns,s.st_uid,s.st_gid),(raw,mode,mtime,uid,gid))

    def test_snapshot_is_read_only_and_pin_revert_restores_exact_bytes_and_metadata(self):
        snapshot=self.execute('snapshot');self.unchanged()
        self.assertEqual(len(snapshot['rows']),5)
        for row in snapshot['rows']:
            self.assertEqual(base64.b64decode(row['data_b64']),self.original[row['name']][0])
        self.assertEqual(self.execute('pin',snapshot)['files'],5)
        for name,(_,expected) in wake.FILES.items():
            self.assertIn(('Image=sha256:'+expected+'\nPull=never\n').encode(),(self.root/name).read_bytes())
        self.assertEqual(self.execute('revert',snapshot)['status'],'reverted');self.unchanged()
        self.assertFalse(list(self.root.glob('*.focus-r6-*')))

    def test_wrong_config_never_reaches_a_write(self):
        def wrong(argv,**kwargs):return types.SimpleNamespace(returncode=0,stdout=(('0'*64)+' amd64 linux\n').encode())
        with self.assertRaises(AssertionError):self.execute('snapshot',inspect=wrong)
        self.unchanged()

    def test_tampered_prior_copy_refuses_before_any_write(self):
        snapshot=self.execute('snapshot');snapshot['rows'][-1]['data_b64']=base64.b64encode(b'changed').decode()
        with self.assertRaises(AssertionError):self.execute('pin',snapshot)
        self.unchanged()

    def test_foreign_edit_after_pin_is_preserved_and_no_other_file_is_reverted(self):
        snapshot=self.execute('snapshot');self.execute('pin',snapshot)
        name=list(wake.FILES)[-1];(self.root/name).write_bytes(b'foreign-edit\n')
        before={p.name:p.read_bytes() for p in self.root.iterdir()}
        with self.assertRaises(AssertionError):self.execute('revert',snapshot)
        self.assertEqual({p.name:p.read_bytes() for p in self.root.iterdir()},before)

    def test_symlink_unit_refuses_without_following(self):
        name=list(wake.FILES)[0];p=self.root/name;raw=p.read_bytes();p.unlink();p.symlink_to(self.home/'other')
        with self.assertRaises(AssertionError):self.execute('snapshot')
        self.assertFalse((self.home/'other').exists());self.assertTrue(p.is_symlink())


class ScopeTests(unittest.TestCase):
    def test_default_never_touches_device_or_credentials(self):
        with patch.object(sys,'argv',['wake']),patch.object(subprocess,'run',side_effect=AssertionError), \
                patch.object(subprocess,'check_output',side_effect=AssertionError),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(wake.main(),0)

    def test_image_only_lease_cannot_authorize_wake(self):
        now=datetime.datetime.now(datetime.timezone.utc)
        lease={'device':'woowbk-dev-e','lane':'nextcloud-r6','source_commit':'a'*40,'phases':['image-recovery'],
               'not_before_utc':(now-datetime.timedelta(minutes=1)).isoformat(),
               'expires_utc':(now+datetime.timedelta(minutes=45)).isoformat(),
               'reserve_bytes':wake.RESERVE,'memory_cap_bytes':wake.DEVICE_CAP}
        with patch.object(wake,'collect',side_effect=AssertionError('no device access')),self.assertRaises(ValueError):
            wake.run_locked(lease,'a'*40)

    def test_control_and_streamed_baseline_hash_programs_compile(self):
        compile(wake.CONTROL,'<bounded inner control>','exec');compile(wake.BASELINE_HASH,'<streamed hashes>','exec')


if __name__=='__main__':unittest.main()
