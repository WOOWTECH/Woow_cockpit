"""Generated policy fixtures only; no live HA/archive/broker access."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from emqx_mnesia_acl_target_variant import create_mnesia_acl_target_variant, _FILE_ONLY, _FALLBACK
from emqx_real_owner_workflow import _target_acl

ROOT=Path(__file__).parent

class VariantTests(unittest.TestCase):
    def test_separate_exact_policy_preserves_original(self):
        original=_target_acl()
        self.assertIn(b'{deny, all}.',original)
        self.assertIn(b'b1-gateway',original)
        variant=create_mnesia_acl_target_variant()
        self.assertEqual(variant.acl,(b'{allow, {username, "lab"}, all, ["lab/#"]}.\n'
            b'{deny, {username, "b1-sensor"}, subscribe, ["b1/secret/#"]}.\n'))
        self.assertTrue(variant.base.endswith(_FALLBACK))
        self.assertNotIn(b'b1-gateway',variant.acl)
        self.assertNotIn(b'{deny, all}',variant.acl)
        self.assertEqual(_target_acl(),original)
        self.assertNotIn('node.cookie',repr(variant))

    def test_only_authorization_changes_and_layout_drift_refuses(self):
        base=b'fixed-generated-prefix\n'+_FILE_ONLY
        with patch('emqx_real_owner_workflow._target_base',return_value=base):
            variant=create_mnesia_acl_target_variant()
        self.assertEqual(variant.base,b'fixed-generated-prefix\n'+_FALLBACK)
        for changed in (base+b'x',base+_FILE_ONLY,base.replace(b'no_match=deny',b'no_match=allow')):
            with self.subTest(shape=len(changed)),patch('emqx_real_owner_workflow._target_base',return_value=changed):
                with self.assertRaises(ValueError):create_mnesia_acl_target_variant()

    def test_private_bytes_expectation_detects_flow_mutation(self):
        v=create_mnesia_acl_target_variant()
        self.assertTrue(v.unchanged(base=v.base,acl=v.acl))
        self.assertFalse(v.unchanged(base=v.base+b'\n',acl=v.acl))
        self.assertFalse(v.unchanged(base=v.base,acl=v.acl+b'{deny, all}.\n'))
        self.assertFalse(v.unchanged(base=bytearray(v.base),acl=v.acl))

    def test_pinned_schema_and_actual_native_authorizer_components(self):
        from emqx_native_runtime import run_native
        v=create_mnesia_acl_target_variant()
        with tempfile.TemporaryDirectory(prefix='emqx-fixed-acl-') as directory, tempfile.TemporaryDirectory(prefix='emqx-fixed-acl-work-') as work:
            root=Path(directory)
            name='emqx_mnesia_acl_target_fixture.escript'
            (root/name).write_bytes((ROOT/name).read_bytes())
            (root/'acl.conf').write_bytes(v.acl)
            # Only native schema fixture path differs; factory mount stays fixed.
            (root/'authorization.conf').write_bytes(_FALLBACK.replace(b'/opt/emqx/etc/lab-acl.conf',b'/input/acl.conf'))
            with tempfile.TemporaryFile() as output:
                code=run_native(root,name,writable_directory=work,output=output)
                output.seek(0);raw=output.read(65537)
            self.assertEqual(code,0,'fixed native ACL component fixture refused')
            self.assertLessEqual(len(raw),65536)
            self.assertIn(b'FIXED_MNESIA_ACL_COMPONENTS_PASS',raw)
