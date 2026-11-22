"""Actual pinned native HOCON + vendor ACL; generated config, no HA/broker."""
import unittest
from emqx_native_hocon import native_hocon
from emqx_native_runtime import IMAGE
from emqx_owner_file_hocon import PROFILE
from emqx_semantic_readers import read_hocon, SemanticRefused

class NativeVendorTests(unittest.TestCase):
    def test_explicit_vendor_profile_native_parse_receipt_and_strict_control(self):
        raw=b'''authorization {sources=[{type=file,enable=true,path="${EMQX_ETC_DIR}/acl.conf"}]}\nauth.password="generated-hocon-private"\n'''
        with self.assertRaises(SemanticRefused):
            read_hocon(raw,native_hocon)
        observed=read_hocon(raw,native_hocon,file_profile=PROFILE,product_image=IMAGE)
        self.assertIn(b'generated-hocon-private',observed.values)
        self.assertIn(b'${EMQX_ETC_DIR}/acl.conf',observed.values)
        self.assertEqual(len(observed.file_receipts),1)
        receipt=observed.file_receipts[0]
        self.assertEqual(receipt['image'],IMAGE)
        self.assertEqual(receipt['bytes'],6763)
        self.assertEqual(receipt['sha256'],'970449f3515ffe63683de4eebac29f6c4cc93f11660cbb3f5bcb0b39df5a4aa0')
        self.assertTrue(receipt['complete'])
